use std::collections::HashMap;
use std::path::{Path, PathBuf};

use crate::core::error::VaultError;
use crate::core::vault::{DirectoryListing, UnlockedVault};

#[derive(Clone)]
pub struct DirectoryCache {
    cache: HashMap<PathBuf, DirectoryListing>,
    max_entries: usize,

    access_counts: HashMap<PathBuf, usize>,

    hits: u64,
    misses: u64,
    evictions: u64,
}

#[derive(Debug)]
pub struct CacheStats {
    pub hits: u64,
    pub misses: u64,
    pub evictions: u64,
    pub current_size: usize,
    pub max_size: usize,
    pub hit_rate: f64,
}

impl DirectoryCache {
    pub fn new(max_size: usize) -> Self {
        DirectoryCache {
            cache: HashMap::new(),
            access_counts: HashMap::new(),
            max_entries: max_size,
            hits: 0,
            misses: 0,
            evictions: 0,
        }
    }

    pub fn init(&mut self, root_listing: DirectoryListing) {
        self.cache.insert(PathBuf::from("/"), root_listing);
        self.access_counts.insert(PathBuf::from("/"), 1);
    }

    fn record_access(&mut self, path: &Path) {
        if let Some(count) = self.access_counts.get_mut(path) {
            *count += 1;
        } else {
            self.access_counts.insert(path.to_path_buf(), 1);
        }
    }

    // TODO: Implement a eviction policy with better performance
    // Currently it is O(n) because we scan the entire access_counts map
    fn evict_if_needed(&mut self) {
        while self.cache.len() >= self.max_entries {
            let mut least_used = None;
            let mut min_access_count = usize::MAX;
            for (path, &count) in &self.access_counts {
                if (count < min_access_count) {
                    min_access_count = count;
                    least_used = Some(path.clone());
                }
            }
            if let Some(path) = least_used {
                self.cache.remove(&path);
                self.access_counts.remove(&path);
                self.evictions += 1;
            }
        }
    }

    pub fn get_directory_listing(
        &mut self,
        dir_path: &Path,
        vault: &mut UnlockedVault,
    ) -> Result<&DirectoryListing, VaultError> {
        if self.cache.contains_key(dir_path) {
            self.record_access(dir_path);
            self.hits += 1;
            return Ok(self.cache.get(dir_path).unwrap());
        }
        self.misses += 1;

        let mut current_path = dir_path.to_path_buf();
        let mut paths_to_fetch = Vec::new();
        self.record_access(&current_path);
        while !self.cache.contains_key(&current_path) {
            paths_to_fetch.push(current_path.clone());

            if let Some(parent) = current_path.parent() {
                current_path = parent.to_path_buf();
            } else {
                // This means we reached the root directory
                break;
            }
        }

        for path in paths_to_fetch.iter().rev() {
            let parent_path = path.parent().ok_or(VaultError::InvalidPath)?;
            let parent_listing = self
                .cache
                .get(parent_path)
                .ok_or(VaultError::CacheInconsistent)?;
            let child_name = path
                .file_name()
                .and_then(|s| s.to_str())
                .ok_or_else(|| VaultError::InvalidPath)?;
            let child_metadata = parent_listing
                .directories
                .get(child_name)
                .ok_or_else(|| VaultError::ResourceNotFound)?;

            let listing = vault
                .get_directory_listing_from_blob_id(&child_metadata.blob_id)
                .map_err(|e| VaultError::Serialization)?;
            self.evict_if_needed();
            self.cache.insert(path.to_path_buf(), listing);
            self.record_access(path);
        }
        Ok(self
            .cache
            .get(dir_path)
            .ok_or(VaultError::CacheInconsistent)?)
    }

    pub fn invalidate_path_and_parents(&mut self, path: &Path) {
        let mut current = Some(path.to_path_buf());
        while let Some(p) = current {
            self.cache.remove(&p);
            self.access_counts.remove(&p);
            current = p.parent().map(|p| p.to_path_buf());
        }
    }

    pub fn stats(&self) -> CacheStats {
        let total_requests = self.hits + self.misses;
        let hit_rate = if total_requests > 0 {
            self.hits as f64 / total_requests as f64
        } else {
            0.0
        };
        CacheStats {
            hits: self.hits,
            misses: self.misses,
            evictions: self.evictions,
            current_size: self.cache.len(),
            max_size: self.max_entries,
            hit_rate,
        }
    }

    pub fn print_stats(&self) {
        let stats = self.stats();
        println!("Cache Stats:");
        println!("Hits: {}", stats.hits);
        println!("Misses: {}", stats.misses);
        println!("Evictions: {}", stats.evictions);
        println!("Current Size: {}", stats.current_size);
        println!("Max Size: {}", stats.max_size);
        println!("Hit Rate: {:.2}%", stats.hit_rate * 100.0);
    }

    pub fn clear(&mut self) {
        self.cache.clear();
        self.access_counts.clear();
        self.hits = 0;
        self.misses = 0;
        self.evictions = 0;
    }
}
