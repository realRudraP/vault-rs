use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use lru::LruCache;

// These types are defined in `vault.rs` and are used by this module.
use crate::core::error::VaultError;
use crate::core::vault::{DirectoryListing, UnlockedVault};

// =============================================================================
// INTERNAL CACHE STATE
// =============================================================================

/// Private internal struct that holds the actual cache state and statistics.
///
/// This struct is wrapped in an `Arc<Mutex<>>` within the public `DirectoryCache`
/// to provide thread-safe, shared access. It is not intended to be used directly
/// and is not cloneable to prevent accidental deep copies of the cache.
struct DirectoryCacheInternal {
    /// The LRU cache storing directory paths and their corresponding listings.
    cache: LruCache<PathBuf, DirectoryListing>,
    /// The blob ID of the root directory, stored separately to allow direct filesystem access
    /// when the root directory is evicted from the cache.
    root_blob_id: Option<String>,
    /// Counter for cache hits. Incremented when a requested item is found in the cache.
    hits: u64,
    /// Counter for cache misses. Incremented when a requested item is not in the cache.
    misses: u64,
    /// Counter for evictions. Incremented when an item is removed to make space for a new one.
    evictions: u64,
}

// =============================================================================
// PUBLIC CACHE API
// =============================================================================

/// A thread-safe, in-memory, LRU cache for directory listings from a vault.
///
/// This struct acts as a smart, cheap-to-clone handle to a shared cache instance.
/// It is designed to reduce latency and load on the underlying `UnlockedVault` by
/// storing frequently accessed directory structures in memory. The cache is
/// path-aware, meaning a request for a deep, uncached path will automatically
/// fetch and cache all intermediate parent directories.
#[derive(Clone)]
pub struct DirectoryCache {
    internal: Arc<Mutex<DirectoryCacheInternal>>,
}

/// A snapshot of the cache's performance statistics.
///
/// This struct provides insight into the effectiveness of the cache, including
/// hit rate, size, and total operations. It is returned by the `stats()` method.
#[derive(Debug, PartialEq)]
pub struct CacheStats {
    /// The total number of times a requested directory was found in the cache.
    pub hits: u64,
    /// The total number of times a requested directory was not in the cache and had to be fetched.
    pub misses: u64,
    /// The total number of items removed from the cache due to the LRU policy.
    pub evictions: u64,
    /// The number of directories currently stored in the cache.
    pub current_size: usize,
    /// The maximum number of directories the cache can hold.
    pub max_size: usize,
    /// The ratio of hits to total requests (hits + misses), from 0.0 to 1.0.
    pub hit_rate: f64,
}

impl DirectoryCache {
    /// Creates a new `DirectoryCache` with a specified maximum capacity.
    ///
    /// The cache will hold at most `max_size` directory listings. The underlying
    /// implementation uses a `NonZeroUsize`, so the capacity will be at least 1,
    /// even if `max_size` is 0.
    ///
    /// # Arguments
    ///
    /// * `max_size` - The maximum number of directory listings to store in the cache.
    ///
    /// # Returns
    ///
    /// * A new `DirectoryCache` instance.
    pub fn new(max_size: usize) -> Self {
        // Ensure the capacity is at least 1, as LruCache requires a non-zero capacity.
        let capacity = std::cmp::max(1, max_size);
        let internal = DirectoryCacheInternal {
            cache: LruCache::new(NonZeroUsize::new(capacity).unwrap()),
            root_blob_id: None,
            hits: 0,
            misses: 0,
            evictions: 0,
        };

        DirectoryCache {
            internal: Arc::new(Mutex::new(internal)),
        }
    }

    /// Initializes the cache by inserting the root directory listing and storing its blob ID.
    ///
    /// This method should be called once after the vault is unlocked to "warm up"
    /// the cache with the root entry. All subsequent cache lookups start from an
    /// ancestor, and seeding the root ensures there is always a valid starting point.
    /// The root blob ID is stored separately to enable direct filesystem access
    /// even if the root directory is evicted from the cache.
    ///
    /// # Arguments
    ///
    /// * `root_listing` - The `DirectoryListing` for the vault's root path (`/`).
    pub fn init(&self, root_listing: DirectoryListing) {
        let mut internal = self.internal.lock().unwrap();
        internal.root_blob_id = Some(root_listing.blob_id.clone());
        internal.cache.put(PathBuf::from("/"), root_listing.clone());
    }

    fn normalize_path(p: &Path) -> PathBuf {
        if p.as_os_str().is_empty() {
            PathBuf::from("/")
        } else {
            p.to_path_buf()
        }
    }
    /// Retrieves a directory listing, using the cache if possible or fetching from the vault.
    ///
    /// This is the core method of the cache. It follows an intelligent fetch strategy:
    /// 1. First, it attempts a direct lookup in the cache for the requested `dir_path`.
    /// 2. On a cache hit, it clones the listing and returns it immediately along with its blob ID.
    /// 3. On a cache miss, it walks up the directory tree from `dir_path` until it finds
    ///    a cached parent directory or reaches the root.
    /// 4. If the root is not cached but the root blob ID is available, it fetches the root
    ///    directly from the filesystem using the stored blob ID.
    /// 5. It then fetches the required child directories sequentially from the vault,
    ///    populating the cache along the way.
    ///
    /// # Arguments
    ///
    /// * `dir_path` - The absolute path of the directory to retrieve from the vault.
    /// * `vault` - A reference to the `UnlockedVault` to use for fetching if the data is not cached.
    /// * `mark_dirty` - If true, the target directory listing will be removed from cache after retrieval to ensure fresh data on next fetch.
    ///
    /// # Returns
    ///
    /// * `Ok(DirectoryListing)` - The requested directory listing.
    /// * `Err(VaultError::ResourceNotFound)` - If the directory or one of its parents does not exist in the vault.
    /// * `Err(VaultError::CacheInconsistent)` - If the cache is in an unexpected state (e.g., a parent is missing when it should exist).
    /// * `Err(VaultError::InvalidPath)` - If the provided path is malformed.
    ///
    /// # Note
    ///
    /// This method assumes that `DirectoryListing` has a `blob_id` field that contains
    /// the blob ID of the blob that stores this directory listing.
    pub fn get_directory_listing(
        &self,
        dir_path: &Path,
        vault: &UnlockedVault,
        mark_dirty: bool,
    ) -> Result<DirectoryListing, VaultError> {
        let mut internal = self.internal.lock().unwrap();
        let dir_path_buf = DirectoryCache::normalize_path(dir_path);

        // Check if we have it in cache (cache hit)
        if let Some(listing) = internal.cache.get(&dir_path_buf).cloned() {
            internal.hits += 1;
            eprintln!("Cache hit for directory: {}", dir_path_buf.display());
            let result = listing.clone();

            // If mark_dirty is true, remove it from cache so next fetch reads from fs
            if mark_dirty {
                eprintln!("Entry popped from cache");
                internal.cache.pop(&dir_path_buf);
            }

            return Ok(result);
        }

        // It's a cache miss, proceed to fetch from vault
        internal.misses += 1;

        let mut current_path = dir_path_buf.clone();
        let mut paths_to_fetch = Vec::new();

        // Walk up the directory tree until we find a cached parent or reach the root
        while !internal.cache.contains(&current_path) {
            paths_to_fetch.push(current_path.clone());
            if let Some(parent) = current_path.parent() {
                current_path = parent.to_path_buf();
            } else {
                break;
            }
        }

        // If we've reached the root and it's not cached, but we have the root blob ID,
        // we can fetch it directly from the filesystem
        let root_path = PathBuf::from("/");
        if !internal.cache.contains(&root_path)
            && (paths_to_fetch.contains(&root_path) || current_path == root_path)
        {
            if let Some(ref root_blob_id) = internal.root_blob_id {
                let root_listing = vault
                    .get_directory_listing_from_blob_id(root_blob_id)
                    .map_err(|_| VaultError::ResourceNotFound)?;

                // Cache the root directory unless it's the target and mark_dirty is true
                let should_cache_root = !mark_dirty || dir_path_buf != root_path;
                if should_cache_root {
                    eprintln!("Caching the fetched root directory now");
                    let is_full = internal.cache.len() == internal.cache.cap().get();
                    let key_exists = internal.cache.contains(&root_path);
                    if is_full && !key_exists {
                        internal.evictions += 1;
                    }
                    internal.cache.put(PathBuf::from("/"), root_listing.clone());
                }

                // If the target was the root directory, return it now
                if dir_path_buf == root_path || dir_path_buf == PathBuf::from("") {
                    return Ok(root_listing);
                }
            }
        }

        let mut last_fetched_listing: Option<DirectoryListing> = None;

        for (i, path) in paths_to_fetch.iter().rev().enumerate() {
            let parent_path = if path == Path::new("/") {
                Path::new("/")
            } else {
                path.parent().ok_or(VaultError::InvalidPath)?
            };

            let child_metadata = {
                let child_name = path
                    .file_name()
                    .and_then(|s| s.to_str())
                    .ok_or(VaultError::InvalidPath)?;

                let parent_listing = if i == 0 {
                    internal
                        .cache
                        .get(&parent_path.to_path_buf())
                        .ok_or(VaultError::CacheInconsistent)?
                } else {
                    last_fetched_listing
                        .as_ref()
                        .ok_or(VaultError::CacheInconsistent)?
                };

                parent_listing
                    .directories
                    .get(child_name)
                    .ok_or(VaultError::ResourceNotFound)?
                    .clone()
            };

            let listing = vault
                .get_directory_listing_from_blob_id(&child_metadata.blob_id)
                .map_err(|_| VaultError::ResourceNotFound)?;

            // Only cache this directory if it's not the target directory or mark_dirty is false
            let should_cache = !mark_dirty || path != &dir_path_buf;

            if should_cache {
                // An eviction occurs if the cache is full AND we are adding a new key.
                let is_full = internal.cache.len() == internal.cache.cap().get();
                let key_exists = internal.cache.contains(path);
                if is_full && !key_exists {
                    internal.evictions += 1;
                }

                internal.cache.put(path.to_path_buf(), listing.clone());
            }

            last_fetched_listing = Some(listing);
        }

        let final_listing = last_fetched_listing.ok_or(VaultError::CacheInconsistent)?;

        // If mark_dirty is true and we just fetched the target directory, remove it from cache
        if mark_dirty && paths_to_fetch.contains(&dir_path_buf) {
            internal.cache.pop(&dir_path_buf);
        }

        Ok(final_listing.clone())
    }

    /// Removes a path and all of its parent directories from the cache.
    ///
    /// Note: The root blob ID is preserved even if the root directory is evicted,
    /// allowing for direct filesystem access when needed.
    pub fn invalidate_path_and_parents(&self, path: &Path) {
        let mut internal = self.internal.lock().unwrap();
        let mut current = Some(path.to_path_buf());
        while let Some(p) = current {
            internal.cache.pop(&p);
            current = p.parent().map(|p| p.to_path_buf());
        }
    }

    /// Returns a snapshot of the cache's current performance statistics.
    pub fn stats(&self) -> CacheStats {
        let internal = self.internal.lock().unwrap();
        let total_requests = internal.hits + internal.misses;
        let hit_rate = if total_requests > 0 {
            internal.hits as f64 / total_requests as f64
        } else {
            0.0
        };
        CacheStats {
            hits: internal.hits,
            misses: internal.misses,
            evictions: internal.evictions,
            current_size: internal.cache.len(),
            max_size: internal.cache.cap().get(),
            hit_rate,
        }
    }

    /// A convenience method to print formatted cache statistics to the console.
    pub fn print_stats(&self) {
        let stats = self.stats();
        println!("Cache Stats:");
        println!("  Hits: {}", stats.hits);
        println!("  Misses: {}", stats.misses);
        println!("  Evictions: {}", stats.evictions);
        println!(
            "  Current Size: {} / {}",
            stats.current_size, stats.max_size
        );
        println!("  Hit Rate: {:.2}%", stats.hit_rate * 100.0);
    }

    /// Clears the entire cache and resets all performance statistics.
    ///
    /// Note: The root blob ID is preserved to maintain the ability to fetch
    /// the root directory directly from the filesystem.
    pub fn clear(&self) {
        let mut internal = self.internal.lock().unwrap();
        internal.cache.clear();
        internal.hits = 0;
        internal.misses = 0;
        internal.evictions = 0;
        // Note: root_blob_id is intentionally preserved
    }

    /// Returns the stored root blob ID, if available.
    ///
    /// This can be useful for debugging or when you need to access the root blob ID
    /// directly without going through the cache.
    pub fn get_root_blob_id(&self) -> Option<String> {
        let internal = self.internal.lock().unwrap();
        internal.root_blob_id.clone()
    }
}

// =============================================================================
// TESTS
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::vault::DirectoryListing;
    use std::collections::HashMap;

    #[test]
    fn test_new_cache_is_empty() {
        let cache = DirectoryCache::new(10);
        let stats = cache.stats();
        assert_eq!(stats.current_size, 0);
        assert_eq!(stats.max_size, 10);
        assert_eq!(stats.hits, 0);
        assert_eq!(stats.misses, 0);
        assert_eq!(stats.evictions, 0);
        assert_eq!(cache.get_root_blob_id(), None);
    }

    #[test]
    fn test_init_cache() {
        let cache = DirectoryCache::new(10);
        let root_listing = DirectoryListing {
            directories: HashMap::new(),
            files: HashMap::new(),
            blob_id: "root_blob_id".to_string(),
        };
        cache.init(root_listing);

        assert_eq!(cache.stats().current_size, 1);
        assert_eq!(cache.get_root_blob_id(), Some("root_blob_id".to_string()));
        let internal = cache.internal.lock().unwrap();
        assert!(internal.cache.contains(&PathBuf::from("/")));
    }

    #[test]
    fn test_root_blob_id_preserved_after_clear() {
        let cache = DirectoryCache::new(10);
        let root_listing = DirectoryListing {
            directories: HashMap::new(),
            files: HashMap::new(),
            blob_id: "root_blob_id".to_string(),
        };
        cache.init(root_listing);

        // Add some other entries
        {
            let mut internal = cache.internal.lock().unwrap();
            let listing = DirectoryListing::new("other_blob_id".to_string());
            internal.cache.put(PathBuf::from("/a"), listing);
            internal.hits = 5;
            internal.misses = 3;
        }

        assert_eq!(cache.stats().current_size, 2);
        assert_eq!(cache.get_root_blob_id(), Some("root_blob_id".to_string()));

        cache.clear();

        // Cache should be cleared but root blob ID preserved
        let stats = cache.stats();
        assert_eq!(stats.current_size, 0);
        assert_eq!(stats.hits, 0);
        assert_eq!(stats.misses, 0);
        assert_eq!(stats.evictions, 0);
        assert_eq!(cache.get_root_blob_id(), Some("root_blob_id".to_string()));
    }

    #[test]
    #[ignore = "Requires a mockable UnlockedVault to test fetch logic"]
    fn test_cache_miss_and_fetch_logic() {
        // This test, if enabled, would be the one to verify eviction statistics,
        // as it would use the public `get_directory_listing` API.
    }

    #[test]
    fn test_invalidation() {
        let cache = DirectoryCache::new(10);
        let listing = DirectoryListing::new("root_blob_id".to_string());
        cache.init(listing.clone());

        {
            let mut internal = cache.internal.lock().unwrap();
            internal.cache.put(PathBuf::from("/a"), listing.clone());
            internal.cache.put(PathBuf::from("/a/b"), listing.clone());
        }
        assert_eq!(cache.stats().current_size, 3); // root + /a + /a/b

        cache.invalidate_path_and_parents(Path::new("/a/b"));
        assert_eq!(cache.stats().current_size, 0);
        // Root blob ID should still be available
        assert_eq!(cache.get_root_blob_id(), Some("root_blob_id".to_string()));
    }

    #[test]
    fn test_lru_eviction() {
        let cache = DirectoryCache::new(2);
        let listing = DirectoryListing::new("root_blob_id".to_string());

        {
            let mut internal = cache.internal.lock().unwrap();
            // 1. Fill the cache
            internal.cache.put(PathBuf::from("/a"), listing.clone());
            internal.cache.put(PathBuf::from("/b"), listing.clone());
            assert_eq!(internal.cache.len(), 2);

            // 2. Access /a to make it most recently used
            internal.cache.get(&PathBuf::from("/a"));

            // 3. Add a new item, which should evict /b
            internal.cache.put(PathBuf::from("/c"), listing.clone());
        }

        // This test verifies the LRU behavior directly. It does not check the `evictions`
        // counter because it bypasses the public API where that counter is managed.
        let internal = cache.internal.lock().unwrap();
        assert_eq!(internal.cache.len(), 2);
        assert!(
            !internal.cache.contains(&PathBuf::from("/b")),
            "Path /b should have been evicted"
        );
        assert!(internal.cache.contains(&PathBuf::from("/a")));
        assert!(internal.cache.contains(&PathBuf::from("/c")));
    }

    #[test]
    fn test_clear_cache() {
        let cache = DirectoryCache::new(5);
        let listing = DirectoryListing::new("root_blob_id".to_string());

        {
            let mut internal = cache.internal.lock().unwrap();
            internal.cache.put(PathBuf::from("/a"), listing.clone());
            internal.cache.put(PathBuf::from("/b"), listing.clone());
            internal.hits = 5;
            internal.misses = 3;
            internal.evictions = 1;
        }
        assert_eq!(cache.stats().current_size, 2);

        cache.clear();
        let stats = cache.stats();
        assert_eq!(stats.current_size, 0);
        assert_eq!(stats.hits, 0);
        assert_eq!(stats.misses, 0);
        assert_eq!(stats.evictions, 0);
    }
}
