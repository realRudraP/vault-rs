use argon2::{
    Argon2,
    password_hash::{PasswordHasher, SaltString, rand_core::OsRng},
};
use directories_next::ProjectDirs;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::{fs, io};
// Check verification
use indexmap::IndexSet;

pub mod core;
pub use core::manager::VaultManager;
const METADATA_FILENAME: &str = "vault.json.enc";
const DATA_DIR_NAME: &str = "data";
// Vault Configuration and Objects

// The metadata is serialized, encrypted and saved to the
// vault's config file
#[derive(Debug, Serialize, Deserialize)]
pub struct VaultMetadata {
    version: usize,
    // The salt is stored as string for JSON compatibility
    pub salt: String,
    // All the files in the storage backend will be addresses
    // as URIs in the form of strings.
    pub vaults: IndexSet<String>,
}

// Represents an unlocked vault in memory

#[derive(Debug)]
pub struct Vault {
    // The master key derived from the user's password. Only exists in memory
    master_key: Vec<u8>,
    // The vault's metadata, including the salt and the list of files
    metadata: VaultMetadata,
    // Any Storage backend which implements StorageBackend
    storage: Box<dyn StorageBackend>,
    // Path to the metadata file
}

#[derive(Debug)]
pub enum VaultError {
    Io(io::Error),
    Serialization(serde_json::Error),
    Crypto(String),
    VaultAlreadyExists,
    VaultNotFound,
    NotImplementedError,
}

impl From<io::Error> for VaultError {
    fn from(e: io::Error) -> Self {
        VaultError::Io(e)
    }
}
impl From<serde_json::Error> for VaultError {
    fn from(value: serde_json::Error) -> Self {
        VaultError::Serialization(value)
    }
}

pub fn connect_storage(uri: &str) -> Result<Box<dyn StorageBackend>, VaultError> {
    let vault_dir = PathBuf::from(uri);
    fs::create_dir_all(&vault_dir)?;
    let data_path = vault_dir.join(DATA_DIR_NAME);
    fs::create_dir_all(&data_path)?;

    Ok(Box::new(LocalStorageBackend::new(vault_dir)?))
}

impl Vault {
    pub fn new(
        storage: Box<dyn StorageBackend>,
        master_password: &str,
    ) -> Result<Self, VaultError> {
        let salt = SaltString::generate(&mut OsRng);

        let argon2 = Argon2::default();
        let key_hash = argon2
            .hash_password(master_password.as_bytes(), &salt)
            .map_err(|e| VaultError::Crypto(e.to_string()))?;

        let master_key = key_hash.hash.unwrap().as_bytes().to_vec();

        let metadata = VaultMetadata {
            salt: salt.to_string(),
            version: 1,
            vaults: IndexSet::new(),
        };

        let vault = Self {
            master_key,
            metadata,
            storage,
        };

        vault.save_metadata()?;

        println!("Vault created successfully!");
        Ok(vault)
    }

    fn save_metadata(&self) -> Result<(), VaultError> {
        let metadata_json = serde_json::to_string(&self.metadata)?;

        self.storage
            .store_blob(METADATA_FILENAME, metadata_json.as_bytes())
    }
}

// Storage backend trait declaration

pub trait StorageBackend: std::fmt::Debug {
    fn store_blob(&self, id: &str, data: &[u8]) -> Result<(), VaultError>;

    fn retrieve_blob(&self, id: &str) -> Result<Vec<u8>, VaultError>;

    fn delete_blob(&self, id: &str) -> Result<(), VaultError>;
}

#[derive(Debug)]
pub struct LocalStorageBackend {
    root_path: PathBuf,
}

impl LocalStorageBackend {
    // Create a new vault at the location provided, ensuring
    // the root directory exists. Also check for existing vault
    // at the same location
    pub fn new(root_path: PathBuf) -> Result<Self, VaultError> {
        if root_path.exists() {
            if root_path.is_dir() {
                let is_empty = root_path
                    .read_dir()
                    .map(|mut entries| entries.next().is_none())
                    .unwrap_or(false);

                if !is_empty {
                    return Err(VaultError::Io(io::Error::new(
                        io::ErrorKind::AlreadyExists,
                        "Directory exists and is not empty",
                    )));
                }
            } else {
                return Err(VaultError::Io(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "Path exists but is not a directory",
                )));
            }
        }
        fs::create_dir_all(&root_path)?;
        Ok(Self { root_path })
    }
}

/*
 * Implement StorageBackend mandated traits for LocalStorageBackend
*/

impl StorageBackend for LocalStorageBackend {
    // Store blob with the given ID inside the root_path of the
    // StorageBackend. The filename is the same as the ID
    fn store_blob(&self, id: &str, data: &[u8]) -> Result<(), VaultError> {
        fs::write(self.root_path.join(id), data)?;
        Ok(())
    }

    // Retrieve the blob from the root_path using the filename as an
    // identifier, and return a vectore of u8
    fn retrieve_blob(&self, id: &str) -> Result<Vec<u8>, VaultError> {
        let path = self.root_path.join(id);
        if !path.exists() {
            return Err(VaultError::Io(io::Error::new(
                io::ErrorKind::NotFound,
                "The requested blob doesn't exist on the filesystem",
            )));
        }
        let data = fs::read(path)?;
        Ok(data)
    }
    // Delete a blob from the root_path using the ID for the filename
    fn delete_blob(&self, id: &str) -> Result<(), VaultError> {
        Ok(fs::remove_file(self.root_path.join(id))?)
    }
}
