use std::fs;
use std::path::PathBuf;

use super::error::VaultError;
use super::manager::{StorageLocations,URIParser};
use std::io;

/*
    The StorageBackend trait defines the interface for storage backends
    that can be used to store vault data. Implementations of this trait
    should provide methods to store, retrieve, delete, and check the existence
    of blobs in the storage.

    It is also recommendeed to have a variable which stores the root path
    of the storage backend, which is used to determine where the blobs are stored.
*/
pub trait StorageBackend:std::fmt::Debug{
    fn store_blob(&self,id:&str,data:&[u8])->Result<(),VaultError>;

    fn get_blob(&self, id:&str)->Result<Vec<u8>,VaultError>;

    fn delete_blob(&self,id:&str)->Result<(),VaultError>;

    fn blob_exists(&self,id:&str)->Result<bool,VaultError>;

}

/*
    This is the smart connection function for the storage backend.
    It takes a URI as input and returns a boxed StorageBackend trait object.
    The URI can be a local file path or an S3 bucket URI, or any other
    storage backend struct which implements the StorageBackend trait.
*/
pub fn connect(uri:&URIParser)->Result<Box<dyn StorageBackend>, VaultError> {
    match uri.location {
        StorageLocations::Local(ref path) => {
            let backend = LocalStorageBackend::new(path.clone())?;
            Ok(Box::new(backend))
        },
        StorageLocations::S3(ref bucket) => {
            // Here you would implement the S3 storage backend
            Err(VaultError::NotImplementedError)
        },
    }
}
#[derive(Debug)]
pub struct LocalStorageBackend{
    root_path: std::path::PathBuf,
}

impl LocalStorageBackend{
    pub fn new(root_path:String)->Result<Self, VaultError>{
            let base_path = PathBuf::from(&root_path);

    // Ensure base path exists (create it if it doesn't)
    if !base_path.exists() {
        fs::create_dir_all(&base_path).map_err(VaultError::Io)?;
    } else if !base_path.is_dir() {
        return Err(VaultError::Io(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "Path exists but is not a directory",
        )));
    }

    let vault_path = base_path.join(".vault");

    // Create .vault dir if it doesn't exist
    if !vault_path.exists() {
        fs::create_dir(&vault_path).map_err(VaultError::Io)?;
    } else if !vault_path.is_dir() {
        return Err(VaultError::Io(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "A non-directory .vault already exists",
        )));
    }

    Ok(Self {
        root_path: vault_path,
    })
}
}

impl StorageBackend for LocalStorageBackend{
    fn store_blob(&self, id: &str, data: &[u8]) -> Result<(), VaultError> {
        let file_path = self.root_path.join(id);
        fs::write(file_path, data).map_err(|e| VaultError::Io(e))
    }

    fn get_blob(&self, id: &str) -> Result<Vec<u8>, VaultError> {
        let file_path = self.root_path.join(id);
        fs::read(file_path).map_err(|e| VaultError::Io(e))
    }

    fn delete_blob(&self, id: &str) -> Result<(), VaultError> {
        let file_path = self.root_path.join(id);
        fs::remove_file(file_path).map_err(|e| VaultError::Io(e))
    }

    fn blob_exists(&self, id: &str) -> Result<bool, VaultError> {
        let file_path = self.root_path.join(id);
        Ok(file_path.exists())
    }
}
