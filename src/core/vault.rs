use crate::core::crypto::{self, encrypt, generate_dek, SecureKey};
use crate::core::error::VaultError;
use crate::core::storage::{StorageBackend, connect};
use base64::Engine;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use crate::core::cache::DirectoryCache;
use uuid::Uuid;

const CACHE_SIZE: usize = 100; // Default cache size

// =============================================================================
// ON-DISK DATA STRUCTURES
// =============================================================================

// This represents the plaintext vault.manifest file

#[derive(Serialize, Deserialize)]
pub struct VaultManifest {
    // The public salt used by the Argon KDF to compute
    // the Key Encryption Key
    pub kdf_salt: String,

    // The 512 bit Data Encryption Key (DEK) encrypted with the
    // Key Encryption Key. Stored as Base64
    pub encrypted_master_key: String, // Encoded as Base64

    // The blob ID of the vault's root directory
    pub root_blob_encrypted_id: String,
}

// The EntryMetadata Structure is used to store the
// required Metadata about a single blob.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct EntryMetadata {
    pub entry_type: EntryType,
    pub blob_id: String,
}

// The comprehensive enum which stores the list of
// types of blobs
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum EntryType {
    File,
    Directory,
}

// =============================================================================
// IN-MEMORY DATA STRUCTURES
// =============================================================================

// Represents the contents of the single file which contains the
// directory listing blob.

#[derive(Default, Serialize, Deserialize,Debug,Clone)]
pub struct DirectoryListing {
    pub directories: HashMap<String, EntryMetadata>,
    pub files: HashMap<String, EntryMetadata>,
}



// Represents an unlocked Vault in the memory. This is a stateless
// toolkit for performing path based cryptographic and storage operations

pub struct UnlockedVault {
    // The fields in this struct will be kept private, considering the sensitivity
    // of the data stored in it.

    // This can hold any struct which implements the StorageBackend trait. The vault
    // is completely modular and can be extended seamlessly
    storage: Box<dyn StorageBackend>,

    // This is the Data Encryption Key (DEK) which will be used to encrypt and decrypt
    // the contents of the files
    content_key: SecureKey,

    // This holds the Data Encryption Key for the filenames and directories
    metadata_key: SecureKey,

    root_directory: DirectoryListing,

    directory_cache: DirectoryCache,
}


impl UnlockedVault {
    pub fn create(storage: Box<dyn StorageBackend>, password: &str) -> Result<Self, VaultError> {
        let main_dek = crypto::generate_dek().unwrap();
        let (content_key, metadata_key) = main_dek.split_into_keys(32);

        let (kdf_salt, kek) = crypto::derive_new_key(password)?;

        let encrypted_master_key = crypto::encrypt(main_dek.as_slice(), &kek)?;

        // Initial Vault Structure Set-up

        let root_listing = DirectoryListing::default();
        let root_listing_json =
            serde_json::to_string(&root_listing).map_err(|_| VaultError::Serialization)?;

        let root_blob_id = Uuid::new_v4().to_string();
        storage.store_blob(&root_blob_id, root_listing_json.as_bytes())?;
        println!("Created root blob with ID: {}", root_blob_id);
        let root_blob_encrypted_id = encrypt(root_blob_id.as_bytes(), &metadata_key)
            .map_err(|_| VaultError::Crypto("Failed to encrypt root blob ID".to_string()))?;
        let root_blob_id = base64::engine::general_purpose::STANDARD.encode(root_blob_encrypted_id);
        println!("Encrypted root blob ID: {}", root_blob_id);
        let base64_engine = base64::engine::general_purpose::STANDARD;
        let manifest = VaultManifest {
            kdf_salt,
            encrypted_master_key: base64_engine.encode(encrypted_master_key),
            root_blob_encrypted_id: root_blob_id.clone(),
        };

        let manifest_json =
            serde_json::to_string(&manifest).map_err(|_| VaultError::Serialization)?;
        storage.store_blob("vault.manifest", manifest_json.as_bytes())?;
        let mut directory_cache = DirectoryCache::new(CACHE_SIZE);
        directory_cache.init(root_listing.clone());

        Ok(Self {
            storage,
            content_key,
            metadata_key,
            root_directory: root_listing,
            directory_cache
        })
    }

    pub fn open(storage: Box<dyn StorageBackend>, password: &str) -> Result<Self, VaultError> {
        let manifest_blob = storage.get_blob("vault.manifest")?;
        let manifest_json =
            String::from_utf8(manifest_blob).map_err(|_| VaultError::Serialization)?;
        let manifest: VaultManifest =
            serde_json::from_str(&manifest_json).map_err(|_| VaultError::Serialization)?;
        let kdf_salt = manifest.kdf_salt.clone();
        let base64_engine = base64::engine::general_purpose::STANDARD;
        let encrypted_master_key = base64_engine
            .decode(&manifest.encrypted_master_key)
            .map_err(|_| VaultError::Serialization)?;
        let kek = crypto::derive_key_from_password_and_salt(password, &kdf_salt)?;
        let main_dek_raw = crypto::decrypt(&encrypted_master_key, &kek)
            .map_err(|_| VaultError::Crypto("Failed to decrypt master key".to_string()))?;
        let main_dek = SecureKey::new(main_dek_raw);
        let (content_key, metadata_key) = main_dek.split_into_keys(32);
        let root_blob_encrypted_id = manifest.root_blob_encrypted_id.clone();
        println!("Root blob encrypted ID: {}", root_blob_encrypted_id);
        let root_blob_id = base64_engine
            .decode(&root_blob_encrypted_id)
            .map_err(|_| VaultError::Serialization)?;
        let root_blob_id = crypto::decrypt(&root_blob_id, &metadata_key)
            .map_err(|_| VaultError::Crypto("Failed to decrypt root blob ID".to_string()))?;
        let root_blob_id = String::from_utf8(root_blob_id)
            .map_err(|_| VaultError::Serialization)?;
        println!("Decrypted root blob ID: {}", root_blob_id);
        let root_blob = storage.get_blob(&root_blob_id)?;
        let root_directory: DirectoryListing =
            serde_json::from_slice(&root_blob).map_err(|_| VaultError::Serialization)?;
        println!("Root directory listing loaded successfully.");
        let mut directory_cache= DirectoryCache::new(CACHE_SIZE);
        directory_cache.init(root_directory.clone());

        Ok(Self {
            storage,
            content_key,
            metadata_key,
            root_directory,
            directory_cache,
        })
    }

    pub fn get_directory_listing_from_blob_id(&self, blob_id: &str) -> Result<DirectoryListing, VaultError> {
        let blob = self.storage.get_blob(blob_id)?;
        let listing: DirectoryListing =
            serde_json::from_slice(&blob).map_err(|_| VaultError::Serialization)?;
        Ok(listing)
    }
}
