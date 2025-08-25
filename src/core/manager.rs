/*
   The Vault Manager struct is responsible for managing all the vaults in the system.
   It provides methods to add, remove, and list vaults, as well as to initialize
   the vault directory.
   The VaultInfo struct represents a single vault's information, including its ID,
   URI, last opened time, and options.
*/

use std::path::Path;
use std::time::SystemTime;

use crate::core::crypto::SecureKey;
use crate::core::error::VaultError;
use crate::core::storage::{self, StorageBackend, connect};
use crate::core::vault::{self, DirectoryListing, UnlockedVault};
use directories_next::ProjectDirs;
use serde::{Deserialize, Serialize, ser};

const MANIFEST_FILENAME: &str = "vault-rs.manifest.json";
// Individual vault information is stored in the VaultInfo struct.

#[derive(Serialize, Deserialize)]
struct VaultInfo {
    // Unique identifier for the vault
    id: String,
    // URI of the vault, which can be a local path or a remote URL
    location: String,
    // The last time the vault was opened
    last_opened: std::time::SystemTime,
    // Additional options for the vault, stored as key-value pairs
    options: std::collections::HashMap<String, String>,
}

// The VaultManager struct manages the collection of vaults.
// It is also responsible for holding the state of the vault directory,
// including setup of the application's configuration directory and manifest file
// as well as initializing the app from exisiting configuration files upon reboots.

#[derive(Serialize, Deserialize)]
pub struct VaultManager {
    version: usize,
    vaults: std::collections::HashMap<String, VaultInfo>,
    #[serde(skip)]
    unlocked_vaults: std::collections::HashMap<String, UnlockedVault>,
}

impl VaultManager {
    pub fn init() -> Result<Self, VaultError> {
        let project_dir = ProjectDirs::from("com.github", "realRudraP", "vault-rs")
            .expect("Failed to get project directory");
        let config_dir = project_dir.config_dir();

        // Check if the config directory exists, and containts the manifest file
        let manifest_path = config_dir.join(MANIFEST_FILENAME);
        if !manifest_path.exists() {
            // Print welcome banner
            Self::print_banner();
            println!("Welcome to Vault-rs! Your secure file vault.");
            println!(
                "It looks like your first time here! Creating a new configuration to get you started."
            );
            println!(
                "-------------------------------------------------------------------------------"
            );
            // Manifest file does not exist, create a new VaultManager

            let vault_manager = VaultManager {
                version: 1,
                vaults: std::collections::HashMap::new(),
                unlocked_vaults: std::collections::HashMap::new(),
            };

            // Serialize the vault manager to JSON
            let manifest_data =
                serde_json::to_string(&vault_manager).expect("Failed to serialize manifest");

            // Create the config directory if it doesn't exist
            std::fs::create_dir_all(config_dir)
                .expect("Failed to create config directory. Please check your permissions.");

            // Write the manifest data to the manifest file
            std::fs::write(manifest_path, manifest_data)
                .expect("Failed to write manifest file. Please check your permissions.");

            println!(
                "Vault initialized successfully. You can now use vault new <vault_name> to add your first vault!"
            );
            Ok(vault_manager)
        } else {
            // Manifest file exists, load the existing VaultManager
            let manifest_data =
                std::fs::read_to_string(&manifest_path).expect("Failed to read manifest file");
            let vault_manager: VaultManager =
                serde_json::from_str(&manifest_data).expect("Failed to deserialize manifest");
            println!(
                "Vault Manager initialized with existing configuration at {}.",
                manifest_path.display()
            );
            Ok(vault_manager)
        }
    }
    pub fn print_banner() {
        let welcome_banner = r#"
                
██╗   ██╗ █████╗ ██╗   ██╗██╗  ████████╗
██║   ██║██╔══██╗██║   ██║██║  ╚══██╔══╝
██║   ██║███████║██║   ██║██║     ██║   
╚██╗ ██╔╝██╔══██║██║   ██║██║     ██║   
 ╚████╔╝ ██║  ██║╚██████╔╝███████╗██║   
  ╚═══╝  ╚═╝  ╚═╝ ╚═════╝ ╚══════╝╚═╝   
         __      __                ____   ___
  ____ _/ /___  / /_  ____ _      / __ \ <  /
 / __ `/ / __ \/ __ \/ __ `/_____/ / / / / / 
/ /_/ / / /_/ / / / / /_/ /_____/ /_/ / / /  
\__,_/_/ .___/_/ /_/\__,_/      \____(_)_/   
      /_/                                                
"#;

        println!("{}", welcome_banner);
    }
    /*
        Core functionality of the VaultManager will go here.
        This includes methods to add, remove, and list vaults,
        as well as methods to open and close vaults.
    */

    pub fn list_vaults(&self) -> Result<Vec<String>, VaultError> {
        Ok(self.vaults.keys().cloned().collect())
    }
    pub fn add_vault(
        &mut self,
        name: &str,
        location: &str,
        options: std::collections::HashMap<String, String>,
        password: String,
    ) -> Result<(), VaultError> {
        if self.vaults.contains_key(name) {
            return Err(VaultError::VaultAlreadyExists);
        } else {
            let uri = URIParser::parse(&location)?;

            let storage = connect(&uri)?;

            let unlocked_vault: UnlockedVault = UnlockedVault::create(storage, &password)?;

            let vault_info = VaultInfo {
                id: uuid::Uuid::new_v4().to_string(),
                location: uri.uri,
                last_opened: std::time::SystemTime::now(),
                options,
            };
            self.vaults.insert(name.to_string(), vault_info);
            self.save_manifest(serde_json::to_string(&self).unwrap())?;
            Ok(())
        }
    }
    pub fn unlock_vault(&mut self, name: &str, password: &str) -> Result<SystemTime, VaultError> {
        let vault_info = self.vaults.get_mut(name).ok_or(VaultError::VaultNotFound)?;

        let uri = URIParser::parse(&vault_info.location)?;
        let storage = connect(&uri)?;
        let unlocked_vault = UnlockedVault::open(storage, password)?;

        // Insert the unlocked vault
        self.unlocked_vaults
            .insert(name.to_string(), unlocked_vault);

        // Update last opened
        let last_opened = vault_info.last_opened;
        println!("Vault was last opened at: {:?}", last_opened);
        vault_info.last_opened = SystemTime::now();

        // Save manifest safely
        let manifest =
            serde_json::to_string(&self).map_err(|_| VaultError::Serialization)?;
        self.save_manifest(manifest)?;

        Ok(last_opened)
    }

    pub fn save_manifest(&self, data: String) -> Result<(), VaultError> {
        let project_dir = ProjectDirs::from("com.github", "realRudraP", "vault-rs")
            .expect("Failed to get project directory");
        let config_dir = project_dir.config_dir();
        let manifest_path = config_dir.join(MANIFEST_FILENAME);
        // Write the manifest data to the manifest file
        std::fs::write(manifest_path, data).map_err(|e| VaultError::Io(e))?;
        Ok(())
    }

    pub fn import_file(
        &self,
        vault_name: &str,
        vault_path: &Path,
        content: &[u8],
    ) -> Result<(), VaultError> {
        if !self.vaults.contains_key(vault_name) {
            return Err(VaultError::VaultNotFound);
        }
        let vault = self
            .unlocked_vaults
            .get(vault_name)
            .ok_or(VaultError::VaultNotUnlocked)?;
        eprintln!(
            "(manager)Importing file into vault '{}': {}",
            vault_name,
            vault_path.display()
        );
        
        vault.import_file(content, vault_path)?;
        println!(
            "Successfully imported into {}:{}",
            vault_name,
            vault_path.display()
        );
        Ok(())
    }

    pub fn export_file(&self, vault_name: &str, vault_path: &Path) -> Result<Vec<u8>, VaultError> {
        let vault = self
            .unlocked_vaults
            .get(vault_name)
            .ok_or(VaultError::VaultNotFound)?;
        eprintln!(
            "(manager)Exporting file from vault '{}': {}",
            vault_name,
            vault_path.display()
        );
        let content = vault.export_file(vault_path)?;
        println!(
            "Successfully exported from {}:{}",
            vault_name,
            vault_path.display()
        );
        Ok(content)
    }

    pub fn list_files_from_vault(&self,vault_name: &str, path:&Path)->Result<Vec<String>,VaultError>{
        let vault= self
            .unlocked_vaults
            .get(vault_name)
            .ok_or(VaultError::VaultNotFound)?;
        vault.list_files(path)
    }
}

/// Helper functions for VaultManager go here

pub enum StorageLocations {
    Local(String),
    S3(String),
}
pub struct URIParser {
    // This struct will handle parsing of URIs for vaults
    pub uri: String,
    pub location: StorageLocations,
}
impl URIParser {
    fn parse(uri: &str) -> Result<Self, VaultError> {
        // Parse the URI and determine the location
        if uri.starts_with("local://") {
            let path = uri.trim_start_matches("local://").to_string();
            Ok(Self {
                uri: uri.to_string(),
                location: StorageLocations::Local(path),
            })
        } else if uri.starts_with("s3://") {
            let bucket = uri.trim_start_matches("s3://").to_string();
            Ok(Self {
                uri: uri.to_string(),
                location: StorageLocations::S3(bucket),
            })
        } else {
            Err(VaultError::InvalidURI)
        }
    }
}
