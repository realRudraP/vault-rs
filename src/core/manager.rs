/*
    The Vault Manager struct is responsible for managing all the vaults in the system.
    It provides methods to add, remove, and list vaults, as well as to initialize
    the vault directory.
    The VaultInfo struct represents a single vault's information, including its ID,
    URI, last opened time, and options.
 */



use crate::core::error::VaultError;
use crate::core::storage::{self, connect, StorageBackend};
use crate::core::vault::UnlockedVault;
use directories_next::ProjectDirs;
use crate::core::crypto::SecureKey;
use serde::{ser, Deserialize, Serialize};


const MANIFEST_FILENAME: &str = "vault-rs.manifest.json";
// Individual vault information is stored in the VaultInfo struct.

#[derive(Serialize,Deserialize)]
struct VaultInfo{
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

#[derive(Serialize,Deserialize)]
pub struct VaultManager{
    version: usize,
    vaults: std::collections::HashMap<String, VaultInfo>,
    #[serde(skip)]
    unlocked_vaults: std::collections::HashMap<String, UnlockedVault>,
}

impl VaultManager {
   pub fn init()->Result<Self,VaultError>{
        let project_dir=ProjectDirs::from("com.github", "realRudraP", "vault-rs").expect("Failed to get project directory");
        let config_dir= project_dir.config_dir();

        // Check if the config directory exists, and containts the manifest file
        let manifest_path = config_dir.join(MANIFEST_FILENAME);
        if !manifest_path.exists() {
            // Print welcome banner
            let welcome_banner=r#"
                
____   ____            .__   __                           
\   \ /   /____   __ __|  |_/  |_          _______  ______
 \   Y   /\__  \ |  |  \  |\   __\  ______ \_  __ \/  ___/
  \     /  / __ \|  |  /  |_|  |   /_____/  |  | \/\___ \ 
   \___/  (____  /____/|____/__|            |__|  /____  >
               \/                                      \/ 
"#;

            println!("{}", welcome_banner);
            println!("Welcome to Vault-rs! Your secure file vault.");
            println!("It looks like your first time here! Creating a new configuration to get you started.");
            println!("-------------------------------------------------------------------------------");
            // Manifest file does not exist, create a new VaultManager

            let vault_manager = VaultManager {
                version: 1,
                vaults: std::collections::HashMap::new(),
                unlocked_vaults: std::collections::HashMap::new(),
                
            };

            // Serialize the vault manager to JSON
            let manifest_data = serde_json::to_string(&vault_manager).expect("Failed to serialize manifest");

            // Create the config directory if it doesn't exist
            std::fs::create_dir_all(config_dir).expect("Failed to create config directory. Please check your permissions.");

            // Write the manifest data to the manifest file
            std::fs::write(manifest_path, manifest_data).expect("Failed to write manifest file. Please check your permissions.");

            println!("Vault initialized successfully. You can now use vault new <vault_name> to add your first vault!");
            Ok(vault_manager)
        } else {
            // Manifest file exists, load the existing VaultManager
            let manifest_data = std::fs::read_to_string(&manifest_path).expect("Failed to read manifest file");
            let vault_manager: VaultManager = serde_json::from_str(&manifest_data).expect("Failed to deserialize manifest");
            println!("Vault Manager initialized with existing configuration at {}.", manifest_path.display());
            Ok(vault_manager)
        }

   }    




   /* 
        Core functionality of the VaultManager will go here.
        This includes methods to add, remove, and list vaults,
        as well as methods to open and close vaults.
    */

    pub fn list_vaults(&self) -> Result<Vec<String>, VaultError> {
        Ok(self.vaults.keys().cloned().collect())
    }
    pub fn add_vault(&mut self, name: String, location: String, options: std::collections::HashMap<String,String>,password:String)->Result<(), VaultError> {
        if self.vaults.contains_key(name.as_str()){
            return Err(VaultError::VaultAlreadyExists);
        }else{
            let uri= URIParser::parse(&location)?;

            let storage = connect(&uri)?;

            let unlocked_vault:UnlockedVault= UnlockedVault::create(storage,&password)?;

            let vault_info = VaultInfo {
                id: uuid::Uuid::new_v4().to_string(),
                location: uri.uri,
                last_opened: std::time::SystemTime::now(),
                options,
            };
            self.vaults.insert(name, vault_info);
            self.save_manifest(serde_json::to_string(&self).unwrap())?;
            Ok(())
        }
    }
    pub fn unlock_vault(&mut self, name: &str, password: &str) -> Result<bool, VaultError> {
        if let Some(vault_info) = self.vaults.get(name) {
            let uri = URIParser::parse(&vault_info.location)?;
            let storage = connect(&uri)?;
            let unlocked_vault = UnlockedVault::open(storage, password)?;
            self.unlocked_vaults.insert(name.to_string(), unlocked_vault);
            // Update the last opened time
            if let Some(vault_info) = self.vaults.get_mut(name) {
                vault_info.last_opened = std::time::SystemTime::now();
            }
            // Save the updated manifest
            self.save_manifest(serde_json::to_string(&self).unwrap())?;
            println!("Vault '{}' unlocked successfully.", name);
            // Update the content and metadata keys
            Ok(true)
        } else {
            Err(VaultError::VaultNotFound)
        }
    }
    
    pub fn save_manifest(&self, data:String) -> Result<(), VaultError> {
        let project_dir = ProjectDirs::from("com.github", "realRudraP", "vault-rs")
            .expect("Failed to get project directory");
        let config_dir = project_dir.config_dir();
        let manifest_path = config_dir.join(MANIFEST_FILENAME);
        // Write the manifest data to the manifest file
        std::fs::write(manifest_path, data).map_err(|e| VaultError::Io(e))?;
        Ok(())
}
}


// Helper functions for VaultManager go here

pub enum StorageLocations{
    Local(String),
    S3(String),
}
pub struct URIParser{
    // This struct will handle parsing of URIs for vaults
    pub uri: String,
    pub location: StorageLocations,
}
impl URIParser{
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


