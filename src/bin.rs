use clap::{Parser, Subcommand};
use rustyline::DefaultEditor;
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    path::{Path, PathBuf},
};
use vault_core::{VaultError, VaultManager};
#[derive(Parser, Debug)]
#[command(name = "vault")]
#[command(about= "A secure file vault.",long_about=None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    New {
        #[arg(short, long, help = "Name of the vault to add")]
        name: String,
        #[arg(
            short,
            long,
            help = "(Optional) Local path to the vault. Use local://<path> format for local files"
        )]
        path: Option<String>,
    },
    List,
    Unlock {
        #[arg(short, long, help = "Name of the vault to unlock")]
        name: String,
    },
}

// Represents a vault in the Vault directory
#[derive(Debug, Serialize, Deserialize)]
pub struct VaultDirInfo {
    id: String,
    uri: String,
    last_opened: Option<std::time::SystemTime>,
    options: HashMap<String, String>,
}
#[derive(Debug, Serialize, Deserialize)]
pub struct VaultDirectory {
    version: usize,
    vaults: HashMap<String, VaultDirInfo>,
}
fn main() {
    let mut manager = VaultManager::init().expect("Failed to initialize VaultManager");
    let cli = Cli::parse();
    let current_dir = std::env::current_dir().expect("Failed to get current directory");
    println!("Current directory: {}", current_dir.display());
    match cli.command {
        Commands::New { name, path } => {
            let path = match path {
                Some(p) => {
                    if !p.starts_with("local://") {
                        p
                    } else {
                        eprintln!("Invalid path format. Use local://<path> for local files.");
                        return;
                    }
                }
                None => {
                    format!("local://{}", current_dir.display())
                }
            };
            // Add a new vault with the provided name and path
            let password: String = rpassword::prompt_password("Enter vault password: ")
                .expect("Failed to read password");
            let repeat_password: String = rpassword::prompt_password("Repeat vault password: ")
                .expect("Failed to read password");
            if password != repeat_password {
                eprintln!("Passwords do not match. Please try again.");
                return;
            }
            println!("Adding vault '{}' at path '{}'", name, path);
            manager
                .add_vault(name, path, HashMap::new(), password)
                .expect("Failed to add vault");
        }
        Commands::List => {
            let vaults = manager.list_vaults().expect("Failed to list vaults");
            for vault in vaults {
                println!("Vault Name: {}", vault);
            }
        }
        Commands::Unlock { name } => {
            let password: String = rpassword::prompt_password("Enter vault password: ")
                .expect("Failed to read password");
            if manager.unlock_vault(&name, &password).is_ok() {
                eprintln!("This feature is not implemented yet.");
            } else {
                eprintln!(
                    "Failed to unlock vault '{}'. Please check the name and password.",
                    name
                );
            }
        }
    }
}

#[derive(Parser, Debug)]
#[command(name = "interactive-vault")]
#[command(no_binary_name = true)]
struct ShellCli {
    #[command(subcommand)]
    command: ShellCommands,
}

#[derive(Subcommand, Debug)]
enum ShellCommands {
    Ls {
        #[arg(default_value = ".")]
        path: String,
    },
    Cd {
        #[arg(default_value = ".")]
        path: String,
    },
    Pwd,
    Mkdir {
        path: String,
        #[arg(short, long)]
        parents: bool,
    },
    Rmdir {
        path: String,
        #[arg(short, long)]
        recursive: bool,
    },
    Touch {
        path: String,
    },
    Rm {
        path: String,
        #[arg(short, long)]
        force: bool,
        #[arg(short, long)]
        recursive: bool,
    },
    Cp {
        source: String,
        destination: String,
        #[arg(short, long)]
        recursive: bool,
    },
    Mv {
        source: String,
        destination: String,
        #[arg(short, long)]
        recursive: bool,
    },
    Clear,
    Help {
        command: Option<String>,
    },
    Exit {
        #[arg(default_value = "0")]
        code: i32,
    },
}

struct VaultShell {
    manager: VaultManager,
    current_dir: PathBuf,
    history: Vec<String>,
    vault_name: String,
}

impl VaultShell {
    fn new(manager: VaultManager, vault_name: String) -> Self {
        VaultShell {
            manager,
            current_dir: PathBuf::from("/"),
            history: Vec::new(),
            vault_name,
        }
    }

    fn resolve_path(&self, path: &str) -> PathBuf {
        if path.starts_with("/") {
            PathBuf::from(path)
        } else if path == "." {
            self.current_dir.clone()
        } else if path == ".." {
            self.current_dir
                .parent()
                .unwrap_or(&self.current_dir)
                .to_path_buf()
        } else {
            self.current_dir.join(path)
        }
    }

    fn cmd_ls(&self, path: &str, long: bool, all: bool, recursive: bool) -> Result<(), VaultError> {
        let resolved_path = self.resolve_path(path);
        Ok(())
    }

    fn execute_command(&mut self, command: ShellCommands) -> Result<(), VaultError> {
        Ok(())
    }
}
