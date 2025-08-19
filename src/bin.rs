use clap::{Parser, Subcommand};
use rustyline::DefaultEditor;
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    fs,
    path::{Path, PathBuf},
};
use vault_core::core::{error::VaultError, manager::VaultManager};
use zeroize::Zeroize;

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
    Import {
        host_path: String,
        #[arg(short = 'v', long)]
        vault_name: String,
        #[arg(short = 'p', long)]
        vault_path: Option<String>,
    },
    Export {
        vault_path: String,
        #[arg(short = 'v', long)]
        vault_name: String,
        #[arg(short = 'p', long)]
        host_path: String,
    },
    Shell,
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
        Commands::Import {
            host_path,
            vault_name,
            vault_path,
        } => {
            let password: String = rpassword::prompt_password("Enter vault password: ")
                .expect("Failed to read password");
            if manager.unlock_vault(&vault_name, &password).is_ok() {
                let content = fs::read(&host_path).expect("Failed to read file from host path");

                let vault_destination = match vault_path {
                    Some(path) => PathBuf::from(path),
                    None => {
                        // Extract filename from host_path and store in root directory
                        let host_file = std::path::Path::new(&host_path);
                        let filename = host_file
                            .file_name()
                            .expect("Invalid host path - no filename")
                            .to_str()
                            .expect("Invalid filename encoding");
                        PathBuf::from("/").join(filename)
                    }
                };

                if let Ok(()) = manager.import_file(&vault_name, &vault_destination, &content) {
                } else {
                    eprintln!("Failed to import file into vault '{}'.", vault_name);
                }
            } else {
                eprintln!(
                    "Failed to unlock vault '{}'. Please check the name and password.",
                    vault_name
                );
            }
        }
        Commands::Export {
            vault_path,
            vault_name,
            host_path,
        } => {
            let password: String = rpassword::prompt_password("Enter vault password: ")
                .expect("Failed to read password");
            let vault_path: PathBuf = PathBuf::from(vault_path);
            if manager.unlock_vault(&vault_name, &password).is_ok() {
                if let Ok(content) = manager.export_file(&vault_name, &vault_path) {
                    fs::write(&host_path, content).expect("Failed to write file to host path");
                } else {
                    eprintln!("Failed to export file from vault '{}'.", vault_name);
                }
            } else {
                eprintln!(
                    "Failed to unlock vault '{}'. Please check the name and password.",
                    vault_name
                );
            }
        }
        Commands::Shell => {
            let mut shell = VaultShell::new(manager);
            shell.run();
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
    Import {
        host_path: String,
        #[arg(short, long)]
        vault_name: String,
        #[arg(short, long)]
        vault_path: Option<String>,
    },
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
    active_vault_name: Option<String>,
    is_running: bool,
}

impl VaultShell {
    fn new(manager: VaultManager) -> Self {
        VaultShell {
            manager,
            current_dir: PathBuf::from("/"),
            history: Vec::new(),
            active_vault_name: None,
            is_running: true,
        }
    }

    fn run(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        let mut rl = DefaultEditor::new()?;
        VaultManager::print_banner();

        while self.is_running {
            let prompt = match &self.active_vault_name {
                Some(name) => format!("{}:{}$ ", name, self.current_dir.display()),
                None => "vault> ".to_string(),
            };

            let line = rl.readline(&prompt)?;
            let args: Vec<&str> = line.trim().split_whitespace().collect();
            if args.is_empty() {
                continue;
            }

            let command = args[0].to_lowercase();
            match command.as_str() {
                "unlock" => match self.cmd_unlock(args[1]) {
                    Ok(()) => {
                        println!("(orchestrator) Vault '{}' unlocked successfully.", args[1]);
                    }
                    Err(e) => {
                        eprintln!("ERROR: {}", e);
                    }
                },
                "list" => match self.cmd_list() {
                    Ok(()) => {
                        println!("(orchestrator) Vaults listed successfully.");
                    }
                    Err(e) => {
                        eprintln!("ERROR: {}", e);
                    }
                },
                "ls" => {
                    if !self.active_vault_name.is_some() {
                        eprintln!(
                            "ERROR: No vault is currently active. Please unlock a vault first."
                        );
                        continue;
                    }
                    let path = if let Some(arg)=args.get(1){
                        self.resolve_path(arg)
                    }else{
                        self.resolve_path(".")
                    };
                    match self.cmd_ls(&path) {
                        Ok(()) => {
                            println!("(orchestrator) Files listed successfully.");
                        }
                        Err(e) => {
                            eprintln!("ERROR: {}", e);
                        }
                    }
                }
                "exit" => {
                    println!("Exiting vault shell.");
                    self.is_running = false;
                }
                &_ => {
                    eprintln!("ERROR: Unknown command '{}'", command);
                }
            }
        }
        Ok(())
    }

    fn resolve_path(&self, path: &str) -> PathBuf {
        if path.starts_with("/") {
            PathBuf::from(path)
        } else if path == "." || path==""{
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

    fn cmd_unlock(&mut self, vault_name: &str) -> Result<(), VaultError> {
        match rpassword::prompt_password("Enter the password for the vault: ") {
            Ok(password) => {
                self.manager.unlock_vault(vault_name, &password)?;
                self.active_vault_name = Some(vault_name.to_string());
                self.current_dir = PathBuf::from("/");
                println!("Vault '{}' unlocked successfully.", vault_name);
            }
            Err(_) => {
                eprintln!("Failed to read password.");
            }
        }
        Ok(())
    }

    fn cmd_list(&self) -> Result<(), VaultError> {
        let vaults = self.manager.list_vaults()?;

        if vaults.is_empty() {
            println!("No vaults found.");
            return Ok(());
        }

        println!("Available vaults:");
        for (i, vault) in vaults.iter().enumerate() {
            println!("  {}. {}", i + 1, vault);
        }

        Ok(())
    }

    fn cmd_ls(&self, path: &Path) -> Result<(), VaultError> {
        let active_vault = match &self.active_vault_name {
            Some(name) => name,
            None => {
                eprintln!("ERROR: No vault is currently active. Please unlock a vault first.");
                return Err(VaultError::NoActiveVault);
            }
        };
        
        let files: Vec<String> = self.manager.list_files_from_vault(active_vault, path)?;

        if files.is_empty() {
            println!("No files found.");
        } else {
            println!("Files:");
            for file in files {
                println!("  - {}", file);
            }
        }

        Ok(())
    }

    fn execute_command(&mut self, command: ShellCommands) -> Result<(), VaultError> {
        Ok(())
    }
}
