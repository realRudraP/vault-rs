use clap::{Parser, Subcommand};
use rustyline::DefaultEditor;
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    fs,
    path::{Component, Path, PathBuf},
};
use vault_core::core::{error::VaultError, manager::VaultManager};

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
                .add_vault(&name, &path, HashMap::new(), password)
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
                        // Extract filename from host_path and store in the current directory directory
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
#[command(name = "vault")]
#[command(no_binary_name = true)]
struct ShellCli {
    #[command(subcommand)]
    command: ShellCommands,
}

#[derive(Subcommand, Debug)]
enum ShellCommands {
    Unlock {
        #[arg(index = 1)]
        vault_name: String,
    },
    List,
    New {
        #[arg(index = 1, short, long)]
        vault_name: String,
        #[arg(short, long)]
        path: Option<String>,
    },
    Destroy {
        #[arg(index = 1, short, long)]
        vault_name: String,
    },
    Ls {
        path: Option<PathBuf>,
    },
    Cd {
        path: Option<PathBuf>,
    },
    Pwd,
    Mkdir {
        path: String,
        #[arg(short)]
        recursive: bool,
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
        path: PathBuf,
    },
    Cp {
        source: String,
        destination: String,
        #[arg(short, long)]
        recursive: bool,
    },
    Mv {
        source: PathBuf,
        destination: PathBuf,
    },
    Clear,
    Import {
        host_path: PathBuf,
        #[arg(short = 'v', long)]
        vault_name: Option<String>,
        #[arg(short = 'p', long)]
        vault_path: Option<PathBuf>,
    },
    Export {
        host_path: Option<PathBuf>,
        #[arg(short = 'v', long)]
        vault_name: Option<String>,
        #[arg(short = 'p', long)]
        vault_path: PathBuf,
    },
    Exit,
}

struct VaultShell {
    manager: VaultManager,
    current_dir: Option<PathBuf>,
    active_vault_name: Option<String>,
    is_running: bool,
}

impl VaultShell {
    fn new(manager: VaultManager) -> Self {
        VaultShell {
            manager,
            current_dir: None,
            active_vault_name: None,
            is_running: true,
        }
    }

    fn run(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        let mut rl = DefaultEditor::new()?;
        VaultManager::print_banner();

        while self.is_running {
            let prompt = match &self.active_vault_name {
            Some(name) => format!("{}:{}$ ", name, self.current_dir.as_ref().unwrap().display()),
            None => "vault> ".to_string(),
            };

            let line = rl.readline(&prompt)?;
            let trimmed = line.trim();

            // Skip empty lines
            if trimmed.is_empty() {
            continue;
            }
            rl.add_history_entry(trimmed)?;
            
            if let Ok(cli) = ShellCli::try_parse_from(trimmed.split_whitespace()) {
                if let Err(e) = self.execute_command(cli.command) {
                    match e {
                        VaultError::NoActiveVault => {
                            println!("ERROR: {}", e);
                            continue;
                        }
                        VaultError::ContinuingExecution => {
                            continue;
                        }
                        _ => {
                            println!("ERROR: {}", e);
                            break;
                        }
                    }
                }
            }
        }
        Ok(())
    }


    fn resolve_path(&self, path_str: &str) -> Result<PathBuf, VaultError> {
        eprintln!("Resolving path: {}", path_str);
        let current_dir = self.current_dir.as_ref().ok_or(VaultError::NoActiveVault)?;
        let input_path = Path::new(path_str);

        let mut resolved_path = if input_path.is_absolute() {
            PathBuf::from("/")
        } else {
            current_dir.clone()
        };

        for component in input_path.components() {
            match component {
                Component::Normal(name) => {
                    resolved_path.push(name);
                }
                Component::ParentDir => {
                    resolved_path.pop();
                }
                Component::CurDir => {
                    // Do nothing
                }
                Component::RootDir => {
                    resolved_path = PathBuf::from("/");
                }
                Component::Prefix(_) => {
                    return Err(VaultError::InvalidPath);
                }
            }
        }
        eprintln!("Resolved path: {}", resolved_path.display());
        Ok(resolved_path)
    }

    fn cmd_mkdir(
        &self,
        folder_name: &str,
        current_path: &Path,
        recursive: bool,
    ) -> Result<(), VaultError> {
        let vault = self
            .active_vault_name
            .as_ref()
            .ok_or(VaultError::NoActiveVault)?;
        self.manager
            .create_folder_in_vault(&vault, &current_path.join(folder_name), recursive)?;
        Ok(())
    }

    fn cmd_mv(&self, source: &PathBuf, destination: &PathBuf) -> Result<(), VaultError> {
        let vault = self
            .active_vault_name
            .as_ref()
            .ok_or(VaultError::NoActiveVault)?;
        self.manager.move_file(&vault, source, destination)?;
        Ok(())
    }

    fn cmd_rm(&self, file_name: &PathBuf, current_path: &Path) -> Result<(), VaultError> {
        let vault = self
            .active_vault_name
            .as_ref()
            .ok_or(VaultError::NoActiveVault)?;
        self.manager
            .delete_file(&vault, &current_path.join(file_name))?;
        Ok(())
    }

    fn cmd_unlock(&mut self, vault_name: &str) -> Result<(), VaultError> {
        if let Err(e) = self.manager.vault_exists_preflight(vault_name) {
            match e {
                VaultError::VaultManifestNotFound => {
                    eprintln!(
                        "Error: Vault '{}' is registered, but its files could not be found.",
                        vault_name
                    );
                    eprintln!(
                        "This can happen if the vault was moved, deleted, or is on a disconnected drive."
                    );

                    println!("\nWould you like to remove this vault's registration? [y/N]");

                    let mut input = String::new();
                    if std::io::stdin().read_line(&mut input).is_ok() {
                        if input.trim().eq_ignore_ascii_case("y") {
                            println!("Removing vault registration...");
                            match self.manager.remove_vault_registration(vault_name) {
                                Ok(_) => println!(
                                    "Successfully removed registration for '{}'.",
                                    vault_name
                                ),
                                Err(e) => eprintln!("Failed to remove registration: {:?}", e),
                            }
                        } else {
                            println!("No action taken. The registration was not removed.");
                        }
                    }
                }
                VaultError::VaultNotFound => {
                    eprintln!("Error: Vault '{}' is not registered.", vault_name);
                }
                _ => {
                    eprintln!("An unexpected error occurred: {:?}", e);
                }
            }
            return Ok(());
        }
        match rpassword::prompt_password("Enter the password for the vault: ") {
            Ok(password) => match self.manager.unlock_vault(vault_name, &password) {
                Ok(_) => {
                    self.active_vault_name = Some(vault_name.to_string());
                    self.current_dir = Some(PathBuf::from("/"));
                    println!("Vault '{}' unlocked successfully.", vault_name);
                }
                Err(e) => {
                    eprintln!("{}", e);
                    return Err(VaultError::ContinuingExecution);
                }
            },
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

    fn cmd_ls(&self, path: Option<&Path>) -> Result<(), VaultError> {
        let active_vault = match &self.active_vault_name {
            Some(name) => name,
            None => {
                return Err(VaultError::NoActiveVault);
            }
        };

        let path= match path {
            Some(p) => self.resolve_path(p.to_str().unwrap())?,
            None => self.current_dir.as_ref().ok_or(VaultError::NoActiveVault)?.clone(),
        };

        let files: Vec<String> = self.manager.list_files_from_vault(active_vault, &path)?;

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

    fn cmd_import(
        &mut self,
        host_path: &Path,
        vault_name: &str,
        vault_path: &Option<PathBuf>,
    ) -> Result<(), VaultError> {
        match self.active_vault_name {
            Some(ref _name) => {
                let content = std::fs::read(host_path).map_err(|_| {
                    VaultError::UnableToAccessLocation(host_path.to_string_lossy().to_string())
                })?;

                let final_vault_path = if let Some(path) = vault_path {
                    path
                } else {
                    self.current_dir.as_ref().ok_or(VaultError::NoActiveVault)?
                };
                let destination_path = final_vault_path.join(host_path.file_name().unwrap_or_else(|| std::ffi::OsStr::new("unnamed_file")));
                self.manager
                    .import_file(vault_name, &destination_path, &content)?;
                Ok(())
            }
            None => Err(VaultError::NoActiveVault),
        }
    }

    fn cmd_export(
        &mut self,
        vault_path: &Path,
        vault_name: &str,
        host_path: Option<PathBuf>,
    ) -> Result<(), VaultError> {
        match self.manager.export_file(vault_name, vault_path) {
            Ok(content) => {
                // Figure out a default filename
                let filename = vault_path
                    .file_name()
                    .unwrap_or_else(|| std::ffi::OsStr::new("exported_file"));

                // Resolve the host path
                let final_host_path = match host_path {
                    Some(path) => {
                        if path.is_dir() {
                            path.join(filename)
                        } else {
                            path
                        }
                    }
                    None => std::env::current_dir().unwrap().join(filename),
                };

                std::fs::write(&final_host_path, content).map_err(VaultError::Io)?;
                println!("File exported to {}", final_host_path.display());
                Ok(())
            }
            Err(e) => Err(e),
        }
    }

    fn cmd_new(&mut self, name: &str, path: &Option<String>) -> Result<(), VaultError> {
        let current_dir = std::env::current_dir()
            .expect("Failed to get current directory")
            .to_str()
            .unwrap()
            .to_string();
        let path = match path {
            Some(p) => {
                if !p.starts_with("local://") {
                    p
                } else {
                    eprintln!("Invalid path format. Use local://<path> for local files.");
                    return Err(VaultError::InvalidPath);
                }
            }
            None => &format!("local://{}", current_dir),
        };
        // Add a new vault with the provided name and path
        let password: String =
            rpassword::prompt_password("Enter vault password: ").expect("Failed to read password");
        let repeat_password: String =
            rpassword::prompt_password("Repeat vault password: ").expect("Failed to read password");
        if password != repeat_password {
            eprintln!("Passwords do not match. Please try again.");
            return Err(VaultError::Generic("Passwords do not match".to_string()));
        }
        println!("Adding vault '{}' at path '{}'", name, path);
        self.manager
            .add_vault(name, path, HashMap::new(), password)
            .expect("Failed to add vault");
        Ok(())
    }
    fn cmd_cd(&mut self, path: &PathBuf) ->Result<(), VaultError> {
        let final_path = self.resolve_path(path.to_str().unwrap())?;
        println!("Changing directory to: {}", final_path.display());
        self.current_dir = Some(final_path);
        println!(
            "Changed directory to: {}",
            self.current_dir.as_ref().unwrap().display()
        );
        Ok(())
    }

    fn cmd_destroy(&mut self, vault_name: &str) -> Result<(), VaultError> {
        println!(
            "! DANGER: You are about to permanently delete the vault '{}' and all of its contents.",
            vault_name
        );
        println!("! This action is irreversible.");
        println!(
            "! To confirm, please type the name of the vault ('{}'):",
            vault_name
        );
        let mut confirmation = String::new();
        std::io::stdin().read_line(&mut confirmation).unwrap();
        if confirmation.trim().eq(vault_name) {
            self.manager.delete_vault(vault_name)?;
            self.manager.remove_vault_registration(vault_name)?;
            println!("Vault '{}' has been deleted.", vault_name);
        } else {
            println!("Vault deletion cancelled.");
        }
        Ok(())
    }

    fn execute_command(&mut self, command: ShellCommands) -> Result<(), VaultError> {
        match command {
            ShellCommands::Unlock { vault_name } => {
                self.cmd_unlock(&vault_name)?;
            }
            ShellCommands::List => {
                self.cmd_list()?;
            }
            ShellCommands::Ls { path } => {
                if let Some(p) = &path {
                    eprintln!("Recieved Argument: {}", p.display());
                    self.cmd_ls(Some(p.as_path()))?;
                } else {
                    eprintln!("No path argument provided, using current directory.");
                    self.cmd_ls(Some(self.current_dir.as_ref().ok_or(VaultError::NoActiveVault)?.as_path()))?;
                }
            }
            ShellCommands::New { vault_name, path } => {
                self.cmd_new(&vault_name, &path)?;
            }
            ShellCommands::Import {
                host_path,
                vault_name,
                vault_path,
            } => {
                let name = if let Some(name) = vault_name {
                    name
                } else if let Some(name) = &self.active_vault_name {
                    name.clone()
                } else {
                    return Err(VaultError::NoActiveVault);
                };

                self.cmd_import(&host_path, &name, &vault_path)?;
            }
            ShellCommands::Export {
                host_path,
                vault_name,
                vault_path,
            } => {
                let name = if let Some(name) = vault_name {
                    name
                } else if let Some(name) = &self.active_vault_name {
                    name.clone()
                } else {
                    return Err(VaultError::NoActiveVault);
                };

                self.cmd_export(&vault_path, &name, host_path)?;
            }

            ShellCommands::Exit => {
                std::process::exit(0);
            }
            ShellCommands::Pwd => {
                println!(
                    "{}",
                    self.current_dir
                        .as_ref()
                        .ok_or(VaultError::NoActiveVault)?
                        .display()
                );
            }
            ShellCommands::Destroy { vault_name } => {
                self.cmd_destroy(&vault_name)?;
            }
            ShellCommands::Mkdir { path, recursive } => {
                self.cmd_mkdir(
                    &path,
                    &self.current_dir.as_ref().ok_or(VaultError::NoActiveVault)?,
                    recursive,
                )?;
            }
            ShellCommands::Rm { path } => {
                self.cmd_rm(&path, &self.current_dir.as_ref().ok_or(VaultError::NoActiveVault)?)
                    .map_err(|e| {
                        eprintln!("Error removing file: {}", e);
                        VaultError::ContinuingExecution
                    })?;
            }
            ShellCommands::Cd { path } => {
                let new_path = self.resolve_path(&path.unwrap().to_str().unwrap());
                // Here we would normally check if the directory exists in the vault
                self.cmd_cd(&new_path.unwrap())?;
            }
            ShellCommands::Mv {
                source,
                destination,
            } => {
                self.cmd_mv(&source, &destination)?;
            }
            _ => {
                eprintln!("Command not implemented yet: {:?}", command);
            }
        }
        Ok(())
    }
}
