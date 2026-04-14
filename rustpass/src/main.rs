// Import Statements
use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::io::{self, Write};
use std::path::PathBuf;

#[derive(Debug, Serialize, Deserialize, Clone)]
struct Entry {
    service: String,
    username: String,
    password: String,
}

#[derive(Debug, Serialize, Deserialize, Default)]
struct Vault {
    entries: HashMap<String, Entry>,
}


#[derive(Parser, Debug)]
#[command(
    name = "rustpass",
    about = "RustyVault – a lightweight CLI password manager",
    version = "0.1.0"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    Add {
        #[arg(short, long)]
        service: String,
        #[arg(short, long)]
        username: String,
    },
    Get {
        service: String,
    },
    Delete {
        service: String,
    },
    List,
    Search {
        query: String,
    },
}

// Get path to vault file (data/vault.json)
fn vault_path() -> PathBuf {
    let mut path = std::env::current_dir().expect("Cannot determine current directory");
    path.push("data");
    fs::create_dir_all(&path).expect("Failed to create data directory");
    path.push("vault.json");
    path
}

// Load vault from file or return empty vault
fn load_vault(path: &PathBuf) -> Vault {
    match fs::read_to_string(path) {
        Ok(contents) => serde_json::from_str(&contents).unwrap_or_else(|e| {
            eprintln!("Warning: vault file is corrupt ({e}). Starting fresh.");
            Vault::default()
        }),
        Err(_) => Vault::default(),
    }
}

// Save vault data to file
fn save_vault(path: &PathBuf, vault: &Vault) {
    let json = serde_json::to_string_pretty(vault).expect("Failed to serialize vault");
    fs::write(path, json).expect("Failed to write vault file");
}

// Get path to master password file (.master)
fn master_path() -> PathBuf {
    let mut path = std::env::current_dir().expect("Cannot determine current directory");
    path.push("data");
    fs::create_dir_all(&path).expect("Failed to create data directory");
    path.push(".master");
    path
}

// Prompt user to enter a password
fn prompt_password(prompt: &str) -> String {
    print!("{}", prompt);
    io::stdout().flush().expect("Failed to flush stdout");
    let mut input = String::new();
    io::stdin().read_line(&mut input).expect("Failed to read input");
    input.trim_end_matches(|c| c == '\n' || c == '\r').to_string()
}

// Setup or verify master password
fn authenticate() -> bool {
    let mp = master_path();

    if !mp.exists() {
        // First-time setup
        println!("═══════════════════════════════════════════");
        println!("  Welcome to RustyVault! First-time setup  ");
        println!("═══════════════════════════════════════════");
        println!("Please create a master password.");
        println!("(This protects access to all your entries.)");

        let pw1 = prompt_password("New master password: ");
        let pw2 = prompt_password("Confirm master password: ");

        if pw1 != pw2 {
            eprintln!("Passwords do not match. Exiting.");
            return false;
        }
        if pw1.is_empty() {
            eprintln!("Master password cannot be empty. Exiting.");
            return false;
        }

        fs::write(&mp, &pw1).expect("Failed to save master password");
        println!("Master password set. You're all set!\n");
        true
    } else {
        let stored = fs::read_to_string(&mp).expect("Failed to read master password file");
        let entered = prompt_password("Master password: ");

        if entered == stored {
            true
        } else {
            eprintln!("Incorrect master password. Access denied.");
            false
        }
    }
}


// Add or update a credential entry
fn cmd_add(vault: &mut Vault, service: &str, username: &str) {
    let password = prompt_password(&format!("Password for '{service}': "));
    if password.is_empty() {
        eprintln!("Password cannot be empty.");
        return;
    }

    let entry = Entry {
        service: service.to_string(),
        username: username.to_string(),
        password,
    };

    let existed = vault.entries.contains_key(service);
    vault.entries.insert(service.to_string(), entry);

    if existed {
        println!("Entry for '{service}' updated.");
    } else {
        println!("Entry for '{service}' added.");
    }
}

// Retrieve and display a credential
fn cmd_get(vault: &Vault, service: &str) {
    match vault.entries.get(service) {
        Some(entry) => {
            println!("──────────────────────────────");
            println!("  Service:  {}", entry.service);
            println!("  Username: {}", entry.username);
            println!("  Password: {}", entry.password);
            println!("──────────────────────────────");
        }
        None => eprintln!("No entry found for '{service}'."),
    }
}

// Delete a credential entry
fn cmd_delete(vault: &mut Vault, service: &str) {
    if vault.entries.remove(service).is_some() {
        println!("Entry for '{service}' deleted.");
    } else {
        eprintln!("No entry found for '{service}'.");
    }
}

// List all stored services
fn cmd_list(vault: &Vault) {
    if vault.entries.is_empty() {
        println!("No entries stored yet. Use `rustpass add` to get started.");
        return;
    }
    println!("Stored services ({} total):", vault.entries.len());
    println!("──────────────────────────────");
    let mut services: Vec<&String> = vault.entries.keys().collect();
    services.sort();
    for s in services {
        let e = &vault.entries[s];
        println!("  {s}  (user: {})", e.username);
    }
    println!("──────────────────────────────");
}

// Search for services by name
fn cmd_search(vault: &Vault, query: &str) {
    let query_lower = query.to_lowercase();
    let matches: Vec<&Entry> = vault
        .entries
        .values()
        .filter(|e| e.service.to_lowercase().contains(&query_lower))
        .collect();

    if matches.is_empty() {
        println!("No entries matching '{query}'.");
        return;
    }
    println!("Results for '{query}' ({} match(es)):", matches.len());
    println!("──────────────────────────────");
    let mut sorted = matches;
    sorted.sort_by(|a, b| a.service.cmp(&b.service));
    for e in sorted {
        println!("  {}  (user: {})", e.service, e.username);
    }
    println!("──────────────────────────────");
}

// Main entry point: parse CLI, authenticate, run command
fn main() {
    let cli = Cli::parse();

    if !authenticate() {
        std::process::exit(1);
    }

    let path = vault_path();
    let mut vault = load_vault(&path);

    match &cli.command {
        Commands::Add { service, username } => {
            cmd_add(&mut vault, service, username);
            save_vault(&path, &vault);
        }
        Commands::Get { service } => {
            cmd_get(&vault, service);
        }
        Commands::Delete { service } => {
            cmd_delete(&mut vault, service);
            save_vault(&path, &vault);
        }
        Commands::List => {
            cmd_list(&vault);
        }
        Commands::Search { query } => {
            cmd_search(&vault, query);
        }
    }
}
