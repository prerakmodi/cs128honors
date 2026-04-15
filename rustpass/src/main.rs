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

// Insert or update an entry in the vault; returns true if it was a new entry
fn add_entry(vault: &mut Vault, service: &str, username: &str, password: &str) -> bool {
    let entry = Entry {
        service: service.to_string(),
        username: username.to_string(),
        password: password.to_string(),
    };
    let is_new = !vault.entries.contains_key(service);
    vault.entries.insert(service.to_string(), entry);
    is_new
}

// Add or update a credential entry
fn cmd_add(vault: &mut Vault, service: &str, username: &str) {
    let password = prompt_password(&format!("Password for '{service}': "));
    if password.is_empty() {
        eprintln!("Password cannot be empty.");
        return;
    }

    let is_new = add_entry(vault, service, username, &password);
    if is_new {
        println!("Entry for '{service}' added.");
    } else {
        println!("Entry for '{service}' updated.");
    }
}

// Retrieve and display a credential
fn cmd_get(vault: &Vault, service: &str, out: &mut impl Write) {
    match vault.entries.get(service) {
        Some(entry) => {
            writeln!(out, "──────────────────────────────").unwrap();
            writeln!(out, "  Service:  {}", entry.service).unwrap();
            writeln!(out, "  Username: {}", entry.username).unwrap();
            writeln!(out, "  Password: {}", entry.password).unwrap();
            writeln!(out, "──────────────────────────────").unwrap();
        }
        None => eprintln!("No entry found for '{service}'."),
    }
}

// Delete a credential entry
fn cmd_delete(vault: &mut Vault, service: &str, out: &mut impl Write) {
    if vault.entries.remove(service).is_some() {
        writeln!(out, "Entry for '{service}' deleted.").unwrap();
    } else {
        eprintln!("No entry found for '{service}'.");
    }
}

// List all stored services
fn cmd_list(vault: &Vault, out: &mut impl Write) {
    if vault.entries.is_empty() {
        writeln!(out, "No entries stored yet. Use `rustpass add` to get started.").unwrap();
        return;
    }
    writeln!(out, "Stored services ({} total):", vault.entries.len()).unwrap();
    writeln!(out, "──────────────────────────────").unwrap();
    let mut services: Vec<&String> = vault.entries.keys().collect();
    services.sort();
    for s in services {
        let e = &vault.entries[s];
        writeln!(out, "  {s}  (user: {})", e.username).unwrap();
    }
    writeln!(out, "──────────────────────────────").unwrap();
}

// Search for services by name
fn cmd_search(vault: &Vault, query: &str, out: &mut impl Write) {
    let query_lower = query.to_lowercase();
    let matches: Vec<&Entry> = vault
        .entries
        .values()
        .filter(|e| e.service.to_lowercase().contains(&query_lower))
        .collect();

    if matches.is_empty() {
        writeln!(out, "No entries matching '{query}'.").unwrap();
        return;
    }
    writeln!(out, "Results for '{query}' ({} match(es)):", matches.len()).unwrap();
    writeln!(out, "──────────────────────────────").unwrap();
    let mut sorted = matches;
    sorted.sort_by(|a, b| a.service.cmp(&b.service));
    for e in sorted {
        writeln!(out, "  {}  (user: {})", e.service, e.username).unwrap();
    }
    writeln!(out, "──────────────────────────────").unwrap();
}

// Main entry point: parse CLI, authenticate, run command
fn main() {
    let cli = Cli::parse();

    if !authenticate() {
        std::process::exit(1);
    }

    let path = vault_path();
    let mut vault = load_vault(&path);
    let stdout = &mut io::stdout();

    match &cli.command {
        Commands::Add { service, username } => {
            cmd_add(&mut vault, service, username);
            save_vault(&path, &vault);
        }
        Commands::Get { service } => {
            cmd_get(&vault, service, stdout);
        }
        Commands::Delete { service } => {
            cmd_delete(&mut vault, service, stdout);
            save_vault(&path, &vault);
        }
        Commands::List => {
            cmd_list(&vault, stdout);
        }
        Commands::Search { query } => {
            cmd_search(&vault, query, stdout);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::fs;

    // Helpers

    fn temp_path(filename: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!("rustpass_test_{}_{}", std::process::id(), filename));
        p
    }

    fn vault_with(entries: &[(&str, &str, &str)]) -> Vault {
        let mut v = Vault::default();
        for (service, username, password) in entries {
            add_entry(&mut v, service, username, password);
        }
        v
    }

    fn output_str(f: impl FnOnce(&mut Vec<u8>)) -> String {
        let mut buf: Vec<u8> = Vec::new();
        f(&mut buf);
        String::from_utf8(buf).unwrap()
    }

    // load_vault tests

    #[test]
    fn load_vault_nonexistent_file_returns_empty() {
        let path = temp_path("nonexistent.json");
        let vault = load_vault(&path);
        assert!(vault.entries.is_empty());
    }

    #[test]
    fn load_vault_valid_json_returns_entries() {
        let path = temp_path("valid.json");
        let json = r#"{"entries":{"github":{"service":"github","username":"alice","password":"s3cr3t"}}}"#;
        fs::write(&path, json).unwrap();

        let vault = load_vault(&path);
        assert_eq!(vault.entries.len(), 1);
        let e = &vault.entries["github"];
        assert_eq!(e.service, "github");
        assert_eq!(e.username, "alice");
        assert_eq!(e.password, "s3cr3t");

        fs::remove_file(&path).ok();
    }

    #[test]
    fn load_vault_corrupt_json_returns_empty() {
        let path = temp_path("corrupt.json");
        fs::write(&path, b"not valid json at all!!!").unwrap();

        let vault = load_vault(&path);
        assert!(vault.entries.is_empty());

        fs::remove_file(&path).ok();
    }

    #[test]
    fn load_vault_empty_file_returns_empty() {
        let path = temp_path("empty.json");
        fs::write(&path, b"").unwrap();

        let vault = load_vault(&path);
        assert!(vault.entries.is_empty());

        fs::remove_file(&path).ok();
    }

    // save_vault tests

    #[test]
    fn save_vault_creates_valid_json_file() {
        let path = temp_path("save_test.json");
        let vault = vault_with(&[("github", "alice", "s3cr3t")]);

        save_vault(&path, &vault);

        let contents = fs::read_to_string(&path).unwrap();
        assert!(contents.contains("github"));
        assert!(contents.contains("alice"));
        assert!(contents.contains("s3cr3t"));

        fs::remove_file(&path).ok();
    }

    #[test]
    fn save_then_load_round_trips_correctly() {
        let path = temp_path("roundtrip.json");
        let original = vault_with(&[
            ("github", "alice", "pass1"),
            ("aws", "bob", "pass2"),
        ]);

        save_vault(&path, &original);
        let loaded = load_vault(&path);

        assert_eq!(loaded.entries.len(), 2);
        assert_eq!(loaded.entries["github"].username, "alice");
        assert_eq!(loaded.entries["aws"].password, "pass2");

        fs::remove_file(&path).ok();
    }

    #[test]
    fn save_vault_empty_vault_produces_valid_json() {
        let path = temp_path("empty_vault.json");
        let vault = Vault::default();

        save_vault(&path, &vault);

        let loaded = load_vault(&path);
        assert!(loaded.entries.is_empty());

        fs::remove_file(&path).ok();
    }

    // add_entry tests

    #[test]
    fn add_entry_new_returns_true_and_inserts() {
        let mut vault = Vault::default();
        let is_new = add_entry(&mut vault, "github", "alice", "pass");
        assert!(is_new);
        assert_eq!(vault.entries.len(), 1);
        assert_eq!(vault.entries["github"].username, "alice");
        assert_eq!(vault.entries["github"].password, "pass");
    }

    #[test]
    fn add_entry_duplicate_returns_false_and_updates() {
        let mut vault = Vault::default();
        add_entry(&mut vault, "github", "alice", "old_pass");
        let is_new = add_entry(&mut vault, "github", "alice", "new_pass");
        assert!(!is_new);
        assert_eq!(vault.entries.len(), 1);
        assert_eq!(vault.entries["github"].password, "new_pass");
    }

    #[test]
    fn add_entry_multiple_services_all_stored() {
        let mut vault = Vault::default();
        add_entry(&mut vault, "github", "alice", "p1");
        add_entry(&mut vault, "aws", "bob", "p2");
        add_entry(&mut vault, "gmail", "charlie", "p3");
        assert_eq!(vault.entries.len(), 3);
    }

    #[test]
    fn add_entry_update_preserves_other_entries() {
        let mut vault = vault_with(&[("github", "alice", "p1"), ("aws", "bob", "p2")]);
        add_entry(&mut vault, "github", "alice", "new_pass");
        assert_eq!(vault.entries["aws"].password, "p2");
    }

    #[test]
    fn add_entry_service_key_is_case_sensitive() {
        let mut vault = Vault::default();
        add_entry(&mut vault, "GitHub", "alice", "p1");
        add_entry(&mut vault, "github", "bob", "p2");
        assert_eq!(vault.entries.len(), 2);
    }

    // cmd_get tests

    #[test]
    fn cmd_get_existing_entry_prints_all_fields() {
        let vault = vault_with(&[("github", "alice", "s3cr3t")]);
        let out = output_str(|buf| cmd_get(&vault, "github", buf));
        assert!(out.contains("github"));
        assert!(out.contains("alice"));
        assert!(out.contains("s3cr3t"));
    }

    #[test]
    fn cmd_get_missing_entry_produces_no_output() {
        let vault = Vault::default();
        let out = output_str(|buf| cmd_get(&vault, "nonexistent", buf));
        assert!(out.is_empty());
    }

    #[test]
    fn cmd_get_does_not_modify_vault() {
        let vault = vault_with(&[("github", "alice", "pass")]);
        let count_before = vault.entries.len();
        let mut buf: Vec<u8> = Vec::new();
        cmd_get(&vault, "github", &mut buf);
        assert_eq!(vault.entries.len(), count_before);
    }

    // cmd_delete tests

    #[test]
    fn cmd_delete_existing_entry_removes_it() {
        let mut vault = vault_with(&[("github", "alice", "pass")]);
        let mut buf: Vec<u8> = Vec::new();
        cmd_delete(&mut vault, "github", &mut buf);
        assert!(!vault.entries.contains_key("github"));
    }

    #[test]
    fn cmd_delete_existing_entry_prints_confirmation() {
        let mut vault = vault_with(&[("github", "alice", "pass")]);
        let out = output_str(|buf| cmd_delete(&mut vault, "github", buf));
        assert!(out.contains("deleted"));
    }

    #[test]
    fn cmd_delete_missing_entry_produces_no_output() {
        let mut vault = Vault::default();
        let out = output_str(|buf| cmd_delete(&mut vault, "nonexistent", buf));
        assert!(out.is_empty());
    }

    #[test]
    fn cmd_delete_only_removes_target_entry() {
        let mut vault = vault_with(&[("github", "alice", "p1"), ("aws", "bob", "p2")]);
        let mut buf: Vec<u8> = Vec::new();
        cmd_delete(&mut vault, "github", &mut buf);
        assert!(!vault.entries.contains_key("github"));
        assert!(vault.entries.contains_key("aws"));
    }

    #[test]
    fn cmd_delete_same_entry_twice_no_panic() {
        let mut vault = vault_with(&[("github", "alice", "pass")]);
        let mut buf: Vec<u8> = Vec::new();
        cmd_delete(&mut vault, "github", &mut buf);
        cmd_delete(&mut vault, "github", &mut buf);
        assert!(vault.entries.is_empty());
    }

    // cmd_list tests

    #[test]
    fn cmd_list_empty_vault_prints_empty_message() {
        let vault = Vault::default();
        let out = output_str(|buf| cmd_list(&vault, buf));
        assert!(out.contains("No entries"));
    }

    #[test]
    fn cmd_list_single_entry_shows_service_and_username() {
        let vault = vault_with(&[("github", "alice", "pass")]);
        let out = output_str(|buf| cmd_list(&vault, buf));
        assert!(out.contains("github"));
        assert!(out.contains("alice"));
    }

    #[test]
    fn cmd_list_multiple_entries_all_appear() {
        let vault = vault_with(&[
            ("github", "alice", "p1"),
            ("aws", "bob", "p2"),
            ("gmail", "charlie", "p3"),
        ]);
        let out = output_str(|buf| cmd_list(&vault, buf));
        assert!(out.contains("github"));
        assert!(out.contains("aws"));
        assert!(out.contains("gmail"));
    }

    #[test]
    fn cmd_list_output_is_sorted_alphabetically() {
        let vault = vault_with(&[("zebra", "u1", "p1"), ("alpha", "u2", "p2"), ("mango", "u3", "p3")]);
        let out = output_str(|buf| cmd_list(&vault, buf));
        let pos_alpha = out.find("alpha").unwrap();
        let pos_mango = out.find("mango").unwrap();
        let pos_zebra = out.find("zebra").unwrap();
        assert!(pos_alpha < pos_mango && pos_mango < pos_zebra);
    }

    #[test]
    fn cmd_list_shows_total_count() {
        let vault = vault_with(&[("github", "a", "p"), ("aws", "b", "p")]);
        let out = output_str(|buf| cmd_list(&vault, buf));
        assert!(out.contains('2'));
    }

    #[test]
    fn cmd_list_does_not_reveal_passwords() {
        let vault = vault_with(&[("github", "alice", "supersecret")]);
        let out = output_str(|buf| cmd_list(&vault, buf));
        assert!(!out.contains("supersecret"));
    }

    // cmd_search tests

    #[test]
    fn cmd_search_exact_match_found() {
        let vault = vault_with(&[("github", "alice", "pass")]);
        let out = output_str(|buf| cmd_search(&vault, "github", buf));
        assert!(out.contains("github"));
        assert!(out.contains("alice"));
    }

    #[test]
    fn cmd_search_partial_match_found() {
        let vault = vault_with(&[("github", "alice", "pass"), ("gitlab", "bob", "pass2")]);
        let out = output_str(|buf| cmd_search(&vault, "git", buf));
        assert!(out.contains("github"));
        assert!(out.contains("gitlab"));
    }

    #[test]
    fn cmd_search_case_insensitive() {
        let vault = vault_with(&[("GitHub", "alice", "pass")]);
        let out = output_str(|buf| cmd_search(&vault, "github", buf));
        assert!(out.contains("GitHub"));
    }

    #[test]
    fn cmd_search_no_match_prints_no_entries_message() {
        let vault = vault_with(&[("github", "alice", "pass")]);
        let out = output_str(|buf| cmd_search(&vault, "aws", buf));
        assert!(out.contains("No entries"));
    }

    #[test]
    fn cmd_search_empty_vault_prints_no_entries_message() {
        let vault = Vault::default();
        let out = output_str(|buf| cmd_search(&vault, "anything", buf));
        assert!(out.contains("No entries"));
    }

    #[test]
    fn cmd_search_results_are_sorted_alphabetically() {
        let vault = vault_with(&[
            ("zebra-app", "u1", "p1"),
            ("alpha-app", "u2", "p2"),
            ("mango-app", "u3", "p3"),
        ]);
        let out = output_str(|buf| cmd_search(&vault, "app", buf));
        let pos_alpha = out.find("alpha-app").unwrap();
        let pos_mango = out.find("mango-app").unwrap();
        let pos_zebra = out.find("zebra-app").unwrap();
        assert!(pos_alpha < pos_mango && pos_mango < pos_zebra);
    }

    #[test]
    fn cmd_search_shows_match_count() {
        let vault = vault_with(&[("github", "a", "p"), ("gitlab", "b", "p")]);
        let out = output_str(|buf| cmd_search(&vault, "git", buf));
        assert!(out.contains('2'));
    }

    #[test]
    fn cmd_search_does_not_reveal_passwords() {
        let vault = vault_with(&[("github", "alice", "supersecret")]);
        let out = output_str(|buf| cmd_search(&vault, "github", buf));
        assert!(!out.contains("supersecret"));
    }

    #[test]
    fn cmd_search_does_not_modify_vault() {
        let vault = vault_with(&[("github", "alice", "pass")]);
        let count_before = vault.entries.len();
        let mut buf: Vec<u8> = Vec::new();
        cmd_search(&vault, "github", &mut buf);
        assert_eq!(vault.entries.len(), count_before);
    }
}
