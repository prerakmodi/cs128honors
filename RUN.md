# RUN.md — How to Run RustyVault

## Prerequisites

Make sure you have the following installed:

- [Git](https://git-scm.com/)
- [Rust](https://www.rust-lang.org/tools/install) (includes `cargo`)

To verify:
```bash
git --version
rustc --version
cargo --version
```

---

## Steps

### 1. Clone the repository

```bash
git clone https://github.com/prerakmodi/cs128honors.git
cd cs128honors/rustpass
```

### 2. Build and run the project

Use `cargo run` followed by a subcommand. The first time you run any command, you will be prompted to create a master password.

**Add a credential:**
```bash
cargo run -- add --service <service-name> --username <username>
```
Example:
```bash
cargo run -- add --service github --username alice
```

**Retrieve a credential:**
```bash
cargo run -- get <service-name>
```

**List all stored services:**
```bash
cargo run -- list
```

**Delete a credential:**
```bash
cargo run -- delete <service-name>
```

**Search for services by name:**
```bash
cargo run -- search <query>
```

---

## Notes

- On first run, you will be prompted to create and confirm a master password. This password is required for all future access.
- Your vault is stored in `rustpass/data/vault.json` and is encrypted with AES-256-GCM. Your master password is never stored in plaintext.
- Password input is hidden — characters will not appear as you type.
