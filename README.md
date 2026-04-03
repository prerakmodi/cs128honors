# CLI Password Manager

## Group Name
RustyVault

## Group Members
Prerak Modi (pmodi26)

Suren Anbarchian (surensa2)

Rohan Hejmadi (hejmadi2)

Tanay Adbe (tadbe2)


## Project Introduction
Our project is a **Command Line Interface (CLI) Password Manager** built in Rust. Our password manager tool will allow users to securely store, retrieve, and manage their passwords from a terminal. The main objective of our project is to design a password manager that is both lightweight and secure without using a graphical interface. Our password manager allows users to securely add, view, delete, and search for stored passwords using a terminal. We have selected this project for a variety of reasons. Our project allows us to work with all aspects of computer systems, such as security, systems programming, and real-world usability. Our project also allows us to utilize the feature of rust.

## Technical Overview
The CLI Password Manager will consist of several core components:
### 1. Command Line Interface
- Parse user commands using a crate like 'clap'
- Support commands such as:
  - 'add' (store a password)
  - 'get' (retrieve a password)
  - 'delete' (remove a password)
  - 'list' (view stored entries)

### 2. Data Storage
- Store user credentials locally in a file 
- Use Rust’s file I/O system for reading and writing data
- Serialize and deserialize data using 'serde'

### 3. Encryption Layer
- Encrypt stored passwords using a cryptography crate 
- Protect access with a master password

### 4. Data Structures
- Use structs to represent credentials
- Use collections like 'HashMap' for efficient lookup

### 5. Error Handling
- Handle invalid inputs, missing files, and incorrect passwords gracefully
- Use Rust’s 'Result' and 'Option' types

## Checkpoint Goals
### Checkpoint 1 (4/13 – 4/17)
- Set up project structure and GitHub repository
- Implement basic CLI command parsing
- Implement file storage 
- Basic functionality for:
  - Adding entries
  - Listing entries
    
 ### Checkpoint 2 (4/27 – 5/1)
- Implement encryption and decryption for stored passwords
- Add password retrieval and deletion
- Improve error handling and input validation
- Begin polishing CLI user experience

### Final Submission (5/6)
- Fully functional password manager
- Master password protection
- Clean, well-documented code
- Search functionality
 
## Possible Challenges
Learning and correctly implementing encryption libraries
Managing file I/O safely without corrupting stored data
Handling Rust’s ownership and borrowing rules, especially with mutable data
Designing a clean and user-friendly CLI interface
Debugging serialization/deserialization issues with 'serde'

## References
Rust Documentation: https://doc.rust-lang.org/

`clap` crate for CLI parsing: https://docs.rs/clap/

`serde` for serialization: https://serde.rs/

Rust Crypto libraries (`ring`, `aes`)

Inspiration from existing password managers like Bitwarden and LastPass

