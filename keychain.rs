use std::collections::HashMap;

pub struct Keychain {
    master_password: String,
    keychain: HashMap<String, String>,
}