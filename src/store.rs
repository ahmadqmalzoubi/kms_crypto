use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{BufReader, BufWriter};
use std::sync::Arc;
use tokio::sync::RwLock;
use base64::Engine;
use base64::engine::general_purpose;
use std::path::Path;

pub type KeyMap = Arc<RwLock<HashMap<String, Vec<u8>>>>;

pub fn load_keys_from_file(path: &str) -> HashMap<String, Vec<u8>> {
    if !Path::new(path).exists() {
        return HashMap::new();
    }

    let file = File::open(path).expect("Failed to open key store");
    let reader = BufReader::new(file);
    let raw: HashMap<String, String> = serde_json::from_reader(reader).unwrap_or_default();
    raw.into_iter()
        .map(|(k, v)| (k, general_purpose::STANDARD.decode(v).unwrap()))
        .collect()
}

pub fn save_keys_to_file(path: &str, data: &HashMap<String, Vec<u8>>) {
    let file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(path)
        .expect("Failed to open key store for writing");

    let writer = BufWriter::new(file);
    let encoded: HashMap<String, String> = data
        .iter()
        .map(|(k, v)| (k.clone(), general_purpose::STANDARD.encode(v)))
        .collect();

    serde_json::to_writer_pretty(writer, &encoded).expect("Failed to write key store");
}
