use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{BufReader, BufWriter};
use std::sync::Arc;
use tokio::sync::RwLock;
use base64::Engine;
use base64::engine::general_purpose;
use std::path::Path;
use serde::{Deserialize, Serialize};
use crate::models::KeyMetadata;
use crate::error::KmsError;

pub type KeyMap = Arc<RwLock<HashMap<String, Vec<u8>>>>;

#[derive(Serialize, Deserialize)]
struct KeyStore {
    keys: HashMap<String, String>, // key_id -> base64_encoded_key
    metadata: HashMap<String, KeyMetadata>, // key_id -> metadata
}

pub fn load_keys_from_file(path: &str) -> HashMap<String, Vec<u8>> {
    if !Path::new(path).exists() {
        return HashMap::new();
    }

    let file = match File::open(path) {
        Ok(file) => file,
        Err(e) => {
            tracing::error!("Failed to open key store: {}", e);
            return HashMap::new();
        }
    };
    
    let reader = BufReader::new(file);
    let key_store: KeyStore = serde_json::from_reader(reader).unwrap_or_else(|e| {
        tracing::warn!("Failed to parse key store, using empty store: {}", e);
        KeyStore {
            keys: HashMap::new(),
            metadata: HashMap::new(),
        }
    });
    
    key_store.keys.into_iter()
        .filter_map(|(k, v)| {
            let key_id = k.clone();
            general_purpose::STANDARD.decode(v)
                .map(|decoded| (k, decoded))
                .map_err(|e| tracing::error!("Failed to decode key {}: {}", key_id, e))
                .ok()
        })
        .collect()
}

pub fn save_keys_to_file(path: &str, data: &HashMap<String, Vec<u8>>) {
    let file = match OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(path) {
        Ok(file) => file,
        Err(e) => {
            tracing::error!("Failed to open key store for writing: {}", e);
            return;
        }
    };

    let writer = BufWriter::new(file);
    let encoded: HashMap<String, String> = data
        .iter()
        .map(|(k, v)| (k.clone(), general_purpose::STANDARD.encode(v)))
        .collect();

    let key_store = KeyStore {
        keys: encoded,
        metadata: HashMap::new(), // We'll handle metadata separately
    };

    if let Err(e) = serde_json::to_writer_pretty(writer, &key_store) {
        tracing::error!("Failed to write key store: {}", e);
    }
}

pub fn save_key_metadata(path: &str, metadata: &KeyMetadata) -> Result<(), KmsError> {
    let metadata_path = format!("{}.metadata", path);
    let file = OpenOptions::new()
        .create(true)
        .write(true)
        .append(true)
        .open(&metadata_path)?;

    let writer = BufWriter::new(file);
    serde_json::to_writer(writer, &metadata)?;
    Ok(())
}

pub fn load_key_metadata(path: &str, key_id: &str) -> Result<KeyMetadata, KmsError> {
    let metadata_path = format!("{}.metadata", path);
    if !Path::new(&metadata_path).exists() {
        return Err(KmsError::KeyNotFound(key_id.to_string()));
    }

    let file = File::open(&metadata_path)?;
    let reader = BufReader::new(file);
    let metadata: HashMap<String, KeyMetadata> = serde_json::from_reader(reader)?;
    
    metadata.get(key_id)
        .cloned()
        .ok_or_else(|| KmsError::KeyNotFound(key_id.to_string()))
}

pub fn load_all_metadata(path: &str) -> Result<HashMap<String, KeyMetadata>, KmsError> {
    let metadata_path = format!("{}.metadata", path);
    if !Path::new(&metadata_path).exists() {
        return Ok(HashMap::new());
    }

    let file = File::open(&metadata_path)?;
    let reader = BufReader::new(file);
    let metadata: HashMap<String, KeyMetadata> = serde_json::from_reader(reader)?;
    Ok(metadata)
}

pub fn update_key_metadata(path: &str, key_id: &str, metadata: &KeyMetadata) -> Result<(), KmsError> {
    let metadata_path = format!("{}.metadata", path);
    let mut all_metadata = load_all_metadata(path).unwrap_or_default();
    all_metadata.insert(key_id.to_string(), metadata.clone());
    
    let file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(&metadata_path)?;
    
    let writer = BufWriter::new(file);
    serde_json::to_writer_pretty(writer, &all_metadata)?;
    Ok(())
}

pub fn delete_key_metadata(path: &str, key_id: &str) -> Result<(), KmsError> {
    let metadata_path = format!("{}.metadata", path);
    let mut all_metadata = load_all_metadata(path).unwrap_or_default();
    all_metadata.remove(key_id);
    
    let file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(&metadata_path)?;
    
    let writer = BufWriter::new(file);
    serde_json::to_writer_pretty(writer, &all_metadata)?;
    Ok(())
}
