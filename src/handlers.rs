use axum::{Json, extract::State, http::StatusCode};
use uuid::Uuid;
use rand::{RngCore, thread_rng};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use aes_gcm::aead::{Aead, KeyInit};
use base64::Engine;
use base64::engine::general_purpose;
use crate::store::{save_keys_to_file, KeyMap, save_key_metadata, load_key_metadata};
use crate::models::*;
use crate::config::AppConfig;
use rsa::{RsaPrivateKey, RsaPublicKey, pkcs8::{EncodePublicKey, EncodePrivateKey, DecodePrivateKey, DecodePublicKey}};
use std::fs::{create_dir_all, write, read_to_string};
use std::sync::Arc;
use tracing::{info, error, instrument};
use validator::Validate;
use chrono::Utc;

#[derive(Clone)]
pub struct AppState {
    pub keys: KeyMap,
    pub config: Arc<AppConfig>,
}

#[instrument]
pub async fn health_check() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "healthy".to_string(),
        timestamp: Utc::now(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        uptime: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    })
}

#[instrument(skip(state))]
pub async fn generate_key(State(state): State<AppState>) -> Result<Json<KeyResponse>, (StatusCode, String)> {
    info!("Generating new symmetric key");
    
    let mut key = vec![0u8; 32];
    thread_rng().fill_bytes(&mut key);

    let key_id = Uuid::new_v4().to_string();
    let now = Utc::now();
    let expires_at = Some(now + chrono::Duration::days(state.config.security.key_expiration_days as i64));
    
    // Save key and metadata
    {
        let mut keys = state.keys.write().await;
        keys.insert(key_id.clone(), key);
        save_keys_to_file(&state.config.storage.key_store_path, &keys);
        
        let metadata = KeyMetadata::new(
            key_id.clone(),
            "AES-256-GCM".to_string(),
            256,
            Some(state.config.security.key_expiration_days),
        );
        let _ = save_key_metadata(&state.config.storage.key_store_path, &metadata);
    }

    info!("Generated key: {}", key_id);

    Ok(Json(KeyResponse {
        key_id,
        algorithm: "AES-256-GCM".to_string(),
        key_size: 256,
        created_at: now,
        expires_at,
    }))
}

#[instrument(skip(state))]
pub async fn encrypt(
    State(state): State<AppState>,
    Json(payload): Json<EncryptRequest>,
) -> Result<Json<EncryptResponse>, (StatusCode, String)> {
    // Validate input
    if let Err(e) = payload.validate() {
        error!("Validation error: {:?}", e);
        return Err((StatusCode::BAD_REQUEST, format!("Validation error: {:?}", e)));
    }

    info!("Encrypting data for key: {}", payload.key_id);

    let keys = state.keys.read().await;
    let key_data = keys.get(&payload.key_id)
        .ok_or_else(|| (StatusCode::NOT_FOUND, "Key not found".to_string()))?;

    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key_data));
    let mut nonce_bytes = [0u8; 12];
    thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, payload.plaintext.as_bytes())
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Encryption failed: {}", e)))?;

    // Update key metadata
    if let Ok(mut metadata) = load_key_metadata(&state.config.storage.key_store_path, &payload.key_id) {
        metadata.increment_usage();
        let _ = save_key_metadata(&state.config.storage.key_store_path, &metadata);
    }

    info!("Successfully encrypted data for key: {}", payload.key_id);

    Ok(Json(EncryptResponse {
        key_id: payload.key_id,
        ciphertext: general_purpose::STANDARD.encode(ciphertext),
        nonce: general_purpose::STANDARD.encode(nonce_bytes),
        algorithm: "AES-256-GCM".to_string(),
        timestamp: Utc::now(),
    }))
}

#[instrument(skip(state))]
pub async fn decrypt(
    State(state): State<AppState>,
    Json(payload): Json<DecryptRequest>,
) -> Result<Json<DecryptResponse>, (StatusCode, String)> {
    // Validate input
    if let Err(e) = payload.validate() {
        error!("Validation error: {:?}", e);
        return Err((StatusCode::BAD_REQUEST, format!("Validation error: {:?}", e)));
    }

    info!("Decrypting data for key: {}", payload.key_id);

    let keys = state.keys.read().await;
    let key_data = keys.get(&payload.key_id)
        .ok_or_else(|| (StatusCode::NOT_FOUND, "Key not found".to_string()))?;

    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key_data));
    let nonce_bytes = general_purpose::STANDARD
        .decode(&payload.nonce)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("Invalid nonce format: {}", e)))?;
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext_bytes = general_purpose::STANDARD
        .decode(&payload.ciphertext)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("Invalid ciphertext format: {}", e)))?;

    let plaintext = cipher
        .decrypt(nonce, ciphertext_bytes.as_ref())
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("Decryption failed: {}", e)))?;

    let plaintext_str = String::from_utf8(plaintext)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("Invalid UTF-8 in plaintext: {}", e)))?;

    // Update key metadata
    if let Ok(mut metadata) = load_key_metadata(&state.config.storage.key_store_path, &payload.key_id) {
        metadata.increment_usage();
        let _ = save_key_metadata(&state.config.storage.key_store_path, &metadata);
    }

    info!("Successfully decrypted data for key: {}", payload.key_id);

    Ok(Json(DecryptResponse {
        plaintext: plaintext_str,
        algorithm: "AES-256-GCM".to_string(),
        timestamp: Utc::now(),
    }))
}

#[instrument(skip(state))]
pub async fn generate_keypair(State(state): State<AppState>) -> Result<Json<KeyPairResponse>, (StatusCode, String)> {
    info!("Generating new RSA keypair");

    let mut rng = rand::thread_rng();
    let bits = 2048;
    let private_key = RsaPrivateKey::new(&mut rng, bits)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to generate keypair: {}", e)))?;
    let public_key = RsaPublicKey::from(&private_key);

    let key_id = Uuid::new_v4().to_string();
    let now = Utc::now();
    let expires_at = Some(now + chrono::Duration::days(state.config.security.key_expiration_days as i64));
    
    let base_path = format!("{}/{}", state.config.storage.asymmetric_keys_path, key_id);
    create_dir_all(&base_path)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to create key directory: {}", e)))?;

    let private_pem = private_key.to_pkcs8_pem(Default::default())
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Private key export failed: {}", e)))?
        .to_string();
    let public_pem = public_key.to_public_key_pem(Default::default())
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Public key export failed: {}", e)))?
        .to_string();

    write(format!("{}/private.pem", base_path), &private_pem)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to write private key: {}", e)))?;
    write(format!("{}/public.pem", base_path), &public_pem)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to write public key: {}", e)))?;

    // Save metadata
    let metadata = KeyMetadata::new(
        key_id.clone(),
        "RSA-2048".to_string(),
        2048,
        Some(state.config.security.key_expiration_days),
    );
    let _ = save_key_metadata(&state.config.storage.key_store_path, &metadata);

    info!("Generated keypair: {}", key_id);

    Ok(Json(KeyPairResponse {
        key_id,
        public_key_pem: public_pem,
        created_at: now,
        expires_at,
    }))
}

#[instrument(skip(state))]
pub async fn encrypt_asymmetric(
    State(state): State<AppState>,
    Json(payload): Json<AsymmetricEncryptRequest>,
) -> Result<Json<AsymmetricEncryptResponse>, (StatusCode, String)> {
    // Validate input
    if let Err(e) = payload.validate() {
        error!("Validation error: {:?}", e);
        return Err((StatusCode::BAD_REQUEST, format!("Validation error: {:?}", e)));
    }

    info!("Encrypting data asymmetrically for key: {}", payload.key_id);

    let public_key_path = format!("{}/{}/public.pem", state.config.storage.asymmetric_keys_path, payload.key_id);
    let pem_data = read_to_string(public_key_path)
        .map_err(|e| (StatusCode::NOT_FOUND, format!("Public key not found: {}", e)))?;
    let public_key = RsaPublicKey::from_public_key_pem(&pem_data)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("Invalid public key format: {}", e)))?;

    let mut rng = rand::thread_rng();
    let enc_data = public_key
        .encrypt(&mut rng, rsa::Pkcs1v15Encrypt, payload.plaintext.as_bytes())
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Encryption failed: {}", e)))?;

    info!("Successfully encrypted data asymmetrically for key: {}", payload.key_id);

    Ok(Json(AsymmetricEncryptResponse {
        ciphertext: general_purpose::STANDARD.encode(enc_data),
        algorithm: "RSA-2048".to_string(),
        timestamp: Utc::now(),
    }))
}

#[instrument(skip(state))]
pub async fn decrypt_asymmetric(
    State(state): State<AppState>,
    Json(payload): Json<AsymmetricDecryptRequest>,
) -> Result<Json<AsymmetricDecryptResponse>, (StatusCode, String)> {
    // Validate input
    if let Err(e) = payload.validate() {
        error!("Validation error: {:?}", e);
        return Err((StatusCode::BAD_REQUEST, format!("Validation error: {:?}", e)));
    }

    info!("Decrypting data asymmetrically for key: {}", payload.key_id);

    let private_key_path = format!("{}/{}/private.pem", state.config.storage.asymmetric_keys_path, payload.key_id);
    let pem_data = read_to_string(private_key_path)
        .map_err(|e| (StatusCode::NOT_FOUND, format!("Private key not found: {}", e)))?;
    let private_key = RsaPrivateKey::from_pkcs8_pem(&pem_data)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("Invalid private key format: {}", e)))?;

    let ciphertext = general_purpose::STANDARD.decode(payload.ciphertext)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("Invalid Base64 ciphertext: {}", e)))?;

    let plaintext = private_key
        .decrypt(rsa::Pkcs1v15Encrypt, &ciphertext)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("Decryption failed: {}", e)))?;

    let text = String::from_utf8(plaintext)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("Invalid UTF-8: {}", e)))?;

    info!("Successfully decrypted data asymmetrically for key: {}", payload.key_id);

    Ok(Json(AsymmetricDecryptResponse {
        plaintext: text,
        algorithm: "RSA-2048".to_string(),
        timestamp: Utc::now(),
    }))
}
