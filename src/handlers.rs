use axum::{Json, extract::State};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use rand::{RngCore, thread_rng};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use aes_gcm::aead::{Aead, KeyInit};
use base64::Engine;
use base64::engine::general_purpose;
use crate::store::{save_keys_to_file, KeyMap};
use rsa::{RsaPrivateKey, RsaPublicKey, pkcs8::{EncodePublicKey, EncodePrivateKey, DecodePrivateKey, DecodePublicKey}};
use std::fs::{create_dir_all, write, read_to_string};

#[derive(Clone)]
pub struct AppState {
    pub keys: KeyMap,
}

#[derive(Serialize)]
pub struct KeyResponse {
    pub key_id: String,
    pub algorithm: String,
    pub key_size: usize,
}

#[derive(Serialize)]
pub struct KeyPairResponse {
    pub key_id: String,
    pub public_key_pem: String,
}

#[derive(Deserialize)]
pub struct EncryptRequest {
    pub key_id: String,
    pub plaintext: String,
}

#[derive(Serialize)]
pub struct EncryptResponse {
    pub key_id: String,
    pub ciphertext: String,
    pub nonce: String,
}

#[derive(Deserialize)]
pub struct DecryptRequest {
    pub key_id: String,
    pub ciphertext: String,
    pub nonce: String,
}

#[derive(Serialize)]
pub struct DecryptResponse {
    pub plaintext: String,
}

#[derive(Deserialize)]
pub struct AsymmetricEncryptRequest {
    pub key_id: String,
    pub plaintext: String,
}

#[derive(Serialize)]
pub struct AsymmetricEncryptResponse {
    pub ciphertext: String,
}

#[derive(Deserialize)]
pub struct AsymmetricDecryptRequest {
    pub key_id: String,
    pub ciphertext: String,
}

#[derive(Serialize)]
pub struct AsymmetricDecryptResponse {
    pub plaintext: String,
}

fn get_store_path() -> String {
    std::env::var("KEY_STORE_PATH").unwrap_or_else(|_| "keys.json".to_string())
}

pub async fn generate_key(State(state): State<AppState>) -> Json<KeyResponse> {
    let mut key = vec![0u8; 32];
    thread_rng().fill_bytes(&mut key);

    let key_id = Uuid::new_v4().to_string();
    {
        let mut keys = state.keys.write().await;
        keys.insert(key_id.clone(), key);
        let path = get_store_path();
        save_keys_to_file(&path, &keys);
    }

    Json(KeyResponse {
        key_id,
        algorithm: "AES-256-GCM".to_string(),
        key_size: 256,
    })
}

pub async fn encrypt(
    State(state): State<AppState>,
    Json(payload): Json<EncryptRequest>,
) -> Result<Json<EncryptResponse>, String> {
    let keys = state.keys.read().await;
    let key_data = keys.get(&payload.key_id).ok_or("Key not found")?;

    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key_data));
    let mut nonce_bytes = [0u8; 12];
    thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, payload.plaintext.as_bytes())
        .map_err(|_| "Encryption failed")?;

    Ok(Json(EncryptResponse {
        key_id: payload.key_id,
        ciphertext: general_purpose::STANDARD.encode(ciphertext),
        nonce: general_purpose::STANDARD.encode(nonce_bytes),
    }))
}

pub async fn decrypt(
    State(state): State<AppState>,
    Json(payload): Json<DecryptRequest>,
) -> Result<Json<DecryptResponse>, String> {
    let keys = state.keys.read().await;
    let key_data = keys.get(&payload.key_id).ok_or("Key not found")?;

    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key_data));
    let nonce_bytes = general_purpose::STANDARD
        .decode(&payload.nonce)
        .map_err(|_| "Invalid nonce format")?;
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext_bytes = general_purpose::STANDARD
        .decode(&payload.ciphertext)
        .map_err(|_| "Invalid ciphertext format")?;

    let plaintext = cipher
        .decrypt(nonce, ciphertext_bytes.as_ref())
        .map_err(|_| "Decryption failed")?;

    let plaintext_str = String::from_utf8(plaintext).map_err(|_| "Invalid UTF-8 in plaintext")?;

    Ok(Json(DecryptResponse {
        plaintext: plaintext_str,
    }))
}

pub async fn generate_keypair() -> Result<Json<KeyPairResponse>, String> {
    let mut rng = rand::thread_rng();
    let bits = 2048;
    let private_key = RsaPrivateKey::new(&mut rng, bits).map_err(|_| "Failed to generate keypair")?;
    let public_key = RsaPublicKey::from(&private_key);

    let key_id = Uuid::new_v4().to_string();
    let base_path = format!("keys/asymmetric/{}", key_id);
    create_dir_all(&base_path).map_err(|_| "Failed to create key directory")?;

    let private_pem = private_key.to_pkcs8_pem(Default::default()).map_err(|_| "Private key export failed")?.to_string();
    let public_pem = public_key.to_public_key_pem(Default::default()).map_err(|_| "Public key export failed")?.to_string();

    write(format!("{}/private.pem", base_path), &private_pem).map_err(|_| "Failed to write private key")?;
    write(format!("{}/public.pem", base_path), &public_pem).map_err(|_| "Failed to write public key")?;

    Ok(Json(KeyPairResponse {
        key_id,
        public_key_pem: public_pem,
    }))
}

pub async fn encrypt_asymmetric(Json(payload): Json<AsymmetricEncryptRequest>) -> Result<Json<AsymmetricEncryptResponse>, String> {
    let public_key_path = format!("keys/asymmetric/{}/public.pem", payload.key_id);
    let pem_data = read_to_string(public_key_path).map_err(|_| "Public key not found")?;
    let public_key = RsaPublicKey::from_public_key_pem(&pem_data).map_err(|_| "Invalid public key format")?;

    let mut rng = rand::thread_rng();
    let enc_data = public_key
        .encrypt(&mut rng, rsa::Pkcs1v15Encrypt, payload.plaintext.as_bytes())
        .map_err(|_| "Encryption failed")?;

    Ok(Json(AsymmetricEncryptResponse {
        ciphertext: general_purpose::STANDARD.encode(enc_data),
    }))
}

pub async fn decrypt_asymmetric(Json(payload): Json<AsymmetricDecryptRequest>) -> Result<Json<AsymmetricDecryptResponse>, String> {
    let private_key_path = format!("keys/asymmetric/{}/private.pem", payload.key_id);
    let pem_data = read_to_string(private_key_path).map_err(|_| "Private key not found")?;
    let private_key = RsaPrivateKey::from_pkcs8_pem(&pem_data).map_err(|_| "Invalid private key format")?;

    let ciphertext = general_purpose::STANDARD.decode(payload.ciphertext).map_err(|_| "Invalid Base64 ciphertext")?;

    let plaintext = private_key
        .decrypt(rsa::Pkcs1v15Encrypt, &ciphertext)
        .map_err(|_| "Decryption failed")?;

    let text = String::from_utf8(plaintext).map_err(|_| "Invalid UTF-8")?;

    Ok(Json(AsymmetricDecryptResponse {
        plaintext: text,
    }))
}
