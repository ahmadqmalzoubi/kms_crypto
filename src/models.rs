use serde::{Deserialize, Serialize};
use validator::Validate;
use chrono::{DateTime, Utc};

#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct EncryptRequest {
    #[validate(length(min = 1, max = 100))]
    pub key_id: String,
    #[validate(length(min = 1, max = 65536))]
    pub plaintext: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct DecryptRequest {
    #[validate(length(min = 1, max = 100))]
    pub key_id: String,
    #[validate(length(min = 1))]
    pub ciphertext: String,
    #[validate(length(min = 1))]
    pub nonce: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct AsymmetricEncryptRequest {
    #[validate(length(min = 1, max = 100))]
    pub key_id: String,
    #[validate(length(min = 1, max = 190))] // RSA 2048 limit
    pub plaintext: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct AsymmetricDecryptRequest {
    #[validate(length(min = 1, max = 100))]
    pub key_id: String,
    #[validate(length(min = 1))]
    pub ciphertext: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyResponse {
    pub key_id: String,
    pub algorithm: String,
    pub key_size: usize,
    pub created_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyPairResponse {
    pub key_id: String,
    pub public_key_pem: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptResponse {
    pub key_id: String,
    pub ciphertext: String,
    pub nonce: String,
    pub algorithm: String,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecryptResponse {
    pub plaintext: String,
    pub algorithm: String,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AsymmetricEncryptResponse {
    pub ciphertext: String,
    pub algorithm: String,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AsymmetricDecryptResponse {
    pub plaintext: String,
    pub algorithm: String,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthResponse {
    pub status: String,
    pub timestamp: DateTime<Utc>,
    pub version: String,
    pub uptime: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyMetadata {
    pub id: String,
    pub algorithm: String,
    pub key_size: usize,
    pub created_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub usage_count: u64,
    pub last_used: Option<DateTime<Utc>>,
    pub is_active: bool,
}

impl KeyMetadata {
    pub fn new(id: String, algorithm: String, key_size: usize, expires_in_days: Option<u32>) -> Self {
        let now = Utc::now();
        let expires_at = expires_in_days.map(|days| now + chrono::Duration::days(days as i64));
        
        Self {
            id,
            algorithm,
            key_size,
            created_at: now,
            expires_at,
            usage_count: 0,
            last_used: None,
            is_active: true,
        }
    }

    pub fn increment_usage(&mut self) {
        self.usage_count += 1;
        self.last_used = Some(Utc::now());
    }

    pub fn is_expired(&self) -> bool {
        if let Some(expires_at) = self.expires_at {
            Utc::now() > expires_at
        } else {
            false
        }
    }
} 