use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use config::{Config, ConfigError, Environment, File};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppConfig {
    pub server: ServerConfig,
    pub storage: StorageConfig,
    pub security: SecurityConfig,
    pub logging: LoggingConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    pub bind_address: SocketAddr,
    pub cors_origins: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageConfig {
    pub key_store_path: String,
    pub asymmetric_keys_path: String,
    pub backup_enabled: bool,
    pub backup_path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityConfig {
    pub max_key_size: usize,
    pub max_plaintext_size: usize,
    pub key_expiration_days: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingConfig {
    pub level: String,
    pub format: String,
}

impl AppConfig {
    pub fn load() -> Result<Self, ConfigError> {
        let config = Config::builder()
            .add_source(File::with_name("config/default"))
            .add_source(File::with_name("config/local").required(false))
            .add_source(Environment::with_prefix("KMS"))
            .build()?;

        config.try_deserialize()
    }

    pub fn default() -> Self {
        Self {
            server: ServerConfig {
                bind_address: "127.0.0.1:9000".parse().unwrap(),
                cors_origins: vec!["*".to_string()],
            },
            storage: StorageConfig {
                key_store_path: "keys.json".to_string(),
                asymmetric_keys_path: "keys/asymmetric".to_string(),
                backup_enabled: false,
                backup_path: "backup".to_string(),
            },
            security: SecurityConfig {
                max_key_size: 4096,
                max_plaintext_size: 65536,
                key_expiration_days: 365,
            },
            logging: LoggingConfig {
                level: "info".to_string(),
                format: "json".to_string(),
            },
        }
    }
} 