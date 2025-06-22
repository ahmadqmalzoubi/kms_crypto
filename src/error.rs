use thiserror::Error;

#[derive(Error, Debug)]
pub enum KmsError {
    #[error("Key not found: {0}")]
    KeyNotFound(String),
    
    #[error("Encryption failed: {0}")]
    EncryptionError(String),
    
    #[error("Decryption failed: {0}")]
    DecryptionError(String),
    
    #[error("Invalid input: {0}")]
    InvalidInput(String),
    
    #[error("Key generation failed: {0}")]
    KeyGenerationError(String),
    
    #[error("Storage error: {0}")]
    StorageError(String),
    
    #[error("Invalid key format: {0}")]
    InvalidKeyFormat(String),
    
    #[error("Base64 decode error: {0}")]
    Base64Error(String),
    
    #[error("UTF-8 error: {0}")]
    Utf8Error(String),
    
    #[error("File system error: {0}")]
    FileSystemError(String),
}

impl From<std::io::Error> for KmsError {
    fn from(err: std::io::Error) -> Self {
        KmsError::FileSystemError(err.to_string())
    }
}

impl From<base64::DecodeError> for KmsError {
    fn from(err: base64::DecodeError) -> Self {
        KmsError::Base64Error(err.to_string())
    }
}

impl From<std::string::FromUtf8Error> for KmsError {
    fn from(err: std::string::FromUtf8Error) -> Self {
        KmsError::Utf8Error(err.to_string())
    }
}

impl From<serde_json::Error> for KmsError {
    fn from(err: serde_json::Error) -> Self {
        KmsError::StorageError(err.to_string())
    }
} 