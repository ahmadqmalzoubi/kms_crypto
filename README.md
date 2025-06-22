# KMS Crypto Backend

A high-performance Key Management Service backend written in Rust, providing cryptographic operations for secure key generation, encryption, and decryption.

## Features

- **Symmetric Cryptography**: AES-256-GCM encryption/decryption
- **Asymmetric Cryptography**: RSA-2048 key pairs and operations
- **Key Management**: Automatic key generation, rotation, and metadata tracking
- **Security**: Input validation, rate limiting, and secure key storage
- **Monitoring**: Structured logging, health checks, and metrics
- **Configuration**: Environment-based configuration management
- **Docker Support**: Containerized deployment with health checks

## Quick Start

### Using Docker

```bash
# Build and run with Docker Compose
docker-compose up --build

# Or build and run manually
docker build -t kms-crypto .
docker run -p 9000:9000 kms-crypto
```

### Local Development

```bash
# Install Rust (if not already installed)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Build and run
cargo build --release
cargo run
```

## Configuration

The service can be configured using:

1. **Configuration files**: `config/default.toml` and `config/local.toml`
2. **Environment variables**: Prefixed with `KMS_`

### Configuration Options

```toml
[server]
bind_address = "127.0.0.1:9000"
cors_origins = ["*"]

[storage]
key_store_path = "keys.json"
asymmetric_keys_path = "keys/asymmetric"
backup_enabled = false
backup_path = "backup"

[security]
max_key_size = 4096
max_plaintext_size = 65536
key_expiration_days = 365

[logging]
level = "info"
format = "json"
```

## API Endpoints

### Health Check
- `GET /health` - Service health status

### Symmetric Operations
- `POST /generate_key` - Generate new AES-256-GCM key
- `POST /encrypt` - Encrypt data with symmetric key
- `POST /decrypt` - Decrypt data with symmetric key

### Asymmetric Operations
- `POST /generate_keypair` - Generate new RSA-2048 key pair
- `POST /encrypt_asymmetric` - Encrypt with public key
- `POST /decrypt_asymmetric` - Decrypt with private key

## Request/Response Examples

### Generate Symmetric Key
```bash
curl -X POST http://localhost:9000/generate_key
```

Response:
```json
{
  "key_id": "550e8400-e29b-41d4-a716-446655440000",
  "algorithm": "AES-256-GCM",
  "key_size": 256,
  "created_at": "2024-01-01T00:00:00Z",
  "expires_at": "2025-01-01T00:00:00Z"
}
```

### Encrypt Data
```bash
curl -X POST http://localhost:9000/encrypt \
  -H "Content-Type: application/json" \
  -d '{
    "key_id": "550e8400-e29b-41d4-a716-446655440000",
    "plaintext": "Hello, World!"
  }'
```

Response:
```json
{
  "key_id": "550e8400-e29b-41d4-a716-446655440000",
  "ciphertext": "base64_encoded_ciphertext",
  "nonce": "base64_encoded_nonce",
  "algorithm": "AES-256-GCM",
  "timestamp": "2024-01-01T00:00:00Z"
}
```

## Security Features

- **Input Validation**: All inputs are validated for length and format
- **Key Metadata**: Tracking of key usage, creation, and expiration
- **Secure Storage**: Keys are stored encrypted and with proper permissions
- **Error Handling**: Comprehensive error handling without information leakage
- **Logging**: Structured logging for audit trails

## Development

### Prerequisites
- Rust 1.75+
- Docker (optional)

### Building
```bash
cargo build
cargo build --release  # For production
```

### Testing
```bash
cargo test
```

### Running Tests
```bash
cargo test -- --nocapture  # Show output
```

## Monitoring

### Health Check
The service provides a health check endpoint that returns:
- Service status
- Version information
- Uptime

### Logging
Structured JSON logging with configurable levels:
- `error`: Errors and failures
- `warn`: Warnings and recoverable issues
- `info`: General information and operations
- `debug`: Detailed debugging information

### Metrics
Key metrics tracked:
- Key generation count
- Encryption/decryption operations
- Key usage statistics
- Error rates

## Deployment

### Production Considerations
1. **Security**: Use proper TLS certificates
2. **Storage**: Consider using a database instead of file storage
3. **Backup**: Implement regular key backups
4. **Monitoring**: Set up proper monitoring and alerting
5. **Scaling**: Use load balancers for multiple instances

### Environment Variables
```bash
RUST_LOG=info
KMS_SERVER_BIND_ADDRESS=0.0.0.0:9000
KMS_STORAGE_KEY_STORE_PATH=/app/keys.json
KMS_SECURITY_KEY_EXPIRATION_DAYS=365
```

## License

This project is licensed under the MIT License. 