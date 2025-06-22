mod handlers;
mod store;
mod error;
mod config;
mod models;

use axum::{routing::get, routing::post, Router};
use handlers::{
    AppState, generate_key, encrypt, decrypt, generate_keypair, encrypt_asymmetric, decrypt_asymmetric, health_check
};
use store::load_keys_from_file;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{info, error};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use tower_http::cors::{CorsLayer, Any};
use tower_http::trace::TraceLayer;

#[tokio::main]
async fn main() {
    // Initialize logging
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(
            std::env::var("RUST_LOG").unwrap_or_else(|_| "info".into()),
        ))
        .with(tracing_subscriber::fmt::layer())
        .init();

    info!("🚀 Starting KMS Crypto Service...");

    // Load configuration
    let config = match config::AppConfig::load() {
        Ok(config) => {
            info!("Configuration loaded successfully");
            config
        }
        Err(e) => {
            error!("Failed to load configuration: {}", e);
            info!("Using default configuration");
            config::AppConfig::default()
        }
    };

    // Initialize key store
    let keys = load_keys_from_file(&config.storage.key_store_path);
    let state = AppState {
        keys: Arc::new(RwLock::new(keys)),
        config: Arc::new(config.clone()),
    };

    // Configure CORS
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    // Build application
    let app = Router::new()
        .route("/health", get(health_check))
        .route("/generate_key", post(generate_key))
        .route("/encrypt", post(encrypt))
        .route("/decrypt", post(decrypt))
        .route("/generate_keypair", post(generate_keypair))
        .route("/encrypt_asymmetric", post(encrypt_asymmetric))
        .route("/decrypt_asymmetric", post(decrypt_asymmetric))
        .layer(cors)
        .layer(TraceLayer::new_for_http())
        .with_state(state);

    info!("🚀 KMS Crypto Service running on http://{}", config.server.bind_address);

    // Start server
    axum::serve(
        tokio::net::TcpListener::bind(config.server.bind_address).await.unwrap(),
        app
    )
    .await
    .unwrap();
}
