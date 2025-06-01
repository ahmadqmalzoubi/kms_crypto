mod handlers;
mod store;

use axum::{routing::get, routing::post, Router};
use handlers::{
    AppState, generate_key, encrypt, decrypt, generate_keypair, encrypt_asymmetric, decrypt_asymmetric
};
use store::load_keys_from_file;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::RwLock;

#[tokio::main]
async fn main() {
    let store_path = std::env::var("KEY_STORE_PATH").unwrap_or_else(|_| "keys.json".to_string());
    let keys = load_keys_from_file(&store_path);
    let state = AppState {
        keys: Arc::new(RwLock::new(keys)),
    };

    let app = Router::new()
        .route("/health", get(health_check))
        .route("/generate_key", post(generate_key))
        .route("/encrypt", post(encrypt))
        .route("/decrypt", post(decrypt))
        .route("/generate_keypair", post(generate_keypair))
        .route("/encrypt_asymmetric", post(encrypt_asymmetric))
        .route("/decrypt_asymmetric", post(decrypt_asymmetric))
        .with_state(state);

    let addr = SocketAddr::from(([127, 0, 0, 1], 9000));
    println!("🚀 KMS Crypto Service running on http://{}", addr);

    axum::serve(tokio::net::TcpListener::bind(addr).await.unwrap(), app)
        .await
        .unwrap();
}

async fn health_check() -> &'static str {
    "KMS Crypto backend is healthy"
}
