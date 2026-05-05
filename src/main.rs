// src/main.rs

mod api;
mod crypto;

use std::sync::Arc;

use axum::{routing::{get, post}, Router};
use tower_http::trace::TraceLayer;
use tracing::info;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};
use zeroize::Zeroizing;

// ─── Stato condiviso ────────────────────────────────────────────────────────

/// Stato iniettato in ogni handler.
/// La master password è avvolta in Zeroizing: viene azzerata se AppState
/// venisse mai droppato (utile nei test).
#[derive(Clone)]
pub struct AppState {
    pub master_password: Arc<Zeroizing<String>>,
}

// ─── Config ─────────────────────────────────────────────────────────────────

struct Config {
    master_password: Zeroizing<String>,
    bind_addr: String,
    log_level: String,
}

impl Config {
    fn from_env() -> Self {
        // Carica .env se presente (utile in sviluppo locale)
        let _ = dotenvy::dotenv();

        let master_password = std::env::var("VAULT_MASTER_PASSWORD")
            .expect("VAULT_MASTER_PASSWORD env var is required");

        if master_password.len() < 20 {
            panic!("VAULT_MASTER_PASSWORD must be at least 20 characters");
        }

        let bind_addr = std::env::var("VAULT_BIND_ADDR")
            .unwrap_or_else(|_| "0.0.0.0:8080".to_string());

        let log_level = std::env::var("RUST_LOG")
            .unwrap_or_else(|_| "vault_service=info,tower_http=warn".to_string());

        Self {
            master_password: Zeroizing::new(master_password),
            bind_addr,
            log_level,
        }
    }
}

// ─── Main ───────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() {
    let config = Config::from_env();

    // Logging strutturato JSON (ottimo per aggregatori tipo Loki/Datadog)
    tracing_subscriber::registry()
        .with(EnvFilter::new(&config.log_level))
        .with(tracing_subscriber::fmt::layer().json())
        .init();

    let state = AppState {
        master_password: Arc::new(config.master_password),
    };

    let app = Router::new()
        .route("/health", get(api::health_handler))
        .route("/encrypt", post(api::encrypt_handler))
        .route("/decrypt", post(api::decrypt_handler))
        .layer(TraceLayer::new_for_http())
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(&config.bind_addr)
        .await
        .unwrap_or_else(|e| panic!("Cannot bind to {}: {e}", config.bind_addr));

    info!(addr = %config.bind_addr, "Vault service started");

    axum::serve(listener, app)
        .await
        .expect("Server error");
}