// src/api.rs
//
// Handler Axum:
//   POST /encrypt  → cifra un plaintext
//   POST /decrypt  → decifra un ProtectedData
//   GET  /health   → liveness probe per Kubernetes/Docker

use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Json},
};
use serde::{Deserialize, Serialize};
use tracing::{error, info, warn};
use zeroize::Zeroizing;

use crate::{crypto::{ProtectedData, Vault, VaultError}, AppState};

// ─── Request / Response ────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct EncryptRequest {
    /// Testo in chiaro da cifrare
    pub plaintext: String,
}

#[derive(Debug, Serialize)]
pub struct EncryptResponse {
    pub data: ProtectedData,
}

#[derive(Debug, Deserialize)]
pub struct DecryptRequest {
    pub data: ProtectedData,
}

#[derive(Debug, Serialize)]
pub struct DecryptResponse {
    /// Testo decifrato
    pub plaintext: String,
}

#[derive(Debug, Serialize)]
pub struct ErrorResponse {
    pub error: String,
    pub code: &'static str,
}

#[derive(Debug, Serialize)]
pub struct HealthResponse {
    pub status: &'static str,
    pub version: &'static str,
}

// ─── Conversione VaultError → HTTP ─────────────────────────────────────────

fn vault_error_response(e: VaultError) -> impl IntoResponse {
    match &e {
        VaultError::Decryption => {
            // Non distinguiamo "password sbagliata" da "dati corrotti"
            // per non dare informazioni all'attaccante
            warn!("Decrypt attempt failed");
            (
                StatusCode::UNAUTHORIZED,
                Json(ErrorResponse {
                    error: "Decryption failed".into(),
                    code: "DECRYPTION_FAILED",
                }),
            )
        }
        VaultError::KeyDerivation(_) => {
            error!("Key derivation error: {e}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "Internal error".into(),
                    code: "KEY_DERIVATION_ERROR",
                }),
            )
        }
        _ => {
            warn!("Vault error: {e}");
            (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: e.to_string(),
                    code: "VAULT_ERROR",
                }),
            )
        }
    }
}

// ─── Handler ───────────────────────────────────────────────────────────────

/// POST /encrypt
/// Body: { "plaintext": "..." }
/// Risposta: { "data": { "salt": "...", "nonce": "...", "ciphertext": "...", "version": 1 } }
pub async fn encrypt_handler(
    State(state): State<AppState>,
    Json(req): Json<EncryptRequest>,
) -> impl IntoResponse {
    // Usiamo Zeroizing per il plaintext ricevuto dall'esterno
    let plaintext = Zeroizing::new(req.plaintext);

    match Vault::encrypt(&plaintext, &state.master_password) {
        Ok(protected) => {
            info!("Encrypt: success");
            (StatusCode::OK, Json(EncryptResponse { data: protected })).into_response()
        }
        Err(e) => vault_error_response(e).into_response(),
    }
}

/// POST /decrypt
/// Body: { "data": { "salt": "...", "nonce": "...", "ciphertext": "...", "version": 1 } }
/// Risposta: { "plaintext": "..." }
pub async fn decrypt_handler(
    State(state): State<AppState>,
    Json(req): Json<DecryptRequest>,
) -> impl IntoResponse {
    match Vault::decrypt(&req.data, &state.master_password) {
        Ok(plaintext) => {
            info!("Decrypt: success");
            // Cloniamo fuori dal Zeroizing per serializzare, poi il Zeroizing fa drop
            let response = DecryptResponse {
                plaintext: plaintext.as_str().to_owned(),
            };
            (StatusCode::OK, Json(response)).into_response()
        }
        Err(e) => vault_error_response(e).into_response(),
    }
}

/// GET /health
pub async fn health_handler() -> impl IntoResponse {
    Json(HealthResponse {
        status: "ok",
        version: env!("CARGO_PKG_VERSION"),
    })
}