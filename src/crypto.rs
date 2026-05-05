// src/crypto.rs
//
// Vault crittografico production-grade:
//   - AES-256-GCM con AAD (autenticazione intestazione)
//   - Argon2id con parametri OWASP-raccomandati
//   - Zeroizzazione automatica di chiavi e plaintext
//   - Serializzazione sicura base64/hex via serde

use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Key, Nonce,
};
use argon2::{Algorithm, Argon2, Params, Version};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use rand::Rng;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

// ─── Errori ────────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum VaultError {
    #[error("Argon2 key derivation failed: {0}")]
    KeyDerivation(String),

    #[error("Encryption failed")]
    Encryption,

    #[error("Decryption failed: wrong password or corrupted data")]
    Decryption,

    #[error("Invalid UTF-8 in decrypted plaintext")]
    InvalidUtf8,

    #[error("Base64 decode error: {0}")]
    Base64(#[from] base64::DecodeError),

    #[error("Hex decode error: {0}")]
    Hex(#[from] hex::FromHexError),

    #[error("Invalid data length for field '{field}': expected {expected}, got {got}")]
    InvalidLength {
        field: &'static str,
        expected: usize,
        got: usize,
    },
}

// ─── Struttura serializzabile ───────────────────────────────────────────────

/// Dati cifrati pronti per essere salvati su DB o restituiti via API.
/// Tutti i campi binari sono serializzati in base64 (salt in hex per leggibilità).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtectedData {
    /// Salt Argon2 (hex, 16 byte → 32 char)
    pub salt: String,
    /// Nonce AES-GCM (base64, 12 byte)
    pub nonce: String,
    pub dek_nonce: String,
    pub encrypted_dek: String,

    /// Ciphertext + GCM tag (base64)
    pub ciphertext: String,
    /// Schema version per future migrazioni
    pub version: u8,
}

impl ProtectedData {
    const CURRENT_VERSION: u8 = 1;

    /// Costruisce da byte grezzi, serializzando in base64/hex
    fn from_raw(
        salt: &[u8; 16],
        nonce: &[u8; 12],
        dek_nonce: &[u8; 12],
        encrypted_dek: Vec<u8>,
        ciphertext: Vec<u8>,
    ) -> Self {
        Self {
            salt: hex::encode(salt),
            nonce: B64.encode(nonce),
            dek_nonce: B64.encode(dek_nonce),
            encrypted_dek: B64.encode(&encrypted_dek),
            ciphertext: B64.encode(&ciphertext),
            version: Self::CURRENT_VERSION,
        }
    }

    /// Decodifica i campi e restituisce byte grezzi con zeroize
    fn to_raw(&self) -> Result<RawData, VaultError> {
        let salt_bytes = hex::decode(&self.salt)?;
        let nonce_bytes = B64.decode(&self.nonce)?;
        let dek_nonce_bytes = B64.decode(&self.dek_nonce)?;
        let encrypted_dek = B64.decode(&self.encrypted_dek)?;
        let ciphertext = B64.decode(&self.ciphertext)?;

        let salt: [u8; 16] =
            salt_bytes
                .try_into()
                .map_err(|v: Vec<u8>| VaultError::InvalidLength {
                    field: "salt",
                    expected: 16,
                    got: v.len(),
                })?;

        let nonce: [u8; 12] =
            nonce_bytes
                .try_into()
                .map_err(|v: Vec<u8>| VaultError::InvalidLength {
                    field: "nonce",
                    expected: 12,
                    got: v.len(),
                })?;

        let dek_nonce: [u8; 12] =
            dek_nonce_bytes
                .try_into()
                .map_err(|v: Vec<u8>| VaultError::InvalidLength {
                    field: "dek_nonce",
                    expected: 12,
                    got: v.len(),
                })?;

        Ok(RawData {
            salt,
            nonce,
            dek_nonce,
            encrypted_dek,
            ciphertext,
        })
    }
}

/// Dati grezzi intermedi — zeroizzati automaticamente al drop
#[derive(Zeroize, ZeroizeOnDrop)]
struct RawData {
    salt: [u8; 16],
    nonce: [u8; 12],
    dek_nonce: [u8; 12],
    encrypted_dek: Vec<u8>,
    ciphertext: Vec<u8>,
}

// ─── Vault ─────────────────────────────────────────────────────────────────

pub struct Vault;

impl Vault {
    // Parametri Argon2id conformi a OWASP 2023:
    //   m=64MB, t=3, p=1 → ~200ms su hardware moderno
    const ARGON2_MEM_KIB: u32 = 64 * 1024; // 64 MiB
    const ARGON2_TIME: u32 = 3;
    const ARGON2_PARALLEL: u32 = 1;

    /// Dervia una chiave AES-256 dalla master password.
    /// Restituisce Zeroizing<[u8;32]>: la chiave viene azzerata al drop.
    fn derive_key(master_password: &str, salt: &[u8]) -> Result<Zeroizing<[u8; 32]>, VaultError> {
        let params = Params::new(
            Self::ARGON2_MEM_KIB,
            Self::ARGON2_TIME,
            Self::ARGON2_PARALLEL,
            Some(32),
        )
        .map_err(|e| VaultError::KeyDerivation(e.to_string()))?;

        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

        let mut key = Zeroizing::new([0u8; 32]);
        argon2
            .hash_password_into(master_password.as_bytes(), salt, key.as_mut())
            .map_err(|e| VaultError::KeyDerivation(e.to_string()))?;

        Ok(key)
    }

    /// Costruisce l'AAD = salt ‖ nonce ‖ version.
    /// Lega il ciphertext ai metadati: sostituirli invalida il MAC.
    fn build_aad(context: &[u8], salt: &[u8; 16], nonce: &[u8; 12], version: u8) -> Vec<u8> {
        let mut aad = Vec::with_capacity(context.len() + 16 + 12 + 1);
        aad.extend_from_slice(context); // es: b"DATA"
        aad.extend_from_slice(salt);
        aad.extend_from_slice(nonce);
        aad.push(version);
        aad
    }

    /// Cifra `plaintext` con la `master_password`.
    /// Ogni chiamata genera salt e nonce fresh da OsRng.
    pub fn encrypt(plaintext: &str, master_password: &str) -> Result<ProtectedData, VaultError> {
        // ─── 1. Genera DEK (Data Encryption Key) ───────────────────────────
        let mut dek = Zeroizing::new([0u8; 32]);
        rand::rng().fill_bytes(dek.as_mut());

        // ─── 2. Genera salt e nonce per DATA ───────────────────────────────
        let mut salt = [0u8; 16];
        let mut data_nonce_bytes = [0u8; 12];

        rand::rng().fill_bytes(&mut salt);
        rand::rng().fill_bytes(&mut data_nonce_bytes);

        // ─── 3. Cifra i dati con DEK ───────────────────────────────────────
        let data_cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(dek.as_ref()));
        let data_nonce = Nonce::from_slice(&data_nonce_bytes);

        let data_aad = Self::build_aad(
            b"DATA",
            &salt,
            &data_nonce_bytes,
            ProtectedData::CURRENT_VERSION,
        );

        let ciphertext = data_cipher
            .encrypt(
                data_nonce,
                Payload {
                    msg: plaintext.as_bytes(),
                    aad: &data_aad,
                },
            )
            .map_err(|_| VaultError::Encryption)?;

        // ─── 4. Deriva KEK (da password) ───────────────────────────────────
        let kek = Self::derive_key(master_password, &salt)?;
        let kek_cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(kek.as_ref()));

        // ─── 5. Cifra il DEK con KEK ───────────────────────────────────────
        let mut dek_nonce_bytes = [0u8; 12];
        rand::rng().fill_bytes(&mut dek_nonce_bytes);

        let dek_nonce = Nonce::from_slice(&dek_nonce_bytes);

        let encrypted_dek = kek_cipher
            .encrypt(
                dek_nonce,
                Payload {
                    msg: dek.as_ref(),
                    aad: b"DEK", // domain separation
                },
            )
            .map_err(|_| VaultError::Encryption)?;

        // ─── 6. Costruisci output ──────────────────────────────────────────
        Ok(ProtectedData {
            salt: hex::encode(salt),
            nonce: B64.encode(data_nonce_bytes),
            dek_nonce: B64.encode(dek_nonce_bytes),
            encrypted_dek: B64.encode(encrypted_dek),
            ciphertext: B64.encode(ciphertext),
            version: ProtectedData::CURRENT_VERSION,
        })
    }

    /// Decifra `data` usando la `master_password`.
    /// Fallisce se la password è errata, i dati sono corrotti,
    /// o l'intestazione (salt/nonce/version) è stata manomessa.
    pub fn decrypt(
        data: &ProtectedData,
        master_password: &str,
    ) -> Result<Zeroizing<String>, VaultError> {
        let raw = data.to_raw()?; // deve includere anche encrypted_dek + dek_nonce

        // ─── 1. Deriva KEK dalla password ──────────────────────────────────
        let kek = Self::derive_key(master_password, &raw.salt)?;
        let kek_cipher =
            Aes256Gcm::new_from_slice(kek.as_ref()).map_err(|_| VaultError::Decryption)?;

        let dek_nonce = Nonce::from_slice(&raw.dek_nonce);

        // ─── 2. Decifra DEK ────────────────────────────────────────────────
        let dek_bytes = kek_cipher
            .decrypt(
                dek_nonce,
                Payload {
                    msg: raw.encrypted_dek.as_slice(),
                    aad: b"DEK",
                },
            )
            .map_err(|_| VaultError::Decryption)?;

        // Metti DEK in Zeroizing
        let dek: Zeroizing<[u8; 32]> =
            Zeroizing::new(dek_bytes.try_into().map_err(|_| VaultError::Decryption)?);

        // ─── 3. Usa DEK per decifrare i dati ───────────────────────────────
        let data_cipher =
            Aes256Gcm::new_from_slice(dek.as_ref()).map_err(|_| VaultError::Decryption)?;

        let nonce = Nonce::from_slice(&raw.nonce);

        let aad = Self::build_aad(b"DATA", &raw.salt, &raw.nonce, data.version);

        let plaintext_bytes = data_cipher
            .decrypt(
                nonce,
                Payload {
                    msg: raw.ciphertext.as_slice(),
                    aad: &aad,
                },
            )
            .map_err(|_| VaultError::Decryption)?;

        // ─── 4. Converti senza clone (IMPORTANTE) ──────────────────────────
        let result = String::from_utf8(plaintext_bytes).map_err(|_| VaultError::InvalidUtf8)?;

        Ok(Zeroizing::new(result))
    }
}
// src/crypto.rs  — aggiungi in fondo al file

#[cfg(test)]
mod tests {
    use super::*;

    const PWD: &str = "a-very-strong-test-password-123!";
    const SECRET: &str = "account: mario@example.com | pass: hunter2";

    #[test]
    fn roundtrip_encrypt_decrypt() {
        let protected = Vault::encrypt(SECRET, PWD).expect("encrypt failed");
        let plaintext = Vault::decrypt(&protected, PWD).expect("decrypt failed");
        assert_eq!(plaintext.as_str(), SECRET);
    }

    #[test]
    fn wrong_password_is_rejected() {
        let protected = Vault::encrypt(SECRET, PWD).expect("encrypt failed");
        let result = Vault::decrypt(&protected, "wrong-password");
        assert!(matches!(result, Err(VaultError::Decryption)));
    }

    #[test]
    fn tampered_ciphertext_is_rejected() {
        let mut protected = Vault::encrypt(SECRET, PWD).expect("encrypt failed");
        // Corrompi un byte del ciphertext
        let mut ct = base64::engine::general_purpose::STANDARD
            .decode(&protected.ciphertext)
            .unwrap();
        ct[0] ^= 0xFF;
        protected.ciphertext = base64::engine::general_purpose::STANDARD.encode(&ct);

        let result = Vault::decrypt(&protected, PWD);
        assert!(matches!(result, Err(VaultError::Decryption)));
    }

    #[test]
    fn tampered_salt_is_rejected() {
        let mut protected = Vault::encrypt(SECRET, PWD).expect("encrypt failed");
        // Sostituisce il salt → AAD cambia → MAC fallisce
        protected.salt = "00".repeat(16);
        let result = Vault::decrypt(&protected, PWD);
        assert!(matches!(result, Err(VaultError::Decryption)));
    }

    #[test]
    fn each_encryption_produces_different_ciphertext() {
        let a = Vault::encrypt(SECRET, PWD).expect("encrypt a failed");
        let b = Vault::encrypt(SECRET, PWD).expect("encrypt b failed");
        // Salt e nonce diversi → ciphertext diverso (semantic security)
        assert_ne!(a.ciphertext, b.ciphertext);
        assert_ne!(a.salt, b.salt);
    }

    #[test]
    fn serialization_roundtrip() {
        let protected = Vault::encrypt(SECRET, PWD).expect("encrypt failed");
        let json = serde_json::to_string(&protected).expect("serialize failed");
        let deserialized: ProtectedData = serde_json::from_str(&json).expect("deserialize failed");
        let plaintext = Vault::decrypt(&deserialized, PWD).expect("decrypt failed");
        assert_eq!(plaintext.as_str(), SECRET);
    }
}
