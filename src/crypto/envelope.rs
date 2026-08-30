use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use crate::crypto::aad::CanonicalAad;
use crate::crypto::kek_provider::KekStore;
use crate::crypto::keys::{DataEncryptionKey, PlaintextData};
use crate::crypto::policy::{validate_primitive_compliance, SecurityClassification};
use crate::crypto::symmetric::{aes_gcm::AesGcmCipher, chacha20::ChaChaCipher};
use crate::crypto::traits::AeadCipher;

pub use crate::domain::errors::CryptoError;

/// Envelope with AAD-bound DEK and key version.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedEnvelope {
    pub ciphertext_b64: String,
    pub nonce_b64: String,
    pub encrypted_dek_b64: String,
    pub dek_nonce_b64: String,
    /// KEK id used to wrap DEK — also AAD. Enables rotation and prevents swap.
    #[serde(default = "default_key_id")]
    pub key_id: String,
    #[serde(default = "default_tenant_id")]
    pub tenant_id: String,
    #[serde(default = "default_purpose")]
    pub purpose: String,
    #[serde(default = "default_algorithm")]
    pub algorithm: String,
}

fn default_key_id() -> String {
    "primary".to_string()
}
fn default_tenant_id() -> String {
    String::new()
}
fn default_purpose() -> String {
    String::new()
}
fn default_algorithm() -> String {
    "aes-256-gcm".to_string()
}

fn is_chacha(algorithm: &str) -> bool {
    algorithm.trim().eq_ignore_ascii_case("chacha20-poly1305")
}

fn aad_bytes(tenant_id: &str, purpose: &str, key_id: &str, algorithm: &str) -> Vec<u8> {
    CanonicalAad {
        tenant_id: tenant_id.to_string(),
        purpose: purpose.to_string(),
        key_id: key_id.to_string(),
        algorithm: algorithm.to_string(),
    }
    .encode()
}

pub fn encrypt_envelope(
    kek_store: &KekStore,
    tenant_id: &str,
    purpose: &str,
    algorithm: &str,
    plaintext: &PlaintextData,
) -> Result<EncryptedEnvelope, CryptoError> {
    let normalized = algorithm.trim().to_ascii_lowercase();
    // must be Strategis-compliant
    validate_primitive_compliance(&normalized, SecurityClassification::Strategis)?;

    let key_id = kek_store.current_id().to_string();
    let kek_bytes = kek_store.current_raw();

    // DEK generation
    let mut dek_bytes = [0u8; 32];
    OsRng.fill_bytes(&mut dek_bytes);
    let dek = DataEncryptionKey::new(dek_bytes);

    // data encryption (same algo as KEK wrap, or fallback to aes)
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let ciphertext = if is_chacha(&normalized) {
        let c = ChaChaCipher::new(dek.as_bytes());
        c.encrypt(&nonce_bytes, plaintext.as_bytes(), b"")
            .map_err(|_| CryptoError::EncryptionFailed)?
    } else if normalized == "aes-256-gcm" {
        let c = AesGcmCipher::new(dek.as_bytes());
        c.encrypt(&nonce_bytes, plaintext.as_bytes(), b"")
            .map_err(|_| CryptoError::EncryptionFailed)?
    } else {
        return Err(CryptoError::PolicyViolation(format!(
            "unsupported algorithm '{}'",
            algorithm
        )));
    };

    // DEK wrap with AAD = CanonicalAad
    let aad = aad_bytes(tenant_id, purpose, &key_id, &normalized);
    let mut dek_nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut dek_nonce_bytes);
    let encrypted_dek = if is_chacha(&normalized) {
        let c = ChaChaCipher::new(kek_bytes);
        c.encrypt(&dek_nonce_bytes, dek.as_bytes(), &aad)
            .map_err(|_| CryptoError::EncryptionFailed)?
    } else {
        let c = AesGcmCipher::new(kek_bytes);
        c.encrypt(&dek_nonce_bytes, dek.as_bytes(), &aad)
            .map_err(|_| CryptoError::EncryptionFailed)?
    };

    Ok(EncryptedEnvelope {
        ciphertext_b64: BASE64.encode(ciphertext),
        nonce_b64: BASE64.encode(nonce_bytes),
        encrypted_dek_b64: BASE64.encode(encrypted_dek),
        dek_nonce_b64: BASE64.encode(dek_nonce_bytes),
        key_id,
        tenant_id: tenant_id.to_string(),
        purpose: purpose.to_string(),
        algorithm: normalized,
    })
}

pub fn decrypt_envelope(
    kek_store: &KekStore,
    envelope: &EncryptedEnvelope,
) -> Result<PlaintextData, CryptoError> {
    let ciphertext = BASE64
        .decode(&envelope.ciphertext_b64)
        .map_err(|_| CryptoError::InvalidBase64)?;
    let nonce = BASE64
        .decode(&envelope.nonce_b64)
        .map_err(|_| CryptoError::InvalidBase64)?;
    let encrypted_dek = BASE64
        .decode(&envelope.encrypted_dek_b64)
        .map_err(|_| CryptoError::InvalidBase64)?;
    let dek_nonce = BASE64
        .decode(&envelope.dek_nonce_b64)
        .map_err(|_| CryptoError::InvalidBase64)?;
    if nonce.len() != 12 || dek_nonce.len() != 12 {
        return Err(CryptoError::DecryptionFailed);
    }

    let algorithm = if envelope.algorithm.is_empty() {
        "aes-256-gcm"
    } else {
        envelope.algorithm.as_str()
    };
    let normalized = algorithm.trim().to_ascii_lowercase();
    validate_primitive_compliance(&normalized, SecurityClassification::Strategis)?;

    let kek_bytes = kek_store
        .resolve_raw(&envelope.key_id)
        .ok_or(CryptoError::UnknownKeyId)?;

    // try canonical AAD first, then fallback to legacy key_id-only AAD for old envelopes
    let aad_canonical = aad_bytes(
        &envelope.tenant_id,
        &envelope.purpose,
        &envelope.key_id,
        &normalized,
    );
    let try_decrypt = |aad: &[u8]| -> Result<Vec<u8>, CryptoError> {
        if is_chacha(&normalized) {
            let c = ChaChaCipher::new(kek_bytes);
            c.decrypt(&dek_nonce, &encrypted_dek, aad)
                .map_err(|_| CryptoError::DecryptionFailed)
        } else if normalized == "aes-256-gcm" {
            let c = AesGcmCipher::new(kek_bytes);
            c.decrypt(&dek_nonce, &encrypted_dek, aad)
                .map_err(|_| CryptoError::DecryptionFailed)
        } else {
            Err(CryptoError::PolicyViolation(format!(
                "unsupported algorithm '{}'",
                algorithm
            )))
        }
    };

    let mut dek_bytes_vec = match try_decrypt(&aad_canonical) {
        Ok(v) => v,
        Err(_) => {
            // back compat: old envelopes used key_id as AAD only
            let is_legacy = envelope.tenant_id.is_empty()
                || envelope.purpose.is_empty()
                || envelope.algorithm.is_empty();
            if is_legacy {
                let legacy_aad = envelope.key_id.as_bytes();
                try_decrypt(legacy_aad)?
            } else {
                return Err(CryptoError::DecryptionFailed);
            }
        }
    };

    if dek_bytes_vec.len() != 32 {
        dek_bytes_vec.zeroize();
        return Err(CryptoError::DecryptionFailed);
    }
    let mut dek_bytes = [0u8; 32];
    dek_bytes.copy_from_slice(&dek_bytes_vec);
    dek_bytes_vec.zeroize();
    let dek = DataEncryptionKey::new(dek_bytes);

    let plaintext_bytes = if is_chacha(&normalized) {
        let c = ChaChaCipher::new(dek.as_bytes());
        c.decrypt(&nonce, &ciphertext, b"")
            .map_err(|_| CryptoError::DecryptionFailed)?
    } else {
        let c = AesGcmCipher::new(dek.as_bytes());
        c.decrypt(&nonce, &ciphertext, b"")
            .map_err(|_| CryptoError::DecryptionFailed)?
    };
    Ok(PlaintextData::new(plaintext_bytes))
}
