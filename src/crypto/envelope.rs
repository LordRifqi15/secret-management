use aes_gcm::{
    aead::{generic_array::GenericArray, Aead, AeadCore, KeyInit, OsRng, Payload},
    Aes256Gcm,
};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use super::keys::{DataEncryptionKey, PlaintextData};

#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("Failed to encrypt data")]
    EncryptionFailed,
    #[error("Failed to decrypt data")]
    DecryptionFailed,
    #[error("Invalid Base64 encoding")]
    InvalidBase64,
    #[error("Unknown key id")]
    UnknownKeyId,
}

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
}

fn default_key_id() -> String {
    "primary".to_string()
}

pub fn encrypt_envelope(
    kek_cipher: &Aes256Gcm,
    key_id: &str,
    plaintext: &PlaintextData,
) -> Result<EncryptedEnvelope, CryptoError> {
    let mut dek_bytes = [0u8; 32];
    OsRng.fill_bytes(&mut dek_bytes);
    let dek = DataEncryptionKey::new(dek_bytes);

    let dek_cipher = Aes256Gcm::new(GenericArray::from_slice(dek.as_bytes()));
    let nonce_bytes = Aes256Gcm::generate_nonce(&mut OsRng);
    let ciphertext = dek_cipher
        .encrypt(&nonce_bytes, plaintext.as_bytes())
        .map_err(|_| CryptoError::EncryptionFailed)?;

    // AAD binds key_id to DEK wrap — swap attack fails
    let dek_nonce_bytes = Aes256Gcm::generate_nonce(&mut OsRng);
    let payload = Payload {
        msg: dek.as_bytes().as_slice(),
        aad: key_id.as_bytes(),
    };
    let encrypted_dek = kek_cipher
        .encrypt(&dek_nonce_bytes, payload)
        .map_err(|_| CryptoError::EncryptionFailed)?;

    Ok(EncryptedEnvelope {
        ciphertext_b64: BASE64.encode(ciphertext),
        nonce_b64: BASE64.encode(nonce_bytes),
        encrypted_dek_b64: BASE64.encode(encrypted_dek),
        dek_nonce_b64: BASE64.encode(dek_nonce_bytes),
        key_id: key_id.to_string(),
    })
}
pub fn decrypt_envelope(
    kek_cipher: &Aes256Gcm,
    envelope: &EncryptedEnvelope,
) -> Result<PlaintextData, CryptoError> {
    let ciphertext = BASE64.decode(&envelope.ciphertext_b64).map_err(|_| CryptoError::InvalidBase64)?;
    let nonce = BASE64.decode(&envelope.nonce_b64).map_err(|_| CryptoError::InvalidBase64)?;
    let encrypted_dek = BASE64.decode(&envelope.encrypted_dek_b64).map_err(|_| CryptoError::InvalidBase64)?;
    let dek_nonce = BASE64.decode(&envelope.dek_nonce_b64).map_err(|_| CryptoError::InvalidBase64)?;
    if nonce.len() != 12 || dek_nonce.len() != 12 {
        return Err(CryptoError::DecryptionFailed);
    }
    let dek_nonce_ga = GenericArray::from_slice(&dek_nonce);
    let payload = Payload { msg: encrypted_dek.as_ref(), aad: envelope.key_id.as_bytes() };
    let mut dek_bytes_vec = kek_cipher.decrypt(dek_nonce_ga, payload).map_err(|_| CryptoError::DecryptionFailed)?;
    if dek_bytes_vec.len() != 32 {
        dek_bytes_vec.zeroize();
        return Err(CryptoError::DecryptionFailed);
    }
    let mut dek_bytes = [0u8; 32];
    dek_bytes.copy_from_slice(&dek_bytes_vec);
    dek_bytes_vec.zeroize();
    let dek = DataEncryptionKey::new(dek_bytes);
    let dek_cipher = Aes256Gcm::new(GenericArray::from_slice(dek.as_bytes()));
    let nonce_ga = GenericArray::from_slice(&nonce);
    let plaintext_bytes = dek_cipher.decrypt(nonce_ga, ciphertext.as_ref()).map_err(|_| CryptoError::DecryptionFailed)?;
    Ok(PlaintextData::new(plaintext_bytes))
}
