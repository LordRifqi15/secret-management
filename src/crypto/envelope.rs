use aes_gcm::{
    aead::{generic_array::GenericArray, Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm,
};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use rand::RngCore;
use serde::{Deserialize, Serialize};

use super::keys::{DataEncryptionKey, KeyEncryptionKey, PlaintextData};

#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("Failed to encrypt data")]
    EncryptionFailed,
    #[error("Failed to decrypt data")]
    DecryptionFailed,
    #[error("Invalid Base64 encoding")]
    InvalidBase64,
}

/// Represents an encrypted payload along with the encrypted DEK used to encode it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedEnvelope {
    /// Base64 encoded ciphertext of the plaintext data
    pub ciphertext_b64: String,
    /// Base64 encoded nonce used for the data encryption
    pub nonce_b64: String,
    /// Base64 encoded encrypted DEK
    pub encrypted_dek_b64: String,
    /// Base64 encoded nonce used for encrypting the DEK
    pub dek_nonce_b64: String,
}

pub fn encrypt_envelope(
    kek: &KeyEncryptionKey,
    plaintext: &PlaintextData,
) -> Result<EncryptedEnvelope, CryptoError> {
    // 1. Generate DEK securely
    let mut dek_bytes = [0u8; 32];
    OsRng.fill_bytes(&mut dek_bytes);
    let dek = DataEncryptionKey::new(dek_bytes);

    // 2. Encrypt plaintext with DEK
    let dek_cipher = Aes256Gcm::new(GenericArray::from_slice(dek.as_bytes()));
    let nonce_bytes = Aes256Gcm::generate_nonce(&mut OsRng); // 96-bits; 12 bytes
    let ciphertext = dek_cipher
        .encrypt(&nonce_bytes, plaintext.as_bytes())
        .map_err(|_| CryptoError::EncryptionFailed)?;

    // 3. Encrypt DEK with KEK
    let kek_cipher = Aes256Gcm::new(GenericArray::from_slice(kek.as_bytes()));
    let dek_nonce_bytes = Aes256Gcm::generate_nonce(&mut OsRng);
    let encrypted_dek = kek_cipher
        .encrypt(&dek_nonce_bytes, dek.as_bytes().as_slice())
        .map_err(|_| CryptoError::EncryptionFailed)?;

    // Both plaintext and dek will be automatically zeroed when dropped at the end of this function.

    Ok(EncryptedEnvelope {
        ciphertext_b64: BASE64.encode(ciphertext),
        nonce_b64: BASE64.encode(nonce_bytes),
        encrypted_dek_b64: BASE64.encode(encrypted_dek),
        dek_nonce_b64: BASE64.encode(dek_nonce_bytes),
    })
}

pub fn decrypt_envelope(
    kek: &KeyEncryptionKey,
    envelope: &EncryptedEnvelope,
) -> Result<PlaintextData, CryptoError> {
    // Decode base64
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

    // 1. Decrypt DEK using KEK
    let kek_cipher = Aes256Gcm::new(GenericArray::from_slice(kek.as_bytes()));
    let dek_nonce_ga = GenericArray::from_slice(&dek_nonce);
    let dek_bytes_vec = kek_cipher
        .decrypt(dek_nonce_ga, encrypted_dek.as_ref())
        .map_err(|_| CryptoError::DecryptionFailed)?;

    if dek_bytes_vec.len() != 32 {
        return Err(CryptoError::DecryptionFailed);
    }

    let mut dek_bytes = [0u8; 32];
    dek_bytes.copy_from_slice(&dek_bytes_vec);
    let dek = DataEncryptionKey::new(dek_bytes);

    // 2. Decrypt data using DEK
    let dek_cipher = Aes256Gcm::new(GenericArray::from_slice(dek.as_bytes()));
    let nonce_ga = GenericArray::from_slice(&nonce);
    let plaintext_bytes = dek_cipher
        .decrypt(nonce_ga, ciphertext.as_ref())
        .map_err(|_| CryptoError::DecryptionFailed)?;

    // Wrap plain result in zeroizing structure
    Ok(PlaintextData::new(plaintext_bytes))
}
