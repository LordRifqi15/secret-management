use thiserror::Error;

/// Unified BSSN crypto error — single source of truth.
/// Re-exported by `crate::crypto::envelope` and `crate::crypto::policy` for compatibility.
#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("Failed to encrypt data")]
    EncryptionFailed,
    #[error("Failed to decrypt data")]
    DecryptionFailed,
    #[error("Invalid Base64 encoding")]
    InvalidBase64,
    #[error("Unknown key id")]
    UnknownKeyId,
    #[error("Policy violation: {0}")]
    PolicyViolation(String),
    #[error("Invalid tenant")]
    InvalidTenant,
    #[error("Rate limited")]
    RateLimited,
    #[error("Unauthorized")]
    Unauthorized,
    #[error("Signing failed")]
    SigningFailed,
    #[error("Verification failed")]
    VerificationFailed,
    #[error("Key exchange failed")]
    KeyExchangeFailed,
    #[error("Invalid key")]
    InvalidKey,
    #[error("Invalid signature")]
    InvalidSignature,
}

pub type Result<T> = std::result::Result<T, CryptoError>;
