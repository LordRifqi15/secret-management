use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

/// Max base64 payload size: 1.5M chars (~1MB decoded).
const MAX_B64_LEN: usize = 1_500_000;
/// Max nonce/DEK fields: 200 chars each (12-byte nonce = 24 chars base64).
const MAX_FIELD_LEN: usize = 200;

fn validate_max_len(s: &str, max: usize, field_name: &str) -> Result<(), String> {
    if s.len() > max {
        Err(format!("{} exceeds maximum length of {} bytes", field_name, max))
    } else if s.is_empty() {
        Err(format!("{} must not be empty", field_name))
    } else {
        Ok(())
    }
}

/// Request body for the `/encrypt` endpoint.
#[derive(Debug, Deserialize, ToSchema)]
pub struct EncryptRequest {
    /// Base64 encoded plaintext payload (max 1MB decoded).
    #[schema(example = "c3RyaW5n")]
    pub payload_b64: String,
}

impl EncryptRequest {
    pub fn validate(&self) -> Result<(), (axum::http::StatusCode, String)> {
        use axum::http::StatusCode;
        validate_max_len(&self.payload_b64, MAX_B64_LEN, "payload_b64")
            .map_err(|e| (StatusCode::PAYLOAD_TOO_LARGE, e))
    }
}
/// Successful encryption response containing the envelope.
#[derive(Debug, Serialize, ToSchema)]
pub struct EncryptResponse {
    /// Base64 encoded ciphertext of the plaintext data.
    #[schema(example = "YWJjZGVmZ2hpams")]
    pub ciphertext_b64: String,
    /// Base64 encoded nonce (12 bytes) used for data encryption.
    #[schema(example = "MTIzNDU2Nzg5MDEy")]
    pub nonce_b64: String,
    /// Base64 encoded DEK encrypted with the KEK.
    #[schema(example = "ZmVkY2JhOTg3NjU0MzIxMA==")]
    pub encrypted_dek_b64: String,
    /// Base64 encoded nonce (12 bytes) used for DEK encryption.
    #[schema(example = "OTg3NjU0MzIxMDk4NzY=")]
    pub dek_nonce_b64: String,
    /// KEK id used to wrap DEK — for rotation.
    #[schema(example = "primary")]
    pub key_id: String,
}
/// Request body for the `/decrypt` endpoint.
#[derive(Debug, Deserialize, ToSchema)]
pub struct DecryptRequest {
    /// Base64 encoded ciphertext from `/encrypt` response.
    #[schema(example = "YWJjZGVmZ2hpams")]
    pub ciphertext_b64: String,
    /// Base64 encoded nonce from `/encrypt` response.
    #[schema(example = "MTIzNDU2Nzg5MDEy")]
    pub nonce_b64: String,
    /// Base64 encoded encrypted DEK from `/encrypt` response.
    #[schema(example = "ZmVkY2JhOTg3NjU0MzIxMA==")]
    pub encrypted_dek_b64: String,
    /// Base64 encoded DEK nonce from `/encrypt` response.
    #[schema(example = "OTg3NjU0MzIxMDk4NzY=")]
    pub dek_nonce_b64: String,
    /// KEK id that wrapped DEK — must match envelope's key_id.
    #[schema(example = "primary")]
    #[serde(default = "default_key_id")]
    pub key_id: String,
}

fn default_key_id() -> String {
    "primary".to_string()
}

impl DecryptRequest {
    pub fn validate(&self) -> Result<(), (axum::http::StatusCode, String)> {
        use axum::http::StatusCode;
        validate_max_len(&self.ciphertext_b64, MAX_B64_LEN, "ciphertext_b64")
            .map_err(|e| (StatusCode::PAYLOAD_TOO_LARGE, e))?;
        validate_max_len(&self.nonce_b64, MAX_FIELD_LEN, "nonce_b64")
            .map_err(|e| (StatusCode::BAD_REQUEST, e))?;
        validate_max_len(&self.encrypted_dek_b64, MAX_FIELD_LEN, "encrypted_dek_b64")
            .map_err(|e| (StatusCode::BAD_REQUEST, e))?;
        validate_max_len(&self.dek_nonce_b64, MAX_FIELD_LEN, "dek_nonce_b64")
            .map_err(|e| (StatusCode::BAD_REQUEST, e))?;
        Ok(())
    }
}

/// Successful decryption response.
#[derive(Debug, Serialize, ToSchema)]
pub struct DecryptResponse {
    /// Base64 encoded decrypted plaintext.
    #[schema(example = "bXkgc2VjcmV0")]
    pub payload_b64: String,
}

/// Error response returned by all error paths.
#[derive(Debug, Serialize, ToSchema)]
pub struct ErrorResponse {
    /// Human-readable error message. Never exposes internal details.
    #[schema(example = "Invalid base64 encoding")]
    pub error: String,
}

