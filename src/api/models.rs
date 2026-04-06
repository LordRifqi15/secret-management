use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

#[derive(Debug, Deserialize, ToSchema)]
pub struct EncryptRequest {
    /// Base64 encoded plaintext payload
    pub payload_b64: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct EncryptResponse {
    pub ciphertext_b64: String,
    pub nonce_b64: String,
    pub encrypted_dek_b64: String,
    pub dek_nonce_b64: String,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct DecryptRequest {
    pub ciphertext_b64: String,
    pub nonce_b64: String,
    pub encrypted_dek_b64: String,
    pub dek_nonce_b64: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct DecryptResponse {
    /// Base64 encoded decrypted payload
    pub payload_b64: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ErrorResponse {
    pub error: String,
}
