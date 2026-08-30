use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

/// BSSN security classification — Rendah < Tinggi < Strategis
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub enum SecurityClassification {
    Rendah,
    Tinggi,
    Strategis,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct PolicyDto {
    pub policy: String,
    pub purpose: String,
    pub tenant_id: String,
    pub classification: SecurityClassification,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct EncryptRequest {
    pub policy: String,
    pub purpose: String,
    pub tenant_id: String,
    /// Base64-encoded plaintext to encrypt
    pub data: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct DecryptRequest {
    pub policy: String,
    pub purpose: String,
    pub tenant_id: String,
    /// Base64-encoded ciphertext / envelope to decrypt
    pub data: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct EncryptResponse {
    pub ciphertext_b64: String,
    pub key_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct DecryptResponse {
    pub plaintext_b64: String,
}
