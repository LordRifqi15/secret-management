use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct EncryptDto {
    pub policy: String,
    pub purpose: String,
    pub tenant_id: String,
    pub classification: String,
    pub data: String,
}
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct DecryptDto {
    pub policy: String,
    pub purpose: String,
    pub tenant_id: String,
    pub classification: String,
    pub data: String,
}
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct SignDto {
    pub policy: String,
    pub purpose: String,
    pub tenant_id: String,
    pub classification: String,
    pub data: String,
}
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct VerifyDto {
    pub policy: String,
    pub purpose: String,
    pub tenant_id: String,
    pub classification: String,
    pub data: String,
    pub signature: String,
}
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct HashDto {
    pub policy: String,
    pub purpose: String,
    pub tenant_id: String,
    pub classification: String,
    pub data: String,
    pub algo: String,
}
#[derive(Debug, Serialize, ToSchema)]
pub struct EncryptV1Response {
    pub ciphertext_b64: String,
    pub nonce_b64: String,
    pub encrypted_dek_b64: String,
    pub dek_nonce_b64: String,
    pub key_id: String,
    pub algorithm: String,
    pub tenant_id: String,
    pub purpose: String,
}
#[derive(Debug, Serialize, ToSchema)]
pub struct DecryptV1Response {
    pub payload_b64: String,
}
#[derive(Debug, Serialize, ToSchema)]
pub struct SignResponse {
    pub signature_b64: String,
    pub key_id: String,
    pub algorithm: String,
}
#[derive(Debug, Serialize, ToSchema)]
pub struct VerifyResponse {
    pub valid: bool,
}
#[derive(Debug, Serialize, ToSchema)]
pub struct HashResponse {
    pub hash_b64: String,
    pub algo: String,
}
