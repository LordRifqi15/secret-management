use axum::{extract::State, http::StatusCode, Json};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use tracing::{debug, error};
use super::models::{
    DecryptRequest, DecryptResponse, EncryptRequest, EncryptResponse, ErrorResponse,
};
use crate::app::SharedAppState;
use crate::crypto::{
    envelope::{decrypt_envelope, encrypt_envelope, EncryptedEnvelope},
    keys::PlaintextData,
};

#[utoipa::path(
    post,
    path = "/encrypt",
    tag = "secret-manager",
    request_body = EncryptRequest,
    responses(
        (status = 200, description = "Successfully encrypted", body = EncryptResponse),
        (status = 400, description = "Invalid payload", body = ErrorResponse),
        (status = 401, description = "Missing or invalid API key", body = ErrorResponse),
        (status = 403, description = "Forbidden (role)", body = ErrorResponse),
        (status = 413, description = "Payload too large", body = ErrorResponse),
        (status = 429, description = "Rate limit exceeded", body = ErrorResponse),
        (status = 500, description = "Internal Server Error", body = ErrorResponse),
    ),
    security(("api_key" = []))
)]
// deprecated: kept for back compat, use /v1/crypto/* instead
pub async fn encrypt_handler(
    State(state): State<SharedAppState>,
    Json(payload): Json<EncryptRequest>,
) -> Result<Json<EncryptResponse>, (StatusCode, Json<ErrorResponse>)> {
    payload.validate().map_err(|(status, msg)| (status, Json(ErrorResponse { error: msg })))?;

    let plaintext_bytes = BASE64.decode(&payload.payload_b64).map_err(|_| {
        (StatusCode::BAD_REQUEST, Json(ErrorResponse { error: "Invalid base64 encoding".to_string() }))
    })?;

    if plaintext_bytes.is_empty() {
        return Err((StatusCode::BAD_REQUEST, Json(ErrorResponse { error: "Plaintext must not be empty".to_string() })));
    }
    if plaintext_bytes.len() > 1_000_000 {
        return Err((StatusCode::PAYLOAD_TOO_LARGE, Json(ErrorResponse { error: "Decoded payload exceeds 1MB".to_string() })));
    }

    let plaintext_data = PlaintextData::new(plaintext_bytes);
    // ponytail: handlers use KekStore directly with default tenant/purpose/algorithm; no spawn_blocking in crypto layer
    let envelope = encrypt_envelope(&state.kek_store, "default", "default", "aes-256-gcm", &plaintext_data).map_err(|e| {
        error!("Encryption failed: {}", e);
        (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse { error: "Encryption failed".to_string() }))
    })?;

    debug!("Successfully encrypted payload key_id={}", envelope.key_id);

    Ok(Json(EncryptResponse {
        ciphertext_b64: envelope.ciphertext_b64,
        nonce_b64: envelope.nonce_b64,
        encrypted_dek_b64: envelope.encrypted_dek_b64,
        dek_nonce_b64: envelope.dek_nonce_b64,
        key_id: envelope.key_id,
    }))
}

#[utoipa::path(
    post,
    path = "/decrypt",
    tag = "secret-manager",
    request_body = DecryptRequest,
    responses(
        (status = 200, description = "Successfully decrypted", body = DecryptResponse),
        (status = 400, description = "Decryption failed or invalid payload", body = ErrorResponse),
        (status = 401, description = "Missing or invalid API key", body = ErrorResponse),
        (status = 403, description = "Forbidden (role)", body = ErrorResponse),
        (status = 413, description = "Payload too large", body = ErrorResponse),
        (status = 429, description = "Rate limit exceeded", body = ErrorResponse),
        (status = 500, description = "Internal Server Error", body = ErrorResponse),
    ),
    security(("api_key" = []))
)]
// deprecated: kept for back compat
pub async fn decrypt_handler(
    State(state): State<SharedAppState>,
    Json(payload): Json<DecryptRequest>,
) -> Result<Json<DecryptResponse>, (StatusCode, Json<ErrorResponse>)> {
    payload.validate().map_err(|(status, msg)| (status, Json(ErrorResponse { error: msg })))?;

    let envelope = EncryptedEnvelope {
        ciphertext_b64: payload.ciphertext_b64.clone(),
        nonce_b64: payload.nonce_b64.clone(),
        encrypted_dek_b64: payload.encrypted_dek_b64.clone(),
        dek_nonce_b64: payload.dek_nonce_b64.clone(),
        key_id: payload.key_id.clone(),
        tenant_id: String::new(),
        purpose: String::new(),
        algorithm: "aes-256-gcm".to_string(),
    };

    // ponytail: KekStore per-tenant + resolve_raw fallback handles unknown key_id
    let plaintext_data = decrypt_envelope(&state.kek_store, &envelope).map_err(|e| {
        if matches!(e, crate::crypto::envelope::CryptoError::UnknownKeyId) {
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse { error: format!("unknown key_id: {}", envelope.key_id) }),
            );
        }
        error!("Decryption failed: {}", e);
        (StatusCode::BAD_REQUEST, Json(ErrorResponse { error: "Decryption failed: invalid ciphertext or corrupted envelope".to_string() }))
    })?;

    debug!("Successfully decrypted payload key_id={}", envelope.key_id);
    let payload_b64 = BASE64.encode(plaintext_data.as_bytes());
    Ok(Json(DecryptResponse { payload_b64 }))
}
