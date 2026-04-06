use axum::{extract::State, http::StatusCode, Json};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use tracing::{error, info};

use super::models::{
    DecryptRequest, DecryptResponse, EncryptRequest, EncryptResponse, ErrorResponse,
};
use crate::crypto::{
    envelope::{decrypt_envelope, encrypt_envelope, EncryptedEnvelope},
    kek_provider::DynKekProvider,
    keys::PlaintextData,
};

#[utoipa::path(
    post,
    path = "/encrypt",
    request_body = EncryptRequest,
    responses(
        (status = 200, description = "Successfully encrypted", body = EncryptResponse),
        (status = 400, description = "Invalid payload", body = ErrorResponse),
        (status = 500, description = "Internal Server Error", body = ErrorResponse),
    )
)]
pub async fn encrypt_handler(
    State(kek_provider): State<DynKekProvider>,
    Json(payload): Json<EncryptRequest>,
) -> Result<Json<EncryptResponse>, (StatusCode, Json<ErrorResponse>)> {
    // 1. Decode base64 input
    let plaintext_bytes = BASE64.decode(&payload.payload_b64).map_err(|_| {
        let err = ErrorResponse {
            error: "Invalid base64 payload".to_string(),
        };
        (StatusCode::BAD_REQUEST, Json(err))
    })?;

    // Wrap in standard zeroizing structure
    let plaintext_data = PlaintextData::new(plaintext_bytes);

    // 2. Fetch KEK
    let kek = kek_provider.get_kek().await.map_err(|e| {
        error!("Failed to retrieve KEK: {}", e);
        let err = ErrorResponse {
            error: "Internal Server Error".to_string(),
        };
        (StatusCode::INTERNAL_SERVER_ERROR, Json(err))
    })?;

    // 3. Encrypt via Envelope Engine
    let envelope = encrypt_envelope(&kek, &plaintext_data).map_err(|e| {
        error!("Encryption failed: {}", e);
        let err = ErrorResponse {
            error: "Encryption failure".to_string(),
        };
        (StatusCode::INTERNAL_SERVER_ERROR, Json(err))
    })?;

    info!("Successfully encrypted payload");

    // 4. Return EncryptedEnvelope fields
    Ok(Json(EncryptResponse {
        ciphertext_b64: envelope.ciphertext_b64,
        nonce_b64: envelope.nonce_b64,
        encrypted_dek_b64: envelope.encrypted_dek_b64,
        dek_nonce_b64: envelope.dek_nonce_b64,
    }))
}

#[utoipa::path(
    post,
    path = "/decrypt",
    request_body = DecryptRequest,
    responses(
        (status = 200, description = "Successfully decrypted", body = DecryptResponse),
        (status = 400, description = "Decryption failed or invalid payload", body = ErrorResponse),
        (status = 500, description = "Internal Server Error", body = ErrorResponse),
    )
)]
pub async fn decrypt_handler(
    State(kek_provider): State<DynKekProvider>,
    Json(payload): Json<DecryptRequest>,
) -> Result<Json<DecryptResponse>, (StatusCode, Json<ErrorResponse>)> {
    let envelope = EncryptedEnvelope {
        ciphertext_b64: payload.ciphertext_b64,
        nonce_b64: payload.nonce_b64,
        encrypted_dek_b64: payload.encrypted_dek_b64,
        dek_nonce_b64: payload.dek_nonce_b64,
    };

    // 1. Fetch KEK
    let kek = kek_provider.get_kek().await.map_err(|e| {
        error!("Failed to retrieve KEK: {}", e);
        let err = ErrorResponse {
            error: "Internal Server Error".to_string(),
        };
        (StatusCode::INTERNAL_SERVER_ERROR, Json(err))
    })?;

    // 2. Decrypt via Envelope Engine
    let plaintext_data = decrypt_envelope(&kek, &envelope).map_err(|e| {
        error!("Decryption failed: {}", e);
        let err = ErrorResponse {
            error: "Decryption failure".to_string(),
        };
        (StatusCode::BAD_REQUEST, Json(err))
    })?;

    info!("Successfully decrypted payload");

    // 3. Encode to base64 and respond
    let payload_b64 = BASE64.encode(plaintext_data.as_bytes());

    Ok(Json(DecryptResponse { payload_b64 }))
}
