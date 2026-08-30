use axum::{extract::State, http::StatusCode, Json};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use crate::api::dto::*;
use crate::api::models::ErrorResponse;
use crate::app::SharedAppState;
use crate::crypto::hash::{Blake2b512, Sha256, Sha3_256, Sha512};
use crate::crypto::keys::PlaintextData;
use crate::crypto::policy::{validate_primitive_compliance, SecurityClassification};
use crate::crypto::traits::Hasher;

// ponytail: minimal v1 handlers, keep file <130 lines
fn class(s: &str) -> SecurityClassification {
    match s.trim().to_ascii_lowercase().as_str() {
        "rendah" => SecurityClassification::Rendah,
        "tinggi" => SecurityClassification::Tinggi,
        _ => SecurityClassification::Strategis,
    }
}
fn err(c: StatusCode, m: String) -> (StatusCode, Json<ErrorResponse>) {
    (c, Json(ErrorResponse { error: m }))
}
fn b64d(s: &str) -> Result<Vec<u8>, (StatusCode, Json<ErrorResponse>)> {
    B64.decode(s).map_err(|_| err(StatusCode::BAD_REQUEST, "Invalid base64".into()))
}
#[utoipa::path(post, path="/v1/crypto/encrypt", request_body=EncryptDto, responses((status=200, body=EncryptV1Response)), security(("api_key"=[])))]
pub async fn encrypt_v1(State(st): State<SharedAppState>, Json(d): Json<EncryptDto>) -> Result<Json<EncryptV1Response>, (StatusCode, Json<ErrorResponse>)> {
    let c = class(&d.classification);
    validate_primitive_compliance("aes-256-gcm", c).map_err(|e| err(StatusCode::BAD_REQUEST, e.to_string()))?;
    st.key_service.get_store(&d.tenant_id).or_else(|| st.key_service.get_store("default")).ok_or(err(StatusCode::BAD_REQUEST, "Unknown tenant".into()))?;
    let pt = b64d(&d.data)?;
    if pt.is_empty() || pt.len() > 1_000_000 { return Err(err(StatusCode::BAD_REQUEST, "Invalid payload size".into())); }
    let pol = crate::crypto::policy::Policy { classification: c, purpose: d.purpose.clone(), tenant_id: d.tenant_id.clone() };
    let env = st.crypto_service.encrypt(&d.tenant_id, &d.purpose, &pol, PlaintextData::new(pt)).await.map_err(|e| err(StatusCode::BAD_REQUEST, e.to_string()))?;
    Ok(Json(EncryptV1Response { ciphertext_b64: env.ciphertext_b64, nonce_b64: env.nonce_b64, encrypted_dek_b64: env.encrypted_dek_b64, dek_nonce_b64: env.dek_nonce_b64, key_id: env.key_id, algorithm: env.algorithm, tenant_id: env.tenant_id, purpose: env.purpose }))
}
#[utoipa::path(post, path="/v1/crypto/decrypt", request_body=DecryptDto, responses((status=200, body=DecryptV1Response)), security(("api_key"=[])))]
pub async fn decrypt_v1(State(st): State<SharedAppState>, Json(d): Json<DecryptDto>) -> Result<Json<DecryptV1Response>, (StatusCode, Json<ErrorResponse>)> {
    let c = class(&d.classification);
    validate_primitive_compliance("aes-256-gcm", c).map_err(|e| err(StatusCode::BAD_REQUEST, e.to_string()))?;
    st.key_service.get_store(&d.tenant_id).or_else(|| st.key_service.get_store("default")).ok_or(err(StatusCode::BAD_REQUEST, "Unknown tenant".into()))?;
    let raw = b64d(&d.data)?;
    let env: crate::crypto::envelope::EncryptedEnvelope = serde_json::from_slice(&raw).map_err(|_| err(StatusCode::BAD_REQUEST, "Invalid envelope".into()))?;
    let pt = st.crypto_service.decrypt(&d.tenant_id, &env).await.map_err(|e| err(StatusCode::BAD_REQUEST, e.to_string()))?;
    Ok(Json(DecryptV1Response { payload_b64: B64.encode(pt.as_bytes()) }))
}
#[utoipa::path(post, path="/v1/crypto/sign", request_body=SignDto, responses((status=200, body=SignResponse)), security(("api_key"=[])))]
pub async fn sign_v1(State(st): State<SharedAppState>, Json(d): Json<SignDto>) -> Result<Json<SignResponse>, (StatusCode, Json<ErrorResponse>)> {
    let c = class(&d.classification);
    validate_primitive_compliance(&d.policy, c).map_err(|e| err(StatusCode::BAD_REQUEST, e.to_string()))?;
    st.key_service.get_store(&d.tenant_id).or_else(|| st.key_service.get_store("default")).ok_or(err(StatusCode::BAD_REQUEST, "Unknown tenant".into()))?;
    let msg = b64d(&d.data)?;
    let pol = d.policy.trim().to_ascii_lowercase();
    let sig = if pol.contains("rsa") {
        use rsa::pss::Pss;
        use sha2::{Digest, Sha256};
        let rsa_key = st.key_service.rsa_key(&d.tenant_id);
        let pss = Pss::new::<Sha256>();
        let hashed = Sha256::digest(&msg);
        rsa_key.sign_with_rng(&mut rand::rngs::OsRng, pss, &hashed).map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "Signing failed".into()))?
    } else {
        use ed25519_dalek::Signer;
        let sk = st.key_service.ed25519_key(&d.tenant_id);
        sk.sign(&msg).to_vec()
    };
    Ok(Json(SignResponse { signature_b64: B64.encode(sig), key_id: "primary".into(), algorithm: d.policy }))
}
#[utoipa::path(post, path="/v1/crypto/verify", request_body=VerifyDto, responses((status=200, body=VerifyResponse)), security(("api_key"=[])))]
pub async fn verify_v1(State(st): State<SharedAppState>, Json(d): Json<VerifyDto>) -> Result<Json<VerifyResponse>, (StatusCode, Json<ErrorResponse>)> {
    let c = class(&d.classification);
    validate_primitive_compliance(&d.policy, c).map_err(|e| err(StatusCode::BAD_REQUEST, e.to_string()))?;
    let msg = b64d(&d.data)?;
    let sig = b64d(&d.signature)?;
    let pol = d.policy.trim().to_ascii_lowercase();
    let ok = if pol.contains("rsa") {
        use rsa::pss::Pss;
        use sha2::{Digest, Sha256};
        let rsa_key = st.key_service.rsa_key(&d.tenant_id);
        let pss = Pss::new::<Sha256>();
        let hashed = Sha256::digest(&msg);
        rsa_key.to_public_key().verify(pss, &hashed, &sig).is_ok()
    } else {
        use ed25519_dalek::{Signature, Verifier};
        let vk = st.key_service.ed25519_key(&d.tenant_id).verifying_key();
        if sig.len() != 64 { false } else { let s = Signature::from_bytes(&sig.clone().try_into().unwrap()); vk.verify(&msg, &s).is_ok() }
    };
    if !ok { return Err(err(StatusCode::BAD_REQUEST, "Verification failed".into())); }
    Ok(Json(VerifyResponse { valid: ok }))
}
#[utoipa::path(post, path="/v1/crypto/hash", request_body=HashDto, responses((status=200, body=HashResponse)), security(("api_key"=[])))]
pub async fn hash_v1(State(_st): State<SharedAppState>, Json(d): Json<HashDto>) -> Result<Json<HashResponse>, (StatusCode, Json<ErrorResponse>)> {
    let c = class(&d.classification);
    let lower = d.algo.trim().to_ascii_lowercase();
    let canon = match lower.as_str() {
        "sha256" => "sha-256",
        "sha512" => "sha-512",
        "sha3_256" => "sha3-256",
        "blake2b512" => "blake2b",
        o => o,
    };
    validate_primitive_compliance(canon, c).map_err(|e| err(StatusCode::BAD_REQUEST, e.to_string()))?;
    let data = b64d(&d.data)?;
    let h: Vec<u8> = match lower.as_str() {
        "sha256" | "sha-256" => Sha256.hash(&data),
        "sha512" | "sha-512" => Sha512.hash(&data),
        "sha3-256" | "sha3_256" => Sha3_256.hash(&data),
        "blake2b" | "blake2b-512" => Blake2b512.hash(&data),
        _ => return Err(err(StatusCode::BAD_REQUEST, "Unsupported algo".into())),
    };
    Ok(Json(HashResponse { hash_b64: B64.encode(h), algo: d.algo }))
}
