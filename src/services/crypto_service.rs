use std::sync::Arc;

use crate::crypto::envelope::{self, CryptoError, EncryptedEnvelope};
use crate::crypto::keys::PlaintextData;
use crate::crypto::policy::{validate_primitive_compliance, Policy};
use crate::services::key_service::KeyService;

/// Envelope encryption service bound to a KeyService.
/// Handles policy validation, zeroize (via PlaintextData), and Arc sharing.
pub struct CryptoService {
    key_service: Arc<KeyService>,
}

impl CryptoService {
    pub fn new(key_service: Arc<KeyService>) -> Self {
        Self { key_service }
    }

    /// Encrypt with tenant-scoped KEK.
    /// Validates policy (aes-256-gcm must be allowed for classification), then
    /// delegates to `envelope::encrypt_envelope`. Plaintext is zeroized on drop.
    pub async fn encrypt(
        &self,
        tenant_id: &str,
        purpose: &str,
        policy: &Policy,
        plaintext: PlaintextData,
    ) -> Result<EncryptedEnvelope, CryptoError> {
        // ponytail: single primitive check; Strategis enforces allowlist
        validate_primitive_compliance("aes-256-gcm", policy.classification)?;
        let store = self
            .key_service
            .get_store(tenant_id)
            .or_else(|| self.key_service.get_store("default"))
            .ok_or(CryptoError::UnknownKeyId)?;
        // delegate to envelope with CanonicalAad + KekStore + algorithm trait
        envelope::encrypt_envelope(store, tenant_id, purpose, "aes-256-gcm", &plaintext)
        // plaintext dropped here -> zeroized via ZeroizeOnDrop
    }

    /// Decrypt envelope with tenant-scoped KEK (resolves key_id with rotation fallback).
    pub async fn decrypt(
        &self,
        tenant_id: &str,
        envelope: &EncryptedEnvelope,
    ) -> Result<PlaintextData, CryptoError> {
        let store = self
            .key_service
            .get_store(tenant_id)
            .or_else(|| self.key_service.get_store("default"))
            .ok_or(CryptoError::UnknownKeyId)?;
        envelope::decrypt_envelope(store, envelope)
    }
}
