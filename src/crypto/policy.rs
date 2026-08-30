pub use crate::domain::errors::CryptoError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityClassification {
    Rendah,
    Tinggi,
    Strategis,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Policy {
    pub classification: SecurityClassification,
    pub purpose: String,
    pub tenant_id: String,
}

pub fn validate_primitive_compliance(algo: &str, level: SecurityClassification) -> Result<(), CryptoError> {
    // ponytail: only Strategis is strict; Rendah/Tinggi permissive
    if level != SecurityClassification::Strategis {
        return Ok(());
    }
    let normalized = algo.trim().to_ascii_lowercase();
    let allowed = matches!(
        normalized.as_str(),
        "aes-256-gcm"
            | "chacha20-poly1305"
            | "rsa-oaep-3072"
            | "x25519"
            | "ed25519"
            | "rsa-pss-3072"
            | "sha-256"
            | "sha-512"
            | "sha3-256"
            | "blake2b"
    );
    if allowed {
        Ok(())
    } else {
        Err(CryptoError::PolicyViolation(format!(
            "algorithm '{}' not allowed for Strategis classification",
            algo.trim()
        )))
    }
}
