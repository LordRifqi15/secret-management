use zeroize::{Zeroize, ZeroizeOnDrop};

/// Memory-safe wrapper for unencrypted sensitive data.
/// Zeroized on drop.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct PlaintextData(Vec<u8>);

impl PlaintextData {
    pub fn new(data: Vec<u8>) -> Self {
        Self(data)
    }
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
    // ponytail: no Clone — duplicates key material in memory
}

/// Master key (KEK) — encrypts DEKs.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct KeyEncryptionKey([u8; 32]);

impl KeyEncryptionKey {
    pub fn new(key: [u8; 32]) -> Self {
        Self(key)
    }
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Data Encryption Key (DEK) — per-payload, dropped after use.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct DataEncryptionKey([u8; 32]);

impl DataEncryptionKey {
    pub fn new(key: [u8; 32]) -> Self {
        Self(key)
    }
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}
