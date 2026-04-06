use zeroize::{Zeroize, ZeroizeOnDrop};

/// A memory-safe wrapper for unencrypted sensitive data.
/// It implements `ZeroizeOnDrop` so that whenever it goes out of scope,
/// its internal byte buffer is securely zeroed out.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct PlaintextData(pub Vec<u8>);

impl PlaintextData {
    pub fn new(data: Vec<u8>) -> Self {
        Self(data)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// The Key Encryption Key (KEK).
/// Master key, used to encrypt/decrypt individual Data Encryption Keys (DEKs).
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct KeyEncryptionKey(pub [u8; 32]);

impl KeyEncryptionKey {
    pub fn new(key: [u8; 32]) -> Self {
        Self(key)
    }
    
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// The Data Encryption Key (DEK).
/// Randomly generated for each distinct payload. Dropped immediately after use.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct DataEncryptionKey(pub [u8; 32]);

impl DataEncryptionKey {
    pub fn new(key: [u8; 32]) -> Self {
        Self(key)
    }
    
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}
