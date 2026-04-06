use async_trait::async_trait;
use hex::FromHex;
use std::env;
use std::sync::Arc;

use super::keys::KeyEncryptionKey;

/// An abstract trait for providing a Key Encryption Key (KEK).
/// This allows us to start with EnvKekProvider, and in the future,
/// implement `VaultKekProvider` to retrieve the KEK or perform KMS operations via HashiCorp Vault.
#[async_trait]
pub trait KekProvider: Send + Sync {
    async fn get_kek(&self) -> Result<KeyEncryptionKey, String>;
}

/// A standard provider fetching KEK via `APP_KEK` environment variable (32-bytes hex encoded).
pub struct EnvKekProvider {
    kek: KeyEncryptionKey,
}

impl EnvKekProvider {
    pub fn new() -> Result<Self, String> {
        let hex_val = env::var("APP_KEK")
            .map_err(|_| "APP_KEK environment variable must be set".to_string())?;
        let bytes: [u8; 32] = <[u8; 32]>::from_hex(&hex_val)
            .map_err(|_| "APP_KEK must be a valid 32-byte hex string".to_string())?;

        Ok(Self {
            kek: KeyEncryptionKey::new(bytes),
        })
    }
}

#[async_trait]
impl KekProvider for EnvKekProvider {
    async fn get_kek(&self) -> Result<KeyEncryptionKey, String> {
        // In a real application, the Env provider might just hold the key in memory.
        // For Vault, this async call might go across the network to retrieve or rotate the key.
        Ok(self.kek.clone())
    }
}

pub type DynKekProvider = Arc<dyn KekProvider>;
