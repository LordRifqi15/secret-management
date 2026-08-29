use aes_gcm::{aead::generic_array::GenericArray, Aes256Gcm, KeyInit};
use hex::FromHex;
use std::{collections::HashMap, env, sync::Arc};

use super::keys::KeyEncryptionKey;

/// Rotatable KEK store — current + optional previous for decrypt fallback.
// ponytail: 2-key store covers 99% rotations; expand to HashMap if >2 versions needed
#[derive(Clone)]
pub struct KekStore {
    current_id: String,
    current: Arc<Aes256Gcm>,
    previous: HashMap<String, Arc<Aes256Gcm>>,
}

impl KekStore {
    pub fn from_env() -> Result<Self, String> {
        let hex = env::var("APP_KEK").map_err(|_| "APP_KEK must be set".to_string())?;
        let id = env::var("APP_KEK_ID").unwrap_or_else(|_| "primary".to_string());
        let kek = Self::cipher_from_hex(&hex)?;
        let mut previous = HashMap::new();
        if let Ok(old_hex) = env::var("APP_KEK_OLD") {
            let old_id = env::var("APP_KEK_OLD_ID").unwrap_or_else(|_| "previous".to_string());
            if old_id != id {
                let old_cipher = Self::cipher_from_hex(&old_hex)?;
                previous.insert(old_id, old_cipher);
            }
        }
        for (k, v) in env::vars() {
            if k.starts_with("APP_KEK_") && k != "APP_KEK_ID" && k != "APP_KEK_OLD" && k != "APP_KEK_OLD_ID" {
                let suffix = k.strip_prefix("APP_KEK_").unwrap().to_lowercase().replace('_', "-");
                if suffix == id || previous.contains_key(&suffix) {
                    continue;
                }
                if let Ok(cipher) = Self::cipher_from_hex(&v) {
                    previous.insert(suffix, cipher);
                }
            }
        }
        Ok(Self { current_id: id, current: kek, previous })
    }

    fn cipher_from_hex(hex: &str) -> Result<Arc<Aes256Gcm>, String> {
        let bytes: [u8; 32] = <[u8; 32]>::from_hex(hex)
            .map_err(|_| "KEK must be 32-byte hex (64 chars)".to_string())?;
        let kek = KeyEncryptionKey::new(bytes);
        Ok(Arc::new(Aes256Gcm::new(GenericArray::from_slice(kek.as_bytes()))))
    }

    pub fn current_id(&self) -> &str {
        &self.current_id
    }
    pub fn current_arc(&self) -> Arc<Aes256Gcm> {
        Arc::clone(&self.current)
    }
    pub fn get(&self, id: &str) -> Option<&Aes256Gcm> {
        if id == self.current_id {
            Some(&self.current)
        } else {
            self.previous.get(id).map(|a| a.as_ref())
        }
    }
    pub fn resolve(&self, id: &str) -> Option<&Aes256Gcm> {
        self.get(id).or_else(|| {
            if id == "primary" && self.current_id != "primary" {
                Some(&self.current)
            } else {
                None
            }
        })
    }
    pub fn resolve_arc(&self, id: &str) -> Option<Arc<Aes256Gcm>> {
        if id == self.current_id {
            Some(Arc::clone(&self.current))
        } else if let Some(c) = self.previous.get(id) {
            Some(Arc::clone(c))
        } else if id == "primary" && self.current_id != "primary" {
            Some(Arc::clone(&self.current))
        } else {
            None
        }
    }
}

// Backward compat helper
pub fn load_kek() -> Result<KeyEncryptionKey, String> {
    let hex = env::var("APP_KEK").map_err(|_| "APP_KEK must be set".to_string())?;
    let bytes: [u8; 32] = <[u8; 32]>::from_hex(&hex)
        .map_err(|_| "APP_KEK must be valid 32-byte hex".to_string())?;
    Ok(KeyEncryptionKey::new(bytes))
}
