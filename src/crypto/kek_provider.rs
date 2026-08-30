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
    current_raw: [u8; 32],
    previous: HashMap<String, Arc<Aes256Gcm>>,
    previous_raw: HashMap<String, [u8; 32]>,
}

impl KekStore {
    pub fn from_env() -> Result<Self, String> {
        let hex = env::var("APP_KEK").map_err(|_| "APP_KEK must be set".to_string())?;
        let id = env::var("APP_KEK_ID").unwrap_or_else(|_| "primary".to_string());
        let (raw, kek) = Self::pair_from_hex(&hex)?;
        let mut previous = HashMap::new();
        let mut previous_raw = HashMap::new();
        if let Ok(old_hex) = env::var("APP_KEK_OLD") {
            let old_id = env::var("APP_KEK_OLD_ID").unwrap_or_else(|_| "previous".to_string());
            if old_id != id {
                if let Ok((r, c)) = Self::pair_from_hex(&old_hex) {
                    previous.insert(old_id.clone(), c);
                    previous_raw.insert(old_id, r);
                }
            }
        }
        for (k, v) in env::vars() {
            if k.starts_with("APP_KEK_") && k != "APP_KEK_ID" && k != "APP_KEK_OLD" && k != "APP_KEK_OLD_ID" {
                let suffix = k.strip_prefix("APP_KEK_").unwrap().to_lowercase().replace('_', "-");
                if suffix == id || previous.contains_key(&suffix) {
                    continue;
                }
                if let Ok((r, c)) = Self::pair_from_hex(&v) {
                    previous.insert(suffix.clone(), c);
                    previous_raw.insert(suffix, r);
                }
            }
        }
        Ok(Self {
            current_id: id,
            current: kek,
            current_raw: raw,
            previous,
            previous_raw,
        })
    }

    /// Construct from hex for per-tenant stores (e.g. APP_TENANT_<id>_KEK).
    // ponytail: minimal helper to avoid duplicating hex->cipher logic in key_service
    pub fn from_hex(id: String, hex: &str) -> Result<Self, String> {
        let (raw, cipher) = Self::pair_from_hex(hex)?;
        Ok(Self {
            current_id: id,
            current: cipher,
            current_raw: raw,
            previous: HashMap::new(),
            previous_raw: HashMap::new(),
        })
    }

    fn pair_from_hex(hex: &str) -> Result<([u8; 32], Arc<Aes256Gcm>), String> {
        let bytes: [u8; 32] = <[u8; 32]>::from_hex(hex)
            .map_err(|_| "KEK must be 32-byte hex (64 chars)".to_string())?;
        let kek = KeyEncryptionKey::new(bytes);
        let cipher = Arc::new(Aes256Gcm::new(GenericArray::from_slice(kek.as_bytes())));
        Ok((bytes, cipher))
    }

    #[allow(dead_code)]
    fn cipher_from_hex(hex: &str) -> Result<Arc<Aes256Gcm>, String> {
        let (_, c) = Self::pair_from_hex(hex)?;
        Ok(c)
    }

    pub fn current_id(&self) -> &str {
        &self.current_id
    }
    pub fn current_arc(&self) -> Arc<Aes256Gcm> {
        Arc::clone(&self.current)
    }
    /// Raw 32-byte KEK for current id — for AeadCipher trait construction.
    pub fn current_raw(&self) -> &[u8; 32] {
        &self.current_raw
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
    /// Raw KEK lookup.
    pub fn get_raw(&self, id: &str) -> Option<&[u8; 32]> {
        if id == self.current_id {
            Some(&self.current_raw)
        } else {
            self.previous_raw.get(id)
        }
    }
    /// Raw KEK with primary fallback.
    pub fn resolve_raw(&self, id: &str) -> Option<&[u8; 32]> {
        self.get_raw(id).or_else(|| {
            if id == "primary" && self.current_id != "primary" {
                Some(&self.current_raw)
            } else {
                None
            }
        })
    }
}

// Backward compat helper
pub fn load_kek() -> Result<KeyEncryptionKey, String> {
    let hex = env::var("APP_KEK").map_err(|_| "APP_KEK must be set".to_string())?;
    let bytes: [u8; 32] = <[u8; 32]>::from_hex(&hex)
        .map_err(|_| "APP_KEK must be valid 32-byte hex".to_string())?;
    Ok(KeyEncryptionKey::new(bytes))
}
