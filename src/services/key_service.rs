use std::collections::HashMap;
use std::env;
use std::sync::Arc;

use dashmap::DashMap;
use ed25519_dalek::SigningKey;
use rsa::RsaPrivateKey;
use sha2::{Digest, Sha256};

use crate::crypto::kek_provider::KekStore;

/// Per-tenant KEK + signing registry.
pub struct KeyService {
    stores: HashMap<String, KekStore>,
    ed25519_cache: DashMap<String, Arc<SigningKey>>,
    rsa_cache: DashMap<String, Arc<RsaPrivateKey>>,
}

impl KeyService {
    /// Build from env.
    /// - Primary: `APP_KEK` / `APP_KEK_ID` via `KekStore::from_env()` -> inserted as "default".
    /// - Per-tenant: `APP_TENANT_<id>_KEK` (and optional `APP_TENANT_<id>_KEK_ID`) when present.
    // ponytail: single HashMap, no extra abstraction; per-tenant scan is O(n) over env vars
    pub fn from_env() -> Result<Self, String> {
        let mut stores: HashMap<String, KekStore> = HashMap::new();
        if let Ok(store) = KekStore::from_env() {
            stores.insert("default".to_string(), store);
        }
        for (k, v) in env::vars() {
            if let Some(rest) = k.strip_prefix("APP_TENANT_") {
                if let Some(tenant_raw) = rest.strip_suffix("_KEK") {
                    let tenant_id = tenant_raw.to_lowercase();
                    if stores.contains_key(&tenant_id) {
                        continue;
                    }
                    let id_key = format!("APP_TENANT_{}_KEK_ID", tenant_raw);
                    let kek_id = env::var(&id_key).unwrap_or_else(|_| "primary".to_string());
                    if let Ok(store) = KekStore::from_hex(kek_id, &v) {
                        stores.insert(tenant_id, store);
                    }
                }
            }
        }
        if stores.is_empty() {
            return Err("no KEK configured (set APP_KEK or APP_TENANT_<id>_KEK)".to_string());
        }
        Ok(Self {
            stores,
            ed25519_cache: DashMap::new(),
            rsa_cache: DashMap::new(),
        })
    }

    pub fn from_single(kek_store: KekStore) -> Self {
        let mut stores = HashMap::new();
        stores.insert("default".to_string(), kek_store);
        Self {
            stores,
            ed25519_cache: DashMap::new(),
            rsa_cache: DashMap::new(),
        }
    }

    pub fn get_store(&self, tenant_id: &str) -> Option<&KekStore> {
        self.stores.get(tenant_id)
    }

    pub fn get_store_or_default(&self, tenant_id: &str) -> Option<&KekStore> {
        self.stores.get(tenant_id).or_else(|| self.stores.get("default"))
    }

    /// Deterministic per-tenant Ed25519 key (SHA256 of tenant_id as seed).
    /// Avoids storing long-term keys for demo; replace with Vault in prod.
    pub fn ed25519_key(&self, tenant_id: &str) -> Arc<SigningKey> {
        self.ed25519_cache
            .entry(tenant_id.to_string())
            .or_insert_with(|| {
                let seed = Sha256::digest(tenant_id.as_bytes());
                Arc::new(SigningKey::from_bytes(&seed.into()))
            })
            .clone()
    }

    /// Per-tenant RSA-3072 key, lazily generated (heavy, 0.5s). Cached.
    pub fn rsa_key(&self, tenant_id: &str) -> Arc<RsaPrivateKey> {
        self.rsa_cache
            .entry(tenant_id.to_string())
            .or_insert_with(|| {
                let mut rng = rand::rngs::OsRng;
                Arc::new(RsaPrivateKey::new(&mut rng, 3072).expect("rsa 3072 gen"))
            })
            .clone()
    }
}
