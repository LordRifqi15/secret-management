use std::collections::HashMap;
use std::env;

use crate::crypto::kek_provider::KekStore;

/// Per-tenant KEK registry.
/// `stores` maps tenant_id -> KekStore. Minimal setup uses single "default" entry.
pub struct KeyService {
    stores: HashMap<String, KekStore>,
}

impl KeyService {
    /// Build from env.
    /// - Primary: `APP_KEK` / `APP_KEK_ID` via `KekStore::from_env()` -> inserted as "default".
    /// - Per-tenant: `APP_TENANT_<id>_KEK` (and optional `APP_TENANT_<id>_KEK_ID`) when present.
    // ponytail: single HashMap, no extra abstraction; per-tenant scan is O(n) over env vars
    pub fn from_env() -> Result<Self, String> {
        let mut stores: HashMap<String, KekStore> = HashMap::new();

        // minimal: single tenant via KekStore::from_env() -> "default"
        if let Ok(store) = KekStore::from_env() {
            stores.insert("default".to_string(), store);
        }

        // per-tenant expansion: APP_TENANT_<ID>_KEK
        for (k, v) in env::vars() {
            if let Some(rest) = k.strip_prefix("APP_TENANT_") {
                if let Some(tenant_raw) = rest.strip_suffix("_KEK") {
                    let tenant_id = tenant_raw.to_lowercase();
                    if stores.contains_key(&tenant_id) {
                        continue;
                    }
                    // optional per-tenant key id: APP_TENANT_<ID>_KEK_ID
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
        Ok(Self { stores })
    }
    /// Create from single KekStore (for AppState fallback when from_env already consumed).
    pub fn from_single(kek_store: KekStore) -> Self {
        let mut stores = HashMap::new();
        stores.insert("default".to_string(), kek_store);
        Self { stores }
    }
    /// Borrow store for tenant. Returns None if tenant not found.
    pub fn get_store(&self, tenant_id: &str) -> Option<&KekStore> {
        self.stores.get(tenant_id)
    }

    /// Get store with fallback to "default" (convenience, not required by spec).
    pub fn get_store_or_default(&self, tenant_id: &str) -> Option<&KekStore> {
        self.stores.get(tenant_id).or_else(|| self.stores.get("default"))
    }
}
