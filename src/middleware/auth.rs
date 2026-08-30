use axum::{
    extract::Request,
    http::{header, StatusCode},
    middleware::Next,
    response::Response,
};
use std::{collections::HashMap, env, sync::LazyLock};

#[derive(Clone, Debug, PartialEq)]
pub enum Role {
    Both,
    EncryptOnly,
    DecryptOnly,
}

impl Role {
    fn allows(&self, path: &str) -> bool {
        match self {
            Role::Both => true,
            Role::EncryptOnly => path == "/encrypt" || path == "/v1/crypto/encrypt" || path == "/v1/crypto/sign" || path == "/v1/crypto/hash",
            Role::DecryptOnly => path == "/decrypt" || path == "/v1/crypto/decrypt" || path == "/v1/crypto/verify",
        }
    }
    fn parse(s: &str) -> Self {
        match s.trim().to_lowercase().as_str() {
            "encrypt" | "enc" | "e" => Role::EncryptOnly,
            "decrypt" | "dec" | "d" => Role::DecryptOnly,
            _ => Role::Both,
        }
    }
}

pub struct ApiKeyStore {
    keys: HashMap<String, Role>,
}

impl ApiKeyStore {
    fn from_env() -> Self {
        let mut keys = HashMap::new();
        if let Ok(val) = env::var("APP_API_KEYS") {
            for part in val.split(',') {
                let part = part.trim();
                if part.is_empty() {
                    continue;
                }
                if let Some((k, r)) = part.split_once(':') {
                    keys.insert(k.trim().to_string(), Role::parse(r));
                } else {
                    keys.insert(part.to_string(), Role::Both);
                }
            }
        }
        if keys.is_empty() {
            if let Ok(k) = env::var("APP_API_KEY") {
                if !k.is_empty() {
                    keys.insert(k, Role::Both);
                }
            }
        }
        Self { keys }
    }
    fn role_for(&self, provided: &str) -> Option<Role> {
        for (k, role) in &self.keys {
            if ct_eq(provided, k) {
                return Some(role.clone());
            }
        }
        None
    }
    fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }
}

static API_KEYS: LazyLock<ApiKeyStore> = LazyLock::new(ApiKeyStore::from_env);

fn ct_eq(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.bytes().zip(b.bytes()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[derive(Clone, Debug)]
#[allow(dead_code)]
pub struct AuthInfo {
    pub role: Role,
}

pub async fn require_api_key(mut req: Request, next: Next) -> Result<Response, StatusCode> {
    if API_KEYS.is_empty() {
        tracing::error!("no API keys configured — all requests rejected");
        return Err(StatusCode::INTERNAL_SERVER_ERROR);
    }
    let provided = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .unwrap_or("");
    let role = API_KEYS.role_for(provided).ok_or(StatusCode::UNAUTHORIZED)?;
    let path = req.uri().path().to_string();
    if !role.allows(&path) {
        tracing::warn!("role {:?} denied for {}", role, path);
        return Err(StatusCode::FORBIDDEN);
    }
    req.extensions_mut().insert(AuthInfo { role });
    Ok(next.run(req).await)
}
