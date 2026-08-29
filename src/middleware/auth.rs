use axum::{
    extract::Request,
    http::{header, StatusCode},
    middleware::Next,
    response::Response,
};
use std::env;
use std::sync::LazyLock;

/// API key loaded once at startup from `APP_API_KEY` env var.
/// Empty/missing = middleware rejects all requests (fail-closed).
static API_KEY: LazyLock<Option<String>> = LazyLock::new(|| env::var("APP_API_KEY").ok());

fn ct_eq(a: &str, b: &str) -> bool {
    // ponytail: manual constant-time compare, subtle crate if throughput matters
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.bytes().zip(b.bytes()) {
        diff |= x ^ y;
    }
    diff == 0
}

pub async fn require_api_key(req: Request, next: Next) -> Result<Response, StatusCode> {
    let required = match API_KEY.as_deref() {
        Some(k) if !k.is_empty() => k,
        _ => {
            tracing::error!("APP_API_KEY not set — all requests rejected");
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }
    };

    let provided = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "));

    match provided {
        Some(key) if ct_eq(key, required) => Ok(next.run(req).await),
        _ => Err(StatusCode::UNAUTHORIZED),
    }
}
