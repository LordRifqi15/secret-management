use axum::{extract::Request, http::StatusCode, middleware::Next, response::Response};
use dashmap::DashMap;
use std::sync::{Arc, LazyLock};
use std::time::{Duration, Instant};

fn max_requests() -> usize {
    std::env::var("RATE_LIMIT").ok().and_then(|v| v.parse().ok()).unwrap_or(100)
}
const WINDOW: Duration = Duration::from_secs(60);

#[derive(Clone)]
struct ClientTracker {
    count: usize,
    window_start: Instant,
}

#[derive(Clone)]
pub struct RateLimiter {
    clients: Arc<DashMap<String, ClientTracker>>,
}

impl RateLimiter {
    pub fn new() -> Self {
        let limiter = Self { clients: Arc::new(DashMap::new()) };
        let clients = Arc::clone(&limiter.clients);
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(WINDOW).await;
                let now = Instant::now();
                clients.retain(|_, tracker| now.duration_since(tracker.window_start) < WINDOW * 2);
            }
        });
        limiter
    }

    pub fn check(&self, bucket_key: &str) -> Result<(), StatusCode> {
        let mut entry = self.clients.entry(bucket_key.to_string()).or_insert(ClientTracker {
            count: 0,
            window_start: Instant::now(),
        });
        let now = Instant::now();
        if now.duration_since(entry.window_start) >= WINDOW {
            entry.count = 0;
            entry.window_start = now;
        }
        entry.count += 1;
        if entry.count > max_requests() {
            return Err(StatusCode::TOO_MANY_REQUESTS);
        }
        Ok(())
    }
}

static LIMITER: LazyLock<RateLimiter> = LazyLock::new(RateLimiter::new);

pub async fn rate_limit_middleware(req: Request, next: Next) -> Result<Response, StatusCode> {
    let client_ip = req
        .extensions()
        .get::<std::net::SocketAddr>()
        .map(|addr| addr.ip().to_string())
        .or_else(|| {
            req.headers()
                .get("X-Forwarded-For")
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.split(',').next())
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
        })
        .unwrap_or_else(|| "unknown".to_string());

    let key_part = req
        .headers()
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .unwrap_or("anon");
    let bucket_key = if key_part == "anon" { client_ip } else { format!("{}:{}", client_ip, key_part) };

    LIMITER.check(&bucket_key)?;
    Ok(next.run(req).await)
}
