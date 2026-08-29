use axum::{extract::Request, middleware::Next, response::Response};
use axum::http::{HeaderName, HeaderValue};

static HDR_CTO: HeaderName = HeaderName::from_static("x-content-type-options");
static HDR_XFO: HeaderName = HeaderName::from_static("x-frame-options");
static HDR_HSTS: HeaderName = HeaderName::from_static("strict-transport-security");
static HDR_CSP: HeaderName = HeaderName::from_static("content-security-policy");
static HDR_REF: HeaderName = HeaderName::from_static("referrer-policy");
static HDR_CACHE: HeaderName = HeaderName::from_static("cache-control");
static HDR_PERM: HeaderName = HeaderName::from_static("permissions-policy");

pub async fn security_headers(req: Request, next: Next) -> Response {
    let mut res = next.run(req).await;
    let h = res.headers_mut();
    // ponytail: from_static never panics — no unwrap
    h.insert(HDR_CTO.clone(), HeaderValue::from_static("nosniff"));
    h.insert(HDR_XFO.clone(), HeaderValue::from_static("DENY"));
    h.insert(
        HDR_HSTS.clone(),
        HeaderValue::from_static("max-age=63072000; includeSubDomains; preload"),
    );
    h.insert(
        HDR_CSP.clone(),
        HeaderValue::from_static("default-src 'none'; frame-ancestors 'none'"),
    );
    h.insert(HDR_REF.clone(), HeaderValue::from_static("no-referrer"));
    h.insert(
        HDR_CACHE.clone(),
        HeaderValue::from_static("no-store, no-cache, must-revalidate"),
    );
    h.insert(HDR_PERM.clone(), HeaderValue::from_static("camera=(), microphone=(), geolocation=()"));
    h.remove("server");
    res
}
