use axum::{middleware as axum_mw, routing::post, Router};
use std::env;
use std::sync::Arc;
use tower_http::cors::{Any, CorsLayer};
use tower_http::trace::TraceLayer;
use utoipa::OpenApi;
use utoipa_swagger_ui::SwaggerUi;

#[derive(OpenApi)]
#[openapi(
    info(
        title = "Secret Management Microservice",
        description = "Envelope encryption service using AES-256-GCM with AAD-bound DEK, key versioning, and RBAC.",
        version = "0.1.0",
        contact(name = "API Support"),
        license(name = "MIT")
    ),
    paths(
        crate::api::handlers::encrypt_handler,
        crate::api::handlers::decrypt_handler,
        crate::api::v1::encrypt_v1,
        crate::api::v1::decrypt_v1,
        crate::api::v1::sign_v1,
        crate::api::v1::verify_v1,
        crate::api::v1::hash_v1
    ),
    components(schemas(
        crate::api::models::EncryptRequest,
        crate::api::models::EncryptResponse,
        crate::api::models::DecryptRequest,
        crate::api::models::DecryptResponse,
        crate::api::models::ErrorResponse,
        crate::api::dto::EncryptDto,
        crate::api::dto::DecryptDto,
        crate::api::dto::SignDto,
        crate::api::dto::VerifyDto,
        crate::api::dto::HashDto,
        crate::api::dto::EncryptV1Response,
        crate::api::dto::DecryptV1Response,
        crate::api::dto::SignResponse,
        crate::api::dto::VerifyResponse,
        crate::api::dto::HashResponse
    )),
    tags((name = "secret-manager", description = "Secret Management Microservice API")),
    modifiers(&SecurityAddon),
    security(("api_key" = ["Bearer token for API authentication"]))
)]
struct ApiDoc;

struct SecurityAddon;

impl utoipa::Modify for SecurityAddon {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        use utoipa::openapi::security::{HttpAuthScheme, HttpBuilder, SecurityScheme};
        if let Some(components) = openapi.components.as_mut() {
            components.add_security_scheme(
                "api_key",
                SecurityScheme::Http(
                    HttpBuilder::new()
                        .scheme(HttpAuthScheme::Bearer)
                        .bearer_format("API Key")
                        .description(Some("API key via APP_API_KEY or APP_API_KEYS (key:role)"))
                        .build(),
                ),
            );
        }
    }
}

use crate::{
    api::{
        handlers::{decrypt_handler, encrypt_handler},
        v1::{decrypt_v1, encrypt_v1, hash_v1, sign_v1, verify_v1},
    },
    crypto::kek_provider::KekStore,
    middleware::{auth::require_api_key, headers::security_headers, rate_limit::rate_limit_middleware},
    services::{CryptoService, KeyService},
};

pub struct AppState {
    pub kek_store: KekStore,
    pub key_service: Arc<KeyService>,
    pub crypto_service: Arc<CryptoService>,
}

pub type SharedAppState = Arc<AppState>;

pub fn create_app() -> Result<Router, String> {
    let kek_store = KekStore::from_env()?;
    // ponytail: KeyService from_env or fallback to single kek_store as default tenant
    let key_service = match KeyService::from_env() {
        Ok(ks) => Arc::new(ks),
        Err(_) => Arc::new(KeyService::from_single(kek_store.clone())),
    };
    let crypto_service = Arc::new(CryptoService::new(key_service.clone()));
    let state: SharedAppState = Arc::new(AppState { kek_store, key_service, crypto_service });
    // CORS: permissive for now, tighten in production
    let cors = CorsLayer::new().allow_origin(Any).allow_methods(Any).allow_headers(Any);
    // Build protected API routes (auth + rate limit + security headers)
    // old endpoints kept for back compat (deprecated)
    let protected_routes = Router::new()
        .route("/encrypt", post(encrypt_handler))
        .route("/decrypt", post(decrypt_handler))
        .route("/v1/crypto/encrypt", post(encrypt_v1))
        .route("/v1/crypto/decrypt", post(decrypt_v1))
        .route("/v1/crypto/sign", post(sign_v1))
        .route("/v1/crypto/verify", post(verify_v1))
        .route("/v1/crypto/hash", post(hash_v1))
        .layer(axum_mw::from_fn(security_headers))
        .layer(axum_mw::from_fn(rate_limit_middleware))
        .layer(axum_mw::from_fn(require_api_key));
    let enable_swagger = env::var("ENABLE_SWAGGER").map(|v| v == "true" || v == "1").unwrap_or(false);
    let mut app = Router::new().merge(protected_routes).layer(cors).layer(TraceLayer::new_for_http()).with_state(state);
    if enable_swagger {
        app = app.merge(SwaggerUi::new("/swagger-ui").url("/api-docs/openapi.json", ApiDoc::openapi()));
    }
    Ok(app)
}
