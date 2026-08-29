use aes_gcm::{
    aead::{generic_array::GenericArray, KeyInit},
    Aes256Gcm,
};
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
        description = "Envelope encryption service using AES-256-GCM. Provides /encrypt and /decrypt endpoints with API key authentication, rate limiting, and input validation.",
        version = "0.1.0",
        contact(
            name = "API Support"
        ),
        license(
            name = "MIT"
        )
    ),
    paths(
        crate::api::handlers::encrypt_handler,
        crate::api::handlers::decrypt_handler
    ),
    components(
        schemas(
            crate::api::models::EncryptRequest,
            crate::api::models::EncryptResponse,
            crate::api::models::DecryptRequest,
            crate::api::models::DecryptResponse,
            crate::api::models::ErrorResponse
        )
    ),
    tags(
        (name = "secret-manager", description = "Secret Management Microservice API")
    ),
    modifiers(&SecurityAddon),
    security(
        ("api_key" = ["Bearer token for API authentication"])
    )
)]
struct ApiDoc;

struct SecurityAddon;

impl utoipa::Modify for SecurityAddon {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        use utoipa::openapi::security::{SecurityScheme, HttpBuilder, HttpAuthScheme};
        if let Some(components) = openapi.components.as_mut() {
            components.add_security_scheme(
                "api_key",
                SecurityScheme::Http(
                    HttpBuilder::new()
                        .scheme(HttpAuthScheme::Bearer)
                        .bearer_format("API Key")
                        .description(Some("API key set via APP_API_KEY environment variable"))
                        .build()
                )
            );
        }
    }
}

use crate::{
    api::handlers::{decrypt_handler, encrypt_handler},
    crypto::kek_provider::load_kek,
    middleware::{
        auth::require_api_key,
        headers::security_headers,
        rate_limit::rate_limit_middleware,
    },
};

pub struct AppState {
    pub kek_cipher: Arc<Aes256Gcm>,
}

pub type SharedAppState = Arc<AppState>;

pub fn create_app() -> Result<Router, String> {
    let kek = load_kek()?;
    let kek_cipher = Arc::new(Aes256Gcm::new(GenericArray::from_slice(kek.as_bytes())));

    let state: SharedAppState = Arc::new(AppState { kek_cipher });
    // CORS: permissive for now, tighten in production
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    // Build protected API routes (auth + rate limit + security headers)
    let protected_routes = Router::new()
        .route("/encrypt", post(encrypt_handler))
        .route("/decrypt", post(decrypt_handler))
        .layer(axum_mw::from_fn(security_headers))
        .layer(axum_mw::from_fn(rate_limit_middleware))
        .layer(axum_mw::from_fn(require_api_key));

    let enable_swagger = env::var("ENABLE_SWAGGER").map(|v| v == "true" || v == "1").unwrap_or(false);

    let mut app = Router::new()
        .merge(protected_routes)
        .layer(cors)
        .layer(TraceLayer::new_for_http())
        .with_state(state);

    if enable_swagger {
        app = app.merge(
            SwaggerUi::new("/swagger-ui").url("/api-docs/openapi.json", ApiDoc::openapi()),
        );
    }

    Ok(app)
}
