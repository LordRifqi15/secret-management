use axum::{routing::post, Router};
use std::sync::Arc;
use tower_http::trace::TraceLayer;
use utoipa::OpenApi;
use utoipa_swagger_ui::SwaggerUi;

#[derive(OpenApi)]
#[openapi(
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
    )
)]
struct ApiDoc;

use crate::{
    api::handlers::{decrypt_handler, encrypt_handler},
    crypto::kek_provider::{DynKekProvider, EnvKekProvider},
};

pub fn create_app() -> Result<Router, String> {
    // Initialize KEK Provider. In the future this can be conditionally set to a VaultKekProvider.
    let env_provider = EnvKekProvider::new()?;
    let kek_provider: DynKekProvider = Arc::new(env_provider);

    let app = Router::new()
        .merge(SwaggerUi::new("/swagger-ui").url("/api-docs/openapi.json", ApiDoc::openapi()))
        .route("/encrypt", post(encrypt_handler))
        .route("/decrypt", post(decrypt_handler))
        .layer(TraceLayer::new_for_http())
        // Apply the KEK provider state to all routes
        .with_state(kek_provider);

    Ok(app)
}
