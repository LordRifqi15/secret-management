mod api;
mod app;
pub mod crypto;

use std::net::SocketAddr;
use tracing::info;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing
    tracing_subscriber::fmt::init();

    info!("Starting Secret Management Microservice...");

    // Build the Axum application
    let app = match app::create_app() {
        Ok(router) => router,
        Err(e) => {
            tracing::error!("Failed to initialize application: {}", e);
            std::process::exit(1);
        }
    };

    // Define the address to serve on
    let addr = SocketAddr::from(([0, 0, 0, 0], 8080));
    info!("Listening on {}", addr);

    // Run the server
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}
