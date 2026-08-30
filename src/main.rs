mod api;
mod app;
pub mod crypto;
pub mod domain;
mod middleware;
pub mod services;

use std::net::SocketAddr;
use tracing::info;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    info!("Starting Secret Management Microservice...");

    let app = app::create_app().map_err(|e| {
        tracing::error!("Failed to initialize application: {}", e);
        e
    })?;

    let port: u16 = std::env::var("PORT")
        .or_else(|_| std::env::var("APP_PORT"))
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(8080);
    let host = std::env::var("APP_HOST").unwrap_or_else(|_| "0.0.0.0".to_string());
    let addr: SocketAddr = format!("{host}:{port}").parse()?;
    info!("Listening on {}", addr);

    let listener = tokio::net::TcpListener::bind(&addr).await?;
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;
    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };
    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install signal handler")
            .recv()
            .await;
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
    tracing::info!("Shutdown signal received");
}
