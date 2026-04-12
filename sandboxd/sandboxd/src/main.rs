use std::path::PathBuf;

use axum::{
    Json, Router,
    extract::Path,
    routing::{delete, get, post},
};
use clap::Parser;
use sandbox_core::ApiError;
use tokio::net::UnixListener;
use tracing::info;

/// The sandbox daemon — manages sandbox sessions via a Unix socket HTTP API.
#[derive(Parser, Debug)]
#[command(name = "sandboxd", about = "Sandbox daemon")]
struct Args {
    /// Path to the Unix socket to listen on.
    #[arg(long, default_value_t = default_socket_path())]
    socket: String,
}

fn default_socket_path() -> String {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".into());
    format!("{home}/.sandboxd/sandboxd.sock")
}

fn app() -> Router {
    Router::new()
        .route("/sessions", post(create_session))
        .route("/sessions", get(list_sessions))
        .route("/sessions/{id}", get(get_session))
        .route("/sessions/{id}", delete(remove_session))
        .route("/sessions/{id}/start", post(start_session))
        .route("/sessions/{id}/stop", post(stop_session))
}

async fn create_session() -> (axum::http::StatusCode, Json<ApiError>) {
    (
        axum::http::StatusCode::NOT_IMPLEMENTED,
        Json(ApiError::new("not implemented")),
    )
}

async fn list_sessions() -> (axum::http::StatusCode, Json<ApiError>) {
    (
        axum::http::StatusCode::NOT_IMPLEMENTED,
        Json(ApiError::new("not implemented")),
    )
}

async fn get_session(Path(_id): Path<String>) -> (axum::http::StatusCode, Json<ApiError>) {
    (
        axum::http::StatusCode::NOT_IMPLEMENTED,
        Json(ApiError::new("not implemented")),
    )
}

async fn remove_session(Path(_id): Path<String>) -> (axum::http::StatusCode, Json<ApiError>) {
    (
        axum::http::StatusCode::NOT_IMPLEMENTED,
        Json(ApiError::new("not implemented")),
    )
}

async fn start_session(Path(_id): Path<String>) -> (axum::http::StatusCode, Json<ApiError>) {
    (
        axum::http::StatusCode::NOT_IMPLEMENTED,
        Json(ApiError::new("not implemented")),
    )
}

async fn stop_session(Path(_id): Path<String>) -> (axum::http::StatusCode, Json<ApiError>) {
    (
        axum::http::StatusCode::NOT_IMPLEMENTED,
        Json(ApiError::new("not implemented")),
    )
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let args = Args::parse();
    let socket_path = PathBuf::from(&args.socket);

    // Create the socket directory if it doesn't exist.
    if let Some(parent) = socket_path.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }

    // Remove stale socket file if it exists.
    if socket_path.exists() {
        info!(?socket_path, "removing stale socket file");
        tokio::fs::remove_file(&socket_path).await?;
    }

    let listener = UnixListener::bind(&socket_path)?;
    info!(socket = %socket_path.display(), "sandboxd listening");

    let app = app();

    // Graceful shutdown on SIGTERM / SIGINT.
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    // Clean up the socket file on exit.
    let _ = tokio::fs::remove_file(&socket_path).await;
    info!("sandboxd shut down");

    Ok(())
}

async fn shutdown_signal() {
    use tokio::signal::unix::{SignalKind, signal};

    let mut sigterm =
        signal(SignalKind::terminate()).expect("failed to install SIGTERM handler");
    let mut sigint =
        signal(SignalKind::interrupt()).expect("failed to install SIGINT handler");

    tokio::select! {
        _ = sigterm.recv() => {
            info!("received SIGTERM, shutting down");
        }
        _ = sigint.recv() => {
            info!("received SIGINT, shutting down");
        }
    }
}
