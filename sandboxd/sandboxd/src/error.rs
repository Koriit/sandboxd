//! Shared HTTP error mapping for daemon handlers.
//!
//! Exposes one helper — [`error_response`] — that converts a
//! [`SandboxError`] into the `(StatusCode, Json<ApiError>)` pair used
//! across every handler.  Centralizing the mapping keeps
//! `main.rs`-side (the bulk of the `/sessions/*` handlers) and
//! `events_http.rs`-side (the `GET /sessions/{id}/events` handler) in
//! lockstep so a new [`SandboxError`] variant cannot silently drift
//! between the two.
//!
//! # Why a tuple
//!
//! axum implements `IntoResponse` for `(StatusCode, Json<T>)`, so
//! callers that need an `axum::response::Response` (e.g. the
//! events sub-router, which returns `Response` directly from each
//! handler) can simply call `.into_response()` on the result, while
//! callers that return `impl IntoResponse` (the main.rs handlers) can
//! return the tuple verbatim.  The caller owns the final shape; this
//! helper only owns the status-code + body mapping and the structured
//! `error!` log.
//!
//! # Logging
//!
//! Every mapping emits one `error!` event with structured `status` and
//! `error` fields and a static `"handler error"` message.  A distinct
//! per-site tag is not needed because the record already includes the
//! `module_path` / span context via tracing's default layer.

use axum::Json;
use axum::http::StatusCode;
use sandbox_core::{ApiError, SandboxError};
use tracing::error;

/// Convert a [`SandboxError`] into an HTTP response body.
///
/// Returns the tuple `(StatusCode, Json<ApiError>)` — axum's
/// `IntoResponse` impls cover both the "return the tuple from an
/// `impl IntoResponse` handler" and the ".into_response() into a
/// [`axum::response::Response`]" shapes.
///
/// Mapping table:
///
/// | Variant                       | Status                      |
/// | ----------------------------- | --------------------------- |
/// | `SessionNotFound`             | `404 Not Found`             |
/// | `InvalidState`                | `400 Bad Request`           |
/// | `InvalidArgument`             | `400 Bad Request`           |
/// | `RootlessDockerRefused`       | `400 Bad Request`           |
/// | `GuestProtocolIncompatible`   | `409 Conflict`              |
/// | `Conflict`                    | `409 Conflict`              |
/// | `Network` / `Ca` /            | `500 Internal Server Error` |
/// | `Gateway` / `Lima`            |                             |
/// | `Io` / `Database` /           | `500 Internal Server Error` |
/// | `Internal`                    |                             |
/// | `Timeout { .. }`              | `504 Gateway Timeout`       |
///
/// The string-wrapping variants (`Network`, `Ca`, `Gateway`, `Lima`)
/// pass the inner message through verbatim; the other variants use
/// their `Display` impl (which prefixes them with the thiserror
/// `#[error("...")]` string) so the body carries enough context to
/// be actionable on the client side.
pub fn error_response(err: SandboxError) -> (StatusCode, Json<ApiError>) {
    let (status, msg) = match &err {
        SandboxError::SessionNotFound(_) => (StatusCode::NOT_FOUND, err.to_string()),
        SandboxError::InvalidState(_) => (StatusCode::BAD_REQUEST, err.to_string()),
        SandboxError::InvalidArgument(_) => (StatusCode::BAD_REQUEST, err.to_string()),
        SandboxError::RootlessDockerRefused => (StatusCode::BAD_REQUEST, err.to_string()),
        SandboxError::GuestProtocolIncompatible { .. } => (StatusCode::CONFLICT, err.to_string()),
        SandboxError::Conflict(msg) => (StatusCode::CONFLICT, msg.clone()),
        SandboxError::Network(msg) => (StatusCode::INTERNAL_SERVER_ERROR, msg.clone()),
        SandboxError::Ca(msg) => (StatusCode::INTERNAL_SERVER_ERROR, msg.clone()),
        SandboxError::Gateway(msg) => (StatusCode::INTERNAL_SERVER_ERROR, msg.clone()),
        SandboxError::Lima(msg) => (StatusCode::INTERNAL_SERVER_ERROR, msg.clone()),
        SandboxError::Io(_) => (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()),
        SandboxError::Database(_) => (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()),
        SandboxError::Internal(_) => (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()),
        SandboxError::Timeout { .. } => (StatusCode::GATEWAY_TIMEOUT, err.to_string()),
    };
    error!(%status, error = %msg, "handler error");
    (status, Json(ApiError::new(msg)))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `Conflict(msg)` maps to `409 Conflict` and the response body
    /// carries the supplied message verbatim. Pins the contract
    /// consumed by the workspace-lock acquire/release handlers and
    /// the lifecycle 409s.
    #[test]
    fn maps_conflict_to_409() {
        let (status, body) = error_response(SandboxError::Conflict(
            "session has an active push operation".into(),
        ));
        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(body.0.error, "session has an active push operation");
    }
}
