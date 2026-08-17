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
/// | `SessionQuotaExhausted`       | `429 Too Many Requests`     |
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
        // 429 rather than 409: the operator's share is full *now*, and
        // stopping a session clears it. The 409 above is the shape a
        // request gets when no share exists to fill, which retrying can
        // never resolve. Rendered from `Display` — this variant carries
        // fields, not a pre-formatted string.
        SandboxError::SessionQuotaExhausted { .. } => {
            (StatusCode::TOO_MANY_REQUESTS, err.to_string())
        }
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

    /// The two vmnet failures must be distinguishable by status code
    /// alone. A client told to retry a configuration conflict retries
    /// forever; a client told an administrator must act on a full share
    /// gives up on something that clears by itself.
    #[test]
    fn a_full_share_is_429_and_an_absent_share_is_409() {
        let (exhausted, _) = error_response(SandboxError::SessionQuotaExhausted {
            operator_uid: 501,
            in_use: 4,
            quota: 4,
            host_slots: 8,
        });
        let (no_range, _) =
            error_response(SandboxError::Conflict("no vmnet slot range".to_string()));

        assert_eq!(exhausted, StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(no_range, StatusCode::CONFLICT);
        assert_ne!(exhausted, no_range);
    }

    /// The 429 body is rendered from the variant's fields, and it tells the
    /// two exhaustion stories apart: an operator holding a share of the
    /// pool must not be sent to a host-level knob that cannot help them.
    #[test]
    fn the_429_body_distinguishes_a_full_share_from_a_full_host() {
        let (_, share) = error_response(SandboxError::SessionQuotaExhausted {
            operator_uid: 501,
            in_use: 4,
            quota: 4,
            host_slots: 8,
        });
        let share = share.0.error;
        assert!(share.contains("501"), "the operator must be named: {share}");
        assert!(
            share.contains("share of 4"),
            "the share must be stated: {share}"
        );
        assert!(
            share.contains("no effect"),
            "raising max_macos_sessions must be ruled out explicitly: {share}"
        );

        let (_, host) = error_response(SandboxError::SessionQuotaExhausted {
            operator_uid: 501,
            in_use: 8,
            quota: 8,
            host_slots: 8,
        });
        let host = host.0.error;
        assert!(
            host.contains("install.sh"),
            "a full host must point at the privileged pool regeneration: {host}"
        );
        assert_ne!(share, host);
    }
}
