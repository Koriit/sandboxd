//! HTTP endpoint `GET /backends`.
//!
//! The CLI fetches this endpoint once per invocation, caches the result
//! for the invocation's lifetime, and uses it to drive client-side
//! validation (e.g. rejecting `--hardened` against the container backend)
//! and the `sandbox inspect -v` capability matrix render. See spec
//! § "CLI learns capabilities via `GET /backends`" for the full contract.
//!
//! # Wiring
//!
//! Mirrors the `events_http` / `policy_http` sub-router pattern: the
//! production daemon merges [`backends_router`] into its top-level axum
//! router so the endpoint shares the daemon's Unix socket. The sub-state
//! ([`BackendsApiState`]) holds an `Arc` of the same backend dispatch
//! map the main `AppState` owns, so there is no double allocation —
//! merging vs. extending the main router lets this module keep its own
//! typed state without a `FromRef` impl on `AppState`.
//!
//! Integration tests under `tests/integration_backends_endpoint.rs` drive
//! the sub-router directly via `tower::ServiceExt::oneshot`, bypassing
//! the full `AppState` construction (Lima manager, gateway, network
//! manager) the main router requires.

use std::collections::HashMap;
use std::sync::Arc;

use axum::{
    Json, Router,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::get,
};
use sandbox_core::backend::{BackendInfo, BackendKind, SessionRuntime};

/// Minimal shared state for the backends HTTP sub-router.
///
/// Wraps the same `Arc<HashMap<BackendKind, Arc<dyn SessionRuntime>>>`
/// the main `AppState` owns. The handler iterates the map once per
/// request to assemble the response — no further state is required.
#[derive(Clone)]
pub struct BackendsApiState {
    pub runtimes: Arc<HashMap<BackendKind, Arc<dyn SessionRuntime>>>,
}

impl BackendsApiState {
    pub fn new(runtimes: Arc<HashMap<BackendKind, Arc<dyn SessionRuntime>>>) -> Self {
        Self { runtimes }
    }
}

/// Build the sub-router for `GET /backends`.
pub fn backends_router(state: Arc<BackendsApiState>) -> Router {
    Router::new()
        .route("/backends", get(list_backends))
        .with_state(state)
}

/// Handler: `GET /backends`.
///
/// Iterates the daemon's backend dispatch table and returns one
/// [`BackendInfo`] per registered runtime. The list is sorted by
/// [`BackendKind`] so the response is deterministic across daemon
/// restarts and across different `HashMap` insertion orders — both the
/// CLI's snapshot-style consumers and operator-facing `sandbox inspect`
/// renders rely on stable ordering.
pub async fn list_backends(State(state): State<Arc<BackendsApiState>>) -> Response {
    let mut infos: Vec<BackendInfo> = state
        .runtimes
        .values()
        .map(|rt| BackendInfo {
            kind: rt.kind(),
            capabilities: rt.capabilities().clone(),
        })
        .collect();
    infos.sort_by_key(|info| info.kind.as_str());
    (StatusCode::OK, Json(infos)).into_response()
}
