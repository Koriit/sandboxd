//! HTTP endpoint `GET /sessions/{id}/policy/propagation-status`.
//!
//! The CLI's `sandbox policy status [--wait]` subcommand and the E2E
//! suite both need a deterministic answer to one question: *has the
//! policy I just applied reached steady state across every enforcement
//! layer?* This module owns the read-only status endpoint that answers
//! it, leaving the apply and clear paths — which mutate the propagation
//! tracker — where they already live (`sandboxd::main`).
//!
//! # Wiring
//!
//! - The production daemon merges [`policy_router`] into its top-level
//!   axum router so the endpoint shares the same Unix socket as every
//!   other `/sessions/*` route.
//! - The sub-state owned by this router ([`PolicyApiState`]) is a thin
//!   handle over shared [`sandbox_core::SessionStore`] +
//!   [`crate::propagation::PropagationStates`] references, so the daemon
//!   does not pay a double-allocation cost — merging vs. extending the
//!   main router lets this module keep its own typed state without
//!   forcing a `FromRef` impl on the main `AppState`.
//! - Integration tests under `tests/policy_http.rs` drive this
//!   sub-router directly via `tower::ServiceExt::oneshot`, bypassing
//!   the full `AppState` construction (Lima, gateway, CA manager, etc.)
//!   that the main router requires.
//!
//! # State machine
//!
//! See [`crate::propagation`] for the full state machine behind the
//! two hash fields (`expected_hash` and `propagated_hash`) and the
//! `propagated` convenience boolean. The handler here performs a
//! simple read-modify-free snapshot against the tracker.

use std::sync::Arc;

use axum::{
    Json, Router,
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::get,
};
use sandbox_core::{PropagationStatusResponse, SandboxError, SessionStore};

use crate::error::error_response as map_error;
use crate::propagation::PropagationStates;

/// Minimal shared state for the policy HTTP sub-router.
///
/// Holds only the handles the handler actually touches: the session
/// store (for `get_session_by_name_or_id`) and the propagation tracker
/// (for the snapshot read). Wrapped in [`Arc`] by axum's state
/// plumbing so every clone stays cheap. Integration tests construct
/// this type directly; the production binary builds it alongside its
/// full `AppState` (in `src/main.rs`) from the same handles, so there
/// is no data duplication — the underlying [`SessionStore`] and
/// [`PropagationStates`] are shared, not cloned-by-value.
#[derive(Clone)]
pub struct PolicyApiState {
    /// Persistent session store — shared with the main `AppState`.
    pub store: Arc<SessionStore>,
    /// Per-session propagation tracker — shared with the main
    /// `AppState` (same `Arc` the apply path and DNS loop mutate).
    pub propagation_states: Arc<PropagationStates>,
}

impl PolicyApiState {
    /// Convenience constructor for call sites that already have the
    /// two handles in hand.
    pub fn new(store: Arc<SessionStore>, propagation_states: Arc<PropagationStates>) -> Self {
        Self {
            store,
            propagation_states,
        }
    }
}

/// Build the sub-router for the policy status endpoint.
///
/// The production daemon merges this router into the top-level router
/// so the endpoint lives on the same socket as the rest of the HTTP API.
/// Integration tests call this directly and drive the returned
/// `Router<()>` via `tower::ServiceExt::oneshot`.
pub fn policy_router(state: Arc<PolicyApiState>) -> Router {
    Router::new()
        .route(
            "/sessions/{id}/policy/propagation-status",
            get(propagation_status),
        )
        .with_state(state)
}

/// Handler: `GET /sessions/{id}/policy/propagation-status`.
///
/// - Resolves the session via `get_session_by_name_or_id` (matches the
///   rest of the `/sessions/{id}/…` family).
/// - Snapshots [`PropagationStates`] for the session.
/// - Returns 200 with a [`PropagationStatusResponse`]; the "never
///   applied" case (no entry in the tracker) maps to all-`None` hashes
///   with `propagated: false` and `seconds_since_apply: 0`, which the
///   CLI wait loop treats as "keep polling, an apply may be mid-flight".
/// - Returns 404 when the session does not exist.
pub async fn propagation_status(
    State(state): State<Arc<PolicyApiState>>,
    Path(id): Path<String>,
) -> Response {
    let session = match state.store.get_session_by_name_or_id(&id) {
        Ok(Some(s)) => s,
        Ok(None) => return map_error(SandboxError::SessionNotFound(id)).into_response(),
        Err(e) => return map_error(e).into_response(),
    };

    let snapshot = state.propagation_states.get(&session.id).await;
    let body = match snapshot {
        Some(s) => PropagationStatusResponse {
            propagated: s.propagated(),
            seconds_since_apply: s.applied_at.elapsed().as_secs(),
            expected_hash: s.applied_hash,
            propagated_hash: s.propagated_hash,
        },
        None => PropagationStatusResponse {
            expected_hash: None,
            propagated_hash: None,
            propagated: false,
            seconds_since_apply: 0,
        },
    };

    (StatusCode::OK, Json(body)).into_response()
}
