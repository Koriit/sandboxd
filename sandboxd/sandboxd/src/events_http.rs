//! HTTP endpoint `GET /sessions/{id}/events`.
//!
//! This module owns the non-follow replay handler landed in M10-S4 Phase 2.
//! The follow-streaming path is deferred to Phase 3 and guarded by a
//! `501 Not Implemented` branch here so the route contract is stable.
//!
//! # Contract
//!
//! - Path: `/sessions/{id}/events` — `{id}` resolves name-or-id via
//!   [`SessionStore::get_session_by_name_or_id`], matching the rest of
//!   the `/sessions/{id}/…` family.
//! - Query: [`EventsQueryDto`] via [`axum_extra::extract::Query`]. We
//!   use axum-extra's extractor (not the built-in `axum::extract::Query`)
//!   because axum 0.8's built-in `Query` delegates to `serde_urlencoded`,
//!   which rejects repeated keys when the target field is `Vec<_>`
//!   (R1 entry check for Phase 2 — see the M10-S4 plan). axum-extra's
//!   `Query` swaps in `serde_html_form` which accepts them.
//! - `follow=false` (default): bounded replay of the session's ring
//!   buffer, rendered as concatenated JSONL (one object per line,
//!   `\n`-terminated) with `Content-Type: application/jsonl`.
//! - `follow=true`: returns `501 Not Implemented` in Phase 2.  Phase 3
//!   replaces this branch with a `Body::from_stream` wrapper around the
//!   broadcast receiver returned by [`EventBus::subscribe`].
//!
//! # Wiring
//!
//! - The production daemon merges [`events_router`] into its top-level
//!   axum router so the endpoint shares the same Unix socket as every
//!   other `/sessions/*` route.
//! - Integration tests (`tests/events_http_non_follow.rs`) build a
//!   minimal [`EventsApiState`] of their own and drive the sub-router
//!   through `tower::ServiceExt::oneshot` without constructing the full
//!   daemon `AppState`.
//!
//! Keep this module narrowly scoped to what the HTTP layer needs — the
//! filter types, DTO, and JSONL helper all live in `sandbox-core`.

use std::sync::Arc;

use axum::{
    Json, Router,
    extract::{Path, State},
    http::{StatusCode, header::CONTENT_TYPE},
    response::IntoResponse,
    routing::get,
};
use axum_extra::extract::Query;
use sandbox_core::{
    ApiError, EventBus, EventsFilter, EventsQueryDto, SandboxError, SessionStore,
    event_to_jsonl_line,
};
use tracing::error;

/// `Content-Type` header value for the JSONL response body.
///
/// Spec Part 3 § "HTTP endpoint" names this verbatim (`application/jsonl`).
/// Exposed publicly so tests can assert against the exact literal without
/// importing the constant's value twice.
pub const APPLICATION_JSONL: &str = "application/jsonl";

/// Body returned from the `follow=true` branch in Phase 2.
///
/// Replaced by the streaming implementation in Phase 3 (M10-S4). Kept as
/// a module-scoped constant so the test that asserts this interim
/// behaviour reads as an intent statement rather than a string compare.
pub const FOLLOW_TRUE_NOT_IMPLEMENTED_BODY: &str = "follow=true not implemented yet";

/// Minimal shared state for the events HTTP sub-router.
///
/// Holds only the handles the handler actually touches: the session
/// store (for `get_session_by_name_or_id`) and the event bus (for
/// `subscribe`). Wrapped in [`Arc`] by axum's state plumbing so every
/// clone stays cheap. Integration tests construct this type directly;
/// the production binary builds it alongside its full `AppState` (in
/// `src/main.rs`) from the same handles, so there is no data
/// duplication — the underlying [`SessionStore`] and [`EventBus`] are
/// shared, not cloned-by-value.
#[derive(Clone)]
pub struct EventsApiState {
    /// Persistent session store — shared with the main `AppState`.
    pub store: Arc<SessionStore>,
    /// In-process event bus — shared with the main `AppState`.
    pub event_bus: EventBus,
}

impl EventsApiState {
    /// Convenience constructor for call sites that already have the
    /// two handles in hand.
    pub fn new(store: Arc<SessionStore>, event_bus: EventBus) -> Self {
        Self { store, event_bus }
    }
}

/// Build the sub-router for the events endpoint.
///
/// The production daemon merges this router into the top-level router
/// so the endpoint lives on the same socket as the rest of the HTTP API.
/// Integration tests call this directly and drive the returned
/// `Router<()>` via `tower::ServiceExt::oneshot`.
pub fn events_router(state: Arc<EventsApiState>) -> Router {
    Router::new()
        .route("/sessions/{id}/events", get(get_session_events))
        .with_state(state)
}

/// Handler: `GET /sessions/{id}/events`.
///
/// - Extracts `Path(id)` and `Query(q)` — see module docs for why we
///   use `axum_extra::extract::Query`.
/// - Resolves the session via `get_session_by_name_or_id` (matches the
///   rest of the `/sessions/{id}/…` family).
/// - Builds the domain [`EventsFilter`] via `EventsFilter::from_query`;
///   unknown layer / decision / event values yield 400.
/// - `follow=true`: returns 501 (Phase 3 implements streaming).
/// - `follow=false`: replays the session's ring buffer, applies the
///   filter, renders each surviving event to JSONL, concatenates into
///   a single body, and returns 200 with `Content-Type: application/jsonl`.
///
/// Return type is `impl IntoResponse` via a `match`/early-return
/// pattern — no `?` operator in the handler body, per the project
/// convention in `CLAUDE.md`.
pub async fn get_session_events(
    State(state): State<Arc<EventsApiState>>,
    Path(id): Path<String>,
    Query(q): Query<EventsQueryDto>,
) -> axum::response::Response {
    // Resolve session name-or-id.
    let session = match state.store.get_session_by_name_or_id(&id) {
        Ok(Some(s)) => s,
        Ok(None) => return error_response(SandboxError::SessionNotFound(id)),
        Err(e) => return error_response(e),
    };

    // Translate the wire DTO into the domain predicate. Unknown values
    // fail loud as 400 InvalidArgument, matching the spec contract.
    let filter = match EventsFilter::from_query(&q) {
        Ok(f) => f,
        Err(e) => return error_response(e),
    };

    if q.follow {
        // TODO(M10-S4 Phase 3): replace with a streaming `Body::from_stream`
        // wrapping the broadcast receiver from `EventBus::subscribe`. See
        // `.tasks/handoffs/20260422-205445-Plan-m10-s4-implementation-plan.md`
        // § "Phase 3 — HTTP endpoint streaming path".
        return (
            StatusCode::NOT_IMPLEMENTED,
            FOLLOW_TRUE_NOT_IMPLEMENTED_BODY,
        )
            .into_response();
    }

    // Atomically snapshot the session's ring and drop the live receiver
    // immediately: non-follow is replay-only.  `subscribe` returns
    // `None` if the session is not registered with the event bus (e.g.
    // a created-but-never-started session).  We treat that as an empty
    // replay rather than 404 — the session exists, it just has no
    // observable events yet.
    let snapshot: Vec<_> = match state.event_bus.subscribe(&session.id) {
        Some((replay, _rx)) => replay,
        None => Vec::new(),
    };

    // Apply the filter + render each surviving event as JSONL.  A
    // per-event serialization error is logged at warn and skipped so a
    // single malformed event does not poison an otherwise-valid replay;
    // in practice this branch is unreachable because every DTO variant
    // serializes deterministic primitives.
    let mut body = String::new();
    for event in snapshot.iter() {
        if !filter.matches(event) {
            continue;
        }
        match event_to_jsonl_line(event) {
            Ok(line) => body.push_str(&line),
            Err(e) => {
                tracing::warn!(error = %e, "skipping event with JSONL render failure");
            }
        }
    }

    (StatusCode::OK, [(CONTENT_TYPE, APPLICATION_JSONL)], body).into_response()
}

// ---------------------------------------------------------------------------
// Local error mapping
// ---------------------------------------------------------------------------

/// Local copy of the daemon-wide `error_response` helper.
///
/// Duplicated here because `main.rs`'s `error_response` is a binary-only
/// item and tests need the same status-code mapping when driving the
/// sub-router directly. The two implementations must stay in lockstep;
/// see `main.rs::error_response` for the canonical mapping table.
///
/// Covered by the `maps_session_not_found_to_404` /
/// `maps_invalid_argument_to_400` /
/// `maps_internal_to_500` tests below.
fn error_response(err: SandboxError) -> axum::response::Response {
    let (status, msg) = match &err {
        SandboxError::SessionNotFound(_) => (StatusCode::NOT_FOUND, err.to_string()),
        SandboxError::InvalidState(_) => (StatusCode::BAD_REQUEST, err.to_string()),
        SandboxError::InvalidArgument(_) => (StatusCode::BAD_REQUEST, err.to_string()),
        SandboxError::Network(msg) => (StatusCode::INTERNAL_SERVER_ERROR, msg.clone()),
        SandboxError::Ca(msg) => (StatusCode::INTERNAL_SERVER_ERROR, msg.clone()),
        SandboxError::Gateway(msg) => (StatusCode::INTERNAL_SERVER_ERROR, msg.clone()),
        SandboxError::Lima(msg) => (StatusCode::INTERNAL_SERVER_ERROR, msg.clone()),
        SandboxError::Io(_) => (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()),
        SandboxError::Database(_) => (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()),
        SandboxError::Internal(_) => (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()),
        SandboxError::Timeout { .. } => (StatusCode::GATEWAY_TIMEOUT, err.to_string()),
    };
    error!(%status, error = %msg, "events handler error");
    (status, Json(ApiError::new(msg))).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::StatusCode;

    #[test]
    fn maps_session_not_found_to_404() {
        let resp = error_response(SandboxError::SessionNotFound("x".into()));
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[test]
    fn maps_invalid_argument_to_400() {
        let resp = error_response(SandboxError::InvalidArgument("bad".into()));
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn maps_internal_to_500() {
        let resp = error_response(SandboxError::Internal("boom".into()));
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }
}
