//! HTTP endpoint `GET /sessions/{id}/events`.
//!
//! This module owns both the non-follow replay handler and the
//! follow-streaming handler.
//!
//! # Contract
//!
//! - Path: `/sessions/{id}/events` — `{id}` resolves name-or-id via
//!   [`SessionStore::get_session_by_name_or_id`], matching the rest of
//!   the `/sessions/{id}/…` family.
//! - Query: [`EventsQueryDto`] via [`axum_extra::extract::Query`]. We
//!   use axum-extra's extractor (not the built-in `axum::extract::Query`)
//!   because axum 0.8's built-in `Query` delegates to `serde_urlencoded`,
//!   which rejects repeated keys when the target field is `Vec<_>`.
//!   axum-extra's `Query` swaps in `serde_html_form` which accepts them.
//! - `follow=false` (default): bounded replay of the session's ring
//!   buffer, rendered as concatenated JSONL (one object per line,
//!   `\n`-terminated) with `Content-Type: application/jsonl`.
//! - `follow=true`: chunked `Content-Type: application/jsonl` streaming
//!   response. The handler subscribes atomically via
//!   [`EventBus::subscribe`], drains the replay snapshot first, then
//!   pulls live events from the broadcast receiver until either the
//!   client disconnects (hyper drops the body future, which cancels the
//!   stream `async fn` and frees the receiver) or the session is
//!   unregistered (receiver reports `RecvError::Closed`).  Lag events
//!   surface as a synthetic `lifecycle.ring_buffer_lag` line — see the
//!   streaming branch below for the shape.  Chunked transfer encoding
//!   is axum-default for unknown-length `Body::from_stream` bodies, so
//!   the handler sets only `Content-Type`.
//!
//! # Wiring
//!
//! - The production daemon merges [`events_router`] into its top-level
//!   axum router so the endpoint shares the same Unix socket as every
//!   other `/sessions/*` route.
//! - Integration tests (`tests/events_http_non_follow.rs` and
//!   `tests/events_http_follow.rs`) build a minimal [`EventsApiState`]
//!   of their own and drive the sub-router through
//!   `tower::ServiceExt::oneshot` without constructing the full daemon
//!   `AppState`.
//!
//! Keep this module narrowly scoped to what the HTTP layer needs — the
//! filter types, DTO, and JSONL helper all live in `sandbox-core`.

use std::sync::Arc;

use axum::{
    Extension, Router,
    body::{Body, Bytes},
    extract::{Path, State},
    http::{StatusCode, header::CONTENT_TYPE},
    response::{IntoResponse, Response},
    routing::get,
};
use axum_extra::extract::Query;
use chrono::Utc;
use sandbox_core::{
    EventBus, EventsFilter, EventsQueryDto, OperatorIdentity, SandboxError, SessionStore,
    event_to_jsonl_line,
};
use tokio::sync::broadcast::error::RecvError;

/// `Content-Type` header value for the JSONL response body.
///
/// Spec Part 3 § "HTTP endpoint" names this verbatim (`application/jsonl`).
/// Exposed publicly so tests can assert against the exact literal without
/// importing the constant's value twice.
pub const APPLICATION_JSONL: &str = "application/jsonl";

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
/// - `follow=true`: streams a chunked JSONL body built from the
///   broadcast receiver (see `follow_response`).
/// - `follow=false`: replays the session's ring buffer, applies the
///   filter, renders each surviving event to JSONL, concatenates into
///   a single body, and returns 200 with `Content-Type: application/jsonl`.
///
/// Return type is `impl IntoResponse` via a `match`/early-return
/// pattern — no `?` operator in the handler body, per the project
/// convention in `CLAUDE.md`.
pub async fn get_session_events(
    State(state): State<Arc<EventsApiState>>,
    Extension(operator): Extension<OperatorIdentity>,
    Path(id): Path<String>,
    Query(q): Query<EventsQueryDto>,
) -> Response {
    // Resolve session name-or-id, scoped to the caller's owner_username
    // so a foreign session id returns the same 404 shape as a truly
    // nonexistent id (spec § 2.4).
    let session = match state.store.get_session_by_name_or_id(&id, &operator.name) {
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
        return follow_response(&state.event_bus, &session.id, filter);
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
// `follow=true` streaming path
// ---------------------------------------------------------------------------

/// Build the `follow=true` response.
///
/// - Subscribes atomically via [`EventBus::subscribe`]; `None` means the
///   session exists in the store but has no per-session sink on the
///   bus.  Treated as an empty replay + a never-producing stream — the
///   client receives `Content-Type: application/jsonl` with a 200 and
///   the body stays open until the client disconnects.  This mirrors
///   the non-follow branch's "session exists but is quiet" semantics.
/// - Returns a [`Response`] whose body is [`Body::from_stream`] over
///   an `async_stream::stream!` generator that (a) drains the replay
///   snapshot through the filter, then (b) consumes the broadcast
///   receiver indefinitely.  On `RecvError::Lagged(n)` the generator
///   emits a stream-local synthetic `lifecycle.ring_buffer_lag` line
///   (see [`lag_marker_line`]) and keeps going; on `RecvError::Closed`
///   (session unregistered) it breaks cleanly and the body ends.
/// - Does **not** set `Transfer-Encoding` explicitly — axum's HTTP/1
///   layer defaults to chunked for a `Body::from_stream` with unknown
///   length.
fn follow_response(
    event_bus: &EventBus,
    session_id: &sandbox_core::SessionId,
    filter: EventsFilter,
) -> Response {
    // Snapshot-and-subscribe under a single lock inside the bus.  An
    // unregistered session surfaces as `None` here; we synthesise an
    // empty replay with an already-closed receiver so the generator
    // below terminates after the empty replay drain.  An already-
    // closed receiver is constructed by subscribing to a fresh, never-
    // sent-to broadcast channel whose only `Sender` is dropped
    // immediately — `recv()` returns `RecvError::Closed` on the first
    // call.
    let (replay, mut rx) = match event_bus.subscribe(session_id) {
        Some(sub) => sub,
        None => {
            let (tx, rx) = tokio::sync::broadcast::channel(1);
            drop(tx);
            (Vec::new(), rx)
        }
    };

    // Drop-observing stream: the `async_stream::stream!` future is
    // owned by hyper's body task.  When the client disconnects, hyper
    // drops that task which drops the stream's future; that in turn
    // drops `rx`, which calls `broadcast::Receiver::drop` and
    // unregisters the subscriber on the bus.  No explicit cancel
    // plumbing needed.
    let body_stream = async_stream::stream! {
        // --- Replay phase.  Apply the same filter used in the non-
        // follow branch so the streaming client sees the identical
        // pre-subscribe history the replay client would see.
        for event in replay.into_iter() {
            if !filter.matches(&event) {
                continue;
            }
            match event_to_jsonl_line(&event) {
                Ok(line) => yield Ok::<Bytes, std::io::Error>(Bytes::from(line)),
                Err(e) => tracing::warn!(error = %e, "skipping event with JSONL render failure"),
            }
        }

        // --- Live phase.  `recv` borrows `rx` exclusively so the loop
        // owns the subscription for its entire lifetime.  The borrow
        // is released when the stream future is dropped.
        loop {
            match rx.recv().await {
                Ok(event) => {
                    if !filter.matches(&event) {
                        continue;
                    }
                    match event_to_jsonl_line(&event) {
                        Ok(line) => yield Ok::<Bytes, std::io::Error>(Bytes::from(line)),
                        Err(e) => tracing::warn!(error = %e, "skipping live event with JSONL render failure"),
                    }
                }
                Err(RecvError::Lagged(n)) => {
                    // Stream-local synthetic; not a bus event; not
                    // persisted.  The consumer fell behind and the
                    // broadcast channel dropped `n` messages; surface
                    // the gap so operators can see it in the raw JSONL
                    // stream rather than silently losing fidelity.
                    // The ring buffer still retains whatever the sink
                    // hasn't evicted, but mid-stream we don't
                    // re-snapshot — the next `recv` call continues
                    // from the channel's current head.
                    yield Ok::<Bytes, std::io::Error>(Bytes::from(lag_marker_line(n)));
                }
                Err(RecvError::Closed) => {
                    // Session was unregistered (teardown).  Terminate
                    // the stream cleanly — the body ends, the client
                    // sees EOF.
                    break;
                }
            }
        }
    };

    Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, APPLICATION_JSONL)
        .body(Body::from_stream(body_stream))
        .expect("static header + stream body => builder cannot fail")
}

/// Render the stream-local `lifecycle.ring_buffer_lag` synthetic line.
///
/// This line is **not** a [`sandbox_core::Event`]: it is never
/// published on the bus, never persisted, and does not flow through
/// the domain → DTO mapper.  It exists only to signal, inline, that
/// the streaming consumer fell behind the broadcast channel and
/// `n` live events were skipped.  The shape is:
///
/// ```json
/// {"layer":"lifecycle","event":"ring_buffer_lag","skipped":<n>,"timestamp":"<RFC3339 now UTC>"}
/// ```
///
/// Always `\n`-terminated so downstream line-splitters don't need a
/// special case.
fn lag_marker_line(skipped: u64) -> String {
    // Hand-format with `serde_json::json!` to keep the field order
    // locked down and avoid threading a throwaway struct through the
    // DTO module (which is reserved for real domain events).
    let value = serde_json::json!({
        "layer": "lifecycle",
        "event": "ring_buffer_lag",
        "skipped": skipped,
        "timestamp": Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
    });
    let mut line = value.to_string();
    line.push('\n');
    line
}

// ---------------------------------------------------------------------------
// Local error mapping
// ---------------------------------------------------------------------------

/// Sub-router adapter around [`crate::error::error_response`].
///
/// The shared helper returns `(StatusCode, Json<ApiError>)` because the
/// bulk of the daemon's handlers return `impl IntoResponse` and consume
/// the tuple directly. The events sub-router's handlers return
/// [`Response`] explicitly (several call sites do `return
/// error_response(...)` from different match arms with different
/// success shapes), so this thin adapter converts once at the call
/// site and keeps the status-code / logging mapping in a single
/// canonical location.
///
/// Covered by the `maps_session_not_found_to_404` /
/// `maps_invalid_argument_to_400` /
/// `maps_internal_to_500` tests below.
fn error_response(err: SandboxError) -> Response {
    crate::error::error_response(err).into_response()
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
