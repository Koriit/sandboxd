//! Integration tests for `GET /sessions/{id}/policy/propagation-status`.
//!
//! # Architecture
//!
//! Each test builds a minimal [`sandboxd::policy_http::PolicyApiState`]
//! around a freshly-created [`SessionStore`] (in a temp dir) and a
//! fresh [`PropagationStates`] tracker, optionally drives the tracker
//! through the same `mark_applied` / `mark_propagated` surface the
//! production apply path + DNS propagation loop use, and then drives
//! the [`sandboxd::policy_http::policy_router`] sub-router through
//! `tower::ServiceExt::oneshot`.  This exercises the real axum 0.8
//! extractor stack, the real handler, the real `SessionStore`
//! name-or-id resolver, and the real propagation state machine —
//! without ever booting the full daemon or going anywhere near Unix
//! sockets.
//!
//! Each test is self-contained: a fresh `TempDir`, a fresh store, and
//! a fresh tracker.  This keeps tests hermetic and parallelizable.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use tempfile::TempDir;
use tower::ServiceExt;

use sandbox_core::{OperatorIdentity, PropagationStatusResponse, SessionConfig, SessionStore};
use sandboxd::policy_http::{PolicyApiState, policy_router};
use sandboxd::propagation::PropagationStates;

/// Username every test-side caller is stamped as. The handler now
/// requires an `Extension<OperatorIdentity>`, and the session-store
/// filter rejects rows that don't match this name — so every fixture
/// session and every test request goes through under the same identity.
const TEST_CALLER: &str = "test-operator";

// ---------------------------------------------------------------------------
// Fixture helpers
// ---------------------------------------------------------------------------

/// Build a freshly-provisioned `(store, temp_dir)` pair rooted in a new
/// `TempDir`.  The caller keeps the `TempDir` alive for the lifetime of
/// the test — dropping it removes the SQLite file.
fn fresh_store() -> (Arc<SessionStore>, TempDir) {
    let tmp = TempDir::new().expect("tempdir");
    let (store, _orphans) = SessionStore::new(tmp.path().to_path_buf()).expect("open store");
    (Arc::new(store), tmp)
}

/// Create a session in `store` and return its id.  Optionally assigns
/// a name so the name-or-id resolution path can be exercised too.
fn provision_session(store: &SessionStore, name: Option<&str>) -> sandbox_core::SessionId {
    let session = store
        .create_session(
            SessionConfig::default(),
            name.map(String::from),
            TEST_CALLER,
            0,
            "",
        )
        .expect("create session");
    session.id
}

/// Build the policy sub-router over a fresh `(store, tracker)` pair.
fn build_router(store: Arc<SessionStore>, states: Arc<PropagationStates>) -> axum::Router {
    let state = Arc::new(PolicyApiState::new(store, states));
    // Layer in a synthetic `OperatorIdentity` so handlers that require
    // it through `Extension<OperatorIdentity>` resolve successfully —
    // the production daemon's `operator_identity_layer` inserts it from
    // `SO_PEERCRED`; tests using `oneshot` need to inject it directly.
    policy_router(state).layer(axum::Extension(OperatorIdentity::new(1000, TEST_CALLER)))
}

/// Issue a `GET /sessions/{id}/policy/propagation-status` against
/// `router` and return `(status, parsed_body)`.  `parsed_body` is
/// `None` when the response is a non-200 (the body shape is not
/// guaranteed for errors).
async fn get_status(
    router: axum::Router,
    id: &str,
) -> (StatusCode, Option<PropagationStatusResponse>) {
    let uri = format!("/sessions/{id}/policy/propagation-status");
    let resp = router
        .oneshot(
            Request::get(&uri)
                .body(Body::empty())
                .expect("build request"),
        )
        .await
        .expect("router responded");
    let status = resp.status();
    let bytes = resp
        .into_body()
        .collect()
        .await
        .expect("body collected")
        .to_bytes();
    let parsed = if status == StatusCode::OK {
        Some(serde_json::from_slice::<PropagationStatusResponse>(&bytes).expect("parse body"))
    } else {
        None
    };
    (status, parsed)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn unknown_session_returns_404() {
    let (store, _tmp) = fresh_store();
    let states = Arc::new(PropagationStates::new());
    let router = build_router(store, states);

    let (status, _) = get_status(router, "does-not-exist").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn session_without_apply_reports_never_applied() {
    let (store, _tmp) = fresh_store();
    let sid = provision_session(&store, None);
    let states = Arc::new(PropagationStates::new());
    let router = build_router(store, states);

    let (status, body) = get_status(router, sid.as_str()).await;
    assert_eq!(status, StatusCode::OK);
    let body = body.expect("200 body");
    assert_eq!(body.expected_hash, None);
    assert_eq!(body.propagated_hash, None);
    assert!(!body.propagated);
    assert_eq!(body.seconds_since_apply, 0);
}

#[tokio::test]
async fn applied_but_not_propagated_reports_expected_only() {
    let (store, _tmp) = fresh_store();
    let sid = provision_session(&store, None);
    let states = Arc::new(PropagationStates::new());

    // Simulate the apply-path side of the tracker: `mark_applied`
    // records `expected_hash` but leaves `propagated_hash` empty until
    // the DNS loop reconciles.
    states.mark_applied(sid, "hash-v1".into()).await;

    let router = build_router(store, states);
    let (status, body) = get_status(router, sid.as_str()).await;
    assert_eq!(status, StatusCode::OK);
    let body = body.expect("200 body");
    assert_eq!(body.expected_hash.as_deref(), Some("hash-v1"));
    assert_eq!(body.propagated_hash, None);
    assert!(!body.propagated);
    // The timestamp was just stamped — the elapsed reading is bounded
    // but effectively zero under any reasonable CI schedule.
    assert!(body.seconds_since_apply <= 5);
}

#[tokio::test]
async fn applied_and_propagated_reports_both_hashes_and_flag() {
    let (store, _tmp) = fresh_store();
    let sid = provision_session(&store, Some("my-session"));
    let states = Arc::new(PropagationStates::new());

    states.mark_applied(sid, "hash-v1".into()).await;
    let edge = states.mark_propagated(sid, "hash-v1").await;
    // Sanity: we are exercising the Fresh-edge path, not some already-
    // propagated side channel.
    assert_eq!(edge, sandboxd::propagation::PropagatedEdge::Fresh);

    // Resolve via name to cover the name-or-id resolver too.
    let router = build_router(store, states);
    let (status, body) = get_status(router, "my-session").await;
    assert_eq!(status, StatusCode::OK);
    let body = body.expect("200 body");
    assert_eq!(body.expected_hash.as_deref(), Some("hash-v1"));
    assert_eq!(body.propagated_hash.as_deref(), Some("hash-v1"));
    assert!(body.propagated);
}

#[tokio::test]
async fn second_apply_with_new_hash_flips_propagated_back_to_false() {
    let (store, _tmp) = fresh_store();
    let sid = provision_session(&store, None);
    let states = Arc::new(PropagationStates::new());

    states.mark_applied(sid, "hash-v1".into()).await;
    states.mark_propagated(sid, "hash-v1").await;

    // A second apply with a different hash must clear the propagated
    // bit — the CLI wait loop relies on this to treat the new apply as
    // still-pending until the DNS loop catches up.
    states.mark_applied(sid, "hash-v2".into()).await;

    let router = build_router(store, states);
    let (status, body) = get_status(router, sid.as_str()).await;
    assert_eq!(status, StatusCode::OK);
    let body = body.expect("200 body");
    assert_eq!(body.expected_hash.as_deref(), Some("hash-v2"));
    assert_eq!(body.propagated_hash, None);
    assert!(!body.propagated);
}

#[tokio::test]
async fn resolves_by_name_and_by_id() {
    let (store, _tmp) = fresh_store();
    let sid = provision_session(&store, Some("alpha"));
    let states = Arc::new(PropagationStates::new());
    states.mark_applied(sid, "hash-v1".into()).await;
    states.mark_propagated(sid, "hash-v1").await;

    // Build a router and drive it twice — once by name, once by id —
    // to make sure the handler uses `get_session_by_name_or_id` and
    // not a raw id lookup. The router is cheap to build from shared
    // handles.
    let router = build_router(Arc::clone(&store), Arc::clone(&states));
    let (status_by_name, body_by_name) = get_status(router, "alpha").await;
    assert_eq!(status_by_name, StatusCode::OK);
    let body_by_name = body_by_name.expect("200 body");

    let router = build_router(store, states);
    let (status_by_id, body_by_id) = get_status(router, sid.as_str()).await;
    assert_eq!(status_by_id, StatusCode::OK);
    let body_by_id = body_by_id.expect("200 body");

    assert_eq!(body_by_name.expected_hash, body_by_id.expected_hash);
    assert_eq!(body_by_name.propagated_hash, body_by_id.propagated_hash);
    assert_eq!(body_by_name.propagated, body_by_id.propagated);
}

/// .5 — foreign session ids must surface as HTTP 404,
/// indistinguishable on the wire from a truly nonexistent id. The
/// handler resolves through `get_session_by_name_or_id`, which is
/// scoped to the caller's `owner_username`; alice's session is
/// invisible to bob.
///
/// The router is built with a synthetic `OperatorIdentity` for `bob`,
/// while the row was created under `alice`. The wire response shape
/// (status, body) must match the shape for a never-existed id.
#[tokio::test]
async fn foreign_session_id_returns_404() {
    let (store, _tmp) = fresh_store();
    // Alice owns the row. We seed via the store directly (not via
    // `provision_session`, which uses the shared TEST_CALLER).
    let session = store
        .create_session(
            sandbox_core::SessionConfig::default(),
            Some("alice-secret".into()),
            "alice",
            0,
            "",
        )
        .expect("alice creates session");

    let states = Arc::new(PropagationStates::new());
    let state = Arc::new(sandboxd::policy_http::PolicyApiState::new(store, states));
    // Route bob's requests — bob's identity, not alice's.
    let router = sandboxd::policy_http::policy_router(state)
        .layer(axum::Extension(OperatorIdentity::new(2000, "bob")));

    // GET alice's session id under bob's identity must be 404 with the
    // same body shape as a truly unknown id.
    let (status_by_id, _) = get_status(router, session.id.as_str()).await;
    assert_eq!(
        status_by_id,
        StatusCode::NOT_FOUND,
        "foreign id must be 404 (not 403) so existence stays hidden"
    );

    // GET by name (alice named the session "alice-secret") under bob's
    // identity must also 404 — name resolution is caller-scoped.
    let states2 = Arc::new(PropagationStates::new());
    let (store2, _tmp2) = fresh_store();
    let _ = store2
        .create_session(
            sandbox_core::SessionConfig::default(),
            Some("alice-secret".into()),
            "alice",
            0,
            "",
        )
        .unwrap();
    let state2 = Arc::new(sandboxd::policy_http::PolicyApiState::new(store2, states2));
    let router2 = sandboxd::policy_http::policy_router(state2)
        .layer(axum::Extension(OperatorIdentity::new(2000, "bob")));
    let (status_by_name, _) = get_status(router2, "alice-secret").await;
    assert_eq!(
        status_by_name,
        StatusCode::NOT_FOUND,
        "name lookup must also be caller-scoped; bob must not see alice's named session"
    );
}
