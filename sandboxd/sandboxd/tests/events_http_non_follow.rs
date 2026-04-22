//! Integration tests for `GET /sessions/{id}/events` — non-follow
//! (`follow=false`) path only.  Follow-streaming is Phase 3 of M10-S4
//! and is covered separately once it lands.
//!
//! # Architecture
//!
//! Each test builds a minimal [`sandboxd::events_http::EventsApiState`]
//! around a freshly-created [`SessionStore`] (in a temp dir) and a
//! default [`EventBus`], registers a fixture session with the bus,
//! publishes a curated set of events into the per-session ring, and
//! then drives the [`sandboxd::events_http::events_router`] sub-router
//! through `tower::ServiceExt::oneshot`.  This exercises the real
//! axum 0.8 extractor stack (including the axum-extra `Query`
//! extractor that replaces the built-in one for repeatable query
//! parameters — see R1 in the M10-S4 plan), the real handler, and the
//! real `SessionStore` name-or-id resolver, without ever booting the
//! full daemon or going anywhere near Unix sockets.
//!
//! Each test is self-contained: a fresh `TempDir`, a fresh store, and
//! a fresh bus.  This keeps tests hermetic and parallelizable.

use std::net::Ipv4Addr;
use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode, header::CONTENT_TYPE};
use chrono::{DateTime, Duration as ChronoDuration, TimeZone, Utc};
use http_body_util::BodyExt;
use tempfile::TempDir;
use tower::ServiceExt;

use sandbox_core::{
    DenyLoggerDeny, DenyLoggerEvent, DenyProtocol, DnsEvent, EnvoyConnection, EnvoyEvent, Event,
    EventBus, EventEnvelope, GatewayShutdownReason, HealthComponent, LifecycleEvent,
    MitmproxyEvent, SessionConfig, SessionStore, TrafficEvent,
};
use sandboxd::events_http::{APPLICATION_JSONL, EventsApiState, events_router};

// ---------------------------------------------------------------------------
// Fixture helpers
// ---------------------------------------------------------------------------

/// A fixed timestamp every fixture uses unless overridden.  Using a
/// stable value lets `since=` boundary tests reason about events
/// crossing the boundary deterministically.
fn fixture_ts() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 4, 22, 12, 0, 0).unwrap() + ChronoDuration::milliseconds(500)
}

/// Build a freshly-provisioned pair of `(store, temp_dir)` rooted in a
/// new `TempDir`.  The caller keeps the `TempDir` alive for the
/// lifetime of the test — dropping it removes the SQLite file.
fn fresh_store() -> (Arc<SessionStore>, TempDir) {
    let tmp = TempDir::new().expect("tempdir");
    let (store, _orphans) = SessionStore::new(tmp.path().to_path_buf()).expect("open store");
    (Arc::new(store), tmp)
}

/// Create a session in `store`, register it on `bus`, and return its
/// id.  The session carries an optional name so the name-or-id
/// resolution path can be exercised too.
fn provision_session(
    store: &SessionStore,
    bus: &EventBus,
    name: Option<&str>,
) -> sandbox_core::SessionId {
    let session = store
        .create_session(SessionConfig::default(), name.map(String::from))
        .expect("create session");
    bus.register_session(session.id);
    session.id
}

/// Build an envelope stamped for `session` at `ts`.
fn envelope(session: sandbox_core::SessionId, ts: DateTime<Utc>) -> EventEnvelope {
    EventEnvelope {
        timestamp: ts,
        session: Some(session),
    }
}

/// The canonical 6-event fixture used by most tests: two DNS, two Envoy,
/// one mitmproxy, one deny-logger.  Returns the events in publish order
/// so tests can assert ordering when relevant.
///
/// Breakdown:
/// - 1 × dns `query_allowed`
/// - 1 × dns `query_denied`
/// - 1 × envoy `connection_allowed`
/// - 1 × envoy `connection_denied`
/// - 1 × mitmproxy `request_allowed`
/// - 1 × deny-logger `deny`
fn six_event_fixture(session: sandbox_core::SessionId, ts: DateTime<Utc>) -> Vec<Event> {
    let conn = || EnvoyConnection {
        src_ip: Ipv4Addr::new(10, 0, 0, 42),
        src_port: 54321,
        dst_ip: Ipv4Addr::new(93, 184, 216, 34),
        dst_port: 443,
        matched_chain: "chain_l3_example".into(),
        cluster: "upstream_example_443".into(),
        upstream_host: Some("93.184.216.34:443".into()),
        bytes_sent: 1024,
        bytes_received: 4096,
        response_flags: "-".into(),
        duration_ms: 42,
        connect_authority: Some("example.com:443".into()),
    };
    vec![
        Event::Traffic {
            envelope: envelope(session, ts),
            event: TrafficEvent::Dns(DnsEvent::QueryAllowed {
                query: "api.example.com".into(),
                qtype: "A".into(),
                resolved_ips: vec![Ipv4Addr::new(93, 184, 216, 34)],
            }),
        },
        Event::Traffic {
            envelope: envelope(session, ts),
            event: TrafficEvent::Dns(DnsEvent::QueryDenied {
                query: "blocked.example.com".into(),
                qtype: "AAAA".into(),
                reason: "policy_deny".into(),
            }),
        },
        Event::Traffic {
            envelope: envelope(session, ts),
            event: TrafficEvent::Envoy(EnvoyEvent::ConnectionAllowed(conn())),
        },
        Event::Traffic {
            envelope: envelope(session, ts),
            event: TrafficEvent::Envoy(EnvoyEvent::ConnectionDenied(conn())),
        },
        Event::Traffic {
            envelope: envelope(session, ts),
            event: TrafficEvent::Mitmproxy(MitmproxyEvent::RequestAllowed {
                host: "api.example.com".into(),
                port: 443,
                method: "GET".into(),
                path: "/v1/widgets".into(),
            }),
        },
        Event::Traffic {
            envelope: envelope(session, ts),
            event: TrafficEvent::DenyLogger(DenyLoggerEvent::Deny(DenyLoggerDeny {
                orig_dst_ip: Ipv4Addr::new(203, 0, 113, 1),
                orig_dst_port: 443,
                protocol: DenyProtocol::Tcp,
                src_ip: Ipv4Addr::new(10, 0, 0, 42),
                src_port: 55123,
            })),
        },
    ]
}

/// Publish every event in `events` into `bus`, panicking if any event is
/// dropped — a dropped publish means the session was not registered,
/// which is a fixture bug rather than behaviour under test.
fn publish_all(bus: &EventBus, events: impl IntoIterator<Item = Event>) {
    for e in events {
        assert!(
            bus.publish(e),
            "fixture publish dropped: session must be registered before publishing"
        );
    }
}

/// Build the events sub-router over a fresh `(store, bus)` pair.  The
/// returned router owns both handles via `Arc`, so callers only need to
/// keep the `TempDir` alive for the SQLite file on disk.
fn build_router(store: Arc<SessionStore>, bus: EventBus) -> axum::Router {
    let state = Arc::new(EventsApiState::new(store, bus));
    events_router(state)
}

/// Thin convenience around `ServiceExt::oneshot` that takes a
/// `GET <uri>` string and returns the `(status, content_type, body)`
/// triple.  `content_type` is `None` when the header is absent.
async fn get_triple(router: axum::Router, uri: &str) -> (StatusCode, Option<String>, Vec<u8>) {
    let req = Request::builder()
        .method("GET")
        .uri(uri)
        .body(Body::empty())
        .expect("build request");
    let resp = router.oneshot(req).await.expect("router ran");
    let status = resp.status();
    let content_type = resp
        .headers()
        .get(CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(String::from);
    let body = resp
        .into_body()
        .collect()
        .await
        .expect("collect body")
        .to_bytes()
        .to_vec();
    (status, content_type, body)
}

/// Parse a JSONL body into one `serde_json::Value` per line.  Empty
/// trailing newlines are ignored so the body-delimiter convention
/// (every object is `\n`-terminated) does not produce a spurious empty
/// object at the end.
fn parse_jsonl(body: &[u8]) -> Vec<serde_json::Value> {
    std::str::from_utf8(body)
        .expect("jsonl body is utf-8")
        .lines()
        .filter(|l| !l.is_empty())
        .map(|l| serde_json::from_str::<serde_json::Value>(l).expect("valid json line"))
        .collect()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// Empty filter replays every buffered event.  The 6-event fixture
/// (2 × dns, 2 × envoy, 1 × mitmproxy, 1 × deny-logger) is the
/// reference shape the M10-S4 plan's Phase 2 exit test names verbatim,
/// so the assertion count is load-bearing.
#[tokio::test]
async fn get_events_empty_filter_returns_all_replay() {
    let (store, _tmp) = fresh_store();
    let bus = EventBus::default();
    let sid = provision_session(&store, &bus, None);
    publish_all(&bus, six_event_fixture(sid, fixture_ts()));

    let router = build_router(store, bus);
    let uri = format!("/sessions/{sid}/events");

    let (status, ctype, body) = get_triple(router, &uri).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(ctype.as_deref(), Some(APPLICATION_JSONL));
    let lines = parse_jsonl(&body);
    assert_eq!(lines.len(), 6, "six fixture events → six JSONL lines");
    // Spot-check the layer mix is preserved (no silent drops).
    let layers: Vec<&str> = lines.iter().map(|v| v["layer"].as_str().unwrap()).collect();
    assert_eq!(layers.iter().filter(|l| **l == "dns").count(), 2);
    assert_eq!(layers.iter().filter(|l| **l == "envoy").count(), 2);
    assert_eq!(layers.iter().filter(|l| **l == "mitmproxy").count(), 1);
    assert_eq!(layers.iter().filter(|l| **l == "deny-logger").count(), 1);
}

/// `?decision=deny` keeps every deny from every layer and drops
/// allows + events that have no decision axis.  Deny-logger `deny`
/// survives; `rate_limited` would not — the 6-event fixture has no
/// `rate_limited` so this is verified by count, and the specific
/// surviving mix is verified by event-name inspection.
#[tokio::test]
async fn get_events_filter_by_decision_deny() {
    let (store, _tmp) = fresh_store();
    let bus = EventBus::default();
    let sid = provision_session(&store, &bus, None);
    publish_all(&bus, six_event_fixture(sid, fixture_ts()));

    let router = build_router(store, bus);
    let uri = format!("/sessions/{sid}/events?decision=deny");

    let (status, ctype, body) = get_triple(router, &uri).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(ctype.as_deref(), Some(APPLICATION_JSONL));
    let lines = parse_jsonl(&body);
    // 3 denies in fixture: dns query_denied, envoy connection_denied,
    // deny-logger deny.  Mitmproxy fixture is an allow.
    assert_eq!(lines.len(), 3, "only deny events match");
    let events: Vec<&str> = lines.iter().map(|v| v["event"].as_str().unwrap()).collect();
    assert!(events.contains(&"query_denied"));
    assert!(events.contains(&"connection_denied"));
    assert!(events.contains(&"deny"));
    // No allows leak through.
    assert!(!events.iter().any(|e| e.ends_with("_allowed")));
}

/// R1 regression: `?layer=dns&layer=deny-logger` must parse the two
/// repeated keys into `Vec<String>` with both values.  The axum 0.8
/// built-in `Query` would reject this; the handler uses
/// `axum_extra::extract::Query` (see module docs in events_http.rs)
/// which delegates to `serde_html_form` and handles it correctly.
#[tokio::test]
async fn get_events_filter_by_layer_multi() {
    let (store, _tmp) = fresh_store();
    let bus = EventBus::default();
    let sid = provision_session(&store, &bus, None);
    publish_all(&bus, six_event_fixture(sid, fixture_ts()));

    let router = build_router(store, bus);
    let uri = format!("/sessions/{sid}/events?layer=dns&layer=deny-logger");

    let (status, ctype, body) = get_triple(router, &uri).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "repeated `layer` query keys must parse cleanly via axum-extra"
    );
    assert_eq!(ctype.as_deref(), Some(APPLICATION_JSONL));
    let lines = parse_jsonl(&body);
    // 2 dns + 1 deny-logger; envoy (×2) + mitmproxy drop out.
    assert_eq!(lines.len(), 3, "union of dns + deny-logger layers");
    for line in &lines {
        let layer = line["layer"].as_str().unwrap();
        assert!(
            layer == "dns" || layer == "deny-logger",
            "unexpected layer `{layer}` survived filter"
        );
    }
}

/// `since=` in the far past accepts every buffered event.  This is the
/// happy-path for `since` and catches any regression where the RFC-3339
/// parser treats past timestamps as invalid.
#[tokio::test]
async fn get_events_since_past_matches_all() {
    let (store, _tmp) = fresh_store();
    let bus = EventBus::default();
    let sid = provision_session(&store, &bus, None);
    publish_all(&bus, six_event_fixture(sid, fixture_ts()));

    let router = build_router(store, bus);
    // 2000-01-01 is well before fixture_ts() (2026-04-22).
    let uri = format!("/sessions/{sid}/events?since=2000-01-01T00:00:00Z");

    let (status, _ctype, body) = get_triple(router, &uri).await;
    assert_eq!(status, StatusCode::OK);
    let lines = parse_jsonl(&body);
    assert_eq!(lines.len(), 6, "far-past since matches every event");
}

/// `since=` in the far future filters every event out.  Body is a
/// zero-length JSONL response — 200 with `Content-Type:
/// application/jsonl` and an empty body.
#[tokio::test]
async fn get_events_since_future_matches_none() {
    let (store, _tmp) = fresh_store();
    let bus = EventBus::default();
    let sid = provision_session(&store, &bus, None);
    publish_all(&bus, six_event_fixture(sid, fixture_ts()));

    let router = build_router(store, bus);
    let uri = format!("/sessions/{sid}/events?since=3000-01-01T00:00:00Z");

    let (status, ctype, body) = get_triple(router, &uri).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(ctype.as_deref(), Some(APPLICATION_JSONL));
    assert!(
        body.is_empty(),
        "far-future since must produce empty body, got {} bytes",
        body.len()
    );
    assert!(parse_jsonl(&body).is_empty());
}

/// Unknown session id: the store returns `Ok(None)`, and the handler
/// translates that into `SandboxError::SessionNotFound` → `404`.  The
/// query suffix is irrelevant for this branch but is included to
/// document that validation of the session id happens before query
/// parsing.
#[tokio::test]
async fn get_events_unknown_session_returns_404() {
    let (store, _tmp) = fresh_store();
    let bus = EventBus::default();
    // No session created in the store — any id is unknown.
    let router = build_router(store, bus);

    let (status, _ctype, _body) = get_triple(router, "/sessions/does-not-exist/events").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

/// `decision=reset` is not in the allowed set (`allow` / `deny`).  The
/// spec says this must fail loud as a 400 with the offending value in
/// the error body — no silent match-nothing.
#[tokio::test]
async fn get_events_unknown_decision_returns_400() {
    let (store, _tmp) = fresh_store();
    let bus = EventBus::default();
    let sid = provision_session(&store, &bus, None);

    let router = build_router(store, bus);
    let uri = format!("/sessions/{sid}/events?decision=reset");

    let (status, _ctype, body) = get_triple(router, &uri).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let body_str = std::str::from_utf8(&body).expect("utf-8 body");
    assert!(
        body_str.contains("reset"),
        "error body should name the rejected decision value; got: {body_str}"
    );
}

// The Phase 2 `get_events_follow_true_returns_501` test that pinned the
// interim `501 Not Implemented` behaviour was superseded by Phase 3 —
// the handler now returns a streaming 200 body.  Follow-mode coverage
// lives in `tests/events_http_follow.rs` (replay + live, client-drop,
// broadcast lag marker).

/// The spec names the response `Content-Type` literally as
/// `application/jsonl`.  Other tests already assert this; this test
/// isolates the header-level contract (including that it is present on
/// an empty-body response, which `since=<future>` gives us).
#[tokio::test]
async fn get_events_content_type_application_jsonl() {
    let (store, _tmp) = fresh_store();
    let bus = EventBus::default();
    let sid = provision_session(&store, &bus, None);
    publish_all(&bus, six_event_fixture(sid, fixture_ts()));

    let router = build_router(store, bus);
    let uri = format!("/sessions/{sid}/events");

    let (status, ctype, _body) = get_triple(router, &uri).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(ctype.as_deref(), Some("application/jsonl"));
}

/// The `{id}` path segment resolves name-or-id via
/// `SessionStore::get_session_by_name_or_id`, matching the rest of the
/// `/sessions/{id}/...` family.  Provisioning a named session and
/// hitting the endpoint by name confirms the resolution path is wired
/// up correctly.
#[tokio::test]
async fn get_events_by_session_name_works() {
    let (store, _tmp) = fresh_store();
    let bus = EventBus::default();
    let sid = provision_session(&store, &bus, Some("fixture-name"));

    // Publish a single event so we can tell the name lookup actually
    // reached the same session as the id lookup would have.
    publish_all(
        &bus,
        vec![Event::Lifecycle {
            envelope: envelope(sid, fixture_ts()),
            event: LifecycleEvent::GatewayReady,
        }],
    );

    let router = build_router(store, bus);
    let uri = "/sessions/fixture-name/events";

    let (status, ctype, body) = get_triple(router, uri).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(ctype.as_deref(), Some(APPLICATION_JSONL));
    let lines = parse_jsonl(&body);
    assert_eq!(lines.len(), 1, "name-resolved session replays its ring");
    assert_eq!(lines[0]["layer"], "lifecycle");
    assert_eq!(lines[0]["event"], "gateway_ready");
}

// ---------------------------------------------------------------------------
// Supplementary coverage
// ---------------------------------------------------------------------------
//
// These tests round out the non-follow contract beyond the minimum the
// plan enumerates, to lock down behaviours that are easy to regress.

/// A session that exists in the store but was never registered with
/// the event bus (e.g., created but never started) must not 404 — the
/// session *does* exist, it just has no observable events yet.  The
/// handler returns 200 with an empty JSONL body.
#[tokio::test]
async fn get_events_unregistered_session_returns_empty_200() {
    let (store, _tmp) = fresh_store();
    let bus = EventBus::default();
    // Create a session in the store but do NOT register it with the bus.
    let session = store
        .create_session(SessionConfig::default(), None)
        .expect("create session");

    let router = build_router(store, bus);
    let uri = format!("/sessions/{}/events", session.id);

    let (status, ctype, body) = get_triple(router, &uri).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(ctype.as_deref(), Some(APPLICATION_JSONL));
    assert!(body.is_empty(), "unregistered session has no events");
}

/// `follow=false` is the default, so omitting the parameter and passing
/// it explicitly must behave identically.  Each probe runs against its
/// own fresh state because `ServiceExt::oneshot` consumes the router.
#[tokio::test]
async fn get_events_follow_false_is_default() {
    // Explicit `follow=false`.
    let (store_a, _tmp_a) = fresh_store();
    let bus_a = EventBus::default();
    let sid_a = provision_session(&store_a, &bus_a, None);
    publish_all(&bus_a, six_event_fixture(sid_a, fixture_ts()));
    let router_a = build_router(store_a, bus_a);
    let (status_a, _ctype_a, body_a) =
        get_triple(router_a, &format!("/sessions/{sid_a}/events?follow=false")).await;

    // Omitted `follow` — default in `EventsQueryDto` is `false`.
    let (store_b, _tmp_b) = fresh_store();
    let bus_b = EventBus::default();
    let sid_b = provision_session(&store_b, &bus_b, None);
    publish_all(&bus_b, six_event_fixture(sid_b, fixture_ts()));
    let router_b = build_router(store_b, bus_b);
    let (status_b, _ctype_b, body_b) =
        get_triple(router_b, &format!("/sessions/{sid_b}/events")).await;

    assert_eq!(status_a, StatusCode::OK);
    assert_eq!(status_b, StatusCode::OK);
    assert_eq!(
        parse_jsonl(&body_a).len(),
        parse_jsonl(&body_b).len(),
        "explicit follow=false and default omission must return same event count"
    );
}

/// A lifecycle event with a variant the filter does not select is
/// filtered out.  This pins the cross-variant behaviour for lifecycle
/// events since the six-event fixture has no lifecycle events.
#[tokio::test]
async fn get_events_filter_lifecycle_event_name() {
    let (store, _tmp) = fresh_store();
    let bus = EventBus::default();
    let sid = provision_session(&store, &bus, None);

    publish_all(
        &bus,
        vec![
            Event::Lifecycle {
                envelope: envelope(sid, fixture_ts()),
                event: LifecycleEvent::GatewayReady,
            },
            Event::Lifecycle {
                envelope: envelope(sid, fixture_ts()),
                event: LifecycleEvent::HealthDegraded {
                    component: HealthComponent::DenyLogger,
                    reason: "timeout".into(),
                },
            },
            Event::Lifecycle {
                envelope: envelope(sid, fixture_ts()),
                event: LifecycleEvent::GatewayShutdown {
                    reason: GatewayShutdownReason::SessionStopped,
                    error: None,
                },
            },
        ],
    );

    let router = build_router(store, bus);
    let uri = format!("/sessions/{sid}/events?event=gateway_ready");

    let (status, _ctype, body) = get_triple(router, &uri).await;
    assert_eq!(status, StatusCode::OK);
    let lines = parse_jsonl(&body);
    assert_eq!(lines.len(), 1);
    assert_eq!(lines[0]["event"], "gateway_ready");
}
