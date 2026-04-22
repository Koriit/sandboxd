//! Integration tests for `GET /sessions/{id}/events` — follow
//! (`follow=true`) streaming path, landed in M10-S4 Phase 3.
//!
//! # Architecture
//!
//! The tests mirror the non-follow test harness (`EventsApiState`
//! built directly, `events_router()` driven via
//! `tower::ServiceExt::oneshot`) but consume the response body as a
//! frame stream rather than collecting it whole:
//!
//! - The handler returns a `Body` produced by
//!   [`axum::body::Body::from_stream`] around an `async_stream::stream!`
//!   generator that emits replay lines first, then live lines from the
//!   broadcast receiver returned by `EventBus::subscribe`.  The body is
//!   unbounded — consumers read until EOF (session unregistered) or
//!   until they drop the body, at which point the generator's future is
//!   dropped which drops the broadcast receiver and unregisters the
//!   subscriber from the bus.
//! - We drive the body through `http_body_util::BodyExt::frame` to pull
//!   one frame at a time and buffer partial lines across frame
//!   boundaries.  In practice `async_stream::stream!` + `Bytes::from`
//!   yields one full line per frame, but the line-splitter buffers
//!   anyway so the test is robust against axum changing its chunking.
//! - Every wait is wrapped in `tokio::time::timeout` so a buggy
//!   implementation that hangs fails loud rather than stalling CI.
//!
//! # Test inventory
//!
//! - `follow_streams_replay_then_live` — replay + live merge,
//!   5 lines in order within 5s.
//! - `follow_client_drop_unregisters_cleanly` — dropping the body
//!   while the stream still has pending work must not panic or leak
//!   a task; a subsequent publish to the same session must still
//!   succeed within 2s.
//! - `follow_lag_emits_ring_buffer_lag_line` — overflowing the
//!   broadcast channel capacity produces at least one synthetic
//!   `{"layer":"lifecycle","event":"ring_buffer_lag","skipped":<n>}`
//!   JSONL line with `n >= 1`.

use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::http::{Request, StatusCode, header::CONTENT_TYPE};
use chrono::Utc;
use http_body_util::BodyExt;
use tempfile::TempDir;
use tower::ServiceExt;

use sandbox_core::{
    DnsEvent, Event, EventBus, EventBusConfig, EventEnvelope, SessionConfig, SessionStore,
    TrafficEvent,
};
use sandboxd::events_http::{APPLICATION_JSONL, EventsApiState, events_router};

// ---------------------------------------------------------------------------
// Fixture helpers
// ---------------------------------------------------------------------------

/// Build a freshly-provisioned `(store, temp_dir)` pair.  Caller keeps
/// the `TempDir` alive for the test's duration.
fn fresh_store() -> (Arc<SessionStore>, TempDir) {
    let tmp = TempDir::new().expect("tempdir");
    let (store, _orphans) = SessionStore::new(tmp.path().to_path_buf()).expect("open store");
    (Arc::new(store), tmp)
}

/// Create a session in `store`, register it with `bus`, return its id.
fn provision_session(store: &SessionStore, bus: &EventBus) -> sandbox_core::SessionId {
    let session = store
        .create_session(SessionConfig::default(), None)
        .expect("create session");
    bus.register_session(session.id);
    session.id
}

/// Build an envelope stamped for `session` at `now()`.
fn envelope(session: sandbox_core::SessionId) -> EventEnvelope {
    EventEnvelope {
        timestamp: Utc::now(),
        session: Some(session),
    }
}

/// Mint a dns `query_allowed` event attributed to `session` with a
/// distinct query name so tests can assert ordering by inspecting the
/// `query` field.
fn dns_allowed(session: sandbox_core::SessionId, query: &str) -> Event {
    Event::Traffic {
        envelope: envelope(session),
        event: TrafficEvent::Dns(DnsEvent::QueryAllowed {
            query: query.into(),
            qtype: "A".into(),
            resolved_ips: vec![Ipv4Addr::new(10, 0, 0, 1)],
        }),
    }
}

/// Build the events sub-router over an owned `(store, bus)` pair.  The
/// router owns both handles via `Arc`, so the caller only needs to
/// keep the `TempDir` alive for the SQLite file on disk.
fn build_router(store: Arc<SessionStore>, bus: EventBus) -> axum::Router {
    let state = Arc::new(EventsApiState::new(store, bus));
    events_router(state)
}

/// Issue `GET <uri>` against `router` without collecting the body.
///
/// Returns `(status, content_type, body)` so the test can incrementally
/// drive `body` through `BodyExt::frame`.  `ServiceExt::oneshot`
/// consumes the router; tests that want multiple requests build their
/// own second router.
async fn open_stream(router: axum::Router, uri: &str) -> (StatusCode, Option<String>, Body) {
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
    let body = resp.into_body();
    (status, content_type, body)
}

/// Read `count` complete JSONL lines from `body`.  Partial lines across
/// frame boundaries are buffered until a `\n` terminator appears.  The
/// whole read is wrapped in `tokio::time::timeout(max_wait)` so a stuck
/// stream fails loudly.
///
/// Returns the collected lines **without** their trailing `\n` and the
/// (still-open) body handle so the caller can drop it explicitly.
async fn read_n_lines(
    body: &mut Body,
    count: usize,
    max_wait: Duration,
) -> Result<Vec<String>, String> {
    let fut = async {
        let mut lines: Vec<String> = Vec::with_capacity(count);
        let mut buffer: Vec<u8> = Vec::new();
        while lines.len() < count {
            let frame = match body.frame().await {
                Some(Ok(f)) => f,
                Some(Err(e)) => return Err(format!("body frame error: {e}")),
                None => return Err(format!("body ended with {} of {count} lines", lines.len())),
            };
            let Ok(data) = frame.into_data() else {
                // Non-data frame (trailers etc.) — ignore and keep reading.
                continue;
            };
            buffer.extend_from_slice(&data);
            while let Some(nl) = buffer.iter().position(|b| *b == b'\n') {
                let line_bytes = buffer.drain(..=nl).collect::<Vec<u8>>();
                let mut line =
                    String::from_utf8(line_bytes).map_err(|e| format!("line not utf-8: {e}"))?;
                // Strip trailing \n (there is exactly one by
                // construction because we drain up-to-and-including
                // the newline).
                assert!(line.ends_with('\n'));
                line.pop();
                lines.push(line);
                if lines.len() == count {
                    break;
                }
            }
        }
        Ok(lines)
    };
    match tokio::time::timeout(max_wait, fut).await {
        Ok(res) => res,
        Err(_) => Err(format!(
            "timed out after {:?} waiting for {count} lines",
            max_wait
        )),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// Core contract: replay lines appear first (3 events published before
/// subscribe), then live lines (2 events published after subscribe
/// returns).  All 5 lines arrive within 5s and preserve publish order.
#[tokio::test]
async fn follow_streams_replay_then_live() {
    let (store, _tmp) = fresh_store();
    let bus = EventBus::default();
    let sid = provision_session(&store, &bus);

    // --- Replay: publish 3 before opening the stream.
    for i in 0..3 {
        assert!(
            bus.publish(dns_allowed(sid, &format!("replay-{i}.example.com"))),
            "fixture publish dropped: session must be registered"
        );
    }

    let router = build_router(store, bus.clone());
    let uri = format!("/sessions/{sid}/events?follow=true");

    let (status, ctype, mut body) = open_stream(router, &uri).await;
    assert_eq!(status, StatusCode::OK, "follow=true must return 200");
    assert_eq!(
        ctype.as_deref(),
        Some(APPLICATION_JSONL),
        "follow body must be application/jsonl"
    );

    // --- Live: publish 2 more after opening the stream.  We spawn
    // this on a timer so the reader has a chance to start draining
    // replay first — either order is correct (replay lines always
    // precede live lines by construction of the handler), but a small
    // delay makes the scenario more representative of real usage.
    let bus_for_live = bus.clone();
    let live_task = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(50)).await;
        for i in 0..2 {
            assert!(
                bus_for_live.publish(dns_allowed(sid, &format!("live-{i}.example.com"))),
                "live publish dropped: session must still be registered"
            );
        }
    });

    let lines = read_n_lines(&mut body, 5, Duration::from_secs(5))
        .await
        .expect("collect 5 lines");
    live_task.await.expect("live publish task joined");

    assert_eq!(lines.len(), 5, "must see 3 replay + 2 live lines");

    // Parse and assert the queries in order.
    let queries: Vec<String> = lines
        .iter()
        .map(|l| {
            let v: serde_json::Value = serde_json::from_str(l).expect("valid JSON line");
            v["query"].as_str().unwrap().to_string()
        })
        .collect();
    assert_eq!(
        queries,
        vec![
            "replay-0.example.com".to_string(),
            "replay-1.example.com".to_string(),
            "replay-2.example.com".to_string(),
            "live-0.example.com".to_string(),
            "live-1.example.com".to_string(),
        ],
        "replay lines must precede live lines, in publish order"
    );

    // Drop the body: the generator's future is dropped which drops
    // `rx`, which unregisters this subscriber from the broadcast
    // channel.  No explicit assertion here beyond "no panic"; the
    // client-drop test below exercises this in isolation.
    drop(body);
}

/// Client-drop contract: dropping the response body mid-stream must
/// not panic, must not leak a task, and must free the broadcast
/// subscription so subsequent publishes on the same session succeed.
///
/// We can't directly observe "no leaked task" from outside, but the
/// sanity-check publish below would block forever if the bus held a
/// poisoned lock or the receiver drop path panicked — so the 2-second
/// timeout around the publish is the load-bearing assertion.
#[tokio::test]
async fn follow_client_drop_unregisters_cleanly() {
    let (store, _tmp) = fresh_store();
    let bus = EventBus::default();
    let sid = provision_session(&store, &bus);

    // Publish 1 event so the replay has something to drain.
    assert!(bus.publish(dns_allowed(sid, "first.example.com")));

    let router = build_router(store, bus.clone());
    let uri = format!("/sessions/{sid}/events?follow=true");

    let (status, _ctype, mut body) = open_stream(router, &uri).await;
    assert_eq!(status, StatusCode::OK);

    // Read exactly 1 line.
    let lines = read_n_lines(&mut body, 1, Duration::from_secs(2))
        .await
        .expect("collect 1 line");
    assert_eq!(lines.len(), 1);

    // Drop the body mid-stream.  The `async_stream::stream!` generator
    // is owned by the hyper body task; dropping the body drops that
    // task, which drops the generator future, which drops the
    // broadcast receiver — unregistering this subscriber from the
    // per-session channel.
    drop(body);

    // Sanity-check: publish another event and confirm the bus is
    // still healthy.  A poisoned lock or a panicking drop path would
    // hang this call; the timeout converts that into a loud failure.
    let publish_ok = tokio::time::timeout(
        Duration::from_secs(2),
        tokio::task::spawn_blocking(move || {
            bus.publish(dns_allowed(sid, "after-drop.example.com"))
        }),
    )
    .await
    .expect("publish did not time out")
    .expect("publish task joined");
    assert!(publish_ok, "publish after client drop must succeed");
}

/// Broadcast-lag contract: when the consumer falls behind the
/// broadcast channel (capacity overflow), the stream emits one or more
/// synthetic `{"layer":"lifecycle","event":"ring_buffer_lag",...}`
/// lines with a numeric `skipped` field >= 1, then continues.  We
/// provoke lag by constructing a small-capacity bus and publishing
/// faster than the stream drains.
///
/// The default `EventBusConfig` sets a broadcast capacity of
/// `DEFAULT_RING_BUFFER_SIZE` (10 000), which is unreasonable to
/// overflow in a unit test.  We shrink it to 8 so a burst of 50
/// publishes reliably lags the subscriber.  Only `broadcast_capacity`
/// is changed; `ring_buffer_size` defaults to 10 000 so the replay
/// snapshot remains large.
#[tokio::test]
async fn follow_lag_emits_ring_buffer_lag_line() {
    let (store, _tmp) = fresh_store();
    let bus = EventBus::new(EventBusConfig {
        broadcast_capacity: 8,
        ..EventBusConfig::default()
    });
    let sid = provision_session(&store, &bus);

    let router = build_router(store, bus.clone());
    let uri = format!("/sessions/{sid}/events?follow=true");

    // Open the stream *before* publishing anything so the broadcast
    // subscription is live at t=0 and every subsequent publish
    // contributes to the in-flight buffer.
    let (status, _ctype, mut body) = open_stream(router, &uri).await;
    assert_eq!(status, StatusCode::OK);

    // Publish 50 events in a tight burst.  The subscriber has not
    // called `recv` yet — we're still inside this test body — so
    // every publish after the first 8 forces `broadcast::Receiver`
    // to drop the oldest and surface `RecvError::Lagged` on the
    // consumer's next `recv` call.
    let burst = 50usize;
    for i in 0..burst {
        assert!(bus.publish(dns_allowed(sid, &format!("burst-{i}.example.com"))));
    }

    // Drain lines with a generous per-test timeout.  We don't know
    // exactly how many live lines the consumer sees (Lagged skips a
    // chunk and continues from the channel's current head) — but the
    // lag-marker line must appear within the first batch we consume.
    // Cap the read at 200 lines to guarantee termination even in a
    // regression where the handler loops on Lagged indefinitely.
    let mut saw_lag = false;
    let mut observed_skipped_total: u64 = 0;
    let mut non_lag_lines = 0usize;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);

    loop {
        if tokio::time::Instant::now() >= deadline {
            break;
        }
        let step = tokio::time::timeout(Duration::from_millis(250), body.frame()).await;
        let Ok(frame_opt) = step else { break };
        let frame = match frame_opt {
            Some(Ok(f)) => f,
            Some(Err(e)) => panic!("frame error: {e}"),
            None => break, // body ended
        };
        let Ok(data) = frame.into_data() else {
            continue;
        };
        // Every yield from the handler is a full line; split on `\n`
        // just to be safe against chunking.
        for line in data.split(|b| *b == b'\n') {
            if line.is_empty() {
                continue;
            }
            let v: serde_json::Value =
                serde_json::from_slice(line).expect("every line is valid JSON");
            if v["layer"] == "lifecycle" && v["event"] == "ring_buffer_lag" {
                let skipped = v["skipped"].as_u64().expect("skipped is numeric");
                assert!(
                    skipped >= 1,
                    "ring_buffer_lag must report skipped >= 1, got {skipped}"
                );
                assert!(
                    v["timestamp"].is_string(),
                    "ring_buffer_lag must carry a timestamp string"
                );
                observed_skipped_total += skipped;
                saw_lag = true;
            } else {
                non_lag_lines += 1;
            }
            if saw_lag && non_lag_lines >= 1 {
                // Proven the stream continues past the lag marker; we
                // can stop reading.  (This keeps the test bounded
                // even on very fast hardware where the consumer
                // catches up mid-burst.)
                break;
            }
        }
        if saw_lag && non_lag_lines >= 1 {
            break;
        }
    }

    assert!(
        saw_lag,
        "broadcast lag must surface as at least one ring_buffer_lag line; \
         observed {non_lag_lines} non-lag lines (total skipped reported: {observed_skipped_total})"
    );

    drop(body);
}
