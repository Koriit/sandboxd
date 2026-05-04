//! End-to-end integration test for the per-session JSONL ingest
//! pipeline.
//!
//! Covers the full read-parse-stamp-publish path without a real
//! gateway container: a test-owned tempdir stands in for the
//! bind-mounted events directory, and the test writes JSONL lines
//! directly to the three producer files (`envoy.jsonl`,
//! `coredns.jsonl`, `mitmproxy.jsonl`).
//!
//! What the test pins:
//!
//! 1. [`SessionIngestor::spawn`] brings up the inotify watcher and
//!    per-layer tailers without error, even when the directory is
//!    initially empty.
//! 2. A complete JSONL line appended by the test is parsed, attributed
//!    to the bound session via [`VmIpSessionMap::lookup`], and
//!    published to the [`EventBus`] within a small deadline. One line
//!    per layer, all three layers, to catch a parser-dispatch
//!    regression.
//! 3. A line whose source IP is NOT bound to any session is dropped
//!    (warn + skip) rather than published — matches the spec's "drop
//!    events on vm_ip miss" note.
//! 4. [`SessionIngestor::abort`] stops the background task so
//!    subsequent appends do not land on the bus.
//!
//! This test exercises real inotify via `notify::RecommendedWatcher`
//! and the 2 s fallback poll, so the deadline is set to a generous
//! 5 s — long enough to tolerate CI jitter without letting a stuck
//! ingestor hide behind a still-passing assertion.

use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Duration;

use sandbox_core::{
    DenyLoggerEvent, DenyProtocol, DnsEvent, EnvoyEvent, Event, EventBus, EventBusConfig,
    MitmproxyEvent, SessionId, SessionIngestor, TrafficEvent, VmIpSessionMap,
};
use tempfile::TempDir;
use tokio::io::AsyncWriteExt;
use tokio::time::timeout;

/// Deadline within which every published event must reach the bus
/// subscriber. Covers inotify latency plus the 2 s fallback poll.
const DEADLINE: Duration = Duration::from_secs(5);

/// Bound VM IP used in every JSONL fixture. Must match what the test
/// seeds into the [`VmIpSessionMap`].
const VM_IP_STR: &str = "10.0.0.42";

/// IP that is NOT bound in the map. Used to assert the "drop on
/// unknown IP" path.
const UNBOUND_IP_STR: &str = "10.0.0.99";

/// Append a JSONL line (with trailing newline) to `path`, creating it
/// if necessary. Uses tokio's async file API so we stay on one runtime
/// and can await flushes deterministically.
async fn append_jsonl_line(path: &std::path::Path, line: &str) {
    let mut f = tokio::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .await
        .expect("open jsonl file for append");
    f.write_all(line.as_bytes()).await.expect("write line");
    f.write_all(b"\n").await.expect("write newline");
    f.flush().await.expect("flush jsonl line");
}

/// Pull one event off the subscriber receiver with a deadline; panics
/// if no event arrives in time. The replay snapshot is checked first
/// so an event published before `subscribe` is still observed.
async fn next_event(
    replay: &mut Vec<Arc<Event>>,
    rx: &mut tokio::sync::broadcast::Receiver<Arc<Event>>,
    ctx: &str,
) -> Arc<Event> {
    if !replay.is_empty() {
        return replay.remove(0);
    }
    match timeout(DEADLINE, rx.recv()).await {
        Ok(Ok(ev)) => ev,
        Ok(Err(e)) => panic!("{ctx}: broadcast receiver closed: {e}"),
        Err(_) => panic!("{ctx}: no event within {DEADLINE:?}"),
    }
}

#[tokio::test]
async fn integration_ingestor_publishes_one_event_per_layer() {
    let tmp = TempDir::new().expect("create tempdir");
    let events_dir = tmp.path().to_path_buf();
    let sid = SessionId::parse("aaaaaaaaaaaa").expect("valid fixture id");

    let bus = EventBus::new(EventBusConfig::default());
    bus.register_session(sid);
    let vm_ip_map = VmIpSessionMap::new();
    vm_ip_map.bind(VM_IP_STR.parse::<Ipv4Addr>().expect("valid vm ip"), sid);

    // Subscribe **before** spawning the ingestor so the broadcast
    // receiver exists when the first event lands. `subscribe` also
    // returns the ring-buffer snapshot, which handles the race where
    // the ingestor publishes just before `rx.recv()` is first polled.
    let (mut replay, mut rx) = bus.subscribe(&sid).expect("session registered");

    let ingestor = SessionIngestor::spawn(sid, events_dir.clone(), bus.clone(), vm_ip_map.clone());

    // Give notify a beat to set up the inotify watch on the empty
    // directory before we write. Without this, the first `Create`
    // event can race ahead of the watcher and be missed — the 2 s
    // fallback poll would still catch it, but we prefer to exercise
    // the inotify path in the common case.
    tokio::time::sleep(Duration::from_millis(100)).await;

    // --- Envoy: one allowed TCP connection. Numeric fields are
    // quoted because our policy.rs templates render Envoy's
    // `json_format` with quoted substitutions (see `envoy.rs`
    // parser comment).
    let envoy_line = r#"{"timestamp":"2026-04-22T09:45:00.100Z","layer":"envoy","event":"connection_allowed","src_ip":"10.0.0.42","src_port":"51234","dst_ip":"93.184.216.34","dst_port":"443","matched_chain":"l3_https","cluster":"upstream_https","upstream_host":"93.184.216.34:443","bytes_sent":"1024","bytes_received":"2048","response_flags":"-","duration_ms":"42","connect_authority":"api.example.com:443"}"#;
    append_jsonl_line(&events_dir.join("envoy.jsonl"), envoy_line).await;

    // --- CoreDNS: one allowed A-record query.
    let coredns_line = r#"{"timestamp":"2026-04-22T09:45:00.200Z","layer":"dns","event":"query_allowed","query":"api.example.com","qtype":"A","client_ip":"10.0.0.42","resolved_ips":["93.184.216.34"]}"#;
    append_jsonl_line(&events_dir.join("coredns.jsonl"), coredns_line).await;

    // --- mitmproxy: one allowed GET.
    let mitm_line = r#"{"timestamp":"2026-04-22T09:45:00.300Z","layer":"mitmproxy","event":"request_allowed","host":"api.example.com","port":443,"method":"GET","path":"/v1/widgets","client_ip":"10.0.0.42"}"#;
    append_jsonl_line(&events_dir.join("mitmproxy.jsonl"), mitm_line).await;

    // Collect three events. Order is not guaranteed (three separate
    // files, each with its own tailer), so classify by variant and
    // assert one of each.
    let mut saw_envoy = false;
    let mut saw_dns = false;
    let mut saw_mitm = false;
    for i in 0..3 {
        let ev = next_event(&mut replay, &mut rx, &format!("event #{i}")).await;
        match &*ev {
            Event::Traffic { envelope, event } => {
                assert_eq!(
                    envelope.session,
                    Some(sid),
                    "every traffic event must carry the bound session id; got {envelope:?}"
                );
                match event {
                    TrafficEvent::Envoy(EnvoyEvent::ConnectionAllowed(conn)) => {
                        assert_eq!(conn.dst_port, 443);
                        assert_eq!(conn.matched_chain, "l3_https");
                        assert_eq!(
                            conn.connect_authority.as_deref(),
                            Some("api.example.com:443")
                        );
                        assert!(!saw_envoy, "duplicate Envoy event");
                        saw_envoy = true;
                    }
                    TrafficEvent::Dns(DnsEvent::QueryAllowed { query, .. }) => {
                        assert_eq!(query, "api.example.com");
                        assert!(!saw_dns, "duplicate DNS event");
                        saw_dns = true;
                    }
                    TrafficEvent::Mitmproxy(MitmproxyEvent::RequestAllowed { path, .. }) => {
                        assert_eq!(path, "/v1/widgets");
                        assert!(!saw_mitm, "duplicate mitmproxy event");
                        saw_mitm = true;
                    }
                    other => panic!("unexpected traffic event variant: {other:?}"),
                }
            }
            Event::Lifecycle { .. } => panic!("unexpected lifecycle event on traffic-only test"),
        }
    }
    assert!(
        saw_envoy && saw_dns && saw_mitm,
        "missing layer coverage: envoy={saw_envoy}, dns={saw_dns}, mitm={saw_mitm}"
    );

    // Stop the task so the tempdir can be dropped cleanly.
    ingestor.abort();
}

#[tokio::test]
async fn integration_ingestor_drops_events_with_unknown_source_ip() {
    let tmp = TempDir::new().expect("create tempdir");
    let events_dir = tmp.path().to_path_buf();
    let sid = SessionId::parse("bbbbbbbbbbbb").expect("valid fixture id");

    let bus = EventBus::new(EventBusConfig::default());
    bus.register_session(sid);
    let vm_ip_map = VmIpSessionMap::new();
    // Deliberately bind only `VM_IP_STR`; the record below uses
    // `UNBOUND_IP_STR` to exercise the miss path.
    vm_ip_map.bind(VM_IP_STR.parse::<Ipv4Addr>().expect("valid vm ip"), sid);
    let (_replay, mut rx) = bus.subscribe(&sid).expect("session registered");

    let ingestor = SessionIngestor::spawn(sid, events_dir.clone(), bus.clone(), vm_ip_map.clone());
    tokio::time::sleep(Duration::from_millis(100)).await;

    // One envoy access-log record with an unbound `src_ip` — must not
    // be published to any session's sink. Envoy is used here (rather
    // than mitmproxy as in older versions of this test) because
    // mitmproxy attribution was intentionally moved off the vm_ip_map
    // lookup path — see the function-level doc on `dispatch_line` and
    // the dedicated
    // `integration_mitmproxy_event_attributes_via_watcher_session_even_with_unbound_client_ip`
    // test below. The drop-on-miss invariant continues to apply to the
    // producers that do use vm_ip_map (envoy + coredns).
    let unknown_line = format!(
        r#"{{"timestamp":"2026-04-22T09:45:01.000Z","layer":"envoy","event":"connection_allowed","src_ip":"{UNBOUND_IP_STR}","src_port":"51234","dst_ip":"93.184.216.34","dst_port":"443","matched_chain":"l3_https","cluster":"upstream_https","upstream_host":"93.184.216.34:443","bytes_sent":"0","bytes_received":"0","response_flags":"-","duration_ms":"1","connect_authority":"api.example.com:443"}}"#,
    );
    append_jsonl_line(&events_dir.join("envoy.jsonl"), &unknown_line).await;

    // Wait past the 2 s poll interval to give the tailer a chance to
    // read and drop; also covers the inotify path even on slow CI.
    // If the event were being (incorrectly) published we would see it
    // on `rx` well before 3 s elapse.
    match timeout(Duration::from_secs(3), rx.recv()).await {
        Ok(Ok(ev)) => {
            panic!("unattributable event must be dropped, but got published: {ev:?}");
        }
        Ok(Err(broadcast_err)) => {
            panic!("broadcast receiver closed unexpectedly: {broadcast_err}");
        }
        Err(_) => {
            // Timeout — expected. Nothing was published.
        }
    }

    ingestor.abort();
}

#[tokio::test]
async fn integration_ingestor_abort_stops_further_publishes() {
    let tmp = TempDir::new().expect("create tempdir");
    let events_dir = tmp.path().to_path_buf();
    let sid = SessionId::parse("cccccccccccc").expect("valid fixture id");

    let bus = EventBus::new(EventBusConfig::default());
    bus.register_session(sid);
    let vm_ip_map = VmIpSessionMap::new();
    vm_ip_map.bind(VM_IP_STR.parse::<Ipv4Addr>().expect("valid vm ip"), sid);
    let (mut replay, mut rx) = bus.subscribe(&sid).expect("session registered");

    let ingestor = SessionIngestor::spawn(sid, events_dir.clone(), bus.clone(), vm_ip_map.clone());
    tokio::time::sleep(Duration::from_millis(100)).await;

    // First write: should be observed on the bus.
    let line_before = r#"{"timestamp":"2026-04-22T09:45:02.000Z","layer":"mitmproxy","event":"request_allowed","host":"api.example.com","port":443,"method":"GET","path":"/before","client_ip":"10.0.0.42"}"#;
    append_jsonl_line(&events_dir.join("mitmproxy.jsonl"), line_before).await;

    let ev = next_event(&mut replay, &mut rx, "event before abort").await;
    match &*ev {
        Event::Traffic {
            event: TrafficEvent::Mitmproxy(MitmproxyEvent::RequestAllowed { path, .. }),
            ..
        } => assert_eq!(path, "/before"),
        other => panic!("expected mitmproxy RequestAllowed(/before), got {other:?}"),
    }

    // Abort the ingestor and then write another line. The abort is
    // cooperative (tokio task abort on yield points); wait a little
    // for the task to actually exit before appending, so the append
    // cannot race ahead of the abort.
    ingestor.abort();
    tokio::time::sleep(Duration::from_millis(200)).await;

    let line_after = r#"{"timestamp":"2026-04-22T09:45:03.000Z","layer":"mitmproxy","event":"request_allowed","host":"api.example.com","port":443,"method":"GET","path":"/after","client_ip":"10.0.0.42"}"#;
    append_jsonl_line(&events_dir.join("mitmproxy.jsonl"), line_after).await;

    // Wait past the 2 s fallback poll — a still-live ingestor would
    // have published by now.
    match timeout(Duration::from_secs(3), rx.recv()).await {
        Ok(Ok(ev)) => panic!("post-abort append must not publish, but got: {ev:?}"),
        Ok(Err(broadcast_err)) => {
            panic!("broadcast receiver closed unexpectedly: {broadcast_err}");
        }
        Err(_) => {
            // Timeout — expected. Aborted ingestor stayed silent.
        }
    }
}

/// Regression test for the mitmproxy attribution bug.
///
/// In production, mitmproxy runs on `127.0.0.1:18080` inside the gateway
/// container and is reached by Envoy via a `tcp_proxy` filter. The
/// mitmproxy addon reports `client_ip` as the kernel-chosen source of
/// Envoy's upstream connect — typically the container's bridge IP
/// (`10.209.0.2`-ish), not the VM's IP (`10.209.0.3`-ish). A naive
/// `vm_ip_map.lookup(client_ip)`-based attribution therefore silently
/// drops every mitmproxy event.
///
/// This test asserts the fix: a mitmproxy record whose `client_ip` is
/// **not** bound in `vm_ip_map` still reaches the session's ring,
/// attributed via the ingestor's own `watcher_session` (the same
/// fallback path the deny-logger's `rate_limited` summary uses). The VM
/// IP is deliberately bound to a *different* address to prove no
/// lookup-by-client_ip is happening under the hood.
#[tokio::test]
async fn integration_mitmproxy_event_attributes_via_watcher_session_even_with_unbound_client_ip() {
    let tmp = TempDir::new().expect("create tempdir");
    let events_dir = tmp.path().to_path_buf();
    let sid = SessionId::parse("eeeeeeeeeeee").expect("valid fixture id");

    let bus = EventBus::new(EventBusConfig::default());
    bus.register_session(sid);
    let vm_ip_map = VmIpSessionMap::new();
    // Bind *only* the VM IP (10.209.0.3). The mitmproxy line below
    // carries `client_ip=10.209.0.2` (the gateway's bridge IP), which
    // is intentionally left unbound — the whole point of the fix is
    // that mitmproxy attribution must not need the client_ip in the
    // map.
    let vm_ip: Ipv4Addr = "10.209.0.3".parse().expect("valid vm ip");
    vm_ip_map.bind(vm_ip, sid);
    let (mut replay, mut rx) = bus.subscribe(&sid).expect("session registered");

    let ingestor = SessionIngestor::spawn(sid, events_dir.clone(), bus.clone(), vm_ip_map.clone());
    tokio::time::sleep(Duration::from_millis(100)).await;

    let mitm_line = r#"{"timestamp":"2026-04-22T09:45:20.000Z","layer":"mitmproxy","event":"request_allowed","host":"registry.npmjs.org","port":443,"method":"GET","path":"/leftpad","client_ip":"10.209.0.2"}"#;
    append_jsonl_line(&events_dir.join("mitmproxy.jsonl"), mitm_line).await;

    let ev = next_event(&mut replay, &mut rx, "mitmproxy unbound-client-ip").await;
    match &*ev {
        Event::Traffic { envelope, event } => {
            assert_eq!(
                envelope.session,
                Some(sid),
                "mitmproxy event must attribute to the ingestor's session, \
                 not resolve through vm_ip_map (client_ip=10.209.0.2 is unbound)",
            );
            match event {
                TrafficEvent::Mitmproxy(MitmproxyEvent::RequestAllowed { host, path, .. }) => {
                    assert_eq!(host, "registry.npmjs.org");
                    assert_eq!(path, "/leftpad");
                }
                other => panic!("expected mitmproxy RequestAllowed, got {other:?}"),
            }
        }
        Event::Lifecycle { .. } => panic!("unexpected lifecycle event"),
    }

    ingestor.abort();
}

/// End-to-end: `nft-deny.jsonl` records are parsed and surface on the
/// session bus. Covers both event shapes prescribed by spec Part 3:
///
/// 1. A TCP `deny` record — the 5-tuple drives a `vm_ip_map.lookup` on
///    the VM's bridge IP, stamping the same session as the other
///    producers.
/// 2. A `rate_limited` summary record — no 5-tuple, so attribution
///    falls back to the ingestor's owning session (the watcher's
///    fallback rule).
#[tokio::test]
async fn deny_logger_jsonl_appears_on_bus() {
    let tmp = TempDir::new().expect("create tempdir");
    let events_dir = tmp.path().to_path_buf();
    let sid = SessionId::parse("dddddddddddd").expect("valid fixture id");

    let bus = EventBus::new(EventBusConfig::default());
    bus.register_session(sid);
    let vm_ip_map = VmIpSessionMap::new();
    vm_ip_map.bind(VM_IP_STR.parse::<Ipv4Addr>().expect("valid vm ip"), sid);
    let (mut replay, mut rx) = bus.subscribe(&sid).expect("session registered");

    let ingestor = SessionIngestor::spawn(sid, events_dir.clone(), bus.clone(), vm_ip_map.clone());
    tokio::time::sleep(Duration::from_millis(100)).await;

    // --- Deny (TCP) — the 5-tuple shape authored by the deny-logger
    // component per spec Part 3 / "Traffic events" row for `deny-logger`:
    // `orig_dst_ip`, `orig_dst_port`, `protocol`, `src_ip`, `src_port`.
    let deny_line = r#"{"timestamp":"2026-04-22T09:45:10.000Z","layer":"deny-logger","event":"deny","orig_dst_ip":"203.0.113.1","orig_dst_port":8443,"protocol":"tcp","src_ip":"10.0.0.42","src_port":51234}"#;
    append_jsonl_line(&events_dir.join("nft-deny.jsonl"), deny_line).await;

    // --- Rate-limited summary — no 5-tuple; `rate_limited_count` +
    // `since_ts` per spec Part 3 / "Hardening rules" § 5. Attribution
    // must fall back to the ingestor's own session.
    let rate_limited_line = r#"{"timestamp":"2026-04-22T09:45:11.000Z","layer":"deny-logger","event":"rate_limited","rate_limited_count":17,"since_ts":"2026-04-22T09:45:10.000Z"}"#;
    append_jsonl_line(&events_dir.join("nft-deny.jsonl"), rate_limited_line).await;

    let mut saw_deny = false;
    let mut saw_rate_limited = false;
    for i in 0..2 {
        let ev = next_event(&mut replay, &mut rx, &format!("deny-logger event #{i}")).await;
        match &*ev {
            Event::Traffic { envelope, event } => {
                assert_eq!(
                    envelope.session,
                    Some(sid),
                    "every deny-logger event must carry the ingestor's session id; got {envelope:?}"
                );
                match event {
                    TrafficEvent::DenyLogger(DenyLoggerEvent::Deny(d)) => {
                        assert_eq!(d.orig_dst_ip, "203.0.113.1".parse::<Ipv4Addr>().unwrap());
                        assert_eq!(d.orig_dst_port, 8443);
                        assert_eq!(d.protocol, DenyProtocol::Tcp);
                        assert_eq!(d.src_ip, "10.0.0.42".parse::<Ipv4Addr>().unwrap());
                        assert_eq!(d.src_port, 51234);
                        assert!(!saw_deny, "duplicate deny event");
                        saw_deny = true;
                    }
                    TrafficEvent::DenyLogger(DenyLoggerEvent::RateLimited {
                        rate_limited_count,
                        ..
                    }) => {
                        assert_eq!(*rate_limited_count, 17);
                        assert!(!saw_rate_limited, "duplicate rate_limited event");
                        saw_rate_limited = true;
                    }
                    other => panic!("unexpected traffic event variant: {other:?}"),
                }
            }
            Event::Lifecycle { .. } => {
                panic!("unexpected lifecycle event on deny-logger traffic test")
            }
        }
    }
    assert!(
        saw_deny && saw_rate_limited,
        "missing deny-logger coverage: deny={saw_deny}, rate_limited={saw_rate_limited}"
    );

    ingestor.abort();
}
