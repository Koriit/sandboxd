//! Daemon-side ingest test for `nft-allow.jsonl`.
//!
//! Pins the new producer file path through the watcher, parser, and bus
//! without depending on the gateway image. Pattern mirrors
//! `sandbox-core/tests/events_ingest_integration.rs`'s
//! `deny_logger_jsonl_appears_on_bus` test:
//!
//! 1. Spawn a [`SessionIngestor`] on a tempdir standing in for the
//!    bind-mounted events directory.
//! 2. Append synthetic `nft-allow.jsonl` lines (one `allow` 5-tuple, one
//!    `rate_limited` summary) using the on-disk shape that
//!    `sandbox-nft-allow-logger`'s [`EventEmitter`] produces.
//! 3. Assert both records flow through the new `nft_logger` parser to
//!    the [`EventBus`] as `TrafficEvent::DenyLogger(Allow|RateLimited)`
//!    on the watcher's owning session.
//!
//! Named `integration_*` so it runs only under
//! `cargo nextest run --profile integration`. The test does no real
//! Docker / Lima work — it relies on a real `notify::RecommendedWatcher`
//! plus tempfs file appends — but exercises the inotify path and the
//! 2-second fallback poll, so the deadline is set generously.

use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Duration;

use sandbox_core::{
    DenyLoggerEvent, DenyProtocol, Event, EventBus, EventBusConfig, SessionId, SessionIngestor,
    TrafficEvent, VmIpSessionMap,
};
use tempfile::TempDir;
use tokio::io::AsyncWriteExt;
use tokio::time::timeout;

const DEADLINE: Duration = Duration::from_secs(5);
const VM_IP_STR: &str = "10.0.0.42";

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

/// Phase 3 contract: an `nft-allow.jsonl` line written into the events
/// directory must reach the bus as `TrafficEvent::DenyLogger(Allow(_))`,
/// stamped with the ingestor's session id.
///
/// Pins:
///
/// - `nft-allow.jsonl` is a known producer file (the watcher's
///   `KNOWN_FILES` table includes it).
/// - The `nft_logger` parser accepts `layer == "allow-logger"` paired
///   with `event == "allow"` and reuses the deny-logger 5-tuple shape.
/// - `src_ip` attribution still goes through `vm_ip_map.lookup` (per
///   the wire format); a bound source IP must
///   resolve to the test session.
/// - The shared `rate_limited` summary survives the layer rename — an
///   `allow-logger` rate-limited record carries no 5-tuple so it falls
///   back to the ingestor's session.
#[tokio::test]
async fn integration_nft_allow_jsonl_appears_on_bus() {
    let tmp = TempDir::new().expect("create tempdir");
    let events_dir = tmp.path().to_path_buf();
    let sid = SessionId::parse("eeeeeeeeeeee").expect("valid fixture id");

    let bus = EventBus::new(EventBusConfig::default());
    bus.register_session(sid);
    let vm_ip_map = VmIpSessionMap::new();
    vm_ip_map.bind(VM_IP_STR.parse::<Ipv4Addr>().expect("valid vm ip"), sid);
    let (mut replay, mut rx) = bus.subscribe(&sid).expect("session registered");

    let ingestor = SessionIngestor::spawn(sid, events_dir.clone(), bus.clone(), vm_ip_map.clone());
    // Beat for inotify to register the watch on the empty dir before
    // any file appears. The 2-second fallback poll would still recover,
    // but we want to exercise the inotify path on the fast path.
    tokio::time::sleep(Duration::from_millis(100)).await;

    // --- Allow (UDP) — the 5-tuple shape authored by the nft-allow-
    // logger component. Wire fields are byte-for-byte identical to
    // `deny-logger`'s `deny` row except for the `event` discriminator
    // and the `layer` tag (additive, not a new pipeline).
    let allow_line = r#"{"timestamp":"2026-04-22T09:45:10.000Z","layer":"allow-logger","event":"allow","orig_dst_ip":"1.1.1.1","orig_dst_port":53,"protocol":"udp","src_ip":"10.0.0.42","src_port":40123}"#;
    append_jsonl_line(&events_dir.join("nft-allow.jsonl"), allow_line).await;

    // --- Rate-limited summary — same shape the deny-logger emits,
    // under the new layer tag. No 5-tuple, so attribution falls back
    // to the ingestor's owning session.
    let rate_limited_line = r#"{"timestamp":"2026-04-22T09:45:11.000Z","layer":"allow-logger","event":"rate_limited","rate_limited_count":11,"since_ts":"2026-04-22T09:45:10.000Z"}"#;
    append_jsonl_line(&events_dir.join("nft-allow.jsonl"), rate_limited_line).await;

    let mut saw_allow = false;
    let mut saw_rate_limited = false;
    for i in 0..2 {
        let ev = next_event(&mut replay, &mut rx, &format!("allow-logger event #{i}")).await;
        match &*ev {
            Event::Traffic { envelope, event } => {
                assert_eq!(
                    envelope.session,
                    Some(sid),
                    "every allow-logger event must carry the ingestor's session id; \
                     got {envelope:?}"
                );
                match event {
                    TrafficEvent::DenyLogger(DenyLoggerEvent::Allow(a)) => {
                        assert_eq!(
                            a.orig_dst_ip,
                            "1.1.1.1".parse::<Ipv4Addr>().unwrap(),
                            "allow record orig_dst_ip must round-trip the synthetic value"
                        );
                        assert_eq!(a.orig_dst_port, 53);
                        assert_eq!(a.protocol, DenyProtocol::Udp);
                        assert_eq!(
                            a.src_ip,
                            VM_IP_STR.parse::<Ipv4Addr>().unwrap(),
                            "allow record src_ip must round-trip the bound VM ip"
                        );
                        assert_eq!(a.src_port, 40123);
                        assert!(!saw_allow, "duplicate allow event");
                        saw_allow = true;
                    }
                    TrafficEvent::DenyLogger(DenyLoggerEvent::RateLimited {
                        rate_limited_count,
                        ..
                    }) => {
                        assert_eq!(*rate_limited_count, 11);
                        assert!(!saw_rate_limited, "duplicate rate_limited event");
                        saw_rate_limited = true;
                    }
                    other => panic!("unexpected traffic event variant: {other:?}"),
                }
            }
            Event::Lifecycle { .. } => {
                panic!("unexpected lifecycle event on allow-logger traffic test")
            }
        }
    }
    assert!(
        saw_allow && saw_rate_limited,
        "missing allow-logger coverage: allow={saw_allow}, rate_limited={saw_rate_limited}"
    );

    // Stop the task so the tempdir can be dropped cleanly.
    ingestor.abort();
}

/// Negative coverage: a `layer == "deny-logger"` record carrying
/// `event == "allow"` is a layer/event mismatch (a gateway-side
/// regression that mis-labels its own files would produce this). The
/// parser must reject it, so nothing reaches the bus.
#[tokio::test]
async fn integration_nft_allow_jsonl_rejects_layer_event_mismatch() {
    let tmp = TempDir::new().expect("create tempdir");
    let events_dir = tmp.path().to_path_buf();
    let sid = SessionId::parse("ffffffffffff").expect("valid fixture id");

    let bus = EventBus::new(EventBusConfig::default());
    bus.register_session(sid);
    let vm_ip_map = VmIpSessionMap::new();
    vm_ip_map.bind(VM_IP_STR.parse::<Ipv4Addr>().expect("valid vm ip"), sid);
    let (replay, mut rx) = bus.subscribe(&sid).expect("session registered");

    let ingestor = SessionIngestor::spawn(sid, events_dir.clone(), bus.clone(), vm_ip_map.clone());
    tokio::time::sleep(Duration::from_millis(100)).await;

    // deny-logger layer + allow event — illegal pairing.
    let mismatch_line = r#"{"timestamp":"2026-04-22T09:45:10.000Z","layer":"deny-logger","event":"allow","orig_dst_ip":"1.1.1.1","orig_dst_port":53,"protocol":"udp","src_ip":"10.0.0.42","src_port":40123}"#;
    append_jsonl_line(&events_dir.join("nft-deny.jsonl"), mismatch_line).await;

    // Wait at least one full poll cycle so the watcher has a chance to
    // (mis)dispatch the line.
    tokio::time::sleep(Duration::from_millis(2_500)).await;

    // Nothing must have reached the bus — both the replay snapshot and
    // the live receiver should be empty.
    assert!(
        replay.is_empty(),
        "replay must be empty after rejected line; got {} events",
        replay.len()
    );
    assert!(
        matches!(
            rx.try_recv(),
            Err(tokio::sync::broadcast::error::TryRecvError::Empty)
        ),
        "live receiver must observe no events from a layer/event mismatch"
    );

    ingestor.abort();
}
