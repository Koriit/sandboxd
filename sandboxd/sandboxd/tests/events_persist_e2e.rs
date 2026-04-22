//! Milestone-exit integration tests for M10-S4 Phase 5 (persistent
//! event sink).
//!
//! Two contracts, both env-gated under `SANDBOX_TEST_INTEGRATION=1`
//! and `#[ignore]`d so they stay out of the default workspace run
//! (which intentionally boots nothing):
//!
//!   1. `persistent_sink_writes_rotated_jsonl` — with
//!      `--events-persist` effectively on (via the Rust API, which
//!      is what the daemon calls), events published to the bus land
//!      as JSONL at
//!      `{base_dir}/sessions/{id}/events/{layer}-YYYY-MM-DD.jsonl`.
//!      We publish a DNS event and a lifecycle event for the same
//!      session, drop the sink, and verify both files exist with
//!      valid JSON on every line.
//!   2. `persistent_sink_pruner_removes_old_files` — fabricate
//!      files at `today-20` and `today-1` under the spec layout,
//!      spawn the sink with `retention_days = 14` and a fast test
//!      interval (`SANDBOX_TEST_PRUNER_INTERVAL_SECS=1`), confirm
//!      the stale file is removed and the recent one survives.
//!
//! These tests drive `PersistentSink::spawn` directly rather than
//! spawning the `sandboxd` binary.  The daemon's only added
//! behaviour (beyond the sink itself) is parsing the two CLI
//! flags and passing them through — covered independently by the
//! clap `#[derive(Parser)]` contract and compile-checked by the
//! build step.

use std::net::Ipv4Addr;
use std::time::Duration;

use chrono::{NaiveDate, Utc};
use sandbox_core::{
    DnsEvent, Event, EventBus, EventBusConfig, EventEnvelope, LifecycleEvent, PersistConfig,
    PersistentSink, SessionId, TrafficEvent,
};
use tempfile::tempdir;
use tokio::fs;
use tokio::time::sleep;

// ---------------------------------------------------------------------------
// Env gate — mirrors m10_s3_end_to_end.rs
// ---------------------------------------------------------------------------

const ENV_GATE: &str = "SANDBOX_TEST_INTEGRATION";

fn env_gate_enabled() -> bool {
    std::env::var(ENV_GATE).map(|v| v == "1").unwrap_or(false)
}

fn skip_unless_enabled(test_name: &str) -> bool {
    if env_gate_enabled() {
        false
    } else {
        eprintln!("SKIP {test_name}: set {ENV_GATE}=1 to enable integration tests");
        true
    }
}

// ---------------------------------------------------------------------------
// Event fixtures
// ---------------------------------------------------------------------------

fn dns_allow(sid: SessionId, query: &str) -> Event {
    Event::Traffic {
        envelope: EventEnvelope {
            timestamp: Utc::now(),
            session: Some(sid),
        },
        event: TrafficEvent::Dns(DnsEvent::QueryAllowed {
            query: query.into(),
            qtype: "A".into(),
            resolved_ips: vec![Ipv4Addr::new(10, 0, 0, 1)],
        }),
    }
}

fn lifecycle_ready(sid: SessionId) -> Event {
    Event::Lifecycle {
        envelope: EventEnvelope {
            timestamp: Utc::now(),
            session: Some(sid),
        },
        event: LifecycleEvent::GatewayReady,
    }
}

// ---------------------------------------------------------------------------
// File-layout mirror
// ---------------------------------------------------------------------------

/// Duplicate of the sink's internal `file_path` layout. Kept local
/// so the test asserts the *observable* shape (what a tail -f
/// consumer would read) without taking a dependency on a private
/// symbol.
fn expected_path(
    base_dir: &std::path::Path,
    sid: &SessionId,
    layer: &str,
    date: NaiveDate,
) -> std::path::PathBuf {
    base_dir
        .join("sessions")
        .join(sid.as_str())
        .join("events")
        .join(format!("{layer}-{}.jsonl", date.format("%Y-%m-%d")))
}

async fn wait_for_file(path: &std::path::Path) {
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    loop {
        if fs::metadata(path).await.is_ok() {
            return;
        }
        if std::time::Instant::now() > deadline {
            panic!("timeout waiting for file: {}", path.display());
        }
        sleep(Duration::from_millis(50)).await;
    }
}

async fn wait_for_lines(path: &std::path::Path, at_least: usize) {
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    loop {
        if let Ok(s) = fs::read_to_string(path).await {
            if s.lines().count() >= at_least {
                return;
            }
        }
        if std::time::Instant::now() > deadline {
            let body = fs::read_to_string(path)
                .await
                .unwrap_or_else(|_| "<missing>".into());
            panic!(
                "timeout waiting for >= {at_least} lines in {}; got:\n{}",
                path.display(),
                body
            );
        }
        sleep(Duration::from_millis(50)).await;
    }
}

// ---------------------------------------------------------------------------
// Test 1 — publish -> disk
// ---------------------------------------------------------------------------

#[tokio::test]
#[ignore = "requires SANDBOX_TEST_INTEGRATION=1"]
async fn persistent_sink_writes_rotated_jsonl() {
    if skip_unless_enabled("persistent_sink_writes_rotated_jsonl") {
        return;
    }

    let dir = tempdir().unwrap();
    let base = dir.path().to_path_buf();

    let bus = EventBus::new(EventBusConfig::default());
    let sid = SessionId::parse("0123456789ab").unwrap();
    bus.register_session(sid);

    let sink = PersistentSink::spawn(
        &bus,
        PersistConfig {
            enabled: true,
            base_dir: base.clone(),
            retention_days: 14,
        },
    );

    // Two DNS events + one lifecycle event on the same session.
    bus.publish(dns_allow(sid, "one.example.com"));
    bus.publish(dns_allow(sid, "two.example.com"));
    bus.publish(lifecycle_ready(sid));

    let today = Utc::now().date_naive();
    let dns_path = expected_path(&base, &sid, "dns", today);
    let life_path = expected_path(&base, &sid, "lifecycle", today);

    wait_for_lines(&dns_path, 2).await;
    wait_for_lines(&life_path, 1).await;

    // Shut down cleanly and re-read.  The shutdown path is where
    // a regression (e.g. not awaiting the sink task) would surface
    // as partial writes — so we assert *after* shutdown.
    sink.shutdown().await;

    let dns_body = fs::read_to_string(&dns_path).await.expect("dns file");
    let life_body = fs::read_to_string(&life_path)
        .await
        .expect("lifecycle file");

    assert_eq!(
        dns_body.lines().count(),
        2,
        "dns file should have exactly 2 JSONL lines; got:\n{dns_body}"
    );
    assert_eq!(
        life_body.lines().count(),
        1,
        "lifecycle file should have exactly 1 JSONL line; got:\n{life_body}"
    );
    for line in dns_body.lines() {
        let v: serde_json::Value = serde_json::from_str(line)
            .unwrap_or_else(|e| panic!("invalid JSON line in dns file: {line:?} => {e}"));
        // Envelope fields should be stamped.
        assert!(v.get("timestamp").is_some(), "missing timestamp: {line}");
        assert!(v.get("session").is_some(), "missing session: {line}");
    }
    let life_line = life_body.lines().next().unwrap();
    let v: serde_json::Value = serde_json::from_str(life_line).expect("lifecycle JSON");
    assert!(v.get("timestamp").is_some());
    assert!(v.get("session").is_some());
}

// ---------------------------------------------------------------------------
// Test 2 — pruner sweeps old files
// ---------------------------------------------------------------------------

#[tokio::test]
#[ignore = "requires SANDBOX_TEST_INTEGRATION=1"]
async fn persistent_sink_pruner_removes_old_files() {
    if skip_unless_enabled("persistent_sink_pruner_removes_old_files") {
        return;
    }

    let dir = tempdir().unwrap();
    let base = dir.path().to_path_buf();
    let sid = SessionId::parse("0123456789ab").unwrap();
    let today = Utc::now().date_naive();

    // Fabricate the two fixture files under the spec layout.
    let events_dir = base.join("sessions").join(sid.as_str()).join("events");
    fs::create_dir_all(&events_dir).await.unwrap();
    let old_date = today - chrono::Duration::days(20);
    let recent_date = today - chrono::Duration::days(1);
    let old_path = events_dir.join(format!("dns-{}.jsonl", old_date.format("%Y-%m-%d")));
    let recent_path = events_dir.join(format!("dns-{}.jsonl", recent_date.format("%Y-%m-%d")));
    fs::write(&old_path, b"{\"old\":1}\n").await.unwrap();
    fs::write(&recent_path, b"{\"recent\":1}\n").await.unwrap();

    // Turn the pruner interval down so the first sweep lands in
    // ~1 s rather than the production 3600 s.  This env var is
    // documented as test-only in `events::persist::pruner` and
    // read once by `pruner_interval()` at the top of the pruner
    // task's `run_loop`.
    //
    // SAFETY: nextest runs each test in its own process by
    // default (see `.config/nextest.toml`), so the env var stays
    // scoped to this test.  We leave it set for the duration of
    // the test and tear it down at the end; an early `remove_var`
    // would race the async pruner task which hasn't yet had its
    // first poll.
    unsafe {
        std::env::set_var("SANDBOX_TEST_PRUNER_INTERVAL_SECS", "1");
    }

    let bus = EventBus::new(EventBusConfig::default());
    bus.register_session(sid);
    let sink = PersistentSink::spawn(
        &bus,
        PersistConfig {
            enabled: true,
            base_dir: base.clone(),
            retention_days: 14,
        },
    );

    // First sweep lands one interval (1 s) after spawn; an extra
    // interval gives scheduler jitter room on loaded CI.  Poll
    // instead of sleeping the deadline so a fast sweep returns
    // fast.
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while old_path.exists() {
        if std::time::Instant::now() > deadline {
            sink.shutdown().await;
            unsafe {
                std::env::remove_var("SANDBOX_TEST_PRUNER_INTERVAL_SECS");
            }
            panic!(
                "timeout waiting for pruner to remove {}",
                old_path.display()
            );
        }
        sleep(Duration::from_millis(50)).await;
    }

    // Recent file still exists — and must survive across the sweep.
    wait_for_file(&recent_path).await;
    assert!(
        recent_path.exists(),
        "recent file must not have been removed: {}",
        recent_path.display()
    );

    sink.shutdown().await;
    unsafe {
        std::env::remove_var("SANDBOX_TEST_PRUNER_INTERVAL_SECS");
    }
}
