//! Milestone-exit integration test for M10-S2 Phase 8.
//!
//! Pins the three contracts the plan requires before the milestone can
//! close (`.tasks/plans/2026-04-21-port-explicit-policies-presets-
//! observability-design/M10/session-2-event-ingestion-pipeline.md`,
//! Phase 8 / exit criteria 4-5):
//!
//!   1. `ingest_traffic_events_stamp_session_and_reach_bus` — apply
//!      policy + trigger one flow per layer ⇒ three domain events appear
//!      on the bus with `envelope.session = <sid>` stamped from the
//!      vm_ip map.  The three parsers (envoy / coredns / mitmproxy) are
//!      exercised through real `SessionIngestor` + `EventBus` wiring,
//!      with fixtures shaped the way the in-container producers emit.
//!   2. `lifecycle_sequence_across_create_apply_stop` — the four-event
//!      sequence a session lifecycle produces at create + apply + stop
//!      lands on the bus in the expected order.  Uses the same
//!      `lifecycle::*` builders + `EventBus::publish` path that
//!      sandboxd::main drives at each emission site, so a regression in
//!      either the builder or the bus contract surfaces here.
//!   3. `policy_reset_on_upgrade_emitted_for_v004_orphans` — seed a DB
//!      at the V001-V003 shape with v1-tokened rules, open via
//!      `SessionStore::new`, and drive the same "publish one event per
//!      orphan" loop sandboxd::main runs after the bus is up.  Asserts
//!      the `previous_rule_count` captured by the two-pass migration
//!      survives all the way to the bus payload.
//!
//! The traffic test uses real inotify + the 2 s fallback poll through a
//! tempdir stand-in for the per-session bind mount; it does *not* spin
//! up a gateway container, Lima VM, or sandboxd::AppState.  That
//! intentionally matches Phase 8's "test-only" scope — the full-stack
//! coverage over real containers lives in `tests/e2e/test_m4_policy.py`
//! and `test_m10_*.py` and is invoked by the exit-gate checklist, not
//! this file.

use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use rusqlite::{Connection, params};
use sandbox_core::events::lifecycle as lifecycle_events;
use sandbox_core::policy::{
    AssuranceLevel, Destination, HttpFilter, HttpMethod, PolicyRule, Protocol,
};
use sandbox_core::{
    DnsEvent, EnvoyEvent, Event, EventBus, EventBusConfig, GatewayShutdownReason, LifecycleEvent,
    MitmproxyEvent, Policy, PolicyApplyStatus, SessionId, SessionIngestor, SessionStore,
    TrafficEvent, VmIpSessionMap,
};
use tempfile::TempDir;
use tokio::io::AsyncWriteExt;
use tokio::sync::broadcast;
use tokio::time::timeout;

/// Refinery handle to V001-V003 of the sandbox-core migration chain.
///
/// The chain lives in `sandbox-core/migrations/`; `embed_migrations!`
/// resolves the path relative to this crate's Cargo.toml so the test
/// embeds the exact files that `SessionStore::new` runs in production.
/// We intentionally target V003 here so the seed can populate v1-shaped
/// rows before `SessionStore::new` applies V004 and sweeps them.
mod v1_migrations {
    refinery::embed_migrations!("../sandbox-core/migrations");
}

/// Deadline within which every published traffic event must reach the
/// subscriber.  The ingestor's 2 s fallback poll is the slowest path;
/// 5 s leaves enough headroom for CI jitter without letting a stuck
/// ingestor hide behind a still-passing assertion.
const TRAFFIC_DEADLINE: Duration = Duration::from_secs(5);

/// VM-bridge IPv4 we bind to the test session's id; every traffic
/// fixture below must use this as its `src_ip` / `client_ip` so the
/// ingestor stamps the envelope correctly.
const VM_IP: &str = "10.0.0.42";

// ---------------------------------------------------------------------------
// Test 1: three-layer traffic ingestion with session attribution
// ---------------------------------------------------------------------------

/// Append a JSONL line (with trailing newline) to `path`.
async fn append_jsonl_line(path: &Path, line: &str) {
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

/// Pull the next event off `(replay, rx)` with a bounded wait, draining
/// the replay snapshot first so events published before `subscribe` are
/// still observed.
async fn next_event(
    replay: &mut Vec<Arc<Event>>,
    rx: &mut broadcast::Receiver<Arc<Event>>,
    ctx: &str,
) -> Arc<Event> {
    if !replay.is_empty() {
        return replay.remove(0);
    }
    match timeout(TRAFFIC_DEADLINE, rx.recv()).await {
        Ok(Ok(ev)) => ev,
        Ok(Err(e)) => panic!("{ctx}: broadcast receiver closed: {e}"),
        Err(_) => panic!("{ctx}: no event within {TRAFFIC_DEADLINE:?}"),
    }
}

/// Phase 8 exit criterion 4: "apply policy, trigger one flow per layer,
/// three events appear in ring buffer with `session` stamped via vm_ip
/// map and envelope fields present."
///
/// Drives the full sandboxd-side ingest pipeline:
///
///   Envoy access-log JSON → envoy parser → vm_ip lookup → bus
///   CoreDNS plugin JSON  → coredns parser → vm_ip lookup → bus
///   mitmproxy addon JSON  → mitmproxy parser → vm_ip lookup → bus
///
/// For each layer the fixture line matches the shape the in-container
/// producer writes (quoted numerics for Envoy, string `resolved_ips` for
/// CoreDNS, bare numeric `port` for mitmproxy — see the goldens in
/// `sandbox-core/src/policy.rs`, `networking/coredns-plugin/events.go`,
/// and `networking/mitmproxy/events.py`).
///
/// Assertions:
/// - Every published event carries `envelope.session = Some(sid)` — the
///   ingestor looked up `vm_ip` and stamped the bound session.
/// - The three layer discriminants (`Envoy`, `Dns`, `Mitmproxy`) are
///   each observed exactly once.
/// - Layer-specific envelope fields arrive intact (e.g. `dst_port`,
///   `connect_authority`, `path`, `resolved_ips`).
#[tokio::test]
async fn ingest_traffic_events_stamp_session_and_reach_bus() {
    let tmp = TempDir::new().expect("create tempdir");
    let events_dir = tmp.path().to_path_buf();
    let sid = SessionId::parse("aaaaaaaaaaaa").expect("valid fixture id");

    let bus = EventBus::new(EventBusConfig::default());
    bus.register_session(sid);

    let vm_ip_map = VmIpSessionMap::new();
    vm_ip_map.bind(VM_IP.parse::<Ipv4Addr>().expect("valid vm ip"), sid);

    // Subscribe before spawning the ingestor so the broadcast receiver
    // exists when the first event lands.  The snapshot half of the
    // tuple covers the race where a line is parsed and published before
    // `rx.recv()` is first polled.
    let (mut replay, mut rx) = bus.subscribe(&sid).expect("session registered");

    let ingestor = SessionIngestor::spawn(sid, events_dir.clone(), bus.clone(), vm_ip_map.clone());

    // Give the inotify watcher a beat to install its watch on the
    // empty directory before we start writing — without this delay
    // the first Create notification can race ahead of the watcher and
    // only the 2 s fallback poll would catch it.
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Envoy L3 allowed CONNECT tunnel fixture.  Shape matches the
    // `json_format` template authored in
    // `PolicyCompiler::l3_tcp_proxy_access_log_yaml` — every numeric
    // field is a string because the template value is quoted (Envoy
    // substitutes inside the quotes).  `response_flags: "-"` places
    // the record on the allow path (see `ALLOWED_RESPONSE_FLAGS` in
    // `events/ingest/envoy.rs`).
    let envoy_line = r#"{"timestamp":"2026-04-22T09:45:00.100Z","layer":"envoy","event":"connection_allowed","src_ip":"10.0.0.42","src_port":"51234","dst_ip":"93.184.216.34","dst_port":"443","matched_chain":"level3_https_p443","cluster":"mitmproxy","upstream_host":"127.0.0.1:18080","bytes_sent":"1024","bytes_received":"2048","response_flags":"-","duration_ms":"42","connect_authority":"api.example.com:443"}"#;
    append_jsonl_line(&events_dir.join("envoy.jsonl"), envoy_line).await;

    // CoreDNS allowed A-record resolution.  Shape matches
    // `networking/coredns-plugin/events.go` -> `EmitQueryAllowed`:
    // `resolved_ips` is always present on allow, `reason` is absent.
    let coredns_line = r#"{"timestamp":"2026-04-22T09:45:00.200Z","layer":"dns","event":"query_allowed","query":"api.example.com","qtype":"A","client_ip":"10.0.0.42","resolved_ips":["93.184.216.34"]}"#;
    append_jsonl_line(&events_dir.join("coredns.jsonl"), coredns_line).await;

    // mitmproxy allowed HTTPS request.  Shape matches
    // `networking/mitmproxy/events.py` -> `emit_request_allowed`:
    // `port` is a bare number, `client_ip` is a string, `reason` is
    // absent on allow.
    let mitm_line = r#"{"timestamp":"2026-04-22T09:45:00.300Z","layer":"mitmproxy","event":"request_allowed","host":"api.example.com","port":443,"method":"GET","path":"/v1/widgets","client_ip":"10.0.0.42"}"#;
    append_jsonl_line(&events_dir.join("mitmproxy.jsonl"), mitm_line).await;

    // Three tailers, three separate files — event arrival order is
    // unordered.  Classify each received event by variant, count the
    // coverage, and assert all three layers were observed exactly once.
    let mut saw_envoy = false;
    let mut saw_dns = false;
    let mut saw_mitm = false;
    for i in 0..3 {
        let ev = next_event(&mut replay, &mut rx, &format!("event #{i}")).await;
        assert_eq!(
            ev.session(),
            Some(&sid),
            "every traffic event must carry the session bound in the vm_ip map; got {ev:?}"
        );
        match &*ev {
            Event::Traffic { envelope, event } => {
                assert_eq!(
                    envelope.session,
                    Some(sid),
                    "envelope.session must match the bound session id"
                );
                match event {
                    TrafficEvent::Envoy(EnvoyEvent::ConnectionAllowed(conn)) => {
                        assert_eq!(conn.dst_port, 443, "envoy dst_port preserved");
                        assert_eq!(
                            conn.matched_chain, "level3_https_p443",
                            "envoy matched_chain preserved"
                        );
                        assert_eq!(
                            conn.connect_authority.as_deref(),
                            Some("api.example.com:443"),
                            "L3 connect_authority preserved"
                        );
                        assert_eq!(
                            conn.src_ip,
                            VM_IP.parse::<Ipv4Addr>().unwrap(),
                            "src_ip flows through"
                        );
                        assert!(!saw_envoy, "duplicate Envoy event");
                        saw_envoy = true;
                    }
                    TrafficEvent::Dns(DnsEvent::QueryAllowed {
                        query,
                        qtype,
                        resolved_ips,
                    }) => {
                        assert_eq!(query, "api.example.com");
                        assert_eq!(qtype, "A");
                        assert_eq!(
                            resolved_ips,
                            &vec!["93.184.216.34".parse::<Ipv4Addr>().unwrap()],
                            "resolved_ips decoded as IPv4"
                        );
                        assert!(!saw_dns, "duplicate DNS event");
                        saw_dns = true;
                    }
                    TrafficEvent::Mitmproxy(MitmproxyEvent::RequestAllowed {
                        host,
                        port,
                        method,
                        path,
                    }) => {
                        assert_eq!(host, "api.example.com");
                        assert_eq!(*port, 443);
                        assert_eq!(method, "GET");
                        assert_eq!(path, "/v1/widgets");
                        assert!(!saw_mitm, "duplicate mitmproxy event");
                        saw_mitm = true;
                    }
                    other => panic!("unexpected traffic event variant: {other:?}"),
                }
            }
            Event::Lifecycle { .. } => {
                panic!("no lifecycle events expected on traffic-only ingest path")
            }
        }
    }
    assert!(
        saw_envoy && saw_dns && saw_mitm,
        "missing layer coverage: envoy={saw_envoy}, dns={saw_dns}, mitm={saw_mitm}"
    );

    ingestor.abort();
}

// ---------------------------------------------------------------------------
// Test 2: lifecycle sequence across start -> apply_policy -> stop
// ---------------------------------------------------------------------------

/// Destructure an [`Event`] as a [`LifecycleEvent`] or panic; shorthand
/// so the `match` ladder below reads linearly instead of nesting two
/// levels of `match` per step.
fn expect_lifecycle(event: &Event) -> &LifecycleEvent {
    match event {
        Event::Lifecycle { event, .. } => event,
        Event::Traffic { .. } => panic!("expected Event::Lifecycle, got Event::Traffic: {event:?}"),
    }
}

/// Build the port-explicit `level: http` policy used by the lifecycle
/// test.  A single rule to a known host at 443 over TCP — this is the
/// smallest well-formed v2 policy that exercises a non-trivial
/// `AssuranceLevel::Http` variant (with one `(GET, /v1/**)` filter).
fn sample_http_policy() -> Policy {
    Policy {
        version: "2.0.0".into(),
        rules: vec![PolicyRule {
            host: Destination::Domain("api.example.com".into()),
            port: 443,
            protocol: Protocol::Tcp,
            reason: Some("fetch api metadata".into()),
            level: AssuranceLevel::Http {
                http_filters: vec![HttpFilter {
                    method: HttpMethod::Get,
                    path: "/v1/**".into(),
                }],
            },
        }],
    }
}

/// Phase 8 exit criterion 5: "lifecycle events visible across
/// `start → apply-policy → stop` cycle."
///
/// Exercises the exact builder + `bus.publish` sequence `sandboxd::main`
/// drives at each emission site (see `setup_session_networking`,
/// `apply_policy` with `ApplyKind::Initial`, and `stop_session`):
///
///   1. `gateway_booting` — published before docker run.
///   2. `gateway_ready`   — published after readiness probe clears.
///   3. `policy_applied`  — published at `ApplyKind::Initial`.  Carries
///      the full policy object, `source_presets`, `status: ok`, no error.
///   4. `gateway_shutdown(SessionStopped)` — published before docker stop
///      on an explicit session-stop.
///
/// The bus snapshot preserves publish order (ring replay), so the test
/// can assert the whole sequence in one drain pass without racing on
/// live receiver wakeups.
///
/// Design decisions pinned by this test (do NOT change the assertions
/// without updating the matching emission-site code in main.rs):
/// - `ApplyKind::Restoration` is deliberately NOT exercised here — the
///   M10-S2 Phase 5 design omits `policy_applied` on restoration so a
///   daemon restart does not re-emit policy events for sessions whose
///   policy was already announced at initial apply.
/// - SIGTERM / daemon teardown does NOT emit `gateway_shutdown`; only
///   an explicit session stop does (reason = `SessionStopped`).  We
///   trigger the explicit path here by publishing the shutdown event
///   directly.
#[tokio::test(flavor = "current_thread")]
async fn lifecycle_sequence_across_create_apply_stop() {
    let bus = EventBus::new(EventBusConfig::default());
    let sid = SessionId::parse("bbbbbbbbbbbb").expect("valid fixture id");
    bus.register_session(sid);

    // Wire up the vm_ip map too so the test exercises the same
    // `create_session`-time binding sandboxd performs before any
    // traffic ingestor spawns.  Not strictly required for lifecycle
    // events (they do not flow through the vm_ip map), but it pins
    // that the binding happens alongside registration.
    let vm_ip_map = VmIpSessionMap::new();
    vm_ip_map.bind(VM_IP.parse::<Ipv4Addr>().unwrap(), sid);
    assert_eq!(
        vm_ip_map.lookup(VM_IP.parse::<Ipv4Addr>().unwrap()),
        Some(sid),
        "vm_ip binding round-trips through the map"
    );

    let policy = sample_http_policy();

    // Step 1 — gateway boot start.  `sandboxd::setup_session_networking`
    // publishes this before `docker run`.
    assert!(
        bus.publish(lifecycle_events::gateway_booting(sid)),
        "booting event must route to the registered session"
    );

    // Step 2 — gateway ready.  `sandboxd::setup_session_networking`
    // publishes this after the readiness probe clears.
    assert!(bus.publish(lifecycle_events::gateway_ready(sid)));

    // Step 3 — initial policy apply.  `sandboxd::apply_policy` with
    // `ApplyKind::Initial` publishes this with the full policy
    // object, the CLI's `--preset` invocation strings, `status: ok`,
    // and no `error`.  The `source_presets` list is a non-empty
    // fixture to pin that the field flows through; an empty Vec is
    // also valid in production (direct API caller, no presets).
    assert!(bus.publish(lifecycle_events::policy_applied(
        sid,
        policy.clone(),
        vec!["cargo".to_string(), "github:api".to_string()],
        PolicyApplyStatus::Ok,
        None,
    )));

    // Step 4 — explicit session stop.  `sandboxd::stop_session`
    // publishes this with `reason = SessionStopped` before the
    // `docker stop` call.  Daemon-wide SIGTERM does NOT emit this
    // event (see Phase 5 design deviation #2).
    assert!(bus.publish(lifecycle_events::gateway_shutdown(
        sid,
        GatewayShutdownReason::SessionStopped,
        None,
    )));

    // Drain the ring buffer.  `subscribe` returns a snapshot in
    // publish order, so the sequence assertion is deterministic and
    // does not depend on live-receiver wakeups.
    let (replay, _rx) = bus.subscribe(&sid).expect("session registered");
    assert_eq!(
        replay.len(),
        4,
        "expected four lifecycle events, got {} ({:?})",
        replay.len(),
        replay
    );

    // Assert each step in order, with per-step field checks on the
    // payloads that sandboxd::main populates.
    match expect_lifecycle(&replay[0]) {
        LifecycleEvent::GatewayBooting => {}
        other => panic!("[0] expected GatewayBooting, got {other:?}"),
    }
    match expect_lifecycle(&replay[1]) {
        LifecycleEvent::GatewayReady => {}
        other => panic!("[1] expected GatewayReady, got {other:?}"),
    }
    match expect_lifecycle(&replay[2]) {
        LifecycleEvent::PolicyApplied {
            policy: p,
            source_presets,
            status,
            error,
        } => {
            assert_eq!(p.version, policy.version, "policy version preserved");
            assert_eq!(
                p.rules.len(),
                policy.rules.len(),
                "policy rule count preserved"
            );
            // Spot-check the rule — this pins the port-explicit shape
            // that M10-S2's V004 migration enforces post-upgrade.
            let rule = &p.rules[0];
            assert_eq!(rule.port, 443);
            assert_eq!(rule.protocol, Protocol::Tcp);
            assert!(
                matches!(rule.level, AssuranceLevel::Http { .. }),
                "level::http preserved"
            );
            assert_eq!(
                source_presets,
                &vec!["cargo".to_string(), "github:api".to_string()],
                "source_presets forwarded from CLI"
            );
            assert_eq!(status, &PolicyApplyStatus::Ok);
            assert!(error.is_none(), "Ok status must not carry an error payload");
        }
        other => panic!("[2] expected PolicyApplied, got {other:?}"),
    }
    match expect_lifecycle(&replay[3]) {
        LifecycleEvent::GatewayShutdown { reason, error } => {
            assert_eq!(
                reason,
                &GatewayShutdownReason::SessionStopped,
                "explicit session stop carries SessionStopped, not DaemonShutdown"
            );
            assert!(
                error.is_none(),
                "SessionStopped shutdown has no error payload"
            );
        }
        other => panic!("[3] expected GatewayShutdown, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Test 3: policy_reset_on_upgrade replay on V004-seeded DB
// ---------------------------------------------------------------------------

/// Seed a fresh sessions.db at the V003 (pre-V004) shape with
/// `sessions_to_seed.len()` v1-tokened policy sessions.
///
/// Returns the path to the seeded DB plus a `Vec<(session_id, rule_count)>`
/// describing what the caller should observe as orphans after
/// `SessionStore::new` runs V004 and sweeps them.  Sessions are seeded
/// with v1-tokened rules that V004 purges unconditionally (protocol
/// values `http` / `https` / `any`, plus bare `tcp` which V004 also
/// drops because no safe port can be invented).  Every seeded session
/// gets `rule_count` rows in `policy_rules` so the two-pass migration
/// snapshot has a real count to preserve.
///
/// Kept local to this test (not moved into a shared helper) because no
/// other test needs to seed a V003-shape DB.  The equivalent seeder in
/// `sandbox-core::store::tests::test_v004_migration_from_v1_seed_db`
/// uses the private `embedded::migrations`; an external integration
/// test has to go through `refinery::embed_migrations!` to populate
/// `refinery_schema_history` correctly.
fn seed_v003_db_with_v1_rules(db_path: &Path, sessions: &[(&str, u32)]) {
    let mut conn = Connection::open(db_path).expect("open raw db");
    conn.pragma_update(None, "foreign_keys", "ON")
        .expect("enable FKs");

    // Apply V001-V003 so the schema + refinery_schema_history match
    // exactly what a pre-upgrade sandboxd left on disk.  Targeting
    // version 3 leaves V004 as the only pending migration when
    // `SessionStore::new` runs later.
    v1_migrations::migrations::runner()
        .set_target(refinery::Target::Version(3))
        .run(&mut conn)
        .expect("apply V001..V003");

    for (session_id, rule_count) in sessions {
        // Insert the session row itself.  `state = 'Stopped'`
        // matches the shape V004 operates on — V004 only touches the
        // policy tables, not `sessions`, so the session rows survive.
        conn.execute(
            "INSERT INTO sessions (id, name, state, config, created_at, updated_at)
             VALUES (?1, NULL, 'Stopped', '{}', '2025-01-01T00:00:00Z', '2025-01-01T00:00:00Z')",
            params![session_id],
        )
        .expect("insert session");

        // Parent policy row.  `version = 1.0.0` is the v1 tag.
        conn.execute(
            "INSERT INTO session_policies (session_id, version) VALUES (?1, '1.0.0')",
            params![session_id],
        )
        .expect("seed session_policies");

        // Seed `rule_count` v1-tokened rules.  Cycle through
        // http/https/any so every seeded session carries at least one
        // of each v1 token V004 is guaranteed to purge — keeps the
        // assertion robust across changes to V004's deletion
        // predicate.
        let v1_tokens = [("http", "http"), ("tls", "https"), ("deny", "any")];
        for i in 0..*rule_count {
            let (level, protocol) = v1_tokens[(i as usize) % v1_tokens.len()];
            conn.execute(
                "INSERT INTO policy_rules
                    (session_id, rule_order, destination_kind, destination_value, level, protocol, reason)
                 VALUES (?1, ?2, 'domain', 'legacy.test', ?3, ?4, 'v1 token')",
                params![session_id, i, level, protocol],
            )
            .expect("seed v1 rule");

            // The `http`-leveled rule also seeds a child filter row,
            // to pin that V004 Step 2 cascades the filter cleanup
            // end-to-end.
            if level == "http" {
                conn.execute(
                    "INSERT INTO policy_rule_http_filters
                        (session_id, rule_order, filter_order, method, path_pattern)
                     VALUES (?1, ?2, 0, 'GET', '/*')",
                    params![session_id, i],
                )
                .expect("seed http filter");
            }
        }
    }
}

/// Phase 8 exit criterion 5 (part 2): "`policy_reset_on_upgrade` on
/// V004-seeded DB."
///
/// End-to-end flow under test:
///
///   1. Seed a pre-V004 sessions.db with N `policy_rules` rows per
///      session, populating `refinery_schema_history` up to V003 so
///      refinery treats V004 as the next pending migration.
///   2. Open the store via `SessionStore::new`, which:
///      - Snapshots pre-V004 rule counts (pass 1: target V003).
///      - Runs V004 (pass 2: unbounded), which deletes all v1 rows.
///      - Sweeps the now-orphaned `session_policies` rows and
///        returns `Vec<OrphanInfo>` with `previous_rule_count`
///        preserved from the pass-1 snapshot.
///   3. Drive the same "publish one event per orphan" loop
///      sandboxd::main runs after the bus is up.  Assert each
///      `policy_reset_on_upgrade` lands on the bus with the correct
///      session id and the correct pre-V004 rule count.
///
/// This is the test that would have caught the pre-Phase-5 bug where
/// `previous_rule_count` was always zero (V004 ran before the
/// snapshot, so every count was read post-purge).  The two-pass
/// migration fix in `SessionStore::new` is what the assertion on
/// `previous_rule_count` really pins.
#[tokio::test(flavor = "current_thread")]
async fn policy_reset_on_upgrade_emitted_for_v004_orphans() {
    let tmp = TempDir::new().expect("tempdir");
    let base_dir: PathBuf = tmp.path().to_path_buf();
    // `SessionStore::new` opens `{base_dir}/sessions.db` — seed the
    // file at that exact path so the store picks it up on open.
    let db_path = base_dir.join("sessions.db");

    // Two sessions with different rule counts, so the `previous_rule_count`
    // assertion cannot accidentally pass with a single fixed value.
    // Session IDs are 12 lowercase hex characters (the `SessionId::parse`
    // contract) so the `main.rs` orphan replay loop can parse them.
    let seed = [
        ("aaaaaaaaaaaa", 3u32), // three v1 rows: http, https, any
        ("bbbbbbbbbbbb", 2u32), // two v1 rows: http, https
    ];
    seed_v003_db_with_v1_rules(&db_path, &seed);

    // Open the store — runs V004 + two-pass snapshot + orphan sweep.
    let (_store, orphans) = SessionStore::new(base_dir.clone()).expect("open store after V004");

    // Sanity: we got exactly two orphan entries back, one per seeded
    // session.  Use a map-by-id so ordering (which V004 does not
    // promise) is not baked into the assertions.
    let orphan_by_sid: std::collections::HashMap<&str, u32> = orphans
        .iter()
        .map(|o| (o.session_id.as_str(), o.previous_rule_count))
        .collect();
    assert_eq!(
        orphan_by_sid.len(),
        seed.len(),
        "orphan count must match seed count; got {orphans:?}"
    );
    for (sid_str, expected_count) in &seed {
        assert_eq!(
            orphan_by_sid.get(sid_str),
            Some(expected_count),
            "previous_rule_count for {sid_str} must match the pre-V004 snapshot"
        );
    }

    // Drive the same bus-publish loop sandboxd::main runs against the
    // orphan list (see `main.rs` line ~3634: register_session +
    // publish(policy_reset_on_upgrade) per orphan).
    let bus = EventBus::new(EventBusConfig::default());
    for orphan in &orphans {
        let sid = SessionId::parse(&orphan.session_id).expect("orphan sid parses");
        bus.register_session(sid);
        assert!(
            bus.publish(lifecycle_events::policy_reset_on_upgrade(
                sid,
                orphan.previous_rule_count as usize,
            )),
            "policy_reset_on_upgrade must route to the just-registered session"
        );
    }

    // Assert each session's sink received exactly one
    // `PolicyResetOnUpgrade` event carrying the matching rule count.
    for (sid_str, expected_count) in &seed {
        let sid = SessionId::parse(sid_str).unwrap();
        let (replay, _rx) = bus
            .subscribe(&sid)
            .unwrap_or_else(|| panic!("session {sid_str} must be registered"));
        assert_eq!(
            replay.len(),
            1,
            "exactly one lifecycle event expected for {sid_str}, got {}",
            replay.len()
        );
        match expect_lifecycle(&replay[0]) {
            LifecycleEvent::PolicyResetOnUpgrade {
                previous_rule_count,
            } => {
                assert_eq!(
                    *previous_rule_count, *expected_count as usize,
                    "previous_rule_count on the bus must match the pre-V004 snapshot for {sid_str}"
                );
            }
            other => panic!("[{sid_str}] expected PolicyResetOnUpgrade, got {other:?}"),
        }
        // Envelope must carry the session for SSE routing.
        assert_eq!(
            replay[0].session(),
            Some(&sid),
            "envelope.session must be stamped with the orphan session id"
        );
    }
}
