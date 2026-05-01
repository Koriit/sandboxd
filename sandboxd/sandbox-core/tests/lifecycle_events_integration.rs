//! End-to-end sequencing test for the sandboxd-emitted lifecycle
//! events.
//!
//! This test exercises the wiring between the lifecycle builder
//! surface (`events::lifecycle::*`) and the `EventBus` fan-out — the
//! same path `sandboxd::main` uses at every emission site. A real
//! gateway and daemon are out of scope here (covered by
//! `tests/e2e/test_m10_*` at the Python suite level); instead this
//! test publishes the expected event *sequence* for a session and
//! asserts the subscriber sees the exact sequence via
//! `EventBus::subscribe`.
//!
//! The contract we're pinning:
//!
//!   `gateway_booting → gateway_ready → policy_applied → gateway_shutdown`
//!
//! matches the happy-path emission order at the create/apply/stop
//! sites in `sandboxd::main`. Any reordering or missing event here is
//! a regression in the emission-site changes made during Phase 5.

use sandbox_core::events::lifecycle;
use sandbox_core::policy::{AssuranceLevel, Destination, Policy, PolicyRule, Protocol};
use sandbox_core::{
    Event, EventBus, EventBusConfig, GatewayShutdownReason, HealthComponent, LifecycleEvent,
    PolicyApplyStatus, SessionId,
};

/// Destructure a domain [`Event`] as a [`LifecycleEvent`] or panic —
/// test shorthand so assertion failures point directly at the variant
/// rather than a tuple-pattern mismatch two lines away.
fn expect_lifecycle(event: &Event) -> &LifecycleEvent {
    match event {
        Event::Lifecycle { event, .. } => event,
        Event::Traffic { .. } => panic!("expected Event::Lifecycle, got Event::Traffic: {event:?}"),
    }
}

fn sample_policy() -> Policy {
    Policy {
        version: "2.0.0".into(),
        rules: vec![PolicyRule {
            host: Destination::Domain("api.example.com".into()),
            port: 443,
            protocol: Protocol::Tcp,
            reason: None,
            level: AssuranceLevel::Transport,
        }],
    }
}

/// Happy-path sequence a `create_session(policy=Some(...)) → stop_session`
/// flow produces on the bus.  Asserts both the **order** (ring replay
/// preserves publish order) and the **variant content** at each step.
#[tokio::test(flavor = "current_thread")]
async fn lifecycle_events_happy_path_sequence() {
    let bus = EventBus::new(EventBusConfig::default());
    let sid = SessionId::parse("aaaaaaaaaaaa").expect("valid fixture id");
    bus.register_session(sid);

    let policy = sample_policy();

    // Emission order mirrors sandboxd::main:
    //   1. setup_session_networking — publish(gateway_booting) before
    //      docker run, publish(gateway_ready) after readiness.
    //   2. create_session — apply_policy(ApplyKind::Initial) publishes
    //      policy_applied.
    //   3. stop_session — publish(gateway_shutdown(SessionStopped))
    //      before the docker stop call.
    assert!(bus.publish(lifecycle::gateway_booting(sid)));
    assert!(bus.publish(lifecycle::gateway_ready(sid)));
    assert!(bus.publish(lifecycle::policy_applied(
        sid,
        policy.clone(),
        vec!["cargo".into()],
        PolicyApplyStatus::Ok,
        None,
    )));
    assert!(bus.publish(lifecycle::gateway_shutdown(
        sid,
        GatewayShutdownReason::SessionStopped,
        None,
    )));

    let (replay, _rx) = bus.subscribe(&sid).expect("session must be registered");
    assert_eq!(
        replay.len(),
        4,
        "expected four lifecycle events in the ring; got {}",
        replay.len()
    );

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
            assert_eq!(p.version, policy.version);
            assert_eq!(p.rules.len(), policy.rules.len());
            assert_eq!(source_presets, &vec!["cargo".to_string()]);
            assert_eq!(status, &PolicyApplyStatus::Ok);
            assert!(error.is_none(), "Ok status must not carry an error");
        }
        other => panic!("[2] expected PolicyApplied, got {other:?}"),
    }
    match expect_lifecycle(&replay[3]) {
        LifecycleEvent::GatewayShutdown { reason, error } => {
            assert_eq!(reason, &GatewayShutdownReason::SessionStopped);
            assert!(
                error.is_none(),
                "session-initiated shutdown has no error payload"
            );
        }
        other => panic!("[3] expected GatewayShutdown, got {other:?}"),
    }
}

/// A policy apply that fails still produces a `policy_applied` event —
/// subscribers need this to alert on misapplied policies without
/// polling the sandboxd log.  Mirrors the `apply_policy` /
/// `apply_policy_inner` split in sandboxd::main, which emits the
/// event with `status = Error` when the inner `Result` is `Err`.
#[tokio::test(flavor = "current_thread")]
async fn policy_applied_error_variant_preserved_on_bus() {
    let bus = EventBus::new(EventBusConfig::default());
    let sid = SessionId::parse("bbbbbbbbbbbb").expect("valid fixture id");
    bus.register_session(sid);

    let policy = sample_policy();

    assert!(bus.publish(lifecycle::policy_applied(
        sid,
        policy.clone(),
        vec![],
        PolicyApplyStatus::Error,
        Some("nftables injection failed: EPERM".into()),
    )));

    let (replay, _rx) = bus.subscribe(&sid).expect("session must be registered");
    assert_eq!(replay.len(), 1);
    match expect_lifecycle(&replay[0]) {
        LifecycleEvent::PolicyApplied {
            status,
            error,
            source_presets,
            ..
        } => {
            assert_eq!(status, &PolicyApplyStatus::Error);
            assert_eq!(
                error.as_deref(),
                Some("nftables injection failed: EPERM"),
                "Error status must carry the failure message"
            );
            assert!(source_presets.is_empty());
        }
        other => panic!("expected PolicyApplied, got {other:?}"),
    }
}

/// `policy_updated` publishes with `previous_policy_hash` populated —
/// the sandboxd-side helper that computes the sha256 of the prior
/// policy's JSON lives in `sandboxd::main`, but the bus contract is
/// that the hash flows through untouched.  Covers the
/// `Some`-previous-policy path exercised by `update_policy`.
#[tokio::test(flavor = "current_thread")]
async fn policy_updated_carries_previous_hash() {
    let bus = EventBus::new(EventBusConfig::default());
    let sid = SessionId::parse("cccccccccccc").expect("valid fixture id");
    bus.register_session(sid);

    let policy = sample_policy();
    let prior_hash = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    assert!(bus.publish(lifecycle::policy_updated(
        sid,
        policy.clone(),
        vec!["npm".into(), "github:api".into()],
        PolicyApplyStatus::Ok,
        None,
        Some(prior_hash.to_string()),
    )));

    let (replay, _rx) = bus.subscribe(&sid).expect("session must be registered");
    assert_eq!(replay.len(), 1);
    match expect_lifecycle(&replay[0]) {
        LifecycleEvent::PolicyUpdated {
            policy: p,
            source_presets,
            status,
            error,
            previous_policy_hash,
        } => {
            assert_eq!(p.version, policy.version);
            assert_eq!(
                source_presets,
                &vec!["npm".to_string(), "github:api".to_string()],
            );
            assert_eq!(status, &PolicyApplyStatus::Ok);
            assert!(error.is_none());
            assert_eq!(previous_policy_hash.as_deref(), Some(prior_hash));
        }
        other => panic!("expected PolicyUpdated, got {other:?}"),
    }
}

/// `health_degraded` / `health_restored` transitions are only emitted
/// on state flips by sandboxd's `poll_and_emit_component_health`, but
/// the bus-level contract is that each flip is a standalone event
/// carrying its component identity.  Verifies both variants round-trip
/// through `publish` / `subscribe`.
#[tokio::test(flavor = "current_thread")]
async fn health_degraded_then_restored_round_trip_on_bus() {
    let bus = EventBus::new(EventBusConfig::default());
    let sid = SessionId::parse("dddddddddddd").expect("valid fixture id");
    bus.register_session(sid);

    assert!(bus.publish(lifecycle::health_degraded(
        sid,
        HealthComponent::Envoy,
        "healthcheck returned exit status 7".into(),
    )));
    assert!(bus.publish(lifecycle::health_restored(sid, HealthComponent::Envoy,)));

    let (replay, _rx) = bus.subscribe(&sid).expect("session must be registered");
    assert_eq!(replay.len(), 2);
    match expect_lifecycle(&replay[0]) {
        LifecycleEvent::HealthDegraded { component, reason } => {
            assert_eq!(component, &HealthComponent::Envoy);
            assert_eq!(reason, "healthcheck returned exit status 7");
        }
        other => panic!("[0] expected HealthDegraded, got {other:?}"),
    }
    match expect_lifecycle(&replay[1]) {
        LifecycleEvent::HealthRestored { component } => {
            assert_eq!(component, &HealthComponent::Envoy);
        }
        other => panic!("[1] expected HealthRestored, got {other:?}"),
    }
}

/// `policy_reset_on_upgrade` flows through the bus with the pre-V004
/// rule count preserved.  Matches the startup replay loop in
/// `sandboxd::main` that iterates `SessionStore::new`'s returned
/// orphan list.
#[tokio::test(flavor = "current_thread")]
async fn policy_reset_on_upgrade_carries_rule_count() {
    let bus = EventBus::new(EventBusConfig::default());
    let sid = SessionId::parse("eeeeeeeeeeee").expect("valid fixture id");
    bus.register_session(sid);

    assert!(bus.publish(lifecycle::policy_reset_on_upgrade(sid, 7)));

    let (replay, _rx) = bus.subscribe(&sid).expect("session must be registered");
    assert_eq!(replay.len(), 1);
    match expect_lifecycle(&replay[0]) {
        LifecycleEvent::PolicyResetOnUpgrade {
            previous_rule_count,
        } => {
            assert_eq!(*previous_rule_count, 7);
        }
        other => panic!("expected PolicyResetOnUpgrade, got {other:?}"),
    }
}

/// Publishing an event for an unregistered session is a silent no-op —
/// `publish` returns false and nothing ends up on a sink.  This is the
/// semantics sandboxd relies on so a racy teardown between "session
/// unregistered" and "emitter publishes" doesn't surface an error.
#[tokio::test(flavor = "current_thread")]
async fn publishing_for_unregistered_session_is_a_noop() {
    let bus = EventBus::new(EventBusConfig::default());
    let sid = SessionId::parse("ffffffffffff").expect("valid fixture id");
    // Deliberately skip register_session.

    assert!(!bus.publish(lifecycle::gateway_booting(sid)));
    assert!(bus.subscribe(&sid).is_none());
}
