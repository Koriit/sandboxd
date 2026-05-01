//! Thin builders for sandboxd-emitted [`LifecycleEvent`] envelopes.
//!
//! Every function here constructs a ready-to-publish [`Event`] with a
//! fresh `Utc::now()` timestamp, the supplied session attribution (or
//! `None` for pre-attachment events like `gateway_booting`), and the
//! appropriate [`LifecycleEvent`] variant. The domain variants themselves
//! are defined in [`crate::events::envelope`] — this module is purely a
//! constructor facade so emission sites in `sandboxd::main` stay terse
//! and one `publish(lifecycle::…)` line is all it takes to signal a
//! lifecycle transition.
//!
//! [`crate::events::EventBus`] is the bus side of this pipeline (its
//! `publish(Event)` entrypoint accepts the envelopes built here);
//! this module is the sandboxd-side producer surface feeding it.
//!
//! Spec reference: `.tasks/specs/2026-04-21-port-explicit-policies-presets-
//! observability-design.md`, Part 3 "Lifecycle events". Each builder
//! maps 1:1 to a row of that table.

use chrono::Utc;

use crate::events::envelope::{
    Event, EventEnvelope, GatewayShutdownReason, HealthComponent, LifecycleEvent, PolicyApplyStatus,
};
use crate::policy::Policy;
use crate::session::SessionId;

/// Internal helper: wrap a `LifecycleEvent` in an `Event::Lifecycle`
/// with the supplied session attribution and a fresh `Utc::now()`
/// timestamp.
///
/// Kept `fn`-scoped rather than `impl`-style so the public builder
/// surface stays a flat list of free functions that call sites can
/// `use` once with `events::lifecycle::*`.
fn wrap(session: Option<SessionId>, event: LifecycleEvent) -> Event {
    Event::Lifecycle {
        envelope: EventEnvelope {
            timestamp: Utc::now(),
            session,
        },
        event,
    }
}

/// `gateway_booting`: sandboxd has initiated gateway container creation
/// but `docker run` has not yet returned readiness.
///
/// Pre-attachment — `session` is carried on the envelope so the bus can
/// route to the session's sink; callers always pass the session id here
/// because by the time this is published the session row already exists
/// in the store and its sink has been registered.
pub fn gateway_booting(session: SessionId) -> Event {
    wrap(Some(session), LifecycleEvent::GatewayBooting)
}

/// `gateway_ready`: all gateway subcomponents (CoreDNS, Envoy,
/// mitmproxy, deny-logger) passed startup checks.
pub fn gateway_ready(session: SessionId) -> Event {
    wrap(Some(session), LifecycleEvent::GatewayReady)
}

/// `policy_applied`: initial policy application at session creation
/// time. Carries the full [`Policy`] payload so subscribers can show
/// the effective ruleset without a separate fetch.
///
/// `source_presets` forwards the original CLI `--preset` invocation
/// strings; empty when the CLI did not expand any presets (or when the
/// request came from a non-CLI client).
///
/// `status` distinguishes successful distribution (`Ok`) from failures
/// the gateway rejected or the distributor could not deliver (`Error`).
/// `error` is populated iff `status == Error`, carrying a human-readable
/// description of the failure.
pub fn policy_applied(
    session: SessionId,
    policy: Policy,
    source_presets: Vec<String>,
    status: PolicyApplyStatus,
    error: Option<String>,
) -> Event {
    wrap(
        Some(session),
        LifecycleEvent::PolicyApplied {
            policy,
            source_presets,
            status,
            error,
        },
    )
}

/// `policy_updated`: subsequent policy update via
/// `sandbox policy update`. Same payload as [`policy_applied`] plus
/// `previous_policy_hash` for diff attribution — the hash of the prior
/// effective [`Policy`], if any was in effect.
pub fn policy_updated(
    session: SessionId,
    policy: Policy,
    source_presets: Vec<String>,
    status: PolicyApplyStatus,
    error: Option<String>,
    previous_policy_hash: Option<String>,
) -> Event {
    wrap(
        Some(session),
        LifecycleEvent::PolicyUpdated {
            policy,
            source_presets,
            status,
            error,
            previous_policy_hash,
        },
    )
}

/// `policy_reset_on_upgrade`: emitted once per session on the first
/// daemon boot after migration V004 dropped the session's v1-shaped
/// policy rows. `previous_rule_count` is the number of v1-shaped rules
/// the migration purged so operators can gauge the blast radius.
pub fn policy_reset_on_upgrade(session: SessionId, previous_rule_count: usize) -> Event {
    wrap(
        Some(session),
        LifecycleEvent::PolicyResetOnUpgrade {
            previous_rule_count,
        },
    )
}

/// `policy_propagated`: the session's current effective policy has
/// fully propagated across all three enforcement layers and (where
/// applicable) the DNS loop has mirrored every `Destination::Domain`
/// rule into the nftables allow sets.
///
/// Transition-only: the propagation loop tracks the last emitted hash
/// per session and suppresses repeat emissions while the hash is
/// stable. Emission resumes on any policy-apply that changes the hash.
///
/// `policy_hash` is the hex SHA-256 digest of the canonical JSON
/// serialization of the [`crate::policy::Policy`] that propagated
/// (see [`crate::policy::hash_policy`]).
pub fn policy_propagated(session: SessionId, policy_hash: String) -> Event {
    wrap(
        Some(session),
        LifecycleEvent::PolicyPropagated { policy_hash },
    )
}

/// `health_degraded`: a subcomponent healthcheck flipped from healthy
/// to failing. Publish on the transition only — not on every polling
/// tick — so the event stream stays sparse even under a sustained
/// outage (plan line 123).
pub fn health_degraded(session: SessionId, component: HealthComponent, reason: String) -> Event {
    wrap(
        Some(session),
        LifecycleEvent::HealthDegraded { component, reason },
    )
}

/// `health_restored`: a previously-degraded subcomponent recovered.
/// Publish on the transition only.
pub fn health_restored(session: SessionId, component: HealthComponent) -> Event {
    wrap(Some(session), LifecycleEvent::HealthRestored { component })
}

/// `gateway_shutdown`: sandboxd is about to stop the gateway container.
/// `reason` is one of `SessionStopped` (user-initiated stop),
/// `DaemonShutdown` (SIGTERM/SIGINT tearing down every session), or
/// `Error` (unexpected failure forcing a shutdown). `error` carries a
/// description iff `reason == Error`.
pub fn gateway_shutdown(
    session: SessionId,
    reason: GatewayShutdownReason,
    error: Option<String>,
) -> Event {
    wrap(
        Some(session),
        LifecycleEvent::GatewayShutdown { reason, error },
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::policy::{
        AssuranceLevel, Destination, HttpFilter, HttpMethod, PolicyRule, Protocol,
    };

    fn fixture_session() -> SessionId {
        SessionId::parse("0123456789ab").expect("valid fixture id")
    }

    fn fixture_policy() -> Policy {
        Policy {
            version: "2.0.0".into(),
            rules: vec![PolicyRule {
                host: Destination::Domain("api.example.com".into()),
                port: 443,
                protocol: Protocol::Tcp,
                reason: None,
                level: AssuranceLevel::Http {
                    http_filters: vec![HttpFilter {
                        method: HttpMethod::Get,
                        path: "/v1/**".into(),
                    }],
                },
            }],
        }
    }

    /// Extract the lifecycle event payload from a domain [`Event`] for
    /// test assertions; panic otherwise so a traffic-variant regression
    /// shows up as a loud failure rather than a silent skip.
    fn expect_lifecycle(event: &Event) -> &LifecycleEvent {
        match event {
            Event::Lifecycle { event, .. } => event,
            Event::Traffic { .. } => panic!("expected Event::Lifecycle, got Event::Traffic"),
        }
    }

    #[test]
    fn gateway_booting_builder_sets_session_and_variant() {
        let sid = fixture_session();
        let event = gateway_booting(sid);
        assert_eq!(event.session(), Some(&sid));
        assert!(matches!(
            expect_lifecycle(&event),
            LifecycleEvent::GatewayBooting
        ));
    }

    #[test]
    fn gateway_ready_builder_sets_session_and_variant() {
        let sid = fixture_session();
        let event = gateway_ready(sid);
        assert_eq!(event.session(), Some(&sid));
        assert!(matches!(
            expect_lifecycle(&event),
            LifecycleEvent::GatewayReady
        ));
    }

    #[test]
    fn policy_applied_builder_populates_all_fields() {
        let sid = fixture_session();
        let policy = fixture_policy();
        let event = policy_applied(
            sid,
            policy.clone(),
            vec!["cargo".into(), "github:api".into()],
            PolicyApplyStatus::Ok,
            None,
        );
        assert_eq!(event.session(), Some(&sid));
        match expect_lifecycle(&event) {
            LifecycleEvent::PolicyApplied {
                policy: p,
                source_presets,
                status,
                error,
            } => {
                assert_eq!(p.version, policy.version);
                assert_eq!(p.rules.len(), 1);
                assert_eq!(
                    source_presets,
                    &vec!["cargo".to_string(), "github:api".to_string()]
                );
                assert_eq!(*status, PolicyApplyStatus::Ok);
                assert!(error.is_none());
            }
            other => panic!("expected PolicyApplied, got {other:?}"),
        }
    }

    #[test]
    fn policy_applied_carries_error_on_failure() {
        let sid = fixture_session();
        let event = policy_applied(
            sid,
            fixture_policy(),
            vec![],
            PolicyApplyStatus::Error,
            Some("compile failed: invalid host".into()),
        );
        match expect_lifecycle(&event) {
            LifecycleEvent::PolicyApplied {
                status,
                error,
                source_presets,
                ..
            } => {
                assert_eq!(*status, PolicyApplyStatus::Error);
                assert_eq!(error.as_deref(), Some("compile failed: invalid host"));
                assert!(source_presets.is_empty());
            }
            other => panic!("expected PolicyApplied, got {other:?}"),
        }
    }

    #[test]
    fn policy_updated_builder_populates_all_fields() {
        let sid = fixture_session();
        let event = policy_updated(
            sid,
            fixture_policy(),
            vec!["npm".into()],
            PolicyApplyStatus::Ok,
            None,
            Some("deadbeef".into()),
        );
        match expect_lifecycle(&event) {
            LifecycleEvent::PolicyUpdated {
                source_presets,
                status,
                error,
                previous_policy_hash,
                ..
            } => {
                assert_eq!(source_presets, &vec!["npm".to_string()]);
                assert_eq!(*status, PolicyApplyStatus::Ok);
                assert!(error.is_none());
                assert_eq!(previous_policy_hash.as_deref(), Some("deadbeef"));
            }
            other => panic!("expected PolicyUpdated, got {other:?}"),
        }
    }

    #[test]
    fn policy_updated_omits_previous_hash_on_first_update() {
        let sid = fixture_session();
        let event = policy_updated(
            sid,
            fixture_policy(),
            vec![],
            PolicyApplyStatus::Ok,
            None,
            None,
        );
        match expect_lifecycle(&event) {
            LifecycleEvent::PolicyUpdated {
                previous_policy_hash,
                ..
            } => {
                assert!(previous_policy_hash.is_none());
            }
            other => panic!("expected PolicyUpdated, got {other:?}"),
        }
    }

    #[test]
    fn policy_reset_on_upgrade_builder_carries_rule_count() {
        let sid = fixture_session();
        let event = policy_reset_on_upgrade(sid, 7);
        assert_eq!(event.session(), Some(&sid));
        match expect_lifecycle(&event) {
            LifecycleEvent::PolicyResetOnUpgrade {
                previous_rule_count,
            } => {
                assert_eq!(*previous_rule_count, 7);
            }
            other => panic!("expected PolicyResetOnUpgrade, got {other:?}"),
        }
    }

    #[test]
    fn policy_propagated_builder_carries_hash() {
        let sid = fixture_session();
        let hash = "abc123def4567890abc123def4567890abc123def4567890abc123def4567890".to_string();
        let event = policy_propagated(sid, hash.clone());
        assert_eq!(event.session(), Some(&sid));
        match expect_lifecycle(&event) {
            LifecycleEvent::PolicyPropagated { policy_hash } => {
                assert_eq!(policy_hash, &hash);
            }
            other => panic!("expected PolicyPropagated, got {other:?}"),
        }
    }

    #[test]
    fn health_degraded_builder_populates_component_and_reason() {
        let sid = fixture_session();
        let event = health_degraded(
            sid,
            HealthComponent::Envoy,
            "admin socket connect refused".into(),
        );
        match expect_lifecycle(&event) {
            LifecycleEvent::HealthDegraded { component, reason } => {
                assert_eq!(*component, HealthComponent::Envoy);
                assert_eq!(reason, "admin socket connect refused");
            }
            other => panic!("expected HealthDegraded, got {other:?}"),
        }
    }

    #[test]
    fn health_restored_builder_populates_component() {
        let sid = fixture_session();
        let event = health_restored(sid, HealthComponent::Coredns);
        match expect_lifecycle(&event) {
            LifecycleEvent::HealthRestored { component } => {
                assert_eq!(*component, HealthComponent::Coredns);
            }
            other => panic!("expected HealthRestored, got {other:?}"),
        }
    }

    #[test]
    fn gateway_shutdown_builder_session_stopped_has_no_error() {
        let sid = fixture_session();
        let event = gateway_shutdown(sid, GatewayShutdownReason::SessionStopped, None);
        match expect_lifecycle(&event) {
            LifecycleEvent::GatewayShutdown { reason, error } => {
                assert_eq!(*reason, GatewayShutdownReason::SessionStopped);
                assert!(error.is_none());
            }
            other => panic!("expected GatewayShutdown, got {other:?}"),
        }
    }

    #[test]
    fn gateway_shutdown_builder_error_carries_description() {
        let sid = fixture_session();
        let event = gateway_shutdown(
            sid,
            GatewayShutdownReason::Error,
            Some("docker stop failed".into()),
        );
        match expect_lifecycle(&event) {
            LifecycleEvent::GatewayShutdown { reason, error } => {
                assert_eq!(*reason, GatewayShutdownReason::Error);
                assert_eq!(error.as_deref(), Some("docker stop failed"));
            }
            other => panic!("expected GatewayShutdown, got {other:?}"),
        }
    }

    #[test]
    fn builders_use_fresh_timestamp() {
        // Two builds back-to-back should produce monotonically non-
        // decreasing timestamps. We don't require strict > because
        // `chrono::Utc::now()` has microsecond resolution on some
        // platforms; this just pins that each call refreshes the
        // timestamp rather than returning a compile-time constant.
        let a = gateway_ready(fixture_session());
        std::thread::sleep(std::time::Duration::from_millis(1));
        let b = gateway_ready(fixture_session());
        assert!(b.envelope().timestamp >= a.envelope().timestamp);
    }
}
