//! Pure transition-detection for component health polling.
//!
//! `sandboxd`'s gateway monitor polls each entry in `MONITORED_COMPONENTS`
//! once per tick, compares the result against the per-session "last
//! observed health" snapshot, and emits a `health_degraded` /
//! `health_restored` lifecycle event on a real transition. The polling +
//! emission glue stays in `sandboxd::main::poll_and_emit_component_health`
//! (it is `async` and shells out via `spawn_blocking`); the *pure*
//! transition-detection step lives here so integration tests can import
//! the same logic instead of re-implementing it.
//!
//! Spec reference: `2026-04-21-port-explicit-policies-presets-
//! observability-design.md`, Part 3 / "Lifecycle events" — only emit on
//! actual flips so the event stream stays sparse under sustained outage.
//!
//! ## Why a separate module
//!
//! Before this module existed, `gateway_deny_pipeline.rs::
//! integration_killing_deny_logger_emits_health_degraded_then_restored`
//! re-implemented ~150 lines of monitor-loop transition-detection inline
//! to assert against an accelerated 500ms cadence. Two parallel
//! implementations created double-maintenance risk: any change to the
//! production monitor (extra component, transition predicate, etc.) had
//! to be mirrored in the test. Extracting the transition core lets both
//! call sites converge on one definition.

use std::collections::HashMap;

use crate::events::envelope::HealthComponent;

/// Sentinel string that [`detect_health_transition`] treats as healthy.
///
/// `GatewayManager::component_health` returns either `"healthy"` or a
/// failure string (e.g. `"unhealthy"`, `"unknown"`); we anchor the
/// healthy verdict to a constant so the test stand-in agrees with
/// production on the exact spelling.
pub const HEALTHY: &str = "healthy";

/// A health-state flip detected by [`detect_health_transition`].
///
/// Maps 1:1 to the `health_degraded` / `health_restored` lifecycle
/// builders in [`crate::events::lifecycle`] — the caller turns each
/// transition into an event via [`crate::events::lifecycle::health_degraded`]
/// or [`crate::events::lifecycle::health_restored`] and publishes onto
/// the bus.
///
/// We deliberately do NOT construct the `Event` here so this module
/// stays free of session-id and timestamp concerns: the caller owns
/// session attribution, and surfacing a struct (rather than an `Event`)
/// keeps the helper testable without an `EventBus` fixture.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HealthTransition {
    /// Component flipped from healthy → unhealthy, or was first
    /// observed in the unhealthy state. `reason` is a human-readable
    /// snippet derived from the raw probe verdict.
    Degraded {
        component: HealthComponent,
        reason: String,
    },
    /// Component flipped from unhealthy → healthy. There is no
    /// per-component reason field because the recovery is the signal.
    Restored { component: HealthComponent },
}

/// Detect whether a single per-component poll constitutes a transition,
/// and update the snapshot in place.
///
/// `last_healthy` is the caller's per-session "last observed" map —
/// keyed on [`HealthComponent`], with `true` meaning the previous tick
/// saw the component healthy. Absence of an entry means "first
/// observation" — which differs from "previously seen healthy" only in
/// that an initial unhealthy poll emits `Degraded` (the alert we want)
/// while an initial healthy poll silently seeds the map (avoiding a
/// noisy `Restored` event at startup).
///
/// Returns `Some(HealthTransition)` iff a real flip happened;
/// `None` otherwise (steady-state healthy or steady-state unhealthy).
///
/// The function is pure modulo `last_healthy` — it never reads or
/// writes any other state, never blocks, and never panics.
pub fn detect_health_transition(
    last_healthy: &mut HashMap<HealthComponent, bool>,
    component: HealthComponent,
    health: &str,
) -> Option<HealthTransition> {
    // Treat any non-`"healthy"` string (including `"unhealthy"`,
    // `"unknown"`, or an error message) as unhealthy. The probe layer
    // already normalises these; we just consume the verdict.
    let is_healthy = health == HEALTHY;
    let previous = last_healthy.get(&component).copied();

    match (previous, is_healthy) {
        // First observation of a healthy component — seed the map but
        // do NOT emit. Emitting `Restored` on first poll would be
        // noise for every fresh session.
        (None, true) => {
            last_healthy.insert(component, true);
            None
        }
        // First observation of an unhealthy component — record AND
        // emit. Subscribers get the alert immediately rather than
        // having to wait for a subsequent flip.
        (None, false) => {
            last_healthy.insert(component, false);
            Some(HealthTransition::Degraded {
                component,
                reason: format!("component reported {health} on first poll"),
            })
        }
        // healthy → unhealthy: the canonical degradation transition.
        (Some(true), false) => {
            last_healthy.insert(component, false);
            Some(HealthTransition::Degraded {
                component,
                reason: format!("component reported {health}"),
            })
        }
        // unhealthy → healthy: recovery.
        (Some(false), true) => {
            last_healthy.insert(component, true);
            Some(HealthTransition::Restored { component })
        }
        // Steady state in either direction — no transition.
        (Some(true), true) | (Some(false), false) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_healthy_poll_seeds_without_emitting() {
        let mut last = HashMap::new();
        let t = detect_health_transition(&mut last, HealthComponent::Envoy, HEALTHY);
        assert_eq!(t, None);
        assert_eq!(last.get(&HealthComponent::Envoy), Some(&true));
    }

    #[test]
    fn first_unhealthy_poll_emits_degraded_with_first_poll_reason() {
        let mut last = HashMap::new();
        let t = detect_health_transition(&mut last, HealthComponent::Envoy, "unhealthy");
        match t {
            Some(HealthTransition::Degraded { component, reason }) => {
                assert_eq!(component, HealthComponent::Envoy);
                assert!(
                    reason.contains("on first poll"),
                    "first-poll degradation must mark the reason as a first poll: {reason}"
                );
                assert!(reason.contains("unhealthy"));
            }
            other => panic!("expected Degraded on first unhealthy poll, got {other:?}"),
        }
        assert_eq!(last.get(&HealthComponent::Envoy), Some(&false));
    }

    #[test]
    fn healthy_to_unhealthy_emits_degraded_without_first_poll_marker() {
        let mut last = HashMap::new();
        last.insert(HealthComponent::Coredns, true);
        let t = detect_health_transition(&mut last, HealthComponent::Coredns, "unhealthy");
        match t {
            Some(HealthTransition::Degraded { component, reason }) => {
                assert_eq!(component, HealthComponent::Coredns);
                assert!(
                    !reason.contains("on first poll"),
                    "post-seed degradation must NOT carry the first-poll marker: {reason}"
                );
                assert!(reason.contains("unhealthy"));
            }
            other => panic!("expected Degraded on healthy→unhealthy, got {other:?}"),
        }
        assert_eq!(last.get(&HealthComponent::Coredns), Some(&false));
    }

    #[test]
    fn unhealthy_to_healthy_emits_restored() {
        let mut last = HashMap::new();
        last.insert(HealthComponent::DenyLogger, false);
        let t = detect_health_transition(&mut last, HealthComponent::DenyLogger, HEALTHY);
        match t {
            Some(HealthTransition::Restored { component }) => {
                assert_eq!(component, HealthComponent::DenyLogger);
            }
            other => panic!("expected Restored on unhealthy→healthy, got {other:?}"),
        }
        assert_eq!(last.get(&HealthComponent::DenyLogger), Some(&true));
    }

    #[test]
    fn steady_healthy_emits_nothing() {
        let mut last = HashMap::new();
        last.insert(HealthComponent::Mitmproxy, true);
        let t = detect_health_transition(&mut last, HealthComponent::Mitmproxy, HEALTHY);
        assert_eq!(t, None);
        assert_eq!(last.get(&HealthComponent::Mitmproxy), Some(&true));
    }

    #[test]
    fn steady_unhealthy_emits_nothing() {
        let mut last = HashMap::new();
        last.insert(HealthComponent::Mitmproxy, false);
        let t = detect_health_transition(&mut last, HealthComponent::Mitmproxy, "unknown");
        assert_eq!(t, None);
        assert_eq!(last.get(&HealthComponent::Mitmproxy), Some(&false));
    }

    /// "unknown" is treated as unhealthy — a probe that cannot reach
    /// the component should alert subscribers, not silently pass.
    #[test]
    fn unknown_verdict_treated_as_unhealthy() {
        let mut last = HashMap::new();
        last.insert(HealthComponent::Envoy, true);
        let t = detect_health_transition(&mut last, HealthComponent::Envoy, "unknown");
        assert!(matches!(t, Some(HealthTransition::Degraded { .. })));
        assert_eq!(last.get(&HealthComponent::Envoy), Some(&false));
    }
}
