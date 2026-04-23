//! Per-session policy-propagation state tracking.
//!
//! The propagation feature answers one question from the CLI, the E2E
//! suite, and operators: *has the policy I just applied reached all
//! three enforcement layers (nftables, Envoy, mitmproxy/CoreDNS) AND
//! has the DNS propagation loop mirrored every `Destination::Domain`
//! rule's resolved IPs into the nftables allow sets?*
//!
//! # State machine
//!
//! Two hashes per session plus a timestamp:
//!
//! * `applied_hash` — set by the policy-apply path the moment
//!   [`sandbox_core::PolicyDistributor::distribute`] returns `Ok`. It
//!   records the content-addressable identity of the latest compiled
//!   policy that has *started* propagating. A fresh apply whose hash
//!   differs from the prior one clears `propagated_hash` back to
//!   `None` — the new policy has not yet reached steady state, so
//!   `propagated` must flip back to `false`.
//!
//! * `propagated_hash` — set by the DNS propagation loop only when
//!   the applied policy has been fully reconciled. "Fully reconciled"
//!   means the loop has (a) at least one complete cycle under the
//!   current `applied_hash`, and (b) the in-memory policy snapshot it
//!   propagated has the same hash as `applied_hash` (i.e. no newer
//!   apply raced ahead while we were reconciling).
//!
//! * `applied_at` — the instant `applied_hash` most recently changed.
//!   The status endpoint exposes `(now - applied_at).as_secs()` as
//!   `seconds_since_apply`, which both the CLI wait loop and the E2E
//!   suite use for timeout accounting.
//!
//! # Transition-only emission
//!
//! The DNS loop calls [`PropagationStates::mark_propagated`] once per
//! cycle. That method returns `true` *only* on the edge where the two
//! hashes become equal after having been unequal — so the
//! [`sandbox_core::events::lifecycle::policy_propagated`] event is
//! emitted at most once per policy-apply, never per cycle. While the
//! policy sits stable, subsequent calls return `false` and the event
//! stream stays quiet. Another apply that changes the hash re-arms the
//! transition by clearing `propagated_hash` inside
//! [`PropagationStates::mark_applied`].
//!
//! # Empty-policy case
//!
//! An empty policy (`rules.is_empty()`) has no `Destination::Domain`
//! rules to resolve. The DNS loop is cancelled entirely in that case
//! (see `clear_session_policy` in the binary), so the reconciliation
//! edge is triggered synchronously from the apply path via
//! [`PropagationStates::mark_propagated`] with the same hash that was
//! just applied. This keeps the "empty policy → propagated" assertion
//! observable to waiters even though no background loop is running.

use std::collections::HashMap;
use std::time::Instant;

use sandbox_core::SessionId;
use tokio::sync::Mutex;

/// Per-session propagation state.
#[derive(Debug, Clone)]
pub struct PropagationState {
    /// Hash of the policy most recently handed to the distributor.
    /// `None` iff no policy has ever been applied to this session.
    pub applied_hash: Option<String>,
    /// Hash of the policy most recently observed to have fully
    /// propagated. `None` until the first reconciliation edge; reset
    /// to `None` whenever `applied_hash` changes.
    pub propagated_hash: Option<String>,
    /// Instant at which `applied_hash` most recently transitioned to
    /// its current value. Used to compute `seconds_since_apply` in the
    /// status endpoint.
    pub applied_at: Instant,
}

impl PropagationState {
    /// `true` when the latest apply has reached steady state.
    pub fn propagated(&self) -> bool {
        match (&self.applied_hash, &self.propagated_hash) {
            (Some(a), Some(p)) => a == p,
            _ => false,
        }
    }
}

/// Async-aware registry keyed by session id.
///
/// The wrapping [`Mutex`] lets the apply path and the DNS loop
/// mutate per-session entries without either blocking the whole
/// daemon. Entries are small (two `Option<String>` + one `Instant`),
/// so holding the lock for the duration of a read-modify-write is
/// negligible compared to the network and docker-exec work the
/// surrounding code performs.
#[derive(Debug, Default)]
pub struct PropagationStates {
    inner: Mutex<HashMap<SessionId, PropagationState>>,
}

/// Outcome of [`PropagationStates::mark_propagated`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PropagatedEdge {
    /// The call moved `propagated_hash` from `!= applied_hash` to
    /// `== applied_hash`. The caller should emit a single
    /// `policy_propagated` lifecycle event.
    Fresh,
    /// The two hashes were already equal on entry — no edge, no
    /// emission. Covers the "loop kept running while the policy
    /// stayed stable" case.
    AlreadyPropagated,
    /// The reconciled hash does not match `applied_hash`. A newer
    /// apply has raced ahead; the loop will catch up on a subsequent
    /// cycle.
    RaceWithNewerApply,
    /// No state exists for this session yet (e.g. a DNS-loop cycle
    /// fires after the session has been cleared). Treated as a no-op.
    Unknown,
}

impl PropagationStates {
    /// Construct an empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record that a compiled policy with the given `hash` has just
    /// been handed to the distributor and succeeded.
    ///
    /// If the hash differs from the previously recorded
    /// `applied_hash`, clears `propagated_hash` and bumps
    /// `applied_at` — the new policy must re-reach steady state
    /// before `propagated` returns `true` again.
    ///
    /// If the hash is identical (e.g. a no-op re-apply), only
    /// `applied_at` is refreshed; `propagated_hash` stays put so a
    /// subsequent `mark_propagated` call does not spuriously edge.
    pub async fn mark_applied(&self, session: SessionId, hash: String) {
        let mut guard = self.inner.lock().await;
        let now = Instant::now();
        match guard.get_mut(&session) {
            Some(state) => {
                let changed = state.applied_hash.as_deref() != Some(hash.as_str());
                state.applied_hash = Some(hash);
                if changed {
                    state.propagated_hash = None;
                    state.applied_at = now;
                }
            }
            None => {
                guard.insert(
                    session,
                    PropagationState {
                        applied_hash: Some(hash),
                        propagated_hash: None,
                        applied_at: now,
                    },
                );
            }
        }
    }

    /// Record that the DNS propagation loop has reconciled a policy
    /// whose hash is `reconciled_hash` and report whether this call
    /// represents the transition edge.
    ///
    /// The caller passes the hash of the policy it *actually*
    /// propagated — not a stale snapshot — so a policy-apply that
    /// raced ahead is detected cleanly:
    /// [`PropagatedEdge::RaceWithNewerApply`] is returned and the
    /// state is left untouched.
    pub async fn mark_propagated(
        &self,
        session: SessionId,
        reconciled_hash: &str,
    ) -> PropagatedEdge {
        let mut guard = self.inner.lock().await;
        let Some(state) = guard.get_mut(&session) else {
            return PropagatedEdge::Unknown;
        };
        let Some(applied) = state.applied_hash.as_deref() else {
            // Never applied anything, yet the loop is claiming it
            // reconciled something — treat as unknown.
            return PropagatedEdge::Unknown;
        };
        if applied != reconciled_hash {
            return PropagatedEdge::RaceWithNewerApply;
        }
        match state.propagated_hash.as_deref() {
            Some(p) if p == applied => PropagatedEdge::AlreadyPropagated,
            _ => {
                state.propagated_hash = Some(applied.to_string());
                PropagatedEdge::Fresh
            }
        }
    }

    /// Snapshot the state for one session. Returns `None` if the
    /// session has never had a policy applied.
    pub async fn get(&self, session: &SessionId) -> Option<PropagationState> {
        self.inner.lock().await.get(session).cloned()
    }

    /// Drop the state for a session. Called when the session is
    /// removed so the map does not grow without bound.
    pub async fn remove(&self, session: &SessionId) {
        self.inner.lock().await.remove(session);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sid(n: u32) -> SessionId {
        // Materialise a 12-char lowercase-hex SessionId from a test
        // index. `SessionId::parse` insists on exactly 12 chars; 8 hex
        // digits from `n` padded on the right gets us there
        // deterministically without pulling in `uuid`.
        let raw = format!("{n:08x}abcd");
        SessionId::parse(&raw).expect("valid session id")
    }

    #[tokio::test]
    async fn mark_applied_initial_sets_hash_and_clears_propagated() {
        let states = PropagationStates::new();
        let s = sid(1);
        states.mark_applied(s, "h1".into()).await;
        let snap = states.get(&s).await.expect("state registered");
        assert_eq!(snap.applied_hash.as_deref(), Some("h1"));
        assert_eq!(snap.propagated_hash, None);
        assert!(!snap.propagated());
    }

    #[tokio::test]
    async fn mark_propagated_fresh_edge_flips_to_true() {
        let states = PropagationStates::new();
        let s = sid(2);
        states.mark_applied(s, "h1".into()).await;
        let edge = states.mark_propagated(s, "h1").await;
        assert_eq!(edge, PropagatedEdge::Fresh);
        let snap = states.get(&s).await.expect("state registered");
        assert!(snap.propagated());
        assert_eq!(snap.propagated_hash.as_deref(), Some("h1"));
    }

    #[tokio::test]
    async fn mark_propagated_second_call_is_already_propagated() {
        let states = PropagationStates::new();
        let s = sid(3);
        states.mark_applied(s, "h1".into()).await;
        let first = states.mark_propagated(s, "h1").await;
        let second = states.mark_propagated(s, "h1").await;
        assert_eq!(first, PropagatedEdge::Fresh);
        assert_eq!(second, PropagatedEdge::AlreadyPropagated);
    }

    #[tokio::test]
    async fn new_apply_clears_propagated_and_re_arms_edge() {
        let states = PropagationStates::new();
        let s = sid(4);
        states.mark_applied(s, "h1".into()).await;
        assert_eq!(states.mark_propagated(s, "h1").await, PropagatedEdge::Fresh);

        // Second apply with a different hash must clear the propagated
        // bit so the next reconciliation edge emits again.
        states.mark_applied(s, "h2".into()).await;
        let snap = states.get(&s).await.expect("state registered");
        assert_eq!(snap.applied_hash.as_deref(), Some("h2"));
        assert_eq!(snap.propagated_hash, None);
        assert!(!snap.propagated());

        assert_eq!(states.mark_propagated(s, "h2").await, PropagatedEdge::Fresh);
    }

    #[tokio::test]
    async fn mark_applied_same_hash_keeps_propagated_bit() {
        let states = PropagationStates::new();
        let s = sid(5);
        states.mark_applied(s, "h1".into()).await;
        assert_eq!(states.mark_propagated(s, "h1").await, PropagatedEdge::Fresh);

        // Identical re-apply — propagated_hash must survive so waiters
        // do not see a transient `propagated=false` window.
        states.mark_applied(s, "h1".into()).await;
        let snap = states.get(&s).await.expect("state registered");
        assert!(snap.propagated());
    }

    #[tokio::test]
    async fn mark_propagated_with_stale_hash_reports_race() {
        let states = PropagationStates::new();
        let s = sid(6);
        states.mark_applied(s, "h1".into()).await;
        // Apply races ahead.
        states.mark_applied(s, "h2".into()).await;
        // Loop tries to mark with the stale hash.
        let edge = states.mark_propagated(s, "h1").await;
        assert_eq!(edge, PropagatedEdge::RaceWithNewerApply);
        let snap = states.get(&s).await.expect("state registered");
        assert!(!snap.propagated());
    }

    #[tokio::test]
    async fn mark_propagated_without_prior_apply_is_unknown() {
        let states = PropagationStates::new();
        let s = sid(7);
        let edge = states.mark_propagated(s, "h1").await;
        assert_eq!(edge, PropagatedEdge::Unknown);
    }

    #[tokio::test]
    async fn remove_drops_entry() {
        let states = PropagationStates::new();
        let s = sid(8);
        states.mark_applied(s, "h1".into()).await;
        states.remove(&s).await;
        assert!(states.get(&s).await.is_none());
    }
}
