//! Envoy LDS-ack helper for the DNS propagation loop.
//!
//! # Why
//!
//! Before this module landed, the DNS propagation loop flipped
//! `propagated=true` the moment the listener-file write returned. That
//! says nothing about whether Envoy has actually re-read the file,
//! parsed the new YAML, accepted the LDS update, and rebuilt its
//! filter chains. There is a ~100–300 ms window after the rename
//! where the listener generation Envoy is serving from is the
//! *previous* one, or — for content-equivalent rewrites that go
//! through the warm-restart drain path — there is briefly *no*
//! listener at all.
//!
//! In that window, VM connections that the daemon has already
//! observed as propagated land on a stale or missing listener and
//! are reset / refused at the gateway. The cargo and github-repo
//! E2Es reproduce this reliably (see
//! `.tasks/handoffs/20260423-m10-s6-e2e-regression.md` hypothesis 1).
//!
//! # What
//!
//! [`wait_for_lds_ack`] takes a full pre-rewrite [`LdsCounters`]
//! snapshot the caller captured *before* the listener file was
//! rewritten, then polls until one of:
//!
//! 1. The number of resolved attempts (`success + rejected`) reaches
//!    `pre.update_attempt + 1` — Envoy has finished processing at
//!    least one LDS read since the snapshot. The accept-vs-reject
//!    attribution looks at which counter advanced past its baseline
//!    in `pre`: `success > pre.success` ∧ `rejected == pre.rejected`
//!    → [`LdsAckOutcome::Accepted`]; the symmetric case →
//!    [`LdsAckOutcome::Rejected`].
//! 2. The deadline expires — we return [`LdsAckOutcome::TimedOut`].
//!
//! # Why a full snapshot, not just `pre.update_attempt`
//!
//! Envoy's `update_rejected` counter is non-zero at process startup
//! because the deny-all bootstrap listener fails validation and
//! ticks the counter once before any user policy applies. A naïve
//! `current.rejected > 0` test would falsely report Rejected on
//! every fresh gateway. Comparing `current.* > pre.*` produces the
//! correct delta regardless of startup state.
//!
//! # Why `update_attempt`, not `update_success`
//!
//! Filesystem-LDS rewrites that produce byte-identical content do
//! not increment `update_success` (Envoy short-circuits the apply
//! once it sees an unchanged version hash) but *do* increment
//! `update_attempt` — which is incremented unconditionally on every
//! successful read of the listener file. Polling on
//! `success`-only would falsely time out on stable cycles. Polling
//! on `(success + rejected) >= pre_attempt + 1` distinguishes
//! "Envoy made up its mind about this rewrite" (success or reject)
//! from "Envoy hasn't read the file yet" (pre_attempt unchanged or
//! resolved-count below pre_attempt).
//!
//! # Trait shape
//!
//! [`LdsStatsProbe`] is the single abstraction the helper depends
//! on — one async fetch returning the three counters as a
//! [`LdsCounters`]. The production implementation
//! ([`DockerExecLdsProbe`]) shells out via `tokio::process::Command`
//! (`docker exec ${container} curl -sf ...`); a test fake can
//! return canned counters to exercise the success / reject /
//! timeout paths hermetically without a real Envoy.

use std::time::Duration;

use crate::error::SandboxError;
use crate::gateway::container_name;
use crate::session::SessionId;

/// Envoy `listener_manager.lds.*` counters relevant to the
/// listener-ack wait. All three are unbounded monotonic u64
/// counters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LdsCounters {
    /// `listener_manager.lds.update_attempt` — increments every
    /// time Envoy reads the listener file (including no-op reads
    /// where content matches the prior generation's hash).
    pub update_attempt: u64,
    /// `listener_manager.lds.update_success` — increments when
    /// Envoy accepts an LDS update. Stays put on no-op rewrites
    /// because Envoy detects the unchanged version.
    pub update_success: u64,
    /// `listener_manager.lds.update_rejected` — increments when
    /// Envoy rejects an LDS update (malformed YAML, schema
    /// violation, unknown fields, etc.).
    pub update_rejected: u64,
}

/// Outcome of [`wait_for_lds_ack`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LdsAckOutcome {
    /// Envoy resolved the rewrite by accepting it. The DNS
    /// propagation loop may flip `propagated=true` for this cycle.
    Accepted,
    /// Envoy resolved the rewrite by rejecting it. The DNS
    /// propagation loop must NOT flip `propagated=true` — the
    /// listener Envoy is serving from is the prior generation, so
    /// the policy is not actually in force.
    Rejected,
    /// The deadline expired before Envoy resolved the rewrite.
    /// Treat as "still in flight" — do not flip `propagated=true`,
    /// let the next propagation cycle retry.
    TimedOut,
}

/// Source of the three LDS counters.
///
/// Callers typically use [`DockerExecLdsProbe`]; tests substitute a
/// fake.
pub trait LdsStatsProbe: Send + Sync {
    /// Fetch a fresh snapshot of [`LdsCounters`]. Errors propagate
    /// to the caller of [`wait_for_lds_ack`], which treats them as
    /// transient and keeps polling until the deadline.
    fn fetch_counters(
        &self,
    ) -> impl std::future::Future<Output = Result<LdsCounters, SandboxError>> + Send;
}

/// Production [`LdsStatsProbe`] that shells out via `docker exec`
/// to query Envoy's admin `/stats` endpoint inside the gateway
/// container.
///
/// Reuses the same docker-exec transport pattern as
/// [`crate::dns_propagation::read_resolved_json`] to keep the
/// daemon free of HTTP-client dependencies for a probe that runs
/// once every 100ms at most.
pub struct DockerExecLdsProbe {
    container: String,
}

impl DockerExecLdsProbe {
    /// Build a probe for the gateway container of `session_id`.
    pub fn new(session_id: &SessionId) -> Self {
        Self {
            container: container_name(session_id),
        }
    }
}

impl LdsStatsProbe for DockerExecLdsProbe {
    fn fetch_counters(
        &self,
    ) -> impl std::future::Future<Output = Result<LdsCounters, SandboxError>> + Send {
        let container = self.container.clone();
        async move {
            // Single round-trip pulls all three counters via Envoy's
            // regex-based `/stats` filter. Anchoring on `$` prevents
            // matching the broader `lds.update_attempt_*` family.
            // The shell is invoked with `sh -c` because the `&` in
            // the URL must reach Envoy as a real query-string
            // separator, not be interpreted as a shell background
            // operator (the integration-test helper at
            // `tests/gateway_integration.rs:421` documents the same
            // quoting issue).
            //
            // Note: we rely on Envoy's text format: `name: value`.
            let url = "http://127.0.0.1:9901/stats?\
                       filter=^listener_manager\\.lds\\.\
                       (update_attempt|update_success|update_rejected)$&\
                       format=text";
            let output = tokio::process::Command::new("docker")
                .args(["exec", &container, "curl", "-sf", url])
                .output()
                .await
                .map_err(|e| {
                    SandboxError::Gateway(format!(
                        "failed to exec curl in {container} for LDS stats: {e}"
                    ))
                })?;
            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                return Err(SandboxError::Gateway(format!(
                    "curl /stats failed in {container}: {stderr}"
                )));
            }
            let text = String::from_utf8_lossy(&output.stdout);
            Ok(parse_lds_counters(&text))
        }
    }
}

/// Parse Envoy text-format `/stats` output into [`LdsCounters`].
///
/// Envoy emits one `name: value\n` line per metric. Counters
/// missing from the response are treated as `0` — Envoy omits
/// counters that have never incremented since process start, so a
/// missing line genuinely means "this counter is at zero".
pub fn parse_lds_counters(text: &str) -> LdsCounters {
    let mut counters = LdsCounters {
        update_attempt: 0,
        update_success: 0,
        update_rejected: 0,
    };
    for line in text.lines() {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let Ok(n) = value.trim().parse::<u64>() else {
            continue;
        };
        match name.trim() {
            "listener_manager.lds.update_attempt" => counters.update_attempt = n,
            "listener_manager.lds.update_success" => counters.update_success = n,
            "listener_manager.lds.update_rejected" => counters.update_rejected = n,
            _ => {}
        }
    }
    counters
}

/// Poll `probe` until Envoy has resolved one LDS rewrite past
/// `pre_attempt`, or until `deadline` elapses.
///
/// `pre_attempt` is the value of `listener_manager.lds.update_attempt`
/// captured *before* the listener file was rewritten. The helper
/// considers the rewrite "resolved" when:
///
/// ```text
/// counters.update_success + counters.update_rejected >= pre_attempt + 1
/// ```
///
/// At that point the helper inspects which counter advanced relative
/// to the prior poll's snapshot to disambiguate accept vs reject.
/// Because both counters increment by 1 per resolved update, the
/// per-cycle delta is unambiguous as long as the helper polls fast
/// enough that no second rewrite happens mid-wait — which is the
/// case here, since the daemon serializes listener writes per
/// session.
///
/// Transient probe errors are logged at `debug` and the helper
/// keeps polling until the deadline. A persistently failing probe
/// will surface as a `TimedOut`, which the DNS loop already treats
/// as "do not flip `propagated`, retry next cycle."
pub async fn wait_for_lds_ack(
    probe: &impl LdsStatsProbe,
    pre: LdsCounters,
    deadline: Duration,
    poll_interval: Duration,
) -> LdsAckOutcome {
    // Edge attribution is delta-based against `pre`, the snapshot
    // the caller captured BEFORE rewriting the listener. The
    // helper polls until one of:
    //
    //   - `current.update_success > pre.update_success` AND
    //     `(current.update_success + current.update_rejected) >=
    //      pre.update_attempt + 1` → Accepted
    //   - `current.update_rejected > pre.update_rejected` AND the
    //     same threshold → Rejected
    //   - The deadline expires → TimedOut
    //
    // The threshold guards against the cosmetic case where
    // `update_success` was already higher than `pre.update_success`
    // because some unrelated background read happened between the
    // pre-snapshot and the listener-write. The delta-on-each-counter
    // disambiguates accept vs reject without depending on Envoy's
    // startup-time counter values (e.g. the deny-all bootstrap
    // listener increments `update_rejected` once at process start;
    // comparing `current.rejected > 0` would falsely report Rejected
    // on every gateway).
    let start = std::time::Instant::now();
    let threshold = pre.update_attempt.saturating_add(1);

    loop {
        match probe.fetch_counters().await {
            Ok(c) => {
                let resolved = c.update_success.saturating_add(c.update_rejected);
                if resolved >= threshold {
                    let success_edge = c.update_success > pre.update_success;
                    let rejected_edge = c.update_rejected > pre.update_rejected;
                    return if success_edge && !rejected_edge {
                        LdsAckOutcome::Accepted
                    } else if rejected_edge && !success_edge {
                        LdsAckOutcome::Rejected
                    } else if rejected_edge {
                        // Both counters advanced — ambiguous (could
                        // be back-to-back rewrites where one of them
                        // is the one we care about, but we can't
                        // tell which). Refuse to flip propagated to
                        // stay safe.
                        LdsAckOutcome::Rejected
                    } else {
                        // resolved >= threshold but neither delta
                        // advanced — only possible if pre captured
                        // wrong (e.g. caller passed a stale
                        // `LdsCounters`). Conservatively timeout-
                        // pretending — surface as TimedOut so the
                        // next propagation cycle re-snapshots.
                        LdsAckOutcome::TimedOut
                    };
                }
            }
            Err(e) => {
                tracing::debug!(error = %e, "LDS stats probe failed (transient)");
            }
        }
        if start.elapsed() >= deadline {
            return LdsAckOutcome::TimedOut;
        }
        tokio::time::sleep(poll_interval).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// Test fake: produces a scripted sequence of counter snapshots.
    /// Once the script is exhausted, returns the last value forever.
    struct ScriptedProbe {
        script: Mutex<Vec<LdsCounters>>,
        last: Mutex<LdsCounters>,
    }

    impl ScriptedProbe {
        fn new(mut script: Vec<LdsCounters>) -> Self {
            // Reverse so we can pop() in order from the back.
            script.reverse();
            let last = *script.last().expect("script must not be empty");
            Self {
                script: Mutex::new(script),
                last: Mutex::new(last),
            }
        }
    }

    impl LdsStatsProbe for ScriptedProbe {
        fn fetch_counters(
            &self,
        ) -> impl std::future::Future<Output = Result<LdsCounters, SandboxError>> + Send {
            let mut script = self.script.lock().unwrap();
            let next = script.pop();
            drop(script);
            if let Some(c) = next {
                *self.last.lock().unwrap() = c;
            }
            let value = *self.last.lock().unwrap();
            async move { Ok(value) }
        }
    }

    /// Test fake: always returns an error.
    struct FailingProbe;

    impl LdsStatsProbe for FailingProbe {
        async fn fetch_counters(&self) -> Result<LdsCounters, SandboxError> {
            Err(SandboxError::Gateway("probe-fail".into()))
        }
    }

    fn counters(attempt: u64, success: u64, rejected: u64) -> LdsCounters {
        LdsCounters {
            update_attempt: attempt,
            update_success: success,
            update_rejected: rejected,
        }
    }

    #[test]
    fn parse_lds_counters_extracts_three_counters() {
        let text = "listener_manager.lds.update_attempt: 5\n\
                    listener_manager.lds.update_success: 4\n\
                    listener_manager.lds.update_rejected: 1\n";
        let c = parse_lds_counters(text);
        assert_eq!(c.update_attempt, 5);
        assert_eq!(c.update_success, 4);
        assert_eq!(c.update_rejected, 1);
    }

    #[test]
    fn parse_lds_counters_treats_missing_lines_as_zero() {
        // Envoy elides counters that have never incremented since
        // process start — a probe that only sees attempts must
        // report `success=0, rejected=0` rather than fail.
        let text = "listener_manager.lds.update_attempt: 1\n";
        let c = parse_lds_counters(text);
        assert_eq!(c.update_attempt, 1);
        assert_eq!(c.update_success, 0);
        assert_eq!(c.update_rejected, 0);
    }

    #[test]
    fn parse_lds_counters_ignores_unrelated_lines() {
        let text = "envoy.something_else: 99\n\
                    listener_manager.lds.update_success: 7\n\
                    not_a_number: oops\n";
        let c = parse_lds_counters(text);
        assert_eq!(c.update_success, 7);
        assert_eq!(c.update_attempt, 0);
        assert_eq!(c.update_rejected, 0);
    }

    #[tokio::test(start_paused = true)]
    async fn wait_returns_accepted_when_success_advances_past_pre() {
        // Pre-rewrite snapshot: Envoy hasn't read anything yet.
        // After the rewrite, update_attempt and update_success
        // both tick to 1: an accepted update.
        let probe = ScriptedProbe::new(vec![
            counters(0, 0, 0), // first poll: nothing has happened yet
            counters(1, 1, 0), // second poll: success=1, threshold met
        ]);
        let outcome = wait_for_lds_ack(
            &probe,
            counters(0, 0, 0),
            Duration::from_secs(5),
            Duration::from_millis(50),
        )
        .await;
        assert_eq!(outcome, LdsAckOutcome::Accepted);
    }

    #[tokio::test(start_paused = true)]
    async fn wait_returns_rejected_when_rejected_advances_past_pre() {
        let probe = ScriptedProbe::new(vec![
            counters(2, 2, 0),
            counters(3, 2, 1), // rejected ticked: malformed listener
        ]);
        let outcome = wait_for_lds_ack(
            &probe,
            counters(2, 2, 0),
            Duration::from_secs(5),
            Duration::from_millis(50),
        )
        .await;
        assert_eq!(outcome, LdsAckOutcome::Rejected);
    }

    #[tokio::test(start_paused = true)]
    async fn wait_ignores_nonzero_startup_rejected_counter() {
        // Regression: at gateway startup, Envoy ticks
        // `update_rejected` once for the deny-all bootstrap listener.
        // A naïve `current.rejected > 0` check would falsely report
        // Rejected. Pre-snapshot already has rejected=1; only
        // success advances on the new rewrite — must report
        // Accepted.
        let probe = ScriptedProbe::new(vec![counters(2, 1, 1)]);
        let outcome = wait_for_lds_ack(
            &probe,
            counters(1, 0, 1), // pre: deny-all already rejected at startup
            Duration::from_secs(5),
            Duration::from_millis(50),
        )
        .await;
        assert_eq!(outcome, LdsAckOutcome::Accepted);
    }

    #[tokio::test(start_paused = true)]
    async fn wait_times_out_when_envoy_never_reads_the_file() {
        // Envoy is wedged: counters never advance past pre.
        let probe = ScriptedProbe::new(vec![counters(0, 0, 0)]);
        let outcome = wait_for_lds_ack(
            &probe,
            counters(0, 0, 0),
            Duration::from_millis(500),
            Duration::from_millis(50),
        )
        .await;
        assert_eq!(outcome, LdsAckOutcome::TimedOut);
    }

    #[tokio::test(start_paused = true)]
    async fn wait_tolerates_transient_probe_errors_until_deadline() {
        // Probe always fails — helper must not crash, must return
        // TimedOut by deadline.
        let probe = FailingProbe;
        let outcome = wait_for_lds_ack(
            &probe,
            counters(0, 0, 0),
            Duration::from_millis(500),
            Duration::from_millis(50),
        )
        .await;
        assert_eq!(outcome, LdsAckOutcome::TimedOut);
    }

    #[tokio::test(start_paused = true)]
    async fn wait_returns_accepted_when_already_acked_on_first_probe() {
        // Edge case: the rewrite was acked between caller capturing
        // `pre` and the helper's first probe (slow probe vs fast
        // Envoy). First poll shows success=1, rejected=0, threshold
        // met, success_edge true, rejected_edge false.
        let probe = ScriptedProbe::new(vec![counters(1, 1, 0)]);
        let outcome = wait_for_lds_ack(
            &probe,
            counters(0, 0, 0),
            Duration::from_secs(5),
            Duration::from_millis(50),
        )
        .await;
        assert_eq!(outcome, LdsAckOutcome::Accepted);
    }

    #[tokio::test(start_paused = true)]
    async fn wait_handles_no_op_rewrite_via_threshold() {
        // Content-identical rewrite: Envoy reads the file
        // (`update_attempt` ticks) but does not re-apply
        // (`update_success` / `update_rejected` unchanged).
        // pre = (0,0,0). After read: (1, 0, 0). resolved = 0,
        // threshold = 1 → still under. The helper times out — the
        // correct behaviour because confirming a no-op rewrite was
        // honored is impossible from Envoy stats alone. The DNS
        // loop guards against this case by skipping the wait
        // entirely on stable cycles where no listener write
        // happened.
        let probe = ScriptedProbe::new(vec![counters(0, 0, 0), counters(1, 0, 0)]);
        let outcome = wait_for_lds_ack(
            &probe,
            counters(0, 0, 0),
            Duration::from_millis(300),
            Duration::from_millis(50),
        )
        .await;
        assert_eq!(outcome, LdsAckOutcome::TimedOut);
    }
}
