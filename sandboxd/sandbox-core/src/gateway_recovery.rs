//! Gateway Lima instance crash-recovery orchestrator.
//!
//! Provides the state-machine logic for the Degraded → Recovering → Healthy
//! networking-status transitions behind injectable dependencies so the
//! orchestration can be covered by hermetic unit tests without Docker, Lima,
//! or nft.
//!
//! # Pieces
//!
//! - [`GatewayRecoveringGuard`] — RAII latch guard; clears `gateway_recovering`
//!   on drop so all return paths (including panics) release the latch.
//! - [`sessions_to_recover`] — pure filter: which sessions a gateway-Lima
//!   recovery must re-create (Running + Lima backend only).
//! - [`run_bounded_recovery`] — bounded-concurrency fill/drain loop with
//!   injected prepare / on_complete / on_join_error callbacks.
//! - [`GatewayRecoveryDeps`] — trait for the store operations needed by the
//!   orchestrator (list sessions, get network info, mark session Error).
//! - [`run_gateway_recovery`] — full state-machine orchestrator; manages the
//!   networking-status map transitions from Degraded through Recovering to Healthy.

use std::collections::HashMap;
use std::future::Future;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;

use tokio::task::JoinSet;
use tracing::{error, info, warn};

use crate::api::NetworkingStatus;
use crate::error::SandboxError;
use crate::network::NetworkInfo;
use crate::session::{Session, SessionId, SessionState};
use crate::store::SessionStore;

// ---------------------------------------------------------------------------
// GatewayRecoveringGuard
// ---------------------------------------------------------------------------

/// RAII guard that clears `gateway_recovering` on drop.
///
/// Used by `recover_gateway_lima` so that the latch is released on all return
/// paths, including early returns and async cancellation (tokio drop). Defined
/// at module scope so the `Drop` impl's `fn drop` is not mistaken for an
/// enclosing function by the `update_state_reconcile` allow-list scanner.
///
/// Not `#[cfg]`-gated: the guard carries no macOS-only types and staying
/// platform-independent lets the release-on-all-paths behaviour be unit-tested
/// on any host.
pub struct GatewayRecoveringGuard(Arc<AtomicBool>);

impl GatewayRecoveringGuard {
    /// Set the latch and return the guard whose `Drop` clears it. Ties the
    /// set-on-entry / clear-on-exit pair together at one call site so the two
    /// halves of the latch lifecycle cannot drift.
    pub fn engage(latch: &Arc<AtomicBool>) -> Self {
        latch.store(true, std::sync::atomic::Ordering::SeqCst);
        Self(Arc::clone(latch))
    }
}

impl Drop for GatewayRecoveringGuard {
    fn drop(&mut self) {
        self.0.store(false, std::sync::atomic::Ordering::SeqCst);
    }
}

// ---------------------------------------------------------------------------
// sessions_to_recover
// ---------------------------------------------------------------------------

/// Select the sessions that a gateway-Lima recovery must re-create.
///
/// Pure filter over an unfiltered session snapshot: a session qualifies iff it
/// is `Running` **and** backed by Lima. Extracted from `recover_gateway_lima`
/// so the selection contract (which rows recovery touches) is unit-testable
/// without a store, a daemon, or a running gateway.
pub fn sessions_to_recover(all: Vec<Session>) -> Vec<Session> {
    use crate::backend::BackendKind;
    all.into_iter()
        .filter(|s| s.state == SessionState::Running && s.backend == BackendKind::Lima)
        .collect()
}

// ---------------------------------------------------------------------------
// run_bounded_recovery
// ---------------------------------------------------------------------------

/// Drive at most `max_concurrent` per-session recovery tasks concurrently,
/// preserving the exact fill/drain control flow of `recover_gateway_lima`.
///
/// This is the bounded-fill concurrency loop lifted out of the orchestrator
/// with its two effectful edges injected so they can be faked in tests:
///
/// - `prepare(session) -> Option<Future>`: async per-session preparation. It
///   performs the "tag Recovering / fetch network info / build inputs" work and
///   returns `Some(fut)` to enqueue an in-flight recovery task, or `None` to
///   skip this session without spawning (the production "no network info →
///   mark Error, continue" path). Returning `None` is the seam's equivalent of
///   the original `continue` inside the fill loop.
/// - `on_complete(outcome)`: async handler run for each task that finishes
///   normally (the drain-side "remove map entry / mark Error" work).
/// - `on_join_error(err)`: handler for a `JoinSet` join error (the spawned
///   async task itself panicked). Mirrors the original's log-and-continue arm.
///
/// The loop invariants preserved verbatim from the original:
///   * never more than `max_concurrent` tasks in flight (the fill `while` gate);
///   * every session is offered to `prepare` exactly once, in order;
///   * one task's outcome never aborts the others (drain handles each in turn);
///   * the loop exits only once the input is exhausted **and** no task remains.
///
/// Generic and platform-independent so the cap, ordering, and partial-failure
/// isolation can be asserted hermetically with an injected fake.
pub async fn run_bounded_recovery<S, PrepFut, TaskFut, R, CompleteFut>(
    sessions: Vec<S>,
    max_concurrent: usize,
    mut prepare: impl FnMut(S) -> PrepFut,
    mut on_complete: impl FnMut(R) -> CompleteFut,
    mut on_join_error: impl FnMut(tokio::task::JoinError),
) where
    PrepFut: Future<Output = Option<TaskFut>>,
    TaskFut: Future<Output = R> + Send + 'static,
    R: Send + 'static,
    CompleteFut: Future<Output = ()>,
{
    let mut join_set: JoinSet<R> = JoinSet::new();
    let mut session_iter = sessions.into_iter().peekable();

    loop {
        // Fill the JoinSet up to the concurrency cap.
        while join_set.len() < max_concurrent {
            let session = match session_iter.next() {
                Some(s) => s,
                None => break,
            };
            match prepare(session).await {
                Some(fut) => {
                    join_set.spawn(fut);
                }
                // Skipped session (e.g. missing network info): no task spawned,
                // just move on to the next candidate.
                None => continue,
            }
        }

        // Wait for any in-flight task to complete.
        match join_set.join_next().await {
            Some(Ok(outcome)) => {
                on_complete(outcome).await;
            }
            Some(Err(e)) => {
                on_join_error(e);
                if session_iter.peek().is_none() && join_set.is_empty() {
                    break;
                }
                continue;
            }
            None => break, // JoinSet empty and no more sessions.
        }

        // Exit when all sessions have been processed.
        if session_iter.peek().is_none() && join_set.is_empty() {
            break;
        }
    }
}

// ---------------------------------------------------------------------------
// GatewayRecoveryDeps
// ---------------------------------------------------------------------------

/// Injectable dependencies for the gateway-Lima recovery orchestrator.
///
/// The production implementation binds `Arc<SessionStore>`. Test code
/// provides an in-memory stub that records calls without touching SQLite,
/// Docker, or Lima.
pub trait GatewayRecoveryDeps: Send + Sync {
    /// Return all sessions in the store. The orchestrator applies
    /// [`sessions_to_recover`] internally to select Running Lima candidates.
    fn list_sessions(&self) -> Result<Vec<Session>, SandboxError>;

    /// Return the stored network info for `id`, or `Ok(None)` when absent.
    fn get_network_info(&self, id: &SessionId) -> Result<Option<NetworkInfo>, SandboxError>;

    /// Mark `id` as `Error` in the persistent store.
    ///
    /// Errors from this call are logged and swallowed by the orchestrator —
    /// it is a best-effort write; a store failure must not prevent recovery
    /// from continuing to the next session.
    fn mark_session_error(&self, id: &SessionId) -> Result<(), SandboxError>;
}

impl GatewayRecoveryDeps for Arc<SessionStore> {
    fn list_sessions(&self) -> Result<Vec<Session>, SandboxError> {
        self.list_sessions_unfiltered()
    }

    fn get_network_info(&self, id: &SessionId) -> Result<Option<NetworkInfo>, SandboxError> {
        self.get_network_info_unfiltered(id)
    }

    fn mark_session_error(&self, id: &SessionId) -> Result<(), SandboxError> {
        self.update_state_reconcile(id, SessionState::Error)
    }
}

// ---------------------------------------------------------------------------
// run_gateway_recovery
// ---------------------------------------------------------------------------

/// Orchestrate a full gateway-Lima recovery, driving the networking-status
/// state machine from **Degraded** → **Recovering** → **Healthy**.
///
/// Called by `recover_gateway_lima` in the daemon after the gateway Lima
/// instance is confirmed unreachable. Manages the `networking_status` map
/// transitions and the recovering latch via [`GatewayRecoveringGuard`];
/// delegates the effectful steps to injected closures so the state-machine
/// logic can be covered by hermetic unit tests.
///
/// ## Recovery sequence
///
/// 1. Engage the `latch` via [`GatewayRecoveringGuard`] (released on return,
///    including early-return and panic paths).
/// 2. Snapshot all Running Lima sessions (`deps.list_sessions()` +
///    [`sessions_to_recover`]) and tag each `Degraded` in `networking_status`.
/// 3. Restart the gateway Lima instance (`restart_gateway().await`).
///    On failure: leave sessions `Degraded` and return — the monitor will
///    re-trigger on the next tick.
/// 4. For each session (bounded concurrency, `max_concurrent` at a time):
///    tag `Recovering`, fetch network info (absent → mark Error + skip),
///    spawn `per_session_recover(id, owner, info)`, then on success remove
///    from map (≡ Healthy) and call `on_session_success`; on failure call
///    `deps.mark_session_error` and remove from map.
///
/// ## Parameters
///
/// - `deps` — store operations: list sessions, get network info, mark error.
/// - `networking_status` — transient in-memory health map; source of truth
///   for the Degraded / Recovering / Healthy transitions.
/// - `latch` — daemon-wide `gateway_recovering` flag.
/// - `restart_gateway` — async thunk that restarts the Lima instance.
///   Returns `Ok(())` on success, `Err(msg)` on failure.
/// - `per_session_recover` — per-session gateway re-create (teardown + setup +
///   any post-steps); result tuple is `(session_id, owner, Ok(())|Err(msg))`.
/// - `on_session_success` — called after a successful per-session recovery
///   (spawn ingestor, re-apply policy — daemon-specific side-effects).
/// - `max_concurrent` — maximum number of simultaneous per-session tasks.
pub async fn run_gateway_recovery<Deps, RestartFut, SessionFut, SuccessFut>(
    deps: &Deps,
    networking_status: Arc<tokio::sync::Mutex<HashMap<SessionId, NetworkingStatus>>>,
    latch: Arc<AtomicBool>,
    restart_gateway: impl FnOnce() -> RestartFut,
    mut per_session_recover: impl FnMut(SessionId, String, NetworkInfo) -> SessionFut,
    mut on_session_success: impl FnMut(SessionId, String) -> SuccessFut,
    max_concurrent: usize,
) where
    Deps: GatewayRecoveryDeps,
    RestartFut: Future<Output = Result<(), String>>,
    SessionFut: Future<Output = (SessionId, String, Result<(), String>)> + Send + 'static,
    SuccessFut: Future<Output = ()>,
{
    let _guard = GatewayRecoveringGuard::engage(&latch);

    info!("gateway Lima recovery: starting full instance recovery");

    // Snapshot all Running Lima sessions up front.
    let sessions = match deps.list_sessions() {
        Ok(s) => sessions_to_recover(s),
        Err(e) => {
            error!(error = %e, "gateway Lima recovery: failed to list sessions");
            return;
        }
    };

    // Tag all candidate sessions Degraded.
    {
        let mut map = networking_status.lock().await;
        for session in &sessions {
            map.insert(session.id, NetworkingStatus::Degraded);
        }
    }

    // Restart the gateway Lima instance.
    match restart_gateway().await {
        Ok(()) => {
            info!("gateway Lima recovery: instance restarted and Docker daemon ready");
        }
        Err(e) => {
            // Includes the 90 s readiness timeout: leave sessions Degraded and
            // let the monitor re-trigger on the next 10 s tick.
            error!(
                error = %e,
                "gateway Lima recovery: instance restart failed; sessions remain Degraded"
            );
            return;
        }
    }

    // Per-session re-create with bounded concurrency. One failure must not
    // abort the rest.
    let mut join_set: JoinSet<(SessionId, String, Result<(), String>)> = JoinSet::new();
    let mut session_iter = sessions.into_iter().peekable();

    loop {
        // Fill the JoinSet up to the concurrency cap.
        while join_set.len() < max_concurrent {
            let session = match session_iter.next() {
                Some(s) => s,
                None => break,
            };

            // Tag Recovering.
            {
                let mut map = networking_status.lock().await;
                map.insert(session.id, NetworkingStatus::Recovering);
            }

            // Fetch stored network info. Absent or error → mark Error, skip.
            let network_info = match deps.get_network_info(&session.id) {
                Ok(Some(info)) => info,
                Ok(None) => {
                    warn!(
                        session_id = %session.id,
                        "gateway Lima recovery: no network info for session; marking Error"
                    );
                    let _ = deps.mark_session_error(&session.id);
                    {
                        let mut map = networking_status.lock().await;
                        map.remove(&session.id);
                    }
                    continue;
                }
                Err(e) => {
                    warn!(
                        session_id = %session.id,
                        error = %e,
                        "gateway Lima recovery: failed to get network info; marking Error"
                    );
                    let _ = deps.mark_session_error(&session.id);
                    {
                        let mut map = networking_status.lock().await;
                        map.remove(&session.id);
                    }
                    continue;
                }
            };

            let sid = session.id;
            let owner = session.owner_username.clone();
            join_set.spawn(per_session_recover(sid, owner, network_info));
        }

        // Drain one completed task.
        match join_set.join_next().await {
            Some(Ok((sid, owner, Ok(())))) => {
                info!(
                    session_id = %sid,
                    "gateway Lima recovery: session gateway recovered"
                );
                // Remove map entry → Healthy (absent entry ≡ Healthy).
                {
                    let mut map = networking_status.lock().await;
                    map.remove(&sid);
                }
                on_session_success(sid, owner).await;
            }
            Some(Ok((sid, _owner, Err(e)))) => {
                error!(
                    session_id = %sid,
                    error = %e,
                    "gateway Lima recovery: failed to recover session gateway; marking Error"
                );
                let _ = deps.mark_session_error(&sid);
                {
                    let mut map = networking_status.lock().await;
                    map.remove(&sid);
                }
            }
            Some(Err(e)) => {
                // A spawned per-session task panicked. Log and continue.
                error!(error = %e, "gateway Lima recovery: JoinSet join error");
                if session_iter.peek().is_none() && join_set.is_empty() {
                    break;
                }
                continue;
            }
            None => break, // JoinSet drained and no more sessions.
        }

        if session_iter.peek().is_none() && join_set.is_empty() {
            break;
        }
    }

    info!("gateway Lima recovery: complete");
    // _guard drops here, clearing the recovering latch.
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::BackendKind;
    use crate::session::SessionState;
    use std::sync::atomic::AtomicUsize;
    use std::sync::atomic::Ordering;
    use std::sync::{Arc, Mutex};

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    /// Build a session with an explicit state + backend.
    fn session_with(state: SessionState, backend: BackendKind) -> Session {
        let mut s = Session::new(Some("recovery-test".into()));
        s.state = state;
        s.backend = backend;
        s
    }

    /// Minimal `NetworkInfo` suitable for stubs.
    fn stub_network_info() -> NetworkInfo {
        NetworkInfo {
            bridge_name: "lima0".into(),
            subnet: "10.0.0.0/29".into(),
            gateway_ip: "10.0.0.3".into(),
            vm_ip: "10.0.0.4".into(),
            docker_network_name: "sandbox-net-test".into(),
            vmnet_slot: None,
        }
    }

    /// In-memory stub for [`GatewayRecoveryDeps`] that does not touch SQLite.
    struct StubDeps {
        /// Sessions returned by `list_sessions`.
        sessions: Vec<Session>,
        /// Network info returned per session id, or `None` to simulate absence.
        network_info: HashMap<SessionId, Option<NetworkInfo>>,
        /// Records every `mark_session_error` call.
        errors_marked: Arc<Mutex<Vec<SessionId>>>,
    }

    impl StubDeps {
        fn new(sessions: Vec<Session>) -> Self {
            let network_info = sessions
                .iter()
                .map(|s| (s.id, Some(stub_network_info())))
                .collect();
            Self {
                sessions,
                network_info,
                errors_marked: Arc::new(Mutex::new(Vec::new())),
            }
        }

        /// Create a stub where `session_id` has no network info (simulates
        /// the "no network info → mark Error" path).
        fn with_missing_network_info(mut self, id: SessionId) -> Self {
            self.network_info.insert(id, None);
            self
        }
    }

    impl GatewayRecoveryDeps for StubDeps {
        fn list_sessions(&self) -> Result<Vec<Session>, SandboxError> {
            Ok(self.sessions.clone())
        }

        fn get_network_info(&self, id: &SessionId) -> Result<Option<NetworkInfo>, SandboxError> {
            Ok(self.network_info.get(id).cloned().flatten())
        }

        fn mark_session_error(&self, id: &SessionId) -> Result<(), SandboxError> {
            self.errors_marked.lock().unwrap().push(*id);
            Ok(())
        }
    }

    // -----------------------------------------------------------------------
    // sessions_to_recover (pure filter)
    // -----------------------------------------------------------------------

    #[test]
    fn filter_selects_only_running_lima_sessions() {
        let running_lima = session_with(SessionState::Running, BackendKind::Lima);
        let want = running_lima.id;

        let all = vec![
            session_with(SessionState::Creating, BackendKind::Lima),
            running_lima,
            session_with(SessionState::Stopped, BackendKind::Lima),
            session_with(SessionState::Running, BackendKind::Container),
            session_with(SessionState::Error, BackendKind::Lima),
        ];

        let selected = sessions_to_recover(all);
        assert_eq!(
            selected.len(),
            1,
            "only the single Running+Lima session qualifies"
        );
        assert_eq!(
            selected[0].id, want,
            "the selected session must be the Running Lima one"
        );
    }

    #[test]
    fn filter_excludes_non_lima_backend() {
        // A Running container session must never be swept into a
        // gateway-Lima recovery — the container backend has no gateway
        // Lima instance to re-create through.
        let all = vec![session_with(SessionState::Running, BackendKind::Container)];
        assert!(
            sessions_to_recover(all).is_empty(),
            "Running Container sessions are not gateway-Lima recovery candidates"
        );
    }

    #[test]
    fn filter_excludes_non_running_states() {
        for state in [
            SessionState::Creating,
            SessionState::Stopped,
            SessionState::Error,
        ] {
            let all = vec![session_with(state, BackendKind::Lima)];
            assert!(
                sessions_to_recover(all).is_empty(),
                "a {state:?} Lima session must not be recovered"
            );
        }
    }

    #[test]
    fn filter_empty_input_is_empty() {
        assert!(sessions_to_recover(Vec::new()).is_empty());
    }

    // -----------------------------------------------------------------------
    // run_bounded_recovery (concurrency-cap loop)
    // -----------------------------------------------------------------------

    /// Never more than `max_concurrent` recovery tasks are in flight at
    /// once, and with more sessions than the cap the loop actually fills
    /// up to the cap (proving the bound is a real ceiling, not an
    /// accidental serialization). Also proves every session is attempted.
    #[tokio::test]
    async fn bounded_loop_respects_concurrency_cap() {
        const CAP: usize = 8;
        const N: usize = 25;

        let in_flight = Arc::new(AtomicUsize::new(0));
        let max_seen = Arc::new(AtomicUsize::new(0));
        let attempted = Arc::new(AtomicUsize::new(0));
        let completed = Arc::new(AtomicUsize::new(0));

        let sessions: Vec<usize> = (0..N).collect();

        run_bounded_recovery(
            sessions,
            CAP,
            |i| {
                let in_flight = Arc::clone(&in_flight);
                let max_seen = Arc::clone(&max_seen);
                let attempted = Arc::clone(&attempted);
                async move {
                    attempted.fetch_add(1, Ordering::SeqCst);
                    Some(async move {
                        // Enter: bump the live counter and record the peak.
                        let now = in_flight.fetch_add(1, Ordering::SeqCst) + 1;
                        max_seen.fetch_max(now, Ordering::SeqCst);
                        // Yield several times so the driver gets a chance
                        // to fill the JoinSet up to the cap while this task
                        // is still "in flight" — deterministic interleaving
                        // on the single-threaded test runtime, no sleeps.
                        for _ in 0..4 {
                            tokio::task::yield_now().await;
                        }
                        in_flight.fetch_sub(1, Ordering::SeqCst);
                        i
                    })
                }
            },
            |_i: usize| {
                let completed = Arc::clone(&completed);
                async move {
                    completed.fetch_add(1, Ordering::SeqCst);
                }
            },
            |_e| panic!("no task should panic in this test"),
        )
        .await;

        let peak = max_seen.load(Ordering::SeqCst);
        assert!(
            peak <= CAP,
            "in-flight tasks ({peak}) must never exceed the cap ({CAP})"
        );
        assert_eq!(
            peak, CAP,
            "with N ({N}) > cap ({CAP}), the loop must fill up to the cap"
        );
        assert_eq!(
            attempted.load(Ordering::SeqCst),
            N,
            "every session must be offered to prepare exactly once"
        );
        assert_eq!(
            completed.load(Ordering::SeqCst),
            N,
            "every spawned task's outcome must be drained via on_complete"
        );
        assert_eq!(
            in_flight.load(Ordering::SeqCst),
            0,
            "no task may remain in flight after the loop returns"
        );
    }

    /// One task failing must not abort the others: every session still
    /// runs, and the aggregate reflects each per-session outcome.
    #[tokio::test]
    async fn bounded_loop_isolates_partial_failure() {
        const CAP: usize = 8;
        const N: usize = 20;

        // Sessions with index % 3 == 0 "fail"; the rest "succeed".
        let sessions: Vec<usize> = (0..N).collect();
        let outcomes = Arc::new(Mutex::new(Vec::<(usize, bool)>::new()));

        run_bounded_recovery(
            sessions,
            CAP,
            |i| async move {
                Some(async move {
                    let ok = i % 3 != 0;
                    (i, if ok { Ok(()) } else { Err(format!("boom-{i}")) })
                })
            },
            |(i, res): (usize, Result<(), String>)| {
                let outcomes = Arc::clone(&outcomes);
                async move {
                    outcomes.lock().unwrap().push((i, res.is_ok()));
                }
            },
            |_e| panic!("no task should panic in this test"),
        )
        .await;

        let mut got = outcomes.lock().unwrap().clone();
        got.sort_by_key(|(i, _)| *i);

        assert_eq!(
            got.len(),
            N,
            "every session must be drained despite failures"
        );
        for (i, ok) in got {
            let expected_ok = i % 3 != 0;
            assert_eq!(
                ok, expected_ok,
                "session {i}: on_complete must see its own per-session outcome"
            );
        }
    }

    /// A `prepare` that returns `None` skips the session without spawning
    /// (the production "no network info → mark Error, continue" path). The
    /// loop must still drain the spawned ones and terminate — even when
    /// every session is skipped (empty JoinSet must not hang).
    #[tokio::test]
    async fn bounded_loop_handles_skipped_sessions() {
        const CAP: usize = 8;
        const N: usize = 10;

        let prepared = Arc::new(AtomicUsize::new(0));
        let completed = Arc::new(AtomicUsize::new(0));

        // Even indices spawn a task; odd indices are skipped (None).
        let sessions: Vec<usize> = (0..N).collect();
        let expected_spawned = (0..N).filter(|i| i % 2 == 0).count();

        run_bounded_recovery(
            sessions,
            CAP,
            |i| {
                let prepared = Arc::clone(&prepared);
                async move {
                    prepared.fetch_add(1, Ordering::SeqCst);
                    if i % 2 == 0 {
                        Some(async move { i })
                    } else {
                        None
                    }
                }
            },
            |_i: usize| {
                let completed = Arc::clone(&completed);
                async move {
                    completed.fetch_add(1, Ordering::SeqCst);
                }
            },
            |_e| panic!("no task should panic in this test"),
        )
        .await;

        assert_eq!(
            prepared.load(Ordering::SeqCst),
            N,
            "prepare must be offered every session, including skipped ones"
        );
        assert_eq!(
            completed.load(Ordering::SeqCst),
            expected_spawned,
            "only spawned (non-skipped) sessions reach on_complete"
        );
    }

    /// All sessions skipped: the loop must terminate (empty JoinSet →
    /// join_next returns None immediately, not a hang).
    #[tokio::test]
    async fn bounded_loop_all_skipped_terminates() {
        let sessions: Vec<usize> = (0..5).collect();
        let completed = Arc::new(AtomicUsize::new(0));

        run_bounded_recovery(
            sessions,
            8,
            |_i| async move { None::<std::future::Ready<()>> },
            |_i: ()| {
                let completed = Arc::clone(&completed);
                async move {
                    completed.fetch_add(1, Ordering::SeqCst);
                }
            },
            |_e| panic!("no task should panic in this test"),
        )
        .await;

        assert_eq!(
            completed.load(Ordering::SeqCst),
            0,
            "no task spawned means on_complete never fires; loop still returns"
        );
    }

    /// Empty input set: the loop returns immediately without spawning or
    /// draining anything.
    #[tokio::test]
    async fn bounded_loop_empty_input_terminates() {
        let sessions: Vec<usize> = Vec::new();
        let prepared = Arc::new(AtomicUsize::new(0));

        run_bounded_recovery(
            sessions,
            8,
            |_i| {
                let prepared = Arc::clone(&prepared);
                async move {
                    prepared.fetch_add(1, Ordering::SeqCst);
                    Some(async move {})
                }
            },
            |_i: ()| async move {},
            |_e| panic!("no task should panic in this test"),
        )
        .await;

        assert_eq!(
            prepared.load(Ordering::SeqCst),
            0,
            "empty input must never invoke prepare"
        );
    }

    // -----------------------------------------------------------------------
    // GatewayRecoveringGuard (latch release on all paths)
    // -----------------------------------------------------------------------

    #[test]
    fn guard_sets_latch_on_engage_and_clears_on_drop() {
        let latch = Arc::new(AtomicBool::new(false));
        {
            let _g = GatewayRecoveringGuard::engage(&latch);
            assert!(
                latch.load(Ordering::SeqCst),
                "engage() must set the recovering latch"
            );
        }
        assert!(
            !latch.load(Ordering::SeqCst),
            "the latch must be cleared when the guard is dropped"
        );
    }

    #[test]
    fn guard_clears_latch_on_early_return_path() {
        // Model an early `return` inside the guarded scope: the guard is
        // held by a function that returns before reaching its natural end.
        let latch = Arc::new(AtomicBool::new(false));

        fn early_return(latch: &Arc<AtomicBool>, bail: bool) {
            let _g = GatewayRecoveringGuard::engage(latch);
            if bail {
                return; // guard drops here
            }
            // (unreached in this test)
        }

        early_return(&latch, true);
        assert!(
            !latch.load(Ordering::SeqCst),
            "latch must be released even when the guarded scope returns early"
        );
    }

    #[test]
    fn guard_clears_latch_on_panic_unwind() {
        // The latch must not stay stuck if the guarded scope panics — Drop
        // runs during unwind. Proves the release-on-all-paths property for
        // the panic path.
        let latch = Arc::new(AtomicBool::new(false));
        let latch_for_closure = Arc::clone(&latch);

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _g = GatewayRecoveringGuard::engage(&latch_for_closure);
            panic!("boom");
        }));

        assert!(result.is_err(), "the guarded closure must have panicked");
        assert!(
            !latch.load(Ordering::SeqCst),
            "latch must be released on the panic-unwind path"
        );
    }

    /// End-to-end over the two seams together: engage the guard, drive a
    /// mixed success/failure bounded run to completion, then confirm the
    /// latch is clear once the guard drops — the composed success/partial
    /// path leaves no stuck latch.
    #[tokio::test]
    async fn guard_released_after_bounded_run_completes() {
        let latch = Arc::new(AtomicBool::new(false));

        {
            let _guard = GatewayRecoveringGuard::engage(&latch);
            assert!(latch.load(Ordering::SeqCst), "latch set during recovery");

            let sessions: Vec<usize> = (0..12).collect();
            run_bounded_recovery(
                sessions,
                8,
                |i| async move { Some(async move { if i % 4 == 0 { Err(()) } else { Ok(()) } }) },
                |_r: Result<(), ()>| async move {},
                |_e| panic!("no task should panic in this test"),
            )
            .await;
        } // guard drops here

        assert!(
            !latch.load(Ordering::SeqCst),
            "latch must be clear after the recovery scope (guard) ends"
        );
    }

    // -----------------------------------------------------------------------
    // run_gateway_recovery — state-machine behaviors
    // -----------------------------------------------------------------------

    /// Builds a shared networking_status map and a recovering latch for use
    /// across the state-machine tests.
    fn make_recovery_state() -> (
        Arc<tokio::sync::Mutex<HashMap<SessionId, NetworkingStatus>>>,
        Arc<AtomicBool>,
    ) {
        (
            Arc::new(tokio::sync::Mutex::new(HashMap::new())),
            Arc::new(AtomicBool::new(false)),
        )
    }

    /// Full Degraded → Recovering → Healthy transition on success.
    ///
    /// One Running Lima session, successful restart, successful per-session
    /// recovery. Verifies:
    ///   - the session is Recovering in the map when per_session_recover runs,
    ///   - the session is absent (= Healthy) after the orchestrator returns,
    ///   - on_session_success was called for the recovered session.
    #[tokio::test]
    async fn recovery_transitions_healthy_on_success() {
        let session = session_with(SessionState::Running, BackendKind::Lima);
        let sid = session.id;
        let deps = StubDeps::new(vec![session]);

        let (networking_status, latch) = make_recovery_state();

        // Record the per-session networking status at the moment the recovery
        // task is invoked — it must be Recovering at that point.
        let status_when_called: Arc<Mutex<Option<Option<NetworkingStatus>>>> =
            Arc::new(Mutex::new(None));
        let ns_snap = Arc::clone(&networking_status);
        let swc = Arc::clone(&status_when_called);

        let success_called: Arc<Mutex<Vec<SessionId>>> = Arc::new(Mutex::new(Vec::new()));
        let sc = Arc::clone(&success_called);

        run_gateway_recovery(
            &deps,
            Arc::clone(&networking_status),
            Arc::clone(&latch),
            || async { Ok::<(), String>(()) },
            |session_id, owner, _info| {
                let ns = Arc::clone(&ns_snap);
                let swc = Arc::clone(&swc);
                async move {
                    // Observe the map state at the time this task runs.
                    let entry = ns.lock().await.get(&session_id).copied();
                    *swc.lock().unwrap() = Some(entry);
                    (session_id, owner, Ok(()))
                }
            },
            |session_id, _owner| {
                let sc = Arc::clone(&sc);
                async move {
                    sc.lock().unwrap().push(session_id);
                }
            },
            8,
        )
        .await;

        // Session must be Recovering at the time the recovery task runs.
        assert_eq!(
            *status_when_called.lock().unwrap(),
            Some(Some(NetworkingStatus::Recovering)),
            "the session must be Recovering in the map when per_session_recover is invoked"
        );

        // Session must be absent from the map after successful recovery (= Healthy).
        assert!(
            !networking_status.lock().await.contains_key(&sid),
            "successfully recovered session must be absent from the map (= Healthy)"
        );

        // The latch must be released after the orchestrator returns.
        assert!(
            !latch.load(Ordering::SeqCst),
            "the recovering latch must be clear after run_gateway_recovery returns"
        );

        // on_session_success must have been called for the recovered session.
        assert_eq!(
            *success_called.lock().unwrap(),
            vec![sid],
            "on_session_success must be called exactly once for the recovered session"
        );

        // mark_session_error must never have been called (no failures).
        assert!(
            deps.errors_marked.lock().unwrap().is_empty(),
            "no sessions should be marked Error on a fully successful recovery"
        );
    }

    /// One session failing its per-session recovery must not prevent the
    /// others from being recovered.
    ///
    /// Three Running Lima sessions; the middle one's recovery fails. After
    /// the orchestrator returns:
    ///   - the two successful sessions are absent from the map (= Healthy),
    ///   - the failed session is absent from the map (Error, not Running),
    ///   - mark_session_error was called exactly once for the failed session,
    ///   - on_session_success was called for the two successful sessions.
    #[tokio::test]
    async fn recovery_partial_failure_does_not_abort_others() {
        let sessions: Vec<Session> = (0..3)
            .map(|_| session_with(SessionState::Running, BackendKind::Lima))
            .collect();
        let ids: Vec<SessionId> = sessions.iter().map(|s| s.id).collect();
        let failing_id = ids[1]; // the middle one fails

        let deps = StubDeps::new(sessions);
        let (networking_status, latch) = make_recovery_state();

        let success_called: Arc<Mutex<Vec<SessionId>>> = Arc::new(Mutex::new(Vec::new()));
        let sc = Arc::clone(&success_called);

        run_gateway_recovery(
            &deps,
            Arc::clone(&networking_status),
            Arc::clone(&latch),
            || async { Ok::<(), String>(()) },
            move |session_id, owner, _info| {
                let result = if session_id == failing_id {
                    Err("injected failure".to_string())
                } else {
                    Ok(())
                };
                async move { (session_id, owner, result) }
            },
            |session_id, _owner| {
                let sc = Arc::clone(&sc);
                async move {
                    sc.lock().unwrap().push(session_id);
                }
            },
            8,
        )
        .await;

        // All sessions must be absent from the map after the run.
        let map = networking_status.lock().await;
        for id in &ids {
            assert!(
                !map.contains_key(id),
                "session {id} must be absent from the map after recovery (regardless of outcome)"
            );
        }
        drop(map);

        // mark_session_error was called exactly once, for the failing session.
        let errors = deps.errors_marked.lock().unwrap().clone();
        assert_eq!(
            errors,
            vec![failing_id],
            "mark_session_error must be called exactly for the session whose recovery failed"
        );

        // on_session_success was called for the two successful sessions.
        // SessionId has no Ord, so we compare as sorted hex strings.
        let mut successes: Vec<String> = success_called
            .lock()
            .unwrap()
            .iter()
            .map(|id| id.to_string())
            .collect();
        successes.sort();
        let mut expected_successes: Vec<String> = ids
            .iter()
            .filter(|id| **id != failing_id)
            .map(|id| id.to_string())
            .collect();
        expected_successes.sort();
        assert_eq!(
            successes, expected_successes,
            "on_session_success must be called for every session that recovered successfully"
        );
    }

    /// Running recovery twice is safe: the second run re-processes the same
    /// Running Lima sessions and leaves them Healthy again. No state leaked
    /// between runs, no panics, the final networking_status map is empty.
    #[tokio::test]
    async fn recovery_idempotent_double_run() {
        let sessions: Vec<Session> = (0..3)
            .map(|_| session_with(SessionState::Running, BackendKind::Lima))
            .collect();
        let ids: Vec<SessionId> = sessions.iter().map(|s| s.id).collect();

        let deps = StubDeps::new(sessions);
        let (networking_status, latch) = make_recovery_state();

        // A simple always-succeeding per_session_recover.
        let succeed = |session_id: SessionId, owner: String, _info: NetworkInfo| async move {
            (session_id, owner, Ok::<(), String>(()))
        };

        // First run.
        run_gateway_recovery(
            &deps,
            Arc::clone(&networking_status),
            Arc::clone(&latch),
            || async { Ok::<(), String>(()) },
            succeed,
            |_, _| async {},
            8,
        )
        .await;

        // After first run: all sessions Healthy, latch clear.
        {
            let map = networking_status.lock().await;
            for id in &ids {
                assert!(
                    !map.contains_key(id),
                    "after first run: {id} must be Healthy"
                );
            }
        }
        assert!(
            !latch.load(Ordering::SeqCst),
            "latch must be clear after first run"
        );

        // Second run with the same deps (sessions still Running in the stub).
        run_gateway_recovery(
            &deps,
            Arc::clone(&networking_status),
            Arc::clone(&latch),
            || async { Ok::<(), String>(()) },
            |session_id, owner, _info| async move { (session_id, owner, Ok(())) },
            |_, _| async {},
            8,
        )
        .await;

        // After second run: all sessions still Healthy, latch still clear.
        {
            let map = networking_status.lock().await;
            for id in &ids {
                assert!(
                    !map.contains_key(id),
                    "after second run: {id} must be Healthy"
                );
            }
        }
        assert!(
            !latch.load(Ordering::SeqCst),
            "latch must be clear after second run"
        );
    }

    /// When the gateway restart fails, sessions remain Degraded (in the map)
    /// and the per-session recovery is never attempted.
    #[tokio::test]
    async fn recovery_aborts_on_restart_failure() {
        let session = session_with(SessionState::Running, BackendKind::Lima);
        let sid = session.id;
        let deps = StubDeps::new(vec![session]);

        let (networking_status, latch) = make_recovery_state();

        let per_session_called = Arc::new(AtomicUsize::new(0));
        let psc = Arc::clone(&per_session_called);

        run_gateway_recovery(
            &deps,
            Arc::clone(&networking_status),
            Arc::clone(&latch),
            || async { Err::<(), _>("gateway start timed out".to_string()) },
            move |session_id, owner, _info| {
                psc.fetch_add(1, Ordering::SeqCst);
                async move { (session_id, owner, Ok(())) }
            },
            |_, _| async {},
            8,
        )
        .await;

        // Session must remain Degraded (still in the map).
        assert_eq!(
            networking_status.lock().await.get(&sid).copied(),
            Some(NetworkingStatus::Degraded),
            "on restart failure sessions must remain Degraded in the map"
        );

        // per_session_recover must never have been invoked.
        assert_eq!(
            per_session_called.load(Ordering::SeqCst),
            0,
            "per_session_recover must not be called when the restart fails"
        );

        // The latch must still be released.
        assert!(
            !latch.load(Ordering::SeqCst),
            "the latch must be released even when recovery aborts on restart failure"
        );
    }

    /// When a session has no network info, it is marked Error and skipped —
    /// other sessions with valid info are still recovered.
    #[tokio::test]
    async fn recovery_skips_sessions_with_missing_network_info() {
        let with_info = session_with(SessionState::Running, BackendKind::Lima);
        let without_info = session_with(SessionState::Running, BackendKind::Lima);
        let sid_good = with_info.id;
        let sid_missing = without_info.id;

        let deps =
            StubDeps::new(vec![with_info, without_info]).with_missing_network_info(sid_missing);
        let (networking_status, latch) = make_recovery_state();

        let success_called: Arc<Mutex<Vec<SessionId>>> = Arc::new(Mutex::new(Vec::new()));
        let sc = Arc::clone(&success_called);

        run_gateway_recovery(
            &deps,
            Arc::clone(&networking_status),
            Arc::clone(&latch),
            || async { Ok::<(), String>(()) },
            |session_id, owner, _info| async move { (session_id, owner, Ok(())) },
            |session_id, _owner| {
                let sc = Arc::clone(&sc);
                async move {
                    sc.lock().unwrap().push(session_id);
                }
            },
            8,
        )
        .await;

        // The session with info must be Healthy (absent from map).
        assert!(
            !networking_status.lock().await.contains_key(&sid_good),
            "session with network info must be Healthy after recovery"
        );

        // The session without info must also be absent from the map (skipped → Error).
        assert!(
            !networking_status.lock().await.contains_key(&sid_missing),
            "session without network info must be removed from the map (skipped, Error state)"
        );

        // mark_session_error must have been called for the session without info.
        let errors = deps.errors_marked.lock().unwrap().clone();
        assert!(
            errors.contains(&sid_missing),
            "mark_session_error must be called for the session with missing network info"
        );

        // on_session_success must only have been called for the session with info.
        assert_eq!(
            *success_called.lock().unwrap(),
            vec![sid_good],
            "on_session_success must only be called for sessions that were actually recovered"
        );
    }
}
