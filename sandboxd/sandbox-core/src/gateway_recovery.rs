//! Gateway Lima instance crash-recovery orchestrator.
//!
//! Provides the state-machine logic for the Degraded → Recovering → Healthy
//! networking-status transitions behind injectable dependencies so the
//! orchestration can be covered by hermetic unit tests without Docker, Lima,
//! or nft.
//!
//! # Pieces
//!
//! - [`GatewayRecoveringGuard`] — RAII latch guard; clears the latch it
//!   engaged on drop so all return paths (including panics) release it.
//! - [`GatewayRecoveryLatches`] — one such latch per gateway owner, so a
//!   recovery of one owner's gateway is invisible to readers of another's.
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
use crate::session_operator::{
    SessionOperator, UnresolvedSessionOperator, resolve_session_operator,
};
use crate::store::SessionStore;

// ---------------------------------------------------------------------------
// GatewayRecoveringGuard
// ---------------------------------------------------------------------------

/// RAII guard that clears on drop the one latch it was engaged on.
///
/// Which latch that is comes from the caller: the daemon pulls an owner's out
/// of [`GatewayRecoveryLatches`], so engaging a guard says "this owner's
/// gateway is recovering" and says nothing about anyone else's.
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
// GatewayRecoveryLatches
// ---------------------------------------------------------------------------

/// One recovery latch per gateway owner.
///
/// A single flag is the right shape for one gateway and the wrong one for
/// several: while it is held, every reader is told a recovery is running,
/// including readers whose gateway is untouched and healthy. Holding one
/// owner's flag would suppress per-session work on every other owner's
/// gateway for the length of a recovery.
///
/// The latch itself is unchanged — each entry is the same `Arc<AtomicBool>`
/// [`GatewayRecoveringGuard`] engages and clears, so the release-on-every-path
/// property comes along untouched. What changes is that there is one per
/// owner rather than one for the process.
///
/// # Keys are gateway owners, not operators
///
/// Callers collapse an operator uid through
/// [`crate::gateway_lima::gateway_owner_uid`] before looking a latch up.
/// While per-operator gateways are off every operator collapses onto the
/// daemon's own uid, so the map holds a single entry that every reader and
/// the one writer share — the single flag, spelled as a map of one.
///
/// # Locking
///
/// One `Mutex<HashMap<u32, _>>`, held across a lookup or an insert and never
/// across an await, with the map growing monotonically — the discipline
/// [`crate::gateway_lima_registry::GatewayLimaManagerRegistry`] uses. Nothing
/// is removed on release because a released latch and an absent one say the
/// same thing, and an entry is one `Arc<AtomicBool>`.
pub struct GatewayRecoveryLatches {
    by_owner: std::sync::Mutex<HashMap<u32, Arc<AtomicBool>>>,
}

impl GatewayRecoveryLatches {
    /// An empty set of latches: nobody is recovering.
    pub fn new() -> Self {
        Self {
            by_owner: std::sync::Mutex::new(HashMap::new()),
        }
    }

    /// The latch for `owner_uid`, creating a cleared one on first lookup.
    ///
    /// The returned `Arc` is stable for the process lifetime: every lookup for
    /// an owner yields the same latch, which is what makes a guard engaged on
    /// one of them visible through the others. Handing back a fresh
    /// `AtomicBool` would hand back a latch nobody else can observe.
    ///
    /// A poisoned lock is recovered rather than propagated, for the reason
    /// `GatewayLimaManagerRegistry::get_or_create` gives: the values are
    /// `Arc`s inserted whole, so a panic elsewhere cannot leave the map in a
    /// state that makes a later lookup wrong, and refusing every gateway
    /// recovery for the rest of the process is the worse answer.
    pub fn for_owner(&self, owner_uid: u32) -> Arc<AtomicBool> {
        let mut by_owner = self.by_owner.lock().unwrap_or_else(|e| e.into_inner());
        Arc::clone(
            by_owner
                .entry(owner_uid)
                .or_insert_with(|| Arc::new(AtomicBool::new(false))),
        )
    }

    /// Whether a recovery is in flight for `owner_uid`.
    ///
    /// An owner with no entry is not recovering: `for_owner` inserts a cleared
    /// latch, and a cleared latch reads the same `false` an absent one does, so
    /// "absent" and "present and clear" are one answer here whatever put the
    /// entry there — a lookup that never engaged included. Reading
    /// therefore does not insert — a monitor that polls every owner it sees
    /// would otherwise grow the map with entries for owners that never
    /// recover.
    pub fn is_recovering(&self, owner_uid: u32) -> bool {
        self.by_owner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&owner_uid)
            .is_some_and(|latch| latch.load(std::sync::atomic::Ordering::SeqCst))
    }

    /// Number of owners with a latch. Exposed for tests.
    #[cfg(test)]
    fn len(&self) -> usize {
        self.by_owner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .len()
    }
}

impl Default for GatewayRecoveryLatches {
    fn default() -> Self {
        Self::new()
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
// partition_by_gateway_owner
// ---------------------------------------------------------------------------

/// How the gateways a recovery has to drive are shared out.
///
/// This is **not** the per-operator-gateway switch, and a caller must not
/// derive it from [`crate::gateway_lima::per_operator_gateway_enabled`]
/// without also holding one gateway per owner.
/// [`crate::gateway_lima::gateway_instance_name`] and
/// [`crate::gateway_lima::gateway_owner_uid`] answer what a gateway is called
/// and which uid owns it; this answers how many there are to act on, which is
/// a property of what the caller is holding rather than of the switch. A
/// daemon carrying one `GatewayLimaManager` drives one gateway in either mode.
///
/// # Why an enum rather than a uid-collapsing function
///
/// A `Fn(u32) -> u32` mapping an operator uid onto an owner uid would express
/// [`Self::PerOperator`] as the identity and [`Self::Shared`] as a constant,
/// and it would be wrong for the shared case: it can only be applied to a uid,
/// so every session's operator would have to be resolved first, and a session
/// whose operator cannot be determined would be stranded with no owner to
/// attribute it to. Under [`Self::Shared`] that question does not arise —
/// there is one gateway, it serves every session, and which operator a session
/// belongs to changes nothing about where it recovers. Making that an arm
/// rather than a constant function is what keeps those sessions recoverable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GatewayOwnership {
    /// One gateway, owned by this uid, serves every session.
    Shared(u32),
    /// Each operator's sessions recover against that operator's own gateway.
    PerOperator,
}

/// The sessions that recover against one gateway owner's gateway.
#[derive(Debug, Clone)]
pub struct RecoveryShard {
    /// The uid owning the gateway these sessions recover against.
    pub owner_uid: u32,
    /// The sessions, in the order the input presented them.
    pub sessions: Vec<Session>,
}

/// A recovery's session set, split by the gateway each session recovers
/// against, plus the sessions that belong to no gateway.
///
/// # The residual is a value, not a leftover
///
/// The point of returning both halves from one call is that the second cannot
/// be produced without the first. Sharding by "invoke recovery once per
/// operator" leaves the sessions that matched no operator existing only
/// implicitly — recoverable by unioning the invocations and diffing against
/// the input, which nothing does, and which nothing *can* do when the
/// invocation count is zero. Here the sessions that no shard claimed are
/// returned alongside the shards that claimed the rest, so a caller that
/// wants to ignore them has to write that down.
///
/// The conservation property — every input session lands in exactly one shard
/// or in [`Self::declined`], never both and never neither — is asserted over
/// whole inputs by this module's tests. It is not restated as an invariant
/// comment on the fields, because a comment cannot fail.
#[derive(Debug, Clone)]
pub struct RecoveryPartition {
    shards: Vec<RecoveryShard>,
    declined: Vec<UnresolvedSessionOperator>,
}

impl RecoveryPartition {
    /// The shards, ordered by owner uid.
    ///
    /// Ordered so a caller's per-shard logging and a test's expectations do
    /// not depend on hash iteration order.
    pub fn shards(&self) -> &[RecoveryShard] {
        &self.shards
    }

    /// The sessions no shard claimed, each carrying why.
    pub fn declined(&self) -> &[UnresolvedSessionOperator] {
        &self.declined
    }

    /// Both halves, by value, for a caller that consumes the shards.
    pub fn into_parts(self) -> (Vec<RecoveryShard>, Vec<UnresolvedSessionOperator>) {
        (self.shards, self.declined)
    }
}

/// Split a recovery's candidate sessions by the gateway each recovers against.
///
/// `sessions` is a candidate set — in production, [`sessions_to_recover`]'s
/// output. Partitioning candidates rather than every row keeps the declined
/// list to sessions a recovery would otherwise have acted on; a `Stopped`
/// session nobody could attribute is not something an administrator needs
/// told about.
///
/// `network_for` reads a session's persisted [`NetworkInfo`], and
/// `resolve_uid` maps an account name to a uid — the two hints
/// [`resolve_session_operator`] ranks. Both are consulted lazily and per
/// session, so under [`GatewayOwnership::Shared`] neither runs at all.
///
/// Pure: it reads no file, opens no store and logs nothing. What to do about
/// the sessions it declines is the caller's decision, and a warning emitted
/// here would announce a problem before anyone had decided it was one — the
/// reason [`resolve_session_operator`] is silent too.
///
/// # Shared ownership always yields exactly one shard
///
/// Including for an empty input. A recovery restarts its gateway before it
/// looks at any session, so "no sessions to re-create" and "no gateway to
/// restart" are different answers, and a caller looping over shards would
/// conflate them if an empty candidate set produced no shard. The shard is
/// the gateway; the sessions are its contents.
///
/// Under [`GatewayOwnership::PerOperator`] the reverse holds: a shard appears
/// only for an owner that has at least one session, because an owner with no
/// sessions is not named by anything in the input. A gateway with nothing
/// running on it is that gateway's monitor's business, not this partition's.
pub fn partition_by_gateway_owner(
    sessions: Vec<Session>,
    ownership: GatewayOwnership,
    network_for: &dyn Fn(&Session) -> Option<NetworkInfo>,
    resolve_uid: &dyn Fn(&str) -> Option<u32>,
) -> RecoveryPartition {
    match ownership {
        GatewayOwnership::Shared(owner_uid) => RecoveryPartition {
            shards: vec![RecoveryShard {
                owner_uid,
                sessions,
            }],
            declined: Vec::new(),
        },
        GatewayOwnership::PerOperator => {
            // Keyed by owner and ordered by owner at the end; insertion order
            // within a shard is the input's, so a shard reads as the subsequence
            // of the input that belongs to it.
            let mut by_owner: HashMap<u32, Vec<Session>> = HashMap::new();
            let mut declined = Vec::new();

            for session in sessions {
                let network = network_for(&session);
                match resolve_session_operator(&session, network.as_ref(), resolve_uid) {
                    SessionOperator::Uid(operator_uid) => {
                        by_owner.entry(operator_uid).or_default().push(session);
                    }
                    SessionOperator::Unresolved(unresolved) => declined.push(unresolved),
                }
            }

            let mut shards: Vec<RecoveryShard> = by_owner
                .into_iter()
                .map(|(owner_uid, sessions)| RecoveryShard {
                    owner_uid,
                    sessions,
                })
                .collect();
            shards.sort_by_key(|shard| shard.owner_uid);

            RecoveryPartition { shards, declined }
        }
    }
}

// ---------------------------------------------------------------------------
// GatewayRecoveryDeclines
// ---------------------------------------------------------------------------

/// The sessions the most recent recovery declined to attribute to a gateway.
///
/// A recovery that shards its session set can leave sessions behind, and a
/// session left behind is a `Running` sandbox whose gateway nobody is going to
/// rebuild — potentially with live egress. That is the outcome this daemon
/// exists to prevent, so the residual is held where `GET /diagnostics` can
/// report it rather than being logged once and lost.
///
/// Modelled on [`crate::vmnet_pool_registry::VmnetPoolRegistry::declined_restores`],
/// which reports the same class of thing for slot claims and renders the same
/// way — one `describe()` line per session.
///
/// # Why the last run replaces rather than accumulates
///
/// The list answers "which sessions is recovery currently unable to place",
/// and a recovery re-answers that question in full every time it runs. Keeping
/// earlier runs would report sessions a later run placed, and sessions that
/// have since been deleted, as though they were still stranded. The pool's
/// list accumulates because a restore happens once per daemon lifetime; this
/// one runs on every gateway crash.
pub struct GatewayRecoveryDeclines {
    last_run: std::sync::Mutex<Vec<UnresolvedSessionOperator>>,
}

impl GatewayRecoveryDeclines {
    /// Nothing has been declined: no recovery has run, or the last one placed
    /// every session it was given.
    pub fn new() -> Self {
        Self {
            last_run: std::sync::Mutex::new(Vec::new()),
        }
    }

    /// Replace the list with what the run that just finished declined.
    ///
    /// Recording an empty list is the point of recording at all: it is how a
    /// run that placed everything clears a previous run's report.
    ///
    /// A poisoned lock is recovered rather than propagated, for the reason
    /// [`GatewayRecoveryLatches::for_owner`] gives: refusing to report for the
    /// rest of the process is the worse answer, and the value is replaced
    /// whole so a panic elsewhere cannot leave a half-written list behind.
    pub fn record(&self, declined: Vec<UnresolvedSessionOperator>) {
        *self.last_run.lock().unwrap_or_else(|e| e.into_inner()) = declined;
    }

    /// One human-readable line per declined session, for `/diagnostics`.
    pub fn describe(&self) -> Vec<String> {
        self.last_run
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .map(|declined| declined.describe())
            .collect()
    }
}

impl Default for GatewayRecoveryDeclines {
    fn default() -> Self {
        Self::new()
    }
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
// RecoveryShardDeps
// ---------------------------------------------------------------------------

/// A [`GatewayRecoveryDeps`] that presents one shard's sessions in place of the
/// whole store's.
///
/// [`run_gateway_recovery`] asks its dependencies for a session list and selects
/// its candidates from what comes back. Handing it a shard is therefore all it
/// takes to scope a run to one gateway owner, and it needs no change to the
/// trait: `list_sessions` is already the only question the orchestrator asks
/// about *which* sessions exist, and the other two it asks per session, about a
/// session it was handed.
///
/// Both reads and the write pass to `inner` unchanged. Narrowing them to the
/// shard would be a second filter with no second question behind it — a session
/// in the shard is by construction one this store listed.
///
/// # The candidate filter runs twice, deliberately
///
/// The orchestrator applies [`sessions_to_recover`] to whatever `list_sessions`
/// returns, and a shard from [`partition_by_gateway_owner`] is already that
/// filter's output, so it runs again here. It is idempotent, and leaving it in
/// place is what keeps this an adapter rather than a second entry point: a
/// caller that assembles a shard by some other route still gets the candidate
/// selection every other caller gets.
pub struct RecoveryShardDeps<'a, D: GatewayRecoveryDeps> {
    inner: &'a D,
    sessions: Vec<Session>,
}

impl<'a, D: GatewayRecoveryDeps> RecoveryShardDeps<'a, D> {
    /// Scope `inner`'s session list to `sessions` for the duration of one run.
    pub fn new(inner: &'a D, sessions: Vec<Session>) -> Self {
        Self { inner, sessions }
    }
}

impl<D: GatewayRecoveryDeps> GatewayRecoveryDeps for RecoveryShardDeps<'_, D> {
    fn list_sessions(&self) -> Result<Vec<Session>, SandboxError> {
        Ok(self.sessions.clone())
    }

    fn get_network_info(&self, id: &SessionId) -> Result<Option<NetworkInfo>, SandboxError> {
        self.inner.get_network_info(id)
    }

    fn mark_session_error(&self, id: &SessionId) -> Result<(), SandboxError> {
        self.inner.mark_session_error(id)
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
/// - `latch` — the recovering flag for the gateway being restarted, which the
///   caller takes from [`GatewayRecoveryLatches`] under its owner's uid. Held
///   for the whole run and released however the run ends.
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
            gateway_egress_ip: None,
            operator_uid: None,
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
    // partition_by_gateway_owner (pure split)
    // -----------------------------------------------------------------------

    /// A Running Lima session carrying the two persisted hints the resolver
    /// ranks ahead of the owner name.
    fn attributable_session(owner: &str, operator_uid: Option<u32>) -> Session {
        let mut session = session_with(SessionState::Running, BackendKind::Lima);
        session.owner_username = owner.to_string();
        session.operator_uid = operator_uid;
        session
    }

    /// A network record naming `operator_uid`, the resolver's first hint.
    fn network_owned_by(operator_uid: u32) -> NetworkInfo {
        NetworkInfo {
            operator_uid: Some(operator_uid),
            ..stub_network_info()
        }
    }

    /// A network reader that fails the test if it is consulted.
    fn unused_network(session: &Session) -> Option<NetworkInfo> {
        unreachable!(
            "session {} must not have its network record read when one gateway serves every \
             session",
            session.id
        )
    }

    /// A name resolver that fails the test if it is consulted.
    fn unused_resolver(name: &str) -> Option<u32> {
        unreachable!(
            "the owner name '{name}' must not be resolved when one gateway serves every session"
        )
    }

    /// Every combination of the three hints the resolver ranks, as a session
    /// set with the network records to read alongside it.
    ///
    /// Enumerated rather than hand-picked so the conservation check runs over
    /// every path through the resolver at once, including all three ways a
    /// session can fail to name an operator. Deterministic: same set, same
    /// order, every run.
    fn every_hint_combination() -> (Vec<Session>, HashMap<SessionId, NetworkInfo>) {
        let mut sessions = Vec::new();
        let mut networks = HashMap::new();

        for network_uid in [None, Some(501), Some(502)] {
            for column_uid in [None, Some(501), Some(503)] {
                // "" has no account on it at all; "ghost" names one this host
                // does not have; "alice" resolves.
                for owner in ["", "alice", "ghost"] {
                    let session = attributable_session(owner, column_uid);
                    if let Some(uid) = network_uid {
                        networks.insert(session.id, network_owned_by(uid));
                    }
                    sessions.push(session);
                }
            }
        }

        (sessions, networks)
    }

    /// Resolves only `alice`, to a uid no persisted hint in the generated set
    /// uses — so a session attributed to 504 was attributed by name and by
    /// nothing else.
    fn resolve_alice(name: &str) -> Option<u32> {
        match name {
            "alice" => Some(504),
            _ => None,
        }
    }

    /// Every input session lands in exactly one shard or in the declined
    /// list — never both, never neither.
    ///
    /// This is the property the whole partition exists for: a session that
    /// falls out of it is a `Running` sandbox with live egress that no
    /// recovery will rebuild a gateway for. Asserted over the full
    /// hint-combination set, under both ownership modes, by counting rather
    /// than by spot-checking.
    #[test]
    fn every_session_lands_in_exactly_one_shard_or_the_declined_list() {
        let (sessions, networks) = every_hint_combination();
        let input_ids: Vec<SessionId> = sessions.iter().map(|s| s.id).collect();
        let network_for = |s: &Session| networks.get(&s.id).cloned();

        for ownership in [GatewayOwnership::Shared(0), GatewayOwnership::PerOperator] {
            let partition = partition_by_gateway_owner(
                sessions.clone(),
                ownership,
                &network_for,
                &resolve_alice,
            );

            // Counted rather than compared as sets: a set comparison would
            // pass on a session placed in two shards at once.
            let mut appearances: HashMap<SessionId, usize> = HashMap::new();
            let mut total = 0usize;
            for id in partition
                .shards()
                .iter()
                .flat_map(|shard| shard.sessions.iter().map(|s| s.id))
                .chain(partition.declined().iter().map(|d| d.session_id))
            {
                *appearances.entry(id).or_default() += 1;
                total += 1;
            }

            for id in &input_ids {
                assert_eq!(
                    appearances.get(id).copied().unwrap_or(0),
                    1,
                    "{ownership:?}: session {id} must appear exactly once across the shards \
                     and the declined list"
                );
            }
            // With every input session appearing exactly once, an equal total
            // leaves no room for anything the input did not contain.
            assert_eq!(
                total,
                input_ids.len(),
                "{ownership:?}: the shards and the declined list together must account for \
                 nothing beyond the input"
            );
        }
    }

    /// Under per-operator ownership every generated session is placed by the
    /// hint the resolver ranks highest, and the ones no hint answers for are
    /// declined with a reason naming what was missing.
    #[test]
    fn per_operator_shards_by_the_highest_ranked_hint() {
        let (sessions, networks) = every_hint_combination();
        let network_for = |s: &Session| networks.get(&s.id).cloned();

        let partition = partition_by_gateway_owner(
            sessions,
            GatewayOwnership::PerOperator,
            &network_for,
            &resolve_alice,
        );

        // 27 sessions: 18 have a network uid (9 × 501, 9 × 502); of the 9
        // without, 3 carry column 501, 3 carry column 503, and the remaining
        // 3 are placed by name only when the name resolves.
        let counts: HashMap<u32, usize> = partition
            .shards()
            .iter()
            .map(|shard| (shard.owner_uid, shard.sessions.len()))
            .collect();
        assert_eq!(
            counts,
            HashMap::from([(501, 12), (502, 9), (503, 3), (504, 1)]),
            "each shard must hold the sessions whose highest-ranked hint names its owner"
        );

        assert_eq!(
            partition.declined().len(),
            2,
            "the two sessions with no uid hint and an unusable owner name must be declined"
        );
        let reasons: Vec<&str> = partition
            .declined()
            .iter()
            .map(|d| d.reason.as_str())
            .collect();
        assert!(
            reasons.iter().any(|r| r.contains("no owner account")),
            "the session with no name at all must say so: {reasons:?}"
        );
        assert!(
            reasons.iter().any(|r| r.contains("does not resolve")),
            "the session whose owner names no account on this host must say so: {reasons:?}"
        );
    }

    /// Shards come back ordered by owner uid, and within a shard the input's
    /// order survives — so a caller's per-shard logging and a test's
    /// expectations do not ride on hash iteration order.
    #[test]
    fn shards_are_ordered_by_owner_and_hold_the_input_order_within() {
        let first = attributable_session("", Some(700));
        let second = attributable_session("", Some(600));
        let third = attributable_session("", Some(700));
        let expected_700 = vec![first.id, third.id];

        let partition = partition_by_gateway_owner(
            vec![first, second, third],
            GatewayOwnership::PerOperator,
            &|_| None,
            &unused_resolver,
        );

        let owners: Vec<u32> = partition.shards().iter().map(|s| s.owner_uid).collect();
        assert_eq!(
            owners,
            vec![600, 700],
            "shards must be ordered by owner uid"
        );

        let ids: Vec<SessionId> = partition.shards()[1]
            .sessions
            .iter()
            .map(|s| s.id)
            .collect();
        assert_eq!(
            ids, expected_700,
            "a shard must read as the subsequence of the input that belongs to it"
        );
    }

    /// One gateway serving every session yields one shard whatever the
    /// sessions say about their operators — including sessions no resolver
    /// could attribute.
    ///
    /// This is the behaviour that keeps today's daemon recovering everything
    /// it recovers now: an unattributable session is not a session without a
    /// gateway when there is only one gateway.
    #[test]
    fn shared_ownership_yields_one_shard_holding_every_session() {
        let sessions = vec![
            attributable_session("", None),
            attributable_session("ghost", None),
            attributable_session("alice", Some(501)),
        ];
        let ids: Vec<SessionId> = sessions.iter().map(|s| s.id).collect();

        let partition = partition_by_gateway_owner(
            sessions,
            GatewayOwnership::Shared(77),
            &unused_network,
            &unused_resolver,
        );

        assert_eq!(partition.shards().len(), 1, "one gateway is one shard");
        assert_eq!(partition.shards()[0].owner_uid, 77);
        assert_eq!(
            partition.shards()[0]
                .sessions
                .iter()
                .map(|s| s.id)
                .collect::<Vec<_>>(),
            ids,
            "every session recovers against the one gateway, in input order"
        );
        assert!(
            partition.declined().is_empty(),
            "nothing can be declined when the one gateway serves every session"
        );
    }

    /// An empty candidate set still yields a shard when one gateway serves
    /// every session.
    ///
    /// A recovery restarts its gateway before it looks at any session, so a
    /// caller looping over shards must still be handed the gateway to
    /// restart. Producing no shard here would turn "nothing to re-create"
    /// into "nothing to restart", and a crashed gateway would stay down.
    #[test]
    fn shared_ownership_yields_a_shard_for_an_empty_session_set() {
        let partition = partition_by_gateway_owner(
            Vec::new(),
            GatewayOwnership::Shared(77),
            &unused_network,
            &unused_resolver,
        );

        assert_eq!(
            partition.shards().len(),
            1,
            "the gateway to restart exists whether or not anything is running on it"
        );
        assert_eq!(partition.shards()[0].owner_uid, 77);
        assert!(partition.shards()[0].sessions.is_empty());
    }

    /// With a gateway per operator, an empty candidate set names no owner, so
    /// there is nothing to act on. The mirror image of the shared case, and
    /// the reason the two are separate arms rather than one uid mapping.
    #[test]
    fn per_operator_ownership_yields_no_shard_for_an_empty_session_set() {
        let partition = partition_by_gateway_owner(
            Vec::new(),
            GatewayOwnership::PerOperator,
            &unused_network,
            &unused_resolver,
        );

        assert!(partition.shards().is_empty());
        assert!(partition.declined().is_empty());
    }

    /// `into_parts` hands back exactly what the accessors report.
    #[test]
    fn into_parts_yields_the_same_shards_and_declines_the_accessors_report() {
        let sessions = vec![
            attributable_session("alice", Some(501)),
            attributable_session("", None),
        ];

        let partition = partition_by_gateway_owner(
            sessions,
            GatewayOwnership::PerOperator,
            &|_| None,
            &resolve_alice,
        );
        let borrowed_shards: Vec<u32> = partition.shards().iter().map(|s| s.owner_uid).collect();
        let borrowed_declines: Vec<SessionId> =
            partition.declined().iter().map(|d| d.session_id).collect();

        let (shards, declined) = partition.into_parts();
        assert_eq!(
            shards.iter().map(|s| s.owner_uid).collect::<Vec<_>>(),
            borrowed_shards
        );
        assert_eq!(
            declined.iter().map(|d| d.session_id).collect::<Vec<_>>(),
            borrowed_declines
        );
    }

    // -----------------------------------------------------------------------
    // GatewayRecoveryDeclines (what /diagnostics reports)
    // -----------------------------------------------------------------------

    #[test]
    fn nothing_is_declined_before_a_recovery_has_run() {
        assert!(GatewayRecoveryDeclines::new().describe().is_empty());
    }

    #[test]
    fn a_declined_session_is_described_with_its_owner_and_the_reason() {
        let session = attributable_session("ghost", None);
        let sid = session.id;
        let partition = partition_by_gateway_owner(
            vec![session],
            GatewayOwnership::PerOperator,
            &|_| None,
            &resolve_alice,
        );

        let declines = GatewayRecoveryDeclines::new();
        declines.record(partition.into_parts().1);

        let lines = declines.describe();
        assert_eq!(lines.len(), 1);
        assert!(
            lines[0].contains(&sid.to_string()) && lines[0].contains("ghost"),
            "the report must name the session and its owner: {}",
            lines[0]
        );
    }

    /// A later run replaces an earlier run's report rather than adding to it.
    ///
    /// Recovery re-answers "which sessions can I not place" in full every
    /// time it runs, so a session a later run placed — or one that has since
    /// been deleted — must stop being reported as stranded.
    #[test]
    fn a_later_run_replaces_what_an_earlier_run_declined() {
        let stranded = attributable_session("ghost", None);
        let first = partition_by_gateway_owner(
            vec![stranded],
            GatewayOwnership::PerOperator,
            &|_| None,
            &resolve_alice,
        );

        let declines = GatewayRecoveryDeclines::new();
        declines.record(first.into_parts().1);
        assert_eq!(declines.describe().len(), 1);

        let placed = attributable_session("alice", None);
        let second = partition_by_gateway_owner(
            vec![placed],
            GatewayOwnership::PerOperator,
            &|_| None,
            &resolve_alice,
        );
        declines.record(second.into_parts().1);

        assert!(
            declines.describe().is_empty(),
            "a run that placed every session must clear the previous run's report"
        );
    }

    // -----------------------------------------------------------------------
    // RecoveryShardDeps (scoping one run to one gateway owner)
    // -----------------------------------------------------------------------

    /// The adapter answers "which sessions" from the shard and every other
    /// question from the store behind it.
    #[test]
    fn shard_deps_lists_the_shard_and_delegates_the_rest() {
        let in_shard = session_with(SessionState::Running, BackendKind::Lima);
        let elsewhere = session_with(SessionState::Running, BackendKind::Lima);
        let in_shard_id = in_shard.id;
        let elsewhere_id = elsewhere.id;

        let store = StubDeps::new(vec![in_shard.clone(), elsewhere]);
        let shard = RecoveryShardDeps::new(&store, vec![in_shard]);

        assert_eq!(
            shard.list_sessions().unwrap().len(),
            1,
            "the adapter must list the shard, not the store"
        );

        // The reads and the write are the store's, unnarrowed: a session id
        // the shard does not hold is still a session this store knows.
        assert!(
            shard.get_network_info(&elsewhere_id).unwrap().is_some(),
            "network info must come from the store, not be filtered by the shard"
        );
        shard.mark_session_error(&elsewhere_id).unwrap();
        assert_eq!(*store.errors_marked.lock().unwrap(), vec![elsewhere_id]);
        assert_ne!(in_shard_id, elsewhere_id);
    }

    /// A recovery driven through a shard acts only on that shard's sessions,
    /// even though the store behind it holds another owner's too.
    ///
    /// This is the whole point of the change: before it, one recovery pass
    /// re-created every session's gateway against one gateway VM.
    #[tokio::test]
    async fn recovery_through_a_shard_touches_no_other_owners_sessions() {
        let mine = session_with(SessionState::Running, BackendKind::Lima);
        let theirs = session_with(SessionState::Running, BackendKind::Lima);
        let mine_id = mine.id;
        let theirs_id = theirs.id;

        let store = StubDeps::new(vec![mine.clone(), theirs]);
        let shard = RecoveryShardDeps::new(&store, vec![mine]);

        let (networking_status, latch) = make_recovery_state();
        let recovered: Arc<Mutex<Vec<SessionId>>> = Arc::new(Mutex::new(Vec::new()));
        let rec = Arc::clone(&recovered);

        run_gateway_recovery(
            &shard,
            Arc::clone(&networking_status),
            latch,
            || async { Ok::<(), String>(()) },
            |session_id, owner, _info| {
                let rec = Arc::clone(&rec);
                async move {
                    rec.lock().unwrap().push(session_id);
                    (session_id, owner, Ok(()))
                }
            },
            |_session_id, _owner| async {},
            8,
        )
        .await;

        assert_eq!(
            *recovered.lock().unwrap(),
            vec![mine_id],
            "only the shard's sessions may have their gateway re-created"
        );
        assert!(
            !networking_status.lock().await.contains_key(&theirs_id),
            "another owner's session must not even be tagged by this run"
        );
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

        // The explicit `return` is the subject of the test, not an oversight:
        // collapsing it into the surrounding control flow would remove the
        // early-exit path whose drop behavior this exercises.
        #[allow(clippy::needless_return)]
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

    // -----------------------------------------------------------------------
    // GatewayRecoveryLatches (one latch per gateway owner)
    // -----------------------------------------------------------------------

    /// The defect the map exists to remove: one owner's recovery must leave
    /// every other owner's latch clear, so a monitor reading for a healthy
    /// gateway is not told to stand down.
    #[test]
    fn engaging_one_owners_latch_leaves_another_owners_clear() {
        let latches = GatewayRecoveryLatches::new();

        let _guard = GatewayRecoveringGuard::engage(&latches.for_owner(1001));

        assert!(latches.is_recovering(1001));
        assert!(
            !latches.is_recovering(1002),
            "a recovery of 1001's gateway must not report 1002's as recovering"
        );
    }

    /// Every lookup for an owner yields the same latch. Without this the
    /// writer would engage one `AtomicBool` and the reader would poll a
    /// different one, and the reader would never see a recovery at all.
    #[test]
    fn an_owner_gets_the_same_latch_on_every_lookup() {
        let latches = GatewayRecoveryLatches::new();

        assert!(Arc::ptr_eq(
            &latches.for_owner(1001),
            &latches.for_owner(1001)
        ));
        assert!(!Arc::ptr_eq(
            &latches.for_owner(1001),
            &latches.for_owner(1002)
        ));
    }

    /// Releasing one owner's recovery does not release another's.
    #[test]
    fn dropping_one_owners_guard_leaves_another_owner_recovering() {
        let latches = GatewayRecoveryLatches::new();
        let _held = GatewayRecoveringGuard::engage(&latches.for_owner(1002));

        {
            let _transient = GatewayRecoveringGuard::engage(&latches.for_owner(1001));
        }

        assert!(!latches.is_recovering(1001));
        assert!(
            latches.is_recovering(1002),
            "1001's guard dropping must not clear the latch 1002 still holds"
        );
    }

    /// An owner nobody has recovered is not recovering, and asking does not
    /// give them a latch — a monitor polling per session must not grow the map
    /// with an entry per owner it happens to see.
    #[test]
    fn an_unknown_owner_is_not_recovering_and_is_not_recorded() {
        let latches = GatewayRecoveryLatches::new();

        assert!(!latches.is_recovering(1001));
        assert_eq!(latches.len(), 0);
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
