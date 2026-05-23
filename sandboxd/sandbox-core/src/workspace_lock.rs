//! Per-session workspace-lock state machine for operator-driven
//! `sandbox workspace push|pull` orchestration.
//!
//! Exports a small pure-data API consumed by the daemon's HTTP
//! handlers and (via DTO mappers) by the CLI. The module deliberately
//! has no I/O, no async, and no awareness of the daemon's `AppState`
//! shape — the per-session `Arc<tokio::sync::Mutex<LockState>>` that
//! wraps these values lives on the daemon's `AppState` and is wired
//! up in a later phase.
//!
//! ## Lifecycle
//!
//! `LockState::new()` returns `Unlocked`. `acquire(op)` transitions
//! to `Locked { op, token }` and returns the freshly-minted
//! `LockToken`; the operator-driven CLI carries that token back to
//! the daemon on the `release` call. `release(token, force)` returns
//! to `Unlocked` either when the supplied token matches the held one
//! *or* when `force == true` (operator escape hatch for
//! orphan-lock recovery). The state-machine is per-process — it is
//! deliberately **not** persisted to the session store, so a daemon
//! restart resets every session to `Unlocked`. Lock state is not persisted.
//!
//! ## Wire shape
//!
//! `WorkspaceOp` round-trips as `"push"` / `"pull"` (snake_case) on
//! the wire. `LockToken` round-trips as the standard hyphenated UUID
//! string so the wire stays stable even if the in-process token
//! representation later changes. The release-handler treats
//! unparseable strings as a sentinel "wrong token" so the
//! adjudication path stays uniform (force-release token semantics).

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::error::SandboxError;

/// Opaque per-acquire token returned to the operator.
///
/// Newtype over [`uuid::Uuid`] so the wire surface and the call sites
/// stay insulated from the underlying representation. The release
/// handler compares tokens byte-wise via `PartialEq`; the all-zeroes
/// "nil" UUID is reserved as a sentinel for unparseable input on the
/// release path (force-release semantics).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct LockToken(uuid::Uuid);

impl LockToken {
    /// Mint a fresh random token. Wraps `uuid::Uuid::new_v4()` — the
    /// caller is responsible for serialising acquire calls so two
    /// concurrent invocations cannot both observe an `Unlocked`
    /// state.
    pub fn new_v4() -> Self {
        Self(uuid::Uuid::new_v4())
    }

    /// All-zeroes sentinel used by the release path to represent an
    /// unparseable supplied token. Guaranteed not to match any
    /// freshly-minted `new_v4()` token.
    pub fn nil() -> Self {
        Self(uuid::Uuid::nil())
    }
}

impl fmt::Display for LockToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl FromStr for LockToken {
    type Err = uuid::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self(uuid::Uuid::from_str(s)?))
    }
}

impl Serialize for LockToken {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.collect_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for LockToken {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        uuid::Uuid::from_str(&s)
            .map(Self)
            .map_err(serde::de::Error::custom)
    }
}

/// Which workspace operation currently holds the lock.
///
/// Wire form is `"push"` / `"pull"` lowercase (snake_case derive) so
/// the DTO mirror in [`crate::api::dto::WorkspaceOpDto`] can
/// round-trip without a custom (de)serializer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkspaceOp {
    Push,
    Pull,
}

impl fmt::Display for WorkspaceOp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Push => f.write_str("push"),
            Self::Pull => f.write_str("pull"),
        }
    }
}

/// Per-session lock-state machine.
///
/// `Unlocked` is the steady state. `acquire(op)` transitions to
/// `Locked { op, token }`; subsequent `acquire` calls return
/// [`SandboxError::Conflict`] until a matching `release` (or a
/// `force = true` release) returns to `Unlocked`. A daemon restart
/// always reconstructs `Unlocked` because nothing in the persisted
/// session record encodes the lock — see [`LockState::new`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LockState {
    Unlocked,
    Locked { op: WorkspaceOp, token: LockToken },
}

impl Default for LockState {
    fn default() -> Self {
        Self::new()
    }
}

impl LockState {
    /// Construct a fresh `Unlocked` state. Used at daemon startup and
    /// on first-touch lazy insert into the per-session lock map; the
    /// "no restoration on construct" property is load-bearing for the
    /// restart-resets-locks contract pinned by the inline test below.
    pub fn new() -> Self {
        Self::Unlocked
    }

    /// Attempt to acquire the lock for `op`. On `Unlocked`, mints a
    /// fresh [`LockToken`], transitions to `Locked`, and returns the
    /// token. On `Locked`, returns
    /// [`SandboxError::Conflict`] with a message naming the
    /// currently-active op (so the operator can decide whether to
    /// wait, cancel, or force-unlock).
    pub fn acquire(&mut self, op: WorkspaceOp) -> Result<LockToken, SandboxError> {
        match self {
            Self::Unlocked => {
                let token = LockToken::new_v4();
                *self = Self::Locked { op, token };
                Ok(token)
            }
            Self::Locked { op: active_op, .. } => Err(SandboxError::Conflict(format!(
                "session has an active {active_op} operation"
            ))),
        }
    }

    /// Release the lock.
    ///
    /// * `Unlocked` → always `Ok(())` (idempotent — re-issuing
    ///   `unlock` after a clean release is a no-op).
    /// * `Locked` with matching token → transition to `Unlocked`,
    ///   return `Ok(())`.
    /// * `Locked` with mismatched token + `force == true` →
    ///   transition to `Unlocked`, return `Ok(())` (operator escape
    ///   hatch for orphan-lock recovery via
    ///   `sandbox workspace unlock --force`).
    /// * `Locked` with mismatched token + `force == false` →
    ///   [`SandboxError::Conflict`] with the standard
    ///   `"lock_token mismatch; pass force=true to override"`
    ///   message.
    pub fn release(&mut self, token: &LockToken, force: bool) -> Result<(), SandboxError> {
        match self {
            Self::Unlocked => Ok(()),
            Self::Locked {
                token: held_token, ..
            } => {
                if force || held_token == token {
                    *self = Self::Unlocked;
                    Ok(())
                } else {
                    Err(SandboxError::Conflict(
                        "lock_token mismatch; pass force=true to override".into(),
                    ))
                }
            }
        }
    }

    /// `true` iff the lock is currently held.
    pub fn is_locked(&self) -> bool {
        matches!(self, Self::Locked { .. })
    }

    /// Return the currently-active op, if any.
    pub fn active_op(&self) -> Option<WorkspaceOp> {
        match self {
            Self::Unlocked => None,
            Self::Locked { op, .. } => Some(*op),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `Unlocked` → `acquire(push)` mints a token and transitions to
    /// `Locked`. Pins the happy-path entry into the state machine.
    #[test]
    fn acquire_when_unlocked_succeeds() {
        let mut state = LockState::new();
        let token = state
            .acquire(WorkspaceOp::Push)
            .expect("acquire on Unlocked must succeed");
        assert!(state.is_locked());
        assert_eq!(state.active_op(), Some(WorkspaceOp::Push));
        match state {
            LockState::Locked { op, token: held } => {
                assert_eq!(op, WorkspaceOp::Push);
                assert_eq!(held, token);
            }
            other => panic!("expected Locked, got {other:?}"),
        }
    }

    /// `acquire` on `Locked` returns `Conflict` and the message names
    /// the currently-active op. Covers all four op-pair combinations
    /// to pin the message content (all four op-pair combinations).
    #[test]
    fn acquire_when_locked_returns_conflict() {
        for (held, attempted) in [
            (WorkspaceOp::Push, WorkspaceOp::Push),
            (WorkspaceOp::Push, WorkspaceOp::Pull),
            (WorkspaceOp::Pull, WorkspaceOp::Push),
            (WorkspaceOp::Pull, WorkspaceOp::Pull),
        ] {
            let mut state = LockState::new();
            state.acquire(held).expect("seed acquire must succeed");
            let err = state
                .acquire(attempted)
                .expect_err("second acquire on Locked must fail");
            match err {
                SandboxError::Conflict(msg) => {
                    let needle = format!("active {held} operation");
                    assert!(
                        msg.contains(&needle),
                        "conflict message must name held op `{held}`; got: {msg}"
                    );
                }
                other => panic!("expected Conflict, got {other:?}"),
            }
        }
    }

    /// `release(token, false)` with the correct token transitions
    /// `Locked` → `Unlocked` and returns `Ok`.
    #[test]
    fn release_with_correct_token_unlocks() {
        let mut state = LockState::new();
        let token = state.acquire(WorkspaceOp::Push).expect("acquire");
        state.release(&token, false).expect("release must succeed");
        assert!(!state.is_locked());
        assert!(state.active_op().is_none());
        assert_eq!(state, LockState::Unlocked);
    }

    /// `release(wrong_token, false)` on `Locked` returns `Conflict`
    /// without mutating state.
    #[test]
    fn release_with_wrong_token_returns_conflict() {
        let mut state = LockState::new();
        let _held = state.acquire(WorkspaceOp::Push).expect("acquire");
        let wrong = LockToken::new_v4();
        let err = state
            .release(&wrong, false)
            .expect_err("mismatched release must fail");
        match err {
            SandboxError::Conflict(msg) => {
                assert!(
                    msg.contains("lock_token mismatch"),
                    "conflict message must say `lock_token mismatch`; got: {msg}"
                );
                assert!(
                    msg.contains("force=true"),
                    "conflict message must point at force=true; got: {msg}"
                );
            }
            other => panic!("expected Conflict, got {other:?}"),
        }
        // State must still be Locked — a failed release does not
        // alter the lock.
        assert!(state.is_locked());
    }

    /// `release(any_token, true)` on `Locked` returns to `Unlocked`
    /// regardless of token match. Operator escape hatch for orphan
    /// recovery.
    #[test]
    fn release_with_force_ignores_token() {
        let mut state = LockState::new();
        let _held = state.acquire(WorkspaceOp::Pull).expect("acquire");
        let unrelated = LockToken::new_v4();
        state
            .release(&unrelated, true)
            .expect("force-release must succeed");
        assert_eq!(state, LockState::Unlocked);
    }

    /// `release` on `Unlocked` is a no-op for both `force=false` and
    /// `force=true`. Pins the idempotent-release contract operators
    /// see when re-issuing `unlock` after a clean release.
    #[test]
    fn release_when_already_unlocked_is_idempotent() {
        let mut state = LockState::new();
        let any = LockToken::new_v4();
        state.release(&any, false).expect("release on Unlocked");
        assert_eq!(state, LockState::Unlocked);
        state.release(&any, true).expect("force on Unlocked");
        assert_eq!(state, LockState::Unlocked);
    }

    /// `LockState::new()` returns `Unlocked`. The lock is per-process
    /// and not persisted; a daemon restart reconstructs every entry
    /// via `new()`. Pinning this explicitly so a later "load from
    /// store" addition would have to delete this test.
    #[test]
    fn restart_resets_locks() {
        assert_eq!(LockState::new(), LockState::Unlocked);
        assert!(!LockState::new().is_locked());
        assert!(LockState::new().active_op().is_none());
    }

    /// `LockToken::Display` and `FromStr` round-trip the UUID string
    /// representation.
    #[test]
    fn lock_token_round_trip() {
        let token = LockToken::new_v4();
        let s = token.to_string();
        let parsed = LockToken::from_str(&s).expect("from_str of own Display must succeed");
        assert_eq!(parsed, token);
    }

    /// `LockToken::from_str` rejects non-UUID input. Unparseable
    /// strings must not silently round-trip to a sentinel — the
    /// release-handler is the only site that converts garbage into
    /// the nil sentinel (and it does so via an explicit
    /// `from_str(...).unwrap_or_else(|_| LockToken::nil())`, not via
    /// the parser).
    #[test]
    fn lock_token_from_str_rejects_garbage() {
        assert!(LockToken::from_str("not-a-uuid").is_err());
        assert!(LockToken::from_str("").is_err());
        assert!(LockToken::from_str("12345").is_err());
    }
}
