//! Library surface for the sandbox daemon.
//!
//! Items that escape the binary:
//!
//! * [`events_http`] — `GET /sessions/{id}/events` (M10-S4 Phase 2/3).
//! * [`policy_http`] — `GET /sessions/{id}/policy/propagation-status`
//!   (M10-S6 todo #37). The read-only status endpoint that the
//!   `sandbox policy status [--wait]` CLI and the E2E suite poll to
//!   decide when a just-applied policy has reached steady state.
//! * [`propagation`] — the per-session propagation-state registry that
//!   both sub-routers and the main binary's apply/clear paths mutate
//!   and read.
//!
//! Integration tests under `sandboxd/sandboxd/tests/` drive each sub-
//! router through tower's `ServiceExt::oneshot`, which requires the
//! handlers + minimal state to live in a library target rather than
//! the binary.
//!
//! The production daemon binary (`src/main.rs`) builds its full
//! `AppState` independently and merges every sub-router listed above
//! into the top-level router. Each sub-state is a thin handle over
//! shared [`sandbox_core::SessionStore`] + [`sandbox_core::EventBus`] +
//! [`propagation::PropagationStates`] references, so the daemon does
//! not pay a double-allocation cost.
//!
//! No other main-binary internals are re-exported here — keep this
//! surface as narrow as possible.

pub mod error;
pub mod events_http;
pub mod policy_http;
pub mod propagation;
