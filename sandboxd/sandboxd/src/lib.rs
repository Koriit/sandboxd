//! Library surface for the sandbox daemon.
//!
//! Today the only item that escapes the binary is the HTTP endpoint for
//! the event access surface — `GET /sessions/{id}/events`, landed in
//! M10-S4 Phase 2.  Integration tests under `sandboxd/sandboxd/tests/`
//! drive it through tower's `ServiceExt::oneshot`, which requires the
//! handler + minimal state to live in a library target rather than the
//! binary.
//!
//! The production daemon binary (`src/main.rs`) builds its full
//! `AppState` independently and merges [`events_http::events_router`]
//! into the top-level router.
//! The sub-state owned by the events router (see
//! [`events_http::EventsApiState`]) is a thin handle over shared
//! [`sandbox_core::SessionStore`] + [`sandbox_core::EventBus`]
//! references, so the daemon does not pay a double-allocation cost.
//!
//! No other main-binary internals are re-exported here — keep this
//! surface as narrow as possible.

pub mod error;
pub mod events_http;
