//! JSONL ingest pipeline — the sandboxd-side consumer of structured event
//! files written by the three policy-enforcing subcomponents inside the
//! gateway container.
//!
//! Spec reference: `.tasks/specs/2026-04-21-port-explicit-policies-presets-
//! observability-design.md`, Part 3 "Envoy access log", "CoreDNS structured
//! emission", "mitmproxy structured emission", and the session-ID stamping
//! paragraph in "Event shape" ("session-ID attribution is sandboxd's job,
//! not each component's"). Phase 7 of the M10-S2 plan.
//!
//! # Shape
//!
//! `create_gateway` bind-mounts a per-session host directory
//! [`crate::events::session_events_host_dir`] into
//! [`crate::events::EVENTS_DIR_IN_CONTAINER`]. The three producers inside
//! the container — Envoy (access log as JSON), the CoreDNS plugin
//! (`EventWriter`), the mitmproxy addon (`EventEmitter`) — append one
//! JSON record per line to `envoy.jsonl`, `coredns.jsonl`, and
//! `mitmproxy.jsonl` respectively.
//!
//! Sandboxd spawns one [`SessionIngestor`] per session after the gateway
//! has finished starting. The ingestor runs a background task that:
//!
//! 1. Watches the events directory for create/modify/moved-to
//!    notifications via `notify::RecommendedWatcher` (inotify on Linux).
//! 2. For every known file name (`envoy.jsonl`, `coredns.jsonl`,
//!    `mitmproxy.jsonl`) spawns a [`jsonl_reader::JsonlTailer`] that
//!    reads from the current offset to EOF on every wake, parses each
//!    complete line, and forwards the resulting [`crate::events::Event`]
//!    to the shared [`crate::events::EventBus`] after stamping
//!    `session_id` via the [`crate::events::VmIpSessionMap`].
//! 3. Ticks a 2-second fallback timer that re-scans all active tailers
//!    even in the absence of inotify events. Virtiofs / 9p propagate
//!    notifications unreliably under some hypervisor configurations,
//!    so the poll is not optional.
//!
//! # Per-layer parsers
//!
//! Each layer owns a module (`envoy`, `coredns`, `mitmproxy`) that
//! parses the on-disk JSON record into a [`crate::events::TrafficEvent`]
//! and returns the originating `src_ip` (Envoy) / `client_ip`
//! (CoreDNS / mitmproxy) for [`crate::events::VmIpSessionMap::lookup`].
//! Records we cannot attribute (unknown VM IP) are dropped with a
//! `tracing::warn!` line rather than published to a fabricated session —
//! see the "drop events on vm_ip miss" note in the plan.
//!
//! # Shutdown
//!
//! [`SessionIngestor::abort`] aborts the inner task; tailers the task
//! spawned will be dropped with their file handles released. This is
//! symmetric with `create_gateway` / `stop_gateway` on the sandboxd side.

use std::path::PathBuf;

use tokio::task::JoinHandle;
use tracing::info;

use crate::events::{EventBus, VmIpSessionMap};
use crate::session::SessionId;

pub mod coredns;
pub mod envoy;
pub mod jsonl_reader;
pub mod mitmproxy;
pub mod watcher;

/// Handle to a spawned per-session ingest task.
///
/// Holding one of these keeps the background task alive; dropping it
/// without calling [`SessionIngestor::abort`] leaves the task running
/// (it owns file handles, inotify watches, and the 2s poll timer). The
/// daemon stores one per session in `AppState` and aborts on
/// `stop_session` / `remove_session`.
pub struct SessionIngestor {
    session_id: SessionId,
    handle: JoinHandle<()>,
}

impl SessionIngestor {
    /// Spawn the ingest background task for a session.
    ///
    /// The task runs [`watcher::run_watcher`], which sets up the inotify
    /// watch on `events_dir`, spawns tailers for any JSONL files that
    /// already exist, and handles subsequent create / modify / moved-to
    /// events for the lifetime of the task.
    ///
    /// Returns a handle the caller stores on `AppState`. The task does
    /// not complete on its own — it runs until [`SessionIngestor::abort`]
    /// is called or the containing runtime shuts down.
    pub fn spawn(
        session_id: SessionId,
        events_dir: PathBuf,
        bus: EventBus,
        vm_ip_map: VmIpSessionMap,
    ) -> Self {
        info!(
            session_id = %session_id,
            events_dir = %events_dir.display(),
            "spawning session event ingestor"
        );
        let handle = tokio::spawn(async move {
            watcher::run_watcher(session_id, events_dir, bus, vm_ip_map).await;
        });
        Self { session_id, handle }
    }

    /// Abort the ingest task.
    ///
    /// Cooperative cancellation: the task may be blocked on a
    /// `tokio::select!` between the inotify receiver and the 2s poll
    /// tick; `abort` interrupts at the next yield point. Subsequent
    /// events written to the ingest dir are not picked up — a fresh
    /// [`SessionIngestor::spawn`] call would be required.
    pub fn abort(self) {
        info!(session_id = %self.session_id, "aborting session event ingestor");
        self.handle.abort();
    }

    /// The session this ingestor serves. Exposed for tests and the
    /// `AppState` bookkeeping map.
    pub fn session_id(&self) -> &SessionId {
        &self.session_id
    }
}
