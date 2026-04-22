//! Unified event stream: domain types.
//!
//! The event surface is defined by spec Part 3 of
//! `.tasks/specs/2026-04-21-port-explicit-policies-presets-observability-
//! design.md`. This module holds the domain representation of events.
//! The wire (JSON) shape and the domain → wire mapper live in
//! [`crate::api::event_dto`] and [`crate::api::event_mapper`] respectively.
//!
//! Subsequent phases of M10-S2 add:
//!
//! - `bus.rs` — per-session ring buffer (Phase 2).
//! - `vm_ip_map.rs` — vm-ip → session-id lookup (Phase 2).
//! - `lifecycle.rs` — sandboxd-side emitters (Phase 5).
//! - `ingest/` — JSONL-tail producers into the bus (Phase 7).

use std::path::PathBuf;

use crate::session::SessionId;

pub mod bus;
pub mod envelope;
pub mod ingest;
pub mod lifecycle;
pub mod persist;
pub mod vm_ip_map;

pub use bus::{
    DEFAULT_BROADCAST_CAPACITY, DEFAULT_RING_BUFFER_SIZE, EventBus, EventBusConfig,
    EventSubscription,
};
pub use envelope::{
    DenyLoggerDeny, DenyLoggerEvent, DenyProtocol, DnsEvent, EnvoyConnection, EnvoyEvent, Event,
    EventEnvelope, GatewayShutdownReason, HealthComponent, LifecycleEvent, MitmproxyEvent,
    PolicyApplyStatus, TrafficEvent,
};
pub use persist::{PersistConfig, PersistentSink};
pub use vm_ip_map::VmIpSessionMap;

/// Root directory on the host under which per-session event directories
/// live. `sandboxd` bind-mounts `${root}/<session-id>/` into each gateway
/// container at `/var/log/gateway/events/` so the three JSONL producers
/// (Envoy access log, CoreDNS plugin, mitmproxy addon) can write structured
/// events that sandboxd's ingest layer tails via `inotify`.
///
/// Using `/tmp` mirrors [`crate::atomic_listener_writer::LISTENER_HOST_ROOT`]:
/// short path (Docker on some platforms limits bind-mount path length),
/// non-persistent across host reboots (sessions are ephemeral anyway),
/// colocated with the session's other transient state.
pub const EVENTS_HOST_ROOT: &str = "/tmp/sandboxd-events";

/// Directory inside the gateway container where the three JSONL producers
/// (Envoy access log, CoreDNS plugin, mitmproxy addon) write their event
/// files. `sandboxd` bind-mounts [`session_events_host_dir`] onto this
/// path when starting the gateway container.
///
/// Kept narrower than the image-wide `/var/log` tmpfs so unstructured
/// per-component text logs (`envoy.log`, `mitmproxy.log`, `coredns.log`)
/// stay on the tmpfs for in-container operator debugging while the
/// structured JSONL files are exposed to the host ingest path.
pub const EVENTS_DIR_IN_CONTAINER: &str = "/var/log/gateway/events";

/// Return the host-side events directory for `session_id`.
///
/// This directory is bind-mounted into the gateway container as
/// [`EVENTS_DIR_IN_CONTAINER`]. The three JSONL producers inside the
/// container write `envoy.jsonl`, `coredns.jsonl`, and `mitmproxy.jsonl`
/// into this directory; sandboxd's ingest layer tails them via `inotify`.
pub fn session_events_host_dir(session_id: &SessionId) -> PathBuf {
    PathBuf::from(EVENTS_HOST_ROOT).join(session_id.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_events_host_dir_concatenates_root_and_session_id() {
        let sid = SessionId::parse("0123456789ab").unwrap();
        let dir = session_events_host_dir(&sid);
        assert_eq!(
            dir,
            PathBuf::from(EVENTS_HOST_ROOT).join("0123456789ab"),
            "events host dir must be <root>/<session_id>"
        );
    }

    #[test]
    fn session_events_host_dirs_are_per_session() {
        let a = SessionId::generate();
        let b = SessionId::generate();
        assert_ne!(
            session_events_host_dir(&a),
            session_events_host_dir(&b),
            "per-session events host dirs must differ"
        );
    }

    #[test]
    fn events_host_root_is_tmp_path() {
        // Mirror the atomic_listener_writer rationale: host root lives
        // under /tmp for short bind-mount paths and ephemeral storage.
        assert!(
            EVENTS_HOST_ROOT.starts_with("/tmp/"),
            "events host root should live under /tmp: {EVENTS_HOST_ROOT}"
        );
    }

    #[test]
    fn events_dir_in_container_is_under_var_log_gateway() {
        // The bind target must sit under /var/log/gateway so the narrower
        // bind mount shadows only the JSONL producer path, leaving the
        // rest of /var/log on tmpfs for operator-debug unstructured logs.
        assert_eq!(EVENTS_DIR_IN_CONTAINER, "/var/log/gateway/events");
    }
}
