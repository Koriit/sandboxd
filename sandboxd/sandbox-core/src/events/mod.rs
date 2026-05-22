//! Unified event stream: domain types.
//!
//! The event surface is defined by spec Part 3 of
//! `.tasks/specs/2026-04-21-port-explicit-policies-presets-observability-
//! design.md`. This module holds the domain representation of events.
//! The wire (JSON) shape and the domain → wire mapper live in
//! [`crate::api::event_dto`] and [`crate::api::event_mapper`] respectively.
//!
//! Submodules:
//!
//! - `bus.rs` — per-session ring buffer.
//! - `vm_ip_map.rs` — vm-ip → session-id lookup.
//! - `lifecycle.rs` — sandboxd-side emitters.
//! - `ingest/` — JSONL-tail producers into the bus.

use std::path::PathBuf;

use crate::session::SessionId;

pub mod bus;
pub mod envelope;
pub mod health_transition;
pub mod ingest;
pub mod lifecycle;
pub mod persist;
pub mod vm_ip_map;

pub use bus::{
    DEFAULT_BROADCAST_CAPACITY, DEFAULT_RING_BUFFER_SIZE, EventBus, EventBusConfig,
    EventSubscription,
};
pub use envelope::{
    DenyLoggerAllow, DenyLoggerDeny, DenyLoggerEvent, DenyProtocol, DnsEvent, EnvoyConnection,
    EnvoyEvent, Event, EventEnvelope, GatewayShutdownReason, HealthComponent, LifecycleEvent,
    MitmproxyEvent, PolicyApplyStatus, TrafficEvent,
};
pub use health_transition::{HEALTHY, HealthTransition, detect_health_transition};
pub use persist::{PersistConfig, PersistentSink};
pub use vm_ip_map::VmIpSessionMap;

/// Return the root directory on the host under which per-session event
/// directories live. `sandboxd` bind-mounts `${root}/<session-id>/` into
/// each gateway container at [`EVENTS_DIR_IN_CONTAINER`] so the three
/// JSONL producers (Envoy access log, CoreDNS plugin, mitmproxy addon)
/// can write structured events that sandboxd's ingest layer tails via
/// `inotify`.
///
/// Resolution order mirrors
/// [`crate::atomic_listener_writer::listener_host_root`] (the canonical
/// 4-level pattern documented in `CLAUDE.md`):
/// 1. `SANDBOX_EVENTS_DIR` env override — operators / tests can pin
///    the path explicitly.
/// 2. `$XDG_RUNTIME_DIR/sandboxd/events/` — the default on systems with
///    a user runtime dir (typical on systemd-managed hosts). Lives on
///    a tmpfs, so non-persistent across host reboots which matches the
///    ephemeral nature of sessions.
/// 3. `$HOME/.local/share/sandboxd/events/` — fallback when XDG is
///    unset (matches the daemon socket-path fallback).
/// 4. `/tmp/sandboxd-events` — last-resort fallback when even `HOME`
///    is unset (containerised CI, etc.).
///
/// The path stays short enough for Docker bind mounts on every supported
/// platform under all four cases.
pub fn events_host_root() -> PathBuf {
    if let Ok(override_dir) = std::env::var("SANDBOX_EVENTS_DIR") {
        return PathBuf::from(override_dir);
    }
    if let Ok(runtime_dir) = std::env::var("XDG_RUNTIME_DIR") {
        return PathBuf::from(runtime_dir).join("sandboxd").join("events");
    }
    if let Ok(home) = std::env::var("HOME") {
        return PathBuf::from(home)
            .join(".local")
            .join("share")
            .join("sandboxd")
            .join("events");
    }
    PathBuf::from("/tmp/sandboxd-events")
}

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
    events_host_root().join(session_id.to_string())
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
            events_host_root().join("0123456789ab"),
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
    fn events_dir_in_container_is_under_var_log_gateway() {
        // The bind target must sit under /var/log/gateway so the narrower
        // bind mount shadows only the JSONL producer path, leaving the
        // rest of /var/log on tmpfs for operator-debug unstructured logs.
        assert_eq!(EVENTS_DIR_IN_CONTAINER, "/var/log/gateway/events");
    }

    // -----------------------------------------------------------------------
    // events_host_root: XDG-compliant resolver
    //
    // These tests mutate process env vars. They are safe under nextest's
    // default per-test-process isolation, but each test snapshots and
    // restores the relevant vars within its own body to be robust against
    // future runner changes that might serialise tests within a process.
    // Mirrors the test pattern in `atomic_listener_writer` for
    // `listener_host_root`.
    // -----------------------------------------------------------------------

    /// Snapshot the trio of env vars `events_host_root` reads, clear
    /// them, run `body`, then restore. Holds `home_env_mutex` for the
    /// duration so concurrent cargo-test threads cannot race on these vars.
    fn with_clean_env<F: FnOnce() -> R, R>(body: F) -> R {
        // Serialize all tests that touch HOME / XDG vars.  nextest runs each
        // test in its own process so the lock is belt-and-suspenders there.
        let _guard = crate::test_support::home_env_mutex().lock().unwrap();
        let prior_override = std::env::var("SANDBOX_EVENTS_DIR").ok();
        let prior_runtime = std::env::var("XDG_RUNTIME_DIR").ok();
        let prior_home = std::env::var("HOME").ok();
        // SAFETY: protected by home_env_mutex(); only one thread touches
        // these vars at a time.
        unsafe {
            std::env::remove_var("SANDBOX_EVENTS_DIR");
            std::env::remove_var("XDG_RUNTIME_DIR");
            std::env::remove_var("HOME");
        }
        let result = body();
        unsafe {
            match prior_override {
                Some(v) => std::env::set_var("SANDBOX_EVENTS_DIR", v),
                None => std::env::remove_var("SANDBOX_EVENTS_DIR"),
            }
            match prior_runtime {
                Some(v) => std::env::set_var("XDG_RUNTIME_DIR", v),
                None => std::env::remove_var("XDG_RUNTIME_DIR"),
            }
            match prior_home {
                Some(v) => std::env::set_var("HOME", v),
                None => std::env::remove_var("HOME"),
            }
        }
        result
    }

    #[test]
    fn events_host_root_honors_explicit_override() {
        with_clean_env(|| {
            // SAFETY: see `with_clean_env`.
            unsafe {
                std::env::set_var("SANDBOX_EVENTS_DIR", "/var/lib/custom-events");
                // Set XDG and HOME too so we prove the override wins
                // over both lower-priority sources.
                std::env::set_var("XDG_RUNTIME_DIR", "/run/user/1000");
                std::env::set_var("HOME", "/home/test");
            }
            assert_eq!(
                events_host_root(),
                PathBuf::from("/var/lib/custom-events"),
                "SANDBOX_EVENTS_DIR must take precedence over XDG and HOME"
            );
        });
    }

    #[test]
    fn events_host_root_uses_xdg_runtime_dir_when_no_override() {
        with_clean_env(|| {
            // SAFETY: see `with_clean_env`.
            unsafe {
                std::env::set_var("XDG_RUNTIME_DIR", "/run/user/1000");
                std::env::set_var("HOME", "/home/test");
            }
            assert_eq!(
                events_host_root(),
                PathBuf::from("/run/user/1000/sandboxd/events"),
                "without SANDBOX_EVENTS_DIR, XDG_RUNTIME_DIR must drive the default"
            );
        });
    }

    #[test]
    fn events_host_root_falls_back_to_home_when_xdg_unset() {
        with_clean_env(|| {
            // SAFETY: see `with_clean_env`.
            unsafe {
                std::env::set_var("HOME", "/home/test");
            }
            assert_eq!(
                events_host_root(),
                PathBuf::from("/home/test/.local/share/sandboxd/events"),
                "without XDG_RUNTIME_DIR, HOME-based fallback must apply"
            );
        });
    }

    #[test]
    fn events_host_root_falls_back_to_tmp_when_home_and_xdg_unset() {
        with_clean_env(|| {
            assert_eq!(
                events_host_root(),
                PathBuf::from("/tmp/sandboxd-events"),
                "with neither XDG nor HOME set, the last-resort /tmp \
                 path must apply so the daemon can still boot"
            );
        });
    }
}
