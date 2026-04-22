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

pub mod envelope;

pub use envelope::{
    DnsEvent, EnvoyConnection, EnvoyEvent, Event, EventEnvelope, GatewayShutdownReason,
    HealthComponent, LifecycleEvent, MitmproxyEvent, PolicyApplyStatus, TrafficEvent,
};
