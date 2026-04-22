//! Domain types for the unified event stream.
//!
//! Every policy-bearing component (DNS, Envoy, mitmproxy) emits one event
//! per decision; sandboxd itself emits lifecycle events around gateway and
//! policy state changes. The wire surface is in [`crate::api::event_dto`];
//! these domain types never serialize directly.
//!
//! Spec reference: `.tasks/specs/2026-04-21-port-explicit-policies-presets-
//! observability-design.md`, Part 3 ("Event surface", "Event shape",
//! "Event categories"). Every event name and every layer-specific field
//! name below is traceable to the spec's Event-categories tables.
//!
//! Design notes:
//!
//! - Domain types deliberately do **not** derive [`serde::Serialize`] /
//!   [`serde::Deserialize`]. Serialization lives on
//!   [`crate::api::event_dto`] so that a domain-shape change does not
//!   silently leak onto the wire (same principle as `crate::api::dto` /
//!   `crate::api::mapper`).
//! - IP addresses are carried as [`Ipv4Addr`]; the ingestion layer (Phase
//!   7) parses Envoy access-log records into these strict types before
//!   publishing so downstream code cannot see malformed IPs.
//! - `session: Option<SessionId>` is [`None`] for lifecycle events that
//!   precede session creation (daemon boot, gateway boot before session
//!   attachment). The DTO renders [`None`] as `""`, per spec.
//! - Traffic events carry no session on this struct; sandboxd's ingestion
//!   layer stamps the envelope `session` from the `vm_ip → session_id` map
//!   before publishing to the bus (spec Part 3, "Session-ID attribution
//!   is sandboxd's job, not each component's").

use std::net::Ipv4Addr;

use chrono::{DateTime, Utc};

use crate::policy::Policy;
use crate::session::SessionId;

// ---------------------------------------------------------------------------
// Top-level envelope
// ---------------------------------------------------------------------------

/// Common envelope fields shared by every event.
///
/// The `layer` discriminator is **not** stored here — it is determined by
/// which variant of [`Event`] wraps the payload, which keeps the domain
/// type total (no "impossible" layer/event pairings).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventEnvelope {
    /// UTC timestamp of when the event was emitted.
    pub timestamp: DateTime<Utc>,
    /// Session the event belongs to. [`None`] for pre-session lifecycle
    /// events (e.g., `gateway_booting` before the session's gateway is
    /// attached).
    pub session: Option<SessionId>,
}

/// A single event in the unified stream.
///
/// Split by top-level category (traffic vs. lifecycle) so ingestion and
/// lifecycle-emitter code can share a common type without constantly
/// dispatching on a flat 15-way enum.
///
/// No [`PartialEq`] derive: lifecycle events carry a [`Policy`] payload,
/// and [`Policy`] does not (and should not — rule-ordering semantics, see
/// [`crate::policy`]) implement [`PartialEq`]. Round-trip tests compare
/// at the DTO level, where full structural equality is meaningful.
#[derive(Debug, Clone)]
pub enum Event {
    /// Per-request or per-connection policy decision emitted by a
    /// policy-enforcing component (CoreDNS plugin, Envoy, mitmproxy).
    Traffic {
        envelope: EventEnvelope,
        event: TrafficEvent,
    },
    /// Gateway and daemon control-plane state change emitted by sandboxd.
    Lifecycle {
        envelope: EventEnvelope,
        event: LifecycleEvent,
    },
}

// ---------------------------------------------------------------------------
// Traffic events
// ---------------------------------------------------------------------------

/// Per-layer traffic event.
///
/// Variants correspond 1:1 to the `Layer` column of spec Part 3
/// / "Traffic events" (minus `deny-logger`, which is the subject of
/// M10-S3 and is intentionally not modeled here yet).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrafficEvent {
    /// CoreDNS policy-plugin decision on a client DNS query.
    Dns(DnsEvent),
    /// Envoy per-connection decision (from a harmonized `access_log` JSON
    /// record on an L1, L2, or L3 filter chain).
    Envoy(EnvoyEvent),
    /// mitmproxy addon per-request decision.
    Mitmproxy(MitmproxyEvent),
}

/// CoreDNS `query_allowed` / `query_denied`.
///
/// Fields match the spec Part 3 "Traffic events" table for layer `dns`:
/// `query`, `qtype`, `resolved_ips` (on allow), `reason` (on deny).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnsEvent {
    QueryAllowed {
        query: String,
        qtype: String,
        resolved_ips: Vec<Ipv4Addr>,
    },
    QueryDenied {
        query: String,
        qtype: String,
        reason: String,
    },
}

/// Envoy per-connection event derived from the JSON access-log record.
///
/// Harmonized across L1, L2, L3 filter chains; `connect_authority` is
/// present only on L3 records (CONNECT-tunnel `REQUESTED_SERVER_NAME`).
/// Named fields follow the plan's JSON field map (plan Phase 4, line 102):
/// spec Part 3 Table names `matched_chain`, `cluster`; plan adds the
/// remaining access-log-standard fields so ingestion does not have to drop
/// data that operators will want.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnvoyEvent {
    ConnectionAllowed(EnvoyConnection),
    ConnectionDenied(EnvoyConnection),
}

/// Payload shared by `connection_allowed` / `connection_denied`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnvoyConnection {
    pub src_ip: Ipv4Addr,
    pub src_port: u16,
    pub dst_ip: Ipv4Addr,
    pub dst_port: u16,
    pub matched_chain: String,
    pub cluster: String,
    pub upstream_host: Option<String>,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub response_flags: String,
    pub duration_ms: u64,
    /// L3 CONNECT-tunnel authority (`REQUESTED_SERVER_NAME`). [`None`] on
    /// L1/L2 chains.
    pub connect_authority: Option<String>,
}

/// mitmproxy addon `request_allowed` / `request_denied`.
///
/// Fields match the spec Part 3 "Traffic events" table for layer
/// `mitmproxy`: `host`, `port`, `method`, `path`, and `reason` on deny.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MitmproxyEvent {
    RequestAllowed {
        host: String,
        port: u16,
        method: String,
        path: String,
    },
    RequestDenied {
        host: String,
        port: u16,
        method: String,
        path: String,
        reason: String,
    },
}

// ---------------------------------------------------------------------------
// Lifecycle events
// ---------------------------------------------------------------------------

/// sandboxd-emitted lifecycle event.
///
/// Variants correspond 1:1 to the rows of spec Part 3 "Lifecycle events"
/// table. Field sets mirror the spec's `Key fields` column exactly; see
/// the per-variant docs for the source row.
///
/// No [`PartialEq`] derive: the [`Policy`] payload on
/// `PolicyApplied` / `PolicyUpdated` cannot trivially be compared for
/// equality (see [`Event`] docs).
#[derive(Debug, Clone)]
pub enum LifecycleEvent {
    /// Gateway container starting (sandboxd initiated).
    GatewayBooting,
    /// Gateway passed startup checks (CoreDNS, Envoy, mitmproxy, deny-
    /// logger all responding).
    GatewayReady,
    /// Initial policy application at session start.
    PolicyApplied {
        policy: Policy,
        /// Original `--preset` invocation strings forwarded by the CLI.
        /// Empty if none.
        source_presets: Vec<String>,
        status: PolicyApplyStatus,
        /// Populated when `status == Error`.
        error: Option<String>,
    },
    /// Subsequent policy update via `sandbox policy update`.
    PolicyUpdated {
        policy: Policy,
        source_presets: Vec<String>,
        status: PolicyApplyStatus,
        error: Option<String>,
        /// Hash of the prior effective policy, for diff attribution.
        previous_policy_hash: Option<String>,
    },
    /// Emitted once per session on first access after V004 migration
    /// removed its v1-shaped rules.
    PolicyResetOnUpgrade { previous_rule_count: usize },
    /// A subcomponent healthcheck started failing.
    HealthDegraded {
        component: HealthComponent,
        reason: String,
    },
    /// A previously-degraded subcomponent recovered.
    HealthRestored { component: HealthComponent },
    /// Gateway container stopping.
    GatewayShutdown {
        reason: GatewayShutdownReason,
        /// Populated when `reason == Error`.
        error: Option<String>,
    },
}

/// Outcome of a policy-apply / policy-update action.
///
/// Serialized as the lowercase strings `"ok"` / `"error"` to match the
/// spec's `status` column for `policy_applied` / `policy_updated`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyApplyStatus {
    Ok,
    Error,
}

/// Subcomponent for [`LifecycleEvent::HealthDegraded`] /
/// [`LifecycleEvent::HealthRestored`].
///
/// Matches the spec's enumeration of gateway subcomponents:
/// `deny-logger`, `envoy`, `mitmproxy`, `coredns`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HealthComponent {
    DenyLogger,
    Envoy,
    Mitmproxy,
    Coredns,
}

/// Reason carried on [`LifecycleEvent::GatewayShutdown`].
///
/// Matches the spec's `reason` values for `gateway_shutdown`:
/// `session_stopped`, `daemon_shutdown`, `error`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GatewayShutdownReason {
    SessionStopped,
    DaemonShutdown,
    Error,
}
