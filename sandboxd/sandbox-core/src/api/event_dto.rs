//! Wire-facing DTOs for the unified event stream.
//!
//! Serialized JSON shape matches the event wire format exactly:
//!
//! ```json
//! {
//!   "timestamp": "2026-04-21T12:34:56.789Z",
//!   "session": "<session-id-or-empty-string>",
//!   "layer": "dns|envoy|mitmproxy|deny-logger|lifecycle",
//!   "event": "<event-name>",
//!   ...layer-specific fields (flattened at top level)...
//! }
//! ```
//!
//! The mapper in [`super::event_mapper`] is the single boundary between
//! [`crate::events`] domain types and this module — same principle as
//! [`super::dto`] / [`super::mapper`].
//!
//! Implementation notes:
//!
//! - The outer [`EventDto`] uses `#[serde(tag = "layer")]` with a
//!   kebab-case rename so each variant's top-level JSON carries
//!   `"layer": "<name>"` as its discriminator. Kebab-case is the
//!   superset: single-word variants (`Dns`, `Envoy`, `Mitmproxy`,
//!   `Lifecycle`) render identically to lowercase, while the
//!   multi-word `DenyLogger` renders as `"deny-logger"`
//!   "Traffic events" (which names the layer `deny-logger`). The
//!   per-layer payload struct carries the envelope fields (`timestamp`,
//!   `session`) and `#[serde(flatten)]`s its per-event body. The body's
//!   own `#[serde(tag = "event")]` emits the event-name discriminator
//!   and each variant's fields at the same level. The net shape is
//!   exactly the flat JSON above.
//! - `timestamp` is formatted as RFC 3339 with millisecond precision and
//!   `Z` suffix (`YYYY-MM-DDTHH:MM:SS.mmmZ`). The mapper rounds (truncates)
//!   sub-millisecond precision from the [`chrono::DateTime<Utc>`] source.
//! - `session` is always present as a string; pre-session lifecycle events
//!   serialize it as `""` as designed (Part 3, "Event shape").
//! - IP addresses are strings on the wire (e.g., `"10.0.0.42"`); domain
//!   carries [`std::net::Ipv4Addr`].

use serde::{Deserialize, Serialize};

use super::dto::PolicyDto;

// ---------------------------------------------------------------------------
// Top-level wire type
// ---------------------------------------------------------------------------

/// An event on the wire.
///
/// The outer `layer` tag (`"dns"` / `"envoy"` / `"mitmproxy"` /
/// `"deny-logger"` / `"lifecycle"`) discriminates variants; the inner
/// body's `event` tag discriminates within the layer.
///
/// No [`PartialEq`] derive: the `Lifecycle` variant transitively carries
/// [`PolicyDto`], whose domain siblings ([`crate::policy::Policy`],
/// [`crate::policy::Destination`]) do not themselves implement
/// [`PartialEq`]. Traffic-layer DTOs do implement [`PartialEq`]
/// structurally — tests can compare them directly, and lifecycle round-
/// trip tests use [`serde_json::Value`] equality instead.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "layer", rename_all = "kebab-case")]
pub enum EventDto {
    Dns(DnsEventDto),
    Envoy(EnvoyEventDto),
    Mitmproxy(MitmproxyEventDto),
    DenyLogger(DenyLoggerEventDto),
    Lifecycle(LifecycleEventDto),
}

// ---------------------------------------------------------------------------
// DNS
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DnsEventDto {
    pub timestamp: String,
    pub session: String,
    #[serde(flatten)]
    pub body: DnsEventBodyDto,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum DnsEventBodyDto {
    QueryAllowed {
        query: String,
        qtype: String,
        resolved_ips: Vec<String>,
    },
    QueryDenied {
        query: String,
        qtype: String,
        reason: String,
    },
}

// ---------------------------------------------------------------------------
// Envoy
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnvoyEventDto {
    pub timestamp: String,
    pub session: String,
    #[serde(flatten)]
    pub body: EnvoyEventBodyDto,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum EnvoyEventBodyDto {
    ConnectionAllowed(EnvoyConnectionDto),
    ConnectionDenied(EnvoyConnectionDto),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnvoyConnectionDto {
    pub src_ip: String,
    pub src_port: u16,
    pub dst_ip: String,
    pub dst_port: u16,
    pub matched_chain: String,
    pub cluster: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub upstream_host: Option<String>,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub response_flags: String,
    pub duration_ms: u64,
    /// L3 `REQUESTED_SERVER_NAME` (CONNECT authority); absent on L1/L2.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub connect_authority: Option<String>,
}

// ---------------------------------------------------------------------------
// mitmproxy
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MitmproxyEventDto {
    pub timestamp: String,
    pub session: String,
    #[serde(flatten)]
    pub body: MitmproxyEventBodyDto,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum MitmproxyEventBodyDto {
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
// Deny-logger / allow-logger (the nft-logger family)
// ---------------------------------------------------------------------------
//
// Wire shape  row for layer
// `deny-logger`:
//
//     | deny-logger | ... | deny | orig_dst_ip, orig_dst_port,
//                              protocol (tcp/udp), src_ip, src_port |
//
// The `rate_limited` summary event carries `rate_limited_count` plus
// `since_ts` marking the start of the summarised window, as designed
// Part 3 / "Hardening rules".
//
// The enum also carries an `allow` variant with the same 5-tuple
// shape as `deny`; the only structural difference is the `event`
// discriminator. The variant lives inside the existing
// `DenyLoggerEventBodyDto` enum (additive change, not a new
// pipeline) so daemon ingest stays one mapper code path.
// Forward-compat: any future `allow_end` / equivalent
// can be added additively here without breaking the existing
// `deny` / `allow` / `rate_limited` shapes — `serde` round-tripping
// is unknown-field-tolerant by default for tagged enums (unknown
// `event` values yield deserialise errors that the ingest parser
// surfaces as drops, mirroring the `deny_logger` path).

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DenyLoggerEventDto {
    pub timestamp: String,
    pub session: String,
    #[serde(flatten)]
    pub body: DenyLoggerEventBodyDto,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum DenyLoggerEventBodyDto {
    Deny {
        /// IPv4 rendered as `Ipv4Addr::to_string()` (e.g. `"203.0.113.1"`).
        orig_dst_ip: String,
        orig_dst_port: u16,
        protocol: DenyProtocolDto,
        src_ip: String,
        src_port: u16,
    },
    /// Allow-flow audit record. Same 5-tuple shape as `Deny`; the
    /// `event` tag is `"allow"`.
    Allow {
        orig_dst_ip: String,
        orig_dst_port: u16,
        protocol: DenyProtocolDto,
        src_ip: String,
        src_port: u16,
    },
    RateLimited {
        rate_limited_count: u32,
        /// Start of the summarised window, RFC 3339 with millisecond
        /// precision and `Z` suffix — same format as the envelope
        /// `timestamp`.
        since_ts: String,
    },
}

/// Wire value of the deny-logger `deny` event's `protocol` field.
///
///  / "Traffic events" row for `deny-logger` prescribes the
/// literals `"tcp"` and `"udp"`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DenyProtocolDto {
    Tcp,
    Udp,
}

// ---------------------------------------------------------------------------
// Lifecycle
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LifecycleEventDto {
    pub timestamp: String,
    pub session: String,
    #[serde(flatten)]
    pub body: LifecycleEventBodyDto,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum LifecycleEventBodyDto {
    GatewayBooting,
    GatewayReady,
    PolicyApplied {
        policy: PolicyDto,
        source_presets: Vec<String>,
        status: PolicyApplyStatusDto,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        error: Option<String>,
    },
    PolicyUpdated {
        policy: PolicyDto,
        source_presets: Vec<String>,
        status: PolicyApplyStatusDto,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        error: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        previous_policy_hash: Option<String>,
    },
    PolicyResetOnUpgrade {
        previous_rule_count: u64,
    },
    PolicyPropagated {
        policy_hash: String,
    },
    HealthDegraded {
        component: HealthComponentDto,
        reason: String,
    },
    HealthRestored {
        component: HealthComponentDto,
    },
    GatewayShutdown {
        reason: GatewayShutdownReasonDto,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        error: Option<String>,
    },
}

/// Wire value of `policy_applied` / `policy_updated` `status`.
///
///  "Lifecycle events" prescribes the literals `"ok"` and
/// `"error"`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PolicyApplyStatusDto {
    Ok,
    Error,
}

/// Wire value of `health_degraded` / `health_restored` `component`.
///
/// The wire format enumerates gateway subcomponents: `deny-logger`, `envoy`,
/// `mitmproxy`, `coredns`. Note the kebab-case on `deny-logger`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum HealthComponentDto {
    DenyLogger,
    Envoy,
    Mitmproxy,
    Coredns,
}

/// Wire value of `gateway_shutdown` `reason`.
///
/// The wire format lists `session_stopped`, `daemon_shutdown`, `error`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GatewayShutdownReasonDto {
    SessionStopped,
    DaemonShutdown,
    Error,
}
