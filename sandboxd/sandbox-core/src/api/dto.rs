//! API DTO (wire) types for session and policy responses.
//!
//! These types are the **only** shape visible on the HTTP wire.  They are
//! deliberately separate from the domain types (`Session`, `SessionConfig`,
//! `Policy`, `PolicyRule`, `AssuranceLevel`) so that adding a new domain
//! field is **inert** on the wire until the mapper in [`super::mapper`] is
//! updated to populate the corresponding DTO field.  No `#[serde(flatten)]`
//! of domain types into wire responses — every wire key is declared here.
//!
//! The conversion rules live in [`super::mapper`].  Keep the mapper as the
//! single edge between the domain and these DTOs; do not let handlers
//! build a DTO from a domain struct directly.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::backend::BackendKind;
use crate::policy::{Destination, HttpFilter, Protocol};
use crate::session::{SessionId, SessionState};

// ---------------------------------------------------------------------------
// Session DTOs
// ---------------------------------------------------------------------------

/// Wire representation of a session (response body for
/// `GET /sessions/{id}`, `POST /sessions`, and elements of
/// `GET /sessions`).
///
/// The `policy` field is only populated for the single-session endpoint
/// (`GET /sessions/{id}`), not for the list endpoint (`GET /sessions`).
/// When `None`, it is omitted from the wire entirely via
/// `skip_serializing_if`, so a list response does not grow an empty
/// `policy: null` noise entry per row.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionDto {
    pub id: SessionId,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    pub state: SessionState,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub config: SessionConfigDto,
    /// Guest agent connectivity status: `"connected"`, `"unreachable"`,
    /// or `null` when the session is not running.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub guest_agent_status: Option<String>,
    /// Gateway container status: `"running"`, `"stopped"`, `"not_found"`,
    /// or `null` when the session is not running.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gateway_status: Option<String>,
    /// Applied network policy, if any.  Populated by
    /// `GET /sessions/{id}` from the daemon's in-memory
    /// `session_policies` map; deliberately left `None` by
    /// `GET /sessions` to keep the list response cheap.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy: Option<PolicyDto>,
    /// Operator-facing warnings produced during the request that
    /// produced this DTO. Populated by `POST /sessions` with the
    /// container backend's first-use lite-image build notice (spec
    /// § "Lite mode → first-use warning"); empty (and therefore
    /// omitted) on every other endpoint and on the steady-state
    /// container path. Always treated as additive: older daemons
    /// rolling forward to a newer record never see this field, and
    /// older clients reading a newer response simply ignore it
    /// (`#[serde(default)]` ensures that direction works too).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
    /// Backend that owns this session's runtime resources. Surfaced
    /// on the wire so HTTP-level integration tests and CLI consumers
    /// can confirm `--backend container` actually routed to the
    /// container runtime. Additive: pre-M11-S3 records and clients
    /// that ignore the field still round-trip via `#[serde(default)]`
    /// (defaults to Lima, matching the implicit pre-M11 contract).
    #[serde(default)]
    pub backend: BackendKind,
}

/// Wire representation of a session's resource configuration.
///
/// Mirrors the persisted [`crate::session::SessionConfig`] but is a
/// distinct type so that:
///
/// 1. Adding a new persisted field (e.g. `network_id`) does not
///    accidentally expose it on the wire.
/// 2. The wire key `workspace_mode` can be surfaced as a short rendered
///    string (`"shared:/path"`, `"clone:<url>"`) rather than as a tagged
///    enum object, which is what CLI consumers actually want to print.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionConfigDto {
    pub cpus: u32,
    pub memory_mb: u32,
    pub disk_gb: u32,
    /// Effective CPU ceiling actually applied at runtime.
    ///
    /// For Lima sessions, mirrors `cpus` (the persisted value is what
    /// QEMU receives). For container sessions a stored `0` sentinel
    /// (caller did not pass `--cpus`) is replaced by the daemon's
    /// host-80% default per `compute_default_resource_limits`; the
    /// resolved fraction (rounded to one decimal place to match
    /// Docker's `--cpus` grammar) lands here so callers can verify
    /// the actually-applied ceiling without inspecting cgroup files.
    /// Additive: pre-M11-S4 records without this field deserialize to
    /// `0.0` via `#[serde(default)]`; older clients reading a newer
    /// response simply ignore the unknown field.
    #[serde(default)]
    pub resolved_cpus: f64,
    /// Effective memory ceiling actually applied at runtime, in
    /// megabytes.
    ///
    /// Same shape and motivation as `resolved_cpus`: a stored `0`
    /// sentinel on a container session is replaced by the daemon's
    /// host-80% default. Pre-M11-S4 records default to `0` via
    /// `#[serde(default)]`.
    #[serde(default)]
    pub resolved_memory_mb: u32,
    /// Rendered workspace-mode summary, if any.  Format:
    /// `"shared:<absolute host path>"` or `"clone:<repo url>"`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub workspace_mode: Option<String>,
    pub hardened: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub repo: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub boot_cmd: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub template: Option<String>,
}

// ---------------------------------------------------------------------------
// Policy DTOs
// ---------------------------------------------------------------------------

/// Wire representation of an applied policy.
///
/// The wire shape intentionally mirrors the domain [`crate::policy::Policy`]
/// today — but is declared here as a separate type so that any future
/// domain-shape change does not silently leak onto the wire.  The level
/// tag and its per-variant data (`http_filters` on the `http` variant)
/// are declared locally by [`PolicyLevelDto`] rather than re-using the
/// domain [`crate::policy::AssuranceLevel`] enum.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyDto {
    /// Schema version (semver) of the policy document.
    pub version: String,
    /// Rules in evaluation order.
    pub rules: Vec<PolicyRuleDto>,
}

/// Wire representation of a single policy rule.
///
/// The level tag and any level-specific data (`http_filters`) are carried
/// by the [`PolicyLevelDto`] enum, flattened into the rule object's top
/// level to match the established wire format.  Flattening a **DTO** enum
/// (not a domain enum) is the explicit boundary that makes adding a new
/// variant to domain [`crate::policy::AssuranceLevel`] inert on the wire
/// until [`super::mapper`] is updated.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyRuleDto {
    pub host: Destination,
    pub port: u16,
    pub protocol: Protocol,
    #[serde(flatten)]
    pub level: PolicyLevelDto,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// Wire representation of a rule's assurance level.
///
/// Tagged enum serialized with `{"level": "..."}` at the rule object's
/// top level.  The `http` variant carries its `http_filters` alongside
/// the tag (matching the pre-existing wire format); all other variants
/// have no per-variant data.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "level", rename_all = "snake_case")]
pub enum PolicyLevelDto {
    Deny,
    Transport,
    Tls,
    Http { http_filters: Vec<HttpFilter> },
}

impl PolicyRuleDto {
    /// Return the per-rule HTTP filters when the level is `Http`.
    pub fn http_filters(&self) -> Option<&[HttpFilter]> {
        match &self.level {
            PolicyLevelDto::Http { http_filters } => Some(http_filters.as_slice()),
            _ => None,
        }
    }
}
