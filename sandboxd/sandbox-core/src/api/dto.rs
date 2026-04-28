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
    /// Backend-neutral session networking summary. Populated by
    /// `GET /sessions/{id}` from the daemon's persisted `NetworkInfo`
    /// (the same source `SessionStore::get_network_info` exposes
    /// internally). For both backends the fields carry the same
    /// meaning — only the *values* shift per backend (Lima: VM-side
    /// `eth1` IP / per-session /28; container: container IP on
    /// `sandbox-net-<id>`).
    ///
    /// Optional at the wrapper level so the response cleanly omits
    /// the block for sessions that don't yet have networking
    /// allocated (e.g. transient `Created`/`Error` states without a
    /// persisted `network_info`). Inside the struct each field is
    /// non-`Option` because they are populated together from the
    /// same `NetworkInfo` row — splitting their availability would
    /// only model an impossible state. Additive on the wire:
    /// pre-Wave-2 records that lack the field round-trip via
    /// `#[serde(default)]`; older clients reading a newer response
    /// silently ignore the unknown key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network: Option<SessionNetworkInfo>,
    /// Backend-neutral session mount surface. Surfaces the in-session
    /// workspace path, the host-side bind source (when the session
    /// was created with `--workspace shared:<path>`), the in-session
    /// CA bundle path (container-only — Lima injects the CA into the
    /// system trust store via the guest agent, not as a bind-mount),
    /// and the named home volume (container-only — Lima has its own
    /// home semantics). Same `Option` + `#[serde(default)]` shape as
    /// `network` above; fields that don't apply to a given backend
    /// stay `None` rather than carrying a placeholder string.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mounts: Option<SessionMountInfo>,
    /// Rootless-Docker probe outcome captured at session-create time
    /// (M11-S8 Wave 2). `Some(_)` only for container sessions where
    /// the daemon ran the probe; `None` for every Lima session and
    /// for legacy container records written by pre-Wave-2 daemons
    /// (forward-compatible via `#[serde(default)]` per CLAUDE.md
    /// "On-disk compatibility").
    ///
    /// Wave 4 docs and Wave 3 integration tests both consume this
    /// shape — `detected` mirrors the host's `docker info` output at
    /// create time, and `forced` records whether the operator passed
    /// `--force-rootless-docker` AND the probe actually returned
    /// rootless (i.e. the override applied). Default-hardened hosts
    /// stamp `{detected: false, forced: false}` and Lima sessions
    /// omit the field entirely.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rootless: Option<SessionRootlessDocker>,
}

/// Wire representation of the rootless-Docker probe outcome stamped
/// onto a container session at create time (M11-S8 Wave 2).
///
/// Spec § Non-goals line 1195 declares rootless Docker out of scope
/// for the lite container backend; the daemon enforces this at
/// session-create time and records the probe outcome here so
/// `sandbox inspect` and `sandbox describe` can render the operator-
/// relevant pair without re-probing. Mirrors
/// [`crate::session::SessionRootlessDocker`] field-for-field — the
/// types are kept distinct so a future shape-change of the persisted
/// struct cannot accidentally leak onto the wire (the same boundary
/// pattern this module enforces for every other persisted →
/// projected pair).
///
/// Pinned semantics:
/// - `forced` implies `detected` — the daemon only sets
///   `forced: true` when the probe returned rootless AND the
///   operator passed `--force-rootless-docker`.
/// - Default-hardened hosts stamp `{detected: false, forced: false}`.
/// - Lima sessions never construct this — the field is `None` on the
///   parent [`SessionDto::rootless`].
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct SessionRootlessDocker {
    /// `true` when the host's `docker info` reported `name=rootless`
    /// at session-create time.
    pub detected: bool,
    /// `true` when `--force-rootless-docker` was passed AND
    /// `detected` is `true`.
    pub forced: bool,
}

/// Backend-neutral per-session networking summary surfaced on the
/// wire by `GET /sessions/{id}`.
///
/// All three fields are sourced from the daemon's persisted
/// [`crate::network::NetworkInfo`] for the session — they are
/// allocated together at create-time and never independently, so the
/// struct is "all-or-nothing" (either populated as a complete unit
/// inside `Some(_)`, or absent via `None` on the parent
/// [`SessionDto::network`]).
///
/// The field *names* are deliberately backend-neutral. Lima carries
/// the VM's `eth1` IP in `session_ip`; container carries the
/// container's IP on `sandbox-net-<id>` in the same field. Operators
/// (and tests) read `session_ip` regardless of backend, which is the
/// whole point of surfacing this — todo #72 was filed because
/// `test_m3_networking` hard-coded the Lima `10.209.x.x/28` shape
/// and skipped the container parameterization in-body.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SessionNetworkInfo {
    /// Per-session gateway container IP (the `.2` in each /28). Same
    /// value on both backends.
    pub gateway_ip: String,
    /// Session-side IP. Lima: VM `eth1` static IP (`.3` in the /28).
    /// Container: container IP on `sandbox-net-<id>` (also `.3`).
    pub session_ip: String,
    /// CIDR of the per-session /28 block, e.g. `"10.209.0.0/28"`.
    /// Backend-agnostic; tests use this in lieu of an IP-shape regex.
    pub session_subnet_cidr: String,
}

/// Backend-neutral per-session mount-surface summary surfaced on the
/// wire by `GET /sessions/{id}`.
///
/// Operators and tests use this to assert on the workspace bind layout
/// without reaching into backend-specific code paths. Each field
/// carries the same meaning across backends; fields whose mechanism
/// only applies to one backend are `Option<String>` and stay `None` on
/// the other.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SessionMountInfo {
    /// In-session absolute path of the workspace. Unified across
    /// backends post Bundle X (M11-S7) — both Lima and container use
    /// `/home/agent/workspace/`.
    pub workspace_path: String,
    /// Absolute host path bound into the session at `workspace_path`.
    /// Set only when the session was created with
    /// `--workspace shared:<host_path>` (rendered on the wire as
    /// `workspace_mode: "shared:<path>"` on `SessionConfigDto`); for
    /// `WorkspaceMode::Clone` and the unset case the daemon does not
    /// bind any host directory and this stays `None`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workspace_host_path: Option<String>,
    /// In-session absolute path of the per-session MITM CA bundle.
    /// Container: `/etc/ssl/certs/sandbox-ca.pem` (bind-mounted
    /// read-only by the runtime). Lima: `None` — the guest agent
    /// installs the CA into the system trust store
    /// (`/usr/local/share/ca-certificates/sandbox-ca.crt` plus
    /// `update-ca-certificates`) rather than via a bind, so there is
    /// no daemon-controlled mount path to surface.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ca_bundle_path: Option<String>,
    /// Named Docker volume that backs `/home/agent` for container
    /// sessions (`sandbox-home-{session_id}`). Lima: `None` — VM
    /// home semantics are not volume-backed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub home_volume: Option<String>,
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
    /// User-requested CPU ceiling. M11-S7 todo #67 widened this from
    /// `u32` to `f32` so the spec § "Resource defaults — container
    /// only" 1-decimal precision survives the persisted round-trip.
    /// Lima sessions still see whole-number values; container
    /// sessions see whatever the operator passed (e.g. `1.5`) or
    /// `0.0` when the operator omitted the flag and the daemon will
    /// substitute the host-80% default at runtime — the resolved
    /// applied value lives in [`Self::resolved_cpus`].
    pub cpus: f32,
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
