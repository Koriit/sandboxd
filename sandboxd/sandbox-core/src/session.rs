use std::path::Path;
use std::str::FromStr;

use chrono::{DateTime, Utc};
use enumset::EnumSetType;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Docker-style 12-hex-character session identifier.
///
/// Generated from the first 12 hex characters of a UUID v4 (simple form).
/// Provides a compact, copy-pastable ID (like Docker container IDs) while
/// maintaining uniform distribution and ~48 bits of entropy.
///
/// Internal storage is a fixed-size `[u8; 12]` of ASCII hex bytes so the
/// type is `Copy`, matching the ergonomics of `uuid::Uuid`.
///
/// Validation: exactly 12 characters, all lowercase hexadecimal `[0-9a-f]`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct SessionId([u8; Self::LEN]);

impl SessionId {
    /// Length of a session ID in characters.
    pub const LEN: usize = 12;

    /// Generate a new random session ID.
    ///
    /// Uses the first 12 hex characters of a UUID v4 (simple form). The
    /// uniform distribution of UUID v4 means the truncated prefix is also
    /// uniformly distributed — but with only 48 bits, callers should catch
    /// and retry on collision when inserting into a unique index.
    pub fn generate() -> Self {
        let full = Uuid::new_v4().simple().to_string();
        // simple() is always 32 hex chars.
        debug_assert!(full.len() >= Self::LEN);
        let mut bytes = [0u8; Self::LEN];
        bytes.copy_from_slice(&full.as_bytes()[..Self::LEN]);
        Self(bytes)
    }

    /// Parse a session ID from a string.
    ///
    /// Requires exactly 12 characters of lowercase hexadecimal.
    pub fn parse(s: &str) -> Result<Self, crate::SandboxError> {
        if s.len() != Self::LEN {
            return Err(crate::SandboxError::Internal(format!(
                "invalid session id: expected {} chars, got {}",
                Self::LEN,
                s.len()
            )));
        }
        if !s
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(crate::SandboxError::Internal(format!(
                "invalid session id: must be lowercase hex [0-9a-f], got {s:?}"
            )));
        }
        let mut bytes = [0u8; Self::LEN];
        bytes.copy_from_slice(s.as_bytes());
        Ok(Self(bytes))
    }

    /// Return the raw string representation.
    ///
    /// Since `parse` / `generate` guarantee ASCII hex bytes, the conversion
    /// from `&[u8; 12]` to `&str` is infallible.
    pub fn as_str(&self) -> &str {
        // SAFETY: bytes are validated to be ASCII hex (UTF-8 compatible)
        // by parse()/generate(), so this is sound.
        std::str::from_utf8(&self.0).expect("session id bytes are validated ASCII hex")
    }

    /// Decode the ID into its 6 raw bytes.
    ///
    /// Used for deriving deterministic MAC addresses. Since `parse` /
    /// `generate` guarantee 12 hex chars, this decode is infallible.
    pub fn as_bytes_array(&self) -> [u8; 6] {
        let mut out = [0u8; 6];
        for (i, chunk) in self.0.chunks_exact(2).enumerate() {
            out[i] = (hex_val(chunk[0]) << 4) | hex_val(chunk[1]);
        }
        out
    }
}

#[inline]
fn hex_val(b: u8) -> u8 {
    match b {
        b'0'..=b'9' => b - b'0',
        b'a'..=b'f' => b - b'a' + 10,
        // parse() guarantees only [0-9a-f] bytes reach here.
        _ => unreachable!("non-hex byte in validated SessionId"),
    }
}

impl std::fmt::Display for SessionId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for SessionId {
    type Err = crate::SandboxError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

impl TryFrom<String> for SessionId {
    type Error = crate::SandboxError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::parse(&value)
    }
}

impl From<SessionId> for String {
    fn from(id: SessionId) -> Self {
        id.as_str().to_string()
    }
}

impl AsRef<str> for SessionId {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

/// How the workspace directory is made available inside the VM.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum WorkspaceMode {
    /// Mount a host directory into the VM via 9p (bidirectional, live).
    Shared {
        /// Absolute path on the host to mount.
        host_path: String,
    },
    /// Clone a git repository into the VM at /home/agent/workspace/.
    Clone {
        /// Git repository URL.
        repo_url: String,
    },
}

/// Kind discriminator for [`WorkspaceMode`], without the variant payload.
///
/// `WorkspaceMode` is data-bearing (`Shared { host_path }`,
/// `Clone { repo_url }`), so it cannot itself participate in
/// [`enumset::EnumSet`] — `EnumSetType` requires unit variants only.
/// `WorkspaceModeKind` is the companion unit-only enum used by
/// [`crate::backend::Capabilities::workspace_modes`] to declare which
/// kinds of workspace handoff a backend supports, independent of any
/// concrete instance.
///
/// The kind is derivable from a `WorkspaceMode` via [`WorkspaceMode::kind`].
///
/// See spec § "Capabilities model" — the spec sketches this set as
/// `EnumSet<WorkspaceMode>`; in practice the discriminator is the
/// kind, and validation never depends on the payload.
#[derive(Debug, EnumSetType, Serialize, Deserialize)]
#[enumset(serialize_repr = "list")]
#[serde(rename_all = "snake_case")]
pub enum WorkspaceModeKind {
    /// 9p host-mount; corresponds to [`WorkspaceMode::Shared`].
    Shared,
    /// Git clone into the VM/container; corresponds to [`WorkspaceMode::Clone`].
    Clone,
}

impl WorkspaceMode {
    /// Return the kind discriminator for this workspace mode.
    ///
    /// Used for capability checks where the payload (paths, URLs) is
    /// irrelevant — only whether the backend supports the *kind*.
    pub fn kind(&self) -> WorkspaceModeKind {
        match self {
            Self::Shared { .. } => WorkspaceModeKind::Shared,
            Self::Clone { .. } => WorkspaceModeKind::Clone,
        }
    }

    /// Parse a workspace mode from the CLI `--workspace` flag value.
    ///
    /// Accepted formats:
    /// - `shared:/absolute/host/path`
    pub fn parse_flag(value: &str) -> Result<Self, String> {
        if let Some(path) = value.strip_prefix("shared:") {
            if path.is_empty() {
                return Err("shared workspace path must not be empty".into());
            }
            if !Path::new(path).is_absolute() {
                return Err(format!(
                    "shared workspace path must be absolute, got: {path}"
                ));
            }
            if !Path::new(path).exists() {
                return Err(format!("shared workspace path does not exist: {path}"));
            }
            Ok(Self::Shared {
                host_path: path.to_string(),
            })
        } else {
            Err(format!(
                "unknown workspace mode: {value}. Expected 'shared:<host-path>'"
            ))
        }
    }
}

/// Current state of a sandbox session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionState {
    Creating,
    Running,
    Stopped,
    Error,
}

impl SessionState {
    /// Check whether a transition from `self` to `new_state` is valid.
    ///
    /// Valid transitions:
    /// - Creating -> Running | Error
    /// - Running -> Stopped | Error
    /// - Stopped -> Running | Error
    /// - Error -> (terminal, no transitions)
    pub fn can_transition_to(self, new_state: SessionState) -> bool {
        matches!(
            (self, new_state),
            (SessionState::Creating, SessionState::Running)
                | (SessionState::Creating, SessionState::Error)
                | (SessionState::Running, SessionState::Stopped)
                | (SessionState::Running, SessionState::Error)
                | (SessionState::Stopped, SessionState::Running)
                | (SessionState::Stopped, SessionState::Error)
        )
    }
}

impl std::fmt::Display for SessionState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Creating => write!(f, "Creating"),
            Self::Running => write!(f, "Running"),
            Self::Stopped => write!(f, "Stopped"),
            Self::Error => write!(f, "Error"),
        }
    }
}

impl FromStr for SessionState {
    type Err = crate::SandboxError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "Creating" => Ok(Self::Creating),
            "Running" => Ok(Self::Running),
            "Stopped" => Ok(Self::Stopped),
            "Error" => Ok(Self::Error),
            other => Err(crate::SandboxError::Internal(format!(
                "unknown session state: {other}"
            ))),
        }
    }
}

/// Resource configuration for a sandbox session.
///
/// Persisted on disk as a JSON blob in the `sessions.config_json` column.
/// Any new field here MUST be `Option<T>` with `#[serde(default)]` so
/// records written by older daemons still deserialize cleanly and records
/// written by newer daemons can be read back on rollback.  See
/// `CLAUDE.md` → "On-disk compatibility" for the full rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionConfig {
    /// Number of CPU cores allocated, integer-valued for backward
    /// compatibility with the persisted `config_json` blob (a daemon
    /// rollback to a pre-todo-#67 build must still be able to read
    /// the integer field). On the container backend this carries the
    /// floored representation of the operator-supplied fractional
    /// value; the precise value lives in [`Self::cpus_decimal`] and
    /// is the authoritative one for HTTP and runtime consumers when
    /// present.
    pub cpus: u32,
    /// Memory in megabytes.
    pub memory_mb: u32,
    /// Disk size in gigabytes.
    pub disk_gb: u32,
    /// How the workspace is provided to the VM (if at all).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub workspace_mode: Option<WorkspaceMode>,
    /// Enable QEMU hardening (device lockdown, cgroup limits).
    ///
    /// When `true` (the default), the QEMU wrapper disables unnecessary
    /// devices and applies cgroup resource limits.  Set to `false` for debugging
    /// or when the hardened configuration causes compatibility issues.
    #[serde(default = "default_hardened")]
    pub hardened: bool,
    /// Git repository URL cloned into `/home/agent/workspace/` at creation.
    ///
    /// Captured so `sandbox inspect`/`sandbox describe` can surface the
    /// original creation input.  `None` on records written by daemons
    /// predating this field (forward-compatible via `#[serde(default)]`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub repo: Option<String>,
    /// Command executed inside the VM once setup completes.
    ///
    /// Captured so `sandbox inspect`/`sandbox describe` can surface the
    /// original creation input.  `None` on records written by daemons
    /// predating this field (forward-compatible via `#[serde(default)]`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub boot_cmd: Option<String>,
    /// Path to a custom Lima template used for creation, if any.
    ///
    /// Captured so `sandbox inspect`/`sandbox describe` can surface the
    /// original creation input.  `None` on records written by daemons
    /// predating this field (forward-compatible via `#[serde(default)]`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub template: Option<String>,
    /// 1-decimal CPU value for the container backend (`0.8`, `1.5`,
    /// `2.0`, …). The wire boundary is `f32` so the spec § "Resource
    /// defaults — container only" precision survives end-to-end (the
    /// historical `u32` shape silently truncated `1.5` to `1` in
    /// `ContainerRuntime::resource_ceilings`).
    ///
    /// Persisted alongside the integer [`Self::cpus`] field rather
    /// than replacing it: an older daemon rolling back must still
    /// see a usable value in the original column. When this field is
    /// `Some`, it is the authoritative precise value (used by the
    /// runtime and the HTTP DTO render); `cpus` then carries the
    /// floored representation as a fallback for older readers.
    /// `None` on records written by daemons predating fractional cpus
    /// (and on every Lima session, where integer cpus is the spec).
    /// Forward-compatible via `#[serde(default)]` per CLAUDE.md
    /// "On-disk compatibility".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cpus_decimal: Option<f32>,
    /// Rootless-Docker probe outcome captured at session-create time.
    /// `Some(_)` only for container sessions where the daemon ran
    /// the probe; `None` for every Lima session and for legacy
    /// container records written before the probe was introduced.
    ///
    /// Surfaced on the wire by the [`crate::api::SessionDto::rootless`]
    /// field so `sandbox inspect` and `sandbox describe` can render
    /// the operator-relevant pair (`detected`, `forced`) without
    /// re-running the probe. Persisted in `config_json` alongside
    /// the rest of the session config; forward-compatible via
    /// `#[serde(default)]` (older daemons rolling back ignore the
    /// unknown field, newer daemons reading older records get
    /// `None`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rootless_docker: Option<SessionRootlessDocker>,
}

/// Persisted rootless-Docker probe outcome for a container session.
///
/// Captured at `POST /sessions` time and stamped into
/// [`SessionConfig::rootless_docker`] so `GET /sessions/{id}` can
/// render the same pair without re-probing — the per-daemon-lifetime
/// probe cache (`backend::container_rootless_probe`) means the value
/// stamped here would never disagree with a fresh re-probe inside
/// the same daemon process anyway, but threading the recorded value
/// through the wire keeps the inspect surface consistent across
/// daemon restarts and across the create-vs-inspect call boundary.
///
/// `forced` implies `detected`: the daemon only sets `forced = true`
/// when the probe returned `true` AND the operator passed
/// `--force-rootless-docker`. A default-hardened host stamps
/// `detected: false, forced: false`; a rootless host without the
/// override is refused at create time and never reaches this struct;
/// a rootless host with the override stamps `detected: true,
/// forced: true`.
///
/// Lima sessions never construct this — the probe is gated to the
/// container backend by spec § Non-goals 1195.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct SessionRootlessDocker {
    /// `true` when the host's `docker info` reported `name=rootless`
    /// at session-create time.
    pub detected: bool,
    /// `true` when the operator passed `--force-rootless-docker` AND
    /// the probe detected rootless mode (i.e., the override actually
    /// applied). `false` on default-hardened hosts even if the
    /// operator passed the flag — the override is only meaningful in
    /// the detected-rootless case.
    pub forced: bool,
}

fn default_hardened() -> bool {
    true
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            cpus: 2,
            memory_mb: 4096,
            disk_gb: 20,
            workspace_mode: None,
            hardened: true,
            repo: None,
            boot_cmd: None,
            template: None,
            cpus_decimal: None,
            rootless_docker: None,
        }
    }
}

/// A sandbox session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    pub id: SessionId,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    pub state: SessionState,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub config: SessionConfig,
    /// Which backend owns this session's runtime resources.
    ///
    /// Persisted as the `sessions.backend` SQLite column (V005
    /// migration); legacy rows written before V005 default to
    /// `BackendKind::Lima` via the column's SQL `DEFAULT 'lima'`,
    /// so any session that pre-dates the column is unambiguously a
    /// Lima session. The container backend threads this kind through
    /// `runtime_for(...)` so handlers dispatch to the right
    /// `SessionRuntime` for each persisted row, without re-deriving
    /// the kind from per-handler heuristics.
    ///
    /// `#[serde(default)]` so JSON snapshots written by older code
    /// paths still deserialize cleanly (defaulting to Lima); the
    /// authoritative source remains the SQLite column.
    #[serde(default)]
    pub backend: crate::backend::BackendKind,
    /// Username of the operator who created this session. Stamped at
    /// `POST /sessions` from `SO_PEERCRED`-resolved identity and used
    /// as the per-caller filter on every subsequent
    /// `SessionStore` read or mutation (api-session-isolation spec
    /// § 2.4). Persisted as the `sessions.owner_username` SQLite column
    /// added by migration V006; legacy rows written before V006 are
    /// erased by V006's destructive `DELETE FROM sessions` step, so
    /// every row reaching this field has a real value.
    ///
    /// `#[serde(default)]` so JSON snapshots written by older code
    /// paths still deserialize cleanly (defaulting to the empty string);
    /// the authoritative source remains the SQLite column.
    #[serde(default)]
    pub owner_username: String,
    /// Daemon ↔ guest wire-protocol version stamped at session-create
    /// time. Bumped only when the protocol shape changes; the
    /// `start_session` compat gate (api-session-isolation spec § 3.4)
    /// reads this to decide whether to take the fast path, refresh the
    /// guest binary, or refuse. Spec 2's M13-S4 lays the column down
    /// with a placeholder `0`; M13-S5 wires up the real constant and
    /// the compat gate.
    ///
    /// `#[serde(default)]` so JSON snapshots written by older code
    /// paths still deserialize cleanly (defaulting to `0`).
    #[serde(default)]
    pub guest_protocol_version: u32,
    /// Semver of the `sandbox-guest` binary running inside this
    /// session's VM/container. Bumped on every guest release; surfaced
    /// in `sandbox describe` / diagnostic paths only (no decision
    /// logic reads this — that's `guest_protocol_version`'s role).
    ///
    /// `#[serde(default)]` so JSON snapshots written by older code
    /// paths still deserialize cleanly (defaulting to the empty string).
    #[serde(default)]
    pub guest_binary_version: String,
}

impl Session {
    /// Create a new session with the given name and default config.
    ///
    /// Defaults the backend to `Lima` to preserve the historical
    /// shape of `Session::new`. New code paths that need a non-Lima
    /// backend should use [`Session::with_config_and_backend`].
    pub fn new(name: Option<String>) -> Self {
        let now = Utc::now();
        Self {
            id: SessionId::generate(),
            name,
            state: SessionState::Creating,
            created_at: now,
            updated_at: now,
            config: SessionConfig::default(),
            backend: crate::backend::BackendKind::Lima,
            owner_username: String::new(),
            guest_protocol_version: 0,
            guest_binary_version: String::new(),
        }
    }

    /// Create a new session with a specific config (Lima backend).
    ///
    /// Retained as a back-compat shim for tests and pre-Phase-3D
    /// call sites; container-backed sessions go through
    /// [`Session::with_config_and_backend`].
    pub fn with_config(name: Option<String>, config: SessionConfig) -> Self {
        Self::with_config_and_backend(name, config, crate::backend::BackendKind::Lima)
    }

    /// Create a new session with a specific config and backend.
    pub fn with_config_and_backend(
        name: Option<String>,
        config: SessionConfig,
        backend: crate::backend::BackendKind,
    ) -> Self {
        let now = Utc::now();
        Self {
            id: SessionId::generate(),
            name,
            state: SessionState::Creating,
            created_at: now,
            updated_at: now,
            config,
            backend,
            owner_username: String::new(),
            guest_protocol_version: 0,
            guest_binary_version: String::new(),
        }
    }

    /// Transition to a new state, updating the `updated_at` timestamp.
    ///
    /// Valid transitions:
    /// - Creating -> Running | Error
    /// - Running -> Stopped | Error
    /// - Stopped -> Running | Error
    /// - Error -> (terminal, no transitions)
    pub fn transition_to(&mut self, new_state: SessionState) -> Result<(), crate::SandboxError> {
        if !self.state.can_transition_to(new_state) {
            return Err(crate::SandboxError::InvalidState(format!(
                "cannot transition from {} to {}",
                self.state, new_state
            )));
        }

        self.state = new_state;
        self.updated_at = Utc::now();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_session_has_creating_state() {
        let session = Session::new(Some("test".into()));
        assert_eq!(session.state, SessionState::Creating);
        assert_eq!(session.name, Some("test".into()));
        assert_eq!(session.config.cpus, 2);
        assert_eq!(session.config.memory_mb, 4096);
        assert_eq!(session.config.disk_gb, 20);
    }

    #[test]
    fn new_session_without_name() {
        let session = Session::new(None);
        assert_eq!(session.state, SessionState::Creating);
        assert!(session.name.is_none());
    }

    #[test]
    fn session_with_custom_config() {
        let config = SessionConfig {
            cpus: 4,
            memory_mb: 8192,
            disk_gb: 50,
            workspace_mode: None,
            hardened: true,
            repo: None,
            boot_cmd: None,
            template: None,
            cpus_decimal: None,
            rootless_docker: None,
        };
        let session = Session::with_config(Some("custom".into()), config);
        assert_eq!(session.config.cpus, 4);
        assert_eq!(session.config.memory_mb, 8192);
        assert_eq!(session.config.disk_gb, 50);
    }

    #[test]
    fn valid_state_transitions() {
        let mut session = Session::new(None);
        assert_eq!(session.state, SessionState::Creating);

        // Creating -> Running
        session.transition_to(SessionState::Running).unwrap();
        assert_eq!(session.state, SessionState::Running);

        // Running -> Stopped
        session.transition_to(SessionState::Stopped).unwrap();
        assert_eq!(session.state, SessionState::Stopped);

        // Stopped -> Running (restart)
        session.transition_to(SessionState::Running).unwrap();
        assert_eq!(session.state, SessionState::Running);
    }

    #[test]
    fn invalid_state_transition() {
        let mut session = Session::new(None);
        // Creating -> Stopped is not valid
        let result = session.transition_to(SessionState::Stopped);
        assert!(result.is_err());
        // State should be unchanged
        assert_eq!(session.state, SessionState::Creating);
    }

    #[test]
    fn error_state_is_terminal() {
        let mut session = Session::new(None);
        session.transition_to(SessionState::Error).unwrap();
        assert_eq!(session.state, SessionState::Error);

        // Cannot transition out of Error
        let result = session.transition_to(SessionState::Running);
        assert!(result.is_err());
        assert_eq!(session.state, SessionState::Error);
    }

    #[test]
    fn can_transition_to_valid() {
        assert!(SessionState::Creating.can_transition_to(SessionState::Running));
        assert!(SessionState::Creating.can_transition_to(SessionState::Error));
        assert!(SessionState::Running.can_transition_to(SessionState::Stopped));
        assert!(SessionState::Running.can_transition_to(SessionState::Error));
        assert!(SessionState::Stopped.can_transition_to(SessionState::Running));
        assert!(SessionState::Stopped.can_transition_to(SessionState::Error));
    }

    #[test]
    fn can_transition_to_invalid() {
        // Error is terminal
        assert!(!SessionState::Error.can_transition_to(SessionState::Running));
        assert!(!SessionState::Error.can_transition_to(SessionState::Stopped));
        assert!(!SessionState::Error.can_transition_to(SessionState::Creating));

        // Creating cannot go directly to Stopped
        assert!(!SessionState::Creating.can_transition_to(SessionState::Stopped));

        // No self-transitions
        assert!(!SessionState::Running.can_transition_to(SessionState::Running));
        assert!(!SessionState::Stopped.can_transition_to(SessionState::Stopped));
        assert!(!SessionState::Creating.can_transition_to(SessionState::Creating));
        assert!(!SessionState::Error.can_transition_to(SessionState::Error));
    }

    #[test]
    fn transition_updates_timestamp() {
        let mut session = Session::new(None);
        let original = session.updated_at;

        // Small sleep to ensure timestamps differ
        std::thread::sleep(std::time::Duration::from_millis(10));

        session.transition_to(SessionState::Running).unwrap();
        assert!(session.updated_at > original);
    }

    #[test]
    fn serialization_round_trip() {
        let session = Session::new(Some("round-trip".into()));
        let json = serde_json::to_string(&session).unwrap();
        let deserialized: Session = serde_json::from_str(&json).unwrap();

        assert_eq!(session.id, deserialized.id);
        assert_eq!(session.name, deserialized.name);
        assert_eq!(session.state, deserialized.state);
        assert_eq!(session.created_at, deserialized.created_at);
        assert_eq!(session.config.cpus, deserialized.config.cpus);
        assert_eq!(session.config.memory_mb, deserialized.config.memory_mb);
        assert_eq!(session.config.disk_gb, deserialized.config.disk_gb);
    }

    #[test]
    fn session_state_serialization() {
        // Verify snake_case serialization
        let json = serde_json::to_string(&SessionState::Creating).unwrap();
        assert_eq!(json, "\"creating\"");

        let json = serde_json::to_string(&SessionState::Running).unwrap();
        assert_eq!(json, "\"running\"");

        let json = serde_json::to_string(&SessionState::Stopped).unwrap();
        assert_eq!(json, "\"stopped\"");

        let json = serde_json::to_string(&SessionState::Error).unwrap();
        assert_eq!(json, "\"error\"");

        // Round-trip
        let state: SessionState = serde_json::from_str("\"running\"").unwrap();
        assert_eq!(state, SessionState::Running);
    }

    #[test]
    fn default_session_config() {
        let config = SessionConfig::default();
        assert_eq!(config.cpus, 2);
        assert_eq!(config.memory_mb, 4096);
        assert_eq!(config.disk_gb, 20);
        assert!(config.workspace_mode.is_none());
        assert!(config.hardened, "hardened should default to true");
        assert!(config.repo.is_none(), "repo defaults to None");
        assert!(config.boot_cmd.is_none(), "boot_cmd defaults to None");
        assert!(config.template.is_none(), "template defaults to None");
    }

    #[test]
    fn hardened_defaults_true_on_deserialization() {
        // When the `hardened` field is missing from JSON, it should
        // default to true via the serde default function.
        let json = r#"{"cpus": 2, "memory_mb": 4096, "disk_gb": 20}"#;
        let config: SessionConfig = serde_json::from_str(json).unwrap();
        assert!(
            config.hardened,
            "hardened should default to true when absent from JSON"
        );
    }

    #[test]
    fn hardened_false_roundtrip() {
        let config = SessionConfig {
            cpus: 2,
            memory_mb: 4096,
            disk_gb: 20,
            workspace_mode: None,
            hardened: false,
            repo: None,
            boot_cmd: None,
            template: None,
            cpus_decimal: None,
            rootless_docker: None,
        };
        let json = serde_json::to_string(&config).unwrap();
        let deser: SessionConfig = serde_json::from_str(&json).unwrap();
        assert!(
            !deser.hardened,
            "hardened=false should survive serialization round-trip"
        );
    }

    #[test]
    fn legacy_config_json_deserializes_with_none_for_new_fields() {
        // A record written by an older daemon has no `repo`,
        // `boot_cmd`, or `template` keys at all.  These fields must
        // deserialize to `None` via `#[serde(default)]` so that rolling
        // upgrades (and mid-conversation rollbacks) do not fail to load.
        let json = r#"{"cpus": 2, "memory_mb": 4096, "disk_gb": 20, "hardened": true}"#;
        let config: SessionConfig = serde_json::from_str(json).unwrap();
        assert_eq!(config.cpus, 2);
        assert_eq!(config.memory_mb, 4096);
        assert_eq!(config.disk_gb, 20);
        assert!(config.hardened);
        assert!(config.workspace_mode.is_none());
        assert!(
            config.repo.is_none(),
            "repo must default to None on legacy records"
        );
        assert!(
            config.boot_cmd.is_none(),
            "boot_cmd must default to None on legacy records"
        );
        assert!(
            config.template.is_none(),
            "template must default to None on legacy records"
        );
        assert!(
            config.cpus_decimal.is_none(),
            "cpus_decimal must default to None on legacy records"
        );
    }

    /// Forward-compat round-trip for [`SessionConfig::cpus_decimal`].
    /// A daemon that persists a fractional cpus value sets both
    /// `cpus` (floored) and `cpus_decimal`; on
    /// rollback an older daemon ignores the unknown field and reads
    /// the integer one. On forward read the new daemon picks up the
    /// precise float value.
    #[test]
    fn cpus_decimal_round_trips_through_serde() {
        let config = SessionConfig {
            cpus: 1, // floor of 1.5
            memory_mb: 4096,
            disk_gb: 20,
            workspace_mode: None,
            hardened: false,
            repo: None,
            boot_cmd: None,
            template: None,
            cpus_decimal: Some(1.5),
            rootless_docker: None,
        };
        let json = serde_json::to_string(&config).unwrap();
        // Wire-form sanity: both keys present, integer is the floor.
        assert!(
            json.contains("\"cpus_decimal\""),
            "cpus_decimal must be emitted when Some; got {json}"
        );
        let deser: SessionConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(deser.cpus, 1);
        assert_eq!(deser.cpus_decimal, Some(1.5));
    }

    /// Forward-compat: a legacy record with no `cpus_decimal` key
    /// must deserialise cleanly with `cpus_decimal: None`. This is
    /// the rollback-from-newer-daemon scenario: the older daemon (us
    /// here) reads a record that *might* be missing the field and
    /// must not fail.
    #[test]
    fn legacy_record_without_cpus_decimal_deserialises() {
        let json = r#"{"cpus": 2, "memory_mb": 4096, "disk_gb": 20, "hardened": true}"#;
        let config: SessionConfig = serde_json::from_str(json).unwrap();
        assert_eq!(config.cpus, 2);
        assert!(config.cpus_decimal.is_none());
    }

    #[test]
    fn new_fields_round_trip_through_serde() {
        let config = SessionConfig {
            cpus: 4,
            memory_mb: 8192,
            disk_gb: 50,
            workspace_mode: None,
            hardened: true,
            repo: Some("https://github.com/example/app.git".into()),
            boot_cmd: Some("make setup".into()),
            template: Some("/tmp/custom.yaml".into()),
            cpus_decimal: None,
            rootless_docker: None,
        };
        let json = serde_json::to_string(&config).unwrap();
        let deser: SessionConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(
            deser.repo.as_deref(),
            Some("https://github.com/example/app.git")
        );
        assert_eq!(deser.boot_cmd.as_deref(), Some("make setup"));
        assert_eq!(deser.template.as_deref(), Some("/tmp/custom.yaml"));
    }

    #[test]
    fn none_fields_are_omitted_from_wire() {
        let config = SessionConfig::default();
        let json = serde_json::to_string(&config).unwrap();
        // workspace_mode, repo, boot_cmd, template, cpus_decimal all
        // skip when None — keeps the persisted blob shape stable for
        // the legacy Lima sessions that never carry these fields.
        assert!(!json.contains("workspace_mode"), "wire JSON: {json}");
        assert!(!json.contains("\"repo\""), "wire JSON: {json}");
        assert!(!json.contains("boot_cmd"), "wire JSON: {json}");
        assert!(!json.contains("template"), "wire JSON: {json}");
        assert!(!json.contains("cpus_decimal"), "wire JSON: {json}");
    }

    #[test]
    fn workspace_mode_parse_shared() {
        // We cannot test with a real path that must exist, so test the
        // validation logic for non-absolute and empty paths.
        let err = WorkspaceMode::parse_flag("shared:").unwrap_err();
        assert!(err.contains("must not be empty"), "err = {err}");

        let err = WorkspaceMode::parse_flag("shared:relative/path").unwrap_err();
        assert!(err.contains("must be absolute"), "err = {err}");

        let err = WorkspaceMode::parse_flag("shared:/nonexistent/path/xyzzy").unwrap_err();
        assert!(err.contains("does not exist"), "err = {err}");

        // Use /tmp which is guaranteed to exist.
        let mode = WorkspaceMode::parse_flag("shared:/tmp").unwrap();
        assert_eq!(
            mode,
            WorkspaceMode::Shared {
                host_path: "/tmp".into()
            }
        );
    }

    #[test]
    fn workspace_mode_parse_unknown() {
        let err = WorkspaceMode::parse_flag("foobar:/some/path").unwrap_err();
        assert!(err.contains("unknown workspace mode"), "err = {err}");
    }

    #[test]
    fn workspace_mode_serialization_shared() {
        let mode = WorkspaceMode::Shared {
            host_path: "/home/user/project".into(),
        };
        let json = serde_json::to_string(&mode).unwrap();
        let deser: WorkspaceMode = serde_json::from_str(&json).unwrap();
        assert_eq!(deser, mode);
    }

    #[test]
    fn workspace_mode_serialization_clone() {
        let mode = WorkspaceMode::Clone {
            repo_url: "https://github.com/example/repo.git".into(),
        };
        let json = serde_json::to_string(&mode).unwrap();
        let deser: WorkspaceMode = serde_json::from_str(&json).unwrap();
        assert_eq!(deser, mode);
    }

    // -----------------------------------------------------------------
    // SessionId tests
    // -----------------------------------------------------------------

    #[test]
    fn session_id_generate_has_correct_format() {
        for _ in 0..32 {
            let id = SessionId::generate();
            let s = id.as_str();
            assert_eq!(s.len(), SessionId::LEN, "id={s}");
            assert!(
                s.bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
                "id {s} must be lowercase hex"
            );
        }
    }

    #[test]
    fn session_id_generate_uniqueness() {
        let mut seen = std::collections::HashSet::new();
        for _ in 0..1024 {
            assert!(
                seen.insert(SessionId::generate()),
                "collision in 1024 iterations"
            );
        }
    }

    #[test]
    fn session_id_parse_accepts_valid() {
        let id = SessionId::parse("0123456789ab").unwrap();
        assert_eq!(id.as_str(), "0123456789ab");
        let id = SessionId::parse("abcdef012345").unwrap();
        assert_eq!(id.as_str(), "abcdef012345");
    }

    #[test]
    fn session_id_parse_rejects_wrong_length() {
        assert!(SessionId::parse("").is_err());
        assert!(SessionId::parse("abc").is_err());
        assert!(SessionId::parse("0123456789a").is_err()); // 11
        assert!(SessionId::parse("0123456789abc").is_err()); // 13
        assert!(SessionId::parse(&"a".repeat(32)).is_err());
    }

    #[test]
    fn session_id_parse_rejects_uppercase() {
        assert!(SessionId::parse("ABCDEF012345").is_err());
        assert!(SessionId::parse("0123456789AB").is_err());
    }

    #[test]
    fn session_id_parse_rejects_non_hex() {
        assert!(SessionId::parse("0123456789ag").is_err());
        assert!(SessionId::parse("0123456789 a").is_err());
        assert!(SessionId::parse("gggggggggggg").is_err());
        assert!(SessionId::parse("xxxxxxxxxxxx").is_err());
    }

    #[test]
    fn session_id_from_str_roundtrip() {
        use std::str::FromStr;
        let id = SessionId::generate();
        let parsed = SessionId::from_str(id.as_str()).unwrap();
        assert_eq!(id, parsed);
    }

    #[test]
    fn session_id_display_matches_as_str() {
        let id = SessionId::parse("deadbeef0123").unwrap();
        assert_eq!(format!("{id}"), "deadbeef0123");
    }

    #[test]
    fn session_id_as_bytes_array_decodes_correctly() {
        let id = SessionId::parse("0123456789ab").unwrap();
        assert_eq!(id.as_bytes_array(), [0x01, 0x23, 0x45, 0x67, 0x89, 0xab]);
        let id = SessionId::parse("deadbeef0000").unwrap();
        assert_eq!(id.as_bytes_array(), [0xde, 0xad, 0xbe, 0xef, 0x00, 0x00]);
    }

    #[test]
    fn session_id_serialization_is_plain_string() {
        let id = SessionId::parse("abcdef012345").unwrap();
        let json = serde_json::to_string(&id).unwrap();
        assert_eq!(json, "\"abcdef012345\"");
        let deser: SessionId = serde_json::from_str(&json).unwrap();
        assert_eq!(deser, id);
    }

    #[test]
    fn session_id_deserialization_rejects_invalid() {
        let err = serde_json::from_str::<SessionId>("\"BADHEX!!!!!!\"");
        assert!(err.is_err());
        let err = serde_json::from_str::<SessionId>("\"short\"");
        assert!(err.is_err());
    }

    #[test]
    fn session_id_as_ref_str() {
        let id = SessionId::parse("0123456789ab").unwrap();
        let s: &str = id.as_ref();
        assert_eq!(s, "0123456789ab");
    }
}
