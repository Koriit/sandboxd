//! Loader for `/etc/sandboxd/users.conf` — the subnet → user authorization
//! file consumed by both the daemon (at startup, to scope its
//! `NetworkManager` /28 allocation pool) and the `sandbox-route-helper`
//! binary (per invocation, to authorize a caller's request to install a
//! default route inside a target container's netns).
//!
//! The file is JSON, root-owned, mode `0644`. See the M11 lite-mode
//! container backend spec, § "Config file: `/etc/sandboxd/users.conf`",
//! for the canonical shape; the spec example is reproduced in
//! [`UsersConfig`].
//!
//! # Path resolution
//!
//! Two entry points exist; they differ on whether they consult the
//! `SANDBOX_USERS_CONF` environment variable:
//!
//! - [`load_users_config`] / [`users_conf_path`] — daemon-facing.
//!   Always honors `SANDBOX_USERS_CONF`. The daemon is not a privilege
//!   boundary (it runs as the operator), so the env-var seam stays
//!   unconditional and is consumed by the daemon-startup integration
//!   tests.
//! - [`load_users_config_route_helper`] / [`route_helper_users_conf_path`]
//!   — `sandbox-route-helper`-facing. Default builds **ignore**
//!   `SANDBOX_USERS_CONF` and read `/etc/sandboxd/users.conf`
//!   unconditionally. Test builds (any consumer enabling the
//!   `test-env-override` Cargo feature on `sandbox-core` — typically
//!   forwarded by `sandbox-route-helper/test-env-override`) honor the
//!   env var so route-helper integration tests can drive the
//!   authorization flow against a tempfile users.conf they own.
//!
//! The split exists because the route helper runs with
//! `cap_sys_admin+ep` (file capabilities) — granting any user who can
//! exec it the equivalent of root for namespace operations. Honoring an
//! attacker-controlled env var to redirect the auth-config read inside
//! a `cap_sys_admin+ep` binary is a local privilege escalation. Default
//! builds of the route helper therefore cannot consult the env var; the
//! feature gate makes the test seam explicit and impossible to ship by
//! accident.
//!
//! Both entry points additionally enforce a defensive ownership/mode
//! check on the canonical `/etc/sandboxd/users.conf` path: the file
//! must be owned by uid 0 and must carry no group- or world-write bits
//! (see `validate_canonical_users_conf_security`). Tempfile paths
//! used by tests are skipped — only the well-known canonical path is
//! checked, so test-tempfile callers (owned by the test runner's uid)
//! pass through unchanged. The check refuses to read a tampered config
//! file even if the daemon or helper somehow ends up reading one
//! outside of the install runbook's `chmod 0644` step.
//!
//! # Lookup helpers
//!
//! Two queries are performed against a loaded [`UsersConfig`]:
//!
//! - [`UsersConfig::find_subnet_by_gateway_ip`] — used by the route
//!   helper at step 3 of the authorization flow to find the subnet whose
//!   CIDR contains the gateway IP argument.
//! - [`UsersConfig::find_subnet_by_uid`] — used by the daemon at startup
//!   (with its own uid) to pick its allocation CIDR, and by the route
//!   helper at step 4 (with the caller's uid) to authorize.
//!
//! Per the spec (line 406-408), `allow_users` entries are admin
//! readability — the helper compares numeric uids internally so admin
//! renames (`usermod`) take effect immediately. Username → uid
//! resolution happens at lookup time via `getpwnam_r` (`nix`'s
//! [`User::from_name`]); names not present on the host (`Ok(None)`) are
//! treated as non-matches and skipped.
//!
//! [`User::from_name`]: nix::unistd::User::from_name

use std::fs;
use std::io;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};

use serde::Deserialize;
use thiserror::Error;
use tracing::warn;

/// Default path to the on-disk users config. Operators must populate this
/// file at install time; the daemon and helper only read it.
pub const DEFAULT_USERS_CONF_PATH: &str = "/etc/sandboxd/users.conf";

/// Environment variable used to override the on-disk path. **Test-only**:
/// production callers must rely on the default. The route-helper
/// integration tests and the daemon-startup tests both set this to a
/// tempfile they own.
pub const USERS_CONF_PATH_ENV: &str = "SANDBOX_USERS_CONF";

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors produced by the users.conf loader.
///
/// Every variant carries the file path that was being read so callers
/// can surface a clear pointer to the operator. The loader never wraps
/// these in [`crate::SandboxError`] internally — daemon-side callers
/// that want to surface them through `SandboxError` should do their own
/// mapping (typically into `SandboxError::InvalidArgument`) so the
/// resulting message preserves the path.
#[derive(Debug, Error)]
pub enum UsersConfigError {
    /// The config file does not exist at the given path. The message
    /// points at the install docs so the operator knows where to look.
    #[error(
        "users.conf not found at {0}; see install docs at \
         docs/start/installation.md"
    )]
    FileNotFound(PathBuf),

    /// I/O error other than `NotFound` (e.g. permission denied).
    #[error("failed to read users.conf at {path}: {source}")]
    ReadFailed {
        path: PathBuf,
        #[source]
        source: io::Error,
    },

    /// JSON parse failure or `deny_unknown_fields` rejection. The
    /// underlying `serde_json::Error` carries line/column information;
    /// we attach the file path explicitly because `serde_json` does not
    /// know it.
    #[error("failed to parse users.conf at {path}: {source}")]
    ParseFailed {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },

    /// A `cidr` field in users.conf failed validation. The most common
    /// causes: missing prefix, prefix outside `[0, 32]`, host bits set
    /// in the base address, or an unparsable IPv4 literal.
    #[error("invalid CIDR {value:?} in users.conf at {path}: {reason}")]
    InvalidCidr {
        path: PathBuf,
        value: String,
        reason: &'static str,
    },

    /// Defensive ownership / mode check on the canonical
    /// `/etc/sandboxd/users.conf` path failed. The route helper runs
    /// with `cap_sys_admin+ep`; reading an authorization-config file
    /// that is not root-owned-and-not-group-or-world-writable would let
    /// any local user re-write the auth list. We surface the specific
    /// failure mode (non-root-owned, group-writable, world-writable) so
    /// operators can re-run the install step that produced the file.
    #[error("users.conf at {path} fails security check: {reason}")]
    InsecureFile { path: PathBuf, reason: &'static str },

    /// The file's `_schema_version` is **newer** than this daemon binary
    /// supports. Typically indicates a downgrade or an interrupted update.
    /// `hint` carries the recovery pointer (run `sandbox update`, or
    /// restore from backup) so the operator's next step is one read away.
    ///
    /// The literal token `users.conf schema version <N> is newer` is
    /// load-bearing for the integration test
    /// `integration_daemon_refuses_start_on_schema_too_new` — any
    /// rewording must keep that substring.
    #[error(
        "users.conf schema version {file_version} is newer than this binary supports (max: {daemon_max}). {hint}"
    )]
    SchemaTooNew {
        file_version: u32,
        daemon_max: u32,
        hint: String,
    },

    /// The file's `_schema_version` is **older** than this daemon binary
    /// supports — the config migration framework has not yet applied
    /// pending migrations to bring the file up to date. `hint` points the
    /// operator at `sandbox update` as the rollforward path.
    ///
    /// The literal token `users.conf schema version <N> is older` is
    /// load-bearing for `integration_daemon_refuses_start_on_schema_too_old`.
    #[error(
        "users.conf schema version {file_version} is older than this binary supports (min: {daemon_min}). {hint}"
    )]
    SchemaTooOld {
        file_version: u32,
        daemon_min: u32,
        hint: String,
    },
}

// ---------------------------------------------------------------------------
// Daemon-side schema-mismatch refusal (Spec 5 § 4.7)
// ---------------------------------------------------------------------------

/// The newest `users.conf` schema version this daemon binary can read.
///
/// At v1, MAX equals MIN (both 1) because only one schema version exists.
/// The pair establishes the pattern: when a future daemon supports both
/// v1 and v2 files (e.g. a rolling-upgrade window where some operators
/// have already run `sandbox update` but others haven't yet), MIN stays
/// at 1 and MAX advances to 2. The validator's `MIN <= v <= MAX` range
/// check is written once and covers both eras without modification.
pub const DAEMON_MAX_SUPPORTED_USERS_CONF_SCHEMA: u32 = 1;

/// The oldest `users.conf` schema version this daemon binary can read.
/// See [`DAEMON_MAX_SUPPORTED_USERS_CONF_SCHEMA`] for the rationale on
/// keeping MIN and MAX as separate constants even when they share a
/// value today.
pub const DAEMON_MIN_SUPPORTED_USERS_CONF_SCHEMA: u32 = 1;

/// Validate that a loaded [`UsersConfig`]'s `_schema_version` is in the
/// daemon's supported range.
///
/// Called by the daemon immediately after `load_users_config()` succeeds
/// (Spec 5 § 4.7 — convergence anchor that forces operators to run
/// `sandbox update` when the config file drifts behind the binary's
/// supported version). The file's `_schema_version` is `Option<u32>`
/// (Spec 1 § 4.2) — `None` is treated as `0`, which means a pre-V001
/// file fails the `MIN >= 1` check on a daemon that requires V001.
///
/// Returns `Err(SchemaTooNew { .. })` when the file is ahead of the
/// daemon (typical cause: downgrade or interrupted update), and
/// `Err(SchemaTooOld { .. })` when the file is behind (typical cause:
/// daemon was upgraded but the framework hasn't applied pending
/// migrations yet). Both variants carry a `hint` that names
/// `sandbox update` and the backup directory so the operator's recovery
/// path is one read away.
pub fn validate_users_conf_schema_version(cfg: &UsersConfig) -> Result<(), UsersConfigError> {
    let v = cfg.schema_version.unwrap_or(0);
    if v > DAEMON_MAX_SUPPORTED_USERS_CONF_SCHEMA {
        return Err(UsersConfigError::SchemaTooNew {
            file_version: v,
            daemon_max: DAEMON_MAX_SUPPORTED_USERS_CONF_SCHEMA,
            hint: "This typically indicates a downgrade or an interrupted update. \
                   Run `sandbox update` to fix, or restore from backup at \
                   /var/lib/sandbox/backups/<latest>/users.conf.bak."
                .to_string(),
        });
    }
    if v < DAEMON_MIN_SUPPORTED_USERS_CONF_SCHEMA {
        return Err(UsersConfigError::SchemaTooOld {
            file_version: v,
            daemon_min: DAEMON_MIN_SUPPORTED_USERS_CONF_SCHEMA,
            hint: "The config migration framework has not yet applied pending migrations. \
                   Run `sandbox update` to bring the file up to date."
                .to_string(),
        });
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Cidr4
// ---------------------------------------------------------------------------

/// IPv4 CIDR — a `(base, prefix_len)` pair where `base` is the network
/// address (no host bits set) and `prefix_len` is in `[0, 32]`.
///
/// Validation happens at parse time so the daemon can hand `(base,
/// prefix_len)` directly to [`crate::NetworkManager::new`] without a
/// second round of error handling. Operators sometimes write
/// `192.168.1.1/24` meaning "/24 with my IP at .1" — we reject that
/// shape and require the canonical network address (e.g.
/// `192.168.1.0/24`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cidr4 {
    base: Ipv4Addr,
    prefix_len: u8,
}

impl Cidr4 {
    /// Parse a CIDR string of the form `"a.b.c.d/n"`. The error type
    /// uses static reasons so it can be embedded in
    /// [`UsersConfigError::InvalidCidr`] without per-call allocation.
    ///
    /// `pub` so the orphan-reaper module (and its integration tests
    /// under `sandbox-core/tests/`) can build `Cidr4` values for the
    /// dual-anchor CIDR pool gate without crossing back through serde
    /// or the users.conf loader.
    ///
    /// Internal API — `#[doc(hidden)]` so it does not appear in the
    /// rendered crate docs and so downstream crates do not treat it as
    /// stable surface. The only callers are
    /// `sandbox-core::users_conf` (Deserialize / `first_invalid_cidr`),
    /// `sandbox-core::backend::orphan_reaper`, and the
    /// `sandbox-core/tests/integration_orphan_reaper*` integration
    /// tests. No external crate (`sandboxd`, `sandbox-cli`,
    /// `sandbox-route-helper`, the nft loggers, `sandbox-event-emitter`,
    /// `sandbox-guest`) calls `parse` — `sandboxd` consumes `Cidr4`
    /// only as a value type. Signature may change without notice.
    #[doc(hidden)]
    pub fn parse(value: &str) -> Result<Self, &'static str> {
        let (addr_str, prefix_str) = value
            .split_once('/')
            .ok_or("missing prefix; expected the form `a.b.c.d/n` (e.g. 10.209.0.0/20)")?;

        let base: Ipv4Addr = addr_str.parse().map_err(|_| "invalid IPv4 address")?;

        let prefix_len: u8 = prefix_str.parse().map_err(|_| "invalid prefix length")?;

        if prefix_len > 32 {
            return Err("prefix length out of range; expected 0..=32");
        }

        // Reject host bits set in the base. For prefix_len == 32 every
        // address is a "network address" by itself; for prefix_len == 0
        // the only valid base is 0.0.0.0. The mask construction below
        // handles both edges cleanly via 64-bit arithmetic (`1u64 <<
        // 32` is well-defined).
        let host_bits = 32u32 - u32::from(prefix_len);
        let mask: u32 = if host_bits == 32 {
            0
        } else {
            !((1u32 << host_bits) - 1)
        };

        if u32::from(base) & !mask != 0 {
            return Err("host bits set; expected the network address (e.g. 10.209.0.0/20)");
        }

        Ok(Self { base, prefix_len })
    }

    /// Network base address (no host bits set).
    pub fn base(&self) -> Ipv4Addr {
        self.base
    }

    /// Prefix length in bits, in `[0, 32]`.
    pub fn prefix_len(&self) -> u8 {
        self.prefix_len
    }

    /// Test whether `ip` falls inside this CIDR.
    ///
    /// `0.0.0.0/0` contains every address; `a.b.c.d/32` contains
    /// exactly `a.b.c.d`.
    pub fn contains(&self, ip: Ipv4Addr) -> bool {
        let host_bits = 32u32 - u32::from(self.prefix_len);
        let mask: u32 = if host_bits == 32 {
            0
        } else {
            !((1u32 << host_bits) - 1)
        };
        (u32::from(ip) & mask) == (u32::from(self.base) & mask)
    }
}

impl<'de> Deserialize<'de> for Cidr4 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        // We surface the parse failure as a serde error so the file
        // path / line / column from `serde_json` flow up unchanged. The
        // higher-level loader then converts a generic ParseFailed into
        // a typed InvalidCidr by re-checking the value with
        // `Cidr4::parse` against the raw text — see
        // `first_invalid_cidr`. Until then, callers using
        // `serde_json::from_str::<UsersConfig>` directly still get a
        // descriptive message.
        let s: String = String::deserialize(deserializer)?;
        Cidr4::parse(&s).map_err(serde::de::Error::custom)
    }
}

// ---------------------------------------------------------------------------
// UsersConfig
// ---------------------------------------------------------------------------

/// Top-level shape of `users.conf`.
///
/// Example file (per spec § "Config file"):
///
/// ```json
/// {
///   "subnets": [
///     { "cidr": "10.209.0.0/20", "allow_users": ["olek"] },
///     { "cidr": "10.210.0.0/20", "allow_users": ["alice", "bob"] }
///   ]
/// }
/// ```
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UsersConfig {
    /// Schema version of the on-disk file, written as the `_schema_version`
    /// key. `None` means the file predates the migration framework and is
    /// treated as version `0` by the framework (Spec 5); V001 advances it
    /// to `Some(1)`. The underscore prefix is the project's convention for
    /// metadata that sits alongside domain data inside the same JSON
    /// object — the Rust field name stays idiomatic via `#[serde(rename)]`.
    #[serde(default, rename = "_schema_version")]
    pub schema_version: Option<u32>,
    /// One entry per allocation subnet. Order is preserved; the lookup
    /// helpers return the **first** match, so operators control
    /// precedence by ordering when CIDRs overlap (uncommon but legal).
    pub subnets: Vec<SubnetEntry>,
}

/// One subnet entry: a CIDR and the usernames authorized to allocate
/// containers within it.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SubnetEntry {
    /// Subnet CIDR. Validated at parse time — see [`Cidr4`].
    pub cidr: Cidr4,
    /// Usernames authorized for this subnet. Resolved to numeric uids
    /// at lookup time via `getpwnam_r`; not validated at parse time, so
    /// the file remains parseable on hosts where some referenced users
    /// don't yet exist (e.g. an admin staging a config before
    /// provisioning the user account).
    pub allow_users: Vec<String>,
    /// Free-form operator-facing description of what this subnet pool is
    /// for. Informational only — no code reads it. Optional so older
    /// `users.conf` files without the field continue to parse; the
    /// `deny_unknown_fields` guard on the struct is preserved so typos
    /// on unrelated fields are still rejected.
    #[serde(default)]
    pub comment: Option<String>,
}

impl UsersConfig {
    /// Find the subnet whose CIDR contains `gateway_ip`.
    ///
    /// Used by the route helper at step 3 of the authorization flow.
    /// Pure — no syscalls, no allocation.
    ///
    /// Returns the **first** matching subnet if entries overlap.
    pub fn find_subnet_by_gateway_ip(&self, gateway_ip: Ipv4Addr) -> Option<&SubnetEntry> {
        self.subnets
            .iter()
            .find(|entry| entry.cidr.contains(gateway_ip))
    }

    /// Find the first subnet whose `allow_users` resolves to
    /// `target_uid`.
    ///
    /// Used by:
    /// - the daemon at startup with its own uid (to choose the
    ///   allocation CIDR);
    /// - the route helper at step 4 with the caller's uid (to
    ///   authorize).
    ///
    /// Resolves each `allow_users` entry via `getpwnam_r` and compares
    /// numerically. Per spec line 406-408: admin renames take effect
    /// immediately — no caching.
    pub fn find_subnet_by_uid(&self, target_uid: u32) -> Option<&SubnetEntry> {
        self.subnets
            .iter()
            .find(|entry| entry.allows_uid(target_uid))
    }
}

impl SubnetEntry {
    /// True iff any name in `allow_users` resolves via `getpwnam_r` to
    /// `target_uid`.
    ///
    /// Numeric comparison — does not depend on `getpwuid_r` of the
    /// caller. Names that do not exist on the host (`getpwnam_r`
    /// returns `Ok(None)`) are treated as non-matches; resolution
    /// errors (other than ENOENT) are logged at `warn!` and skipped, so
    /// a single unresolvable entry does not deny a caller who appears
    /// elsewhere in the same `allow_users` list.
    pub fn allows_uid(&self, target_uid: u32) -> bool {
        for name in &self.allow_users {
            match nix::unistd::User::from_name(name) {
                Ok(Some(user)) => {
                    if user.uid.as_raw() == target_uid {
                        return true;
                    }
                }
                Ok(None) => {
                    // User not on this host — admin may have staged
                    // the config before provisioning the account.
                    // Treat as non-match.
                }
                Err(err) => {
                    warn!(
                        target: "sandbox_core::users_conf",
                        user = %name,
                        error = %err,
                        "getpwnam_r failed; skipping entry"
                    );
                }
            }
        }
        false
    }
}

// ---------------------------------------------------------------------------
// Migration V001 — pure transform
// ---------------------------------------------------------------------------

/// Apply migration **V001** to a `users.conf` value: stamp
/// `_schema_version: 1` at the top level and ensure every pool's
/// `allow_users` array contains `"sandbox"` (prepended if absent).
///
/// The transform is **pure** — no I/O, no path resolution, no
/// `UsersConfig` round-trip. It operates on `serde_json::Value` directly
/// so it can ingest inputs that pre-date the post-V001 strict schema
/// (e.g. a file with no `_schema_version` field, which would not yet
/// satisfy the typed shape if the field were non-optional). The file-IO
/// wrapper (atomic-rename write, lock file, backup folder) is owned by
/// the migration framework in Spec 5; this function is the content
/// contribution from Spec 1.
///
/// # Idempotency
///
/// Running the transform twice yields a value equal to running it once.
/// Two distinct paths reach this contract:
///
/// - A file already at `_schema_version: 1` is unchanged. (The framework
///   never invokes this branch under normal operation per Spec 5 § 4.2 —
///   it returns early when current == target — but the branch remains as
///   defense-in-depth for ad-hoc test or tool invocations.)
/// - A pool whose `allow_users` already contains `"sandbox"` is left
///   untouched, including operator-chosen order (e.g. `["alice",
///   "sandbox"]` stays in that order rather than being shuffled into the
///   canonical `["sandbox", "alice"]`).
///
/// # Shape preservation
///
/// Inputs that are not `Value::Object` (or whose `subnets` field is not
/// an array, or whose `allow_users` is not an array) are returned
/// unchanged — the framework will validate the produced value against
/// `UsersConfig` after the transform runs (Spec 5), so a malformed input
/// surfaces as a typed parse error downstream rather than a silent
/// mutation here. We deliberately do not coerce or repair shapes the
/// strict schema would reject.
pub fn migrate_v001(value: serde_json::Value) -> serde_json::Value {
    let serde_json::Value::Object(mut obj) = value else {
        return value;
    };

    obj.insert(
        "_schema_version".to_string(),
        serde_json::Value::Number(1u32.into()),
    );

    if let Some(serde_json::Value::Array(subnets)) = obj.get_mut("subnets") {
        for entry in subnets.iter_mut() {
            let Some(entry_obj) = entry.as_object_mut() else {
                continue;
            };
            let Some(serde_json::Value::Array(allow_users)) = entry_obj.get_mut("allow_users")
            else {
                continue;
            };
            let already_has_sandbox = allow_users.iter().any(|n| n.as_str() == Some("sandbox"));
            if !already_has_sandbox {
                allow_users.insert(0, serde_json::Value::String("sandbox".to_string()));
            }
        }
    }

    serde_json::Value::Object(obj)
}

// ---------------------------------------------------------------------------
// Path resolution and loading
// ---------------------------------------------------------------------------

/// Resolve the on-disk path of `users.conf` for daemon callers.
///
/// Honors `SANDBOX_USERS_CONF` unconditionally — the daemon runs as the
/// operator, so the env-var seam consumed by the daemon-startup
/// integration tests is not a privilege boundary. Production daemons
/// rely on the default path; tests set the env var to a tempfile they
/// own.
///
/// **The route helper must NOT use this function.** See
/// [`route_helper_users_conf_path`] for the helper-side equivalent
/// whose env-var consultation is feature-gated behind `test-env-override`.
pub fn users_conf_path() -> PathBuf {
    if let Ok(p) = std::env::var(USERS_CONF_PATH_ENV) {
        return PathBuf::from(p);
    }
    PathBuf::from(DEFAULT_USERS_CONF_PATH)
}

/// Resolve the on-disk path of `users.conf` for the
/// `sandbox-route-helper` binary.
///
/// Default builds (production) ignore `SANDBOX_USERS_CONF` and always
/// return [`DEFAULT_USERS_CONF_PATH`]. The route helper runs with
/// `cap_sys_admin+ep` (file capabilities); honoring an
/// attacker-controlled env var would redirect the authorization-config
/// read inside a privileged binary, which is a local privilege
/// escalation. Default builds therefore cannot consult the env var.
///
/// Test builds enable the `test-env-override` feature on `sandbox-core`
/// (typically forwarded via `sandbox-route-helper/test-env-override`)
/// and consult the env var so the route-helper integration tests can
/// drive the authorization flow against a tempfile users.conf they
/// own.
pub fn route_helper_users_conf_path() -> PathBuf {
    #[cfg(feature = "test-env-override")]
    if let Ok(p) = std::env::var(USERS_CONF_PATH_ENV) {
        return PathBuf::from(p);
    }
    PathBuf::from(DEFAULT_USERS_CONF_PATH)
}

/// Load and validate the users config from the daemon-resolved path
/// ([`users_conf_path`]).
pub fn load_users_config() -> Result<UsersConfig, UsersConfigError> {
    load_users_config_from(&users_conf_path())
}

/// Load and validate the users config from the route-helper-resolved
/// path ([`route_helper_users_conf_path`]).
///
/// The privilege-aware entry point used by `sandbox-route-helper`'s
/// `main.rs`. Default builds always read [`DEFAULT_USERS_CONF_PATH`];
/// `test-env-override` builds honor `SANDBOX_USERS_CONF` for tests.
pub fn load_users_config_route_helper() -> Result<UsersConfig, UsersConfigError> {
    load_users_config_from(&route_helper_users_conf_path())
}

/// Load and validate the users config from `path`.
///
/// Both [`load_users_config`] and [`load_users_config_route_helper`]
/// route through here so the defensive ownership/mode check on the
/// canonical `/etc/sandboxd/users.conf` path is shared between daemon
/// and helper. Tempfile paths used by tests pass through unchanged
/// (only the canonical path triggers the check); see
/// `validate_canonical_users_conf_security`.
pub fn load_users_config_from(path: &Path) -> Result<UsersConfig, UsersConfigError> {
    validate_canonical_users_conf_security(path)?;

    let raw = match fs::read_to_string(path) {
        Ok(s) => s,
        Err(err) if err.kind() == io::ErrorKind::NotFound => {
            return Err(UsersConfigError::FileNotFound(path.to_path_buf()));
        }
        Err(err) => {
            return Err(UsersConfigError::ReadFailed {
                path: path.to_path_buf(),
                source: err,
            });
        }
    };

    parse_users_config(&raw, path)
}

/// Defensive ownership/mode check applied at config-load time when the
/// path resolves to the canonical [`DEFAULT_USERS_CONF_PATH`].
///
/// We refuse to read the file if it is not owned by uid 0, if it
/// carries any group- or world-write bits, or if it is a symlink. The
/// route helper runs with `cap_sys_admin+ep`; if the auth file were
/// group/world-writable, any local user could rewrite their own
/// `allow_users` entry and grant themselves access to a foreign subnet.
/// Linux guarantees that uid 0 is `root`, so an explicit numeric check
/// is sufficient and avoids pulling in a name-resolver crate.
///
/// **Symlink behavior.** This check uses [`fs::symlink_metadata`], which
/// does **not** follow symlinks. If `/etc/sandboxd/users.conf` is a
/// symlink we refuse to read it — even if the target happens to be
/// root-owned and 0644 — because a writable directory anywhere in the
/// link's parent chain (or write-access to the link itself) lets a
/// non-root user re-point the auth file at a config they control. The
/// install runbook places a regular file at the canonical path, so the
/// documented configuration trips no extra check; operators who
/// previously placed a symlink there must replace it with a regular
/// file (or, equivalently, copy the target's contents in place).
///
/// We deliberately scope this to the canonical path only:
///
/// - Tempfile-based tests (anywhere outside `/etc/sandboxd/`) bypass the
///   check naturally, so unit tests and the route-helper integration
///   tests using `SANDBOX_USERS_CONF`-pointed tempfiles pass through.
/// - Operators who genuinely run with a non-root-owned config at the
///   canonical path are misconfigured and want the loud failure.
/// - A missing file is signalled later by `FileNotFound` from
///   `read_to_string`, not here, so the existing error path stays
///   intact.
fn validate_canonical_users_conf_security(path: &Path) -> Result<(), UsersConfigError> {
    validate_users_conf_security_against(path, Path::new(DEFAULT_USERS_CONF_PATH))
}

/// Inner of [`validate_canonical_users_conf_security`], parameterized
/// over the canonical path so unit tests can pin the check against a
/// temp directory they own (and can chmod / chown-via-current-state).
/// Production callers always pass [`DEFAULT_USERS_CONF_PATH`].
fn validate_users_conf_security_against(
    path: &Path,
    canonical: &Path,
) -> Result<(), UsersConfigError> {
    if path != canonical {
        return Ok(());
    }
    // Use `symlink_metadata` rather than `metadata` so a symlink at the
    // canonical path is examined directly (as a symlink), not transparently
    // followed to its target. Otherwise an attacker who can write into any
    // directory along the link's parent chain can re-point the canonical
    // path at a config they own and pass the ownership/mode check via the
    // target's attributes.
    let meta = match fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(err) if err.kind() == io::ErrorKind::NotFound => {
            // Defer NotFound to `load_users_config_from`'s `read_to_string`
            // arm so the existing `FileNotFound` error variant (with its
            // operator-friendly install-docs hint) is what surfaces.
            return Ok(());
        }
        Err(err) => {
            return Err(UsersConfigError::ReadFailed {
                path: path.to_path_buf(),
                source: err,
            });
        }
    };
    if meta.file_type().is_symlink() {
        return Err(UsersConfigError::InsecureFile {
            path: path.to_path_buf(),
            reason: "file must not be a symlink; replace it with a regular file per the \
                     install step in docs/start/installation.md",
        });
    }
    use std::os::unix::fs::MetadataExt;
    if meta.uid() != 0 {
        return Err(UsersConfigError::InsecureFile {
            path: path.to_path_buf(),
            reason: "file must be owned by root (uid 0); re-run the install step in \
                     docs/start/installation.md to repair",
        });
    }
    let mode = meta.mode() & 0o7777;
    if !is_secure_mode(mode) {
        return Err(UsersConfigError::InsecureFile {
            path: path.to_path_buf(),
            reason: "file must not be group- or world-writable (no `g+w` or `o+w` bits); \
                     re-run the install step in docs/start/installation.md to repair",
        });
    }
    Ok(())
}

/// Pure mode-bits predicate: true iff `mode` carries neither group-write
/// (`S_IWGRP` = `0o020`) nor world-write (`S_IWOTH` = `0o002`).
///
/// Even a root-owned but mode `0o646` file means a non-root user can
/// rewrite the auth list — the wrapper [`validate_users_conf_security_against`]
/// rejects on either arm. Extracted to a pure helper so the matrix of
/// (group-write, world-write) combinations can be exercised by unit
/// tests that cannot chown a tempfile to root.
fn is_secure_mode(mode: u32) -> bool {
    mode & 0o022 == 0
}

/// Parse `raw` (the file contents) into a [`UsersConfig`], attaching
/// `path` to any error variant. Split out from
/// [`load_users_config_from`] to give the [`Cidr4`] parse failures a
/// place to be reclassified from a generic JSON error into the typed
/// [`UsersConfigError::InvalidCidr`] variant — see implementation notes.
fn parse_users_config(raw: &str, path: &Path) -> Result<UsersConfig, UsersConfigError> {
    // First try a generic parse. On failure, see if we can pin it on a
    // specific CIDR field — that gives operators a much better error
    // message than the bare serde "invalid value" rendering. We do this
    // by re-parsing into a shape that preserves CIDRs as raw strings,
    // re-validating each one with `Cidr4::parse`, and surfacing the
    // first specific failure as `InvalidCidr`. If that probe doesn't
    // fire, we fall back to the original `serde_json::Error`.
    match serde_json::from_str::<UsersConfig>(raw) {
        Ok(cfg) => Ok(cfg),
        Err(orig) => {
            if let Some(cidr_err) = first_invalid_cidr(raw, path) {
                Err(cidr_err)
            } else {
                Err(UsersConfigError::ParseFailed {
                    path: path.to_path_buf(),
                    source: orig,
                })
            }
        }
    }
}

/// Re-parse `raw` into a permissive shape that keeps `cidr` as a string
/// and check each CIDR with [`Cidr4::parse`]. Returns the first failure
/// as a typed [`UsersConfigError::InvalidCidr`], or `None` if every
/// CIDR string parses cleanly (in which case the original error must
/// have been about something else — unknown fields, wrong types, etc.).
fn first_invalid_cidr(raw: &str, path: &Path) -> Option<UsersConfigError> {
    #[derive(Deserialize)]
    struct Probe {
        subnets: Vec<ProbeEntry>,
    }
    #[derive(Deserialize)]
    struct ProbeEntry {
        cidr: String,
        // Other fields ignored — we only care about CIDR shape here.
    }

    let probe: Probe = serde_json::from_str(raw).ok()?;
    for entry in probe.subnets {
        if let Err(reason) = Cidr4::parse(&entry.cidr) {
            return Some(UsersConfigError::InvalidCidr {
                path: path.to_path_buf(),
                value: entry.cidr,
                reason,
            });
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    /// Write `contents` to a fresh tempfile and return it. The tempfile
    /// is held by the caller so its on-disk path survives until drop.
    fn write_tempfile(contents: &str) -> NamedTempFile {
        let mut f = NamedTempFile::new().expect("tempfile");
        f.write_all(contents.as_bytes()).expect("write");
        f.flush().expect("flush");
        f
    }

    // -----------------------------------------------------------------
    // Roundtrip parse — happy path matching the spec example.
    // -----------------------------------------------------------------

    #[test]
    fn parses_spec_example_two_subnets() {
        let raw = r#"{
            "subnets": [
                { "cidr": "10.209.0.0/20", "allow_users": ["olek"] },
                { "cidr": "10.210.0.0/20", "allow_users": ["alice", "bob"] }
            ]
        }"#;
        let f = write_tempfile(raw);
        let cfg = load_users_config_from(f.path()).expect("parse");

        assert_eq!(cfg.subnets.len(), 2);

        assert_eq!(cfg.subnets[0].cidr.base(), Ipv4Addr::new(10, 209, 0, 0));
        assert_eq!(cfg.subnets[0].cidr.prefix_len(), 20);
        assert_eq!(cfg.subnets[0].allow_users, vec!["olek".to_string()]);

        assert_eq!(cfg.subnets[1].cidr.base(), Ipv4Addr::new(10, 210, 0, 0));
        assert_eq!(cfg.subnets[1].cidr.prefix_len(), 20);
        assert_eq!(
            cfg.subnets[1].allow_users,
            vec!["alice".to_string(), "bob".to_string()]
        );
    }

    // -----------------------------------------------------------------
    // Missing file.
    // -----------------------------------------------------------------

    #[test]
    fn missing_file_yields_file_not_found() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("does-not-exist.json");
        let err = load_users_config_from(&path).expect_err("must fail");
        match err {
            UsersConfigError::FileNotFound(p) => {
                assert_eq!(p, path);
                let msg = UsersConfigError::FileNotFound(path.clone()).to_string();
                assert!(
                    msg.contains(path.to_str().unwrap()),
                    "message must include the path, got {msg}"
                );
                assert!(
                    msg.contains("install docs"),
                    "message must point at install docs, got {msg}"
                );
            }
            other => panic!("expected FileNotFound, got {other:?}"),
        }
    }

    // -----------------------------------------------------------------
    // Malformed JSON.
    // -----------------------------------------------------------------

    #[test]
    fn malformed_json_yields_parse_failed() {
        let f = write_tempfile("not json");
        let err = load_users_config_from(f.path()).expect_err("must fail");
        let display = err.to_string();
        match err {
            UsersConfigError::ParseFailed { path, .. } => {
                assert_eq!(path, f.path());
                assert!(
                    display.contains(f.path().to_str().unwrap()),
                    "message must include path, got {display}"
                );
            }
            other => panic!("expected ParseFailed, got {other:?}"),
        }
    }

    // -----------------------------------------------------------------
    // deny_unknown_fields enforcement.
    // -----------------------------------------------------------------

    #[test]
    fn unknown_top_level_field_rejected() {
        let raw = r#"{
            "subnets": [
                { "cidr": "10.209.0.0/20", "allow_users": ["olek"] }
            ],
            "extra_field": 1
        }"#;
        let f = write_tempfile(raw);
        let err = load_users_config_from(f.path()).expect_err("must fail");
        assert!(
            matches!(err, UsersConfigError::ParseFailed { .. }),
            "expected ParseFailed for unknown top-level field, got {err:?}"
        );
    }

    #[test]
    fn unknown_subnet_field_rejected() {
        let raw = r#"{
            "subnets": [
                {
                    "cidr": "10.209.0.0/20",
                    "allow_users": ["olek"],
                    "stowaway": true
                }
            ]
        }"#;
        let f = write_tempfile(raw);
        let err = load_users_config_from(f.path()).expect_err("must fail");
        assert!(
            matches!(err, UsersConfigError::ParseFailed { .. }),
            "expected ParseFailed for unknown subnet-entry field, got {err:?}"
        );
    }

    /// A typo on a known field name (`alow_users` instead of
    /// `allow_users`) must still trip `deny_unknown_fields`. This guards
    /// against accidentally regressing the typo-detection when the
    /// optional `comment` field is added — the guard rests on the
    /// `deny_unknown_fields` attribute on the struct, and the optional
    /// `#[serde(default)]` field is allowed to coexist with it.
    #[test]
    fn typo_on_allow_users_field_rejected() {
        let raw = r#"{
            "subnets": [
                {
                    "cidr": "10.209.0.0/20",
                    "alow_users": ["olek"]
                }
            ]
        }"#;
        let f = write_tempfile(raw);
        let err = load_users_config_from(f.path()).expect_err("must fail");
        assert!(
            matches!(err, UsersConfigError::ParseFailed { .. }),
            "expected ParseFailed for typo on `allow_users`, got {err:?}"
        );
    }

    // -----------------------------------------------------------------
    // Optional `comment` field — parsed when present, defaults to None
    // when absent. Informational only; no code reads it. The field's
    // `#[serde(default)]` lets older files without it keep parsing
    // while `deny_unknown_fields` continues to catch typos on unrelated
    // field names (covered by `typo_on_allow_users_field_rejected`).
    // -----------------------------------------------------------------

    #[test]
    fn comment_field_populates_option_when_present() {
        let raw = r#"{
            "subnets": [
                {
                    "comment": "Production pool — operator's daemon.",
                    "cidr": "10.209.0.0/20",
                    "allow_users": ["olek"]
                }
            ]
        }"#;
        let f = write_tempfile(raw);
        let cfg = load_users_config_from(f.path()).expect("parse");
        assert_eq!(cfg.subnets.len(), 1);
        assert_eq!(
            cfg.subnets[0].comment.as_deref(),
            Some("Production pool — operator's daemon."),
        );
    }

    #[test]
    fn comment_field_absent_yields_none() {
        let raw = r#"{
            "subnets": [
                { "cidr": "10.209.0.0/20", "allow_users": ["olek"] }
            ]
        }"#;
        let f = write_tempfile(raw);
        let cfg = load_users_config_from(f.path()).expect("parse");
        assert_eq!(cfg.subnets.len(), 1);
        assert!(
            cfg.subnets[0].comment.is_none(),
            "comment must default to None when absent, got {:?}",
            cfg.subnets[0].comment,
        );
    }

    // -----------------------------------------------------------------
    // Invalid CIDR strings.
    // -----------------------------------------------------------------

    fn assert_cidr_rejected(value: &str) {
        let raw = format!(r#"{{ "subnets": [ {{ "cidr": "{value}", "allow_users": [] }} ] }}"#);
        let f = write_tempfile(&raw);
        let err = load_users_config_from(f.path()).expect_err("must fail");
        match err {
            UsersConfigError::InvalidCidr {
                path,
                value: v,
                reason,
            } => {
                assert_eq!(path, f.path());
                assert_eq!(v, value);
                assert!(!reason.is_empty(), "reason must be non-empty");
            }
            other => panic!("expected InvalidCidr for {value:?}, got {other:?}"),
        }
    }

    #[test]
    fn cidr_missing_prefix_rejected() {
        assert_cidr_rejected("10.209.0.0");
    }

    #[test]
    fn cidr_prefix_above_32_rejected() {
        assert_cidr_rejected("10.209.0.0/33");
    }

    #[test]
    fn cidr_with_host_bits_rejected() {
        assert_cidr_rejected("10.209.0.5/20");
    }

    #[test]
    fn cidr_bad_address_rejected() {
        assert_cidr_rejected("not-an-ip/20");
    }

    #[test]
    fn cidr_bad_prefix_rejected() {
        assert_cidr_rejected("10.209.0.0/abc");
    }

    #[test]
    fn cidr_host_bits_error_message_mentions_network_address() {
        // Verifies the static reason text the spec calls for: operators
        // confused about base vs. host address get a clear hint.
        let err = Cidr4::parse("10.209.0.5/20").unwrap_err();
        assert!(
            err.contains("network address"),
            "host-bits-set message must mention 'network address', got {err}"
        );
    }

    // -----------------------------------------------------------------
    // Cidr4::contains.
    // -----------------------------------------------------------------

    #[test]
    fn contains_basic_membership() {
        let c = Cidr4::parse("10.209.0.0/20").unwrap();
        assert!(c.contains(Ipv4Addr::new(10, 209, 5, 42)));
        assert!(c.contains(Ipv4Addr::new(10, 209, 0, 0)));
        assert!(!c.contains(Ipv4Addr::new(10, 210, 0, 1)));
    }

    #[test]
    fn contains_full_zero_prefix() {
        // /0 contains every address.
        let c = Cidr4::parse("0.0.0.0/0").unwrap();
        assert!(c.contains(Ipv4Addr::new(0, 0, 0, 0)));
        assert!(c.contains(Ipv4Addr::new(255, 255, 255, 255)));
        assert!(c.contains(Ipv4Addr::new(10, 209, 5, 42)));
    }

    #[test]
    fn contains_host_route_prefix_32() {
        let c = Cidr4::parse("10.209.0.0/32").unwrap();
        assert!(c.contains(Ipv4Addr::new(10, 209, 0, 0)));
        assert!(!c.contains(Ipv4Addr::new(10, 209, 0, 1)));
        assert!(!c.contains(Ipv4Addr::new(10, 209, 0, 255)));
    }

    // -----------------------------------------------------------------
    // find_subnet_by_gateway_ip.
    // -----------------------------------------------------------------

    fn cfg_with_two_subnets() -> UsersConfig {
        let raw = r#"{
            "subnets": [
                { "cidr": "10.209.0.0/20", "allow_users": ["olek"] },
                { "cidr": "10.210.0.0/20", "allow_users": ["alice", "bob"] }
            ]
        }"#;
        let f = write_tempfile(raw);
        load_users_config_from(f.path()).expect("parse")
    }

    #[test]
    fn find_subnet_by_gateway_ip_hit() {
        let cfg = cfg_with_two_subnets();
        let entry = cfg
            .find_subnet_by_gateway_ip(Ipv4Addr::new(10, 209, 5, 2))
            .expect("hit");
        assert_eq!(entry.cidr.base(), Ipv4Addr::new(10, 209, 0, 0));

        let entry = cfg
            .find_subnet_by_gateway_ip(Ipv4Addr::new(10, 210, 0, 2))
            .expect("hit");
        assert_eq!(entry.cidr.base(), Ipv4Addr::new(10, 210, 0, 0));
    }

    #[test]
    fn find_subnet_by_gateway_ip_miss() {
        let cfg = cfg_with_two_subnets();
        assert!(
            cfg.find_subnet_by_gateway_ip(Ipv4Addr::new(10, 211, 0, 1))
                .is_none()
        );
    }

    #[test]
    fn find_subnet_by_gateway_ip_overlap_returns_first() {
        // /16 superset followed by a /20 subset: an IP inside both
        // matches the /16 entry (which appears first). Operators who
        // need different precedence must reorder.
        let raw = r#"{
            "subnets": [
                { "cidr": "10.209.0.0/16", "allow_users": ["olek"] },
                { "cidr": "10.209.0.0/20", "allow_users": ["alice"] }
            ]
        }"#;
        let f = write_tempfile(raw);
        let cfg = load_users_config_from(f.path()).expect("parse");
        let hit = cfg
            .find_subnet_by_gateway_ip(Ipv4Addr::new(10, 209, 5, 1))
            .expect("hit");
        assert_eq!(hit.cidr.prefix_len(), 16, "first entry wins on overlap");
    }

    // -----------------------------------------------------------------
    // SubnetEntry::allows_uid / find_subnet_by_uid against the host's
    // /etc/passwd.
    //
    // These tests touch real `getpwnam_r`. They require the test
    // runner's username (whatever it is) to exist on the host — which
    // is universally true in any environment that supports running
    // unit tests.
    // -----------------------------------------------------------------

    #[cfg(target_os = "linux")]
    #[test]
    fn allows_uid_matches_runner_username() {
        let runner_uid = nix::unistd::Uid::current();
        let runner_user = nix::unistd::User::from_uid(runner_uid)
            .expect("getpwuid_r")
            .expect("runner uid must resolve to a user account");
        let raw = format!(
            r#"{{
                "subnets": [
                    {{ "cidr": "10.209.0.0/20", "allow_users": ["{}"] }}
                ]
            }}"#,
            runner_user.name
        );
        let f = write_tempfile(&raw);
        let cfg = load_users_config_from(f.path()).expect("parse");

        assert!(cfg.subnets[0].allows_uid(runner_uid.as_raw()));

        let hit = cfg.find_subnet_by_uid(runner_uid.as_raw()).expect("hit");
        assert_eq!(hit.cidr.base(), Ipv4Addr::new(10, 209, 0, 0));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn allows_uid_rejects_bogus_username() {
        let runner_uid = nix::unistd::Uid::current();
        let raw = r#"{
            "subnets": [
                {
                    "cidr": "10.209.0.0/20",
                    "allow_users": ["definitely-not-a-real-user-9c3f"]
                }
            ]
        }"#;
        let f = write_tempfile(raw);
        let cfg = load_users_config_from(f.path()).expect("parse");

        assert!(!cfg.subnets[0].allows_uid(runner_uid.as_raw()));
        assert!(cfg.find_subnet_by_uid(runner_uid.as_raw()).is_none());
    }

    // -----------------------------------------------------------------
    // Empty subnets / empty allow_users.
    // -----------------------------------------------------------------

    #[test]
    fn empty_subnets_array_parses_and_lookups_miss() {
        let f = write_tempfile(r#"{ "subnets": [] }"#);
        let cfg = load_users_config_from(f.path()).expect("parse");
        assert!(cfg.subnets.is_empty());
        assert!(
            cfg.find_subnet_by_gateway_ip(Ipv4Addr::new(10, 0, 0, 1))
                .is_none()
        );
        assert!(cfg.find_subnet_by_uid(0).is_none());
        assert!(cfg.find_subnet_by_uid(u32::MAX).is_none());
    }

    #[test]
    fn empty_allow_users_parses_and_allows_uid_returns_false() {
        let raw = r#"{
            "subnets": [
                { "cidr": "10.209.0.0/20", "allow_users": [] }
            ]
        }"#;
        let f = write_tempfile(raw);
        let cfg = load_users_config_from(f.path()).expect("parse");
        assert_eq!(cfg.subnets.len(), 1);
        assert!(!cfg.subnets[0].allows_uid(0));
        assert!(!cfg.subnets[0].allows_uid(1000));
    }

    // -----------------------------------------------------------------
    // users_conf_path env-var seam.
    // -----------------------------------------------------------------

    /// `users_conf_path` reads `SANDBOX_USERS_CONF` to support the
    /// route-helper / daemon-startup integration tests. Run serially
    /// since process-wide env vars are not test-isolated.
    #[test]
    fn users_conf_path_honors_env_override() {
        // SAFETY: setting/unsetting env vars is unsafe in Rust 2024
        // because of cross-thread races; we accept the risk in a unit
        // test that doesn't spawn other env-reading threads.
        let prev = std::env::var(USERS_CONF_PATH_ENV).ok();
        unsafe {
            std::env::set_var(USERS_CONF_PATH_ENV, "/tmp/test-users.conf");
        }
        let p = users_conf_path();
        assert_eq!(p, PathBuf::from("/tmp/test-users.conf"));

        // Restore prior state so we don't leak into other tests in the
        // same process.
        unsafe {
            match prev {
                Some(v) => std::env::set_var(USERS_CONF_PATH_ENV, v),
                None => std::env::remove_var(USERS_CONF_PATH_ENV),
            }
        }
    }

    // -----------------------------------------------------------------
    // route_helper_users_conf_path — env-var consultation gated by the
    // `test-env-override` feature.
    //
    // `cfg(feature = ...)` here is a compile-time check, so the two
    // tests below split on whether the crate is currently being
    // compiled with the feature enabled (route-helper integration
    // tests do this via the `test-env-override` feature on
    // `sandbox-route-helper`; default `cargo nextest run` builds do
    // not).
    // -----------------------------------------------------------------

    #[cfg(not(feature = "test-env-override"))]
    #[test]
    fn route_helper_users_conf_path_ignores_env_in_default_build() {
        let prev = std::env::var(USERS_CONF_PATH_ENV).ok();
        // SAFETY: see the rationale on `users_conf_path_honors_env_override`.
        unsafe {
            std::env::set_var(USERS_CONF_PATH_ENV, "/tmp/should-not-be-honored.conf");
        }
        let p = route_helper_users_conf_path();
        assert_eq!(
            p,
            PathBuf::from(DEFAULT_USERS_CONF_PATH),
            "default builds must ignore SANDBOX_USERS_CONF in route-helper-side resolution; \
             honoring it would let any local exec of the cap'd helper redirect its auth read"
        );
        unsafe {
            match prev {
                Some(v) => std::env::set_var(USERS_CONF_PATH_ENV, v),
                None => std::env::remove_var(USERS_CONF_PATH_ENV),
            }
        }
    }

    #[cfg(feature = "test-env-override")]
    #[test]
    fn route_helper_users_conf_path_honors_env_with_test_env_override_feature() {
        let prev = std::env::var(USERS_CONF_PATH_ENV).ok();
        // SAFETY: see the rationale on `users_conf_path_honors_env_override`.
        unsafe {
            std::env::set_var(USERS_CONF_PATH_ENV, "/tmp/test-users.conf");
        }
        let p = route_helper_users_conf_path();
        assert_eq!(
            p,
            PathBuf::from("/tmp/test-users.conf"),
            "with `test-env-override` enabled, SANDBOX_USERS_CONF must be honored so \
             route-helper integration tests can drive a tempfile config"
        );
        unsafe {
            match prev {
                Some(v) => std::env::set_var(USERS_CONF_PATH_ENV, v),
                None => std::env::remove_var(USERS_CONF_PATH_ENV),
            }
        }
    }

    // -----------------------------------------------------------------
    // Defensive ownership/mode check — `validate_users_conf_security_against`.
    //
    // We can't chown a tempfile to root from a non-root unit test, so
    // the uid-0 arm of `validate_users_conf_security_against` is
    // covered by the two `defensive_check_refuses_*` tests below: any
    // tempfile-owned-by-the-runner at the canonical path triggers
    // `InsecureFile` via the uid-0 check (which fires first, after the
    // symlink arm).
    //
    // The mode-bits arm is exercised independently by
    // `is_secure_mode_matrix` against the extracted `is_secure_mode`
    // helper — that's a pure function, so we can sweep every relevant
    // (group-write, world-write) combination without needing a real
    // file we can chown to root.
    //
    // The symlink arm is exercised by
    // `defensive_check_refuses_canonical_path_that_is_a_symlink`: it
    // points the "canonical" path at a tempfile via a symlink and
    // asserts the validator rejects on symlink grounds before the
    // uid-0 / mode-bits arms have a chance to fire.
    //
    // The positive arm of the wrapper (root-owned, 0644) is exercised
    // by the daemon at runtime *and* via the path-comparison bypass:
    // a tempfile path that is NOT the configured canonical path
    // passes through unchanged regardless of ownership/mode, so the
    // existing happy-path tests (`parses_spec_example_two_subnets`
    // etc.) prove the bypass works.
    // -----------------------------------------------------------------

    #[cfg(target_os = "linux")]
    #[test]
    fn defensive_check_refuses_non_root_owned_canonical_file() {
        // The test's tempfile is owned by the test runner's uid (≠ 0
        // in any normal CI environment), so passing the same tempfile
        // path as both `path` and `canonical` triggers the uid-0 arm.
        let f = write_tempfile(r#"{ "subnets": [] }"#);
        let err = validate_users_conf_security_against(f.path(), f.path())
            .expect_err("non-root-owned canonical file must be refused");
        match err {
            UsersConfigError::InsecureFile { path, reason } => {
                assert_eq!(path, f.path());
                assert!(
                    reason.contains("uid 0") || reason.contains("root"),
                    "reason should mention root/uid 0; got: {reason}"
                );
            }
            other => panic!("expected InsecureFile, got {other:?}"),
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn defensive_check_refuses_canonical_file_owned_by_non_root_even_when_world_writable() {
        // The test's tempfile is owned by the test runner's uid (≠ 0
        // in any normal CI environment). Setting mode `0o666` is
        // belt-and-suspenders — the uid-0 arm fires first regardless,
        // but exercising the canonical-path branch with a non-default
        // mode keeps redundant coverage of the uid-0 refusal.
        // The mode-bits arm is exercised separately by
        // `is_secure_mode_matrix` below, which does not need a real
        // file to chmod.
        use std::os::unix::fs::PermissionsExt;
        let f = write_tempfile(r#"{ "subnets": [] }"#);
        let mut perms = std::fs::metadata(f.path()).expect("stat").permissions();
        perms.set_mode(0o666);
        std::fs::set_permissions(f.path(), perms).expect("chmod");
        let err = validate_users_conf_security_against(f.path(), f.path())
            .expect_err("non-root-owned canonical file must be refused");
        assert!(
            matches!(err, UsersConfigError::InsecureFile { .. }),
            "expected InsecureFile, got {err:?}"
        );
    }

    #[test]
    fn is_secure_mode_matrix() {
        // The canonical secure modes the install runbook produces
        // (0o600 / 0o644) plus the partially-permissive shapes that
        // must still be accepted (0o640 grants read-only group). Every
        // mode that carries S_IWGRP (0o020) or S_IWOTH (0o002) — alone
        // or in combination — must be refused, regardless of owner-
        // permission bits, because the auth file's integrity rests on
        // it being writable only by root.
        let cases: &[(u32, bool)] = &[
            (0o600, true),
            (0o644, true),
            (0o640, true),
            (0o620, false), // S_IWGRP
            (0o602, false), // S_IWOTH
            (0o666, false), // S_IWGRP | S_IWOTH | owner-rw
            (0o066, false), // S_IWGRP | S_IWOTH, no owner perms
            (0o022, false), // S_IWGRP | S_IWOTH alone (no read bits)
        ];
        for (mode, expected) in cases.iter().copied() {
            assert_eq!(
                is_secure_mode(mode),
                expected,
                "is_secure_mode(0o{mode:o}) should be {expected}",
            );
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn defensive_check_refuses_canonical_path_that_is_a_symlink() {
        // A symlink at the canonical path is rejected even when its
        // target satisfies the ownership/mode check, because writability
        // anywhere in the link's parent chain (or write-access to the
        // link itself) lets a non-root user re-point the auth file at
        // a config they control. We exercise this by pointing the
        // "canonical" path at a regular tempfile via a symlink and
        // asserting the validator refuses on symlink grounds — this
        // arm fires before the uid-0 / mode-bits arms, so the test
        // does not need a root-owned target.
        let target = write_tempfile(r#"{ "subnets": [] }"#);
        let dir = tempfile::tempdir().expect("tempdir");
        let link = dir.path().join("users.conf");
        std::os::unix::fs::symlink(target.path(), &link).expect("symlink");

        let err = validate_users_conf_security_against(&link, &link)
            .expect_err("symlink at the canonical path must be refused");
        match err {
            UsersConfigError::InsecureFile { path, reason } => {
                assert_eq!(path, link);
                assert!(
                    reason.contains("symlink"),
                    "reason should mention symlink; got: {reason}"
                );
                assert!(
                    reason.contains("docs/start/installation.md"),
                    "reason should point at install runbook; got: {reason}"
                );
            }
            other => panic!("expected InsecureFile, got {other:?}"),
        }
    }

    #[test]
    fn defensive_check_skips_when_path_is_not_canonical() {
        // The whole point of the path-equality bypass: a tempfile
        // whose path is NOT the configured canonical path passes
        // unchanged regardless of ownership / mode. This is what
        // keeps every existing tempfile-based test in this file
        // (and the route-helper integration tests) green without
        // a per-test feature flag.
        let f = write_tempfile(r#"{ "subnets": [] }"#);
        let canonical = std::path::Path::new("/etc/sandboxd/users.conf");
        // f.path() is in /tmp/<random>, never == /etc/sandboxd/users.conf
        validate_users_conf_security_against(f.path(), canonical)
            .expect("non-canonical path must bypass the security check");
    }

    #[test]
    fn defensive_check_skips_when_canonical_file_does_not_exist() {
        // ENOENT on the canonical path defers to the regular
        // FileNotFound error variant downstream — the security check
        // must not pre-empt it.
        let dir = tempfile::tempdir().expect("tempdir");
        let nonexistent = dir.path().join("does-not-exist.conf");
        validate_users_conf_security_against(&nonexistent, &nonexistent)
            .expect("missing canonical file must defer to FileNotFound downstream");
    }

    // -----------------------------------------------------------------
    // `_schema_version` schema field.
    //
    // The field is `Option<u32>` + `#[serde(default)]`; older files
    // without it parse as `None`. `deny_unknown_fields` still rejects
    // typos verbatim — operator-facing error text contains the exact
    // mistyped key, so `serde_json` is the single source of truth for
    // the rejection message and we pin that contract here.
    // -----------------------------------------------------------------

    #[test]
    fn schema_version_absent_yields_none() {
        let raw = r#"{
            "subnets": [
                { "cidr": "10.209.0.0/20", "allow_users": ["olek"] }
            ]
        }"#;
        let f = write_tempfile(raw);
        let cfg = load_users_config_from(f.path()).expect("parse");
        assert!(
            cfg.schema_version.is_none(),
            "absent _schema_version must default to None, got {:?}",
            cfg.schema_version,
        );
    }

    #[test]
    fn schema_version_present_populates_option() {
        let raw = r#"{
            "_schema_version": 1,
            "subnets": [
                { "cidr": "10.209.0.0/20", "allow_users": ["olek"] }
            ]
        }"#;
        let f = write_tempfile(raw);
        let cfg = load_users_config_from(f.path()).expect("parse");
        assert_eq!(cfg.schema_version, Some(1));

        // Other u32 values round-trip the same way — the field's typing
        // is `Option<u32>`, not a "must be 1" constraint (that policy
        // belongs to the migration framework in Spec 5, not the parser).
        let raw_v7 = r#"{
            "_schema_version": 7,
            "subnets": []
        }"#;
        let f7 = write_tempfile(raw_v7);
        let cfg7 = load_users_config_from(f7.path()).expect("parse");
        assert_eq!(cfg7.schema_version, Some(7));
    }

    #[test]
    fn schema_version_typo_rejected() {
        // A close-but-wrong variant of `_schema_version` must trip
        // `deny_unknown_fields`; the parser's job is to reject
        // unrecognised keys verbatim so the operator sees their typo.
        let raw = r#"{
            "_schemaversion": 1,
            "subnets": [
                { "cidr": "10.209.0.0/20", "allow_users": ["olek"] }
            ]
        }"#;
        let f = write_tempfile(raw);
        let err = load_users_config_from(f.path()).expect_err("must fail");
        assert!(
            matches!(err, UsersConfigError::ParseFailed { .. }),
            "expected ParseFailed for typo on `_schema_version`, got {err:?}"
        );
    }

    /// Pin the `deny_unknown_fields` verbatim-key contract: a one-character
    /// typo (missing the `c` in `_schema_version`) is rejected, and the
    /// error string contains the exact mistyped key so the operator can
    /// see what they wrote. Future maintenance that swaps the rejection
    /// surface (custom `Deserialize` impl, hand-rolled validator) must
    /// keep this property.
    #[test]
    fn users_conf_schema_version_typo_rejected_with_clear_error() {
        let raw = r#"{
            "_shema_version": 1,
            "subnets": [
                { "cidr": "10.209.0.0/20", "allow_users": ["olek"] }
            ]
        }"#;
        let f = write_tempfile(raw);
        let err = load_users_config_from(f.path()).expect_err("must fail");
        let msg = err.to_string();
        assert!(
            matches!(err, UsersConfigError::ParseFailed { .. }),
            "expected ParseFailed for `_shema_version` typo, got {err:?}"
        );
        assert!(
            msg.contains("_shema_version"),
            "error message must name the mistyped key verbatim so the operator \
             can see exactly what they wrote; got: {msg}"
        );
    }

    // -----------------------------------------------------------------
    // Migration V001 — pure transform.
    //
    // Inputs and outputs follow Spec 1 § 5.5 verbatim. The transform is
    // pure (no I/O), so each row is a single `assert_eq!` between
    // `serde_json::Value` trees. `Value` equality is structural — key
    // order inside an object is not part of the comparison, so the spec
    // examples' textual order is incidental to the test contract.
    // -----------------------------------------------------------------

    /// Parse a JSON literal into a `serde_json::Value`. Tiny helper so the
    /// table-style tests below stay close to the spec's example shapes.
    fn json(raw: &str) -> serde_json::Value {
        serde_json::from_str(raw).expect("json literal must parse")
    }

    #[test]
    fn v001_adds_sandbox_to_single_user_pool() {
        // Spec § 5.5 — Input A → Output A.
        let input = json(
            r#"{
                "subnets": [
                    { "cidr": "10.209.0.0/24", "allow_users": ["alice"] }
                ]
            }"#,
        );
        let expected = json(
            r#"{
                "_schema_version": 1,
                "subnets": [
                    { "cidr": "10.209.0.0/24", "allow_users": ["sandbox", "alice"] }
                ]
            }"#,
        );
        assert_eq!(migrate_v001(input), expected);
    }

    #[test]
    fn v001_adds_sandbox_to_multiple_pools_independently() {
        // Spec § 5.5 — Input B → Output B. Each pool is migrated
        // independently; the operator's `comment` field rides through.
        let input = json(
            r#"{
                "subnets": [
                    { "cidr": "10.209.0.0/24", "allow_users": ["alice"], "comment": "alice prod" },
                    { "cidr": "10.210.0.0/24", "allow_users": ["bob", "carol"] }
                ]
            }"#,
        );
        let expected = json(
            r#"{
                "_schema_version": 1,
                "subnets": [
                    { "cidr": "10.209.0.0/24", "allow_users": ["sandbox", "alice"], "comment": "alice prod" },
                    { "cidr": "10.210.0.0/24", "allow_users": ["sandbox", "bob", "carol"] }
                ]
            }"#,
        );
        assert_eq!(migrate_v001(input), expected);
    }

    #[test]
    fn v001_noops_pool_already_containing_sandbox() {
        // Spec § 5.5 — Input C → Output C. Operator hand-added `sandbox`
        // in a different order; V001 must not shuffle.
        let input = json(
            r#"{
                "subnets": [
                    { "cidr": "10.209.0.0/24", "allow_users": ["alice", "sandbox"] }
                ]
            }"#,
        );
        let expected = json(
            r#"{
                "_schema_version": 1,
                "subnets": [
                    { "cidr": "10.209.0.0/24", "allow_users": ["alice", "sandbox"] }
                ]
            }"#,
        );
        assert_eq!(migrate_v001(input), expected);
    }

    #[test]
    fn v001_noops_when_schema_version_already_one() {
        // Spec § 5.5 — Input D. Bit-equal output.
        let input = json(
            r#"{
                "_schema_version": 1,
                "subnets": [
                    { "cidr": "10.209.0.0/24", "allow_users": ["sandbox", "alice"] }
                ]
            }"#,
        );
        let expected = input.clone();
        assert_eq!(migrate_v001(input), expected);
    }

    #[test]
    fn v001_preserves_comment_field() {
        // A subnet with an operator-supplied `comment` must keep it
        // through the transform — V001 touches `allow_users` and the
        // top-level `_schema_version` only.
        let input = json(
            r#"{
                "subnets": [
                    {
                        "cidr": "10.209.0.0/20",
                        "allow_users": ["alice"],
                        "comment": "alice prod — please leave this alone"
                    }
                ]
            }"#,
        );
        let output = migrate_v001(input);
        let comment = output
            .get("subnets")
            .and_then(|s| s.get(0))
            .and_then(|e| e.get("comment"))
            .and_then(|c| c.as_str());
        assert_eq!(comment, Some("alice prod — please leave this alone"));
    }

    #[test]
    fn v001_idempotent_when_run_twice() {
        // Pure-function idempotency: f(f(x)) == f(x). Covers both
        // observable branches (schema-version already at 1; sandbox
        // already in pool) on the second pass.
        let input = json(
            r#"{
                "subnets": [
                    { "cidr": "10.209.0.0/24", "allow_users": ["alice"] },
                    { "cidr": "10.210.0.0/24", "allow_users": ["bob"] }
                ]
            }"#,
        );
        let once = migrate_v001(input);
        let twice = migrate_v001(once.clone());
        assert_eq!(twice, once, "V001 must be idempotent on the second pass");
    }

    #[test]
    fn v001_preserves_existing_field_order_when_possible() {
        // The transform must not drop, rename, or add fields outside the
        // ones it owns (`_schema_version` at top level; `"sandbox"` inside
        // each `allow_users`). Operator-supplied keys at the subnet level
        // ride through; their presence in the output is a structural
        // contract independent of `serde_json::Value`'s map-ordering
        // implementation.
        let input = json(
            r#"{
                "subnets": [
                    {
                        "cidr": "10.209.0.0/24",
                        "allow_users": ["alice"],
                        "comment": "primary"
                    }
                ]
            }"#,
        );
        let output = migrate_v001(input);

        // Top level: gained exactly `_schema_version`; `subnets` still
        // present; nothing else.
        let top = output.as_object().expect("top is object");
        let top_keys: std::collections::BTreeSet<&str> = top.keys().map(|k| k.as_str()).collect();
        assert_eq!(
            top_keys,
            ["_schema_version", "subnets"].into_iter().collect(),
            "top-level keys must be exactly {{_schema_version, subnets}} after V001"
        );
        assert_eq!(top.get("_schema_version"), Some(&serde_json::json!(1)));

        // Subnet level: every original key survives; `allow_users` is
        // extended by the prepended `"sandbox"` entry.
        let entry = output["subnets"][0].as_object().expect("entry is object");
        let entry_keys: std::collections::BTreeSet<&str> =
            entry.keys().map(|k| k.as_str()).collect();
        assert_eq!(
            entry_keys,
            ["cidr", "allow_users", "comment"].into_iter().collect(),
            "subnet entry keys must be unchanged (no drops, no additions)"
        );
        assert_eq!(entry.get("comment"), Some(&serde_json::json!("primary")));
        assert_eq!(
            entry.get("allow_users"),
            Some(&serde_json::json!(["sandbox", "alice"])),
        );
    }

    // -----------------------------------------------------------------
    // Negative-input branches in migrate_v001 (defensive coverage).
    //
    // The function is permissive on shape so a corrupted users.conf
    // does not crash the migration walk — instead unparseable bytes
    // ride through unchanged and the daemon-side schema validator
    // (`validate_users_conf_schema_version` below) surfaces the
    // problem with a typed error. These tests pin each "this is not
    // a shape I understand, so I'll skip the transform" branch the
    // function takes (lines 526-527 for top-level non-object; lines
    // 535-543 for `subnets` not-an-array / entry not-an-object /
    // `allow_users` not-an-array / `allow_users`-absent).
    // -----------------------------------------------------------------

    #[test]
    fn v001_non_object_top_level_rides_through_unchanged() {
        // The transform's first match-or-else returns `value`
        // verbatim when the top level isn't an object — the V001
        // transform has nothing to do with a scalar / array / null
        // root, so the input passes through and the
        // schema-version validator downstream surfaces the shape
        // problem with a clear error.
        let scalar = serde_json::Value::Number(42u32.into());
        assert_eq!(migrate_v001(scalar.clone()), scalar);

        let array = serde_json::json!([1, 2, 3]);
        assert_eq!(migrate_v001(array.clone()), array);

        let null = serde_json::Value::Null;
        assert_eq!(migrate_v001(null.clone()), null);

        let string = serde_json::Value::String("not-a-config".to_string());
        assert_eq!(migrate_v001(string.clone()), string);
    }

    #[test]
    fn v001_subnets_not_array_stamps_version_only() {
        // Top-level object with a `subnets` that is NOT an array:
        // the V001 transform takes the `else { continue }`-style
        // arm (the `Some(Array(_))` pattern fails to match), so the
        // function still stamps `_schema_version` at the top level
        // but does not touch the malformed `subnets` field.
        let input = serde_json::json!({
            "subnets": "this is a string, not an array",
        });
        let output = migrate_v001(input.clone());
        let obj = output.as_object().expect("top stays object");
        assert_eq!(obj.get("_schema_version"), Some(&serde_json::json!(1)));
        assert_eq!(
            obj.get("subnets"),
            Some(&serde_json::json!("this is a string, not an array")),
            "malformed subnets must pass through unchanged"
        );
    }

    #[test]
    fn v001_subnets_absent_stamps_version_only() {
        // Top-level object with NO `subnets` key at all: the
        // transform stamps `_schema_version` and does not synthesise
        // a subnets field (V001 is not a "fill in missing defaults"
        // pass — that's the parent application's job).
        let input = serde_json::json!({
            "comment": "users config without subnets is non-canonical but tolerated"
        });
        let output = migrate_v001(input);
        let obj = output.as_object().expect("top stays object");
        assert_eq!(obj.get("_schema_version"), Some(&serde_json::json!(1)));
        assert!(
            obj.get("subnets").is_none(),
            "V001 must not synthesise a `subnets` field when input has none"
        );
        assert_eq!(
            obj.get("comment"),
            Some(&serde_json::json!(
                "users config without subnets is non-canonical but tolerated"
            )),
            "unrelated keys must ride through unchanged"
        );
    }

    #[test]
    fn v001_subnet_entry_not_object_rides_through() {
        // `subnets[i]` is not an object — the inner
        // `let Some(entry_obj) = entry.as_object_mut() else { continue }`
        // arm fires; the malformed entry is skipped without crashing
        // the loop, and any well-formed siblings are still migrated.
        let input = serde_json::json!({
            "subnets": [
                "junk-not-an-object",
                { "cidr": "10.209.0.0/24", "allow_users": ["alice"] }
            ]
        });
        let output = migrate_v001(input);
        let subnets = output["subnets"].as_array().expect("subnets array");
        assert_eq!(subnets.len(), 2, "loop must visit every entry");
        // The malformed entry rides through unchanged.
        assert_eq!(subnets[0], serde_json::json!("junk-not-an-object"));
        // The well-formed sibling was migrated normally.
        assert_eq!(
            subnets[1].get("allow_users"),
            Some(&serde_json::json!(["sandbox", "alice"])),
            "well-formed sibling entries must still be migrated"
        );
    }

    #[test]
    fn v001_allow_users_not_array_rides_through() {
        // `subnets[i].allow_users` is not an array — the inner
        // `let Some(Array(allow_users)) = entry_obj.get_mut("allow_users") else { continue }`
        // arm fires; the entry is skipped (no `"sandbox"` insertion)
        // but other fields on the same entry survive.
        let input = serde_json::json!({
            "subnets": [
                {
                    "cidr": "10.209.0.0/24",
                    "allow_users": "this should be an array",
                    "comment": "alice prod"
                }
            ]
        });
        let output = migrate_v001(input);
        let entry = output["subnets"][0].as_object().expect("entry is object");
        // allow_users left unchanged (no prepended "sandbox").
        assert_eq!(
            entry.get("allow_users"),
            Some(&serde_json::json!("this should be an array"))
        );
        // The companion fields ride through.
        assert_eq!(entry.get("cidr"), Some(&serde_json::json!("10.209.0.0/24")));
        assert_eq!(entry.get("comment"), Some(&serde_json::json!("alice prod")));
        // Top-level schema version stamped, as always.
        assert_eq!(
            output.get("_schema_version"),
            Some(&serde_json::json!(1))
        );
    }

    #[test]
    fn v001_allow_users_absent_rides_through() {
        // The entry is an object but has no `allow_users` key — the
        // same `else { continue }` arm fires from a different angle
        // (`get_mut("allow_users")` returns `None`). The transform
        // does not synthesise an `allow_users` field; it leaves the
        // entry intact and stamps the top-level version.
        let input = serde_json::json!({
            "subnets": [
                {
                    "cidr": "10.209.0.0/24",
                    "comment": "missing allow_users — defensive shape"
                }
            ]
        });
        let output = migrate_v001(input);
        let entry = output["subnets"][0].as_object().expect("entry is object");
        assert!(
            entry.get("allow_users").is_none(),
            "V001 must not synthesise `allow_users` when absent"
        );
        assert_eq!(entry.get("cidr"), Some(&serde_json::json!("10.209.0.0/24")));
        assert_eq!(
            output.get("_schema_version"),
            Some(&serde_json::json!(1))
        );
    }

    // -----------------------------------------------------------------
    // Daemon-side schema-version validator (Spec 5 § 4.7).
    //
    // Construct a `UsersConfig` directly with the field we want to drive;
    // the validator is a pure function on the loaded struct, so we don't
    // need a tempfile round-trip here. The Cidr in the (empty) subnets
    // vec is irrelevant — the validator only looks at `schema_version`.
    // -----------------------------------------------------------------

    fn cfg_with_version(v: Option<u32>) -> UsersConfig {
        UsersConfig {
            schema_version: v,
            subnets: Vec::new(),
        }
    }

    #[test]
    fn validate_users_conf_schema_version_accepts_supported() {
        let cfg = cfg_with_version(Some(DAEMON_MAX_SUPPORTED_USERS_CONF_SCHEMA));
        validate_users_conf_schema_version(&cfg).expect("max-supported version must validate");

        let cfg_min = cfg_with_version(Some(DAEMON_MIN_SUPPORTED_USERS_CONF_SCHEMA));
        validate_users_conf_schema_version(&cfg_min).expect("min-supported version must validate");
    }

    #[test]
    fn validate_users_conf_schema_version_rejects_too_new() {
        let cfg = cfg_with_version(Some(DAEMON_MAX_SUPPORTED_USERS_CONF_SCHEMA + 2));
        let err = validate_users_conf_schema_version(&cfg)
            .expect_err("ahead-of-binary version must error");
        match &err {
            UsersConfigError::SchemaTooNew {
                file_version,
                daemon_max,
                hint,
            } => {
                assert_eq!(*file_version, DAEMON_MAX_SUPPORTED_USERS_CONF_SCHEMA + 2);
                assert_eq!(*daemon_max, DAEMON_MAX_SUPPORTED_USERS_CONF_SCHEMA);
                assert!(
                    hint.contains("sandbox update"),
                    "hint must point at `sandbox update`; got: {hint}"
                );
            }
            other => panic!("expected SchemaTooNew, got {other:?}"),
        }
        let display = err.to_string();
        assert!(
            display.contains("is newer"),
            "Display must use the load-bearing `is newer` token; got: {display}"
        );
        assert!(
            display.contains("sandbox update"),
            "Display must surface the hint; got: {display}"
        );
    }

    #[test]
    fn validate_users_conf_schema_version_rejects_too_old() {
        // Synthesise an "older" scenario by handing the validator a
        // version below MIN. With MIN==1, the only `< 1` slot is 0 —
        // which is also the "absent" treatment (`treats_absent_as_zero`
        // pins that branch). We still want a dedicated test for the
        // Some(0) shape because in a future era MIN > 1 the two cases
        // diverge.
        let cfg = cfg_with_version(Some(0));
        let err = validate_users_conf_schema_version(&cfg)
            .expect_err("behind-of-binary version must error");
        match &err {
            UsersConfigError::SchemaTooOld {
                file_version,
                daemon_min,
                hint,
            } => {
                assert_eq!(*file_version, 0);
                assert_eq!(*daemon_min, DAEMON_MIN_SUPPORTED_USERS_CONF_SCHEMA);
                assert!(
                    hint.contains("sandbox update"),
                    "hint must point at `sandbox update`; got: {hint}"
                );
            }
            other => panic!("expected SchemaTooOld, got {other:?}"),
        }
        let display = err.to_string();
        assert!(
            display.contains("is older"),
            "Display must use the load-bearing `is older` token; got: {display}"
        );
    }

    #[test]
    fn validate_users_conf_schema_version_treats_absent_as_zero() {
        // `schema_version: None` (file with no `_schema_version` key)
        // is treated as `0` by the validator; with MIN == 1 that
        // surfaces as SchemaTooOld at file_version=0.
        let cfg = cfg_with_version(None);
        let err = validate_users_conf_schema_version(&cfg)
            .expect_err("absent _schema_version must be treated as 0 and rejected");
        match err {
            UsersConfigError::SchemaTooOld { file_version, .. } => {
                assert_eq!(file_version, 0, "absent must map to file_version=0");
            }
            other => panic!("expected SchemaTooOld(file_version=0), got {other:?}"),
        }
    }
}
