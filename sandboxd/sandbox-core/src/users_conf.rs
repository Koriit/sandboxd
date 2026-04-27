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
//! Production callers use [`load_users_config`], which reads the path
//! returned by [`users_conf_path`]. The default path is
//! `/etc/sandboxd/users.conf`. The `SANDBOX_USERS_CONF` environment
//! variable overrides the default — this is a **test-only** seam used by
//! unit tests and route-helper integration tests; operators must never
//! set it in production.
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
    fn parse(value: &str) -> Result<Self, &'static str> {
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
// Path resolution and loading
// ---------------------------------------------------------------------------

/// Resolve the on-disk path of `users.conf`.
///
/// Honors `SANDBOX_USERS_CONF` as a **test-only** override; in
/// production this returns [`DEFAULT_USERS_CONF_PATH`].
pub fn users_conf_path() -> PathBuf {
    if let Ok(p) = std::env::var(USERS_CONF_PATH_ENV) {
        return PathBuf::from(p);
    }
    PathBuf::from(DEFAULT_USERS_CONF_PATH)
}

/// Load and validate the users config from the resolved path
/// ([`users_conf_path`]).
pub fn load_users_config() -> Result<UsersConfig, UsersConfigError> {
    load_users_config_from(&users_conf_path())
}

/// Load and validate the users config from `path`.
///
/// Test seam — production callers should use [`load_users_config`].
pub fn load_users_config_from(path: &Path) -> Result<UsersConfig, UsersConfigError> {
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
}
