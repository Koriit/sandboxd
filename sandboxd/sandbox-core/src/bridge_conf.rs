//! Daemon-side schema-version validator for `/etc/qemu/bridge.conf`.
//!
//! The daemon does **not** otherwise parse this file — it is QEMU's,
//! consumed only by `qemu-bridge-helper`. Spec 5 § 4.7 layers a small
//! schema-mismatch refusal on top so the convergence property of the
//! update flow extends to both managed config files. v1 ships with
//! `bridge.conf` at version `0` (no migration applies to it yet);
//! [`DAEMON_MAX_SUPPORTED_BRIDGE_CONF_SCHEMA`] is `0` and the validator
//! is a no-op until a future migration bumps it.
//!
//! Version detection: first-line comment of the form
//! `# sandbox-schema-version: <int>`. QEMU's bridge-helper parser
//! ignores `#`-prefixed lines (verified in Spec 3 § 9), so the marker
//! is transparent to QEMU. A file with no marker is treated as
//! version `0`.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use thiserror::Error;

/// Default path to the on-disk bridge config. Operators populate this
/// file at install time; the daemon reads only the schema-version
/// header.
pub const DEFAULT_BRIDGE_CONF_PATH: &str = "/etc/qemu/bridge.conf";

/// Environment variable used to override the on-disk path. **Test-only**
/// — production callers must rely on the default. The integration tests
/// for daemon-startup schema-mismatch refusal set this to a tempfile
/// they own (mirrors the `SANDBOX_USERS_CONF` env-var seam in
/// [`crate::users_conf`]).
pub const BRIDGE_CONF_PATH_ENV: &str = "SANDBOX_BRIDGE_CONF";

/// The newest `bridge.conf` schema version this daemon binary can read.
///
/// v1 ships with `bridge.conf` at version `0` — no migration applies to
/// it yet. The constant exists so the validator's range check works
/// today and continues to work after a future migration bumps it.
pub const DAEMON_MAX_SUPPORTED_BRIDGE_CONF_SCHEMA: u32 = 0;

/// The oldest `bridge.conf` schema version this daemon binary can read.
/// Mirrors `MIN`/`MAX` pattern in [`crate::users_conf`]; both equal `0`
/// at v1.
pub const DAEMON_MIN_SUPPORTED_BRIDGE_CONF_SCHEMA: u32 = 0;

/// Errors produced by the bridge.conf header reader and validator.
#[derive(Debug, Error)]
pub enum BridgeConfigError {
    /// I/O error other than `NotFound` (e.g. permission denied). A
    /// missing file is **not** an error here — the daemon does not
    /// require bridge.conf to exist (operators without Lima/QEMU
    /// installed never create it), so the validator treats absence as
    /// "no header" (version 0). Callers that want a stricter shape
    /// should use [`validate_schema_version`]'s `path_exists_required`
    /// counterpart (not yet needed in v1).
    #[error("failed to read bridge.conf at {path}: {source}")]
    ReadFailed {
        path: PathBuf,
        #[source]
        source: io::Error,
    },

    /// The file's first line was not valid UTF-8. We require UTF-8 for
    /// the schema header; the rest of the file is QEMU's and may carry
    /// any byte sequence QEMU accepts.
    #[error("bridge.conf at {path} is not valid UTF-8: {source}")]
    NotUtf8 {
        path: PathBuf,
        #[source]
        source: std::str::Utf8Error,
    },

    /// The file's `# sandbox-schema-version: <int>` header is **newer**
    /// than this daemon binary supports.
    #[error(
        "bridge.conf schema version {file_version} is newer than this binary supports (max: {daemon_max}). {hint}"
    )]
    SchemaTooNew {
        file_version: u32,
        daemon_max: u32,
        hint: String,
    },

    /// The file's `# sandbox-schema-version: <int>` header is **older**
    /// than this daemon binary supports.
    #[error(
        "bridge.conf schema version {file_version} is older than this binary supports (min: {daemon_min}). {hint}"
    )]
    SchemaTooOld {
        file_version: u32,
        daemon_min: u32,
        hint: String,
    },
}

/// Resolve the on-disk path of `bridge.conf`. Honors
/// [`BRIDGE_CONF_PATH_ENV`] for the daemon-startup integration tests; the
/// daemon is not the privilege boundary, so the env-var seam is
/// unconditional (mirrors [`crate::users_conf::users_conf_path`]).
pub fn bridge_conf_path() -> PathBuf {
    if let Ok(p) = std::env::var(BRIDGE_CONF_PATH_ENV) {
        return PathBuf::from(p);
    }
    PathBuf::from(DEFAULT_BRIDGE_CONF_PATH)
}

/// Read the `# sandbox-schema-version: <int>` header from a
/// `bridge.conf` byte slice. Returns `0` when the marker is absent or
/// unparsable. Returns `Err` only for genuine UTF-8 failures on the
/// first line — partial/garbled bytes are not silently mapped to
/// version `0`.
pub fn read_bridge_conf_schema_version(bytes: &[u8]) -> Result<u32, std::str::Utf8Error> {
    // Cap the first-line scan to a sensible bound so a malformed
    // single-giant-line file does not force us to UTF-8 decode the
    // whole blob.
    let head = if bytes.len() > 4096 {
        &bytes[..4096]
    } else {
        bytes
    };
    let head_str = std::str::from_utf8(head)?;
    let first = head_str.lines().next().unwrap_or("");
    const PREFIX: &str = "# sandbox-schema-version:";
    Ok(first
        .strip_prefix(PREFIX)
        .map(str::trim)
        .and_then(|s| s.parse::<u32>().ok())
        .unwrap_or(0))
}

/// Validate the schema version of the on-disk `bridge.conf`.
///
/// Reads [`bridge_conf_path`], extracts the header (treating absence as
/// `0`), and refuses if the version is outside
/// `[DAEMON_MIN_SUPPORTED_BRIDGE_CONF_SCHEMA, DAEMON_MAX_SUPPORTED_BRIDGE_CONF_SCHEMA]`.
///
/// A **missing** `bridge.conf` is **not** an error: the daemon does not
/// require the file to exist (operators without QEMU/Lima never create
/// it). This matches Spec 5 § 4.7's text "the daemon reads bridge.conf
/// for this check only; it does not otherwise parse the file."
pub fn validate_schema_version() -> Result<(), BridgeConfigError> {
    let path = bridge_conf_path();
    validate_schema_version_at(&path)
}

/// Path-explicit variant of [`validate_schema_version`] used by the
/// integration tests so they can drive a tempfile path without the env
/// var.
pub fn validate_schema_version_at(path: &Path) -> Result<(), BridgeConfigError> {
    let bytes = match fs::read(path) {
        Ok(b) => b,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(e) => {
            return Err(BridgeConfigError::ReadFailed {
                path: path.to_path_buf(),
                source: e,
            });
        }
    };
    let v =
        read_bridge_conf_schema_version(&bytes).map_err(|source| BridgeConfigError::NotUtf8 {
            path: path.to_path_buf(),
            source,
        })?;
    if v > DAEMON_MAX_SUPPORTED_BRIDGE_CONF_SCHEMA {
        return Err(BridgeConfigError::SchemaTooNew {
            file_version: v,
            daemon_max: DAEMON_MAX_SUPPORTED_BRIDGE_CONF_SCHEMA,
            hint: "Run `sandbox update` to fix, or restore from backup at \
                   /var/lib/sandbox/backups/<latest>/bridge.conf.bak."
                .to_string(),
        });
    }
    // The MIN/MAX symmetric check below is dead at v1 (MIN==0, u32 is
    // non-negative) but kept verbatim so that when a future migration
    // raises `DAEMON_MIN_SUPPORTED_BRIDGE_CONF_SCHEMA` past zero the
    // refusal arm fires without a code change. Clippy
    // (absurd_extreme_comparisons) flags the always-false `<` against a
    // u32 zero floor; the allow is scoped to this single comparison.
    #[allow(clippy::absurd_extreme_comparisons)]
    let too_old = v < DAEMON_MIN_SUPPORTED_BRIDGE_CONF_SCHEMA;
    if too_old {
        return Err(BridgeConfigError::SchemaTooOld {
            file_version: v,
            daemon_min: DAEMON_MIN_SUPPORTED_BRIDGE_CONF_SCHEMA,
            hint: "Run `sandbox update` to bring the file up to date.".to_string(),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_header_returns_zero_when_absent() {
        assert_eq!(read_bridge_conf_schema_version(b"allow sb-*\n").unwrap(), 0);
        assert_eq!(read_bridge_conf_schema_version(b"").unwrap(), 0);
    }

    #[test]
    fn read_header_returns_value_when_present() {
        let blob = b"# sandbox-schema-version: 2\nallow sb-*\n";
        assert_eq!(read_bridge_conf_schema_version(blob).unwrap(), 2);
    }

    #[test]
    fn read_header_returns_zero_when_malformed() {
        // Non-numeric tail → treated as absent, value 0.
        let blob = b"# sandbox-schema-version: abc\nallow sb-*\n";
        assert_eq!(read_bridge_conf_schema_version(blob).unwrap(), 0);
    }

    #[test]
    fn validate_accepts_missing_file() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let path = tmp.path().join("does-not-exist.conf");
        validate_schema_version_at(&path).expect("missing bridge.conf must validate as no-op");
    }

    #[test]
    fn validate_accepts_no_header_when_max_is_zero() {
        // With MAX==0, a file with no header (treated as version 0)
        // sits in the supported range and validates clean.
        let tmp = tempfile::tempdir().expect("tempdir");
        let path = tmp.path().join("bridge.conf");
        std::fs::write(&path, b"allow sb-*\n").expect("write");
        validate_schema_version_at(&path).expect("no header (v0) must validate at MAX=0");
    }

    #[test]
    fn validate_rejects_header_too_new() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let path = tmp.path().join("bridge.conf");
        std::fs::write(&path, b"# sandbox-schema-version: 99\nallow sb-*\n").expect("write");
        let err = validate_schema_version_at(&path).expect_err("v99 must error at MAX=0");
        match err {
            BridgeConfigError::SchemaTooNew {
                file_version,
                daemon_max,
                ..
            } => {
                assert_eq!(file_version, 99);
                assert_eq!(daemon_max, DAEMON_MAX_SUPPORTED_BRIDGE_CONF_SCHEMA);
            }
            other => panic!("expected SchemaTooNew, got {other:?}"),
        }
    }
}
