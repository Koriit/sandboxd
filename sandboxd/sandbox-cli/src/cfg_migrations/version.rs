//! Schema-version detection per managed file..5.
//!
//! Two files are versioned today, each with its own marker:
//!
//! - `users.conf` (JSON): top-level `_schema_version: <int>` key. Read
//!   with `serde_json::Value` and look up the key. A file with no
//!   `_schema_version` is treated as version `0` and V001 applies.
//!
//! - `bridge.conf` (text): first-line comment
//!   `# sandbox-schema-version: <int>`. QEMU's bridge-helper parser
//!   ignores `#`-prefixed lines, so the marker is transparent to QEMU.
//!   A file with no marker is treated as version `0`.
//!
//! If the version marker is absent (pre-V001 file from an older
//! install), the file is at version `0` and the framework applies
//! V001+ in order.

use super::{MigrationError, TargetFile};

/// Read the `_schema_version` (or header marker, for `bridge.conf`) from
/// a managed file's byte contents.
///
/// Returns `0` when the marker is absent. Refuses with
/// [`MigrationError::Parse`] when the file is structurally malformed
/// (e.g. `users.conf` that is not valid JSON, or a `bridge.conf` whose
/// first line is not valid UTF-8). A corrupted file is not silently
/// migrated.
pub fn read_schema_version(bytes: &[u8], file: TargetFile) -> Result<u32, MigrationError> {
    match file {
        TargetFile::UsersConf => {
            let v: serde_json::Value = serde_json::from_slice(bytes)
                .map_err(|e| MigrationError::Parse(format!("users.conf is not valid JSON: {e}")))?;
            Ok(v.get("_schema_version")
                .and_then(|v| v.as_u64())
                .map(|n| n as u32)
                .unwrap_or(0))
        }
        TargetFile::BridgeConf => {
            // Cap the first-line scan to keep a malformed
            // single-giant-line file from forcing UTF-8 decode of the
            // whole blob. 4 KiB is plenty for "# sandbox-schema-version:
            // <int>" plus the standard QEMU bridge-rule prefix lines.
            let head = if bytes.len() > 4096 {
                &bytes[..4096]
            } else {
                bytes
            };
            let head_str = std::str::from_utf8(head)
                .map_err(|e| MigrationError::Parse(format!("bridge.conf not utf-8: {e}")))?;
            let first = head_str.lines().next().unwrap_or("");
            const PREFIX: &str = "# sandbox-schema-version:";
            Ok(first
                .strip_prefix(PREFIX)
                .map(str::trim)
                .and_then(|s| s.parse::<u32>().ok())
                .unwrap_or(0))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------
    // users.conf — JSON `_schema_version` field.
    // -----------------------------------------------------------------

    #[test]
    fn read_schema_version_users_conf_default_zero() {
        // A users.conf without `_schema_version` (pre-V001 shape) reads
        // as version 0; V001 applies.
        let bytes = br#"{"subnets": [{"cidr": "10.0.0.0/24", "allow_users": ["alice"]}]}"#;
        let v =
            read_schema_version(bytes, TargetFile::UsersConf).expect("absent key must map to 0");
        assert_eq!(v, 0);
    }

    #[test]
    fn read_schema_version_users_conf_reads_present() {
        let bytes = br#"{"_schema_version": 3, "subnets": []}"#;
        let v = read_schema_version(bytes, TargetFile::UsersConf).expect("v3 parses");
        assert_eq!(v, 3);

        let bytes_v1 = br#"{"_schema_version": 1, "subnets": []}"#;
        assert_eq!(
            read_schema_version(bytes_v1, TargetFile::UsersConf).expect("v1 parses"),
            1
        );
    }

    #[test]
    fn read_schema_version_users_conf_refuses_invalid_json() {
        let bytes = b"not json at all";
        let err =
            read_schema_version(bytes, TargetFile::UsersConf).expect_err("malformed must error");
        match err {
            MigrationError::Parse(msg) => assert!(
                msg.contains("not valid JSON"),
                "Parse message must name the problem; got: {msg}"
            ),
            other => panic!("expected Parse, got {other:?}"),
        }
    }

    // -----------------------------------------------------------------
    // bridge.conf — first-line `# sandbox-schema-version:` header.
    // -----------------------------------------------------------------

    #[test]
    fn read_schema_version_bridge_conf_default_zero() {
        // A bridge.conf without the header (typical of pre-migration
        // installs, or operator-only files) reads as version 0.
        let bytes = b"allow sb-*\nallow virbr0\n";
        let v = read_schema_version(bytes, TargetFile::BridgeConf).expect("no header maps to 0");
        assert_eq!(v, 0);
    }

    #[test]
    fn read_schema_version_bridge_conf_reads_present() {
        let bytes = b"# sandbox-schema-version: 2\nallow sb-*\n";
        let v = read_schema_version(bytes, TargetFile::BridgeConf).expect("v2 header parses");
        assert_eq!(v, 2);
    }

    #[test]
    fn read_schema_version_bridge_conf_refuses_invalid_first_line_utf8() {
        // Non-UTF-8 bytes at the top of the file must surface as
        // MigrationError::Parse so the framework does not silently
        // migrate a garbled file.
        let bytes = b"\xff\xfe# sandbox-schema-version: 1\n";
        let err =
            read_schema_version(bytes, TargetFile::BridgeConf).expect_err("invalid utf-8 errors");
        match err {
            MigrationError::Parse(msg) => assert!(
                msg.contains("not utf-8"),
                "Parse message must name utf-8 issue; got: {msg}"
            ),
            other => panic!("expected Parse, got {other:?}"),
        }
    }
}
