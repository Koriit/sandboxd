//! V001 adapter: applies the documented contract
//! `/etc/sandboxd/users.conf` via the framework's [`ConfigMigration`]
//! trait.
//!
//! The pure transform (which adds `"sandbox"` to every subnet's
//! `allow_users` and stamps `_schema_version: 1`) lives in
//! `sandbox_core::users_conf::migrate_v001` together with the
//! `UsersConfig` schema struct —.1 deliberately keeps the
//! content-level invariant next to the schema definition that tests it.
//! This adapter wraps that transform with serde-driven byte ↔ value
//! round-trip plumbing so the framework's apply loop can drive it.

use super::{ConfigMigration, MigrationError, TargetFile};

/// The V001 migration. Stateless — the trait methods are all pure
/// functions that consult compile-time constants.
pub struct Migration;

impl ConfigMigration for Migration {
    fn id(&self) -> u32 {
        1
    }
    fn name(&self) -> &'static str {
        "add_sandbox_to_allow_users"
    }
    fn target_file(&self) -> TargetFile {
        TargetFile::UsersConf
    }
    fn from_version(&self) -> u32 {
        0
    }
    fn to_version(&self) -> u32 {
        1
    }
    fn apply(&self, file_contents: &[u8]) -> Result<Vec<u8>, MigrationError> {
        let value: serde_json::Value = serde_json::from_slice(file_contents)
            .map_err(|e| MigrationError::Parse(format!("users.conf is not valid JSON: {e}")))?;
        let transformed = sandbox_core::users_conf::migrate_v001(value);
        // Pretty-print so operator diffs against `git`-style backups
        // stay readable. The two-space indent matches the shape
        // `install.sh` writes at first install (the documented contract.19).
        serde_json::to_vec_pretty(&transformed)
            .map(|mut v| {
                // serde_json::to_vec_pretty does not emit a trailing
                // newline; canonical text files end in one.
                if !v.ends_with(b"\n") {
                    v.push(b'\n');
                }
                v
            })
            .map_err(|e| MigrationError::Transform(format!("serialize users.conf: {e}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: parse a string of JSON literal into `serde_json::Value`
    /// for structural comparison (key order independent).
    fn json(raw: &str) -> serde_json::Value {
        serde_json::from_str(raw).expect("test json literal must parse")
    }

    /// Table-driven coverage for the documented contract inputs A/B/C plus an
    /// operator-customized row that exercises the "preserves unknown
    /// keys" contract from.6. Bytes-in / bytes-out path,
    /// because the framework calls `apply(&[u8]) -> Vec<u8>`.
    #[test]
    fn migration_v001_round_trip() {
        struct Row {
            name: &'static str,
            input: &'static str,
            expected: &'static str,
        }

        let rows = [
            Row {
                name: "empty subnets list",
                input: r#"{ "subnets": [] }"#,
                expected: r#"{ "_schema_version": 1, "subnets": [] }"#,
            },
            Row {
                name: "the documented contract Input A — single user pool",
                input: r#"{
                    "subnets": [
                        { "cidr": "10.209.0.0/24", "allow_users": ["alice"] }
                    ]
                }"#,
                expected: r#"{
                    "_schema_version": 1,
                    "subnets": [
                        { "cidr": "10.209.0.0/24", "allow_users": ["sandbox", "alice"] }
                    ]
                }"#,
            },
            Row {
                name: "the documented contract Input B — multi-user, multi-pool",
                input: r#"{
                    "subnets": [
                        { "cidr": "10.209.0.0/24", "allow_users": ["alice"], "comment": "alice prod" },
                        { "cidr": "10.210.0.0/24", "allow_users": ["bob", "carol"] }
                    ]
                }"#,
                expected: r#"{
                    "_schema_version": 1,
                    "subnets": [
                        { "cidr": "10.209.0.0/24", "allow_users": ["sandbox", "alice"], "comment": "alice prod" },
                        { "cidr": "10.210.0.0/24", "allow_users": ["sandbox", "bob", "carol"] }
                    ]
                }"#,
            },
            Row {
                name: "the documented contract Input C — sandbox already present",
                input: r#"{
                    "subnets": [
                        { "cidr": "10.209.0.0/24", "allow_users": ["alice", "sandbox"] }
                    ]
                }"#,
                expected: r#"{
                    "_schema_version": 1,
                    "subnets": [
                        { "cidr": "10.209.0.0/24", "allow_users": ["alice", "sandbox"] }
                    ]
                }"#,
            },
            Row {
                // Operator-added top-level keys must
                // survive the round-trip. V001's pure transform uses
                // `serde_json::Value` precisely so unknown keys ride
                // through; the byte-level adapter must not drop them.
                name: "operator-customized — unknown top-level key preserved",
                input: r#"{
                    "_operator_note": "staging-env",
                    "subnets": [
                        { "cidr": "10.209.0.0/24", "allow_users": ["alice"] }
                    ]
                }"#,
                expected: r#"{
                    "_operator_note": "staging-env",
                    "_schema_version": 1,
                    "subnets": [
                        { "cidr": "10.209.0.0/24", "allow_users": ["sandbox", "alice"] }
                    ]
                }"#,
            },
        ];

        for row in rows {
            let m = Migration;
            let out_bytes = m
                .apply(row.input.as_bytes())
                .unwrap_or_else(|e| panic!("[{}] apply failed: {e:?}", row.name));
            let out: serde_json::Value = serde_json::from_slice(&out_bytes)
                .unwrap_or_else(|e| panic!("[{}] output not JSON: {e}", row.name));
            let expected = json(row.expected);
            assert_eq!(
                out, expected,
                "[{}] V001 output mismatch.\n  got:      {out}\n  expected: {expected}",
                row.name,
            );
        }
    }

    /// Idempotency at the adapter level. A file at `_schema_version: 1`
    /// passed through `apply` produces JSON equal (structurally) to the
    /// input — V001's pure transform short-circuits when the version
    /// stamp is already present.
    ///
    /// Note: this is the **adapter** idempotency, distinct from the
    /// framework's selection-rule idempotency (the apply loop never
    /// invokes `apply` on a file at the target version in the first
    /// place). Both shoulds hold; this test pins
    /// the inner property.
    #[test]
    fn migration_v001_idempotent_when_already_applied() {
        let already_at_v1 = r#"{
            "_schema_version": 1,
            "subnets": [
                { "cidr": "10.209.0.0/24", "allow_users": ["sandbox", "alice"] }
            ]
        }"#;

        let m = Migration;
        let out_bytes = m
            .apply(already_at_v1.as_bytes())
            .expect("apply on already-v1 must succeed");
        let out: serde_json::Value = serde_json::from_slice(&out_bytes).expect("valid JSON out");
        let input_val = json(already_at_v1);
        assert_eq!(
            out, input_val,
            "V001 must be a no-op on a file already at _schema_version 1"
        );
    }
}
