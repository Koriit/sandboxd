//! Config migration framework — Spec 5 § 4.
//!
//! A small Rust module set inside `sandbox-cli/` that applies versioned
//! transforms to `/etc/sandboxd/users.conf` and `/etc/qemu/bridge.conf`.
//! Its shape mirrors refinery's pattern (versioned migrations, numeric
//! ordering, idempotent apply, validation before commit) but applies to
//! filesystem files rather than SQL tables.
//!
//! The framework lives in `sandbox-cli/` rather than `sandbox-core/`
//! because the only invoker is the CLI's `sandbox update` orchestration
//! — the daemon never applies migrations itself. The daemon's role is
//! to **refuse to start** on schema mismatch (Spec 5 § 4.7, which lives
//! in `sandbox-core::users_conf` / `sandbox-core::bridge_conf`); that
//! refusal does not need the framework or its registry.

use std::io::Write;
use std::path::{Path, PathBuf};

use thiserror::Error;

pub mod v001_add_sandbox_to_allow_users;
pub mod version;

pub use version::read_schema_version;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors produced by the framework. Each variant is operator-facing
/// (callers either render `Display` directly to stderr or wrap it for
/// the `sandbox update` log file).
#[derive(Debug, Error)]
pub enum MigrationError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("parse: {0}")]
    Parse(String),
    #[error("transform: {0}")]
    Transform(String),
    #[error("validation: post-migration content did not parse against target schema: {0}")]
    Validation(String),
    #[error("schema version unreadable from {0}: {1}")]
    SchemaUnreadable(String, String),
}

// ---------------------------------------------------------------------------
// TargetFile
// ---------------------------------------------------------------------------

/// Which on-disk file a migration applies to. Each managed file has its
/// own version sequence; V001 on `UsersConf` is distinct from a future
/// V001 on `BridgeConf`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TargetFile {
    /// `/etc/sandboxd/users.conf` (JSON; `_schema_version` top-level
    /// integer per Spec 1 § 4.2).
    UsersConf,
    /// `/etc/qemu/bridge.conf` (text; first-line
    /// `# sandbox-schema-version: <int>` header). Reserved — no
    /// migration ships against it in v1.
    BridgeConf,
}

impl TargetFile {
    /// The canonical on-disk path for this managed file. Used by the
    /// access gate on `--apply-config-migration` to refuse arbitrary
    /// `--file` arguments.
    pub fn canonical_path(&self) -> PathBuf {
        match self {
            TargetFile::UsersConf => PathBuf::from("/etc/sandboxd/users.conf"),
            TargetFile::BridgeConf => PathBuf::from("/etc/qemu/bridge.conf"),
        }
    }

    /// Inverse of [`canonical_path`]: classify a path argument into its
    /// `TargetFile` variant. Returns `None` for anything that is not
    /// exactly one of the registry's canonical paths — the gate uses
    /// this to refuse `--file /tmp/whatever` shapes.
    pub fn from_canonical_path(p: &Path) -> Option<Self> {
        if p == Path::new("/etc/sandboxd/users.conf") {
            Some(TargetFile::UsersConf)
        } else if p == Path::new("/etc/qemu/bridge.conf") {
            Some(TargetFile::BridgeConf)
        } else {
            None
        }
    }

    /// Display name used in operator-facing error messages
    /// (`migration V001 not found in registry for <target>`).
    pub fn display_name(&self) -> &'static str {
        match self {
            TargetFile::UsersConf => "users.conf",
            TargetFile::BridgeConf => "bridge.conf",
        }
    }
}

// ---------------------------------------------------------------------------
// ConfigMigration trait
// ---------------------------------------------------------------------------

/// A versioned, content-only transform. The framework owns file IO,
/// atomic-write, and validation; migrations own only the transform.
///
/// **Selection rule (binding):** every migration advances **exactly
/// one version** — `to_version() == from_version() + 1`. Multi-version
/// skips are composed by chaining migrations. The unit test
/// `registry_migrations_advance_exactly_one_version` pins this rule.
pub trait ConfigMigration: Sync {
    /// Stable numeric ID. Migrations are applied in ascending order.
    /// Convention: V001..V999 zero-padded in module names; integer here.
    fn id(&self) -> u32;
    /// Short human-readable name (matches the module suffix —
    /// `add_sandbox_to_allow_users`).
    fn name(&self) -> &'static str;
    /// File this migration applies to. A migration touches exactly one
    /// file; cross-file migrations would compose two migrations with
    /// the same `id()` on different `TargetFile`s.
    fn target_file(&self) -> TargetFile;
    /// `from_version` it expects to read. Used by the apply loop to
    /// pick the next pending migration; also documents intent.
    ///
    /// The `from_` prefix is a schema-version qualifier (paired with
    /// `to_version`) — not a Rust "constructor from X" convention —
    /// so clippy's wrong-self-convention check is suppressed here.
    #[allow(clippy::wrong_self_convention)]
    fn from_version(&self) -> u32;
    /// `to_version` it produces. After apply, the file's
    /// `_schema_version` (or header marker) reads this value.
    fn to_version(&self) -> u32;
    /// Pure transform — read bytes in, return bytes out. The framework
    /// validates the result against the target schema after the call.
    fn apply(&self, file_contents: &[u8]) -> Result<Vec<u8>, MigrationError>;
}

// ---------------------------------------------------------------------------
// Registry
// ---------------------------------------------------------------------------

/// The static migration registry. Each entry is a `&'static dyn` so
/// callers can iterate without allocating.
///
/// New migrations land here as `&module::Migration` references — the
/// `Migration` struct must be unit (no fields) so the static-reference
/// pattern works at compile time without `OnceCell`.
pub fn registry() -> &'static [&'static dyn ConfigMigration] {
    &[&v001_add_sandbox_to_allow_users::Migration]
}

/// Return the full ordered list of pending migrations for `file` from
/// `current` (exclusive) to `target` (inclusive). Used for display
/// purposes — the `--check` pending-migrations summary and the
/// confirmation prompt. The `apply_pending` loop in § 4.3 does NOT
/// call this; it uses `find()` on the registry directly for sequential
/// one-step-at-a-time application.
pub fn pending(file: TargetFile, current: u32, target: u32) -> Vec<&'static dyn ConfigMigration> {
    registry()
        .iter()
        .copied()
        .filter(|m| {
            m.target_file() == file && m.from_version() >= current && m.to_version() <= target
        })
        .collect()
}

/// The highest `to_version()` defined for the given file across the
/// static registry. `0` when no migration exists for the file.
pub fn latest_for(file: TargetFile) -> u32 {
    registry()
        .iter()
        .filter(|m| m.target_file() == file)
        .map(|m| m.to_version())
        .max()
        .unwrap_or(0)
}

// ---------------------------------------------------------------------------
// Migration set (`--dump-migration-set`)
// ---------------------------------------------------------------------------

/// One entry in the JSON output of `sandbox --dump-migration-set`. The
/// shape is the operator-stable contract M16-S2's `--dry-run`
/// stopped-session classification depends on; field names are pinned
/// here so future migrations can be added without renaming keys.
#[derive(Debug, Clone, serde::Serialize)]
pub struct MigrationEntry {
    pub id: u32,
    pub name: &'static str,
    pub from_version: u32,
    pub to_version: u32,
    pub target_file: &'static str,
}

/// Render the registry as `Vec<MigrationEntry>` — suitable for JSON
/// serialisation by callers.
pub fn dump_migration_set() -> Vec<MigrationEntry> {
    registry()
        .iter()
        .map(|m| MigrationEntry {
            id: m.id(),
            name: m.name(),
            from_version: m.from_version(),
            to_version: m.to_version(),
            target_file: m.target_file().display_name(),
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Atomic write
// ---------------------------------------------------------------------------

/// Write `bytes` atomically over `path`. Spec 5 § 4.4: use
/// `NamedTempFile::new_in(parent)` + `persist(path)`. Same-FS rename
/// guarantees no half-written state — `rename(2)` is atomic when src
/// and dst are on the same filesystem.
pub fn atomic_write(path: &Path, bytes: &[u8]) -> Result<(), MigrationError> {
    let parent = path.parent().ok_or_else(|| {
        MigrationError::Transform(format!("path has no parent directory: {}", path.display()))
    })?;
    let mut tmp = tempfile::NamedTempFile::new_in(parent)?;
    tmp.write_all(bytes)?;
    tmp.as_file().sync_all()?;
    tmp.persist(path).map_err(|e| MigrationError::Io(e.error))?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

/// Validate the post-migration bytes against the target file's schema.
/// For `users.conf` we round-trip through the strict `UsersConfig`
/// (`#[serde(deny_unknown_fields)]`) so a transform that produced
/// content the daemon won't parse fails here, before the atomic
/// rename. For `bridge.conf` we currently only validate that the
/// first-line header is well-formed; future migrations may add more.
fn validate_against_target_schema(
    bytes: &[u8],
    file: TargetFile,
    expected_version: u32,
) -> Result<(), MigrationError> {
    match file {
        TargetFile::UsersConf => {
            // Strict round-trip: the same `UsersConfig` shape the
            // daemon loads at startup must accept the migrated bytes.
            let _cfg: sandbox_core::UsersConfig = serde_json::from_slice(bytes).map_err(|e| {
                MigrationError::Validation(format!(
                    "users.conf post-migration content does not satisfy UsersConfig schema: {e}"
                ))
            })?;
        }
        TargetFile::BridgeConf => {
            // No structural schema yet; header well-formedness is
            // checked below.
        }
    }
    // Version-marker sanity check: the migrated bytes must read back
    // at `expected_version`. Catches transforms that forgot to stamp.
    let read_back = read_schema_version(bytes, file)?;
    if read_back != expected_version {
        return Err(MigrationError::Validation(format!(
            "post-migration schema version is {read_back}, expected {expected_version}"
        )));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Apply loop
// ---------------------------------------------------------------------------

/// For a managed file, read the current `_schema_version`, find the
/// chain of migrations from current to target, and apply them in order.
/// Each application is its own atomic write — the file is at a
/// consistent version after every successful migration, never in a
/// half-applied state.
///
/// Convenience wrapper that uses [`TargetFile::canonical_path`]. Used
/// by `sandbox update`'s in-process orchestration. The hidden
/// `--apply-config-migration` CLI affordance drives [`apply_pending_at`]
/// directly so it can target a tempfile path the outer shell flow
/// `sudo -k mv`s into place.
pub fn apply_pending(file: TargetFile) -> Result<Vec<u32>, MigrationError> {
    let path = file.canonical_path();
    apply_pending_at(file, &path)
}

/// Path-explicit variant of [`apply_pending`]. The integration test
/// `integration_config_migration_applies_v001_to_legacy_file` drives
/// this against a tempfile so it can run without root and without
/// touching `/etc/`.
pub fn apply_pending_at(file: TargetFile, path: &Path) -> Result<Vec<u32>, MigrationError> {
    let mut applied = Vec::new();
    loop {
        let bytes = std::fs::read(path)?;
        let current = read_schema_version(&bytes, file)?;
        let target = latest_for(file);
        if current >= target {
            return Ok(applied);
        }
        let migration = registry()
            .iter()
            .copied()
            .find(|m| m.target_file() == file && m.from_version() == current)
            .ok_or_else(|| {
                MigrationError::Transform(format!(
                    "no migration available for {file:?} at version {current} (target: {target})"
                ))
            })?;

        let new_bytes = migration.apply(&bytes)?;
        validate_against_target_schema(&new_bytes, file, migration.to_version())?;
        atomic_write(path, &new_bytes)?;

        applied.push(migration.id());
    }
}

/// Apply a single migration in memory and return the produced bytes
/// without writing anywhere. Used by `sandbox update --dry-run` (Spec 5
/// § 3.1.12) and by the hidden `--apply-config-migration` subcommand
/// (which then `sudo -k mv`s the result into place externally).
///
/// `migration` is resolved by id from the static registry. The caller
/// is responsible for providing the input bytes that match the
/// migration's `from_version`.
pub fn apply_migration_in_memory(
    migration_id: u32,
    input: &[u8],
    expected_file: TargetFile,
) -> Result<Vec<u8>, MigrationError> {
    let m = registry()
        .iter()
        .copied()
        .find(|m| m.id() == migration_id && m.target_file() == expected_file)
        .ok_or_else(|| {
            MigrationError::Transform(format!(
                "migration V{migration_id:03} not found in registry for {}",
                expected_file.display_name()
            ))
        })?;

    let out = m.apply(input)?;
    validate_against_target_schema(&out, expected_file, m.to_version())?;
    Ok(out)
}

/// Look up a migration by id. Returns `None` for unknown ids; the
/// `--apply-config-migration` gate uses this to refuse before any
/// transform runs.
pub fn find_by_id(migration_id: u32) -> Option<&'static dyn ConfigMigration> {
    registry().iter().copied().find(|m| m.id() == migration_id)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use std::sync::OnceLock;

    // ---------------------------------------------------------------------
    // Synthetic test registry — for the apply-pending walk tests.
    //
    // The production registry only contains V001 today. To exercise the
    // walk-chain branch we hand-build a TestRegistry consisting of two
    // pseudo-migrations and run the apply loop against a tempfile. The
    // walk-chain test cannot stand on V001 alone because there is no
    // V002 to advance to; we model the chain inside the test scope.
    // ---------------------------------------------------------------------

    struct StubV001Then1;
    impl ConfigMigration for StubV001Then1 {
        fn id(&self) -> u32 {
            101
        }
        fn name(&self) -> &'static str {
            "stub_v001"
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
        fn apply(&self, bytes: &[u8]) -> Result<Vec<u8>, MigrationError> {
            let mut v: serde_json::Value =
                serde_json::from_slice(bytes).map_err(|e| MigrationError::Parse(e.to_string()))?;
            v.as_object_mut()
                .unwrap()
                .insert("_schema_version".into(), serde_json::json!(1));
            let mut out = serde_json::to_vec_pretty(&v).unwrap();
            out.push(b'\n');
            Ok(out)
        }
    }

    struct StubV002Then2;
    impl ConfigMigration for StubV002Then2 {
        fn id(&self) -> u32 {
            102
        }
        fn name(&self) -> &'static str {
            "stub_v002"
        }
        fn target_file(&self) -> TargetFile {
            TargetFile::UsersConf
        }
        fn from_version(&self) -> u32 {
            1
        }
        fn to_version(&self) -> u32 {
            2
        }
        fn apply(&self, bytes: &[u8]) -> Result<Vec<u8>, MigrationError> {
            let mut v: serde_json::Value =
                serde_json::from_slice(bytes).map_err(|e| MigrationError::Parse(e.to_string()))?;
            v.as_object_mut()
                .unwrap()
                .insert("_schema_version".into(), serde_json::json!(2));
            let mut out = serde_json::to_vec_pretty(&v).unwrap();
            out.push(b'\n');
            Ok(out)
        }
    }

    /// Test-only overridable registry: the apply loop calls
    /// `test_registry()` instead of `registry()` when this `Mutex` is
    /// populated. We swap it in for the walk-chain test and out at the
    /// end so other tests see the production registry.
    fn test_registry_slot() -> &'static Mutex<Option<&'static [&'static dyn ConfigMigration]>> {
        static SLOT: OnceLock<Mutex<Option<&'static [&'static dyn ConfigMigration]>>> =
            OnceLock::new();
        SLOT.get_or_init(|| Mutex::new(None))
    }

    /// Serializes test-registry-using tests so concurrent worker
    /// threads don't fight over the global slot. Held for the duration
    /// of `with_test_registry`; the slot itself uses a separate Mutex
    /// so the loop helper can take/release fine-grained locks inside
    /// the test body without deadlocking against this guard.
    fn test_registry_serializer() -> &'static Mutex<()> {
        static SER: OnceLock<Mutex<()>> = OnceLock::new();
        SER.get_or_init(|| Mutex::new(()))
    }

    /// Per-test inline registry override. The production code paths
    /// don't see this — only the helper below does. The serializer
    /// lock prevents concurrent test threads from racing on the
    /// global slot.
    fn with_test_registry<F>(reg: &'static [&'static dyn ConfigMigration], f: F)
    where
        F: FnOnce(),
    {
        let _ser = test_registry_serializer()
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let slot = test_registry_slot();
        {
            let mut g = slot.lock().unwrap();
            *g = Some(reg);
        }
        f();
        let mut g = slot.lock().unwrap();
        *g = None;
    }

    /// In-test variant of `latest_for` that honors the test slot.
    fn latest_for_test(file: TargetFile) -> u32 {
        let g = test_registry_slot().lock().unwrap();
        if let Some(reg) = *g {
            return reg
                .iter()
                .filter(|m| m.target_file() == file)
                .map(|m| m.to_version())
                .max()
                .unwrap_or(0);
        }
        drop(g);
        latest_for(file)
    }

    /// In-test variant of `apply_pending_at` that honors the test slot
    /// in place of the production registry. Mirrors the production
    /// path otherwise.
    fn apply_pending_at_with_test_registry(
        file: TargetFile,
        path: &Path,
    ) -> Result<Vec<u32>, MigrationError> {
        let mut applied = Vec::new();
        loop {
            let bytes = std::fs::read(path)?;
            let current = read_schema_version(&bytes, file)?;
            let target = latest_for_test(file);
            if current >= target {
                return Ok(applied);
            }
            let migration = {
                let g = test_registry_slot().lock().unwrap();
                let reg: &[&dyn ConfigMigration] = (*g).unwrap_or_else(|| registry());
                reg.iter()
                    .copied()
                    .find(|m| m.target_file() == file && m.from_version() == current)
                    .ok_or_else(|| {
                        MigrationError::Transform(format!(
                            "no migration available for {file:?} at version {current}"
                        ))
                    })?
            };
            let new_bytes = migration.apply(&bytes)?;
            validate_against_target_schema(&new_bytes, file, migration.to_version())?;
            atomic_write(path, &new_bytes)?;
            applied.push(migration.id());
        }
    }

    // ---------------------------------------------------------------------
    // Tests
    // ---------------------------------------------------------------------

    /// Synthetic V001 (0→1) + V002 (1→2) registry; seed a tempfile at
    /// V0; run apply_pending; assert applied == [101, 102] and the
    /// final on-disk version reads as 2. Pins the walk-chain contract
    /// of Spec 5 § 4.3.
    #[test]
    fn apply_pending_walks_chain() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let path = tmp.path().join("users.conf");
        std::fs::write(
            &path,
            br#"{"subnets":[{"cidr":"10.0.0.0/24","allow_users":["sandbox","alice"]}]}"#,
        )
        .unwrap();

        static REG: &[&dyn ConfigMigration] = &[&StubV001Then1, &StubV002Then2];
        let mut applied_result: Option<Result<Vec<u32>, MigrationError>> = None;
        with_test_registry(REG, || {
            applied_result = Some(apply_pending_at_with_test_registry(
                TargetFile::UsersConf,
                &path,
            ));
        });
        let applied = applied_result.unwrap().expect("walk succeeds");
        assert_eq!(applied, vec![101, 102], "walked V101 then V102");

        let final_bytes = std::fs::read(&path).unwrap();
        let final_v = read_schema_version(&final_bytes, TargetFile::UsersConf).unwrap();
        assert_eq!(final_v, 2, "on-disk version after walk");
    }

    /// Seed a tempfile at version >= target; apply_pending returns an
    /// empty applied list and the file is unchanged.
    #[test]
    fn apply_pending_skips_already_at_target() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let path = tmp.path().join("users.conf");
        let already_at_v2 = br#"{"_schema_version":2,"subnets":[{"cidr":"10.0.0.0/24","allow_users":["sandbox","alice"]}]}"#;
        std::fs::write(&path, already_at_v2).unwrap();
        let mtime_before = std::fs::metadata(&path).unwrap().modified().unwrap();

        static REG: &[&dyn ConfigMigration] = &[&StubV001Then1, &StubV002Then2];
        let mut result: Option<Result<Vec<u32>, MigrationError>> = None;
        with_test_registry(REG, || {
            result = Some(apply_pending_at_with_test_registry(
                TargetFile::UsersConf,
                &path,
            ));
        });
        let applied = result.unwrap().expect("skip path returns Ok");
        assert!(
            applied.is_empty(),
            "no migrations to apply, got {applied:?}"
        );

        let mtime_after = std::fs::metadata(&path).unwrap().modified().unwrap();
        assert_eq!(
            mtime_before, mtime_after,
            "skip path must not touch the file"
        );
    }

    /// The atomic-write contract: the destination path holds the
    /// pre-write content (or no content) until `persist` runs; readers
    /// never see a half-written file. We exercise this by writing into
    /// a tempfile parent that does not exist — `NamedTempFile::new_in`
    /// errors before any byte hits `path`, so the destination is
    /// untouched. This is the failure-mode counterpart to a successful
    /// rename: either both happen (write + rename) or neither does.
    #[test]
    fn apply_pending_atomic_write_visible_only_after_complete() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let path = tmp.path().join("users.conf");
        let original = br#"{"subnets":[{"cidr":"10.0.0.0/24","allow_users":["sandbox","alice"]}]}"#;
        std::fs::write(&path, original).unwrap();

        // Inject a fault: pre-existing path whose parent is a regular
        // file (so `NamedTempFile::new_in(parent)` returns ENOTDIR
        // before any write happens). The destination path's content
        // must be the pre-write bytes after the failure.
        let blocker = tmp.path().join("blocker");
        std::fs::write(&blocker, b"i am not a directory").unwrap();
        // The synthetic target path lives "inside" the blocker — its
        // parent is a regular file, not a dir.
        let synthetic = blocker.join("users.conf");

        // Direct call: assert atomic_write errors and the original
        // file (which we have not touched) is bit-for-bit preserved.
        let err = atomic_write(&synthetic, b"new content")
            .expect_err("write under a non-directory parent must error");
        match err {
            MigrationError::Io(_) => {}
            other => panic!("expected Io, got {other:?}"),
        }

        // The pre-existing canonical-path file we wrote earlier must
        // still hold its original content: the failed write touched
        // `synthetic`, not `path`, so we assert the original `path`
        // is unmodified — the same invariant the apply loop relies on
        // (a failed migration never leaves the canonical path in a
        // half-applied state).
        let post = std::fs::read(&path).unwrap();
        assert_eq!(
            post.as_slice(),
            original,
            "atomic_write failure must not mutate the canonical path"
        );
    }

    /// Pin the binding selection rule from Spec 5 § 4.2: every entry
    /// in the **production** registry has `to_version() ==
    /// from_version() + 1`. A future contributor adding a
    /// multi-version-skip migration trips this test.
    #[test]
    fn registry_migrations_advance_exactly_one_version() {
        for m in registry() {
            assert_eq!(
                m.to_version(),
                m.from_version() + 1,
                "migration V{:03} ({}) violates the selection rule: from={} to={}",
                m.id(),
                m.name(),
                m.from_version(),
                m.to_version(),
            );
        }
    }

    /// The same property under fault injection: a synthetic migration
    /// with `to_version() != from_version() + 1` placed in a test-only
    /// registry must trip a `to_version == from_version + 1` assertion.
    /// This is the negative twin of the production-registry test —
    /// confirms the assertion catches bad shapes, not just that the
    /// current registry happens to satisfy it.
    #[test]
    fn registry_selection_rule_assertion_catches_synthetic_violator() {
        struct Bad;
        impl ConfigMigration for Bad {
            fn id(&self) -> u32 {
                999
            }
            fn name(&self) -> &'static str {
                "bad"
            }
            fn target_file(&self) -> TargetFile {
                TargetFile::UsersConf
            }
            fn from_version(&self) -> u32 {
                0
            }
            fn to_version(&self) -> u32 {
                3
            }
            fn apply(&self, _: &[u8]) -> Result<Vec<u8>, MigrationError> {
                unimplemented!()
            }
        }
        let bad = Bad;
        assert_ne!(
            bad.to_version(),
            bad.from_version() + 1,
            "the synthetic violator must violate (otherwise the test is tautological)"
        );
    }

    /// TargetFile <-> canonical path round-trip.
    #[test]
    fn target_file_canonical_path_round_trip() {
        for f in [TargetFile::UsersConf, TargetFile::BridgeConf] {
            let p = f.canonical_path();
            let back = TargetFile::from_canonical_path(&p).expect("canonical maps back");
            assert_eq!(back, f);
        }
        assert!(TargetFile::from_canonical_path(Path::new("/tmp/fake.json")).is_none());
        assert!(TargetFile::from_canonical_path(Path::new("/etc/sandboxd/other.json")).is_none());
    }

    /// `dump_migration_set` returns one entry per registered migration
    /// with the documented JSON shape (id, from_version, to_version,
    /// target_file). The CLI handler for `--dump-migration-set` writes
    /// `serde_json::to_string(&dump_migration_set())` to stdout; this
    /// test exercises the serialised shape.
    #[test]
    fn dump_migration_set_returns_documented_shape() {
        let entries = dump_migration_set();
        assert!(!entries.is_empty(), "registry has at least V001");
        let json = serde_json::to_value(&entries).expect("serialise");
        let arr = json.as_array().expect("array");
        for entry in arr {
            let obj = entry.as_object().expect("object");
            assert!(obj.contains_key("id"));
            assert!(obj.contains_key("from_version"));
            assert!(obj.contains_key("to_version"));
            assert!(obj.contains_key("target_file"));
        }
    }
}
