//! Cross-crate migration coverage.
//!
//! Tests in this file are named with the `integration_*` prefix and
//! are selected by the `integration` nextest profile (see
//! `sandboxd/.config/nextest.toml`). The substantive migration logic
//! is exercised by hermetic unit tests inside `src/store.rs::tests`
//! (`test_v004_migration_from_v1_seed_db`,
//! `test_v005_backend_column_migration`); the tests here are thin
//! wrappers that exercise the same migrations from outside the crate
//! to satisfy explicit verification commands in milestone handoffs
//! (e.g. M11-S1 Phase 1A) and to give the integration profile a
//! schema-evolution smoke that runs alongside the Docker-backed
//! gateway validators.
//!
//! The tests are still hermetic — embedded migrations + rusqlite, no
//! Docker required. The `integration_*` prefix here is therefore
//! about the test profile (matching the verification command in
//! M11-S1 Phase 1A) rather than about needing out-of-process state.

use rusqlite::{Connection, params};
use sandbox_core::SessionStore;
use tempfile::TempDir;

/// V005 migration: smoke-tests the `sessions.backend` column from
/// outside the crate, mirroring the unit test
/// `test_v005_backend_column_migration` in `store.rs::tests`.
///
/// Verifies after migration that:
///   1. The `backend` column exists.
///   2. Inserting a row with `backend = 'container'` succeeds.
///   3. Inserting a row with `backend = 'foo'` fails the CHECK
///      constraint declared by the V005 SQL.
///
/// Run via `cargo nextest run --profile integration -E
/// 'test(integration_v005_backend_column_migration)'`.
#[test]
fn integration_v005_backend_column_migration() {
    let dir = TempDir::new().expect("tempdir");
    let (_store, _orphans) = SessionStore::new(dir.path().to_path_buf()).expect("open at V005");

    let conn = Connection::open(dir.path().join("sessions.db")).unwrap();

    // 1. The `backend` column exists post-migration.
    let mut stmt = conn.prepare("PRAGMA table_info(sessions)").unwrap();
    let cols: Vec<String> = stmt
        .query_map([], |row| row.get::<_, String>(1))
        .unwrap()
        .map(|r| r.unwrap())
        .collect();
    assert!(
        cols.iter().any(|c| c == "backend"),
        "expected `backend` column after V005; got {cols:?}"
    );

    // 2. The CHECK constraint accepts 'container' (and by extension
    //    'lima', exercised exhaustively by the unit test).
    let now = chrono::Utc::now().to_rfc3339();
    conn.execute(
        "INSERT INTO sessions (id, name, state, config, created_at, updated_at, backend)
         VALUES (?1, ?2, 'Stopped', '{}', ?3, ?3, 'container')",
        params!["111111111111", "ctr", now],
    )
    .expect("container backend must be accepted");

    // 3. The CHECK constraint rejects any other token.
    let err = conn.execute(
        "INSERT INTO sessions (id, name, state, config, created_at, updated_at, backend)
         VALUES (?1, ?2, 'Stopped', '{}', ?3, ?3, 'foo')",
        params!["222222222222", "bad", now],
    );
    assert!(
        err.is_err(),
        "CHECK constraint must reject backend='foo'; got Ok"
    );
}
