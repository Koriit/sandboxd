//! Test-only helpers shared across `sandbox-core`'s own integration
//! tests and (cross-crate) the daemon's `tests/` integration suite.
//!
//! Cargo's per-test-binary integration model makes it difficult to
//! share `tests/`-local helpers across crates: a `tests/helpers/`
//! module under `sandbox-core` is unreachable from `sandboxd/tests/`.
//! Putting the helper in `src/` (instead of `tests/helpers/`) is the
//! idiomatic Cargo pattern for shared cross-crate test scaffolding;
//! the literal `tests/helpers/` path conflicts with cross-crate
//! consumption, so the deviation is intentional.
//!
//! Each helper is **public-API**, **runtime-stable**, and exercised
//! only by integration tests. Production code paths must never reach
//! these helpers; the `test_support` module name and the docs on
//! each helper make that contract explicit.
//!
//! See:
//! - [`crate::test_support::docker_path_stub`] — RAII guard that prepends a temp directory
//!   containing a `docker` shim to `PATH`, with configurable
//!   `docker info --format '{{.SecurityOptions}}'` responses for
//!   testing the rootless-Docker probe.
//! - [`home_env_mutex`] — process-wide lock for tests that mutate `HOME`,
//!   `XDG_RUNTIME_DIR`, or other XDG env vars; prevents races between
//!   tests that run concurrently under `cargo test`.

pub mod docker_path_stub;

/// Returns a reference to the process-wide mutex that serializes all
/// tests which mutate `HOME`, `XDG_RUNTIME_DIR`, `SANDBOX_LISTENER_DIR`,
/// `SANDBOX_EVENTS_DIR`, or any other XDG / home-directory env var.
///
/// `cargo test` runs unit tests within the same binary concurrently on
/// multiple threads. Without serialization, one test's `remove_var("HOME")`
/// races with another test's `env::var("HOME")` and causes flakes. nextest
/// provides per-test process isolation so the lock is belt-and-suspenders
/// there, but it keeps `cargo test` deterministic.
///
/// # Usage
///
/// ```ignore
/// let _guard = crate::test_support::home_env_mutex().lock().unwrap();
/// // mutate HOME / XDG_RUNTIME_DIR here
/// ```
pub fn home_env_mutex() -> &'static std::sync::Mutex<()> {
    static LOCK: std::sync::OnceLock<std::sync::Mutex<()>> = std::sync::OnceLock::new();
    LOCK.get_or_init(|| std::sync::Mutex::new(()))
}
