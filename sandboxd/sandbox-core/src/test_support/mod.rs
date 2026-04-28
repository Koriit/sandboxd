//! Test-only helpers shared across `sandbox-core`'s own integration
//! tests and (cross-crate) the daemon's `tests/` integration suite.
//!
//! Cargo's per-test-binary integration model makes it difficult to
//! share `tests/`-local helpers across crates: a `tests/helpers/`
//! module under `sandbox-core` is unreachable from `sandboxd/tests/`.
//! Putting the helper in `src/` (instead of `tests/helpers/`) is the
//! idiomatic Cargo pattern for shared cross-crate test scaffolding;
//! see the M11-S8 plan section ("Single-test file ... plus a helper
//! ... or similar") which permits the placement deviation when the
//! literal `tests/helpers/` path conflicts with cross-crate
//! consumption.
//!
//! Each helper is **public-API**, **runtime-stable**, and exercised
//! only by integration tests. Production code paths must never reach
//! these helpers; the `test_support` module name and the docs on
//! each helper make that contract explicit.
//!
//! See:
//! - [`docker_path_stub`] — RAII guard that prepends a temp directory
//!   containing a `docker` shim to `PATH`, with configurable
//!   `docker info --format '{{.SecurityOptions}}'` responses for
//!   testing the rootless-Docker probe.

pub mod docker_path_stub;
