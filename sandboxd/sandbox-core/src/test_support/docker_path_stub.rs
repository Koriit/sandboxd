//! RAII guard that prepends a `docker` shim to `PATH` for tests of
//! the rootless-Docker probe (and any other code path that calls
//! `docker info --format '{{.SecurityOptions}}'`).
//!
//! # Why
//!
//! The container backend's rootless-Docker probe
//! ([`crate::backend::container_rootless_probe`]) shells out to
//! `docker info`. Verifying both the rootless and the default-hardened
//! arms of the daemon's create-session gate without an actual
//! rootless-Docker installation requires intercepting that one
//! invocation while letting every other `docker` call (test image
//! build, `docker create`, etc.) pass through to the real binary.
//!
//! # How
//!
//! On construction, the helper:
//! 1. Acquires a process-wide mutex so two parallel tests cannot
//!    race on `PATH`. Cargo's nextest runs integration tests in
//!    parallel within a binary; without serialization, one test's
//!    `PATH` mutation would corrupt another's environment.
//! 2. Records the current `PATH` so the shim can forward
//!    non-intercepted invocations to the real `docker`.
//! 3. Creates a temporary directory containing a `docker` shim
//!    (a bash script) and a small data file with the canned
//!    `docker info` response.
//! 4. Mutates `PATH` to prepend the temp directory.
//!
//! On `Drop` (RAII), the helper:
//! 1. Restores the saved `PATH`.
//! 2. Releases the process-wide mutex.
//! 3. Drops the [`tempfile::TempDir`], which removes the shim.
//!
//! # Why bash and not a Rust binary
//!
//! The workspace has no precedent for compiling a Rust shim at test
//! time; `bash` is universally available on the Linux dev/CI hosts
//! the daemon itself targets. The shim is ~10 lines of POSIX shell
//! and trivially portable. If the workspace later moves to a
//! Rust-only test-substrate convention, this can be migrated
//! without changing the public API of [`DockerPathStub`] /
//! [`DockerInfoBehavior`].
//!
//! # Why a process-wide mutex (and not `serial_test`)
//!
//! `serial_test` would force a new dev-dependency on every crate
//! that consumes the helper. The mutex below is local, zero-deps,
//! and gives the same "no two tests in this process touch `PATH`
//! concurrently" guarantee. Cross-process serialization is
//! unnecessary because each test process owns its own `PATH`.
//!
//! # Public API (consumed by Wave 3's integration tests)
//!
//! - [`DockerInfoBehavior`] — enum of the three canned response
//!   shapes.
//! - [`DockerPathStub::new`] — constructor; returns a guard that
//!   holds the `PATH` mutation until dropped.
//! - [`DockerPathStub::path`] — accessor for the temp directory's
//!   path, useful for assertions and for directly invoking the
//!   shim under test (e.g., to verify the shim's behavior in
//!   isolation).

use std::env;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::sync::{Mutex, MutexGuard, OnceLock};

use tempfile::TempDir;

/// Configurable response shape for the stub's
/// `docker info --format '{{.SecurityOptions}}'` interception.
///
/// Wave 3's tests mix-and-match these three behaviors against the
/// daemon's container-create flow:
///
/// - [`ReportRootless`](Self::ReportRootless) — the daemon should
///   refuse the create with [`crate::SandboxError::RootlessDockerRefused`]
///   unless the `--force-rootless-docker` flag is set.
/// - [`ReportDefault`](Self::ReportDefault) — the create should
///   proceed; this is the unchanged baseline behavior.
/// - [`Fail`](Self::Fail) — the daemon should propagate a
///   [`crate::SandboxError::Gateway`] (probe failure is not a
///   silent default).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DockerInfoBehavior {
    /// Stub emits a `SecurityOptions` list that contains the
    /// `name=rootless` token; probe must classify the host as
    /// rootless.
    ReportRootless,
    /// Stub emits a `SecurityOptions` list without `name=rootless`;
    /// probe must classify the host as default-hardened.
    ReportDefault,
    /// Stub exits non-zero on any `docker info` invocation; probe
    /// must surface a typed error.
    Fail,
}

impl DockerInfoBehavior {
    /// Verbatim shell snippet the shim runs when `docker info` is
    /// invoked. Pulled out so the shim's behavior is self-evident
    /// from this enum and stays in sync with the variants.
    fn shim_action(self) -> &'static str {
        match self {
            // The literal Docker output shapes are documented in
            // `container_rootless_probe::parse_security_options` —
            // keep the canned strings in lock-step with that
            // module's expectations.
            DockerInfoBehavior::ReportRootless => {
                "echo '[name=seccomp,profile=builtin name=rootless]'\nexit 0"
            }
            DockerInfoBehavior::ReportDefault => "echo '[name=seccomp,profile=builtin]'\nexit 0",
            DockerInfoBehavior::Fail => {
                "echo 'rootless-docker probe stub: configured to fail' >&2\nexit 1"
            }
        }
    }
}

/// Process-wide mutex guarding `PATH` mutations. Tests that
/// construct [`DockerPathStub`] in parallel within the same test
/// binary will serialize on this lock. The lock is released when
/// the [`DockerPathStub`] guard is dropped.
fn path_mutex() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

/// RAII guard that intercepts `docker info` calls for the duration
/// of its lifetime. See the module docs for the high-level shape
/// and Wave 3's integration tests for concrete usage.
///
/// The guard is **not** `Send` — callers must keep it on the same
/// thread that constructed it. This matches how integration tests
/// use it (single-threaded test bodies) and avoids the need to
/// reason about cross-thread `PATH` mutation visibility.
///
/// Dropping the guard restores `PATH` and releases the mutex even if
/// a test panics in between, so a failing test cannot leak `PATH`
/// state into a subsequent test in the same binary.
pub struct DockerPathStub {
    /// Temp directory holding the shim. Dropped last, after `PATH`
    /// has been restored, so an in-flight subprocess that already
    /// captured `PATH` cannot dereference a missing shim path.
    _tempdir: TempDir,
    /// Saved `PATH` value to restore on drop. `None` if `PATH` was
    /// unset on construction (rare but legal — restored to unset).
    saved_path: Option<String>,
    /// Holds the mutex guard for the lifetime of `self`. The
    /// `'static` lifetime is satisfied by `path_mutex()` returning
    /// a reference to a `OnceLock`-managed static.
    _lock_guard: MutexGuard<'static, ()>,
}

impl DockerPathStub {
    /// Construct a new stub with the given `behavior` and install it
    /// at the front of `PATH`.
    ///
    /// Blocks if another stub is currently active in the same
    /// process (the mutex serializes parallel tests). Returns the
    /// guard once it has the lock and the stub is fully installed.
    ///
    /// # Panics
    ///
    /// Panics on any I/O failure (tempdir creation, file write,
    /// chmod). Test helpers prefer panic-on-failure to surface setup
    /// errors as test failures with stack traces, mirroring the
    /// `expect`-heavy convention in the existing integration tests
    /// (`integration_container_runtime.rs` etc.).
    pub fn new(behavior: DockerInfoBehavior) -> Self {
        // NOTE: poisoned-mutex recovery — a previous test's panic
        // poisons the lock; we recover the guard via `into_inner`
        // because the poison only signals "a previous test panicked
        // mid-stub", not "the lock state is corrupted". Each
        // construction does its own setup from scratch.
        let lock_guard = match path_mutex().lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };

        let tempdir = TempDir::new().expect("create tempdir for docker shim");
        let shim_path = tempdir.path().join("docker");

        // Save PATH before mutation. The shim resolves the real
        // `docker` via the saved value (passed through an env var)
        // so non-`info` calls forward correctly even though `PATH`
        // currently has the stub at its head.
        let saved_path = env::var("PATH").ok();
        let saved_path_for_shim = saved_path.clone().unwrap_or_default();

        // Generate the shim. Bash because the workspace has no
        // precedent for build-time-compiled Rust shims and bash is
        // universally available on the Linux daemon target.
        //
        // Behavior:
        // - If invoked as `docker info --format '{{.SecurityOptions}}'`
        //   (the exact shape the rootless probe uses), apply the
        //   configured action.
        // - Otherwise, exec the real docker resolved from the
        //   saved PATH (passed via $SANDBOX_REAL_PATH).
        //
        // The matched arg sequence is exact, not a prefix match —
        // the probe always sends those three positional args in
        // that order, and intercepting on shape (rather than
        // subcommand alone) keeps unrelated `docker info` calls
        // (e.g., a developer running `docker info` interactively
        // during debugging) flowing through.
        let shim_body = format!(
            r#"#!/usr/bin/env bash
# Test shim for the rootless-Docker probe. Generated by
# sandbox_core::test_support::docker_path_stub::DockerPathStub.
# Do not edit by hand; the file lives in a tempdir and is removed
# when the test guard is dropped.

set -u

if [ "$#" -eq 3 ] \
    && [ "$1" = "info" ] \
    && [ "$2" = "--format" ] \
    && [ "$3" = "{{{{.SecurityOptions}}}}" ]; then
    {action}
fi

# Forward all other invocations to the real `docker` resolved via
# the test harness's saved PATH. Use `env -i` to wipe PATH, then
# set it back to the saved value, so the recursive lookup cannot
# re-enter this shim.
exec env -i \
    PATH="$SANDBOX_REAL_PATH" \
    HOME="${{HOME:-/}}" \
    USER="${{USER:-}}" \
    docker "$@"
"#,
            action = behavior.shim_action(),
        );

        fs::write(&shim_path, shim_body).expect("write docker shim");
        let mut perms = fs::metadata(&shim_path)
            .expect("stat docker shim")
            .permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&shim_path, perms).expect("chmod docker shim");

        // Mutate PATH: prepend the shim directory and pass the saved
        // PATH through to the shim via SANDBOX_REAL_PATH.
        let new_path = match saved_path.as_deref() {
            Some(existing) => format!("{}:{}", tempdir.path().display(), existing),
            None => tempdir.path().display().to_string(),
        };
        // SAFETY (Rust 2024 set_var semantics): callers serialize
        // through `path_mutex()`, so no concurrent reader/writer
        // races on the env block exist for the lifetime of this
        // mutation. The corresponding restore in `Drop` happens
        // under the same lock.
        unsafe {
            env::set_var("PATH", &new_path);
            env::set_var("SANDBOX_REAL_PATH", &saved_path_for_shim);
        }

        Self {
            _tempdir: tempdir,
            saved_path,
            _lock_guard: lock_guard,
        }
    }

    /// Path to the temp directory holding the shim. Useful for
    /// tests that want to assert the directory is on PATH or to
    /// invoke the shim directly without going through the probe.
    pub fn path(&self) -> &std::path::Path {
        self._tempdir.path()
    }
}

impl Drop for DockerPathStub {
    fn drop(&mut self) {
        // Restore PATH (or remove it if it was unset on entry).
        // Done before tempdir cleanup so any in-flight subprocess
        // that captured the modified PATH does not lose its shim
        // mid-execution. SAFETY: same justification as `new()` —
        // the mutex serializes env mutations.
        unsafe {
            match self.saved_path.take() {
                Some(prev) => env::set_var("PATH", prev),
                None => env::remove_var("PATH"),
            }
            env::remove_var("SANDBOX_REAL_PATH");
        }
        // `_tempdir` and `_lock_guard` are dropped by the auto-
        // generated Drop in field order: tempdir first (cleans up
        // the shim file), then the lock guard (releases the
        // process-wide mutex).
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;

    /// Verify the full integration path: install the stub, invoke
    /// `docker info --format '{{.SecurityOptions}}'` via the same
    /// `Command` shape the probe uses, and observe the canned
    /// rootless output. Confirms shim install + PATH mutation +
    /// argv-shape match all line up.
    #[test]
    fn report_rootless_intercepts_info_call() {
        let _stub = DockerPathStub::new(DockerInfoBehavior::ReportRootless);

        let output = Command::new("docker")
            .arg("info")
            .arg("--format")
            .arg("{{.SecurityOptions}}")
            .output()
            .expect("spawn shim");

        assert!(output.status.success(), "shim should exit 0 for rootless");
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            stdout.contains("name=rootless"),
            "expected `name=rootless` in stub output, got: {stdout}"
        );
    }

    #[test]
    fn report_default_omits_rootless_token() {
        let _stub = DockerPathStub::new(DockerInfoBehavior::ReportDefault);

        let output = Command::new("docker")
            .arg("info")
            .arg("--format")
            .arg("{{.SecurityOptions}}")
            .output()
            .expect("spawn shim");

        assert!(output.status.success(), "shim should exit 0 for default");
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            !stdout.contains("name=rootless"),
            "default-hardened stub must not emit `name=rootless`, got: {stdout}"
        );
        assert!(
            stdout.contains("name=seccomp"),
            "default stub should still emit a non-empty SecurityOptions list, got: {stdout}"
        );
    }

    #[test]
    fn fail_behavior_exits_nonzero() {
        let _stub = DockerPathStub::new(DockerInfoBehavior::Fail);

        let output = Command::new("docker")
            .arg("info")
            .arg("--format")
            .arg("{{.SecurityOptions}}")
            .output()
            .expect("spawn shim");

        assert!(!output.status.success(), "Fail stub must exit non-zero");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("configured to fail"),
            "Fail stub should explain itself in stderr: {stderr}"
        );
    }

    #[test]
    fn drop_restores_path() {
        let saved = env::var("PATH").ok();
        {
            let _stub = DockerPathStub::new(DockerInfoBehavior::ReportDefault);
            // Inside the guard, PATH must be modified.
            let modified = env::var("PATH").expect("PATH set during guard");
            assert_ne!(Some(modified), saved.clone(), "PATH must be modified");
        }
        // After Drop, PATH is back.
        assert_eq!(env::var("PATH").ok(), saved, "PATH must be restored");
        // SANDBOX_REAL_PATH is cleaned up.
        assert!(
            env::var("SANDBOX_REAL_PATH").is_err(),
            "SANDBOX_REAL_PATH must be cleared after drop"
        );
    }

    /// The shim is on PATH ahead of any real `docker`, so a fresh
    /// `which docker` resolves to the temp directory. Confirms the
    /// PATH ordering, not just that PATH was mutated.
    #[test]
    fn shim_takes_precedence_on_path() {
        let stub = DockerPathStub::new(DockerInfoBehavior::ReportDefault);
        let path = env::var("PATH").expect("PATH set");
        let first_dir = path.split(':').next().expect("non-empty PATH");
        assert_eq!(
            std::path::Path::new(first_dir),
            stub.path(),
            "stub directory must be PATH[0], got {first_dir}"
        );
    }

    /// Two stubs constructed back-to-back in the same thread serialize
    /// cleanly through the mutex. The second sees the first's `Drop`
    /// effects (PATH restored) before its own setup runs.
    #[test]
    fn sequential_stubs_do_not_leak() {
        let baseline = env::var("PATH").ok();
        {
            let _a = DockerPathStub::new(DockerInfoBehavior::ReportRootless);
        }
        {
            let _b = DockerPathStub::new(DockerInfoBehavior::ReportDefault);
        }
        assert_eq!(env::var("PATH").ok(), baseline);
    }
}
