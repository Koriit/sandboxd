//! Rootless-Docker probe for the container backend.
//!
//! Spec § Non-goals line 1175 declares rootless Docker out of scope:
//! Lite's target is **default-hardened Docker**. The previous milestone
//! (M11-S7) caught the gap between this prose contract and the daemon's
//! actual behavior — a polarity-inverted `is_rootless_docker()` skipif
//! on `tests/e2e/test_lite.py:493` was silently masking the fact that
//! the daemon happily created container sessions on rootless hosts,
//! where userns-remap shifts ownership of bind-mounted workspace files
//! in ways the spec § Workspace UID-alignment contract does not cover.
//!
//! This module is the daemon-side detection point that closes the loop:
//! it runs `docker info --format '{{.SecurityOptions}}'` once per
//! daemon lifetime and inspects the output for the literal substring
//! `name=rootless`. The result is cached for the daemon's lifetime —
//! the Docker daemon's mode does not change without a restart, so a
//! per-startup probe is sufficient and a re-probe within the same
//! daemon lifetime is wasted I/O.
//!
//! # Placement and reachability
//!
//! This module is a sibling of [`super::container`] and is **only**
//! consumed by the container backend's session-create path (wired in
//! M11-S8 Wave 2). It is **not** re-exported via [`super`] and Lima
//! code paths never reach it — the structural decision keeps the probe
//! container-only by construction, not by convention.
//!
//! # Public API (consumed by Wave 2's session-create handler)
//!
//! - [`is_rootless_docker`] — async, returns `Ok(true)` on rootless
//!   hosts, `Ok(false)` on default-hardened hosts, and a typed
//!   [`SandboxError::Gateway`] if `docker info` itself fails. Probe
//!   failure is **never** treated as "not rootless" — Wave 2's caller
//!   propagates the error so the operator sees a clear "Docker daemon
//!   unreachable" diagnostic rather than a silent default that could
//!   later create a session against an unsupported environment.
//!
//! - [`reset_cache_for_tests`] (test-only) — clears the cache so a
//!   single test process can run multiple probes against different
//!   PATH-stub configurations.
//!
//! # Caching and error handling
//!
//! The cache is `OnceLock<Mutex<Option<Result<bool, String>>>>`. We
//! cache the `Result` (not just the success value) because:
//! - On a healthy default-hardened host, the probe runs once at the
//!   first session-create call and every subsequent call is a
//!   single-mutex acquire-release.
//! - On a host where `docker info` is broken (binary missing, daemon
//!   down), re-probing every session-create call is wasted work — the
//!   environment is unchanged. The cached error message is reconstructed
//!   into a fresh [`SandboxError::Gateway`] on each access since
//!   `SandboxError` is intentionally not [`Clone`].
//!
//! `Mutex<Option<...>>` is preferred over `OnceLock<Result<...>>`
//! because the test-only [`reset_cache_for_tests`] path needs a sound
//! way to invalidate the cache without `unsafe` reference-casting; an
//! explicit interior-mutability primitive is the idiomatic answer.
//! The mutex contention is benign: the critical section is a single
//! `Option::clone()` after the first probe call.

use std::process::Command;
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

use crate::error::SandboxError;
use crate::process::run_with_timeout;

/// Wall-clock timeout for the `docker info` invocation. Sized to
/// match the existing per-call timeout in [`super::container`]'s
/// `run_docker` so a busy or unhealthy Docker daemon surfaces as a
/// timeout rather than an indefinite hang.
const DOCKER_INFO_TIMEOUT: Duration = Duration::from_secs(60);

/// Substring the probe greps for in the `docker info` output. Docker
/// emits the security-options list as
/// `[name=seccomp,profile=builtin name=rootless]` on rootless hosts
/// and `[name=seccomp,profile=builtin]` (no `name=rootless`) on
/// default-hardened hosts. Match on the literal token to avoid false
/// positives from any prose that mentions the word "rootless".
const ROOTLESS_TOKEN: &str = "name=rootless";

/// Per-daemon cache. `None` means the probe has not run yet;
/// `Some(Ok(bool))` is the successful probe outcome;
/// `Some(Err(String))` is a cached probe-failure message that will be
/// wrapped in [`SandboxError::Gateway`] on each access.
///
/// `OnceLock<Mutex<...>>` is the standard pattern for a lazily-
/// initialised static with interior mutability — cheap to construct
/// (the `Mutex` is created at most once on first access) and sound
/// for the test-only reset path in [`reset_cache_for_tests`].
fn probe_cache() -> &'static Mutex<Option<Result<bool, String>>> {
    static CACHE: OnceLock<Mutex<Option<Result<bool, String>>>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(None))
}

/// Run the rootless-Docker probe (or return the cached result).
///
/// Returns `Ok(true)` if the host's Docker daemon is in rootless mode,
/// `Ok(false)` if it is in default-hardened mode, and
/// [`SandboxError::Gateway`] if the probe itself failed (binary
/// missing, daemon unreachable, malformed output, timeout).
///
/// Wraps the blocking `docker` invocation in [`tokio::task::spawn_blocking`]
/// per the workspace's `spawn_blocking` discipline (CLAUDE.md "Key
/// conventions"). Subsequent calls within the same daemon lifetime
/// are cheap — they read the cached result without spawning a child
/// process.
///
/// # Errors
///
/// Probe-failure is **never** converted to a default — Wave 2's
/// session-create handler propagates the [`SandboxError::Gateway`] to
/// the operator. The intent: a daemon that cannot probe its own
/// Docker is not in a state to safely create sessions, and the
/// operator deserves a clear "Docker daemon unreachable" signal
/// rather than a silent fallback that might later fail at
/// `docker create` time with a less-actionable error.
pub async fn is_rootless_docker() -> Result<bool, SandboxError> {
    // Fast path: cache hit. Lock, clone, drop the guard before
    // returning so the lock is not held across the caller's await
    // points.
    {
        let guard = probe_cache().lock().map_err(|e| {
            SandboxError::Internal(format!("rootless probe cache mutex poisoned: {e}"))
        })?;
        if let Some(cached) = guard.as_ref() {
            return match cached {
                Ok(b) => Ok(*b),
                Err(msg) => Err(SandboxError::Gateway(msg.clone())),
            };
        }
    }

    // Cache miss — run the probe on a blocking thread so we don't
    // park the tokio runtime on a subprocess.
    let probed: Result<bool, String> = tokio::task::spawn_blocking(probe_blocking)
        .await
        .map_err(|e| SandboxError::Internal(format!("spawn_blocking join failed: {e}")))?;

    // Install into the cache. A concurrent racer that already
    // installed a value loses to no one — both observe the same
    // probe-deterministic outcome, so a last-writer-wins install is
    // semantically equivalent to a first-writer-wins install at the
    // per-host scope.
    {
        let mut guard = probe_cache().lock().map_err(|e| {
            SandboxError::Internal(format!("rootless probe cache mutex poisoned: {e}"))
        })?;
        *guard = Some(probed.clone());
    }

    match probed {
        Ok(b) => Ok(b),
        Err(msg) => Err(SandboxError::Gateway(msg)),
    }
}

/// Run `docker info --format '{{.SecurityOptions}}'` and parse for the
/// rootless token. Synchronous because [`is_rootless_docker`] dispatches
/// it onto a blocking thread.
///
/// Returns `Ok(true)` / `Ok(false)` for a successful probe and
/// `Err(String)` carrying the operator-facing message for any failure
/// path (spawn error, non-zero exit, timeout). The string is what
/// gets cached and re-wrapped into [`SandboxError::Gateway`] on each
/// observation of the cached error.
fn probe_blocking() -> Result<bool, String> {
    let mut cmd = Command::new("docker");
    cmd.arg("info").arg("--format").arg("{{.SecurityOptions}}");

    let output = run_with_timeout(
        &mut cmd,
        DOCKER_INFO_TIMEOUT,
        "docker info (rootless probe)",
    )
    .map_err(|e| match e {
        // Surface the most common operator-actionable cause
        // (Docker not installed) with the binary name it failed
        // on, so the daemon log makes the cause obvious.
        SandboxError::Internal(msg) if msg.contains("failed to spawn") => {
            format!("rootless-docker probe could not spawn `docker`: {msg}")
        }
        other => format!("rootless-docker probe failed: {other}"),
    })?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!(
            "rootless-docker probe: `docker info` exited {} — {}",
            output
                .status
                .code()
                .map(|c| c.to_string())
                .unwrap_or_else(|| "<signal>".to_string()),
            stderr.trim()
        ));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    Ok(parse_security_options(&stdout))
}

/// Parse the `{{.SecurityOptions}}` template output and decide
/// whether it indicates rootless mode.
///
/// Docker emits the list in Go-template debug form, e.g.
/// `[name=seccomp,profile=builtin name=rootless]\n` on a rootless
/// host. We do **not** parse the bracket structure — the literal
/// [`ROOTLESS_TOKEN`] substring is the source of truth for rootless
/// detection in Docker's documented output and avoids fragility
/// against unrelated security-option additions in future Docker
/// versions. Pulled out as a free function so unit tests can pin the
/// semantics without spawning `docker`.
fn parse_security_options(output: &str) -> bool {
    output.contains(ROOTLESS_TOKEN)
}

/// Reset the cached probe result. **Test-only.** Allows a single
/// test process to run multiple probes against different PATH-stub
/// configurations (e.g. one test asserts "rootless ⇒ refused", a
/// neighbour asserts "default-hardened ⇒ proceeds"). Exposed as
/// `pub` (not `pub(crate)`) so cross-crate integration tests in the
/// daemon (M11-S8 Wave 3, located in `sandboxd/sandboxd/tests/`) can
/// invalidate the cache between PATH-stub reconfigurations within
/// the same test binary.
///
/// Production code MUST NOT call this — caching is a correctness
/// property of the probe (a daemon's Docker mode does not change
/// without a restart), not just a performance optimisation. The
/// `for_tests` suffix and the docs make the contract explicit; a
/// future audit can grep for the function name to confirm no
/// non-test caller exists.
pub fn reset_cache_for_tests() {
    let mut guard = probe_cache()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    *guard = None;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_security_options_rootless() {
        // Verbatim shape Docker emits on a rootless host. The
        // probe's contract is to find the `name=rootless` literal
        // substring anywhere in the output.
        let raw = "[name=seccomp,profile=builtin name=rootless]\n";
        assert!(parse_security_options(raw));
    }

    #[test]
    fn parse_security_options_default_hardened() {
        // Default Docker, no userns-remap, no rootless.
        let raw = "[name=seccomp,profile=builtin]\n";
        assert!(!parse_security_options(raw));
    }

    #[test]
    fn parse_security_options_extra_options_with_rootless() {
        // Future Docker versions may add more security options
        // alongside rootless; the probe must continue to detect
        // rootless without depending on the surrounding list.
        let raw = "[name=apparmor name=seccomp,profile=builtin name=rootless name=cgroupns]\n";
        assert!(parse_security_options(raw));
    }

    #[test]
    fn parse_security_options_empty_list() {
        // A pathological but valid shape — no security options at
        // all. Not rootless.
        let raw = "[]\n";
        assert!(!parse_security_options(raw));
    }

    #[test]
    fn parse_security_options_mention_in_unrelated_prose_does_not_match() {
        // Sanity: the token is a literal `name=rootless`, not the
        // bare word "rootless". Avoids false positives from any
        // future Docker output that mentions rootless in prose.
        let raw = "[name=seccomp]\nrootless mode is not enabled\n";
        assert!(!parse_security_options(raw));
    }

    /// End-to-end exercise of the probe against the PATH-stub
    /// helper. Confirms that the public `is_rootless_docker` async
    /// surface, the cache plumbing, and the bash shim all line up —
    /// so Wave 2's session-create handler can call the probe with
    /// confidence that the tested shape matches what production
    /// Docker emits.
    ///
    /// Pinned to a single multi-step body (rather than three
    /// independent `#[tokio::test]`s) because the stub mutates a
    /// process-wide PATH and the probe holds a process-wide cache
    /// — interleaving them across tokio tests would race even
    /// inside the stub's own mutex (the cache lives outside the
    /// stub's lock). One test, three sequential phases, with an
    /// explicit cache reset between them.
    #[tokio::test]
    async fn probe_against_path_stub_round_trip() {
        use crate::test_support::docker_path_stub::{DockerInfoBehavior, DockerPathStub};

        // Phase 1: ReportRootless ⇒ probe sees `name=rootless` ⇒ true.
        reset_cache_for_tests();
        {
            let _stub = DockerPathStub::new(DockerInfoBehavior::ReportRootless);
            let observed = is_rootless_docker()
                .await
                .expect("probe should succeed against ReportRootless stub");
            assert!(
                observed,
                "ReportRootless stub must classify host as rootless"
            );
        }

        // Phase 2: ReportDefault ⇒ probe sees no rootless token ⇒ false.
        reset_cache_for_tests();
        {
            let _stub = DockerPathStub::new(DockerInfoBehavior::ReportDefault);
            let observed = is_rootless_docker()
                .await
                .expect("probe should succeed against ReportDefault stub");
            assert!(
                !observed,
                "ReportDefault stub must classify host as default-hardened"
            );
        }

        // Phase 3: Fail ⇒ probe surfaces a typed Gateway error,
        // never silently defaults to "not rootless".
        reset_cache_for_tests();
        {
            let _stub = DockerPathStub::new(DockerInfoBehavior::Fail);
            let err = is_rootless_docker()
                .await
                .expect_err("probe must surface error for Fail stub, not silently default");
            match &err {
                SandboxError::Gateway(msg) => {
                    assert!(
                        msg.contains("rootless-docker probe"),
                        "Gateway error should be tagged as a probe failure: {msg}"
                    );
                }
                other => panic!("expected SandboxError::Gateway, got {other:?}"),
            }
        }

        // Reset before any subsequent test in this module observes
        // a stale cache from phase 3.
        reset_cache_for_tests();
    }
}
