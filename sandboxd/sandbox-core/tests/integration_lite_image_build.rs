//! Integration tests for [`sandbox_core::backend::ensure_image`] —
//! the missing-image build path of the lite-mode container backend.
//!
//! These tests exercise the real `docker` daemon: each one runs a real
//! `docker build` against a unique daemon-version-shaped tag and asserts
//! the resulting image artefact is observable via `docker image
//! inspect`. RAII guards remove every tag the test creates so parallel
//! runs and panic paths cannot leak images.
//!
//! Test names are prefixed `integration_*` so the default hermetic
//! `make test` profile filters them out (see
//! `sandboxd/.config/nextest.toml`); the integration profile selects
//! them via that prefix.
//!
//! ## `sandbox-guest` staging
//!
//! `ensure_image()` resolves the `sandbox-guest` binary via
//! `sandbox_core::lima::guest_agent_path` — `{current_exe().parent()}/
//! sandbox-guest`. Under `cargo nextest`, the test binary lives in
//! `target/<profile>/deps/`, while the workspace's built `sandbox-guest`
//! lives in `target/<profile>/sandbox-guest`. Each test calls
//! [`ensure_sandbox_guest_in_exe_parent`] before invoking
//! `ensure_image` so the agent binary is reachable from the test
//! exe's parent. The helper is safe to call concurrently — `Once`
//! gates the copy.

use std::process::{Command, Stdio};
use std::sync::{Mutex, Once};
use std::time::{SystemTime, UNIX_EPOCH};

use sandbox_core::backend::{
    EnsureImageOutcome, LITE_FIRST_USE_WARNING, LITE_IMAGE_REPOSITORY, ensure_image,
};

// ---------------------------------------------------------------------------
// sandbox-guest staging — one-time copy from target/<profile>/ into
// the test binary's deps/ directory so `guest_agent_path()` resolves.
// ---------------------------------------------------------------------------

static GUEST_STAGED: Once = Once::new();

fn ensure_sandbox_guest_in_exe_parent() {
    GUEST_STAGED.call_once(|| {
        let exe = std::env::current_exe().expect("current_exe");
        let deps_dir = exe.parent().expect("test exe parent (deps/)");
        let dest = deps_dir.join("sandbox-guest");
        if dest.exists() {
            return;
        }

        // The workspace's target dir is the parent of `deps/` — i.e.
        // `target/<profile>/`. `sandbox-guest` lives there after a
        // successful `cargo build --workspace`.
        let profile_dir = deps_dir
            .parent()
            .expect("deps_dir parent (target/<profile>/)");
        let candidates = [
            profile_dir.join("sandbox-guest"),
            // Cargo sometimes produces the binary one level higher in
            // unusual layouts (workspace + custom target dirs).
            profile_dir
                .parent()
                .map(|p| p.join("sandbox-guest"))
                .unwrap_or_default(),
        ];
        let src = candidates
            .iter()
            .find(|p| p.exists())
            .cloned()
            .unwrap_or_else(|| {
                panic!(
                    "sandbox-guest binary not found in any of: {candidates:?}. \
                     Run `cargo build --workspace` first.",
                )
            });

        std::fs::copy(&src, &dest).unwrap_or_else(|e| {
            panic!(
                "failed to stage sandbox-guest from {} to {}: {e}",
                src.display(),
                dest.display()
            )
        });
    });
}

// ---------------------------------------------------------------------------
// Tag minting + RAII cleanup
// ---------------------------------------------------------------------------

/// Mint a fresh, unique daemon-version-shaped string. Includes the
/// pid + nanos + a per-call counter so two tests running in the same
/// process and at the same instant still get distinct tags.
fn unique_daemon_version(label: &str) -> String {
    static COUNTER: Mutex<u64> = Mutex::new(0);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let pid = std::process::id();
    let n = {
        let mut g = COUNTER.lock().unwrap();
        *g = g.wrapping_add(1);
        *g
    };
    format!("test-build-{label}-{pid}-{nanos}-{n}")
}

/// RAII guard that `docker rmi -f`s the lite image tag on Drop.
/// Built-once-per-test contract: every test owns exactly one fresh
/// tag and tears it down whether it passed or panicked.
struct LiteImageCleanup {
    tag: String,
}

impl LiteImageCleanup {
    fn new(daemon_version: &str) -> Self {
        Self {
            tag: format!("{LITE_IMAGE_REPOSITORY}:{daemon_version}"),
        }
    }
}

impl Drop for LiteImageCleanup {
    fn drop(&mut self) {
        let _ = Command::new("docker")
            .args(["rmi", "-f", &self.tag])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
}

fn docker_image_inspect_succeeds(tag: &str) -> bool {
    Command::new("docker")
        .args(["image", "inspect", tag])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// First-use path: a fresh daemon-version tag is built, the warning
/// text matches the design verbatim, and `docker image inspect` confirms
/// the image is registered with the host docker daemon afterwards.
#[test]
fn integration_lite_image_build_first_use_emits_warning_and_tags_image() {
    ensure_sandbox_guest_in_exe_parent();
    let version = unique_daemon_version("first-use");
    let _cleanup = LiteImageCleanup::new(&version);

    let outcome = ensure_image(&version).expect("ensure_image must succeed on first use");

    match outcome {
        EnsureImageOutcome::Built { warning } => {
            assert_eq!(
                warning, LITE_FIRST_USE_WARNING,
                "warning text must match LITE_FIRST_USE_WARNING verbatim"
            );
        }
        EnsureImageOutcome::AlreadyPresent => {
            panic!("first use must report Built, got AlreadyPresent")
        }
    }

    let tag = format!("{LITE_IMAGE_REPOSITORY}:{version}");
    assert!(
        docker_image_inspect_succeeds(&tag),
        "image {tag} must be present after Built outcome"
    );
}

/// Second call with the same daemon version must observe
/// `AlreadyPresent` (no `Built`, no warning) — the inspect-then-skip
/// path that keeps subsequent session creates fast.
#[test]
fn integration_lite_image_build_second_call_skips_build() {
    ensure_sandbox_guest_in_exe_parent();
    let version = unique_daemon_version("skip");
    let _cleanup = LiteImageCleanup::new(&version);

    let first = ensure_image(&version).expect("ensure_image must succeed on first call");
    assert!(
        matches!(first, EnsureImageOutcome::Built { .. }),
        "first call must report Built, got {first:?}"
    );

    let second = ensure_image(&version).expect("ensure_image must succeed on second call");
    assert_eq!(
        second,
        EnsureImageOutcome::AlreadyPresent,
        "second call must skip the build"
    );
}

// Disabled: this test hangs indefinitely on memory-constrained hosts
// (folio_wait_bit_common, no docker activity). See
// https://github.com/Koriit/sandboxd/issues/10 for the investigation.
// Re-enable after the root cause (slow-timeout policy and/or
// container_image_lock deadlock investigation) is resolved.
//
// /// Concurrency contract: N threads racing into `ensure_image()` with
// /// the same fresh tag observe exactly one `Built` and `N-1`
// /// `AlreadyPresent`. Pins the `container_image_lock` mutex's
// /// invariant — without it, parallel docker builds duplicate work.
// #[test]
// fn integration_lite_image_build_concurrent_calls_serialize() {
//     ensure_sandbox_guest_in_exe_parent();
//     let version = unique_daemon_version("concurrent");
//     let _cleanup = LiteImageCleanup::new(&version);
//
//     const N: usize = 4;
//     let barrier = Arc::new(Barrier::new(N));
//     let mut handles = Vec::with_capacity(N);
//     for _ in 0..N {
//         let barrier = Arc::clone(&barrier);
//         let version = version.clone();
//         handles.push(thread::spawn(move || {
//             barrier.wait();
//             ensure_image(&version)
//         }));
//     }
//
//     let outcomes: Vec<EnsureImageOutcome> = handles
//         .into_iter()
//         .map(|h| h.join().expect("thread join").expect("ensure_image"))
//         .collect();
//
//     let built_count = outcomes
//         .iter()
//         .filter(|o| matches!(o, EnsureImageOutcome::Built { .. }))
//         .count();
//     let already_count = outcomes
//         .iter()
//         .filter(|o| matches!(o, EnsureImageOutcome::AlreadyPresent))
//         .count();
//
//     assert_eq!(
//         built_count, 1,
//         "exactly one thread must observe Built (got {built_count}); outcomes: {outcomes:?}"
//     );
//     assert_eq!(
//         already_count,
//         N - 1,
//         "remaining threads must observe AlreadyPresent (got {already_count}); outcomes: {outcomes:?}"
//     );
//
//     if let Some(EnsureImageOutcome::Built { warning }) = outcomes
//         .iter()
//         .find(|o| matches!(o, EnsureImageOutcome::Built { .. }))
//     {
//         assert_eq!(warning, LITE_FIRST_USE_WARNING);
//     }
//
//     let tag = format!("{LITE_IMAGE_REPOSITORY}:{version}");
//     assert!(
//         docker_image_inspect_succeeds(&tag),
//         "image {tag} must be present after the race",
//     );
// }
