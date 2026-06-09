//! Integration tests for [`sandbox_core::backend::rebuild_lite_image`]
//! — the operator-driven rebuild path of the lite-mode container
//! backend.
//!
//! `rebuild_lite_image` is the operator-driven counterpart to
//! `ensure_image`: where `ensure_image` short-circuits when the image is
//! already present, `rebuild_lite_image` always runs `docker build`
//! (with or without `--no-cache` per the operator's flag). These tests
//! exercise the real `docker` daemon — the same scaffold pattern as
//! `integration_lite_image_build.rs`:
//!
//! - Each test mints a unique daemon-version-shaped tag so parallel
//!   runs cannot collide.
//! - RAII cleanup `docker rmi -f`s the tag on drop.
//! - `sandbox-guest` is staged into the test binary's parent before
//!   any `rebuild_lite_image` call (the lite Dockerfile copies the
//!   guest binary in via `guest_agent_path()`).
//!
//! Test names are prefixed `integration_*` so the default hermetic
//! `make test` profile filters them out (see
//! `sandboxd/.config/nextest.toml`); the integration profile selects
//! them via that prefix.

use std::process::{Command, Stdio};
use std::sync::{Mutex, Once};
use std::time::{SystemTime, UNIX_EPOCH};

use sandbox_core::backend::{
    EnsureImageOutcome, LITE_IMAGE_REPOSITORY, ensure_image, rebuild_lite_image,
};

// ---------------------------------------------------------------------------
// sandbox-guest staging — same one-time copy as the build tests, so the
// lite Dockerfile's `COPY` of `sandbox-guest` resolves under nextest's
// `target/<profile>/deps/` exe layout.
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

        let profile_dir = deps_dir
            .parent()
            .expect("deps_dir parent (target/<profile>/)");
        let candidates = [
            profile_dir.join("sandbox-guest"),
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
// Tag minting + RAII cleanup (mirrors integration_lite_image_build.rs).
// ---------------------------------------------------------------------------

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
    format!("test-rebuild-{label}-{pid}-{nanos}-{n}")
}

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

/// `rebuild_lite_image` against a fresh tag must produce a tagged image
/// observable via `docker image inspect`. Equivalent to "first build"
/// from the operator's perspective (`sandbox rebuild-image --backend
/// container` against a host that never created a lite session before).
#[test]
fn integration_lite_image_rebuild_fresh_tag_produces_image() {
    ensure_sandbox_guest_in_exe_parent();
    let version = unique_daemon_version("fresh");
    let _cleanup = LiteImageCleanup::new(&version);

    let docker_home = tempfile::tempdir().expect("per-test docker_home tempdir");
    rebuild_lite_image(&version, false, docker_home.path()).expect("rebuild_lite_image must succeed on fresh tag");

    let tag = format!("{LITE_IMAGE_REPOSITORY}:{version}");
    assert!(
        docker_image_inspect_succeeds(&tag),
        "image {tag} must be present after rebuild_lite_image",
    );
}

/// `rebuild_lite_image` always runs `docker build` even when the image
/// is already present — that is the property that distinguishes it from
/// `ensure_image`. Pin via `ensure_image` first (Built, then
/// AlreadyPresent), then call `rebuild_lite_image` and confirm the
/// image is still inspectable. The "always rebuild" property is not
/// directly observable without instrumenting docker; we settle for the
/// post-condition (image present) and the lock-reuse property (the
/// rebuild path must not deadlock against `ensure_image`'s same lock).
#[test]
fn integration_lite_image_rebuild_after_ensure_image_succeeds() {
    ensure_sandbox_guest_in_exe_parent();
    let version = unique_daemon_version("post-ensure");
    let _cleanup = LiteImageCleanup::new(&version);

    let docker_home = tempfile::tempdir().expect("per-test docker_home tempdir");
    let first = ensure_image(&version, docker_home.path()).expect("ensure_image first call");
    assert!(
        matches!(first, EnsureImageOutcome::Built { .. }),
        "ensure_image first call must build, got {first:?}",
    );

    let second = ensure_image(&version, docker_home.path()).expect("ensure_image second call");
    assert_eq!(
        second,
        EnsureImageOutcome::AlreadyPresent,
        "ensure_image second call must skip the build",
    );

    rebuild_lite_image(&version, false, docker_home.path())
        .expect("rebuild_lite_image must succeed after ensure_image");

    let tag = format!("{LITE_IMAGE_REPOSITORY}:{version}");
    assert!(
        docker_image_inspect_succeeds(&tag),
        "image {tag} must remain present after rebuild_lite_image",
    );
}

/// `no_cache: true` must produce the same observable outcome — a
/// tagged image — as `no_cache: false`. The cache-bust flag changes the
/// build's internal layer reuse but not the post-condition this test
/// pins. Adding `--no-cache` to the docker argv is a behaviour the
/// underlying `build_lite_image` unit tests assert via `Dockerfile`
/// argument inspection; here we just confirm the flag does not break
/// the build path against a real docker daemon.
#[test]
fn integration_lite_image_rebuild_with_no_cache_succeeds() {
    ensure_sandbox_guest_in_exe_parent();
    let version = unique_daemon_version("no-cache");
    let _cleanup = LiteImageCleanup::new(&version);

    let docker_home = tempfile::tempdir().expect("per-test docker_home tempdir");
    rebuild_lite_image(&version, true, docker_home.path()).expect("rebuild_lite_image with no_cache=true must succeed");

    let tag = format!("{LITE_IMAGE_REPOSITORY}:{version}");
    assert!(
        docker_image_inspect_succeeds(&tag),
        "image {tag} must be present after rebuild_lite_image(no_cache=true)",
    );
}
