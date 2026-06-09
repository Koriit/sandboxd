//! Integration tests for image-presence semantics observed at
//! session-create time.
//!
//! Two contracts the daemon enforces on every `POST /sessions`:
//!
//! 1. **Lite image is built on demand.** A daemon started with
//!    `sandboxd-lite:<daemon-version>` absent does not refuse to
//!    start; the first session-create that needs the lite image
//!    invokes `ensure_image`, which builds it on the spot and tags
//!    it at the daemon's version. After session-create returns
//!    successfully, the image is observable via `docker image
//!    inspect`. The test re-uses the lite-image build contract
//!    already pinned by `integration_lite_image_build_*` but renames
//!    it to align with the daemon-productionization.6
//!    naming.
//!
//! 2. **Missing gateway image is a hard refusal.** A daemon started
//!    with `sandbox-gateway:<daemon-version>` absent still starts
//!    (so `sandbox doctor` can report it), but every subsequent
//!    `POST /sessions` returns a clear `SandboxError::Gateway`
//!    naming the missing tag and pointing the operator at
//!    `sandbox update`. The integration test confirms the daemon-
//!    side primitives that compose this refusal:
//!    - `gateway_image_present` against a guaranteed-missing tag
//!      returns `Ok(false)`;
//!    - the operator-visible hint rendered for that tag includes
//!      the load-bearing substrings (`sandbox update`, the tag).
//!
//! Design reference: daemon-productionization (image pinning) —
//! `integration_session_create_builds_lite_image_on_demand`,
//! `integration_session_create_refused_on_missing_gateway_image`.

use std::process::{Command, Stdio};
use std::sync::{Mutex, Once};
use std::time::{SystemTime, UNIX_EPOCH};

use sandbox_core::backend::{
    EnsureImageOutcome, LITE_IMAGE_REPOSITORY, ensure_image, lite_image_tag_for_version,
};
use sandbox_core::gateway::{
    GATEWAY_IMAGE_REPOSITORY, gateway_image_present, missing_gateway_image_hint,
};

// ---------------------------------------------------------------------------
// sandbox-guest staging — mirrors `integration_lite_image_build.rs`.
// `ensure_image` resolves the agent binary via `current_exe().parent()`;
// `cargo nextest` places the test binary in `target/<profile>/deps/`
// while the workspace's `sandbox-guest` lives in `target/<profile>/`.
// Stage a copy next to the test exe so the build context picks it up.
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

        std::fs::copy(&src, &dest)
            .unwrap_or_else(|e| panic!("stage sandbox-guest {src:?} -> {dest:?}: {e}"));

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&dest, std::fs::Permissions::from_mode(0o755))
                .expect("chmod sandbox-guest");
        }
    });
}

fn unique_label(prefix: &str) -> String {
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
    format!("{prefix}-{pid}-{nanos}-{n}")
}

/// Best-effort tag cleanup on drop; tests own a unique
/// `sandboxd-lite:<test-version>` tag and free it whether they pass
/// or panic.
struct LiteImageCleanup {
    tag: String,
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

/// Daemon-side first-use path: a session-create that needs a lite
/// image whose `sandboxd-lite:<daemon-version>` tag is not present
/// triggers `ensure_image`, which builds and tags it on the spot.
/// After the call, the image is observable via `docker image
/// inspect`. We don't exercise the full HTTP `POST /sessions` because
/// it would require booting Lima, a gateway container, the network
/// manager and the event bus — none of which the lite-image-build
/// contract depends on. The piece this test pins is the
/// `ensure_image` building block that `create_session` calls into.
#[test]
fn integration_session_create_builds_lite_image_on_demand() {
    ensure_sandbox_guest_in_exe_parent();

    let version = unique_label("on-demand-build");
    let tag = lite_image_tag_for_version(&version);
    let _cleanup = LiteImageCleanup { tag: tag.clone() };

    // Precondition: the image must NOT be present before the call —
    // otherwise the test is trivially satisfied by a stale tag. The
    // unique-version-per-call infrastructure guarantees this, but
    // pin it explicitly so a future fixture leak is loud.
    assert!(
        !docker_image_inspect_succeeds(&tag),
        "test precondition: {tag} must not exist before the on-demand build"
    );

    let docker_home = tempfile::tempdir().expect("per-test docker_home tempdir");
    let outcome = ensure_image(&version, docker_home.path())
        .expect("on-demand lite-image build must succeed on first call");

    match outcome {
        EnsureImageOutcome::Built { .. } => { /* expected */ }
        EnsureImageOutcome::AlreadyPresent => {
            panic!(
                "first call for a fresh daemon-version must build the image, not skip; \
                 outcome={outcome:?}, tag={tag}"
            )
        }
    }

    assert!(
        docker_image_inspect_succeeds(&tag),
        "after on-demand build, `docker image inspect {tag}` must succeed"
    );

    // The post-build tag conforms to the daemon's pinning rule:
    // `sandboxd-lite:<daemon-version>`, never `:latest`.
    assert!(
        tag.starts_with(&format!("{LITE_IMAGE_REPOSITORY}:")),
        "post-build tag must use the canonical repository prefix; got: {tag}"
    );
    assert!(
        !tag.ends_with(":latest"),
        "post-build tag must not collapse to :latest; got: {tag}"
    );
}

/// Session-create refusal contract: a daemon started without the
/// `sandbox-gateway:<daemon-version>` image returns a clear
/// `SandboxError::Gateway(...)` whose `Display` mentions the missing
/// tag and points the operator at `sandbox update`. We assert the
/// two building blocks the daemon composes:
///
/// 1. `gateway_image_present` against a guaranteed-missing tag
///    returns `Ok(false)` (the docker-side `no such image` path).
/// 2. `missing_gateway_image_hint` against that tag includes the
///    load-bearing operator tokens.
///
/// The end-to-end HTTP path (refused `POST /sessions`) reuses the
/// same primitives and is covered by the higher-level E2E suite;
/// pinning the primitives here keeps the contract testable without
/// booting the full daemon for an integration run.
#[test]
fn integration_session_create_refused_on_missing_gateway_image() {
    // Compose a tag we are confident does not exist locally. The
    // suffix is a nanosecond-precision timestamp + pid, which is the
    // same uniqueness primitive the lite-image tests use.
    let tag = format!(
        "{GATEWAY_IMAGE_REPOSITORY}:absent-{}",
        unique_label("missing")
    );

    // Sanity: not just "missing on this CI machine" but also "the
    // gateway_image_present helper returns Ok(false) for it".
    let present = gateway_image_present(&tag).expect(
        "gateway_image_present must distinguish missing from docker-daemon errors; \
         this test requires a reachable docker daemon",
    );
    assert!(
        !present,
        "test precondition: tag {tag} must not exist on the host"
    );

    // The operator-visible hint rendered for that tag includes the
    // tokens the design mandates: the missing tag and the
    // `sandbox update` remediation pointer.
    let hint = missing_gateway_image_hint(&tag);
    assert!(
        hint.contains(&tag),
        "hint must name the missing tag verbatim; got: {hint}"
    );
    assert!(
        hint.contains("sandbox update"),
        "hint must point the operator at `sandbox update`; got: {hint}"
    );
    assert!(
        hint.contains("gateway image missing"),
        "hint must lead with `gateway image missing` so operators can grep journald; \
         got: {hint}"
    );
}
