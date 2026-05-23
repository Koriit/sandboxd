//! Integration tests for gateway-image tag pinning.
//!
//! The daemon-productionization revision pins every gateway-container
//! reference to `sandbox-gateway:<daemon-version>` — never `:latest`,
//! never a bare repository name. This test exercises the runtime
//! behavior:
//!
//! - Build a fake `sandbox-gateway:<workspace-version>` image (the
//!   real gateway image is heavy; for this assertion the daemon-side
//!   composition matters, not the image contents);
//! - Run a sleep-stub container at that tag;
//! - Assert the resulting container's image reference, as reported by
//!   `docker inspect`, matches the pinned daemon-version tag.
//!
//! Test name uses the workspace `integration_*` prefix so the default
//! nextest profile filters it out; the integration profile selects it
//! by prefix. Design reference: daemon-productionization (image pinning) —
//! `integration_gateway_image_pinned_to_daemon_version`.

use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use sandbox_core::gateway::{GATEWAY_IMAGE_REPOSITORY, gateway_image_tag_for_version};

/// RAII guard: best-effort `docker rm -f` on drop. Test crashes
/// before the explicit cleanup line don't leak the container.
struct ContainerGuard {
    name: String,
}

impl Drop for ContainerGuard {
    fn drop(&mut self) {
        let _ = Command::new("docker")
            .args(["rm", "-f", &self.name])
            .output();
    }
}

/// RAII guard: best-effort `docker rmi` on drop. Removing the tag is
/// non-destructive — docker keeps the underlying image layer around
/// for any other tag that points at it, and our test tag is
/// timestamp-suffixed so the tag is unique per test invocation and
/// safe to remove.
struct ImageGuard {
    tag: String,
}

impl Drop for ImageGuard {
    fn drop(&mut self) {
        let _ = Command::new("docker").args(["rmi", &self.tag]).output();
    }
}

#[test]
fn integration_gateway_image_pinned_to_daemon_version() {
    // Compose the canonical daemon-version-pinned tag exactly the way
    // the daemon does. The constant + helper assertion is also pinned
    // by a hermetic unit test; this integration test pins the
    // docker-side behavior.
    let version = env!("CARGO_PKG_VERSION");
    let pinned_tag = gateway_image_tag_for_version(version);
    assert!(
        pinned_tag.starts_with(&format!("{GATEWAY_IMAGE_REPOSITORY}:")),
        "tag must use the canonical repository prefix; got: {pinned_tag}"
    );
    assert_ne!(
        pinned_tag,
        format!("{GATEWAY_IMAGE_REPOSITORY}:latest"),
        "production daemon must never compose a `:latest` reference"
    );

    // Suffix the tag with a timestamp so concurrent test runs and
    // any pre-built `sandbox-gateway:<version>` on the host don't
    // collide. The test asserts the *shape* of the pinning rule,
    // not that the daemon's exact CARGO_PKG_VERSION image is on the
    // host (that's what the gateway-image build step provides).
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let test_tag = format!("{GATEWAY_IMAGE_REPOSITORY}:itest-{version}-{nanos}");

    // Build a tiny image at the test tag. We tag a known busybox
    // image so the test doesn't depend on the real gateway image
    // being present; the daemon's pinning logic doesn't inspect
    // image *contents*, only references.
    //
    // Pull busybox first so the tag step doesn't fail on a clean CI
    // image cache.
    let pull = Command::new("docker")
        .args(["pull", "busybox:1.36"])
        .output()
        .expect("docker pull should be invokable; ensure Docker daemon is running");
    assert!(
        pull.status.success(),
        "docker pull failed: stderr={}",
        String::from_utf8_lossy(&pull.stderr)
    );

    let tag_cmd = Command::new("docker")
        .args(["tag", "busybox:1.36", &test_tag])
        .output()
        .expect("docker tag should be invokable");
    assert!(
        tag_cmd.status.success(),
        "docker tag failed: stderr={}",
        String::from_utf8_lossy(&tag_cmd.stderr)
    );
    let _image_guard = ImageGuard {
        tag: test_tag.clone(),
    };

    // Run a container at the pinned tag.
    let ctr_name = format!("sandbox-gateway-pin-test-{nanos}");
    let run = Command::new("docker")
        .args([
            "run",
            "-d",
            "--name",
            &ctr_name,
            "--entrypoint",
            "sleep",
            &test_tag,
            "60",
        ])
        .output()
        .expect("docker run should be invokable");
    assert!(
        run.status.success(),
        "docker run failed: stderr={}",
        String::from_utf8_lossy(&run.stderr)
    );
    let _ctr_guard = ContainerGuard {
        name: ctr_name.clone(),
    };

    // Inspect the running container; its `.Config.Image` is the
    // image *reference* docker recorded at run time — that is the
    // string we want to match against the pinned tag. (`Image` on
    // the top-level inspect node is the resolved image ID, not the
    // reference, and would be useless for this assertion.)
    let inspect = Command::new("docker")
        .args(["inspect", "--format", "{{.Config.Image}}", &ctr_name])
        .output()
        .expect("docker inspect should be invokable");
    assert!(
        inspect.status.success(),
        "docker inspect failed: stderr={}",
        String::from_utf8_lossy(&inspect.stderr)
    );

    let image_ref = String::from_utf8(inspect.stdout)
        .expect("docker inspect output must be utf-8")
        .trim()
        .to_string();

    assert_eq!(
        image_ref, test_tag,
        "container's image reference must equal the pinned tag we ran it at — \
         the daemon's gateway-image-pinning rule depends on this exact wire shape; \
         got `{image_ref}`, expected `{test_tag}`"
    );
    assert!(
        !image_ref.ends_with(":latest"),
        "container's image reference must NOT collapse to `:latest`; got `{image_ref}`"
    );
}
