//! Integration test for the lite-mode orphan reaper.
//!
//! Spec § "Orphan cleanup on daemon start" — the reaper enumerates the
//! `sandbox-` Docker namespace at boot and removes any container,
//! `sandbox-home-*` volume, or `sandbox-net-*` network whose derived
//! session id is not present in `sessions.db`.
//!
//! This file stands real Docker resources up under two synthetic
//! session ids — one "live" (present in the live set passed to the
//! reaper) and one "orphan" (absent) — runs the reaper, and asserts
//! the orphan is gone while the live one survives. Hermetic unit
//! coverage of the parsers, partitioning, and best-effort error paths
//! lives next to the production code in
//! `sandbox-core/src/backend/orphan_reaper.rs::tests`; this file
//! exercises only the parts that need a real `docker` daemon.
//!
//! Naming follows the workspace convention: tests are prefixed
//! `integration_*` so the `integration` nextest profile (defined in
//! `sandboxd/.config/nextest.toml`) selects them and the default
//! profile filters them out.

use std::collections::HashSet;
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

use sandbox_core::Cidr4;
use sandbox_core::backend::{CliDockerOps, reap_orphans};
use sandbox_core::session::SessionId;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Pick a fresh, non-colliding 12-hex session id derived from the
/// wall-clock — the per-call seed mixes in so callers building an
/// "orphan" pair and a "live" pair in the same test get distinct ids
/// even when the wall clock has moved fewer than a few hundred
/// nanoseconds between calls.
///
/// PID is mixed into the trailing slot because two `cargo nextest`
/// processes running on the same host (parallel CI, dev-host plus
/// CI agent, etc.) would otherwise share both the per-call seed and
/// the low-order wall-clock nanos and could land on the same 12-hex
/// id. `std::process::id()` differs per OS process, so its low byte
/// breaks that cross-process tie. Chose `process::id()` over an
/// atomic counter because the counter is per-process — it cannot
/// disambiguate two test processes that each happen to start their
/// counter at 0.
fn unique_session_id(seed: &str) -> SessionId {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let raw = format!("{nanos:032x}");
    let seed_byte = seed.as_bytes().iter().fold(0u8, |a, b| a.wrapping_add(*b));
    let pid_byte = (std::process::id() & 0xff) as u8;
    // Two leading hex chars from the seed, eight trailing hex chars
    // from the wall-clock, two trailing hex chars from the pid — 12
    // total. SessionId::parse demands exactly 12.
    let tail = &raw[2..10];
    let mixed = format!("{seed_byte:02x}{tail}{pid_byte:02x}");
    SessionId::parse(&mixed).expect("12-hex session id")
}

/// Best-effort cleanup of one (container, volume, network) tuple. Used
/// both as a pre-test hygiene step and inside the RAII Drop guard.
fn pre_clean(container: &str, volume: &str, network: &str) {
    let _ = Command::new("docker")
        .args(["rm", "-f", container])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    let _ = Command::new("docker")
        .args(["volume", "rm", volume])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    let _ = Command::new("docker")
        .args(["network", "rm", network])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
}

/// Returns true when `docker inspect <name>` succeeds — i.e. the
/// resource still exists. Used as the assertion primitive for both the
/// "should be reaped" and "should NOT be reaped" branches.
fn docker_exists(kind: &str, name: &str) -> bool {
    let args: &[&str] = match kind {
        "container" => &["container", "inspect", name],
        "volume" => &["volume", "inspect", name],
        "network" => &["network", "inspect", name],
        _ => panic!("unknown kind {kind}"),
    };
    Command::new("docker")
        .args(args)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Create a stopped (i.e. `created` state) `alpine:latest` container
/// with the given name. The reaper just needs *some* container in the
/// `sandbox-` namespace, and `created` is the cheapest state — `docker
/// rm -f` removes it regardless.
fn create_stopped_container(name: &str) {
    let output = Command::new("docker")
        .args([
            "create",
            "--name",
            name,
            "--entrypoint",
            "true",
            "alpine:latest",
        ])
        .output()
        .expect("docker create should be invokable; ensure Docker is running");
    assert!(
        output.status.success(),
        "docker create --name {name} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn create_volume(name: &str) {
    let output = Command::new("docker")
        .args(["volume", "create", name])
        .output()
        .expect("docker volume create should be invokable");
    assert!(
        output.status.success(),
        "docker volume create {name} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn create_network(name: &str, third_octet: u8, fourth_octet: u8) {
    // Use a non-overlapping /28 in 10.99.x.0/16 so the test does not
    // fight any production allocation. Caller picks the (third, fourth)
    // octet so two networks created in the same test don't collide.
    let subnet = format!("10.99.{third_octet}.{fourth_octet}/28");
    let output = Command::new("docker")
        .args(["network", "create", "--subnet", &subnet, name])
        .output()
        .expect("docker network create should be invokable");
    assert!(
        output.status.success(),
        "docker network create {name} ({subnet}) failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

/// RAII guard that always tears down the test resources even if the
/// assertion below panics, leaving the host clean for the next run.
struct ResourceCleanup {
    container: String,
    volume: String,
    network: String,
}

impl Drop for ResourceCleanup {
    fn drop(&mut self) {
        pre_clean(&self.container, &self.volume, &self.network);
    }
}

// ---------------------------------------------------------------------------
// Test
// ---------------------------------------------------------------------------

/// End-to-end exercise of the reaper against real Docker, covering
/// **both** sides of the contract in a single pass:
///
/// - An "orphan" tuple (container/volume/network) under a synthetic
///   session id NOT in the live set must be removed.
/// - A "live" tuple under a session id present in the live set must
///   NOT be touched.
///
/// Combining the two cases into one test (rather than splitting into
/// orphan-only and live-only fixtures) keeps the test inherently
/// race-free against parallel runs and pins the reaper's full
/// behavioural promise in one assertion block.
#[tokio::test]
async fn integration_orphan_reaper_removes_orphans_and_preserves_live_resources() {
    let orphan_sid = unique_session_id("orphan");
    let live_sid = unique_session_id("live-session");
    // The seed-mixing scheme means orphan_sid and live_sid only
    // collide if the seeds hash to the same byte AND the wall clock
    // produces identical low-order nanos for both calls. The pair
    // chosen above ("orphan" vs "live-session") sums to different
    // bytes, so the leading hex chars differ.
    assert_ne!(orphan_sid, live_sid, "orphan and live ids must differ");

    let orphan_container = format!("sandbox-{orphan_sid}");
    let orphan_volume = format!("sandbox-home-{orphan_sid}");
    let orphan_network = format!("sandbox-net-{orphan_sid}");
    let live_container = format!("sandbox-{live_sid}");
    let live_volume = format!("sandbox-home-{live_sid}");
    let live_network = format!("sandbox-net-{live_sid}");

    // Pre-test cleanup of any leaked resources from a prior failed run.
    pre_clean(&orphan_container, &orphan_volume, &orphan_network);
    pre_clean(&live_container, &live_volume, &live_network);

    // RAII guards — Drop runs even if an assertion below panics.
    let _orphan_cleanup = ResourceCleanup {
        container: orphan_container.clone(),
        volume: orphan_volume.clone(),
        network: orphan_network.clone(),
    };
    let _live_cleanup = ResourceCleanup {
        container: live_container.clone(),
        volume: live_volume.clone(),
        network: live_network.clone(),
    };

    // Stand both tuples up under real Docker. Pick distinct /28s for
    // the two networks so they don't fight over the same subnet.
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let third = (nanos as u8).wrapping_mul(1);
    let fourth_orphan = (nanos.wrapping_shr(8) as u8).wrapping_mul(16);
    let fourth_live = fourth_orphan.wrapping_add(16);

    create_stopped_container(&orphan_container);
    create_volume(&orphan_volume);
    create_network(&orphan_network, third, fourth_orphan);

    create_stopped_container(&live_container);
    create_volume(&live_volume);
    create_network(&live_network, third, fourth_live);

    // Sanity: every resource exists before the reaper runs.
    for (kind, name) in [
        ("container", &orphan_container),
        ("container", &live_container),
        ("volume", &orphan_volume),
        ("volume", &live_volume),
        ("network", &orphan_network),
        ("network", &live_network),
    ] {
        assert!(
            docker_exists(kind, name),
            "precondition: {kind} {name} should exist before reaper runs"
        );
    }

    // Live set carries only `live_sid`; the reaper must reap the
    // `orphan_sid` tuple and leave the `live_sid` tuple intact.
    //
    // NB: parallel reaper tests on the same host would interfere with
    // each other (a concurrent test's "live" set wouldn't include
    // *our* orphan id); this test stays single-threaded by virtue of
    // being the only `integration_orphan_reaper_*` test in the suite.
    let live: HashSet<SessionId> = [live_sid].into_iter().collect();
    // The fixture's networks live in `10.99.0.0/16` (see
    // `create_network` above), which spans every /28 the test pulls
    // out of that range. The dual-anchor IPAM gate is exercised
    // explicitly in `integration_orphan_reaper_cidr.rs`; here we
    // want the existing reap-and-preserve contract under a CIDR
    // pool that fully contains the fixture's networks, so the gate
    // is permissive and the assertions below keep their original
    // shape.
    let pool = Cidr4::parse("10.99.0.0/16").expect("test pool parses");
    let report = reap_orphans(&CliDockerOps, &live, &pool).await;

    // Counters: at least one of each (other orphans on the host from
    // unrelated parallel tests can push this higher; we assert the
    // floor, not equality).
    assert!(
        report.containers_reaped >= 1,
        "reaper should report at least 1 container reaped, got {}",
        report.containers_reaped
    );
    assert!(
        report.volumes_reaped >= 1,
        "reaper should report at least 1 volume reaped, got {}",
        report.volumes_reaped
    );
    assert!(
        report.networks_reaped >= 1,
        "reaper should report at least 1 network reaped, got {}",
        report.networks_reaped
    );

    // Contract A — orphan resources are gone.
    assert!(
        !docker_exists("container", &orphan_container),
        "orphan container {orphan_container} should have been removed by the reaper"
    );
    assert!(
        !docker_exists("volume", &orphan_volume),
        "orphan volume {orphan_volume} should have been removed by the reaper"
    );
    assert!(
        !docker_exists("network", &orphan_network),
        "orphan network {orphan_network} should have been removed by the reaper"
    );

    // Contract B — live resources survived.
    assert!(
        docker_exists("container", &live_container),
        "live container {live_container} must NOT be reaped when its session id is live"
    );
    assert!(
        docker_exists("volume", &live_volume),
        "live volume {live_volume} must NOT be reaped when its session id is live"
    );
    assert!(
        docker_exists("network", &live_network),
        "live network {live_network} must NOT be reaped when its session id is live"
    );
}
