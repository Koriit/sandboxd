//! M11-S10 dual-anchor (CIDR-pool) orphan-reaper integration tests.
//!
//! These tests stand up real Docker fixtures and exercise the
//! second of the two ownership anchors documented at
//! `sandbox-core/src/backend/orphan_reaper.rs` § "Dual-anchor
//! ownership model": networks must lie inside the daemon's
//! `NetworkManager` allocator pool to be reaped, even when the
//! `sandbox-net-{12hex}` name prefix matches and the derived
//! session id is absent from the live set.
//!
//! Coverage split with `integration_orphan_reaper.rs`:
//!
//! - The pre-S10 file pins the **single-anchor** contract — name
//!   prefix says ours, session id orphaned, reaper removes the tuple.
//! - This file pins the **second anchor** added by S10 — IPAM probe
//!   gates the network reap (and transitively the container/volume
//!   siblings sharing the session id).
//!
//! Naming follows the workspace convention: tests are prefixed
//! `integration_*` so the `integration` nextest profile selects them
//! and the default profile filters them out.

use std::collections::HashSet;
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

use sandbox_core::Cidr4;
use sandbox_core::backend::{CliDockerOps, reap_orphans};
use sandbox_core::session::SessionId;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Fixed seed-prefix space for this file's session ids. Each test
/// derives its `(orphan, …)` 12-hex ids from the wall clock plus a
/// per-test seed — see [`unique_session_id`] — so two tests running
/// back-to-back never collide on the same `sandbox-{id}` name even
/// when the wall-clock nanosecond resolution is coarse.
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
    let tail = &raw[2..10];
    let mixed = format!("{seed_byte:02x}{tail}{pid_byte:02x}");
    SessionId::parse(&mixed).expect("12-hex session id")
}

/// Best-effort cleanup of one `(container, volume, network)` tuple.
/// Used both as a pre-test hygiene step and inside the RAII Drop
/// guard.
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

// Container attaches to Docker's default `bridge` network rather than
// the per-test `sandbox-net-{sid}`. Some Docker engine versions register
// a `created`-state container as an active endpoint of its custom
// network, which then makes `docker network rm sandbox-net-{sid}` fail
// with "network has active endpoints". The dual-anchor gate cares about
// the session-id correspondence between `sandbox-{sid}` and
// `sandbox-net-{sid}`, not the Docker-level network attachment.
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

/// Create a Docker bridge network with the given subnet. The /28 the
/// in-pool test uses is carved from the daemon's allocator pool space
/// (`10.209.0.0/24`); the /24 the out-of-pool test uses is in
/// `192.168.99.0/24`, deliberately distant from the pool so a
/// neighboring sandboxd's IPAM is unambiguously different.
fn create_network(name: &str, subnet: &str) {
    let output = Command::new("docker")
        .args(["network", "create", "--subnet", subnet, name])
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

/// Sweep the host of any leftover `sandbox-net-{seed_byte}*` /
/// `sandbox-{seed_byte}*` / `sandbox-home-{seed_byte}*` resources from
/// a prior failed run. Best-effort; failures are intentionally
/// ignored.
fn pre_clean_all(orphan_sid: &SessionId) {
    pre_clean(
        &format!("sandbox-{orphan_sid}"),
        &format!("sandbox-home-{orphan_sid}"),
        &format!("sandbox-net-{orphan_sid}"),
    );
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// An out-of-pool `sandbox-net-{12hex}` network — same name prefix,
/// CIDR outside the daemon's allocator pool — must NOT be reaped.
/// The container and volume sharing the same session id inherit the
/// exemption transitively (the network is "not ours" by the second
/// anchor, so its siblings aren't either).
#[tokio::test]
async fn integration_reaper_skips_out_of_pool_network() {
    let orphan_sid = unique_session_id("cidr-out-of-pool");
    let container = format!("sandbox-{orphan_sid}");
    let volume = format!("sandbox-home-{orphan_sid}");
    let network = format!("sandbox-net-{orphan_sid}");

    pre_clean_all(&orphan_sid);
    let _cleanup = ResourceCleanup {
        container: container.clone(),
        volume: volume.clone(),
        network: network.clone(),
    };

    // Out-of-pool subnet — neighboring sandboxd's territory by
    // construction. Pool below is `10.209.0.0/24`.
    create_network(&network, "192.168.99.0/24");
    create_volume(&volume);
    create_stopped_container(&container);

    // Sanity preconditions — every fixture exists before the reaper
    // runs.
    for (kind, name) in [
        ("network", &network),
        ("volume", &volume),
        ("container", &container),
    ] {
        assert!(
            docker_exists(kind, name),
            "precondition: {kind} {name} should exist before reaper runs"
        );
    }

    let pool = Cidr4::parse("10.209.0.0/24").expect("test pool parses");
    let live: HashSet<SessionId> = HashSet::new();
    let _report = reap_orphans(&CliDockerOps, &live, &pool).await;

    // Dual-anchor enforcement: the name says sandboxd's, but the CIDR
    // does not — the reaper must leave all three resources intact.
    assert!(
        docker_exists("network", &network),
        "out-of-pool network {network} must NOT be reaped; second anchor failed"
    );
    assert!(
        docker_exists("container", &container),
        "container {container} sharing session id with an out-of-pool network must NOT be reaped"
    );
    assert!(
        docker_exists("volume", &volume),
        "volume {volume} sharing session id with an out-of-pool network must NOT be reaped"
    );
}

/// An in-pool `sandbox-net-{12hex}` network whose session id is
/// orphaned must be reaped, along with its container and home
/// volume — the pre-S10 contract is preserved when both anchors
/// agree.
#[tokio::test]
async fn integration_reaper_reaps_in_pool_network() {
    let orphan_sid = unique_session_id("cidr-in-pool");
    let container = format!("sandbox-{orphan_sid}");
    let volume = format!("sandbox-home-{orphan_sid}");
    let network = format!("sandbox-net-{orphan_sid}");

    pre_clean_all(&orphan_sid);
    let _cleanup = ResourceCleanup {
        container: container.clone(),
        volume: volume.clone(),
        network: network.clone(),
    };

    // /28 inside the pool. Concrete value chosen so two parallel
    // runs of this test (one from this file, one from the original
    // `integration_orphan_reaper.rs`) don't collide — the
    // `docker-sandbox-namespace` test group serializes the two,
    // but defense-in-depth.
    create_network(&network, "10.209.0.16/28");
    create_volume(&volume);
    create_stopped_container(&container);

    for (kind, name) in [
        ("network", &network),
        ("volume", &volume),
        ("container", &container),
    ] {
        assert!(
            docker_exists(kind, name),
            "precondition: {kind} {name} should exist before reaper runs"
        );
    }

    let pool = Cidr4::parse("10.209.0.0/24").expect("test pool parses");
    let live: HashSet<SessionId> = HashSet::new();
    let _report = reap_orphans(&CliDockerOps, &live, &pool).await;

    assert!(
        !docker_exists("container", &container),
        "in-pool orphan container {container} should have been reaped"
    );
    assert!(
        !docker_exists("volume", &volume),
        "in-pool orphan volume {volume} should have been reaped"
    );
    assert!(
        !docker_exists("network", &network),
        "in-pool orphan network {network} should have been reaped"
    );
}

/// Create an IPv6-only Docker bridge network. The IPv4 IPAM `Config`
/// array is empty; the IPAM probe in the reaper drops IPv6 entries
/// (the M11-S10 gate is IPv4-only), so [`crate::ipam_subnets_in_pool`]
/// receives an empty slice and returns `false` per the fail-closed
/// contract. Docker requires `--ipv4=false` when an IPv6 subnet is
/// the only one configured; without it Docker auto-attaches a
/// default-pool IPv4 subnet that would defeat the test.
fn create_ipv6_only_network(name: &str, subnet: &str) {
    let output = Command::new("docker")
        .args([
            "network",
            "create",
            "--ipv6",
            "--ipv4=false",
            "--subnet",
            subnet,
            name,
        ])
        .output()
        .expect("docker network create should be invokable");
    assert!(
        output.status.success(),
        "docker network create --ipv6 --ipv4=false {name} ({subnet}) failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

/// Fail-closed test: when a `sandbox-net-{12hex}` network has no
/// IPv4 IPAM entries (here, IPv6-only via `--ipv4=false`), the reaper
/// must preserve **all three** session-id-siblings — the network
/// itself, the home volume, and the container — even though the
/// container is attached to Docker's default `bridge` rather than the
/// IPv6-only network. The transitive-ownership rule is what's under
/// test: the IPv4-IPAM-empty network puts its session id in the
/// out-of-pool skip set, and the container/volume passes consult
/// that skip set before partitioning. This is the integration-side
/// equivalent of the unit test
/// `reap_orphans_skips_network_with_empty_ipam_data` in
/// `orphan_reaper.rs::tests` — the unit suite covers the parser and
/// in-pool helper exhaustively (malformed JSON, empty `Config` array,
/// partial overlap); this integration test pins the same fail-closed
/// outcome through a real `docker network inspect` call.
#[tokio::test]
async fn integration_reaper_skips_resources_when_sibling_network_has_no_ipv4_ipam() {
    let orphan_sid = unique_session_id("cidr-no-ipv4-ipam");
    let container = format!("sandbox-{orphan_sid}");
    let volume = format!("sandbox-home-{orphan_sid}");
    let network = format!("sandbox-net-{orphan_sid}");

    pre_clean_all(&orphan_sid);
    let _cleanup = ResourceCleanup {
        container: container.clone(),
        volume: volume.clone(),
        network: network.clone(),
    };

    // IPv6-only — no IPv4 entries in the IPAM `Config` array. The
    // reaper's IPAM probe returns an empty `Vec<Cidr4>`, which
    // `ipam_subnets_in_pool` treats as fail-closed "untrusted".
    create_ipv6_only_network(&network, "fd00::/64");
    create_volume(&volume);
    // Container kept off the IPv6 network — alpine and many bare
    // images don't have IPv6 stacks configured for arbitrary
    // bridges, so attaching the container would fail.
    // `pre_clean_all` ensures no stale stand-alone container exists,
    // and the container attaches to the default `bridge` so it's
    // reachable for the reaper's container-pass. The dual-anchor
    // gate gets to protect it transitively because its session id
    // matches the out-of-pool/missing-IPAM network.
    create_stopped_container(&container);

    for (kind, name) in [
        ("network", &network),
        ("volume", &volume),
        ("container", &container),
    ] {
        assert!(
            docker_exists(kind, name),
            "precondition: {kind} {name} should exist before reaper runs"
        );
    }

    let pool = Cidr4::parse("10.209.0.0/24").expect("test pool parses");
    let live: HashSet<SessionId> = HashSet::new();
    let _report = reap_orphans(&CliDockerOps, &live, &pool).await;

    // Fail-closed: every fixture survives because the network's
    // empty IPv4 IPAM put its session id in the out-of-pool skip set.
    assert!(
        docker_exists("network", &network),
        "IPv4-IPAM-empty network {network} must NOT be reaped (fail-closed)"
    );
    assert!(
        docker_exists("volume", &volume),
        "volume {volume} sharing session id with an IPAM-empty network must NOT be reaped"
    );
    assert!(
        docker_exists("container", &container),
        "container {container} sharing session id with an IPAM-empty network must NOT be reaped"
    );
}
