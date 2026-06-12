//! Owner-label coexistence integration tests for the orphan reaper.
//!
//! These tests verify that the reaper's `sandboxd.owner=<pool>` label filter
//! correctly isolates two simulated daemons running with disjoint pool CIDRs.
//! A resource owned by pool B must never be reaped when pool A's reaper runs,
//! even if the resource name would otherwise match the `sandbox-*` prefix.
//!
//! This file replaces the former IPAM dual-anchor tests (which tested
//! `docker network inspect` IPAM-based ownership). The owner label is now the
//! sole ownership anchor; the IPAM helpers are retained in the unit-test suite
//! as parser coverage only.
//!
//! Naming follows the workspace convention: tests are prefixed `integration_*`
//! so the `integration` nextest profile selects them and the default profile
//! filters them out.

use std::collections::HashSet;
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

use sandbox_core::Cidr4;
use sandbox_core::backend::{CliDockerOps, reap_orphans};
use sandbox_core::session::SessionId;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const POOL_A: &str = "10.209.0.0/24";
const POOL_B: &str = "192.168.99.0/24";

fn pool_a() -> Cidr4 {
    Cidr4::parse(POOL_A).expect("pool A parses")
}

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

fn pre_clean_all(sid: &SessionId) {
    pre_clean(
        &format!("sandbox-{sid}"),
        &format!("sandbox-home-{sid}"),
        &format!("sandbox-net-{sid}"),
    );
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

fn create_stopped_container(name: &str, pool: &str) {
    let label = format!("sandboxd.owner={pool}");
    let output = Command::new("docker")
        .args([
            "create",
            "--name",
            name,
            "--label",
            &label,
            "--entrypoint",
            "true",
            "alpine:latest",
        ])
        .output()
        .expect("docker create should be invokable");
    assert!(
        output.status.success(),
        "docker create --name {name} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn create_volume(name: &str, pool: &str) {
    let label = format!("sandboxd.owner={pool}");
    let output = Command::new("docker")
        .args(["volume", "create", "--label", &label, name])
        .output()
        .expect("docker volume create should be invokable");
    assert!(
        output.status.success(),
        "docker volume create {name} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn create_network(name: &str, subnet: &str, pool: &str) {
    let label = format!("sandboxd.owner={pool}");
    let output = Command::new("docker")
        .args([
            "network", "create", "--subnet", subnet, "--label", &label, name,
        ])
        .output()
        .expect("docker network create should be invokable");
    assert!(
        output.status.success(),
        "docker network create {name} ({subnet}) failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

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
// Tests
// ---------------------------------------------------------------------------

/// A resource labelled `sandboxd.owner=POOL_B` must NOT be touched when
/// pool A's reaper runs. This exercises the primary coexistence guarantee:
/// label-filtered enumeration means a co-deployed daemon's resources are
/// invisible to the other's reaper.
#[tokio::test]
async fn integration_reaper_skips_neighbor_labelled_resources() {
    let b_sid = unique_session_id("b-labelled");
    let container = format!("sandbox-{b_sid}");
    let volume = format!("sandbox-home-{b_sid}");
    let network = format!("sandbox-net-{b_sid}");

    pre_clean_all(&b_sid);
    let _cleanup = ResourceCleanup {
        container: container.clone(),
        volume: volume.clone(),
        network: network.clone(),
    };

    // Pool B owns these resources.
    create_network(&network, "10.209.0.16/28", POOL_B);
    create_volume(&volume, POOL_B);
    create_stopped_container(&container, POOL_B);

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

    // Run pool A's reaper — it must not see pool B's resources.
    let live: HashSet<SessionId> = HashSet::new();
    let _report = reap_orphans(&CliDockerOps, &live, &pool_a()).await;

    // All pool B resources must survive intact.
    assert!(
        docker_exists("network", &network),
        "pool-B-owned network {network} must NOT be reaped by pool-A reaper"
    );
    assert!(
        docker_exists("container", &container),
        "pool-B-owned container {container} must NOT be reaped by pool-A reaper"
    );
    assert!(
        docker_exists("volume", &volume),
        "pool-B-owned volume {volume} must NOT be reaped by pool-A reaper"
    );
}

/// A resource labelled `sandboxd.owner=POOL_A` with an orphaned session id
/// IS reaped when pool A's reaper runs, even if the session has no associated
/// Docker network (Stopped-session shape: network released, container+volume
/// survive).
struct ContainerVolumeCleanup {
    container: String,
    volume: String,
}

impl Drop for ContainerVolumeCleanup {
    fn drop(&mut self) {
        let _ = Command::new("docker")
            .args(["rm", "-f", &self.container])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
        let _ = Command::new("docker")
            .args(["volume", "rm", &self.volume])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
}

#[tokio::test]
async fn integration_reaper_reaps_own_labelled_orphan_without_network() {
    let orphan_sid = unique_session_id("a-orphan-no-net");
    let container = format!("sandbox-{orphan_sid}");
    let volume = format!("sandbox-home-{orphan_sid}");

    // Pre-clean any leftovers.
    let _ = Command::new("docker")
        .args(["rm", "-f", &container])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    let _ = Command::new("docker")
        .args(["volume", "rm", &volume])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();

    let _cleanup = ContainerVolumeCleanup {
        container: container.clone(),
        volume: volume.clone(),
    };

    create_volume(&volume, POOL_A);
    create_stopped_container(&container, POOL_A);
    // Intentionally no network — simulates a Stopped session.

    assert!(docker_exists("container", &container));
    assert!(docker_exists("volume", &volume));

    let live: HashSet<SessionId> = HashSet::new();
    let report = reap_orphans(&CliDockerOps, &live, &pool_a()).await;

    assert!(
        report.containers_reaped >= 1,
        "orphan container {container} should have been reaped"
    );
    assert!(
        report.volumes_reaped >= 1,
        "orphan volume {volume} should have been reaped"
    );
    assert!(
        !docker_exists("container", &container),
        "orphan container {container} should be gone after reaper"
    );
    assert!(
        !docker_exists("volume", &volume),
        "orphan volume {volume} should be gone after reaper"
    );
}

/// An in-pool `sandbox-net-{12hex}` network with a matching pool-A label
/// and an orphaned session id must be reaped, along with its container and
/// home volume.
#[tokio::test]
async fn integration_reaper_reaps_in_pool_labelled_network() {
    let orphan_sid = unique_session_id("a-labelled-in-pool");
    let container = format!("sandbox-{orphan_sid}");
    let volume = format!("sandbox-home-{orphan_sid}");
    let network = format!("sandbox-net-{orphan_sid}");

    pre_clean_all(&orphan_sid);
    let _cleanup = ResourceCleanup {
        container: container.clone(),
        volume: volume.clone(),
        network: network.clone(),
    };

    create_network(&network, "10.209.0.16/28", POOL_A);
    create_volume(&volume, POOL_A);
    create_stopped_container(&container, POOL_A);

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

    let live: HashSet<SessionId> = HashSet::new();
    let _report = reap_orphans(&CliDockerOps, &live, &pool_a()).await;

    assert!(
        !docker_exists("container", &container),
        "pool-A orphan container {container} should have been reaped"
    );
    assert!(
        !docker_exists("volume", &volume),
        "pool-A orphan volume {volume} should have been reaped"
    );
    assert!(
        !docker_exists("network", &network),
        "pool-A orphan network {network} should have been reaped"
    );
}
