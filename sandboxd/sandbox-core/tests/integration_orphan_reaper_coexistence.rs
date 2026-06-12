//! Docker coexistence integration tests for the orphan reaper.
//!
//! These tests approximate a two-daemon deployment by running `reap_orphans`
//! twice — once from pool A's perspective and once from pool B's — verifying
//! that each daemon's reaper only touches its own resources and never
//! cross-deletes the other's. A real two-process test would require two
//! running daemon instances and is e2e territory; these tests faithfully
//! simulate the key invariants through a single test process with labelled
//! Docker fixtures.
//!
//! Key behaviors under test:
//!
//! - A neighbour daemon's labelled live resources are never reaped.
//! - A Stopped-session shape (container + volume, no network) is reaped
//!   when the session is orphaned — the owner label proves ownership even
//!   without the network present.
//! - A neighbour daemon's network-less orphan (Stopped session) is NOT reaped
//!   even though its session id is absent from the local live set — the
//!   label difference protects it.
//!
//! The legacy unlabelled fallback path is absent by design: this codebase
//! uses pure owner-label filtering. Unlabelled resources from pre-upgrade
//! daemons would not appear in the filtered listing and are therefore
//! already safe.
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
// Test pools: two daemons with disjoint allocation pools.
// ---------------------------------------------------------------------------

const POOL_A: &str = "10.209.0.0/20";
const POOL_B: &str = "10.220.0.0/20";

fn pool_a() -> Cidr4 {
    Cidr4::parse(POOL_A).expect("pool A parses")
}

fn pool_b() -> Cidr4 {
    Cidr4::parse(POOL_B).expect("pool B parses")
}

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

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

fn create_container(name: &str, pool: &str) {
    let label = format!("sandboxd.owner={pool}");
    let out = Command::new("docker")
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
        .expect("docker create");
    assert!(out.status.success(), "docker create {name} failed");
}

fn create_volume(name: &str, pool: &str) {
    let label = format!("sandboxd.owner={pool}");
    let out = Command::new("docker")
        .args(["volume", "create", "--label", &label, name])
        .output()
        .expect("docker volume create");
    assert!(out.status.success(), "docker volume create {name} failed");
}

fn create_network(name: &str, subnet: &str, pool: &str) {
    let label = format!("sandboxd.owner={pool}");
    let out = Command::new("docker")
        .args([
            "network", "create", "--subnet", subnet, "--label", &label, name,
        ])
        .output()
        .expect("docker network create");
    assert!(
        out.status.success(),
        "docker network create {name} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

fn cleanup(container: &str, volume: &str, network: &str) {
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

fn cleanup_cv(container: &str, volume: &str) {
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
}

struct TripleCleanup {
    container: String,
    volume: String,
    network: String,
}

impl Drop for TripleCleanup {
    fn drop(&mut self) {
        cleanup(&self.container, &self.volume, &self.network);
    }
}

struct PairCleanup {
    container: String,
    volume: String,
}

impl Drop for PairCleanup {
    fn drop(&mut self) {
        cleanup_cv(&self.container, &self.volume);
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// C1: Both pool-A and pool-B resources with live session ids survive both
/// reaper passes. Neither daemon reaps the other's live resources.
#[tokio::test]
async fn integration_reaper_does_not_reap_neighbor_labelled_live_session() {
    let a_sid = unique_session_id("coex-a-live");
    let b_sid = unique_session_id("coex-b-live");

    let a_ctr = format!("sandbox-{a_sid}");
    let a_vol = format!("sandbox-home-{a_sid}");
    let a_net = format!("sandbox-net-{a_sid}");
    let b_ctr = format!("sandbox-{b_sid}");
    let b_vol = format!("sandbox-home-{b_sid}");
    let b_net = format!("sandbox-net-{b_sid}");

    for (c, v, n) in [(&a_ctr, &a_vol, &a_net), (&b_ctr, &b_vol, &b_net)] {
        cleanup(c, v, n);
    }
    let _a = TripleCleanup {
        container: a_ctr.clone(),
        volume: a_vol.clone(),
        network: a_net.clone(),
    };
    let _b = TripleCleanup {
        container: b_ctr.clone(),
        volume: b_vol.clone(),
        network: b_net.clone(),
    };

    create_network(&a_net, "10.209.0.16/28", POOL_A);
    create_volume(&a_vol, POOL_A);
    create_container(&a_ctr, POOL_A);
    create_network(&b_net, "10.220.0.16/28", POOL_B);
    create_volume(&b_vol, POOL_B);
    create_container(&b_ctr, POOL_B);

    // Run pool A's reaper with A's sid in the live set.
    let live_a: HashSet<SessionId> = [a_sid].into_iter().collect();
    reap_orphans(&CliDockerOps, &live_a, &pool_a()).await;

    // Run pool B's reaper with B's sid in the live set.
    let live_b: HashSet<SessionId> = [b_sid].into_iter().collect();
    reap_orphans(&CliDockerOps, &live_b, &pool_b()).await;

    // All resources must survive both passes.
    for (kind, name) in [
        ("container", &a_ctr),
        ("volume", &a_vol),
        ("network", &a_net),
        ("container", &b_ctr),
        ("volume", &b_vol),
        ("network", &b_net),
    ] {
        assert!(
            docker_exists(kind, name),
            "live {kind} {name} must NOT be reaped by either daemon's reaper"
        );
    }
}

/// C2: A pool-A-labelled container + volume with NO network (Stopped-session
/// shape) and an orphaned session id IS reaped by pool A's reaper. The owner
/// label proves ownership without a network — this is the key fix.
#[tokio::test]
async fn integration_reaper_reaps_own_network_less_orphan() {
    let orphan_sid = unique_session_id("coex-a-no-net-orphan");
    let ctr = format!("sandbox-{orphan_sid}");
    let vol = format!("sandbox-home-{orphan_sid}");

    cleanup_cv(&ctr, &vol);
    let _guard = PairCleanup {
        container: ctr.clone(),
        volume: vol.clone(),
    };

    create_volume(&vol, POOL_A);
    create_container(&ctr, POOL_A);
    // No network — simulates a Stopped session that released its network.

    assert!(docker_exists("container", &ctr));
    assert!(docker_exists("volume", &vol));

    let live: HashSet<SessionId> = HashSet::new();
    let report = reap_orphans(&CliDockerOps, &live, &pool_a()).await;

    assert!(
        report.containers_reaped >= 1,
        "pool-A network-less orphan container must be reaped"
    );
    assert!(
        report.volumes_reaped >= 1,
        "pool-A network-less orphan volume must be reaped"
    );
    assert!(!docker_exists("container", &ctr), "container must be gone");
    assert!(!docker_exists("volume", &vol), "volume must be gone");
}

/// C3: A pool-B-labelled container + volume with NO network and an orphaned
/// session id (from B's perspective) is NOT reaped by pool A's reaper.
/// The label difference protects pool B's Stopped sessions from pool A.
#[tokio::test]
async fn integration_reaper_does_not_reap_neighbor_network_less_orphan() {
    let b_sid = unique_session_id("coex-b-no-net-orphan");
    let ctr = format!("sandbox-{b_sid}");
    let vol = format!("sandbox-home-{b_sid}");

    cleanup_cv(&ctr, &vol);
    let _guard = PairCleanup {
        container: ctr.clone(),
        volume: vol.clone(),
    };

    create_volume(&vol, POOL_B);
    create_container(&ctr, POOL_B);
    // No network — pool B's Stopped-session shape.

    assert!(docker_exists("container", &ctr));
    assert!(docker_exists("volume", &vol));

    // Run pool A's reaper. Pool B's resources must be invisible to it.
    let live: HashSet<SessionId> = HashSet::new();
    let report = reap_orphans(&CliDockerOps, &live, &pool_a()).await;

    // Pool A reaped 0 containers/volumes from its own label space.
    // Pool B's resources must still exist.
    assert!(
        docker_exists("container", &ctr),
        "pool-B container {ctr} must NOT be reaped by pool-A reaper"
    );
    assert!(
        docker_exists("volume", &vol),
        "pool-B volume {vol} must NOT be reaped by pool-A reaper"
    );
    let _ = report; // Count may be ≥0 from other fixtures; the key assertion is above.
}
