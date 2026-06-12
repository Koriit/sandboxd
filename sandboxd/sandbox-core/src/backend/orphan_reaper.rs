//! Boot-time orphan cleanup for the lite container backend.
//!
//! On every daemon boot, enumerate Docker resources owned by this daemon
//! (filtered by the `sandboxd.owner=<pool>` label) and prune any that are
//! not referenced by a row in `sessions.db`. The same code path handles
//! crash recovery — a daemon that crashed between `docker create` and the
//! SQLite insert leaves a container with no owning session row, and the next
//! boot reaps it.
//!
//! # Scope
//!
//! Three resource kinds are reconciled, each on its own naming
//! convention:
//!
//! | Resource  | Name shape                | Source of truth            |
//! | --------- | ------------------------- | -------------------------- |
//! | Container | `sandbox-{session_id}`    | `docker ps -a`             |
//! | Volume    | `sandbox-home-{id}`       | `docker volume ls`         |
//! | Network   | `sandbox-net-{id}`        | `docker network ls`        |
//!
//! Names that don't decode to a 12-hex `SessionId` (e.g.
//! `sandbox-gw-{id}` for the gateway container, or anything outside the
//! sandbox namespace) are ignored — the reaper only touches resources it
//! can prove are lite-session siblings. This keeps the gateway-container
//! reconciler (which owns `sandbox-gw-*`) and any operator-created
//! resources outside the sandbox namespace untouched.
//!
//! # Owner-label ownership model (primary coexistence anchor)
//!
//! Every Docker resource created by this daemon carries a
//! `sandboxd.owner=<pool-cidr>` label (e.g. `sandboxd.owner=10.209.0.0/20`).
//! The reaper filters Docker listings by this label so it only sees
//! resources that belong to *this* daemon. A co-deployed daemon with a
//! disjoint pool CIDR has its own distinct label value and its resources
//! are never returned by the filtered listing — no cross-daemon reaping
//! is possible regardless of session-id overlap.
//!
//! This label is the primary ownership anchor: it survives network
//! teardown, so a Stopped session's container and home volume (whose
//! `sandbox-net-{id}` has been released) remain attributable and are
//! correctly protected by the live-set or reaped as orphans. See
//! `docs/concepts/networking.md` for the full coexistence prose.
//!
//! # Delete order
//!
//! Resources are deleted in the order containers → volumes → networks.
//! This ensures the network `rm` never races a still-attached container,
//! avoiding "active endpoints" log noise.
//!
//! # Best-effort, idempotent
//!
//! - Best-effort: a single `docker rm`/`docker volume rm`/`docker
//!   network rm` failure is logged at `warn!` and the rest of the pass
//!   continues. Daemon startup must not abort because Docker is unhappy.
//! - Idempotent: re-running the reaper on a clean state is a no-op (the
//!   live set covers everything; the reap-list is empty).
//! - No daemon-config knob: the reaper runs unconditionally as designed
//!   contract — there is no opt-in/opt-out env var or CLI flag.
//!
//! # Test seam
//!
//! The reaper is parametrised over a [`DockerOps`] trait so unit tests
//! can stub out the docker CLI surface without touching real Docker.
//! The production implementation [`CliDockerOps`] shells out to
//! `docker` exactly like the rest of the container backend.

use std::collections::HashSet;

use async_trait::async_trait;
use tracing::{info, warn};

use crate::error::SandboxError;
use crate::lima::parse_session_id_from_name;
use crate::session::SessionId;
use crate::users_conf::Cidr4;

// ---------------------------------------------------------------------------
// Naming-prefix constants
// ---------------------------------------------------------------------------

/// Prefix shared by every per-session home volume — `sandbox-home-{id}`
const HOME_VOLUME_PREFIX: &str = "sandbox-home-";

/// Prefix shared by every per-session docker network — `sandbox-net-{id}`
const NETWORK_PREFIX: &str = "sandbox-net-";

// ---------------------------------------------------------------------------
// Pure parsing helpers (unit-testable, no Docker)
// ---------------------------------------------------------------------------

/// Try to extract a session id from a lite container name of the form
/// `sandbox-{session_id}`. Returns `None` for any name that does not
/// decode to a valid 12-hex session id — including the gateway
/// container (`sandbox-gw-...`), volume names, network names, and any
/// container outside the sandbox namespace.
///
/// Reuses [`parse_session_id_from_name`] so the lite container, the
/// Lima VM, and the canonical [`crate::backend::RuntimeHandle`] all
/// share the exact same naming check.
pub fn parse_container_session_id(name: &str) -> Option<SessionId> {
    parse_session_id_from_name(name)
}

/// Try to extract a session id from a home-volume name of the form
/// `sandbox-home-{session_id}`.
pub fn parse_home_volume_session_id(name: &str) -> Option<SessionId> {
    name.strip_prefix(HOME_VOLUME_PREFIX)
        .and_then(|s| SessionId::parse(s).ok())
}

/// Try to extract a session id from a docker-network name of the form
/// `sandbox-net-{session_id}`.
pub fn parse_network_session_id(name: &str) -> Option<SessionId> {
    name.strip_prefix(NETWORK_PREFIX)
        .and_then(|s| SessionId::parse(s).ok())
}

/// Pair of `(name, session_id)` lists returned by [`partition_orphans`]:
/// the first holds entries whose session id is in the live set ("keep"),
/// the second holds entries whose session id is absent ("reap"). Aliased
/// so the public signature stays readable and clippy's
/// `type_complexity` lint is satisfied.
pub type OrphanPartition<S> = (Vec<(S, SessionId)>, Vec<(S, SessionId)>);

/// Partition `(name, session_id)` pairs into "live" and "orphan" buckets
/// against the supplied set of live session ids.
///
/// Pure, allocation-light helper. Pulled out of the reaper proper so the
/// classification logic is exercised by hermetic unit tests without
/// touching docker.
pub fn partition_orphans<I, S>(items: I, live: &HashSet<SessionId>) -> OrphanPartition<S>
where
    I: IntoIterator<Item = (S, SessionId)>,
    S: AsRef<str>,
{
    let mut keep = Vec::new();
    let mut reap = Vec::new();
    for (name, sid) in items {
        if live.contains(&sid) {
            keep.push((name, sid));
        } else {
            reap.push((name, sid));
        }
    }
    (keep, reap)
}

// ---------------------------------------------------------------------------
// Docker-ops trait (test seam)
// ---------------------------------------------------------------------------

/// Minimal Docker surface the reaper needs. One method per `docker`
/// invocation; unit tests stub this with an in-memory fake. Production
/// uses [`CliDockerOps`].
#[async_trait]
pub trait DockerOps: Send + Sync {
    /// Enumerate every container in the `sandbox-` namespace owned by the
    /// given pool, including stopped ones.
    ///
    /// Production: `docker ps -a --filter name=sandbox-
    ///   --filter label=sandboxd.owner=<pool> --format '{{.Names}}'`.
    async fn list_owned_containers(&self, pool: &str) -> Result<Vec<String>, SandboxError>;

    /// Enumerate every volume whose name begins with `sandbox-home-` and
    /// that carries `sandboxd.owner=<pool>`.
    ///
    /// Production: `docker volume ls
    ///   --filter name=sandbox-home-
    ///   --filter label=sandboxd.owner=<pool> --format '{{.Name}}'`.
    async fn list_owned_home_volumes(&self, pool: &str) -> Result<Vec<String>, SandboxError>;

    /// Enumerate every docker network whose name begins with `sandbox-net-`
    /// and that carries `sandboxd.owner=<pool>`.
    ///
    /// Production: `docker network ls
    ///   --filter name=sandbox-net-
    ///   --filter label=sandboxd.owner=<pool> --format '{{.Name}}'`.
    async fn list_owned_networks(&self, pool: &str) -> Result<Vec<String>, SandboxError>;

    /// `docker rm -f <name>`. Errors propagate so the caller can decide
    /// whether to log+continue or surface; the reaper logs+continues.
    async fn remove_container(&self, name: &str) -> Result<(), SandboxError>;

    /// `docker volume rm <name>`. Same error contract as
    /// [`Self::remove_container`].
    async fn remove_volume(&self, name: &str) -> Result<(), SandboxError>;

    /// `docker network rm <name>`. Same error contract as
    /// [`Self::remove_container`].
    async fn remove_network(&self, name: &str) -> Result<(), SandboxError>;
}

// ---------------------------------------------------------------------------
// Production CLI implementation
// ---------------------------------------------------------------------------

/// Production [`DockerOps`] impl — shells out to the `docker` CLI via
/// the same `run_docker_raw` plumbing the rest of the container backend
/// uses.
pub struct CliDockerOps;

#[async_trait]
impl DockerOps for CliDockerOps {
    async fn list_owned_containers(&self, pool: &str) -> Result<Vec<String>, SandboxError> {
        let label_filter = format!("label=sandboxd.owner={pool}");
        let stdout = run_docker_raw(
            &[
                "ps",
                "-a",
                "--filter",
                "name=sandbox-",
                "--filter",
                &label_filter,
                "--format",
                "{{.Names}}",
            ],
            "docker ps (orphan reaper)",
        )
        .await?;
        Ok(parse_one_per_line(&stdout))
    }

    async fn list_owned_home_volumes(&self, pool: &str) -> Result<Vec<String>, SandboxError> {
        let label_filter = format!("label=sandboxd.owner={pool}");
        let stdout = run_docker_raw(
            &[
                "volume",
                "ls",
                "--filter",
                "name=sandbox-home-",
                "--filter",
                &label_filter,
                "--format",
                "{{.Name}}",
            ],
            "docker volume ls (orphan reaper)",
        )
        .await?;
        Ok(parse_one_per_line(&stdout))
    }

    async fn list_owned_networks(&self, pool: &str) -> Result<Vec<String>, SandboxError> {
        let label_filter = format!("label=sandboxd.owner={pool}");
        let stdout = run_docker_raw(
            &[
                "network",
                "ls",
                "--filter",
                "name=sandbox-net-",
                "--filter",
                &label_filter,
                "--format",
                "{{.Name}}",
            ],
            "docker network ls (orphan reaper)",
        )
        .await?;
        Ok(parse_one_per_line(&stdout))
    }

    async fn remove_container(&self, name: &str) -> Result<(), SandboxError> {
        // `docker rm -f` against a nonexistent container exits non-zero
        // with "No such container"; treat as success so re-runs after a
        // partial reap don't error.
        match run_docker_raw(&["rm", "-f", name], "docker rm (orphan reaper)").await {
            Ok(_) => Ok(()),
            Err(SandboxError::Gateway(msg)) if msg.contains("No such container") => Ok(()),
            Err(e) => Err(e),
        }
    }

    async fn remove_volume(&self, name: &str) -> Result<(), SandboxError> {
        match run_docker_raw(&["volume", "rm", name], "docker volume rm (orphan reaper)").await {
            Ok(_) => Ok(()),
            Err(SandboxError::Gateway(msg))
                if msg.contains("No such volume") || msg.contains("no such volume") =>
            {
                Ok(())
            }
            Err(e) => Err(e),
        }
    }

    async fn remove_network(&self, name: &str) -> Result<(), SandboxError> {
        match run_docker_raw(
            &["network", "rm", name],
            "docker network rm (orphan reaper)",
        )
        .await
        {
            Ok(_) => Ok(()),
            Err(SandboxError::Gateway(msg))
                if msg.contains("No such network") || msg.contains("network not found") =>
            {
                Ok(())
            }
            Err(e) => Err(e),
        }
    }
}

/// `docker <args>` with the standard 60s wall-clock timeout, returning
/// trimmed stdout on success. Mirrors `container::run_docker` byte-for-
/// byte but kept module-local so the reaper does not depend on
/// `container.rs`'s internals.
async fn run_docker_raw(args: &[&str], operation: &'static str) -> Result<String, SandboxError> {
    use std::time::Duration;

    let owned: Vec<String> = args.iter().map(|s| (*s).to_string()).collect();
    let op = operation.to_string();
    tokio::task::spawn_blocking(move || {
        let mut cmd = std::process::Command::new("docker");
        for arg in &owned {
            cmd.arg(arg);
        }
        let output = crate::process::run_with_timeout(&mut cmd, Duration::from_secs(60), &op)
            .map_err(|e| match e {
                SandboxError::Internal(msg) if msg.contains("failed to spawn") => {
                    SandboxError::Gateway(format!("failed to run {op}: {msg}"))
                }
                other => other,
            })?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
            return Err(SandboxError::Gateway(format!("{op} failed: {stderr}")));
        }
        Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
    })
    .await
    .map_err(|e| SandboxError::Internal(format!("spawn_blocking join failed: {e}")))?
}

/// Split docker's `{{.Names}}` / `{{.Name}}` output (one entry per
/// line) into a list of trimmed, non-empty strings.
fn parse_one_per_line(stdout: &str) -> Vec<String> {
    stdout
        .lines()
        .map(|l| l.trim())
        .filter(|l| !l.is_empty())
        .map(|l| l.to_string())
        .collect()
}

// ---------------------------------------------------------------------------
// Reaper
// ---------------------------------------------------------------------------

/// Tally of resources reaped by a single [`reap_orphans`] pass.
/// Returned to the daemon for the boot-time summary log line; each
/// number counts successful removals only (failed `docker rm` calls are
/// logged at `warn!` and excluded).
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ReaperReport {
    pub containers_reaped: u32,
    pub volumes_reaped: u32,
    pub networks_reaped: u32,
}

/// Enumerate every Docker resource owned by `pool` (via the
/// `sandboxd.owner=<pool>` label) and remove the ones whose derived
/// session id is not in `live`. Best-effort and idempotent — see the
/// module docs.
///
/// Deletion order is containers → volumes → networks so a network `rm`
/// never races a still-attached container.
///
/// `pool` is the canonical CIDR string (`<base>/<prefix>`) that this
/// daemon stamps on every resource it creates. Only resources whose
/// `sandboxd.owner` label matches this exact string are returned by the
/// filtered listing — resources owned by a co-deployed daemon with a
/// different pool are never seen and therefore never touched.
///
/// Failures during enumeration (e.g. Docker daemon unreachable) abort
/// that resource-class only and are logged at `warn!`; the other
/// classes still get their pass. Failures during `docker rm` are
/// logged at `warn!` and skip incrementing the count for that
/// resource.
pub async fn reap_orphans<D: DockerOps + ?Sized>(
    docker: &D,
    live: &HashSet<SessionId>,
    pool: &Cidr4,
) -> ReaperReport {
    let pool_str = format!("{}/{}", pool.base(), pool.prefix_len());
    let mut report = ReaperReport::default();

    // ---- Containers (delete first so networks don't have active endpoints) ----
    let orphan_containers = collect_orphan_containers(docker, &pool_str, live).await;

    for (name, sid) in &orphan_containers {
        match docker.remove_container(name).await {
            Ok(()) => {
                info!(
                    container = %name,
                    session_id = %sid,
                    "orphan reaper: removed container with no owning session"
                );
                report.containers_reaped += 1;
            }
            Err(e) => {
                warn!(
                    container = %name,
                    session_id = %sid,
                    error = %e,
                    "orphan reaper: docker rm failed; continuing"
                );
            }
        }
    }

    // ---- Volumes ----
    match docker.list_owned_home_volumes(&pool_str).await {
        Ok(names) => {
            let classified: Vec<(String, SessionId)> = names
                .into_iter()
                .filter_map(|name| parse_home_volume_session_id(&name).map(|sid| (name, sid)))
                .collect();
            let (_keep, reap) = partition_orphans(classified, live);
            for (name, sid) in reap {
                match docker.remove_volume(&name).await {
                    Ok(()) => {
                        info!(
                            volume = %name,
                            session_id = %sid,
                            "orphan reaper: removed home volume with no owning session"
                        );
                        report.volumes_reaped += 1;
                    }
                    Err(e) => {
                        warn!(
                            volume = %name,
                            session_id = %sid,
                            error = %e,
                            "orphan reaper: docker volume rm failed; continuing"
                        );
                    }
                }
            }
        }
        Err(e) => {
            warn!(
                error = %e,
                "orphan reaper: failed to list sandbox home volumes; skipping volume reap"
            );
        }
    }

    // ---- Networks (delete last to avoid active-endpoint races) ----
    match docker.list_owned_networks(&pool_str).await {
        Ok(names) => {
            let classified: Vec<(String, SessionId)> = names
                .into_iter()
                .filter_map(|name| parse_network_session_id(&name).map(|sid| (name, sid)))
                .collect();
            let (_keep, reap) = partition_orphans(classified, live);
            for (name, sid) in reap {
                match docker.remove_network(&name).await {
                    Ok(()) => {
                        info!(
                            network = %name,
                            session_id = %sid,
                            "orphan reaper: removed network with no owning session"
                        );
                        report.networks_reaped += 1;
                    }
                    Err(e) => {
                        warn!(
                            network = %name,
                            session_id = %sid,
                            error = %e,
                            "orphan reaper: docker network rm failed; continuing"
                        );
                    }
                }
            }
        }
        Err(e) => {
            warn!(
                error = %e,
                "orphan reaper: failed to list sandbox networks; skipping network reap"
            );
        }
    }

    info!(
        containers_reaped = report.containers_reaped,
        volumes_reaped = report.volumes_reaped,
        networks_reaped = report.networks_reaped,
        live_sessions = live.len(),
        "orphan reaper: pass complete"
    );

    report
}

/// Enumerate owned containers and partition into orphans. Extracted
/// so the deletion loop can have its own scope separate from enumeration.
async fn collect_orphan_containers<D: DockerOps + ?Sized>(
    docker: &D,
    pool_str: &str,
    live: &HashSet<SessionId>,
) -> Vec<(String, SessionId)> {
    match docker.list_owned_containers(pool_str).await {
        Ok(names) => {
            let classified: Vec<(String, SessionId)> = names
                .into_iter()
                .filter_map(|name| {
                    // parse_container_session_id rejects gateway containers
                    // (sandbox-gw-*) — their 15-char suffix doesn't parse
                    // as a 12-hex SessionId.
                    parse_container_session_id(&name).map(|sid| (name, sid))
                })
                .collect();
            let (_keep, reap) = partition_orphans(classified, live);
            reap
        }
        Err(e) => {
            warn!(
                error = %e,
                "orphan reaper: failed to list sandbox containers; skipping container reap"
            );
            Vec::new()
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Mutex;

    fn sid(hex: &str) -> SessionId {
        SessionId::parse(hex).expect("valid 12-hex session id")
    }

    /// Default pool string used by [`FakeDocker`] tests.
    const POOL_A: &str = "10.209.0.0/20";
    const POOL_B: &str = "10.220.0.0/20";

    fn pool_a() -> Cidr4 {
        Cidr4::parse(POOL_A).expect("pool A parses")
    }

    /// In-memory [`DockerOps`] fake. Records every removal call so tests
    /// can assert on what the reaper attempted to delete. Resources are
    /// bucketed by owner-label pool string.
    #[derive(Default)]
    struct FakeDocker {
        /// containers[pool] = list of names owned by that pool
        containers: HashMap<String, Vec<String>>,
        /// volumes[pool] = list of names owned by that pool
        volumes: HashMap<String, Vec<String>>,
        /// networks[pool] = list of names owned by that pool
        networks: HashMap<String, Vec<String>>,
        removed_containers: Mutex<Vec<String>>,
        removed_volumes: Mutex<Vec<String>>,
        removed_networks: Mutex<Vec<String>>,
        fail_remove_container: Option<String>,
        fail_list_volumes: bool,
    }

    impl FakeDocker {
        /// Add a container owned by `pool`.
        fn add_container(mut self, pool: &str, name: &str) -> Self {
            self.containers
                .entry(pool.to_string())
                .or_default()
                .push(name.to_string());
            self
        }
        /// Add a volume owned by `pool`.
        fn add_volume(mut self, pool: &str, name: &str) -> Self {
            self.volumes
                .entry(pool.to_string())
                .or_default()
                .push(name.to_string());
            self
        }
        /// Add a network owned by `pool`.
        fn add_network(mut self, pool: &str, name: &str) -> Self {
            self.networks
                .entry(pool.to_string())
                .or_default()
                .push(name.to_string());
            self
        }
    }

    #[async_trait]
    impl DockerOps for FakeDocker {
        async fn list_owned_containers(&self, pool: &str) -> Result<Vec<String>, SandboxError> {
            Ok(self.containers.get(pool).cloned().unwrap_or_default())
        }
        async fn list_owned_home_volumes(&self, pool: &str) -> Result<Vec<String>, SandboxError> {
            if self.fail_list_volumes {
                return Err(SandboxError::Gateway("fake docker volume ls failed".into()));
            }
            Ok(self.volumes.get(pool).cloned().unwrap_or_default())
        }
        async fn list_owned_networks(&self, pool: &str) -> Result<Vec<String>, SandboxError> {
            Ok(self.networks.get(pool).cloned().unwrap_or_default())
        }
        async fn remove_container(&self, name: &str) -> Result<(), SandboxError> {
            if let Some(target) = self.fail_remove_container.as_deref() {
                if name == target {
                    return Err(SandboxError::Gateway(format!(
                        "simulated rm failure: {name}"
                    )));
                }
            }
            self.removed_containers
                .lock()
                .expect("mutex")
                .push(name.to_string());
            Ok(())
        }
        async fn remove_volume(&self, name: &str) -> Result<(), SandboxError> {
            self.removed_volumes
                .lock()
                .expect("mutex")
                .push(name.to_string());
            Ok(())
        }
        async fn remove_network(&self, name: &str) -> Result<(), SandboxError> {
            self.removed_networks
                .lock()
                .expect("mutex")
                .push(name.to_string());
            Ok(())
        }
    }

    // -- Parsers -----------------------------------------------------------

    #[test]
    fn parse_container_session_id_accepts_canonical_name() {
        assert_eq!(
            parse_container_session_id("sandbox-0123456789ab"),
            Some(sid("0123456789ab"))
        );
    }

    #[test]
    fn parse_container_session_id_rejects_gateway_container() {
        // Gateway containers are `sandbox-gw-{id}` — the suffix after
        // `sandbox-` has 15 chars, not 12, so SessionId::parse rejects.
        // The reaper must NOT touch gateway containers.
        assert_eq!(parse_container_session_id("sandbox-gw-0123456789ab"), None);
    }

    #[test]
    fn parse_container_session_id_rejects_volume_and_network_names() {
        assert_eq!(
            parse_container_session_id("sandbox-home-0123456789ab"),
            None
        );
        assert_eq!(parse_container_session_id("sandbox-net-0123456789ab"), None);
    }

    #[test]
    fn parse_container_session_id_rejects_outside_namespace() {
        assert_eq!(parse_container_session_id("my-other-container"), None);
        assert_eq!(parse_container_session_id("sandbox"), None);
        assert_eq!(parse_container_session_id("sandbox-"), None);
        assert_eq!(parse_container_session_id("sandbox-not-hex-here"), None);
        // 11 hex chars (one short of LEN).
        assert_eq!(parse_container_session_id("sandbox-0123456789a"), None);
        // 13 hex chars (one over LEN).
        assert_eq!(parse_container_session_id("sandbox-0123456789abc"), None);
        // Uppercase rejected — SessionId::parse demands lowercase.
        assert_eq!(parse_container_session_id("sandbox-0123456789AB"), None);
    }

    #[test]
    fn parse_home_volume_session_id_accepts_canonical_name() {
        assert_eq!(
            parse_home_volume_session_id("sandbox-home-deadbeef0000"),
            Some(sid("deadbeef0000"))
        );
    }

    #[test]
    fn parse_home_volume_session_id_rejects_other_namespaces() {
        assert_eq!(parse_home_volume_session_id("sandbox-deadbeef0000"), None);
        assert_eq!(
            parse_home_volume_session_id("sandbox-net-deadbeef0000"),
            None
        );
        assert_eq!(parse_home_volume_session_id("home-deadbeef0000"), None);
        assert_eq!(parse_home_volume_session_id("sandbox-home-not-hex"), None);
    }

    #[test]
    fn parse_network_session_id_accepts_canonical_name() {
        assert_eq!(
            parse_network_session_id("sandbox-net-aabbccddeeff"),
            Some(sid("aabbccddeeff"))
        );
    }

    #[test]
    fn parse_network_session_id_rejects_other_namespaces() {
        assert_eq!(parse_network_session_id("sandbox-aabbccddeeff"), None);
        assert_eq!(parse_network_session_id("sandbox-home-aabbccddeeff"), None);
        assert_eq!(parse_network_session_id("sandbox-gw-aabbccddeeff"), None);
        assert_eq!(parse_network_session_id("sandbox-net-XYZ"), None);
    }

    // -- Partitioning ------------------------------------------------------

    #[test]
    fn partition_orphans_splits_correctly() {
        let live: HashSet<SessionId> = [sid("aaaaaaaaaaaa"), sid("bbbbbbbbbbbb")]
            .into_iter()
            .collect();
        let items = vec![
            ("sandbox-aaaaaaaaaaaa".to_string(), sid("aaaaaaaaaaaa")),
            ("sandbox-bbbbbbbbbbbb".to_string(), sid("bbbbbbbbbbbb")),
            ("sandbox-cccccccccccc".to_string(), sid("cccccccccccc")),
            ("sandbox-dddddddddddd".to_string(), sid("dddddddddddd")),
        ];
        let (keep, reap) = partition_orphans(items, &live);
        assert_eq!(keep.len(), 2);
        assert_eq!(reap.len(), 2);
        let reap_ids: HashSet<SessionId> = reap.iter().map(|(_, s)| *s).collect();
        assert!(reap_ids.contains(&sid("cccccccccccc")));
        assert!(reap_ids.contains(&sid("dddddddddddd")));
    }

    #[test]
    fn partition_orphans_clean_state_is_no_op() {
        let live: HashSet<SessionId> = [sid("aaaaaaaaaaaa")].into_iter().collect();
        let items = vec![("sandbox-aaaaaaaaaaaa", sid("aaaaaaaaaaaa"))];
        let (keep, reap) = partition_orphans(items, &live);
        assert_eq!(keep.len(), 1);
        assert!(reap.is_empty());
    }

    #[test]
    fn partition_orphans_empty_live_set_reaps_everything() {
        let live: HashSet<SessionId> = HashSet::new();
        let items = vec![
            ("sandbox-aaaaaaaaaaaa", sid("aaaaaaaaaaaa")),
            ("sandbox-bbbbbbbbbbbb", sid("bbbbbbbbbbbb")),
        ];
        let (keep, reap) = partition_orphans(items, &live);
        assert!(keep.is_empty());
        assert_eq!(reap.len(), 2);
    }

    // -- Reaper end-to-end with owner-label filter -------------------------

    #[tokio::test]
    async fn reap_orphans_removes_resources_with_no_live_session() {
        let live_sid = sid("aaaaaaaaaaaa");
        let orphan_sid = sid("bbbbbbbbbbbb");
        let fake = FakeDocker::default()
            .add_container(POOL_A, &format!("sandbox-{live_sid}"))
            .add_container(POOL_A, &format!("sandbox-{orphan_sid}"))
            // Gateway container — must NOT be reaped (name parsing rejects it).
            .add_container(POOL_A, &format!("sandbox-gw-{live_sid}"))
            .add_volume(POOL_A, &format!("sandbox-home-{live_sid}"))
            .add_volume(POOL_A, &format!("sandbox-home-{orphan_sid}"))
            .add_network(POOL_A, &format!("sandbox-net-{live_sid}"))
            .add_network(POOL_A, &format!("sandbox-net-{orphan_sid}"));

        let live: HashSet<SessionId> = [live_sid].into_iter().collect();
        let report = reap_orphans(&fake, &live, &pool_a()).await;

        assert_eq!(report.containers_reaped, 1);
        assert_eq!(report.volumes_reaped, 1);
        assert_eq!(report.networks_reaped, 1);

        let removed_containers = fake.removed_containers.lock().expect("mutex").clone();
        assert_eq!(removed_containers, vec![format!("sandbox-{orphan_sid}")]);

        let removed_volumes = fake.removed_volumes.lock().expect("mutex").clone();
        assert_eq!(removed_volumes, vec![format!("sandbox-home-{orphan_sid}")]);

        let removed_networks = fake.removed_networks.lock().expect("mutex").clone();
        assert_eq!(removed_networks, vec![format!("sandbox-net-{orphan_sid}")]);
    }

    #[tokio::test]
    async fn reap_orphans_clean_state_is_no_op() {
        let live_sid = sid("aaaaaaaaaaaa");
        let fake = FakeDocker::default()
            .add_container(POOL_A, &format!("sandbox-{live_sid}"))
            .add_volume(POOL_A, &format!("sandbox-home-{live_sid}"))
            .add_network(POOL_A, &format!("sandbox-net-{live_sid}"));

        let live: HashSet<SessionId> = [live_sid].into_iter().collect();
        let report = reap_orphans(&fake, &live, &pool_a()).await;

        assert_eq!(report, ReaperReport::default());
        assert!(fake.removed_containers.lock().expect("mutex").is_empty());
        assert!(fake.removed_volumes.lock().expect("mutex").is_empty());
        assert!(fake.removed_networks.lock().expect("mutex").is_empty());
    }

    #[tokio::test]
    async fn reap_orphans_empty_inputs_is_a_noop() {
        let fake = FakeDocker::default();
        let live: HashSet<SessionId> = HashSet::new();
        let report = reap_orphans(&fake, &live, &pool_a()).await;
        assert_eq!(report, ReaperReport::default());
    }

    #[tokio::test]
    async fn reap_orphans_skips_unparseable_names() {
        // Every container name listed is *not* a lite session container
        // — gateway, namespace-foreign, and non-hex suffix entries
        // should all be ignored, leaving the report empty.
        let fake = FakeDocker::default()
            .add_container(POOL_A, "sandbox-gw-aaaaaaaaaaaa")
            .add_container(POOL_A, "sandbox-not-hex-here")
            .add_container(POOL_A, "totally-unrelated")
            .add_volume(POOL_A, "sandbox-home-not-hex")
            .add_volume(POOL_A, "sandbox-other-volume")
            .add_network(POOL_A, "sandbox-net-not-hex")
            .add_network(POOL_A, "bridge");

        let live: HashSet<SessionId> = HashSet::new();
        let report = reap_orphans(&fake, &live, &pool_a()).await;
        assert_eq!(report, ReaperReport::default());
    }

    #[tokio::test]
    async fn reap_orphans_continues_on_individual_remove_failure() {
        let orphan_a = sid("aaaaaaaaaaaa");
        let orphan_b = sid("bbbbbbbbbbbb");
        let mut fake = FakeDocker::default()
            .add_container(POOL_A, &format!("sandbox-{orphan_a}"))
            .add_container(POOL_A, &format!("sandbox-{orphan_b}"));
        fake.fail_remove_container = Some(format!("sandbox-{orphan_a}"));

        let live: HashSet<SessionId> = HashSet::new();
        let report = reap_orphans(&fake, &live, &pool_a()).await;
        // Only one of the two reaps succeeded.
        assert_eq!(report.containers_reaped, 1);
        let removed = fake.removed_containers.lock().expect("mutex").clone();
        assert_eq!(removed, vec![format!("sandbox-{orphan_b}")]);
    }

    #[tokio::test]
    async fn reap_orphans_continues_on_list_failure_for_one_class() {
        let orphan = sid("aaaaaaaaaaaa");
        let mut fake = FakeDocker::default()
            .add_container(POOL_A, &format!("sandbox-{orphan}"))
            .add_network(POOL_A, &format!("sandbox-net-{orphan}"));
        // Volume list fails — must not abort the container or network passes.
        fake.fail_list_volumes = true;

        let live: HashSet<SessionId> = HashSet::new();
        let report = reap_orphans(&fake, &live, &pool_a()).await;
        assert_eq!(report.containers_reaped, 1);
        assert_eq!(report.volumes_reaped, 0);
        assert_eq!(report.networks_reaped, 1);
    }

    #[tokio::test]
    async fn reap_orphans_does_not_touch_neighbor_daemon_resources() {
        // Resources owned by pool B must NOT be reaped when pool A runs its reaper.
        let orphan_a = sid("aaaaaaaaaaaa");
        let orphan_b = sid("bbbbbbbbbbbb");
        let fake = FakeDocker::default()
            // Pool A: orphan (should be reaped)
            .add_container(POOL_A, &format!("sandbox-{orphan_a}"))
            .add_volume(POOL_A, &format!("sandbox-home-{orphan_a}"))
            .add_network(POOL_A, &format!("sandbox-net-{orphan_a}"))
            // Pool B: orphan (must NOT be reaped by A's reaper)
            .add_container(POOL_B, &format!("sandbox-{orphan_b}"))
            .add_volume(POOL_B, &format!("sandbox-home-{orphan_b}"))
            .add_network(POOL_B, &format!("sandbox-net-{orphan_b}"));

        let live: HashSet<SessionId> = HashSet::new();
        let report = reap_orphans(&fake, &live, &pool_a()).await;

        // Only pool A resources were reaped.
        assert_eq!(report.containers_reaped, 1);
        assert_eq!(report.volumes_reaped, 1);
        assert_eq!(report.networks_reaped, 1);

        let removed_containers = fake.removed_containers.lock().expect("mutex").clone();
        assert!(!removed_containers.contains(&format!("sandbox-{orphan_b}")));

        let removed_volumes = fake.removed_volumes.lock().expect("mutex").clone();
        assert!(!removed_volumes.contains(&format!("sandbox-home-{orphan_b}")));

        let removed_networks = fake.removed_networks.lock().expect("mutex").clone();
        assert!(!removed_networks.contains(&format!("sandbox-net-{orphan_b}")));
    }

    #[tokio::test]
    async fn reap_orphans_reaps_network_less_orphan_with_label() {
        // A Stopped session: container + volume present, network gone.
        // With the owner label, these are still provably ours and reapable.
        let orphan_sid = sid("cccccccccccc");
        let fake = FakeDocker::default()
            .add_container(POOL_A, &format!("sandbox-{orphan_sid}"))
            .add_volume(POOL_A, &format!("sandbox-home-{orphan_sid}"));
        // No network entry — the network was already released.

        let live: HashSet<SessionId> = HashSet::new();
        let report = reap_orphans(&fake, &live, &pool_a()).await;

        assert_eq!(report.containers_reaped, 1);
        assert_eq!(report.volumes_reaped, 1);
        assert_eq!(report.networks_reaped, 0);
    }

    // -- run_docker_raw stdout parser -------------------------------------

    #[test]
    fn parse_one_per_line_strips_blanks_and_whitespace() {
        let stdout = "sandbox-aaaaaaaaaaaa\n\nsandbox-bbbbbbbbbbbb\n  sandbox-cccccccccccc  \n";
        assert_eq!(
            parse_one_per_line(stdout),
            vec![
                "sandbox-aaaaaaaaaaaa".to_string(),
                "sandbox-bbbbbbbbbbbb".to_string(),
                "sandbox-cccccccccccc".to_string(),
            ]
        );
    }

    #[test]
    fn parse_one_per_line_empty_input_is_empty_vec() {
        assert!(parse_one_per_line("").is_empty());
        assert!(parse_one_per_line("\n\n   \n").is_empty());
    }
}
