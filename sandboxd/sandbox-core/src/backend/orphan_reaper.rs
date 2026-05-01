//! Boot-time orphan cleanup for the lite container backend.
//!
//! Spec § "Orphan cleanup on daemon start" (lite-mode container backend
//! design): on every daemon boot, enumerate Docker resources living in
//! the `sandbox-` namespace and prune any that are not referenced by a
//! row in `sessions.db`. Same code path handles crash recovery — a
//! daemon that crashed between `docker create` and the SQLite insert
//! leaves a container with no owning session row, and the next boot
//! reaps it.
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
//! # Dual-anchor ownership model
//!
//! The name-prefix check above is the **first** ownership anchor:
//! "name says sandboxd's." On a host running a single sandboxd that is
//! sufficient. On a host running two sandboxds — prod + dev test, two
//! parallel test runs, a dev build colliding with a stale prod prefix —
//! it is not, because every sandboxd uses the same `sandbox-`,
//! `sandbox-home-`, and `sandbox-net-` prefixes. Without a second
//! anchor, each daemon's reaper would mass-delete the other's
//! resources.
//!
//! The **second** anchor is the daemon's `NetworkManager` allocator
//! pool CIDR (resolved from `users.conf` at startup, default
//! `10.209.0.0/24`). Networks whose IPAM-reported IPv4 subnets lie
//! outside the pool are skipped — "name says sandboxd's, CIDR says
//! **this** sandboxd's." Containers and home volumes are owned
//! by-network transitively: a container or volume attached to an
//! out-of-pool network is left alone because the network itself is
//! left alone.
//!
//! The CIDR check is fail-closed: networks with no IPAM data,
//! malformed inspect output, or any IPv4 subnet outside the pool are
//! skipped. The inverse — reaping on partial in-pool overlap — would
//! be a footgun: a network with one in-pool /28 and one out-of-pool
//! /28 must not be torn down, because the out-of-pool half is by
//! definition not ours. See [`DockerOps::inspect_network_ipam`] for
//! the IPAM probe surface and `docs/concepts/networking.md`
//! § "The naming scheme" for the prose-side dual-anchor description.
//!
//! Scope limitation: the dual-anchor protects siblings of out-of-pool
//! networks **observed during the network pass**. A container or volume
//! whose `sandbox-net-{sid}` has already been torn down on the host
//! falls through to single-anchor (name-prefix) protection only — the
//! second anchor cannot reach a network that no longer exists at probe
//! time. Acceptable in practice because the 12-hex session id makes
//! cross-daemon collisions vanishingly rare; revisit if a multi-daemon
//! deployment runbook (deferred from S10) lands.
//!
//! # Best-effort, idempotent
//!
//! - Best-effort: a single `docker rm`/`docker volume rm`/`docker
//!   network rm` failure is logged at `warn!` and the rest of the pass
//!   continues. Daemon startup must not abort because Docker is unhappy.
//! - Idempotent: re-running the reaper on a clean state is a no-op (the
//!   live set covers everything; the reap-list is empty).
//! - No daemon-config knob: the reaper runs unconditionally per spec
//!   contract — there is no opt-in/opt-out env var or CLI flag.
//!
//! # Test seam
//!
//! The reaper is parametrised over a [`DockerOps`] trait so unit tests
//! can stub out the docker CLI surface without touching real Docker.
//! The production implementation [`CliDockerOps`] shells out to
//! `docker` exactly like the rest of the container backend.

use std::collections::HashSet;
use std::net::Ipv4Addr;

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
/// (spec § "Per-session home volume").
const HOME_VOLUME_PREFIX: &str = "sandbox-home-";

/// Prefix shared by every per-session docker network — `sandbox-net-{id}`
/// (spec § "Per-session network").
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
    /// Enumerate every container in the `sandbox-` namespace, including
    /// stopped ones (`docker ps -a --filter name=sandbox- --format '{{.Names}}'`).
    async fn list_sandbox_containers(&self) -> Result<Vec<String>, SandboxError>;

    /// Enumerate every volume whose name begins with `sandbox-home-`
    /// (`docker volume ls --filter name=sandbox-home- --format '{{.Name}}'`).
    async fn list_sandbox_home_volumes(&self) -> Result<Vec<String>, SandboxError>;

    /// Enumerate every docker network whose name begins with
    /// `sandbox-net-` (`docker network ls --filter name=sandbox-net- --format '{{.Name}}'`).
    async fn list_sandbox_networks(&self) -> Result<Vec<String>, SandboxError>;

    /// `docker rm -f <name>`. Errors propagate so the caller can decide
    /// whether to log+continue or surface; the reaper logs+continues.
    async fn remove_container(&self, name: &str) -> Result<(), SandboxError>;

    /// `docker volume rm <name>`. Same error contract as
    /// [`Self::remove_container`].
    async fn remove_volume(&self, name: &str) -> Result<(), SandboxError>;

    /// `docker network rm <name>`. Same error contract as
    /// [`Self::remove_container`].
    async fn remove_network(&self, name: &str) -> Result<(), SandboxError>;

    /// IPAM probe for the dual-anchor CIDR gate (M11-S10). Returns
    /// every IPv4 subnet (`a.b.c.d/n`) Docker reports for the named
    /// network's IPAM configuration. Implementations shell out to
    /// `docker network inspect <name> --format '{{json .IPAM}}'` and
    /// parse the resulting JSON.
    ///
    /// Fail-closed contract:
    /// - `Ok(vec![])` — Docker returned IPAM data with no IPv4
    ///   subnets (or only IPv6 entries we don't gate on). The
    ///   reaper treats an empty list as "no in-pool subnets" and
    ///   skips the network.
    /// - `Err(_)` — inspect failed or the JSON did not parse. The
    ///   reaper logs at `warn!` and skips the network.
    ///
    /// In both fail-closed paths, the network is **not reaped**. The
    /// inverse (reaping on missing/partial data) would mass-delete a
    /// neighboring sandboxd's resources whenever its `docker network
    /// inspect` happens to be transiently slow or returns an
    /// unexpected shape.
    async fn inspect_network_ipam(&self, name: &str) -> Result<Vec<Cidr4>, SandboxError>;
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
    async fn list_sandbox_containers(&self) -> Result<Vec<String>, SandboxError> {
        // `--filter name=sandbox-` matches any container whose name
        // *contains* the substring (docker's filter is a substring
        // match, not a prefix anchor). `parse_container_session_id`
        // re-anchors the prefix and validates the 12-hex tail, so any
        // false positives (e.g. an operator-created `my-sandbox-foo`)
        // fall through harmlessly.
        let stdout = run_docker_raw(
            &[
                "ps",
                "-a",
                "--filter",
                "name=sandbox-",
                "--format",
                "{{.Names}}",
            ],
            "docker ps (orphan reaper)",
        )
        .await?;
        Ok(parse_one_per_line(&stdout))
    }

    async fn list_sandbox_home_volumes(&self) -> Result<Vec<String>, SandboxError> {
        let stdout = run_docker_raw(
            &[
                "volume",
                "ls",
                "--filter",
                "name=sandbox-home-",
                "--format",
                "{{.Name}}",
            ],
            "docker volume ls (orphan reaper)",
        )
        .await?;
        Ok(parse_one_per_line(&stdout))
    }

    async fn list_sandbox_networks(&self) -> Result<Vec<String>, SandboxError> {
        let stdout = run_docker_raw(
            &[
                "network",
                "ls",
                "--filter",
                "name=sandbox-net-",
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

    async fn inspect_network_ipam(&self, name: &str) -> Result<Vec<Cidr4>, SandboxError> {
        // `--format '{{json .IPAM}}'` returns a single JSON object
        // (the IPAM block) per network, e.g.
        //   {"Driver":"default","Options":{},"Config":[{"Subnet":"10.209.0.16/28"}]}
        // We extract every IPv4 `Subnet` from `Config[]` and skip
        // entries whose subnet is IPv6 (`fd00::/64` etc.) — the M11-S10
        // gate is IPv4-only by design (see module docs).
        let stdout = run_docker_raw(
            &["network", "inspect", name, "--format", "{{json .IPAM}}"],
            "docker network inspect (orphan reaper IPAM probe)",
        )
        .await?;
        parse_ipam_subnets(&stdout)
    }
}

/// Parse the JSON output of `docker network inspect <name> --format
/// '{{json .IPAM}}'` and extract every IPv4 subnet. Pulled out so unit
/// tests can pin the JSON-shape contract without touching Docker.
///
/// Returns:
/// - `Ok(vec![cidr, ...])` — the IPv4 subnets the inspector reported
///   under `Config[].Subnet`. IPv6 entries are silently dropped (the
///   gate is IPv4-only by design); see the module-level dual-anchor
///   description.
/// - `Ok(vec![])` — IPAM block had no `Config` array, or every entry
///   was missing/IPv6/non-CIDR. The reaper treats this as fail-closed
///   "untrusted, not ours" per the [`DockerOps::inspect_network_ipam`]
///   contract.
/// - `Err(SandboxError::Gateway)` — JSON failed to parse. Same
///   fail-closed treatment downstream.
fn parse_ipam_subnets(stdout: &str) -> Result<Vec<Cidr4>, SandboxError> {
    let trimmed = stdout.trim();
    if trimmed.is_empty() {
        return Ok(Vec::new());
    }
    let value: serde_json::Value = serde_json::from_str(trimmed).map_err(|e| {
        SandboxError::Gateway(format!(
            "docker network inspect IPAM JSON parse failed: {e}"
        ))
    })?;
    let mut out = Vec::new();
    if let Some(configs) = value.get("Config").and_then(|c| c.as_array()) {
        for entry in configs {
            let Some(subnet_str) = entry.get("Subnet").and_then(|s| s.as_str()) else {
                continue;
            };
            // Skip IPv6 — `Cidr4::parse` rejects them with "invalid
            // IPv4 address", but matching the colon character first is
            // cheaper than driving through the parser's error path
            // for every dual-stack network.
            if subnet_str.contains(':') {
                continue;
            }
            match Cidr4::parse(subnet_str) {
                Ok(c) => out.push(c),
                Err(reason) => {
                    warn!(
                        subnet = %subnet_str,
                        reason = %reason,
                        "orphan reaper: skipping malformed IPv4 subnet in IPAM output"
                    );
                }
            }
        }
    }
    Ok(out)
}

/// True iff the network's IPAM block is fully contained in the
/// daemon's allocator pool — every reported IPv4 subnet's base address
/// **and** broadcast address fall inside `pool`. Both endpoints must
/// be in-pool because a /28 that straddles the pool boundary would
/// have its base in-pool and its broadcast out-of-pool, and the
/// network as a whole is half-out-of-pool.
///
/// Fail-closed: an empty `subnets` slice returns `false`. The reaper
/// must not reap a network whose IPAM is empty or unparseable; see the
/// module docs.
fn ipam_subnets_in_pool(subnets: &[Cidr4], pool: &Cidr4) -> bool {
    if subnets.is_empty() {
        return false;
    }
    subnets.iter().all(|net| {
        let base_u32 = u32::from(net.base());
        let host_bits = 32u32 - u32::from(net.prefix_len());
        let last_u32 = if host_bits == 32 {
            // /0 — only the global default route, which can never be
            // an allocator pool anyway. Treat as out-of-pool.
            return false;
        } else {
            // `saturating_add` is defensive: `Cidr4::parse` rejects
            // bases with host bits set, so for any well-formed `Cidr4`
            // the addition cannot overflow. Kept for readability and to
            // avoid surprising future readers who reach this expression
            // without the parser invariant in mind.
            base_u32.saturating_add((1u32 << host_bits) - 1)
        };
        pool.contains(net.base()) && pool.contains(Ipv4Addr::from(last_u32))
    })
}

/// `docker <args>` with the standard 60s wall-clock timeout, returning
/// trimmed stdout on success. Mirrors `container::run_docker` byte-for-
/// byte but kept module-local so the reaper does not depend on
/// `container.rs`'s internals; the spec calls this a sibling concern,
/// not an extension of the per-session lifecycle.
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
/// line) into a list of trimmed, non-empty strings. The trailing
/// newline is stripped by [`run_docker_raw`] but defensive `trim` here
/// keeps the helper independent.
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

/// Enumerate every `sandbox-*` Docker resource and remove the ones
/// whose derived session id is not in `live`. Best-effort and
/// idempotent — see the module docs.
///
/// Failures during enumeration (e.g. Docker daemon unreachable) abort
/// that resource-class only and are logged at `warn!`; the other
/// classes still get their pass. Failures during `docker rm` are
/// logged at `warn!` and skip incrementing the count for that
/// resource.
///
/// `pool` is the daemon's `NetworkManager` allocator pool — the second
/// of the two ownership anchors documented in the module-level
/// "Dual-anchor ownership model" section. Networks whose IPAM-reported
/// IPv4 subnets are not fully in-pool are skipped; their attached
/// containers and home volumes are skipped transitively (the reaper
/// rebuilds the live-by-network sets from `docker network inspect` so
/// out-of-pool resources never enter the partition step).
pub async fn reap_orphans<D: DockerOps + ?Sized>(
    docker: &D,
    live: &HashSet<SessionId>,
    pool: &Cidr4,
) -> ReaperReport {
    let mut report = ReaperReport::default();

    // ---- Networks ----
    //
    // Run the network pass first so the dual-anchor CIDR gate can
    // populate `out_of_pool_sids` — the set of session ids whose
    // `sandbox-net-{id}` network was filtered out by the IPAM check.
    // The container and volume passes below skip those session ids
    // transitively: a container/volume that shares a session id with
    // an out-of-pool network is "not ours" by the same anchor.
    let mut out_of_pool_sids: HashSet<SessionId> = HashSet::new();
    match docker.list_sandbox_networks().await {
        Ok(names) => {
            let mut classified: Vec<(String, SessionId)> = Vec::new();
            for name in names {
                if let Some(sid) = parse_network_session_id(&name) {
                    classified.push((name, sid));
                }
            }
            let (_keep, reap) = partition_orphans(classified, live);
            for (name, sid) in reap {
                // Dual-anchor (M11-S10): the name says sandboxd's;
                // before reaping, confirm the IPAM-reported subnets
                // also say *this* sandboxd's (i.e. fully inside the
                // allocator pool). Anything else — out-of-pool, no
                // IPAM data, malformed inspect output — is skipped
                // fail-closed and its session id is recorded so the
                // container and volume passes don't reap its
                // siblings.
                let in_pool = match docker.inspect_network_ipam(&name).await {
                    Ok(subnets) => ipam_subnets_in_pool(&subnets, pool),
                    Err(e) => {
                        warn!(
                            network = %name,
                            session_id = %sid,
                            error = %e,
                            "orphan reaper: docker network inspect IPAM failed; \
                             skipping network (fail-closed)"
                        );
                        false
                    }
                };
                if !in_pool {
                    info!(
                        network = %name,
                        session_id = %sid,
                        pool_base = %pool.base(),
                        pool_prefix = pool.prefix_len(),
                        "orphan reaper: network IPAM not in allocator pool; \
                         skipping network and its session-id siblings"
                    );
                    out_of_pool_sids.insert(sid);
                    continue;
                }
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

    // ---- Containers ----
    match docker.list_sandbox_containers().await {
        Ok(names) => {
            let mut classified: Vec<(String, SessionId)> = Vec::new();
            for name in names {
                if let Some(sid) = parse_container_session_id(&name) {
                    // Skip containers whose session id has an
                    // out-of-pool sibling network — see the network
                    // pass above for the transitive-ownership rule.
                    if out_of_pool_sids.contains(&sid) {
                        info!(
                            container = %name,
                            session_id = %sid,
                            "orphan reaper: skipping container — sibling \
                             network is out-of-pool"
                        );
                        continue;
                    }
                    classified.push((name, sid));
                }
                // Names that don't parse (e.g. `sandbox-gw-*` gateway
                // containers, or `sandbox-net-*` etc. coincidentally
                // matched by the substring filter) are silently
                // skipped — they aren't lite session containers.
            }
            let (_keep, reap) = partition_orphans(classified, live);
            for (name, sid) in reap {
                match docker.remove_container(&name).await {
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
        }
        Err(e) => {
            warn!(
                error = %e,
                "orphan reaper: failed to list sandbox containers; skipping container reap"
            );
        }
    }

    // ---- Volumes ----
    match docker.list_sandbox_home_volumes().await {
        Ok(names) => {
            let mut classified: Vec<(String, SessionId)> = Vec::new();
            for name in names {
                if let Some(sid) = parse_home_volume_session_id(&name) {
                    if out_of_pool_sids.contains(&sid) {
                        info!(
                            volume = %name,
                            session_id = %sid,
                            "orphan reaper: skipping home volume — sibling \
                             network is out-of-pool"
                        );
                        continue;
                    }
                    classified.push((name, sid));
                }
            }
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

    info!(
        containers_reaped = report.containers_reaped,
        volumes_reaped = report.volumes_reaped,
        networks_reaped = report.networks_reaped,
        live_sessions = live.len(),
        "orphan reaper: pass complete"
    );

    report
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

    /// Permissive pool used by tests that pre-date the M11-S10
    /// dual-anchor gate. `0.0.0.0/0` matches every IPv4 subnet, so the
    /// pre-S10 reaper-end-to-end tests below see the same behavior they
    /// did before the second anchor landed.
    fn permissive_pool() -> Cidr4 {
        Cidr4::parse("0.0.0.0/0").expect("0.0.0.0/0 parses")
    }

    /// Default in-pool subnet for `FakeDocker` networks: a /28 inside
    /// the permissive pool. Tests that care about CIDR specifics (the
    /// new M11-S10 unit tests below) override per network via
    /// `FakeDocker::network_ipam`.
    fn default_in_pool_subnet() -> Cidr4 {
        Cidr4::parse("10.209.0.0/28").expect("10.209.0.0/28 parses")
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
        // Plain container name is not a home volume.
        assert_eq!(parse_home_volume_session_id("sandbox-deadbeef0000"), None);
        // Network name is not a home volume.
        assert_eq!(
            parse_home_volume_session_id("sandbox-net-deadbeef0000"),
            None
        );
        // Wrong prefix.
        assert_eq!(parse_home_volume_session_id("home-deadbeef0000"), None);
        // Bad suffix.
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

    // -- Reaper end-to-end with a fake DockerOps --------------------------

    /// IPAM-probe outcome modeled by [`FakeDocker`]. `Subnets` mirrors
    /// the real `inspect_network_ipam` return shape; `InspectErr`
    /// exercises the fail-closed branch where Docker returns a
    /// non-zero exit (network missing, daemon unreachable, etc.).
    enum FakeIpam {
        Subnets(Vec<Cidr4>),
        InspectErr,
    }

    /// In-memory [`DockerOps`] fake. Records every removal call so tests
    /// can assert on what the reaper attempted to delete.
    #[derive(Default)]
    struct FakeDocker {
        containers: Vec<String>,
        volumes: Vec<String>,
        networks: Vec<String>,
        removed_containers: Mutex<Vec<String>>,
        removed_volumes: Mutex<Vec<String>>,
        removed_networks: Mutex<Vec<String>>,
        // When set, the corresponding remove_* call returns Err to
        // exercise the best-effort path.
        fail_remove_container: Option<String>,
        fail_list_volumes: bool,
        // M11-S10 dual-anchor: per-network IPAM probe outcome. Networks
        // not in the map default to a single `default_in_pool_subnet()`
        // /28 so pre-S10 tests keep their existing semantics under the
        // permissive pool.
        network_ipam: HashMap<String, FakeIpam>,
    }

    #[async_trait]
    impl DockerOps for FakeDocker {
        async fn list_sandbox_containers(&self) -> Result<Vec<String>, SandboxError> {
            Ok(self.containers.clone())
        }
        async fn list_sandbox_home_volumes(&self) -> Result<Vec<String>, SandboxError> {
            if self.fail_list_volumes {
                Err(SandboxError::Gateway("fake docker volume ls failed".into()))
            } else {
                Ok(self.volumes.clone())
            }
        }
        async fn list_sandbox_networks(&self) -> Result<Vec<String>, SandboxError> {
            Ok(self.networks.clone())
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
        async fn inspect_network_ipam(&self, name: &str) -> Result<Vec<Cidr4>, SandboxError> {
            match self.network_ipam.get(name) {
                Some(FakeIpam::Subnets(s)) => Ok(s.clone()),
                Some(FakeIpam::InspectErr) => Err(SandboxError::Gateway(format!(
                    "fake docker network inspect IPAM failed for {name}"
                ))),
                // No fixture entry: return a single in-pool /28 so
                // pre-S10 tests continue to pass under the permissive
                // pool.
                None => Ok(vec![default_in_pool_subnet()]),
            }
        }
    }

    #[tokio::test]
    async fn reap_orphans_removes_resources_with_no_live_session() {
        let live_sid = sid("aaaaaaaaaaaa");
        let orphan_sid = sid("bbbbbbbbbbbb");
        let fake = FakeDocker {
            containers: vec![
                format!("sandbox-{live_sid}"),
                format!("sandbox-{orphan_sid}"),
                // Gateway container — must NOT be reaped.
                format!("sandbox-gw-{live_sid}"),
                // Outside namespace — must NOT be reaped.
                "totally-unrelated-container".to_string(),
            ],
            volumes: vec![
                format!("sandbox-home-{live_sid}"),
                format!("sandbox-home-{orphan_sid}"),
            ],
            networks: vec![
                format!("sandbox-net-{live_sid}"),
                format!("sandbox-net-{orphan_sid}"),
            ],
            ..Default::default()
        };
        let live: HashSet<SessionId> = [live_sid].into_iter().collect();
        let report = reap_orphans(&fake, &live, &permissive_pool()).await;

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
        let fake = FakeDocker {
            containers: vec![format!("sandbox-{live_sid}")],
            volumes: vec![format!("sandbox-home-{live_sid}")],
            networks: vec![format!("sandbox-net-{live_sid}")],
            ..Default::default()
        };
        let live: HashSet<SessionId> = [live_sid].into_iter().collect();
        let report = reap_orphans(&fake, &live, &permissive_pool()).await;

        assert_eq!(report, ReaperReport::default());
        assert!(fake.removed_containers.lock().expect("mutex").is_empty());
        assert!(fake.removed_volumes.lock().expect("mutex").is_empty());
        assert!(fake.removed_networks.lock().expect("mutex").is_empty());
    }

    #[tokio::test]
    async fn reap_orphans_empty_inputs_is_a_noop() {
        let fake = FakeDocker::default();
        let live: HashSet<SessionId> = HashSet::new();
        let report = reap_orphans(&fake, &live, &permissive_pool()).await;
        assert_eq!(report, ReaperReport::default());
    }

    #[tokio::test]
    async fn reap_orphans_skips_unparseable_names() {
        // Every container name listed is *not* a lite session container
        // — gateway, namespace-foreign, and non-hex suffix entries
        // should all be ignored, leaving the report empty.
        let fake = FakeDocker {
            containers: vec![
                "sandbox-gw-aaaaaaaaaaaa".to_string(),
                "sandbox-not-hex-here".to_string(),
                "totally-unrelated".to_string(),
            ],
            volumes: vec![
                "sandbox-home-not-hex".to_string(),
                "sandbox-other-volume".to_string(),
            ],
            networks: vec!["sandbox-net-not-hex".to_string(), "bridge".to_string()],
            ..Default::default()
        };
        let live: HashSet<SessionId> = HashSet::new();
        let report = reap_orphans(&fake, &live, &permissive_pool()).await;
        assert_eq!(report, ReaperReport::default());
    }

    #[tokio::test]
    async fn reap_orphans_continues_on_individual_remove_failure() {
        let orphan_a = sid("aaaaaaaaaaaa");
        let orphan_b = sid("bbbbbbbbbbbb");
        let fake = FakeDocker {
            containers: vec![format!("sandbox-{orphan_a}"), format!("sandbox-{orphan_b}")],
            // Make the *first* removal fail; the reaper must still
            // attempt — and succeed on — the second.
            fail_remove_container: Some(format!("sandbox-{orphan_a}")),
            ..Default::default()
        };
        let live: HashSet<SessionId> = HashSet::new();
        let report = reap_orphans(&fake, &live, &permissive_pool()).await;
        // Only one of the two reaps succeeded.
        assert_eq!(report.containers_reaped, 1);
        let removed = fake.removed_containers.lock().expect("mutex").clone();
        assert_eq!(removed, vec![format!("sandbox-{orphan_b}")]);
    }

    #[tokio::test]
    async fn reap_orphans_continues_on_list_failure_for_one_class() {
        let orphan = sid("aaaaaaaaaaaa");
        let fake = FakeDocker {
            // Containers list works.
            containers: vec![format!("sandbox-{orphan}")],
            // Volume list fails — must not abort the container or
            // network passes.
            fail_list_volumes: true,
            networks: vec![format!("sandbox-net-{orphan}")],
            ..Default::default()
        };
        let live: HashSet<SessionId> = HashSet::new();
        let report = reap_orphans(&fake, &live, &permissive_pool()).await;
        assert_eq!(report.containers_reaped, 1);
        assert_eq!(report.volumes_reaped, 0);
        assert_eq!(report.networks_reaped, 1);
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

    // -- M11-S10 dual-anchor IPAM helpers ----------------------------------

    #[test]
    fn parse_ipam_subnets_extracts_ipv4_subnets() {
        // Shape mirrors the real `docker network inspect --format '{{json .IPAM}}'`
        // output for a single-subnet bridge network.
        let stdout = r#"{"Driver":"default","Options":{},"Config":[{"Subnet":"10.209.0.16/28","Gateway":"10.209.0.17"}]}"#;
        let subnets = parse_ipam_subnets(stdout).expect("parse ok");
        assert_eq!(subnets.len(), 1);
        assert_eq!(subnets[0].base().to_string(), "10.209.0.16");
        assert_eq!(subnets[0].prefix_len(), 28);
    }

    #[test]
    fn parse_ipam_subnets_drops_ipv6_entries() {
        // Dual-stack network — the gate is IPv4-only by design.
        let stdout =
            r#"{"Driver":"default","Config":[{"Subnet":"10.209.0.32/28"},{"Subnet":"fd00::/64"}]}"#;
        let subnets = parse_ipam_subnets(stdout).expect("parse ok");
        assert_eq!(subnets.len(), 1);
        assert_eq!(subnets[0].base().to_string(), "10.209.0.32");
    }

    #[test]
    fn parse_ipam_subnets_empty_config_returns_empty_vec() {
        // No `Config` array at all — fail-closed input.
        let stdout = r#"{"Driver":"default","Options":{}}"#;
        let subnets = parse_ipam_subnets(stdout).expect("parse ok");
        assert!(subnets.is_empty());
    }

    #[test]
    fn parse_ipam_subnets_ipv6_only_config_returns_empty_vec() {
        // IPv6-only Config — every entry is dropped by the IPv4 filter,
        // so the parser returns an empty `Vec<Cidr4>` and the gate
        // upstream then fails closed. The `integration_reaper_skips_
        // network_with_missing_ipam` integration test exercises the
        // same path through real Docker; this hermetic test pins the
        // parser contract directly.
        let stdout = r#"{"Driver":"default","Config":[{"Subnet":"fd00::/64"}]}"#;
        let subnets = parse_ipam_subnets(stdout).expect("parse ok");
        assert!(
            subnets.is_empty(),
            "IPv6-only Config must yield empty IPv4 subnet list (fail-closed end-to-end)"
        );
    }

    #[test]
    fn parse_ipam_subnets_empty_input_returns_empty_vec() {
        assert!(parse_ipam_subnets("").expect("parse ok").is_empty());
    }

    #[test]
    fn parse_ipam_subnets_malformed_json_errors() {
        let stdout = "not json {";
        assert!(parse_ipam_subnets(stdout).is_err());
    }

    #[test]
    fn ipam_subnets_in_pool_empty_subnets_is_fail_closed() {
        let pool = Cidr4::parse("10.209.0.0/24").expect("parse");
        assert!(!ipam_subnets_in_pool(&[], &pool));
    }

    #[test]
    fn ipam_subnets_in_pool_single_subnet_inside_pool() {
        let pool = Cidr4::parse("10.209.0.0/24").expect("parse");
        let net = Cidr4::parse("10.209.0.16/28").expect("parse");
        assert!(ipam_subnets_in_pool(&[net], &pool));
    }

    #[test]
    fn ipam_subnets_in_pool_single_subnet_outside_pool() {
        let pool = Cidr4::parse("10.209.0.0/24").expect("parse");
        let net = Cidr4::parse("192.168.99.0/24").expect("parse");
        assert!(!ipam_subnets_in_pool(&[net], &pool));
    }

    #[test]
    fn ipam_subnets_in_pool_partial_overlap_is_fail_closed() {
        // `/24` straddles the `/28` pool boundary — base in-pool but
        // broadcast out. Reaping a half-out-of-pool network would be a
        // footgun (see module docs).
        let pool = Cidr4::parse("10.209.0.0/28").expect("parse");
        let net = Cidr4::parse("10.209.0.0/24").expect("parse");
        assert!(!ipam_subnets_in_pool(&[net], &pool));
    }

    #[test]
    fn ipam_subnets_in_pool_all_or_nothing_across_multi_subnet_network() {
        let pool = Cidr4::parse("10.209.0.0/20").expect("parse");
        let in_pool_a = Cidr4::parse("10.209.0.0/28").expect("parse");
        let in_pool_b = Cidr4::parse("10.209.1.0/28").expect("parse");
        let out_of_pool = Cidr4::parse("192.168.99.0/28").expect("parse");

        // All inside → in-pool.
        assert!(ipam_subnets_in_pool(&[in_pool_a, in_pool_b], &pool));
        // Any outside → not in-pool (fail-closed against partial trust).
        assert!(!ipam_subnets_in_pool(&[in_pool_a, out_of_pool], &pool));
    }

    // -- M11-S10 dual-anchor reaper-end-to-end ----------------------------

    #[tokio::test]
    async fn reap_orphans_skips_network_with_out_of_pool_ipam() {
        let orphan_sid = sid("bbbbbbbbbbbb");
        let pool = Cidr4::parse("10.209.0.0/24").expect("parse");
        let mut ipam = HashMap::new();
        ipam.insert(
            format!("sandbox-net-{orphan_sid}"),
            // A second sandboxd's network — same prefix, different
            // CIDR pool. Must NOT be reaped.
            FakeIpam::Subnets(vec![Cidr4::parse("192.168.99.0/28").expect("parse")]),
        );
        let fake = FakeDocker {
            containers: vec![format!("sandbox-{orphan_sid}")],
            volumes: vec![format!("sandbox-home-{orphan_sid}")],
            networks: vec![format!("sandbox-net-{orphan_sid}")],
            network_ipam: ipam,
            ..Default::default()
        };
        let live: HashSet<SessionId> = HashSet::new();
        let report = reap_orphans(&fake, &live, &pool).await;

        assert_eq!(report, ReaperReport::default());
        // Transitive ownership: container and volume sharing the
        // out-of-pool network's session id must also be left intact.
        assert!(fake.removed_containers.lock().expect("mutex").is_empty());
        assert!(fake.removed_volumes.lock().expect("mutex").is_empty());
        assert!(fake.removed_networks.lock().expect("mutex").is_empty());
    }

    #[tokio::test]
    async fn reap_orphans_reaps_network_with_in_pool_ipam() {
        let orphan_sid = sid("bbbbbbbbbbbb");
        let pool = Cidr4::parse("10.209.0.0/24").expect("parse");
        let mut ipam = HashMap::new();
        ipam.insert(
            format!("sandbox-net-{orphan_sid}"),
            FakeIpam::Subnets(vec![Cidr4::parse("10.209.0.16/28").expect("parse")]),
        );
        let fake = FakeDocker {
            containers: vec![format!("sandbox-{orphan_sid}")],
            volumes: vec![format!("sandbox-home-{orphan_sid}")],
            networks: vec![format!("sandbox-net-{orphan_sid}")],
            network_ipam: ipam,
            ..Default::default()
        };
        let live: HashSet<SessionId> = HashSet::new();
        let report = reap_orphans(&fake, &live, &pool).await;
        assert_eq!(report.containers_reaped, 1);
        assert_eq!(report.volumes_reaped, 1);
        assert_eq!(report.networks_reaped, 1);
    }

    #[tokio::test]
    async fn reap_orphans_skips_network_when_inspect_errors() {
        // Fail-closed on inspect errors — the network is left alone
        // (and its container/volume siblings too) so a transient
        // Docker hiccup does not mass-delete a neighbor's resources.
        let orphan_sid = sid("bbbbbbbbbbbb");
        let pool = Cidr4::parse("10.209.0.0/24").expect("parse");
        let mut ipam = HashMap::new();
        ipam.insert(format!("sandbox-net-{orphan_sid}"), FakeIpam::InspectErr);
        let fake = FakeDocker {
            containers: vec![format!("sandbox-{orphan_sid}")],
            volumes: vec![format!("sandbox-home-{orphan_sid}")],
            networks: vec![format!("sandbox-net-{orphan_sid}")],
            network_ipam: ipam,
            ..Default::default()
        };
        let live: HashSet<SessionId> = HashSet::new();
        let report = reap_orphans(&fake, &live, &pool).await;
        assert_eq!(report, ReaperReport::default());
        assert!(fake.removed_containers.lock().expect("mutex").is_empty());
        assert!(fake.removed_volumes.lock().expect("mutex").is_empty());
        assert!(fake.removed_networks.lock().expect("mutex").is_empty());
    }

    #[tokio::test]
    async fn reap_orphans_skips_network_with_empty_ipam_data() {
        // Inspect succeeds but reports no IPv4 subnets (e.g. an
        // operator-created IPv6-only network coincidentally named
        // `sandbox-net-{12hex}`). Fail-closed.
        let orphan_sid = sid("bbbbbbbbbbbb");
        let pool = Cidr4::parse("10.209.0.0/24").expect("parse");
        let mut ipam = HashMap::new();
        ipam.insert(
            format!("sandbox-net-{orphan_sid}"),
            FakeIpam::Subnets(vec![]),
        );
        let fake = FakeDocker {
            containers: vec![format!("sandbox-{orphan_sid}")],
            volumes: vec![format!("sandbox-home-{orphan_sid}")],
            networks: vec![format!("sandbox-net-{orphan_sid}")],
            network_ipam: ipam,
            ..Default::default()
        };
        let live: HashSet<SessionId> = HashSet::new();
        let report = reap_orphans(&fake, &live, &pool).await;
        assert_eq!(report, ReaperReport::default());
    }
}
