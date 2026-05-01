use std::fs;
use std::path::Path;
use std::process::Command;
use std::thread;
use std::time::{Duration, Instant};

use tracing::{debug, info, warn};

use crate::atomic_listener_writer::{
    AtomicListenerWriter, session_listener_host_dir, session_listener_host_path,
};
use crate::error::SandboxError;
use crate::events::{EVENTS_DIR_IN_CONTAINER, session_events_host_dir};
use crate::network::NetworkInfo;
use crate::policy::{LISTENER_DIR_IN_CONTAINER, PolicyCompiler};
use crate::process::run_with_timeout;
use crate::session::SessionId;

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// Health status of a gateway container.
#[derive(Debug, Clone, PartialEq)]
pub enum GatewayStatus {
    /// All components (Envoy, CoreDNS, mitmproxy) are healthy AND
    /// Envoy currently has at least one active LDS-served listener
    /// (`listener_manager.total_listeners_active >= 1`).
    Healthy,
    /// All container processes are healthy (the in-container
    /// `/healthcheck.sh` script returned 0), but Envoy has no active
    /// listener yet (`listener_manager.total_listeners_active == 0`).
    ///
    /// This is the expected verdict during the boot window between
    /// `create_gateway` returning and the first
    /// `PolicyDistributor::distribute` call landing — the deny-all
    /// bootstrap listener (empty `filter_chains`) is rejected by
    /// Envoy at runtime, so no listener is active until policy is
    /// applied. It is also the verdict if a policy-compiled listener
    /// is rejected by LDS at apply time (an on-the-wire regression
    /// that pre-#52 was masked as `Healthy`).
    ///
    /// Recovery code paths (`gateway_monitor`, network reconciliation)
    /// treat `Starting` as non-actionable — like `Healthy`, it does
    /// not trigger a restart. The visibility this carries is for
    /// external observers (CLI list, `/sessions/{id}/health`) and
    /// future policy-distributor diagnostics.
    Starting,
    /// At least one component reported unhealthy.
    Unhealthy(String),
    /// The container is not running (or does not exist).
    NotRunning,
}

/// Docker's native per-container health verdict, as surfaced by
/// `docker inspect --format '{{.State.Health.Status}}' <container>`.
///
/// This is the verdict Docker itself maintains by invoking the container's
/// `HEALTHCHECK` directive on a cadence (interval / timeout / retries /
/// start-period) — for the gateway image that directive runs
/// `/healthcheck.sh`, which Phase 4 extended to include the deny-logger
/// probe. Reading this value is strictly cheaper than re-running the
/// healthcheck ourselves: Docker has already run it, applied the
/// retry/debounce window, and cached the verdict.
///
/// `gateway_monitor` uses this enum as a first-pass signal — an
/// `Unhealthy` verdict here means Docker has already observed `retries`
/// consecutive failures and is the canonical "container unhealthy"
/// signal the spec calls for: Docker marks the container unhealthy,
/// sandboxd's gateway health polling observes this, and the gateway
/// container is restarted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DockerHealth {
    /// Within the HEALTHCHECK `start-period` — Docker has not yet
    /// produced a verdict. Callers should keep waiting rather than
    /// interpreting this as failure.
    Starting,
    /// Docker's last HEALTHCHECK invocation succeeded.
    Healthy,
    /// Docker has seen `retries` consecutive HEALTHCHECK failures and
    /// has flipped the container to unhealthy. This is the signal
    /// `gateway_monitor` acts on to trigger a restart.
    Unhealthy,
    /// The container has no HEALTHCHECK configured, so Docker has no
    /// opinion. Callers should fall back to their own probe (e.g.
    /// `gateway_status`). The gateway image *does* configure a
    /// HEALTHCHECK, so seeing this on a running gateway is unusual and
    /// worth falling back on rather than treating as a verdict.
    None,
    /// The container does not exist, is not running, or `docker
    /// inspect` failed in a way we cannot attribute to a specific
    /// health state. Treat as "don't act on this" and fall back to
    /// `gateway_status`, which has its own "not running" handling.
    Unknown,
}

impl DockerHealth {
    /// Parse the raw stdout of
    /// `docker inspect --format '{{.State.Health.Status}}' <container>`.
    ///
    /// Docker emits one of `starting`, `healthy`, `unhealthy`, or
    /// `<no value>` (when no HEALTHCHECK is configured) followed by a
    /// newline. Older / edge cases may emit an empty string. Anything
    /// we do not recognise maps to [`DockerHealth::Unknown`] so the
    /// caller falls back to its own probe rather than acting on a
    /// verdict we cannot interpret.
    pub fn parse(raw: &str) -> Self {
        match raw.trim() {
            "starting" => DockerHealth::Starting,
            "healthy" => DockerHealth::Healthy,
            "unhealthy" => DockerHealth::Unhealthy,
            // `docker inspect` emits the literal string "<no value>"
            // when the template field is missing (no HEALTHCHECK).
            // Some Docker versions also just emit "none".
            "none" | "<no value>" => DockerHealth::None,
            "" => DockerHealth::Unknown,
            _ => DockerHealth::Unknown,
        }
    }
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Docker image name for the gateway container.
pub const GATEWAY_IMAGE: &str = "sandbox-gateway";

/// Maximum time to wait for individual component readiness.
const COMPONENT_READY_TIMEOUT: Duration = Duration::from_secs(45);

/// Interval between component readiness polls.
const COMPONENT_POLL_INTERVAL: Duration = Duration::from_secs(1);

/// Timeout for `docker run` when starting the gateway container.
const DOCKER_RUN_TIMEOUT: Duration = Duration::from_secs(60);

/// Timeout for `docker stop` when stopping the gateway container.
const DOCKER_STOP_TIMEOUT: Duration = Duration::from_secs(30);

/// Timeout for `docker rm` when removing the gateway container.
const DOCKER_RM_TIMEOUT: Duration = Duration::from_secs(15);

/// Timeout for `docker inspect` when checking gateway status.
const DOCKER_INSPECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Timeout for `docker inspect` when retrieving the container IP.
const CONTAINER_IP_TIMEOUT: Duration = Duration::from_secs(10);

/// Timeout for `docker exec nft` when injecting nftables rulesets.
const NFT_EXEC_TIMEOUT: Duration = Duration::from_secs(15);

// ---------------------------------------------------------------------------
// Gateway listener ports
// ---------------------------------------------------------------------------
//
// These are the destination ports DNAT'd VM traffic terminates on inside the
// gateway container. They are centralised here because `gateway::…` ruleset
// generators, `policy::compile_nftables`, and `dns_propagation::
// generate_domain_ip_rules` all need to agree on the numeric values; having a
// single source of truth prevents drift when ports are reshuffled (as happens
// every time the deny-logger / mitmproxy / Envoy surface is renegotiated).

/// DNS port handled by CoreDNS inside the gateway container.
pub const GATEWAY_DNS_PORT: u16 = 53;

/// TCP port handled by Envoy's `original_dst` listener inside the gateway
/// container. All VM TCP traffic that matches a policy `allow` rule is DNAT'd
/// to this port.
pub const GATEWAY_ENVOY_PORT: u16 = 10000;

/// TCP port handled by the deny-logger inside the gateway container. VM TCP
/// connections to destinations *not* matched by a policy `allow` rule are
/// DNAT'd here; the deny-logger reads `SO_ORIGINAL_DST`, emits a structured
/// `deny` event, and closes the socket with RST.
///
/// See spec `.tasks/specs/2026-04-21-port-explicit-policies-presets-observability-design.md`
/// Part 3 § "Listener design".
pub const GATEWAY_DENY_LOGGER_TCP_PORT: u16 = 10001;

/// NFLOG group the kernel emits dropped-UDP packets on. Denied UDP
/// no longer DNATs to a userland listener; the prerouting chain
/// matches unmatched UDP with
/// `meta l4proto udp log group {NFT_NFLOG_DENY_GROUP}; meta l4proto udp drop`,
/// and the kernel mirrors each dropped packet to NFNLGRP_NFLOG with the
/// pre-rewrite IPv4+UDP headers in `NFULA_PAYLOAD`. The
/// `sandbox-nft-deny-logger` binary subscribes to this group and
/// emits the JSONL deny event directly from the headers — no userland
/// datapath, no DNAT, no conntrack lookup.
///
/// `1` is the lowest available unused group on the host; `0` is left
/// free as a conventional "unset/system-reserved" sentinel. The value
/// is currently hard-coded; if it ever needs to be tunable the
/// `--nflog-group` flag in `sandbox-nft-deny-logger`'s CLI is the
/// downstream knob.
pub const NFT_NFLOG_DENY_GROUP: u16 = 1;

/// TCP port exposing the deny-logger's `/health` endpoint inside the gateway
/// container. **Not** in any DNAT set — reached only from inside the container
/// via `docker exec`-driven healthchecks and sandboxd's `component_health`
/// probe.
pub const GATEWAY_DENY_LOGGER_HEALTH_PORT: u16 = 10003;

/// Name of the nftables concat set (inside both `sandbox_dnat` and
/// `sandbox_policy`) that holds `(ipv4_addr . inet_service)` allow tuples
/// for TCP destinations.
pub const NFT_POLICY_ALLOW_TCP_SET: &str = "policy_allow_tcp";

/// Name of the nftables concat set (inside both `sandbox_dnat` and
/// `sandbox_policy`) that holds `(ipv4_addr . inet_service)` allow tuples
/// for UDP destinations.
pub const NFT_POLICY_ALLOW_UDP_SET: &str = "policy_allow_udp";

// ---------------------------------------------------------------------------
// GatewayManager
// ---------------------------------------------------------------------------

/// Manages per-session gateway containers and their nftables rules.
///
/// Each sandbox session gets its own gateway container running Envoy, CoreDNS,
/// and mitmproxy. The gateway sits on the session's Docker bridge network and
/// intercepts all VM traffic via nftables DNAT rules.
///
/// nftables rules are injected into the container via `docker exec`. The
/// container is granted `CAP_NET_ADMIN` and includes the `nft` binary so it
/// can manage its own nftables rules without requiring host-level privileges.
pub struct GatewayManager;

impl GatewayManager {
    /// Create a new `GatewayManager`.
    pub fn new() -> Self {
        Self
    }

    // -- Container lifecycle ---------------------------------------------------

    /// Create and start the gateway container on the session's Docker network.
    ///
    /// After starting the container, this method:
    /// 1. Writes the initial DNS policy file (if provided) so CoreDNS
    ///    loads it on first startup, avoiding a race with the reload timer
    /// 2. Immediately injects deny-all nftables rules
    /// 3. Waits for all components (Envoy, CoreDNS, mitmproxy) to be ready
    /// 4. Injects DNAT rules to route traffic through the gateway
    ///
    /// This ordering ensures no traffic can flow until all components are ready
    /// and the full nftables ruleset is in place.
    ///
    /// The `initial_dns_policy` parameter, when `Some`, is written to the
    /// gateway's `/etc/coredns/policy.conf` immediately after the container
    /// starts but before CoreDNS initialises.  This ensures the very first
    /// `LoadFile` call inside CoreDNS sees the intended policy, eliminating
    /// the window where CoreDNS would serve NXDOMAIN for all queries while
    /// waiting for its reload timer to detect the file change.
    pub fn create_gateway(
        &self,
        session_id: &SessionId,
        network_info: &NetworkInfo,
        ca_dir: Option<&Path>,
        initial_dns_policy: Option<&str>,
    ) -> Result<(), SandboxError> {
        let container_name = container_name(session_id);

        info!(
            session_id = %session_id,
            container = %container_name,
            network = %network_info.docker_network_name,
            gateway_ip = %network_info.gateway_ip,
            ca_dir = ?ca_dir,
            "creating gateway container"
        );

        // Pre-cleanup: remove any leftover container with the same name.
        //
        // When a session is stopped, the gateway container is normally removed
        // by `stop_gateway`. However, if that removal failed (e.g. daemon
        // crash, Docker transient error) or the session was force-killed, a
        // stopped container may still exist. `docker run` would then fail with
        // "container name is already in use". We defensively remove it here.
        //
        // `docker rm -f` handles both running and stopped containers and
        // exits with an error only when the container does not exist, which
        // we intentionally ignore.
        let rm_output = run_with_timeout(
            Command::new("docker").args(["rm", "--force", &container_name]),
            DOCKER_RM_TIMEOUT,
            "docker rm (pre-cleanup)",
        );
        match rm_output {
            Ok(output) if output.status.success() => {
                info!(
                    session_id = %session_id,
                    container = %container_name,
                    "removed leftover gateway container before recreation"
                );
            }
            _ => {
                // Container did not exist or docker rm failed — either way,
                // proceed to create a fresh one.
            }
        }

        // Pre-setup: ensure the per-session listener host directory exists
        // and seed it with the initial LDS listener file before `docker run`.
        //
        // Envoy's filesystem LDS watches a directory for `MovedTo` inotify
        // events (upstream `#20474`). Sandboxd bind-mounts this host dir
        // into the container as [`LISTENER_DIR_IN_CONTAINER`] — when
        // sandboxd atomically replaces the listener file via host-side
        // `fs::rename`, the rename produces a `MovedTo` event visible to
        // Envoy's watcher inside the container.
        //
        // The initial listener file is a deny-all listener (no filter
        // chains) written now so Envoy has something valid to load on
        // first boot. PolicyDistributor rewrites it later when the
        // session policy is applied.
        //
        // The gateway container used to ship with `envoy-base.yaml`
        // baked in, which installed an L1 pass-through listener on
        // first boot. The bootstrap is now policy-agnostic and the
        // day-one listener is served via LDS — so the initial
        // listener must itself be deliverable via LDS, and the simplest
        // fail-closed default is deny-all. For sessions started without
        // a policy, this means the Envoy listener is deny-all rather
        // than L1 pass-through; net user-visible behaviour is unchanged
        // because the nftables layer (`sandbox_policy`) gates traffic
        // first and is also empty on a no-policy session, and DNS is
        // deny-by-default. Policy-driven L3 filter chains replace this
        // default once a policy is applied. See
        // `PolicyCompiler::compile_initial_envoy_listener` for the
        // full rationale.
        let listener_host_dir = session_listener_host_dir(session_id);
        // Best-effort cleanup of any leftover dir from a crashed previous
        // session with the same ID (extremely unlikely given UUIDs, but
        // cheap to handle).
        let _ = fs::remove_dir_all(&listener_host_dir);
        fs::create_dir_all(&listener_host_dir).map_err(|e| {
            SandboxError::Gateway(format!(
                "failed to create listener host dir {}: {e}",
                listener_host_dir.display()
            ))
        })?;

        let listener_host_path = session_listener_host_path(session_id);
        let initial_listener = PolicyCompiler::compile_initial_envoy_listener();
        AtomicListenerWriter::new(&listener_host_path)
            .write(&initial_listener)
            .map_err(|e| {
                SandboxError::Gateway(format!(
                    "failed to write initial Envoy listener at {}: {e}",
                    listener_host_path.display()
                ))
            })?;

        debug!(
            session_id = %session_id,
            listener_host_dir = %listener_host_dir.display(),
            "initial Envoy listener file written; bind-mounting into container"
        );

        // Pre-setup: ensure the per-session events host directory exists
        // and is empty before `docker run`. The three JSONL producers
        // inside the container (Envoy access log, CoreDNS plugin,
        // mitmproxy addon) append to envoy.jsonl / coredns.jsonl /
        // mitmproxy.jsonl inside this directory, which sandboxd tails
        // via `inotify` in the ingest layer.
        //
        // Mirrors the listener host-dir handling above: best-effort
        // cleanup of any leftover dir from a crashed previous session
        // with the same ID, then create. Errors from create are fatal —
        // without this directory the bind mount below would fail and the
        // JSONL producers would write into the tmpfs (losing the
        // ingest path).
        let events_host_dir = session_events_host_dir(session_id);
        let _ = fs::remove_dir_all(&events_host_dir);
        fs::create_dir_all(&events_host_dir).map_err(|e| {
            SandboxError::Gateway(format!(
                "failed to create events host dir {}: {e}",
                events_host_dir.display()
            ))
        })?;

        debug!(
            session_id = %session_id,
            events_host_dir = %events_host_dir.display(),
            "events host dir ready; bind-mounting into container at {EVENTS_DIR_IN_CONTAINER}"
        );

        // Step 1: Start the container.
        //
        // With /28 subnets, Docker bridge claims .1 as the gateway. We
        // explicitly assign .2 (gateway_ip from NetworkInfo) to the gateway
        // container via --ip so the IP is deterministic and matches the
        // nftables DNAT rules.
        let mut args = vec![
            "run".to_string(),
            "-d".to_string(),
            "--name".to_string(),
            container_name.clone(),
            "--network".to_string(),
            network_info.docker_network_name.clone(),
            "--ip".to_string(),
            network_info.gateway_ip.clone(),
            "--read-only".to_string(),
            "--cap-add".to_string(),
            "NET_ADMIN".to_string(),
            "--tmpfs".to_string(),
            "/var/log:rw,noexec,nosuid".to_string(),
            "--tmpfs".to_string(),
            "/var/run:rw,noexec,nosuid".to_string(),
            "--tmpfs".to_string(),
            "/tmp:rw,exec,nosuid".to_string(),
            "--tmpfs".to_string(),
            "/root/.mitmproxy:rw".to_string(),
            "--tmpfs".to_string(),
            "/etc/coredns:rw,noexec,nosuid".to_string(),
            "--tmpfs".to_string(),
            "/etc/envoy:rw,noexec,nosuid".to_string(),
            // Bind-mount the per-session listener host directory into the
            // LDS-watched directory inside the container. sandboxd rewrites
            // the listener file via host-side `fs::rename` — see
            // `atomic_listener_writer` — which produces the `MovedTo`
            // inotify event Envoy's filesystem LDS watcher subscribes to.
            "-v".to_string(),
            format!(
                "{}:{}:rw",
                listener_host_dir.display(),
                LISTENER_DIR_IN_CONTAINER,
            ),
            // Bind-mount the per-session events host directory into
            // [`EVENTS_DIR_IN_CONTAINER`]. The three JSONL producers
            // inside the container append structured events to this
            // path; sandboxd's Phase 7 ingest layer tails the files
            // via `inotify`.
            //
            // This bind sits *underneath* the `/var/log` tmpfs mount
            // above — Docker applies mounts in path-length order, so
            // the tmpfs lands on `/var/log` first and this narrower
            // bind then mounts onto `/var/log/gateway/events/`. The
            // tmpfs starts empty, Docker auto-creates the mountpoint
            // inside it, and operator-debug unstructured logs
            // (envoy.log, mitmproxy.log, coredns.log) continue to
            // live on the tmpfs beside this bind rather than on the
            // host filesystem.
            "-v".to_string(),
            format!(
                "{}:{}:rw",
                events_host_dir.display(),
                EVENTS_DIR_IN_CONTAINER,
            ),
        ];

        // When a CA directory is provided, bind-mount the mitmproxy CA
        // files on top of the tmpfs.  Docker processes mounts in order,
        // so these bind mounts overlay the specific files within the
        // tmpfs at /root/.mitmproxy.
        if let Some(dir) = ca_dir {
            let ca_pem = dir.join("mitmproxy-ca.pem");
            let ca_cert_pem = dir.join("mitmproxy-ca-cert.pem");

            args.push("-v".to_string());
            args.push(format!(
                "{}:/root/.mitmproxy/mitmproxy-ca.pem:ro",
                ca_pem.display()
            ));
            args.push("-v".to_string());
            args.push(format!(
                "{}:/root/.mitmproxy/mitmproxy-ca-cert.pem:ro",
                ca_cert_pem.display()
            ));

            debug!(
                session_id = %session_id,
                ca_pem = %ca_pem.display(),
                ca_cert_pem = %ca_cert_pem.display(),
                "mounting CA certificates into gateway container"
            );
        }

        args.extend([
            "--sysctl".to_string(),
            "net.ipv4.ip_forward=1".to_string(),
            "--sysctl".to_string(),
            "net.ipv6.conf.all.forwarding=0".to_string(),
            "--restart".to_string(),
            "unless-stopped".to_string(),
            "--label".to_string(),
            format!("sandbox.session_id={session_id}"),
            GATEWAY_IMAGE.to_string(),
        ]);

        let args_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
        let output = run_with_timeout(
            Command::new("docker").args(&args_refs),
            DOCKER_RUN_TIMEOUT,
            "docker run (gateway)",
        )
        .map_err(|e| match e {
            SandboxError::Internal(msg) if msg.contains("failed to spawn") => {
                SandboxError::Gateway(format!("failed to run docker run: {msg}"))
            }
            other => other,
        })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(SandboxError::Gateway(format!(
                "docker run failed for gateway container: {stderr}"
            )));
        }

        debug!(
            session_id = %session_id,
            container = %container_name,
            gateway_ip = %network_info.gateway_ip,
            "gateway container started"
        );

        // Step 2a: Write the Envoy static bootstrap into the container.
        //
        // The bootstrap is policy-agnostic (admin endpoint, cluster
        // definitions, `dynamic_resources.lds_config` pointing at the
        // LDS-watched listener file) so the content is the same for every
        // session. It is written here so the entrypoint can start Envoy
        // pointing at `/etc/envoy/envoy-bootstrap.yaml`.
        //
        // The entrypoint script waits for this file to appear before
        // launching Envoy, so the write must happen before Envoy
        // readiness is awaited below.
        {
            use crate::policy::BOOTSTRAP_FILE_IN_CONTAINER;
            use crate::policy_distributor::write_file_to_container;
            let bootstrap = PolicyCompiler::compile_envoy_bootstrap();
            if let Err(e) =
                write_file_to_container(&container_name, BOOTSTRAP_FILE_IN_CONTAINER, &bootstrap)
            {
                // Fatal: without the bootstrap Envoy cannot start.
                return Err(SandboxError::Gateway(format!(
                    "failed to write Envoy bootstrap to {container_name}: {e}"
                )));
            }
            debug!(
                session_id = %session_id,
                "wrote Envoy static bootstrap to gateway container"
            );
        }

        // Step 2b: Write the initial DNS policy file if one was provided.
        //
        // The entrypoint creates a deny-all default at
        // /etc/coredns/policy.conf only if the file does not yet exist.
        // By writing the policy here (before the entrypoint's check runs
        // or before CoreDNS calls LoadFile), we ensure the first policy
        // load sees the correct content — no reload-timer race.
        if let Some(policy_content) = initial_dns_policy {
            use crate::policy_distributor::write_file_to_container;
            match write_file_to_container(
                &container_name,
                "/etc/coredns/policy.conf",
                policy_content,
            ) {
                Ok(()) => {
                    debug!(
                        session_id = %session_id,
                        "wrote initial DNS policy to gateway container"
                    );
                }
                Err(e) => {
                    // Non-fatal: the entrypoint will create a deny-all default
                    // and sandboxd can overwrite it later, but there will be
                    // a brief window where DNS queries are denied.
                    warn!(
                        session_id = %session_id,
                        error = %e,
                        "failed to write initial DNS policy (CoreDNS may briefly deny queries)"
                    );
                }
            }
        }

        // Step 3: Immediately inject deny-all nftables rules.
        //
        // This must happen before components finish initialising so no traffic
        // can leak before the full ruleset is in place.
        self.inject_deny_all(session_id)?;

        // Step 4: Wait for all components to become ready.
        self.wait_for_components(session_id)?;

        // Step 5: Inject DNAT rules (now that all components are serving).
        // Use the explicit gateway IP from NetworkInfo as the DNAT target.
        self.inject_dnat(session_id, network_info, &network_info.gateway_ip)?;

        info!(
            session_id = %session_id,
            container = %container_name,
            "gateway fully initialised with nftables rules"
        );

        Ok(())
    }

    /// Stop and remove the gateway container.
    ///
    /// Shutdown ordering:
    /// 1. Remove DNAT rules (so no new traffic is routed to the gateway)
    /// 2. Stop the container (which stops all components)
    /// 3. Remove the container (network namespace disappears, cleaning up
    ///    the deny-all rules automatically)
    pub fn stop_gateway(&self, session_id: &SessionId) -> Result<(), SandboxError> {
        let container_name = container_name(session_id);

        info!(
            session_id = %session_id,
            container = %container_name,
            "stopping gateway container"
        );

        // Step 1: Remove DNAT rules (best-effort; container might already be gone).
        if let Err(e) = self.remove_dnat_rules(session_id) {
            warn!(
                session_id = %session_id,
                error = %e,
                "failed to remove DNAT rules (container may already be stopped)"
            );
        }

        // Step 2: Stop the container.
        let output = run_with_timeout(
            Command::new("docker").args(["stop", "--time", "10", &container_name]),
            DOCKER_STOP_TIMEOUT,
            "docker stop (gateway)",
        )
        .map_err(|e| match e {
            SandboxError::Internal(msg) if msg.contains("failed to spawn") => {
                SandboxError::Gateway(format!("failed to run docker stop: {msg}"))
            }
            other => other,
        })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            // Not fatal if container is already stopped.
            warn!(
                session_id = %session_id,
                stderr = %stderr.trim(),
                "docker stop returned non-zero (container may already be stopped)"
            );
        }

        // Step 3: Remove the container.
        let output = run_with_timeout(
            Command::new("docker").args(["rm", "--force", &container_name]),
            DOCKER_RM_TIMEOUT,
            "docker rm (gateway)",
        )
        .map_err(|e| match e {
            SandboxError::Internal(msg) if msg.contains("failed to spawn") => {
                SandboxError::Gateway(format!("failed to run docker rm: {msg}"))
            }
            other => other,
        })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(SandboxError::Gateway(format!(
                "docker rm failed for gateway container: {stderr}"
            )));
        }

        // Step 4: Remove the per-session listener host directory that was
        // bind-mounted into the container. Best-effort: nothing else
        // depends on this path surviving after the container is gone.
        let listener_host_dir = session_listener_host_dir(session_id);
        if let Err(e) = fs::remove_dir_all(&listener_host_dir) {
            if e.kind() != std::io::ErrorKind::NotFound {
                warn!(
                    session_id = %session_id,
                    dir = %listener_host_dir.display(),
                    error = %e,
                    "failed to remove listener host dir (non-fatal)"
                );
            }
        }

        // Step 5: Remove the per-session events host directory that
        // held the three JSONL producer files. Same best-effort
        // posture as the listener dir above — the ingest layer stops
        // tailing as part of session teardown so the files are no
        // longer referenced after `docker rm`.
        //
        // Debug escape hatch: when `SANDBOX_KEEP_SESSION_EVENTS` is set
        // (any non-empty value), skip the cleanup so the per-session
        // `mitmproxy.jsonl`, `coredns.jsonl`, `envoy.jsonl`,
        // `nft-deny.jsonl`, and `nft-allow.jsonl` files survive
        // `sandbox rm`. E2E test
        // failures often hinge on which layer denied a connection;
        // without this flag, the proof is gone before a human can look.
        // The keep semantics are per-process: any session removed while
        // the env var is set leaks its events dir, intentionally — a
        // human is expected to inspect and clean up afterwards.
        let events_host_dir = session_events_host_dir(session_id);
        if std::env::var_os("SANDBOX_KEEP_SESSION_EVENTS").is_some_and(|v| !v.is_empty()) {
            info!(
                session_id = %session_id,
                dir = %events_host_dir.display(),
                "SANDBOX_KEEP_SESSION_EVENTS set; preserving events host dir for debugging"
            );
        } else if let Err(e) = fs::remove_dir_all(&events_host_dir) {
            if e.kind() != std::io::ErrorKind::NotFound {
                warn!(
                    session_id = %session_id,
                    dir = %events_host_dir.display(),
                    error = %e,
                    "failed to remove events host dir (non-fatal)"
                );
            }
        }

        info!(
            session_id = %session_id,
            container = %container_name,
            "gateway container stopped and removed"
        );

        Ok(())
    }

    /// Restart a crashed or stopped gateway container.
    ///
    /// This removes the old container (best-effort) and creates a fresh one
    /// with the full setup (nftables deny-all, component readiness, DNAT).
    ///
    /// This is preferred over `docker start` because the nftables rules live
    /// in the container's network namespace, which is destroyed when the
    /// container exits. A fresh container gets a new namespace that needs
    /// the full rule injection sequence.
    pub fn restart_gateway(
        &self,
        session_id: &SessionId,
        network_info: &NetworkInfo,
        ca_dir: Option<&Path>,
        initial_dns_policy: Option<&str>,
    ) -> Result<(), SandboxError> {
        info!(
            session_id = %session_id,
            "restarting gateway container"
        );

        // Remove old container (best-effort).
        if let Err(e) = self.stop_gateway(session_id) {
            warn!(
                session_id = %session_id,
                error = %e,
                "failed to stop old gateway during restart (may already be gone)"
            );
        }

        // Create fresh container with full setup.
        self.create_gateway(session_id, network_info, ca_dir, initial_dns_policy)
    }

    /// Check gateway health.
    ///
    /// Two-stage probe:
    /// 1. Run the in-container `/healthcheck.sh` script (Envoy /ready,
    ///    CoreDNS /health, mitmproxy process, deny-logger /health).
    ///    A non-zero exit code yields `Unhealthy`.
    /// 2. If healthcheck.sh succeeded, query Envoy admin
    ///    `/stats?filter=listener_manager.total_listeners_active$&format=text`
    ///    via `docker exec`. A value `>= 1` yields `Healthy`; a value
    ///    of `0` yields `Starting`.
    ///
    /// The listener-active probe closes the gap between "container
    /// processes are running" and "Envoy is actually serving traffic".
    /// Pre-#52 the bootstrap deny-all listener (empty `filter_chains`)
    /// is rejected by Envoy at runtime — `total_listeners_active` is
    /// `0` until the first apply-policy lands a populated listener via
    /// LDS — but `gateway_status` mis-reported `Healthy` throughout
    /// that window and continued to mis-report `Healthy` if a
    /// policy-compiled listener was rejected at runtime
    /// (`lds.update_rejected` ticked but `total_listeners_active`
    /// stayed at `0`). The two-stage probe surfaces both cases as
    /// `Starting` instead, distinct from both `Healthy` and `Unhealthy`.
    ///
    /// If the listener-count probe itself fails (e.g. admin endpoint
    /// transient error, container racing through restart), the verdict
    /// degrades to `Healthy` rather than `Starting` to avoid a flap-
    /// driven false positive — `Healthy` is the prior behaviour and
    /// any persistent listener regression will fail the next probe
    /// cycle anyway.
    pub fn gateway_status(&self, session_id: &SessionId) -> Result<GatewayStatus, SandboxError> {
        let container_name = container_name(session_id);

        // First check if the container is running.
        let output = run_with_timeout(
            Command::new("docker").args([
                "inspect",
                "--format",
                "{{.State.Running}}",
                &container_name,
            ]),
            DOCKER_INSPECT_TIMEOUT,
            "docker inspect (gateway status)",
        )
        .map_err(|e| match e {
            SandboxError::Internal(msg) if msg.contains("failed to spawn") => {
                SandboxError::Gateway(format!("failed to run docker inspect: {msg}"))
            }
            other => other,
        })?;

        if !output.status.success() {
            return Ok(GatewayStatus::NotRunning);
        }

        let running = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if running != "true" {
            return Ok(GatewayStatus::NotRunning);
        }

        // Run the healthcheck script.
        let output = run_with_timeout(
            Command::new("docker").args(["exec", &container_name, "/healthcheck.sh"]),
            DOCKER_INSPECT_TIMEOUT,
            "docker exec (healthcheck)",
        )
        .map_err(|e| match e {
            SandboxError::Internal(msg) if msg.contains("failed to spawn") => {
                SandboxError::Gateway(format!("failed to run healthcheck: {msg}"))
            }
            other => other,
        })?;

        let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();

        if !output.status.success() {
            return Ok(GatewayStatus::Unhealthy(stdout));
        }

        // Stage 2: probe Envoy's listener_manager.total_listeners_active.
        // The container processes are healthy; we now distinguish
        // `Healthy` (>= 1 active listener) from `Starting` (0 active
        // listeners — boot window or LDS rejection).
        match self.gateway_listener_active_count(session_id) {
            Some(0) => Ok(GatewayStatus::Starting),
            Some(_) => Ok(GatewayStatus::Healthy),
            // Probe failure: fall through to `Healthy`. See the rustdoc
            // above — flapping the verdict on a transient admin-endpoint
            // hiccup would be worse than masking a single sample of a
            // genuine problem (which surfaces on the next cycle).
            None => Ok(GatewayStatus::Healthy),
        }
    }

    /// Return the value of Envoy's
    /// `listener_manager.total_listeners_active` gauge inside the
    /// gateway container, or `None` if the probe fails (container not
    /// running, admin endpoint not yet ready, transient `docker exec`
    /// error, parse failure).
    ///
    /// This is the load-bearing primitive for `gateway_status`'s
    /// `Healthy` vs `Starting` arm — see that method's rustdoc for
    /// the contract — and is exposed publicly for two reasons:
    ///   - Integration tests under `sandbox-core/tests/gateway_integration.rs`
    ///     assert the count directly to lock in the contract.
    ///   - Any future tooling that wants a raw "is Envoy serving?"
    ///     signal independent of CoreDNS / mitmproxy / deny-logger
    ///     can call this without re-implementing the docker-exec
    ///     plumbing.
    ///
    /// Implementation: `docker exec <gw> curl -sf
    /// 'http://127.0.0.1:9901/stats?filter=^listener_manager\\.total_listeners_active$&format=text'`
    /// and parse the `name: value` text output. Same transport used by
    /// `DockerExecLdsProbe` (cf. `lds_ack.rs`) — the `&` in the URL must
    /// reach Envoy as a real query-string separator, so the URL is
    /// passed verbatim as one argv element rather than built via shell.
    pub fn gateway_listener_active_count(&self, session_id: &SessionId) -> Option<u64> {
        let container_name = container_name(session_id);
        let url = "http://127.0.0.1:9901/stats?\
                   filter=^listener_manager\\.total_listeners_active$&\
                   format=text";
        let output = run_with_timeout(
            Command::new("docker").args(["exec", &container_name, "curl", "-sf", url]),
            DOCKER_INSPECT_TIMEOUT,
            "docker exec (envoy listener_active probe)",
        )
        .ok()?;
        if !output.status.success() {
            return None;
        }
        let text = String::from_utf8_lossy(&output.stdout);
        // Expected: `listener_manager.total_listeners_active: <n>`.
        // Envoy omits zero-valued counters from /stats but EMITS
        // gauges (which `total_listeners_active` is) at their current
        // value — a missing line for this gauge would be unusual but
        // safest to treat as `None` rather than guessing 0.
        for line in text.lines() {
            if let Some((_, v)) = line.split_once(':') {
                if let Ok(n) = v.trim().parse::<u64>() {
                    return Some(n);
                }
            }
        }
        None
    }

    /// Return the container status as a string: "running", "stopped", or
    /// "not_found".
    pub fn container_status_str(&self, session_id: &SessionId) -> String {
        let container_name = container_name(session_id);

        let output = run_with_timeout(
            Command::new("docker").args([
                "inspect",
                "--format",
                "{{.State.Status}}",
                &container_name,
            ]),
            DOCKER_INSPECT_TIMEOUT,
            "docker inspect (container status)",
        );

        match output {
            Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout).trim().to_string(),
            _ => "not_found".to_string(),
        }
    }

    /// Read Docker's native per-container health verdict via
    /// `docker inspect --format '{{.State.Health.Status}}' <container>`.
    ///
    /// This is the verdict Docker maintains from the container's
    /// `HEALTHCHECK` directive (interval / timeout / retries / start-
    /// period already applied). It is strictly cheaper than re-running
    /// the healthcheck script from outside — Docker has already run it
    /// on the inside.
    ///
    /// Callers should use this as a first-pass signal; the aggregate
    /// [`GatewayStatus`] verdict (from [`Self::gateway_status`]) remains
    /// authoritative for the full Healthy / Unhealthy / NotRunning
    /// mapping (e.g. it also catches `.State.Running == false` without
    /// a health directive). See [`DockerHealth`] for the individual
    /// variants and how to react to each.
    ///
    /// This performs a single blocking `docker inspect` call. Async
    /// callers must wrap this in `tokio::task::spawn_blocking` per
    /// project conventions (it uses `std::process::Command`
    /// internally).
    pub fn container_health_status(&self, session_id: &SessionId) -> DockerHealth {
        let container_name = container_name(session_id);

        let output = run_with_timeout(
            Command::new("docker").args([
                "inspect",
                "--format",
                "{{.State.Health.Status}}",
                &container_name,
            ]),
            DOCKER_INSPECT_TIMEOUT,
            "docker inspect (container health)",
        );

        match output {
            Ok(o) if o.status.success() => {
                let raw = String::from_utf8_lossy(&o.stdout);
                DockerHealth::parse(raw.as_ref())
            }
            // Container missing, inspect failed, or stderr-only output:
            // we cannot attribute a verdict, so fall back to Unknown.
            // Callers fall back to `gateway_status`, which has its own
            // NotRunning handling.
            _ => DockerHealth::Unknown,
        }
    }

    /// Check the health of a single component inside the gateway container.
    ///
    /// Returns "healthy", "unhealthy", or "unknown" (if the container is not
    /// running or the check cannot be performed).
    pub fn component_health(&self, session_id: &SessionId, component: &str) -> String {
        let container_name = container_name(session_id);

        let check_cmd: &[&str] = match component_probe(component) {
            Some(cmd) => cmd,
            None => return "unknown".to_string(),
        };

        let mut args = vec!["exec", &container_name];
        args.extend(check_cmd);

        match run_with_timeout(
            Command::new("docker").args(&args),
            DOCKER_INSPECT_TIMEOUT,
            &format!("docker exec ({component} health)"),
        ) {
            Ok(output) if output.status.success() => "healthy".to_string(),
            Ok(_) => "unhealthy".to_string(),
            Err(_) => "unknown".to_string(),
        }
    }

    // -- nftables injection ----------------------------------------------------

    /// Inject the deny-all nftables ruleset into the gateway container's
    /// network namespace.
    ///
    /// This is the first ruleset applied, before any components are ready.
    /// It drops all inbound and forwarded traffic while allowing outbound.
    pub fn inject_deny_all(&self, session_id: &SessionId) -> Result<(), SandboxError> {
        let ruleset = generate_deny_all_ruleset();
        self.inject_nftables_ruleset(session_id, &ruleset, "deny-all")
    }

    /// Inject the DNAT nftables rules into the gateway container's network
    /// namespace.
    ///
    /// These rules redirect DNS traffic to CoreDNS and all other TCP traffic
    /// to Envoy. They also block cloud metadata and IPv6.
    ///
    /// `container_ip` is the gateway container's IP on the Docker bridge
    /// (explicitly assigned via `--ip` from NetworkInfo.gateway_ip).
    pub fn inject_dnat(
        &self,
        session_id: &SessionId,
        network_info: &NetworkInfo,
        container_ip: &str,
    ) -> Result<(), SandboxError> {
        let ruleset = generate_dnat_ruleset(&network_info.subnet, container_ip);
        self.inject_nftables_ruleset(session_id, &ruleset, "DNAT")?;

        // Also update the forward chain to allow forwarding from the VM subnet.
        let forward_rules = generate_forward_allow_ruleset(&network_info.subnet, container_ip);
        self.inject_nftables_ruleset(session_id, &forward_rules, "forward-allow")?;

        // Open the input chain for service ports (DNS, Envoy) from the VM
        // subnet.  Without this, DNATted traffic is rejected by the deny-all
        // input chain.
        let input_rules = generate_input_allow_ruleset(&network_info.subnet);
        self.inject_nftables_ruleset(session_id, &input_rules, "input-allow")
    }

    /// Inject nftables rules into the gateway container's network namespace.
    ///
    /// This is the public API for injecting arbitrary nftables rules. It
    /// uses the explicit gateway IP from NetworkInfo and combines the
    /// deny-all base rules and DNAT rules.
    pub fn inject_nftables(
        &self,
        session_id: &SessionId,
        network_info: &NetworkInfo,
    ) -> Result<(), SandboxError> {
        self.inject_deny_all(session_id)?;
        self.inject_dnat(session_id, network_info, &network_info.gateway_ip)
    }

    /// Inject an arbitrary nftables ruleset into the gateway container's
    /// network namespace. This is the public entry point for policy modules
    /// (e.g. DNS propagation, policy distributor) that need to update
    /// nftables rules outside the base deny-all/DNAT lifecycle.
    pub fn inject_nftables_ruleset_public(
        &self,
        session_id: &SessionId,
        ruleset: &str,
        label: &str,
    ) -> Result<(), SandboxError> {
        self.inject_nftables_ruleset(session_id, ruleset, label)
    }

    /// Remove the DNAT + policy nftables tables from the gateway container's
    /// network namespace. Called before shutdown to stop routing new traffic.
    ///
    /// `sandbox_dnat` and `sandbox_policy` are both managed as a pair —
    /// `sandbox_dnat` holds the conditional-DNAT + set declarations,
    /// `sandbox_policy` holds the Envoy-egress output-chain allow rules.
    /// Tear both down atomically in a single `nft -f` input so the gateway
    /// doesn't briefly run with only half the pair present (which could
    /// leak traffic through the orphaned chain on the way to container
    /// stop).
    pub fn remove_dnat_rules(&self, session_id: &SessionId) -> Result<(), SandboxError> {
        // `table inet X {}` + `delete table inet X` is the idempotent
        // delete idiom: `add table` (what `table inet X {}` is shorthand
        // for) is a no-op when the table exists, and the subsequent
        // `delete table` always succeeds. Without the add-first line,
        // tearing down a session whose policy never landed (so
        // `sandbox_policy` was never created) would fail with
        // "No such file or directory".
        let ruleset = "table inet sandbox_dnat {}\n\
                       table inet sandbox_policy {}\n\
                       delete table inet sandbox_dnat\n\
                       delete table inet sandbox_policy\n";
        self.inject_nftables_ruleset(session_id, ruleset, "remove-DNAT")
    }

    // -- Internal helpers ------------------------------------------------------

    /// Get the IP address of the gateway container on its Docker network.
    ///
    /// With /28 subnets the gateway container gets an explicit IP via `--ip`,
    /// but this method is retained for verification and integration tests.
    pub fn container_ip(&self, session_id: &SessionId) -> Result<String, SandboxError> {
        let container_name = container_name(session_id);

        let output = run_with_timeout(
            Command::new("docker").args([
                "inspect",
                "--format",
                "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}",
                &container_name,
            ]),
            CONTAINER_IP_TIMEOUT,
            "docker inspect (container IP)",
        )
        .map_err(|e| match e {
            SandboxError::Internal(msg) if msg.contains("failed to spawn") => {
                SandboxError::Gateway(format!(
                    "failed to inspect container IP for {container_name}: {msg}"
                ))
            }
            other => other,
        })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(SandboxError::Gateway(format!(
                "docker inspect failed for {container_name}: {stderr}"
            )));
        }

        let ip = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if ip.is_empty() {
            return Err(SandboxError::Gateway(format!(
                "container {container_name} has no IP address"
            )));
        }

        Ok(ip)
    }

    /// Inject an nftables ruleset into the container via `docker exec`.
    fn inject_nftables_ruleset(
        &self,
        session_id: &SessionId,
        ruleset: &str,
        label: &str,
    ) -> Result<(), SandboxError> {
        let container = container_name(session_id);

        debug!(
            session_id = %session_id,
            container = %container,
            label = label,
            "injecting nftables ruleset via docker exec"
        );

        let mut child = Command::new("docker")
            .args(["exec", "-i", &container, "nft", "-f", "-"])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .map_err(|e| {
                SandboxError::Gateway(format!("failed to spawn {label} nftables injection: {e}"))
            })?;

        // Write the ruleset to stdin, then close it.
        {
            use std::io::Write;
            if let Some(ref mut stdin) = child.stdin {
                let _ = stdin.write_all(ruleset.as_bytes());
            }
            child.stdin.take();
        }

        // Wait with timeout to avoid unbounded hangs.
        let deadline = Instant::now() + NFT_EXEC_TIMEOUT;
        let output = loop {
            match child.try_wait() {
                Ok(Some(_)) => {
                    break child.wait_with_output().map_err(|e| {
                        SandboxError::Gateway(format!(
                            "failed to collect output from {label} nftables injection: {e}"
                        ))
                    })?;
                }
                Ok(None) if Instant::now() >= deadline => {
                    warn!(label = label, "nftables injection timed out, killing");
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(SandboxError::Gateway(format!(
                        "nftables {label} injection timed out after {}s",
                        NFT_EXEC_TIMEOUT.as_secs()
                    )));
                }
                Ok(None) => thread::sleep(Duration::from_millis(50)),
                Err(e) => {
                    return Err(SandboxError::Gateway(format!(
                        "failed to poll {label} nftables injection: {e}"
                    )));
                }
            }
        };

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(SandboxError::Gateway(format!(
                "nftables {label} injection failed: {stderr}"
            )));
        }

        debug!(
            session_id = %session_id,
            label = label,
            "nftables ruleset injected"
        );

        Ok(())
    }

    /// Wait for all gateway components to become ready.
    ///
    /// The probe commands are sourced from [`component_probe`], which is
    /// also used by [`GatewayManager::component_health`] — keeping startup
    /// readiness and steady-state health on the exact same probes.
    ///
    /// Order matches the historical wait order (Envoy → CoreDNS →
    /// mitmproxy) with deny-logger appended last. deny-logger is the
    /// data-path ingress for deny traffic and binds on the gateway
    /// bridge IP rather than 127.0.0.1 (spec 2026-04-21 Part 3 /
    /// "Deny-logger component / Listener design"), so its probe goes
    /// through `$(hostname -i)`.
    fn wait_for_components(&self, session_id: &SessionId) -> Result<(), SandboxError> {
        let container_name = container_name(session_id);
        let deadline = Instant::now() + COMPONENT_READY_TIMEOUT;

        info!(
            session_id = %session_id,
            timeout_secs = COMPONENT_READY_TIMEOUT.as_secs(),
            "waiting for gateway components to become ready"
        );

        for (component, log_name) in KNOWN_COMPONENTS {
            let probe = component_probe(component).unwrap_or_else(|| {
                // Unreachable: KNOWN_COMPONENTS and component_probe are
                // kept in sync by the
                // `component_probe_returns_some_for_every_known_component`
                // unit test.
                panic!("no probe command registered for known component {component:?}");
            });
            self.wait_for_component(&container_name, log_name, probe, deadline)?;
        }

        info!(
            session_id = %session_id,
            "all gateway components are ready"
        );

        Ok(())
    }

    /// Poll a single component for readiness by running a check command
    /// inside the container.
    fn wait_for_component(
        &self,
        container_name: &str,
        component_name: &str,
        check_cmd: &[&str],
        deadline: Instant,
    ) -> Result<(), SandboxError> {
        debug!(
            container = container_name,
            component = component_name,
            "waiting for component readiness"
        );

        let mut last_stdout = String::new();
        let mut last_stderr = String::new();
        let mut last_exit_code: Option<i32> = None;
        let mut attempts: u32 = 0;

        while Instant::now() < deadline {
            let mut args = vec!["exec", container_name];
            args.extend(check_cmd);

            let output = Command::new("docker").args(&args).output().map_err(|e| {
                SandboxError::Gateway(format!("failed to check {component_name} readiness: {e}"))
            })?;

            attempts += 1;

            if output.status.success() {
                debug!(
                    container = container_name,
                    component = component_name,
                    attempts,
                    "component is ready"
                );
                return Ok(());
            }

            last_exit_code = output.status.code();
            last_stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
            last_stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();

            thread::sleep(COMPONENT_POLL_INTERVAL);
        }

        Err(SandboxError::Gateway(format!(
            "{component_name} did not become ready within {}s after {attempts} probes \
             (last exit={exit}, stdout={stdout:?}, stderr={stderr:?}, probe={probe:?})",
            COMPONENT_READY_TIMEOUT.as_secs(),
            exit = last_exit_code
                .map(|c| c.to_string())
                .unwrap_or_else(|| "signal".into()),
            stdout = last_stdout,
            stderr = last_stderr,
            probe = check_cmd,
        )))
    }
}

impl Default for GatewayManager {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Naming helpers
// ---------------------------------------------------------------------------

/// Generate the Docker container name for a session's gateway.
pub fn container_name(session_id: &SessionId) -> String {
    format!("sandbox-gw-{session_id}")
}

// ---------------------------------------------------------------------------
// Component probes
// ---------------------------------------------------------------------------

/// The set of gateway subcomponents whose readiness is polled on startup
/// (`wait_for_components`) and whose liveness is polled on steady state
/// by sandboxd's gateway monitor (`component_health`).
///
/// Each entry pairs the canonical kebab-case probe label used by
/// [`component_probe`] with a human-readable log/display name.
///
/// Order is the startup wait order — matches the historical sequence
/// (Envoy → CoreDNS → mitmproxy) with deny-logger appended last so a
/// deny-logger failure surfaces only once the other components are up.
pub const KNOWN_COMPONENTS: &[(&str, &str)] = &[
    ("envoy", "Envoy"),
    ("coredns", "CoreDNS"),
    ("mitmproxy", "mitmproxy"),
    ("deny-logger", "deny-logger"),
];

/// Return the `docker exec` argv that probes `component`'s readiness,
/// or `None` if `component` is not a recognised subcomponent name.
///
/// Used by both [`GatewayManager::component_health`] (steady-state
/// liveness polling) and `GatewayManager::wait_for_components`
/// (startup readiness wait) — keeping both paths on the identical
/// probe command per component.
///
/// The deny-logger probe uses `sh -c` to discover the gateway bridge
/// IP at runtime via `hostname -i`, because the deny-logger listeners
/// bind on that address rather than 127.0.0.1 (PREROUTING DNAT to
/// loopback is dropped by the kernel as a martian destination unless
/// `route_localnet=1` is set, which the gateway container does not
/// enable — see spec 2026-04-21 Part 3 / "Deny-logger component /
/// Listener design"). The same pattern is used by the container's
/// `healthcheck.sh` and `entrypoint.sh`.
pub fn component_probe(component: &str) -> Option<&'static [&'static str]> {
    match component {
        "envoy" => Some(&["curl", "-sf", "http://127.0.0.1:9901/ready"]),
        "coredns" => Some(&["curl", "-sf", "http://127.0.0.1:8180/health"]),
        "mitmproxy" => Some(&["pgrep", "-x", "mitmdump"]),
        "deny-logger" => Some(&[
            "sh",
            "-c",
            "curl -sf \"http://$(hostname -i | awk '{print $1}'):10003/health\"",
        ]),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// nftables ruleset generators
// ---------------------------------------------------------------------------

/// Generate the deny-all base ruleset.
///
/// This ruleset:
/// - Drops all inbound traffic (except loopback and established connections)
/// - Drops all forwarded traffic
/// - Allows all outbound traffic
/// - Allows ICMP for diagnostics
pub fn generate_deny_all_ruleset() -> String {
    r#"table inet sandbox {
    chain input {
        type filter hook input priority 0; policy drop;

        # Allow loopback
        iif lo accept

        # Allow established/related
        ct state established,related accept

        # Allow ICMP (ping)
        ip protocol icmp accept

        # Reject everything else (fast failure)
        reject
    }

    chain forward {
        type filter hook forward priority 0; policy drop;
        reject
    }

    chain output {
        type filter hook output priority 0; policy accept;
    }
}
"#
    .to_string()
}

/// Generate the DNAT ruleset that routes VM traffic through the gateway.
///
/// **Two-table conditional DNAT shape.** The `sandbox_dnat` table
/// makes the allow/deny decision for VM egress via conditional DNAT
/// keyed on the `policy_allow_{tcp,udp}` concat sets:
///
/// - DNS (port 53) → CoreDNS (unchanged)
/// - VM TCP matching `(ip daddr, tcp dport)` in `@policy_allow_tcp` →
///   Envoy :10000
/// - VM UDP matching `(ip daddr, udp dport)` in `@policy_allow_udp` →
///   Envoy :10000 (future-proofed; Envoy drops UDP today)
/// - All other VM TCP → deny-logger :10001
/// - All other VM UDP → deny-logger :10002
/// - Block cloud metadata (169.254.169.254)
/// - Drop non-loopback IPv6
/// - MASQUERADE outgoing traffic
///
/// The concat sets are declared here *empty*. `PolicyCompiler::compile_nftables`
/// and `dns_propagation::generate_domain_ip_rules` rewrite the set elements
/// when a policy lands / resolves. Until then, every non-53 VM packet DNATs
/// to the deny-logger, surfacing as a structured `deny` event with the
/// original 5-tuple — this is the intentional fail-closed default.
///
/// **Cross-table set refs vs. duplication.** nftables 1.0.6 on kernel 6.8
/// (as pinned in the gateway image) does **not** support the
/// `@<table>::<set>` cross-table reference syntax; `nft -c` rejects it
/// with "No such file or directory". As a consequence the set
/// declarations are duplicated in both `sandbox_dnat` and `sandbox_policy`
/// and populated identically by the compile / DNS-propagation paths.
/// Verified empirically via `nft -c -f -` on the gateway image before the
/// landing commit.
pub fn generate_dnat_ruleset(vm_subnet: &str, gateway_ip: &str) -> String {
    format!(
        r#"table inet sandbox_dnat {{
    set {NFT_POLICY_ALLOW_TCP_SET} {{
        type ipv4_addr . inet_service
        flags interval
    }}

    set {NFT_POLICY_ALLOW_UDP_SET} {{
        type ipv4_addr . inet_service
        flags interval
    }}

    chain prerouting {{
        type nat hook prerouting priority dstnat;

        # DNS -> CoreDNS (port 53)
        ip saddr {vm_subnet} udp dport {GATEWAY_DNS_PORT} dnat to {gateway_ip}:{GATEWAY_DNS_PORT}
        ip saddr {vm_subnet} tcp dport {GATEWAY_DNS_PORT} dnat to {gateway_ip}:{GATEWAY_DNS_PORT}

        # Policy-allowed TCP -> Envoy (conditional DNAT keyed on
        # (ip daddr, dport) concat set populated by the policy compiler
        # and DNS propagation loop).
        ip saddr {vm_subnet} meta l4proto tcp ip daddr . tcp dport @{NFT_POLICY_ALLOW_TCP_SET} dnat to {gateway_ip}:{GATEWAY_ENVOY_PORT}

        # Policy-allowed UDP -> direct to upstream. The UDP allow path
        # skips Envoy entirely (UDP cannot be MITM'd / has no L7
        # inspection surface). The packet falls through prerouting
        # un-DNAT'd; the `forward` chain admits VM-subnet UDP destined
        # to an allowed (ip, port) and POSTROUTING masquerades it out.
        ip saddr {vm_subnet} meta l4proto udp ip daddr . udp dport @{NFT_POLICY_ALLOW_UDP_SET} accept

        # Unmatched TCP -> deny-logger (DNAT to userland listener).
        # Fail-closed: pre-policy VM traffic hits this rule too and is
        # surfaced as a structured `deny` event instead of a silent RST.
        ip saddr {vm_subnet} meta l4proto tcp dnat to {gateway_ip}:{GATEWAY_DENY_LOGGER_TCP_PORT}

        # Unmatched UDP -> NFLOG group then drop. No DNAT, no userland
        # listener. The kernel mirrors the dropped packet to
        # NFNLGRP_NFLOG with the pre-rewrite IPv4+UDP headers;
        # `sandbox-nft-deny-logger` subscribes to the group and emits
        # the JSONL deny event with the original 5-tuple. Silent drop
        # on the wire (no ICMP unreachable).
        ip saddr {vm_subnet} meta l4proto udp log group {NFT_NFLOG_DENY_GROUP}
        ip saddr {vm_subnet} meta l4proto udp drop

        # Block cloud metadata
        ip daddr 169.254.169.254 drop

        # Drop IPv6
        ip6 daddr != ::1 drop
    }}

    chain postrouting {{
        type nat hook postrouting priority srcnat;

        # MASQUERADE for outgoing traffic
        masquerade
    }}
}}
"#,
    )
}

/// Generate rules that open the input chain for service ports.
///
/// The initial deny-all ruleset blocks all inbound traffic. After DNAT
/// is configured, traffic from the VM subnet is rewritten to the
/// gateway's own IP on one of three destination ports (down from
/// four — the legacy deny-logger UDP listener at :10002 is gone,
/// replaced by an NFLOG-driven UDP deny path):
///
/// - `:53` — DNS (CoreDNS)
/// - `:10000` — Envoy's `original_dst` listener (policy-allowed TCP only;
///   Envoy terminates TCP and — for L3 destinations — opens a CONNECT
///   tunnel to mitmproxy on loopback `127.0.0.1:18080`. UDP does not
///   DNAT here — the UDP allow path is direct.)
/// - `:10001` — deny-logger TCP listener (VM TCP that *didn't* match any
///   policy allow tuple)
///
/// Plus `:10003` — the deny-logger's `/health` endpoint. This one is **not**
/// reachable from the VM subnet (no DNAT rule), only from inside the
/// container via `docker exec`-driven healthchecks and sandboxd's
/// `component_health` probe. We still open it on the input chain so those
/// in-container probes work even though they route via loopback + bridge.
///
/// The input chain must accept traffic on each of these ports, otherwise
/// the DNATted packets (and in-container healthchecks) are rejected by
/// the trailing `reject` rule.
pub fn generate_input_allow_ruleset(vm_subnet: &str) -> String {
    format!(
        r#"flush chain inet sandbox input
table inet sandbox {{
    chain input {{
        # Allow loopback
        iif lo accept

        # Allow established/related
        ct state established,related accept

        # Allow ICMP (ping) for diagnostics
        ip protocol icmp accept

        # Allow DNS from VM subnet (CoreDNS)
        ip saddr {vm_subnet} udp dport {GATEWAY_DNS_PORT} accept
        ip saddr {vm_subnet} tcp dport {GATEWAY_DNS_PORT} accept

        # Allow HTTP proxy from VM subnet (Envoy)
        ip saddr {vm_subnet} tcp dport {GATEWAY_ENVOY_PORT} accept

        # Allow deny-logger TCP listener (denied VM TCP lands here via DNAT)
        ip saddr {vm_subnet} tcp dport {GATEWAY_DENY_LOGGER_TCP_PORT} accept

        # Allow deny-logger /health probe (in-container only; no DNAT for it)
        tcp dport {GATEWAY_DENY_LOGGER_HEALTH_PORT} accept

        # Reject everything else (fast failure)
        reject
    }}
}}
"#,
    )
}

/// Generate the forward-allow rules that permit VM traffic to be forwarded
/// through the gateway to the outside world.
///
/// This replaces the initial deny-all forward chain with one that admits:
///
///   1. Traffic the prerouting chain DNAT'd to the gateway (TCP via
///      Envoy:10000, deny-logger:10001, CoreDNS:53). The DNAT rewrites
///      the destination to `gateway_ip` so the gateway-IP match captures
///      it.
///   2. VM-subnet UDP destined off-gateway. Allowed UDP `accept`s at
///      PREROUTING without DNAT, so its destination remains the
///      upstream IP. Denied UDP is `drop`-ed at PREROUTING via the
///      `log group N; drop` pair earlier on the chain, so by the time
///      UDP reaches FORWARD, it has already been filtered against the
///      policy allow-set; admitting all VM-subnet UDP at FORWARD is
///      therefore safe.
///   3. Established / related return traffic (kernel conntrack).
pub fn generate_forward_allow_ruleset(vm_subnet: &str, gateway_ip: &str) -> String {
    format!(
        r#"flush chain inet sandbox forward
table inet sandbox {{
    chain forward {{
        # Allow DNAT'd traffic (destination rewritten to gateway by prerouting)
        ip saddr {vm_subnet} ip daddr {gateway_ip} accept

        # Allow policy-allowed UDP. The prerouting chain's
        # `log group N; drop` rule has already filtered denied UDP, so
        # anything that reaches this chain is either explicitly allowed
        # or DNS (DNS-DNAT'd to gateway_ip and caught by the rule
        # above). Admitting VM-subnet UDP wholesale is the simplest
        # correct shape; defence-in-depth lives at PREROUTING.
        ip saddr {vm_subnet} meta l4proto udp accept

        # Allow established return traffic
        ct state established,related accept

        reject
    }}
}}
"#
    )
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // -- Naming tests -------------------------------------------------------

    #[test]
    fn test_gateway_container_name() {
        let session_id = SessionId::parse("550e8400e29b").unwrap();
        assert_eq!(container_name(&session_id), "sandbox-gw-550e8400e29b");
    }

    // -- Component probe tests ----------------------------------------------

    #[test]
    fn component_probe_returns_some_for_every_known_component() {
        for (probe_label, _log_name) in KNOWN_COMPONENTS {
            assert!(
                component_probe(probe_label).is_some(),
                "component_probe must have a probe for known component {probe_label:?} \
                 (KNOWN_COMPONENTS and component_probe must stay in sync)"
            );
        }
    }

    #[test]
    fn component_probe_returns_none_for_unknown_component() {
        assert!(component_probe("").is_none());
        assert!(component_probe("nope").is_none());
        // Rule out case-sensitivity accidents — the canonical form is
        // lowercase kebab-case and we must not silently accept other
        // shapes.
        assert!(component_probe("Envoy").is_none());
        assert!(component_probe("DENY-LOGGER").is_none());
        assert!(component_probe("deny_logger").is_none());
    }

    #[test]
    fn component_probe_deny_logger_uses_gateway_bridge_ip_not_loopback() {
        // The deny-logger listener binds on the gateway bridge IP (not
        // 127.0.0.1) because PREROUTING DNAT to loopback is dropped by
        // the kernel as a martian destination unless
        // `route_localnet=1` is set — and the gateway container does
        // not enable it. A regression to `127.0.0.1:10003` here would
        // produce false-negative health checks that match the exact
        // empirical failure Phase 4 fixed in healthcheck.sh, so guard
        // against it explicitly.
        let probe = component_probe("deny-logger").expect("deny-logger must be a known probe");

        // The probe must invoke a shell so `$(hostname -i)` expands at
        // probe time; `docker exec` passes argv straight to execve and
        // does not interpret `$(...)` itself.
        assert_eq!(
            probe.first().copied(),
            Some("sh"),
            "deny-logger probe must go through `sh -c` so hostname discovery \
             happens inside the gateway container, not on the host"
        );
        assert!(
            probe.iter().any(|arg| arg.contains("hostname -i")),
            "deny-logger probe must discover the bridge IP via `hostname -i` \
             (matches healthcheck.sh and entrypoint.sh)"
        );
        assert!(
            probe.iter().any(|arg| arg.contains(":10003/health")),
            "deny-logger probe must hit the health listener on port 10003"
        );
        assert!(
            !probe.iter().any(|arg| arg.contains("127.0.0.1:10003")),
            "deny-logger probe must NOT hardcode 127.0.0.1 — the listener \
             binds on the gateway bridge IP (see Phase 4 / healthcheck.sh)"
        );
    }

    #[test]
    fn known_components_contain_deny_logger_last() {
        // wait_for_components iterates KNOWN_COMPONENTS in order, so
        // the ordering guarantee matters: deny-logger last means a
        // deny-logger readiness failure surfaces only once the other
        // components are up (making the failure unambiguously
        // attributable to deny-logger rather than to an earlier
        // component blocking its startup).
        let labels: Vec<&str> = KNOWN_COMPONENTS.iter().map(|(l, _)| *l).collect();
        assert_eq!(
            labels,
            vec!["envoy", "coredns", "mitmproxy", "deny-logger"],
            "KNOWN_COMPONENTS order is load-bearing — deny-logger must be last"
        );
    }

    // -- Deny-all ruleset tests ---------------------------------------------

    #[test]
    fn test_deny_all_ruleset_well_formed() {
        let ruleset = generate_deny_all_ruleset();

        // Must define the sandbox table.
        assert!(
            ruleset.contains("table inet sandbox"),
            "must define 'table inet sandbox'"
        );

        // Must have input chain with drop policy.
        assert!(ruleset.contains("chain input"), "must define input chain");
        assert!(
            ruleset.contains("policy drop"),
            "input chain must have drop policy"
        );

        // Must have forward chain with drop policy.
        assert!(
            ruleset.contains("chain forward"),
            "must define forward chain"
        );

        // Must have output chain with accept policy.
        assert!(ruleset.contains("chain output"), "must define output chain");
        assert!(
            ruleset.contains("policy accept"),
            "output chain must have accept policy"
        );

        // Must allow loopback.
        assert!(
            ruleset.contains("iif lo accept"),
            "must allow loopback traffic"
        );

        // Must allow established/related.
        assert!(
            ruleset.contains("ct state established,related accept"),
            "must allow established/related connections"
        );

        // Must allow ICMP.
        assert!(
            ruleset.contains("ip protocol icmp accept"),
            "must allow ICMP"
        );

        // Must reject (not just drop) unmatched input for fast failure.
        assert!(
            ruleset.contains("reject"),
            "must reject unmatched traffic for fast failure"
        );
    }

    // -- DNAT ruleset tests -------------------------------------------------

    #[test]
    fn test_dnat_ruleset_with_correct_ips() {
        let ruleset = generate_dnat_ruleset("10.209.0.0/28", "10.209.0.2");

        // Must define the sandbox_dnat table.
        assert!(
            ruleset.contains("table inet sandbox_dnat"),
            "must define 'table inet sandbox_dnat'"
        );

        // Must declare both concat sets (filtering lives in
        // sandbox_dnat.prerouting, not sandbox_policy.forward).
        assert!(
            ruleset.contains("set policy_allow_tcp"),
            "must declare policy_allow_tcp concat set"
        );
        assert!(
            ruleset.contains("set policy_allow_udp"),
            "must declare policy_allow_udp concat set"
        );
        assert!(
            ruleset.contains("type ipv4_addr . inet_service"),
            "concat sets must be typed ipv4_addr . inet_service"
        );

        // Must have prerouting chain.
        assert!(
            ruleset.contains("chain prerouting"),
            "must define prerouting chain"
        );

        // DNS DNAT rules.
        assert!(
            ruleset.contains("ip saddr 10.209.0.0/28 udp dport 53 dnat to 10.209.0.2:53"),
            "must DNAT UDP DNS to CoreDNS"
        );
        assert!(
            ruleset.contains("ip saddr 10.209.0.0/28 tcp dport 53 dnat to 10.209.0.2:53"),
            "must DNAT TCP DNS to CoreDNS"
        );

        // Conditional DNAT to Envoy for policy-allowed TCP. Policy-
        // allowed UDP is `accept`-ed without DNAT (UDP allow path
        // skips Envoy).
        assert!(
            ruleset.contains(
                "ip saddr 10.209.0.0/28 meta l4proto tcp ip daddr . tcp dport \
                 @policy_allow_tcp dnat to 10.209.0.2:10000"
            ),
            "must conditionally DNAT policy-allowed TCP to Envoy:10000 via \
             @policy_allow_tcp set lookup:\n{ruleset}"
        );
        assert!(
            ruleset.contains(
                "ip saddr 10.209.0.0/28 meta l4proto udp ip daddr . udp dport \
                 @policy_allow_udp accept"
            ),
            "must `accept` policy-allowed UDP without DNAT so MASQUERADE \
             routes it directly to upstream (UDP allow path is direct):\n{ruleset}"
        );
        assert!(
            !ruleset.contains("@policy_allow_udp dnat to"),
            "DNAT-to-Envoy is forbidden for policy-allowed UDP \
             (Envoy is TCP-only and the allow path is direct):\n{ruleset}"
        );

        // Deny-logger fall-through DNAT rule for TCP. UDP does not
        // DNAT to a userland listener; it `log group {N}; drop`s.
        assert!(
            ruleset.contains("ip saddr 10.209.0.0/28 meta l4proto tcp dnat to 10.209.0.2:10001"),
            "must DNAT non-allowed VM TCP to deny-logger :10001:\n{ruleset}"
        );
        assert!(
            ruleset.contains("ip saddr 10.209.0.0/28 meta l4proto udp log group 1"),
            "must mirror unmatched VM UDP to NFLOG group 1 (kernel-side \
             deny path):\n{ruleset}"
        );
        assert!(
            ruleset.contains("ip saddr 10.209.0.0/28 meta l4proto udp drop"),
            "must drop unmatched VM UDP after the NFLOG mirror:\n{ruleset}"
        );
        assert!(
            !ruleset.contains("dnat to 10.209.0.2:10002"),
            "no UDP-to-:10002 DNAT should remain — the legacy userland \
             UDP listener has been replaced by the NFLOG-driven deny \
             path:\n{ruleset}"
        );

        // The old unconditional "tcp dport != 53 dnat to Envoy" rule is
        // gone; filtering now happens in sandbox_dnat itself via the
        // conditional-DNAT-to-Envoy and deny-logger fall-through rules.
        assert!(
            !ruleset.contains("tcp dport != 53 dnat to"),
            "must NOT retain the old unconditional 'tcp dport != 53' DNAT \
             rule:\n{ruleset}"
        );

        // Cloud metadata blocking.
        assert!(
            ruleset.contains("ip daddr 169.254.169.254 drop"),
            "must block cloud metadata endpoint"
        );

        // IPv6 drop (except loopback).
        assert!(
            ruleset.contains("ip6 daddr != ::1 drop"),
            "must drop non-loopback IPv6"
        );

        // MASQUERADE.
        assert!(
            ruleset.contains("chain postrouting"),
            "must define postrouting chain"
        );
        assert!(
            ruleset.contains("masquerade"),
            "must MASQUERADE outgoing traffic"
        );
    }

    #[test]
    fn test_dnat_ruleset_different_subnet() {
        let ruleset = generate_dnat_ruleset("10.209.0.16/28", "10.209.0.18");

        assert!(
            ruleset.contains("ip saddr 10.209.0.16/28"),
            "must use the provided subnet"
        );
        assert!(
            ruleset.contains("dnat to 10.209.0.18:53"),
            "must use the provided gateway IP for DNS"
        );
        assert!(
            ruleset.contains("dnat to 10.209.0.18:10000"),
            "must use the provided gateway IP for Envoy"
        );
        assert!(
            ruleset.contains("dnat to 10.209.0.18:10001"),
            "must use the provided gateway IP for deny-logger TCP"
        );
        // No UDP DNAT-to-listener: the UDP deny path is
        // `log group N; drop`. There must therefore be no
        // gateway-IP-prefixed :10002 DNAT in the ruleset.
        assert!(
            !ruleset.contains("dnat to 10.209.0.18:10002"),
            "no UDP-to-:10002 DNAT should remain (UDP deny is \
             NFLOG-driven, not via a userland listener):\n{ruleset}"
        );
    }

    #[test]
    fn generate_dnat_ruleset_routes_unmatched_tcp_to_listener_unmatched_udp_to_nflog() {
        // Explicit pin: non-allowed TCP DNATs to :10001
        // (deny-logger listener), non-allowed UDP is mirrored to NFLOG
        // group 1 and dropped (no userland listener). Any future
        // reshuffle that silently drops either arm would reintroduce
        // the silent-denial gap.
        let ruleset = generate_dnat_ruleset("10.10.10.0/28", "10.10.10.2");

        assert!(
            ruleset.contains("dnat to 10.10.10.2:10001"),
            "ruleset must DNAT denied TCP to deny-logger :10001:\n{ruleset}"
        );
        assert!(
            ruleset.contains("meta l4proto udp log group 1"),
            "ruleset must mirror denied UDP to NFLOG group 1:\n{ruleset}"
        );
        assert!(
            ruleset.contains("meta l4proto udp drop"),
            "ruleset must drop denied UDP after the NFLOG mirror:\n{ruleset}"
        );
    }

    #[test]
    fn generate_dnat_ruleset_orders_allow_before_deny() {
        // The conditional-DNAT-to-Envoy / accept-allowed-UDP rules must
        // appear *before* the unconditional fall-through rules
        // (deny-logger DNAT for TCP / NFLOG-then-drop for UDP),
        // otherwise nftables evaluates the first-match fall-through
        // and no traffic ever reaches Envoy / no UDP allow ever
        // succeeds.
        let ruleset = generate_dnat_ruleset("10.10.10.0/28", "10.10.10.2");

        let envoy_pos = ruleset
            .find("dnat to 10.10.10.2:10000")
            .expect("allow-to-Envoy rule must be present");
        let allow_udp_pos = ruleset
            .find("@policy_allow_udp accept")
            .expect("UDP allow-accept rule must be present");
        let deny_tcp_pos = ruleset
            .find("dnat to 10.10.10.2:10001")
            .expect("deny-logger TCP fall-through must be present");
        let deny_udp_pos = ruleset
            .find("meta l4proto udp log group")
            .expect("UDP NFLOG mirror must be present");

        assert!(
            envoy_pos < deny_tcp_pos,
            "allow-to-Envoy rule must appear before deny-logger TCP \
             fall-through; envoy_pos={envoy_pos} deny_tcp_pos={deny_tcp_pos} \
             ruleset:\n{ruleset}"
        );
        assert!(
            allow_udp_pos < deny_udp_pos,
            "UDP allow-accept rule must appear before UDP NFLOG \
             fall-through; allow_udp_pos={allow_udp_pos} \
             deny_udp_pos={deny_udp_pos} ruleset:\n{ruleset}"
        );
    }

    #[test]
    fn generate_dnat_ruleset_dns_precedes_filter_decision() {
        // DNS (port 53) must DNAT to CoreDNS *before* the policy-allow
        // and deny-logger rules are evaluated, otherwise a VM's first
        // DNS query would be misdirected to the deny-logger (and
        // subsequently RST'd) before it ever reaches CoreDNS.
        let ruleset = generate_dnat_ruleset("10.10.10.0/28", "10.10.10.2");

        let dns_pos = ruleset
            .find("udp dport 53 dnat to 10.10.10.2:53")
            .expect("DNS DNAT rule must be present");
        let allow_pos = ruleset
            .find("@policy_allow_tcp")
            .expect("policy-allow rule must be present");
        let deny_pos = ruleset
            .find("dnat to 10.10.10.2:10001")
            .expect("deny-logger fall-through must be present");

        assert!(
            dns_pos < allow_pos,
            "DNS rule must precede policy-allow rule; dns={dns_pos} \
             allow={allow_pos}"
        );
        assert!(
            dns_pos < deny_pos,
            "DNS rule must precede deny-logger fall-through; dns={dns_pos} \
             deny={deny_pos}"
        );
    }

    // -- Forward-allow ruleset tests ----------------------------------------

    #[test]
    fn test_forward_allow_ruleset() {
        let ruleset = generate_forward_allow_ruleset("10.209.0.0/28", "10.209.0.2");

        // Must flush the existing forward chain first.
        assert!(
            ruleset.contains("flush chain inet sandbox forward"),
            "must flush existing forward chain"
        );

        // Must allow forwarding from VM subnet ONLY to gateway IP (DNAT'd traffic).
        assert!(
            ruleset.contains("ip saddr 10.209.0.0/28 ip daddr 10.209.0.2 accept"),
            "must allow forwarding from VM subnet only to gateway IP\nruleset:\n{ruleset}"
        );

        // VM-subnet UDP that didn't get DNAT'd at PREROUTING (it was
        // either allowed via the allow-set accept, or DNS-DNAT'd to
        // gateway_ip and caught by the rule above) must still pass
        // forward. The allowed-UDP path does not route through Envoy,
        // so a strict gateway-IP-only rule would drop allowed UDP
        // destined to upstream IPs. Denied UDP is already filtered by
        // `nft drop` at PREROUTING, so admitting VM-subnet UDP
        // wholesale here is safe.
        assert!(
            ruleset.contains("ip saddr 10.209.0.0/28 meta l4proto udp accept"),
            "forward chain must admit VM-subnet UDP so the allow-path \
             datapath works (denied UDP is filtered \
             at PREROUTING):\n{ruleset}"
        );

        // The old TCP-blanket-accept regression must still not be
        // present — TCP is allow-only via the gateway-IP DNAT rule
        // above (only DNATted TCP makes it through).
        let has_tcp_blanket_accept = ruleset.lines().any(|line| {
            line.contains("ip saddr 10.209.0.0/28 accept")
                && !line.contains("ip daddr")
                && !line.contains("meta l4proto udp")
        });
        assert!(
            !has_tcp_blanket_accept,
            "must NOT have a TCP-or-untyped blanket accept without \
             daddr restriction:\n{ruleset}"
        );

        // Must allow established return traffic.
        assert!(
            ruleset.contains("ct state established,related accept"),
            "must allow established return traffic"
        );

        // Must reject unmatched.
        assert!(
            ruleset.contains("reject"),
            "must reject unmatched forwarded traffic"
        );
    }

    // -- Input-allow ruleset tests ------------------------------------------

    #[test]
    fn generate_input_allow_ruleset_has_no_tcp_8080_accept() {
        // mitmproxy runs in regular mode on 127.0.0.1:18080 — it is
        // no longer bound to 0.0.0.0:8080 in transparent mode. Nothing
        // in the VM subnet should reach mitmproxy directly over
        // TCP/8080 — Envoy terminates the connection and opens a
        // CONNECT tunnel to mitmproxy over loopback. The input-allow
        // chain must drop the stale accept so the gateway surface
        // remains tight.
        let ruleset = generate_input_allow_ruleset("10.209.0.0/28");

        assert!(
            !ruleset.contains("tcp dport 8080"),
            "sandbox input chain must no longer accept tcp dport 8080 \
             (mitmproxy runs on 127.0.0.1:18080):\n{ruleset}"
        );
        assert!(
            !ruleset.contains("tcp dport 18080"),
            "mitmproxy's 18080 is loopback-only and must NOT be opened to \
             the VM subnet:\n{ruleset}"
        );

        // The other intentional allows must stay intact.
        assert!(
            ruleset.contains("udp dport 53"),
            "DNS (UDP) must still be allowed from the VM subnet:\n{ruleset}"
        );
        assert!(
            ruleset.contains("tcp dport 53"),
            "DNS (TCP) must still be allowed from the VM subnet:\n{ruleset}"
        );
        assert!(
            ruleset.contains("tcp dport 10000"),
            "Envoy HTTP proxy port must still be allowed from the VM subnet:\n{ruleset}"
        );
    }

    #[test]
    fn generate_input_allow_ruleset_admits_10001_and_10003_but_not_10002() {
        // The deny-logger listens on TWO ports inside the gateway
        // container — TCP :10001 (denied VM TCP DNATted here) and
        // :10003 (the `/health` endpoint). The previous UDP listener
        // on :10002 is gone; UDP deny is NFLOG-driven and has no
        // userland listener. The input chain must admit :10001 and
        // :10003 but MUST NOT admit `:10002` — opening the port back
        // up would only paper over a regression that re-introduced the
        // listener.
        let ruleset = generate_input_allow_ruleset("10.209.0.0/28");

        assert!(
            ruleset.contains("tcp dport 10001"),
            "deny-logger TCP listener port :10001 must be admitted by the \
             input chain so DNATted denied VM TCP reaches it:\n{ruleset}"
        );
        assert!(
            !ruleset.contains("dport 10002"),
            "the legacy UDP listener at :10002 has been removed — \
             :10002 must not be admitted on the input chain anymore:\n{ruleset}"
        );
        assert!(
            ruleset.contains("tcp dport 10003"),
            "deny-logger /health endpoint port :10003 must be admitted by \
             the input chain so HEALTHCHECK and sandboxd's component_health \
             probe succeed:\n{ruleset}"
        );
    }

    // -- DockerHealth parser tests ------------------------------------------

    #[test]
    fn docker_health_parse_known_states() {
        // The four verdicts Docker documents for `.State.Health.Status`.
        // gateway_monitor's restart trigger keys off the Unhealthy
        // variant, so each mapping is load-bearing.
        assert_eq!(DockerHealth::parse("starting"), DockerHealth::Starting);
        assert_eq!(DockerHealth::parse("healthy"), DockerHealth::Healthy);
        assert_eq!(DockerHealth::parse("unhealthy"), DockerHealth::Unhealthy);
        assert_eq!(DockerHealth::parse("none"), DockerHealth::None);
    }

    #[test]
    fn docker_health_parse_strips_trailing_newline() {
        // `docker inspect` appends a trailing newline to its output —
        // if the parser does not trim whitespace, every real probe
        // lands on the catch-all Unknown branch and the refinement is
        // effectively dead. Exercise each verdict with the newline
        // Docker actually emits.
        assert_eq!(DockerHealth::parse("starting\n"), DockerHealth::Starting);
        assert_eq!(DockerHealth::parse("healthy\n"), DockerHealth::Healthy);
        assert_eq!(DockerHealth::parse("unhealthy\n"), DockerHealth::Unhealthy);
        assert_eq!(DockerHealth::parse("none\n"), DockerHealth::None);
    }

    #[test]
    fn docker_health_parse_no_healthcheck_configured() {
        // When no HEALTHCHECK directive is set, Go's `text/template`
        // renders the empty interface as the literal string
        // "<no value>". Older Docker versions / edge cases may render
        // as "none". Both must map to DockerHealth::None so the caller
        // knows to fall back to its own probe rather than treating the
        // missing verdict as a failure.
        assert_eq!(
            DockerHealth::parse("<no value>"),
            DockerHealth::None,
            "\"<no value>\" is Docker's render of an absent HEALTHCHECK \
             and must map to DockerHealth::None, not Unknown — the gateway \
             image ships with a HEALTHCHECK so this is unusual but defensible"
        );
        assert_eq!(DockerHealth::parse("<no value>\n"), DockerHealth::None);
    }

    #[test]
    fn docker_health_parse_empty_and_malformed_map_to_unknown() {
        // Empty output means the inspect call succeeded but produced
        // nothing parseable (container gone between the `running`
        // check and the health read, for instance). Malformed output
        // from a future / unsupported Docker version must also fall
        // through rather than silently mis-triggering a restart.
        assert_eq!(DockerHealth::parse(""), DockerHealth::Unknown);
        assert_eq!(DockerHealth::parse("\n"), DockerHealth::Unknown);
        assert_eq!(DockerHealth::parse("   "), DockerHealth::Unknown);
        assert_eq!(
            DockerHealth::parse("HEALTHY"),
            DockerHealth::Unknown,
            "Docker emits the lowercase form; anything else is not the \
             canonical verdict and must not be interpreted"
        );
        assert_eq!(DockerHealth::parse("up"), DockerHealth::Unknown);
        assert_eq!(
            DockerHealth::parse("unhealthy: deny-logger down"),
            DockerHealth::Unknown,
            "Docker does not append reasons to Health.Status — any \
             adorned verdict is malformed and must fall through rather \
             than matching the Unhealthy arm by prefix"
        );
    }

    #[test]
    fn docker_health_variants_are_all_distinct() {
        // `gateway_monitor` drives restart off a match on this enum:
        //
        //   Healthy   → no-op
        //   Starting  → no-op, log at debug
        //   Unhealthy → restart
        //   None      → fall back to `gateway_status`
        //   Unknown   → fall back to `gateway_status`
        //
        // Two variants collapsing to the same value would let a
        // future refactor silently re-route one to the other's arm —
        // e.g. `Starting == Healthy` would let a start-period
        // container be treated as healthy, and `Unhealthy ==
        // Unknown` would downgrade a real restart trigger to the
        // fallback probe. Enumerate the full cross-product so any
        // accidental identity gets caught at `cargo test` time rather
        // than during a post-incident review.
        let all = [
            DockerHealth::Starting,
            DockerHealth::Healthy,
            DockerHealth::Unhealthy,
            DockerHealth::None,
            DockerHealth::Unknown,
        ];
        for (i, a) in all.iter().enumerate() {
            for (j, b) in all.iter().enumerate() {
                if i == j {
                    assert_eq!(a, b, "variant must equal itself: {a:?}");
                } else {
                    assert_ne!(
                        a, b,
                        "DockerHealth variants must be pairwise distinct — \
                         gateway_monitor's restart/fallback decisions rely \
                         on the match arms not collapsing: {a:?} vs {b:?}"
                    );
                }
            }
        }
    }
}
