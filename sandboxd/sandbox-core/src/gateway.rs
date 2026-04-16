use std::path::Path;
use std::process::Command;
use std::thread;
use std::time::{Duration, Instant};

use tracing::{debug, info, warn};
use uuid::Uuid;

use crate::error::SandboxError;
use crate::network::NetworkInfo;
use crate::process::run_with_timeout;

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// Health status of a gateway container.
#[derive(Debug, Clone, PartialEq)]
pub enum GatewayStatus {
    /// All components (Envoy, CoreDNS, mitmproxy) are healthy.
    Healthy,
    /// At least one component reported unhealthy.
    Unhealthy(String),
    /// The container is not running (or does not exist).
    NotRunning,
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Docker image name for the gateway container (built in M3-S1).
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
        session_id: &Uuid,
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
            Command::new("docker")
                .args(["rm", "--force", &container_name]),
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

        let args_refs: Vec<&str> =
            args.iter().map(|s| s.as_str()).collect();
        let output = run_with_timeout(
            Command::new("docker")
                .args(&args_refs),
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

        // Step 2: Write the initial DNS policy file if one was provided.
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
    pub fn stop_gateway(&self, session_id: &Uuid) -> Result<(), SandboxError> {
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
            Command::new("docker")
                .args(["stop", "--time", "10", &container_name]),
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
            Command::new("docker")
                .args(["rm", "--force", &container_name]),
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
        session_id: &Uuid,
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

    /// Check gateway health by running the healthcheck script inside the
    /// container.
    pub fn gateway_status(
        &self,
        session_id: &Uuid,
    ) -> Result<GatewayStatus, SandboxError> {
        let container_name = container_name(session_id);

        // First check if the container is running.
        let output = run_with_timeout(
            Command::new("docker")
                .args([
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

        let running =
            String::from_utf8_lossy(&output.stdout).trim().to_string();
        if running != "true" {
            return Ok(GatewayStatus::NotRunning);
        }

        // Run the healthcheck script.
        let output = run_with_timeout(
            Command::new("docker")
                .args(["exec", &container_name, "/healthcheck.sh"]),
            DOCKER_INSPECT_TIMEOUT,
            "docker exec (healthcheck)",
        )
        .map_err(|e| match e {
            SandboxError::Internal(msg) if msg.contains("failed to spawn") => {
                SandboxError::Gateway(format!("failed to run healthcheck: {msg}"))
            }
            other => other,
        })?;

        let stdout =
            String::from_utf8_lossy(&output.stdout).trim().to_string();

        if output.status.success() {
            Ok(GatewayStatus::Healthy)
        } else {
            Ok(GatewayStatus::Unhealthy(stdout))
        }
    }

    /// Return the container status as a string: "running", "stopped", or
    /// "not_found".
    pub fn container_status_str(&self, session_id: &Uuid) -> String {
        let container_name = container_name(session_id);

        let output = run_with_timeout(
            Command::new("docker")
                .args([
                    "inspect",
                    "--format",
                    "{{.State.Status}}",
                    &container_name,
                ]),
            DOCKER_INSPECT_TIMEOUT,
            "docker inspect (container status)",
        );

        match output {
            Ok(o) if o.status.success() => {
                String::from_utf8_lossy(&o.stdout).trim().to_string()
            }
            _ => "not_found".to_string(),
        }
    }

    /// Check the health of a single component inside the gateway container.
    ///
    /// Returns "healthy", "unhealthy", or "unknown" (if the container is not
    /// running or the check cannot be performed).
    pub fn component_health(
        &self,
        session_id: &Uuid,
        component: &str,
    ) -> String {
        let container_name = container_name(session_id);

        let check_cmd: &[&str] = match component {
            "envoy" => {
                &["curl", "-sf", "http://127.0.0.1:9901/ready"]
            }
            "coredns" => {
                &["curl", "-sf", "http://127.0.0.1:8180/health"]
            }
            "mitmproxy" => &["pgrep", "-x", "mitmdump"],
            _ => return "unknown".to_string(),
        };

        let mut args = vec!["exec", &container_name];
        args.extend(check_cmd);

        match run_with_timeout(
            Command::new("docker").args(&args),
            DOCKER_INSPECT_TIMEOUT,
            &format!("docker exec ({component} health)"),
        ) {
            Ok(output) if output.status.success() => {
                "healthy".to_string()
            }
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
    pub fn inject_deny_all(&self, session_id: &Uuid) -> Result<(), SandboxError> {
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
        session_id: &Uuid,
        network_info: &NetworkInfo,
        container_ip: &str,
    ) -> Result<(), SandboxError> {
        let ruleset = generate_dnat_ruleset(
            &network_info.subnet,
            container_ip,
        );
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
        session_id: &Uuid,
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
        session_id: &Uuid,
        ruleset: &str,
        label: &str,
    ) -> Result<(), SandboxError> {
        self.inject_nftables_ruleset(session_id, ruleset, label)
    }

    /// Remove the DNAT nftables rules from the gateway container's network
    /// namespace. Called before shutdown to stop routing new traffic.
    pub fn remove_dnat_rules(&self, session_id: &Uuid) -> Result<(), SandboxError> {
        let ruleset = "delete table inet sandbox_dnat\n";
        self.inject_nftables_ruleset(session_id, ruleset, "remove-DNAT")
    }

    // -- Internal helpers ------------------------------------------------------

    /// Get the IP address of the gateway container on its Docker network.
    ///
    /// With /28 subnets the gateway container gets an explicit IP via `--ip`,
    /// but this method is retained for verification and integration tests.
    pub fn container_ip(&self, session_id: &Uuid) -> Result<String, SandboxError> {
        let container_name = container_name(session_id);

        let output = run_with_timeout(
            Command::new("docker")
                .args([
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
        session_id: &Uuid,
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
                SandboxError::Gateway(format!(
                    "failed to spawn {label} nftables injection: {e}"
                ))
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
                Ok(Some(_)) => break child.wait_with_output().map_err(|e| {
                    SandboxError::Gateway(format!(
                        "failed to collect output from {label} nftables injection: {e}"
                    ))
                })?,
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
    fn wait_for_components(&self, session_id: &Uuid) -> Result<(), SandboxError> {
        let container_name = container_name(session_id);
        let deadline = Instant::now() + COMPONENT_READY_TIMEOUT;

        info!(
            session_id = %session_id,
            timeout_secs = COMPONENT_READY_TIMEOUT.as_secs(),
            "waiting for gateway components to become ready"
        );

        // Wait for Envoy readiness (admin endpoint).
        self.wait_for_component(
            &container_name,
            "Envoy",
            &["curl", "-sf", "http://127.0.0.1:9901/ready"],
            deadline,
        )?;

        // Wait for CoreDNS readiness (health endpoint).
        self.wait_for_component(
            &container_name,
            "CoreDNS",
            &["curl", "-sf", "http://127.0.0.1:8180/health"],
            deadline,
        )?;

        // Wait for mitmproxy readiness (process check).
        self.wait_for_component(
            &container_name,
            "mitmproxy",
            &["pgrep", "-x", "mitmdump"],
            deadline,
        )?;

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

        while Instant::now() < deadline {
            let mut args = vec!["exec", container_name];
            args.extend(check_cmd);

            let output = Command::new("docker")
                .args(&args)
                .output()
                .map_err(|e| {
                    SandboxError::Gateway(format!(
                        "failed to check {component_name} readiness: {e}"
                    ))
                })?;

            if output.status.success() {
                debug!(
                    container = container_name,
                    component = component_name,
                    "component is ready"
                );
                return Ok(());
            }

            thread::sleep(COMPONENT_POLL_INTERVAL);
        }

        Err(SandboxError::Gateway(format!(
            "{component_name} did not become ready within {}s",
            COMPONENT_READY_TIMEOUT.as_secs()
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
pub fn container_name(session_id: &Uuid) -> String {
    format!("sandbox-gw-{session_id}")
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
/// - DNS (port 53) -> CoreDNS
/// - All other TCP -> Envoy (port 10000)
/// - Block cloud metadata (169.254.169.254)
/// - Drop non-loopback IPv6
/// - MASQUERADE outgoing traffic
pub fn generate_dnat_ruleset(vm_subnet: &str, gateway_ip: &str) -> String {
    format!(
        r#"table inet sandbox_dnat {{
    chain prerouting {{
        type nat hook prerouting priority dstnat;

        # DNS -> CoreDNS (port 53)
        ip saddr {vm_subnet} udp dport 53 dnat to {gateway_ip}:53
        ip saddr {vm_subnet} tcp dport 53 dnat to {gateway_ip}:53

        # TCP -> Envoy (port 10000) for all other TCP traffic
        ip saddr {vm_subnet} tcp dport != 53 dnat to {gateway_ip}:10000

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
"#
    )
}

/// Generate rules that open the input chain for service ports.
///
/// The initial deny-all ruleset blocks all inbound traffic.  After DNAT
/// is configured, traffic from the VM subnet is rewritten to the
/// gateway's own IP on port 53 (DNS), 10000 (Envoy proxy), or
/// 8080 (mitmproxy for L3 HTTPS inspection).  The input chain must
/// accept this traffic, otherwise the DNATted/redirected packets are
/// rejected.
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
        ip saddr {vm_subnet} udp dport 53 accept
        ip saddr {vm_subnet} tcp dport 53 accept

        # Allow HTTP proxy from VM subnet (Envoy)
        ip saddr {vm_subnet} tcp dport 10000 accept

        # Allow HTTPS inspection from VM subnet (mitmproxy, L3 redirect)
        ip saddr {vm_subnet} tcp dport 8080 accept

        # Reject everything else (fast failure)
        reject
    }}
}}
"#
    )
}

/// Generate the forward-allow rules that permit VM traffic to be forwarded
/// through the gateway to the outside world.
///
/// This replaces the initial deny-all forward chain with one that allows
/// forwarding from the VM subnet and established return traffic.
pub fn generate_forward_allow_ruleset(vm_subnet: &str, gateway_ip: &str) -> String {
    // We use "table inet sandbox" with just the chain we want to replace.
    // nft merges chain definitions, but since we're replacing the forward chain,
    // we first flush it and then add the new rules.
    //
    // After DNAT in the prerouting chain, legitimate traffic has its destination
    // rewritten to the gateway IP.  Non-DNS UDP has no DNAT rule and retains its
    // original external destination.  By requiring `ip daddr {gateway_ip}` we
    // only allow traffic that was successfully DNAT'd, blocking non-DNS UDP that
    // would otherwise escape the sandbox unproxied.
    format!(
        r#"flush chain inet sandbox forward
table inet sandbox {{
    chain forward {{
        # Allow DNAT'd traffic (destination rewritten to gateway by prerouting)
        ip saddr {vm_subnet} ip daddr {gateway_ip} accept

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
        let session_id =
            Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap();
        assert_eq!(
            container_name(&session_id),
            "sandbox-gw-550e8400-e29b-41d4-a716-446655440000"
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
        assert!(
            ruleset.contains("chain input"),
            "must define input chain"
        );
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
        assert!(
            ruleset.contains("chain output"),
            "must define output chain"
        );
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

        // TCP DNAT to Envoy (excluding DNS).
        assert!(
            ruleset.contains(
                "ip saddr 10.209.0.0/28 tcp dport != 53 dnat to 10.209.0.2:10000"
            ),
            "must DNAT non-DNS TCP to Envoy"
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

        // Must NOT have a blanket accept from VM subnet (the old security gap).
        let has_blanket_accept = ruleset.lines().any(|line| {
            line.contains("ip saddr 10.209.0.0/28 accept")
                && !line.contains("ip daddr")
        });
        assert!(
            !has_blanket_accept,
            "must NOT have blanket accept without daddr restriction\nruleset:\n{ruleset}"
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

}
