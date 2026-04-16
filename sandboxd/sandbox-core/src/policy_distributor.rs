use std::process::Command;

use tracing::{debug, error, info, warn};
use uuid::Uuid;

use crate::error::SandboxError;
use crate::gateway::{self, GatewayManager};
use crate::policy::CompiledPolicy;

// ---------------------------------------------------------------------------
// Distribution step tracking (for rollback)
// ---------------------------------------------------------------------------

/// Records which distribution steps have completed, enabling rollback on
/// partial failure.
#[derive(Debug, Default)]
struct DistributionState {
    coredns_written: bool,
    mitmproxy_written: bool,
    nftables_injected: bool,
    envoy_written: bool,
}

// ---------------------------------------------------------------------------
// PolicyDistributor
// ---------------------------------------------------------------------------

/// Distributes compiled policy configurations to gateway components.
///
/// Distribution is atomic: if any step fails, all previously completed
/// steps are rolled back to the previous configuration.
pub struct PolicyDistributor;

impl PolicyDistributor {
    /// Distribute a compiled policy to all gateway components.
    ///
    /// Steps (in order):
    /// 1. Write CoreDNS policy file to gateway container
    /// 2. Write mitmproxy policy JSON to gateway container
    /// 3. Update nftables rules via docker exec
    /// 4. Write Envoy config and signal reload
    ///
    /// On partial failure, previously completed steps are rolled back.
    pub fn distribute(
        session_id: &Uuid,
        compiled: &CompiledPolicy,
        gateway: &GatewayManager,
    ) -> Result<(), SandboxError> {
        let container = gateway::container_name(session_id);
        let mut state = DistributionState::default();

        info!(
            session_id = %session_id,
            container = %container,
            "distributing compiled policy to gateway components"
        );

        // Read previous configs for rollback (best-effort).
        let previous = PreviousConfigs::read(session_id);

        // Step 1: Write CoreDNS policy file.
        if let Err(e) = write_file_to_container(
            &container,
            "/etc/coredns/policy.conf",
            &compiled.coredns_config,
        ) {
            error!(
                session_id = %session_id,
                error = %e,
                "failed to write CoreDNS policy"
            );
            return Err(e);
        }
        state.coredns_written = true;
        debug!(session_id = %session_id, "CoreDNS policy written");

        // Step 2: Write mitmproxy policy JSON.
        if let Err(e) = write_file_to_container(
            &container,
            "/tmp/mitmproxy/policy.json",
            &compiled.mitmproxy_config,
        ) {
            error!(
                session_id = %session_id,
                error = %e,
                "failed to write mitmproxy policy"
            );
            Self::rollback_steps(session_id, &state, &previous);
            return Err(e);
        }
        state.mitmproxy_written = true;
        debug!(session_id = %session_id, "mitmproxy policy written");

        // Step 3: Inject nftables rules.
        if !compiled.nftables_rules.is_empty() {
            if let Err(e) = gateway.inject_nftables_ruleset_public(
                session_id,
                &compiled.nftables_rules,
                "policy-distribute",
            ) {
                error!(
                    session_id = %session_id,
                    error = %e,
                    "failed to inject nftables policy rules"
                );
                Self::rollback_steps(session_id, &state, &previous);
                return Err(e);
            }
            state.nftables_injected = true;
            debug!(session_id = %session_id, "nftables policy rules injected");
        } else {
            // When no nftables rules are needed, flush any stale
            // sandbox_policy table left from a previous policy distribution.
            let flush_script = "delete table inet sandbox_policy\n";
            let _ = gateway.inject_nftables_ruleset_public(
                session_id,
                flush_script,
                "policy-flush",
            );
            debug!(session_id = %session_id, "flushed stale sandbox_policy table (if any)");
        }

        // Step 4: Write Envoy config and trigger reload.
        if let Err(e) = write_file_to_container(
            &container,
            "/etc/envoy/envoy.yaml",
            &compiled.envoy_config,
        ) {
            error!(
                session_id = %session_id,
                error = %e,
                "failed to write Envoy config"
            );
            Self::rollback_steps(session_id, &state, &previous);
            return Err(e);
        }
        #[allow(unused_assignments)] // Consistent with prior steps; enables rollback if steps are added.
        { state.envoy_written = true; }
        debug!(session_id = %session_id, "Envoy config written");

        // Signal Envoy to reload by hitting the admin endpoint.
        // Envoy's admin API at :9901/quitquitquit would kill it; instead we
        // use the hot restart mechanism or rely on file watch. Since our
        // gateway Envoy is configured with --restart-epoch, we send a POST
        // to /drain_listeners to gracefully re-read config. However, the
        // simplest reliable approach is to kill and let supervisord/entrypoint
        // restart it with the new config.
        if let Err(e) = reload_envoy(&container) {
            warn!(
                session_id = %session_id,
                error = %e,
                "failed to signal Envoy reload (Envoy will pick up config on next restart)"
            );
            // Non-fatal: Envoy will eventually restart via the gateway
            // container's process supervisor.
        }

        info!(
            session_id = %session_id,
            "policy distribution complete"
        );

        Ok(())
    }

    /// Rollback previously completed distribution steps.
    fn rollback_steps(
        session_id: &Uuid,
        state: &DistributionState,
        previous: &PreviousConfigs,
    ) {
        let container = gateway::container_name(session_id);

        warn!(
            session_id = %session_id,
            "rolling back policy distribution"
        );

        if state.envoy_written {
            if let Some(ref config) = previous.envoy {
                let _ = write_file_to_container(&container, "/etc/envoy/envoy.yaml", config);
                let _ = reload_envoy(&container);
            }
        }

        if state.nftables_injected {
            if let Some(ref rules) = previous.nftables {
                // Re-inject previous nftables rules. If there were none, flush
                // the policy table.
                if rules.is_empty() {
                    let flush = "delete table inet sandbox_policy\n";
                    let gateway = GatewayManager::new();
                    let _ = gateway.inject_nftables_ruleset_public(
                        session_id,
                        flush,
                        "policy-rollback",
                    );
                } else {
                    let gateway = GatewayManager::new();
                    let _ = gateway.inject_nftables_ruleset_public(
                        session_id,
                        rules,
                        "policy-rollback",
                    );
                }
            }
        }

        if state.mitmproxy_written {
            if let Some(ref config) = previous.mitmproxy {
                let _ = write_file_to_container(
                    &container,
                    "/tmp/mitmproxy/policy.json",
                    config,
                );
            }
        }

        if state.coredns_written {
            if let Some(ref config) = previous.coredns {
                let _ = write_file_to_container(
                    &container,
                    "/etc/coredns/policy.conf",
                    config,
                );
            }
        }

        warn!(
            session_id = %session_id,
            "policy distribution rollback complete"
        );
    }
}

// ---------------------------------------------------------------------------
// Previous config snapshot (for rollback)
// ---------------------------------------------------------------------------

/// Snapshot of previous configurations read from the gateway container.
#[derive(Debug, Default)]
struct PreviousConfigs {
    coredns: Option<String>,
    mitmproxy: Option<String>,
    nftables: Option<String>,
    envoy: Option<String>,
}

impl PreviousConfigs {
    /// Best-effort read of current configs from the container.
    fn read(session_id: &Uuid) -> Self {
        let container = gateway::container_name(session_id);

        let coredns = read_file_from_container(&container, "/etc/coredns/policy.conf").ok();
        let mitmproxy =
            read_file_from_container(&container, "/tmp/mitmproxy/policy.json").ok();
        let envoy = read_file_from_container(&container, "/etc/envoy/envoy.yaml").ok();

        // Reading current nftables state from the namespace.
        let nftables = read_nftables_state(session_id).ok();

        Self {
            coredns,
            mitmproxy,
            nftables,
            envoy,
        }
    }
}

// ---------------------------------------------------------------------------
// Container file I/O helpers
// ---------------------------------------------------------------------------

/// Write content to a file inside a Docker container.
///
/// Uses `docker exec sh -c 'cat > path'` with the content piped to stdin.
pub fn write_file_to_container(
    container: &str,
    path: &str,
    content: &str,
) -> Result<(), SandboxError> {
    use std::io::Write;

    let mut child = Command::new("docker")
        .args(["exec", "-i", container, "sh", "-c", &format!("cat > '{path}'")])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| {
            SandboxError::Gateway(format!(
                "failed to write {path} to {container}: {e}"
            ))
        })?;

    if let Some(ref mut stdin) = child.stdin {
        stdin.write_all(content.as_bytes()).map_err(|e| {
            SandboxError::Gateway(format!(
                "failed to pipe content to {path} in {container}: {e}"
            ))
        })?;
    }
    // Drop stdin to signal EOF.
    child.stdin.take();

    let output = child.wait_with_output().map_err(|e| {
        SandboxError::Gateway(format!(
            "failed to complete write of {path} to {container}: {e}"
        ))
    })?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(SandboxError::Gateway(format!(
            "write to {path} in {container} failed: {stderr}"
        )));
    }

    Ok(())
}

/// Read a file from inside a Docker container.
fn read_file_from_container(
    container: &str,
    path: &str,
) -> Result<String, SandboxError> {
    let output = Command::new("docker")
        .args(["exec", container, "cat", path])
        .output()
        .map_err(|e| {
            SandboxError::Gateway(format!(
                "failed to read {path} from {container}: {e}"
            ))
        })?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(SandboxError::Gateway(format!(
            "cat {path} in {container} failed: {stderr}"
        )));
    }

    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

/// Read the current nftables sandbox_policy table state from the container
/// via `docker exec`.
fn read_nftables_state(session_id: &Uuid) -> Result<String, SandboxError> {
    let container = gateway::container_name(session_id);

    let output = Command::new("docker")
        .args([
            "exec", &container,
            "nft", "list", "table", "inet", "sandbox_policy",
        ])
        .output()
        .map_err(|e| {
            SandboxError::Gateway(format!("failed to list nftables policy table: {e}"))
        })?;

    if !output.status.success() {
        // Table may not exist yet -- that's OK.
        return Ok(String::new());
    }

    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

/// Signal the gateway entrypoint to restart Envoy with the updated config.
///
/// We send SIGHUP to PID 1 (the entrypoint script) inside the container.
/// The entrypoint's SIGHUP trap kills the current Envoy process and starts
/// a new one with the updated `/etc/envoy/envoy.yaml`.
fn reload_envoy(container: &str) -> Result<(), SandboxError> {
    let output = Command::new("docker")
        .args(["exec", container, "kill", "-HUP", "1"])
        .output()
        .map_err(|e| {
            SandboxError::Gateway(format!(
                "failed to signal Envoy reload in {container}: {e}"
            ))
        })?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(SandboxError::Gateway(format!(
            "Envoy reload signal failed in {container}: {stderr}"
        )));
    }

    Ok(())
}
