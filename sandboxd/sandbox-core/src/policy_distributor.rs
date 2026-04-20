use std::process::Command;

use tracing::{debug, error, info, warn};

use crate::atomic_listener_writer::{AtomicListenerWriter, session_listener_host_path};
use crate::error::SandboxError;
use crate::gateway::{self, GatewayManager};
use crate::policy::{BOOTSTRAP_FILE_IN_CONTAINER, CompiledPolicy, PolicyCompiler};
use crate::session::SessionId;

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
    envoy_bootstrap_written: bool,
    envoy_listener_written: bool,
}

// ---------------------------------------------------------------------------
// PolicyDistributor
// ---------------------------------------------------------------------------

/// Distributes compiled policy configurations to gateway components.
///
/// Distribution is atomic: if any step fails, all previously completed
/// steps are rolled back to the previous configuration.
///
/// **M9-S18**: Envoy config is split into a **static bootstrap**
/// (`envoy-bootstrap.yaml`) and a **dynamic listener file**
/// (`listeners/listener.yaml`, served via filesystem LDS). The bootstrap
/// is written via `docker exec`; the listener file is written on the host
/// into a bind-mounted directory via
/// [`AtomicListenerWriter`](crate::AtomicListenerWriter), producing a
/// `MovedTo` inotify event that triggers Envoy's LDS reload without a
/// listener drain. See
/// `.tasks/specs/2026-04-19-l3-envoy-mitmproxy-flow-design.md` and
/// upstream Envoy issue `#20474` for the constraints this design
/// respects.
pub struct PolicyDistributor;

impl PolicyDistributor {
    /// Distribute a compiled policy to all gateway components.
    ///
    /// Steps (in order):
    /// 1. Write CoreDNS policy file to gateway container
    /// 2. Write mitmproxy policy JSON to gateway container
    /// 3. Update nftables rules via docker exec
    /// 4. Write Envoy static bootstrap via `docker exec`
    /// 5. Atomically rewrite the LDS-served listener file on the host
    ///    (Envoy picks up the change via `MovedTo` inotify event; no
    ///    listener drain, no process restart)
    ///
    /// On partial failure, previously completed steps are rolled back.
    pub fn distribute(
        session_id: &SessionId,
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
            let _ =
                gateway.inject_nftables_ruleset_public(session_id, flush_script, "policy-flush");
            debug!(session_id = %session_id, "flushed stale sandbox_policy table (if any)");
        }

        // Step 4: Write Envoy static bootstrap to the container.
        //
        // The bootstrap is policy-agnostic, so the same content is
        // rewritten on every distribution. The write is cheap (a few KB
        // via `docker exec ... > file`) and keeps rollback handling
        // uniform across all four components.
        if let Err(e) = write_file_to_container(
            &container,
            BOOTSTRAP_FILE_IN_CONTAINER,
            &compiled.envoy_bootstrap_config,
        ) {
            error!(
                session_id = %session_id,
                error = %e,
                "failed to write Envoy bootstrap"
            );
            Self::rollback_steps(session_id, &state, &previous);
            return Err(e);
        }
        state.envoy_bootstrap_written = true;
        debug!(session_id = %session_id, "Envoy bootstrap written");

        // Step 5: Atomically rewrite the LDS-served listener file.
        //
        // The listener file lives in a per-session host directory
        // bind-mounted into the container as
        // [`crate::policy::LISTENER_DIR_IN_CONTAINER`]. The atomic
        // writer enforces the "only filter_chains differ" invariant
        // between generations so Envoy can pick up the new config via
        // LDS without draining the listener.
        let listener_path = session_listener_host_path(session_id);
        let writer = AtomicListenerWriter::new(&listener_path);
        if let Err(e) = writer.write(&compiled.envoy_listener_config) {
            error!(
                session_id = %session_id,
                path = %listener_path.display(),
                error = %e,
                "failed to atomically write Envoy listener file"
            );
            Self::rollback_steps(session_id, &state, &previous);
            return Err(SandboxError::Gateway(format!(
                "Envoy listener write failed: {e}"
            )));
        }
        #[allow(unused_assignments)]
        // Consistent with prior steps; enables rollback if steps are added.
        {
            state.envoy_listener_written = true;
        }
        debug!(session_id = %session_id, "Envoy listener file written (LDS will pick up)");

        info!(
            session_id = %session_id,
            "policy distribution complete"
        );

        Ok(())
    }

    /// Rollback previously completed distribution steps.
    fn rollback_steps(
        session_id: &SessionId,
        state: &DistributionState,
        previous: &PreviousConfigs,
    ) {
        let container = gateway::container_name(session_id);

        warn!(
            session_id = %session_id,
            "rolling back policy distribution"
        );

        // Revert listener file to previous generation (or to the
        // deny-all initial listener if there was none). The
        // AtomicListenerWriter will enforce the invariant on this
        // restoration write; if the invariant check fails we log and
        // move on — a failed rollback is not worse than a failed
        // forward write at this stage.
        if state.envoy_listener_written {
            let listener_path = session_listener_host_path(session_id);
            let restore_content = previous
                .envoy_listener
                .clone()
                .unwrap_or_else(PolicyCompiler::compile_initial_envoy_listener);
            let writer = AtomicListenerWriter::new(&listener_path);
            if let Err(e) = writer.write(&restore_content) {
                warn!(
                    session_id = %session_id,
                    path = %listener_path.display(),
                    error = %e,
                    "failed to roll back Envoy listener file"
                );
            }
        }

        if state.envoy_bootstrap_written {
            if let Some(ref config) = previous.envoy_bootstrap {
                let _ = write_file_to_container(&container, BOOTSTRAP_FILE_IN_CONTAINER, config);
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
                let _ = write_file_to_container(&container, "/tmp/mitmproxy/policy.json", config);
            }
        }

        if state.coredns_written {
            if let Some(ref config) = previous.coredns {
                let _ = write_file_to_container(&container, "/etc/coredns/policy.conf", config);
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
    envoy_bootstrap: Option<String>,
    envoy_listener: Option<String>,
}

impl PreviousConfigs {
    /// Best-effort read of current configs from the container (and the
    /// host-side listener file).
    fn read(session_id: &SessionId) -> Self {
        let container = gateway::container_name(session_id);

        let coredns = read_file_from_container(&container, "/etc/coredns/policy.conf").ok();
        let mitmproxy = read_file_from_container(&container, "/tmp/mitmproxy/policy.json").ok();
        let envoy_bootstrap =
            read_file_from_container(&container, BOOTSTRAP_FILE_IN_CONTAINER).ok();

        // The listener file is on the host (bind-mounted into the
        // container) — read it directly so rollback works even if the
        // container is partially broken.
        let listener_path = session_listener_host_path(session_id);
        let envoy_listener = std::fs::read_to_string(&listener_path).ok();

        // Reading current nftables state from the namespace.
        let nftables = read_nftables_state(session_id).ok();

        Self {
            coredns,
            mitmproxy,
            nftables,
            envoy_bootstrap,
            envoy_listener,
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
        .args([
            "exec",
            "-i",
            container,
            "sh",
            "-c",
            &format!("cat > '{path}'"),
        ])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| {
            SandboxError::Gateway(format!("failed to write {path} to {container}: {e}"))
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
fn read_file_from_container(container: &str, path: &str) -> Result<String, SandboxError> {
    let output = Command::new("docker")
        .args(["exec", container, "cat", path])
        .output()
        .map_err(|e| {
            SandboxError::Gateway(format!("failed to read {path} from {container}: {e}"))
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
fn read_nftables_state(session_id: &SessionId) -> Result<String, SandboxError> {
    let container = gateway::container_name(session_id);

    let output = Command::new("docker")
        .args([
            "exec",
            &container,
            "nft",
            "list",
            "table",
            "inet",
            "sandbox_policy",
        ])
        .output()
        .map_err(|e| SandboxError::Gateway(format!("failed to list nftables policy table: {e}")))?;

    if !output.status.success() {
        // Table may not exist yet -- that's OK.
        return Ok(String::new());
    }

    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}
