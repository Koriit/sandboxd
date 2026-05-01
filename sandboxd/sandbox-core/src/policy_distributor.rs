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
/// Envoy config is split into a **static bootstrap**
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
            // sandbox_policy table left from a previous policy
            // distribution. `sandbox_dnat` is intentionally left
            // intact — its chain shape was laid down at create_gateway
            // time and an empty policy means empty concat sets, which
            // the chain already fall-throughs to the deny-logger for
            // (exactly the fail-closed behaviour we want). Use the
            // idempotent `add table` + `delete table` idiom so the
            // flush is safe whether or not `sandbox_policy` currently
            // exists.
            let flush_script = "table inet sandbox_policy {}\n\
                                delete table inet sandbox_policy\n";
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
                let gateway = GatewayManager::new();
                if rules.is_empty() {
                    // No prior policy state: flush sandbox_policy via
                    // the idempotent idiom. sandbox_dnat is left
                    // intact (its chain shape was laid down at
                    // create_gateway time; empty concat sets already
                    // give fail-closed behaviour).
                    let flush = "table inet sandbox_policy {}\n\
                                 delete table inet sandbox_policy\n";
                    let _ = gateway.inject_nftables_ruleset_public(
                        session_id,
                        flush,
                        "policy-rollback",
                    );
                } else {
                    // Re-inject the previous two-table snapshot. The
                    // snapshot came from `read_nftables_state` as raw
                    // `nft list table` output for each table; prepend
                    // idempotent flushes so re-injection replaces
                    // rather than merges on top of the half-applied
                    // state we are rolling back from.
                    let restore = format!(
                        "table inet sandbox_dnat {{}}\n\
                         flush table inet sandbox_dnat\n\
                         table inet sandbox_policy {{}}\n\
                         flush table inet sandbox_policy\n\
                         {rules}"
                    );
                    let _ = gateway.inject_nftables_ruleset_public(
                        session_id,
                        &restore,
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

/// Read the current nftables state for both policy tables
/// (`sandbox_dnat` + `sandbox_policy`) from the container via `docker
/// exec`. The snapshot is used by rollback to restore the pre-apply
/// ruleset.
///
/// Both tables are managed as a pair — `sandbox_dnat` carries the
/// VM-egress conditional-DNAT decision and both concat sets;
/// `sandbox_policy` carries the gateway-egress allow `output`
/// chain keyed on the same sets. A rollback that restored only one
/// would leave the gateway in a half-configured state, so the snapshot
/// covers both. Each table is listed separately; either may be absent
/// (e.g. when no policy has ever been applied) — the listing for a
/// missing table is silently omitted.
fn read_nftables_state(session_id: &SessionId) -> Result<String, SandboxError> {
    let container = gateway::container_name(session_id);
    let mut combined = String::new();

    for table in ["sandbox_dnat", "sandbox_policy"] {
        let output = Command::new("docker")
            .args(["exec", &container, "nft", "list", "table", "inet", table])
            .output()
            .map_err(|e| {
                SandboxError::Gateway(format!("failed to list nftables table {table}: {e}"))
            })?;

        if output.status.success() {
            combined.push_str(&String::from_utf8_lossy(&output.stdout));
        }
        // Missing table is fine — the gateway may not have any policy
        // state yet (e.g. we snapshot right after create_gateway but
        // before any apply).
    }

    Ok(combined)
}
