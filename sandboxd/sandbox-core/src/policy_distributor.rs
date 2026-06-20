use std::path::Path;
use std::process::Command;

use tracing::{debug, error, info, warn};

use crate::atomic_listener_writer::{
    AtomicListenerWriter, session_listener_host_path, write_listener_into_container,
};
use crate::error::SandboxError;
use crate::gateway::{self, GatewayManager};
use crate::policy::{BOOTSTRAP_FILE_IN_CONTAINER, CompiledPolicy, PolicyCompiler};
use crate::session::SessionId;

/// Build a `docker` [`Command`] with the optional forwarded-socket
/// `-H unix://<sock>` prefix pre-applied.
///
/// The policy/DNS free functions receive the gateway's optional socket
/// (read from the passed-in `GatewayManager` via
/// [`GatewayManager::docker_socket`]) and shell out through this helper so
/// their transport mirrors the manager's nft injection. On Linux the socket
/// is always `None`, so no `-H` flag is prepended and behaviour is
/// byte-for-byte identical to the prior bare `Command::new("docker")`.
fn docker_with_socket(socket: Option<&Path>) -> Command {
    let mut cmd = Command::new("docker");
    if let Some(sock) = socket {
        cmd.args(["-H", &format!("unix://{}", sock.display())]);
    }
    cmd
}

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
/// [`AtomicListenerWriter`], producing a
/// `MovedTo` inotify event that triggers Envoy's LDS reload without a
/// listener drain. See upstream Envoy issue `#20474` for the constraints
/// this design respects (listener identity must not change between
/// filter-chain rewrites; only `filter_chains` / `default_filter_chain`
/// may differ).
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

        // Transport: on Linux this is `None` (host Docker socket, no `-H`);
        // on macOS it is the gateway Lima VM's forwarded socket so the
        // `docker exec` file writes reach the in-VM gateway container. The
        // nft injection already routes through `gateway` (socket-aware).
        let socket = gateway.docker_socket();

        info!(
            session_id = %session_id,
            container = %container,
            "distributing compiled policy to gateway components"
        );

        // Read previous configs for rollback (best-effort).
        let previous = PreviousConfigs::read(session_id, socket);

        // Step 1: Write CoreDNS policy file.
        if let Err(e) = write_file_to_container_on_socket(
            socket,
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
        if let Err(e) = write_file_to_container_on_socket(
            socket,
            &container,
            "/tmp/mitmproxy/policy.json",
            &compiled.mitmproxy_config,
        ) {
            error!(
                session_id = %session_id,
                error = %e,
                "failed to write mitmproxy policy"
            );
            Self::rollback_steps(session_id, gateway, &state, &previous);
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
                Self::rollback_steps(session_id, gateway, &state, &previous);
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
        if let Err(e) = write_file_to_container_on_socket(
            socket,
            &container,
            BOOTSTRAP_FILE_IN_CONTAINER,
            &compiled.envoy_bootstrap_config,
        ) {
            error!(
                session_id = %session_id,
                error = %e,
                "failed to write Envoy bootstrap"
            );
            Self::rollback_steps(session_id, gateway, &state, &previous);
            return Err(e);
        }
        state.envoy_bootstrap_written = true;
        debug!(session_id = %session_id, "Envoy bootstrap written");

        // Step 5: Atomically rewrite the LDS-served listener file.
        //
        // The listener content + framing is identical across platforms;
        // only the delivery differs:
        //   - Linux: the listener file lives in a per-session host
        //     directory bind-mounted into the container as
        //     [`crate::policy::LISTENER_DIR_IN_CONTAINER`]. The host-side
        //     atomic writer renames into place; the kernel emits the
        //     `MovedTo` event Envoy's LDS watcher consumes.
        //   - macOS: there is no host bind-mount (the dir is an
        //     in-container tmpfs), so the rename must happen inside the
        //     container via `docker exec` (write-temp + `mv -f`). The
        //     in-container `mv` emits the same `IN_MOVED_TO` event.
        // Both paths enforce the "only filter_chains differ" invariant so
        // Envoy reloads via LDS without draining the listener.
        let listener_write = if let Some(sock) = socket {
            write_listener_into_container(
                session_id,
                sock,
                &container,
                &compiled.envoy_listener_config,
            )
        } else {
            let listener_path = session_listener_host_path(session_id);
            AtomicListenerWriter::new(&listener_path)
                .write(&compiled.envoy_listener_config)
                .map(|_| ())
                .map_err(|e| SandboxError::Gateway(e.to_string()))
        };
        if let Err(e) = listener_write {
            error!(
                session_id = %session_id,
                error = %e,
                "failed to atomically write Envoy listener file"
            );
            Self::rollback_steps(session_id, gateway, &state, &previous);
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
        gateway: &GatewayManager,
        state: &DistributionState,
        previous: &PreviousConfigs,
    ) {
        let container = gateway::container_name(session_id);
        let socket = gateway.docker_socket();

        warn!(
            session_id = %session_id,
            "rolling back policy distribution"
        );

        // Revert listener file to previous generation (or to the
        // deny-all initial listener if there was none). The invariant is
        // enforced on this restoration write (host writer on Linux,
        // in-container delivery on macOS); if it fails we log and move on
        // — a failed rollback is not worse than a failed forward write at
        // this stage.
        if state.envoy_listener_written {
            let restore_content = previous
                .envoy_listener
                .clone()
                .unwrap_or_else(PolicyCompiler::compile_initial_envoy_listener);
            let restore_result = if let Some(sock) = socket {
                write_listener_into_container(session_id, sock, &container, &restore_content)
            } else {
                let listener_path = session_listener_host_path(session_id);
                AtomicListenerWriter::new(&listener_path)
                    .write(&restore_content)
                    .map(|_| ())
                    .map_err(|e| SandboxError::Gateway(e.to_string()))
            };
            if let Err(e) = restore_result {
                warn!(
                    session_id = %session_id,
                    error = %e,
                    "failed to roll back Envoy listener file"
                );
            }
        }

        if state.envoy_bootstrap_written {
            if let Some(ref config) = previous.envoy_bootstrap {
                let _ = write_file_to_container_on_socket(
                    socket,
                    &container,
                    BOOTSTRAP_FILE_IN_CONTAINER,
                    config,
                );
            }
        }

        if state.nftables_injected {
            if let Some(ref rules) = previous.nftables {
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
                let _ = write_file_to_container_on_socket(
                    socket,
                    &container,
                    "/tmp/mitmproxy/policy.json",
                    config,
                );
            }
        }

        if state.coredns_written {
            if let Some(ref config) = previous.coredns {
                let _ = write_file_to_container_on_socket(
                    socket,
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
    envoy_bootstrap: Option<String>,
    envoy_listener: Option<String>,
}

impl PreviousConfigs {
    /// Best-effort read of current configs from the container (and the
    /// host-side listener file on Linux / the in-process cache on macOS).
    ///
    /// `socket` is the gateway's optional forwarded Docker socket: `None`
    /// on Linux (host socket, no `-H`), `Some` on macOS (in-VM gateway
    /// socket).
    fn read(session_id: &SessionId, socket: Option<&Path>) -> Self {
        let container = gateway::container_name(session_id);

        let coredns =
            read_file_from_container_on_socket(socket, &container, "/etc/coredns/policy.conf").ok();
        let mitmproxy =
            read_file_from_container_on_socket(socket, &container, "/tmp/mitmproxy/policy.json")
                .ok();
        let envoy_bootstrap =
            read_file_from_container_on_socket(socket, &container, BOOTSTRAP_FILE_IN_CONTAINER)
                .ok();

        // Snapshot the prior listener generation for rollback.
        //   - Linux: read the host-side bind-mounted file directly so
        //     rollback works even if the container is partially broken.
        //   - macOS: there is no host file; the in-container listener
        //     writer keeps an in-process cache of the last generation it
        //     delivered. Leaving this `None` is safe — a `None` prior on
        //     rollback just restores the deny-all initial listener, which
        //     is fail-closed.
        let envoy_listener = if socket.is_some() {
            crate::atomic_listener_writer::cached_listener_pub(session_id)
        } else {
            let listener_path = session_listener_host_path(session_id);
            std::fs::read_to_string(&listener_path).ok()
        };

        // Reading current nftables state from the namespace.
        let nftables = read_nftables_state_on_socket(session_id, socket).ok();

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

/// Write content to a file inside a Docker container (host Docker socket).
///
/// Thin wrapper over [`write_file_to_container_on_socket`] with no
/// forwarded socket — the Linux behaviour, byte-for-byte unchanged
/// (`docker exec sh -c 'cat > path'`, no `-H` flag). Retained as the
/// public Linux entry point and for callers (e.g. `reapply_session_policy`'s
/// empty-policy path) that target the host socket.
pub fn write_file_to_container(
    container: &str,
    path: &str,
    content: &str,
) -> Result<(), SandboxError> {
    write_file_to_container_on_socket(None, container, path, content)
}

/// Write content to a file inside a Docker container, optionally routing
/// through a forwarded gateway-VM Docker socket.
///
/// `socket = None` is the Linux path (host Docker socket, no `-H` flag);
/// `socket = Some(path)` is the macOS path (in-VM gateway socket via
/// `-H unix://<path>`). Uses `docker exec sh -c 'cat > path'` with the
/// content piped to stdin.
pub fn write_file_to_container_on_socket(
    socket: Option<&Path>,
    container: &str,
    path: &str,
    content: &str,
) -> Result<(), SandboxError> {
    use std::io::Write;

    let mut child = docker_with_socket(socket)
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

/// Read a file from inside a Docker container, optionally over a
/// forwarded gateway-VM Docker socket (`None` on Linux → no `-H` flag).
fn read_file_from_container_on_socket(
    socket: Option<&Path>,
    container: &str,
    path: &str,
) -> Result<String, SandboxError> {
    let output = docker_with_socket(socket)
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
fn read_nftables_state_on_socket(
    session_id: &SessionId,
    socket: Option<&Path>,
) -> Result<String, SandboxError> {
    let container = gateway::container_name(session_id);
    let mut combined = String::new();

    for table in ["sandbox_dnat", "sandbox_policy"] {
        let output = docker_with_socket(socket)
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
