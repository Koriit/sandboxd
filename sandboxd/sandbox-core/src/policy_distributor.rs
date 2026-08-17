use std::time::Duration;

use tracing::{debug, error, info, warn};

use sandbox_docker_argv::container::ContainerCommand;
use sandbox_docker_argv::gateway::{FileDelivery, GatewayFile, NftTable, StdinCommand};

use crate::atomic_listener_writer::{
    AtomicListenerWriter, session_listener_host_path, write_listener_into_container,
};
use crate::docker::{DockerOp, DockerRoute};
use crate::error::SandboxError;
use crate::gateway::{self, GatewayManager};
use crate::policy::{CompiledPolicy, PolicyCompiler};
use crate::session::SessionId;

/// Wall-clock budget for a single policy-file write or read.
///
/// The artifacts are a few KB and the transport is a local socket; a write
/// that has not completed in this long is wedged rather than slow, and the
/// distribution's rollback wants to start rather than wait.
const POLICY_FILE_TIMEOUT: Duration = Duration::from_secs(30);

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

        // Transport: the manager's route. On Linux it addresses the host
        // Docker daemon; on macOS it reaches the Docker daemon inside the
        // gateway VM. The nft injection takes the same route, so the two
        // halves of a distribution cannot end up talking to different
        // daemons.
        let route = gateway.route();

        info!(
            session_id = %session_id,
            container = %container,
            "distributing compiled policy to gateway components"
        );

        // Read previous configs for rollback (best-effort).
        let previous = PreviousConfigs::read(session_id, route);

        // Step 1: Write CoreDNS policy file.
        if let Err(e) = write_gateway_file(
            route,
            &container,
            GatewayFile::CorednsPolicy,
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
        if let Err(e) = write_gateway_file(
            route,
            &container,
            GatewayFile::MitmproxyPolicy,
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
        if let Err(e) = write_gateway_file(
            route,
            &container,
            GatewayFile::EnvoyBootstrap,
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
        let listener_write = if route.is_vm() {
            write_listener_into_container(
                session_id,
                route,
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
        let route = gateway.route();

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
            let restore_result = if route.is_vm() {
                write_listener_into_container(session_id, route, &container, &restore_content)
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
                let _ = write_gateway_file(route, &container, GatewayFile::EnvoyBootstrap, config);
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
                let _ = write_gateway_file(route, &container, GatewayFile::MitmproxyPolicy, config);
            }
        }

        if state.coredns_written {
            if let Some(ref config) = previous.coredns {
                let _ = write_gateway_file(route, &container, GatewayFile::CorednsPolicy, config);
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
    /// `route` is the gateway manager's own route, so the snapshot is taken
    /// from the same Docker daemon the forward writes go to.
    fn read(session_id: &SessionId, route: &DockerRoute) -> Self {
        let container = gateway::container_name(session_id);

        let coredns = read_gateway_file(route, &container, GatewayFile::CorednsPolicy).ok();
        let mitmproxy = read_gateway_file(route, &container, GatewayFile::MitmproxyPolicy).ok();
        let envoy_bootstrap =
            read_gateway_file(route, &container, GatewayFile::EnvoyBootstrap).ok();

        // Snapshot the prior listener generation for rollback.
        //   - Linux: read the host-side bind-mounted file directly so
        //     rollback works even if the container is partially broken.
        //   - macOS: there is no host file; the in-container listener
        //     writer keeps an in-process cache of the last generation it
        //     delivered. Leaving this `None` is safe — a `None` prior on
        //     rollback just restores the deny-all initial listener, which
        //     is fail-closed.
        let envoy_listener = if route.is_vm() {
            crate::atomic_listener_writer::cached_listener_pub(session_id)
        } else {
            let listener_path = session_listener_host_path(session_id);
            std::fs::read_to_string(&listener_path).ok()
        };

        // Reading current nftables state from the namespace.
        let nftables = read_nftables_state(session_id, route).ok();

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

// ---------------------------------------------------------------------------
// Seed artifacts
// ---------------------------------------------------------------------------
//
// Two of the artifacts a gateway container is seeded with are generated
// rather than supplied: the Envoy bootstrap and the deny-all initial
// listener. The container's entrypoint blocks on both before it starts
// Envoy, so what is written here decides whether the enforcement pipeline
// comes up at all — and *what* is written has to be the compiler's output,
// not a copy of it.
//
// Each pairing lives in one function so the artifact and its generator
// cannot be separated at a call site, and so a test can assert the pairing
// rather than re-deriving it.

/// The Envoy static bootstrap and the compiler that produces it.
pub fn envoy_bootstrap_artifact() -> (GatewayFile, String) {
    (
        GatewayFile::EnvoyBootstrap,
        PolicyCompiler::compile_envoy_bootstrap(),
    )
}

/// The deny-all initial Envoy listener and the compiler that produces it.
///
/// Deny-all is the point: it unblocks the entrypoint without admitting
/// anything, so the window between the container starting and the first
/// policy landing is closed rather than open.
pub fn envoy_initial_listener_artifact() -> (GatewayFile, String) {
    (
        GatewayFile::EnvoyListener,
        PolicyCompiler::compile_initial_envoy_listener(),
    )
}

/// Both Envoy artifacts, in the order the entrypoint needs them.
///
/// Used where the listener has to be delivered into the container as well
/// as the bootstrap — that is, wherever there is no host directory
/// bind-mounted over `/etc/envoy/listeners`.
pub fn envoy_seed_artifacts() -> Vec<(GatewayFile, String)> {
    vec![
        envoy_bootstrap_artifact(),
        envoy_initial_listener_artifact(),
    ]
}

/// The op that delivers `content` as `file` inside `container`.
///
/// Factored out so the identity between a generator's output and the bytes
/// the container receives can be asserted without running Docker: the op is
/// what carries the artifact, so the op is what a test has to inspect.
pub fn write_gateway_file_op(container: &str, file: GatewayFile, content: &str) -> DockerOp {
    DockerOp::ContainerExecStdin {
        name: container.to_string(),
        command: StdinCommand::WriteGatewayFile {
            file,
            delivery: FileDelivery::Replace,
        },
        body: content.to_string(),
    }
}

/// Write one of the enumerated gateway artifacts into `container`.
///
/// The content is piped to `cat` on the child's standard input; the
/// destination path is a constant of the argv crate selected by `file`.
/// Nothing the caller supplies reaches the shell — see the module note on
/// [`sandbox_docker_argv::gateway`].
pub fn write_gateway_file(
    route: &DockerRoute,
    container: &str,
    file: GatewayFile,
    content: &str,
) -> Result<(), SandboxError> {
    let label = format!("docker exec (write {})", file.as_str());
    let output = route
        .run(
            write_gateway_file_op(container, file, content),
            POLICY_FILE_TIMEOUT,
            &label,
        )
        .map_err(|e| {
            SandboxError::Gateway(format!(
                "failed to write {} to {container}: {e}",
                file.path()
            ))
        })?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(SandboxError::Gateway(format!(
            "write to {} in {container} failed: {stderr}",
            file.path()
        )));
    }

    Ok(())
}

/// Read one of the enumerated gateway artifacts back out of `container`.
pub fn read_gateway_file(
    route: &DockerRoute,
    container: &str,
    file: GatewayFile,
) -> Result<String, SandboxError> {
    let label = format!("docker exec (read {})", file.as_str());
    let output = route
        .run(
            DockerOp::ContainerExec {
                name: container.to_string(),
                command: ContainerCommand::ReadGatewayFile { file },
            },
            POLICY_FILE_TIMEOUT,
            &label,
        )
        .map_err(|e| {
            SandboxError::Gateway(format!(
                "failed to read {} from {container}: {e}",
                file.path()
            ))
        })?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(SandboxError::Gateway(format!(
            "cat {} in {container} failed: {stderr}",
            file.path()
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
fn read_nftables_state(
    session_id: &SessionId,
    route: &DockerRoute,
) -> Result<String, SandboxError> {
    let container = gateway::container_name(session_id);
    let mut combined = String::new();

    for table in NftTable::ALL {
        let output = route
            .run(
                DockerOp::ContainerExec {
                    name: container.clone(),
                    command: ContainerCommand::ListNftTable { table: *table },
                },
                POLICY_FILE_TIMEOUT,
                "docker exec (nft list table)",
            )
            .map_err(|e| {
                SandboxError::Gateway(format!(
                    "failed to list nftables table {}: {e}",
                    table.name()
                ))
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

#[cfg(test)]
mod tests {
    use super::*;

    // -- The op the write travels in -----------------------------------------

    /// The artifact reaches the container on stdin and the destination path
    /// comes from the enum. Together those are why no daemon-supplied string
    /// is in the shell body: the only caller-supplied values in the op are
    /// the container name (an argv element) and the content (a byte stream).
    #[test]
    fn a_policy_write_carries_its_content_on_stdin_and_its_path_in_the_enum() {
        let op = write_gateway_file_op(
            "sandbox-gw-abc123",
            GatewayFile::CorednsPolicy,
            "policy body\n",
        );
        assert_eq!(op.stdin_body(), Some("policy body\n"));
        let argv = op.argv().expect("write op renders");
        assert_eq!(
            argv,
            vec![
                "exec",
                "-i",
                "sandbox-gw-abc123",
                "sh",
                "-c",
                "mkdir -p '/etc/coredns' && cat > '/etc/coredns/policy.conf'",
            ]
        );
        assert!(
            !argv.iter().any(|a| a.contains("policy body")),
            "the artifact must never appear in the argv: {argv:?}"
        );
    }

    /// A body full of the characters that break naive command construction
    /// changes nothing about the command line — it is not on the command
    /// line. This is the property the whole write shape exists to give.
    #[test]
    fn a_hostile_body_does_not_reach_the_shell() {
        let hostile = "'; rm -rf / #\n$(id)\n`id`\n\"quoted\" — ünïcode\n";
        let benign = write_gateway_file_op("gw", GatewayFile::EnvoyBootstrap, "x")
            .argv()
            .expect("renders");
        let op = write_gateway_file_op("gw", GatewayFile::EnvoyBootstrap, hostile);
        assert_eq!(op.argv().expect("renders"), benign);
        assert_eq!(op.stdin_body(), Some(hostile));
    }

    /// The read is a plain `cat` with no shell at all, so there is nothing
    /// for a path to break out of even in principle.
    #[test]
    fn a_policy_read_invokes_no_shell() {
        let op = DockerOp::ContainerExec {
            name: "sandbox-gw-x".to_string(),
            command: ContainerCommand::ReadGatewayFile {
                file: GatewayFile::EnvoyBootstrap,
            },
        };
        assert_eq!(
            op.argv().expect("read op renders"),
            vec![
                "exec",
                "sandbox-gw-x",
                "cat",
                "/etc/envoy/envoy-bootstrap.yaml"
            ]
        );
        assert!(op.stdin_body().is_none());
    }

    /// The rollback snapshot covers both tables — restoring one would leave
    /// the gateway half-configured, with the concat sets and the chain that
    /// keys on them out of step.
    #[test]
    fn the_rollback_snapshot_names_both_policy_tables() {
        let names: Vec<&str> = NftTable::ALL.iter().map(|t| t.name()).collect();
        assert_eq!(names, vec!["sandbox_dnat", "sandbox_policy"]);
    }

    // -- Artifact identity ---------------------------------------------------

    /// §3.4 step 6: the Envoy bootstrap written into the container is the
    /// compiler's output, and it survives the trip to the write op intact.
    /// A drifted bootstrap is a gateway whose Envoy either refuses to start
    /// or starts pointed at the wrong listener directory.
    #[test]
    fn the_bootstrap_seed_is_its_compilers_output() {
        let (file, content) = envoy_bootstrap_artifact();
        assert!(matches!(file, GatewayFile::EnvoyBootstrap));
        assert_eq!(content, PolicyCompiler::compile_envoy_bootstrap());

        let op = write_gateway_file_op("sandbox-gw-abc123", file, &content);
        assert_eq!(
            op.stdin_body(),
            Some(PolicyCompiler::compile_envoy_bootstrap().as_str()),
            "the bytes the container receives must be the compiler's output"
        );
    }

    /// §3.4 step 7: the seeded listener is the deny-all initial listener,
    /// byte for byte. Seeding anything else would open the window this
    /// artifact exists to close.
    #[test]
    fn the_listener_seed_is_the_deny_all_initial_listener() {
        let (file, content) = envoy_initial_listener_artifact();
        assert!(matches!(file, GatewayFile::EnvoyListener));
        assert_eq!(content, PolicyCompiler::compile_initial_envoy_listener());

        let op = write_gateway_file_op("sandbox-gw-abc123", file, &content);
        assert_eq!(
            op.stdin_body(),
            Some(PolicyCompiler::compile_initial_envoy_listener().as_str())
        );
    }

    /// The entrypoint blocks on both, so both are seeded, in that order.
    #[test]
    fn both_envoy_artifacts_are_seeded_in_entrypoint_order() {
        let seeds = envoy_seed_artifacts();
        assert_eq!(seeds.len(), 2);
        assert_eq!(seeds[0], envoy_bootstrap_artifact());
        assert_eq!(seeds[1], envoy_initial_listener_artifact());
    }

    /// §3.4 step 8: the CoreDNS policy the distributor writes is the
    /// compiled policy's, unchanged. This is the artifact that decides
    /// which names resolve at all.
    #[test]
    fn the_coredns_write_carries_the_compiled_policy() {
        let compiled = "example.com\nrewrite stop {\n  name exact \"a.b\" c.d\n}\n";
        let op = write_gateway_file_op("sandbox-gw-abc123", GatewayFile::CorednsPolicy, compiled);
        assert_eq!(op.stdin_body(), Some(compiled));
        assert!(
            op.argv()
                .expect("renders")
                .iter()
                .any(|a| a.contains("/etc/coredns/policy.conf")),
            "the write must name the file CoreDNS reads"
        );
    }

    /// The container name is the caller's, derived from the session id, and
    /// travels as its own argv element rather than as text in a command.
    #[test]
    fn the_write_op_carries_the_session_container() {
        let session = SessionId::parse("0123456789ab").unwrap();
        let container = gateway::container_name(&session);
        assert_eq!(container, "sandbox-gw-0123456789ab");
        let argv = write_gateway_file_op(&container, GatewayFile::MitmproxyPolicy, "{}")
            .argv()
            .expect("renders");
        assert!(argv.contains(&container));
    }

    // -- DistributionState: rollback step-tracking ---------------------------

    /// A freshly-constructed `DistributionState` has every step un-set.
    /// This is the rollback-safety precondition: `rollback_steps` only undoes
    /// a step when its flag is `true`, so a `Default` state must trigger zero
    /// rollback writes — otherwise an early failure (e.g. step 1 fails) would
    /// roll back steps that never ran, writing to a half-created gateway.
    #[test]
    fn distribution_state_default_marks_nothing_done() {
        let state = DistributionState::default();
        assert!(!state.coredns_written);
        assert!(!state.mitmproxy_written);
        assert!(!state.nftables_injected);
        assert!(!state.envoy_bootstrap_written);
        assert!(!state.envoy_listener_written);
    }

    /// The step flags are independent: marking one done leaves the others
    /// un-set. `distribute` flips them one at a time as each step succeeds, so
    /// rollback after step N must see exactly steps 1..=N marked — never a
    /// later step that has not run yet.
    #[test]
    // Incremental field assignment is the behaviour under test: it mirrors how
    // `distribute` flips one flag per completed step. A struct-literal
    // initializer would not exercise the per-step independence we assert.
    #[allow(clippy::field_reassign_with_default)]
    fn distribution_state_flags_are_independent() {
        let mut state = DistributionState::default();
        // Mark the steps in the order `distribute` sets them, asserting each
        // flip is isolated to its own flag.
        state.coredns_written = true;
        assert!(state.coredns_written && !state.mitmproxy_written);

        state.mitmproxy_written = true;
        assert!(state.mitmproxy_written && !state.nftables_injected);

        state.nftables_injected = true;
        assert!(state.nftables_injected && !state.envoy_bootstrap_written);

        state.envoy_bootstrap_written = true;
        assert!(state.envoy_bootstrap_written && !state.envoy_listener_written);

        state.envoy_listener_written = true;
        // After the final step every flag is set — a fully-distributed policy.
        assert!(
            state.coredns_written
                && state.mitmproxy_written
                && state.nftables_injected
                && state.envoy_bootstrap_written
                && state.envoy_listener_written
        );
    }

    // -- PreviousConfigs snapshot --------------------------------------------

    /// A defaulted `PreviousConfigs` carries no prior generation for any
    /// component. On rollback this is the "nothing to restore" baseline: the
    /// listener restore falls back to the deny-all initial listener
    /// (fail-closed), and the other components are simply left as-is.
    #[test]
    fn previous_configs_default_is_all_none() {
        let prev = PreviousConfigs::default();
        assert!(prev.coredns.is_none());
        assert!(prev.mitmproxy.is_none());
        assert!(prev.nftables.is_none());
        assert!(prev.envoy_bootstrap.is_none());
        assert!(prev.envoy_listener.is_none());
    }
}
