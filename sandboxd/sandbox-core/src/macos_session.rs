/// macOS session lifecycle helpers.
///
/// Orchestrates the macOS-specific create/teardown flow for Lima (full-backend)
/// sessions:
///
/// - `setup_macos_gateway` — creates the per-session macvlan Docker network and
///   gateway container inside the gateway Lima VM (steps 6–11 of the create flow).
/// - `teardown_macos_gateway` — removes the gateway container and macvlan network
///   on stop/rm (idempotent, tolerates "not found").
/// - `check_host_ip_forwarding_disabled` — asserts that macOS host IP forwarding
///   is disabled on both IPv4 and IPv6, which is required for the egress guarantee.
///
/// `restrict=on` verification is handled by `LimaManager::verify_restrict_on`
/// (in `sandbox_core::lima`), which uses the broker-mediated QMP path on macOS
/// and a direct marker read on Linux.
///
/// All functions are `#[cfg(target_os = "macos")]`. The module is declared in
/// `lib.rs` as `#[cfg(target_os = "macos")] pub mod macos_session`.
#[cfg(target_os = "macos")]
use std::path::Path;
#[cfg(target_os = "macos")]
use std::process::Command;
#[cfg(target_os = "macos")]
use std::time::Duration;

#[cfg(target_os = "macos")]
use tracing::{debug, info, warn};

#[cfg(target_os = "macos")]
use crate::error::SandboxError;
#[cfg(target_os = "macos")]
use crate::network::NetworkInfo;
#[cfg(target_os = "macos")]
use crate::process::run_with_timeout;
#[cfg(target_os = "macos")]
use crate::session::SessionId;

// ---------------------------------------------------------------------------
// Container / network naming
// ---------------------------------------------------------------------------

/// Docker container name for a session's macOS gateway.
///
/// Mirrors the Linux naming convention in `gateway.rs` (`container_name`).
/// On macOS the container runs inside the gateway Lima VM, not on the host.
#[cfg(target_os = "macos")]
pub fn macos_gateway_container_name(session_id: &SessionId) -> String {
    format!("sandbox-gw-{session_id}")
}

/// Docker macvlan network name for a session's macOS gateway.
///
/// The macvlan network bridges the gateway container onto the `limaN` NIC
/// inside the gateway VM, giving the session VM an isolated L2 segment.
#[cfg(target_os = "macos")]
pub fn macos_docker_network_name(session_id: &SessionId) -> String {
    format!("sandbox-net-{session_id}")
}

// ---------------------------------------------------------------------------
// Timeout constants
// ---------------------------------------------------------------------------

/// Timeout for `docker run` (gateway container creation inside the VM).
#[cfg(target_os = "macos")]
const DOCKER_RUN_TIMEOUT: Duration = Duration::from_secs(60);

/// Timeout for `docker network create/rm` operations.
#[cfg(target_os = "macos")]
const DOCKER_NETWORK_TIMEOUT: Duration = Duration::from_secs(30);

/// Timeout for `docker network connect`.
#[cfg(target_os = "macos")]
const DOCKER_CONNECT_TIMEOUT: Duration = Duration::from_secs(15);

/// Timeout for `docker rm`.
#[cfg(target_os = "macos")]
const DOCKER_RM_TIMEOUT: Duration = Duration::from_secs(15);

// ---------------------------------------------------------------------------
// Environment helper
// ---------------------------------------------------------------------------

/// Build a `docker -H unix://<socket>` command targeting the gateway VM's
/// forwarded Docker socket.
///
/// Replicates the env-sanitization discipline from `gateway_lima.rs`
/// (`apply_docker_env`): clears the inherited environment and reconstructs
/// only the vars the docker CLI needs (`PATH`, `HOME`). This prevents
/// `DOCKER_HOST` or other ambient overrides from redirecting the command.
#[cfg(target_os = "macos")]
fn gateway_docker_cmd(gateway_docker_socket: &Path) -> Command {
    let socket_str = format!("unix://{}", gateway_docker_socket.display());
    let current_path = std::env::var("PATH").unwrap_or_default();
    let path_value = format!("/opt/homebrew/bin:/usr/local/bin:{current_path}");
    let home = std::env::var("HOME").unwrap_or_default();
    if home.is_empty() {
        warn!("gateway_docker_cmd: HOME is unset; docker CLI may fail to locate its config dir");
    }

    let mut cmd = Command::new("docker");
    cmd.env_clear()
        .env("PATH", &path_value)
        .env("HOME", home)
        .args(["-H", &socket_str]);
    cmd
}

// ---------------------------------------------------------------------------
// setup_macos_gateway
// ---------------------------------------------------------------------------

/// Orchestrate the macOS macvlan network + gateway container creation
/// for a session (steps 6–11 of the create flow).
///
/// Steps:
///  6. Create macvlan Docker network inside gateway VM: `sandbox-net-<id>`
///     (`--driver macvlan --opt parent=<nic_name>`)
///  7. Create gateway container: `sandbox-gw-<id>` on `sandboxd-egress`,
///     then provision the per-session mitmproxy CA, Envoy bootstrap +
///     deny-all listener, and initial DNS policy into its tmpfs
///  8. Connect container to macvlan with static IP (`gateway_ip`)
///  9. Inject deny-all nftables
/// 10. Wait for gateway healthy
/// 11. Inject DNAT
///
/// Returns `Ok(())` on success; caller does `limactl start` +
/// `LimaManager::verify_restrict_on` + marks the session Running after.
///
/// On failure: caller must tear down (`teardown_macos_gateway`) and
/// release the slot (`vmnet_pool.release_lima_slot`).
// The 8 parameters cover the distinct concerns: session identity,
// networking (2 params), Docker socket target, image, per-session
// mitmproxy CA, DNS policy, and owner label. Bundling them into a struct
// would require a public config type; the current shape matches the Linux
// `create_gateway` parameter footprint and is clearer at the call site.
#[cfg(target_os = "macos")]
#[allow(clippy::too_many_arguments)]
pub fn setup_macos_gateway(
    session_id: &SessionId,
    network_info: &NetworkInfo,
    nic_name: &str,
    gateway_docker_socket: &Path,
    gateway_image_tag: &str,
    ca_dir: Option<&Path>,
    initial_dns_policy: Option<&str>,
    owner_pool: Option<&str>,
) -> Result<(), SandboxError> {
    let container_name = macos_gateway_container_name(session_id);
    let network_name = macos_docker_network_name(session_id);

    info!(
        session_id = %session_id,
        container = %container_name,
        nic = %nic_name,
        gateway_ip = %network_info.gateway_ip,
        "setting up macOS gateway"
    );

    // Step 6: Create macvlan network inside gateway VM.
    //
    // The macvlan network is parented on `limaN` (the slot NIC), giving the
    // gateway container an isolated L2 segment on the session's /29 block.
    // The subnet/gateway passed here set the IPAM range Docker uses when
    // assigning IPs; we later assign the gateway IP explicitly via
    // `docker network connect --ip`.
    {
        // Compute B+1 from the subnet CIDR for macvlan IPAM gateway address.
        // The actual packet-gateway role is played by the container at B+3
        // (gateway_ip), wired up by the nft DNAT rules; B+1 is the IPAM
        // default-gateway field only (not used for routing by the VM).
        let ipam_gateway = compute_subnet_plus_one(&network_info.subnet)?;

        let output = run_with_timeout(
            gateway_docker_cmd(gateway_docker_socket).args([
                "network",
                "create",
                "--driver",
                "macvlan",
                "--opt",
                &format!("parent={nic_name}"),
                // macvlan_mode=private: blocks macvlan-to-macvlan traffic on
                // the same parent NIC. Defense-in-depth L2-isolation control:
                // sessions normally use different parent NICs (different slots),
                // but private mode prevents cross-session L2 traffic even if two
                // sessions ended up sharing a parent (e.g., after slot reuse).
                "--opt",
                "macvlan_mode=private",
                "--subnet",
                &network_info.subnet,
                "--gateway",
                &ipam_gateway,
                "--label",
                &format!("sandbox.session_id={session_id}"),
                &network_name,
            ]),
            DOCKER_NETWORK_TIMEOUT,
            "docker network create (macvlan)",
        )?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(SandboxError::Gateway(format!(
                "failed to create macvlan network {network_name}: {stderr}"
            )));
        }
        debug!(
            session_id = %session_id,
            network = %network_name,
            nic = %nic_name,
            "macvlan network created"
        );
    }

    // Pre-cleanup: remove any leftover container with the same name before
    // docker run. Mirrors the Linux `create_gateway` pre-cleanup that
    // defends against daemon-crash-mid-create / replay scenarios. UUID
    // session IDs make true collisions impossible in steady state, but the
    // defensive removal costs nothing and protects edge cases (e.g., a test
    // replay with a fixed session ID).
    let _ = run_with_timeout(
        gateway_docker_cmd(gateway_docker_socket).args(["rm", "--force", &container_name]),
        DOCKER_RM_TIMEOUT,
        "docker rm (macOS pre-cleanup)",
    );

    // Step 7: Create gateway container attached to sandboxd-egress.
    //
    // The container starts on sandboxd-egress (its upstream egress NIC).
    // The macvlan connection (step 8) adds the VM-facing NIC with the
    // static gateway_ip. Keeping the two NICs separate means the container
    // is never missing its default-route uplink, which would make health
    // checks fail before the macvlan attach completes.
    {
        let run_args = build_macos_gateway_docker_args(session_id, gateway_image_tag, owner_pool);
        let args_refs: Vec<&str> = run_args.iter().map(|s| s.as_str()).collect();
        let output = run_with_timeout(
            gateway_docker_cmd(gateway_docker_socket).args(&args_refs),
            DOCKER_RUN_TIMEOUT,
            "docker run (macOS gateway)",
        )?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(SandboxError::Gateway(format!(
                "docker run failed for macOS gateway container {container_name}: {stderr}"
            )));
        }
        debug!(
            session_id = %session_id,
            container = %container_name,
            "macOS gateway container started on sandboxd-egress"
        );
    }

    // Provision the per-session mitmproxy CA into the container's
    // `/root/.mitmproxy` tmpfs. Without this, mitmproxy self-generates a
    // throwaway CA the sandbox VM does not trust, so every intercepted HTTPS
    // flow fails certificate verification. Same write path as the lite
    // sibling — shared via `provision_mitmproxy_ca`.
    provision_mitmproxy_ca(gateway_docker_socket, &container_name, ca_dir)?;

    // Write the Envoy static bootstrap into the container (same as Linux path).
    {
        use crate::policy::{BOOTSTRAP_FILE_IN_CONTAINER, PolicyCompiler};
        let bootstrap = PolicyCompiler::compile_envoy_bootstrap();
        if let Err(e) = write_file_to_gateway_container(
            gateway_docker_socket,
            &container_name,
            BOOTSTRAP_FILE_IN_CONTAINER,
            &bootstrap,
        ) {
            return Err(SandboxError::Gateway(format!(
                "failed to write Envoy bootstrap to macOS gateway {container_name}: {e}"
            )));
        }
        debug!(
            session_id = %session_id,
            "wrote Envoy static bootstrap to macOS gateway container"
        );
    }

    // Seed the initial deny-all Envoy listener into the container.
    //
    // The gateway entrypoint blocks until both the bootstrap file (written
    // above) and this listener file exist before it starts Envoy. On macOS
    // the listener directory is not bind-mounted from the host (no host-path
    // → gateway-VM-path bridge), so the file must be injected via `docker
    // exec`. The `write_file_to_gateway_container` helper now creates the
    // parent directory inline, so no separate mkdir step is needed.
    //
    // The initial deny-all listener unblocks Envoy at startup. Subsequent
    // policy-driven listener replacements are distributed via
    // `PolicyDistributor::distribute` using `write_listener_into_container`
    // over the forwarded Docker socket — the same path as the Linux
    // `AtomicListenerWriter` but tunnelled through the gateway-VM socket.
    {
        use crate::policy::{LISTENER_FILE_IN_CONTAINER, PolicyCompiler};
        let listener = PolicyCompiler::compile_initial_envoy_listener();
        if let Err(e) = write_file_to_gateway_container(
            gateway_docker_socket,
            &container_name,
            LISTENER_FILE_IN_CONTAINER,
            &listener,
        ) {
            return Err(SandboxError::Gateway(format!(
                "failed to write initial Envoy listener to macOS gateway {container_name}: {e}"
            )));
        }
        debug!(
            session_id = %session_id,
            "wrote initial deny-all Envoy listener to macOS gateway container"
        );
    }

    // Write the initial DNS policy if provided.
    if let Some(policy_content) = initial_dns_policy {
        if let Err(e) = write_file_to_gateway_container(
            gateway_docker_socket,
            &container_name,
            "/etc/coredns/policy.conf",
            policy_content,
        ) {
            warn!(
                session_id = %session_id,
                error = %e,
                "failed to write initial DNS policy to macOS gateway (CoreDNS may briefly deny queries)"
            );
        }
    }

    // Step 8: Connect container to macvlan with static IP (gateway_ip = B+3).
    {
        let output = run_with_timeout(
            gateway_docker_cmd(gateway_docker_socket).args([
                "network",
                "connect",
                "--ip",
                &network_info.gateway_ip,
                &network_name,
                &container_name,
            ]),
            DOCKER_CONNECT_TIMEOUT,
            "docker network connect (macvlan)",
        )?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(SandboxError::Gateway(format!(
                "failed to connect {container_name} to macvlan {network_name}: {stderr}"
            )));
        }
        debug!(
            session_id = %session_id,
            container = %container_name,
            gateway_ip = %network_info.gateway_ip,
            "gateway container connected to macvlan with static IP"
        );
    }

    // Steps 9–11: Use a single GatewayManager pointed at the forwarded
    // socket so all docker exec calls go through the gateway VM's Docker
    // daemon. Creating it once avoids redundant allocations.
    {
        use crate::gateway::GatewayManager;
        let gm = GatewayManager::with_gateway_socket(gateway_docker_socket.to_path_buf());

        // Step 9: Inject deny-all nftables into the gateway container.
        gm.inject_deny_all(session_id)?;

        // Step 10: Wait for each gateway component to be individually ready
        // (mitmproxy → Envoy → deny-logger → allow-logger → CoreDNS), mirroring
        // the Linux `create_gateway` per-component wait. `wait_for_components`
        // is the same method called by the Linux path.
        gm.wait_for_components(session_id)?;
        info!(
            session_id = %session_id,
            "macOS gateway components all healthy"
        );

        // Step 11: Inject DNAT rules (now that all components are serving).
        gm.inject_dnat(session_id, network_info, &network_info.gateway_ip)?;
    }

    info!(
        session_id = %session_id,
        container = %container_name,
        "macOS gateway fully initialised with nftables rules"
    );
    Ok(())
}

/// Orchestrate the macOS lite-mode gateway setup inside the gateway VM.
///
/// Like [`setup_macos_gateway`] but for the lite (container) backend:
/// the per-session Docker bridge already exists (created by
/// `NetworkManager::create_network_on_socket` before this call), so step 6
/// (network create) is skipped. The gateway container is started on the
/// `sandboxd-egress` bridge as its upstream, then connected to the
/// per-session bridge for the sandbox-container-facing NIC.
///
/// Steps (numbers mirror the Lima create flow):
/// 7. Create gateway container (`sandbox-gw-<id>`) on `sandboxd-egress`.
/// 8. Connect to per-session bridge with static gateway IP.
/// 9–11. Inject deny-all nftables → wait healthy → inject DNAT.
#[cfg(target_os = "macos")]
#[allow(clippy::too_many_arguments)]
pub fn setup_macos_lite_gateway(
    session_id: &SessionId,
    network_info: &NetworkInfo,
    gateway_docker_socket: &Path,
    gateway_image_tag: &str,
    ca_dir: Option<&Path>,
    initial_dns_policy: Option<&str>,
    owner_pool: Option<&str>,
) -> Result<(), SandboxError> {
    let container_name = macos_gateway_container_name(session_id);
    // The per-session bridge was created by create_network_on_socket
    // and follows the same naming convention as the macvlan case.
    let network_name = macos_docker_network_name(session_id);

    info!(
        session_id = %session_id,
        container = %container_name,
        bridge = %network_name,
        gateway_ip = %network_info.gateway_ip,
        "setting up macOS lite gateway (bridge)"
    );

    // Pre-cleanup: remove any leftover container with the same name.
    let _ = run_with_timeout(
        gateway_docker_cmd(gateway_docker_socket).args(["rm", "--force", &container_name]),
        DOCKER_RM_TIMEOUT,
        "docker rm (macOS lite pre-cleanup)",
    );

    // Step 7: Create gateway container on sandboxd-egress (upstream NIC).
    {
        let run_args = build_macos_gateway_docker_args(session_id, gateway_image_tag, owner_pool);
        let args_refs: Vec<&str> = run_args.iter().map(|s| s.as_str()).collect();
        let output = run_with_timeout(
            gateway_docker_cmd(gateway_docker_socket).args(&args_refs),
            DOCKER_RUN_TIMEOUT,
            "docker run (macOS lite gateway)",
        )?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(SandboxError::Gateway(format!(
                "docker run failed for macOS lite gateway container {container_name}: {stderr}"
            )));
        }
        debug!(
            session_id = %session_id,
            container = %container_name,
            "macOS lite gateway container started on sandboxd-egress"
        );
    }

    // Provision the per-session mitmproxy CA into the gateway container's
    // `/root/.mitmproxy` tmpfs. Without this, mitmproxy self-generates a
    // throwaway CA that the sandbox container's trust store (pinned to the
    // per-session CA) does not recognize, so every intercepted HTTPS flow
    // fails certificate verification. Shared with the full-backend sibling
    // via `provision_mitmproxy_ca`.
    provision_mitmproxy_ca(gateway_docker_socket, &container_name, ca_dir)?;

    // Write the Envoy static bootstrap into the container.
    {
        use crate::policy::{BOOTSTRAP_FILE_IN_CONTAINER, PolicyCompiler};
        let bootstrap = PolicyCompiler::compile_envoy_bootstrap();
        if let Err(e) = write_file_to_gateway_container(
            gateway_docker_socket,
            &container_name,
            BOOTSTRAP_FILE_IN_CONTAINER,
            &bootstrap,
        ) {
            return Err(SandboxError::Gateway(format!(
                "failed to write Envoy bootstrap to macOS lite gateway {container_name}: {e}"
            )));
        }
    }

    // Seed the initial deny-all Envoy listener.
    {
        use crate::policy::{LISTENER_FILE_IN_CONTAINER, PolicyCompiler};
        let listener = PolicyCompiler::compile_initial_envoy_listener();
        if let Err(e) = write_file_to_gateway_container(
            gateway_docker_socket,
            &container_name,
            LISTENER_FILE_IN_CONTAINER,
            &listener,
        ) {
            return Err(SandboxError::Gateway(format!(
                "failed to write Envoy listener to macOS lite gateway {container_name}: {e}"
            )));
        }
    }

    // Write initial DNS policy if provided.
    if let Some(policy_content) = initial_dns_policy {
        if let Err(e) = write_file_to_gateway_container(
            gateway_docker_socket,
            &container_name,
            "/etc/coredns/policy.conf",
            policy_content,
        ) {
            warn!(
                session_id = %session_id,
                error = %e,
                "failed to write initial DNS policy to macOS lite gateway (best-effort)"
            );
        }
    }

    // Step 8: Connect container to the per-session bridge with static IP.
    // For the lite path the network is a plain bridge (not macvlan).
    {
        let output = run_with_timeout(
            gateway_docker_cmd(gateway_docker_socket).args([
                "network",
                "connect",
                "--ip",
                &network_info.gateway_ip,
                &network_name,
                &container_name,
            ]),
            DOCKER_CONNECT_TIMEOUT,
            "docker network connect (lite bridge)",
        )?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(SandboxError::Gateway(format!(
                "failed to connect {container_name} to lite bridge {network_name}: {stderr}"
            )));
        }
        debug!(
            session_id = %session_id,
            container = %container_name,
            gateway_ip = %network_info.gateway_ip,
            "lite gateway container connected to per-session bridge"
        );
    }

    // Steps 9-11: Use GatewayManager over the forwarded socket for nft and health.
    {
        use crate::gateway::GatewayManager;
        let gm = GatewayManager::with_gateway_socket(gateway_docker_socket.to_path_buf());
        gm.inject_deny_all(session_id)?;
        gm.wait_for_components(session_id)?;
        gm.inject_dnat(session_id, network_info, &network_info.gateway_ip)?;
    }

    info!(
        session_id = %session_id,
        container = %container_name,
        "macOS lite gateway fully initialised"
    );
    Ok(())
}

/// Build the `docker run` argument vector for a macOS gateway container.
///
/// Extracted from `setup_macos_gateway` so the hardening properties
/// (no `--privileged`, `--read-only`, exactly one `--cap-add NET_ADMIN`,
/// no host-path bind-mounts) can be asserted in unit tests without
/// requiring a live Docker daemon.
///
/// The returned `Vec<String>` is the complete argument list starting with
/// `run`. Callers prepend `docker -H <socket>` and pass it to
/// `run_with_timeout`.
#[cfg(target_os = "macos")]
pub fn build_macos_gateway_docker_args(
    session_id: &SessionId,
    gateway_image_tag: &str,
    owner_pool: Option<&str>,
) -> Vec<String> {
    let container_name = macos_gateway_container_name(session_id);
    let mut args = vec![
        "run".to_string(),
        "-d".to_string(),
        "--name".to_string(),
        container_name,
        "--network".to_string(),
        crate::gateway_lima::EGRESS_BRIDGE_NAME.to_string(),
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
        "--sysctl".to_string(),
        "net.ipv4.ip_forward=1".to_string(),
        "--sysctl".to_string(),
        "net.ipv6.conf.all.forwarding=0".to_string(),
        // CoreDNS upstream forwarder. On macOS the gateway container runs
        // inside the gateway Lima VM, where Docker's embedded DNS at
        // 127.0.0.11 (the Linux default the entrypoint bakes in) is a dead
        // end: its own upstream, the VM's 127.0.0.53 systemd-resolved stub,
        // does not answer, so an allowed domain SERVFAILs on the forward even
        // though the DNS policy admits it. The VM reaches public resolvers
        // directly over eth0 (port 53 is permitted by the gateway-VM egress
        // firewall), so point CoreDNS there. Multiple resolvers give
        // failover; the entrypoint renders them into the `forward .` line.
        // This never weakens deny — a denied domain is answered NXDOMAIN
        // before the forward runs — and does not touch the Linux path, which
        // keeps the 127.0.0.11 default.
        "--env".to_string(),
        "SANDBOX_COREDNS_UPSTREAM=8.8.8.8 8.8.4.4 1.1.1.1".to_string(),
        "--restart".to_string(),
        "unless-stopped".to_string(),
        "--label".to_string(),
        format!("sandbox.session_id={session_id}"),
    ];

    if let Some(pool) = owner_pool {
        args.push("--label".to_string());
        args.push(format!("sandboxd.owner={pool}"));
    }

    // On macOS the listener and events host directories are not bind-mounted
    // into the gateway VM (the VM has its own filesystem). Bind-mounts from
    // the macOS host are not available inside the gateway VM's container
    // namespace.
    //
    // The initial deny-all Envoy listener is seeded via `docker exec` in
    // `setup_macos_gateway` so that Envoy can start. Dynamic LDS listener
    // updates use `AtomicListenerWriter` over the forwarded Docker socket
    // (`write_listener_into_container`) — see `PolicyDistributor::distribute`.

    args.push(gateway_image_tag.to_string());
    args
}

// ---------------------------------------------------------------------------
// teardown_macos_gateway
// ---------------------------------------------------------------------------

/// Tear down the macOS gateway side for a session (stop/rm flow).
///
/// Steps (all idempotent — "not found" is tolerated):
/// 1. Flush DNAT rules (exec nft into the gateway container)
/// 2. `docker rm -f sandbox-gw-<id>` via the forwarded socket
/// 3. `docker network rm sandbox-net-<id>` via the forwarded socket
///
/// Each step tolerates "not found" so the function is safe to call
/// even if the gateway was partially set up or has already been torn down.
#[cfg(target_os = "macos")]
pub fn teardown_macos_gateway(
    session_id: &SessionId,
    gateway_docker_socket: &Path,
) -> Result<(), SandboxError> {
    let container_name = macos_gateway_container_name(session_id);
    let network_name = macos_docker_network_name(session_id);

    info!(
        session_id = %session_id,
        container = %container_name,
        network = %network_name,
        "tearing down macOS gateway"
    );

    // Step 1: Flush DNAT rules (best-effort; container may already be gone).
    {
        use crate::gateway::GatewayManager;
        let gm = GatewayManager::with_gateway_socket(gateway_docker_socket.to_path_buf());
        if let Err(e) = gm.remove_dnat_rules(session_id) {
            warn!(
                session_id = %session_id,
                error = %e,
                "failed to remove macOS gateway DNAT rules (container may already be stopped)"
            );
        }
    }

    // Step 2: Remove the gateway container.
    let rm_output = run_with_timeout(
        gateway_docker_cmd(gateway_docker_socket).args(["rm", "-f", &container_name]),
        DOCKER_RM_TIMEOUT,
        "docker rm (macOS gateway container)",
    );
    match rm_output {
        Ok(output) if !output.status.success() => {
            let stderr = String::from_utf8_lossy(&output.stderr);
            // Tolerate "not found".
            if !stderr.contains("No such container") && !stderr.contains("no such container") {
                warn!(
                    session_id = %session_id,
                    container = %container_name,
                    stderr = %stderr.trim(),
                    "docker rm returned non-zero for macOS gateway (non-fatal)"
                );
            }
        }
        Err(e) => {
            warn!(
                session_id = %session_id,
                error = %e,
                "failed to run docker rm for macOS gateway container (non-fatal)"
            );
        }
        _ => {}
    }

    // Step 3: Remove the macvlan network.
    let rm_net = run_with_timeout(
        gateway_docker_cmd(gateway_docker_socket).args(["network", "rm", &network_name]),
        DOCKER_NETWORK_TIMEOUT,
        "docker network rm (macvlan)",
    );
    match rm_net {
        Ok(output) if !output.status.success() => {
            let stderr = String::from_utf8_lossy(&output.stderr);
            // Tolerate "not found".
            if !stderr.contains("No such network") && !stderr.contains("no such network") {
                warn!(
                    session_id = %session_id,
                    network = %network_name,
                    stderr = %stderr.trim(),
                    "docker network rm returned non-zero for macOS gateway (non-fatal)"
                );
            }
        }
        Err(e) => {
            warn!(
                session_id = %session_id,
                error = %e,
                "failed to run docker network rm for macOS gateway (non-fatal)"
            );
        }
        _ => {}
    }

    info!(
        session_id = %session_id,
        "macOS gateway teardown complete"
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// check_host_ip_forwarding_disabled
// ---------------------------------------------------------------------------

/// Assert that macOS host IP forwarding is disabled on both IPv4 and IPv6.
///
/// If either sysctl is 1, egress from a guest on-link to B+1 could be routed
/// off-segment by the macOS host's vmnet bridge, voiding the egress guarantee.
/// The daemon must refuse to start (or create sessions) when forwarding is on.
///
/// Sysctl keys used:
/// - IPv4: `net.inet.ip.forwarding`
/// - IPv6: `net.inet6.ip6.forwarding` (note: `inet6`, not `inet.ip6`)
///
/// An absent or unknown sysctl key is treated defensively as **off (0)** — a
/// missing forwarding knob cannot be enabled by a VPN client or Docker Desktop,
/// so we don't refuse startup for it. Only a confirmed value of `1` (or higher)
/// causes a hard refusal.
///
/// Returns `Ok(())` when both sysctls are 0 (or absent), `Err(SandboxError::Internal(_))`
/// with a descriptive message when either is confirmed non-zero.
#[cfg(target_os = "macos")]
pub fn check_host_ip_forwarding_disabled() -> Result<(), SandboxError> {
    let out4 = std::process::Command::new("/usr/sbin/sysctl")
        .args(["-n", "net.inet.ip.forwarding"])
        .output()
        .map_err(|e| SandboxError::Internal(format!("sysctl failed: {e}")))?;
    // The correct macOS IPv6 forwarding key is net.inet6.ip6.forwarding (note:
    // "inet6", not "inet.ip6"). The key net.inet.ip6.forwarding does not exist
    // on macOS and returns "unknown oid" on stderr with no stdout output.
    let out6 = std::process::Command::new("/usr/sbin/sysctl")
        .args(["-n", "net.inet6.ip6.forwarding"])
        .output()
        .map_err(|e| SandboxError::Internal(format!("sysctl failed: {e}")))?;

    // Treat an absent/unknown-oid sysctl (empty stdout) defensively as off (0)
    // for both keys: if the key doesn't exist the forwarding knob cannot be
    // enabled. Only a confirmed non-"0" value causes a hard refusal. Both keys
    // are handled identically so neither path can spuriously refuse to start
    // due to a missing key.
    let v4_raw = String::from_utf8_lossy(&out4.stdout).trim().to_string();
    let v4 = if v4_raw.is_empty() {
        "0".to_string()
    } else {
        v4_raw
    };
    let v6_raw = String::from_utf8_lossy(&out6.stdout).trim().to_string();
    let v6 = if v6_raw.is_empty() {
        "0".to_string()
    } else {
        v6_raw
    };

    if v4 != "0" {
        return Err(SandboxError::Internal(format!(
            "host IP forwarding (net.inet.ip.forwarding={v4}) must be 0 for egress control — \
             sandboxd refuses to start with forwarding enabled. \
             Internet Sharing and sleep/wake cycles can re-enable it. \
             Reset with: sudo sysctl -w net.inet.ip.forwarding=0"
        )));
    }
    if v6 != "0" {
        return Err(SandboxError::Internal(format!(
            "host IPv6 forwarding (net.inet6.ip6.forwarding={v6}) must be 0 for egress control — \
             sandboxd refuses to start with IPv6 forwarding enabled. \
             Reset with: sudo sysctl -w net.inet6.ip6.forwarding=0"
        )));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Write a file into a gateway container via `docker exec` over the
/// forwarded socket.
///
/// Used by `setup_macos_gateway` to write the Envoy bootstrap and the
/// initial DNS policy into the freshly-started container.
#[cfg(target_os = "macos")]
fn write_file_to_gateway_container(
    gateway_docker_socket: &Path,
    container_name: &str,
    container_path: &str,
    content: &str,
) -> Result<(), SandboxError> {
    use std::io::Write;
    use std::process::Stdio;

    // Use `mkdir -p` to ensure the parent directory exists before writing.
    // The listener file lives under `/etc/envoy/listeners/` which is not
    // created by the container image itself — the entrypoint only creates it
    // as part of the Envoy start sequence, which is gated on this file
    // already existing. Creating the parent inline here avoids the race.
    let parent = std::path::Path::new(container_path)
        .parent()
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_else(|| "/".to_string());
    debug_assert!(
        !parent.contains('\''),
        "write_file_to_gateway_container: parent path contains single-quote: {parent}"
    );
    debug_assert!(
        !container_path.contains('\''),
        "write_file_to_gateway_container: container_path contains single-quote: {container_path}"
    );
    let sh_cmd = format!("mkdir -p '{parent}' && cat > '{container_path}'");

    let mut child = gateway_docker_cmd(gateway_docker_socket)
        .args(["exec", "-i", container_name, "sh", "-c", &sh_cmd])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| {
            SandboxError::Gateway(format!(
                "failed to spawn write_file_to_gateway_container for {container_path}: {e}"
            ))
        })?;

    if let Some(ref mut stdin) = child.stdin {
        let _ = stdin.write_all(content.as_bytes());
    }
    child.stdin.take();

    let output = child.wait_with_output().map_err(|e| {
        SandboxError::Gateway(format!(
            "failed to wait for write_file_to_gateway_container {container_path}: {e}"
        ))
    })?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(SandboxError::Gateway(format!(
            "write_file_to_gateway_container {container_path} failed: {stderr}"
        )));
    }
    Ok(())
}

/// Read the per-session mitmproxy CA files from the host `ca_dir` and return
/// the `(container_path, content)` pairs to write into the gateway container's
/// `/root/.mitmproxy` tmpfs.
///
/// Two files mirror the Linux bind-mount layout (see `ca.rs`):
/// - `mitmproxy-ca.pem` — CA private key + cert concatenated (mitmproxy's
///   signing key; the sole secret in the lite provisioning set).
/// - `mitmproxy-ca-cert.pem` — cert only.
///
/// Factored out as a seam so the `setup_macos_lite_gateway` write step is unit-
/// testable without spawning `docker exec`: a test populates a temp `ca_dir`
/// and asserts the returned paths/contents.
#[cfg(target_os = "macos")]
fn mitmproxy_ca_writes(ca_dir: &Path) -> Result<Vec<(String, String)>, SandboxError> {
    let ca_pem_src = ca_dir.join("mitmproxy-ca.pem");
    let ca_cert_src = ca_dir.join("mitmproxy-ca-cert.pem");

    let ca_pem = std::fs::read_to_string(&ca_pem_src).map_err(|e| {
        SandboxError::Gateway(format!(
            "failed to read mitmproxy CA {}: {e}",
            ca_pem_src.display()
        ))
    })?;
    let ca_cert = std::fs::read_to_string(&ca_cert_src).map_err(|e| {
        SandboxError::Gateway(format!(
            "failed to read mitmproxy CA cert {}: {e}",
            ca_cert_src.display()
        ))
    })?;

    Ok(vec![
        ("/root/.mitmproxy/mitmproxy-ca.pem".to_string(), ca_pem),
        (
            "/root/.mitmproxy/mitmproxy-ca-cert.pem".to_string(),
            ca_cert,
        ),
    ])
}

/// Provision the per-session mitmproxy CA into the gateway container's
/// `/root/.mitmproxy` tmpfs over the forwarded Docker socket.
///
/// Shared by both [`setup_macos_gateway`] (full backend) and
/// [`setup_macos_lite_gateway`] (lite backend): without it mitmproxy
/// self-generates a throwaway CA that the sandbox VM/container's trust
/// store (pinned to the per-session CA) does not recognize, so every
/// intercepted HTTPS flow fails certificate verification. The CA key+cert
/// are the only secret material provisioned here — they go straight into
/// the container's tmpfs over the forwarded socket, never into the shared
/// VM filesystem.
///
/// `None` `ca_dir` is a no-op (caller chose not to provision a CA, e.g. a
/// degraded recovery path). A present-but-unreadable CA file is a hard
/// error (the gateway must never boot trusting an absent/empty CA).
#[cfg(target_os = "macos")]
fn provision_mitmproxy_ca(
    gateway_docker_socket: &Path,
    container_name: &str,
    ca_dir: Option<&Path>,
) -> Result<(), SandboxError> {
    let Some(ca_dir) = ca_dir else {
        return Ok(());
    };
    for (container_path, content) in mitmproxy_ca_writes(ca_dir)? {
        if let Err(e) = write_file_to_gateway_container(
            gateway_docker_socket,
            container_name,
            &container_path,
            &content,
        ) {
            return Err(SandboxError::Gateway(format!(
                "failed to write mitmproxy CA {container_path} to macOS gateway \
                 {container_name}: {e}"
            )));
        }
    }
    Ok(())
}

/// Compute B+1 from a subnet CIDR string (e.g. `"10.209.128.0/29"` → `"10.209.128.1"`).
///
/// Used to derive the IPAM gateway address for the macvlan network.
/// Docker requires a gateway address for macvlan IPAM; we pick B+1 (the
/// first usable address in the /29 block) as the IPAM "gateway" — purely
/// for IPAM bookkeeping, not as a packet-forwarding gateway. The real
/// packet gateway is the gateway container at B+3 (`network_info.gateway_ip`).
#[cfg(target_os = "macos")]
fn compute_subnet_plus_one(subnet_cidr: &str) -> Result<String, SandboxError> {
    // Parse the base address from the CIDR string.
    let base_str = subnet_cidr
        .split('/')
        .next()
        .ok_or_else(|| SandboxError::Network(format!("invalid subnet CIDR: {subnet_cidr}")))?;
    let base: std::net::Ipv4Addr = base_str.parse().map_err(|e| {
        SandboxError::Network(format!(
            "failed to parse subnet base address {base_str}: {e}"
        ))
    })?;
    let base_u32 = u32::from(base);
    Ok(std::net::Ipv4Addr::from(base_u32 + 1).to_string())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    #[cfg(target_os = "macos")]
    use super::*;

    // -- Container / network naming -------------------------------------------

    #[cfg(target_os = "macos")]
    #[test]
    fn test_gateway_container_naming() {
        let id = SessionId::parse("aabbccddeeff").unwrap();
        let cname = macos_gateway_container_name(&id);
        assert!(
            cname.starts_with("sandbox-gw-"),
            "container name must start with sandbox-gw-"
        );
        assert!(
            cname.contains("aabbccddeeff"),
            "container name must contain session id"
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn test_docker_network_naming() {
        let id = SessionId::parse("aabbccddeeff").unwrap();
        let nname = macos_docker_network_name(&id);
        assert!(
            nname.starts_with("sandbox-net-"),
            "network name must start with sandbox-net-"
        );
        assert!(
            nname.contains("aabbccddeeff"),
            "network name must contain session id"
        );
    }

    // -- mitmproxy CA provisioning seam (hermetic) ---------------------------

    /// `mitmproxy_ca_writes` reads the two per-session CA files from the host
    /// `ca_dir` and returns the `(container_path, content)` pairs that
    /// `setup_macos_lite_gateway` writes into the gateway container's
    /// `/root/.mitmproxy` tmpfs. Pins the canonical in-container paths and that
    /// each file's bytes round-trip — the contract that makes the sandbox
    /// container trust the same CA mitmproxy signs with.
    #[cfg(target_os = "macos")]
    #[test]
    fn mitmproxy_ca_writes_returns_two_files() {
        let dir = tempfile::tempdir().unwrap();
        let ca_pem = "KEY+CERT-COMBINED\n";
        let ca_cert = "CERT-ONLY\n";
        std::fs::write(dir.path().join("mitmproxy-ca.pem"), ca_pem).unwrap();
        std::fs::write(dir.path().join("mitmproxy-ca-cert.pem"), ca_cert).unwrap();

        let writes = mitmproxy_ca_writes(dir.path()).expect("ca writes");
        assert_eq!(
            writes,
            vec![
                (
                    "/root/.mitmproxy/mitmproxy-ca.pem".to_string(),
                    ca_pem.to_string()
                ),
                (
                    "/root/.mitmproxy/mitmproxy-ca-cert.pem".to_string(),
                    ca_cert.to_string()
                ),
            ],
            "mitmproxy CA writes must target the two canonical tmpfs paths with \
             the host CA file contents verbatim",
        );
    }

    /// A missing CA file is a hard error (the caller aborts create) — the
    /// gateway must never boot trusting an absent/empty CA.
    #[cfg(target_os = "macos")]
    #[test]
    fn mitmproxy_ca_writes_errors_on_missing_file() {
        let dir = tempfile::tempdir().unwrap();
        // Only the combined file exists; the cert-only file is absent.
        std::fs::write(dir.path().join("mitmproxy-ca.pem"), "x").unwrap();
        assert!(
            mitmproxy_ca_writes(dir.path()).is_err(),
            "missing mitmproxy-ca-cert.pem must surface as an error"
        );
    }

    /// `provision_mitmproxy_ca(None)` is a no-op: when no CA dir is supplied
    /// the helper returns `Ok(())` without touching the socket.
    ///
    /// The socket path is bogus on purpose. Any code path that reaches socket
    /// I/O (the `write_file_to_gateway_container` call inside the `Some` branch)
    /// would error and propagate via `?`, making the test fail — so an `Ok`
    /// result proves the `None` branch short-circuited before any `docker exec`.
    /// See `provision_mitmproxy_ca_with_complete_ca_reaches_socket` below for
    /// the complementary assertion that the `Some`+complete-CA path DOES reach
    /// the socket.
    #[cfg(target_os = "macos")]
    #[test]
    fn provision_mitmproxy_ca_none_is_noop() {
        let bogus_sock = std::path::Path::new("/nonexistent/gateway-docker.sock");
        // unwrap() rather than is_ok(): if it errors, the message surfaces the cause.
        provision_mitmproxy_ca(bogus_sock, "sandbox-gw-x", None)
            .expect("provision_mitmproxy_ca(None) must be a no-op Ok");
    }

    /// `provision_mitmproxy_ca` with a complete CA dir DOES reach the socket:
    /// a bogus socket path errors after the host-file reads succeed, proving
    /// the `None` test above is a genuine short-circuit check (not "always Ok").
    #[cfg(target_os = "macos")]
    #[test]
    fn provision_mitmproxy_ca_with_complete_ca_reaches_socket() {
        let dir = tempfile::tempdir().unwrap();
        // Write both files that `mitmproxy_ca_writes` requires.
        std::fs::write(dir.path().join("mitmproxy-ca.pem"), "fake-key").unwrap();
        std::fs::write(dir.path().join("mitmproxy-ca-cert.pem"), "fake-cert").unwrap();
        let bogus_sock = std::path::Path::new("/nonexistent/gateway-docker.sock");
        // Host-file reads succeed; socket I/O is attempted and must fail.
        let result = provision_mitmproxy_ca(bogus_sock, "sandbox-gw-x", Some(dir.path()));
        assert!(
            result.is_err(),
            "provision_mitmproxy_ca with a complete CA dir must error on a bogus socket"
        );
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("sandbox-gw-x"),
            "error must name the container; got: {msg}"
        );
    }

    /// A present-but-incomplete CA dir is a hard error before any socket I/O:
    /// `provision_mitmproxy_ca` surfaces the `mitmproxy_ca_writes` read
    /// failure (missing cert-only file) rather than silently proceeding. The
    /// error is produced reading the host CA files, so the bogus socket is
    /// never contacted.
    #[cfg(target_os = "macos")]
    #[test]
    fn provision_mitmproxy_ca_missing_file_errors() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("mitmproxy-ca.pem"), "x").unwrap();
        let bogus_sock = std::path::Path::new("/nonexistent/gateway-docker.sock");
        assert!(
            provision_mitmproxy_ca(bogus_sock, "sandbox-gw-x", Some(dir.path())).is_err(),
            "provision_mitmproxy_ca with an incomplete CA dir must error"
        );
    }

    // -- VmnetPool slot claim/release (hermetic, delegates to VmnetPool) ------

    #[cfg(target_os = "macos")]
    #[test]
    fn test_slot_claim_then_release_no_leak() {
        use crate::network::VmnetPool;
        let pool = VmnetPool::new(4);
        let id = SessionId::parse("aabbccddeeff").unwrap();
        let (slot, _subnet, _gw, _vm) = pool.claim_lima_slot(&id).unwrap();
        assert!(pool.allocated_slot_indices().contains(&slot.index));
        pool.release_lima_slot(&id).unwrap();
        // After release, pool is empty.
        assert!(
            !pool.allocated_slot_indices().contains(&slot.index),
            "slot must be released"
        );
        assert_eq!(pool.running_session_count(), 0);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn test_pool_exhaustion() {
        use crate::network::VmnetPool;
        let pool = VmnetPool::new(2);
        let id0 = SessionId::parse("000000000000").unwrap();
        let id1 = SessionId::parse("111111111111").unwrap();
        let id2 = SessionId::parse("222222222222").unwrap();
        pool.claim_lima_slot(&id0).unwrap();
        pool.claim_lima_slot(&id1).unwrap();
        // Third claim must fail.
        let result = pool.claim_lima_slot(&id2);
        assert!(
            result.is_err(),
            "claiming beyond max_slots must fail with an error"
        );
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("max concurrent sessions reached"),
            "error must mention 'max concurrent sessions reached': {err_msg}"
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn test_partial_create_rollback_releases_slot() {
        use crate::network::{NetworkInfo, VmnetPool, VmnetSlot};
        let pool = VmnetPool::new(4);
        let id = SessionId::parse("aabbccddeeff").unwrap();
        let (slot, subnet_cidr, gw, vm) = pool.claim_lima_slot(&id).unwrap();

        // Simulate partial create: set_lima_network_info was called.
        let info = NetworkInfo {
            bridge_name: format!("lima{}", slot.index),
            subnet: subnet_cidr,
            gateway_ip: gw.to_string(),
            vm_ip: vm.to_string(),
            docker_network_name: macos_docker_network_name(&id),
            vmnet_slot: Some(VmnetSlot {
                index: slot.index,
                daemon_label: slot.daemon_label.clone(),
                socket_path: slot.socket_path.clone(),
            }),
        };
        pool.set_lima_network_info(&id, slot.index, info).unwrap();

        // Rollback: release.
        pool.release_lima_slot(&id).unwrap();
        assert!(
            !pool.allocated_slot_indices().contains(&slot.index),
            "slot must be freed on rollback"
        );
        assert_eq!(pool.running_session_count(), 0);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn test_vmnet_slot_json_roundtrip() {
        use crate::network::{NetworkInfo, VmnetSlot};
        let info = NetworkInfo {
            bridge_name: "lima2".to_string(),
            subnet: "10.209.128.16/29".to_string(),
            gateway_ip: "10.209.128.19".to_string(),
            vm_ip: "10.209.128.20".to_string(),
            docker_network_name: "sandbox-net-aabbccddeeff".to_string(),
            vmnet_slot: Some(VmnetSlot {
                index: 2,
                daemon_label: "io.sandboxd.vmnet.2".to_string(),
                socket_path: "/var/run/sandbox/vmnet/slot-2.sock".to_string(),
            }),
        };
        let json = serde_json::to_string(&info).unwrap();
        let decoded: NetworkInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.vmnet_slot.as_ref().unwrap().index, 2);
        assert_eq!(
            decoded.vmnet_slot.as_ref().unwrap().daemon_label,
            "io.sandboxd.vmnet.2"
        );
        assert_eq!(
            decoded.vmnet_slot.as_ref().unwrap().socket_path,
            "/var/run/sandbox/vmnet/slot-2.sock"
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn test_old_row_deserialize_missing_vmnet_slot() {
        // Old NetworkInfo JSON without vmnet_slot must deserialize with vmnet_slot: None.
        let old_json = r#"{
            "bridge_name": "sb-abcdef012345",
            "subnet": "10.209.0.0/28",
            "gateway_ip": "10.209.0.2",
            "vm_ip": "10.209.0.3",
            "docker_network_name": "sandbox-net-abcdef012345"
        }"#;
        let info: crate::network::NetworkInfo = serde_json::from_str(old_json).unwrap();
        assert!(
            info.vmnet_slot.is_none(),
            "old rows without vmnet_slot must deserialize with None"
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn test_forwarding_check_uses_correct_sysctl_keys() {
        // Confirm both sysctl keys exist and are readable on this host:
        // - IPv4: net.inet.ip.forwarding  (present on macOS, returns 0 or 1)
        // - IPv6: net.inet6.ip6.forwarding (present on macOS, note "inet6" not "inet")
        // Also confirm the wrong IPv6 key (net.inet.ip6.forwarding) is absent.
        let ipv4_out = std::process::Command::new("sysctl")
            .args(["-n", "net.inet.ip.forwarding"])
            .output()
            .expect("sysctl must be available on macOS");
        let ipv4_val = String::from_utf8_lossy(&ipv4_out.stdout).trim().to_string();
        assert!(
            !ipv4_val.is_empty(),
            "net.inet.ip.forwarding must be readable on macOS (got empty output)"
        );
        assert!(
            ipv4_val == "0" || ipv4_val == "1",
            "net.inet.ip.forwarding must be 0 or 1, got: {ipv4_val:?}"
        );

        let ipv6_out = std::process::Command::new("sysctl")
            .args(["-n", "net.inet6.ip6.forwarding"])
            .output()
            .expect("sysctl must be available on macOS");
        let ipv6_val = String::from_utf8_lossy(&ipv6_out.stdout).trim().to_string();
        assert!(
            !ipv6_val.is_empty(),
            "net.inet6.ip6.forwarding must be readable on macOS (got empty output)"
        );
        assert!(
            ipv6_val == "0" || ipv6_val == "1",
            "net.inet6.ip6.forwarding must be 0 or 1, got: {ipv6_val:?}"
        );

        // The wrong IPv6 key must produce empty stdout (unknown oid on macOS).
        let wrong_out = std::process::Command::new("sysctl")
            .args(["-n", "net.inet.ip6.forwarding"])
            .output()
            .expect("sysctl must be available");
        let wrong_val = String::from_utf8_lossy(&wrong_out.stdout)
            .trim()
            .to_string();
        assert!(
            wrong_val.is_empty(),
            "net.inet.ip6.forwarding must be absent on macOS (unknown oid, empty stdout); \
             got: {wrong_val:?}. If this changed, update the sysctl key in check_host_ip_forwarding_disabled."
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn test_forwarding_check_treats_empty_sysctl_as_off() {
        // Both the IPv4 and IPv6 paths treat an absent/empty-stdout sysctl as
        // off (0). This test verifies the symmetric behaviour:
        // - Neither path spuriously refuses to start when a key is absent.
        // - Any error produced must reference only the correct key names.
        //
        // On a correctly-configured dev machine both keys return "0", so the
        // function returns Ok. If either returns "1", Err is expected to name
        // the correct key (net.inet.ip.forwarding or net.inet6.ip6.forwarding),
        // never the wrong key (net.inet.ip6.forwarding).
        let result = check_host_ip_forwarding_disabled();
        if let Err(ref e) = result {
            let msg = e.to_string();
            // Must NOT reference the wrong IPv6 key (the one that is an
            // unknown oid on macOS and would cause a spurious false alarm).
            assert!(
                !msg.contains("net.inet.ip6.forwarding"),
                "error must NOT reference the absent key net.inet.ip6.forwarding; got: {msg}"
            );
            // Must reference one of the two correct keys.
            assert!(
                msg.contains("net.inet.ip.forwarding") || msg.contains("net.inet6.ip6.forwarding"),
                "error must reference a correct sysctl key; got: {msg}"
            );
        }
        // If Ok: both keys returned "0" (or were absent, treated as 0) —
        // the symmetric empty-as-off handling is working for both paths.
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn test_macos_gateway_hardening_args() {
        // Assert the gateway container's hardened config via `build_macos_gateway_docker_args`:
        // - No `--privileged` (shared-gateway-VM blast-radius control).
        // - `--read-only` rootfs.
        // - Exactly one `--cap-add` and it is `NET_ADMIN` (required for in-container
        //   nft injection; no other capability added).
        // - No host system bind-mounts (no `-v` args).
        // - The in-VM Docker socket is never bind-mounted into the container (a
        //   gateway-container escape via the shared Docker socket would compromise
        //   all sessions at once).
        let id = SessionId::parse("aabbccddeeff").unwrap();
        let args =
            build_macos_gateway_docker_args(&id, "sandbox-gateway:test", Some("10.209.128.0/24"));

        // Must contain --read-only.
        assert!(
            args.contains(&"--read-only".to_string()),
            "gateway run args must contain --read-only; got: {args:?}"
        );

        // Exactly one --cap-add and it must be NET_ADMIN.
        let cap_add_count = args.iter().filter(|a| *a == "--cap-add").count();
        assert_eq!(
            cap_add_count, 1,
            "gateway run args must have exactly one --cap-add (got {cap_add_count}); args: {args:?}"
        );
        // NET_ADMIN must appear as the value immediately following --cap-add.
        let cap_add_pos = args.iter().position(|a| a == "--cap-add").unwrap();
        assert_eq!(
            args[cap_add_pos + 1],
            "NET_ADMIN",
            "the --cap-add value must be NET_ADMIN; got {:?}",
            args[cap_add_pos + 1]
        );

        // Must NOT contain --privileged.
        assert!(
            !args.iter().any(|a| a == "--privileged"),
            "gateway run args must NOT contain --privileged; got: {args:?}"
        );

        // Must NOT bind-mount anything (no -v args). macOS gateway containers
        // run fully on tmpfs inside the gateway VM; host paths are not available.
        assert!(
            !args.iter().any(|a| a == "-v" || a == "--volume"),
            "gateway run args must NOT contain -v / --volume bind-mounts; got: {args:?}"
        );

        // The in-VM Docker socket must never appear as a bind-mount source.
        // (Belt-and-suspenders check in case a future change adds -v args.)
        assert!(
            !args.iter().any(|a| a.contains("docker.sock")),
            "gateway run args must not reference docker.sock in any arg; got: {args:?}"
        );
    }

    /// macOS gateway containers must set `SANDBOX_COREDNS_UPSTREAM` to
    /// reachable public resolvers. Inside the gateway Lima VM, CoreDNS's
    /// baked-in default upstream (Docker's embedded DNS at 127.0.0.11) is a
    /// dead end — its own upstream, the VM's 127.0.0.53 systemd-resolved stub,
    /// does not answer — so an allowed domain SERVFAILs on the forward even
    /// though the policy admits it. The env var overrides the forwarder to
    /// public resolvers the VM reaches directly over eth0, which is what
    /// makes egress *allow* actually resolve on macOS. Deny is unaffected (a
    /// denied domain is NXDOMAIN'd before the forward runs), and the Linux
    /// path is untouched (it never uses this builder and keeps 127.0.0.11).
    #[cfg(target_os = "macos")]
    #[test]
    fn test_macos_gateway_sets_coredns_upstream_to_public_resolvers() {
        let id = SessionId::parse("aabbccddeeff").unwrap();
        let args = build_macos_gateway_docker_args(&id, "sandbox-gateway:test", None);

        // `--env` must be immediately followed by the SANDBOX_COREDNS_UPSTREAM
        // assignment; docker requires the KEY=VALUE to follow the flag.
        let env_pos = args
            .iter()
            .position(|a| a == "--env")
            .unwrap_or_else(|| panic!("gateway run args must carry an --env flag; got: {args:?}"));
        let env_val = &args[env_pos + 1];
        assert!(
            env_val.starts_with("SANDBOX_COREDNS_UPSTREAM="),
            "the --env value must set SANDBOX_COREDNS_UPSTREAM; got {env_val:?}"
        );
        // Must NOT be the dead-end in-VM Docker embedded resolver — that is
        // exactly the value that SERVFAILs allowed domains on macOS.
        assert!(
            !env_val.contains("127.0.0.11"),
            "macOS CoreDNS upstream must not be the dead-end 127.0.0.11 \
             embedded resolver; got {env_val:?}"
        );
        // Must point at a public resolver the VM can reach directly.
        assert!(
            env_val.contains("8.8.8.8") || env_val.contains("1.1.1.1"),
            "macOS CoreDNS upstream must be a reachable public resolver; \
             got {env_val:?}"
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn test_compute_subnet_plus_one() {
        assert_eq!(
            compute_subnet_plus_one("10.209.128.0/29").unwrap(),
            "10.209.128.1"
        );
        assert_eq!(
            compute_subnet_plus_one("10.209.0.0/28").unwrap(),
            "10.209.0.1"
        );
        assert_eq!(
            compute_subnet_plus_one("192.168.0.0/24").unwrap(),
            "192.168.0.1"
        );
    }
}
