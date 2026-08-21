/// macOS session lifecycle helpers.
///
/// Orchestrates the macOS-specific create/teardown flow for Lima (full-backend)
/// sessions:
///
/// - `setup_macos_gateway` — creates the per-session macvlan Docker network and
///   gateway container inside the gateway Lima VM (steps 6–11 of the create flow).
/// - `teardown_macos_gateway` — removes the gateway container and macvlan network
///   on stop/rm (idempotent, tolerates "not found").
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
use std::time::Duration;

#[cfg(target_os = "macos")]
use tracing::{debug, info, warn};

#[cfg(target_os = "macos")]
use sandbox_docker_argv::container::{InspectFlag, InspectFormat, RemoveForce};
#[cfg(target_os = "macos")]
use sandbox_docker_argv::gateway::GatewayFile;
use sandbox_docker_argv::network::{
    EndpointGatewayPriority, NetworkCreateSpec, NetworkDriver, NetworkOption,
};

use crate::docker::{DockerOp, DockerRoute};
use crate::error::SandboxError;
#[cfg(target_os = "macos")]
use crate::network::NetworkInfo;
#[cfg(target_os = "macos")]
use crate::policy_distributor::{envoy_seed_artifacts, write_gateway_file};
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
    docker: &DockerRoute,
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

        // macvlan_mode=private blocks macvlan-to-macvlan traffic on the same
        // parent NIC. Defence-in-depth L2 isolation: sessions normally use
        // different parent NICs (different slots), but private mode prevents
        // cross-session L2 traffic even if two sessions ended up sharing a
        // parent (e.g. after slot reuse).
        let spec = NetworkCreateSpec {
            name: network_name.clone(),
            driver: NetworkDriver::Macvlan,
            subnet: Some(network_info.subnet.clone()),
            gateway: Some(ipam_gateway),
            session_id: Some(session_id.to_string()),
            owner_pool: None,
            options: vec![
                NetworkOption::MacvlanParent(nic_name.to_string()),
                NetworkOption::MacvlanModePrivate,
            ],
        };
        let output = docker.run(
            DockerOp::NetworkCreate { spec },
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
    let _ = docker.run(
        DockerOp::ContainerRemove {
            name: container_name.clone(),
            force: RemoveForce::Long,
        },
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
        let output = docker.run(
            gateway_container_run_op(session_id, gateway_image_tag, owner_pool),
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
    provision_mitmproxy_ca(docker, &container_name, ca_dir)?;

    // Seed both Envoy artifacts into the container.
    //
    // The gateway entrypoint blocks until the bootstrap file and the
    // listener file both exist before it starts Envoy. On macOS the listener
    // directory is not bind-mounted from the host (no host-path →
    // gateway-VM-path bridge), so both are written into the container's
    // tmpfs; the write op's delivery script creates the parent directory
    // inline, so no separate mkdir step is needed.
    //
    // The initial listener is deny-all, which is what makes unblocking the
    // entrypoint safe. Subsequent policy-driven listener replacements are
    // distributed via `PolicyDistributor::distribute` using
    // `write_listener_into_container` — the same content the Linux
    // `AtomicListenerWriter` writes, delivered in-container instead.
    for (file, content) in envoy_seed_artifacts() {
        if let Err(e) = write_gateway_file(docker, &container_name, file, &content) {
            return Err(SandboxError::Gateway(format!(
                "failed to write {} to macOS gateway {container_name}: {e}",
                file.path()
            )));
        }
        debug!(
            session_id = %session_id,
            artifact = file.as_str(),
            "seeded Envoy artifact into macOS gateway container"
        );
    }

    // Write the initial DNS policy if provided.
    if let Some(policy_content) = initial_dns_policy {
        if let Err(e) = write_gateway_file(
            docker,
            &container_name,
            GatewayFile::CorednsPolicy,
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
    //
    // The endpoint takes part in Docker's default-gateway election exactly
    // as it always has. Only the lite bridge declines it, because only that
    // bridge's masquerade was removed.
    {
        let output = docker.run(
            DockerOp::NetworkConnect {
                network: network_name.clone(),
                container: container_name.clone(),
                ip: Some(network_info.gateway_ip.clone()),
                gateway_priority: EndpointGatewayPriority::Default,
            },
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
        let gm = GatewayManager::with_route(docker.clone());

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
    docker: &DockerRoute,
    gateway_image_tag: &str,
    ca_dir: Option<&Path>,
    initial_dns_policy: Option<&str>,
    owner_pool: Option<&str>,
) -> Result<String, SandboxError> {
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
    let _ = docker.run(
        DockerOp::ContainerRemove {
            name: container_name.clone(),
            force: RemoveForce::Long,
        },
        DOCKER_RM_TIMEOUT,
        "docker rm (macOS lite pre-cleanup)",
    );

    // Step 7: Create gateway container on sandboxd-egress (upstream NIC).
    {
        let output = docker.run(
            gateway_container_run_op(session_id, gateway_image_tag, owner_pool),
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
    provision_mitmproxy_ca(docker, &container_name, ca_dir)?;

    // Seed both Envoy artifacts into the container — same reasoning as the
    // full-backend sibling: the entrypoint blocks on both, and the initial
    // listener is deny-all.
    for (file, content) in envoy_seed_artifacts() {
        if let Err(e) = write_gateway_file(docker, &container_name, file, &content) {
            return Err(SandboxError::Gateway(format!(
                "failed to write {} to macOS lite gateway {container_name}: {e}",
                file.path()
            )));
        }
    }

    // Write initial DNS policy if provided.
    if let Some(policy_content) = initial_dns_policy {
        if let Err(e) = write_gateway_file(
            docker,
            &container_name,
            GatewayFile::CorednsPolicy,
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
    //
    // The endpoint declines the default-gateway election. Attaching a
    // second network to a running container otherwise moves its default
    // route onto the new endpoint, which would put this container's own way
    // out on the session bridge — a bridge deliberately created without
    // masquerade (`session_bridge_options`, `network.rs`), and therefore a
    // dead end. Its route out is the egress bridge it was started on.
    {
        let output = docker.run(
            DockerOp::NetworkConnect {
                network: network_name.clone(),
                container: container_name.clone(),
                ip: Some(network_info.gateway_ip.clone()),
                gateway_priority: EndpointGatewayPriority::NeverDefaultGateway,
            },
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

    // Step 8a: read the address Docker gave the gateway on the egress
    // bridge. The gateway's own egress filter admits its upstream leg by
    // source address, and with the session bridge no longer masquerading
    // that leg sources from here — so the ruleset injected below has to
    // name it. Docker assigns it per container, which is why it is read
    // here, on the create path, rather than remembered.
    let egress_ip = {
        let output = docker.run(
            DockerOp::ContainerInspect {
                name: container_name.clone(),
                format: InspectFormat::EgressNetworkIpAddress,
                flag: InspectFlag::Short,
            },
            DOCKER_CONNECT_TIMEOUT,
            "docker inspect (gateway egress address)",
        )?;
        let addr = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if !output.status.success() || addr.is_empty() || addr == "<no value>" {
            return Err(SandboxError::Gateway(format!(
                "could not read {container_name}'s address on {}: without it the \
                 gateway's own upstream leg is not admitted by its egress filter",
                crate::gateway_lima::EGRESS_BRIDGE_NAME
            )));
        }
        debug!(
            session_id = %session_id,
            container = %container_name,
            egress_ip = %addr,
            "gateway egress-side address discovered"
        );
        addr
    };
    let network_info = &NetworkInfo {
        gateway_egress_ip: Some(egress_ip.clone()),
        ..network_info.clone()
    };

    // Steps 9-11: Use GatewayManager over the forwarded socket for nft and health.
    {
        use crate::gateway::GatewayManager;
        let gm = GatewayManager::with_route(docker.clone());
        gm.inject_deny_all(session_id)?;
        gm.wait_for_components(session_id)?;
        gm.inject_dnat(session_id, network_info, &network_info.gateway_ip)?;
    }

    info!(
        session_id = %session_id,
        container = %container_name,
        "macOS lite gateway fully initialised"
    );
    Ok(egress_ip)
}

/// The `docker run` op for a session's gateway container inside the VM.
///
/// The hardening properties (no `--privileged`, `--read-only`, exactly one
/// `--cap-add NET_ADMIN`, no host-path bind-mounts) live in the shared argv
/// builder, where both sides of the broker channel render them from the same
/// source.
///
/// On macOS the listener and events host directories are deliberately not
/// bind-mounted: the gateway VM has its own filesystem, so a bind from the
/// macOS host would mount nothing. The initial deny-all Envoy listener is
/// seeded by a separate write into the container's tmpfs, and dynamic LDS
/// updates go the same way.
#[cfg(target_os = "macos")]
fn gateway_container_run_op(
    session_id: &SessionId,
    gateway_image_tag: &str,
    owner_pool: Option<&str>,
) -> DockerOp {
    DockerOp::GatewayContainerRun {
        session_id: session_id.to_string(),
        image_tag: gateway_image_tag.to_string(),
        network: crate::gateway_lima::EGRESS_BRIDGE_NAME.to_string(),
        owner_pool: owner_pool.map(str::to_string),
        // Inside the gateway VM, Docker's embedded resolver at 127.0.0.11 is
        // a dead end: its own upstream (the VM's systemd-resolved stub) does
        // not answer, so an allowed domain SERVFAILs on the forward even
        // though DNS policy admits it. The VM reaches public resolvers
        // directly over eth0. This never weakens deny — a denied domain is
        // answered NXDOMAIN before the forward runs — and does not touch the
        // Linux path, which keeps the 127.0.0.11 default.
        coredns_upstream: Some(MACOS_COREDNS_UPSTREAM.to_string()),
    }
}

/// Public resolvers CoreDNS forwards to inside the gateway VM. Multiple
/// entries give failover; the entrypoint renders them into the `forward .`
/// line.
#[cfg(target_os = "macos")]
const MACOS_COREDNS_UPSTREAM: &str = "8.8.8.8 8.8.4.4 1.1.1.1";

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
    docker: &DockerRoute,
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
        let gm = GatewayManager::with_route(docker.clone());
        if let Err(e) = gm.remove_dnat_rules(session_id) {
            warn!(
                session_id = %session_id,
                error = %e,
                "failed to remove macOS gateway DNAT rules (container may already be stopped)"
            );
        }
    }

    // Step 2: Remove the gateway container.
    let rm_output = docker.run(
        DockerOp::ContainerRemove {
            name: container_name.clone(),
            force: RemoveForce::Short,
        },
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
    let rm_net = docker.run(
        DockerOp::NetworkRemove {
            name: network_name.clone(),
        },
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

// NOTE(#80): The macOS full-backend does not gate on host IP forwarding.
// A root sandbox guest can bypass the gateway by routing via the host bridge
// when the host has IP forwarding + NAT (e.g. Internet Sharing) enabled.
// This is a known open issue; the structural fix is deferred and tracked in
// GitHub issue #80.

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Read the per-session mitmproxy CA files from the host `ca_dir` and return
/// the `(destination, content)` pairs to write into the gateway container's
/// `/root/.mitmproxy` tmpfs.
///
/// Two files mirror the Linux bind-mount layout (see `ca.rs`):
/// - `mitmproxy-ca.pem` — CA private key + cert concatenated (mitmproxy's
///   signing key; the sole secret in the lite provisioning set).
/// - `mitmproxy-ca-cert.pem` — cert only.
///
/// Factored out as a seam so the `setup_macos_lite_gateway` write step is unit-
/// testable without spawning `docker exec`: a test populates a temp `ca_dir`
/// and asserts the returned destinations/contents.
#[cfg(target_os = "macos")]
fn mitmproxy_ca_writes(ca_dir: &Path) -> Result<Vec<(GatewayFile, String)>, SandboxError> {
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
        (GatewayFile::MitmproxyCaKey, ca_pem),
        (GatewayFile::MitmproxyCaCert, ca_cert),
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
    docker: &DockerRoute,
    container_name: &str,
    ca_dir: Option<&Path>,
) -> Result<(), SandboxError> {
    let Some(ca_dir) = ca_dir else {
        return Ok(());
    };
    for (file, content) in mitmproxy_ca_writes(ca_dir)? {
        if let Err(e) = write_gateway_file(docker, container_name, file, &content) {
            return Err(SandboxError::Gateway(format!(
                "failed to write mitmproxy CA {} to macOS gateway {container_name}: {e}",
                file.path()
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

    /// A stand-in operator uid for pool tests. The pool does not interpret
    /// it — it records the uid with the claim and names it in the
    /// exhaustion error — so any value above the system-uid floor does.
    const TEST_OPERATOR_UID: u32 = 501;
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
    /// `ca_dir` and returns the `(destination, content)` pairs that
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
                (GatewayFile::MitmproxyCaKey, ca_pem.to_string()),
                (GatewayFile::MitmproxyCaCert, ca_cert.to_string()),
            ],
            "mitmproxy CA writes must target the two canonical tmpfs paths with \
             the host CA file contents verbatim",
        );
        assert_eq!(writes[0].0.path(), "/root/.mitmproxy/mitmproxy-ca.pem");
        assert_eq!(writes[1].0.path(), "/root/.mitmproxy/mitmproxy-ca-cert.pem");
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

    /// A route that cannot reach any Docker daemon, for asserting which
    /// paths do and do not attempt an invocation.
    #[cfg(target_os = "macos")]
    fn unreachable_route() -> DockerRoute {
        DockerRoute::Vm {
            owner_uid: TEST_OPERATOR_UID,
            executor: std::sync::Arc::new(crate::docker::LocalSocketDockerExecutor::new(
                "/nonexistent/gateway-docker.sock",
                "/nonexistent",
            )),
        }
    }

    /// `provision_mitmproxy_ca(None)` is a no-op: when no CA dir is supplied
    /// the helper returns `Ok(())` without running any docker op.
    ///
    /// The route is unreachable on purpose. Any code path that reaches an
    /// invocation would error and propagate via `?`, making the test fail —
    /// so an `Ok` result proves the `None` branch short-circuited. See
    /// `provision_mitmproxy_ca_with_complete_ca_runs_the_write` below for the
    /// complementary assertion that the `Some`+complete-CA path DOES.
    #[cfg(target_os = "macos")]
    #[test]
    fn provision_mitmproxy_ca_none_is_noop() {
        // unwrap() rather than is_ok(): if it errors, the message surfaces the cause.
        provision_mitmproxy_ca(&unreachable_route(), "sandbox-gw-x", None)
            .expect("provision_mitmproxy_ca(None) must be a no-op Ok");
    }

    /// `provision_mitmproxy_ca` with a complete CA dir DOES run the write:
    /// an unreachable route errors after the host-file reads succeed, proving
    /// the `None` test above is a genuine short-circuit check (not "always Ok").
    #[cfg(target_os = "macos")]
    #[test]
    fn provision_mitmproxy_ca_with_complete_ca_runs_the_write() {
        let dir = tempfile::tempdir().unwrap();
        // Write both files that `mitmproxy_ca_writes` requires.
        std::fs::write(dir.path().join("mitmproxy-ca.pem"), "fake-key").unwrap();
        std::fs::write(dir.path().join("mitmproxy-ca-cert.pem"), "fake-cert").unwrap();
        // Host-file reads succeed; the docker op is attempted and must fail.
        let result = provision_mitmproxy_ca(&unreachable_route(), "sandbox-gw-x", Some(dir.path()));
        assert!(
            result.is_err(),
            "provision_mitmproxy_ca with a complete CA dir must error on an unreachable route"
        );
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("sandbox-gw-x"),
            "error must name the container; got: {msg}"
        );
    }

    /// A present-but-incomplete CA dir is a hard error before any docker op:
    /// `provision_mitmproxy_ca` surfaces the `mitmproxy_ca_writes` read
    /// failure (missing cert-only file) rather than silently proceeding. The
    /// error is produced reading the host CA files, so no docker op runs.
    #[cfg(target_os = "macos")]
    #[test]
    fn provision_mitmproxy_ca_missing_file_errors() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("mitmproxy-ca.pem"), "x").unwrap();
        assert!(
            provision_mitmproxy_ca(&unreachable_route(), "sandbox-gw-x", Some(dir.path())).is_err(),
            "provision_mitmproxy_ca with an incomplete CA dir must error"
        );
    }

    // -- The session-bridge attach (hermetic, over a recording route) --------

    /// A route whose executor records every op and can be told to refuse the
    /// attach — enough to observe what the setup path asks for, and what it
    /// does when Docker says no.
    #[cfg(target_os = "macos")]
    struct RecordingExecutor {
        ops: std::sync::Mutex<Vec<DockerOp>>,
        /// When set, `NetworkConnect` fails with this on stderr.
        refuse_connect_with: Option<String>,
    }

    #[cfg(target_os = "macos")]
    #[async_trait::async_trait]
    impl crate::docker::DockerExecutor for RecordingExecutor {
        fn run(
            &self,
            _op_uid: u32,
            op: DockerOp,
            _timeout: Duration,
            _label: &str,
        ) -> Result<std::process::Output, SandboxError> {
            use std::os::unix::process::ExitStatusExt;

            let is_connect = matches!(op, DockerOp::NetworkConnect { .. });
            self.ops.lock().expect("op log").push(op);

            match (&self.refuse_connect_with, is_connect) {
                (Some(stderr), true) => Ok(std::process::Output {
                    // Docker's own exit code for a command line it will not
                    // accept, which is what an unsupported flag produces.
                    status: std::process::ExitStatus::from_raw(125 << 8),
                    stdout: Vec::new(),
                    stderr: stderr.as_bytes().to_vec(),
                }),
                _ => Ok(std::process::Output {
                    status: std::process::ExitStatus::from_raw(0),
                    stdout: Vec::new(),
                    stderr: Vec::new(),
                }),
            }
        }

        async fn open_stream(
            &self,
            _op_uid: u32,
            _stream: crate::docker::DockerStream,
        ) -> Result<crate::docker::DockerStreamConn, SandboxError> {
            unreachable!("gateway setup opens no streams")
        }
    }

    #[cfg(target_os = "macos")]
    fn test_network_info() -> NetworkInfo {
        NetworkInfo {
            gateway_egress_ip: None,
            bridge_name: "sb-aabbccddeeff".to_string(),
            subnet: "10.209.0.0/28".to_string(),
            gateway_ip: "10.209.0.2".to_string(),
            vm_ip: "10.209.0.3".to_string(),
            docker_network_name: "sandbox-net-aabbccddeeff".to_string(),
            vmnet_slot: None,
            operator_uid: None,
        }
    }

    /// Two properties of the session-bridge attach, both at the production
    /// call site rather than in an argv-rendering test.
    ///
    /// **It declines the default-gateway election.** Attaching a network to
    /// a running container re-runs that election and has been measured to
    /// move the default route onto the new endpoint — which for this
    /// container would be the session bridge, whose masquerade was
    /// deliberately removed. Its route out is the egress bridge it was
    /// started on, so the attach has to say so explicitly.
    ///
    /// **A refused attach fails the setup.** This is what makes it safe not
    /// to assert a minimum Docker version for the flag: a daemon too old to
    /// accept it refuses the command, and that refusal has to propagate as
    /// an error rather than leaving a gateway wired to a bridge that leads
    /// nowhere. Exercised with Docker's own exit code for a command line it
    /// will not accept.
    #[cfg(target_os = "macos")]
    #[test]
    fn session_bridge_attach_declines_the_default_route_and_a_refusal_fails_the_setup() {
        let executor = std::sync::Arc::new(RecordingExecutor {
            ops: std::sync::Mutex::new(Vec::new()),
            refuse_connect_with: Some("unknown flag: --gw-priority\n".to_string()),
        });
        let route = DockerRoute::Vm {
            owner_uid: TEST_OPERATOR_UID,
            executor: executor.clone(),
        };
        let session_id = SessionId::parse("aabbccddeeff").unwrap();

        let err = setup_macos_lite_gateway(
            &session_id,
            &test_network_info(),
            &route,
            "sandbox-gateway:test",
            None,
            None,
            None,
        )
        .expect_err("a refused attach must fail gateway setup");

        let msg = err.to_string();
        assert!(
            msg.contains("unknown flag"),
            "the failure must carry what Docker refused, so an operator can \
             see why; got: {msg}"
        );
        assert!(
            msg.contains("sandbox-net-aabbccddeeff"),
            "the failure must name the bridge it could not attach; got: {msg}"
        );

        let ops = executor.ops.lock().expect("op log");
        let connect = ops
            .iter()
            .find(|op| matches!(op, DockerOp::NetworkConnect { .. }))
            .expect("setup must attach the session bridge");
        match connect {
            DockerOp::NetworkConnect {
                network,
                ip,
                gateway_priority,
                ..
            } => {
                assert_eq!(
                    *gateway_priority,
                    EndpointGatewayPriority::NeverDefaultGateway,
                    "the session-bridge endpoint must decline the default-gateway \
                     election; with it left at Docker's default the gateway \
                     container's own route out moves onto a bridge that no longer \
                     masquerades",
                );
                assert_eq!(network, "sandbox-net-aabbccddeeff");
                assert_eq!(ip.as_deref(), Some("10.209.0.2"));
            }
            other => unreachable!("matched a connect op, got {other:?}"),
        }
    }

    // -- VmnetPool slot claim/release (hermetic, delegates to VmnetPool) ------

    #[cfg(target_os = "macos")]
    #[test]
    fn test_slot_claim_then_release_no_leak() {
        use crate::network::VmnetPool;
        let pool = VmnetPool::new(4);
        let id = SessionId::parse("aabbccddeeff").unwrap();
        let (slot, _subnet, _gw, _vm) = pool.claim_lima_slot(&id, TEST_OPERATOR_UID).unwrap();
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
        pool.claim_lima_slot(&id0, TEST_OPERATOR_UID).unwrap();
        pool.claim_lima_slot(&id1, TEST_OPERATOR_UID).unwrap();
        // Third claim must fail.
        let result = pool.claim_lima_slot(&id2, TEST_OPERATOR_UID);
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
        let (slot, subnet_cidr, gw, vm) = pool.claim_lima_slot(&id, TEST_OPERATOR_UID).unwrap();

        // Simulate partial create: set_lima_network_info was called.
        let info = NetworkInfo {
            gateway_egress_ip: None,
            operator_uid: None,
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
            gateway_egress_ip: None,
            operator_uid: None,
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
        let args = gateway_container_run_op(&id, "sandbox-gateway:test", Some("10.209.128.0/24"))
            .argv()
            .expect("gateway run renders");

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
        let args = gateway_container_run_op(&id, "sandbox-gateway:test", None)
            .argv()
            .expect("gateway run renders");

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
