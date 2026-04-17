//! Integration tests for the gateway container lifecycle and nftables injection.
//!
//! Requirements:
//!   - Docker daemon running
//!   - `sandbox-gateway` image built (`make gateway-image`)
//!   - Sufficient privileges for Docker and nftables

use std::process::Command;

use sandbox_core::gateway::{GATEWAY_IMAGE, GatewayManager, GatewayStatus, container_name};
use sandbox_core::network::NetworkManager;
use sandbox_core::session::SessionId;
use std::net::Ipv4Addr;

#[test]
fn test_gateway_lifecycle() {
    // Use 10.209.3.0/24 to avoid collisions with other tests.
    let net_mgr = NetworkManager::new(Ipv4Addr::new(10, 209, 3, 0), 24).unwrap();
    let gw_mgr = GatewayManager::new();
    let session_id = SessionId::generate();

    // Create the Docker network.
    let network_info = net_mgr.create_network(&session_id).unwrap();

    // Create the gateway container with nftables rules.
    let create_result = gw_mgr.create_gateway(&session_id, &network_info, None, None);
    if let Err(ref e) = create_result {
        // Clean up on failure.
        let _ = gw_mgr.stop_gateway(&session_id);
        let _ = net_mgr.delete_network(&session_id);
        panic!("create_gateway failed: {e}");
    }

    // Verify health.
    let status = gw_mgr.gateway_status(&session_id).unwrap();
    assert_eq!(status, GatewayStatus::Healthy, "gateway should be healthy");

    // Verify nftables rules are present in the container.
    let gw_container = container_name(&session_id);
    let output = Command::new("docker")
        .args(["exec", &gw_container, "nft", "list", "ruleset"])
        .output()
        .expect("docker exec nft list should succeed");

    let nft_output = String::from_utf8_lossy(&output.stdout);
    assert!(
        nft_output.contains("table inet sandbox"),
        "deny-all table should exist in nft ruleset: {nft_output}"
    );
    assert!(
        nft_output.contains("table inet sandbox_dnat"),
        "DNAT table should exist in nft ruleset: {nft_output}"
    );

    // Stop and remove the gateway.
    gw_mgr.stop_gateway(&session_id).unwrap();

    // Verify the container is gone.
    let status = gw_mgr.gateway_status(&session_id).unwrap();
    assert_eq!(
        status,
        GatewayStatus::NotRunning,
        "gateway should not be running after stop"
    );

    // Clean up the network.
    net_mgr.delete_network(&session_id).unwrap();
}

#[test]
fn test_gateway_nftables_injection_standalone() {
    // Use 10.209.4.0/24 to avoid collisions.
    let net_mgr = NetworkManager::new(Ipv4Addr::new(10, 209, 4, 0), 24).unwrap();
    let gw_mgr = GatewayManager::new();
    let session_id = SessionId::generate();

    // Create network and a minimal container (no need for full gateway here).
    let network_info = net_mgr.create_network(&session_id).unwrap();

    // Start the gateway image with CAP_NET_ADMIN so nft works inside the
    // container. Override entrypoint with sleep so we can test nftables
    // injection without the full gateway stack.
    let gw_container = container_name(&session_id);
    let output = Command::new("docker")
        .args([
            "run",
            "-d",
            "--name",
            &gw_container,
            "--network",
            &network_info.docker_network_name,
            "--cap-add",
            "NET_ADMIN",
            "--sysctl",
            "net.ipv4.ip_forward=1",
            "--entrypoint",
            "sleep",
            GATEWAY_IMAGE,
            "300",
        ])
        .output()
        .expect("docker run should succeed");

    if !output.status.success() {
        let _ = net_mgr.delete_network(&session_id);
        panic!(
            "docker run failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    // Discover the container's auto-assigned IP.
    let container_ip = gw_mgr.container_ip(&session_id).unwrap();

    // Inject deny-all rules.
    gw_mgr.inject_deny_all(&session_id).unwrap();

    // Verify rules are present.
    let output = Command::new("docker")
        .args(["exec", &gw_container, "nft", "list", "ruleset"])
        .output()
        .expect("nft list should succeed");

    let nft_output = String::from_utf8_lossy(&output.stdout);
    assert!(
        nft_output.contains("table inet sandbox"),
        "deny-all table should exist"
    );
    assert!(
        nft_output.contains("policy drop"),
        "input policy should be drop"
    );

    // Inject DNAT rules using the container's actual IP.
    gw_mgr
        .inject_dnat(&session_id, &network_info, &container_ip)
        .unwrap();

    let output = Command::new("docker")
        .args(["exec", &gw_container, "nft", "list", "ruleset"])
        .output()
        .expect("nft list should succeed");

    let nft_output = String::from_utf8_lossy(&output.stdout);
    assert!(
        nft_output.contains("table inet sandbox_dnat"),
        "DNAT table should exist"
    );
    assert!(nft_output.contains("dnat"), "DNAT rules should be present");

    // Remove DNAT rules.
    gw_mgr.remove_dnat_rules(&session_id).unwrap();

    let output = Command::new("docker")
        .args(["exec", &gw_container, "nft", "list", "ruleset"])
        .output()
        .expect("nft list should succeed");

    let nft_output = String::from_utf8_lossy(&output.stdout);
    assert!(
        !nft_output.contains("table inet sandbox_dnat"),
        "DNAT table should be removed after remove_dnat_rules"
    );
    // deny-all should still be present.
    assert!(
        nft_output.contains("table inet sandbox"),
        "deny-all table should still exist"
    );

    // Clean up.
    let _ = Command::new("docker")
        .args(["rm", "--force", &gw_container])
        .output();
    let _ = net_mgr.delete_network(&session_id);
}
