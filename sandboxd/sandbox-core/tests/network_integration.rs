//! Integration tests for Docker network creation and deletion.
//!
//! Requirements:
//!   - Docker daemon running

use std::net::Ipv4Addr;
use std::process::Command;

use sandbox_core::network::NetworkManager;
use sandbox_core::session::SessionId;

#[test]
fn test_docker_create_and_delete_network() {
    // Use 10.209.1.0/24 to avoid collisions with the labels test.
    let mgr = NetworkManager::new(
        Ipv4Addr::new(10, 209, 1, 0),
        24,
        "10.209.1.0/24".to_string(),
    )
    .unwrap();
    let session_id = SessionId::generate();

    // Create network.
    let info = mgr.create_network(&session_id).unwrap();

    assert!(info.bridge_name.starts_with("sb-"));
    assert!(info.docker_network_name.starts_with("sandbox-net-"));
    // Subnet is dynamically allocated (/28 within the 10.209.1.0/24 pool),
    // so don't hardcode the exact value -- just verify the format.
    assert!(
        info.subnet.ends_with("/28"),
        "subnet should be /28: {}",
        info.subnet
    );
    assert!(
        info.gateway_ip.starts_with("10.209.1."),
        "gateway_ip: {}",
        info.gateway_ip
    );
    assert!(info.vm_ip.starts_with("10.209.1."), "vm_ip: {}", info.vm_ip);

    // Verify with docker network inspect.
    let output = Command::new("docker")
        .args([
            "network",
            "inspect",
            &info.docker_network_name,
            "--format",
            "{{json .IPAM.Config}}",
        ])
        .output()
        .expect("docker inspect should succeed");

    assert!(output.status.success(), "docker inspect failed");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains(&info.subnet),
        "inspect output should contain subnet {}: {stdout}",
        info.subnet
    );

    // Delete network.
    mgr.delete_network(&session_id).unwrap();

    // Verify it's gone.
    let output = Command::new("docker")
        .args(["network", "inspect", &info.docker_network_name])
        .output()
        .expect("docker inspect should run");
    assert!(
        !output.status.success(),
        "network should not exist after deletion"
    );
}

#[test]
fn test_docker_network_labels() {
    // Use 10.209.2.0/24 to avoid collisions with the create/delete test.
    let mgr = NetworkManager::new(
        Ipv4Addr::new(10, 209, 2, 0),
        24,
        "10.209.2.0/24".to_string(),
    )
    .unwrap();
    let session_id = SessionId::generate();

    let info = mgr.create_network(&session_id).unwrap();

    // Verify the session_id label.
    let output = Command::new("docker")
        .args([
            "network",
            "inspect",
            &info.docker_network_name,
            "--format",
            "{{index .Labels \"sandbox.session_id\"}}",
        ])
        .output()
        .expect("docker inspect should succeed");

    assert!(output.status.success());
    let label_value = String::from_utf8_lossy(&output.stdout).trim().to_string();
    assert_eq!(
        label_value,
        session_id.to_string(),
        "label should contain session_id"
    );

    // Clean up.
    mgr.delete_network(&session_id).unwrap();
}
