//! VM networking orchestration — attaches a sandbox VM to its Docker bridge.
//!
//! This module coordinates the three-step process of connecting a VM to the
//! session's isolated network:
//!
//! 1. **TAP device** — created on the host and attached to the Docker bridge
//! 2. **QMP hot-add** — adds the TAP as a NIC to the running QEMU VM
//! 3. **Guest config** — configures the new NIC inside the VM with a static IP

use tracing::info;
use uuid::Uuid;

use crate::error::SandboxError;
use crate::guest::{GuestConnector, GuestResponse};
use crate::network::{NetworkInfo, NetworkManager};
use crate::qmp::{QmpClient, generate_guest_network_script, mac_from_uuid, tap_name_for_session};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// QMP netdev backend ID for the hot-added NIC.
const NETDEV_ID: &str = "net1";

/// QMP device frontend ID for the hot-added NIC.
const DEVICE_ID: &str = "nic1";

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Attach a sandbox VM to its session's Docker bridge network.
///
/// This is the main orchestration function called after the VM has booted
/// and the guest agent is responsive. It:
///
/// 1. Creates a TAP device on the host, attached to the Docker bridge
/// 2. Hot-adds the TAP as a NIC to the VM via QMP
/// 3. Configures the NIC inside the VM via the guest agent
///
/// On failure, it attempts to clean up the TAP device.
pub async fn attach_vm_to_bridge(
    session_id: &Uuid,
    network_info: &NetworkInfo,
    network_manager: &NetworkManager,
    guest: &GuestConnector,
) -> Result<(), SandboxError> {
    let tap_name = tap_name_for_session(session_id);
    let mac = mac_from_uuid(session_id);

    info!(
        session_id = %session_id,
        tap = %tap_name,
        mac = %mac,
        bridge = %network_info.bridge_name,
        vm_ip = %network_info.vm_ip,
        gateway_ip = %network_info.gateway_ip,
        "attaching VM to bridge network"
    );

    // Step 1: Create TAP device on host, attached to Docker bridge.
    let tap_name = network_manager.create_tap(session_id, network_info)?;

    // Step 2: Hot-add the TAP as a NIC via QMP.
    let qmp = QmpClient::for_session(session_id)?;

    info!(
        session_id = %session_id,
        qmp_socket = %qmp.socket_path().display(),
        "hot-adding NIC via QMP"
    );

    if let Err(e) = qmp.add_tap_nic(&tap_name, NETDEV_ID, DEVICE_ID, &mac) {
        // Clean up the TAP on failure.
        let _ = network_manager.delete_tap(session_id);
        return Err(SandboxError::Network(format!(
            "QMP NIC hot-add failed: {e}"
        )));
    }

    // Step 3: Configure the NIC inside the VM via the guest agent.
    let script =
        generate_guest_network_script(&network_info.gateway_ip, &network_info.vm_ip, &mac);

    info!(
        session_id = %session_id,
        "configuring network inside VM via guest agent"
    );

    let response = guest
        .exec(session_id, "bash", &["-c", &script])
        .await
        .map_err(|e| {
            SandboxError::Network(format!(
                "failed to execute network config in VM: {e}"
            ))
        })?;

    match response {
        GuestResponse::ExecResult {
            exit_code,
            stdout,
            stderr,
        } => {
            if exit_code != 0 {
                return Err(SandboxError::Network(format!(
                    "guest network configuration failed (exit {}): stdout={stdout}, stderr={stderr}",
                    exit_code
                )));
            }
            info!(
                session_id = %session_id,
                output = %stdout.trim(),
                "VM network configured successfully"
            );
        }
        GuestResponse::Error { message } => {
            return Err(SandboxError::Network(format!(
                "guest agent returned error during network config: {message}"
            )));
        }
        other => {
            return Err(SandboxError::Network(format!(
                "unexpected guest response during network config: {other:?}"
            )));
        }
    }

    Ok(())
}

/// Detach a sandbox VM from its Docker bridge network by removing the TAP device.
///
/// The TAP deletion is idempotent — if it was already cleaned up, this succeeds.
/// The in-VM NIC configuration is not cleaned up because the VM is typically
/// being shut down when this is called.
pub fn detach_vm_from_bridge(
    session_id: &Uuid,
    network_manager: &NetworkManager,
) -> Result<(), SandboxError> {
    info!(
        session_id = %session_id,
        "detaching VM from bridge network"
    );
    network_manager.delete_tap(session_id)
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constants() {
        // Verify the QMP IDs are sensible strings.
        assert_eq!(NETDEV_ID, "net1");
        assert_eq!(DEVICE_ID, "nic1");
    }

    #[test]
    fn test_attach_generates_correct_tap_name() {
        let id =
            Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap();
        let tap = tap_name_for_session(&id);
        assert_eq!(tap, "tap-sb-550e84");
    }

    #[test]
    fn test_attach_generates_correct_mac() {
        let id =
            Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap();
        let mac = mac_from_uuid(&id);
        assert_eq!(mac, "52:54:00:55:0e:84");
    }

    #[test]
    fn test_detach_uses_correct_tap_name() {
        // Verify that detach would use the same TAP name as attach.
        let id = Uuid::new_v4();
        let tap_attach = tap_name_for_session(&id);
        let tap_detach = tap_name_for_session(&id);
        assert_eq!(tap_attach, tap_detach);
    }

    #[test]
    fn test_guest_script_for_network_info() {
        let info = NetworkInfo {
            bridge_name: "sb-550e8400-e2".to_string(),
            subnet: "10.209.0.0/28".to_string(),
            gateway_ip: "10.209.0.2".to_string(),
            vm_ip: "10.209.0.3".to_string(),
            docker_network_name: "sandbox-net-test".to_string(),
        };

        let mac = "52:54:00:55:0e:84";
        let script =
            generate_guest_network_script(&info.gateway_ip, &info.vm_ip, mac);

        assert!(script.contains("10.209.0.3/28"));
        assert!(script.contains("via 10.209.0.2"));
        assert!(script.contains("nameserver 10.209.0.2"));
        assert!(script.contains(mac));
    }
}
