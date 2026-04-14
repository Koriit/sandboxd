//! VM networking orchestration — configures a sandbox VM's bridge NIC.
//!
//! With `qemu-bridge-helper`, the NIC is attached to the Docker bridge at
//! VM boot time by the QEMU wrapper script. This module handles only the
//! guest-side configuration:
//!
//! 1. **Wait** for the bridge NIC to appear inside the VM (by MAC address)
//! 2. **Configure** the NIC with a static IP, default route, and DNS

use tracing::info;
use uuid::Uuid;

use crate::error::SandboxError;
use crate::guest::{GuestConnector, GuestResponse};
use crate::network::NetworkInfo;
use crate::qmp::{generate_guest_network_script, mac_from_uuid};

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Configure the bridge NIC inside a sandbox VM.
///
/// The NIC is already present at boot (added by the QEMU wrapper via
/// `qemu-bridge-helper`). This function configures it with a static IP,
/// default route through the gateway, and DNS pointing to the gateway's
/// CoreDNS instance.
///
/// Called after the VM has booted and the guest agent is responsive.
pub async fn attach_vm_to_bridge(
    session_id: &Uuid,
    network_info: &NetworkInfo,
    guest: &GuestConnector,
) -> Result<(), SandboxError> {
    let mac = mac_from_uuid(session_id);

    info!(
        session_id = %session_id,
        mac = %mac,
        bridge = %network_info.bridge_name,
        vm_ip = %network_info.vm_ip,
        gateway_ip = %network_info.gateway_ip,
        "configuring bridge NIC inside VM"
    );

    // Configure the NIC inside the VM via the guest agent.
    // The NIC is found by MAC address — it was added at boot by the QEMU
    // wrapper and should already be visible inside the guest.
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

/// Detach a sandbox VM from its Docker bridge network.
///
/// With `qemu-bridge-helper`, the TAP device is owned by QEMU and is
/// automatically destroyed when the VM stops. This function is a no-op
/// but retained for API compatibility during teardown sequences.
pub fn detach_vm_from_bridge(
    session_id: &Uuid,
) -> Result<(), SandboxError> {
    info!(
        session_id = %session_id,
        "detaching VM from bridge network (no-op: TAP owned by QEMU)"
    );
    Ok(())
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_attach_generates_correct_mac() {
        let id =
            Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap();
        let mac = mac_from_uuid(&id);
        assert_eq!(mac, "52:54:00:55:0e:84");
    }

    #[test]
    fn test_detach_is_noop() {
        let id = Uuid::new_v4();
        // detach should always succeed (it's a no-op).
        assert!(detach_vm_from_bridge(&id).is_ok());
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
