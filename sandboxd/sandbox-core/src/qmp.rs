//! Minimal QMP (QEMU Machine Protocol) client for NIC hot-add.
//!
//! QMP is a JSON-based protocol over a Unix socket. The exchange is:
//! 1. Connect to the QMP socket
//! 2. Read the greeting (JSON object with `"QMP"` key)
//! 3. Send `{"execute": "qmp_capabilities"}` and read the OK response
//! 4. Send commands and read responses
//!
//! This module uses synchronous I/O because QMP is strictly request/response
//! and there is no need for async.

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::Duration;

use tracing::debug;

use crate::error::SandboxError;
use crate::session::SessionId;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Timeout for reading a QMP response.
const READ_TIMEOUT: Duration = Duration::from_secs(10);

/// Timeout for writing a QMP command.
const WRITE_TIMEOUT: Duration = Duration::from_secs(5);

// ---------------------------------------------------------------------------
// QmpClient
// ---------------------------------------------------------------------------

/// A minimal QMP client for sending commands to a QEMU instance.
pub struct QmpClient {
    socket_path: PathBuf,
}

impl QmpClient {
    /// Create a new QMP client targeting the given socket path.
    pub fn new(socket_path: PathBuf) -> Self {
        Self { socket_path }
    }

    /// Construct the QMP socket path for a Lima-managed sandbox VM.
    ///
    /// Lima stores QMP sockets at `~/.lima/{vm_name}/qmp.sock`.
    pub fn for_session(session_id: &SessionId) -> Result<Self, SandboxError> {
        let home = std::env::var("HOME")
            .map_err(|_| SandboxError::Internal("HOME environment variable not set".into()))?;
        let vm_name = crate::lima::vm_name(session_id);
        let socket_path = PathBuf::from(home)
            .join(".lima")
            .join(vm_name)
            .join("qmp.sock");
        Ok(Self { socket_path })
    }

    /// Return the socket path (useful for diagnostics).
    pub fn socket_path(&self) -> &Path {
        &self.socket_path
    }

    /// Send a QMP command and return the parsed JSON response.
    ///
    /// This opens a fresh connection, performs the QMP handshake
    /// (`qmp_capabilities`), sends the command, reads the response,
    /// and closes the connection.
    ///
    /// Each call opens a new connection because QMP is stateful and holding
    /// a persistent connection across multiple calls adds complexity with no
    /// benefit for our use case (we send at most 2-3 commands per session).
    pub fn execute(
        &self,
        command: &str,
        arguments: serde_json::Value,
    ) -> Result<serde_json::Value, SandboxError> {
        let mut stream = self.connect_and_negotiate()?;

        // Build and send the command.
        let cmd = if arguments.is_null() || arguments.as_object().is_some_and(|m| m.is_empty()) {
            serde_json::json!({ "execute": command })
        } else {
            serde_json::json!({ "execute": command, "arguments": arguments })
        };

        let response = self.send_command(&mut stream, &cmd)?;
        Ok(response)
    }

    /// Hot-add a TAP network device to the VM.
    ///
    /// This sends two QMP commands:
    /// 1. `netdev_add` — creates the TAP backend
    /// 2. `device_add` — creates the virtio-net-pci frontend
    pub fn add_tap_nic(
        &self,
        tap_name: &str,
        netdev_id: &str,
        device_id: &str,
        mac: &str,
    ) -> Result<(), SandboxError> {
        let mut stream = self.connect_and_negotiate()?;

        // Step 1: Add the TAP netdev backend.
        let netdev_cmd = serde_json::json!({
            "execute": "netdev_add",
            "arguments": {
                "type": "tap",
                "id": netdev_id,
                "ifname": tap_name,
                "script": "no",
                "downscript": "no"
            }
        });

        debug!(
            tap = tap_name,
            netdev_id = netdev_id,
            "sending netdev_add command"
        );
        let response = self.send_command(&mut stream, &netdev_cmd)?;
        Self::check_qmp_response(&response, "netdev_add")?;

        // Step 2: Add the virtio-net-pci device frontend.
        // The device is placed on the pcie-root-port that our QEMU wrapper
        // injects at boot (`-device pcie-root-port,id=pcie-hotplug-port,...`).
        // Without an explicit bus, QEMU would try to place it on the root
        // complex (pcie.0), which does not support hotplugging on q35.
        let device_cmd = serde_json::json!({
            "execute": "device_add",
            "arguments": {
                "driver": "virtio-net-pci",
                "netdev": netdev_id,
                "id": device_id,
                "mac": mac,
                "bus": "pcie-hotplug-port"
            }
        });

        debug!(
            device_id = device_id,
            mac = mac,
            "sending device_add command"
        );
        let response = self.send_command(&mut stream, &device_cmd)?;
        Self::check_qmp_response(&response, "device_add")?;

        Ok(())
    }

    // -- Internal helpers -----------------------------------------------------

    /// Connect to the QMP socket and complete the capability negotiation.
    fn connect_and_negotiate(&self) -> Result<BufReader<UnixStream>, SandboxError> {
        let stream = UnixStream::connect_addr(
            &std::os::unix::net::SocketAddr::from_pathname(&self.socket_path).map_err(|e| {
                SandboxError::Internal(format!(
                    "invalid QMP socket path {}: {e}",
                    self.socket_path.display()
                ))
            })?,
        )
        .or_else(|_| UnixStream::connect(&self.socket_path))
        .map_err(|e| {
            SandboxError::Internal(format!(
                "failed to connect to QMP socket at {}: {e}",
                self.socket_path.display()
            ))
        })?;

        stream.set_read_timeout(Some(READ_TIMEOUT)).ok();
        stream.set_write_timeout(Some(WRITE_TIMEOUT)).ok();

        let mut reader = BufReader::new(stream);

        // Read the QMP greeting.
        let greeting = read_qmp_line(&mut reader)?;
        if greeting.get("QMP").is_none() {
            return Err(SandboxError::Internal(format!(
                "unexpected QMP greeting (no 'QMP' key): {greeting}"
            )));
        }

        debug!("QMP greeting received");

        // Send qmp_capabilities to enter command mode.
        let capabilities_cmd = serde_json::json!({ "execute": "qmp_capabilities" });
        let response = self.send_command(&mut reader, &capabilities_cmd)?;
        Self::check_qmp_response(&response, "qmp_capabilities")?;

        debug!("QMP capabilities negotiated");

        Ok(reader)
    }

    /// Send a JSON command and read the JSON response.
    fn send_command(
        &self,
        reader: &mut BufReader<UnixStream>,
        cmd: &serde_json::Value,
    ) -> Result<serde_json::Value, SandboxError> {
        let cmd_bytes = serde_json::to_vec(cmd)
            .map_err(|e| SandboxError::Internal(format!("failed to serialize QMP command: {e}")))?;

        // Get mutable access to the underlying stream for writing.
        let stream = reader.get_mut();
        stream
            .write_all(&cmd_bytes)
            .map_err(|e| SandboxError::Internal(format!("failed to write QMP command: {e}")))?;
        stream.write_all(b"\n").map_err(|e| {
            SandboxError::Internal(format!("failed to write QMP command newline: {e}"))
        })?;
        stream
            .flush()
            .map_err(|e| SandboxError::Internal(format!("failed to flush QMP socket: {e}")))?;

        // Read lines until we get a response with "return" or "error".
        // QMP may emit asynchronous event messages between commands; skip them.
        loop {
            let line = read_qmp_line(reader)?;

            if line.get("return").is_some() || line.get("error").is_some() {
                return Ok(line);
            }

            // Asynchronous event — skip and keep reading.
            debug!(event = %line, "skipping QMP async event");
        }
    }

    /// Check that a QMP response indicates success.
    fn check_qmp_response(
        response: &serde_json::Value,
        command_name: &str,
    ) -> Result<(), SandboxError> {
        if response.get("return").is_some() {
            return Ok(());
        }
        if let Some(error) = response.get("error") {
            let class = error
                .get("class")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");
            let desc = error
                .get("desc")
                .and_then(|v| v.as_str())
                .unwrap_or("no description");
            return Err(SandboxError::Internal(format!(
                "QMP {command_name} failed: {class}: {desc}"
            )));
        }
        Err(SandboxError::Internal(format!(
            "QMP {command_name}: unexpected response: {response}"
        )))
    }
}

// ---------------------------------------------------------------------------
// MAC address generation
// ---------------------------------------------------------------------------

/// Generate a deterministic MAC address from a session ID.
///
/// Format: `52:54:00:XX:YY:ZZ` where XX, YY, ZZ are derived from the
/// first 3 bytes of the session id. The `52:54:00` prefix is the QEMU OUI
/// (Organizationally Unique Identifier).
pub fn mac_from_session_id(session_id: &SessionId) -> String {
    let bytes = session_id.as_bytes_array();
    format!(
        "52:54:00:{:02x}:{:02x}:{:02x}",
        bytes[0], bytes[1], bytes[2]
    )
}

/// Generate the TAP device name for a session.
///
/// Format: `tb-{session_id}`, where the session id is 12 hex chars.
/// Total length: 3 + 12 = 15 chars, exactly at the kernel's IFNAMSIZ limit.
pub fn tap_name_for_session(session_id: &SessionId) -> String {
    format!("tb-{session_id}")
}

// ---------------------------------------------------------------------------
// Guest network configuration script
// ---------------------------------------------------------------------------

/// Generate a shell script that configures the hot-added NIC inside the VM.
///
/// The interface is located by MAC address rather than a hardcoded name
/// because Ubuntu 24.04 (and most modern distros) use predictable interface
/// naming — the hot-added NIC will appear as e.g. `enp1s0`, not `eth1`.
///
/// The script:
/// 1. Waits for an interface with the given MAC to appear (up to 10 seconds)
/// 2. Assigns a static IP
/// 3. Brings the interface up
/// 4. Adds a default route through the gateway with metric 50
///    (lower than SLIRP's default metric, making it preferred for internet)
/// 5. Sets DNS to the gateway
/// 6. Disables IPv6 on the new interface
pub fn generate_guest_network_script(gateway_ip: &str, vm_ip: &str, mac: &str) -> String {
    format!(
        r#"#!/bin/bash
set -euo pipefail

TARGET_MAC="{mac}"

# Find the interface with the expected MAC address (up to 10 seconds).
# The NIC is hot-added via QMP and may take a moment to appear.
IFACE=""
TRIES=0
while [ -z "$IFACE" ]; do
    TRIES=$((TRIES + 1))
    if [ "$TRIES" -ge 20 ]; then
        echo "ERROR: no interface with MAC $TARGET_MAC appeared after 10 seconds" >&2
        ip link show >&2
        exit 1
    fi
    IFACE=$(ip -o link show | awk -v mac="$TARGET_MAC" 'tolower($0) ~ tolower(mac) {{ split($2, a, ":"); print a[1] }}')
    [ -z "$IFACE" ] && sleep 0.5
done

echo "Found interface $IFACE with MAC $TARGET_MAC"

# Configure static IP
ip addr add {vm_ip}/28 dev "$IFACE"
ip link set "$IFACE" up

# Add default route through gateway with metric 50.
# The SLIRP route (via eth0) has a higher metric, so this interface is
# preferred for internet traffic, but SSH via eth0 still works.
ip route add default via {gateway_ip} dev "$IFACE" metric 50

# Set DNS to gateway (CoreDNS).
# On Ubuntu 24.04, /etc/resolv.conf is a symlink managed by
# systemd-resolved.  We must replace it with a static file, otherwise
# systemd-resolved will overwrite our changes.
if [ -L /etc/resolv.conf ]; then
    rm /etc/resolv.conf
fi
echo "nameserver {gateway_ip}" > /etc/resolv.conf

# Disable IPv6 on the new interface to prevent leakage
sysctl -w net.ipv6.conf."$IFACE".disable_ipv6=1

echo "$IFACE configured: {vm_ip}/28 via {gateway_ip}"
"#
    )
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Read a single line of JSON from the QMP socket.
fn read_qmp_line(reader: &mut BufReader<UnixStream>) -> Result<serde_json::Value, SandboxError> {
    let mut line = String::new();
    reader
        .read_line(&mut line)
        .map_err(|e| SandboxError::Internal(format!("failed to read from QMP socket: {e}")))?;

    if line.is_empty() {
        return Err(SandboxError::Internal(
            "QMP socket closed unexpectedly".into(),
        ));
    }

    serde_json::from_str(line.trim()).map_err(|e| {
        SandboxError::Internal(format!("failed to parse QMP JSON: {e} (line: {line})"))
    })
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // -- MAC address tests ---------------------------------------------------

    #[test]
    fn test_mac_address_format() {
        let id = SessionId::parse("550e8400e29b").unwrap();
        let mac = mac_from_session_id(&id);

        // Must start with QEMU OUI prefix.
        assert!(
            mac.starts_with("52:54:00:"),
            "MAC must start with QEMU OUI: {mac}"
        );

        // Must be a valid MAC format (6 colon-separated hex pairs).
        let parts: Vec<&str> = mac.split(':').collect();
        assert_eq!(parts.len(), 6, "MAC must have 6 octets: {mac}");

        for part in &parts {
            assert_eq!(part.len(), 2, "each MAC octet must be 2 hex chars: {mac}");
            assert!(
                part.chars().all(|c| c.is_ascii_hexdigit()),
                "each MAC octet must be hex: {mac}"
            );
        }
    }

    #[test]
    fn test_mac_address_determinism() {
        let id = SessionId::parse("550e8400e29b").unwrap();
        let mac1 = mac_from_session_id(&id);
        let mac2 = mac_from_session_id(&id);
        assert_eq!(mac1, mac2, "MAC address must be deterministic");
    }

    #[test]
    fn test_mac_address_uniqueness() {
        let id1 = SessionId::parse("550e8400e29b").unwrap();
        let id2 = SessionId::parse("a1b2c3d4e5f6").unwrap();
        let mac1 = mac_from_session_id(&id1);
        let mac2 = mac_from_session_id(&id2);
        assert_ne!(mac1, mac2, "different ids should produce different MACs");
    }

    #[test]
    fn test_mac_address_specific_bytes() {
        // Session id 550e8400e29b -> first 3 bytes are 0x55, 0x0e, 0x84.
        let id = SessionId::parse("550e8400e29b").unwrap();
        let mac = mac_from_session_id(&id);
        assert_eq!(mac, "52:54:00:55:0e:84");
    }

    // -- TAP name tests ------------------------------------------------------

    #[test]
    fn test_tap_name_format() {
        let id = SessionId::parse("550e8400e29b").unwrap();
        let name = tap_name_for_session(&id);

        assert!(
            name.starts_with("tb-"),
            "TAP name must start with 'tb-': {name}"
        );
        assert_eq!(name, "tb-550e8400e29b");
    }

    #[test]
    fn test_tap_name_length() {
        // Kernel interface names are limited to 15 characters (IFNAMSIZ).
        // "tb-" (3) + 12 hex = exactly 15.
        let id = SessionId::generate();
        let name = tap_name_for_session(&id);

        assert_eq!(
            name.len(),
            15,
            "TAP name '{name}' should be exactly 15 chars (IFNAMSIZ)"
        );
    }

    #[test]
    fn test_tap_name_determinism() {
        let id = SessionId::parse("550e8400e29b").unwrap();
        let name1 = tap_name_for_session(&id);
        let name2 = tap_name_for_session(&id);
        assert_eq!(name1, name2, "TAP name must be deterministic");
    }

    // -- Guest network script tests ------------------------------------------

    #[test]
    fn test_network_config_script_contains_ips() {
        let script = generate_guest_network_script("10.209.0.2", "10.209.0.3", "52:54:00:ab:cd:ef");

        assert!(
            script.contains("10.209.0.3/28"),
            "script must assign the VM IP with /28 prefix"
        );
        assert!(
            script.contains("via 10.209.0.2"),
            "script must route through the gateway IP"
        );
        assert!(
            script.contains("nameserver 10.209.0.2"),
            "script must set DNS to the gateway"
        );
    }

    #[test]
    fn test_network_config_script_finds_interface_by_mac() {
        let mac = "52:54:00:ab:cd:ef";
        let script = generate_guest_network_script("10.209.0.2", "10.209.0.3", mac);

        assert!(
            script.contains(mac),
            "script must search for the interface by MAC address"
        );
        assert!(
            script.contains("sleep 0.5"),
            "script must poll with a delay"
        );
    }

    #[test]
    fn test_network_config_script_disables_ipv6() {
        let script = generate_guest_network_script("10.209.0.2", "10.209.0.3", "52:54:00:ab:cd:ef");

        assert!(
            script.contains("disable_ipv6=1"),
            "script must disable IPv6 on the hot-added interface"
        );
    }

    #[test]
    fn test_network_config_script_sets_metric() {
        let script = generate_guest_network_script("10.209.0.2", "10.209.0.3", "52:54:00:ab:cd:ef");

        assert!(
            script.contains("metric 50"),
            "script must set route metric for the hot-added interface"
        );
    }

    #[test]
    fn test_network_config_script_different_subnet() {
        let script =
            generate_guest_network_script("10.209.0.18", "10.209.0.19", "52:54:00:12:34:56");

        assert!(
            script.contains("10.209.0.19/28"),
            "script must use provided VM IP"
        );
        assert!(
            script.contains("via 10.209.0.18"),
            "script must use provided gateway IP"
        );
        assert!(
            script.contains("nameserver 10.209.0.18"),
            "script must use provided gateway as DNS"
        );
    }

    #[test]
    fn test_network_config_script_is_bash() {
        let script = generate_guest_network_script("10.0.0.1", "10.0.0.2", "52:54:00:ab:cd:ef");
        assert!(
            script.starts_with("#!/bin/bash"),
            "script must have bash shebang"
        );
        assert!(
            script.contains("set -euo pipefail"),
            "script must use strict mode"
        );
    }

    #[test]
    fn test_check_qmp_response_success() {
        let response = serde_json::json!({ "return": {} });
        assert!(QmpClient::check_qmp_response(&response, "test").is_ok());
    }

    #[test]
    fn test_check_qmp_response_error() {
        let response = serde_json::json!({
            "error": {
                "class": "GenericError",
                "desc": "Device 'nic1' already exists"
            }
        });
        let result = QmpClient::check_qmp_response(&response, "device_add");
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("GenericError"),
            "error should contain the class: {err}"
        );
        assert!(
            err.contains("already exists"),
            "error should contain the description: {err}"
        );
    }

    #[test]
    fn test_check_qmp_response_unexpected() {
        let response = serde_json::json!({ "something": "unexpected" });
        let result = QmpClient::check_qmp_response(&response, "test");
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("unexpected response"),
            "error should mention unexpected: {err}"
        );
    }

    // -- QmpClient construction tests ----------------------------------------

    #[test]
    fn test_qmp_client_new() {
        let client = QmpClient::new(PathBuf::from("/tmp/test.sock"));
        assert_eq!(client.socket_path(), Path::new("/tmp/test.sock"));
    }

    #[test]
    fn test_qmp_client_for_session() {
        // This test may fail in environments without HOME set, but that's
        // expected.
        let id = SessionId::parse("550e8400e29b").unwrap();
        if let Ok(client) = QmpClient::for_session(&id) {
            let path = client.socket_path().to_string_lossy();
            assert!(
                path.contains(".lima/sandbox-550e8400e29b/qmp.sock"),
                "socket path should contain Lima VM directory: {path}"
            );
        }
    }
}
