use std::collections::HashSet;
use std::net::Ipv4Addr;
use std::process::Command;
use std::sync::Mutex;

use serde::{Deserialize, Serialize};
use tracing::{debug, info};
use uuid::Uuid;

use crate::error::SandboxError;

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// Information about a session's Docker bridge network.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkInfo {
    /// Kernel bridge interface name (max 15 chars): `sb-{session_id[0..11]}`.
    pub bridge_name: String,
    /// Subnet in CIDR notation, e.g. `"10.209.0.0/30"`.
    pub subnet: String,
    /// Gateway IP (the `.1` in the /30), assigned to the bridge.
    pub gateway_ip: String,
    /// VM IP (the `.2` in the /30), to be assigned to the VM's veth.
    pub vm_ip: String,
    /// Docker network name: `sandbox-net-{session_id}`.
    pub docker_network_name: String,
}

// ---------------------------------------------------------------------------
// SubnetAllocator
// ---------------------------------------------------------------------------

/// Carves /30 subnets from a base range.
///
/// Each /30 has 4 addresses:
///   .0 = network, .1 = gateway, .2 = VM, .3 = broadcast
///
/// A /24 base provides 64 /30 blocks (256 / 4).
#[derive(Debug)]
struct SubnetAllocator {
    /// Base network address, e.g. `10.209.0.0`.
    base: Ipv4Addr,
    /// Prefix length of the base range (e.g. 24). Retained for diagnostics.
    #[allow(dead_code)]
    prefix_len: u8,
    /// Set of allocated /30 block indices (0..max_blocks).
    allocated: HashSet<u8>,
    /// Maximum number of /30 blocks: 2^(32 - prefix_len) / 4.
    max_blocks: u8,
}

impl SubnetAllocator {
    /// Create a new allocator for the given base range.
    ///
    /// `prefix_len` must be <= 30 (a /30 is the smallest usable subnet).
    /// The number of /30 blocks is `2^(32 - prefix_len) / 4`.
    fn new(base: Ipv4Addr, prefix_len: u8) -> Result<Self, SandboxError> {
        if prefix_len > 30 {
            return Err(SandboxError::Network(format!(
                "prefix length {prefix_len} is too large; maximum is 30"
            )));
        }

        let host_bits = 32 - prefix_len;
        // Total addresses in the range.
        let total_addrs: u32 = 1 << host_bits;
        // Each /30 uses 4 addresses.
        let max_blocks = total_addrs / 4;

        // We store the block index as u8, so cap at 255.
        if max_blocks > 255 {
            return Err(SandboxError::Network(format!(
                "base range /{prefix_len} yields {max_blocks} blocks, which exceeds u8 limit"
            )));
        }

        Ok(Self {
            base,
            prefix_len,
            allocated: HashSet::new(),
            max_blocks: max_blocks as u8,
        })
    }

    /// Allocate the next available /30 block.
    ///
    /// Returns `(block_index, subnet_base, gateway_ip, vm_ip)`.
    fn allocate(&mut self) -> Result<(u8, Ipv4Addr, Ipv4Addr, Ipv4Addr), SandboxError> {
        // Find the lowest free index.
        let block_idx = (0..self.max_blocks)
            .find(|idx| !self.allocated.contains(idx))
            .ok_or_else(|| {
                SandboxError::Network(format!(
                    "subnet pool exhausted: all {} /30 blocks are allocated",
                    self.max_blocks
                ))
            })?;

        self.allocated.insert(block_idx);

        let base_u32 = u32::from(self.base);
        let offset = (block_idx as u32) * 4;
        let subnet_base = Ipv4Addr::from(base_u32 + offset);
        let gateway_ip = Ipv4Addr::from(base_u32 + offset + 1);
        let vm_ip = Ipv4Addr::from(base_u32 + offset + 2);

        Ok((block_idx, subnet_base, gateway_ip, vm_ip))
    }

    /// Release a /30 block back to the pool.
    fn release(&mut self, block_idx: u8) {
        self.allocated.remove(&block_idx);
    }

    /// Mark a specific block as allocated (used during state rebuild).
    fn mark_allocated(&mut self, block_idx: u8) -> Result<(), SandboxError> {
        if block_idx >= self.max_blocks {
            return Err(SandboxError::Network(format!(
                "block index {block_idx} out of range (max {})",
                self.max_blocks
            )));
        }
        self.allocated.insert(block_idx);
        Ok(())
    }

    /// Determine the block index for a given subnet base address.
    fn block_index_for(&self, subnet_base: Ipv4Addr) -> Option<u8> {
        let base_u32 = u32::from(self.base);
        let addr_u32 = u32::from(subnet_base);

        if addr_u32 < base_u32 {
            return None;
        }

        let offset = addr_u32 - base_u32;
        if offset % 4 != 0 {
            return None;
        }

        let idx = offset / 4;
        if idx >= self.max_blocks as u32 {
            return None;
        }

        Some(idx as u8)
    }
}

// ---------------------------------------------------------------------------
// NetworkManager
// ---------------------------------------------------------------------------

/// Manages per-session Docker bridge networks with /30 subnets.
///
/// Each session gets an isolated Docker bridge network with a unique /30
/// subnet carved from a configurable base range (default `10.209.0.0/24`).
pub struct NetworkManager {
    subnet_allocator: Mutex<SubnetAllocator>,
    /// Maps session_id -> (block_index, NetworkInfo) for active networks.
    networks: Mutex<std::collections::HashMap<Uuid, (u8, NetworkInfo)>>,
}

impl NetworkManager {
    /// Create a new `NetworkManager` with the given base range.
    ///
    /// Default: `10.209.0.0/24` provides 64 /30 subnets.
    pub fn new(base: Ipv4Addr, prefix_len: u8) -> Result<Self, SandboxError> {
        let allocator = SubnetAllocator::new(base, prefix_len)?;
        Ok(Self {
            subnet_allocator: Mutex::new(allocator),
            networks: Mutex::new(std::collections::HashMap::new()),
        })
    }

    /// Create a new `NetworkManager` with the default base range `10.209.0.0/24`.
    pub fn with_defaults() -> Result<Self, SandboxError> {
        Self::new(Ipv4Addr::new(10, 209, 0, 0), 24)
    }

    /// Rebuild allocator state from existing `NetworkInfo` entries.
    ///
    /// Call this on daemon startup after loading sessions from the store.
    /// For each session that has a `NetworkInfo`, the corresponding /30 block
    /// is marked as allocated.
    pub fn restore_from_infos(
        &self,
        entries: &[(Uuid, NetworkInfo)],
    ) -> Result<(), SandboxError> {
        let mut alloc = self.subnet_allocator.lock().map_err(|e| {
            SandboxError::Internal(format!("lock poisoned: {e}"))
        })?;
        let mut nets = self.networks.lock().map_err(|e| {
            SandboxError::Internal(format!("lock poisoned: {e}"))
        })?;

        for (session_id, info) in entries {
            // Parse the subnet base from the CIDR string.
            let subnet_base = parse_subnet_base(&info.subnet)?;
            let block_idx = alloc.block_index_for(subnet_base).ok_or_else(|| {
                SandboxError::Network(format!(
                    "subnet {} does not map to a valid block in the base range",
                    info.subnet
                ))
            })?;
            alloc.mark_allocated(block_idx)?;
            nets.insert(*session_id, (block_idx, info.clone()));
        }

        Ok(())
    }

    /// Create a Docker bridge network for the given session.
    ///
    /// Allocates a /30 subnet, shells out to `docker network create`, and
    /// returns the resulting `NetworkInfo`.
    pub fn create_network(&self, session_id: &Uuid) -> Result<NetworkInfo, SandboxError> {
        // Check if the session already has a network.
        {
            let nets = self.networks.lock().map_err(|e| {
                SandboxError::Internal(format!("lock poisoned: {e}"))
            })?;
            if let Some((_, info)) = nets.get(session_id) {
                return Err(SandboxError::Network(format!(
                    "session {} already has network {}",
                    session_id, info.docker_network_name
                )));
            }
        }

        // Allocate a /30 subnet.
        let (block_idx, subnet_base, gateway_ip, vm_ip) = {
            let mut alloc = self.subnet_allocator.lock().map_err(|e| {
                SandboxError::Internal(format!("lock poisoned: {e}"))
            })?;
            alloc.allocate()?
        };

        let session_str = session_id.to_string();
        // Kernel bridge name: "sb-" (3 chars) + first 11 chars of UUID = 14 chars (max 15).
        let short_id = &session_str[..11.min(session_str.len())];
        let bridge_name = format!("sb-{short_id}");
        let docker_network_name = format!("sandbox-net-{session_id}");
        let subnet = format!("{subnet_base}/30");

        let info = NetworkInfo {
            bridge_name: bridge_name.clone(),
            subnet: subnet.clone(),
            gateway_ip: gateway_ip.to_string(),
            vm_ip: vm_ip.to_string(),
            docker_network_name: docker_network_name.clone(),
        };

        // Shell out to docker network create.
        debug!(
            session_id = %session_id,
            subnet = %subnet,
            gateway = %gateway_ip,
            bridge = %bridge_name,
            "creating Docker bridge network"
        );

        let output = Command::new("docker")
            .args([
                "network",
                "create",
                "--driver",
                "bridge",
                "--subnet",
                &subnet,
                "--gateway",
                &gateway_ip.to_string(),
                "--label",
                &format!("sandbox.session_id={session_id}"),
                "--opt",
                &format!("com.docker.network.bridge.name={bridge_name}"),
                &docker_network_name,
            ])
            .output()
            .map_err(|e| {
                SandboxError::Network(format!("failed to run docker network create: {e}"))
            })?;

        if !output.status.success() {
            // Roll back the allocation.
            let mut alloc = self.subnet_allocator.lock().map_err(|e| {
                SandboxError::Internal(format!("lock poisoned: {e}"))
            })?;
            alloc.release(block_idx);

            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(SandboxError::Network(format!(
                "docker network create failed: {stderr}"
            )));
        }

        // Track the network.
        {
            let mut nets = self.networks.lock().map_err(|e| {
                SandboxError::Internal(format!("lock poisoned: {e}"))
            })?;
            nets.insert(*session_id, (block_idx, info.clone()));
        }

        info!(
            session_id = %session_id,
            network = %docker_network_name,
            subnet = %subnet,
            "Docker bridge network created"
        );

        Ok(info)
    }

    /// Delete the Docker bridge network for the given session.
    pub fn delete_network(&self, session_id: &Uuid) -> Result<(), SandboxError> {
        let (block_idx, info) = {
            let nets = self.networks.lock().map_err(|e| {
                SandboxError::Internal(format!("lock poisoned: {e}"))
            })?;
            nets.get(session_id)
                .cloned()
                .ok_or_else(|| {
                    SandboxError::Network(format!(
                        "no network found for session {session_id}"
                    ))
                })?
        };

        debug!(
            session_id = %session_id,
            network = %info.docker_network_name,
            "deleting Docker bridge network"
        );

        let output = Command::new("docker")
            .args(["network", "rm", &info.docker_network_name])
            .output()
            .map_err(|e| {
                SandboxError::Network(format!("failed to run docker network rm: {e}"))
            })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(SandboxError::Network(format!(
                "docker network rm failed: {stderr}"
            )));
        }

        // Release the subnet and remove tracking.
        {
            let mut alloc = self.subnet_allocator.lock().map_err(|e| {
                SandboxError::Internal(format!("lock poisoned: {e}"))
            })?;
            alloc.release(block_idx);
        }
        {
            let mut nets = self.networks.lock().map_err(|e| {
                SandboxError::Internal(format!("lock poisoned: {e}"))
            })?;
            nets.remove(session_id);
        }

        info!(
            session_id = %session_id,
            network = %info.docker_network_name,
            "Docker bridge network deleted"
        );

        Ok(())
    }

    /// Retrieve the `NetworkInfo` for a session, if it has a network.
    pub fn network_info(&self, session_id: &Uuid) -> Result<Option<NetworkInfo>, SandboxError> {
        let nets = self.networks.lock().map_err(|e| {
            SandboxError::Internal(format!("lock poisoned: {e}"))
        })?;
        Ok(nets.get(session_id).map(|(_, info)| info.clone()))
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Parse the base address from a CIDR string like `"10.209.0.4/30"`.
fn parse_subnet_base(cidr: &str) -> Result<Ipv4Addr, SandboxError> {
    let addr_str = cidr
        .split('/')
        .next()
        .ok_or_else(|| SandboxError::Network(format!("invalid CIDR: {cidr}")))?;
    addr_str
        .parse::<Ipv4Addr>()
        .map_err(|e| SandboxError::Network(format!("invalid IP in CIDR {cidr}: {e}")))
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // -- SubnetAllocator unit tests ------------------------------------------

    #[test]
    fn test_allocate_subnet() {
        let mut alloc =
            SubnetAllocator::new(Ipv4Addr::new(10, 209, 0, 0), 24).unwrap();

        let (idx, subnet_base, gateway, vm) = alloc.allocate().unwrap();
        assert_eq!(idx, 0);
        assert_eq!(subnet_base, Ipv4Addr::new(10, 209, 0, 0));
        assert_eq!(gateway, Ipv4Addr::new(10, 209, 0, 1));
        assert_eq!(vm, Ipv4Addr::new(10, 209, 0, 2));
    }

    #[test]
    fn test_allocate_multiple() {
        let mut alloc =
            SubnetAllocator::new(Ipv4Addr::new(10, 209, 0, 0), 24).unwrap();

        let (idx0, base0, gw0, vm0) = alloc.allocate().unwrap();
        let (idx1, base1, gw1, vm1) = alloc.allocate().unwrap();
        let (idx2, base2, gw2, vm2) = alloc.allocate().unwrap();

        // Verify indices are sequential.
        assert_eq!(idx0, 0);
        assert_eq!(idx1, 1);
        assert_eq!(idx2, 2);

        // Verify no IP overlap.
        assert_eq!(base0, Ipv4Addr::new(10, 209, 0, 0));
        assert_eq!(base1, Ipv4Addr::new(10, 209, 0, 4));
        assert_eq!(base2, Ipv4Addr::new(10, 209, 0, 8));

        assert_eq!(gw0, Ipv4Addr::new(10, 209, 0, 1));
        assert_eq!(gw1, Ipv4Addr::new(10, 209, 0, 5));
        assert_eq!(gw2, Ipv4Addr::new(10, 209, 0, 9));

        assert_eq!(vm0, Ipv4Addr::new(10, 209, 0, 2));
        assert_eq!(vm1, Ipv4Addr::new(10, 209, 0, 6));
        assert_eq!(vm2, Ipv4Addr::new(10, 209, 0, 10));
    }

    #[test]
    fn test_release_and_reuse() {
        let mut alloc =
            SubnetAllocator::new(Ipv4Addr::new(10, 209, 0, 0), 24).unwrap();

        let (idx0, _, _, _) = alloc.allocate().unwrap();
        let (idx1, _, _, _) = alloc.allocate().unwrap();
        assert_eq!(idx0, 0);
        assert_eq!(idx1, 1);

        // Release block 0.
        alloc.release(idx0);

        // Next allocation should reuse block 0 (lowest free).
        let (reused_idx, base, gw, vm) = alloc.allocate().unwrap();
        assert_eq!(reused_idx, 0);
        assert_eq!(base, Ipv4Addr::new(10, 209, 0, 0));
        assert_eq!(gw, Ipv4Addr::new(10, 209, 0, 1));
        assert_eq!(vm, Ipv4Addr::new(10, 209, 0, 2));
    }

    #[test]
    fn test_pool_exhaustion() {
        // Use a /30 base — that gives exactly 1 /30 block.
        let mut alloc =
            SubnetAllocator::new(Ipv4Addr::new(10, 209, 0, 0), 30).unwrap();

        assert_eq!(alloc.max_blocks, 1);

        // Allocate the only block.
        let (idx, _, _, _) = alloc.allocate().unwrap();
        assert_eq!(idx, 0);

        // Second allocation should fail.
        let result = alloc.allocate();
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("exhausted"),
            "error should mention pool exhaustion: {err}"
        );
    }

    #[test]
    fn test_pool_exhaustion_full_24() {
        // A /24 gives 64 /30 blocks.
        let mut alloc =
            SubnetAllocator::new(Ipv4Addr::new(10, 209, 0, 0), 24).unwrap();

        assert_eq!(alloc.max_blocks, 64);

        // Allocate all 64 blocks.
        for i in 0..64u8 {
            let (idx, _, _, _) = alloc.allocate().unwrap();
            assert_eq!(idx, i);
        }

        // 65th allocation should fail.
        let result = alloc.allocate();
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("exhausted"));
    }

    #[test]
    fn test_block_index_for() {
        let alloc =
            SubnetAllocator::new(Ipv4Addr::new(10, 209, 0, 0), 24).unwrap();

        assert_eq!(
            alloc.block_index_for(Ipv4Addr::new(10, 209, 0, 0)),
            Some(0)
        );
        assert_eq!(
            alloc.block_index_for(Ipv4Addr::new(10, 209, 0, 4)),
            Some(1)
        );
        assert_eq!(
            alloc.block_index_for(Ipv4Addr::new(10, 209, 0, 252)),
            Some(63)
        );

        // Not on a /30 boundary.
        assert_eq!(
            alloc.block_index_for(Ipv4Addr::new(10, 209, 0, 3)),
            None
        );
        // Out of range.
        assert_eq!(
            alloc.block_index_for(Ipv4Addr::new(10, 210, 0, 0)),
            None
        );
        // Before base.
        assert_eq!(
            alloc.block_index_for(Ipv4Addr::new(10, 208, 0, 0)),
            None
        );
    }

    #[test]
    fn test_invalid_prefix_len() {
        let result = SubnetAllocator::new(Ipv4Addr::new(10, 0, 0, 0), 31);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("too large"));
    }

    // -- NetworkInfo tests ---------------------------------------------------

    #[test]
    fn test_network_info_fields() {
        let mgr =
            NetworkManager::new(Ipv4Addr::new(10, 209, 0, 0), 24).unwrap();

        let session_id = Uuid::new_v4();

        // We can't call create_network without Docker, so test the allocator
        // and info construction manually.
        let (_, subnet_base, gateway_ip, vm_ip) = {
            let mut alloc = mgr.subnet_allocator.lock().unwrap();
            alloc.allocate().unwrap()
        };

        let session_str = session_id.to_string();
        let short_id = &session_str[..11];
        let bridge_name = format!("sb-{short_id}");
        let docker_network_name = format!("sandbox-net-{session_id}");

        let info = NetworkInfo {
            bridge_name: bridge_name.clone(),
            subnet: format!("{subnet_base}/30"),
            gateway_ip: gateway_ip.to_string(),
            vm_ip: vm_ip.to_string(),
            docker_network_name: docker_network_name.clone(),
        };

        assert_eq!(info.subnet, "10.209.0.0/30");
        assert_eq!(info.gateway_ip, "10.209.0.1");
        assert_eq!(info.vm_ip, "10.209.0.2");
        assert!(info.bridge_name.starts_with("sb-"));
        assert!(info.docker_network_name.starts_with("sandbox-net-"));
    }

    #[test]
    fn test_bridge_name_length() {
        // Kernel interface names are limited to 15 characters.
        // "sb-" is 3 chars + 11 chars of UUID = 14 chars max.
        let session_id = Uuid::new_v4();
        let session_str = session_id.to_string();
        let short_id = &session_str[..11];
        let bridge_name = format!("sb-{short_id}");

        assert!(
            bridge_name.len() <= 15,
            "bridge name '{}' is {} chars (max 15)",
            bridge_name,
            bridge_name.len()
        );
        // Should be exactly 14 chars: "sb-" (3) + 11 chars.
        assert_eq!(bridge_name.len(), 14);
    }

    #[test]
    fn test_network_info_serialization() {
        let info = NetworkInfo {
            bridge_name: "sb-550e8400-e2".to_string(),
            subnet: "10.209.0.0/30".to_string(),
            gateway_ip: "10.209.0.1".to_string(),
            vm_ip: "10.209.0.2".to_string(),
            docker_network_name: "sandbox-net-550e8400-e29b-41d4-a716-446655440000"
                .to_string(),
        };

        let json = serde_json::to_string(&info).unwrap();
        let deserialized: NetworkInfo = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.bridge_name, info.bridge_name);
        assert_eq!(deserialized.subnet, info.subnet);
        assert_eq!(deserialized.gateway_ip, info.gateway_ip);
        assert_eq!(deserialized.vm_ip, info.vm_ip);
        assert_eq!(
            deserialized.docker_network_name,
            info.docker_network_name
        );
    }

    #[test]
    fn test_restore_from_infos() {
        let mgr =
            NetworkManager::new(Ipv4Addr::new(10, 209, 0, 0), 24).unwrap();

        let id1 = Uuid::new_v4();
        let id2 = Uuid::new_v4();

        let info1 = NetworkInfo {
            bridge_name: "sb-aaaaaaaaaaa".to_string(),
            subnet: "10.209.0.0/30".to_string(),
            gateway_ip: "10.209.0.1".to_string(),
            vm_ip: "10.209.0.2".to_string(),
            docker_network_name: format!("sandbox-net-{id1}"),
        };

        let info2 = NetworkInfo {
            bridge_name: "sb-bbbbbbbbbbb".to_string(),
            subnet: "10.209.0.8/30".to_string(),
            gateway_ip: "10.209.0.9".to_string(),
            vm_ip: "10.209.0.10".to_string(),
            docker_network_name: format!("sandbox-net-{id2}"),
        };

        mgr.restore_from_infos(&[(id1, info1.clone()), (id2, info2.clone())])
            .unwrap();

        // Verify the blocks are marked as allocated.
        {
            let alloc = mgr.subnet_allocator.lock().unwrap();
            assert!(alloc.allocated.contains(&0)); // 10.209.0.0 -> block 0
            assert!(alloc.allocated.contains(&2)); // 10.209.0.8 -> block 2
            assert!(!alloc.allocated.contains(&1)); // block 1 should be free
        }

        // Verify network_info returns the restored data.
        let fetched1 = mgr.network_info(&id1).unwrap();
        assert!(fetched1.is_some());
        let fetched1 = fetched1.unwrap();
        assert_eq!(fetched1.subnet, "10.209.0.0/30");

        let fetched2 = mgr.network_info(&id2).unwrap();
        assert!(fetched2.is_some());
        let fetched2 = fetched2.unwrap();
        assert_eq!(fetched2.subnet, "10.209.0.8/30");

        // Verify that the next allocation skips restored blocks.
        // Block 0 and 2 are used, so next free is block 1.
        let (idx, base, _, _) = {
            let mut alloc = mgr.subnet_allocator.lock().unwrap();
            alloc.allocate().unwrap()
        };
        assert_eq!(idx, 1);
        assert_eq!(base, Ipv4Addr::new(10, 209, 0, 4));
    }

    #[test]
    fn test_network_info_not_found() {
        let mgr =
            NetworkManager::new(Ipv4Addr::new(10, 209, 0, 0), 24).unwrap();

        let result = mgr.network_info(&Uuid::new_v4()).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_parse_subnet_base() {
        assert_eq!(
            parse_subnet_base("10.209.0.0/30").unwrap(),
            Ipv4Addr::new(10, 209, 0, 0)
        );
        assert_eq!(
            parse_subnet_base("10.209.0.4/30").unwrap(),
            Ipv4Addr::new(10, 209, 0, 4)
        );
        assert!(parse_subnet_base("not-an-ip/30").is_err());
    }

    // -- Docker integration tests (require Docker daemon) --------------------

    #[test]
    #[ignore]
    fn test_docker_create_and_delete_network() {
        // Use 10.209.1.0/24 to avoid collisions with the labels test.
        let mgr =
            NetworkManager::new(Ipv4Addr::new(10, 209, 1, 0), 24).unwrap();
        let session_id = Uuid::new_v4();

        // Create network.
        let info = mgr.create_network(&session_id).unwrap();

        assert!(info.bridge_name.starts_with("sb-"));
        assert!(info.docker_network_name.starts_with("sandbox-net-"));
        assert_eq!(info.subnet, "10.209.1.0/30");
        assert_eq!(info.gateway_ip, "10.209.1.1");
        assert_eq!(info.vm_ip, "10.209.1.2");

        // Verify with docker network inspect.
        let output = Command::new("docker")
            .args(["network", "inspect", &info.docker_network_name, "--format", "{{json .IPAM.Config}}"])
            .output()
            .expect("docker inspect should succeed");

        assert!(output.status.success(), "docker inspect failed");
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            stdout.contains("10.209.1.0/30"),
            "inspect output should contain subnet: {stdout}"
        );
        assert!(
            stdout.contains("10.209.1.1"),
            "inspect output should contain gateway: {stdout}"
        );

        // Delete network.
        mgr.delete_network(&session_id).unwrap();

        // Verify it's gone.
        let output = Command::new("docker")
            .args(["network", "inspect", &info.docker_network_name])
            .output()
            .expect("docker inspect should run");
        assert!(!output.status.success(), "network should not exist after deletion");
    }

    #[test]
    #[ignore]
    fn test_docker_network_labels() {
        // Use 10.209.2.0/24 to avoid collisions with the create/delete test.
        let mgr =
            NetworkManager::new(Ipv4Addr::new(10, 209, 2, 0), 24).unwrap();
        let session_id = Uuid::new_v4();

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
}
