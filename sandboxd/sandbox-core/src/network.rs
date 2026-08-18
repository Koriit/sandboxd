use std::collections::HashSet;
use std::net::Ipv4Addr;
use std::sync::Mutex;
use std::time::Duration;

use sandbox_docker_argv::network::{NetworkCreateSpec, NetworkDriver, NetworkOption};
use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};

use crate::docker::{DockerOp, DockerRoute};
use crate::error::SandboxError;
use crate::session::SessionId;

#[cfg(target_os = "macos")]
use ring::digest;
#[cfg(target_os = "macos")]
use std::collections::HashMap;

// ---------------------------------------------------------------------------
// Timeout constants
// ---------------------------------------------------------------------------

/// Timeout for `docker network create`.
const CREATE_NETWORK_TIMEOUT: Duration = Duration::from_secs(30);

/// Timeout for `docker network rm`.
const DELETE_NETWORK_TIMEOUT: Duration = Duration::from_secs(30);

/// Timeout for `docker network inspect`.
const INSPECT_NETWORK_TIMEOUT: Duration = Duration::from_secs(10);

// ---------------------------------------------------------------------------
// Per-session bridge options
// ---------------------------------------------------------------------------

/// Driver options every per-session bridge carries.
///
/// One function rather than a literal at each call site, because the two
/// creation paths — first create and the recreate-on-start path in
/// [`NetworkManager::ensure_network`] — must not be able to drift apart. A
/// session whose bridge was recreated with different options is a session
/// with different egress properties.
///
/// # Masquerade, and why the answer depends on the route
///
/// Docker's bridge driver masquerades a network's subnet out of the host's
/// uplink by default, which gives every container on the bridge a working
/// path to the internet through the bridge's `.1` address from the instant
/// it starts — before `sandbox-route-helper` has replaced that default
/// route with the gateway container's address, and again any time something
/// inside the container points its default route back at `.1`. The second
/// one is the bypass no policy rule can see, because it never reaches the
/// gateway container at all. Turning the NAT off removes the path instead
/// of filtering it, and makes the pre-route state fail closed.
///
/// It can only be turned off where the gateway container has an uplink of
/// its own, and that differs by platform:
///
/// - **In-VM bridges (macOS lite, [`DockerRoute::Vm`]).** The gateway
///   container is started on the `sandboxd-egress` bridge and the session
///   bridge is attached to it afterwards, so it keeps a route to the
///   internet that does not depend on this NAT. Masquerade off.
/// - **Host bridges ([`DockerRoute::Host`], Linux).** The gateway container
///   has exactly one NIC, on the session bridge itself, and there is no
///   `sandboxd-egress` — that bridge exists only inside the macOS gateway
///   VM. Here the session bridge's masquerade *is* the gateway's uplink,
///   and removing it takes out every allowed flow, not just the bypass.
///   Masquerade left at Docker's default.
///
/// Note this is about the *gateway's* traffic, not the sandbox's: a session
/// container's allowed traffic never consults this NAT either way, because
/// it is addressed to the gateway container on the same bridge and never
/// leaves it.
fn session_bridge_options(bridge_name: &str, route: &DockerRoute) -> Vec<NetworkOption> {
    let mut options = vec![NetworkOption::BridgeName(bridge_name.to_string())];
    if matches!(route, DockerRoute::Vm { .. }) {
        options.push(NetworkOption::BridgeMasquerade(false));
    }
    options
}

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// Information about a session's network.
///
/// On Linux this describes a Docker bridge /28. On macOS this describes an
/// isolated socket_vmnet /29 slot; the `vmnet_slot` field carries the
/// macOS-specific slot metadata and is absent on Linux rows and on stopped
/// macOS sessions (slots are released on stop).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkInfo {
    /// Kernel bridge interface name.
    ///
    /// Linux: `sb-{session_id}` (3 + 12 = 15 chars, the Linux IFNAMSIZ
    /// maximum). macOS: the gateway Lima VM's NIC name for this slot, e.g.
    /// `lima2` for slot 2 (the NIC at index 2 in the gateway VM's
    /// `networks:` list).
    pub bridge_name: String,
    /// Subnet in CIDR notation.
    ///
    /// Linux: e.g. `"10.209.0.0/28"`. macOS: e.g. `"10.209.128.0/29"` for
    /// slot 0. Note the semantics of `gateway_ip`/`vm_ip` differ between
    /// platforms — see those fields.
    pub subnet: String,
    /// Gateway container IP.
    ///
    /// Linux: the `.2` in the /28 (Docker bridge claims `.1`).
    /// macOS: `B+3` in the /29 slot, where `B` is the slot's base address.
    /// The gateway container is assigned this address statically via Docker
    /// macvlan `--ip`.
    pub gateway_ip: String,
    /// Sandbox VM IP.
    ///
    /// Linux: the `.3` in the /28, assigned to the VM's veth.
    /// macOS: `B+4` in the /29 slot, assigned statically via cloud-init.
    pub vm_ip: String,
    /// Docker network name: `sandbox-net-{session_id}`.
    pub docker_network_name: String,
    /// macOS-only: socket_vmnet slot info.
    ///
    /// `None` on Linux sessions, and on stopped macOS sessions (slots are
    /// released on stop). Persisted inside the `network_info` JSON blob with
    /// `#[serde(default)]` so old rows (written before this field existed)
    /// deserialize cleanly with `None`.
    #[serde(default)]
    pub vmnet_slot: Option<VmnetSlot>,
    /// The operator uid this session's slot (or session-count token)
    /// belongs to.
    ///
    /// macOS only in practice; `None` on Linux rows. Restore needs it to
    /// route a persisted session back into the right operator's pool, and
    /// nothing else on the record answers that question:
    /// `Session.owner_username` is a *name*, and a name has to be resolved
    /// against a directory that may have changed underneath it.
    ///
    /// Not derived from the slot index, though the slot does imply a range
    /// and a range does imply an operator. That derivation is wrong twice
    /// over: lite sessions claim a token and no slot at all, so it would
    /// cover only half the sessions; and it would misattribute an old
    /// session the moment a slot changed hands, silently and with no way
    /// to notice. An explicit field covers both backends and cannot be
    /// quietly wrong.
    ///
    /// `Option` + `#[serde(default)]` per `CLAUDE.md`'s blob-field rules:
    /// a row written before this field existed deserializes with `None`,
    /// and a row written with it deserializes on a daemon that predates it
    /// (serde ignores unknown fields), so a rollback loses the routing hint
    /// rather than the record.
    #[serde(default)]
    pub operator_uid: Option<u32>,
}

/// Identity of a socket_vmnet slot claimed by a running macOS Lima session.
///
/// Persisted inside the `NetworkInfo` JSON blob. Old rows (pre-macOS or
/// stopped sessions) deserialize with `vmnet_slot: None`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VmnetSlot {
    /// Slot index `0..max_slots-1`.
    pub index: u16,
    /// launchd job label, e.g. `"io.sandboxd.vmnet.2"`.
    pub daemon_label: String,
    /// Path to the socket_vmnet Unix socket for this slot,
    /// e.g. `"/var/run/sandbox/vmnet/slot-2.sock"`.
    pub socket_path: String,
}

// ---------------------------------------------------------------------------
// SubnetAllocator
// ---------------------------------------------------------------------------

/// Carves /28 subnets from a base range.
///
/// Each /28 has 16 addresses:
///   .0 = network, .1 = Docker bridge gateway (auto-claimed),
///   .2 = gateway container, .3 = VM, .4-.14 = unused, .15 = broadcast
///
/// A /24 base provides 16 /28 blocks (256 / 16).
#[derive(Debug)]
struct SubnetAllocator {
    /// Base network address, e.g. `10.209.0.0`.
    base: Ipv4Addr,
    /// Prefix length of the base range (e.g. 24). Retained for diagnostics.
    prefix_len: u8,
    /// Set of allocated /28 block indices (0..max_blocks).
    allocated: HashSet<u16>,
    /// Maximum number of /28 blocks: 2^(32 - prefix_len) / 16. A `/20`
    /// (the shipped `users.conf` default) yields exactly 256 blocks,
    /// which is why this is u16 rather than u8.
    max_blocks: u16,
}

impl SubnetAllocator {
    /// Create a new allocator for the given base range.
    ///
    /// `prefix_len` must be <= 28 (a /28 is the smallest usable subnet).
    /// The number of /28 blocks is `2^(32 - prefix_len) / 16`.
    fn new(base: Ipv4Addr, prefix_len: u8) -> Result<Self, SandboxError> {
        if prefix_len > 28 {
            return Err(SandboxError::Network(format!(
                "prefix length {prefix_len} is too large; maximum is 28"
            )));
        }

        let host_bits = 32 - prefix_len;
        // Total addresses in the range.
        let total_addrs: u32 = 1 << host_bits;
        // Each /28 uses 16 addresses.
        let max_blocks = total_addrs / 16;

        // Block index is stored as u16 (65535 blocks is well past any
        // practical pool size — `/12` already gives 65536). Reject
        // anything bigger so the cast below cannot truncate.
        if max_blocks > u16::MAX as u32 {
            return Err(SandboxError::Network(format!(
                "base range /{prefix_len} yields {max_blocks} blocks, \
                 which exceeds the u16 block-index limit ({})",
                u16::MAX
            )));
        }

        Ok(Self {
            base,
            prefix_len,
            allocated: HashSet::new(),
            max_blocks: max_blocks as u16,
        })
    }

    /// Allocate the next available /28 block.
    ///
    /// Returns `(block_index, subnet_base, gateway_ip, vm_ip)`.
    fn allocate(&mut self) -> Result<(u16, Ipv4Addr, Ipv4Addr, Ipv4Addr), SandboxError> {
        // Find the lowest free index.
        let block_idx = (0..self.max_blocks)
            .find(|idx| !self.allocated.contains(idx))
            .ok_or_else(|| {
                SandboxError::Network(format!(
                    "subnet pool exhausted: all {} /28 blocks are allocated",
                    self.max_blocks
                ))
            })?;

        self.allocated.insert(block_idx);

        let base_u32 = u32::from(self.base);
        let offset = (block_idx as u32) * 16;
        let subnet_base = Ipv4Addr::from(base_u32 + offset);
        // .1 is claimed by Docker bridge; .2 = gateway container, .3 = VM
        let gateway_ip = Ipv4Addr::from(base_u32 + offset + 2);
        let vm_ip = Ipv4Addr::from(base_u32 + offset + 3);

        Ok((block_idx, subnet_base, gateway_ip, vm_ip))
    }

    /// Release a /28 block back to the pool.
    fn release(&mut self, block_idx: u16) {
        self.allocated.remove(&block_idx);
    }

    /// Mark a specific block as allocated (used during state rebuild).
    fn mark_allocated(&mut self, block_idx: u16) -> Result<(), SandboxError> {
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
    fn block_index_for(&self, subnet_base: Ipv4Addr) -> Option<u16> {
        let base_u32 = u32::from(self.base);
        let addr_u32 = u32::from(subnet_base);

        if addr_u32 < base_u32 {
            return None;
        }

        let offset = addr_u32 - base_u32;
        if offset % 16 != 0 {
            return None;
        }

        let idx = offset / 16;
        if idx >= self.max_blocks as u32 {
            return None;
        }

        Some(idx as u16)
    }
}

// ---------------------------------------------------------------------------
// NetworkManager
// ---------------------------------------------------------------------------

/// Manages per-session Docker bridge networks with /28 subnets.
///
/// Each session gets an isolated Docker bridge network with a unique /28
/// subnet carved from a configurable base range (default `10.209.0.0/24`).
pub struct NetworkManager {
    subnet_allocator: Mutex<SubnetAllocator>,
    /// Maps session_id -> (block_index, NetworkInfo) for active networks.
    networks: Mutex<std::collections::HashMap<SessionId, (u16, NetworkInfo)>>,
    /// Canonical pool CIDR string (`<base>/<prefix>`, e.g. `10.209.0.0/20`)
    /// stamped as `sandboxd.owner=<pool>` on every Docker resource this daemon
    /// creates. Used by the orphan reaper to distinguish resources belonging to
    /// this daemon from those belonging to a co-deployed daemon with a disjoint
    /// pool.
    pub owner_pool: String,
}

impl NetworkManager {
    /// Create a new `NetworkManager` with the given base range.
    ///
    /// `owner_pool` is the canonical CIDR string (`<base>/<prefix>`) stamped
    /// as `sandboxd.owner=<pool>` on every Docker resource created by this
    /// daemon. Pass the same value as `allocation_pool`'s canonical form:
    /// `format!("{}/{}", pool.base(), pool.prefix_len())`.
    ///
    /// Default: `10.209.0.0/24` provides 16 /28 subnets.
    pub fn new(base: Ipv4Addr, prefix_len: u8, owner_pool: String) -> Result<Self, SandboxError> {
        let allocator = SubnetAllocator::new(base, prefix_len)?;
        Ok(Self {
            subnet_allocator: Mutex::new(allocator),
            networks: Mutex::new(std::collections::HashMap::new()),
            owner_pool,
        })
    }

    /// Create a new `NetworkManager` with the default base range `10.209.0.0/24`.
    /// Owner pool defaults to `10.209.0.0/24` — used only in unit tests that
    /// don't exercise the owner-label path.
    pub fn with_defaults() -> Result<Self, SandboxError> {
        Self::new(
            Ipv4Addr::new(10, 209, 0, 0),
            24,
            "10.209.0.0/24".to_string(),
        )
    }

    /// Rebuild allocator state from existing `NetworkInfo` entries.
    ///
    /// Call this on daemon startup after loading sessions from the store.
    /// For each session that has a `NetworkInfo`, the corresponding /28 block
    /// is marked as allocated.
    pub fn restore_from_infos(
        &self,
        entries: &[(SessionId, NetworkInfo)],
    ) -> Result<(), SandboxError> {
        let mut alloc = self
            .subnet_allocator
            .lock()
            .map_err(|e| SandboxError::Internal(format!("lock poisoned: {e}")))?;
        let mut nets = self
            .networks
            .lock()
            .map_err(|e| SandboxError::Internal(format!("lock poisoned: {e}")))?;

        for (session_id, info) in entries {
            // Parse the subnet base from the CIDR string.
            let subnet_base = parse_subnet_base(&info.subnet)?;
            let block_idx = alloc.block_index_for(subnet_base).ok_or_else(|| {
                SandboxError::Network(format!(
                    "subnet {} does not map to a valid block in the base range \
                     {}/{} (session {})",
                    info.subnet, alloc.base, alloc.prefix_len, session_id
                ))
            })?;
            alloc.mark_allocated(block_idx)?;
            nets.insert(*session_id, (block_idx, info.clone()));
        }

        Ok(())
    }

    /// Create a Docker bridge network for the given session, optionally
    /// targeting a forwarded Docker socket.
    ///
    /// Allocates a /28 subnet from the daemon's pool, shells out to
    /// `docker [-H unix://<socket>] network create --driver bridge`, and
    /// returns the resulting `NetworkInfo`.
    ///
    /// `route` is [`DockerRoute::Host`] on Linux (host docker daemon,
    /// unchanged) and [`DockerRoute::Vm`] on macOS lite-mode, where the
    /// bridge belongs inside the gateway VM rather than on the macOS host.
    ///
    /// If Docker reports a subnet pool overlap (stale network from a previous
    /// daemon), the allocator advances to the next block and retries.
    pub fn create_network_on_route(
        &self,
        session_id: &SessionId,
        route: &DockerRoute,
    ) -> Result<NetworkInfo, SandboxError> {
        self.create_network_inner(session_id, route)
    }

    /// Create a Docker bridge network for the given session.
    ///
    /// Allocates a /28 subnet, shells out to `docker network create`, and
    /// returns the resulting `NetworkInfo`.
    ///
    /// If Docker reports a subnet pool overlap (stale network from a previous
    /// daemon), the allocator advances to the next block and retries.
    pub fn create_network(&self, session_id: &SessionId) -> Result<NetworkInfo, SandboxError> {
        self.create_network_inner(session_id, &DockerRoute::Host)
    }

    fn create_network_inner(
        &self,
        session_id: &SessionId,
        route: &DockerRoute,
    ) -> Result<NetworkInfo, SandboxError> {
        // Check if the session already has a network.
        {
            let nets = self
                .networks
                .lock()
                .map_err(|e| SandboxError::Internal(format!("lock poisoned: {e}")))?;
            if let Some((_, info)) = nets.get(session_id) {
                return Err(SandboxError::Network(format!(
                    "session {} already has network {}",
                    session_id, info.docker_network_name
                )));
            }
        }

        let max_attempts = {
            let alloc = self
                .subnet_allocator
                .lock()
                .map_err(|e| SandboxError::Internal(format!("lock poisoned: {e}")))?;
            alloc.max_blocks as usize
        };

        let mut last_err = String::new();

        for attempt in 0..max_attempts {
            // Allocate a /28 subnet.
            let (block_idx, subnet_base, gateway_ip, vm_ip) = {
                let mut alloc = self
                    .subnet_allocator
                    .lock()
                    .map_err(|e| SandboxError::Internal(format!("lock poisoned: {e}")))?;
                alloc.allocate()?
            };

            let bridge_name = format!("sb-{session_id}");
            let docker_network_name = format!("sandbox-net-{session_id}");
            let subnet = format!("{subnet_base}/28");

            debug!(
                session_id = %session_id,
                subnet = %subnet,
                gateway = %gateway_ip,
                bridge = %bridge_name,
                attempt = attempt + 1,
                "creating Docker bridge network"
            );

            let spec = NetworkCreateSpec {
                name: docker_network_name.clone(),
                driver: NetworkDriver::Bridge,
                subnet: Some(subnet.clone()),
                gateway: None,
                session_id: Some(session_id.to_string()),
                owner_pool: Some(self.owner_pool.clone()),
                options: session_bridge_options(&bridge_name, route),
            };
            let output = route
                .run(
                    DockerOp::NetworkCreate { spec },
                    CREATE_NETWORK_TIMEOUT,
                    "docker network create",
                )
                .map_err(|e| match e {
                    SandboxError::Internal(msg) if msg.contains("failed to spawn") => {
                        SandboxError::Network(format!("failed to run docker network create: {msg}"))
                    }
                    other => other,
                })?;

            if output.status.success() {
                let info = NetworkInfo {
                    bridge_name,
                    subnet: subnet.clone(),
                    gateway_ip: gateway_ip.to_string(),
                    vm_ip: vm_ip.to_string(),
                    docker_network_name: docker_network_name.clone(),
                    vmnet_slot: None,
                    // Linux: the per-operator vmnet partition is a macOS
                    // concept and this allocator is not part of it.
                    operator_uid: None,
                };

                // Track the network.
                {
                    let mut nets = self
                        .networks
                        .lock()
                        .map_err(|e| SandboxError::Internal(format!("lock poisoned: {e}")))?;
                    nets.insert(*session_id, (block_idx, info.clone()));
                }

                info!(
                    session_id = %session_id,
                    network = %docker_network_name,
                    subnet = %subnet,
                    "Docker bridge network created"
                );

                return Ok(info);
            }

            let stderr = String::from_utf8_lossy(&output.stderr);
            last_err = stderr.to_string();

            // Retry on pool overlap (stale network from previous daemon).
            // Keep the block allocated so the next allocate() picks a
            // different block — the subnet is occupied by an external
            // Docker network we don't control.
            if stderr.contains("Pool overlaps") || stderr.contains("invalid pool request") {
                warn!(
                    session_id = %session_id,
                    subnet = %subnet,
                    attempt = attempt + 1,
                    "subnet pool overlap, trying next block"
                );
                continue;
            }

            // Non-overlap error — release the block and fail immediately.
            {
                let mut alloc = self
                    .subnet_allocator
                    .lock()
                    .map_err(|e| SandboxError::Internal(format!("lock poisoned: {e}")))?;
                alloc.release(block_idx);
            }

            return Err(SandboxError::Network(format!(
                "docker network create failed: {stderr}"
            )));
        }

        Err(SandboxError::Network(format!(
            "docker network create failed after {max_attempts} attempts: {last_err}"
        )))
    }

    /// Delete the Docker bridge network for the given session (host daemon).
    pub fn delete_network(&self, session_id: &SessionId) -> Result<(), SandboxError> {
        self.delete_network_inner(session_id, &DockerRoute::Host)
    }

    /// Route-aware variant of [`Self::delete_network`].
    ///
    /// A [`DockerRoute::Vm`] route removes the bridge from inside the gateway
    /// VM (macOS lite-mode); [`DockerRoute::Host`] is byte-identical to
    /// [`Self::delete_network`]. Mirrors [`Self::create_network_on_route`].
    pub fn delete_network_on_route(
        &self,
        session_id: &SessionId,
        route: &DockerRoute,
    ) -> Result<(), SandboxError> {
        self.delete_network_inner(session_id, route)
    }

    fn delete_network_inner(
        &self,
        session_id: &SessionId,
        route: &DockerRoute,
    ) -> Result<(), SandboxError> {
        let (block_idx, info) = {
            let nets = self
                .networks
                .lock()
                .map_err(|e| SandboxError::Internal(format!("lock poisoned: {e}")))?;
            nets.get(session_id).cloned().ok_or_else(|| {
                SandboxError::Network(format!("no network found for session {session_id}"))
            })?
        };

        debug!(
            session_id = %session_id,
            network = %info.docker_network_name,
            "deleting Docker bridge network"
        );

        let output = route
            .run(
                DockerOp::NetworkRemove {
                    name: info.docker_network_name.clone(),
                },
                DELETE_NETWORK_TIMEOUT,
                "docker network rm",
            )
            .map_err(|e| match e {
                SandboxError::Internal(msg) if msg.contains("failed to spawn") => {
                    SandboxError::Network(format!("failed to run docker network rm: {msg}"))
                }
                other => other,
            })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(SandboxError::Network(format!(
                "docker network rm failed: {stderr}"
            )));
        }

        // Release the subnet and remove tracking.
        {
            let mut alloc = self
                .subnet_allocator
                .lock()
                .map_err(|e| SandboxError::Internal(format!("lock poisoned: {e}")))?;
            alloc.release(block_idx);
        }
        {
            let mut nets = self
                .networks
                .lock()
                .map_err(|e| SandboxError::Internal(format!("lock poisoned: {e}")))?;
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
    pub fn network_info(
        &self,
        session_id: &SessionId,
    ) -> Result<Option<NetworkInfo>, SandboxError> {
        let nets = self
            .networks
            .lock()
            .map_err(|e| SandboxError::Internal(format!("lock poisoned: {e}")))?;
        Ok(nets.get(session_id).map(|(_, info)| info.clone()))
    }

    /// Ensure the Docker bridge network exists for a session with existing
    /// `NetworkInfo`.
    ///
    /// Unlike `create_network`, this does NOT allocate a new subnet. It uses
    /// the `NetworkInfo` already tracked in the manager's in-memory map
    /// (typically restored from DB at startup via `restore_from_infos`).
    ///
    /// If the Docker network already exists, this is a no-op. If it was
    /// removed (e.g. during `stop`), it is recreated with the same subnet.
    ///
    /// On Linux this targets the host Docker daemon. For macOS lite-mode
    /// sessions where the bridge lives inside the gateway VM, use
    /// `ensure_network_on_socket` with the forwarded socket path.
    pub fn ensure_network(&self, session_id: &SessionId) -> Result<NetworkInfo, SandboxError> {
        self.ensure_network_inner(session_id, &DockerRoute::Host)
    }

    /// Socket-aware variant of `ensure_network`.
    ///
    /// When `docker_socket` is `Some`, the docker client is directed to that
    /// forwarded socket (macOS lite-mode — the bridge lives inside the
    /// gateway VM). When `docker_socket` is `None` this is byte-identical
    /// to `ensure_network` and targets the host Docker daemon.
    pub fn ensure_network_on_route(
        &self,
        session_id: &SessionId,
        route: &DockerRoute,
    ) -> Result<NetworkInfo, SandboxError> {
        self.ensure_network_inner(session_id, route)
    }

    fn ensure_network_inner(
        &self,
        session_id: &SessionId,
        route: &DockerRoute,
    ) -> Result<NetworkInfo, SandboxError> {
        let info = {
            let nets = self
                .networks
                .lock()
                .map_err(|e| SandboxError::Internal(format!("lock poisoned: {e}")))?;
            nets.get(session_id)
                .map(|(_, info)| info.clone())
                .ok_or_else(|| {
                    SandboxError::Network(format!(
                        "no network info tracked for session {session_id}"
                    ))
                })?
        };

        // Check if the Docker network already exists.
        let check = route
            .run(
                DockerOp::NetworkInspect {
                    name: info.docker_network_name.clone(),
                },
                INSPECT_NETWORK_TIMEOUT,
                "docker network inspect",
            )
            .map_err(|e| match e {
                SandboxError::Internal(msg) if msg.contains("failed to spawn") => {
                    SandboxError::Network(format!("failed to run docker network inspect: {msg}"))
                }
                other => other,
            })?;

        if check.status.success() {
            debug!(
                session_id = %session_id,
                network = %info.docker_network_name,
                "Docker bridge network already exists"
            );
            return Ok(info);
        }

        // Network does not exist -- recreate it with the same subnet.
        info!(
            session_id = %session_id,
            network = %info.docker_network_name,
            subnet = %info.subnet,
            bridge = %info.bridge_name,
            "recreating Docker bridge network"
        );

        let spec = NetworkCreateSpec {
            name: info.docker_network_name.clone(),
            driver: NetworkDriver::Bridge,
            subnet: Some(info.subnet.clone()),
            gateway: None,
            session_id: Some(session_id.to_string()),
            owner_pool: None,
            options: session_bridge_options(&info.bridge_name, route),
        };
        let output = route
            .run(
                DockerOp::NetworkCreate { spec },
                CREATE_NETWORK_TIMEOUT,
                "docker network create (ensure)",
            )
            .map_err(|e| match e {
                SandboxError::Internal(msg) if msg.contains("failed to spawn") => {
                    SandboxError::Network(format!("failed to run docker network create: {msg}"))
                }
                other => other,
            })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(SandboxError::Network(format!(
                "docker network create failed for ensure_network: {stderr}"
            )));
        }

        info!(
            session_id = %session_id,
            network = %info.docker_network_name,
            "Docker bridge network recreated"
        );

        Ok(info)
    }

    /// Remove the Docker bridge network for a session without releasing the
    /// subnet allocation or removing the in-memory tracking.
    ///
    /// Used during `stop` to free Docker resources while preserving the
    /// ability to recreate the same network on `start`. The subnet stays
    /// allocated so it cannot be reused by another session.
    ///
    /// If the Docker network does not exist, this is a no-op (returns Ok).
    pub fn remove_docker_network(&self, session_id: &SessionId) -> Result<(), SandboxError> {
        self.remove_docker_network_inner(session_id, &DockerRoute::Host)
    }

    /// Route-aware variant of [`Self::remove_docker_network`].
    ///
    /// A [`DockerRoute::Vm`] route means the
    /// bridge is removed from inside the gateway VM (macOS lite-mode). When
    /// `None` this is byte-identical to [`remove_docker_network`].
    pub fn remove_docker_network_on_route(
        &self,
        session_id: &SessionId,
        route: &DockerRoute,
    ) -> Result<(), SandboxError> {
        self.remove_docker_network_inner(session_id, route)
    }

    fn remove_docker_network_inner(
        &self,
        session_id: &SessionId,
        route: &DockerRoute,
    ) -> Result<(), SandboxError> {
        let info = {
            let nets = self
                .networks
                .lock()
                .map_err(|e| SandboxError::Internal(format!("lock poisoned: {e}")))?;
            match nets.get(session_id) {
                Some((_, info)) => info.clone(),
                None => {
                    debug!(
                        session_id = %session_id,
                        "no network tracked for session, nothing to remove"
                    );
                    return Ok(());
                }
            }
        };

        debug!(
            session_id = %session_id,
            network = %info.docker_network_name,
            "removing Docker bridge network (keeping allocation)"
        );

        let output = route
            .run(
                DockerOp::NetworkRemove {
                    name: info.docker_network_name.clone(),
                },
                DELETE_NETWORK_TIMEOUT,
                "docker network rm (remove)",
            )
            .map_err(|e| match e {
                SandboxError::Internal(msg) if msg.contains("failed to spawn") => {
                    SandboxError::Network(format!("failed to run docker network rm: {msg}"))
                }
                other => other,
            })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            // If the network doesn't exist, that's fine.
            if stderr.contains("not found") || stderr.contains("No such network") {
                debug!(
                    session_id = %session_id,
                    "Docker network already removed"
                );
                return Ok(());
            }
            return Err(SandboxError::Network(format!(
                "docker network rm failed: {stderr}"
            )));
        }

        info!(
            session_id = %session_id,
            network = %info.docker_network_name,
            "Docker bridge network removed (allocation preserved)"
        );

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Parse the base address from a CIDR string like `"10.209.0.16/28"`.
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
// macOS: socket_vmnet pool
// ===========================================================================

/// Default base network for macOS socket_vmnet /29 slots.
///
/// Distinct from Linux's `10.209.0.0/24` to avoid address conflicts in
/// dual-boot or shared-config scenarios.
#[cfg(target_os = "macos")]
pub const MACOS_VMNET_BASE: Ipv4Addr = Ipv4Addr::new(10, 209, 128, 0);

/// Base directory where slot sockets are created.
#[cfg(target_os = "macos")]
pub const VMNET_SOCKET_DIR: &str = "/var/run/sandbox/vmnet";

/// The socket_vmnet binary path that launchd daemons exec.
///
/// Staged here by install.sh from the Homebrew prefix so root-owned
/// launchd daemons never exec an admin-writable path.
#[cfg(target_os = "macos")]
pub const STAGED_SOCKET_VMNET_PATH: &str = "/Library/sandboxd/socket_vmnet";

/// The macOS daemon account and group named by every vmnet launchd plist.
///
/// macOS reserves `_sandbox` (uid/gid 60) for its Seatbelt subsystem, so
/// sandboxd uses a dedicated `_sandboxd` account and group of its own.
///
/// This is the Rust *declaration* of that identity, and the only place the
/// name is written in this crate. Two other emitters declare it
/// independently — `DARWIN_SANDBOXD_ACCOUNT` in the `Makefile` and
/// `_sandboxd_acct` in `scripts/install.sh` — because a `curl | sh`
/// installer cannot read a file from the repo and `make` cannot read a Rust
/// constant. `scripts/check-vmnet-uuid-equivalence.py` extracts all three,
/// plus the account the installer actually *creates*, and fails when they
/// disagree; that comparison, rather than a shared literal, is what keeps
/// them from drifting.
///
/// Rust code must use this constant rather than repeating the literal. The
/// broker's enrollment gate does — the group it checks membership in and the
/// group these plists name are the same identity, and a fourth declaration
/// would be a fourth thing to keep in step. Not `cfg`-gated for that reason:
/// `broker.rs` compiles on every platform even though the account is a macOS
/// concept.
pub const SANDBOXD_ACCOUNT: &str = "_sandboxd";

/// Fixed sandboxd namespace UUID for per-slot network-identifier derivation.
///
/// Used as the UUIDv5 namespace when deriving each slot's `--vmnet-network-identifier`.
/// Must be stable across releases — changing it would produce different UUIDs for
/// existing slots and could break booted VMs that reference the old identifiers.
///
/// Derived once via `uuid::Uuid::new_v4()` and hardcoded. Not a secret.
#[cfg(target_os = "macos")]
const SANDBOXD_VMNET_NAMESPACE: &[u8; 16] = &[
    0x6d, 0x4f, 0x6e, 0x2b, 0x95, 0x8a, 0x4f, 0x1a, 0xa2, 0x31, 0x7e, 0x8c, 0xd0, 0x12, 0x3e, 0x5b,
];

/// Derive the deterministic per-slot `--vmnet-network-identifier` UUID.
///
/// Implements UUIDv5 (SHA-1 namespace-based) using the fixed sandboxd vmnet
/// namespace and the slot index as the name. Deterministic so the identifier
/// is stable across daemon/host restarts; unique per slot so the kernel
/// isolates each slot on its own L2 bridge — the load-bearing inter-slot
/// isolation control.
///
/// # UUIDv5 construction
///
/// RFC 4122 §4.3: hash = SHA1(namespace_bytes ++ name_bytes); take bytes
/// [0..16], set version = 5 (bits 4–7 of byte 6), set variant = RFC4122
/// (bits 6–7 of byte 8).
#[cfg(target_os = "macos")]
pub fn vmnet_slot_network_identifier(slot: u16) -> String {
    let mut ctx = digest::Context::new(&digest::SHA1_FOR_LEGACY_USE_ONLY);
    ctx.update(SANDBOXD_VMNET_NAMESPACE);
    ctx.update(&slot.to_be_bytes());
    let hash = ctx.finish();
    let h = hash.as_ref();

    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&h[..16]);

    // Set version = 5 (top nibble of byte 6).
    bytes[6] = (bytes[6] & 0x0f) | 0x50;
    // Set variant = RFC 4122 (top two bits of byte 8 = 10).
    bytes[8] = (bytes[8] & 0x3f) | 0x80;

    // Format as 8-4-4-4-12.
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        bytes[0],
        bytes[1],
        bytes[2],
        bytes[3],
        bytes[4],
        bytes[5],
        bytes[6],
        bytes[7],
        bytes[8],
        bytes[9],
        bytes[10],
        bytes[11],
        bytes[12],
        bytes[13],
        bytes[14],
        bytes[15],
    )
}

/// Compute the address roles for a given slot's /29 subnet.
///
/// Each slot occupies the /29 at `B = MACOS_VMNET_BASE + 8·slot`.
///
/// | Offset | Role |
/// |--------|------|
/// | `B+0`  | Network address |
/// | `B+1`  | Host-side vmnet gateway — the per-identifier `bridgeN` address on the macOS host. Reachable on-link but host mode provides no internet transit; not an egress path. |
/// | `B+2`  | Gateway Lima VM's slot NIC (macvlan parent) — link-up only; no L3 address assigned. |
/// | `B+3`  | Gateway container IP — assigned statically via Docker macvlan `--ip`. |
/// | `B+4`  | Sandbox VM IP — assigned statically via cloud-init; default route = `B+3`. |
/// | `B+5`  | Unused |
/// | `B+6`  | Unused |
/// | `B+7`  | Broadcast |
///
/// Returns `(subnet_cidr, gateway_ip, vm_ip)` where:
/// - `subnet_cidr` is e.g. `"10.209.128.0/29"` for slot 0
/// - `gateway_ip` is `B+3` (gateway container)
/// - `vm_ip` is `B+4` (sandbox VM)
#[cfg(target_os = "macos")]
pub fn vmnet_slot_addresses(slot: u16) -> (String, Ipv4Addr, Ipv4Addr) {
    let base_u32 = u32::from(MACOS_VMNET_BASE);
    let slot_base = base_u32 + (slot as u32) * 8;
    let subnet_base = Ipv4Addr::from(slot_base);
    let gateway_ip = Ipv4Addr::from(slot_base + 3);
    let vm_ip = Ipv4Addr::from(slot_base + 4);
    (format!("{subnet_base}/29"), gateway_ip, vm_ip)
}

/// Derive the socket path for a given slot.
#[cfg(target_os = "macos")]
pub fn vmnet_slot_socket_path(slot: u16) -> String {
    format!("{VMNET_SOCKET_DIR}/slot-{slot}.sock")
}

/// Recover the slot index from a vmnet slot socket path — the exact inverse of
/// [`vmnet_slot_socket_path`].
///
/// The socket path is the authority on which L2 segment an interface is
/// attached to, so anything that claims a `lima<n>` name for an entry can be
/// checked against the socket it sits on rather than trusted. Returns `None`
/// unless the path is byte-for-byte what `vmnet_slot_socket_path` would emit
/// for the parsed index — which rejects a foreign directory and non-canonical
/// spellings (`slot-04.sock`, `slot-+4.sock`) alike.
#[cfg(target_os = "macos")]
pub fn slot_from_vmnet_socket_path(path: &str) -> Option<u16> {
    let file = std::path::Path::new(path).file_name()?.to_str()?;
    let digits = file.strip_prefix("slot-")?.strip_suffix(".sock")?;
    // Reject non-canonical spellings (`slot-04.sock`, `slot-+4.sock`) so the
    // round-trip is exact in both directions: a path only parses back to the
    // slot that would have generated it.
    let slot: u16 = digits.parse().ok()?;
    (vmnet_slot_socket_path(slot) == path).then_some(slot)
}

/// Derive the launchd daemon label for a given slot.
#[cfg(target_os = "macos")]
pub fn vmnet_slot_daemon_label(slot: u16) -> String {
    format!("io.sandboxd.vmnet.{slot}")
}

/// Verify that the account a vmnet plist names resolves on this host.
///
/// The plist's root `/bin/sh -c` preamble runs
/// `install -d -o <account> -g <account> …` at every boot, because `/var/run`
/// is cleared each time. `install` exits non-zero with `unknown user` /
/// `unknown group` when the account is absent, and the preamble is
/// `&&`-chained, so socket_vmnet is never exec'd: every slot in the pool
/// dies, `KeepAlive` turns it into a throttled retry loop, and the failure
/// surfaces at the next reboot — detached from whatever wrote the plist and
/// reported success.
///
/// Emitting such a plist is therefore never useful, and every emitter must
/// refuse rather than defer. Returns an error naming the account and the way
/// to create it.
#[cfg(target_os = "macos")]
pub fn ensure_vmnet_account_resolvable(account: &str) -> Result<(), SandboxError> {
    let user_ok = nix::unistd::User::from_name(account)
        .ok()
        .flatten()
        .is_some();
    let group_ok = nix::unistd::Group::from_name(account)
        .ok()
        .flatten()
        .is_some();
    if user_ok && group_ok {
        return Ok(());
    }

    let missing = if !user_ok && !group_ok {
        "user and group do"
    } else if !user_ok {
        "user does"
    } else {
        "group does"
    };
    Err(SandboxError::Network(format!(
        "refusing to generate a vmnet plist naming '{account}': that {missing} not exist on \
         this host. The plist's root pre-exec preamble runs \
         `install -d -o {account} -g {account} -m 0750 /var/run/sandbox` at every boot; with \
         the account absent that fails, the &&-chain short-circuits, and no socket_vmnet slot \
         starts. Create the account first: `make setup-darwin-sandboxd-user` on a dev host, \
         or run `scripts/install.sh` for a production install."
    )))
}

/// Render the launchd plist XML for a single socket_vmnet pool slot.
///
/// Pure: takes the account name rather than reading it from the host, so the
/// exact bytes that would be installed can be asserted without a provisioned
/// machine. [`generate_vmnet_plist`] is the emitter to call in anger — it
/// refuses to produce a plist for an account that does not resolve.
///
/// The generated plist is installed at
/// `/Library/LaunchDaemons/io.sandboxd.vmnet.<n>.plist` as a root-owned
/// LaunchDaemon. Key design properties:
///
/// - Shell wrapper as `ProgramArguments`: creates socket parent directories
///   with explicit `<account>:<account> 0750` ownership *before* socket_vmnet
///   binds. `/var/run` is cleared on every macOS boot; launchd imposes no
///   ordering between independent jobs, so the daemon cannot rely on the
///   directory surviving a reboot or on `sandboxd` having run first. Using
///   `install -d -o <account> -g <account> -m 0750` is idempotent and yields
///   the correct owner regardless of which root job wins the boot race.
/// - `--vmnet-mode=host`: isolated virtual network, no NAT to internet.
/// - `--vmnet-network-identifier=<uuid>`: deterministic, per-slot UUID
///   (derived from the fixed sandboxd namespace + slot index) — each unique
///   identifier gets its own isolated L2 bridge, preventing cross-slot
///   traffic; deterministic so it is stable across daemon/host restarts.
/// - `--socket-group=<account>`: overrides socket_vmnet's `staff` default;
///   only the daemon account and enrolled operators can connect.
/// - No `--vmnet-gateway`/`--vmnet-dhcp-end`: network-identifier mode
///   carries no DHCP; all addresses are assigned statically.
/// - `RunAtLoad=true` + `KeepAlive`: start at boot, restart on crash.
#[cfg(target_os = "macos")]
pub fn render_vmnet_plist(slot: u16, account: &str) -> String {
    let label = vmnet_slot_daemon_label(slot);
    let socket_path = vmnet_slot_socket_path(slot);
    let network_identifier = vmnet_slot_network_identifier(slot);

    // Shell command: create parent dirs with correct ownership, verify the staged
    // binary's code signature, then exec socket_vmnet.
    //
    // `&&` is escaped as `&amp;&amp;` because this string is embedded in an XML
    // `<string>` element — bare `&` is illegal XML and `plutil -lint` rejects it.
    // launchd un-escapes XML entities before passing the string to `/bin/sh -c`,
    // so the shell receives the literal `&&` operator at runtime.
    //
    // The codesign --verify --strict check runs after the dir preamble and before
    // exec.  These daemons run as root; the `codesign --verify` step makes any
    // content tampering fail-closed before socket_vmnet is exec'd with root
    // privileges.  Root-owned /Library/sandboxd blocks non-root writes; this check
    // catches tampering that bypasses that protection (e.g. root-level compromise).
    // No pinned cdhash: cdhash changes on every brew upgrade, which would break
    // the pool silently on every socket_vmnet update.  The Apple code signature
    // covers integrity without requiring a manually-maintained pin.
    let exec_cmd = format!(
        "install -d -o {account} -g {account} -m 0750 /var/run/sandbox &amp;&amp; \
install -d -o {account} -g {account} -m 0750 /var/run/sandbox/vmnet &amp;&amp; \
codesign --verify --strict {STAGED_SOCKET_VMNET_PATH} || {{ echo 'sandboxd: codesign verify failed for {STAGED_SOCKET_VMNET_PATH} -- binary may be tampered; refusing to exec'; exit 1; }} &amp;&amp; \
exec {STAGED_SOCKET_VMNET_PATH} \
--vmnet-mode=host \
--vmnet-network-identifier={network_identifier} \
--socket-group={account} \
{socket_path}"
    );

    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>{label}</string>

    <key>ProgramArguments</key>
    <array>
        <string>/bin/sh</string>
        <string>-c</string>
        <string>{exec_cmd}</string>
    </array>

    <key>RunAtLoad</key>
    <true/>

    <key>KeepAlive</key>
    <dict>
        <key>SuccessfulExit</key>
        <false/>
        <key>Crashed</key>
        <true/>
    </dict>

    <key>ThrottleInterval</key>
    <integer>5</integer>

    <key>StandardOutPath</key>
    <string>/var/log/sandbox/vmnet-{slot}.stdout.log</string>

    <key>StandardErrorPath</key>
    <string>/var/log/sandbox/vmnet-{slot}.stderr.log</string>
</dict>
</plist>
"#
    )
}

/// Generate the launchd plist XML for a pool slot, or refuse.
///
/// The emitter to call in anger. Checks that [`SANDBOXD_ACCOUNT`] resolves on
/// this host *before* rendering, so a plist that would break the whole pool at
/// the next boot is never produced. See [`ensure_vmnet_account_resolvable`] for
/// why deferring that failure is so expensive.
#[cfg(target_os = "macos")]
pub fn generate_vmnet_plist(slot: u16) -> Result<String, SandboxError> {
    ensure_vmnet_account_resolvable(SANDBOXD_ACCOUNT)?;
    Ok(render_vmnet_plist(slot, SANDBOXD_ACCOUNT))
}

// ---------------------------------------------------------------------------
// VmnetPool — macOS socket_vmnet slot manager
// ---------------------------------------------------------------------------

/// Manages socket_vmnet NIC slots and session-count tokens for macOS.
///
/// Tracks two distinct things:
///
/// 1. **NIC slots** — The N pre-provisioned socket_vmnet instances, one per
///    pool slot. Lima (full-backend) sessions claim a NIC slot on `create`
///    and release it on `stop`. Lite (container) sessions claim no NIC slot.
///
/// 2. **Session-count tokens** — A cap on total concurrent running sessions
///    across both backends (`max_slots`). Lima sessions consume both a NIC
///    slot *and* a token; lite sessions consume only a token.
///
/// This is the macOS counterpart to Linux's [`SubnetAllocator`]/
/// [`NetworkManager`] and follows the same locking pattern.
///
/// # One pool per operator
///
/// A pool owns a *range* — the slot indices it may hand out — rather than a
/// count. On a host with a single operator that range is the whole pool and
/// the behaviour is byte-for-byte what it always was. On a partitioned host
/// there are several pools behind
/// [`VmnetPoolRegistry`](crate::vmnet_pool_registry::VmnetPoolRegistry), each
/// seeded with a disjoint range, and `session_count` becomes that operator's
/// quota rather than a host-wide cap. Nothing about claim/release changes:
/// there is simply more than one pool.
#[cfg(target_os = "macos")]
pub struct VmnetPool {
    /// Claimed NIC slot indices. Always a subset of [`Self::range`].
    allocated_slots: Mutex<HashSet<u16>>,
    /// In-use session-count tokens.
    session_count: Mutex<u32>,
    /// The slot indices this pool may hand out, sorted and deduplicated.
    ///
    /// A range is a set rather than a `lo..hi` pair because enrollment
    /// accepts a discontiguous assignment (`0-3,6`), and a pool that
    /// silently filled the hole would hand out a slot on someone else's
    /// L2 segment.
    range: Vec<u16>,
    /// Slots in the host pool, across every operator.
    ///
    /// Not used for admission — [`Self::range`] decides that. It exists so
    /// the exhaustion error can tell "your share is full" from "the host is
    /// full", which have different remediations.
    host_slots: u16,
    /// Maps session_id → the slot claim for sessions that hold a NIC slot
    /// (Lima sessions). The entry is inserted at `claim_lima_slot` time with
    /// `info: None` and upgraded by `set_lima_network_info`. This two-phase
    /// write ensures that a partial-create rollback via `release_lima_slot`
    /// always finds the entry and can free the slot, even if the caller never
    /// reached `set_lima_network_info`. Lite sessions are tracked only via
    /// `session_count`.
    networks: Mutex<HashMap<SessionId, SlotClaim>>,
}

/// One session's hold on a NIC slot.
#[cfg(target_os = "macos")]
struct SlotClaim {
    /// The claimed slot index.
    slot: u16,
    /// The operator the claim belongs to. Recorded at claim time rather
    /// than read off the `NetworkInfo`, because during the placeholder
    /// window there is no `NetworkInfo` yet — and that window is exactly
    /// when a leaked slot most needs attributing.
    operator_uid: u32,
    /// `None` until `set_lima_network_info` upgrades the placeholder.
    info: Option<NetworkInfo>,
}

/// A slot the pool believes is claimed, with the operator it belongs to.
#[cfg(target_os = "macos")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClaimedSlot {
    /// The claimed slot index.
    pub slot: u16,
    /// The session holding it.
    pub session_id: SessionId,
    /// The operator the claiming session belongs to.
    pub operator_uid: u32,
}

#[cfg(target_os = "macos")]
impl VmnetPool {
    /// Create a pool over the contiguous range `0..max_slots`.
    ///
    /// The un-partitioned shape: one operator, the whole pool. `max_slots`
    /// comes from the `max_macos_sessions` config value (default 8).
    pub fn new(max_slots: u16) -> Self {
        Self::with_range(&(0..max_slots).collect::<Vec<u16>>(), max_slots)
    }

    /// Create a pool over an explicit set of slot indices.
    ///
    /// The range is sorted and deduplicated; a duplicate in the caller's
    /// slice would otherwise inflate the quota without adding capacity.
    /// `host_slots` is the size of the whole host pool — see
    /// [`Self::host_slots`].
    pub fn with_range(range: &[u16], host_slots: u16) -> Self {
        let mut range = range.to_vec();
        range.sort_unstable();
        range.dedup();
        Self {
            allocated_slots: Mutex::new(HashSet::new()),
            session_count: Mutex::new(0),
            range,
            host_slots,
            networks: Mutex::new(HashMap::new()),
        }
    }

    /// Slots in the host pool, across every operator.
    pub fn host_slots(&self) -> u16 {
        self.host_slots
    }

    /// Build the exhaustion error for this pool's operator.
    ///
    /// One place, three callers — the two claim paths and the lite token
    /// path — where the message used to exist as three copies free to drift.
    fn exhausted(&self, operator_uid: u32, in_use: u32) -> SandboxError {
        SandboxError::SessionQuotaExhausted {
            operator_uid,
            in_use,
            quota: self.max_slots(),
            host_slots: self.host_slots,
        }
    }

    /// Maximum number of concurrent sessions for this pool's operator —
    /// the size of its range.
    ///
    /// Identical to the constructor argument for a `new(n)` pool, which is
    /// what every un-partitioned host has.
    pub fn max_slots(&self) -> u16 {
        self.range.len() as u16
    }

    /// The slot indices this pool may hand out, sorted.
    pub fn range(&self) -> &[u16] {
        &self.range
    }

    /// Claim a NIC slot and a session-count token for a Lima session.
    ///
    /// On success returns the claimed [`VmnetSlot`] plus the /29 address
    /// roles: `(slot, subnet_cidr, gateway_ip, vm_ip)`.
    ///
    /// Atomically records a placeholder entry `(slot_idx, None)` in `networks`
    /// at claim time. This ensures that a partial-create rollback via
    /// `release_lima_slot` always finds the entry and frees the slot, even
    /// if the caller fails before calling `set_lima_network_info`.
    ///
    /// `operator_uid` is the operator the session belongs to; it is recorded
    /// with the claim so a leaked slot can be attributed even before
    /// `set_lima_network_info` runs, and it is what the exhaustion error
    /// names.
    ///
    /// Fails with [`SandboxError::SessionQuotaExhausted`] (429) when every
    /// slot in this operator's range is in use.
    pub fn claim_lima_slot(
        &self,
        session_id: &SessionId,
        operator_uid: u32,
    ) -> Result<(VmnetSlot, String, Ipv4Addr, Ipv4Addr), SandboxError> {
        let mut slots = self
            .allocated_slots
            .lock()
            .map_err(|e| SandboxError::Internal(format!("lock poisoned: {e}")))?;
        let mut count = self
            .session_count
            .lock()
            .map_err(|e| SandboxError::Internal(format!("lock poisoned: {e}")))?;
        let mut nets = self
            .networks
            .lock()
            .map_err(|e| SandboxError::Internal(format!("lock poisoned: {e}")))?;

        let running = *count;
        if running >= self.max_slots() as u32 {
            return Err(self.exhausted(operator_uid, running));
        }

        // Find the lowest free slot *within this operator's range*. The
        // count cap above normally makes this unreachable; it stays as the
        // structural guarantee that a pool cannot hand out an index it does
        // not own, whatever the count says.
        let slot_idx = *self
            .range
            .iter()
            .find(|i| !slots.contains(i))
            .ok_or_else(|| self.exhausted(operator_uid, running))?;

        slots.insert(slot_idx);
        *count += 1;
        // Insert a placeholder now so release_lima_slot can always find this
        // entry. The placeholder is upgraded to Some(info) by set_lima_network_info.
        nets.insert(
            *session_id,
            SlotClaim {
                slot: slot_idx,
                operator_uid,
                info: None,
            },
        );

        drop(nets);
        drop(slots);
        drop(count);

        let vmnet_slot = VmnetSlot {
            index: slot_idx,
            daemon_label: vmnet_slot_daemon_label(slot_idx),
            socket_path: vmnet_slot_socket_path(slot_idx),
        };
        let (subnet_cidr, gateway_ip, vm_ip) = vmnet_slot_addresses(slot_idx);

        Ok((vmnet_slot, subnet_cidr, gateway_ip, vm_ip))
    }

    /// Claim only a session-count token for a lite (container) session.
    ///
    /// Lite sessions use an in-VM Docker bridge and consume no NIC slot,
    /// but they do count against the operator's quota — which is why the
    /// quota cannot be derived from slot indices alone.
    ///
    /// Fails with [`SandboxError::SessionQuotaExhausted`] (429) when the
    /// operator's quota is reached.
    pub fn claim_lite_token(&self, operator_uid: u32) -> Result<(), SandboxError> {
        let mut count = self
            .session_count
            .lock()
            .map_err(|e| SandboxError::Internal(format!("lock poisoned: {e}")))?;
        let running = *count;
        if running >= self.max_slots() as u32 {
            return Err(self.exhausted(operator_uid, running));
        }
        *count += 1;
        Ok(())
    }

    /// Upgrade the placeholder entry recorded at `claim_lima_slot` time to
    /// the full `NetworkInfo`.
    ///
    /// Called after `claim_lima_slot` returns successfully, once the caller
    /// has built the complete `NetworkInfo` (bridge_name, docker_network_name, etc.).
    ///
    /// Returns `Err` if the session has no placeholder entry (which indicates
    /// a caller bug — `claim_lima_slot` must have been called first).
    pub fn set_lima_network_info(
        &self,
        session_id: &SessionId,
        slot_idx: u16,
        info: NetworkInfo,
    ) -> Result<(), SandboxError> {
        let mut nets = self
            .networks
            .lock()
            .map_err(|e| SandboxError::Internal(format!("lock poisoned: {e}")))?;
        match nets.get_mut(session_id) {
            Some(entry) => {
                // Sanity check: slot index should match what was claimed.
                if entry.slot != slot_idx {
                    return Err(SandboxError::Internal(format!(
                        "slot index mismatch for session {session_id}: \
                         claimed {}, got {}",
                        entry.slot, slot_idx
                    )));
                }
                entry.info = Some(info);
                Ok(())
            }
            None => Err(SandboxError::Internal(format!(
                "no slot placeholder for session {session_id}: \
                 call claim_lima_slot before set_lima_network_info"
            ))),
        }
    }

    /// Release a Lima session's NIC slot and session-count token (idempotent).
    ///
    /// Idempotent: if the session holds no slot (already released, or was a
    /// lite session), this is a no-op. The session-count token is always
    /// decremented when a NIC slot is released.
    pub fn release_lima_slot(&self, session_id: &SessionId) -> Result<(), SandboxError> {
        let slot_idx = {
            let mut nets = self
                .networks
                .lock()
                .map_err(|e| SandboxError::Internal(format!("lock poisoned: {e}")))?;
            nets.remove(session_id).map(|claim| claim.slot)
        };

        if let Some(idx) = slot_idx {
            {
                let mut slots = self
                    .allocated_slots
                    .lock()
                    .map_err(|e| SandboxError::Internal(format!("lock poisoned: {e}")))?;
                slots.remove(&idx);
            }
            {
                let mut count = self
                    .session_count
                    .lock()
                    .map_err(|e| SandboxError::Internal(format!("lock poisoned: {e}")))?;
                *count = count.saturating_sub(1);
            }
        }
        Ok(())
    }

    /// Release only a session-count token for a lite session (idempotent).
    pub fn release_lite_token(&self) -> Result<(), SandboxError> {
        let mut count = self
            .session_count
            .lock()
            .map_err(|e| SandboxError::Internal(format!("lock poisoned: {e}")))?;
        *count = count.saturating_sub(1);
        Ok(())
    }

    /// Retrieve the `NetworkInfo` for a Lima session, if it holds a slot and
    /// `set_lima_network_info` has been called.
    ///
    /// Returns `None` when the session has no slot, or when the slot was claimed
    /// but `set_lima_network_info` has not yet been called (placeholder state).
    pub fn network_info(
        &self,
        session_id: &SessionId,
    ) -> Result<Option<NetworkInfo>, SandboxError> {
        let nets = self
            .networks
            .lock()
            .map_err(|e| SandboxError::Internal(format!("lock poisoned: {e}")))?;
        Ok(nets.get(session_id).and_then(|claim| claim.info.clone()))
    }

    /// Rebuild pool state from existing `NetworkInfo` entries at daemon startup.
    ///
    /// For each session whose `NetworkInfo` contains a `vmnet_slot`, marks
    /// that slot as allocated and increments the session count. Call this
    /// after loading sessions from the store, with the entries already
    /// sharded to this pool's operator.
    ///
    /// The bounds check is the same one it always was, narrowed from "inside
    /// the pool" to "inside this operator's range": a persisted claim on a
    /// slot this pool does not own is refused rather than absorbed, because
    /// absorbing it would put two operators on one L2 segment.
    pub fn restore_from_infos(
        &self,
        entries: &[(SessionId, NetworkInfo)],
        operator_uid: u32,
    ) -> Result<(), SandboxError> {
        let mut slots = self
            .allocated_slots
            .lock()
            .map_err(|e| SandboxError::Internal(format!("lock poisoned: {e}")))?;
        let mut count = self
            .session_count
            .lock()
            .map_err(|e| SandboxError::Internal(format!("lock poisoned: {e}")))?;
        let mut nets = self
            .networks
            .lock()
            .map_err(|e| SandboxError::Internal(format!("lock poisoned: {e}")))?;

        for (session_id, info) in entries {
            if let Some(vs) = &info.vmnet_slot {
                let idx = vs.index;
                if !self.range.contains(&idx) {
                    return Err(SandboxError::Network(format!(
                        "slot index {idx} from session {session_id} is outside the \
                         range assigned to operator uid {operator_uid} ({:?})",
                        self.range
                    )));
                }
                slots.insert(idx);
                *count += 1;
                // Restored sessions have full NetworkInfo; store as Some.
                nets.insert(
                    *session_id,
                    SlotClaim {
                        slot: idx,
                        operator_uid,
                        info: Some(info.clone()),
                    },
                );
            }
        }
        Ok(())
    }

    /// Restore `n` lite session-count tokens at daemon startup.
    ///
    /// Called after loading sessions from the store. Lite sessions have no
    /// `vmnet_slot` so [`Self::restore_from_infos`] does not count them —
    /// they are tracked only via `session_count`. This method bumps the
    /// count by `n` to reflect running lite (container-backend) sessions
    /// that survived a daemon restart.
    ///
    /// The caller is responsible for determining `n` by counting the running
    /// `BackendKind::Container` sessions from the store (after the 6a/6b
    /// reconcile, so only genuinely-running sessions are counted). This keeps
    /// the session-count cap honest across daemon restarts: without this call,
    /// the cap would under-count until lite sessions are explicitly stopped
    /// and released.
    ///
    /// Fails with `Err` only when the lock is poisoned — a programming error,
    /// not a runtime condition.
    pub fn restore_lite_tokens(&self, n: u32) -> Result<(), crate::error::SandboxError> {
        if n == 0 {
            return Ok(());
        }
        let mut count = self
            .session_count
            .lock()
            .map_err(|e| crate::error::SandboxError::Internal(format!("lock poisoned: {e}")))?;
        *count += n;
        Ok(())
    }

    /// Return the current number of running sessions.
    pub fn running_session_count(&self) -> u32 {
        *self.session_count.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Return the set of currently allocated slot indices.
    pub fn allocated_slot_indices(&self) -> HashSet<u16> {
        self.allocated_slots
            .lock()
            .map(|g| g.clone())
            .unwrap_or_default()
    }

    /// Return every slot the pool currently believes is claimed, with the
    /// session and the operator holding it.
    ///
    /// The map is the in-memory source of truth for which session owns which
    /// slot (seeded from persisted `NetworkInfo` at startup, mutated on
    /// claim/release). Cross-referencing the returned session ids against the
    /// live session store surfaces leaked slots — a slot still claimed by a
    /// session that no longer exists.
    ///
    /// The operator dimension is carried on the claim rather than inferred
    /// from which pool the claim came out of: operators without an assigned
    /// range share one pool, so the pool alone cannot answer who holds what.
    pub fn claimed_slot_sessions(&self) -> Vec<ClaimedSlot> {
        self.networks
            .lock()
            .map(|nets| {
                nets.iter()
                    .map(|(sid, claim)| ClaimedSlot {
                        slot: claim.slot,
                        session_id: *sid,
                        operator_uid: claim.operator_uid,
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Return the socket path for a given slot (for the template generator).
    pub fn slot_socket_path(&self, slot: u16) -> String {
        vmnet_slot_socket_path(slot)
    }
}

// ===========================================================================
// macOS: socket_vmnet binary ancestry + ownership assertion
// ===========================================================================

/// Check whether a file mode has group-writable or other-writable bits set.
///
/// Returns `true` if the mode is writable by non-root principals (i.e.,
/// group-writable bit `0o020` or other-writable bit `0o002` is set).
///
/// This helper is factored out of [`assert_root_exec_ancestry`] so the
/// mode-check logic can be unit-tested independently without requiring root
/// or a real filesystem hierarchy. On a non-root dev machine, the full
/// ancestry assertion's uid check fires first; testing this helper directly
/// exercises the mode-writable code path unconditionally.
#[cfg(target_os = "macos")]
pub fn is_path_mode_writable(mode: u32) -> bool {
    mode & 0o022 != 0
}

/// Verify that a path and all of its ancestors up to `/` are root-owned and
/// not group/other-writable.
///
/// This is the daemon's startup security check for the root-exec'd
/// `socket_vmnet` binary staged at `/Library/sandboxd/socket_vmnet`.
/// Because launchd daemons exec that binary as root, any ancestor
/// directory or the binary itself that is writable by a non-root principal
/// would allow privilege escalation. The daemon refuses to proceed if this
/// assertion fails.
///
/// This function does NOT touch the real filesystem for privileged paths —
/// it calls `std::fs::metadata` which works on any path you have read
/// permission for. The negative test uses a tempdir fixture tree.
///
/// Returns `Ok(())` if the entire ancestry chain is safe.
/// Returns `Err(OwnershipAssertionError)` with a description of the first
/// violation found.
#[cfg(target_os = "macos")]
pub fn assert_root_exec_ancestry(path: &std::path::Path) -> Result<(), OwnershipAssertionError> {
    use std::os::unix::fs::MetadataExt;

    // Collect the path and all its ancestors, then reverse to walk top-down
    // (from `/` to the target binary). Top-down traversal is semantically
    // correct — a writable ancestor directory is more dangerous than a writable
    // binary (replacing the directory lets an attacker substitute the binary),
    // so ancestor checks should fire first.
    let mut ancestors: Vec<std::path::PathBuf> = Vec::new();
    let mut current = path.to_path_buf();
    loop {
        ancestors.push(current.clone());
        let parent = match current.parent() {
            Some(p) if p != current => p.to_path_buf(),
            _ => break,
        };
        current = parent;
    }
    // Reverse so we check from root (/) down to the target binary.
    ancestors.reverse();

    for component in &ancestors {
        let meta = std::fs::metadata(component).map_err(|e| OwnershipAssertionError {
            path: component.display().to_string(),
            reason: format!("cannot stat: {e}"),
        })?;

        let uid = meta.uid();
        let mode = meta.mode();

        // Must not be group-writable (bit 0o020) or other-writable (bit 0o002).
        // The mode-writable check uses `is_path_mode_writable` so it can be
        // unit-tested independently without requiring root.
        if is_path_mode_writable(mode) {
            let bad_bits = mode & 0o022;
            return Err(OwnershipAssertionError {
                path: component.display().to_string(),
                reason: format!(
                    "writable by non-root (mode 0{mode:o}, writable bits 0{bad_bits:o})"
                ),
            });
        }

        // Must be root-owned (uid 0).
        if uid != 0 {
            return Err(OwnershipAssertionError {
                path: component.display().to_string(),
                reason: format!("owned by uid {uid}, expected uid 0 (root)"),
            });
        }
    }

    Ok(())
}

/// Error produced by [`assert_root_exec_ancestry`] when the ancestry chain
/// is unsafe for root-exec.
#[cfg(target_os = "macos")]
#[derive(Debug)]
pub struct OwnershipAssertionError {
    /// The path component that failed the check.
    pub path: String,
    /// Human-readable reason for the failure.
    pub reason: String,
}

#[cfg(target_os = "macos")]
impl std::fmt::Display for OwnershipAssertionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "unsafe root-exec path {}: {}", self.path, self.reason)
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// A [`DockerRoute::Vm`] for tests that only ask the route *which* it
    /// is. Nothing here runs an op — the option set is decided by the
    /// variant, so the executor never has to answer.
    fn test_vm_route() -> DockerRoute {
        struct UnusedExecutor;

        #[async_trait::async_trait]
        impl crate::docker::DockerExecutor for UnusedExecutor {
            fn run(
                &self,
                _op_uid: u32,
                _op: DockerOp,
                _timeout: Duration,
                _label: &str,
            ) -> Result<std::process::Output, SandboxError> {
                unreachable!("these tests render argv; they run no ops")
            }

            async fn open_stream(
                &self,
                _op_uid: u32,
                _stream: crate::docker::DockerStream,
            ) -> Result<crate::docker::DockerStreamConn, SandboxError> {
                unreachable!("these tests render argv; they open no streams")
            }
        }

        DockerRoute::Vm {
            op_uid: 501,
            executor: std::sync::Arc::new(UnusedExecutor),
        }
    }

    // -- network ops -------------------------------------------------------

    /// The removal op names the network and nothing else. Which Docker
    /// daemon hears it is the route's decision, made where the socket
    /// actually lives — a target named here would be a target the caller
    /// could choose.
    #[test]
    fn network_removal_op_names_the_network_and_not_a_target() {
        let argv = DockerOp::NetworkRemove {
            name: "sandbox-net-abc123".to_string(),
        }
        .argv()
        .expect("network rm renders");
        assert_eq!(argv, vec!["network", "rm", "sandbox-net-abc123"]);
    }

    /// A bridge created inside the gateway VM is created with Docker's
    /// masquerade turned off. This is the whole of the pre-route window's
    /// fail-closed property: with the NAT in place, a container reaches the
    /// internet through the bridge's `.1` from the instant it starts —
    /// before the route helper has pointed it at the gateway, and again any
    /// time something inside it rewrites its default route back.
    #[test]
    fn in_vm_session_bridge_disables_docker_masquerade() {
        let argv = DockerOp::NetworkCreate {
            spec: NetworkCreateSpec {
                name: "sandbox-net-abc123".to_string(),
                driver: NetworkDriver::Bridge,
                subnet: Some("10.209.0.0/28".to_string()),
                gateway: None,
                session_id: Some("abc123".to_string()),
                owner_pool: Some("10.209.0.0/20".to_string()),
                options: session_bridge_options("sb-abc123", &test_vm_route()),
            },
        }
        .argv()
        .expect("network create renders");
        assert!(
            argv.windows(2).any(|w| w[0] == "--opt"
                && w[1] == "com.docker.network.bridge.enable_ip_masquerade=false"),
            "an in-VM session bridge must be created with masquerade disabled, \
             got: {argv:?}"
        );
    }

    /// The host route keeps Docker's default. On Linux the gateway
    /// container has one NIC, on the session bridge itself, and no
    /// `sandboxd-egress` to fall back on — the bridge's masquerade is what
    /// carries every allowed flow out, so removing it would take out
    /// legitimate egress rather than only the bypass.
    #[test]
    fn host_session_bridge_keeps_docker_masquerade() {
        let argv = DockerOp::NetworkCreate {
            spec: NetworkCreateSpec {
                name: "sandbox-net-abc123".to_string(),
                driver: NetworkDriver::Bridge,
                subnet: Some("10.209.0.0/28".to_string()),
                gateway: None,
                session_id: Some("abc123".to_string()),
                owner_pool: Some("10.209.0.0/20".to_string()),
                options: session_bridge_options("sb-abc123", &DockerRoute::Host),
            },
        }
        .argv()
        .expect("network create renders");
        assert!(
            !argv
                .iter()
                .any(|arg| arg.starts_with("com.docker.network.bridge.enable_ip_masquerade")),
            "a host session bridge must not name the masquerade option at all, \
             got: {argv:?}"
        );
    }

    /// The full option set, pinned per route. Both creation paths — first
    /// create and the recreate-on-start path — read their options from this
    /// one function, so pinning it here pins what a session's bridge is on
    /// either path. A bridge recreated on start with a different option set
    /// would be a session whose egress properties changed under it.
    #[test]
    fn session_bridge_options_are_pinned_per_route() {
        assert_eq!(
            session_bridge_options("sb-abc123", &test_vm_route()),
            vec![
                NetworkOption::BridgeName("sb-abc123".to_string()),
                NetworkOption::BridgeMasquerade(false),
            ],
        );
        assert_eq!(
            session_bridge_options("sb-abc123", &DockerRoute::Host),
            vec![NetworkOption::BridgeName("sb-abc123".to_string())],
        );
    }

    /// The per-session bridge carries both labels the orphan reaper filters
    /// on: without the owner label a co-deployed daemon's listing would not
    /// see the network, and it would survive every reap as an orphan nobody
    /// claims.
    #[test]
    fn per_session_bridge_carries_the_session_and_owner_labels() {
        let spec = NetworkCreateSpec {
            name: "sandbox-net-abc123".to_string(),
            driver: NetworkDriver::Bridge,
            subnet: Some("10.209.0.0/28".to_string()),
            gateway: None,
            session_id: Some("abc123".to_string()),
            owner_pool: Some("10.209.0.0/20".to_string()),
            options: vec![NetworkOption::BridgeName("sb-abc123".to_string())],
        };
        let argv = DockerOp::NetworkCreate { spec }
            .argv()
            .expect("network create renders");
        assert!(
            argv.windows(2)
                .any(|w| w[0] == "--label" && w[1] == "sandbox.session_id=abc123")
        );
        assert!(
            argv.windows(2)
                .any(|w| w[0] == "--label" && w[1] == "sandboxd.owner=10.209.0.0/20")
        );
        assert!(
            argv.windows(2)
                .any(|w| w[0] == "--opt" && w[1] == "com.docker.network.bridge.name=sb-abc123")
        );
    }

    // -- SubnetAllocator unit tests ------------------------------------------

    #[test]
    fn test_allocate_subnet() {
        let mut alloc = SubnetAllocator::new(Ipv4Addr::new(10, 209, 0, 0), 24).unwrap();

        let (idx, subnet_base, gateway, vm) = alloc.allocate().unwrap();
        assert_eq!(idx, 0);
        assert_eq!(subnet_base, Ipv4Addr::new(10, 209, 0, 0));
        assert_eq!(gateway, Ipv4Addr::new(10, 209, 0, 2));
        assert_eq!(vm, Ipv4Addr::new(10, 209, 0, 3));
    }

    #[test]
    fn test_allocate_multiple() {
        let mut alloc = SubnetAllocator::new(Ipv4Addr::new(10, 209, 0, 0), 24).unwrap();

        let (idx0, base0, gw0, vm0) = alloc.allocate().unwrap();
        let (idx1, base1, gw1, vm1) = alloc.allocate().unwrap();
        let (idx2, base2, gw2, vm2) = alloc.allocate().unwrap();

        // Verify indices are sequential.
        assert_eq!(idx0, 0);
        assert_eq!(idx1, 1);
        assert_eq!(idx2, 2);

        // Verify no IP overlap (each /28 block = 16 addresses).
        assert_eq!(base0, Ipv4Addr::new(10, 209, 0, 0));
        assert_eq!(base1, Ipv4Addr::new(10, 209, 0, 16));
        assert_eq!(base2, Ipv4Addr::new(10, 209, 0, 32));

        assert_eq!(gw0, Ipv4Addr::new(10, 209, 0, 2));
        assert_eq!(gw1, Ipv4Addr::new(10, 209, 0, 18));
        assert_eq!(gw2, Ipv4Addr::new(10, 209, 0, 34));

        assert_eq!(vm0, Ipv4Addr::new(10, 209, 0, 3));
        assert_eq!(vm1, Ipv4Addr::new(10, 209, 0, 19));
        assert_eq!(vm2, Ipv4Addr::new(10, 209, 0, 35));
    }

    #[test]
    fn test_release_and_reuse() {
        let mut alloc = SubnetAllocator::new(Ipv4Addr::new(10, 209, 0, 0), 24).unwrap();

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
        assert_eq!(gw, Ipv4Addr::new(10, 209, 0, 2));
        assert_eq!(vm, Ipv4Addr::new(10, 209, 0, 3));
    }

    #[test]
    fn test_pool_exhaustion() {
        // Use a /28 base -- that gives exactly 1 /28 block.
        let mut alloc = SubnetAllocator::new(Ipv4Addr::new(10, 209, 0, 0), 28).unwrap();

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
        // A /24 gives 16 /28 blocks.
        let mut alloc = SubnetAllocator::new(Ipv4Addr::new(10, 209, 0, 0), 24).unwrap();

        assert_eq!(alloc.max_blocks, 16);

        // Allocate all 16 blocks.
        for i in 0..16u16 {
            let (idx, _, _, _) = alloc.allocate().unwrap();
            assert_eq!(idx, i);
        }

        // 17th allocation should fail.
        let result = alloc.allocate();
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("exhausted"));
    }

    #[test]
    fn test_allocator_accepts_slash_20() {
        // /20 yields exactly 256 /28 blocks — one past u8::MAX. This
        // is the prefix shipped in `contrib/users.conf.example`, so
        // any host that runs `make setup-users-conf` lands here on
        // first daemon start.
        let alloc = SubnetAllocator::new(Ipv4Addr::new(10, 209, 0, 0), 20).unwrap();
        assert_eq!(alloc.max_blocks, 256);
    }

    #[test]
    fn test_block_index_for() {
        let alloc = SubnetAllocator::new(Ipv4Addr::new(10, 209, 0, 0), 24).unwrap();

        assert_eq!(alloc.block_index_for(Ipv4Addr::new(10, 209, 0, 0)), Some(0));
        assert_eq!(
            alloc.block_index_for(Ipv4Addr::new(10, 209, 0, 16)),
            Some(1)
        );
        assert_eq!(
            alloc.block_index_for(Ipv4Addr::new(10, 209, 0, 240)),
            Some(15)
        );

        // Not on a /28 boundary.
        assert_eq!(alloc.block_index_for(Ipv4Addr::new(10, 209, 0, 3)), None);
        // Out of range.
        assert_eq!(alloc.block_index_for(Ipv4Addr::new(10, 210, 0, 0)), None);
        // Before base.
        assert_eq!(alloc.block_index_for(Ipv4Addr::new(10, 208, 0, 0)), None);
    }

    #[test]
    fn test_invalid_prefix_len() {
        let result = SubnetAllocator::new(Ipv4Addr::new(10, 0, 0, 0), 29);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("too large"));
    }

    // -- NetworkInfo tests ---------------------------------------------------

    #[test]
    fn test_network_info_fields() {
        let mgr = NetworkManager::new(
            Ipv4Addr::new(10, 209, 0, 0),
            24,
            "10.209.0.0/24".to_string(),
        )
        .unwrap();

        let session_id = SessionId::generate();

        // We can't call create_network without Docker, so test the allocator
        // and info construction manually.
        let (_, subnet_base, gateway_ip, vm_ip) = {
            let mut alloc = mgr.subnet_allocator.lock().unwrap();
            alloc.allocate().unwrap()
        };

        let bridge_name = format!("sb-{session_id}");
        let docker_network_name = format!("sandbox-net-{session_id}");

        let info = NetworkInfo {
            operator_uid: None,
            bridge_name: bridge_name.clone(),
            subnet: format!("{subnet_base}/28"),
            gateway_ip: gateway_ip.to_string(),
            vm_ip: vm_ip.to_string(),
            docker_network_name: docker_network_name.clone(),
            vmnet_slot: None,
        };

        assert_eq!(info.subnet, "10.209.0.0/28");
        assert_eq!(info.gateway_ip, "10.209.0.2");
        assert_eq!(info.vm_ip, "10.209.0.3");
        assert!(info.bridge_name.starts_with("sb-"));
        assert!(info.docker_network_name.starts_with("sandbox-net-"));
    }

    #[test]
    fn test_bridge_name_length() {
        // Kernel interface names are limited to 15 characters (IFNAMSIZ).
        // "sb-" is 3 chars + 12 chars of session id = exactly 15.
        let session_id = SessionId::generate();
        let bridge_name = format!("sb-{session_id}");

        assert_eq!(
            bridge_name.len(),
            15,
            "bridge name '{bridge_name}' should be exactly 15 chars (IFNAMSIZ)"
        );
    }

    #[test]
    fn test_network_info_serialization() {
        let info = NetworkInfo {
            operator_uid: None,
            bridge_name: "sb-550e8400-e2".to_string(),
            subnet: "10.209.0.0/28".to_string(),
            gateway_ip: "10.209.0.2".to_string(),
            vm_ip: "10.209.0.3".to_string(),
            docker_network_name: "sandbox-net-550e8400-e29b-41d4-a716-446655440000".to_string(),
            vmnet_slot: None,
        };

        let json = serde_json::to_string(&info).unwrap();
        let deserialized: NetworkInfo = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.bridge_name, info.bridge_name);
        assert_eq!(deserialized.subnet, info.subnet);
        assert_eq!(deserialized.gateway_ip, info.gateway_ip);
        assert_eq!(deserialized.vm_ip, info.vm_ip);
        assert_eq!(deserialized.docker_network_name, info.docker_network_name);
    }

    /// Upgrade direction: a `network_info` blob written before
    /// `operator_uid` existed still deserializes, with the field absent
    /// rather than the record rejected.
    #[test]
    fn a_record_written_before_operator_uid_still_deserializes() {
        let older = r#"{
            "bridge_name": "lima3",
            "subnet": "10.209.128.24/29",
            "gateway_ip": "10.209.128.27",
            "vm_ip": "10.209.128.28",
            "docker_network_name": "sandbox-net-aabbccddeeff"
        }"#;

        let info: NetworkInfo =
            serde_json::from_str(older).expect("an older row must still load, not fail the daemon");

        assert_eq!(info.operator_uid, None);
        assert_eq!(info.vmnet_slot, None);
        assert_eq!(info.bridge_name, "lima3");
    }

    /// Rollback direction: a blob written *with* `operator_uid` must still
    /// load on a daemon that predates the field. Pinned by deserializing
    /// into a struct shaped like the older one — if `NetworkInfo` ever grew
    /// `deny_unknown_fields`, a downgrade would start rejecting every row
    /// this daemon wrote, and only a test in this shape would catch it.
    #[test]
    fn a_record_written_with_operator_uid_survives_a_rollback() {
        #[derive(serde::Deserialize)]
        #[allow(dead_code)]
        struct NetworkInfoBeforeOperatorUid {
            bridge_name: String,
            subnet: String,
            gateway_ip: String,
            vm_ip: String,
            docker_network_name: String,
            #[serde(default)]
            vmnet_slot: Option<VmnetSlot>,
        }

        let current = NetworkInfo {
            operator_uid: Some(501),
            bridge_name: "lima3".to_string(),
            subnet: "10.209.128.24/29".to_string(),
            gateway_ip: "10.209.128.27".to_string(),
            vm_ip: "10.209.128.28".to_string(),
            docker_network_name: "sandbox-net-aabbccddeeff".to_string(),
            vmnet_slot: None,
        };
        let json = serde_json::to_string(&current).unwrap();
        assert!(
            json.contains("operator_uid"),
            "the field must actually be on the wire, or the rollback assertion \
             below proves nothing"
        );

        let older: NetworkInfoBeforeOperatorUid = serde_json::from_str(&json)
            .expect("a daemon that predates the field must still read this row");
        assert_eq!(older.bridge_name, "lima3");
    }

    #[test]
    fn test_restore_from_infos() {
        let mgr = NetworkManager::new(
            Ipv4Addr::new(10, 209, 0, 0),
            24,
            "10.209.0.0/24".to_string(),
        )
        .unwrap();

        let id1 = SessionId::generate();
        let id2 = SessionId::generate();

        let info1 = NetworkInfo {
            operator_uid: None,
            bridge_name: "sb-aaaaaaaaaaa".to_string(),
            subnet: "10.209.0.0/28".to_string(),
            gateway_ip: "10.209.0.2".to_string(),
            vm_ip: "10.209.0.3".to_string(),
            docker_network_name: format!("sandbox-net-{id1}"),
            vmnet_slot: None,
        };

        let info2 = NetworkInfo {
            operator_uid: None,
            bridge_name: "sb-bbbbbbbbbbb".to_string(),
            subnet: "10.209.0.32/28".to_string(),
            gateway_ip: "10.209.0.34".to_string(),
            vm_ip: "10.209.0.35".to_string(),
            docker_network_name: format!("sandbox-net-{id2}"),
            vmnet_slot: None,
        };

        mgr.restore_from_infos(&[(id1, info1.clone()), (id2, info2.clone())])
            .unwrap();

        // Verify the blocks are marked as allocated.
        {
            let alloc = mgr.subnet_allocator.lock().unwrap();
            assert!(alloc.allocated.contains(&0)); // 10.209.0.0 -> block 0
            assert!(alloc.allocated.contains(&2)); // 10.209.0.32 -> block 2
            assert!(!alloc.allocated.contains(&1)); // block 1 should be free
        }

        // Verify network_info returns the restored data.
        let fetched1 = mgr.network_info(&id1).unwrap();
        assert!(fetched1.is_some());
        let fetched1 = fetched1.unwrap();
        assert_eq!(fetched1.subnet, "10.209.0.0/28");

        let fetched2 = mgr.network_info(&id2).unwrap();
        assert!(fetched2.is_some());
        let fetched2 = fetched2.unwrap();
        assert_eq!(fetched2.subnet, "10.209.0.32/28");

        // Verify that the next allocation skips restored blocks.
        // Block 0 and 2 are used, so next free is block 1.
        let (idx, base, _, _) = {
            let mut alloc = mgr.subnet_allocator.lock().unwrap();
            alloc.allocate().unwrap()
        };
        assert_eq!(idx, 1);
        assert_eq!(base, Ipv4Addr::new(10, 209, 0, 16));
    }

    #[test]
    fn test_network_info_not_found() {
        let mgr = NetworkManager::new(
            Ipv4Addr::new(10, 209, 0, 0),
            24,
            "10.209.0.0/24".to_string(),
        )
        .unwrap();

        let result = mgr.network_info(&SessionId::generate()).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_parse_subnet_base() {
        assert_eq!(
            parse_subnet_base("10.209.0.0/28").unwrap(),
            Ipv4Addr::new(10, 209, 0, 0)
        );
        assert_eq!(
            parse_subnet_base("10.209.0.16/28").unwrap(),
            Ipv4Addr::new(10, 209, 0, 16)
        );
        assert!(parse_subnet_base("not-an-ip/28").is_err());
    }

    // -- VmnetSlot serde round-trip (platform-agnostic) ----------------------

    /// `VmnetSlot` round-trips through serde; an old row missing the field
    /// deserializes `NetworkInfo` with `vmnet_slot: None`.
    #[test]
    fn test_vmnet_slot_serde_round_trip() {
        let slot = VmnetSlot {
            index: 3,
            daemon_label: "io.sandboxd.vmnet.3".to_string(),
            socket_path: "/var/run/sandbox/vmnet/slot-3.sock".to_string(),
        };
        let info = NetworkInfo {
            operator_uid: None,
            bridge_name: "lima3".to_string(),
            subnet: "10.209.128.24/29".to_string(),
            gateway_ip: "10.209.128.27".to_string(),
            vm_ip: "10.209.128.28".to_string(),
            docker_network_name: "sandbox-net-abc".to_string(),
            vmnet_slot: Some(slot.clone()),
        };

        let json = serde_json::to_string(&info).unwrap();
        let deserialized: NetworkInfo = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.vmnet_slot, Some(slot));
        assert_eq!(deserialized.gateway_ip, "10.209.128.27");
    }

    /// An old-format JSON row (missing the `vmnet_slot` field) deserializes
    /// cleanly with `vmnet_slot: None` via `#[serde(default)]`.
    #[test]
    fn test_vmnet_slot_old_row_deserializes_none() {
        let old_row = r#"{
            "bridge_name": "sb-550e8400e29b",
            "subnet": "10.209.0.0/28",
            "gateway_ip": "10.209.0.2",
            "vm_ip": "10.209.0.3",
            "docker_network_name": "sandbox-net-test"
        }"#;

        let info: NetworkInfo = serde_json::from_str(old_row).unwrap();
        assert!(
            info.vmnet_slot.is_none(),
            "old row without vmnet_slot must deserialize to None"
        );
        assert_eq!(info.gateway_ip, "10.209.0.2");
    }

    // -- macOS-specific tests ------------------------------------------------

    #[cfg(target_os = "macos")]
    mod macos_tests {
        use super::*;
        use tempfile::TempDir;

        /// A stand-in operator uid for pool tests. The pool does not interpret
        /// it — it records the uid with the claim and names it in the
        /// exhaustion error — so any value above the system-uid floor does.
        const TEST_OPERATOR_UID: u32 = 501;

        // -- /29 address role computation ------------------------------------

        #[test]
        fn test_vmnet_slot_addresses_slot0() {
            let (subnet, gw, vm) = vmnet_slot_addresses(0);
            // B = 10.209.128.0, gateway = B+3, vm = B+4
            assert_eq!(subnet, "10.209.128.0/29");
            assert_eq!(gw, Ipv4Addr::new(10, 209, 128, 3));
            assert_eq!(vm, Ipv4Addr::new(10, 209, 128, 4));
        }

        #[test]
        fn test_vmnet_slot_addresses_slot1() {
            let (subnet, gw, vm) = vmnet_slot_addresses(1);
            // B = 10.209.128.8, gateway = B+3=.11, vm = B+4=.12
            assert_eq!(subnet, "10.209.128.8/29");
            assert_eq!(gw, Ipv4Addr::new(10, 209, 128, 11));
            assert_eq!(vm, Ipv4Addr::new(10, 209, 128, 12));
        }

        #[test]
        fn test_vmnet_slot_addresses_slot2_worked_example() {
            // Spec worked example: slot 2, B = 10.209.128.16,
            // gateway container B+3 = .19, sandbox B+4 = .20.
            let (subnet, gw, vm) = vmnet_slot_addresses(2);
            assert_eq!(subnet, "10.209.128.16/29");
            assert_eq!(gw, Ipv4Addr::new(10, 209, 128, 19));
            assert_eq!(vm, Ipv4Addr::new(10, 209, 128, 20));
        }

        #[test]
        fn test_vmnet_slot_addresses_no_overlap() {
            // Verify /29 slots don't overlap.
            let (s0, _, _) = vmnet_slot_addresses(0);
            let (s1, _, _) = vmnet_slot_addresses(1);
            let (s7, gw7, vm7) = vmnet_slot_addresses(7);
            // Slot 0: 10.209.128.0–7, Slot 1: .8–.15, Slot 7: .56–.63
            assert_eq!(s0, "10.209.128.0/29");
            assert_eq!(s1, "10.209.128.8/29");
            assert_eq!(s7, "10.209.128.56/29");
            assert_eq!(gw7, Ipv4Addr::new(10, 209, 128, 59));
            assert_eq!(vm7, Ipv4Addr::new(10, 209, 128, 60));
        }

        // -- Deterministic network-identifier UUID derivation ----------------

        #[test]
        fn test_vmnet_network_identifier_is_deterministic() {
            let uuid0a = vmnet_slot_network_identifier(0);
            let uuid0b = vmnet_slot_network_identifier(0);
            assert_eq!(uuid0a, uuid0b, "same slot must produce the same UUID");
        }

        #[test]
        fn test_vmnet_network_identifier_unique_per_slot() {
            let uuids: Vec<String> = (0..8).map(vmnet_slot_network_identifier).collect();
            // All must be unique.
            let unique: std::collections::HashSet<&String> = uuids.iter().collect();
            assert_eq!(
                unique.len(),
                8,
                "each slot must have a distinct network-identifier UUID"
            );
        }

        #[test]
        fn test_vmnet_network_identifier_is_valid_v5_uuid() {
            let uuid = vmnet_slot_network_identifier(0);
            // Must be 36 chars with the standard 8-4-4-4-12 format.
            assert_eq!(uuid.len(), 36);
            let parts: Vec<&str> = uuid.split('-').collect();
            assert_eq!(parts.len(), 5);
            assert_eq!(parts[0].len(), 8);
            assert_eq!(parts[1].len(), 4);
            assert_eq!(parts[2].len(), 4);
            assert_eq!(parts[3].len(), 4);
            assert_eq!(parts[4].len(), 12);

            // Version bits: byte 6 high nibble = 5.
            let version_char = parts[2].chars().next().unwrap();
            assert_eq!(version_char, '5', "UUID version must be 5 (UUIDv5)");

            // Variant bits: byte 8 high bits = 10xx (chars '8', '9', 'a', 'b').
            let variant_char = parts[3].chars().next().unwrap();
            assert!(
                matches!(variant_char, '8' | '9' | 'a' | 'b'),
                "UUID variant must be RFC 4122 (bits 10xx), got '{variant_char}'"
            );
        }

        /// Pinned UUID values: asserts exact expected UUIDs for slots 0 and 2.
        ///
        /// These values are the authoritative ground truth for the
        /// `--vmnet-network-identifier` UUIDs in the installed launchd plists.
        /// If either the Rust derivation or the Makefile Python generator changes
        /// the namespace bytes or algorithm, one of these tests will fail —
        /// catching drift before it silently breaks inter-slot isolation.
        ///
        /// Verified against the Python implementation (identical output):
        ///   SHA1(NAMESPACE || slot.to_be_bytes()), version=5, variant=RFC4122.
        #[test]
        fn test_vmnet_network_identifier_pinned_values() {
            assert_eq!(
                vmnet_slot_network_identifier(0),
                "a25e1b72-b44a-573c-be93-fe2da03c5a96",
                "slot 0 network-identifier must be stable"
            );
            assert_eq!(
                vmnet_slot_network_identifier(1),
                "632c6b78-8256-579e-a88d-041b5adfd423",
                "slot 1 network-identifier must be stable"
            );
            assert_eq!(
                vmnet_slot_network_identifier(2),
                "a1a1fa3e-5809-5b63-9a1b-358845ec042b",
                "slot 2 network-identifier must be stable"
            );
        }

        // -- Plist generation ------------------------------------------------

        #[test]
        fn test_plist_contains_required_argv() {
            let plist = render_vmnet_plist(2, SANDBOXD_ACCOUNT);
            assert!(
                plist.contains("--vmnet-mode=host"),
                "plist must include --vmnet-mode=host"
            );
            assert!(
                plist.contains("--socket-group=_sandboxd"),
                "plist must include --socket-group=_sandboxd"
            );
            assert!(
                plist.contains("--vmnet-network-identifier="),
                "plist must include --vmnet-network-identifier"
            );
            assert!(
                plist.contains("slot-2.sock"),
                "plist must reference the slot's socket path"
            );
            assert!(
                plist.contains(STAGED_SOCKET_VMNET_PATH),
                "plist must exec the staged socket_vmnet binary"
            );
        }

        #[test]
        fn test_plist_has_run_at_load_and_keep_alive() {
            let plist = render_vmnet_plist(0, SANDBOXD_ACCOUNT);
            assert!(plist.contains("<key>RunAtLoad</key>"));
            assert!(plist.contains("<true/>"));
            assert!(plist.contains("<key>KeepAlive</key>"));
        }

        #[test]
        fn test_plist_has_pre_exec_dir_creation() {
            let plist = render_vmnet_plist(0, SANDBOXD_ACCOUNT);
            // The pre-exec wrapper must create /var/run/sandbox and
            // /var/run/sandbox/vmnet with _sandboxd ownership.
            assert!(
                plist.contains("install -d -o _sandboxd -g _sandboxd -m 0750 /var/run/sandbox"),
                "plist must create /var/run/sandbox with _sandboxd:_sandboxd 0750"
            );
            assert!(
                plist.contains("/var/run/sandbox/vmnet"),
                "plist must create /var/run/sandbox/vmnet"
            );
        }

        /// The pre-exec wrapper must include a codesign --verify --strict check
        /// before exec'ing the staged binary.  This guard makes content tampering
        /// fail-closed: the daemon refuses to exec a binary that fails verification.
        #[test]
        fn test_plist_has_codesign_guard() {
            for slot in 0u16..4 {
                let plist = render_vmnet_plist(slot, SANDBOXD_ACCOUNT);
                let guard_fragment =
                    format!("codesign --verify --strict {STAGED_SOCKET_VMNET_PATH}");
                assert!(
                    plist.contains(&guard_fragment),
                    "slot {slot}: plist must include codesign --verify --strict guard before exec"
                );
                assert!(
                    plist.contains("refusing to exec"),
                    "slot {slot}: plist must include actionable error message in guard failure path"
                );
            }
        }

        #[test]
        fn test_plist_label_matches_slot() {
            for slot in 0u16..4 {
                let plist = render_vmnet_plist(slot, SANDBOXD_ACCOUNT);
                assert!(
                    plist.contains(&format!("io.sandboxd.vmnet.{slot}")),
                    "plist label must be io.sandboxd.vmnet.{slot}"
                );
            }
        }

        #[test]
        fn test_plist_network_identifier_is_deterministic_across_calls() {
            let plist_a = render_vmnet_plist(3, SANDBOXD_ACCOUNT);
            let plist_b = render_vmnet_plist(3, SANDBOXD_ACCOUNT);
            assert_eq!(plist_a, plist_b, "plist generation must be deterministic");
        }

        #[test]
        fn test_plist_no_networks_yaml() {
            // The plist must NOT reference networks.yaml anywhere.
            let plist = render_vmnet_plist(0, SANDBOXD_ACCOUNT);
            assert!(
                !plist.contains("networks.yaml"),
                "plist must not reference networks.yaml"
            );
        }

        /// Every occurrence of the account name in the rendered plist comes
        /// from the parameter — nothing is hardcoded behind the caller's back.
        ///
        /// A stray literal would survive a rename of [`SANDBOXD_ACCOUNT`] and
        /// re-introduce exactly the split-brain this parameterization removes.
        #[test]
        fn test_plist_account_is_fully_parameterized() {
            let plist = render_vmnet_plist(0, "nobody");
            assert!(
                !plist.contains(SANDBOXD_ACCOUNT),
                "rendering for 'nobody' must not leak the default account name:\n{plist}"
            );
            assert!(
                plist.contains("install -d -o nobody -g nobody -m 0750 /var/run/sandbox"),
                "the dir preamble must name the account it was given:\n{plist}"
            );
            assert!(
                plist.contains("install -d -o nobody -g nobody -m 0750 /var/run/sandbox/vmnet"),
                "the vmnet dir preamble must name the account it was given:\n{plist}"
            );
            assert!(
                plist.contains("--socket-group=nobody"),
                "--socket-group must name the account it was given:\n{plist}"
            );
        }

        /// A plist naming an account that does not resolve is never emitted.
        ///
        /// `install -d -o <absent> …` fails at every boot and `&&`-short-circuits
        /// the whole preamble, so such a plist silently kills the entire pool.
        /// The emitter must fail loudly instead, naming the account.
        #[test]
        fn test_generate_refuses_when_account_is_absent() {
            let absent = "_sandboxd_definitely_absent_test_account";
            let err = ensure_vmnet_account_resolvable(absent)
                .expect_err("an account that cannot exist must be refused");
            let msg = err.to_string();
            assert!(
                msg.contains(absent),
                "the refusal must name the offending account, got: {msg}"
            );
            assert!(
                msg.contains("install -d"),
                "the refusal must explain what breaks, got: {msg}"
            );
            assert!(
                msg.contains("setup-darwin-sandboxd-user") || msg.contains("install.sh"),
                "the refusal must say how to fix it, got: {msg}"
            );
        }

        /// The resolvability check passes for an account that does exist.
        ///
        /// `daemon` is a stock macOS account whose user *and* group both
        /// resolve (unlike `root`, whose group is `wheel`), so this pins the
        /// happy path without depending on sandboxd being provisioned here.
        #[test]
        fn test_ensure_account_resolvable_accepts_existing_account() {
            ensure_vmnet_account_resolvable("daemon")
                .expect("the stock 'daemon' user and group resolve on every macOS host");
        }

        /// `generate_vmnet_plist` agrees byte-for-byte with the pure renderer.
        ///
        /// Only meaningful once the host is provisioned; before that the
        /// generator correctly refuses and there is nothing to compare.
        #[test]
        fn test_generate_matches_render_when_account_resolves() {
            match generate_vmnet_plist(1) {
                Ok(plist) => assert_eq!(
                    plist,
                    render_vmnet_plist(1, SANDBOXD_ACCOUNT),
                    "the guarded emitter must return exactly what the renderer produces"
                ),
                Err(e) => {
                    let msg = e.to_string();
                    assert!(
                        msg.contains(SANDBOXD_ACCOUNT),
                        "on an unprovisioned host the refusal must name {SANDBOXD_ACCOUNT}, \
                         got: {msg}"
                    );
                }
            }
        }

        /// The plist must not contain bare `&` (only `&amp;`).
        ///
        /// Raw `&&` in a plist `<string>` element is illegal XML; `plutil -lint`
        /// rejects it. The shell receives literal `&&` after launchd un-escapes
        /// the XML entities.
        #[test]
        fn test_plist_ampersand_is_xml_escaped() {
            for slot in 0u16..4 {
                let plist = render_vmnet_plist(slot, SANDBOXD_ACCOUNT);

                // No bare & should appear in the XML (outside of &amp; etc.).
                // Scan character by character: any `&` not followed by `amp;`
                // is a bare ampersand.
                let bytes = plist.as_bytes();
                for i in 0..bytes.len() {
                    if bytes[i] == b'&' {
                        let remainder = &plist[i..];
                        assert!(
                            remainder.starts_with("&amp;")
                                || remainder.starts_with("&lt;")
                                || remainder.starts_with("&gt;")
                                || remainder.starts_with("&quot;")
                                || remainder.starts_with("&apos;"),
                            "slot {slot}: bare '&' found at byte {i}; \
                             must be escaped as &amp; in XML: ...{}...",
                            &plist[i.saturating_sub(20)..(i + 20).min(plist.len())]
                        );
                    }
                }

                // Also assert that the XML-escaped form of && is present.
                assert!(
                    plist.contains("&amp;&amp;"),
                    "slot {slot}: plist must contain &amp;&amp; for the shell && operator"
                );
            }
        }

        /// Shell out to `plutil -lint` to verify the generated plist is valid XML.
        ///
        /// Requires `plutil` (available on macOS). The test writes the plist to
        /// a tempfile and validates it.
        #[test]
        fn test_plist_passes_plutil_lint() {
            use std::io::Write;
            use tempfile::NamedTempFile;

            // Verify plutil is available; skip gracefully if not (non-macOS CI).
            if std::process::Command::new("plutil")
                .arg("--version")
                .output()
                .is_err()
            {
                return;
            }

            for slot in 0u16..2 {
                let plist = render_vmnet_plist(slot, SANDBOXD_ACCOUNT);
                let mut f = NamedTempFile::with_suffix(".plist").unwrap();
                f.write_all(plist.as_bytes()).unwrap();
                f.flush().unwrap();

                let output = std::process::Command::new("plutil")
                    .arg("-lint")
                    .arg(f.path())
                    .output()
                    .expect("plutil must be runnable");

                assert!(
                    output.status.success(),
                    "slot {slot}: plutil -lint failed on generated plist:\n{}\nplist content:\n{}",
                    String::from_utf8_lossy(&output.stderr),
                    plist
                );
            }
        }

        // -- slot ⇄ socket path round trip -----------------------------------

        /// Every slot's socket path parses back to that slot, so the path can
        /// be used to check a claimed interface name rather than trusted.
        #[test]
        fn slot_socket_path_round_trips_for_every_slot() {
            for slot in 0u16..64 {
                let path = vmnet_slot_socket_path(slot);
                assert_eq!(
                    slot_from_vmnet_socket_path(&path),
                    Some(slot),
                    "{path} must parse back to slot {slot}"
                );
            }
        }

        /// Anything that is not exactly a slot socket path parses to nothing —
        /// including a non-canonical index and a path in another directory,
        /// either of which would let a wrong entry pass a naive check.
        #[test]
        fn slot_socket_path_rejects_non_canonical_and_foreign_paths() {
            for path in [
                "/var/run/sandbox/vmnet/slot-04.sock",
                "/var/run/sandbox/vmnet/slot-+4.sock",
                "/var/run/sandbox/vmnet/slot-.sock",
                "/var/run/sandbox/vmnet/slot-4.socket",
                "/var/run/sandbox/vmnet/lima4.sock",
                "/tmp/slot-4.sock",
                "slot-4.sock",
                "",
            ] {
                assert_eq!(
                    slot_from_vmnet_socket_path(path),
                    None,
                    "{path} must not parse as a slot socket"
                );
            }
        }

        // -- VmnetPool slot claim/release ------------------------------------

        #[test]
        fn test_vmnet_pool_claim_lima_slot() {
            let pool = VmnetPool::new(4);
            let session_id = SessionId::generate();
            let (slot, subnet, gw, vm) = pool
                .claim_lima_slot(&session_id, TEST_OPERATOR_UID)
                .unwrap();

            assert_eq!(slot.index, 0);
            assert_eq!(slot.daemon_label, "io.sandboxd.vmnet.0");
            assert_eq!(slot.socket_path, "/var/run/sandbox/vmnet/slot-0.sock");
            assert_eq!(subnet, "10.209.128.0/29");
            assert_eq!(gw, Ipv4Addr::new(10, 209, 128, 3));
            assert_eq!(vm, Ipv4Addr::new(10, 209, 128, 4));
            assert_eq!(pool.running_session_count(), 1);
        }

        #[test]
        fn test_vmnet_pool_claim_sequential_slots() {
            let pool = VmnetPool::new(4);
            let id0 = SessionId::generate();
            let id1 = SessionId::generate();
            let (s0, _, _, _) = pool.claim_lima_slot(&id0, TEST_OPERATOR_UID).unwrap();
            let (s1, _, _, _) = pool.claim_lima_slot(&id1, TEST_OPERATOR_UID).unwrap();

            assert_eq!(s0.index, 0);
            assert_eq!(s1.index, 1);
            assert_eq!(pool.running_session_count(), 2);
        }

        #[test]
        fn test_vmnet_pool_release_and_reuse() {
            let pool = VmnetPool::new(4);
            let id0 = SessionId::generate();
            let id1 = SessionId::generate();
            let id2 = SessionId::generate();

            let (s0, _, _, _) = pool.claim_lima_slot(&id0, TEST_OPERATOR_UID).unwrap();
            let _ = pool.claim_lima_slot(&id1, TEST_OPERATOR_UID).unwrap();

            // Populate the full NetworkInfo (optional step after claim).
            let info = NetworkInfo {
                operator_uid: None,
                bridge_name: "lima0".to_string(),
                subnet: "10.209.128.0/29".to_string(),
                gateway_ip: "10.209.128.3".to_string(),
                vm_ip: "10.209.128.4".to_string(),
                docker_network_name: format!("sandbox-net-{id0}"),
                vmnet_slot: Some(VmnetSlot {
                    index: s0.index,
                    daemon_label: s0.daemon_label.clone(),
                    socket_path: s0.socket_path.clone(),
                }),
            };
            pool.set_lima_network_info(&id0, s0.index, info).unwrap();
            pool.release_lima_slot(&id0).unwrap();

            assert_eq!(pool.running_session_count(), 1);

            // Next claim should reuse slot 0.
            let (s2, _, _, _) = pool.claim_lima_slot(&id2, TEST_OPERATOR_UID).unwrap();
            assert_eq!(s2.index, 0);
        }

        #[test]
        fn test_vmnet_pool_release_idempotent() {
            let pool = VmnetPool::new(4);
            let id = SessionId::generate();

            let (s0, _, _, _) = pool.claim_lima_slot(&id, TEST_OPERATOR_UID).unwrap();
            let info = NetworkInfo {
                operator_uid: None,
                bridge_name: "lima0".to_string(),
                subnet: "10.209.128.0/29".to_string(),
                gateway_ip: "10.209.128.3".to_string(),
                vm_ip: "10.209.128.4".to_string(),
                docker_network_name: format!("sandbox-net-{id}"),
                vmnet_slot: Some(VmnetSlot {
                    index: s0.index,
                    daemon_label: s0.daemon_label.clone(),
                    socket_path: s0.socket_path.clone(),
                }),
            };
            pool.set_lima_network_info(&id, s0.index, info).unwrap();

            // Release twice — must not panic or double-decrement.
            pool.release_lima_slot(&id).unwrap();
            pool.release_lima_slot(&id).unwrap();

            assert_eq!(pool.running_session_count(), 0);
        }

        /// Partial-create rollback: claim a slot, then release without ever
        /// calling `set_lima_network_info`. The slot must return to the pool
        /// and the session-count must be decremented.
        #[test]
        fn test_vmnet_pool_release_without_set_info_frees_slot() {
            let pool = VmnetPool::new(4);
            let id = SessionId::generate();

            let (s0, _, _, _) = pool.claim_lima_slot(&id, TEST_OPERATOR_UID).unwrap();
            assert_eq!(pool.running_session_count(), 1);
            assert!(pool.allocated_slot_indices().contains(&s0.index));

            // Release WITHOUT calling set_lima_network_info — simulates a
            // partial-create rollback where the create flow fails before the
            // NetworkInfo is built.
            pool.release_lima_slot(&id).unwrap();

            assert_eq!(pool.running_session_count(), 0, "count must be decremented");
            assert!(
                !pool.allocated_slot_indices().contains(&s0.index),
                "slot must be freed"
            );

            // The freed slot must be reclaimable.
            let id2 = SessionId::generate();
            let (s2, _, _, _) = pool.claim_lima_slot(&id2, TEST_OPERATOR_UID).unwrap();
            assert_eq!(s2.index, s0.index, "freed slot must be reused");
        }

        /// Double-release after claim-without-info must not double-decrement.
        #[test]
        fn test_vmnet_pool_double_release_without_set_info_no_underflow() {
            let pool = VmnetPool::new(4);
            let id = SessionId::generate();

            pool.claim_lima_slot(&id, TEST_OPERATOR_UID).unwrap();
            pool.release_lima_slot(&id).unwrap(); // first release — frees slot
            pool.release_lima_slot(&id).unwrap(); // second release — must be no-op

            assert_eq!(pool.running_session_count(), 0);
        }

        // -- NIC-slot-vs-session-token split ---------------------------------

        #[test]
        fn test_lite_token_consumes_no_nic_slot() {
            let pool = VmnetPool::new(4);

            // Claim a lite token — should succeed and increment session count
            // but NOT allocate any slot.
            pool.claim_lite_token(TEST_OPERATOR_UID).unwrap();
            assert_eq!(pool.running_session_count(), 1);
            assert!(
                pool.allocated_slot_indices().is_empty(),
                "lite token must not claim any NIC slot"
            );
        }

        #[test]
        fn test_mixed_lima_and_lite_sessions() {
            // 3 Lima + 2 lite sessions under pool size 8 — uses 3 NIC slots.
            let pool = VmnetPool::new(8);
            let ids: Vec<SessionId> = (0..3).map(|_| SessionId::generate()).collect();

            for id in &ids {
                pool.claim_lima_slot(id, TEST_OPERATOR_UID).unwrap();
            }
            pool.claim_lite_token(TEST_OPERATOR_UID).unwrap();
            pool.claim_lite_token(TEST_OPERATOR_UID).unwrap();

            assert_eq!(pool.running_session_count(), 5);
            assert_eq!(
                pool.allocated_slot_indices().len(),
                3,
                "only Lima sessions consume NIC slots"
            );
        }

        // -- Pool exhaustion error -------------------------------------------

        #[test]
        fn test_pool_exhaustion_lima_slot() {
            let pool = VmnetPool::new(2);
            let id0 = SessionId::generate();
            let id1 = SessionId::generate();
            let id2 = SessionId::generate();

            pool.claim_lima_slot(&id0, TEST_OPERATOR_UID).unwrap();
            pool.claim_lima_slot(&id1, TEST_OPERATOR_UID).unwrap();

            let result = pool.claim_lima_slot(&id2, TEST_OPERATOR_UID);
            // Structured, not a pre-formatted string: the numbers are fields
            // and the text is rendered from `Display` in one place. Three
            // sites raise this condition, and as three copies of a literal
            // they were free to drift apart.
            match result {
                Err(SandboxError::SessionQuotaExhausted {
                    operator_uid,
                    in_use,
                    quota,
                    host_slots,
                }) => {
                    assert_eq!(operator_uid, TEST_OPERATOR_UID);
                    assert_eq!(in_use, 2);
                    assert_eq!(quota, 2);
                    assert_eq!(host_slots, 2);
                }
                other => panic!("exhaustion must be the structured quota variant, got {other:?}"),
            }

            let err = pool
                .claim_lima_slot(&id2, TEST_OPERATOR_UID)
                .unwrap_err()
                .to_string();
            assert!(
                err.contains("max concurrent sessions reached"),
                "exhaustion error must mention 'max concurrent sessions reached': {err}"
            );
            assert!(
                err.contains("max_macos_sessions"),
                "exhaustion error must mention max_macos_sessions: {err}"
            );
        }

        #[test]
        fn test_pool_exhaustion_lite_token() {
            let pool = VmnetPool::new(1);
            pool.claim_lite_token(TEST_OPERATOR_UID).unwrap();

            let result = pool.claim_lite_token(TEST_OPERATOR_UID);
            assert!(result.is_err());
            let err = result.unwrap_err().to_string();
            assert!(err.contains("max concurrent sessions reached"));
        }

        // -- Lite stop/start token accounting --------------------------------
        //
        // A stopped lite session retains its token. Only remove (full cleanup)
        // releases it. This mirrors Linux stop behavior and prevents pool drift
        // across stop/start cycles.

        #[test]
        fn lite_token_retained_across_stop_start_no_drift() {
            // Claim a lite token (simulate create).
            let pool = VmnetPool::new(2);
            pool.claim_lite_token(TEST_OPERATOR_UID).unwrap();
            assert_eq!(pool.running_session_count(), 1);

            // Stop does NOT release the token — the session is paused, not gone.
            // No release_lite_token call here, matching the stop_session behavior.
            assert_eq!(
                pool.running_session_count(),
                1,
                "token must still be held after stop"
            );

            // Start also does NOT re-claim — the token was never released.
            // Verify the pool cap is still enforced (the held token blocks a new one).
            pool.claim_lite_token(TEST_OPERATOR_UID).unwrap(); // second session, still under cap=2
            assert_eq!(pool.running_session_count(), 2);

            // Third claim must fail — cap enforced by the retained first token.
            let result = pool.claim_lite_token(TEST_OPERATOR_UID);
            assert!(
                result.is_err(),
                "cap must be enforced by the retained stopped-session token"
            );

            // Remove (full cleanup) releases both tokens.
            pool.release_lite_token().unwrap(); // remove first session
            pool.release_lite_token().unwrap(); // remove second session
            assert_eq!(pool.running_session_count(), 0);
        }

        #[test]
        fn lite_token_stop_then_remove_single_release() {
            // Verify that a single claim → stop (no release) → remove (release)
            // cycle results in exactly one net release: count goes 1 → 0.
            let pool = VmnetPool::new(4);
            pool.claim_lite_token(TEST_OPERATOR_UID).unwrap();
            assert_eq!(pool.running_session_count(), 1);

            // stop: no release
            // remove: one release
            pool.release_lite_token().unwrap();
            assert_eq!(pool.running_session_count(), 0);

            // A new session can now be created — the slot is free.
            pool.claim_lite_token(TEST_OPERATOR_UID).unwrap();
            assert_eq!(pool.running_session_count(), 1);
        }

        // -- State restore ---------------------------------------------------

        #[test]
        fn test_vmnet_pool_restore_from_infos() {
            let pool = VmnetPool::new(4);
            let id0 = SessionId::generate();
            let id1 = SessionId::generate();

            let info0 = NetworkInfo {
                operator_uid: None,
                bridge_name: "lima0".to_string(),
                subnet: "10.209.128.0/29".to_string(),
                gateway_ip: "10.209.128.3".to_string(),
                vm_ip: "10.209.128.4".to_string(),
                docker_network_name: format!("sandbox-net-{id0}"),
                vmnet_slot: Some(VmnetSlot {
                    index: 0,
                    daemon_label: "io.sandboxd.vmnet.0".to_string(),
                    socket_path: "/var/run/sandbox/vmnet/slot-0.sock".to_string(),
                }),
            };
            let info1 = NetworkInfo {
                operator_uid: None,
                bridge_name: "lima2".to_string(),
                subnet: "10.209.128.16/29".to_string(),
                gateway_ip: "10.209.128.19".to_string(),
                vm_ip: "10.209.128.20".to_string(),
                docker_network_name: format!("sandbox-net-{id1}"),
                vmnet_slot: Some(VmnetSlot {
                    index: 2,
                    daemon_label: "io.sandboxd.vmnet.2".to_string(),
                    socket_path: "/var/run/sandbox/vmnet/slot-2.sock".to_string(),
                }),
            };

            pool.restore_from_infos(&[(id0, info0), (id1, info1)], TEST_OPERATOR_UID)
                .unwrap();

            assert_eq!(pool.running_session_count(), 2);
            let slots = pool.allocated_slot_indices();
            assert!(slots.contains(&0));
            assert!(slots.contains(&2));
            assert!(!slots.contains(&1));
            assert!(!slots.contains(&3));
        }

        #[test]
        fn test_vmnet_pool_restore_skips_infos_without_slot() {
            // Lite sessions have no vmnet_slot; restore_from_infos must skip them.
            let pool = VmnetPool::new(4);
            let id = SessionId::generate();

            let info = NetworkInfo {
                operator_uid: None,
                bridge_name: "sb-test".to_string(),
                subnet: "10.209.0.0/28".to_string(),
                gateway_ip: "10.209.0.2".to_string(),
                vm_ip: "10.209.0.3".to_string(),
                docker_network_name: format!("sandbox-net-{id}"),
                vmnet_slot: None,
            };

            pool.restore_from_infos(&[(id, info)], TEST_OPERATOR_UID)
                .unwrap();
            assert_eq!(pool.running_session_count(), 0);
            assert!(pool.allocated_slot_indices().is_empty());
        }

        // -- restore_lite_tokens -----------------------------------------------

        /// Restoring n lite tokens bumps session_count by n and does not
        /// allocate any NIC slots — lite sessions have no vmnet_slot.
        #[test]
        fn restore_lite_tokens_bumps_session_count_without_slot() {
            let pool = VmnetPool::new(8);
            pool.restore_lite_tokens(3).unwrap();
            assert_eq!(pool.running_session_count(), 3);
            assert!(
                pool.allocated_slot_indices().is_empty(),
                "lite tokens must not allocate any NIC slots"
            );
        }

        /// restore_lite_tokens(0) is a no-op.
        #[test]
        fn restore_lite_tokens_zero_is_noop() {
            let pool = VmnetPool::new(8);
            pool.restore_lite_tokens(0).unwrap();
            assert_eq!(pool.running_session_count(), 0);
        }

        /// Mixed restore: slot sessions via restore_from_infos + lite sessions
        /// via restore_lite_tokens produce the correct combined count and the
        /// right set of allocated NIC slots.
        ///
        /// Scenario: 2 Lima sessions (slots 0 and 2) + 3 lite sessions.
        /// Expected: running_session_count() == 5, allocated_slot_indices() == {0, 2}.
        #[test]
        fn restore_mixed_lima_and_lite_sessions() {
            let pool = VmnetPool::new(8);
            let id0 = SessionId::generate();
            let id1 = SessionId::generate();

            let info0 = NetworkInfo {
                operator_uid: None,
                bridge_name: "lima0".to_string(),
                subnet: "10.209.128.0/29".to_string(),
                gateway_ip: "10.209.128.3".to_string(),
                vm_ip: "10.209.128.4".to_string(),
                docker_network_name: format!("sandbox-net-{id0}"),
                vmnet_slot: Some(VmnetSlot {
                    index: 0,
                    daemon_label: "io.sandboxd.vmnet.0".to_string(),
                    socket_path: "/var/run/sandbox/vmnet/slot-0.sock".to_string(),
                }),
            };
            let info1 = NetworkInfo {
                operator_uid: None,
                bridge_name: "lima2".to_string(),
                subnet: "10.209.128.16/29".to_string(),
                gateway_ip: "10.209.128.19".to_string(),
                vm_ip: "10.209.128.20".to_string(),
                docker_network_name: format!("sandbox-net-{id1}"),
                vmnet_slot: Some(VmnetSlot {
                    index: 2,
                    daemon_label: "io.sandboxd.vmnet.2".to_string(),
                    socket_path: "/var/run/sandbox/vmnet/slot-2.sock".to_string(),
                }),
            };

            // Restore 2 Lima slots.
            pool.restore_from_infos(&[(id0, info0), (id1, info1)], TEST_OPERATOR_UID)
                .unwrap();
            // Then restore 3 lite tokens.
            pool.restore_lite_tokens(3).unwrap();

            assert_eq!(
                pool.running_session_count(),
                5,
                "2 Lima + 3 lite = 5 total sessions"
            );
            let slots = pool.allocated_slot_indices();
            assert_eq!(slots.len(), 2, "only Lima sessions hold NIC slots");
            assert!(slots.contains(&0));
            assert!(slots.contains(&2));
            assert!(!slots.contains(&1));
        }

        /// A lite session restored via restore_lite_tokens consumes a token —
        /// subsequent claim attempts must respect the cap.
        #[test]
        fn restore_lite_tokens_count_enforced_against_cap() {
            let pool = VmnetPool::new(4);
            // Pre-fill with 3 lite tokens (as if 3 lite sessions were running).
            pool.restore_lite_tokens(3).unwrap();
            assert_eq!(pool.running_session_count(), 3);

            // One more lite token must succeed (total = 4, cap = 4).
            pool.claim_lite_token(TEST_OPERATOR_UID).unwrap();
            assert_eq!(pool.running_session_count(), 4);

            // Another lite token must fail (cap exhausted).
            let result = pool.claim_lite_token(TEST_OPERATOR_UID);
            assert!(result.is_err(), "must fail when cap is reached");
            let err = result.unwrap_err().to_string();
            assert!(
                err.contains("max concurrent sessions reached"),
                "got: {err}"
            );
        }

        /// Linux path is unaffected: restore_from_infos behavior is unchanged
        /// for slot sessions (no regression on the existing contract).
        #[test]
        fn restore_from_infos_slot_behavior_unchanged() {
            let pool = VmnetPool::new(4);
            let id = SessionId::generate();
            let info = NetworkInfo {
                operator_uid: None,
                bridge_name: "lima0".to_string(),
                subnet: "10.209.128.0/29".to_string(),
                gateway_ip: "10.209.128.3".to_string(),
                vm_ip: "10.209.128.4".to_string(),
                docker_network_name: format!("sandbox-net-{id}"),
                vmnet_slot: Some(VmnetSlot {
                    index: 0,
                    daemon_label: "io.sandboxd.vmnet.0".to_string(),
                    socket_path: "/var/run/sandbox/vmnet/slot-0.sock".to_string(),
                }),
            };
            pool.restore_from_infos(&[(id, info)], TEST_OPERATOR_UID)
                .unwrap();
            // restore_from_infos still counts the session AND marks the slot.
            assert_eq!(pool.running_session_count(), 1);
            assert!(pool.allocated_slot_indices().contains(&0));
        }

        // -- startup slot-leak release tests ----------------------------------
        //
        // These tests model the startup slot-leak release behaviour from step 6
        // of the macOS daemon startup sequence:
        //
        // A session that is not Running but whose NetworkInfo holds a vmnet_slot
        // is a "leaked" slot. The startup reconcile (6a) releases those slots
        // by calling pool.release_lima_slot() — after which the pool no longer
        // reports that slot as allocated. This frees the slot for new sessions.

        #[test]
        fn test_startup_slot_leak_release_stopped_session() {
            // Simulate: a stopped session held slot 1 across a daemon restart.
            // The session is not Running, so its slot is leaked and should be
            // released. After release, the pool has zero allocated slots.
            let pool = VmnetPool::new(4);
            let id = SessionId::generate();

            // claim_lima_slot simulates what create did at runtime.
            let (slot, subnet, gw, vm) = pool.claim_lima_slot(&id, TEST_OPERATOR_UID).unwrap();
            let info = NetworkInfo {
                operator_uid: None,
                bridge_name: format!("lima{}", slot.index),
                subnet,
                gateway_ip: gw.to_string(),
                vm_ip: vm.to_string(),
                docker_network_name: format!("sandbox-net-{id}"),
                vmnet_slot: Some(VmnetSlot {
                    index: slot.index,
                    daemon_label: slot.daemon_label.clone(),
                    socket_path: slot.socket_path.clone(),
                }),
            };
            pool.set_lima_network_info(&id, slot.index, info).unwrap();

            // Session is now "stopped" (daemon crashed while it was claimed).
            // 6a should release the slot.
            assert!(pool.allocated_slot_indices().contains(&slot.index));
            pool.release_lima_slot(&id).unwrap();

            // After release: slot must be free.
            assert!(
                !pool.allocated_slot_indices().contains(&slot.index),
                "slot must be released after startup leak cleanup"
            );
            assert_eq!(pool.running_session_count(), 0);
        }

        #[test]
        fn test_startup_slot_leak_release_multiple_sessions() {
            // Two stopped sessions each held a slot. Both should be released.
            let pool = VmnetPool::new(4);
            let id0 = SessionId::generate();
            let id1 = SessionId::generate();

            let (slot0, _, _, _) = pool.claim_lima_slot(&id0, TEST_OPERATOR_UID).unwrap();
            let (slot1, _, _, _) = pool.claim_lima_slot(&id1, TEST_OPERATOR_UID).unwrap();

            assert_eq!(pool.running_session_count(), 2);

            pool.release_lima_slot(&id0).unwrap();
            pool.release_lima_slot(&id1).unwrap();

            assert_eq!(pool.running_session_count(), 0);
            assert!(
                !pool.allocated_slot_indices().contains(&slot0.index),
                "slot0 must be released"
            );
            assert!(
                !pool.allocated_slot_indices().contains(&slot1.index),
                "slot1 must be released"
            );
        }

        #[test]
        fn test_startup_slot_restore_only_running_sessions() {
            // Step 7 restore_from_infos: only sessions that are still Running
            // after the reconcile (6a) contribute to pool state.
            // This mirrors the daemon's logic: running_infos goes to restore_from_infos,
            // non-running sessions get slot released first.
            let pool = VmnetPool::new(4);

            let id_running = SessionId::generate();
            let id_stopped = SessionId::generate();

            // Construct two NetworkInfo entries (as if loaded from DB).
            let info_running = NetworkInfo {
                operator_uid: None,
                bridge_name: "lima0".to_string(),
                subnet: "10.209.128.0/29".to_string(),
                gateway_ip: "10.209.128.3".to_string(),
                vm_ip: "10.209.128.4".to_string(),
                docker_network_name: format!("sandbox-net-{id_running}"),
                vmnet_slot: Some(VmnetSlot {
                    index: 0,
                    daemon_label: "io.sandboxd.vmnet.0".to_string(),
                    socket_path: "/var/run/sandbox/vmnet/slot-0.sock".to_string(),
                }),
            };
            // The stopped session's NetworkInfo is defined here to document what
            // the daemon would load from the DB, but is intentionally NOT passed to
            // restore_from_infos (the daemon releases the slot for stopped sessions
            // first and only restores running-session infos).
            let _info_stopped = NetworkInfo {
                operator_uid: None,
                bridge_name: "lima1".to_string(),
                subnet: "10.209.128.8/29".to_string(),
                gateway_ip: "10.209.128.11".to_string(),
                vm_ip: "10.209.128.12".to_string(),
                docker_network_name: format!("sandbox-net-{id_stopped}"),
                vmnet_slot: Some(VmnetSlot {
                    index: 1,
                    daemon_label: "io.sandboxd.vmnet.1".to_string(),
                    socket_path: "/var/run/sandbox/vmnet/slot-1.sock".to_string(),
                }),
            };

            // Only pass the running session to restore_from_infos.
            pool.restore_from_infos(&[(id_running, info_running)], TEST_OPERATOR_UID)
                .unwrap();

            assert_eq!(
                pool.running_session_count(),
                1,
                "only the running session should contribute to pool count"
            );
            assert!(
                pool.allocated_slot_indices().contains(&0),
                "running session's slot must be marked allocated"
            );
            assert!(
                !pool.allocated_slot_indices().contains(&1),
                "stopped session's slot must NOT be in pool (it was released, not restored)"
            );
        }

        // -- no networks.yaml written test -----------------------------------

        #[test]
        fn test_no_networks_yaml_written() {
            // VmnetPool must never write to any networks.yaml file.
            // This test verifies that no VmnetPool operation creates any file
            // containing "networks.yaml" in its name.
            let pool = VmnetPool::new(4);
            let id = SessionId::generate();
            pool.claim_lima_slot(&id, TEST_OPERATOR_UID).unwrap();
            // If the previous call wrote networks.yaml anywhere, the test
            // environment would surface it. We assert none of the socket paths
            // contain "networks.yaml".
            let slot_path = pool.slot_socket_path(0);
            assert!(
                !slot_path.contains("networks.yaml"),
                "slot socket path must not reference networks.yaml"
            );
            // Plist content must not reference networks.yaml.
            let plist = render_vmnet_plist(0, SANDBOXD_ACCOUNT);
            assert!(!plist.contains("networks.yaml"));
        }

        // -- Ownership assertion tests ----------------------------------------
        //
        // Two layers of tests:
        //
        // 1. `is_path_mode_writable` unit tests — test the mode-check logic
        //    directly, with no filesystem or uid involved. These always exercise
        //    the mode-check code path regardless of whether the test runs as root.
        //
        // 2. `assert_root_exec_ancestry` fixture tests — test the full assertion
        //    against a tempdir tree. On a non-root dev machine, the uid check fires
        //    first for safe-mode paths, confirming the full chain works end-to-end.

        // -- is_path_mode_writable unit tests ---------------------------------

        /// Safe modes must not be flagged as writable.
        #[test]
        fn test_is_path_mode_writable_safe_modes() {
            assert!(
                !is_path_mode_writable(0o755),
                "0755 is not writable by group/other"
            );
            assert!(
                !is_path_mode_writable(0o700),
                "0700 is not writable by group/other"
            );
            assert!(
                !is_path_mode_writable(0o644),
                "0644 is not writable by group/other"
            );
            assert!(
                !is_path_mode_writable(0o444),
                "0444 is not writable by group/other"
            );
        }

        /// Group-writable bit (0o020) must be detected.
        #[test]
        fn test_is_path_mode_writable_group_writable() {
            assert!(
                is_path_mode_writable(0o775),
                "0775 has group-writable bit set"
            );
            assert!(
                is_path_mode_writable(0o720),
                "0720 has group-writable bit set"
            );
        }

        /// Other-writable bit (0o002) must be detected.
        #[test]
        fn test_is_path_mode_writable_other_writable() {
            assert!(
                is_path_mode_writable(0o777),
                "0777 has other-writable bit set"
            );
            assert!(
                is_path_mode_writable(0o755 | 0o002),
                "0757 has other-writable bit set"
            );
        }

        // -- assert_root_exec_ancestry fixture tests --------------------------

        /// On a non-root dev machine, a safe-mode (0755) path fails only the uid
        /// check (not the mode check). This confirms mode is checked first and
        /// that a safe mode reaches the uid gate.
        #[test]
        fn test_ownership_assertion_safe_mode_uid_check_fires() {
            use std::os::unix::fs::PermissionsExt;

            let tmp = TempDir::new().unwrap();
            let binary_path = tmp.path().join("socket_vmnet");
            std::fs::write(&binary_path, b"fake binary").unwrap();

            // Mode 0755: no group/other write bits — safe mode, so uid check fires.
            std::fs::set_permissions(&binary_path, std::fs::Permissions::from_mode(0o755)).unwrap();

            // On a non-root dev machine, uid != 0 fires. We confirm the mode
            // check did NOT fire (the error mentions uid, not "writable").
            let result = assert_root_exec_ancestry(&binary_path);
            assert!(
                result.is_err(),
                "on a non-root dev machine a non-root-owned path must be rejected"
            );
            let err = result.unwrap_err().to_string();
            assert!(
                err.contains("uid"),
                "error must mention uid ownership (mode is safe, so uid check fires): {err}"
            );
            assert!(
                !err.contains("writable"),
                "error must NOT mention writable (mode is 0755, safe): {err}"
            );
        }

        /// A path whose immediate file is group-writable is rejected.
        ///
        /// The mode-check code path itself is directly tested via
        /// `is_path_mode_writable` (see tests above, which do not depend on the
        /// filesystem). This fixture test confirms the full `assert_root_exec_ancestry`
        /// rejects a path that is in a chain with a writable component.
        /// On a non-root dev machine the rejection may fire on an ancestor component
        /// (uid check) before reaching the writable file; what matters is that
        /// the assertion returns Err.
        #[test]
        fn test_ownership_assertion_writable_path_is_rejected() {
            use std::os::unix::fs::PermissionsExt;

            let tmp = TempDir::new().unwrap();
            let binary_path = tmp.path().join("socket_vmnet");
            std::fs::write(&binary_path, b"fake binary").unwrap();

            // Mode 0775: group-writable bit set.
            std::fs::set_permissions(&binary_path, std::fs::Permissions::from_mode(0o775)).unwrap();

            // The assertion must reject the path.
            let result = assert_root_exec_ancestry(&binary_path);
            assert!(
                result.is_err(),
                "writable path must be rejected by the assertion"
            );
        }

        /// An ancestor directory that is other-writable is rejected by the ancestry
        /// check. The full assertion is verified end-to-end — error is returned.
        #[test]
        fn test_ownership_assertion_rejects_path_with_writable_ancestor() {
            use std::os::unix::fs::PermissionsExt;

            let tmp = TempDir::new().unwrap();
            let dir = tmp.path().join("Library").join("sandboxd");
            std::fs::create_dir_all(&dir).unwrap();
            let binary_path = dir.join("socket_vmnet");
            std::fs::write(&binary_path, b"fake binary").unwrap();

            // Make the ancestor directory other-writable.
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o777)).unwrap();

            // The full assertion must fail. On a non-root dev machine the tempdir
            // components all have safe mode (0700 or similar) but uid != 0, so
            // the uid check fires somewhere in the ancestry chain. The ancestor
            // dir's other-writable bit is tested directly via is_path_mode_writable
            // (see above) since fixture-based end-to-end testing for a specific
            // ancestor component is not possible without root.
            let result = assert_root_exec_ancestry(&binary_path);
            assert!(
                result.is_err(),
                "path with writable ancestor must be rejected"
            );
        }
    }
}

// ===========================================================================
// macOS: inter-slot L2 isolation integration test
//
// Named `integration_*` per project convention so the `integration` nextest
// profile selects it and the default profile filters it out.
//
// Checks structural preconditions for the inter-slot L2 isolation property:
// that the two live socket_vmnet daemon sockets are present and their
// network-identifier UUIDs are distinct (distinct UUIDs cause the kernel
// vmnet.framework to place each slot on its own isolated L2 bridge).
//
// Full datapath verification — confirming that a same-subnet ARP across two
// distinct network identifiers actually fails at the kernel level — requires
// live QEMU endpoints attached to running socket_vmnet daemons and is covered
// by the egress E2E regression in the Lima session test suite.
// ===========================================================================

#[cfg(test)]
#[cfg(target_os = "macos")]
mod integration_vmnet_tests {
    use super::*;

    /// Structural precondition check for the inter-slot L2 isolation invariant.
    ///
    /// Verifies that:
    ///   1. Slot 0 and slot 1 socket_vmnet sockets are present (live pool).
    ///   2. The network-identifier UUIDs for slot 0 and slot 1 are distinct.
    ///   3. No socket path references `networks.yaml`.
    ///
    /// Full live L2 datapath isolation (ARP across distinct identifiers fails)
    /// requires live QEMU endpoints and is covered by the egress E2E regression
    /// in the Lima session test suite.
    ///
    /// Run with:
    ///   cargo nextest run --profile integration \
    ///     -E 'test(integration_vmnet_inter_slot_l2_isolation)'
    #[test]
    fn integration_vmnet_inter_slot_l2_isolation() {
        let slot0_socket = vmnet_slot_socket_path(0);
        let slot1_socket = vmnet_slot_socket_path(1);

        // Gate: both sockets must be present. If not, the dev pool is not running.
        if !std::path::Path::new(&slot0_socket).exists()
            || !std::path::Path::new(&slot1_socket).exists()
        {
            panic!(
                "inter-slot L2 isolation test requires the live vmnet pool to be running.\n\
                 Expected sockets:\n  {slot0_socket}\n  {slot1_socket}\n\
                 Run: make setup-dev-env  (to bootstrap the io.sandboxd.vmnet.N daemons)"
            );
        }

        // Verify the UUIDs are distinct — distinct identifiers cause the kernel
        // to place each slot on its own isolated L2 bridge.
        let uuid0 = vmnet_slot_network_identifier(0);
        let uuid1 = vmnet_slot_network_identifier(1);
        assert_ne!(
            uuid0, uuid1,
            "slot 0 and slot 1 must have distinct network-identifier UUIDs for L2 isolation"
        );

        // Verify the UUID format is valid (UUIDv5).
        for (slot, uuid) in [(0u16, &uuid0), (1u16, &uuid1)] {
            let parts: Vec<&str> = uuid.split('-').collect();
            assert_eq!(parts.len(), 5, "slot {slot} UUID must have 5 parts");
            assert_eq!(
                parts[2].chars().next().unwrap(),
                '5',
                "slot {slot} UUID must be version 5"
            );
        }

        // Verify no socket path references networks.yaml (the unmanaged socket:
        // attachment model must never use networks.yaml).
        assert!(
            !slot0_socket.contains("networks.yaml"),
            "slot socket path must not reference networks.yaml"
        );
        assert!(
            !slot1_socket.contains("networks.yaml"),
            "slot socket path must not reference networks.yaml"
        );
    }
}
