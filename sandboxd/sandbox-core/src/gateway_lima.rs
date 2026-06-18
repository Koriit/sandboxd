/// Gateway Lima instance manager (macOS only).
///
/// Manages the `sandboxd-gateway` Lima instance — the persistent daemon-owned
/// Linux VM that hosts all gateway containers across all sandbox sessions.
///
/// The gateway instance is daemon infrastructure, not per-operator. It lives
/// under the daemon's own LIMA_HOME (`/var/lib/sandboxd/<_sandbox-uid>/lima/`)
/// and all `limactl` ops on it run via the `op_uid == daemon_uid` degenerate
/// path of the `LimaExecutor` seam (i.e., `run_limactl_direct` in the daemon —
/// no agent, no privilege pivot needed because the daemon already is `_sandbox`).
///
/// ## Lifecycle (startup)
///
/// `ensure_ready` drives the full gateway-init sequence described in
/// § Daemon startup sequence (macOS) step 4:
///
/// 1. If absent: generate template → `limactl create` → `limactl start`
/// 2. If present and stopped: `limactl start`
/// 3. If present and running: verify forwarded socket accessible
/// 4. Poll `docker -H <sock> info` until ready (60 s timeout, 2 s interval)
/// 5. Discover slot→NIC map via `limactl shell … ip -json link`
/// 6. Ensure `sandboxd-egress` NAT bridge (idempotent)
/// 7. Apply baseline default-drop egress nft on `eth0`
///
/// ## NIC discovery
///
/// The gateway VM has N+1 NICs: `eth0` (management/slirp) and `lima0`..`limaN-1`
/// (one per socket_vmnet pool slot). `discover_nics` runs
/// `ip -json link show` inside the VM, selects `limaN` interfaces, orders them
/// by numeric suffix, and builds the `slot_index → interface_name` map.
///
/// If discovered NIC count ≠ `max_slots`, this is NON-FATAL: a warning is logged
/// and the daemon continues with the actually-discovered count. Pool resize is
/// handled by the pool-resize handler when all sessions are stopped.
///
/// ## Baseline `eth0` nft policy
///
/// Applied via `limactl shell … nft -f -` on stdin. The policy:
///
/// - Default drop on `output` (egress from the gateway VM itself via `eth0`)
/// - Allow conntrack established/related (re-originated upstream responses from
///   gateway containers that have already been intercepted and re-opened)
/// - Allow DNS egress (port 53 UDP/TCP) so Lima's embedded resolver can reach
///   upstream nameservers
/// - Allow established/related INPUT (return traffic for DNS + upstream)
///
/// The gateway VM's `eth0` is NEVER `restrict=on` — it is the sanctioned egress
/// uplink. This nft policy is its defense-in-depth control, not a block.
#[cfg(target_os = "macos")]
use std::collections::HashMap;
#[cfg(target_os = "macos")]
use std::path::{Path, PathBuf};
#[cfg(target_os = "macos")]
use std::process::Command;
#[cfg(target_os = "macos")]
use std::sync::{Arc, Mutex};
#[cfg(target_os = "macos")]
use std::thread;
#[cfg(target_os = "macos")]
use std::time::{Duration, Instant};

#[cfg(target_os = "macos")]
use tracing::{info, warn};

#[cfg(target_os = "macos")]
use crate::error::SandboxError;
#[cfg(target_os = "macos")]
use crate::lima::{LimaExecutor, LimaOp};
#[cfg(target_os = "macos")]
use crate::network::VmnetPool;
#[cfg(target_os = "macos")]
use crate::process::run_with_timeout;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Lima instance name for the daemon-owned gateway VM.
#[cfg(target_os = "macos")]
pub const GATEWAY_INSTANCE_NAME: &str = "sandboxd-gateway";

/// Docker bridge name created inside the gateway Lima VM for upstream egress.
/// All gateway containers attach to this bridge as their default route.
#[cfg(target_os = "macos")]
pub const EGRESS_BRIDGE_NAME: &str = "sandboxd-egress";

/// Ubuntu 24.04 LTS aarch64 cloud image URL (Apple Silicon only).
/// Shared with the Linux code path in `lima.rs`.
#[cfg(target_os = "macos")]
pub const UBUNTU_NOBLE_ARM64_URL: &str =
    "https://cloud-images.ubuntu.com/releases/noble/release/ubuntu-24.04-server-cloudimg-arm64.img";

/// Minimum Lima version required (embedded in the template `minimumLimaVersion`).
#[cfg(target_os = "macos")]
pub const MIN_LIMA_VERSION: &str = "1.2.0";

/// How often to poll `docker info` during readiness wait.
#[cfg(target_os = "macos")]
const DOCKER_READY_POLL_INTERVAL: Duration = Duration::from_secs(2);

/// Total timeout waiting for the gateway Docker socket to become ready.
///
/// On first boot this covers cloud-init + Docker install (apt install docker.io
/// on Ubuntu 24.04 takes 2-3 minutes on this host). On subsequent daemon
/// restarts the VM is already provisioned so the socket becomes ready in a few
/// seconds. 300 seconds is generous headroom for the worst-case first-boot path.
#[cfg(target_os = "macos")]
const DOCKER_READY_TIMEOUT: Duration = Duration::from_secs(300);

/// Timeout for `limactl create sandboxd-gateway`. The Ubuntu cloud image
/// download (~600 MiB) dominates on first run; subsequent creates skip the
/// download via Lima's cache. Matches `BASE_CREATE_TIMEOUT` in `lima.rs`.
#[cfg(target_os = "macos")]
const GATEWAY_CREATE_TIMEOUT: Duration = Duration::from_secs(1200);

/// Timeout for `limactl start sandboxd-gateway`. Cloud-init provisioning
/// (docker.io apt install) on first boot is the slow path.
#[cfg(target_os = "macos")]
const GATEWAY_START_TIMEOUT: Duration = Duration::from_secs(600);

/// Timeout for `limactl stop sandboxd-gateway`.
#[cfg(target_os = "macos")]
const GATEWAY_STOP_TIMEOUT: Duration = Duration::from_secs(60);

/// Timeout for `limactl shell` NIC-discovery and nft-application commands.
#[cfg(target_os = "macos")]
const GATEWAY_SHELL_TIMEOUT: Duration = Duration::from_secs(30);

/// Timeout for `limactl list --json`.
#[cfg(target_os = "macos")]
const GATEWAY_LIST_TIMEOUT: Duration = Duration::from_secs(10);

/// Timeout for Docker operations inside the gateway VM (bridge create, etc.).
#[cfg(target_os = "macos")]
const DOCKER_OP_TIMEOUT: Duration = Duration::from_secs(30);

/// Timeout for nft injection via `nft -f -` on stdin inside the gateway VM.
#[cfg(target_os = "macos")]
const NFT_INJECT_TIMEOUT: Duration = Duration::from_secs(15);

// ---------------------------------------------------------------------------
// NIC map
// ---------------------------------------------------------------------------

/// Result of gateway NIC discovery: a mapping from pool slot index to the
/// in-VM interface name for that slot (`lima0`, `lima1`, …).
///
/// Slot 0 → `lima0`, slot 1 → `lima1`, etc. The map is keyed by slot index.
/// The count of entries may differ from `max_slots` (see module-level note on
/// non-fatal mismatch).
#[cfg(target_os = "macos")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NicMap {
    /// Maps slot index → in-VM interface name.
    pub slot_to_iface: HashMap<u16, String>,
    /// Number of NICs discovered (may differ from `max_slots`).
    pub discovered_count: usize,
}

#[cfg(target_os = "macos")]
impl NicMap {
    /// Look up the interface name for a given slot.
    pub fn interface_for_slot(&self, slot: u16) -> Option<&str> {
        self.slot_to_iface.get(&slot).map(|s| s.as_str())
    }
}

// ---------------------------------------------------------------------------
// NIC discovery parser (pure, testable without a live VM)
// ---------------------------------------------------------------------------

/// A single entry from `ip -json link show` output, capturing the fields we need.
///
/// The full `ip link` JSON has many more fields; we only deserialize what
/// `discover_nics_from_ip_json` needs.
#[cfg(target_os = "macos")]
#[derive(Debug, serde::Deserialize)]
pub struct IpLinkEntry {
    /// Interface name, e.g. `"eth0"`, `"lima0"`, `"lima1"`.
    pub ifname: String,
    /// Interface index. Not used for slot mapping (we key on name) but
    /// included for completeness and potential future debugging.
    #[allow(dead_code)]
    pub ifindex: u32,
}

/// Parse the output of `ip -json link show` and extract the `limaN` interfaces.
///
/// Selection rules:
/// - Include interfaces whose name matches `^lima(\d+)$`.
/// - Exclude `eth0` (management/slirp NIC) and any non-`lima` names.
/// - Order by numeric suffix to produce the canonical slot→NIC mapping.
///
/// Returns `(slot_to_iface, discovered_count)`.
///
/// This function is pure and has no I/O; it can be unit-tested by feeding
/// representative JSON.
#[cfg(target_os = "macos")]
pub fn discover_nics_from_ip_json(json: &str) -> Result<NicMap, SandboxError> {
    let entries: Vec<IpLinkEntry> = serde_json::from_str(json).map_err(|e| {
        SandboxError::Internal(format!(
            "gateway NIC discovery: failed to parse `ip -json link` output: {e}"
        ))
    })?;

    // Collect (numeric_suffix, name) pairs for limaN interfaces.
    let mut lima_nics: Vec<(u16, String)> = Vec::new();
    for entry in &entries {
        if let Some(suffix) = entry.ifname.strip_prefix("lima") {
            if let Ok(n) = suffix.parse::<u16>() {
                lima_nics.push((n, entry.ifname.clone()));
            }
        }
    }

    // Sort by numeric suffix so slot 0 → lima0, slot 1 → lima1, etc.
    lima_nics.sort_by_key(|(n, _)| *n);

    let discovered_count = lima_nics.len();

    // Build the slot_index → interface_name map: the nth entry (0-indexed) in
    // the sorted list maps to slot n.
    let slot_to_iface: HashMap<u16, String> = lima_nics
        .into_iter()
        .enumerate()
        .map(|(idx, (_, name))| (idx as u16, name))
        .collect();

    Ok(NicMap {
        slot_to_iface,
        discovered_count,
    })
}

// ---------------------------------------------------------------------------
// Template generation
// ---------------------------------------------------------------------------

/// Generate the Lima YAML template for the `sandboxd-gateway` instance.
///
/// The template includes:
/// - `vmType: qemu` (HVF-accelerated on Apple Silicon; never VZ)
/// - N socket_vmnet NIC entries (one per pool slot), from `VmnetPool::slot_socket_path`
/// - Forwarded Docker socket at `{{.Dir}}/gateway-docker.sock`
/// - `containerd: {system: false, user: false}` (Docker handles containers)
/// - Provisioning scripts: docker.io install, eth0 MTU clamp, IPv6 disable on
///   limaN NICs, no-DHCP netplan for limaN NICs
///
/// The `max_slots` parameter determines the number of `networks:` entries.
#[cfg(target_os = "macos")]
pub fn generate_gateway_template(max_slots: u16) -> String {
    // Build the networks section: one socket: entry per pool slot.
    let networks_section = (0..max_slots)
        .map(|slot| {
            format!(
                "  - socket: {}\n",
                crate::network::vmnet_slot_socket_path(slot)
            )
        })
        .collect::<String>();

    // Build the no-DHCP netplan printf lines for each limaN NIC.
    // Without this, systemd-networkd tries DHCP on every limaN NIC and
    // blocks boot on `network-online.target` waiting for leases that never arrive.
    //
    // We use `printf` rather than a heredoc because the Lima template is a YAML
    // block scalar (`script: |`) — heredoc terminators must appear at column 0 in
    // the shell script, but column-0 content in a YAML block scalar terminates the
    // scalar and is parsed as YAML, causing a parse error. `printf` appended line
    // by line avoids the column-0 heredoc marker entirely.
    let netplan_lima_entries = (0..max_slots)
        .map(|slot| {
            // Each NIC block: "    lima{n}:" (4-space indent under `ethernets:`)
            // followed by dhcp4/optional at 6-space indent. The \\n sequences
            // are the printf escape sequences for newlines inside the shell string.
            format!(
                "      printf '    lima{slot}:\\n      dhcp4: no\\n      optional: true\\n' >> /etc/netplan/99-sandbox-vmnet.yaml\n"
            )
        })
        .collect::<String>();

    // Build the sysctl disable-IPv6 lines for each limaN NIC.
    let ipv6_disable_lines = (0..max_slots)
        .map(|slot| format!("      sysctl -w net.ipv6.conf.lima{slot}.disable_ipv6=1\n"))
        .collect::<String>();

    format!(
        r#"vmType: "qemu"
minimumLimaVersion: "{MIN_LIMA_VERSION}"

images:
  - location: "{UBUNTU_NOBLE_ARM64_URL}"
    arch: aarch64

cpus: 2
memory: "2GiB"
disk: "20GiB"

# N socket_vmnet NICs — one per pool slot.
# Count = max_macos_sessions (default 8). Fixed at instance creation.
networks:
{networks_section}
# Expose the guest Docker socket to the macOS host via Lima forwarding.
portForwards:
  - guestSocket: "/var/run/docker.sock"
    hostSocket: "{{{{.Dir}}}}/gateway-docker.sock"

containerd:
  system: false
  user: false

provision:
  - mode: system
    script: |
      #!/bin/bash
      # Install Docker Engine from Ubuntu packages (docker.io — NOT docker-ce).
      # Matches the Linux base/gateway provisioning path:
      # no extra apt source, fewer moving parts, works offline-after-mirror.
      # Retry loop because Lima slirp can drop packets under concurrent fetches.
      until apt-get update -qq && apt-get install -y docker.io; do
        echo "apt retry..." >&2; sleep 5
      done
      systemctl enable docker
      systemctl start docker
      # Restrict the Docker socket to the docker group — never world-writable.
      # A world-writable socket lets any in-VM process (incl. a compromised
      # gateway container) reach Docker and escalate to root-in-gateway-VM,
      # defeating "the gateway pipeline is isolated from operators" for ALL
      # sessions at once.
      groupadd -f docker
      chgrp docker /var/run/docker.sock
      chmod 660 /var/run/docker.sock
      # Add the Lima SSH user to the docker group so Lima's socket-forward
      # (which connects as the login user via SSH) can read /var/run/docker.sock.
      # Lima creates an operator user with the same UID as the macOS host user.
      # macOS UIDs typically start at 500 (unlike Linux where they start at 1000),
      # so we add all non-system users (UID 500–65533) to the docker group. This
      # is portable across macOS hosts without baking in a specific username.
      for u in $(awk -F: '$3 >= 500 && $3 < 65534 {{print $1}}' /etc/passwd); do
        usermod -aG docker "$u"
      done
  - mode: system
    script: |
      #!/bin/bash
      # Clamp eth0 (slirp/Lima management NIC) MTU to 1280.
      # Lima/slirp does not relay host PMTU into the guest; on paths with
      # PMTU < 1500 (PPPoE, WiFi, VPN) TCP segments get silently dropped.
      # 1280 is the IPv6 minimum — safe on all paths. The socket_vmnet NICs
      # (lima0…) use native L2 MTU and are unaffected.
      # Clamp by NIC name (eth0 = slirp/management), never by index.
      #
      # printf is used instead of a heredoc because the Lima template is a
      # YAML block scalar — heredoc terminators at column 0 would be
      # misinterpreted by the YAML parser as end-of-scalar.
      printf 'network:\n  ethernets:\n    eth0:\n      mtu: 1280\n' \
        > /etc/netplan/99-sandbox-mtu.yaml
      chmod 0644 /etc/netplan/99-sandbox-mtu.yaml
      netplan apply
  - mode: system
    script: |
      #!/bin/bash
      # Disable IPv6 on the socket_vmnet NICs (lima0…limaN-1) and
      # configure them as link-up only with no DHCP.
      #
      # Rationale:
      # - The in-container ruleset already drops ip6, but disabling IPv6 on
      #   the host-side NIC closes the parallel link-local/RA path — a guest
      #   cannot emit IPv6 RAs or link-local multicast onto the segment to
      #   reach a neighbor.
      # - Without `dhcp4: no` + `optional: true`, Ubuntu systemd-networkd
      #   attempts DHCP on every unconfigured NIC and BLOCKS boot waiting for
      #   leases that never arrive on network-identifier segments (no DHCP).
      #
      # printf is used to write the netplan YAML to avoid column-0 heredoc
      # markers that would break YAML parsing of the Lima template.
{ipv6_disable_lines}      printf 'network:\n  ethernets:\n' > /etc/netplan/99-sandbox-vmnet.yaml
{netplan_lima_entries}      chmod 0644 /etc/netplan/99-sandbox-vmnet.yaml
      netplan apply
"#,
    )
}

// ---------------------------------------------------------------------------
// Baseline eth0 nft ruleset
// ---------------------------------------------------------------------------

/// Generate the baseline egress nft policy for the gateway VM's `eth0` NIC
/// (the Lima/QEMU user-mode SLIRP management uplink).
///
/// ## Traffic paths on the gateway VM
///
/// The gateway VM has two distinct forwarding paths on `eth0`:
///
/// 1. **FORWARD chain**: Gateway container traffic — Docker NAT/MASQUERADE takes
///    packets from the `sandboxd-egress` bridge, masquerades them as the gateway
///    VM's IP, and forwards them out `eth0`. This path is managed entirely by
///    Docker's own iptables/nft rules in the `ip filter`/`ip nat` tables. Our
///    policy must NOT interfere with it, and deliberately does not — this table
///    declares no FORWARD chain, so Docker NAT is completely unaffected.
///
/// 2. **OUTPUT chain**: Traffic originating from the gateway VM's own host-namespace
///    processes — Lima agents, Docker daemon (image pulls, registry access),
///    systemd-resolved (DNS forwarding), etc. This is what our
///    `sandboxd-gateway-eth0` table governs, and this is the surface that must be
///    bounded to limit blast radius if a gateway component escapes its container
///    namespace into the VM's host namespace.
///
/// ## Policy design
///
/// **OUTPUT (gateway VM's own processes on `eth0`):**
/// - Non-eth0 interfaces (loopback, limaN Docker bridges): pass through — these
///   are handled by per-session container nftables and Docker's own rules.
/// - `ct state established,related`: allow return traffic for connections already
///   open — this rule is load-bearing for all allowed outbound flows.
/// - Explicit port allow-list for what VM-host-namespace processes genuinely need:
///   DNS (port 53 TCP+UDP), HTTPS (port 443), HTTP (port 80). This covers Docker
///   daemon image pulls, Lima agents (HTTPS), and systemd-resolved DNS forwarding.
/// - Default drop: all other VM-originated new outbound on eth0 is blocked, so a
///   compromised component that escapes into the gateway VM's host namespace cannot
///   freely egress to arbitrary destinations.
///
/// **INPUT (incoming on `eth0`):**
/// - `ct state established,related`: accept return traffic for connections the VM
///   opened.
/// - Drop new/invalid: external parties cannot initiate connections into the
///   gateway VM.
///
/// ## Why container egress is unaffected
///
/// Gateway container re-originated traffic traverses the FORWARD chain (Docker
/// NAT/MASQUERADE), not the OUTPUT chain. Because this table declares no FORWARD
/// chain, Docker's iptables FORWARD rules operate without any interference. The
/// OUTPUT restrictions bind only VM-host-namespace processes — which is exactly
/// the blast-radius bound required: a compromised component that escapes its
/// container netns into the gateway VM's host network namespace is constrained to
/// DNS + HTTPS + HTTP, not arbitrary outbound.
#[cfg(target_os = "macos")]
pub fn generate_gateway_eth0_nft_policy() -> String {
    // The ruleset is applied inside the gateway Lima VM via `nft -f` on a tempfile.
    // It uses a sandboxd-specific table rather than modifying the filter table so
    // it does not conflict with Docker's iptables/nft rules.
    //
    // Idempotency across daemon restarts (daemon restart against a still-running
    // gateway VM must not fail):
    //
    //   table inet sandboxd-gateway-eth0 {}      <- create-if-absent (no-op if exists)
    //   flush table inet sandboxd-gateway-eth0   <- atomically clear all rules
    //   table inet sandboxd-gateway-eth0 { ... } <- re-add the full ruleset
    //
    // This mirrors the `sandbox_dnat`/`sandbox_policy` pattern in `policy.rs`.
    r#"# sandboxd baseline egress policy for gateway VM eth0.
#
# eth0 is the Lima/QEMU user-mode SLIRP management NIC — the gateway VM's
# only sanctioned path to the internet. This table bounds the blast radius
# of a compromised gateway component by restricting the gateway VM's own
# host-namespace processes to the specific ports they genuinely need.
#
# Traffic path clarification:
# - Gateway CONTAINER egress goes through the FORWARD chain (Docker NAT), not
#   this OUTPUT chain. This table has no FORWARD chain, so Docker NAT is
#   completely unaffected — container egress policy is enforced separately by
#   the per-session Envoy/nft pipeline.
# - OUTPUT governs only the gateway VM's host-namespace processes (Lima agents,
#   Docker daemon, systemd-resolved, etc.). These are restricted to an explicit
#   port allow-list so a component that escapes its container namespace into the
#   VM host namespace cannot freely egress to arbitrary destinations.
# - The INPUT chain drops unsolicited inbound on eth0.

# Create-if-absent then flush: idempotent across daemon restarts.
table inet sandboxd-gateway-eth0 {}
flush table inet sandboxd-gateway-eth0

table inet sandboxd-gateway-eth0 {
  chain output-eth0 {
    type filter hook output priority 0; policy drop;

    # Allow loopback traffic (Docker bridge + in-VM processes).
    oifname "lo" accept

    # Do NOT restrict traffic on socket_vmnet NICs (lima0…) or Docker bridges —
    # those are managed by per-session gateway container nftables and Docker's
    # own FORWARD chain rules. This policy controls only eth0.
    oifname != "eth0" accept

    # Allow return traffic for connections already opened.
    # This rule is load-bearing: all port-specific accepts below depend on it
    # for the return path (established/related flows).
    ct state established,related accept

    # DNS: systemd-resolved forwards queries to upstream resolvers.
    ip protocol udp udp dport 53 accept
    ip protocol tcp tcp dport 53 accept

    # HTTPS: Docker daemon pulls gateway images from registries; Lima agents
    # communicate over HTTPS.
    ip protocol tcp tcp dport 443 accept

    # HTTP: apt-get package updates; some Docker registries use plain HTTP.
    ip protocol tcp tcp dport 80 accept

    # Drop invalid/untracked packets.
    ct state invalid drop

    # Default drop: all other VM-host-namespace new outbound on eth0 is
    # blocked. A component that escapes its container namespace cannot freely
    # egress — only DNS, HTTPS, and HTTP are permitted.
  }

  chain input-eth0 {
    type filter hook input priority 0; policy accept;

    # Accept established/related on eth0 (return traffic for VM-opened connections).
    iifname "eth0" ct state established,related accept

    # Drop new/invalid inbound connections on eth0 — no external host
    # should be initiating connections to the gateway VM directly.
    iifname "eth0" ct state new,invalid drop
  }
}
"#
    .to_string()
}

// ---------------------------------------------------------------------------
// Shared command helpers
// ---------------------------------------------------------------------------

/// Apply minimal-reconstruction environment sanitization to a `limactl` command.
///
/// Mirrors the env-clearing discipline in `run_limactl_direct` (daemon's `broker.rs`):
/// clear the inherited environment and reconstruct only what `limactl` needs
/// (`LIMA_HOME`, `PATH`, `HOME`, `TERM`). This prevents stale env vars from
/// the daemon process (e.g., `LIMA_HOME` pointing to a user's personal Lima,
/// `DOCKER_HOST`, or any shell export) from influencing gateway operations.
///
/// `daemon_uid` is used to resolve the daemon's LIMA_HOME path; the caller
/// supplies it directly so this function has no side effects beyond building
/// the command.
#[cfg(target_os = "macos")]
fn apply_limactl_env(cmd: &mut Command, daemon_uid: u32) {
    let lima_home = crate::lima::operator_lima_home(daemon_uid);
    let lima_home_str = lima_home.to_string_lossy().into_owned();
    let current_path = std::env::var("PATH").unwrap_or_default();
    let path_value = format!("/opt/homebrew/bin:/usr/local/bin:{current_path}");
    let home = std::env::var("HOME").unwrap_or_default();
    if home.is_empty() {
        tracing::warn!(
            "apply_limactl_env: HOME is unset; limactl may fail to locate its config directory"
        );
    }

    cmd.env_clear()
        .env("LIMA_HOME", &lima_home_str)
        .env("PATH", &path_value)
        .env("HOME", home)
        .env("TERM", "dumb");
}

/// Apply minimal-reconstruction environment sanitization to a `docker` command.
///
/// Clears the inherited environment and reconstructs only a minimal `PATH`.
/// The `-H unix://<socket>` flag (already in the caller's args) is the sole
/// authority for which Docker daemon is targeted; stripping `DOCKER_HOST` and
/// other Docker env vars (e.g. `DOCKER_CONFIG`, `DOCKER_TLS_VERIFY`) prevents
/// any ambient override from redirecting the command to a different daemon.
#[cfg(target_os = "macos")]
fn apply_docker_env(cmd: &mut Command) {
    let current_path = std::env::var("PATH").unwrap_or_default();
    let path_value = format!("/opt/homebrew/bin:/usr/local/bin:{current_path}");
    let home = std::env::var("HOME").unwrap_or_default();
    if home.is_empty() {
        tracing::warn!(
            "apply_docker_env: HOME is unset; docker CLI may fail to locate its config directory"
        );
    }

    // env_clear removes DOCKER_HOST and all other ambient overrides; then we
    // reconstruct only the vars the docker CLI needs to locate its binary
    // dependencies.
    cmd.env_clear().env("PATH", &path_value).env("HOME", home);
}

// ---------------------------------------------------------------------------
// GatewayLimaManager
// ---------------------------------------------------------------------------

/// Manages the `sandboxd-gateway` Lima instance and its Docker infrastructure.
///
/// Constructed once at daemon startup (macOS only) with a reference to the
/// `VmnetPool` (for socket paths) and the `LimaExecutor` (for `limactl` ops
/// via the daemon-uid degenerate path).
///
/// After `ensure_ready` completes successfully:
/// - `nic_map()` returns the discovered slot→NIC mapping.
/// - The `sandboxd-egress` Docker bridge exists in the gateway VM.
/// - The baseline `eth0` nft policy is in place.
#[cfg(target_os = "macos")]
pub struct GatewayLimaManager {
    /// Daemon's LIMA_HOME: `/var/lib/sandboxd/<daemon-uid>/lima/`.
    daemon_lima_home: PathBuf,

    /// Derived path to the forwarded Docker socket:
    /// `<daemon_lima_home>/sandboxd-gateway/gateway-docker.sock`
    gateway_docker_socket: PathBuf,

    /// Daemon uid — passed as `op_uid` to the executor (degenerate path).
    daemon_uid: u32,

    /// Operator-execution seam for `limactl` ops (all go via daemon_uid).
    executor: Arc<dyn LimaExecutor>,

    /// Number of pool slots (from `VmnetPool::max_slots`).
    max_slots: u16,

    /// Discovered slot→NIC map, populated after a successful `ensure_ready`.
    nic_map: Mutex<Option<NicMap>>,
}

#[cfg(target_os = "macos")]
impl GatewayLimaManager {
    /// Construct a new manager.
    ///
    /// - `daemon_lima_home` — the daemon's LIMA_HOME root (e.g.
    ///   `/var/lib/sandboxd/<daemon_uid>/lima/`).
    /// - `executor` — the `LimaExecutor` implementation (on macOS this is
    ///   `AgentBrokerExecutor`; when `op_uid == daemon_uid` it routes to
    ///   `run_limactl_direct`).
    /// - `daemon_uid` — the daemon's own uid; passed as `op_uid` on every
    ///   `limactl` call so the executor takes the degenerate direct path.
    /// - `pool` — the `VmnetPool` used to derive socket paths for the template.
    pub fn new(
        daemon_lima_home: PathBuf,
        executor: Arc<dyn LimaExecutor>,
        daemon_uid: u32,
        pool: &VmnetPool,
    ) -> Self {
        let gateway_docker_socket = daemon_lima_home
            .join(GATEWAY_INSTANCE_NAME)
            .join("gateway-docker.sock");
        let max_slots = pool.max_slots();
        Self {
            daemon_lima_home,
            gateway_docker_socket,
            daemon_uid,
            executor,
            max_slots,
            nic_map: Mutex::new(None),
        }
    }

    /// Return the path to the forwarded Docker socket on the macOS host.
    ///
    /// This socket becomes accessible after `ensure_ready` succeeds and the
    /// gateway VM's Docker daemon is fully up.
    pub fn gateway_docker_socket(&self) -> &Path {
        &self.gateway_docker_socket
    }

    /// Return the cached NIC map, or `None` if `ensure_ready` has not completed.
    pub fn nic_map(&self) -> Option<NicMap> {
        self.nic_map
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    /// Full gateway-instance bring-up sequence (startup step 4a–4g).
    ///
    /// Idempotent: safe to call on every daemon restart. The gateway instance
    /// is persistent; if already running this verifies the forwarded socket and
    /// returns quickly.
    ///
    /// Steps:
    /// 1. Determine instance state (absent / stopped / running).
    /// 2. If absent: write template → `limactl create` → `limactl start`.
    /// 3. If stopped: `limactl start`.
    /// 4. If running: proceed.
    /// 5. Poll `docker -H <sock> info` until ready (60 s / 2 s).
    /// 6. Discover slot→NIC map; cache it; warn on count mismatch.
    /// 7. Ensure `sandboxd-egress` NAT bridge (idempotent).
    /// 8. Apply baseline `eth0` nft policy.
    pub fn ensure_ready(&self) -> Result<(), SandboxError> {
        let state = self.query_instance_state()?;
        info!(state = %state, "gateway Lima instance state at startup");

        match state.as_str() {
            "Running" => {
                info!("gateway Lima instance already running; verifying forwarded socket");
                // Verify reachability below (docker info poll).
            }
            "Stopped" => {
                info!("gateway Lima instance stopped; starting it");
                self.start_instance()?;
            }
            "None" => {
                info!("gateway Lima instance absent; creating and starting it");
                self.create_instance()?;
                self.start_instance()?;
            }
            other => {
                // Unknown Lima status — attempt a start anyway; limactl is
                // idempotent for already-running instances.
                warn!(
                    status = other,
                    "gateway Lima instance in unknown state; attempting start"
                );
                self.start_instance().unwrap_or_else(|e| {
                    warn!(error = %e, "gateway Lima start returned error; continuing");
                });
            }
        }

        // Step 4d: poll `docker -H <sock> info` until the Docker daemon inside
        // the gateway VM is ready.
        self.wait_docker_ready()?;

        // Step 4e: discover slot→NIC map.
        let nic_map = self.discover_nics()?;
        let discovered = nic_map.discovered_count;
        if discovered != self.max_slots as usize {
            warn!(
                discovered,
                expected = self.max_slots,
                "gateway Lima NIC count mismatch: discovered {} NICs but max_slots={}. \
                 Pool resize requires all sessions to be stopped and the gateway instance \
                 to be recreated. Continuing this run with the {} actually-discovered NICs.",
                discovered,
                self.max_slots,
                discovered
            );
        } else {
            info!(
                nic_count = discovered,
                "gateway Lima NIC discovery complete"
            );
        }
        {
            let mut guard = self.nic_map.lock().unwrap_or_else(|e| e.into_inner());
            *guard = Some(nic_map);
        }

        // Step 4f: ensure sandboxd-egress bridge.
        self.ensure_egress_bridge()?;

        // Step 4g: apply baseline eth0 nft policy.
        self.apply_eth0_nft_policy()?;

        info!("gateway Lima instance ready");
        Ok(())
    }

    // -------------------------------------------------------------------------
    // Private helpers
    // -------------------------------------------------------------------------

    /// Query the Lima instance state by running `limactl list --json`.
    ///
    /// Returns `"Running"`, `"Stopped"`, or `"None"` (instance absent).
    fn query_instance_state(&self) -> Result<String, SandboxError> {
        let output = self.executor.run(
            self.daemon_uid,
            LimaOp::ListJson,
            GATEWAY_LIST_TIMEOUT,
            "gateway: limactl list",
        )?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(SandboxError::Lima(format!(
                "gateway: limactl list failed: {stderr}"
            )));
        }

        let json_str = String::from_utf8_lossy(&output.stdout);
        // Each line of limactl list --json is a separate JSON object.
        for line in json_str.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            let obj: serde_json::Value = match serde_json::from_str(line) {
                Ok(v) => v,
                Err(_) => continue,
            };
            let name = obj.get("name").and_then(|v| v.as_str()).unwrap_or_default();
            if name == GATEWAY_INSTANCE_NAME {
                let status = obj
                    .get("status")
                    .and_then(|v| v.as_str())
                    .unwrap_or("Unknown")
                    .to_string();
                return Ok(status);
            }
        }

        // Instance not found in the list.
        Ok("None".to_string())
    }

    /// Write the gateway template YAML to a file and run `limactl create`.
    fn create_instance(&self) -> Result<(), SandboxError> {
        let template_content = generate_gateway_template(self.max_slots);

        // Write the template to a sibling directory of LIMA_HOME — NOT inside
        // LIMA_HOME itself. If the template is written inside LIMA_HOME (e.g.
        // at LIMA_HOME/sandboxd-gateway/lima.yaml), limactl will see the
        // directory during instance enumeration before `limactl create` runs
        // and will report "instance already exists". Writing outside LIMA_HOME
        // sidesteps this, mirroring the `write_operator_readable_template`
        // pattern in `lima.rs`.
        let template_dir = self
            .daemon_lima_home
            .parent()
            .ok_or_else(|| {
                SandboxError::Internal(format!(
                    "gateway: daemon_lima_home {} has no parent",
                    self.daemon_lima_home.display()
                ))
            })?
            .to_path_buf();

        std::fs::create_dir_all(&template_dir).map_err(|e| {
            SandboxError::Internal(format!(
                "gateway: failed to create template dir {}: {e}",
                template_dir.display()
            ))
        })?;

        let template_path = template_dir.join("sandboxd-gateway-tmpl.yaml");
        std::fs::write(&template_path, &template_content).map_err(|e| {
            SandboxError::Internal(format!(
                "gateway: failed to write template to {}: {e}",
                template_path.display()
            ))
        })?;
        info!(path = %template_path.display(), "gateway Lima template written");

        let result = self.executor.run(
            self.daemon_uid,
            LimaOp::Create {
                vm: GATEWAY_INSTANCE_NAME,
                yaml_path: &template_path,
                // No per-operator owner marker for the gateway instance —
                // it is daemon infrastructure, not tracked by the Lima orphan
                // reaper's per-operator marker scheme.
                owner: "",
            },
            GATEWAY_CREATE_TIMEOUT,
            "gateway: limactl create",
        );

        // Clean up the temp template file regardless of success/failure.
        let _ = std::fs::remove_file(&template_path);

        let output = result?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(SandboxError::Lima(format!(
                "gateway: limactl create failed: {stderr}"
            )));
        }

        info!("gateway Lima instance created");
        Ok(())
    }

    /// Run `limactl start sandboxd-gateway`.
    fn start_instance(&self) -> Result<(), SandboxError> {
        let start_timeout_s = GATEWAY_START_TIMEOUT.as_secs() as u32;

        let output = self.executor.run(
            self.daemon_uid,
            LimaOp::Start {
                vm: GATEWAY_INSTANCE_NAME,
                // The gateway instance NEVER uses the qemu-wrapper (restrict=on
                // applies to sandbox VMs only; the gateway VM's eth0 is the
                // sanctioned egress uplink). Pass an empty path to signal
                // "no wrapper" — run_limactl_direct checks for empty string.
                qemu_wrapper: Path::new(""),
                // The gateway VM is not a sandbox VM; no device lockdown.
                hardened: false,
                memory_mb: 2048,
                cpus: 2,
                start_timeout_s,
                // No Docker bridge for the gateway VM itself (it connects via
                // the forwarded socket, not via a bridge NIC).
                bridge: None,
                unrestricted_slirp_for_provisioning: false,
            },
            GATEWAY_START_TIMEOUT + Duration::from_secs(60),
            "gateway: limactl start",
        )?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(SandboxError::Lima(format!(
                "gateway: limactl start failed: {stderr}"
            )));
        }

        info!("gateway Lima instance started");
        Ok(())
    }

    /// Poll until the gateway Docker daemon is reachable via the forwarded socket.
    ///
    /// Two-phase readiness:
    ///
    /// 1. **Inside-VM check (via `limactl shell`)**: wait until `docker info`
    ///    succeeds inside the VM. This is the authoritative signal that the Docker
    ///    daemon is running and its socket is available in the VM, regardless of
    ///    whether the Lima host-side socket forward is set up yet.
    ///
    /// 2. **Host-side socket forward check**: once Docker is confirmed running
    ///    inside the VM, poll the forwarded socket path with `docker -H` until
    ///    it is accessible from the macOS host. Lima establishes the socket
    ///    forward via SSH at VM-start time; if the forward was set up before
    ///    Docker started (during cloud-init), Lima may need a moment to re-detect
    ///    the socket.
    fn wait_docker_ready(&self) -> Result<(), SandboxError> {
        let deadline = Instant::now() + DOCKER_READY_TIMEOUT;

        info!(
            socket = %self.gateway_docker_socket.display(),
            timeout_s = DOCKER_READY_TIMEOUT.as_secs(),
            "waiting for gateway Docker daemon to be ready"
        );

        // Phase 1: wait for Docker inside the VM to be running.
        loop {
            let docker_check = self.run_gateway_shell(
                "docker info >/dev/null 2>&1 && echo READY",
                Duration::from_secs(15),
            );

            match docker_check {
                Ok(output) if output.status.success() => {
                    let stdout = String::from_utf8_lossy(&output.stdout);
                    if stdout.contains("READY") {
                        info!("gateway Docker daemon running inside VM");
                        break;
                    }
                }
                _ => {}
            }

            if Instant::now() >= deadline {
                return Err(SandboxError::Gateway(format!(
                    "Docker daemon did not start inside gateway VM within {}s",
                    DOCKER_READY_TIMEOUT.as_secs()
                )));
            }
            thread::sleep(DOCKER_READY_POLL_INTERVAL);
        }

        // Phase 2: wait for the host-side forwarded socket to be accessible.
        // Lima's host agent establishes the SSH socket forward; it may retry a
        // few times after the in-VM Docker socket appears.
        let socket_str = format!("unix://{}", self.gateway_docker_socket.display());
        loop {
            let mut cmd = Command::new("docker");
            apply_docker_env(&mut cmd);
            cmd.args(["-H", &socket_str, "info"]);

            let result = run_with_timeout(
                &mut cmd,
                Duration::from_secs(5),
                "gateway: docker info probe via forwarded socket",
            );

            match result {
                Ok(output) if output.status.success() => {
                    info!("gateway Docker socket accessible from host");
                    return Ok(());
                }
                _ => {}
            }

            if Instant::now() >= deadline {
                return Err(SandboxError::Gateway(format!(
                    "gateway Docker socket at {} did not become ready within {}s",
                    self.gateway_docker_socket.display(),
                    DOCKER_READY_TIMEOUT.as_secs()
                )));
            }

            thread::sleep(DOCKER_READY_POLL_INTERVAL);
        }
    }

    /// Discover the slot→NIC map by running `ip -json link show` inside the VM.
    fn discover_nics(&self) -> Result<NicMap, SandboxError> {
        // Run `ip -json link show` inside the gateway VM.
        // We use a shell command via limactl shell.
        let output = self.run_gateway_shell("ip -json link show", GATEWAY_SHELL_TIMEOUT)?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(SandboxError::Internal(format!(
                "gateway NIC discovery: `ip -json link show` failed: {stderr}"
            )));
        }

        let json = String::from_utf8_lossy(&output.stdout);
        discover_nics_from_ip_json(&json)
    }

    /// Ensure the `sandboxd-egress` Docker bridge exists inside the gateway VM.
    ///
    /// Uses `docker -H <socket> network create`; idempotent — tolerates the
    /// "network already exists" error and treats it as success.
    fn ensure_egress_bridge(&self) -> Result<(), SandboxError> {
        let socket_str = format!("unix://{}", self.gateway_docker_socket.display());

        let mut cmd = Command::new("docker");
        apply_docker_env(&mut cmd);
        cmd.args([
            "-H",
            &socket_str,
            "network",
            "create",
            "--driver",
            "bridge",
            EGRESS_BRIDGE_NAME,
        ]);

        let output =
            run_with_timeout(&mut cmd, DOCKER_OP_TIMEOUT, "gateway: create egress bridge")?;

        if output.status.success() {
            info!(
                bridge = EGRESS_BRIDGE_NAME,
                "sandboxd-egress bridge created"
            );
            return Ok(());
        }

        let stderr = String::from_utf8_lossy(&output.stderr);
        // Tolerate "already exists" — idempotent.
        if stderr.contains("already exists") || stderr.contains("network with name") {
            info!(
                bridge = EGRESS_BRIDGE_NAME,
                "sandboxd-egress bridge already exists"
            );
            return Ok(());
        }

        Err(SandboxError::Gateway(format!(
            "gateway: failed to create {EGRESS_BRIDGE_NAME} bridge: {stderr}"
        )))
    }

    /// Apply the baseline default-drop egress nft policy on the gateway VM's
    /// `eth0` NIC via `nft -f -` with the ruleset on stdin.
    fn apply_eth0_nft_policy(&self) -> Result<(), SandboxError> {
        let ruleset = generate_gateway_eth0_nft_policy();
        self.inject_nft_via_shell(&ruleset)
    }

    /// Inject an nft ruleset inside the gateway VM via `limactl shell … nft -f -`.
    ///
    /// The ruleset is written to the child's stdin. The gateway VM's `nft`
    /// binary must be present (it is part of `nftables`, installed by default
    /// on Ubuntu 24.04).
    fn inject_nft_via_shell(&self, ruleset: &str) -> Result<(), SandboxError> {
        // We cannot pass stdin through `LimaExecutor::run` (which captures
        // output via `run_with_timeout`). Instead, use the shell command to
        // echo the ruleset and pipe into nft.
        //
        // The safest approach: write the ruleset to a tempfile in the gateway
        // VM via `limactl shell -- bash -c 'cat > /tmp/sandboxd-nft.conf'`
        // and then apply it with `nft -f /tmp/sandboxd-nft.conf`.
        //
        // This avoids shell quoting issues with the ruleset content on stdin.

        // Step 1: write the ruleset to a tempfile inside the VM.
        let write_cmd = format!(
            "cat > /tmp/sandboxd-gateway-eth0-nft.conf << 'SANDBOXD_NFT_EOF'\n{ruleset}\nSANDBOXD_NFT_EOF",
        );
        let write_output = self.run_gateway_shell(&write_cmd, GATEWAY_SHELL_TIMEOUT)?;
        if !write_output.status.success() {
            let stderr = String::from_utf8_lossy(&write_output.stderr);
            return Err(SandboxError::Internal(format!(
                "gateway nft: failed to write ruleset to tempfile in VM: {stderr}"
            )));
        }

        // Step 2: apply the ruleset. `nft` requires CAP_NET_ADMIN (root inside
        // the VM); the Lima SSH user connects as the operator (non-root), so we
        // use `sudo nft`. Lima provisions the Ubuntu VM with passwordless sudo
        // for all users, so this is safe in the gateway VM context.
        let apply_output = self.run_gateway_shell(
            "sudo nft -f /tmp/sandboxd-gateway-eth0-nft.conf",
            NFT_INJECT_TIMEOUT,
        )?;

        if !apply_output.status.success() {
            let stderr = String::from_utf8_lossy(&apply_output.stderr);
            return Err(SandboxError::Gateway(format!(
                "gateway nft: failed to apply eth0 baseline policy: {stderr}"
            )));
        }

        info!("gateway Lima eth0 baseline nft policy applied");
        Ok(())
    }

    /// Run a shell command inside the gateway Lima VM via `limactl shell`.
    ///
    /// This is the degenerate direct path (daemon_uid == op_uid) — the daemon
    /// runs `limactl` directly as `_sandbox`, which already owns the gateway
    /// instance's LIMA_HOME.
    fn run_gateway_shell(
        &self,
        command: &str,
        timeout: Duration,
    ) -> Result<std::process::Output, SandboxError> {
        let mut cmd = Command::new("limactl");
        apply_limactl_env(&mut cmd, self.daemon_uid);
        cmd.args(["shell", GATEWAY_INSTANCE_NAME, "--", "bash", "-c", command]);

        run_with_timeout(&mut cmd, timeout, "gateway: limactl shell")
    }

    /// Stop the gateway Lima instance.
    ///
    /// Called on clean daemon shutdown when no sessions are running.
    pub fn stop_instance(&self) -> Result<(), SandboxError> {
        let output = self.executor.run(
            self.daemon_uid,
            LimaOp::Stop {
                vm: GATEWAY_INSTANCE_NAME,
                force: false,
            },
            GATEWAY_STOP_TIMEOUT,
            "gateway: limactl stop",
        )?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(SandboxError::Lima(format!(
                "gateway: limactl stop failed: {stderr}"
            )));
        }

        info!("gateway Lima instance stopped");
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- NIC discovery parser (pure, hermetic) --------------------------------

    /// Representative `ip -json link show` output from a gateway VM with
    /// eth0 (management NIC) + lima0, lima1, lima2 (socket_vmnet NICs).
    const IP_JSON_3_SLOTS: &str = r#"[
    {"ifindex":1,"ifname":"lo","flags":["LOOPBACK","UP","LOWER_UP"],"link_type":"loopback","address":"00:00:00:00:00:00","broadcast":"00:00:00:00:00:00"},
    {"ifindex":2,"ifname":"eth0","flags":["BROADCAST","MULTICAST","UP","LOWER_UP"],"link_type":"ether","address":"52:55:0a:00:02:0f","broadcast":"ff:ff:ff:ff:ff:ff"},
    {"ifindex":3,"ifname":"lima0","flags":["BROADCAST","MULTICAST","UP","LOWER_UP"],"link_type":"ether","address":"52:55:0a:d1:80:00","broadcast":"ff:ff:ff:ff:ff:ff"},
    {"ifindex":4,"ifname":"lima1","flags":["BROADCAST","MULTICAST","UP","LOWER_UP"],"link_type":"ether","address":"52:55:0a:d1:80:08","broadcast":"ff:ff:ff:ff:ff:ff"},
    {"ifindex":5,"ifname":"lima2","flags":["BROADCAST","MULTICAST","UP","LOWER_UP"],"link_type":"ether","address":"52:55:0a:d1:80:10","broadcast":"ff:ff:ff:ff:ff:ff"}
]"#;

    /// Representative output with only eth0 and lima0 (1-slot pool).
    const IP_JSON_1_SLOT: &str = r#"[
    {"ifindex":1,"ifname":"lo","flags":["LOOPBACK","UP","LOWER_UP"],"link_type":"loopback","address":"00:00:00:00:00:00","broadcast":"00:00:00:00:00:00"},
    {"ifindex":2,"ifname":"eth0","flags":["BROADCAST","MULTICAST","UP","LOWER_UP"],"link_type":"ether","address":"52:55:0a:00:02:0f","broadcast":"ff:ff:ff:ff:ff:ff"},
    {"ifindex":3,"ifname":"lima0","flags":["BROADCAST","MULTICAST","UP","LOWER_UP"],"link_type":"ether","address":"52:55:0a:d1:80:00","broadcast":"ff:ff:ff:ff:ff:ff"}
]"#;

    /// Representative output with only eth0 — no limaN NICs at all
    /// (simulates a misconfigured or not-yet-attached gateway).
    const IP_JSON_NO_LIMA: &str = r#"[
    {"ifindex":1,"ifname":"lo","flags":["LOOPBACK","UP","LOWER_UP"],"link_type":"loopback","address":"00:00:00:00:00:00","broadcast":"00:00:00:00:00:00"},
    {"ifindex":2,"ifname":"eth0","flags":["BROADCAST","MULTICAST","UP","LOWER_UP"],"link_type":"ether","address":"52:55:0a:00:02:0f","broadcast":"ff:ff:ff:ff:ff:ff"}
]"#;

    #[test]
    fn nic_discovery_3_slots() {
        let map = discover_nics_from_ip_json(IP_JSON_3_SLOTS).unwrap();
        assert_eq!(map.discovered_count, 3);
        assert_eq!(map.slot_to_iface.get(&0), Some(&"lima0".to_string()));
        assert_eq!(map.slot_to_iface.get(&1), Some(&"lima1".to_string()));
        assert_eq!(map.slot_to_iface.get(&2), Some(&"lima2".to_string()));
        assert_eq!(map.slot_to_iface.get(&3), None);
    }

    #[test]
    fn nic_discovery_1_slot() {
        let map = discover_nics_from_ip_json(IP_JSON_1_SLOT).unwrap();
        assert_eq!(map.discovered_count, 1);
        assert_eq!(map.slot_to_iface.get(&0), Some(&"lima0".to_string()));
    }

    #[test]
    fn nic_discovery_excludes_eth0() {
        let map = discover_nics_from_ip_json(IP_JSON_3_SLOTS).unwrap();
        // eth0 must never appear as a slot NIC.
        for iface in map.slot_to_iface.values() {
            assert_ne!(iface, "eth0", "eth0 must never be mapped to a slot");
        }
    }

    #[test]
    fn nic_discovery_no_lima_nics() {
        // When no limaN NICs are present, we get an empty map (discovered_count 0).
        // This is the count-mismatch non-fatal case.
        let map = discover_nics_from_ip_json(IP_JSON_NO_LIMA).unwrap();
        assert_eq!(map.discovered_count, 0);
        assert!(map.slot_to_iface.is_empty());
    }

    #[test]
    fn nic_discovery_count_mismatch_is_non_fatal() {
        // 3 slots discovered but max_slots would be 8 in production — the
        // function itself returns successfully; the caller (GatewayLimaManager)
        // logs a warning. Verify parse succeeds.
        let map = discover_nics_from_ip_json(IP_JSON_3_SLOTS).unwrap();
        // The parse succeeds — caller decides what to do with the mismatch.
        assert_eq!(map.discovered_count, 3);
    }

    #[test]
    fn nic_discovery_invalid_json() {
        let result = discover_nics_from_ip_json("not json at all");
        assert!(result.is_err());
    }

    // -- Template generation (pure, hermetic) ---------------------------------

    #[test]
    fn template_contains_qemu_vmtype() {
        let tmpl = generate_gateway_template(4);
        assert!(
            tmpl.contains("vmType: \"qemu\""),
            "template must specify vmType qemu"
        );
    }

    #[test]
    fn template_contains_correct_socket_count() {
        let tmpl = generate_gateway_template(4);
        // Each slot produces one `- socket:` entry.
        let socket_count = tmpl.matches("  - socket:").count();
        assert_eq!(
            socket_count, 4,
            "template must have exactly 4 socket entries for max_slots=4"
        );

        let tmpl8 = generate_gateway_template(8);
        let socket_count8 = tmpl8.matches("  - socket:").count();
        assert_eq!(
            socket_count8, 8,
            "template must have exactly 8 socket entries for max_slots=8"
        );
    }

    #[test]
    fn template_slot_socket_paths_match_vmnet_pool() {
        let tmpl = generate_gateway_template(3);
        // Verify the socket paths match what VmnetPool::slot_socket_path returns.
        for slot in 0u16..3 {
            let expected = crate::network::vmnet_slot_socket_path(slot);
            assert!(
                tmpl.contains(&expected),
                "template must contain socket path {expected} for slot {slot}"
            );
        }
    }

    #[test]
    fn template_has_forwarded_docker_socket() {
        let tmpl = generate_gateway_template(4);
        assert!(
            tmpl.contains("guestSocket: \"/var/run/docker.sock\""),
            "template must forward the guest Docker socket"
        );
        assert!(
            tmpl.contains("hostSocket: \"{{.Dir}}/gateway-docker.sock\""),
            "template must use Lima .Dir macro for the host socket path"
        );
    }

    #[test]
    fn template_has_docker_provision() {
        let tmpl = generate_gateway_template(4);
        assert!(
            tmpl.contains("apt-get install -y docker.io"),
            "template must provision docker.io"
        );
    }

    #[test]
    fn template_has_mtu_clamp() {
        let tmpl = generate_gateway_template(4);
        assert!(
            tmpl.contains("mtu: 1280"),
            "template must clamp eth0 MTU to 1280"
        );
    }

    #[test]
    fn template_has_no_dhcp_for_lima_nics() {
        let tmpl = generate_gateway_template(3);
        assert!(
            tmpl.contains("dhcp4: no"),
            "template must disable DHCP on limaN NICs"
        );
        assert!(
            tmpl.contains("optional: true"),
            "template must mark limaN NICs as optional (no boot stall)"
        );
    }

    #[test]
    fn template_has_minimum_lima_version() {
        let tmpl = generate_gateway_template(4);
        assert!(
            tmpl.contains(MIN_LIMA_VERSION),
            "template must specify minimumLimaVersion"
        );
    }

    #[test]
    fn template_has_ubuntu_noble_image() {
        let tmpl = generate_gateway_template(4);
        assert!(
            tmpl.contains(UBUNTU_NOBLE_ARM64_URL),
            "template must reference the Ubuntu 24.04 aarch64 cloud image"
        );
    }

    #[test]
    fn template_disables_containerd() {
        let tmpl = generate_gateway_template(4);
        assert!(
            tmpl.contains("system: false"),
            "template must disable containerd (system)"
        );
        assert!(
            tmpl.contains("user: false"),
            "template must disable containerd (user)"
        );
    }

    // -- Baseline nft policy (pure, text assertions) --------------------------

    #[test]
    fn nft_policy_has_default_drop_output() {
        let ruleset = generate_gateway_eth0_nft_policy();
        assert!(
            ruleset.contains("policy drop"),
            "baseline nft must default-drop on output"
        );
    }

    #[test]
    fn nft_policy_allows_established_related() {
        let ruleset = generate_gateway_eth0_nft_policy();
        assert!(
            ruleset.contains("ct state established,related accept"),
            "baseline nft must allow established/related (re-originated upstream)"
        );
    }

    #[test]
    fn nft_policy_allows_dns_port_53() {
        let ruleset = generate_gateway_eth0_nft_policy();
        assert!(
            ruleset.contains("udp dport 53 accept"),
            "baseline nft must allow DNS (UDP port 53) for systemd-resolved"
        );
        assert!(
            ruleset.contains("tcp dport 53 accept"),
            "baseline nft must allow DNS (TCP port 53) for systemd-resolved"
        );
    }

    #[test]
    fn nft_policy_allows_https_port_443() {
        let ruleset = generate_gateway_eth0_nft_policy();
        assert!(
            ruleset.contains("tcp dport 443 accept"),
            "baseline nft must allow HTTPS (TCP port 443) for Docker daemon image pulls and Lima agents"
        );
    }

    #[test]
    fn nft_policy_allows_http_port_80() {
        let ruleset = generate_gateway_eth0_nft_policy();
        assert!(
            ruleset.contains("tcp dport 80 accept"),
            "baseline nft must allow HTTP (TCP port 80) for apt-get and HTTP registries"
        );
    }

    #[test]
    fn nft_policy_does_not_have_blanket_new_accept() {
        // The policy must NOT have a blanket `ct state new accept` on the OUTPUT
        // chain — that would allow any VM-host-namespace process to egress
        // anywhere, defeating the blast-radius bound.
        let ruleset = generate_gateway_eth0_nft_policy();
        assert!(
            !ruleset.contains("ct state new accept"),
            "baseline nft must NOT have a blanket ct state new accept; use explicit port allow-list"
        );
    }

    #[test]
    fn nft_policy_scoped_to_eth0() {
        let ruleset = generate_gateway_eth0_nft_policy();
        // The output chain must restrict its policy to eth0 specifically.
        // The "oifname != eth0 accept" rule lets other NICs (limaN) through
        // the output chain unhindered.
        assert!(
            ruleset.contains("oifname != \"eth0\" accept"),
            "baseline nft policy must only restrict eth0 output, not limaN NICs"
        );
    }

    #[test]
    fn nft_policy_has_sandboxd_table_name() {
        let ruleset = generate_gateway_eth0_nft_policy();
        assert!(
            ruleset.contains("table inet sandboxd-gateway-eth0"),
            "nft ruleset must use the sandboxd-gateway-eth0 table name"
        );
    }

    #[test]
    fn nft_policy_drops_new_inbound_on_eth0() {
        let ruleset = generate_gateway_eth0_nft_policy();
        assert!(
            ruleset.contains("ct state new,invalid drop"),
            "baseline nft must drop new/invalid inbound connections on eth0"
        );
    }

    #[test]
    fn nft_policy_is_idempotent_contains_flush() {
        // The ruleset must contain the create-if-absent + flush idiom so that
        // applying it a second time (daemon restart against a still-running
        // gateway VM) does not fail with "chain already exists" from nft.
        let ruleset = generate_gateway_eth0_nft_policy();
        // create-if-absent: bare `table inet X {}` is an implicit `add table` no-op
        assert!(
            ruleset.contains("table inet sandboxd-gateway-eth0 {}"),
            "nft ruleset must have a bare-table create-if-absent statement for idempotency"
        );
        // flush: clears existing chains so the re-add below cannot collide
        assert!(
            ruleset.contains("flush table inet sandboxd-gateway-eth0"),
            "nft ruleset must flush the table before re-creating chains for idempotency"
        );
        // The flush must appear before the table-with-chains block.
        let flush_pos = ruleset
            .find("flush table inet sandboxd-gateway-eth0")
            .unwrap();
        let chain_pos = ruleset.find("chain output-eth0").unwrap();
        assert!(
            flush_pos < chain_pos,
            "flush must appear before the chain definitions"
        );
    }

    // -- NicMap accessor tests -------------------------------------------------

    #[test]
    fn nic_map_interface_for_slot_accessor() {
        let map = discover_nics_from_ip_json(IP_JSON_3_SLOTS).unwrap();
        assert_eq!(map.interface_for_slot(0), Some("lima0"));
        assert_eq!(map.interface_for_slot(1), Some("lima1"));
        assert_eq!(map.interface_for_slot(2), Some("lima2"));
        assert_eq!(map.interface_for_slot(3), None); // out of range
    }
}
