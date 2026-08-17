/// Gateway Lima instance manager (macOS only).
///
/// Manages the `sandboxd-gateway` Lima instance — the persistent daemon-owned
/// Linux VM that hosts all gateway containers across all sandbox sessions.
///
/// The gateway instance is daemon infrastructure, not per-operator. It lives
/// under the daemon's own LIMA_HOME
/// (`/var/lib/sandboxd/<_sandboxd-uid>/<_sandboxd-uid>/lima/` — the daemon is its
/// own operator, so both uid components of the 3-level path are its uid)
/// and all `limactl` ops on it run via the `op_uid == daemon_uid` degenerate
/// path of the `LimaExecutor` seam (i.e., `run_limactl_direct` in the daemon —
/// no agent, no privilege pivot needed because the daemon already is `_sandboxd`).
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
/// The gateway VM has N+1 NICs: `eth0` (management/slirp) and one `lima<slot>`
/// per socket_vmnet pool slot the instance was created with. The slot→interface
/// map is **built by the daemon** from the slot set it rendered the template
/// with, not read out of the guest: `generate_gateway_template` pins
/// `interface: lima<slot>` on every `networks:` entry, so the daemon already
/// knows the answer before it asks.
///
/// `discover_nics` runs `ip -json link show` inside the VM and uses the result
/// **only to verify** that each expected interface is actually present. A slot
/// whose interface is missing is left out of the map — it never acquires a
/// guessed or positionally-derived name — and the claim sites refuse to start a
/// session on it. The guest string can withhold an entry; it can never name one.
///
/// If discovered NIC count ≠ the requested slot count, the mismatch is deferred
/// to the `decide_pool_resize` handler in the bin-crate startup sequence.
/// `ensure_ready` itself does not decide — it discovers and caches; the caller
/// acts on the result.
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
use crate::backend::container::lite_image_tag_for_version;
#[cfg(target_os = "macos")]
use crate::error::SandboxError;
#[cfg(target_os = "macos")]
use crate::gateway::gateway_image_tag_for_daemon;
#[cfg(target_os = "macos")]
use crate::lima::{LimaExecutor, LimaOp};
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

/// vCPU count assigned to the daemon-owned gateway Lima VM.
///
/// On macOS lite, every sandbox container runs inside this VM via the
/// forwarded Docker socket, so a container's `--cpus` ceiling must fit within
/// the VM rather than the macOS host. The container backend reads this to cap
/// its default/explicit CPU allotment (see
/// `container::macos_container_cpu_ceiling`). Wired into
/// `generate_gateway_template`'s `cpus:` line so the VM spec and the cap stay
/// in lockstep.
#[cfg(target_os = "macos")]
pub const GATEWAY_VM_CPUS: u32 = 2;

/// RAM (MiB) assigned to the daemon-owned gateway Lima VM (mirrors the
/// template's `memory: "2GiB"`). The container backend caps a sandbox
/// container's memory ceiling to this minus a fixed VM/gateway-overhead margin
/// (see `container::macos_container_memory_ceiling_mb`).
#[cfg(target_os = "macos")]
pub const GATEWAY_VM_MEMORY_MB: u32 = 2048;

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

/// Readiness timeout used during crash recovery restarts of the gateway Lima
/// instance.
///
/// Shorter than `DOCKER_READY_TIMEOUT` (300 s for first-boot) because on
/// recovery the VM is already provisioned — the Docker daemon typically becomes
/// reachable in a few seconds. A stuck recovery must surface quickly so the
/// 10-second poll loop can re-attempt rather than blocking for five minutes.
#[cfg(target_os = "macos")]
const GATEWAY_RECOVERY_READY_TIMEOUT: Duration = Duration::from_secs(90);

/// Filename of the cached gateway image tarball inside the daemon LIMA_HOME.
/// The operator populates it via:
///   make gateway-image && docker save <tag> -o <path>
/// where <path> is `{daemon_lima_home}/gateway-image.tar`.
#[cfg(target_os = "macos")]
pub const GATEWAY_IMAGE_TARBALL_FILENAME: &str = "gateway-image.tar";

/// Filename of the cached lite image tarball inside the daemon LIMA_HOME.
/// The operator populates it via:
///   make lite-image && make stage-lite-image
/// where the destination path is `{daemon_lima_home}/lite-image.tar`.
#[cfg(target_os = "macos")]
pub const LITE_IMAGE_TARBALL_FILENAME: &str = "lite-image.tar";

/// Filename of the Linux aarch64 `sandbox-route-helper` binary staged in the
/// daemon LIMA_HOME for copying into the gateway VM.
///
/// The operator populates this once via:
///   make build-route-helper-linux-aarch64
/// or by downloading from the release assets. The daemon copies it into the
/// gateway VM and setcap's it during `ensure_ready`.
#[cfg(target_os = "macos")]
pub const ROUTE_HELPER_LINUX_BINARY_FILENAME: &str = "sandbox-route-helper-linux-aarch64";

/// In-VM install path for `sandbox-route-helper` inside the gateway Lima VM.
/// Mirrors the host FHS install path used on Linux.
#[cfg(target_os = "macos")]
pub const IN_VM_ROUTE_HELPER_PATH: &str = "/usr/local/libexec/sandboxd/sandbox-route-helper";

/// Timeout for `limactl copy` (binary staging into the gateway VM).
#[cfg(target_os = "macos")]
const ROUTE_HELPER_COPY_TIMEOUT: Duration = Duration::from_secs(30);

/// Timeout for staging a per-session lite container file into the gateway VM
/// (`limactl shell mkdir` and per-file `limactl copy`).
#[cfg(target_os = "macos")]
const LITE_FILE_STAGE_TIMEOUT: Duration = Duration::from_secs(30);

/// Parent of the per-session lite staging directories inside the gateway VM.
///
/// `/tmp` is `1777` (sticky, world-writable) so the operator's Lima SSH login
/// can `mkdir` and `limactl copy` into it without sudo, while root-in-VM (the
/// Docker daemon applying the bind) can still read it. The material staged here
/// is non-secret: the per-session public CA cert, the operator's SSH public key
/// (`authorized_keys`), and the synthetic `passwd`/`group` files. The sole
/// secret — the mitmproxy CA private key — never lands here; it is written
/// straight into the gateway container's tmpfs (see `macos_session`).
#[cfg(target_os = "macos")]
pub const LITE_STAGE_ROOT: &str = "/tmp/sandbox-lite";

// ---------------------------------------------------------------------------
// NIC map
// ---------------------------------------------------------------------------

/// Result of gateway NIC verification: a mapping from pool slot index to the
/// in-VM interface name for that slot.
///
/// Slot `n` → `lima<n>`, always — the name is [`slot_interface_name`] applied to
/// the slot the daemon assigned, never a name lifted out of guest output. An
/// entry is present only when the guest was observed to actually carry that
/// interface; a slot whose interface is missing is **absent from the map**, and
/// the claim sites turn that absence into a refused session rather than a guess.
///
/// The number of entries may therefore be smaller than the number of slots
/// requested, and `discovered_count` may differ from both (see the module-level
/// note on non-fatal mismatch).
#[cfg(target_os = "macos")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NicMap {
    /// Maps slot index → in-VM interface name, for verified slots only.
    pub slot_to_iface: HashMap<u16, String>,
    /// Number of `lima<n>` interfaces the guest reported, whether or not they
    /// were expected. This is an observation of the VM's shape and feeds
    /// `decide_pool_resize`; it is deliberately not the size of the map.
    pub discovered_count: usize,
    /// Slots that were requested but whose interface the guest did not report.
    /// Retained for diagnostics — the enforcement is the missing map entry.
    pub missing_slots: Vec<u16>,
}

#[cfg(target_os = "macos")]
impl NicMap {
    /// Look up the interface name for a given slot.
    pub fn interface_for_slot(&self, slot: u16) -> Option<&str> {
        self.slot_to_iface.get(&slot).map(|s| s.as_str())
    }
}

// ---------------------------------------------------------------------------
// Slot identity: no guessed NIC, no guessed slot
// ---------------------------------------------------------------------------
//
// The slot NIC is the macvlan parent — it decides which isolated L2 segment a
// session's traffic lands on — and it is persisted as `NetworkInfo.bridge_name`,
// so getting it wrong is durable rather than transient. The slot index is the
// same decision one level up.
//
// Neither may be guessed. A guessed `lima<n>` is right only by coincidence, and
// wrong silently: the session comes up, its traffic egresses, and it does so on
// a segment nobody chose. Once the pool is partitioned per operator, the guess
// can put a session on *another operator's* segment, past that operator's
// egress policy, with nothing in the deny-event stream to show for it. Refusing
// costs a session that was not going to be correctly isolated anyway.
//
// The three functions below are the whole policy, kept pure so the sites that
// use them stay thin and the behaviour can be asserted without a live VM.

/// Resolve a slot's gateway NIC from the verified map alone.
///
/// For sites with no durable record worth trusting: a fresh slot claim (create,
/// and restarting a stopped session, both of which claim a *new* slot so the old
/// `bridge_name` names the wrong one), and gateway recovery. A map miss is a
/// refusal — there is nothing else to consult.
#[cfg(target_os = "macos")]
pub fn nic_from_verified_map(nic_map: Option<&NicMap>, slot: u16) -> Result<String, SandboxError> {
    nic_map
        .and_then(|m| m.interface_for_slot(slot))
        .map(|s| s.to_string())
        .ok_or_else(|| nic_map_miss_error(slot))
}

/// Resolve a restored session's gateway NIC, preferring its durable record.
///
/// `NetworkInfo.bridge_name` was written at create time from the verified map,
/// and it is what the session's existing macvlan is *actually* parented on — so
/// reading it is correct, not a lucky fallback. It also has to stay usable when
/// the map is merely not populated yet: `nic_map()` returns `None` until
/// `ensure_ready` completes, and refusing on that would break restore for a
/// reason that is not a fault.
///
/// So the record wins; the map only fills a blank record. A disagreement is a
/// refusal rather than a re-parent: moving a running session's macvlan to a
/// different segment is a worse answer than declining to touch it.
#[cfg(target_os = "macos")]
pub fn nic_from_record_or_map(
    nic_map: Option<&NicMap>,
    slot: u16,
    persisted_bridge_name: &str,
) -> Result<String, SandboxError> {
    let mapped = nic_map.and_then(|m| m.interface_for_slot(slot));
    if persisted_bridge_name.is_empty() {
        // No record to restore from — the map is the only authority left.
        return mapped
            .map(|s| s.to_string())
            .ok_or_else(|| nic_map_miss_error(slot));
    }
    if let Some(mapped) = mapped
        && mapped != persisted_bridge_name
    {
        return Err(SandboxError::Gateway(format!(
            "session is recorded on gateway NIC `{persisted_bridge_name}` for vmnet slot \
             {slot}, but the gateway VM now maps that slot to `{mapped}`. Refusing to \
             re-parent a running session's macvlan onto a different L2 segment; stop the \
             session and re-create it."
        )));
    }
    Ok(persisted_bridge_name.to_string())
}

/// Resolve the slot a persisted session belongs to.
///
/// Defaulting a missing slot to 0 attaches the session to whichever segment slot
/// 0 happens to be — under per-operator ranges, someone else's. That is a worse
/// outcome than the NIC-name guess, and one level further up: a wrong NIC picks
/// the wrong interface within a known slot, a wrong slot picks the wrong slot
/// outright.
#[cfg(target_os = "macos")]
pub fn slot_for_persisted_session(
    network_info: &crate::network::NetworkInfo,
) -> Result<u16, SandboxError> {
    network_info
        .vmnet_slot
        .as_ref()
        .map(|s| s.index)
        .ok_or_else(|| {
            SandboxError::Gateway(
                "session has no vmnet slot recorded in its network info; refusing to recover \
                 it onto a default slot index, which would attach it to whichever L2 segment \
                 slot 0 belongs to. Stop and re-create the session to claim a slot."
                    .to_string(),
            )
        })
}

/// The gateway VM carries no verified interface for `slot`.
///
/// The map holds an entry only for slots whose pinned `lima<slot>` interface was
/// observed in the gateway VM, so a miss means either the map is not yet
/// populated or the VM does not have that NIC.
#[cfg(target_os = "macos")]
fn nic_map_miss_error(slot: u16) -> SandboxError {
    SandboxError::Gateway(format!(
        "no verified gateway NIC for vmnet slot {slot} (expected `{}` in the gateway VM). \
         Refusing rather than parenting the session's macvlan on a guessed interface, which \
         would place it on an unknown L2 segment. Check that the gateway Lima instance is up \
         and was created with this slot: `limactl list` and \
         `limactl shell {GATEWAY_INSTANCE_NAME} ip -json link show`.",
        slot_interface_name(slot),
    ))
}

/// The in-VM interface name that belongs to a pool slot.
///
/// Single source of truth for the `slot n ⇔ lima<n>` correspondence. The
/// template generator pins it into every `networks:` entry, NIC verification
/// looks for exactly this name, and §1.1a's agent-side validator re-derives it
/// from the socket path. Lima honours whatever name it is given and never warns
/// about a non-positional one, so this correspondence is ours to hold, not
/// Lima's.
#[cfg(target_os = "macos")]
pub fn slot_interface_name(slot: u16) -> String {
    format!("lima{slot}")
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

/// Build the slot→NIC map for `slots`, using `ip -json link show` output only
/// to verify it.
///
/// **The mapping is not derived from the guest.** The daemon rendered the
/// instance template with an explicit slot set and pinned
/// `interface: lima<slot>` on each entry, so it already knows what every slot's
/// interface is called; this function asserts that claim against the VM instead
/// of asking the VM for the answer. That matters because after ownership flips
/// the gateway VM is the operator's, and the map selects the macvlan parent —
/// i.e. which L2 segment a session lands on. A parser that keyed off guest text
/// would let the operator choose the segment.
///
/// Verification rules:
/// - For each requested slot, the guest must report an interface named exactly
///   [`slot_interface_name`]`(slot)`. Present → mapped. Absent → left out of the
///   map and recorded in `missing_slots`.
/// - `discovered_count` counts every `lima<n>` interface the guest reported,
///   expected or not. It is an observation of the VM's shape for
///   `decide_pool_resize`, not a measure of the map.
/// - `eth0` and every other non-`lima<n>` name are ignored throughout.
///
/// A missing interface is deliberately **not** an error here. An unusable slot
/// must refuse the session that claims it, which is what the absent map entry
/// produces at the claim sites; making it an error instead would fail the whole
/// of `ensure_ready`, and at startup that means the daemon refuses to boot —
/// taking out `decide_pool_resize`'s reduced-pool arms, which exist precisely
/// for the case where the VM has fewer NICs than the config asks for.
///
/// This function is pure and has no I/O; it can be unit-tested by feeding
/// representative JSON.
#[cfg(target_os = "macos")]
pub fn discover_nics_from_ip_json(json: &str, slots: &[u16]) -> Result<NicMap, SandboxError> {
    let entries: Vec<IpLinkEntry> = serde_json::from_str(json).map_err(|e| {
        SandboxError::Internal(format!(
            "gateway NIC discovery: failed to parse `ip -json link` output: {e}"
        ))
    })?;

    // Names of every lima<n> interface the guest reports. Kept as names, not
    // parsed suffixes, so `lima04` cannot stand in for `lima4`.
    let observed: std::collections::HashSet<&str> = entries
        .iter()
        .filter(|e| {
            e.ifname
                .strip_prefix("lima")
                .is_some_and(|suffix| suffix.parse::<u16>().is_ok())
        })
        .map(|e| e.ifname.as_str())
        .collect();
    let discovered_count = observed.len();

    let mut slot_to_iface: HashMap<u16, String> = HashMap::new();
    let mut missing_slots: Vec<u16> = Vec::new();
    for &slot in slots {
        let expected = slot_interface_name(slot);
        if observed.contains(expected.as_str()) {
            slot_to_iface.insert(slot, expected);
        } else {
            missing_slots.push(slot);
        }
    }

    if !missing_slots.is_empty() {
        warn!(
            missing_slots = ?missing_slots,
            discovered_count,
            "gateway NIC verification: expected interfaces are absent from the gateway VM; \
             sessions claiming these slots will be refused rather than parented on a \
             guessed interface. A Lima older than the version that honours the per-entry \
             `interface:` key produces exactly this."
        );
    }

    Ok(NicMap {
        slot_to_iface,
        discovered_count,
        missing_slots,
    })
}

// ---------------------------------------------------------------------------
// Template generation
// ---------------------------------------------------------------------------

/// Render one `networks:` entry, binding a slot's socket to its pinned in-VM
/// interface name.
///
/// ```yaml
///   - socket: /var/run/sandbox/vmnet/slot-6.sock
///     interface: lima6
/// ```
///
/// Both halves come from the same `slot`, and the guard re-derives the slot
/// from the rendered socket path to confirm they still describe the same
/// segment. That is the invariant Lima will not enforce for us: it accepts
/// `interface: lima2` on `slot-7.sock` without a warning, and the result is a
/// session silently parented on another slot's L2 segment.
///
/// The guard cannot fire on any input this function accepts — a `u16` always
/// round-trips — which is the point: it is here so that a later edit that
/// decouples the two halves stops being silent. §1.1a's agent-side validator
/// makes the same check from outside the daemon's trust boundary, where a
/// compromised daemon cannot skip it.
#[cfg(target_os = "macos")]
fn gateway_network_entry(slot: u16) -> String {
    let socket = crate::network::vmnet_slot_socket_path(slot);
    let interface = slot_interface_name(slot);
    assert_eq!(
        crate::network::slot_from_vmnet_socket_path(&socket),
        Some(slot),
        "gateway template: interface {interface} would be pinned onto socket {socket}, \
         which does not belong to slot {slot}"
    );
    format!("  - socket: {socket}\n    interface: {interface}\n")
}

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
/// `slots` is the set of pool slots this instance is to own — one `networks:`
/// entry each, in the order given. It is an argument rather than manager state
/// on purpose: a slot set is the set of L2 segments the VM lands on, and a
/// stored copy that went stale would be a wrong set of segments rather than a
/// wrong count. There is no copy to go stale.
#[cfg(target_os = "macos")]
pub fn generate_gateway_template(slots: &[u16]) -> String {
    // Build the networks section: one entry per pool slot, each pinning the
    // in-VM interface name.
    //
    // Without `interface:`, Lima names guest NICs by *array position* —
    // a VM given slots {4,5,6,7} would call them lima0..lima3. The NIC name
    // selects the macvlan parent, so positional naming on a non-contiguous
    // range silently parents sessions on the wrong L2 segment. Pinning the
    // name removes the coupling to position.
    //
    // Lima honours whatever name it is given and never warns about a
    // non-positional one — `interface: lima2` on `slot-7.sock` validates
    // clean. So the `lima<n>` ⇔ slot n correspondence is not something Lima
    // enforces; it is this generator's to hold, which is why both halves of
    // every entry are derived from the same `slot` binding below and checked
    // against each other rather than written out twice.
    let networks_section = slots
        .iter()
        .map(|&slot| gateway_network_entry(slot))
        .collect::<String>();

    // Build the 9p mounts stanza for the lite shared-workspace root.
    // The shared root is mounted read-write into the gateway VM at the same
    // absolute path as the host, so the host→VM path translation is an
    // identity (no remapping needed). Per-session shared: paths must be
    // validated at create time to fall under this root.
    //
    // Note: the 9p read is performed by _sandboxd (the gateway VM's user),
    // NOT the operator. This is the TCC asymmetry: lite shared: gets no
    // operator TCC consent path. Sources must be readable by _sandboxd and
    // must not live in TCC-protected directories (Desktop, Documents, Downloads).
    let shared_root = crate::lite_macos::lite_shared_root();
    let mounts_stanza = crate::lite_macos::lite_shared_root_9p_stanza(&shared_root);

    // Build the no-DHCP netplan printf lines for each limaN NIC.
    // Without this, systemd-networkd tries DHCP on every limaN NIC and
    // blocks boot on `network-online.target` waiting for leases that never arrive.
    //
    // We use `printf` rather than a heredoc because the Lima template is a YAML
    // block scalar (`script: |`) — heredoc terminators must appear at column 0 in
    // the shell script, but column-0 content in a YAML block scalar terminates the
    // scalar and is parsed as YAML, causing a parse error. `printf` appended line
    // by line avoids the column-0 heredoc marker entirely.
    let netplan_lima_entries = slots
        .iter()
        .map(|&slot| {
            // Each NIC block: "    lima{n}:" (4-space indent under `ethernets:`)
            // followed by dhcp4/optional at 6-space indent. The \\n sequences
            // are the printf escape sequences for newlines inside the shell string.
            let iface = slot_interface_name(slot);
            format!(
                "      printf '    {iface}:\\n      dhcp4: no\\n      optional: true\\n' >> /etc/netplan/99-sandbox-vmnet.yaml\n"
            )
        })
        .collect::<String>();

    // Build the sysctl disable-IPv6 lines for each limaN NIC.
    let ipv6_disable_lines = slots
        .iter()
        .map(|&slot| {
            format!(
                "      sysctl -w net.ipv6.conf.{}.disable_ipv6=1\n",
                slot_interface_name(slot)
            )
        })
        .collect::<String>();

    // Derive the `memory:` suffix from the MiB constant so the VM spec and the
    // container-backend memory cap (which reads GATEWAY_VM_MEMORY_MB) cannot
    // drift. 2048 MiB renders as the historical "2GiB".
    let memory_gib = GATEWAY_VM_MEMORY_MB / 1024;
    let gateway_cpus = GATEWAY_VM_CPUS;
    format!(
        r#"vmType: "qemu"
minimumLimaVersion: "{MIN_LIMA_VERSION}"

images:
  - location: "{UBUNTU_NOBLE_ARM64_URL}"
    arch: aarch64

cpus: {gateway_cpus}
memory: "{memory_gib}GiB"
disk: "20GiB"

# N socket_vmnet NICs — one per pool slot.
# Count = max_macos_sessions (default 8). Fixed at instance creation.
networks:
{networks_section}
# Expose the guest Docker socket to the macOS host via Lima forwarding.
portForwards:
  - guestSocket: "/var/run/docker.sock"
    hostSocket: "{{{{.Dir}}}}/gateway-docker.sock"

# 9p mount for lite-mode shared: workspaces.
# The shared root is exposed read-write at the same absolute path so the
# host->VM path translation is an identity. Per-session shared: paths must
# fall under this root (validated at session-create time).
# NOTE: reads are performed as _sandboxd (the gateway VM user), not the
# operator. Sources outside TCC-protected dirs work without consent.
{mounts_stanza}
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
      # Make the in-VM Docker socket world-readable/writable.
      #
      # Lima's socket-forward connects to /var/run/docker.sock as the SSH login
      # user (the operator). The obvious approach — chgrp the 0660 socket to the
      # docker group and add the operator to that group — does NOT work here:
      # Lima establishes a persistent ControlPersist SSH master connection at VM
      # boot, BEFORE this provision runs, so every forwarded channel inherits the
      # operator's boot-time supplementary groups. The docker group added now is
      # absent from those channels' credentials (`id` for the operator over the
      # master shows no docker group despite /etc/group listing it), so the
      # forward can't read a 0660 socket and the host side sees EOF.
      #
      # 0666 is safe here: the HOST-side forwarded gateway-docker.sock is 0600
      # (operator-only), the gateway VM is a single-tenant daemon-owned appliance,
      # and the VM's /var/run/docker.sock is a unix socket that is never
      # bind-mounted into any lite/gateway container — so no container can reach
      # it. Widening the in-VM mode does not widen the external attack surface.
      #
      # The drop-in makes the mode survive docker.socket restarts; the direct
      # chmod fixes the already-running socket for the current boot (the drop-in
      # only takes effect on the next docker.socket (re)start, which we must not
      # force here without disrupting the running dockerd).
      groupadd -f docker
      mkdir -p /etc/systemd/system/docker.socket.d
      printf '[Socket]\nSocketMode=0666\n' \
        > /etc/systemd/system/docker.socket.d/10-socketmode.conf
      systemctl daemon-reload
      chmod 666 /var/run/docker.sock
  - mode: system
    script: |
      #!/bin/bash
      # Allow the daemon to invoke sandbox-route-helper inside the VM without
      # a password prompt. The sudoers entry is scoped to exactly one binary
      # so no other command can be run as root via this grant.
      #
      # printf is used instead of a heredoc because the Lima template is a
      # YAML block scalar — heredoc terminators at column 0 would be
      # misinterpreted by the YAML parser as end-of-scalar.
      printf 'ALL ALL=(root) NOPASSWD: /usr/local/libexec/sandboxd/sandbox-route-helper\n' \
        > /etc/sudoers.d/sandbox-route-helper
      chmod 0440 /etc/sudoers.d/sandbox-route-helper
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
// Lite-session staging path + argv builders (pure, testable)
// ---------------------------------------------------------------------------

/// VM staging directory for a session's lite-container provisioning files.
///
/// `{LITE_STAGE_ROOT}/<session_id>`. Pure string composition — no I/O.
#[cfg(target_os = "macos")]
pub fn lite_stage_dir(session_id: &str) -> String {
    format!("{LITE_STAGE_ROOT}/{session_id}")
}

/// `limactl shell` argv that creates the per-session staging directory inside
/// the gateway VM. Shape: `["shell", "<vm>", "--", "mkdir", "-p", "<dir>"]`,
/// matching the prefix `run_gateway_shell_argv` expects.
#[cfg(target_os = "macos")]
pub fn lite_stage_mkdir_argv(vm_dir: &str) -> Vec<String> {
    vec![
        "shell".to_string(),
        GATEWAY_INSTANCE_NAME.to_string(),
        "--".to_string(),
        "mkdir".to_string(),
        "-p".to_string(),
        vm_dir.to_string(),
    ]
}

/// `limactl shell` argv that removes the per-session staging directory from the
/// gateway VM. Shape: `["shell", "<vm>", "--", "rm", "-rf", "<dir>"]`.
#[cfg(target_os = "macos")]
pub fn lite_stage_rm_argv(vm_dir: &str) -> Vec<String> {
    vec![
        "shell".to_string(),
        GATEWAY_INSTANCE_NAME.to_string(),
        "--".to_string(),
        "rm".to_string(),
        "-rf".to_string(),
        vm_dir.to_string(),
    ]
}

// ---------------------------------------------------------------------------
// GatewayLimaManager
// ---------------------------------------------------------------------------

/// Manages the `sandboxd-gateway` Lima instance and its Docker infrastructure.
///
/// Constructed once at daemon startup (macOS only) with the `LimaExecutor`
/// (for `limactl` ops via the daemon-uid degenerate path). It holds no pool and
/// no slot set — the slot set is an argument to the calls that need one.
///
/// After `ensure_ready` completes successfully:
/// - `nic_map()` returns the verified slot→NIC mapping.
/// - The `sandboxd-egress` Docker bridge exists in the gateway VM.
/// - The baseline `eth0` nft policy is in place.
#[cfg(target_os = "macos")]
pub struct GatewayLimaManager {
    /// Daemon's LIMA_HOME: `/var/lib/sandboxd/<daemon-uid>/<daemon-uid>/lima/`.
    daemon_lima_home: PathBuf,

    /// Derived path to the forwarded Docker socket:
    /// `<daemon_lima_home>/sandboxd-gateway/gateway-docker.sock`
    gateway_docker_socket: PathBuf,

    /// Daemon uid — passed as `op_uid` to the executor (degenerate path).
    daemon_uid: u32,

    /// Operator-execution seam for `limactl` ops (all go via daemon_uid).
    executor: Arc<dyn LimaExecutor>,

    /// Verified slot→NIC map, populated after a successful `ensure_ready`.
    nic_map: Mutex<Option<NicMap>>,
}

#[cfg(target_os = "macos")]
impl GatewayLimaManager {
    /// Construct a new manager.
    ///
    /// - `daemon_lima_home` — the daemon's LIMA_HOME root (e.g.
    ///   `/var/lib/sandboxd/<daemon_uid>/<daemon_uid>/lima/`).
    /// - `executor` — the `LimaExecutor` implementation (on macOS this is
    ///   `AgentBrokerExecutor`; when `op_uid == daemon_uid` it routes to
    ///   `run_limactl_direct`).
    /// - `daemon_uid` — the daemon's own uid; passed as `op_uid` on every
    ///   `limactl` call so the executor takes the degenerate direct path.
    ///
    /// The manager holds **no** pool and no slot set. Which slots the gateway
    /// instance owns is supplied per call, by the caller, from the assignment
    /// that is live at that moment — see [`GatewayLimaManager::ensure_ready`].
    /// A slot set copied in here would be a set of L2 segments cached at
    /// construction, and the manager is never rebuilt.
    pub fn new(
        daemon_lima_home: PathBuf,
        executor: Arc<dyn LimaExecutor>,
        daemon_uid: u32,
    ) -> Self {
        let gateway_docker_socket = daemon_lima_home
            .join(GATEWAY_INSTANCE_NAME)
            .join("gateway-docker.sock");
        Self {
            daemon_lima_home,
            gateway_docker_socket,
            daemon_uid,
            executor,
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
    /// 5. Poll `docker -H <sock> info` until ready (300 s / 2 s on first boot).
    /// 6. Verify the slot→NIC map; cache it. Any mismatch with the configured
    ///    pool size is handled by `decide_pool_resize` in the caller — this
    ///    method does not decide; it only observes and caches.
    /// 7. Ensure `sandboxd-egress` NAT bridge (idempotent).
    /// 8. Apply baseline `eth0` nft policy.
    ///
    /// `slots` is the slot set the gateway instance is to own: the entries the
    /// template gets when the instance is absent, and the interfaces NIC
    /// verification requires when it is present. Callers pass the assignment
    /// that is live at the moment of the call.
    pub fn ensure_ready(&self, slots: &[u16]) -> Result<(), SandboxError> {
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
                self.create_instance(slots)?;
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

        // Step 4d.5: load the gateway container image into the gateway VM's
        // Docker daemon if it is not already present. The image is cached as a
        // tarball at `{daemon_lima_home}/gateway-image.tar` (populated via
        // `make gateway-image && docker save <tag> -o <path>` by the operator
        // before starting the daemon). If the tarball is absent, we skip and
        // let the session-create check catch the missing image later.
        self.load_gateway_image_if_needed();

        // Step 4e: verify the slot→NIC map against the VM and cache it.
        //
        // Verification is purely mechanical — it reports which of the expected
        // interfaces the VM actually has. Any mismatch between the discovered
        // count and the configured pool size is handled by the pool-resize
        // decision in the bin-crate startup sequence, which calls
        // `decide_pool_resize` after `ensure_ready` returns. This method does
        // not decide; it only observes and caches.
        let nic_map = self.discover_nics(slots)?;
        let discovered = nic_map.discovered_count;
        info!(
            nic_count = discovered,
            mapped = nic_map.slot_to_iface.len(),
            "gateway Lima NIC verification complete"
        );
        {
            let mut guard = self.nic_map.lock().unwrap_or_else(|e| e.into_inner());
            *guard = Some(nic_map);
        }

        // Step 4f: ensure sandboxd-egress bridge.
        self.ensure_egress_bridge()?;

        // Step 4g: apply baseline eth0 nft policy.
        self.apply_eth0_nft_policy()?;

        // Step 4h: ensure the sandbox-route-helper is installed and setcap'd
        // inside the gateway VM. Required for the lite-mode container path on
        // macOS. Non-fatal if the host-side binary is not yet staged — lite
        // sessions will fail at route-install time with an actionable error.
        if let Err(e) = self.ensure_route_helper_in_vm() {
            warn!(
                error = %e,
                "ensure_route_helper_in_vm failed (non-fatal; \
                 lite-mode sessions will fail at route-install time)"
            );
        }

        info!("gateway Lima instance ready");
        Ok(())
    }

    // -------------------------------------------------------------------------
    // Private helpers
    // -------------------------------------------------------------------------

    /// Load the gateway container image into the gateway VM's Docker daemon
    /// from a cached tarball, if the image is not already present.
    ///
    /// The tarball lives at `{daemon_lima_home}/gateway-image.tar`. The operator
    /// populates it via:
    ///   make gateway-image && \
    ///   docker save sandbox-gateway:$(cat sandboxd/Cargo.toml | grep '^version' | cut -d'"' -f2) \
    ///     -o {daemon_lima_home}/gateway-image.tar
    ///
    /// If the tarball is absent this is a best-effort no-op — the session-create
    /// check will catch the missing image and return an actionable error.
    ///
    /// Non-fatal: failures are logged at `warn!` but do not abort `ensure_ready`.
    fn load_gateway_image_if_needed(&self) {
        let tarball = self.daemon_lima_home.join(GATEWAY_IMAGE_TARBALL_FILENAME);
        if !tarball.exists() {
            // The tarball is not yet in daemon_lima_home.  Check whether
            // install.sh staged it at the daemon base dir
            // (`{state_root}/{daemon_uid}/gateway-image.tar`), which is two
            // levels above daemon_lima_home (`…/{daemon_uid}/{daemon_uid}/lima`).
            // If it is there, copy it into daemon_lima_home so that the path
            // the Docker-load code below expects is satisfied.
            let staged = self
                .daemon_lima_home
                .parent()
                .and_then(|p| p.parent())
                .map(|base| base.join(GATEWAY_IMAGE_TARBALL_FILENAME));
            let copied = if let Some(ref staged_path) = staged {
                if staged_path.exists() {
                    // Ensure daemon_lima_home exists (ensure_ready creates it, but
                    // belt-and-suspenders before the copy).
                    if let Err(e) = std::fs::create_dir_all(&self.daemon_lima_home) {
                        warn!(
                            error = %e,
                            dir = %self.daemon_lima_home.display(),
                            "failed to create daemon_lima_home for tarball copy; skipping"
                        );
                        false
                    } else {
                        match std::fs::copy(staged_path, &tarball) {
                            Ok(_) => {
                                info!(
                                    from = %staged_path.display(),
                                    to = %tarball.display(),
                                    "gateway image tarball copied from staged location"
                                );
                                true
                            }
                            Err(e) => {
                                warn!(
                                    error = %e,
                                    from = %staged_path.display(),
                                    to = %tarball.display(),
                                    "failed to copy staged gateway tarball; skipping docker load"
                                );
                                false
                            }
                        }
                    }
                } else {
                    false
                }
            } else {
                false
            };

            if !copied {
                info!(
                    tarball = %tarball.display(),
                    "gateway image tarball not found; skipping docker load \
                     (populate it with: make gateway-image && docker save <tag> -o {})",
                    tarball.display()
                );
                return;
            }
        }

        // Check if the image is already loaded in the gateway VM's Docker daemon.
        let image_tag = gateway_image_tag_for_daemon(env!("CARGO_PKG_VERSION"));
        let socket_str = format!("unix://{}", self.gateway_docker_socket.display());
        let inspect = {
            let mut cmd = Command::new("docker");
            apply_docker_env(&mut cmd);
            cmd.args(["-H", &socket_str, "image", "inspect", &image_tag]);
            run_with_timeout(
                &mut cmd,
                DOCKER_OP_TIMEOUT,
                "docker image inspect (gateway)",
            )
        };
        match inspect {
            Ok(ref out) if out.status.success() => {
                info!(tag = %image_tag, "gateway image already loaded in gateway VM");
                return;
            }
            Ok(_) => {
                // Image not present — proceed to load.
            }
            Err(e) => {
                warn!(
                    error = %e,
                    "docker image inspect in gateway VM failed; attempting load anyway"
                );
            }
        }

        // Load the tarball via stdin pipe into `docker load`.
        // Stream the file directly to the child's stdin rather than reading
        // the entire (hundreds of MB) tarball into memory first.
        info!(
            tarball = %tarball.display(),
            tag = %image_tag,
            "loading gateway image into gateway VM from tarball"
        );

        let load_result = {
            use std::io;
            use std::process::Stdio;
            let spawn_result = {
                let mut cmd = Command::new("docker");
                apply_docker_env(&mut cmd);
                cmd.args(["-H", &socket_str, "load"])
                    .stdin(Stdio::piped())
                    .stdout(Stdio::piped())
                    .stderr(Stdio::piped())
                    .spawn()
            };
            let mut child = match spawn_result {
                Ok(c) => c,
                Err(e) => {
                    warn!(error = %e, "failed to spawn docker load for gateway image");
                    return;
                }
            };
            // Take the stdin handle so we own it and can drop it to signal EOF.
            let mut stdin = match child.stdin.take() {
                Some(s) => s,
                None => {
                    warn!("docker load: failed to take stdin handle");
                    let _ = child.kill();
                    return;
                }
            };
            let mut file = match std::fs::File::open(&tarball) {
                Ok(f) => f,
                Err(e) => {
                    warn!(
                        tarball = %tarball.display(),
                        error = %e,
                        "failed to open gateway image tarball for streaming"
                    );
                    let _ = child.kill();
                    return;
                }
            };
            if let Err(e) = io::copy(&mut file, &mut stdin) {
                warn!(error = %e, "failed to stream tarball to docker load stdin");
                let _ = child.kill();
                return;
            }
            // Drop stdin to close the pipe and signal EOF to docker load.
            drop(stdin);
            match child.wait_with_output() {
                Ok(o) => o,
                Err(e) => {
                    warn!(error = %e, "docker load wait failed");
                    return;
                }
            }
        };

        if load_result.status.success() {
            info!(tag = %image_tag, "gateway image loaded into gateway VM");
        } else {
            warn!(
                tag = %image_tag,
                stderr = %String::from_utf8_lossy(&load_result.stderr).trim(),
                "docker load for gateway image returned non-zero; \
                 gateway sessions may fail if image is missing"
            );
        }
    }

    /// Load the lite container image into the gateway VM's Docker daemon
    /// from a cached tarball, if the image is not already present.
    ///
    /// The tarball lives at `{daemon_lima_home}/lite-image.tar`. The operator
    /// populates it via:
    ///   make lite-image && make stage-lite-image
    ///
    /// Idempotent: skips the load when the image is already present in the
    /// gateway VM's Docker daemon (checked via `docker image inspect`).
    ///
    /// Non-fatal: on tarball absence the function returns `Ok(())` — the
    /// subsequent `docker create` in `create_session_macos_lite` will fail
    /// with a clear "No such image" error, surfacing an actionable message
    /// to the operator.  On load failure the error is propagated so the
    /// caller can surface it before allocating any session resources.
    pub fn load_lite_image_into_gateway(&self) -> Result<(), SandboxError> {
        let tarball = self.daemon_lima_home.join(LITE_IMAGE_TARBALL_FILENAME);
        if !tarball.exists() {
            info!(
                tarball = %tarball.display(),
                "lite image tarball not found; skipping docker load \
                 (populate it with: make lite-image && make stage-lite-image)"
            );
            return Ok(());
        }

        let image_tag = lite_image_tag_for_version(env!("CARGO_PKG_VERSION"));
        let socket_str = format!("unix://{}", self.gateway_docker_socket.display());

        // Idempotence check: skip if the image is already present.
        let inspect = {
            let mut cmd = Command::new("docker");
            apply_docker_env(&mut cmd);
            cmd.args(["-H", &socket_str, "image", "inspect", &image_tag]);
            run_with_timeout(&mut cmd, DOCKER_OP_TIMEOUT, "docker image inspect (lite)")
        };
        match inspect {
            Ok(ref out) if out.status.success() => {
                info!(tag = %image_tag, "lite image already loaded in gateway VM");
                return Ok(());
            }
            Ok(_) => {
                // Image not present — proceed to load.
            }
            Err(e) => {
                warn!(
                    error = %e,
                    "docker image inspect for lite image in gateway VM failed; attempting load anyway"
                );
            }
        }

        info!(
            tarball = %tarball.display(),
            tag = %image_tag,
            "loading lite image into gateway VM from tarball"
        );
        let load_result = {
            use std::io;
            use std::process::Stdio;
            let mut child = {
                let mut cmd = Command::new("docker");
                apply_docker_env(&mut cmd);
                cmd.args(["-H", &socket_str, "load"])
                    .stdin(Stdio::piped())
                    .stdout(Stdio::piped())
                    .stderr(Stdio::piped())
                    .spawn()
                    .map_err(|e| {
                        SandboxError::Internal(format!(
                            "failed to spawn docker load for lite image: {e}"
                        ))
                    })?
            };
            // Take the stdin handle so we own it and can drop it to signal EOF.
            let mut stdin = child.stdin.take().ok_or_else(|| {
                let _ = child.kill();
                SandboxError::Internal(
                    "docker load (lite): failed to take stdin handle".to_string(),
                )
            })?;
            let mut file = std::fs::File::open(&tarball).map_err(|e| {
                let _ = child.kill();
                SandboxError::Internal(format!(
                    "failed to open lite image tarball {}: {e}",
                    tarball.display()
                ))
            })?;
            if let Err(e) = io::copy(&mut file, &mut stdin) {
                let _ = child.kill();
                return Err(SandboxError::Internal(format!(
                    "failed to stream lite tarball to docker load stdin: {e}"
                )));
            }
            // Drop stdin to close the pipe and signal EOF to docker load.
            drop(stdin);
            child.wait_with_output().map_err(|e| {
                SandboxError::Internal(format!("docker load wait failed for lite image: {e}"))
            })?
        };

        if load_result.status.success() {
            info!(tag = %image_tag, "lite image loaded into gateway VM");
            Ok(())
        } else {
            let stderr = String::from_utf8_lossy(&load_result.stderr);
            Err(SandboxError::Internal(format!(
                "docker load for lite image returned non-zero (tag={image_tag}): {}",
                stderr.trim()
            )))
        }
    }

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
    ///
    /// `slots` is the slot set the new instance owns — one pinned `networks:`
    /// entry each.
    fn create_instance(&self, slots: &[u16]) -> Result<(), SandboxError> {
        let template_content = generate_gateway_template(slots);

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
                // The gateway VM is daemon infrastructure; it always runs as the
                // daemon uid and goes through run_limactl_direct, bypassing the
                // agent's socket_vmnet check. The field is set to true here to
                // reflect that the gateway template includes a socket_vmnet NIC,
                // though the value is not inspected by run_limactl_direct.
                is_hardened_session: true,
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

    /// Verify the slot→NIC map by running `ip -json link show` inside the VM.
    ///
    /// The map itself is built from `slots`; the guest output is only checked
    /// against it. See [`discover_nics_from_ip_json`].
    fn discover_nics(&self, slots: &[u16]) -> Result<NicMap, SandboxError> {
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
        discover_nics_from_ip_json(&json, slots)
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

    /// The Lima instance name for the daemon-owned gateway VM.
    /// Exposed as an associated constant so daemon code that needs to pass
    /// the VM name to `build_in_vm_route_helper_argv` can reference it without
    /// importing the module-level constant directly.
    pub const GATEWAY_INSTANCE_NAME: &'static str = GATEWAY_INSTANCE_NAME;

    /// Run a shell command inside the gateway Lima VM via `limactl shell`.
    ///
    /// This is the degenerate direct path (daemon_uid == op_uid) — the daemon
    /// runs `limactl` directly as `_sandboxd`, which already owns the gateway
    /// instance's LIMA_HOME.
    pub fn run_gateway_shell(
        &self,
        command: &str,
        timeout: Duration,
    ) -> Result<std::process::Output, SandboxError> {
        let mut cmd = Command::new("limactl");
        apply_limactl_env(&mut cmd, self.daemon_uid);
        cmd.args(["shell", GATEWAY_INSTANCE_NAME, "--", "bash", "-c", command]);

        run_with_timeout(&mut cmd, timeout, "gateway: limactl shell")
    }

    /// Run an arbitrary argv inside the gateway Lima VM via `limactl shell`.
    ///
    /// The argv is expected to be in the form returned by
    /// `build_in_vm_route_helper_argv`: `["shell", "<vm>", "--", <cmd>, <args>...]`.
    /// The first two elements (`shell` and the VM name) are extracted as
    /// positional args after `limactl`; the rest are passed verbatim.
    ///
    /// This is used for the in-VM `sandbox-route-helper --vm-gateway-mode`
    /// invocation, which cannot go through `run_gateway_shell` (string command)
    /// because the helper's argv cannot be safely shell-escaped in general.
    pub fn run_gateway_shell_argv(
        &self,
        argv: &[String],
    ) -> Result<std::process::Output, SandboxError> {
        // argv shape: ["shell", "<vm>", "--", <rest...>]
        // limactl shell <vm> -- <rest...>
        if argv.len() < 4 || argv[0] != "shell" || argv[2] != "--" {
            return Err(SandboxError::Internal(format!(
                "run_gateway_shell_argv: unexpected argv shape: {argv:?}"
            )));
        }
        let mut cmd = Command::new("limactl");
        apply_limactl_env(&mut cmd, self.daemon_uid);
        // argv[0] = "shell", argv[1] = vm_name, argv[2] = "--", argv[3..] = command
        cmd.args(argv);
        run_with_timeout(
            &mut cmd,
            GATEWAY_SHELL_TIMEOUT,
            "gateway: limactl shell (argv)",
        )
    }

    /// Ensure `sandbox-route-helper` is installed and setcap'd inside the
    /// gateway Lima VM.
    ///
    /// The lite-mode container path invokes the route-helper inside the gateway
    /// VM (via `limactl shell … sudo sandbox-route-helper --vm-gateway-mode`)
    /// to install the default route inside the sandbox container's netns. The
    /// helper binary must exist in the VM with the required file capabilities.
    ///
    /// # Provisioning mechanism
    ///
    /// The daemon LIMA_HOME (`{daemon_lima_home}`) is expected to contain a
    /// pre-staged Linux aarch64 binary at
    /// `{daemon_lima_home}/sandbox-route-helper-linux-aarch64`.
    ///
    /// The operator populates this binary via:
    /// ```text
    /// make build-route-helper-linux-aarch64
    /// ```
    /// or by downloading from the release assets and renaming to
    /// `sandbox-route-helper-linux-aarch64` in the daemon LIMA_HOME.
    ///
    /// If the binary is not found at the host path, this method logs a
    /// warning and returns `Ok(())` — lite-mode sessions will fail at
    /// route-install time rather than at daemon startup. This is intentional:
    /// the gateway VM can still serve Lima sessions without the route-helper.
    ///
    /// If the binary is already present in the VM and setcap'd correctly, this
    /// method is a fast no-op (checked via a `test -x` probe).
    ///
    /// # Security
    ///
    /// The copy targets `/usr/local/libexec/sandboxd/sandbox-route-helper` in
    /// the VM. After copying, `sudo setcap 'cap_net_admin,cap_sys_admin,
    /// cap_sys_ptrace=eip'` is applied. The VM's sudo is passwordless for root
    /// operations (Lima's provisioning model).
    pub fn ensure_route_helper_in_vm(&self) -> Result<(), SandboxError> {
        use tracing::debug;

        let host_binary = self
            .daemon_lima_home
            .join(ROUTE_HELPER_LINUX_BINARY_FILENAME);

        if !host_binary.exists() {
            warn!(
                path = %host_binary.display(),
                "gateway VM route-helper binary not found at staging path; \
                 lite-mode sessions will fail at route-install time. \
                 Populate it with: make build-route-helper-linux-aarch64"
            );
            return Ok(());
        }

        // Probe: check that the binary is installed, executable, and has the expected
        // capability set. Checking only `test -x` is insufficient — a binary that was
        // copied but whose `setcap` step failed (or whose caps were stripped) passes
        // the executable probe but then fails at route-install time with EPERM. The
        // `getcap | grep` check catches that case and forces a reinstall.
        let probe_result = self.run_gateway_shell(
            &format!(
                "test -x {IN_VM_ROUTE_HELPER_PATH} && \
                 getcap {IN_VM_ROUTE_HELPER_PATH} | grep -q cap_net_admin && echo exists"
            ),
            ROUTE_HELPER_COPY_TIMEOUT,
        );
        let already_installed = match probe_result {
            Ok(output) => {
                let stdout = String::from_utf8_lossy(&output.stdout);
                output.status.success() && stdout.trim() == "exists"
            }
            Err(_) => false,
        };

        if already_installed {
            debug!("gateway VM route-helper already installed with caps; skipping copy");
            return Ok(());
        }

        info!(
            src = %host_binary.display(),
            dst = %format!("{}:{IN_VM_ROUTE_HELPER_PATH}", GATEWAY_INSTANCE_NAME),
            "installing sandbox-route-helper into gateway VM"
        );

        // Create the target directory inside the VM.
        let mkdir_output = self.run_gateway_shell(
            "sudo mkdir -p /usr/local/libexec/sandboxd",
            ROUTE_HELPER_COPY_TIMEOUT,
        )?;
        if !mkdir_output.status.success() {
            let stderr = String::from_utf8_lossy(&mkdir_output.stderr);
            return Err(SandboxError::Lima(format!(
                "ensure_route_helper_in_vm: failed to mkdir in gateway VM: {stderr}"
            )));
        }

        // Copy the binary from the host into the gateway VM using `limactl copy`.
        //
        // `limactl copy` runs rsync-over-ssh as the unprivileged Lima SSH user
        // (the operator), which cannot write into the root-owned
        // /usr/local/libexec/sandboxd directory created above. So stage the
        // binary at a writable temp path first, then `sudo install` it into the
        // final root-owned location below.
        const STAGED_ROUTE_HELPER_PATH: &str = "/tmp/sandbox-route-helper.staged";
        let dst = format!("{GATEWAY_INSTANCE_NAME}:{STAGED_ROUTE_HELPER_PATH}");
        let mut copy_cmd = Command::new("limactl");
        apply_limactl_env(&mut copy_cmd, self.daemon_uid);
        copy_cmd.args(["copy", host_binary.to_str().unwrap_or(""), &dst]);
        let copy_output = run_with_timeout(
            &mut copy_cmd,
            ROUTE_HELPER_COPY_TIMEOUT,
            "gateway: limactl copy",
        )?;
        if !copy_output.status.success() {
            let stderr = String::from_utf8_lossy(&copy_output.stderr);
            return Err(SandboxError::Lima(format!(
                "ensure_route_helper_in_vm: limactl copy failed: {stderr}"
            )));
        }

        // Move the staged binary into the root-owned final location as root.
        // `install -m 0755` places it atomically with the correct mode, then
        // remove the staging copy. This is the privileged step the unprivileged
        // `limactl copy` above cannot perform directly.
        let install_output = self.run_gateway_shell(
            &format!(
                "sudo install -m 0755 {STAGED_ROUTE_HELPER_PATH} {IN_VM_ROUTE_HELPER_PATH} && \
                 rm -f {STAGED_ROUTE_HELPER_PATH}"
            ),
            ROUTE_HELPER_COPY_TIMEOUT,
        )?;
        if !install_output.status.success() {
            let stderr = String::from_utf8_lossy(&install_output.stderr);
            return Err(SandboxError::Lima(format!(
                "ensure_route_helper_in_vm: install into {IN_VM_ROUTE_HELPER_PATH} failed: {stderr}"
            )));
        }

        // Set execute bit and apply capabilities.
        let setcap_output = self.run_gateway_shell(
            &format!(
                "sudo chmod +x {IN_VM_ROUTE_HELPER_PATH} && \
                 sudo setcap 'cap_net_admin,cap_sys_admin,cap_sys_ptrace=eip' \
                 {IN_VM_ROUTE_HELPER_PATH}"
            ),
            ROUTE_HELPER_COPY_TIMEOUT,
        )?;
        if !setcap_output.status.success() {
            let stderr = String::from_utf8_lossy(&setcap_output.stderr);
            return Err(SandboxError::Lima(format!(
                "ensure_route_helper_in_vm: setcap failed: {stderr}"
            )));
        }

        info!("sandbox-route-helper installed and setcap'd in gateway VM");
        Ok(())
    }

    /// Stage a session's lite-container provisioning files into a per-session,
    /// operator-writable, VM-resident directory and return that directory's
    /// path inside the gateway VM.
    ///
    /// On macOS the lite container runs inside the gateway VM via the forwarded
    /// Docker socket, so Docker resolves bind-mount *sources* against the VM
    /// filesystem — not the macOS host. The CA cert and the three SSH files
    /// (`authorized_keys`, `passwd`, `group`) the daemon generated on the host
    /// therefore have to be copied into the VM before `docker create` can bind
    /// them into the container at their canonical in-container paths.
    ///
    /// The staging directory is `{LITE_STAGE_ROOT}/<session_id>/`. The four
    /// files keep their canonical basenames so the existing bind builders
    /// (`build_ca_mount_args` binds `<dir>/cert.pem`; `build_ssh_mount_args`
    /// joins `<dir>` with the three SSH filenames) can point at the returned
    /// VM directory unchanged.
    ///
    /// Idempotent: the `mkdir -p` and per-file `limactl copy` overwrite, so it
    /// is safe to call on both the create and restart paths.
    ///
    /// Returns the VM staging directory path (e.g.
    /// `/tmp/sandbox-lite/<session_id>`). The caller sets the
    /// `ContainerNetwork`'s `ca_host_path` to `<dir>/cert.pem` and its
    /// `ssh_host_dir` to `<dir>`.
    pub fn stage_lite_session_files(
        &self,
        session_id: &str,
        cert_pem_host: &Path,
        authorized_keys_host: &Path,
        passwd_host: &Path,
        group_host: &Path,
    ) -> Result<String, SandboxError> {
        let vm_dir = lite_stage_dir(session_id);

        // Create the per-session staging directory in the VM's sticky /tmp.
        // Runs as the operator's Lima SSH login — no sudo needed.
        let mkdir_argv = lite_stage_mkdir_argv(&vm_dir);
        let mkdir_output = self.run_gateway_shell_argv(&mkdir_argv)?;
        if !mkdir_output.status.success() {
            let stderr = String::from_utf8_lossy(&mkdir_output.stderr);
            return Err(SandboxError::Lima(format!(
                "stage_lite_session_files: failed to mkdir {vm_dir} in gateway VM: {stderr}"
            )));
        }

        // Copy each file into the staging directory under its canonical
        // basename so the bind builders resolve the same paths the Linux
        // host binds use.
        for (host_src, basename) in [
            (cert_pem_host, "cert.pem"),
            (authorized_keys_host, "authorized_keys"),
            (passwd_host, "passwd"),
            (group_host, "group"),
        ] {
            let dst = format!("{GATEWAY_INSTANCE_NAME}:{vm_dir}/{basename}");
            let mut copy_cmd = Command::new("limactl");
            apply_limactl_env(&mut copy_cmd, self.daemon_uid);
            copy_cmd.args(["copy", host_src.to_str().unwrap_or(""), &dst]);
            let copy_output = run_with_timeout(
                &mut copy_cmd,
                LITE_FILE_STAGE_TIMEOUT,
                "gateway: limactl copy (lite session file)",
            )?;
            if !copy_output.status.success() {
                let stderr = String::from_utf8_lossy(&copy_output.stderr);
                return Err(SandboxError::Lima(format!(
                    "stage_lite_session_files: limactl copy of {basename} into {vm_dir} failed: {stderr}"
                )));
            }
        }

        info!(
            session_id = %session_id,
            vm_dir = %vm_dir,
            "staged lite session files into gateway VM"
        );
        Ok(vm_dir)
    }

    /// Remove a session's lite-container staging directory from the gateway VM.
    ///
    /// Best-effort: failures are logged at `warn!` and swallowed. The bind into
    /// the container holds no lock on these files (Docker copies the bind source
    /// at mount time), so removing the staging dir on delete simply reclaims the
    /// non-secret bytes; a failure here never blocks teardown.
    pub fn cleanup_lite_session_files(&self, session_id: &str) {
        let vm_dir = lite_stage_dir(session_id);
        let argv = lite_stage_rm_argv(&vm_dir);
        match self.run_gateway_shell_argv(&argv) {
            Ok(output) if output.status.success() => {
                info!(
                    session_id = %session_id,
                    vm_dir = %vm_dir,
                    "removed lite session staging dir from gateway VM"
                );
            }
            Ok(output) => {
                let stderr = String::from_utf8_lossy(&output.stderr);
                warn!(
                    session_id = %session_id,
                    vm_dir = %vm_dir,
                    stderr = %stderr.trim(),
                    "cleanup_lite_session_files: rm returned non-zero (non-fatal)"
                );
            }
            Err(e) => {
                warn!(
                    session_id = %session_id,
                    vm_dir = %vm_dir,
                    error = %e,
                    "cleanup_lite_session_files: rm failed (non-fatal)"
                );
            }
        }
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

    /// Return the current Lima instance state string.
    ///
    /// Returns `"Running"`, `"Stopped"`, or `"None"` (instance absent).
    /// Thin public wrapper over `query_instance_state` so the recovery
    /// orchestrator can snapshot instance state without calling `ensure_ready`.
    pub fn instance_state(&self) -> Result<String, SandboxError> {
        self.query_instance_state()
    }

    /// Probe whether the gateway Docker daemon is reachable via the forwarded
    /// socket.
    ///
    /// Runs a single `docker -H <sock> info` with a short timeout.
    ///
    /// - `Ok(true)` — daemon healthy and reachable.
    /// - `Ok(false)` — connection refused, timeout, or non-zero exit: the
    ///   gateway VM is down or its Docker daemon has not started; the failure
    ///   is retryable by the caller.
    /// - `Err(_)` — unexpected internal error (e.g. `run_with_timeout` could
    ///   not spawn the child).
    pub fn probe_docker_health(&self) -> Result<bool, SandboxError> {
        let socket_str = format!("unix://{}", self.gateway_docker_socket.display());
        let mut cmd = Command::new("docker");
        apply_docker_env(&mut cmd);
        cmd.args(["-H", &socket_str, "info"]);

        let result = run_with_timeout(
            &mut cmd,
            Duration::from_secs(5),
            "gateway: docker info probe via forwarded socket",
        );

        match result {
            Ok(output) => Ok(output.status.success()),
            Err(SandboxError::Timeout { .. }) => Ok(false),
            Err(e) => Err(e),
        }
    }

    /// Resolve the version-pinned gateway image tag the daemon expects inside
    /// the gateway Lima instance.
    ///
    /// Surfaced through `/diagnostics` so doctor can show which tag the
    /// presence check is keyed on.
    pub fn expected_gateway_image_tag(&self) -> String {
        gateway_image_tag_for_daemon(env!("CARGO_PKG_VERSION"))
    }

    /// Probe whether the version-pinned gateway image is present inside the
    /// gateway Lima instance, via the forwarded Docker socket.
    ///
    /// - `Ok(true)` — `docker -H <sock> image inspect <tag>` exited 0.
    /// - `Ok(false)` — the probe ran and the image is absent (`no such image`
    ///   / `no such object`).
    /// - `Err(_)` — the probe could not run to a verdict (Docker daemon
    ///   unreachable, fork failure, unexpected stderr). The caller maps this
    ///   to a "restart the daemon" hint rather than "image missing".
    ///
    /// Mirrors the host-side `gateway::gateway_image_present` three-state
    /// contract, but targets the forwarded gateway Docker socket instead of
    /// the host Docker daemon.
    pub fn gateway_image_present_inside_lima(&self) -> Result<bool, SandboxError> {
        let tag = self.expected_gateway_image_tag();
        let socket_str = format!("unix://{}", self.gateway_docker_socket.display());
        let mut cmd = Command::new("docker");
        apply_docker_env(&mut cmd);
        cmd.args(["-H", &socket_str, "image", "inspect", &tag]);

        let output = run_with_timeout(
            &mut cmd,
            DOCKER_OP_TIMEOUT,
            "gateway: docker image inspect via forwarded socket",
        )?;
        if output.status.success() {
            return Ok(true);
        }
        let stderr_lower = String::from_utf8_lossy(&output.stderr).to_lowercase();
        if stderr_lower.contains("no such image") || stderr_lower.contains("no such object") {
            Ok(false)
        } else {
            Err(SandboxError::Internal(format!(
                "docker image inspect {tag} via gateway socket failed unexpectedly: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            )))
        }
    }

    /// Check whether the daemon-versioned lite image is present inside the
    /// gateway VM's Docker.
    ///
    /// Mirrors [`gateway_image_present_inside_lima`] but targets the lite
    /// image tag (`sandboxd-lite:<version>`). On macOS the lite image lives in
    /// the gateway VM's Docker — there is no host Docker — so this is the only
    /// correct probe site.
    pub fn lite_image_present_inside_lima(&self) -> Result<bool, SandboxError> {
        use crate::backend::lite_image_tag_for_version;
        let tag = lite_image_tag_for_version(env!("CARGO_PKG_VERSION"));
        let socket_str = format!("unix://{}", self.gateway_docker_socket.display());
        let mut cmd = Command::new("docker");
        apply_docker_env(&mut cmd);
        cmd.args(["-H", &socket_str, "image", "inspect", &tag]);

        let output = run_with_timeout(
            &mut cmd,
            DOCKER_OP_TIMEOUT,
            "gateway: docker image inspect lite via forwarded socket",
        )?;
        if output.status.success() {
            return Ok(true);
        }
        let stderr_lower = String::from_utf8_lossy(&output.stderr).to_lowercase();
        if stderr_lower.contains("no such image") || stderr_lower.contains("no such object") {
            Ok(false)
        } else {
            Err(SandboxError::Internal(format!(
                "docker image inspect {tag} via gateway socket failed unexpectedly: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            )))
        }
    }

    /// Probe the version string of the daemon's `limactl` binary.
    ///
    /// Runs `limactl --version` with the same minimal `PATH` the daemon uses
    /// for its gateway-instance control-plane ops (Homebrew + `/usr/local/bin`
    /// ahead of the inherited `PATH`). This is a pure binary-version read with
    /// no operator-uid context — distinct from the privilege-pivoting
    /// control-plane ops that must route through `sandbox-lima-helper`.
    ///
    /// Returns the parsed `X.Y.Z` version string (e.g. `"1.2.0"`) on success.
    pub fn lima_version(&self) -> Result<String, SandboxError> {
        let mut cmd = Command::new("limactl");
        let current_path = std::env::var("PATH").unwrap_or_default();
        let path_value = format!("/opt/homebrew/bin:/usr/local/bin:{current_path}");
        cmd.env("PATH", &path_value).arg("--version");

        let output =
            run_with_timeout(&mut cmd, GATEWAY_LIST_TIMEOUT, "gateway: limactl --version")?;
        if !output.status.success() {
            return Err(SandboxError::Lima(format!(
                "limactl --version failed: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            )));
        }
        // `limactl --version` prints `limactl version X.Y.Z`; extract the
        // first dotted-numeric token so the doctor can compare against
        // MIN_LIMA_VERSION regardless of surrounding wording.
        let stdout = String::from_utf8_lossy(&output.stdout);
        let version = stdout
            .split_whitespace()
            .find(|tok| {
                let trimmed = tok.trim_start_matches('v');
                let mut parts = trimmed.split('.');
                parts.clone().count() >= 2 && parts.all(|p| p.chars().all(|c| c.is_ascii_digit()))
            })
            .map(|tok| tok.trim_start_matches('v').to_string())
            .ok_or_else(|| {
                SandboxError::Lima(format!(
                    "could not parse limactl version from output: {}",
                    stdout.trim()
                ))
            })?;
        Ok(version)
    }

    /// Stop the gateway Lima instance unconditionally (`limactl stop --force`).
    ///
    /// Tolerates "not running" and "not found" as success so the recovery
    /// orchestrator can call this without needing to know the current state.
    pub fn force_stop_instance(&self) -> Result<(), SandboxError> {
        let output = self.executor.run(
            self.daemon_uid,
            LimaOp::Stop {
                vm: GATEWAY_INSTANCE_NAME,
                force: true,
            },
            GATEWAY_STOP_TIMEOUT,
            "gateway: limactl stop --force",
        )?;

        if output.status.success() {
            info!("gateway Lima instance force-stopped");
            return Ok(());
        }

        let stderr = String::from_utf8_lossy(&output.stderr);
        // Tolerate "already stopped" and "not found" — idempotent.
        if stderr.contains("not running")
            || stderr.contains("not found")
            || stderr.contains("no instance")
            || stderr.contains("instance not found")
        {
            info!(
                stderr = %stderr.trim(),
                "gateway Lima force-stop: already stopped or absent (treating as success)"
            );
            return Ok(());
        }

        Err(SandboxError::Lima(format!(
            "gateway: limactl stop --force failed: {stderr}"
        )))
    }

    /// Delete the gateway Lima instance (`limactl delete sandboxd-gateway`).
    ///
    /// Idempotent: "not found" and "no instance" errors are treated as success.
    /// Called by the pool-resize rebuild arm after `force_stop_instance` to
    /// remove the instance directory before `create_instance` rebuilds it with
    /// a new NIC count. (`create_instance` fails with "already exists" if the
    /// directory is still present.)
    pub fn delete_instance(&self) -> Result<(), SandboxError> {
        let output = self.executor.run(
            self.daemon_uid,
            LimaOp::Delete {
                vm: GATEWAY_INSTANCE_NAME,
            },
            GATEWAY_STOP_TIMEOUT,
            "gateway: limactl delete",
        )?;

        if output.status.success() {
            info!("gateway Lima instance deleted");
            return Ok(());
        }

        let stderr = String::from_utf8_lossy(&output.stderr);
        // Tolerate "not found" / "no instance" — idempotent.
        if stderr.contains("not found")
            || stderr.contains("no instance")
            || stderr.contains("instance not found")
        {
            info!(
                stderr = %stderr.trim(),
                "gateway Lima delete: instance absent (treating as success)"
            );
            return Ok(());
        }

        Err(SandboxError::Lima(format!(
            "gateway: limactl delete failed: {stderr}"
        )))
    }

    /// Restart the gateway Lima instance for crash recovery.
    ///
    /// Performs a forced stop followed by a start, then waits up to
    /// `GATEWAY_RECOVERY_READY_TIMEOUT` (90 s) for the Docker daemon to
    /// become reachable. Unlike `ensure_ready`'s 300-second first-boot timeout,
    /// the 90-second recovery timeout surfaces a stuck restart quickly so the
    /// monitor's 10-second poll can re-attempt.
    ///
    /// On success, re-verifies the slot→NIC map against `slots` and re-caches
    /// it, then re-establishes the egress bridge and applies the baseline
    /// `eth0` nft policy (all idempotent operations).
    ///
    /// This path never creates an instance, so `slots` is used only for
    /// verification — a slot whose interface the restarted VM does not carry
    /// drops out of the map, and the sessions on it are refused rather than
    /// re-parented onto a guess.
    ///
    /// Callers must wrap this in `tokio::task::spawn_blocking` because it
    /// shells out to `limactl` and `docker`.
    pub fn restart_instance_for_recovery(&self, slots: &[u16]) -> Result<(), SandboxError> {
        info!("gateway Lima recovery: force-stopping instance");
        self.force_stop_instance()?;

        info!("gateway Lima recovery: starting instance");
        self.start_instance()?;

        // Poll until the Docker daemon is reachable via the forwarded socket,
        // using the shorter recovery deadline rather than the first-boot one.
        let deadline = Instant::now() + GATEWAY_RECOVERY_READY_TIMEOUT;
        let socket_str = format!("unix://{}", self.gateway_docker_socket.display());

        info!(
            socket = %self.gateway_docker_socket.display(),
            timeout_s = GATEWAY_RECOVERY_READY_TIMEOUT.as_secs(),
            "gateway Lima recovery: waiting for Docker daemon to be reachable"
        );

        loop {
            let mut cmd = Command::new("docker");
            apply_docker_env(&mut cmd);
            cmd.args(["-H", &socket_str, "info"]);

            let result = run_with_timeout(
                &mut cmd,
                Duration::from_secs(5),
                "gateway recovery: docker info probe",
            );

            if matches!(result, Ok(ref o) if o.status.success()) {
                info!("gateway Lima recovery: Docker daemon reachable");
                break;
            }

            if Instant::now() >= deadline {
                return Err(SandboxError::Gateway(format!(
                    "gateway Lima recovery: Docker socket at {} did not become ready within {}s",
                    self.gateway_docker_socket.display(),
                    GATEWAY_RECOVERY_READY_TIMEOUT.as_secs(),
                )));
            }

            thread::sleep(DOCKER_READY_POLL_INTERVAL);
        }

        // Re-verify the slot→NIC map and re-cache it.
        info!("gateway Lima recovery: re-verifying slot NICs");
        let nic_map = self.discover_nics(slots)?;
        {
            let mut guard = self.nic_map.lock().unwrap_or_else(|e| e.into_inner());
            *guard = Some(nic_map);
        }

        // Re-establish shared gateway fabric (idempotent operations).
        info!("gateway Lima recovery: re-establishing egress bridge");
        self.ensure_egress_bridge()?;

        info!("gateway Lima recovery: re-applying eth0 nft policy");
        self.apply_eth0_nft_policy()?;

        info!("gateway Lima recovery: instance ready");
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Pool resize decision (pure, hermetic)
// ---------------------------------------------------------------------------

/// Outcome of the pool-resize decision at daemon startup.
///
/// The daemon computes this once — after NIC discovery but before constructing
/// the `VmnetPool` — and acts on it. Every arm carries `effective_n`, the NIC
/// count that *actually exists* on the gateway instance after the arm runs;
/// callers must size the `VmnetPool` from `effective_n`, never blindly from
/// `config_n`.
#[cfg(target_os = "macos")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PoolResizeDecision {
    /// NIC count already matches config. Proceed with the existing gateway.
    NoChange {
        /// Pool size: equals `config_n` (which equals `discovered_nic_count`).
        effective_n: u16,
    },
    /// Config changed but sessions are running — cannot disrupt them. Proceed
    /// with the discovered NIC count; resize takes effect on next full restart
    /// with no sessions.
    WarnRunningSessions {
        /// Pool size capped at the currently-discovered NIC count.
        effective_n: u16,
        /// The requested new pool size (for the warning message).
        config_n: u16,
        /// Number of running sessions that prevented the resize.
        running: u32,
    },
    /// Config changed, no sessions running, but the socket_vmnet launchd daemon
    /// set has not been updated to match `config_n` — that is a privileged step
    /// the daemon cannot perform itself. Proceed with discovered count.
    RefuseNeedsPrivilegedRegen {
        /// Pool size capped at the currently-discovered NIC count.
        effective_n: u16,
        /// The requested new pool size (for the warning message).
        config_n: u16,
        /// Observed daemon-set size (for the warning message).
        daemon_set_n: u16,
    },
    /// Safe to rebuild: no sessions running and the socket_vmnet daemon set
    /// already matches `config_n`. Caller must stop → delete → recreate(target_n)
    /// → start the gateway instance, then re-discover NICs.
    Rebuild {
        /// The target NIC count for the rebuilt gateway instance.
        target_n: u16,
    },
}

/// Decide what to do when the gateway's discovered NIC count differs from the
/// configured pool size.
///
/// This is the single authority for the resize decision. It is a pure function
/// of the four startup-time observations; all I/O and orchestration live in the
/// caller.
///
/// # Arguments
///
/// * `config_n` — desired pool size from `SANDBOX_MAX_MACOS_SESSIONS` (default 8).
/// * `discovered_nic_count` — `NicMap::discovered_count` after `ensure_ready`.
/// * `daemon_set_n` — number of socket_vmnet launchd slots observed on disk
///   (plist count AND socket liveness; see `observe_vmnet_daemon_set`).
/// * `running` — number of Lima sessions currently in the `Running` state
///   (from the session store; read before constructing the pool).
///
/// # Decision tree
///
/// ```text
/// discovered == config_n  →  NoChange
/// discovered != config_n AND running > 0  →  WarnRunningSessions (effective = discovered)
/// discovered != config_n AND running == 0 AND daemon_set_n != config_n  →  RefuseNeedsPrivilegedRegen
/// discovered != config_n AND running == 0 AND daemon_set_n == config_n  →  Rebuild
/// ```
#[cfg(target_os = "macos")]
pub fn decide_pool_resize(
    config_n: u16,
    discovered_nic_count: usize,
    daemon_set_n: u16,
    running: u32,
) -> PoolResizeDecision {
    let discovered_n = discovered_nic_count as u16;
    if discovered_n == config_n {
        return PoolResizeDecision::NoChange {
            effective_n: config_n,
        };
    }
    // Mismatch: config_n != discovered.
    if running > 0 {
        return PoolResizeDecision::WarnRunningSessions {
            effective_n: discovered_n,
            config_n,
            running,
        };
    }
    if daemon_set_n != config_n {
        return PoolResizeDecision::RefuseNeedsPrivilegedRegen {
            effective_n: discovered_n,
            config_n,
            daemon_set_n,
        };
    }
    // running == 0 AND daemon_set_n == config_n — safe to rebuild.
    PoolResizeDecision::Rebuild { target_n: config_n }
}

// ---------------------------------------------------------------------------
// Daemon-set observation (no privilege; reads world-readable artifacts)
// ---------------------------------------------------------------------------

/// Default path to the system LaunchDaemons directory.
#[cfg(target_os = "macos")]
pub const VMNET_LAUNCH_DAEMONS_DIR: &str = "/Library/LaunchDaemons";

/// Count the number of `io.sandboxd.vmnet.<n>.plist` files in `plist_dir`.
///
/// Counts entries whose filename matches `^io\.sandboxd\.vmnet\.\d+\.plist$`.
/// The directory is root-owned but world-readable (`0644` plists); no privilege
/// is needed.
///
/// Returns 0 if the directory does not exist or cannot be read.
#[cfg(target_os = "macos")]
pub fn count_vmnet_plists(plist_dir: &std::path::Path) -> u16 {
    let entries = match std::fs::read_dir(plist_dir) {
        Ok(e) => e,
        Err(_) => return 0,
    };
    let mut count: u16 = 0;
    for entry in entries.flatten() {
        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        if is_vmnet_plist_name(&name_str) {
            count = count.saturating_add(1);
        }
    }
    count
}

/// Return true if `name` matches `io.sandboxd.vmnet.<n>.plist`.
#[cfg(target_os = "macos")]
fn is_vmnet_plist_name(name: &str) -> bool {
    let Some(rest) = name.strip_prefix("io.sandboxd.vmnet.") else {
        return false;
    };
    let Some(index_str) = rest.strip_suffix(".plist") else {
        return false;
    };
    index_str.parse::<u16>().is_ok()
}

/// Count how many of the `0..n` slot sockets at `socket_dir/slot-<i>.sock`
/// exist on disk.
///
/// Uses `Path::exists()` — no socket connection attempted. Returns the count of
/// present socket files.
#[cfg(target_os = "macos")]
pub fn count_reachable_slot_sockets(socket_dir: &std::path::Path, n: u16) -> u16 {
    (0..n)
        .filter(|&slot| socket_dir.join(format!("slot-{slot}.sock")).exists())
        .count() as u16
}

/// Observe the socket_vmnet launchd daemon set size without privilege.
///
/// Returns `min(plist_count, socket_count)` as a conservative proxy for the
/// number of fully-provisioned slots. This assumes plists and sockets are
/// generated with matching, contiguous indices — as `make setup-dev-env`
/// guarantees — so the minimum of the two independent totals equals the number
/// of slots where both the plist and socket are present.
///
/// In practice this is called with `config_n` as `expected_n`; the returned
/// count equals `config_n` only when the privileged regen has already produced
/// all `config_n` slots and the daemons are running.
///
/// For the resize-decision predicate, callers compare the returned value against
/// `config_n`: equality means the daemon set is ready for a gateway rebuild;
/// inequality means the privileged regen has not yet run.
///
/// Uses the production paths by default; pass explicit paths in tests.
#[cfg(target_os = "macos")]
pub fn observe_vmnet_daemon_set(
    plist_dir: &std::path::Path,
    socket_dir: &std::path::Path,
    expected_n: u16,
) -> u16 {
    let plist_count = count_vmnet_plists(plist_dir);
    let socket_count = count_reachable_slot_sockets(socket_dir, expected_n.max(plist_count));

    // Both plist and socket must be present for a slot to count.
    // The minimum of the two is the number of fully-provisioned slots.
    plist_count.min(socket_count)
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

    /// Output from a VM holding the **offset** range `{4,5,6,7}` with the
    /// per-entry `interface:` key honoured — the shape positional naming gets
    /// wrong, and the reason this parser exists.
    const IP_JSON_SLOTS_4_TO_7: &str = r#"[
    {"ifindex":1,"ifname":"lo","flags":["LOOPBACK","UP","LOWER_UP"],"link_type":"loopback","address":"00:00:00:00:00:00","broadcast":"00:00:00:00:00:00"},
    {"ifindex":2,"ifname":"eth0","flags":["BROADCAST","MULTICAST","UP","LOWER_UP"],"link_type":"ether","address":"52:55:0a:00:02:0f","broadcast":"ff:ff:ff:ff:ff:ff"},
    {"ifindex":3,"ifname":"lima4","flags":["BROADCAST","MULTICAST","UP","LOWER_UP"],"link_type":"ether","address":"52:55:0a:d1:80:20","broadcast":"ff:ff:ff:ff:ff:ff"},
    {"ifindex":4,"ifname":"lima5","flags":["BROADCAST","MULTICAST","UP","LOWER_UP"],"link_type":"ether","address":"52:55:0a:d1:80:28","broadcast":"ff:ff:ff:ff:ff:ff"},
    {"ifindex":5,"ifname":"lima6","flags":["BROADCAST","MULTICAST","UP","LOWER_UP"],"link_type":"ether","address":"52:55:0a:d1:80:30","broadcast":"ff:ff:ff:ff:ff:ff"},
    {"ifindex":6,"ifname":"lima7","flags":["BROADCAST","MULTICAST","UP","LOWER_UP"],"link_type":"ether","address":"52:55:0a:d1:80:38","broadcast":"ff:ff:ff:ff:ff:ff"}
]"#;

    #[test]
    fn nic_discovery_3_slots() {
        let map = discover_nics_from_ip_json(IP_JSON_3_SLOTS, &[0, 1, 2]).unwrap();
        assert_eq!(map.discovered_count, 3);
        assert_eq!(map.slot_to_iface.get(&0), Some(&"lima0".to_string()));
        assert_eq!(map.slot_to_iface.get(&1), Some(&"lima1".to_string()));
        assert_eq!(map.slot_to_iface.get(&2), Some(&"lima2".to_string()));
        assert_eq!(map.slot_to_iface.get(&3), None);
        assert!(map.missing_slots.is_empty());
    }

    #[test]
    fn nic_discovery_1_slot() {
        let map = discover_nics_from_ip_json(IP_JSON_1_SLOT, &[0]).unwrap();
        assert_eq!(map.discovered_count, 1);
        assert_eq!(map.slot_to_iface.get(&0), Some(&"lima0".to_string()));
    }

    /// An offset range maps to **its own** slot numbers. This is the whole
    /// point of the change: the previous parser sorted by suffix and then keyed
    /// by list position, so `lima4..lima7` came back as slots 0..3 — every
    /// session on the VM one segment-set away from where it belonged.
    #[test]
    fn nic_discovery_offset_range_keys_by_slot_not_position() {
        let map = discover_nics_from_ip_json(IP_JSON_SLOTS_4_TO_7, &[4, 5, 6, 7]).unwrap();
        assert_eq!(map.discovered_count, 4);
        assert_eq!(map.interface_for_slot(4), Some("lima4"));
        assert_eq!(map.interface_for_slot(5), Some("lima5"));
        assert_eq!(map.interface_for_slot(6), Some("lima6"));
        assert_eq!(map.interface_for_slot(7), Some("lima7"));
        // The positional reading would have put entries here.
        for slot in 0u16..4 {
            assert_eq!(
                map.interface_for_slot(slot),
                None,
                "slot {slot} is not in this VM's range and must not be mapped"
            );
        }
        assert!(map.missing_slots.is_empty());
    }

    /// Every mapped name is derived from the slot, never lifted from the guest
    /// string — asserted over the whole map rather than at one entry.
    #[test]
    fn nic_map_names_are_derived_from_the_slot_for_every_entry() {
        for slots in [&[0u16, 1, 2][..], &[4, 5, 6, 7][..]] {
            let json = if slots[0] == 0 {
                IP_JSON_3_SLOTS
            } else {
                IP_JSON_SLOTS_4_TO_7
            };
            let map = discover_nics_from_ip_json(json, slots).unwrap();
            for (slot, iface) in &map.slot_to_iface {
                assert_eq!(
                    iface,
                    &slot_interface_name(*slot),
                    "slot {slot} mapped to {iface}, which is not its own interface name"
                );
            }
        }
    }

    #[test]
    fn nic_discovery_excludes_eth0() {
        let map = discover_nics_from_ip_json(IP_JSON_3_SLOTS, &[0, 1, 2]).unwrap();
        // eth0 must never appear as a slot NIC.
        for iface in map.slot_to_iface.values() {
            assert_ne!(iface, "eth0", "eth0 must never be mapped to a slot");
        }
    }

    #[test]
    fn nic_discovery_no_lima_nics() {
        // When no limaN NICs are present, we get an empty map (discovered_count 0).
        // This is the count-mismatch non-fatal case.
        let map = discover_nics_from_ip_json(IP_JSON_NO_LIMA, &[0, 1, 2]).unwrap();
        assert_eq!(map.discovered_count, 0);
        assert!(map.slot_to_iface.is_empty());
        assert_eq!(map.missing_slots, vec![0, 1, 2]);
    }

    /// A slot the VM does not carry is **absent** from the map, not guessed
    /// into it. This is the fail-closed half: the claim sites turn the absence
    /// into a refused session.
    ///
    /// It is also the backstop for a Lima too old to honour the per-entry
    /// `interface:` key — such a VM names an offset range positionally, so none
    /// of the expected interfaces exist and every slot fails verification
    /// rather than silently mapping to another slot's segment.
    #[test]
    fn nic_verification_omits_slots_the_guest_does_not_carry() {
        // Requested {4,5,6,7}; an old Lima ignored `interface:` and named them
        // positionally, so the guest reports lima0..lima3.
        let map = discover_nics_from_ip_json(IP_JSON_3_SLOTS, &[4, 5, 6, 7]).unwrap();
        assert!(
            map.slot_to_iface.is_empty(),
            "no expected interface is present, so nothing may be mapped"
        );
        assert_eq!(map.missing_slots, vec![4, 5, 6, 7]);
        // The interfaces the guest *does* report are still counted — that count
        // is what the pool-resize decision reads.
        assert_eq!(map.discovered_count, 3);
    }

    /// A partially-provisioned VM maps what it can and withholds the rest.
    #[test]
    fn nic_verification_is_per_slot_not_all_or_nothing() {
        let map = discover_nics_from_ip_json(IP_JSON_3_SLOTS, &[1, 2, 5]).unwrap();
        assert_eq!(map.interface_for_slot(1), Some("lima1"));
        assert_eq!(map.interface_for_slot(2), Some("lima2"));
        assert_eq!(map.interface_for_slot(5), None);
        assert_eq!(map.missing_slots, vec![5]);
    }

    /// A missing interface must not fail the whole verification: at startup
    /// that would be the daemon refusing to boot, which would take out the
    /// reduced-pool arms of `decide_pool_resize`. The refusal belongs at the
    /// claim site, per session.
    #[test]
    fn nic_verification_missing_slot_is_not_an_error() {
        assert!(discover_nics_from_ip_json(IP_JSON_NO_LIMA, &[0, 1]).is_ok());
    }

    /// A guest name that merely *parses* to the right number is not the right
    /// name. `lima04` must not satisfy slot 4.
    #[test]
    fn nic_verification_rejects_non_canonical_guest_names() {
        const IP_JSON_PADDED: &str = r#"[
    {"ifindex":2,"ifname":"eth0","flags":[],"link_type":"ether","address":"52:55:0a:00:02:0f","broadcast":"ff:ff:ff:ff:ff:ff"},
    {"ifindex":3,"ifname":"lima04","flags":[],"link_type":"ether","address":"52:55:0a:d1:80:20","broadcast":"ff:ff:ff:ff:ff:ff"}
]"#;
        let map = discover_nics_from_ip_json(IP_JSON_PADDED, &[4]).unwrap();
        assert_eq!(map.interface_for_slot(4), None);
        assert_eq!(map.missing_slots, vec![4]);
    }

    #[test]
    fn nic_discovery_count_mismatch_is_non_fatal() {
        // 3 NICs present but 8 slots requested — the function itself returns
        // successfully; the caller (GatewayLimaManager) logs a warning and the
        // startup resize decision acts on the count.
        let slots: Vec<u16> = (0..8).collect();
        let map = discover_nics_from_ip_json(IP_JSON_3_SLOTS, &slots).unwrap();
        assert_eq!(map.discovered_count, 3);
        assert_eq!(map.slot_to_iface.len(), 3);
    }

    #[test]
    fn nic_discovery_invalid_json() {
        let result = discover_nics_from_ip_json("not json at all", &[0]);
        assert!(result.is_err());
    }

    // -- Template generation (pure, hermetic) ---------------------------------

    /// The contiguous slot set of a single-operator pool of `n` slots — the
    /// shape every host runs today.
    fn slots(n: u16) -> Vec<u16> {
        (0..n).collect()
    }

    /// Extract every `networks:` entry from a rendered template as
    /// `(socket_path, interface_name)`.
    ///
    /// Reads the emitted YAML rather than re-deriving from the generator's
    /// inputs, so an assertion over the result is a statement about what was
    /// actually written to the file Lima consumes. Panics on a `- socket:`
    /// entry with no `interface:` line, which is itself the invariant failing.
    fn template_network_entries(tmpl: &str) -> Vec<(String, String)> {
        let mut lines = tmpl.lines().peekable();
        let mut entries = Vec::new();
        while let Some(line) = lines.next() {
            let Some(socket) = line.strip_prefix("  - socket: ") else {
                continue;
            };
            let interface = lines
                .peek()
                .and_then(|next| next.strip_prefix("    interface: "))
                .unwrap_or_else(|| {
                    panic!("networks entry for {socket} has no `interface:` line following it")
                });
            entries.push((socket.to_string(), interface.to_string()));
        }
        entries
    }

    /// Every emitted entry pins `interface: lima<slot>` on that slot's socket —
    /// asserted over **all** entries, and for an offset range as well as a
    /// contiguous one.
    ///
    /// Lima names guest NICs by array position unless told otherwise, and it
    /// accepts a wrong name without warning: `interface: lima2` on
    /// `slot-7.sock` validates clean and puts the session on slot 7's segment
    /// under slot 2's name. Nothing downstream would notice. The invariant is
    /// checked here by parsing the socket path back to a slot number, so the
    /// two halves of each entry are compared rather than co-derived.
    #[test]
    fn template_pins_interface_to_its_own_slot_for_every_entry() {
        for slot_set in [slots(1), slots(4), slots(8), vec![4, 5, 6, 7], vec![2, 7]] {
            let tmpl = generate_gateway_template(&slot_set);
            let entries = template_network_entries(&tmpl);
            assert_eq!(
                entries.len(),
                slot_set.len(),
                "one networks entry per slot for {slot_set:?}"
            );
            for (socket, interface) in &entries {
                let slot = crate::network::slot_from_vmnet_socket_path(socket)
                    .unwrap_or_else(|| panic!("socket path {socket} does not name a slot"));
                assert_eq!(
                    interface,
                    &format!("lima{slot}"),
                    "entry on {socket} pins interface {interface}, which belongs to a \
                     different slot — the session would land on the wrong L2 segment"
                );
            }
            // And the entries cover exactly the requested slots, in order.
            let emitted: Vec<u16> = entries
                .iter()
                .map(|(socket, _)| crate::network::slot_from_vmnet_socket_path(socket).unwrap())
                .collect();
            assert_eq!(emitted, slot_set);
        }
    }

    /// An offset range renders its own slots throughout — sockets, netplan
    /// stanzas and IPv6-disable lines alike — and never slot 0..n-1.
    #[test]
    fn template_offset_range_renders_its_own_slots() {
        let tmpl = generate_gateway_template(&[4, 5, 6, 7]);

        assert_eq!(
            tmpl.matches("  - socket:").count(),
            4,
            "one socket entry per requested slot"
        );
        for slot in 4u16..8 {
            assert!(
                tmpl.contains(&crate::network::vmnet_slot_socket_path(slot)),
                "template must reference slot {slot}'s socket"
            );
            assert!(
                tmpl.contains(&format!("    interface: lima{slot}\n")),
                "template must pin lima{slot}"
            );
            assert!(
                tmpl.contains(&format!("printf '    lima{slot}:")),
                "netplan must configure lima{slot}"
            );
            assert!(
                tmpl.contains(&format!("net.ipv6.conf.lima{slot}.disable_ipv6=1")),
                "IPv6 must be disabled on lima{slot}"
            );
        }
        for slot in 0u16..4 {
            assert!(
                !tmpl.contains(&crate::network::vmnet_slot_socket_path(slot)),
                "template must not reference slot {slot}, which this VM does not own"
            );
            assert!(
                !tmpl.contains(&format!("    interface: lima{slot}\n")),
                "template must not pin lima{slot}"
            );
            assert!(
                !tmpl.contains(&format!("net.ipv6.conf.lima{slot}.disable_ipv6=1")),
                "template must not configure lima{slot}"
            );
        }
    }

    /// The netplan and IPv6-disable stanzas cover exactly the same interfaces
    /// as the `networks:` entries. A NIC configured in one and missing from the
    /// other is a boot stall or a live IPv6 path on a segment we do not police.
    #[test]
    fn template_provisioning_covers_every_emitted_interface() {
        for slot_set in [slots(3), vec![4, 5, 6, 7], vec![2, 7]] {
            let tmpl = generate_gateway_template(&slot_set);
            let entries = template_network_entries(&tmpl);
            assert_eq!(
                tmpl.matches("printf '    lima").count(),
                entries.len(),
                "netplan stanza count must equal the networks entry count for {slot_set:?}"
            );
            assert_eq!(
                tmpl.matches("sysctl -w net.ipv6.conf.lima").count(),
                entries.len(),
                "IPv6-disable line count must equal the networks entry count for {slot_set:?}"
            );
            for (_, interface) in &entries {
                assert!(
                    tmpl.contains(&format!("printf '    {interface}:")),
                    "{interface} has a networks entry but no netplan stanza"
                );
                assert!(
                    tmpl.contains(&format!("net.ipv6.conf.{interface}.disable_ipv6=1")),
                    "{interface} has a networks entry but no IPv6-disable line"
                );
            }
        }
    }

    #[test]
    fn template_contains_qemu_vmtype() {
        let tmpl = generate_gateway_template(&slots(4));
        assert!(
            tmpl.contains("vmType: \"qemu\""),
            "template must specify vmType qemu"
        );
    }

    /// The VM `cpus:`/`memory:` lines render from the published
    /// `GATEWAY_VM_CPUS` / `GATEWAY_VM_MEMORY_MB` constants (which the
    /// container backend reads to cap a sandbox container's resources). Pins
    /// the historical `cpus: 2` / `memory: "2GiB"` rendering so the VM spec and
    /// the resource cap cannot silently drift apart.
    #[test]
    fn template_cpus_and_memory_match_published_constants() {
        let tmpl = generate_gateway_template(&slots(4));
        assert_eq!(GATEWAY_VM_CPUS, 2);
        assert_eq!(GATEWAY_VM_MEMORY_MB, 2048);
        assert!(
            tmpl.contains("cpus: 2\n"),
            "template must render `cpus: 2` from GATEWAY_VM_CPUS"
        );
        assert!(
            tmpl.contains("memory: \"2GiB\"\n"),
            "template must render `memory: \"2GiB\"` from GATEWAY_VM_MEMORY_MB"
        );
    }

    #[test]
    fn template_contains_correct_socket_count() {
        let tmpl = generate_gateway_template(&slots(4));
        // Each slot produces one `- socket:` entry.
        let socket_count = tmpl.matches("  - socket:").count();
        assert_eq!(
            socket_count, 4,
            "template must have exactly 4 socket entries for a 4-slot set"
        );

        let tmpl8 = generate_gateway_template(&slots(8));
        let socket_count8 = tmpl8.matches("  - socket:").count();
        assert_eq!(
            socket_count8, 8,
            "template must have exactly 8 socket entries for an 8-slot set"
        );
    }

    #[test]
    fn template_slot_socket_paths_match_vmnet_pool() {
        let tmpl = generate_gateway_template(&slots(3));
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
        let tmpl = generate_gateway_template(&slots(4));
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
        let tmpl = generate_gateway_template(&slots(4));
        assert!(
            tmpl.contains("apt-get install -y docker.io"),
            "template must provision docker.io"
        );
        // The in-VM docker socket must be made world-RW so Lima's
        // ControlPersist-master socket-forward (whose channels carry the
        // operator's boot-time groups, missing any docker group added later)
        // can read it. Persisted via a docker.socket drop-in + chmod for the
        // current boot.
        assert!(
            tmpl.contains("SocketMode=0666"),
            "template must set the docker socket mode to 0666 via a drop-in"
        );
        assert!(
            tmpl.contains("/etc/systemd/system/docker.socket.d/10-socketmode.conf"),
            "template must write the docker.socket drop-in for persistent SocketMode"
        );
        assert!(
            tmpl.contains("chmod 666 /var/run/docker.sock"),
            "template must chmod the already-running docker socket for the current boot"
        );
    }

    #[test]
    fn template_has_mtu_clamp() {
        let tmpl = generate_gateway_template(&slots(4));
        assert!(
            tmpl.contains("mtu: 1280"),
            "template must clamp eth0 MTU to 1280"
        );
    }

    #[test]
    fn template_has_no_dhcp_for_lima_nics() {
        let tmpl = generate_gateway_template(&slots(3));
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
        let tmpl = generate_gateway_template(&slots(4));
        assert!(
            tmpl.contains(MIN_LIMA_VERSION),
            "template must specify minimumLimaVersion"
        );
    }

    #[test]
    fn template_has_ubuntu_noble_image() {
        let tmpl = generate_gateway_template(&slots(4));
        assert!(
            tmpl.contains(UBUNTU_NOBLE_ARM64_URL),
            "template must reference the Ubuntu 24.04 aarch64 cloud image"
        );
    }

    #[test]
    fn template_disables_containerd() {
        let tmpl = generate_gateway_template(&slots(4));
        assert!(
            tmpl.contains("system: false"),
            "template must disable containerd (system)"
        );
        assert!(
            tmpl.contains("user: false"),
            "template must disable containerd (user)"
        );
    }

    #[test]
    fn template_has_lite_shared_root_9p_mounts_stanza() {
        let tmpl = generate_gateway_template(&slots(4));
        // The template must include a mounts: block for lite shared: workspaces.
        assert!(
            tmpl.contains("mounts:"),
            "template must contain a mounts: stanza for lite shared: workspaces"
        );
        assert!(
            tmpl.contains("mountType: \"9p\""),
            "template mounts stanza must use 9p mountType"
        );
        assert!(
            tmpl.contains("writable: true"),
            "template mounts stanza must be writable"
        );
        assert!(
            tmpl.contains("securityModel: \"mapped-xattr\""),
            "template mounts stanza must use mapped-xattr security model"
        );
        // The mounts: block must appear between portForwards and containerd.
        let port_pos = tmpl
            .find("portForwards:")
            .expect("portForwards: must exist");
        let mounts_pos = tmpl.find("mounts:").expect("mounts: must exist");
        let containerd_pos = tmpl.find("containerd:").expect("containerd: must exist");
        assert!(
            port_pos < mounts_pos,
            "mounts: must appear after portForwards:"
        );
        assert!(
            mounts_pos < containerd_pos,
            "mounts: must appear before containerd:"
        );
    }

    #[test]
    fn template_has_route_helper_sudoers_provision() {
        let tmpl = generate_gateway_template(&slots(4));
        // The sudoers entry must be scoped to exactly the route-helper binary path.
        assert!(
            tmpl.contains("/usr/local/libexec/sandboxd/sandbox-route-helper"),
            "template must reference the route-helper path in the sudoers provision"
        );
        assert!(
            tmpl.contains("NOPASSWD:"),
            "template must grant NOPASSWD for the route-helper"
        );
        assert!(
            tmpl.contains("/etc/sudoers.d/sandbox-route-helper"),
            "template must write the sudoers fragment to /etc/sudoers.d/sandbox-route-helper"
        );
        assert!(
            tmpl.contains("chmod 0440"),
            "template must set 0440 on the sudoers fragment"
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
        let map = discover_nics_from_ip_json(IP_JSON_3_SLOTS, &[0, 1, 2]).unwrap();
        assert_eq!(map.interface_for_slot(0), Some("lima0"));
        assert_eq!(map.interface_for_slot(1), Some("lima1"));
        assert_eq!(map.interface_for_slot(2), Some("lima2"));
        assert_eq!(map.interface_for_slot(3), None); // out of range
    }

    // -- Slot identity: refusals, not guesses ---------------------------------

    /// A map covering `slots`, as a healthy gateway VM would produce.
    fn verified_map(slots: &[u16]) -> NicMap {
        NicMap {
            slot_to_iface: slots.iter().map(|&s| (s, slot_interface_name(s))).collect(),
            discovered_count: slots.len(),
            missing_slots: Vec::new(),
        }
    }

    fn network_info_with_slot(slot: Option<u16>, bridge_name: &str) -> crate::network::NetworkInfo {
        crate::network::NetworkInfo {
            bridge_name: bridge_name.to_string(),
            subnet: "10.209.128.0/29".to_string(),
            gateway_ip: "10.209.128.3".to_string(),
            vm_ip: "10.209.128.4".to_string(),
            docker_network_name: "sandbox-net-test".to_string(),
            vmnet_slot: slot.map(|index| crate::network::VmnetSlot {
                index,
                daemon_label: crate::network::vmnet_slot_daemon_label(index),
                socket_path: crate::network::vmnet_slot_socket_path(index),
            }),
        }
    }

    /// The create and recovery sites: a NIC-map miss is an error, never a
    /// `lima<slot>` guess.
    #[test]
    fn nic_from_verified_map_refuses_a_miss() {
        let map = verified_map(&[0, 1]);
        assert_eq!(nic_from_verified_map(Some(&map), 1).unwrap(), "lima1");

        // Slot outside the map — the VM has no verified interface for it.
        let err = nic_from_verified_map(Some(&map), 5).unwrap_err();
        assert!(
            err.to_string().contains("no verified gateway NIC"),
            "unexpected error: {err}"
        );
        // Map not populated at all.
        assert!(nic_from_verified_map(None, 0).is_err());
    }

    /// The restart site keeps working from the durable record when the map is
    /// unpopulated — this is the regression that hard-erroring all three sites
    /// alike would have caused. `nic_map()` is `None` until `ensure_ready`
    /// completes, which is not a fault and must not fail a restore.
    #[test]
    fn nic_from_record_survives_an_unpopulated_map() {
        assert_eq!(
            nic_from_record_or_map(None, 3, "lima3").unwrap(),
            "lima3",
            "an unpopulated map must not defeat a session's persisted NIC"
        );
        // Also when the map is populated but does not cover the slot.
        let map = verified_map(&[0, 1]);
        assert_eq!(
            nic_from_record_or_map(Some(&map), 3, "lima3").unwrap(),
            "lima3"
        );
    }

    /// …but with no record either, there is nothing left to trust.
    #[test]
    fn nic_from_record_refuses_when_the_record_is_also_empty() {
        let err = nic_from_record_or_map(None, 3, "").unwrap_err();
        assert!(
            err.to_string().contains("no verified gateway NIC"),
            "unexpected error: {err}"
        );
        // A populated map fills a blank record rather than refusing.
        let map = verified_map(&[3]);
        assert_eq!(nic_from_record_or_map(Some(&map), 3, "").unwrap(), "lima3");
    }

    /// Record and map disagreeing is a refusal, not a re-parent: the running
    /// session's macvlan is already attached to the recorded NIC.
    #[test]
    fn nic_from_record_refuses_a_disagreement() {
        let map = verified_map(&[3]);
        let err = nic_from_record_or_map(Some(&map), 3, "lima7").unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("lima7") && msg.contains("lima3"),
            "unexpected error: {msg}"
        );
        assert!(msg.contains("re-parent"), "unexpected error: {msg}");
    }

    /// The real silent guess: a session with no recorded slot defaulting to
    /// index 0. Under per-operator ranges that is another operator's segment.
    #[test]
    fn slot_for_persisted_session_refuses_a_missing_slot() {
        let ni = network_info_with_slot(Some(4), "lima4");
        assert_eq!(slot_for_persisted_session(&ni).unwrap(), 4);

        let ni = network_info_with_slot(None, "lima0");
        let err = slot_for_persisted_session(&ni).unwrap_err();
        assert!(
            err.to_string().contains("no vmnet slot recorded"),
            "unexpected error: {err}"
        );
    }

    /// A session whose recorded slot is 0 is not the same thing as a session
    /// with no recorded slot — the old default made them indistinguishable.
    #[test]
    fn slot_for_persisted_session_distinguishes_slot_zero_from_absent() {
        assert_eq!(
            slot_for_persisted_session(&network_info_with_slot(Some(0), "lima0")).unwrap(),
            0
        );
        assert!(slot_for_persisted_session(&network_info_with_slot(None, "lima0")).is_err());
    }

    // -- LIMA_HOME path depth (§ UNIX_PATH_MAX) --------------------------------

    /// The gateway instance's `ssh.sock` address fits in `sun_path`.
    ///
    /// Computed from the real path builders rather than eyeballed, so it stays
    /// true when the state root, the nesting or the instance-name scheme
    /// changes — which are the three things that consume the headroom. Lima
    /// resolves symlinks before binding, so there is no way to spell around an
    /// over-long path; the VM simply fails to start, with an error that does
    /// not name path length as the cause.
    #[test]
    fn gateway_instance_socket_path_fits_unix_path_max() {
        use crate::lima::{
            MACOS_UNIX_PATH_MAX, SANDBOXD_STATE_ROOT, instance_socket_path_fits,
            instance_ssh_socket_path, operator_lima_home_inner,
        };

        // Production shape (daemon is its own operator) plus a 5-digit-uid host,
        // which is the widest realistic uid pair.
        for (daemon_uid, op_uid) in [(309u32, 309u32), (309, 501), (12345, 98765)] {
            let lima_home = operator_lima_home_inner(SANDBOXD_STATE_ROOT, daemon_uid, op_uid);
            let sock = instance_ssh_socket_path(&lima_home, GATEWAY_INSTANCE_NAME);
            let len = sock.as_os_str().len();
            assert!(
                instance_socket_path_fits(&lima_home, GATEWAY_INSTANCE_NAME),
                "{} is {len} bytes; sun_path holds {MACOS_UNIX_PATH_MAX} including the \
                 terminator, so the gateway VM would fail to start",
                sock.display()
            );
            // A session VM's instance name is the longer of the two schemes in
            // this tree; hold the bound for it too.
            let session_instance = crate::lima::vm_name(&crate::session::SessionId::generate());
            assert!(
                instance_socket_path_fits(&lima_home, &session_instance),
                "session instance {session_instance} under {} exceeds sun_path",
                lima_home.display()
            );
        }
    }

    // -- Pool resize decision (pure, hermetic) ---------------------------------

    /// C0: NIC count already matches config — no action needed.
    #[test]
    fn decide_pool_resize_no_change_when_counts_match() {
        let d = decide_pool_resize(8, 8, 8, 0);
        assert_eq!(d, PoolResizeDecision::NoChange { effective_n: 8 });
    }

    /// C0: single-slot pool also matches.
    #[test]
    fn decide_pool_resize_no_change_single_slot() {
        let d = decide_pool_resize(1, 1, 1, 0);
        assert_eq!(d, PoolResizeDecision::NoChange { effective_n: 1 });
    }

    /// C1: config changed upward but sessions are running — warn, keep discovered.
    #[test]
    fn decide_pool_resize_warns_and_keeps_discovered_when_sessions_running_grow() {
        // Pool wants to grow 8 → 12 but 3 sessions are live.
        let d = decide_pool_resize(12, 8, 8, 3);
        assert_eq!(
            d,
            PoolResizeDecision::WarnRunningSessions {
                effective_n: 8,
                config_n: 12,
                running: 3,
            }
        );
    }

    /// C1: config changed downward but sessions are running — warn, keep discovered.
    #[test]
    fn decide_pool_resize_warns_and_keeps_discovered_when_sessions_running_shrink() {
        // Pool wants to shrink 12 → 8 but 1 session is live.
        let d = decide_pool_resize(8, 12, 8, 1);
        assert_eq!(
            d,
            PoolResizeDecision::WarnRunningSessions {
                effective_n: 12,
                config_n: 8,
                running: 1,
            }
        );
    }

    /// C1: effective_n is always discovered, not config_n.
    #[test]
    fn decide_pool_resize_effective_n_is_discovered_when_sessions_running() {
        let d = decide_pool_resize(4, 8, 4, 5);
        match d {
            PoolResizeDecision::WarnRunningSessions { effective_n, .. } => {
                assert_eq!(effective_n, 8, "effective_n must be discovered count");
            }
            other => panic!("expected WarnRunningSessions, got {other:?}"),
        }
    }

    /// C2: no sessions running, but the vmnet daemon set hasn't been updated — refuse.
    #[test]
    fn decide_pool_resize_refuses_rebuild_when_daemon_set_mismatch_grow() {
        // Config N=12 but daemon set still at 8; no sessions.
        let d = decide_pool_resize(12, 8, 8, 0);
        assert_eq!(
            d,
            PoolResizeDecision::RefuseNeedsPrivilegedRegen {
                effective_n: 8,
                config_n: 12,
                daemon_set_n: 8,
            }
        );
    }

    /// C2: shrink path — daemon set doesn't match new smaller config_n.
    #[test]
    fn decide_pool_resize_refuses_rebuild_when_daemon_set_mismatch_shrink() {
        // Config N=4 but daemon set still at 8; no sessions.
        let d = decide_pool_resize(4, 8, 8, 0);
        assert_eq!(
            d,
            PoolResizeDecision::RefuseNeedsPrivilegedRegen {
                effective_n: 8,
                config_n: 4,
                daemon_set_n: 8,
            }
        );
    }

    /// C2: effective_n is always discovered in the refuse arm.
    #[test]
    fn decide_pool_resize_effective_n_is_discovered_when_refused() {
        let d = decide_pool_resize(12, 8, 8, 0);
        match d {
            PoolResizeDecision::RefuseNeedsPrivilegedRegen { effective_n, .. } => {
                assert_eq!(effective_n, 8, "effective_n must be discovered count");
            }
            other => panic!("expected RefuseNeedsPrivilegedRegen, got {other:?}"),
        }
    }

    /// C3: safe to rebuild — no sessions, daemon set matches config_n, NIC count differs.
    #[test]
    fn decide_pool_resize_rebuilds_when_safe_grow() {
        // Config N=12, daemon set is 12, but gateway still has 8 NICs; no sessions.
        let d = decide_pool_resize(12, 8, 12, 0);
        assert_eq!(d, PoolResizeDecision::Rebuild { target_n: 12 });
    }

    /// C3: shrink path — daemon set matches smaller config_n.
    #[test]
    fn decide_pool_resize_rebuilds_when_safe_shrink() {
        // Config N=4, daemon set is 4, gateway still has 8 NICs; no sessions.
        let d = decide_pool_resize(4, 8, 4, 0);
        assert_eq!(d, PoolResizeDecision::Rebuild { target_n: 4 });
    }

    /// Running > 0 takes priority over daemon_set mismatch — always WarnRunningSessions.
    #[test]
    fn decide_pool_resize_running_sessions_takes_priority() {
        // Even if the daemon set matches config_n, running sessions block rebuild.
        let d = decide_pool_resize(12, 8, 12, 2);
        assert!(
            matches!(d, PoolResizeDecision::WarnRunningSessions { .. }),
            "running sessions must always produce WarnRunningSessions, not Rebuild"
        );
    }

    // -- Daemon-set observation helpers (tempdir-based, hermetic) ---------------

    #[test]
    fn count_vmnet_plists_counts_matching_files() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path();
        // Create 3 matching plists + 1 non-matching file.
        std::fs::write(path.join("io.sandboxd.vmnet.0.plist"), b"").unwrap();
        std::fs::write(path.join("io.sandboxd.vmnet.1.plist"), b"").unwrap();
        std::fs::write(path.join("io.sandboxd.vmnet.2.plist"), b"").unwrap();
        std::fs::write(path.join("com.example.other.plist"), b"").unwrap();
        assert_eq!(count_vmnet_plists(path), 3);
    }

    #[test]
    fn count_vmnet_plists_returns_zero_for_missing_dir() {
        let dir = std::path::Path::new("/nonexistent/path/that/does/not/exist");
        assert_eq!(count_vmnet_plists(dir), 0);
    }

    #[test]
    fn count_vmnet_plists_empty_dir() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(count_vmnet_plists(dir.path()), 0);
    }

    #[test]
    fn count_reachable_slot_sockets_counts_present_sockets() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path();
        // Create slot-0 and slot-2 sockets; slot-1 is absent.
        std::fs::write(path.join("slot-0.sock"), b"").unwrap();
        std::fs::write(path.join("slot-2.sock"), b"").unwrap();
        // Checking 3 slots (0..3): only 0 and 2 exist → count = 2.
        assert_eq!(count_reachable_slot_sockets(path, 3), 2);
    }

    #[test]
    fn count_reachable_slot_sockets_all_present() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path();
        for slot in 0..4u16 {
            std::fs::write(path.join(format!("slot-{slot}.sock")), b"").unwrap();
        }
        assert_eq!(count_reachable_slot_sockets(path, 4), 4);
    }

    #[test]
    fn count_reachable_slot_sockets_missing_socket_breaks_match() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path();
        // Only slot-0 socket, but we check for 4 slots.
        std::fs::write(path.join("slot-0.sock"), b"").unwrap();
        assert_eq!(count_reachable_slot_sockets(path, 4), 1);
    }

    #[test]
    fn observe_vmnet_daemon_set_matches_when_all_present() {
        let plist_dir = tempfile::tempdir().unwrap();
        let socket_dir = tempfile::tempdir().unwrap();
        for slot in 0..4u16 {
            std::fs::write(
                plist_dir
                    .path()
                    .join(format!("io.sandboxd.vmnet.{slot}.plist")),
                b"",
            )
            .unwrap();
            std::fs::write(socket_dir.path().join(format!("slot-{slot}.sock")), b"").unwrap();
        }
        // Both plist count and socket count are 4 → observed = 4.
        assert_eq!(
            observe_vmnet_daemon_set(plist_dir.path(), socket_dir.path(), 4),
            4
        );
    }

    #[test]
    fn observe_vmnet_daemon_set_mismatches_when_socket_missing() {
        let plist_dir = tempfile::tempdir().unwrap();
        let socket_dir = tempfile::tempdir().unwrap();
        // 4 plists, but only 3 sockets (slot-2 missing).
        for slot in 0..4u16 {
            std::fs::write(
                plist_dir
                    .path()
                    .join(format!("io.sandboxd.vmnet.{slot}.plist")),
                b"",
            )
            .unwrap();
        }
        for slot in [0u16, 1, 3] {
            std::fs::write(socket_dir.path().join(format!("slot-{slot}.sock")), b"").unwrap();
        }
        // min(4, 3) = 3, not 4 → mismatch against expected_n=4.
        assert!(observe_vmnet_daemon_set(plist_dir.path(), socket_dir.path(), 4) < 4);
    }

    #[test]
    fn observe_vmnet_daemon_set_mismatches_when_plist_missing() {
        let plist_dir = tempfile::tempdir().unwrap();
        let socket_dir = tempfile::tempdir().unwrap();
        // 3 plists, 4 sockets.
        for slot in 0..3u16 {
            std::fs::write(
                plist_dir
                    .path()
                    .join(format!("io.sandboxd.vmnet.{slot}.plist")),
                b"",
            )
            .unwrap();
        }
        for slot in 0..4u16 {
            std::fs::write(socket_dir.path().join(format!("slot-{slot}.sock")), b"").unwrap();
        }
        // min(3, 4) = 3, not 4.
        assert!(observe_vmnet_daemon_set(plist_dir.path(), socket_dir.path(), 4) < 4);
    }

    // -- Gateway image tarball staging chain (hermetic) ------------------------

    /// Verify that the daemon-base-dir staging path (where install.sh writes
    /// `$BASE_DIR/gateway-image.tar`) matches the path that
    /// `load_gateway_image_if_needed` computes as its copy-source.
    ///
    /// install.sh writes to `{state_root}/{daemon_uid}/gateway-image.tar`
    /// (BASE_DIR with no sub-directories).  The daemon's copy-source is
    /// `daemon_lima_home.parent().parent() / gateway-image.tar`, which for
    /// daemon_lima_home = `{state_root}/{daemon_uid}/{daemon_uid}/lima` resolves
    /// to the same path.  This test pins that algebra so a path refactor on
    /// either side immediately fails the build.
    #[cfg(target_os = "macos")]
    #[test]
    fn gateway_staged_tarball_path_matches_daemon_copy_source() {
        use std::path::PathBuf;
        // Simulate the layout with uid 60 as both daemon_uid and op_uid (the
        // degenerate gateway case where op_uid == daemon_uid).
        let daemon_lima_home = PathBuf::from("/var/lib/sandboxd/60/60/lima");

        // What load_gateway_image_if_needed computes as its copy-source.
        let copy_source = daemon_lima_home
            .parent()
            .and_then(|p| p.parent())
            .map(|base| base.join(GATEWAY_IMAGE_TARBALL_FILENAME))
            .expect("daemon_lima_home has two parent levels");

        // What install.sh writes: BASE_DIR = /var/lib/sandboxd/<daemon_uid>
        let install_staged = PathBuf::from("/var/lib/sandboxd/60/gateway-image.tar");

        assert_eq!(
            copy_source, install_staged,
            "daemon copy-source must equal install.sh staged path; \
             update both sides together if this path changes"
        );
    }

    /// The gateway image tarball filename constant must match the filename the
    /// daemon's `load_gateway_image_if_needed` logic expects.  Pins the constant
    /// so a rename on either side fails the build immediately.
    #[cfg(target_os = "macos")]
    #[test]
    fn gateway_image_tarball_filename_is_canonical() {
        assert_eq!(
            GATEWAY_IMAGE_TARBALL_FILENAME, "gateway-image.tar",
            "tarball filename must match install.sh staged filename"
        );
    }

    // -- Lite image tarball staging (pure, hermetic) ---------------------------

    /// The lite image tarball filename constant must match the filename the
    /// daemon's LIMA_HOME staging target (make stage-lite-image) produces.
    /// Both sides hard-code "lite-image.tar"; this test pins the constant so
    /// any rename trips the build immediately.
    #[cfg(target_os = "macos")]
    #[test]
    fn lite_image_tarball_filename_is_canonical() {
        assert_eq!(
            LITE_IMAGE_TARBALL_FILENAME, "lite-image.tar",
            "tarball filename must match the make stage-lite-image staging target"
        );
    }

    /// The lite image tag produced by `lite_image_tag_for_version` must have
    /// the `sandboxd-lite:<version>` shape. `load_lite_image_into_gateway`
    /// passes this tag to `docker image inspect` and `docker load`; a drift
    /// here would silently bypass the idempotency check.
    #[cfg(target_os = "macos")]
    #[test]
    fn lite_image_tag_format_matches_load_path() {
        let version = "1.2.3";
        let tag = lite_image_tag_for_version(version);
        assert_eq!(
            tag, "sandboxd-lite:1.2.3",
            "lite image tag must be sandboxd-lite:<version>"
        );
        assert!(
            tag.starts_with("sandboxd-lite:"),
            "tag repository must be sandboxd-lite"
        );
    }

    /// The lite image tarball path is derived as
    /// `{daemon_lima_home}/{LITE_IMAGE_TARBALL_FILENAME}`.  Verify the join
    /// produces the expected path so a refactor to a sub-directory or a
    /// different filename is immediately visible here.
    #[cfg(target_os = "macos")]
    #[test]
    fn lite_image_tarball_path_derivation() {
        use std::path::PathBuf;
        let home = PathBuf::from("/var/lib/sandboxd/60/60/lima");
        let tarball = home.join(LITE_IMAGE_TARBALL_FILENAME);
        assert_eq!(
            tarball,
            PathBuf::from("/var/lib/sandboxd/60/60/lima/lite-image.tar"),
            "tarball path must be daemon_lima_home/lite-image.tar"
        );
    }

    // -- Lite-session staging argv builders (pure, hermetic) ------------------

    /// The per-session staging directory is `{LITE_STAGE_ROOT}/<session_id>`.
    #[cfg(target_os = "macos")]
    #[test]
    fn lite_stage_dir_derivation() {
        assert_eq!(
            lite_stage_dir("0123456789ab"),
            "/tmp/sandbox-lite/0123456789ab"
        );
    }

    /// `lite_stage_mkdir_argv` produces the `limactl shell <vm> -- mkdir -p
    /// <dir>` shape that `run_gateway_shell_argv` expects (prefix
    /// `["shell", "<vm>", "--", ...]`).
    #[cfg(target_os = "macos")]
    #[test]
    fn lite_stage_mkdir_argv_shape() {
        let argv = lite_stage_mkdir_argv("/tmp/sandbox-lite/0123456789ab");
        assert_eq!(
            argv,
            vec![
                "shell".to_string(),
                GATEWAY_INSTANCE_NAME.to_string(),
                "--".to_string(),
                "mkdir".to_string(),
                "-p".to_string(),
                "/tmp/sandbox-lite/0123456789ab".to_string(),
            ],
        );
    }

    /// `lite_stage_rm_argv` produces the `limactl shell <vm> -- rm -rf <dir>`
    /// shape used by the delete path's best-effort cleanup.
    #[cfg(target_os = "macos")]
    #[test]
    fn lite_stage_rm_argv_shape() {
        let argv = lite_stage_rm_argv("/tmp/sandbox-lite/0123456789ab");
        assert_eq!(
            argv,
            vec![
                "shell".to_string(),
                GATEWAY_INSTANCE_NAME.to_string(),
                "--".to_string(),
                "rm".to_string(),
                "-rf".to_string(),
                "/tmp/sandbox-lite/0123456789ab".to_string(),
            ],
        );
    }

    /// The per-file `limactl copy` destination places each file under its
    /// canonical basename inside the staging dir, so the bind builders
    /// (`build_ca_mount_args` reading `<dir>/cert.pem`, `build_ssh_mount_args`
    /// joining `<dir>` with the three SSH filenames) resolve unchanged.
    #[cfg(target_os = "macos")]
    #[test]
    fn lite_stage_copy_destinations() {
        let vm_dir = lite_stage_dir("0123456789ab");
        for basename in ["cert.pem", "authorized_keys", "passwd", "group"] {
            let dst = format!("{GATEWAY_INSTANCE_NAME}:{vm_dir}/{basename}");
            assert_eq!(
                dst,
                format!("sandboxd-gateway:/tmp/sandbox-lite/0123456789ab/{basename}"),
            );
        }
    }
}
