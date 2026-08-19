//! Agent-side re-validation of every field in every `BrokerOp`.
//!
//! These checks are **defense-in-depth**: the daemon is considered an untrusted
//! requester from the agent's perspective. The validation rules mirror those of
//! `sandbox-lima-helper`'s Steps 4–6 exactly — same regex, same path rules,
//! same numeric ranges, same reject-not-clamp policy.
//!
//! Every validation function returns `Err(String)` on failure; the string is
//! a human-readable reason that the agent includes in `BrokerResult::Rejected`.
//! The caller maps `Err` to `Rejected` without clamping or retrying.
//!
//! # Reject, never clamp
//!
//! If a field fails validation, the op is rejected outright. The agent does not
//! silently adjust out-of-range values (no `value.clamp(min, max)`). A clamped
//! value would mask a daemon bug and produce behaviour the daemon did not
//! expect; a hard rejection forces the daemon to be corrected.
//!
//! # Own-uid gate
//!
//! `validate_op_uid` is the first check on every op: if the daemon-supplied
//! `op_uid` does not match the agent's own `getuid()`, the request is rejected
//! immediately. This is the macOS analog of the linux helper's step-1 (daemon
//! identity check) + step-3 (op-uid gate) combined: the agent already *is* the
//! operator, so any mismatch is a routing error or a stale-channel race.
//!
//! # Path confinement
//!
//! Every path the agent reads or writes that falls under LIMA_HOME is validated
//! with `validate_lima_home_path(lima_home, path)`, which asserts:
//! - `path` is absolute.
//! - `path` contains no `..` components.
//! - `path` starts with `lima_home` (prefix confinement).
//!
//! Paths that are outside LIMA_HOME (e.g. the qemu-wrapper path, which must be
//! the daemon-shipped binary under `/usr/local/libexec/sandboxd/`) are
//! validated with `validate_path_arg` (absolute, no `..`, no NUL), without
//! the LIMA_HOME prefix check.

use std::sync::LazyLock;

use regex::Regex;

// ---------------------------------------------------------------------------
// Compiled regexes — module-level LazyLock, same pattern as lima-helper
// ---------------------------------------------------------------------------

/// VM name: `^[a-zA-Z0-9_-]{1,64}$`, first char must not be `-`.
static VM_NAME_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[a-zA-Z0-9_\-]{1,64}$").unwrap());

/// Bridge name: `^[a-zA-Z0-9_-]{1,15}$`.
static BRIDGE_NAME_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[a-zA-Z0-9_\-]{1,15}$").unwrap());

/// MAC address: `^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$`.
static VM_MAC_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$").unwrap());

/// CIDR charset: only `[0-9./]`, 1–18 chars. Structural parse follows.
static CIDR_CHARSET_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[0-9./]{1,18}$").unwrap());

/// Session name: same rules as VM name. Used for `RunRsync.session_name`.
static SESSION_NAME_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[a-zA-Z0-9_\-]{1,64}$").unwrap());

// ---------------------------------------------------------------------------
// PATH_MAX — platform constant
// ---------------------------------------------------------------------------

/// Upper bound for path length. Queried once; falls back to 4096 if the
/// syscall fails (same fallback as lima-helper).
fn path_max() -> usize {
    let v = unsafe { libc::pathconf(c"/".as_ptr(), libc::_PC_PATH_MAX) };
    if v > 0 { v as usize } else { 4096 }
}

// ---------------------------------------------------------------------------
// Own-uid gate
// ---------------------------------------------------------------------------

/// Verify that `op_uid` matches the agent's own uid (from `getuid()`).
///
/// This is the first check on every op. A mismatch means the daemon is routing
/// this request to the wrong agent, or the broker connection is stale after a
/// uid recycle. Either way, the agent must not act on it.
pub fn validate_op_uid(own_uid: u32, op_uid: u32) -> Result<(), String> {
    if op_uid != own_uid {
        return Err(format!(
            "op_uid {op_uid} does not match agent uid {own_uid}; routing error or stale channel"
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// VM name
// ---------------------------------------------------------------------------

/// Validate a VM name: `^[a-zA-Z0-9_-]{1,64}$`, first char not `-`.
///
/// Mirrors `sandbox-lima-helper::imp::validate_vm_name` exactly.
/// The leading-dash check is defense against a name that the regex admits
/// (since `-` is in the character class) but `limactl` would parse as a flag.
pub fn validate_vm_name(name: &str) -> Result<(), String> {
    if name.is_empty() || name.len() > 64 {
        return Err(format!("invalid vm name (empty or > 64 chars): {name:?}"));
    }
    if name.starts_with('-') {
        return Err(format!("invalid vm name (leading dash): {name:?}"));
    }
    if !VM_NAME_RE.is_match(name) {
        return Err(format!(
            "invalid vm name (must match ^[a-zA-Z0-9_-]{{1,64}}$): {name:?}"
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Path validation
// ---------------------------------------------------------------------------

/// Validate a path argument: absolute, no NUL, no `..`, length ≤ PATH_MAX.
///
/// Mirrors `sandbox-lima-helper::imp::validate_path_arg`. Does NOT enforce
/// LIMA_HOME confinement — use `validate_lima_home_path` for that.
pub fn validate_path_arg(field: &str, path: &str) -> Result<(), String> {
    if path.contains('\0') {
        return Err(format!("{field}: path contains NUL byte"));
    }
    if path.len() > path_max() {
        return Err(format!("{field}: path exceeds PATH_MAX"));
    }
    if !path.starts_with('/') {
        return Err(format!("{field}: path must be absolute (starts with '/')"));
    }
    for component in path.split('/') {
        if component == ".." {
            return Err(format!("{field}: path must not contain '..' components"));
        }
    }
    Ok(())
}

/// Validate that `path` is (a) a valid path (via `validate_path_arg`) and
/// (b) confined under `lima_home`.
///
/// LIMA_HOME confinement is the macOS analog of the linux helper's post-setresuid
/// uid-enforced write restriction. On macOS the agent already runs as the
/// operator, so the OS enforces ownership correctly — but we validate the prefix
/// anyway so a daemon routing bug (wrong LIMA_HOME in the payload) fails loudly
/// rather than silently operating in the wrong operator's tree.
///
/// `lima_home` must itself be an absolute, no-`..` path (the agent constructs
/// it from its own uid, not from the daemon payload).
pub fn validate_lima_home_path(lima_home: &str, path: &str) -> Result<(), String> {
    validate_path_arg("path", path)?;
    // lima_home may or may not end with '/'; normalise for prefix comparison.
    let base = if lima_home.ends_with('/') {
        lima_home.to_string()
    } else {
        format!("{lima_home}/")
    };
    if !path.starts_with(base.as_str()) && path != lima_home {
        return Err(format!(
            "path {path:?} is outside the agent's LIMA_HOME {lima_home:?}"
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Numeric range check
// ---------------------------------------------------------------------------

/// Validate that `value` is in `[min, max]` (inclusive). Reject, never clamp.
///
/// Mirrors `sandbox-lima-helper::imp::validate_range`.
pub fn validate_range(field: &str, value: u32, min: u32, max: u32) -> Result<(), String> {
    if value < min || value > max {
        return Err(format!(
            "{field}: value {value} is out of range [{min}, {max}]"
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// CIDR owner
// ---------------------------------------------------------------------------

/// Validate a pool CIDR string (charset + structural parse).
///
/// Mirrors `sandbox-lima-helper::imp::validate_cidr_owner`.
pub fn validate_cidr_owner(field: &str, value: &str) -> Result<(), String> {
    if !CIDR_CHARSET_RE.is_match(value) {
        return Err(format!(
            "{field}: {value:?} must be a CIDR string (digits, dots, slashes only, ≤18 chars)"
        ));
    }
    let Some((addr_part, prefix_part)) = value.split_once('/') else {
        return Err(format!(
            "{field}: {value:?} missing '/' (expected a.b.c.d/n)"
        ));
    };
    let octets: Vec<&str> = addr_part.split('.').collect();
    if octets.len() != 4
        || octets
            .iter()
            .any(|o| o.parse::<u8>().is_err() || o.is_empty())
    {
        return Err(format!(
            "{field}: address part {addr_part:?} is not a valid IPv4 dotted-quad"
        ));
    }
    match prefix_part.parse::<u8>() {
        Ok(p) if p <= 32 => {}
        _ => {
            return Err(format!(
                "{field}: prefix {prefix_part:?} is not an integer 0-32"
            ));
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Bridge name + MAC
// ---------------------------------------------------------------------------

/// Validate a bridge name: `^[a-zA-Z0-9_-]{1,15}$`.
///
/// Mirrors `sandbox-lima-helper::imp::validate_bridge_name`.
pub fn validate_bridge_name(name: &str) -> Result<(), String> {
    if !BRIDGE_NAME_RE.is_match(name) {
        return Err(format!(
            "invalid bridge name {name:?}: must match ^[a-zA-Z0-9_-]{{1,15}}$"
        ));
    }
    Ok(())
}

/// Validate a MAC address: regex + unicast-bit check (LSB of first octet must
/// be 0).
///
/// Mirrors `sandbox-lima-helper::imp::validate_vm_mac`.
pub fn validate_vm_mac(mac: &str) -> Result<(), String> {
    if !VM_MAC_RE.is_match(mac) {
        return Err(format!(
            "invalid MAC address {mac:?}: must be xx:xx:xx:xx:xx:xx (hex octets)"
        ));
    }
    let first_octet = u8::from_str_radix(&mac[..2], 16).expect("regex guarantees valid hex");
    if first_octet & 0x01 != 0 {
        return Err(format!(
            "invalid MAC address {mac:?}: multicast bit (LSB of first octet) is set"
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Session name (RunRsync)
// ---------------------------------------------------------------------------

/// Validate a session name token (`sandbox-<id>` form).
///
/// Rules mirror `validate_vm_name`; used for `RunRsync.session_name`.
pub fn validate_session_name(name: &str) -> Result<(), String> {
    if name.is_empty() || name.len() > 64 {
        return Err(format!(
            "invalid session name (empty or > 64 chars): {name:?}"
        ));
    }
    if name.starts_with('-') {
        return Err(format!("invalid session name (leading dash): {name:?}"));
    }
    if !SESSION_NAME_RE.is_match(name) {
        return Err(format!(
            "invalid session name (must match ^[a-zA-Z0-9_-]{{1,64}}$): {name:?}"
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Hardened flag
// ---------------------------------------------------------------------------

/// Validate the `hardened` boolean. This is a typed `bool` in `BrokerOp::Start`
/// (unlike the helper's string "0"/"1"), so validation is trivially satisfied
/// by the Rust type system. The function exists as a doc anchor and for
/// potential future extension.
pub fn validate_hardened(_hardened: bool) -> Result<(), String> {
    // A `bool` in Rust is already constrained to `true` or `false`. No
    // further validation is needed — the type system enforces the invariant
    // that would otherwise require a string comparison.
    Ok(())
}

// ---------------------------------------------------------------------------
// Backend kind (RunRsync)
// ---------------------------------------------------------------------------

/// Validate the `backend` field: must be exactly "lima" or "container".
///
/// Mirrors `sandbox-lima-helper::imp::validate_run_rsync_args`.
pub fn validate_backend(backend: &str) -> Result<(), String> {
    if backend != "lima" && backend != "container" {
        return Err(format!(
            "invalid backend {backend:?}: must be 'lima' or 'container'"
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Lima YAML shape validation
// ---------------------------------------------------------------------------

// The validator is split by VM *class*, and the split is the security-relevant
// part of this module. Read this before changing either half.
//
// Two classes exist, and the class is selected by **which `BrokerOp` variant
// the daemon invoked** — `Create` for the session class, `CreateGateway` for
// the gateway class. Nothing else selects it. Not a flag on the request, not
// the VM's name, not anything else the daemon writes on the wire. That matters
// because the daemon is an untrusted requester here (see the module doc above):
// any selector the daemon can set is a selector the daemon can set *wrongly*,
// and the thing it would be choosing is whether a VM may attach more than one
// NIC. The closed op enum is what already bounds a compromised daemon, so the
// class rides on it and inherits the same bound.
//
// What each class still guarantees, in this module's own terms:
//
// * Both classes — the YAML parses, its top level is a mapping, `vmType` is
//   present and exactly `"qemu"` (an absent one would let Lima default to VZ on
//   macOS, which cannot attach socket_vmnet at all), and there is no top-level
//   singular `network:` key. Every NIC entry's `socket:` is absolute, free of
//   `..`, and inside `/var/run/sandbox/vmnet/`. No entry may carry `mode:`
//   (a Lima-managed named network).
//
// * Session class (`validate_lima_yaml_shape`) — **exactly one** NIC entry, and
//   that entry's only key is `socket:`. This is unchanged, and it is applied
//   unconditionally on the `Create` path: nothing about the name, the YAML, or
//   any other field can obtain a different rule for a session VM.
//   `require_socket_vmnet == false` (the base-image build VM, which has no
//   `networks:` key by design) waives only the *presence* of `networks:`; if
//   the key is there it is held to the same single-entry rule.
//
// * Gateway class (`validate_gateway_lima_yaml_shape`) — one or more NIC
//   entries, because a gateway VM's job is to sit on every pool slot's L2
//   segment at once. This is a different rule, not a weaker one: each entry
//   must carry exactly the two keys `socket:` and `interface:`; each socket
//   must be a canonical `slot-<n>.sock` path (round-trip exact, so `slot-04`
//   and a foreign directory are both out); the interface name must be the
//   `lima<n>` that belongs to *that* slot; and no two entries may name the same
//   slot. Lima itself will not check any of this — it accepts
//   `interface: lima2` on `slot-7.sock` without a murmur, and the result is a
//   VM whose NIC names point at the wrong segments. So where the session rule
//   bounds the *number* of segments a VM reaches, the gateway rule bounds
//   *which* segment each of its NICs is on, and both are checks the daemon
//   cannot skip.
//
// The two rules are also mutually exclusive by entry shape: a session entry has
// exactly `{socket}` and a gateway entry exactly `{socket, interface}`. A
// gateway template presented on the `Create` op is rejected (two keys), and a
// session template presented on `CreateGateway` is rejected (no `interface`).

/// Validate the parts of a daemon-rendered `lima.yaml` that every VM class
/// shares, returning the parsed top-level mapping for the class-specific
/// checks to work from.
///
/// Covers: non-empty, parses as YAML, top level is a mapping, `vmType` present
/// and `"qemu"`, no top-level singular `network:` key. See the class-split
/// comment above for why these are the shared set.
fn validate_lima_yaml_common(lima_yaml: &str) -> Result<serde_yaml::Mapping, String> {
    use serde_yaml::Value;

    if lima_yaml.trim().is_empty() {
        return Err("lima.yaml is empty".to_string());
    }

    // Parse the YAML. serde_yaml rejects malformed YAML; multi-document
    // (`---`-separated) docs are handled by `from_str` which returns the
    // first document — we then check for the absence of structural keys
    // the second doc could smuggle in. A completely valid single-document
    // YAML is what we expect from the daemon template.
    let doc: Value = serde_yaml::from_str(lima_yaml)
        .map_err(|e| format!("lima.yaml failed to parse as YAML: {e}"))?;

    // The top-level document must be a mapping.
    let top = match doc {
        Value::Mapping(m) => m,
        _ => return Err("lima.yaml top-level must be a YAML mapping".to_string()),
    };

    // Check: `vmType` must be present and equal to `"qemu"`.
    //
    // Lima on macOS defaults to VZ (Virtualization.framework) when `vmType` is
    // unset. VZ cannot attach socket_vmnet NICs — it would boot the VM under
    // vzNAT, bypassing the gateway and voiding egress control entirely. An
    // absent `vmType` is therefore as dangerous as `vmType: vz` on macOS.
    //
    // The daemon template must always emit `vmType: "qemu"` explicitly so this
    // check can verify the correct backend is selected. Any other value
    // (`vz`, `libkrun`, etc.) or an absent key is rejected.
    //
    // Parsing normalises all syntactic forms — `vmType: qemu`, `{vmType: qemu}`,
    // `'vmType': qemu`, `"vmType": qemu` — into the same key/value in the mapping,
    // so this check is robust to YAML serialisation style.
    let vmtype_val = top
        .get("vmType")
        .ok_or_else(|| {
            "lima.yaml must contain vmType: \"qemu\"; absent vmType is rejected because \
             Lima defaults to VZ on macOS, which cannot attach socket_vmnet and \
             would void egress control"
                .to_string()
        })?
        .as_str()
        .ok_or_else(|| "lima.yaml vmType value must be a string".to_string())?;
    if vmtype_val != "qemu" {
        return Err(format!(
            "lima.yaml vmType must be \"qemu\", got {vmtype_val:?}; \
             vz (and any other non-qemu backend) cannot attach socket_vmnet \
             and would void egress control"
        ));
    }

    // Check: no `network` key (singular) at the top level. Some Lima versions
    // accept this form as an alias for `networks`; reject it unconditionally so
    // the check below on `networks` is the only code path. This applies to
    // every VM class.
    if top.contains_key("network") {
        return Err(
            "lima.yaml must not contain a 'network' key; use 'networks' with a socket: entry"
                .to_string(),
        );
    }

    Ok(top)
}

/// Validate the shape of a daemon-rendered `lima.yaml` for a **session-class**
/// VM (or the transient base-image build VM).
///
/// This is the rule for every VM reached through `BrokerOp::Create`, and it is
/// applied to all of them unconditionally: a session VM gets the single-NIC
/// rule no matter what it is called. A gateway-shaped name presented here is
/// still a session create and is still held to this rule — the name buys
/// nothing. The gateway class has its own entry point,
/// [`validate_gateway_lima_yaml_shape`], reachable only from
/// `BrokerOp::CreateGateway`.
///
/// The agent writes the YAML verbatim after this check; it does not parse or
/// reassemble the YAML. Shape validation asserts the YAML is safe to write:
///
/// - The `vmType` key must be present at the top level and equal to `"qemu"`.
///   Lima on macOS **defaults to VZ (Virtualization.framework)** when `vmType`
///   is unset. VZ cannot attach socket_vmnet NICs, so a VM booting under VZ
///   would use vzNAT and bypass the gateway entirely — voiding egress control.
///   An absent `vmType` is therefore rejected, as is any value other than
///   `"qemu"`. The daemon template must always emit `vmType: "qemu"` explicitly.
/// - The `networks` sequence (if present) contains exactly one entry, that
///   entry is a mapping with a `socket` key and no `mode` key. Lima 2.x uses
///   `networks: [{socket: <path>}]` for unmanaged socket_vmnet attachments;
///   `mode:` indicates a managed named-network form that is not permitted.
/// - No additional top-level `network` key (alternate singular form Lima may
///   accept in some versions).
///
/// This function validates SHAPE only — structural properties of the YAML
/// (vmType value, socket NIC count, mode absence). The rendered field
/// values (socket paths, CIDR, wrapper path) are validated separately by
/// the per-field validators called before this function.
///
/// Structural parsing via `serde_yaml` is used rather than line-by-line string
/// matching. String matching cannot reliably detect flow-style YAML
/// (`{socket: ...}`), quoted keys (`'socket':` / `"socket":`), YAML anchors
/// and aliases (`&nic {socket: ...}` / `*nic`), or multi-document YAML
/// (`---`). These serialisation forms are all producible by a YAML serializer
/// in a buggy daemon, and this is the egress-control boundary: a bypass here
/// defeats sandboxd's core unbypassable-egress promise. Parsing to
/// `serde_yaml::Value` normalises all serialisation styles so the shape
/// assertions are robust by construction.
///
/// Returns `Err(String)` with a human-readable reason on any shape violation.
///
/// `require_socket_vmnet` controls whether a `networks:` key with exactly one
/// socket_vmnet entry is required. Pass `true` for real session VMs (which MUST
/// attach a socket_vmnet NIC for egress enforcement); pass `false` for the
/// transient base-image build VM, which uses Lima's slirp NIC only and has no
/// `networks:` key. All other shape checks (vmType, no singular `network` key,
/// NIC structure) apply regardless of this flag.
pub fn validate_lima_yaml_shape(
    lima_yaml: &str,
    expected_vm: &str,
    require_socket_vmnet: bool,
) -> Result<(), String> {
    let top = validate_lima_yaml_common(lima_yaml)?;

    // Check: the `networks` sequence contains exactly one entry with a valid
    // socket_vmnet path.
    //
    // When `require_socket_vmnet` is true (real session VMs), a `networks:` key
    // with exactly one socket_vmnet entry is mandatory — Lima on macOS uses this
    // NIC as the VM's data-plane attachment to the gateway; its absence means
    // the VM has no managed NIC and egress enforcement is void.
    //
    // When `require_socket_vmnet` is false (base-image build VM), the `networks:`
    // key is absent by design: the build VM uses Lima's slirp NIC only during
    // cloud-init provisioning and is never promoted to a session. In this case
    // we skip the presence requirement but still validate the entry if it exists.
    //
    // Valid Lima 2.x form (block style):
    //   networks:
    //     - socket: /var/run/sandbox/vmnet/slot-0.sock
    //
    // Valid Lima 2.x form (flow style, fully normalised by the parser):
    //   networks: [{socket: /var/run/sandbox/vmnet/slot-0.sock}]
    //
    // All of these produce the same `Value::Sequence([Mapping({socket: ...})])`.
    let networks_val_opt = top.get("networks");

    if require_socket_vmnet {
        // Session VM: `networks:` is required.
        let networks_val = networks_val_opt.ok_or_else(|| {
            "lima.yaml must contain a 'networks' key with exactly one socket_vmnet entry"
                .to_string()
        })?;
        validate_networks_entry(networks_val)?;
    } else if let Some(networks_val) = networks_val_opt {
        // Base-image build VM: `networks:` is absent by design.
        // If it is unexpectedly present, validate it anyway — an invalid entry
        // is still rejected so a malformed template cannot slip past unnoticed.
        validate_networks_entry(networks_val)?;
    }
    // else: base-image build VM with no `networks:` key — correct, no check needed.

    // Belt-and-suspenders: the expected VM name should appear somewhere in the
    // raw YAML text. This is a coarse sanity check — the `vm` field in the
    // BrokerOp is the authoritative name used for limactl's `--name` flag, but
    // a daemon that sends a YAML for the wrong VM is at minimum mis-routing.
    if !expected_vm.is_empty() && !lima_yaml.contains(expected_vm) {
        return Err(format!(
            "lima.yaml does not appear to reference the expected VM name {expected_vm:?}"
        ));
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Gateway-class Lima YAML shape validation
// ---------------------------------------------------------------------------

/// Directory holding the socket_vmnet slot sockets. Mirrors
/// `sandbox_core::network::VMNET_SOCKET_DIR`, restated here because this crate
/// deliberately does not depend on `sandbox-core` — the agent's validators must
/// not be reachable from, or weakenable by, the daemon's own crate graph.
const VMNET_SLOT_SOCKET_DIR: &str = "/var/run/sandbox/vmnet";

/// The socket path belonging to pool slot `slot`.
///
/// The agent-side mirror of `sandbox_core::network::vmnet_slot_socket_path`.
fn vmnet_slot_socket_path(slot: u16) -> String {
    format!("{VMNET_SLOT_SOCKET_DIR}/slot-{slot}.sock")
}

/// The in-VM interface name pinned to pool slot `slot`.
///
/// The agent-side mirror of `sandbox_core::gateway_lima::slot_interface_name`.
fn slot_interface_name(slot: u16) -> String {
    format!("lima{slot}")
}

/// Recover the pool slot from a vmnet slot socket path — the exact inverse of
/// [`vmnet_slot_socket_path`].
///
/// The socket path is the authority on which L2 segment a NIC lands on, so an
/// entry claiming a `lima<n>` interface name can be *checked* against the
/// socket it sits on rather than believed. Returns `None` unless the path is
/// byte-for-byte what [`vmnet_slot_socket_path`] would emit for the parsed
/// index, which rejects a foreign directory and non-canonical spellings
/// (`slot-04.sock`, `slot-+4.sock`) alike — an inexact parse here would let two
/// different spellings of "the same" path disagree about which slot they mean,
/// and the disagreement is exactly what the interface check is trying to catch.
///
/// The agent-side mirror of `sandbox_core::network::slot_from_vmnet_socket_path`.
fn slot_from_vmnet_socket_path(path: &str) -> Option<u16> {
    let file = std::path::Path::new(path).file_name()?.to_str()?;
    let digits = file.strip_prefix("slot-")?.strip_suffix(".sock")?;
    let slot: u16 = digits.parse().ok()?;
    (vmnet_slot_socket_path(slot) == path).then_some(slot)
}

/// Validate the shape of a daemon-rendered `lima.yaml` for a **gateway-class**
/// VM.
///
/// Reachable only from `BrokerOp::CreateGateway`. See the class-split comment
/// at the top of this section of the module for why the class rides on the op
/// variant and on nothing else.
///
/// A gateway VM's purpose is to terminate every pool slot's L2 segment, so
/// unlike a session VM it carries one socket_vmnet NIC per slot. That is the
/// only thing this rule permits that the session rule does not; everything else
/// it demands is *additional*:
///
/// - `networks:` must be present and must be a non-empty sequence. A gateway VM
///   with no slot NICs has nothing to gateway.
/// - Each entry's keys are exactly `socket:` and `interface:` — no more (an
///   extra key could turn on Lima networking behaviour nobody reviewed), no
///   fewer. In particular `mode:` is rejected, as it is for a session VM.
/// - Each `socket:` passes [`validate_socket_path`] *and* parses back to a pool
///   slot via [`slot_from_vmnet_socket_path`]. The session rule stops at the
///   directory prefix; here the whole filename must be canonical, because the
///   slot number it encodes is load-bearing for the next check.
/// - Each `interface:` is exactly the `lima<n>` belonging to that entry's own
///   slot. Lima will not check this: it accepts `interface: lima2` on
///   `slot-7.sock` silently, and since the NIC name is what selects the macvlan
///   parent inside the VM, the result is sessions parented on the wrong
///   segment — a cross-session isolation failure that looks like nothing at
///   all from the outside. The daemon's template generator makes the same
///   check when it renders; this one makes it from outside the daemon's trust
///   boundary, where a compromised daemon cannot skip it.
/// - No two entries name the same slot. Two NICs on one segment is never a
///   thing a correct render produces, and it would give the VM two interface
///   names for one segment.
///
/// There is deliberately **no expected-VM-name argument**. `CreateGateway`
/// carries no VM name on the wire — the agent derives the instance name from
/// its own uid — so there is no name here to cross-check the YAML against, and
/// the session path's belt-and-suspenders containment check has nothing to
/// operate on. That check exists to catch a daemon mis-routing a YAML to the
/// wrong *named* instance; with the name gone from the request, so is the
/// mis-routing it guards against. (Lima templates carry no instance name in
/// their body in any case.)
pub fn validate_gateway_lima_yaml_shape(lima_yaml: &str) -> Result<(), String> {
    use serde_yaml::Value;

    let top = validate_lima_yaml_common(lima_yaml)?;

    let networks_val = top.get("networks").ok_or_else(|| {
        "lima.yaml must contain a 'networks' key with one socket_vmnet entry per pool slot"
            .to_string()
    })?;

    let networks_seq = match networks_val {
        Value::Sequence(s) => s,
        _ => {
            return Err(
                "lima.yaml 'networks' must be a sequence (list of NIC entries)".to_string(),
            );
        }
    };

    if networks_seq.is_empty() {
        return Err(
            "lima.yaml 'networks' must contain at least one socket_vmnet entry; a gateway \
             instance with no slot NICs terminates no session segment"
                .to_string(),
        );
    }

    let mut seen_slots: Vec<u16> = Vec::with_capacity(networks_seq.len());

    for (index, entry) in networks_seq.iter().enumerate() {
        let nic = match entry {
            Value::Mapping(m) => m,
            _ => {
                return Err(format!(
                    "lima.yaml 'networks[{index}]' must be a mapping \
                     (expected {{socket: ..., interface: ...}})"
                ));
            }
        };

        // `mode:` names a Lima-managed network. Called out separately from the
        // key-set check below so the error says why, not just "unexpected key".
        if nic.contains_key("mode") {
            return Err(format!(
                "lima.yaml 'networks[{index}]' must not have a 'mode' key; \
                 managed named-network entries are not permitted — only socket: entries"
            ));
        }

        if !nic.contains_key("socket") {
            return Err(format!(
                "lima.yaml 'networks[{index}]' must have a 'socket' key (socket_vmnet path)"
            ));
        }
        if !nic.contains_key("interface") {
            return Err(format!(
                "lima.yaml 'networks[{index}]' must have an 'interface' key pinning the \
                 in-VM NIC name to its slot; without it Lima names NICs by array position \
                 and a non-contiguous slot set is parented on the wrong segments"
            ));
        }
        if nic.len() != 2 {
            return Err(format!(
                "lima.yaml 'networks[{index}]' must have exactly two keys \
                 ('socket', 'interface'), found {} keys: {:?}",
                nic.len(),
                nic.keys().filter_map(|k| k.as_str()).collect::<Vec<_>>()
            ));
        }

        let socket_val = nic.get("socket").and_then(|v| v.as_str()).ok_or_else(|| {
            format!("lima.yaml 'networks[{index}].socket' must be a string value")
        })?;
        validate_socket_path(socket_val)?;

        let slot = slot_from_vmnet_socket_path(socket_val).ok_or_else(|| {
            format!(
                "lima.yaml 'networks[{index}].socket' {socket_val:?} is not a canonical \
                 pool slot socket path (expected {VMNET_SLOT_SOCKET_DIR}/slot-<n>.sock \
                 with no leading zeros or sign)"
            )
        })?;

        let interface_val = nic
            .get("interface")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                format!("lima.yaml 'networks[{index}].interface' must be a string value")
            })?;
        let expected_interface = slot_interface_name(slot);
        if interface_val != expected_interface {
            return Err(format!(
                "lima.yaml 'networks[{index}]' pins interface {interface_val:?} onto socket \
                 {socket_val:?}, which belongs to slot {slot} \
                 (expected interface {expected_interface:?}); the in-VM NIC name selects the \
                 macvlan parent, so a mismatch parents sessions on another slot's segment"
            ));
        }

        if seen_slots.contains(&slot) {
            return Err(format!(
                "lima.yaml 'networks[{index}]' repeats slot {slot}; each pool slot may be \
                 attached at most once"
            ));
        }
        seen_slots.push(slot);
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Networks-entry validation (used inside validate_lima_yaml_shape)
// ---------------------------------------------------------------------------

/// Validate the `networks:` value from a parsed lima.yaml.
///
/// Enforces: exactly one entry; that entry is a mapping; it has a `socket` key
/// and no `mode` key; exactly one key total; and the socket path passes
/// `validate_socket_path`.
fn validate_networks_entry(networks_val: &serde_yaml::Value) -> Result<(), String> {
    use serde_yaml::Value;

    let networks_seq = match networks_val {
        Value::Sequence(s) => s,
        _ => {
            return Err(
                "lima.yaml 'networks' must be a sequence (list of NIC entries)".to_string(),
            );
        }
    };

    // Exactly one NIC entry is required — the socket_vmnet NIC. Lima's
    // mandatory management NIC (user/slirp) is not expressed in the YAML;
    // Lima adds it automatically. No additional YAML-level NICs are permitted.
    if networks_seq.len() != 1 {
        return Err(format!(
            "lima.yaml 'networks' must contain exactly one socket_vmnet entry, found {}",
            networks_seq.len()
        ));
    }

    let nic = match &networks_seq[0] {
        Value::Mapping(m) => m,
        _ => {
            return Err(
                "lima.yaml 'networks' entry must be a mapping (expected {{socket: ...}})"
                    .to_string(),
            );
        }
    };

    // The NIC entry must have a `socket` key.
    if !nic.contains_key("socket") {
        return Err(
            "lima.yaml 'networks' entry must have a 'socket' key (socket_vmnet path)".to_string(),
        );
    }

    // The NIC entry must NOT have a `mode` key. `mode: shared` / `mode: host`
    // indicate Lima-managed named networks — not permitted; the socket: attach
    // is unmanaged and does not use `mode`.
    if nic.contains_key("mode") {
        return Err("lima.yaml 'networks' entry must not have a 'mode' key; \
             managed named-network entries are not permitted — only bare socket: entries"
            .to_string());
    }

    // The NIC entry must not have any key other than `socket`. Any additional
    // key could introduce unexpected Lima networking behaviour.
    if nic.len() != 1 {
        return Err(format!(
            "lima.yaml 'networks' entry must have exactly one key ('socket'), \
             found {} keys: {:?}",
            nic.len(),
            nic.keys().filter_map(|k| k.as_str()).collect::<Vec<_>>()
        ));
    }

    // Validate the socket path value itself. A buggy daemon could render an
    // arbitrary socket path, connecting the VM to a non-sandboxd socket and
    // bypassing egress enforcement. Requirements:
    //   - absolute (no relative paths)
    //   - no `..` traversal components
    //   - confined to the `/var/run/sandbox/vmnet/` namespace
    let socket_val = nic
        .get("socket")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "lima.yaml 'networks[0].socket' must be a string value".to_string())?;
    validate_socket_path(socket_val)?;

    Ok(())
}

// ---------------------------------------------------------------------------
// Socket-path validation (used inside validate_lima_yaml_shape)
// ---------------------------------------------------------------------------

/// Validate a `socket:` path extracted from a rendered `lima.yaml`.
///
/// Enforces three properties that together prevent a buggy daemon from routing
/// a VM to an arbitrary (non-sandboxd) socket_vmnet instance and bypassing
/// egress enforcement:
///
/// 1. Absolute path — no relative segments.
/// 2. No `..` traversal — `path::Path::components` must be free of
///    `Component::ParentDir`.
/// 3. Confined to `/var/run/sandbox/vmnet/` — the slot socket namespace. Only
///    sockets within this prefix are daemon-managed slot sockets; anything
///    outside it is unrecognized or attacker-controlled.
///
/// Rejection on any violation: the agent never clamps or rewrites the value,
/// it rejects outright.
pub fn validate_socket_path(path: &str) -> Result<(), String> {
    use std::path::{Component, Path};

    if path.is_empty() {
        return Err("socket path is empty".to_string());
    }

    let p = Path::new(path);

    if !p.is_absolute() {
        return Err(format!(
            "socket path {path:?} is not absolute; only absolute paths are permitted"
        ));
    }

    for component in p.components() {
        if component == Component::ParentDir {
            return Err(format!(
                "socket path {path:?} contains '..' traversal; traversal is not permitted"
            ));
        }
    }

    // Require the path to be inside the vmnet slot socket namespace.
    const VMNET_PREFIX: &str = "/var/run/sandbox/vmnet/";
    if !path.starts_with(VMNET_PREFIX) {
        return Err(format!(
            "socket path {path:?} is not within the expected prefix {VMNET_PREFIX:?}; \
             only sandboxd-managed slot sockets are permitted"
        ));
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Qemu-wrapper assertion
// ---------------------------------------------------------------------------

/// Assert that the qemu-wrapper path is:
/// 1. A valid absolute, no-`..` path (via `validate_path_arg`).
/// 2. Present on disk and executable by the agent (via `access(2)`).
///
/// The agent does not write the wrapper — that is the daemon's responsibility
/// at install time. This check ensures the wrapper the daemon nominated is
/// actually present and executable before the agent runs `limactl start/create`
/// with it.
pub fn validate_qemu_wrapper(qemu_wrapper: &str) -> Result<(), String> {
    validate_path_arg("qemu_wrapper", qemu_wrapper)?;
    // Check executability via access(2).
    let path_c =
        std::ffi::CString::new(qemu_wrapper).map_err(|_| "qemu_wrapper path contains NUL")?;
    // SAFETY: path_c is a valid NUL-terminated C string.
    let rc = unsafe { libc::access(path_c.as_ptr(), libc::X_OK) };
    if rc != 0 {
        let errno = unsafe { *libc::__error() };
        return Err(format!(
            "qemu_wrapper {qemu_wrapper:?} is not executable (errno {errno})"
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Docker op field validation
// ---------------------------------------------------------------------------

/// Docker object name (container, network, volume): Docker's own rule —
/// starts alphanumeric, then alphanumerics plus `_`, `.`, `-`.
static DOCKER_NAME_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[a-zA-Z0-9][a-zA-Z0-9_.\-]{0,127}$").unwrap());

/// Image reference: registry/name:tag or name:tag or a bare name.
static IMAGE_REF_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[a-zA-Z0-9][a-zA-Z0-9_.\-/:@]{0,255}$").unwrap());

/// Validate a Docker object name.
///
/// The charset is Docker's, not ours — a name outside it would be rejected
/// by the daemon anyway, and accepting it here only moves the failure later.
/// The leading-alphanumeric rule additionally rules out a name that would be
/// read as a flag.
pub fn validate_docker_name(field: &str, name: &str) -> Result<(), String> {
    if !DOCKER_NAME_RE.is_match(name) {
        return Err(format!(
            "{field}: {name:?} is not a valid docker object name \
             (must match ^[a-zA-Z0-9][a-zA-Z0-9_.-]{{0,127}}$)"
        ));
    }
    Ok(())
}

/// Validate a `--filter name=<prefix>` value.
///
/// Same charset as a full name; a prefix is a name that happens to be short,
/// and the leading-alphanumeric rule is what stops `--filter name=-foo` from
/// turning into a flag.
pub fn validate_docker_name_prefix(field: &str, prefix: &str) -> Result<(), String> {
    validate_docker_name(field, prefix)
}

/// Validate an image reference (`name`, `name:tag`, `registry/name:tag`).
pub fn validate_image_ref(field: &str, image: &str) -> Result<(), String> {
    if !IMAGE_REF_RE.is_match(image) {
        return Err(format!("{field}: {image:?} is not a valid image reference"));
    }
    Ok(())
}

/// Validate a dotted-quad IPv4 address.
pub fn validate_ipv4(field: &str, value: &str) -> Result<(), String> {
    let octets: Vec<&str> = value.split('.').collect();
    if octets.len() != 4
        || octets
            .iter()
            .any(|o| o.is_empty() || o.parse::<u8>().is_err())
    {
        return Err(format!(
            "{field}: {value:?} is not a valid IPv4 dotted-quad"
        ));
    }
    Ok(())
}

/// Validate a space-separated list of upstream resolver addresses.
///
/// This value lands in a `--env` assignment, so it must not be able to
/// smuggle a second assignment: every token has to parse as an address and
/// nothing else is admitted.
pub fn validate_resolver_list(field: &str, value: &str) -> Result<(), String> {
    if value.is_empty() {
        return Err(format!("{field}: resolver list is empty"));
    }
    let mut seen = 0usize;
    for token in value.split(' ') {
        if token.is_empty() {
            return Err(format!("{field}: {value:?} has an empty resolver entry"));
        }
        validate_ipv4(field, token)?;
        seen += 1;
    }
    if seen > 8 {
        return Err(format!("{field}: more than 8 resolvers in {value:?}"));
    }
    Ok(())
}

/// Validate a path that will be interpolated into a docker `--mount` option
/// list.
///
/// Absolute, no `..` (via [`validate_path_arg`]), and additionally free of
/// `,` and `=`: docker reads both as option-list syntax there, so a path
/// containing either would add mount options nobody wrote.
pub fn validate_mount_path(field: &str, path: &str) -> Result<(), String> {
    validate_path_arg(field, path)?;
    if let Some(ch) = path.chars().find(|c| matches!(c, ',' | '=')) {
        return Err(format!(
            "{field}: {path:?} contains {ch:?}, which docker reads as option-list \
             syntax inside a --mount value"
        ));
    }
    Ok(())
}

/// Ceiling on the size of an artifact the daemon may write into a gateway
/// container.
///
/// Far above anything the generators produce — the largest artifact is the
/// Envoy listener, tens of KB with a full policy — so this is not a
/// correctness bound on any real policy. It exists so a runaway generator
/// on the other end of the socket cannot make the agent buffer an
/// unbounded string, and so an oversized frame fails with a reason instead
/// of as an allocation.
pub const MAX_GATEWAY_ARTIFACT_BYTES: usize = 8 * 1024 * 1024;

/// Characters that would be re-read by a shell if they appeared inside the
/// single-quoted words of a `sh -c` body.
const SHELL_UNSAFE: &[char] = &[
    '\'', '"', '`', '$', ';', '&', '|', '<', '>', '(', ')', '{', '}', '[', ']', '*', '?', '!', '#',
    '~', '\\', '\n', '\r', '\t', ' ',
];

/// Check that the path an enumerated gateway file resolves to is safe to
/// interpolate into the `sh -c` body that writes it.
///
/// # Why this exists when nothing here is caller-supplied
///
/// The write command's destination comes from an enum, so the daemon
/// contributes a discriminant and never a path — that is the allowlist, and
/// it is why the single quotes in the delivery script are legibility rather
/// than a defence. What this function adds is that the allowlist's *entries*
/// are checked, in the shipping build, on every op. A future variant whose
/// path carried a quote or a `$` would otherwise silently make those quotes
/// load-bearing, and the site this replaced made exactly that check with a
/// `debug_assert!` — a guard that is compiled out of release, which is to
/// say a guard that was not there.
///
/// The argv crate has a unit test asserting the same property over every
/// variant. That test and this check answer different questions: the test
/// says the set was correct when it was built, this says the agent refuses
/// an entry that is not, including one reaching it from a daemon built from
/// a different revision.
pub fn validate_gateway_file_path(
    file: sandbox_docker_argv::gateway::GatewayFile,
) -> Result<(), String> {
    for (label, value) in [
        ("path", file.path()),
        ("parent_dir", file.parent_dir()),
        ("staging_path", file.staging_path()),
    ] {
        if !value.starts_with('/') || value.contains("..") {
            return Err(format!(
                "gateway file {}: {label} {value:?} is not a plain absolute path",
                file.as_str()
            ));
        }
        if let Some(ch) = value.chars().find(|c| SHELL_UNSAFE.contains(c)) {
            return Err(format!(
                "gateway file {}: {label} {value:?} contains {ch:?}, which a shell \
                 would re-read",
                file.as_str()
            ));
        }
    }
    Ok(())
}

/// Validate one stdin-fed command and the artifact it carries.
///
/// Three things are checked, and only one of them is about the command:
///
/// - **The write allowlist.** A file the daemon may read is not thereby a
///   file the daemon may write. `GatewayFile::writable` is the split, and
///   this is where it is enforced.
/// - **The destination path.** See [`validate_gateway_file_path`].
/// - **The artifact's size.** The content itself is not otherwise
///   inspected: it is policy, the daemon is the authority on what it says,
///   and the process that reads it — `nft` or `cat` — is the one that
///   decides whether it parses. An agent that second-guessed the ruleset
///   would be re-implementing the policy compiler with less information.
fn validate_stdin_command(
    command: &crate::protocol::StdinCommand,
    body: &str,
) -> Result<(), String> {
    use crate::protocol::StdinCommand;

    if body.len() > MAX_GATEWAY_ARTIFACT_BYTES {
        return Err(format!(
            "stdin body is {} bytes, over the {MAX_GATEWAY_ARTIFACT_BYTES}-byte ceiling",
            body.len()
        ));
    }

    match command {
        // The ruleset goes to `nft -f -`, which reads it as content. There
        // is no command line to protect.
        StdinCommand::ApplyNftRuleset => Ok(()),
        StdinCommand::WriteGatewayFile { file, .. } => {
            let file: sandbox_docker_argv::gateway::GatewayFile = (*file).into();
            if !file.writable() {
                return Err(format!(
                    "gateway file {} is read-only; the daemon may read it but not write it",
                    file.as_str()
                ));
            }
            validate_gateway_file_path(file)
        }
    }
}

/// Re-validate a [`crate::protocol::DockerStreamOp`] before the agent opens
/// a byte pipe into a container.
///
/// There is exactly one field to check, and that is the point of the op's
/// shape: the destination inside the container is a discriminant the agent
/// turns into a `socat` address from its own constants, and the Docker daemon
/// is the agent's own socket, so neither is a value that could be wrong. What
/// the daemon does supply is the container name, and a name that is not a
/// name is how `docker exec` gets an extra flag.
pub fn validate_docker_stream_op(op: &crate::protocol::DockerStreamOp) -> Result<(), String> {
    validate_docker_name("container", op.container())
}

/// Re-validate every field of a [`crate::protocol::DockerOp`] before the
/// agent builds any argv from it.
///
/// The daemon has validated these values too. That is not a reason to skip
/// them here: the agent's whole job is to be the thing that still says no
/// when the daemon has been persuaded to ask for something it should not.
pub fn validate_docker_op(op: &crate::protocol::DockerOp) -> Result<(), String> {
    use crate::protocol::{ContainerCommand, DockerOp};

    match op {
        DockerOp::ContainerCreate { spec } => {
            validate_session_name(&spec.session_id)?;
            validate_docker_name("docker_network", &spec.docker_network)?;
            validate_ipv4("container_ip", &spec.container_ip)?;
            validate_ipv4("gateway_ip", &spec.gateway_ip)?;
            validate_image_ref("image_tag", &spec.image_tag)?;
            validate_range("memory_mb", spec.memory_mb, 64, 1_048_576)?;
            if !(spec.cpus.is_finite() && spec.cpus > 0.0 && spec.cpus <= 1024.0) {
                return Err(format!("cpus: {} is not a usable cpu count", spec.cpus));
            }
            if let Some(pool) = &spec.owner_pool {
                validate_cidr_owner("owner_pool", pool)?;
            }
            if let Some(bind) = &spec.workspace_bind {
                validate_mount_path("workspace_bind.host_path", &bind.host_path)?;
                validate_mount_path("workspace_bind.guest_path", &bind.guest_path)?;
            }
            if let Some(ca) = &spec.ca_host_path {
                validate_mount_path("ca_host_path", ca)?;
            }
            if let Some(dir) = &spec.ssh_host_dir {
                validate_mount_path("ssh_host_dir", dir)?;
            }
            if let Some(src) = &spec.guest_bind_source {
                validate_mount_path("guest_bind_source", src)?;
            }
        }
        DockerOp::ContainerStart { name }
        | DockerOp::ContainerRestart { name }
        | DockerOp::ContainerRemove { name, .. } => {
            validate_docker_name("container", name)?;
        }
        DockerOp::ContainerStop {
            name, grace_secs, ..
        } => {
            validate_docker_name("container", name)?;
            validate_range("grace_secs", *grace_secs, 0, 3600)?;
        }
        DockerOp::ContainerInspect { name, .. } => {
            validate_docker_name("container", name)?;
        }
        DockerOp::ContainerList {
            name_prefix,
            owner_pool,
        }
        | DockerOp::NetworkList {
            name_prefix,
            owner_pool,
        }
        | DockerOp::VolumeList {
            name_prefix,
            owner_pool,
        } => {
            validate_docker_name_prefix("name_prefix", name_prefix)?;
            if let Some(pool) = owner_pool {
                validate_cidr_owner("owner_pool", pool)?;
            }
        }
        DockerOp::ContainerExec { name, command } => {
            validate_docker_name("container", name)?;
            match command {
                // The one variant carrying a caller-supplied string.
                ContainerCommand::MakeDirectory { path } => {
                    validate_path_arg("mkdir path", path)?;
                }
                // A read whose path comes from the enum still has its
                // resolved path checked: the read is a bare `cat` with no
                // shell, but the same enum feeds the write, and a variant
                // that is unfit to interpolate should be refused wherever
                // it appears rather than only where it is dangerous.
                ContainerCommand::ReadGatewayFile { file } => {
                    validate_gateway_file_path((*file).into())?;
                }
                // The remaining variants are constants of the argv crate
                // and have nothing to validate — which is the point of
                // enumerating them.
                ContainerCommand::SshdListening
                | ContainerCommand::GatewayHealthcheck
                | ContainerCommand::ComponentProbe { .. }
                | ContainerCommand::ListNftTable { .. }
                | ContainerCommand::EnvoyStat { .. } => {}
            }
        }
        DockerOp::ContainerExecStdin {
            name,
            command,
            body,
        } => {
            validate_docker_name("container", name)?;
            validate_stdin_command(command, body)?;
        }
        DockerOp::HomeVolumeChown {
            session_id,
            image_tag,
            operator_uid,
            operator_gid,
        } => {
            validate_session_name(session_id)?;
            validate_image_ref("image_tag", image_tag)?;
            // uid 0 would hand the volume to root, which is the opposite of
            // what this op exists to do.
            validate_range("operator_uid", *operator_uid, 1, u32::MAX - 1)?;
            validate_range("operator_gid", *operator_gid, 1, u32::MAX - 1)?;
        }
        DockerOp::GatewayContainerRun {
            session_id,
            image_tag,
            network,
            owner_pool,
            coredns_upstream,
        } => {
            validate_session_name(session_id)?;
            validate_image_ref("image_tag", image_tag)?;
            validate_docker_name("network", network)?;
            if let Some(pool) = owner_pool {
                validate_cidr_owner("owner_pool", pool)?;
            }
            if let Some(upstream) = coredns_upstream {
                validate_resolver_list("coredns_upstream", upstream)?;
            }
        }
        DockerOp::NetworkCreate { spec } => {
            validate_docker_name("network", &spec.name)?;
            if let Some(subnet) = &spec.subnet {
                validate_cidr_owner("subnet", subnet)?;
            }
            if let Some(gateway) = &spec.gateway {
                validate_ipv4("gateway", gateway)?;
            }
            if let Some(session_id) = &spec.session_id {
                validate_session_name(session_id)?;
            }
            if let Some(pool) = &spec.owner_pool {
                validate_cidr_owner("owner_pool", pool)?;
            }
            for option in &spec.options {
                validate_network_option(option)?;
            }
        }
        DockerOp::NetworkRemove { name } | DockerOp::NetworkInspect { name } => {
            validate_docker_name("network", name)?;
        }
        DockerOp::NetworkConnect {
            network,
            container,
            ip,
            // The daemon states an intent, not a number: both variants are
            // in-range by construction and the value Docker sees is this
            // agent's constant, so there is nothing here to re-validate.
            gateway_priority: _,
        } => {
            validate_docker_name("network", network)?;
            validate_docker_name("container", container)?;
            if let Some(ip) = ip {
                validate_ipv4("ip", ip)?;
            }
        }
        DockerOp::VolumeCreate {
            name,
            session_id,
            owner_pool,
        } => {
            validate_docker_name("volume", name)?;
            if let Some(session_id) = session_id {
                validate_session_name(session_id)?;
            }
            if let Some(pool) = owner_pool {
                validate_cidr_owner("owner_pool", pool)?;
            }
        }
        DockerOp::VolumeRemove { name } => {
            validate_docker_name("volume", name)?;
        }
        DockerOp::ImageInspect { tag } => {
            validate_image_ref("tag", tag)?;
        }
        // Nothing crosses the wire on these two: the tarball is named by an
        // enum the agent resolves against its own staging directory, and
        // `docker info` takes no arguments at all.
        DockerOp::ImageLoad { .. } | DockerOp::DaemonInfo => {}
    }
    Ok(())
}

/// Re-validate every field of a [`crate::protocol::InVmOp`] before the agent
/// builds any argv from it.
///
/// There is very little to check, and that is the shape working rather than
/// the check being thin. Eight of the twelve variants carry no daemon-supplied
/// value at all — what they do is fixed by the variant and rendered from
/// constants. What remains is three kinds of value, and each gets the check its
/// destination needs:
///
/// - **The session identifier**, which is joined onto a constant root to name
///   a directory that is created, written into and eventually `rm -rf`'d. A
///   value with a `/` or a `..` in it would move that `rm -rf` somewhere else
///   in the VM, so it gets the same charset check a VM or session name gets —
///   which admits neither.
/// - **The nftables ruleset and the staged file bodies**, which are content.
///   They are deliberately *not* pattern-checked: an nftables ruleset that had
///   to survive a syntax filter here would have two parsers disagreeing about
///   what the policy says, and the one that matters is `nft`'s. What makes
///   them safe is where they go — a parser's stdin and a file's contents —
///   not what they look like.
/// - **The container pid and gateway address** on
///   [`crate::protocol::InVmOp::InstallContainerRoute`], where almost all of
///   the checking was done by the types before this function ran. An
///   `Ipv4Addr` field cannot hold a non-address; a `u32` cannot hold a
///   negative. The one thing left over is that the far end parses the pid into
///   an `i32`, so a value above `i32::MAX` would arrive here well-formed and
///   fail at the helper's own parser with a message about argument syntax
///   rather than about the value. Rejecting it here is the difference between
///   a clear error and a confusing one.
///
/// # What this function deliberately does not check
///
/// That the gateway address is the *right* one for that container. It is not a
/// check that can be made here, and writing a weak version of it would be
/// worse than none: the process this control exists to stop runs the installed
/// helper directly, inside the VM, and never reaches this function. A caller
/// who is subject to this validation is one who was already going through the
/// daemon. The control that binds the other caller too is in the helper, after
/// it enters the container's network namespace — see that crate's
/// `containment` module.
pub fn validate_in_vm_op(op: &crate::protocol::InVmOp) -> Result<(), String> {
    use crate::protocol::InVmOp;

    match op {
        InVmOp::LiteStageCreate { session_id }
        | InVmOp::LiteStageRemove { session_id }
        | InVmOp::LiteStageWrite { session_id, .. } => {
            validate_session_name(session_id)?;
        }
        InVmOp::InstallContainerRoute { container_pid, .. } => {
            validate_container_pid(*container_pid)?;
        }
        // Nothing daemon-supplied crosses the wire on these. The commands are
        // constants of the argv crate; the ruleset on `ApplyNftBaseline` is
        // content for `nft`'s parser, not a value with a shape to check.
        InVmOp::DockerReady
        | InVmOp::LinkShowJson
        | InVmOp::ApplyNftBaseline { .. }
        | InVmOp::RouteHelperProbe
        | InVmOp::RouteHelperMakeInstallDir
        | InVmOp::RouteHelperStage
        | InVmOp::RouteHelperInstall
        | InVmOp::RouteHelperSetcap => {}
    }
    Ok(())
}

/// The process the route-install op enters the network namespace of.
///
/// The type already did the work that matters — a `u32` cannot be negative, so
/// the rendered argv word cannot start with `-` and be read as a flag. Two
/// bounds remain, and both exist so that a bad value fails here with a message
/// naming it rather than three layers down with a message about something else:
///
/// - **Zero is not a pid.** It is the value an uninitialised field or a failed
///   `docker inspect` produces, and `pidfd_open(0)` fails with `EINVAL` — an
///   error that reads like a kernel problem rather than a missing container.
/// - **Above `i32::MAX` is not a pid the far end can parse.** The helper's
///   argument parser takes an `i32`. A larger value is well-formed on this side
///   and unparseable on the other.
///
/// The upper bound is deliberately `i32::MAX` rather than the running kernel's
/// `pid_max`: `pid_max` is tunable, lives in the VM rather than here, and a pid
/// that is merely improbable is not the thing worth rejecting. What is worth
/// rejecting is a value that cannot survive the wire.
fn validate_container_pid(pid: u32) -> Result<(), String> {
    if pid == 0 {
        return Err("container pid must be a real process id; got 0".to_string());
    }
    if pid > i32::MAX as u32 {
        return Err(format!(
            "container pid {pid} exceeds the maximum a pid can be ({})",
            i32::MAX
        ));
    }
    Ok(())
}

/// Validate one network `--opt` value.
fn validate_network_option(option: &crate::protocol::NetworkOption) -> Result<(), String> {
    use crate::protocol::NetworkOption;
    match option {
        NetworkOption::BridgeName { interface } => validate_bridge_name(interface),
        // A boolean cannot carry anything but itself.
        NetworkOption::BridgeMasquerade { .. } => Ok(()),
        NetworkOption::MacvlanParent { parent } => validate_bridge_name(parent),
        // A mode with one admissible value carries nothing to validate.
        NetworkOption::MacvlanModePrivate => Ok(()),
    }
}

// ---------------------------------------------------------------------------
// Tests — non-tautological, exercise the real validation functions
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Arbitrary daemon-uid used in test fixture paths.  The value `501` is the
    /// default macOS UID for the first non-root user and has no special meaning
    /// here — it is chosen only to keep fixture paths realistic.
    const TEST_DAEMON_UID: u32 = 501;

    // -----------------------------------------------------------------------
    // own-uid gate
    // -----------------------------------------------------------------------

    #[test]
    fn own_uid_gate_passes_when_equal() {
        assert!(validate_op_uid(1000, 1000).is_ok());
    }

    #[test]
    fn own_uid_gate_rejects_foreign_uid() {
        let result = validate_op_uid(1000, 1001);
        assert!(result.is_err());
        // Must contain the mismatched uids in the reason.
        let reason = result.unwrap_err();
        assert!(
            reason.contains("1001"),
            "reason should mention op_uid: {reason}"
        );
        assert!(
            reason.contains("1000"),
            "reason should mention own_uid: {reason}"
        );
    }

    #[test]
    fn own_uid_gate_rejects_uid_zero() {
        // Even if the agent somehow ran as uid 0, an op_uid of 0 should be
        // rejected: the own-uid check would compare 0 == 0 (pass), but a
        // real agent running as uid 0 indicates a misconfiguration — and the
        // broker already rejects uid-0 check-ins at the daemon side. Test that
        // an op_uid=0 from the daemon to a non-zero agent is rejected.
        let result = validate_op_uid(1000, 0);
        assert!(result.is_err());
    }

    // -----------------------------------------------------------------------
    // VM name validation — must reject, not clamp
    // -----------------------------------------------------------------------

    #[test]
    fn vm_name_valid_cases() {
        for name in &[
            "sandbox-abc",
            "sandbox123",
            "a",
            "Z",
            "abc_def",
            "ABCdef123",
            &"a".repeat(64),
        ] {
            assert!(
                validate_vm_name(name).is_ok(),
                "expected valid vm name: {name:?}"
            );
        }
    }

    #[test]
    fn vm_name_rejects_empty() {
        assert!(validate_vm_name("").is_err());
    }

    #[test]
    fn vm_name_rejects_too_long() {
        assert!(validate_vm_name(&"a".repeat(65)).is_err());
    }

    #[test]
    fn vm_name_rejects_leading_dash() {
        // Leading dash would be parsed as a flag by limactl.
        let result = validate_vm_name("-bad-name");
        assert!(
            result.is_err(),
            "leading-dash vm name must be rejected, not clamped"
        );
    }

    #[test]
    fn vm_name_rejects_space() {
        assert!(validate_vm_name("has space").is_err());
    }

    #[test]
    fn vm_name_rejects_dot() {
        assert!(validate_vm_name("has.dot").is_err());
    }

    #[test]
    fn vm_name_rejects_slash() {
        // A slash would allow path traversal when the name is used in a path.
        let result = validate_vm_name("has/slash");
        assert!(
            result.is_err(),
            "slash in vm name must be rejected, not passed to limactl"
        );
    }

    #[test]
    fn vm_name_rejects_dotdot_component() {
        assert!(validate_vm_name("..").is_err());
    }

    #[test]
    fn vm_name_rejects_newline() {
        assert!(validate_vm_name("has\nnewline").is_err());
    }

    // -----------------------------------------------------------------------
    // Path argument validation
    // -----------------------------------------------------------------------

    #[test]
    fn path_arg_valid_absolute_paths() {
        assert!(validate_path_arg("--yaml", "/etc/lima/base.yaml").is_ok());
        assert!(validate_path_arg("--yaml", "/a/b/c").is_ok());
        assert!(validate_path_arg("--yaml", "/usr/local/libexec/sandboxd/wrapper").is_ok());
    }

    #[test]
    fn path_arg_rejects_relative() {
        let result = validate_path_arg("--yaml", "relative/path");
        assert!(
            result.is_err(),
            "relative path must be rejected, not used as-is"
        );
    }

    #[test]
    fn path_arg_rejects_dotdot_traversal() {
        let result = validate_path_arg("--yaml", "/etc/../etc/passwd");
        assert!(
            result.is_err(),
            "dotdot traversal must be rejected, not resolved"
        );
    }

    #[test]
    fn path_arg_rejects_nul_byte() {
        let result = validate_path_arg("--yaml", "/etc/file\0name");
        assert!(result.is_err(), "NUL byte in path must be rejected");
    }

    // -----------------------------------------------------------------------
    // LIMA_HOME confinement
    // -----------------------------------------------------------------------

    #[test]
    fn lima_home_confinement_accepts_child_path() {
        let lima_home = format!("/var/lib/sandboxd/{TEST_DAEMON_UID}/1000/lima");
        let path = format!("/var/lib/sandboxd/{TEST_DAEMON_UID}/1000/lima/sandbox-abc/lima.yaml");
        assert!(validate_lima_home_path(&lima_home, &path).is_ok());
    }

    #[test]
    fn lima_home_confinement_accepts_trailing_slash_variant() {
        let lima_home = format!("/var/lib/sandboxd/{TEST_DAEMON_UID}/1000/lima/");
        let path = format!("/var/lib/sandboxd/{TEST_DAEMON_UID}/1000/lima/sandbox-abc/file");
        assert!(validate_lima_home_path(&lima_home, &path).is_ok());
    }

    #[test]
    fn lima_home_confinement_rejects_parent_escape() {
        // Path escapes LIMA_HOME by going to a sibling dir.
        let lima_home = format!("/var/lib/sandboxd/{TEST_DAEMON_UID}/1000/lima");
        let result = validate_lima_home_path(
            &lima_home,
            &format!("/var/lib/sandboxd/{TEST_DAEMON_UID}/9999/lima/sandbox-abc/file"),
        );
        assert!(
            result.is_err(),
            "path outside LIMA_HOME must be rejected, not followed"
        );
    }

    #[test]
    fn lima_home_confinement_rejects_dotdot_escape() {
        let lima_home = format!("/var/lib/sandboxd/{TEST_DAEMON_UID}/1000/lima");
        let result = validate_lima_home_path(
            &lima_home,
            &format!("/var/lib/sandboxd/{TEST_DAEMON_UID}/1000/lima/../other/file"),
        );
        assert!(
            result.is_err(),
            "dotdot escape from LIMA_HOME must be rejected"
        );
    }

    #[test]
    fn lima_home_confinement_rejects_prefix_spoofing() {
        // A path that starts with the LIMA_HOME string but is actually a
        // sibling directory (e.g. `…/<daemon_uid>/1000/limactl`).
        let lima_home = format!("/var/lib/sandboxd/{TEST_DAEMON_UID}/1000/lima");
        let result = validate_lima_home_path(
            &lima_home,
            &format!("/var/lib/sandboxd/{TEST_DAEMON_UID}/1000/limactl/evil"),
        );
        // The base is normalised to `…/1000/lima/`, so `limactl/evil` does
        // not start with it — correct rejection.
        assert!(result.is_err(), "prefix-spoof path must be rejected");
        // The error must name the rejected path so the caller can diagnose it.
        let msg = result.unwrap_err();
        assert!(
            msg.contains("limactl/evil"),
            "error must identify the rejected path; got: {msg}"
        );
    }

    // -----------------------------------------------------------------------
    // Numeric range — reject, never clamp
    // -----------------------------------------------------------------------

    #[test]
    fn range_valid_boundary_values() {
        assert!(validate_range("--cpus", 1, 1, 64).is_ok());
        assert!(validate_range("--cpus", 64, 1, 64).is_ok());
        assert!(validate_range("--memory-mb", 256, 256, 262144).is_ok());
        assert!(validate_range("--memory-mb", 262144, 256, 262144).is_ok());
    }

    #[test]
    fn range_rejects_below_min() {
        // Must reject, not clamp to min; error must name the field and the
        // rejected value so the caller can produce a useful diagnostic.
        let result = validate_range("--cpus", 0, 1, 64);
        let msg = result.expect_err("value below min must be rejected, not clamped to 1");
        assert!(
            msg.contains("--cpus"),
            "error must name the field; got: {msg}"
        );
        assert!(
            msg.contains('0'),
            "error must identify the rejected value; got: {msg}"
        );

        let mem_err = validate_range("--memory-mb", 255, 256, 262144)
            .expect_err("255 MB is below the 256 MB floor");
        assert!(
            mem_err.contains("--memory-mb"),
            "error must name the field; got: {mem_err}"
        );
    }

    #[test]
    fn range_rejects_above_max() {
        // Must reject, not clamp to max; error must name the field and the
        // rejected value so the caller can produce a useful diagnostic.
        let result = validate_range("--cpus", 65, 1, 64);
        let msg = result.expect_err("value above max must be rejected, not clamped to 64");
        assert!(
            msg.contains("--cpus"),
            "error must name the field; got: {msg}"
        );
        assert!(
            msg.contains("65"),
            "error must identify the rejected value; got: {msg}"
        );

        let mem_err = validate_range("--memory-mb", 262145, 256, 262144)
            .expect_err("262145 MB exceeds the ceiling");
        assert!(
            mem_err.contains("--memory-mb"),
            "error must name the field; got: {mem_err}"
        );
    }

    // -----------------------------------------------------------------------
    // CIDR owner
    // -----------------------------------------------------------------------

    #[test]
    fn cidr_valid_cases() {
        assert!(validate_cidr_owner("--owner", "10.209.0.0/20").is_ok());
        assert!(validate_cidr_owner("--owner", "0.0.0.0/0").is_ok());
        assert!(validate_cidr_owner("--owner", "255.255.255.0/24").is_ok());
    }

    #[test]
    fn cidr_rejects_missing_slash() {
        assert!(validate_cidr_owner("--owner", "10.209.0.0").is_err());
    }

    #[test]
    fn cidr_rejects_bad_prefix() {
        assert!(validate_cidr_owner("--owner", "10.0.0.0/33").is_err());
        assert!(validate_cidr_owner("--owner", "10.0.0.0/abc").is_err());
    }

    #[test]
    fn cidr_rejects_bad_address() {
        assert!(validate_cidr_owner("--owner", "10.256.0.0/24").is_err());
        assert!(validate_cidr_owner("--owner", "not-an-ip/24").is_err());
    }

    #[test]
    fn cidr_rejects_injection_chars() {
        // Shell metacharacters must be rejected — these would be visible in
        // the marker file if they slipped through.
        assert!(validate_cidr_owner("--owner", "10.0.0.0/24\n").is_err());
        assert!(validate_cidr_owner("--owner", "10.0.0.0 /24").is_err());
        assert!(validate_cidr_owner("--owner", "10.0.0.0/24;rm -rf /").is_err());
    }

    // -----------------------------------------------------------------------
    // Bridge name + MAC
    // -----------------------------------------------------------------------

    #[test]
    fn bridge_name_valid() {
        assert!(validate_bridge_name("sandbox-br").is_ok());
        assert!(validate_bridge_name("br0").is_ok());
        assert!(validate_bridge_name(&"a".repeat(15)).is_ok());
    }

    #[test]
    fn bridge_name_rejects_empty() {
        assert!(validate_bridge_name("").is_err());
    }

    #[test]
    fn bridge_name_rejects_too_long() {
        assert!(validate_bridge_name(&"a".repeat(16)).is_err());
    }

    #[test]
    fn bridge_name_rejects_dot() {
        assert!(validate_bridge_name("has.dot").is_err());
    }

    #[test]
    fn mac_valid_unicast() {
        assert!(validate_vm_mac("02:00:00:00:00:01").is_ok());
        // Even first-octet MSB pattern: 0xA2 = 1010_0010, LSB=0 (unicast).
        assert!(validate_vm_mac("A2:BB:CC:DD:EE:FF").is_ok());
    }

    #[test]
    fn mac_rejects_multicast_bit() {
        // 0x01 has LSB=1 — multicast.
        let result = validate_vm_mac("01:00:00:00:00:01");
        assert!(
            result.is_err(),
            "multicast MAC must be rejected, not used for VM NIC"
        );
    }

    #[test]
    fn mac_rejects_malformed() {
        assert!(validate_vm_mac("not-a-mac").is_err());
        assert!(validate_vm_mac("GG:00:00:00:00:01").is_err()); // non-hex
        assert!(validate_vm_mac("02:00:00:00:00").is_err()); // too short
    }

    // -----------------------------------------------------------------------
    // Lima YAML shape validation
    // -----------------------------------------------------------------------

    /// Canonical block-style YAML with vmType: qemu and a single socket NIC.
    /// This is the form the daemon's macOS template produces and must be accepted.
    #[test]
    fn lima_yaml_valid_shape_block_style() {
        let yaml = r#"
vmType: "qemu"
images:
  - location: "https://cloud-images.ubuntu.com/releases/noble/release/ubuntu-24.04-server-cloudimg-arm64.img"
    arch: aarch64
cpus: 2
memory: "4GiB"
disk: "20GiB"
networks:
  - socket: /var/run/sandbox/vmnet/slot-0.sock
"#;
        assert!(
            validate_lima_yaml_shape(yaml, "", true).is_ok(),
            "canonical block-style YAML with vmType: qemu must be accepted"
        );
    }

    /// Flow-style `networks` sequence with vmType: qemu.
    /// A buggy daemon using a YAML serializer could produce this form. The
    /// structural parser normalises it to the same Value as the block form,
    /// so it must also be accepted (vmType: qemu, one socket NIC, no mode).
    #[test]
    fn lima_yaml_valid_shape_flow_style_networks() {
        let yaml =
            "vmType: qemu\ncpus: 2\nnetworks: [{socket: /var/run/sandbox/vmnet/slot-0.sock}]\n";
        assert!(
            validate_lima_yaml_shape(yaml, "", true).is_ok(),
            "flow-style single socket NIC with vmType: qemu must be accepted"
        );
    }

    /// vmType absent — must be rejected. Lima on macOS defaults to VZ when
    /// vmType is unset, which cannot attach socket_vmnet and voids egress control.
    #[test]
    fn lima_yaml_rejects_missing_vmtype() {
        let yaml = "networks:\n  - socket: /var/run/sandbox/vmnet/slot-0.sock\n";
        let result = validate_lima_yaml_shape(yaml, "test-vm", true);
        assert!(
            result.is_err(),
            "absent vmType must be rejected — Lima defaults to VZ on macOS, \
             which cannot attach socket_vmnet and would void egress control"
        );
    }

    /// vmType: vz — must be rejected regardless of serialisation style.
    #[test]
    fn lima_yaml_rejects_vmtype_vz() {
        let yaml = "vmType: vz\nnetworks:\n  - socket: /var/run/sandbox/vmnet/slot-0.sock\n";
        let result = validate_lima_yaml_shape(yaml, "test-vm", true);
        assert!(
            result.is_err(),
            "vmType: vz must be rejected — VZ bypasses the gateway"
        );
    }

    /// vmType: qemu — must now be accepted (required for macOS QEMU guarantee).
    #[test]
    fn lima_yaml_accepts_vmtype_qemu_explicit() {
        let yaml = "vmType: qemu\nnetworks:\n  - socket: /var/run/sandbox/vmnet/slot-0.sock\n";
        let result = validate_lima_yaml_shape(yaml, "", true);
        assert!(
            result.is_ok(),
            "explicit vmType: qemu must be accepted; error: {:?}",
            result.err()
        );
    }

    /// vmType: libkrun — a non-qemu, non-vz backend — must be rejected.
    #[test]
    fn lima_yaml_rejects_vmtype_non_qemu() {
        let yaml = "vmType: libkrun\nnetworks:\n  - socket: /var/run/sandbox/vmnet/slot-0.sock\n";
        let result = validate_lima_yaml_shape(yaml, "", true);
        assert!(
            result.is_err(),
            "vmType: libkrun must be rejected — only qemu is permitted"
        );
    }

    /// Flow-style vmType: vz — rejected regardless of serialisation style.
    /// The structural parser catches this regardless of serialisation style.
    #[test]
    fn lima_yaml_rejects_vmtype_flow_style() {
        // Inline flow-mapping for the whole document — vmType: vz in braces.
        // The YAML parser normalises this to the same top-level mapping.
        let yaml = "{vmType: vz, networks: [{socket: /var/run/sandbox/vmnet/slot-0.sock}]}\n";
        let result = validate_lima_yaml_shape(yaml, "", true);
        assert!(
            result.is_err(),
            "flow-style vmType: vz in a flow-mapping document must be rejected"
        );
    }

    /// No `networks` key at all — must be rejected.
    #[test]
    fn lima_yaml_rejects_missing_networks() {
        let yaml = "vmType: qemu\ncpus: 2\nmemory: \"4GiB\"\ndisk: \"20GiB\"\n";
        let result = validate_lima_yaml_shape(yaml, "test-vm", true);
        assert!(
            result.is_err(),
            "YAML with no networks key must be rejected"
        );
    }

    /// Two socket NIC entries — only one is permitted.
    #[test]
    fn lima_yaml_rejects_multiple_socket_nics() {
        let yaml = "vmType: qemu\nnetworks:\n  - socket: /var/run/sandbox/vmnet/slot-0.sock\n  - socket: /var/run/sandbox/vmnet/slot-1.sock\n";
        let result = validate_lima_yaml_shape(yaml, "test-vm", true);
        assert!(
            result.is_err(),
            "YAML with multiple socket NICs must be rejected"
        );
    }

    /// Two socket NICs in flow style — `[{socket: ...}, {socket: ...}]`.
    /// Previously evadable: the second entry's `socket:` appeared after the
    /// first, so the line-counter would find 2, but a carefully crafted
    /// single-line form might not. The structural parser counts entries in
    /// the sequence directly.
    #[test]
    fn lima_yaml_rejects_multiple_socket_nics_flow_style() {
        let yaml = "vmType: qemu\nnetworks: [{socket: /var/run/sandbox/vmnet/slot-0.sock}, {socket: /var/run/sandbox/vmnet/slot-1.sock}]\n";
        let result = validate_lima_yaml_shape(yaml, "test-vm", true);
        assert!(
            result.is_err(),
            "flow-style multiple socket NICs must be rejected"
        );
    }

    /// NIC entry with a `mode` key — managed named-network form, not permitted.
    /// The NIC must have exactly one key (`socket`); any extra key is rejected.
    #[test]
    fn lima_yaml_rejects_nic_with_mode_key() {
        // Single NIC entry containing both socket and mode — extra key, rejected.
        let yaml = "vmType: qemu\nnetworks:\n  - socket: /var/run/sandbox/vmnet/slot-0.sock\n    mode: shared\n";
        let result = validate_lima_yaml_shape(yaml, "test-vm", true);
        assert!(
            result.is_err(),
            "NIC entry with a mode: key must be rejected"
        );
    }

    /// NIC entry in flow style containing `socket` AND `mode`.
    /// Previously evadable with line-based checking if the mode entry appeared
    /// on the same line as socket in flow style. The structural parser sees the
    /// mapping keys regardless of serialisation form.
    #[test]
    fn lima_yaml_rejects_nic_mode_in_flow_style() {
        // Flow-style NIC mapping with both socket and mode.
        let yaml = "vmType: qemu\nnetworks: [{socket: /var/run/sandbox/vmnet/slot-0.sock, mode: shared}]\n";
        let result = validate_lima_yaml_shape(yaml, "test-vm", true);
        assert!(
            result.is_err(),
            "flow-style {{socket: ..., mode: shared}} NIC must be rejected; \
             previously evadable with line-based matching"
        );
    }

    /// YAML anchor and alias — `&nic {socket: ...}` then `*nic` as a second
    /// entry. Previously evadable: the alias `*nic` doesn't contain the literal
    /// string `socket:`, so the line-counter would find only 1 socket entry
    /// but there are actually 2 NICs. serde_yaml resolves anchors/aliases
    /// during parsing, so the second entry is materialised as a full mapping
    /// and the sequence-length check catches the extra NIC.
    #[test]
    fn lima_yaml_rejects_anchor_alias_extra_nic() {
        let yaml = "vmType: qemu\nnetworks:\n  - &nic\n    socket: /var/run/sandbox/vmnet/slot-0.sock\n  - *nic\n";
        let result = validate_lima_yaml_shape(yaml, "test-vm", true);
        assert!(
            result.is_err(),
            "anchor/alias that introduces a second NIC must be rejected; \
             previously evadable with line-based counting"
        );
    }

    /// Quoted key `'socket'` — flow-style NIC with a quoted key name.
    /// Previously evadable with line-based checks: `'socket':` does not
    /// start with `socket:` or `- socket:` and doesn't contain ` socket:`.
    /// The structural parser resolves the quoted key to the same string.
    #[test]
    fn lima_yaml_valid_shape_quoted_socket_key() {
        // serde_yaml parses 'socket' and socket as the same string key.
        // A single-NIC YAML with a quoted key must be accepted — the check is
        // on the parsed structure, not the raw text.
        let yaml = "vmType: qemu\nnetworks:\n  - 'socket': /var/run/sandbox/vmnet/slot-0.sock\n";
        assert!(
            validate_lima_yaml_shape(yaml, "", true).is_ok(),
            "quoted 'socket' key must be accepted — parser normalises to same key"
        );
    }

    /// Quoted `vmType` key — `'vmType': vz`. Previously, line-based checking
    /// of `lima_yaml.contains("vmType:")` would miss this form because the
    /// colon follows the closing quote, not the key text directly. The
    /// structural parser resolves the quoted key to the same string.
    #[test]
    fn lima_yaml_rejects_quoted_vmtype_key() {
        let yaml = "'vmType': vz\nnetworks:\n  - socket: /slot-0.sock\n";
        let result = validate_lima_yaml_shape(yaml, "test-vm", true);
        assert!(
            result.is_err(),
            "quoted 'vmType' key must be rejected; \
             previously evadable with contains(\"vmType:\") check"
        );
    }

    /// Empty YAML — must be rejected.
    #[test]
    fn lima_yaml_rejects_empty() {
        let result = validate_lima_yaml_shape("", "test-vm", true);
        assert!(result.is_err(), "empty YAML must be rejected");
    }

    // -----------------------------------------------------------------------
    // B2 fix: base-image-build YAML (networks-less) validation
    //
    // The base-image build VM uses Lima's slirp NIC only and deliberately
    // has no `networks:` key. When `require_socket_vmnet` is false the check
    // must not require a socket_vmnet entry; all other checks (vmType, singular
    // `network` key, etc.) still apply to both session and base-build VMs.
    // -----------------------------------------------------------------------

    /// A hardened session create with a networks-less lima.yaml must still be
    /// rejected — the socket_vmnet requirement is not gated on the base-build
    /// exemption when `require_socket_vmnet` is true.
    #[test]
    fn lima_yaml_session_create_requires_networks_entry() {
        let yaml = "vmType: \"qemu\"\ncpus: 4\nmemory: \"4GiB\"\ndisk: \"10GiB\"\n";
        let result = validate_lima_yaml_shape(yaml, "test-vm", true);
        assert!(
            result.is_err(),
            "session create (require_socket_vmnet=true) with networks-less YAML must be rejected"
        );
        let reason = result.unwrap_err();
        assert!(
            reason.contains("networks"),
            "rejection reason must mention 'networks'; got: {reason:?}"
        );
    }

    /// A base-image-build create (require_socket_vmnet=false) with a
    /// networks-less lima.yaml must pass the socket_vmnet check. This is the
    /// B2 fix: the base-image build VM has no networks: key by design.
    #[test]
    fn lima_yaml_base_build_create_accepts_networks_less_yaml() {
        let yaml = "vmType: \"qemu\"\ncpus: 4\nmemory: \"4GiB\"\ndisk: \"10GiB\"\n";
        let result = validate_lima_yaml_shape(yaml, "", false);
        assert!(
            result.is_ok(),
            "base-image-build create (require_socket_vmnet=false) must accept \
             networks-less YAML; error: {:?}",
            result.err()
        );
    }

    /// A hardened session create with a valid socket_vmnet entry still passes.
    /// This ensures the gating change does not inadvertently break the session
    /// VM creation path.
    #[test]
    fn lima_yaml_session_create_with_socket_vmnet_passes() {
        let yaml = "vmType: \"qemu\"\nnetworks:\n  - socket: /var/run/sandbox/vmnet/slot-0.sock\n";
        let result = validate_lima_yaml_shape(yaml, "", true);
        assert!(
            result.is_ok(),
            "session create with valid socket_vmnet entry must pass; error: {:?}",
            result.err()
        );
    }

    /// A base-image-build create with a networks-less YAML still requires
    /// vmType: qemu — the vmType check is unconditional.
    #[test]
    fn lima_yaml_base_build_still_requires_vmtype_qemu() {
        let yaml = "cpus: 4\nmemory: \"4GiB\"\ndisk: \"10GiB\"\n";
        let result = validate_lima_yaml_shape(yaml, "", false);
        assert!(
            result.is_err(),
            "base-image-build create must still reject absent vmType"
        );
    }

    /// A base-image-build create with vmType: vz must still be rejected — the
    /// vmType check is unconditional regardless of require_socket_vmnet.
    #[test]
    fn lima_yaml_base_build_still_rejects_vmtype_vz() {
        let yaml = "vmType: vz\ncpus: 4\nmemory: \"4GiB\"\n";
        let result = validate_lima_yaml_shape(yaml, "", false);
        assert!(
            result.is_err(),
            "base-image-build create must reject vmType: vz; \
             vmType check is unconditional"
        );
    }

    // -----------------------------------------------------------------------
    // Backend validation
    // -----------------------------------------------------------------------

    #[test]
    fn backend_valid_values() {
        assert!(validate_backend("lima").is_ok());
        assert!(validate_backend("container").is_ok());
    }

    #[test]
    fn backend_rejects_arbitrary_string() {
        // An arbitrary backend string must be rejected — not passed to rsync.
        let result = validate_backend("docker exec -it --privileged");
        assert!(
            result.is_err(),
            "arbitrary backend string must be rejected, not forwarded to rsync"
        );
    }

    #[test]
    fn backend_rejects_empty() {
        assert!(validate_backend("").is_err());
    }

    // -----------------------------------------------------------------------
    // NON-FEATURES contract — these tests verify that the closed enum shape
    // and validation together enforce the NON-FEATURES contract from the
    // lima-helper's NON-FEATURES block (adapted for the broker protocol).
    // -----------------------------------------------------------------------

    /// Verify that a VM name containing a shell metacharacter is rejected by
    /// `validate_vm_name`. This is one of the NON-FEATURES contract tests:
    /// even if the daemon were to send a shell-injection payload, the agent
    /// must reject it before it reaches any exec call.
    #[test]
    fn non_features_no_shell_injection_via_vm_name() {
        // Shell injection attempt in the VM name field.
        let injection = "sandbox-abc; rm -rf /";
        let result = validate_vm_name(injection);
        assert!(
            result.is_err(),
            "shell metacharacter in vm name must be rejected before reaching exec"
        );
    }

    /// Verify that a path containing `..` traversal is rejected, not resolved.
    /// This is the NON-FEATURES contract for path confinement.
    #[test]
    fn non_features_no_path_traversal() {
        // Traversal attempt: escape LIMA_HOME and write to a system path.
        let lima_home = format!("/var/lib/sandboxd/{TEST_DAEMON_UID}/1000/lima");
        let traversal =
            format!("/var/lib/sandboxd/{TEST_DAEMON_UID}/1000/lima/../../../etc/cron.d/evil");
        let result = validate_lima_home_path(&lima_home, &traversal);
        assert!(
            result.is_err(),
            "dotdot traversal must be rejected, not resolved to /etc/cron.d/evil"
        );
    }

    /// Verify that a foreign uid is rejected even if the value is numeric and
    /// well-formed. This is the NON-FEATURES contract for the own-uid gate.
    #[test]
    fn non_features_foreign_uid_rejected() {
        // Agent runs as uid 1000; daemon routes to the wrong agent (uid 1001).
        let result = validate_op_uid(1000, 1001);
        assert!(
            result.is_err(),
            "foreign uid must be rejected; agent must only act for its own uid"
        );
    }

    // -----------------------------------------------------------------------
    // validate_socket_path — socket path confinement
    // -----------------------------------------------------------------------

    #[test]
    fn socket_path_valid_slot() {
        assert!(
            validate_socket_path("/var/run/sandbox/vmnet/slot-0.sock").is_ok(),
            "a valid slot socket path must be accepted"
        );
    }

    #[test]
    fn socket_path_valid_slot_numbered() {
        assert!(
            validate_socket_path("/var/run/sandbox/vmnet/slot-7.sock").is_ok(),
            "slot-7 socket path must be accepted"
        );
    }

    #[test]
    fn socket_path_rejects_relative() {
        let result = validate_socket_path("var/run/sandbox/vmnet/slot-0.sock");
        assert!(
            result.is_err(),
            "relative socket path must be rejected; only absolute paths are permitted"
        );
    }

    #[test]
    fn socket_path_rejects_traversal() {
        let result = validate_socket_path("/var/run/sandbox/vmnet/../../../tmp/evil.sock");
        assert!(
            result.is_err(),
            "socket path with '..' traversal must be rejected"
        );
    }

    #[test]
    fn socket_path_rejects_out_of_prefix() {
        let result = validate_socket_path("/var/run/arbitrary/slot-0.sock");
        assert!(
            result.is_err(),
            "socket path outside /var/run/sandbox/vmnet/ must be rejected"
        );
    }

    #[test]
    fn socket_path_rejects_empty() {
        let result = validate_socket_path("");
        assert!(result.is_err(), "empty socket path must be rejected");
    }

    // -----------------------------------------------------------------------
    // B1: validate_lima_yaml_shape rejects non-vmnet socket paths
    // -----------------------------------------------------------------------

    /// A YAML with a socket path outside the vmnet prefix must be rejected.
    /// This guards against a buggy daemon routing a VM to an arbitrary socket,
    /// which would bypass egress enforcement.
    #[test]
    fn lima_yaml_rejects_out_of_prefix_socket_path() {
        let yaml = "cpus: 2\nnetworks:\n  - socket: /arbitrary/socket.sock\n";
        let result = validate_lima_yaml_shape(yaml, "", true);
        assert!(
            result.is_err(),
            "socket path outside /var/run/sandbox/vmnet/ must be rejected by shape validation"
        );
    }

    #[test]
    fn lima_yaml_rejects_traversal_socket_path() {
        let yaml =
            "cpus: 2\nnetworks:\n  - socket: /var/run/sandbox/vmnet/../../../tmp/evil.sock\n";
        let result = validate_lima_yaml_shape(yaml, "", true);
        assert!(
            result.is_err(),
            "socket path with '..' traversal must be rejected"
        );
    }

    #[test]
    fn lima_yaml_rejects_relative_socket_path() {
        let yaml = "cpus: 2\nnetworks:\n  - socket: relative/vmnet/slot-0.sock\n";
        let result = validate_lima_yaml_shape(yaml, "", true);
        assert!(
            result.is_err(),
            "relative socket path must be rejected by shape validation"
        );
    }

    // -----------------------------------------------------------------------
    // Validator round-trip: real daemon-rendered macOS template output
    //
    // These fixtures are derived from the actual output of
    // `LimaManager::generate_template` with `is_macos=true`. They serve as
    // ground truth: any change to the macOS template generation that breaks
    // these tests indicates a shape violation the agent would reject.
    // -----------------------------------------------------------------------

    /// Round-trip: the daemon's macOS sandbox VM template (slot 0, no workspace,
    /// operator uid == 1000) must pass `validate_lima_yaml_shape`.
    ///
    /// This is the canonical minimal rendered template. All other macOS template
    /// variants (different slots, operator-uid cloud-init, shared workspace) share
    /// the same shape-critical fields — only their provision scripts differ.
    #[test]
    fn validator_roundtrip_macos_template_slot0_no_workspace() {
        // This YAML mirrors the actual output of generate_template_macos for:
        //   session_id = "550e8400e29b", vmnet_slot = 0, operator_identity = None
        // Key shape invariants: vmType: "qemu" present, networks with one socket
        // entry in /var/run/sandbox/vmnet/, no mode key, no network (singular) key.
        let yaml = r#"# Auto-generated Lima template for macOS sandbox session 550e8400e29b
minimumLimaVersion: "2.0.0"

vmType: "qemu"

images:
- location: "https://cloud-images.ubuntu.com/releases/noble/release/ubuntu-24.04-server-cloudimg-arm64.img"
  arch: "aarch64"

cpus: 2
memory: "4GiB"
disk: "20GiB"

networks:
- socket: /var/run/sandbox/vmnet/slot-0.sock

mounts: []
portForwards: []

containerd:
  system: false
  user: false

user:
  name: "sandbox"
  home: "/home/sandbox"

provision:
- mode: system
  script: |
    #!/bin/bash
    hostnamectl set-hostname sandbox-550e8400e29b
"#;
        let result = validate_lima_yaml_shape(yaml, "sandbox-550e8400e29b", true);
        assert!(
            result.is_ok(),
            "canonical macOS template (slot 0) must pass shape validation; error: {:?}",
            result.err()
        );
    }

    /// Round-trip: macOS template with a non-zero slot index.
    #[test]
    fn validator_roundtrip_macos_template_slot3() {
        let yaml = r#"minimumLimaVersion: "2.0.0"
vmType: "qemu"
images:
- location: "https://cloud-images.ubuntu.com/releases/noble/release/ubuntu-24.04-server-cloudimg-arm64.img"
  arch: "aarch64"
cpus: 2
memory: "4GiB"
disk: "20GiB"
networks:
- socket: /var/run/sandbox/vmnet/slot-3.sock
mounts: []
portForwards: []
containerd:
  system: false
  user: false
user:
  name: "sandbox"
  home: "/home/sandbox"
"#;
        let result = validate_lima_yaml_shape(yaml, "", true);
        assert!(
            result.is_ok(),
            "macOS template with slot 3 must pass shape validation; error: {:?}",
            result.err()
        );
    }

    /// Round-trip: macOS template with a 9p shared workspace mount.
    /// The shape validator inspects vmType (must be qemu), networks, and socket
    /// paths — not the mounts section content.
    #[test]
    fn validator_roundtrip_macos_template_with_shared_workspace() {
        let yaml = r#"minimumLimaVersion: "2.0.0"
vmType: "qemu"
images:
- location: "https://cloud-images.ubuntu.com/releases/noble/release/ubuntu-24.04-server-cloudimg-arm64.img"
  arch: "aarch64"
cpus: 2
memory: "4GiB"
disk: "20GiB"
networks:
- socket: /var/run/sandbox/vmnet/slot-1.sock
mountType: "9p"
mounts:
- location: "/home/operator/project"
  mountPoint: "/workspace"
  writable: true
  9p:
    securityModel: mapped-xattr
    cache: mmap
portForwards: []
containerd:
  system: false
  user: false
user:
  name: "sandbox"
  home: "/home/sandbox"
"#;
        let result = validate_lima_yaml_shape(yaml, "", true);
        assert!(
            result.is_ok(),
            "macOS template with 9p shared workspace must pass shape validation; error: {:?}",
            result.err()
        );
    }

    // -----------------------------------------------------------------------
    // Class split: the session rule is applied to every session create
    //
    // The property these two guard is that VM class is selected by the op the
    // daemon invoked and by nothing else. They are written against the session
    // entry point specifically, because that is the side where a leak is
    // dangerous: a session VM permitted the gateway shape reaches more than one
    // L2 segment and routes around its own gateway.
    // -----------------------------------------------------------------------

    /// A four-NIC gateway-shaped template, as the daemon renders one.
    fn gateway_shaped_networks_yaml() -> String {
        "vmType: \"qemu\"\ncpus: 4\nnetworks:\n\
         \x20 - socket: /var/run/sandbox/vmnet/slot-0.sock\n    interface: lima0\n\
         \x20 - socket: /var/run/sandbox/vmnet/slot-1.sock\n    interface: lima1\n\
         \x20 - socket: /var/run/sandbox/vmnet/slot-2.sock\n    interface: lima2\n\
         \x20 - socket: /var/run/sandbox/vmnet/slot-3.sock\n    interface: lima3\n"
            .to_string()
    }

    /// A session create carrying two NIC entries is rejected — the single-NIC
    /// rule, which is what holds a session VM to one L2 segment.
    #[test]
    fn session_rule_rejects_two_network_entries() {
        let yaml = "vmType: \"qemu\"\nnetworks:\n\
                    \x20 - socket: /var/run/sandbox/vmnet/slot-0.sock\n\
                    \x20 - socket: /var/run/sandbox/vmnet/slot-1.sock\n";
        let err = validate_lima_yaml_shape(yaml, "", true)
            .expect_err("two NIC entries must be rejected on the session path");
        assert!(
            err.contains("exactly one socket_vmnet entry"),
            "rejection must come from the single-NIC rule, not incidentally from \
             some other check; got: {err:?}"
        );
    }

    /// A gateway-shaped *name* on the session path buys nothing: the session
    /// rule still applies, and a gateway-shaped template is still rejected.
    ///
    /// This is the half of the class split that a name-derived class selector
    /// would get wrong. The name is a daemon-supplied wire field; if it chose
    /// the rule, a compromised daemon would pick the multi-NIC rule for a
    /// session VM by spelling its name a particular way.
    #[test]
    fn session_rule_applies_to_a_gateway_shaped_name() {
        let yaml = gateway_shaped_networks_yaml();
        for name in [
            "sandboxd-gateway",
            "sandboxd-gateway-0",
            "sandboxd-gateway-501",
            "sandboxd-gateway-1000",
        ] {
            let yaml_with_name = format!("# vm: {name}\n{yaml}");
            let err = validate_lima_yaml_shape(&yaml_with_name, name, true).expect_err(
                "a gateway-shaped name on the session path must not obtain the gateway rule",
            );
            assert!(
                err.contains("exactly one socket_vmnet entry"),
                "{name}: rejection must come from the session single-NIC rule; got: {err:?}"
            );
        }
    }

    // -----------------------------------------------------------------------
    // Gateway-class lima.yaml shape validation
    // -----------------------------------------------------------------------

    /// The gateway template the daemon renders — the verbatim output of
    /// `sandbox_core::gateway_lima::generate_gateway_template(&[0, 1, 2, 3, 4,
    /// 5, 6, 7])`, the default 8-slot pool, captured on 2026-08-19.
    ///
    /// A copy rather than a call: this crate deliberately does not depend on
    /// `sandbox-core` (see `Cargo.toml`), which is why the pre-existing
    /// session-template round-trip fixtures above are copies too. It is kept
    /// whole, provisioning scripts and all, rather than trimmed to the
    /// shape-critical stanzas — the scripts are YAML block scalars containing
    /// `printf` lines full of `\n` escapes and `#` comments, and whether the
    /// parser survives them is part of what "the real template is accepted"
    /// means. `sandbox_core::gateway_lima`'s own
    /// `generated_gateway_template_satisfies_the_agent_gateway_rule` asserts
    /// the live generator still emits a template of this shape, so drift is
    /// caught there rather than silently invalidating this fixture.
    const GATEWAY_TEMPLATE: &str = r##"vmType: "qemu"
minimumLimaVersion: "1.2.0"

images:
  - location: "https://cloud-images.ubuntu.com/releases/noble/release/ubuntu-24.04-server-cloudimg-arm64.img"
    arch: aarch64

cpus: 2
memory: "2GiB"
disk: "20GiB"

# N socket_vmnet NICs — one per pool slot.
# Count = max_macos_sessions (default 8). Fixed at instance creation.
networks:
  - socket: /var/run/sandbox/vmnet/slot-0.sock
    interface: lima0
  - socket: /var/run/sandbox/vmnet/slot-1.sock
    interface: lima1
  - socket: /var/run/sandbox/vmnet/slot-2.sock
    interface: lima2
  - socket: /var/run/sandbox/vmnet/slot-3.sock
    interface: lima3
  - socket: /var/run/sandbox/vmnet/slot-4.sock
    interface: lima4
  - socket: /var/run/sandbox/vmnet/slot-5.sock
    interface: lima5
  - socket: /var/run/sandbox/vmnet/slot-6.sock
    interface: lima6
  - socket: /var/run/sandbox/vmnet/slot-7.sock
    interface: lima7

# Expose the guest Docker socket to the macOS host via Lima forwarding.
portForwards:
  - guestSocket: "/var/run/docker.sock"
    hostSocket: "{{.Dir}}/gateway-docker.sock"

# 9p mount for lite-mode shared: workspaces.
# The shared root is exposed read-write at the same absolute path so the
# host->VM path translation is an identity. Per-session shared: paths must
# fall under this root (validated at session-create time).
# NOTE: reads are performed as _sandboxd (the gateway VM user), not the
# operator. Sources outside TCC-protected dirs work without consent.
mountType: "9p"
mounts:
  - location: "/tmp/sandbox-shared"
    writable: true
    9p:
      securityModel: "mapped-xattr"
      cache: "mmap"

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
      # This grant is redundant, and is kept deliberately. It is redundant
      # because the VM's login user already holds `ALL=(ALL) NOPASSWD:ALL`
      # from the distro image's own cloud-init — measured, not assumed — so
      # every sudo in this VM is already passwordless and this fragment
      # authorizes nothing that was not authorized without it.
      #
      # It is kept because it is the only place the *intended* privilege is
      # written down. If the base image ever tightens its default (a distro
      # change nothing here controls), this fragment is what keeps the one
      # sudo the daemon actually needs working, and the route-install path
      # does not silently start prompting. Removing it would trade a line of
      # documentation for a dependency on someone else's default.
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
      sysctl -w net.ipv6.conf.lima0.disable_ipv6=1
      sysctl -w net.ipv6.conf.lima1.disable_ipv6=1
      sysctl -w net.ipv6.conf.lima2.disable_ipv6=1
      sysctl -w net.ipv6.conf.lima3.disable_ipv6=1
      sysctl -w net.ipv6.conf.lima4.disable_ipv6=1
      sysctl -w net.ipv6.conf.lima5.disable_ipv6=1
      sysctl -w net.ipv6.conf.lima6.disable_ipv6=1
      sysctl -w net.ipv6.conf.lima7.disable_ipv6=1
      printf 'network:\n  ethernets:\n' > /etc/netplan/99-sandbox-vmnet.yaml
      printf '    lima0:\n      dhcp4: no\n      optional: true\n' >> /etc/netplan/99-sandbox-vmnet.yaml
      printf '    lima1:\n      dhcp4: no\n      optional: true\n' >> /etc/netplan/99-sandbox-vmnet.yaml
      printf '    lima2:\n      dhcp4: no\n      optional: true\n' >> /etc/netplan/99-sandbox-vmnet.yaml
      printf '    lima3:\n      dhcp4: no\n      optional: true\n' >> /etc/netplan/99-sandbox-vmnet.yaml
      printf '    lima4:\n      dhcp4: no\n      optional: true\n' >> /etc/netplan/99-sandbox-vmnet.yaml
      printf '    lima5:\n      dhcp4: no\n      optional: true\n' >> /etc/netplan/99-sandbox-vmnet.yaml
      printf '    lima6:\n      dhcp4: no\n      optional: true\n' >> /etc/netplan/99-sandbox-vmnet.yaml
      printf '    lima7:\n      dhcp4: no\n      optional: true\n' >> /etc/netplan/99-sandbox-vmnet.yaml
      chmod 0644 /etc/netplan/99-sandbox-vmnet.yaml
      netplan apply
"##;

    /// The whole point of the split: a legitimate 8-NIC gateway template passes
    /// every check on the gateway path.
    ///
    /// "Every check" is load-bearing. The NIC-count rule is only the first one
    /// a gateway template trips on the session path; behind it sit the
    /// entry-shape rules and, at the end, the session path's expected-VM-name
    /// containment check — which a Lima template can never satisfy, since a
    /// template carries no instance name in its body. The gateway path has no
    /// name to check against and so does not make that check at all.
    #[test]
    fn gateway_rule_accepts_the_real_gateway_template() {
        let result = validate_gateway_lima_yaml_shape(GATEWAY_TEMPLATE);
        assert!(
            result.is_ok(),
            "the daemon's rendered gateway template must pass the gateway-class \
             validator; error: {:?}",
            result.err()
        );
    }

    /// The same template is still rejected on the session path — the split adds
    /// a class, it does not widen the existing one.
    #[test]
    fn session_rule_still_rejects_the_real_gateway_template() {
        let err = validate_lima_yaml_shape(GATEWAY_TEMPLATE, "", true)
            .expect_err("the gateway template must not pass the session-class validator");
        assert!(
            err.contains("exactly one socket_vmnet entry"),
            "rejection must come from the session single-NIC rule; got: {err:?}"
        );
    }

    /// An interface name pinned onto a socket belonging to a different slot is
    /// rejected.
    ///
    /// Lima accepts this silently, and the in-VM NIC name is what selects the
    /// macvlan parent — so the result is sessions parented on another slot's L2
    /// segment, with nothing anywhere reporting a problem.
    #[test]
    fn gateway_rule_rejects_interface_slot_mismatch() {
        let yaml = "vmType: \"qemu\"\nnetworks:\n\
                    \x20 - socket: /var/run/sandbox/vmnet/slot-7.sock\n    interface: lima2\n";
        let err = validate_gateway_lima_yaml_shape(yaml)
            .expect_err("interface pinned to the wrong slot must be rejected");
        assert!(
            err.contains("slot 7") && err.contains("lima7"),
            "the rejection must name the slot the socket belongs to and the \
             interface that slot requires; got: {err:?}"
        );
    }

    /// A session-shaped entry (`socket:` only, no `interface:`) is rejected on
    /// the gateway path. Without the pin Lima names NICs by array position, so
    /// a non-contiguous slot set lands on the wrong segments.
    #[test]
    fn gateway_rule_rejects_entry_without_interface() {
        let yaml = "vmType: \"qemu\"\nnetworks:\n\
                    \x20 - socket: /var/run/sandbox/vmnet/slot-0.sock\n";
        let err = validate_gateway_lima_yaml_shape(yaml)
            .expect_err("a gateway NIC entry without interface: must be rejected");
        assert!(
            err.contains("interface"),
            "rejection must name the missing interface key; got: {err:?}"
        );
    }

    /// Two entries naming the same slot are rejected.
    #[test]
    fn gateway_rule_rejects_duplicate_slot() {
        let yaml = "vmType: \"qemu\"\nnetworks:\n\
                    \x20 - socket: /var/run/sandbox/vmnet/slot-3.sock\n    interface: lima3\n\
                    \x20 - socket: /var/run/sandbox/vmnet/slot-3.sock\n    interface: lima3\n";
        let err = validate_gateway_lima_yaml_shape(yaml)
            .expect_err("the same slot attached twice must be rejected");
        assert!(
            err.contains("repeats slot 3"),
            "rejection must name the repeated slot; got: {err:?}"
        );
    }

    /// A non-canonical socket spelling is rejected even though it names a real
    /// directory. `slot-04.sock` is not a path the pool ever creates, and an
    /// inexact parse would make it agree with `lima4` while socket_vmnet has
    /// nothing listening on it.
    #[test]
    fn gateway_rule_rejects_non_canonical_socket_spelling() {
        for socket in [
            "/var/run/sandbox/vmnet/slot-04.sock",
            "/var/run/sandbox/vmnet/slot-+4.sock",
            "/var/run/sandbox/vmnet/slot-4.sock.bak",
            "/var/run/sandbox/vmnet/slot-.sock",
        ] {
            let yaml = format!(
                "vmType: \"qemu\"\nnetworks:\n  - socket: {socket}\n    interface: lima4\n"
            );
            assert!(
                validate_gateway_lima_yaml_shape(&yaml).is_err(),
                "non-canonical socket spelling {socket:?} must be rejected"
            );
        }
    }

    /// A socket outside the pool's directory is rejected, exactly as on the
    /// session path — this is where a VM would be attached to a socket_vmnet
    /// instance sandboxd does not run.
    #[test]
    fn gateway_rule_rejects_socket_outside_the_pool_directory() {
        for socket in [
            "/tmp/slot-0.sock",
            "/var/run/sandbox/vmnet/../evil/slot-0.sock",
            "slot-0.sock",
        ] {
            let yaml = format!(
                "vmType: \"qemu\"\nnetworks:\n  - socket: {socket}\n    interface: lima0\n"
            );
            assert!(
                validate_gateway_lima_yaml_shape(&yaml).is_err(),
                "socket outside the pool directory {socket:?} must be rejected"
            );
        }
    }

    /// `mode:` names a Lima-managed network and is rejected on the gateway path
    /// as it is on the session path — including in flow style, which a
    /// line-based check would miss.
    #[test]
    fn gateway_rule_rejects_mode_key() {
        for yaml in [
            "vmType: \"qemu\"\nnetworks:\n  - socket: /var/run/sandbox/vmnet/slot-0.sock\n    \
             interface: lima0\n    mode: shared\n",
            "vmType: \"qemu\"\nnetworks: [{socket: /var/run/sandbox/vmnet/slot-0.sock, \
             interface: lima0, mode: shared}]\n",
        ] {
            let err = validate_gateway_lima_yaml_shape(yaml)
                .expect_err("a NIC entry with mode: must be rejected");
            assert!(
                err.contains("mode"),
                "rejection must name the mode key; got: {err:?}"
            );
        }
    }

    /// Any key beyond `socket:` and `interface:` is rejected — an unreviewed
    /// key could switch on Lima networking behaviour nobody looked at.
    #[test]
    fn gateway_rule_rejects_extra_keys() {
        let yaml = "vmType: \"qemu\"\nnetworks:\n\
                    \x20 - socket: /var/run/sandbox/vmnet/slot-0.sock\n\
                    \x20   interface: lima0\n    macAddress: \"52:54:00:12:34:56\"\n";
        let err =
            validate_gateway_lima_yaml_shape(yaml).expect_err("an extra NIC key must be rejected");
        assert!(
            err.contains("exactly two keys"),
            "rejection must come from the key-set rule; got: {err:?}"
        );
    }

    /// A gateway VM with no slot NICs terminates no session segment; an absent
    /// or empty `networks:` is rejected rather than treated as "nothing to
    /// check".
    #[test]
    fn gateway_rule_rejects_absent_or_empty_networks() {
        for yaml in [
            "vmType: \"qemu\"\ncpus: 2\n",
            "vmType: \"qemu\"\nnetworks: []\n",
        ] {
            let err = validate_gateway_lima_yaml_shape(yaml)
                .expect_err("a gateway template with no NIC entries must be rejected");
            assert!(
                err.contains("networks"),
                "rejection must name the networks key; got: {err:?}"
            );
        }
    }

    /// The shared prelude still applies on the gateway path: a non-qemu (or
    /// absent) `vmType` is rejected. On macOS an unset `vmType` means VZ, which
    /// cannot attach socket_vmnet at all.
    #[test]
    fn gateway_rule_rejects_non_qemu_vmtype() {
        for yaml in [
            "vmType: \"vz\"\nnetworks:\n  - socket: /var/run/sandbox/vmnet/slot-0.sock\n    \
             interface: lima0\n",
            "networks:\n  - socket: /var/run/sandbox/vmnet/slot-0.sock\n    interface: lima0\n",
        ] {
            let err = validate_gateway_lima_yaml_shape(yaml)
                .expect_err("a non-qemu vmType must be rejected on the gateway path too");
            assert!(
                err.contains("vmType"),
                "rejection must name vmType; got: {err:?}"
            );
        }
    }

    /// The singular `network:` alias is rejected on the gateway path too — the
    /// plural key must be the only code path on both classes.
    #[test]
    fn gateway_rule_rejects_singular_network_key() {
        let yaml = "vmType: \"qemu\"\nnetwork:\n  - socket: /var/run/sandbox/vmnet/slot-0.sock\n\
                    networks:\n  - socket: /var/run/sandbox/vmnet/slot-0.sock\n    interface: lima0\n";
        let err = validate_gateway_lima_yaml_shape(yaml)
            .expect_err("a singular network: key must be rejected");
        assert!(
            err.contains("'network' key"),
            "rejection must name the singular network key; got: {err:?}"
        );
    }

    /// A session-class template on the gateway path is rejected. Together with
    /// `session_rule_still_rejects_the_real_gateway_template` this makes the two
    /// rules mutually exclusive by entry shape: neither class's template is
    /// accepted by the other class's rule.
    #[test]
    fn gateway_rule_rejects_a_session_template() {
        let yaml = "vmType: \"qemu\"\ncpus: 2\nnetworks:\n\
                    \x20 - socket: /var/run/sandbox/vmnet/slot-0.sock\n";
        assert!(
            validate_gateway_lima_yaml_shape(yaml).is_err(),
            "a session template must not pass the gateway-class validator"
        );
    }

    /// The slot parser round-trips exactly, in both directions.
    #[test]
    fn slot_socket_path_round_trips_exactly() {
        for slot in [0u16, 1, 7, 8, 63, 1000, u16::MAX] {
            let path = vmnet_slot_socket_path(slot);
            assert_eq!(
                slot_from_vmnet_socket_path(&path),
                Some(slot),
                "{path} must parse back to slot {slot}"
            );
        }
        for path in [
            "/var/run/sandbox/vmnet/slot-04.sock",
            "/var/run/sandbox/vmnet/slot-+4.sock",
            "/var/run/sandbox/vmnet/slot- 4.sock",
            "/var/run/sandbox/vmnet/slot-65536.sock",
            "/var/run/sandbox/vmnet/slot-.sock",
            "/var/run/sandbox/vmnet/slot-0.sock/",
            "/tmp/slot-0.sock",
            "slot-0.sock",
        ] {
            assert_eq!(
                slot_from_vmnet_socket_path(path),
                None,
                "{path} must not parse to a slot"
            );
        }
    }

    // -----------------------------------------------------------------------
    // Docker op validation
    // -----------------------------------------------------------------------

    mod docker {
        use super::super::*;
        use crate::protocol::{
            ContainerCommand, ContainerCreateSpec, DockerOp, EndpointGatewayPriority, EnvoyStat,
            FileDelivery, GatewayComponent, GatewayFile, InspectFlag, InspectFormat,
            NetworkCreateSpec, NetworkDriver, NetworkOption, NftTable, RemoveForce, StagedImage,
            StdinCommand, WorkspaceBindSpec,
        };

        fn create_spec() -> ContainerCreateSpec {
            ContainerCreateSpec {
                session_id: "abc123def456".to_string(),
                docker_network: "sandbox-net-abc123def456".to_string(),
                container_ip: "10.209.0.3".to_string(),
                gateway_ip: "10.209.0.2".to_string(),
                image_tag: "sandboxd-lite:0.1.10".to_string(),
                user_uid: 501,
                user_gid: 20,
                memory_mb: 2048,
                cpus: 2.0,
                owner_pool: Some("10.209.0.0/20".to_string()),
                workspace_bind: None,
                ca_host_path: None,
                ssh_host_dir: None,
                guest_bind_source: None,
            }
        }

        fn network_spec() -> NetworkCreateSpec {
            NetworkCreateSpec {
                name: "sandbox-net-abc123def456".to_string(),
                driver: NetworkDriver::Bridge,
                subnet: Some("10.209.0.0/28".to_string()),
                gateway: None,
                session_id: Some("abc123def456".to_string()),
                owner_pool: Some("10.209.0.0/20".to_string()),
                options: vec![
                    NetworkOption::BridgeName {
                        interface: "sb-abc123def456".to_string(),
                    },
                    NetworkOption::BridgeMasquerade { enabled: false },
                ],
            }
        }

        /// Every op the daemon can send, in its well-formed shape, with
        /// realistic field values.
        ///
        /// This is the mirror of `broker.rs`'s `docker_wire::every_op`, which
        /// holds the same set on the sending side. Keeping the acceptance
        /// check here — rather than importing this validator into the daemon's
        /// target — is what stops the whole validation suite from running
        /// twice. The two lists are held in step by the count assertion below,
        /// which is the same number on both sides.
        fn every_op() -> Vec<DockerOp> {
            vec![
                DockerOp::ContainerCreate {
                    spec: create_spec(),
                },
                DockerOp::ContainerStart {
                    name: "sandbox-abc123def456".to_string(),
                },
                DockerOp::ContainerStop {
                    name: "sandbox-abc123def456".to_string(),
                    grace_secs: 10,
                    long_flag: false,
                },
                DockerOp::ContainerRestart {
                    name: "sandbox-abc123def456".to_string(),
                },
                DockerOp::ContainerRemove {
                    name: "sandbox-abc123def456".to_string(),
                    force: RemoveForce::Short,
                },
                DockerOp::ContainerInspect {
                    name: "sandbox-abc123def456".to_string(),
                    format: InspectFormat::StatePid,
                    flag: InspectFlag::Short,
                },
                DockerOp::ContainerList {
                    name_prefix: "sandbox-".to_string(),
                    owner_pool: Some("10.209.0.0/20".to_string()),
                },
                DockerOp::ContainerExec {
                    name: "sandbox-abc123def456".to_string(),
                    command: ContainerCommand::ComponentProbe {
                        component: GatewayComponent::Envoy,
                    },
                },
                DockerOp::HomeVolumeChown {
                    session_id: "abc123def456".to_string(),
                    image_tag: "sandboxd-lite:0.1.10".to_string(),
                    operator_uid: 501,
                    operator_gid: 20,
                },
                DockerOp::GatewayContainerRun {
                    session_id: "abc123def456".to_string(),
                    image_tag: "sandbox-gateway:0.1.10".to_string(),
                    network: "sandboxd-egress".to_string(),
                    owner_pool: Some("10.209.0.0/20".to_string()),
                    coredns_upstream: Some("8.8.8.8 1.1.1.1".to_string()),
                },
                DockerOp::NetworkCreate {
                    spec: network_spec(),
                },
                DockerOp::NetworkRemove {
                    name: "sandbox-net-abc123def456".to_string(),
                },
                DockerOp::NetworkInspect {
                    name: "sandbox-net-abc123def456".to_string(),
                },
                DockerOp::NetworkConnect {
                    network: "sandbox-net-abc123def456".to_string(),
                    container: "sandbox-gw-abc123def456".to_string(),
                    ip: Some("10.209.0.2".to_string()),
                    gateway_priority: EndpointGatewayPriority::NeverDefaultGateway,
                },
                DockerOp::NetworkList {
                    name_prefix: "sandbox-net-".to_string(),
                    owner_pool: None,
                },
                DockerOp::VolumeCreate {
                    name: "sandbox-home-abc123def456".to_string(),
                    session_id: Some("abc123def456".to_string()),
                    owner_pool: Some("10.209.0.0/20".to_string()),
                },
                DockerOp::VolumeRemove {
                    name: "sandbox-home-abc123def456".to_string(),
                },
                DockerOp::VolumeList {
                    name_prefix: "sandbox-home-".to_string(),
                    owner_pool: None,
                },
                DockerOp::ImageInspect {
                    tag: "sandbox-gateway:0.1.10".to_string(),
                },
                DockerOp::ImageLoad {
                    image: StagedImage::Gateway,
                },
                DockerOp::DaemonInfo,
                DockerOp::ContainerExecStdin {
                    name: "sandbox-gw-abc123def456".to_string(),
                    command: StdinCommand::WriteGatewayFile {
                        file: GatewayFile::CorednsPolicy,
                        delivery: FileDelivery::Replace,
                    },
                    body: "example.com\n".to_string(),
                },
            ]
        }

        /// The whole op set, in its well-formed shape, is accepted. Written as
        /// one list rather than 21 tests so a variant added without a
        /// validation arm shows up as a missing entry here.
        #[test]
        fn every_well_formed_op_is_accepted() {
            let ops = every_op();
            assert_eq!(ops.len(), 22, "every DockerOp variant must be covered here");
            for op in ops {
                assert!(
                    validate_docker_op(&op).is_ok(),
                    "well-formed op rejected: {op:?} → {:?}",
                    validate_docker_op(&op).err()
                );
            }
        }

        /// A name that starts with `-` would be read by docker as a flag, not
        /// as an object name. Every op that names an object must refuse it —
        /// checked across the whole family rather than at one call site,
        /// because one unguarded arm is all it takes.
        #[test]
        fn no_op_accepts_a_name_that_docker_would_read_as_a_flag() {
            let flaggy = "--privileged".to_string();
            let ops = vec![
                DockerOp::ContainerStart {
                    name: flaggy.clone(),
                },
                DockerOp::ContainerRestart {
                    name: flaggy.clone(),
                },
                DockerOp::ContainerRemove {
                    name: flaggy.clone(),
                    force: RemoveForce::Short,
                },
                DockerOp::ContainerStop {
                    name: flaggy.clone(),
                    grace_secs: 1,
                    long_flag: false,
                },
                DockerOp::ContainerInspect {
                    name: flaggy.clone(),
                    format: InspectFormat::StatePid,
                    flag: InspectFlag::Short,
                },
                DockerOp::ContainerExec {
                    name: flaggy.clone(),
                    command: ContainerCommand::GatewayHealthcheck,
                },
                DockerOp::NetworkRemove {
                    name: flaggy.clone(),
                },
                DockerOp::NetworkInspect {
                    name: flaggy.clone(),
                },
                DockerOp::NetworkConnect {
                    network: flaggy.clone(),
                    container: "sandbox-abc".to_string(),
                    ip: None,
                    gateway_priority: EndpointGatewayPriority::Default,
                },
                DockerOp::VolumeRemove {
                    name: flaggy.clone(),
                },
                DockerOp::ContainerList {
                    name_prefix: flaggy.clone(),
                    owner_pool: None,
                },
                DockerOp::NetworkList {
                    name_prefix: flaggy.clone(),
                    owner_pool: None,
                },
                DockerOp::VolumeList {
                    name_prefix: flaggy.clone(),
                    owner_pool: None,
                },
            ];
            for op in ops {
                assert!(
                    validate_docker_op(&op).is_err(),
                    "a leading-dash name must be refused: {op:?}"
                );
            }
        }

        /// Docker reads `,` and `=` as option-list syntax inside a `--mount`
        /// value, so a path containing either would add mount options nobody
        /// wrote — `,bind-propagation=rshared` being the interesting one.
        #[test]
        fn create_refuses_option_list_syntax_in_every_mount_path() {
            for bad in ["/tmp/a,bind-propagation=rshared", "/tmp/a=b"] {
                let mut spec = create_spec();
                spec.workspace_bind = Some(WorkspaceBindSpec {
                    host_path: bad.to_string(),
                    guest_path: "/home/sandbox/workspace".to_string(),
                });
                assert!(
                    validate_docker_op(&DockerOp::ContainerCreate { spec }).is_err(),
                    "workspace host_path {bad:?} must be refused"
                );

                let mut spec = create_spec();
                spec.ca_host_path = Some(bad.to_string());
                assert!(
                    validate_docker_op(&DockerOp::ContainerCreate { spec }).is_err(),
                    "ca_host_path {bad:?} must be refused"
                );

                let mut spec = create_spec();
                spec.ssh_host_dir = Some(bad.to_string());
                assert!(
                    validate_docker_op(&DockerOp::ContainerCreate { spec }).is_err(),
                    "ssh_host_dir {bad:?} must be refused"
                );
            }
        }

        /// Every path in a create spec must be absolute and free of `..`. A
        /// relative or traversing bind source is a mount of something other
        /// than what the daemon meant.
        #[test]
        fn create_refuses_relative_and_traversing_paths() {
            for bad in ["relative/path", "/var/lib/../../etc/shadow"] {
                let mut spec = create_spec();
                spec.ca_host_path = Some(bad.to_string());
                assert!(
                    validate_docker_op(&DockerOp::ContainerCreate { spec }).is_err(),
                    "ca_host_path {bad:?} must be refused"
                );
            }
        }

        /// `mkdir -p` runs inside the container, so its path is not confined
        /// to the agent's own tree — but it must still be a path, not a
        /// relative fragment or a traversal.
        #[test]
        fn exec_mkdir_requires_an_absolute_path_without_traversal() {
            for bad in ["workspace", "/home/sandbox/../../etc"] {
                let op = DockerOp::ContainerExec {
                    name: "sandbox-abc123def456".to_string(),
                    command: ContainerCommand::MakeDirectory {
                        path: bad.to_string(),
                    },
                };
                assert!(
                    validate_docker_op(&op).is_err(),
                    "mkdir path {bad:?} must be refused"
                );
            }
        }

        /// The resolver list lands in a `--env` assignment. Anything that is
        /// not an address could smuggle a second assignment past the flag.
        #[test]
        fn gateway_run_refuses_a_resolver_list_that_is_not_addresses() {
            for bad in [
                "8.8.8.8 evil",
                "8.8.8.8  1.1.1.1",
                "",
                "1.2.3.4 SANDBOX_OTHER=x",
            ] {
                let op = DockerOp::GatewayContainerRun {
                    session_id: "abc123def456".to_string(),
                    image_tag: "sandbox-gateway:0.1.10".to_string(),
                    network: "sandboxd-egress".to_string(),
                    owner_pool: None,
                    coredns_upstream: Some(bad.to_string()),
                };
                assert!(
                    validate_docker_op(&op).is_err(),
                    "resolver list {bad:?} must be refused"
                );
            }
        }

        /// The owner-pool label is what the reaper filters on. A malformed
        /// value would produce a label nothing matches, leaving the resource
        /// unattributable to any daemon.
        #[test]
        fn owner_pool_must_be_a_cidr() {
            let op = DockerOp::ContainerList {
                name_prefix: "sandbox-".to_string(),
                owner_pool: Some("not-a-cidr".to_string()),
            };
            assert!(validate_docker_op(&op).is_err());

            let mut spec = create_spec();
            spec.owner_pool = Some("10.209.0.0/33".to_string());
            assert!(validate_docker_op(&DockerOp::ContainerCreate { spec }).is_err());
        }

        /// The chown init container exists to hand the volume to the operator.
        /// uid 0 would hand it to root, which is the opposite.
        #[test]
        fn home_volume_chown_refuses_uid_zero() {
            let op = DockerOp::HomeVolumeChown {
                session_id: "abc123def456".to_string(),
                image_tag: "sandboxd-lite:0.1.10".to_string(),
                operator_uid: 0,
                operator_gid: 20,
            };
            assert!(validate_docker_op(&op).is_err());
        }

        /// Addresses are parsed, not pattern-matched: a value docker would
        /// reject anyway should not reach it, and one that looks like an
        /// address but is not must not pass.
        #[test]
        fn addresses_must_parse() {
            for bad in ["10.209.0.256", "10.209.0", "not-an-ip", ""] {
                let op = DockerOp::NetworkConnect {
                    network: "sandbox-net-abc".to_string(),
                    container: "sandbox-gw-abc".to_string(),
                    ip: Some(bad.to_string()),
                    gateway_priority: EndpointGatewayPriority::Default,
                };
                assert!(
                    validate_docker_op(&op).is_err(),
                    "address {bad:?} must be refused"
                );
            }
        }

        /// A bridge interface name is bounded at 15 characters by the kernel;
        /// a longer one silently truncates and collides.
        #[test]
        fn network_options_are_validated() {
            let mut spec = network_spec();
            spec.options = vec![NetworkOption::BridgeName {
                interface: "sb-this-name-is-far-too-long".to_string(),
            }];
            assert!(validate_docker_op(&DockerOp::NetworkCreate { spec }).is_err());

            let mut spec = network_spec();
            spec.options = vec![NetworkOption::MacvlanParent {
                parent: "eth0; rm -rf /".to_string(),
            }];
            assert!(validate_docker_op(&DockerOp::NetworkCreate { spec }).is_err());
        }

        /// Resource ceilings are checked because a nonsense value is a
        /// daemon-side bug worth surfacing as a rejection rather than as a
        /// docker error minutes later.
        #[test]
        fn create_refuses_unusable_resource_ceilings() {
            let mut spec = create_spec();
            spec.cpus = 0.0;
            assert!(validate_docker_op(&DockerOp::ContainerCreate { spec }).is_err());

            let mut spec = create_spec();
            spec.cpus = f64::NAN;
            assert!(validate_docker_op(&DockerOp::ContainerCreate { spec }).is_err());

            let mut spec = create_spec();
            spec.memory_mb = 0;
            assert!(validate_docker_op(&DockerOp::ContainerCreate { spec }).is_err());
        }

        /// The two ops that carry nothing are accepted unconditionally —
        /// stated as a test so "it has no validation" is a recorded decision
        /// rather than an omission.
        #[test]
        fn the_two_argument_free_ops_carry_nothing_to_reject() {
            assert!(validate_docker_op(&DockerOp::DaemonInfo).is_ok());
            assert!(
                validate_docker_op(&DockerOp::ImageLoad {
                    image: StagedImage::Lite
                })
                .is_ok()
            );
        }

        // -- Egress-plane writes ---------------------------------------------

        fn write_op(file: GatewayFile, body: &str) -> DockerOp {
            DockerOp::ContainerExecStdin {
                name: "sandbox-gw-abc123def456".to_string(),
                command: StdinCommand::WriteGatewayFile {
                    file,
                    delivery: FileDelivery::Replace,
                },
                body: body.to_string(),
            }
        }

        /// Every writable artifact is writable, and the one file another
        /// process owns is refused. Read access does not imply write access,
        /// and this is where that stops being a convention.
        #[test]
        fn a_write_to_a_read_only_artifact_is_refused() {
            for file in [
                GatewayFile::CorednsPolicy,
                GatewayFile::MitmproxyPolicy,
                GatewayFile::MitmproxyCaKey,
                GatewayFile::MitmproxyCaCert,
                GatewayFile::EnvoyBootstrap,
                GatewayFile::EnvoyListener,
            ] {
                assert!(
                    validate_docker_op(&write_op(file, "x")).is_ok(),
                    "{file:?} must be writable"
                );
            }
            let err = validate_docker_op(&write_op(GatewayFile::CorednsResolved, "x"))
                .expect_err("CoreDNS owns its resolved-address report");
            assert!(err.contains("read-only"), "{err}");

            // …and it is still readable, which is the point of the split.
            assert!(
                validate_docker_op(&DockerOp::ContainerExec {
                    name: "sandbox-gw-abc123def456".to_string(),
                    command: ContainerCommand::ReadGatewayFile {
                        file: GatewayFile::CorednsResolved,
                    },
                })
                .is_ok()
            );
        }

        /// Every destination the write op can name is a plain absolute path
        /// with nothing a shell would re-read. This is the check the
        /// replaced site made with a `debug_assert!` — which is to say, not
        /// in the build that ships.
        #[test]
        fn every_destination_survives_shell_interpolation() {
            for file in sandbox_docker_argv::gateway::GatewayFile::ALL {
                validate_gateway_file_path(*file)
                    .unwrap_or_else(|e| panic!("{} is unfit to interpolate: {e}", file.as_str()));
            }
        }

        /// The artifact itself is not second-guessed. A ruleset or a policy
        /// file containing quotes, newlines, `$(…)` and non-ASCII is
        /// ordinary content, and refusing it would break real policies while
        /// protecting nothing — the body never reaches a shell.
        #[test]
        fn a_hostile_looking_artifact_is_still_valid_content() {
            let body = "'; rm -rf / #\n$(id)\n`id`\n\"quoted\" — ünïcode\n";
            assert!(validate_docker_op(&write_op(GatewayFile::CorednsPolicy, body)).is_ok());
            assert!(
                validate_docker_op(&DockerOp::ContainerExecStdin {
                    name: "sandbox-gw-abc123def456".to_string(),
                    command: StdinCommand::ApplyNftRuleset,
                    body: body.to_string(),
                })
                .is_ok()
            );
        }

        /// The size ceiling refuses with a reason rather than as an
        /// allocation. It sits far above any artifact the generators
        /// produce, so a real policy never meets it.
        #[test]
        fn an_oversized_artifact_is_refused_with_a_reason() {
            let body = "x".repeat(MAX_GATEWAY_ARTIFACT_BYTES + 1);
            let err = validate_docker_op(&write_op(GatewayFile::CorednsPolicy, &body))
                .expect_err("an artifact over the ceiling must be refused");
            assert!(err.contains("ceiling"), "{err}");

            // A realistic multi-KB artifact is nowhere near it.
            let realistic = "table inet sandbox_dnat { }\n".repeat(4_000);
            assert!(realistic.len() > 100_000);
            assert!(validate_docker_op(&write_op(GatewayFile::CorednsPolicy, &realistic)).is_ok());
        }

        /// The stdin-fed op names a container like every other op, and a
        /// container name docker would read as a flag is refused there too.
        #[test]
        fn a_stdin_fed_op_still_validates_its_container() {
            assert!(
                validate_docker_op(&DockerOp::ContainerExecStdin {
                    name: "--privileged".to_string(),
                    command: StdinCommand::ApplyNftRuleset,
                    body: "x".to_string(),
                })
                .is_err()
            );
        }

        /// The three read commands carry enums and nothing else, so there is
        /// nothing in them for a caller to control. Stated as a test so the
        /// absence of validation is a recorded decision.
        #[test]
        fn the_policy_plane_reads_carry_nothing_to_reject() {
            for command in [
                ContainerCommand::ReadGatewayFile {
                    file: GatewayFile::EnvoyBootstrap,
                },
                ContainerCommand::ListNftTable {
                    table: NftTable::SandboxPolicy,
                },
                ContainerCommand::EnvoyStat {
                    stat: EnvoyStat::LdsCounters,
                },
                ContainerCommand::EnvoyStat {
                    stat: EnvoyStat::ActiveListeners,
                },
            ] {
                assert!(
                    validate_docker_op(&DockerOp::ContainerExec {
                        name: "sandbox-gw-abc123def456".to_string(),
                        command,
                    })
                    .is_ok()
                );
            }
        }
    }

    // -----------------------------------------------------------------------
    // In-VM op validation
    // -----------------------------------------------------------------------

    mod in_vm {
        use super::super::*;
        use crate::protocol::{
            InVmOp, InVmTransferSource, LiteStageFile, in_vm_shell_steps, in_vm_stdin_body,
            in_vm_transfer,
        };

        /// Every in-VM op the daemon can send, in its well-formed shape.
        ///
        /// The mirror of `broker.rs`'s `in_vm_wire::every_op`, held in step by
        /// the count assertion below — the same number on both sides. Same
        /// arrangement, and same reason, as the Docker set above.
        fn every_op() -> Vec<InVmOp> {
            vec![
                InVmOp::DockerReady,
                InVmOp::LinkShowJson,
                InVmOp::ApplyNftBaseline {
                    ruleset: "table inet sandbox_eth0 {\n  chain out { drop }\n}\n".to_string(),
                },
                InVmOp::RouteHelperProbe,
                InVmOp::RouteHelperMakeInstallDir,
                InVmOp::RouteHelperStage,
                InVmOp::RouteHelperInstall,
                InVmOp::RouteHelperSetcap,
                InVmOp::LiteStageCreate {
                    session_id: "abc123def456".to_string(),
                },
                InVmOp::LiteStageWrite {
                    session_id: "abc123def456".to_string(),
                    file: LiteStageFile::CertPem,
                    body: "-----BEGIN CERTIFICATE-----\nMIIB\n".to_string(),
                },
                InVmOp::LiteStageRemove {
                    session_id: "abc123def456".to_string(),
                },
                InVmOp::InstallContainerRoute {
                    container_pid: 4242,
                    gateway_ip: std::net::Ipv4Addr::new(10, 42, 7, 2),
                },
            ]
        }

        #[test]
        fn every_well_formed_op_is_accepted() {
            let ops = every_op();
            assert_eq!(ops.len(), 12, "every InVmOp variant must be covered here");
            for op in ops {
                assert!(
                    validate_in_vm_op(&op).is_ok(),
                    "well-formed op rejected: {op:?} → {:?}",
                    validate_in_vm_op(&op).err()
                );
            }
        }

        /// The session identifier is joined onto a constant root to name a
        /// directory that gets `rm -rf`'d. A traversal, an absolute path or a
        /// bare `..` would move that `rm -rf` somewhere else inside the VM —
        /// so every op carrying one must refuse all three, not just the op
        /// that does the removing.
        #[test]
        fn no_lite_stage_op_accepts_a_session_id_that_escapes_the_stage_root() {
            for bad in [
                "../../etc",
                "..",
                "/",
                "abc/../..",
                "abc/def",
                "a b",
                "",
                "-rf",
            ] {
                for op in [
                    InVmOp::LiteStageCreate {
                        session_id: bad.to_string(),
                    },
                    InVmOp::LiteStageRemove {
                        session_id: bad.to_string(),
                    },
                    InVmOp::LiteStageWrite {
                        session_id: bad.to_string(),
                        file: LiteStageFile::Passwd,
                        body: "x".to_string(),
                    },
                ] {
                    assert!(
                        validate_in_vm_op(&op).is_err(),
                        "session id {bad:?} must be refused: {op:?}"
                    );
                }
            }
        }

        /// An accepted session identifier cannot make the rendered path leave
        /// the stage root. The validator is the guard; this asserts the guard
        /// actually buys the property, rather than asserting the guard exists.
        #[test]
        fn an_accepted_session_id_keeps_every_rendered_path_under_the_stage_root() {
            for op in every_op() {
                if let Some(steps) = in_vm_shell_steps(&op) {
                    for step in steps {
                        for word in step {
                            if word.starts_with("/tmp/sandbox-lite") {
                                assert!(
                                    !word.contains(".."),
                                    "{op:?} rendered a traversing path: {word}"
                                );
                            }
                        }
                    }
                }
                if let Some(transfer) = in_vm_transfer(&op) {
                    assert!(!transfer.destination.contains(".."), "{op:?}");
                }
            }
        }

        /// The whole point of the set: no op renders a shell. Asserted here as
        /// well as in the argv crate because this is the side that runs it,
        /// and because a future variant could render its own argv rather than
        /// going through a builder.
        #[test]
        fn no_op_renders_a_shell_invocation() {
            for op in every_op() {
                let Some(steps) = in_vm_shell_steps(&op) else {
                    continue;
                };
                for step in steps {
                    for word in &step {
                        assert!(
                            !matches!(word.as_str(), "sh" | "bash" | "zsh" | "dash" | "-c"),
                            "{op:?} renders {step:?}, which invokes a shell"
                        );
                    }
                }
            }
        }

        /// Every op is a command or a transfer, never both and never neither.
        #[test]
        fn every_op_is_exactly_one_of_a_command_or_a_transfer() {
            for op in every_op() {
                assert!(
                    in_vm_shell_steps(&op).is_some() ^ in_vm_transfer(&op).is_some(),
                    "{op:?} is not exactly one of a command or a transfer"
                );
            }
        }

        /// Only the nftables baseline feeds stdin, and it feeds it verbatim.
        /// A ruleset that were transformed anywhere between the generator and
        /// `nft` would be a policy change nobody wrote.
        #[test]
        fn only_the_nft_baseline_carries_a_body_and_it_is_unmodified() {
            let ruleset =
                "table inet t {\n  chain c { type filter hook output priority 0; drop }\n}\n";
            for op in every_op() {
                match &op {
                    InVmOp::ApplyNftBaseline { .. } => {
                        let op = InVmOp::ApplyNftBaseline {
                            ruleset: ruleset.to_string(),
                        };
                        assert_eq!(in_vm_stdin_body(&op), Some(ruleset));
                    }
                    _ => assert!(
                        in_vm_stdin_body(&op).is_none(),
                        "{op:?} unexpectedly carries a stdin body"
                    ),
                }
            }
        }

        /// The nftables ruleset survives the JSON frame. It is the largest
        /// thing that crosses the newline-delimited channel and it is full of
        /// newlines, braces and quotes; a frame that split would deliver a
        /// prefix of the egress policy, which `nft` would accept as a whole
        /// and much more permissive one.
        #[test]
        fn the_nft_ruleset_is_escaped_by_the_json_encoding() {
            let hostile = "table inet t {\n  \"quoted\"\n}\n\r\ttrailing\n";
            let op = crate::protocol::BrokerOp::InVm {
                op_uid: 501,
                op: InVmOp::ApplyNftBaseline {
                    ruleset: hostile.to_string(),
                },
            };
            let line = serde_json::to_string(&op).expect("serialize");
            assert!(
                !line.contains('\n'),
                "the encoded frame contains a literal newline"
            );

            let back: crate::protocol::BrokerOp = serde_json::from_str(&line).expect("round trip");
            let crate::protocol::BrokerOp::InVm {
                op: InVmOp::ApplyNftBaseline { ruleset },
                ..
            } = back
            else {
                panic!("wrong variant after round trip");
            };
            assert_eq!(ruleset, hostile);
        }

        /// Neither transfer carries a source path — the whole reason the lite
        /// files travel as content. A path field would be a request to copy
        /// an arbitrary file into a VM with passwordless sudo.
        #[test]
        fn no_transfer_names_a_source_path() {
            for op in every_op() {
                let Some(transfer) = in_vm_transfer(&op) else {
                    continue;
                };
                match transfer.source {
                    InVmTransferSource::RouteHelperBinary => {}
                    InVmTransferSource::Content { basename, mode, .. } => {
                        assert!(
                            !basename.contains('/'),
                            "a transfer source basename must not be a path: {basename}"
                        );
                        assert_eq!(mode, 0o644);
                    }
                }
                assert!(transfer.destination.starts_with('/'));
            }
        }

        /// An unknown op name is rejected at deserialization rather than
        /// reaching a handler. This is what "the enum is closed" means on the
        /// wire, as opposed to in the source.
        #[test]
        fn an_op_name_not_in_the_enum_fails_to_deserialize() {
            let json = r#"{"in_vm_op":"run_shell","command":"rm -rf /"}"#;
            assert!(serde_json::from_str::<InVmOp>(json).is_err());
        }

        // -- the route-install op's two fields -------------------------------

        #[test]
        fn a_zero_container_pid_is_rejected() {
            let op = InVmOp::InstallContainerRoute {
                container_pid: 0,
                gateway_ip: std::net::Ipv4Addr::new(10, 42, 7, 2),
            };
            let err = validate_in_vm_op(&op).expect_err("pid 0 must be rejected");
            assert!(err.contains('0'), "the error should name the value: {err}");
        }

        /// The helper's parser takes an `i32`. A pid above that arrives
        /// well-formed on this side and dies at the far end's argument parser,
        /// where the message is about syntax rather than about the value.
        #[test]
        fn a_container_pid_the_far_end_cannot_parse_is_rejected() {
            for pid in [i32::MAX as u32 + 1, u32::MAX] {
                let op = InVmOp::InstallContainerRoute {
                    container_pid: pid,
                    gateway_ip: std::net::Ipv4Addr::new(10, 42, 7, 2),
                };
                assert!(
                    validate_in_vm_op(&op).is_err(),
                    "pid {pid} exceeds i32::MAX and must be rejected"
                );
            }
        }

        #[test]
        fn the_container_pid_bounds_admit_the_values_a_real_container_has() {
            for pid in [1u32, 2, 4242, 65535, i32::MAX as u32] {
                let op = InVmOp::InstallContainerRoute {
                    container_pid: pid,
                    gateway_ip: std::net::Ipv4Addr::new(10, 42, 7, 2),
                };
                assert!(
                    validate_in_vm_op(&op).is_ok(),
                    "pid {pid} is a legitimate value and must be accepted"
                );
            }
        }

        /// The gateway address is an `Ipv4Addr` field, so the rejection of
        /// everything that is not an address happens at deserialization — this
        /// op cannot be *constructed* from a hostile wire value, which is a
        /// stronger property than rejecting one after construction.
        ///
        /// The leading-zero case is the one worth pinning by name. Historically
        /// `inet_aton` read `010.0.0.1` as octal, and a parser that admitted it
        /// would let one written form denote two different addresses. Rust's
        /// does not, and a future parser swap that reintroduced it would break
        /// here.
        #[test]
        fn the_gateway_address_rejects_everything_that_is_not_an_ipv4_address() {
            for bad in [
                "10.0.0.2; rm -rf /",
                "$(id)",
                "gateway.local",
                "fd00::1",
                "10.0.0.2/28",
                "010.0.0.1",
                "10.0.0",
                "",
                "-10.0.0.2",
            ] {
                let json = format!(
                    r#"{{"in_vm_op":"install_container_route","container_pid":4242,"gateway_ip":"{bad}"}}"#
                );
                assert!(
                    serde_json::from_str::<InVmOp>(&json).is_err(),
                    "{bad:?} must not deserialize into a gateway address"
                );
            }
        }

        /// The pid is a `u32`, so a negative never becomes an op at all. The
        /// rendered argv word can therefore never begin with `-`, which is what
        /// keeps it from being read as a flag by the helper's parser.
        #[test]
        fn a_negative_container_pid_does_not_deserialize() {
            let json = r#"{"in_vm_op":"install_container_route","container_pid":-1,"gateway_ip":"10.0.0.2"}"#;
            assert!(serde_json::from_str::<InVmOp>(json).is_err());
        }
    }

    // -----------------------------------------------------------------------
    // Docker stream ops
    // -----------------------------------------------------------------------

    mod docker_stream_ops {
        use super::*;
        use crate::protocol::DockerStreamOp;

        fn every_stream(container: &str) -> [DockerStreamOp; 3] {
            [
                DockerStreamOp::GuestAgent {
                    container: container.to_string(),
                },
                DockerStreamOp::Sshd {
                    container: container.to_string(),
                },
                DockerStreamOp::DnsGate {
                    container: container.to_string(),
                },
            ]
        }

        /// A real container name is accepted on every destination.
        #[test]
        fn a_valid_container_name_is_accepted_for_every_destination() {
            for op in every_stream("sandbox-abc123def456") {
                assert!(
                    validate_docker_stream_op(&op).is_ok(),
                    "{op:?} must be accepted"
                );
            }
        }

        /// The container name is the only value the daemon supplies on these
        /// ops, so it is the only thing that can be wrong — and a name that
        /// is not a name is how `docker exec` acquires an extra flag. Every
        /// destination re-validates it; none is exempt because it "only"
        /// listens.
        #[test]
        fn a_container_name_that_is_not_a_name_is_refused_on_every_destination() {
            for bad in [
                "-H",
                "--privileged",
                "sandbox abc",
                "sandbox;rm -rf /",
                "",
                "sandbox/abc",
            ] {
                for op in every_stream(bad) {
                    let err = validate_docker_stream_op(&op)
                        .expect_err("a non-name container must be refused");
                    assert!(
                        err.contains("container"),
                        "the refusal must name the field; got {err}"
                    );
                }
            }
        }

        /// The destination is a discriminant, not a value: nothing the daemon
        /// sends can change where a stream lands, so validation has nothing
        /// to check there. Pinned by asserting the rendered address comes out
        /// of the enum rather than out of the op's fields.
        #[test]
        fn the_destination_comes_from_the_discriminant_and_not_from_the_payload() {
            let addresses: Vec<String> = every_stream("sandbox-abc123def456")
                .iter()
                .map(|op| op.target().socat_address())
                .collect();
            assert_eq!(
                addresses,
                vec![
                    "TCP:127.0.0.1:5123".to_string(),
                    "TCP:127.0.0.1:22".to_string(),
                    "UNIX-LISTEN:/var/log/gateway/events/dns-gate.sock,unlink-early".to_string(),
                ]
            );
        }

        /// The gate listener must never be forked on the agent side either:
        /// `,fork` would multiplex concurrent gate connections onto one stdio
        /// stream and corrupt the per-query request/ack framing, on the
        /// egress-allow decision path.
        #[test]
        fn the_agent_rendered_gate_listener_is_never_forked() {
            let argv = crate::protocol::docker_stream_argv(
                &DockerStreamOp::DnsGate {
                    container: "sandbox-gw-x".to_string(),
                },
                Some(std::path::Path::new(
                    "/lima/sandboxd-gateway/gateway-docker.sock",
                )),
            );
            assert!(
                !argv.iter().any(|a| a.contains("fork")),
                "the gate listener must not fork; got {argv:?}"
            );
            assert_eq!(
                argv,
                vec![
                    "-H",
                    "unix:///lima/sandboxd-gateway/gateway-docker.sock",
                    "exec",
                    "-i",
                    "sandbox-gw-x",
                    "socat",
                    "-",
                    "UNIX-LISTEN:/var/log/gateway/events/dns-gate.sock,unlink-early",
                ]
            );
        }
    }
}
