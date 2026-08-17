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

/// Validate the shape of a daemon-rendered `lima.yaml` for a sandbox VM.
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
    let top = match &doc {
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
    // the check below on `networks` is the only code path. This applies to both
    // session VMs and base-image build VMs.
    if top.contains_key("network") {
        return Err(
            "lima.yaml must not contain a 'network' key; use 'networks' with a socket: entry"
                .to_string(),
        );
    }

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
    // Docker op validation
    // -----------------------------------------------------------------------

    mod docker {
        use super::super::*;
        use crate::protocol::{
            ContainerCommand, ContainerCreateSpec, DockerOp, EnvoyStat, FileDelivery,
            GatewayComponent, GatewayFile, InspectFlag, InspectFormat, NetworkCreateSpec,
            NetworkDriver, NetworkOption, NftTable, RemoveForce, StagedImage, StdinCommand,
            WorkspaceBindSpec,
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
}
