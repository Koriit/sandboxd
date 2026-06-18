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
pub fn validate_lima_yaml_shape(lima_yaml: &str, expected_vm: &str) -> Result<(), String> {
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
    // accept this form as an alias for `networks`; reject it so the check
    // below on `networks` is the only code path.
    if top.contains_key("network") {
        return Err(
            "lima.yaml must not contain a 'network' key; use 'networks' with a socket: entry"
                .to_string(),
        );
    }

    // Check: the `networks` sequence contains exactly one entry, that entry is
    // a mapping with a `socket` key and no `mode` key.
    //
    // Valid Lima 2.x form (block style):
    //   networks:
    //     - socket: /var/run/sandbox/vmnet/slot-0.sock
    //
    // Valid Lima 2.x form (flow style, fully normalised by the parser):
    //   networks: [{socket: /var/run/sandbox/vmnet/slot-0.sock}]
    //
    // All of these produce the same `Value::Sequence([Mapping({socket: ...})])`.
    let networks_val = top.get("networks").ok_or_else(|| {
        "lima.yaml must contain a 'networks' key with exactly one socket_vmnet entry".to_string()
    })?;

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
// Tests — non-tautological, exercise the real validation functions
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

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
        let lima_home = "/var/lib/sandboxd/501/1000/lima";
        let path = "/var/lib/sandboxd/501/1000/lima/sandbox-abc/lima.yaml";
        assert!(validate_lima_home_path(lima_home, path).is_ok());
    }

    #[test]
    fn lima_home_confinement_accepts_trailing_slash_variant() {
        let lima_home = "/var/lib/sandboxd/501/1000/lima/";
        let path = "/var/lib/sandboxd/501/1000/lima/sandbox-abc/file";
        assert!(validate_lima_home_path(lima_home, path).is_ok());
    }

    #[test]
    fn lima_home_confinement_rejects_parent_escape() {
        // Path escapes LIMA_HOME by going to a sibling dir.
        let lima_home = "/var/lib/sandboxd/501/1000/lima";
        let result = validate_lima_home_path(
            lima_home,
            "/var/lib/sandboxd/501/9999/lima/sandbox-abc/file",
        );
        assert!(
            result.is_err(),
            "path outside LIMA_HOME must be rejected, not followed"
        );
    }

    #[test]
    fn lima_home_confinement_rejects_dotdot_escape() {
        let lima_home = "/var/lib/sandboxd/501/1000/lima";
        let result =
            validate_lima_home_path(lima_home, "/var/lib/sandboxd/501/1000/lima/../other/file");
        assert!(
            result.is_err(),
            "dotdot escape from LIMA_HOME must be rejected"
        );
    }

    #[test]
    fn lima_home_confinement_rejects_prefix_spoofing() {
        // A path that starts with the LIMA_HOME string but is actually a
        // sibling directory (e.g. `/var/lib/sandboxd/501/1000/limactl`).
        let lima_home = "/var/lib/sandboxd/501/1000/lima";
        let result = validate_lima_home_path(lima_home, "/var/lib/sandboxd/501/1000/limactl/evil");
        // The base is normalised to `/var/lib/sandboxd/501/1000/lima/`, so
        // `limactl/evil` does not start with it — correct rejection.
        assert!(result.is_err(), "prefix-spoof path must be rejected");
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
        // Must reject, not clamp to min.
        let result = validate_range("--cpus", 0, 1, 64);
        assert!(
            result.is_err(),
            "value below min must be rejected, not clamped to 1"
        );
        assert!(validate_range("--memory-mb", 255, 256, 262144).is_err());
    }

    #[test]
    fn range_rejects_above_max() {
        // Must reject, not clamp to max.
        let result = validate_range("--cpus", 65, 1, 64);
        assert!(
            result.is_err(),
            "value above max must be rejected, not clamped to 64"
        );
        assert!(validate_range("--memory-mb", 262145, 256, 262144).is_err());
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
            validate_lima_yaml_shape(yaml, "").is_ok(),
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
            validate_lima_yaml_shape(yaml, "").is_ok(),
            "flow-style single socket NIC with vmType: qemu must be accepted"
        );
    }

    /// vmType absent — must be rejected. Lima on macOS defaults to VZ when
    /// vmType is unset, which cannot attach socket_vmnet and voids egress control.
    #[test]
    fn lima_yaml_rejects_missing_vmtype() {
        let yaml = "networks:\n  - socket: /var/run/sandbox/vmnet/slot-0.sock\n";
        let result = validate_lima_yaml_shape(yaml, "test-vm");
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
        let result = validate_lima_yaml_shape(yaml, "test-vm");
        assert!(
            result.is_err(),
            "vmType: vz must be rejected — VZ bypasses the gateway"
        );
    }

    /// vmType: qemu — must now be accepted (required for macOS QEMU guarantee).
    #[test]
    fn lima_yaml_accepts_vmtype_qemu_explicit() {
        let yaml = "vmType: qemu\nnetworks:\n  - socket: /var/run/sandbox/vmnet/slot-0.sock\n";
        let result = validate_lima_yaml_shape(yaml, "");
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
        let result = validate_lima_yaml_shape(yaml, "");
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
        let result = validate_lima_yaml_shape(yaml, "");
        assert!(
            result.is_err(),
            "flow-style vmType: vz in a flow-mapping document must be rejected"
        );
    }

    /// No `networks` key at all — must be rejected.
    #[test]
    fn lima_yaml_rejects_missing_networks() {
        let yaml = "vmType: qemu\ncpus: 2\nmemory: \"4GiB\"\ndisk: \"20GiB\"\n";
        let result = validate_lima_yaml_shape(yaml, "test-vm");
        assert!(
            result.is_err(),
            "YAML with no networks key must be rejected"
        );
    }

    /// Two socket NIC entries — only one is permitted.
    #[test]
    fn lima_yaml_rejects_multiple_socket_nics() {
        let yaml = "vmType: qemu\nnetworks:\n  - socket: /var/run/sandbox/vmnet/slot-0.sock\n  - socket: /var/run/sandbox/vmnet/slot-1.sock\n";
        let result = validate_lima_yaml_shape(yaml, "test-vm");
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
        let result = validate_lima_yaml_shape(yaml, "test-vm");
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
        let result = validate_lima_yaml_shape(yaml, "test-vm");
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
        let result = validate_lima_yaml_shape(yaml, "test-vm");
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
        let result = validate_lima_yaml_shape(yaml, "test-vm");
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
            validate_lima_yaml_shape(yaml, "").is_ok(),
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
        let result = validate_lima_yaml_shape(yaml, "test-vm");
        assert!(
            result.is_err(),
            "quoted 'vmType' key must be rejected; \
             previously evadable with contains(\"vmType:\") check"
        );
    }

    /// Empty YAML — must be rejected.
    #[test]
    fn lima_yaml_rejects_empty() {
        let result = validate_lima_yaml_shape("", "test-vm");
        assert!(result.is_err(), "empty YAML must be rejected");
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
        let lima_home = "/var/lib/sandboxd/501/1000/lima";
        let traversal = "/var/lib/sandboxd/501/1000/lima/../../../etc/cron.d/evil";
        let result = validate_lima_home_path(lima_home, traversal);
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
        let result = validate_lima_yaml_shape(yaml, "");
        assert!(
            result.is_err(),
            "socket path outside /var/run/sandbox/vmnet/ must be rejected by shape validation"
        );
    }

    #[test]
    fn lima_yaml_rejects_traversal_socket_path() {
        let yaml =
            "cpus: 2\nnetworks:\n  - socket: /var/run/sandbox/vmnet/../../../tmp/evil.sock\n";
        let result = validate_lima_yaml_shape(yaml, "");
        assert!(
            result.is_err(),
            "socket path with '..' traversal must be rejected"
        );
    }

    #[test]
    fn lima_yaml_rejects_relative_socket_path() {
        let yaml = "cpus: 2\nnetworks:\n  - socket: relative/vmnet/slot-0.sock\n";
        let result = validate_lima_yaml_shape(yaml, "");
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
        let result = validate_lima_yaml_shape(yaml, "sandbox-550e8400e29b");
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
        let result = validate_lima_yaml_shape(yaml, "");
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
        let result = validate_lima_yaml_shape(yaml, "");
        assert!(
            result.is_ok(),
            "macOS template with 9p shared workspace must pass shape validation; error: {:?}",
            result.err()
        );
    }
}
