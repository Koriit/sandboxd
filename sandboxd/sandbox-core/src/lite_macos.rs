//! Pure helpers for the lite-mode container backend on macOS.
//!
//! These functions are platform-neutral at the code level (they contain no
//! `#[cfg(target_os = "macos")]`) and are testable on any platform. The
//! macOS lite path in the daemon is the only production caller, but keeping
//! these in a non-cfg'd module means the hermetic unit tests run on every CI
//! platform (including Linux) without needing a macOS agent.
//!
//! # Scope
//!
//! - **Shared-root config** ([`lite_shared_root`] / [`lite_shared_root_9p_stanza`]):
//!   the daemon-side configuration knob and the Lima `mounts:` 9p stanza
//!   string builder. Wired into `generate_gateway_template` at gateway template
//!   generation time.
//! - **Host→VM path translation** ([`translate_shared_path`] / [`validate_shared_path`]):
//!   pure path rewriting from a host `shared:` path to the in-VM 9p mountpoint
//!   path the sandbox container will bind-mount.
//! - **In-VM route-helper argv** ([`build_in_vm_route_helper_argv`]): constructs
//!   the `limactl shell … sandbox-route-helper` argv vector for the gateway VM.
//!   Pure; no execution.

use std::net::IpAddr;
use std::path::{Path, PathBuf};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Environment variable a caller can set to override the default
/// `SANDBOX_LITE_SHARED_ROOT`. When unset the daemon uses
/// [`DEFAULT_LITE_SHARED_ROOT`].
pub const LITE_SHARED_ROOT_ENV: &str = "SANDBOX_LITE_SHARED_ROOT";

/// Default path exposed to the gateway Lima VM via Lima's 9p `mounts:` stanza.
/// Chosen as `/tmp/sandbox-shared` — a writable, world-accessible directory
/// that is outside TCC-protected folders (Desktop, Documents, Downloads) and
/// does not require operator consent for `_sandbox` to read. Operators whose
/// workspaces live elsewhere must either (a) move the workspace under this
/// root, (b) set `SANDBOX_LITE_SHARED_ROOT` to a parent of their workspace,
/// or (c) use `local:` / `clone:` instead of `shared:`.
///
/// The in-VM mountpoint mirrors this path verbatim (no remapping): a host
/// file at `<root>/project/foo.txt` is visible inside the gateway VM at
/// `<root>/project/foo.txt` with the same absolute path. This keeps the
/// host→VM translation trivial (identity) while allowing the daemon to
/// validate that a requested `shared:<host>` path is under the root.
pub const DEFAULT_LITE_SHARED_ROOT: &str = "/tmp/sandbox-shared";

/// Path at which `sandbox-route-helper` is installed inside the gateway Lima
/// VM. The helper is baked into the gateway VM image and setcap'd at image
/// build time — the same install path as on Linux. This constant is used by
/// [`build_in_vm_route_helper_argv`] to construct the `limactl shell …`
/// invocation.
pub const IN_VM_ROUTE_HELPER_PATH: &str = "/usr/local/libexec/sandboxd/sandbox-route-helper";

// ---------------------------------------------------------------------------
// Shared-root config
// ---------------------------------------------------------------------------

/// Return the lite shared-workspace root path.
///
/// Checks `SANDBOX_LITE_SHARED_ROOT`; falls back to
/// [`DEFAULT_LITE_SHARED_ROOT`] when unset. The returned path is used both
/// as the host-side source for the Lima 9p `mounts:` stanza and as the
/// validation root for per-session `shared:<host>` paths.
///
/// No filesystem I/O is performed — the caller is responsible for ensuring
/// the directory exists before the gateway VM is provisioned.
pub fn lite_shared_root() -> PathBuf {
    std::env::var_os(LITE_SHARED_ROOT_ENV)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_LITE_SHARED_ROOT))
}

/// Generate the Lima `mounts:` 9p stanza for the lite shared-workspace root.
///
/// The stanza exposes `shared_root` read-write into the gateway Lima VM at
/// the same absolute path (identity mount), using the `mapped-xattr` 9p
/// security model (consistent with per-session VM mounts). The `mmap` cache
/// mode matches the existing per-session precedent in `lima.rs`.
///
/// The returned string is a YAML fragment intended to be inserted between the
/// `portForwards:` block and the `containerd:` block in the gateway Lima
/// template.
///
/// # Format
///
/// ```yaml
/// mounts:
///   - location: "/tmp/sandbox-shared"
///     writable: true
///     mountType: "9p"
///     9p:
///       securityModel: "mapped-xattr"
///       cache: "mmap"
/// ```
pub fn lite_shared_root_9p_stanza(shared_root: &Path) -> String {
    format!(
        "mounts:\n  - location: \"{location}\"\n    writable: true\n    mountType: \"9p\"\n    9p:\n      securityModel: \"mapped-xattr\"\n      cache: \"mmap\"\n",
        location = shared_root.display()
    )
}

// ---------------------------------------------------------------------------
// Host→VM path translation
// ---------------------------------------------------------------------------

/// Translate a host `shared:` workspace path to its in-VM 9p mountpoint path.
///
/// The gateway Lima VM exposes `shared_root` at the same absolute path via
/// Lima's 9p `mounts:` stanza (identity mount). Therefore the in-VM path of
/// a host file `<shared_root>/<rel>` is simply `<shared_root>/<rel>` — no
/// remapping is needed.
///
/// Returns `Ok(vm_path)` when `host_path` is under `shared_root` (including
/// the root itself). Returns `Err` when `host_path` is not under `shared_root`
/// or when the relative component cannot be computed (e.g. a non-normalizable
/// path).
///
/// This is a pure function — no filesystem I/O.
pub fn translate_shared_path(
    host_path: &Path,
    shared_root: &Path,
) -> Result<PathBuf, SharedPathError> {
    // Canonicalize-free relative-path check: strip the shared_root prefix
    // from host_path to get the relative component, then rejoin it under
    // shared_root.  We do NOT call std::fs::canonicalize because (a) the path
    // may not exist yet (the operator may create the workspace after
    // provisioning) and (b) the function must be hermetic / pure.
    match host_path.strip_prefix(shared_root) {
        Ok(rel) => Ok(shared_root.join(rel)),
        Err(_) => Err(SharedPathError::OutsideRoot {
            host_path: host_path.to_path_buf(),
            shared_root: shared_root.to_path_buf(),
        }),
    }
}

/// Validate that `host_path` is under `shared_root` without performing the
/// full translation.
///
/// Returns `Ok(())` when valid, `Err` when the path is outside the root.
/// Equivalent to checking whether [`translate_shared_path`] would succeed,
/// but communicates intent more clearly at call sites that only need the
/// validation step.
pub fn validate_shared_path(host_path: &Path, shared_root: &Path) -> Result<(), SharedPathError> {
    host_path
        .strip_prefix(shared_root)
        .map(|_| ())
        .map_err(|_| SharedPathError::OutsideRoot {
            host_path: host_path.to_path_buf(),
            shared_root: shared_root.to_path_buf(),
        })
}

/// Error returned when a `shared:` host path falls outside the configured
/// `lite_shared_root`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SharedPathError {
    /// The requested host path is not under the shared root.
    OutsideRoot {
        host_path: PathBuf,
        shared_root: PathBuf,
    },
}

impl std::fmt::Display for SharedPathError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SharedPathError::OutsideRoot {
                host_path,
                shared_root,
            } => write!(
                f,
                "lite shared: path {} is outside the configured shared root {} — \
                 move the workspace under the root or set SANDBOX_LITE_SHARED_ROOT",
                host_path.display(),
                shared_root.display()
            ),
        }
    }
}

impl std::error::Error for SharedPathError {}

// ---------------------------------------------------------------------------
// In-VM route-helper argv builder
// ---------------------------------------------------------------------------

/// Build the argv for invoking `sandbox-route-helper` inside the gateway Lima
/// VM via `limactl shell`.
///
/// On macOS the sandbox container's PID is a **gateway-VM** PID (meaningless
/// on the host). The cap'd `sandbox-route-helper` binary is installed inside
/// the VM at [`IN_VM_ROUTE_HELPER_PATH`]. This function builds the full
/// `limactl shell <vm> -- sudo <helper> <args>` argv vector that the daemon
/// passes to the lima executor's `shell` command.
///
/// # Arguments
///
/// - `gateway_vm_name`: the Lima instance name (typically `"sandboxd-gateway"`).
/// - `vm_pid`: the sandbox container's PID as seen from inside the gateway VM
///   (obtained via `docker -H <sock> inspect -f '{{.State.Pid}}'`).
/// - `gateway_ip`: the per-session gateway container IP the sandbox container's
///   default route must be pointed at.
///
/// # Authorization
///
/// Inside the gateway VM the route-helper is single-tenant: the VM is
/// `_sandbox` infra with no per-operator identity threading. The helper is
/// invoked as `sudo` (passwordless, configured in the VM's sudoers) without
/// a `--for-user` flag. The VM itself is the authorization boundary — only the
/// daemon can reach it via the Lima shell path.
///
/// # Returns
///
/// A `Vec<String>` suitable as an argv slice to the Lima executor's
/// `limactl shell` command.
pub fn build_in_vm_route_helper_argv(
    gateway_vm_name: &str,
    vm_pid: i32,
    gateway_ip: IpAddr,
) -> Vec<String> {
    vec![
        "shell".to_string(),
        gateway_vm_name.to_string(),
        "--".to_string(),
        "sudo".to_string(),
        IN_VM_ROUTE_HELPER_PATH.to_string(),
        vm_pid.to_string(),
        gateway_ip.to_string(),
    ]
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- Shared-root config --------------------------------------------------

    #[test]
    fn lite_shared_root_defaults_when_env_unset() {
        // Remove the env var for this test (may be set from a parent process).
        // Use std::env::remove_var inside a scoped guard so parallel tests are
        // not affected — nextest runs each test in a separate process so
        // env-var mutation is safe.
        let prev = std::env::var_os(LITE_SHARED_ROOT_ENV);
        unsafe { std::env::remove_var(LITE_SHARED_ROOT_ENV) };
        let root = lite_shared_root();
        // Restore before any assertion that might panic.
        if let Some(val) = prev {
            unsafe { std::env::set_var(LITE_SHARED_ROOT_ENV, val) };
        }
        assert_eq!(root, PathBuf::from(DEFAULT_LITE_SHARED_ROOT));
    }

    #[test]
    fn lite_shared_root_honored_when_env_set() {
        // nextest spawns each test in its own process, so set_var is safe here.
        let custom = "/opt/my-workspaces";
        unsafe { std::env::set_var(LITE_SHARED_ROOT_ENV, custom) };
        let root = lite_shared_root();
        unsafe { std::env::remove_var(LITE_SHARED_ROOT_ENV) };
        assert_eq!(root, PathBuf::from(custom));
    }

    #[test]
    fn lite_shared_root_9p_stanza_is_well_formed() {
        let root = Path::new("/tmp/sandbox-shared");
        let stanza = lite_shared_root_9p_stanza(root);
        // Must start with the mounts: key at the top level.
        assert!(
            stanza.starts_with("mounts:"),
            "stanza must start with 'mounts:': {stanza:?}"
        );
        // Must contain the root path.
        assert!(
            stanza.contains("/tmp/sandbox-shared"),
            "stanza must contain root path: {stanza:?}"
        );
        // Must be writable.
        assert!(
            stanza.contains("writable: true"),
            "stanza must be writable: {stanza:?}"
        );
        // Must use 9p mountType.
        assert!(
            stanza.contains("mountType: \"9p\""),
            "stanza must use mountType 9p: {stanza:?}"
        );
        // Security model must be mapped-xattr.
        assert!(
            stanza.contains("securityModel: \"mapped-xattr\""),
            "stanza must use mapped-xattr security model: {stanza:?}"
        );
        // Cache must be mmap.
        assert!(
            stanza.contains("cache: \"mmap\""),
            "stanza must use mmap cache: {stanza:?}"
        );
    }

    #[test]
    fn lite_shared_root_9p_stanza_custom_root() {
        let root = Path::new("/Users/alice/workspaces");
        let stanza = lite_shared_root_9p_stanza(root);
        assert!(stanza.contains("/Users/alice/workspaces"));
    }

    // -- Host→VM path translation --------------------------------------------

    #[test]
    fn translate_shared_path_path_under_root() {
        let root = Path::new("/tmp/sandbox-shared");
        let host = Path::new("/tmp/sandbox-shared/project/src/main.rs");
        let vm_path = translate_shared_path(host, root).expect("must succeed");
        // Identity mount: in-VM path equals host path.
        assert_eq!(
            vm_path,
            PathBuf::from("/tmp/sandbox-shared/project/src/main.rs")
        );
    }

    #[test]
    fn translate_shared_path_root_itself() {
        let root = Path::new("/tmp/sandbox-shared");
        let vm_path = translate_shared_path(root, root).expect("root itself must be valid");
        assert_eq!(vm_path, root);
    }

    #[test]
    fn translate_shared_path_direct_child() {
        let root = Path::new("/tmp/sandbox-shared");
        let host = Path::new("/tmp/sandbox-shared/project");
        let vm_path = translate_shared_path(host, root).expect("direct child must succeed");
        assert_eq!(vm_path, PathBuf::from("/tmp/sandbox-shared/project"));
    }

    #[test]
    fn translate_shared_path_deeply_nested() {
        let root = Path::new("/opt/workspaces");
        let host = Path::new("/opt/workspaces/a/b/c/d/e.txt");
        let vm_path = translate_shared_path(host, root).expect("deeply nested must succeed");
        assert_eq!(vm_path, host);
    }

    #[test]
    fn translate_shared_path_outside_root_rejected() {
        let root = Path::new("/tmp/sandbox-shared");
        let host = Path::new("/tmp/other-dir/project");
        let err = translate_shared_path(host, root).expect_err("outside root must be rejected");
        match &err {
            SharedPathError::OutsideRoot {
                host_path,
                shared_root,
            } => {
                assert_eq!(host_path, host);
                assert_eq!(shared_root, root);
            }
        }
        // Error message must be human-readable.
        let msg = err.to_string();
        assert!(
            msg.contains("outside the configured shared root"),
            "got: {msg}"
        );
    }

    #[test]
    fn translate_shared_path_sibling_root_rejected() {
        // /tmp/sandbox-sharedX is NOT under /tmp/sandbox-shared — must be rejected
        // (prefix match must be a full path component, not a string prefix).
        let root = Path::new("/tmp/sandbox-shared");
        let host = Path::new("/tmp/sandbox-sharedX/foo");
        let result = translate_shared_path(host, root);
        assert!(
            result.is_err(),
            "sibling directory with matching prefix must be rejected"
        );
    }

    #[test]
    fn validate_shared_path_under_root_ok() {
        let root = Path::new("/tmp/sandbox-shared");
        let host = Path::new("/tmp/sandbox-shared/project");
        assert!(validate_shared_path(host, root).is_ok());
    }

    #[test]
    fn validate_shared_path_outside_root_err() {
        let root = Path::new("/tmp/sandbox-shared");
        let host = Path::new("/home/alice/project");
        assert!(validate_shared_path(host, root).is_err());
    }

    // -- In-VM route-helper argv builder -------------------------------------

    #[test]
    fn build_in_vm_route_helper_argv_correct_shape() {
        let argv =
            build_in_vm_route_helper_argv("sandboxd-gateway", 12345, "10.0.0.2".parse().unwrap());
        // Expected: ["shell", "sandboxd-gateway", "--", "sudo", "<helper>", "12345", "10.0.0.2"]
        assert_eq!(argv[0], "shell");
        assert_eq!(argv[1], "sandboxd-gateway");
        assert_eq!(argv[2], "--");
        assert_eq!(argv[3], "sudo");
        assert_eq!(argv[4], IN_VM_ROUTE_HELPER_PATH);
        assert_eq!(argv[5], "12345");
        assert_eq!(argv[6], "10.0.0.2");
        assert_eq!(argv.len(), 7);
    }

    #[test]
    fn build_in_vm_route_helper_argv_ipv4_address() {
        let argv = build_in_vm_route_helper_argv(
            "sandboxd-gateway",
            999,
            "192.168.100.3".parse().unwrap(),
        );
        assert_eq!(argv[5], "999");
        assert_eq!(argv[6], "192.168.100.3");
    }

    #[test]
    fn build_in_vm_route_helper_argv_ipv6_address() {
        let argv =
            build_in_vm_route_helper_argv("sandboxd-gateway", 42, "fd00::1".parse().unwrap());
        assert_eq!(argv[5], "42");
        assert_eq!(argv[6], "fd00::1");
    }

    #[test]
    fn build_in_vm_route_helper_argv_vm_name_propagated() {
        let argv = build_in_vm_route_helper_argv("my-custom-vm", 1, "10.1.2.3".parse().unwrap());
        assert_eq!(argv[1], "my-custom-vm");
    }
}
