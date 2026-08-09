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
/// Chosen as `/tmp/sandbox-shared` because the principal that reads the host
/// side of this mount is the **daemon user** (`_sandboxd`, which owns the
/// gateway VM), not the operator — and `/tmp` is world-traversable, so that
/// read succeeds. An operator's home directory is not: it is owned by the
/// operator with mode 0750 and `_sandboxd` is outside its group, so the daemon
/// user cannot even traverse into a workspace there. (TCC adds a second gate
/// on top of that for Desktop / Documents / Downloads, but the ownership and
/// mode bits are what rule out home-directory paths in general.) Operators
/// whose workspaces live elsewhere must either (a) stage the content under
/// this root, (b) set `SANDBOX_LITE_SHARED_ROOT` to a parent of their
/// workspace that `_sandboxd` can traverse, or (c) use `clone:` / `--repo`,
/// the operator-uid transfer commands (`sandbox sync`, `sandbox cp`), or the
/// full backend instead of lite `shared:`.
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
/// `mountType` is a TOP-LEVEL Lima key (a sibling of `mounts:`), not a
/// per-mount field. Emitting `mountType` inside a `mounts:` list item makes
/// Lima reject it as an unknown field (non-strict YAML) and silently fall back
/// to the default mount type. The per-mount `9p:` options block only takes
/// effect when the top-level mount type is 9p.
///
/// ```yaml
/// mountType: "9p"
/// mounts:
///   - location: "/tmp/sandbox-shared"
///     writable: true
///     9p:
///       securityModel: "mapped-xattr"
///       cache: "mmap"
/// ```
pub fn lite_shared_root_9p_stanza(shared_root: &Path) -> String {
    format!(
        "mountType: \"9p\"\nmounts:\n  - location: \"{location}\"\n    writable: true\n    9p:\n      securityModel: \"mapped-xattr\"\n      cache: \"mmap\"\n",
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
    // Delegate the containment decision rather than repeating it. The two
    // functions previously carried separate copies of the same `strip_prefix`
    // check, and so also carried the same defect; sharing one implementation
    // is what keeps a fix to one from missing the other.
    validate_shared_path(host_path, shared_root)?;
    let rel = host_path
        .strip_prefix(shared_root)
        .expect("validate_shared_path accepted the path, so the prefix strips");
    Ok(shared_root.join(rel))
}

/// Validate that `host_path` is under `shared_root` without performing the
/// full translation.
///
/// Returns `Ok(())` when valid, `Err` when the path is outside the root.
/// Equivalent to checking whether [`translate_shared_path`] would succeed,
/// but communicates intent more clearly at call sites that only need the
/// validation step.
///
/// Containment is decided lexically. We do NOT call `std::fs::canonicalize`
/// because (a) the path may not exist yet — the operator may create the
/// workspace after provisioning — and (b) the function must be hermetic /
/// pure. A lexical check is only sound on a path with no `..` component:
/// `strip_prefix` matches `..` as an ordinary component, so
/// `<root>/../../var/run` strips cleanly and rejoins to a path that resolves
/// outside the root once the *VM* resolves it. Hence the component check
/// below — it is what makes the lexical prefix test mean containment.
pub fn validate_shared_path(host_path: &Path, shared_root: &Path) -> Result<(), SharedPathError> {
    if let Some(component) = host_path.components().find_map(|c| match c {
        std::path::Component::ParentDir => Some(".."),
        std::path::Component::CurDir => Some("."),
        _ => None,
    }) {
        return Err(SharedPathError::NonCanonicalComponent {
            host_path: host_path.to_path_buf(),
            shared_root: shared_root.to_path_buf(),
            component: component.to_string(),
        });
    }
    host_path
        .strip_prefix(shared_root)
        .map(|_| ())
        .map_err(|_| SharedPathError::OutsideRoot {
            host_path: host_path.to_path_buf(),
            shared_root: shared_root.to_path_buf(),
        })
}

/// Error returned when a `shared:` host path is not usable as a lite-backend
/// mount source — either outside the configured `lite_shared_root`, or
/// spelled in a way that makes the containment check unsound.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SharedPathError {
    /// The requested host path is not under the shared root.
    OutsideRoot {
        host_path: PathBuf,
        shared_root: PathBuf,
    },
    /// The requested host path contains a `..` or `.` component, so a lexical
    /// containment check cannot decide where it actually points.
    NonCanonicalComponent {
        host_path: PathBuf,
        shared_root: PathBuf,
        component: String,
    },
}

impl std::fmt::Display for SharedPathError {
    /// The `OutsideRoot` rendering is the operator-facing explanation for this
    /// refusal, so it names the real cause and the alternatives rather than
    /// only restating the rule. The cause is Unix ownership, not TCC: the
    /// gateway VM belongs to the daemon user, so the daemon user is the one
    /// reading the host side of the mount, and an operator-owned home
    /// directory is not traversable by it. Callers surface this verbatim (see
    /// the lite `shared:` validation in the daemon's macOS create path) — keep
    /// it self-contained.
    ///
    /// The same bar applies to `NonCanonicalComponent`: a refusal that said
    /// only "invalid path" would be a regression even though it rejects the
    /// same inputs, because the operator would have no way to tell a typo from
    /// a rule they had not met.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SharedPathError::OutsideRoot {
                host_path,
                shared_root,
            } => write!(
                f,
                "lite shared: path {host} is outside the configured shared root {root}. \
                 On the lite backend the sandbox container runs inside a gateway VM owned \
                 by the sandboxd daemon user (`_sandboxd`), and that user — not you — reads \
                 the host side of the mount; it cannot traverse your home directory (owned \
                 by you, mode 0750, with `_sandboxd` outside its group), so only paths under \
                 the shared root are mountable. What works instead: \
                 (a) clone:<repo-url> or --repo for a git-backed project — the clone runs \
                 inside the guest and never reads the host filesystem; \
                 (b) `sandbox sync` / `sandbox cp` (and `sandbox workspace push|pull` on a \
                 local: workspace), which run as your own uid over the daemon-mediated SSH \
                 proxy and can therefore read what `_sandboxd` cannot; \
                 (c) stage the content under {root} and point shared: there (the root itself \
                 is overridable via SANDBOX_LITE_SHARED_ROOT); or \
                 (d) use the full backend (drop --lite), whose per-session VM mounts the host \
                 directory as your own uid and so accepts any path.",
                host = host_path.display(),
                root = shared_root.display()
            ),
            SharedPathError::NonCanonicalComponent {
                host_path,
                shared_root,
                component,
            } => write!(
                f,
                "lite shared: path {host} contains a `{component}` component, which this \
                 backend cannot accept. The shared-root check that guards this mount is \
                 lexical — it compares path components on the host and never touches the \
                 filesystem, because the workspace directory is allowed not to exist yet. \
                 A `..` defeats that check rather than failing it: it compares as an \
                 ordinary component, so the path passes, and is only resolved later, inside \
                 the gateway VM, where it can land anywhere in the VM's filesystem rather \
                 than under the root. Refusing the spelling is therefore the check, not an \
                 extra restriction on top of it. What works instead: \
                 (a) pass the already-resolved path — it still does not need to exist, and \
                 for a directory that does, `cd <dir> && pwd -P` prints it; \
                 (b) if the resolved path turns out to be outside {root}, stage the content \
                 under that root and point shared: there (the root itself is overridable \
                 via SANDBOX_LITE_SHARED_ROOT); or \
                 (c) use the full backend (drop --lite), whose per-session VM mounts the \
                 host directory as your own uid.",
                host = host_path.display(),
                root = shared_root.display()
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
/// `limactl shell <vm> -- sudo <helper> --vm-gateway-mode <args>` argv vector
/// that the daemon passes to the lima executor's `shell` command.
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
/// Inside the gateway VM the route-helper uses `--vm-gateway-mode`, which
/// activates the degenerate single-tenant authorization path. The VM boundary
/// replaces the host-uid + pair-membership gate:
///
/// - Only the daemon (`_sandboxd`, running on the macOS host) can issue
///   `limactl shell sandboxd-gateway` commands. The Lima SSH credentials for
///   the gateway VM are exclusively owned by the daemon's LIMA_HOME.
/// - The gateway VM is single-tenant `_sandboxd` infra — no operator user can
///   independently reach its sudo path.
///
/// The `sudo` invocation escalates to root (uid 0) inside the VM; the helper
/// enforces the root-uid requirement in `--vm-gateway-mode`, so any invocation
/// that did not go through `sudo` (and therefore is not uid 0) is rejected
/// at the gate.
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
        "--vm-gateway-mode".to_string(),
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
        // mountType is a top-level Lima key (sibling of mounts:), so the stanza
        // must begin with it — not with `mounts:`.
        assert!(
            stanza.starts_with("mountType: \"9p\""),
            "stanza must start with top-level 'mountType: \"9p\"': {stanza:?}"
        );
        // The mounts: key must follow at the top level too.
        assert!(
            stanza.contains("\nmounts:\n"),
            "stanza must contain a top-level 'mounts:' key: {stanza:?}"
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
            other => panic!("expected OutsideRoot for a canonical path, got: {other:?}"),
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

    /// The shared-root check is lexical, and `strip_prefix` treats `..` as an
    /// ordinary component: `<root>/../../var/run` strips cleanly against
    /// `<root>` and rejoins to a path that resolves outside the root. Nothing
    /// on the host catches it, because the host never resolves it — the
    /// gateway VM does, at mount time.
    ///
    /// `/var/run` is deliberate. A target that merely does not exist would be
    /// refused later by the bind failing on a missing source, so a test
    /// written against one would still pass with this rejection removed and
    /// would be pinning the wrong mechanism. `/var/run` exists inside the VM.
    #[test]
    fn validate_shared_path_rejects_parent_dir_escape() {
        let root = Path::new("/tmp/sandbox-shared");
        let host = Path::new("/tmp/sandbox-shared/../../var/run");

        // The premise: the lexical prefix test this function is built on does
        // not, by itself, reject the path. If this ever stops holding, the
        // assertion below is no longer testing what it claims to.
        assert!(
            host.strip_prefix(root).is_ok(),
            "premise: `..` passes strip_prefix, which is why an explicit \
             component check is required"
        );

        let err = validate_shared_path(host, root).expect_err("`..` escape must be rejected");
        match &err {
            SharedPathError::NonCanonicalComponent {
                host_path,
                shared_root,
                component,
            } => {
                assert_eq!(host_path, host);
                assert_eq!(shared_root, root);
                assert_eq!(component, "..");
            }
            other => panic!("expected NonCanonicalComponent, got: {other:?}"),
        }
    }

    /// `translate_shared_path` had its own copy of the same lexical check and
    /// therefore its own copy of the same defect. It now delegates; this pins
    /// that it does, so a future edit cannot reintroduce a second
    /// implementation that drifts.
    #[test]
    fn translate_shared_path_rejects_parent_dir_escape() {
        let root = Path::new("/tmp/sandbox-shared");
        let host = Path::new("/tmp/sandbox-shared/../../var/run");
        let err = translate_shared_path(host, root).expect_err("`..` escape must be rejected");
        assert!(
            matches!(err, SharedPathError::NonCanonicalComponent { .. }),
            "got: {err:?}"
        );
    }

    /// A new refusal path must meet the same bar as the one below it: name the
    /// cause and the alternatives. A bare "invalid path" would reject the same
    /// inputs and still be a regression, because the operator could not tell a
    /// typo from a rule they had not met.
    #[test]
    fn non_canonical_error_names_cause_and_alternatives() {
        let err = validate_shared_path(
            Path::new("/tmp/sandbox-shared/../../var/run"),
            Path::new("/tmp/sandbox-shared"),
        )
        .expect_err("`..` must be rejected");
        let msg = err.to_string();

        // What was rejected, and against which root.
        assert!(
            msg.contains("/tmp/sandbox-shared/../../var/run"),
            "got: {msg}"
        );
        assert!(msg.contains("/tmp/sandbox-shared"), "got: {msg}");

        // Cause: the check is lexical and the resolution happens elsewhere —
        // not "this character is banned".
        assert!(msg.contains("lexical"), "got: {msg}");
        assert!(msg.contains("gateway VM"), "got: {msg}");

        // Alternatives, in the same shape the OutsideRoot refusal uses.
        assert!(msg.contains("pwd -P"), "got: {msg}");
        assert!(msg.contains("SANDBOX_LITE_SHARED_ROOT"), "got: {msg}");
        assert!(msg.contains("full backend"), "got: {msg}");
    }

    /// The refusal an operator actually sees must name the real cause — the
    /// gateway VM's daemon user reads the host side of the mount and cannot
    /// traverse an operator-owned home directory — and then point at the paths
    /// that do work. Pinned here because an earlier version of this message
    /// attributed the refusal to macOS TCC, which sent operators chasing
    /// privacy consent for a Unix-permissions problem.
    #[test]
    fn outside_root_error_names_cause_and_alternatives() {
        let err = validate_shared_path(
            Path::new("/Users/alice/Project"),
            Path::new("/tmp/sandbox-shared"),
        )
        .expect_err("home-directory path must be rejected");
        let msg = err.to_string();

        // Both paths are named so the operator can see what was compared.
        assert!(msg.contains("/Users/alice/Project"), "got: {msg}");
        assert!(msg.contains("/tmp/sandbox-shared"), "got: {msg}");

        // Cause: the daemon user does the read, and ownership/mode — not
        // privacy consent — is what denies it.
        assert!(msg.contains("_sandboxd"), "got: {msg}");
        assert!(msg.contains("home directory"), "got: {msg}");
        assert!(
            !msg.contains("TCC"),
            "TCC is at most secondary here; the message must not blame it: {msg}"
        );

        // Alternatives: guest-side clone, operator-uid transfer commands, the
        // shared-root staging path (with its env override), and the full backend.
        assert!(msg.contains("clone:"), "got: {msg}");
        assert!(msg.contains("sandbox sync"), "got: {msg}");
        assert!(msg.contains(LITE_SHARED_ROOT_ENV), "got: {msg}");
        assert!(msg.contains("full backend"), "got: {msg}");
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
        // Expected: ["shell", "sandboxd-gateway", "--", "sudo", "<helper>",
        //            "--vm-gateway-mode", "12345", "10.0.0.2"]
        assert_eq!(argv[0], "shell");
        assert_eq!(argv[1], "sandboxd-gateway");
        assert_eq!(argv[2], "--");
        assert_eq!(argv[3], "sudo");
        assert_eq!(argv[4], IN_VM_ROUTE_HELPER_PATH);
        assert_eq!(argv[5], "--vm-gateway-mode");
        assert_eq!(argv[6], "12345");
        assert_eq!(argv[7], "10.0.0.2");
        assert_eq!(argv.len(), 8);
    }

    #[test]
    fn build_in_vm_route_helper_argv_ipv4_address() {
        let argv = build_in_vm_route_helper_argv(
            "sandboxd-gateway",
            999,
            "192.168.100.3".parse().unwrap(),
        );
        // pid is at index 6, gateway_ip at index 7 (--vm-gateway-mode at index 5)
        assert_eq!(argv[6], "999");
        assert_eq!(argv[7], "192.168.100.3");
    }

    #[test]
    fn build_in_vm_route_helper_argv_ipv6_address() {
        let argv =
            build_in_vm_route_helper_argv("sandboxd-gateway", 42, "fd00::1".parse().unwrap());
        assert_eq!(argv[6], "42");
        assert_eq!(argv[7], "fd00::1");
    }

    #[test]
    fn build_in_vm_route_helper_argv_vm_name_propagated() {
        let argv = build_in_vm_route_helper_argv("my-custom-vm", 1, "10.1.2.3".parse().unwrap());
        assert_eq!(argv[1], "my-custom-vm");
    }

    #[test]
    fn build_in_vm_route_helper_argv_includes_vm_gateway_mode_flag() {
        let argv =
            build_in_vm_route_helper_argv("sandboxd-gateway", 1, "10.0.0.1".parse().unwrap());
        // The --vm-gateway-mode flag must appear between the helper path and the
        // positional args so the route-helper's parse_argv processes it as a flag,
        // not as the container_pid positional.
        assert!(
            argv.contains(&"--vm-gateway-mode".to_string()),
            "argv must contain --vm-gateway-mode: {argv:?}"
        );
        let mode_pos = argv.iter().position(|a| a == "--vm-gateway-mode").unwrap();
        let helper_pos = argv
            .iter()
            .position(|a| a == IN_VM_ROUTE_HELPER_PATH)
            .unwrap();
        // --vm-gateway-mode must come after the helper path and before the positionals.
        assert!(
            mode_pos > helper_pos,
            "--vm-gateway-mode must appear after the helper path"
        );
    }
}
