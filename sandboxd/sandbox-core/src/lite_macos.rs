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
//!   path the sandbox container will bind-mount. Of the pair, only
//!   [`validate_shared_path`] has a production caller; the mount is an
//!   identity mount, so the daemon validates and then uses the host path
//!   unchanged. See [`translate_shared_path`] for why the unused half is
//!   still here and what would justify deleting it.

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
///
/// # No production caller — a seam the identity mount made unnecessary
///
/// Nothing outside this module's tests calls this. It has never had a
/// production caller: it arrived with the container-backend seams for lite
/// mode, ahead of a translation step that turned out not to be needed,
/// because the 9p stanza mounts `shared_root` at the same absolute path in
/// the VM. Read the body with that in mind — `shared_root.join(rel)` where
/// `rel` was just stripped from `shared_root` reconstructs the input, so the
/// whole function is an identity transform on every path it accepts. Identity
/// as a [`Path`], not byte-for-byte: given `shared_root` itself, `rel` is
/// empty and the join returns `<shared_root>/` with a trailing separator.
/// The two compare equal because `Path` compares components, but a caller
/// that formatted the result into a string would not get back what it passed
/// in. The live path calls [`validate_shared_path`] and then uses the host
/// path directly (`sandboxd/src/main.rs`, lite session create), which is the
/// same result without the round trip.
///
/// It is kept, not deleted, for one reason: it is where a non-identity
/// mapping would go if the mount ever stopped being an identity mount — a
/// per-session subdirectory, or a VM-side prefix. If that has not happened
/// by the time someone next reads this, delete it and the re-export in
/// `lib.rs`; a `pub` identity function with no caller costs more in reader
/// confusion than the seam saves.
///
/// Its test is a drift guard on this function, not a second confirmation
/// that the escape is closed on a live path. Only [`validate_shared_path`]
/// gives that.
pub fn translate_shared_path(
    host_path: &Path,
    shared_root: &Path,
) -> Result<PathBuf, SharedPathError> {
    // Delegate both halves — component scan and root-containment test —
    // rather than repeating either. The two functions previously carried
    // separate copies of the same `strip_prefix`, and so also carried the
    // same defect; sharing one implementation is what keeps a fix to one
    // from missing the other.
    validate_shared_path(host_path, shared_root)?;
    let rel = host_path
        .strip_prefix(shared_root)
        .expect("validate_shared_path accepted the path, so the prefix strips");
    Ok(shared_root.join(rel))
}

/// Validate that `host_path` is under `shared_root` without performing the
/// full translation.
///
/// Equivalent to checking whether [`translate_shared_path`] would succeed,
/// but communicates intent more clearly at call sites that only need the
/// validation step.
///
/// # Two checks, and they need separate names
///
/// This function body is two sequential checks with opposite behaviour on
/// the same input, so "the containment check" is not a usable name for
/// either. Throughout this module they are called:
///
/// - the **component scan** — the `ParentDir` / `CurDir` search, which
///   *rejects* `..`, returning [`SharedPathError::NonCanonicalComponent`];
/// - the **root-containment test** — the `strip_prefix` against
///   `shared_root`, which *accepts* `..` and decides only outside-root,
///   returning [`SharedPathError::OutsideRoot`].
///
/// The distinction is not stylistic. Both statements below are true and
/// they read as a contradiction under one name: removing the component scan
/// makes three tests fail, and the root-containment test on its own returns
/// `Ok` for `<root>/../../var/run`. Naming the halves separately is what
/// keeps that from being re-litigated.
///
/// # Why lexical
///
/// We do NOT call `std::fs::canonicalize` because (a) the path may not exist
/// yet — the operator may create the workspace after provisioning — and (b)
/// the function must be hermetic / pure. A lexical test is only sound on a
/// path with no `..` component: `strip_prefix` matches `..` as an ordinary
/// component, so `<root>/../../var/run` strips cleanly and rejoins to a path
/// that resolves outside the root once the *VM* resolves it. The component
/// scan running first is what makes the root-containment test mean
/// containment; the ordering is load-bearing, not incidental.
///
/// # Scope of the component scan
///
/// `Path::components()` normalises interior `.` and repeated separators away
/// before this function ever sees them, so on an absolute path `..` is the
/// only non-canonical component the scan *can* observe. That is sufficient
/// here, because `..` is also the only one that changes where the path
/// resolves. The other spellings are rejected upstream by
/// `WorkspaceMode::parse_flag`, which inspects the raw string and can still
/// see them; do not read the `CurDir` arm below as this function covering
/// them — it fires only for a relative path, which cannot be contained by any
/// root and is rejected as absoluteness upstream.
///
/// # One route of three — what refusing `..` here does not reach
///
/// This closes one way of naming a mount source outside the root: *spelling*
/// it. Two others reach the same place and are open by design, so a reader
/// who takes this check for "a workspace path cannot leave the shared root"
/// has read more than is here.
///
/// - **A symlink planted inside the workspace.** The 9p export above is
///   `mapped-xattr`, under which a guest-created symlink is stored host-side
///   as a *regular file* carrying `S_IFLNK` in a `user.virtfs.*` xattr.
///   Nothing on the host sees a link — not this scan, not
///   `std::fs::canonicalize` — while dockerd, resolving `src=` inside the VM,
///   is handed a real symlink and follows it. That is structural, not a race:
///   the two views genuinely disagree about what the inode is, so no
///   re-check, retry or narrower window changes it, and containment has to be
///   decided in the namespace where the path is used. An agent with write
///   access to its own workspace — which is the feature — can plant one.
/// - **The payoff at the far end — the specific one that made this the
///   headline route — is closed.** The gateway VM's `/var/run/docker.sock`
///   was mode `0666`, so a mount source landing on it was root over the
///   dockerd that enforces egress for every session in that VM: an agent
///   escaping its own sandbox and voiding its own egress policy. It is now
///   `0660`, owned by `root:<the VM login user's primary group>`
///   ([`crate::gateway_lima`]), and a sandbox container holds neither that
///   group nor ownership — so a bind of the VM's runtime directory no longer
///   yields a usable socket.
///
///   Read that narrowly. The traversal is unchanged, this check still does
///   not close it, and every other in-VM path a mount source can name is
///   reached exactly as before. What went away is this route's worst
///   consequence, not the route.
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
/// spelled in a way that makes the root-containment test unsound.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SharedPathError {
    /// The requested host path is not under the shared root.
    OutsideRoot {
        host_path: PathBuf,
        shared_root: PathBuf,
    },
    /// The requested host path contains a component that leaves the lexical
    /// root-containment test unable to decide where it actually points. On
    /// the absolute paths this backend receives that means `..`; see
    /// [`validate_shared_path`] for why the other non-canonical spellings are
    /// not visible here and are rejected upstream instead.
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

    /// The root-containment test is lexical, and `strip_prefix` treats `..`
    /// as an ordinary component: `<root>/../../var/run` strips cleanly
    /// against `<root>` and rejoins to a path that resolves outside the root.
    /// Nothing on the host catches it, because the host never resolves it —
    /// the gateway VM does, at mount time. Hence the component scan, which is
    /// what this pins.
    ///
    /// `/var/run` is deliberate. A target that merely does not exist would be
    /// refused later by the bind failing on a missing source, so a test
    /// written against one would still pass with this rejection removed and
    /// would be pinning the wrong mechanism. `/var/run` exists inside the VM.
    #[test]
    fn validate_shared_path_rejects_parent_dir_escape() {
        let root = Path::new("/tmp/sandbox-shared");
        let host = Path::new("/tmp/sandbox-shared/../../var/run");

        // The premise: the root-containment test half of this function does
        // not, by itself, reject the path. If this ever stops holding, the
        // assertion below is no longer testing what it claims to. Read this
        // together with the rejection at the end — the two are not in
        // conflict, they are the two halves behaving differently on one
        // input, which is why they carry separate names.
        assert!(
            host.strip_prefix(root).is_ok(),
            "premise: `..` passes strip_prefix, which is why the component \
             scan in front of it is required"
        );

        // Second premise, and the reason the parser checks the raw string
        // rather than delegating here: `components()` normalises interior `.`
        // and `//` away, so `..` is the only non-canonical component this
        // function can observe. If that ever changes, the division of labour
        // documented on `validate_shared_path` needs rewriting.
        for normalised in ["/tmp/sandbox-shared/./x", "/tmp/sandbox-shared//x"] {
            assert!(
                !Path::new(normalised)
                    .components()
                    .any(|c| matches!(c, std::path::Component::CurDir)),
                "premise: {normalised} has no CurDir component to find"
            );
            assert!(
                validate_shared_path(Path::new(normalised), root).is_ok(),
                "{normalised} is accepted here by design — the parser rejects it"
            );
        }

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
    ///
    /// That is all it is. The function under test has no production caller,
    /// so passing here does not add a second confirmation that the escape is
    /// closed on a path an operator can reach — that comes from
    /// `validate_shared_path` alone. Do not count this one twice.
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
}
