//! Pure helpers for the lite-mode container backend on macOS.
//!
//! These functions are platform-neutral at the code level and are testable on
//! any platform. The macOS lite path in the daemon is the only production
//! caller, but keeping these in a non-cfg'd module means the hermetic unit
//! tests run on every CI platform (including Linux) without needing a macOS
//! agent.
//!
//! **One exception, and it is deliberately one function wide.**
//! [`read_virtfs_mode_xattr`] is `#[cfg(target_os = "macos")]` because it is
//! a `getxattr(2)` call whose flag argument does not exist off Darwin. The
//! logic it feeds — [`decode_virtfs_mode`] and
//! [`reject_guest_planted_symlink`] — takes the read as an injected closure
//! and stays testable everywhere. Keep the split there: the syscall is the
//! only part that cannot run on Linux, and widening the `cfg` past it would
//! take the containment logic out of the platform-neutral test set with it.
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
/// Chosen as `/tmp/sandbox-shared` because it is world-traversable, and so the
/// host-side read succeeds whichever principal performs it.
///
/// **Which principal that is depends on a mode**, and the distinction is worth
/// stating because the constraint below is only binding in one of them. In the
/// default configuration — per-operator gateways off, which is every install
/// that has not set `SANDBOX_PER_OPERATOR_GATEWAY` — there is a single gateway
/// VM owned by the **daemon user** (`_sandboxd`), and that user, not the
/// operator, reads the host side. With per-operator gateways enabled each
/// operator's own VM performs the read as that operator.
///
/// Under the default, an operator's home directory is unusable as a source: it
/// is owned by the operator with mode 0750 and `_sandboxd` is outside its
/// group, so the daemon user cannot even traverse into a workspace there. (TCC
/// adds a second gate on top of that for Desktop / Documents / Downloads, but
/// the ownership and mode bits are what rule out home-directory paths in
/// general.) Operators whose workspaces live elsewhere must either (a) stage
/// the content under this root, (b) set `SANDBOX_LITE_SHARED_ROOT` to a parent
/// of their workspace that `_sandboxd` can traverse, or (c) use `clone:` /
/// `--repo`, the operator-uid transfer commands (`sandbox sync`, `sandbox cp`),
/// or the full backend instead of lite `shared:`.
///
/// The root stays a single daemon-wide path in either mode: it is exported to
/// the VM as a whole, not per session, so every session on that VM sees all of
/// it. That is a reason to keep it a dedicated staging directory rather than
/// widening it to something an operator already keeps other things in — see
/// [`reject_guest_planted_symlink`] for the cross-session hazard that follows
/// from the export being VM-wide.
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

/// Generate the Lima `mounts:` 9p stanza for the lite shared-workspace roots.
///
/// The stanza exposes each root read-write into the gateway Lima VM at the
/// same absolute path (identity mount), using the `mapped-xattr` 9p security
/// model (consistent with per-session VM mounts). The `mmap` cache mode
/// matches the existing per-session precedent in `lima.rs`.
///
/// The returned string is a YAML fragment intended to be inserted between the
/// `portForwards:` block and the `containerd:` block in the gateway Lima
/// template.
///
/// # An empty set is an empty string, not an empty `mounts:`
///
/// A gateway with nothing to export must emit no `mountType:` and no
/// `mounts:` at all. `mounts:` with no items parses as a null value rather
/// than an empty list, and `mountType: "9p"` with nothing to mount states a
/// mount type for mounts that do not exist. Both are avoidable by emitting
/// nothing, and nothing is what the default configuration produces once a
/// root set is a declaration rather than a constant.
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
///   - location: "/Users/alice/src"
///     writable: true
///     9p:
///       securityModel: "mapped-xattr"
///       cache: "mmap"
/// ```
///
/// # Why `mapped-xattr`, and why not the alternatives
///
/// `mapped-xattr` is written here deliberately: it is *not* the 9p default.
/// Lima defaults to `none`, which upstream chose specifically so that symlinks
/// round-trip. Overriding a default costs something, so the reasoning is
/// recorded rather than left to be re-derived by whoever next reads a symlink
/// bug report.
///
/// **`passthrough` is not available at all.** It makes the host filesystem the
/// ground truth: a guest `chown` or mode change applies literally to the host
/// inode, which requires the QEMU process to be able to honour it — in
/// practice root, or `CAP_CHOWN` + `CAP_FOWNER` + `CAP_DAC_OVERRIDE`. This
/// gateway's QEMU runs as an ordinary user account and the sandbox runs
/// untrusted code by design, so granting that would hand a compromised in-VM
/// agent a host-side ownership-and-mode primitive over the shared directory —
/// dropping a setuid binary that outlives the session, re-owning host files to
/// the calling user. The cost exceeds the benefit, and it is the same call
/// already made for per-session VM mounts.
///
/// **`none` is passthrough minus the strict error reporting**, and the second
/// half is the part that is easy to state backwards. It does *not* mean the
/// host inode takes on the guest's view. Metadata operations the QEMU user
/// cannot perform — `chown` to another uid, `mknod`, setting setuid bits —
/// **silently succeed and have no underlying effect**: the guest sees success
/// and a later `stat` shows the file unchanged. Only operations the QEMU user
/// could have performed anyway actually land. What `none` genuinely buys is
/// symlinks: a guest `ln -s` becomes a real host symlink, so a host-side
/// `canonicalize` can see it, which is exactly the blindness
/// [`reject_guest_planted_symlink`] exists to work around.
///
/// **Kept at `mapped-xattr` anyway.** Switching to `none` would remove the
/// host-side blindness, but the containment decision no longer *depends* on
/// host-side visibility — it is made inside the VM, in the namespace the path
/// is actually used in, and is therefore correct under either model. So `none`
/// would retire no check while adding a surface where a guest is told its
/// metadata operation worked when it did not. That is a worse trade than the
/// one it replaces, and the migration would also change the meaning of every
/// file already staged under an existing export.
pub fn lite_shared_root_9p_stanza(shared_roots: &[PathBuf]) -> String {
    if shared_roots.is_empty() {
        return String::new();
    }
    let entries = shared_roots
        .iter()
        .map(|root| {
            format!(
                "  - location: \"{location}\"\n    writable: true\n    9p:\n      securityModel: \"mapped-xattr\"\n      cache: \"mmap\"\n",
                location = root.display()
            )
        })
        .collect::<String>();
    format!("mountType: \"9p\"\nmounts:\n{entries}")
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
/// in. The live path reaches [`validate_shared_path`] through the daemon's
/// `shared:` containment helper and then binds the spelling the gateway VM
/// resolved, which under an identity mount is this function's result without
/// the round trip.
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

// ---------------------------------------------------------------------------
// Guest-planted symlinks in the 9p export
// ---------------------------------------------------------------------------

/// The extended attribute QEMU's `mapped-xattr` 9p security model uses to
/// store a guest inode's mode — including its file-type bits — on the host.
pub const VIRTFS_MODE_XATTR: &str = "user.virtfs.mode";

/// `S_IFMT` — the file-type field of a mode word.
const S_IFMT: u32 = 0o170_000;
/// `S_IFLNK` — the file-type value that says "symbolic link".
const S_IFLNK: u32 = 0o120_000;

/// Decode a `user.virtfs.mode` value into a mode word.
///
/// # Why two lengths
///
/// QEMU writes `sizeof(mode_t)` bytes, and `mode_t` is 16-bit on Darwin and
/// 32-bit on Linux. The gateway QEMU runs on the host reading this attribute,
/// so 2 is what a macOS host sees; 4 is accepted so the decode is not silently
/// wrong if the host side ever moves.
///
/// # Why little-endian
///
/// Measured, not derived: a guest `ln -s /run escape` under a `mapped-xattr`
/// export stores `FF A1` — `0xA1FF`, i.e. `S_IFLNK | 0777` — on an
/// Apple-Silicon host. Host byte order and little-endian are indistinguishable
/// on every platform this daemon runs on, so the measurement does not
/// discriminate between the two readings and this code does not claim to know
/// which QEMU intends.
///
/// Returns `None` for any other length rather than guessing. See
/// [`reject_guest_planted_symlink`] for what the caller does with that.
pub fn decode_virtfs_mode(raw: &[u8]) -> Option<u32> {
    match raw {
        [lo, hi] => Some(u32::from(u16::from_le_bytes([*lo, *hi]))),
        [a, b, c, d] => Some(u32::from_le_bytes([*a, *b, *c, *d])),
        _ => None,
    }
}

/// Refuse a `shared:` path any of whose components below the root is a
/// symlink the guest planted.
///
/// # What this catches that resolving inside the VM does not
///
/// The in-VM resolve is the authority on *where a path lands*, and it is what
/// stops an escape out of the export. It cannot object to a link that lands
/// back **inside** the root — and one session planting
/// `proj/link -> ../other-session` so that a later `shared:proj/link` reads a
/// second session's workspace is exactly such a link. The resolve reports
/// `Inside` and is right to. This check is what refuses it.
///
/// It also produces the better message for the case both cover, because it
/// knows *which component* is the link rather than only where the whole path
/// ended up.
///
/// # Why the host cannot just `lstat` for this
///
/// Under `mapped-xattr` a guest-created symlink is stored host-side as an
/// ordinary regular file whose contents are the link target; `lstat` reports
/// `S_IFREG` and `canonicalize` walks straight past it. The type is in the
/// extended attribute and nowhere else, so reading the attribute is the only
/// way to see it from the host.
///
/// A *host*-created symlink needs none of this — it is a real symlink and
/// `validate_shared_path`'s caller sees it as one.
///
/// # Where it starts, and where it does not
///
/// Components are walked from the root downwards. The root itself is not
/// checked: it is the host side of the mount, created by the daemon before
/// the VM boots, and a guest cannot replace the directory it is exported
/// through.
///
/// # What an undecodable attribute does, and the dependency that makes that
/// acceptable
///
/// An attribute present but of an unexpected length is logged and skipped
/// rather than treated as a refusal, because refusing would break every
/// `shared:` path on a host whose QEMU stores it differently — a total outage
/// in exchange for a case nobody has seen. That is only tolerable because the
/// in-VM resolve runs unconditionally behind this and is the check that
/// bounds the escape. **This is therefore a supporting measure and must not
/// become the only one**: making the resolve conditional on anything would
/// silently promote this fail-open path into the whole guard.
pub fn reject_guest_planted_symlink(
    host_path: &Path,
    shared_root: &Path,
    read_virtfs_mode: &dyn Fn(&Path) -> Option<Vec<u8>>,
) -> Result<(), SharedPathError> {
    let relative =
        host_path
            .strip_prefix(shared_root)
            .map_err(|_| SharedPathError::OutsideRoot {
                host_path: host_path.to_path_buf(),
                shared_root: shared_root.to_path_buf(),
            })?;

    let mut prefix = shared_root.to_path_buf();
    for component in relative.components() {
        prefix.push(component);
        let Some(raw) = read_virtfs_mode(&prefix) else {
            continue;
        };
        match decode_virtfs_mode(&raw) {
            Some(mode) if mode & S_IFMT == S_IFLNK => {
                return Err(SharedPathError::GuestPlantedSymlink {
                    host_path: host_path.to_path_buf(),
                    shared_root: shared_root.to_path_buf(),
                    component: prefix.clone(),
                });
            }
            Some(_) => {}
            None => tracing::warn!(
                path = %prefix.display(),
                len = raw.len(),
                "{VIRTFS_MODE_XATTR} is present but is neither 2 nor 4 bytes; \
                 cannot tell whether this component is a guest-planted symlink. \
                 Containment for this path now rests entirely on resolving it \
                 inside the VM."
            ),
        }
    }
    Ok(())
}

/// Read [`VIRTFS_MODE_XATTR`] off `path` without following a symlink.
///
/// `None` covers every reason the attribute is not readable as bytes — absent
/// (the overwhelmingly common case: any file the host created), path gone,
/// permission denied. The caller treats all of them as "nothing to object
/// to", which is correct for the first and is the same fail-open the
/// undecodable case takes for the rest; see [`reject_guest_planted_symlink`].
///
/// `XATTR_NOFOLLOW` is not optional. Without it a host symlink at the final
/// component would be followed and the attribute read off the target, which
/// answers a question about the wrong inode.
#[cfg(target_os = "macos")]
pub fn read_virtfs_mode_xattr(path: &Path) -> Option<Vec<u8>> {
    use std::os::unix::ffi::OsStrExt;

    let c_path = std::ffi::CString::new(path.as_os_str().as_bytes()).ok()?;
    let c_name = std::ffi::CString::new(VIRTFS_MODE_XATTR).ok()?;

    // SAFETY: both pointers are NUL-terminated C strings that outlive the
    // call. A null value pointer with a zero size is the documented way to
    // ask only for the length.
    let size = unsafe {
        libc::getxattr(
            c_path.as_ptr(),
            c_name.as_ptr(),
            std::ptr::null_mut(),
            0,
            0,
            libc::XATTR_NOFOLLOW,
        )
    };
    if size < 0 {
        return None;
    }

    let mut buf = vec![0u8; size as usize];
    // SAFETY: `buf` has exactly `size` bytes of capacity and is written by the
    // kernel for at most that many.
    let read = unsafe {
        libc::getxattr(
            c_path.as_ptr(),
            c_name.as_ptr(),
            buf.as_mut_ptr().cast(),
            buf.len(),
            0,
            libc::XATTR_NOFOLLOW,
        )
    };
    if read < 0 {
        return None;
    }
    buf.truncate(read as usize);
    Some(buf)
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
    /// A component of the requested path is a symlink created from inside a
    /// sandbox. `component` is the full path to that component, not just its
    /// name — the operator has to be able to go delete it, and under
    /// `mapped-xattr` `ls -l` on the host will not show them which one it is.
    GuestPlantedSymlink {
        host_path: PathBuf,
        shared_root: PathBuf,
        component: PathBuf,
    },
}

impl std::fmt::Display for SharedPathError {
    /// Every rendering here is surfaced to an operator verbatim, so each names
    /// the real cause and the alternatives rather than only restating the rule.
    /// Keep them self-contained.
    ///
    /// # `OutsideRoot` is no longer the outside-the-export refusal
    ///
    /// It was, while a gateway exported exactly one root. A gateway now exports
    /// a *set*, and "outside the export" is a question about the whole set —
    /// which this type cannot ask, because it is handed one root. The daemon
    /// therefore decides it before calling in, and renders its own refusal
    /// naming every exported root and how to add one. This variant survives as
    /// the single-root answer for [`translate_shared_path`] and as the
    /// unreachable arm of [`validate_shared_path`] once the daemon has already
    /// selected a containing root — not as the message an operator meets.
    ///
    /// Read the rest of this paragraph as the *bar* that message has to clear
    /// rather than as a description of where it is now written. Two causes, and
    /// they are stated in that order deliberately. The first is
    /// unconditional: the shared root is the *only* host path exported into the
    /// gateway VM, so a path outside it does not exist in the namespace the
    /// container mounts from — no permission change on the host can make it
    /// appear. The second explains why the root sits where it does, and it is
    /// Unix ownership rather than TCC: in the default configuration the VM is
    /// the daemon user's, so `_sandboxd` performs the host-side read and cannot
    /// traverse an operator-owned home directory. That second half is
    /// mode-dependent — with per-operator gateways enabled the operator's own
    /// VM does the read — which is exactly why it is the supporting reason here
    /// and not the headline. Getting the order wrong would leave an operator on
    /// a per-operator install concluding the refusal no longer applies to them.
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
                 On the lite backend the sandbox container runs inside a gateway VM, and \
                 {root} is the only host directory exported into that VM — a path outside \
                 it is not in the filesystem the container mounts from, so no change of \
                 permissions on the host makes it usable. The root is where it is because, \
                 unless per-operator gateways are enabled, the VM belongs to the sandboxd \
                 daemon user (`_sandboxd`) and that user — not you — performs the host-side \
                 read; it cannot traverse your home directory (owned by you, mode 0750, with \
                 `_sandboxd` outside its group). What works instead: \
                 (a) clone:<repo-url> or --repo for a git-backed project — the clone runs \
                 inside the guest and never reads the host filesystem; \
                 (b) `sandbox sync` / `sandbox cp` (and `sandbox workspace push|pull` on a \
                 local: workspace), which run as your own uid over the daemon-mediated SSH \
                 proxy and so are not bound by the export at all; \
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
            SharedPathError::GuestPlantedSymlink {
                host_path,
                shared_root,
                component,
            } => write!(
                f,
                "lite shared: path {host} passes through {component}, which is a symbolic \
                 link created from inside a sandbox rather than by you. Following it would \
                 mount whatever it points at — possibly another session's workspace, or \
                 somewhere outside {root} entirely — under a path that looks like your own. \
                 It will not show up as a link in `ls -l`: the gateway VM's export stores a \
                 guest symlink as an ordinary file plus an extended attribute, so the host \
                 sees a small regular file whose contents are the target. Read it with \
                 `cat {component}` to see where it points, and `xattr -px \
                 {xattr} {component}` to confirm the type. What works instead: \
                 (a) delete or replace the link (`rm {component}`) if it is not wanted, then \
                 retry; \
                 (b) pass the path the link points at directly, if that path is itself under \
                 {root}; or \
                 (c) stage the content you want under a fresh directory beneath {root} and \
                 point shared: there.",
                host = host_path.display(),
                root = shared_root.display(),
                component = component.display(),
                xattr = VIRTFS_MODE_XATTR,
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

    // -- Guest-planted symlinks ----------------------------------------------
    //
    // The byte patterns below are not invented. They were read off a live
    // `mapped-xattr` export on an Apple-Silicon host: `ln -s /run escape`
    // inside the guest, then `xattr -px user.virtfs.mode` on the macOS side.
    // A guest regular file and a guest directory were measured alongside so
    // the symlink case is distinguished from its neighbours rather than
    // merely recognised on its own.

    /// `S_IFLNK | 0777` as a Darwin 16-bit `mode_t`, little-endian.
    const MEASURED_GUEST_SYMLINK: [u8; 2] = [0xFF, 0xA1];
    /// `S_IFREG | 0644`, same encoding.
    const MEASURED_GUEST_FILE: [u8; 2] = [0xA4, 0x81];
    /// `S_IFDIR | 0775`, same encoding.
    const MEASURED_GUEST_DIR: [u8; 2] = [0xFD, 0x41];

    #[test]
    fn the_measured_mode_bytes_decode_to_the_types_they_were_read_from() {
        assert_eq!(decode_virtfs_mode(&MEASURED_GUEST_SYMLINK), Some(0o120_777));
        assert_eq!(decode_virtfs_mode(&MEASURED_GUEST_FILE), Some(0o100_644));
        assert_eq!(decode_virtfs_mode(&MEASURED_GUEST_DIR), Some(0o040_775));
    }

    /// A Linux host stores the same mode in four bytes, and the high half is
    /// zero for every mode that exists — so a decoder that only looked at the
    /// first two bytes would pass this test by accident. The value here is
    /// `S_IFLNK | 0777` widened, which has a non-zero third byte.
    #[test]
    fn a_four_byte_mode_is_decoded_whole_rather_than_truncated() {
        assert_eq!(
            decode_virtfs_mode(&[0xFF, 0xA1, 0x00, 0x00]),
            Some(0o120_777)
        );
        assert_eq!(
            decode_virtfs_mode(&[0x00, 0x00, 0x01, 0x00]).map(|m| m & S_IFMT),
            Some(0),
            "a mode whose bits live above the low half must not be read as a \
             low-half value",
        );
    }

    #[test]
    fn an_unexpected_attribute_length_decodes_to_nothing_rather_than_a_guess() {
        assert_eq!(decode_virtfs_mode(&[]), None);
        assert_eq!(decode_virtfs_mode(&[0xFF]), None);
        assert_eq!(decode_virtfs_mode(&[0xFF, 0xA1, 0x00]), None);
    }

    /// Reader that answers for exactly the paths given to it.
    fn reader_for(entries: &[(&'static str, [u8; 2])]) -> impl Fn(&Path) -> Option<Vec<u8>> {
        let owned: Vec<(PathBuf, Vec<u8>)> = entries
            .iter()
            .map(|(p, m)| (PathBuf::from(p), m.to_vec()))
            .collect();
        move |path: &Path| {
            owned
                .iter()
                .find(|(p, _)| p == path)
                .map(|(_, m)| m.clone())
        }
    }

    #[test]
    fn a_guest_symlink_at_an_intermediate_component_is_refused() {
        let reader = reader_for(&[
            ("/tmp/shared/proj", MEASURED_GUEST_DIR),
            ("/tmp/shared/proj/link", MEASURED_GUEST_SYMLINK),
        ]);
        let err = reject_guest_planted_symlink(
            Path::new("/tmp/shared/proj/link/src"),
            Path::new("/tmp/shared"),
            &reader,
        )
        .expect_err("an intermediate guest symlink must be refused");

        match err {
            SharedPathError::GuestPlantedSymlink { component, .. } => assert_eq!(
                component,
                PathBuf::from("/tmp/shared/proj/link"),
                "the refusal must name the component that is the link, not the \
                 whole path — the operator has to be able to go delete it",
            ),
            other => panic!("wrong variant: {other:?}"),
        }
    }

    /// The property the in-VM resolve cannot supply: a link that lands back
    /// inside the export is `Inside` and would be allowed, yet it reaches
    /// another session's workspace.
    #[test]
    fn a_guest_symlink_is_refused_even_though_it_points_back_inside_the_root() {
        let reader = reader_for(&[(
            "/tmp/shared/mine/peek",
            MEASURED_GUEST_SYMLINK, // -> ../other-session, still under the root
        )]);
        assert!(
            reject_guest_planted_symlink(
                Path::new("/tmp/shared/mine/peek"),
                Path::new("/tmp/shared"),
                &reader,
            )
            .is_err(),
            "containment is not the only question this measure answers; a link \
             that stays inside the root still crosses between sessions",
        );
    }

    #[test]
    fn guest_files_and_directories_along_the_path_are_not_mistaken_for_links() {
        let reader = reader_for(&[
            ("/tmp/shared/proj", MEASURED_GUEST_DIR),
            ("/tmp/shared/proj/src", MEASURED_GUEST_DIR),
            ("/tmp/shared/proj/src/main.rs", MEASURED_GUEST_FILE),
        ]);
        assert!(
            reject_guest_planted_symlink(
                Path::new("/tmp/shared/proj/src/main.rs"),
                Path::new("/tmp/shared"),
                &reader,
            )
            .is_ok(),
            "only S_IFLNK is a link; a guest-created file or directory is \
             ordinary content",
        );
    }

    /// Host-created content carries no attribute at all. That is the common
    /// case, and it must not read as suspicious.
    #[test]
    fn a_path_with_no_virtfs_attributes_is_accepted() {
        assert!(
            reject_guest_planted_symlink(
                Path::new("/tmp/shared/proj/src"),
                Path::new("/tmp/shared"),
                &|_| None,
            )
            .is_ok()
        );
    }

    /// The root is the host side of the mount. The daemon creates it before
    /// the VM boots and a guest cannot replace it, so it is not walked — and
    /// an attribute sitting on it must not be read as a refusal.
    #[test]
    fn the_shared_root_itself_is_not_walked() {
        let reader = reader_for(&[("/tmp/shared", MEASURED_GUEST_SYMLINK)]);
        assert!(
            reject_guest_planted_symlink(
                Path::new("/tmp/shared/proj"),
                Path::new("/tmp/shared"),
                &reader,
            )
            .is_ok()
        );
    }

    #[test]
    fn an_undecodable_attribute_falls_through_to_the_in_vm_resolve() {
        let owned = [(PathBuf::from("/tmp/shared/proj"), vec![0xFF, 0xA1, 0x00])];
        let reader = move |path: &Path| {
            owned
                .iter()
                .find(|(p, _)| p == path)
                .map(|(_, m)| m.clone())
        };
        assert!(
            reject_guest_planted_symlink(
                Path::new("/tmp/shared/proj"),
                Path::new("/tmp/shared"),
                &reader,
            )
            .is_ok(),
            "an attribute this code cannot read must not take down every \
             shared: path on the host; the resolve behind it is what bounds \
             the escape",
        );
    }

    #[test]
    fn a_path_outside_the_root_is_reported_as_such_rather_than_walked() {
        let err = reject_guest_planted_symlink(
            Path::new("/etc/passwd"),
            Path::new("/tmp/shared"),
            &|_| panic!("nothing under the root to walk"),
        )
        .expect_err("must refuse");
        assert!(matches!(err, SharedPathError::OutsideRoot { .. }));
    }

    #[test]
    fn the_guest_symlink_refusal_names_the_cause_and_the_alternatives() {
        let msg = SharedPathError::GuestPlantedSymlink {
            host_path: PathBuf::from("/tmp/shared/proj/link/src"),
            shared_root: PathBuf::from("/tmp/shared"),
            component: PathBuf::from("/tmp/shared/proj/link"),
        }
        .to_string();

        assert!(
            msg.contains("/tmp/shared/proj/link"),
            "must name the offending component: {msg}"
        );
        assert!(
            msg.contains("created from inside a sandbox"),
            "must name the cause rather than restating the rule: {msg}"
        );
        assert!(
            msg.contains("will not show up as a link in `ls -l`"),
            "must warn that the host view contradicts the refusal, or the \
             operator will read it as a false positive: {msg}"
        );
        assert!(
            msg.contains("rm /tmp/shared/proj/link") && msg.contains("stage the content"),
            "must offer working alternatives: {msg}"
        );
    }

    /// The one part that cannot be exercised off Darwin: that
    /// [`read_virtfs_mode_xattr`] reads the attribute this module names, and
    /// reads it off the named inode rather than off a symlink's target.
    #[cfg(target_os = "macos")]
    #[test]
    fn the_xattr_reader_reads_the_named_inode_and_not_a_link_target() {
        use std::os::unix::ffi::OsStrExt;

        let dir = tempfile::tempdir().expect("tempdir");
        let target = dir.path().join("target");
        std::fs::write(&target, b"x").expect("write target");
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&target, &link).expect("symlink");

        assert_eq!(
            read_virtfs_mode_xattr(&target),
            None,
            "a file with no such attribute must read as absent, not as an error \
             the caller cannot distinguish"
        );

        let c_target = std::ffi::CString::new(target.as_os_str().as_bytes()).unwrap();
        let c_name = std::ffi::CString::new(VIRTFS_MODE_XATTR).unwrap();
        // SAFETY: both are NUL-terminated and outlive the call; the value
        // buffer is a live slice of the declared length.
        let rc = unsafe {
            libc::setxattr(
                c_target.as_ptr(),
                c_name.as_ptr(),
                MEASURED_GUEST_SYMLINK.as_ptr().cast(),
                MEASURED_GUEST_SYMLINK.len(),
                0,
                libc::XATTR_NOFOLLOW,
            )
        };
        assert_eq!(rc, 0, "setxattr on the temp file must succeed");

        assert_eq!(
            read_virtfs_mode_xattr(&target).as_deref(),
            Some(&MEASURED_GUEST_SYMLINK[..]),
            "the attribute must round-trip verbatim"
        );
        assert_eq!(
            read_virtfs_mode_xattr(&link),
            None,
            "XATTR_NOFOLLOW must make the read describe the link itself; \
             following it would answer about the target's inode instead"
        );
    }

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
        let roots = [PathBuf::from("/tmp/sandbox-shared")];
        let stanza = lite_shared_root_9p_stanza(&roots);
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
        let roots = [PathBuf::from("/Users/alice/workspaces")];
        let stanza = lite_shared_root_9p_stanza(&roots);
        assert!(stanza.contains("/Users/alice/workspaces"));
    }

    #[test]
    fn lite_shared_root_9p_stanza_is_empty_for_an_empty_root_set() {
        // Not `mounts:` with no items — that parses as a null value, and a
        // `mountType:` naming a type for mounts that do not exist is a claim
        // about nothing. A gateway with nothing to export emits neither key.
        assert_eq!(lite_shared_root_9p_stanza(&[]), "");
    }

    #[test]
    fn lite_shared_root_9p_stanza_emits_one_entry_per_root() {
        let roots = [
            PathBuf::from("/tmp/sandbox-shared"),
            PathBuf::from("/Users/alice/src"),
            PathBuf::from("/Users/alice/scratch"),
        ];
        let stanza = lite_shared_root_9p_stanza(&roots);

        // One top-level `mountType:` and one top-level `mounts:` for the whole
        // set — emitting them per entry is the silent-fallback bug the format
        // note on the generator describes.
        assert_eq!(stanza.matches("mountType:").count(), 1, "{stanza}");
        assert_eq!(stanza.matches("mounts:").count(), 1, "{stanza}");
        assert_eq!(stanza.matches("- location:").count(), 3, "{stanza}");

        // Declaration order is preserved, so the template a reader compares
        // against the declaration file reads in the same order as the file.
        let positions: Vec<usize> = roots
            .iter()
            .map(|r| {
                stanza
                    .find(&format!("location: \"{}\"", r.display()))
                    .unwrap_or_else(|| panic!("{} missing from {stanza}", r.display()))
            })
            .collect();
        assert!(
            positions.windows(2).all(|w| w[0] < w[1]),
            "roots must appear in declaration order: {positions:?} in {stanza}"
        );

        // Every entry carries its own options block; a root that inherited
        // nothing would mount with Lima's defaults instead.
        assert_eq!(stanza.matches("writable: true").count(), 3, "{stanza}");
        assert_eq!(
            stanza.matches("securityModel: \"mapped-xattr\"").count(),
            3,
            "{stanza}"
        );
        assert_eq!(stanza.matches("cache: \"mmap\"").count(), 3, "{stanza}");
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

    /// The refusal an operator actually sees must name the real cause and then
    /// point at the paths that do work. Two things are pinned, because the
    /// message has been wrong in two different ways:
    ///
    /// - It once attributed the refusal to macOS TCC, which sent operators
    ///   chasing privacy consent for a problem that is not about consent.
    /// - It then attributed it solely to `_sandboxd` doing the read, which is
    ///   only true while per-operator gateways are off. The unconditional
    ///   reason — the root is the only directory exported into the VM — has to
    ///   be present too, or the message becomes false the moment that switch is
    ///   thrown.
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

        // Headline cause: the root is the only thing exported into the VM.
        // This one holds in every mode, so it is what the operator must read
        // first.
        assert!(msg.contains("only host directory exported"), "got: {msg}");

        // Supporting cause: under the default configuration the daemon user
        // does the read, and ownership/mode — not privacy consent — is what
        // denies it. Carried with its condition, not as a bare assertion.
        assert!(msg.contains("_sandboxd"), "got: {msg}");
        assert!(msg.contains("home directory"), "got: {msg}");
        assert!(
            msg.contains("per-operator gateways are enabled"),
            "the `_sandboxd` claim is mode-dependent and must not be stated flat: {msg}"
        );
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
