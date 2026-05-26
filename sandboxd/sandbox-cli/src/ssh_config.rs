//! `~/.ssh/sandbox/` management module — the CLI-side companion to the
//! daemon's `GET /sessions/{id}/ssh-config` endpoint.
//!
//! Owns the only filesystem mutations the CLI performs under the
//! operator's `$HOME`. Implements the cross-user CLI access spec §
//! Architecture → CLI: persistent ssh-config + thin `sandbox proxy`
//! and the milestone-level layout decisions captured below.
//!
//! # Layout
//!
//! ```text
//! ~/.ssh/                          # mode 0700 (created if absent)
//!   config                         # mode 0600 (created if absent); the
//!                                  # operator-owned ssh client config —
//!                                  # we only insert a managed Include
//!                                  # block at the top, never anywhere
//!                                  # else.
//!   sandbox/                       # mode 0700, owned end-to-end by us
//!     sandbox-<id>                 # mode 0644: per-session OpenSSH
//!                                  # config block (`Host sandbox-<id>`
//!                                  # …), `IdentityFile` rewritten to
//!                                  # the on-disk key path.
//!     sandbox-<id>.key             # mode 0600: per-session private key.
//!     .lock                        # mode 0600: flock target.
//! ```
//!
//! # `Include` line in `~/.ssh/config`
//!
//! A marker-delimited block is inserted at the **very top** of
//! `~/.ssh/config` so SSH's first-match-wins semantics cannot cause an
//! earlier user-authored `Host *` (or `Host sandbox-*`) block to shadow
//! the generated `Host sandbox-<id>` aliases:
//!
//! ```text
//! # >>> sandbox CLI managed >>>
//! Include ~/.ssh/sandbox/sandbox-*[!y]
//! # <<< sandbox CLI managed <<<
//! ```
//!
//! The glob `sandbox-*[!y]` matches every per-session config file
//! (`sandbox-<id>` — `<id>` is exactly 12 lowercase hex chars per
//! `sandbox-core::SessionId`, so the last char is in `[0-9a-f]`, never
//! `y`) while excluding the matching `sandbox-<id>.key` private-key
//! files (which all end in `y`). POSIX `glob(3)` — the same library
//! OpenSSH's `Include` directive uses — supports the `[!...]`
//! character-class negation portably. We pick this over a clean
//! `*.conf` extension because the task description prescribes the
//! `sandbox-<id>` filename verbatim, and a custom suffix would be a
//! gratuitous deviation from the wire-format-adjacent SSH alias name.
//!
//! # Atomicity, concurrency, and crash safety
//!
//! Every mutation — config file write, key file write, `~/.ssh/config`
//! Include block insertion, per-session entry removal, reconcile pass —
//! is wrapped in an exclusive `flock` on `~/.ssh/sandbox/.lock`. The
//! lock survives across CLI invocations, so a concurrent
//! `sandbox ssh` and `sandbox ls --reconcile` cannot race. Every file
//! rewrite stages bytes into a sibling tempfile (in the same directory
//! as the destination so `rename(2)` is atomic on the same filesystem)
//! and commits via `persist`. A SIGKILL between `tempfile.write_all`
//! and `tempfile.persist` leaves the original file untouched.
//!
//! # Reusability across M18-S6 / M18-S7
//!
//! The five SSH-shaped commands the milestone rewrites
//! (`sandbox ssh`, `cp`, `sync`, `workspace push`, `workspace pull`)
//! all go through [`ensure_session_entry`] once per invocation; it
//! takes the daemon's `SshConfigDto` and the session id, writes
//! everything to disk, ensures the global `Include` block, and returns
//! the alias name (`sandbox-<id>`) the caller passes to `ssh` / `scp` /
//! `rsync`. The S7 lifecycle hooks use [`remove_session_entry`]
//! (`sandbox rm` and `sandbox proxy` lazy-404),
//! [`reconcile_against_list`] (`sandbox ls`), and
//! [`query_existing`] (the proxy shim's quick "do I have a stale
//! entry?" probe).

use std::fs::{File, OpenOptions, Permissions};
use std::io::{Read, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use nix::fcntl::FlockArg;
#[allow(deprecated)]
use nix::fcntl::flock;
use sandbox_core::{SSH_CONFIG_IDENTITY_FILE_PLACEHOLDER, SshConfigDto};
use std::os::fd::AsRawFd;
use tempfile::NamedTempFile;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Sub-directory under `~/.ssh/` we own end-to-end.
pub const SANDBOX_DIR_NAME: &str = "sandbox";

/// Per-session ControlMaster socket directory inside
/// `~/.ssh/sandbox/`. The daemon-emitted SSH config block carries
/// `ControlPath ~/.ssh/sandbox/sockets/%C` — OpenSSH creates the
/// per-multiplex socket *file* under that path but does **not**
/// auto-create the parent directory; if `sockets/` is absent the
/// first `ssh sandbox-<id>` call dies with
/// `unix_listener: cannot bind to path …/sockets/<hash>: …`. We
/// pre-create the directory the first time we touch a session entry
/// so the operator never sees that error.
pub const SOCKETS_DIR_NAME: &str = "sockets";

/// Lock file inside `~/.ssh/sandbox/` — flocked exclusive for every
/// mutation in this module.
pub const LOCK_FILE_NAME: &str = ".lock";

/// Opening marker for the managed Include block inside `~/.ssh/config`.
/// The CLI scans for this exact line (and [`INCLUDE_MARKER_END`]) to
/// locate its managed region; everything between the markers belongs to
/// us, everything outside is the operator's.
pub const INCLUDE_MARKER_BEGIN: &str = "# >>> sandbox CLI managed >>>";

/// Closing marker for the managed Include block.
pub const INCLUDE_MARKER_END: &str = "# <<< sandbox CLI managed <<<";

/// `Include` directive line inserted between the markers. The glob
/// `sandbox-*[!y]` picks up every per-session OpenSSH-config file
/// (`sandbox-<id>`, where `<id>` is 12 lowercase-hex chars) without
/// pulling in the matching `sandbox-<id>.key` private-key files (whose
/// names all end in `y`). Glob negation `[!...]` is POSIX-standard and
/// recognised by OpenSSH's underlying `glob(3)` call.
pub const INCLUDE_LINE: &str = "Include ~/.ssh/sandbox/sandbox-*[!y]";

// File mode bits.
const MODE_DIR_PRIVATE: u32 = 0o700;
const MODE_FILE_KEY: u32 = 0o600;
const MODE_FILE_CONFIG: u32 = 0o644;
const MODE_FILE_SSH_CONFIG: u32 = 0o600;
const MODE_FILE_LOCK: u32 = 0o600;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Failure modes the management module surfaces. Each variant carries
/// enough context for the CLI's outermost error renderer to construct
/// an operator-actionable message.
#[derive(Debug, thiserror::Error)]
pub enum SshConfigError {
    /// I/O error reaching the SSH config area.
    #[error("ssh-config {op} failed on {path}: {source}")]
    Io {
        op: &'static str,
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    /// The home directory could not be resolved. We never auto-fall-
    /// back to `/tmp` or similar — without a real `$HOME` the operator
    /// would not see their config later, which is worse than failing
    /// loud.
    #[error("cannot resolve home directory (set $HOME)")]
    NoHome,
    /// The daemon-emitted config block did not contain the
    /// `<CLI-rewrites-this>` placeholder token. Treated as a wire-
    /// format break — likely a daemon ⇄ CLI version skew.
    #[error(
        "daemon-emitted SSH config block is missing the `{placeholder}` placeholder; \
         the CLI cannot rewrite IdentityFile. Daemon version skew?"
    )]
    MissingPlaceholder { placeholder: &'static str },
    /// The session id supplied by the caller did not parse as a valid
    /// lowercase-hex session id. We refuse to write files for an
    /// invalid id rather than smuggle the bytes onto the filesystem.
    #[error("invalid session id `{id}`: must be 12 lowercase hex characters")]
    InvalidSessionId { id: String },
}

impl SshConfigError {
    fn io(op: &'static str, path: &Path, source: std::io::Error) -> Self {
        Self::Io {
            op,
            path: path.to_path_buf(),
            source,
        }
    }
}

// ---------------------------------------------------------------------------
// Path helpers
// ---------------------------------------------------------------------------

/// `~/.ssh/` for the given `$HOME` root.
pub fn ssh_dir(home: &Path) -> PathBuf {
    home.join(".ssh")
}

/// `~/.ssh/config` for the given `$HOME` root.
pub fn ssh_config_path(home: &Path) -> PathBuf {
    ssh_dir(home).join("config")
}

/// `~/.ssh/sandbox/` for the given `$HOME` root.
pub fn sandbox_dir(home: &Path) -> PathBuf {
    ssh_dir(home).join(SANDBOX_DIR_NAME)
}

/// `~/.ssh/sandbox/.lock` — the flock target.
pub fn lock_path(home: &Path) -> PathBuf {
    sandbox_dir(home).join(LOCK_FILE_NAME)
}

/// `~/.ssh/sandbox/sockets/` — the ControlMaster socket directory the
/// daemon-emitted SSH config block (`ControlPath
/// ~/.ssh/sandbox/sockets/%C`) writes its multiplex sockets into.
pub fn sockets_dir(home: &Path) -> PathBuf {
    sandbox_dir(home).join(SOCKETS_DIR_NAME)
}

/// Per-session OpenSSH-config file: `~/.ssh/sandbox/sandbox-<id>`.
pub fn session_config_path(home: &Path, id: &str) -> PathBuf {
    sandbox_dir(home).join(format!("sandbox-{id}"))
}

/// Per-session private-key file: `~/.ssh/sandbox/sandbox-<id>.key`.
pub fn session_key_path(home: &Path, id: &str) -> PathBuf {
    sandbox_dir(home).join(format!("sandbox-{id}.key"))
}

/// The SSH `Host` alias for a session — `sandbox-<id>`. The same string
/// the daemon-emitted config block uses as its `Host` directive value.
pub fn ssh_alias_for(id: &str) -> String {
    format!("sandbox-{id}")
}

/// Validate that `id` is a 12-char lowercase-hex string. Mirrors
/// `sandbox_core::SessionId::parse`'s alphabet check; we keep the
/// validation local to avoid pulling the type-level wrapper through
/// every caller (the daemon DTO carries the id as a `String`).
fn validate_session_id(id: &str) -> Result<(), SshConfigError> {
    let ok = id.len() == 12
        && id
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
    if ok {
        Ok(())
    } else {
        Err(SshConfigError::InvalidSessionId { id: id.to_string() })
    }
}

// ---------------------------------------------------------------------------
// `$HOME` resolution
// ---------------------------------------------------------------------------

/// Resolve `$HOME`. Refuses to silently fall back to a tempdir or any
/// other location — the operator's persistent SSH config must land in
/// their real home directory so external tools (`ssh` from a shell,
/// VS Code Remote-SSH, etc.) pick it up.
pub fn resolve_home() -> Result<PathBuf, SshConfigError> {
    std::env::var_os("HOME")
        .filter(|s| !s.is_empty())
        .map(PathBuf::from)
        .ok_or(SshConfigError::NoHome)
}

// ---------------------------------------------------------------------------
// Directory + lock setup
// ---------------------------------------------------------------------------

/// Ensure `~/.ssh/` exists with mode 0700.
fn ensure_ssh_dir(home: &Path) -> Result<PathBuf, SshConfigError> {
    let dir = ssh_dir(home);
    create_dir_if_missing(&dir, MODE_DIR_PRIVATE)?;
    Ok(dir)
}

/// Ensure `~/.ssh/sandbox/` exists with mode 0700. Also ensures
/// `~/.ssh/` exists first.
fn ensure_sandbox_dir(home: &Path) -> Result<PathBuf, SshConfigError> {
    ensure_ssh_dir(home)?;
    let dir = sandbox_dir(home);
    create_dir_if_missing(&dir, MODE_DIR_PRIVATE)?;
    Ok(dir)
}

/// Ensure `~/.ssh/sandbox/sockets/` exists with mode 0700. The
/// daemon-emitted SSH config block carries
/// `ControlPath ~/.ssh/sandbox/sockets/%C`; OpenSSH creates the per-
/// multiplex socket file under that path but does not auto-create the
/// parent directory. Pre-creating it sidesteps the
/// `unix_listener: cannot bind` error operators would otherwise see on
/// the first `ssh sandbox-<id>` call for a fresh `$HOME`.
fn ensure_sockets_dir(home: &Path) -> Result<PathBuf, SshConfigError> {
    ensure_sandbox_dir(home)?;
    let dir = sockets_dir(home);
    create_dir_if_missing(&dir, MODE_DIR_PRIVATE)?;
    Ok(dir)
}

/// `mkdir -p` for a single level: create `path` if missing; if present,
/// tighten the mode bits to `mode` (so a previous 0755 directory is
/// brought down to 0700 the first time we touch it). On the create
/// branch we set the mode via `DirBuilder` so we never momentarily
/// expose a wider-than-intended view of the directory.
fn create_dir_if_missing(path: &Path, mode: u32) -> Result<(), SshConfigError> {
    use std::fs::DirBuilder;
    if path.exists() {
        // Re-tighten mode in case the directory was created earlier
        // with a wider umask.
        let perm = Permissions::from_mode(mode);
        std::fs::set_permissions(path, perm).map_err(|e| SshConfigError::io("chmod", path, e))?;
        return Ok(());
    }
    let mut builder = DirBuilder::new();
    builder.mode(mode);
    builder
        .create(path)
        .map_err(|e| SshConfigError::io("mkdir", path, e))?;
    Ok(())
}

/// Open (creating if missing) the lock file at `~/.ssh/sandbox/.lock`
/// with mode 0600. The handle owns the kernel-level advisory lock; the
/// caller takes `LockGuard::acquire_exclusive` to actually flock it.
fn open_lock_file(home: &Path) -> Result<File, SshConfigError> {
    ensure_sandbox_dir(home)?;
    let path = lock_path(home);
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(MODE_FILE_LOCK)
        .open(&path)
        .map_err(|e| SshConfigError::io("open", &path, e))?;
    // Re-tighten mode in case the file existed under a different mode.
    std::fs::set_permissions(&path, Permissions::from_mode(MODE_FILE_LOCK))
        .map_err(|e| SshConfigError::io("chmod", &path, e))?;
    Ok(file)
}

/// RAII guard around an exclusive `flock`. Dropping the guard closes
/// the FD, which the kernel interprets as releasing the advisory lock.
struct LockGuard {
    _file: File,
}

impl LockGuard {
    /// Acquire an exclusive blocking flock on the lock file.
    ///
    /// Blocking is the right behaviour here: every CLI invocation that
    /// mutates `~/.ssh/sandbox/` does so for a few milliseconds at
    /// most; making one wait for the other is the contention-correct
    /// outcome (versus failing loudly, which would force every
    /// `sandbox ssh` caller to retry).
    fn acquire_exclusive(home: &Path) -> Result<Self, SshConfigError> {
        let file = open_lock_file(home)?;
        let fd = file.as_raw_fd();
        #[allow(deprecated)]
        // `nix::fcntl::flock(fd, FlockArg)` is the same pre-deprecation
        // call the `sandbox update` lock module uses. The deprecation
        // suggests `Flock::lock` but that returns an owned handle the
        // existing call sites are not yet plumbed for; we follow the
        // same `#[allow(deprecated)]` ratchet update::lock.rs ships.
        flock(fd, FlockArg::LockExclusive).map_err(|errno| {
            SshConfigError::io(
                "flock",
                &lock_path(home),
                std::io::Error::from_raw_os_error(errno as i32),
            )
        })?;
        Ok(Self { _file: file })
    }
}

// ---------------------------------------------------------------------------
// Atomic write helper
// ---------------------------------------------------------------------------

/// Stage `bytes` into a sibling tempfile under `dir`, set the mode,
/// then atomically rename onto `final_path`. The tempfile is created
/// with `tempfile::NamedTempFile` so a panic between create and persist
/// auto-unlinks the partial file.
fn atomic_write(
    dir: &Path,
    final_path: &Path,
    bytes: &[u8],
    mode: u32,
) -> Result<(), SshConfigError> {
    let mut tmp = NamedTempFile::new_in(dir).map_err(|e| SshConfigError::io("mktemp", dir, e))?;
    tmp.write_all(bytes)
        .map_err(|e| SshConfigError::io("write", tmp.path(), e))?;
    tmp.as_file_mut()
        .sync_all()
        .map_err(|e| SshConfigError::io("fsync", tmp.path(), e))?;
    // Tighten the mode on the tempfile *before* the rename, so the
    // post-rename file never momentarily exists at the default umask.
    let perm = Permissions::from_mode(mode);
    std::fs::set_permissions(tmp.path(), perm)
        .map_err(|e| SshConfigError::io("chmod", tmp.path(), e))?;
    tmp.persist(final_path)
        .map_err(|e| SshConfigError::io("rename", final_path, e.error))?;
    Ok(())
}

/// Read a file fully or return `None` if it does not exist.
fn read_optional(path: &Path) -> Result<Option<String>, SshConfigError> {
    match File::open(path) {
        Ok(mut f) => {
            let mut buf = String::new();
            f.read_to_string(&mut buf)
                .map_err(|e| SshConfigError::io("read", path, e))?;
            Ok(Some(buf))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(SshConfigError::io("open", path, e)),
    }
}

// ---------------------------------------------------------------------------
// `~/.ssh/config` Include block
// ---------------------------------------------------------------------------

/// The managed Include block, fully formatted, exactly as it appears in
/// `~/.ssh/config`. Three lines, each terminated by `\n`; the closing
/// marker line is followed by a blank line so the block visually
/// separates from any user-authored content beneath it.
fn managed_block() -> String {
    format!("{INCLUDE_MARKER_BEGIN}\n{INCLUDE_LINE}\n{INCLUDE_MARKER_END}\n\n")
}

/// Ensure the managed Include block is present at the **very top** of
/// `~/.ssh/config`. Creates `~/.ssh/config` with mode 0600 if absent.
/// Idempotent — calling twice leaves the file in the same state.
///
/// Strategy:
/// 1. Read existing content (empty string if file is missing).
/// 2. If the file already begins with our `INCLUDE_MARKER_BEGIN` line
///    AND contains `INCLUDE_MARKER_END` further along, locate the end
///    marker and replace the bytes between (and including) the markers
///    with a freshly-rendered block — this rewrites the block in-place
///    even if the operator manually edited the `Include` directive.
/// 3. Otherwise, prepend a fresh block in front of whatever the user
///    has, terminating their existing content unchanged below.
///
/// We never delete or modify any line outside the marker range. A
/// concurrent `sandbox` invocation is serialised by the caller's
/// flock on `~/.ssh/sandbox/.lock` (this function is called from
/// inside the locked region).
pub fn ensure_include_block(home: &Path) -> Result<(), SshConfigError> {
    let _guard = LockGuard::acquire_exclusive(home)?;
    ensure_include_block_locked(home)
}

/// Variant of [`ensure_include_block`] for callers that already hold
/// the flock. Internal — public entry points must acquire the lock
/// themselves.
fn ensure_include_block_locked(home: &Path) -> Result<(), SshConfigError> {
    ensure_ssh_dir(home)?;
    let cfg_path = ssh_config_path(home);
    let existing = read_optional(&cfg_path)?.unwrap_or_default();

    let new_content = upsert_include_block(&existing);
    if new_content == existing && cfg_path.exists() {
        return Ok(());
    }

    let parent = cfg_path
        .parent()
        .ok_or_else(|| SshConfigError::io("parent", &cfg_path, std::io::ErrorKind::Other.into()))?;
    atomic_write(
        parent,
        &cfg_path,
        new_content.as_bytes(),
        MODE_FILE_SSH_CONFIG,
    )
}

/// Pure-string transform: given the current contents of `~/.ssh/config`,
/// return the contents with the managed Include block at the top. If
/// the input already starts with the block, the existing block is
/// replaced (in-place rewrite tolerates manual edits inside the
/// markers); otherwise a fresh block is prepended. Everything outside
/// the marker range is preserved byte-for-byte.
fn upsert_include_block(existing: &str) -> String {
    // Case 1: file is empty or whitespace-only -> just the block.
    if existing.trim().is_empty() {
        return managed_block();
    }

    // Case 2: file already starts with our begin marker. Locate the
    // matching end marker and rewrite the slice in between.
    let begin_line = format!("{INCLUDE_MARKER_BEGIN}\n");
    if existing.starts_with(&begin_line) {
        if let Some(end_marker_pos) = existing.find(INCLUDE_MARKER_END) {
            // Advance past the end marker line (including its `\n`).
            let after_marker = end_marker_pos + INCLUDE_MARKER_END.len();
            let after_eol = existing[after_marker..]
                .find('\n')
                .map(|n| after_marker + n + 1)
                .unwrap_or(existing.len());
            // Skip exactly one blank-separator newline if present, so
            // the block does not accumulate blank lines on every rewrite.
            let after_sep = if existing[after_eol..].starts_with('\n') {
                after_eol + 1
            } else {
                after_eol
            };
            let tail = &existing[after_sep..];
            // The block already ends with "\n\n"; append the tail as-is.
            return format!("{}{tail}", managed_block());
        }
        // Begin marker present but no end marker — the operator (or a
        // crash) left an unterminated block. We bail to prepending a
        // fresh block; the orphan begin marker becomes operator-visible
        // content that they can clean up themselves. We must not auto-
        // delete it — that would violate the "never touch lines outside
        // our markers" contract.
    }

    // Case 3: marker(s) found mid-file, not at top. The spec is
    // explicit: the block must be at the very top to avoid first-
    // match-wins shadowing. We prepend a fresh block; the misplaced
    // remnant becomes operator-visible debris.
    let block = managed_block();
    let mut out = String::with_capacity(block.len() + existing.len());
    out.push_str(&block);
    out.push_str(existing);
    out
}

// ---------------------------------------------------------------------------
// Per-session entries
// ---------------------------------------------------------------------------

/// Write the per-session entry for `id`: rewrite the daemon-emitted
/// `IdentityFile <CLI-rewrites-this>` placeholder to the on-disk key
/// path, stage the config + key files atomically, and ensure the
/// `Include` block is present in `~/.ssh/config`. Returns the SSH
/// alias name (`sandbox-<id>`) the caller passes to `ssh` / `scp` /
/// `rsync`.
///
/// All filesystem mutations run under an exclusive flock on
/// `~/.ssh/sandbox/.lock` so a concurrent `sandbox ssh` for the same
/// session can never observe a half-staged entry.
///
/// **Key-first ordering:** the key file is staged and renamed
/// **before** the config file. The per-session config block carries
/// the absolute path of the key file in its `IdentityFile` directive;
/// once the config file is visible (post-rename), any `ssh` reader
/// must find the key path resolved — so the key must already exist on
/// disk by then. We honour that ordering even though both writes run
/// under the same flock, because external `ssh` clients (VS Code
/// Remote-SSH, etc.) do not take our lock.
pub fn ensure_session_entry(
    home: &Path,
    id: &str,
    dto: &SshConfigDto,
) -> Result<String, SshConfigError> {
    validate_session_id(id)?;
    if !dto.config.contains(SSH_CONFIG_IDENTITY_FILE_PLACEHOLDER) {
        return Err(SshConfigError::MissingPlaceholder {
            placeholder: SSH_CONFIG_IDENTITY_FILE_PLACEHOLDER,
        });
    }

    let _guard = LockGuard::acquire_exclusive(home)?;
    let sandbox_dir = ensure_sandbox_dir(home)?;
    // The `ControlPath …/sockets/%C` directive in the daemon-emitted
    // config requires the sockets directory to exist before `ssh`
    // tries to bind a multiplex socket there. Pre-create now so the
    // first `ssh sandbox-<id>` invocation does not die with
    // `unix_listener: cannot bind to path …`.
    ensure_sockets_dir(home)?;

    let key_path = session_key_path(home, id);
    let config_path = session_config_path(home, id);

    // Step 1: stage the key file (atomic rename — key visible only
    // when complete).
    atomic_write(
        &sandbox_dir,
        &key_path,
        dto.private_key.as_bytes(),
        MODE_FILE_KEY,
    )?;

    // Step 2: rewrite the placeholder to the absolute key path.
    let rewritten_config = dto.config.replace(
        SSH_CONFIG_IDENTITY_FILE_PLACEHOLDER,
        &format_key_path(&key_path),
    );

    // Step 3: stage the per-session config file. After this rename,
    // `ssh sandbox-<id>` (via the global Include) will resolve the
    // alias to a fully-coherent block.
    atomic_write(
        &sandbox_dir,
        &config_path,
        rewritten_config.as_bytes(),
        MODE_FILE_CONFIG,
    )?;

    // Step 4: ensure the Include block in `~/.ssh/config` so external
    // ssh clients pick the new alias up.
    ensure_include_block_locked(home)?;

    Ok(ssh_alias_for(id))
}

/// Stringify a key path for embedding into `IdentityFile`. SSH config
/// is whitespace-sensitive, so paths with spaces require quoting; we
/// quote unconditionally to keep the rendered config robust on
/// arbitrary `$HOME` paths (CI tempdirs sometimes contain spaces).
fn format_key_path(path: &Path) -> String {
    format!("\"{}\"", path.display())
}

/// Remove the per-session entry for `id`: unlink both the config file
/// and the key file. Idempotent — missing files are silently
/// tolerated, since the caller's invariant is "this id is no longer
/// active" which is the post-condition regardless of which files were
/// present at call time. Acquires the flock.
pub fn remove_session_entry(home: &Path, id: &str) -> Result<(), SshConfigError> {
    validate_session_id(id)?;
    let _guard = LockGuard::acquire_exclusive(home)?;
    remove_session_entry_locked(home, id)
}

fn remove_session_entry_locked(home: &Path, id: &str) -> Result<(), SshConfigError> {
    let key_path = session_key_path(home, id);
    let cfg_path = session_config_path(home, id);
    unlink_if_present(&cfg_path)?;
    unlink_if_present(&key_path)?;
    Ok(())
}

/// Unlink `path` if present; success on `NotFound`.
fn unlink_if_present(path: &Path) -> Result<(), SshConfigError> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(SshConfigError::io("unlink", path, e)),
    }
}

/// Check whether a per-session entry exists for `id`. M18-S7's
/// `sandbox proxy` lazy-404 path uses this to skip an unnecessary
/// flock-and-unlink round when there is nothing to clean up.
pub fn query_existing(home: &Path, id: &str) -> Result<bool, SshConfigError> {
    validate_session_id(id)?;
    // No lock needed for a single `exists()` check — the worst case is
    // a benign TOCTOU race with a concurrent write, where the caller
    // either falls through to a no-op `remove_session_entry` (which
    // is also idempotent) or skips a cleanup that the next pass picks
    // up.
    Ok(session_config_path(home, id).exists() || session_key_path(home, id).exists())
}

/// Reconcile the on-disk per-session entries against the daemon's
/// authoritative list of live session ids. Every entry whose id is
/// **not** in `live_ids` is removed. Returns the list of session ids
/// that were removed, ordered as discovered on disk. Acquires the
/// flock so a concurrent `sandbox ssh` cannot race entry removal.
///
/// Used by M18-S7's `sandbox ls` opportunistic reconcile pass.
pub fn reconcile_against_list(
    home: &Path,
    live_ids: &[&str],
) -> Result<Vec<String>, SshConfigError> {
    let _guard = LockGuard::acquire_exclusive(home)?;

    let dir = sandbox_dir(home);
    if !dir.exists() {
        return Ok(Vec::new());
    }

    // Build a `HashSet<&str>` once for O(1) membership.
    use std::collections::HashSet;
    let live: HashSet<&str> = live_ids.iter().copied().collect();

    let mut removed = Vec::new();
    let entries = std::fs::read_dir(&dir).map_err(|e| SshConfigError::io("readdir", &dir, e))?;
    for entry in entries {
        let entry = entry.map_err(|e| SshConfigError::io("readdir-entry", &dir, e))?;
        let file_name = entry.file_name();
        let name = match file_name.to_str() {
            Some(s) => s,
            None => continue, // non-UTF8 names are not ours; leave alone
        };
        // We own files matching `sandbox-<id>` (config) and
        // `sandbox-<id>.key`. Skip everything else (`.lock`, any tempfiles
        // mid-rename, user-authored siblings).
        let id_opt = strip_session_prefix(name);
        let id = match id_opt {
            Some(i) => i,
            None => continue,
        };
        // Defensive: ignore any file whose extracted id portion is not
        // a 12-char lowercase-hex string — those are not ours.
        if validate_session_id(id).is_err() {
            continue;
        }
        if live.contains(id) {
            continue;
        }
        // The id is unknown to the daemon. Drop the entry. We do not
        // call `remove_session_entry` (which would do its own flock —
        // we already hold it) and call the locked helper directly.
        // Track in `removed` only on first sight; both the config and
        // key file may yield the same id but we want one entry per id.
        if !removed.iter().any(|s| s == id) {
            remove_session_entry_locked(home, id)?;
            removed.push(id.to_string());
        }
    }
    Ok(removed)
}

/// If `name` matches `sandbox-<id>` or `sandbox-<id>.key`, return the
/// `<id>` slice; otherwise `None`. The matching is whole-file-name —
/// we do not strip directory components.
fn strip_session_prefix(name: &str) -> Option<&str> {
    let rest = name.strip_prefix("sandbox-")?;
    Some(rest.strip_suffix(".key").unwrap_or(rest))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::MetadataExt;
    use tempfile::TempDir;

    /// Build a synthetic `SshConfigDto` matching the daemon's exact
    /// wire shape — same template `sandbox_core::render_ssh_config_block`
    /// produces, same placeholder token.
    fn fake_dto(id: &str) -> SshConfigDto {
        SshConfigDto {
            config: sandbox_core::render_ssh_config_block(id),
            private_key: format!(
                "-----BEGIN OPENSSH PRIVATE KEY-----\nfake-bytes-for-{id}\n-----END OPENSSH PRIVATE KEY-----\n"
            ),
        }
    }

    fn mode_bits(path: &Path) -> u32 {
        std::fs::metadata(path).expect("metadata").mode() & 0o7777
    }

    // -----------------------------------------------------------------------
    // upsert_include_block — pure-string transform
    // -----------------------------------------------------------------------

    #[test]
    fn upsert_include_block_inserts_into_empty_file() {
        let result = upsert_include_block("");
        assert_eq!(result, managed_block());
        assert!(result.starts_with(INCLUDE_MARKER_BEGIN));
        assert!(result.contains(INCLUDE_LINE));
        assert!(result.contains(INCLUDE_MARKER_END));
    }

    #[test]
    fn upsert_include_block_prepends_when_user_content_absent_of_markers() {
        let existing = "Host github.com\n  User git\n";
        let result = upsert_include_block(existing);
        assert!(
            result.starts_with(INCLUDE_MARKER_BEGIN),
            "managed block must be at the very top to avoid first-match-wins shadowing; got: {result}"
        );
        assert!(
            result.ends_with(existing),
            "user content must be preserved byte-for-byte at the tail; got: {result}"
        );
    }

    #[test]
    fn upsert_include_block_is_idempotent() {
        let once = upsert_include_block("");
        let twice = upsert_include_block(&once);
        assert_eq!(once, twice, "re-running upsert must be a no-op");
    }

    #[test]
    fn upsert_include_block_idempotent_with_trailing_user_content() {
        let existing = "Host alpha\n  HostName 10.0.0.1\n";
        let once = upsert_include_block(existing);
        let twice = upsert_include_block(&once);
        assert_eq!(once, twice);
        // User content survives both passes.
        assert!(twice.contains("Host alpha"));
        assert!(twice.contains("HostName 10.0.0.1"));
    }

    #[test]
    fn upsert_include_block_rewrites_in_place_when_managed_line_drifted() {
        // Operator manually edited the Include line inside our markers.
        // Re-upsert should restore the canonical line without disturbing
        // anything outside the markers.
        let drifted = format!(
            "{INCLUDE_MARKER_BEGIN}\nInclude ~/old-path/*\n{INCLUDE_MARKER_END}\n\nHost beta\n  User dev\n"
        );
        let result = upsert_include_block(&drifted);
        assert!(result.contains(INCLUDE_LINE));
        assert!(!result.contains("Include ~/old-path/*"));
        assert!(result.contains("Host beta"));
        assert!(result.contains("User dev"));
    }

    #[test]
    fn upsert_include_block_handles_misplaced_remnant_by_prepending_fresh() {
        // User-authored content sits above an orphan managed block.
        // We must not touch the orphan; just prepend a fresh block at
        // the top so first-match-wins is still satisfied.
        let mid = format!(
            "Host gamma\n  HostName 10.0.0.2\n{INCLUDE_MARKER_BEGIN}\n{INCLUDE_LINE}\n{INCLUDE_MARKER_END}\n"
        );
        let result = upsert_include_block(&mid);
        assert!(result.starts_with(INCLUDE_MARKER_BEGIN));
        // Both the new top block AND the legacy mid block survive.
        // (Operator can clean the latter up; we do not touch anything
        // outside our top markers.)
        let occurrences = result.matches(INCLUDE_MARKER_BEGIN).count();
        assert_eq!(
            occurrences, 2,
            "must prepend at top without disturbing the orphan; got: {result}"
        );
    }

    // -----------------------------------------------------------------------
    // ensure_include_block — touches ~/.ssh/config under a tempdir HOME
    // -----------------------------------------------------------------------

    #[test]
    fn ensure_include_block_creates_ssh_config_with_mode_0600() {
        let tmp = TempDir::new().unwrap();
        let home = tmp.path();
        ensure_include_block(home).expect("ensure_include_block");

        let cfg = ssh_config_path(home);
        assert!(cfg.exists(), "~/.ssh/config must be created");
        assert_eq!(mode_bits(&cfg), MODE_FILE_SSH_CONFIG);
        assert_eq!(mode_bits(&ssh_dir(home)), MODE_DIR_PRIVATE);

        let body = std::fs::read_to_string(&cfg).unwrap();
        assert!(body.starts_with(INCLUDE_MARKER_BEGIN));
        assert!(body.contains(INCLUDE_LINE));
        assert!(body.contains(INCLUDE_MARKER_END));
    }

    #[test]
    fn ensure_include_block_idempotent_against_existing_user_config() {
        let tmp = TempDir::new().unwrap();
        let home = tmp.path();
        // Pre-populate `~/.ssh/config` with an operator-authored Host
        // block. Mode is 0600 (the standard for `~/.ssh/config`).
        std::fs::create_dir_all(home.join(".ssh")).unwrap();
        let cfg = ssh_config_path(home);
        std::fs::write(&cfg, "Host github.com\n  User git\n").unwrap();
        std::fs::set_permissions(&cfg, Permissions::from_mode(0o600)).unwrap();

        ensure_include_block(home).expect("first call");
        let after_first = std::fs::read_to_string(&cfg).unwrap();
        ensure_include_block(home).expect("second call");
        let after_second = std::fs::read_to_string(&cfg).unwrap();

        assert_eq!(after_first, after_second, "second call must be a no-op");
        assert!(after_first.starts_with(INCLUDE_MARKER_BEGIN));
        // User content survives.
        assert!(after_first.contains("Host github.com"));
        assert!(after_first.contains("  User git"));
    }

    // -----------------------------------------------------------------------
    // ensure_session_entry — writes config + key + Include block
    // -----------------------------------------------------------------------

    /// `ensure_session_entry` must pre-create `~/.ssh/sandbox/sockets/`
    /// so the `ControlPath …/sockets/%C` directive in the daemon-
    /// emitted config block does not die on the first `ssh` call with
    /// `unix_listener: cannot bind to path …` (OpenSSH does not
    /// auto-create the parent directory of `ControlPath`).
    #[test]
    fn ensure_session_entry_creates_sockets_dir() {
        let tmp = TempDir::new().unwrap();
        let home = tmp.path();
        let id = "0123456789ab";

        ensure_session_entry(home, id, &fake_dto(id)).expect("write entry");

        let sockets = sockets_dir(home);
        assert!(sockets.is_dir(), "sockets/ must exist as a directory");
        assert_eq!(
            mode_bits(&sockets),
            MODE_DIR_PRIVATE,
            "sockets/ must be mode 0700"
        );
    }

    #[test]
    fn ensure_session_entry_writes_config_and_key_with_correct_modes() {
        let tmp = TempDir::new().unwrap();
        let home = tmp.path();
        let id = "0123456789ab";
        let dto = fake_dto(id);

        let alias = ensure_session_entry(home, id, &dto).expect("write entry");
        assert_eq!(alias, "sandbox-0123456789ab");

        let cfg = session_config_path(home, id);
        let key = session_key_path(home, id);
        assert!(cfg.exists(), "per-session config must exist");
        assert!(key.exists(), "per-session key must exist");
        assert_eq!(mode_bits(&cfg), MODE_FILE_CONFIG);
        assert_eq!(mode_bits(&key), MODE_FILE_KEY);

        // `~/.ssh/sandbox/` directory is mode 0700.
        assert_eq!(mode_bits(&sandbox_dir(home)), MODE_DIR_PRIVATE);
        // `.lock` exists and is mode 0600.
        assert_eq!(mode_bits(&lock_path(home)), MODE_FILE_LOCK);
    }

    #[test]
    fn ensure_session_entry_rewrites_identity_file_placeholder_to_key_path() {
        let tmp = TempDir::new().unwrap();
        let home = tmp.path();
        let id = "abcdef012345";
        let dto = fake_dto(id);

        // Sanity: the daemon-emitted block must contain the placeholder.
        assert!(dto.config.contains(SSH_CONFIG_IDENTITY_FILE_PLACEHOLDER));

        ensure_session_entry(home, id, &dto).expect("write entry");

        let body = std::fs::read_to_string(session_config_path(home, id)).unwrap();
        assert!(
            !body.contains(SSH_CONFIG_IDENTITY_FILE_PLACEHOLDER),
            "placeholder must be rewritten away; got: {body}"
        );
        let expected_key_path = session_key_path(home, id);
        assert!(
            body.contains(&format!("IdentityFile \"{}\"", expected_key_path.display())),
            "rewritten IdentityFile must point at the on-disk key path; got: {body}"
        );
    }

    #[test]
    fn ensure_session_entry_rejects_invalid_session_id() {
        let tmp = TempDir::new().unwrap();
        let home = tmp.path();
        let dto = fake_dto("0123456789ab");

        let err = ensure_session_entry(home, "../etc/passwd", &dto).unwrap_err();
        assert!(matches!(err, SshConfigError::InvalidSessionId { .. }));
        // Refusal must not have left any artefacts under the home dir.
        assert!(!sandbox_dir(home).exists());
    }

    #[test]
    fn ensure_session_entry_rejects_dto_missing_placeholder() {
        let tmp = TempDir::new().unwrap();
        let home = tmp.path();
        let id = "0123456789ab";
        let dto = SshConfigDto {
            config: "Host sandbox-0123456789ab\n  HostName 127.0.0.1\n  IdentityFile /tmp/already-rewritten\n".into(),
            private_key: "fake".into(),
        };
        let err = ensure_session_entry(home, id, &dto).unwrap_err();
        assert!(matches!(err, SshConfigError::MissingPlaceholder { .. }));
    }

    #[test]
    fn ensure_session_entry_is_idempotent() {
        let tmp = TempDir::new().unwrap();
        let home = tmp.path();
        let id = "0123456789ab";
        let dto = fake_dto(id);

        ensure_session_entry(home, id, &dto).expect("first");
        let first_cfg = std::fs::read_to_string(session_config_path(home, id)).unwrap();
        let first_key = std::fs::read_to_string(session_key_path(home, id)).unwrap();

        ensure_session_entry(home, id, &dto).expect("second");
        let second_cfg = std::fs::read_to_string(session_config_path(home, id)).unwrap();
        let second_key = std::fs::read_to_string(session_key_path(home, id)).unwrap();

        assert_eq!(first_cfg, second_cfg);
        assert_eq!(first_key, second_key);
    }

    // -----------------------------------------------------------------------
    // remove_session_entry
    // -----------------------------------------------------------------------

    #[test]
    fn remove_session_entry_unlinks_both_files() {
        let tmp = TempDir::new().unwrap();
        let home = tmp.path();
        let id = "0123456789ab";
        let dto = fake_dto(id);

        ensure_session_entry(home, id, &dto).expect("write");
        assert!(session_config_path(home, id).exists());
        assert!(session_key_path(home, id).exists());

        remove_session_entry(home, id).expect("remove");
        assert!(!session_config_path(home, id).exists());
        assert!(!session_key_path(home, id).exists());

        // ~/.ssh/config Include block survives (it is global; removing
        // one session does not invalidate the directive).
        let cfg = std::fs::read_to_string(ssh_config_path(home)).unwrap();
        assert!(cfg.contains(INCLUDE_LINE));
    }

    #[test]
    fn remove_session_entry_is_idempotent_on_absent_session() {
        let tmp = TempDir::new().unwrap();
        let home = tmp.path();
        // First call against a never-written id must succeed (it's the
        // caller's "make sure this session is gone" semantic).
        // The sandbox dir is auto-created by the lock file open.
        remove_session_entry(home, "0123456789ab").expect("remove on absent");
    }

    // -----------------------------------------------------------------------
    // query_existing
    // -----------------------------------------------------------------------

    #[test]
    fn query_existing_reports_truth() {
        let tmp = TempDir::new().unwrap();
        let home = tmp.path();
        let id = "0123456789ab";
        assert!(!query_existing(home, id).unwrap());
        ensure_session_entry(home, id, &fake_dto(id)).unwrap();
        assert!(query_existing(home, id).unwrap());
        remove_session_entry(home, id).unwrap();
        assert!(!query_existing(home, id).unwrap());
    }

    // -----------------------------------------------------------------------
    // reconcile_against_list
    // -----------------------------------------------------------------------

    #[test]
    fn reconcile_removes_stale_entries_and_keeps_live_ones() {
        let tmp = TempDir::new().unwrap();
        let home = tmp.path();
        let live = "aaaaaaaaaaaa";
        let stale = "bbbbbbbbbbbb";
        let other_stale = "cccccccccccc";

        ensure_session_entry(home, live, &fake_dto(live)).unwrap();
        ensure_session_entry(home, stale, &fake_dto(stale)).unwrap();
        ensure_session_entry(home, other_stale, &fake_dto(other_stale)).unwrap();

        let removed = reconcile_against_list(home, &[live]).unwrap();
        let mut removed_sorted = removed.clone();
        removed_sorted.sort();
        assert_eq!(
            removed_sorted,
            vec![stale.to_string(), other_stale.to_string()]
        );

        assert!(session_config_path(home, live).exists());
        assert!(session_key_path(home, live).exists());
        assert!(!session_config_path(home, stale).exists());
        assert!(!session_key_path(home, stale).exists());
        assert!(!session_config_path(home, other_stale).exists());
        assert!(!session_key_path(home, other_stale).exists());
    }

    #[test]
    fn reconcile_against_empty_sandbox_dir_is_no_op() {
        let tmp = TempDir::new().unwrap();
        let home = tmp.path();
        let removed = reconcile_against_list(home, &[]).unwrap();
        assert!(removed.is_empty());
    }

    #[test]
    fn reconcile_ignores_files_outside_our_naming_convention() {
        let tmp = TempDir::new().unwrap();
        let home = tmp.path();
        // Pre-create the sandbox dir + a few foreign files.
        ensure_sandbox_dir(home).unwrap();
        std::fs::write(sandbox_dir(home).join("not-ours.conf"), "hi").unwrap();
        std::fs::write(sandbox_dir(home).join("sandbox-not-hex!@#"), "hi").unwrap();
        // And a real entry.
        let id = "0123456789ab";
        ensure_session_entry(home, id, &fake_dto(id)).unwrap();

        let removed = reconcile_against_list(home, &[]).unwrap();
        assert_eq!(removed, vec![id.to_string()]);
        // Foreign files survive.
        assert!(sandbox_dir(home).join("not-ours.conf").exists());
        assert!(sandbox_dir(home).join("sandbox-not-hex!@#").exists());
    }

    // -----------------------------------------------------------------------
    // flock contention
    // -----------------------------------------------------------------------

    #[test]
    fn flock_serialises_concurrent_writers() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::thread;
        use std::time::Duration;

        let tmp = TempDir::new().unwrap();
        let home = tmp.path().to_path_buf();
        // Establish the sandbox directory and lock file up front so
        // both writer threads race only on the kernel `flock` call.
        ensure_sandbox_dir(&home).unwrap();

        let in_critical = Arc::new(AtomicUsize::new(0));
        let observed_concurrent = Arc::new(AtomicUsize::new(0));

        let mut handles = Vec::new();
        for n in 0..4 {
            let home = home.clone();
            let in_critical = Arc::clone(&in_critical);
            let observed_concurrent = Arc::clone(&observed_concurrent);
            handles.push(thread::spawn(move || {
                for k in 0..3 {
                    let _guard = LockGuard::acquire_exclusive(&home).expect("flock");
                    let now_inside = in_critical.fetch_add(1, Ordering::SeqCst) + 1;
                    if now_inside > 1 {
                        observed_concurrent.fetch_add(1, Ordering::SeqCst);
                    }
                    // Hold the lock long enough that a racing thread
                    // would observe `in_critical > 1` if the flock did
                    // not serialise us.
                    thread::sleep(Duration::from_millis(20));
                    in_critical.fetch_sub(1, Ordering::SeqCst);
                    let _ = (n, k); // suppress unused-binding warning
                }
            }));
        }
        for h in handles {
            h.join().unwrap();
        }

        assert_eq!(
            observed_concurrent.load(Ordering::SeqCst),
            0,
            "flock must serialise critical sections; observed concurrent entries"
        );
    }

    // -----------------------------------------------------------------------
    // Crash safety — simulated SIGKILL mid-write
    // -----------------------------------------------------------------------

    /// Simulate an abort mid-write: stage a tempfile under
    /// `~/.ssh/sandbox/`, write partial bytes, then drop the
    /// `NamedTempFile` without persisting (which is what would happen
    /// to a `tempfile::NamedTempFile` if the process were SIGKILLed
    /// between `write_all` and `persist`). The destination file
    /// either does not exist or still contains the prior bytes — it
    /// is never observed as half-written.
    #[test]
    fn aborted_atomic_write_leaves_no_half_file() {
        let tmp = TempDir::new().unwrap();
        let home = tmp.path();
        let id = "0123456789ab";

        // Write a real entry first; capture the "prior" bytes.
        ensure_session_entry(home, id, &fake_dto(id)).expect("first write");
        let cfg_path = session_config_path(home, id);
        let prior_bytes = std::fs::read_to_string(&cfg_path).expect("read prior");

        // Simulate an aborted write: open a fresh NamedTempFile in the
        // sandbox dir, write partial bytes, drop without persisting.
        let parent = sandbox_dir(home);
        {
            let mut tmp_file = NamedTempFile::new_in(&parent).expect("tempfile");
            tmp_file.write_all(b"PARTIAL!!!").expect("partial write");
            // Tempfile drops here without persist() — simulates SIGKILL
            // between write_all and persist. The destination file is
            // untouched.
        }

        // The destination file still has the prior bytes; no
        // half-written content reached it.
        let observed = std::fs::read_to_string(&cfg_path).expect("read after abort");
        assert_eq!(
            observed, prior_bytes,
            "aborted mid-write must leave the destination at the prior content; \
             observed half-written bytes!"
        );

        // No stray tempfile leaked into the sandbox dir beyond the
        // ones we own (config, key, .lock).
        let mut leftover = Vec::new();
        for entry in std::fs::read_dir(&parent).unwrap() {
            let entry = entry.unwrap();
            let name = entry.file_name();
            let name_str = name.to_string_lossy().into_owned();
            // Tempfile names are like `.tmpAbCdEf` — they start with
            // `.tmp`. The NamedTempFile RAII drop removes them.
            if name_str.starts_with(".tmp") {
                leftover.push(name_str);
            }
        }
        assert!(
            leftover.is_empty(),
            "NamedTempFile drop must clean up partial tempfiles; leftover: {leftover:?}"
        );
    }

    // -----------------------------------------------------------------------
    // ~/.ssh/config Include block survives entry write/remove cycles
    // -----------------------------------------------------------------------

    /// The global `Include` block lives in `~/.ssh/config` and must
    /// survive removal of every per-session entry — it is a directive
    /// pointing at the sandbox dir, not at any specific session, and
    /// removing it on `sandbox rm` would silently break every other
    /// session's `sandbox ssh`.
    #[test]
    fn include_block_survives_entry_removal_cycle() {
        let tmp = TempDir::new().unwrap();
        let home = tmp.path();
        let id = "0123456789ab";

        ensure_session_entry(home, id, &fake_dto(id)).unwrap();
        let cfg_after_write = std::fs::read_to_string(ssh_config_path(home)).unwrap();
        assert!(cfg_after_write.contains(INCLUDE_LINE));

        remove_session_entry(home, id).unwrap();
        let cfg_after_remove = std::fs::read_to_string(ssh_config_path(home)).unwrap();
        assert!(
            cfg_after_remove.contains(INCLUDE_LINE),
            "`Include` block must survive entry removal; got: {cfg_after_remove}"
        );
        assert_eq!(
            cfg_after_write, cfg_after_remove,
            "removing a per-session entry must not touch `~/.ssh/config` at all"
        );
    }

    // -----------------------------------------------------------------------
    // Alias name pin (wire-format-bound to render_ssh_config_block)
    // -----------------------------------------------------------------------

    /// The alias the CLI returns from [`ensure_session_entry`] must
    /// match the `Host sandbox-<id>` line in the daemon-emitted
    /// config block. Pins the contract M18-S6's command wrappers
    /// depend on: the returned string is the literal argument to pass
    /// to `ssh` / `scp` / `rsync`.
    #[test]
    fn ssh_alias_for_matches_daemon_emitted_host_line() {
        let id = "0123456789ab";
        let alias = ssh_alias_for(id);
        let block = sandbox_core::render_ssh_config_block(id);
        assert_eq!(alias, "sandbox-0123456789ab");
        assert!(
            block.contains(&format!("Host {alias}")),
            "alias must match the daemon-emitted Host line; alias={alias}, block={block}"
        );
    }
}
