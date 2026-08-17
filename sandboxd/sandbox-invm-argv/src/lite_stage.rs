//! The per-session provisioning files a lite container needs to exist
//! **inside** the gateway VM before `docker create` can bind them.
//!
//! On macOS the lite container runs on the VM's Docker daemon, so Docker
//! resolves bind-mount *sources* against the VM's filesystem. The CA
//! certificate and the three SSH files the daemon generated on the host do not
//! exist there; they have to be put into a per-session directory in the VM
//! first, keeping their canonical basenames so the existing bind builders
//! resolve the same paths the Linux host binds use.

use crate::owned;

/// Root of the per-session staging directories inside the VM.
///
/// The VM's `/tmp` is sticky and the login user owns what it creates there, so
/// this needs no `sudo` — which is the reason it is `/tmp` and not somewhere
/// tidier.
///
/// Nothing secret lands here. The certificate is a CA *certificate*, the
/// authorized-keys file is a public key, and `passwd`/`group` are two
/// synthetic lines. The one secret in the lite path — the mitmproxy CA private
/// key — is written straight into the gateway container's tmpfs and never
/// touches this directory.
pub const STAGE_ROOT_IN_VM: &str = "/tmp/sandbox-lite";

/// The four files a lite session stages, and nothing else.
///
/// # Why this is an enum and not a filename
///
/// These are the files a container's identity is assembled from: the CA it
/// will trust, the key that may log into it, and the uid it runs as. A
/// caller-supplied basename would let whoever is on the other end of the
/// broker channel write any name into a directory that is about to be bound
/// into a container — including names the bind builders already point at.
///
/// # Adding a variant is a security change
///
/// Each variant is one more file the daemon can place inside the operator's
/// VM. Check whether the bind builders actually read the file before adding
/// the name they would read it under.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LiteStageFile {
    /// The session's CA certificate, bound in as the trust root.
    CertPem,
    /// The session keypair's public half, read by the in-container `sshd`.
    AuthorizedKeys,
    /// Synthetic `/etc/passwd` — one entry mapping the runtime uid to the
    /// username `sshd`'s `AllowUsers` directive accepts.
    Passwd,
    /// Synthetic `/etc/group` — the matching single group entry.
    Group,
}

impl LiteStageFile {
    /// All four, for exhaustive iteration in tests and at call sites that
    /// stage the whole set.
    pub const ALL: &'static [LiteStageFile] = &[
        LiteStageFile::CertPem,
        LiteStageFile::AuthorizedKeys,
        LiteStageFile::Passwd,
        LiteStageFile::Group,
    ];

    /// The canonical basename this file keeps inside the staging directory.
    ///
    /// The bind builders join the staging directory with these names, so they
    /// are not free to change: `build_ca_mount_args` binds `<dir>/cert.pem`
    /// and `build_ssh_mount_args` joins `<dir>` with the other three.
    pub fn basename(self) -> &'static str {
        match self {
            LiteStageFile::CertPem => "cert.pem",
            LiteStageFile::AuthorizedKeys => "authorized_keys",
            LiteStageFile::Passwd => "passwd",
            LiteStageFile::Group => "group",
        }
    }

    /// The mode the file must carry inside the VM.
    ///
    /// All four are read by processes inside the container running as the
    /// session uid, not as the bind's owner, so all four are `0644`. This is
    /// a property of the variant rather than a field on the op for the usual
    /// reason: a caller-chosen mode on a file bound into a container is a
    /// knob with no legitimate setting other than the one below.
    pub fn mode(self) -> u32 {
        match self {
            LiteStageFile::CertPem
            | LiteStageFile::AuthorizedKeys
            | LiteStageFile::Passwd
            | LiteStageFile::Group => 0o644,
        }
    }

    /// A stable label for logs and error messages.
    pub fn as_str(self) -> &'static str {
        self.basename()
    }
}

/// The VM staging directory for `session_id`: `{STAGE_ROOT_IN_VM}/<id>`.
///
/// Pure string composition. `session_id` is validated by the side that runs
/// the command before it reaches here — this function cannot tell a session
/// identifier from a traversal.
pub fn stage_dir(session_id: &str) -> String {
    format!("{STAGE_ROOT_IN_VM}/{session_id}")
}

/// The in-VM path one staged file lands at.
pub fn file_path(stage_dir: &str, file: LiteStageFile) -> String {
    format!("{stage_dir}/{}", file.basename())
}

/// The basename the transfer's *source* copy carries in the running side's own
/// LIMA_HOME.
///
/// The body of each file crosses the broker channel as content, so the side
/// that runs `limactl copy` first materialises it somewhere it owns. Both
/// sides derive that name the same way so a leftover from a crashed run is
/// recognisable and gets overwritten rather than accumulating.
pub fn transfer_basename(session_id: &str, file: LiteStageFile) -> String {
    format!(".lite-stage-{session_id}-{}", file.basename())
}

/// `mkdir -p <dir>` inside the VM. No `sudo`: the login user owns what it
/// makes under the sticky `/tmp`.
pub fn mkdir_argv(dir: &str) -> Vec<String> {
    let mut argv = owned(&["mkdir", "-p"]);
    argv.push(dir.to_string());
    argv
}

/// `rm -rf <dir>` inside the VM.
pub fn rm_argv(dir: &str) -> Vec<String> {
    let mut argv = owned(&["rm", "-rf"]);
    argv.push(dir.to_string());
    argv
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_stage_dir_is_the_root_joined_with_the_session() {
        assert_eq!(stage_dir("abc123"), "/tmp/sandbox-lite/abc123");
    }

    /// The bind builders join the staging directory with these exact names.
    /// Renaming one here silently unbinds a file inside the container, which
    /// presents as an SSH or TLS failure a long way from this file.
    #[test]
    fn the_basenames_are_the_ones_the_bind_builders_expect() {
        assert_eq!(LiteStageFile::CertPem.basename(), "cert.pem");
        assert_eq!(LiteStageFile::AuthorizedKeys.basename(), "authorized_keys");
        assert_eq!(LiteStageFile::Passwd.basename(), "passwd");
        assert_eq!(LiteStageFile::Group.basename(), "group");
    }

    #[test]
    fn every_staged_file_is_world_readable_inside_the_container() {
        for file in LiteStageFile::ALL {
            assert_eq!(file.mode(), 0o644, "{file:?} has an unexpected mode");
        }
    }

    #[test]
    fn all_four_basenames_are_distinct() {
        let mut seen: Vec<&str> = LiteStageFile::ALL.iter().map(|f| f.basename()).collect();
        seen.sort_unstable();
        let before = seen.len();
        seen.dedup();
        assert_eq!(before, seen.len(), "two variants share a basename");
    }

    #[test]
    fn file_paths_land_under_the_session_directory() {
        let dir = stage_dir("s1");
        for file in LiteStageFile::ALL {
            let path = file_path(&dir, *file);
            assert!(path.starts_with("/tmp/sandbox-lite/s1/"), "{path}");
        }
    }

    /// The transfer copies are per-session and per-file, so two sessions
    /// staging concurrently cannot overwrite each other's source file
    /// mid-copy.
    #[test]
    fn transfer_basenames_do_not_collide_across_sessions_or_files() {
        let mut names = Vec::new();
        for session in ["s1", "s2"] {
            for file in LiteStageFile::ALL {
                names.push(transfer_basename(session, *file));
            }
        }
        let before = names.len();
        names.sort();
        names.dedup();
        assert_eq!(before, names.len(), "transfer basenames collide");
    }

    #[test]
    fn mkdir_and_rm_need_no_privilege() {
        assert_eq!(mkdir_argv("/tmp/sandbox-lite/s1")[0], "mkdir");
        assert_eq!(rm_argv("/tmp/sandbox-lite/s1")[0], "rm");
    }
}
