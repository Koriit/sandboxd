//! The gateway container's policy plane: the artifacts the enforcement
//! pipeline blocks on, and the commands that deliver them.
//!
//! Everything in this module describes files and tables **inside** a gateway
//! container: the Envoy bootstrap and listener Envoy refuses to start
//! without, the CoreDNS policy that decides which names resolve, the
//! mitmproxy policy and CA, and the two nftables tables that carry the
//! allow/deny decision itself.
//!
//! # Why these are enums and not paths
//!
//! Two of the deliveries below genuinely need a shell: creating the parent
//! directory and writing the file are two commands, and the listener has to
//! be renamed into place so Envoy's filesystem-LDS watcher sees an
//! `IN_MOVED_TO`. A shell command line built from a caller-supplied path is
//! the classic injection shape, and the guard it usually gets — quote the
//! path and hope — is only as good as whoever remembers to check.
//!
//! So no path is caller-supplied. [`GatewayFile`] enumerates the artifacts,
//! each variant maps to a `&'static str` in this crate, and the shell body
//! is a function of two enums. What crosses the broker channel is the
//! discriminant; the string that reaches `sh -c` never left this file. That
//! is the allowlist, in the strongest form available: not "the input is
//! checked against a list" but "there is no input".
//!
//! The **content** of an artifact is caller-supplied, and deliberately so —
//! it is the policy. It reaches the child on stdin, where no shell parses
//! it: `cat` and `nft -f -` read bytes, not command lines.

// ---------------------------------------------------------------------------
// In-container paths
// ---------------------------------------------------------------------------

/// Absolute path inside the gateway container for the Envoy static
/// bootstrap. The container's entrypoint blocks on this file's existence
/// before it starts Envoy.
pub const BOOTSTRAP_FILE_IN_CONTAINER: &str = "/etc/envoy/envoy-bootstrap.yaml";

/// Absolute path of the LDS-watched listener directory inside the gateway
/// container. Envoy's filesystem LDS subscription is pinned to this
/// directory, so a rename into it is what triggers a listener reload.
pub const LISTENER_DIR_IN_CONTAINER: &str = "/etc/envoy/listeners";

/// Absolute path of the LDS-served listener file inside the gateway
/// container.
pub const LISTENER_FILE_IN_CONTAINER: &str = "/etc/envoy/listeners/listener.yaml";

/// Absolute path of the CoreDNS policy file — the artifact that decides
/// which names resolve at all.
pub const COREDNS_POLICY_FILE_IN_CONTAINER: &str = "/etc/coredns/policy.conf";

/// Absolute path of the CoreDNS resolved-address report. Written by CoreDNS
/// itself; the daemon only reads it.
pub const COREDNS_RESOLVED_FILE_IN_CONTAINER: &str = "/etc/coredns/resolved.json";

/// Absolute path of the mitmproxy policy document.
pub const MITMPROXY_POLICY_FILE_IN_CONTAINER: &str = "/tmp/mitmproxy/policy.json";

/// Absolute path of the per-session mitmproxy CA key+cert bundle.
pub const MITMPROXY_CA_KEY_IN_CONTAINER: &str = "/root/.mitmproxy/mitmproxy-ca.pem";

/// Absolute path of the per-session mitmproxy CA certificate.
pub const MITMPROXY_CA_CERT_IN_CONTAINER: &str = "/root/.mitmproxy/mitmproxy-ca-cert.pem";

/// Envoy admin `/stats` URL for the active-listener gauge.
///
/// One argv element, never a shell word: the `&` separating the query
/// parameters has to reach Envoy as a separator rather than being read as a
/// background operator.
pub const ENVOY_ACTIVE_LISTENERS_STATS_URL: &str = "http://127.0.0.1:9901/stats?\
     filter=^listener_manager\\.total_listeners_active$&\
     format=text";

// ---------------------------------------------------------------------------
// GatewayFile
// ---------------------------------------------------------------------------

/// The closed set of gateway-container files the daemon may name.
///
/// # Adding a variant is a security change
///
/// A variant here is a path the daemon can read, and — if it is also
/// [writable](Self::writable) — a path the daemon can overwrite inside a
/// container that terminates TLS for a whole session. The set stops
/// bounding anything the moment it grows a variant whose path is not
/// already part of the enforcement pipeline, so:
///
/// - **Name the artifact, not the location.** `EnvoyListener`, not
///   `EtcEnvoyListenersListenerYaml`. A variant whose name is a path is a
///   path field wearing an enum.
/// - **Read-only unless the daemon is the writer.** [`Self::writable`] is
///   the split, and the agent refuses a write to a variant on the wrong
///   side of it. A file some other process owns — CoreDNS's resolved-address
///   report is the one that exists — is readable and nothing more.
/// - **The path is a constant of this crate.** It has to survive
///   interpolation into a `sh -c` body, and
///   `every_path_is_safe_to_interpolate_into_a_shell_word` is what says it
///   does. A new variant either passes that test or does not go in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GatewayFile {
    /// The CoreDNS policy — which names resolve.
    CorednsPolicy,
    /// CoreDNS's own report of what it resolved. Read-only.
    CorednsResolved,
    /// The mitmproxy policy document.
    MitmproxyPolicy,
    /// The per-session mitmproxy CA key+cert bundle.
    MitmproxyCaKey,
    /// The per-session mitmproxy CA certificate.
    MitmproxyCaCert,
    /// Envoy's static bootstrap.
    EnvoyBootstrap,
    /// Envoy's LDS-served listener.
    EnvoyListener,
}

impl GatewayFile {
    /// Every variant, for exhaustive iteration in tests and validation.
    ///
    /// A variant missing from this slice is caught by
    /// [`Self::path`]'s exhaustive match plus the count assertion in this
    /// module's tests.
    pub const ALL: &'static [GatewayFile] = &[
        GatewayFile::CorednsPolicy,
        GatewayFile::CorednsResolved,
        GatewayFile::MitmproxyPolicy,
        GatewayFile::MitmproxyCaKey,
        GatewayFile::MitmproxyCaCert,
        GatewayFile::EnvoyBootstrap,
        GatewayFile::EnvoyListener,
    ];

    /// The artifact's absolute path inside the container.
    pub fn path(self) -> &'static str {
        match self {
            GatewayFile::CorednsPolicy => COREDNS_POLICY_FILE_IN_CONTAINER,
            GatewayFile::CorednsResolved => COREDNS_RESOLVED_FILE_IN_CONTAINER,
            GatewayFile::MitmproxyPolicy => MITMPROXY_POLICY_FILE_IN_CONTAINER,
            GatewayFile::MitmproxyCaKey => MITMPROXY_CA_KEY_IN_CONTAINER,
            GatewayFile::MitmproxyCaCert => MITMPROXY_CA_CERT_IN_CONTAINER,
            GatewayFile::EnvoyBootstrap => BOOTSTRAP_FILE_IN_CONTAINER,
            GatewayFile::EnvoyListener => LISTENER_FILE_IN_CONTAINER,
        }
    }

    /// The directory holding the artifact.
    ///
    /// Spelled out per variant rather than derived from [`Self::path`]: the
    /// value is interpolated into a shell body, and a literal a reviewer can
    /// read beats a computed prefix they have to reconstruct.
    pub fn parent_dir(self) -> &'static str {
        match self {
            GatewayFile::CorednsPolicy | GatewayFile::CorednsResolved => "/etc/coredns",
            GatewayFile::MitmproxyPolicy => "/tmp/mitmproxy",
            GatewayFile::MitmproxyCaKey | GatewayFile::MitmproxyCaCert => "/root/.mitmproxy",
            GatewayFile::EnvoyBootstrap => "/etc/envoy",
            GatewayFile::EnvoyListener => LISTENER_DIR_IN_CONTAINER,
        }
    }

    /// The staging path a [`FileDelivery::AtomicRename`] writes before the
    /// rename. Same directory as the target, so the rename is one syscall
    /// on one filesystem and the watcher sees `IN_MOVED_TO` rather than a
    /// create-plus-write.
    pub fn staging_path(self) -> &'static str {
        match self {
            GatewayFile::CorednsPolicy => "/etc/coredns/policy.conf.tmp",
            GatewayFile::CorednsResolved => "/etc/coredns/resolved.json.tmp",
            GatewayFile::MitmproxyPolicy => "/tmp/mitmproxy/policy.json.tmp",
            GatewayFile::MitmproxyCaKey => "/root/.mitmproxy/mitmproxy-ca.pem.tmp",
            GatewayFile::MitmproxyCaCert => "/root/.mitmproxy/mitmproxy-ca-cert.pem.tmp",
            GatewayFile::EnvoyBootstrap => "/etc/envoy/envoy-bootstrap.yaml.tmp",
            GatewayFile::EnvoyListener => "/etc/envoy/listeners/listener.yaml.tmp",
        }
    }

    /// Whether the daemon may write this artifact.
    ///
    /// `false` for files another process owns. The agent refuses a write op
    /// naming one, so read access does not imply write access.
    pub fn writable(self) -> bool {
        match self {
            GatewayFile::CorednsResolved => false,
            GatewayFile::CorednsPolicy
            | GatewayFile::MitmproxyPolicy
            | GatewayFile::MitmproxyCaKey
            | GatewayFile::MitmproxyCaCert
            | GatewayFile::EnvoyBootstrap
            | GatewayFile::EnvoyListener => true,
        }
    }

    /// A stable label for logs and error messages.
    pub fn as_str(self) -> &'static str {
        match self {
            GatewayFile::CorednsPolicy => "coredns-policy",
            GatewayFile::CorednsResolved => "coredns-resolved",
            GatewayFile::MitmproxyPolicy => "mitmproxy-policy",
            GatewayFile::MitmproxyCaKey => "mitmproxy-ca-key",
            GatewayFile::MitmproxyCaCert => "mitmproxy-ca-cert",
            GatewayFile::EnvoyBootstrap => "envoy-bootstrap",
            GatewayFile::EnvoyListener => "envoy-listener",
        }
    }
}

// ---------------------------------------------------------------------------
// FileDelivery
// ---------------------------------------------------------------------------

/// How a gateway file is put in place.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileDelivery {
    /// Truncate and rewrite the file where it stands.
    ///
    /// The parent directory is created first. Every writable artifact lives
    /// in a container tmpfs that the image does not always pre-create — the
    /// listener directory in particular is created by the entrypoint's Envoy
    /// start sequence, which is itself gated on the listener file existing.
    Replace,
    /// Write a staging file beside the target, then rename over it.
    ///
    /// The rename is what Envoy's filesystem-LDS watcher subscribes to
    /// (`IN_MOVED_TO`); a plain rewrite would let Envoy read a half-written
    /// listener. Only meaningful for [`GatewayFile::EnvoyListener`] today,
    /// but the mechanism is not listener-specific.
    AtomicRename,
}

impl FileDelivery {
    /// A stable label for logs and error messages.
    pub fn as_str(self) -> &'static str {
        match self {
            FileDelivery::Replace => "replace",
            FileDelivery::AtomicRename => "atomic-rename",
        }
    }
}

// ---------------------------------------------------------------------------
// NftTable
// ---------------------------------------------------------------------------

/// The two `inet` nftables tables the gateway's policy plane manages.
///
/// `sandbox_dnat` carries the VM-egress conditional-DNAT decision and both
/// concat sets; `sandbox_policy` carries the gateway-egress allow chain keyed
/// on the same sets. They are managed as a pair — a rollback that restored
/// one would leave the gateway half-configured.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NftTable {
    SandboxDnat,
    SandboxPolicy,
}

impl NftTable {
    /// Both tables, in the order the rollback snapshot reads them.
    pub const ALL: &'static [NftTable] = &[NftTable::SandboxDnat, NftTable::SandboxPolicy];

    /// The table's name as `nft` spells it.
    pub fn name(self) -> &'static str {
        match self {
            NftTable::SandboxDnat => "sandbox_dnat",
            NftTable::SandboxPolicy => "sandbox_policy",
        }
    }
}

// ---------------------------------------------------------------------------
// StdinCommand
// ---------------------------------------------------------------------------

/// The closed set of commands the daemon may feed a body to on stdin.
///
/// These are the two shapes §5.3 of the design calls out as not fitting a
/// plain request/response op: a multi-KB artifact goes to the child's
/// standard input rather than into its argv.
///
/// # Adding a variant is a security change
///
/// This enum and [`GatewayFile`] are the whole of what a compromised daemon
/// can write inside the operator's gateway container. Both rules from
/// [`crate::container::ContainerCommand`] apply, plus one specific to this
/// enum: **a variant whose body is interpreted as commands rather than as
/// data does not belong here.** `nft -f -` and `cat` both read their stdin
/// as content; a variant that piped the body to a shell would turn the
/// content channel — the one thing here that *is* caller-supplied — into an
/// argv pass-through by another route.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StdinCommand {
    /// `nft -f -` — apply an nftables ruleset read from stdin.
    ///
    /// The ruleset is the artifact whose drift is an unenforced policy, so
    /// it goes to `nft` verbatim: no shell, no quoting, no transformation
    /// between the generator and the parser.
    ApplyNftRuleset,
    /// Deliver one gateway file, its content read from stdin.
    WriteGatewayFile {
        file: GatewayFile,
        delivery: FileDelivery,
    },
}

impl StdinCommand {
    /// The argv this command runs inside the container.
    ///
    /// For [`Self::WriteGatewayFile`] the result is `sh -c <body>`, and the
    /// body is a function of the two enums above and nothing else. See
    /// [`write_script`].
    pub fn argv(self) -> Vec<String> {
        match self {
            StdinCommand::ApplyNftRuleset => {
                vec!["nft".to_string(), "-f".to_string(), "-".to_string()]
            }
            StdinCommand::WriteGatewayFile { file, delivery } => vec![
                "sh".to_string(),
                "-c".to_string(),
                write_script(file, delivery),
            ],
        }
    }

    /// A stable label for logs and error messages.
    pub fn as_str(self) -> &'static str {
        match self {
            StdinCommand::ApplyNftRuleset => "nft-apply",
            StdinCommand::WriteGatewayFile { .. } => "file-write",
        }
    }
}

/// The `sh -c` body that delivers `file` under `delivery`.
///
/// Every interpolated value is a `&'static str` from this module. Nothing a
/// caller supplies appears in the result — which is why the single quotes
/// below are legibility rather than a defence, and why
/// `every_path_is_safe_to_interpolate_into_a_shell_word` is a test of this
/// crate's own constants rather than of an input.
pub fn write_script(file: GatewayFile, delivery: FileDelivery) -> String {
    let dir = file.parent_dir();
    let path = file.path();
    match delivery {
        FileDelivery::Replace => format!("mkdir -p '{dir}' && cat > '{path}'"),
        FileDelivery::AtomicRename => {
            let staging = file.staging_path();
            format!("mkdir -p '{dir}' && cat > '{staging}' && mv -f '{staging}' '{path}'")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The property the "there is no input" claim rests on: every path this
    /// module can interpolate into a `sh -c` body is a plain absolute path
    /// with nothing a shell would re-read. A new [`GatewayFile`] variant
    /// whose path carried a quote, a space, a `$` or a `;` would make the
    /// single quotes in [`write_script`] load-bearing — and they are not
    /// written to be.
    #[test]
    fn every_path_is_safe_to_interpolate_into_a_shell_word() {
        let unsafe_chars = [
            '\'', '"', '`', '$', ';', '&', '|', '<', '>', '(', ')', '{', '}', '[', ']', '*', '?',
            '!', '#', '~', '\\', '\n', '\r', '\t', ' ',
        ];
        for file in GatewayFile::ALL {
            for (label, value) in [
                ("path", file.path()),
                ("parent_dir", file.parent_dir()),
                ("staging_path", file.staging_path()),
            ] {
                assert!(
                    value.starts_with('/'),
                    "{}.{label} must be absolute: {value:?}",
                    file.as_str()
                );
                assert!(
                    !value.contains(".."),
                    "{}.{label} must not traverse: {value:?}",
                    file.as_str()
                );
                for ch in unsafe_chars {
                    assert!(
                        !value.contains(ch),
                        "{}.{label} contains {ch:?}, which a shell would re-read: {value:?}",
                        file.as_str()
                    );
                }
            }
        }
    }

    /// The staging path is the target path plus a suffix, in the same
    /// directory. A staging file on another filesystem would turn the
    /// rename into a copy, and Envoy's watcher would see the wrong event.
    #[test]
    fn staging_sits_beside_its_target() {
        for file in GatewayFile::ALL {
            assert_eq!(
                file.staging_path(),
                format!("{}.tmp", file.path()),
                "{} stages somewhere other than beside its target",
                file.as_str()
            );
            assert!(
                file.path().starts_with(file.parent_dir()),
                "{} does not live in the directory it names",
                file.as_str()
            );
        }
    }

    /// The complete set of shell bodies, written out. This is the review
    /// surface: a reader can see every string that reaches `sh -c` without
    /// running anything, and a change to any of them fails here.
    #[test]
    fn the_shell_bodies_are_exactly_these() {
        let expected: &[(GatewayFile, FileDelivery, &str)] = &[
            (
                GatewayFile::CorednsPolicy,
                FileDelivery::Replace,
                "mkdir -p '/etc/coredns' && cat > '/etc/coredns/policy.conf'",
            ),
            (
                GatewayFile::MitmproxyPolicy,
                FileDelivery::Replace,
                "mkdir -p '/tmp/mitmproxy' && cat > '/tmp/mitmproxy/policy.json'",
            ),
            (
                GatewayFile::MitmproxyCaKey,
                FileDelivery::Replace,
                "mkdir -p '/root/.mitmproxy' && cat > '/root/.mitmproxy/mitmproxy-ca.pem'",
            ),
            (
                GatewayFile::MitmproxyCaCert,
                FileDelivery::Replace,
                "mkdir -p '/root/.mitmproxy' && cat > '/root/.mitmproxy/mitmproxy-ca-cert.pem'",
            ),
            (
                GatewayFile::EnvoyBootstrap,
                FileDelivery::Replace,
                "mkdir -p '/etc/envoy' && cat > '/etc/envoy/envoy-bootstrap.yaml'",
            ),
            (
                GatewayFile::EnvoyListener,
                FileDelivery::Replace,
                "mkdir -p '/etc/envoy/listeners' && cat > '/etc/envoy/listeners/listener.yaml'",
            ),
            (
                GatewayFile::EnvoyListener,
                FileDelivery::AtomicRename,
                "mkdir -p '/etc/envoy/listeners' && \
                 cat > '/etc/envoy/listeners/listener.yaml.tmp' && \
                 mv -f '/etc/envoy/listeners/listener.yaml.tmp' \
                 '/etc/envoy/listeners/listener.yaml'",
            ),
        ];
        for (file, delivery, body) in expected {
            assert_eq!(&write_script(*file, *delivery), body);
        }
    }

    /// CoreDNS writes its own resolved-address report; the daemon reads it.
    /// The split is what stops a read allowlist from doubling as a write
    /// allowlist.
    #[test]
    fn the_file_coredns_owns_is_not_writable() {
        assert!(!GatewayFile::CorednsResolved.writable());
        for file in GatewayFile::ALL {
            if !matches!(file, GatewayFile::CorednsResolved) {
                assert!(file.writable(), "{} should be writable", file.as_str());
            }
        }
        assert_eq!(
            GatewayFile::ALL.len(),
            7,
            "a new gateway file must be classified writable or not here"
        );
    }

    /// The nft apply carries no shell at all — the ruleset is data on a
    /// file descriptor, and `nft` is the only thing that parses it.
    #[test]
    fn applying_a_ruleset_invokes_no_shell() {
        let argv = StdinCommand::ApplyNftRuleset.argv();
        assert_eq!(argv, vec!["nft", "-f", "-"]);
        assert!(!argv.iter().any(|a| a == "sh" || a == "-c"));
    }

    #[test]
    fn a_file_write_is_a_shell_with_exactly_one_body() {
        let argv = StdinCommand::WriteGatewayFile {
            file: GatewayFile::CorednsPolicy,
            delivery: FileDelivery::Replace,
        }
        .argv();
        assert_eq!(argv.len(), 3);
        assert_eq!(&argv[0], "sh");
        assert_eq!(&argv[1], "-c");
        assert_eq!(
            &argv[2],
            &write_script(GatewayFile::CorednsPolicy, FileDelivery::Replace)
        );
    }

    #[test]
    fn nft_tables_name_the_pair_the_policy_plane_manages() {
        assert_eq!(NftTable::SandboxDnat.name(), "sandbox_dnat");
        assert_eq!(NftTable::SandboxPolicy.name(), "sandbox_policy");
        assert_eq!(NftTable::ALL.len(), 2);
    }

    /// The stats URL is one argv element on purpose: the `&` separates two
    /// query parameters for Envoy, and a shell would read it as a job-control
    /// operator.
    #[test]
    fn the_stats_url_is_a_single_query_string() {
        assert!(ENVOY_ACTIVE_LISTENERS_STATS_URL.contains("filter=^listener_manager"));
        assert!(ENVOY_ACTIVE_LISTENERS_STATS_URL.contains("&format=text"));
        assert!(!ENVOY_ACTIVE_LISTENERS_STATS_URL.contains(' '));
    }
}
