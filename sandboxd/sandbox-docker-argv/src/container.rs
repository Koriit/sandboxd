//! Container-lifecycle argv builders.
//!
//! Every function here is pure: typed values in, argv out. The daemon
//! calls them when it drives its own Docker daemon; the per-operator agent
//! calls the same functions when the daemon asks it to drive the Docker
//! instance inside the operator's VM. Neither side ever hands the other a
//! ready-made argv.

use crate::DockerArgvError;

/// Hardening flags for the container's `/tmp` tmpfs.
pub const TMPFS_TMP_FLAGS: &str = "rw,nosuid,nodev,size=256m";
/// Hardening flags for the container's `/run` tmpfs.
pub const TMPFS_RUN_FLAGS: &str = "rw,nosuid,nodev,size=16m";
/// Process-count ceiling applied to every session container.
pub const PIDS_LIMIT: u32 = 512;

/// Stable in-container path of the per-session sandbox CA.
pub const SANDBOX_CA_CONTAINER_PATH: &str = "/etc/ssl/certs/sandbox-ca.pem";

/// HTTPS-client trust env var names that must point at the per-session CA
/// file inside the container, in the order the argv emits them.
pub const SANDBOX_CA_ENV_VARS: &[&str] = &[
    "CURL_CA_BUNDLE",
    "SSL_CERT_FILE",
    "REQUESTS_CA_BUNDLE",
    "NODE_EXTRA_CA_CERTS",
];

/// In-container destination of the daemon-staged `sandbox-guest` binary.
pub const GUEST_BIND_DESTINATION: &str = "/usr/local/bin/sandbox-guest";

/// The three per-session SSH credential files and their in-container
/// destinations, in the order the argv emits them.
pub const SSH_CREDENTIAL_MOUNTS: &[(&str, &str)] = &[
    ("authorized_keys", "/run/sandbox/authorized_keys"),
    ("passwd", "/etc/passwd"),
    ("group", "/etc/group"),
];

/// The container name for a session id (`sandbox-<id>`).
pub fn container_name(session_id: &str) -> String {
    format!("sandbox-{session_id}")
}

/// The named home volume for a session id (`sandbox-home-<id>`).
pub fn home_volume_name(session_id: &str) -> String {
    format!("sandbox-home-{session_id}")
}

/// Format the cpus knob as a one-decimal string (`2.0`, `0.5`).
pub fn format_cpus(cpus: f64) -> String {
    format!("{cpus:.1}")
}

/// A host→guest bind pair for the session workspace.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkspaceBindSpec {
    pub host_path: String,
    pub guest_path: String,
}

/// Every typed value `docker create` needs for a session container.
///
/// Fields are plain owned scalars rather than the daemon's richer types
/// (`SessionId`, `IpAddr`, `PathBuf`) so the struct can be populated
/// identically on both sides of the broker channel without either side
/// depending on the other's type vocabulary.
#[derive(Debug, Clone, PartialEq)]
pub struct ContainerCreateSpec {
    pub session_id: String,
    pub docker_network: String,
    pub container_ip: String,
    pub gateway_ip: String,
    pub image_tag: String,
    pub user_uid: u32,
    pub user_gid: u32,
    pub memory_mb: u32,
    pub cpus: f64,
    /// Daemon pool CIDR stamped as the `sandboxd.owner` label. `None` on
    /// sessions registered before pool ownership existed.
    pub owner_pool: Option<String>,
    /// Operator-supplied workspace bind, if any.
    pub workspace_bind: Option<WorkspaceBindSpec>,
    /// Host path of the per-session CA certificate, if one was staged.
    pub ca_host_path: Option<String>,
    /// Host directory holding the three staged SSH credential files.
    pub ssh_host_dir: Option<String>,
    /// Host path of the `sandbox-guest` binary to overlay read-only.
    /// `None` skips the overlay — the case where the host path does not
    /// exist inside the Docker daemon's own filesystem.
    pub guest_bind_source: Option<String>,
}

/// Compose the `docker create` argv for a session container.
///
/// Argument order is part of the contract.
///
/// Fallible because the operator-supplied workspace paths are interpolated
/// into a `--mount` option list: docker reads `,` and `=` as option-list
/// syntax there, so a path containing either would silently add mount
/// options nobody wrote. Rejecting is the only correct answer a pure
/// builder can give — docker's option parser is the sole authority on what
/// an escape would mean.
pub fn container_create_argv(spec: &ContainerCreateSpec) -> Result<Vec<String>, DockerArgvError> {
    let home_volume = home_volume_name(&spec.session_id);
    let workspace_mount = match spec.workspace_bind.as_ref() {
        None => None,
        Some(bind) => {
            for (label, path) in [
                ("host_path", &bind.host_path),
                ("guest_path", &bind.guest_path),
            ] {
                if let Some(ch) = path.chars().find(|c| matches!(c, ',' | '=')) {
                    return Err(DockerArgvError::new(format!(
                        "workspace {label} {path:?} contains {ch:?}, which docker reads \
                         as option-list syntax in a `--mount` value rather than as part of \
                         the path — a path containing it would silently add mount options \
                         the daemon never wrote. What works instead: rename the directory \
                         to a name without `,` or `=`, stage a copy at such a path and \
                         point the workspace there, or for a git-backed project use \
                         clone:<repo-url> / --repo, which never names a host path."
                    )));
                }
            }
            Some(format!(
                "type=bind,src={},dst={}",
                bind.host_path, bind.guest_path
            ))
        }
    };

    let mut args: Vec<String> = vec![
        "create".to_string(),
        "--name".to_string(),
        container_name(&spec.session_id),
        "--hostname".to_string(),
        spec.session_id.clone(),
        "--network".to_string(),
        spec.docker_network.clone(),
        "--ip".to_string(),
        spec.container_ip.clone(),
        "--dns".to_string(),
        spec.gateway_ip.clone(),
        // Hardening — every flag in the documented contract applied
        // verbatim, in table order.
        "--read-only".to_string(),
        "--tmpfs".to_string(),
        format!("/tmp:{TMPFS_TMP_FLAGS}"),
        "--tmpfs".to_string(),
        format!("/run:{TMPFS_RUN_FLAGS}"),
        "--security-opt".to_string(),
        "no-new-privileges".to_string(),
        "--security-opt".to_string(),
        "seccomp=builtin".to_string(),
        "--cap-drop".to_string(),
        "ALL".to_string(),
        // Lower the privileged-port floor inside the container netns so the
        // in-image sshd can bind `127.0.0.1:22` as an unprivileged uid
        // without CAP_NET_BIND_SERVICE. The sysctl is namespaced (net) and
        // applies only to this container.
        "--sysctl".to_string(),
        "net.ipv4.ip_unprivileged_port_start=22".to_string(),
        "--user".to_string(),
        format!("{}:{}", spec.user_uid, spec.user_gid),
        "--pids-limit".to_string(),
        PIDS_LIMIT.to_string(),
        "--memory".to_string(),
        format!("{}m", spec.memory_mb),
        "--cpus".to_string(),
        format_cpus(spec.cpus),
        "--restart".to_string(),
        "no".to_string(),
        "--label".to_string(),
        format!("sandbox.session_id={}", spec.session_id),
    ];

    if let Some(pool) = spec.owner_pool.as_ref() {
        args.push("--label".to_string());
        args.push(format!("sandboxd.owner={pool}"));
    }

    args.push("--mount".to_string());
    args.push(format!("type=volume,src={home_volume},dst=/home/sandbox"));

    if let Some(source) = spec.guest_bind_source.as_ref() {
        args.push("-v".to_string());
        args.push(format!("{source}:{GUEST_BIND_DESTINATION}:ro"));
    }

    if let Some(mount) = workspace_mount {
        args.push("--mount".to_string());
        args.push(mount);
    }

    args.extend(ca_mount_args(spec.ca_host_path.as_deref()));
    args.extend(ssh_mount_args(spec.ssh_host_dir.as_deref()));

    // Trailing positional: image tag — must come last so subsequent
    // entrypoint args (none here) line up with the docker CLI grammar.
    args.push(spec.image_tag.clone());
    Ok(args)
}

/// The `--mount` + `--env` fragment for the per-session CA bind, or an
/// empty vec when no CA was staged.
pub fn ca_mount_args(ca_host_path: Option<&str>) -> Vec<String> {
    let Some(ca_path) = ca_host_path else {
        return Vec::new();
    };
    let mut out = Vec::with_capacity(2 + SANDBOX_CA_ENV_VARS.len() * 2);
    out.push("--mount".to_string());
    out.push(format!(
        "type=bind,src={ca_path},dst={SANDBOX_CA_CONTAINER_PATH},readonly"
    ));
    for var in SANDBOX_CA_ENV_VARS {
        out.push("--env".to_string());
        out.push(format!("{var}={SANDBOX_CA_CONTAINER_PATH}"));
    }
    out
}

/// The three `--mount` pairs for the staged SSH credential files, or an
/// empty vec when no SSH directory was staged.
pub fn ssh_mount_args(ssh_host_dir: Option<&str>) -> Vec<String> {
    let Some(dir) = ssh_host_dir else {
        return Vec::new();
    };
    let dir = dir.trim_end_matches('/');
    let mut out = Vec::with_capacity(SSH_CREDENTIAL_MOUNTS.len() * 2);
    for (file_name, dst) in SSH_CREDENTIAL_MOUNTS {
        out.push("--mount".to_string());
        out.push(format!(
            "type=bind,src={dir}/{file_name},dst={dst},readonly"
        ));
    }
    out
}

/// `docker start <name>`.
pub fn container_start_argv(name: &str) -> Vec<String> {
    vec!["start".to_string(), name.to_string()]
}

/// `docker stop -t <secs> <name>`.
pub fn container_stop_argv(name: &str, grace_secs: u32) -> Vec<String> {
    vec![
        "stop".to_string(),
        "-t".to_string(),
        grace_secs.to_string(),
        name.to_string(),
    ]
}

/// `docker stop --time <secs> <name>` — the long-flag spelling the gateway
/// manager has always used. Kept distinct from [`container_stop_argv`]
/// rather than unified, because the two argvs are pinned by separate tests
/// and silently changing either is a behaviour change nobody asked for.
pub fn container_stop_long_argv(name: &str, grace_secs: u32) -> Vec<String> {
    vec![
        "stop".to_string(),
        "--time".to_string(),
        grace_secs.to_string(),
        name.to_string(),
    ]
}

/// `docker restart <name>`.
pub fn container_restart_argv(name: &str) -> Vec<String> {
    vec!["restart".to_string(), name.to_string()]
}

/// How `docker rm` spells its force flag at a given call site.
///
/// Two spellings are in production use and both are pinned by tests, so
/// the choice is carried as a typed value rather than normalised away.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RemoveForce {
    /// No force flag — removal fails on a running container.
    No,
    /// `-f`.
    Short,
    /// `--force`.
    Long,
}

/// `docker rm [-f|--force] <name>`.
pub fn container_remove_argv(name: &str, force: RemoveForce) -> Vec<String> {
    let mut argv = vec!["rm".to_string()];
    match force {
        RemoveForce::No => {}
        RemoveForce::Short => argv.push("-f".to_string()),
        RemoveForce::Long => argv.push("--force".to_string()),
    }
    argv.push(name.to_string());
    argv
}

/// The closed set of `docker inspect --format` templates the daemon asks
/// for.
///
/// A free-form format string would be a Go-template pass-through: it can
/// read any field of the container's configuration, including its
/// environment and mounts. Enumerating the templates keeps the read
/// surface reviewable.
///
/// # Adding a variant is a security change
///
/// Every variant here is a field of the container's configuration the
/// daemon can read out of the operator's VM. Nobody is going to replace
/// this enum with a format string in one obvious commit — the way it stops
/// bounding anything is one more variant at a time, each individually
/// reasonable, until the set covers enough of the config that a free string
/// would have been equivalent.
///
/// So: before adding one, say what the *caller* needs, not what template
/// answers it, and check whether an existing variant already does. A
/// variant that exists only because it was convenient at one call site is
/// the sixth one this warning is written for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InspectFormat {
    /// `{{.State.Status}}` — the lifecycle state word.
    StateStatus,
    /// `{{.State.Running}}` — the running boolean.
    StateRunning,
    /// `{{.State.Health.Status}}` — the healthcheck verdict.
    StateHealthStatus,
    /// `{{.State.Pid}}` — the container's init pid in the Docker daemon's
    /// pid namespace.
    StatePid,
    /// `{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}` — the
    /// container's address on its attached network.
    NetworkIpAddress,
}

impl InspectFormat {
    /// The Go template this format renders.
    pub fn template(self) -> &'static str {
        match self {
            InspectFormat::StateStatus => "{{.State.Status}}",
            InspectFormat::StateRunning => "{{.State.Running}}",
            InspectFormat::StateHealthStatus => "{{.State.Health.Status}}",
            InspectFormat::StatePid => "{{.State.Pid}}",
            InspectFormat::NetworkIpAddress => {
                "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}"
            }
        }
    }
}

/// How `docker inspect` spells its format flag at a given call site.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InspectFlag {
    /// `-f`.
    Short,
    /// `--format`.
    Long,
}

/// `docker inspect [-f|--format] <template> <name>`.
pub fn container_inspect_argv(name: &str, format: InspectFormat, flag: InspectFlag) -> Vec<String> {
    vec![
        "inspect".to_string(),
        match flag {
            InspectFlag::Short => "-f".to_string(),
            InspectFlag::Long => "--format".to_string(),
        },
        format.template().to_string(),
        name.to_string(),
    ]
}

/// `docker ps -a --filter name=<prefix> [--filter label=sandboxd.owner=<pool>]
/// --format {{.Names}}`.
pub fn container_list_argv(name_prefix: &str, owner_pool: Option<&str>) -> Vec<String> {
    let mut argv = vec![
        "ps".to_string(),
        "-a".to_string(),
        "--filter".to_string(),
        format!("name={name_prefix}"),
    ];
    if let Some(pool) = owner_pool {
        argv.push("--filter".to_string());
        argv.push(format!("label=sandboxd.owner={pool}"));
    }
    argv.push("--format".to_string());
    argv.push("{{.Names}}".to_string());
    argv
}

/// `docker run --rm --user 0:0 --mount … --entrypoint chown <image> -R
/// <uid>:<gid> /home/sandbox` — the one-shot init container that hands the
/// freshly seeded home volume to the operator's uid.
pub fn home_chown_run_argv(
    session_id: &str,
    image_tag: &str,
    operator_uid: u32,
    operator_gid: u32,
) -> Vec<String> {
    let home_volume = home_volume_name(session_id);
    vec![
        "run".to_string(),
        "--rm".to_string(),
        "--user".to_string(),
        "0:0".to_string(),
        "--mount".to_string(),
        format!("type=volume,src={home_volume},dst=/home/sandbox"),
        "--entrypoint".to_string(),
        "chown".to_string(),
        image_tag.to_string(),
        "-R".to_string(),
        format!("{operator_uid}:{operator_gid}"),
        "/home/sandbox".to_string(),
    ]
}

/// The gateway container name for a session id (`sandbox-gw-<id>`).
pub fn gateway_container_name(session_id: &str) -> String {
    format!("sandbox-gw-{session_id}")
}

/// Compose the `docker run` argv for a session's gateway container.
///
/// The hardening properties this pins are the contract: no `--privileged`,
/// `--read-only` rootfs, exactly one `--cap-add NET_ADMIN`, every writable
/// area a tmpfs, and no host-path bind-mount anywhere — the gateway VM has
/// its own filesystem, so a host bind would silently mount nothing.
pub fn gateway_container_run_argv(
    session_id: &str,
    image_tag: &str,
    network: &str,
    owner_pool: Option<&str>,
    coredns_upstream: Option<&str>,
) -> Vec<String> {
    let mut args = vec![
        "run".to_string(),
        "-d".to_string(),
        "--name".to_string(),
        gateway_container_name(session_id),
        "--network".to_string(),
        network.to_string(),
        "--read-only".to_string(),
        "--cap-add".to_string(),
        "NET_ADMIN".to_string(),
        "--tmpfs".to_string(),
        "/var/log:rw,noexec,nosuid".to_string(),
        "--tmpfs".to_string(),
        "/var/run:rw,noexec,nosuid".to_string(),
        "--tmpfs".to_string(),
        "/tmp:rw,exec,nosuid".to_string(),
        "--tmpfs".to_string(),
        "/root/.mitmproxy:rw".to_string(),
        "--tmpfs".to_string(),
        "/etc/coredns:rw,noexec,nosuid".to_string(),
        "--tmpfs".to_string(),
        "/etc/envoy:rw,noexec,nosuid".to_string(),
        "--sysctl".to_string(),
        "net.ipv4.ip_forward=1".to_string(),
        "--sysctl".to_string(),
        "net.ipv6.conf.all.forwarding=0".to_string(),
    ];

    // CoreDNS upstream forwarder. Inside the gateway VM, Docker's embedded
    // resolver at 127.0.0.11 is a dead end — its own upstream, the VM's
    // systemd-resolved stub, does not answer, so an allowed domain SERVFAILs
    // on the forward even though DNS policy admits it. Pointing CoreDNS at
    // public resolvers never weakens deny: a denied domain is answered
    // NXDOMAIN before the forward runs.
    if let Some(upstream) = coredns_upstream {
        args.push("--env".to_string());
        args.push(format!("SANDBOX_COREDNS_UPSTREAM={upstream}"));
    }

    args.push("--restart".to_string());
    args.push("unless-stopped".to_string());
    args.push("--label".to_string());
    args.push(format!("sandbox.session_id={session_id}"));

    if let Some(pool) = owner_pool {
        args.push("--label".to_string());
        args.push(format!("sandboxd.owner={pool}"));
    }

    args.push(image_tag.to_string());
    args
}

/// The closed set of commands the daemon may ask to run inside a
/// container.
///
/// This is the enum that stops `docker exec` from being an argv
/// pass-through. Each variant names an operation, not a command line; the
/// command line is built here and nowhere else. Variants that carry data
/// carry exactly the values that vary — a path, a component name — never a
/// program name and never a shell string.
///
/// # Adding a variant is a security change
///
/// Each variant is code the daemon can cause to run inside a container the
/// operator owns, so the set is the answer to "what can a compromised
/// daemon execute in there?". That answer is only useful while it is short.
/// The failure mode is not somebody adding an argv pass-through — it is a
/// steady drip of individually reasonable variants until the set is
/// effectively open and the agent's validation has nothing left to refuse.
///
/// Two rules for the variant after this one:
///
/// - **Name the operation, not the command.** `SshdListening`, not
///   `RunSs { args }`. If the variant's name reads like a command line, it
///   is a pass-through wearing an enum.
/// - **Carry only what varies.** A path or an identifier is a field; a
///   program name, a flag list or a shell fragment is not. Anything that
///   would let the caller change *what runs* rather than *what it runs on*
///   belongs in this crate as a constant, next to the probes, or nowhere.
///
/// And whatever it carries, add the matching agent-side validation in the
/// same change — a field nobody checks is a field the caller controls.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContainerCommand {
    /// `ss -tlnH ( sport = :22 )` — is sshd listening yet?
    SshdListening,
    /// `mkdir -p <path>` — pre-create an rsync destination.
    MakeDirectory { path: String },
    /// `/healthcheck.sh` — the gateway image's own aggregate health probe.
    GatewayHealthcheck,
    /// The readiness probe for one named gateway component.
    ComponentProbe { component: GatewayComponent },
    /// Read one of the enumerated gateway policy files back out.
    ///
    /// `cat <path>`, with the path a constant of this crate — the read
    /// counterpart of [`crate::gateway::StdinCommand::WriteGatewayFile`],
    /// used to snapshot the prior generation before a policy apply so a
    /// failure can be rolled back.
    ReadGatewayFile { file: crate::gateway::GatewayFile },
    /// List one of the two sandbox nftables tables.
    ///
    /// The other half of the rollback snapshot: the ruleset currently in
    /// force, as `nft` prints it.
    ListNftTable { table: crate::gateway::NftTable },
    /// Read one of the enumerated Envoy admin statistics.
    ///
    /// The URL is a constant of [`crate::gateway::EnvoyStat`] passed as one
    /// argv element, so the `&` in its query string reaches Envoy rather
    /// than a shell.
    EnvoyStat { stat: crate::gateway::EnvoyStat },
}

/// The gateway container's five long-running components.
///
/// Their probes are constants of this crate. Two of them need a shell
/// because the listener address is only discoverable from inside the
/// container (`hostname -i`); that shell string is written here, not
/// supplied by the daemon, which is what keeps it off the "shell built
/// from caller input" list.
///
/// This enum is reached through [`ContainerCommand::ComponentProbe`], so
/// the warning on that type applies here too: a new component means a new
/// probe body, and a probe body is code running inside the operator's
/// container. Two of the five already contain a shell; a third should have
/// to justify itself the same way these two do.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GatewayComponent {
    Envoy,
    Coredns,
    Mitmproxy,
    DenyLogger,
    AllowLogger,
}

impl GatewayComponent {
    /// The component's canonical lowercase kebab-case name, as it appears
    /// in operator-facing status output.
    pub fn as_str(self) -> &'static str {
        match self {
            GatewayComponent::Envoy => "envoy",
            GatewayComponent::Coredns => "coredns",
            GatewayComponent::Mitmproxy => "mitmproxy",
            GatewayComponent::DenyLogger => "deny-logger",
            GatewayComponent::AllowLogger => "allow-logger",
        }
    }

    /// Parse a canonical component name. Deliberately case-sensitive:
    /// the canonical form is lowercase kebab-case and accepting other
    /// shapes would silently widen the set.
    pub fn parse(name: &str) -> Option<Self> {
        match name {
            "envoy" => Some(GatewayComponent::Envoy),
            "coredns" => Some(GatewayComponent::Coredns),
            "mitmproxy" => Some(GatewayComponent::Mitmproxy),
            "deny-logger" => Some(GatewayComponent::DenyLogger),
            "allow-logger" => Some(GatewayComponent::AllowLogger),
            _ => None,
        }
    }

    /// The component's readiness probe argv, as run inside the container.
    pub fn probe(self) -> Vec<String> {
        match self {
            GatewayComponent::Envoy => vec![
                "curl".to_string(),
                "-sf".to_string(),
                "http://127.0.0.1:9901/ready".to_string(),
            ],
            GatewayComponent::Coredns => vec![
                "curl".to_string(),
                "-sf".to_string(),
                "http://127.0.0.1:8180/health".to_string(),
            ],
            GatewayComponent::Mitmproxy => {
                vec![
                    "pgrep".to_string(),
                    "-x".to_string(),
                    "mitmdump".to_string(),
                ]
            }
            // The deny/allow loggers bind their health listeners on the
            // gateway bridge IP rather than loopback (PREROUTING DNAT to
            // loopback is dropped as a martian destination), so the probe
            // has to discover that address from inside the container.
            GatewayComponent::DenyLogger => vec![
                "sh".to_string(),
                "-c".to_string(),
                "curl -sf \"http://$(hostname -i | awk '{print $1}'):10003/health\"".to_string(),
            ],
            GatewayComponent::AllowLogger => vec![
                "sh".to_string(),
                "-c".to_string(),
                "curl -sf \"http://$(hostname -i | awk '{print $1}'):10004/health\"".to_string(),
            ],
        }
    }
}

impl ContainerCommand {
    /// The argv this command runs inside the container.
    pub fn argv(&self) -> Vec<String> {
        match self {
            ContainerCommand::SshdListening => vec![
                "ss".to_string(),
                "-tlnH".to_string(),
                "( sport = :22 )".to_string(),
            ],
            ContainerCommand::MakeDirectory { path } => {
                vec!["mkdir".to_string(), "-p".to_string(), path.clone()]
            }
            ContainerCommand::GatewayHealthcheck => vec!["/healthcheck.sh".to_string()],
            ContainerCommand::ComponentProbe { component } => component.probe(),
            ContainerCommand::ReadGatewayFile { file } => {
                vec!["cat".to_string(), file.path().to_string()]
            }
            ContainerCommand::ListNftTable { table } => vec![
                "nft".to_string(),
                "list".to_string(),
                "table".to_string(),
                "inet".to_string(),
                table.name().to_string(),
            ],
            ContainerCommand::EnvoyStat { stat } => vec![
                "curl".to_string(),
                "-sf".to_string(),
                stat.url().to_string(),
            ],
        }
    }
}

/// `docker exec <name> <command…>`.
pub fn container_exec_argv(name: &str, command: &ContainerCommand) -> Vec<String> {
    let mut argv = vec!["exec".to_string(), name.to_string()];
    argv.extend(command.argv());
    argv
}

/// `docker exec -i <name> <command…>` — the stdin-fed form.
///
/// `-i` is what keeps the child's standard input attached to the pipe the
/// caller writes the artifact to. Without it the exec runs with a closed
/// stdin and `cat > file` truncates the policy file to empty — a failure
/// that looks like a successful write.
pub fn container_exec_stdin_argv(name: &str, command: crate::gateway::StdinCommand) -> Vec<String> {
    let mut argv = vec!["exec".to_string(), "-i".to_string(), name.to_string()];
    argv.extend(command.argv());
    argv
}

#[cfg(test)]
mod tests {
    use super::*;

    fn minimal_spec() -> ContainerCreateSpec {
        ContainerCreateSpec {
            session_id: "abc123".to_string(),
            docker_network: "sandbox-net-abc123".to_string(),
            container_ip: "10.209.0.3".to_string(),
            gateway_ip: "10.209.0.2".to_string(),
            image_tag: "sandboxd-lite:0.1.0".to_string(),
            user_uid: 1000,
            user_gid: 1000,
            memory_mb: 2048,
            cpus: 2.0,
            owner_pool: None,
            workspace_bind: None,
            ca_host_path: None,
            ssh_host_dir: None,
            guest_bind_source: None,
        }
    }

    #[test]
    fn create_argv_leads_with_the_subcommand_and_ends_with_the_image() {
        let argv = container_create_argv(&minimal_spec()).expect("minimal spec must build");
        assert_eq!(argv.first().map(String::as_str), Some("create"));
        assert_eq!(argv.last().map(String::as_str), Some("sandboxd-lite:0.1.0"));
    }

    #[test]
    fn create_argv_carries_every_hardening_flag() {
        let argv = container_create_argv(&minimal_spec()).expect("minimal spec must build");
        for flag in [
            "--read-only",
            "--security-opt",
            "--cap-drop",
            "--pids-limit",
            "--restart",
        ] {
            assert!(argv.iter().any(|a| a == flag), "missing {flag}: {argv:?}");
        }
        assert!(
            argv.windows(2)
                .any(|w| w[0] == "--cap-drop" && w[1] == "ALL")
        );
        assert!(argv.windows(2).any(|w| w[0] == "--restart" && w[1] == "no"));
        assert!(
            argv.windows(2)
                .any(|w| w[0] == "--security-opt" && w[1] == "no-new-privileges")
        );
        assert!(
            argv.windows(2)
                .any(|w| w[0] == "--security-opt" && w[1] == "seccomp=builtin")
        );
    }

    #[test]
    fn create_argv_omits_the_guest_overlay_when_no_source_is_given() {
        let argv = container_create_argv(&minimal_spec()).expect("minimal spec must build");
        assert!(
            !argv.iter().any(|a| a == "-v"),
            "no guest bind source means no -v flag: {argv:?}"
        );
    }

    #[test]
    fn create_argv_binds_the_guest_binary_read_only_when_a_source_is_given() {
        let mut spec = minimal_spec();
        spec.guest_bind_source = Some("/usr/local/libexec/sandboxd/sandbox-guest".to_string());
        let argv = container_create_argv(&spec).expect("spec must build");
        assert!(argv.windows(2).any(|w| {
            w[0] == "-v"
                && w[1]
                    == "/usr/local/libexec/sandboxd/sandbox-guest:/usr/local/bin/sandbox-guest:ro"
        }));
    }

    #[test]
    fn create_argv_stamps_the_owner_label_only_when_a_pool_is_set() {
        let argv = container_create_argv(&minimal_spec()).expect("minimal spec must build");
        assert!(!argv.iter().any(|a| a.starts_with("sandboxd.owner=")));

        let mut spec = minimal_spec();
        spec.owner_pool = Some("10.209.128.0/24".to_string());
        let argv = container_create_argv(&spec).expect("spec must build");
        assert!(
            argv.windows(2)
                .any(|w| w[0] == "--label" && w[1] == "sandboxd.owner=10.209.128.0/24")
        );
    }

    #[test]
    fn create_argv_rejects_option_list_syntax_in_a_workspace_path() {
        for bad in ["/tmp/a,b", "/tmp/a=b"] {
            let mut spec = minimal_spec();
            spec.workspace_bind = Some(WorkspaceBindSpec {
                host_path: bad.to_string(),
                guest_path: "/home/sandbox/workspace".to_string(),
            });
            let err = container_create_argv(&spec)
                .expect_err("a path with docker option-list syntax must be refused");
            assert!(
                err.message().contains("option-list syntax"),
                "message must explain why: {}",
                err.message()
            );
        }
    }

    #[test]
    fn create_argv_emits_ca_mount_and_all_four_trust_env_vars() {
        let mut spec = minimal_spec();
        spec.ca_host_path = Some("/var/lib/sandboxd/sessions/abc123/ca/cert.pem".to_string());
        let argv = container_create_argv(&spec).expect("spec must build");
        assert!(argv.windows(2).any(|w| {
            w[0] == "--mount"
                && w[1]
                    == "type=bind,src=/var/lib/sandboxd/sessions/abc123/ca/cert.pem,\
                        dst=/etc/ssl/certs/sandbox-ca.pem,readonly"
        }));
        for var in SANDBOX_CA_ENV_VARS {
            assert!(
                argv.windows(2).any(
                    |w| w[0] == "--env" && w[1] == format!("{var}={SANDBOX_CA_CONTAINER_PATH}")
                ),
                "missing trust env var {var}: {argv:?}"
            );
        }
    }

    #[test]
    fn ssh_mount_args_emit_three_readonly_binds_in_order() {
        let args = ssh_mount_args(Some("/var/lib/sandboxd/sessions/abc/ssh"));
        assert_eq!(args.len(), 6);
        assert_eq!(
            args[1],
            "type=bind,src=/var/lib/sandboxd/sessions/abc/ssh/authorized_keys,\
             dst=/run/sandbox/authorized_keys,readonly"
        );
        assert_eq!(
            args[3],
            "type=bind,src=/var/lib/sandboxd/sessions/abc/ssh/passwd,dst=/etc/passwd,readonly"
        );
        assert_eq!(
            args[5],
            "type=bind,src=/var/lib/sandboxd/sessions/abc/ssh/group,dst=/etc/group,readonly"
        );
    }

    #[test]
    fn ssh_mount_args_are_empty_without_a_staging_directory() {
        assert!(ssh_mount_args(None).is_empty());
    }

    #[test]
    fn remove_argv_spells_force_the_way_the_call_site_asks() {
        assert_eq!(container_remove_argv("c", RemoveForce::No), vec!["rm", "c"]);
        assert_eq!(
            container_remove_argv("c", RemoveForce::Short),
            vec!["rm", "-f", "c"]
        );
        assert_eq!(
            container_remove_argv("c", RemoveForce::Long),
            vec!["rm", "--force", "c"]
        );
    }

    #[test]
    fn inspect_argv_uses_the_enumerated_template_and_the_requested_flag() {
        assert_eq!(
            container_inspect_argv("c", InspectFormat::StatePid, InspectFlag::Short),
            vec!["inspect", "-f", "{{.State.Pid}}", "c"]
        );
        assert_eq!(
            container_inspect_argv("c", InspectFormat::StateHealthStatus, InspectFlag::Long),
            vec!["inspect", "--format", "{{.State.Health.Status}}", "c"]
        );
    }

    #[test]
    fn list_argv_adds_the_owner_filter_only_when_a_pool_is_given() {
        assert_eq!(
            container_list_argv("sandbox-", None),
            vec![
                "ps",
                "-a",
                "--filter",
                "name=sandbox-",
                "--format",
                "{{.Names}}"
            ]
        );
        let argv = container_list_argv("sandbox-", Some("10.209.128.0/24"));
        assert!(
            argv.windows(2)
                .any(|w| w[0] == "--filter" && w[1] == "label=sandboxd.owner=10.209.128.0/24")
        );
    }

    #[test]
    fn every_gateway_component_has_a_probe_and_round_trips_its_name() {
        for component in [
            GatewayComponent::Envoy,
            GatewayComponent::Coredns,
            GatewayComponent::Mitmproxy,
            GatewayComponent::DenyLogger,
            GatewayComponent::AllowLogger,
        ] {
            assert!(!component.probe().is_empty());
            assert_eq!(GatewayComponent::parse(component.as_str()), Some(component));
        }
    }

    #[test]
    fn component_names_are_case_sensitive() {
        assert!(GatewayComponent::parse("Envoy").is_none());
        assert!(GatewayComponent::parse("DENY-LOGGER").is_none());
        assert!(GatewayComponent::parse("deny_logger").is_none());
        assert!(GatewayComponent::parse("").is_none());
    }

    /// The logger probes must discover the bridge IP inside the container
    /// rather than assuming loopback — a regression to `127.0.0.1` produces
    /// health checks that pass while the listener is unreachable.
    #[test]
    fn logger_probes_discover_the_bridge_ip_rather_than_loopback() {
        for (component, port) in [
            (GatewayComponent::DenyLogger, "10003"),
            (GatewayComponent::AllowLogger, "10004"),
        ] {
            let probe = component.probe();
            assert_eq!(probe.first().map(String::as_str), Some("sh"));
            assert!(probe.iter().any(|a| a.contains("hostname -i")));
            assert!(probe.iter().any(|a| a.contains(&format!(":{port}/health"))));
            assert!(
                !probe
                    .iter()
                    .any(|a| a.contains(&format!("127.0.0.1:{port}")))
            );
        }
    }

    #[test]
    fn exec_argv_places_the_container_before_the_command() {
        let argv = container_exec_argv(
            "sandbox-abc",
            &ContainerCommand::MakeDirectory {
                path: "/home/sandbox/workspace".to_string(),
            },
        );
        assert_eq!(
            argv,
            vec![
                "exec",
                "sandbox-abc",
                "mkdir",
                "-p",
                "/home/sandbox/workspace"
            ]
        );
    }

    #[test]
    fn home_chown_run_argv_overrides_the_entrypoint_and_runs_as_root() {
        let argv = home_chown_run_argv("abc", "sandboxd-lite:0.1.0", 501, 20);
        assert!(argv.windows(2).any(|w| w[0] == "--user" && w[1] == "0:0"));
        assert!(
            argv.windows(2)
                .any(|w| w[0] == "--entrypoint" && w[1] == "chown")
        );
        assert!(argv.iter().any(|a| a == "--rm"));
        assert_eq!(argv.last().map(String::as_str), Some("/home/sandbox"));
        assert!(argv.iter().any(|a| a == "501:20"));
    }

    #[test]
    fn resource_names_follow_the_session_id() {
        assert_eq!(container_name("abc"), "sandbox-abc");
        assert_eq!(home_volume_name("abc"), "sandbox-home-abc");
        assert_eq!(gateway_container_name("abc"), "sandbox-gw-abc");
    }

    #[test]
    fn gateway_run_argv_keeps_the_hardening_contract() {
        let argv = gateway_container_run_argv(
            "abc",
            "sandbox-gateway:test",
            "sandboxd-egress",
            Some("10.209.128.0/24"),
            Some("8.8.8.8 1.1.1.1"),
        );
        assert!(!argv.iter().any(|a| a == "--privileged"));
        assert!(argv.iter().any(|a| a == "--read-only"));
        assert_eq!(argv.iter().filter(|a| *a == "--cap-add").count(), 1);
        assert!(
            argv.windows(2)
                .any(|w| w[0] == "--cap-add" && w[1] == "NET_ADMIN")
        );
        assert!(
            !argv.iter().any(|a| a == "-v" || a == "--volume"),
            "a host bind-mount would silently mount nothing inside the VM: {argv:?}"
        );
        assert!(
            !argv.iter().any(|a| a.contains("docker.sock")),
            "the gateway container must never be handed a docker socket: {argv:?}"
        );
        assert_eq!(
            argv.last().map(String::as_str),
            Some("sandbox-gateway:test")
        );
    }

    #[test]
    fn gateway_run_argv_omits_the_upstream_env_when_none_is_requested() {
        let argv = gateway_container_run_argv(
            "abc",
            "sandbox-gateway:test",
            "sandboxd-egress",
            None,
            None,
        );
        assert!(
            !argv
                .iter()
                .any(|a| a.starts_with("SANDBOX_COREDNS_UPSTREAM="))
        );
        assert!(!argv.iter().any(|a| a.starts_with("sandboxd.owner=")));
    }

    #[test]
    fn cpus_render_with_one_decimal() {
        assert_eq!(format_cpus(2.0), "2.0");
        assert_eq!(format_cpus(0.5), "0.5");
    }

    // -- Policy-plane exec shapes -------------------------------------------

    #[test]
    fn reading_a_gateway_file_is_a_plain_cat_of_a_constant_path() {
        let argv = container_exec_argv(
            "sandbox-gw-abc",
            &ContainerCommand::ReadGatewayFile {
                file: crate::gateway::GatewayFile::EnvoyBootstrap,
            },
        );
        assert_eq!(
            argv,
            vec![
                "exec",
                "sandbox-gw-abc",
                "cat",
                "/etc/envoy/envoy-bootstrap.yaml"
            ]
        );
        assert!(!argv.iter().any(|a| a == "sh"));
    }

    #[test]
    fn listing_a_table_names_the_inet_family() {
        let argv = container_exec_argv(
            "sandbox-gw-abc",
            &ContainerCommand::ListNftTable {
                table: crate::gateway::NftTable::SandboxPolicy,
            },
        );
        assert_eq!(
            argv,
            vec![
                "exec",
                "sandbox-gw-abc",
                "nft",
                "list",
                "table",
                "inet",
                "sandbox_policy"
            ]
        );
    }

    /// The stats URL must survive as one argv element. Split across two, the
    /// `&` would reach the container as a separate word and the probe would
    /// read a different (or no) counter.
    #[test]
    fn every_envoy_stat_probe_passes_its_url_as_one_element() {
        for stat in crate::gateway::EnvoyStat::ALL {
            let argv = container_exec_argv(
                "sandbox-gw-abc",
                &ContainerCommand::EnvoyStat { stat: *stat },
            );
            assert_eq!(argv.len(), 5, "{argv:?}");
            assert_eq!(&argv[..4], &["exec", "sandbox-gw-abc", "curl", "-sf"]);
            assert_eq!(argv[4], stat.url());
        }
    }

    /// `-i` is the difference between writing the artifact and truncating
    /// the file to empty, so it is pinned separately from the command body.
    #[test]
    fn the_stdin_fed_exec_keeps_its_interactive_flag() {
        let argv = container_exec_stdin_argv(
            "sandbox-gw-abc",
            crate::gateway::StdinCommand::ApplyNftRuleset,
        );
        assert_eq!(argv, vec!["exec", "-i", "sandbox-gw-abc", "nft", "-f", "-"]);
    }

    #[test]
    fn the_stdin_fed_exec_carries_the_write_body_last() {
        let command = crate::gateway::StdinCommand::WriteGatewayFile {
            file: crate::gateway::GatewayFile::EnvoyListener,
            delivery: crate::gateway::FileDelivery::AtomicRename,
        };
        let argv = container_exec_stdin_argv("sandbox-gw-abc", command);
        assert_eq!(&argv[..5], &["exec", "-i", "sandbox-gw-abc", "sh", "-c"]);
        assert_eq!(
            argv[5],
            crate::gateway::write_script(
                crate::gateway::GatewayFile::EnvoyListener,
                crate::gateway::FileDelivery::AtomicRename,
            )
        );
        assert_eq!(argv.len(), 6);
    }
}
