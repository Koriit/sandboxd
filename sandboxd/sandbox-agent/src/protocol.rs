// NON-FEATURES — DO NOT ADD without revisiting the trust model.
//
// * No argv pass-through to limactl. Every flag the agent passes to limactl
//   is hardcoded inside this crate per operation variant; the daemon contributes
//   only the typed field values, never a raw argv vector or shell string.
//
// * No shell. The agent never invokes a shell and never constructs a command
//   line from caller-supplied strings.
//
// * No `~` or env-var expansion of caller-supplied values.
//
// * No path outside the agent's own LIMA_HOME. Every path in every op variant
//   is validated as absolute with no `..` components and confined to the
//   agent's own per-operator LIMA_HOME subtree before the agent acts on it.
//
// * No operation not in this enum. The enum is closed — a future operation
//   requires a new reviewed variant. Unrecognised JSON is deserialized as an
//   error and the request is rejected.
//
// * No acting on a uid other than the agent's own. The agent reads its uid
//   from `getuid()` and rejects any request whose `op_uid` does not match.
//
// * No agent-constructed networking. The daemon renders the complete lima.yaml
//   and passes it as the Create payload; the agent validates its shape and
//   writes it verbatim. It never assembles networking configuration from typed
//   fields.
//
// * No cross-session safety decision rests on agent-reported state. The daemon
//   uses the agent's op results (exit codes, marker content) for its own
//   session bookkeeping, but cross-session isolation rests on per-uid LIMA_HOME
//   and the socket_vmnet slot/segment topology — never on a claim the agent
//   makes about what it did.

//! Broker wire protocol — the typed message set that crosses the broker
//! channel between the daemon and each per-operator agent.
//!
//! # Framing model
//!
//! The protocol distinguishes two framing modes over the same underlying Unix
//! stream:
//!
//! ## One-shot (all ops except `GuestSocat`)
//!
//! ```text
//! daemon → agent: JSON(BrokerRequest)\n
//! agent → daemon: JSON(BrokerResponse)\n
//! ```
//!
//! Each side writes a single newline-terminated JSON object per message.
//!
//! The channel is **pipelined**: the daemon may have several requests
//! outstanding at once and does not wait for one response before sending the
//! next request. `request_id` is what correlates them, and responses may come
//! back in any order — the agent answers each op when that op finishes, which
//! for a mix of fast and slow ops is not the order they arrived in. Neither
//! side may infer anything from response order.
//!
//! Ordering where it is needed comes from the caller: a dependent sequence
//! such as create-then-start is sequential because the caller awaits each
//! response before issuing the next request.
//!
//! ## Streaming (the stream-class ops)
//!
//! Two op variants are stream-class rather than request/response:
//! [`BrokerOp::GuestSocat`], which reaches the guest agent inside a Lima VM,
//! and [`BrokerOp::DockerStream`], which reaches an endpoint inside one of the
//! operator's containers. Both open a long-lived bidirectional byte pump, and
//! both carry a `stream_token`; [`BrokerOp::stream_token_slot`] is the single
//! place that says which variants those are.
//!
//! The multiplexed framing, which is the one the daemon uses:
//!
//! ```text
//! daemon → agent (control): JSON(BrokerRequest { op: <stream op with token> })\n
//! agent  → daemon (control): JSON(BrokerResponse::StreamReady { token })\n
//! agent  → daemon (NEW connection): STREAM_CONNECT:<token>\n
//! [bidirectional raw byte stream on that connection until either side closes]
//! ```
//!
//! The control connection is never consumed and is not blocked for the
//! duration: the stream open is one op like any other and resolves when its
//! `StreamReady` arrives.
//!
//! The legacy single-connection framing survives for `GuestSocat` only, and
//! only for agents predating the multiplexed protocol:
//!
//! ```text
//! daemon → agent: JSON(BrokerRequest { op: GuestSocat { vm } })\n
//! agent → daemon: JSON(BrokerResponse::StreamOpen)\n
//! [bidirectional raw byte stream until either side closes]
//! ```
//!
//! After `StreamOpen` the connection carries raw bytes — the agent splices its
//! stdin/stdout to `limactl shell <vm> -- socat - TCP:127.0.0.1:5123` and
//! copies between the broker connection and the socat process until either end
//! closes. There is no further framing; the agent and daemon each close their
//! half of the stream to signal EOF to the other. Any further `BrokerResponse`
//! JSON after `StreamOpen` would be a protocol error.
//!
//! # Relationship to `LimaOp<'a>` in `sandbox-core`
//!
//! `sandbox-core::lima::LimaOp<'a>` is the in-process, borrowed representation
//! of a Lima operation — its fields borrow from the call-site's owned data and
//! are not serde-serializable. `BrokerOp` here is the owned, serde-serializable
//! counterpart that crosses the wire.
//!
//! The two types are structurally isomorphic for the shared op variants.
//! `BrokerOp` additionally carries `RestrictOnVerify` (a post-boot verification
//! op that has no `LimaOp` equivalent — it reads the wrapper marker / queries
//! QMP) and `GuestSocat` as a named variant (in `LimaOp` this is handled via
//! a separate `guest_socat` async method, not a `run` variant).
//!
//! The daemon maps `LimaOp<'a>` → `BrokerOp` for serialization; the agent
//! deserializes `BrokerOp` and re-validates every field independently before
//! constructing the hardcoded `limactl` argv. The daemon maps `BrokerOp` ←
//! the typed executor-seam call; neither mapping is via raw string construction.

use serde::{Deserialize, Serialize};

/// A single request from the daemon to the agent.
///
/// Serialized as `{"request_id": <u64>, "op": <BrokerOp>}\n` (newline-delimited JSON).
/// The `request_id` is an opaque monotonic counter chosen by the daemon. The
/// agent must echo it in the matching `BrokerResponse`: it is the only thing
/// that correlates a response to its request, and the channel carries
/// concurrent ops. A response whose id the daemon is not waiting for is
/// discarded.
#[derive(Debug, Serialize, Deserialize)]
pub struct BrokerRequest {
    /// Monotonic request identifier, echoed in the response.
    pub request_id: u64,
    /// The typed operation to perform.
    pub op: BrokerOp,
}

/// A response from the agent to the daemon.
///
/// Serialized as `{"request_id": <u64>, "result": <BrokerResult>}\n`.
#[derive(Debug, Serialize, Deserialize)]
pub struct BrokerResponse {
    /// Echo of the matching `BrokerRequest::request_id`.
    pub request_id: u64,
    /// The operation result.
    pub result: BrokerResult,
}

/// The outcome of a one-shot brokered operation.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum BrokerResult {
    /// Operation succeeded. `stdout` and `stderr` carry the raw captured output
    /// from the limactl child (UTF-8 lossy; may be empty).
    Ok {
        stdout: String,
        stderr: String,
        exit_code: i32,
    },
    /// The agent rejected the request due to a validation failure. The daemon
    /// must treat this as a hard error and not retry with the same payload.
    /// `reason` is a human-readable description for diagnostics.
    Rejected { reason: String },
    /// `limactl` was invoked but exited with a non-zero status. This is
    /// distinct from `Ok { exit_code != 0 }` only for clarity — both carry
    /// the same fields; the daemon treats non-zero exit codes uniformly.
    Failed {
        stdout: String,
        stderr: String,
        exit_code: i32,
    },
    /// The `GuestSocat` streaming op is open. After this response the stream
    /// carries raw bytes; there are no further framed messages.
    ///
    /// Retained for wire-compatibility with agents that have not yet been
    /// updated to the multiplexed protocol. The daemon no longer sends
    /// `GuestSocat` on the control connection; updated agents respond with
    /// [`StreamReady`] instead and open a separate stream connection.
    StreamOpen,
    /// Multiplexed GuestSocat: the agent has acknowledged the op and will open
    /// a separate stream connection carrying `STREAM_CONNECT:<token>\n`.
    ///
    /// The `token` is the correlation token the daemon embedded in the
    /// `GuestSocat` request (see [`BrokerOp::GuestSocat::stream_token`]).
    /// The agent echoes it back so the daemon can match the incoming stream
    /// connection to this pending op. The control connection is not consumed.
    StreamReady { token: String },
    /// The `RestrictOnVerify` check passed — `restrict=on` is confirmed on the
    /// management netdev for the named VM.
    RestrictConfirmed { vm: String, netdev_token: String },
    /// The `RestrictOnVerify` check failed — the wrapper marker is absent or
    /// does not contain `restrict=on`, or QMP verification failed.
    /// The daemon must tear the VM down and fail the session.
    RestrictNotConfirmed { vm: String, reason: String },
}

/// The closed set of operations the agent may perform.
///
/// Each variant carries typed, named fields — no raw argv, no shell strings.
/// The agent constructs the `limactl` command line from these fields with
/// hardcoded flags; it never passes caller-supplied strings directly to a shell
/// or to `exec` as part of an argv that was not fully composed by the agent.
///
/// Variants marked with `op_uid` carry the daemon-asserted operator uid for
/// belt-and-suspenders cross-checking (the agent independently verifies this
/// matches its own `getuid()` — see `validation::validate_op_uid`).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "subcommand", rename_all = "snake_case")]
pub enum BrokerOp {
    /// Create a new Lima VM instance from a daemon-rendered `lima.yaml`.
    ///
    /// The agent validates the YAML's shape (vmType must be "qemu"; when
    /// `is_hardened_session` is true, a single socket_vmnet NIC entry is also
    /// required; no extra NICs; qemu-wrapper path absolute and no `..`) and
    /// writes it verbatim to `{lima_home}/{vm}/lima.yaml` before running
    /// `limactl create`.
    ///
    /// After `limactl create` succeeds, the agent writes the owner marker to
    /// `{lima_home}/{vm}/sandboxd-owner`.
    Create {
        op_uid: u32,
        vm: String,
        /// The complete rendered `lima.yaml` content. The agent validates shape
        /// and writes it verbatim; it does not assemble or modify the content.
        lima_yaml: String,
        /// Pool CIDR written to `{lima_home}/{vm}/sandboxd-owner` after create.
        owner: String,
        /// Absolute path to the sandboxd-shipped qemu-wrapper. The agent asserts
        /// the wrapper is present and executable before running `limactl create`.
        qemu_wrapper: String,
        /// True when creating a real session VM (socket_vmnet NIC required).
        /// False for the base-image build VM, which uses Lima's slirp NIC only
        /// and therefore has no `networks:` key in its lima.yaml.
        is_hardened_session: bool,
    },
    /// Create this operator's own gateway Lima VM from a daemon-rendered
    /// `lima.yaml`.
    ///
    /// # Why this is a separate variant rather than a flag on `Create`
    ///
    /// A gateway VM and a session VM are held to *different* NIC-shape rules:
    /// a session VM must have exactly one socket_vmnet NIC (one L2 segment,
    /// one gateway, no second path off the box), while a gateway VM legitimately
    /// carries one NIC per pool slot. Something has to say which rule applies,
    /// and that selector is the whole security question — pick it wrong and a
    /// session VM is permitted the multi-NIC shape that routes around egress
    /// policy.
    ///
    /// So the selector is **which variant the daemon invoked**, and nothing
    /// else. It is not a `bool`, not a class string, and — importantly — not
    /// derived from the VM's name: the name is a daemon-supplied wire field and
    /// the daemon is an untrusted requester here (see `validation`'s module
    /// doc). Deriving the class from a name would move the daemon's control
    /// from one field to another rather than remove it. Deriving it from the
    /// variant reuses the property the whole op set already rests on: the enum
    /// is closed, so the reachable classes are exactly the ones someone
    /// reviewed.
    ///
    /// # No `vm` field
    ///
    /// There is deliberately no VM-name field on the wire. The agent derives
    /// the instance name from its own `getuid()` — same reasoning as
    /// `handler::own_gateway_vm`: an instance name is what `limactl` acts on,
    /// and a daemon that names the instance can point a reviewed operation at
    /// an arbitrary one. With no field there is nothing to get wrong.
    ///
    /// Consequently there is also no `owner` field (the gateway is daemon-owned
    /// infrastructure and gets no per-operator owner marker — this matches what
    /// the existing daemon-uid direct path does today) and no `qemu_wrapper`
    /// field (the gateway VM deliberately runs without the `restrict=on`
    /// wrapper on its management NIC; `Create`'s wrapper field is already
    /// empty on this path).
    CreateGateway {
        op_uid: u32,
        /// The complete rendered `lima.yaml` content. The agent validates it
        /// against the *gateway-class* shape rule and writes it verbatim; it
        /// does not assemble or modify the content.
        lima_yaml: String,
    },
    /// Start (boot) an existing Lima VM instance.
    Start {
        op_uid: u32,
        vm: String,
        /// Absolute path to the sandboxd-shipped qemu-wrapper. The agent asserts
        /// the wrapper is present and executable before invoking limactl.
        qemu_wrapper: String,
        /// Whether the VM is a hardened session ("1") or a base-image build ("0").
        hardened: bool,
        memory_mb: u32,
        cpus: u32,
        start_timeout_s: u32,
        /// Optional bridge NIC: (bridge_name, vm_mac). Both fields must be
        /// supplied together or both must be absent.
        bridge: Option<BridgePair>,
        /// When true, the qemu-wrapper allows unrestricted slirp during
        /// provisioning. Only valid together with `bridge`.
        unrestricted_slirp_for_provisioning: bool,
    },
    /// Stop a running Lima VM instance.
    Stop {
        op_uid: u32,
        vm: String,
        force: bool,
    },
    /// Delete a Lima VM instance (always `--force`).
    Delete { op_uid: u32, vm: String },
    /// Clone a Lima VM instance from a base image.
    Clone {
        op_uid: u32,
        base: String,
        vm: String,
        cpus: u32,
        memory_gib: u32,
        disk_gb: u32,
        owner: String,
    },
    /// List all Lima instances as JSON (`limactl list --json`).
    ListJson { op_uid: u32 },
    /// Install the sandbox-guest binary and systemd unit into a running VM.
    InstallGuestAgent { op_uid: u32, vm: String },
    /// Read the operator's Lima SSH private key from `{lima_home}/_config/user`.
    ReadUserKey { op_uid: u32 },
    /// Run rsync to push a host workspace into the VM (or container).
    RunRsync {
        op_uid: u32,
        /// "lima" or "container" — selects the rsync remote-shell transport.
        backend: String,
        session_name: String,
        host_path: String,
        guest_path: String,
        no_gitignore: bool,
    },
    /// Read `{lima_home}/{vm}/sandboxd-owner` and return its contents.
    ReadOwnerMarker { op_uid: u32, vm: String },
    /// Open a long-lived bidirectional stream to the in-VM guest agent.
    ///
    /// Multiplexed protocol (updated agents):
    ///   daemon → agent (control connection): `GuestSocat { ..., stream_token: Some("hex…") }`
    ///   agent → daemon (control connection): `StreamReady { token: "hex…" }`
    ///   agent → daemon (NEW connection):     `STREAM_CONNECT:<token>\n`, then raw byte-pump
    ///
    /// The control connection is never consumed. Each GuestSocat op gets its own
    /// dedicated stream connection. The `stream_token` is a cryptographically
    /// random single-use correlation handle; the daemon matches the incoming
    /// stream connection to the pending op by token, then verifies the stream
    /// connection's peer-cred independently (peer-cred + group + uid — full auth
    /// chain, not pre-authorized by the control connection).
    ///
    /// Legacy fallback (agents that have not yet been updated):
    ///   When `stream_token` is `None` the agent responds with `StreamOpen` and
    ///   the original single-connection byte-pump runs on the control connection.
    ///   The daemon detects this and falls back to the old handoff path.
    GuestSocat {
        op_uid: u32,
        vm: String,
        /// Correlation token for the multiplexed stream connection. `None` in
        /// requests sent to legacy agents (pre-multiplexing protocol).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        stream_token: Option<String>,
    },
    /// Post-boot `restrict=on` verification.
    ///
    /// The agent reads the qemu-wrapper marker file at
    /// `{lima_home}/{vm}/sandboxd-restrict-marker` — written by the wrapper
    /// after it successfully injected `restrict=on` into the management netdev
    /// — and confirms the marker contains `restrict=on`. If the marker is absent
    /// or does not contain `restrict=on`, the agent responds with
    /// `BrokerResult::RestrictNotConfirmed`.
    ///
    /// This op rides the broker channel because the QEMU process and its
    /// associated files are operator-owned and unreadable by the `_sandboxd`
    /// daemon; the daemon cannot perform this check directly.
    ///
    /// Same own-uid + VM-name re-validation as every other op.
    RestrictOnVerify { op_uid: u32, vm: String },
    /// Open a long-lived byte stream to an endpoint inside one of the
    /// containers on the agent's own Docker daemon.
    ///
    /// Same multiplexed shape as [`BrokerOp::GuestSocat`] — the daemon embeds
    /// a `stream_token`, the agent answers `StreamReady` on the control
    /// connection and opens a separate connection for the bytes. What differs
    /// is the transport underneath: `docker exec … socat` against the agent's
    /// own VM rather than `limactl shell`.
    ///
    /// **The daemon does not name the endpoint or the Docker daemon.**
    /// [`DockerStreamOp`] is a closed enum of three destinations, each of
    /// which renders its `socat` address from constants in
    /// `sandbox-docker-argv`; the socket is the agent's own, derived from its
    /// own LIMA_HOME. A stream is a raw byte pipe into a container, so a
    /// caller-chosen address would be the whole of what these ops can do.
    DockerStream {
        op_uid: u32,
        stream: DockerStreamOp,
        /// Correlation token for the multiplexed stream connection. Always
        /// `Some` in production: unlike `GuestSocat` this op has no
        /// single-connection legacy form, so an agent that receives it
        /// without a token rejects it rather than falling back.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        stream_token: Option<String>,
    },
    /// Run one typed `docker` operation against the Docker daemon inside the
    /// agent's own VM.
    ///
    /// The op set is grouped behind one variant rather than flattened into
    /// this enum so that a reviewer asking "what can the daemon make my
    /// Docker do?" reads exactly one enum, [`DockerOp`], rather than
    /// picking twenty variants out of a list that also contains VM
    /// lifecycle. The compile-time exhaustiveness that matters is preserved
    /// one level down: the agent's docker dispatch matches [`DockerOp`]
    /// exhaustively, so an unhandled variant does not build.
    ///
    /// **The daemon does not name the target daemon.** No socket path
    /// crosses the wire on this op; the agent addresses its own VM's
    /// forwarded socket, derived from its own LIMA_HOME. That is what keeps
    /// `-H unix://<own socket>` the sole target authority and keeps every
    /// path in this op set inside the agent's own subtree.
    Docker { op_uid: u32, op: DockerOp },
    /// Run one typed operation **inside** the agent's own gateway VM, through
    /// `limactl shell` or `limactl copy`.
    ///
    /// Grouped behind one variant for the same reason [`BrokerOp::Docker`] is:
    /// a reviewer asking "what can the daemon make happen inside my VM?" reads
    /// one enum, [`InVmOp`], rather than picking twelve variants out of a list
    /// that also contains VM lifecycle.
    ///
    /// **The daemon does not name the VM.** No instance name crosses the wire
    /// on this op; the agent addresses its own gateway instance, derived from
    /// its own uid — the same discipline that keeps `-H unix://<own socket>`
    /// the sole target authority on the Docker ops. It matters more here, not
    /// less: a `limactl shell` runs as the VM's login user, which has
    /// passwordless `sudo`, so a caller-chosen instance would be a root shell
    /// in a VM of the caller's choosing.
    InVm { op_uid: u32, op: InVmOp },
}

// ---------------------------------------------------------------------------
// Docker stream set
// ---------------------------------------------------------------------------

/// The closed set of long-lived byte streams the daemon may open into one of
/// the operator's containers.
///
/// Read this enum as the answer to "what can the daemon make my Docker pipe
/// bytes to?". Each variant names a destination whose address is a constant
/// in `sandbox-docker-argv`; the only value that varies is which container.
/// There is deliberately no variant carrying a port, a socket path or a
/// `socat` address — a stream *is* a raw byte pipe, so a caller-chosen
/// destination would make this op set unbounded no matter how many variants
/// it had.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "stream_op", rename_all = "snake_case")]
pub enum DockerStreamOp {
    /// The in-session `sandbox-guest` agent. Carries sandboxd's structured
    /// guest protocol; the daemon opens one per guest request.
    GuestAgent { container: String },
    /// The in-session `sshd`, for the proxy WebSocket. Held open for a whole
    /// SSH session — hours, under a remote-development client.
    Sshd { container: String },
    /// The gateway container's DNS-policy gate socket. One per DNS query,
    /// on the egress-allow decision path.
    DnsGate { container: String },
}

impl DockerStreamOp {
    /// The container this stream enters.
    pub fn container(&self) -> &str {
        match self {
            DockerStreamOp::GuestAgent { container }
            | DockerStreamOp::Sshd { container }
            | DockerStreamOp::DnsGate { container } => container,
        }
    }

    /// The in-container endpoint this stream reaches.
    pub fn target(&self) -> sandbox_docker_argv::stream::StreamTarget {
        use sandbox_docker_argv::stream::StreamTarget;
        match self {
            DockerStreamOp::GuestAgent { .. } => StreamTarget::GuestAgent,
            DockerStreamOp::Sshd { .. } => StreamTarget::Sshd,
            DockerStreamOp::DnsGate { .. } => StreamTarget::DnsGate,
        }
    }
}

// ---------------------------------------------------------------------------
// Docker op set
// ---------------------------------------------------------------------------

/// The closed set of `docker` operations the daemon may request.
///
/// Read this enum as the answer to "what is the daemon allowed to do to the
/// operator's Docker?". Every variant names an operation and carries only
/// the values that vary. There is deliberately no variant carrying an argv,
/// a shell string, a Go template or a filesystem path to read — each of
/// those would be a pass-through in disguise, and one of them makes the
/// agent's validation decorative.
///
/// The counterpart on the daemon side is `sandbox_core::docker::DockerOp`;
/// both render their command line through the shared `sandbox-docker-argv`
/// crate, so the two sides cannot disagree about what an op means.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "docker_op", rename_all = "snake_case")]
pub enum DockerOp {
    /// `docker create` a session container from its typed specification.
    ContainerCreate { spec: ContainerCreateSpec },
    /// `docker start <name>`.
    ContainerStart { name: String },
    /// `docker stop` with an explicit grace period.
    ContainerStop {
        name: String,
        grace_secs: u32,
        /// `--time` when true, `-t` when false. Two spellings are in
        /// production use and both are pinned by tests.
        long_flag: bool,
    },
    /// `docker restart <name>`.
    ContainerRestart { name: String },
    /// `docker rm [-f|--force] <name>`.
    ContainerRemove { name: String, force: RemoveForce },
    /// `docker inspect` one enumerated field of a container's state.
    ContainerInspect {
        name: String,
        format: InspectFormat,
        flag: InspectFlag,
    },
    /// `docker ps -a` filtered by name prefix and optional owner pool.
    ContainerList {
        name_prefix: String,
        owner_pool: Option<String>,
    },
    /// `docker exec` one of the enumerated commands inside a container.
    ContainerExec {
        name: String,
        command: ContainerCommand,
    },
    /// `docker exec -i` one of the enumerated stdin-fed commands inside a
    /// container, with `body` on its standard input.
    ///
    /// This is the shape the egress-plane artifacts arrive in: an nftables
    /// ruleset, an Envoy bootstrap or listener, a CoreDNS policy. They are
    /// multi-KB and contain newlines, so they travel as a JSON string field
    /// rather than in an argv.
    ///
    /// **Framing.** The channel is newline-delimited JSON and this field is
    /// the largest thing that crosses it. It is safe because JSON string
    /// encoding is what escapes the delimiter: `serde_json` emits `\n` for a
    /// newline, `\"` for a quote, `\uXXXX` for the other control characters,
    /// and multi-byte UTF-8 for the rest — none of which is a literal
    /// `0x0A`. A frame therefore contains exactly one newline, the one the
    /// writer appends. `body_is_escaped_by_the_json_encoding` pins that with
    /// a body built to break it.
    ///
    /// **The body is data, not a command.** `command` decides what reads it,
    /// and every variant reads it as content: `nft -f -` parses a ruleset,
    /// `cat` writes bytes to a file. Nothing interprets it as a command line.
    ContainerExecStdin {
        name: String,
        command: StdinCommand,
        body: String,
    },
    /// Run the one-shot init container that chowns a session's home volume.
    HomeVolumeChown {
        session_id: String,
        image_tag: String,
        operator_uid: u32,
        operator_gid: u32,
    },
    /// `docker run` a session's gateway container.
    GatewayContainerRun {
        session_id: String,
        image_tag: String,
        network: String,
        owner_pool: Option<String>,
        coredns_upstream: Option<String>,
    },
    /// `docker network create` from a typed specification.
    NetworkCreate { spec: NetworkCreateSpec },
    /// `docker network rm <name>`.
    NetworkRemove { name: String },
    /// `docker network inspect <name>`.
    NetworkInspect { name: String },
    /// `docker network connect [--ip <addr>] <network> <container>`.
    NetworkConnect {
        network: String,
        container: String,
        ip: Option<String>,
        #[serde(default)]
        gateway_priority: EndpointGatewayPriority,
    },
    /// `docker network ls` filtered by name prefix and optional owner pool.
    NetworkList {
        name_prefix: String,
        owner_pool: Option<String>,
    },
    /// `docker volume create` with the session and owner labels.
    VolumeCreate {
        name: String,
        session_id: Option<String>,
        owner_pool: Option<String>,
    },
    /// `docker volume rm <name>`.
    VolumeRemove { name: String },
    /// `docker volume ls` filtered by name prefix and optional owner pool.
    VolumeList {
        name_prefix: String,
        owner_pool: Option<String>,
    },
    /// `docker image inspect <tag>`.
    ImageInspect { tag: String },
    /// `docker load` one of the staged image tarballs.
    ///
    /// The tarball is named by the enum, not by a path: the agent resolves
    /// the variant to a filename inside its own staging directory and
    /// streams it. A path field here would be arbitrary read access granted
    /// to whatever is on the other end of the socket.
    ImageLoad { image: StagedImage },
    /// `docker info` — does the target daemon answer?
    DaemonInfo,
}

/// How `docker rm` spells its force flag.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RemoveForce {
    No,
    Short,
    Long,
}

/// The enumerated `docker inspect --format` templates.
///
/// Adding a variant here widens what a compromised daemon can read out of
/// the operator's VM — see the warning on
/// `sandbox_docker_argv::container::InspectFormat`, which this mirrors.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InspectFormat {
    StateStatus,
    StateRunning,
    StateHealthStatus,
    StatePid,
    NetworkIpAddress,
    /// The container's address on the shared egress bridge specifically.
    EgressNetworkIpAddress,
}

/// How `docker inspect` spells its format flag.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InspectFlag {
    Short,
    Long,
}

/// The enumerated commands the daemon may run inside a container.
///
/// Adding a variant here widens what a compromised daemon can execute
/// inside the operator's container, and needs the matching validation arm
/// in the same change — see the warning on
/// `sandbox_docker_argv::container::ContainerCommand`, which this mirrors.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "command", rename_all = "snake_case")]
pub enum ContainerCommand {
    /// Is sshd listening on port 22 yet?
    SshdListening,
    /// Pre-create an rsync destination directory.
    MakeDirectory { path: String },
    /// The gateway image's aggregate health script.
    GatewayHealthcheck,
    /// One named gateway component's readiness probe.
    ComponentProbe { component: GatewayComponent },
    /// Read one of the enumerated gateway policy files back out.
    ReadGatewayFile { file: GatewayFile },
    /// List one of the two sandbox nftables tables.
    ListNftTable { table: NftTable },
    /// Read one of the enumerated Envoy admin statistics.
    EnvoyStat { stat: EnvoyStat },
}

/// The Envoy admin `/stats` queries the daemon may run.
///
/// Envoy's `filter` parameter is a regex, so a free-form filter would read
/// whatever it liked out of the admin surface — see the warning on
/// `sandbox_docker_argv::gateway::EnvoyStat`, which this mirrors.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EnvoyStat {
    ActiveListeners,
    LdsCounters,
}

/// The closed set of commands the daemon may feed a body to on stdin.
///
/// Adding a variant widens what a compromised daemon can write inside the
/// operator's gateway container — see the warning on
/// `sandbox_docker_argv::gateway::StdinCommand`, which this mirrors.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(tag = "stdin_command", rename_all = "snake_case")]
pub enum StdinCommand {
    /// `nft -f -` — apply an nftables ruleset read from stdin.
    ApplyNftRuleset,
    /// Deliver one gateway file, its content read from stdin.
    WriteGatewayFile {
        file: GatewayFile,
        delivery: FileDelivery,
    },
}

/// The gateway-container artifacts the daemon may name.
///
/// Each variant maps to a `&'static str` path in the argv crate; no path
/// crosses the wire. Adding a variant is a security change — see the
/// warning on `sandbox_docker_argv::gateway::GatewayFile`.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GatewayFile {
    CorednsPolicy,
    CorednsResolved,
    MitmproxyPolicy,
    MitmproxyCaKey,
    MitmproxyCaCert,
    EnvoyBootstrap,
    EnvoyListener,
}

/// How a gateway file is put in place.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FileDelivery {
    Replace,
    AtomicRename,
}

/// The two `inet` nftables tables the gateway's policy plane manages.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NftTable {
    SandboxDnat,
    SandboxPolicy,
}

/// The gateway container's five long-running components.
///
/// A new component means a new probe body running inside the operator's
/// container — see the warning on
/// `sandbox_docker_argv::container::GatewayComponent`.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GatewayComponent {
    Envoy,
    Coredns,
    Mitmproxy,
    DenyLogger,
    AllowLogger,
}

/// The image tarballs the daemon stages for loading into a VM.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StagedImage {
    Gateway,
    Lite,
}

/// Docker network drivers the daemon creates networks with.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkDriver {
    Bridge,
    Macvlan,
}

/// Whether an endpoint being attached may become the container's default
/// route.
///
/// Nullary, like [`NetworkOption::MacvlanModePrivate`]: the daemon says
/// which of the two intents it has, and the number Docker is given is the
/// agent's to choose. Older daemons do not send the field at all, which
/// deserializes as [`EndpointGatewayPriority::Default`] — Docker's own
/// behaviour, and what those daemons already relied on.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EndpointGatewayPriority {
    #[default]
    Default,
    NeverDefaultGateway,
}

/// The enumerated `--opt key=value` pairs a network may carry.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "option", rename_all = "snake_case")]
pub enum NetworkOption {
    BridgeName { interface: String },
    BridgeMasquerade { enabled: bool },
    MacvlanParent { parent: String },
    MacvlanModePrivate,
}

/// The operator-supplied workspace bind pair.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkspaceBindSpec {
    pub host_path: String,
    pub guest_path: String,
}

/// Every typed value `docker create` needs for a session container.
///
/// Each field is re-validated by the agent before any argv is built; none
/// of them is passed through to a shell.
#[derive(Debug, Clone, Serialize, Deserialize)]
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
    #[serde(default)]
    pub owner_pool: Option<String>,
    #[serde(default)]
    pub workspace_bind: Option<WorkspaceBindSpec>,
    #[serde(default)]
    pub ca_host_path: Option<String>,
    #[serde(default)]
    pub ssh_host_dir: Option<String>,
    #[serde(default)]
    pub guest_bind_source: Option<String>,
}

/// Every typed value `docker network create` needs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkCreateSpec {
    pub name: String,
    pub driver: NetworkDriver,
    #[serde(default)]
    pub subnet: Option<String>,
    #[serde(default)]
    pub gateway: Option<String>,
    #[serde(default)]
    pub session_id: Option<String>,
    #[serde(default)]
    pub owner_pool: Option<String>,
    #[serde(default)]
    pub options: Vec<NetworkOption>,
}

// ---------------------------------------------------------------------------
// In-VM op set
// ---------------------------------------------------------------------------

/// The closed set of operations the daemon may ask the agent to perform
/// **inside** its own gateway VM.
///
/// Read this enum as the answer to "what is the daemon allowed to do inside my
/// VM?". It is a shorter list than the Docker one and a sharper one: these run
/// as the VM's login user, which has passwordless `sudo`, so there is no
/// variant carrying a command, a shell string, a capability set or a path to
/// write. Where the Docker set had to enumerate formats and templates to stop
/// a read from widening, this set has to enumerate whole operations to stop a
/// write from becoming root.
///
/// # Adding a variant is a security change
///
/// Each variant is one more thing a compromised daemon can run as root inside
/// the VM that terminates the session's TLS and carries its egress policy.
/// Name the operation, never the command — and check whether an existing
/// variant already does it.
///
/// The counterpart on the daemon side is `sandbox_core::in_vm::InVmOp`; both
/// render their command lines through the shared `sandbox-invm-argv` crate, so
/// the two sides cannot disagree about what an op means.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "in_vm_op", rename_all = "snake_case")]
pub enum InVmOp {
    /// Is the VM's own Docker daemon answering?
    DockerReady,
    /// The guest's own view of its NICs, as JSON.
    LinkShowJson,
    /// Apply the VM's `eth0` default-drop nftables baseline, the ruleset
    /// arriving on `nft`'s standard input.
    ///
    /// **This is the egress-enforcement op in this set.** The body is the
    /// policy: multi-KB, full of newlines, and read as content by a parser
    /// rather than as a command line by anything. It travels as a JSON string
    /// field on the newline-delimited channel for the same reason
    /// [`DockerOp::ContainerExecStdin`]'s does, and is safe for the same
    /// reason — JSON string encoding is what escapes the frame delimiter.
    ApplyNftBaseline { ruleset: String },
    /// Report whether `sandbox-route-helper` is installed in the VM with its
    /// capabilities. Reports; does not decide.
    RouteHelperProbe,
    /// Create the root-owned directory the helper installs into.
    RouteHelperMakeInstallDir,
    /// Copy the pre-staged helper binary into the VM.
    ///
    /// Carries no source path: the binary is named by a constant of the argv
    /// crate and resolved against the **agent's own** LIMA_HOME. A path field
    /// here would be a request to copy an arbitrary file into a VM that is
    /// about to hand it `cap_net_admin`.
    RouteHelperStage,
    /// Move the staged copy into its final root-owned location.
    RouteHelperInstall,
    /// Mark the installed helper executable and apply its capabilities.
    ///
    /// The capability set is a constant of the argv crate, not a field. A
    /// caller-chosen capability set on a root-owned binary is the same
    /// authority as a caller-chosen command.
    RouteHelperSetcap,
    /// Create a session's lite-container staging directory.
    LiteStageCreate { session_id: String },
    /// Put one of four enumerated provisioning files into a session's staging
    /// directory, its content carried in `body`.
    ///
    /// The basename and the mode come from `file`, not from the daemon. The
    /// content has to travel because the daemon writes these files into its
    /// own session directory at mode 0700 — which the agent cannot read at
    /// all once the VM is the operator's.
    LiteStageWrite {
        session_id: String,
        file: LiteStageFile,
        body: String,
    },
    /// Remove a session's staging directory.
    LiteStageRemove { session_id: String },
    /// Run the provisioned `sandbox-route-helper` to install a sandbox
    /// container's default route.
    ///
    /// **This is the other egress-enforcement op in this set.**
    /// [`InVmOp::ApplyNftBaseline`] decides what the gateway drops; this
    /// decides whether the sandbox's packets reach the gateway to be judged at
    /// all. A wrong `gateway_ip` produces a container that routes elsewhere and
    /// reports no error.
    ///
    /// Both fields are typed rather than stringly, and that is the whole of
    /// what this side guarantees about them: a `u32` renders no leading `-` and
    /// so can never be read as a flag by the helper's parser, and an
    /// `Ipv4Addr` rejects at *deserialization* anything that is not an address
    /// — no hostname, no path, no shell metacharacter, no IPv6 literal the
    /// helper would refuse later. The agent's validation adds only the bound
    /// the far end's `i32` parse needs.
    ///
    /// **The agent cannot check that the address is correct, and does not
    /// try.** It is on the caller's side of the boundary: a process inside the
    /// VM can run the installed helper directly, and such a caller never
    /// reaches this enum. The check that survives a direct invocation is in the
    /// helper, after it enters the container's network namespace, against what
    /// the kernel reports there.
    InstallContainerRoute {
        container_pid: u32,
        gateway_ip: std::net::Ipv4Addr,
    },
}

/// The four files a lite session stages into its VM directory.
///
/// Mirrors `sandbox_invm_argv::lite_stage::LiteStageFile` — see the warning
/// there. Adding a variant is a security change: it is one more filename the
/// daemon can write into a directory about to be bound into a container.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LiteStageFile {
    CertPem,
    AuthorizedKeys,
    Passwd,
    Group,
}

// ---------------------------------------------------------------------------
// Wire → argv-crate conversions
// ---------------------------------------------------------------------------
//
// The argv crate is deliberately serde-free (it is the leaf both the daemon
// and the agent depend on, and keeping it dependency-free is the property
// that lets it sit under both). These conversions are the seam: the wire
// types carry serde, the argv types carry the rendering, and the mapping
// between them is total.

impl From<LiteStageFile> for sandbox_invm_argv::lite_stage::LiteStageFile {
    fn from(value: LiteStageFile) -> Self {
        match value {
            LiteStageFile::CertPem => Self::CertPem,
            LiteStageFile::AuthorizedKeys => Self::AuthorizedKeys,
            LiteStageFile::Passwd => Self::Passwd,
            LiteStageFile::Group => Self::Group,
        }
    }
}

impl From<RemoveForce> for sandbox_docker_argv::container::RemoveForce {
    fn from(value: RemoveForce) -> Self {
        match value {
            RemoveForce::No => Self::No,
            RemoveForce::Short => Self::Short,
            RemoveForce::Long => Self::Long,
        }
    }
}

impl From<InspectFormat> for sandbox_docker_argv::container::InspectFormat {
    fn from(value: InspectFormat) -> Self {
        match value {
            InspectFormat::StateStatus => Self::StateStatus,
            InspectFormat::StateRunning => Self::StateRunning,
            InspectFormat::StateHealthStatus => Self::StateHealthStatus,
            InspectFormat::StatePid => Self::StatePid,
            InspectFormat::NetworkIpAddress => Self::NetworkIpAddress,
            InspectFormat::EgressNetworkIpAddress => Self::EgressNetworkIpAddress,
        }
    }
}

impl From<InspectFlag> for sandbox_docker_argv::container::InspectFlag {
    fn from(value: InspectFlag) -> Self {
        match value {
            InspectFlag::Short => Self::Short,
            InspectFlag::Long => Self::Long,
        }
    }
}

impl From<GatewayComponent> for sandbox_docker_argv::container::GatewayComponent {
    fn from(value: GatewayComponent) -> Self {
        match value {
            GatewayComponent::Envoy => Self::Envoy,
            GatewayComponent::Coredns => Self::Coredns,
            GatewayComponent::Mitmproxy => Self::Mitmproxy,
            GatewayComponent::DenyLogger => Self::DenyLogger,
            GatewayComponent::AllowLogger => Self::AllowLogger,
        }
    }
}

impl From<StagedImage> for sandbox_docker_argv::image::StagedImage {
    fn from(value: StagedImage) -> Self {
        match value {
            StagedImage::Gateway => Self::Gateway,
            StagedImage::Lite => Self::Lite,
        }
    }
}

impl From<NetworkDriver> for sandbox_docker_argv::network::NetworkDriver {
    fn from(value: NetworkDriver) -> Self {
        match value {
            NetworkDriver::Bridge => Self::Bridge,
            NetworkDriver::Macvlan => Self::Macvlan,
        }
    }
}

impl From<&NetworkOption> for sandbox_docker_argv::network::NetworkOption {
    fn from(value: &NetworkOption) -> Self {
        match value {
            NetworkOption::BridgeName { interface } => Self::BridgeName(interface.clone()),
            NetworkOption::BridgeMasquerade { enabled } => Self::BridgeMasquerade(*enabled),
            NetworkOption::MacvlanParent { parent } => Self::MacvlanParent(parent.clone()),
            NetworkOption::MacvlanModePrivate => Self::MacvlanModePrivate,
        }
    }
}

impl From<GatewayFile> for sandbox_docker_argv::gateway::GatewayFile {
    fn from(value: GatewayFile) -> Self {
        match value {
            GatewayFile::CorednsPolicy => Self::CorednsPolicy,
            GatewayFile::CorednsResolved => Self::CorednsResolved,
            GatewayFile::MitmproxyPolicy => Self::MitmproxyPolicy,
            GatewayFile::MitmproxyCaKey => Self::MitmproxyCaKey,
            GatewayFile::MitmproxyCaCert => Self::MitmproxyCaCert,
            GatewayFile::EnvoyBootstrap => Self::EnvoyBootstrap,
            GatewayFile::EnvoyListener => Self::EnvoyListener,
        }
    }
}

impl From<FileDelivery> for sandbox_docker_argv::gateway::FileDelivery {
    fn from(value: FileDelivery) -> Self {
        match value {
            FileDelivery::Replace => Self::Replace,
            FileDelivery::AtomicRename => Self::AtomicRename,
        }
    }
}

impl From<EnvoyStat> for sandbox_docker_argv::gateway::EnvoyStat {
    fn from(value: EnvoyStat) -> Self {
        match value {
            EnvoyStat::ActiveListeners => Self::ActiveListeners,
            EnvoyStat::LdsCounters => Self::LdsCounters,
        }
    }
}

impl From<NftTable> for sandbox_docker_argv::gateway::NftTable {
    fn from(value: NftTable) -> Self {
        match value {
            NftTable::SandboxDnat => Self::SandboxDnat,
            NftTable::SandboxPolicy => Self::SandboxPolicy,
        }
    }
}

impl From<StdinCommand> for sandbox_docker_argv::gateway::StdinCommand {
    fn from(value: StdinCommand) -> Self {
        match value {
            StdinCommand::ApplyNftRuleset => Self::ApplyNftRuleset,
            StdinCommand::WriteGatewayFile { file, delivery } => Self::WriteGatewayFile {
                file: file.into(),
                delivery: delivery.into(),
            },
        }
    }
}

impl From<&ContainerCommand> for sandbox_docker_argv::container::ContainerCommand {
    fn from(value: &ContainerCommand) -> Self {
        match value {
            ContainerCommand::SshdListening => Self::SshdListening,
            ContainerCommand::MakeDirectory { path } => Self::MakeDirectory { path: path.clone() },
            ContainerCommand::GatewayHealthcheck => Self::GatewayHealthcheck,
            ContainerCommand::ComponentProbe { component } => Self::ComponentProbe {
                component: (*component).into(),
            },
            ContainerCommand::ReadGatewayFile { file } => Self::ReadGatewayFile {
                file: (*file).into(),
            },
            ContainerCommand::ListNftTable { table } => Self::ListNftTable {
                table: (*table).into(),
            },
            ContainerCommand::EnvoyStat { stat } => Self::EnvoyStat {
                stat: (*stat).into(),
            },
        }
    }
}

impl From<&ContainerCreateSpec> for sandbox_docker_argv::container::ContainerCreateSpec {
    fn from(value: &ContainerCreateSpec) -> Self {
        Self {
            session_id: value.session_id.clone(),
            docker_network: value.docker_network.clone(),
            container_ip: value.container_ip.clone(),
            gateway_ip: value.gateway_ip.clone(),
            image_tag: value.image_tag.clone(),
            user_uid: value.user_uid,
            user_gid: value.user_gid,
            memory_mb: value.memory_mb,
            cpus: value.cpus,
            owner_pool: value.owner_pool.clone(),
            workspace_bind: value.workspace_bind.as_ref().map(|bind| {
                sandbox_docker_argv::container::WorkspaceBindSpec {
                    host_path: bind.host_path.clone(),
                    guest_path: bind.guest_path.clone(),
                }
            }),
            ca_host_path: value.ca_host_path.clone(),
            ssh_host_dir: value.ssh_host_dir.clone(),
            guest_bind_source: value.guest_bind_source.clone(),
        }
    }
}

impl From<&NetworkCreateSpec> for sandbox_docker_argv::network::NetworkCreateSpec {
    fn from(value: &NetworkCreateSpec) -> Self {
        Self {
            name: value.name.clone(),
            driver: value.driver.into(),
            subnet: value.subnet.clone(),
            gateway: value.gateway.clone(),
            session_id: value.session_id.clone(),
            owner_pool: value.owner_pool.clone(),
            options: value.options.iter().map(Into::into).collect(),
        }
    }
}

// The daemon builds its ops in the argv crate's vocabulary, so the mapping
// runs the other way too. Both directions live here because the wire types
// are this crate's — an impl on the daemon side would be an orphan.

impl From<sandbox_docker_argv::container::RemoveForce> for RemoveForce {
    fn from(value: sandbox_docker_argv::container::RemoveForce) -> Self {
        use sandbox_docker_argv::container::RemoveForce as Src;
        match value {
            Src::No => Self::No,
            Src::Short => Self::Short,
            Src::Long => Self::Long,
        }
    }
}

impl From<sandbox_docker_argv::container::InspectFormat> for InspectFormat {
    fn from(value: sandbox_docker_argv::container::InspectFormat) -> Self {
        use sandbox_docker_argv::container::InspectFormat as Src;
        match value {
            Src::StateStatus => Self::StateStatus,
            Src::StateRunning => Self::StateRunning,
            Src::StateHealthStatus => Self::StateHealthStatus,
            Src::StatePid => Self::StatePid,
            Src::NetworkIpAddress => Self::NetworkIpAddress,
            Src::EgressNetworkIpAddress => Self::EgressNetworkIpAddress,
        }
    }
}

impl From<sandbox_docker_argv::container::InspectFlag> for InspectFlag {
    fn from(value: sandbox_docker_argv::container::InspectFlag) -> Self {
        use sandbox_docker_argv::container::InspectFlag as Src;
        match value {
            Src::Short => Self::Short,
            Src::Long => Self::Long,
        }
    }
}

impl From<sandbox_docker_argv::container::GatewayComponent> for GatewayComponent {
    fn from(value: sandbox_docker_argv::container::GatewayComponent) -> Self {
        use sandbox_docker_argv::container::GatewayComponent as Src;
        match value {
            Src::Envoy => Self::Envoy,
            Src::Coredns => Self::Coredns,
            Src::Mitmproxy => Self::Mitmproxy,
            Src::DenyLogger => Self::DenyLogger,
            Src::AllowLogger => Self::AllowLogger,
        }
    }
}

impl From<sandbox_docker_argv::image::StagedImage> for StagedImage {
    fn from(value: sandbox_docker_argv::image::StagedImage) -> Self {
        use sandbox_docker_argv::image::StagedImage as Src;
        match value {
            Src::Gateway => Self::Gateway,
            Src::Lite => Self::Lite,
        }
    }
}

impl From<sandbox_docker_argv::network::NetworkDriver> for NetworkDriver {
    fn from(value: sandbox_docker_argv::network::NetworkDriver) -> Self {
        use sandbox_docker_argv::network::NetworkDriver as Src;
        match value {
            Src::Bridge => Self::Bridge,
            Src::Macvlan => Self::Macvlan,
        }
    }
}

impl From<EndpointGatewayPriority> for sandbox_docker_argv::network::EndpointGatewayPriority {
    fn from(value: EndpointGatewayPriority) -> Self {
        match value {
            EndpointGatewayPriority::Default => Self::Default,
            EndpointGatewayPriority::NeverDefaultGateway => Self::NeverDefaultGateway,
        }
    }
}

impl From<sandbox_docker_argv::network::EndpointGatewayPriority> for EndpointGatewayPriority {
    fn from(value: sandbox_docker_argv::network::EndpointGatewayPriority) -> Self {
        use sandbox_docker_argv::network::EndpointGatewayPriority as Src;
        match value {
            Src::Default => Self::Default,
            Src::NeverDefaultGateway => Self::NeverDefaultGateway,
        }
    }
}

impl From<&sandbox_docker_argv::network::NetworkOption> for NetworkOption {
    fn from(value: &sandbox_docker_argv::network::NetworkOption) -> Self {
        use sandbox_docker_argv::network::NetworkOption as Src;
        match value {
            Src::BridgeName(interface) => Self::BridgeName {
                interface: interface.clone(),
            },
            Src::BridgeMasquerade(enabled) => Self::BridgeMasquerade { enabled: *enabled },
            Src::MacvlanParent(parent) => Self::MacvlanParent {
                parent: parent.clone(),
            },
            Src::MacvlanModePrivate => Self::MacvlanModePrivate,
        }
    }
}

impl From<sandbox_docker_argv::gateway::GatewayFile> for GatewayFile {
    fn from(value: sandbox_docker_argv::gateway::GatewayFile) -> Self {
        use sandbox_docker_argv::gateway::GatewayFile as Src;
        match value {
            Src::CorednsPolicy => Self::CorednsPolicy,
            Src::CorednsResolved => Self::CorednsResolved,
            Src::MitmproxyPolicy => Self::MitmproxyPolicy,
            Src::MitmproxyCaKey => Self::MitmproxyCaKey,
            Src::MitmproxyCaCert => Self::MitmproxyCaCert,
            Src::EnvoyBootstrap => Self::EnvoyBootstrap,
            Src::EnvoyListener => Self::EnvoyListener,
        }
    }
}

impl From<sandbox_docker_argv::gateway::FileDelivery> for FileDelivery {
    fn from(value: sandbox_docker_argv::gateway::FileDelivery) -> Self {
        use sandbox_docker_argv::gateway::FileDelivery as Src;
        match value {
            Src::Replace => Self::Replace,
            Src::AtomicRename => Self::AtomicRename,
        }
    }
}

impl From<sandbox_docker_argv::gateway::EnvoyStat> for EnvoyStat {
    fn from(value: sandbox_docker_argv::gateway::EnvoyStat) -> Self {
        use sandbox_docker_argv::gateway::EnvoyStat as Src;
        match value {
            Src::ActiveListeners => Self::ActiveListeners,
            Src::LdsCounters => Self::LdsCounters,
        }
    }
}

impl From<sandbox_docker_argv::gateway::NftTable> for NftTable {
    fn from(value: sandbox_docker_argv::gateway::NftTable) -> Self {
        use sandbox_docker_argv::gateway::NftTable as Src;
        match value {
            Src::SandboxDnat => Self::SandboxDnat,
            Src::SandboxPolicy => Self::SandboxPolicy,
        }
    }
}

impl From<sandbox_docker_argv::gateway::StdinCommand> for StdinCommand {
    fn from(value: sandbox_docker_argv::gateway::StdinCommand) -> Self {
        use sandbox_docker_argv::gateway::StdinCommand as Src;
        match value {
            Src::ApplyNftRuleset => Self::ApplyNftRuleset,
            Src::WriteGatewayFile { file, delivery } => Self::WriteGatewayFile {
                file: file.into(),
                delivery: delivery.into(),
            },
        }
    }
}

impl From<&sandbox_docker_argv::container::ContainerCommand> for ContainerCommand {
    fn from(value: &sandbox_docker_argv::container::ContainerCommand) -> Self {
        use sandbox_docker_argv::container::ContainerCommand as Src;
        match value {
            Src::SshdListening => Self::SshdListening,
            Src::MakeDirectory { path } => Self::MakeDirectory { path: path.clone() },
            Src::GatewayHealthcheck => Self::GatewayHealthcheck,
            Src::ComponentProbe { component } => Self::ComponentProbe {
                component: (*component).into(),
            },
            Src::ReadGatewayFile { file } => Self::ReadGatewayFile {
                file: (*file).into(),
            },
            Src::ListNftTable { table } => Self::ListNftTable {
                table: (*table).into(),
            },
            Src::EnvoyStat { stat } => Self::EnvoyStat {
                stat: (*stat).into(),
            },
        }
    }
}

impl From<&sandbox_docker_argv::container::ContainerCreateSpec> for ContainerCreateSpec {
    fn from(value: &sandbox_docker_argv::container::ContainerCreateSpec) -> Self {
        Self {
            session_id: value.session_id.clone(),
            docker_network: value.docker_network.clone(),
            container_ip: value.container_ip.clone(),
            gateway_ip: value.gateway_ip.clone(),
            image_tag: value.image_tag.clone(),
            user_uid: value.user_uid,
            user_gid: value.user_gid,
            memory_mb: value.memory_mb,
            cpus: value.cpus,
            owner_pool: value.owner_pool.clone(),
            workspace_bind: value.workspace_bind.as_ref().map(|bind| WorkspaceBindSpec {
                host_path: bind.host_path.clone(),
                guest_path: bind.guest_path.clone(),
            }),
            ca_host_path: value.ca_host_path.clone(),
            ssh_host_dir: value.ssh_host_dir.clone(),
            guest_bind_source: value.guest_bind_source.clone(),
        }
    }
}

impl From<&sandbox_docker_argv::network::NetworkCreateSpec> for NetworkCreateSpec {
    fn from(value: &sandbox_docker_argv::network::NetworkCreateSpec) -> Self {
        Self {
            name: value.name.clone(),
            driver: value.driver.into(),
            subnet: value.subnet.clone(),
            gateway: value.gateway.clone(),
            session_id: value.session_id.clone(),
            owner_pool: value.owner_pool.clone(),
            options: value.options.iter().map(Into::into).collect(),
        }
    }
}

/// Bridge NIC pair (bridge_name + vm_mac). Both fields are validated
/// separately by the agent — bridge name regex and MAC unicast-bit check.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BridgePair {
    pub bridge_name: String,
    pub vm_mac: String,
}

impl BrokerOp {
    /// The `op_uid` field common to all variants.
    ///
    /// The agent calls this to extract the daemon-asserted target uid for
    /// comparison against its own `getuid()`.
    pub fn op_uid(&self) -> u32 {
        match self {
            BrokerOp::Create { op_uid, .. }
            | BrokerOp::CreateGateway { op_uid, .. }
            | BrokerOp::Start { op_uid, .. }
            | BrokerOp::Stop { op_uid, .. }
            | BrokerOp::Delete { op_uid, .. }
            | BrokerOp::Clone { op_uid, .. }
            | BrokerOp::ListJson { op_uid }
            | BrokerOp::InstallGuestAgent { op_uid, .. }
            | BrokerOp::ReadUserKey { op_uid }
            | BrokerOp::RunRsync { op_uid, .. }
            | BrokerOp::ReadOwnerMarker { op_uid, .. }
            | BrokerOp::GuestSocat { op_uid, .. }
            | BrokerOp::RestrictOnVerify { op_uid, .. }
            | BrokerOp::DockerStream { op_uid, .. }
            | BrokerOp::Docker { op_uid, .. }
            | BrokerOp::InVm { op_uid, .. } => *op_uid,
        }
    }

    /// The op's `stream_token` field, for the ops that have one.
    ///
    /// This is the single definition of "stream-class op" that both sides of
    /// the channel work from. The daemon uses it to embed a freshly-minted
    /// correlation token before the request goes on the wire, and to refuse a
    /// stream open for an op that has nowhere to put one; the agent uses it
    /// to decide whether a request opens a stream or answers inline.
    ///
    /// The match is exhaustive on purpose. A new op variant does not compile
    /// until someone says which of the two it is, which is the only cheap
    /// moment to notice that a stream op has been added without its token
    /// plumbing — a stream that carries no token cannot be correlated to the
    /// connection the agent opens for it, and would hang instead of failing.
    pub fn stream_token_slot(&mut self) -> Option<&mut Option<String>> {
        match self {
            BrokerOp::GuestSocat { stream_token, .. }
            | BrokerOp::DockerStream { stream_token, .. } => Some(stream_token),
            BrokerOp::Create { .. }
            | BrokerOp::CreateGateway { .. }
            | BrokerOp::Start { .. }
            | BrokerOp::Stop { .. }
            | BrokerOp::Delete { .. }
            | BrokerOp::Clone { .. }
            | BrokerOp::ListJson { .. }
            | BrokerOp::InstallGuestAgent { .. }
            | BrokerOp::ReadUserKey { .. }
            | BrokerOp::RunRsync { .. }
            | BrokerOp::ReadOwnerMarker { .. }
            | BrokerOp::RestrictOnVerify { .. }
            | BrokerOp::Docker { .. }
            | BrokerOp::InVm { .. } => None,
        }
    }

    /// A short label naming the op family, for log lines and refusals that
    /// should not carry the whole payload.
    pub fn label(&self) -> &'static str {
        match self {
            BrokerOp::Create { .. } => "create",
            BrokerOp::CreateGateway { .. } => "create-gateway",
            BrokerOp::Start { .. } => "start",
            BrokerOp::Stop { .. } => "stop",
            BrokerOp::Delete { .. } => "delete",
            BrokerOp::Clone { .. } => "clone",
            BrokerOp::ListJson { .. } => "list-json",
            BrokerOp::InstallGuestAgent { .. } => "install-guest-agent",
            BrokerOp::ReadUserKey { .. } => "read-user-key",
            BrokerOp::RunRsync { .. } => "run-rsync",
            BrokerOp::ReadOwnerMarker { .. } => "read-owner-marker",
            BrokerOp::GuestSocat { .. } => "guest-socat",
            BrokerOp::RestrictOnVerify { .. } => "restrict-on-verify",
            BrokerOp::DockerStream { .. } => "docker-stream",
            BrokerOp::Docker { .. } => "docker",
            BrokerOp::InVm { .. } => "in-vm",
        }
    }
}

/// Prefix of the stream-connection identification frame.
///
/// When an agent opens a dedicated stream connection for a stream-class op
/// (see [`BrokerOp::stream_token_slot`]) it sends this prefix immediately
/// after the CHECKIN/auth phase, followed by the correlation token and a
/// newline:
///
/// ```text
/// STREAM_CONNECT:<hex-token>\n
/// ```
///
/// The daemon matches the token to a pending `PendingStream` entry registered
/// by the control-connection path, verifies the connection's peer-cred matches
/// the expected operator uid, and then hands the raw stream to the caller.
pub const STREAM_CONNECT_PREFIX: &str = "STREAM_CONNECT:";

/// The name of the wrapper marker file written by the qemu-wrapper after it
/// successfully injects `restrict=on` into the management netdev argv.
///
/// Path: `{lima_home}/{vm}/sandboxd-restrict-marker`.
/// Contents: the full rewritten `-netdev user,...` token including `restrict=on`.
///
/// The `RestrictOnVerify` op reads this file and confirms the token contains
/// `restrict=on`. Absence of the file means the wrapper did not run or failed
/// to inject the flag; the daemon must tear the VM down.
pub const RESTRICT_MARKER_FILENAME: &str = "sandboxd-restrict-marker";

/// Substring that must be present in the restrict marker file contents for the
/// `RestrictOnVerify` check to pass.
pub const RESTRICT_ON_MARKER: &str = "restrict=on";

/// Render a wire op's argv through the shared builders.
///
/// The conversion into the argv crate's own types is where the wire
/// vocabulary stops and the command-line vocabulary begins; both sides of
/// the channel cross it through the same functions, so neither can hold a
/// different idea of what an op means.
/// Render a stream op's `docker exec` argv through the shared builder.
///
/// `socket` is supplied by whoever is about to run the invocation — the
/// agent's own forwarded socket. It is not a field on the op and never
/// crosses the channel; see `own_gateway_docker_socket` in the agent's
/// handler for why that distinction is the whole point.
pub fn docker_stream_argv(op: &DockerStreamOp, socket: Option<&std::path::Path>) -> Vec<String> {
    sandbox_docker_argv::stream::stream_exec_argv(socket, op.container(), op.target())
}

/// Render an in-VM op's command, as the sequence of argv to run inside the VM.
///
/// `None` for the two ops that are file transfers rather than commands — see
/// [`in_vm_transfer`].
///
/// Mirrors `sandbox_core::in_vm::InVmOp::shell_steps` and renders through the
/// same builders, which is what keeps the daemon's idea of an op and the
/// agent's from drifting.
pub fn in_vm_shell_steps(op: &InVmOp) -> Option<Vec<Vec<String>>> {
    use sandbox_invm_argv::{lite_stage, route_helper, vm};

    let steps = match op {
        InVmOp::DockerReady => vec![vm::docker_ready_argv()],
        InVmOp::LinkShowJson => vec![vm::link_show_json_argv()],
        InVmOp::ApplyNftBaseline { .. } => vec![vm::apply_nft_baseline_argv()],
        InVmOp::RouteHelperProbe => vec![
            route_helper::probe_executable_argv(),
            route_helper::probe_caps_argv(),
        ],
        InVmOp::RouteHelperMakeInstallDir => vec![route_helper::make_install_dir_argv()],
        InVmOp::RouteHelperInstall => route_helper::install_argv(),
        InVmOp::RouteHelperSetcap => {
            vec![route_helper::chmod_argv(), route_helper::setcap_argv()]
        }
        InVmOp::LiteStageCreate { session_id } => {
            vec![lite_stage::mkdir_argv(&lite_stage::stage_dir(session_id))]
        }
        InVmOp::LiteStageRemove { session_id } => {
            vec![lite_stage::rm_argv(&lite_stage::stage_dir(session_id))]
        }
        InVmOp::InstallContainerRoute {
            container_pid,
            gateway_ip,
        } => vec![route_helper::install_container_route_argv(
            *container_pid,
            *gateway_ip,
        )],
        InVmOp::RouteHelperStage | InVmOp::LiteStageWrite { .. } => return None,
    };
    Some(steps)
}

/// The file transfer an in-VM op performs, if it is one: which file, and
/// where inside the VM it lands.
///
/// The *source* is not part of the answer, deliberately. It is resolved by the
/// agent against its own LIMA_HOME — either the enumerated route-helper
/// filename already sitting there, or a scratch copy of the content the op
/// carried.
pub fn in_vm_transfer(op: &InVmOp) -> Option<InVmTransfer> {
    use sandbox_invm_argv::lite_stage;

    match op {
        InVmOp::RouteHelperStage => Some(InVmTransfer {
            source: InVmTransferSource::RouteHelperBinary,
            destination: sandbox_invm_argv::route_helper::STAGED_PATH_IN_VM.to_string(),
        }),
        InVmOp::LiteStageWrite {
            session_id,
            file,
            body,
        } => {
            let file: lite_stage::LiteStageFile = (*file).into();
            Some(InVmTransfer {
                destination: lite_stage::file_path(&lite_stage::stage_dir(session_id), file),
                source: InVmTransferSource::Content {
                    basename: lite_stage::transfer_basename(session_id, file),
                    mode: file.mode(),
                    body: body.clone(),
                },
            })
        }
        _ => None,
    }
}

/// One file transfer into the VM.
#[derive(Debug, Clone)]
pub struct InVmTransfer {
    /// Where the source comes from on the agent's side.
    pub source: InVmTransferSource,
    /// The absolute path inside the VM the file lands at.
    pub destination: String,
}

/// Where the agent gets a transfer's source from.
///
/// Both arms resolve inside the agent's own LIMA_HOME. Neither carries a path
/// the daemon chose.
#[derive(Debug, Clone)]
pub enum InVmTransferSource {
    /// The pre-staged Linux/aarch64 route-helper binary, already present in
    /// the agent's LIMA_HOME under its enumerated filename.
    RouteHelperBinary,
    /// Content the op carried, to be written to a scratch file in the agent's
    /// LIMA_HOME at `mode` and copied from there. The mode matters: `limactl
    /// copy` preserves the source's, and that is what the container sees.
    Content {
        basename: String,
        mode: u32,
        body: String,
    },
}

/// The artifact an in-VM op writes to the child's standard input, if any.
///
/// Only the nftables baseline has one. Stdin on a `limactl shell` is a pipe
/// into a VM with passwordless `sudo`; that its single reader is an `nft`
/// parser is a property worth keeping true.
pub fn in_vm_stdin_body(op: &InVmOp) -> Option<&str> {
    match op {
        InVmOp::ApplyNftBaseline { ruleset } => Some(ruleset),
        _ => None,
    }
}

pub fn docker_argv(op: &crate::protocol::DockerOp) -> Result<Vec<String>, String> {
    use sandbox_docker_argv::{container, image, network, volume};

    let argv = match op {
        DockerOp::ContainerCreate { spec } => {
            let spec: container::ContainerCreateSpec = spec.into();
            container::container_create_argv(&spec).map_err(|e| e.into_message())?
        }
        DockerOp::ContainerStart { name } => container::container_start_argv(name),
        DockerOp::ContainerStop {
            name,
            grace_secs,
            long_flag,
        } => {
            if *long_flag {
                container::container_stop_long_argv(name, *grace_secs)
            } else {
                container::container_stop_argv(name, *grace_secs)
            }
        }
        DockerOp::ContainerRestart { name } => container::container_restart_argv(name),
        DockerOp::ContainerRemove { name, force } => {
            container::container_remove_argv(name, (*force).into())
        }
        DockerOp::ContainerInspect { name, format, flag } => {
            container::container_inspect_argv(name, (*format).into(), (*flag).into())
        }
        DockerOp::ContainerList {
            name_prefix,
            owner_pool,
        } => container::container_list_argv(name_prefix, owner_pool.as_deref()),
        DockerOp::ContainerExec { name, command } => {
            let command: container::ContainerCommand = command.into();
            container::container_exec_argv(name, &command)
        }
        DockerOp::ContainerExecStdin { name, command, .. } => {
            container::container_exec_stdin_argv(name, (*command).into())
        }
        DockerOp::HomeVolumeChown {
            session_id,
            image_tag,
            operator_uid,
            operator_gid,
        } => container::home_chown_run_argv(session_id, image_tag, *operator_uid, *operator_gid),
        DockerOp::GatewayContainerRun {
            session_id,
            image_tag,
            network: net,
            owner_pool,
            coredns_upstream,
        } => container::gateway_container_run_argv(
            session_id,
            image_tag,
            net,
            owner_pool.as_deref(),
            coredns_upstream.as_deref(),
        ),
        DockerOp::NetworkCreate { spec } => {
            let spec: network::NetworkCreateSpec = spec.into();
            network::network_create_argv(&spec)
        }
        DockerOp::NetworkRemove { name } => network::network_remove_argv(name),
        DockerOp::NetworkInspect { name } => network::network_inspect_argv(name),
        DockerOp::NetworkConnect {
            network: net,
            container: ctr,
            ip,
            gateway_priority,
        } => network::network_connect_argv(net, ctr, ip.as_deref(), (*gateway_priority).into()),
        DockerOp::NetworkList {
            name_prefix,
            owner_pool,
        } => network::network_list_argv(name_prefix, owner_pool.as_deref()),
        DockerOp::VolumeCreate {
            name,
            session_id,
            owner_pool,
        } => volume::volume_create_argv(name, session_id.as_deref(), owner_pool.as_deref()),
        DockerOp::VolumeRemove { name } => volume::volume_remove_argv(name),
        DockerOp::VolumeList {
            name_prefix,
            owner_pool,
        } => volume::volume_list_argv(name_prefix, owner_pool.as_deref()),
        DockerOp::ImageInspect { tag } => image::image_inspect_argv(tag),
        DockerOp::ImageLoad { .. } => image::image_load_argv(),
        DockerOp::DaemonInfo => image::daemon_info_argv(),
    };
    Ok(argv)
}
