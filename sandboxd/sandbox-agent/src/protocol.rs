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
//! ## Streaming (`GuestSocat`)
//!
//! `GuestSocat` opens a long-lived bidirectional byte-pump to the in-VM guest
//! agent. Its framing is distinct from one-shot request/response:
//!
//! ```text
//! daemon → agent: JSON(BrokerRequest { op: GuestSocat { vm } })\n
//! agent → daemon: JSON(BrokerResponse::StreamOpen)\n
//! [bidirectional raw byte stream until either side closes]
//! ```
//!
//! After `StreamOpen`, the stream carries raw bytes — the agent splices its
//! stdin/stdout to `limactl shell <vm> -- socat - TCP:127.0.0.1:5123` and
//! copies between the broker connection and the socat process until either end
//! closes. There is no further framing; the agent and daemon each close their
//! half of the stream to signal EOF to the other.
//!
//! The daemon treats `StreamOpen` as the signal to begin raw-byte I/O; any
//! further `BrokerResponse` JSON on the stream after `StreamOpen` would be a
//! protocol error (the agent must not write any more framed data after sending
//! `StreamOpen`).
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
            | BrokerOp::RestrictOnVerify { op_uid, .. } => *op_uid,
        }
    }
}

/// Prefix of the stream-connection identification frame.
///
/// When an agent opens a dedicated stream connection for a `GuestSocat` op
/// it sends this prefix immediately after the CHECKIN/auth phase, followed
/// by the correlation token and a newline:
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
