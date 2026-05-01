//! NFLOG receiver: subscribe to `NFNLGRP_NFLOG` group 1 and emit one
//! `deny` event per kernel-emitted message.
//!
//! ## Why this exists
//!
//! The previous datapath DNAT'd unmatched UDP to a userland listener on
//! `gateway_ip:10002`; the listener `recv()`'d the datagram purely so
//! the kernel had a `(src,dst)` pair to feed into a conntrack lookup
//! that recovered the pre-DNAT destination (the kernel had already
//! mutated the destination during DNAT).
//! `2026-05-01-udp-nft-loggers-design.md` Decision 2 removes the DNAT
//! and the userland listener entirely: the kernel drops denied UDP via
//! `nft drop` and copies the packet to NFLOG group 1. NFLOG carries the
//! *pre-rewrite* IPv4 + UDP headers, so the pre-DNAT 5-tuple is the
//! receiver's straight-from-the-headers parse.
//!
//! ## Wire shape
//!
//! Each kernel-emitted message is an `nlmsghdr` whose 16-bit type field
//! splits into `(NFNL_SUBSYS_ULOG << 8) | NFULNL_MSG_PACKET`, followed
//! by a `nfgenmsg` header (`family / version / res_id`, where `res_id`
//! is the NFLOG group number in network byte order), and then a
//! sequence of TLV attributes. The ones we care about:
//!
//! - `NFULA_PACKET_HDR` (1) — `(hw_protocol be16, hook u8, _pad u8)`.
//!   We use this to confirm the captured frame is IPv4 (hw_protocol =
//!   0x0800).
//! - `NFULA_PAYLOAD` (9) — raw bytes starting at the L3 header (the
//!   IPv4 header in our case). For IPv4 + UDP this is enough to extract
//!   `(src_ip, src_port, dst_ip, dst_port)`.
//! - Other attributes (`NFULA_TIMESTAMP`, `NFULA_PREFIX`,
//!   `NFULA_HWADDR`, …) are ignored; the deny event only needs the
//!   5-tuple.
//!
//! The wire format is stable kernel UAPI documented in
//! `linux/netfilter/nfnetlink_log.h` and `linux/netfilter/nfnetlink.h`.
//!
//! ## Bind sequence
//!
//! Before the kernel will emit packets to us, we send three
//! configuration messages on the same socket (mirrors the
//! `libnetfilter_log` handshake):
//!
//! 1. `NFULNL_MSG_CONFIG` with `res_id = 0` carrying
//!    `NFULA_CFG_CMD = NFULNL_CFG_CMD_PF_BIND` for `AF_INET` — tells
//!    the kernel this socket wants nflog notifications for IPv4.
//! 2. `NFULNL_MSG_CONFIG` with `res_id = group` carrying
//!    `NFULA_CFG_CMD = NFULNL_CFG_CMD_BIND` — tells the kernel this
//!    socket is the consumer for that group. Without this step the
//!    family-level PF_BIND alone is a no-op and the kernel never
//!    routes any packets to us.
//! 3. `NFULNL_MSG_CONFIG` with `res_id = group` carrying
//!    `NFULA_CFG_MODE = (NFULNL_COPY_PACKET, copy_range)` — tells the
//!    kernel what to copy to userspace for messages on the requested
//!    group. We ask for the full L3 payload because rewinding through
//!    just headers would not let us validate the L4 length.
//!
//! Both messages are documented in
//! `linux/netfilter/nfnetlink_log.h` (`NFULNL_MSG_CONFIG` /
//! `NFULA_CFG_CMD` / `NFULA_CFG_MODE`); the same handshake is what
//! `libnetfilter_log` performs internally.
//!
//! ## Async / blocking
//!
//! The receive loop blocks on `recv` inside `tokio::task::spawn_blocking`
//! (CLAUDE.md convention) so the netlink syscall doesn't park a worker
//! thread of the runtime under sustained traffic. The hot path is
//! single-threaded by design; the sender is the kernel and the consumer
//! is one task.

use std::io;
use std::net::Ipv4Addr;
use std::os::fd::{AsRawFd, RawFd};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use chrono::Utc;
use netlink_sys::{Socket, SocketAddr, protocols::NETLINK_NETFILTER};
use thiserror::Error;

use sandbox_event_emitter::{Admit, DenyRecord, EventEmitter, Protocol, RateCap};

// -----------------------------------------------------------------------------
// Wire-format constants. Mirror `linux/netfilter/nfnetlink.h` and
// `linux/netfilter/nfnetlink_log.h` (UAPI; stable kernel ABI).
// -----------------------------------------------------------------------------

/// Netfilter subsystem byte for ULOG (NFLOG userspace logging).
const NFNL_SUBSYS_ULOG: u8 = 4;

/// Top-level message type: a captured packet notification.
const NFULNL_MSG_PACKET: u8 = 0;
/// Top-level message type: a configuration command.
const NFULNL_MSG_CONFIG: u8 = 1;

/// CFG attribute holding a `(cmd: u8)` enum value.
const NFULA_CFG_CMD: u16 = 1;
/// CFG attribute holding `nfulnl_msg_config_mode { copy_range: u32be,
/// copy_mode: u8, _pad: u8 }`.
const NFULA_CFG_MODE: u16 = 2;

/// `NFULNL_CFG_CMD_BIND` — bind this socket to a specific NFLOG group
/// (group number passed in `res_id`). Required before the kernel will
/// emit any packet messages for the group on this socket.
const NFULNL_CFG_CMD_BIND: u8 = 1;
/// `NFULNL_CFG_CMD_PF_BIND` — bind this socket to a protocol family
/// (AF_INET / AF_INET6 / …) so the kernel routes nflog packets for
/// that family to us. Per UAPI `enum nfulnl_msg_config_cmds`,
/// `PF_BIND = 3`; the previous `= 1` value collided with
/// `NFULNL_CFG_CMD_BIND` and meant the family handshake was
/// effectively a no-op group-zero bind, so the kernel never routed
/// packets to the socket.
const NFULNL_CFG_CMD_PF_BIND: u8 = 3;
/// `NFULNL_COPY_PACKET` — copy the full packet (subject to copy_range).
const NFULNL_COPY_PACKET: u8 = 2;
/// Copy-range we request from the kernel. The maximum IPv4 packet plus
/// some headroom; we don't actually need this many bytes (we only read
/// L3 + L4 headers) but asking for the full packet matches what
/// `libnetfilter_log` does and avoids any kernel-side truncation that
/// would break our header parse for jumbo MTU edge cases.
const COPY_RANGE: u32 = 0xFFFF;

/// Per-packet attribute: nfulnl_msg_packet_hdr.
const NFULA_PACKET_HDR: u16 = 1;
/// Per-packet attribute: raw L3 payload (the IPv4 header onward).
const NFULA_PAYLOAD: u16 = 9;

/// `NLA_F_NESTED` bit on attribute types. Mask out before comparing.
const NLA_F_NESTED: u16 = 0x8000;
/// `NLA_F_NET_BYTEORDER` bit on attribute types. Mask out before
/// comparing.
const NLA_F_NET_BYTEORDER: u16 = 0x4000;
const NLA_TYPE_MASK: u16 = !(NLA_F_NESTED | NLA_F_NET_BYTEORDER);

/// netlink message header size.
const NLMSG_HDR_LEN: usize = 16;
/// nfgenmsg header size: family u8 + version u8 + res_id u16be.
const NFGEN_HDR_LEN: usize = 4;

/// Hardware-protocol value for IPv4 in the NFULA_PACKET_HDR attribute
/// (`ETH_P_IP` from `linux/if_ether.h`, in network byte order).
const ETH_P_IP_BE: u16 = 0x0800;

/// IP protocol number for UDP. We assert this in the L3 header before
/// parsing the UDP source/destination ports, so a stray non-UDP packet
/// (the deny rule scopes to `meta l4proto udp` so this should not
/// happen in production) does not produce a malformed deny event.
const IPPROTO_UDP: u8 = 17;

const NLM_F_REQUEST: u16 = 1;
const NLM_F_ACK: u16 = 4;

// -----------------------------------------------------------------------------
// Diagnostics counters. Process-wide; the deny-logger is per-session
// (one process per gateway container).
// -----------------------------------------------------------------------------

/// NFLOG messages successfully parsed and emitted as deny events.
static NFLOG_EMITTED: AtomicU64 = AtomicU64::new(0);
/// NFLOG messages rejected by the parser (truncated, missing payload,
/// non-IPv4, non-UDP).
static NFLOG_PARSE_ERRORS: AtomicU64 = AtomicU64::new(0);

/// Snapshot of `NFLOG_EMITTED`. Diagnostic only.
#[allow(dead_code)]
pub fn emitted() -> u64 {
    NFLOG_EMITTED.load(Ordering::Relaxed)
}

/// Snapshot of `NFLOG_PARSE_ERRORS`. Diagnostic only.
#[allow(dead_code)]
pub fn parse_errors() -> u64 {
    NFLOG_PARSE_ERRORS.load(Ordering::Relaxed)
}

// -----------------------------------------------------------------------------
// Errors.
// -----------------------------------------------------------------------------

#[derive(Debug, Error)]
pub enum NflogError {
    #[error("nflog i/o: {0}")]
    Io(#[from] io::Error),
    #[error("nflog protocol error: {0}")]
    Protocol(String),
}

// -----------------------------------------------------------------------------
// Subscriber handle.
// -----------------------------------------------------------------------------

/// Owns the netlink socket bound to NFNLGRP_NFLOG group `group`.
pub struct NflogSubscriber {
    socket: Socket,
    /// NFLOG group we subscribed to. Carried for diagnostics +
    /// post-bind sanity checks (the kernel emits `nfgenmsg.res_id` =
    /// our group on every packet message; if it ever differs we have a
    /// configuration bug).
    group: u16,
}

impl NflogSubscriber {
    /// Open a NETLINK_NETFILTER socket and configure it as the
    /// consumer of nflog packets for `group`.
    ///
    /// We `bind()` with `nl_groups = 0` because the
    /// `NFULNL_MSG_CONFIG` handshake (PF_BIND + per-group BIND, sent
    /// from `configure`) is what registers the socket as the per-group
    /// consumer; NFLOG packet messages are unicast to that consumer
    /// rather than multicast over `nl_groups`. Mirrors the
    /// `libnetfilter_log` setup sequence.
    ///
    /// Requires `CAP_NET_ADMIN` — present in the gateway container by
    /// virtue of `--cap-add NET_ADMIN` (audit §2.4).
    pub fn bind(group: u16) -> Result<Self, NflogError> {
        if group == 0 {
            return Err(NflogError::Protocol(
                "nflog group 0 is reserved (Resolution 1 pins group 1)".into(),
            ));
        }

        let mut socket = Socket::new(NETLINK_NETFILTER)?;
        // Bump the receive buffer so a UDP-deny burst doesn't drop
        // packets on the kernel side before we can drain. The kernel
        // default (`net.core.rmem_default`, ~200 KiB) is enough for
        // single-flow workloads but a 12-flow simultaneous burst
        // overflowed it on the prior 8 KiB userspace buffer, leaving
        // only 1 of 12 packets visible. 4 MiB is the value
        // `libnetfilter_log` uses by default and is well within
        // `net.core.rmem_max` on stock kernels (`8388608` on Linux 6).
        socket.set_rx_buf_sz(4 * 1024 * 1024)?;
        // pid=0 → kernel auto-assigns; nl_groups=0 because per-group
        // routing comes from the NFULNL_CFG_CMD_BIND handshake.
        socket.bind(&SocketAddr::new(0, 0))?;

        let mut me = Self { socket, group };
        me.configure()?;
        Ok(me)
    }

    /// Send the three-step PF_BIND + group-BIND + COPY_PACKET
    /// handshake. After this returns, the kernel will emit one
    /// NFULNL_MSG_PACKET per nft `log group <group>` hit on this
    /// socket.
    fn configure(&mut self) -> Result<(), NflogError> {
        // Step 1: NFULNL_CFG_CMD_PF_BIND for AF_INET, res_id = 0.
        let cmd_msg = build_config_pf_bind(libc::AF_INET as u8);
        self.socket.send(&cmd_msg, 0)?;

        // Step 2: NFULNL_CFG_CMD_BIND for our group. Without this the
        // PF_BIND alone is a no-op — the kernel needs an explicit
        // per-group consumer registration before it will route packets
        // for `nft log group <group>` to this socket.
        let bind_msg = build_config_group_bind(self.group);
        self.socket.send(&bind_msg, 0)?;

        // Step 3: NFULA_CFG_MODE NFULNL_COPY_PACKET for our group.
        let mode_msg = build_config_mode(self.group);
        self.socket.send(&mode_msg, 0)?;
        Ok(())
    }

    /// Receive one or more NFULNL_MSG_PACKET notifications. Returns
    /// every parsed deny record from the recv buffer; an empty `Vec`
    /// indicates the buffer held only ACKs / non-packet messages /
    /// non-UDP packets (caller loops without acting). Multi-message
    /// batches happen in two regimes: a) the kernel concatenates
    /// nflog packet messages into a single sk_buff under bursts; b)
    /// during configure() the three handshake ACKs may arrive
    /// alongside the first user packet.
    pub fn recv_packets(&mut self) -> Result<Vec<DenyRecord>, NflogError> {
        // 64 KiB recv buffer — matches the order-4 page allocation
        // `nfnetlink_log` uses for its skb (`NLMSG_GOODSIZE`), so a
        // burst of packets that the kernel coalesces into one skb
        // arrives here without truncation.
        let mut buf = [0u8; 64 * 1024];
        let n = self.socket.recv(&mut &mut buf[..], 0)?;
        let bytes = &buf[..n];
        parse_all(bytes, self.group)
    }

    /// Underlying file descriptor — exposed for tests that want to
    /// drive the socket directly (e.g. inject a synthetic netlink
    /// message via writev). Not used in production.
    #[allow(dead_code)]
    pub(crate) fn as_raw_fd(&self) -> RawFd {
        self.socket.as_raw_fd()
    }
}

// -----------------------------------------------------------------------------
// Receive loop.
// -----------------------------------------------------------------------------

/// Run the NFLOG receive loop. Blocks the calling task; the caller
/// places this inside `tokio::task::spawn_blocking` per CLAUDE.md's
/// blocking-syscall convention.
///
/// Returns `Ok(())` when the socket is closed cleanly (only on test
/// abort — production runs forever) and an `Err` on unrecoverable I/O.
/// Soft errors (parse failures, non-UDP packets) increment the
/// counters and continue the loop.
pub fn run_blocking(
    mut subscriber: NflogSubscriber,
    emitter: Arc<EventEmitter>,
    rate_cap: Arc<RateCap>,
) -> Result<(), NflogError> {
    loop {
        match subscriber.recv_packets() {
            Ok(records) => {
                for record in records {
                    if rate_cap.try_admit(Utc::now()) == Admit::Ok {
                        emitter.emit_deny(record);
                        NFLOG_EMITTED.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
            Err(NflogError::Io(err)) if err.kind() == io::ErrorKind::Interrupted => {
                continue;
            }
            Err(NflogError::Io(err)) => {
                tracing::warn!(error = %err, "nflog recv failed");
                return Err(NflogError::Io(err));
            }
            Err(NflogError::Protocol(msg)) => {
                NFLOG_PARSE_ERRORS.fetch_add(1, Ordering::Relaxed);
                tracing::debug!(reason = %msg, "nflog message dropped at parse");
            }
        }
    }
}

// -----------------------------------------------------------------------------
// Wire encode / decode.
// -----------------------------------------------------------------------------

/// Build a `NFULNL_MSG_CONFIG` (PF_BIND, AF_INET) message. `res_id` is
/// 0 because the PF_BIND command operates on the protocol family, not
/// a specific group.
fn build_config_pf_bind(family: u8) -> Vec<u8> {
    let payload = build_config_cmd_payload(NFULNL_CFG_CMD_PF_BIND);
    build_nlmsg(
        NFNL_SUBSYS_ULOG,
        NFULNL_MSG_CONFIG,
        NLM_F_REQUEST | NLM_F_ACK,
        family,
        /* res_id */ 0,
        &payload,
    )
}

/// Build a `NFULNL_MSG_CONFIG` (CMD_BIND) message for NFLOG group
/// `group`. `family` is `AF_UNSPEC` because the per-group bind is
/// family-agnostic — the family was already pinned by the prior
/// `PF_BIND` step.
fn build_config_group_bind(group: u16) -> Vec<u8> {
    let payload = build_config_cmd_payload(NFULNL_CFG_CMD_BIND);
    build_nlmsg(
        NFNL_SUBSYS_ULOG,
        NFULNL_MSG_CONFIG,
        NLM_F_REQUEST | NLM_F_ACK,
        /* family */ libc::AF_UNSPEC as u8,
        group,
        &payload,
    )
}

/// Build a `NFULNL_MSG_CONFIG` (NFULA_CFG_MODE = COPY_PACKET) message
/// targeting NFLOG group `group`.
fn build_config_mode(group: u16) -> Vec<u8> {
    let payload = build_config_mode_payload(COPY_RANGE);
    build_nlmsg(
        NFNL_SUBSYS_ULOG,
        NFULNL_MSG_CONFIG,
        NLM_F_REQUEST | NLM_F_ACK,
        /* family */ libc::AF_INET as u8,
        group,
        &payload,
    )
}

/// Single-attribute payload: `NFULA_CFG_CMD = (cmd: u8)`. Padded to
/// 4-byte boundary per netlink TLV rules.
fn build_config_cmd_payload(cmd: u8) -> Vec<u8> {
    // nlattr is 4 bytes (len: u16, ty: u16) followed by payload + pad.
    let mut out = Vec::with_capacity(8);
    let attr_len: u16 = 4 + 1; // header + 1-byte cmd
    out.extend_from_slice(&attr_len.to_ne_bytes());
    out.extend_from_slice(&NFULA_CFG_CMD.to_ne_bytes());
    out.push(cmd);
    // pad to 4-byte alignment
    while out.len() % 4 != 0 {
        out.push(0);
    }
    out
}

/// Single-attribute payload: `NFULA_CFG_MODE` = `(copy_range: u32be,
/// copy_mode: u8, _pad: u8)`. `_pad` is 2 bytes including the trailing
/// alignment.
fn build_config_mode_payload(copy_range: u32) -> Vec<u8> {
    // struct nfulnl_msg_config_mode {
    //   __be32 copy_range;
    //   __u8   copy_mode;
    //   __u8   _pad;
    // } — 6 bytes, padded to 8 inside the attribute.
    let mut out = Vec::with_capacity(12);
    let attr_len: u16 = 4 + 6;
    out.extend_from_slice(&attr_len.to_ne_bytes());
    out.extend_from_slice(&NFULA_CFG_MODE.to_ne_bytes());
    out.extend_from_slice(&copy_range.to_be_bytes());
    out.push(NFULNL_COPY_PACKET);
    out.push(0); // _pad
    while out.len() % 4 != 0 {
        out.push(0);
    }
    out
}

/// Build a complete netlink message: `nlmsghdr` + `nfgenmsg` + payload.
fn build_nlmsg(
    subsys: u8,
    msg_type: u8,
    flags: u16,
    family: u8,
    res_id: u16,
    payload: &[u8],
) -> Vec<u8> {
    let total_len = NLMSG_HDR_LEN + NFGEN_HDR_LEN + payload.len();
    let mut out = Vec::with_capacity(total_len);

    // nlmsghdr: len, type, flags, seq, pid
    out.extend_from_slice(&(total_len as u32).to_ne_bytes());
    let nl_type: u16 = ((subsys as u16) << 8) | (msg_type as u16);
    out.extend_from_slice(&nl_type.to_ne_bytes());
    out.extend_from_slice(&flags.to_ne_bytes());
    out.extend_from_slice(&0u32.to_ne_bytes()); // seq
    out.extend_from_slice(&0u32.to_ne_bytes()); // pid (kernel auto-fills)

    // nfgenmsg: family u8, version u8, res_id u16be
    out.push(family);
    out.push(0); // NFNETLINK_V0
    out.extend_from_slice(&res_id.to_be_bytes());

    // payload (already aligned)
    out.extend_from_slice(payload);

    out
}

/// Parse every netlink message in a `recv` buffer, returning the deny
/// records extracted from `NFULNL_MSG_PACKET` notifications. Non-packet
/// messages (config replies, NLMSG_DONE, NLMSG_ERROR, …) and packets we
/// can't decode (non-IPv4, non-UDP, missing payload) are skipped.
///
/// The kernel coalesces multiple nflog packet notifications into a
/// single skb under bursts (the boundary is one `skb_size = 4096 << 4`
/// page allocation), so a single `recv` may carry multiple packet
/// messages — we MUST drain them all here. Earlier revisions returned
/// after the first packet and lost the rest of the batch.
fn parse_all(mut buf: &[u8], expected_group: u16) -> Result<Vec<DenyRecord>, NflogError> {
    let mut out = Vec::new();
    while buf.len() >= NLMSG_HDR_LEN {
        // nlmsghdr fields.
        let len = u32::from_ne_bytes(buf[0..4].try_into().unwrap()) as usize;
        let nl_type = u16::from_ne_bytes(buf[4..6].try_into().unwrap());
        if len < NLMSG_HDR_LEN || len > buf.len() {
            return Err(NflogError::Protocol(format!(
                "nlmsghdr length out of bounds (len={len}, buf={})",
                buf.len()
            )));
        }
        let msg = &buf[..len];
        let next = aligned(len);

        let subsys = ((nl_type >> 8) & 0xFF) as u8;
        let kind = (nl_type & 0xFF) as u8;

        if subsys == NFNL_SUBSYS_ULOG && kind == NFULNL_MSG_PACKET {
            if msg.len() < NLMSG_HDR_LEN + NFGEN_HDR_LEN {
                return Err(NflogError::Protocol("packet msg too short".into()));
            }
            let nfgen = &msg[NLMSG_HDR_LEN..NLMSG_HDR_LEN + NFGEN_HDR_LEN];
            let res_id = u16::from_be_bytes([nfgen[2], nfgen[3]]);
            if res_id != expected_group {
                // A different group reusing the same socket — should not
                // happen in our deployment (we bind exactly one group)
                // but ignore rather than error so a future multi-group
                // setup doesn't have to refactor this path.
                tracing::debug!(
                    expected = expected_group,
                    got = res_id,
                    "nflog packet for unexpected group; skipping"
                );
            } else {
                let attrs = &msg[NLMSG_HDR_LEN + NFGEN_HDR_LEN..];
                match parse_packet_attrs(attrs) {
                    Ok(Some(record)) => out.push(record),
                    Ok(None) => {
                        // Non-IPv4 / non-UDP / no payload — skip but
                        // count so the operator can spot a misconfig.
                        NFLOG_PARSE_ERRORS.fetch_add(1, Ordering::Relaxed);
                    }
                    Err(err) => {
                        NFLOG_PARSE_ERRORS.fetch_add(1, Ordering::Relaxed);
                        tracing::debug!(error = %err, "nflog attr parse failed");
                    }
                }
            }
        }
        // Skip non-packet messages (config replies, NLMSG_DONE, etc.).
        if next >= buf.len() {
            break;
        }
        buf = &buf[next..];
    }
    Ok(out)
}

/// Walk the TLV attributes of a packet message, locate
/// `NFULA_PACKET_HDR` (to gate on IPv4) and `NFULA_PAYLOAD` (to read
/// the L3+L4 headers).
fn parse_packet_attrs(mut buf: &[u8]) -> Result<Option<DenyRecord>, NflogError> {
    let mut hw_proto: Option<u16> = None;
    let mut payload: Option<&[u8]> = None;

    while buf.len() >= 4 {
        let attr_len = u16::from_ne_bytes(buf[0..2].try_into().unwrap()) as usize;
        let attr_type_raw = u16::from_ne_bytes(buf[2..4].try_into().unwrap());
        let attr_type = attr_type_raw & NLA_TYPE_MASK;
        if attr_len < 4 || attr_len > buf.len() {
            return Err(NflogError::Protocol(format!(
                "nlattr length out of bounds (len={attr_len}, buf={})",
                buf.len()
            )));
        }
        let val = &buf[4..attr_len];
        match attr_type {
            NFULA_PACKET_HDR => {
                if val.len() >= 2 {
                    hw_proto = Some(u16::from_be_bytes([val[0], val[1]]));
                }
            }
            NFULA_PAYLOAD => {
                payload = Some(val);
            }
            _ => {}
        }
        let next = aligned(attr_len);
        if next >= buf.len() {
            break;
        }
        buf = &buf[next..];
    }

    // The deny rule scopes to `meta l4proto udp`, but the kernel does
    // not pre-filter NFLOG to the matching family — gate on the
    // hw-protocol attribute so a hypothetical IPv6 nflog hit would not
    // produce a malformed IPv4 deny event.
    let Some(hw_proto) = hw_proto else {
        return Err(NflogError::Protocol(
            "NFULA_PACKET_HDR missing in packet message".into(),
        ));
    };
    if hw_proto != ETH_P_IP_BE {
        return Err(NflogError::Protocol(format!(
            "non-IPv4 hw_protocol 0x{hw_proto:04x}; skipping"
        )));
    }

    let Some(payload) = payload else {
        return Err(NflogError::Protocol(
            "NFULA_PAYLOAD missing in packet message".into(),
        ));
    };

    parse_ipv4_udp(payload)
}

/// Extract `(src, dst)` from raw IPv4 + UDP bytes.
///
/// The IPv4 header may carry options (variable IHL) so the L4 offset
/// is `IHL * 4` rather than a fixed 20. Returns `Ok(None)` for non-UDP
/// packets — the deny rule is UDP-only so this is a defensive guard,
/// not a hot path.
fn parse_ipv4_udp(payload: &[u8]) -> Result<Option<DenyRecord>, NflogError> {
    if payload.len() < 20 {
        return Err(NflogError::Protocol(format!(
            "IPv4 header truncated ({} bytes)",
            payload.len()
        )));
    }
    let version_ihl = payload[0];
    let version = version_ihl >> 4;
    if version != 4 {
        return Err(NflogError::Protocol(format!(
            "non-IPv4 packet (version={version})"
        )));
    }
    let ihl = (version_ihl & 0x0F) as usize;
    if ihl < 5 {
        return Err(NflogError::Protocol(format!("invalid IHL={ihl}")));
    }
    let l4_off = ihl * 4;
    if payload.len() < l4_off + 8 {
        return Err(NflogError::Protocol(format!(
            "IPv4+UDP truncated (len={}, need {})",
            payload.len(),
            l4_off + 8
        )));
    }
    let proto = payload[9];
    if proto != IPPROTO_UDP {
        // Should not happen for our deny rule; defensive.
        return Ok(None);
    }
    let src_ip = Ipv4Addr::new(payload[12], payload[13], payload[14], payload[15]);
    let dst_ip = Ipv4Addr::new(payload[16], payload[17], payload[18], payload[19]);
    let src_port = u16::from_be_bytes([payload[l4_off], payload[l4_off + 1]]);
    let dst_port = u16::from_be_bytes([payload[l4_off + 2], payload[l4_off + 3]]);
    Ok(Some(DenyRecord {
        orig_dst_ip: dst_ip,
        orig_dst_port: dst_port,
        protocol: Protocol::Udp,
        src_ip,
        src_port,
    }))
}

/// Round `n` up to the next 4-byte boundary. NLMSG / NLA payloads are
/// always 4-byte aligned; `NLMSG_ALIGN(n)` from `linux/netlink.h`.
const fn aligned(n: usize) -> usize {
    (n + 3) & !3usize
}

// -----------------------------------------------------------------------------
// Tests.
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aligned_rounds_up_to_4() {
        assert_eq!(aligned(0), 0);
        assert_eq!(aligned(1), 4);
        assert_eq!(aligned(3), 4);
        assert_eq!(aligned(4), 4);
        assert_eq!(aligned(5), 8);
        assert_eq!(aligned(20), 20);
    }

    /// Build a synthetic NFLOG packet message and parse it — the
    /// hermetic regression catcher for the entire wire pipeline (no
    /// netlink syscall, no kernel).
    #[test]
    fn parse_one_extracts_5tuple_from_well_formed_message() {
        // IPv4 header (20 bytes, no options): version 4, IHL 5, total
        // length doesn't matter for our parse.
        let mut ipv4 = [0u8; 20];
        ipv4[0] = 0x45; // version 4 << 4 | IHL 5
        ipv4[9] = IPPROTO_UDP;
        // src 10.20.30.40, dst 198.51.100.1
        ipv4[12..16].copy_from_slice(&[10, 20, 30, 40]);
        ipv4[16..20].copy_from_slice(&[198, 51, 100, 1]);

        // UDP header (8 bytes): src_port 50000, dst_port 9999.
        let mut udp = [0u8; 8];
        udp[0..2].copy_from_slice(&50_000u16.to_be_bytes());
        udp[2..4].copy_from_slice(&9_999u16.to_be_bytes());

        let payload: Vec<u8> = [&ipv4[..], &udp[..]].concat();

        // Build the attribute block: NFULA_PACKET_HDR (hw_proto IPv4)
        // + NFULA_PAYLOAD.
        let mut attrs = Vec::new();
        // NFULA_PACKET_HDR
        let hdr_val: [u8; 4] = [
            0x08, 0x00, // hw_protocol = 0x0800 (IPv4) be
            0,    // hook
            0,    // _pad
        ];
        let attr_hdr_len: u16 = 4 + 4;
        attrs.extend_from_slice(&attr_hdr_len.to_ne_bytes());
        attrs.extend_from_slice(&NFULA_PACKET_HDR.to_ne_bytes());
        attrs.extend_from_slice(&hdr_val);
        // already aligned

        // NFULA_PAYLOAD
        let payload_attr_len = (4 + payload.len()) as u16;
        attrs.extend_from_slice(&payload_attr_len.to_ne_bytes());
        attrs.extend_from_slice(&NFULA_PAYLOAD.to_ne_bytes());
        attrs.extend_from_slice(&payload);
        while attrs.len() % 4 != 0 {
            attrs.push(0);
        }

        // Wrap in nfgenmsg + nlmsghdr.
        let nl_type: u16 = ((NFNL_SUBSYS_ULOG as u16) << 8) | (NFULNL_MSG_PACKET as u16);
        let total_len = NLMSG_HDR_LEN + NFGEN_HDR_LEN + attrs.len();
        let mut msg = Vec::with_capacity(total_len);
        msg.extend_from_slice(&(total_len as u32).to_ne_bytes());
        msg.extend_from_slice(&nl_type.to_ne_bytes());
        msg.extend_from_slice(&0u16.to_ne_bytes()); // flags
        msg.extend_from_slice(&0u32.to_ne_bytes()); // seq
        msg.extend_from_slice(&0u32.to_ne_bytes()); // pid
        // nfgenmsg
        msg.push(libc::AF_INET as u8);
        msg.push(0);
        msg.extend_from_slice(&1u16.to_be_bytes()); // res_id = group 1
        msg.extend_from_slice(&attrs);

        let parsed = parse_all(&msg, 1).expect("well-formed message parses");
        assert_eq!(parsed.len(), 1, "exactly one record from one packet msg");
        let record = &parsed[0];
        assert_eq!(record.src_ip, Ipv4Addr::new(10, 20, 30, 40));
        assert_eq!(record.src_port, 50_000);
        assert_eq!(record.orig_dst_ip, Ipv4Addr::new(198, 51, 100, 1));
        assert_eq!(record.orig_dst_port, 9_999);
        assert_eq!(record.protocol, Protocol::Udp);
    }

    #[test]
    fn parse_ipv4_udp_handles_options_via_ihl() {
        // 24-byte IPv4 header (one 4-byte option), UDP payload.
        let mut ipv4 = [0u8; 24];
        ipv4[0] = 0x46; // version 4 << 4 | IHL 6 (24 bytes)
        ipv4[9] = IPPROTO_UDP;
        ipv4[12..16].copy_from_slice(&[1, 2, 3, 4]);
        ipv4[16..20].copy_from_slice(&[5, 6, 7, 8]);
        // ipv4[20..24] = options padding
        let mut udp = [0u8; 8];
        udp[0..2].copy_from_slice(&123u16.to_be_bytes());
        udp[2..4].copy_from_slice(&456u16.to_be_bytes());
        let payload: Vec<u8> = [&ipv4[..], &udp[..]].concat();

        let record = parse_ipv4_udp(&payload).unwrap().unwrap();
        assert_eq!(record.src_port, 123);
        assert_eq!(record.orig_dst_port, 456);
    }

    #[test]
    fn parse_ipv4_udp_rejects_non_udp_quietly() {
        let mut ipv4 = vec![0u8; 28];
        ipv4[0] = 0x45;
        ipv4[9] = 6; // TCP
        let result = parse_ipv4_udp(&ipv4).unwrap();
        assert!(
            result.is_none(),
            "non-UDP IPv4 packet should produce no deny record"
        );
    }

    #[test]
    fn parse_ipv4_udp_errors_on_truncated_header() {
        let buf = vec![0u8; 10];
        let err = parse_ipv4_udp(&buf).unwrap_err();
        assert!(
            matches!(err, NflogError::Protocol(_)),
            "truncated IPv4 must surface a protocol error; got {err:?}"
        );
    }

    #[test]
    fn build_config_pf_bind_round_trips_subsys_and_type() {
        let bytes = build_config_pf_bind(libc::AF_INET as u8);
        // nlmsghdr: 16 bytes
        assert!(bytes.len() >= 16);
        let nl_type = u16::from_ne_bytes([bytes[4], bytes[5]]);
        let subsys = (nl_type >> 8) as u8;
        let kind = (nl_type & 0xFF) as u8;
        assert_eq!(subsys, NFNL_SUBSYS_ULOG);
        assert_eq!(kind, NFULNL_MSG_CONFIG);
        // nfgenmsg.family at offset 16
        assert_eq!(bytes[16], libc::AF_INET as u8);
        // nfgenmsg.res_id (be16) at offset 18 — PF_BIND uses res_id 0
        assert_eq!(u16::from_be_bytes([bytes[18], bytes[19]]), 0);
    }

    #[test]
    fn build_config_mode_targets_requested_group() {
        let bytes = build_config_mode(7);
        // res_id (be16) at offset 18 = group
        assert_eq!(u16::from_be_bytes([bytes[18], bytes[19]]), 7);
    }

    #[test]
    fn nflog_subscriber_rejects_group_zero() {
        match NflogSubscriber::bind(0) {
            Err(NflogError::Protocol(_)) => {}
            Err(other) => panic!("expected Protocol error for group 0; got {other:?}"),
            Ok(_) => panic!("group 0 must be rejected"),
        }
    }
}
