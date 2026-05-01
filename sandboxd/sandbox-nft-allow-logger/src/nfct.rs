//! NFCT receiver: subscribe to `NFNLGRP_CONNTRACK_NEW` and emit one
//! `allow` event per kernel-emitted message that carries a UDP flow.
//!
//! ## Why this exists
//!
//! `2026-05-01-udp-nft-loggers-design.md` Decision 3 closes the UDP
//! allow-flow audit gap. Allowed UDP traverses no userland datapath
//! under Decision 1 — the kernel `accept`s the packet at prerouting,
//! MASQUERADE rewrites the source on egress, and the datagram leaves
//! directly. The audit signal is the conntrack NEW-flow event the
//! kernel already emits on every new tracked flow: this binary
//! subscribes to that multicast stream, filters for UDP at parse
//! time, extracts the original-direction tuple, and writes one JSONL
//! `allow` record per flow.
//!
//! ## NFCT vs NFLOG: subscription model
//!
//! NFLOG (used by the deny-logger) requires a *three-step* explicit
//! handshake to register the socket as the per-group consumer:
//! `PF_BIND` (family) + `CMD_BIND` (group) + `CFG_MODE` (copy
//! range). Without those messages the kernel never routes packet
//! notifications to the socket.
//!
//! NFCT (this binary) is *multicast* on the netlink socket's
//! `nl_groups` bitmask — a single `bind()` with the right group bit
//! set is enough. There is no PF_BIND, no per-group CMD_BIND, no
//! mode handshake. The kernel broadcasts every CT-NEW message to
//! every socket subscribed to the group; per-message filtering
//! (UDP-only) happens here at parse time.
//!
//! `NFNLGRP_CONNTRACK_NEW` is enum value `1` in
//! `linux/netfilter/nfnetlink.h`; the netlink socket subscribes via
//! `nl_groups = 1 << (NFNLGRP_CONNTRACK_NEW - 1) = 1 << 0 = 1`.
//!
//! ## Wire shape (`IPCTNL_MSG_CT_NEW`)
//!
//! Each kernel-emitted message is an `nlmsghdr` whose 16-bit type
//! field splits into `(NFNL_SUBSYS_CTNETLINK << 8) |
//! IPCTNL_MSG_CT_NEW` (subsystem `1`, message `0`), followed by a
//! `nfgenmsg` header (`family / version / res_id`), then a sequence
//! of TLV attributes. The ones we care about:
//!
//! - `CTA_TUPLE_ORIG` (1, nested) → original-direction 5-tuple. Per
//!   `enum ctattr_tuple` (UAPI):
//!     - `CTA_TUPLE_IP` (1, nested) →
//!         - `CTA_IP_V4_SRC` (1) — `__be32` source IPv4
//!         - `CTA_IP_V4_DST` (2) — `__be32` destination IPv4
//!     - `CTA_TUPLE_PROTO` (2, nested) →
//!         - `CTA_PROTO_NUM` (1) — `u8` IP protocol (17 = UDP)
//!         - `CTA_PROTO_SRC_PORT` (2) — `__be16` source port
//!         - `CTA_PROTO_DST_PORT` (3) — `__be16` destination port
//!
//! Other top-level attributes (`CTA_TUPLE_REPLY`, `CTA_STATUS`,
//! `CTA_TIMEOUT`, `CTA_MARK`, `CTA_ID`, …) are ignored — the allow
//! event only needs the original-direction 5-tuple.
//!
//! Wire format is stable kernel UAPI documented in
//! `linux/netfilter/nfnetlink_conntrack.h` and
//! `linux/netfilter/nfnetlink.h`.
//!
//! ## NLA flag masking
//!
//! Per `linux/netlink.h`:
//!   - `NLA_F_NESTED        = 0x8000` — set on nested-attribute
//!     types. Conntrack tuples set this on `CTA_TUPLE_ORIG`,
//!     `CTA_TUPLE_REPLY`, `CTA_TUPLE_IP`, `CTA_TUPLE_PROTO`. Older
//!     kernels did not always set it consistently — defensively
//!     mask before comparing the type code.
//!   - `NLA_F_NET_BYTEORDER = 0x4000` — set when the attribute
//!     value is in network byte order. The conntrack subsystem sets
//!     it on `CTA_PROTO_SRC_PORT`, `CTA_PROTO_DST_PORT`,
//!     `CTA_IP_V4_SRC`, `CTA_IP_V4_DST`. Mask before comparing.
//!
//! `NLA_TYPE_MASK = ~(NLA_F_NESTED | NLA_F_NET_BYTEORDER)` is the
//! defensive idiom (the deny-logger's NFLOG parser uses the
//! identical mask).
//!
//! ## NEW-only filtering
//!
//! The subscription is `NFNLGRP_CONNTRACK_NEW`, not the
//! `NFNLGRP_CONNTRACK_UPDATE` or `NFNLGRP_CONNTRACK_DESTROY`
//! groups, so the kernel only pushes `IPCTNL_MSG_CT_NEW` messages
//! to this socket — no UPDATE / DELETE / GET_DYING noise. We
//! defensively check the message type anyway so a future kernel
//! that re-uses the same multicast group for a new message kind
//! does not silently feed us wrong events.
//!
//! ## Async / blocking
//!
//! The receive loop blocks on `recv` inside
//! `tokio::task::spawn_blocking` (CLAUDE.md convention) so the
//! netlink syscall doesn't park a worker thread of the runtime
//! under sustained traffic. The hot path is single-threaded by
//! design; the sender is the kernel and the consumer is one task.
//!
//! ## 30-second-rollover (documented elsewhere)
//!
//! Kernel sysctl `net.netfilter.nf_conntrack_udp_timeout` (default
//! 30 s) ages out a UDP flow that goes silent; the next packet on
//! the same 5-tuple creates a new conntrack entry and triggers a
//! second `IPCTNL_MSG_CT_NEW` event. We will emit two allow records
//! for what an operator might call "one session." This is a
//! property of UDP-via-conntrack, not a bug. Documented in spec
//! Decision 3 and the troubleshooting docs; no test asserts it
//! (would require either a fast-clock harness or a 30 s sleep,
//! both undesirable).

use std::io;
use std::net::Ipv4Addr;
use std::os::fd::{AsRawFd, RawFd};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use chrono::Utc;
use netlink_sys::{Socket, SocketAddr, protocols::NETLINK_NETFILTER};
use thiserror::Error;

use sandbox_event_emitter::{Admit, AllowRecord, EventEmitter, Protocol, RateCap};

// -----------------------------------------------------------------------------
// Wire-format constants. Mirror `linux/netfilter/nfnetlink.h` and
// `linux/netfilter/nfnetlink_conntrack.h` (UAPI; stable kernel ABI).
// -----------------------------------------------------------------------------

/// Netfilter subsystem byte for CTNETLINK (conntrack subsystem).
const NFNL_SUBSYS_CTNETLINK: u8 = 1;

/// `IPCTNL_MSG_CT_NEW` — top-level message type for "new conntrack
/// entry" notifications. Multicast-broadcast on
/// `NFNLGRP_CONNTRACK_NEW`.
const IPCTNL_MSG_CT_NEW: u8 = 0;

// CTA_* — top-level attributes inside an `IPCTNL_MSG_CT_*` message.
// Kept here as `pub(crate)` instead of `const` private so test bodies
// can reference them when synthesising wire fixtures.
/// `CTA_TUPLE_ORIG` — nested, holds the original-direction 5-tuple.
const CTA_TUPLE_ORIG: u16 = 1;
// (CTA_TUPLE_REPLY = 2, CTA_STATUS = 3, … unused.)

// Inside `CTA_TUPLE_ORIG` (nested):
/// `CTA_TUPLE_IP` — nested IP-family addresses.
const CTA_TUPLE_IP: u16 = 1;
/// `CTA_TUPLE_PROTO` — nested L4 protocol info.
const CTA_TUPLE_PROTO: u16 = 2;

// Inside `CTA_TUPLE_IP` (nested):
/// `CTA_IP_V4_SRC` — `__be32` IPv4 source.
const CTA_IP_V4_SRC: u16 = 1;
/// `CTA_IP_V4_DST` — `__be32` IPv4 destination.
const CTA_IP_V4_DST: u16 = 2;

// Inside `CTA_TUPLE_PROTO` (nested):
/// `CTA_PROTO_NUM` — `u8` IP protocol number (UDP = 17).
const CTA_PROTO_NUM: u16 = 1;
/// `CTA_PROTO_SRC_PORT` — `__be16` source port.
const CTA_PROTO_SRC_PORT: u16 = 2;
/// `CTA_PROTO_DST_PORT` — `__be16` destination port.
const CTA_PROTO_DST_PORT: u16 = 3;

/// `NLA_F_NESTED` bit on attribute types. Mask out before comparing.
const NLA_F_NESTED: u16 = 0x8000;
/// `NLA_F_NET_BYTEORDER` bit on attribute types. Mask out before
/// comparing — see module docs.
const NLA_F_NET_BYTEORDER: u16 = 0x4000;
const NLA_TYPE_MASK: u16 = !(NLA_F_NESTED | NLA_F_NET_BYTEORDER);

/// netlink message header size.
const NLMSG_HDR_LEN: usize = 16;
/// nfgenmsg header size: family u8 + version u8 + res_id u16be.
const NFGEN_HDR_LEN: usize = 4;

/// IP protocol number for UDP. Per Decision 3, we filter the NFCT
/// stream for UDP at parse time; non-UDP flows (TCP especially —
/// Envoy already audits TCP) are silently skipped.
const IPPROTO_UDP: u8 = 17;

/// `NFNLGRP_CONNTRACK_NEW` is enum value 1; bind via
/// `nl_groups = 1 << (NFNLGRP_CONNTRACK_NEW - 1) = 0x1`. See module
/// docs for the multicast vs PF_BIND distinction.
const NL_GROUPS_CONNTRACK_NEW: u32 = 0x0000_0001;

// -----------------------------------------------------------------------------
// Diagnostics counters. Process-wide; the allow-logger is per-session
// (one process per gateway container).
// -----------------------------------------------------------------------------

/// NFCT messages successfully parsed and emitted as allow events.
static NFCT_EMITTED: AtomicU64 = AtomicU64::new(0);
/// NFCT messages skipped (non-UDP flow, missing attributes, malformed).
static NFCT_SKIPPED: AtomicU64 = AtomicU64::new(0);
/// NFCT messages rejected by the parser (truncated, attr length out of
/// bounds — wire-shape violations, distinct from "skipped" for
/// operator-debugging purposes).
static NFCT_PARSE_ERRORS: AtomicU64 = AtomicU64::new(0);

/// Snapshot of `NFCT_EMITTED`. Read by the binary's `/health` body
/// builder (`main.rs::run`) so operators see the cumulative count of
/// NFCT messages successfully turned into `allow` events without
/// scraping logs.
///
/// `pub(crate)` because the only caller is `main.rs`'s closure
/// passed into `health::run`; binary-crate items cannot be reached
/// from outside the crate, so a plain `pub` would be misleading.
pub(crate) fn emitted() -> u64 {
    NFCT_EMITTED.load(Ordering::Relaxed)
}

/// Snapshot of `NFCT_SKIPPED`. Same `/health` consumer as
/// [`emitted`]. Skips are normal high-volume traffic on the
/// multicast socket — TCP CT-NEW arrives here too and is filtered
/// out at parse time — so this counter is informational rather than
/// alerting.
pub(crate) fn skipped() -> u64 {
    NFCT_SKIPPED.load(Ordering::Relaxed)
}

/// Snapshot of `NFCT_PARSE_ERRORS`. Same `/health` consumer as
/// [`emitted`]; non-zero values signal wire-shape violations
/// (truncated nlmsg lengths, attribute-length mismatches) that
/// operator tooling should surface.
pub(crate) fn parse_errors() -> u64 {
    NFCT_PARSE_ERRORS.load(Ordering::Relaxed)
}

// -----------------------------------------------------------------------------
// Errors.
// -----------------------------------------------------------------------------

#[derive(Debug, Error)]
pub enum NfctError {
    #[error("nfct i/o: {0}")]
    Io(#[from] io::Error),
    #[error("nfct protocol error: {0}")]
    Protocol(String),
}

// -----------------------------------------------------------------------------
// Subscriber handle.
// -----------------------------------------------------------------------------

/// Owns the netlink socket subscribed to `NFNLGRP_CONNTRACK_NEW`.
pub struct NfctSubscriber {
    socket: Socket,
}

impl NfctSubscriber {
    /// Open a `NETLINK_NETFILTER` socket and subscribe to the
    /// conntrack-NEW multicast group.
    ///
    /// Unlike NFLOG, NFCT does not require a configuration handshake:
    /// the kernel multicasts CT events to every socket whose
    /// `nl_groups` bitmask includes `NFNLGRP_CONNTRACK_NEW`. We bind
    /// once with `nl_groups = 0x1` and immediately start receiving.
    ///
    /// Requires `CAP_NET_ADMIN` — present in the gateway container by
    /// virtue of `--cap-add NET_ADMIN` (audit §2.4). The conntrack
    /// subsystem is loaded by the existing gateway-container netlink
    /// setup.
    pub fn bind() -> Result<Self, NfctError> {
        let mut socket = Socket::new(NETLINK_NETFILTER)?;
        // Bump the receive buffer for the same reason the deny-logger
        // does (NFLOG): a high-fan-out workload can deliver bursts
        // larger than the default `net.core.rmem_default` window. 4
        // MiB matches the deny-logger and is well within
        // `net.core.rmem_max` on stock kernels.
        socket.set_rx_buf_sz(4 * 1024 * 1024)?;
        // pid=0 → kernel auto-assigns; `nl_groups = 0x1` subscribes
        // to `NFNLGRP_CONNTRACK_NEW`. No PF_BIND, no per-group
        // CMD_BIND — multicast model.
        socket.bind(&SocketAddr::new(0, NL_GROUPS_CONNTRACK_NEW))?;

        Ok(Self { socket })
    }

    /// Receive one or more `IPCTNL_MSG_CT_NEW` notifications. Returns
    /// every parsed allow record from the recv buffer; an empty
    /// `Vec` indicates the buffer held only non-UDP flows or
    /// malformed messages (caller loops without acting).
    pub fn recv_events(&mut self) -> Result<Vec<AllowRecord>, NfctError> {
        // 64 KiB recv buffer — same sizing rationale as the
        // deny-logger's NFLOG receiver.
        let mut buf = [0u8; 64 * 1024];
        let n = self.socket.recv(&mut &mut buf[..], 0)?;
        let bytes = &buf[..n];
        parse_all(bytes)
    }

    /// Underlying file descriptor.
    ///
    /// Used by the SIGTERM-driven clean-exit path in `main.rs`: the
    /// receive loop runs inside `tokio::task::spawn_blocking` and is
    /// parked in a kernel `recv` that tokio cancellation cannot
    /// interrupt. To exit promptly on SIGTERM the main task takes a
    /// snapshot of this fd before moving the subscriber into the
    /// blocking task, then calls [`shutdown_recv`] from the signal
    /// handler so the in-flight `recv` returns with EBADF / ENOTCONN
    /// / `n=0` and the loop drops out cleanly. Mirrors the
    /// deny-logger's `NflogSubscriber::as_raw_fd` plumbing.
    pub(crate) fn as_raw_fd(&self) -> RawFd {
        self.socket.as_raw_fd()
    }
}

/// Initiate clean exit by half-closing the netlink socket on `fd`.
///
/// Calls `shutdown(fd, SHUT_RDWR)`. On a netlink socket this causes
/// any pending `recv` to return — typically with `n=0` (graceful
/// peer-close semantics) or with `EBADF` if the fd was reaped between
/// the shutdown and the next syscall — letting the receive loop
/// observe the shutdown atomic and exit. Prefer this to a bare
/// `close(fd)`: `close` frees the fd while another thread may still
/// be holding it inside the recvmsg, opening a window for fd reuse
/// (a fresh socket bound to the same number) before the recv thread
/// notices. `shutdown` keeps the fd valid until the recv thread
/// drops the subscriber.
///
/// Soft-fail on error: the SIGTERM path never blocks on this — if
/// `shutdown` fails for any reason the kernel cleans up at process
/// exit anyway. Logged at `debug` so operators investigating slow
/// shutdowns can see the trace.
///
/// Mirrors `nflog::shutdown_recv` in the deny-logger.
pub(crate) fn shutdown_recv(fd: RawFd) {
    // SAFETY: `fd` is a snapshot taken from a live `NfctSubscriber`
    // before that subscriber was moved into the spawn_blocking task.
    // The fd may have been closed by a concurrent drop of the
    // subscriber — in which case `shutdown` returns `EBADF` which we
    // ignore. Calling shutdown on an open fd of any kind is a benign
    // operation; the failure path here is purely diagnostic.
    let rc = unsafe { libc::shutdown(fd, libc::SHUT_RDWR) };
    if rc != 0 {
        let err = io::Error::last_os_error();
        tracing::debug!(error = %err, "nfct shutdown(SHUT_RDWR) failed; relying on process-exit fd reap");
    }
}

// -----------------------------------------------------------------------------
// Receive loop.
// -----------------------------------------------------------------------------

/// Run the NFCT receive loop. Blocks the calling task; the caller
/// places this inside `tokio::task::spawn_blocking` per CLAUDE.md's
/// blocking-syscall convention.
///
/// Returns `Ok(())` when `shutdown` is set (clean SIGTERM exit driven
/// from `main.rs`'s signal handler — see [`shutdown_recv`]). Returns
/// an `Err` on unrecoverable I/O *not attributable to the shutdown
/// path*. Soft errors (parse failures, non-UDP flows) increment the
/// counters and continue the loop.
///
/// ## Shutdown contract
///
/// The blocking `recv` cannot be cancelled by tokio. The SIGTERM
/// exit path in `main.rs` therefore:
///
/// 1. Sets `shutdown` to `true`.
/// 2. Calls [`shutdown_recv`] on the netlink fd, which causes any
///    in-flight `recvmsg` to return with `n=0` / `EBADF` /
///    `ENOTCONN`.
/// 3. The recv loop observes the post-syscall outcome, sees the
///    `shutdown` flag, and returns `Ok(())`.
///
/// Goal: exit within ~1 second of SIGTERM rather than relying on
/// the 10-second SIGKILL escalation in the gateway entrypoint.
pub fn run_blocking(
    mut subscriber: NfctSubscriber,
    emitter: Arc<EventEmitter>,
    rate_cap: Arc<RateCap>,
    shutdown: Arc<AtomicBool>,
) -> Result<(), NfctError> {
    loop {
        // Cheap pre-check so a `shutdown` flip that happened *between*
        // recvs (no in-flight syscall to interrupt) still exits
        // promptly. The post-syscall arms below cover the in-flight
        // case via `shutdown_recv`'s socket half-close.
        if shutdown.load(Ordering::Acquire) {
            return Ok(());
        }
        match subscriber.recv_events() {
            Ok(records) => {
                if records.is_empty() && shutdown.load(Ordering::Acquire) {
                    return Ok(());
                }
                for record in records {
                    if rate_cap.try_admit(Utc::now()) == Admit::Ok {
                        emitter.emit_allow(record);
                        NFCT_EMITTED.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
            Err(NfctError::Io(err)) if err.kind() == io::ErrorKind::Interrupted => {
                continue;
            }
            Err(NfctError::Io(err)) if shutdown.load(Ordering::Acquire) => {
                tracing::debug!(error = %err, "nfct recv error during shutdown; exiting cleanly");
                return Ok(());
            }
            Err(NfctError::Io(err)) => {
                tracing::warn!(error = %err, "nfct recv failed");
                return Err(NfctError::Io(err));
            }
            Err(NfctError::Protocol(msg)) => {
                NFCT_PARSE_ERRORS.fetch_add(1, Ordering::Relaxed);
                tracing::debug!(reason = %msg, "nfct message dropped at parse");
            }
        }
    }
}

// -----------------------------------------------------------------------------
// Wire decode.
// -----------------------------------------------------------------------------

/// Parse every netlink message in a `recv` buffer, returning the
/// allow records extracted from `IPCTNL_MSG_CT_NEW` notifications.
/// Non-CT-NEW messages, non-UDP flows, and incomplete tuples are
/// silently skipped (counted into `NFCT_SKIPPED` rather than
/// surfaced as errors — the kernel's multicast stream legitimately
/// carries a mix of message kinds).
fn parse_all(mut buf: &[u8]) -> Result<Vec<AllowRecord>, NfctError> {
    let mut out = Vec::new();
    while buf.len() >= NLMSG_HDR_LEN {
        let len = u32::from_ne_bytes(buf[0..4].try_into().unwrap()) as usize;
        let nl_type = u16::from_ne_bytes(buf[4..6].try_into().unwrap());
        if len < NLMSG_HDR_LEN || len > buf.len() {
            return Err(NfctError::Protocol(format!(
                "nlmsghdr length out of bounds (len={len}, buf={})",
                buf.len()
            )));
        }
        let msg = &buf[..len];
        let next = aligned(len);

        let subsys = ((nl_type >> 8) & 0xFF) as u8;
        let kind = (nl_type & 0xFF) as u8;

        if subsys == NFNL_SUBSYS_CTNETLINK && kind == IPCTNL_MSG_CT_NEW {
            if msg.len() < NLMSG_HDR_LEN + NFGEN_HDR_LEN {
                return Err(NfctError::Protocol(
                    "ct-new msg too short for nfgenmsg header".into(),
                ));
            }
            let attrs = &msg[NLMSG_HDR_LEN + NFGEN_HDR_LEN..];
            match parse_ct_new_attrs(attrs) {
                Ok(Some(record)) => out.push(record),
                Ok(None) => {
                    NFCT_SKIPPED.fetch_add(1, Ordering::Relaxed);
                }
                Err(err) => {
                    NFCT_PARSE_ERRORS.fetch_add(1, Ordering::Relaxed);
                    tracing::debug!(error = %err, "nfct ct-new attr parse failed");
                }
            }
        } else {
            // Multicast group is NEW-only, but defensively count any
            // other message kind that arrives (a future kernel that
            // re-purposes the group, or a CT-NEW kernel bug, surfaces
            // here as a skip).
            NFCT_SKIPPED.fetch_add(1, Ordering::Relaxed);
        }

        if next >= buf.len() {
            break;
        }
        buf = &buf[next..];
    }
    Ok(out)
}

/// Walk top-level `CTA_*` attributes. We only care about
/// `CTA_TUPLE_ORIG`; all other attributes are skipped.
fn parse_ct_new_attrs(buf: &[u8]) -> Result<Option<AllowRecord>, NfctError> {
    let mut tuple_orig: Option<&[u8]> = None;
    for entry in AttrIter::new(buf) {
        let (attr_type, val) = entry?;
        if attr_type == CTA_TUPLE_ORIG {
            tuple_orig = Some(val);
        }
    }

    let Some(tuple_orig) = tuple_orig else {
        return Err(NfctError::Protocol(
            "CTA_TUPLE_ORIG missing on ct-new message".into(),
        ));
    };
    parse_tuple(tuple_orig)
}

/// Parse the `CTA_TUPLE_ORIG` nested block. Returns `Ok(None)` for
/// non-UDP flows (we filter at parse time per Decision 3 rationale).
fn parse_tuple(buf: &[u8]) -> Result<Option<AllowRecord>, NfctError> {
    let mut ip_block: Option<&[u8]> = None;
    let mut proto_block: Option<&[u8]> = None;
    for entry in AttrIter::new(buf) {
        let (attr_type, val) = entry?;
        match attr_type {
            CTA_TUPLE_IP => ip_block = Some(val),
            CTA_TUPLE_PROTO => proto_block = Some(val),
            _ => {}
        }
    }

    let ip_block = ip_block
        .ok_or_else(|| NfctError::Protocol("CTA_TUPLE_IP missing inside CTA_TUPLE_ORIG".into()))?;
    let proto_block = proto_block.ok_or_else(|| {
        NfctError::Protocol("CTA_TUPLE_PROTO missing inside CTA_TUPLE_ORIG".into())
    })?;

    // Parse the L4 proto first — if it isn't UDP, short-circuit
    // before bothering with the IPs (Decision 3: kernel emits CT-NEW
    // for every L4 protocol, we filter for UDP only).
    let (proto_num, src_port, dst_port) = parse_proto_block(proto_block)?;
    if proto_num != IPPROTO_UDP {
        return Ok(None);
    }
    // Both ports are required — IPv4 conntrack always carries them
    // for UDP/TCP. Missing port on a UDP CT-NEW is a kernel-side
    // anomaly worth surfacing, not silently skipping.
    let src_port = src_port
        .ok_or_else(|| NfctError::Protocol("CTA_PROTO_SRC_PORT missing on UDP ct-new".into()))?;
    let dst_port = dst_port
        .ok_or_else(|| NfctError::Protocol("CTA_PROTO_DST_PORT missing on UDP ct-new".into()))?;

    let (src_ip, dst_ip) = parse_ip_block(ip_block)?;

    Ok(Some(AllowRecord {
        orig_dst_ip: dst_ip,
        orig_dst_port: dst_port,
        protocol: Protocol::Udp,
        src_ip,
        src_port,
    }))
}

/// Parse the `CTA_TUPLE_IP` nested block. IPv6 entries are silently
/// ignored — the gateway is IPv4-only by design and conntrack still
/// emits CT-NEW with empty `CTA_IP_V*_*` attributes; surfacing IPv6
/// as a parse error would mask the IPv4 records on a dual-stack
/// host.
fn parse_ip_block(buf: &[u8]) -> Result<(Ipv4Addr, Ipv4Addr), NfctError> {
    let mut src: Option<Ipv4Addr> = None;
    let mut dst: Option<Ipv4Addr> = None;
    for entry in AttrIter::new(buf) {
        let (attr_type, val) = entry?;
        match attr_type {
            CTA_IP_V4_SRC if val.len() == 4 => {
                src = Some(Ipv4Addr::new(val[0], val[1], val[2], val[3]));
            }
            CTA_IP_V4_DST if val.len() == 4 => {
                dst = Some(Ipv4Addr::new(val[0], val[1], val[2], val[3]));
            }
            _ => {}
        }
    }
    let src = src.ok_or_else(|| NfctError::Protocol("CTA_IP_V4_SRC missing".into()))?;
    let dst = dst.ok_or_else(|| NfctError::Protocol("CTA_IP_V4_DST missing".into()))?;
    Ok((src, dst))
}

/// Parse the `CTA_TUPLE_PROTO` nested block. Returns
/// `(proto_num, src_port?, dst_port?)`; ports are returned as
/// `Option` so the caller can decide whether to require them based
/// on the protocol (UDP/TCP yes, ICMP no — different attributes).
fn parse_proto_block(buf: &[u8]) -> Result<(u8, Option<u16>, Option<u16>), NfctError> {
    let mut proto_num: Option<u8> = None;
    let mut src_port: Option<u16> = None;
    let mut dst_port: Option<u16> = None;
    for entry in AttrIter::new(buf) {
        let (attr_type, val) = entry?;
        match attr_type {
            CTA_PROTO_NUM if !val.is_empty() => proto_num = Some(val[0]),
            CTA_PROTO_SRC_PORT if val.len() == 2 => {
                src_port = Some(u16::from_be_bytes([val[0], val[1]]));
            }
            CTA_PROTO_DST_PORT if val.len() == 2 => {
                dst_port = Some(u16::from_be_bytes([val[0], val[1]]));
            }
            _ => {}
        }
    }
    let proto_num = proto_num.ok_or_else(|| NfctError::Protocol("CTA_PROTO_NUM missing".into()))?;
    Ok((proto_num, src_port, dst_port))
}

/// Iterator over a TLV attribute block. Yields `(masked_type, value)`
/// per attribute, surfacing wire-shape violations as an error item
/// (the iterator stops after the first error).
///
/// Type codes are pre-masked against `NLA_TYPE_MASK` so callers
/// compare against the bare attribute IDs without worrying about
/// the `NLA_F_NESTED` / `NLA_F_NET_BYTEORDER` flags. Handles the
/// 4-byte alignment padding between attributes.
///
/// Implemented as an iterator (rather than a closure-visitor) so the
/// borrow on the underlying buffer can flow through the for-loop's
/// item lifetime — a closure-visitor would require a HRTB on the
/// `FnMut` signature that conflicts with capturing local
/// `Option<&[u8]>` slots in the caller.
struct AttrIter<'a> {
    buf: &'a [u8],
    done: bool,
}

impl<'a> AttrIter<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, done: false }
    }
}

impl<'a> Iterator for AttrIter<'a> {
    type Item = Result<(u16, &'a [u8]), NfctError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done || self.buf.len() < 4 {
            return None;
        }
        let attr_len = u16::from_ne_bytes(self.buf[0..2].try_into().unwrap()) as usize;
        let attr_type_raw = u16::from_ne_bytes(self.buf[2..4].try_into().unwrap());
        let attr_type = attr_type_raw & NLA_TYPE_MASK;
        if attr_len < 4 || attr_len > self.buf.len() {
            self.done = true;
            return Some(Err(NfctError::Protocol(format!(
                "nlattr length out of bounds (len={attr_len}, buf={})",
                self.buf.len()
            ))));
        }
        let val = &self.buf[4..attr_len];
        let next = aligned(attr_len);
        if next >= self.buf.len() {
            self.done = true;
        } else {
            self.buf = &self.buf[next..];
        }
        Some(Ok((attr_type, val)))
    }
}

/// Round `n` up to the next 4-byte boundary. NLMSG / NLA payloads
/// are always 4-byte aligned; `NLMSG_ALIGN(n)` from
/// `linux/netlink.h`.
const fn aligned(n: usize) -> usize {
    (n + 3) & !3usize
}

// -----------------------------------------------------------------------------
// Tests.
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Append one nlattr (TLV) to `out`, padding to the 4-byte
    /// boundary. Test helper for synthesising NFCT wire fixtures.
    fn push_attr(out: &mut Vec<u8>, attr_type: u16, payload: &[u8]) {
        let attr_len = (4 + payload.len()) as u16;
        out.extend_from_slice(&attr_len.to_ne_bytes());
        out.extend_from_slice(&attr_type.to_ne_bytes());
        out.extend_from_slice(payload);
        while out.len() % 4 != 0 {
            out.push(0);
        }
    }

    /// Build a `CTA_TUPLE_PROTO` nested block carrying `(proto, src_port, dst_port)`.
    fn build_proto_block(proto: u8, src_port: u16, dst_port: u16) -> Vec<u8> {
        let mut out = Vec::new();
        // CTA_PROTO_NUM is a single byte; pad to 4 by `push_attr`.
        push_attr(&mut out, CTA_PROTO_NUM, &[proto]);
        push_attr(&mut out, CTA_PROTO_SRC_PORT, &src_port.to_be_bytes());
        push_attr(&mut out, CTA_PROTO_DST_PORT, &dst_port.to_be_bytes());
        out
    }

    /// Build a `CTA_TUPLE_IP` nested block carrying `(src, dst)` in
    /// IPv4 attributes.
    fn build_ip_block(src: Ipv4Addr, dst: Ipv4Addr) -> Vec<u8> {
        let mut out = Vec::new();
        push_attr(&mut out, CTA_IP_V4_SRC, &src.octets());
        push_attr(&mut out, CTA_IP_V4_DST, &dst.octets());
        out
    }

    /// Build a `CTA_TUPLE_ORIG` nested block. The `NLA_F_NESTED`
    /// flag bit is *not* set in this fixture so we exercise the
    /// "older kernels don't always set NLA_F_NESTED" defensive
    /// path; the parser must still recognise the attr by its bare
    /// type code (`NLA_TYPE_MASK`).
    fn build_tuple_orig(
        proto: u8,
        src: Ipv4Addr,
        src_port: u16,
        dst: Ipv4Addr,
        dst_port: u16,
    ) -> Vec<u8> {
        let ip_block = build_ip_block(src, dst);
        let proto_block = build_proto_block(proto, src_port, dst_port);
        let mut out = Vec::new();
        push_attr(&mut out, CTA_TUPLE_IP, &ip_block);
        push_attr(&mut out, CTA_TUPLE_PROTO, &proto_block);
        out
    }

    /// Wrap an attribute block in a complete `IPCTNL_MSG_CT_NEW`
    /// netlink message (nlmsghdr + nfgenmsg + attrs). Returns the
    /// raw bytes the parser sees out of `recv()`.
    fn build_ct_new_msg(attrs: &[u8]) -> Vec<u8> {
        let total_len = NLMSG_HDR_LEN + NFGEN_HDR_LEN + attrs.len();
        let mut msg = Vec::with_capacity(total_len);
        // nlmsghdr.
        msg.extend_from_slice(&(total_len as u32).to_ne_bytes());
        let nl_type: u16 = ((NFNL_SUBSYS_CTNETLINK as u16) << 8) | (IPCTNL_MSG_CT_NEW as u16);
        msg.extend_from_slice(&nl_type.to_ne_bytes());
        msg.extend_from_slice(&0u16.to_ne_bytes()); // flags
        msg.extend_from_slice(&0u32.to_ne_bytes()); // seq
        msg.extend_from_slice(&0u32.to_ne_bytes()); // pid
        // nfgenmsg.
        msg.push(libc::AF_INET as u8);
        msg.push(0); // NFNETLINK_V0
        msg.extend_from_slice(&0u16.to_be_bytes()); // res_id (unused on CT-NEW)
        msg.extend_from_slice(attrs);
        // Pad the message to the 4-byte boundary (parse_all uses
        // `aligned(len)` to find the next message boundary).
        while msg.len() % 4 != 0 {
            msg.push(0);
        }
        msg
    }

    #[test]
    fn aligned_rounds_up_to_4() {
        assert_eq!(aligned(0), 0);
        assert_eq!(aligned(1), 4);
        assert_eq!(aligned(3), 4);
        assert_eq!(aligned(4), 4);
        assert_eq!(aligned(20), 20);
    }

    /// End-to-end parse of a synthetic CT-NEW message carrying a UDP
    /// flow. Pins the original-direction tuple extraction, the
    /// `Protocol::Udp` discriminator, and the byte-order parse on
    /// the IPv4 + port fields.
    #[test]
    fn parse_one_extracts_5tuple_from_well_formed_udp_ct_new() {
        let mut attrs = Vec::new();
        let tuple = build_tuple_orig(
            IPPROTO_UDP,
            Ipv4Addr::new(10, 0, 0, 42),
            51234,
            Ipv4Addr::new(198, 51, 100, 7),
            123,
        );
        push_attr(&mut attrs, CTA_TUPLE_ORIG, &tuple);
        let msg = build_ct_new_msg(&attrs);

        let parsed = parse_all(&msg).expect("well-formed udp ct-new must parse");
        assert_eq!(parsed.len(), 1, "exactly one record from one ct-new msg");
        let record = &parsed[0];
        assert_eq!(record.src_ip, Ipv4Addr::new(10, 0, 0, 42));
        assert_eq!(record.src_port, 51_234);
        assert_eq!(record.orig_dst_ip, Ipv4Addr::new(198, 51, 100, 7));
        assert_eq!(record.orig_dst_port, 123);
        assert_eq!(record.protocol, Protocol::Udp);
    }

    /// Non-UDP flows (TCP especially — Envoy already audits TCP) are
    /// silently skipped. Per Decision 3 rationale: "kernel does the
    /// filtering for us — TCP NEW events would arrive too, but TCP
    /// has Envoy doing the equivalent logging — we don't want
    /// double-counting."
    #[test]
    fn parse_skips_tcp_ct_new_silently() {
        let mut attrs = Vec::new();
        const IPPROTO_TCP: u8 = 6;
        let tuple = build_tuple_orig(
            IPPROTO_TCP,
            Ipv4Addr::new(10, 0, 0, 42),
            55_123,
            Ipv4Addr::new(203, 0, 113, 5),
            443,
        );
        push_attr(&mut attrs, CTA_TUPLE_ORIG, &tuple);
        let msg = build_ct_new_msg(&attrs);

        let parsed = parse_all(&msg).expect("tcp ct-new must not error");
        assert!(
            parsed.is_empty(),
            "tcp flows must be silently skipped (no double-count vs Envoy)"
        );
    }

    /// `NLA_F_NESTED` and `NLA_F_NET_BYTEORDER` flags must be
    /// masked off before comparing the type code. Kernel sets these
    /// flags on the conntrack tuple attributes (NESTED on tuples,
    /// NET_BYTEORDER on the IPv4 + port leaf attrs); the parser
    /// must tolerate both forms — the kernel-emitted form (with
    /// flags) and the older form (without).
    #[test]
    fn parse_handles_nla_flag_bits_on_nested_attrs() {
        // Build a tuple where every nested type has NLA_F_NESTED
        // set, mirroring what real kernels emit. The leaf addr/port
        // attrs have NLA_F_NET_BYTEORDER set.
        let src = Ipv4Addr::new(10, 0, 0, 99);
        let dst = Ipv4Addr::new(192, 0, 2, 1);
        let src_port: u16 = 60_000;
        let dst_port: u16 = 53;

        let mut ip_block = Vec::new();
        push_attr(
            &mut ip_block,
            CTA_IP_V4_SRC | NLA_F_NET_BYTEORDER,
            &src.octets(),
        );
        push_attr(
            &mut ip_block,
            CTA_IP_V4_DST | NLA_F_NET_BYTEORDER,
            &dst.octets(),
        );

        let mut proto_block = Vec::new();
        push_attr(&mut proto_block, CTA_PROTO_NUM, &[IPPROTO_UDP]);
        push_attr(
            &mut proto_block,
            CTA_PROTO_SRC_PORT | NLA_F_NET_BYTEORDER,
            &src_port.to_be_bytes(),
        );
        push_attr(
            &mut proto_block,
            CTA_PROTO_DST_PORT | NLA_F_NET_BYTEORDER,
            &dst_port.to_be_bytes(),
        );

        let mut tuple = Vec::new();
        push_attr(&mut tuple, CTA_TUPLE_IP | NLA_F_NESTED, &ip_block);
        push_attr(&mut tuple, CTA_TUPLE_PROTO | NLA_F_NESTED, &proto_block);

        let mut attrs = Vec::new();
        push_attr(&mut attrs, CTA_TUPLE_ORIG | NLA_F_NESTED, &tuple);

        let msg = build_ct_new_msg(&attrs);
        let parsed = parse_all(&msg).expect("nested+netbyteorder flags must parse");
        assert_eq!(parsed.len(), 1, "must yield exactly one record");
        let record = &parsed[0];
        assert_eq!(record.src_ip, src);
        assert_eq!(record.src_port, src_port);
        assert_eq!(record.orig_dst_ip, dst);
        assert_eq!(record.orig_dst_port, dst_port);
        assert_eq!(record.protocol, Protocol::Udp);
    }

    /// Multi-message recv buffer: kernel coalescing under bursts can
    /// stuff multiple CT-NEW messages into a single skb. Parser
    /// must drain all of them, not just the first. Parallels the
    /// deny-logger's NFLOG multi-msg test.
    #[test]
    fn parse_drains_multi_msg_recv_buffer() {
        let mut attrs1 = Vec::new();
        push_attr(
            &mut attrs1,
            CTA_TUPLE_ORIG,
            &build_tuple_orig(
                IPPROTO_UDP,
                Ipv4Addr::new(10, 0, 0, 1),
                40000,
                Ipv4Addr::new(1, 1, 1, 1),
                53,
            ),
        );
        let mut attrs2 = Vec::new();
        push_attr(
            &mut attrs2,
            CTA_TUPLE_ORIG,
            &build_tuple_orig(
                IPPROTO_UDP,
                Ipv4Addr::new(10, 0, 0, 2),
                40001,
                Ipv4Addr::new(8, 8, 8, 8),
                53,
            ),
        );
        let mut combined = build_ct_new_msg(&attrs1);
        combined.extend(build_ct_new_msg(&attrs2));

        let parsed = parse_all(&combined).expect("multi-msg buffer must parse");
        assert_eq!(parsed.len(), 2, "must drain both ct-new messages");
        assert_eq!(parsed[0].src_ip, Ipv4Addr::new(10, 0, 0, 1));
        assert_eq!(parsed[1].src_ip, Ipv4Addr::new(10, 0, 0, 2));
    }

    /// Non-CT-NEW message kinds (e.g. spurious UPDATE on the same
    /// socket if a future kernel re-uses the multicast group) are
    /// silently skipped, not surfaced as parse errors. The skip
    /// counter increments so operators see the anomaly via
    /// diagnostics.
    #[test]
    fn parse_skips_unknown_message_type() {
        // Build an `IPCTNL_MSG_CT_DELETE`-like message (kind = 2)
        // with no attrs; parse_all should skip without erroring.
        const IPCTNL_MSG_CT_DELETE: u8 = 2;
        let mut msg = Vec::new();
        msg.extend_from_slice(&((NLMSG_HDR_LEN + NFGEN_HDR_LEN) as u32).to_ne_bytes());
        let nl_type: u16 = ((NFNL_SUBSYS_CTNETLINK as u16) << 8) | (IPCTNL_MSG_CT_DELETE as u16);
        msg.extend_from_slice(&nl_type.to_ne_bytes());
        msg.extend_from_slice(&0u16.to_ne_bytes());
        msg.extend_from_slice(&0u32.to_ne_bytes());
        msg.extend_from_slice(&0u32.to_ne_bytes());
        msg.push(libc::AF_INET as u8);
        msg.push(0);
        msg.extend_from_slice(&0u16.to_be_bytes());

        let parsed = parse_all(&msg).expect("unknown ct message must not error");
        assert!(parsed.is_empty(), "unknown ct kind yields no records");
    }

    /// Truncated nlmsghdr length surfaces as a protocol error, not a
    /// silent skip — wire-shape violation.
    #[test]
    fn parse_errors_on_truncated_nlmsg_length() {
        // length field claims 1024 bytes but buffer is only 16.
        let mut msg = vec![0u8; 16];
        msg[0..4].copy_from_slice(&1024u32.to_ne_bytes());
        let nl_type: u16 = ((NFNL_SUBSYS_CTNETLINK as u16) << 8) | (IPCTNL_MSG_CT_NEW as u16);
        msg[4..6].copy_from_slice(&nl_type.to_ne_bytes());

        let err = parse_all(&msg).unwrap_err();
        assert!(
            matches!(err, NfctError::Protocol(_)),
            "truncated nlmsg length must surface as Protocol error; got {err:?}"
        );
    }

    /// Pin the SIGTERM clean-exit contract: a thread blocked on
    /// `recv` against a Linux socket exits promptly when a peer
    /// thread calls `shutdown(fd, SHUT_RDWR)` on the same fd. We
    /// can't construct an `NfctSubscriber` in a unit test
    /// (`NETLINK_NETFILTER` bind needs `CAP_NET_ADMIN`), but the
    /// shutdown→recv-returns mechanism is a generic kernel-socket
    /// behaviour — we exercise it on a `socketpair(AF_UNIX)` so the
    /// hermetic test suite can own the assertion. The
    /// `NfctSubscriber::shutdown_recv` callsite delegates to the
    /// same `libc::shutdown(fd, SHUT_RDWR)` syscall this test
    /// exercises. Mirrors the deny-logger's identically-named test.
    #[test]
    fn shutdown_unblocks_blocking_recv_within_one_second() {
        use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
        use std::sync::mpsc;
        use std::time::{Duration, Instant};

        let mut sv: [libc::c_int; 2] = [0; 2];
        let rc = unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, sv.as_mut_ptr()) };
        assert_eq!(rc, 0, "socketpair: {}", io::Error::last_os_error());
        // SAFETY: socketpair populated valid fds on success.
        let read_end = unsafe { OwnedFd::from_raw_fd(sv[0]) };
        let _write_end = unsafe { OwnedFd::from_raw_fd(sv[1]) };

        let read_fd = read_end.as_raw_fd();

        let (tx, rx) = mpsc::channel();
        let reader = std::thread::spawn(move || {
            let mut buf = [0u8; 16];
            // SAFETY: `read_fd` is owned by the moved `read_end`.
            let n = unsafe {
                libc::recv(
                    read_end.as_raw_fd(),
                    buf.as_mut_ptr().cast::<libc::c_void>(),
                    buf.len(),
                    0,
                )
            };
            tx.send((n, io::Error::last_os_error().raw_os_error()))
                .expect("send recv outcome");
        });

        std::thread::sleep(Duration::from_millis(50));

        let start = Instant::now();
        super::shutdown_recv(read_fd);

        let outcome = rx
            .recv_timeout(Duration::from_secs(1))
            .expect("recv must return within 1s of shutdown(SHUT_RDWR); SIGTERM contract violated");
        let elapsed = start.elapsed();
        assert!(
            elapsed < Duration::from_secs(1),
            "shutdown→recv-returns latency budget is 1s; got {elapsed:?}"
        );
        let (n, errno) = outcome;
        assert!(
            n == 0 || (n < 0 && errno.is_some()),
            "expected n=0 (graceful close) or n<0 with errno set; got n={n} errno={errno:?}"
        );
        reader.join().expect("reader thread");
    }
}
