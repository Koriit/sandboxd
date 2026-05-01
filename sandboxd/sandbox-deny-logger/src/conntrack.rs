//! Conntrack netlink lookup for UDP pre-DNAT destination recovery.
//!
//! ## Why this exists
//!
//! For TCP, `getsockopt(SOL_IP, SO_ORIGINAL_DST)` on the accepted socket
//! returns the pre-DNAT destination because the kernel threads the
//! conntrack entry through the socket fd. UDP has no per-flow fd — the
//! listener socket is shared by every datagram — and the kernel does
//! **not** surface the pre-DNAT destination via `IP_ORIGDSTADDR` for
//! conntrack-DNAT'd UDP. The `IP_ORIGDSTADDR` cmsg returns the
//! *post-DNAT, as-delivered* destination (the listener's own bind
//! address after PREROUTING DNAT rewrites the dst), which equals
//! `gateway_ip:10002` for every denied UDP datagram — useless for
//! attribution.
//!
//! The supported recovery path is the netfilter conntrack netlink
//! protocol (`NFNL_SUBSYS_CTNETLINK`). After PREROUTING DNAT runs,
//! conntrack records two tuples for the flow:
//!
//! - `ORIG`: `(src=vm_ip:vm_port, dst=pre_dnat_ip:pre_dnat_port)` — the
//!   datagram as the VM sent it.
//! - `REPLY`: `(src=gateway_ip:10002, dst=vm_ip:vm_port)` — the
//!   direction the kernel expects a reply from after DNAT mutated the
//!   destination.
//!
//! The deny-logger sees the post-DNAT 4-tuple at `recvmsg` time
//! (`(vm_ip:vm_port, gateway_ip:10002)`); the matching conntrack entry
//! is keyed on the REPLY direction. We send `IPCTNL_MSG_CT_GET` with a
//! `CTA_TUPLE_REPLY` payload and parse `CTA_TUPLE_ORIG` from the reply
//! to get the pre-DNAT destination.
//!
//! ## Crate choice
//!
//! `netlink-sys` (pure Rust, `rust-netlink` ecosystem) for the
//! netlink socket. The netfilter wire format
//! (`nfgenmsg + IPCTNL_MSG_CT_GET attributes`) is encoded by hand in
//! this file because:
//!
//! - The published `netlink-packet-netfilter v0.2.0` does not include
//!   conntrack support (only `nflog`); conntrack is on `main` only,
//!   unreleased. Pinning to a git rev for a security-sensitive crate
//!   adds supply-chain risk we'd rather avoid for ~200 lines of stable
//!   kernel-ABI emit/parse logic.
//! - The `nfct` / libnetfilter_conntrack C-FFI route would require
//!   pulling libmnl + libnetfilter_conntrack into the gateway image
//!   (`debian:bookworm-slim`), bloating it and adding a glibc-version
//!   coupling.
//! - The `conntrack` crate (rusty-bolt/conntrack-rs) only exposes
//!   `dump()` (full-table walk), unacceptable per-datagram cost.
//!
//! The netfilter wire format we depend on is documented in
//! `linux/netfilter/nfnetlink.h`, `linux/netfilter/nfnetlink_conntrack.h`,
//! and the Linux kernel sources; it's stable kernel ABI.
//!
//! ## Lifecycle
//!
//! One netlink socket is constructed at startup
//! ([`ConntrackLookup::new`]) and shared by the receive loop. The
//! socket is bound with `bind_auto` (kernel picks the port) and
//! connected to `(0, 0)` so subsequent `send`/`recv` need not specify
//! the peer. `CAP_NET_ADMIN` is required and is provided by the
//! gateway container's run flags (`gateway.rs`).
//!
//! Because the lookup is a single send + single recv per datagram and
//! the deny-logger's hot path is already serialised through a single
//! receive loop, the netlink socket itself is owned by that loop and
//! used synchronously — no per-call clone, no Mutex.
//!
//! ## Failure modes
//!
//! 1. **Conntrack entry GC'd** (unlikely for an in-flight datagram —
//!    the kernel installs the entry as part of the DNAT decision and
//!    keeps it for the UDP timeout, ~30s — but possible on a true
//!    race). Surfaced as `LookupError::NotFound`.
//! 2. **Kernel returned an error other than ENOENT.** Surfaced as
//!    `LookupError::Kernel`.
//! 3. **Netlink wire-protocol error** (truncation, unexpected
//!    payload). Surfaced as `LookupError::Protocol`.
//!
//! Caller (the UDP receive loop) treats all three as "fall back to
//! the post-DNAT tuple, log a warn, still emit the deny event so we
//! never lose a deny attribution".

use std::io;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::os::fd::{AsRawFd, RawFd};
use std::sync::atomic::{AtomicU64, Ordering};

use netlink_sys::{Socket, SocketAddr, protocols::NETLINK_NETFILTER};
use thiserror::Error;

// -----------------------------------------------------------------------------
// Wire-format constants.
//
// These mirror the Linux kernel UAPI headers
// (`linux/netfilter/nfnetlink.h` and
// `linux/netfilter/nfnetlink_conntrack.h`). Stable kernel ABI; no
// reason to expect drift across kernel versions.
// -----------------------------------------------------------------------------

/// `NFNL_SUBSYS_CTNETLINK` — netfilter subsystem byte for conntrack.
const NFNL_SUBSYS_CTNETLINK: u8 = 1;

/// `IPCTNL_MSG_CT_NEW` — kernel reply message type when an entry is
/// returned (the kernel re-uses NEW for both unsolicited new-entry
/// notifications and as the reply payload to a CT_GET).
const IPCTNL_MSG_CT_NEW: u8 = 0;

/// `IPCTNL_MSG_CT_GET` — request type: look up a single entry by tuple.
const IPCTNL_MSG_CT_GET: u8 = 1;

/// `NFPROTO_IPV4` — netfilter protocol family for IPv4. Goes in the
/// `nfgenmsg.family` field of every netfilter request.
const NFPROTO_IPV4: u8 = 2;

/// Top-level conntrack attribute: original-direction tuple.
const CTA_TUPLE_ORIG: u16 = 1;
/// Top-level conntrack attribute: reply-direction tuple. We send the
/// REPLY tuple in the request to look up entries by their post-DNAT
/// 4-tuple.
const CTA_TUPLE_REPLY: u16 = 2;

/// Nested attribute inside `CTA_TUPLE_*`: the IP-layer sub-tuple.
const CTA_TUPLE_IP: u16 = 1;
/// Nested attribute inside `CTA_TUPLE_*`: the L4 sub-tuple.
const CTA_TUPLE_PROTO: u16 = 2;

/// IP-tuple attribute: IPv4 source address.
const CTA_IP_V4_SRC: u16 = 1;
/// IP-tuple attribute: IPv4 destination address.
const CTA_IP_V4_DST: u16 = 2;

/// Proto-tuple attribute: L4 protocol number (e.g. IPPROTO_UDP).
const CTA_PROTO_NUM: u16 = 1;
/// Proto-tuple attribute: L4 source port.
const CTA_PROTO_SRC_PORT: u16 = 2;
/// Proto-tuple attribute: L4 destination port.
const CTA_PROTO_DST_PORT: u16 = 3;

/// `NLA_F_NESTED` — bit OR'd into the attribute type to signal a
/// nested attribute (a TLV containing other TLVs). Conntrack uses this
/// for `CTA_TUPLE_*` and the IP/PROTO sub-tuples.
const NLA_F_NESTED: u16 = 0x8000;

/// `NLA_F_NET_BYTEORDER` — second high bit. Signals that the
/// attribute payload is in network byte order (big-endian) rather than
/// host byte order. Current upstream kernel conntrack emitters use
/// `nla_put_be*` helpers which do **not** set this flag, but a kernel
/// build that flips it on (distro patches, future hardening) would
/// otherwise silently regress lookups: the type comparison would miss
/// and the parser would report `CTA_TUPLE_ORIG missing IPv4 dst`.
/// Mask it out before any type comparison.
const NLA_F_NET_BYTEORDER: u16 = 0x4000;

/// Mask matching the kernel's `NLA_TYPE_MASK` from
/// `<linux/netlink.h>` (UAPI):
/// `#define NLA_TYPE_MASK ~(NLA_F_NESTED | NLA_F_NET_BYTEORDER)`.
/// Use this when comparing a raw `attr_type` against an attribute
/// constant to be robust to the kernel emitting either flag.
const NLA_TYPE_MASK: u16 = !(NLA_F_NESTED | NLA_F_NET_BYTEORDER);

// Netlink message header constants.
const NLMSG_NOOP: u16 = 1;
const NLMSG_ERROR: u16 = 2;
const NLMSG_DONE: u16 = 3;

const NLM_F_REQUEST: u16 = 1;
/// Used only by the unit-test suite to assert we deliberately do *not*
/// request acks. See the rationale in `build_get_request`.
#[cfg(test)]
const NLM_F_ACK: u16 = 4;

/// `nlmsghdr` size in bytes.
const NLMSG_HDR_LEN: usize = 16;
/// `nfgenmsg` size in bytes (family u8 + version u8 + res_id u16be).
const NFGEN_HDR_LEN: usize = 4;

/// Counter for conntrack lookup misses (race / GC). Read by tests and
/// could be wired to a future `/health` field. Process-wide because the
/// deny-logger is per-session (one process per gateway container).
static CONNTRACK_LOOKUP_MISSES: AtomicU64 = AtomicU64::new(0);

/// Snapshot of the lookup-miss counter. For diagnostic use; not part
/// of the wire protocol. Currently no consumer in-tree; will be wired
/// to `/health` JSON in M12-S2 when the operator surface is broadened.
#[allow(dead_code)]
pub fn lookup_misses() -> u64 {
    CONNTRACK_LOOKUP_MISSES.load(Ordering::Relaxed)
}

/// Error category for a single conntrack lookup.
#[derive(Debug, Error)]
pub enum LookupError {
    /// Kernel responded with `-ENOENT` — no conntrack entry matches the
    /// requested REPLY tuple. Race between datagram arrival and
    /// conntrack GC.
    #[error("conntrack entry not found")]
    NotFound,
    /// Kernel responded with a non-ENOENT error.
    #[error("conntrack kernel error: errno={0}")]
    Kernel(i32),
    /// Wire-protocol error: truncated reply, missing required NLA,
    /// unexpected payload type, etc.
    #[error("conntrack protocol error: {0}")]
    Protocol(String),
    /// I/O error on the netlink socket itself.
    #[error("conntrack i/o: {0}")]
    Io(#[from] io::Error),
}

/// One-time-init netlink lookup handle used by the UDP receive loop.
///
/// Owns a `NETLINK_NETFILTER` socket bound at startup. Not `Clone` and
/// not `Sync` — single-owner, single-threaded use only.
pub struct ConntrackLookup {
    socket: Socket,
}

impl ConntrackLookup {
    /// Open and bind a `NETLINK_NETFILTER` socket. Requires
    /// `CAP_NET_ADMIN` — present in the gateway container by virtue
    /// of `--cap-add NET_ADMIN`.
    ///
    /// Errors here are fatal: if conntrack lookup is unavailable, the
    /// deny-logger has no way to recover the pre-DNAT tuple and would
    /// silently regress to the post-DNAT bug. Bubble up so the process
    /// exits non-zero and Docker's HEALTHCHECK flips the container
    /// unhealthy.
    pub fn new() -> io::Result<Self> {
        let mut socket = Socket::new(NETLINK_NETFILTER)?;
        socket.bind_auto()?;
        socket.connect(&SocketAddr::new(0, 0))?;
        Ok(Self { socket })
    }

    /// Recover the pre-DNAT destination for a UDP flow.
    ///
    /// `post_dnat_src` is what `recvmsg` reported as the datagram's
    /// peer (the VM's `(ip, port)`); `post_dnat_dst` is the listener's
    /// own bind address (`gateway_ip:10002`). The kernel keys
    /// conntrack on the REPLY tuple `(post_dnat_dst → post_dnat_src)`,
    /// so we send a `CT_GET` with `CTA_TUPLE_REPLY` populated and
    /// parse `CTA_TUPLE_ORIG.dst` from the reply.
    ///
    /// On success returns the pre-DNAT destination as a `SocketAddrV4`.
    pub fn lookup_pre_dnat_dst(
        &mut self,
        post_dnat_src: SocketAddrV4,
        post_dnat_dst: SocketAddrV4,
    ) -> Result<SocketAddrV4, LookupError> {
        let req = build_get_request(post_dnat_src, post_dnat_dst);
        self.socket.send(&req, 0)?;

        // Conntrack reply payload + netlink header is a few hundred
        // bytes for an IPv4/UDP entry; 4096 is generous.
        let mut rx_buf = vec![0u8; 4096];
        let n = self.socket.recv(&mut &mut rx_buf[..], 0)?;
        let rx = &rx_buf[..n];

        match parse_ct_reply(rx)? {
            CtReply::Entry(orig_dst) => Ok(orig_dst),
            CtReply::NotFound => {
                CONNTRACK_LOOKUP_MISSES.fetch_add(1, Ordering::Relaxed);
                Err(LookupError::NotFound)
            }
            CtReply::Kernel(errno) => Err(LookupError::Kernel(errno)),
        }
    }
}

impl AsRawFd for ConntrackLookup {
    fn as_raw_fd(&self) -> RawFd {
        self.socket.as_raw_fd()
    }
}

/// Build the `IPCTNL_MSG_CT_GET` request bytes keyed on the REPLY
/// tuple of the post-DNAT flow.
fn build_get_request(post_dnat_src: SocketAddrV4, post_dnat_dst: SocketAddrV4) -> Vec<u8> {
    // Build the inner CTA_TUPLE_REPLY payload first; we need its
    // length before we can emit the outer attribute header.
    let ip_tuple = build_ip_tuple_v4(*post_dnat_dst.ip(), *post_dnat_src.ip());
    let proto_tuple = build_proto_tuple_udp(post_dnat_dst.port(), post_dnat_src.port());

    let mut tuple_payload = Vec::with_capacity(ip_tuple.len() + proto_tuple.len());
    tuple_payload.extend_from_slice(&ip_tuple);
    tuple_payload.extend_from_slice(&proto_tuple);

    let mut tuple_attr = emit_nla(CTA_TUPLE_REPLY | NLA_F_NESTED, &tuple_payload);

    // Compose the netfilter payload: nfgenmsg + attributes.
    let mut nf_payload = Vec::with_capacity(NFGEN_HDR_LEN + tuple_attr.len());
    nf_payload.extend_from_slice(&[NFPROTO_IPV4, 0, 0, 0]); // family, version=0, res_id=0 (BE u16)
    nf_payload.append(&mut tuple_attr);

    // Wrap in the netlink header.
    let total_len = NLMSG_HDR_LEN + nf_payload.len();
    let mut nl_buf = Vec::with_capacity(total_len);
    nl_buf.extend_from_slice(&(total_len as u32).to_ne_bytes());
    let nlmsg_type = ((NFNL_SUBSYS_CTNETLINK as u16) << 8) | (IPCTNL_MSG_CT_GET as u16);
    nl_buf.extend_from_slice(&nlmsg_type.to_ne_bytes());
    // NLM_F_REQUEST only — *not* NLM_F_ACK. With NLM_F_ACK the kernel
    // sends a separate NLMSG_ERROR(errno=0) ack frame after a
    // successful CT_GET reply; the next lookup's `recv()` would then
    // pull that stale ack instead of its own response, corrupting the
    // pipeline. On a CT_GET miss the kernel sends NLMSG_ERROR(errno=
    // -ENOENT) regardless of whether NLM_F_ACK was set, so dropping
    // the flag costs nothing.
    let flags = NLM_F_REQUEST;
    nl_buf.extend_from_slice(&flags.to_ne_bytes());
    // seq=0 — we do single-request/single-reply on a connected socket
    // so seq matching isn't needed.
    nl_buf.extend_from_slice(&0u32.to_ne_bytes());
    // pid=0 — the kernel treats this as "let kernel fill in"; OK on a
    // connected socket.
    nl_buf.extend_from_slice(&0u32.to_ne_bytes());
    nl_buf.extend_from_slice(&nf_payload);
    nl_buf
}

/// Emit a netlink attribute (TLV): `len(u16le) | type(u16le) | value | pad`.
/// The header itself counts toward `len`. Pad to 4-byte boundary at the
/// end (alignment is implicit in the header, but the payload start of
/// the next attribute must be aligned).
fn emit_nla(attr_type: u16, value: &[u8]) -> Vec<u8> {
    let header_len = 4u16; // u16 length + u16 type
    let total_len = header_len + value.len() as u16;
    let padded_len = ((total_len as usize + 3) & !3) - total_len as usize;
    let mut out = Vec::with_capacity(total_len as usize + padded_len);
    out.extend_from_slice(&total_len.to_ne_bytes());
    out.extend_from_slice(&attr_type.to_ne_bytes());
    out.extend_from_slice(value);
    out.extend(std::iter::repeat_n(0u8, padded_len));
    out
}

/// Build a `CTA_TUPLE_IP` (nested) attribute carrying IPv4 src + dst.
fn build_ip_tuple_v4(src: Ipv4Addr, dst: Ipv4Addr) -> Vec<u8> {
    let src_attr = emit_nla(CTA_IP_V4_SRC, &src.octets());
    let dst_attr = emit_nla(CTA_IP_V4_DST, &dst.octets());
    let mut payload = Vec::with_capacity(src_attr.len() + dst_attr.len());
    payload.extend_from_slice(&src_attr);
    payload.extend_from_slice(&dst_attr);
    emit_nla(CTA_TUPLE_IP | NLA_F_NESTED, &payload)
}

/// Build a `CTA_TUPLE_PROTO` (nested) attribute carrying UDP +
/// src/dst ports. Ports are big-endian on the wire (network byte
/// order).
fn build_proto_tuple_udp(src_port: u16, dst_port: u16) -> Vec<u8> {
    // NLA payload for u8 PROTO_NUM is 1 byte but the value field is
    // padded to 4 bytes by `emit_nla`'s alignment logic. The kernel
    // only inspects the first byte.
    let proto = emit_nla(CTA_PROTO_NUM, &[libc::IPPROTO_UDP as u8]);
    let sport = emit_nla(CTA_PROTO_SRC_PORT, &src_port.to_be_bytes());
    let dport = emit_nla(CTA_PROTO_DST_PORT, &dst_port.to_be_bytes());
    let mut payload = Vec::with_capacity(proto.len() + sport.len() + dport.len());
    payload.extend_from_slice(&proto);
    payload.extend_from_slice(&sport);
    payload.extend_from_slice(&dport);
    emit_nla(CTA_TUPLE_PROTO | NLA_F_NESTED, &payload)
}

/// Internal classification of a kernel reply.
enum CtReply {
    Entry(SocketAddrV4),
    NotFound,
    Kernel(i32),
}

/// Parse the kernel reply: either an `IPCTNL_MSG_CT_NEW` payload
/// carrying the entry, or an `NLMSG_ERROR` carrying an errno.
fn parse_ct_reply(buf: &[u8]) -> Result<CtReply, LookupError> {
    if buf.len() < NLMSG_HDR_LEN {
        return Err(LookupError::Protocol(format!(
            "netlink reply truncated: {} bytes",
            buf.len()
        )));
    }
    let len = u32::from_ne_bytes(buf[0..4].try_into().unwrap()) as usize;
    let nlmsg_type = u16::from_ne_bytes(buf[4..6].try_into().unwrap());
    if len > buf.len() {
        return Err(LookupError::Protocol(format!(
            "netlink reply length ({len}) exceeds buffer ({})",
            buf.len()
        )));
    }

    if nlmsg_type == NLMSG_ERROR {
        // NLMSG_ERROR payload begins with a 32-bit signed errno (which
        // is 0 for "ack" — a successful CT_GET wouldn't normally take
        // this branch since the kernel returns the entry directly).
        if len < NLMSG_HDR_LEN + 4 {
            return Err(LookupError::Protocol(
                "netlink error message too short".to_string(),
            ));
        }
        let errno = i32::from_ne_bytes(buf[NLMSG_HDR_LEN..NLMSG_HDR_LEN + 4].try_into().unwrap());
        if errno == 0 {
            // Pure ack with no preceding entry — caller asked for an
            // entry but the kernel said "OK, here's nothing". Treat
            // as NotFound.
            return Ok(CtReply::NotFound);
        }
        if errno == -libc::ENOENT {
            return Ok(CtReply::NotFound);
        }
        return Ok(CtReply::Kernel(-errno));
    }

    if nlmsg_type == NLMSG_DONE || nlmsg_type == NLMSG_NOOP {
        // Unexpected for a single-tuple CT_GET — should not reach
        // here on a successful entry response.
        return Err(LookupError::Protocol(format!(
            "unexpected netlink message type {nlmsg_type}"
        )));
    }

    // Otherwise this should be a netfilter conntrack reply: the high
    // byte is the subsystem (CTNETLINK = 1) and the low byte is
    // IPCTNL_MSG_CT_NEW. Validate before parsing further.
    let subsys = (nlmsg_type >> 8) as u8;
    let inner_type = nlmsg_type as u8;
    if subsys != NFNL_SUBSYS_CTNETLINK {
        return Err(LookupError::Protocol(format!(
            "unexpected netfilter subsystem: {subsys}"
        )));
    }
    if inner_type != IPCTNL_MSG_CT_NEW && inner_type != IPCTNL_MSG_CT_GET {
        return Err(LookupError::Protocol(format!(
            "unexpected conntrack message type: {inner_type}"
        )));
    }

    let payload_start = NLMSG_HDR_LEN + NFGEN_HDR_LEN;
    if len < payload_start {
        return Err(LookupError::Protocol(
            "conntrack reply truncated before nfgenmsg".to_string(),
        ));
    }
    let attrs = &buf[payload_start..len];
    let orig_dst = find_orig_dst(attrs)?;
    Ok(CtReply::Entry(orig_dst))
}

/// Walk the top-level NLA list, find `CTA_TUPLE_ORIG`, and pull
/// `(IPv4 dst, dst port)` out of its nested attributes.
fn find_orig_dst(attrs: &[u8]) -> Result<SocketAddrV4, LookupError> {
    for (attr_type, value) in iter_nlas(attrs)? {
        if attr_type & NLA_TYPE_MASK == CTA_TUPLE_ORIG {
            return parse_tuple_v4_dst(value);
        }
    }
    Err(LookupError::Protocol(
        "reply missing CTA_TUPLE_ORIG attribute".to_string(),
    ))
}

/// Parse a `CTA_TUPLE_*` nested payload: extract the IPv4 dst and
/// L4 dst port. Other nested entries (src, proto num, src port) are
/// ignored.
fn parse_tuple_v4_dst(buf: &[u8]) -> Result<SocketAddrV4, LookupError> {
    let mut dst_ip: Option<Ipv4Addr> = None;
    let mut dst_port: Option<u16> = None;

    for (attr_type, value) in iter_nlas(buf)? {
        let stripped = attr_type & NLA_TYPE_MASK;
        if stripped == CTA_TUPLE_IP {
            for (ip_type, ip_value) in iter_nlas(value)? {
                if ip_type & NLA_TYPE_MASK == CTA_IP_V4_DST && ip_value.len() >= 4 {
                    dst_ip = Some(Ipv4Addr::new(
                        ip_value[0],
                        ip_value[1],
                        ip_value[2],
                        ip_value[3],
                    ));
                }
            }
        } else if stripped == CTA_TUPLE_PROTO {
            for (proto_type, proto_value) in iter_nlas(value)? {
                if proto_type & NLA_TYPE_MASK == CTA_PROTO_DST_PORT && proto_value.len() >= 2 {
                    dst_port = Some(u16::from_be_bytes([proto_value[0], proto_value[1]]));
                }
            }
        }
    }

    match (dst_ip, dst_port) {
        (Some(ip), Some(port)) => Ok(SocketAddrV4::new(ip, port)),
        _ => Err(LookupError::Protocol(
            "CTA_TUPLE_ORIG missing IPv4 dst or dst port".to_string(),
        )),
    }
}

/// Walk a netlink attribute list (TLV stream). Returns
/// `(type, value_slice)` pairs; the caller is responsible for stripping
/// `NLA_F_NESTED` if relevant.
fn iter_nlas(mut buf: &[u8]) -> Result<Vec<(u16, &[u8])>, LookupError> {
    let mut out = Vec::new();
    while !buf.is_empty() {
        if buf.len() < 4 {
            return Err(LookupError::Protocol(format!(
                "nla truncated: {} bytes left",
                buf.len()
            )));
        }
        let len = u16::from_ne_bytes([buf[0], buf[1]]) as usize;
        let attr_type = u16::from_ne_bytes([buf[2], buf[3]]);
        if len < 4 || len > buf.len() {
            return Err(LookupError::Protocol(format!(
                "nla length out of range: len={len}, buf={}",
                buf.len()
            )));
        }
        let value = &buf[4..len];
        out.push((attr_type, value));
        // Pad to 4-byte alignment.
        let padded = (len + 3) & !3;
        if padded > buf.len() {
            break;
        }
        buf = &buf[padded..];
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `build_get_request` produces a buffer whose top-level netlink
    /// header carries the right type, flags, and length. Hermetic.
    #[test]
    fn build_get_request_has_correct_header() {
        let src = SocketAddrV4::new(Ipv4Addr::new(10, 211, 0, 3), 54321);
        let dst = SocketAddrV4::new(Ipv4Addr::new(10, 211, 0, 2), 10002);
        let buf = build_get_request(src, dst);

        let len = u32::from_ne_bytes(buf[0..4].try_into().unwrap()) as usize;
        assert_eq!(len, buf.len(), "nlmsg.len must equal buffer length");
        let nlmsg_type = u16::from_ne_bytes(buf[4..6].try_into().unwrap());
        assert_eq!(nlmsg_type >> 8, NFNL_SUBSYS_CTNETLINK as u16);
        assert_eq!(nlmsg_type as u8, IPCTNL_MSG_CT_GET);
        let flags = u16::from_ne_bytes(buf[6..8].try_into().unwrap());
        assert_eq!(flags & NLM_F_REQUEST, NLM_F_REQUEST);
        // We deliberately do NOT request NLM_F_ACK — the ack would
        // arrive as a separate frame after a successful entry reply
        // and leak into the next lookup's recv. See `build_get_request`
        // for the full rationale.
        assert_eq!(flags & NLM_F_ACK, 0);

        // nfgenmsg.family is at offset NLMSG_HDR_LEN.
        assert_eq!(buf[NLMSG_HDR_LEN], NFPROTO_IPV4);
    }

    /// Round-trip: build a request, then synthesize a kernel reply by
    /// hand that swaps `CTA_TUPLE_REPLY` (sent) for `CTA_TUPLE_ORIG`
    /// carrying `(pre_dnat_ip, pre_dnat_port)`. Assert
    /// `parse_ct_reply` extracts those values.
    #[test]
    fn parse_ct_reply_extracts_orig_dst() {
        let pre_dnat_dst = SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 7), 9999);
        let vm_src = SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 3), 33333);

        // Build the kernel reply: nlmsghdr (type=CT_NEW) + nfgenmsg +
        // CTA_TUPLE_ORIG nested payload with vm_src as the source and
        // pre_dnat_dst as the destination.
        let ip_tuple = build_ip_tuple_v4(*vm_src.ip(), *pre_dnat_dst.ip());
        let proto_tuple = build_proto_tuple_udp(vm_src.port(), pre_dnat_dst.port());
        let mut tuple_payload = Vec::new();
        tuple_payload.extend_from_slice(&ip_tuple);
        tuple_payload.extend_from_slice(&proto_tuple);
        let orig_attr = emit_nla(CTA_TUPLE_ORIG | NLA_F_NESTED, &tuple_payload);

        let mut nf_payload = Vec::new();
        nf_payload.extend_from_slice(&[NFPROTO_IPV4, 0, 0, 0]);
        nf_payload.extend_from_slice(&orig_attr);

        let total_len = NLMSG_HDR_LEN + nf_payload.len();
        let mut buf = Vec::with_capacity(total_len);
        buf.extend_from_slice(&(total_len as u32).to_ne_bytes());
        let nlmsg_type = ((NFNL_SUBSYS_CTNETLINK as u16) << 8) | (IPCTNL_MSG_CT_NEW as u16);
        buf.extend_from_slice(&nlmsg_type.to_ne_bytes());
        buf.extend_from_slice(&0u16.to_ne_bytes()); // flags
        buf.extend_from_slice(&0u32.to_ne_bytes()); // seq
        buf.extend_from_slice(&0u32.to_ne_bytes()); // pid
        buf.extend_from_slice(&nf_payload);

        match parse_ct_reply(&buf).expect("parse") {
            CtReply::Entry(addr) => {
                assert_eq!(addr.ip(), pre_dnat_dst.ip());
                assert_eq!(addr.port(), pre_dnat_dst.port());
            }
            other => panic!(
                "expected Entry, got {:?}",
                match other {
                    CtReply::NotFound => "NotFound",
                    CtReply::Kernel(_) => "Kernel",
                    CtReply::Entry(_) => unreachable!(),
                }
            ),
        }
    }

    /// Same shape as `parse_ct_reply_extracts_orig_dst`, but every
    /// CTA_* attribute type at every nesting level (CTA_TUPLE_ORIG,
    /// CTA_IP_V4_DST, CTA_IP_V4_SRC, CTA_PROTO_NUM,
    /// CTA_PROTO_SRC_PORT, CTA_PROTO_DST_PORT, plus the inner
    /// CTA_TUPLE_IP / CTA_TUPLE_PROTO containers) carries the
    /// `NLA_F_NET_BYTEORDER` flag OR'd onto its type byte. The kernel
    /// UAPI `NLA_TYPE_MASK` masks out both NLA_F_NESTED and
    /// NLA_F_NET_BYTEORDER, so the parser must be flag-tolerant on
    /// type comparisons or the lookup silently regresses to
    /// `Protocol("missing IPv4 dst")` whenever a kernel build flips
    /// the flag on (distro patches, future hardening). Current
    /// upstream conntrack emitters use `nla_put_be*` which doesn't
    /// set the flag, so this test exists precisely to guard against
    /// the future where they do.
    #[test]
    fn parse_ct_reply_tolerates_nla_f_net_byteorder_on_every_cta() {
        let pre_dnat_dst = SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 11), 4444);
        let vm_src = SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 5), 60001);

        // Build the IP sub-tuple by hand so we can OR
        // NLA_F_NET_BYTEORDER onto each leaf type.
        let src_ip_attr = emit_nla(CTA_IP_V4_SRC | NLA_F_NET_BYTEORDER, &vm_src.ip().octets());
        let dst_ip_attr = emit_nla(
            CTA_IP_V4_DST | NLA_F_NET_BYTEORDER,
            &pre_dnat_dst.ip().octets(),
        );
        let mut ip_inner = Vec::new();
        ip_inner.extend_from_slice(&src_ip_attr);
        ip_inner.extend_from_slice(&dst_ip_attr);
        // Nested container with both NLA_F_NESTED *and*
        // NLA_F_NET_BYTEORDER set — the kernel can in principle set
        // both, and `NLA_TYPE_MASK` strips both.
        let ip_tuple = emit_nla(CTA_TUPLE_IP | NLA_F_NESTED | NLA_F_NET_BYTEORDER, &ip_inner);

        // Build the proto sub-tuple by hand likewise. Ports stay in
        // network byte order on the wire regardless of the flag —
        // the flag is metadata about how to interpret the payload,
        // not a payload-format toggle.
        let proto_num_attr = emit_nla(
            CTA_PROTO_NUM | NLA_F_NET_BYTEORDER,
            &[libc::IPPROTO_UDP as u8],
        );
        let sport_attr = emit_nla(
            CTA_PROTO_SRC_PORT | NLA_F_NET_BYTEORDER,
            &vm_src.port().to_be_bytes(),
        );
        let dport_attr = emit_nla(
            CTA_PROTO_DST_PORT | NLA_F_NET_BYTEORDER,
            &pre_dnat_dst.port().to_be_bytes(),
        );
        let mut proto_inner = Vec::new();
        proto_inner.extend_from_slice(&proto_num_attr);
        proto_inner.extend_from_slice(&sport_attr);
        proto_inner.extend_from_slice(&dport_attr);
        let proto_tuple = emit_nla(
            CTA_TUPLE_PROTO | NLA_F_NESTED | NLA_F_NET_BYTEORDER,
            &proto_inner,
        );

        let mut tuple_payload = Vec::new();
        tuple_payload.extend_from_slice(&ip_tuple);
        tuple_payload.extend_from_slice(&proto_tuple);
        // Top-level CTA_TUPLE_ORIG with both flags set.
        let orig_attr = emit_nla(
            CTA_TUPLE_ORIG | NLA_F_NESTED | NLA_F_NET_BYTEORDER,
            &tuple_payload,
        );

        let mut nf_payload = Vec::new();
        nf_payload.extend_from_slice(&[NFPROTO_IPV4, 0, 0, 0]);
        nf_payload.extend_from_slice(&orig_attr);

        let total_len = NLMSG_HDR_LEN + nf_payload.len();
        let mut buf = Vec::with_capacity(total_len);
        buf.extend_from_slice(&(total_len as u32).to_ne_bytes());
        let nlmsg_type = ((NFNL_SUBSYS_CTNETLINK as u16) << 8) | (IPCTNL_MSG_CT_NEW as u16);
        buf.extend_from_slice(&nlmsg_type.to_ne_bytes());
        buf.extend_from_slice(&0u16.to_ne_bytes()); // flags
        buf.extend_from_slice(&0u32.to_ne_bytes()); // seq
        buf.extend_from_slice(&0u32.to_ne_bytes()); // pid
        buf.extend_from_slice(&nf_payload);

        match parse_ct_reply(&buf).expect("parse") {
            CtReply::Entry(addr) => {
                assert_eq!(
                    addr.ip(),
                    pre_dnat_dst.ip(),
                    "byte-order-flagged CTA_IP_V4_DST must still be recognised",
                );
                assert_eq!(
                    addr.port(),
                    pre_dnat_dst.port(),
                    "byte-order-flagged CTA_PROTO_DST_PORT must still be recognised",
                );
            }
            CtReply::NotFound => {
                panic!("byte-order-flagged CTA_TUPLE_ORIG was missed by find_orig_dst");
            }
            CtReply::Kernel(e) => panic!("unexpected kernel error: {e}"),
        }
    }

    /// Synthetic NLMSG_ERROR with `-ENOENT` is classified as
    /// `CtReply::NotFound` by `parse_ct_reply`. The miss counter is
    /// incremented one layer up (in `lookup_pre_dnat_dst`), so we
    /// don't observe it from this layer.
    #[test]
    fn parse_ct_reply_translates_enoent_to_notfound() {
        let mut buf = Vec::new();
        // Length: 16-byte nlmsghdr + 4-byte errno.
        buf.extend_from_slice(&(20u32).to_ne_bytes());
        buf.extend_from_slice(&NLMSG_ERROR.to_ne_bytes());
        buf.extend_from_slice(&0u16.to_ne_bytes()); // flags
        buf.extend_from_slice(&0u32.to_ne_bytes()); // seq
        buf.extend_from_slice(&0u32.to_ne_bytes()); // pid
        buf.extend_from_slice(&(-libc::ENOENT).to_ne_bytes());

        match parse_ct_reply(&buf).expect("parse") {
            CtReply::NotFound => {}
            CtReply::Entry(_) => panic!("ENOENT must not be parsed as Entry"),
            CtReply::Kernel(e) => panic!("ENOENT must be NotFound, not Kernel({e})"),
        }
    }

    /// `iter_nlas` walks a series of attributes correctly, including
    /// padding.
    #[test]
    fn iter_nlas_walks_padded_stream() {
        let a1 = emit_nla(1, &[0x01]); // 1 byte payload + 3 bytes pad
        let a2 = emit_nla(2, &[0x02, 0x03]); // 2-byte payload + 2 bytes pad
        let mut buf = a1.clone();
        buf.extend_from_slice(&a2);

        let parsed = iter_nlas(&buf).expect("walk");
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].0, 1);
        assert_eq!(parsed[0].1, &[0x01]);
        assert_eq!(parsed[1].0, 2);
        assert_eq!(parsed[1].1, &[0x02, 0x03]);
    }

    /// `parse_tuple_v4_dst` rejects a tuple missing the dst port.
    #[test]
    fn parse_tuple_v4_dst_rejects_missing_port() {
        // CTA_TUPLE_IP only — no proto sub-tuple.
        let payload = build_ip_tuple_v4(Ipv4Addr::new(1, 2, 3, 4), Ipv4Addr::new(5, 6, 7, 8));
        match parse_tuple_v4_dst(&payload) {
            Err(LookupError::Protocol(msg)) => {
                assert!(msg.contains("missing"), "unexpected msg: {msg}");
            }
            other => panic!("expected Protocol error, got {other:?}"),
        }
    }
}
