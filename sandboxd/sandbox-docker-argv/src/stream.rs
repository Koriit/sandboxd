//! The long-lived byte streams into a container, and the `docker exec` that
//! carries each one.
//!
//! Three streams in the product are held open rather than run to completion:
//! the guest-agent transport, the SSH proxy's byte pump, and the DNS-policy
//! gate bridge. They are one family here because they are one argv shape —
//! `docker exec -i <container> socat - <address>` — differing only in which
//! in-container endpoint `socat` is pointed at.
//!
//! # Why the endpoint is an enum and not a string
//!
//! The address is what a stream *reaches*. A caller-supplied one would let
//! whoever names it open a byte pipe to any port or socket inside the
//! container, which is the whole of what these streams do — the closed op set
//! would still be closed and would bound nothing. [`StreamTarget`] therefore
//! enumerates the three endpoints and each renders a `&'static`-derived
//! address from constants in this crate; what crosses the broker channel is
//! the discriminant.
//!
//! # Why the addresses live here
//!
//! Both sides of the broker channel render them: the daemon when it owns the
//! VM itself, the operator's agent when it does not. A second declaration of
//! an endpoint is how the two sides come to disagree about where a stream
//! lands, and a stream that lands somewhere else is not detectable from
//! either end. `sandbox-core` re-exports the two that had names there
//! already, so no call site has to know they moved.

use std::path::Path;

use crate::host_args;

/// TCP port the in-session `sandbox-guest` agent listens on, inside every
/// session on both backends.
///
/// Re-exported as `sandbox_core::guest::GUEST_AGENT_PORT`, which is where it
/// was declared before both sides of the broker needed to render it.
pub const GUEST_AGENT_PORT: u16 = 5123;

/// TCP port the in-session `sshd` listens on inside a lite container.
pub const SSHD_PORT: u16 = 22;

/// Absolute path of the DNS-policy gate socket **inside** the gateway
/// container — the exact path the baked-in Corefile dials.
///
/// Re-exported as `sandbox_core::dns_gate::DNS_GATE_SOCKET_IN_CONTAINER`.
pub const DNS_GATE_SOCKET_IN_CONTAINER: &str = "/var/log/gateway/events/dns-gate.sock";

/// The closed set of in-container endpoints a long-lived stream may reach.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamTarget {
    /// The in-session `sandbox-guest` agent. Carries sandboxd's structured
    /// guest protocol; one connection per guest request.
    GuestAgent,
    /// The in-session `sshd`. Carries an operator's SSH session, which under
    /// a remote-development client runs for hours.
    Sshd,
    /// The gateway container's DNS-policy gate socket. Unlike the other two
    /// this one **listens**: see [`StreamTarget::socat_address`] for why the
    /// listener is not forked, which is a correctness property of the egress
    /// decision path rather than a tuning choice.
    DnsGate,
}

impl StreamTarget {
    /// The `socat` address this target renders to.
    ///
    /// # The gate listener is deliberately not forked
    ///
    /// [`StreamTarget::DnsGate`] renders `UNIX-LISTEN:<path>,unlink-early`
    /// with **no `,fork`**. The CoreDNS gate plugin opens one connection per
    /// DNS query, writes one length-prefixed request frame, reads one ack
    /// frame and closes. `socat`'s `,fork` would multiplex every concurrent
    /// connection onto a single stdio byte stream with no record boundaries,
    /// so two queries in flight at once would interleave and corrupt each
    /// other's frames — on the path that decides what egress is allowed.
    /// One accepted connection per exec is what gives each gate round-trip
    /// an independent stdio pair.
    ///
    /// `unlink-early` clears a socket inode left behind by a listener that
    /// was killed mid-flight, so a dead predecessor cannot wedge the next
    /// accept with `Address already in use`.
    pub fn socat_address(self) -> String {
        match self {
            StreamTarget::GuestAgent => format!("TCP:127.0.0.1:{GUEST_AGENT_PORT}"),
            StreamTarget::Sshd => format!("TCP:127.0.0.1:{SSHD_PORT}"),
            StreamTarget::DnsGate => {
                format!("UNIX-LISTEN:{DNS_GATE_SOCKET_IN_CONTAINER},unlink-early")
            }
        }
    }

    /// A short label for logs and error messages.
    pub fn label(self) -> &'static str {
        match self {
            StreamTarget::GuestAgent => "guest-agent",
            StreamTarget::Sshd => "sshd",
            StreamTarget::DnsGate => "dns-gate",
        }
    }
}

/// The `docker` arguments that open one long-lived stream:
/// `[-H unix://<sock>] exec -i <container> socat - <address>`.
///
/// Pure, so the shape can be asserted without spawning anything — including
/// the property that the gate listener never carries `,fork`.
///
/// `socket` follows [`host_args`]: `None` is the host-daemon case (Linux, and
/// the argv is byte-identical to the historical one), `Some` pins the target
/// authority at a Docker daemon inside a VM. Whoever runs the invocation
/// supplies its own socket — the path is never carried across the broker
/// channel.
///
/// `-i` is present on all three: without stdin the pump is one-directional.
/// There is deliberately no `-t` — a TTY would line-buffer and corrupt every
/// one of these payloads.
pub fn stream_exec_argv(
    socket: Option<&Path>,
    container: &str,
    target: StreamTarget,
) -> Vec<String> {
    let mut argv: Vec<String> = Vec::with_capacity(8);
    argv.extend(host_args(socket));
    argv.push("exec".to_string());
    argv.push("-i".to_string());
    argv.push(container.to_string());
    argv.push("socat".to_string());
    argv.push("-".to_string());
    argv.push(target.socat_address());
    argv
}

#[cfg(test)]
mod tests {
    use super::*;

    const SOCK: &str = "/var/lib/sandboxd/501/sandboxd-gateway/gateway-docker.sock";

    #[test]
    fn guest_agent_stream_targets_the_agent_port() {
        let argv = stream_exec_argv(
            Some(Path::new(SOCK)),
            "sandbox-abc123",
            StreamTarget::GuestAgent,
        );
        assert_eq!(
            argv,
            vec![
                "-H",
                "unix:///var/lib/sandboxd/501/sandboxd-gateway/gateway-docker.sock",
                "exec",
                "-i",
                "sandbox-abc123",
                "socat",
                "-",
                "TCP:127.0.0.1:5123",
            ]
        );
    }

    #[test]
    fn sshd_stream_targets_port_22() {
        let argv = stream_exec_argv(None, "sandbox-def456", StreamTarget::Sshd);
        assert_eq!(
            argv,
            vec![
                "exec",
                "-i",
                "sandbox-def456",
                "socat",
                "-",
                "TCP:127.0.0.1:22",
            ]
        );
    }

    #[test]
    fn dns_gate_stream_listens_on_the_corefile_path() {
        let argv = stream_exec_argv(Some(Path::new(SOCK)), "sandbox-gw-x", StreamTarget::DnsGate);
        let listen = argv.last().expect("argv has a listen address");
        assert_eq!(
            listen,
            "UNIX-LISTEN:/var/log/gateway/events/dns-gate.sock,unlink-early"
        );
    }

    /// The gate listener must never be forked: `,fork` would multiplex
    /// concurrent gate connections onto one stdio byte stream and corrupt the
    /// per-connection request/ack framing, on the egress-allow decision path.
    /// Asserted over every target so a future variant cannot acquire it
    /// unnoticed either.
    #[test]
    fn no_stream_target_ever_forks() {
        for target in [
            StreamTarget::GuestAgent,
            StreamTarget::Sshd,
            StreamTarget::DnsGate,
        ] {
            let argv = stream_exec_argv(Some(Path::new(SOCK)), "c", target);
            assert!(
                !argv.iter().any(|a| a.contains("fork")),
                "{} stream must not fork; got {argv:?}",
                target.label()
            );
        }
    }

    /// Every stream forwards stdin and none allocates a TTY. A missing `-i`
    /// makes the pump one-directional; a `-t` line-buffers it.
    #[test]
    fn every_stream_forwards_stdin_and_none_allocates_a_tty() {
        for target in [
            StreamTarget::GuestAgent,
            StreamTarget::Sshd,
            StreamTarget::DnsGate,
        ] {
            let argv = stream_exec_argv(None, "c", target);
            assert!(
                argv.iter().any(|a| a == "-i"),
                "{} stream must forward stdin; got {argv:?}",
                target.label()
            );
            assert!(
                !argv.iter().any(|a| a == "-t" || a == "-it" || a == "-ti"),
                "{} stream must not allocate a TTY; got {argv:?}",
                target.label()
            );
        }
    }

    /// With no socket the argv carries no `-H`, so the Linux/host-daemon
    /// invocation is byte-identical to the shape that predates the seam.
    #[test]
    fn no_socket_omits_the_host_flag() {
        for target in [
            StreamTarget::GuestAgent,
            StreamTarget::Sshd,
            StreamTarget::DnsGate,
        ] {
            let argv = stream_exec_argv(None, "c", target);
            assert!(
                !argv.iter().any(|a| a == "-H"),
                "host-daemon {} argv must not carry -H: {argv:?}",
                target.label()
            );
        }
    }
}
