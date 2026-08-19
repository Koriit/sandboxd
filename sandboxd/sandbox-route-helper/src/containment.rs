//! Deciding whether a gateway address is plausible for a network namespace,
//! from what that namespace says about itself.
//!
//! # The question this answers, and why it is asked here
//!
//! The helper's in-VM mode takes a container pid and a gateway address, enters
//! the container's network namespace, and rewrites its default route. The
//! gateway address is the address every packet the sandbox sends will be handed
//! to. Getting it wrong does not fail — it produces a container whose egress
//! goes somewhere other than the policy gateway, with nothing inside the
//! sandbox able to notice.
//!
//! Every layer above this one — the daemon that builds the op, the broker that
//! carries it, the agent that validates it — has nothing to check this address
//! against. Its *shape* is settled before any of them look at it: the op field
//! is an `Ipv4Addr` and cannot hold a non-address. What the agent's validator
//! examines is the container pid; the address it passes through. None of them
//! can check whether it is the right address, and more importantly **none of
//! them is on the path that matters**. The adversary here is a process inside
//! the gateway VM that runs
//!
//! ```text
//! sudo /usr/local/libexec/sandboxd/sandbox-route-helper --vm-gateway-mode <pid> <ip>
//! ```
//!
//! directly. Such a caller never touches the daemon, the broker, or the agent's
//! validation. Any check made on caller-supplied input is therefore worth
//! exactly nothing against it: the attacker supplies the input.
//!
//! What the attacker does *not* supply is what the kernel reports about the
//! namespace once the helper has entered it. That is the only ground truth
//! available on this path, and so it is the only thing this module uses. The
//! rule is: **a route may be installed only if the gateway address is
//! consistent with what the namespace says about itself.**
//!
//! # Why this is a pure function
//!
//! The decision is separated from the namespace read so it can be tested
//! exhaustively without a netns — including on a macOS development host, where
//! the rest of this crate does not even compile past a stub. The caller does
//! the `getifaddrs` walk and the narrowing; every accept and reject rule is
//! here, with no syscalls, no I/O and no globals.
//!
//! # What this is not
//!
//! **Defence in depth, not a boundary.** The adversary is root inside the
//! gateway VM, and root can shape what a namespace reports — by creating a
//! Docker network with a chosen subnet and attaching the container to it. And
//! the `/28` the daemon allocates still leaves thirteen addresses passing: of
//! its sixteen, a namespace reporting just the sandbox's own `.3` gets exactly
//! three refused — the network address, the broadcast address, and that `.3`
//! itself — and the other thirteen accepted. One of the thirteen is the
//! session's real gateway; this module returns the same verdict for all
//! thirteen, so nothing it sees tells that one apart from the other twelve.
//! Passing these checks therefore does **not** establish that the address is
//! the session's assigned gateway.
//!
//! What it does establish is worth stating as the code implements it, rather
//! than as a list of things that are "obviously wrong":
//! [`gateway_is_on_an_observed_subnet`] accepts exactly when the gateway is
//! RFC 1918, is not an address the namespace already holds, and is a host
//! address on some subnet the namespace reports — where "reports" means an
//! interface whose mask is contiguous and no shorter than `/8`.
//!
//! Two of those clauses refuse with no qualifier at all: an address outside
//! RFC 1918 space is refused whatever the namespace says, and so is one the
//! namespace already holds on an interface of its own. A namespace that reports
//! nothing refuses every address there is.
//!
//! The third clause is the containment test, and what it is worth is **relative
//! to the observed prefix** — the dependence is total. Under the topology the
//! daemon allocates, a `/28` per session, nothing outside that session's own
//! sixteen addresses passes it, so a neighbouring session's gateway is refused:
//! an observed `10.209.0.3/28` accepts `10.209.0.2` and refuses `10.209.0.18`,
//! the `.2` of the `/28` next door. Widen the observed prefix and the test
//! weakens in step, to the point of deciding nothing: an interface on
//! `10.0.0.3/8` contains the whole of `10.0.0.0/8`, so `10.99.99.99` is accepted
//! there and containment has added nothing to the RFC 1918 clause that ran
//! before it. Network and broadcast addresses are relative in the same way,
//! refused only while no observed subnet can host them — `10.0.0.15` is refused
//! against a lone `10.0.0.3/28` and accepted once a `10.0.0.20/24` is observed
//! beside it. All three are measured, and pinned by tests below rather than
//! left as prose.
//!
//! That accept condition is this module's verdict, not the outcome. The helper
//! reaches this module along a single path — `run_vm_gateway_mode` — through
//! three references rather than one call: `gateway_is_on_an_observed_subnet`
//! for the verdict here, `NetnsAddr::new` while collecting the namespace's
//! addresses, and `is_rfc1918` from the all-addresses-private check. On that
//! path an accept is a precondition of the route install rather than a
//! trigger for it. By the time it is consulted the caller has required uid 0
//! and a `pidfd_open` and `setns` that both succeeded, and has separately
//! required every non-`lo` IPv4 address the namespace holds to be RFC 1918;
//! after it accepts, `ip route replace` still has to succeed. A namespace
//! reporting `203.0.113.5/24` on one interface and `10.0.0.3/28` on another
//! meets all three clauses for gateway `10.0.0.2` and gets no route at all:
//! the all-addresses-private check refuses the public address first, and this
//! module is never reached.
//!
//! So the sentence to carry away is "the gateway is on a subnet this namespace
//! is attached to", never "the gateway is an address related to this session".

// Off Linux, the only consumer of this module is `imp`, which is gated to
// Linux and therefore does not exist — so every item here reads as dead. The
// module is still compiled, and its tests still run, which is the whole reason
// it is not gated too; see the `mod containment` declaration in `main.rs`.
// Silencing dead-code only on the platforms where the consumer is absent keeps
// the warning live where it would mean something.
#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

use std::fmt;
use std::net::Ipv4Addr;

/// One IPv4 address the kernel reports on an interface inside the namespace,
/// with the netmask it was configured with.
///
/// This is the whole of what the decision below is allowed to know. It is
/// deliberately a plain value: the caller reads it from the kernel, and nothing
/// on the caller's side of the boundary can influence it without first
/// controlling the namespace itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NetnsAddr {
    /// An IPv4 address on a non-loopback interface in the namespace.
    pub address: Ipv4Addr,
    /// That address's netmask, as the kernel reports it.
    pub netmask: Ipv4Addr,
}

impl NetnsAddr {
    /// Construct from an address and a netmask.
    pub fn new(address: Ipv4Addr, netmask: Ipv4Addr) -> Self {
        Self { address, netmask }
    }

    /// The prefix length this netmask denotes, if it is a contiguous mask.
    ///
    /// `None` for a non-contiguous mask (`255.0.255.0` and the like). Such a
    /// mask is not a subnet this code can reason about, and rather than pick an
    /// interpretation it is treated as no evidence at all — see
    /// [`gateway_is_on_an_observed_subnet`].
    fn prefix_len(&self) -> Option<u8> {
        let bits = u32::from(self.netmask);
        let ones = bits.leading_ones();
        // Contiguous iff the mask is exactly `ones` leading 1s and nothing else.
        if ones == 32 {
            return Some(32);
        }
        if bits << ones == 0 {
            Some(ones as u8)
        } else {
            None
        }
    }
}

/// Why a gateway address was refused.
///
/// Carries the values it refused so the message names them. The `Display` text
/// is the operator-facing diagnostic and is load-bearing — it is the only thing
/// a person debugging a failed session sees — so it is exercised by tests
/// rather than left to be right by inspection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GatewayRejection {
    /// The namespace reported no IPv4 address on any non-loopback interface.
    NoAddresses,
    /// The gateway address is not in RFC 1918 space.
    NotPrivate { gateway: Ipv4Addr },
    /// The gateway address is one of the namespace's own addresses.
    OwnAddress { gateway: Ipv4Addr },
    /// The gateway address is a subnet's network address, which no host holds.
    NetworkAddress {
        gateway: Ipv4Addr,
        base: Ipv4Addr,
        prefix_len: u8,
    },
    /// The gateway address is a subnet's broadcast address.
    BroadcastAddress {
        gateway: Ipv4Addr,
        base: Ipv4Addr,
        prefix_len: u8,
    },
    /// The gateway address is not inside any subnet the namespace is on.
    OutsideEverySubnet { gateway: Ipv4Addr },
}

impl fmt::Display for GatewayRejection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoAddresses => write!(
                f,
                "the container netns reports no IPv4 address on any non-loopback \
                 interface, so nothing there attests to which gateway is correct; \
                 refusing route install"
            ),
            Self::NotPrivate { gateway } => write!(
                f,
                "gateway {gateway} is not a private RFC 1918 address; \
                 refusing route install"
            ),
            Self::OwnAddress { gateway } => write!(
                f,
                "gateway {gateway} is the container's own address; a container \
                 cannot be its own default gateway; refusing route install"
            ),
            Self::NetworkAddress {
                gateway,
                base,
                prefix_len,
            } => write!(
                f,
                "gateway {gateway} is the network address of {base}/{prefix_len} \
                 and cannot be a host; refusing route install"
            ),
            Self::BroadcastAddress {
                gateway,
                base,
                prefix_len,
            } => write!(
                f,
                "gateway {gateway} is the broadcast address of {base}/{prefix_len} \
                 and cannot be a host; refusing route install"
            ),
            Self::OutsideEverySubnet { gateway } => write!(
                f,
                "gateway {gateway} is not on any subnet the container netns is \
                 attached to; refusing route install"
            ),
        }
    }
}

/// Is `gateway_ip` a plausible default gateway for a namespace whose own IPv4
/// addresses are `observed`?
///
/// Pure — no syscalls, no I/O, no globals. `observed` is what the caller read
/// from the kernel after entering the namespace; nothing else is consulted.
///
/// # The rules, and why each one is here
///
/// 1. **No addresses fails closed.** See [`GatewayRejection::NoAddresses`] and
///    the note below.
/// 2. **The gateway must be RFC 1918.** This does *not* follow from
///    containment, and the difference is not academic: an interface configured
///    `172.20.0.5/8` yields the subnet `172.0.0.0/8`, which contains the
///    publicly-routable `172.5.1.1`. Containment alone would accept it.
/// 3. **The gateway is not one of the namespace's own addresses.** A container
///    routing through itself has no egress at all, and accepting it would let a
///    caller blackhole a session while appearing to configure it.
/// 4. **The gateway is a usable host address on some subnet the namespace is
///    on.** One subnet accepting is enough: a container legitimately has more
///    than one interface, and requiring every one of them to contain the
///    gateway would reject correct configurations.
///
/// # The no-addresses case fails closed, deliberately
///
/// The control works by having the namespace attest to its own topology. A
/// namespace that reports nothing has made no attestation, and "no evidence" is
/// not "evidence of correctness" — failing open would mean an attacker who can
/// present an address-stripped namespace gets the check switched off, which is
/// a strictly easier move than finding a colliding subnet.
///
/// It also costs nothing operationally. A netns with no non-loopback address
/// has no interface to route out of, so `ip route replace` would fail anyway;
/// failing closed rejects no configuration that would otherwise have worked,
/// and turns an opaque `ENETUNREACH` into a message that names the problem.
///
/// # Masks that are not subnets
///
/// A non-contiguous netmask, and a prefix shorter than `/8`, are both skipped
/// rather than interpreted. A `/0` "subnet" would contain every address and
/// make the check vacuous for anything else in the list; a non-contiguous mask
/// has no single subnet to speak of. Neither is evidence, and treating
/// non-evidence as permission is how a control becomes decorative.
pub fn gateway_is_on_an_observed_subnet(
    observed: &[NetnsAddr],
    gateway_ip: Ipv4Addr,
) -> Result<(), GatewayRejection> {
    if observed.is_empty() {
        return Err(GatewayRejection::NoAddresses);
    }

    if !is_rfc1918(gateway_ip) {
        return Err(GatewayRejection::NotPrivate {
            gateway: gateway_ip,
        });
    }

    if observed.iter().any(|a| a.address == gateway_ip) {
        return Err(GatewayRejection::OwnAddress {
            gateway: gateway_ip,
        });
    }

    // A reason recorded from a subnet that *contained* the gateway but could
    // not host it. It is more useful than the generic "outside every subnet",
    // so it is preferred if no subnet accepts.
    let mut specific: Option<GatewayRejection> = None;

    for addr in observed {
        let Some(prefix_len) = addr.prefix_len() else {
            continue;
        };
        if prefix_len < 8 {
            continue;
        }

        let mask = u32::from(addr.netmask);
        let base_bits = u32::from(addr.address) & mask;
        if u32::from(gateway_ip) & mask != base_bits {
            continue;
        }

        let base = Ipv4Addr::from(base_bits);

        // RFC 3021: on a /31 both addresses are usable hosts, so there is no
        // network or broadcast address to exclude. A /32 has no second address
        // at all, so a gateway inside it would have had to equal the observed
        // address and was already refused above.
        if prefix_len <= 30 {
            let broadcast = Ipv4Addr::from(base_bits | !mask);
            if gateway_ip == base {
                specific.get_or_insert(GatewayRejection::NetworkAddress {
                    gateway: gateway_ip,
                    base,
                    prefix_len,
                });
                continue;
            }
            if gateway_ip == broadcast {
                specific.get_or_insert(GatewayRejection::BroadcastAddress {
                    gateway: gateway_ip,
                    base,
                    prefix_len,
                });
                continue;
            }
        }

        return Ok(());
    }

    Err(specific.unwrap_or(GatewayRejection::OutsideEverySubnet {
        gateway: gateway_ip,
    }))
}

/// Is this address in RFC 1918 private space?
///
/// `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`. The single definition in
/// this crate: `gateway_is_on_an_observed_subnet` calls it here, and the in-VM
/// address enforcement calls it from the same `run_vm_gateway_mode` path, so
/// the two cannot drift into disagreeing about what "private" means.
pub fn is_rfc1918(ip: Ipv4Addr) -> bool {
    let o = ip.octets();
    o[0] == 10 || (o[0] == 172 && (16..=31).contains(&o[1])) || (o[0] == 192 && o[1] == 168)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `a.b.c.d/prefix` → a `NetnsAddr`, for readable test tables.
    fn at(address: &str, prefix_len: u8) -> NetnsAddr {
        let mask = if prefix_len == 0 {
            0u32
        } else {
            u32::MAX << (32 - prefix_len)
        };
        NetnsAddr::new(address.parse().unwrap(), Ipv4Addr::from(mask))
    }

    fn ip(s: &str) -> Ipv4Addr {
        s.parse().unwrap()
    }

    // -- the two outcomes the control exists to separate -------------------

    #[test]
    fn a_gateway_on_the_containers_own_subnet_is_accepted() {
        let observed = [at("10.0.0.3", 28)];
        assert_eq!(
            gateway_is_on_an_observed_subnet(&observed, ip("10.0.0.2")),
            Ok(())
        );
    }

    #[test]
    fn a_gateway_on_a_different_subnet_is_refused() {
        let observed = [at("10.0.0.3", 28)];
        assert_eq!(
            gateway_is_on_an_observed_subnet(&observed, ip("10.0.1.2")),
            Err(GatewayRejection::OutsideEverySubnet {
                gateway: ip("10.0.1.2")
            })
        );
    }

    /// The real topology this runs against: a `/28` per session, `.1` the
    /// Docker bridge, `.2` the gateway container, `.3` the sandbox. If this
    /// case ever fails, the control is rejecting production.
    #[test]
    fn the_session_topology_the_daemon_allocates_is_accepted() {
        for third in [0u8, 7, 42, 255] {
            let observed = [at(&format!("10.42.{third}.3"), 28)];
            let gateway = ip(&format!("10.42.{third}.2"));
            assert_eq!(
                gateway_is_on_an_observed_subnet(&observed, gateway),
                Ok(()),
                "the allocator's own /28 layout must be accepted"
            );
        }
    }

    // -- boundary addresses within a containing subnet ---------------------

    #[test]
    fn the_network_address_is_refused() {
        let observed = [at("10.0.0.3", 28)];
        assert_eq!(
            gateway_is_on_an_observed_subnet(&observed, ip("10.0.0.0")),
            Err(GatewayRejection::NetworkAddress {
                gateway: ip("10.0.0.0"),
                base: ip("10.0.0.0"),
                prefix_len: 28,
            })
        );
    }

    #[test]
    fn the_broadcast_address_is_refused() {
        let observed = [at("10.0.0.3", 28)];
        assert_eq!(
            gateway_is_on_an_observed_subnet(&observed, ip("10.0.0.15")),
            Err(GatewayRejection::BroadcastAddress {
                gateway: ip("10.0.0.15"),
                base: ip("10.0.0.0"),
                prefix_len: 28,
            })
        );
    }

    #[test]
    fn the_containers_own_address_is_refused() {
        let observed = [at("10.0.0.3", 28)];
        assert_eq!(
            gateway_is_on_an_observed_subnet(&observed, ip("10.0.0.3")),
            Err(GatewayRejection::OwnAddress {
                gateway: ip("10.0.0.3")
            })
        );
    }

    /// A `/31` is a point-to-point link on which both addresses are hosts
    /// (RFC 3021), so the network/broadcast exclusion must not apply.
    ///
    /// Asserted from both ends. The name is a claim about *both* addresses, and
    /// exercising only one of them would leave the other — the one a `/30`
    /// would call the network address, and so the one at risk — unpinned.
    #[test]
    fn both_addresses_of_a_slash_31_are_usable() {
        assert_eq!(
            gateway_is_on_an_observed_subnet(&[at("10.0.0.0", 31)], ip("10.0.0.1")),
            Ok(()),
            "the upper address must be usable as the peer's gateway"
        );
        assert_eq!(
            gateway_is_on_an_observed_subnet(&[at("10.0.0.1", 31)], ip("10.0.0.0")),
            Ok(()),
            "and so must the lower one, which is not a network address here"
        );
    }

    /// A `/32` has exactly one address, which is the container's. There is no
    /// gateway it can contain, and the own-address rule is what says so.
    #[test]
    fn a_slash_32_can_host_no_gateway() {
        let observed = [at("10.0.0.3", 32)];
        assert_eq!(
            gateway_is_on_an_observed_subnet(&observed, ip("10.0.0.3")),
            Err(GatewayRejection::OwnAddress {
                gateway: ip("10.0.0.3")
            })
        );
        assert_eq!(
            gateway_is_on_an_observed_subnet(&observed, ip("10.0.0.2")),
            Err(GatewayRejection::OutsideEverySubnet {
                gateway: ip("10.0.0.2")
            })
        );
    }

    // -- multiple addresses ------------------------------------------------

    /// A container legitimately has more than one interface. Any one of them
    /// containing the gateway is enough — requiring all would reject correct
    /// configurations.
    #[test]
    fn a_gateway_on_the_second_of_several_interfaces_is_accepted() {
        let observed = [at("172.17.0.2", 16), at("10.0.0.3", 28)];
        assert_eq!(
            gateway_is_on_an_observed_subnet(&observed, ip("10.0.0.2")),
            Ok(())
        );
    }

    #[test]
    fn a_gateway_on_none_of_several_interfaces_is_refused() {
        let observed = [at("172.17.0.2", 16), at("10.0.0.3", 28)];
        assert_eq!(
            gateway_is_on_an_observed_subnet(&observed, ip("192.168.9.9")),
            Err(GatewayRejection::OutsideEverySubnet {
                gateway: ip("192.168.9.9")
            })
        );
    }

    /// When one subnet contains the gateway but cannot host it and another
    /// does not contain it at all, the reported reason is the specific one.
    /// The generic message would send a reader looking for the wrong problem.
    #[test]
    fn the_more_specific_refusal_reason_wins() {
        let observed = [at("10.0.0.3", 28), at("192.168.1.5", 24)];
        assert_eq!(
            gateway_is_on_an_observed_subnet(&observed, ip("10.0.0.15")),
            Err(GatewayRejection::BroadcastAddress {
                gateway: ip("10.0.0.15"),
                base: ip("10.0.0.0"),
                prefix_len: 28,
            })
        );
    }

    // -- the no-addresses case ---------------------------------------------

    /// The decision the module doc argues for at length: no attestation means
    /// no route. Failing open here would let an attacker disable the control
    /// by presenting an address-stripped namespace.
    #[test]
    fn a_namespace_with_no_addresses_is_refused() {
        assert_eq!(
            gateway_is_on_an_observed_subnet(&[], ip("10.0.0.2")),
            Err(GatewayRejection::NoAddresses)
        );
    }

    /// And it stays refused for a gateway that would have been accepted had
    /// any address been present — the emptiness is the reason, not the value.
    #[test]
    fn no_gateway_value_rescues_an_empty_namespace() {
        for gw in ["10.0.0.2", "192.168.1.1", "172.16.0.1", "8.8.8.8"] {
            assert_eq!(
                gateway_is_on_an_observed_subnet(&[], ip(gw)),
                Err(GatewayRejection::NoAddresses)
            );
        }
    }

    // -- privateness is not implied by containment -------------------------

    /// The case that justifies keeping the RFC 1918 rule inside this function
    /// rather than inheriting it from the address enforcement next door: a
    /// `172.20.0.5/8` interface yields `172.0.0.0/8`, which *contains* the
    /// publicly-routable `172.5.1.1`. Containment alone would accept it.
    #[test]
    fn a_public_gateway_inside_an_observed_subnet_is_still_refused() {
        let observed = [at("172.20.0.5", 8)];
        assert_eq!(
            gateway_is_on_an_observed_subnet(&observed, ip("172.5.1.1")),
            Err(GatewayRejection::NotPrivate {
                gateway: ip("172.5.1.1")
            })
        );
    }

    #[test]
    fn a_public_gateway_is_refused_before_anything_else_is_considered() {
        let observed = [at("10.0.0.3", 8)];
        for gw in [
            "8.8.8.8",
            "1.1.1.1",
            "172.15.0.1",
            "172.32.0.1",
            "192.169.0.1",
        ] {
            assert_eq!(
                gateway_is_on_an_observed_subnet(&observed, ip(gw)),
                Err(GatewayRejection::NotPrivate { gateway: ip(gw) }),
                "{gw} is not RFC 1918 and must be refused"
            );
        }
    }

    // -- masks that are not evidence ---------------------------------------

    /// A non-contiguous mask has no single subnet to reason about. It is
    /// skipped rather than interpreted — treating non-evidence as permission
    /// is how a control becomes decorative.
    #[test]
    fn a_non_contiguous_netmask_is_not_evidence() {
        let observed = [NetnsAddr::new(ip("10.0.0.3"), ip("255.0.255.0"))];
        assert_eq!(
            gateway_is_on_an_observed_subnet(&observed, ip("10.0.0.2")),
            Err(GatewayRejection::OutsideEverySubnet {
                gateway: ip("10.0.0.2")
            })
        );
    }

    /// A prefix shorter than /8 would contain almost everything and make the
    /// check vacuous for every other address in the list.
    #[test]
    fn a_prefix_shorter_than_eight_bits_is_not_evidence() {
        for prefix_len in 0..8u8 {
            let observed = [at("10.0.0.3", prefix_len)];
            assert_eq!(
                gateway_is_on_an_observed_subnet(&observed, ip("10.255.255.2")),
                Err(GatewayRejection::OutsideEverySubnet {
                    gateway: ip("10.255.255.2")
                }),
                "/{prefix_len} must not be treated as a subnet"
            );
        }
    }

    /// A vacuous mask on one interface must not launder a gateway that no
    /// real interface is on.
    #[test]
    fn a_vacuous_mask_alongside_a_real_one_does_not_widen_the_decision() {
        let observed = [at("10.0.0.3", 0), at("10.0.0.3", 28)];
        assert_eq!(
            gateway_is_on_an_observed_subnet(&observed, ip("192.168.50.1")),
            Err(GatewayRejection::OutsideEverySubnet {
                gateway: ip("192.168.50.1")
            })
        );
    }

    #[test]
    fn prefix_len_reads_the_masks_the_kernel_actually_reports() {
        assert_eq!(at("10.0.0.1", 8).prefix_len(), Some(8));
        assert_eq!(at("10.0.0.1", 16).prefix_len(), Some(16));
        assert_eq!(at("10.0.0.1", 24).prefix_len(), Some(24));
        assert_eq!(at("10.0.0.1", 28).prefix_len(), Some(28));
        assert_eq!(at("10.0.0.1", 31).prefix_len(), Some(31));
        assert_eq!(at("10.0.0.1", 32).prefix_len(), Some(32));
        assert_eq!(at("10.0.0.1", 0).prefix_len(), Some(0));
        assert_eq!(
            NetnsAddr::new(ip("10.0.0.1"), ip("255.0.255.0")).prefix_len(),
            None
        );
        assert_eq!(
            NetnsAddr::new(ip("10.0.0.1"), ip("0.0.0.255")).prefix_len(),
            None
        );
    }

    // -- rfc1918 -----------------------------------------------------------

    #[test]
    fn rfc1918_covers_exactly_the_three_ranges() {
        for private in [
            "10.0.0.0",
            "10.255.255.255",
            "172.16.0.0",
            "172.31.255.255",
            "192.168.0.0",
            "192.168.255.255",
        ] {
            assert!(is_rfc1918(ip(private)), "{private} is RFC 1918");
        }
        for public in [
            "9.255.255.255",
            "11.0.0.0",
            "172.15.255.255",
            "172.32.0.0",
            "192.167.255.255",
            "192.169.0.0",
            "0.0.0.0",
            "255.255.255.255",
            "127.0.0.1",
        ] {
            assert!(!is_rfc1918(ip(public)), "{public} is not RFC 1918");
        }
    }

    // -- the limits the module doc states ----------------------------------
    //
    // The module doc says what this control does *not* buy. Each of those
    // sentences is asserted here, so a future widening of the rules trips a
    // test rather than quietly making the prose generous.

    /// The refusal the control is actually worth under the topology the daemon
    /// allocates: the session next door. `10.209.0.18` is the `.2` of the
    /// adjacent `/28` — a well-formed private gateway address, and precisely
    /// what a cross-session mix-up or a direct invoker of the helper reaches
    /// for. This is the case the control has to catch to be worth having.
    #[test]
    fn a_neighbouring_sessions_gateway_is_refused_under_the_allocated_topology() {
        let observed = [at("10.209.0.3", 28)];
        assert_eq!(
            gateway_is_on_an_observed_subnet(&observed, ip("10.209.0.2")),
            Ok(()),
            "this session's own gateway must still be accepted"
        );
        assert_eq!(
            gateway_is_on_an_observed_subnet(&observed, ip("10.209.0.18")),
            Err(GatewayRejection::OutsideEverySubnet {
                gateway: ip("10.209.0.18")
            }),
            "the adjacent /28's gateway must be refused"
        );
    }

    /// And the ceiling on that: containment is relative to the observed
    /// prefix, so a wide enough prefix leaves it deciding nothing. Inside a
    /// `/8` on `10.0.0.0/8`, every RFC 1918 address in the block is contained,
    /// and the check collapses into the `is_rfc1918` test that already ran
    /// above it.
    ///
    /// This is why the module doc does not say "an unrelated private address is
    /// refused". That sentence is true under a `/28` and false here, and a
    /// reader cannot tell which one they are in from the sentence alone.
    #[test]
    fn a_widened_observed_prefix_leaves_containment_deciding_nothing() {
        assert_eq!(
            gateway_is_on_an_observed_subnet(&[at("10.0.0.3", 8)], ip("10.99.99.99")),
            Ok(()),
            "a /8 contains all of 10.0.0.0/8, so an unrelated private address \
             passes containment"
        );
        assert_eq!(
            gateway_is_on_an_observed_subnet(&[at("10.0.0.3", 28)], ip("10.99.99.99")),
            Err(GatewayRejection::OutsideEverySubnet {
                gateway: ip("10.99.99.99")
            }),
            "the same address under the prefix production uses is outside \
             every observed subnet"
        );
    }

    /// The network/broadcast exclusion is relative in the same way: it refuses
    /// only while *no* observed subnet can host the address. `10.0.0.15` is the
    /// broadcast of `10.0.0.0/28` and an ordinary host on `10.0.0.0/24`, so a
    /// namespace reporting both accepts it. The one-subnet-accepting rule
    /// applies to boundary addresses too, and a doc claiming a flat "a network
    /// or broadcast address is refused" would be wrong here.
    #[test]
    fn a_boundary_address_is_refused_only_while_no_subnet_can_host_it() {
        assert_eq!(
            gateway_is_on_an_observed_subnet(&[at("10.0.0.3", 28)], ip("10.0.0.15")),
            Err(GatewayRejection::BroadcastAddress {
                gateway: ip("10.0.0.15"),
                base: ip("10.0.0.0"),
                prefix_len: 28,
            }),
            "against the /28 alone it is the broadcast address"
        );
        assert_eq!(
            gateway_is_on_an_observed_subnet(
                &[at("10.0.0.3", 28), at("10.0.0.20", 24)],
                ip("10.0.0.15")
            ),
            Ok(()),
            "a /24 observed beside it hosts .15 perfectly well"
        );
    }

    /// The count the module doc puts on the session `/28`. A number in prose
    /// rots silently when the rules widen — this one was wrong once — so it is
    /// asserted rather than described, together with the two facts it is there
    /// to support: which three of the sixteen are refused, and that the real
    /// `.2` is among the thirteen with nothing marking it out.
    #[test]
    fn a_session_slash_28_admits_thirteen_of_its_sixteen_addresses() {
        let observed = [at("10.0.0.3", 28)];
        let block: Vec<Ipv4Addr> = (0..16u32)
            .map(|offset| Ipv4Addr::from(u32::from(ip("10.0.0.0")) + offset))
            .collect();
        let accepted: Vec<Ipv4Addr> = block
            .iter()
            .copied()
            .filter(|a| gateway_is_on_an_observed_subnet(&observed, *a).is_ok())
            .collect();

        assert_eq!(accepted.len(), 13, "accepted: {accepted:?}");
        let refused: Vec<Ipv4Addr> = block
            .iter()
            .copied()
            .filter(|a| !accepted.contains(a))
            .collect();
        assert_eq!(
            refused,
            vec![ip("10.0.0.0"), ip("10.0.0.3"), ip("10.0.0.15")],
            "the network address, the container's own address and the \
             broadcast address are the three that do not pass"
        );
        assert!(
            accepted.contains(&ip("10.0.0.2")),
            "the session's real gateway is one of the thirteen — the doc's \
             point being that nothing here separates it from the other twelve"
        );
    }

    /// The counterexample the module doc uses to keep its accept condition
    /// from being read as a statement about route installation. Both halves of
    /// it are decided by code in this file, so both are pinned here: the
    /// namespace meets every clause for `10.0.0.2`, and the address that makes
    /// the caller refuse before this module is consulted is refused by this
    /// module's own `is_rfc1918`.
    #[test]
    fn the_doc_counterexample_accepts_while_holding_a_public_address() {
        let observed = [at("203.0.113.5", 24), at("10.0.0.3", 28)];
        assert_eq!(
            gateway_is_on_an_observed_subnet(&observed, ip("10.0.0.2")),
            Ok(()),
            "this module accepts the gateway"
        );
        assert!(
            !is_rfc1918(ip("203.0.113.5")),
            "and the caller's all-addresses-private check refuses this \
             namespace before this module is ever reached"
        );
    }

    // -- the operator-facing text ------------------------------------------

    /// Every rejection names the address it refused. These messages are the
    /// only thing a person debugging a failed session sees, and a message that
    /// says "refused" without saying what was refused costs a debugging round
    /// trip against a VM.
    #[test]
    fn every_rejection_message_names_the_value_it_refused() {
        let gw = ip("10.0.0.15");
        let cases = [
            GatewayRejection::NotPrivate { gateway: gw },
            GatewayRejection::OwnAddress { gateway: gw },
            GatewayRejection::NetworkAddress {
                gateway: gw,
                base: ip("10.0.0.0"),
                prefix_len: 28,
            },
            GatewayRejection::BroadcastAddress {
                gateway: gw,
                base: ip("10.0.0.0"),
                prefix_len: 28,
            },
            GatewayRejection::OutsideEverySubnet { gateway: gw },
        ];
        for case in cases {
            let text = case.to_string();
            assert!(
                text.contains("10.0.0.15"),
                "{case:?} renders without naming the address: {text}"
            );
            assert!(
                text.contains("refusing route install"),
                "{case:?} does not say what it refused to do: {text}"
            );
        }
        let empty = GatewayRejection::NoAddresses.to_string();
        assert!(empty.contains("refusing route install"), "{empty}");
    }
}
