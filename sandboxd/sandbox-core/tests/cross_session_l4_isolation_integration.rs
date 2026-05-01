//! Cross-session L4 isolation.
//!
//! These tests pair with the e2e structural disjoint-subnet check in
//! `tests/e2e/test_m3_networking.py::test_concurrent_sessions`. The e2e
//! test already asserts the daemon hands two concurrent sessions
//! disjoint `vm_subnet`s — the architectural contract on both Lima and
//! container backends. What that test cannot assert behaviourally on
//! the container backend is that a packet from session A's `vm_subnet`
//! targeting session B's `vm_subnet` is actually dropped on the wire:
//! the gateway PREROUTING DNAT (see `gateway.rs:1462-1486`) rewrites
//! every TCP/UDP packet from session A's `saddr` to A's own gateway
//! sinks before it can leave A's bridge, so a TCP probe from inside
//! session A to session B's gateway IP succeeds against A's own
//! deny-logger / CoreDNS regardless of whether B's bridge is reachable.
//! Lima retains an ICMP-based behavioural check (ICMP is not DNAT'd
//! by the prerouting rules), but `CAP_NET_RAW` is dropped on the lite
//! container backend (spec § Hardening) and there is no working ICMP
//! path. Hence the structural integration coverage in this file: it
//! locks in the *forward-chain* shape — for every per-session gateway,
//! the only egress accepts admit either traffic that PREROUTING
//! DNAT'd to that session's *own* gateway IP, or VM-subnet UDP that
//! PREROUTING already filtered against the policy allow-set. Neither
//! match path admits a packet whose `ip daddr` falls inside another
//! session's `vm_subnet`, so cross-session TCP traverses the trailing
//! `reject` and is dropped.
//!
//! The assertion form is **absence-of-accept** rather than an explicit
//! drop rule, because the existing forward chain (see
//! `generate_forward_allow_ruleset` in `gateway.rs:1601`) is encoded
//! as a positive allow-list followed by `reject` — there is no
//! explicit cross-session drop rule, by design. Mirrors the encoding
//! of the existing `test_forward_allow_ruleset` "no TCP blanket
//! accept" guard in `gateway.rs::tests`.
//!
//! These tests are hermetic: they call the public ruleset generators
//! and pattern-match the emitted nft text. No Docker, no Lima — they
//! run in the default `make test` profile alongside the existing
//! gateway structural tests.

use sandbox_core::gateway::generate_forward_allow_ruleset;

/// Two disjoint `/28` subnets in the same `/24` allocation pool used
/// by `NetworkManager` (10.209.0.0/24). Mirrors the layout the daemon
/// hands out to two concurrent sessions.
const SESSION_A_SUBNET: &str = "10.209.0.0/28";
const SESSION_A_GATEWAY: &str = "10.209.0.2";
const SESSION_B_SUBNET: &str = "10.209.0.16/28";
const SESSION_B_GATEWAY: &str = "10.209.0.18";

/// A representative IP inside session B's subnet — used to probe
/// whether session A's forward chain admits a packet targeting
/// anything in B's subnet.
const SESSION_B_VM_IP: &str = "10.209.0.20";

#[test]
fn forward_chain_admits_only_dnatd_traffic_to_own_gateway_ip() {
    // Session A's forward chain must admit traffic destined to A's own
    // gateway IP (the PREROUTING-DNAT sink) and nothing else by daddr.
    // In particular, the per-packet allow rule must NOT contain
    // session B's gateway IP or any IP from session B's subnet.
    let ruleset = generate_forward_allow_ruleset(SESSION_A_SUBNET, SESSION_A_GATEWAY);

    // Positive: A's own gateway-IP allow rule is present.
    assert!(
        ruleset.contains(&format!(
            "ip saddr {SESSION_A_SUBNET} ip daddr {SESSION_A_GATEWAY} accept"
        )),
        "session A's forward chain must admit DNAT'd traffic to its own gateway IP\n\
         ruleset:\n{ruleset}"
    );

    // Negative: session B's gateway IP must not appear anywhere in
    // session A's forward chain — the forward-allow generator is
    // single-session by design and a regression that interpolated a
    // peer's gateway IP would be a hard cross-session leak.
    assert!(
        !ruleset.contains(SESSION_B_GATEWAY),
        "session A's forward chain must not reference session B's gateway IP \
         {SESSION_B_GATEWAY}; cross-session daddr leakage:\n{ruleset}"
    );

    // Negative: session B's subnet literal must not appear in session
    // A's forward chain either.
    assert!(
        !ruleset.contains(SESSION_B_SUBNET),
        "session A's forward chain must not reference session B's subnet \
         {SESSION_B_SUBNET}; cross-session saddr/daddr leakage:\n{ruleset}"
    );
}

#[test]
fn forward_chain_drops_cross_session_tcp_via_absence_of_accept() {
    // Cross-session TCP isolation: session A's forward chain must not
    // admit any TCP packet whose `ip daddr` falls inside session B's
    // subnet. The chain encodes this as **absence of accept** — every
    // TCP-eligible accept rule pins `ip daddr` to A's own gateway IP
    // (or admits only conntrack return traffic), so cross-session TCP
    // falls through to the trailing `reject`.
    let ruleset = generate_forward_allow_ruleset(SESSION_A_SUBNET, SESSION_A_GATEWAY);

    // The chain must end with a `reject` (the catch-all that drops
    // unmatched cross-session TCP).
    assert!(
        ruleset.contains("reject"),
        "forward chain must terminate with `reject` so unmatched \
         cross-session TCP is dropped:\n{ruleset}"
    );

    // Walk every accept rule and assert each TCP-or-untyped accept
    // either (a) admits only return traffic via conntrack, (b) admits
    // wholesale UDP (the documented allow-path datapath, safe because
    // PREROUTING already filtered denied UDP against the policy
    // allow-set), or (c) pins `ip daddr` to
    // session A's own gateway IP. Because session B's subnet is
    // disjoint from A's by construction (NetworkManager allocates
    // distinct /28s out of the 10.209.0.0/24 pool), no accept rule of
    // form (c) can match a packet whose daddr is in B's subnet.
    for raw_line in ruleset.lines() {
        let line = raw_line.trim();
        if !line.contains("accept") {
            continue;
        }
        if line.starts_with('#') {
            continue;
        }
        // (a) Conntrack return-traffic — does not admit cross-session
        // probes (no prior conntrack entry on A's gateway for a
        // packet originating in A and destined to B).
        if line.contains("ct state") {
            continue;
        }
        // (b) Wholesale UDP allow — safe per the allow-path datapath.
        if line.contains("meta l4proto udp") {
            continue;
        }
        // (c) The remaining shape this generator emits is the
        // gateway-IP-pinned DNAT-sink rule:
        //     ip saddr <A_subnet> ip daddr <A_gw_ip> accept
        // Assert the rule pins daddr to A's own gateway IP and
        // therefore cannot match a daddr in B's subnet (disjoint by
        // construction).
        let expected = format!("ip saddr {SESSION_A_SUBNET} ip daddr {SESSION_A_GATEWAY} accept");
        assert!(
            line.contains(&expected),
            "unexpected accept rule shape in forward chain — every TCP-\
             or-untyped accept must pin `ip daddr` to A's own gateway IP \
             ({SESSION_A_GATEWAY}) so cross-session traffic falls through \
             to the trailing `reject`. Offending line:\n  {line}\n\
             full ruleset:\n{ruleset}"
        );
    }

    // Defence in depth: explicitly assert that the cross-session
    // 5-tuple shape — saddr in A's subnet, daddr in B's subnet, no
    // protocol qualifier — has no admitting rule. The forward chain
    // must not contain any rule of form
    // `ip saddr <A_subnet> ip daddr <B_*> accept`.
    let cross_session_admit_b_subnet =
        format!("ip saddr {SESSION_A_SUBNET} ip daddr {SESSION_B_SUBNET} accept");
    let cross_session_admit_b_gateway =
        format!("ip saddr {SESSION_A_SUBNET} ip daddr {SESSION_B_GATEWAY} accept");
    let cross_session_admit_b_vm_ip =
        format!("ip saddr {SESSION_A_SUBNET} ip daddr {SESSION_B_VM_IP} accept");
    assert!(
        !ruleset.contains(&cross_session_admit_b_subnet),
        "forward chain must not contain a cross-session subnet-level admit:\n{ruleset}"
    );
    assert!(
        !ruleset.contains(&cross_session_admit_b_gateway),
        "forward chain must not contain a cross-session admit for B's gateway IP:\n{ruleset}"
    );
    assert!(
        !ruleset.contains(&cross_session_admit_b_vm_ip),
        "forward chain must not contain a cross-session admit for an IP in B's subnet:\n{ruleset}"
    );
}

#[test]
fn each_session_forward_chain_only_references_its_own_subnet_and_gateway() {
    // Generate the forward chain for both sessions and assert each
    // ruleset only references its own session's identifiers. This is
    // the structural counterpart to the e2e disjoint-subnet check:
    // even though each session's gateway is a distinct container
    // (and so the rulesets are never co-resident), the generator
    // itself must not accidentally bake in another session's subnet
    // or gateway IP.
    let a = generate_forward_allow_ruleset(SESSION_A_SUBNET, SESSION_A_GATEWAY);
    let b = generate_forward_allow_ruleset(SESSION_B_SUBNET, SESSION_B_GATEWAY);

    // A's ruleset references only A's identifiers.
    assert!(
        a.contains(SESSION_A_SUBNET),
        "session A's ruleset must reference its own subnet:\n{a}"
    );
    assert!(
        a.contains(SESSION_A_GATEWAY),
        "session A's ruleset must reference its own gateway IP:\n{a}"
    );
    assert!(
        !a.contains(SESSION_B_SUBNET),
        "session A's ruleset must not reference session B's subnet:\n{a}"
    );
    assert!(
        !a.contains(SESSION_B_GATEWAY),
        "session A's ruleset must not reference session B's gateway IP:\n{a}"
    );

    // B's ruleset references only B's identifiers.
    assert!(
        b.contains(SESSION_B_SUBNET),
        "session B's ruleset must reference its own subnet:\n{b}"
    );
    assert!(
        b.contains(SESSION_B_GATEWAY),
        "session B's ruleset must reference its own gateway IP:\n{b}"
    );
    assert!(
        !b.contains(SESSION_A_SUBNET),
        "session B's ruleset must not reference session A's subnet:\n{b}"
    );
    assert!(
        !b.contains(SESSION_A_GATEWAY),
        "session B's ruleset must not reference session A's gateway IP:\n{b}"
    );
}
