# UDP datapath honesty + kernel-layer audit logging

**Date:** 2026-05-01
**Status:** proposed
**Driving milestone:** M12-S2 (sandbox daemon)
**Supersedes:** none — first design spec on this surface
**Related specs:**

- `.tasks/specs/2026-04-19-l3-envoy-mitmproxy-flow-design.md` — establishes the
  Envoy-as-sole-TCP-entry-point invariant; this spec narrows that
  invariant to TCP only and explicitly excludes UDP from the Envoy
  pipeline.
- `.tasks/specs/2026-04-21-port-explicit-policies-presets-observability-design.md`
  — defines the deny-logger component this spec splits and renames.
- `docs/internal/m12-s1-udp-audit.md` — the read-only audit produced
  during M12-S1 that this spec acts on.

## Summary

M12-S1 fixed UDP deny-event attribution by adding a netfilter conntrack
netlink lookup inside the deny-logger's UDP receive loop. That landed
the immediate user-visible bug (every UDP deny event carried
`gateway_ip:10002` as the destination) but the audit it depended on
surfaced three deeper truths the previous design papered over:

1. The UDP **allow path** through Envoy is structurally dead. Envoy
   has no UDP listener and the gateway input chain rejects
   `udp dport 10000`. The `policy_allow_udp` concat set DNATs UDP into
   that dead end, and the M9-S19 L3 spec's "all TCP through Envoy"
   invariant has been silently extrapolated into "all transport through
   Envoy" — which was never true for UDP.
2. The UDP **deny path** runs through a userland UDP listener on
   `:10002` whose only job is to `recv()` and discard the datagram so
   that the conntrack lookup in step (1) of the receive loop can
   recover the pre-DNAT destination. There is no protocol-level reason
   for that listener to exist — UDP has nothing to "respond to" — and
   the lookup itself is bookkeeping the kernel already does.
3. There is **no audit-flow logging for allowed UDP** today. Allowed
   UDP transits PREROUTING → MASQUERADE silently, leaving an asymmetry
   with TCP (where Envoy emits an access-log record per L1/L2/L3
   admission).

This spec resolves all three at once by realigning UDP with what nft
and the kernel can already tell us, without adding userland datapath:

- The allowed-UDP path goes **direct to upstream** through nft. No
  Envoy hop. The original intent in `networking-design.md:479,1395`
  ("UDP policy is enforced purely by nftables ... no userland proxy")
  becomes literally true.
- The denied-UDP path moves from **DNAT-to-listener** to
  **`nft drop` with NFLOG copy**. The kernel emits a netlink message
  with the original 5-tuple; the deny-logger subscribes to that
  group and emits the JSONL deny event. No DNAT, no userland datagram
  reception, no conntrack lookup.
- The allow-flow audit gap is closed by subscribing to
  `nfnetlink_conntrack`'s `NFNLGRP_CONNTRACK_NEW` multicast group,
  filtered for UDP. The kernel already emits one event per new flow;
  the new logger turns those into JSONL audit records.
- The single `sandbox-deny-logger` binary splits into a shared lib
  crate (`sandbox-event-emitter`) plus two binaries:
  `sandbox-nft-deny-logger` (NFLOG-driven UDP deny + the existing TCP
  listener path) and `sandbox-nft-allow-logger` (NFCT-driven allow
  audit). The `nft-` prefix signals that the data source is the
  kernel/nft layer rather than a userland L7 proxy — a property both
  binaries share and one operators need to know about when they reason
  about UDP observability limits.

This is not a feature addition; it is a structural correction. It
brings the implementation back into line with the original networking
design and removes a userland surface that exists only to launder the
kernel's own bookkeeping.

## Background

### What M12-S1 left in place

M12-S1 took the path the audit doc explicitly framed as the immediate
fix: replace the cmsg-based pre-DNAT recovery in the UDP receive loop
with a netfilter conntrack netlink lookup. The implementation lives at
`sandboxd/sandbox-deny-logger/src/conntrack.rs` (hand-rolled
`IPCTNL_MSG_CT_GET` request/reply on a `NETLINK_NETFILTER` socket) and
is called from `sandboxd/sandbox-deny-logger/src/udp.rs:111-141` once
per received datagram. The Phase 8 test that knowingly asserted the
wrong post-DNAT tuple was rewritten; a load-style integration test was
added.

That work did not — and was not asked to — touch the surrounding
nftables shape, the Envoy listener, or the rationale for why a UDP
listener exists at all. The audit doc was explicit: M12-S1 is the
attribution fix; M12-S2 is "what does *allow UDP* actually mean today?"
and the doc reconciliation that follows.

### Three findings the audit surfaced

Each of the three S2 problems traces back to a numbered audit finding.
Citations are `audit-doc:line` against
`docs/internal/m12-s1-udp-audit.md`.

**Allow-path is structurally dead** (audit §3.b1, §1.6, §1.8 row
"Allow path"). The PREROUTING chain DNATs `policy_allow_udp` matches
to `gateway_ip:10000`
(`sandboxd/sandbox-core/src/policy.rs:756`,
`sandboxd/sandbox-core/src/gateway.rs:1473`). The input chain accepts
UDP only on `:53` and `:10002`
(`sandboxd/sandbox-core/src/gateway.rs:1537,1547`). `udp dport 10000`
is rejected at INPUT. Envoy on `:10000` is TCP-only by configuration
(`sandboxd/sandbox-core/src/policy.rs:1796-1827`); even if a UDP
packet survived INPUT it would arrive at a socket no Envoy worker is
listening on. The DNS-propagation-driven population of
`policy_allow_udp`
(`sandboxd/sandbox-core/src/dns_propagation.rs:368-403`) is doing
correct compile-time bookkeeping for a runtime path that doesn't
exist. The `tests/e2e/test_m4_policy.py:321` allow-path test passes
only because UDP/53 is special-cased to CoreDNS earlier in the chain
(`policy.rs:751`), bypassing the `policy_allow_udp` rule entirely.

**Deny-path runs a useless userland listener** (audit §1.4, §2.3,
§5 "Deny-attribution-related"). After M12-S1, the UDP receive loop's
contribution to the deny event is the post-DNAT 4-tuple
`(vm_ip:vm_port, gateway_ip:10002)` plus a fixed-size discard buffer.
The pre-DNAT destination — the only attribution-relevant field that
isn't already in the 4-tuple — comes from a netlink lookup the kernel
serves out of the conntrack entry it created when DNAT fired. The
listener never reads the payload, never sends a response, and exists
solely so that there is an `(src, dst)` pair to feed into the
conntrack lookup. The kernel already had the original 5-tuple at
PREROUTING time, before DNAT mutated it; surfacing that tuple via
NFLOG instead of reconstructing it via NFCT would make the listener
unnecessary.

**No allow-flow audit log** (audit §1.8, §5 cross-reference). Allowed
UDP transits PREROUTING → POSTROUTING (MASQUERADE) → upstream and
leaves no observable record. TCP allow-path admission is logged by
Envoy's access log at three of the four pipeline exits (L1, L2, L3 via
mitmproxy). UDP has no equivalent because there is no userland process
in its allow path — and the spec position is now that there *should
not* be one. The data source we want is the kernel itself: conntrack
emits a netlink event for every new tracked flow, and we already have
`CAP_NET_ADMIN` in the gateway container (audit §2.4 confirms).

The doc-drift symptoms catalogued in audit §4 (`docs/concepts/-
networking.md:141` overclaim, `networking-design.md:1395` "purely
nftables" promise, `networking-design.md:1221` ICMP-unreachable mandate
that doesn't match the silent-drop reality) are downstream of these
three: each is a place where the design described an end-state the
implementation drifted away from. Closing all three drifts is part of
this spec's scope.

### Why now, and why together

The four pieces — kill the dead allow-path DNAT, kill the listener,
add NFCT allow-logging, rename + split the binaries — could in
principle ship as four sequential PRs. They are bundled here because:

- Each piece individually leaves the deny-logger binary in a worse
  position than the current S1-frozen state. Removing the UDP
  listener without an NFLOG subscriber drops UDP attribution. Adding
  the NFLOG subscriber without removing the listener doubles the
  emit pipeline. Renaming the binary without splitting it leaves the
  lib-crate refactor as a follow-up that has to chase the rename.
- The doc reconciliation (Decision 6) is genuinely cross-cutting:
  every doc that mentions UDP today is wrong in a way that exactly
  one of these decisions makes right.
- Operators who upgrade across this milestone see one named change
  ("UDP datapath corrected and split-logged") rather than four
  small changes whose order matters.

## Goals and non-goals

### Goals

1. **Honest UDP datapath.** Allowed UDP traverses no userland
   process. Denied UDP traverses no userland process *for the deny
   itself* — the kernel drops it; userland only observes the drop.
2. **Audit-log parity for UDP.** A daemon consumer can correlate an
   allowed UDP flow back to a session-attributable record, just as it
   can for an allowed TCP connection via the Envoy access log.
3. **Pre-DNAT attribution by construction, not reconstruction.** The
   pre-DNAT 5-tuple of a denied UDP datagram is reported by the
   kernel at the moment of the drop, before DNAT (which no longer
   fires for the deny path) could mutate it.
4. **Naming that signals the gating layer.** The two binaries carry an
   `nft-` prefix; nothing in their name implies they observe an L7
   stream.
5. **Doc reconciliation.** Every UDP overclaim in user-facing and
   internal docs is reconciled against the new behaviour.

### Non-goals

- **TCP datapath changes.** TCP allow-path through Envoy stays. TCP
  deny-path through the listener (`SO_ORIGINAL_DST` + RST close) stays.
  The TCP side of the deny-logger binary moves into
  `sandbox-nft-deny-logger` unchanged.
- **L7 inspection of UDP.** UDP cannot be MITM'd or HTTP-inspected
  (audit §1.7, `docs/guides/network-policies.md:174`). This spec
  affirms that limitation; it does not try to work around it.
- **Conntrack recv-buffer hardening (#113), `iter_nlas` allocation
  reduction (#116), audit-log-into-/health (#112).** All deferred to
  M12-S9 or later. Decision 5's lib crate makes these tractable but
  doesn't perform them.
- **ICMP-unreachable behaviour.** `nft drop` is silent today and stays
  silent under this spec; the `networking-design.md:1221` mandate is
  reconciled to "silent drop" with rationale. Adding
  `nft reject with icmp port-unreachable` is called out as an Open
  Question (§Open questions) for the user to decide before
  implementation; the default behaviour proposed below is
  silent-drop.
- **Removing the existing `policy_allow_udp` set or its DNS-propagation
  population.** The set continues to exist and continues to be
  populated — but the rule it backs DNATs nothing, it `accepts` and
  lets MASQUERADE handle the egress. Decision 1 below covers the
  rule-shape change; the set itself is unchanged on disk, which keeps
  rollback and forward-compat clean.
- **IPv6.** IPv4-only, unchanged.

## Decisions

The six decisions below were settled in the planning conversation; this
section records them as the contract. Each decision states the change,
the rationale, the alternatives considered and rejected, and the
concrete code/test/doc impact.

### Decision 1 — UDP allow-path skips Envoy entirely

**Decision.** Reshape the `sandbox_dnat` PREROUTING chain so that a
match on `policy_allow_udp` results in `accept` (or its equivalent
"no further DNAT, let POSTROUTING masquerade") rather than
`dnat to gateway_ip:10000`. The packet leaves the gateway via the
existing MASQUERADE rule on `postrouting` and reaches the upstream
host directly. Envoy is not in the path.

**Rationale.** Three independent reasons:

- **The current DNAT is structurally dead.** As §Background and
  audit §1.6 establish, even if a UDP packet hits the
  `policy_allow_udp` match and gets DNATted to `gateway_ip:10000`,
  the input chain rejects `udp dport 10000`
  (`gateway.rs:1547` covers `:10002` only) and Envoy has no UDP
  listener bound on `:10000` anyway. The DNAT rule, the input-chain
  accept that would need to admit it, and the Envoy listener
  config that would need to receive it form a triple-empty stack.
- **L7 inspection is not available for UDP.** Even if all three were
  fixed, Envoy's `tcp_proxy` filter chain and mitmproxy's CONNECT
  tunnel are TCP-only by construction
  (`sandboxd/sandbox-core/src/policy.rs:1796-1827`,
  `.tasks/specs/2026-04-19-l3-envoy-mitmproxy-flow-design.md`). UDP
  cannot be MITM'd, has no equivalent of HTTP CONNECT, and has no
  per-flow accept fd that would let `SO_ORIGINAL_DST` work for
  Envoy in the way it does for TCP. Routing UDP through Envoy buys
  zero L7 capability.
- **The original design said exactly this.** `networking-design.md:479`
  and `:1395` both say "UDP traffic is handled purely by nftables
  rules ... no userland proxy is involved." The DNAT-to-Envoy rule
  was forward-compat scaffolding (audit §3.c4) that drifted into
  looking like a live path.

**Alternatives rejected.**

- *(a)* **Add a UDP listener to Envoy + accept on the input chain.**
  Preserves the "everything through Envoy" architectural symmetry
  but adds Envoy `udp_listener_config`, a new filter chain shape, an
  input-chain accept rule for `udp dport 10000`, and runtime
  test/observability surface — all to gain zero L7 capability. The
  symmetry isn't a property of the design; the design was always
  "TCP through Envoy, UDP through nft." (a) is more code for less
  honesty.
- *(c)* **Remove the allow-path entirely** (treat UDP as deny-only).
  Removes the claimed allow capability that the policy schema
  exposes (`Protocol::Udp` is a valid first-class enum variant —
  `sandbox-core/src/policy.rs:2909`) and that
  `docs/concepts/policy-model.md:60,108,159` documents. Plan
  revision required, much larger scope.

(b), the chosen path, is the smallest change that makes the
implementation honest about a property the design has always claimed.

**Code/test/doc impact.**

- Modify `sandbox_dnat` shape in
  `sandboxd/sandbox-core/src/gateway.rs:1473` and the matching
  policy-compiled site at `sandboxd/sandbox-core/src/policy.rs:756`.
  The rule keyed on `@policy_allow_udp` becomes a non-DNAT accept
  (the precise nft verb is implementation-phase detail; one option
  is `meta l4proto udp ip daddr . udp dport @policy_allow_udp accept`
  on the prerouting chain, which short-circuits the catch-all DNAT
  below it).
- Verify the catch-all `meta l4proto udp dnat to gateway_ip:10002`
  rule (`gateway.rs:1479`, `policy.rs:760`) is removed — Decision 2
  replaces it with an NFLOG drop.
- The forward chain (`gateway.rs:1565`,
  `generate_forward_allow_ruleset`) will need to admit allowed UDP
  flowing through to MASQUERADE rather than rejecting it as
  non-DNATted (audit §1.1: "any non-DNATted UDP is rejected at
  FORWARD"). The exact rule is implementation-phase, but the goal
  is: allowed UDP is forwarded to upstream; everything else falls
  through to Decision 2's NFLOG drop.
- The DNS-DNAT rule (`gateway.rs:1466`, `policy.rs:751`) is
  unchanged — DNS to CoreDNS is not "the UDP allow path" in the
  policy sense, it's a system-level interception (audit §1.1 rule
  1).
- E2E: `tests/e2e/test_m4_policy.py:321 — test_level1_transport_udp`
  must continue to pass without relying on the special-cased DNS
  DNAT. Audit §5 notes it currently uses DNS, which is special; we
  add a non-DNS UDP allow case (e.g. NTP/UDP-123, audit §3.c1)
  whose path goes through `policy_allow_udp` proper.
- Docs: `docs/concepts/networking.md:191` "redirected to the
  deny-logger" prose is now correct only for denied UDP (and via
  NFLOG, see Decision 2); allowed UDP "exits at nft" needs explicit
  prose. Reconciliation in Decision 6.

### Decision 2 — UDP deny-path switches from DNAT-to-listener to NFLOG

**Decision.** Replace the catch-all PREROUTING rule that DNATs
unmatched UDP to `gateway_ip:10002` with an `nft log group N ; drop`
rule (or equivalent two-rule NFLOG-then-drop sequence). The kernel
emits one netlink message per matched packet on NFLOG group `N`
carrying the full IPv4 + UDP headers. The packet is dropped at nft;
it never enters userland datapath. A receive loop in the (renamed)
`sandbox-nft-deny-logger` binary subscribes to NFLOG group `N`, parses
the netlink message, and emits the JSONL deny event with the original
5-tuple straight from the headers.

**Rationale.**

- **The userland UDP listener exists only to launder the kernel's
  bookkeeping.** Its `recv()` discards the payload (audit §1.4 / `udp.rs:34,62-87`)
  and its only contribution to the deny event is the post-DNAT
  `(src, dst)` 4-tuple, which the conntrack lookup in
  `conntrack.rs` then translates back into the pre-DNAT 5-tuple
  the kernel already had at PREROUTING time. NFLOG carries that
  pre-DNAT 5-tuple natively (it logs at the chain hook before DNAT
  rewrites the destination *if* the log rule is placed before the
  DNAT — under this spec there is no DNAT-for-deny so this isn't a
  concern).
- **Eliminating the listener removes a class of failure modes.** UDP
  recv buffer truncation (audit §3.c2 / `udp.rs:34`), the absence
  of per-source rate-limiting on the listener (audit §3.c1), and
  the conntrack-race fallback path (`udp.rs:114-138`) all go away
  because the listener goes away.
- **The conntrack lookup module becomes obsolete on the UDP-deny
  path.** Important note for readers coming from the M12-S1
  context: `sandbox-deny-logger/src/conntrack.rs` is referenced
  *only* from `udp.rs` and `main.rs` (verified by grep against the
  workspace). TCP-deny in `tcp.rs:222-249` uses
  `getsockopt(SOL_IP, SO_ORIGINAL_DST)` and has never touched the
  conntrack module. Once UDP-deny moves to NFLOG, the conntrack
  module has no in-tree caller — the implementation phase will
  decide whether to delete it or keep it for the audit-allow path
  (it isn't useful there either, since NFCT events carry the tuple
  directly; deletion is the likely outcome).
- **TCP-deny stays listener-based, unchanged.** TCP needs a real
  socket to send a clean RST (`tcp.rs:251-265`) and `SO_ORIGINAL_DST`
  is the TCP-native pre-DNAT recovery path (`tcp.rs:222-249`); both
  work correctly today. Splitting the deny-logger binary does not
  alter the TCP datapath. The TCP listener moves wholesale into
  `sandbox-nft-deny-logger`.

**Alternatives rejected.**

- **Keep the listener, just to keep the binary structure.** Loses
  the entire reason to do this work — the listener is the userland
  surface that shouldn't exist. Strictly worse than the status quo
  on the dimensions that matter (one more failure surface, no new
  capability).
- **Use NFQUEUE (`nft queue num N`) instead of NFLOG.** NFQUEUE is
  for *deciding* whether to accept/drop in userland. We have already
  decided (the policy compiler ran). NFQUEUE adds a userland verdict
  step that's not needed and a verdict-timeout failure mode that
  blocks traffic. NFLOG is observe-only by design.
- **Use plain `nft log` (printk to dmesg) without the NFLOG
  netlink stream.** Loses structured access to the headers; we'd
  parse strings out of `dmesg`. Strictly worse.

**Code/test/doc impact.**

- Add NFLOG group `N` rule to `sandbox_dnat.prerouting`
  (`gateway.rs:~1479`, `policy.rs:~760`). The exact placement and
  the value of `N` are implementation-phase detail; an Open
  Question is logged below for the group-number choice.
- Delete the catch-all `... dnat to gateway_ip:10002` rule.
- Delete the `udp dport 10002 accept` rule on the input chain
  (`gateway.rs:1547`) — there is no longer a process listening on
  that port.
- The `sandbox-nft-deny-logger` binary loses its UDP listener
  (`udp.rs::bind` and `udp.rs::run` deleted) and gains an NFLOG
  receive loop on a new netlink socket
  (`NETLINK_NETFILTER`, NFNLGRP_NFLOG_BIND family — implementation
  detail). The TCP listener path is unchanged.
- The `conntrack.rs` module loses its only caller. Implementation
  phase decides keep-or-delete; recommended: delete (its tests
  travel with it). If kept, it must be marked clearly as "no
  in-tree caller, retained for…" with a reason, otherwise it'll
  rot.
- Tests: the integration test
  `integration_udp_send_to_non_allowlisted_destination_emits_deny_event`
  (`sandboxd/sandboxd/tests/m10_s3_end_to_end.rs:610`) still asserts
  the same wire-shape (a JSONL deny event with the right pre-DNAT
  5-tuple) but the data source under test changes from "UDP
  listener + conntrack lookup" to "NFLOG receive". The S1
  load-style test
  (`integration_udp_load_pre_dnat_attribution_holds_under_concurrent_flows`)
  similarly retargets to NFLOG.
- Docs: `docs/concepts/networking.md:127-130, 141, 191` references
  to "the deny-logger UDP listener" need to read "kernel-emitted
  NFLOG events parsed by the nft-deny-logger" or similar. Spelled
  out in Decision 6.

### Decision 3 — UDP allow-path audit logging via `NFCT_T_NEW`

**Decision.** Add a new netlink subscription to
`nfnetlink_conntrack`'s `NFNLGRP_CONNTRACK_NEW` multicast group,
filtered for UDP flows. The kernel emits one event per new tracked
flow; the new `sandbox-nft-allow-logger` binary parses each event's
original-direction tuple and emits a JSONL allow-event record
analogous to the existing deny event (same emitter, different
`event` discriminator).

**Rationale.**

- **Per-flow is the right granularity.** The TCP allow-path audit
  signal is per-connection (Envoy access log: one record per
  accepted connection). UDP's analogue is per-flow, which conntrack
  already maintains for us. Per-packet would be too noisy and would
  redundantly log every datagram in a long-running flow.
- **The data source is already enabled.** Audit §2.4 verified that
  the conntrack subsystem is loaded inside the gateway container as
  part of the existing M12-S1 work; no new module load, no new
  capability bump. `CAP_NET_ADMIN` is already in the run flags.
- **The kernel does the filtering for us.** NFCT events expose the
  L4 protocol in the original tuple; we filter for UDP at parse
  time and skip the rest (TCP NEW events would arrive too, but TCP
  has Envoy doing the equivalent logging — we don't want
  double-counting).

**The 30-second-timeout property must be documented.** Plain UDP
flows are tracked by conntrack with a default timeout of 30 s
(kernel sysctl `net.netfilter.nf_conntrack_udp_timeout`). A UDP
"session" — there is no session in the protocol; this is the
conntrack-flow construct — that goes silent for ≥30 s and then
resumes on the same 5-tuple will trigger conntrack to age the
existing entry out and create a new one on the next packet, firing a
second `NFCT_T_NEW` event. The audit log will show two allow records
for what an operator might colloquially call "one session." This is
not a bug; it is the property of UDP-via-conntrack and is the same
reason the kernel's own `conntrack -L` walk-output shows the same
shape. The doc reconciliation (Decision 6) calls this out in
`docs/guides/troubleshooting.md` as a UDP-specific behaviour to
expect.

**Alternatives rejected.**

- **Per-packet UDP allow-logging via a second NFLOG group on the
  allow rule.** Strictly more events, no extra information for
  flows that span multiple packets. Operator surface area
  (rate-cap pressure, JSONL volume) goes up sharply for no audit
  win.
- **Sample conntrack via periodic `conntrack -L` polling.** Loses
  events for flows that come and go between polls. Adds a process
  scheduler dependency. Strictly worse than the streaming
  multicast subscription.
- **Have the allow-logger sniff on the bridge interface
  (libpcap).** Adds a packet-capture privilege requirement,
  duplicates the kernel's flow tracking, and would re-parse
  packets the kernel has already classified. Rejected.

**Code/test/doc impact.**

- New binary `sandbox-nft-allow-logger` (Decision 4 names it; this
  decision describes its function).
- One netlink socket per process subscribed to
  `NFNLGRP_CONNTRACK_NEW`. Implementation choice between
  `netlink-sys` (consistent with the M12-S1 conntrack module) and
  `netlink-packet-netfilter` (since the published v0.2.0 covers
  nfnetlink_log/conntrack subscriptions even where it didn't cover
  the synchronous CT_GET path) is an implementation-phase call;
  the design here is data-source-agnostic.
- JSONL emitted via the shared `sandbox-event-emitter` lib
  (Decision 5). Wire shape is decided in implementation; the
  envelope round-trips through the same DTO/event-mapper code as
  the existing deny event (`sandbox-core/src/api/event_mapper.rs`,
  `sandbox-core/src/events/envelope.rs`,
  `sandbox-core/src/events/ingest/deny_logger.rs`) so daemon-side
  ingest is a small additive change, not a new pipeline.
- Tests: a new integration test that exercises an allowed UDP flow
  end-to-end and asserts an allow event lands with the right
  5-tuple. A unit-level test for the 30s-rollover property is
  optional and gated on whether the implementation can synthesise
  a fast-rollover scenario hermetically (probably not — file as a
  follow-up if needed).
- Docs: `docs/concepts/policy-model.md:60,108,159`,
  `docs/guides/network-policies.md`, `docs/guides/troubleshooting.md`
  all need a UDP audit-log mention. Reconciliation in Decision 6.

### Decision 4 — Naming: `sandbox-nft-deny-logger` and `sandbox-nft-allow-logger`

**Decision.** Rename the existing `sandbox-deny-logger` crate and
binary to `sandbox-nft-deny-logger`. Add a new crate and binary
`sandbox-nft-allow-logger` for Decision 3's audit-flow logger. Both
share the lib crate from Decision 5.

**Rationale.** The current name is silent on a property operators
need to know about: the data source is the kernel/nft layer, not an
L7 proxy. The TCP side of the deny-logger reads `SO_ORIGINAL_DST` on
an accepted socket — that's a kernel/conntrack signal, not an L7
read. Once UDP-deny moves to NFLOG (Decision 2) and UDP-allow is
added via NFCT (Decision 3), all three observation paths are
kernel-sourced. The `nft-` prefix is honest about what these
binaries can and cannot tell you: protocol-level facts about the
flow (5-tuple, verdict, timestamp), but nothing about payload
content. Tied to the doc reconciliation in Decision 6, the prefix
becomes a recognisable signal of "kernel-layer observability,
asymmetric to Envoy's L7 access log."

The audit doc explicitly framed the problem as "the existing name
hides the gating layer" (audit §3.b3, §4.1 — both about doc claims
that confuse kernel and proxy signals).

**Alternatives rejected.**

- **One multi-modal binary `sandbox-nft-logger` with deny + allow
  modes selected by flag.** Operationally awkward: both modes need
  to run simultaneously in the gateway container, so operators
  would launch the same binary twice with different flags, and a
  single supervision unit would cover heterogeneous failure modes.
  The user explicitly preferred separate binaries during planning
  for: independent failure domains (NFLOG group goes down vs. NFCT
  subscription goes down), distinct supervisor / restart policies
  possible per source, cleaner ownership boundaries — each binary
  owns one event source.
- **Keep the existing name, add `sandbox-nft-allow-logger`
  alongside.** Inconsistent — half the matched-pair carries the
  prefix, half doesn't. Also leaves the audit-§4.1 doc overclaim
  in place: anything keyed on the binary name still has to qualify
  what its data source is. Bundling the rename here is the right
  call.
- **`sandbox-flow-logger` / `sandbox-conn-logger`.** Less specific
  about the data source; "flow" and "conn" don't tell you the
  layer. The whole point of the rename is layer-honesty.

**Code/test/doc impact.**

- Crate rename in `sandboxd/Cargo.toml` workspace members and the
  crate dir itself (`sandboxd/sandbox-deny-logger/` →
  `sandboxd/sandbox-nft-deny-logger/`). The `[[bin]] name` field
  in the sub-crate's `Cargo.toml` similarly flips
  (`sandbox-deny-logger` → `sandbox-nft-deny-logger`).
- New crate `sandboxd/sandbox-nft-allow-logger/` with its own
  `Cargo.toml` and a thin `src/main.rs` that initialises the
  shared lib and runs the NFCT subscriber.
- Gateway container build: Dockerfile stage 2 builder (the
  `deny-logger-builder` stage,
  `networking/gateway/Dockerfile:36-45`) now produces two binaries.
  The `cargo build --release -p ...` invocation runs twice (or
  once across both packages). Both binaries are installed in stage
  3.
- Gateway entrypoint (`networking/gateway/entrypoint.sh:213-218`)
  starts both binaries in sequence. The `wait_for_ready` block
  (`:223`) extends to probe both `/health` endpoints. Process
  monitoring (`:259`) tracks both PIDs. Shutdown order (`:72`)
  similarly extends.
- `/health` endpoint paths: the deny-logger today serves
  `/health` on its bind IP at port `:10003`
  (`sandbox-deny-logger/src/health.rs:157`). The renamed binary
  keeps that. The allow-logger gets a different port —
  implementation-phase choice, suggested `:10004` for adjacency,
  but not load-bearing in this spec.
- Documentation references to the binary name in
  `docs/concepts/networking.md:141`,
  `docs/guides/troubleshooting.md`, the M9-S19 spec
  (`.tasks/specs/2026-04-19-l3-envoy-mitmproxy-flow-design.md`),
  the M10-S3 spec
  (`.tasks/specs/2026-04-21-port-explicit-policies-presets-observability-design.md`),
  and the milestone files
  (`docs/internal/milestones/M*.md`) all need a sweep. The grep
  pattern is straightforward (`sandbox-deny-logger`); the
  reconciliation lands in Decision 6.
- Integration tests: every test that references the binary by
  name (`integration_*` tests in `sandboxd/sandboxd/tests/`,
  fixture loaders, `make` targets) gets retargeted. Test bodies
  that assert on JSONL `event` types (`deny`, `rate_limited`,
  and now `allow`) are wire-shape independent of the binary
  name.

The rename is a breaking change for anyone scripting against the
binary name, but sandboxd has no production users (the
`docs/internal/m12-s1-udp-audit.md` and the L3 spec both note this
explicitly); the change is intra-tree only.

### Decision 5 — Shared lib crate `sandbox-event-emitter`

**Decision.** Extract a lib crate `sandbox-event-emitter` from the
existing deny-logger crate, owning the cross-cutting infrastructure
both binaries need: the JSONL writer
(`sandbox-deny-logger/src/event.rs::EventEmitter`), the per-process
rate cap (`limits.rs::RateCap`), the periodic
`rate_limited`-summary flush ticker (`limits::spawn_flush_ticker`),
the `/health` endpoint shape (`health.rs`), and shared file/path
handling. Both binaries depend on it.

The conntrack-lookup module (`conntrack.rs`) is **not** moved into
the lib: per Decision 2 it loses its only caller and is the strongest
deletion candidate. If retained for any reason, it stays in the
deny-logger binary's tree (it has no reuse value for the allow-logger,
which uses NFCT events that already carry the tuple).

**Rationale.**

- **Avoid duplication.** Both binaries emit JSONL with the same
  envelope shape (the event-mapper round-trip in
  `sandbox-core/src/api/event_mapper.rs`,
  `sandbox-core/src/events/envelope.rs` is wire-shape-keyed; the
  emitter writes the wire shape). Both need rate-capping (a
  high-rate UDP storm hitting deny *or* a high-fan-out service
  generating allow events). Both need a `/health` endpoint for the
  gateway entrypoint's readiness probe.
- **Preserve the wire-shape contract.** The `EventEmitter` already
  has tests that pin the JSONL line shape
  (`event.rs:187 deny_line_has_required_fields_and_snake_case`)
  and the rate-cap counter behaviour
  (`event.rs:238 gauge_increments_on_emit_and_resets`). Moving
  these into a lib lets us extend the envelope (add `event:
  "allow"`) without forking the contract.
- **Two binaries, not one.** As established in Decision 4: the user
  explicitly preferred two binaries for failure-domain isolation
  and supervision clarity. The lib-crate factoring is what makes
  that preference cheap.

**Alternatives rejected.**

- **Don't extract a lib; copy-paste the JSONL writer.** Strictly
  worse. The wire-shape contract is the single most important
  invariant in this surface and copy-pasting it is a regression
  waiting to happen.
- **Move the conntrack module into the lib crate too.** It has one
  caller (Decision 2 removes that one). Putting it in the lib gives
  it visibility it doesn't earn. If a future component genuinely
  needs synchronous conntrack lookup, the module can be revived as
  a lib at that point — and revived honestly, not as dead-code lib
  inheritance.
- **Lift `/health` into a generic shared HTTP server.** The current
  `/health` shape is one JSON endpoint, ~150 LOC, used by both
  binaries identically. Generalising it is yang for which we have
  no demand.

**Code/test/doc impact.**

- New crate `sandboxd/sandbox-event-emitter/` (lib only — no
  `[[bin]]`).
- Migrate `event.rs`, `limits.rs`, `health.rs` modules into it.
  Public surface: `EventEmitter`, `RateCap`,
  `spawn_flush_ticker`, the protocol enum, the `DenyRecord` and
  (new) `AllowRecord` types, the health server's `bind/run`
  helpers.
- `sandbox-nft-deny-logger` and `sandbox-nft-allow-logger` depend
  on it via path or workspace-member dependency.
- Existing tests in `event.rs` and `limits.rs` move with the code
  and continue to pin the same invariants.
- The `event:` discriminator gains a new `allow` variant.
  Round-trip tests in
  `sandbox-core/src/api/event_mapper.rs`,
  `sandbox-core/src/events/envelope.rs`, and
  `sandbox-core/src/events/ingest/deny_logger.rs` extend
  additively; the `deny`-shape tests stay green untouched.

### Decision 6 — Doc reconciliation folded in

**Decision.** Update every doc that overclaims, mis-claims, or
silently relies on the old UDP behaviour. Reconciliation lands in the
same milestone session as the code; it is in scope for S2, not a
follow-up.

**Rationale.** Each affected doc is wrong in a way *exactly* one of
Decisions 1-5 fixes. Splitting the doc reconciliation into a follow-up
session would mean the docs are wrong for the duration between code
landing and doc-PR landing, and any user reading the doc in that
window draws wrong conclusions. Bundling them costs little — the doc
edits are concrete, line-anchored, and the diffs are small.

**Concrete reconciliations.**

1. **`docs/concepts/networking.md:141`** —
   *"recovers the pre-DNAT destination via `SO_ORIGINAL_DST` /
   `IP_ORIGDSTADDR`"*. Today this is a TCP-only truth dressed up as
   a TCP/UDP truth (audit §4.1, §3.b3). After this spec the line
   reads, in spirit: "TCP via `SO_ORIGINAL_DST` on the accepted
   socket; UDP-deny via NFLOG (which carries the original 5-tuple
   at deny time, before any DNAT could mutate it); UDP-allow via
   NFCT events on `NFNLGRP_CONNTRACK_NEW`."
2. **`networking-design.md:1395`** — *"UDP policy is enforced
   purely by nftables (IP/port allow/deny) with no userland
   proxy"*. Today this is contradicted by the deny-logger UDP
   listener in the deny path (audit §4.7). After Decision 1 + 2 it
   is genuinely true (no userland datapath; the NFLOG / NFCT
   loggers are observe-only audit consumers, not proxy elements).
   The line stays as written; the doc that explains the deny path
   is updated to clarify "observe-only NFLOG audit, not in the
   datapath."
3. **`networking-design.md:1221`** — *"use REJECT (TCP RST for TCP,
   ICMP unreachable for UDP) rather than DROP where possible"*.
   `nft drop` is silent (audit §4.8). The reconciliation has two
   options:
   - *(A)* Honour the spec by emitting `nft reject with icmp port-unreachable`
     instead of `drop` on the deny rule. Adds a single rule
     attribute, observable to the VM, useful to applications that
     check ICMP for "no route" signalling.
   - *(B)* Update the spec wording to "silent drop" with rationale:
     sandboxed apps shouldn't be able to probe topology via ICMP
     responses; the audit log already attributes the deny.
   The default proposed is *(B)*. *(A)* is logged as an Open Question
   below for the user to flip if they prefer.
4. **`networking-design.md:1115-1121`** — the UDP subsection is a
   three-bullet stub (audit §3.b12). Replace with a substantive
   paragraph: UDP enforcement is allow-by-set, observe-by-NFLOG-and-NFCT,
   no userland datapath, no L7 inspection, no MITM.
5. **`docs/guides/network-policies.md:174`** — *"Non-TCP protocols
   (QUIC/HTTP/3, raw UDP) cannot be inspected at this level"* is
   correct in the first sentence; the second sentence about QUIC is
   structurally true but operationally misleading (audit §4.4). Add
   an explicit UDP section with at least one concrete example
   (e.g. NTP/UDP-123, audit §3.c1). Reuses the wording from #4.
6. **`docs/concepts/policy-model.md:60,108,159`** — UDP appears as
   a `protocol` enum value with no mention of UDP-specific limits
   (no L7, no MITM, allow-audit is per-flow not per-packet) (audit
   §3.b10, §4.5). Add a short caveats paragraph next to the protocol
   enum description.
7. **`docs/guides/troubleshooting.md`** — add UDP-specific
   troubleshooting entries: how to read the new allow event in
   the JSONL, the 30 s NFCT-rollover property (Decision 3), what a
   silent drop looks like end-to-end (no TCP RST, no ICMP unreachable
   under default *(B)* — just timeouts in the VM-side socket layer,
   plus a deny event in the audit log).

**Alternatives rejected.**

- **Defer all doc work to M12-S3 / S9.** Means the docs lie for the
  duration. Specifically rejected by the M12 plan
  (`docs/internal/milestones/M12.md` M12-S2 in scope: "Reconcile
  docs with verified behavior").

**Code/test/doc impact.**

- All edits are doc-only and grep-anchored. No code touched by
  Decision 6 alone.

## Architecture

### Datapath after the change

```
VM app
  → VM kernel → virtio-net → per-session bridge
    → gateway container netns
      → nftables PREROUTING (sandbox_dnat)
          ┌──────────────────────────────────────────────────────────┐
          │ rule 1  : ip saddr {vm_subnet} udp dport 53              │
          │           dnat to gateway_ip:53            → CoreDNS     │
          │ rule 2  : ip saddr {vm_subnet} meta l4proto udp          │
          │           ip daddr . udp dport @policy_allow_udp accept  │
          │           (no DNAT — falls through to FORWARD/MASQ)      │
          │ rule 3  : ip saddr {vm_subnet} meta l4proto udp          │
          │           log group N                                    │
          │ rule 4  : ip saddr {vm_subnet} meta l4proto udp drop     │
          │ rule 5  : (unchanged) ip daddr 169.254.169.254 drop      │
          │ rule 6  : (unchanged) ip6 daddr != ::1 drop              │
          └──────────────────────────────────────────────────────────┘
          (TCP rules unchanged; DNAT to Envoy:10000 same as today)

Allowed UDP path (rule 2):
  → MASQUERADE on POSTROUTING → upstream (direct, no Envoy hop)
  → conntrack NEW event → multicast on NFNLGRP_CONNTRACK_NEW
      → sandbox-nft-allow-logger receives → JSONL allow record

Denied UDP path (rules 3+4):
  → kernel emits NFLOG group N message (full 5-tuple, headers)
  → packet drop (rule 4)
      → sandbox-nft-deny-logger receives netlink message
      → JSONL deny record

TCP allow / deny / DNS — unchanged from current
```

The exact rule numbers above are illustrative; the implementation
phase chooses the placement (rules 3+4 may collapse into a single
`log group N ; drop` jump-block, etc.). The shape is what matters:
no DNAT for UDP except for DNS-to-CoreDNS, no userland datapath for
either UDP allow or UDP deny.

### Logger architecture

```
                 ┌─────────────────────────────────────────────────────┐
                 │   sandbox-event-emitter   (lib crate)               │
                 │   - EventEmitter (JSONL writer)                     │
                 │   - RateCap + flush ticker (rate_limited summary)   │
                 │   - /health endpoint shape                          │
                 │   - DenyRecord, AllowRecord, Protocol               │
                 └─────────────────────────────────────────────────────┘
                       ▲                                ▲
                       │                                │
                       │                                │
   ┌───────────────────┴────────────────┐    ┌──────────┴────────────────────┐
   │  sandbox-nft-deny-logger           │    │  sandbox-nft-allow-logger     │
   │  (binary)                          │    │  (binary)                     │
   │                                    │    │                               │
   │  - TCP listener :10001             │    │  - NFCT subscriber on         │
   │    accept(2) → SO_ORIGINAL_DST     │    │    NFNLGRP_CONNTRACK_NEW      │
   │    → SO_LINGER 0 → RST close       │    │  - filter UDP only            │
   │  - NFLOG receive on group N        │    │  - emit AllowRecord per       │
   │    parse headers → emit DenyRecord │    │    new flow                   │
   │  - /health on :10003               │    │  - /health on :10004 (or…)   │
   │  - JSONL via shared lib            │    │  - JSONL via shared lib       │
   └────────────────────────────────────┘    └───────────────────────────────┘
                       │                                │
                       └──────────────┬─────────────────┘
                                      ▼
                         /var/log/gateway/events/<jsonl>
                          (per-session bind mount; sandboxd
                           ingest tails from host side)
```

Both binaries write to the same per-session events directory; the
JSONL filenames are distinct
(`/var/log/gateway/events/nft-deny-logger.jsonl`,
`/var/log/gateway/events/nft-allow-logger.jsonl` — exact names are
implementation detail). sandboxd's existing per-session ingest
watcher handles both files because the watcher is directory-scoped,
not file-scoped.

### Gateway container changes

The container build (Dockerfile stage 2) extends to produce two
binaries; the runtime image installs both. The entrypoint
(`networking/gateway/entrypoint.sh`) starts both binaries — order
between them does not matter (both can start in parallel after
mitmproxy/Envoy/CoreDNS, before nftables rules are pushed by sandboxd).
Both are monitored in the same process-monitor loop; either exiting
takes the container down so Docker restarts it. Both expose a
`/health` endpoint so the existing `wait_for_ready` shape still works.

There is no requirement that the two binaries share a process or a
runtime; each is its own tokio-runtime, its own netlink socket, its
own JSONL file descriptor. Independent failure domains is the
explicit goal (Decision 4 rationale).

## Test plan

The shape mirrors prior specs: hermetic unit tests for compilation
and parsing, integration tests under `sandboxd/sandboxd/tests/` for
container-real wiring, e2e tests in `tests/e2e/` for VM-real flows.

### Compilation logic (Rust unit / `nft -c`)

- `sandbox-core/src/policy.rs` — the existing
  `compile_udp_cidr_produces_udp_rules`,
  `compile_mixed_tcp_and_udp_cidrs_segregate_by_protocol`, and the
  DNS-propagation-side
  `domain_ip_rules_segregate_tcp_and_udp_rules` tests retarget to the
  new rule shape (allow becomes a non-DNAT accept; deny becomes
  `log group N ; drop`).
- `sandbox-core/tests/validators.rs:354 —
  integration_compile_nftables_passes_nft_c` — the compile output
  with both TCP and UDP CIDR rules continues to pass `nft -c -f -`
  (this is the structural regression catcher; the rule shape changes
  but `nft` accepts it).

### Allow-path delivery (e2e)

A new e2e case in `tests/e2e/test_m4_policy.py` opens a non-DNS UDP
socket from the VM to an allowed external `(host, port)` and asserts:

- The datagram reaches the upstream (a small UDP echo target on the
  host or a captive sink fixture).
- An `event: "allow"` record appears in the per-session JSONL with
  the correct 5-tuple.
- No deny event for that flow.

The existing `test_level1_transport_udp` (DNS) keeps passing as a
smoke test for the unchanged DNS-DNAT special case.

### Deny-path delivery and attribution (e2e + integration)

The S1 integration test
`integration_udp_send_to_non_allowlisted_destination_emits_deny_event`
keeps its assertion (`event: "deny"` with pre-DNAT 5-tuple) but the
data source under test changes from "UDP listener + conntrack" to
"NFLOG receive". The S1 load test
`integration_udp_load_pre_dnat_attribution_holds_under_concurrent_flows`
similarly retargets.

A new e2e case asserts deny attribution across the
behavioural-blocking gap (audit §3.b6,
`tests/e2e/test_m3_networking.py:440-444` skips this today): a denied
UDP datagram emits a deny event in the events stream, even though
there is no behavioural ICMP-reject signal at the VM (silent drop
under Decision 6 *(B)*).

### Multi-port and bidirectional (e2e)

- **Multi-port-same-host.** Two UDP rules to the same external IP on
  different ports; assert that traffic to both is allowed and traffic
  to a third port on the same host is denied. Audit §3.b8
  ("explicit scope" per the M12-S2 plan) and the M12.md S2 in-scope
  list both call this out.
- **Bidirectional.** A UDP echo round-trip — VM sends a datagram to
  an allowed upstream UDP echo server, the response comes back via
  conntrack's reverse-path translation (kernel-handled), VM
  receives. Asserts the post-allow path doesn't break return
  delivery.
- **Allowed-IP edge case.** Direct-IP destination skipping DNS — VM
  dials an IP literal that is in `policy_allow_udp` via a CIDR rule
  (not via DNS-resolved set membership). Audit §1.1 rule 2
  references the CIDR vs DNS rule paths; this exercises the CIDR
  side.

### Allow-flow log assertions (integration)

A new integration test under `sandboxd/sandboxd/tests/` exercises
`sandbox-nft-allow-logger` directly: open a UDP flow that should be
allowed, assert the allow event lands. The 30 s rollover property is
documented but not asserted in tests (would require either a
fast-clock test harness or a 30 s sleep — both undesirable; logged
as a follow-up if a hermetic shape can be found).

### Deny-flow log assertions via NFLOG (integration)

Mirror of the allow test: open a UDP flow that should be denied,
assert the deny event lands with the pre-DNAT 5-tuple. The wire
shape is identical to S1's expectation; the data source changes.

### No-regression on TCP

The TCP allow path (through Envoy) and deny path (through the
listener with `SO_ORIGINAL_DST` + RST close) must continue to pass
their existing tests unchanged. The `tcp.rs` module moves into
`sandbox-nft-deny-logger` byte-for-byte; its unit tests
(`tcp.rs::tests` block) move with it. Integration tests that assert
TCP deny attribution
(`sandboxd/sandboxd/tests/m10_s3_end_to_end.rs` Phase 8 test 1) keep
asserting the same shape against the renamed binary.

## Migration / breaking changes

- **Binary rename.** `sandbox-deny-logger` → `sandbox-nft-deny-logger`.
  Anyone scripting against the binary name in tests, fixtures, or
  Makefile recipes needs an update. Grep pattern is straightforward.
  No production users; intra-tree only. New binary
  `sandbox-nft-allow-logger` adds a third name to the surface.
- **Supervisor changes in the gateway container.**
  `networking/gateway/entrypoint.sh` starts two binaries instead of
  one; readiness probe is double; process-monitor loop tracks two
  PIDs; shutdown order extends. No external config change.
- **`/health` shape.** The deny-logger's existing `/health` JSON
  shape (asserted by `sandbox-deny-logger/src/health.rs:157`)
  contains a `udp_listener: "ok"` field — this no longer makes
  sense (no UDP listener). The replacement shape reports on the
  NFLOG socket binding instead. Any tests asserting on the literal
  field name update with the rename. The new allow-logger has its
  own `/health` shape with an NFCT-subscription field. Both fields
  are added on top of the existing structure rather than replacing
  it wholesale, so any operator-tooling that reads `/health` and
  looks at the top-level "ok" status keeps working.
- **JSONL filename.** If the implementation chooses
  `nft-deny-logger.jsonl` / `nft-allow-logger.jsonl` rather than
  reusing `deny-logger.jsonl`, the daemon-side ingest watcher
  configuration may need a glob update. Implementation detail —
  but flagged here as an operator-visible artifact.
- **Conntrack lookup module.** If deleted (Decision 2 / 5
  recommendation), any out-of-tree consumer that imported it
  breaks. There are none in-tree.
- **Forward-compat on `policy_allow_udp`.** The set itself does not
  change shape; only the rule that consumes the set changes. A
  daemon roll-back to a pre-S2 binary would re-introduce the
  DNAT-to-`:10000` rule shape, which is broken the same way it has
  always been broken; rollback is therefore a return to the broken
  status quo, not a new failure mode.

## Resolved decisions (post-spec review)

The following items were flagged during spec drafting as needing
user follow-up before implementation. Each has now been resolved.
The original framing is preserved so future readers can see what
was open and why; the **Resolution** line below each item is the
binding contract for the implementation phase.

1. **NFLOG group number.** Decision 2 uses an unspecified `N`. nft
   conventionally uses small integers (0-65535); we have no
   pre-existing use, so the choice is open. Suggest `0` for
   simplicity unless another nft consumer in the gateway image
   conflicts.

   **Resolution:** group number `1` — the lowest available unused
   group, stable across reboots, and consumed only by
   `sandbox-nft-deny-logger`. The value is configurable via the
   gateway nft template; `1` is the default and is the value tests
   assert against. Picking `1` rather than `0` leaves `0` free as a
   conventional "unset/system-reserved" sentinel for any future
   nft consumer that wants the lowest non-zero slot.
2. **ICMP-unreachable on UDP deny — Decision 6 #3 alternatives.**
   *(A)* `nft reject with icmp port-unreachable` (matches
   `networking-design.md:1221` literal wording, gives VM-side
   applications a "no route" ICMP signal) vs. *(B)* silent `nft
   drop` (current behaviour, denies probing-via-ICMP). Spec
   default is *(B)*; user to flip if *(A)* is preferred. The
   choice is user-visible and security-relevant.

   **Resolution:** keep silent drop (`nft drop`, **not**
   `nft reject with icmp port-unreachable`). Sandboxed applications
   should not be able to probe topology via timing or error-response
   side-channels; silent drop is the conservative posture and the
   audit log already attributes the deny via the JSONL stream. The
   `networking-design.md:1221` wording ("ICMP unreachable for UDP")
   is reconciled to "silent drop" as part of Decision 6's doc-edit
   set — see Decision 6 #3, which now collapses to alternative *(B)*
   with the rationale recorded inline.
3. **Per-source rate-cap policy for the allow-logger.** Audit volume
   for allow events on a busy session could be high (any UDP-using
   service that opens many short-lived flows — DNS-of-non-DNS,
   QUIC discovery, multicast-DNS — fans out one NFCT_T_NEW per
   flow). The deny-logger today has a per-process `RateCap` and no
   per-source cap (audit §3.c1). The allow-logger inherits the
   per-process cap by default. Open: should we add a per-source
   bucket on the allow side? Defer-able to M12-S9 if the volume
   under realistic workload turns out tractable; flag for the
   user to size.

   **Resolution:** defer to M12-S9. The allow-event volume is
   bounded by `NFCT_T_NEW` events (per-flow, not per-packet), so
   expected steady-state load is low. If production traffic reveals
   starvation of the per-process `RateCap` budget by allow events
   crowding out deny events (or vice versa), M12-S9 can pair this
   work with the existing #108 UDP rate-cap hardening for the
   deny-logger and add a per-source bucket on both sides at once.
   For S2, the allow-logger inherits the per-process cap unchanged.
4. **Conntrack module: delete or retain?** Decision 2 / 5 recommend
   delete. User to confirm. If retain, with what justification? (No
   in-tree caller after this lands.)

   **Resolution:** delete `sandboxd/sandbox-deny-logger/src/conntrack.rs`
   entirely in the same PR as the NFLOG migration. Once UDP-deny
   moves to NFLOG, the module has no remaining callers — TCP-deny
   uses `SO_ORIGINAL_DST` (verified at `tcp.rs:222-249` per the
   original spec drafting), and the new NFCT-driven allow-logger
   reads tuples directly from conntrack multicast events rather
   than via synchronous `IPCTNL_MSG_CT_GET`. Deletion eliminates
   ~759 LOC plus the `netlink-sys` and `libc` direct dependencies
   in `sandboxd/sandbox-deny-logger/Cargo.toml` (these get
   re-introduced transitively via `sandbox-event-emitter`, since
   both the new NFLOG-based deny-logger and the NFCT-based
   allow-logger need netlink — but the lib crate owns those deps,
   not the binary's `Cargo.toml`). Implementation note: the
   deletion happens in the same PR as the NFLOG migration; do not
   retain the module as dead code "in case it's useful later" —
   future revival should be honest, not inherited.
5. **`/health` field stability.** The current shape includes
   `udp_listener: "ok"`; the rename is a chance to redesign. Open:
   should the new shape be backward-compatible (keep the field,
   make it stub-OK) or honestly-new (different fields)? Suggested
   default: honestly-new — operator tooling can adapt. User to
   confirm.

   **Resolution:** preserve the existing `/health` field names
   through the binary rename. The `sandbox-deny-logger` →
   `sandbox-nft-deny-logger` rename keeps the `/health` JSON shape
   identical (`events_emitted_60s`, `rate_limited_count`, etc.) so
   any operator/monitor scraping the endpoint sees no breaking
   change in the response body. The new `sandbox-nft-allow-logger`
   adds its own `/health` with parallel field names
   (`allow_events_emitted_60s` and so on). The only operator-visible
   break is the URL path *if* a deployment embeds the binary name in
   the path — implementation phase verifies this and calls it out
   in the commit body if so. The previously-flagged
   `udp_listener: "ok"` field (see §Migration / breaking changes)
   is replaced with an `nflog_socket: "ok"` field of equivalent
   shape, so monitors that check field *presence* keep working;
   only those that pin the specific key name need an update — and
   that key name was internal-implementation-tied, so the swap is
   honest about the layer change.
6. **JSONL filename.** Reuse `deny-logger.jsonl` /
   `<new>-allow-logger.jsonl` or rename to `nft-deny-logger.jsonl`
   / `nft-allow-logger.jsonl`? Affects daemon-side ingest
   configuration. Suggested default: rename for symmetry with the
   binary rename. User to confirm or override.

   **Resolution:** deny events go to `nft-deny.jsonl`; allow
   events go to `nft-allow.jsonl`. Both files live in the existing
   per-session JSONL output directory under the gateway container's
   events bind mount. The deny file is renamed from its current
   name (verify exact current name during implementation —
   `deny.jsonl` / `deny-logger.jsonl` per the working-tree at the
   time of writing); the rename is a breaking change for any
   external tail-watcher and is captured in the
   §Migration / breaking changes notes. The shorter `nft-deny` /
   `nft-allow` form is preferred over `nft-deny-logger` /
   `nft-allow-logger` because the file already lives in a
   logger-emitted-events directory — the `-logger` suffix is
   implicit context, not new information.
7. **Allow-event wire shape.** Decision 3 says "JSONL allow-event
   records analogous to the deny events." The exact field set is an
   implementation-phase call but the user may want to review:
   should the allow event include a flow-end signal (NFCT
   `IPCTNL_MSG_CT_DELETE` on flow expiry) too, or NEW-only? Spec
   default: NEW-only. Flow-end logging is a clean follow-up if
   needed.

   **Resolution:** emit on `NFCT_T_NEW` only; skip
   `NFCT_T_DESTROY` (flow-end). The per-flow allow event answers
   the audit question "client X started a flow to Y on port Z,"
   which is the only audit semantic users need from a sandbox-policy
   standpoint; end-of-flow timing is not user-visible and is not
   actionable for policy enforcement. If observability needs
   flow-duration data later (e.g. for cost/latency analytics), a
   follow-on can subscribe to `NFCT_T_DESTROY` and emit a separate
   `event: "allow_end"` record without changing the existing
   `event: "allow"` shape — the wire-shape contract is preserved
   either way.

## Out of scope

Folded explicitly here so future readers don't expect them under M12-S2:

- **TCP datapath changes.** The Envoy-mediated TCP allow path and the
  `SO_ORIGINAL_DST`-driven TCP deny listener stay byte-for-byte. They
  move into `sandbox-nft-deny-logger` with no shape change.
- **Audit-log into `/health`** (todo #112). Useful future work; not
  this spec. The shared lib (Decision 5) makes it tractable.
- **Conntrack recv-buffer hardening** (todo #113). The conntrack
  module's per-call buffer sizing is an existing concern that would
  travel with the module if retained; with deletion it goes away.
- **`iter_nlas` allocation reduction** (todo #116). Internal to the
  conntrack module; same disposition as #113.
- **ICMP-unreachable behaviour change.** Logged as Open Question #2;
  if the user picks *(A)* it lands here, if *(B)* it doesn't. Either
  way it is a single rule attribute, not a new feature surface.
- **IPv6.** Sandbox networking remains IPv4-only (audit §3.b9 does
  not raise IPv6, and the `Corefile` strips AAAA upstream). UDP/IPv6
  is a future spec.
- **Per-source rate-cap on the allow-logger.** Open Question #3;
  defer-able to M12-S9 unless empirically needed.
- **Replacing Envoy's TCP-only access-log surface with a unified
  `nft-` family for TCP too.** TCP through Envoy is structurally
  important for L7 inspection; the nft-only path proposed here for
  UDP is precisely the path TCP cannot take (no MITM, no L7). The
  binaries and the spec are UDP-focused; reusing the lib for a TCP
  observation path is a future option, not a goal.

## Appendix: cross-reference to audit items

The audit doc enumerates findings as `(a)..(c)` (S1) and `b1..b12`,
`c1..c4` (later). For traceability, this spec resolves the following:

- **b1** (UDP allow-path unreachable) → Decision 1.
- **b2** (Envoy has no UDP listener) → Decision 1 (rejected
  alternative *(a)* explicitly).
- **b3** (`docs/concepts/networking.md:141` overclaim) →
  Decision 6 #1.
- **b4** (`docs/concepts/networking.md:130` "records the pre-DNAT
  5-tuple" for UDP) → resolved by S1 already; doc reread under
  Decision 6.
- **b5..b8** (e2e parity gaps) → §Test plan.
- **b9** (`docs/guides/network-policies.md` no UDP example) →
  Decision 6 #5.
- **b10** (`docs/concepts/policy-model.md` no UDP-specific limits) →
  Decision 6 #6.
- **b11** (`docs/guides/troubleshooting.md` no UDP-specific flow) →
  Decision 6 #7.
- **b12** (`networking-design.md:1115-1121` UDP subsection stub) →
  Decision 6 #4.
- **c1** (no per-source UDP rate cap) → Open Question #3, defer to
  M12-S9.
- **c2** (recv-buffer truncation accounting) → resolved
  trivially by Decision 2 (no userland recv).
- **c3** (no e2e for `http+udp` rejection) → §Test plan optional,
  defer if not absorbed here.
- **c4** (`policy_allow_udp` forward-compat dead code) → resolved
  by Decision 1 (the set is now backed by a real rule).

Items **a1..a3** were S1 deliverables and are already in the tree;
this spec inherits them as preconditions.
