# L3 flow: restore Envoy → mitmproxy via PROXY protocol v2

## Summary

The implementation of L3 (HTTP-inspected) traffic flow diverged from the
original design in `networking-design.md`. The design requires all TCP
from the VM to traverse Envoy, with Envoy routing L3 traffic to mitmproxy
on gateway loopback. The implementation currently bypasses Envoy for L3
by using a higher-priority nftables table (`sandbox_l3`) that DNATs TCP
80/443 for policy-allowed IPs directly to mitmproxy.

This spec restores the design-faithful flow by filling the one gap the
design left open: **how Envoy hands the original destination to mitmproxy
across the proxy hop**. We fill it with PROXY protocol v2.

## Context

### Why the divergence exists

`SO_ORIGINAL_DST` is a Linux socket option that reads the pre-DNAT
destination from conntrack. It works only on a socket whose accepted
connection was itself DNATed. When Envoy proxies a connection — accepts
on one socket, opens a fresh socket to the next hop — the downstream
socket has no conntrack history tied to the original destination, so
`SO_ORIGINAL_DST` returns the local loopback address rather than the
real upstream.

Mitmproxy's transparent mode defaults to `SO_ORIGINAL_DST`. The
implementation responded to this by routing L3 traffic around Envoy
entirely (the `sandbox_l3` DNAT table), preserving `SO_ORIGINAL_DST` at
the cost of violating three design points:

1. **Envoy as the single TCP entry point** — the design says *"TCP →
   Envoy (original_dst, protocol-aware routing)"* is the sole TCP path;
   the implementation has a second path (nftables → mitmproxy).
2. **Policy-driven classification** — the design principle is
   *"Policy drives classification, not protocol sniffing."* The
   implementation reintroduced port-based routing for L3 (DNAT only for
   TCP 80/443), which made non-HTTP ports to an L3 destination silently
   downgrade to opaque passthrough.
3. **Fail-closed during config propagation** — the design says *"No
   traffic is permitted to a new destination until all components are
   consistent."* The implementation has a ~2s window where L3 traffic
   falls through Envoy as SNI-verified passthrough with no HTTP
   inspection.

### Why the design-faithful flow is achievable

Mitmproxy does not have to use `SO_ORIGINAL_DST`. Latest mitmproxy
supports PROXY protocol v2 on its listener; Envoy supports PROXY v2 as
an upstream transport socket wrapper. This is an off-the-shelf,
kernel-privilege-free mechanism for passing the original source and
destination across a proxy hop.

## Target design

### High-level flow

```
VM app
  → VM kernel → virtio-net → per-session bridge
    → gateway container
      → nftables PREROUTING DNAT (sandbox_dnat)
        → all TCP ≠ 53 → Envoy :10000 (original_dst listener)
          → Envoy filter-chain match (by destination IP or catch-all)
            ├─ matched L3 chain → mitmproxy cluster
            │     ↳ upstream transport wraps outbound TCP with
            │       PROXY protocol v2 header
            │       (src = VM IP:port, dst = real external IP:port)
            │     ↳ mitmproxy reads PROXY v2 on its listener, uses dst
            │       as upstream target (no SO_ORIGINAL_DST dependency)
            │     ↳ mitmproxy terminates TLS, inspects HTTP, forwards
            │       to real destination
            ├─ matched L2 chain → original_dst passthrough (unchanged)
            ├─ matched L1 chain → original_dst passthrough (unchanged)
            └─ no match → connection closed (deny by default)
```

### Three properties this restores

- **Single mediated egress path.** All TCP hits Envoy. Envoy is the
  sole routing decision point. No split responsibility, no second DNAT
  target.
- **Policy-driven, not port-driven.** L3 filter chains are keyed on
  destination identity (resolved IPs, CIDR, or catch-all for wildcard).
  All traffic to an L3 destination — any port, any protocol on the
  wire — routes to mitmproxy. Mitmproxy rejects non-HTTP content, per
  the design's rule that wire behavior contradicting the declared
  level is denied.
- **Fail-closed during propagation.** Envoy has no default passthrough
  chain. Connections that don't match any explicit filter chain are
  closed. Traffic to a destination whose IPs haven't been propagated
  into Envoy's config yet is dropped; applications retry naturally
  after propagation completes.

### Ports (after this change)

| Port  | Role                                           | Bind              |
|-------|------------------------------------------------|-------------------|
| 53    | CoreDNS (DNS exception)                        | Gateway IP        |
| 10000 | Envoy `original_dst` listener                  | Gateway IP        |
| 18080 | mitmproxy listener (Envoy upstream endpoint)   | `127.0.0.1` only  |

The mitmproxy port moves from `8080` to `18080`, and the bind moves to
loopback only. Two reasons: (a) signalling — the port is an internal
Envoy→mitmproxy link, not a VM-facing DNAT target; (b) defence in
depth — if a future change added a DNAT back to port 8080, it would
fail closed rather than silently working.

## Component changes

### Envoy

**New cluster `mitmproxy`**:

- `type: STATIC`, single endpoint `127.0.0.1:18080`
- upstream transport socket wrapped in
  `envoy.transport_sockets.upstream_proxy_protocol` (v3) with
  `version: V2`, inner transport `raw_buffer`
- TCP health check (1s timeout, 5s interval) so a dead mitmproxy shows
  up in Envoy's admin stats

**L3 filter-chain compilation** (in `sandbox-core/src/policy.rs`):

- Per-domain L3 destination: filter chain matched by `prefix_ranges`
  built from the DNS cache's current resolved IPs for the domain,
  routing to `cluster: mitmproxy`. (Replaces today's SNI-only match
  routing to `original_dst`.)
- `Destination::Cidr` at L3: filter chain matched by `prefix_ranges`
  on the CIDR, routing to `cluster: mitmproxy`.
- Wildcard `*` L3 destination: default filter chain (no match),
  routing to `cluster: mitmproxy`.
- **No port predicate** on any L3 chain. L3 applies to all traffic to
  the destination.

**No default passthrough chain.** Envoy's listener has no catch-all
chain for non-L3 destinations. Unmatched connections are closed.

**L1/L2 chains**: unchanged — existing matching criteria (SNI for L2,
destination IP for L1) and existing routing (`original_dst` passthrough
after SNI validation for L2, opaque TCP for L1) stay as they are.

### mitmproxy

- Bind: `127.0.0.1:18080` (was `0.0.0.0:8080` or equivalent).
- Mode: transparent with PROXY protocol v2 reception enabled.
- Behaviour change: uses the PROXY v2 header's destination as the
  upstream target instead of `SO_ORIGINAL_DST`; uses the header's
  source as the logged client IP (VM's IP appears in logs instead of
  `127.0.0.1` — a side benefit).
- Latest mitmproxy is pinned in the gateway Dockerfile. The specific
  config option for PROXY v2 reception is verified against the pinned
  version during implementation.

### nftables (in `sandbox-core/src/gateway.rs` and
`sandbox-core/src/dns_propagation.rs`)

**Deleted:**

- `generate_l3_redirect_rules` and the `sandbox_l3` table it produces
  (in `dns_propagation.rs`).
- The DNS-propagation call site that invokes
  `generate_l3_redirect_rules`.
- Any `sandbox_l3` teardown paths.
- The `tcp dport 8080 accept` rule in `generate_input_allow_ruleset`
  (no longer needed — mitmproxy is loopback-only and loopback traffic
  is accepted by the existing `iif lo accept`).

**Kept unchanged:**

- `sandbox_dnat` (DNS → CoreDNS, all other TCP → Envoy:10000,
  cloud-metadata block, IPv6 drop, MASQUERADE).
- `sandbox_policy` (DNS-derived IP allow rules for Envoy's outbound
  connections to L1/L2 destinations).
- `sandbox` (deny-all forward baseline).

Gateway nftables tables after this change: three (`sandbox`,
`sandbox_dnat`, `sandbox_policy`).

### Configuration propagation (new subsystem concern)

Today DNS propagation writes only nftables rules. After this change
it also rewrites Envoy's listener filter chains when the resolved IPs
for an L3 domain change.

**Mechanism: regenerate the Envoy config file and restart the Envoy
process inside the gateway container.** Envoy does not support
SIGHUP-triggered config reload; xDS and hot restart (parent-child
process swap) both preserve connections but add machinery we don't
need for a single-Envoy-per-session gateway. A plain process restart
is ~1s and drops any in-flight connections through Envoy; applications
retry, consistent with the fail-closed-during-propagation semantics
already mandated by the design.

**Ordering.** For L3 destinations the Envoy config *is* the gate —
there is no per-IP nftables rule to sequence after it. The existing
outside-in propagation order (`networking-design.md:1345-1349`)
continues to govern L1/L2: `sandbox_policy` nftables rules are
installed last, after inner components are consistent. L3 propagation
fits inside the same window — Envoy restart happens alongside the
inner-component updates, before nftables.

## Design doc amendment (`networking-design.md`)

The design specifies the L3 pipeline but never says how Envoy hands the
destination to mitmproxy. Minimal targeted amendment.

**Add to `##### Envoy` classification list (around line 512):**

> level 3 destinations: route to the mitmproxy cluster on gateway
> loopback; the upstream transport encodes the original source and
> destination in a PROXY protocol v2 header, so mitmproxy does not
> depend on `SO_ORIGINAL_DST` across the Envoy proxy hop.

**Add to `##### mitmproxy` bullet list (around line 520):**

> learns the original source and destination from the PROXY protocol
> v2 header emitted by Envoy on its upstream connection, and uses the
> destination as the upstream target (transparent mode without
> `SO_ORIGINAL_DST`).

The traffic-flow ASCII art (lines 139–147) and the assurance-level
exit-point table (line 395, "Level 3 — HTTP inspected → Full pipeline
traversal") already describe the correct flow. The amendment closes the
mechanism gap without restructuring the document.

## User-facing doc updates

### `docs/concepts/networking.md`

- Fix the request-flow mermaid diagram (lines 78–107): the L3 branch
  becomes `Envoy ▸ mitmproxy ▸ External`. Remove the
  `Forward to 127.0.0.1:8080` wording that will no longer be accurate;
  replace with a line describing PROXY v2 as the Envoy→mitmproxy
  contract.
- New subsection **"Policy changes are fail-closed during
  propagation"**: when a policy is applied, updated, or a session
  starts, components are reconfigured in outside-in order; newly-allowed
  destinations are briefly unreachable until all components are
  consistent; this is intentional, not a bug; applications are expected
  to retry. Links back to `networking-design.md`'s fail-closed section.
- Explicit statement in the nftables / request-flow prose that L3
  applies to all traffic to an L3-declared destination regardless of
  port, and non-HTTP content on those connections is rejected at
  mitmproxy (not silently passed through).

### `docs/guides/network-policies.md`

- New subsection **"What happens when you apply or change a policy"**:
  expect the first connection after policy change / session start to
  fail briefly, then succeed; standard retry logic handles this;
  applies equally to `policy apply`, `policy update`, session `start`,
  and cache-TTL expiry events.
- Note on L3 level: "Declaring a destination at L3 means HTTP-only.
  Non-HTTP traffic to that destination — raw TCP, custom TLS protocols
  — is rejected. Use L1 (transport) or L2 (TLS-verified) for those."

### `docs/guides/troubleshooting.md`

Three new entries:

- *"First connection after applying/changing policy fails, then works"*
  → cause: propagation window; expected for ~1–2s; not a bug.
- *"Non-HTTP connection to an L3 destination fails"* → cause: L3 is
  HTTP-only by design; switch to L1 or L2 for raw protocol access.
- *"How do I verify a connection was HTTP-inspected?"* → check both
  Envoy access log and mitmproxy log; both should contain the same
  connection.

### `docs/concepts/architecture.md`

One-line fix if the gateway-pipeline prose asserts anything
now-inaccurate about the L3 path; verify at edit time.

### `docs/guides/hardening.md`

Verify the L3 flow description (if any) is still accurate; update in
the consistency pass.

## Testing plan

### Unit tests (Rust)

In `sandbox-core/src/policy.rs` and `sandbox-core/src/dns_propagation.rs`:

- **Flip assertions** in `compile_level3_envoy_no_mitmproxy_cluster`
  and any sibling tests that assert the mitmproxy cluster is absent
  from Envoy config. Mitmproxy cluster must now be present, with
  `upstream_proxy_protocol` transport socket at `version: V2`.
- **New test**: L3 filter chains match on `prefix_ranges` derived from
  DNS cache IPs, not `server_names`.
- **New test**: L3 wildcard (`*`) produces a default filter chain
  routing to `mitmproxy` cluster.
- **New test (fail-closed)**: `compile_envoy_config` called with a
  policy containing an L3 domain and an empty DNS cache produces a
  listener with no filter chain for that domain; unmatched traffic is
  dropped (no passthrough chain exists).
- **New test**: `generate_dnat_ruleset` emits nothing L3-specific;
  `generate_input_allow_ruleset` no longer contains
  `tcp dport 8080 accept`.
- **Remove** `generate_l3_redirect_rules` tests entirely.

### Gateway integration test (`sandbox-core/tests/gateway_integration.rs`)

- After session start, gateway nftables has three tables
  (`sandbox`, `sandbox_dnat`, `sandbox_policy`) — not four.
- Mitmproxy is listening on `127.0.0.1:18080`; nothing is listening on
  `8080`; nothing is listening on `18080` on the VM-facing IP.

### E2E tests (`tests/e2e/test_m4_policy.py`)

- Existing L3 inspection test must still pass (host sees per-session
  CA; HTTP inspection works end-to-end).
- **New assertion**: an L3 connection appears in both the Envoy access
  log AND the mitmproxy log (verifies both are on the path).
- **New assertion**: raw TCP (non-HTTP) to an L3 destination's IP on
  port 443 is rejected at mitmproxy — not opaquely passed through.

The originally-proposed "first connection may fail ~1–2s then succeeds"
e2e test is **not** included. It would be timing-dependent and flaky;
the fail-closed property is covered deterministically by the unit test
above (empty DNS cache → no L3 chain → traffic dropped).

## Post-implementation consistency pass

After the code change is complete and tests pass, run a structured
sweep to catch second-order staleness.

**Grep sweep across the repo** (code, tests, docs, comments):

- `sandbox_l3` — should have zero matches.
- `8080` — only intentional references remain (none expected in sandbox
  code after the port flip).
- `SO_ORIGINAL_DST` — appears only in comments explaining *why* we use
  PROXY v2 instead.
- `bypasses Envoy` / `skip Envoy` / `Envoy is bypassed` — gone.
- `pre-propagation` / `falls through to Envoy` / `~2 seconds` — gone.
- `tcp dport 8080 accept` — gone.
- `original_dst` cluster in an L3 context — gone.
- `dport { 80, 443 }` / port-based routing in L3 context — gone.

**File-level read-through** — not just grep, re-read end-to-end for
subtle inconsistencies:

- `networking-design.md` — coherent after the amendment?
- `docs/concepts/networking.md` — diagram and prose align?
- `docs/concepts/architecture.md` — L3 prose accurate?
- `docs/guides/hardening.md` — any L3-path assertion that changed?
- `docs/guides/network-policies.md` — new propagation section fits?
- `docs/guides/troubleshooting.md` — new entries fit existing
  structure?
- `sandbox-core/src/policy.rs` — the comment block that currently
  justifies bypassing Envoy (lines 862–888) is replaced with accurate
  commentary on the PROXY v2 flow.
- `sandbox-core/src/dns_propagation.rs` — module docs; no lingering
  references to L3 redirect rules.
- `sandbox-core/src/gateway.rs` — `generate_input_allow_ruleset` and
  `generate_dnat_ruleset` comments.
- `tests/e2e/test_m4_policy.py` — test docstrings.
- `CLAUDE.md` — no lingering reference to the current L3 flow.

Findings from the sweep are either fixed in the same branch or
explicitly deferred with a note.

## Rollout

- **On-disk schema**: unchanged. Gateway config is regenerated per
  session, not persisted; no migration required.
- **Running sessions**: keep their existing gateway container and
  config until stop/start. New sessions use the new flow. No in-place
  migration step.
- **Gateway image**: `make gateway-image` rebuilds with latest
  mitmproxy and PROXY v2 enabled. Daemon pins the image digest as
  usual.
- **Daemon binary**: compiles new Envoy config and deletes the
  `sandbox_l3` codepaths.
- **Backwards compatibility**: none required — the change is fully
  internal to the gateway.

## Explicitly out of scope

- Policy language changes. The policy schema, CLI surface, and HTTP API
  are unchanged. The policy stays abstract per principle #3.
- L1 and L2 paths. They already exit at Envoy per the design and are
  not touched.
- DNS-to-IP propagation into `sandbox_policy`. Still needed for L1/L2
  IP-level allow rules; mechanism unchanged.
- macOS path. The gateway image is identical across platforms; only
  the network attachment differs. The L3 flow change is
  platform-agnostic.
- The "Envoy default filter chain = deny" decision is an expression of
  an existing design principle (`networking-design.md:1349`), not a
  new policy. We are not changing the design; we are fixing the
  implementation to match it.
