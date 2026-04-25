# L3 flow: restore Envoy → mitmproxy via HTTP CONNECT tunneling

## Summary

Prior to M9-S19 the implementation of L3 (HTTP-inspected) traffic flow
diverged from the original design in `networking-design.md`. The design
requires all TCP from the VM to traverse Envoy, with Envoy routing L3
traffic to mitmproxy on gateway loopback. The pre-cutover implementation
bypassed Envoy for L3 by using a higher-priority nftables table
(`sandbox_l3`) that DNATed TCP 80/443 for policy-allowed IPs directly to
mitmproxy.

This spec (shipped in M9-S19) restored the design-faithful flow by
filling the one gap the design left open: **how Envoy hands the original
destination to mitmproxy across the proxy hop**. It is filled with
HTTP/1.1 CONNECT tunneling (Envoy's `tcp_proxy.tunneling_config`,
terminated by mitmproxy in regular/forward-proxy mode).

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
pre-M9-S19 implementation responded to this by routing L3 traffic around
Envoy entirely (the `sandbox_l3` DNAT table), preserving
`SO_ORIGINAL_DST` at the cost of violating three design points:

1. **Envoy as the single TCP entry point** — the design says *"TCP →
   Envoy (original_dst, protocol-aware routing)"* is the sole TCP path;
   the old implementation had a second path (nftables → mitmproxy).
2. **Policy-driven classification** — the design principle is
   *"Policy drives classification, not protocol sniffing."* The old
   implementation reintroduced port-based routing for L3 (DNAT only for
   TCP 80/443), which made non-HTTP ports to an L3 destination silently
   downgrade to opaque passthrough.
3. **Fail-closed during config propagation** — the design says *"No
   traffic is permitted to a new destination until all components are
   consistent."* The old implementation had a ~2s window where L3
   traffic fell through Envoy as SNI-verified passthrough with no HTTP
   inspection.

### Why the design-faithful flow is achievable

- Mitmproxy does not have to use `SO_ORIGINAL_DST`. Its **regular
  (forward) proxy mode** reads the destination from the
  `CONNECT host:port` line and has always done so — it is mitmproxy's
  original design.
- Envoy's TCP proxy filter has `tunneling_config` that wraps the
  upstream leg in an HTTP/1.1 CONNECT tunnel whose authority is
  derived from the downstream original destination. (Envoy PR
  `#21067`, 2022.)
- This is an off-the-shelf, kernel-privilege-free mechanism supported
  by both projects without custom code.

### Operating constraints

Two constraints shape the implementation choices below.

**No external backwards compatibility required.** sandboxd has no
production users yet. Changes that break wire compatibility, on-disk
format, port numbers, or Envoy config shape with pre-change sessions
are acceptable. Running sessions at upgrade time stop/start rather
than migrating in place. The only compatibility concern is
intra-session: the daemon must be able to restart without losing
session state, which the existing persistence model already handles.

**Connection preservation during policy changes is required.** A
sandbox workload routinely holds many concurrent connections —
HTTP/2 streams, long-lived gRPC, websockets, SSE. Terminating all of
them on every policy change or DNS-cache update is an unacceptable
UX degradation and can look like random-seeming workload failures.
Config updates must be applied in a way that preserves in-flight
connections and only affects *new* ones. This rules out process
restart as the propagation mechanism.

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
            │     ↳ Envoy `tcp_proxy.tunneling_config` emits
            │       `CONNECT <orig-dst>:<port> HTTP/1.1` upstream,
            │       then streams the original TCP bytes through the tunnel
            │     ↳ mitmproxy (regular mode) reads the CONNECT authority
            │       as upstream target and opens the real connection
            │       (no SO_ORIGINAL_DST dependency)
            │     ↳ mitmproxy terminates TLS, inspects HTTP, forwards
            │       to real destination
            ├─ matched L2 chain → original_dst passthrough (unchanged)
            ├─ matched L1 chain → original_dst passthrough (unchanged)
            └─ no match → connection closed (deny by default)
```

### Four properties this restores

- **Single mediated egress path.** All TCP hits Envoy. Envoy is the
  sole routing decision point. No split responsibility, no second DNAT
  target.
- **Policy-driven, not port-driven.** L3 filter chains are keyed on
  destination identity (resolved IPs, CIDR, or catch-all for wildcard).
  All traffic to an L3 destination — any port, any protocol on the
  wire — routes to mitmproxy. Non-HTTP content inside the L3 CONNECT
  tunnel is not cleanly inspected by mitmproxy's HTTP pipeline and
  will close noisily on parse failure (strict "reject non-HTTP" is a
  separate design property not provided by this swap).
- **Fail-closed during propagation.** Envoy has no default passthrough
  chain. Connections that don't match any explicit filter chain are
  closed. Traffic to a destination whose IPs haven't been propagated
  into Envoy's config yet is dropped; applications retry naturally
  after propagation completes.
- **Connection preservation across policy changes.** Listener config
  is delivered to Envoy via xDS (filesystem subscription), not by
  restarting the process. Existing connections continue on the old
  listener generation and complete naturally; only *new* connections
  use the updated filter chains. Long-lived workloads (HTTP/2 streams,
  gRPC, websockets) are unaffected by unrelated policy edits.

### Ports (after M9-S19)

| Port  | Role                                           | Bind              |
|-------|------------------------------------------------|-------------------|
| 53    | CoreDNS (DNS exception)                        | Gateway IP        |
| 10000 | Envoy `original_dst` listener                  | Gateway IP        |
| 18080 | mitmproxy listener (Envoy upstream endpoint)   | `127.0.0.1` only  |

M9-S19 moved the mitmproxy port from `8080` to `18080` and moved the
bind to loopback only. Two reasons: (a) signalling — the port is an
internal Envoy→mitmproxy link, not a VM-facing DNAT target; (b) defence
in depth — if a future change added a DNAT back to port 8080, it would
fail closed rather than silently working.

## Component changes

### Envoy

**Bootstrap split.** The Envoy configuration is split into a static
bootstrap file and a dynamic listener file:

- Bootstrap (static, written once per session): admin, clusters
  (including the new `mitmproxy` cluster and the existing
  `original_dst` cluster), and a `dynamic_resources.lds_config`
  pointing at a filesystem `path` for the listener.
- Listener file (dynamic, rewritten on each DNS propagation event):
  the listener's `filter_chains` — the only piece of Envoy config
  that changes at runtime.

Clusters stay in the static bootstrap because their definitions never
change during a session's lifetime.

**New cluster `mitmproxy`**:

- `type: STATIC`, single endpoint `127.0.0.1:18080`
- `typed_extension_protocol_options` set to
  `envoy.extensions.upstreams.http.v3.HttpProtocolOptions` with
  `explicit_http_config.http_protocol_options: {}` — forces HTTP/1.1
  (HTTP/2 CONNECT is unsupported by mitmproxy, upstream issue
  `#1138`)
- TCP health check (1s timeout, 5s interval) so a dead mitmproxy shows
  up in Envoy's admin stats
- **No transport-socket wrapping.** The cluster uses the default
  `raw_buffer` upstream transport. There is no
  `upstream_proxy_protocol` wrapper — the CONNECT preface is emitted
  by `tunneling_config` on the per-chain `tcp_proxy` filter, not by
  a transport-socket header.

**L3 filter-chain compilation** (in `sandbox-core/src/policy.rs`):

- Per-domain L3 destination: filter chain matched by `prefix_ranges`
  built from the DNS cache's current resolved IPs for the domain,
  routing to `cluster: mitmproxy`. (Replaces the pre-M9-S19 SNI-only
  match routing to `original_dst`.)
- `Destination::Cidr` at L3: filter chain matched by `prefix_ranges`
  on the CIDR, routing to `cluster: mitmproxy`.
- Wildcard `*` L3 destination: default filter chain (no match),
  routing to `cluster: mitmproxy`. *(Superseded — bare-`*` host is
  rejected under the v2 schema (M10-S1); the `default_filter_chain`
  code path below is therefore unreachable in practice. See the
  2026-04-21 spec for the v2 schema and the `*.<suffix>` wildcard
  rules that replaced it.)*
- **YAML indent sharp edge** (discovered during M9-S19): the emitted
  `default_filter_chain:` key must sit at the same indent as
  `filter_chains:` — both are direct fields of the Listener resource
  (sibling of `address`, `listener_filters`, etc.). The project
  templates use 4-space indent at that level today. A two-space
  slip once caused `default_filter_chain` to be parsed as a peer of
  `resources:` at the DiscoveryResponse root, leaving the Listener
  with no chains at all; Envoy then silently closed every connection
  while admin stats still looked healthy. The compiler regression test
  `compile_l3_wildcard_emits_default_filter_chain` in
  `sandboxd/sandbox-core/src/policy.rs` guards the exact indent.
  *(Context: retained as defensive guidance — the `default_filter_chain`
  emitter path is no longer exercised by v2 policies, but the indent
  rule still applies if the emitter is reintroduced for a future
  catch-all use case.)*
- **Destination port predicate** on every L3 chain. L3 filter chains
  match on destination identity (prefix_ranges from resolved IPs or
  CIDR) and destination port derived from the rule. *(Amendment to
  the original "No port predicate" decision — see
  `.tasks/specs/2026-04-21-port-explicit-policies-presets-observability-design.md`
  § "Amendments to the L3 spec and its landed implementation" item 1.)*
- In each L3 chain the `tcp_proxy` filter sets
  `tunneling_config.hostname = "%DOWNSTREAM_LOCAL_ADDRESS%"` so the
  CONNECT authority Envoy sends upstream is the downstream original
  destination (IP:port as observed on the `original_dst` listener).
  This primary path was validated end-to-end during M9-S19 on Envoy
  1.32.2 (the pinned version) — see
  `.tasks/verification/20260420-connect-tunneling/` for the
  reproducible shell harness. A dynamic-metadata fallback (populate
  via `set_filter_state` earlier in the chain, reference from
  `tunneling_config.hostname` as `%DYNAMIC_METADATA(...)%`) remains
  documented as a contingency should a future Envoy version regress
  around Envoy issue `#23700`; it has **not** been implemented. The
  verification harness should be re-run on any Envoy version bump so
  this contingency is invoked deliberately, not discovered at
  runtime.
- `tunneling_config.protocol` is left unset — Envoy's default is
  HTTP/1.1, which matches the cluster's `HttpProtocolOptions` pin.
  If a future Envoy change flips the default, the cluster-level
  `HttpProtocolOptions` still forces HTTP/1.1 upstream, so the wire
  protocol is pinned end-to-end by the cluster config regardless of
  the per-filter default.

**No default passthrough chain.** Envoy's listener has no catch-all
chain for non-L3 destinations. Unmatched connections are closed.

**L1/L2 chains**: unchanged — existing matching criteria (SNI for L2,
destination IP for L1) and existing routing (`original_dst` passthrough
after SNI validation for L2, opaque TCP for L1) stay as they are.

### mitmproxy

- Bind: `127.0.0.1:18080` (was `0.0.0.0:8080` or equivalent).
- Mode: **`regular`** (forward proxy), not transparent. Flags:
  `--mode regular --listen-host 127.0.0.1 --listen-port 18080`.
- Reads the upstream destination from the `CONNECT host:port` request
  line emitted by Envoy's tunneling config; opens the upstream
  connection to that target; MITMs the tunneled TLS using the
  per-session CA (identical TLS MITM behaviour to transparent mode).
- Proxy-Authorization not required; mitmproxy's regular mode does not
  enable auth unless the `proxyauth` addon is loaded (it isn't).
- The current pinned version (`mitmproxy 11.1.3`) supports this
  natively — no upgrade required.
- Existing addons (`policy_addon.py`, `passthrough_addon.py`) run
  unchanged — they operate on the inner HTTP request/response, not on
  how the connection was established.

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
  cloud-metadata block, IPv6 drop, MASQUERADE). *(Amendment: VM-egress
  filtering now happens inside this table as conditional DNAT over
  `policy_allow_{tcp,udp}` concat sets — see
  `.tasks/specs/2026-04-21-port-explicit-policies-presets-observability-design.md`
  Part 3 / "Placement in the nftables pipeline".)*
- Envoy-egress rules in `sandbox_policy` are kept unchanged (DNS-derived
  IP allow rules for Envoy's outbound connections to L1/L2
  destinations). *(Amendment: the prior VM-egress reject behavior of
  this table is removed; those packets now flow through the DNAT path
  above into the deny-logger. See the 2026-04-21 spec §
  "Amendments to the L3 spec and its landed implementation" item 2.)*
- `sandbox` (deny-all forward baseline).

Gateway nftables tables after M9-S19: three (`sandbox`,
`sandbox_dnat`, `sandbox_policy`).

### Configuration propagation (new subsystem concern)

Before M9-S19 the DNS propagation loop wrote only nftables rules.
Post-cutover it also rewrites Envoy's listener filter chains when the
resolved IPs for an L3 domain change.

**Mechanism: xDS via filesystem subscription (LDS).** Envoy's static
bootstrap config points its Listener Discovery Service (LDS) at a
filesystem path inside the gateway container. sandboxd writes the
updated listener YAML to that path on each DNS propagation event,
using an atomic rename so Envoy observes a consistent file. Envoy
detects the change, creates a new listener generation with the
updated filter chains, and routes *new* connections through it. The
old generation keeps serving existing connections until they close
naturally. **No connection drops for unrelated destinations, no
process restart, no request failures for in-flight work.**

This satisfies the connection-preservation constraint stated above.
Process restart was considered and rejected for this reason: a
workload holding dozens of concurrent connections would see all of
them reset on every policy change, which manifests as random-seeming
failures to the workload author and breaks long-lived protocols
(HTTP/2, gRPC streams, websockets) outright.

Filesystem subscription is a standard Envoy xDS transport — it
requires only that sandboxd can write files into a volume the gateway
container reads. No gRPC xDS server. CDS for the mitmproxy cluster is
not required (cluster definition is static; only the listener's
filter chains change).

**Publication mechanism from sandboxd to the container.** Other gateway
configuration (bootstrap, mitmproxy policy, CoreDNS config) is delivered
via `docker exec` piping stdin into a file inside the container (see
`sandboxd/sandbox-core/src/policy_distributor.rs`,
`write_file_to_container`, approx. lines 267–315). That mechanism
produces `Modified` inotify events on the destination file. Envoy's
filesystem LDS **only fires on `MovedTo` inotify events**, not on
`Modified` events — this is acknowledged upstream design (issue
`envoyproxy/envoy#20474`). A direct `docker exec > file` write would
therefore be silently ignored by the listener watcher.

M9-S18/S19 adopted option (a) below; option (b) is kept for historical
context:

(a) **[Shipped.]** A per-session host directory
    (`$XDG_RUNTIME_DIR/sandboxd/listeners/<session-id>/`, with
    `~/.local/share/sandboxd/listeners/<session-id>/` fallback when XDG
    is unset, and a `SANDBOX_LISTENER_DIR` env override; see
    [`listener_host_root`] for the resolver) is bind-mounted into the
    gateway container at `/etc/envoy/listeners/`. sandboxd writes the
    listener file from the host via tempfile + `fs::rename` on the same
    filesystem, producing the `MovedTo` event Envoy requires. The
    implementation lives in
    `sandboxd/sandbox-core/src/atomic_listener_writer.rs` and enforces
    the writer-level invariant below by parsing the
    `FILTER_CHAINS_BEGIN_MARKER` / `FILTER_CHAINS_END_MARKER` boundary
    and rejecting any diff outside that region.
(b) Keep `docker exec` and run
    `sh -c 'cat > tmp && mv tmp final'` inside the container so the
    rename happens there, producing the required `MovedTo` event. Not
    adopted.

The bootstrap must set `dynamic_resources.lds_config.path_config_source.path`
to the listener file and `watched_directory` to the parent directory
(the watcher needs to observe rename-into events on the directory,
not edits to the file path directly).

**Writer-level invariant.** Between any two generations, **only
`filter_chains` and `default_filter_chain` should differ**. Changes
to `listener_filters`, `metadata`, `socket_options`,
`traffic_direction`, the bind address, or
`per_connection_buffer_limit_bytes` force a full listener drain and
reset existing connections, which destroys the connection-preservation
property. `AtomicListenerWriter` enforces this by marker-delimited
content comparison (`FILTER_CHAINS_BEGIN_MARKER` /
`FILTER_CHAINS_END_MARKER`); any non-matching diff outside that region
returns `ListenerWriteError::InvariantViolated` and the new generation
is rejected.

**Static-listener caveat.** Envoy refuses to update a
statically-defined listener via LDS — the listener must be delivered
via LDS from session start. The bootstrap/LDS split must happen on
day one and cannot be retrofitted to a running session that started
with a static listener.

**Ordering.** For L3 destinations the Envoy listener file *is* the
gate — there is no per-IP nftables rule to sequence after it. The
existing outside-in propagation order
(`networking-design.md:1345-1349`) continues to govern L1/L2:
`sandbox_policy` nftables rules are installed last, after inner
components are consistent. L3 propagation fits inside the same window
— the Envoy listener file is written alongside the inner-component
updates, before nftables.

## Design doc amendment (`networking-design.md`)

The design specifies the L3 pipeline but never says how Envoy hands the
destination to mitmproxy. Minimal targeted amendment.

**Add to `##### Envoy` classification list (around line 512):**

> level 3 destinations: route to the mitmproxy cluster on gateway
> loopback, wrapping the upstream leg in an HTTP/1.1 CONNECT tunnel
> whose authority is the downstream original destination (Envoy
> `tcp_proxy.tunneling_config`); mitmproxy reads the CONNECT
> authority as its upstream target, so no `SO_ORIGINAL_DST` dependency
> survives the proxy hop.

**Add to `##### mitmproxy` bullet list (around line 520):**

> runs in regular (forward) proxy mode; receives an HTTP/1.1 CONNECT
> on its listener from Envoy, parses the authority as the upstream
> target, and performs TLS MITM on the tunneled connection.

The traffic-flow ASCII art (lines 139–147) and the assurance-level
exit-point table (line 395, "Level 3 — HTTP inspected → Full pipeline
traversal") already describe the correct flow. The amendment closes the
mechanism gap without restructuring the document.

## User-facing doc updates

### `docs/concepts/networking.md`

- Fix the request-flow mermaid diagram (lines 78–107): the L3 branch
  becomes `Envoy ▸ CONNECT tunnel ▸ mitmproxy ▸ External`. Remove the
  `Forward to 127.0.0.1:8080` wording (no longer accurate post-M9-S19);
  replace with a prose line describing HTTP/1.1 CONNECT as the
  Envoy→mitmproxy contract.
- New subsection **"Policy changes are fail-closed during
  propagation"**: when a policy is applied, updated, or a session
  starts, components are reconfigured in outside-in order; newly-allowed
  destinations are briefly unreachable until all components are
  consistent; this is intentional, not a bug; applications are expected
  to retry. Links back to `networking-design.md`'s fail-closed section.
- Explicit statement in the nftables / request-flow prose that L3
  applies to all traffic to an L3-declared destination regardless of
  port. Note that L3 inspects HTTP — with or without TLS; HTTPS is
  MITM'd using the per-session CA, and plain HTTP flows through the
  CONNECT tunnel and is inspected directly. Non-HTTP protocols inside
  the L3 CONNECT tunnel are not cleanly inspected by mitmproxy's HTTP
  pipeline and will close on parse failure rather than being silently
  passed through.

### `docs/guides/network-policies.md`

- New subsection **"What happens when you apply or change a policy"**:
  expect the first connection after policy change / session start to
  fail briefly, then succeed; standard retry logic handles this;
  applies equally to `policy apply`, `policy update`, session `start`,
  and cache-TTL expiry events.
- Note on L3 level: L3 inspects HTTP — with or without TLS (HTTPS is
  MITM'd using the per-session CA; plain HTTP is inspected directly
  through the tunnel). Non-HTTP protocols inside the L3 tunnel (raw
  TCP, custom TLS protocols) will not be cleanly inspected and may
  close on parse failure — use L1 (transport) or L2 (TLS-verified)
  for those.

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

### Verification harness (Envoy CONNECT tunneling)

`.tasks/verification/20260420-connect-tunneling/` contains a standalone
shell harness (`run-verification.sh` + `in-container.sh` +
`envoy-primary.yaml`) that reproduces the CONNECT-tunnel flow end-to-end
against the pinned gateway image. It proves that
`tunneling_config.hostname = "%DOWNSTREAM_LOCAL_ADDRESS%"` interpolates
correctly on the current Envoy version (1.32.2 at M9-S19 time) and that
the CONNECT `:authority` emitted upstream equals the downstream
original destination. Re-run this harness on any Envoy version bump
before landing the bump — it is the deterministic signal that the
documented dynamic-metadata fallback is still not required.

### Unit tests (Rust)

In `sandbox-core/src/policy.rs` and `sandbox-core/src/dns_propagation.rs`:

- **Flip assertions** in `compile_level3_envoy_no_mitmproxy_cluster`
  and any sibling tests that assert the mitmproxy cluster is absent
  from Envoy config. Mitmproxy cluster must now be present, with
  `typed_extension_protocol_options` set to
  `envoy.extensions.upstreams.http.v3.HttpProtocolOptions` and
  `explicit_http_config.http_protocol_options` populated (HTTP/1.1).
- **New test**: L3 filter chain's `tcp_proxy` filter has
  `tunneling_config.hostname` set to the expected format string
  (`%DOWNSTREAM_LOCAL_ADDRESS%` or the dynamic-metadata fallback).
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
- **New assertion**: the Envoy access log entry for an L3 connection
  shows an HTTP CONNECT request with `:authority` set to the original
  destination (IP:port), confirming the tunnel is in place. This
  doubles as the "appears in both logs" assertion above.
- **New assertion (empirical, non-HTTP behaviour)**: raw TCP
  (non-HTTP) to an L3 destination's IP on port 443 is observed to
  close during mitmproxy's HTTP-parse phase — not opaquely passed
  through. The assertion should be written against the actual
  observed failure mode (connection close with parser error), not
  against a claim that mitmproxy "rejects" non-HTTP cleanly.
- **New assertion (connection preservation)**: open a long-lived HTTP
  response stream to an allowed L3 destination; while it is open,
  apply a policy update that adds an *unrelated* domain; verify the
  original stream receives its remaining bytes without reset. This is
  the headline property xDS-based propagation buys us; a process
  restart would visibly break this test.

The originally-proposed "first connection may fail ~1–2s then succeeds"
e2e test is **not** included. It would be timing-dependent and flaky;
the fail-closed property is covered deterministically by the unit test
above (empty DNS cache → no L3 chain → traffic dropped).

## Post-implementation consistency pass

After the code change is complete and tests pass, run a structured
sweep to catch second-order staleness.

**Grep sweep across the repo** (code, tests, docs, comments).

*Negative-presence (must each have zero matches in implementation code;
matches acceptable only in rationale/historical comments):*

- `sandbox_l3`.
- `8080` — only intentional references remain (none expected in sandbox
  code after the port flip).
- `SO_ORIGINAL_DST` — remains on Envoy's `original_dst` listener
  filter (that part is correct and unchanged); does **not** appear in
  the mitmproxy codepath post-change.
- `upstream_proxy_protocol` — never adopted.
- `PROXY protocol v2` / `PROXY v2` — absent from implementation code
  and comments; acceptable only in historical notes or rejected-option
  writeups.
- `transparent mode` / `--mode transparent` — zero matches in
  implementation code, gateway `entrypoint.sh`, and Dockerfile;
  acceptable only in rationale comments explaining why we chose
  regular mode.
- `bypasses Envoy` / `skip Envoy` / `Envoy is bypassed`.
- `pre-propagation` / `falls through to Envoy` / `~2 seconds`.
- `tcp dport 8080 accept`.
- `original_dst` cluster referenced in an L3 context.
- `dport { 80, 443 }` / any port-based routing in an L3 context.

*Positive-presence (must each have at least one match):*

- `tunneling_config` — appears in `sandbox-core/src/policy.rs` in the
  L3 chain compiler.
- `--mode regular` — appears in the gateway `entrypoint.sh` in place
  of any prior `--mode transparent`.
- `HttpProtocolOptions` (or `explicit_http_config`) — appears in
  `sandbox-core/src/policy.rs` in the mitmproxy cluster compiler,
  pinning HTTP/1.1 upstream.

**File-level read-through** — not just grep, re-read end-to-end for
subtle inconsistencies:

- `networking-design.md` — coherent after the amendment?
- `docs/concepts/networking.md` — diagram and prose align?
- `docs/concepts/architecture.md` — L3 prose accurate?
- `docs/guides/hardening.md` — any L3-path assertion that changed?
- `docs/guides/network-policies.md` — new propagation section fits?
- `docs/guides/troubleshooting.md` — new entries fit existing
  structure?
- `sandbox-core/src/policy.rs` — the comment block near
  `compile_envoy_bootstrap` (was lines 862–888 pre-cutover) has been
  replaced with accurate commentary on the CONNECT-tunneling flow
  (Envoy `tunneling_config` → mitmproxy regular mode). Post-M9-S20 the
  line numbers may shift; anchor on the function name.
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
- **Gateway image**: no mitmproxy rebuild or version bump was required —
  the pinned `mitmproxy 11.1.3` supports regular-mode CONNECT
  natively. The gateway `entrypoint.sh` mitmproxy startup line was
  updated to `--mode regular --listen-host 127.0.0.1 --listen-port
  18080`. Daemon pins the image digest as usual.
- **Daemon binary**: compiles the new Envoy config and the
  `sandbox_l3` codepaths have been deleted.
- **Backwards compatibility**: none required — the change was fully
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
