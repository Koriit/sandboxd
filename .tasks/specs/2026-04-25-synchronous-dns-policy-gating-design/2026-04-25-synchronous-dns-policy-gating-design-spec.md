# Synchronous DNS-policy gating

## Summary

This spec closes the DNS-rotation propagation race architecturally by
gating the CoreDNS plugin's DNS response to the VM on a sandboxd-side
ack that the resolved IPs have been admitted to nftables, the Envoy
listener, and (where applicable) mitmproxy. It replaces the existing
poll-driven `dns_propagation_loop` cadence (2 s) with an event-driven
synchronous handshake on first observation of a new (domain, IP-set)
tuple, retains the loop only as a steady-state reconciler, and removes
the two CDN-supernet workarounds (`CARGO_FASTLY_CIDR_POOL` /
`GITHUB_INTERACTIVE_CIDR_POOL`) that were the M10-S5..S8 stop-gap.

One milestone (M10-S10), one document. Decomposition into work items
is deferred to a delivery map of the same shape as
`2026-04-21-port-explicit-policies-presets-observability-delivery.md`.

## Context

### Why this is needed

The sandbox places the agent VM behind a layered network gateway. The
outbound flow on first contact with a fresh hostname is:

1. The VM resolves `host.example.com`. CoreDNS in the gateway container
   answers (typically <1 ms after upstream returns), and writes the
   resolved IPs to `/etc/coredns/resolved.json` via the Reporter
   (`networking/coredns-plugin/report.go:47-89`, atomic rename).
2. sandboxd's per-session DNS propagation loop polls `resolved.json`
   every 2 s (`sandboxd/sandboxd/src/main.rs:2240-2479` — `dns_-`
   `propagation_loop`), updates the `DnsCache`
   (`sandbox-core/src/dns_propagation.rs:42-249`), and on detected
   change calls `propagate_dns_changes`
   (`sandbox-core/src/dns_propagation.rs:429-472`):
   - rewrites the per-session Envoy listener YAML via
     `AtomicListenerWriter` (filesystem LDS);
   - waits for Envoy's `update_success` / `update_rejected` counters to
     advance via `wait_for_lds_ack` (`sandbox-core/src/lds_ack.rs:238`,
     introduced in `3098b67`);
   - injects a regenerated `sandbox_dnat` + `sandbox_policy` ruleset
     populating the per-protocol concat sets `policy_allow_tcp`/
     `policy_allow_udp` keyed on `ipv4_addr . inet_service`
     (`generate_domain_ip_rules`,
     `sandbox-core/src/dns_propagation.rs:358-413`).
3. The VM, having already received the DNS answer in step 1, opens TCP
   to one of the resolved IPs. nft set-membership decides allow/deny.
   If the IP is not yet in `policy_allow_tcp`, the connection falls
   through to the deny-logger on `:10001` and is RST'd
   (placement: `2026-04-21-port-explicit-policies-presets-observability-design.md`
   §"Placement in the nftables pipeline").

There is therefore a **bounded but non-zero window** — bounded above
by the 2 s poll interval plus the LDS ack time (typically ~250 ms,
`sandbox-core/src/lds_ack.rs:9-13`) — during which the VM holds an IP
the daemon has not yet admitted. The window is the race.

#### Observed evidence

The race manifests reliably for hostnames that

- ship single-digit-second TTLs (Fastly's `index.crates.io` /
  `static.crates.io` ship TTL=2 s; GitHub's
  `github.com`/`codeload.github.com` ship TTL=60 s but rotate within
  a multi-IP /20 pool); and
- the VM's own `getaddrinfo` resolves via the gateway's CoreDNS,
  which forwards to Docker's embedded resolver
  (`networking/gateway/Corefile:30`); successive resolutions can land
  on different rotation slots of the same authoritative pool.

The dominant captured failures:

- `tests/e2e/test_m10_s5_presets.py::test_cargo_preset_allows_cargo_-`
  `fetch` failing with `curl: (35) Send failure: Connection reset by
  peer` mid-TLS to `static.crates.io` after `policy_propagated` had
  already fired with the prior rotation slot in cache. Verifier
  handoff: `.tasks/handoffs/20260425-124800-verifier-m10-s8-group9-`
  `cargo-preset-still-failing.md`.
- `tests/e2e/test_m10_s5_presets.py::test_github_repo_preset_scopes_-`
  `to_one_repo` failing with `git clone … Connection reset by peer`
  on `github.com` 800 ms after `propagated=true` fired with .4 in
  cache while the VM resolved .3.  Investigation handoff:
  `.tasks/handoffs/20260425-121741-m10-s8-group9-multihost-propagation-`
  `race.md` (hypothesis "d" confirmed).

#### What the existing workarounds buy

Two preset-level patches in `sandbox-cli/src/presets/builtin.rs` papered
over specific symptoms:

- `CARGO_FASTLY_CIDR_POOL` (`9d1dca7`,
  `sandbox-cli/src/presets/builtin.rs:269-277`) emits HTTP-level CIDR
  rules for `151.101.0.0/16` + `146.75.0.0/17`, the two Fastly Anycast
  supernets serving `index.crates.io` / `static.crates.io`.
- `GITHUB_INTERACTIVE_CIDR_POOL` (`874a9bb`,
  `sandbox-cli/src/presets/builtin.rs:503-510`) emits HTTP-level CIDR
  rules for `140.82.112.0/20` + `192.30.252.0/22`, the two ranges from
  `https://api.github.com/meta` covering `github.com` / `codeload` /
  `api.github.com` rotation.

Both rely on the existing L3 routing primitive: an HTTP-level CIDR rule
gives Envoy a filter chain that admits the rotated-out IP into
mitmproxy, where the *domain* rule's `http_filters` carries the
allow/deny decision via the HTTP `Host` header. They are correct but
unscalable: every flaky service requires an operator to hand-source its
published Anycast pool, and the patch is silently insufficient for any
service whose pool is not stable across resolution events (CDN POPs
that A/B new IPs, geo-routed CDNs, etc.). They are removed by this
spec; see "Workaround removal" below.

### Why now

The M10-S8 polish sweep landed the in-window UNION semantics for
`DnsCache` (`f7f3d7d`) which closed *part* of the race — once the
gateway and VM each contribute an IP within the same TTL window, the
cache no longer evicts the older one. UNION removes the
post-resolution-eviction failure mode but does nothing for the
*pre-first-resolution* failure: when the VM's `getaddrinfo` arrives at
CoreDNS, gets a brand-new IP back, and opens TCP before sandboxd's 2 s
poll has even noticed there is something to propagate. UNION cannot fix
that — by definition there is nothing to union with yet. The
synchronous-gating fix below is the architectural close-out for the
class of failures UNION cannot reach.

The propagation contract introduced by `3098b67` (LDS-ack wait before
flipping `propagated=true`) is the closest precedent in the codebase
for what this spec proposes: it is also a "hold a state transition
until the downstream component has acked" pattern. The wire here is
different (CoreDNS plugin holds a DNS response rather than sandboxd
holding a propagated bit), but the shape is the same.

### Operating constraints

**No external backwards compatibility required.** sandboxd has no
production users. Behavioural changes between gateway/daemon versions
require a stop/start of running sessions; no on-disk migration is
introduced by this spec.

**Connection preservation during policy changes is required**
(inherited unchanged from the L3 spec). Synchronous gating affects
*first-resolution* DNS responses; existing connections through Envoy
are unaffected. The 2 s reconciliation loop continues as a safety net.

**Additional first-DNS latency is acceptable.** Per the user's explicit
guidance, the latency budget below assumes a one-time per-(domain,
IP-set) cost on first observation of a new tuple; steady-state queries
do not pay it.

## Goals and non-goals

### Goals

1. The VM never receives a DNS answer for an allowed domain whose
   resolved IPs are not yet admitted to `policy_allow_tcp` /
   `policy_allow_udp` (and, for HTTP-level rules, present in the Envoy
   listener's filter-chain `prefix_ranges`).
2. The first-resolution gating is bounded in latency, observable, and
   degrades to a documented behaviour (see §"Error and timeout
   behavior") on sandboxd unavailability.
3. The CDN-supernet workarounds (`CARGO_FASTLY_CIDR_POOL`,
   `GITHUB_INTERACTIVE_CIDR_POOL`) are removed; the cargo and
   github-repo E2E presets pass on hand-resolved domain rules alone.
4. Existing per-session bind-mount infrastructure
   (`session_events_host_dir`, `session_listener_host_dir`) is reused;
   no new container or process boundary.

### Non-goals

- **Path C (CoreDNS plugin writes nft directly).** Rejected. It crosses
  a process and language boundary (Go writes nft state owned by the
  Rust daemon's policy_distributor / DnsCache rebuild-from-cache
  model), forces nft-rule generation logic into two languages, and
  removes sandboxd's single source of truth for the join of
  `policy + cache → ruleset` (see `generate_domain_ip_rules` doc
  block, `dns_propagation.rs:319-357`). Path C trades the propagation
  race for a divergence race between the two writers; it is not an
  architectural improvement.
- **UDP DNS race for non-A queries.** AAAA queries are denied at the
  request layer with an empty answer (`networking/coredns-plugin/handler.go`
  in the AAAA branch of `ServeDNS`). SVCB/HTTPS queries are forwarded
  upstream and only have the ECH SvcParam stripped from the response —
  but the gate is invoked only for A queries (`ri.qtype == dns.TypeA`
  in `responseInterceptor.WriteMsg`) since A is the only qtype whose
  resolved IPs need to be admitted into nft / Envoy. SVCB/HTTPS
  responses therefore never enter the gating path, and there is no
  race. No change here.
- **IPv6.** Sandbox networking is IPv4-only by design
  (`Corefile`/handler stripping AAAA above; nft sets are
  `ipv4_addr . inet_service`). Out of scope for this milestone; an
  IPv6 follow-up would extend the gate uniformly.
- **Multi-resolver and external-DNS scenarios.** The VM resolves only
  via the gateway's CoreDNS (`/etc/resolv.conf` is pinned to the
  gateway IP at provisioning time). VMs that bypass CoreDNS — by
  hard-coding an upstream resolver in their workload — are outside the
  threat model.
- **Caching layer below CoreDNS in the VM** (e.g.
  systemd-resolved's per-link cache). The gate operates on what
  CoreDNS *answers*; if the VM serves a stale answer from its own
  cache, the cached IP is by construction one CoreDNS already
  returned through the gate, and the post-gate steady-state UNION
  semantics keep it admitted for the cached entry's lifetime.
- **Restructuring the propagation contract for non-DNS state.**
  `policy_applied`, `policy_updated`, `policy_propagated` lifecycle
  events keep their current shape (M10-S2). The gate adds a new
  per-resolution event class but does not redefine those.

## Target design

### Sequencing

This is a single daemon + gateway-image release. CoreDNS plugin and
sandboxd ship in lockstep; a sandboxd that does not understand the new
gate request must not be paired with a CoreDNS plugin that produces
them, and vice versa. The gate is keyed by a per-session Unix-domain
socket on a bind mount that exists only when both sides are at the new
version (see §"IPC primitive").

No phased rollout within the spec. Existing sessions stop and restart
to pick up the new gateway image.

### Design overview

CoreDNS resolves a query to a non-empty IP set. **Before** writing the
DNS response back to the VM, the plugin issues a `propagate-and-ack`
request to sandboxd carrying the (domain, IPs, ttl, port-set-from-
policy) tuple. sandboxd performs the existing
`generate_domain_ip_rules` → nft inject → `compile_envoy_listener` →
`AtomicListenerWriter` → `wait_for_lds_ack` chain *synchronously* for
this single change, then acks. CoreDNS then writes the DNS response.

If sandboxd does not ack within a per-request deadline, the plugin
releases the response anyway (fail-open with denial logged — see
§"Error and timeout behavior") and emits a `dns_gate_timed_out`
structured event so the operator can observe degradation.

The 2 s `dns_propagation_loop` is **kept** as a steady-state
reconciler: it still consumes `resolved.json` (the IP-report stream is
unchanged), runs UNION-merging of cache entries, and re-derives
listener+nft state on TTL expiry / `Removed` changes. What changes is
that the loop is no longer the *primary* path for first-resolution
correctness — it becomes the safety net for cases where the gate
timed out, fired but the change-set was empty (no-op resolution), or
the steady-state cache simply rolled forward.

### Sequence diagram

The diagram traces the new first-resolution path. Steady-state and
non-gated paths are noted at the end.

```
VM                CoreDNS plugin       sandboxd            nft / Envoy / mitmproxy
 |                      |                  |                       |
 | A? host.example.com  |                  |                       |
 |--------------------->|                  |                       |
 |                      | (forward upstream, get IPs)               |
 |                      |                  |                       |
 |                      | propagate-and-ack request                 |
 |                      | { domain, ips, ttl, corr_id, deadline }   |
 |                      |----------------->|                       |
 |                      |                  | join (domain, ips) with policy
 |                      |                  | → (ip, port) tuples per protocol
 |                      |                  | nft -f sandbox_dnat + sandbox_policy
 |                      |                  |---------------------->|
 |                      |                  |        nft batch ack  |
 |                      |                  |<----------------------|
 |                      |                  | AtomicListenerWriter  |
 |                      |                  | (rename listener.yaml)|
 |                      |                  |---------------------->|
 |                      |                  | wait_for_lds_ack      |
 |                      |                  |  (poll Envoy stats)   |
 |                      |                  |<----------------------| (Accepted)
 |                      |                  |                       |
 |                      |    ack { corr_id, status: ok }            |
 |                      |<-----------------|                       |
 |                      |                  |                       |
 |  A: host.example.com → ips              |                       |
 |<---------------------|                  |                       |
 |                      |                  |                       |
 | TCP SYN → ip:443     |                  |                       |
 |--------------------------------------------------------->| (admitted, DNAT to Envoy :10000)
```

Steady-state queries (the same `(domain, ip-set)` already in cache)
take a short-circuit path: the plugin's check against an in-process
"recently-acked" set elides the IPC round-trip. See §"Wire format" for
the cache contract.

### IPC primitive

**Choice: per-session Unix-domain socket on the existing per-session
events bind mount.** Concretely, sandboxd binds
`{events_host_root()}/<session-id>/dns-gate.sock` (host side) which the
gateway sees at `/var/log/gateway/events/dns-gate.sock` inside the
container. The CoreDNS plugin connects on demand from its `WriteMsg`
interceptor.

#### Why this primitive

The constraints the spec imposed:

- Bidirectional with ack — rules out one-way FIFOs and inotify-driven
  drop boxes.
- Bounded latency on first request — rules out anything that would add
  HTTP-stack overhead inside CoreDNS' hot path; UDS framing is a few
  syscalls.
- Survives container restarts — the socket file lives on the host, the
  container side is a bind-mount; restarting the gateway container
  rebinds the same path.
- Crosses the gateway/host boundary — the gateway is a Docker
  container; sandboxd runs on the host. Bind-mounted UDS handles this
  natively (Linux passes the underlying inode through the mount
  namespace; both sides `connect()`/`accept()` on the same path).

Three primitives were considered explicitly:

| Primitive | Bidirectional? | Latency | Restart story | Verdict |
|---|---|---|---|---|
| FIFO pair (request + ack) | Yes via two FIFOs | Low (open + write + read) | Brittle: writers block on no reader; reopen logic per-request | Reject |
| Unix-domain socket (UDS) | Yes (one socket) | Low (`connect` + `write` + `read` per request, or pooled) | Robust: socket file survives, reconnect on `ECONNREFUSED` | **Pick** |
| HTTP over UDS | Yes | Higher (HTTP framing in CoreDNS' Go runtime, JSON parsing, hyper-style overhead in Rust) | Same as UDS | Reject — HTTP framing is overkill for a single request shape |

The events directory is the right home: it already exists per-session,
already has the host-↔-container bind mount path resolution
(`events_host_root()` in `sandbox-core/src/events/mod.rs:64-79`), and
the events ingester (Phase 7 of M10-S2) is the only other long-lived
host↔container conduit on the same mount. Adding the socket file
beside the existing JSONL files keeps the bind-mount surface unchanged.

The socket file's lifecycle is owned by sandboxd:

- created on session start in `create_gateway`
  (`sandbox-core/src/gateway.rs`, alongside the existing
  `events_host_dir` / `listener_host_dir` setup at lines 363-378), and
- removed in `stop_gateway`'s cleanup. The
  `SANDBOX_KEEP_SESSION_EVENTS=1` escape hatch (commit `472da76`) keeps
  the socket file too — useful for post-mortem inspection of the gate
  request stream when an E2E flakes.

CoreDNS plugin connect semantics:

- Lazy connect on first `WriteMsg` interception: the plugin holds no
  socket open across queries by default. A short-lived per-request
  connection is fine at the request rates we expect (single-digit /s
  per session); if profiling shows the connect cost dominating, a
  process-local pool can be added without changing the wire shape.
- On `ECONNREFUSED` / `ENOENT` (sandboxd not running, or the socket has
  not been created yet during an early-boot race), the plugin treats
  the request as `dns_gate_timed_out` synthetically — see §"Error and
  timeout behavior".

#### Why not Path C (plugin writes nft directly)

Listed as a non-goal above; restated here for the IPC choice context:
Path C eliminates the IPC entirely by having the plugin issue
`nft add element` from inside `WriteMsg`. It is rejected because it
forks the rule-generation source of truth across Go and Rust, breaks
sandboxd's "rebuild from `policy + cache`" model, and creates a new
divergence class (CoreDNS adds an element the daemon has no record of;
the next full rewrite from the daemon evicts it). Path D (this spec)
keeps the daemon as the single writer.

### Wire format

JSON over the UDS, framed by length-prefixed line (one JSON object per
`\n`-terminated line). Sufficient for the message volumes here — UDS
delivers in-order, atomically up to `PIPE_BUF`, and JSON keeps the
plugin and daemon on a self-describing wire that does not require a
shared schema artifact.

#### Request: CoreDNS → sandboxd

```json
{
  "kind": "propagate_and_ack",
  "version": 1,
  "correlation_id": "01HZ...ULID",
  "domain": "static.crates.io",
  "qtype": "A",
  "ips": ["151.101.194.137", "151.101.66.137"],
  "ttl_seconds": 2,
  "deadline_ms": 1500
}
```

| Field | Required | Notes |
|---|---|---|
| `kind` | yes | Discriminator. Initial value `propagate_and_ack`; reserved for future variants |
| `version` | yes | Hard-fail if the daemon's accepted set does not include the version. v1 is the first release |
| `correlation_id` | yes | ULID generated by the plugin per request. Echoed in the ack so concurrent requests on a pooled connection can be matched |
| `domain` | yes | The query's lowercased name, trailing dot stripped (matches CoreDNS plugin's `displayName` at `handler.go:45`) |
| `qtype` | yes | `A` only in v1; the gate is not invoked for AAAA (denied at request time) or SVCB / HTTPS (forwarded upstream with the ECH SvcParam stripped from the response — no IPs to admit into nft) |
| `ips` | yes | Non-empty list of resolved IPv4 strings, in the order CoreDNS observed them |
| `ttl_seconds` | yes | The minimum TTL across the resolved A records, matching `Reporter::RecordResponse`'s logic at `report.go:55-62` |
| `deadline_ms` | yes | The plugin's deadline for the ack. The daemon honors this — see §"Error and timeout behavior" |

`port` is intentionally absent from the request: the daemon already
holds the port context (it owns the policy). The daemon joins the
plugin's `(domain, ips)` with each rule's `(port, protocol)` exactly
as `generate_domain_ip_rules` does today
(`sandbox-core/src/dns_propagation.rs:358-413`).

#### Ack: sandboxd → CoreDNS

```json
{
  "kind": "propagate_ack",
  "version": 1,
  "correlation_id": "01HZ...ULID",
  "status": "ok",
  "elapsed_ms": 187
}
```

`status` is one of:

- `"ok"` — the change has been applied to nft and Envoy listener has
  acked LDS update. CoreDNS releases the DNS response.
- `"noop"` — the IPs were already in the daemon's cache and admitted
  (steady-state cache hit, fast-path). CoreDNS releases immediately.
- `"rejected"` — the daemon refused to admit the IPs (e.g. nft inject
  failed, listener rejected by Envoy). CoreDNS treats this as a hard
  deny and **does not** release the response — it returns SERVFAIL to
  the VM instead, mirroring the existing policy-deny posture
  (`handler.go:71-77` returns NXDOMAIN for policy denial; SERVFAIL is
  the natural code for "would-have-allowed but the gateway is broken").
  This case is visible to the operator as a `dns_gate_rejected`
  structured event (see §"Observability").
- `"unknown_session"` — the daemon does not recognise the session
  identity bound to this socket. Should not happen in steady state;
  treated by the plugin as `dns_gate_timed_out` and released
  fail-open (see §"Error and timeout behavior").

`elapsed_ms` is informational; the plugin records it as a metric.

#### Error: sandboxd → CoreDNS (out-of-line)

If the daemon parses the request shape but rejects the version (e.g. a
mismatched gateway image), it returns:

```json
{
  "kind": "propagate_error",
  "version": 1,
  "correlation_id": "01HZ...ULID",
  "code": "unsupported_version",
  "message": "version 2 not supported; daemon speaks v1"
}
```

The plugin treats this as `dns_gate_timed_out` and emits a
`dns_gate_protocol_error` structured event so the operator sees the
mismatch.

#### Plugin-side cache

The plugin keeps a small in-process cache of recently-acked
`(domain, sorted-ips)` tuples with the same TTL window the daemon
uses on its side. On a query whose answer matches a cached entry
unchanged, the plugin emits `propagate_and_ack` anyway with status
`noop` expected, but skips waiting on the deadline — it sends and
fires-and-forgets the request as a heartbeat to keep the daemon's
TTL window fresh. This avoids a full round-trip on every steady-state
query while keeping the daemon's cache aligned. A subset-or-superset
mismatch invalidates the cached entry and falls through to the full
gate path. The cache is not persisted; CoreDNS plugin restarts begin
with a cold cache.

### Latency budget

The latency added on a first-resolution gate is dominated by three
existing operations the daemon already performs on the propagation
path; the gate moves them inside the DNS response window rather than
deferring them by up to 2 s.

| Phase | Typical | Worst-case observed | Notes |
|---|---|---|---|
| UDS connect + JSON write | <2 ms | <10 ms | UDS on a local bind mount |
| nft batch inject (`gateway::inject_nftables_ruleset_public`) | 5–25 ms | ~80 ms | Two-table transaction over `nft -f` (M10-S3) |
| `AtomicListenerWriter::write` (rename) | <5 ms | <20 ms | Same-FS rename, file size O(few KB) |
| `wait_for_lds_ack` until `Accepted` | 100–250 ms | ~500 ms (5 s deadline retained) | Documented at `lds_ack.rs:9-13` |
| JSON ack write back | <2 ms | <5 ms | |
| **Total first-resolution** | **~150–300 ms** | **~600 ms** | Well below the plugin's `deadline_ms = 1500` default |

Steady-state queries (cache-hit short-circuit, status=`noop`) cost only
the UDS round-trip (~5 ms) and do not trigger any nft / listener work.

The numbers above are extrapolated from the LDS-ack helper's
implementation notes (`lds_ack.rs:6-13`) and the integration-test
observations referenced in the M10-S6 regression handoff
(`.tasks/handoffs/20260423-m10-s6-e2e-regression.md`). They are
expected to hold on first measurement; the test plan below requires
empirical confirmation.

User-perceptible? At ~300 ms on first DNS for a brand-new host this is
imperceptible against any real workload — `git clone` and `cargo fetch`
spend tens of seconds in TLS+payload after the resolution. Steady-state
adds <10 ms which is below DNS resolution noise.

### Error and timeout behavior

The plugin's deadline is the contractual upper bound on how long a DNS
answer can be held. When the deadline expires before sandboxd acks:

**Decision: fail-open with denial-class observability (option (c) from
the delegation prompt).** The plugin releases the DNS answer to the VM
unchanged — the workload keeps moving — and emits a structured
`dns_gate_timed_out` event into the existing CoreDNS JSONL stream
(`coredns.jsonl` in the per-session events dir). The daemon's
event-bus ingestion picks it up and surfaces it to operators via
`sandbox events`. The 2 s `dns_propagation_loop` continues to run in
the background and will close the race on its own cadence (within
~2 s + LDS ack), restoring correctness. The deny-logger
(`:10001`/`:10002`) catches any RST'd connection in the window and
emits its own `deny` event, completing the audit chain.

Why not (a) fail-closed (SERVFAIL after timeout):

- A wedged sandboxd process would silently break **all** DNS for the
  VM, not just the unfortunate first-resolution. The blast radius of
  daemon flakiness becomes the entire workload, which is worse than
  the race the gate exists to close.
- The user's stated tolerance — "additional first-connection latency
  is acceptable" — does not extend to "sandboxd outage = DNS outage."

Why not (b) silent fail-open (release the answer, re-introduce the
race without a signal):

- Silent fail-open returns the codebase to its pre-spec state for the
  exact subset of resolutions the gate was designed to fix. With no
  observable signal, an operator cannot distinguish "the gate is
  working" from "the gate has been silently broken for weeks."

(c) preserves availability and makes the degradation observable. The
deny-logger catches any RST'd connection in the gap, so the audit
trail is complete even when the gate fails-open.

#### Specific failure modes

- **sandboxd crashed / restarting.** UDS connect fails with
  `ECONNREFUSED` or `ENOENT`. Plugin treats as `dns_gate_timed_out`,
  releases. The 2 s loop will catch up after restart;
  `policy_propagated` re-fires when the cache + nft state realign
  with the surviving session policy.
- **nft inject failed inside the daemon.** Daemon returns
  `propagate_ack { status: "rejected" }`. Plugin returns SERVFAIL to
  the VM and emits `dns_gate_rejected` (not `dns_gate_timed_out` —
  the daemon answered, it just refused). This path is loud because
  an nft failure is a real bug class.
- **Envoy listener rejected (`LdsAckOutcome::Rejected`).** Same as
  above: ack `status: "rejected"`. Operators see both
  `dns_gate_rejected` and the existing `health_degraded` lifecycle
  event.
- **Daemon admin endpoint slow / `wait_for_lds_ack` returns
  `TimedOut`.** The daemon honors the plugin's `deadline_ms` first:
  if the plugin's deadline fires before the LDS-ack deadline, the
  daemon abandons the wait and returns
  `propagate_ack { status: "ok" }` with the nft side already applied
  but listener uncertain. The plugin releases. The 2 s loop's next
  cycle re-runs `wait_for_lds_ack` from a fresh snapshot. This is the
  same forgiving posture `dns_propagation_loop` already takes when
  LDS ack times out (`main.rs:2433-2442`).
- **Concurrent gate requests for the same domain.** The daemon
  serializes per-session policy state behind the existing
  `propagation_states` mutex (`sandboxd/src/propagation.rs:96-98`).
  Concurrent UDS connections are accepted in parallel; the per-session
  serialization means the second arrival sees the first's `(ip, port)`
  set already admitted and short-circuits to `status: "noop"`.

### Fallback / migration semantics

#### Relationship to `mark_propagated` and `policy_propagated`

The propagation contract introduced by the M10 design and `3098b67`
remains. `policy_propagated` is still the user-observable "policy is
in force" signal, fired once per apply cycle when every
`Destination::Domain` rule has a cache entry and the listener has
acked. The synchronous gate does *not* emit `policy_propagated` —
that event is policy-scoped, not query-scoped. A first-resolution gate
admitting `static.crates.io` does not retroactively change the
"propagated" status of the cargo preset.

What changes is the *timing*: today, `policy_propagated` fires on the
first `dns_propagation_loop` cycle that sees all domains resolved.
With the gate in place, `policy_propagated` fires on the first cycle
*after* the first VM query for each policy domain has been gated and
acked. In typical usage the cycle observation lands within one 2 s
poll of the last domain being queried. Existing CLI `--wait` and E2E
`wait_policy_propagated` flows continue to work unchanged.

#### Relationship to the 2 s `dns_propagation_loop`

**The loop stays.** Three jobs it still owns:

1. **Steady-state reconciliation.** TTL expiry sweeps that drop
   stale cache entries and regenerate the listener+nft state are still
   loop-driven. The gate is a write path, not a sweep.
2. **Recovery from gate timeouts.** When the gate times out
   (`dns_gate_timed_out`), the loop closes the race within 2 s of the
   next `resolved.json` write — the plugin's Reporter still writes
   resolved IPs as it does today, so the loop's input is unchanged.
3. **UNION semantics for in-window rotations.** The cache merge
   logic (`DnsCache::update`,
   `sandbox-core/src/dns_propagation.rs:98-225`) remains the canonical
   place for resolving "gateway and VM each saw a different rotation
   slot" — the gate enforces correctness for the path that goes
   through CoreDNS, but UNION still matters for the post-gate cache
   life cycle (a fresh observation that brings a new IP within the
   TTL window unions into the existing entry).

The poll interval is unchanged at 2 s. There is no tightening of the
loop because the gate already closes the dominant race; loosening to
e.g. 5 s is also out of scope (no benefit observed).

#### `mark_propagated` and the `policy_propagated` lifecycle event

Untouched. The gate writes through the same nft / listener entry
points and the same `propagation_states` registry; the
`mark_propagated` edge fires from the loop, not the gate. This
preserves the M10-S2 contract for `policy_propagated` exactly.

#### On-disk compatibility

No new persisted fields, no schema changes, no `sessions.db` migration.
The gate is purely a runtime IPC; restarts pick up the unchanged on-
disk state.

### Observability

Three new structured event types in the existing event taxonomy
(`sandbox-core/src/events/envelope.rs`); all under the existing
`dns` layer.

| Event | Layer | Fields | When |
|---|---|---|---|
| `dns_gate_request` | `dns` | `domain`, `ips`, `ttl_seconds`, `deadline_ms`, `correlation_id` | Plugin emits before connecting to the daemon. Useful for forensics on a missing ack |
| `dns_gate_ack` | `dns` | `correlation_id`, `status` (`ok`/`noop`/`rejected`/`unknown_session`), `elapsed_ms` | Plugin emits on receiving the ack |
| `dns_gate_timed_out` | `dns` | `correlation_id`, `domain`, `deadline_ms`, `elapsed_ms` (real wall time the plugin waited) | Plugin emits when the deadline fires before any ack |
| `dns_gate_rejected` | `dns` | `correlation_id`, `domain`, `reason` (free-form daemon string) | Plugin emits on `propagate_ack { status: "rejected" }` |
| `dns_gate_protocol_error` | `dns` | `correlation_id`, `code`, `message` | Plugin emits on receiving `propagate_error` from the daemon |

The daemon's side of the IPC also emits a peer event for
correlation: `dns_gate_serviced` with the same `correlation_id`,
`status`, `elapsed_ms` plus the per-cycle counter snapshot deltas
(`nft_inject_ms`, `lds_ack_ms`). Layer is `lifecycle` — this is a
daemon-side event, not a plugin-side one.

#### Metrics (Prometheus-shape, daemon-side)

- `sandboxd_dns_gate_requests_total{session, status}` — counter, label
  `status` ∈ {`ok`, `noop`, `rejected`, `unknown_session`}.
- `sandboxd_dns_gate_elapsed_ms{session, phase}` — histogram, label
  `phase` ∈ {`nft_inject`, `lds_ack`, `total`}.
- `sandboxd_dns_gate_timeouts_total{session, reason}` — counter,
  `reason` ∈ {`plugin_deadline`, `lds_ack_deadline`, `nft_failure`}.

CoreDNS plugin emits its existing per-query metrics unchanged; the
gate counters are sandboxd-side.

#### Log lines

- `tracing::info!` on each ack with `(session, domain, ips, status,
  elapsed_ms)` — keep enough context that an operator can tail the
  daemon log and diagnose flakes without enabling trace.
- `tracing::warn!` on every timeout / rejection / protocol error,
  with the same fields plus the failure reason.

### Compiler and runtime consequences

#### sandboxd

- **New module** `sandbox-core/src/dns_gate.rs`. Owns the UDS listener
  (one per session), the request/ack codec, and the
  `service_gate_request` orchestrator that calls the existing
  `generate_domain_ip_rules` + `AtomicListenerWriter` +
  `wait_for_lds_ack` chain. Runs on the daemon's tokio runtime; the
  per-session listener task is spawned in `start_dns_propagation_loop`
  alongside the existing loop spawn at
  `sandboxd/sandboxd/src/main.rs:2148-2201`, and cancelled in
  `cancel_dns_propagation_loop` at the same site.
- **`generate_domain_ip_rules` is reused unchanged.** The gate is a
  per-resolution invocation of the same join logic; the function's
  current shape (`policy + cache → ruleset string`) is what the gate
  needs.
- **`PolicyDistributor` is not in the gate path.** The gate writes
  through the lower-level helpers
  (`gateway::inject_nftables_ruleset_public`,
  `AtomicListenerWriter`); the distributor's whole-policy semantics
  apply at policy-apply time, not per-resolution.
- **`DnsCache` is updated by the gate path.** Today the cache is
  populated only by the loop's `read_resolved_json` + `cache.update`.
  The gate calls a new `DnsCache::observe(domain, ips, ttl)` (a thin
  wrapper around the same UNION logic) so the cache reflects each
  ack in real time. The loop continues to call `cache.update` from
  `resolved.json`; the two paths converge because both feed into the
  same `entries` map and the UNION semantics are commutative.
- **`DockerExecLdsProbe` is reused unchanged** for the gate's
  `wait_for_lds_ack` call.

#### CoreDNS plugin (`networking/coredns-plugin/`)

- New file `gate.go` with the UDS client, request encoder, and ack
  decoder. Connects on `WriteMsg` interception in `responseInterceptor`
  (`handler.go:122-156`), holds the response under
  `dns.ResponseWriter.WriteMsg` until the ack lands or the deadline
  fires.
- New file `gate_cache.go` with the small in-process recently-acked
  cache (TTL-aligned).
- `setup.go` gains a `gate_socket` directive in the Corefile parser
  (`networking/coredns-plugin/setup.go:64-105`); when set, the plugin
  runs in gated mode, when unset, the plugin behaves as today
  (legacy mode). The gateway image's Corefile sets the directive to
  `/var/log/gateway/events/dns-gate.sock`.
- `events.go` gains the four new event variants
  (`dns_gate_request` / `_ack` / `_timed_out` / `_rejected` /
  `_protocol_error`) emitted into the same JSONL stream the existing
  `query_allowed` / `query_denied` go to.

#### Gateway image

- The Corefile (`networking/gateway/Corefile`) gains the
  `gate_socket /var/log/gateway/events/dns-gate.sock` directive in the
  `sandboxpolicy` block.
- No new processes or volume mounts. The events bind mount already
  carries the socket path.

### Test plan

#### Hermetic (default `make test`, no Docker)

Three new groups in `sandbox-core/src/dns_gate.rs`:

- `dns_gate_writes_through_to_concat_set_on_first_observation` —
  build a `Policy`, an empty `DnsCache`, a fake gateway that records
  inject calls, drive `service_gate_request` with one IP. Assert: the
  recorded ruleset contains `<ip> . 443` in `policy_allow_tcp`.
- `dns_gate_short_circuits_on_cache_hit` — pre-populate the cache,
  drive the same request, assert the gateway's recorded inject count
  is zero and the ack carries `status: "noop"`.
- `dns_gate_returns_rejected_on_lds_failure` — wire a
  `ScriptedProbe` that returns `Rejected`, assert the ack carries
  `status: "rejected"`.
- `dns_gate_honours_plugin_deadline_when_lds_slow` — script the
  probe to return `TimedOut` after a real-time delay greater than the
  request deadline; assert the ack returns `status: "ok"` for the nft
  side already applied (matching the §"Error and timeout behavior"
  posture for partial success).
- `dns_gate_codec_round_trips_request_and_ack` — pin the JSON wire
  shape against a frozen fixture so any future schema drift is loud.

CoreDNS plugin Go tests (in `networking/coredns-plugin/gate_test.go`):

- `TestGateClientReleasesResponseOnTimeout` — using
  `httptest.NewUnstartedServer`-style fake UDS that never answers,
  assert the plugin releases the answer after `deadline_ms` and emits
  a `dns_gate_timed_out` event.
- `TestGateClientHonoursAckOk` — fake UDS that answers in <50 ms;
  assert `WriteMsg` happens after the ack.
- `TestGateClientFailsClosedOnRejected` — fake UDS that returns
  `status: "rejected"`; assert the plugin returns SERVFAIL.

#### Integration (`make test-integration`)

- `integration_dns_gate_first_resolution_admits_before_response` —
  bring up a real gateway image, issue a DNS query for a host whose
  IPs are not in any cache, assert via `nft list set policy_allow_tcp`
  that the IP is present **before** the daemon side observes the
  response delivered to a fake VM client (introspect by reading
  `coredns.jsonl` for the `query_allowed` event, which today is
  emitted before `WriteMsg` returns — gate inserts itself between
  the resolution and `query_allowed`, so the strict ordering becomes
  an assertion).
- `integration_dns_gate_steady_state_short_circuits` — issue the
  same query twice; assert the second ack carries `status: "noop"`
  and no listener rewrite occurred (LDS counters unchanged).
- `integration_dns_gate_fails_open_when_daemon_socket_missing` —
  delete the socket file mid-test, issue a query, assert the plugin
  emits `dns_gate_timed_out` and the response is delivered.

#### E2E (`make test-e2e`)

The two existing tests that were the cargo / github-repo workaround
target are the regression tests for this milestone:

- `tests/e2e/test_m10_s5_presets.py::test_cargo_preset_allows_cargo_-`
  `fetch` — was the original case the `CARGO_FASTLY_CIDR_POOL`
  workaround patched. After this spec ships, the test passes with the
  workaround removed (see "Workaround removal" below).
- `tests/e2e/test_m10_s5_presets.py::test_github_repo_preset_scopes_-`
  `to_one_repo` — was the original case the
  `GITHUB_INTERACTIVE_CIDR_POOL` workaround patched. Same story.

Both pass on **3 consecutive runs** to ensure the gate is closing the
race deterministically rather than masking flakiness. This was the
verification convention the M10-S8 group orchestrator used for the
same tests when the workarounds first landed.

Two additions:

- `tests/e2e/test_m10_s10_dns_gate.py::test_first_resolution_is_-`
  `gated` — minimal preset, single host, drives a direct
  `getent hosts <host>` from the VM and asserts the gateway's
  `coredns.jsonl` contains a `dns_gate_ack { status: "ok" }` event
  with the same correlation ID as the matching `dns_gate_request`,
  and that the ack precedes the `query_allowed` event.
- `tests/e2e/test_m10_s10_dns_gate.py::test_gate_timeout_falls_-`
  `back_to_loop` — start the session, drop the socket file, drive a
  query, assert the timed-out event fires, the response is delivered,
  and within 4 s (one loop cycle + ack budget) the IP is admitted
  via the legacy path.

Exit criterion (per the user's M10-S10 spec): `make test`,
`make test-integration`, and `make test-e2e` all pass clean.

### Workaround removal

Removed in this milestone, in the same release as the gate ships:

- `sandboxd/sandbox-cli/src/presets/builtin.rs` — delete:
  - `CARGO_FASTLY_CIDR_POOL` (lines 269-277).
  - `expand_cargo`'s call site for the pool (lines 213-230) — leave
    the `consume_rules(&["crates.io", "index.crates.io",
    "static.crates.io"])` call.
  - `GITHUB_INTERACTIVE_CIDR_POOL` (lines 503-510).
  - `expand_github_repo`'s call site for the pool (lines 599-606,
    around `for cidr in GITHUB_INTERACTIVE_CIDR_POOL`).
- `sandboxd/sandbox-cli/src/presets/builtin.rs` tests:
  - `expand_cargo_emits_cidr_pool_rules_at_http_level` (line 1087).
  - `cargo_fastly_cidr_pool_covers_published_ranges` (line 1145).
  - `expand_github_repo_emits_cidr_pool_rules_at_http_level` (line
    1478).
  - `github_interactive_cidr_pool_covers_published_ranges` (line
    1540).
  - `expand_github_repo_multi_repo_emits_cidr_pool_once` (line
    1562).
  - `expand_github_repo_single_repo_emits_six_host_rules_with_-`
    `substituted_paths` (line 1270) needs its expected count
    re-baselined from `6 + GITHUB_INTERACTIVE_CIDR_POOL.len()` to
    just `6`.
  - `expand_cargo_matches_spec` (line 869) similarly drops the
    domain-rule filter helper if it becomes redundant.

Verification step (called out as a hard requirement so the workaround
removal commit is a real test of the gate, not a vanity edit):

- `test_cargo_preset_allows_cargo_fetch` and
  `test_github_repo_preset_scopes_to_one_repo` pass on 3 consecutive
  runs **without** the deleted constants in the source tree. The
  passing run is the regression gate.

Also clean up the preset comments that reference the workarounds —
docstrings on `expand_cargo` (lines 197-232) and
`expand_github_repo` (lines 535-606) currently spend dozens of lines
explaining why CIDR rules are emitted. After removal those comments
are misleading; replace with a one-line note pointing at this spec
for the historical context.

The two referenced milestone todos (#39, #40, both closed by the
workaround commits) stay closed — the workarounds delivered a working
fix at the time. This spec retires the workarounds, not the todos.

## Out of scope

- **UDP DNS race for non-A queries.** AAAA queries are denied at the
  request layer; SVCB / HTTPS queries are forwarded upstream with only
  the ECH SvcParam stripped from the response. Neither path enters the
  gate (gate is A-only, since only A responses carry IPs to admit), so
  there is no race for these qtypes.
- **IPv6.** All sandbox networking is IPv4-only by design; an IPv6
  follow-up extends the gate uniformly but is a separate milestone.
- **Multi-resolver scenarios.** The threat model assumes the VM
  resolves only via the gateway's CoreDNS. Workloads that bypass
  CoreDNS by hard-coding an upstream resolver in their config are
  out-of-scope; their DNS path does not touch the gate.
- **CoreDNS plugin direct nft writer (Path C).** Rejected as a
  non-goal; see "Goals and non-goals".
- **Per-query authorization beyond resolution.** The gate confirms
  that the resolved IP is admitted in the policy's nft / Envoy state.
  Per-query rate limiting, per-tenant scopes, and other controls
  layered on top remain a future addition.
- **`dns_gate_timed_out` driving a degraded-mode policy.** Today the
  timed-out path falls back to the loop's 2 s reconciler. A future
  enhancement could mark the affected host as "racy" and pre-allow a
  conservative supernet for it — but that is exactly the workaround
  pattern this spec is removing, and it should not return through the
  back door.
- **Persistent gate request log.** Events are written to JSONL via
  the existing per-session events bind mount with the
  `events.persist` toggle and the daemon-side ring buffer. No new
  retention surface here.
- **gRPC / HTTP framing on the IPC.** UDS + JSONL is sufficient at
  the request rates we expect. A future protocol revision can swap
  the framing without breaking the request/ack contract.
- **Plugin-to-daemon shared library / cgo.** The gate is plain UDS so
  the CoreDNS plugin remains pure Go and the daemon remains pure
  Rust. No FFI surface.

## Known gaps / deferred decisions

- **Default value for `deadline_ms`.** Spec proposes 1500 ms based on
  the latency-budget table, but the value is a knob worth confirming
  empirically against the real LDS-ack tail behaviour observed under
  E2E load. The first delivery commit picks 1500 ms; a follow-up may
  tune.
- **Whether the gate request should carry the `correlation_id` of
  the originating policy-apply.** Today the gate is decoupled from
  policy applies — the daemon services any in-policy domain
  regardless of which apply added it. Threading the apply-side
  correlation ID would let operators pivot from a `policy_applied`
  event straight to all gate events that flowed under it. Deferred
  unless a real triage workflow asks for it.
- **Pooled / multiplexed UDS connections.** The first cut uses
  per-request connections. If profiling under E2E shows the connect
  cost dominating (it should not — UDS local-loopback connect is
  microseconds), a per-plugin connection pool with multiplexed
  request IDs is a drop-in optimization that does not change the
  wire shape.
- **Event-ingestion ordering.** The plugin emits `dns_gate_request`
  → daemon emits `dns_gate_serviced` → plugin emits `dns_gate_ack`,
  but the JSONL ingestor tails three independent files and may
  re-order events with millisecond-close timestamps. Consumers that
  need strict pairing should use `correlation_id`, not arrival
  order — same convention as the existing
  `query_allowed`/`query_denied` ↔ `connection_allowed`/
  `connection_denied` chain in M10-S2.
- **The gate request is not signed.** A compromised gateway-internal
  process that can write to the UDS could lie about resolved IPs.
  Threat model: the gateway container is already a trust boundary
  (root inside, isolated network namespace); a compromised process
  inside it has many easier wins than racing the gate with synthetic
  resolutions. If the threat model tightens — e.g. the plugin is
  ever moved out of the gateway container — a per-session HMAC
  derived from the session ID is a small, additive change.
- **Cache invalidation on policy change.** When sandboxd applies a
  new policy that *removes* a previously-allowed domain, the daemon
  side regenerates state from scratch and the loop's `Removed` sweep
  evicts the cache entry. The gate's plugin-side cache learns about
  the removal only on the next gate request that hits the no-longer-
  allowed domain, where the daemon returns either a `noop` (if the
  IP set unchanged) or `rejected` (if the IPs were unique to the
  removed rule). Either path is correct — the VM cannot reach a
  removed rule's IPs because the listener no longer has a chain for
  them — but it does mean the plugin's cache may briefly show a
  stale "recently acked" entry. This is a cache-hygiene quirk, not
  a correctness gap. A more aggressive invalidation could push a
  `cache_invalidate { domain }` message from daemon to plugin on
  policy removal; deferred until a measurable need.

## Amendments to the M10 design

The M10 design's propagation contract (Part 3, "Lifecycle events" /
`policy_propagated`) is unchanged in shape — the gate adds a new event
class but does not redefine the existing ones. One textual tweak to
the M10 design would clarify the relationship; deferred to the
delivery doc rather than landing here:

- The `policy_propagated` event description in the M10 design
  (`2026-04-21-port-explicit-policies-presets-observability-design.md`,
  lines 720-721) reads "Policy has propagated to all three enforcement
  layers (nftables, Envoy, mitmproxy) AND the DNS-driven loop has
  reconciled every `Destination::Domain` rule …". With this spec the
  reconciliation happens via *either* the gate (per-resolution) or
  the loop (steady-state); both feed `mark_propagated` through the
  same registry. A non-normative note explaining that the gate is
  one of two write paths into the cache is worth adding when this
  spec ships, but is a doc edit, not a behaviour change.
