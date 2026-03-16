# Network Control Design for the Sandbox

## Status

Draft for implementation.

## Purpose

This document defines the **network-control subsystem** of the sandbox.

Its purpose is to make outbound network behavior:

* denied by default
* explicitly authorized
* observable
* auditable
* reducible to a small number of assurance levels

This subsystem is the **first part** of the sandbox. It does **not** claim to make arbitrary code “safe.” Its role is narrower and more defensible:

> ensure that all outbound network activity is mediated through a controlled pipeline, with explicit policy and explicit exceptions.

## Non-goals

This subsystem does **not** guarantee:

* that allowed external services are benign
* that allowed services will not relay or transform traffic
* that arbitrary non-HTTP protocols can be strongly verified
* that TLS passthrough has the same assurance as HTTP inspection
* that compatibility can be achieved for every application without bypasses
* that arbitrary software can safely use the internet merely because direct egress is blocked
* that the mediation pipeline will have low latency or high throughput — this is a sandbox for running untrusted code, not a production service runtime; performance overhead from mediation is accepted by design

This subsystem reduces risk. It does not eliminate it.

## Core design principles

1. **Deny by default**
   Every network flow is denied unless explicitly permitted.

2. **Single mediated egress path**
   All network traffic from the sandbox namespace must pass through one controlled interception and policy pipeline.

3. **Policy is abstract**
   The sandbox policy must describe **intent** and **assurance level**, not the internal mechanics of Envoy, mitmproxy, iptables, or nftables.

4. **HTTP is the only real happy path**
   The only fully supported and strongly verified outbound mode is:

   * HTTP or HTTPS
   * with visible host identity
   * with HTTP request inspection
   * with host or `:authority` validation per request

5. **Everything else is a bypass**
   Any flow that is not inspectable HTTP(S) is treated as an **explicit bypass** at a reduced assurance level, with weaker guarantees and stronger review requirements.

6. **Bypasses are first-class policy objects**
   A bypass is not an implementation accident. It is an explicit decision with known security consequences.

7. **Multiple assurance levels**
   Not all allowed traffic has the same security meaning. The system must model this clearly.

8. **Transparent to applications where possible**
   Applications should, where possible, behave as though they are making ordinary outbound connections. The sandbox mediates beneath them.

9. **No implementation leakage into policy**
   Users of the sandbox policy should not need to know which layer enforces a rule. They should define what is allowed, what must be inspected, and what exceptions exist.

## High-level architecture

The network-control subsystem is implemented as a layered pipeline inside a dedicated network namespace:

```text
sandboxed process
    ↓
network namespace
    ↓
kernel firewall (deny by default)
    ↓
iptables REDIRECT
    ├─ DNS → local resolver (policy-aware, logging)
    ├─ TCP → Envoy (original_dst, protocol-aware routing)
    │       ├─ HTTP(S) → mitmproxy → destination
    │       └─ TLS-verified / transport-only → destination
    └─ UDP → nftables (IP/port allow/deny)
```

### Layer responsibilities

#### Network namespace

Provides isolation from the host network stack and ensures the sandbox has a single controlled outbound path.

#### Kernel firewall (nftables + iptables)

Provides hard enforcement and transparent interception:

* deny by default — all protocols denied unless explicitly permitted
* only TCP and UDP are supported IP protocols
* ICMP is explicitly denied by default
* tunneling protocols (GRE, IPIP, WireGuard, etc.) are explicitly denied
* no direct egress outside the policy path
* explicit protocol and destination allow rules
* loopback/local exemptions where required
* IPv4 and IPv6 parity

**iptables REDIRECT** performs transparent interception at the kernel level:

* DNS traffic (TCP/UDP port 53) is redirected to the local resolver
* TCP traffic is redirected to Envoy's listener, which uses the `original_dst` listener filter to recover the real destination from the redirected socket
* UDP traffic is handled purely by nftables rules (IP/port allow/deny) — no userland proxy is involved

This eliminates the need for userland transparent interception proxies. The kernel handles the redirect, and Envoy recovers the original destination natively.

#### Local DNS resolver

A local DNS resolver runs inside the namespace and serves as the single enforced DNS path:

* **policy-aware resolution**: only domains permitted by policy resolve successfully; non-allowed domains receive NXDOMAIN
* **query logging**: all DNS queries are logged, providing domain→IP correlation for audit trails
* **enforced path**: nftables rules redirect all DNS traffic to the local resolver — no alternate resolver paths are possible

The resolver is the bridge between domain-based policy and IP-based enforcement. When policy permits a domain, the resolver both answers the query and makes the resolved IP available to the sandbox daemon for nftables rule updates.

#### Envoy

Receives redirected TCP connections and provides protocol-aware routing and bypass classification:

* uses the `original_dst` listener filter to recover the real destination from iptables-redirected connections
* listener filter chains that classify traffic by protocol, not by peeking for a TLS ClientHello
* explicit separation of TLS-verified from transport-only based on declared policy
* SNI extraction and validation for connections that are natively TLS
* custom network filters for explicitly supported STARTTLS-style protocols (PostgreSQL is supported at launch via Envoy's builtin filter; other STARTTLS protocols will be added when needed; unsupported STARTTLS protocols fall to transport-only)
* builtin protocol support where available (e.g., PostgreSQL proxy filter)
* route to inspection path, TLS-verified path, or transport-only path
* reject clearly invalid or unsupported traffic classes

Why Envoy over HAProxy: not every TLS-capable protocol begins with a TLS ClientHello. Protocols like PostgreSQL negotiate TLS via a protocol-specific startup exchange (SSLRequest → server confirmation → ClientHello). HAProxy's routing model assumes it can peek at the first bytes to detect TLS, which fails for STARTTLS-style protocols. Envoy's architecture supports this natively in two ways: (1) builtin protocol filters for well-known protocols like PostgreSQL, and (2) custom network filters for other STARTTLS-style protocols, allowing the proxy to participate in the protocol handshake and upgrade to TLS at the correct point in the exchange. Only explicitly supported STARTTLS protocols will have filters — unsupported STARTTLS protocols cannot use TLS-verified and must fall to transport-only or be denied.

**Classification mechanism:** Envoy does not inspect first bytes to guess the protocol class. The sandbox daemon compiles each destination's declared assurance level into Envoy's filter chain configuration. Filter chains match on destination IP and port and apply the behavior declared in policy:

* level 4 destinations: route to mitmproxy for HTTP inspection
* level 3 destinations: expect TLS, extract and validate SNI, forward directly to destination
* level 2 destinations: forward as opaque TCP with no TLS assumption

If wire behavior contradicts the declared level (e.g., a level 3 destination sends no TLS ClientHello), the connection is denied. Policy drives classification, not protocol sniffing.

#### mitmproxy

Provides the only strong verification path for HTTP(S):

* TLS interception where permitted
* HTTP/1 `Host` validation
* HTTP/2 `:authority` validation
* request-level policy enforcement
* visibility and analytics
* upstream-proxy support where explicitly allowed

## Threat model

Assume sandboxed code may be:

* untrusted
* buggy
* malicious
* evasive
* proxy-aware
* capable of spawning helper processes
* capable of using raw sockets where kernel policy allows
* capable of using application-layer relays if such services are allowed

Assume the sandbox must defend primarily against:

* unsanctioned direct egress
* hidden DNS resolution paths
* protocol tunneling over allowed ports
* misuse of shared-IP or CDN-hosted services
* use of upstream proxies or relay APIs to broaden reach
* accidental over-permissiveness caused by policy confusion
* illusion of strong verification where only weak signals exist

## Security boundary

The system strongly controls:

* which first-hop destinations may be contacted
* which transport classes may be used
* whether HTTP(S) must be inspected
* whether a bypass is required
* whether traffic stayed inside the policy pipeline

The system does **not** strongly control:

* what an allowed destination does on the app’s behalf
* whether an allowed API is effectively acting as a proxy or relay
* arbitrary non-HTTP semantics over allowed channels
* ultimate safety of the workload itself

This means the trust boundary is:

```text
sandboxed application
    ↓
approved first-hop destination
```

After that first hop, trust depends on the service itself.

## Policy model

### Policy abstraction

The policy model must describe:

* what destinations or services are allowed
* which traffic classes require inspection
* which traffic classes are allowed only via explicit bypass
* what assurance level applies
* what logging and auditing requirements apply

The policy model must **not** expose internal components such as:

* Envoy listener/filter/cluster configuration
* mitmproxy ignore lists
* nftables/iptables rules
* DNS resolver configuration
* routing tables

Those are backend implementation artifacts.

## Policy outcomes

Every attempted outbound flow must resolve to exactly one outcome:

1. **Deny** (level 0)
2. **Allow at UDP level** (level 1)
3. **Allow at transport-only level** (level 2)
4. **Allow at TLS-verified level** (level 3)
5. **Allow with HTTP inspection** (level 4)

There is no implicit “best effort allow.”

## Policy evaluation model

### Pipeline short-circuit

Policy is evaluated sequentially through the pipeline. Each layer either forwards traffic to the next layer or routes it directly to the destination. Once traffic exits the pipeline at a given layer, downstream layers never see it and their rules are not evaluated.

This means there is no policy conflict resolution. The deny-by-default baseline combined with the fixed pipeline order makes ambiguous overlaps impossible. If a domain is declared as a TLS-verified bypass, its traffic exits at Envoy — any mitmproxy rules that might reference the same domain are never reached. They are irrelevant, not overridden.

### Assurance level determines exit point

The declared assurance level in policy determines which pipeline layer is the terminal decision point for a given flow:

| Assurance level | Exit point | Downstream layers |
|---|---|---|
| Level 0 — Denied | Any layer (kernel firewall is backstop) | N/A |
| Level 1 — UDP | nftables | Envoy and mitmproxy are not involved |
| Level 2 — Transport-only | Envoy | mitmproxy is not involved |
| Level 3 — TLS-verified | Envoy | mitmproxy is not involved |
| Level 4 — HTTP inspected | mitmproxy | Full pipeline traversal |

## Assurance levels

### Level 0 — Denied

The flow is not permitted.

### Level 1 — UDP

Weakest assurance.

Conditions:

* service identity is often weak
* protocol semantics may be opaque
* only narrowly approved use cases are allowed

### Level 2 — Transport-only

Low assurance. The connection is plain TCP — no TLS is expected or required.

Conditions:

* traffic is allowed as a generic TCP capability
* no TLS is assumed — the wire protocol is opaque
* identity is limited to IP/port
* application semantics are entirely opaque

Key distinction from TLS-verified: no encryption is expected or verified. This is a raw capability grant to reach a specific TCP endpoint. The system cannot verify anything about what flows over the connection.

### Level 3 — TLS-verified

Moderate assurance. The connection uses TLS and connection-level identity is verified, but HTTP inspection is not performed.

Conditions:

* the policy declares that this destination is allowed at TLS-verified level
* the connection is natively TLS (ClientHello is the first message on the wire) **or** Envoy handles TLS negotiation via a protocol-specific network filter for explicitly supported STARTTLS protocols (e.g., PostgreSQL via builtin filter)
* SNI is extracted and validated when present in natively-TLS connections
* for STARTTLS-style protocols, the network filter participates in the protocol handshake and upgrades to TLS at the correct point — SNI may still not be available, but the proxy has protocol-level awareness of the connection
* request-level HTTP semantics are not available

Key distinction from transport-only: the system knows TLS is in use and the policy explicitly requires it. The connection carries encrypted traffic to a declared TLS-capable service.

Typical reasons:

* non-HTTP TLS protocol (databases, mail, custom protocols)
* certificate pinning or custom trust store prevents HTTP interception
* application cannot trust the interception CA

### Level 4 — HTTP inspected

Strongest supported assurance.

Conditions:

* HTTP or HTTPS only
* TLS interception succeeds when HTTPS is used
* request-level host identity is visible
* `Host` or `:authority` validated per request
* policy can enforce method/path/headers/body if needed

This is the only true “happy path.”

## Fundamental design rule

### HTTP inspection is mandatory by default

If a flow is HTTP or HTTPS and the sandbox wants meaningful host-level policy, then inspection is mandatory.

This is true even if the user defines no method/path rules of their own.

Reason:

* SNI is only a connection property
* actual HTTP target identity is a request property
* HTTP/2 connection reuse/coalescing allows multiple hostnames over one TLS connection
* HTTP/1.1 keep-alive also allows request-level host variation
* therefore host allowlisting cannot rely only on SNI or IP

So:

* HTTP(S) without inspection is **not** the default allow path
* it is an **explicit bypass**

## Why HTTP is the only happy path

HTTP and HTTPS are the only traffic classes for which the sandbox can, in general, do all of the following together:

* preserve mostly transparent application behavior
* observe destination identity at request level
* validate host per request
* apply fine-grained policy
* produce meaningful analytics
* distinguish “service A” from “service B” on the same IP

Every other traffic class loses one or more of those properties.

## Bypass framework

### Definition

A bypass is any policy entry that allows traffic below level 4 (HTTP inspected) — that is, at level 1 (UDP), level 2 (transport-only), or level 3 (TLS-verified) — without full HTTP inspection and request-level verification.

Bypasses are valid and necessary. They are not failures of the system. But they must be explicit, logged, and reviewable.

### Bypass principles

1. No implicit bypasses
2. Every bypass has a declared reason
3. Every bypass has a declared assurance level (1, 2, or 3)
4. Every bypass is visible in logs and audits
5. Bypasses should be as narrow as possible
6. Bypasses should not be mistaken for fully verified traffic

### Bypass as policy metadata

A bypass is not a separate classification system. It is a policy entry at a specific assurance level with a documented reason. The assurance levels (0–4) are the only classification needed.

Example reasons for level 1 (UDP):

* protocol requires UDP (e.g., DNS to a specific resolver)

Example reasons for level 2 (transport-only):

* protocol requires raw TCP semantics
* STARTTLS protocol without a supported network filter
* legacy protocol without TLS support

Example reasons for level 3 (TLS-verified):

* certificate pinning prevents HTTP interception
* custom trust store prevents transparent inspection
* non-HTTP TLS protocol (database, mail, custom)
* upstream proxy semantics require special handling

### Policy semantics for bypasses

A bypass policy entry should document:

* what assurance level applies
* why HTTP inspection is not possible
* what narrower checks still apply at the granted level
* what security implications are accepted

Examples of policy intent:

* allow HTTPS to service X at level 3 (TLS-verified) — reason: certificate pinning
* allow PostgreSQL to service Y at level 3 (TLS-verified) — reason: non-HTTP TLS protocol
* allow legacy service Z at level 2 (transport-only) — reason: no TLS support
* allow UDP to resolver R at level 1 — reason: DNS requires UDP
* allow explicit upstream HTTP proxy P at level 3 (TLS-verified) — reason: upstream proxy workflow

## Namespace model

### Requirement

All sandboxed traffic must originate from a dedicated network namespace.

### Goals

* no shared host routes
* no direct host egress
* no policy dependence on host-global networking state
* no host trust-store coupling
* easy traffic attribution per sandbox

### Implementation

Network namespaces are created and managed via Docker engine. Docker provides good security defaults for container isolation — no shared host network by default, seccomp profiles, and dropped capabilities. The sandbox leverages Docker's namespace and network management rather than raw `ip netns` or `unshare`, which also provides a well-understood operational model for lifecycle management (create, start, stop, cleanup).

### Interfaces inside the namespace

The namespace requires:

* one main routed path for external connectivity
* loopback (`lo`)

Loopback is required and normal.

### Loopback principles

Loopback is:

* allowed
* necessary
* local fabric for internal sandbox components

Loopback is **not**:

* a privilege boundary
* inherently trusted
* exempt from design scrutiny

### Loopback concerns

1. Local services bound to loopback are reachable by sandboxed processes in the namespace
2. Admin/debug interfaces must not be exposed insecurely on loopback
3. Local resolvers or local proxy listeners become part of the trusted computing base
4. Transparent interception must avoid accidentally redirecting local control traffic and creating loops
5. IPv4 loopback and IPv6 loopback must both be handled

### Loopback rule

Use loopback for local data-plane plumbing where necessary, but prefer:

* Unix sockets for control/admin paths
* strict separation of data plane and control plane
* authenticated or permission-gated local services

## Kernel firewall requirements

The kernel firewall (nftables + iptables) is the hard enforcement layer and the transparent interception mechanism.

### Must enforce

* deny by default — all traffic denied unless explicitly permitted
* only TCP and UDP are supported IP protocols
* ICMP is explicitly denied by default
* tunneling protocols (GRE, IPIP, WireGuard, etc.) are explicitly denied
* explicit allow only for permitted traffic
* no direct internet egress outside the policy path
* no direct DNS except the local resolver path
* both IPv4 and IPv6
* no fail-open on Envoy or mitmproxy failure
* no accidental side interfaces or alternate routes

### Must provide

* iptables REDIRECT rules to route TCP traffic to Envoy
* iptables REDIRECT rules to route DNS traffic to the local resolver
* nftables rules for UDP allow/deny (IP/port based)
* loopback exemptions
* self-traffic exemptions for Envoy and mitmproxy
* explicit host and port restrictions as derived from policy

### Important rule

The kernel firewall is authoritative for **containment** and **transparent interception**, not for final service identity.

## DNS model

### Principle

There must be exactly one approved DNS resolution path inside the sandbox.

### Requirements

* deny direct external DNS by default
* deny alternate resolver paths unless explicitly allowed
* all DNS policy must be explicit
* DNS answers do not by themselves authorize traffic

### DNS resolution for policy enforcement

Policy is expressed in terms of domain names, but enforcement components (nftables) operate on IP addresses. The local DNS resolver bridges this gap:

* the local resolver is the only DNS path available inside the namespace — nftables redirects all DNS traffic to it
* non-allowed domains receive NXDOMAIN — the resolver enforces policy at the DNS layer
* for allowed domains, resolution results are reported to the sandbox daemon, which maintains TTL-aware IP-to-domain mappings and pushes updated nftables rules
* re-resolution occurs when DNS TTL expires, with a configurable maximum interval (e.g., 60 seconds) as an upper bound regardless of TTL — domains with very long TTLs must not leave stale IPs in place indefinitely
* on resolution failure: immediately remove the previously resolved IPs for the affected domain (fail-closed), log the failure, and reflect the failure in the sandbox health status — stale IPs from domains that no longer resolve are a potential attack vector (e.g., IP takeover) and must not persist
* all DNS queries are logged for audit trail purposes, providing domain→IP correlation that supports connection attribution

### Important limitation

DNS allowlisting is not final service verification.

A DNS answer:

* may be shared across many hostnames
* may be one of many CDN edges
* may later be used with a different hostname or protocol

Therefore DNS is only an input to policy, never final proof.

### Stale IP window

There is an inherent window between when a domain's IP address changes and when the control plane re-resolves and pushes the update. During this window, traffic to the old IP remains permitted while traffic to the new IP is not yet allowed.

This is a known limitation of any DNS-based policy system. TTL-aware resolution minimizes the window but cannot eliminate it entirely. The design accepts this trade-off. Policy authors should be aware that IP-level enforcement is eventually consistent with DNS, not instantaneous.

## SNI model

### Principle

SNI is useful, but only as a connection-level signal.

It is suitable for:

* coarse TLS routing
* coarse host expectation
* reducing ambiguity on shared IPs
* rejecting clearly invalid TLS cases

It is not sufficient for final HTTP authorization.

### Rule

* if HTTP(S) is being used and strict host policy matters, SNI alone is not enough
* no-SNI TLS requires explicit bypass
* SNI validation is required where applicable, but it is not the final authority for HTTP traffic

## HTTP model

### Principle

HTTP identity is request-scoped, not connection-scoped.

Therefore:

* HTTP/1 `Host` must be validated per request
* HTTP/2 `:authority` must be validated per request

### Consequence

HTTP inspection is mandatory for normal allowed web traffic.

### HTTP rules

The sandbox must be able to enforce, when configured:

* allowed hosts
* allowed methods
* allowed paths
* allowed schemes
* host/path consistency
* explicit block or allow rules

Even if only host-level policy is required, request-level inspection remains mandatory.

## Certificate management

### Requirement

TLS interception by mitmproxy requires a CA certificate that the sandboxed application trusts. The sandbox must manage this certificate lifecycle.

### CA generation and storage

* a unique CA keypair is generated per sandbox instance at creation time
* the CA is short-lived — its validity period matches the sandbox lifetime
* the private key is stored only in the sandbox's control plane and is never mounted into the sandboxed container
* per-sandbox generation ensures that compromise of one sandbox's CA does not affect others

### Trust store injection

The CA certificate (public part only) is injected into the sandboxed container so that applications trust the interception CA:

* mounted into the container's system trust store location
* standard environment variables set for applications that use their own trust store resolution (`SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE`, `NODE_EXTRA_CA_CERTS`, etc.)

This provides transparent interception for applications that rely on the system trust store or standard environment variables.

### Certificate pinning and custom trust stores

Applications that use certificate pinning or hardcoded trust stores will reject the interception CA. These applications require a TLS-verified bypass (level 3).

Some pinned applications expose configuration options to provide a custom CA certificate. Whether and how to use such options is the user's responsibility — the sandbox provides the bypass mechanism, not application-specific CA configuration.

### Rotation

For ephemeral sandboxes, rotation is not required — the CA lives and dies with the sandbox instance. For long-lived sandboxes, a CA rotation procedure is a future enhancement.

## Upstream proxy support

### Requirement

The sandbox may need to support applications that intentionally use an explicit upstream HTTP proxy.

### Design position

This is allowed only as an explicit policy path.

### Why this is special

For a normal transparent client:

* proxy-style `CONNECT` is unexpected and invalid

For a client intentionally using an upstream HTTP proxy:

* `CONNECT` and absolute-form HTTP requests are expected

Therefore:

* explicit upstream-proxy use must be modeled as a separate policy case
* it must not be silently merged into the ordinary transparent-origin path

### CONNECT handling

CONNECT requests are only valid when targeting a destination declared as an upstream proxy in policy. CONNECT to any other destination is denied — this prevents applications from using CONNECT as a tunneling mechanism through non-proxy endpoints.

Once traffic reaches the allowed upstream proxy, the sandbox's trust boundary applies: the proxy is an approved first-hop destination, and what it does on the application's behalf is beyond the sandbox's control. This is consistent with the trust model for all other allowed destinations.

The sandbox does not attempt to validate or restrict the final destination behind the upstream proxy. Such validation would be:

* inconsistent with the trust boundary — no other allowed service is policed for what it does on behalf of the application
* unreliable — the proxy could relay anywhere regardless of what the CONNECT target declares
* already addressed by the relay-capable services classification

## Transport and protocol classes

### HTTP/HTTPS

Default mode:

* inspected
* strongly verified
* request-level identity enforcement

### Non-HTTP TLS

Allowed only by explicit bypass:

* may use SNI if visible
* service identity remains weaker than inspected HTTP

### Generic TCP

Allowed only by explicit bypass:

* opaque semantics
* strong dependence on trust in the endpoint

### UDP

Allowed only by explicit bypass:

* narrow and intentional
* strongest review burden
* generally weakest service identity guarantees

## Escape-pattern assumptions and responses

The design explicitly accounts for the following classes of behavior.

### Direct IP connections

Response:

* denied unless explicitly allowed
* never equivalent to hostname authorization

### Alternate DNS paths

Response:

* denied unless explicitly allowed

### IPv6-only or IPv6-bypass paths

Response:

* deny by default or fully mirror policy in IPv6

### QUIC / HTTP/3

Response:

* deny by default unless explicitly bypassed

### Raw non-HTTP traffic on expected ports

Response:

* deny unless explicit bypass applies

### Missing SNI

Response:

* explicit bypass only

### Pinning or custom trust stores

Response:

* explicit application configuration or explicit bypass

### CONNECT on transparent-origin path

Response:

* denied unless the target is declared as an upstream proxy in policy

### Local helper proxies inside namespace

Response:

* acceptable so long as namespace-wide egress policy still applies

### Shared-IP/CDN ambiguity

Response:

* resolved only by SNI plus HTTP host validation
* IP allowlists are never final web identity checks

### ECH or other opaque TLS evolution

Response:

* explicit bypass only

## Relay-capable services and trust amplification

A destination may be allowed at the network level yet still act as an application-layer proxy or relay.

Examples include services that can:

* fetch arbitrary URLs
* open arbitrary outbound connections on behalf of the client
* execute code remotely
* forward requests
* act as browser automation backends
* act as generic callback or webhook brokers

This is not a failure of the sandbox network layer. It is a trust issue in the allowed destination.

### Policy implication

Allowed destinations should conceptually be classified into:

* terminal services
* API services
* relay-capable services
* explicit proxies

The network-control subsystem cannot fully solve this problem, but it must not hide it.

## Fail-closed requirement

The system must fail closed.

If any policy-enforcing component fails:

* direct egress must not become available
* default result must be deny
* bypasses must not silently widen

This includes failures of:

* namespace plumbing
* routing setup
* iptables/nftables rules
* local DNS resolver
* Envoy (if Envoy crashes, redirected TCP connections fail — the kernel firewall ensures no direct egress is possible regardless)
* mitmproxy
* sandbox daemon / policy distribution

## Health monitoring

### Component liveness probes

Each enforcement component in the pipeline must expose or support a liveness probe:

* **iptables/nftables** — rule verification (expected chains and redirect rules are present and active)
* **local DNS resolver** — test resolution of a known-allowed domain
* **Envoy** — admin health endpoint
* **mitmproxy** — health endpoint
* **sandbox daemon** — internal self-check (DNS resolution cycle completing, configuration distribution succeeding)

The sandbox daemon polls these probes periodically. Per-component probes serve a diagnostic purpose: when something is wrong, they identify which component is the source of the failure.

### Failure response

When a component probe fails:

* log an alert with the affected component identified
* update the sandbox status to reflect degraded networking
* expose the health state via a sandbox daemon status command
* attempt to send a system notification that sandbox networking is degraded

The system must **not** automatically terminate the sandbox on health-check failure. The sandbox may be running long-lived processes that do not require network access. The sandbox owner decides what action to take based on the reported status.

### End-to-end pipeline verification

Per-component probes do not guarantee that traffic is actually being proxied through the full pipeline. A true end-to-end probe — originating from within the sandbox network namespace and traversing the complete chain (iptables REDIRECT → Envoy → mitmproxy → destination) — would provide stronger assurance.

This is recognized as a future enhancement. The design for an end-to-end health-check mechanism is documented separately. Per-component probes are sufficient for initial implementation and provide actionable diagnostics without introducing additional attack surface.

## Component lifecycle and startup ordering

### Requirement

The pipeline components must start in a specific order to avoid transient exposure or broken behavior during sandbox initialization.

### Startup order

Components start outside-in — the outermost enforcement layer first, the traffic gate last:

1. **Kernel firewall (nftables)** — deny-by-default rules are applied first. Nothing can leave the namespace. This is always safe.
2. **mitmproxy** — starts and becomes ready to receive forwarded HTTP(S) traffic from Envoy.
3. **Envoy** — starts and becomes ready to receive redirected TCP traffic. Can route to mitmproxy, which is already available.
4. **Local DNS resolver** — starts and becomes ready to answer queries.
5. **iptables REDIRECT rules** — applied last. Traffic is only redirected into the pipeline once all components are ready to handle it.

### Why this order is safe

The kernel firewall's deny-by-default rules are the first thing applied and the last thing removed. The iptables REDIRECT rules are the gate — no traffic enters the userland pipeline until every component is confirmed ready. During the startup window, the namespace has network access denied entirely, which is the correct default.

### Readiness gates

Each component must signal readiness before the next one in the sequence starts:

* **mitmproxy** — health endpoint returns successfully
* **Envoy** — admin health endpoint returns successfully
* **Local DNS resolver** — test query for a known domain resolves successfully

The sandbox daemon orchestrates this sequence and will not proceed to the next step until the current component passes its readiness check.

### Component failure during operation

If a component crashes after the pipeline is fully operational:

* iptables REDIRECT rules remain active — redirected traffic hits a dead port and connections fail
* this is fail-closed by design — no traffic leaks, connections simply break
* the sandbox daemon detects the failure via health probes and reports degraded status
* the sandbox daemon may attempt to restart the failed component without restarting the entire sandbox

Traffic is never silently rerouted or allowed to bypass the pipeline due to a component failure.

## Error propagation

### Principle

When the pipeline denies a connection, the sandboxed application should receive a fast, informative error rather than a silent timeout. Different pipeline layers produce different error signals, but the design preference is immediate failure with useful feedback for the application and full context in logs for the operator.

### Error behavior by layer

**Kernel firewall (nftables):**

* use REJECT (TCP RST for TCP, ICMP unreachable for UDP) rather than DROP where possible
* REJECT gives the application immediate feedback; DROP causes timeouts
* exception: DROP may be appropriate for security-sensitive cases where revealing policy structure is undesirable

**Local DNS resolver:**

* return NXDOMAIN for non-allowed domains
* the application sees "unknown host" — a clean, fast, and familiar error that is typically surfaced clearly by applications

**Envoy:**

* denied connections receive a TCP RST (connection reset)
* this is Envoy's default behavior for connections that do not match any allowed filter chain
* the application sees an immediate connection failure

**mitmproxy:**

* denied HTTP requests receive an HTTP error response (e.g., 403)
* the application receives a real HTTP response it can interpret programmatically
* the response should not leak internal policy details

### Logging

Every denial at every layer is logged with full context:

* source address and port
* intended destination and port
* protocol
* policy rule that triggered the denial
* assurance level (if applicable)
* layer that produced the denial

The application receives a terse error. The audit log receives the full story.

## Logging and audit requirements

Every connection attempt should be attributable to one of the policy outcomes.

At minimum, logs should support:

* deny events
* inspected HTTP(S) events
* bypass events
* upstream-proxy events
* missing-SNI events
* unsupported-protocol events
* policy-resolution reasoning
* policy object responsible for the decision

Bypasses must be especially visible.

A bypass should always be auditable as:

* who allowed it
* why it exists
* what class it belongs to
* what assurance was lost

## Policy authoring requirements

The policy language should let users express intent such as:

* allow web access to service X
* require full HTTP inspection for service Y
* allow service Z only at TLS-verified level
* allow UDP only to resolver R
* deny everything else

The policy language should not require users to know:

* which backend enforces the rule
* which ACL syntax is used
* whether the rule becomes an SNI check, DNS check, host check, or firewall rule

Those are compilation details of the policy engine.

### Policy schema

The concrete policy schema (e.g., JSON Schema) is intentionally not defined in this design document. It will be produced as part of the implementation, once the interaction between policy intent and backend capabilities is better understood.

However, the implementation **must** produce a formal, machine-readable schema document. This is a hard requirement, not an optional deliverable.

### Policy versioning

Every policy document must declare the schema version it conforms to, following the pattern established by Kubernetes manifests:

* the version field must be present and must use [Semantic Versioning](https://semver.org/)
* the system must reject policy documents whose declared version is incompatible with the currently supported schema
* backward-compatible minor/patch versions may be accepted; incompatible major versions must be rejected
* the schema version is a property of the policy document, not of the sandbox runtime

This ensures that policy documents remain interpretable over time and that silent behavioral changes from schema drift are prevented.

## Control plane / sandbox daemon

A dedicated sandbox daemon serves as the single source of truth for sandbox network policy. It is the mechanism that makes the policy abstraction guarantee real. The sandbox daemon is a single process that manages multiple concurrent sandbox instances, each with its own networking stack.

### Responsibilities

* accept abstract policy documents as input — the same documents authored by users
* compile abstract policy into component-specific configurations: nftables/iptables rules, local DNS resolver policy, Envoy listener/filter/cluster config, mitmproxy rules
* manage the local DNS resolver's policy (allowed domains, NXDOMAIN for denied domains)
* receive resolution results from the local resolver and push updated IP-based rules to nftables
* distribute generated configuration to all running enforcement components
* ensure no enforcement component is hand-configured — all configuration is generated from the abstract policy
* manage lifecycle of per-sandbox networking stacks (namespace, firewall rules, resolver, Envoy, mitmproxy)

### Design constraints

* the sandbox daemon is the only component that interprets policy intent
* enforcement components receive only their own generated configuration and do not interpret abstract policy
* configuration updates (including DNS re-resolution) must be applied without requiring sandbox restart where possible
* the sandbox daemon must validate policy documents against the declared schema version before compilation

### Time synchronization

Time synchronization is a host responsibility. Sandbox containers inherit the host system clock — this is standard Docker behavior, not a network concern. The sandbox networking subsystem does not need to provide NTP access or any time-synchronization path.

### Policy compilation error handling

Policy compilation is an all-or-nothing operation. Either the entire policy compiles successfully to all backend configurations, or it is rejected in full. No partial application is permitted.

Rationale: a half-applied policy is worse than no policy. It creates a false sense of security where some rules are enforced and others are silently missing. Fail-fast is the only safe default.

Compilation validates in two phases:

**Schema validation:**

* the policy document structure conforms to the declared schema version
* all required fields are present and correctly typed
* assurance levels are valid
* referenced protocol classes are recognized

**Semantic validation:**

* every rule can be compiled to every relevant backend — if a rule cannot be expressed in a required backend, compilation fails
* no internal contradictions exist (e.g., the same destination declared at conflicting assurance levels)
* assurance levels are consistent with declared protocol classes (e.g., UDP traffic cannot be declared at level 4)
* bypass entries have required metadata (reason, assurance level)

On failure, the sandbox daemon reports:

* which rule failed validation
* which backend could not express the rule (if applicable)
* why the compilation failed

DNS resolution failures are not compilation errors. Policy is expressed in domain names. Domain-to-IP resolution is a runtime control-plane concern, not a compile-time concern.

## Implementation guidance derived from the design

### What the backend stack should do

#### Kernel firewall (nftables + iptables)

* enforce deny-by-default for all protocols
* deny ICMP and tunneling protocols (GRE, IPIP, WireGuard, etc.)
* permit only TCP and UDP
* redirect DNS traffic to the local resolver via iptables REDIRECT
* redirect TCP traffic to Envoy via iptables REDIRECT
* enforce UDP allow/deny rules (IP/port) via nftables
* ensure no direct egress is possible outside the policy path

#### Local DNS resolver

* resolve only policy-permitted domains; return NXDOMAIN for all others
* log all queries for audit trail (domain→IP correlation)
* report resolution results to the sandbox daemon for nftables rule updates
* serve as the single DNS path — no alternate resolvers reachable

#### Envoy

* use the `original_dst` listener filter to recover real destinations from iptables-redirected connections
* classify connections into inspection, TLS-verified, or transport-only based on declared policy — not by peeking for ClientHello
* extract and validate SNI for natively-TLS connections
* use builtin protocol filters where available (e.g., PostgreSQL proxy filter) for protocol-aware TLS handling
* use custom network filters for other explicitly supported STARTTLS-style protocols to handle the protocol handshake and TLS upgrade
* deny or fall back to transport-only for STARTTLS protocols without a supported filter
* route plain transport-only traffic without assuming any TLS
* reject clearly invalid or unsupported traffic classes

#### mitmproxy

* perform mandatory inspection for ordinary HTTP(S)
* validate host identity per request
* support explicit bypasses and upstream-proxy workflows where allowed

### Important architectural rule

The backend stack exists to implement the sandbox policy.

The policy does not exist to mirror the backend stack.

## Residual risks

Even with correct implementation, the following residual risks remain:

* allowed services may be malicious or overly capable
* allowed APIs may act as relays
* generic TCP/UDP bypasses remain weak assurance paths
* TLS-verified level loses request-level certainty
* application compatibility may pressure policy toward broader exceptions
* user misunderstanding may overestimate the guarantees of “allowed” traffic

These are not implementation bugs. They are the natural limits of the problem space.

## Final design summary

This subsystem defines a sandbox network architecture in which:

* all traffic is captured in a dedicated namespace
* all traffic is denied by default — only TCP and UDP are supported; ICMP and tunneling protocols are explicitly denied
* iptables REDIRECT transparently intercepts traffic at the kernel level, with Envoy recovering original destinations via `original_dst`
* a local DNS resolver enforces policy at the DNS layer and provides query logging for audit trails
* UDP policy is enforced purely by nftables (IP/port allow/deny) with no userland proxy
* the only normal allowed mode is inspected HTTP(S)
* every non-HTTP or non-inspected flow is an explicit bypass
* bypasses are classified by assurance level
* policy is abstract and implementation-independent
* policy backends are hidden behind a single sandbox policy model compiled by the sandbox daemon
* the system fails closed
* logs make every exception visible
* the design is honest about the difference between constrained egress and true safety

The result is not “safe internet access for arbitrary code.”

The result is:

> explicit, mediated, auditable outbound capability with strong controls for HTTP(S) and explicit trust-based exceptions for everything else.
