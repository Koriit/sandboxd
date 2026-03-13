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

This subsystem reduces risk. It does not eliminate it.

## Core design principles

1. **Deny by default**
   Every network flow is denied unless explicitly permitted.

2. **Single mediated egress path**
   All network traffic from the sandbox namespace must pass through one controlled interception and policy pipeline.

3. **Policy is abstract**
   The sandbox policy must describe **intent** and **assurance level**, not the internal mechanics of Dante, Envoy, mitmproxy, routing, or nftables.

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
tun2proxy (transparent interception / traffic capture)
    ↓
Dante (coarse transport mediation)
    ↓
Envoy (protocol-aware routing and bypass classification)
    ↓
mitmproxy (HTTP(S) inspection and host validation)
    ↓
external destination
```

### Layer responsibilities

#### Network namespace

Provides isolation from the host network stack and ensures the sandbox has a single controlled outbound path.

#### Kernel firewall

Provides hard enforcement:

* deny by default
* no direct egress
* explicit protocol and destination allow rules
* loopback/local exemptions where required
* IPv4 and IPv6 parity

#### tun2proxy

Used primarily as a **mechanism**, not a policy engine.

Its role is to:

* intercept all traffic entering the sandbox network path
* ensure traffic can be proxied, mediated, and inspected
* make arbitrary applications usable without requiring explicit proxy configuration

It is not the source of policy truth.

#### Dante

Provides coarse transport mediation:

* TCP/UDP class handling
* coarse destination/IP/port/protocol gating
* no final hostname authority

Dante is not the final security decision point for web identity.

#### Envoy

Provides protocol-aware routing and bypass classification:

* listener filter chains that classify traffic by protocol, not by peeking for a TLS ClientHello
* explicit separation of TLS-verified from transport-only based on declared policy
* SNI extraction and validation for connections that are natively TLS
* custom network filters for explicitly supported STARTTLS-style protocols (supported protocols will be documented separately; unsupported STARTTLS protocols fall to transport-only)
* builtin protocol support where available (e.g., PostgreSQL proxy filter)
* route to inspection path, TLS-verified path, or transport-only path
* reject clearly invalid or unsupported traffic classes

Why Envoy over HAProxy: not every TLS-capable protocol begins with a TLS ClientHello. Protocols like PostgreSQL negotiate TLS via a protocol-specific startup exchange (SSLRequest → server confirmation → ClientHello). HAProxy's routing model assumes it can peek at the first bytes to detect TLS, which fails for STARTTLS-style protocols. Envoy's architecture supports this natively in two ways: (1) builtin protocol filters for well-known protocols like PostgreSQL, and (2) custom network filters for other STARTTLS-style protocols, allowing the proxy to participate in the protocol handshake and upgrade to TLS at the correct point in the exchange. Only explicitly supported STARTTLS protocols will have filters — unsupported STARTTLS protocols cannot use TLS-verified and must fall to transport-only or be denied.

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

* Dante rule syntax
* Envoy listener/filter/cluster configuration
* mitmproxy ignore lists
* nftables chains
* routing tables
* tun2proxy flags

Those are backend implementation artifacts.

## Policy outcomes

Every attempted outbound flow must resolve to exactly one outcome:

1. **Deny** (level 0)
2. **Allow with HTTP inspection** (level 1)
3. **Allow at TLS-verified level** (level 2)
4. **Allow at transport-only level** (level 3)
5. **Allow at UDP level** (level 4)

There is no implicit “best effort allow.”

## Assurance levels

### Level 0 — Denied

The flow is not permitted.

### Level 1 — HTTP inspected

Strongest supported assurance.

Conditions:

* HTTP or HTTPS only
* TLS interception succeeds when HTTPS is used
* request-level host identity is visible
* `Host` or `:authority` validated per request
* policy can enforce method/path/headers/body if needed

This is the only true “happy path.”

### Level 2 — TLS-verified

Reduced assurance. The connection uses TLS and connection-level identity is verified, but HTTP inspection is not performed.

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

### Level 3 — Transport-only

Further reduced assurance. The connection is plain TCP — no TLS is expected or required.

Conditions:

* traffic is allowed as a generic TCP capability
* no TLS is assumed — the wire protocol is opaque
* identity is limited to IP/port
* application semantics are entirely opaque

Key distinction from TLS-verified: no encryption is expected or verified. This is a raw capability grant to reach a specific TCP endpoint. The system cannot verify anything about what flows over the connection.

### Level 4 — UDP

Weakest assurance.

Conditions:

* service identity is often weak
* protocol semantics may be opaque
* only narrowly approved use cases are allowed

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

A bypass is any policy entry that allows traffic at level 2 or below — that is, without full HTTP inspection and request-level verification.

Bypasses are valid and necessary. They are not failures of the system. But they must be explicit, logged, and reviewable.

### Bypass principles

1. No implicit bypasses
2. Every bypass has a declared reason
3. Every bypass has a declared assurance level (2, 3, or 4)
4. Every bypass is visible in logs and audits
5. Bypasses should be as narrow as possible
6. Bypasses should not be mistaken for fully verified traffic

### Bypass as policy metadata

A bypass is not a separate classification system. It is a policy entry at a specific assurance level with a documented reason. The assurance levels (0–4) are the only classification needed.

Example reasons for level 2 (TLS-verified):

* certificate pinning prevents HTTP interception
* custom trust store prevents transparent inspection
* non-HTTP TLS protocol (database, mail, custom)
* upstream proxy semantics require special handling

Example reasons for level 3 (transport-only):

* protocol requires raw TCP semantics
* STARTTLS protocol without a supported network filter
* legacy protocol without TLS support

Example reasons for level 4 (UDP):

* protocol requires UDP (e.g., DNS to a specific resolver)

### Policy semantics for bypasses

A bypass policy entry should document:

* what assurance level applies
* why HTTP inspection is not possible
* what narrower checks still apply at the granted level
* what security implications are accepted

Examples of policy intent:

* allow HTTPS to service X at level 2 (TLS-verified) — reason: certificate pinning
* allow PostgreSQL to service Y at level 2 (TLS-verified) — reason: non-HTTP TLS protocol
* allow legacy service Z at level 3 (transport-only) — reason: no TLS support
* allow UDP to resolver R at level 4 — reason: DNS requires UDP
* allow explicit upstream HTTP proxy P at level 2 (TLS-verified) — reason: upstream proxy workflow

## Namespace model

### Requirement

All sandboxed traffic must originate from a dedicated network namespace.

### Goals

* no shared host routes
* no direct host egress
* no policy dependence on host-global networking state
* no host trust-store coupling
* easy traffic attribution per sandbox

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

The kernel firewall is the hard enforcement layer.

### Must enforce

* deny by default
* explicit allow only
* no direct internet egress outside the policy path
* no direct DNS except controlled resolver path
* both IPv4 and IPv6
* no fail-open on userland proxy failure
* no accidental side interfaces or alternate routes

### Must support

* loopback exemptions
* self-traffic exemptions for the proxy chain
* explicit UDP policy
* explicit bypass handling
* explicit host and port restrictions as derived from policy

### Important rule

The kernel firewall is authoritative for **containment**, not for final service identity.

## DNS model

### Principle

There must be exactly one approved DNS resolution path inside the sandbox.

### Requirements

* deny direct external DNS by default
* deny alternate resolver paths unless explicitly allowed
* all DNS policy must be explicit
* DNS answers do not by themselves authorize traffic

### Important limitation

DNS allowlisting is not final service verification.

A DNS answer:

* may be shared across many hostnames
* may be one of many CDN edges
* may later be used with a different hostname or protocol

Therefore DNS is only an input to policy, never final proof.

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

### Implication

Supporting upstream HTTP proxies adds another policy concern:

* validate the final intended destination as expressed by the proxy protocol where possible
* do not treat upstream-proxy access as equivalent to raw TCP freedom

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

* invalid and denied unless explicit upstream-proxy policy applies

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
* DNS policy path
* Dante
* Envoy
* mitmproxy
* policy distribution

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

## Recommended policy doctrine

1. Default deny everything
2. Permit only traffic explicitly allowed by policy
3. Treat inspected HTTP(S) as the standard allowed mode
4. Treat every non-inspected mode as an explicit bypass
5. Prefer narrow bypasses over broad capability grants
6. Never confuse destination reachability with semantic safety
7. Log all bypasses prominently
8. Treat relay-capable allowed services as high-risk trust decisions
9. Keep host-level enforcement request-aware for HTTP
10. Fail closed

## Implementation guidance derived from the design

### What the backend stack should do

#### tun2proxy

* capture and proxy traffic transparently
* act as interception mechanism
* not own policy semantics

#### Dante

* mediate transport classes
* enforce coarse protocol/IP/port restrictions
* not act as final hostname authority

#### Envoy

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
* all traffic is denied by default
* tun2proxy transparently intercepts traffic so it can be proxied and inspected
* the only normal allowed mode is inspected HTTP(S)
* every non-HTTP or non-inspected flow is an explicit bypass
* bypasses are classified by assurance level
* policy is abstract and implementation-independent
* policy backends are hidden behind a single sandbox policy model
* the system fails closed
* logs make every exception visible
* the design is honest about the difference between constrained egress and true safety

The result is not “safe internet access for arbitrary code.”

The result is:

> explicit, mediated, auditable outbound capability with strong controls for HTTP(S) and explicit trust-based exceptions for everything else.

If you want, the next step is turning this into an RFC-style structure with sections like **Requirements**, **Architecture**, **Policy Compilation**, **Security Considerations**, and **Operational Considerations**.
