# Networking Subsystem Design

## Status

Draft for implementation.

This is the **networking subsystem design** for the sandbox architecture defined in [sandbox-design.md](sandbox-design.md). It covers everything about networking end-to-end — from the agent process inside the VM all the way to the destination.

The [sandbox design](sandbox-design.md) covers the isolation boundary, VM lifecycle, gateway container deployment, session lifecycle, vsock control channel, VM hardening, workspace provisioning, and platform considerations. This document covers the network-control pipeline, policy model, traffic flow, and all networking configuration required to make the system work.

## Table of contents

- [Purpose](#purpose)
- [Non-goals](#non-goals)
- [Core design principles](#core-design-principles)
- [Architecture](#architecture)
  - [End-to-end architecture](#end-to-end-architecture)
  - [VM-side networking configuration](#vm-side-networking-configuration)
  - [Per-session network](#per-session-network)
  - [Gateway container pipeline](#gateway-container-pipeline)
- [Policy model](#policy-model)
  - [Policy outcomes](#policy-outcomes)
  - [Policy evaluation model](#policy-evaluation-model)
  - [Assurance levels](#assurance-levels)
  - [Layer responsibilities](#layer-responsibilities)
  - [Policy abstraction](#policy-abstraction)
  - [Fundamental design rule](#fundamental-design-rule)
  - [Why HTTP is the only happy path](#why-http-is-the-only-happy-path)
  - [Bypass framework](#bypass-framework)
  - [Policy authoring requirements](#policy-authoring-requirements)
- [Threat model and security](#threat-model-and-security)
  - [Threat model](#threat-model)
  - [Security boundary](#security-boundary)
  - [Escape-pattern assumptions and responses](#escape-pattern-assumptions-and-responses)
  - [Relay-capable services and trust amplification](#relay-capable-services-and-trust-amplification)
  - [Fail-closed requirement](#fail-closed-requirement)
- [Layer models](#layer-models)
  - [Kernel firewall requirements](#kernel-firewall-requirements)
  - [DNS model](#dns-model)
  - [SNI model](#sni-model)
  - [HTTP model](#http-model)
  - [Certificate management](#certificate-management)
  - [Upstream proxy support](#upstream-proxy-support)
  - [Transport and protocol classes](#transport-and-protocol-classes)
- [Operations](#operations)
  - [Health monitoring](#health-monitoring)
  - [Component lifecycle and startup ordering](#component-lifecycle-and-startup-ordering)
  - [Error propagation](#error-propagation)
  - [Logging and audit requirements](#logging-and-audit-requirements)
  - [Control plane / sandbox daemon](#control-plane--sandbox-daemon)
- [Closing](#closing)
  - [Residual risks](#residual-risks)
  - [Final design summary](#final-design-summary)

## Purpose

This document defines the **networking subsystem** of the sandbox architecture.

Its purpose is to make outbound network behavior:

* denied by default
* explicitly authorized
* observable
* auditable
* reducible to a small number of assurance levels

This subsystem covers the complete network path: from the agent process inside the VM, through the VM's kernel networking stack, across the per-session network, into the gateway container's proxy pipeline, and out to the destination. It defines what is configured where, what each component enforces, and how they compose into a coherent end-to-end policy enforcement system.

The isolation boundary itself — why VMs, how Lima manages them, how the gateway container is deployed, session lifecycle, vsock control channel — is defined in the [sandbox design](sandbox-design.md). This document assumes that architecture and defines everything networking within it.

## Non-goals

This subsystem does **not** guarantee:

* that allowed external services are benign
* that allowed services will not relay or transform traffic
* that arbitrary non-HTTP protocols can be strongly verified
* that TLS passthrough has the same assurance as HTTP inspection
* that compatibility can be achieved for every application without bypasses
* that arbitrary software can safely use the internet merely because direct egress is blocked
* that the mediation pipeline will have low latency or high throughput — this is a sandbox for running untrusted code, not a production service runtime; performance overhead from mediation is accepted by design
* that ingress connections to the sandbox are controllable — inbound connections are denied by default and controllable ingress policy is a future enhancement not covered by this design

This subsystem reduces risk. It does not eliminate it.

## Core design principles

1. **Deny by default**
   Every network flow is denied unless explicitly permitted.

2. **Single mediated egress path**
   All network traffic from the VM must pass through one controlled interception and policy pipeline — the gateway container. There is no alternate path.

3. **Policy is abstract**
   The sandbox policy must describe **intent** and **assurance level**, not the internal mechanics of Envoy, mitmproxy, or nftables.

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

7. **Four assurance levels**
   Not all allowed traffic has the same security meaning. The system models this with four levels (0–3), from denied to fully inspected.

8. **Transparent to applications where possible**
   Applications should, where possible, behave as though they are making ordinary outbound connections. The sandbox mediates beneath them.

9. **No implementation leakage into policy**
   Users of the sandbox policy should not need to know which layer enforces a rule. They should define what is allowed, what must be inspected, and what exceptions exist.

## Architecture

### End-to-end architecture

The networking subsystem spans two execution environments — the VM and the gateway container — connected by a per-session network (Docker bridge on Linux, dedicated vmnet on macOS).

```text
Agent process (in VM)
  → VM kernel networking → virtio-net
    → per-session network → gateway container eth0
      → nftables PREROUTING DNAT
        → Envoy / mitmproxy / DNS resolver
          → destination (or deny)
```

Traffic originates inside the VM, exits via the VM's single virtual NIC (virtio-net), crosses the per-session network, and enters the gateway container as forwarded traffic on the container's network interface. Inside the gateway, nftables PREROUTING DNAT rules intercept the forwarded traffic and redirect it into the proxy pipeline — Envoy, mitmproxy, and the DNS resolver — which enforce policy before forwarding permitted traffic to its destination.

The proxy pipeline inside the gateway container is a layered enforcement stack:

```text
forwarded traffic from VM (on gateway eth0)
    ↓
nftables (deny by default, PREROUTING DNAT)
    ├─ DNS → local resolver (policy-aware, logging)
    ├─ TCP → Envoy (original_dst, protocol-aware routing)
    │       ├─ HTTP(S) → mitmproxy → destination
    │       └─ TLS-verified / transport-only → destination
    └─ UDP → nftables (IP/port allow/deny)
```

#### Key properties

**Traffic is forwarded, not locally generated.** In the gateway container, traffic from the VM arrives on the container's network interface — it is forwarded traffic, not traffic generated by a local process. This is the fundamental difference from a shared-namespace model. nftables uses PREROUTING DNAT (for forwarded traffic) rather than OUTPUT REDIRECT (for locally-generated traffic).

**The VM has no bypass path.** The VM has exactly one physical exit — a virtio-net NIC connected to the per-session network. Even with root access, modifying the routing table, firewall rules, or creating additional virtual interfaces inside the VM does not create an alternate path out; all IP traffic exits through the single NIC and reaches the gateway's nftables. The only other communication path is vsock, which is a host-guest socket family (AF_VSOCK) that does not carry IP traffic and does not traverse the proxy pipeline. See [sandbox-design.md § Control channel (vsock)](sandbox-design.md#control-channel-vsock).

**Inner Docker traffic is transparent.** When the agent runs Docker containers inside the VM, those containers' outbound traffic follows the same path: inner container → inner Docker bridge → VM kernel NAT → VM virtio-net → gateway → pipeline → destination. The proxy pipeline sees the VM's IP as the source, not the inner container's IP. No special configuration is needed. See [VM-side networking configuration § Inner Docker networking](#inner-docker-networking).

### VM-side networking configuration

The VM must be configured to route all traffic through the gateway container and to trust the interception CA. This configuration is applied during VM provisioning (cloud-init) and is immutable from the agent's perspective. For the provisioning process and VM lifecycle, see [sandbox-design.md § VM specification](sandbox-design.md#vm-specification).

#### Network interface and routing

The VM has a single network interface (virtio-net) with a single default route:

* **One NIC, IPv4 only.** The VM exposes exactly one external network interface (plus the standard loopback) — a virtio-net device connected to the per-session network (Docker bridge on Linux, dedicated vmnet on macOS). The NIC is configured with an IPv4 address only; no IPv6 addresses are assigned on the network interface. No other network interfaces exist (no additional NICs, no virtio-fs, no USB network adapters).
* **Default route to gateway.** The default route points to the gateway container's IP on the /30 subnet. All traffic (except loopback and vsock) exits via this route.
* **Static or DHCP.** The VM's IP on the /30 subnet is assigned during provisioning — either statically in the Lima template or via DHCP from the per-session network.
* **No alternate routes.** No other routes exist. The routing table contains only the default route to the gateway, the connected /30 subnet route, and loopback.

#### DNS configuration

`/etc/resolv.conf` points to the gateway container's DNS resolver IP on the /30 subnet. This makes the gateway's policy-aware DNS resolver the default resolver for all applications in the VM.

nftables rules inside the gateway provide a safety net: all DNS traffic (TCP/UDP port 53) arriving from the VM is redirected to the local resolver regardless of the destination address. Applications that ignore `resolv.conf` or hardcode resolver addresses (e.g., `8.8.8.8`) are still forced through the policy-aware resolver.

#### Agent privilege model

The agent process runs as root inside the VM. This is a deliberate design choice — the security model does not depend on the agent's privilege level inside the VM:

* **The VM boundary provides hardware isolation.** The agent cannot escape the VM regardless of privilege level. Root inside the VM does not grant any access to the host, the gateway container, or other sessions.
* **The gateway pipeline enforces network policy via topology.** The single virtio-net NIC is the only exit from the VM, and all traffic hits the gateway's nftables. Root inside the VM can modify the guest's routing table or firewall rules, but cannot create an alternate physical path out — all packets still traverse the gateway.
* **Root eliminates usability barriers.** Package management (`apt`, `pip`, `npm`), system configuration, global tool installation, and Docker operations work without `sudo` wrappers or group membership workarounds.

Operators can optionally configure a non-root agent user as a defense-in-depth measure against hypothetical VM escape exploits. This is a hardening option, not a security requirement — see [sandbox-design.md § Guest OS hardening](sandbox-design.md#guest-os-hardening).

#### Single-homed networking

Docker sets `net.ipv4.ip_forward=1` globally inside the VM for its internal bridge networking. This has no security implication because the VM has a single external network interface (virtio-net) with one default route to the gateway — there is no second interface to forward traffic to, so the VM cannot act as a router. Creating additional virtual interfaces inside the VM (even with root access) does not change this: all traffic still exits through the single virtio-net NIC to the gateway. IPv6 is not enabled inside the VM.

#### CA certificate trust

TLS interception by mitmproxy (inside the gateway container) requires that applications in the VM trust the interception CA. The CA certificate (public part only) is installed during provisioning:

* **System trust store.** Installed in `/usr/local/share/ca-certificates/` and registered via `update-ca-certificates`. This covers applications that use the system trust store (most Linux applications, curl, wget, etc.).
* **Standard environment variables.** The following environment variables are set system-wide:
  * `SSL_CERT_FILE` — used by OpenSSL-based applications
  * `REQUESTS_CA_BUNDLE` — used by Python requests library
  * `NODE_EXTRA_CA_CERTS` — used by Node.js
  * `CURL_CA_BUNDLE` — used by curl and libcurl
* **Docker daemon trust store.** The CA certificate is installed in `/etc/docker/certs.d/` so that the inner Docker daemon trusts the interception CA when pulling images from registries over HTTPS.

The CA private key is never present inside the VM. It exists only in the gateway container, accessible to mitmproxy. Per-session CA generation and lifecycle are described in [Certificate management](#certificate-management).

#### Inner Docker networking

The agent runs a Docker daemon inside the VM. This is standard Docker — the inner daemon creates its own bridge networks, manages its own iptables/nftables rules, and performs its own NAT. This is entirely within the VM's network namespace and does not interact with the gateway's configuration.

When an inner container needs to reach an external service, the traffic path is:

```text
Inner container → inner Docker bridge → VM kernel NAT → VM virtio-net
  → per-session network → gateway container → proxy pipeline → destination
```

The inner Docker daemon's NAT translates container source IPs to the VM's IP on the /30 subnet. The gateway's proxy pipeline sees the VM's IP as the source — it does not see or care about inner container IPs. This is transparent and requires no special configuration.

When inner containers communicate with each other (e.g., services in a `docker compose` stack), traffic stays on the inner Docker bridge and never reaches the gateway. This is standard Docker behavior.

Port mapping (`-p` flag) works normally inside the VM. Inner containers can bind ports and other inner containers (or the agent process) can reach them via `localhost` or the inner bridge. These connections stay inside the VM.

### Per-session network

Each session has a dedicated IPv4-only network that provides the link layer between the VM and its gateway container. On Linux, this is a Docker bridge network; on macOS, this is a dedicated socket_vmnet instance. The network is provisioned by the sandbox daemon (at session creation on Linux, from a pre-provisioned pool on macOS) and released during session destruction. For the full session lifecycle, see [sandbox-design.md § Session lifecycle](sandbox-design.md#session-lifecycle).

```text
VM (virtio-net) ←→ per-session network ←→ gateway container (eth0)
```

The connectivity mechanism differs by platform, but both achieve the same result: the VM has a single NIC with a default route pointing at the gateway container's IP, and traffic arrives at the gateway with original destination intact so that PREROUTING DNAT works correctly.

#### VM-to-gateway connectivity

##### Linux

On Linux, the sandbox daemon creates a per-session Docker bridge network. The gateway container attaches to this bridge normally (via Docker). The sandbox VM's QEMU/KVM process uses a TAP device on the same bridge as its network backend — Lima configures this via its `networks` YAML stanza. This gives the VM direct L2 connectivity to the gateway container on the bridge subnet, and the VM's default route points to the gateway's IP on the bridge.

```
Linux host
├── sandboxd
├── Docker daemon (hosts all gateway containers)
│   ├── Gateway container session-1 (bridge-1)
│   ├── Gateway container session-2 (bridge-2)
│   └── ...
├── Sandbox VM session-1 (TAP on bridge-1) → routes to gateway-1
├── Sandbox VM session-2 (TAP on bridge-2) → routes to gateway-2
└── ...
```

Each session is fully isolated at L2 — the TAP device, bridge, and gateway container form a private network segment. No cross-session traffic is possible.

##### macOS

On macOS, Docker does not run natively — it runs inside a Linux VM (Docker Desktop's VM, or a Colima/Lima VM). This means a sandbox VM cannot attach a TAP device to a Docker bridge on the macOS host because that bridge exists inside another VM's network namespace.

The solution uses a per-session vmnet pool model that mirrors the per-session Docker bridge isolation on Linux:

1. **socket_vmnet pool** — sandboxd pre-provisions a pool of socket_vmnet instances at daemon startup on macOS. Each instance has its own /30 subnet (2 usable IPs: one for the gateway, one for the sandbox VM). The pool size is configurable (`max_concurrent_sessions_macos`, default 8). Each socket_vmnet instance is an isolated L2 segment — the same isolation property as Linux's per-session Docker bridges.

2. **Colima (sandboxd-managed)** — sandboxd manages a single Colima instance (a Lima-based Docker runtime) that hosts all gateway containers across all sessions. This Colima instance is completely independent of whatever Docker setup the developer uses (Docker Desktop, their own Colima, etc.). The developer never interacts with it directly.

3. **Docker macvlan (private mode)** — inside the sandboxd-managed Colima VM, each gateway container uses Docker macvlan networking (`-o macvlan_mode=private`) on the vmnet-facing NIC for its session's vmnet. macvlan private mode is used as defense in depth, even though isolation is already provided by the separate vmnet instances.

**Session lifecycle on macOS:**

* **Session start:** Claim a vmnet slot from the pool. Attach a Colima NIC to that vmnet. Create a gateway container with macvlan (private mode) on that NIC. Boot the sandbox VM on the same vmnet. The two share a /30 subnet — only they can communicate.
* **Session stop:** Stop the VM, destroy the gateway container, detach and release the vmnet slot back to the pool.
* **Pool exhaustion:** If the pool is exhausted, reject the session start with a clear error ("max concurrent sessions reached, increase pool size and restart sandboxd"). No silent degradation.

Only running sessions consume pool slots — stopped or created-but-not-started sandboxes do not.

```
macOS host
├── sandboxd
├── socket_vmnet pool (N instances, each an isolated /30 subnet)
│
├── Colima VM (one, managed by sandboxd)
│   ├── NIC-1 on vmnet-1 → Gateway container session-1 (macvlan)
│   ├── NIC-2 on vmnet-2 → Gateway container session-2 (macvlan)
│   └── (NICs attached/detached as sessions start/stop)
│
├── Sandbox VM session-1 on vmnet-1 → routes to gateway-1
├── Sandbox VM session-2 on vmnet-2 → routes to gateway-2
└── ...
```

The sandbox VM's default route points to its gateway's IP on the /30 subnet. Traffic arrives at the gateway container with the original destination intact — PREROUTING DNAT works exactly as on Linux. From the gateway container's perspective, the traffic flow is indistinguishable from the Linux TAP-on-bridge model. Both platforms use the same gateway container image — only the network attachment differs (Docker bridge on Linux, macvlan on a per-session vmnet on macOS).

Each session is fully isolated at L2 — the vmnet instance, gateway container, and sandbox VM form a private /30 network segment. No cross-session traffic is possible, the same as Linux's per-session bridges.

The shared Colima VM introduces the only cross-session failure mode in the architecture. On Linux, gateway containers are independent — a single gateway crash affects only its session, and all other sessions continue unaffected. On macOS, the Colima VM hosts all gateway containers, so if it crashes, every active session loses networking simultaneously. This is an inherent consequence of the macOS platform constraint (Docker requires a Linux VM), not a design flaw. sandboxd must monitor the Colima VM's health, restart it on failure, and recreate gateway containers afterward; sessions will experience a networking interruption during recovery. All other failure modes remain session-scoped on both platforms.

#### Isolation properties

* **No shared L2 segments.** Each session gets its own network segment — a Docker bridge on Linux, a dedicated vmnet instance on macOS. Sessions do not share network segments.
* **No inter-session traffic.** Because network segments are per-session, VMs from different sessions cannot communicate at the network level. There is no L2 path between sessions.
* **No host network.** The gateway container is attached to the per-session network, not the host network (`--network` is the session bridge on Linux; macvlan on the session's vmnet on macOS). The gateway cannot reach other sessions' networks or the host's network stack directly.
* **Gateway egress.** The gateway container's own outbound connections — Envoy forwarding permitted requests, the DNS resolver querying upstream nameservers — follow the standard Docker/Colima NAT path. On Linux, Docker applies MASQUERADE on the host's external interface for traffic leaving the session bridge; the gateway's outbound packets are SNAT'd to the host IP. On macOS, the sandboxd-managed Colima VM provides NAT for all containers it hosts; outbound traffic from the gateway is masqueraded through Colima's external interface. No `--network=host` or special egress privileges are needed.

#### Subnet allocation

Each session gets its own /30 subnet (2 usable IPs: one for the gateway, one for the VM). Subnets are carved from a configurable base range — default `10.209.0.0/24` — chosen from an uncommon RFC 1918 slice to minimize conflicts with VPN and corporate networks. Operators can override the base range to avoid conflicts with their specific network environment.

This applies to both platforms: Docker bridge subnets on Linux and vmnet subnets on macOS. The gateway's IP on the /30 subnet serves as:

* the VM's default gateway (default route target)
* the DNS resolver address (in `/etc/resolv.conf`)
* the DNAT target for nftables redirect rules

#### MTU

The MTU must be consistent across the VM NIC, per-session network segment, and gateway interface. Docker bridge networks on Linux default to 1500, which is correct for most environments. On macOS, each per-session vmnet instance uses the same default. On cloud networks with encapsulation overhead (e.g., AWS VPCs with VxLAN), the host's outbound MTU may be lower — the gateway relies on standard path MTU discovery for outbound traffic. If outbound path MTU issues arise, the per-session network MTU can be configured at session creation time; this is an implementation detail, not a design concern.

### Gateway container pipeline

The gateway container runs the proxy pipeline outside the VM, on the host side of the VM's virtual NIC. It is a standard Docker container using the runc runtime. For deployment details, security posture, and lifecycle management, see [sandbox-design.md § Gateway container](sandbox-design.md#gateway-container).

#### What runs inside the gateway

* **nftables** — PREROUTING DNAT rules for forwarded traffic from the VM
* **Envoy** — original_dst listener for protocol-aware routing
* **mitmproxy** — HTTP inspection and policy enforcement
* **DNS resolver** — policy-aware resolution, query logging

These components form the layered enforcement pipeline described throughout this document. The gateway container has `CAP_NET_ADMIN` (required for nftables) but otherwise runs with Docker's default security profile — no `--privileged`, no host PID namespace, no host filesystem mounts beyond configuration volumes, read-only root filesystem with writable volumes for logs and runtime state.

IP forwarding must be enabled in the gateway container (`net.ipv4.ip_forward=1`, set via `--sysctl` at container creation) because it acts as the router for the VM's traffic. Without IP forwarding, forwarded packets from the VM would be dropped before reaching the nftables PREROUTING DNAT rules.

The entire networking subsystem is IPv4-only by design. IPv6 forwarding is explicitly disabled in the gateway (`net.ipv6.conf.all.forwarding=0`), and any IPv6 traffic that reaches the gateway is dropped by a blanket nftables `ip6` drop rule. This is a deliberate simplification — a single-stack network reduces attack surface and eliminates an entire class of bypass vectors (see [Escape-pattern assumptions and responses](#escape-pattern-assumptions-and-responses)). IPv6 support is deferred as a future improvement (see [Residual risks](#residual-risks)).

#### Traffic interception model

Traffic arrives at the gateway container from the VM as forwarded packets on the container's network interface. This is fundamentally different from intercepting locally-generated traffic in a shared namespace. The following table compares the previous design iteration (shared network namespace) with the current gateway container model for readers familiar with the earlier approach:

| Property | Shared namespace (old model) | Gateway container (current model) |
|---|---|---|
| Traffic source | Local process in same namespace | VM, via per-session network interface |
| nftables chain | OUTPUT REDIRECT | PREROUTING DNAT |
| Traffic type | Locally-generated | Forwarded |
| Namespace sharing | Proxy pipeline shares namespace with sandboxed process | Proxy pipeline has its own namespace; VM has its own kernel |

nftables PREROUTING DNAT intercepts forwarded traffic before routing decisions and redirects it to the pipeline components (Envoy listener, DNS resolver). Envoy uses the `original_dst` listener filter to recover the real destination from the DNAT-redirected connection — the same mechanism as before, just triggered by PREROUTING DNAT instead of OUTPUT REDIRECT.

On macOS, the gateway container uses a Docker macvlan network on a per-session vmnet instance instead of a Docker bridge (see [VM-to-gateway connectivity § macOS](#macos) for the full explanation). The pipeline behavior is identical — traffic arrives on the gateway's network interface from the VM with the original destination intact, and the same PREROUTING DNAT rules intercept it. The vmnet/macvlan vs. bridge distinction is a link-layer detail that does not affect the proxy pipeline, policy model, or any behavior described in this document.

#### Loopback inside the gateway

The gateway container has its own loopback interface. Loopback is used for internal communication between pipeline components (e.g., Envoy forwarding to mitmproxy). Loopback traffic inside the gateway is not subject to the PREROUTING DNAT rules — those rules match only traffic arriving on the VM-facing interface from the VM.

Loopback principles:

* allowed and necessary for internal pipeline plumbing
* not a privilege boundary
* admin/debug interfaces on pipeline components must not be exposed insecurely
* prefer Unix sockets for control/admin paths where possible
* strict separation of data plane (forwarded traffic from VM) and control plane (component-internal communication)

#### No self-traffic exemptions needed

In the old shared-namespace model (OUTPUT REDIRECT), Envoy and mitmproxy's outbound connections to real destinations were locally-generated traffic in the same namespace as the intercepted process — they would hit the same OUTPUT chain rules and loop back into the proxy. That model required explicit UID/GID-based exemptions so the proxies' own traffic could bypass interception.

In the current gateway container model, this problem does not exist. PREROUTING DNAT rules match only forwarded traffic arriving on the VM-facing interface from the VM. When Envoy or mitmproxy open outbound connections to real destinations, those connections are locally generated inside the gateway container — they traverse the OUTPUT chain, not PREROUTING. Since the DNAT rules are in PREROUTING, locally-generated traffic never hits them. The chain separation inherently prevents interception loops without any exemption rules.

## Policy model

### Policy outcomes

Every attempted outbound flow must resolve to exactly one outcome:

1. **Deny** (level 0)
2. **Allow at transport-only level** (level 1) — TCP or UDP
3. **Allow at TLS-verified level** (level 2)
4. **Allow with HTTP inspection** (level 3)

There is no implicit "best effort allow."

### Policy evaluation model

#### Pipeline short-circuit

Policy is evaluated sequentially through the pipeline. Each layer either forwards traffic to the next layer or routes it directly to the destination. Once traffic exits the pipeline at a given layer, downstream layers never see it and their rules are not evaluated.

This means there is no policy conflict resolution. The deny-by-default baseline combined with the fixed pipeline order makes ambiguous overlaps impossible. If a domain is declared as a TLS-verified bypass, its traffic exits at Envoy — any mitmproxy rules that might reference the same domain are never reached. They are irrelevant, not overridden.

#### Assurance level determines exit point

The declared assurance level in policy determines which pipeline layer is the terminal decision point for a given flow:

| Assurance level | Exit point | Downstream layers |
|---|---|---|
| Level 0 — Denied | Any layer (kernel firewall is backstop) | N/A |
| Level 1 — Transport-only (UDP) | nftables | Envoy and mitmproxy are not involved |
| Level 1 — Transport-only (TCP) | Envoy | mitmproxy is not involved |
| Level 2 — TLS-verified | Envoy | mitmproxy is not involved |
| Level 3 — HTTP inspected | mitmproxy | Full pipeline traversal |

### Assurance levels

The assurance level indicates how much the sandbox can verify about a connection. Lower levels mean less verification by the sandbox — and therefore require greater trust in the destination. At level 3, the sandbox verifies request-level identity and enforces fine-grained policy, so minimal trust in the destination is needed. At level 1, the sandbox can only gate by IP and port, so the operator must trust that the destination itself is safe. Level 0 would require infinite trust — which is impossible to justify — so it is denied.

#### Level 0 — Denied

The flow is not permitted.

#### Level 1 — Transport-only

Lowest assurance. The connection is opaque — no TLS is expected or required. The transport protocol (TCP or UDP) is a required property of the policy entry; nftables requires the protocol to generate rules.

Conditions:

* traffic is allowed as a generic transport capability (TCP or UDP)
* no TLS is assumed — the wire protocol is opaque
* identity is limited to IP/port
* application semantics are entirely invisible
* only narrowly approved use cases are allowed

For UDP: exits at nftables (IP/port allow/deny) — no userland proxy is involved. UDP is connectionless and inherently harder to attribute.

For TCP: exits at Envoy, which forwards it as opaque TCP. TCP has connection state but the sandbox cannot verify anything about what flows over the connection.

Both share the same assurance: opaque semantics, identity limited to IP/port, application semantics invisible. The transport protocol is a property of the connection, not a different assurance level.

Key distinction from TLS-verified: no encryption is expected or verified. This is a raw capability grant to reach a specific endpoint.

#### Level 2 — TLS-verified

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

#### Level 3 — HTTP inspected

Strongest supported assurance.

Conditions:

* HTTP or HTTPS only
* TLS interception succeeds when HTTPS is used
* request-level host identity is visible
* `Host` or `:authority` validated per request
* policy can enforce method/path/headers/body if needed

This is the only true "happy path."

### Layer responsibilities

##### Kernel firewall (nftables)

Provides hard enforcement and transparent interception of forwarded traffic from the VM:

* deny by default — all protocols denied unless explicitly permitted
* only TCP and UDP are supported IP protocols
* ICMP is explicitly denied by default
* tunneling protocols (GRE, IPIP, WireGuard, etc.) are explicitly denied
* no direct egress outside the policy path
* explicit protocol and destination allow rules
* gateway-internal loopback exemptions where required
* explicit host and port restrictions as derived from policy
* IPv4 rules implement full policy; IPv6 rules are a blanket drop (the networking subsystem is IPv4-only)

**nftables PREROUTING DNAT** performs transparent interception of forwarded traffic arriving from the VM:

* DNS traffic (TCP/UDP port 53) is redirected to the local resolver. This serves as a safety net — even applications in the VM that ignore resolv.conf or use hardcoded resolver addresses are forced through the local resolver. Well-behaved applications reach the resolver directly via resolv.conf configuration; nftables redirect catches everything else
* TCP traffic is redirected to Envoy's listener, which uses the `original_dst` listener filter to recover the real destination from the DNAT-redirected socket
* UDP traffic is handled purely by nftables rules (IP/port allow/deny) — no userland proxy is involved. The local DNS resolver is not an exception: it is an actual destination (resolv.conf points applications to it directly), not a proxy in the UDP path. nftables enforces that port 53 traffic can only reach the local resolver; all other port 53 traffic is denied

This eliminates the need for userland transparent interception proxies. The kernel handles the redirect, and Envoy recovers the original destination natively.

##### Local DNS resolver

A local DNS resolver runs inside the gateway container and serves as the single enforced DNS path:

* **policy-aware resolution**: only domains permitted by policy resolve successfully; non-allowed domains receive NXDOMAIN
* **query logging**: all DNS queries are logged, providing domain→IP correlation for audit trails
* **enforced path**: nftables PREROUTING DNAT rules redirect all DNS traffic from the VM to the local resolver — no alternate resolver paths are possible

The resolver is the bridge between domain-based policy and IP-based enforcement. When policy permits a domain, the resolver both answers the query and makes the resolved IP available to the sandbox daemon for propagation to all enforcement components that operate on IP addresses.

**ECH stripping:** The local DNS resolver strips HTTPS/SVCB records that carry ECHConfig from DNS responses by default. This prevents clients from learning the server's Encrypted Client Hello public key, forcing a fallback to standard TLS with plaintext SNI. This is necessary because ECH encrypts the entire inner ClientHello — including SNI — using the server's public key, which defeats both SNI-based routing at Envoy and TLS interception at mitmproxy. ECH stripping applies to level 2 (TLS-verified) and level 3 (HTTP inspected) destinations. Level 2 requires SNI extraction and validation, which ECH also defeats. Level 1 (transport-only) destinations are not affected — they do not depend on TLS or SNI. ECH stripping is enabled by default because without it, increasing ECH adoption would silently break HTTP inspection for destinations that previously worked, producing confusing TLS handshake errors with no clear cause.

##### Envoy

Receives DNAT-redirected TCP connections and provides protocol-aware routing and bypass classification:

* uses the `original_dst` listener filter to recover the real destination from nftables PREROUTING DNAT-redirected connections
* listener filter chains that classify traffic by protocol, not by peeking for a TLS ClientHello
* explicit separation of TLS-verified from transport-only based on declared policy
* SNI extraction and validation for connections that are natively TLS
* custom network filters for explicitly supported STARTTLS-style protocols (PostgreSQL is supported at launch via Envoy's builtin filter; other STARTTLS protocols will be added when needed; unsupported STARTTLS protocols fall to transport-only)
* builtin protocol support where available (e.g., PostgreSQL proxy filter)
* route to inspection path, TLS-verified path, or transport-only path
* reject clearly invalid or unsupported traffic classes

Why Envoy over HAProxy: not every TLS-capable protocol begins with a TLS ClientHello. Protocols like PostgreSQL negotiate TLS via a protocol-specific startup exchange (SSLRequest → server confirmation → ClientHello). HAProxy's routing model assumes it can peek at the first bytes to detect TLS, which fails for STARTTLS-style protocols. Envoy's architecture supports this natively in two ways: (1) builtin protocol filters for well-known protocols like PostgreSQL, and (2) custom network filters for other STARTTLS-style protocols, allowing the proxy to participate in the protocol handshake and upgrade to TLS at the correct point in the exchange. Only explicitly supported STARTTLS protocols will have filters — unsupported STARTTLS protocols cannot use TLS-verified and must fall to transport-only or be denied.

**Classification mechanism:** Envoy does not inspect first bytes to guess the protocol class. The sandbox daemon compiles each destination's declared assurance level into Envoy's filter chain configuration. Filter chains match on destination IP and port and apply the behavior declared in policy:

* level 3 destinations: route to mitmproxy for HTTP inspection
* level 2 destinations: expect TLS, extract and validate SNI, forward directly to destination
* level 1 (TCP) destinations: forward as opaque TCP with no TLS assumption

If wire behavior contradicts the declared level (e.g., a level 2 destination sends no TLS ClientHello), the connection is denied. Policy drives classification, not protocol sniffing.

##### mitmproxy

Provides the only strong verification path for HTTP(S):

* TLS interception where permitted
* HTTP/1 `Host` validation
* HTTP/2 `:authority` validation
* request-level policy enforcement
* visibility and analytics
* upstream-proxy support where explicitly allowed

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
* nftables rules
* DNS resolver configuration
* routing tables

Those are backend implementation artifacts.

### Fundamental design rule

#### HTTP inspection is mandatory by default

If a flow is HTTP or HTTPS and the sandbox wants meaningful host-level policy, then inspection is mandatory.

This is true even if the user defines no method/path rules of their own.

Reason:

* SNI is a connection property. HTTP `Host` / `:authority` is a request property.
* HTTP/2 multiplexes requests to multiple hosts over a single TLS connection — this is standard protocol behavior, not an attack. A connection legitimately established to an allowed domain (valid SNI) can carry requests targeting different hosts.
* This is the same class of problem as HTTP-level domain fronting (see [domain fronting analysis in the SNI model](#domain-fronting)), but arising from protocol design rather than malicious intent.
* Even HTTP/1.1 keep-alive allows host switching between requests on the same connection.
* Therefore, connection-level checks (SNI, IP) are structurally insufficient for host-level policy — only request-level inspection can enforce it.

So:

* HTTP(S) without inspection is **not** the default allow path
* it is an **explicit bypass**

### Why HTTP is the only happy path

HTTP and HTTPS are the only traffic classes for which the sandbox can, in general, do all of the following together:

* preserve mostly transparent application behavior
* observe destination identity at request level
* validate host per request
* apply fine-grained policy
* produce meaningful analytics
* distinguish "service A" from "service B" on the same IP

Every other traffic class loses one or more of those properties.

### Bypass framework

#### Definition

A bypass is any policy entry that allows traffic below level 3 (HTTP inspected) — that is, at level 1 (transport-only) or level 2 (TLS-verified) — without full HTTP inspection and request-level verification.

Bypasses are valid and necessary. They are not failures of the system. But they must be explicit, logged, and reviewable.

#### Bypass principles

1. No implicit bypasses
2. Every bypass has a declared reason
3. Every bypass has a declared assurance level (1 or 2)
4. Every bypass is visible in logs and audits
5. Bypasses should be as narrow as possible
6. Bypasses should not be mistaken for fully verified traffic

#### Bypass as policy metadata

A bypass is not a separate classification system. It is a policy entry at a specific assurance level with a documented reason. The assurance levels (0–3) are the only classification needed.

Example reasons for level 1 (transport-only):

* protocol requires UDP (e.g., NTP, SNMP, syslog)
* protocol requires raw TCP semantics
* STARTTLS protocol without a supported network filter
* legacy protocol without TLS support

Example reasons for level 2 (TLS-verified):

* certificate pinning prevents HTTP interception
* custom trust store prevents transparent inspection
* non-HTTP TLS protocol (database, mail, custom)
* upstream proxy semantics require special handling

#### Policy semantics for bypasses

A bypass policy entry should document:

* what assurance level applies
* why HTTP inspection is not possible
* what narrower checks still apply at the granted level
* what security implications are accepted

Examples of policy intent:

* allow HTTPS to service X at level 2 (TLS-verified) — reason: certificate pinning
* allow PostgreSQL to service Y at level 2 (TLS-verified) — reason: non-HTTP TLS protocol
* allow legacy service Z at level 1 (transport-only, TCP) — reason: no TLS support
* allow UDP to NTP server N at level 1 (transport-only, UDP) — reason: NTP requires UDP
* allow explicit upstream HTTP proxy P at level 2 (TLS-verified) — reason: upstream proxy workflow

Note: DNS resolution does not appear in bypass examples because the local DNS resolver is a built-in system service. All DNS traffic (TCP/UDP port 53) from the VM is intercepted by nftables PREROUTING DNAT and redirected to the local resolver automatically. This is a system-level mechanism that operators cannot override or configure via policy.

### Policy authoring requirements

The policy language should let users express intent such as:

* allow web access to service X
* require full HTTP inspection for service Y
* allow service Z only at TLS-verified level
* allow UDP only to NTP server N
* deny everything else
* allow only GET requests to `api.github.com/repos/{owner}/{repo}/pulls/{number}` — granting read access to a specific pull request without broader GitHub API access
* allow only GET and HEAD to a specific service — no mutations permitted
* deny POST to any path on a specific service
* allow access to a service but only on specific paths

The policy language should not require users to know:

* which backend enforces the rule
* which ACL syntax is used
* whether the rule becomes an SNI check, DNS check, host check, or firewall rule

Those are compilation details of the policy engine.

HTTP-level method and path controls are the key capability that distinguishes this sandbox from network-level firewalls. Any firewall can gate by IP and port. The ability to constrain not just *which* service is reachable but *what operations* are permitted on that service is what makes HTTP inspection meaningful. A sandbox policy that allows access to a version control API but only permits reading a specific pull request is fundamentally more constrained than one that allows all traffic to the API's IP address.

#### Policy schema

The concrete policy schema (e.g., JSON Schema) is intentionally not defined in this design document. It will be produced as part of the implementation, once the interaction between policy intent and backend capabilities is better understood.

However, the implementation **must** produce a formal, machine-readable schema document. This is a hard requirement, not an optional deliverable.

#### Policy versioning

Every policy document must declare the schema version it conforms to, following the pattern established by Kubernetes manifests:

* the version field must be present and must use [Semantic Versioning](https://semver.org/)
* the system must reject policy documents whose declared version is incompatible with the currently supported schema
* backward-compatible minor/patch versions may be accepted; incompatible major versions must be rejected
* the schema version is a property of the policy document, not of the sandbox runtime

This ensures that policy documents remain interpretable over time and that silent behavioral changes from schema drift are prevented.

## Threat model and security

### Threat model

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
* misuse of shared-IP or CDN-hosted services
* use of upstream proxies or relay APIs to broaden reach
* accidental over-permissiveness caused by policy confusion
* illusion of strong verification where only weak signals exist

### Security boundary

The system strongly controls:

* which first-hop destinations may be contacted
* which transport classes may be used
* whether HTTP(S) must be inspected
* whether a bypass is required
* whether traffic stayed inside the policy pipeline

The system does **not** strongly control:

* what an allowed destination does on the app's behalf
* whether an allowed API is effectively acting as a proxy or relay
* arbitrary non-HTTP semantics over allowed channels
* ultimate safety of the workload itself

This means the trust boundary is:

```text
sandboxed application (in VM)
    ↓
gateway proxy pipeline
    ↓
approved first-hop destination
```

After that first hop, trust depends on the service itself.

### Escape-pattern assumptions and responses

The design explicitly accounts for the following classes of behavior.

#### Direct IP connections

Response:

* denied unless explicitly allowed
* never equivalent to hostname authorization

#### Alternate DNS paths

Response:

* denied unless explicitly allowed

#### IPv6-only or IPv6-bypass paths

Response:

* eliminated by design — the networking subsystem is IPv4-only. IPv6 is dropped at the gateway's nftables (`ip6` blanket drop), the per-session network has no IPv6 addressing, the VM NIC has no IPv6 address, and the DNS resolver strips AAAA records. There is no IPv6 path to exploit.

#### QUIC / HTTP/3

Response:

* deny by default unless explicitly bypassed

#### Raw non-HTTP traffic on expected ports

Response:

* deny unless explicit bypass applies

#### Missing SNI

Response:

* explicit bypass only

#### Pinning or custom trust stores

Response:

* explicit application configuration or explicit bypass

#### CONNECT on transparent-origin path

Response:

* denied unless the target is declared as an upstream proxy in policy

#### Local helper proxies inside the VM

Response:

* acceptable so long as all egress from the VM still traverses the gateway pipeline

#### Shared-IP/CDN ambiguity

Response:

* resolved only by SNI plus HTTP host validation
* IP allowlists are never final web identity checks

#### ECH or other opaque TLS evolution

Response:

* ECH configs are stripped from DNS responses by default for level 2 and level 3 destinations, forcing client fallback to standard TLS
* if the upstream server mandates ECH and rejects non-ECH connections, the destination requires an explicit level 1 (transport-only) bypass — HTTP inspection is not possible
* ECH stripping is enabled by default to prevent silent inspection breakage as ECH adoption grows

### Relay-capable services and trust amplification

A destination may be allowed at the network level yet still act as an application-layer proxy or relay.

Examples include services that can:

* fetch arbitrary URLs
* open arbitrary outbound connections on behalf of the client
* execute code remotely
* forward requests
* act as browser automation backends
* act as generic callback or webhook brokers

This is not a failure of the sandbox network layer. It is a trust issue in the allowed destination.

#### Policy implication

Allowed destinations should conceptually be classified into:

* terminal services
* API services
* relay-capable services
* explicit proxies

The network-control subsystem cannot fully solve this problem, but it must not hide it.

### Fail-closed requirement

The system must fail closed.

If any policy-enforcing component fails:

* direct egress must not become available
* default result must be deny
* bypasses must not silently widen

This includes failures of:

* per-session network connectivity
* nftables rules
* local DNS resolver
* Envoy (if Envoy crashes, DNAT-redirected TCP connections hit a dead port and fail — the kernel firewall ensures no direct egress is possible regardless)
* mitmproxy
* sandbox daemon / policy distribution

The fail-closed property extends to the VM boundary: if the gateway container is not running, the VM has no network connectivity. The per-session network provides no default route to the internet — only to the gateway. See [sandbox-design.md § Core design principles](sandbox-design.md#core-design-principles).

## Layer models

### Kernel firewall requirements

The kernel firewall (nftables) inside the gateway container is the hard enforcement layer and the transparent interception mechanism for forwarded traffic from the VM.

#### Must enforce

* deny by default — all traffic denied unless explicitly permitted
* only TCP and UDP are supported IP protocols
* ICMP is explicitly denied by default
* tunneling protocols (GRE, IPIP, WireGuard, etc.) are explicitly denied
* explicit allow only for permitted traffic
* no direct internet egress outside the policy path
* no direct DNS except the local resolver path
* IPv4 rules implement full policy; IPv6 rules are a blanket drop (the networking subsystem is IPv4-only)
* no fail-open on Envoy or mitmproxy failure
* no accidental side interfaces or alternate routes

#### Must provide

* nftables PREROUTING DNAT rules to redirect forwarded TCP traffic from the VM to Envoy
* nftables PREROUTING DNAT rules to redirect forwarded DNS traffic from the VM to the local resolver
* nftables rules for UDP allow/deny (IP/port based)
* gateway-internal loopback exemptions
* explicit host and port restrictions as derived from policy

#### Important rule

The kernel firewall is authoritative for **containment** and **transparent interception**, not for final service identity.

### DNS model

#### Principle

There must be exactly one approved DNS resolution path available to the VM.

#### Requirements

* deny direct external DNS by default
* deny alternate resolver paths unless explicitly allowed
* all DNS policy must be explicit
* DNS answers do not by themselves authorize traffic

#### DNS resolution for policy enforcement

Policy is expressed in terms of domain names, but some enforcement components operate on IP addresses. The local DNS resolver bridges this gap:

* the local resolver is the only DNS path available to the VM — resolv.conf points to it, and nftables PREROUTING DNAT redirects all DNS traffic from the VM to it
* non-allowed domains receive NXDOMAIN — the resolver enforces policy at the DNS layer
* AAAA records are stripped from all responses — the resolver returns only A records. The network path is IPv4-only, so AAAA records for allowed domains would resolve to unreachable IPv6 addresses. Stripping them avoids unnecessary resolution failures and happy-eyeballs delays in dual-stack client libraries.
* for allowed domains, resolution results are reported to the sandbox daemon, which maintains TTL-aware IP-to-domain mappings and pushes configuration updates to all enforcement components that operate on IP addresses
* re-resolution occurs when DNS TTL expires, with a configurable maximum interval (e.g., 60 seconds) as an upper bound regardless of TTL — domains with very long TTLs must not leave stale IPs in place indefinitely
* on resolution failure: immediately remove the previously resolved IPs for the affected domain (fail-closed), log the failure, and reflect the failure in the sandbox health status — stale IPs from domains that no longer resolve are a potential attack vector (e.g., IP takeover) and must not persist
* all DNS queries are logged for audit trail purposes, providing domain→IP correlation that supports connection attribution

#### DNS interception is tamper-proof

The agent runs as root inside the VM and can modify `resolv.conf`, hardcode alternate DNS servers, or configure applications to use any resolver it chooses. None of this matters. All traffic from the VM exits through the single virtio-net NIC, crosses the bridge, and hits the gateway container's nftables PREROUTING DNAT rules. Any packet destined for port 53 (UDP or TCP) is redirected to the local resolver regardless of the original destination address the agent specified.

The gateway container runs on the host side of the hardware virtualization boundary — outside the VM. The agent cannot modify its nftables rules, restart its processes, or interfere with it in any way. This is a stronger property than the old namespace-based model: the enforcement point sits behind a hardware boundary (virtio-net), not just a kernel boundary (namespaces). The agent's root privileges are scoped to the VM guest and do not extend to the host or gateway.

#### Important limitation

DNS allowlisting is not final service verification.

A DNS answer:

* may be shared across many hostnames
* may be one of many CDN edges
* may later be used with a different hostname or protocol

Therefore DNS is only an input to policy, never final proof.

#### Stale IP window

There is an inherent window between when a domain's IP address changes and when the control plane re-resolves and pushes the update. During this window, traffic to the old IP remains permitted while traffic to the new IP is not yet allowed.

This is a known limitation of any DNS-based policy system. TTL-aware resolution minimizes the window but cannot eliminate it entirely. The design accepts this trade-off. Policy authors should be aware that IP-level enforcement is eventually consistent with DNS, not instantaneous.

#### Connection termination on IP rotation

When DNS re-resolution produces a **changed** IP set for a domain (IPs added, removed, or replaced), the sandbox daemon pushes updated configuration to all enforcement components. IPs no longer present in the new set are removed from nftables rules and Envoy configuration, and existing connections to those removed IPs are terminated immediately. There is no grace period or connection draining.

When re-resolution produces the **same** IP set as the previous resolution, no action is taken — existing connections, nftables rules, and Envoy configuration are left untouched. This is critical for domains with short TTLs (common for CDNs), which would otherwise cause unnecessary connection churn for long-lived connections such as WebSocket streams or gRPC streaming RPCs.

Rationale for immediate termination on actual IP change:

* an old IP may no longer belong to the intended service — allowing continued communication risks connecting to a different host (IP takeover)
* this is consistent with the fail-closed philosophy applied to DNS resolution failure
* the sandbox is not a production runtime — brief connection interruptions are acceptable by design
* applications that need resilience will retry naturally

#### DNS-over-TLS and DNS-over-HTTPS

DNS-over-TLS (DoT, port 853) is blocked by nftables unless explicitly allowed. No special handling is required.

DNS-over-HTTPS (DoH) operates over port 443 and is indistinguishable from normal HTTPS traffic at the network level. If an application sends DoH queries to an allowed HTTPS destination (e.g., a public DNS provider that is also in the allow list), it can resolve domain names outside the local resolver's control.

This does not expand the application's network reach — resolved IPs must still be present in the nftables allow list to be reachable. However, it bypasses the local resolver's query logging and NXDOMAIN enforcement, creating a gap in audit trails.

DoH is accepted as a residual risk. Operators who require complete DNS audit coverage can block known DoH providers at the policy level.

### SNI model

#### Principle

SNI is useful, but only as a connection-level signal.

It is suitable for:

* coarse TLS routing
* coarse host expectation
* reducing ambiguity on shared IPs
* rejecting clearly invalid TLS cases

It is not sufficient for final HTTP authorization.

#### Rule

* if HTTP(S) is being used and strict host policy matters, SNI alone is not enough
* no-SNI TLS requires explicit bypass
* SNI validation is required where applicable, but it is not the final authority for HTTP traffic

#### Domain fronting

Domain fronting is a key attack that motivates the combination of SNI validation and HTTP-level host validation. Two variants exist:

**SNI-level fronting:** A shared IP (e.g., a CDN edge) hosts both allowed and disallowed services. The application connects to the shared IP but sets the TLS SNI to a disallowed domain. SNI validation catches this — the SNI does not match any allowed domain and the connection is rejected.

**HTTP-level fronting:** The application sets the TLS SNI to an allowed domain (passing SNI validation) but sets the HTTP `Host` or `:authority` header to a different, disallowed domain. The destination server (e.g., a CDN) routes based on the HTTP header, not the SNI, delivering traffic to the disallowed service. HTTP-level host validation catches this — the mismatch between SNI and the request-level host is detected by mitmproxy.

Neither check alone is sufficient. SNI validation without HTTP inspection misses HTTP-level fronting. HTTP inspection without SNI validation misses connections that never reach mitmproxy (levels below 3). Both checks are required, and they catch different attacks.

### HTTP model

#### Principle

HTTP identity is request-scoped, not connection-scoped.

Therefore:

This is a direct consequence of HTTP/2 connection multiplexing and HTTP/1.1 keep-alive host switching — the same connection may carry requests for different hosts, making connection-level identity (SNI, IP) insufficient. See also the [domain fronting analysis in the SNI model](#domain-fronting).

* HTTP/1 `Host` must be validated per request
* HTTP/2 `:authority` must be validated per request

#### Consequence

HTTP inspection is mandatory for normal allowed web traffic.

#### HTTP rules

The sandbox must be able to enforce, when configured:

* allowed hosts
* allowed methods
* allowed paths
* allowed schemes
* host/path consistency
* explicit block or allow rules

Even if only host-level policy is required, request-level inspection remains mandatory.

### Certificate management

#### Requirement

TLS interception by mitmproxy requires a CA certificate that applications in the VM trust. The sandbox must manage this certificate lifecycle.

#### CA generation and storage

* a unique CA keypair is generated per session at creation time
* the CA is short-lived — its validity period matches the session lifetime
* the private key is stored only in the gateway container (accessible to mitmproxy) and is never present inside the VM
* per-session generation ensures that compromise of one session's CA does not affect others

#### Trust store injection

The CA certificate (public part only) is injected into the VM during provisioning so that applications trust the interception CA:

* installed in the VM's system trust store (`/usr/local/share/ca-certificates/` + `update-ca-certificates`)
* standard environment variables set for applications that use their own trust store resolution (`SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE`, `NODE_EXTRA_CA_CERTS`, `CURL_CA_BUNDLE`)
* installed in the Docker daemon trust store (`/etc/docker/certs.d/`) for registry image pulls

This provides transparent interception for applications that rely on the system trust store or standard environment variables. The detailed trust store paths and environment variables are specified in [VM-side networking configuration § CA certificate trust](#ca-certificate-trust).

#### Certificate pinning and custom trust stores

Applications that use certificate pinning or hardcoded trust stores will reject the interception CA. These applications require a TLS-verified bypass (level 2).

Some pinned applications expose configuration options to provide a custom CA certificate. Whether and how to use such options is the user's responsibility — the sandbox provides the bypass mechanism, not application-specific CA configuration.

#### Rotation

For ephemeral sessions, rotation is not required — the CA lives and dies with the session. For long-lived sessions, a CA rotation procedure is a future enhancement.

### Upstream proxy support

#### Requirement

The sandbox may need to support applications that intentionally use an explicit upstream HTTP proxy.

#### Design position

This is allowed only as an explicit policy path.

#### Why this is special

For a normal transparent client:

* proxy-style `CONNECT` is unexpected and invalid

For a client intentionally using an upstream HTTP proxy:

* `CONNECT` and absolute-form HTTP requests are expected

Therefore:

* explicit upstream-proxy use must be modeled as a separate policy case
* it must not be silently merged into the ordinary transparent-origin path

#### CONNECT handling

CONNECT requests are only valid when targeting a destination declared as an upstream proxy in policy. CONNECT to any other destination is denied — this prevents applications from using CONNECT as a tunneling mechanism through non-proxy endpoints.

When mitmproxy inspects traffic to a declared upstream proxy (level 3), it also validates the CONNECT target — the destination the client asks the proxy to connect to. If the CONNECT target is not an allowed destination in policy, the request is denied with an HTTP 599 response. This is a special case where the sandbox can see the intended next hop beyond the proxy and enforces what is visible.

This is a pragmatic exception to the general trust boundary principle. For most allowed destinations, the sandbox does not police what the service does on behalf of the application. But a CONNECT request explicitly declares the next-hop destination in a field the sandbox can inspect, so it is validated. The upstream proxy could still relay to disallowed destinations through other means — the trust boundary still applies beyond what the sandbox can observe.

CONNECT validation is performed by mitmproxy, which is the only component in the pipeline with HTTP-level visibility. Envoy forwards traffic to mitmproxy without parsing HTTP semantics.

### Transport and protocol classes

#### HTTP/HTTPS

Default mode:

* inspected
* strongly verified
* request-level identity enforcement

#### gRPC

Standard HTTP/2 traffic — POST requests with `content-type: application/grpc` and a path identifying the service and method. Flows through mitmproxy as normal HTTP/2 at level 3 (HTTP inspected). No special handling required.

#### WebSocket

Begins as an HTTP/1.1 Upgrade request (or HTTP/2 extended CONNECT). After the handshake completes, the connection upgrades to an opaque bidirectional binary frame stream that is no longer HTTP-inspectable. Same pattern as QUIC/HTTP/3 — the initial handshake is visible but the ongoing stream is not. WebSocket destinations require a level 2 (TLS-verified) bypass.

#### Non-HTTP TLS

Allowed only by explicit bypass:

* may use SNI if visible
* service identity remains weaker than inspected HTTP

#### Generic TCP

Allowed only by explicit bypass:

* opaque semantics
* strong dependence on trust in the endpoint

#### UDP

Allowed only by explicit bypass:

* narrow and intentional
* strongest review burden
* generally weakest service identity guarantees

## Operations

### Health monitoring

#### Component liveness probes

Each enforcement component in the pipeline must expose or support a liveness probe:

* **nftables** — rule verification (expected chains and PREROUTING DNAT rules are present and active)
* **local DNS resolver** — test resolution of a known-allowed domain
* **Envoy** — admin health endpoint
* **mitmproxy** — health endpoint
* **sandbox daemon** — internal self-check (DNS resolution cycle completing, configuration distribution succeeding)

The sandbox daemon polls these probes periodically. Per-component probes serve a diagnostic purpose: when something is wrong, they identify which component is the source of the failure.

#### Failure response

When a component probe fails:

* log an alert with the affected component identified
* update the sandbox status to reflect degraded networking
* expose the health state via a sandbox daemon status command
* attempt to send a system notification that sandbox networking is degraded

The system must **not** automatically terminate the sandbox on health-check failure. The sandbox may be running long-lived processes that do not require network access. The sandbox owner decides what action to take based on the reported status.

#### End-to-end pipeline verification

Per-component probes do not guarantee that traffic is actually being proxied through the full pipeline. A true end-to-end probe — originating from within the VM and traversing the complete chain (VM → bridge → gateway → nftables PREROUTING DNAT → Envoy → mitmproxy → destination) — would provide stronger assurance.

This is recognized as a future enhancement. Per-component probes are sufficient for initial implementation and provide actionable diagnostics without introducing additional attack surface.

### Component lifecycle and startup ordering

#### Requirement

The pipeline components must start in a specific order to avoid transient exposure or broken behavior during session initialization. The sandbox daemon orchestrates this sequence as part of session creation — see [sandbox-design.md § Session lifecycle](sandbox-design.md#session-lifecycle) for the full create/start/stop/destroy flow.

#### Startup order

Components start outside-in — the outermost enforcement layer first, the traffic gate last:

1. **Kernel firewall (nftables)** — deny-by-default rules are applied first. Nothing can leave the gateway. This is always safe.
2. **mitmproxy** — starts and becomes ready to receive forwarded HTTP(S) traffic from Envoy.
3. **Envoy** — starts and becomes ready to receive DNAT-redirected TCP traffic. Can route to mitmproxy, which is already available.
4. **Local DNS resolver** — starts and becomes ready to answer queries.
5. **nftables PREROUTING DNAT rules** — applied last. Traffic is only redirected into the pipeline once all components are ready to handle it.

#### Why this order is safe

The kernel firewall's deny-by-default rules are the first thing applied and the last thing removed. The nftables PREROUTING DNAT rules are the gate — no traffic enters the userland pipeline until every component is confirmed ready. During the startup window, forwarded traffic from the VM is denied entirely, which is the correct default.

#### Readiness gates

Each component must signal readiness before the next one in the sequence starts:

* **mitmproxy** — health endpoint returns successfully
* **Envoy** — admin health endpoint returns successfully
* **Local DNS resolver** — test query for a known domain resolves successfully

The sandbox daemon orchestrates this sequence and will not proceed to the next step until the current component passes its readiness check.

#### Component failure during operation

If a component crashes after the pipeline is fully operational:

* nftables PREROUTING DNAT rules remain active — redirected traffic hits a dead port and connections fail
* this is fail-closed by design — no traffic leaks, connections simply break
* the sandbox daemon detects the failure via health probes and reports degraded status
* the sandbox daemon may attempt to restart the failed component without restarting the entire session

Traffic is never silently rerouted or allowed to bypass the pipeline due to a component failure.

#### Shutdown order

Shutdown is the reverse of startup — the traffic gate is removed first, the backstop last:

1. **nftables PREROUTING DNAT rules** — removed first. No new traffic enters the pipeline.
2. **Local DNS resolver** — stopped. No new DNS queries are answered.
3. **Envoy** — stopped. No new TCP connections are routed.
4. **mitmproxy** — stopped.
5. **nftables deny-by-default rules** — removed last. The backstop remains until all components are down.

This mirrors the startup logic: the PREROUTING DNAT rules are the gate that controls whether traffic enters the pipeline. Removing them first ensures no new connections are initiated while components shut down. The deny-by-default rules remain as the final safety net until the gateway container is fully torn down.

In-flight connections are terminated immediately as components stop. There is no drain period — this is consistent with the connection termination behavior during IP rotation and the sandbox's non-production posture.

### Error propagation

#### Principle

When the pipeline denies a connection, the application in the VM should receive a fast, informative error rather than a silent timeout. Different pipeline layers produce different error signals, but the design preference is immediate failure with useful feedback for the application and full context in logs for the operator.

#### Error behavior by layer

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

* denied HTTP requests receive an HTTP 599 response (non-standard)
* 599 is deliberately non-standard — no upstream server would send it, making it immediately recognizable as a sandbox policy denial
* the response body should explicitly identify the denial as a sandbox policy decision
* the response should not leak internal policy details beyond the fact that the request was denied

#### Logging

Every denial at every layer is logged with full context:

* source address and port
* intended destination and port
* protocol
* policy rule that triggered the denial
* assurance level (if applicable)
* layer that produced the denial

The application receives a terse error. The audit log receives the full story.

### Logging and audit requirements

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

### Control plane / sandbox daemon

The sandbox daemon is the single process per host that manages all sandbox sessions. It is the single source of truth for sandbox network policy and the mechanism that makes the policy abstraction guarantee real. For the daemon's full responsibilities (VM lifecycle, session management, vsock, resource management), see [sandbox-design.md § Sandbox daemon (sandboxd)](sandbox-design.md#sandbox-daemon-sandboxd).

This section covers only the daemon's **networking-specific responsibilities**.

#### Policy compilation and distribution

* accept abstract policy documents as input — the same documents authored by users
* compile abstract policy into component-specific configurations: nftables rules, local DNS resolver policy, Envoy listener/filter/cluster config, mitmproxy rules
* distribute generated configuration to all running enforcement components in the gateway container
* ensure no enforcement component is hand-configured — all configuration is generated from the abstract policy
* validate policy documents against the declared schema version before compilation

#### DNS re-resolution and IP propagation

* manage the local DNS resolver's policy (allowed domains, NXDOMAIN for denied domains)
* receive resolution results from the local resolver and compare against the current IP set for each domain — push updated configuration only when the resolved IP set actually changes (no-op when IPs are unchanged)
* perform TTL-aware re-resolution with configurable maximum intervals
* immediately remove stale IPs on resolution failure (fail-closed)

#### Configuration distribution to gateway components

* the sandbox daemon is the only component that interprets policy intent
* enforcement components receive only their own generated configuration and do not interpret abstract policy
* configuration updates (including DNS re-resolution) must be applied without requiring session restart where possible

#### Policy compilation error handling

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
* assurance levels are consistent with declared protocol classes (e.g., UDP traffic cannot be declared at level 3)
* bypass entries have required metadata (reason, assurance level)

On failure, the sandbox daemon reports:

* which rule failed validation
* which backend could not express the rule (if applicable)
* why the compilation failed

Domain resolution is performed at compile time as a validation step. All policy domains are resolved during compilation — if a domain cannot be resolved, compilation fails with an error identifying the unresolvable domain. This provides immediate feedback when a policy references a domain that does not exist or is unreachable.

The compile-time resolution also produces the initial seed IPs used to generate the first set of nftables rules and Envoy filter chain configurations. These IPs are a point-in-time snapshot. Runtime re-resolution (TTL-aware, managed by the sandbox daemon) keeps the IP mappings current as DNS records change.

#### Hot-reload with rollback

The all-or-nothing guarantee extends from compilation to distribution. When a policy update is applied at runtime, the sandbox daemon distributes the new configuration to components in outside-in order:

1. **nftables deny/allow rules** — updated first
2. **mitmproxy** — reconfigured
3. **Envoy** — reconfigured
4. **Local DNS resolver** — reconfigured
5. **nftables PREROUTING DNAT rules** — updated last

During the update window, newly-added destinations may be briefly unreachable until all components have been reconfigured. This is by design — the outside-in ordering ensures fail-closed behavior during transitions. No traffic is permitted to a new destination until all components are consistent.

If any component fails to accept the new configuration, the sandbox daemon rolls back all previously updated components to their prior configuration. No partial policy state is permitted — either the entire update succeeds across all components or the session remains on the previous policy.

In-flight connections to destinations removed by the new policy are terminated immediately, consistent with the connection termination behavior during IP rotation.

The sandbox daemon reports the outcome of every policy update: success, or failure with the component that rejected the configuration and the rollback status.

## Closing

### Residual risks

Even with correct implementation, the following residual risks remain:

* allowed services may be malicious or overly capable
* allowed APIs may act as relays
* generic TCP/UDP bypasses remain weak assurance paths
* TLS-verified level loses request-level certainty
* application compatibility may pressure policy toward broader exceptions
* user misunderstanding may overestimate the guarantees of "allowed" traffic
* increasing ECH adoption may force more destinations to level 1 bypasses as servers begin mandating ECH, reducing the proportion of traffic that can be verified at level 2 or inspected at level 3
* protocol tunneling over allowed ports and connections — if an application tunnels arbitrary data inside valid requests to an allowed destination, the sandbox cannot detect or prevent it
* hidden DNS resolution paths (e.g., DoH to allowed destinations) do not expand network reach — unresolved IPs remain blocked by nftables — but bypass the local resolver's query logging and NXDOMAIN enforcement

These are not implementation bugs. They are the natural limits of the problem space.

#### Deferred: IPv6 support

The networking subsystem is IPv4-only by design. This is a deliberate simplification that reduces attack surface and complexity. IPv6 support is deferred as a future improvement. When implemented, it would require:

* dual-stack per-session networks (`--ipv6` on session bridge creation on Linux, dual-stack vmnet subnets on macOS)
* `inet`-family nftables rules (unified IPv4/IPv6 policy tables instead of separate `ip` and `ip6` tables)
* AAAA record handling in the DNS resolver (return AAAA alongside A records for allowed domains)
* IPv6 forwarding enabled in the gateway container (`net.ipv6.conf.all.forwarding=1`)
* dual-stack VM configuration (IPv6 address on the bridge interface, IPv6 default route to the gateway)

The intended model is session-level opt-in — sessions that need IPv6 destinations would request dual-stack networking at creation time. Sessions that don't need IPv6 would remain single-stack to preserve the simpler security posture.

### Final design summary

This subsystem defines the networking architecture for the sandbox in which:

* all VM egress traffic traverses a single path: VM → per-session network → gateway container → proxy pipeline → destination
* all traffic is denied by default — only TCP and UDP are supported; ICMP and tunneling protocols are explicitly denied
* nftables PREROUTING DNAT transparently intercepts forwarded traffic from the VM, with Envoy recovering original destinations via `original_dst`
* a local DNS resolver enforces policy at the DNS layer and provides query logging for audit trails
* UDP policy is enforced purely by nftables (IP/port allow/deny) with no userland proxy
* the only normal allowed mode is inspected HTTP(S)
* every non-HTTP or non-inspected flow is an explicit bypass
* bypasses are classified by assurance level
* policy is abstract and implementation-independent
* policy backends are hidden behind a single sandbox policy model compiled by the sandbox daemon
* the VM's network topology is the primary constraint — single NIC, single default route, no alternate physical exit path even with root access inside the VM (the agent runs as root by default; non-root is an optional operator hardening setting)
* inner Docker networking is transparent — inner container traffic NATs to the VM's IP and follows the same gateway path
* per-session network segments (Docker bridges on Linux, vmnet instances on macOS) provide complete inter-session isolation
* the system fails closed — no gateway means no network connectivity
* logs make every exception visible
* the design is honest about the difference between constrained egress and true safety

The result is not "safe internet access for arbitrary code."

The result is:

> explicit, mediated, auditable outbound capability with strong controls for HTTP(S) and explicit trust-based exceptions for everything else.
