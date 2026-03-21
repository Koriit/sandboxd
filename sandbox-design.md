# Sandbox Design for Coding AI Agents

## Status

Draft for implementation.

## Table of contents

- [Purpose](#purpose)
- [Non-goals](#non-goals)
- [Core design principles](#core-design-principles)
- [Architecture overview](#architecture-overview)
- [Why VMs over containers](#why-vms-over-containers)
- [Why Lima](#why-lima)
- [Sandbox daemon (sandboxd)](#sandbox-daemon-sandboxd)
- [Session lifecycle](#session-lifecycle)
- [VM specification](#vm-specification)
- [VM hardening layers](#vm-hardening-layers)
- [Gateway container](#gateway-container)
- [Networking integration](#networking-integration)
- [Workspace provisioning](#workspace-provisioning)
- [Control channel (vsock)](#control-channel-vsock)
- [Inner Docker policy](#inner-docker-policy)
- [Certificate management](#certificate-management)
- [Platform-specific considerations](#platform-specific-considerations)
- [Resource management](#resource-management)
- [Time synchronization](#time-synchronization)
- [Threat model and escape analysis](#threat-model-and-escape-analysis)
- [Defense in depth summary](#defense-in-depth-summary)
- [Residual risks](#residual-risks)
- [Relationship to the networking design](#relationship-to-the-networking-design)
- [Deferred work](#deferred-work)

## Purpose

This document defines the **overall sandbox architecture** for running coding AI agents in isolated, disposable environments with full Docker, Docker Compose, and testcontainers capability.

The sandbox must:

* give agents a realistic local-dev experience — `docker build`, `docker compose up`, testcontainers, port binding, network creation all work as expected
* prevent agents from escaping the sandbox or accessing unauthorized resources
* prevent agents from tampering with the network policy pipeline that mediates their outbound traffic
* work on both Linux (production, CI, EC2) and macOS (local developer machines) using the same architecture
* support both ephemeral sessions (create, use, destroy) and persistable sessions (stop, resume with disk state preserved)

The network-control subsystem — proxy pipeline, DNS resolver, policy model, assurance levels — is defined in the [networking design document](networking-design.md). This document covers the isolation boundary, VM lifecycle, gateway deployment model, workspace provisioning, and how the networking subsystem connects to the VM.

## Non-goals

This design does **not** cover:

* the policy language or schema — defined in the networking design
* proxy pipeline internals (Envoy filter chains, mitmproxy rules, DNS resolver implementation) — defined in the networking design
* ingress connectivity (allowing external access to services running inside the sandbox) — future enhancement
* multi-tenant scheduling or orchestration across many hosts — this design covers a single host running one or more sessions
* IDE or editor integration — the sandbox exposes SSH and vsock; how tools connect is outside scope
* Windows host support

## Core design principles

1. **Hardware isolation boundary**
   The sandbox boundary is a virtual machine, not a container. Hardware virtualization (KVM on Linux, Apple Virtualization.framework on macOS) enforces the boundary in silicon. A single kernel vulnerability cannot escape the sandbox.

2. **Untamperable network policy**
   The network proxy pipeline runs outside the VM, on the host side of the VM's virtual NIC. The agent cannot modify, bypass, or disable the pipeline because it has no access to the host or the gateway container.

3. **Minimal attack surface**
   The VM exposes the smallest possible device model. No virtio-fs, no USB, no display, no legacy devices. Every device is code parsing guest-controlled input — fewer devices means fewer opportunities for exploitation.

4. **Ephemeral by default**
   Sessions are disposable. Destroy deletes all state irrecoverably. Persistence is opt-in (stop preserves disk; resume restarts from disk state). No session accumulates long-lived trust or credentials.

5. **Cross-platform with one architecture**
   The same conceptual architecture — Lima VM + gateway container + proxy pipeline — runs on Linux and macOS. Platform differences are confined to the hypervisor backend (QEMU/KVM vs. Apple VZ) and are not visible to the agent or the policy model.

6. **Fail closed**
   If the gateway container is not running, the VM has no network connectivity. If the proxy pipeline is degraded, traffic fails — it does not bypass. The deny-by-default posture from the networking design extends to the VM boundary: no gateway means no egress.

7. **Defense in depth**
   No single layer is assumed to be perfect. The design stacks independent security mechanisms so that failure of any one layer does not result in full compromise.

## Architecture overview

```
Host (Linux or macOS)
├── sandboxd (one per host, manages all sessions)
│
├── Session N
│   ├── Lima VM (QEMU/KVM on Linux, Apple VZ on macOS)
│   │   ├── Agent process (non-root, docker group)
│   │   ├── dockerd (root, constrained by authorization plugin)
│   │   ├── Workspace (/home/agent/workspace — cloned repo, writable)
│   │   └── Single NIC (virtio-net) → default route to gateway
│   │
│   └── Gateway container (standard Docker, runc runtime)
│       ├── nftables (PREROUTING DNAT for forwarded VM traffic)
│       ├── Envoy (original_dst listener)
│       ├── mitmproxy (HTTP inspection)
│       └── DNS resolver (policy-aware)
│
│   VM ←→ Gateway: Docker bridge network (per-session, isolated)
│   VM ←→ Host: vsock (control channel, not IP — does not traverse proxy)
│
├── Session M
│   ├── Lima VM ...
│   └── Gateway container ...
│
└── Host Docker daemon (manages gateway containers)
```

### Key structural properties

**One VM per session.** Each agent session gets its own VM with its own kernel, filesystem, and Docker daemon. Sessions cannot interact with each other.

**One gateway per session.** Each VM has a dedicated gateway container running the proxy pipeline. Gateway containers are isolated from each other via per-session Docker bridge networks.

**Two communication paths.** The VM has exactly two paths to the outside: (1) the virtual NIC, which routes through the gateway container, and (2) vsock, which connects directly to the sandbox daemon on the host. There are no other paths — no shared filesystems, no host mounts, no metadata services.

**Sandbox daemon is the control plane.** The sandbox daemon manages both the VM lifecycle and the gateway container lifecycle. It is the same daemon described in the networking design — extended here with VM management responsibilities.

## Why VMs over containers

The decision to use VMs rather than containers is the foundational architectural choice. It was made after evaluating container-based approaches and finding them structurally inadequate for this threat model.

### Container escape requires one vulnerability

In a container-based sandbox (including Sysbox), the agent shares the host kernel. A single kernel vulnerability — exploitable via any of the ~300 syscalls available to the container — gives the agent host root. The attack is:

```
Agent → syscall to shared host kernel → exploit kernel bug → host root
```

This is one vulnerability, one step. The entire security model depends on the host kernel being bug-free with respect to the syscall surface exposed to the container.

### VM escape requires chaining multiple vulnerabilities

In a VM-based sandbox, the agent runs its own kernel. To reach the host, the agent must:

1. Exploit the guest kernel to gain guest root (or already have it)
2. Craft malicious device I/O targeting a QEMU bug in one of the 4 virtio devices
3. Achieve code execution in the QEMU process on the host
4. Escalate from the unprivileged, sandboxed QEMU process to host privileges

```
Agent → exploit guest kernel → craft malicious device I/O →
  trigger QEMU bug → land in sandboxed QEMU process → escalate to host
```

This requires 2-3 independent vulnerabilities chained across different software components (guest kernel, QEMU device emulation, host privilege escalation). Each step targets a different codebase with different security properties.

### Sysbox was evaluated and rejected

Sysbox enables Docker-in-Docker without `--privileged` by providing an alternate OCI runtime with user namespaces, virtualized `/proc`/`/sys`, and relaxed seccomp/AppArmor profiles. It was evaluated as the container-based approach (see [research report](.tasks/handoffs/chatgpt-dind.md)). It was rejected for four reasons:

1. **Blocks gVisor.** Both Sysbox and gVisor are OCI runtimes. They cannot be composed — you cannot run a Sysbox container inside gVisor or vice versa. This eliminates the possibility of adding a syscall-filtering layer.

2. **Linux-only.** Sysbox has no documented support on macOS, including inside Lima or Colima VMs. The sandbox must work on macOS developer machines. A Linux-only isolation boundary does not meet the cross-platform requirement.

3. **Wider syscall surface.** Sysbox relaxes the outer container's seccomp profile to allow `mount`, `unmount`, `pivot_root`, and other high-leverage syscalls. It also disables AppArmor for the outer container. These relaxations are necessary for DinD to function, but they widen the attack surface relative to a standard container.

4. **Shared kernel.** Regardless of Sysbox's mitigations, the fundamental problem remains: the agent and the host share a kernel. The mitigations reduce risk; they do not change the structural property that one kernel bug is sufficient for escape.

### gVisor was evaluated and rejected

gVisor intercepts syscalls in userspace and implements a subset of the Linux kernel API, providing a strong syscall-filtering boundary. It has an official Docker-in-gVisor tutorial. It was rejected for one reason:

**gVisor requires `--iptables=false` on the inner dockerd.** Without iptables, Docker cannot perform port mapping (`-p` flag). Without port mapping, testcontainers' port discovery mechanism breaks. Testcontainers is a non-negotiable requirement. This is not a configuration issue — it is a fundamental incompatibility between gVisor's network stack and Docker's port mapping implementation.

### Firecracker and Cloud Hypervisor were evaluated and rejected

Firecracker (AWS) and Cloud Hypervisor provide microVM-based isolation with sub-second boot times and extreme density. They were rejected for one reason:

**KVM-only.** Both require KVM, which means Linux-only. They do not run on macOS. Lima with QEMU provides the same hardware isolation boundary (both use KVM on Linux) with the addition of Apple VZ support on macOS. Firecracker's advantages — sub-second boot, thousands of VMs per host — are optimizations for short-lived serverless functions. Agent sessions are long-lived (minutes to hours). The boot time difference (sub-second vs. 10-30 seconds) is not meaningful for this use case.

### Industry validation

The VM-over-container choice aligns with the direction of the industry:

* Gitpod moved from Kubernetes containers to VMs (Firecracker)
* GitHub Codespaces uses VMs
* Docker Sandboxes (January 2026) uses microVMs
* Fly.io and Sprites use Firecracker

These projects reached the same conclusion independently: for isolation of untrusted or semi-trusted workloads, VMs provide a qualitatively stronger boundary than containers.

## Why Lima

Lima (Linux Machines) is a CNCF incubating project that manages Linux VMs on macOS and Linux. It provides a single CLI (`limactl`) that abstracts the hypervisor backend.

### Selection criteria

| Requirement | Lima |
|---|---|
| Cross-platform (Linux + macOS) | QEMU/KVM on Linux, Apple VZ on macOS |
| Docker inside VM | Provisioned via templates; first-class use case |
| Programmatic API | CLI (`limactl`) + YAML templates |
| Community and maintenance | CNCF incubating, active development |
| AI sandbox support | v2.0 added agent sandboxing as first-class use case |
| Snapshot support | VM snapshots for fast cold starts |
| vsock support | Supported for host-guest communication |

### What Lima provides

* VM creation from YAML templates with cloud-init provisioning
* Automatic hypervisor selection (QEMU with KVM on Linux, VZ on macOS)
* SSH access to VMs via `limactl shell`
* File sharing (disabled in this design — repos cloned inside VM)
* Port forwarding (used selectively for control paths)
* VM snapshot and restore

### What Lima does not provide

* Network policy enforcement — handled by the gateway container
* Docker authorization plugins — handled inside the VM
* Multi-host orchestration — handled by external tooling
* Gateway container management — handled by the sandbox daemon

Lima is the VM lifecycle manager. The sandbox daemon wraps Lima with policy enforcement, gateway management, and session lifecycle.

## Sandbox daemon (sandboxd)

The sandbox daemon is a single process per host that manages all sandbox sessions. It is the same daemon described in the networking design — that document covers its role in policy compilation and distribution. This document covers its role in VM and gateway lifecycle management.

### Responsibilities

**Session lifecycle:**

* create, start, stop, and destroy sessions
* manage Lima VM instances (create, start, stop, delete)
* manage gateway containers (create, start, stop, remove)
* manage per-session Docker bridge networks
* coordinate VM and gateway startup/shutdown ordering

**Policy management** (as defined in the networking design):

* accept abstract policy documents
* compile policy into component-specific configurations
* distribute configuration to gateway container components
* manage DNS re-resolution and IP propagation
* validate policy documents against declared schema versions

**Control channel:**

* listen on vsock for control messages from VMs
* authenticate and validate all control messages
* expose session status and health information

**Resource management:**

* enforce per-session resource limits (CPU, memory, disk)
* monitor host capacity
* report resource utilization per session

### Daemon lifecycle

The sandbox daemon starts before any sessions exist and persists across session lifecycles. It is a long-lived process, not a per-session process. On restart, it recovers state from Lima's VM inventory and Docker's container inventory — both are durable and survive daemon restarts.

### API surface

The sandbox daemon exposes a local API (Unix socket or localhost-only) for session management. This API is used by CLI tools and orchestration layers. It is not exposed on the network.

```
sandboxd create [--template <path>] [--policy <path>] [--boot-cmd <cmd>]
sandboxd start <session-id>
sandboxd stop <session-id>
sandboxd destroy <session-id>
sandboxd ssh <session-id>
sandboxd status [<session-id>]
sandboxd policy update <session-id> <policy-path>
sandboxd logs <session-id> [--component <name>]
```

## Session lifecycle

### Create

`sandboxd create` performs the following steps in order:

1. **Allocate session ID.** Generate a unique session identifier.
2. **Create per-session Docker bridge network.** An isolated bridge network that will connect the gateway container to the VM's virtual NIC.
3. **Create gateway container.** A standard Docker container (runc runtime) attached to the session's bridge network. The container runs the proxy pipeline components (nftables, Envoy, mitmproxy, DNS resolver) but does not start them yet.
4. **Create Lima VM.** Instantiate a VM from the Lima template. The VM's network interface is connected to the session's bridge network. The VM's default route points to the gateway container's IP on the bridge.
5. **Provision the VM.** Cloud-init and provisioning scripts install Docker, agent tooling, and hardening configuration inside the VM.
6. **Start the gateway pipeline.** Start the proxy pipeline inside the gateway container using the startup ordering defined in the networking design (nftables deny-by-default first, redirect rules last).
7. **Start the VM.** Boot the VM. At this point, the VM has network connectivity through the gateway, mediated by the proxy pipeline.
8. **Run boot command (optional).** If `--boot-cmd` was specified, execute it inside the VM after startup completes. This is typically used to clone a repository or start an agent process.

The VM has no network connectivity until the gateway pipeline is fully operational. This is intentional — the pipeline must be ready before traffic can flow.

### Start

`sandboxd start <session-id>` resumes a previously stopped session:

1. Start the gateway container and pipeline (same ordering as create).
2. Start the Lima VM (boots from preserved disk state).
3. Reconnect networking (VM's default route to gateway).

Processes that were running when the session was stopped are not restored — there are no memory snapshots. Only disk state persists. The Docker daemon inside the VM starts fresh, but previously pulled images and created volumes remain on disk.

### Stop

`sandboxd stop <session-id>` gracefully stops a session:

1. Shut down the proxy pipeline inside the gateway container (reverse of startup ordering — redirect rules removed first, deny-by-default last, as defined in the networking design).
2. Shut down the Lima VM. The VM's disk state is preserved.
3. Stop the gateway container.

The session's Docker bridge network and disk image remain. The session can be resumed with `start`.

### Destroy

`sandboxd destroy <session-id>` irrecoverably deletes a session:

1. Stop the session if running (same as `stop`).
2. Delete the Lima VM and its disk image.
3. Remove the gateway container.
4. Remove the per-session Docker bridge network.

All state is deleted. This cannot be undone.

### SSH

`sandboxd ssh <session-id>` opens an SSH connection to the VM. This uses either vsock (preferred, no IP path required) or a host-local port forward. SSH is a control path at the same trust level as vsock — it is not exposed on the network and is not accessible to other sessions or external parties.

### Status

`sandboxd status` reports the state of all sessions or a specific session:

* VM state (running, stopped, creating, error)
* Gateway state (running, stopped, error)
* Pipeline health (per-component, as defined in the networking design)
* Resource utilization (CPU, memory, disk)
* Policy version in effect

## VM specification

### Lima template

Each VM is created from a Lima YAML template that specifies:

* base image (stock Ubuntu cloud image)
* CPU, memory, and disk allocation
* hypervisor backend (auto-detected: QEMU/KVM on Linux, VZ on macOS)
* network configuration (bridge network to gateway)
* vsock enablement
* provisioning scripts (cloud-init)
* disabled features: file sharing (no virtio-fs), port forwarding (controlled by sandboxd)

### Base image

Stock Ubuntu cloud images. No custom disk images are built or maintained. All customization is performed via cloud-init provisioning during `create`. This eliminates the need for an image build pipeline and ensures the base is always a known, upstream-maintained artifact.

### Provisioning

Cloud-init provisioning installs and configures:

* Docker Engine (CE) and Docker Compose plugin
* Agent user account (non-root, member of `docker` group)
* SSH authorized keys (for `sandboxd ssh`)
* System hardening (see [VM hardening layers](#vm-hardening-layers))
* Interception CA certificate in the system trust store and standard environment variables (`SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE`, `NODE_EXTRA_CA_CERTS`, `CURL_CA_BUNDLE`)
* DNS configuration (`resolv.conf` pointing to the gateway's DNS resolver)

### Snapshot optimization

Provisioning a VM from scratch takes time (package installation, Docker setup). For fast cold starts, the sandbox daemon can snapshot a provisioned VM and use the snapshot as the base for new sessions. This amortizes provisioning cost across sessions.

Snapshot management is a performance optimization, not a security boundary. Snapshots must be re-provisioned when the base image, provisioning scripts, or security configuration changes.

## VM hardening layers

### Device model

The VM exposes the minimal set of virtio devices required for operation:

| Device | Purpose | Attack surface |
|---|---|---|
| virtio-net | Networking (routed through gateway) | Network packet parsing |
| virtio-blk | Root disk (VM image) | Block I/O protocol |
| virtio-rng | Entropy (/dev/urandom seeding for SSH keys, TLS, etc.) | Minimal — read-only, no guest-controlled input parsing |
| virtio-vsock | Host-guest control channel | vsock protocol parsing |

**Not present:** USB controller, display adapter, sound device, floppy controller, legacy ISA devices, virtio-fs, virtio-serial (beyond vsock), PCI passthrough, GPU.

Every device in the VM's device model is code in QEMU (or VZ) that parses guest-controlled input. The guest kernel and any guest process can craft arbitrary device I/O. Each device is therefore an attack surface. The security value of a minimal device model is linear — fewer devices means fewer independent targets for exploitation.

### QEMU process hardening (Linux)

On Linux, the QEMU process that backs each VM is sandboxed at the host level:

* **Unprivileged user.** QEMU runs as a dedicated non-root user with no special capabilities.
* **Seccomp.** QEMU's built-in seccomp sandbox is enabled: `-sandbox on,obsolete=deny,elevateprivileges=deny,spawn=deny`. This denies obsolete syscalls, prevents privilege escalation, and prevents QEMU from spawning child processes.
* **Namespaces.** The QEMU process runs in its own mount, PID, and IPC namespaces. It cannot see or interact with other host processes.
* **No host filesystem access.** QEMU has access only to the VM's disk image file. No host directories are mounted into the QEMU process.
* **Cgroup limits.** The QEMU process is placed in a cgroup with CPU, memory, and PID limits. A compromised QEMU process cannot exhaust host resources.

On macOS, Apple Virtualization.framework provides equivalent isolation through the platform's own sandboxing mechanisms. The VZ process runs in a macOS sandbox profile with restricted entitlements.

### Guest kernel

Two options, with different security/operational trade-off:

**Option A — Stock Ubuntu kernel (default):**

The stock kernel shipped with the Ubuntu cloud image. This is a general-purpose kernel with loadable modules, USB drivers, and other subsystems that are unnecessary in this VM. The attack surface is larger, but operational overhead is zero — no custom kernel to build, test, or maintain.

**Option B — Minimal custom kernel (optional hardening):**

A custom kernel with only the required subsystems compiled in:

* No loadable modules (`CONFIG_MODULES=n`) — prevents loading kernel modules from inside the VM
* No USB, Bluetooth, sound, GPU subsystems
* No unnecessary filesystems (only ext4, tmpfs, proc, sysfs, cgroup)
* Hardening options enabled: `CONFIG_HARDENED_USERCOPY`, `CONFIG_STACKPROTECTOR_STRONG`, `CONFIG_RANDOMIZE_BASE` (KASLR), `CONFIG_RANDOMIZE_MEMORY`
* No `CONFIG_KEXEC` — prevents loading a replacement kernel from inside the VM

Option A is the default. Option B is available for deployments where the additional hardening justifies the operational cost of maintaining a custom kernel build.

### Guest OS hardening

**Read-only root filesystem.** The root filesystem is mounted read-only. Writable overlays are provided for:

* `/var` — Docker storage, logs, runtime state
* `/tmp` — temporary files
* `/home/agent/workspace` — the agent's working directory

This prevents the agent (or a compromised process) from modifying system binaries, configuration, or the Docker daemon binary.

**Agent runs as non-root.** The agent process runs as a dedicated non-root user (`agent`) that is a member of the `docker` group. This provides Docker access without root privileges.

**No CAP_NET_ADMIN.** The agent user does not have `CAP_NET_ADMIN`. This prevents the agent from reconfiguring the VM's network stack — it cannot add routes, modify iptables/nftables rules, or create network interfaces. The single default route to the gateway is immutable from the agent's perspective.

**No CAP_SYS_ADMIN.** The agent user does not have `CAP_SYS_ADMIN`. This prevents namespace manipulation, mount operations, and other privileged operations.

**dockerd runs as root.** This is required by Docker Engine. The Docker daemon is constrained by an authorization plugin (see [Inner Docker policy](#inner-docker-policy)) that restricts the agent's use of dangerous Docker features.

### Network hardening

* **Single NIC.** The VM has one network interface (virtio-net) with one default route to the gateway container.
* **No metadata service.** The IP range 169.254.169.254 is not routable from the VM. Cloud metadata services (AWS IMDS, GCP metadata, etc.) are not accessible. This prevents credential theft from the host's cloud environment.
* **vsock for control.** The control channel between the VM and the sandbox daemon uses AF_VSOCK, which is a host-guest socket family — not an IP protocol. vsock traffic does not traverse the VM's network interface and is not subject to the proxy pipeline. This separation ensures that control traffic cannot be observed or tampered with by the agent's network-facing code.
* **No IP forwarding.** IP forwarding is disabled in the guest kernel. The VM cannot act as a router.

## Gateway container

The gateway container runs the network proxy pipeline outside the VM. It is a standard Docker container using the runc runtime — no Sysbox, no elevated privileges, no DinD.

### What runs inside the gateway

* **nftables** — PREROUTING DNAT rules for forwarded traffic from the VM
* **Envoy** — original_dst listener for protocol-aware routing
* **mitmproxy** — HTTP inspection and policy enforcement
* **DNS resolver** — policy-aware resolution, query logging

These are the same components described in the networking design. The proxy pipeline's behavior — policy model, assurance levels, DNS model, SNI model, HTTP model, bypass framework — is entirely defined in that document and is not duplicated here.

### Why a gateway container

The proxy pipeline must run outside the VM so that the agent cannot tamper with it. A container is the natural deployment unit:

* **Isolation from the agent.** The gateway container is on the host side of the VM's virtual NIC. The agent has no filesystem access, no process visibility, and no control channel to the gateway.
* **Isolation from the host.** The gateway container runs in its own network namespace, filesystem, and PID namespace. It does not have access to the host's network stack or filesystem beyond what Docker provides.
* **Lifecycle management.** Docker provides well-understood primitives for starting, stopping, and removing containers. The sandbox daemon manages gateway containers alongside VMs.
* **Standard runtime.** The gateway container uses the standard runc runtime. It does not need Sysbox, elevated privileges, or any special capabilities beyond `CAP_NET_ADMIN` (required for nftables).

### Gateway security posture

The gateway container is a trusted component — it runs the sandbox operator's code (Envoy, mitmproxy, DNS resolver, nftables rules), not agent-controlled code. Its security posture is:

* Standard Docker container with default seccomp profile
* No `--privileged`
* `CAP_NET_ADMIN` only (required for nftables, dropped after rule setup where possible)
* No host network (`--network` is the per-session bridge, not `host`)
* No host PID namespace
* No host filesystem mounts beyond configuration volumes
* Read-only root filesystem with writable volumes for logs and runtime state

## Networking integration

### Per-session bridge network

Each session has a dedicated Docker bridge network that connects the gateway container to the VM's virtual NIC:

```
VM (virtio-net) ←→ Bridge network ←→ Gateway container (eth0)
```

The bridge network is created by the sandbox daemon during session creation and deleted during session destruction. Sessions do not share bridge networks — inter-session traffic is impossible at the network level.

### VM network configuration

Inside the VM:

* The single NIC receives an IP address on the bridge subnet (DHCP or static, configured during provisioning)
* The default route points to the gateway container's IP on the bridge
* `/etc/resolv.conf` points to the gateway container's DNS resolver IP
* No other routes exist — all traffic (except loopback and vsock) exits via the default route to the gateway

### Traffic flow

All agent-initiated network traffic follows this path:

```
Agent process (in VM)
  → VM kernel networking → virtio-net
    → Docker bridge → gateway container eth0
      → nftables PREROUTING DNAT
        → Envoy / mitmproxy / DNS resolver (per networking design)
          → destination (or deny)
```

Because the traffic arrives at the gateway container from the VM (forwarded traffic, not locally-generated traffic), the gateway uses nftables PREROUTING DNAT rather than OUTPUT REDIRECT. This is the only technical difference from a shared-namespace model. The policy model, assurance levels, DNS model, SNI model, HTTP model, bypass framework, fail-closed behavior, startup/shutdown ordering, health monitoring, and all other aspects described in the networking design are unchanged.

### Docker-in-VM networking

The agent's inner Docker daemon runs inside the VM and creates its own bridge networks for containers. This is standard Docker networking — the inner daemon's bridges are entirely within the VM's network namespace.

When a container inside the VM needs to reach an external service:

```
Inner container → inner Docker bridge → VM kernel NAT → VM virtio-net
  → gateway → proxy pipeline → destination
```

The inner Docker daemon's NAT translates container traffic to the VM's IP, which then follows the standard path through the gateway. The proxy pipeline sees the VM's IP as the source, not the inner container's IP. This is transparent — no special configuration is needed.

When containers inside the VM communicate with each other (e.g., `docker compose` services), traffic stays on the inner Docker bridge and never reaches the gateway. This is standard Docker behavior and is unaffected by the sandbox architecture.

## Workspace provisioning

### Repos are cloned inside the VM

Source code repositories are cloned inside the VM, not shared from the host via virtio-fs or similar mechanisms.

**Why not virtio-fs:**

* virtio-fs requires virtiofsd (a FUSE daemon) running on the host with access to the host filesystem
* virtiofsd is additional code parsing guest-controlled filesystem operations — an attack surface
* a compromised guest could exploit virtiofsd to read or write host files
* eliminating virtio-fs entirely removes this attack surface class

**Trade-off:** The initial clone takes time and network bandwidth through the proxy pipeline. For large repositories, this can be significant. Snapshot optimization (snapshot a VM after the initial clone) mitigates this for repeated use of the same repository.

### Clone mechanism

The agent (or the boot command) clones the repository using standard `git clone` through the proxy pipeline. The policy must allow HTTPS access to the git hosting service (e.g., `github.com`, `gitlab.com`) at level 3 (HTTP inspected) or level 2 (TLS-verified, for SSH-based git).

### Credential injection

Credentials for private repositories must be injected into the VM securely. This is a deferred design item — the mechanism is not yet defined. Requirements:

* Credentials must not be baked into the VM image or snapshot
* Credentials must not be accessible to the proxy pipeline (the gateway should not see git authentication tokens)
* Credentials should be scoped to specific repositories where possible
* Credentials should be ephemeral — they expire with the session

Candidate mechanisms include vsock-based credential injection, short-lived tokens generated per session, and VM cloud-init userdata. The design will be specified before implementation.

### Result extraction

Work products are extracted from the VM primarily via `git push` through the proxy pipeline. For non-git artifacts, `rsync` or `scp` over vsock provides a direct host-guest transfer path that does not traverse the proxy pipeline.

## Control channel (vsock)

### Purpose

vsock (AF_VSOCK) provides a direct communication channel between the VM and the sandbox daemon on the host. It is used for control-plane operations that should not traverse the network proxy pipeline.

### Why vsock

* **Not an IP protocol.** vsock uses its own socket address family (AF_VSOCK), not IP addresses. It does not appear on any network interface and is not subject to nftables, Envoy, or any part of the proxy pipeline.
* **Point-to-point.** vsock connects the VM directly to the host hypervisor. There is no routing, no DNS, no TLS — it is a direct channel.
* **No network tampering.** The agent cannot intercept, redirect, or modify vsock traffic by manipulating the VM's network configuration (iptables, routes, DNS). vsock operates below the IP layer.

### Use cases

* **Session status.** The sandbox daemon queries VM health, Docker daemon status, and resource utilization.
* **File transfer.** Copying files between host and VM without traversing the proxy pipeline (e.g., result extraction, credential injection).
* **SSH transport.** SSH can be tunneled over vsock, eliminating the need for IP-based SSH access to the VM.
* **Shutdown coordination.** The sandbox daemon sends graceful shutdown signals to the VM via vsock.

### Security considerations

vsock is a bidirectional channel. The agent inside the VM can initiate vsock connections to the host. The sandbox daemon must validate all incoming vsock messages and reject unexpected or malformed requests. The vsock channel should expose a minimal, well-defined API — not a general-purpose shell or command execution facility.

A compromised agent could attempt to exploit bugs in the sandbox daemon's vsock message handler. The handler must be implemented with the same defensive posture as any network service parsing untrusted input: strict message format validation, bounded message sizes, no shell injection, no path traversal.

## Inner Docker policy

### Requirement

The Docker daemon inside the VM runs as root and accepts commands from the agent via the Docker socket. Docker's authorization model is all-or-nothing — any user with socket access can perform any Docker operation. Without additional controls, the agent can:

* Run `--privileged` containers (gaining full host-equivalent capabilities inside the VM)
* Use `--network=host` (accessing the VM's network stack directly)
* Use `--pid=host` (seeing all VM processes)
* Bind-mount arbitrary VM filesystem paths
* Add arbitrary Linux capabilities

These operations are dangerous even inside a VM. A `--privileged` container inside the VM has unrestricted access to the VM's kernel, which is the same kernel that mediates the virtio device boundary. Unrestricted capabilities make QEMU exploitation easier if the guest kernel is compromised.

### Enforcement mechanism

Docker authorization plugins intercept Docker API requests and can approve or deny them based on request context. An authorization plugin on the inner dockerd will deny:

* `--privileged` flag
* `--network=host`
* `--pid=host`
* `--device` (arbitrary device access)
* Unrestricted `cap_add` (only a safe subset permitted)
* Bind mounts outside the workspace directory

### Status

The authorization plugin design and implementation are deferred. The requirement is stated here because it affects the overall security model. Until the plugin is implemented, the agent has unrestricted Docker access inside the VM. This is acceptable for initial deployment because the VM boundary provides the primary isolation — inner Docker restrictions are defense-in-depth, not the primary boundary.

## Certificate management

TLS interception by mitmproxy (inside the gateway container) requires that the agent's applications trust the interception CA. Certificate management is detailed in the networking design. The relevant integration points for this design are:

### CA generation

A unique CA keypair is generated per session at creation time. The private key is stored only in the gateway container (accessible to mitmproxy). It is never injected into the VM.

### Trust store injection

The CA certificate (public part only) is injected into the VM during provisioning:

* Installed in the system trust store (`/usr/local/share/ca-certificates/` + `update-ca-certificates`)
* Standard environment variables set: `SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE`, `NODE_EXTRA_CA_CERTS`, `CURL_CA_BUNDLE`

This provides transparent TLS interception for applications that use the system trust store or standard environment variables. Applications with certificate pinning or custom trust stores require a TLS-verified bypass (level 2) as described in the networking design.

### Docker daemon trust store

The Docker daemon inside the VM also needs to trust the interception CA for pulling images from registries over HTTPS. The CA certificate is installed in Docker's trust store (`/etc/docker/certs.d/`) during provisioning.

## Platform-specific considerations

### Linux (production, CI, EC2)

**Hypervisor:** QEMU with KVM acceleration. KVM is a kernel module that provides hardware-assisted virtualization using CPU VMX/EPT extensions. Performance is near-native for CPU-bound workloads.

**EC2 deployment:** Running QEMU/KVM inside an EC2 instance requires nested virtualization support. This is available on:

* Bare-metal instance types (e.g., `m5.metal`, `c5.metal`) — KVM runs directly on hardware
* Nitro-based instances with nested KVM support — KVM runs inside the Nitro hypervisor

Standard EC2 instances do not support nested virtualization. The sandbox cannot run on standard instances. QEMU can fall back to software emulation (TCG) on unsupported instances, but the performance penalty is prohibitive for practical use.

**Host Docker:** The host Docker daemon (which manages gateway containers) is a standard Docker installation. It does not need Sysbox or any special runtime.

### macOS (local development)

**Hypervisor:** Lima with Apple Virtualization.framework (VZ) backend. VZ provides hardware-assisted virtualization on Apple Silicon with near-native performance. On Intel Macs, Lima falls back to QEMU with Hypervisor.framework acceleration.

**VM startup time:** Approximately 10-30 seconds on Apple Silicon with VZ. Acceptable for interactive development sessions. Snapshot optimization can reduce this.

**Coexistence with Colima.** Developers who use Colima (which also uses Lima) for their day-to-day Docker workflow can continue doing so. The sandbox daemon manages its own Lima VMs with separate names, separate bridge networks, and separate lifecycle. There is no conflict — Lima supports multiple concurrent VM instances.

**Host Docker daemon.** The gateway containers require a Docker daemon on the macOS host. This is provided by Docker Desktop or Colima. The sandbox daemon uses whichever Docker daemon is available on the host.

**Feature parity.** The sandbox architecture is identical on both platforms. The only difference is the hypervisor backend. The gateway container, proxy pipeline, policy model, and session lifecycle are the same. Tests written against the sandbox on macOS will behave identically on Linux.

## Resource management

### Per-session limits

Each session is allocated bounded resources:

| Resource | Enforcement point | Notes |
|---|---|---|
| CPU | Lima VM config + QEMU cgroup | Limits total CPU available to the VM |
| Memory | Lima VM config + QEMU cgroup | Limits total memory available to the VM |
| Disk | Lima VM disk size | Fixed at creation time; not dynamically expandable |
| PIDs | QEMU cgroup | Prevents fork bombs from affecting the host |
| Network bandwidth | Gateway container cgroup (optional) | Rate limiting on the gateway's network interface |

### Host capacity

The sandbox daemon tracks host resource utilization and refuses to create new sessions when the host is at capacity. The capacity model accounts for:

* QEMU process overhead per VM (memory for device emulation, virtio buffers)
* Gateway container overhead per session (Envoy, mitmproxy, DNS resolver memory)
* Docker bridge network overhead (negligible)
* Host system reserved resources (OS, sandbox daemon, host Docker daemon)

Capacity planning guidelines are a deferred work item. Initial deployment will use conservative per-session limits and manual capacity management.

## Time synchronization

Time synchronization is a host responsibility. The VM's clock is set from the host during boot via the hypervisor's time synchronization mechanism (KVM clock on Linux, VZ clock on macOS). NTP access from within the VM is not required and is not provided through the proxy pipeline.

If clock drift becomes an issue for long-running sessions, an NTP path can be added as a level 1 (transport-only) bypass in the network policy. This is not expected to be necessary for typical session durations (minutes to hours).

## Threat model and escape analysis

### Who is the adversary

The agent process inside the VM. The agent is assumed to be:

* capable of executing arbitrary code inside the VM
* capable of gaining root inside the VM (via Docker, kernel exploits, or misconfiguration)
* capable of crafting arbitrary network traffic
* capable of crafting arbitrary device I/O to all virtio devices
* capable of crafting arbitrary vsock messages to the sandbox daemon
* knowledgeable about the sandbox architecture

The agent is not assumed to be:

* capable of physical access to the host
* capable of exploiting hardware side channels (Spectre/Meltdown) — coding agents are not crafting speculative execution exploits; this is a theoretical rather than practical risk for this threat model

### Attack surfaces ranked by practical risk

#### 1. QEMU device emulation (medium risk, mitigatable)

**What it is:** Each virtio device is implemented as code in QEMU that parses guest-controlled input. A bug in device emulation code can give the guest code execution in the QEMU process.

**Why it matters:** This is the most likely VM escape vector. QEMU device emulation has historically been a source of vulnerabilities (VENOM in 2015 targeted the floppy controller; various virtio bugs have been found and patched).

**Mitigations:**
* Minimal device model (4 devices vs. dozens in a default QEMU configuration)
* QEMU process runs as unprivileged user with seccomp, namespaces, and cgroup limits
* Even successful exploitation lands in a sandboxed process, not host root
* virtio-rng has minimal attack surface (read-only, no guest-controlled input parsing)
* virtio-vsock has a small, well-defined protocol

**Residual risk:** A vulnerability in virtio-net or virtio-blk emulation could give the guest code execution in the QEMU process. The QEMU sandboxing is the second line of defense.

#### 2. vsock protocol handler in sandboxd (medium risk, mitigatable)

**What it is:** The sandbox daemon listens on vsock for control messages from the VM. A compromised agent can send arbitrary vsock messages.

**Why it matters:** If the sandbox daemon's vsock handler has a vulnerability (buffer overflow, command injection, path traversal), the agent could compromise the daemon — which runs on the host and manages all sessions.

**Mitigations:**
* Minimal, well-defined vsock API
* Strict input validation on all messages
* No shell execution in the vsock handler
* The sandbox daemon runs as a dedicated user, not root (where possible)
* The vsock handler should be treated as an untrusted-input parser and fuzz-tested

**Residual risk:** A bug in the vsock handler could compromise the sandbox daemon. This is a high-value target because the daemon manages all sessions.

#### 3. KVM host kernel module (low risk)

**What it is:** KVM is a kernel module on the host that provides hardware-assisted virtualization. It handles VM exits, memory management, and CPU state transitions.

**Why it matters:** A vulnerability in KVM could allow a guest to execute code in the host kernel.

**Mitigations:**
* KVM is well-audited (~50K lines of code) and heavily tested
* Most historical KVM CVEs are denial of service, not code execution
* Keep the host kernel updated

**Residual risk:** A KVM code execution vulnerability would bypass all other protections. This is the highest-impact risk but also the lowest-probability one.

#### 4. Apple VZ (low risk, less audited)

**What it is:** Apple Virtualization.framework on macOS. Less public security research than KVM/QEMU.

**Why it matters:** macOS is used for local development, not production. A VZ vulnerability affects developer machines, not production infrastructure.

**Mitigations:**
* Apple's platform security model (SIP, sandboxing, notarization)
* VZ is a simpler implementation than QEMU (less code, smaller surface)
* macOS is for development only — production runs on Linux with KVM/QEMU

**Residual risk:** Less public vulnerability research means less confidence in the absence of bugs. Acceptable for developer workstations; not relied upon for production security.

#### 5. Side channels (low risk for this threat model)

**What it is:** Spectre, Meltdown, and related speculative execution attacks that can leak data across VM boundaries.

**Why it matters:** A VM on the same physical host as sensitive workloads could theoretically leak data.

**Mitigations:**
* Host kernel mitigations (retpoline, IBRS, etc.) are applied by default on modern kernels
* The sandbox does not run alongside sensitive workloads — it is a dedicated environment
* Coding agents are not crafting speculative execution exploits

**Residual risk:** Theoretical. Not a practical concern for this threat model.

### Escape chain comparison

**Container (Sysbox) escape — 1 step:**
```
Agent → syscall to shared host kernel → exploit kernel bug → host root
```

**VM (QEMU/KVM) escape — 3-4 steps:**
```
Agent → exploit guest kernel (or already root)
  → craft malicious virtio device I/O
    → trigger QEMU device emulation bug
      → land in unprivileged, sandboxed QEMU process
        → escalate from sandboxed process to host
```

The VM escape requires chaining vulnerabilities across 3-4 independent components: guest kernel, QEMU device emulation, and host privilege escalation from a sandboxed process. Each step targets different code with different security properties.

### What a fully compromised VM gives the attacker

Even with root inside the VM:

* **Cannot reach host filesystem.** No virtio-fs, no host mounts.
* **Cannot bypass proxy pipeline.** The gateway is on the host side of the virtual NIC. The agent can craft arbitrary network packets, but they all pass through the gateway.
* **Cannot communicate with other sessions.** Bridge networks are per-session. The VM cannot reach other VMs' bridge networks.
* **Cannot access cloud metadata.** 169.254.169.254 is not routable.
* **Can attempt QEMU exploitation** via crafted I/O on the 4 virtio devices.
* **Can attempt vsock exploitation** against the sandbox daemon's message handler.
* **Can consume allocated resources** (CPU, memory, disk) up to the per-session limits.
* **Can destroy their own workspace** — this is expected and acceptable for a disposable session.

## Defense in depth summary

```
Layer 1: Hardware         CPU VMX/EPT (Intel) or VHE (ARM) — enforced by silicon
Layer 2: Hypervisor       KVM (Linux) or Apple VZ (macOS) — host kernel module
Layer 3: QEMU process     Unprivileged user + seccomp + namespaces + cgroups
Layer 4: Device model     4 virtio devices only — no USB, display, legacy, virtio-fs
Layer 5: Guest kernel     Stock (default) or minimal hardened (optional)
Layer 6: Guest OS         Read-only root filesystem, writable overlay for workspace
Layer 7: Agent process    Non-root user, no CAP_NET_ADMIN, no CAP_SYS_ADMIN
Layer 8: Inner Docker     Authorization plugin denying dangerous flags (deferred)
Layer 9: Network path     Single NIC → gateway container → proxy pipeline
Layer 10: Proxy pipeline  nftables + Envoy + mitmproxy + DNS (see networking design)
Layer 11: Network policy  Abstract policy model, compiled and distributed by sandboxd
```

No single layer is assumed to be sufficient. The design goal is that any layer's failure degrades the security posture but does not result in full compromise. The most critical assumption is that hardware virtualization (layers 1-2) provides a qualitatively stronger boundary than any software-only mechanism.

## Residual risks

Even with correct implementation, the following risks remain:

* **QEMU device emulation vulnerabilities** are the most likely VM escape vector. The minimal device model and QEMU process sandboxing mitigate but do not eliminate this risk.
* **vsock handler vulnerabilities** in the sandbox daemon could be exploited by a compromised agent. The handler must be hardened as untrusted-input-facing code.
* **KVM vulnerabilities** are low-probability but high-impact. Keeping the host kernel updated is the only mitigation.
* **Stock guest kernel** has a larger attack surface than a minimal custom kernel. The default configuration accepts this trade-off for operational simplicity.
* **Inner Docker without authorization plugin** (initial deployment) means the agent has unrestricted Docker access inside the VM. This is defense-in-depth loss, not primary boundary loss.
* **Provisioning from network** means the initial VM setup depends on network access through the proxy pipeline. A supply-chain attack on provisioned packages could compromise the VM. Snapshot-based provisioning mitigates by reducing the number of times provisioning occurs.
* **Long-lived sessions** accumulate state (Docker images, files, configuration) that may include sensitive data. Destroy cleans this up, but the data exists on disk while the session is running.
* **Clock drift** in long-running sessions without NTP could affect TLS certificate validation, log correlation, and time-sensitive operations.

These are structural limitations, not implementation bugs. They define the boundary of what this sandbox can guarantee.

## Relationship to the networking design

The [networking design document](networking-design.md) defines the network-control subsystem: the proxy pipeline, policy model, assurance levels, DNS model, SNI model, HTTP model, bypass framework, fail-closed behavior, startup/shutdown ordering, health monitoring, error propagation, logging, and the sandbox daemon's policy compilation responsibilities.

This document defines the isolation boundary, VM lifecycle, and how the networking subsystem is deployed and connected.

### What changed in the networking design

The networking design originally described the proxy pipeline running inside a network namespace shared with the sandboxed process. It has been updated to describe the gateway container model used by this architecture. The only technical change was the nftables chain:

| Model | nftables chain | Traffic source |
|---|---|---|
| Shared namespace (original model) | OUTPUT REDIRECT | Locally-generated traffic |
| Gateway container (current model) | PREROUTING DNAT | Forwarded traffic from VM interface |

Everything else — policy model, assurance levels, DNS model, SNI model, HTTP model, bypass framework, component lifecycle, health monitoring, error propagation, logging — is unchanged. Both documents now describe the same gateway container deployment model.

### What this document adds

* VM as the isolation boundary (replacing the container namespace)
* Lima as the VM manager
* Gateway container as the deployment unit for the proxy pipeline
* Per-session bridge networks connecting VMs to gateways
* vsock control channel between VMs and the sandbox daemon
* VM hardening layers (device model, QEMU sandboxing, guest OS hardening)
* Workspace provisioning (clone inside VM, not shared via virtio-fs)
* Platform-specific considerations (Linux/KVM, macOS/VZ, EC2 constraints)
* Session lifecycle (create, start, stop, destroy)
* Inner Docker authorization (requirement stated, implementation deferred)

## Deferred work

The following items are identified as necessary but are not designed in this document. Each will require its own design work before implementation.

* **Credential injection for private repos.** Secure mechanism for injecting git credentials into the VM without exposing them to the proxy pipeline or baking them into snapshots.
* **Docker registry mirror/cache.** A host-side registry mirror to avoid re-pulling images in ephemeral sessions. This is a performance optimization that reduces network overhead and speeds up container starts.
* **Inner Docker authorization plugin.** Design and implementation of the Docker authorization plugin that restricts dangerous Docker operations inside the VM.
* **VM snapshot optimization.** Defining when snapshots are taken, how they are stored, when they are invalidated, and how provisioning changes propagate to snapshot-based sessions.
* **Resource limit tuning guidelines.** Recommended CPU, memory, and disk allocations for different workload profiles (small web app, large monorepo, ML/data workloads).
* **Multi-session resource management.** Host capacity planning, session scheduling, and resource contention handling when multiple sessions run concurrently.
* **Ingress connectivity.** Allowing external access to services running inside the sandbox (e.g., for webhook testing, external API callbacks). This requires extending the gateway container with reverse-proxy capabilities and defining an ingress policy model.
* **Session monitoring and alerting.** Integration with external monitoring systems for session health, resource utilization, and security events.
