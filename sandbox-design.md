# Sandbox Design for Coding AI Agents

## Status

Draft for implementation.

## Table of contents

- [Context](#context)
  - [Purpose](#purpose)
  - [Non-goals](#non-goals)
  - [Core design principles](#core-design-principles)
- [Architecture](#architecture)
  - [Architecture overview](#architecture-overview)
  - [Why VMs over containers](#why-vms-over-containers)
  - [Why Lima](#why-lima)
  - [Sandbox daemon (sandboxd)](#sandbox-daemon-sandboxd)
  - [Session lifecycle](#session-lifecycle)
  - [Failure handling](#failure-handling)
- [VM & isolation](#vm--isolation)
  - [VM specification](#vm-specification)
  - [VM hardening layers](#vm-hardening-layers)
  - [Gateway container](#gateway-container)
  - [Networking integration](#networking-integration)
  - [Inner Docker policy](#inner-docker-policy)
  - [Platform-specific considerations](#platform-specific-considerations)
  - [Time synchronization](#time-synchronization)
- [Operations](#operations)
  - [Workspace provisioning](#workspace-provisioning)
  - [Control channel (vsock)](#control-channel-vsock)
  - [Certificate management](#certificate-management)
  - [Resource management](#resource-management)
- [Security analysis](#security-analysis)
  - [Threat model and escape analysis](#threat-model-and-escape-analysis)
  - [Defense in depth summary](#defense-in-depth-summary)
  - [Residual risks](#residual-risks)
- [Deferred work](#deferred-work)

## Context

### Purpose

This document defines the **overall sandbox architecture** for running coding AI agents in isolated, disposable environments with full Docker, Docker Compose, and testcontainers capability.

The sandbox must:

* give agents a realistic local-dev experience — `docker build`, `docker compose up`, testcontainers, port binding, network creation all work as expected
* prevent agents from escaping the sandbox or accessing unauthorized resources
* prevent agents from tampering with the network policy pipeline that mediates their outbound traffic
* work on both Linux (production, CI, EC2) and macOS (local developer machines) using the same architecture
* support both ephemeral sessions (create, use, rm) and persistable sessions (stop, resume with disk state preserved)

The network-control subsystem — proxy pipeline, DNS resolver, policy model, assurance levels — is defined in the [networking design document](networking-design.md). This document covers the isolation boundary, VM lifecycle, gateway deployment model, workspace provisioning, and how the networking subsystem connects to the VM.

### Non-goals

This design does **not** cover:

* the policy language or schema — defined in the networking design
* proxy pipeline internals (Envoy filter chains, mitmproxy rules, DNS resolver implementation) — defined in the networking design
* ingress connectivity (allowing external access to services running inside the sandbox) — future enhancement
* multi-tenant scheduling or orchestration across many hosts — this design covers a single host running one or more sessions
* IDE or editor integration — the sandbox exposes SSH and vsock; how tools connect is outside scope
* Windows host support

### Core design principles

1. **Hardware isolation boundary**
   The sandbox boundary is a virtual machine, not a container. Hardware virtualization (KVM on Linux, Apple Virtualization.framework on macOS) enforces the boundary in silicon. A single kernel vulnerability cannot escape the sandbox.

2. **Untamperable network policy**
   The network proxy pipeline runs outside the VM, on the host side of the VM's virtual NIC. The agent cannot modify, bypass, or disable the pipeline because it has no access to the host or the gateway container.

3. **Minimal attack surface**
   The VM exposes the smallest possible device model. No virtio-fs (by default), no USB, no display, no legacy devices. Every device is code parsing guest-controlled input — fewer devices means fewer opportunities for exploitation.

4. **Ephemeral by default**
   Sessions are disposable. Removal (`rm`) deletes all state irrecoverably. Persistence is opt-in (stop preserves disk; resume restarts from disk state). No session accumulates long-lived trust or credentials.

5. **Cross-platform with one architecture**
   The same conceptual architecture — Lima VM + gateway container + proxy pipeline — runs on Linux and macOS. Platform differences are confined to the hypervisor backend (QEMU/KVM vs. Apple VZ) and the VM-to-gateway connectivity layer (TAP on Docker bridge vs. per-session vmnet with macvlan). The gateway container, proxy pipeline, policy model, and agent experience are identical on both platforms.

6. **Fail closed**
   If the gateway container is not running, the VM has no network connectivity. If the proxy pipeline is degraded, traffic fails — it does not bypass. The deny-by-default posture from the networking design extends to the VM boundary: no gateway means no egress.

7. **Defense in depth**
   No single layer is assumed to be perfect. The design stacks independent security mechanisms so that failure of any one layer does not result in full compromise.

## Architecture

### Architecture overview

```
Host (Linux or macOS)
├── sandboxd (one per host, manages all sessions)
│
├── Session N
│   ├── Lima VM (QEMU/KVM on Linux, Apple VZ on macOS)
│   │   ├── Agent process (root)
│   │   ├── dockerd (root, constrained by authorization plugin)
│   │   ├── Workspace (/root/workspace — cloned repo, writable)
│   │   └── Single NIC (virtio-net) → default route to gateway
│   │
│   └── Gateway container (standard Docker, runc runtime)
│       ├── nftables (PREROUTING DNAT for forwarded VM traffic)
│       ├── Envoy (original_dst listener)
│       ├── mitmproxy (HTTP inspection)
│       └── CoreDNS (policy-aware, custom plugin)
│
│   VM ←→ Gateway: per-session network (Docker bridge on Linux, dedicated vmnet on macOS)
│   VM ←→ Host: vsock (control channel, not IP — does not traverse proxy)
│
├── Session M
│   ├── Lima VM ...
│   └── Gateway container ...
│
└── Docker daemon (manages gateway containers; host Docker on Linux, sandboxd-managed Colima on macOS)
    On macOS: socket_vmnet pool (N instances, each an isolated /30 subnet)
```

#### Key structural properties

**One VM per session.** Each agent session gets its own VM with its own kernel, filesystem, and Docker daemon. Sessions cannot interact with each other.

**One gateway per session.** Each VM has a dedicated gateway container running the proxy pipeline. Gateway containers are isolated from each other via per-session networks (Docker bridges on Linux, dedicated vmnet instances on macOS).

**Two communication paths.** The VM has exactly two paths to the outside: (1) the virtual NIC, which routes through the gateway container, and (2) vsock, a direct host-guest channel used by sandboxd to connect to a listener inside the VM (connection direction is host→VM only). There are no other paths — no shared filesystems, no host mounts, no metadata services.

**Sandbox daemon is the control plane.** The sandbox daemon manages both the VM lifecycle and the gateway container lifecycle. It is the same daemon described in the networking design — extended here with VM management responsibilities.

### Why VMs over containers

The decision to use VMs rather than containers is the foundational architectural choice. It was made after evaluating container-based approaches and finding them structurally inadequate for this threat model.

#### Container escape requires one vulnerability

In a container-based sandbox (including Sysbox), the agent shares the host kernel. A single kernel vulnerability — exploitable via any of the ~300 syscalls available to the container — gives the agent host root. The attack is:

```
Agent → syscall to shared host kernel → exploit kernel bug → host root
```

This is one vulnerability, one step. The entire security model depends on the host kernel being bug-free with respect to the syscall surface exposed to the container.

#### VM escape requires chaining multiple vulnerabilities

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

#### Sysbox was evaluated and rejected

Sysbox enables Docker-in-Docker without `--privileged` by providing an alternate OCI runtime with user namespaces, virtualized `/proc`/`/sys`, and relaxed seccomp/AppArmor profiles. It was evaluated as the container-based approach (see [research report](.tasks/handoffs/chatgpt-dind.md)). It was rejected for four reasons:

1. **Blocks gVisor.** Both Sysbox and gVisor are OCI runtimes. They cannot be composed — you cannot run a Sysbox container inside gVisor or vice versa. This eliminates the possibility of adding a syscall-filtering layer.

2. **Linux-only.** Sysbox has no documented support on macOS, including inside Lima or Colima VMs. The sandbox must work on macOS developer machines. A Linux-only isolation boundary does not meet the cross-platform requirement.

3. **Wider syscall surface.** Sysbox relaxes the outer container's seccomp profile to allow `mount`, `unmount`, `pivot_root`, and other high-leverage syscalls. It also disables AppArmor for the outer container. These relaxations are necessary for DinD to function, but they widen the attack surface relative to a standard container.

4. **Shared kernel.** Regardless of Sysbox's mitigations, the fundamental problem remains: the agent and the host share a kernel. The mitigations reduce risk; they do not change the structural property that one kernel bug is sufficient for escape.

#### gVisor was evaluated and rejected

gVisor intercepts syscalls in userspace and implements a subset of the Linux kernel API, providing a strong syscall-filtering boundary. It has an official Docker-in-gVisor tutorial. It was rejected for one reason:

**gVisor requires `--iptables=false` on the inner dockerd.** Without iptables, Docker cannot perform port mapping (`-p` flag). Without port mapping, testcontainers' port discovery mechanism breaks. Testcontainers is a non-negotiable requirement. This is not a configuration issue — it is a fundamental incompatibility between gVisor's network stack and Docker's port mapping implementation.

#### Firecracker and Cloud Hypervisor were evaluated and rejected

Firecracker (AWS) and Cloud Hypervisor provide microVM-based isolation with sub-second boot times and extreme density. They were rejected for one reason:

**KVM-only.** Both require KVM, which means Linux-only. They do not run on macOS. Lima with QEMU provides the same hardware isolation boundary (both use KVM on Linux) with the addition of Apple VZ support on macOS. Firecracker's advantages — sub-second boot, thousands of VMs per host — are optimizations for short-lived serverless functions. Agent sessions are long-lived (minutes to hours). The boot time difference (sub-second vs. 10-30 seconds) is not meaningful for this use case.

#### Industry validation

The VM-over-container choice aligns with the direction of the industry:

* Gitpod moved from Kubernetes containers to VMs (Firecracker)
* GitHub Codespaces uses VMs
* Docker Sandboxes (January 2026) uses microVMs
* Fly.io and Sprites use Firecracker

These projects reached the same conclusion independently: for isolation of untrusted or semi-trusted workloads, VMs provide a qualitatively stronger boundary than containers.

### Why Lima

Lima (Linux Machines) is a CNCF incubating project that manages Linux VMs on macOS and Linux. It provides a single CLI (`limactl`) that abstracts the hypervisor backend.

#### Selection criteria

| Requirement | Lima |
|---|---|
| Cross-platform (Linux + macOS) | QEMU/KVM on Linux, Apple VZ on macOS |
| Docker inside VM | Provisioned via templates; first-class use case |
| Programmatic API | CLI (`limactl`) + YAML templates |
| Community and maintenance | CNCF incubating, active development |
| AI sandbox support | v2.0 added agent sandboxing as first-class use case |
| Snapshot support | VM snapshots for fast cold starts |
| vsock support | Supported for host-guest communication |

#### What Lima provides

* VM creation from YAML templates with cloud-init provisioning
* Automatic hypervisor selection (QEMU with KVM on Linux, VZ on macOS)
* SSH access to VMs via `limactl shell`
* File sharing (disabled in this design — repos cloned inside VM)
* Port forwarding (automatic forwarding disabled; sandboxd uses selective, controlled forwarding for specific control paths)
* VM snapshot and restore

#### What Lima does not provide

* Network policy enforcement — handled by the gateway container
* Docker authorization plugins — handled inside the VM (defense-in-depth against untrusted code running dangerous Docker operations — see [Inner Docker policy](#inner-docker-policy))
* Multi-host orchestration — handled by external tooling
* Gateway container management — handled by the sandbox daemon

Lima is the VM lifecycle manager. The sandbox daemon wraps Lima with policy enforcement, gateway management, and session lifecycle.

### Sandbox daemon (sandboxd)

The sandbox daemon is a single process per host that manages all sandbox sessions. It is the same daemon described in the networking design — that document covers its role in policy compilation and distribution. This document covers its role in VM and gateway lifecycle management.

#### Responsibilities

**Session lifecycle:**

* create, start, stop, and remove sessions
* manage Lima VM instances (create, start, stop, delete)
* manage gateway containers (create, start, stop, remove)
* manage per-session networks (Docker bridges on Linux, vmnet pool on macOS)
* coordinate VM and gateway startup/shutdown ordering

**Policy management** (as defined in the networking design):

* accept abstract policy documents
* compile policy into component-specific configurations
* distribute configuration to gateway container components
* manage DNS re-resolution and IP propagation
* validate policy documents against declared schema versions

**Control channel:**

* initiate vsock connections to VM-side listeners for control operations
* authenticate and validate all data received from VM-side listeners
* expose session status and health information

**Resource management:**

* enforce per-session resource limits (CPU, memory, disk)
* monitor host capacity
* report resource utilization per session

#### Daemon lifecycle

The sandbox daemon starts before any sessions exist and persists across session lifecycles. It is a long-lived process, not a per-session process. On restart, it recovers state from Lima's VM inventory and Docker's container inventory — both are durable and survive daemon restarts.

#### API surface

The sandbox daemon exposes a local API over a Unix socket with HTTP semantics. This API is used by CLI tools and orchestration layers. macOS supports Unix sockets; no platform-specific transport is needed.

```
sandboxd create [--name <name>] [--template <path>] [--policy <path>] [--boot-cmd <cmd>]
sandboxd start <session>
sandboxd stop <session>
sandboxd rm <session>
sandboxd ps
sandboxd ls
sandboxd ssh <session>
sandboxd cp <session>:<path> <local-path>   # or reverse
sandboxd policy update <session> <policy-path>
sandboxd logs <session> [--component <name>]
```

Sessions can be referenced by ID or by name. `--name` is optional on create; if omitted, only the generated ID is available. The CLI verbs mirror Docker's API (`ps`, `ls`, `rm`, `cp`) so the interface is familiar to developers.

### Session lifecycle

#### Create

`sandboxd create` performs the following steps in order:

1. **Allocate session ID.** Generate a unique session identifier.
2. **Provision per-session network.** On Linux, create a per-session Docker bridge network. On macOS, claim a vmnet slot from the pre-provisioned pool (see [networking-design.md § VM-to-gateway connectivity](networking-design.md#vm-to-gateway-connectivity)). Each session gets a /30 subnet (2 usable IPs: gateway + VM).
3. **Create gateway container.** A standard Docker container (runc runtime) attached to the session's network (on macOS, inside the sandboxd-managed Colima instance). The container runs the proxy pipeline components (Envoy, mitmproxy, DNS resolver) but does not start them yet. nftables rules are injected by sandboxd from outside the container.
4. **Start the gateway pipeline.** Start the proxy pipeline inside the gateway container using the startup ordering defined in the networking design (nftables deny-by-default first, redirect rules last).
5. **Create Lima VM.** Instantiate a VM from the Lima template. The VM's network interface is connected to the session's network. The VM's default route points to the gateway container's IP on the /30 subnet.
6. **Provision the VM.** Cloud-init and provisioning scripts install Docker, agent tooling, and hardening configuration inside the VM. The gateway pipeline is already operational, so cloud-init has network access through the proxy.
7. **Start the VM.** Boot the VM. At this point, the VM has network connectivity through the gateway, mediated by the proxy pipeline.
8. **Run boot command (optional).** If `--boot-cmd` was specified, execute it inside the VM after startup completes. This is typically used to clone a repository or start an agent process.

The VM has no network connectivity until the gateway pipeline is fully operational. This is intentional — the pipeline must be ready before traffic can flow.

#### Start

`sandboxd start <session>` resumes a previously stopped session:

1. Recreate per-session network. On Linux, create a Docker bridge with the session's deterministic /30 subnet. On macOS, claim a vmnet slot from the pool. Stopped sessions hold no network resources.
2. Create and start the gateway container and pipeline (same as create steps 3-4).
3. Start the Lima VM (boots from preserved disk state).
4. Reconnect networking (VM's default route to gateway).

Processes that were running when the session was stopped are not restored — there are no memory snapshots. Only disk state persists. The Docker daemon inside the VM starts fresh, but previously pulled images and created volumes remain on disk.

#### Stop

`sandboxd stop <session>` gracefully stops a session:

1. Shut down the proxy pipeline inside the gateway container (reverse of startup ordering — redirect rules removed first, deny-by-default last, as defined in the networking design).
2. Shut down the Lima VM. The VM's disk state is preserved.
3. Stop and remove the gateway container.
4. Tear down the per-session network. On Linux, remove the Docker bridge. On macOS, release the vmnet slot back to the pool. Stopped sessions hold no network resources — bridges and slots are recreated on start.

The session's disk image remains. The session can be resumed with `start`.

#### Remove

`sandboxd rm <session-id>` irrecoverably deletes a session:

1. Stop the session if running (same as `stop`).
2. Delete the Lima VM and its disk image.
3. Remove the gateway container (if not already removed by `stop`).
4. Release the per-session network. On Linux, remove the Docker bridge network. On macOS, release the vmnet slot back to the pool (if not already released by `stop`).

All state is deleted. This cannot be undone.

#### SSH

`sandboxd ssh <session>` opens an SSH connection to the VM over vsock. No IP path is involved — the connection does not traverse the proxy pipeline. SSH is a control path at the same trust level as vsock — it is not exposed on the network and is not accessible to other sessions or external parties.

#### Status

`sandboxd ps` lists sessions with their state. `sandboxd ls` provides a compact listing. Both report per-session:

* VM state (running, stopped, creating, error)
* Gateway state (running, stopped, error)
* Pipeline health (per-component, as defined in the networking design)
* Resource utilization (CPU, memory, disk)
* Policy version in effect

### Failure handling

sandboxd must handle partial failures gracefully. Sessions involve multiple resources (VM, gateway container, per-session network, disk images) that can fail independently.

#### Partial session creation

If sandboxd crashes mid-create, resources may be left in an inconsistent state — a network bridge without a gateway, a VM without a network. On restart, sandboxd reconciles desired state (from its persistent session store) against actual state (Docker containers, Lima VMs, network bridges). Orphaned resources that don't belong to any known session are torn down. Sessions that failed mid-creation are marked as `error` and their partial resources are cleaned up.

#### Gateway container crash

If the gateway container exits, the VM loses all network connectivity. sandboxd detects this via Docker container events and restarts the gateway on the same per-session network with the same IP. The VM does not need reconfiguration — its default route and DNS already point to the gateway's fixed IP on the /30 subnet. Active TCP connections inside the VM will break; new connections resume once the gateway is back.

#### VM process exit

If the QEMU or Lima process dies unexpectedly, sandboxd marks the session as `error`. The workspace disk image is preserved so the user can inspect results or retry. The gateway container and per-session network are left in place until the session is explicitly removed (`sandboxd rm`), allowing forensic inspection of network state.

#### sandboxd crash and restart

sandboxd persists session metadata before creating resources. On restart, it:

1. Loads all known sessions from persistent storage.
2. Enumerates actual resources (Docker containers, Lima VMs, networks).
3. For each known session, checks whether its resources are intact. Intact sessions are resumed (state set to `running` or `stopped` as appropriate).
4. Resources not associated with any known session are orphans — torn down.
5. Sessions whose resources are partially missing are marked `error` for operator review.

#### Colima crash (macOS)

On macOS, all gateway containers run inside a sandboxd-managed Colima instance. If Colima crashes, every gateway container is lost simultaneously. sandboxd detects this, restarts Colima, and recreates the gateway containers for all active sessions. See the networking design for details on Colima failure modes and recovery.

## VM & isolation

### VM specification

#### Lima template

Each VM is created from a Lima YAML template that specifies:

* base image (stock Ubuntu cloud image)
* CPU, memory, and disk allocation
* hypervisor backend (auto-detected: QEMU/KVM on Linux, VZ on macOS)
* network configuration (per-session network to gateway)
* vsock enablement
* provisioning scripts (cloud-init)
* disabled features: file sharing disabled by default (virtio-fs available as opt-in for shared mount mode), automatic port forwarding (sandboxd manages selective forwarding for control paths)

#### Base image

The default base is a stock Ubuntu cloud image — a known, upstream-maintained artifact. All customization is performed via cloud-init provisioning during `create`. Pre-built images (snapshots from a previous provisioning run) are an optional alternative for environments that cannot allow any egress during provisioning (air-gapped deployments, strict compliance). No dedicated image build pipeline is required — `sandboxd create` with provisioning followed by a snapshot produces the pre-built image.

#### Provisioning

Cloud-init provisioning installs and configures:

* Docker Engine (CE) and Docker Compose plugin
* Root environment for the agent (workspace directory, shell configuration)
* SSH authorized keys for root (for `sandboxd ssh`)
* System hardening (see [VM hardening layers](#vm-hardening-layers))
* Interception CA certificate in the system trust store and standard environment variables (`SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE`, `NODE_EXTRA_CA_CERTS`, `CURL_CA_BUNDLE`)
* DNS configuration (`resolv.conf` pointing to the gateway's DNS resolver)

Provisioning is a **trusted setup phase** — only our controlled cloud-init scripts run, no agent code executes. Fresh provisioning requires network access to package repositories (Ubuntu mirrors, Docker APT repos, GPG key servers) that the production network policy does not permit. During initial image preparation, cloud-init runs under a permissive bootstrap network policy that allows access to these package sources. The snapshot captures the fully provisioned state, so production sessions created from snapshots never need this wider access. The bootstrap policy is only active during image preparation and is never applied to agent sessions.

#### Snapshot optimization

Provisioning a VM from scratch takes time (package installation, Docker setup). For fast cold starts, the sandbox daemon can snapshot a provisioned VM and use the snapshot as the base for new sessions. This amortizes provisioning cost across sessions.

Snapshot management is a performance optimization, not a security boundary. Snapshots must be re-provisioned when the base image, provisioning scripts, or security configuration changes.

### VM hardening layers

#### Device model

The VM exposes the minimal set of virtio devices required for operation:

| Device | Purpose | Attack surface |
|---|---|---|
| virtio-net | Networking (routed through gateway) | Network packet parsing |
| virtio-blk | Root disk (VM image) | Block I/O protocol |
| virtio-rng | Entropy (/dev/urandom seeding for SSH keys, TLS, etc.) | Minimal — read-only, no guest-controlled input parsing |
| virtio-vsock | Host-guest control channel | vsock protocol parsing |

**Not present:** USB controller, display adapter, sound device, floppy controller, legacy ISA devices, virtio-fs (available as opt-in for shared mount mode; see [Workspace provisioning](#workspace-provisioning)), virtio-serial, PCI passthrough, GPU.

Every device in the VM's device model is code in QEMU (or VZ) that parses guest-controlled input. The guest kernel and any guest process can craft arbitrary device I/O. Each device is therefore an attack surface. The security value of a minimal device model is linear — fewer devices means fewer independent targets for exploitation.

#### QEMU process hardening (Linux)

On Linux, the QEMU process that backs each VM is sandboxed at the host level:

* **Unprivileged user.** QEMU runs as a dedicated non-root user with no special capabilities.
* **Seccomp.** QEMU's built-in seccomp sandbox is enabled: `-sandbox on,obsolete=deny,elevateprivileges=deny,spawn=deny`. This denies obsolete syscalls, prevents privilege escalation, and prevents QEMU from spawning child processes.
* **Namespaces.** The QEMU process runs in its own mount, PID, and IPC namespaces. It cannot see or interact with other host processes.
* **No host filesystem access.** QEMU has access only to the VM's disk image file. No host directories are mounted into the QEMU process.
* **Cgroup limits.** The QEMU process is placed in a cgroup with CPU, memory, and PID limits. A compromised QEMU process cannot exhaust host resources.

On macOS, Apple Virtualization.framework provides equivalent isolation through the platform's own sandboxing mechanisms. The VZ process runs in a macOS sandbox profile with restricted entitlements.

#### Guest kernel

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

#### Guest OS hardening

**Writable root filesystem.** The root filesystem is writable. Agents can install packages, modify system configuration, and install global tools — the same workflow a developer would use on a local machine. The VM is disposable; any modifications are discarded when the session is destroyed. Security is enforced by the VM boundary (hardware isolation) and the gateway pipeline (network control), not by filesystem permissions inside the guest. Resource limits (CPU, memory, disk) prevent abuse of writable storage.

**Agent runs as root.** The agent process runs as root inside the VM. This is a deliberate design choice — the VM boundary (hardware isolation) and gateway pipeline (topological enforcement) provide the security properties, not the agent's privilege level inside the VM. Running as non-root would add usability barriers (package installation, system configuration, Docker operations, global tool installation) without improving the security posture. Operators can optionally configure a non-root agent user as a defense-in-depth measure against hypothetical VM escape exploits.

**dockerd runs as root.** This is required by Docker Engine. The Docker daemon is constrained by an authorization plugin (see [Inner Docker policy](#inner-docker-policy)) that restricts the agent's use of dangerous Docker features.

#### Network hardening

* **Single NIC.** The VM has one network interface (virtio-net) with one default route to the gateway container.
* **No metadata service.** The IP range 169.254.169.254 is not routable from the VM. Cloud metadata services (AWS IMDS, GCP metadata, etc.) are not accessible. This prevents credential theft from the host's cloud environment.
* **vsock for control.** The control channel between the VM and the sandbox daemon uses AF_VSOCK, which is a host-guest socket family — not an IP protocol. vsock traffic does not traverse the VM's network interface and is not subject to the proxy pipeline. This separation ensures that control traffic cannot be observed or tampered with by the agent's network-facing code.
* **Single-homed networking.** The VM has one external network interface with one default route to the gateway. Docker enables `net.ipv4.ip_forward=1` inside the VM for its internal bridge networking. This has no security implication because the VM has no second interface to forward traffic to — it cannot act as a router. Even with root privileges, creating additional virtual interfaces inside the VM does not change this: all traffic still exits through the single virtio-net NIC to the gateway. IPv6 is not enabled inside the VM.

### Gateway container

The gateway container runs the network proxy pipeline outside the VM. It is a standard Docker container using the runc runtime — no Sysbox, no elevated privileges, no DinD.

#### What runs inside the gateway

* **nftables** — PREROUTING DNAT rules for forwarded traffic from the VM
* **Envoy** — original_dst listener for protocol-aware routing
* **mitmproxy** — HTTP inspection and policy enforcement
* **CoreDNS** (with a custom policy plugin) — policy-aware resolution, query logging

These are the same components described in the networking design. The proxy pipeline's behavior — policy model, assurance levels, DNS model, SNI model, HTTP model, bypass framework — is entirely defined in that document and is not duplicated here.

#### Why a gateway container

The proxy pipeline must run outside the VM so that the agent cannot tamper with it. A container is the natural deployment unit:

* **Isolation from the agent.** The gateway container is on the host side of the VM's virtual NIC. The agent has no filesystem access, no process visibility, and no control channel to the gateway.
* **Isolation from the host.** The gateway container runs in its own network namespace, filesystem, and PID namespace. It does not have access to the host's network stack or filesystem beyond what Docker provides.
* **Lifecycle management.** Docker provides well-understood primitives for starting, stopping, and removing containers. The sandbox daemon manages gateway containers alongside VMs.
* **Standard runtime.** The gateway container uses the standard runc runtime. It does not need Sysbox, elevated privileges, or any special capabilities beyond Docker's defaults.
* **Same image everywhere.** The gateway container runs the same image on both platforms. The connectivity layer differs between Linux and macOS (see [networking-design.md § VM-to-gateway connectivity](networking-design.md#vm-to-gateway-connectivity)); the gateway image, proxy pipeline, and policy enforcement are identical.

#### Gateway security posture

The gateway container is a trusted component — it runs the sandbox operator's code (Envoy, mitmproxy, DNS resolver), not agent-controlled code. nftables rules in the gateway's network namespace are managed by sandboxd from outside the container (via `nsenter` or `docker exec`). Its security posture is:

* Standard Docker container with default seccomp profile
* No `--privileged`
* No additional capabilities — the gateway runs with Docker's default capability set
* No host network (`--network` is the per-session network — Docker bridge on Linux, macvlan on the session's vmnet on macOS — not `host`)
* No host PID namespace
* No host filesystem mounts beyond configuration volumes
* Read-only root filesystem with writable volumes for logs and runtime state

### Networking integration

#### Per-session network

Each session has a dedicated network that connects the gateway container to the VM's virtual NIC:

```
VM (virtio-net) ←→ Per-session network ←→ Gateway container (eth0)
```

On Linux, this is a Docker bridge network created during session creation and deleted during session removal. On macOS, this is a dedicated socket_vmnet instance claimed from a pre-provisioned pool at session start and released at session stop. Both platforms use /30 subnets (2 usable IPs: gateway + VM) carved from a configurable base range (default `10.209.0.0/24`). Sessions do not share network segments — inter-session traffic is impossible at the network level. See [networking-design.md § Per-session network](networking-design.md#per-session-network) for full details.

#### VM network configuration

Inside the VM:

* The single NIC receives an IPv4 address on the /30 subnet (DHCP or static, configured during provisioning). No IPv6 addresses are assigned — the networking subsystem is IPv4-only.
* The default route points to the gateway container's IP on the /30 subnet
* `/etc/resolv.conf` points to the gateway container's DNS resolver IP
* No other routes exist — all traffic (except loopback and vsock) exits via the default route to the gateway

#### VM-to-gateway connectivity

The mechanism that connects the sandbox VM to its gateway container differs between Linux and macOS, but both achieve the same result: the VM has a single NIC with a default route pointing at the gateway container's IP, and traffic arrives at the gateway with original destination intact so that PREROUTING DNAT works correctly.

* **Linux:** Per-session Docker bridge network. The VM's QEMU TAP device and the gateway container attach to the same bridge — direct L2 connectivity.
* **macOS:** Per-session vmnet pool. sandboxd pre-provisions a pool of socket_vmnet instances at daemon startup, each with its own /30 subnet. At session start, a vmnet slot is claimed, a Colima NIC is attached, and the gateway container uses macvlan on that NIC. Each session is fully L2-isolated — the same property as Linux's per-session bridges.

For the full platform-specific connectivity explanation, including architecture diagrams, see [networking-design.md § VM-to-gateway connectivity](networking-design.md#vm-to-gateway-connectivity).

#### Docker-in-VM networking

The agent's inner Docker daemon runs inside the VM and creates its own bridge networks for containers. This is standard Docker networking — the inner daemon's bridges are entirely within the VM's network namespace.

When a container inside the VM needs to reach an external service:

```
Inner container → inner Docker bridge → VM kernel NAT → VM virtio-net
  → gateway → proxy pipeline → destination
```

The inner Docker daemon's NAT translates container traffic to the VM's IP, which then follows the standard path through the gateway. The proxy pipeline sees the VM's IP as the source, not the inner container's IP. This is transparent — no special configuration is needed.

When containers inside the VM communicate with each other (e.g., `docker compose` services), traffic stays on the inner Docker bridge and never reaches the gateway. This is standard Docker behavior and is unaffected by the sandbox architecture.

### Inner Docker policy

#### Requirement

The Docker daemon inside the VM runs as root and accepts commands from the agent via the Docker socket. Docker's authorization model is all-or-nothing — any user with socket access can perform any Docker operation. Without additional controls, the agent can:

* Run `--privileged` containers (gaining full host-equivalent capabilities inside the VM)
* Use `--network=host` (accessing the VM's network stack directly)
* Use `--pid=host` (seeing all VM processes)
* Bind-mount arbitrary VM filesystem paths
* Add arbitrary Linux capabilities

These operations are dangerous even inside a VM. The primary concern is defense-in-depth against untrusted code that the agent runs — malicious dependencies, compromised packages, or generated scripts. A `--privileged` inner container gives such code unrestricted kernel access within the VM, making lateral movement and exploitation easier. It also weakens the VM boundary: unrestricted capabilities on the VM's kernel (the same kernel that mediates the virtio device boundary) make QEMU exploitation more feasible if the guest kernel is compromised.

#### Enforcement mechanism

Docker authorization plugins intercept Docker API requests and can approve or deny them based on request context. An authorization plugin on the inner dockerd will deny:

* `--privileged` flag
* `--network=host`
* `--pid=host`
* `--device` (arbitrary device access)
* Unrestricted `cap_add` (only a safe subset permitted)
* Bind mounts outside the workspace directory

The plugin must intercept all container lifecycle operations — `create`, `run`, `start`, and `update` — not just creation-time requests. Without this, a container created before the plugin is active (or during any enforcement gap) could be started later with previously granted privileged settings, bypassing all restrictions.

#### Status

The authorization plugin design and implementation are deferred. The requirement is stated here because it affects the overall security model. Until the plugin is implemented, the agent has unrestricted Docker access inside the VM. This is acceptable for initial deployment because the VM boundary provides the primary isolation — inner Docker restrictions are defense-in-depth, not the primary boundary.

### Platform-specific considerations

#### Linux (production, CI, EC2)

**Hypervisor:** QEMU with KVM acceleration. KVM is a kernel module that provides hardware-assisted virtualization using CPU VMX/EPT extensions. Performance is near-native for CPU-bound workloads.

**EC2 deployment:** Running QEMU/KVM inside an EC2 instance requires nested virtualization support. This is available on:

* Bare-metal instance types (e.g., `m5.metal`, `c5.metal`) — KVM runs directly on hardware
* Nitro-based virtual instances with nested KVM support — currently C8i, M8i, and R8i families (Intel Xeon 6). AWS expanded nested virtualization to virtual instances in February 2026.

Graviton (ARM) instances do not support nested KVM. On unsupported instance types, QEMU can fall back to software emulation (TCG), but the performance penalty is prohibitive for practical use.

**Host Docker:** The host Docker daemon (which manages gateway containers) is a standard Docker installation. It does not need Sysbox or any special runtime.

#### macOS (local development)

**Hypervisor:** Lima with Apple Virtualization.framework (VZ) backend. VZ provides hardware-assisted virtualization on Apple Silicon with near-native performance. On Intel Macs, Lima falls back to QEMU with Hypervisor.framework acceleration.

**VM startup time:** Approximately 10-30 seconds on Apple Silicon with VZ. Acceptable for interactive development sessions. Snapshot optimization can reduce this.

**socket_vmnet pool (required dependency).** sandboxd pre-provisions a pool of socket_vmnet instances at daemon startup on macOS. Each instance is an isolated L2 segment with its own /30 subnet. The pool size is configurable (`max_concurrent_sessions_macos`, default 8). Only running sessions consume pool slots — stopped or created-but-not-started sandboxes do not. If the pool is exhausted, session start is rejected with a clear error; there is no silent degradation. socket_vmnet is open-source (Apache 2.0 license) and is the standard Lima mechanism for shared networking on macOS. See [networking-design.md § VM-to-gateway connectivity](networking-design.md#vm-to-gateway-connectivity) for the full explanation.

**sandboxd-managed Colima instance.** On macOS, sandboxd manages its own Colima instance to host all gateway containers. This is necessary because Docker on macOS runs inside a Linux VM, and sandbox VMs cannot attach TAP devices to Docker bridges that exist inside another VM. At session start, a Colima NIC is attached to the claimed vmnet slot and the gateway container uses macvlan (private mode) on that NIC. At session stop, the gateway container is destroyed and the NIC is detached. See [networking-design.md § VM-to-gateway connectivity](networking-design.md#vm-to-gateway-connectivity) for how the networking works.

This Colima instance is completely independent of the developer's Docker setup:

* Developers using Docker Desktop continue using Docker Desktop for their own work
* Developers using their own Colima instance continue using it — sandboxd's Colima has a separate instance name, separate data directory, and separate lifecycle
* Two Docker daemons coexist without conflict on macOS — they run in separate VMs with separate sockets. sandboxd's Colima instance uses a non-default socket path (e.g., `~/.sandboxd/colima/docker.sock`) to avoid conflict with the developer's existing Docker Desktop or Colima installation.
* Colima is free/open-source (MIT license), Lima-based, and architecturally aligned with the sandbox's use of Lima for sandbox VMs

The developer never interacts with sandboxd's Colima instance directly. sandboxd manages its lifecycle (starting it on first session creation, stopping it when the last session is removed or on daemon shutdown).

**Coexistence with developer Lima VMs.** Developers who use Lima directly (outside Colima) for other purposes can continue doing so. The sandbox daemon manages its own Lima VMs with separate names and separate lifecycle. There is no conflict — Lima supports multiple concurrent VM instances.

**Feature parity.** The sandbox architecture is identical on both platforms. The differences are confined to the hypervisor backend (QEMU/KVM vs. Apple VZ) and the VM-to-gateway connectivity layer (TAP on Docker bridge vs. per-session vmnet with macvlan — see [networking-design.md § VM-to-gateway connectivity](networking-design.md#vm-to-gateway-connectivity)). Both platforms achieve the same isolation property: each session gets its own L2 segment with a /30 subnet. The gateway container image, proxy pipeline, policy model, and session lifecycle are the same. Tests written against the sandbox on macOS will behave identically on Linux.

### Time synchronization

Time synchronization is a host responsibility. The VM's clock is set from the host during boot via the hypervisor's time synchronization mechanism (KVM clock on Linux, VZ clock on macOS). NTP access from within the VM is not required and is not provided through the proxy pipeline.

If clock drift becomes an issue for long-running sessions, an NTP path can be added as a level 1 (transport-only) bypass in the network policy. This is not expected to be necessary for typical session durations (minutes to hours).

## Operations

### Workspace provisioning

#### Workspace transfer modes

There are three ways to get code into and out of the VM, each with different trade-offs:

**Clone inside the VM (default).** The agent (or the boot command) clones the repository using `git clone` through the proxy pipeline. The policy must allow HTTPS access to the git hosting service (e.g., `github.com`, `gitlab.com`) at level 3 (HTTP inspected) or level 1 (transport-only, for SSH-based git; protocol: TCP). Work products are extracted via `git push` through the proxy pipeline.

**Git remote over vsock.** sandboxd exposes the VM-side repository as a git remote on the host. The developer can `git pull` the agent's work or `git push` branches into the VM — bidirectional, standard git workflow. The git protocol runs over vsock, not IP: no proxy pipeline traversal, no network exposure. sandboxd mediates the connection and validates VM-side paths to prevent path traversal. This is the recommended mode for local development — less messy than file copy, no shared mount needed.

**Shared mount (opt-in, local dev only).** virtio-fs exposes a host directory inside the VM. The agent works directly on the host filesystem. This is the most convenient mode for multi-session or multi-agent workflows on the same repository but has security implications: virtiofsd (a FUSE daemon) runs on the host parsing guest-controlled filesystem operations, and a compromised guest could exploit it to read or write host files. Use only when the convenience outweighs the additional attack surface.

For non-git artifacts, `sandboxd cp` provides direct host-guest file transfer over vsock (rsync under the hood). This does not traverse the proxy pipeline.

#### Credential injection

Credentials for private repositories must be injected into the VM securely. This is a deferred design item — the mechanism is not yet defined. Requirements:

* Credentials must not be baked into the VM image or snapshot
* Credentials should be scoped to specific repositories where possible
* In production/CI: credentials should be ephemeral — short-lived tokens generated per session that expire when the session ends
* In local dev: long-lived personal tokens are the practical reality. The sandbox does not prevent their use but operators should be aware of the exposure

Candidate mechanisms include vsock-based credential injection, short-lived tokens generated per session, and VM cloud-init userdata. A future enhancement is proxy-level credential replacement — the agent uses dummy tokens, and the gateway swaps them for real credentials on egress. This keeps real credentials out of the VM entirely but requires protocol-aware token injection (deferred).

#### Result extraction

For git repositories, extraction uses `git push` (through the proxy pipeline) or `git pull` from the host (over the vsock git remote). For non-git artifacts, `sandboxd cp` transfers files over vsock.

### Control channel (vsock)

#### Purpose

vsock (AF_VSOCK) provides a direct communication channel between the VM and the sandbox daemon on the host. It is used for control-plane operations that should not traverse the network proxy pipeline.

#### Why vsock

* **Not an IP protocol.** vsock uses its own socket address family (AF_VSOCK), not IP addresses. It does not appear on any network interface and is not subject to nftables, Envoy, or any part of the proxy pipeline.
* **Point-to-point.** vsock connects the VM directly to the host hypervisor. There is no routing, no DNS, no TLS — it is a direct channel.
* **No network tampering.** The agent cannot intercept, redirect, or modify vsock traffic by manipulating the VM's network configuration (iptables, routes, DNS). vsock operates below the IP layer.

#### Connection direction

Connection direction is **host→VM only.** sandboxd initiates all vsock connections to a listener provisioned inside the VM. The VM cannot open vsock connections back to the host — sandboxd does not bind a vsock listener, so there is nothing for the VM to connect to. This eliminates unsolicited inbound connections, but does not eliminate attack surface: a compromised agent can replace or tamper with the VM-side listener and send crafted responses when sandboxd connects. sandboxd must treat all data received over vsock as untrusted input.

The VM-side listener is a minimal, purpose-built daemon provisioned during VM creation. It accepts connections from the host and responds to control-plane requests.

#### Use cases

* **Session status.** The sandbox daemon connects to the VM-side listener and queries VM health, Docker daemon status, and resource utilization.
* **File transfer.** Copying files between host and VM without traversing the proxy pipeline (e.g., result extraction, credential injection).
* **SSH transport.** SSH can be tunneled over vsock, eliminating the need for IP-based SSH access to the VM.
* **Shutdown coordination.** The sandbox daemon connects to the VM-side listener and sends graceful shutdown signals.

#### Security considerations

The primary attack vector is sandboxd connecting to a malicious or compromised VM-side listener that sends crafted responses. A compromised agent can replace or tamper with the VM-side listener and return adversarial data in response to sandboxd's requests. sandboxd must treat all data received from the VM-side listener as untrusted input: strict response format validation, bounded message sizes, no shell injection, no path traversal.

**Per-session handler isolation.** sandboxd forks a handler process per session with minimal privileges. The main daemon communicates with forked handlers via a restricted internal channel. A compromised handler — whether from a malicious VM-side response exploiting a parsing bug or any other cause — affects only that session. It cannot access other sessions' state, other handlers' memory, or the main daemon's control structures.

This is the highest-risk custom code in the system. Unlike QEMU/KVM, which are battle-tested by a large community, the vsock protocol handler is private code parsing untrusted input over the most direct host-guest communication channel. It must be implemented with the same defensive posture as any network service facing the internet, and fuzz-tested against adversarial inputs.

### Certificate management

TLS interception by mitmproxy (inside the gateway container) requires that the agent's applications trust the interception CA. Certificate management is detailed in [networking-design.md § Certificate management](networking-design.md#certificate-management). The relevant integration points for this design are:

#### CA generation

A unique CA keypair is generated per session at creation time. The private key is stored only in the gateway container (accessible to mitmproxy). It is never injected into the VM.

#### Trust store injection

The CA certificate (public part only) is injected into the VM during provisioning:

* Installed in the system trust store (`/usr/local/share/ca-certificates/` + `update-ca-certificates`)
* Standard environment variables set: `SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE`, `NODE_EXTRA_CA_CERTS`, `CURL_CA_BUNDLE`

This provides transparent TLS interception for applications that use the system trust store or standard environment variables. Applications with certificate pinning or custom trust stores require a TLS-verified bypass (level 2) as described in the networking design.

#### Docker daemon trust store

The Docker daemon inside the VM also needs to trust the interception CA for pulling images from registries over HTTPS. The CA certificate is installed in Docker's trust store (`/etc/docker/certs.d/`) during provisioning.

### Resource management

#### Per-session limits

Each session is allocated bounded resources:

| Resource | Enforcement point | Notes |
|---|---|---|
| CPU | Lima VM config + QEMU cgroup | Limits total CPU available to the VM |
| Memory | Lima VM config + QEMU cgroup | Limits total memory available to the VM |
| Disk | Lima VM disk size | Fixed at creation time; not dynamically expandable |
| PIDs | QEMU cgroup | Prevents fork bombs from affecting the host |
| Network bandwidth | Gateway container cgroup (optional) | Rate limiting on the gateway's network interface |

#### Host capacity

The sandbox daemon tracks host resource utilization and refuses to create new sessions when the host is at capacity. The capacity model accounts for:

* QEMU process overhead per VM (memory for device emulation, virtio buffers)
* Gateway container overhead per session (Envoy, mitmproxy, DNS resolver memory)
* Per-session network overhead (Docker bridges on Linux, vmnet instances on macOS — negligible)
* Host system reserved resources (OS, sandbox daemon, host Docker daemon)

Capacity planning guidelines are a deferred work item. Initial deployment will use conservative per-session limits and manual capacity management.

## Security analysis

### Threat model and escape analysis

#### Who is the adversary

The agent process inside the VM, and any code it fetches, generates, or executes. This includes npm/pip dependencies, cloned repositories, generated scripts, test suites, and build tooling — code that is not under the agent's or user's direct control. A supply-chain attack or malicious dependency runs with the same privileges as the agent. The adversary is assumed to be:

* capable of executing arbitrary code inside the VM
* capable of gaining root inside the VM (via Docker, kernel exploits, or misconfiguration)
* capable of crafting arbitrary network traffic
* capable of crafting arbitrary device I/O to all virtio devices
* capable of replacing or tampering with the VM-side vsock listener to send crafted responses to sandboxd
* knowledgeable about the sandbox architecture

The agent is not assumed to be:

* capable of physical access to the host
* capable of exploiting hardware side channels (Spectre/Meltdown) — coding agents are not crafting speculative execution exploits; this is a theoretical rather than practical risk for this threat model

#### Attack surfaces ranked by practical risk

##### 1. vsock protocol handler in sandboxd (highest risk, mitigatable)

**What it is:** sandboxd initiates vsock connections to the VM-side listener and parses responses. A compromised agent can replace or tamper with the VM-side listener to send crafted, adversarial responses.

**Why it matters:** The vsock handler is custom, private code parsing untrusted input over the most direct host-guest communication channel. Unlike QEMU/KVM, which are battle-tested by a large open-source community with extensive fuzzing and security audit history, the vsock protocol handler has none of that hardening. A vulnerability (buffer overflow, command injection, path traversal) could compromise the sandbox daemon — which runs on the host and manages all sessions.

**Mitigations:**
* Host→VM only connection direction — sandboxd does not bind a vsock listener, eliminating inbound attack surface
* Per-session handler isolation — sandboxd forks a handler process per session with minimal privileges; a compromised handler affects only that session
* Minimal, well-defined vsock API
* Strict validation of all data received from the VM-side listener
* No shell execution in the vsock handler
* The sandbox daemon runs as a dedicated user, not root (where possible)
* The vsock handler must be fuzz-tested against adversarial inputs

**Residual risk:** A bug in sandboxd's response parser could be triggered by a compromised VM-side listener sending crafted responses. Per-session handler isolation contains the blast radius to a single session, but the handler process still runs on the host. This is the highest-priority code to harden and audit.

##### 2. QEMU device emulation (medium risk, mitigatable)

**What it is:** Each virtio device is implemented as code in QEMU that parses guest-controlled input. A bug in device emulation code can give the guest code execution in the QEMU process.

**Why it matters:** QEMU device emulation has historically been a source of vulnerabilities (VENOM in 2015 targeted the floppy controller; various virtio bugs have been found and patched). However, QEMU is extensively audited by a large open-source community, subject to continuous fuzzing (OSS-Fuzz), and benefits from decades of security hardening. This drops it below vsock in practical risk ranking.

**Mitigations:**
* Minimal device model (4 devices vs. dozens in a default QEMU configuration)
* QEMU process runs as unprivileged user with seccomp, namespaces, and cgroup limits
* Even successful exploitation lands in a sandboxed process, not host root
* virtio-rng has minimal attack surface (read-only, no guest-controlled input parsing)
* Community-hardened codebase with extensive security audit history

**Residual risk:** A vulnerability in virtio-net or virtio-blk emulation could give the guest code execution in the QEMU process. The QEMU sandboxing is the second line of defense.

##### 3. KVM host kernel module (low risk)

**What it is:** KVM is a kernel module on the host that provides hardware-assisted virtualization. It handles VM exits, memory management, and CPU state transitions.

**Why it matters:** A vulnerability in KVM could allow a guest to execute code in the host kernel.

**Mitigations:**
* KVM is well-audited (~50K lines of code) and heavily tested
* Most historical KVM CVEs are denial of service, not code execution
* Keep the host kernel updated

**Residual risk:** A KVM code execution vulnerability would bypass all other protections. This is the highest-impact risk but also the lowest-probability one.

##### 4. Apple VZ (low risk, less audited)

**What it is:** Apple Virtualization.framework on macOS. Less public security research than KVM/QEMU.

**Why it matters:** macOS is used for local development, not production. A VZ vulnerability affects developer machines, not production infrastructure.

**Mitigations:**
* Apple's platform security model (SIP, sandboxing, notarization)
* VZ is a simpler implementation than QEMU (less code, smaller surface)
* macOS is for development only — production runs on Linux with KVM/QEMU

**Residual risk:** Less public vulnerability research means less confidence in the absence of bugs. Acceptable for developer workstations; not relied upon for production security.

##### 5. Side channels (low risk for this threat model)

**What it is:** Spectre, Meltdown, and related speculative execution attacks that can leak data across VM boundaries.

**Why it matters:** A VM on the same physical host as sensitive workloads could theoretically leak data.

**Mitigations:**
* Host kernel mitigations (retpoline, IBRS, etc.) are applied by default on modern kernels
* The sandbox does not run alongside sensitive workloads — it is a dedicated environment
* Coding agents are not crafting speculative execution exploits

**Residual risk:** Theoretical. Not a practical concern for this threat model.

#### Escape chain comparison

**Container (Sysbox) escape — 1 step:**
```
Agent → syscall to shared host kernel → exploit kernel bug → host root
```

**VM (QEMU/KVM) escape — 3 steps:**
```
Agent (root inside VM)
  → craft malicious virtio device I/O
    → trigger QEMU device emulation bug
      → land in unprivileged, sandboxed QEMU process
        → escalate from sandboxed process to host
```

The agent has root inside the VM by default, but root in the guest is not root on the host. The VM escape requires chaining vulnerabilities across 3 independent components: QEMU device emulation, host process sandbox escape, and host privilege escalation. Each step targets different code with different security properties.

#### What root inside the VM does not give the attacker

The agent runs as root inside the VM by default. Despite this:

* **Cannot reach host filesystem.** In the default configuration, no virtio-fs and no host mounts. The opt-in shared mount mode enables virtio-fs with acknowledged additional attack surface (see [Workspace provisioning](#workspace-provisioning)).
* **Cannot bypass proxy pipeline.** The gateway is on the host side of the virtual NIC. The agent can craft arbitrary network packets, but they all pass through the gateway.
* **Cannot communicate with other sessions.** Per-session networks are isolated. The VM cannot reach other VMs' network segments.
* **Cannot access cloud metadata.** 169.254.169.254 is not routable.
* **Can attempt QEMU exploitation** via crafted I/O on the 4 virtio devices.
* **Can attempt vsock exploitation** by replacing or tampering with the VM-side vsock listener to send crafted responses when sandboxd connects.
* **Can consume allocated resources** (CPU, memory, disk) up to the per-session limits.
* **Can destroy their own workspace** — this is expected and acceptable for a disposable session.

### Defense in depth summary

```
Layer 1: Hardware         CPU VMX/EPT (Intel) or VHE (ARM) — enforced by silicon
Layer 2: Hypervisor       KVM (Linux) or Apple VZ (macOS) — host kernel module
Layer 3: QEMU process     Unprivileged user + seccomp + namespaces + cgroups
Layer 4: Device model     4 virtio devices only — no USB, display, legacy, virtio-fs (by default)
Layer 5: Guest kernel     Stock (default) or minimal hardened (optional)
Layer 6: Guest OS         Writable root (disposable — destroyed with session), resource-limited
Layer 7: Agent process    Root (VM boundary is the security boundary, not user privilege)
Layer 8: Inner Docker     Authorization plugin denying dangerous flags (deferred)
Layer 9: Network path     Single NIC → gateway container → proxy pipeline
Layer 10: Proxy pipeline  nftables + Envoy + mitmproxy + DNS (see networking design)
Layer 11: Network policy  Abstract policy model, compiled and distributed by sandboxd
```

No single layer is assumed to be sufficient. The design goal is that any layer's failure degrades the security posture but does not result in full compromise. The most critical assumption is that hardware virtualization (layers 1-2) provides a qualitatively stronger boundary than any software-only mechanism.

### Residual risks

Even with correct implementation, the following risks remain:

* **vsock handler vulnerabilities** in sandboxd's response parser could be triggered by a compromised VM-side listener sending crafted responses. Per-session handler isolation contains the blast radius but does not eliminate it — the handler runs on the host. This is the highest-priority custom code to harden.
* **QEMU device emulation vulnerabilities** are the most likely VM escape vector. The minimal device model and QEMU process sandboxing mitigate but do not eliminate this risk.
* **KVM vulnerabilities** are low-probability but high-impact. Keeping the host kernel updated is the only mitigation.
* **Stock guest kernel** has a larger attack surface than a minimal custom kernel. The default configuration accepts this trade-off for operational simplicity.
* **Inner Docker without authorization plugin** (initial deployment) means the agent has unrestricted Docker access inside the VM. This is defense-in-depth loss, not primary boundary loss.
* **Provisioning from network** means the initial VM setup depends on network access through the proxy pipeline. A supply-chain attack on provisioned packages could compromise the VM. Snapshot-based provisioning mitigates by reducing the number of times provisioning occurs.
* **Long-lived sessions** accumulate state (Docker images, files, configuration) that may include sensitive data. `rm` cleans this up, but the data exists on disk while the session is running.
* **Clock drift** in long-running sessions without NTP could affect TLS certificate validation, log correlation, and time-sensitive operations.

These are structural limitations, not implementation bugs. They define the boundary of what this sandbox can guarantee.

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
* **IPv6 support.** The networking subsystem is IPv4-only by design — a deliberate simplification that reduces attack surface. When IPv6-only destinations become necessary, this requires dual-stack per-session networks, dual-stack VM configuration, IPv6-aware nftables rules, AAAA record handling in the DNS resolver, and IPv6 forwarding in the gateway container. See [networking-design.md § Deferred: IPv6 support](networking-design.md#deferred-ipv6-support) for the full requirements.
* **GPU passthrough.** PCI passthrough for GPU-accelerated data workloads. Requires IOMMU support and platform-specific configuration.
