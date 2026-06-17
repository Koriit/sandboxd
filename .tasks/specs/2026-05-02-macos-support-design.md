# macOS Support — Design Spec

**Date:** 2026-05-02 (reconciled 2026-06-07 against post-M18 `origin/master`)  
**Status:** Draft  
**Supersedes:** `docs/internal/milestones/F1.md` (placeholder)

> **Reconciliation note (2026-06-07).** This spec was first drafted against a pre-M18 codebase. Since then the Linux daemon adopted a **per-operator execution model**: one unprivileged daemon (`sandbox`) per host, keyed under a per-daemon-uid state root `/var/lib/sandboxd/<daemon_uid>/`, with a `cap_setuid` `sandbox-lima-helper` that pivots to the *operator's* uid before every `limactl` call, a 3-level per-operator `LIMA_HOME`, and operator-uid-aligned VMs/containers (operator identity captured via `SO_PEERCRED`, persisted in the V008 `operator_uid`/`operator_gid` columns). macOS **mirrors the per-operator/per-uid shape but eliminates the privileged pivot**: instead of a setuid/cap helper, each operator runs a **per-operator agent** (a LaunchAgent running *as the operator* in their login session) that the daemon brokers `limactl` work to — so on macOS there is **no `sandbox-lima-helper` and no setuid** (see § Privilege model on macOS). `umask(0o077)` + operator-owned dirs replace `setfacl`. The macOS host daemon user is **`_sandbox`** (macOS underscore convention); the in-VM/in-container guest user is **`sandbox`** with home `/home/sandbox` (unified across backends on Linux — macOS inherits it). Schema is at **V010**.

> **Revision note (2026-06-14) — two design changes from review.**
> 1. **Full-backend VM type: `qemu`, not `vz`.** Sandbox VMs (and the gateway Lima instance) on macOS use **`vmType: "qemu"` + socket_vmnet**, *not* VZ. The earlier draft assumed Lima could attach a socket_vmnet NIC to a VZ VM via `VZFileHandleNetworkDeviceAttachment` — that attachment **does not exist** (socket_vmnet's QEMU length-prefixed datagram framing is incompatible with VZ's raw datagrams; [lima-vm/socket_vmnet#13](https://github.com/lima-vm/socket_vmnet/issues/13) is still open). VZ's only working networking is vzNAT (bypasses the gateway → defeats egress control) or bridged (needs an Apple entitlement). Since **absolute, unbypassable egress control is sandboxd's core promise**, the full backend uses QEMU+socket_vmnet — the historically-supported macOS pairing that mirrors the Linux macvlan model exactly. QEMU on Apple Silicon runs arm64 guests with native HVF CPU acceleration; the only cost vs VZ is guest I/O throughput, which is the right thing to trade for enforceable networking. Revisit if VZ gains a working socket_vmnet path — tracked at [#63](https://github.com/Koriit/sandboxd/issues/63). **Empirically validated on real hardware** (macOS 26.4 / Lima 2.1.1 / QEMU 11.0.1 / socket_vmnet host mode, 2026-06-14): QEMU + unmanaged per-VM `socket:` attach + host-mode DHCP work, and a Docker-style `macvlan(private)` child with its own MAC traverses socket_vmnet to both the host gateway and a second VM — i.e. the gateway-container→sandbox-VM interception path holds, no fallback needed. The spike also corrected two details now reflected throughout: the unmanaged attach is a **per-VM `networks: [{socket: <path>}]`** entry (Lima 2.x rejects `socket:` in the global `networks.yaml`), and the guest socket_vmnet NIC is named **`lima0`** (not `enp0sX`). A subsequent review refined the slot segments to **`--vmnet-network-identifier` + static addressing** for hard inter-slot L2 isolation. **The task-A spike (2026-06-14) confirmed inter-slot isolation holds** (distinct per-identifier host bridges; a same-subnet ARP across identifiers fails) and **surfaced a cross-platform egress bypass**: Lima's mandatory slirp management NIC (`eth0`) reaches the internet and was only route-metric-deprioritized, which a root guest can override. The fix — **`-netdev user,restrict=on`** on the management NIC (spike-verified hard block; SSH preserved) — applies to **both platforms**; **Linux has since implemented it** ([#65](https://github.com/Koriit/sandboxd/issues/65), commit `4b134ec`), and macOS mirrors the same `lima.rs` qemu-wrapper mechanism (§ vzNAT and SLIRP). (The spike also corrected an earlier assumption: the host-side gateway `B+1` *does* exist per segment — isolation comes from separate per-identifier bridges, not from removing the host.)
> 2. **Broker protocol is a first-class trust surface.** The daemon↔agent broker that replaces the Linux setuid helper is specified to the same hardened bar as `sandbox-lima-helper` (closed subcommand enum, no argv/shell pass-through, agent-side op-uid + path re-validation) — see § The per-operator agent / broker protocol.

---

## Contents

- [Overview](#overview) — scope, non-goals
- [Glossary](#glossary) — QEMU+HVF, VZ/vzNAT (why not used), socket_vmnet, Lima instance, vmnet slot, etc.
- [Prerequisites](#prerequisites) — socket_vmnet (daemon mode), Lima 1.2.0+, Docker CLI, Tart (optional)
- [Platform detection and code abstraction](#platform-detection-and-code-abstraction) — per-operator model, the operator-execution seam (Linux setuid helper vs macOS per-operator agent), Docker socket wiring, Lima template branching
- [Gateway Lima instance](#gateway-lima-instance) — paths, YAML template, lifecycle, upstream DNS, readiness
- [socket_vmnet pool](#socket_vmnet-pool) — subnet allocation, slot lifecycle, initialization, concurrency
- [Sandbox VM template (macOS)](#sandbox-vm-template-macos) — QEMU + socket_vmnet, narrow `restrict=on` wrapper (no Linux seccomp/cgroup wrapper), 9p shared mount
- [Session lifecycle on macOS](#session-lifecycle-on-macos) — NIC naming, create/start/stop/rm
- [Daemon startup sequence (macOS)](#daemon-startup-sequence-macos) — eight numbered steps
- [Session store schema changes](#session-store-schema-changes) — `vmnet_slot` in NetworkInfo JSON blob, inspect output
- [Pool resize handling](#pool-resize-handling) — rebuild gateway instance on `max_macos_sessions` change
- [Failure handling](#failure-handling) — gateway Lima crash, socket_vmnet failure, container crash, slot leak detection
- [Security posture](#security-posture) — layer mapping, known deltas, topological invariants
- [Integration with daemon infrastructure (M13–M18)](#integration-with-daemon-infrastructure-m13-m18) — M18 cross-user CLI (hard prerequisite), per-caller isolation, version handling, install + update, doctor checks consolidated, workspace modes, lite-mode container backend, tarball contents, disk usage, TCC/SIP, reboot, coexistence
- [Networking design corrections](#networking-design-corrections) — four updates needed in `networking-design.md`

---

## Overview

This document specifies the design for full macOS support in sandboxd. macOS is a development platform — not a production target. The security guarantees are equivalent to Linux, achieved through different mechanisms. The CLI user experience is identical on both platforms.

**Deployment assumption (load-bearing): interactively-logged-in Macs.** Operators using sandboxd are logged into a macOS login session. The per-operator execution model runs each operator's `limactl` inside a **per-operator agent** in that operator's own login session (§ Privilege model on macOS) — which eliminates any privileged setuid/setcap pivot *and* makes `shared:` workspace TCC consent possible, at the cost that an operator's sandbox VMs are **login-scoped** (stop on logout, resume on re-login) and the daemon can act for an operator only while that operator is logged in. Headless / not-logged-in multi-tenant macOS servers are therefore out of scope (Non-goals).

### Scope

- socket_vmnet pool management
- sandboxd-managed Lima gateway instance (Lima driven via the operator-execution seam — per-operator agent on macOS — no Colima)
- macvlan gateway container deployment
- QEMU Lima template for sandbox VMs (socket_vmnet networking, HVF-accelerated)
- Session lifecycle integration (create/start/stop/rm)
- Daemon startup and prerequisite handling
- Colima-free Docker socket exposure from Lima guest to macOS host
- Failure recovery
- Security posture parity
- Installation via `scripts/install.sh` (extended to support `Darwin`) as a launchd **system daemon** under `_sandbox`
- Per-operator execution model on macOS: a **per-operator agent** (no setuid/root) that runs `limactl` as the operator, per-operator `LIMA_HOME`, operator-uid-aligned QEMU VMs and lite containers (mirrors the Linux post-M18 per-operator shape, minus the privileged pivot)
- `sandbox update` parity on macOS (same UX, launchctl service control, gateway image refresh inside the persistent Lima instance)
- `sandbox doctor` macOS-specific checks (socket_vmnet, gateway Lima instance, vmnet pool, per-operator agent)
- Cross-cutting integration with M13–M18 infrastructure (per-caller isolation, version equality, cross-user CLI, workspace modes, workspace-lock)

### Non-goals

- Production deployment on macOS
- Headless / not-logged-in multi-tenant macOS servers (the per-operator agent requires the operator to be logged in — § Privilege model on macOS; interactive-desktop Macs are the target)
- Windows support
- Ingress connectivity
- Multi-host orchestration
- Homebrew formula (may follow as a wrapper around install.sh; not required for initial launch)
- Apple Developer ID signing & notarization of the macOS binaries (deferred follow-up; the curl|bash and brew install paths don't trigger Gatekeeper)
- Native macOS Lima support without socket_vmnet (vzNAT bypasses the proxy pipeline; explicitly rejected)

---

## Glossary

Terms used densely throughout this spec, disambiguated:

- **QEMU + HVF** — the macOS hypervisor path sandboxd uses for sandbox VMs and the gateway Lima instance (`vmType: "qemu"`). On Apple Silicon, `qemu-system-aarch64 -accel hvf` runs arm64 guests with native CPU acceleration via Apple's Hypervisor.framework — *not* emulation. socket_vmnet is QEMU's native networking path, which is why this (not VZ) is the backend (§ vmType and network). `qemu` is pulled in as a Lima dependency by `brew install lima`.
- **VZ (Virtualization.framework)** — Apple's hypervisor framework and Lima's *default* macOS backend. sandboxd does **not** use it for sandbox VMs: VZ offers no interceptable isolated-L2 networking — vzNAT bypasses the gateway, bridged needs an Apple entitlement, and socket_vmnet cannot attach to VZ ([socket_vmnet#13](https://github.com/lima-vm/socket_vmnet/issues/13)). Defined here because the design must explicitly select `qemu` over Lima's VZ default. See § vmType and network; revisit tracked at [#63](https://github.com/Koriit/sandboxd/issues/63).
- **vzNAT** — `VZNATNetworkDeviceAttachment`, VZ's built-in NAT. One of the two reasons VZ is unusable for sandboxd (the other: socket_vmnet can't attach to VZ): VM traffic is NATed *inside* Virtualization.framework before reaching any interface sandboxd can intercept, so it bypasses the gateway pipeline. The QEMU analog to avoid is user-mode SLIRP (`-netdev user`) — same escape-hatch problem. Sandbox VMs always use socket_vmnet (§ vmType and network).
- **socket_vmnet** — Brew-installed system-level helper that exposes vmnet kernel interfaces over Unix sockets, providing isolated L2 segments to **QEMU** Lima VMs without requiring root in the calling process. (socket_vmnet's wire protocol is QEMU-native — this is the supported pairing.)
- **Lima instance** — A managed VM under a `LIMA_HOME`. Three instance kinds in this design, with **different ownership**:
  - **Gateway Lima instance** (`sandboxd-gateway`) — persistent Linux VM that hosts the per-session gateway containers (Envoy, mitmproxy, CoreDNS, deny-logger, allow-logger). One per daemon, **daemon-owned infrastructure** — lives under the daemon's own `LIMA_HOME` (`/var/lib/sandboxd/<_sandbox-uid>/lima/`), runs as `_sandbox`. macOS only — on Linux the gateway is a per-session container on the host's Docker daemon, no Lima involved.
  - **sandbox-base** — golden Lima VM image cloned for each session. **Per-operator**: built lazily under the operator's `LIMA_HOME` on that operator's first session create. Same on Linux and macOS — both use the **QEMU** backend (macOS just adds socket_vmnet networking and HVF acceleration).
  - **Per-session sandbox VM** — `sandbox-<session-id>`, the actual workload VM, **per-operator** (under the operator's `LIMA_HOME`). Cloned from that operator's sandbox-base via `limactl clone` — run by that operator's **per-operator agent** on macOS (the agent runs as the operator), via the lima-helper pivot on Linux.
- **`sandbox-lima-helper`** — **Linux-only** privileged helper at `/usr/local/libexec/sandboxd/sandbox-lima-helper`, setcap `cap_setuid+ep`. Validates its caller (`getuid()==sandbox-uid` + group membership), validates the requested operator uid, setuid-pivots to that operator, and `exec`s `limactl` with a sanitized env (`LIMA_HOME` set to the per-operator tree, `umask 0o077`). **Not present on macOS** — its job is done by the *per-operator agent*.
- **per-operator agent (macOS)** — a LaunchAgent (`io.sandboxd.agent`) registered at operator enrollment, which `launchd` runs **as the operator** in that operator's login session. The system daemon (`_sandbox`) brokers `limactl` work to it over a check-in channel; because the agent already runs as the operator, it `exec`s `limactl` **natively** — no setuid, no capability, no root. The macOS implementation of the *operator-execution seam* (§ Platform detection, § Privilege model on macOS).
- **operator-execution seam (`LimaExecutor`)** — the trait abstracting "run this `limactl` op as operator N": `SetuidHelperExecutor` on Linux (the helper above), `AgentBrokerExecutor` on macOS (the agent above). **The daemon never invokes `limactl` directly** on either platform — every operation routes through this seam. The op set **mirrors `sandbox-lima-helper`'s subcommand set verbatim** (all 11): `Create`, `Start`, `Stop`, `Delete`, `Clone`, `List`, `InstallGuestAgent`, `Copy`, `ReadUserKey` (proxy SSH-key read), `RunRsync` (`local:`/workspace-push transport), and the `GuestSocat` guest transport. (The macOS broker must cover **all** of these, including `RunRsync` and `ReadUserKey` — § The per-operator agent / broker protocol.)
- **pivot** — the privileged **uid switch** by which the **Linux** `sandbox-lima-helper` changes its own user identity from the caller (the daemon's `sandbox` uid) to the *operator's* uid — via `setuid`/`setresuid`, using its `cap_setuid` capability — *before* `exec`'ing `limactl`, so `limactl` (and the VM it launches) run as the operator. It is a privilege **drop** to a specific enrolled operator (or, in the *degenerate* case, to the daemon's **own** uid `_sandbox` — e.g. for the gateway instance — a no-op identity-wise). **macOS has no pivot:** the per-operator agent already runs *as* the operator, so no uid change occurs. Distinct from operator-identity *capture* (reading the caller's uid from `LOCAL_PEERCRED`), which is how the daemon *learns* which operator a request belongs to — the pivot is the act of *becoming* that uid (Linux only). "Pre-pivot caller uid" = the helper's identity before this switch. (Term inherited from `CLAUDE.md` and the M18 lima-helper design.)
- **per-operator LIMA_HOME** — `/var/lib/sandboxd/<_sandbox-uid>/<operator_uid>/lima/`, a 3-level path (state-root / daemon-uid / operator-uid). Owned by the operator, so the operator's `limactl` (run by their agent on macOS, via the helper pivot on Linux) owns its VM tree; the SSH key inside is a plain `0600` file (no default named-user ACL — see operator-uid-alignment section for the OpenSSH StrictKeyfileMode rationale). Each operator's sandbox VMs live here, isolated from other operators by uid.
- **operator-uid alignment** — the mechanism by which a session's VM/container runs at the *operator's* numeric uid (not the daemon's), so `shared:` (9p) workspace files have correct host-side ownership. Operator identity is captured from the API socket's peer credentials (`LOCAL_PEERCRED` on macOS, `SO_PEERCRED` on Linux), daemon-stamped onto the session (never client-supplied), and persisted in the `operator_uid`/`operator_gid` columns (V008). The QEMU VM process runs at the operator uid because the operator's own agent runs `limactl` (macOS) / via the lima-helper pivot (Linux); cloud-init `usermod` aligns the in-VM `sandbox` user when the operator uid ≠ the image default (1000).
- **vmnet slot** — Index `0..N-1` (default N=8) identifying one of the gateway Lima instance's pre-attached socket_vmnet NICs. Each slot is a separate socket_vmnet instance — the `io.sandboxd.vmnet.<N>` root daemon, socket `slot-<N>.sock`, a `/29` subnet. There is **no Lima network *name***; VMs attach to a slot directly via a per-VM `networks: [{socket: …/slot-<N>.sock}]` entry (§ Initialization — verified on Lima 2.1.1). **Lima (QEMU) sessions** claim slots at create time, release at stop; **lite sessions claim none** (they use an internal Docker bridge — § M11). Non-sticky across stop/start.
- **macvlan parent** — Linux Docker macvlan networks need a parent NIC. Inside the gateway Lima VM, the parent is one of the socket_vmnet NICs (Lima names them `lima0`, `lima1`, … in `networks:` order — e.g. `lima1` for slot 1; the management NIC is `eth0`). The **Lima-mode** gateway container attaches as a macvlan child of that parent, to share the socket_vmnet L2 segment with the external sandbox VM. **Lite mode does not use macvlan** — it uses an internal Docker bridge inside the gateway Lima VM (§ M11).
- **Forwarded Docker socket** — Lima `portForwards` exposes the gateway Lima VM's `/var/run/docker.sock` to the macOS host at `/var/lib/sandboxd/<_sandbox-uid>/lima/sandboxd-gateway/gateway-docker.sock`. All daemon-issued `docker` commands target this socket via `DOCKER_HOST`. **Host-side perms: `_sandbox`-only.** Lima creates the forwarded socket `0600` owned by `_sandbox` (the user running `limactl` for the gateway), and it sits inside the `0750 _sandbox:_sandbox` per-uid root. Controlling this socket is root-equivalent *inside the gateway VM* and tampering with it would break egress enforcement for **every** session at once, so it must **not** be group-readable: enrolled operators (group `_sandbox`) may traverse the directory but cannot connect to the gateway Docker socket — only the daemon (`_sandbox`) can. (This is the single largest cross-session blast radius on macOS; see § Security posture.)
- **`_sandbox` user** — the macOS **host** system user the daemon runs as (macOS underscore convention; analog of Linux's `sandbox`). Owns the per-daemon-uid state root `/var/lib/sandboxd/<_sandbox-uid>/`, the daemon process, the gateway Lima instance, and the unix API socket. Distinct from the in-VM/in-container guest user, which is named **`sandbox`** (home `/home/sandbox`). Per-operator sandbox VMs are owned by the *operator's* uid, not `_sandbox`.
- **daemon-uid state root** — `/var/lib/sandboxd/<daemon_uid>/`, the per-daemon-uid root under which all of a daemon's state lives (sessions.db, socket, backups, the daemon's own gateway `LIMA_HOME`, and the per-operator `LIMA_HOME` subtrees). Keyed by uid so a production daemon (`_sandbox`) and a dev/test daemon could coexist without colliding. The daemon derives `<daemon_uid>` from `getuid()`; on Linux the lima-helper derives the same segment from its pre-pivot caller uid, and on macOS the daemon hands each agent the resolved per-operator `LIMA_HOME` path over the broker channel.
- **Workspace lock** — M17 in-memory per-session mutex inside the daemon, serializing `sandbox workspace push`/`pull` ops and blocking `sandbox stop` / `sandbox delete` against locked sessions.
- **Substrate** — The Linux execution environment a sandbox or gateway component runs in. Always Linux. On Linux hosts the substrate is the host kernel; on macOS hosts the substrate is the gateway Lima VM (for the gateway pipeline + lite containers) or per-session sandbox VMs (for full sandbox sessions).

---

## Prerequisites

The following must be installed on the macOS host before sandboxd can operate. sandboxd checks for each at daemon startup and fails with actionable error messages if any are missing.

### socket_vmnet

socket_vmnet provides isolated L2 network segments for Lima VMs without requiring root in the calling process — each socket_vmnet **instance** is an independent virtual switch (one isolated segment). The operator installs the **binary**:

```
brew install socket_vmnet
```

sandboxd does **not** use socket_vmnet's own Homebrew launchd service (`brew services start socket_vmnet`). That service starts a *single* instance on one socket and one subnet (gateway `192.168.105.1`), which cannot provide the pool's N isolated segments. Instead sandboxd runs **its own N socket_vmnet daemons** — one per pool slot — as root-owned launchd jobs that install.sh generates from `max_macos_sessions` (see § socket_vmnet pool § Initialization, and § socket_vmnet access for why this avoids any Lima sudoers entry). sandboxd's startup prerequisite check verifies the socket_vmnet binary is present (Apple Silicon Homebrew prefix `/opt/homebrew/opt/socket_vmnet/bin/socket_vmnet`) and that its own socket_vmnet daemons' sockets are reachable; a missing binary fails fast:

```
error: socket_vmnet is not installed. Install it:
  brew install socket_vmnet
```

### Lima (and QEMU)

Lima is required on both platforms. On macOS, `limactl` must be on PATH and report version ≥ **1.2.0**.

sandboxd uses Lima's **QEMU** driver on macOS (`vmType: "qemu"` — see § vmType and network for why, not VZ). The QEMU driver needs the `qemu-system-aarch64` binary present; Homebrew's `lima` formula **depends on `qemu`**, so `brew install lima` pulls it in (a standalone `brew install qemu` also satisfies it). On Apple Silicon, QEMU uses HVF acceleration automatically — Homebrew's `qemu` ships signed with the `com.apple.security.hypervisor` entitlement that HVF requires (§ Apple code signing). The startup prereq check confirms `limactl` resolves a usable QEMU driver; a missing `qemu` binary fails fast with `brew install lima` (or `brew install qemu`) guidance.

`MIN_LIMA_VERSION = "1.2.0"` is the floor we actually test against in the install-e2e harness — older versions are explicitly unsupported. The version is enforced in three places — `scripts/install.sh`, the daemon's startup prerequisite check, and `sandbox doctor` — that share a single source of truth: install.sh holds the canonical value inline (alongside cosign version pins, SHA256 expectations, etc.), and the Rust-side constants in `sandbox-cli` and the daemon are drift-tested against install.sh at build time:

- **install.sh** prerequisite check — `printf '%s\n%s\n' "$MIN_LIMA_VERSION" "$(limactl --version | awk '{print $3}')" | sort -V -C` catches version skew before any system state is written. Fails fast with `brew upgrade lima` guidance.
- **Daemon startup** — refuses to start if `limactl --version` reports an older version. Catches the case where install.sh ran fine but the operator later downgraded Lima.
- **`sandbox doctor`** — diagnostic surface (`check_lima_version` row, gated on `cfg!(target_os = "macos")`).

Lima's own `minimumLimaVersion: "1.2.0"` directive in the gateway Lima YAML template is a defensive duplicate: it lets Lima itself refuse the YAML if some out-of-band tool ever launches the instance against an older `limactl`. The primary enforcement is sandboxd's checks above.

### socket_vmnet access (sandboxd-managed daemons, no Lima sudoers)

**Resolved design.** The pool needs N *isolated* L2 segments (one per slot), and each isolated segment is a separate socket_vmnet instance on its own socket — so the pool is N socket_vmnet instances. socket_vmnet's own Homebrew service starts only **one** instance, so it cannot back the pool. sandboxd therefore runs the instances itself, as **N root-owned launchd daemons** it installs (`io.sandboxd.vmnet.<n>`, generated from `max_macos_sessions`), each: `socket_vmnet --vmnet-mode=host --vmnet-network-identifier=<per-slot UUID> --socket-group=_sandbox /var/run/sandbox/vmnet/slot-<n>.sock` — a unique per-slot network-identifier puts each slot on its own isolated L2 network with no DHCP, and `--socket-group=_sandbox` overrides socket_vmnet's `staff` default so the slot socket is reachable only by `_sandbox`/enrolled operators (§ Initialization, § Subnet allocation, § M13). Lima references them through the **unmanaged `socket:`** field (§ Initialization), so *Lima never starts or stops socket_vmnet* — it only connects to the already-running socket.

**Consequence — there is NO `/etc/sudoers.d/lima` entry (this resolves the prior open verification item).** The `limactl sudoers` mechanism exists only for Lima's *managed* networks, where Lima sudo-spawns/reaps socket_vmnet per VM. Under the unmanaged `socket:` model that machinery is never invoked, so no sudoers file — per-operator or group-scoped — is generated, installed, or stripped on uninstall. This is deliberate: it keeps the privileged surface inside a sandboxd-owned, narrowly-scoped launchd daemon (consistent with the narrow-helper philosophy — route-helper / lima-helper on Linux) rather than granting every enrolled operator NOPASSWD sudo to a root network daemon. (This is also why the design did not adopt the alternative "Lima-managed + sudoers" model.)

**What the connecting identities need is socket access.** Two kinds of process connect to a slot's socket: the daemon-owned gateway Lima instance (as `_sandbox`) and each operator's sandbox VM (as the operator — run by that operator's agent). All are members of the `_sandbox` group. The slot sockets live under `/var/run/sandbox/vmnet/` (directory owned `_sandbox:_sandbox` mode 0750; sockets group `_sandbox`), so `_sandbox`-group members can connect and non-members cannot — no separate "socket_vmnet access group" is introduced.

**Binary integrity (root-exec foothold).** Because the `io.sandboxd.vmnet.<n>` daemons exec socket_vmnet *as root*, the binary they exec — **and its entire directory ancestry** — must be root-owned and not writable by any non-root principal. A user who can replace the binary (or rename a parent directory and substitute one) gains root code-execution. This rules out **both** the admin-writable Homebrew prefix (`/opt/homebrew/...`) **and** `/usr/local/...`: socket_vmnet's own README warns that `/usr/local` "is sometimes chowned for a non-admin user, so `/usr/local` is not an appropriate prefix," and on Apple Silicon Homebrew may have chowned `/usr/local/*`. install.sh therefore stages the root-exec'd socket_vmnet at **`/Library/sandboxd/socket_vmnet`** (`root:wheel` 0755): `/Library` is `root:wheel` on every macOS and is not writable by admin users without sudo, so the full ancestry (`/` → `/Library` → `/Library/sandboxd`) is provably root-owned and non-admin-writable — unlike `/usr/local`. The daemon **asserts** at startup that this binary and every ancestor up to `/` is root-owned and not group/other-writable, and **refuses to proceed** (rather than trusting a hijackable root-exec target) otherwise. (The other sandboxd binaries stay under `/usr/local/libexec/sandboxd/` because they are **not** root-exec'd — launchd runs `sandboxd` as `_sandbox` and `sandbox-agent` as the operator — so replacing them yields no privilege escalation; only the root-exec'd socket_vmnet needs the `/Library` guarantee.) **Dylib closure is system-only (verified):** `otool -L` on the Homebrew socket_vmnet resolves to exactly `/System/Library/Frameworks/vmnet.framework/…/vmnet` and `/usr/lib/libSystem.B.dylib` — both SIP-protected — with **no** admin-writable Homebrew dylib in the closure, so the root-exec'd binary cannot be subverted via a planted dependency. install.sh should re-check this at stage time (reject if the closure ever gains a non-system path). **Prevention vs. detection:** the daemon's startup ownership assertion runs *after* the vmnet daemons have already root-exec'd the binary at boot, so it is **detection**, not prevention. The actual root-exec guard belongs in the launchd job: the `io.sandboxd.vmnet.<n>` pre-exec wrapper should verify the binary (ownership + a pinned cdhash / `codesign --verify`) *before* exec, and the daemon's assertion is the second line that alerts and refuses to proceed.

`sandbox doctor` checks: `check_socket_vmnet_access` verifies the operator is in the `_sandbox` group and can reach the slot sockets; `check_socket_vmnet_running` verifies the N `io.sandboxd.vmnet.<n>` launchd daemons are loaded.

### Docker CLI

sandboxd shells out to `docker` for gateway container lifecycle and nftables injection. The Docker CLI must be on the macOS host PATH. The source (Docker Desktop, Homebrew, Orbstack) does not matter — sandboxd injects `DOCKER_HOST` explicitly on every invocation, so the CLI's own default context is irrelevant.

### Tart (optional — install-e2e dev only)

Tart (`brew install cirruslabs/cli/tart`) is a VZ-based VM manager purpose-built for running macOS VMs inside macOS for CI. It is **required only** for `make test-install-e2e` (and the CI `build-macos` install-e2e step) to exercise the macOS **install *and* uninstall** paths (plus `sandbox update`) against a fresh, isolated macOS VM rather than the developer's actual machine. See § install / uninstall e2e coverage (Tart) for the scenario set.

It is **not** required for any other workflow: not for running sandboxd, not for `make test`, not for `make test-integration`, not for `make test-e2e`. End users installing sandboxd via `install.sh` do not need Tart.

`make setup-dev-env` checks for Tart's presence and warns if absent — it does not auto-install.

---

## Platform detection and code abstraction

### Where platform-specific logic lives

macOS support does not introduce a new `BackendKind` variant. Sessions on macOS continue to use `backend = 'lima'` (the V005 `backend` column, `DEFAULT 'lima'`). The `BackendKind::Lima` dispatch path handles both Linux and macOS — platform differences are encapsulated inside the Lima backend (`LimaManagerRegistry` / `LimaManager` / `LimaRuntime`) and behind the **operator-execution seam** introduced below.

Platform is decided at compile time via `cfg!(target_os = "macos")`. It is not persisted — `backend = 'lima'` is sufficient to identify Lima sessions on both platforms.

#### The operator-execution seam (`LimaExecutor`)

**The daemon never invokes `limactl` directly, and never runs it as the operator's uid itself, on either platform.** What it needs is "run this `limactl` operation *as operator N*." *How* that is delivered is the one genuinely platform-divergent piece, and it is factored into a seam — structurally parallel to the existing `SessionRuntime::guest_transport` seam (Lima `socat` bridge vs container `docker exec` bridge) and the `Backend` trait. This is the refactor macOS support requires: extract operator-context limactl execution from the (today Linux-only, helper-shaped) call sites into a trait with two implementations.

```
trait LimaExecutor {                       // "run this limactl op as operator N, return its output"
    fn run(&self, op_uid: u32, subcommand: LimaSubcommand, args: &[..]) -> Result<Output>;
}
```

| | Linux (`SetuidHelperExecutor`) | macOS (`AgentBrokerExecutor`) |
|---|---|---|
| mechanism | exec `sandbox-lima-helper --op-uid N …`, which **setcap/setuid-pivots** to the operator, then execs `limactl` | route the request to operator N's **per-operator user-agent** (running *as* N), which execs `limactl` **natively as N** |
| privilege used | setcap `cap_setuid+ep` (drop-to-operator) | **none** — the agent already *is* operator N; no setuid, no setcap, no root |
| selected by | `cfg!(target_os = "linux")` | `cfg!(target_os = "macos")` |
| **Linux is unchanged** | the post-M18 setuid/cap helper, verbatim | — |

On **Linux** this is exactly the post-M18 helper, untouched by macOS work. On **macOS** there is **no privileged pivot at all**: a long-lived per-operator **agent** (a LaunchAgent registered at operator enrollment, running in operator N's own login session as uid N) checks in with the daemon over a broker channel, and the daemon hands it limactl work; because the agent already runs as the operator, it needs no capability, no setuid, and no root. See § Privilege model on macOS for the full model, its IPC, and its login-session constraints.

The per-operator registry structure is shared; only the executor differs:

```
LimaManagerRegistry          # Mutex<HashMap<operator_uid, Arc<LimaManager>>> — one manager per operator
  └─ LimaManager             # carries: operator_uid, per-operator LIMA_HOME, and a LimaExecutor
       └─ runs limactl ONLY via its LimaExecutor (Linux: setuid helper; macOS: operator's agent)
```

**Gateway instance is the degenerate case.** The gateway Lima instance is daemon-owned infrastructure whose `op_uid` is `_sandbox`'s *own* uid. On Linux the `SetuidHelperExecutor` "pivots" to `_sandbox` (a no-op pivot). On macOS the `AgentBrokerExecutor` special-cases `op_uid == _sandbox`: the daemon **runs `limactl` directly, as itself** — there is no agent for `_sandbox` because the daemon already *is* `_sandbox`. Human-operator op-uids route to that operator's agent; the daemon's own uid does not.

`LimaRuntime` constructs the platform-appropriate `LimaExecutor` once at startup. On Linux it resolves and verifies the helper (env override `SANDBOX_LIMA_HELPER_PATH` → canonical `/usr/local/libexec/sandboxd/sandbox-lima-helper`, `cap_setuid` present); a missing/unprivileged helper is a **fatal startup error**. On macOS there is no helper to resolve — startup instead verifies the daemon can bind its agent-broker channel (see § Privilege model on macOS). The gateway Lima instance is managed by a distinct daemon-uid `LimaManager` (operator_uid = `_sandbox`'s own uid), not vended from the per-operator registry.

`LimaRuntime` also carries `gateway_docker_socket: Option<PathBuf>` (`None` on Linux, `Some(...)` on macOS) for the forwarded gateway Docker socket described next.

### Docker socket wiring

On Linux, `GatewayManager` calls `docker` against the system socket (no override).

On macOS, `GatewayManager` must target the gateway Lima instance's forwarded socket instead. Rather than injecting `DOCKER_HOST` at each callsite, `GatewayManager` gains a `docker_socket: Option<PathBuf>` field. All `Command::new("docker")` calls inside `GatewayManager` are factored through a helper that injects `DOCKER_HOST` when `docker_socket.is_some()`:

```rust
struct GatewayManager {
    docker_socket: Option<PathBuf>,  // None on Linux, Some(gateway-docker.sock) on macOS
}
```

`LimaRuntime` constructs `GatewayManager` with the appropriate socket path. The prerequisite check (`docker --version`) does not contact any socket and does not require DOCKER_HOST.

`gateway_docker_socket` is resolved at `LimaRuntime` startup, after the gateway Lima instance is ready (step 4d of the daemon startup sequence). No docker command that contacts the daemon is issued before that point. After resolution, the *path* is fixed for the run, but commands against it may legitimately **fail** later — e.g. during a gateway-Lima outage, where the gateway-crash-recovery path (§ Failure handling) deliberately issues `docker -H <gateway-socket>` calls while the gateway is down. Callers therefore treat a connection-refused (gateway not reachable) as a distinct, retryable condition from a command-level error, rather than assuming the socket is always live once resolved.

### Lima template branching

`LimaManager::generate_template()` accepts an `is_macos: bool` flag threaded from `LimaRuntime`:

- **Linux** (`is_macos = false`): `vmType: "qemu"`, QEMU wrapper script with `qemu-bridge-helper`, seccomp/namespace/cgroup flags, `mountType: "9p"`
- **macOS** (`is_macos = true`): `vmType: "qemu"` **as well** — but socket_vmnet network entry (not `qemu-bridge-helper`), and **no Linux wrapper script** (macOS has no `systemd-run`/cgroups/namespaces, and QEMU's `-sandbox` seccomp is a Linux-only feature). Same `mountType: "9p"`. HVF acceleration is applied automatically by Lima's QEMU driver on Apple Silicon.

Both platforms run QEMU; the deltas are the networking attachment (qemu-bridge-helper vs socket_vmnet) and the Linux-only process-isolation wrapper. All other callsites are platform-independent.

### Privilege model on macOS (per-operator agent, no setuid)

The Linux privilege-model rule (CLAUDE.md) is: the daemon runs unprivileged; the privilege to *become an operator and run `limactl` as them* lives in a narrowly-scoped setcap/setuid helper, never in the daemon. **macOS reaches the same end (limactl runs as the operator) by a different, more idiomatic route that needs no privileged pivot at all** — and so has **no `sandbox-lima-helper` on the host**.

Instead, each operator runs a **per-operator agent** — a macOS LaunchAgent registered at enrollment, started by `launchd` in that operator's own login session, **running as the operator's uid**. The unprivileged system daemon (`_sandbox`) brokers limactl work to the right operator's agent (the macOS `AgentBrokerExecutor` of the § operator-execution seam). Because the agent already *is* the operator, it runs `limactl` natively — no setuid, no setcap, no root, no uid pivot, and therefore no setuid binary anywhere on the host.

| Privileged component on the macOS host | Status |
|---|---|
| `sandbox-lima-helper` | **Not present.** Linux-only binary (setcap `cap_setuid+ep`); not shipped, installed, or built for macOS. Its job is done by the per-operator agent running as the operator. |
| `sandbox-route-helper` | **Not on the host** — runs *inside* the gateway Lima VM (Linux substrate), setcap'd as on Linux. Unchanged. |
| socket_vmnet pool daemons (`io.sandboxd.vmnet.<n>`) | **The only root component on the macOS host** — and not a pivot: `vmnet.framework` inherently requires root, so these are pure network-infra LaunchDaemons (§ socket_vmnet pool). They never run `limactl` or touch operator identities. |

So on macOS: the system daemon is unprivileged (`_sandbox`), the per-operator agents are unprivileged (each runs as its operator), and the sole host root surface is the socket_vmnet network daemons. **There is no setuid-root binary on the macOS host.**

#### The per-operator agent

- **What it is.** A LaunchAgent (`io.sandboxd.agent`) installed at operator enrollment (`install.sh --add-user`). `launchd` starts one instance per logged-in operator, in that operator's session, as that operator's uid. The agent binary ships in the macOS tarball (occupying the slot the lima-helper holds on Linux).
- **launchd scoping — `LimitLoadToSessionType: Aqua` is mandatory.** A LaunchAgent in `/Library/LaunchAgents` with no `LimitLoadToSessionType` is loaded into **every** session type — including `LoginWindow` (the pre-login context, which runs jobs **as root**) and `Background`/`Standard`. That would start the agent as **root** with no Aqua session (so TCC can't prompt) and let it attempt a broker check-in as uid 0 — exactly the case the broker rejects (`uid < 500`), but it should never arise. The plist therefore sets `LimitLoadToSessionType: Aqua`, so the agent loads **only** in a real GUI login session, as the logged-in operator — which is also what makes the TCC-consent path (§ SIP and TCC) work. (This gates the **full backend only**; lite mode needs no agent and works without a GUI session — § Login-session constraints / scope.) The `_sandbox`-membership self-check is kept as defense-in-depth but is a clean no-`KeepAlive` exit (no respawn loop for non-enrolled users). Under fast user switching, each logged-in user gets its own Aqua-scoped instance — see § Failure handling for duplicate-check-in / switched-away handling.
- **Check-in (IPC direction = agent → daemon).** On login the agent connects *out* to the daemon's **broker socket** and registers. The daemon then pushes `limactl`-exec requests over that established channel and reads results back. This is the idiomatic direction — a system daemon reaching *into* a user's launchd domain is the discouraged one (and would require root the daemon doesn't have). The broker socket is specified exactly like the API socket (§ Install paths): absolute path **`/var/run/sandbox/broker.sock`**, mode **0660**, owner **`_sandbox:_sandbox`**, inside the 0750 `/var/run/sandbox/` dir; the daemon **recreates it with the correct owner/mode before listening** at every startup (`/var/run` is cleared on boot). **Single connection per uid:** a new check-in for an already-connected uid **evicts and closes the prior connection** (last-writer-wins) — covering re-login / fast-user-switch races; the daemon never fans a uid's work across two channels. A **heartbeat/liveness** ping lets the daemon drop a dead agent connection promptly rather than trusting a long-stale one (see § Failure handling).
- **Anti-spoof + authorization (kernel-checked, never self-claimed).** The daemon does **not** trust the agent's *claimed* uid — it reads the connecting peer's uid via `LOCAL_PEERCRED` at `accept()`, exactly as it authenticates the `sandbox` CLI. An agent cannot register as a uid it does not run as. The daemon **rejects** any check-in whose peer uid is `0` or below the system-account floor (`< 500`) — a check-in must come from a real enrolled operator, never root or a service account. `_sandbox`-group membership is the enrollment gate, but it is **re-resolved from the peer uid via `getgrouplist(3)`** (Directory Services), *never* read from the peercred group array (`xucred.cr_groups` is capped at 16 and unreliable — § M13). The broker socket being group-`_sandbox` 0660 is a first filter; the `getgrouplist`-on-uid check is the authoritative one.
- **limactl invocation.** The agent runs `limactl` with `LIMA_HOME=/var/lib/sandboxd/<_sandbox-uid>/<op_uid>/lima/` and `umask 0o077` (so the per-VM SSH key lands `0600` for OpenSSH `StrictKeyfileMode`). It finds `limactl` via PATH — but **a LaunchAgent does not inherit the operator's interactive-shell PATH** (`launchd` does not source `~/.zprofile`/`~/.zshrc`), so `/opt/homebrew/bin` is absent by default. The agent therefore sets its own PATH explicitly (prepending `/opt/homebrew/bin:/usr/local/bin`, or resolving `limactl` via a small candidate-path probe). This is *not* the hardcoded-path lockstep a setuid helper would need — the agent runs as the operator and just has to establish a sane PATH for itself, not bake a single privileged path; but the "inherits Homebrew prefix natively" claim is only true for an interactive shell, not a launchd job, so the agent must do this.

#### Broker protocol (what crosses the wire) — the trust surface that replaces `sandbox-lima-helper`

The broker is the macOS analog of the most carefully-reviewed file in the Linux tree (`sandbox-lima-helper`), and it is specified to the **same hardened bar**. The agent runs `limactl` *as the operator* on behalf of a remote requester (the daemon); anything that can influence a brokered request reaches `limactl` in the operator's session. The protocol therefore mirrors the helper's NON-FEATURES contract (`sandbox-lima-helper/src/main.rs`):

- **Closed subcommand enum, no pass-through.** The wire request is a tagged enum of the exact operations the seam needs — `Create`, `Start`, `Stop`, `Delete`, `Clone`, `List`, `InstallGuestAgent`, `Copy`, `ReadUserKey`, `RunRsync`, plus the `GuestSocat` transport (the full `LimaExecutor` op set — § operator-execution seam) — each carrying **typed, named fields**, never a raw argv vector or a shell string. The agent constructs the `limactl` command line itself from those typed fields with hardcoded flags per subcommand; it never `exec`s a caller-supplied string and never invokes a shell.
- **Agent-side re-validation of every field.** The agent independently validates: VM name against a strict regex (`sandbox-<session-id>` / `sandbox-base` shapes only), every path argument absolute with no `..` traversal and confined to the operator's own `LIMA_HOME` subtree, numeric fields (cpus/memory/disk) within sane ranges. A field that fails validation is rejected, not clamped.
- **Agent verifies the work is for its own uid.** The agent learns its uid from `getuid()`, **not** from the daemon's framing, and **rejects any request whose target `op_uid`/`LIMA_HOME` does not match its own uid** — the macOS analog of the helper's independent `--op-uid` gate (`resolve_op_uid` / `op_uid_in_sandbox_group`). So even a daemon routing bug (or a reused connection after a uid recycle) cannot make operator A's agent act against operator B's tree.
- **Networking is daemon-authored, never agent-constructed.** For `Create`, the daemon renders the **complete** `lima.yaml` — including the `networks: [{socket: …/slot-<n>.sock}]` stanza for the slot it allocated — and passes it as the op's payload (it cannot write the file directly: the operator's `LIMA_HOME` is `0700` operator-owned). The agent **re-validates** the rendered config — VM name and every path confined to its own `LIMA_HOME` (as above); the gateway-facing NIC is exactly the expected socket_vmnet `socket:` entry; **no additional NICs** beyond the socket_vmnet NIC and Lima's one mandatory management NIC; no `vmType` override — then writes it **verbatim** and runs `limactl create`. The agent never assembles networking from typed fields. **Crucially, the egress lockdown of the mandatory management NIC lives in the qemu-wrapper, not the YAML** — Lima auto-adds the `user`/slirp `eth0`, so the agent cannot validate `restrict=on` by inspecting the rendered `lima.yaml`. The brokered `Create`/`Start` payload therefore includes the **`--qemu-wrapper` path**, and the agent **asserts it will launch with that wrapper** (and that the wrapper is the sandboxd-shipped, root-owned one that injects+verifies `restrict=on`); the wrapper's own fail-closed check + the **broker-mediated** post-boot verification (the *agent* reads the wrapper marker / QMP, since the QEMU process and its QMP socket are operator-owned and unreadable by the `_sandbox` daemon — § vzNAT and SLIRP) are what actually guarantee `restrict=on`. This keeps the egress-topology decision in the daemon (so a daemon-routing bug, not just the agent, is what validation guards against) and keeps the agent's privileged surface minimal and auditable. (Note the scope of what this defends — § Trust model: it guards against a *buggy daemon*, not a *malicious agent*, which is out of the egress threat model.)
- **NON-FEATURES (explicit, mirroring the helper):** no argv pass-through; no shell; no `~`/env expansion of caller-supplied values; no path outside the operator's `LIMA_HOME`; no operation not in the enum; no acting on a uid other than the agent's own; no agent-constructed networking. This block is the load-bearing review surface — it must exist, and be reviewed, exactly as the helper's does.
- **One-shot vs streaming ops.** Most ops are request→response (the agent runs `limactl`, returns stdout/stderr/exit-code framed back over the channel). **`GuestSocat`** is the exception: it is a **long-lived streaming op** — the agent execs `limactl shell <vm> -- socat - TCP:127.0.0.1:5123` and the daemon holds the resulting byte-pump open for the guest-agent session's lifetime (the macOS analog of the `SessionRuntime::guest_transport` Lima pipe). The wire protocol must frame this as a bidirectional stream over the broker channel (e.g. a multiplexed sub-stream), distinct from the one-shot request/response framing, and the agent must still enforce the same VM-name/op-uid validation before opening it. (The SSH *proxy* byte-mover is **not** carried over the broker — for a Lima VM the daemon dials `127.0.0.1:<sshLocalPort>` on host loopback directly; § M18 proxy byte-mover.)

#### Login-session constraints (the cost of this model)

This model is correct **only because the macOS target is interactively-logged-in Macs** (§ Overview / Non-goals). Two consequences are load-bearing and must be documented for operators:

1. **An operator's limactl work is available only while that operator is logged in** (their agent is checked in). If the daemon needs to act for operator N whose agent is not connected, it returns an actionable error (`session agent for <user> is not running — log in / re-login`) rather than silently failing. The daemon **cannot** summon a logged-out operator's agent (that would need root for `launchctl asuser`, which it does not have).
2. **Sandbox VMs are login-scoped.** A QEMU VM is launched by `limactl` under the operator's agent, inside the operator's login session; on logout, the session is torn down → the VM stops. Sessions therefore **stop on logout and resume on re-login** (the daemon reconciles each operator's VMs when their agent re-checks-in — § Daemon startup / Failure handling). The **gateway** Lima instance (system daemon, `_sandbox`) persists across logouts. This gateway-persists / sandbox-VM-login-scoped asymmetry is the accepted trade-off for eliminating the privileged pivot.

**Scope of the GUI requirement — full backend only; lite mode works over SSH.** The Aqua-login requirement is **not** because HVF needs a GUI: the gateway Lima instance launches QEMU+HVF+socket_vmnet from a *sessionless* `_sandbox` `LaunchDaemon`, proving VM-launch capability is GUI-independent. The requirement exists because the per-operator agent must run `limactl`/QEMU **as the operator** (operator-uid ownership of the per-operator `LIMA_HOME`) and must be in a GUI session for the **TCC consent path** (§ SIP and TCC) — and a LaunchAgent only loads in an Aqua session. Consequently:

- The **full (Lima VM) backend** requires the operator to be logged into the GUI. Over an SSH-only login (no Aqua session) the agent never checks in, so full-backend `create`/`start`/`stop` for that operator return the actionable error above. This is consistent with the stated target (interactively-logged-in Macs) and is **not** a regression for headless servers, which are an explicit Non-goal.
- The **lite (container) backend is unaffected by login state.** Lite sessions are driven entirely by the system daemon (`_sandbox`) over the forwarded gateway Docker socket (`ContainerRuntime`, § M11) — they use no `limactl`, no operator agent, and no socket_vmnet slot — so **lite mode works over SSH / without a GUI session.** An SSH-only operator therefore retains the full lite-mode workflow; only the VM backend is GUI-gated.

Running the **full backend headless** (no GUI login) is an **accepted limitation**, not a planned feature — consistent with the interactive-dev-Mac target and the headless-multi-tenant Non-goal (§ Overview). SSH-only operators use lite mode. It is technically feasible (load the agent in a non-Aqua per-user session), but TCC-protected `shared:` still would not prompt and the demand isn't there for the stated target; revisit only if that changes.

#### Trust model

Cross-operator isolation is **OS-uid-enforced and stronger than the Linux helper model**: each operator's agent is a distinct process running as a distinct uid, touching only that operator's per-operator `LIMA_HOME` (`0700`, operator-owned). There is no shared privileged component that could be coaxed into acting for the wrong operator — the failure mode "helper pivots to the wrong op-uid" cannot exist because there is no pivot. The daemon authenticates each agent by kernel-supplied peer-cred uid; `_sandbox`-group membership gates who may enroll/connect at all. The system daemon never holds elevated privilege, is never setuid, and is not run as root — same posture as Linux, reached without a setuid binary.

**What the egress guarantee is scoped against (guest, not operator).** sandboxd's unbypassable-egress promise is enforced **against the guest** — untrusted code running *inside* the sandbox VM cannot change its own NICs or routes, so it has no path off the isolated socket_vmnet segment except through the gateway. It is **not** scoped against a malicious *operator*: on macOS, as on Linux, `qemu` runs **as the operator**, so an operator — or malware running with the operator's privileges — could give their own VM a `user`-mode/SLIRP netdev and bypass the gateway for *their own* sandbox. This is unpreventable while qemu runs as the operator and is **identical on both platforms**; the operator is the *beneficiary* of egress control (they run untrusted agents inside and rely on the guarantee), not its adversary. The blast radius of such self-sabotage is strictly the operator's **own** sessions — per-uid `LIMA_HOME` and the daemon never cross-routing one operator's work to another's agent mean a rogue agent can never weaken or observe another tenant's sandbox. The broker's *daemon-authored networking* rule (§ Broker protocol) and agent-side validation therefore guard against a **buggy daemon**, not a malicious agent — the latter is out of the egress threat model by this boundary.

**Broker channel authenticates the uid, not "the genuine agent."** Because the broker socket admits any process running as an enrolled operator (the kernel peer-cred uid is the gate), a non-agent process running with the operator's privileges can speak the protocol and even win the last-writer-wins check-in. This is acceptable under the boundary above: such an impostor has exactly the operator's privileges — which already include running `qemu`/`limactl` directly — so it can only affect *that operator's own* sessions, never another tenant's. The daemon must not (and does not) make any **cross-session** safety decision contingent on agent-*reported* state; cross-session isolation rests on per-uid `LIMA_HOME` and the slot/segment topology, never on believing an agent's claims about what it did.

**TCC bonus.** Because the agent runs in the operator's Aqua session, it *can* obtain TCC consent — so `shared:` workspaces into TCC-protected dirs (`~/Documents`, …) become workable via a normal one-time prompt the operator sees, rather than silently failing. See § SIP and TCC.

**No launchd hardening hazard.** Unlike the Linux `sandboxd.service` (which must omit `NoNewPrivileges`/`ProtectHome` so the kernel honors the setcap helper's file capabilities), macOS has no setuid/setcap binary to protect, so no analogous launchd key constrains the design.

---

## Gateway Lima instance

sandboxd manages a single Lima instance named `sandboxd-gateway` that serves as the host for all gateway containers across all sessions. This instance runs a Linux VM on macOS and exposes Docker to the macOS host via Lima socket forwarding.

**Ownership: daemon, not per-operator.** Unlike per-session sandbox VMs (which are owned by the operator's uid under the operator's `LIMA_HOME`), the gateway Lima instance is *shared daemon infrastructure*. It lives under the daemon's own `LIMA_HOME` (`/var/lib/sandboxd/<_sandbox-uid>/lima/`) and runs as `_sandbox`. limactl operations on it run as `_sandbox` itself: on macOS the daemon runs `limactl` **directly** (it already *is* `_sandbox` — the `op_uid == _sandbox` degenerate case of the § operator-execution seam, with no agent involved), on Linux via the lima-helper pivoted to `_sandbox`'s own uid. There is one gateway instance per daemon regardless of how many operators are active; per-operator isolation happens at the sandbox-VM and macvlan-segment layers, not at the gateway-instance layer.

### Lima, managed directly (no Colima)

sandboxd drives Lima itself (via the operator-execution seam → `limactl`); it does not use Colima. Three reasons:

1. **N pre-attached NICs**: the gateway instance requires N `networks:` entries (one per pool slot) in the Lima YAML. Colima's CLI does not expose this level of control. Working around it by writing to Colima's internal files is fragile.
2. **Opinionated conflicts**: Colima makes assumptions about Docker daemon configuration, socket paths, and VM lifecycle that may conflict with sandboxd's requirements.
3. **Full control**: sandboxd already manages Lima VMs directly (through the helper). The gateway instance is another Lima VM — consistent with the existing architecture.

Lima's socket forwarding feature (used by Colima internally) is a documented Lima primitive. We use it directly.

### Instance name and paths

| Resource | Path |
|---|---|
| Lima instance name | `sandboxd-gateway` |
| Daemon's `LIMA_HOME` | `/var/lib/sandboxd/<_sandbox-uid>/lima/` |
| Lima instance directory | `/var/lib/sandboxd/<_sandbox-uid>/lima/sandboxd-gateway/` |
| Docker socket (guest) | `/var/run/docker.sock` |
| Docker socket (host, forwarded) | `/var/lib/sandboxd/<_sandbox-uid>/lima/sandboxd-gateway/gateway-docker.sock` |

The gateway instance is managed by the daemon as `_sandbox` (directly on macOS — the daemon already *is* `_sandbox`; via the lima-helper pivot to `_sandbox`'s own uid on Linux), with `LIMA_HOME=/var/lib/sandboxd/<_sandbox-uid>/lima/`. The Lima YAML uses `{{.Dir}}/gateway-docker.sock` which Lima resolves to the instance directory. sandboxd derives the forwarded-socket path at startup by joining the daemon `LIMA_HOME` with `sandboxd-gateway/gateway-docker.sock`. This is a daemon-internal detail, not user-configurable.

### Lima template structure

The gateway Lima instance template is generated by sandboxd at daemon startup and written to `/var/lib/sandboxd/<_sandbox-uid>/lima/sandboxd-gateway/lima.yaml` before `limactl start` is called (if not already present).

```yaml
vmType: "qemu"          # NOT vz — socket_vmnet attaches to QEMU, not VZ (§ vmType and network)
minimumLimaVersion: "1.2.0"

images:
  - location: "https://cloud-images.ubuntu.com/releases/noble/release/ubuntu-24.04-server-cloudimg-arm64.img"
    arch: aarch64
# Apple Silicon only on macOS — no amd64 image entry needed.
# QEMU uses HVF acceleration automatically on Apple Silicon (arm64-on-arm64, native CPU).

cpus: 2
memory: "2GiB"
disk: "20GiB"

# N socket_vmnet NICs — one per pool slot.
# Count is determined by max_macos_sessions config (default 8).
# Fixed at instance creation: Lima attaches `networks:` NICs when it creates the
# instance and has no supported way to add a NIC to an already-created instance;
# rebuilding the gateway to add one would disrupt all live sessions.
networks:
  - socket: /var/run/sandbox/vmnet/slot-0.sock
  - socket: /var/run/sandbox/vmnet/slot-1.sock
  # ... through slot-(N-1).sock — one per pool slot (unmanaged socket_vmnet attach)

# Expose the guest Docker socket to the macOS host.
portForwards:
  - guestSocket: "/var/run/docker.sock"
    hostSocket: "{{.Dir}}/gateway-docker.sock"

containerd:
  system: false
  user: false

provision:
  - mode: system
    script: |
      # Install Docker Engine from Ubuntu's own packages (the `docker.io`
      # package) — NOT the docker.com apt repo / `docker-ce`. This matches the
      # Linux base/gateway provisioning (`lima.rs`, since commit 8bacb1b): no
      # extra apt source, fewer moving parts, and it works offline-after-mirror.
      # Wrapped in a retry loop because Lima slirp can drop packets under
      # concurrent apt fetches.
      until apt-get update -qq && apt-get install -y docker.io; do
        echo "apt retry..." >&2; sleep 5
      done
      systemctl enable docker
      systemctl start docker
      # Make the Docker socket group-accessible to the forwarding user, NOT world-writable.
      # The gateway VM's Docker daemon is root-equivalent *inside the VM*; a world-writable
      # socket would let any process in the gateway VM (incl. a compromised gateway container)
      # reach Docker and escalate to root-in-gateway-VM, defeating "the gateway pipeline runs
      # outside the VM, the agent can't tamper with it" for ALL sessions at once. Restrict to
      # the lima/docker group that the portForward runs as:
      groupadd -f docker
      chgrp docker /var/run/docker.sock
      chmod 660 /var/run/docker.sock   # was 666 — never world-writable
  - mode: system
    script: |
      # Clamp eth0 (the slirp/Lima management NIC) MTU to 1280.
      # Lima/slirp doesn't relay host PMTU into the guest; on paths with
      # PMTU < 1500 (PPPoE, WiFi, VPN) guest TCP segments get silently
      # dropped. 1280 is the IPv6 minimum — safe on all paths. The
      # socket_vmnet NICs (lima0…) use native L2 MTU and are unaffected.
      # (Clamp by NIC *name* — eth0 is the slirp/management NIC — never by
      # interface index; QEMU virt PCI ordering does not guarantee eth0=index 0.)
      install -m 0600 /dev/stdin /etc/netplan/99-sandbox-mtu.yaml <<'EOF'
      network:
        ethernets:
          eth0:
            mtu: 1280
      EOF
      netplan apply
```

The template is minimal: Docker Engine plus a little network hardening (the MTU clamp above, and the two items below), and nothing else — no agent tooling, no workspace, no vsock listener, no sandbox-specific provisioning.

Two further network-hardening items beyond the `eth0` MTU clamp:

- **IPv6 disabled on the socket_vmnet NICs and the macvlan.** The in-container ruleset already drops `ip6` (§ networking), but the gateway VM's own `lima0…` socket_vmnet NICs and the per-session macvlan should also have IPv6 disabled (`net.ipv6.conf.<nic>.disable_ipv6=1`) so a guest cannot emit IPv6 RAs / link-local multicast onto the segment to reach a neighbor. (The task-A spike confirmed IPv4 inter-segment isolation holds; disabling IPv6 closes the parallel link-local/RA path for single-stack hygiene.) Single-stack IPv4 end-to-end, mirroring the Linux model.
- **MSS clamping on the gateway's forwarding path.** The VM-facing side runs native L2 MTU (1500) while `eth0` is clamped to 1280, so the gateway container's nftables ruleset clamps forwarded TCP to the path MTU (`tcp option maxseg size set rt mtu`), preventing large segments from black-holing on the 1280 uplink. This lives in the gateway nft ruleset sandboxd injects, not the VM netplan.
- **Socket_vmnet NICs: explicit no-DHCP, link-up only (avoid boot stall).** A network-identifier segment has **no DHCP** (§ Subnet allocation), but Ubuntu's systemd-networkd will, by default, attempt DHCP on every unconfigured NIC and **block boot** (`wait-online`) on the N `lima0…` socket_vmnet NICs that will never get a lease. The gateway template's provisioning must therefore render netplan for each socket_vmnet NIC as `dhcp4: no` + `optional: true`, with **no L3 address** (the macvlan parent `B+2` is link-only — Docker brings the macvlan up). Symmetrically, the **sandbox VM's** cloud-init renders its single socket_vmnet NIC as `dhcp4: no`, static `B+4`, default route → `B+3` (no `wait-online` on it). Without this, the gateway VM (N NICs) and sandbox VMs hang at boot waiting for DHCP that never comes.

### Lifecycle

| Event | Action |
|---|---|
| Daemon startup, instance absent | Generate template → `limactl create sandboxd-gateway` → `limactl start sandboxd-gateway` → wait for forwarded socket readiness |
| Daemon startup, instance present and running | Verify forwarded socket accessible → proceed |
| Daemon startup, instance present but stopped | `limactl start sandboxd-gateway` → wait for socket |
| Pool size config changed (requires restart) | See Pool resize section |
| Daemon shutdown (all sessions stopped) | `limactl stop sandboxd-gateway` |
| Daemon shutdown (sessions still running) | Leave instance running; stop on next clean shutdown |

The gateway Lima instance is **persistent** — it is not torn down between daemon restarts unless explicitly requested. Stopping and recreating it is expensive (~30s) and unnecessary.

### Upstream DNS resolver discovery

The gateway container's CoreDNS forwards permitted queries to `127.0.0.11` — Docker's embedded resolver inside the gateway Lima VM. The full chain on macOS is:

1. macOS host's primary DNS resolver(s) (set by the active network service, visible via `scutil --dns`).
2. Lima auto-detects the host resolvers via `scutil --dns` at VM boot and writes the discovered nameservers into the gateway Lima VM's `/etc/resolv.conf`.
3. The gateway Lima VM's Docker daemon reads `/etc/resolv.conf` and exposes those upstreams via its container-local embedded resolver at `127.0.0.11`.
4. CoreDNS in the gateway container forwards to `127.0.0.11` (unchanged from the Linux configuration in `networking/gateway/Corefile`).

**sandboxd does no DNS-specific work on macOS.** The existing CoreDNS `forward . 127.0.0.11` directive works as-is because Lima + Docker between them propagate the host's resolver configuration end-to-end.

**Known limitation:** macOS's per-service / per-domain DNS (split DNS configured via `scutil` for VPN profiles, search domains per network service) is collapsed by Lima to a single set of primary resolvers. Operators with complex VPN-driven split DNS may see some internal hostnames fail to resolve inside sandboxes. The escape hatch: edit the gateway Lima YAML to add an explicit `dns:` stanza listing the required resolvers. This is rare enough to be a troubleshooting-docs item, not a daemon configuration knob.

**Resolver staleness across host network changes.** Because the gateway VM's `/etc/resolv.conf` is populated from `scutil --dns` **at VM boot** and the gateway instance is **persistent** (it survives across logouts and is not recreated per session), an operator who changes networks (home → office → VPN) while the gateway stays booted keeps the *boot-time* upstream resolvers — which can then be stale, breaking resolution for **all** sessions until refreshed. Remedy: re-read `scutil --dns` and rewrite the gateway VM's resolvers (a `sandbox doctor`/CLI trigger, or — bluntly — restart the gateway instance). Wake-from-sleep is a common trigger for this (§ Reboot and wake-from-sleep). Surfaced as a troubleshooting item; not auto-tracked against host network-config changes in the first cut.

### Readiness check

After `limactl start`, sandboxd polls the forwarded socket path with `docker -H unix://<socket> info` at 2-second intervals with a 60-second timeout. Only after this succeeds does sandboxd proceed to session recovery or accept new session requests.

---

## socket_vmnet pool

### Purpose

socket_vmnet instances provide isolated L2 segments. Each instance is an independent virtual switch with its own /29 subnet — the macOS equivalent of a Linux per-session Docker bridge. The pool is pre-provisioned at daemon startup because **Lima fixes a VM's `networks:` NIC set at instance-creation time** and offers no supported way to attach a NIC to an already-created instance. (QEMU *can* hotplug netdevs at the monitor level, but Lima does not drive that, and depending on an unsupported path would be fragile.) Dynamic per-session NIC attachment to the gateway instance is therefore impossible without recreating it — which would disrupt all live sessions. The pool pre-attaches all N NICs at startup.

### Instance naming

Each pool slot is a socket_vmnet **daemon** `io.sandboxd.vmnet.<n>` owning the socket `/var/run/sandbox/vmnet/slot-<n>.sock`. There are no Lima *network names* to collide with a developer's setup — VMs attach by socket path, and the sockets live in sandboxd's own `/var/run/sandbox/vmnet/` namespace (distinct from Lima's `/var/run/lima/` and Homebrew's `/opt/homebrew/var/run/socket_vmnet`).

### Subnet allocation

/29 subnets carved from a configurable base range, default `10.209.128.0/24` (distinct from Linux's default `10.209.0.0/24` to avoid conflicts in dual-boot or shared-config scenarios). A /24 holds 32 /29 subnets; the default pool of 8 sessions uses 8 of them. **Slot *n* occupies the /29 at base `B = 10.209.128.0 + 8·n`** (slot 0 → `.0/29`, slot 1 → `.8/29`, slot 2 → `.16/29`, …). The address roles below are **relative to that per-slot base `B`**, not absolute — the role table is the *rule*, applied per slot:

| Offset in slot's /29 | Role |
|---|---|
| `B+0` | Network address |
| `B+1` | **Host-side vmnet gateway** — each `--vmnet-network-identifier` segment gets its own host bridge (`bridgeN`) carrying this address (spike-confirmed). Reachable on-link by the guest, but host mode provides **no internet transit**, and the guest's management `eth0` is `restrict=on` — so it is not an egress path (§ vzNAT and SLIRP) |
| `B+2` | Gateway Lima VM's slot NIC (the macvlan parent) — brought **link-up only** by gateway-VM provisioning; a macvlan parent needs no L3 address |
| `B+3` | Gateway container IP — assigned **statically** by Docker macvlan (`--ip`) |
| `B+4` | Sandbox VM IP — assigned **statically via cloud-init** (no DHCP on the segment); its default route is set to `B+3` |
| `B+5 … B+6` | Unused |
| `B+7` | Broadcast |

(Worked example, slot 2 with `B = 10.209.128.16`: gateway container `B+3 = .19`, sandbox `B+4 = .20` — matching the `sandbox inspect` example below. Both are assigned statically; the socket_vmnet daemon for slot *n* runs in network-identifier mode with no DHCP, so it has no `--vmnet-gateway`/`--vmnet-dhcp-end`.)

A **/29** is allocated per slot. The task-A spike confirmed the L3 participants: the host-side vmnet gateway (`B+1`, on the segment's own `bridgeN`), the gateway container (`B+3`), and the sandbox VM (`B+4`); the macvlan parent (`B+2`) is link-only. Three host addresses plus network/broadcast do not fit a /30 (2 usable), so **/29 is required** — not merely headroom. A /24 holds 32 /29 subnets, far more than the default pool of 8. The gateway container communicates with the sandbox VM across the socket_vmnet L2 segment via the macvlan interface; macvlan `private` mode permits communication with external L2 hosts (the sandbox VM) while preventing macvlan-to-parent and macvlan-to-macvlan traffic.

The gateway container IP (`B+3`) serves as the VM's default route and DNS resolver address — identical to the Linux model. **Note on shared `NetworkInfo` fields:** macOS stores these in the same `gateway_ip`/`vm_ip` columns as Linux, but the *address roles differ per platform* — on macOS they hold the `B+3`/`B+4` offsets of a /29, whereas Linux's /28 layout puts the gateway at `.2` and VM at `.3`. The field names are shared; the per-platform semantics are not.

#### Gateway → internet egress (full backend)

The socket_vmnet slot segment is intentionally **isolated** (`--vmnet-mode=host` + a unique per-slot `--vmnet-network-identifier`): it carries only the sandbox-VM ↔ gateway-container link and has **no NAT to the internet** — host mode does not route to external networks, and macOS does not IP-forward by default. The sandbox VM's slot NIC is given a **static** IP (`B+4`) and a **default route explicitly set to the gateway container (`B+3`)** via cloud-init — *not* a DHCP-provided default (there is no DHCP on a network-identifier segment). The VM also carries Lima's mandatory management NIC (slirp `eth0`), but it is **`restrict=on`** (§ vzNAT and SLIRP) so it cannot egress — leaving the gateway as the only path to the internet. The gateway container then needs a **second, separate interface for its own upstream egress** — its macvlan child on the slot segment is `private` mode, which blocks macvlan→parent, so the gateway *cannot* egress over the VM-facing NIC.

> **Threat-model note — on-link neighbors vs. the gateway.** "Default route = gateway" constrains *routed* (off-segment) traffic, but every host on the /29 is also an **on-link** neighbor the guest can address directly without traversing `B+3`. The spike confirmed the segment **does** carry a host-side vmnet gateway (`B+1`, on a per-identifier `bridgeN`), and the guest *can* reach it on-link — this is **not** filtered by the gateway container's nftables (on-link traffic never enters the gateway netns). Two facts make it a non-bypass: (1) **host mode provides no internet transit** — `B+1` is a dead-end vmnet bridge, not a route to the outside, **provided the macOS host is not IP-forwarding**; and (2) the guest's *other* NIC, the slirp `eth0`, is **`restrict=on`** (§ vzNAT and SLIRP), so it cannot egress either. So a guest reaching `B+1` is a host-local attack-surface consideration (the macOS host's own vmnet bridge), not an egress bypass of the core promise.
>
> **Enforced invariant — host IP-forwarding must be off.** Fact (1) is *conditional*: if `net.inet.ip.forwarding=1` on the host (which third-party software — Docker Desktop, some VPN clients, Internet Sharing — can enable), the host could route a guest's on-link `B+1` traffic off-segment, and that path is invisible to the gateway nft (it never enters the gateway netns). The spike confirmed `B+1` exists but did **not** test it as a dead-end under forwarding=1, so the daemon must **not** assume it. **The daemon asserts `sysctl net.inet.ip.forwarding == 0` at startup** (and `sandbox doctor` checks it), refusing to start / surfacing a hard error if forwarding is enabled; enabling host IP-forwarding **voids the egress guarantee** and is documented as unsupported. (Disabling `restrict=on`'s sibling, `net.inet.ip6.forwarding`, is implied by the single-stack-IPv4 posture; assert both.) **Inter-segment isolation** (a guest on slot-N reaching slot-M) is **spike-confirmed absent**: distinct per-identifier bridges, and a same-subnet ARP across identifiers fails.

The gateway container therefore has **two NICs**:

1. **VM-facing** — `macvlan(private)` child of the gateway Lima VM's socket_vmnet NIC for this slot, IP `B+3`. The sandbox VM's traffic arrives here and is DNAT'd to the local Envoy/mitmproxy listeners (DNS to CoreDNS). This NIC is *not* the gateway's default route.
2. **Upstream egress** — a NIC on a shared NAT-masqueraded Docker **bridge** (`sandboxd-egress`) that the daemon creates once in the gateway Lima VM at gateway init (daemon startup step 4); this is the gateway container's **default route**. When Envoy/mitmproxy terminate the VM's connection and re-originate it to the real destination (and when CoreDNS forwards a permitted query), that upstream traffic leaves over this NIC → Docker bridge NAT → the gateway Lima VM's **`eth0` slirp/management uplink** → the macOS host's network → the internet. The `sandboxd-egress` bridge is shared across all gateway containers, which is safe: it is the *upstream* (trusted-infra) side only — per-session isolation lives entirely on the VM-facing side (the isolated socket_vmnet slot), and no sandbox VM/container ever touches `sandboxd-egress`.

So the end-to-end path is: **sandbox VM (`B+4`) → gateway container (`B+3`, isolated slot segment) → intercept (nft DNAT → Envoy/mitmproxy, CoreDNS) → re-originated upstream connection → gateway container's bridge NIC → NAT → gateway Lima VM `eth0` → macOS host → internet.** The guest never has a path to `eth0`; only the gateway does, and only for already-policed traffic.

> **Defense-in-depth on the shared `eth0` uplink.** `eth0` is QEMU user-mode SLIRP — the *one* place SLIRP is allowed, because it is the trusted-infra uplink, not a guest NIC (no sandbox VM/container is ever on the `sandboxd-egress` bridge that reaches it). Per-session enforcement lives entirely on the VM-facing side, so a *compromised gateway component* (Envoy/mitmproxy/CoreDNS, or a container escape — § Security posture / Known deltas) would otherwise have an unfiltered path straight out `eth0`, defeating egress control for every session at once. The gateway VM's `eth0` therefore **MUST** carry a baseline egress nft policy (default-drop; allow only the gateway containers' re-originated upstream flows + DNS), applied as part of gateway-VM init (daemon startup step 4, alongside the `sandboxd-egress` bridge), so even a compromised in-VM component cannot freely egress. This is the gateway VM's egress control — distinct from (and mutually exclusive with) the sandbox VMs' `restrict=on`, which cannot be used here because the gateway legitimately *must* egress. It does not change the per-session model; it bounds the shared-chokepoint blast radius.

### Slot lifecycle

| Event | Slot state |
|---|---|
| `session create` | Slot claimed immediately; slot index written to session's `NetworkInfo` in `sessions.db`. The VM is booted as part of `create` — there is no "created but not started" persistent state. |
| `session stop` | Slot released back to pool |
| `session start` (resume stopped) | Fresh slot claimed (any available); Lima YAML updated with new slot name before `limactl start` |
| `session rm` | Slot released if held (idempotent) |

**Slots are not sticky across stop/start.** A session that was on slot 2 may resume on slot 5. The sandbox VM's `lima.yaml` is rewritten before each `limactl start` with the newly claimed slot's `socket:` path.

### Pool exhaustion

If all slots are claimed and a new `start` is requested, sandboxd returns:

```
Error: max concurrent sessions reached (8 running).
To increase the limit, set max_macos_sessions in config and restart sandboxd.
```

No silent degradation. The count reflects **running** sessions only; stopped sessions do not consume slots.

### Initialization

sandboxd owns the socket_vmnet instances as pool infrastructure (peer to the gateway Lima instance). install.sh installs **N root-owned launchd daemons** — `io.sandboxd.vmnet.<n>` for slot `n` in `0..N-1`, generated from `max_macos_sessions` — each running one socket_vmnet bound to that slot's socket and /29 (using the per-slot base `B = 10.209.128.0 + 8·n` from § Subnet allocation):

```
# /Library/LaunchDaemons/io.sandboxd.vmnet.2.plist runs (slot 2):
socket_vmnet --vmnet-mode=host \
  --vmnet-network-identifier=<deterministic-per-slot-UUID> \   # isolated L2 segment; NO DHCP
  --socket-group=_sandbox \                                    # NOT the default "staff" (= every standard user)
  /var/run/sandbox/vmnet/slot-2.sock
```

Each slot's `--vmnet-network-identifier` is a **unique, deterministic UUID** (derived from a fixed sandboxd namespace UUID + the slot index) — unique so the kernel places each slot on its own isolated vmnet network (no cross-slot L2 leakage), deterministic so the identifier is stable across daemon/host restarts. No `--vmnet-gateway`/`--vmnet-dhcp-end`: a network-identifier segment carries no DHCP, so all addresses are assigned statically (§ Subnet allocation). `RunAtLoad=true` starts them at boot; `KeepAlive` restarts a crashed instance. They are independent of sandboxd's own lifecycle — sandboxd never starts/stops socket_vmnet, so at sandboxd startup the instances are already up.

**The unmanaged socket_vmnet attachment is a *per-VM* `networks:` entry — sandboxd writes no `networks.yaml` at all.** Each VM that needs a slot (the gateway instance, and every sandbox VM) carries the socket path directly in its own generated `lima.yaml`:

```yaml
# in the VM's own lima.yaml (gateway instance: one entry per slot; sandbox VM: its claimed slot)
networks:
  - socket: /var/run/sandbox/vmnet/slot-<n>.sock
```

**Empirically verified (macOS 26.4 / Lima 2.1.1 / QEMU 11.0.1, 2026-06-14):** Lima accepts the per-VM `socket:` field and wires the QEMU `-netdev socket` to the running socket_vmnet daemon; the NIC is named **`lima0`** (`lima1`, … for further slots; the management NIC is `eth0`). That spike ran **plain host mode with DHCP**; the chosen design uses **`--vmnet-network-identifier` + static addressing** instead. **The follow-up spike (2026-06-14) confirmed on real hardware:** (a) each unique network-identifier gets its **own isolated host bridge + subnet**, and a guest on one identifier **cannot** reach a guest on another — same-subnet ARP across identifiers fails, so **inter-slot isolation holds**; (b) network-identifier segments provide **no DHCP**, so static addressing is required (as designed); (c) the host-side vmnet gateway (`B+1`) **does** exist per segment, reachable on-link but with no internet transit; (d) Lima's mandatory slirp `eth0` reaches the internet unless set **`restrict=on`**, which hard-blocks guest egress while preserving SSH (§ vzNAT and SLIRP). The `socket:`-attach and `lima0` naming findings hold regardless of mode. **What does *not* work on Lima 2.x:** putting `socket:` under a *named* network in the global `_config/networks.yaml` — Lima rejects it as an unknown field. So there is **no `sandboxd-vmnet-*` named network, and sandboxd writes nothing to any `networks.yaml`** (daemon or per-operator). The segment is a network-identifier-isolated fabric with no DHCP; addresses are static (§ Subnet allocation) and the segment's identity is owned entirely by the socket_vmnet daemon's `--vmnet-network-identifier` flag (above). (Lima's *managed* form — a named `mode: shared/host` network that Lima sudo-spawns — is deliberately not used; see § socket_vmnet access.)

This **eliminates the per-operator-`networks.yaml` mirroring** the earlier draft required: because the socket path lives in each VM's own `lima.yaml` (generated by the daemon at create time), there is nothing to merge into the daemon's or any operator's `_config/networks.yaml`, and a developer's personal `~/.lima/_config/networks.yaml` is never read or touched.

When the gateway Lima instance starts (step 4 of daemon startup) and when a sandbox VM starts (run by its operator's agent on macOS / via the lima-helper pivot on Linux) with its `networks: [{socket: …/slot-<n>.sock}]` entry, Lima simply connects that NIC to the already-running socket_vmnet daemon for slot `n` — it never spawns socket_vmnet.

The prerequisite check for socket_vmnet is: verify the socket_vmnet binary is present at the staged root-owned path `/Library/sandboxd/socket_vmnet` (install.sh stages it from the Apple Silicon Homebrew prefix `/opt/homebrew/opt/socket_vmnet/bin/socket_vmnet`) **and that it plus its ancestry is root-owned and non-writable by non-root** (§ socket_vmnet access — root-exec foothold), and that the N `io.sandboxd.vmnet.<n>` launchd daemons are loaded with their slot sockets present.

### Concurrency

`VmnetPool` is the macOS counterpart to Linux's `SubnetAllocator` (`sandbox-core/src/network.rs`) and follows the same locking pattern:

```rust
pub struct VmnetPool {
    allocated: Mutex<HashSet<u16>>,                                 // claimed slot indices
    max_slots: u16,                                                  // fixed at startup from max_macos_sessions
    networks: Mutex<HashMap<SessionId, (u16, NetworkInfo)>>,         // session → claimed slot + network info
}
```

`VmnetPool` is owned by the daemon and shared between backends via `Arc<VmnetPool>`. It tracks **two distinct things**: the **N socket_vmnet NIC slots** and the **total running-session count** (the `max_macos_sessions` cap, across both backends). `LimaRuntime` claims a NIC slot **and** a session-count token; `ContainerRuntime` (lite) claims **only** a session-count token — it consumes **no** NIC slot (it uses an in-VM Docker bridge, § Pool slot allocation). Keeping the fixed NIC count distinct from the session cap is what lets e.g. 3 Lima + 5 lite sessions run under `N = 8` using only 3 NICs. (The earlier "both backends call `allocate()` for a slot" framing was wrong — lite must not consume a NIC slot, or the mixed case over-counts NICs.)

Other shared writes are already safe without additional locking:

- **No shared `networks.yaml` writes.** The unmanaged socket attachment lives in each VM's own `lima.yaml` (per-VM `socket:`), so there is no daemon-wide or per-operator `networks.yaml` to coordinate writes to. Each sandbox VM's `lima.yaml` is session-local (serialized by its per-session state machine).
- **`docker network create`** uses per-session-id names (unique by construction). Docker daemon handles its own atomicity.
- **`docker exec nft -f -`** writes to per-session nftables state; the per-session state machine in the backend runtime already serializes these.
- **`sessions.db`** uses SQLite WAL mode (existing). Multi-writer-safe.
- **Sandbox VM Lima YAML rewrites** between stop/start are session-local; the per-session state machine serializes them.

---

## Sandbox VM template (macOS)

### Hardware requirements

**Apple Silicon only.** sandboxd on macOS requires an Apple Silicon Mac (M1 or later) running macOS 14 (Sonoma) or later. Intel Macs are explicitly unsupported — the Intel macOS GitHub Actions runner (`macos-13`) has been retired from the CI matrix, so no Intel build is shipped and no Intel-specific testing happens. Apple Silicon was always the strategic target for macOS support, and the Intel population in the dev-machine fleet is shrinking fast enough that maintaining two architectures isn't justified.

macOS 14 is the floor because that is the version we test on in CI (`macos-14` runner). QEMU+HVF and socket_vmnet both work on macOS 13, but the stack sandboxd relies on (QEMU/HVF stability, socket_vmnet, Lima 1.2.0's QEMU paths) is exercised against macOS 14 only.

### vmType and network

The sandbox VM Lima template on macOS uses the **same `vmType` as Linux (`qemu`)** and differs only in its networking attachment and the absence of the Linux process-isolation wrapper:

```yaml
vmType: "qemu"          # same as Linux; HVF-accelerated on Apple Silicon

networks:
  - socket: /var/run/sandbox/vmnet/slot-{slot_index}.sock
```

**Why QEMU and not VZ.** The full backend needs an *isolated L2 segment the gateway can intercept* (§ vzNAT and SLIRP must never be used). The only way to get that on macOS is socket_vmnet — and **socket_vmnet attaches to QEMU, not VZ.** A VZ VM cannot take a socket_vmnet NIC: socket_vmnet speaks QEMU's `-netdev socket` datagram protocol (a `uint32be` length prefix per frame), which is incompatible with VZ's `VZFileHandleNetworkDeviceAttachment` raw-datagram framing; bridging the two is unimplemented ([lima-vm/socket_vmnet#13](https://github.com/lima-vm/socket_vmnet/issues/13), open). So sandbox VMs run under QEMU, where Lima wires the VM's `-netdev socket` straight to the slot's socket_vmnet socket — the historically-supported, well-trodden macOS pairing. (Revisit if VZ ever gains a working socket_vmnet attachment: [#63](https://github.com/Koriit/sandboxd/issues/63).)

The `networks:` entry uses the slot claimed for this session; sandboxd writes only the slot name and Lima handles the socket_vmnet dial. The sandbox VM template includes a single `aarch64` image entry (Apple Silicon only) pointing at the same Canonical cloud image URL the daemon uses on Linux (`https://cloud-images.ubuntu.com/releases/noble/release/ubuntu-24.04-server-cloudimg-arm64.img`). The URL constants are shared with the Linux code path in `sandbox-core/src/lima.rs` — no macOS-specific image hosting or URL.

Per-session sandbox VMs are **per-operator** (under the operator's `LIMA_HOME`). Every `limactl` operation on them — `create`, `start`, `stop`, `delete`, `clone`, `install-guest-agent`, the guest-socat transport — runs via the operator-execution seam (§ Privilege model on macOS): brokered to that operator's agent on macOS (which runs it natively as the operator), through `sandbox-lima-helper` pivoted to that operator's uid on Linux. The VM template, the slot claim, and the cloud-init are generated by the daemon; the seam just runs the resulting `limactl` invocation as the operator.

### vzNAT and user-mode SLIRP must never be used

The sandbox VM must have **no route out except through the gateway**. Two attachments must never be the VM's *general-egress* NIC, and a third (Lima's mandatory management NIC) must be **egress-locked**:

- **vzNAT** (`VZNATNetworkDeviceAttachment`) — VZ's NAT stack (moot now that the backend is QEMU, but called out so the template generator never falls back to it if the backend is ever reconsidered).
- **QEMU user-mode networking / SLIRP as a general-egress NIC** (`-netdev user` without `restrict`) — SLIRP NATs guest traffic straight out via the host; those packets **never arrive on the gateway container's interface**, so nftables PREROUTING DNAT has nothing to intercept and Envoy/mitmproxy see nothing — the egress-control model fails silently. The socket_vmnet `networks:` stanza is therefore **mandatory** as the gateway-facing NIC.

**But Lima's management NIC *is* SLIRP, and it cannot be removed.** Lima reaches the guest (SSH, readiness probes, port-forwards) over a QEMU user-mode NIC (`eth0`). So every Lima VM has a slirp `eth0` *in addition to* the socket_vmnet gateway NIC — on **both** platforms. **Empirically (task-A spike, 2026-06-14), that `eth0` NATs straight to the internet** — a stock Lima VM reaches `1.1.1.1` over it. Merely deprioritizing it by route metric (giving the gateway a lower-metric default route — what the Linux `qmp.rs` guest script does today with `metric 50`) is **not sufficient**: a root-in-guest process can delete the gateway route, or add a more-specific route via `eth0`, and egress freely. **Route preference is not an egress control against a malicious root guest** — and the core promise is explicitly "no bypass *regardless of root in the VM*."

**The fix (cross-platform, spike-verified): the management NIC must be `-netdev user,restrict=on`.** `restrict=on` makes libslirp **drop all guest-initiated traffic to the host and the outside**, while leaving explicitly-configured host→guest forwards (the SSH `hostfwd`) working. Verified on real hardware (macOS 26.4 / Lima 2.1.1 / QEMU 11.0.1): with `restrict=on` the VM still boots and `limactl shell`/SSH work, but the guest **cannot reach the internet via `eth0` even after manually running `ip route add default via <slirp-gw> dev eth0`** (ICMP 100 % loss, TCP refused), while the socket_vmnet gateway segment is unaffected. The gateway NIC thus becomes the **only** egress path, enforced at the QEMU/slirp layer rather than by an overridable route metric. The metric-50 default route stays as a *convenience* (so a well-behaved guest prefers the gateway), but it is no longer the security boundary.

**Scope — `restrict=on` applies to *sandbox* VMs only; the gateway VM's `eth0` is exempt.** The lockdown locks down the management NIC of each **sandbox** VM. It must **never** be applied to the **gateway** Lima instance's `eth0`, which is the system's *sanctioned egress uplink* (gateway container → `sandboxd-egress` NAT bridge → gateway-VM `eth0` → host → internet, § Gateway → internet egress) — restricting it would drop all upstream traffic and sever egress for **every** session at once. The wrapper-injection is therefore gated on **instance kind** (sandbox VM), *not* merely `is_macos`. The gateway VM's `eth0` is bounded instead by the **MUST**-level baseline egress nft policy in § Gateway → internet egress (it is unrestricted-but-policed, never `restrict=on` — the two are mutually exclusive on the same NIC). On Linux this distinction does not even arise (there is no gateway VM — the gateway is a host container), so `restrict=on` there applies to the sandbox VM unconditionally.

**This fix has now LANDED on Linux and is the model macOS mirrors.** On macOS the per-VM QEMU user netdev of each *sandbox* VM must carry `restrict=on`. **On Linux this already shipped** ([#65](https://github.com/Koriit/sandboxd/issues/65), closed by commit `4b134ec`, with the `#66`/`#76` provisioning follow-ups): `lima.rs`'s qemu-wrapper now **rewrites the management slirp netdev to `restrict=on` before QEMU sees the argv**, gated by the `SANDBOX_UNRESTRICTED_SLIRP_FOR_PROVISIONING` env flag — base-image builds intentionally keep *unrestricted* slirp for package installs, and session VMs are restricted once the sandbox bridge is active — with qemu-wrapper unit coverage and a Lima E2E regression that deletes the gateway route and confirms the slirp fallback still cannot reach the internet. **macOS reuses the same wrapper mechanism**; its only deltas are the `--qemu-wrapper`/firmware-path/HVF-via-exec specifics above and the operator-agent indirection. (Earlier drafts framed this as "always carry the socket_vmnet stanza, never the `user` netdev" — that was incomplete: the `user` netdev is *unavoidable* as Lima's management NIC, so the requirement is to **restrict** it, not to omit it. `networking-design.md` is corrected to match.)

*Injecting `restrict=on` via a qemu-wrapper — macOS specifics (spike-learned):*

- **Wrapper selection: use Lima's `--qemu-wrapper <abs-path>` flag** — the same mechanism the Linux backend already uses (`lima.rs` passes `--qemu-wrapper` to `limactl`), **not** `PATH` interposition. A `PATH`-order wrapper is process-global and would also intercept the operator's *personal* Lima/Colima qemu; `--qemu-wrapper` is per-`limactl`-invocation and scoped to sandbox-VM launches only.
- **The injection is an in-place *rewrite*, not an append** (see § The rewrite, below) — this differs from the Linux wrapper, which only *appends* a bridge NIC.
- **Firmware path:** Lima derives the **edk2 firmware search path from the qemu binary's directory**, so the wrapper's dir must expose `share/qemu/edk2-aarch64-code.fd` (e.g. a symlink to the Homebrew firmware) or Lima aborts with "could not find firmware." (Confirmed in the spike.)
- **HVF works through the wrapper:** the (unsigned) wrapper `exec`s the real Homebrew qemu, which is signed with `com.apple.security.hypervisor` and re-acquires the entitlement on `exec` (spike-confirmed: VM booted with HVF via the wrapper).

This **supersedes** the "No Linux seccomp/cgroup wrapper on macOS" note below — macOS needs a *narrow* wrapper to inject `restrict=on` for sandbox VMs, even though the Linux seccomp/cgroup wrapper still does not apply.

**The rewrite (fail-closed).** `restrict=on` is a sub-option of the *existing* `-netdev user` token, not a separate flag — and you cannot add a *second* `user` netdev (QEMU rejects duplicate netdev IDs, and a new id would not be the one bound to `eth0`). So the wrapper cannot *append* (the way the Linux wrapper appends its bridge NIC); it must **rewrite Lima's generated `-netdev user,…` argument in place**. The algorithm: scan the QEMU argv for the management user netdev — the `-netdev` value beginning `user,` that carries the SSH `hostfwd=` sub-option (handling both the single-arg form `-netdev user,…` and the split form `-netdev` `user,…`) — and splice `,restrict=on` into it, **preserving `hostfwd`** (SSH must keep working). It must **fail closed**: if it finds **zero or more than one** `user` netdev, or cannot confirm `restrict=on` is present in the rewritten token, it **aborts the launch** rather than starting a VM with an unrestricted management NIC. A Lima version that stops emitting a `user` netdev, or renames it, therefore fails loudly instead of silently shipping a bypass.

**Post-boot verification (the launch is not trusted blind).** Because the wrapper is host-side string-surgery on Lima-generated argv — fragile across Lima versions — the launch is not assumed to have worked. The wrapper is the *primary* guard (it fails closed, § The rewrite: if it cannot inject `restrict=on` into exactly one `user` netdev it aborts, so a VM that started at all was rewritten) — and it **records the final rewritten netdev token to a marker file** in the instance dir as positive evidence. Before a session is marked `Running` / allowed to carry traffic, that marker is confirmed to show `restrict=on` on the management netdev; if absent, the VM is torn down and the op fails.

**What the landed Linux fix relies on (and what macOS adds).** The Linux fix (`4b134ec`) guarantees the lockdown two ways, which macOS mirrors: the wrapper **fails closed** (§ The rewrite — if it cannot inject `restrict=on` it aborts the launch), and a **Lima E2E regression** boots a session, deletes the gateway default route inside the guest, and confirms the slirp `eth0` still cannot reach the internet. **macOS MUST carry the same E2E regression.** Because the macOS wrapper additionally runs through the operator's agent and rewrites cross-version-fragile Lima argv, macOS **also adds a runtime check** before the session is marked `Running` (create step 13). That check is **cross-uid**: the sandbox QEMU runs as the operator and its QMP socket lives under the operator-owned `LIMA_HOME` (`0700`), unreadable by the `_sandbox` daemon — so it rides the brokered `Start` op (the **agent** reads the wrapper marker / queries the live QEMU — QMP `query-netdev` / HMP `info network` — and returns the `restrict` state; the daemon refuses to mark `Running` unless confirmed). Per the threat boundary (§ Trust model) this guards against a *buggy daemon/wrapper*, not a malicious agent. Detection-after-boot is acceptable *only* because the guest cannot egress before its NIC carries traffic; a silent wrapper failure would otherwise be an undetectable bypass — which is why both the fail-closed wrapper and these checks exist.

### No Linux seccomp/cgroup wrapper on macOS (but a narrow `restrict=on` wrapper IS needed)

On Linux, the sandbox VM template injects a QEMU wrapper script that applies seccomp sandbox flags (`-sandbox on,obsolete=deny,elevateprivileges=deny,spawn=deny`), namespace isolation, and cgroup-based resource limits via `systemd-run`.

macOS also runs a QEMU process — but **none of the *Linux* wrapper applies**: `systemd-run`/cgroups/namespaces are Linux kernel primitives that don't exist on macOS, and QEMU's `-sandbox` seccomp filter is Linux-only (libseccomp). That Linux wrapper-script injection in `LimaManager` must be gated on `is_macos == false`.

macOS does, however, need a **narrow qemu-wrapper of its own** — *not* for seccomp/cgroups, but solely to inject `restrict=on` into the user-mode (management) netdev of each **sandbox** VM (§ vzNAT and SLIRP). It is **not** applied to the gateway Lima instance (whose `eth0` is the egress uplink); the wrapper is wired only for sandbox-VM launches. Without it, a sandbox VM's slirp `eth0` is an internet egress path a root guest can use. macOS guest egress is forced through the gateway by **two** mechanisms together: the network topology (socket_vmnet isolated segment + gateway as the only *routed* path) **and** the `restrict=on` lockdown of the management NIC (so the unavoidable slirp `eth0` cannot egress). The wrapper runs as the operator (QEMU is launched by `limactl` inside the operator's agent) with HVF acceleration; see the firmware-path / HVF-via-exec notes in § vzNAT and SLIRP.

### Resource limits

QEMU-backed VMs get their CPU count and memory ceiling from the Lima template (`cpus`, `memory`), fixed at VM launch. On macOS there is **no runtime resource enforcement** equivalent to Linux's `systemd-run --scope --property=MemoryLimit=...` (cgroups don't exist on macOS), so a runaway VM cannot be throttled mid-session. This is the same delta VZ would have had — a known, accepted delta for the dev-only platform (see Security posture).

### Operator-uid alignment

The post-M18 Linux model runs the VM process at the *operator's* numeric uid (via the helper pivot) and aligns the in-VM `sandbox` user to the same uid via cloud-init, so `shared:` workspace files have correct host-side ownership. macOS reaches the same end (an operator-uid VM process) **without a pivot**:

- **VM process uid.** Because `limactl start` runs inside the operator's own agent — which `launchd` runs *as* the operator — the QEMU VM process on the macOS host runs as the operator's uid (not `_sandbox`), natively. This is what lets a `shared:` 9p mount of the operator's `~/project` be read/written with the operator's ownership.
- **In-VM user alignment.** The base image bakes the guest `sandbox` user at uid:gid `1000:1000`. When the operator's uid ≠ 1000, the daemon emits a cloud-init `provision: mode: system` block — `groupmod -g <op_gid> sandbox; usermod -u <op_uid> -g <op_gid> sandbox; chown -R <op_uid>:<op_gid> /home/sandbox` — so the in-VM user's numeric id matches the host operator. At the default uid 1000 the block is elided (zero-cost single-operator path).
- **SSH key perms.** The helper sets `umask 0o077` before `limactl create`, so Lima writes the per-VM SSH key (`_config/user`) as a plain `0600` file owned by the operator. This satisfies OpenSSH `StrictKeyfileMode` without needing a POSIX/NFSv4 ACL — important because the M18 proxy SSH-port lookup and the cross-user path depend on that key being usable.

This is identical in shape to Linux; the macOS-specific piece is that there is **no pivot at all** — the operator's agent already runs as the operator, so the operator-uid VM process falls out for free. (And because the agent lives in the operator's login session, TCC consent for protected `shared:` paths becomes possible rather than silently denied — § SIP and TCC.)

### Workspace mount type — 9p on both platforms

`LimaManager::generate_template()` emits `mountType: "9p"` for `WorkspaceMode::Shared`. Because **macOS now uses the QEMU backend too** (not VZ), 9p — QEMU's built-in shared-mount type — works on both platforms, so **there is no `mountType` branch**: both Linux and macOS use `mountType: "9p"` with the same `9p: { securityModel, cache }` sub-stanza. (This is a simplification the QEMU decision buys: the earlier VZ-based draft needed a `mountType: "virtiofs"` macOS branch, since VZ doesn't do 9p; under QEMU that branch disappears.)

`WorkspaceMode::Shared { security_model }` (M17) selects the 9p `mapped-xattr`/`none` semantics identically on both platforms, and operator-uid alignment is what makes `mapped-xattr` ownership correct (the QEMU process runs as the operator on macOS just as the helper-pivoted process does on Linux). `securityModel` is honored on macOS exactly as on Linux — no macOS-specific handling. `WorkspaceMode::Local` (rsync-based snapshot, no mount) and `WorkspaceMode::Clone` (in-guest git clone) are platform-independent and require no changes.

### Everything else is identical

The remaining cloud-init provisioning (Docker, agent tooling, hostname, SSH keys, CA certificate injection, resolv.conf) is identical to Linux. The guest OS, agent privilege model, and network configuration are platform-independent. With the QEMU decision, the macOS-vs-Linux template deltas shrink to just two: the **socket_vmnet `networks:` entry** (instead of qemu-bridge-helper) and the **absent Linux process-isolation wrapper** — `vmType` (`qemu`) and `mountType` (`9p`) are now the *same* on both platforms. Everything else, including the operator-uid-alignment cloud-init block, is shared code.

---

## Session lifecycle on macOS

### NIC interface naming inside gateway Lima VM

The gateway Lima instance has N+1 virtio-net devices: one Lima management NIC and N socket_vmnet NICs (one per pool slot). Virtio-net devices are named by the Linux kernel using predictable naming based on PCI slot. Lima adds socket_vmnet NICs to the VM in YAML `networks:` order, and the kernel assigns PCI slots in that same order. Illustrative naming on Ubuntu 24.04 under QEMU (exact names vary by QEMU machine/PCI topology — **sandboxd discovers them at runtime, never hardcodes them**, see below):

- Management NIC (Lima user-mode/slirp, gives the VM internet): `eth0`
- Pool slot 0 (`socket: …/slot-0.sock`): `lima0`
- Pool slot 1 (`socket: …/slot-1.sock`): `lima1`
- Pool slot n: `lima{n}`

(Confirmed on Lima 2.1.1: Lima names socket-attached NICs `lima0`, `lima1`, … in `networks:` order; the management NIC is `eth0`. The earlier draft guessed `enp0sX` — wrong, but moot since the names are discovered at runtime, never hardcoded.)

This pattern reflects PCI bus ordering on Apple Silicon under QEMU's `virt` machine.

sandboxd does not hardcode this mapping. At daemon startup, after the gateway instance is ready, sandboxd discovers the actual interface names by running (as `_sandbox`, since the gateway instance is daemon-owned — directly on macOS, via the lima-helper pivot to `_sandbox` on Linux):

```
limactl shell sandboxd-gateway -- ip -json link show
```

It selects the socket_vmnet NICs **by name** — the `limaN` interfaces (Lima's naming for `socket:`-attached NICs, in `networks:` order), excluding the `eth0` slirp/management NIC — and orders them by their numeric `N` suffix. The resulting ordered list maps directly to pool slots: `lima0` → slot 0, `lima1` → slot 1, and so on. It keys on the interface **name**, never a raw interface index: under QEMU's `virt` machine, PCI ordering does not guarantee the management NIC is index 0, so an index-based "skip the first" heuristic could pick the wrong NIC. (Lima 2.x reliably names `socket:` NICs `limaN`; if a future Lima changes the scheme, the discovery keys on whichever name is not the slirp/default-route NIC.)

The resulting `slot_index → interface_name` map is cached in daemon state and used for all macvlan `--opt parent=` arguments in the current run. If the discovered NIC count does not match `max_macos_sessions`, the daemon does **not** hard-fail startup — it hands off to the pool-resize handler (§ Pool resize handling), which is the single authority on this mismatch: with no running sessions it recreates the gateway to match config N; with running sessions it logs a warning and **continues for this run with the actually-discovered NIC count** (so the daemon always starts and existing sessions keep working). The map and the effective pool size are built from the *discovered* NICs, never blindly from config.

**Operator identity & execution routing (applies to every step below).** At `POST /sessions`, the daemon reads the caller's uid/gid from the API socket peer credentials (`LOCAL_PEERCRED`), stamps them onto the session (`operator_uid`/`operator_gid`, never client-supplied), and ensures the operator's `LIMA_HOME` exists (`ensure_operator_lima_home()`). Every `limactl <...>` below runs via the operator-execution seam: on **macOS**, brokered to the operator's agent (which runs it natively as the operator) — **this requires that operator's agent to be checked in (i.e. the operator is logged in); if it isn't, create is refused with an actionable `session agent for <user> is not running` error**; on **Linux**, through `sandbox-lima-helper --op-uid <operator_uid>`. Every `docker -H <gateway-socket> <...>` targets the gateway Lima instance's forwarded socket and runs as `_sandbox` (the gateway is daemon infrastructure). Lite-mode container sessions additionally pass `--user <operator_uid>:<operator_gid>` (see lite-mode section).

### create

1. Capture operator identity from `LOCAL_PEERCRED`; `ensure_operator_lima_home()` for this operator
2. Allocate session ID
3. Claim vmnet slot from pool; slot index written to session's `NetworkInfo` in `sessions.db`
4. Write session to `sessions.db` with slot info (`backend = 'lima'`, `operator_uid`/`operator_gid`, `vmnet_slot` in NetworkInfo)
5. Generate Lima QEMU template (incl. operator-uid-alignment cloud-init when op-uid ≠ 1000)
6. `limactl create <sandbox-vm>` **via the operator-execution seam (op-uid)** — the daemon-rendered template (step 5) is passed over the broker as a blob; the agent validates it (socket_vmnet-only networking, no SLIRP, paths confined — § Broker protocol) and writes it **verbatim** before running `limactl create` (no VM process yet)
7. Create macvlan network in gateway Lima instance: `docker -H <gateway-socket> network create --driver macvlan --opt macvlan_mode=private --opt parent=<slot-nic-name> --subnet <slot-/29> sandbox-net-<session-id>`
   (network name is **`sandbox-net-<session-id>`** — *not* `sandboxd-net-` — matching `network.rs`'s `docker_network_name` and the prefix the orphan-reaper parses to reclaim leaked networks; a divergent name would leak macvlan networks)
   (`<slot-nic-name>` is looked up from the cached `slot_index → interface_name` map built at daemon startup)
8. Create the gateway container (name `sandbox-gw-<session-id>`, per `container_name()` — the same scheme as Linux; written `<container>` in the commands below) with **two NICs** — an upstream egress NIC and the VM-facing macvlan (§ Gateway → internet egress):
   - `docker -H <gateway-socket> run --name sandbox-gw-<session-id> --network sandboxd-egress --cap-add NET_ADMIN ... <gateway-image>` — attaches it to a NAT-masqueraded Docker **bridge** inside the gateway Lima VM as its **default route** (upstream egress → gateway Lima VM `eth0` → host → internet).
   - `docker -H <gateway-socket> network connect --ip <gateway-ip B+3> sandbox-net-<session-id> <container>` — adds the **macvlan(private)** child facing the sandbox VM. (Macvlan-only would leave the gateway with *no* egress, since `private` mode blocks macvlan→parent.)
9. Inject deny-by-default nftables rules into the gateway container: `docker -H <gateway-socket> exec <container> nft -f -`
   (the container's `--cap-add NET_ADMIN` from step 8 is **required** precisely because `nft` runs *inside* the container here — this is the proven Linux injection path verbatim, `GatewayManager::inject_nftables_ruleset`; sandboxd does **not** inject from the host via `nsenter`. Do not "drop NET_ADMIN" — it would break rule injection.)
10. Wait for gateway components to be healthy (mitmproxy → Envoy → deny-logger → allow-logger → CoreDNS)
11. Inject DNAT rules: `docker -H <gateway-socket> exec <container> nft -f -`
12. `limactl start <sandbox-vm>` **via the operator-execution seam (op-uid)**, launched through the **sandbox-VM qemu-wrapper** that rewrites the management NIC to `-netdev user,restrict=on` (§ vzNAT and SLIRP; gated on instance kind — the gateway instance is *not* wrapped). QEMU runs as the operator. The wrapper fails closed if it cannot inject `restrict=on`.
13. **Verify `restrict=on` before allowing traffic (broker op)** — the agent confirms (wrapper marker / QMP `query-netdev`) that the management netdev carries `restrict=on`, and reports to the daemon; if unconfirmed, tear the VM down and fail. The session is not marked `Running` until this passes (§ vzNAT and SLIRP, post-boot verification). The window between step 12 and this check is VM boot only (no workload yet), and `eth0` egress is already blocked if the wrapper succeeded.
14. Run boot command if specified

**Egress happens-before invariant (load-bearing).** The sandbox VM's socket_vmnet NIC must **never** carry traffic on its slot until that slot's gateway container has applied **both** deny-all *and* DNAT. The step order guarantees this on create — `limactl start` (step 12, the first moment the VM can emit a packet) runs only after deny-all (9), component health (10), and DNAT (11). The same ordering is mandatory on the resume and gateway-recovery paths (below), where the VM may boot onto a *fresh* slot: the gateway container for that slot must be healthy with deny-all+DNAT in place *before* the VM's NIC is attached/started, so the VM's very first egress is already intercepted. (This is why the gateway is brought up before `limactl start` everywhere, not merely on create.)

**Partial-create rollback.** If any step 6–13 fails (e.g. a brokered `limactl` step errors, the agent drops mid-sequence — § Per-operator agent unavailable — or the `restrict=on` verification at step 13 does not confirm), the daemon unwinds in reverse: stop/remove the gateway container, remove the macvlan network, **release the claimed slot**, and mark the session failed — so a half-built create never leaks a slot, a gateway container, or a VM that's up without its gateway. Each unwind step tolerates "not found" (idempotent), mirroring the stop path.

### start (resume stopped session)

1. Claim a fresh vmnet slot (any available — slots are not sticky)
2. Update `sessions.db` with new slot info
3. Update sandbox VM's Lima YAML with new slot name
4. Create macvlan network in gateway Lima instance (same as create step 7)
5. Create and start gateway container, apply deny-all, wait healthy, inject DNAT (same as create steps 8–11)
6. `limactl start <sandbox-vm>` **through the sandbox-VM qemu-wrapper**, then verify `restrict=on` (same as create steps 12–13) — **only after step 5 completes**, per the egress happens-before invariant above; partial-resume failures unwind as in create.

### stop

1. Remove DNAT rules: `docker -H <gateway-socket> exec <container> nft -f -` (flush DNAT chains)
2. `limactl stop <sandbox-vm>`
3. Stop and remove gateway container: `docker -H <gateway-socket> rm -f <container>`
4. Remove macvlan network: `docker -H <gateway-socket> network rm sandbox-net-<session-id>`
5. Release vmnet slot back to pool
6. Update `sessions.db` — clear slot fields, status = stopped

Disk state (Lima VM image) is preserved. The session can be resumed with `start`.

### rm

1. Stop if running (same as stop)
2. `limactl delete <sandbox-vm>`
3. Remove macvlan network if still present (idempotent)
4. Release slot if still held (idempotent)
5. Remove session from `sessions.db`

---

## Daemon startup sequence (macOS)

```
1. Construct the macOS LimaExecutor (AgentBrokerExecutor) and bind the agent-broker channel
   (a group-`_sandbox` unix socket where per-operator agents check in). There is NO lima-helper
   to resolve on macOS. LimaRuntime constructed with is_macos=true; daemon base-dir =
   /var/lib/sandboxd/<_sandbox-uid>; gateway_docker_socket =
   <daemon-LIMA_HOME>/sandboxd-gateway/gateway-docker.sock; GatewayManager constructed with it.

2. Prerequisite checks (fail fast with install instructions if missing):
   a. socket_vmnet binary staged at /Library/sandboxd/socket_vmnet with root-owned ancestry (asserted)
      + the N io.sandboxd.vmnet.<n> launchd daemons active
   b. `limactl` on PATH, version ≥ MIN_LIMA_VERSION (1.2.0)
   c. `docker` CLI on PATH
   d. agent-broker channel bound and listening (per-operator agents check in here as operators
      log in); there is no host lima-helper on macOS
   e. the N io.sandboxd.vmnet.<n> launchd daemons are loaded and their slot sockets under
      /var/run/sandbox/vmnet/ are reachable (sandboxd does not start them — launchd does, at boot)
   f. host IP-forwarding is OFF: `sysctl net.inet.ip.forwarding` and `net.inet.ip6.forwarding`
      both == 0. If either is 1, refuse to start with a hard error — host forwarding would let a
      guest route off-segment via the on-link host vmnet gateway (B+1), voiding the egress
      guarantee (§ Gateway → internet egress, threat-model note). Re-checked by `sandbox doctor`.

3. socket_vmnet pool init:
   - NO networks.yaml is written (daemon or per-operator). The unmanaged socket attachment is a
     per-VM `networks: [{socket: /var/run/sandbox/vmnet/slot-<n>.sock}]` entry embedded in each
     VM's generated lima.yaml at create time (§ socket_vmnet pool § Initialization — verified on
     Lima 2.1.1; the global networks.yaml does NOT accept `socket:`).
   - This step just records the slot→socket-path map (N = max_macos_sessions, default 8) for the
     template generator to embed.
   - socket_vmnet daemons are sandboxd-owned launchd jobs started at boot — NOT by Lima and NOT by
     sandboxd at runtime; sandboxd only connects VMs to the already-running slot sockets.

4. Gateway Lima instance init (run by the daemon directly as _sandbox — no agent, no pivot):
   a. If instance absent: generate template (N NICs) → limactl create → limactl start
   b. If instance present and stopped: limactl start
   c. If instance present and running: verify forwarded socket accessible
   d. Poll gateway-docker.sock with `docker info` until ready (60s timeout)
   e. Discover slot_index → NIC-name map (limactl shell … ip -json link, run directly as _sandbox)
   f. Ensure the shared `sandboxd-egress` NAT bridge exists in the gateway Lima VM
      (docker network create, idempotent) — every gateway container attaches to it for
      upstream egress → gateway Lima VM eth0 → host (§ Gateway → internet egress)
   g. Apply the baseline default-drop egress nft policy on the gateway VM's eth0 (MUST — allow
      only the gateway containers' re-originated upstream flows + DNS; § Gateway → internet egress).
      The gateway VM's eth0 is the egress uplink and is NEVER restrict=on; this nft policy is its
      egress control, bounding a compromised-gateway-component blast radius.

5. Load sessions from sessions.db

6. Reconcile. Two halves, split by what each needs:
   a. **Gateway-side cleanup runs UNCONDITIONALLY for every session** (logged-in or not). The gateway
      containers, macvlan networks, and slot claims live in the daemon-owned gateway Lima instance,
      reachable as `_sandbox` with **no agent involved** — so a logged-out operator's leftover gateway
      container from a pre-logout/pre-reboot run must NOT wait for that operator to log back in. For every
      session whose VM is not currently running (which includes all sessions of not-logged-in operators,
      since sessions are login-scoped): remove its gateway container + macvlan network and release its slot.
      Orphaned gateway containers with no matching session: remove. This prevents logged-out operators'
      gateway containers / networks / slots from leaking until next login.
   b. **VM-side reconcile needs the operator's agent.** For each operator whose agent is checked in, list
      that operator's VMs via their agent and, for each running session, verify the VM is up (mark error
      if not). Operators not logged in are reconciled (VM-side) lazily when their agent next checks in —
      their VMs are down anyway (login-scoped, § Privilege model on macOS); their *gateway-side* state was
      already cleaned in (a).

7. Restore pool state:
   - Mark slots as claimed for running sessions
   - All other slots are available

8. Accept API requests
```

The base VM name used for the golden base image is resolved from `SANDBOX_BASE_VM_NAME` env var at startup (default `sandbox-base`). This is a pre-existing mechanism shared with Linux; macOS uses it identically.

---

## Session store schema changes

The `sessions.db` SQLite schema requires **no new columns** for macOS support. macOS Lima sessions use `backend = 'lima'` (added in V005), the same value as Linux Lima sessions. Platform is not persisted — it is a runtime property of the daemon.

The latest migration at time of writing is **V010** (`add_sshd_ready`). The columns the per-operator model relies on already exist and macOS reuses them unchanged: `operator_uid`/`operator_gid` (V008 — captured from `LOCAL_PEERCRED`/`SO_PEERCRED`, drive the operator-execution seam (helper pivot on Linux, agent routing on macOS) and operator-uid alignment), `ssh_keypair_json` (V007 — the M18 proxy keypair, container backend), and V009/V010 housekeeping (drop legacy operator-less sessions; sshd-ready flag). The macOS implementation **adds no migration of its own** — the only macOS-specific persisted state (the vmnet slot) lives inside the existing `network_info` JSON blob. **The no-migration claim is load-bearing on `NetworkInfo` being persisted as a single serialized-struct blob** (one `network_info` column holding the serialized `NetworkInfo`, added in V002), *not* as discrete per-field columns: only then does adding a new `Option<VmnetSlot>` field with `#[serde(default)]` deserialize cleanly against old rows with no schema change. Confirm against `store.rs` before relying on it; if the layout were ever discrete columns, adding `vmnet_slot` *would* need a migration.

One JSON blob field addition is required.

### `network_info` JSON blob (inside the existing `network_info` column)

The `NetworkInfo` struct gains macOS-specific optional fields. Existing field types match the current code (`String` for IP addresses, matching the JSON serialization convention used throughout the codebase):

```rust
struct NetworkInfo {
    // existing fields (unchanged)
    bridge_name: String,      // Linux: Docker bridge name; macOS: gateway Lima instance NIC name for this slot
    subnet: String,
    gateway_ip: String,       // dotted-decimal, e.g. "10.209.128.3"
    vm_ip: String,             // dotted-decimal, e.g. "10.209.128.4"
    docker_network_name: String,

    // macOS-only; None on Linux and on stopped macOS sessions
    #[serde(default)]
    vmnet_slot: Option<VmnetSlot>,
}

struct VmnetSlot {
    index: u16,                // 0..N-1 (u16 for consistency with SubnetAllocator block_index)
    daemon_label: String,      // "io.sandboxd.vmnet.{index}" (the socket_vmnet launchd job)
    socket_path: String,       // socket_vmnet socket path for this slot (embedded as the VM's `socket:`)
}
```

`vmnet_slot` is `None` for stopped macOS sessions (slots are released on stop). The pool reconstructs its in-memory state at daemon startup from sessions where `vmnet_slot` is non-null.

### `sandbox inspect` output for macOS sessions

`sandbox inspect <session>` surfaces the macOS-specific NetworkInfo addition. The DTO (`SessionDto.network_info`) gains an `Option<VmnetSlot>` field that mirrors the on-disk JSON; absent on Linux sessions, present (when running) on macOS sessions. The CLI's `inspect` output adds three lines under the existing network section when the field is present:

```
Network:
  bridge      lima2                           # gateway Lima NIC for the macvlan parent (slot 2)
  subnet      10.209.128.16/29
  gateway_ip  10.209.128.19                   # gateway container's macvlan IP
  vm_ip       10.209.128.20                   # sandbox VM's IP via socket_vmnet
  vmnet_slot  2 (io.sandboxd.vmnet.2)         # NEW — macOS only
```

`sandbox inspect --verbose` (or `--json`) additionally surfaces the gateway Lima instance's current state from the `/diagnostics` payload: `gateway_lima_state`, `gateway_image_tag_inside_lima`. These are session-independent (every session sees the same daemon-wide values) but worth including for operator triage of "is the gateway healthy."

`sandbox ls` is unchanged on macOS — slot numbers are not surfaced in the list view; operators run `inspect` for slot detail. The list view's existing columns (name, status, backend, workspace) suffice.

---

## Pool resize handling

The gateway Lima instance's NIC count is fixed at creation time (Lima attaches `networks:` NICs only at instance creation; no runtime NIC-attach). Changing `max_macos_sessions` requires rebuilding the gateway instance.

**Procedure when pool size changes:**

1. User updates config and restarts sandboxd
2. Daemon startup detects NIC count mismatch: reads `/var/lib/sandboxd/<_sandbox-uid>/lima/sandboxd-gateway/lima.yaml` and counts `networks:` entries; compares against `max_macos_sessions` from config
3. If **no running sessions** *and* the vmnet daemon set already matches the new N (see the privileged-resize note below): stop gateway instance → delete → recreate with new N → start.
4. If **running sessions exist**: do **not** resize and do **not** hard-fail startup; log a warning and **continue this run with the discovered (old) NIC count**, deferring the new N until all sessions stop:
   ```
   warning: max_macos_sessions changed from 8 to 12 but 3 sessions are running.
   Pool resize requires all sessions to be stopped. Continuing with the current pool of 8;
   stop all sessions and restart sandboxd to apply the new size.
   ```

This is the single authority for a config-vs-actual NIC mismatch at startup — the NIC-discovery step (§ Session lifecycle § NIC interface naming) defers here rather than aborting, so **the daemon always starts** and the *effective* pool size is the count of NICs that actually exist on the gateway instance. There is no live pool resize. This is intentional — the constraint comes from Lima's fixed-at-creation NIC model (no runtime NIC-attach), not a design choice.

**socket_vmnet daemon set must be regenerated too (needs root).** N also governs the `io.sandboxd.vmnet.<n>` launchd daemons (§ socket_vmnet pool § Initialization). Adding/removing those is a privileged operation in the launchd *system* domain — the unprivileged `_sandbox` daemon **cannot** do it on its own. So a pool resize on macOS is not a pure config-edit-and-restart: it requires a sudo step to regenerate + `bootstrap`/`bootout` the vmnet plist set (the daemon detects the mismatch and refuses with guidance to re-run the privileged resize path — e.g. `sudo sandbox-install --resize-pool` / re-running the relevant install.sh step). The daemon's own gateway-instance recreate (steps 3–4 above) happens after the vmnet daemon set matches the new N.

---

## Failure handling

### Gateway Lima instance crash

The gateway Lima instance hosts **all** gateway containers. Its crash affects all active sessions simultaneously — this is the only cross-session *availability* failure mode in the macOS architecture and is an inherent consequence of the platform constraint. (The corresponding cross-session *security* blast radius — a gateway-container escape to the shared in-VM Docker daemon — is covered in § Security posture / Known deltas.)

**Detection:** sandboxd polls `docker -H <gateway-socket> info` every 10 seconds. Three consecutive failures trigger crash recovery.

**Recovery sequence:**

1. Tag all currently-running sessions with in-memory `networking_status = Degraded`. This is **not** a `SessionState` change — the persisted state stays `Running`. `networking_status` is a transient DTO-level field (Healthy | Degraded | Recovering) surfaced by `sandbox inspect` and `sandbox ls --verbose`, derived from in-memory daemon state.
2. `limactl stop --force sandboxd-gateway` (if needed to clear broken state)
3. `limactl start sandboxd-gateway`
4. Poll forwarded socket until ready (90s timeout — longer than the 60s startup budget because a force-stopped-and-restarted instance recovers more slowly than a clean boot; the extra headroom avoids a spurious second recovery cycle)
5. Tag all sessions `networking_status = Recovering`. For each running session (in parallel):
   - `docker -H <gateway-socket> rm -f sandbox-gw-<session-id>` (idempotent — ignore "not found")
   - `docker -H <gateway-socket> network rm sandbox-net-<session-id>` (idempotent — ignore "not found")
   - `docker -H <gateway-socket> network create --driver macvlan ...` (fresh create)
   - `docker -H <gateway-socket> run ...` (fresh container)
   - Re-inject DNAT rules
   - On success: clear `networking_status` (back to `Healthy`). On failure: transition the session to `SessionState::Error` and clear `networking_status`.
6. Sessions that fail individual recovery transition to `Error` and require manual intervention; other sessions continue.

`SessionState` itself is unchanged. The `networking_status` field exists only in the API DTO and in-memory daemon state — no schema migration, no new enum variant in `session.rs`. If the daemon crashes mid-recovery, the next daemon startup's reconcile loop sees sessions persisted as `Running`, re-checks gateway health, and either marks them `networking_status = Healthy` or kicks off recovery again. The in-memory `networking_status` field is rebuilt every daemon startup from gateway-health probes.

Recovery is idempotent because each step either tolerates "not found" errors or starts from scratch after explicit removal.

**Contrast with Linux:** On Linux, gateway containers are independent — a single container crash affects only its session. The Colima-equivalent cross-session failure mode does not exist on Linux.

### socket_vmnet process failure

socket_vmnet instances are sandboxd-owned launchd daemons (`io.sandboxd.vmnet.<n>`) with `KeepAlive`, so launchd **auto-restarts** a crashed instance within its throttle interval. A mid-session crash still manifests transiently as network loss for the VMs on that slot's L2 segment (the segment goes dark until launchd respawns socket_vmnet, which re-attaches to the same isolated network-identifier segment, and the VMs' links recover — addresses are static, so there is no re-DHCP). sandboxd does not independently supervise socket_vmnet — launchd owns the restart — but `sandbox doctor`'s `check_socket_vmnet_running` surfaces a daemon that is crash-looping (failing to stay up), and the failure otherwise surfaces through the gateway container becoming unreachable (triggering the gateway crash recovery path) or through VM disconnection. No separate sandboxd recovery path is defined for bare socket_vmnet crashes — launchd's `KeepAlive` plus the existing gateway/VM failure paths cover them.

### Per-operator agent unavailable (macOS-only)

A failure mode with no Linux analog (Linux invokes the setuid helper per-call; there is no long-lived per-operator process): the operator's agent (§ Privilege model on macOS) is not checked in.

- **Operator not logged in / agent never checked in.** Any operation needing that operator's `limactl` (create, or start/stop of their **Lima VM**) is **refused with an actionable error** (`session agent for <user> is not running — log in`), never silently hung. The system daemon and the shared gateway stay healthy; only that operator's *full-backend* VM ops are blocked. **Lite-mode sessions for the same operator are unaffected** — they run entirely through the system daemon over the forwarded Docker socket (no agent, no `limactl`), so an operator without a GUI session (e.g. SSH-only) can still create and use lite sessions (§ Login-session constraints / scope).
- **Agent crash mid-session.** `launchd` respawns the agent in the operator's session. Because the operator's running VMs are hosted by `limactl` processes under the agent, an agent crash can drop those VMs (segment goes dark / VM stops); on respawn the agent re-checks-in and the daemon reconciles that operator's sessions (dead VMs → `stopped`; operator can resume). This is the same login-scoped lifetime described in § Privilege model — an agent crash is effectively a mini-logout for that operator's VMs.
- **No cross-operator impact.** One operator's agent being down never touches another operator's sessions or the shared gateway — isolation is per-uid.

### Fast user switching, re-login, and duplicate check-in (macOS-only)

Under macOS fast user switching, **multiple operators can be logged in at once**, each with its own Aqua session and its own `io.sandboxd.agent` instance (one per login context). The reconcile loop already iterates `SELECT DISTINCT operator_uid` and brokers per-uid, but three edge cases need explicit handling:

- **Duplicate check-in for one uid.** A re-login (or a second seat) can produce a *second* agent connection for the same operator uid before the first's socket is torn down. The broker resolves this **last-connection-wins**: a fresh check-in for an already-connected uid evicts and closes the prior channel (§ The per-operator agent / check-in). The daemon never fans one uid's `limactl` work across two channels; pushed work always goes to the current connection. **Effect on in-flight streams:** any long-lived `GuestSocat` byte-pump (§ Broker protocol) riding the evicted channel is severed when the prior connection closes — so a re-login drops that operator's active guest-agent transport sessions, which then **reconnect over the fresh channel** (the guest-agent transport already tolerates reconnection). The VMs themselves are untouched; only the broker-carried stream re-establishes.
- **Switched-away (still logged-in) operator.** A fast-user-switch *away* does **not** log the operator out — their Aqua session persists, their agent stays checked in, and `launchd` keeps the agent alive across the switch, so brokered ops still work. Their QEMU VMs **keep running** while switched away — fast user switching does *not* suspend or freeze the switched-away user's processes — so the daemon must **not** treat a switched-away operator's session as failed; it is simply healthy and still running. (Contrast a real logout, which tears the session down and stops the VMs — the login-scoped case.)
- **Stale captured uid / uid recycle.** `LOCAL_PEERCRED` is captured at connect time and is not live (§ M13). The broker connection is long-lived, so the daemon must not trust a captured uid indefinitely: the heartbeat/liveness ping drops a dead connection promptly, and a new check-in (which re-reads the peer uid at `accept()`) is what re-establishes a uid's channel after logout/login — the daemon ties VM-side reconcile (startup step 6b) to a *fresh* check-in event, not to a possibly-stale long-lived connection.

### Individual gateway container crash (inside gateway Lima instance)

Same recovery as Linux: sandboxd detects via Docker container events, restarts the gateway container for that session only, re-injects rules. Other sessions are unaffected.

### Slot leak detection

At daemon startup, sandboxd checks for slot leaks:

- Slots held by sessions in `stopped` state are released (stopped sessions must hold no slot).
- Slots held by sessions that no longer exist in `sessions.db` are released.

sandboxd does not directly health-check each socket_vmnet process — but it does **not** delegate their lifecycle to Lima (the unmanaged model: Lima never starts socket_vmnet). The `io.sandboxd.vmnet.<n>` launchd daemons carry `KeepAlive`, so **launchd** auto-restarts a crashed instance; `sandbox doctor` surfaces one that is crash-looping. A slot is treated as available whenever `sessions.db` shows no running session holding it — and slot reclamation is tied to the **VM-liveness reconcile** (startup step 6b / agent re-check-in): a session persisted `Running` whose VM is confirmed dead has its slot **released**, so a dead-VM slot is not leaked. A claimed slot whose backing socket_vmnet is momentarily down (between crash and `KeepAlive` restart) is a transient dark segment, not a misassignment hazard — the per-slot `--vmnet-network-identifier` is stable, so the slot re-attaches to the same isolated segment on restart.

---

## Security posture

### Layer mapping

| Layer | Linux | macOS |
|---|---|---|
| 1 — Hardware | Intel VMX/EPT | Apple ARMv8 VHE (Apple Silicon) |
| 2 — Hypervisor | KVM kernel module | QEMU + Apple Hypervisor.framework (HVF) — native arm64 CPU acceleration |
| 3 — VM process isolation | QEMU: unprivileged user + PID/mount/IPC namespaces + seccomp (disabled due to qemu-bridge-helper setuid) + cgroup limits | QEMU: unprivileged process running as the **operator's uid** + the HVF VM boundary. macOS has no cgroups/namespaces and QEMU's `-sandbox` seccomp is Linux-only, so there is no host-side process sandbox — isolation rests on the HVF VM boundary and the unprivileged operator uid. Effectively equivalent to Linux, whose seccomp is also disabled. |
| 4 — Device model | 4 virtio devices (net, blk, rng, vsock); USB/display/sound/legacy absent | Same 4 devices; Lima QEMU template only exposes explicitly configured devices |
| 5 — Guest kernel | Stock Ubuntu | Same |
| 6 — Guest OS | Writable root, resource-limited | Same |
| 7 — Agent process | Root inside VM | Same |
| 8 — Inner Docker | Authorization plugin (deferred) | Same (deferred) |
| 9 — Network path | VM gateway NIC → Docker bridge → gateway container; gateway egresses via host Docker NAT → host uplink. (Management slirp `eth0` is `restrict=on` — landed, #65.) | VM gateway NIC → socket_vmnet (isolated slot) → gateway container macvlan (`B+3`); gateway egresses via its NAT bridge → gateway Lima VM `eth0` slirp uplink → host (all inside the gateway Lima instance). Sandbox-VM management `eth0` is `restrict=on` |
| 10 — Proxy pipeline | nftables + mitmproxy + Envoy + deny-logger + allow-logger + CoreDNS | Identical — same container image, same rules, Linux kernel inside gateway Lima instance |
| 11 — Network policy | Abstract policy compiled by sandboxd | Same |

### Known deltas

**Resource limits:** Linux enforces CPU/memory/PID limits on the QEMU process via cgroups (`systemd-run --scope`). On macOS, the QEMU VM gets its CPU count and memory ceiling at launch (from the Lima template `cpus`/`memory`) but there is **no runtime enforcement** — macOS has no cgroups, so a runaway VM cannot be throttled mid-session. macOS is a dev platform; this is an accepted delta.

**QEMU seccomp:** Linux's QEMU seccomp sandbox is disabled in the current implementation (a setuid interaction with qemu-bridge-helper). macOS QEMU has no seccomp at all — `-sandbox` is a Linux-only (libseccomp) feature. So neither platform applies QEMU seccomp; both Layer-3 postures rest on the hypervisor boundary plus the unprivileged VM-process uid. The practical security property is equivalent.

**Shared gateway-VM blast radius (security, not just availability):** On Linux each session's gateway container is an independent host container, so a gateway-container escape compromises the host (already the TCB) without a structural path to *other* sessions' enforcement. On macOS all gateway containers share one Docker daemon inside the single gateway Lima VM, and each carries `CAP_NET_ADMIN` (required for in-container `nft` injection — § create step 9). A gateway-container escape that reached the in-VM Docker daemon could therefore rewrite **every** concurrent session's nft rules and gateway containers — a cross-session *egress-control* compromise, not merely the availability failure noted at § Failure handling. Dropping `NET_ADMIN` does **not** mitigate this: it would break rule injection, and the escape vector is the shared daemon, not the cap. The controls are (a) the gateway container's hardened config (no `--privileged`, read-only rootfs, no host mounts, exactly one added cap), (b) the in-VM Docker socket never bind-mounted into any gateway container, and (c) the forwarded host-side socket being `_sandbox`-only (§ Forwarded Docker socket). This is inherent to the one-gateway-VM-hosts-all-containers model and is an accepted dev-platform delta.

**macOS is dev-only:** These deltas are acceptable because macOS is not a production target. Production runs on Linux.

### Topological controls (identical)

The properties that matter most for the security model are unchanged:

- VM egress is forced through the gateway by **two** mechanisms, neither defeatable by a root guest: (1) the gateway NIC sits on an isolated socket_vmnet segment with **no NAT to the internet** and is the VM's default route; (2) Lima's unavoidable slirp management NIC (`eth0`) is **`-netdev user,restrict=on`** — a QEMU/slirp-layer hard egress block (spike-verified: blocks the internet even when root re-adds the route), *not* a route-metric preference. So there is no internet bypass regardless of root in the VM. (The per-identifier host gateway `B+1` is reachable on-link but is a dead-end — no internet transit.)
- Gateway pipeline runs outside the VM — agent cannot tamper with it
- nftables deny-by-default — no traffic passes without explicit policy
- Per-session L2 isolation — sessions cannot reach each other. On Linux this is the per-bridge guarantee; on macOS it rests on a unique per-slot `--vmnet-network-identifier` — **spike-confirmed** (distinct per-identifier host bridges; a same-subnet ARP across identifiers fails)

---

## Integration with daemon infrastructure (M13–M18)

This spec was originally drafted before M13–M17 landed; M18 (cross-user CLI access + per-operator execution model) landed afterward and is now on `origin/master`. This section maps each piece of that infrastructure onto macOS. The big one — M18 — has already reshaped the daemon's core model (see the reconciliation note at the top); the subsections below are now mostly "macOS reuses the landed mechanism, with these substitutions" rather than "macOS must add this."

### M18 — cross-user CLI access + per-operator model (landed; macOS reuses it)

M18 (see `.tasks/specs/2026-05-24-cross-user-cli-access-design/` and `.tasks/specs/2026-05-29-m18-s10-sandbox-lima-helper-design/`) is the milestone that resolved the latent "CLI can't reach daemon-owned VMs" bug, and it did so by introducing the per-operator execution model this spec now mirrors throughout. What landed, cross-platform:

- **`sandbox-lima-helper`** (Linux) — the daemon never calls `limactl` directly; the helper pivots to the operator's uid. **macOS substitution: no helper at all** — the per-operator agent runs `limactl` as the operator (§ Privilege model on macOS).
- **Per-operator LIMA_HOME** and **operator-uid alignment** (V008 `operator_uid`/`operator_gid`). macOS reuses verbatim (§ Operator-uid alignment).
- **SSH proxy for the six SSH-shaped verbs.** `GET /sessions/{id}/ssh-config` returns the per-session SSH config + key; `GET /sessions/{id}/proxy` is a WebSocket the daemon byte-pipes to the session's sshd. The CLI ships a hidden `sandbox proxy <id>` used as SSH `ProxyCommand`, and maintains `~/.ssh/sandbox/{config,keys/,sockets/}` with a marker-bracketed `Include` in `~/.ssh/config`. `ssh`/`cp`/`sync`/`workspace push|pull`/`git-remote-sandbox` all become standard SSH-client invocations against a `Host sandbox-<id>` alias — external tools (VS Code Remote-SSH, JetBrains Gateway) work unchanged.
- **V007** keypair migration; **lite image gained sshd** and renamed its guest user `agent`→`sandbox` (home `/home/sandbox`).

The daemon's proxy byte-mover, per session type, on macOS:
- **Lima sandbox VM**: the daemon resolves `sshLocalPort` from `limactl list --json` **run via that session's operator agent on macOS (the VM is per-operator) / the lima-helper pivot on Linux**, then dials `127.0.0.1:<sshLocalPort>` directly (Lima binds the forward on host loopback; loopback is reachable cross-uid, so `_sandbox` can dial a port the operator's `limactl` bound). Works like Linux — Lima's host-side port forward is platform-independent.
  - **Known cross-uid exposure (document, don't pretend otherwise).** That same "loopback is reachable cross-uid" property means the Lima SSH forward is reachable by **any local user on the host**, not just `_sandbox` — Lima's forward is a plain loopback listener, not uid-scoped. So the daemon's `/sessions/{id}/proxy` *ownership* check is **not** the boundary protecting a session's sshd; any local user who enumerates listening loopback ports (`lsof -iTCP -sTCP:LISTEN`) can connect to a session's `sshLocalPort` directly. The actual guard is the **per-session SSH keypair** (V007): the in-guest sshd is **key-only** (no password auth), and the private key is `0600` under the operator's `~/.ssh/sandbox/keys/<id>`. This is the same shape on Linux. The Security-posture section lists it as a known delta rather than burying it as a connectivity convenience; an operator wanting stronger isolation can bind the Lima forward to a per-operator loopback alias.
- **Lite container** (inside the gateway Lima): `docker -H <forwarded-gateway-socket> exec <container> socat - TCP:127.0.0.1:22`. The forwarded-socket plumbing already exists for gateway-container ops; the proxy reuses it.

The earlier framing of this section ("macOS depends on M18 landing first") is now satisfied — M18 has landed. The remaining macOS work is to implement the platform substitutions (the per-operator agent + agent-broker channel, launchd, socket_vmnet pool, QEMU template, 9p shared mount) on top of the model M18 established.

### M13 — per-caller API session isolation

The daemon identifies callers via peer credentials on the unix socket (`/var/run/sandbox/sandboxd.sock` on macOS, mode 0660 owned by `_sandbox:_sandbox`). **Correction to an earlier draft:** the current code does **not** call `SO_PEERCRED` directly — it uses tokio's `UnixStream::peer_cred()` (`sandboxd/src/main.rs`), which already abstracts the `SO_PEERCRED` (Linux) vs `LOCAL_PEERCRED` (macOS) syscall difference and returns the peer's **uid + primary gid**. So for the `(uid, gid)` the daemon actually persists, macOS likely needs **no hand-rolled path** — `peer_cred()` works on both platforms. The macOS-specific subtleties only matter *if* a raw `getsockopt(SOL_LOCAL, LOCAL_PEERCRED)` read of the full `xucred` is ever introduced: (a) `LOCAL_PEERCRED` yields the peer's *effective* uid (vs Linux `SO_PEERCRED`'s connect-time uid — equal for a normal CLI), captured at connect time, not live — which is why a developer added to `_sandbox` must start a fresh login session before connecting (install.sh's group-membership warning); and (b) **`xucred.cr_groups` is capped at `NGROUPS` (16) and its supplementary-group list is unreliable across macOS versions** — so `_sandbox`-group-membership decisions must **never** be read from the peercred group array; they re-resolve the captured uid through Directory Services via `getgrouplist(3)` (what the Linux lima-helper does for its op-uid gate, and what the macOS daemon does when authenticating an agent's check-in and gating enrollment).

> **`NGROUPS`-cap vs. the socket DAC `connect()` check (the broker/API/slot sockets are `0660` group `_sandbox`).** The 16-cap above is about the *static* group array (`xucred.cr_groups`, `getgroups(2)`); the **authoritative** authZ gate is already `getgrouplist(3)`, so it is unaffected. The kernel's own DAC check when an operator's process `connect()`s to a `0660` group-`_sandbox` socket was the open question — and the **spike settled it (macOS 26.4, 2026-06-14): the 16-group cap does not cause denial.** Despite `kern.ngroups = 16`, `getgroups()` surfaced **42** groups for a test user (no truncation), and a `connect()` to a `0660` socket whose owning group sat at **position 17** in that live list **succeeded** (a true non-member was still `EACCES`-denied — DAC works). macOS resolves membership via the directory/membership resolver (`memberd`/opendirectoryd — `kauth_cred_ismember_gid`), so a real `_sandbox` member connects regardless of group count or static-array position. **Conclusion:** the `0660` group-`_sandbox` design is safe for high-group-count (corporate/MDM) operators; **no `0666` fallback is needed.** (Should this ever regress, the bounded fallback stands: for the broker/API sockets the daemon's post-`accept()` `getgrouplist` gate is authoritative, so the DAC bit is only a first filter and could be widened to `0666` without weakening security.) The **slot sockets** have *no* app-layer gate (socket_vmnet is a dumb byte-pump), so there the group bit + the `0750` group-`_sandbox` `/var/run/sandbox/vmnet/` dir traversal *is* the control — set explicitly via `--socket-group=_sandbox` (socket_vmnet's default is `staff`, i.e. *every* standard user) — and the same spike result shows that gate holds for many-group operators too.

The captured `(uid, gid)` does double duty: it is the `owner_username` filter for session ownership **and** the `operator_uid`/`operator_gid` (V008) that drives the operator-execution seam (lima-helper pivot on Linux, agent routing on macOS) and operator-uid alignment. Multi-user macOS works identically to multi-user Linux: developers are added to the `_sandbox` group (`dseditgroup -o edit -a <user> -t user _sandbox`), each developer's sessions are owner-filtered, and each developer's VMs run under their own uid in their own per-operator LIMA_HOME.

The `sandbox-route-helper` does exist on macOS — but **inside the gateway Lima VM** (Linux substrate), where it installs the per-session container default route in a netns, setcap'd exactly as on Linux. It is not a macOS-host binary and is not in the macOS host install. No Linux-only host-side privilege check fires on the macOS host; **there is no privileged macOS-host binary at all** — the per-operator agent runs unprivileged as the operator, and the only root component on the host is the socket_vmnet pool daemons (network infra, § socket_vmnet pool).

**User credentials never cross the `_sandbox` boundary.** The `_sandbox` daemon does not access any calling user's `$SSH_AUTH_SOCK`, personal `~/.ssh/`, git config, or gpg keys. Two flows that look like they might need this turn out not to:

- The git-remote-sandbox flow (host `git push sandbox::<session>/...`) goes through the M18 SSH proxy: the CLI uses the per-session keypair under `~/.ssh/sandbox/keys/<id>` and tunnels via `sandbox proxy` → the daemon's `/sessions/{id}/proxy` WebSocket → the session's sshd. The daemon never touches the user's personal SSH agent or keys; it only byte-pipes the proxy.
- Outbound `git push origin` from inside a sandbox VM (e.g., to github.com) requires the user to provide credentials inside the sandbox via the workspace mount (`shared:`), manual key copy, or HTTPS+PAT. Identical on Linux and macOS. The daemon does not proxy this traffic — it passes through the gateway pipeline like any other outbound network call, gated by policy.

### M14 — version handling and `sandbox doctor`

- **CLI ↔ daemon version equality**: enforced on every connect; platform-independent. Applies on macOS unchanged.
- **Gateway image version pinning**: the gateway container's Docker image tag is version-pinned to the daemon's release. On macOS the gateway image is **`docker load`ed from the staged tarball** into the gateway Lima instance (`docker -H <gateway-socket> load -i <staged-tar>`) during daemon startup step 4, before the readiness check — there is **no registry pull** (§ Gateway image distribution: the image ships as a tarball, never pushed to a registry). If the image tag inside the gateway Lima instance does not match the daemon's expected version, the daemon loads the matching tarball before proceeding.
- **`sandbox doctor`**: gains macOS-specific checks. The existing checks (`check_kvm_accessible`, `check_route_helper_caps`, `check_users_conf_pool`) are Linux-only and are skipped on macOS via `cfg!(target_os = "linux")` gates. New macOS checks (names per the consolidated table below, which is authoritative):
  - `check_socket_vmnet_installed` — the staged `socket_vmnet` binary is present at `/Library/sandboxd/socket_vmnet` with root-owned ancestry; `check_socket_vmnet_running` — the N `io.sandboxd.vmnet.<n>` launchd daemons are loaded and their slot sockets exist (the binary-present and daemons-loaded checks are **separate** rows, not one conflated check)
  - `check_gateway_lima_instance` — verifies `sandboxd-gateway` exists, is running, and its forwarded Docker socket is reachable
  - `check_vmnet_pool_slots` — verifies the pool has the configured number of slots and that no slot is leaked (claimed by a session that doesn't exist)
  - `check_gateway_image_inside_lima` — verifies the version-pinned gateway image is present inside the gateway Lima instance and matches the daemon's expected tag
- **`/diagnostics` endpoint**: the diagnostics payload includes new macOS-only fields when the daemon is running on macOS: `gateway_lima_state` (running / stopped / absent / error), `vmnet_pool_size`, `vmnet_pool_claimed`, `gateway_image_tag_inside_lima`. These are `Option`-typed and absent on Linux.

#### `sandbox doctor` checks — consolidated reference

All `sandbox doctor` checks added or affected by macOS support, in one table. Each row links to the subsection that defines the underlying constraint.

| Check name | Scope | What it probes | Defined in |
|---|---|---|---|
| `check_lima_version` | macOS | `limactl --version` ≥ MIN_LIMA_VERSION (1.2.0) | Prerequisites § Lima |
| `check_socket_vmnet_access` | macOS | operator is in the `_sandbox` group and can connect to the slot sockets under `/var/run/sandbox/vmnet/` (no `/etc/sudoers.d/lima` exists or is needed — unmanaged socket_vmnet) | Prerequisites § socket_vmnet access |
| `check_operator_agent` | macOS | the per-operator agent (`io.sandboxd.agent`) is installed for the calling operator and **checked in** to the daemon's broker channel; warns if the operator is enrolled but the agent isn't connected (typically: not logged in), since limactl ops cannot be brokered without it | Privilege model on macOS |
| `check_socket_vmnet_installed` | macOS | `socket_vmnet` binary present at the staged root-owned path `/Library/sandboxd/socket_vmnet`, with root-owned non-writable ancestry (install.sh stages it from the Homebrew prefix) | M15 § install.sh changes |
| `check_socket_vmnet_running` | macOS | the N `io.sandboxd.vmnet.<n>` launchd daemons are loaded (`launchctl print system/io.sandboxd.vmnet.<n>`) and their slot sockets under `/var/run/sandbox/vmnet/` exist | M15 § install.sh changes |
| `check_gateway_lima_instance` | macOS | `sandboxd-gateway` exists, is running, forwarded Docker socket reachable via `docker -H <gateway-socket> info` | M14 § version handling and `sandbox doctor` |
| `check_vmnet_pool_slots` | macOS | Pool has the configured number of slots; no slot is leaked (claimed by a session that does not exist) | Failure handling § Slot leak detection |
| `check_gateway_image_inside_lima` | macOS | Version-pinned gateway image present inside the gateway Lima instance and matching the daemon's expected tag | M14 § version handling and `sandbox doctor` |
| `check_tcc_workspace_access` | macOS | The daemon can stat typical workspace roots; warns if a TCC-protected path returns permission error | M15 § SIP and TCC |
| `check_disk_space` | platform-independent | Free space on the filesystem containing `/var/lib/sandboxd/`; warns below 10 GiB free | M15 § Disk usage |
| `check_lima_base_image` (**C14**, added v0.1.7) | platform-independent (lima backend) | Golden Lima base VM (`sandbox-base`) present in the operator's LIMA_HOME. **Daemon-mediated** via the `/diagnostics` payload (`lima_base_image_present` / `_probe_failed` / `_probe_error`, fed by `lima_mgr.check_base_image()`) — the CLI **never** calls `limactl` or the helper directly. Informational `Skip` ("not built yet") when absent; on macOS the base VM is the QEMU `sandbox-base`, so this is the macOS pre-build check too (hint: `sandbox rebuild-image --backend lima`). A `probe_failed` verdict surfaces the operator-facing reason — which on macOS most often means the **operator's agent isn't checked in** (not logged in) or `limactl` isn't on the operator's PATH, tying this check to the per-operator-agent constraints in § Privilege model. | M15 § Golden base VM; § Privilege model |
| `check_kvm_accessible` | Linux | (existing) `/dev/kvm` present and accessible | (Linux pre-existing) |
| `check_route_helper_caps` | Linux | (existing) `sandbox-route-helper` has the correct capabilities | (Linux pre-existing) |
| `check_users_conf_pool` | Linux | (existing) `/etc/sandboxd/users.conf` parses and grants the daemon's user the right CIDR pool | (Linux pre-existing) |

Linux-only checks are gated `cfg!(target_os = "linux")` and skipped on macOS; macOS-only checks are gated `cfg!(target_os = "macos")` and skipped on Linux. `check_disk_space` runs on both.

### M15 — release & install infrastructure

`scripts/install.sh` is extended to support macOS (Apple Silicon only). The release pipeline produces a single macOS tarball — `aarch64-apple-darwin`. Each tarball is signed with cosign — sigstore/cosign is multi-platform and the verification path in `install.sh` works on macOS without changes.

#### Build artifact matrix

Sandboxd's deployable surface spans host binaries, in-substrate binaries (deployed inside containers and sandbox VMs), and full container images. Each artifact is built by the method best suited to it — not by a single workspace-wide `cargo build`.

| Artifact | What it does | Build method | Make target |
|---|---|---|---|
| `sandboxd` | Host daemon | Native cargo on host | `make sandbox` (alias: `make build` builds everything) |
| `sandbox` CLI | Host CLI (and `git-remote-sandbox` symlink) | Native cargo on host | `make sandbox` |
| `sandbox-guest` | Guest-agent binary that runs inside each sandbox VM/container | Cargo inside a Linux docker container (base = same Linux as `sandbox-base`); resulting binary is moved back to the host | `make guest` |
| `sandbox-route-helper` | Privileged setcap binary for the Linux container backend's route install | Cargo inside a Linux docker container (base = latest Debian/Ubuntu); resulting binary is moved back to the host | `make route-helper` |
| `sandbox-nft-deny-logger` + `sandbox-nft-allow-logger` | Gateway-container processes for nft event logging | Cargo inside a Linux docker container (base = same as `sandbox-gateway` image); artifacts are moved back or fed straight into the gateway image build context | `make nft-loggers` |
| `sandbox-gateway` image | Per-session gateway container (Envoy, mitmproxy, CoreDNS, both nft-loggers) | `docker buildx` multi-arch (`linux/amd64,linux/arm64`) | `make gateway-image` |
| `sandboxd-lite` image | Lite-mode session container image | Daemon builds it at runtime when first `--lite` session is created. No make target. | — |
| `sandbox-base` | Golden Lima VM image for sandbox sessions | Daemon builds it at runtime on first session create. No make target. | — |
| `site/dist/` | Documentation site | npm/Astro pipeline | `make docs-build` (unrelated to platform) |

**Key implication:** `cargo build --workspace` is **not** the canonical build command on any platform. It is replaced by `make build`, which orchestrates per-artifact builds with the right toolchain (host cargo for host binaries, dockerized cargo for in-substrate binaries, docker buildx for images). This is true on Linux and macOS alike — the difference is which host the dockerized builds run against, not which build commands are invoked.

The "built inside docker" pattern means: spin up a short-lived Linux container with a pinned Rust toolchain, mount the workspace source, `cargo build` the target crate inside, and move the resulting artifact back to the host. The host's own Rust toolchain is not used for these artifacts. The base images are pinned per the table above so each artifact's ABI matches its eventual runtime substrate (e.g., nft-loggers must match the gateway image's libc).

#### Cross-platform workspace cleanliness (clippy)

Three crates ship binaries that target Linux only — `sandbox-route-helper`, `sandbox-nft-deny-logger`, `sandbox-nft-allow-logger`. Each pulls Linux-only deps: `nix` (sched/net), `caps`, `netlink-sys`. For `cargo clippy --workspace` to pass on macOS, each of the three gets the same minimal cfg-gating treatment:

1. Their Linux-only Cargo deps are moved to `[target.'cfg(target_os = "linux")'.dependencies]`.
2. The Linux-specific code in `src/main.rs` is moved into a `#[cfg(target_os = "linux")] mod imp` module.
3. A non-Linux stub `fn main()` is added that prints `error: this binary runs on Linux only` and exits with code 2.

No source changes are needed in any other crate. `sandbox-guest` compiles cleanly on macOS today (its deps are cross-platform); `sandbox-event-emitter` likewise. `cargo fmt --workspace` works on macOS today (no compilation step).

#### CI matrix

| Job | Runner | Responsibility |
|---|---|---|
| `build-linux` | `ubuntu-latest` | Build Linux artifacts (full Linux tarball + multi-arch gateway image push). Run hermetic + integration + `make test-e2e-linux` (explicit, host-asserting). Sign the Linux tarball with cosign. |
| `build-macos` | `macos-14` (Apple Silicon) | Build macOS host artifacts. Run hermetic + integration tests for macOS paths. Run the **same e2e suite natively** via `make test-e2e-macos` (explicit, host-asserting → QEMU+HVF sandbox VMs on the **bare** runner host, no nested virtualization). Run `make test-install-e2e` (macOS install via Tart). Sign the macOS tarball with cosign. |

CI jobs call the **explicit** `test-e2e-linux` / `test-e2e-macos` targets (not the auto-detecting `test-e2e`), so a misconfigured runner fails loudly instead of silently running the wrong platform's selection.

**No nested virtualization is required on the macOS CI runner.** macOS-native e2e boots QEMU+HVF sandbox VMs directly on the bare `macos-14` host — HVF works on M1; only nested virt (M3+/macOS 15) would be a problem, and the native suite doesn't nest. (Nesting matters only for the dev-convenience `make test-linux`, which runs the Linux suite *inside* a Lima VM on a Mac — that is not a CI path; CI runs the Linux suite natively on `ubuntu-latest`.)

install-e2e: the Linux install path is exercised on `build-linux` (or via Lima from either runner); the macOS install path is exercised on `build-macos` via Tart. `macos-13` (Intel) is out of scope; `macos-15` may be added when GitHub stabilizes it (and would additionally unlock nested-virt for `make test-linux` on CI, if ever wanted).

#### macOS e2e harness adaptation

**Principle: one suite, a thin platform seam, marker-gated platform-specific tests — do not fork the suite.** The pytest *test bodies* are already platform-agnostic: they drive the daemon HTTP API, the `sandbox` CLI, and `limactl` through the portable `limactl_cmd()` seam (which is just `env LIMA_HOME=<per-operator> limactl …` — already correct on both platforms). What is Linux-bound today lives entirely in `tests/e2e/conftest.py` fixtures and the Makefile, not in the tests.

**Platform seam in conftest.** Introduce a small `_platform` module selected at collection time on `sys.platform`, vending per-platform implementations:

| Concern | Linux | macOS |
|---|---|---|
| e2e daemon user | `sandbox-test` | `_sandbox-test` (created via `dscl`/`sysadminctl`) |
| daemon launch | `sudo -n -u sandbox-test sandboxd …` | `sudo -n -u _sandbox-test sandboxd …` — same shape; on macOS the test operator's per-operator agent (running as the operator) does the limactl work, brokered by the daemon, so the harness must also bring up that agent |
| pytest group activation | `sg sandbox-test -c …` | no `sg` on macOS — re-exec pytest via `sudo -n -u $(id -un) …` (a fresh process picks up the `dseditgroup`-added `_sandbox-test` membership) |
| preflight | qemu-bridge-helper present+setuid, `/dev/kvm` | socket_vmnet pool daemons running+reachable, the test operator's per-operator agent registered+checked in |
| dev test-cap helpers | `setcap` (`install-*-test-cap`) | register the dev per-operator agent (no setuid — the agent runs as the test operator) |
| state paths | `/var/lib/sandboxd/<uid>/…` | identical |
| `limactl_cmd()` | `env LIMA_HOME=… limactl` | identical (portable today) |

The import-time `pwd.getpwnam("sandbox-test")` (currently `conftest.py:171`) becomes `pwd.getpwnam(PLATFORM.daemon_test_user)`, failing with an actionable "run `make setup-dev-env`" message if the user is absent — instead of an opaque `KeyError` at collection.

**Markers — the reuse mechanism.** Two orthogonal axes, both already partly present:

- **Platform axis (new):** no marker → runs on **both** platforms (the majority — session create/start/stop/rm, policy/egress enforcement, the gateway pipeline, workspace clone/local, git-remote, the cross-user SSH proxy). `@pytest.mark.linux_only` → qemu-bridge-helper, `/dev/kvm`, route-helper netns, systemd. `@pytest.mark.macos_only` → socket_vmnet pool slot lifecycle, gateway Lima instance lifecycle, vmnet NIC discovery, per-operator agent check-in/broker, launchd service control, `dscl` install. (9p `shared:` mounts are *not* macOS-specific — both platforms run QEMU+9p now, so those tests are unmarked.)
- **Backend axis (existing, M12-S13):** `@pytest.mark.lima` / `@pytest.mark.container`. A `lima`-marked test runs on **Linux-QEMU and macOS-QEMU** (same backend, different networking attachment) — same body = reuse. A `container`-marked test runs on host-Docker (Linux) and gateway-Lima-Docker (macOS).

Net: a platform-agnostic, backend-agnostic test runs in up to four cells (linux×{lima,container}, macos×{lima,container}) with one body. New tests are written platform-agnostic by default; markers are added only for genuinely platform-specific behavior. This is how duplication is avoided — net-new tests exist only for the ~dozen genuinely-macOS-only and ~handful Linux-only behaviors.

**Makefile entry points — auto-detect for devs, explicit for pipelines.** All targets share one pytest core (same suite, same marker selection); they differ only in the per-platform setup (Linux `setcap` + `sg`; macOS `dscl` + per-operator agent registration + group re-exec) and in whether they detect or assert the host OS.

- **Dev convenience (auto-detect):** `make test-e2e` reads `uname -s` and dispatches to the host's native flow, selecting `-m "not macos_only"` on Linux and `-m "not linux_only"` on macOS. One command, both platforms. `make test-e2e-container` / `make test-e2e-matrix` are the scope selectors (PR-time container-only vs full backend matrix) and likewise auto-detect the host (on macOS `-matrix` = QEMU-Lima + gateway-Lima-container; on Linux = QEMU-Lima + host-container).
- **Pipelines (explicit, host-asserting):** `make test-e2e-linux` and `make test-e2e-macos` are dedicated targets that **hard-assert the host OS and fail fast** if invoked on the wrong runner (no silent wrong-platform run in CI) before running that platform's full native matrix. CI calls these directly — `build-linux` → `make test-e2e-linux`, `build-macos` → `make test-e2e-macos` — so the pipeline never depends on auto-detection. The PR-vs-merge scope distinction composes via a `SCOPE` knob (`make test-e2e-macos SCOPE=container` for the PR-time container-only slice; default is the full matrix), avoiding a combinatorial explosion of `test-e2e-<platform>-<scope>` target names.

The auto-detecting `test-e2e` is implemented on top of the explicit pair (detect → invoke `test-e2e-linux` or `test-e2e-macos`), so there is exactly one code path per platform and the dev and pipeline entry points cannot drift.

#### Apple code signing and notarization (skipped initially)

**First, a hard prerequisite that is NOT skipped: ad-hoc signing.** On Apple Silicon the kernel (AMFI) **refuses to `execve()` any Mach-O that lacks a valid code signature — including an ad-hoc one** — *before* Gatekeeper is ever consulted and regardless of any quarantine xattr. An unsigned arm64 binary is `SIGKILL`ed at exec with "Code Signature Invalid." This is an architecture invariant on every supported target (macOS 14/15, M1–M4), independent of the notarization decision below. Therefore the release pipeline **must ad-hoc-sign every shipped Mach-O** (`sandboxd`, `sandbox`, the per-operator agent binary; cosign ships already-signed upstream) with `codesign -s - <binary>` and verify with `codesign -v`; install.sh / install-e2e should `codesign -v` the staged binaries as a guard. Caveat: Rust's macOS linker *does* apply an ad-hoc signature by default, so a clean `cargo build` artifact usually runs — but **`strip`/post-link processing invalidates the signature** (re-sign after any such step), so the pipeline cannot assume "cargo built it, therefore it's signed." (There is **no setuid binary** on macOS, so the setuid-bit-vs-signature interaction does not arise.) The notarization-skip below is about *Developer-ID + notarytool*, a different and genuinely optional layer.

**Hypervisor entitlement lands on Homebrew's `qemu`, not on any sandboxd binary.** QEMU's HVF acceleration requires the `com.apple.security.hypervisor` entitlement (and, depending on macOS version, `com.apple.vm.hypervisor`). The process that needs it is `qemu-system-aarch64` — which is **Homebrew's `qemu`, already signed-and-entitled by the formula**; sandboxd never ships or replaces it. So **no sandboxd-shipped Mach-O needs any entitlement** — ad-hoc signing (no entitlements) is sufficient for `sandboxd`/`sandbox`/`sandbox-agent`. (Were VM launch ever moved into a sandboxd binary, that binary would have to be signed *with* the hypervisor entitlement — ad-hoc can carry an entitlement, but note EDR/MDM fleets often flag ad-hoc-signed binaries bearing virtualization entitlements as anomalous. Not a concern as long as `qemu` is the launcher.)

The macOS tarball's binaries are **not** signed with an Apple Developer ID certificate and not submitted to Apple's notarization service in the initial release. Rationale:

- Gatekeeper only blocks binaries carrying the `com.apple.quarantine` extended attribute. That attribute is set by Safari, Mail.app, Messages, AirDrop, and the App Store — **not** by `curl`, `wget`, `brew install`, or `tar` extraction.
- The canonical install path on macOS (per the launchd plist section above) is `curl ... | sudo bash`. Tarballs downloaded by curl have no quarantine xattr, so the extracted binaries do not trigger Gatekeeper. The `sudo launchctl bootstrap system` step also does not invoke Gatekeeper on the daemon binary.
- A future Homebrew formula (deferred, see "Homebrew formula" below) downloads bottles in the same curl-without-quarantine mode that brew uses for every other formula; signing remains unnecessary.
- The only path that does trigger Gatekeeper is users downloading the tarball manually from the GitHub Releases UI in Safari. For this case, the troubleshooting docs ship a one-liner workaround: `sudo xattr -dr com.apple.quarantine /path/to/sandboxd-<version>-<arch>-apple-darwin.tar.gz`.

This matches the conventions used by most comparable OSS CLI tools that distribute via brew + curl (kubectl, helm, kustomize, most CNCF tooling). Projects that sign with Apple Developer ID (Tailscale, Docker Desktop, VS Code, GitHub CLI, Rustup, Go) do so because they also distribute via Safari-downloadable packages or because their products integrate with macOS network filters / system extensions — neither applies here.

Adding full Apple codesign + `notarytool submit` + `stapler staple` to the release pipeline is a follow-on item, gated on the project obtaining Apple Developer Program enrollment ($99/yr) — out of scope for this milestone.


#### Install daemon model: system launchd daemon

sandboxd on macOS runs as a **system launchd daemon** under a dedicated `_sandbox:_sandbox` system user — the direct analog of the Linux `sandbox:sandbox` systemd model. Rationale:

- socket_vmnet must run as root (vmnet.framework); sandboxd runs it as system-level launchd daemons (`io.sandboxd.vmnet.<n>`, § socket_vmnet access). The privilege boundary cannot be eliminated on the host, so a system daemon model is the honest fit.
- the vmnet pool's socket_vmnet instances are system-wide launchd daemons (`io.sandboxd.vmnet.<n>`) owning sockets under `/var/run/sandbox/vmnet/` — system-wide resources. A per-user daemon model would force a UID-scoped pool/daemon naming scheme to avoid cross-user collisions — additional complexity for no functional gain.
- Multi-user support is built into the post-M18 model: a single daemon brokers all sessions; per-caller isolation is enforced via `LOCAL_PEERCRED` (owner filter) and the **per-operator agent** (each operator's VMs run as that operator via their own agent, under their own per-operator LIMA_HOME) — the macOS analog of Linux's operator-uid pivot.
- The gateway Lima instance lives in `_sandbox`'s own LIMA_HOME; each operator's sandbox VMs live under that operator's per-operator LIMA_HOME. Ordinary developer users running `limactl list` as themselves see none of it.

The privilege boundary matches Linux's intent — unprivileged daemon, group-scoped unix socket access, sudo-required install/uninstall/update — but reaches it with **no host privilege elevation at all**: there is no setuid/setcap helper on macOS (per-operator agents run as their own operators; the only root component is the socket_vmnet network daemons). macOS's `_`-prefix convention (`_postgres`, `_mysql`, `_appstore`, etc.) is followed for the system user name.

The `sandbox-route-helper` runs **inside the gateway Lima VM** (Linux substrate), setcap'd as on Linux — it is not a macOS-host binary and is not in the macOS-host install.

#### Install paths on macOS

The daemon's state lives under a **per-daemon-uid root** `/var/lib/sandboxd/<_sandbox-uid>/`, mirroring Linux. `<_sandbox-uid>` is resolved at install time via `id -u _sandbox`.

> **Note on `/var/lib` on macOS.** macOS has no `/var/lib` by default (it is not a standard macOS path; the idiomatic locations would be `/Library/Application Support/` or `/usr/local/var/`). Using `/var/lib/sandboxd/` is a **deliberate Linux-parity choice** — it keeps the per-daemon-uid state-root layout byte-identical across platforms, which simplifies the shared daemon/store/update code and the docs. install.sh creates `/var/lib` and `/var/lib/sandboxd` if absent (root:wheel 0755). The runtime and log dirs (`/var/run/sandbox`, `/var/log/sandbox`) are macOS-standard (`/var/run`, `/var/log` exist and are the conventional homes for daemon sockets and logs).

| Resource | Path |
|---|---|
| `sandboxd` binary | `/usr/local/libexec/sandboxd/sandboxd` (not on user PATH — daemon-internal, invoked only by launchd) |
| `sandbox` CLI binary | `/usr/local/bin/sandbox` (on PATH — operator-facing) |
| per-operator agent binary | `/usr/local/libexec/sandboxd/sandbox-agent` (`root:wheel` 0755 — **no setuid**; `launchd` runs it *as the operator* via the LaunchAgent below) |
| per-operator agent LaunchAgent | `/Library/LaunchAgents/io.sandboxd.agent.plist` (system-wide; `launchd` starts it per-user at login *as that user*. **Must set `LimitLoadToSessionType: Aqua`** — see § The per-operator agent / launchd scoping. The agent additionally self-gates on `_sandbox` membership, exiting cleanly for non-enrolled users) |
| `sandbox-guest` | `/usr/local/libexec/sandboxd/sandbox-guest` (linux/arm64 ELF; daemon stages it into VMs/lite image) |
| `cosign` | `/usr/local/libexec/sandboxd/cosign` (pinned release binary, `root:wheel` 0755, off PATH — alongside the other helpers). install.sh stages it; `sandbox update` **reuses** it and refuses (rather than bootstrapping cosign) if it is absent. Matches `COSIGN_BIN_PATH` in `sandbox-cli/src/update/fetch.rs`. |
| State root (`--base-dir`) | `/var/lib/sandboxd/<_sandbox-uid>/` (sessions.db, lock, install-state, backups; owned `_sandbox:_sandbox` mode 0750; `/var/lib/sandboxd` itself is root-owned 0755) |
| Daemon LIMA_HOME (gateway instance) | `/var/lib/sandboxd/<_sandbox-uid>/lima/` |
| Per-operator LIMA_HOME (sandbox VMs) | `/var/lib/sandboxd/<_sandbox-uid>/<operator_uid>/lima/` (created lazily at first session per operator) |
| Runtime directory | `/var/run/sandbox/` (unix socket; mode 0750 owned by `_sandbox:_sandbox`). `/var/run` → `/private/var/run` is **cleared on every boot**, so the daemon re-creates `/var/run/sandbox/` (with correct owner/mode) at startup before binding the socket — it must not assume the directory persists. |
| Daemon unix socket | `/var/run/sandbox/sandboxd.sock` (mode 0660 owned by `_sandbox:_sandbox`; developers in `_sandbox` group can connect) |
| Logs | `/var/log/sandbox/` (daemon's own `sandboxd.log` rotated in-process; `launchd.{stdout,stderr}.log` for pre-init output — see Log rotation) |
| launchd plist | `/Library/LaunchDaemons/io.sandboxd.daemon.plist` (root-owned, mode 0644) |
| Cached tarballs (install/update working area) | `/var/lib/sandboxd/<_sandbox-uid>/cache/` |

Paths follow Linux conventions (`/var/lib/sandboxd/<uid>`, `/var/run/sandbox`, `/var/log/sandbox`). `~/Library/...` user-level paths are **not** used — the daemon is a system service, not a per-user agent. macOS has no `/run/`, so `/var/run/` (the canonical alias) is used. `sandbox-route-helper` and the nft-loggers are absent from the macOS-host install — they live inside the gateway Lima VM / gateway image.

The existing XDG resolver in `sandbox-cli/src/cli_xdg.rs` continues to work for client-side config lookup (per-user CLI config, presets) — that remains user-scoped on both platforms.

#### launchd plist

`sandboxd/contrib/launchd/io.sandboxd.daemon.plist` ships as a source artifact alongside `sandboxd/contrib/systemd/sandboxd.service`. install.sh copies it to `/Library/LaunchDaemons/` during install (with `sudo`). The keys below are summarized in shorthand for readability — the shipped artifact is a real XML plist (`<key>`/`<dict>`/`<true/>` etc.), e.g. `KeepAlive` is a `<dict>` with `<key>SuccessfulExit</key><false/><key>Crashed</key><true/>`, not the `{ … }` shorthand shown here. The plist:

- `UserName=_sandbox`, `GroupName=_sandbox` — daemon runs as the system user, not root
- `KeepAlive={ "SuccessfulExit" = false; "Crashed" = true }` — restart on crash, do not respawn on clean exit (analogous to systemd `Restart=on-failure`)
- `ThrottleInterval=5` — minimum 5s between (re)spawns. **Note:** launchd has *no* equivalent to systemd's `StartLimitBurst`/`StartLimitIntervalSec` "N restarts in T seconds then give up" governor — a crash-looping job is respawned every 5s indefinitely (launchd logs "service only ran for N seconds, throttling" but never permanently stops it). If a give-up-after-N-failures policy is wanted, it must be implemented in-daemon (e.g. a startup-failure counter), not expected from launchd. (An earlier draft wrongly attributed a 5-in-300s burst limit to the plist; launchd cannot express that.)
- `StandardOutPath=/var/log/sandbox/launchd.stdout.log`, `StandardErrorPath=/var/log/sandbox/launchd.stderr.log` (pre-tracing-init output + panics only; the daemon's structured log stream goes to `/var/log/sandbox/sandboxd.log`, rotated in-process — see Log rotation)
- `RunAtLoad=true` — start at boot (install.sh runs `sudo launchctl bootstrap system …` and `sudo launchctl enable system/io.sandboxd.daemon` to persist across reboots)
- `ProgramArguments`: `[ "/usr/local/libexec/sandboxd/sandboxd", "--base-dir", "/var/lib/sandboxd/<_sandbox-uid>", "--socket", "/var/run/sandbox/sandboxd.sock" ]` (install.sh substitutes the resolved uid)
- `WorkingDirectory=/var/lib/sandboxd/<_sandbox-uid>`
- `EnvironmentVariables`:
  - `PATH=/usr/local/bin:/opt/homebrew/bin:/usr/bin:/bin` — daemon can find `docker` and `limactl` (which it runs as itself only for the gateway instance) regardless of Homebrew prefix.
  - `HOME=/var/lib/sandboxd/<_sandbox-uid>` — launchd does **not** populate HOME from the directory-service record for system daemons; pin it explicitly. (The daemon's own gateway-instance limactl ops run as `_sandbox` directly with `LIMA_HOME` set per invocation; operator limactl runs in the per-operator agents, not the daemon; the daemon does not export `LIMA_HOME` globally.) This is the macOS analog of the systemd unit's recently-added `Environment=HOME=@SANDBOX_BASE_DIR@`: it is **defense-in-depth** for subprocesses (notably `docker build`) that consult `$HOME` to create a config dir — the *primary* fix threads `docker_home` explicitly into the build (§ M11 § ContainerRuntime platform-awareness), and the pinned HOME backstops any future subprocess that reads `$HOME` without going through that path.
- `ExitTimeOut=20` — launchd sends SIGTERM and waits 20 seconds for graceful shutdown before SIGKILL. This matches the existing tokio-based shutdown handler in `sandboxd/src/main.rs` (drains in-flight HTTP via `axum::serve(...).with_graceful_shutdown(...)`, then flushes the persistent event sink, then removes the unix socket file). 20 seconds is comfortably more than the drain budget.

The plist does **not** set `SessionCreate=true` — it does not need an Aqua session.

#### Graceful shutdown contract

The daemon's SIGTERM handler is the same code path on both platforms (`tokio::signal::unix::SignalKind::terminate()` works identically on Linux and macOS). On SIGTERM, the daemon:

1. Stops accepting new API connections (axum's `.with_graceful_shutdown(...)` short-circuits the accept loop).
2. Waits for in-flight HTTP requests to drain (no explicit timeout on the per-request side — relies on launchd's 20s wall-clock).
3. Tears down the persistent event sink (`persistent_sink.shutdown()` aborts and joins relay / sink / pruner tasks; file handles close deterministically).
4. Removes the unix socket file.
5. Exits 0.

The daemon **does not** stop the gateway Lima instance on shutdown — the gateway is persistent across daemon restarts (Gateway Lima instance § Lifecycle). The daemon **does not** stop running sandbox VMs or sandbox containers — sessions outlive daemon restarts; the reconcile loop on the next daemon startup handles state recovery.

`sandbox update`'s `launchctl bootout` + `bootstrap` cycle and `launchctl kickstart -k` follow the same SIGTERM-then-SIGKILL semantics; no separate update-time shutdown path exists.

#### install.sh changes

The `detect_os()` function in `scripts/install.sh` (currently `die "sandboxd installs on Linux only"`) is replaced with a branch on `uname -s`:

```sh
case "$(uname -s)" in
    Linux)  OS=linux ;;
    Darwin) OS=darwin ;;
    *) die "unsupported OS: $(uname -s) (Linux and macOS only)" ;;
esac
```

install.sh requires sudo on both platforms (already true for Linux). On macOS additions:

- Arch-detect: only `arm64` is accepted (mapped to `aarch64-apple-darwin`). `x86_64` on Darwin is rejected with a clear "Intel Macs are not supported" error. macOS's `uname -m` returns `arm64`, not `aarch64`.
- Prerequisite check skips `check_kernel_version` (Linux-specific) on macOS and adds:
  - `check_socket_vmnet_installed` — verifies the `socket_vmnet` binary is present (Apple Silicon Homebrew prefix `/opt/homebrew/opt/socket_vmnet/bin/socket_vmnet`); install.sh then **stages it** to a root-owned path the pool daemons exec (see the socket_vmnet pool daemons step below)
  - `check_socket_vmnet_running` — verifies the N `io.sandboxd.vmnet.<n>` launchd daemons are loaded (`launchctl print system/io.sandboxd.vmnet.<n>`) and their slot sockets under `/var/run/sandbox/vmnet/` exist (NOT the Homebrew `socket_vmnet` service — sandboxd does not use it)
  - `check_lima_installed_and_version` — verifies `limactl --version` ≥ MIN_LIMA_VERSION (see Lima version requirement in Prerequisites). Because the per-operator agent runs `limactl` from the **operator's own PATH** (it runs as the operator and inherits their Homebrew prefix), there is no hardcoded-candidate-path lockstep to maintain — the `/opt/homebrew/bin/limactl` gap that would have bitten a hardcoded-path setuid helper simply does not arise. A preflight that finds no usable `limactl` prints a `brew install lima` hint and exits non-zero.
  - `check_socket_vmnet_access` — verifies the operator is in the `_sandbox` group and can reach the slot sockets under `/var/run/sandbox/vmnet/` (see socket_vmnet access in Prerequisites — no Lima sudoers is involved)
- System user provisioning on first install: install.sh creates the `_sandbox` user and group. `dscl` requires **one `-create` per attribute** (you cannot set multiple attributes in a single call), and the user needs `RealName` and a disabled `Password` in addition to the obvious fields. Concretely:
  ```sh
  # group
  dscl . -create /Groups/_sandbox
  dscl . -create /Groups/_sandbox PrimaryGroupID <next-free-gid-below-500>
  dscl . -create /Groups/_sandbox RealName "sandboxd daemon"
  # user
  dscl . -create /Users/_sandbox
  dscl . -create /Users/_sandbox UniqueID <next-free-uid-below-500>
  dscl . -create /Users/_sandbox PrimaryGroupID <gid>
  dscl . -create /Users/_sandbox NFSHomeDirectory /var/lib/sandboxd/<uid>
  dscl . -create /Users/_sandbox UserShell /usr/bin/false
  dscl . -create /Users/_sandbox RealName "sandboxd daemon"
  dscl . -create /Users/_sandbox Password '*'        # disabled login
  ```
  The `_`-prefix + `UserShell /usr/bin/false` is the idiomatic hidden-service-account pattern; the legacy `IsHidden 1` attribute is unreliable across macOS versions and is not used. install.sh **may instead use `sysadminctl -addUser _sandbox -UID <uid> -GID <gid> -home /var/lib/sandboxd/<uid> -shell /usr/bin/false -roleAccount`**, which is the modern, less error-prone path and handles the RealName/Password wiring itself — preferred where available.
  - Idempotent — re-running install.sh detects the existing user and skips creation. Resolves `<_sandbox-uid>` after creation for the per-uid state paths.
- Developer (operator) group membership: install.sh prompts (or accepts `--add-user <name>`) to add the running developer to the `_sandbox` group via `dseditgroup -o edit -a <name> -t user _sandbox`. **This is now load-bearing for cross-user**: the daemon only brokers to (and accepts agent check-ins from) operators in the `_sandbox` group, and the daemon socket is group-gated. The developer must log out and back in for the group change to take effect for **new processes' live credentials** (the gid a process carries when it `connect()`s the socket) **and** for the per-operator agent to activate (it self-gates on `_sandbox` membership and `launchd` (re)starts it at login) — install.sh warns about this.
  - **Group-check resolver (recent master).** `sandbox doctor`'s membership check switched from `getgroups(2)` (live process groups) to **`getgrouplist(3)`** (the *configured* set — primary gid ∪ supplementary groups from the directory database). The motivation on Linux was `newgrp sandbox` dropping the group from the live supplementary list (a false-negative); on macOS `getgrouplist(3)` consults **Directory Services**, so once `dseditgroup` has added the operator to `_sandbox` the doctor check reports `Member` **immediately**, before any re-login. The distinction to keep clear in the docs: the *doctor check* (configured membership) goes green at once, but *actual socket access* still needs a fresh login/process to carry the gid in its live credentials — so install.sh's "log out and back in" warning stays, it just no longer governs whether `doctor` passes.
- Per-operator agent install (no privilege step): install.sh installs the agent binary to `/usr/local/libexec/sandboxd/sandbox-agent` (`root:wheel` 0755, **no setuid**) and the system-wide LaunchAgent plist to `/Library/LaunchAgents/io.sandboxd.agent.plist`. There is **no setuid/setcap step on macOS** — the agent runs unprivileged as the operator. `launchd` starts it (as the operator) at each enrolled operator's next login, at which point it checks in with the daemon. The plist **must set `LimitLoadToSessionType: Aqua`** (see launchd-scoping note below) so it loads only in a real GUI login session — never in the `LoginWindow` context (which runs as **root**) or `Background`/`Standard`. The agent also self-gates on `_sandbox` membership as defense-in-depth, but that gate must be a **clean exit with no `KeepAlive` respawn** (omit `KeepAlive`, or use `KeepAlive={SuccessfulExit=false}`) so a non-enrolled user's login doesn't produce a perpetual throttled respawn loop.
- State directories created with correct ownership: `install -d -o root -g wheel -m 0755 /var/lib/sandboxd`; `install -d -o _sandbox -g _sandbox -m 0750 /var/lib/sandboxd/<uid> /var/run/sandbox /var/run/sandbox/vmnet /var/log/sandbox`. Per-operator LIMA_HOME subtrees are created lazily by the daemon (`ensure_operator_lima_home`), not by install.sh.
- **socket_vmnet pool daemons (macOS-specific, installed before the sandboxd daemon).** install.sh stages the `socket_vmnet` binary at **`/Library/sandboxd/socket_vmnet`** (`root:wheel` 0755; install.sh creates `/Library/sandboxd` `root:wheel` 0755) — copied from the Homebrew binary so the root daemons never exec an admin-writable file. `/Library` is root-owned and not admin-writable on every macOS, so the binary's full ancestry is provably root-owned — unlike `/usr/local`, which Homebrew may have chowned (§ socket_vmnet access). It then generates **N launchd plists** `/Library/LaunchDaemons/io.sandboxd.vmnet.<n>.plist` from `max_macos_sessions` — each running one `socket_vmnet --vmnet-mode=host --vmnet-network-identifier=<per-slot UUID> --socket-group=_sandbox /var/run/sandbox/vmnet/slot-<n>.sock` with `RunAtLoad`+`KeepAlive`. **Because `/var/run` is cleared on every boot and launchd imposes no ordering between independent jobs**, each `io.sandboxd.vmnet.<n>` job must create its own socket's parent dir before binding — it cannot rely on the install-time dir surviving a reboot or on the sandboxd daemon (a separate, unordered job) having run first. **The parent dir must be created with an explicit owner, not a bare `mkdir -p`:** these jobs run as **root**, so a plain `mkdir -p /var/run/sandbox/vmnet` would leave `/var/run/sandbox` `root:wheel` (root's umask) — and the unprivileged `_sandbox` daemon, racing to create the same dir for its API/broker sockets, then **cannot** `chown` a root-owned dir to fix it. So the pre-exec wrapper uses `install -d -o _sandbox -g _sandbox -m 0750 /var/run/sandbox` (and `… -m 0750 /var/run/sandbox/vmnet`), which deterministically yields `_sandbox:_sandbox 0750` **regardless of which unordered job wins the race** — the daemon then finds the dir already correct (and still asserts/repairs owner+mode before listening). install.sh `bootstrap`s + `enable`s each and waits for the N slot sockets to appear. These come up **before** the sandboxd daemon (whose startup prereq 2e requires them). The `/var/run/sandbox/vmnet/` socket dir is group `_sandbox` so `_sandbox` and enrolled operators can connect.
- Service load: `sudo launchctl bootstrap system /Library/LaunchDaemons/io.sandboxd.daemon.plist`; `sudo launchctl enable system/io.sandboxd.daemon` for persistent enable across reboots.
- **Eager provisioning + health-gated repair (recent master).** After the daemon is up, install.sh now eagerly pre-builds the session image rather than deferring it to first-session-create, by running `SANDBOX_SOCKET=… sandbox rebuild-image --backend <backend> -y` (the backend resolved from the install's default). On macOS this pre-builds the lite image inside the gateway Lima instance (and/or pre-builds the `sandbox-base` VM for the Lima backend, matching the C14 doctor hint `sandbox rebuild-image --backend lima`), so the first session is fast and any build failure surfaces at install time, not on first use. The non-root rebuild path redirects its output to an operator-writable temp (a recent installer fix). Provisioning is **health-gated**: install.sh waits for the daemon socket to answer before provisioning and treats a provisioning failure as a non-fatal warning (the install still completes; `sandbox doctor` will flag the missing image).

Missing prerequisites print actionable `brew install socket_vmnet` / `brew install lima` instructions and exit non-zero. (install.sh does **not** direct the operator to `brew services start socket_vmnet` — it stages the binary and installs its own `io.sandboxd.vmnet.<n>` daemons instead.)

#### Log rotation

launchd does not rotate logs (unlike systemd-journald on Linux). The daemon handles its own rotation in-process via `tracing-appender::rolling`:

- Daemon log stream goes to `/var/log/sandbox/sandboxd.log` via a `tracing_appender::rolling::Builder` configured with daily rotation, max 7 generations, and a 50-MiB size cap per file (so a chatty day doesn't blow the daily roll-over). Rotated files are renamed `sandboxd.log.YYYY-MM-DD` and gzip-compressed lazily on the next rotation pass.
- The plist's `StandardOutPath`/`StandardErrorPath` point at `/var/log/sandbox/launchd.{stdout,stderr}.log`. These capture only pre-tracing-init startup output and uncaught panics — small and bounded. They are NOT rotated; if they ever grow significantly that's an anomaly worth investigating, not a routine size concern.
- No `newsyslog` config ships. No SIGHUP plumbing. No dependence on launchd's StandardOutPath redirection for the main log stream.

**Why not `newsyslog`.** BSD `newsyslog`'s `N` flag means "do not signal the daemon" — it is **not** a copy-truncate semantic (BSD newsyslog has no copy-truncate flag at all). Default newsyslog rotation does `rename(2)` + create new file; the daemon's launchd-inherited fd keeps writing to the rotated file unless the daemon handles SIGHUP and reopens. Putting that plumbing in the daemon just to keep newsyslog in the loop adds complexity with no win — in-daemon rotation via tracing-appender is simpler, gives us programmatic control over format and retention, and is symmetric with the same approach we'd use on Linux if we ever stopped relying on journald.

**Why not journald on Linux.** Linux today uses systemd-journald — that stays. The macOS in-daemon rotation does not change the Linux logging path. The tracing subscriber's macOS branch is gated `cfg!(target_os = "macos")` and writes to the rolling file appender; the Linux branch keeps stdout-to-journald.

install.sh on macOS creates `/var/log/sandbox/` as `_sandbox:_sandbox` mode `0750`. uninstall.sh removes it under `--purge-state` (same as the other state directories).

#### Homebrew formula (optional, follow-up)

A Homebrew formula (`sandboxd.rb`) may be added in a subsequent release as a thin wrapper around install.sh — it would `brew install`-style discover the latest tarball, prompt for sudo, and delegate to the same trust path. The formula is **not** required for the initial macOS launch; install.sh is the canonical install path on both platforms.

#### scripts/uninstall.sh on macOS

`scripts/uninstall.sh` mirrors install.sh: detect OS, dispatch platform-specific teardown, idempotent at every step. The Darwin branch sequence:

1. **Pre-flight refusal** — refuse if any session is in `running` state or any workspace lock is held (M17). Operator must `sandbox stop --all` first. Bypassed by `--force`.
2. **Stop the daemon** — `sudo launchctl bootout system/io.sandboxd.daemon` (idempotent — ignore "service not loaded"). With the daemon down, the gateway and sandbox VMs keep running; the purge below removes their state regardless, so they need not be individually stopped via limactl. (Optionally, before bootout, `sandbox stop --all` while the daemon is still up cleanly tears down gateway + sandbox VMs through the normal path — the daemon brokers each sandbox-VM teardown to that operator's agent and runs gateway teardown as `_sandbox`. uninstall.sh does not shell `limactl` directly: post-bootout it just removes state.)
3. **Reap leftover VMs** — best-effort safety net for instances orphaned by a non-graceful stop. macOS sandbox VMs **are** `qemu-system-aarch64` processes (launched by Lima under each operator's agent), but uninstall.sh must **never `pkill qemu-system`** — that would also kill the developer's *personal* Lima/Colima QEMU VMs, which are indistinguishable by process name. uninstall.sh does **not** shell `limactl` directly either (limactl is only ever driven through the daemon — via each operator's agent on macOS). The correct reap is therefore to **leave the orphans for the purge step (6)** to delete by removing their disk images under the per-operator LIMA_HOME. (Booting out an operator's agent / logging them out tears down their login session and with it their sandbox QEMU processes, since the VMs are login-scoped — step 5 boots out loaded agents.) If a clean teardown is wanted, do it *before* bootout via `sandbox stop --all` while the daemon is still up — that drives limactl correctly through each operator's agent. Post-bootout, uninstall.sh only removes state. Do **not** ship a `pkill qemu` line — it is both unsafe (hits personal VMs) and unnecessary (purge removes the disk images).
4. **Remove launchd plists** — bootout and remove the daemon plist **and** the N socket_vmnet pool daemons: `sudo launchctl bootout system/io.sandboxd.vmnet.<n>` for each slot, then `sudo rm -f /Library/LaunchDaemons/io.sandboxd.daemon.plist /Library/LaunchDaemons/io.sandboxd.vmnet.*.plist` (idempotent — ignore "service not loaded"). Booting out the vmnet daemons stops the pool's socket_vmnet instances and tears down their slot sockets under `/var/run/sandbox/vmnet/`.
5. **Remove binaries + the per-operator agent** — `sudo rm -f /usr/local/libexec/sandboxd/sandboxd /usr/local/libexec/sandboxd/sandbox-agent /usr/local/libexec/sandboxd/sandbox-guest /usr/local/libexec/sandboxd/cosign /usr/local/bin/sandbox /Library/LaunchAgents/io.sandboxd.agent.plist` (and any user-created `/usr/local/bin/git-remote-sandbox` symlink), plus the root-exec'd socket_vmnet at `sudo rm -rf /Library/sandboxd` (the dedicated root-owned staging dir). Best-effort bootout any currently-loaded operator agents (`sudo launchctl bootout gui/<uid>/io.sandboxd.agent` per logged-in operator); removing the plist prevents future starts. The staged `socket_vmnet` and `cosign` are sandboxd-owned copies, so removing them here is safe — the operator's Homebrew `socket_vmnet`/`cosign` (if any) are untouched. The `libexec/sandboxd/` directory is removed in the purge step.
6. **Optional state purge** (gated on `--purge-state`, default off; prompt the operator interactively when neither `--purge-state` nor `--yes` is set):
   - `sudo rm -rf /var/lib/sandboxd/<_sandbox-uid> /var/log/sandbox /var/run/sandbox` (and `rmdir /var/lib/sandboxd` if now empty). This removes the daemon LIMA_HOME, all per-operator LIMA_HOME subtrees, sessions.db, backups, and cache.
   - Without `--purge-state`, state is left in place. A future re-install can recover existing sessions (assuming their VM disk images survive under the per-operator LIMA_HOME subtrees).
7. **Remove the `_sandbox` system user/group** — only when `--purge-state` was given. Order matters: strip the group's members *before* deleting the group, so no user record points at a now-nonexistent gid:
   - For each member, `sudo dseditgroup -o edit -d <user> -t user _sandbox`
   - `sudo dseditgroup -o delete _sandbox`
   - `sudo dscl . -delete /Users/_sandbox`
   - Idempotent.
8. **Verification** — `launchctl print system/io.sandboxd.daemon` should now error; `/Library/LaunchDaemons/io.sandboxd.daemon.plist` should be absent. Print a "uninstall complete" line with any residual paths if state was kept.

Flags on uninstall.sh:
- `--purge-state` — full state removal (steps 6 + 7). Default: off.
- `--force` — bypass pre-flight refusal (running sessions are killed; their state is lost). For CI/recovery. Backed by the daemon's `DELETE /sessions/{id}?force=true` (recent master: `StopParams.force`), which **skips the workspace-lock conflict check** and tolerates individual teardown-step failures, succeeding as long as the session ends up `Stopped` — exactly the semantics a forced purge needs so a held lock or a wedged VM cannot block uninstall. (Platform-independent; same handler on Linux and macOS.)
- `--yes` / `-y` — non-interactive; skip the purge prompt (defaults to "keep state").

The Linux branch of uninstall.sh has the same shape with `systemctl stop sandboxd`, `userdel sandbox`, `groupdel sandbox` substitutions. Paths (`/var/lib/sandboxd/<uid>`, etc.) are already shared.

#### install / uninstall e2e coverage (Tart)

Both `install.sh` **and** `uninstall.sh` are exercised end-to-end on macOS — not just install. The Linux install-e2e suite (`tests/install-e2e/`) already covers a full matrix of scenarios — happy-path install, idempotent re-install, air-gapped (`--from`), sigstore/refusal paths, the upgrade path, **`test_uninstall.py`**, a full install→uninstall cycle in `test_install_happy_path.py`, and ~a dozen `sandbox update` scenarios (rollback, backup retention, concurrent-refused, multi-version, dev-install rejection). The macOS install-e2e mirrors this scenario set against **Tart macOS VMs** instead of Lima Linux-distro VMs.

Unlike the session e2e suite (one portable body, thin platform seam), install-e2e is **more platform-divergent** by nature — the install *steps themselves* differ (launchd vs systemd, `dscl`/`sysadminctl` vs `useradd`, per-operator agent vs `setcap` helper, socket_vmnet pool vs qemu-bridge). So the shared layer is the **scenario shape and the assertions about observable end-state**, not the step implementations. Concretely, the macOS install-e2e must assert:

- **install.sh** (happy path): `_sandbox` user/group created (`dscl`/`sysadminctl`); `sandboxd`/`sandbox`/`sandbox-agent`/`sandbox-guest` landed at their target paths; the per-operator agent binary is **not** setuid (plain `root:wheel` 0755) and the `io.sandboxd.agent` LaunchAgent plist is installed in `/Library/LaunchAgents/`; the daemon launchd plist installed at `/Library/LaunchDaemons/` and the service `bootstrap`ed + `enable`d (`launchctl print system/io.sandboxd.daemon` succeeds); the N `io.sandboxd.vmnet.<n>` daemons loaded; per-uid state dirs created with correct owner/mode; gateway image tarball staged; daemon reaches healthy (socket answers); the test operator's agent checks in (when the operator session is present); `sandbox doctor` all-green.
- **install.sh idempotency:** a second run is a no-op (no duplicate user, no re-bootstrap error, exit 0).
- **install.sh refusals:** Intel host rejected; missing socket_vmnet/Lima rejected with actionable message; cosign/MANIFEST verification failure aborts before any state change.
- **uninstall.sh:** `launchctl bootout` succeeds and the service is gone; the daemon plist **and** the `io.sandboxd.agent` LaunchAgent plist removed; binaries (incl. the per-operator agent) removed; the `io.sandboxd.vmnet.<n>` daemons booted out; with `--purge-state` the per-uid state tree, `_sandbox` user, and group are removed (members stripped before group deletion); without `--purge-state`, state is preserved and a subsequent re-install recovers it. A full **install → create-session → uninstall → re-install** cycle is the headline test (mirrors `test_install_happy_path.py`).
- **`sandbox update`:** the launchctl bootout/bootstrap swap, **agent-binary swap (no re-privilege step — there is no setuid on macOS)**, gateway-image reload, backup retention, and rollback — the macOS analogs of the Linux update scenarios.

These run under `make test-install-e2e` on the `build-macos` CI job (Tart), and are the reason Tart is a (dev-optional) prerequisite. Tart is used here precisely because install/uninstall mutate system state (users, `/Library/LaunchDaemons`, setuid binaries) that must not touch the dev's real machine — the same isolation rationale as the Linux suite's throwaway Lima distro VMs.

Like the Linux suite, the macOS install-e2e tests the **`build.sh`-assembled** `install.sh`/`uninstall.sh` (ui.sh inlined, test-env handling per `--keep-test-env`) — i.e. the exact self-contained bytes a `curl | sh` user receives — so the suite doubles as a regression guard on the assembler itself, including the macOS `Darwin` branch and the rich-UI degradation path.

#### Release tarball contents

The release pipeline produces per-arch tarballs with a parallel structure on both platforms. Contents differ only where the artifacts differ. The tarball is downloaded and unpacked by install.sh (which is hosted separately at `https://Koriit.github.io/sandboxd/install.sh`, NOT bundled inside the tarball).

##### Linux tarball

`sandboxd-<version>-x86_64-unknown-linux-gnu.tar.gz` (and the `aarch64-unknown-linux-gnu` counterpart):

```
sandboxd-<version>-<linux-triple>/
├── MANIFEST                                            # JSON inventory: artifact paths + sha256 + version metadata
├── bin/
│   ├── sandboxd                                        # → /usr/local/libexec/sandboxd/sandboxd
│   ├── sandbox                                         # → /usr/local/bin/sandbox
│   ├── sandbox-route-helper                            # → /usr/local/libexec/sandboxd/  (setcap cap_net_admin,cap_sys_ptrace,cap_sys_admin=eip)
│   ├── sandbox-lima-helper                             # → /usr/local/libexec/sandboxd/  (setcap cap_setuid+ep)
│   └── sandbox-guest                                   # → /usr/local/libexec/sandboxd/sandbox-guest
├── systemd/
│   └── sandboxd.service                                # → /etc/systemd/system/sandboxd.service
└── images/
    └── sandbox-gateway-linux-<arch>-<version>.tar      # docker load into host Docker daemon
```

##### macOS tarball

`sandboxd-<version>-aarch64-apple-darwin.tar.gz` (Apple Silicon only — no Intel tarball):

```
sandboxd-<version>-aarch64-apple-darwin/
├── MANIFEST                                            # same JSON shape as Linux
├── bin/
│   ├── sandboxd                                        # → /usr/local/libexec/sandboxd/sandboxd
│   ├── sandbox                                         # → /usr/local/bin/sandbox
│   ├── sandbox-agent                                   # → /usr/local/libexec/sandboxd/  (per-operator agent; root:wheel 0755, NO setuid)
│   └── sandbox-guest                                   # → /usr/local/libexec/sandboxd/sandbox-guest (linux/arm64 ELF)
├── launchd/
│   ├── io.sandboxd.daemon.plist                        # → /Library/LaunchDaemons/io.sandboxd.daemon.plist  (system daemon)
│   └── io.sandboxd.agent.plist                         # → /Library/LaunchAgents/io.sandboxd.agent.plist    (per-operator agent; runs per-user at login)
└── images/
    └── sandbox-gateway-linux-arm64-<version>.tar       # staged at /var/lib/sandboxd/<_sandbox-uid>/cache/; daemon docker-loads into gateway Lima
```

(No `sandbox-route-helper` in the macOS tarball — it runs inside the gateway Lima VM, shipped in the gateway image. No `newsyslog/` config — log rotation is in-process via tracing-appender.)

##### Shared notes

- **MANIFEST at root**, JSON. Lists each artifact's relative path and sha256 alongside version metadata. cosign signs the entire tarball; install.sh re-verifies every file against MANIFEST after extraction. MANIFEST is the trusted source of the version string — the tarball filename is not.
- **No `install.sh` / `uninstall.sh` / `README.md` in the tarball.** The installer/uninstaller are hosted as **self-contained single files** at `https://Koriit.github.io/sandboxd/{install,uninstall}.sh`. They are *assembled* by `scripts/build.sh`, which inlines the shared rich-UI engine `scripts/ui.sh` into each (and strips the test-env span), emitting to `build/dist`; `docs.yml` just invokes `build.sh` and deploys its output. `curl https://Koriit.github.io/sandboxd/install.sh | sudo bash` downloads the assembled install.sh standalone; it then fetches the release tarball and verifies it via cosign + MANIFEST. This is platform-independent — the macOS `Darwin` branch lives inside the same `install.sh`/`uninstall.sh`/`ui.sh` sources and rides the same assembler.
- **`scripts/` shared layer (correction to an earlier draft of this spec).** `scripts/lib.sh` **still exists** — it is the canonical home of the 3 cosign constants (version + the two SHA256s); `install.sh` keeps a 3-line bootstrap mirror of them inline (so `curl|sh` works with no adjacent file) and sources the on-disk `lib.sh` in dev checkouts; a drift test (`test_lib_sh_drift.py`) keeps the mirror and the Rust-side constants in `sandbox-cli/src/update/fetch.rs` in lockstep. `lib.sh` ships in the **tarball** beside its `sandbox update` consumer. (An earlier draft of this spec wrongly stated lib.sh was removed — it was not.) `scripts/ui.sh` (rich-UI engine) and `scripts/build.sh` (assembler) were added by the uninstall-TUI-parity work; both are dev/build-time artifacts, not shipped in the tarball. macOS-specific shell constants (e.g., `MIN_LIMA_VERSION`, the `cosign-darwin-arm64` SHA256) follow the same pattern — canonical in `lib.sh`, inline-mirrored where curl|sh needs them, drift-tested.
- **`uninstall.sh` has full TUI parity with `install.sh`** (shared `ui.sh` engine; same alt-screen checklist + privileged-batch progress model), degrading to a byte-identical plain path when rich mode is unavailable. The macOS uninstall *steps* (§ scripts/uninstall.sh on macOS) animate through that same shared engine; nothing macOS-specific in the UI layer.
- **No `update.sh`.** `sandbox update` is a CLI subcommand of the `sandbox` binary.
- **No Lima base VM image, no lite-mode image.** Both are daemon-built at runtime.
- **No `sandbox-nft-deny-logger` / `sandbox-nft-allow-logger` binaries directly.** They live inside the gateway image tarball under `images/`.

##### Per-platform deltas (Linux vs macOS)

| Item | Linux | macOS |
|---|---|---|
| Service config | `systemd/sandboxd.service` | `launchd/io.sandboxd.daemon.plist` |
| Log rotation | journald | in-process (tracing-appender → `/var/log/sandbox/sandboxd.log`); no newsyslog config |
| `sandbox-route-helper` binary | Yes — Linux backend needs it | Not shipped (route helper is Linux-only) |
| `sandbox-guest` binary | Yes — `bin/sandbox-guest` (a `linux/<host-arch>` ELF, not the macOS host's arch). Installed to `/usr/local/libexec/sandboxd/sandbox-guest`. | Same staging convention — `bin/sandbox-guest` is a `linux/arm64` ELF. Installed to the same `/usr/local/libexec/sandboxd/sandbox-guest` path. |
| Gateway image tarball | One per host arch | Always `linux/arm64` (Apple Silicon only) |
| `sandboxd` install path | `/usr/local/libexec/sandboxd/sandboxd` (NOT `/usr/local/bin/`) | Same |

**Note on the `sandboxd` install path.** The daemon binary lives under `/usr/local/libexec/sandboxd/` on both platforms, alongside `sandbox-route-helper` and `sandbox-guest`. It is **not** on user PATH. Only the launchd plist (macOS) / systemd unit (Linux) invokes it; operators never run `sandboxd` directly. The dev workflow uses `cargo run -p sandboxd` from a workspace checkout, not the installed binary. This is a cleanup the macOS spec also applies to Linux — the existing Linux install at `/usr/local/bin/sandboxd` puts the daemon on PATH, where an operator could accidentally invoke it and create a second process competing with the service-managed one for the unix socket. The cross-platform install.sh / systemd unit / launchd plist all point at the libexec path; `sandbox update` is updated to swap the binary at the new location.

`sandbox-guest` is a *Linux* binary on both platforms — the daemon's job is to inject it into Linux substrate at runtime (the gateway Lima VM for the lite-mode image build, and the sandbox-base VM during provisioning). On Linux the host arch happens to match the substrate arch; on macOS the binary is `linux/arm64` even though the host is Apple Silicon. The release pipeline must build a `linux/arm64` `sandbox-guest` for the macOS tarball — same dockerized cargo build as item 2 (Build artifact matrix) describes for `make guest`.

#### SIP and TCC

**System Integrity Protection (SIP).** sandboxd does not require any SIP carve-outs. The paths it writes (`/var/lib/sandboxd/<uid>`, `/var/run/sandbox` incl. `/var/run/sandbox/vmnet/`, `/var/log/sandbox`, `/Library/sandboxd/` (the root-owned socket_vmnet staging dir), `/Library/LaunchDaemons/io.sandboxd.daemon.plist`, the `/Library/LaunchDaemons/io.sandboxd.vmnet.*.plist` pool daemons, and `/Library/LaunchAgents/io.sandboxd.agent.plist`) are all SIP-allowed locations for system-installed software. (No `/etc/sudoers.d/lima` is written — the unmanaged socket_vmnet model needs none; see § socket_vmnet access.) No `csrutil` changes are required for install, run, or uninstall. The daemon does not modify SIP-protected paths like `/System/`, `/usr/` (proper — install.sh uses `/usr/local/bin/`, which is operator-modifiable), or any of the protected app bundles.

**Transparency, Consent, and Control (TCC).** TCC governs application access to user data in protected directories (`~/Documents`, `~/Desktop`, `~/Downloads`, `~/Pictures`, `~/Movies`, `~/Music`, the Camera, the Microphone, etc.) and to features like Full Disk Access. The system daemon itself never reads these — its footprint is entirely under `/var/lib/sandboxd`.

The user-facing TCC surface is `shared:` workspace mounts: `sandbox create --workspace shared:~/Documents/project` makes the operator's sandbox VM access `~/Documents` on the host via the 9p shared mount (the host-side 9p server lives in the `qemu-system` process).

**The per-operator-agent model makes this *possible* — and it is a direct benefit of that design** (whether it *fully* works hinges on a residual TCC-attribution question, below). On macOS the QEMU VM (whose `qemu-system` process performs the host-side 9p file access) is launched by `limactl` running inside the **operator's own agent**, which `launchd` runs **in the operator's Aqua login session, as the operator**. A process in a user's Aqua session **can** trigger the normal "allow access to your Documents?" consent dialog — unlike a sessionless system daemon, which TCC *denies without any prompt*. So the first `shared:` access to a protected dir should prompt the operator (who, on the interactive-desktop target, is present at the machine) — **provided TCC attributes the grandchild `qemu-system` read to a process still inside that Aqua session**, which the daemonization caveat below puts in question. This is exactly Apple's recommended "an agent in the user session obtains consent" pattern, available **only because** we run limactl in the operator's session rather than through a sessionless privileged pivot. (Had we kept a setuid-helper/system-daemon pivot, this access would have been silently denied — so eliminating the pivot fixed TCC as a side effect.)

**Confirmed on hardware (macOS 26.4):** a dedicated, ad-hoc-signed Mach-O binary launched by an Aqua-session LaunchAgent triggers its **own** TCC consent prompt (attributed to that binary by name); after the operator clicks Allow the protected-dir read succeeds and the grant **persists** across re-runs; a non-protected path (`~/projects/…`) needs no consent at all. **Design requirement this surfaced:** the agent must be a uniquely-identified **signed binary**, never a shell script. A script runs as `/bin/sh` — a shared system binary that TCC will **not** prompt for as its own subject; it falls back to naming the controlling terminal/GUI app, and *that* grant does **not** cover the script's access, so the read is effectively denied. `sandbox-agent` is a Mach-O binary (ad-hoc-signed per § Apple code signing), so this holds — but the agent must never be reduced to a script wrapper around `limactl`.

Consequences and caveats:
- **`shared:` into `~/Documents` etc. is *intended* to work**, gated on a one-time per-operator TCC consent (their own dialog, in their own session) — **pending the real-chain verification below**. The grant is keyed to the **responsible binary** in the operator's TCC context (operator-scoped → no cross-user exposure); *which* binary in the agent→`limactl`→`qemu-system` chain that resolves to is the remaining item below, and if it lands on Homebrew's `qemu-system` the practical fallback is a one-time **Full Disk Access** grant on qemu rather than a per-`shared:` prompt.
- **It requires the operator to be present to consent.** A fully non-interactive first run against a protected path fails until consent is granted — acceptable for the interactive-desktop target, and no worse than the non-protected-path default below.
- `sandbox doctor`'s `check_tcc_workspace_access` row is now **informational**: if a `shared:` source sits in a protected dir, it notes "you'll be prompted to grant access on first use" rather than flagging a hard failure.
- For `local:` workspace mode (rsync snapshot at create), the rsync also runs inside the operator's agent (as the operator, in-session), so the same consent path covers protected *source* paths.
- **Zero-prompt default.** Operators who prefer no dialogs can keep workspaces outside the protected set (`~/projects/…`, `~/dev/…`) — no TCC involvement at all. Full Disk Access remains an optional manual grant for unattended setups.

> **Open verification item (narrow, non-blocking) — partially closed.** A hands-on run on **macOS 26.4 confirmed the core mechanism**: an Aqua-session LaunchAgent whose program is a *dedicated, ad-hoc-signed binary* gets its **own** consent prompt for `~/Documents`, and after Allow the read works and **persists**; a non-protected path needs no consent. The run also confirmed the failure mode to avoid — a faceless `/bin/sh` script is **not** a promptable TCC subject (the prompt misattributes to the controlling terminal and the grant does not cover the script's access → denied), which is why the agent must be a signed binary (see the design-requirement note above). **What still needs the real chain:** in production the agent does not read the file itself — `limactl`/`qemu-system` (its children) do — so confirm **which binary TCC attributes the child read to**: the **agent** (the launchd job's responsible process — the *desired* outcome, one clean per-operator-agent grant) or `limactl`/`qemu-system`. **This is not a coin-flip in our favor:** `limactl start` typically **daemonizes** the `qemu-system` process (backgrounds it and returns), so qemu is reparented toward `launchd` and detached from the agent's responsibility chain — making attribution to `qemu-system` **at least as likely** as to the agent, and raising a worse branch where a fully-detached qemu with no Aqua responsibility gets **no prompt at all and is silently denied**. The verification must therefore also record *whether a prompt appears at all*, not just which binary it names. That determines the name the operator sees in the prompt and the entry they'd manage in System Settings. **Upgrade-invalidation caveat:** if TCC attributes the read to **Homebrew's `qemu-system`** (or `limactl`) rather than to `sandbox-agent`, the grant is keyed to *that* binary's cdhash — so **every `brew upgrade qemu`/`lima` changes the cdhash and re-triggers the prompt**, a recurring operator papercut. Attribution to the agent (whose cdhash we control and only change on `sandbox update`) is the desired outcome for exactly this reason; if it lands on qemu/limactl instead, document the re-prompt-on-upgrade behavior and steer heavy protected-dir users toward a one-time Full Disk Access grant. None of this blocks the design (non-protected paths need no TCC). **How to reproduce the real-chain check:** install the agent as its signed binary, trigger it via **launchd-at-login** (NOT `launchctl kickstart` from a terminal — that misattributes the prompt to the terminal; a `StartInterval` timer also failed to fire promptly in a non-Aqua bootstrap context), have it drive `limactl start` of a `shared:~/Documents/…` session, and observe which binary the consent dialog names. Beware false results: a pre-existing Full Disk Access grant on any chain binary masks denials, so check/clear that first.

Apple notarization does not affect any of this — TCC is not tied to signing.

#### Reboot and wake-from-sleep

**Reboot.** When the macOS host reboots:

1. launchd loads `io.sandboxd.daemon` from `/Library/LaunchDaemons/` (because install.sh ran `sudo launchctl bootstrap system …` + `enable`).
2. The N `io.sandboxd.vmnet.<n>` launchd daemons auto-start (`RunAtLoad`), bringing up the pool's socket_vmnet instances before sandboxd needs them.
3. (No Lima privileged helper or `/etc/sudoers.d/lima` to start — sandboxd uses unmanaged socket_vmnet; see § socket_vmnet access.)
4. The sandboxd daemon starts. Its startup sequence (M15 § Daemon startup sequence — macOS) brings up the gateway Lima instance and reconciles persisted session state.
5. **Sandbox VMs and their sessions are NOT auto-restarted.** Sessions that were running before the reboot are now "stopped" — their VMs are off, their slot claims are stale.

The daemon's reconcile loop on first startup after a reboot must handle this:

- For each session in `running` state in `sessions.db`, the daemon verifies the VM is actually running (via `limactl list -j` or equivalent). If not running (which is the case for all sessions after a reboot), the daemon marks the session `stopped` and clears any in-memory slot claim. The session row's `vmnet_slot` JSON blob field stays — operators can `sandbox start <session>` to resume on a fresh slot.
- For each running session's gateway container that's no longer present (because the gateway Lima VM was stopped during shutdown), the daemon recreates it on the next `sandbox start`. No reconcile-time recreation is needed.
- For each persisted slot claim in `sessions.db` belonging to a now-stopped session, the daemon releases the slot to the pool (slot leak detection — already specified).

**Wake from sleep.** When the host wakes from sleep:

- The gateway Lima VM and any running sandbox VMs are frozen along with the host during sleep (the `qemu-system` processes are suspended with everything else) and resume on wake.
- TCP connections held open across the sleep are typically lost (the host's network state changed). Sessions reconnect on next use.
- The daemon's gateway-health poll detects unhealthy state if any (gateway container is healthy if the VM resumed cleanly; degraded if not). The existing gateway-crash recovery handles the degraded case.
- Time inside the VMs may have drifted during sleep. The guest's `systemd-timesyncd` / `chrony` (provisioned in the base image) resyncs on wake. TLS validity errors should be rare in practice.

**Operator surface.** No new CLI is added for reboot/sleep handling. `sandbox ls` after a reboot shows sessions in the `stopped` state; the operator uses normal `sandbox start <session>` to resume. After a long sleep, the operator may want to `sandbox restart <session>` if connections inside the sandbox were broken — same workflow as Linux.

#### Coexistence with user-owned Lima and Colima

Developers commonly already have their own Lima setups (per-user `~/.lima/...` instances) and/or Colima running for their personal Docker work. Sandboxd is designed to coexist without interference:

- **Distinct home directories.** sandboxd's state lives under `/var/lib/sandboxd/<_sandbox-uid>/` — the gateway instance in the daemon LIMA_HOME (`.../lima/`), each operator's sandbox VMs in their per-operator LIMA_HOME (`.../<operator_uid>/lima/`). A developer's *personal* Lima instances live under their own `~/.lima/` and are never touched. Personal `limactl list` shows only personal instances; sandbox instances live in the daemon-owned / per-operator trees and are reached only via the daemon (the gateway as `_sandbox`, each operator's VMs via their agent).
- **Distinct vmnet sockets, no shared config.** sandboxd writes **nothing** to any `networks.yaml` — its VMs attach to socket_vmnet via a per-VM `socket:` path (§ socket_vmnet pool § Initialization), so a developer's personal `~/.lima/_config/networks.yaml` is never read or touched. A developer's personal Lima references socket_vmnet under Lima's own `/var/run/lima/` namespace (or the brew daemon's `/opt/homebrew/var/run/socket_vmnet`); sandboxd's slot sockets live in a **separate** namespace under `/var/run/sandbox/vmnet/`, owned by the `io.sandboxd.vmnet.<n>` daemons — so sandboxd's pool and any developer's personal Lima/socket_vmnet usage never share a socket or collide.
- **Separate socket_vmnet instances.** sandboxd runs its **own** socket_vmnet pool daemons (`io.sandboxd.vmnet.<n>`, root-owned, sockets under `/var/run/sandbox/vmnet/`) — **not** the Homebrew `brew services` instance. A developer's personal Lima uses its own socket_vmnet (the Homebrew daemon at `/opt/homebrew/var/run/socket_vmnet`, or a sudo-spawned per-VM one). The two never share a socket, so there is no contention or naming collision (§ socket_vmnet pool).
- **Colima is unrelated to sandboxd.** Colima is a separate Lima-based VM manager that bundles Docker; sandboxd does not interact with Colima. A developer running Colima for their personal Docker work continues to do so; sandboxd's gateway Lima instance is independent and never references Colima's state.
- **Docker Desktop / OrbStack / Rancher Desktop on the macOS host** are similarly untouched — the daemon talks only to the Docker daemon inside the gateway Lima VM via the forwarded socket. The macOS host's Docker context (whatever the developer has set) is not used.
- **CPU/memory ceilings.** Both the developer's own Lima/Colima VMs and sandboxd's Lima VMs run on the same host (sandboxd's via QEMU+HVF). They share the host's physical CPUs and RAM. Running 8 sandbox sessions plus the developer's own 4 GiB VM at once is the operator's planning responsibility, not the daemon's.

The coexistence story is explicit because misunderstanding it is a likely first-time-user concern ("will installing sandboxd break my Colima?"). Documentation includes a brief "coexistence with existing Lima setups" note.

#### Disk usage

Components contributing to sandboxd's disk footprint:

| Component | Storage location | Notes |
|---|---|---|
| `sandboxd` + `sandbox` + `sandbox-guest` binaries | `/usr/local/libexec/sandboxd/` + `/usr/local/bin/sandbox` | Small, fixed |
| Gateway Lima VM image | `/var/lib/sandboxd/<_sandbox-uid>/lima/sandboxd-gateway/diffdisk` | 20 GiB declared in YAML; QEMU qcow2 diffdisk on an APFS sparse file — actual on-disk grows with VM writes |
| `sandbox-base` Lima VM image | `/var/lib/sandboxd/<_sandbox-uid>/<operator_uid>/lima/sandbox-base/diffdisk` | Same backing format. Provisioned lazily on first session create. |
| Per-session sandbox VM (cloned from base) | `/var/lib/sandboxd/<_sandbox-uid>/<operator_uid>/lima/sandbox-<session-id>/diffdisk` | 20 GiB declared. APFS clone-on-write: near-zero incremental at clone time, diverges as the session writes |
| Per-session lite container image | inside the gateway Lima VM's Docker storage | Daemon-built once per version; shared across all lite sessions of that version |
| Session events / logs | `/var/lib/sandboxd/<_sandbox-uid>/events/<session-id>/` | Capped by event-emitter rate-limits + daemon-side rotation |
| Daemon logs | `/var/log/sandbox/sandboxd.log` | Rotated in-process via tracing-appender (see Log rotation subsection) |
| `sandbox update` backups | `/var/lib/sandboxd/<_sandbox-uid>/backups/` | See "Backup contents" below |

Actual sizes for the Lima VM images and lite-mode image depend on workload and have not been measured. Operators sizing a host should treat the 20-GiB-per-VM declared values as a ceiling per VM, not a typical figure — QEMU qcow2 + APFS sparsing keeps actual usage well below that for clean sessions.

##### macOS-specific deltas

The genuinely new fixed cost on macOS (vs Linux) is the **gateway Lima VM**. On Linux the gateway is a per-session container that lives inside the host Docker's storage driver — no separate VM. On macOS the gateway Lima instance is persistent across daemon restarts and reserves a sparse qcow2 disk for its lifetime.

The **cached gateway image tarball** at `/var/lib/sandboxd/<_sandbox-uid>/cache/sandbox-gateway-linux-arm64-<version>.tar` is also macOS-only: install.sh stages it (the gateway Lima isn't up at install time), and the daemon `docker load`s it into the gateway Lima during gateway init (step 4 of daemon startup). **The daemon retains the current version's tarball** (it does *not* delete it after load) precisely so it can **self-heal**: if at any later gateway-init the gateway image is missing inside the Lima VM (e.g., the gateway VM was rebuilt), the daemon re-loads from the retained tarball automatically — a local `docker load`, no network and **no dedicated CLI command**. This resolves the earlier `--redownload-gateway` TBD: there is no such command — reload is automatic on daemon (re)start, and `sandbox doctor`'s gateway-image check surfaces the condition with "restart the daemon" as the fix. Steady-state disk cost is one gateway-image tarball (~hundreds of MB — negligible beside the multi-GB gateway VM disk). If the tarball itself is also missing, re-running `sandbox update` (idempotent, even to the same version) re-stages it.

##### APFS behavior notes

- `du` may overstate apparent size because of clone-aware accounting quirks; `diskutil apfs cliInfo <volume>` and `df` give more honest numbers. The boot volume's free space includes sandbox state, so apparent free-space loss shows up in Finder views and other system tooling — expected.
- Deleting a session via `sandbox rm` reclaims only the writes that diverged from the clone source. Reclamation is **asynchronous** (APFS GC) — operators may not see freed space immediately.

##### `sandbox doctor` disk-space check

A new `check_disk_space` row (platform-independent) reports the free space on the filesystem containing `/var/lib/sandboxd/`. The check **warns** below **10 GiB free** and otherwise reports OK. No hard failure threshold and no enforcement — the daemon does not refuse `sandbox create` based on free space. 10 GiB is an arbitrary first-cut; the right value depends on measuring real-world growth patterns.

**Follow-ups tracked as GitHub issues, not blocking macOS launch:**
- [#14](https://github.com/Koriit/sandboxd/issues/14) — Measure typical disk growth across the existing test workloads and refine the 10 GiB doctor warn threshold to something empirically justified.
- [#15](https://github.com/Koriit/sandboxd/issues/15) — Design hard disk-budget enforcement (refuse `sandbox create` when free space is below an operator-configurable threshold). Deferred — the operator-configurable knob has design surface we haven't worked through.

##### Backup contents (`sandbox update`)

`sandbox update` keeps 2 backup sets per the M16 retention model. The macOS backup set is **defined as** (everything needed to roll back to the previous version, nothing recoverable by other means):

- **Backed up:**
  - `sessions.db` — the only persistent daemon state not recoverable by disk inspection.
  - the swapped binaries: previous `sandboxd`, `sandbox`, `sandbox-agent` (per-operator agent), `sandbox-guest`, and the staged `cosign`.
  - the previous service configs: `io.sandboxd.daemon.plist` and `io.sandboxd.agent.plist`.
  - the previous version's **gateway image tarball** — so a rollback can `docker load` the matching gateway image into the gateway Lima VM (the live cache holds only the *current* version's tarball).
  - the install-state file.
- **NOT backed up:**
  - Lima VM images (gateway VM disk, `sandbox-base`, per-session sandbox VMs) — large, slow to copy, and forward-growing, so not recoverable to a sensible point-in-time. After a rollback, running sessions reconnect to their existing VMs as-is.
  - the daemon's `lima.yaml` templates and the `io.sandboxd.vmnet.<n>.plist` set — both regenerated deterministically at startup / from `max_macos_sessions`, so they need no backup.
  - There is **no `/etc/sudoers.d/lima`** to back up (unmanaged socket_vmnet — § socket_vmnet access).

Backup-set storage is at `/var/lib/sandboxd/<_sandbox-uid>/backups/<version>/` owned by `_sandbox:_sandbox`.

#### Gateway image distribution (per-arch tarballs)

The gateway image is **not** pushed to a registry. It is built by the release pipeline, packaged as a tarball, and shipped inside the release artifact. install.sh / `sandbox update` loads it into Docker via `docker load`.

Today the release ships a single-arch tarball (`images/sandbox-gateway-${VERSION}.tar`). macOS support requires per-arch tarballs because the gateway Docker daemon lives inside a Linux VM whose architecture matches the macOS host (linux/arm64 on Apple Silicon).

Release pipeline changes:
- Build both arches on the Linux runner via `docker buildx build --platform linux/amd64,linux/arm64 --output type=docker,dest=…`. Two tarballs produced from one runner:
  - `images/sandbox-gateway-linux-amd64-${VERSION}.tar`
  - `images/sandbox-gateway-linux-arm64-${VERSION}.tar`
- Linux tarball includes both arch's gateway image tarballs (install.sh on Linux selects the matching arch).
- macOS tarball includes only `images/sandbox-gateway-linux-arm64-${VERSION}.tar` (Apple Silicon only).
- macOS runner does **not** build gateway images — cross-arch builds centralize on Linux runner.

install.sh / daemon-side load:
- **Linux** (unchanged): install.sh's existing `docker_load_gateway` step runs `sudo docker load -i …` against the host Docker daemon. Selects the matching arch's tarball.
- **macOS**: install.sh stages the tarball at `/var/lib/sandboxd/<_sandbox-uid>/cache/sandbox-gateway-linux-arm64-${VERSION}.tar` (mode 0640 owned by `_sandbox`) but does **not** run `docker load` directly — the gateway Lima VM is not yet up at the install.sh stage. The daemon picks up the load during its gateway init (step 4 of daemon startup): after the forwarded Docker socket is reachable, the daemon checks `docker -H <gateway-socket> image inspect sandbox-gateway:${VERSION}` and, on absence, runs `docker -H <gateway-socket> load < /var/lib/sandboxd/<_sandbox-uid>/cache/sandbox-gateway-linux-arm64-${VERSION}.tar`. The `docker load` stdin pipe streams the bytes through the forwarded socket — no need to copy the tarball into the Lima VM filesystem first. Idempotent; subsequent daemon startups skip the load.

On `sandbox update` (M16), the new daemon's expected gateway image tag differs from the running gateway Lima VM's loaded image. The update orchestrator stages the new tarball at the cache path; the new daemon's gateway init loads it on first start after the update.

#### Golden base VM (`sandbox-base`) on macOS

`sandbox-base` is the pre-provisioned Lima VM that new sessions clone from. It is **per-operator** — each operator gets their own base image under their LIMA_HOME (`/var/lib/sandboxd/<_sandbox-uid>/<operator_uid>/lima/sandbox-base/`) under QEMU, built by that operator's agent on macOS (the agent runs as the operator) / via the lima-helper pivot on Linux. The provisioning is identical to Linux's base image (Ubuntu 24.04 cloud image + apt provisioning chain + sandbox-guest binary install) minus the Linux process-isolation wrapper, which doesn't apply on macOS.

The daemon builds the base VM **lazily on a given operator's first session create**. Eager build at install time would add ~3 minutes to install for users who want to evaluate the daemon without creating sessions; eager build at first daemon startup would block `launchctl bootstrap` and make `/health` unreachable for minutes. Lazy honesty is the right UX: an operator's first `sandbox create` takes longer than subsequent ones, the CLI surfaces a clear "building base VM (one-time, ~3 min)" line via the existing `lifecycle_events` bus, subsequent sessions clone from that operator's cached base in ~5–10 seconds. APFS copy-on-write keeps the storage cost of additional clones near-zero. (The `LimaManagerRegistry` serializes same-operator base builds, so two concurrent first-creates by one operator don't race.)

Refresh on daemon version bump: the update orchestrator (M16) compares the persisted base-VM-version marker against the new daemon's expected version. On skew, the orchestrator stops the base VM and deletes its directory before completing the update. The next session create triggers a lazy rebuild on the new daemon version.

**Pre-warm for dev/CI:** there is no make target for pre-warming. The first test run after a fresh clone pays the build cost. CI persists the per-operator base under `/var/lib/sandboxd/<_sandbox-uid>/<operator_uid>/lima/sandbox-base/` and the gateway under `/var/lib/sandboxd/<_sandbox-uid>/lima/sandboxd-gateway/` across runs via GitHub Actions cache, keyed on the provisioning-script hash — the rebuild only fires when provisioning changes. Same caching strategy on Linux.

#### Dev workflow on macOS

macOS developers run sandboxd in two modes:

- **Foreground (no system daemon)** — `cargo run -p sandboxd -- --base-dir /tmp/sandboxd-dev --socket /tmp/sandboxd-dev.sock`. The dev's own user owns the state directory; `_sandbox` is not created; `/Library/LaunchDaemons/` and `/Library/LaunchAgents/` are not touched. Here the daemon **is** the operator (one uid), so on macOS it runs `limactl` **directly as itself** — no per-operator agent and no broker are needed in single-uid foreground mode (the `AgentBrokerExecutor`'s `op_uid == self` degenerate case, exactly like the gateway). (The Linux foreground path is analogous: a dev-built helper pivoting to the daemon's own uid, which needs no privilege.) Standard inner-loop iteration.
- **System daemon (production-shaped)** — `make build && sudo ./scripts/install.sh --from .` installs from the local checkout. Used for testing install-e2e paths.

Existing make targets that work unchanged on macOS:
- `make test` — hermetic suite (`cargo nextest run --workspace`, default profile). The three Linux-only crates either compile to stub mains on macOS (per the clippy/workspace-cleanliness section) or have no host-runnable tests; the suite is otherwise hermetic.
- `make test-integration` — runs the `integration` nextest profile. macOS-specific integration tests live in their own files (no separate profile — selected by `cfg!(target_os = "macos")` gates at the test fixture level).
- `make test-e2e` — runs the pytest e2e suite. On macOS, sessions boot via Lima/QEMU (HVF-accelerated).
- `make gateway-image`, `make guest`, `make route-helper`, `make nft-loggers` — work on any host with Docker; the in-substrate ones build via docker-cargo (see Build artifact matrix above). `sandboxd-lite` and `sandbox-base` have no make target — the daemon builds them at runtime on first use.

New make target:
- `make test-linux` — runs the full Linux test suite (hermetic + integration + e2e) inside a Linux Lima VM. On a Linux dev box, this is a no-op alias to `make test test-integration test-e2e`. On a macOS dev box, it spawns a Linux Lima VM, mounts the workspace, and invokes the suite inside — letting a macOS developer verify they didn't regress *Linux* behavior without owning a Linux machine. This is distinct from `make test-e2e`, which on macOS runs the suite **natively against the macOS daemon** (the thing that actually validates the macOS code paths). **Nesting caveat:** the Linux suite's VM-backend (Lima/QEMU) tests boot VMs *inside* the Lima VM, which needs nested virtualization — available only on **M3+/macOS 15**. On M1/M2 those tests fall back to slow TCG; the **container-backend subset needs no nesting** (Docker-in-Lima-VM works on any Apple Silicon Mac), so `make test-linux` is most useful for the container suite on older Macs. This is a dev-convenience target, never a CI path (CI runs the Linux suite natively on `ubuntu-latest`).

`make setup-dev-env` on Darwin checks (does **not** install) prerequisites:
- `socket_vmnet` binary installed (`brew install socket_vmnet` if missing) and the N `io.sandboxd.vmnet.<n>` pool daemons loaded with their slot sockets present under `/var/run/sandbox/vmnet/`; operator in the `_sandbox` group (sandboxd runs its own socket_vmnet daemons, not the Homebrew `socket_vmnet` service)
- `limactl` on PATH with version ≥ MIN_LIMA_VERSION (`brew install lima` if missing)
- the per-operator agent registered (for the cross-user / system-daemon variant): the `io.sandboxd.agent` LaunchAgent installed and the test operator in `_sandbox` so their agent checks in. **No setuid step** — the agent runs as the test operator. (Single-uid foreground dev needs no agent — the daemon runs `limactl` as itself.)
- For e2e: the `_sandbox-test` daemon user + group (created via `dscl`/`sysadminctl`, mirroring Linux's `sandbox-test`), and the running developer added to the `_sandbox-test` group via `dseditgroup`. This is the cross-user e2e identity, kept distinct from the production `_sandbox` user so the harness's per-uid state tree (`/var/lib/sandboxd/<_sandbox-test-uid>/`) is structurally disjoint from production — same isolation guarantee as the Linux harness.
- (Optional, only if `make test-install-e2e` is on the dev's plan) `tart` is installed (`brew install cirruslabs/cli/tart` if missing). Tart is preflighted but not auto-installed — same model as Lima and socket_vmnet.

Missing prereqs print actionable `brew install …` lines and exit non-zero. The check is idempotent.

### M16 — `sandbox update`

`sandbox update` works on macOS with the same UX as Linux: pre-flight checks → backup → download/verify → swap binaries → restart daemon → schema migrations apply → confirm health. Platform-specific differences are encapsulated in the orchestrator's service-control step (systemd on Linux, launchctl on macOS) and in the gateway image refresh step (no equivalent on Linux, where the gateway image lives on the host).

#### Pre-flight (additions for macOS)

The pre-flight inventory adds three macOS-specific checks to the existing pre-flight chain (M16 § Pre-flight):

- No running sessions (same as Linux — refuses if any session is in `running` state).
- No workspace locks held (same as Linux — refuses if any session has an outstanding push/pull op via the M17 workspace-lock subsystem).
- Gateway Lima instance is reachable (`docker -H <gateway-socket> info`) — if unreachable, the update refuses with an actionable error directing the operator to start the gateway or run `sandbox doctor` first.

#### Service control via launchctl

`sandbox update` requires sudo on macOS (same as Linux). **Sudo-credential model (recent master):** the update flow now warms credentials **once** with `sudo -v` at the start of the run, then every privileged sub-step uses `sudo -n` (non-interactive) — replacing the older per-step `sudo -k` ("kill cached creds before each call") model. This applies on both platforms; on macOS the same warm-then-`-n` flow drives the `launchctl`/`install`/`chmod` steps below. (The install.sh path is unchanged by this — it still always prompts for sudo and never piggybacks a cached credential; the warm-then-`-n` change is specific to the `sandbox update` Rust orchestrator.) The Linux orchestrator stops the systemd unit (`systemctl stop sandboxd`), replaces the binary, then starts the unit (`systemctl start sandboxd`). The macOS orchestrator uses the modern `bootout`/`bootstrap` verbs (legacy `unload`/`load` is deprecated since macOS 10.10):

- Stop: `sudo launchctl bootout system/io.sandboxd.daemon`
- Start: `sudo launchctl bootstrap system /Library/LaunchDaemons/io.sandboxd.daemon.plist`

The `was_running` lock-file field (M16 § Lock file) captures whether the daemon was running before the update; on macOS, it controls whether `bootstrap` is invoked after the swap. If the daemon was not running pre-update, the update completes with the daemon left stopped (operator must run `sudo launchctl bootstrap system /Library/LaunchDaemons/io.sandboxd.daemon.plist` manually) — same behavior as Linux.

**Agent/helper handling after swap.** On Linux the binary-swap replaces `sandbox-lima-helper` and re-applies `setcap cap_setuid+ep` — a hard step, since a helper that lost its caps would fail every post-update session. **On macOS there is no setuid/setcap step:** the swap replaces the per-operator agent binary (`sandbox-agent`, plain `root:wheel` 0755) and the daemon binary, with no privilege to re-apply. Running operator agents keep executing the old binary until their next launch, so the update should `launchctl kickstart -k` the loaded `io.sandboxd.agent` instances (or simply note that operators pick up the new agent at their next login).

#### Gateway Lima instance handling

The gateway Lima instance is **persistent across daemon restarts** (this spec § Gateway Lima instance § Lifecycle). On `sandbox update`:

1. The orchestrator stops the daemon (sessions already verified absent in pre-flight).
2. The orchestrator does **not** stop the gateway Lima instance — it remains running. This is intentional: socket_vmnet processes also remain running, so re-claiming pool slots after the daemon restart is fast (no socket_vmnet re-init).
3. The new daemon starts. During its step 4 (gateway init), it detects the running gateway instance and proceeds to verify Docker reachability.
4. The new daemon checks the gateway image tag inside the gateway Lima instance against its own version. If they match, no action. If they differ, the daemon **`docker load`s the new gateway image tarball** (staged by `sandbox update` at `/var/lib/sandboxd/<_sandbox-uid>/cache/` — there is no registry; see § Gateway image distribution) into the gateway Lima instance, then proceeds to readiness.
5. If the gateway Lima instance's *Lima template* itself changed between versions (e.g., the new daemon expects more NICs from a pool-size config change, or a different cpu/memory setting), the daemon detects the mismatch via the existing pool-resize handler (§ Pool resize handling) and either auto-recreates the gateway instance (if no sessions are present, which the pre-flight guaranteed) or fails with a clear error.

Gateway image refresh inside the Lima instance is fast (a single `docker load` of the staged image tarball — the gateway image is **never** pulled from a registry, § release pipeline — typically ~30 seconds). The update overhead on macOS is therefore: daemon stop → binary swap → daemon start → gateway image `docker load` → daemon ready — typically under one minute.

#### Tarball download (auto-download + air-gapped)

Recent master added auto-download to `sandbox update`. By default the orchestrator downloads the release tarball **and** its `.sigstore` bundle from GitHub Releases; `--from <tarball>` switches to a local file for air-gapped hosts (the cosign/MANIFEST verification path is identical either way). The URL contract (`release_asset_urls` / `download_tarball` in `sandbox-cli/src/update/fetch.rs`) is **v-prefixed tag in the path segment, bare version in the asset filename**:

```
{source_url}/v{version}/sandboxd-{version}-{arch}.tar.gz
{source_url}/v{version}/sandboxd-{version}-{arch}.tar.gz.sigstore
```

`{arch}` is the Rust target triple from `installed_arch`. On macOS that is **`aarch64-apple-darwin`** (Apple Silicon only), so the asset is `sandboxd-{version}-aarch64-apple-darwin.tar.gz` — exactly what the release pipeline publishes (§ Release tarball contents). The download uses the same `curl -fsSL --retry 3 --retry-delay 2` flags as install.sh and cleans up partial files on failure. (The v-prefix/bare-filename split is load-bearing: GitHub Releases serves assets only under the `v`-prefixed *tag* path while the asset name itself carries the bare semver — a recent fix, since the earlier code 404'd by using a bare version in the path segment.)

#### Cosign verification

cosign verification works on macOS without changes. The cosign binary itself is downloaded for the host architecture during install (`cosign-darwin-arm64` — Apple Silicon only) and **staged at `/usr/local/libexec/sandboxd/cosign`** (`root:wheel` 0755, off PATH — see Install paths). Its SHA256 expectation is added to the inline constants in install.sh alongside the existing Linux entries. Recent master moved this path off `/usr/local/bin/cosign` into the libexec helper dir: `sandbox update` **reuses** the install-staged cosign (`COSIGN_BIN_PATH = /usr/local/libexec/sandboxd/cosign` in `sandbox-cli/src/update/fetch.rs`) and surfaces an actionable `CosignNotFound` error pointing at install.sh rather than bootstrapping cosign itself — separation of concerns: install.sh owns cosign provisioning, update only consumes it. The macOS path follows the Linux convention exactly.

**Pin-table gap to close.** `cosign_pin_for_arch` (in `sandbox-cli/src/update/fetch.rs`) and the `lib.sh` SHA256 constants are currently **Linux-triples-only** — there is no `cosign-darwin-arm64` entry. As written, the macOS update path would either fail closed (no pin → refuse, acceptable) or, if naively stubbed, consume an *unverified* cosign — and that binary is the trust root for every subsequent update, so an unverified one is a security regression, not just an availability bug. Closing this means adding the pinned `cosign-darwin-arm64` version + SHA256 to **both** `lib.sh` and the Rust pin table (and the drift test that keeps them in lockstep), so `cosign_pin_for_arch("aarch64-apple-darwin")` resolves. This is a concrete implementation item, not a research question.

#### Backup retention

The 2-set backup retention model (M16 § Backup retention) works identically on macOS. Backups live under `/var/lib/sandboxd/<_sandbox-uid>/backups/`, owned by `_sandbox:_sandbox` (same convention as the rest of the state directory).

### M11 — lite-mode container backend on macOS

`BackendKind::Container` (lite mode) is supported on macOS by hosting sandbox containers **inside the sandboxd-managed gateway Lima instance** (`sandboxd-gateway`). Rejected alternative: hosting sandbox containers on the user's Docker Desktop / Colima / OrbStack — that would require cross-Docker bridging between two separate Linux VMs (the user's Docker host and the gateway Lima), which Docker does not support and which would fracture sandboxd's exclusive control over the gateway pipeline.

#### Architecture

For each lite session, sandboxd creates a **per-session internal Docker bridge network inside the gateway Lima instance** and attaches two containers to it — **the same topology the Linux container backend uses**, just targeting the gateway Lima VM's forwarded Docker socket instead of the host's:

- **Gateway container** — same image and lifecycle as Lima sessions (Envoy, CoreDNS, mitmproxy, deny-logger, allow-logger). Sits on the per-session bridge with the sandbox container (VM-facing side), and — like the full backend's gateway — carries a **second NAT-bridge NIC for its own upstream egress**.
- **Sandbox container** — the lite-mode session workload, also on the per-session bridge. Per M18, the lite image carries an sshd bound to `127.0.0.1:22`; the daemon-mediated SSH proxy reaches it via `docker -H <forwarded-gateway-socket> exec <container> socat - TCP:127.0.0.1:22`. CLI verbs (`sandbox ssh|cp|sync|workspace`) are identical to Linux lite mode — both flow through the proxy endpoint.

`sandbox-route-helper` — which already runs **inside the gateway Lima VM** (Linux substrate) — repoints the sandbox container's default route at the gateway container's per-session-bridge IP, so all sandbox egress is forced through the gateway's nftables/Envoy/mitmproxy. **Gateway → internet egress (lite):** the gateway container then re-originates the policed traffic out its NAT-bridge NIC → the gateway Lima VM's **`eth0` slirp/management uplink** → the macOS host → the internet — the same egress hop as the full backend, differing only in that the VM-facing side is an internal Docker bridge rather than a socket_vmnet macvlan segment. This is byte-for-byte the proven Linux container-backend interception path.

**No macvlan, no socket_vmnet for lite.** socket_vmnet/macvlan exist to put the gateway container on the *external* L2 segment shared with a **Lima-mode** sandbox **VM** (a genuine external host). In lite mode both endpoints are containers co-located inside the gateway Lima VM, so a plain internal bridge connects them — and the macvlan `private`-vs-`bridge` question (which would otherwise block gateway↔container traffic) does not arise at all. (This resolves the prior open verification item: lite mode does not use macvlan.)

The /29 socket_vmnet layout (§ Subnet allocation) applies to **Lima** sessions only. **Lite sessions use neither the /29 nor a socket_vmnet NIC** — their per-session network is an internal Docker bridge with a private subnet Docker assigns inside the gateway Lima VM:

| Role | Lima session (/29 on socket_vmnet) | Lite session (internal Docker bridge) |
|---|---|---|
| segment router | none — network-identifier segment has no host router (`B+1` reserved); VM default route = gateway container (`B+3`) | Docker bridge `.1` (NAT → gateway-Lima uplink) |
| gateway container | `B+3` (macvlan on the socket_vmnet NIC) | on the bridge (the sandbox's repointed default route) |
| sandbox endpoint | `B+4` (static) — sandbox **VM** via socket_vmnet | sandbox **container** on the same bridge |

#### Pool slot allocation

socket_vmnet NICs are consumed **only by Lima sessions** (each Lima sandbox VM needs an external L2 segment). **Lite sessions consume no socket_vmnet NIC** — they use an in-VM Docker bridge. `max_macos_sessions` (default 8) is the **total** concurrent-session cap across both backends, enforced by the daemon's session counter; the pool provisions N socket_vmnet NICs so up to N concurrent *Lima* sessions can run. At any moment, NIC usage = the number of running Lima sessions — an all-lite workload uses zero NICs, an all-Lima workload uses all N. This decouples lite concurrency from the fixed NIC count (lite is bounded by gateway-Lima-VM resources, not NICs, within the shared total).

#### ContainerRuntime platform-awareness

Mirroring `LimaRuntime`, `ContainerRuntime` gains an `is_macos: bool` and `docker_socket: Option<PathBuf>` set at construction by the daemon. When `is_macos`, every `Command::new("docker")` invocation inside `ContainerRuntime` injects `DOCKER_HOST=unix:///var/lib/sandboxd/<_sandbox-uid>/lima/sandboxd-gateway/gateway-docker.sock` — the same forwarded socket used by `GatewayManager` for gateway-container ops. On Linux, the field is `None` and docker commands hit the host daemon (unchanged).

**`docker build` HOME/DOCKER_CONFIG pinning (recent master).** The lite-image build path (`ensure_image` / `rebuild_lite_image` / `build_lite_image` in `sandbox-core/src/backend/container.rs`) now takes a `docker_home: &Path` and sets `HOME=<docker_home>` + `DOCKER_CONFIG=<docker_home>/docker` on the `docker build` subprocess. Production callers pass the daemon **base-dir**. The motivation: the Docker build client creates its config dir under `$HOME`, and a daemon running as a system user with a non-writable `HOME` (Linux `/nonexistent`; macOS the directory-service home) would abort the build at that `mkdir`. This is cross-platform — on macOS the daemon's `state.base_dir` (`/var/lib/sandboxd/<_sandbox-uid>`) is passed as `docker_home`, which is exactly the `HOME` the launchd plist already pins (§ launchd plist), so the lite-image build inside the gateway Lima instance lands its Docker client config in a writable, daemon-owned location.

#### Performance trade-off (the lite premise on macOS)

On Linux, lite mode's appeal is "skip the VM boot, get a session in ~2 seconds." On macOS the gateway Lima instance is already booted (persistent across daemon restarts), so the per-session overhead is dominated by per-session bridge creation + gateway container start + sandbox container start — typically ~5 seconds vs ~120 seconds for a Lima session. The win is still significant (24× faster) but smaller than the Linux delta (60× faster). This is documented as "macOS lite mode is fast but not instant; the gateway Lima VM dominates the cold-start cost the first time you start the daemon."

#### Workspace modes for lite on macOS

- `shared:` — Docker bind mount from inside the gateway Lima VM. The user's host workspace is exposed to the gateway Lima via Lima's own 9p `mounts:` stanza (added to the gateway Lima template at install time, *not* per-session), then bind-mounted into the sandbox container. Double-hop (host → gateway Lima VM → container) — acceptable for dev workloads. **Caveat (asymmetry vs Lima `shared:`):** the gateway Lima VM runs as `_sandbox` (daemon infra), so the host-side 9p access is performed by **`_sandbox`**, not the operator — unlike Lima-mode `shared:`, where the operator's own agent (in their login session) does it. Consequently lite `shared:` does **not** get the operator's TCC consent path (§ SIP and TCC), and the host source must be readable by `_sandbox`. Keep lite `shared:` sources outside TCC-protected dirs and readable by the daemon user (or prefer `local:`/`clone:`). Worth documenting as a real lite-vs-Lima difference.
- `local:` — rsync-based snapshot at session create. Identical to Lima sessions (the sandbox container is the rsync target instead of a VM).
- `clone:` — `git clone` inside the sandbox container at start. Platform-independent.

#### Differences in the session lifecycle

The lite `create` flow mirrors the **Linux container backend**, not the Lima QEMU-VM flow — all `docker` calls target the forwarded gateway-Lima Docker socket:

1. Create the per-session **internal Docker bridge** in the gateway Lima VM (not a macvlan-on-socket_vmnet network).
2. Start the gateway container with **two NICs** — the per-session bridge (VM-facing) and the shared `sandboxd-egress` NAT bridge (its default route, upstream egress → gateway Lima VM `eth0` → host; § Gateway → internet egress) — then apply deny-all nftables → wait for components healthy → inject DNAT (same gateway steps as a Lima session).
3. Start the **sandbox container** on the per-session bridge (`docker -H <gateway-socket> run --user <op_uid>:<op_gid> …`); it is *not* attached to `sandboxd-egress`.
4. `sandbox-route-helper` (in the gateway Lima VM) repoints the sandbox container's default route at the gateway container's per-session-bridge IP — so the sandbox's only egress is through the gateway.

There is **no `limactl` and no socket_vmnet slot** in the lite path. `stop`/`start`/`rm` manage the two containers + the per-session bridge.

### M17 — workspace modes and workspace-lock

- **`shared:` workspace mode**: see "Workspace mount type" subsection above. `mountType` is `9p` on **both** platforms (both run QEMU), so there is no `is_macos` branch and `securityModel` applies identically.
- **`local:` workspace mode**: rsync-based snapshot at session create, plus `sandbox workspace push`/`pull` during the session. Platform-independent — uses the same rsync codepath on both platforms. On macOS the rsync target is the sandbox VM (over Lima's SSH transport), which works identically whether the VM runs under QEMU on Linux or QEMU on macOS.
- **Workspace-lock subsystem**: in-memory per-session mutex inside the daemon, serializing push/pull ops and refusing `sandbox stop`/`sandbox delete` against locked sessions. Daemon-internal — platform-independent. `sandbox workspace unlock --force` works the same on macOS.

No macOS-specific work is needed for workspace-lock. The `shared:` mountType branch and the rsync transport's reliance on Lima's SSH (rather than any platform-specific channel) are the only workspace-related macOS deltas.

---

## Networking design corrections

The following corrections to `networking-design.md` have been **applied** (kept here as the rationale record). #5 is the newest, from the task-A spike.

### 1. macOS backend = QEMU + socket_vmnet; ban vzNAT and SLIRP (gap — not mentioned at all)

Add a subsection under "VM-to-gateway connectivity § macOS" explicitly stating:

> macOS sandbox VMs run under **`vmType: "qemu"`** (HVF-accelerated on Apple Silicon), **not** VZ. The full backend needs an isolated L2 segment the gateway can intercept; the only attachment that provides one is **socket_vmnet**, which attaches to QEMU, not VZ (VZ's `VZFileHandleNetworkDeviceAttachment` is wire-incompatible with socket_vmnet's QEMU framing — [socket_vmnet#13](https://github.com/lima-vm/socket_vmnet/issues/13)). All sandbox VMs must configure a **per-VM** `networks: [{socket: /var/run/sandbox/vmnet/slot-<n>.sock}]` entry — the unmanaged socket_vmnet attach, **not** a named network in the global `networks.yaml` (Lima rejects `socket:` there).
>
> Two "NAT the guest straight to the internet" attachments must **never** be used, because each gives the guest a direct egress path that bypasses the gateway (nftables PREROUTING DNAT has nothing to intercept; Envoy/mitmproxy see nothing):
> - **QEMU user-mode networking / SLIRP** (`-netdev user`, QEMU's *default*) — the live hazard under the QEMU backend.
> - **vzNAT** (`VZNATNetworkDeviceAttachment`) — VZ's NAT; moot under QEMU but listed so a future backend reconsideration never reintroduces it.

### 2. Pool justification (wrong reason given)

The current text justifies the vmnet pool as a startup-cost optimization. This is incorrect — VM boot time (~2 minutes) dwarfs socket_vmnet initialization. The real reason:

> The pool pre-provisions NICs on the gateway Lima instance because Lima attaches a VM's `networks:` NICs only at instance-creation time and offers no supported way to add a NIC to an already-created instance. Dynamic per-session NIC attachment to the gateway instance is therefore impossible without recreating it, which would disrupt all live sessions. The pool is not a performance optimization; it is the only viable architecture under Lima's fixed-at-creation NIC model.

### 3. "Colima" terminology (wrong architecture described)

networking-design.md's macOS section refers to "Colima (sandboxd-managed)" throughout. The architecture does not use Colima. Replace all occurrences of "Colima" (in the macOS section) with "sandboxd-managed Lima gateway instance (`sandboxd-gateway`)". Specifically: lines describing the gateway instance (currently "Colima VM"), gateway egress ("Colima's external interface"), and the ASCII diagram ("Colima VM (one, managed by sandboxd)").

### 4. Subnet size (wrong: /30, should be /29)

networking-design.md states: "Each instance has its own /30 subnet (2 usable IPs: one for the gateway, one for the sandbox VM)." This is wrong — a /30 has only two usable IPs, but three participants need addresses (spike-confirmed): the **host-side vmnet gateway (`B+1`)**, the gateway container (`B+3`), and the sandbox VM (`B+4`); the macvlan parent (`B+2`) is link-only. The correct size is /29 (6 usable IPs). Updated the description and the subnet diagram accordingly.

### 5. Management slirp NIC must be `restrict=on` (cross-platform — also fixes shipping Linux)

**Supersedes the "never use `-netdev user`" framing in #1.** Lima's *management* NIC **is** `-netdev user` (slirp `eth0`) and cannot be removed — Lima needs it for SSH/readiness — so the requirement is to **restrict** it, not omit it. The task-A spike (2026-06-14) confirmed that NIC NATs straight to the internet, and that route-metric deprioritization (Linux `qmp.rs` `metric 50`) is overridable by a root guest. networking-design.md now states the management NIC is **`-netdev user,restrict=on`** on **both** platforms — a QEMU/slirp-layer hard egress block (host→guest SSH `hostfwd` preserved; guest-initiated egress dropped, spike-verified). The socket_vmnet/bridge gateway NIC stays the only egress path. **Linux has since implemented this** (#65, commit `4b134ec`): the `lima.rs` qemu-wrapper injects `restrict=on`, gated by `SANDBOX_UNRESTRICTED_SLIRP_FOR_PROVISIONING` (base-image builds stay unrestricted; sessions restricted). macOS mirrors the same wrapper.
