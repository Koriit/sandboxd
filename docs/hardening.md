# Hardening

This guide explains the security hardening applied to sandbox sessions. Every session is hardened by default -- no opt-in or configuration is needed. This document describes what is hardened, how each layer works, and how to disable hardening for debugging.

## Overview

Hardening operates at five layers:

| Layer | What it protects against |
|-------|--------------------------|
| QEMU sandboxing | VM escape via QEMU process exploitation |
| Device model lockdown | Attack surface from unnecessary emulated hardware |
| Network isolation | Cross-session communication, direct internet access |
| TLS interception | Unmonitored outbound HTTPS traffic |
| Guest OS | Privilege escalation, path traversal within the VM |

All layers are enabled when `SessionConfig.hardened` is `true`, which is the default. The `--no-hardening` CLI flag disables the QEMU-level protections (seccomp, device lockdown, cgroup limits) but does not affect network isolation or TLS interception.

## QEMU sandboxing

The sandbox runs QEMU through a wrapper script (`~/.sandboxd/libexec/qemu-system-x86_64`) that injects security flags and resource limits. Lima invokes this wrapper via the `QEMU_SYSTEM_X86_64` environment variable.

### Seccomp filter

When hardened mode is active (`SANDBOX_QEMU_HARDENED=1`), the wrapper adds:

```
-sandbox on,obsolete=deny,elevateprivileges=deny,spawn=allow
```

This enables QEMU's built-in seccomp sandbox with two deny policies and one allow:

| Policy | Effect |
|--------|--------|
| `obsolete=deny` | Blocks deprecated syscalls that have known exploitation patterns |
| `elevateprivileges=deny` | Prevents the QEMU process from gaining elevated privileges |
| `spawn=allow` | Allows QEMU to spawn child processes (required for `qemu-bridge-helper` to create TAP devices) |

The seccomp filter is applied by QEMU itself at startup, before the guest begins executing. If a vulnerability allows code execution within the QEMU process, these restrictions limit what the attacker can do.

### Cgroup resource limits

When the environment variables `SANDBOX_QEMU_MEMORY_MB` and `SANDBOX_QEMU_CPUS` are set (propagated from `SessionConfig`), and `systemd-run` is available, the wrapper places QEMU in a transient systemd scope with resource limits:

```bash
systemd-run --user --scope --slice=sandbox.slice \
    -p MemoryMax="${SANDBOX_QEMU_MEMORY_MB}M" \
    -p "CPUQuota=${SANDBOX_QEMU_CPUS}00%" \
    -p TasksMax=256 \
    /usr/bin/qemu-system-x86_64 ...
```

| Limit | Default | Effect |
|-------|---------|--------|
| `MemoryMax` | 4096M (from `SessionConfig.memory_mb`) | OOM-kills the QEMU process if it exceeds the limit |
| `CPUQuota` | 200% (from `SessionConfig.cpus = 2`) | Limits CPU time to the equivalent of N cores |
| `TasksMax` | 256 | Limits the number of threads/processes QEMU can create |

All sandbox QEMU processes are placed under a `sandbox.slice` cgroup, making it easy to monitor resource usage across all sessions:

```bash
systemctl --user status sandbox.slice
```

### Fallback behavior

If `systemd-run` is not available (e.g., on systems without systemd user sessions), the wrapper falls back to running QEMU directly without cgroup limits. The seccomp sandbox and device lockdown still apply. Resource limits in this configuration depend on the host OS kernel's default cgroup policies.

To check whether cgroup limits are active for a running session:

```bash
# Find the QEMU process
pgrep -af 'qemu.*sandbox-'

# Check if it is in a systemd scope
cat /proc/<pid>/cgroup
```

## Device model lockdown

In hardened mode, the QEMU wrapper strips unnecessary emulated devices and disables features that expand the attack surface.

### Flags applied

```
-no-user-config -display none -vga none
```

| Flag | Effect |
|------|--------|
| `-no-user-config` | Ignores user-level QEMU configuration files |
| `-display none` | Disables graphical display output |
| `-vga none` | Removes VGA device emulation |

### Devices retained

Only three virtio devices remain:

| Device | Purpose |
|--------|---------|
| `virtio-net-pci` | Network connectivity (added at boot by the QEMU wrapper via `qemu-bridge-helper`) |
| `virtio-blk` | Disk I/O (managed by Lima) |
| `virtio-rng-pci` | Guest entropy source (added by the wrapper: `-device virtio-rng-pci`) |

The `virtio-rng-pci` device is explicitly added in hardened mode to ensure the guest kernel's random number generator initializes quickly. Without it, `/dev/random` would be extremely slow, causing long boot times and potential hangs.

### Lima template settings

The Lima template also contributes to device lockdown:

```yaml
video:
  display: "none"
audio:
  device: "none"
```

Lima translates these into additional QEMU flags at VM creation time, ensuring no display or sound device is attached regardless of what the QEMU defaults would otherwise include.

### Devices not present

The following devices are explicitly absent in hardened mode:

- USB controller and devices
- Sound card
- VGA/display adapter

Each absent device eliminates a category of device-emulation bugs that could be exploited from within the guest.

## Gateway container hardening

The gateway container is configured with a minimal capability set and a read-only filesystem.

### Capabilities

The gateway container is granted only `CAP_NET_ADMIN` (via `--cap-add NET_ADMIN`). This is required for managing nftables rules inside the container. No other elevated capabilities are granted. The daemon manages nftables rules by running `docker exec ... nft` commands inside the container -- no sudo or host-level nftables access is used.

### Read-only filesystem

The container runs with `--read-only` to prevent modifications to the container filesystem. Writable paths are mounted as tmpfs volumes for directories that need runtime writes (logs, PID files, and similar transient data). CA certificate files are bind-mounted read-only from the host.

### No root/sudo on host

The entire sandbox daemon runs as a regular user. No sudo, root, or sudoers configuration is required. The daemon needs only `docker` and `kvm` group membership. The gateway container's `CAP_NET_ADMIN` is scoped to the container's own network namespace and does not grant any host-level privilege.

## Network isolation

Network hardening is always active regardless of the `--no-hardening` flag. See the [networking guide](networking.md) for full details. This section summarizes the security-relevant properties.

### Per-session Docker bridge

Each session gets its own Docker bridge network with a /28 subnet (e.g., `10.209.0.0/28`). Sessions cannot communicate with each other because they are on separate L2 segments with no routing between them.

### nftables deny-all baseline

The gateway container starts with deny-all nftables rules, injected via `docker exec` immediately after container creation, before any gateway component is ready:

- **Input chain:** Drop all inbound traffic (except loopback and established connections).
- **Forward chain:** Drop all forwarded traffic.
- **Output chain:** Allow all (the gateway itself needs internet access to forward traffic).

DNAT rules that route traffic through the proxy pipeline are injected only after all gateway components (Envoy, CoreDNS, mitmproxy) pass their readiness checks. This ordering prevents any traffic from leaking before the full enforcement pipeline is operational.

### Gateway-mediated traffic

The VM's single data NIC routes all traffic through the gateway container. There is no alternate path to the internet. The traffic flow is:

1. VM packets exit via virtio-net to the Docker bridge.
2. nftables PREROUTING DNAT rules redirect DNS to CoreDNS and all TCP to Envoy.
3. Envoy routes connections through mitmproxy (for inspection) or directly to the destination (for passthrough).

### Metadata endpoint blocked

Cloud provider metadata endpoints are explicitly blocked:

```
ip daddr 169.254.169.254 drop
```

This prevents the VM from accessing cloud instance metadata, which often contains IAM credentials, instance identity tokens, and other sensitive information.

### IPv6 dropped

All non-loopback IPv6 traffic is dropped at the nftables level:

```
ip6 daddr != ::1 drop
```

The sandbox is IPv4-only. IPv6 is blocked to prevent dual-stack bypass attacks where an application could use IPv6 to circumvent the IPv4-based proxy pipeline.

## TLS interception

Each session gets its own CA certificate for HTTPS inspection. This allows the sandbox to inspect and enforce policies on encrypted traffic.

### Per-session ECDSA P-256 CA

At session creation, sandboxd generates an ECDSA P-256 CA keypair. The CA uses SHA-1 for Subject Key Identifier computation (RFC 5280 section 4.2.1.2, method 1) to match how mitmproxy computes Authority Key Identifiers when signing intercepted certificates. This prevents SKI/AKI mismatches that would cause certificate chain verification to fail.

CA files are stored in the session directory:

```
~/.sandboxd/sessions/{session_id}/ca/
    cert.pem                  # CA certificate (public)
    key.pem                   # CA private key (PKCS#8 PEM)
    mitmproxy-ca.pem          # key + cert concatenated (mitmproxy format)
    mitmproxy-ca-cert.pem     # cert-only alias
```

### CA private key never enters the VM

The CA private key (`key.pem`) is bind-mounted read-only into the gateway container for mitmproxy to use. It is never copied into the VM. The VM receives only the public certificate (`cert.pem`), which is injected into the system trust store and application-specific trust stores via environment variables:

| Variable | Value |
|----------|-------|
| `SSL_CERT_FILE` | `/etc/ssl/certs/ca-certificates.crt` |
| `REQUESTS_CA_BUNDLE` | `/etc/ssl/certs/ca-certificates.crt` |
| `NODE_EXTRA_CA_CERTS` | `/usr/local/share/ca-certificates/sandbox-ca.crt` |
| `CURL_CA_BUNDLE` | `/etc/ssl/certs/ca-certificates.crt` |

### Session isolation

Each session uses a different CA keypair. Compromise of one session's CA does not affect other sessions. CA files are deleted when a session is removed.

## Guest OS hardening

### Dedicated `agent` user

The VM runs an `agent` user with a home directory at `/home/agent`. The agent user has passwordless sudo for system operations (required by the guest agent for network configuration and CA injection), but all sandbox workloads run under this user account rather than root.

### Minimal cloud image

The VM uses Ubuntu 24.04 server cloud images (`ubuntu-24.04-server-cloudimg-amd64.img`). Cloud images are minimal by default -- they contain only the packages needed for a functioning system. No desktop environment, no unnecessary services, no development tools beyond what is explicitly provisioned.

### Path validation in guest agent

The guest agent validates all file transfer paths before performing operations. Only paths within the following directories are permitted:

| Allowed directory | Purpose |
|-------------------|---------|
| `/home/agent/` | Agent user home directory |
| `/root/` | Root home (legacy workspace path) |
| `/tmp/` | Temporary files |

Paths outside these directories are rejected. Additionally, paths under system directories (`/proc`, `/sys`, `/dev`, `/etc`) are always denied, even if they appear to be under an allowed prefix. Path traversal using `..` components is detected and rejected.

### Message size limits

The host-guest communication protocol enforces a 1 MB maximum message size. Messages exceeding this limit are rejected before processing, preventing memory exhaustion attacks against the guest agent.

## Disabling hardening

Pass `--no-hardening` when creating a session:

```bash
sandbox create --name debug-session --no-hardening
```

### What `--no-hardening` disables

| Feature | Disabled? |
|---------|-----------|
| Seccomp filter | Yes |
| Cgroup resource limits | Yes |
| Device lockdown (`-no-user-config`, `-display none`, `-vga none`) | Yes |
| Lima template `video: none`, `audio: none` | Yes |
| `virtio-rng-pci` injection | Yes |
| Per-session network isolation | No |
| nftables firewall | No |
| TLS interception | No |
| Guest OS path validation | No |
| Message size limits | No |

### When to use `--no-hardening`

- **Debugging VM boot issues.** The hardened device model can cause compatibility problems with certain guest configurations. If a VM fails to boot, disabling hardening can help isolate whether the issue is caused by the restricted device model.
- **Running graphical applications.** If the workload requires a display device (unlikely in sandbox use cases), hardening must be disabled.
- **Diagnosing QEMU crashes.** The seccomp filter may block syscalls that QEMU needs for specific operations. Disabling hardening removes the seccomp filter, allowing you to determine if the crash is seccomp-related.

Do not use `--no-hardening` in production. The hardened configuration is the tested and supported default.

## Security trade-offs

### 9p shared mounts

When using shared workspace mode (`--workspace shared:<path>`), a 9p filesystem device is added to the VM. This expands the attack surface:

- **Additional device.** 9p adds a host-guest filesystem interface that does not exist in the default configuration.
- **Host directory access.** The guest has direct read-write access to a host directory. A VM escape combined with 9p access could compromise host files.
- **Bidirectional writes.** Changes made by the guest are immediately visible on the host and vice versa. There is no review or approval step.

Use clone mode (`--repo`) or file transfer (`sandbox cp`) instead of shared mounts when isolation is more important than convenience. See the [workspace modes guide](workspaces.md) for details.

### SLIRP networking

Lima uses SLIRP (user-mode networking) for the VM's management interface (`eth0`). SLIRP provides SSH access to the VM without requiring root privileges or TAP device setup. However:

- SLIRP runs in the QEMU process's address space, adding to its attack surface.
- The management interface is separate from the sandbox data plane (`eth1`), which routes through the gateway. The data plane uses a real TAP device and Docker bridge.
- The sandbox sets a lower route metric (50) on the data plane interface so that internet traffic prefers the gateway-mediated path. SSH and Lima management traffic still flows over SLIRP via `eth0`.

SLIRP is a Lima requirement for VM management. It cannot be removed without replacing Lima's SSH provisioning mechanism.
