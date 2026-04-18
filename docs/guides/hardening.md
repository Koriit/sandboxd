---
title: Hardening
description: The layers of defence applied to every session, what they protect against, and how to turn each knob up or down.
---

Every sandbox session is hardened by default — you do not opt in. This guide walks through each hardening layer as an operational knob: what it protects against, how it is configured, and when (if ever) you would turn it off. For the broader security model, see [networking](/concepts/networking/) and [policy model](/concepts/policy-model/).

## The security model

Hardening operates at five layers, from the outside in:

| Layer | Protects against |
|---|---|
| QEMU device + cgroup lockdown | VM escape via QEMU exploitation; runaway resource use |
| KVM hardware isolation | Guest access to host memory |
| Network isolation | Cross-session traffic, direct-internet bypass |
| TLS interception | Unmonitored HTTPS egress |
| Guest OS | In-VM privilege escalation, path traversal |

`SessionConfig.hardened` is `true` by default. `--no-hardening` disables the **QEMU-level** protections only. Network isolation and TLS interception remain on unconditionally — you cannot disable them per session.

Read the layers in order: an attacker has to defeat each one in turn to reach your host, and the higher layers are deliberately the cheapest to preserve.

## Layer 1 — QEMU wrapper

QEMU runs through a wrapper at `~/.local/share/sandboxd/libexec/qemu-system-x86_64` (or `$XDG_DATA_HOME/sandboxd/libexec/` if you set that variable). The wrapper injects security flags and wraps the process in a systemd scope for resource limits.

### Device lockdown

In hardened mode, the wrapper strips emulated devices and ignores user QEMU config:

| Flag | Effect |
|---|---|
| `-no-user-config` | Ignore user-level QEMU config files |
| `-display none` | No graphical display |
| `-vga none` | No VGA device |

The Lima template reinforces this at VM creation time:

```yaml
video:
  display: "none"
audio:
  device: "none"
```

Only three virtio devices remain:

- `virtio-net-pci` — data plane, attached at boot via `qemu-bridge-helper`.
- `virtio-blk` — disk I/O, managed by Lima.
- `virtio-rng-pci` — entropy source, explicitly added by the wrapper so the guest kernel's RNG initializes promptly.

Each absent device (USB, sound, VGA) removes a category of device-emulation bugs.

### Cgroup resource limits

When `SANDBOX_QEMU_MEMORY_MB` and `SANDBOX_QEMU_CPUS` are set and `systemd-run` is available, the wrapper places QEMU in a transient `sandbox.slice` scope:

| Limit | Default | Purpose |
|---|---|---|
| `MemoryMax` | `memory_mb` + 512 MB headroom | OOM-kill QEMU if it exceeds the cap |
| `CPUQuota` | `cpus * 100%` | Limit CPU time to N cores |
| `TasksMax` | 256 | Cap threads QEMU can spawn |

Check a running session's cgroup placement:

```bash
pgrep -af 'qemu.*sandbox-'
cat /proc/<pid>/cgroup
systemctl --user status sandbox.slice
```

If `systemd-run` is not available, the wrapper falls back to running QEMU directly — device lockdown still applies, but resource limits default to the kernel's baseline.

### Seccomp is deliberately off

QEMU's `-sandbox on` requires `PR_SET_NO_NEW_PRIVS`, which strips setuid from child processes. `qemu-bridge-helper` — the tool that attaches the data NIC to the Docker bridge — is setuid, so enabling seccomp would break networking for every session. The remaining layers (device lockdown, cgroup limits, KVM isolation, gateway enforcement) provide the defence-in-depth instead.

## Layer 2 — Gateway container

The gateway container ships with a tight capability set and a read-only root.

- **Capability set:** `CAP_NET_ADMIN` only. Required for managing nftables inside the container's own netns. No host-level nftables touch.
- **`--read-only` root:** container filesystem is immutable. Writable paths (logs, PID files) come from tmpfs mounts. CA certificate files are bind-mounted read-only from the host.
- **No sudo on the host:** the entire daemon runs as a regular user. The only host privileges required are membership in the `docker` and `kvm` groups.

## Layer 3 — Network isolation

Network hardening cannot be turned off per session. For the full model see [networking](/concepts/networking/). The security-relevant guarantees:

- **Per-session bridge.** Each session lives on its own `/28` Docker bridge. Sessions cannot reach each other.
- **Deny-all baseline.** nftables rules in the gateway drop every forwarded packet by default. DNAT rules that route traffic through the proxy pipeline are installed only after all three gateway components pass readiness.
- **Gateway-mediated egress.** The VM's single data NIC routes through the gateway. There is no alternate path to the internet.
- **Metadata endpoint blocked.** `169.254.169.254` is dropped at nftables. IAM tokens and cloud instance metadata are unreachable.
- **IPv4 only.** IPv6 is dropped at nftables to prevent dual-stack bypass:

```
ip6 daddr != ::1 drop
```

## Layer 4 — TLS interception

Each session gets its own ECDSA P-256 CA. The CA uses SHA-1 for Subject Key Identifier computation (RFC 5280 § 4.2.1.2 method 1) so that SKI matches the AKIs mitmproxy writes on signed certificates.

CA files live at:

```
~/.local/share/sandboxd/sessions/{session_id}/ca/
    cert.pem                 # public
    key.pem                  # private (PKCS#8 PEM)
    mitmproxy-ca.pem         # key + cert concatenated
    mitmproxy-ca-cert.pem    # cert-only alias
```

The **private key never enters the VM.** It is bind-mounted read-only into the gateway container. The VM receives only `cert.pem`, installed into:

| Variable | Value |
|---|---|
| `SSL_CERT_FILE` | `/etc/ssl/certs/ca-certificates.crt` |
| `REQUESTS_CA_BUNDLE` | `/etc/ssl/certs/ca-certificates.crt` |
| `NODE_EXTRA_CA_CERTS` | `/usr/local/share/ca-certificates/sandbox-ca.crt` |
| `CURL_CA_BUNDLE` | `/etc/ssl/certs/ca-certificates.crt` |

Plus the system trust store (`update-ca-certificates`) and the in-VM Docker daemon's registry trust store.

## Layer 5 — Guest OS

- **Non-root `agent` user.** Sandbox workloads run as `agent`, not root. The account has passwordless sudo for operations the guest agent needs (network config, CA injection), but nothing runs as root by default.
- **Minimal cloud image.** Ubuntu 24.04 server cloud image — no desktop, no dev tools beyond what provisioning adds.
- **Path validation.** The guest agent only accepts file operations in allow-listed directories:

  | Directory | Purpose |
  |---|---|
  | `/home/agent/` | Agent user home |
  | `/root/` | Legacy workspace path |
  | `/tmp/` | Temporary files |

  Paths under `/proc`, `/sys`, `/dev`, `/etc` are rejected even if they appear under an allowed prefix. Traversal with `..` is detected and denied.
- **Message size cap.** The host-to-guest protocol rejects messages larger than 1 MB before processing, preventing memory-exhaustion attacks against the guest agent.

## Disabling hardening

`--no-hardening` exists for debugging, not production:

```bash
sandbox create --name debug-session --no-hardening
```

What it turns off — and, crucially, what it does not:

| Feature | Disabled by `--no-hardening`? |
|---|---|
| Cgroup resource limits | Yes |
| Device lockdown (`-no-user-config`, `-display none`, `-vga none`) | Yes |
| Lima template `video: none`, `audio: none` | Yes |
| `virtio-rng-pci` injection | Yes |
| Per-session network isolation | **No** |
| nftables firewall | **No** |
| TLS interception | **No** |
| Guest OS path validation | **No** |
| Message size limits | **No** |

### When to use it

- Diagnosing a VM that will not boot, to rule out the restricted device model.
- Running a workload that genuinely needs a display device (unusual).
- Investigating QEMU crashes where device emulation might be the root cause.

Do not run `--no-hardening` against real workloads. The hardened configuration is the default for a reason.

## Security trade-offs you choose

### 9p shared mounts

`--workspace shared:<path>` adds a 9p filesystem device to the VM so a host directory is live-visible inside. This is the largest deliberately-offered reduction in isolation:

- An additional host-to-guest device surface that does not exist in clone mode.
- The guest has direct read-write access to the chosen host directory.
- Writes flow both ways with no review or approval step.

Use clone mode (`--repo`) plus `sandbox cp` or git remote transport when isolation matters more than convenience. See [workspaces concepts](/concepts/workspaces/) for the trade-off and [workspaces guide](/guides/workspaces/) for the commands.

### SLIRP management network

The VM has two NICs. `eth1` is a TAP device on the per-session Docker bridge — the data plane that routes through the gateway. `eth0` is a **SLIRP** interface used only for Lima's SSH management channel. This section explains what SLIRP is and why it's the trade-off it is.

**What SLIRP is.** SLIRP is a user-mode networking stack bundled with QEMU. Rather than bridging the guest NIC to a real host interface (which requires a TAP device and elevated privileges), SLIRP implements a small TCP/IP stack inside the QEMU process itself: it terminates the guest's packets, translates them into ordinary socket calls on the host, and proxies the responses back. The guest sees a functioning network; the host sees QEMU making normal outbound connections. SLIRP also forwards selected host ports into the guest, which is how Lima obtains its SSH channel without any privileged networking setup.

**Why Lima uses it.** No TAP device, no bridge configuration, no root — it works out of the box on any developer machine. That is a real portability win for a per-session VM.

**What it costs.** SLIRP runs in-process with QEMU, so any bug in its packet-handling code executes in the same address space as the hypervisor. That widens the QEMU attack surface compared to a plain TAP bridge, where the kernel does the forwarding. SLIRP is also slower than a TAP bridge and emulates some protocols (ICMP, raw sockets) only partially.

**How the sandbox contains that.** SLIRP is confined to `eth0` and carries only Lima's SSH traffic — all outbound application traffic goes over `eth1` to the gateway. The guest adds a default route over `eth1` with a lower metric than SLIRP's, so internet-bound traffic prefers the gateway path; SSH and Lima management still ride SLIRP. The policy layer (DNS filtering, nftables, Envoy, mitmproxy) only applies to traffic that reaches the gateway — that is by construction true for the data plane, since SLIRP has no route to anything a user workload would use.

Removing SLIRP would require replacing Lima's SSH provisioning; it is not currently configurable.

## Related reading

- [Networking](/concepts/networking/) — how the network-isolation layer actually works.
- [Policy model](/concepts/policy-model/) — the contract that defines what traffic is allowed.
- [Workspaces concepts](/concepts/workspaces/) — the isolation cost of each provisioning mode.
- [Troubleshooting](/guides/troubleshooting/) — when a hardened session misbehaves.
