---
title: Hardening
description: The layers of defence applied to every session, what they protect against, and how to turn each knob up or down.
---

Every sandbox session is hardened by default — you do not opt in. This guide walks through each hardening layer as an operational knob: what it protects against, how it is configured, and when (if ever) you would turn it off. For the broader security model, see [networking](/sandboxd/concepts/networking/) and [policy model](/sandboxd/concepts/policy-model/).

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

When `SANDBOX_QEMU_MEMORY_MB` and `SANDBOX_QEMU_CPUS` are set and the user-systemd bus is reachable, the wrapper places QEMU in a transient `sandbox.slice` scope:

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

If `systemd-run` is not on `PATH` **or** the daemon's user-systemd bus is not reachable, the wrapper falls back to running QEMU directly — device lockdown still applies, but resource limits default to the kernel's baseline. When this happens the QEMU wrapper prints a warning to stderr:

```
WARNING: sandboxd qemu-wrapper: user-systemd bus unreachable or systemd-run absent -- cgroup limits (MemoryMax/CPUQuota/TasksMax) are NOT applied to this VM. Run: loginctl enable-linger <operator-user>
```

#### Prerequisite: `loginctl enable-linger`

**Cgroup enforcement requires a running user manager (`/run/user/<uid>`) for the operator.** A service-account operator that has no active login session and no linger enabled has `systemd-run` on `PATH` but no user bus, so `systemd-run --user --scope` would abort immediately with `Failed to connect to bus: No medium found`. The wrapper's `systemctl --user show-environment` probe catches this before exec'ing `systemd-run`, and falls back to running QEMU without limits.

To permanently enable the user manager for a system-user operator (e.g. the `sandbox` account), run once as root:

```bash
loginctl enable-linger <operator-user>
# Example for the sandbox system user:
loginctl enable-linger sandbox
```

Without an active login session **or** `enable-linger`, session VMs boot **without** cgroup limits — `MemoryMax`, `CPUQuota`, and `TasksMax` are not enforced. Verify after enabling:

```bash
loginctl show-user <operator-user> | grep Linger
# Expected: Linger=yes
systemctl --user -M <operator-user>@ status
# Expected: systemd user manager is active
```

### Seccomp is deliberately off

QEMU's `-sandbox on` requires `PR_SET_NO_NEW_PRIVS`, which strips setuid from child processes. `qemu-bridge-helper` — the tool that attaches the data NIC to the Docker bridge — is setuid, so enabling seccomp would break networking for every session. The remaining layers (device lockdown, cgroup limits, KVM isolation, gateway enforcement) provide the defence-in-depth instead.

## Layer 2 — Gateway container

The gateway container ships with a tight capability set and a read-only root.

- **Capability set:** `CAP_NET_ADMIN` only. Required for managing nftables inside the container's own netns. No host-level nftables touch.
- **`--read-only` root:** container filesystem is immutable. Writable paths (logs, PID files) come from tmpfs mounts. CA certificate files are bind-mounted read-only from the host.
- **No sudo on the host:** the entire daemon runs as a regular user. The only host privileges required are membership in the `docker` and `kvm` groups.

### Privileged helpers and the `SANDBOX_USERS_CONF` boundary

Three privileged helpers exist in the install footprint: `qemu-bridge-helper` (setuid root, ships with QEMU), `sandbox-route-helper` (cap'd `cap_net_admin,cap_sys_admin=eip`, lives at `/usr/local/libexec/sandboxd/sandbox-route-helper`), and `sandbox-lima-helper` (cap'd `cap_setuid+ep`, lives at `/usr/local/libexec/sandboxd/sandbox-lima-helper`). All three are invoked by the daemon, not by operators directly. `qemu-bridge-helper` cross-checks the caller's uid against its own ACL before attaching a TAP device; `sandbox-route-helper` enforces a **pair-membership check** against `/etc/sandboxd/users.conf` before any namespace mutation — both the calling process's uid (the daemon, via `getuid`) and the operator name passed in `--for-user` (which the daemon reads from `SO_PEERCRED` on its accepted Unix socket) must appear in the same pool's `allow_users`. A compromised daemon cannot invent operator names that are not already paired with its own runtime uid; a local user with `allow_users` access cannot drive the helper from outside the daemon because they cannot forge the `SO_PEERCRED`-derived `--for-user` argument the daemon supplies. Every allow/deny decision is recorded to a JSON-Lines audit log; see [Audit log](/sandboxd/start/installation/#audit-log) in the installation guide for the on-disk path, field set, and the deny-path-write-failure escalation contract.

`sandbox-lima-helper` pivots the daemon to an operator's uid before exec'ing `limactl` for every Lima control-plane operation. Two gates protect it: (1) a kernel-enforced caller-uid check (`getuid() == sandbox-system-user-uid`) that confines it to the daemon process; (2) membership in the `sandbox` group. Unlike `sandbox-route-helper`, it carries no `--for-user` pair-membership check — its allowed callers are limited to the daemon uid at the kernel level rather than through an ACL file. `cap_setuid` is a substantially stronger capability than the `cap_net_admin` the route-helper holds, so its narrow invocation surface (daemon only, kernel-gated) is the primary containment. See [Per-operator LIMA_HOME](/sandboxd/guides/per-operator-lima-home/) for how the helper fits into the full per-operator Lima lifecycle.

The `sandbox-route-helper` binary's authorization model rests on the integrity of `/etc/sandboxd/users.conf`. Two concrete defences keep the file trustworthy:

1. **Defensive ownership/mode check at config-load time.** The loader refuses to read the canonical path if the file is not owned by uid 0, or if it carries any group/world-write bits. A misconfigured `chmod 666 /etc/sandboxd/users.conf` cannot grant any user write access to the auth list — the loader bails before parsing, with an error pointing at the install runbook.
2. **`SANDBOX_USERS_CONF` env-var override is feature-gated in the helper.** The daemon honors the env var unconditionally (the daemon is not the privilege boundary; it runs as the operator). The route helper, however, runs with `cap_net_admin,cap_sys_admin=eip` — granting any user who can exec it kernel-level namespace authority. Honoring an attacker-controlled env var inside the cap'd binary would let any local user point the helper at a `users.conf` they own, granting themselves arbitrary `allow_users` entries. Production builds of the route helper therefore **ignore** `SANDBOX_USERS_CONF` entirely; only test builds (`cargo build --features test-env-override`, installed at `/usr/local/libexec/sandboxd-test/` and never used by the daemon) consult it. The split makes the privilege boundary auditable: the file capability and the env-var seam cannot co-exist in the same binary.

## Layer 3 — Network isolation

Network hardening cannot be turned off per session. For the full model see [networking](/sandboxd/concepts/networking/). The security-relevant guarantees:

- **Per-session bridge.** Each session lives on its own `/28` Docker bridge. Sessions cannot reach each other.
- **Deny-all baseline.** nftables rules in the gateway drop every forwarded packet by default. DNAT rules that route traffic through the proxy pipeline are installed only after the gateway's policy-enforcing components (CoreDNS, Envoy, mitmproxy) and audit loggers (sandbox-nft-deny-logger, sandbox-nft-allow-logger) pass readiness.
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

- **Non-root guest user.** Sandbox workloads run as a non-root user, not root. The in-VM user is named `sandbox` on both backends, with uid 1000 / gid 1000 and home at `/home/sandbox/`. The Lima `sandbox` account has passwordless sudo for operations the guest agent needs (network config, CA injection); the lite-image `sandbox` account has no sudo (the lite container is `--read-only` with `--cap-drop ALL`, so the operations sudo would gate are not reachable to begin with).
- **Minimal cloud image.** Ubuntu 24.04 server cloud image (Lima) or minimal Ubuntu 24.04 userland (lite) — no desktop, no dev tools beyond what provisioning adds.
- **Path validation.** The guest agent only accepts file operations in allow-listed directories. Both backends use `/home/sandbox/` as the guest user home:

  | Directory | Purpose |
  |---|---|
  | `/home/sandbox/` | Guest user home |
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

Use clone mode (`--repo`) plus `sandbox cp` or git remote transport when isolation matters more than convenience. See [workspaces concepts](/sandboxd/concepts/workspaces/) for the trade-off and [workspaces guide](/sandboxd/guides/workspaces/) for the commands.

#### Per-session `securityModel`

The `--workspace` flag's trailing token selects the 9p `securityModel`:

```text
shared:<host>[:<guest>][:<security-model>]
```

`sandboxd` exposes two of the four 9p models. The rest are deliberately omitted:

| Model | Exposed? | When to pick it |
|---|---|---|
| `mapped-xattr` | Yes (default) | Most cases. File ownership and modes are stored in extended attributes on the host; sandbox-side files do not actually carry the operator's uid. Safer because a guest that escapes 9p still does not own host-visible artefacts. |
| `none` | Yes (opt in) | Real-symlink interop both directions. A build step inside the guest that creates a symlink lands on the host as an actual symlink, not as a 9p-encoded placeholder. The cost is that file ownership reflects the guest's view, which is less restrictive than `mapped-xattr`. |
| `passthrough` | No | Would require `sandboxd` to run as root so guest uids could be applied directly to host inodes. Incompatible with the rootless-Docker, `cap_net_admin`-only privilege envelope this guide documents. |
| `mapped-file` | No | Functionally equivalent to `mapped-xattr` for the cases that matter, with the additional cost of a metadata-persistence file inside the host workspace. Operators rarely want a hidden sidecar file appearing in the directory they share. |

The default is `mapped-xattr`. Override to `none` only when symlink semantics matter — for example, a `make install` step inside the guest that lays down symlinks expected to round-trip back to the operator's host filesystem.

Set the model at create time via the third colon-segment of the flag value (see [workspaces guide](/sandboxd/guides/workspaces/#pick-a-security-model)). The choice is persisted on the session record and cannot be changed after create; `sandbox rm` plus a fresh `create` is the only way to revisit it.

### `local:` snapshot workspace

`--workspace local:<path>` seeds the guest with a one-shot `rsync` snapshot of a host directory. Unlike `shared:`, no 9p device is attached and no host directory is bound into the VM:

- No 9p filesystem surface added to QEMU — one device-emulation category fewer than `shared:`.
- No live host writes are visible to the guest after create. The guest sees the tree as it was at create time.
- No live guest writes are visible to the host. Guest-side modifications stay inside the session.
- Trade-off is staleness: the operator decides when (and whether) to push or pull updates across the boundary via the dedicated `sandbox workspace push` / `pull` commands.

Reach for `local:` when you want to seed a session from a host directory without giving up the isolation properties of clone mode. See [workspaces concepts](/sandboxd/concepts/workspaces/) for the broader comparison and [workspaces guide](/sandboxd/guides/workspaces/#snapshot-a-host-directory-local-mode) for the commands.

### SLIRP management network

The VM has two NICs. `eth1` is a TAP device on the per-session Docker bridge — the data plane that routes through the gateway. `eth0` is a **SLIRP** interface used only for Lima's SSH management channel. This section explains what SLIRP is and why it's the trade-off it is.

**What SLIRP is.** SLIRP is a user-mode networking stack bundled with QEMU. Rather than bridging the guest NIC to a real host interface (which requires a TAP device and elevated privileges), SLIRP implements a small TCP/IP stack inside the QEMU process itself: it terminates the guest's packets, translates them into ordinary socket calls on the host, and proxies the responses back. The guest sees a functioning network; the host sees QEMU making normal outbound connections. SLIRP also forwards selected host ports into the guest, which is how Lima obtains its SSH channel without any privileged networking setup.

**Why Lima uses it.** No TAP device, no bridge configuration, no root — it works out of the box on any developer machine. That is a real portability win for a per-session VM.

**What it costs.** SLIRP runs in-process with QEMU, so any bug in its packet-handling code executes in the same address space as the hypervisor. That widens the QEMU attack surface compared to a plain TAP bridge, where the kernel does the forwarding. SLIRP is also slower than a TAP bridge and emulates some protocols (ICMP, raw sockets) only partially.

**How the sandbox contains that.** SLIRP is confined to `eth0` and carries only Lima's SSH traffic — all outbound application traffic goes over `eth1` to the gateway. The guest adds a default route over `eth1` with a lower metric than SLIRP's, so internet-bound traffic prefers the gateway path; SSH and Lima management still ride SLIRP. The policy layer (DNS filtering, nftables, Envoy, mitmproxy) only applies to traffic that reaches the gateway — that is by construction true for the data plane, since SLIRP has no route to anything a user workload would use.

Removing SLIRP would require replacing Lima's SSH provisioning; it is not currently configurable.

## Related reading

- [Networking](/sandboxd/concepts/networking/) — how the network-isolation layer actually works.
- [Policy model](/sandboxd/concepts/policy-model/) — the contract that defines what traffic is allowed.
- [Workspaces concepts](/sandboxd/concepts/workspaces/) — the isolation cost of each provisioning mode.
- [Troubleshooting](/sandboxd/guides/troubleshooting/) — when a hardened session misbehaves.
