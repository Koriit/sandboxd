---
title: Lite mode
description: Container-backed sessions for fast, ephemeral agent runs — what they trade against Lima VM isolation, what works, what does not, and when to choose lite over the default Lima backend.
---

Lite mode runs each session inside a Docker container instead of a Lima/QEMU virtual machine. The trade is simple: you get session-creation in the low-second range and a much smaller resource footprint, but you give up VM-grade isolation. This guide explains the trade in detail, lists the workloads that lite cannot host, and gives you a clear rule for when to pick lite versus Lima.

For the broader security model that lite mode plugs into, see [Hardening](/sandboxd/guides/hardening/) and [Networking](/sandboxd/concepts/networking/). For the operational lifecycle that lite shares with Lima, see [Sessions](/sandboxd/concepts/sessions/).

## What lite mode is

A lite session is a container-backed session: instead of a Lima/QEMU VM, the session lives inside a Docker container running an Ubuntu-based image with the same `sandbox-guest` agent the Lima backend uses. The lite image ships with a small bundled `sshd` listening on `127.0.0.1:22` inside the container's network namespace (not exposed to the host) so the daemon-mediated SSH and SSH-shaped operations (`sandbox ssh`, `sandbox cp`, `sandbox sync`, `git-remote-sandbox`, external SSH tooling) reach a session through the same mechanism on both backends. The in-container guest user is named `sandbox` (uid 1000); the Lima backend continues to use `agent` (uid 1000) on its VM. Activate lite mode explicitly per session with either flag — the two are equivalent:

```bash
sandbox create --name fast --lite
sandbox create --name fast --backend container
```

Everything that wraps a session — gateway container, per-session bridge, TLS interception, applied policy, workspace bind mount, `sandbox cp`, `sandbox ssh`, `sandbox exec`, `git-remote-sandbox` — is identical across the two backends. The difference is only the runtime that hosts the guest.

## Isolation trade-off in plain language

Lima sessions run inside a QEMU virtual machine. The guest has its own kernel, its own address space, and its own device model; an exploit in the guest must defeat the hypervisor before it touches the host. That is what "VM-grade isolation" means in this codebase.

Lite sessions run inside a Docker container. The guest shares the host kernel through Linux namespaces, with seccomp and capability drops as the boundary. An exploit in the guest only needs to defeat the namespace + seccomp surface to reach the host kernel — a smaller and more familiar attack surface than a hypervisor escape.

The lite container ships with the hardening posture the daemon enforces: `--cap-drop ALL` (no Linux capabilities), `--security-opt no-new-privileges`, `--security-opt seccomp=default` (Docker's default seccomp profile), `--read-only` root with explicit tmpfs mounts for `/tmp`, `/var/tmp`, and `/run`, and `--pids-limit 512` as a fork-bomb ceiling. The host runs the container as a non-root user via `--user`; see [UID alignment](#uid-alignment) below. None of those knobs change the fundamental shared-kernel posture — they reduce blast radius, they do not introduce a separate kernel.

If the agent or the workload it runs needs VM-grade isolation as a security property, choose Lima. If the workload is something a developer would run on their laptop without thinking twice, lite is the cheaper substrate.

## What this breaks

Lite mode disables several capabilities the Lima backend supports, by design. If your workload needs any of these, choose Lima:

- **Docker-in-Docker.** No privileged mode, no `/var/run/docker.sock` mount.
- **FUSE.** Requires `CAP_SYS_ADMIN` or device nodes not exposed.
- **Kernel modules.** Not loadable in a userns-less default-seccomp container.
- **Raw network sockets.** `CAP_NET_RAW` dropped; `ping` and similar tools fail.
- **`/proc` writes.** Dropped; `sysctl -w` fails.

These are the capabilities the Lima backend has and the lite backend does not — they are the trade you accept when you opt in to lite mode.

`--no-cache` at session create time is also rejected on the container backend. The lite image is shared across concurrent lite sessions, so a per-session cache-bust would force every other lite session to rebuild. Operator-driven image rebuilds remain available via `sandbox rebuild-image`; see [Rebuilding the lite image](#rebuilding-the-lite-image) below.

## What is preserved across lite ↔ Lima

The session contract does not change with the backend. Across both lite and Lima you keep:

- **Workspace bind mount.** `--workspace shared:<path>` and `--workspace clone:<repo>` work the same way on both backends. On macOS, `shared:` has an access-identity difference you need to account for — see [Shared workspaces on macOS](#shared-workspaces-on-macos) below.
- **Per-session home volume.** `/home/sandbox` lives in a named Docker volume `sandbox-home-{session_id}` for lite sessions — it survives `sandbox stop` / `sandbox start` and is deleted with `sandbox rm`. The Lima backend offers the equivalent (`/home/sandbox` on its VM disk; the in-VM account is `sandbox` with the same home directory path on both backends). Either way you get state within a session, clean slate between sessions.
- **Gateway and policy parity.** Per-session gateway container, per-session bridge, per-session CA, TLS interception, applied policy, and DNS-driven egress filtering all run identically on both backends.
- **Same CLI surface.** `sandbox cp`, `sandbox ssh`, `sandbox exec`, `git-remote-sandbox`, `sandbox logs`, `sandbox policy update` — every command works against both backends without flags.

In other words: lite changes the substrate underneath the guest, not the contract you have with the daemon. Switching a script from Lima to lite typically only requires adding `--lite` to the `sandbox create` call.

## Egress on macOS lite: the bridge is not a way out

On macOS, a lite session's per-session Docker bridge is created **without** Docker's default masquerade. The practical consequences, in order of how likely you are to meet them:

- **There is exactly one route out of a lite session: the gateway container.** Traffic sent anywhere else — most obviously to the bridge's own `.1` address — goes nowhere, and the caller sees a timeout rather than a refusal. Nothing on that path can send back an error, so an 8-second hang with no response is what "there was no route" looks like from inside the session.
- **A session that has just started is already closed.** Between the container starting and the daemon installing its default route there is a brief window in which Docker's own route is still in place. With the NAT removed, that window carries no egress at all rather than unfiltered egress.
- **Nothing about applying policy changes.** Allowed traffic is addressed to the gateway container on the same bridge, which never consults the NAT, and the gateway reaches the internet over its own separate uplink.

This is a macOS-lite property. On Linux the same bridge keeps Docker's masquerade, because there the gateway container's only NIC is on that bridge and its own upstream traffic depends on it.

## Shared workspaces on macOS

On macOS, the lite and Lima backends expose `shared:` workspaces through different access paths, and that difference affects which directories you can use.

**Lima backend.** The VM mounts the host directory directly via a 9p stanza that Lima provisions on behalf of the operator. Access to the host filesystem runs as the operator's uid, so any path the operator can read works — including paths under the operator's home directory. macOS TCC (Transparency, Consent, and Control) is the only additional gate, and the grants the operator has given cover the mount.

**Lite backend.** Sandbox containers run inside a persistent gateway Lima VM (`sandboxd-gateway`) that the daemon owns. The host directory reaches the sandbox container via a double-hop: the host 9p-mounts the shared root into the gateway VM as the `_sandboxd` daemon user, and the gateway VM bind-mounts that path into the sandbox container. Because the host-side read runs as `_sandboxd` — not as the operator — ordinary Unix ownership decides what is reachable, and a home directory is not: `/Users/<you>` is owned by you with mode 0750, and `_sandboxd` is not in its group, so the daemon user cannot even traverse into it. A directory that your own processes read freely is simply unreadable over this path.

### What this means in practice

The load-bearing constraint is ownership, not privacy consent: **nothing under your home directory is reachable by `_sandboxd`**, whether or not it sits in a TCC-protected location. TCC (Desktop, Documents, Downloads, `~/Library`) is a second gate layered on top, and it only becomes relevant once the ownership gate is passed.

The default lite shared root is `/tmp/sandbox-shared`, which `_sandboxd` can traverse because `/tmp` is world-traversable. Per-session `shared:` paths must be under this root, and the daemon rejects any path *spelled* outside it at `sandbox create` time. That check is lexical — it compares components on the host and never touches the filesystem, because the workspace directory is allowed not to exist yet — so it constrains the spelling, not what the path resolves to once the gateway VM mounts it. `..` components are refused outright for exactly that reason. A symlink planted inside the workspace is a different matter: it is followed when the VM resolves the mount source, and the lexical check above cannot see one. Treat the shared root as the content you have chosen to expose, not as a boundary the sandbox cannot cross.

```bash
# Works — /tmp is world-traversable, so _sandboxd can read the shared root.
sandbox create --lite --name dev \
    --workspace "shared:/tmp/sandbox-shared/myproject"

# Rejected at create time on macOS lite — _sandboxd cannot traverse $HOME.
sandbox create --lite --name dev \
    --workspace "shared:$HOME/Projects/myproject"
```

If your workspace lives outside `/tmp/sandbox-shared`, you have these options:

1. **Stage the project under `/tmp/sandbox-shared`.** The simplest fix for a single project. A symlink is not enough — the shared root is 9p-mounted into the gateway VM, so the content itself must live under it.
2. **Set `SANDBOX_LITE_SHARED_ROOT` to a different root.** The daemon picks up this environment variable at startup and uses it as the 9p-mounted root instead of the default. It must be a directory `_sandboxd` can actually traverse — pointing it at a parent inside your home directory passes the daemon's path check but still fails at mount time.
3. **Use `clone:` or `--repo` instead of `shared:`.** The clone runs inside the guest and never touches the host filesystem, so no host-side access identity is involved at all. This is the cleanest fit for a git-backed project.
4. **Move files explicitly with `sandbox sync` or `sandbox cp`.** These run on the CLI side as your own uid, over the daemon-mediated SSH proxy, so they read paths `_sandboxd` cannot. The same applies to `sandbox workspace push` / `pull` on a `local:` workspace. You give up live bidirectional visibility, but for workloads where the agent reads the workspace once and you sync results back explicitly, this is a clean fit.

> **`local:` carries the same host-side constraint on macOS lite.** The create-time `local:` push is run by the daemon (there is no setuid pivot to the operator on macOS), so its host source must be readable by `_sandboxd` just like a `shared:` source. The operator-driven `sandbox workspace push` / `pull` and `sandbox sync` are the parts that run as your uid.

> On Lima sessions (full backend) there is no `_sandboxd` intermediary — the VM mounts the host directory on behalf of the operator, so `shared:` accepts any path you can read and this restriction does not apply.

## Resource defaults

The lite backend computes defaults once at daemon startup based on the host's reported memory and CPU count:

| Default | Value |
|---|---|
| `memory_mb` (unset) | `host_ram × 0.8`, rounded down to a whole MB |
| `cpus` (unset) | `host_cpus × 0.8`, rounded to 1 decimal place |

These are **ceilings** (OOM bound and CFS quota), not reservations. Multiple concurrent lite sessions share the same 80%-of-host envelope rather than each getting a private slice. This matches operator intuition: lite is for small, ephemeral runs, not for reserving 80% of the laptop per session.

Lima defaults (currently 4 GB / 2 CPUs) are unchanged — the percentage rule applies only to the lite backend.

Pass `--memory` (in MB) and `--cpus` explicitly to override the defaults, on either backend. Fractional values for `--cpus` (e.g. `1.5`) are accepted only on the container backend; the Lima backend rejects them at session-create time because `limactl` requires integer CPU counts.

### Resource defaults on macOS

The `host × 0.8` rule above describes the Linux container backend, where the container runs directly on the host. On macOS the lite container does **not** run on the host — it runs inside the persistent gateway Lima VM (`sandboxd-gateway`), which is fixed at 2 vCPU / 2 GiB. Docker inside that VM cannot allocate more cores or memory than the VM has, so the daemon clamps the resolved `(memory, cpus)` pair to the VM's capacity:

| Resource | macOS lite ceiling | macOS lite floor |
|---|---|---|
| `cpus` | 2 (the gateway VM's vCPU count) | 1.0 |
| `memory_mb` | ~1536 MiB (VM RAM minus ~512 MiB reserved for the VM kernel, the per-session gateway container, and the in-VM Docker daemon) | 512 MiB |

This clamp applies to **both** the `host × 0.8` defaults **and** any explicit `--memory` / `--cpus` you pass. On a 64 GB / 12-core Mac the `host × 0.8` default would resolve to ~51 GB / 9.6 CPU, but the macOS lite session is clamped to ~1.5 GiB / 2 vCPU regardless — and an explicit `--cpus 8` is likewise capped at 2. If you request a value above the ceiling the daemon silently clamps it rather than failing; without the clamp `docker create` inside the VM would reject the over-large request outright. For workloads that need more than ~1.5 GiB / 2 vCPU per session on macOS, use the Lima (full) backend, where the per-session VM is sized independently of the gateway VM.

## UID alignment

The lite container runs as the host operator's uid:gid. When the host uid is not 1000, the daemon passes `--user <host-uid>:<host-gid>` to `docker run` so files written inside the container — into the workspace bind mount or back out via `sandbox cp` — land owned by the operator on the host.

The daemon does **not** use Docker user-namespace remapping (`--userns=...`). Userns-remap would force a chown on host files at mount time, which is destructive and surprising. The straightforward `--user` flag aligns the in-container uid to the host uid for the same observable effect, with no host-side filesystem mutation.

## Bundled sshd

The lite image bundles a small OpenSSH server that the lite container starts as part of its init sequence. It binds to `127.0.0.1:22` **inside the container's network namespace** and is never published to a host port — so a host-side `ss -tlnp` will never show it, and another lite session on the same host cannot collide with it.

The daemon reaches this sshd through the same byte-mover endpoint operators talk to (`GET /sessions/<id>/proxy`, the WebSocket the `sandbox proxy` shim is wired into). The server-side ferry runs the equivalent of:

```bash
docker exec -i <container> socat - TCP:127.0.0.1:22
```

…and bidirectionally pipes the WebSocket frames against `socat`'s stdio. The session's sshd sees a normal TCP connection from inside its own loopback; the operator's `ssh sandbox-<id>` client sees a normal SSH connection through `ProxyCommand sandbox proxy <id>`. The Lima backend uses an analogous TCP-stream path against the VM's port-forwarded sshd; both backends converge on the same WebSocket so operator-side tooling (`sandbox ssh`, `sandbox cp`, `sandbox sync`, `git-remote-sandbox`, VS Code Remote-SSH, JetBrains Gateway) is backend-agnostic.

The design picks **daemon-mediated proxy over host-port forwarding** for three concrete reasons:

- **No host-port conflicts.** Multiple concurrent lite sessions on the same host would otherwise have to negotiate disjoint host ports (or accept that only one can bind `22`). With the in-container loopback the operator never thinks about port allocation; the session id is the only handle.
- **The daemon owns reachability.** Authorization to reach a session's sshd is gated by `GET /sessions/<id>/proxy` (which returns `404 Not Found` when the caller is not the session's owner per `owner_username`). A host-published port would push authorization to the operator's firewall, which is not a place sandboxd controls.
- **Same plumbing for both backends.** Lima sessions already use a WebSocket against an in-VM sshd; reusing the same shape for the lite backend means CLI tools, docs, and integration tests do not branch by backend.

The cost is one extra hop (WebSocket-to-socat) in the SSH datapath. That hop is in-process for the daemon and uses tokio's async pipes for the long-lived byte pump, so the throughput penalty is on the order of one extra mmap; in practice it is invisible against the SSH cipher's own throughput ceiling.

## Prerequisites

Lite mode requires Docker 24.0+ on the host. That is already a sandboxd prerequisite; see [Installation](/sandboxd/start/installation/) for the install steps. If you only intend to use lite mode and never spin up a Lima VM, the Lima/QEMU/KVM stack is not needed at runtime — but you still build the workspace via `make build`, which compiles every crate.

One exception, despite its name: on Linux the `sandbox-lima-helper` setcap binary **is** required for lite-only installs. The daemon resolves it during startup regardless of which backend your sessions will use, and aborts if it is missing or un-cap'd. `install.sh` installs it for you; if you are installing by hand, see [`sandbox-lima-helper`](/sandboxd/start/installation/#sandbox-lima-helper).

The first lite session on a fresh daemon-version triggers a Docker build of the lite image (a few minutes, one time). Subsequent lite sessions reuse the cached image and start in seconds.

## Rebuilding the lite image

`sandbox rebuild-image` accepts a `--backend` flag and rebuilds either backend's image, or both. Default is `all`:

```bash
# Rebuild both Lima's golden image and the lite container image.
sandbox rebuild-image

# Rebuild only the lite image.
sandbox rebuild-image --backend container

# Force a full cache-bust (Docker --no-cache).
sandbox rebuild-image --backend container --no-cache
```

Rebuilds for the two backends are independent — concurrent `--backend lima` and `--backend container` calls do not block each other. Per-backend failures are printed with a `rebuild-image[<backend>]:` prefix; the command exits non-zero if any selected backend fails.

## When to choose lite vs. Lima

A short rule of thumb:

| Pick lite when... | Pick Lima when... |
|---|---|
| You want session creation in seconds, not minutes. | You need VM-grade isolation as a security property. |
| The workload is ordinary developer tooling — git, language toolchains, builds, tests. | The workload needs Docker-in-Docker, FUSE, kernel modules, or raw network sockets. |
| You expect to spin up and tear down many ephemeral sessions per day. | The workload writes to `/proc` (`sysctl -w`) or otherwise depends on per-session kernel state. |
| You want the smallest possible per-session resource footprint. | You want the per-session `--no-cache` create-path that Lima offers. |

When in doubt, start with Lima — it is the default for a reason. Switch a session to `--lite` once you have confirmed the workload only needs the capabilities the lite container provides.

## Related reading

- [Hardening](/sandboxd/guides/hardening/) — the layered defence model lite plugs into.
- [Sessions](/sandboxd/concepts/sessions/) — the lifecycle and persistence semantics that apply to both backends.
- [Networking](/sandboxd/concepts/networking/) — the gateway-mediated egress that wraps both backends identically.
- [Installation](/sandboxd/start/installation/) — Docker prerequisites and host setup.
