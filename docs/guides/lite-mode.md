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

- **Workspace bind mount.** `--workspace shared:<path>` and `--workspace clone:<repo>` work the same way on both backends.
- **Per-session home volume.** `/home/sandbox` lives in a named Docker volume `sandbox-home-{session_id}` for lite sessions — it survives `sandbox stop` / `sandbox start` and is deleted with `sandbox rm`. The Lima backend offers the equivalent (`/home/agent` on its VM disk; the in-VM account is also `sandbox`, but the home directory path retains its historical name). Either way you get state within a session, clean slate between sessions.
- **Gateway and policy parity.** Per-session gateway container, per-session bridge, per-session CA, TLS interception, applied policy, and DNS-driven egress filtering all run identically on both backends.
- **Same CLI surface.** `sandbox cp`, `sandbox ssh`, `sandbox exec`, `git-remote-sandbox`, `sandbox logs`, `sandbox policy update` — every command works against both backends without flags.

In other words: lite changes the substrate underneath the guest, not the contract you have with the daemon. Switching a script from Lima to lite typically only requires adding `--lite` to the `sandbox create` call.

## Resource defaults

The lite backend computes defaults once at daemon startup based on the host's reported memory and CPU count:

| Default | Value |
|---|---|
| `memory_mb` (unset) | `host_ram × 0.8`, rounded down to a whole MB |
| `cpus` (unset) | `host_cpus × 0.8`, rounded to 1 decimal place |

These are **ceilings** (OOM bound and CFS quota), not reservations. Multiple concurrent lite sessions share the same 80%-of-host envelope rather than each getting a private slice. This matches operator intuition: lite is for small, ephemeral runs, not for reserving 80% of the laptop per session.

Lima defaults (currently 4 GB / 2 CPUs) are unchanged — the percentage rule applies only to the lite backend.

Pass `--memory` (in MB) and `--cpus` explicitly to override the defaults, on either backend. Fractional values for `--cpus` (e.g. `1.5`) are accepted only on the container backend; the Lima backend rejects them at session-create time because `limactl` requires integer CPU counts.

## UID alignment

The lite container runs as the host operator's uid:gid. When the host uid is not 1000, the daemon passes `--user <host-uid>:<host-gid>` to `docker run` so files written inside the container — into the workspace bind mount or back out via `sandbox cp` — land owned by the operator on the host.

The daemon does **not** use Docker user-namespace remapping (`--userns=...`). Userns-remap would force a chown on host files at mount time, which is destructive and surprising. The straightforward `--user` flag aligns the in-container uid to the host uid for the same observable effect, with no host-side filesystem mutation.

## Prerequisites

Lite mode requires Docker 24.0+ on the host. That is already a sandboxd prerequisite; see [Installation](/sandboxd/start/installation/) for the install steps. If you only intend to use lite mode and never spin up a Lima VM, the Lima/QEMU/KVM stack is not needed at runtime — but you still build the workspace via `make build`, which compiles every crate.

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
