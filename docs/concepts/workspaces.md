---
title: Workspaces
description: How sandboxd delivers source code into a session — the five provisioning modes and their isolation trade-offs.
---

A workspace is whatever source code and project files a session can see. sandboxd offers five ways to get those files into — and out of — a VM, and the choice has real isolation consequences. This page explains the model. For hands-on commands, see the [workspaces guide](/guides/workspaces/).

## Why multiple modes

A coding agent needs a place to read source, write changes, and hand results back. Those three needs pull in different directions:

- **Isolation** wants the VM's filesystem to stay fully contained — no host path ever reachable from inside.
- **Latency** wants changes to appear immediately on both sides, without a copy step.
- **Bandwidth** wants to move only what changed, not a full re-sync each time.

No single mechanism wins on all three. sandboxd exposes five modes so you can pick the trade-off that fits the workload.

## The five modes

| Mode | Direction | Latency | Isolation |
|---|---|---|---|
| **Clone** | One-shot pull from a remote git host | Minutes (network-bound) | Full |
| **Shared mount** | Bidirectional, live | Instant | Reduced — host directory exposed |
| **`sandbox cp`** | Bidirectional, per-transfer | Per-transfer | Full |
| **`sandbox sync`** | Bidirectional, rsync-driven directory sync | Per-operation, delta-only | Full |
| **Git remote transport** | Bidirectional, via `git push`/`git pull` | Per-operation | Full |

### Clone mode

At session creation, sandboxd runs `git clone` inside the VM to pull a repository into `/home/agent/workspace/`. The clone is a one-shot provisioning step — no ongoing link to the remote exists afterwards. Subsequent updates require either network access (permitted by policy) or one of the other modes.

Clone is the simplest model for CI-style workloads: the session starts with a known tree, runs some work, and is thrown away.

### Shared mount

The host directory is mounted into the VM via QEMU's 9p filesystem. Reads and writes flow both ways in real time — the VM and the host see the same bytes with no sync step.

Shared mount trades isolation for developer ergonomics. The guest has read-write access to the chosen host directory, and 9p adds a filesystem-protocol surface reachable from inside the VM. See [hardening](/guides/hardening/) for the security-trade-offs section.

### `sandbox cp`

An explicit, scp-style copy between the host and a running session. The CLI dispatches to the backend's native copy tool — `limactl cp` for Lima sessions, `docker cp` for container sessions — so each invocation is a point-in-time transfer with no persistent mount and no network exposure. Good for moving config files, build artifacts, or logs across the boundary without giving up isolation. Notably, the daemon HTTP API is *not* in the path: the host running `sandbox cp` needs the same backend binary the daemon would use to manage the session.

### `sandbox sync`

A directory-level delta sync built on `rsync`, using the backend's session tool as the remote-shell transport (`rsync -e "limactl shell"` for Lima, `rsync -e "docker exec -i"` for container). Unlike `sandbox cp`, it transfers only what changed between the source and destination trees and supports recursive directory copy with attribute preservation, includes/excludes, and dry-run via the trailing `-- <rsync-args>` slot. Use it when iterating on a host-side tree that needs to land inside a running session repeatedly without the cost of a full re-copy. The session must be running on both ends — the rsync remote-shell needs a live process to hand off to.

### Git remote transport

A git remote helper (`git-remote-sandbox`) that lets `git push` and `git pull` operate directly against a repository inside a running session. Git's pack protocol rides over the existing host-to-guest channel; no network policy, no open port.

This mode is designed for the common coding-agent loop: commit locally, push into the sandbox, build and test inside, pull results back.

## Data flow at a glance

```mermaid
flowchart LR
    Host["Host"]
    HostFS[("Host<br/>filesystem")]
    Remote(["Remote<br/>git host"])
    VM["Session VM"]
    WS[("Workspace<br/>/home/agent/workspace")]

    Remote -- "clone<br/>(one-shot)" --> WS
    HostFS -- "9p mount<br/>(bidirectional, live)" --- WS
    Host -- "sandbox cp<br/>(snapshot)" --> WS
    WS -- "sandbox cp<br/>(snapshot)" --> Host
    Host -- "sandbox sync<br/>(rsync delta)" --- WS
    Host -- "git push/pull<br/>over sandbox::" --- WS
```

All five modes land data in the same place: `/home/agent/workspace/` inside the VM. What differs is the channel and whether updates continue to flow after session creation.

## Isolation trade-offs

Only shared mount reduces the VM's isolation from the host; the other four modes preserve full isolation.

- **Clone** pulls bytes through the gateway at creation time, then closes the loop. The only lasting exposure is whatever the policy allows for network.
- **`sandbox cp`** dispatches to `limactl cp` / `docker cp` — both operate over the backend's already-authenticated control channel; no extra network exposure is opened on the host or in the gateway path.
- **`sandbox sync`** runs `rsync` with the backend's session tool as the remote-shell, so the bytes ride that same control channel. No SSH/rsync daemon is exposed to the network.
- **Git remote transport** works the same way: the daemon already has a socket into the VM, so git's pack protocol rides it without opening anything new.
- **Shared mount** is different. QEMU's 9p filesystem exposes a directory live. The guest can write anything, at any time, to anything under that directory. A VM escape paired with 9p access expands the blast radius to those host files. See [hardening](/guides/hardening/#9p-shared-mounts) for the detailed security-model notes.

## Boot commands

Regardless of mode, you can run an arbitrary command inside the VM after provisioning finishes — `npm install`, `make setup`, whatever the project needs to become usable. Boot commands run as the `agent` user and run after the workspace is in place, so they can depend on the tree being present.

## Choosing a mode

- **Automating a job with a known start and end?** Clone — deterministic and throwaway.
- **Interactively editing on the host with an IDE, building in the VM?** Shared mount — live bidirectional visibility is worth the isolation cost while you iterate.
- **Need to shuttle a one-off file across?** `sandbox cp` — no setup, full isolation.
- **Repeatedly syncing a directory tree, want delta-only transfer?** `sandbox sync` — rsync over the backend's control channel.
- **Commit-push-test-pull loop?** Git remote transport — the coding-agent native flow.

You can combine modes: clone at creation, then use `sandbox cp` or `sandbox sync` for artifacts, or bootstrap with git remote transport and use `sandbox cp` for logs. The modes are not exclusive — only `--repo` and `--workspace shared:` are mutually exclusive at session-creation time, because they both want to own the initial state of `/home/agent/workspace/`.

## Next steps

- [Workspaces guide](/guides/workspaces/) — commands and concrete flows for each mode.
- [Sessions](/concepts/sessions/) — how a workspace fits into the broader session lifecycle.
- [Networking](/concepts/networking/) — what clone mode needs from your policy.
