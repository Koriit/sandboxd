---
title: SSH access — the `~/.ssh/sandbox/` managed area
description: How sandboxd projects every session as a `Host sandbox-<id>` SSH alias so the CLI, ad-hoc `ssh`/`scp`/`rsync`, and IDE remote-development tools all use the same daemon-mediated transport.
---

Every CLI command that needs a shell inside a session — `sandbox ssh`,
`sandbox cp`, `sandbox sync`, `sandbox workspace push`, `sandbox
workspace pull`, and (transitively) `git-remote-sandbox` — dispatches
through a daemon-mediated SSH transport rather than shelling out to
`limactl shell` or `docker exec` directly. The transport's
operator-visible surface is a per-session OpenSSH `Host sandbox-<id>`
alias managed under `~/.ssh/sandbox/`, included from the top of
`~/.ssh/config`. Anything that reads OpenSSH client config — VS Code
Remote-SSH, JetBrains Gateway, ad-hoc `ssh`/`scp`/`rsync` — sees the
same alias and uses it without the `sandbox` CLI being in the data
path beyond a thin `ProxyCommand` shim.

This page explains the layout, lifecycle, and trust model of the
managed SSH config area. For the IDE walkthrough, see the [external
SSH tools guide](/sandboxd/guides/external-ssh-tools/). For the
daemon-side endpoints that back it, see the [HTTP API
reference](/sandboxd/reference/http-api/).

## What the CLI writes under `~/.ssh/`

The first SSH-shaped CLI command per session (e.g. `sandbox ssh <id>`
or `sandbox cp file <id>:/path`) fetches the session's SSH config from
the daemon and stages two files under `~/.ssh/sandbox/`. The directory
is created on first use with mode `0700`.

| Path | Mode | Created by | Purpose |
|---|---|---|---|
| `~/.ssh/sandbox/` | `0700` | First SSH-shaped CLI command | Directory owned end-to-end by the CLI. |
| `~/.ssh/sandbox/sandbox-<id>` | `0600` | First SSH-shaped CLI command per session | Per-session OpenSSH config block. Contains the `Host sandbox-<id>` alias with `ProxyCommand`, `IdentityFile`, multiplexing directives, and host-key options. |
| `~/.ssh/sandbox/sandbox-<id>.key` | `0600` | Same | Per-session private key (PEM-encoded ed25519 for container sessions; copy of Lima's per-VM key for Lima sessions). |
| `~/.ssh/sandbox/sockets/` | `0700` | Same | ControlMaster socket directory. OpenSSH creates per-multiplex socket *files* under this path on demand but does not auto-create the parent — the CLI pre-creates it so the first `ssh sandbox-<id>` does not error out. |
| `~/.ssh/sandbox/.lock` | `0600` | Same | Lock target. Every mutation in this area (config write, key write, `Include` block insertion, session-entry removal, reconcile pass) is wrapped in an exclusive `flock` on this file so concurrent CLI invocations cannot race. |

`<id>` is the 12-character lowercase-hex session ID (the same id that
`sandbox ps`, `sandbox describe`, and every API endpoint use). The two
per-session files (`sandbox-<id>` and `sandbox-<id>.key`) sit
side-by-side rather than under a `keys/<id>/` subdirectory — this is
intentional so a POSIX glob on the config-file shape can pick up every
session entry without globbing the key files.

Every file write goes through a sibling tempfile + atomic `rename(2)`
so a SIGKILL between the write and the rename leaves the prior
contents intact, never a half-written file. The flock guarantees a
concurrent `sandbox ssh` and `sandbox ls` (which runs an opportunistic
reconcile pass against the daemon) cannot race against the same files.

### Per-session config contents

`~/.ssh/sandbox/sandbox-<id>` carries the daemon-emitted SSH config
block verbatim, with the `IdentityFile` placeholder rewritten by the
CLI to the on-disk key path:

```text
Host sandbox-<id>
  HostName 127.0.0.1
  Port 22
  User sandbox
  ProxyCommand sandbox proxy <id>
  IdentityFile ~/.ssh/sandbox/sandbox-<id>.key
  UserKnownHostsFile /dev/null
  StrictHostKeyChecking no
  ServerAliveInterval 30
  ControlMaster auto
  ControlPath ~/.ssh/sandbox/sockets/%C
  ControlPersist 60
```

`HostName`/`Port` are placeholders — the actual transport is opened by
`ProxyCommand`, so the values are never used to open a TCP socket, but
`ssh` requires them syntactically. `UserKnownHostsFile=/dev/null` +
`StrictHostKeyChecking no` are deliberate (see [Trust
model](#trust-model) below). `ControlMaster`/`ControlPath`/`ControlPersist`
enable connection multiplexing so a `git-remote-sandbox` push that
fires many small SSH operations only pays the WebSocket-handshake +
SSH-kex cost once.

## The managed `Include` block in `~/.ssh/config`

The CLI also inserts a marker-delimited block at the **very top** of
`~/.ssh/config` (creating the file with mode `0600` if absent):

```text
# >>> sandbox CLI managed >>>
Include ~/.ssh/sandbox/sandbox-*[!y]
# <<< sandbox CLI managed <<<
```

Three properties of this block matter to operators:

- **It is auto-managed.** The CLI scans for the exact marker lines
  (`# >>> sandbox CLI managed >>>` / `# <<< sandbox CLI managed <<<`)
  and treats everything between them as its own. Hand-edits inside the
  markers will be overwritten on the next mutation. Anything outside
  the markers — your existing `Host` blocks, comments, global config —
  is preserved across CLI invocations.
- **It sits at the very top.** OpenSSH applies `Host` matches in
  first-match-wins order; placing the `Include` at the top prevents
  an earlier user-authored `Host *` from shadowing the generated
  `sandbox-<id>` aliases.
- **The glob excludes key files.** `sandbox-*[!y]` matches every
  per-session config file (`sandbox-<id>`, where `<id>` ends in
  `[0-9a-f]`) but excludes the matching `sandbox-<id>.key` private
  keys (whose names all end in `y`). `[!...]` is POSIX character-class
  negation; OpenSSH's `Include` uses `glob(3)` so this is portable.

The block is idempotent: a re-run that finds it already in place is a
no-op. Removing it manually is supported — the next CLI invocation
will re-insert it.

## Lifecycle

The managed SSH config area is lifecycle-bound to the sessions it
describes. The CLI maintains the on-disk state through three
operations:

- **Write.** Triggered by the first SSH-shaped command per session
  (e.g. the first `sandbox ssh <id>` or `sandbox cp ... <id>:...`).
  The CLI fetches the per-session config + private key from the
  daemon's [`GET /sessions/{id}/ssh-config`](/sandboxd/reference/http-api/#get-sessionsidssh-config--per-session-ssh-config-block-and-private-key)
  endpoint, writes both files, and ensures the `Include` block.
- **Remove.** `sandbox rm <id>` deletes the per-session config + key
  files. A 404 from the proxy endpoint also triggers lazy removal —
  if the daemon does not know about the session anymore (because it
  was removed by another operator, or out-of-band, or the daemon
  state was reset), the CLI cleans up its local entry on the next
  `sandbox proxy` invocation against that id.
- **Reconcile.** `sandbox ps` / `sandbox ls` runs an opportunistic
  reconcile pass by default: it queries the daemon's session list,
  computes the diff against the on-disk entries, and removes orphans.
  This catches the case where a session was deleted while the CLI was
  not running (e.g. from a different shell, or by another operator
  before the lazy 404 path could trigger). Tools that need strict
  read-only semantics on the local SSH config area can pass
  [`--no-reconcile`](/sandboxd/reference/cli/#sandbox-ps).

## Trust model

`StrictHostKeyChecking no` + `UserKnownHostsFile=/dev/null` are
deliberately set in every per-session config block because the
session's sshd is reachable **only** through the daemon-mediated
tunnel:

- For container sessions, the sshd is bound to loopback inside the
  container's network namespace and never exposed to the host. The
  only way to reach it from outside the namespace is `docker exec`,
  which is gated by the daemon's group permission on the docker
  socket. See the [lite mode guide](/sandboxd/guides/lite-mode/) for
  details.
- For Lima sessions, the daemon discovers the per-VM TCP port that
  Lima forwards to the in-VM sshd's port 22 (`sshLocalPort`) and
  opens an in-process `127.0.0.1` connection to it. The CLI never
  talks to that port directly.

In both cases the daemon's `GET /sessions/{id}/proxy` WebSocket
endpoint owns the data path; an attacker would have to bypass the
daemon's peercred check (which authenticates the calling operator's
uid) to inject bytes. Host-key verification adds no defense in this
model — there is no MITM surface to verify against — and would only
generate spurious `~/.ssh/known_hosts` churn as ephemeral container
host keys regenerate on every session start. This matches Lima's
stance for its own VMs.

The per-session SSH private key lives at
`~/.ssh/sandbox/sandbox-<id>.key` with mode `0600`, same as any other
key under `~/.ssh/`. Persistence is the explicit trade-off for IDE
compatibility — IDEs cannot use a per-call tempfile they cannot read.
A stale key on disk after a session has been deleted gives the holder
no useful access because the corresponding session no longer exists
and the proxy endpoint will return 404 (which itself triggers the
lazy cleanup described in [Lifecycle](#lifecycle)).

## Trust-group membership

Every member of the `sandbox` OS group is trusted with every
session's private key — the daemon's peercred check authenticates the
calling operator's uid, but does not distinguish *which* operator
owns a given session beyond enforcing the per-session 404-on-foreign
isolation contract. In practice this means: add only operators you
already trust with shell-level access to other operators' sessions to
the `sandbox` group. The [installation
guide](/sandboxd/start/installation/) covers group setup; the
[architecture page](/sandboxd/concepts/architecture/) covers the
broader isolation model.

## Why home directories differ between Lima and lite

Both backends run their in-VM workload as a `sandbox` user (uid 1000)
so the daemon-emitted SSH config block's `User sandbox` line resolves
on either side without per-backend branching. Both backends use
`/home/sandbox/` as the in-VM home directory — the `~` substitution
in `sandbox cp`/`sync` arguments resolves to `/home/sandbox` on both
backends.

## Next steps

- [External SSH tools](/sandboxd/guides/external-ssh-tools/) — VS
  Code Remote-SSH and JetBrains Gateway walkthrough.
- [HTTP API reference](/sandboxd/reference/http-api/) — daemon-side
  endpoints (`GET /sessions/{id}/ssh-config`, `GET /sessions/{id}/proxy`).
- [`sandbox proxy` hidden subcommand](/sandboxd/reference/cli/#sandbox-proxy-hidden)
  — the `ProxyCommand` shim's exit-code contract.
- [Sessions](/sandboxd/concepts/sessions/) — the broader session
  lifecycle this SSH config area is bound to.
