---
title: External SSH tools (VS Code Remote-SSH, JetBrains Gateway, ad-hoc ssh/scp/rsync)
description: How VS Code Remote-SSH, JetBrains Gateway, and ad-hoc ssh/scp/rsync clients use sandboxd's managed SSH config block to connect to a session through the daemon — no extra setup beyond what the `sandbox` CLI already does on first use.
---

Every sandbox session is reachable from any tool that reads OpenSSH
client config — VS Code Remote-SSH, JetBrains Gateway, `ssh`, `scp`,
`rsync`, your shell's tab completion against `~/.ssh/config`. This is
not a separate integration: it is a side effect of the [`~/.ssh/sandbox/`
managed area](/sandboxd/concepts/ssh-access/) that the `sandbox` CLI
maintains for its own commands.

This guide walks through hooking VS Code and JetBrains Gateway at the
generated `Host sandbox-<id>` alias, plus the ad-hoc `ssh`/`scp`/`rsync`
flow. For the layout of the managed area itself, see the [SSH access
concept page](/sandboxd/concepts/ssh-access/).

## Prerequisites

- A running sandbox session. Either backend works (Lima VM or
  container/lite); the SSH transport is daemon-mediated and uniform
  across them.
- A first-time SSH-shaped CLI command run for that session so the
  managed config has been written. Any of the following triggers the
  write:

    ```bash
    sandbox ssh <id>           # interactive shell — exits immediately on ^D
    sandbox ssh <id> -- uname  # one-shot command
    sandbox ls                 # reconcile pass also creates entries
    ```

    After this, `~/.ssh/sandbox/sandbox-<id>` exists and your
    `~/.ssh/config` contains the managed `Include` block (see [SSH
    access — Managed Include block](/sandboxd/concepts/ssh-access/#the-managed-include-block-in-sshconfig)).

That's it — no SSH agent, no port forward, no copy-paste of keys.
Every SSH client that reads `~/.ssh/config` will now resolve `Host
sandbox-<id>` to the daemon-mediated tunnel.

## VS Code Remote-SSH

1. Install the [Remote - SSH](https://marketplace.visualstudio.com/items?itemName=ms-vscode-remote.remote-ssh)
   extension if you have not already.
2. Open the command palette (`Ctrl+Shift+P` / `Cmd+Shift+P`) and run
   **Remote-SSH: Connect to Host…**.
3. The host picker reads `~/.ssh/config` and lists every `Host`
   alias, including the `sandbox-<id>` entries the CLI wrote. Pick
   the one for your session.
4. VS Code opens a new window connected to the session. The first
   connection installs the VS Code server inside the session's home
   directory — `/home/sandbox/.vscode-server/` on container sessions,
   `/home/agent/.vscode-server/` on Lima (both backends run as the
   `sandbox` user; Lima's home is pinned at `/home/agent/` for
   historical workspace-path compatibility). Subsequent reconnects
   reuse the existing server install.
5. **Open Folder** points at the workspace: `/home/sandbox/workspace`
   on container sessions, `/home/agent/workspace` on Lima.

VS Code's SSH multiplexing pairs with the `ControlMaster auto` /
`ControlPath ~/.ssh/sandbox/sockets/%C` / `ControlPersist 60`
directives in the generated config, so opening additional terminals,
running tasks, and re-opening the same window all share the existing
tunnel. A daemon restart drops the tunnel; VS Code surfaces this as a
disconnected indicator and will reconnect on the next interaction,
paying the WebSocket handshake cost once.

## JetBrains Gateway

1. Open **JetBrains Gateway** and pick **SSH** as the connection type.
2. In the connection dialog, the "Host" picker resolves
   `~/.ssh/config` aliases — type `sandbox-` and the per-session
   entries autocomplete. Pick the one for your session; the rest of
   the fields (port, user, identity file) are read from the
   generated config block and do not need to be filled in manually.
3. Continue to **Check Connection and Continue**. Gateway opens an
   SSH session, probes the OS, and offers to download a JetBrains IDE
   backend (IntelliJ, PyCharm, GoLand, etc.) into the session.
4. Pick a project path inside the session
   (`/home/sandbox/workspace/<repo>` for container, `/home/agent/workspace/<repo>`
   for Lima) and continue. Gateway pulls the IDE backend into the
   session's home, then launches the thin client on your host.

Like VS Code, Gateway leans on SSH multiplexing for its many small
connections (status probes, file watches, indexing reads). The
`ControlPersist 60` window means short reconnects are cheap; sessions
idle beyond a minute pay one handshake on next use.

## Ad-hoc `ssh`, `scp`, `rsync`

The managed `Host sandbox-<id>` alias is available to any tool that
calls into OpenSSH. The shapes the `sandbox` CLI internally uses —
which are exactly what an ad-hoc operator would type — are:

```bash
ssh sandbox-<id>                                   # interactive shell
ssh sandbox-<id> -- uname -a                       # one-shot command
scp ./localfile sandbox-<id>:/home/sandbox/        # upload (container)
scp sandbox-<id>:/home/sandbox/result ./           # download (container)
rsync -av --delete ./src/ sandbox-<id>:/home/sandbox/workspace/src/
```

A common-case difference between backends is the in-session home
directory: `/home/sandbox/` on container sessions, `/home/agent/` on
Lima. Both backends run the in-VM workload as the `sandbox` user
(uid 1000) — the daemon-generated config sets `User sandbox`
uniformly — but Lima's home is pinned at `/home/agent/` for
historical workspace-path compatibility, while the lite container
uses the conventional `/home/sandbox/`.

You do not need to remember the session id by heart; `sandbox ls`
lists every entry the CLI is managing. The 12-character hex id in the
`ID` column is the `<id>` you append to `sandbox-`.

## What works without the CLI being in the data path

The CLI is only in the data path for the `ProxyCommand` shim
(`sandbox proxy <id>` — see the [hidden subcommand
reference](/sandboxd/reference/cli/#sandbox-proxy-hidden)), which is
itself a thin byte mover between OpenSSH's stdio and the daemon's
WebSocket proxy. Everything else — TTY allocation, terminal resize,
signal forwarding, agent forwarding, multiplexing, all of OpenSSH's
client-side feature set — runs through the standard `ssh` client.

This means an IDE or ad-hoc tool that needs an OpenSSH-shaped surface
(scp protocol, sftp subsystem, agent forwarding) gets it for free as
long as the bundled sshd inside the session supports it. The
sandboxd-provisioned container and Lima images both ship a standard
OpenSSH sshd, so these features work out of the box.

## What does not work

- **A second host directly inside the session.** OpenSSH's `Match
  exec` / nested `Host` blocks resolve against `~/.ssh/config` from
  the *client* side; chaining `sandbox-<id>` as a `ProxyJump` for
  another `Host` works, but using the session itself as a jump host
  for arbitrary destinations does not because the in-session sshd is
  bound to loopback and has no route out beyond the gateway's
  network-policy pipeline.
- **Host-key pinning.** The managed config sets `StrictHostKeyChecking
  no` and `UserKnownHostsFile=/dev/null` (see [SSH access — Trust
  model](/sandboxd/concepts/ssh-access/#trust-model)). The sshd is
  reachable only via the daemon-mediated tunnel; there is no MITM
  surface to pin a host key against. Removing those directives in a
  hand-edit will not fail loud — the connection will just complain
  about an unknown host on every reconnect.
- **SSH access from a different host.** The managed config and
  daemon socket are both local to the operator's machine. To reach a
  session from a different host, either run the `sandbox` CLI there
  (it'll establish its own managed area against a remote daemon's
  socket, which is not a supported topology in v1) or tunnel the
  daemon socket through some other mechanism.

## Troubleshooting

- **The `sandbox-<id>` alias doesn't appear in my SSH client's host
  picker.** The CLI has not written the managed entry yet. Run
  `sandbox ls` (which runs an opportunistic reconcile pass and
  creates missing entries for active sessions) or `sandbox ssh <id>`
  once.
- **`Permission denied (publickey)` on first connect.** Usually means
  the per-session key is stale because the daemon has rotated it. The
  `sandbox` CLI's outermost dispatch retries once on this failure
  after re-fetching the config; an external client doesn't. Run
  `sandbox ssh <id>` once to refresh the local entry, then retry the
  external tool.
- **The connection drops after a daemon restart.** Expected. The
  next reconnect pays one WebSocket handshake. Long-lived IDE
  sessions (VS Code, JetBrains) handle this automatically; ad-hoc
  shells need to be re-invoked.

## Next steps

- [SSH access — the `~/.ssh/sandbox/` managed area](/sandboxd/concepts/ssh-access/)
  — file layout, lifecycle, trust model.
- [`sandbox proxy` hidden subcommand](/sandboxd/reference/cli/#sandbox-proxy-hidden)
  — the ProxyCommand shim's exit-code contract.
- [HTTP API reference](/sandboxd/reference/http-api/) — daemon-side
  endpoints behind the transport.
