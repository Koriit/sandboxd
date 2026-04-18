---
title: Use workspaces
description: Provision source code into a session using clone, shared mount, sandbox cp, or git remote transport.
---

This guide shows you how to use each workspace mode with copy-pasteable commands. For background on the four modes and their trade-offs, see [workspaces concepts](/concepts/workspaces/).

## Before you start

You need:

- A running `sandboxd` daemon — see [Quickstart](/start/quickstart/) if you have not set one up.
- The `sandbox` CLI on your `PATH`.
- For git remote transport, the `git-remote-sandbox` symlink on your `PATH` alongside `sandbox`.

All commands below assume these are in place.

## Clone a repository at session creation

Clone is the default way to bring a remote repository into a new session. The clone runs inside the VM during provisioning.

```bash
sandbox create --name dev \
    --repo https://github.com/octocat/Hello-World.git
```

For a private or gated repository, pair `--repo` with a policy that allows the git host:

```bash
sandbox create --name dev \
    --policy ./policy.json \
    --repo https://github.com/myorg/private-repo.git
```

The repository lands in `/home/agent/workspace/` inside the VM. Verify it cloned:

```bash
sandbox exec dev -- ls /home/agent/workspace
```

### Troubleshooting clone

- **Clone fails, session still comes up.** Clone failure is non-fatal. The session reaches `Running` with an empty workspace. Check the daemon logs for the `git clone` error, then fix the policy or URL and redo.
- **`NXDOMAIN` on the git host.** The domain is not in the policy. See [network policies](/guides/network-policies/).
- **`Connection refused`.** DNS resolved but the IP is not allowed. Check the policy's assurance level and CIDR coverage.

## Mount a host directory (shared mode)

Shared mode exposes a host directory live inside the VM via 9p. Use it for interactive development when you want the host IDE and the in-VM toolchain to share the same files.

Mount the current directory:

```bash
sandbox create --name dev \
    --workspace "shared:$(pwd)"
```

Combine with a boot command to install dependencies after the mount:

```bash
sandbox create --name dev \
    --workspace "shared:$(pwd)" \
    --boot-cmd "cd /home/agent/workspace && npm install"
```

Constraints:

- The host path must be absolute and must already exist.
- `--workspace` and `--repo` are mutually exclusive.

Verify the mount:

```bash
sandbox exec dev -- ls /home/agent/workspace
```

Changes on either side appear immediately on the other — no sync step needed.

Shared mount reduces VM isolation. If your workload does not need live bidirectional visibility, prefer clone plus `sandbox cp` or git remote transport. See [hardening](/guides/hardening/#9p-shared-mounts) for the full trade-off.

## Copy individual files with `sandbox cp`

`sandbox cp` moves single files or directories between the host and a running session. The syntax mirrors `scp`: `session:path` for VM-side paths, plain paths for host-side.

Upload to the VM:

```bash
sandbox cp ./config.toml dev:/home/agent/workspace/config.toml
```

Download from the VM:

```bash
sandbox cp dev:/home/agent/workspace/output.log ./output.log
```

Copy a directory (transferred as chunked base64 through the daemon):

```bash
sandbox cp ./dist dev:/home/agent/workspace/dist
```

`sandbox cp` works regardless of which workspace mode you chose at creation time.

## Sync via `git push` and `git pull`

Git remote transport lets you use standard git commands against a repository inside a session, without any network policy.

Add the session as a git remote:

```bash
git remote add sandbox sandbox::dev/home/agent/workspace
```

The URL format is `sandbox::<session>/<repo-path>`. If you omit the path, it defaults to `/home/agent/workspace`:

```bash
git remote add sandbox sandbox::dev
```

Push local commits into the VM:

```bash
git push sandbox main
```

Pull VM-side commits back to the host:

```bash
git pull sandbox main
```

Both `git-upload-pack` (fetch/pull) and `git-receive-pack` (push) are supported. The path is entirely host-local — no policy rules are needed.

### Troubleshooting git remote transport

- **`git-remote-sandbox: command not found`.** The symlink is missing from `PATH`. Install it next to the `sandbox` binary and re-check `which git-remote-sandbox`.
- **`Permission denied` opening the daemon socket.** Set `SANDBOX_SOCKET` to the socket path you are using, or start the daemon first.
- **Target path is not a git repository.** Initialise it inside the VM first: `sandbox exec dev -- git -C /home/agent/workspace init`.

## Run a command after provisioning

`--boot-cmd` runs an arbitrary shell command after the workspace is in place. It runs as the `agent` user; use `sudo` for root operations.

```bash
sandbox create --name dev \
    --repo https://github.com/example/app.git \
    --boot-cmd "cd /home/agent/workspace && npm install"
```

Boot command failure does not block the session from reaching `Running`. Re-run failed steps with `sandbox exec`.

## Common flows

### Interactive development

Share the current directory, install dependencies on boot, run tests via `exec`.

```bash
sandbox create --name dev \
    --workspace "shared:$(pwd)" \
    --boot-cmd "cd /home/agent/workspace && npm install"
sandbox exec dev -- bash -c "cd /home/agent/workspace && npm test"
sandbox rm dev
```

### CI-style run

Clone, build, test, pull artifacts back.

```bash
sandbox create --name ci-run \
    --policy ./ci-policy.json \
    --repo https://github.com/myorg/app.git \
    --boot-cmd "cd /home/agent/workspace && make build && make test"
sandbox cp ci-run:/home/agent/workspace/dist/app.tar.gz ./app.tar.gz
sandbox rm ci-run
```

### Push-test-pull loop

Create a blank session, push the local tree, run tests, pull results back.

```bash
sandbox create --name review
git remote add review sandbox::review/home/agent/workspace
git push review main
sandbox exec review -- bash -c "cd /home/agent/workspace && make test"
git pull review main
sandbox rm review
```

## Where to go next

- [Network policies](/guides/network-policies/) — open specific destinations so clone and other network operations can reach them.
- [First real session](/guides/first-real-session/) — put workspaces, policy, and the agent together in one flow.
- [Troubleshooting](/guides/troubleshooting/) — when something does not work.
