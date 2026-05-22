---
title: Integrate with a coding agent
description: Drive sandboxd from Claude Code, another coding agent, or a CI runner — create sessions from scripts, run non-interactive commands, and move files.
---

sandboxd is designed to be driven non-interactively. This guide shows you how to plug it into a coding agent or a CI runner: create a session from a script, run commands in it, copy artifacts in and out, and tear it down cleanly.

You need sandboxd installed and the daemon running. See [Installation](/sandboxd/start/installation/) and the [Quickstart](/sandboxd/start/quickstart/) if you are starting from zero.

## The non-interactive surface

Everything you need from a script is three commands:

| Command | Purpose |
|---|---|
| `sandbox create` | Provision a new session. Exit code 0 means the session is `running` and the guest agent has pinged back. |
| `sandbox exec <session> -- <cmd>` | Run one command inside the session. Exit code and stdout/stderr are forwarded. |
| `sandbox cp <src> <dst>` | Move files in or out. `session:path` on whichever side is remote. |

Plus the teardown pair:

| Command | Purpose |
|---|---|
| `sandbox stop <session>` | Halt the VM, keep the config. Fast restart later. |
| `sandbox rm <session>` | Full teardown. Session ID is gone. |

Most of these are thin wrappers around the [HTTP API](/sandboxd/reference/http-api/) — `create`, `exec`, `stop`, and `rm` each map to a single endpoint. `sandbox cp` is the exception: it resolves the session via the API and then dispatches to the backend's native copy tool (`limactl cp` for Lima, `docker cp` for the container backend), so the data path never crosses the daemon. If you want to skip the CLI and speak HTTP over the Unix socket directly, the reference page documents every endpoint.

## Pattern 1: one-shot run from a shell script

The simplest integration: a script that creates a session, runs a build, copies the result out, and deletes the session.

```bash
#!/usr/bin/env bash
set -euo pipefail

SESSION_NAME="ci-$(date +%s)-$$"
WORK_REPO="https://github.com/example/app.git"
POLICY=/etc/sandbox/policies/ci.json
ARTIFACT=/home/agent/workspace/target/release/app

cleanup() { sandbox rm "$SESSION_NAME" >/dev/null 2>&1 || true; }
trap cleanup EXIT

# Create the session; exit code is non-zero if provisioning fails.
sandbox create \
    --name "$SESSION_NAME" \
    --cpus 4 --memory 8192 \
    --repo "$WORK_REPO" \
    --policy "$POLICY"

# Run the build; stdout/stderr stream back, exit code is forwarded.
sandbox exec "$SESSION_NAME" -- bash -lc \
    'cd /home/agent/workspace && cargo build --release'

# Copy the artifact out.
sandbox cp "$SESSION_NAME:$ARTIFACT" ./app

# Trap handles cleanup on both success and failure.
```

Two things to notice:

- The `trap cleanup EXIT` handler guarantees teardown even if the build fails. If you drop the trap, a failed build leaves the session around, which leaks VMs over time.
- `sandbox create` blocks until the session is `running` and the guest agent has responded to a ping. You do not need to sleep or poll afterwards.

## Pattern 2: long-lived session for an interactive agent

Coding agents like Claude Code typically want to keep a session alive across many tool calls, rather than spin one up per command. The flow is:

1. **At agent start**: `sandbox create --name claude-$SESSION --workspace shared:$PROJECT_DIR`.
2. **Per tool call**: `sandbox exec claude-$SESSION -- <cmd>` or `sandbox cp ...`.
3. **At agent exit**: `sandbox stop claude-$SESSION` (fast restart later) or `sandbox rm` (clean slate).

Using `--workspace shared:$PROJECT_DIR` mounts a host directory into the VM at `/home/agent/workspace` over 9p, so changes the agent makes inside the session are immediately visible on the host and vice versa. See [Workspaces](/sandboxd/guides/workspaces/) for details.

Example: a Python wrapper that an agent might use.

```python
import subprocess
from pathlib import Path

class Sandbox:
    def __init__(self, name: str, project_dir: Path, policy: Path | None = None):
        self.name = name
        args = [
            "sandbox", "create",
            "--name", name,
            "--workspace", f"shared:{project_dir}",
        ]
        if policy is not None:
            args += ["--policy", str(policy)]
        subprocess.run(args, check=True)

    def exec(self, *cmd: str) -> subprocess.CompletedProcess:
        return subprocess.run(
            ["sandbox", "exec", self.name, "--", *cmd],
            capture_output=True, text=True,
        )

    def close(self, remove: bool = False) -> None:
        cmd = "rm" if remove else "stop"
        subprocess.run(["sandbox", cmd, self.name], check=False)

# Usage from the agent's tool loop:
sb = Sandbox("claude-demo", Path.cwd(), policy=Path("policy.json"))
try:
    result = sb.exec("cargo", "test")
    print(result.stdout)
    print("exit:", result.returncode)
finally:
    sb.close(remove=False)  # stop, so next agent run restarts fast
```

Two things worth adding to this skeleton if you are wiring it into a real agent:

- **Timeout every `exec`**. A runaway build inside the session will block your agent. Wrap the `subprocess.run` call in `timeout=`.
- **Stream output** instead of capturing. For long commands, use `subprocess.Popen` with `stdout=subprocess.PIPE` and iterate; forward each line to the agent's tool-response channel so the agent sees progress.

## Pattern 3: CI runner

In a CI environment you rarely need a live daemon — you want one-shot isolation per job. Bake a sandboxd install into your runner image, start the daemon at job start, and run your job script as a non-root user.

GitHub Actions example (conceptual):

```yaml
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install sandboxd
        run: |
          curl -fsSL https://Koriit.github.io/sandboxd/install.sh | bash

      - name: Start daemon
        run: |
          sandboxd &
          # Wait for socket. Do NOT sleep-loop in production CI.
          for _ in $(seq 1 30); do
            [ -S "$XDG_RUNTIME_DIR/sandboxd/sandboxd.sock" ] && break
            sleep 1
          done

      - name: Run build in sandbox
        run: |
          sandbox create --name job --workspace shared:$PWD \
              --policy .github/sandbox-policy.json
          sandbox exec job -- make test
          sandbox rm job
```

Key considerations:

- The runner needs `/dev/kvm` and Docker. On GitHub-hosted runners this means `runs-on: ubuntu-latest` + a self-hosted KVM-capable runner, or a nested-virtualization-capable machine type.
- Check in a policy file at `.github/sandbox-policy.json` (or equivalent). Keep the allow-list narrow — the CI job should only reach what the build actually needs.
- If your build needs to pull from a private registry, add that registry to the policy with `level: tls` and set any required auth in the VM's env (via `--boot-cmd` or `sandbox exec`).

## Passing secrets into a session

`sandbox exec` inherits your shell — you pass env vars via the command itself:

```bash
sandbox exec my-session -- bash -c 'echo "$API_TOKEN" | curl -H @- https://api.example.com'
```

But note: the command line (including `"$API_TOKEN"`) is visible in `ps` on the host during the exec. For real secrets, prefer uploading them as files:

```bash
echo "$API_TOKEN" > /tmp/token
sandbox cp /tmp/token my-session:/home/agent/.token
rm /tmp/token
sandbox exec my-session -- bash -c 'cat /home/agent/.token | curl -H @- https://api.example.com'
```

File permissions inside the session follow the backend tool's behavior: `sandbox cp` dispatches to `limactl cp` (Lima) or `docker cp` (container), which preserve the source file's mode bits the same way `scp` and `docker cp` do natively. There is no in-band `--mode` knob — chmod the file on the host before copying, or run `sandbox exec <session> -- chmod 600 /home/agent/.token` afterwards.

## Observability

For every session you run, the gateway container writes a structured traffic log (Envoy access log, mitmproxy flow log, CoreDNS query log). Pull it per session with:

```bash
sandbox logs my-session --component mitmproxy --tail 200
sandbox logs my-session --component envoy --follow
```

When integrating into an agent, a good pattern is to tail the log in the background while the agent runs and include a summary in the tool response ("23 outbound requests, 2 blocked by policy, most-contacted host: github.com"). This gives the agent's user visibility into what the session actually did on the network.

## What to read next

- [HTTP API reference](/sandboxd/reference/http-api/) — skip the CLI and speak JSON directly.
- [Workspaces](/sandboxd/guides/workspaces/) — `shared:` vs `clone:` trade-offs.
- [Network policies](/sandboxd/guides/network-policies/) — author policies that your agent ships with its tools.
- [Hardening](/sandboxd/guides/hardening/) — lock down the host side before running untrusted code inside a session.
