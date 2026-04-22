---
title: CLI reference
description: Complete reference for the sandbox command-line tool — every subcommand, flag, and session-identifier rule.
---

Complete reference for the `sandbox` command-line tool. The CLI communicates with the `sandboxd` daemon over a Unix socket.

For a condensed tour of the main commands, see the [Quickstart](/start/quickstart/). For the daemon's HTTP API that backs the CLI, see [Architecture](/concepts/architecture/).

## Global options

| Option | Default | Description |
|--------|---------|-------------|
| `--socket <path>` | `$XDG_RUNTIME_DIR/sandboxd/sandboxd.sock` | Path to the sandboxd Unix socket (falls back to `~/.local/share/sandboxd/sandboxd.sock`). Also honored by the daemon. Can be overridden by the `SANDBOX_SOCKET` env var; an explicit `--socket` flag takes precedence. |
| `--yes`, `-y` | | Assume yes to interactive prompts (use defaults without prompting) |

All commands accept the `--socket` and `--yes` options:

```bash
sandbox --socket /tmp/custom.sock ps
```

## Session identifiers

Every session has an auto-generated 12-character lowercase hex **session ID** (e.g. `550e8400e29b`). Commands that take a `<session>` argument accept any of:

- the session's human-readable `--name` (if one was set at creation time),
- the full 12-character session ID, or
- any unique prefix of the session ID (Docker-style). If the prefix matches multiple sessions, the CLI reports the ambiguity and lists the matching IDs.

For example, if a session has ID `550e8400e29b`, then `sandbox start 550e` works as long as no other session ID starts with `550e`.

---

## sandbox create

Create and boot a new sandbox session.

### Synopsis

```
sandbox create [OPTIONS]
```

### Options

| Option | Default | Description |
|--------|---------|-------------|
| `--name <name>` | (optional) | Human-readable name for the session. If omitted, the session is identified solely by its auto-generated 12-character hex session ID. |
| `--cpus <n>` | `2` | Number of CPU cores |
| `--memory <mb>` | `4096` | Memory in megabytes |
| `--disk <gb>` | `20` | Disk size in gigabytes |
| `--repo <url>` | | Git repository URL to clone into `/home/agent/workspace/` |
| `--workspace <mode>` | | Workspace mode (e.g., `shared:/path/to/dir`) |
| `--boot-cmd <cmd>` | | Command to execute after provisioning |
| `--policy <path>` | | Path to a policy JSON file to apply after creation |
| `--template <path>` | | Path to a custom Lima YAML template |
| `--no-hardening` | | Disable QEMU hardening (device lockdown, cgroup limits) |
| `--no-cache` | | Skip the pre-baked base image and use the full create path |

Notes:

- `--repo` and `--workspace` are mutually exclusive.
- `--workspace` must use the `shared:<absolute-path>` format. The path must exist.
- `--boot-cmd` runs as `bash -c "<cmd>"` via the guest agent after all other provisioning.
- `--no-hardening` disables QEMU device lockdown and cgroup resource limits. Use for debugging only.

### Examples

```bash
# Basic session with defaults
sandbox create --name dev

# Custom resources
sandbox create --name heavy --cpus 4 --memory 8192 --disk 50

# Clone a repository
sandbox create --name project \
    --repo https://github.com/example/app.git \
    --policy policy.json

# Shared host directory
sandbox create --name local-dev \
    --workspace shared:/home/user/my-project \
    --boot-cmd "cd /home/agent/workspace && npm install"

# Custom Lima template
sandbox create --name custom --template /path/to/template.yaml
```

---

## sandbox start

Start a stopped sandbox session. Restores networking (Docker bridge, gateway container, VM NIC attachment, CA injection) using the same subnet and IPs from the original creation.

### Synopsis

```
sandbox start <session>
```

### Arguments

| Argument | Description |
|----------|-------------|
| `<session>` | Session name or session ID (see [Session identifiers](#session-identifiers)). |

### Examples

```bash
sandbox start my-sandbox
sandbox start 550e8400e29b
sandbox start 550e           # prefix match (if unique)
```

---

## sandbox stop

Stop a running sandbox session. Tears down networking resources (TAP device, gateway container, Docker bridge) but preserves the VM disk, subnet allocation, and CA certificate for restart.

### Synopsis

```
sandbox stop <session>
```

### Arguments

| Argument | Description |
|----------|-------------|
| `<session>` | Session name or session ID (see [Session identifiers](#session-identifiers)). |

### Examples

```bash
sandbox stop my-sandbox
```

---

## sandbox rm

Remove a sandbox session permanently. Stops the VM if running, deletes the Lima instance, tears down all networking resources, removes the CA certificate, and deletes the session from the database.

### Synopsis

```
sandbox rm <session>
```

### Arguments

| Argument | Description |
|----------|-------------|
| `<session>` | Session name or session ID (see [Session identifiers](#session-identifiers)). |

### Examples

```bash
sandbox rm my-sandbox
sandbox rm 0123456789ab
```

---

## sandbox ps

List all sandbox sessions with their current state, guest agent status, and gateway status.

### Synopsis

```
sandbox ps
```

### Aliases

`sandbox ls` is an alias for `sandbox ps`.

### Output columns

| Column | Description |
|--------|-------------|
| ID | 12-character hex session ID |
| NAME | Human-readable name (or `-` if unnamed) |
| STATE | `running`, `stopped`, `creating`, or `error` |
| AGENT | Guest agent status: `connected`, `unreachable`, or `-` (not checked) |
| GATEWAY | Gateway status: `healthy`, `unhealthy: <reason>`, `not_running`, or `-` |
| CREATED | Relative timestamp (e.g., `2m ago`, `3h ago`) |

### Examples

```bash
sandbox ps
```

```
ID            NAME        STATE       AGENT        GATEWAY      CREATED
a1b2c3d4e5f6  dev         running     connected    healthy      5m ago
cafebabe1234  ci-run      stopped     -            -            2h ago
```

---

## sandbox ssh

Open an interactive SSH session in a sandbox, or run a single command non-interactively. Uses `limactl shell` under the hood.

### Synopsis

```
sandbox ssh <session> [-- <command> [args...]]
```

### Arguments

| Argument | Description |
|----------|-------------|
| `<session>` | Session name or session ID (see [Session identifiers](#session-identifiers)). |
| `<command>` | Optional command to run non-interactively (after `--`) |

### Examples

```bash
# Interactive shell
sandbox ssh my-sandbox

# Run a single command
sandbox ssh my-sandbox -- uname -a

# Run a command with arguments
sandbox ssh my-sandbox -- ls -la /home/agent/workspace
```

---

## sandbox exec

Execute a command inside a sandbox via the guest agent. Unlike `ssh`, this uses the daemon's guest agent channel (TCP via SSH tunnel), not a direct SSH session.

### Synopsis

```
sandbox exec <session> <command> [args...]
```

The command and arguments should be placed after `--`:

```
sandbox exec <session> -- <command> [args...]
```

### Arguments

| Argument | Description |
|----------|-------------|
| `<session>` | Session name or session ID (see [Session identifiers](#session-identifiers)). |
| `<command>` | Command and arguments to execute |

### Output

- stdout from the command is printed to stdout.
- stderr from the command is printed to stderr.
- The CLI exits with the same exit code as the remote command.

### Examples

```bash
# List workspace contents
sandbox exec my-sandbox -- ls /home/agent/workspace

# Run a shell command
sandbox exec my-sandbox -- bash -c "cd /home/agent/workspace && make test"

# Check disk usage
sandbox exec my-sandbox -- df -h
```

---

## sandbox cp

Copy files between the host and a sandbox VM. Uses the `session:path` syntax to specify the remote side.

### Synopsis

```
sandbox cp <src> <dst>
```

One of `<src>` or `<dst>` must use the `session:path` format to identify the remote side.

### Arguments

| Argument | Description |
|----------|-------------|
| `<src>` | Source path. Prefix with `session:` for VM paths. |
| `<dst>` | Destination path. Prefix with `session:` for VM paths. |

### Details

- Files are transferred via the guest agent using base64-encoded payloads.
- Large files are automatically chunked (700 KB per chunk).
- Both source and destination cannot be remote.

### Examples

```bash
# Upload a file to the VM
sandbox cp local/config.toml my-sandbox:/root/config.toml

# Download a file from the VM
sandbox cp my-sandbox:/root/output.log ./output.log

# Upload a build artifact
sandbox cp ./dist/app.tar.gz ci-run:/home/agent/workspace/app.tar.gz
```

---

## sandbox logs

Stream gateway container logs for a sandbox session. Useful for debugging networking, policy enforcement, and proxy behavior.

### Synopsis

```
sandbox logs <session> [OPTIONS]
```

### Arguments

| Argument | Description |
|----------|-------------|
| `<session>` | Session name or session ID (see [Session identifiers](#session-identifiers)). |

### Options

| Option | Default | Description |
|--------|---------|-------------|
| `--component <name>` | `all` | Component to filter: `all`, `envoy`, `mitmproxy`, `coredns` |
| `--follow`, `-f` | | Stream logs continuously |
| `--tail <n>` | `100` | Show last N lines |

### Details

- `--component all` shows the gateway container's stdout/stderr (entrypoint output) via `docker logs`.
- Individual component logs (`envoy`, `mitmproxy`, `coredns`) are read from log files inside the container at `/var/log/gateway/`.
- `--follow` streams logs continuously until interrupted (Ctrl+C).

### Examples

```bash
# View last 100 lines of all gateway logs
sandbox logs my-sandbox

# Stream Envoy logs continuously
sandbox logs my-sandbox --component envoy --follow

# View last 50 lines of CoreDNS logs
sandbox logs my-sandbox --component coredns --tail 50

# Stream all logs
sandbox logs my-sandbox -f
```

---

## sandbox events

Replay or stream the session's event stream — every per-request decision made by the gateway's DNS, Envoy, mitmproxy, and deny-logger layers, plus the session's lifecycle events. Thin client over [`GET /sessions/{id}/events`](/reference/http-api/#get-sessionsidevents--replay-or-stream-events).

### Synopsis

```
sandbox events <session> [--follow] [--layer <name>]... [--event <name>]... [--decision allow|deny] [--since <ts-or-duration>] [--json | --table]
```

### Arguments

| Argument | Description |
|----------|-------------|
| `<session>` | Session name or session ID (see [Session identifiers](#session-identifiers)). Required. |

### Options

| Option | Default | Description |
|--------|---------|-------------|
| `--follow`, `-f` | off | Stream live events as they arrive, until interrupted with Ctrl+C. Without it, the CLI prints the current ring-buffer contents and exits when the response body ends. |
| `--layer <name>` | | Filter by layer. Valid values: `dns`, `envoy`, `mitmproxy`, `deny-logger`, `lifecycle`. Repeat to include multiple layers; values within the flag combine with OR. |
| `--event <name>` | | Filter by event name (e.g. `query_denied`, `connection_allowed`, `deny`, `rate_limited`, `policy_applied`). Repeat to include multiple names. |
| `--decision <allow\|deny>` | | Filter by verdict. Single-valued at the CLI: the HTTP endpoint accepts a repeatable parameter, but passing both `allow` and `deny` is equivalent to omitting the filter entirely, so the CLI takes one or neither. |
| `--since <ts-or-duration>` | | Lower-bound cutoff for event timestamps. Accepts either an RFC 3339 timestamp (`2026-04-22T12:00:00Z`) or a shorthand duration (`30s`, `5m`, `2h`, `7d`) resolved against the CLI's wall clock. The duration shorthand is a CLI convenience — the value sent on the wire is always an RFC 3339 timestamp. |
| `--json` | on (non-TTY) | Emit raw JSONL, one event per line. Default when stdout is not a TTY so shell redirects (`sandbox events <id> --follow > file.jsonl`) preserve round-trip fidelity. |
| `--table` | on (TTY) | Render a human-readable fixed-column table instead of JSONL. Default when stdout is a TTY. Deny rows are colored red. |

`--json` and `--table` are mutually exclusive.

### Filter semantics

Axes combine with AND, values within an axis with OR. So

```bash
sandbox events dev --layer=dns --layer=mitmproxy --decision=deny
```

returns every DNS or mitmproxy event **and** whose decision is deny. An `--event` filter that names an event carrying no decision axis (any `lifecycle` event, or the deny-logger `rate_limited` summary) is valid on its own but produces no matches when combined with `--decision`.

### Output

- **JSONL** (default when stdout is not a TTY, or when `--json` is set): each line is a single JSON object matching the wire shape documented under [`GET /sessions/{id}/events`](/reference/http-api/#get-sessionsidevents--replay-or-stream-events). Lines the CLI cannot parse as an event — most notably the synthetic `lifecycle.ring_buffer_lag` marker the server emits when a follow stream falls behind — are passed through unchanged in JSONL mode.
- **Table** (default when stdout is a TTY, or when `--table` is set): a fixed-column layout with `TIME`, `SESSION` (first 8 chars of the id), `LAYER`, `EVENT`, `HOST:PORT`, and `DETAIL` columns. `DETAIL` is truncated to 60 characters with `…`. Deny rows are wrapped in ANSI red when stdout is a TTY. Any line the table renderer cannot parse as an `EventDto` is emitted on its own row prefixed with `! ` so nothing is dropped silently.

### Exit behavior

- Non-follow: exits 0 when the response body ends (typically within ~1s of the last line).
- Follow: runs until SIGINT. On Ctrl+C, pending output is flushed, the socket is closed, and the CLI exits 130 (128 + SIGINT).
- Any HTTP-level error returned by the daemon (`404` for an unknown session, `400` for an invalid filter value or malformed `--since`) is printed to stderr and the CLI exits non-zero.

### Examples

```bash
# Replay the current ring buffer as JSONL.
sandbox events dev

# Stream only deny decisions, live, rendered as a table.
sandbox events dev --follow --decision=deny --table

# Only DNS and mitmproxy events, from the last 5 minutes.
sandbox events dev --layer=dns --layer=mitmproxy --since=5m

# Capture a follow stream for later analysis; JSONL is the default for non-TTYs.
sandbox events dev --follow > events.jsonl

# Pinpoint the moment a policy was applied.
sandbox events dev --event=policy_applied
```

### Discovery workflow

The events stream is intended as the operator-facing feedback loop for tightening a network policy from scratch. The canonical pattern is:

1. **Create the session under an empty or minimal policy.** Start from a fail-closed state (or a small starting allow-list) so every outbound attempt that should be legitimate ends up denied at least once.

   ```bash
   sandbox create --name dev --policy empty-policy.json
   ```

2. **Run the workload inside the session.** The commands the agent actually wants to execute — `git clone`, `npm install`, a test suite, a curl to an upstream API.

   ```bash
   sandbox exec dev -- bash -c "cd /home/agent/workspace && npm install"
   ```

3. **Inspect what was denied.** `--decision=deny` surfaces the denials from every layer (CoreDNS, Envoy, mitmproxy, and the deny-logger's raw packet observations). `--follow` streams them live while the workload is still running; omitting `--follow` replays whatever is already in the ring buffer.

   ```bash
   sandbox events dev --decision=deny --follow
   ```

4. **Write a tighter policy that allow-lists the required targets.** Each deny event names the host / port / protocol the workload tried to reach; fold those into the policy JSON.

5. **Apply the new policy.** `sandbox policy update` hot-reloads every gateway component without restarting the session.

   ```bash
   sandbox policy update dev --policy dev-policy.json
   ```

6. **Re-run the workload.** Run `sandbox events dev --decision=deny` once more — no new denies means the policy is tight enough.

The `tests/e2e/test_m10_s4_discovery.py` suite encodes this exact flow end-to-end. See [Network policies](/guides/network-policies/) for how to structure the policy JSON once you know which targets to allow.

---

## sandbox health

Show detailed health status of a sandbox session, including VM status, guest agent connectivity, gateway component health, and network resource status.

### Synopsis

```
sandbox health <session>
```

### Arguments

| Argument | Description |
|----------|-------------|
| `<session>` | Session name or session ID (see [Session identifiers](#session-identifiers)). |

### Output

```
Session:   9f8e7d6c5b4a
VM:        running
Agent:     connected
Gateway:
  Container: running
  Envoy:     healthy
  mitmproxy: healthy
  CoreDNS:   healthy
Network:
  Bridge:  exists
  TAP:     exists
```

### Examples

```bash
sandbox health my-sandbox
sandbox health 9f8e7d6c5b4a
```

---

## sandbox inspect

Print the full state of one or more sandbox sessions as a JSON array. Output is pretty-printed and valid for piping into `jq`.

### Synopsis

```
sandbox inspect <session>...
```

### Arguments

| Argument | Description |
|----------|-------------|
| `<session>...` | One or more session names or session IDs (see [Session identifiers](#session-identifiers)). |

### Details

- Emits a JSON array of `SessionDto` objects — one element per argument, in input order.
- The CLI resolves every id against the daemon first. If any is missing, it writes an error naming the first missing id to stderr, exits non-zero, and emits **no** stdout. Successful lookups earlier in the argument list are not printed.
- Requests are issued in parallel; ordering of the response array follows the command line, not wall-clock completion.
- The `policy` field is present only when a policy has been applied to the session; it is omitted otherwise.

### Output

```json
[
  {
    "id": "a1b2c3d4e5f6",
    "name": "dev",
    "state": "running",
    "created_at": "2026-04-17T12:34:56Z",
    "updated_at": "2026-04-17T12:40:02Z",
    "config": {
      "cpus": 2,
      "memory_mb": 4096,
      "disk_gb": 20,
      "workspace_mode": "shared:/home/olek/project",
      "hardened": true,
      "repo": "https://github.com/example/app.git",
      "boot_cmd": "make setup",
      "template": null
    },
    "guest_agent_status": "connected",
    "gateway_status": "running",
    "policy": {
      "version": "2.0.0",
      "rules": [
        {
          "host": "github.com",
          "port": 443,
          "protocol": "tcp",
          "level": "http",
          "http_filters": [{ "method": "GET", "path": "/repos/**" }],
          "reason": "fetch repo metadata"
        }
      ]
    }
  }
]
```

### Examples

```bash
# Inspect a single session
sandbox inspect my-sandbox

# Inspect multiple sessions and extract IDs with jq
sandbox inspect dev ci-run | jq -r '.[].id'

# Inspect by a unique ID prefix
sandbox inspect a1b2
```

---

## sandbox describe

Render one or more sandbox sessions in a human-readable layout, similar to `kubectl describe`. Shows header fields, `Config`, `Runtime`, and the currently applied `Policy` (if any).

### Synopsis

```
sandbox describe <session>...
```

### Arguments

| Argument | Description |
|----------|-------------|
| `<session>...` | One or more session names or session IDs (see [Session identifiers](#session-identifiers)). |

### Details

- Multiple sessions are rendered as separate blocks separated by a single blank line; input order is preserved.
- The CLI resolves every id against the daemon first. If any is missing, it writes an error naming the first missing id to stderr, exits non-zero, and emits **no** stdout. Successful lookups earlier in the argument list are not printed.
- When no policy is applied to a session, the policy section collapses to a single `Policy: none` line.

### Output

```
Session:      a1b2c3d4e5f6
Name:         dev
State:        running
Created:      2026-04-17 12:34:56 UTC (5m ago)
Updated:      2026-04-17 12:40:02 UTC

Config:
  CPUs:        2
  Memory:      4096 MB
  Disk:        20 GB
  Workspace:   shared:/home/olek/project
  Hardened:    true
  Repo:        https://github.com/example/app.git
  Boot cmd:    make setup
  Template:    -

Runtime:
  Guest agent: connected
  Gateway:     running

Policy (v2.0.0, 3 rules):
  [0] allow http      github.com:443
        protocol:    tcp
        http_filters: GET /repos/**
        reason:      fetch repo metadata
  [1] allow tls       registry.npmjs.org:443
        protocol:    tcp
  [2] deny            0.0.0.0/0:443
        protocol:    tcp
        reason:      default deny
```

Each rule prints its `(host, port)` identity on the top line, followed by indented `protocol:`, any `http_filters:` entries (one per filter), and an optional `reason:`.

### Examples

```bash
# Describe a single session
sandbox describe my-sandbox

# Describe several sessions in one go
sandbox describe dev ci-run staging
```

---

## sandbox policy update

Apply a new network policy to a running sandbox session, or clear the existing one. A new policy completely replaces the old — there is no merging. All gateway components (CoreDNS, nftables, Envoy, mitmproxy) are reconfigured and hot-reloaded without restarting the session.

### Synopsis

```
sandbox policy update <session> (--policy <path> | --clear)
```

### Arguments

| Argument | Description |
|----------|-------------|
| `<session>` | Session name or session ID (see [Session identifiers](#session-identifiers)). |

### Options

| Option | Description |
|--------|-------------|
| `--policy <path>` | Path to a policy JSON file to apply. Mutually exclusive with `--clear`. |
| `--clear` | Remove any active policy and revert the session to the fail-closed default (empty CoreDNS allow-list, deny-all gateway). Idempotent. Mutually exclusive with `--policy`. |

Exactly one of `--policy` or `--clear` must be supplied.

### Details

- With `--policy`, the policy file is validated client-side before sending to the daemon; invalid JSON or a rejected schema aborts the request.
- The policy must parse as a valid `Policy` JSON structure (see [policy model](/concepts/policy-model/)).
- `--clear` is a no-op when the session already has no policy.

### Examples

```bash
# Apply a policy by session name
sandbox policy update my-sandbox --policy policy.json

# Apply a policy by session ID (or unique ID prefix)
sandbox policy update feedfacecafe --policy restricted-policy.json

# Drop the active policy and return the session to fail-closed
sandbox policy update my-sandbox --clear
```

---

## git-remote-sandbox (symlink)

`git-remote-sandbox` is a symlink to the `sandbox` binary, not a subcommand. You never invoke it directly: git does, automatically, whenever it resolves a `sandbox::<session>/<repo-path>` URL. The binary detects it was invoked under that name (via `argv[0]`) and switches into git remote-helper mode, tunneling the git pack protocol over `sandbox ssh` to the repository inside the target session VM.

### URL format

```
sandbox::<session>/<repo-path>
```

| Part | Description |
|------|-------------|
| `<session>` | Session name or session ID (see [Session identifiers](#session-identifiers)). |
| `<repo-path>` | Absolute path to the git repository inside the VM (e.g., `/home/agent/workspace`). If omitted, defaults to `/home/agent/workspace`. |

### Usage

```bash
# Clone straight out of a session VM
git clone sandbox::my-session/home/agent/workspace local-checkout

# Or add the VM as a remote on an existing repo and push/pull normally
git remote add origin sandbox::my-session/home/agent/workspace
git push origin main
git pull origin main
```

### Requirements and notes

- The `git-remote-sandbox` symlink must be installed on `PATH` alongside the `sandbox` binary; git looks it up by name.
- The daemon socket path can be overridden with the `SANDBOX_SOCKET` environment variable. The `--socket` global flag is not available in remote-helper mode because git controls argv.

---

## sandbox rebuild-image

Rebuild the pre-baked base VM image. The base image is a fully provisioned Lima VM snapshot that accelerates `sandbox create` by skipping the cloud-init provisioning steps. Use this command after updating provisioning scripts or when the base image is stale.

### Synopsis

```
sandbox rebuild-image
```

### Examples

```bash
sandbox rebuild-image
```
