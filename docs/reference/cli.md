---
title: CLI reference
description: Complete reference for the sandbox command-line tool — every subcommand, flag, and session-identifier rule.
---

Complete reference for the `sandbox` command-line tool. The CLI communicates with the `sandboxd` daemon over a Unix socket.

For a condensed tour of the main commands, see the [Quickstart](/sandboxd/start/quickstart/). For the daemon's HTTP API that backs the CLI, see [Architecture](/sandboxd/concepts/architecture/).

## Global options

| Option | Default | Description |
|--------|---------|-------------|
| `--socket <path>` | `$XDG_RUNTIME_DIR/sandboxd/sandboxd.sock` | Path to the sandboxd Unix socket (falls back to `~/.local/share/sandboxd/sandboxd.sock`). Also honored by the daemon. Can be overridden by the `SANDBOX_SOCKET` env var; an explicit `--socket` flag takes precedence. |
| `--yes`, `-y` | | Assume yes to interactive prompts (use defaults without prompting) |

All commands accept the `--socket` and `--yes` options:

```bash
sandbox --socket /tmp/custom.sock ps
```

## Caller identity and per-operator scope

Every CLI invocation connects to the daemon over its Unix socket; the kernel verifies the caller's UID via `SO_PEERCRED` and the daemon resolves that UID to a username for ownership stamping. There is no API key, no token, no `--user` flag — your operating-system identity *is* the credential.

Session views are caller-scoped:

- `sandbox ps`, `sandbox describe`, and every per-session subcommand operate only on sessions owned by the invoking operator.
- A session created by another operator is invisible: `sandbox ps` omits the row, and any attempt to address its ID with `sandbox start <id>`, `sandbox exec <id>`, `sandbox rm <id>`, etc., returns "session not found" (same wire shape as a truly-not-found ID; the daemon does not distinguish the two cases).
- Root (`sudo sandbox ps`) sees the union of every operator's sessions — root resolves to the `root` username at the daemon, which has no per-user partition. There is no admin override in v1 for non-root operators; if you need to inspect another operator's sessions, run as that operator.

Implications:

- Two operators on the same host can run `sandbox create` concurrently without colliding. Each sees only their own sessions; subnet allocation is daemon-wide and prevents IP overlap.
- `sandbox rm` cannot remove another operator's session — root is the only escape hatch.
- The `sandbox` system user (the daemon's runtime user post-install) is not a special case at the API: a `sudo -u sandbox sandbox ps` lists only sessions whose `owner_username` is `sandbox`, which in normal operation is none.

For the HTTP-level mechanics see [HTTP API: caller identity and per-caller isolation](/sandboxd/reference/http-api/#caller-identity-and-per-caller-isolation).

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
| `--cpus <n>` | backend default | Number of CPU cores. Lima sessions fall back to 2 cores; container ("lite") sessions fall back to the daemon's host-80% ceiling. Accepts a fractional value (`0.8`, `1.5`, `2.0`, …); the container backend rounds to one decimal at request-parse time. Lima sessions truncate the fractional part because QEMU's `-smp` flag pins integer cores. Passing a fractional value with an explicit `--backend lima` (or a Lima resolved default) is rejected; use an integer instead. |
| `--memory <mb>` | backend default | Memory in megabytes. Lima sessions fall back to 4096 MB; container ("lite") sessions fall back to the daemon's host-80% ceiling. |
| `--disk <gb>` | `20` | Disk size in gigabytes |
| `--repo <url>` | | Git repository URL to clone into the session's workspace directory (`/home/sandbox/workspace/` on both Lima and container sessions). |
| `--workspace <mode>` | | Workspace mode (e.g., `shared:/path/to/dir`) |
| `--boot-cmd <cmd>` | | Command to execute after provisioning |
| `--policy <path>` | | Path to a policy JSON file to apply after creation |
| `--preset <invocation>` | | Preset invocation to apply on top of `--policy`. Repeatable. See [`--preset` invocations](#preset-invocations) below and the [Presets guide](/sandboxd/guides/network-policies/#presets). |
| `--template <path>` | | Path to a custom Lima YAML template |
| `--backend <name>` | resolved | Which backend hosts the session: `lima` or `container`. When omitted, the daemon resolves from `SANDBOX_DEFAULT_BACKEND`, the per-user config (`~/.config/sandboxd/config.json`), and finally the hardcoded default `lima`. Mutually exclusive with `--lite`. |
| `--lite` | | Sugar for `--backend container`. Mutually exclusive with `--backend`. See [Lite mode](/sandboxd/guides/lite-mode/). |
| `--no-hardening` | | Disable QEMU hardening (device lockdown, cgroup limits). Lima only. |
| `--no-cache` | | Skip the pre-baked base image and use the full create path. **Lima only** — rejected on the container backend (the lite image is shared across concurrent lite sessions, so a per-session cache-bust would force every other lite session to rebuild). Use [`sandbox rebuild-image --backend container --no-cache`](#sandbox-rebuild-image) for operator-driven lite-image rebuilds. |
| `--force-rootless-docker` | | Operator opt-in override that allows session-create on a rootless Docker host (container backend only — combining it with a Lima-resolved backend is a misuse error). Off by default; the daemon refuses container-backend session-create on rootless Docker so accidental mode-mismatch can't slip through. The flag is per-invocation and never persisted. |

Notes:

- `--repo` and `--workspace` are mutually exclusive.
- `--workspace` must use the `shared:<absolute-path>` format. The path must exist.
- `--boot-cmd` runs as `bash -c "<cmd>"` via the guest agent after all other provisioning.
- `--no-hardening` disables QEMU device lockdown and cgroup resource limits. Use for debugging only.

### Preset invocations

Preset invocations are client-local macros that expand to v2 policy rules inside the CLI before the effective policy is sent to the daemon. `--preset` is repeatable; every invocation layers more rules on top of the `--policy` file (if any).

Syntax:

```
--preset '<name>[:key=val[,key=val,...]]'
```

- `<name>` is the preset to apply, e.g. `npm`, `github-repo`. Unparameterized presets use the bare name (`npm`); the legacy trailing-colon form (`npm:`) is still accepted.
- Each `key=val` segment supplies one parameter. Keys and values are separated by `=`; segments are separated by `,`.
- Values may not contain a raw `,`, `:`, or `=`. There is no escape mechanism — a forbidden character in a value is a hard error. In practice no built-in preset param needs any of those characters, and user presets should pick param shapes that avoid them.
- Repeated keys stack in invocation order (e.g. `'github-repo:repo=foo/bar,repo=baz/qux'` passes two repos).

The flag is repeatable so multiple presets can be stacked on one command line:

```bash
sandbox create --name dev --preset 'npm' --preset 'pypi'
```

Interaction with `--policy`:

- Presets merge **into** the policy file — both sets of rules contribute to the effective policy.
- Rule identity is the `(host, port)` pair. Any collision between the policy file and a preset expansion (or between two preset expansions) is a hard error that names every contributing source. See [`(host, port)` uniqueness](/sandboxd/guides/network-policies/#host-and-port-uniqueness) for the exact error shape.

Errors (text-identical to the CLI's `Error: <...>` line on stderr, exit code 1):

- **Unknown preset** — `--preset 'foo'` where `foo` is neither a built-in nor a user-configured preset:

  ```
  Error: unknown preset 'foo'
  ```

- **Malformed invocation** — empty name or a param segment missing `=`:

  ```
  Error: malformed preset invocation 'github-repo:repo': param segment 'repo' is missing '=' between key and value; use 'github-repo:key=value' for parameterized presets or 'github-repo' for parameterless presets
  ```

- **Forbidden character in value** — a raw `,`, `:`, or `=` inside a value:

  ```
  Error: preset 'github-repo': param 'repo=foo/bar:extra' contains forbidden character ':' in value; preset params must not contain , : or =
  ```

- **Duplicate `(host, port)`** across policy file + presets — every contributing source is named in the block:

  ```
  Error: policy validation failed: duplicate destination (registry.npmjs.org, 443)
    - declared by policy file /tmp/policy.json
    - declared by preset invocation 'npm' (built-in 'npm')
  ```

See the [Presets guide](/sandboxd/guides/network-policies/#presets) for the built-in catalog and user-preset file format, and [`sandbox policy preset`](#sandbox-policy-preset) below for the client-local inspection subcommands.

Example:

```bash
# Create a session whose agent can fetch npm packages and clone one GitHub repo.
sandbox create --name dev \
    --preset 'npm' \
    --preset 'github-repo:repo=rust-lang/rustlings'
```

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
    --boot-cmd "cd /home/sandbox/workspace && npm install"

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

List sandbox sessions owned by the invoking operator with their current state, guest agent status, and gateway status.

The listing is **caller-scoped**: each operator sees only the sessions they created. A session created by another operator is omitted entirely — there is no "owned by X" column because every row is owned by the caller. Running `sudo sandbox ps` lists root-owned sessions; on a freshly-installed host with no root-created sessions, that is normally an empty table. See [Caller identity and per-operator scope](#caller-identity-and-per-operator-scope) for the full ownership model.

By default `sandbox ps`/`sandbox ls` also runs an opportunistic reconcile pass against the local [`~/.ssh/sandbox/` managed area](/sandboxd/concepts/ssh-access/): the CLI computes the diff between the daemon's session list and the on-disk per-session SSH config entries, removes orphans (sessions deleted while the CLI was not running), and writes missing entries for active sessions. This keeps external SSH tooling (VS Code Remote-SSH, JetBrains Gateway, ad-hoc `ssh`/`scp`/`rsync`) honest without the operator having to think about it. Pass `--no-reconcile` to suppress the pass — see below.

### Synopsis

```
sandbox ps [--no-reconcile]
```

### Aliases

`sandbox ls` is an alias for `sandbox ps`. The alias accepts the same options.

### Options

| Option | Default | Description |
|--------|---------|-------------|
| `--no-reconcile` | off | Skip the opportunistic reconcile pass against `~/.ssh/sandbox/`. The command only reads the daemon's session list and prints it — no local SSH-config mutations. Intended for read-only tooling (scripts, monitoring, debugging) where a list operation must not mutate operator state. Note: orphan SSH-config entries left on disk in `--no-reconcile` mode are cleaned up the next time `sandbox ps`/`sandbox ls` runs without the flag, or lazily on the next `sandbox proxy` invocation that returns 404 for the orphan id. |

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

Open an interactive SSH session in a sandbox, or run a single command non-interactively. Dispatches to the standard `ssh` client against the `sandbox-<id>` alias the CLI manages under [`~/.ssh/sandbox/`](/sandboxd/concepts/ssh-access/); the underlying transport is the daemon's `GET /sessions/{id}/proxy` WebSocket endpoint.

### Synopsis

```
sandbox ssh <session> [-- <command> [args...]]
```

### Arguments

| Argument | Description |
|----------|-------------|
| `<session>` | Session name or session ID (see [Session identifiers](#session-identifiers)). |
| `<command>` | Optional command to run non-interactively (after `--`) |

### Details

- The first invocation per session ensures the managed `~/.ssh/sandbox/sandbox-<id>` config + key files exist and the `Include` block is present at the top of `~/.ssh/config`. Subsequent invocations re-use the on-disk state and the existing ControlMaster multiplex socket if one is live.
- If the daemon has rotated the per-session key since the local entry was written, the first SSH attempt fails with `Permission denied (publickey)` and the CLI silently re-fetches the config and retries once. The retry is matched **only at the outermost CLI dispatch** — nested invocations through `git-remote-sandbox` cannot stack retries.
- TTY allocation, terminal resize, and signal forwarding are handled by the standard `ssh` client.
- The in-session user is `sandbox` on both backends (uid 1000) with home at `/home/sandbox/`. The SSH config block sets `User sandbox` uniformly.

### Examples

```bash
# Interactive shell
sandbox ssh my-sandbox

# Run a single command
sandbox ssh my-sandbox -- uname -a

# Run a command with arguments (container session — adjust path for Lima)
sandbox ssh my-sandbox -- ls -la /home/sandbox/workspace
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
sandbox exec my-sandbox -- ls /home/sandbox/workspace

# Run a shell command
sandbox exec my-sandbox -- bash -c "cd /home/sandbox/workspace && make test"

# Check disk usage
sandbox exec my-sandbox -- df -h
```

---

## sandbox cp

Copy files or directories between the host and a sandbox session. Uses the `session:path` syntax to specify the remote side.

### Synopsis

```
sandbox cp <src> <dst>
```

One of `<src>` or `<dst>` must use the `session:path` format to identify the remote side.

### Arguments

| Argument | Description |
|----------|-------------|
| `<src>` | Source path. Prefix with `session:` for session-side paths. |
| `<dst>` | Destination path. Prefix with `session:` for session-side paths. |

### Details

- Dispatches to the standard `scp` client against the `sandbox-<id>` alias the CLI manages under [`~/.ssh/sandbox/`](/sandboxd/concepts/ssh-access/), uniformly across both backends. The underlying transport is the daemon's `GET /sessions/{id}/proxy` WebSocket endpoint.
- Recurses into directories transparently (scp's `-r`).
- Errors (missing source, permission denied, unreachable session) come from `scp` verbatim.
- Both source and destination cannot be remote.
- Like [`sandbox ssh`](#sandbox-ssh), a stale local SSH config triggers a single transparent retry after the CLI re-fetches the config from the daemon.
- For incremental directory mirroring (skip-unchanged, attribute preservation, deletion mirroring), use [`sandbox sync`](#sandbox-sync) instead — `cp` retransfers the full source on every invocation.

### Examples

```bash
# Upload a file to the session
sandbox cp local/config.toml my-sandbox:/home/sandbox/workspace/config.toml

# Download a file from the session
sandbox cp my-sandbox:/home/sandbox/workspace/output.log ./output.log

# Upload a build artifact
sandbox cp ./dist/app.tar.gz ci-run:/home/sandbox/workspace/app.tar.gz

# Upload a directory (recurses transparently)
sandbox cp ./dist my-sandbox:/home/sandbox/workspace/dist
```

---

## sandbox sync

Mirror a directory between the host and a sandbox session via `rsync`. Use this when you need incremental updates, attribute preservation across re-runs, and the deletion of source-removed files on the destination — properties `cp` does not provide.

### Synopsis

```
sandbox sync <src> <dst> [-- <rsync-args>...]
```

One of `<src>` or `<dst>` must use the `session:path` format to identify the remote side.

### Arguments

| Argument | Description |
|----------|-------------|
| `<src>` | Source path. Prefix with `session:` for session-side paths. |
| `<dst>` | Destination path. Prefix with `session:` for session-side paths. |
| `-- <rsync-args>...` | Optional extra rsync flags (everything after `--`). Spliced between the baseline `-a --delete -e <shell>` and the source / destination operands so rsync's argv parser receives them as flags, not as additional sources. |

### Details

- Dispatches to the host's `rsync` binary using standard `ssh` as the remote-shell transport against the `sandbox-<id>` alias the CLI manages under [`~/.ssh/sandbox/`](/sandboxd/concepts/ssh-access/): `rsync -a --delete -e ssh ... sandbox-<id>:...`. Both backends use the same shape — the alias resolves the daemon proxy for either runtime.
- Baseline flag set is `-a --delete`: archive mode (preserves perms, ownership, mtimes, symlinks, recursion) plus mirror semantics (delete destination entries that no longer exist on the source).
- Pass-through flags after `--` are layered on top of the baseline. Use them for `--exclude`, `--bwlimit`, `--partial`, `--info=progress2`, etc. The CLI does not interpret them — it splices them straight into rsync's argv between the baseline flags and the operands, which is the position rsync's synopsis (`rsync [OPTION...] SRC... [DEST]`) requires.
- **Requires `rsync` on both the host and inside the session image.** sandboxd-provisioned base images (Lima golden image, Lite container image) include rsync by default. If you supply a custom image, install rsync yourself or `sandbox sync` will fail with `rsync: command not found` from whichever side is missing it.
- Errors (missing source, permission denied, unreachable session) come from `rsync` verbatim. The exit code is propagated unchanged so callers can branch on rsync's documented exit-code table (`man rsync(1)`).
- Both source and destination cannot be remote.
- Like [`sandbox ssh`](#sandbox-ssh), a stale local SSH config triggers a single transparent retry after the CLI re-fetches the config from the daemon.

### Examples

```bash
# Upload a directory tree to the session, preserving attributes
sandbox sync ./src my-sandbox:/home/sandbox/workspace/src

# Pull build artifacts back to the host, deleting host-side files
# that no longer exist in the session (mirror semantics)
sandbox sync ci-run:/home/sandbox/workspace/dist ./dist

# Re-run after editing a few files: rsync only retransfers the deltas
sandbox sync ./src my-sandbox:/home/sandbox/workspace/src

# Demonstrate `--delete`: a file removed locally is removed in the
# session on the next sync
rm ./src/obsolete.go
sandbox sync ./src my-sandbox:/home/sandbox/workspace/src
# /home/sandbox/workspace/src/obsolete.go is now gone in the session too

# Pass-through extra rsync flags after `--`. The CLI splices them
# between the baseline `-a --delete -e ssh` and the operands.
sandbox sync ./src my-sandbox:/home/sandbox/workspace/src \
    -- --exclude '*.log' --exclude 'target/' --info=progress2

# Throttle bandwidth and keep partials across resumed runs.
sandbox sync ci-run:/home/sandbox/workspace/artifacts ./out \
    -- --bwlimit=1m --partial
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

Replay or stream the session's event stream — every per-request decision made by the gateway's DNS, Envoy, mitmproxy, and nft-logger layers (deny + allow), plus the session's lifecycle events. Thin client over [`GET /sessions/{id}/events`](/sandboxd/reference/http-api/#get-sessionsidevents--replay-or-stream-events).

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
| `--layer <name>` | | Filter by layer. Valid values: `dns`, `envoy`, `mitmproxy`, `deny-logger`, `lifecycle`. Repeat to include multiple layers; values within the flag combine with OR. The nft-allow-logger's `allow` events flow on the `deny-logger` layer (sibling members of the nft-logger family on the bus); use `--event=allow` to narrow. |
| `--event <name>` | | Filter by event name (e.g. `query_denied`, `connection_allowed`, `deny`, `allow`, `rate_limited`, `policy_applied`, `policy_propagated`). Repeat to include multiple names. |
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

- **JSONL** (default when stdout is not a TTY, or when `--json` is set): each line is a single JSON object matching the wire shape documented under [`GET /sessions/{id}/events`](/sandboxd/reference/http-api/#get-sessionsidevents--replay-or-stream-events). Lines the CLI cannot parse as an event — most notably the synthetic `lifecycle.ring_buffer_lag` marker the server emits when a follow stream falls behind — are passed through unchanged in JSONL mode.
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
   sandbox exec dev -- bash -c "cd /home/sandbox/workspace && npm install"
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

The `tests/e2e/test_discovery.py` suite encodes this exact flow end-to-end. See [Network policies](/sandboxd/guides/network-policies/) for how to structure the policy JSON once you know which targets to allow.

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
sandbox policy update <session> (--policy <path> | --preset <invocation>... | --clear)
```

### Arguments

| Argument | Description |
|----------|-------------|
| `<session>` | Session name or session ID (see [Session identifiers](#session-identifiers)). |

### Options

| Option | Description |
|--------|-------------|
| `--policy <path>` | Path to a policy JSON file to apply. Mutually exclusive with `--clear`. Composes with `--preset`. |
| `--preset <invocation>` | Preset invocation to merge into the effective policy. Repeatable. Mutually exclusive with `--clear`. Same syntax and semantics as [`sandbox create --preset`](#preset-invocations). |
| `--clear` | Remove any active policy and revert the session to the fail-closed default (empty CoreDNS allow-list, deny-all gateway). Idempotent. Mutually exclusive with `--policy` and `--preset`. |

At least one of `--policy`, `--preset`, or `--clear` must be supplied. `--policy` and `--preset` compose (presets expand and merge into the file's rules); `--clear` is mutually exclusive with both.

### Details

- With `--policy`, the policy file is validated client-side before sending to the daemon; invalid JSON or a rejected schema aborts the request.
- The policy must parse as a valid `Policy` JSON structure (see [policy model](/sandboxd/concepts/policy-model/)).
- With `--preset`, each invocation is expanded locally into a rule set and merged with the (optional) `--policy` file. `(host, port)` collisions across the file and preset expansions are hard errors that name every contributing source — see [`(host, port)` uniqueness](/sandboxd/guides/network-policies/#host-and-port-uniqueness).
- The original `--preset` invocation strings are sent to the daemon as a `source_presets` audit field alongside the effective policy.
- `--clear` is a no-op when the session already has no policy.

### Examples

```bash
# Apply a policy by session name
sandbox policy update my-sandbox --policy policy.json

# Apply a policy by session ID (or unique ID prefix)
sandbox policy update feedfacecafe --policy restricted-policy.json

# Apply presets on top of an existing policy file
sandbox policy update dev --policy policy.json \
    --preset 'npm' \
    --preset 'github-repo:repo=rust-lang/rustlings'

# Apply presets with no file policy (presets become the whole effective policy)
sandbox policy update dev --preset 'cargo'

# Drop the active policy and return the session to fail-closed
sandbox policy update my-sandbox --clear
```

---

## sandbox policy preset

Inspect the built-in and user-configured preset catalog. All three subcommands are **client-local** — they do not contact the sandbox daemon and do not require the Unix socket to be reachable. User presets are loaded from `$XDG_CONFIG_HOME/sandboxd/presets/*.json` (falling back to `$HOME/.config/sandboxd/presets/*.json`); see the [Presets guide](/sandboxd/guides/network-policies/#user-presets) for the file format.

### Synopsis

```
sandbox policy preset list
sandbox policy preset show <name>
sandbox policy preset expand '<invocation>'
```

### sandbox policy preset list

Enumerate every preset available to the CLI, sorted alphabetically by name. Output is a two-column, tab-separated table:

| Column | Description |
|--------|-------------|
| `NAME` | Preset name (the string typed before the `:` in an invocation). |
| `SOURCE` | `built-in` for compile-time presets, or `user: <absolute-path>` for user-configured presets loaded from the XDG presets directory. |

Pipe through `column -t -s $'\t'` for a pretty-printed table.

Example:

```bash
sandbox policy preset list
```

```
cargo	built-in
claude	built-in
docker	built-in
dockerhub	built-in
github	built-in
github-pr	built-in
github-repo	built-in
goproxy	built-in
gradle	built-in
maven	built-in
npm	built-in
pypi	built-in
ubuntu	built-in
```

With a user preset on disk, its row appears in alphabetical position with the full file path:

```
my-internal	user: /home/alice/.config/sandboxd/presets/my-internal.json
```

### sandbox policy preset show `<name>`

Print the preset's description and parameter schema. Useful before invoking a parameterized preset to see which `key=val` pairs it accepts.

Arguments:

| Argument | Description |
|----------|-------------|
| `<name>` | Preset name, exactly as it appears in `sandbox policy preset list`. |

Output shape: a multi-line block with `Preset:`, `Description:`, `Source:`, and a `Params:` section. Unparameterized presets render `Params: (none)`; parameterized presets list each declared parameter with `(required)` / `(repeatable)` flags.

Example — an unparameterized preset:

```bash
sandbox policy preset show npm
```

```
Preset: npm
Description: Allow npm registry reads (registry.npmjs.org).
Source: built-in
Params: (none)
```

Example — a parameterized preset:

```bash
sandbox policy preset show github-repo
```

```
Preset: github-repo
Description: Allow narrow GitHub access scoped to one or more repos (param: repo=owner/name).
Source: built-in
Params:
  - repo=owner/name (required, repeatable)
```

Looking up a name that does not exist in the catalog exits non-zero:

```
Error: unknown preset 'not-a-real-preset'
```

A user preset file whose `name` field collides with a built-in is a hard error at lookup time (user files cannot shadow built-ins):

```
Error: preset 'npm' is defined by both a built-in and a user file at
  /home/alice/.config/sandboxd/presets/npm.json
user presets cannot shadow built-ins; rename or delete the user file.
```

### sandbox policy preset expand `'<invocation>'`

Expand a preset invocation into a v2 policy document and print it to stdout. The output is a complete `{"version":"2.0.0","rules":[...]}` document — you can redirect it to a file and feed it back into `sandbox create --policy` unchanged.

Arguments:

| Argument | Description |
|----------|-------------|
| `<invocation>` | Raw preset invocation (see [`sandbox create --preset`](#preset-invocations)). Quote the string to protect `:` / `,` / `=` from the shell. |

Use cases:

- **Dry-run before apply** — preview the exact rules a `--preset` flag would contribute before creating a session.
- **Round-trip to a policy file** — capture an expansion as a starting point for a hand-edited policy.
- **Drift / review** — compare `expand` output across CLI releases to see what a built-in preset's rule set became.

Errors are the same set as [`--preset`](#preset-invocations) (unknown preset, malformed invocation, forbidden character in value, missing required param, invalid parameter value, ...), printed to stderr with a non-zero exit.

Example — an unparameterized preset:

```bash
sandbox policy preset expand 'npm'
```

```json
{
  "version": "2.0.0",
  "rules": [
    {
      "host": "registry.npmjs.org",
      "port": 443,
      "protocol": "tcp",
      "level": "http",
      "http_filters": [
        {
          "method": "GET",
          "path": "/**"
        },
        {
          "method": "HEAD",
          "path": "/**"
        }
      ]
    }
  ]
}
```

Example — round-trip an expansion into a policy file:

```bash
sandbox policy preset expand 'github-repo:repo=rust-lang/rustlings' > /tmp/expanded.json
sandbox create --name dev --policy /tmp/expanded.json
```

See the [Presets guide](/sandboxd/guides/network-policies/#presets) for a tour of the built-in catalog and the user-preset file format.

---

## git-remote-sandbox (symlink)

`git-remote-sandbox` is a symlink to the `sandbox` binary, not a subcommand. You never invoke it directly: git does, automatically, whenever it resolves a `sandbox::<session>/<repo-path>` URL. The binary detects it was invoked under that name (via `argv[0]`) and switches into git remote-helper mode, tunneling the git pack protocol over [`sandbox ssh`](#sandbox-ssh) to the repository inside the target session.

### URL format

```
sandbox::<session>/<repo-path>
```

| Part | Description |
|------|-------------|
| `<session>` | Session name or session ID (see [Session identifiers](#session-identifiers)). |
| `<repo-path>` | Absolute path to the git repository inside the session (e.g., `/home/sandbox/workspace` for both Lima and container sessions). If omitted, defaults to the session's workspace path. |

### Usage

```bash
# Clone straight out of a container session
git clone sandbox::my-session/home/sandbox/workspace local-checkout

# Or add the session as a remote on an existing repo and push/pull normally
git remote add origin sandbox::my-session/home/sandbox/workspace
git push origin main
git pull origin main
```

### Requirements and notes

- The `git-remote-sandbox` symlink must be installed on `PATH` alongside the `sandbox` binary; git looks it up by name.
- The daemon socket path can be overridden with the `SANDBOX_SOCKET` environment variable. The `--socket` global flag is not available in remote-helper mode because git controls argv.

---

## sandbox proxy (hidden)

`sandbox proxy <id>` is the `ProxyCommand` shim invoked by `ssh sandbox-<id>` for every connection that resolves through the managed [`~/.ssh/sandbox/sandbox-<id>`](/sandboxd/concepts/ssh-access/) config block. It is **hidden from `--help`** because operators do not invoke it directly — `ssh` does, automatically, via the generated `ProxyCommand` line.

You may still encounter the subcommand if you read your own managed SSH config or trace an `ssh -v` log. This section documents the contract so the trace is interpretable.

### Synopsis

```
sandbox proxy <id>
```

### What it does

- Performs an HTTP-to-WebSocket upgrade against the daemon's [`GET /sessions/{id}/proxy`](/sandboxd/reference/http-api/#get-sessionsidproxy--websocket-byte-mover-into-the-sessions-sshd) endpoint over the same Unix-socket transport every other CLI ⇄ daemon call uses.
- Bidirectionally ferries bytes between its own stdin/stdout (which `ssh` has connected to its SSH transport) and the WebSocket's binary frames.
- Performs **no** SSH-protocol parsing, no retry, no drift recovery, no lifecycle cleanup beyond a lazy-404 sweep of the local managed entry when the daemon reports the session no longer exists. SSH authentication and channel multiplexing happen end-to-end between the operator's `ssh` client and the in-session sshd.

### Exit codes

| Exit code | Symbol | Meaning |
|-----------|--------|---------|
| `0` | `EXIT_OK` | Clean disconnect — one end half-closed and every byte was ferried across before exit. `ssh` reports a normal exit. |
| `1` | `EXIT_GENERIC_FAILURE` | Generic failure — I/O error, handshake failure, malformed response, daemon socket unreachable. `ssh` reports the `ProxyCommand` as having failed (typically as `kex_exchange_identification: Connection closed by remote host`). |
| `2` | `EXIT_SESSION_NOT_FOUND` | Daemon returned `404 Not Found` for the session id. The session either does not exist (typo, since-deleted, or never created) or belongs to another operator. The CLI also lazily cleans the orphaned `~/.ssh/sandbox/sandbox-<id>` entry off this exit. |

The exit-code shape is committed: external tooling that wraps `sandbox proxy` (none ships in v1, but operators may script their own) can branch on these values without observing the stderr message.

### Wire-format note

The subcommand name (`proxy`) and its single positional argument (`<id>`) are wire-format-stable — the daemon-emitted SSH config block carries `ProxyCommand sandbox proxy <id>` verbatim. Renaming the subcommand is a breaking change for every session that ever wrote a managed config entry.

---

## sandbox policy status

Report policy-propagation status for a session. Queries `GET /sessions/{id}/policy/propagation-status` and prints the result, optionally polling until the most recent policy-apply has reconciled across every enforcement layer.

### Synopsis

```
sandbox policy status <session> [--wait] [--timeout <duration>]
```

### Arguments

| Argument | Description |
|----------|-------------|
| `<session>` | Session name or session ID (see [Session identifiers](#session-identifiers)). |

### Options

| Option | Default | Description |
|--------|---------|-------------|
| `--wait` | off | Poll until the latest policy-apply has reached steady state across nftables, Envoy, and mitmproxy/CoreDNS. Without it, the command reads the status once and exits. |
| `--timeout <duration>` | `60s` | Deadline for `--wait`. Accepts plain seconds (`60`), `s`, `m`, `h`, or `ms` suffixes (`60s`, `2m`, `1h`, `500ms`). Ignored unless `--wait` is set. |

### Details

- Exits 0 when the latest policy-apply has propagated, or when no policy has ever been applied (nothing to wait for).
- Exits non-zero on daemon errors. With `--wait`, exits non-zero if the deadline passes before the policy propagates — useful in scripts and the E2E suite to fail fast instead of `time.sleep()`-ing.
- See [networking → Synchronous DNS-policy gating](/sandboxd/concepts/networking/#synchronous-dns-policy-gating) for the propagation model and the `policy_propagated` lifecycle event this command waits on.

### Examples

```bash
# Read the current propagation snapshot and exit.
sandbox policy status dev

# Apply a policy, then block until every enforcement layer has reconciled.
sandbox policy update dev --policy ./policy.json
sandbox policy status dev --wait --timeout 10s
```

---

## sandbox rebuild-image

Rebuild the pre-baked backend image(s) the daemon clones from on the fast `sandbox create` path. For Lima, "rebuild" cache-busts the golden VM image; for the container backend, it rebuilds the lite image.

### Synopsis

```
sandbox rebuild-image [--backend lima|container|all] [--no-cache]
```

### Options

| Option | Default | Description |
|--------|---------|-------------|
| `--backend <name>` | `all` | Which backend's image to rebuild. `all` rebuilds every installed backend's image; per-backend failures are printed with a `rebuild-image[<backend>]:` prefix and the command exits non-zero if any selected backend fails. Concurrent `--backend lima` and `--backend container` calls do not block each other. |
| `--no-cache` | | Cache-bust the rebuild. Container: passes `--no-cache` to `docker build`. Lima: already cache-busts on every rebuild (delete-then-build the golden VM), so this flag is a no-op for Lima but kept for symmetry with the container path. |

### Examples

```bash
# Rebuild both Lima's golden image and the lite container image.
sandbox rebuild-image

# Rebuild only the lite image with full cache-bust.
sandbox rebuild-image --backend container --no-cache

# Rebuild only the Lima golden image.
sandbox rebuild-image --backend lima
```

---

## sandbox update

Apply a pending sandboxd upgrade — or report what would happen. Orchestrates the full upgrade flow: pre-flight checks (read-only), confirmation prompt, then the stateful steps that stop the daemon, install new binaries, run config migrations, and restart. Each privileged step uses `sudo -k <action>` so every elevation appears as its own line in `/var/log/sandbox-install.log`. The operator-facing walkthrough lives at [Operate: update](/sandboxd/operate/update/).

### Synopsis

```
sudo sandbox update [--version <v>] [--from <path>] [--cosign-bundle <path>]
                    [--source-url <url>] [--check] [--dry-run] [--yes]
                    [--force] [--quiet|--verbose]
```

### Options

| Option | Default | Description |
|--------|---------|-------------|
| `--version <semver>` | `latest` | Pin to a specific release tag. With no flag, the latest tag is resolved via the GitHub Releases API. |
| `--from <path>` | | Use a pre-staged local tarball (or extracted directory) instead of fetching from GitHub Releases. Required for air-gapped operation; the version is read from the embedded `MANIFEST`, not the filename. |
| `--cosign-bundle <path>` | | Path to a sigstore bundle for `--from` verification. Requires `--from`. When omitted, the CLI looks for a sibling `<tarball>.sigstore` file. |
| `--source-url <url>` | GitHub Releases | Override the default release-tarball base URL. Mutually exclusive with `--from`. |
| `--check` | | Read-only mode: report installed vs available, then exit. Never acquires the update lock, never contacts cosign, never extracts anything. See exit codes below. |
| `--dry-run` | | Read-only mode: print the step-by-step plan (`would execute` or `would skip` per stateful step) and exit. Never mutates state. |
| `--yes` | | Skip the interactive confirmation prompt. Equivalent to answering `y`. |
| `--force` | | Proceed past the "active sessions exist" guard. The daemon stop will terminate active sessions mid-flight — use only when the daemon is wedged and you want to upgrade anyway. |
| `--quiet` | | Quieter logging (one line per major step). |
| `--verbose` | | Verbose logging (full per-step detail). |

`--check` and `--dry-run` are read-only and may be run without `sudo`. Every other invocation requires `sudo sandbox update` (the CLI binary itself is unprivileged; each step re-elevates via `sudo -k`).

### Exit codes

| Code | Meaning |
|------|---------|
| `0` | Success: applied; `--check` reported up-to-date; `--dry-run` printed plan; or confirmation answered `N`. |
| `1` | Runtime error — pre-flight refused, daemon unreachable, network failure, cosign-verify failed, partial-failure mid-flow. |
| `2` | Argument-parse failure or refused flag combination (e.g. `--cosign-bundle` without `--from`). |
| `3` | `--check` only — an update is available. Machine-readable signal. |

### Examples

```bash
# Resolve `latest` via the GitHub Releases API and apply.
sudo sandbox update

# Pre-flight only — print the upgrade plan, exit without mutating anything.
sandbox update --check
sandbox update --dry-run

# Pin a specific target version.
sudo sandbox update --version 1.2.0

# Air-gapped: pre-staged tarball + sigstore bundle, no network.
sudo sandbox update \
    --from /path/to/sandboxd-1.2.0-x86_64-unknown-linux-gnu.tar.gz \
    --cosign-bundle /path/to/sandboxd-1.2.0-x86_64-unknown-linux-gnu.tar.gz.sigstore \
    --yes

# Branch on --check exit code in a script.
sandbox update --check; rc=$?
[ $rc -eq 3 ] && sudo sandbox update --yes
```

For the full operator walkthrough — pre-flight, the stateful flow, backup mechanics, lock-file semantics, and the rollback recipe — see [Operate: update](/sandboxd/operate/update/). For the manual recipe to restore a previous release, see [Roll back a sandboxd upgrade](/sandboxd/guides/rollback/).

---

## sandbox doctor

Diagnose the local sandboxd installation. Connects tolerantly: the CLI ↔ daemon strict-equality version handshake is bypassed for this subcommand, so `sandbox doctor` can *diagnose* a version skew rather than be refused by it. The same property makes `doctor` the load-bearing post-update verification step and the post-rollback green-light gate in the [rollback recipe](/sandboxd/guides/rollback/).

### Synopsis

```
sandbox doctor [--verbose]
```

### Options

| Option | Default | Description |
|--------|---------|-------------|
| `--verbose` | | Print every check (including passes) rather than only failures and skip-hints. |

### Examples

```bash
# Standard run — prints failures only by default.
sandbox doctor

# Full check listing including passes.
sandbox doctor --verbose
```

The check shape, individual probes, and remediation hints are an evolving surface; consult the command's output for the authoritative list.
