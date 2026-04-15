# CLI Reference

Complete reference for the `sandbox` command-line tool. The CLI communicates with the `sandboxd` daemon over a Unix socket.

## Global options

| Option | Default | Description |
|--------|---------|-------------|
| `--socket <path>` | `$XDG_RUNTIME_DIR/sandboxd/sandboxd.sock` | Path to the sandboxd Unix socket (falls back to `~/.local/share/sandboxd/sandboxd.sock`) |
| `--quiet`, `-q` | | Suppress interactive prompts (use defaults silently) |

All commands accept the `--socket` and `--quiet` options:

```bash
sandbox --socket /tmp/custom.sock ps
```

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
| `--name <name>` | (auto-generated UUID) | Human-readable name for the session |
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

**Notes:**
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
| `<session>` | Session name or UUID |

### Examples

```bash
sandbox start my-sandbox
sandbox start a1b2c3d4-e5f6-7890-abcd-ef1234567890
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
| `<session>` | Session name or UUID |

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
| `<session>` | Session name or UUID |

### Examples

```bash
sandbox rm my-sandbox
sandbox rm a1b2c3d4-e5f6-7890-abcd-ef1234567890
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
| ID | Session UUID |
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
ID                                    NAME        STATE       AGENT        GATEWAY      CREATED
a1b2c3d4-e5f6-7890-abcd-ef1234567890  dev         running     connected    healthy      5m ago
b2c3d4e5-f6a7-8901-bcde-f23456789012  ci-run      stopped     -            -            2h ago
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
| `<session>` | Session name or UUID |
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
| `<session>` | Session name or UUID |
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
| `<session>` | Session name or UUID |

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

## sandbox health

Show detailed health status of a sandbox session, including VM status, guest agent connectivity, gateway component health, and network resource status.

### Synopsis

```
sandbox health <session>
```

### Arguments

| Argument | Description |
|----------|-------------|
| `<session>` | Session name or UUID |

### Output

```
Session:   a1b2c3d4-e5f6-7890-abcd-ef1234567890
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
sandbox health a1b2c3d4-e5f6-7890-abcd-ef1234567890
```

---

## sandbox policy update

Apply a new network policy to a running sandbox session. The new policy completely replaces the existing one -- there is no merging. All gateway components (CoreDNS, nftables, Envoy, mitmproxy) are reconfigured and hot-reloaded without restarting the session.

### Synopsis

```
sandbox policy update <session> <policy-path>
```

### Arguments

| Argument | Description |
|----------|-------------|
| `<session>` | Session name or UUID |
| `<policy-path>` | Path to a policy JSON file |

### Details

- The policy file is validated client-side before sending to the daemon.
- The policy must parse as a valid `Policy` JSON structure (see [policy.md](policy.md) for the format).
- If validation fails, no request is sent and the error is printed.

### Examples

```bash
# Apply a policy by session name
sandbox policy update my-sandbox policy.json

# Apply a policy by session ID
sandbox policy update a1b2c3d4-... restricted-policy.json
```

---

## sandbox git-remote

Act as a git remote helper for the `ext::` transport. This command is not typically invoked directly -- it is designed to be called by git's ext:: remote transport to relay git protocol streams between a local git client and a repository inside a sandbox VM.

### Synopsis

```
sandbox git-remote <service> <session> [OPTIONS]
```

### Arguments

| Argument | Description |
|----------|-------------|
| `<service>` | Git service name (e.g., `git-upload-pack`, `git-receive-pack`), passed by git as `%S` |
| `<session>` | Session name or UUID |

### Options

| Option | Default | Description |
|--------|---------|-------------|
| `--repo-path <path>` | `/home/agent/workspace` | Path to the git repository inside the VM |

### Usage

Add a sandbox VM as a git remote using the `ext::` transport:

```bash
git remote add sandbox \
    "ext::sandbox git-remote %S my-session"
```

Then use standard git operations:

```bash
# Push local changes into the VM
git push sandbox main

# Pull changes from the VM
git pull sandbox main
```

### Details

- Supports `git-upload-pack` (fetch/pull) and `git-receive-pack` (push) operations.
- Communication is entirely host-local (CLI to daemon socket to guest agent). No network policy rules are needed.
- Use `--repo-path` to target a repository at a non-default location inside the VM.

### Examples

```bash
# Remote with default repo path (/home/agent/workspace)
git remote add sandbox "ext::sandbox git-remote %S my-session"

# Remote with custom repo path
git remote add sandbox \
    "ext::sandbox git-remote %S my-session --repo-path /home/agent/project"

# Remote with custom socket
git remote add sandbox \
    "ext::sandbox --socket /tmp/sandbox.sock git-remote %S my-session"
```

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
