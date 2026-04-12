# claude-sandbox

Lightweight, policy-controlled sandbox environments for Claude. Each sandbox runs
in an isolated VM with per-session networking, traffic inspection, and configurable
access policies.

## Architecture

- **sandboxd** -- daemon managing sandbox lifecycle (VM creation, networking, policy)
- **sandbox** (CLI) -- user-facing command-line tool for creating and managing sandboxes
- **sandbox-guest** -- agent running inside each VM, communicating with the host over vsock
- **sandbox-core** -- shared library with types, config, error handling, and session storage
- **networking/** -- gateway container, CoreDNS policy plugin, mitmproxy addons, Envoy configs

## Prerequisites

- **Rust** >= 1.75 (stable)
- **Lima** >= 2.0 for VM management (`limactl` must be on PATH)
- **QEMU** for the VM backend (Lima uses it internally)
- **Docker** for the networking gateway container
- **KVM** (`/dev/kvm` accessible) for hardware-accelerated VMs
- **Go** >= 1.22 (for the CoreDNS plugin)
- **Python** >= 3.12 with pytest (for E2E tests)

## Getting Started

### 1. Install prerequisites

**Rust** (via rustup):

```sh
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source $HOME/.cargo/env
```

**Lima** (VM manager):

```sh
# See https://lima-vm.io/docs/installation/ for your platform
brew install lima        # macOS
# or download from https://github.com/lima-vm/lima/releases
```

**KVM** (Linux only):

```sh
sudo apt install qemu-system-x86 ovmf    # Ubuntu/Debian
sudo usermod -aG kvm $USER                # grant KVM access
# Log out and back in, or run: newgrp kvm
```

Verify KVM is accessible:

```sh
ls -la /dev/kvm
# Should show crw-rw---- or crw-rw-rw- with group kvm
```

**Docker** (for networking components):

```sh
curl -fsSL https://get.docker.com | sh
sudo usermod -aG docker $USER
```

### 2. Build

```sh
make build
# or equivalently:
cd sandboxd && cargo build --workspace
```

This produces two binaries:
- `sandboxd/target/debug/sandboxd` -- the daemon
- `sandboxd/target/debug/sandbox` -- the CLI

### 3. Start the daemon

```sh
# In one terminal:
sandboxd/target/debug/sandboxd

# Or with custom paths:
sandboxd/target/debug/sandboxd --socket /tmp/my.sock --base-dir /tmp/my-state
```

The daemon listens on a Unix socket (default: `~/.sandboxd/sandboxd.sock`) and
stores session state in a SQLite database under its base directory (default:
`~/.sandboxd/`).

### 4. Create your first sandbox

```sh
# In another terminal:
sandbox create --name my-first-sandbox

# With custom resources:
sandbox create --name my-first-sandbox --cpus 2 --memory 2048 --disk 20
```

This creates and boots a Lima VM. The first run downloads the Ubuntu 24.04
cloud image (~700 MB) and may take a few minutes. Subsequent creates reuse the
cached image.

### 5. Check status

```sh
sandbox ps
```

Output:

```
ID                                    NAME              STATE       CREATED
a1b2c3d4-e5f6-7890-abcd-ef1234567890  my-first-sandbox  Running     2m ago
```

### 6. SSH into the sandbox

> **Note:** `sandbox ssh` is not yet implemented (planned for M2). For now, use
> Lima directly:

```sh
limactl shell sandbox-<session-id> -- bash
```

Replace `<session-id>` with the UUID from `sandbox ps`.

### 7. Stop and start

```sh
sandbox stop my-first-sandbox
sandbox start my-first-sandbox
```

Stopping a sandbox gracefully shuts down the VM. Starting it boots the VM again.
Data on the VM's disk is preserved across stop/start cycles.

### 8. Remove

```sh
sandbox rm my-first-sandbox
```

This stops the VM (if running), deletes the Lima instance, and removes the
session from the daemon's database.

## CLI Reference

All CLI commands accept `--socket <path>` to override the daemon socket location.

| Command | Description |
|---------|-------------|
| `sandbox create [--name NAME] [--cpus N] [--memory MB] [--disk GB] [--template PATH]` | Create and boot a new sandbox VM |
| `sandbox ps` | List all sandbox sessions |
| `sandbox ls` | Alias for `ps` |
| `sandbox start <name-or-id>` | Start a stopped sandbox |
| `sandbox stop <name-or-id>` | Stop a running sandbox |
| `sandbox rm <name-or-id>` | Remove a sandbox (stops if running) |

## Build

```sh
make build       # cargo build --workspace
make test        # cargo test --workspace
make test-e2e    # run E2E test suite (pytest)
make clean       # cargo clean
```

## Project layout

```
claude-sandbox/
  docs/              design docs, session plan
  sandboxd/          Rust cargo workspace
    sandboxd/        daemon binary
    sandbox-cli/     CLI binary (produces `sandbox`)
    sandbox-core/    shared library
    sandbox-guest/   VM-side vsock listener
  tests/e2e/         E2E test suite (pytest)
  networking/        gateway and proxy components
    coredns-plugin/  Go CoreDNS policy plugin
    mitmproxy/       Python mitmproxy addons
    envoy/           Envoy config templates
    gateway/         gateway container Dockerfile
```
