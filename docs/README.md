# claude-sandbox

claude-sandbox provides isolated, policy-controlled sandbox environments for coding agents. Each sandbox runs in a dedicated QEMU/KVM virtual machine managed by Lima, with per-session networking, traffic inspection, and configurable access policies.

## Key features

- **Isolated VMs** -- each session runs in its own QEMU/KVM virtual machine with configurable CPU, memory, and disk resources. QEMU hardening (device lockdown, seccomp) is enabled by default.
- **Per-session networking** -- every session gets a dedicated Docker bridge network with a gateway container running the proxy pipeline (Envoy, mitmproxy, CoreDNS).
- **Policy engine** -- deny-by-default network policies control which destinations a session can reach and at what level of inspection (transport, TLS-verified, or full HTTP inspection).
- **TLS interception** -- per-session CA certificates enable transparent HTTPS inspection through mitmproxy. The CA is automatically injected into the VM's trust store.
- **Workspace provisioning** -- clone git repositories, mount host directories via virtio-fs, copy files, or push/pull via git-over-vsock.
- **Guest agent** -- a lightweight agent inside each VM communicates with the host over vsock, enabling command execution, file transfer, and git operations without network access.

## Architecture

```text
sandbox (CLI)  -->  Unix socket  -->  sandboxd (daemon)
                                          |
                        +-----------------+-----------------+
                        |                 |                 |
                     Lima/QEMU     Docker bridge      SQLite store
                     (VM mgmt)     + gateway           (sessions)
                                   container
```

- **sandboxd** -- daemon managing the full sandbox lifecycle (VM creation, networking, policy distribution, guest agent communication).
- **sandbox** -- CLI tool for creating and managing sandbox sessions.
- **sandbox-guest** -- agent running inside each VM, communicating with the host over vsock.
- **sandbox-core** -- shared library with types, configuration, error handling, and session storage.
- **networking/** -- gateway container image, CoreDNS policy plugin, mitmproxy addons, and Envoy configuration templates.

See [architecture.md](architecture.md) for a detailed component overview.

## Prerequisites

- Linux with KVM support (`/dev/kvm` accessible)
- Docker 24+
- Lima 2.1+ (`limactl` on PATH)
- Rust 1.85+ (stable) for building from source
- QEMU with `qemu-system-x86` and OVMF firmware

See [installation.md](installation.md) for detailed setup instructions.

## Quickstart

### 1. Build

```bash
make build
# Produces: sandboxd/target/debug/sandboxd and sandboxd/target/debug/sandbox
```

Build the gateway container image:

```bash
make gateway-image
```

### 2. Start the daemon

```bash
sandboxd/target/debug/sandboxd
```

The daemon listens on `~/.sandboxd/sandboxd.sock` and stores state in `~/.sandboxd/`.

### 3. Create a session

```bash
# Basic session with default resources (2 CPUs, 4 GB RAM, 20 GB disk)
sandbox create --name my-sandbox

# With custom resources and a git repo
sandbox create --name dev \
    --cpus 4 --memory 8192 --disk 50 \
    --repo https://github.com/example/project.git

# With a network policy
sandbox create --name locked-down \
    --policy policy.json \
    --repo https://github.com/example/project.git
```

### 4. Check status

```bash
sandbox ps
```

```
ID                                    NAME        STATE       AGENT        GATEWAY      CREATED
a1b2c3d4-e5f6-7890-abcd-ef1234567890  my-sandbox  running     connected    healthy      2m ago
```

### 5. Run commands

```bash
# Execute a command via the guest agent
sandbox exec my-sandbox -- ls /root/workspace

# Open an interactive SSH session
sandbox ssh my-sandbox

# Run a non-interactive command via SSH
sandbox ssh my-sandbox -- uname -a
```

### 6. Copy files

```bash
# Upload a file to the VM
sandbox cp config.toml my-sandbox:/root/config.toml

# Download a file from the VM
sandbox cp my-sandbox:/root/output.log ./output.log
```

### 7. Manage the session

```bash
# Stop (preserves VM disk)
sandbox stop my-sandbox

# Start again (restores networking)
sandbox start my-sandbox

# Remove permanently
sandbox rm my-sandbox
```

## Build commands

```bash
make build         # cargo build --workspace
make test          # cargo test --workspace
make test-e2e      # E2E test suite (pytest)
make gateway-image # build the gateway container image
make clean         # cargo clean
```

## Project layout

```
claude-sandbox/
  docs/              documentation
  sandboxd/          Rust cargo workspace
    sandboxd/        daemon binary
    sandbox-cli/     CLI binary (produces `sandbox`)
    sandbox-core/    shared library
    sandbox-guest/   VM-side vsock agent
  tests/e2e/         E2E test suite (pytest)
  networking/        gateway and proxy components
    coredns-plugin/  Go CoreDNS policy plugin
    mitmproxy/       Python mitmproxy addons
    envoy/           Envoy config templates
    gateway/         gateway container Dockerfile
```

## Documentation

| Document | Description |
|----------|-------------|
| [installation.md](installation.md) | System requirements and detailed setup guide |
| [cli-reference.md](cli-reference.md) | Complete CLI command reference |
| [architecture.md](architecture.md) | Component overview and design |
| [networking.md](networking.md) | Network architecture and troubleshooting |
| [policy.md](policy.md) | Policy format and enforcement |
| [workspaces.md](workspaces.md) | Workspace modes (clone, shared mount, cp, git-over-vsock) |

## License

MIT
