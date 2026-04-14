# Installation

This guide covers system requirements, dependency installation, and building claude-sandbox from source.

## System requirements

| Requirement | Minimum | Notes |
|-------------|---------|-------|
| OS | Linux (x86_64) | Tested on Ubuntu 22.04/24.04 |
| KVM | `/dev/kvm` accessible | Required for hardware-accelerated VMs |
| Docker | 24.0+ | For gateway containers and networking |
| Lima | 2.1+ | VM management (`limactl` must be on PATH) |
| Rust | 1.85+ (stable) | For building from source |
| QEMU | 8.0+ | `qemu-system-x86` with OVMF firmware |
| Go | 1.22+ | For the CoreDNS policy plugin |
| Python | 3.12+ | For E2E tests only |

## KVM setup

KVM provides hardware-accelerated virtualization. Without it, VMs fall back to software emulation and are unusably slow.

### Install QEMU and KVM

```bash
# Ubuntu/Debian
sudo apt install -y qemu-system-x86 qemu-utils ovmf

# Fedora
sudo dnf install -y qemu-system-x86 qemu-img edk2-ovmf

# Arch
sudo pacman -S qemu-full edk2-ovmf
```

### Verify KVM access

```bash
ls -la /dev/kvm
```

Expected output shows the device with group `kvm`:

```
crw-rw---- 1 root kvm 10, 232 ... /dev/kvm
```

If the device exists but your user cannot access it:

```bash
sudo usermod -aG kvm $USER
```

Log out and back in (or run `newgrp kvm`) for the group change to take effect.

### Verify KVM works

```bash
# Quick test -- this should print KVM acceleration info
qemu-system-x86_64 -accel help 2>&1 | grep -i kvm
```

If KVM is not available, check that your CPU supports hardware virtualization (Intel VT-x or AMD-V) and that it is enabled in BIOS/UEFI settings.

## Docker setup

Docker is used for the per-session gateway containers that run the networking pipeline (Envoy, mitmproxy, CoreDNS). Both standard Docker (with `docker` group membership) and rootless Docker are supported.

### Install Docker

```bash
curl -fsSL https://get.docker.com | sh
sudo usermod -aG docker $USER
```

Log out and back in for the group change to take effect.

For rootless Docker, follow the [Docker rootless mode documentation](https://docs.docker.com/engine/security/rootless/). Rootless Docker uses a user namespace and stores its data under `~/.local/share/docker` with the socket at `$XDG_RUNTIME_DIR/docker.sock`.

### Verify Docker

```bash
docker info
```

This should print Docker version and runtime information without `sudo`. If you get a permission error, the group change has not taken effect yet.

## Lima installation

Lima manages the QEMU VMs used by claude-sandbox. The `limactl` binary must be on your PATH.

### Install from release tarball

```bash
VERSION=$(curl -fsSL https://api.github.com/repos/lima-vm/lima/releases/latest \
  | grep tag_name | cut -d'"' -f4)
curl -fsSL \
  "https://github.com/lima-vm/lima/releases/download/${VERSION}/lima-${VERSION#v}-Linux-x86_64.tar.gz" \
  | tar xz -C ~/.local
```

For aarch64 hosts, replace `x86_64` with `aarch64` in the URL.

### Verify Lima

```bash
limactl --version
```

If `limactl` is not found, ensure `~/.local/bin` is in your PATH:

```bash
export PATH="$HOME/.local/bin:$PATH"
```

Add this to your shell profile (`~/.bashrc` or `~/.zshrc`) to make it permanent.

See [lima-linux-install.md](lima-linux-install.md) for a more detailed Lima setup guide, including shell completion.

## Rust toolchain

The sandbox is written in Rust. You need the stable toolchain to build from source.

### Install Rust via rustup

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source $HOME/.cargo/env
```

### Verify Rust version

```bash
rustc --version
# Should be 1.85.0 or newer
```

## Building from source

### Clone the repository

```bash
git clone https://github.com/anthropics/claude-sandbox.git
cd claude-sandbox
```

### Build the Rust workspace

```bash
make build
# Equivalent to: cd sandboxd && cargo build --workspace
```

This produces three binaries in `sandboxd/target/debug/`:

| Binary | Description |
|--------|-------------|
| `sandboxd` | The daemon |
| `sandbox` | The CLI |
| `sandbox-guest` | The VM-side guest agent |

### Build the gateway container image

```bash
make gateway-image
# Equivalent to: docker build -t sandbox-gateway -f networking/gateway/Dockerfile networking/
```

The gateway image bundles Envoy, mitmproxy, CoreDNS, and the policy plugin into a single container.

### Privilege model

sandboxd runs as a regular user -- it does **not** require root or sudo. The user running the daemon needs membership in two groups:

- **`docker`** -- to manage Docker containers and networks.
- **`kvm`** -- for hardware-accelerated virtualization via `/dev/kvm`.

All privilege escalation is handled by the underlying tools (Docker, qemu-bridge-helper) rather than the daemon itself.

### qemu-bridge-helper setup

The QEMU bridge helper (`qemu-bridge-helper`) is a setuid binary that creates TAP devices and attaches them to bridge networks. It must be installed and configured for sandbox networking to work.

**Verify the binary exists and is setuid:**

```bash
ls -la /usr/lib/qemu/qemu-bridge-helper
# Expected: -rwsr-xr-x ... /usr/lib/qemu/qemu-bridge-helper
```

If it is not setuid, set it (this is the only step that requires root):

```bash
sudo chmod u+s /usr/lib/qemu/qemu-bridge-helper
```

**Configure bridge access:**

Create `/etc/qemu/bridge.conf` if it does not exist:

```bash
sudo mkdir -p /etc/qemu
echo "allow br0" | sudo tee /etc/qemu/bridge.conf
sudo chmod 644 /etc/qemu/bridge.conf
```

The `allow br0` line permits `qemu-bridge-helper` to attach TAP devices to bridges named `br0`. sandboxd uses Docker-managed bridges (named `sb-{session_id}`), so you may also need a broader allow rule:

```bash
echo "allow all" | sudo tee /etc/qemu/bridge.conf
```

### Run tests

```bash
make test          # Unit and integration tests (cargo test)
make test-e2e      # End-to-end tests (pytest, requires running daemon)
```

`make test-e2e` automatically creates a Python virtualenv in `tests/e2e/.venv/` on first run and reinstalls dependencies when `tests/e2e/pyproject.toml` changes. No manual venv setup is needed.

## First run

### 1. Start the daemon

```bash
sandboxd/target/debug/sandboxd
```

The daemon creates its state directory at `~/.sandboxd/` (SQLite database, session data, CA certificates) and listens on `~/.sandboxd/sandboxd.sock`. No root or sudo is needed -- the daemon runs as your regular user.

To customize paths:

```bash
sandboxd/target/debug/sandboxd --socket /tmp/sandbox.sock --base-dir /tmp/sandbox-state
```

### 2. Create your first session

In a separate terminal:

```bash
sandboxd/target/debug/sandbox create --name hello
```

On first run, Lima downloads the Ubuntu 24.04 cloud image (~700 MB). This is cached for subsequent sessions. The full create process (image download, VM boot, guest agent installation, networking setup) takes 2--5 minutes on first run, under 1 minute on subsequent runs with a cached image.

### 3. Verify the session

```bash
sandbox ps
```

Expected output:

```
ID                                    NAME   STATE       AGENT        GATEWAY      CREATED
xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx  hello  running     connected    healthy      30s ago
```

### 4. Run a command

```bash
sandbox exec hello -- uname -a
```

### 5. Clean up

```bash
sandbox rm hello
```

## Troubleshooting

### "Cannot connect to sandboxd" error

The CLI cannot reach the daemon socket. Check that:

1. The daemon is running (`ps aux | grep sandboxd`).
2. The socket path matches. The default is `~/.sandboxd/sandboxd.sock`. If you started the daemon with a custom `--socket`, pass the same path to the CLI: `sandbox --socket /path/to/sock ps`.

### "Permission denied" on `/dev/kvm`

Your user is not in the `kvm` group. Run:

```bash
sudo usermod -aG kvm $USER
```

Then log out and back in. Verify with `groups` that `kvm` appears in the list.

### Lima VM fails to start

Common causes:

- **OVMF firmware missing.** Install the OVMF package for your distro (see KVM setup above).
- **Port conflict.** Another Lima instance or process is using the same port range. Check `limactl list` for stale VMs.
- **Disk space.** VM images require several GB. Ensure the Lima data directory (`~/.lima/`) has sufficient space.

### Gateway container not starting

The gateway container requires the `sandbox-gateway` Docker image. Build it with:

```bash
make gateway-image
```

If the container starts but shows as unhealthy, check the gateway logs:

```bash
sandbox logs <session> --tail 50
```

### Docker permission denied

If Docker commands fail with permission errors, ensure your user is in the `docker` group and that you have logged out and back in after adding the group:

```bash
groups | grep docker
```

If `docker` does not appear, run `sudo usermod -aG docker $USER` and log out/in again.
