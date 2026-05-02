---
title: Installation
description: Full prerequisite, dependency, and build steps for running sandboxd on Linux — KVM, Docker, Lima, QEMU, and Rust.
---

This guide covers system requirements, dependency installation, and building sandboxd from source. If you want the fast path, skim the [Quickstart](/start/quickstart/) instead.

## System requirements

| Requirement | Minimum | Notes |
|-------------|---------|-------|
| OS | Linux (x86_64) | Tested on Ubuntu 22.04/24.04 |
| Linux kernel | 5.8+ | `sandbox-route-helper` needs `pidfd_open(2)` (5.3+) and `setns(pidfd, ...)` (5.8+) |
| KVM | `/dev/kvm` accessible | Required for hardware-accelerated VMs |
| Docker | 24.0+ | For gateway containers and networking |
| Lima | 2.1+ | VM management (`limactl` must be on PATH); skippable at runtime if you only use [lite mode](/guides/lite-mode/) |
| Rust | 1.88+ (stable) | For building from source |
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
qemu-system-x86_64 -accel help 2>&1 | grep -i kvm
```

If KVM is not available, check that your CPU supports hardware virtualization (Intel VT-x or AMD-V) and that it is enabled in BIOS/UEFI settings.

### qemu-bridge-helper setup

The QEMU bridge helper (`qemu-bridge-helper`) is a setuid binary that creates TAP devices and attaches them to bridge networks. It must be installed and configured for sandbox networking to work.

Verify the binary exists and is setuid:

```bash
ls -la /usr/lib/qemu/qemu-bridge-helper
# Expected: -rwsr-xr-x ... /usr/lib/qemu/qemu-bridge-helper
```

If it is not setuid, set it (this is the only step that requires root):

```bash
sudo chmod u+s /usr/lib/qemu/qemu-bridge-helper
```

Configure bridge access. Create `/etc/qemu/bridge.conf` if it does not exist:

```bash
sudo mkdir -p /etc/qemu
echo "allow all" | sudo tee /etc/qemu/bridge.conf
sudo chmod 644 /etc/qemu/bridge.conf
```

sandboxd creates a fresh Docker-managed bridge per session (named `sb-{session_id}`), so `qemu-bridge-helper` needs permission to attach TAP devices to any bridge name. `allow all` is the simplest rule; if you want to scope it, list each session bridge explicitly or match the `sb-*` prefix via repeated `allow` lines.

## Docker setup

Docker runs the per-session gateway containers. Both standard Docker (with `docker` group membership) and rootless Docker are supported.

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

This prints Docker version and runtime information without `sudo`. If you get a permission error, the group change has not taken effect yet.

## Lima installation

Lima manages the QEMU VMs used by sandboxd. The `limactl` binary must be on your `PATH`.

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

If `limactl` is not found, ensure `~/.local/bin` is in your `PATH`:

```bash
export PATH="$HOME/.local/bin:$PATH"
```

Add this to your shell profile (`~/.bashrc` or `~/.zshrc`) to make it permanent.

### Lima on Linux — extended setup

Lima's official docs gloss over Linux-specific setup. The section above covers the essentials; the extras below are optional.

#### Minimal QEMU dependency

If you only need Lima for sandboxd, you can install the QEMU dependencies without OVMF. sandboxd still needs OVMF for its own VM firmware, so the earlier [Install QEMU and KVM](#install-qemu-and-kvm) instructions are preferred. For a Lima-only setup:

```bash
# Ubuntu/Debian
sudo apt install -y qemu-system-x86 qemu-utils

# Fedora
sudo dnf install -y qemu-system-x86 qemu-img

# Arch
sudo pacman -S qemu-full
```

#### Shell completion

Enable `limactl` tab completion in your shell.

Zsh — add to `~/.zshrc`:

```bash
eval "$(limactl completion zsh)"
```

Bash — add to `~/.bashrc`:

```bash
eval "$(limactl completion bash)"
```

Fish:

```fish
limactl completion fish | source
```

#### Test Lima directly (optional)

If you want to confirm Lima itself works before running sandboxd, start a default Ubuntu VM:

```bash
limactl start
lima
```

`limactl start` downloads the OS image and nerdctl on first run. `lima` drops you into a shell inside the VM. You do not need this step for sandboxd — sandboxd drives `limactl` directly.

## Rust toolchain

sandboxd is written in Rust. You need the stable toolchain to build from source.

### Install Rust via rustup

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source $HOME/.cargo/env
```

### Verify Rust version

```bash
rustc --version
# Should be 1.88.0 or newer
```

## Build from source

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

The gateway image bundles Envoy, mitmproxy, CoreDNS (with the policy plugin), sandbox-nft-deny-logger, and sandbox-nft-allow-logger into a single container.

### Privilege model

sandboxd runs as a regular user — it does **not** require root or sudo. The user running the daemon needs membership in two groups:

- **`docker`** — to manage Docker containers and networks.
- **`kvm`** — for hardware-accelerated virtualization via `/dev/kvm`.

All privilege escalation is handled by the underlying tools (Docker, `qemu-bridge-helper`, `sandbox-route-helper`) rather than the daemon itself. See [qemu-bridge-helper setup](#qemu-bridge-helper-setup) earlier in this page and [sandboxd configuration](#sandboxd-configuration) below for the one-time configuration.

### Run tests

Before running `make test-e2e`, complete [sandboxd configuration](#sandboxd-configuration) below — the end-to-end suite boots a real daemon, which refuses to start without `/etc/sandboxd/users.conf` and a `setcap`-installed `sandbox-route-helper`. `make test` (unit-only) does not need those steps; `make test-integration` depends on `make install-route-helper-test-cap` automatically.

```bash
make test               # Hermetic unit tests; no Docker / Lima / nft (fast)
make test-integration   # Adds out-of-process integration tests (Docker required)
make test-e2e           # End-to-end tests (pytest, requires running daemon)
```

`make test-e2e` automatically creates a Python virtualenv in `tests/e2e/.venv/` on first run and reinstalls dependencies when `tests/e2e/pyproject.toml` changes. No manual venv setup is needed.

## sandboxd configuration

Two one-time steps are required before the daemon starts: a system-wide config file at `/etc/sandboxd/users.conf`, and a privileged helper binary at `/usr/local/libexec/sandboxd/sandbox-route-helper`. Both stay in place across upgrades.

### One-shot setup: `make setup-dev-env`

The repository ships a make target that runs every per-host install/configure step the project needs. It prints `[sudo] <exact change>` before each privileged operation so you see what is about to be modified before authenticating, and is fully idempotent — re-running on an already-configured host prints `✓ already configured` for every step and invokes no `sudo`.

Multiple `[sudo]` announce lines do not mean multiple password prompts: `sudo` caches your authentication for a few minutes (the `timestamp_timeout` setting, typically 5–15 minutes on most distros), so you usually authenticate once at the first privileged step and the rest run silently. If enough time has elapsed between steps, `sudo` will re-prompt — that is normal.

```bash
make setup-dev-env
```

This composes the five sub-targets below. Each is independently runnable if you only need to (re)apply one step:

| Sub-target | What it does |
|---|---|
| `make install-route-helper-prod-cap` | Installs the cap'd production helper at `/usr/local/libexec/sandboxd/sandbox-route-helper` |
| `make install-route-helper-test-cap` | Installs the cap'd `test-env-override`-feature helper at `/usr/local/libexec/sandboxd-test/sandbox-route-helper` (used by `make test-integration`) |
| `make setup-bridge-conf` | Ensures `/etc/qemu/bridge.conf` authorizes sandbox bridges (`sb-*`); refuses to silently mutate an existing file with conflicting content |
| `make setup-users-conf` | Installs `/etc/sandboxd/users.conf` from `contrib/users.conf.example` with `$USER` substituted; leaves an existing file alone |
| `make setup-bridge-helper-setuid` | `chmod u+s /usr/lib/qemu/qemu-bridge-helper` if not already setuid |

The sections below explain what each prerequisite does and document the manual install path if you cannot or do not want to use the make target.

### users.conf

`/etc/sandboxd/users.conf` declares which Unix users may run the daemon and which CIDR pool each one allocates from. The daemon reads this file at startup, looks up its own uid in the `allow_users` lists, and uses the matching subnet's CIDR as its session-network allocation pool. If the file is missing, malformed, or contains no subnet matching the daemon's uid, sandboxd refuses to start; error messages name the offending file path.

The file is JSON, **owned by root, mode `0644`**. The daemon and the route helper additionally enforce a defensive ownership/mode check at config-load time: if the canonical path `/etc/sandboxd/users.conf` is not owned by uid 0 or carries any group/world-write bits, the loader refuses to use it. The route helper's authorization model rests on this file being immutable to non-root callers — a group-writable copy could let a local user grant themselves arbitrary `allow_users` entries.

Schema:

```json
{
  "subnets": [
    { "cidr": "<CIDR>", "allow_users": ["<unix-username>", "..."] }
  ]
}
```

Multiple subnet entries are allowed; each binds one CIDR pool to a list of allowed Unix usernames. The daemon resolves `allow_users` entries to numeric uids via `getpwnam_r` at startup, so renaming a user with `usermod` takes effect on the next daemon start without editing this file.

For a single-user dev install (one daemon user, one default pool), `make setup-users-conf` renders `contrib/users.conf.example` with `$USER` substituted in. The manual equivalent:

```bash
sudo mkdir -p /etc/sandboxd
echo '{"subnets":[{"cidr":"10.209.0.0/20","allow_users":["'"$USER"'"]}]}' \
    | sudo tee /etc/sandboxd/users.conf > /dev/null
sudo chown root:root /etc/sandboxd/users.conf
sudo chmod 0644 /etc/sandboxd/users.conf
```

The shell-redirect through `sudo tee` is intentional — `sudo echo ... > file` does not work because the shell opens the file before `sudo` is involved.

#### `SANDBOX_USERS_CONF` env-var override

The daemon honors a `SANDBOX_USERS_CONF` environment variable that overrides the canonical path. This is a test-only seam consumed by the daemon-startup integration tests; production operators must not set it. The route helper additionally **does not honor this env var** in production builds — see [sandbox-route-helper](#sandbox-route-helper) below for the privilege rationale.

### sandbox-route-helper

`sandbox-route-helper` is a small privileged binary, built alongside the daemon, that installs the per-session default route inside container netns'es on the daemon's behalf. The production install path is `/usr/local/libexec/sandboxd/sandbox-route-helper` (per FHS § 4.7: libexec is for non-user-facing helper binaries that other binaries invoke directly). The binary must carry the `cap_sys_admin` Linux capability:

```bash
sudo install -D -m 0755 \
    sandboxd/target/release/sandbox-route-helper \
    /usr/local/libexec/sandboxd/sandbox-route-helper
sudo setcap cap_sys_admin+ep /usr/local/libexec/sandboxd/sandbox-route-helper
```

If you only built in debug mode, swap `release` for `debug` in the source path. The capability must be re-applied after every reinstall — `setcap` attributes do not survive a binary copy. The make target `make install-route-helper-prod-cap` automates both steps and is stamp-driven on the source's mtime so a re-run after an unchanged build is a no-op.

Verify the capability is set:

```bash
getcap /usr/local/libexec/sandboxd/sandbox-route-helper
# Expected: /usr/local/libexec/sandboxd/sandbox-route-helper cap_sys_admin=ep
```

Do **not** make this binary setuid root. The capability approach is intentional: the daemon stays unprivileged, and the helper acquires only the kernel permission it needs (joining a container's network namespace via `pidfd_open(2)` + `setns(2)`). The helper is invoked by sandboxd, not by operators directly, and it cross-checks the caller's uid against the same `users.conf` `allow_users` list — operators with no `allow_users` entry cannot use it even if they can execute the binary.

#### Privilege boundary: `SANDBOX_USERS_CONF` is feature-gated

The route helper runs with `cap_sys_admin+ep`. Honoring an attacker-controlled environment variable to redirect its authorization-config read inside that privileged binary would be a local privilege escalation: any user who can exec the helper could point it at a `users.conf` they own, granting themselves arbitrary `allow_users` entries. The production build (no Cargo features) therefore **cannot consult `SANDBOX_USERS_CONF`** — it always reads `/etc/sandboxd/users.conf`. The route-helper integration tests use a separate test-feature build (`cargo build --features test-env-override`) installed at `/usr/local/libexec/sandboxd-test/`, which the daemon never invokes; this build does honor the env var so tests can drive a tempfile config they own.

The daemon itself continues to honor `SANDBOX_USERS_CONF` unconditionally because the daemon is not the privilege boundary — only the cap'd helper is.

## First run

### 1. Start the daemon

```bash
sandboxd/target/debug/sandboxd
```

The daemon creates its state directory at `~/.local/share/sandboxd/` (SQLite database, session data, CA certificates) and listens on `$XDG_RUNTIME_DIR/sandboxd/sandboxd.sock` (typically `/run/user/$UID/sandboxd/sandboxd.sock`). Set `$XDG_DATA_HOME` or `$XDG_RUNTIME_DIR` to customize, or use `--base-dir` and `--socket` flags. No root or sudo is needed — the daemon runs as your regular user.

To customize paths:

```bash
sandboxd/target/debug/sandboxd --socket /tmp/sandbox.sock --base-dir /tmp/sandbox-state
```

### 2. Create your first session

In a separate terminal:

```bash
sandboxd/target/debug/sandbox create --name hello
```

On the first run, Lima downloads the Ubuntu 24.04 cloud image (about 700 MB). This is cached for subsequent sessions. The full create process (image download, VM boot, guest agent installation, networking setup) takes 2 to 5 minutes on first run, under 1 minute on subsequent runs with a cached image.

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

## Next steps

- [Quickstart](/start/quickstart/) for the condensed path through create/exec/ssh.
- [CLI reference](/reference/cli/) for every command and flag.
- [Troubleshooting](/guides/troubleshooting/) for common setup errors and how to diagnose them.
