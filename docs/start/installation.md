---
title: Installation
description: Install sandboxd on Linux via the signed install.sh, with a developer-mode fallback for repository contributors.
---

This guide covers two install paths:

- [**Operator install**](#operator-install-curl--bash) — the supported production install via the signed `install.sh` hosted on GitHub Pages. This is what you want unless you're building sandboxd from source.
- [**Developer install**](#developer-install-make-setup-dev-env) — for contributors who want to build the daemon from source and run it as their own user. Same machine-level prerequisites; different artifact layout.

If you want the fast path through create/exec/ssh once installed, see [Quickstart](/start/quickstart/).

## System requirements

| Requirement | Minimum | Notes |
|-------------|---------|-------|
| OS | Linux (x86_64 or aarch64) | Tested on Ubuntu 22.04/24.04 |
| Linux kernel | 5.8+ | `sandbox-route-helper` needs `pidfd_open(2)` (5.3+) and `setns(pidfd, ...)` (5.8+) |
| KVM | `/dev/kvm` accessible | Required for hardware-accelerated VMs |
| Docker | 24.0+ | For gateway containers and networking |
| Lima | 2.1+ | VM management (`limactl` must be on PATH); skippable at runtime if you only use [lite mode](/guides/lite-mode/) |
| QEMU | 8.0+ | `qemu-system-x86` with OVMF firmware |
| `setcap`, `jq`, `curl` | any recent | `install.sh` probes for all three |
| Rust | 1.88+ (stable) | Developer install only — for building from source |
| Go | 1.22+ | Developer install only — for the CoreDNS policy plugin |
| Python | 3.12+ | Developer install only — for E2E tests |

Sections below cover the prerequisites in detail. If `install.sh` finds any missing it will refuse and print the exact package names per detected distro.

## Operator install (`curl | bash`)

The signed installer lives at `https://Koriit.github.io/sandboxd/install.sh`. It is POSIX-shell, fully idempotent, and re-runnable.

```bash
curl -fsSL https://Koriit.github.io/sandboxd/install.sh | bash
```

This walks 24 steps: prereq probe, sigstore-verified tarball download, binary install, `sandbox` system-user create, `setcap` on the route helper, `setuid` on `qemu-bridge-helper`, `docker load` of the gateway image, and `systemd` unit install. Every privileged step uses `sudo -k`. A re-run on an already-installed host detects each desired end-state and logs `action=skip`.

After install, finish the two follow-up steps the installer prints:

```bash
# 1. Activate sandbox-group membership in your current shell.
newgrp sandbox    # or log out and back in

# 2. Start the daemon under systemd.
sudo systemctl enable --now sandboxd

# 3. Verify the install.
sandbox doctor
```

### Variants

```bash
# Pin a specific release.
curl -fsSL https://Koriit.github.io/sandboxd/install.sh | bash -s -- --version 1.1.0

# Air-gapped: the operator already has the tarball locally.
curl -fsSL https://Koriit.github.io/sandboxd/install.sh | bash -s -- \
    --from /path/to/sandboxd-1.1.0-x86_64-unknown-linux-gnu.tar.gz

# Fully offline: pre-staged tarball + sigstore bundle, no network at all.
curl -fsSL https://Koriit.github.io/sandboxd/install.sh | bash -s -- \
    --from /path/to/sandboxd-1.1.0-x86_64-unknown-linux-gnu.tar.gz \
    --cosign-bundle /path/to/sandboxd-1.1.0-x86_64-unknown-linux-gnu.tar.gz.sigstore

# Non-interactive (no prompts).
curl -fsSL https://Koriit.github.io/sandboxd/install.sh | bash -s -- --yes
```

Full flag list: `--version`, `--from`, `--cosign-bundle`, `--source-url`, `--yes`, `--verbose`, `--quiet`, `--no-color`, `--help`.

### What it installs

| Artifact | Destination |
|---|---|
| `sandboxd` binary | `/usr/local/bin/sandboxd` |
| `sandbox` CLI | `/usr/local/bin/sandbox` |
| `sandbox-route-helper` | `/usr/local/libexec/sandboxd/sandbox-route-helper` (with `cap_net_admin,cap_sys_admin=eip`) |
| systemd unit | `/etc/systemd/system/sandboxd.service` |
| `users.conf` | `/etc/sandboxd/users.conf` |
| Bridge authorization | `allow sb-*` appended to `/etc/qemu/bridge.conf` |
| Gateway image | `sandbox-gateway:<version>` loaded into Docker |
| Daemon state dir | `/var/lib/sandbox/` (owner `sandbox:sandbox`, mode `0750`) |
| Install state record | `/var/lib/sandbox/.install-state.json` |
| Install log | `/var/log/sandbox-install.log` |

The `sandbox` system user is created (if not already present); the invoking operator (from `$SUDO_USER`) is added to the `sandbox` group.

### Trust chain

The install chain is auditable at every link:

1. **TLS to GitHub Pages** delivers `install.sh` (standard `*.github.io` TLS).
2. **`install.sh` pins cosign** at version `v2.4.1` by sha256. The script downloads cosign, verifies the binary, and refuses on mismatch.
3. **cosign verifies the release tarball's sigstore bundle** against the project's GitHub Actions OIDC identity (`https://github.com/Koriit/sandboxd/.github/workflows/release.yml`). Any other signing identity is rejected.
4. **`install.sh` re-checks each artifact's sha256** against the tarball's `MANIFEST` file.

For an air-gapped review pass, fetch the script first and read it before piping to `bash`:

```bash
curl -fsSL https://Koriit.github.io/sandboxd/install.sh | less
```

### Uninstall

```bash
curl -fsSL https://Koriit.github.io/sandboxd/uninstall.sh | bash -s -- --yes
```

This removes the binaries, systemd unit, and any install-time changes recorded in `/var/lib/sandbox/.install-state.json` (only reverts changes the installer made). State at `/var/lib/sandbox/` and the `sandbox` user are preserved; add `--purge` to also remove them.

```bash
curl -fsSL https://Koriit.github.io/sandboxd/uninstall.sh | bash -s -- --purge --yes
```

`--force` overrides the "active sessions exist" refusal; resources may leak. `--purge` without `--yes` requires typing `PURGE` to confirm.

## Developer install (`make setup-dev-env`)

For contributors building sandboxd from source. This path runs the daemon as your own user (not the system `sandbox` user) with state under `~/.local/share/sandboxd/`. Helper installation, bridge-conf, `users.conf`, and the setuid step are folded into `make setup-dev-env`. See [Developer install — build from source](#developer-install--build-from-source) below for the full walkthrough. The two paths can coexist on the same host, but should not run two daemons in parallel: see [Dev-mode vs operator-mode coexistence](#dev-mode-vs-operator-mode-coexistence) below before mixing them.

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

The QEMU bridge helper (`qemu-bridge-helper`) is a setuid binary that creates TAP devices and attaches them to bridge networks. It must be installed and configured for sandbox networking to work. The operator-install path handles this for you; the steps below are the manual equivalent for the developer path.

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

sandboxd creates a fresh Docker-managed bridge per session (named `sb-{session_id}`), so `qemu-bridge-helper` needs permission to attach TAP devices to any bridge name. `allow all` is the dev-box convenience; the operator-install path narrows this to `allow sb-*` (production scope).

## Docker setup

Docker runs the per-session gateway containers and, under the lite-mode backend, the session container itself. Use standard (default-hardened) Docker.

### Install Docker

```bash
curl -fsSL https://get.docker.com | sh
sudo usermod -aG docker $USER
```

Log out and back in for the group change to take effect.

### A note on rootless Docker

Rootless Docker is supported, but with caveats on the lite-mode (container) backend. Userns-remap shifts ownership of bind-mounted workspace files in ways that break lite-mode's workspace UID-alignment contract, so by default the daemon refuses container-backend session-create on rootless hosts. Operators who accept they are operating outside the supported envelope can opt in per-invocation with `sandbox create --force-rootless-docker`. Lima-backed sessions are unaffected — workspace state lives inside the VM rather than in a host bind-mount, so the gateway container runs cleanly on rootless Docker.

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

## Developer install — build from source

Skip this section unless you are building sandboxd from a local checkout. For an operator install, see [Operator install (`curl | bash`)](#operator-install-curl--bash) above.

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

Two one-time steps are required before the daemon starts: a system-wide config file at `/etc/sandboxd/users.conf`, and a privileged helper binary at `/usr/local/libexec/sandboxd/sandbox-route-helper`. Both stay in place across upgrades. The [operator install](#operator-install-curl--bash) handles both for you; this section documents the manual equivalent used by the developer path.

### One-shot setup: `make setup-dev-env`

The repository ships a make target that runs every per-host install/configure step the project needs. It prints `[sudo] <exact change>` before each privileged operation so you see what is about to be modified before authenticating, and is fully idempotent — re-running on an already-configured host prints `+ already configured` for every step and invokes no `sudo`.

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
  "_schema_version": 1,
  "subnets": [
    { "cidr": "<CIDR>", "allow_users": ["sandbox", "<unix-username>", "..."] }
  ]
}
```

Multiple subnet entries are allowed; each binds one CIDR pool to a list of allowed Unix usernames. The daemon resolves `allow_users` entries to numeric uids via `getpwnam_r` at startup, so renaming a user with `usermod` takes effect on the next daemon start without editing this file.

**Two conventions to know if you edit this file by hand:**

- **`_schema_version`** is the integer-valued schema marker the config migration framework reads. The field is optional — an absent or `0` value is treated as a pre-V001 file and brought up to date by the framework on the next daemon start (V001 stamps `_schema_version: 1`). Hand-edited files that already match the post-V001 shape should include `_schema_version: 1` at the top; an unknown variant (e.g. typo `_shema_version`) is rejected with a parser error naming the bad key verbatim.
- **`"sandbox"` in every pool's `allow_users`** is the system-user convention that pairs with the route helper's pair-membership check: every pool lists `"sandbox"` alongside the operator name (e.g. `["sandbox", "alice"]`). The V001 migration auto-prepends `"sandbox"` to each pool when it runs; if you write the file by hand, include it. The name is harmlessly unresolvable on dev boxes that have not provisioned a `sandbox` system account — the route helper treats unresolvable `allow_users` entries as non-matches without failing the rest of the pair check.

For a single-user dev install, `make setup-users-conf` renders `contrib/users.conf.example` with `$USER` substituted in. The example ships **two pools**:

| CIDR | Purpose | Read by |
|------|---------|---------|
| `10.209.0.0/20` | Production pool | The operator's `sandboxd` reading the canonical `/etc/sandboxd/users.conf`. The daemon's `find_subnet_by_uid` lookup returns this entry first since it appears first in the array. |
| `10.220.0.0/20` | E2E test pool | The e2e test daemon, which `tests/e2e/conftest.py` launches with `SANDBOX_USERS_CONF` pointing at a tempfile users.conf containing only this entry. The production `sandbox-route-helper` continues reading the canonical file — which lists both pools — so authorization for the test pool's gateway IP succeeds without weakening the [`SANDBOX_USERS_CONF` privilege boundary](#privilege-boundary-sandbox_users_conf-is-feature-gated). |

The two pools are non-overlapping `/20` blocks. Disjoint CIDRs let the CIDR-scoped reaper distinguish test-daemon resources from production-daemon resources at startup, so a `make test-e2e` run never touches a live production session.

The manual equivalent of `make setup-users-conf`:

```bash
sudo mkdir -p /etc/sandboxd
sudo tee /etc/sandboxd/users.conf > /dev/null <<EOF
{
  "_schema_version": 1,
  "subnets": [
    { "cidr": "10.209.0.0/20", "allow_users": ["sandbox", "$USER"] },
    { "cidr": "10.220.0.0/20", "allow_users": ["sandbox", "$USER"] }
  ]
}
EOF
sudo chown root:root /etc/sandboxd/users.conf
sudo chmod 0644 /etc/sandboxd/users.conf
```

The shell-redirect through `sudo tee` is intentional — `sudo echo ... > file` does not work because the shell opens the file before `sudo` is involved.

##### Upgrade path for hosts installed before the dual-pool layout

Hosts that ran `make setup-dev-env` before the dual-pool layout landed carry a single-pool canonical file (production pool only). Re-running `make setup-users-conf` on such a host detects the missing test pool and idempotently appends it via a `python3` JSON round-trip; operator-added entries are preserved untouched. A second invocation prints `+ already configured` and invokes no `sudo`. `contrib/users.conf.example` is the source of truth for the layout — diff against it if you want to confirm what `make setup-users-conf` will install on a fresh host.

#### `SANDBOX_USERS_CONF` env-var override

The daemon honors a `SANDBOX_USERS_CONF` environment variable that overrides the canonical path. The e2e test harness uses it to point the test daemon at a tempfile listing only the test pool (`10.220.0.0/20`); production operators must not set it. The route helper additionally **does not honor this env var** in production builds — see [sandbox-route-helper](#sandbox-route-helper) below for the privilege rationale.

### sandbox-route-helper

`sandbox-route-helper` is a small privileged binary, built alongside the daemon, that installs the per-session default route inside container netns'es on the daemon's behalf. The production install path is `/usr/local/libexec/sandboxd/sandbox-route-helper` (per FHS § 4.7: libexec is for non-user-facing helper binaries that other binaries invoke directly). The binary must carry both `cap_sys_admin` (for `setns(2)` into the container netns) and `cap_net_admin` (for `RTM_NEWROUTE`, raised to the ambient set before the helper execs `ip(8)`):

```bash
sudo install -D -m 0755 \
    sandboxd/target/release/sandbox-route-helper \
    /usr/local/libexec/sandboxd/sandbox-route-helper
sudo setcap 'cap_net_admin,cap_sys_admin=eip' /usr/local/libexec/sandboxd/sandbox-route-helper
```

The `=eip` flags put both caps in Permitted **and** Inheritable; the Inheritable bit is what lets the helper raise `CAP_NET_ADMIN` to the ambient set so the spawned `ip(8)` inherits it. Under rootless Docker the previous `cap_sys_admin+ep`-only install also worked because `CAP_SYS_ADMIN` in the parent userns implicitly grants every cap inside child userns'es; under rootful Docker the netns is in init userns directly and that promotion does not happen, so `CAP_NET_ADMIN` must be wired through explicitly.

If you only built in debug mode, swap `release` for `debug` in the source path. The capabilities must be re-applied after every reinstall — `setcap` attributes do not survive a binary copy. The make target `make install-route-helper-prod-cap` automates both steps and is stamp-driven on the source's mtime so a re-run after an unchanged build is a no-op.

Verify the capabilities are set:

```bash
getcap /usr/local/libexec/sandboxd/sandbox-route-helper
# Expected: /usr/local/libexec/sandboxd/sandbox-route-helper cap_net_admin,cap_sys_admin=eip
```

Do **not** make this binary setuid root. The capability approach is intentional: the daemon stays unprivileged, and the helper acquires only the kernel permissions it needs (joining a container's network namespace via `pidfd_open(2)` + `setns(2)`, and installing the default route inside it). The helper is invoked by sandboxd, not by operators directly, and it enforces a **pair-membership check** against `users.conf` before any namespace mutation: both the calling process's uid (the daemon, via `getuid`) and the operator name passed in `--for-user` (which the daemon reads from `SO_PEERCRED` on its accepted Unix socket) must appear in the same pool's `allow_users`. Operators with no `allow_users` entry cannot run sessions even if they can execute the helper, and a compromised daemon cannot invent operator names that are not already paired with its own runtime uid. See [Audit log](#audit-log) below for where every allow/deny decision is recorded.

#### Audit log

The route helper writes a JSON-Lines record to disk on **every** invocation — both allowed and denied — so operators triaging a deny, or just confirming that authorization is being audited, have a forensic trail.

**Location.** The helper resolves the audit-log path in this order:

1. `$XDG_RUNTIME_DIR/sandboxd/route-helper-audit.log` (typically `/run/user/$UID/sandboxd/route-helper-audit.log`).
2. `$HOME/.local/share/sandboxd/route-helper-audit.log` (fallback when `XDG_RUNTIME_DIR` is unset).
3. `/tmp/sandboxd/route-helper-audit.log` (last-resort fallback when neither variable is set, e.g. in containerised environments without `HOME`).

The parent directory is created on the first invocation if it does not exist.

**Format.** One JSON object per line; fields:

| Field | Type | Notes |
|-------|------|-------|
| `ts` | RFC 3339 timestamp, millisecond precision (`Z` suffix) | Wall-clock time the record was written. |
| `decision` | `"allowed"` or `"denied"` | The helper's authorization outcome. |
| `reason` | string | Present only on `decision: "denied"`. Short tag — e.g. `"pair-check failed"`, `"gateway-ip not in any subnet"`. |
| `caller` | string | Username resolved from the helper's own `getuid()` (the daemon's runtime uid). |
| `for_user` | string | Value of the helper's `--for-user` argument (the operator name the daemon asserts). |
| `pool` | string (CIDR) | The matched subnet, e.g. `"10.209.0.0/20"`. Omitted when the gateway IP did not match any configured subnet (i.e. `reason: "gateway-ip not in any subnet"`). |
| `gateway_ip` | string | The gateway IP the helper was asked to install a route to. |
| `pid` | integer | The helper's own PID. |

Example lines:

```jsonl
{"ts":"2026-05-11T14:23:09.123Z","decision":"allowed","caller":"alice","for_user":"alice","pool":"10.209.0.0/20","gateway_ip":"10.209.0.2","pid":12345}
{"ts":"2026-05-11T14:23:11.477Z","decision":"denied","reason":"pair-check failed","caller":"alice","for_user":"bob","pool":"10.210.0.0/20","gateway_ip":"10.210.0.2","pid":12346}
```

**Write-failure asymmetry.** The two paths handle audit-log write failures differently:

- **Allow path.** A failed audit-log write is logged to stderr but otherwise swallowed; the helper still installs the route and exits success. Audit-log infrastructure failures (disk full, missing parent dir, ENOSPC) must not cause a denial-of-service to session creation — routing availability wins, and the missing record surfaces as a daemon-side stderr line for the operator to triage.
- **Deny path.** A failed audit-log write is **escalated**: the helper logs to stderr **and** exits with the deny exit code (`1`). The deny itself already happened — the escalation here ensures the forensic record does not evaporate silently when an attacker (or a misconfigured environment) tries to censor a deny by making the log unwritable.

#### Privilege boundary: `SANDBOX_USERS_CONF` is feature-gated

The route helper runs with `cap_net_admin,cap_sys_admin=eip`. Honoring an attacker-controlled environment variable to redirect its authorization-config read inside that privileged binary would be a local privilege escalation: any user who can exec the helper could point it at a `users.conf` they own, granting themselves arbitrary `allow_users` entries. The production build (no Cargo features) therefore **cannot consult `SANDBOX_USERS_CONF`** — it always reads `/etc/sandboxd/users.conf`. The route-helper integration tests use a separate test-feature build (`cargo build --features test-env-override`) installed at `/usr/local/libexec/sandboxd-test/`, which the daemon never invokes; this build does honor the env var so tests can drive a tempfile config they own.

The daemon itself continues to honor `SANDBOX_USERS_CONF` unconditionally because the daemon is not the privilege boundary — only the cap'd helper is.

## Dev-mode vs operator-mode coexistence

The two install paths produce different layouts:

| Artifact | Developer install (`make setup-dev-env`) | Operator install (`install.sh`) |
|---|---|---|
| `sandboxd` binary | Run from `sandboxd/target/release/sandboxd` | `/usr/local/bin/sandboxd` |
| `sandbox` CLI | Run from `sandboxd/target/release/sandbox` | `/usr/local/bin/sandbox` |
| `sandbox-route-helper` | `/usr/local/libexec/sandboxd/sandbox-route-helper` | Same path |
| systemd unit | Not installed (run by hand) | `/etc/systemd/system/sandboxd.service` |
| State dir | `~/.local/share/sandboxd/` | `/var/lib/sandbox/` |
| Socket | `$XDG_RUNTIME_DIR/sandboxd/sandboxd.sock` | `/run/sandbox/sandboxd.sock` |
| `sandbox` user | Not created | Created |
| `users.conf` | `["sandbox", "$USER"]` | `["sandbox", "<invoking-operator>"]` |
| `bridge.conf` | `allow all` (dev convenience) | `allow sb-*` (production scope) |

`install.sh`'s pre-existing-install detection refuses if `/usr/local/bin/sandboxd` exists. The developer's daemon under `sandboxd/target/release/sandboxd` is not detected by that check, so `install.sh` runs successfully on a dev box — but the two daemons should not run at the same time. To migrate from the developer path to the operator install: stop the dev daemon, optionally copy `~/.local/share/sandboxd/sessions.db` to `/var/lib/sandbox/sessions.db` (manual operation, no automated migration yet), then run `install.sh` and `sudo systemctl enable --now sandboxd`.

## First run

After install, drive sandboxd through the CLI:

```bash
# Create a session.
sandbox create --name hello

# Verify.
sandbox ps

# Run a command.
sandbox exec hello -- uname -a

# Clean up.
sandbox rm hello
```

Operator-install: the CLI talks to `/run/sandbox/sandboxd.sock` (via the `sandbox` group). Developer install: the CLI talks to `$XDG_RUNTIME_DIR/sandboxd/sandboxd.sock` after you start the daemon (`sandboxd/target/debug/sandboxd`).

On the first run, Lima downloads the Ubuntu 24.04 cloud image (about 700 MB). This is cached for subsequent sessions. The full create process (image download, VM boot, guest agent installation, networking setup) takes 2 to 5 minutes on first run, under 1 minute on subsequent runs with a cached image.

## Diagnosing problems: `sandbox doctor`

After installation, run `sandbox doctor` to verify every load-bearing invariant in one call. The command is the single entry point for "is my install healthy?" diagnosis. It checks:

- the daemon is running (systemd in production, socket-connect in dev mode);
- the CLI and daemon report the same `CARGO_PKG_VERSION`;
- the caller is in the `sandbox` group (or, in dev mode, that no `sandbox` group exists);
- the socket has the expected mode;
- the daemon's uid can read+write `/dev/kvm`;
- the gateway and lite container images are loaded (the lite image is built on first use);
- the route-helper has its setcap capability;
- the state directory exists with the expected mode + ownership;
- `users.conf` parses and lists the daemon's user;
- no running session is on a drift'd guest protocol;
- no orphan substrate resources are leaking host-wide.

Exit codes follow the `git`/`make` convention: `0` for clean, `1` for "at least one check failed", `2` for "doctor itself could not run". Add `--verbose` to see every check (passes are suppressed by default so the failure list is the actionable surface). Each failure carries a `hint:` line operators can copy-paste — usually a single shell command that fixes it.

In dev mode (no `sandbox` system user, daemon run by hand), checks specific to the system-service shape (group membership, socket-mode strictness, state-dir ownership) degrade to informational skips so the dev workflow still passes a clean run.

## Next steps

- [Quickstart](/start/quickstart/) for the condensed path through create/exec/ssh.
- [CLI reference](/reference/cli/) for every command and flag.
- [Troubleshooting](/guides/troubleshooting/) for common setup errors and how to diagnose them.
