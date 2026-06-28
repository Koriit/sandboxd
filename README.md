# claude-sandbox

Isolated, policy-controlled Linux VMs for coding agents. Each sandbox runs in a
dedicated QEMU/KVM virtual machine managed by Lima with per-session networking,
a deny-by-default policy engine, TLS interception, and workspace provisioning.

## Architecture

```
CLI (sandbox) --> Unix socket --> Daemon (sandboxd) --> Lima/QEMU VMs
                                       |
                                       v
                              Docker bridge (per-session)
                                       |
                                       v
                              Gateway container
                              (Envoy, mitmproxy, CoreDNS)
```

- **CLI** (`sandbox`) communicates with the daemon over a Unix domain socket.
- **Daemon** (`sandboxd`) manages session lifecycle, networking orchestration, and
  exposes an HTTP API.
- **Per-session networking** uses a dedicated Docker bridge and gateway container
  running Envoy proxy, mitmproxy for TLS interception, and CoreDNS.
- **Guest agent** runs inside each VM for command execution and file transfer.
- **SQLite** session store tracks active sessions and their configuration.

> The diagram above shows the Linux substrate (gateway container on the host's Docker, per-session host Docker bridge). On Apple-Silicon macOS the same components run inside a persistent gateway Lima VM reached over a forwarded Docker socket, and per-session VMs attach to `socket_vmnet` L2 segments instead of a host Docker bridge — see [Networking](docs/concepts/networking.md#macos-networking-topology).

## Crates

| Crate | Purpose |
|-------|---------|
| `sandbox-core` | Shared library: backends (Lima/container), session store, policy, events, guest protocol |
| `sandboxd` | Daemon binary: HTTP API on Unix socket, session lifecycle, networking orchestration |
| `sandbox-cli` | CLI binary (`sandbox`, also installed as `git-remote-sandbox`): session management, exec, file transfer, policy |
| `sandbox-guest` | Guest agent binary (runs inside VM/container): command execution, file transfer |
| `sandbox-route-helper` | Privileged setcap binary: installs the default route inside a container netns on behalf of an authorized caller |
| `sandbox-event-emitter` | Shared lib used by both nft-loggers (JSONL writer + record types) |
| `sandbox-nft-deny-logger` | Gateway-container binary: emits `deny` records (TCP DNAT + UDP NFLOG) |
| `sandbox-nft-allow-logger` | Gateway-container binary: audits allowed UDP flows via NFCT |

## Prerequisites

**Linux x86_64:**

- KVM access
- Docker 24.0+
- Lima 2.1+
- QEMU 8.0+ with OVMF
- Rust 1.88+

**Apple-Silicon macOS:**

- macOS on Apple Silicon (arm64); Intel Macs are not supported
- Lima, `socket_vmnet`, and QEMU (`brew install lima socket_vmnet qemu`)
- Docker is provisioned *inside* the gateway VM by the installer — no host Docker Desktop is required
- Rust 1.88+

On macOS, sandboxd does not run the gateway directly on the host. The substrate is a persistent daemon-owned Lima VM (`sandboxd-gateway`) that hosts every session's gateway container, plus a pool of `socket_vmnet` daemons that provide each full-backend session VM its own isolated L2 segment. See [Networking](docs/concepts/networking.md#macos-networking-topology) for the topology.

See `docs/` for detailed installation and configuration instructions.

## Quick start

```bash
make build
sandboxd/target/debug/sandboxd &
sandbox create --name my-sandbox
sandbox exec my-sandbox -- echo "hello from sandbox"
sandbox rm my-sandbox
```

## Dev environment setup

Before running `make test-integration` or any of the `make test-e2e*`
targets on a fresh checkout, run:

```bash
make setup-dev-env
```

This is a one-shot, idempotent operator entry point that installs the
cap'd `sandbox-route-helper` binaries, writes `/etc/sandboxd/users.conf`,
configures `/etc/qemu/bridge.conf`, and ensures `qemu-bridge-helper` is
setuid. Re-running on a configured host prints `✓ already configured`
and invokes no `sudo`. See `docs/start/installation.md` for details.

## Build and test

```bash
make build                  # cargo build --workspace
make test                   # hermetic unit tests (~5s, no Docker/Lima/nft)
make test-integration       # integration tests (requires Docker + cap'd route helper)
make test-e2e-container     # PR-time E2E: container backend only (~5-10 min)
make test-e2e-matrix        # full E2E matrix: Lima + container (~30-45 min, needs /dev/kvm)
make test-e2e               # back-compat alias for test-e2e-matrix
make gateway-image          # build gateway container
make lite-image             # build lite-mode container image
make clean                  # cargo clean
```

`make test-integration` rebuilds the `sandbox-gateway` image and runs
every test named `integration_*` across the workspace. These include
the gateway-container lifecycle tests and the policy-compiler
validator tests that feed the compiler's outputs through the real
consumers (`nft -c` for the ruleset, `envoy --mode validate` for the
bootstrap + listener). The `integration` nextest profile
(`sandboxd/.config/nextest.toml`) selects them via the name prefix;
the default profile filters them out, so they never run under the
default `make test` path.

## Project structure

```
sandboxd/            Rust workspace (8 crates)
networking/          Gateway container (Envoy, mitmproxy, CoreDNS, nft-loggers)
tests/e2e/           Python E2E test suite (pytest)
docs/                Project documentation
```

## Documentation

See the `docs/` directory for detailed documentation:

- [Installation](docs/start/installation.md)
- [Quickstart](docs/start/quickstart.md)
- [Architecture](docs/concepts/architecture.md)
- [Networking](docs/concepts/networking.md)
- [Policy model](docs/concepts/policy-model.md)
- [Workspaces](docs/concepts/workspaces.md)
- [CLI reference](docs/reference/cli.md)
- [HTTP API reference](docs/reference/http-api.md)
- [Hardening](docs/guides/hardening.md)
- [Troubleshooting](docs/guides/troubleshooting.md)
