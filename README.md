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

## Crates

| Crate | Purpose |
|-------|---------|
| `sandbox-core` | Shared library: session types, CA management, gateway/network/policy management, Lima VM management, session store |
| `sandbox-cli` | CLI binary (`sandbox`): create/manage sessions, execute commands, file transfer, policy management |
| `sandboxd` | Daemon binary: HTTP API on Unix socket, session lifecycle, networking orchestration |
| `sandbox-guest` | Guest agent binary (runs inside VM): command execution, file transfer |

## Prerequisites

- Linux x86_64 with KVM access
- Docker 24.0+
- Lima 2.1+
- QEMU 8.0+ with OVMF
- Rust 1.85+

See `docs/` for detailed installation and configuration instructions.

## Quick start

```bash
make build
sandboxd/target/debug/sandboxd &
sandbox create --name my-sandbox
sandbox exec my-sandbox -- echo "hello from sandbox"
sandbox rm my-sandbox
```

## Build and test

```bash
make build            # cargo build --workspace
make test             # unit tests (~444 tests, ~5s)
make test-integration # integration tests (requires Docker + Lima)
make test-e2e         # full E2E suite (boots real VMs, ~45 min)
make gateway-image    # build gateway container
make clean            # cargo clean
```

## Project structure

```
sandboxd/           Rust workspace (4 crates)
networking/          Gateway container (Envoy, mitmproxy, CoreDNS)
tests/e2e/           Python E2E test suite (pytest)
docs/                Project documentation
```

## Documentation

See the `docs/` directory for detailed documentation:

- [Architecture](docs/architecture.md)
- [Installation](docs/installation.md)
- [CLI reference](docs/cli-reference.md)
- [Networking](docs/networking.md)
- [Policy engine](docs/policy.md)
- [Workspaces](docs/workspaces.md)
- [Hardening](docs/hardening.md)
- [Troubleshooting](docs/troubleshooting.md)
