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
- **Lima** for VM management
- **Docker** for the networking gateway container
- **KVM** (`/dev/kvm` accessible) for hardware-accelerated VMs
- **Go** >= 1.22 (for the CoreDNS plugin)
- **Python** >= 3.12 with pytest (for E2E tests)

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
