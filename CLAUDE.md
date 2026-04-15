# Sandbox Daemon (sandboxd)

Sandbox daemon providing isolated Linux VMs (Lima/QEMU) for coding agents.

## Project structure

- `sandboxd/` — Rust workspace (4 crates: sandbox-core, sandbox-cli, sandboxd, sandbox-guest)
- `networking/` — Gateway container (Envoy, mitmproxy, CoreDNS)
- `tests/e2e/` — Python E2E test suite (pytest)
- `docs/` — Project documentation

## Build and test

```bash
make build            # cargo build --workspace
make test             # cargo test --workspace --quiet (unit tests, ~5s)
make test-integration # integration tests (requires Docker + Lima)
make test-e2e         # full E2E suite (boots real VMs, ~30-45 min)
make gateway-image    # docker build for gateway container
```

## E2E tests

E2E tests boot real Lima/QEMU VMs and are SLOW. Individual test files take 3-10 minutes. The full suite (33 tests across 7 files) takes 30-45 minutes.

**Running E2E tests from Claude Code:**
- Never run the full suite in a foreground bash call — it will hit the 10-minute timeout.
- Use `run_in_background: true` and poll with `bash sleep 60` between status checks.
- For faster iteration, run individual test files: `python -m pytest test_m5_git_remote.py -v`
- Run a single test first before running the full suite.

```bash
# From tests/e2e/:
source .venv/bin/activate
python -m pytest test_m1_vm_lifecycle.py -v --timeout=600  # single file
python -m pytest -v --timeout=600                           # full suite
```

## Rust workspace

Working directory for cargo commands: `sandboxd/`

```bash
cd sandboxd && cargo build --workspace
cd sandboxd && cargo test --workspace
cd sandboxd && cargo clippy --workspace
```

Unit test count: ~413 tests across 4 crates.

## Key conventions

- All `std::process::Command` calls in async handlers are wrapped in `tokio::task::spawn_blocking`
- Guest agent communication (TCP-over-SSH) is already async — do not wrap in spawn_blocking
- Error responses use `error_response()` helper that maps `SandboxError` variants to HTTP status codes
- Handler return type is `impl IntoResponse` — use `match` on spawn_blocking results, not `?` operator
- Socket path default: `$XDG_RUNTIME_DIR/sandboxd/sandboxd.sock` (falls back to `~/.local/share/sandboxd/sandboxd.sock`)
- Git remote helper: `git-remote-sandbox` symlink to `sandbox` binary, uses `sandbox::session/repo-path` URLs
