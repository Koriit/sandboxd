# Sandbox Daemon (sandboxd)

Sandbox daemon providing isolated Linux VMs (Lima/QEMU) for coding agents.

## Project structure

- `sandboxd/` — Rust workspace (4 crates: sandbox-core, sandbox-cli, sandboxd, sandbox-guest)
- `networking/` — Gateway container (Envoy, mitmproxy, CoreDNS)
- `tests/e2e/` — Python E2E test suite (pytest)
- `docs/` — Project documentation

## Build and test

```bash
make build                  # cargo build --workspace
make test                   # hermetic unit tests only — fast, no Docker/Lima/nft
make test-integration       # test + every #[ignore]d integration test (Docker required)
make test-e2e               # full E2E suite (boots real VMs, ~30-45 min)
make gateway-image          # docker build for gateway container
```

### Integration-test convention

Any test that needs out-of-process state (real gateway container,
`nft -c` / `envoy --mode validate` CLIs, a Lima VM, etc.) is marked
`#[ignore]` at the test site with a reason string pointing to
`make test-integration`. This keeps `make test` hermetic (~5s, no
Docker dependency) and lets `make test-integration` run everything
via `cargo nextest run --run-ignored only`.

Validator tests (policy-compiler outputs run through `nft -c` in a
`CAP_NET_ADMIN` container, Envoy `--mode validate`, and a
`serde_json` round-trip of the mitmproxy config) additionally
short-circuit at the top of the test body unless
`SANDBOX_TEST_VALIDATORS=1` is set — double-guard for environments
that have Docker but lack the specific external binaries. The Make
target always sets it.

For iteration on a single integration test, run nextest directly
with `--run-ignored only -E '<filter>'`:
`cd sandboxd && cargo nextest run --run-ignored only -E 'test(gateway_lifecycle)'`.

## E2E tests

E2E tests boot real Lima/QEMU VMs and are SLOW. Individual test files take 3-10 minutes. The full suite takes 30-45 minutes.

**Running E2E tests from Claude Code:**
- Never run the full suite in a foreground bash call — it will hit the 10-minute timeout.
- Delegate to a subagent, or use `run_in_background: true`.
- To poll between checks, use foreground `true && sleep 120 && <check-command>` — this saves tokens vs. background sleep + separate poll. Set timeout high enough for the sleep.
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
cd sandboxd && cargo nextest run --workspace
cd sandboxd && cargo clippy --workspace
```

Test runner: cargo-nextest (config at `sandboxd/.config/nextest.toml`).

## Key conventions

- All `std::process::Command` calls in async handlers are wrapped in `tokio::task::spawn_blocking`
- Guest agent communication (TCP-over-SSH) is already async — do not wrap in spawn_blocking
- Error responses use `error_response()` helper that maps `SandboxError` variants to HTTP status codes
- Handler return type is `impl IntoResponse` — use `match` on spawn_blocking results, not `?` operator
- Socket path default: `$XDG_RUNTIME_DIR/sandboxd/sandboxd.sock` (falls back to `~/.local/share/sandboxd/sandboxd.sock`). Both the daemon and CLI honor the `SANDBOX_SOCKET` env var as an override; an explicit `--socket` flag takes precedence over the env var.
- Git remote helper: `git-remote-sandbox` symlink to `sandbox` binary, uses `sandbox::session/repo-path` URLs

## On-disk compatibility

Session state persists across daemon restarts in `{base_dir}/sessions.db` (SQLite). Schema evolution rules:

- **SQLite columns** (`sessions`, `network_info`, etc.) — adding or changing a column requires an explicit migration step in `SessionStore::open`. Never drop a column without verifying no older daemon needs it.
- **JSON blob fields** (columns like `config_json`, `network_info` JSON payloads) — when adding a field to a persisted struct (`SessionConfig`, `NetworkInfo`, etc.), make it `Option<T>` with `#[serde(default)]` so records written by older versions still deserialize. Never remove or rename a persisted blob field without a migration.
- **Forward-compat on rollback** — records written by a newer daemon may be read by an older one during rollback. Use `#[serde(default)]` + unknown-field tolerance to keep this safe.
