# Sandbox Daemon (sandboxd)

Sandbox daemon providing isolated Linux environments for coding agents — Lima/QEMU VMs (full backend) and default-hardened Docker containers (lite-mode backend), with a shared per-session network gateway that enforces egress policy.

## Project structure

- `sandboxd/` — Rust workspace, 8 crates:
  - `sandbox-core` — shared library (backends, store, policy, events, guest protocol)
  - `sandboxd` — daemon binary (HTTP API over unix socket)
  - `sandbox-cli` — `sandbox` CLI binary (also installed as `git-remote-sandbox`)
  - `sandbox-guest` — guest-agent binary that runs inside each VM/container
  - `sandbox-route-helper` — privileged setcap binary that installs the default route inside a container netns on behalf of an authorized caller
  - `sandbox-lima-helper` — privileged setcap binary that pivots to an operator's uid before exec'ing `limactl` for every Lima control-plane operation
  - `sandbox-event-emitter` — shared lib used by both nft-loggers (JSONL writer + record types)
  - `sandbox-nft-deny-logger` — gateway-container binary that emits `deny` records (TCP DNAT + UDP NFLOG)
  - `sandbox-nft-allow-logger` — gateway-container binary that audits allowed UDP flows via NFCT
- `networking/` — Gateway container (five-process pipeline: Envoy, mitmproxy, CoreDNS, nft-deny-logger, nft-allow-logger) plus the in-tree CoreDNS plugin
- `tests/e2e/` — Python E2E test suite (pytest)
- `docs/` — Project documentation

## Build and test

```bash
make build                  # cargo build --workspace (preceded by fmt-check)
make test                   # hermetic unit tests only — fast, no Docker/Lima/nft
make test-integration       # every `integration_*`-prefixed test in the workspace (Docker required)
make test-e2e-container     # PR-time E2E: container backend only (~5-10 min)
make test-e2e-matrix        # full E2E matrix: Lima + container (~30-45 min, needs /dev/kvm for the Lima half)
make test-e2e               # back-compat alias for test-e2e-matrix
make gateway-image          # docker build for the gateway container
make lite-image             # docker build for the lite-mode container image
make setup-dev-env          # one-shot per-host install/configure (route-helper cap'd install, qemu bridge.conf, users.conf, qemu-bridge-helper setuid)
```

### Integration-test convention

Any test that needs out-of-process state (real gateway container,
`nft -c` / `envoy --mode validate` CLIs, a Lima VM, etc.) is named
with an `integration_*` prefix at the test site. The `integration`
nextest profile (`sandboxd/.config/nextest.toml`) selects tests by
that prefix; the default profile filters them out. No `#[ignore]`
attribute, no env gate — membership is self-describing at the call
site via the name.

This keeps `make test` hermetic (~5s, no Docker dependency) and lets
`make test-integration` run the full integration set via
`cargo nextest run --workspace --profile integration` after building
the gateway image.

For iteration on a single integration test, layer an `-E` filter on
top of the profile:
`cd sandboxd && cargo nextest run --profile integration -E 'test(integration_gateway_lifecycle)'`.

## E2E tests

E2E tests boot real Lima/QEMU VMs and are SLOW. Individual test files take 3-10 minutes. The full suite takes 30-45 minutes.

**Running E2E tests from Claude Code:**
- Never run the full suite in a foreground bash call — it will hit the 10-minute timeout.
- Delegate to a subagent, or use `run_in_background: true`.
- To poll between checks, use foreground `true && sleep 120 && <check-command>` — this saves tokens vs. background sleep + separate poll. Set timeout high enough for the sleep.
- For faster iteration, run individual test files: `python -m pytest test_git_remote.py -v`
- Run a single test first before running the full suite.

```bash
# From tests/e2e/:
source .venv/bin/activate
python -m pytest test_vm_lifecycle.py -v --timeout=600  # single file
python -m pytest -v --timeout=600                           # full suite
```

If `python -m pytest` reports `ModuleNotFoundError: No module named 'pytest'` despite `pip list` showing it, the host's `python3` was upgraded under the venv since it was built — `tests/e2e/.venv/bin/python` is now ABI-mismatched with the new interpreter. `make test-e2e` (and friends) auto-rebuild the venv via a version-stamped marker (`.installed.pythonX.Y`); for the manual `source .venv/bin/activate` path above, run `rm -rf tests/e2e/.venv && make test-e2e-container` once to rebuild against the current `python3`, then the activate-and-iterate flow works again.

### Cross-user harness (default `sandbox-systemd`)

The suite runs the daemon as the unprivileged `sandbox` system user while the test runner acts as the *operator* (a separate uid), so the daemon's uid differs from the operator's — the real cross-user path. When running or debugging:

- **Sandbox-group membership must be live.** The daemon socket is `0660`, group `sandbox`; the pytest process must carry that group in its credentials. `usermod -aG sandbox <you>` only takes effect at next login, so `make test-e2e-matrix` / `test-e2e-container` self-wrap the pytest step in `sg sandbox -c` (set `SANDBOX_HARNESS=test-user` for the legacy single-uid path, which skips the wrap).
- **Per-operator LIMA_HOME.** Lima VMs, configs, and the SSH key live under `/var/lib/sandboxd/<operator_uid>/lima/`, owned by the operator uid. The key is a plain `0600` file: OpenSSH StrictKeyfileMode reads `st_mode`, and a POSIX-ACL *named-user* entry surfaces its mask in the group bits (tripping OpenSSH), so the per-operator LIMA_HOME deliberately carries no default named-user ACL. Test-side `limactl` must run **as the operator** with `LIMA_HOME` set (`limactl_cmd()` in conftest), never `sudo -u sandbox` — the daemon uid cannot read the operator-owned files.
- **In-VM home is backend-specific:** Lima `/home/agent`, container `/home/sandbox`; cross-backend tests select via `guest_home(backend)`.
- **The test-cap'd `sandbox-lima-helper` can install stale.** Its stamp may report "already configured" without reinstalling a changed binary — `rm sandboxd/target/.dev-env-stamps/lima-helper-test.stamp && make install-lima-helper-test-cap` after any helper change.

### Debugging a red matrix

The cross-user matrix boots real VMs and runs ~1.5–2h on the 8 GB host. Launch it detached (or via a background agent) and poll the log rather than blocking. When triaging:

- **Isolate failures one at a time** — never two VMs/containers at once (8 GB). A long full run can *cascade* (e.g. the gateway degrading mid-run fails later policy/preset tests); an isolated rerun separates a real bug from load/cascade.
- **Container-backend failures are independent of the Lima cross-user path** (the container backend never runs `limactl` through `sandbox-lima-helper`) — a fast discriminator for whether a failure involves the helper / cross-user execution at all.
- Read a background agent's **log/output file**, not its full JSONL transcript, for ground truth.
- Guard long docker/Lima runs against ENOSPC — see **Disk pressure** below.

### Disk pressure (ENOSPC)

`/` (≈96 GB) holds `/var/lib/docker` (image layers + build cache), the Lima VM disk images under `/var/lib/sandboxd/<uid>/lima/`, and `/tmp`. Long or repeated e2e / integration runs accumulate fast: every `make gateway-image` / `lite-image` rebuild adds build-cache layers (tens of GB over a session), each Lima VM is a multi-GB qcow2, and a crashed run can leave an orphaned QEMU process still holding its disk image. When `/` fills, the failure is usually **confusing rather than an obvious "disk full"** — `cargo` dies mid-link, `docker build` fails, or VM creation hangs.

**Watch it.** `df -h /`. During a long background run, arm a watcher that alerts when free space drops below a threshold (e.g. a poll loop that emits only when free space is under ~10–12 GB) rather than discovering ENOSPC after a wasted hour.

**Reclaim it** (most-reclaimable first; these preserve tagged images):

- `docker builder prune -f` — build cache is usually the largest reclaimable chunk (tens of GB).
- `docker image prune -f` — dangling/untagged layers only; leaves the tagged `gateway` / `lite` images intact.
- `pkill -f qemu-system` — reap orphaned/leaked sandbox VMs; a crashed run can leave a multi-GB QEMU holding its disk image.
- Remove leftover Lima instance dirs under the per-operator LIMA_HOME if a run died before teardown.

Do **not** blanket `docker system prune -a` mid-session — it evicts the tagged `gateway` / `lite` images and forces slow rebuilds.

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
- **Async-I/O carve-out for long-lived child processes.** The `spawn_blocking` rule above applies to one-shot Command invocations (e.g. `limactl list`, `docker inspect`). The proxy WebSocket handler's container path holds a `docker exec ... socat` byte pump open for the entire SSH session (potentially hours under VS Code Remote-SSH or JetBrains Gateway); the Lima path holds an analogous TCP stream. Wrapping either in `spawn_blocking` would occupy a blocking-task slot for the session's lifetime and deadlock the executor under load. These long-lived pumps use `tokio::process::Command` (or `tokio::net::TcpStream`) with async pipes — see the Async-I/O carve-out doc-comment in `sandboxd/sandboxd/src/proxy_http.rs` for the full rationale. Any future "uniformly wrap Command in spawn_blocking" sweep must leave the carve-out site alone.
- Guest agent communication is already async — do not wrap in spawn_blocking. Transport is a per-backend `socat`-bridged pipe (`limactl shell <vm> -- socat - TCP:127.0.0.1:5123` for Lima, `docker exec <ctr> socat - TCP:127.0.0.1:5123` for container) selected via the `SessionRuntime::guest_transport` seam in `sandbox-core::backend`
- Error responses use `error_response()` helper that maps `SandboxError` variants to HTTP status codes
- Handler return type is `impl IntoResponse` — use `match` on spawn_blocking results, not `?` operator
- Socket path default: `$XDG_RUNTIME_DIR/sandboxd/sandboxd.sock` (falls back to `~/.local/share/sandboxd/sandboxd.sock`). Both the daemon and CLI honor the `SANDBOX_SOCKET` env var as an override; an explicit `--socket` flag takes precedence over the env var.
- Git remote helper: `git-remote-sandbox` symlink to `sandbox` binary, uses `sandbox::session/repo-path` URLs
- Config files: all config files (daemon, CLI, per-session metadata) use JSON — not TOML, not YAML
- **No milestone tags in code or tests.** Comments like `// M11-S10 added X` or `// M12-S2 Decision N` belong in git log and PR descriptions, not in source. Code should explain itself in its own terms.
- **Privilege model: narrowly-scoped setcap helpers over broad daemon capabilities.** The daemon (`sandboxd`) runs as the unprivileged `sandbox` system user without elevated capabilities. When an operation genuinely needs `CAP_*`, factor it into a separate setcap helper binary rather than granting the capability to the daemon itself. Two helpers are installed at `/usr/local/libexec/sandboxd/`:
  - `sandbox-route-helper` — `cap_net_admin,cap_sys_admin=eip`; installs the default route inside a container netns; pair-membership check on the caller.
  - `sandbox-lima-helper` — `cap_setuid+ep`; pivots to an operator's uid via `setresuid` before exec'ing `limactl` for every Lima control-plane operation; `getuid()==sandbox-user-uid` (kernel-checked) + sandbox-group membership as caller gates. The daemon **never invokes `limactl` directly** — every limactl call goes through this helper.
  Do NOT add `AmbientCapabilities` / `CapabilityBoundingSet` to `sandboxd.service`, do NOT setcap the daemon binary itself, and do NOT run the daemon as root. The narrow-helper approach keeps the privileged surface ~50–100 lines per capability, separately reviewable, and tightly scoped to its specific purpose.

## On-disk compatibility

Session state persists across daemon restarts in `{base_dir}/sessions.db` (SQLite). `SessionStore::new` (in `sandbox-core/src/store.rs`) opens the DB and runs every pending migration via `refinery` against `sandbox-core/migrations/`. Schema evolution rules:

- **SQLite columns** (`sessions`, `network_info`, etc.) — adding or changing a column requires a new `V<NNN>__<name>.sql` file in `sandbox-core/migrations/`. Never drop a column without verifying no older daemon needs it; refinery enforces forward-only application of the migration set.
- **JSON blob fields** (columns like `config_json`, `network_info` JSON payloads) — when adding a field to a persisted struct (`SessionConfig`, `NetworkInfo`, etc.), make it `Option<T>` with `#[serde(default)]` so records written by older versions still deserialize. Never remove or rename a persisted blob field without a migration.
- **Forward-compat on rollback** — records written by a newer daemon may be read by an older one during rollback. Use `#[serde(default)]` + unknown-field tolerance to keep this safe.

## graphify

This project has a knowledge graph at graphify-out/ with god nodes, community structure, and cross-file relationships.

Rules:
- For codebase questions, first run `graphify query "<question>"` when graphify-out/graph.json exists. Use `graphify path "<A>" "<B>"` for relationships and `graphify explain "<concept>"` for focused concepts. These return a scoped subgraph, usually much smaller than GRAPH_REPORT.md or raw grep output.
- If graphify-out/wiki/index.md exists, use it for broad navigation instead of raw source browsing.
- Read graphify-out/GRAPH_REPORT.md only for broad architecture review or when query/path/explain do not surface enough context.
- After modifying code, run `graphify update .` to keep the graph current (AST-only, no API cost).
