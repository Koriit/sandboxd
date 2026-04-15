# Implementation Plan

## References

- [Sandbox design](../sandbox-design.md) — isolation boundary, VM lifecycle, gateway deployment, session lifecycle, vsock, hardening
- [Networking design](../networking-design.md) — proxy pipeline, policy model, assurance levels, DNS model, traffic flow

## Table of contents

- [Repo structure](#repo-structure)
- [Execution model](#execution-model)
- [M0: Project Scaffolding](#m0-project-scaffolding) — cargo workspace, directory structure, pytest setup
- [M1: sandboxd Skeleton + Lima VM Lifecycle](#m1-sandboxd-skeleton--lima-vm-lifecycle) — CLI, session store, Lima integration, session lifecycle
- [M2: vsock Control Channel](#m2-vsock-control-channel) — host connector, VM-side listener, SSH over vsock
- [M3: Gateway Container + Per-Session Networking](#m3-gateway-container--per-session-networking-linux) — gateway image, Docker bridge, nftables, CA lifecycle, orchestration
- [M4: Policy Engine](#m4-policy-engine) — policy schema, compilation, CoreDNS plugin, mitmproxy addon, DNS propagation
- [M5: Workspace Provisioning](#m5-workspace-provisioning) — clone mode, cp, git-over-vsock
- [M6: Hardening](#m6-hardening) — QEMU sandboxing, device model lockdown
- [M7: Documentation](#m7-documentation) — polish and consolidate user, operator, and contributor docs
- [M8: Polish and Deferred TODOs](#m8-polish-and-deferred-todos) — resolve accumulated TODOs, deferred findings, technical debt
- [M8.5: E2E Fix-up](#m85-e2e-fix-up--portability-and-runtime-correctness) — fix all runtime issues preventing E2E tests from passing
- [M9: User Polish and Refactors](#m9-user-polish-and-refactors) — XDG paths, root-level README and CLAUDE.md
- [Risks](#risks)
- [Completed session count](#completed-session-count)
- [Future Milestones](#future-milestones)
  - [F1: macOS Support](#f1-macos-support) — socket_vmnet, Colima, macvlan

## Repo structure

```
claude-sandbox/
├── docs/                # design docs, session plan
├── sandboxd/            # Rust cargo workspace
│   ├── sandboxd/        # daemon binary
│   ├── sandbox-cli/     # CLI binary (binary name: `sandbox`)
│   ├── sandbox-core/    # shared library: session store, config, types
│   └── sandbox-guest/   # VM-side vsock listener binary (runs inside the VM)
├── tests/
│   └── e2e/             # cumulative E2E test suite (pytest)
└── networking/          # gateway component configs and plugins
    ├── coredns-plugin/  # Go module — custom CoreDNS policy plugin
    ├── mitmproxy/       # Python addon(s) for policy enforcement
    ├── envoy/           # Envoy config templates
    └── gateway/         # Dockerfile + entrypoint for gateway container image
```

## Execution model

### Sequential sessions

Sessions are linearized for single-agent tracking. Some sessions could theoretically run in parallel based on their entry criteria, but we execute one at a time in session-number order. Each session is implemented by a subagent delegated from the main orchestrating agent.

Future milestones (F-series) are documented at the end of this plan but are not on the critical path.

### Branch model

- `main` — stable branch, each session merges here on completion
- `impl/m{N}-s{K}-{slug}` — short-lived session branch, branched from main, merged back after session completion

### Progress tracking

The `/session-tracking` skill (`.claude/skills/session-tracking/`) manages `.tasks/progress.json` — a structured JSON log with three sections:

- **`current_state`** — quick orientation: current milestone, session, status, progress count
- **`current_log`** — append-only entries during the active session (decisions, discoveries, blockers). Cleared on session close.
- **`log`** — permanent append-only record of completed sessions with summaries, decisions, and artifacts

The orchestrator follows a two-phase protocol: during a session, it appends entries to `current_log`; at session close, it distills these into a permanent `log` entry. Appending structured JSON entries is trivially reliable even under heavy context degradation — no synthesis required until session close, when the orchestrator has fresh context from the subagent's completion signal.

Format reference: `.claude/skills/session-tracking/progress-schema.json`

Initialize with `progress init --total-sessions 30` (the Linux critical path: M0 through M8). Future milestones (F-series) are a separate track — add via `replan` when ready.

### Context recovery

A post-compact hook (planned, see `.claude/skills/session-tracking/hooks-plan.md`) will inject a reminder to read `.tasks/progress.json` and `docs/session-plan.md` after context compaction. Until the hook is configured, the orchestrator should read these files manually after detecting compaction or context loss.

### Team composition

Each session uses a team of agents. The main orchestrating agent decides team composition per session based on the work involved — there is no fixed template. Guidelines:

- Every session should have at least an **implementer** and a separate agent for **final verification** (exit criteria check, E2E suite run). The implementer should use TDD and run tests during development — the separation is about the *final* quality gate, not about forbidding the implementer from testing.
- For sessions touching multiple languages (e.g., M4-S5 wiring Rust + Go + Python), consider one teammate per language.
- E2E test debugging is unpredictable — for integration-heavy sessions (M3-S6, M4-S6), consider a dedicated teammate for running and interpreting test failures.
- Simpler sessions (M0-S1 scaffolding, M6-S2 device lockdown) may only need one or two agents.

### E2E testing

E2E tests are cumulative. Each milestone adds tests; all previous tests must still pass. The E2E suite is the first thing every session runs before starting work and the last thing before declaring done.

Tests live in `tests/e2e/` (top-level, outside the Rust workspace) using **pytest**. Tests shell out to the `sandbox` CLI binary, run Docker commands, SSH into VMs, and assert on observable behavior. pytest provides the right balance of power and simplicity for system-level tests — fixtures handle session setup/teardown, assertions are readable, and every developer has Python.

Tests require a Linux host with KVM and Docker.

---

## M0: Project Scaffolding

### M0-S1: Cargo workspace and directory structure

**Entry criteria:** Empty repo (current state — design docs only).

**Tasks:**
- Create the Cargo workspace at `sandboxd/` with four crates:
  - `sandboxd` (binary) — daemon entrypoint, placeholder `main.rs`
  - `sandbox-cli` (binary) — CLI entrypoint, placeholder `main.rs`. The crate name is `sandbox-cli` but the binary name in `Cargo.toml` is `sandbox`.
  - `sandbox-core` (library) — shared types, config, error module
  - `sandbox-guest` (binary) — VM-side vsock listener, placeholder `main.rs`. Shares types with sandboxd via `sandbox-core`.
- Add workspace-level dependencies: `clap`, `tokio`, `axum`, `rusqlite`, `serde`, `serde_json`, `thiserror`, `tracing`, `tracing-subscriber`, `uuid`
- Create `tests/e2e/` directory with pytest scaffolding: `pyproject.toml` with `pytest` dependency, `conftest.py` with fixtures for session management (create/destroy helpers, CLI wrappers, cleanup finalizers). Use a venv (`tests/e2e/.venv/`, added to `.gitignore`)
- Create a top-level `Makefile` with targets: `build` (cargo build --workspace), `test` (cargo test --workspace), `test-e2e` (activate venv + pytest), `gateway-image` (docker build networking/gateway), `clean`
- Create `networking/` directory structure: `coredns-plugin/`, `mitmproxy/`, `envoy/`, `gateway/`
- Initialize Go module in `networking/coredns-plugin/`
- Add workspace-level `rustfmt.toml` and `clippy.toml`
- Add `.github/` CI placeholder (cargo build, cargo test, cargo clippy)
- Create `docs/README.md` with project overview, prerequisites (Rust, Lima, Docker, KVM), and build instructions (`make build`, `make test`)
- Verify `cargo build --workspace` and `cargo test --workspace` succeed

**Exit criteria:** `cargo build --workspace` produces two binaries (daemon and `sandbox` CLI). `cargo test --workspace` passes. Directory structure matches the repo layout above.

---

## M1: sandboxd Skeleton + Lima VM Lifecycle

### M1-S1: CLI framework and Unix socket API server

**Entry criteria:** M0-S1 complete.

**Tasks:**
- Implement CLI argument parsing in `sandbox-cli` using clap:
  - Subcommands: `create`, `start`, `stop`, `rm`, `ps`, `ls` (stubs that send HTTP to the daemon socket)
  - Global option: `--socket <path>` (default `~/.sandboxd/sandboxd.sock`)
- Implement HTTP API server in `sandboxd` using axum over a Unix socket:
  - `POST /sessions` (create)
  - `POST /sessions/{id}/start`
  - `POST /sessions/{id}/stop`
  - `DELETE /sessions/{id}` (rm)
  - `GET /sessions` (ps/ls)
  - `GET /sessions/{id}`
  - All handlers return 501 for now
- Define `Session` type in `sandbox-core`: id (UUID), name (optional), state enum (`Creating`, `Running`, `Stopped`, `Error`), timestamps, config
- Define `SandboxError` enum in `sandbox-core` with `thiserror`
- Daemon startup: create socket directory, bind socket, install signal handlers (SIGTERM/SIGINT for graceful shutdown)

**Exit criteria:** `sandbox ps` connects to the daemon socket and receives a 501 response. Daemon starts, binds socket, shuts down cleanly on SIGTERM. Unit tests for CLI arg parsing and session types.

---

### M1-S2: Session store (SQLite)

**Entry criteria:** M1-S1 complete (Session types defined).

**Tasks:**
- Implement `SessionStore` in `sandbox-core` using rusqlite:
  - `create_session(config) -> Session`
  - `get_session(id) -> Option<Session>`
  - `list_sessions() -> Vec<Session>`
  - `update_state(id, state)`
  - `delete_session(id)`
- SQLite database at `~/.sandboxd/sessions.db` (global state; per-session files go under `~/.sandboxd/sessions/{session_id}/`)
- Create per-session directory on session creation: `~/.sandboxd/sessions/{session_id}/` (holds template.yaml, ca/, policy/, logs/)
- Schema: `sessions` table with id, name, state, config (JSON), created_at, updated_at
- WAL mode for concurrent reads
- Migrations: use `refinery` — versioned SQL files in a `migrations/` directory (e.g., `V001__create_sessions.sql`), applied in order, tracked in a metadata table (Flyway-style)
- Unit tests: CRUD operations, state transitions, concurrent access

**Exit criteria:** All SessionStore unit tests pass. Database is created on first access, schema migrations run automatically.

---

### M1-S3: Lima integration module

**Entry criteria:** M1-S1 complete (Session types defined).

**Tasks:**
- Implement `LimaManager` in `sandbox-core`:
  - `create_vm(session_id, template_path) -> Result<()>` — shells out to `limactl create`
  - `start_vm(session_id) -> Result<()>` — `limactl start`
  - `stop_vm(session_id) -> Result<()>` — `limactl stop`
  - `delete_vm(session_id) -> Result<()>` — `limactl delete`
  - `vm_status(session_id) -> Result<VmStatus>`
  - `list_vms() -> Result<Vec<VmInfo>>` — `limactl list --json`
- VM naming convention: `sandbox-{session_id}` (prefix avoids collision with user VMs)
- Lima YAML template generation: minimal template with:
  - Ubuntu cloud image
  - QEMU backend with KVM (Linux)
  - CPU, memory, disk from session config (sensible defaults: 2 CPU, 4GB RAM, 20GB disk)
  - cloud-init provisioning: install Docker, configure SSH keys, set hostname
  - Disable file sharing, disable automatic port forwarding
  - Override Lima defaults: disable host mounts (`mounts: []`), disable user propagation. VM user is a passwordless-sudoer `agent` user (not the host user, not root)
- Template written to `~/.sandboxd/sessions/{session_id}/template.yaml`
- Error handling: parse `limactl` stderr for common failures (KVM not available, disk space, etc.)
- Integration tests that require Lima installed (gated behind `#[cfg(feature = "integration")]` or similar)

**Exit criteria:** `LimaManager::create_vm` produces a valid Lima template and creates a VM. `stop_vm` and `delete_vm` clean up. `vm_status` correctly reports state. Integration test: create VM, verify it boots (SSH works via `limactl shell`), destroy it.

---

### M1-S4: Wire CLI to daemon — session lifecycle

**Entry criteria:** M1-S2 and M1-S3 complete (session store + Lima integration).

**Tasks:**
- Wire API handlers in `sandboxd` to use `SessionStore` and `LimaManager`:
  - `POST /sessions`: create session in store, generate Lima template, create VM, start VM, update state
  - `POST /sessions/{id}/start`: `limactl start` the VM, update session state to Running. Note: the `start` handler will be extended in M3-S6 to include network and gateway recreation.
  - `POST /sessions/{id}/stop`: stop VM, update state
  - `DELETE /sessions/{id}`: stop VM (if running), delete VM, delete session from store
  - `GET /sessions`: list from store, enrich with VM status
  - `GET /sessions/{id}`: get from store, enrich with VM status
- CLI subcommands: `create` (accepts `--name`, `--cpus`, `--memory`, `--disk`, `--template <path>` to use a custom Lima template instead of the generated default), `start`, `stop`, `rm`, `ps`, `ls`
- CLI `ps` and `ls` display session table (id, name, state, uptime)
- Daemon state reconciliation on startup: load sessions from store, check Lima VM inventory, mark orphans as `Error`
- Update `docs/README.md` with getting started guide: install sandboxd, create your first sandbox, basic CLI reference for available commands
- Write E2E tests in `tests/e2e/test_m1_vm_lifecycle.py`:
  - `test_create_and_destroy` — create a session, verify VM boots (can run a command inside via `limactl shell`), destroy it, verify cleanup
  - `test_stop_and_start` — create a session, write a file inside the VM via `limactl shell`, stop it, start it again, verify the file persists (read it back via `limactl shell`)

**Exit criteria:** `sandbox create --name test` creates a VM that boots with Docker installed. `sandbox ps` shows it. `sandbox start` resumes a stopped session. `sandbox rm test` destroys it. E2E tests pass. Daemon restart reconciles state correctly.

---

## M2: vsock Control Channel

### M2-S1: vsock host-side connector

**Entry criteria:** M1 complete (VMs boot and are manageable).

**Tasks:**
- Add `vsock` crate dependency (or use `nix` for raw AF_VSOCK)
- Implement `VsockConnector` in `sandbox-core`:
  - `connect(cid: u32, port: u32) -> Result<VsockStream>`
  - Connection timeout, retry with backoff
  - Message framing: length-prefixed messages, bounded max size
  - Request/response protocol: JSON-over-vsock with strict validation
  - Per-session handler isolation: spawn a dedicated tokio task per session, limit its capabilities
- Define vsock protocol messages:
  - `Ping` / `Pong` (health check)
  - `Exec { command, args }` / `ExecResult { exit_code, stdout, stderr }` (bounded output)
  - `Status` / `StatusResult { ... }`
- All response parsing treats VM input as untrusted: bounded reads, no shell interpolation, strict JSON schema validation
- Investigate Lima vsock CID discovery mechanism. Determine how sandboxd obtains the CID for each VM (`limactl list --json`, Lima template configuration, or QEMU command-line parsing). If Lima doesn't expose CID, assign CIDs explicitly in the Lima template.
- Design decision: vsock handler isolation model. Choose between Tokio tasks (simpler, shared-memory isolation) or forked OS processes (stronger isolation, but complex with async runtime). Document the decision and rationale.
- Unit tests with mock vsock (test framing, parsing, bounds checking, malformed input rejection)

**Exit criteria:** `VsockConnector` can connect to a vsock CID/port, send a framed message, receive a framed response. Unit tests cover normal operation and adversarial inputs (oversized messages, malformed JSON, truncated frames).

---

### M2-S2: VM-side vsock listener

**Entry criteria:** M2-S1 complete (protocol defined).

**Tasks:**
- Create `sandbox-guest` crate in the Cargo workspace — a Rust binary that runs inside the VM, sharing types with sandboxd via `sandbox-core`:
  - Listens on AF_VSOCK port (e.g., 5000) for host connections
  - Implements the request/response protocol from M2-S1
  - Handles `Ping`, `Exec` (runs command, returns bounded output), `Status`
  - `Exec` must not allow unbounded output — truncate at a configurable limit
- Update Lima cloud-init template to:
  - Copy the `sandbox-guest` binary into the VM during provisioning
  - Start it as a systemd service
  - Enable vsock in the Lima template (ensure vsock device is present)
- Test: daemon connects to VM via vsock, sends Ping, gets Pong

**Exit criteria:** After VM boot, the vsock listener is running inside the VM. The host can connect and exchange messages. `Ping`/`Pong` works. `Exec` can run a simple command (e.g., `uname -a`) and return output.

---

### M2-S3: `sandbox ssh` and E2E tests

**Entry criteria:** M2-S2 complete (vsock works end-to-end).

**Tasks:**
- Implement `sandbox ssh <session>`:
  - Tunnel SSH over vsock (use `ssh -o ProxyCommand` with a vsock proxy helper, or implement directly)
  - No IP-based SSH — connection goes purely over vsock
  - Interactive terminal support (allocate PTY)
- Wire vsock health check into `sandbox ps` — show vsock connectivity status per session
- Update daemon: after VM boot, wait for vsock connectivity before reporting session as `Running`
- E2E tests in `tests/e2e/test_m2_vsock.py`:
  - `test_vsock_connection` — create session, connect via vsock, ping
  - `test_vsock_exec` — execute command via vsock, verify output
  - `test_ssh_over_vsock` — SSH into session, run command, verify output
- Verify all M1 E2E tests still pass

**Exit criteria:** `sandbox ssh test-session` opens an interactive SSH session via vsock. E2E tests for vsock connectivity and command execution pass. All M1 tests still pass.

---

## M3: Gateway Container + Per-Session Networking (Linux)

### M3-S1: Gateway container image

**Entry criteria:** M2 complete.

**Tasks:**
- Create `networking/gateway/Dockerfile`:
  - Base image: Debian slim or Alpine
  - Install: Envoy, mitmproxy, CoreDNS (binary). No CA generation tools — sandboxd generates the CA keypair and mounts the private key into the container
  - Entrypoint: supervisor script that starts components in correct order (mitmproxy, Envoy, CoreDNS)
  - Read-only root filesystem, writable volumes for `/var/log`, `/var/run`, `/tmp`
  - Health check endpoint (simple HTTP server or script that checks all components)
- Create minimal Envoy config (`networking/envoy/envoy-base.yaml`):
  - `original_dst` listener on a known port
  - Basic TCP proxy cluster (no policy yet — pass-through)
- Create minimal mitmproxy config (`networking/mitmproxy/`):
  - Addon skeleton that logs connections (no policy enforcement yet)
  - Listen on port for Envoy to forward to
  - Health endpoint
- Create minimal CoreDNS config (`networking/envoy/` — no, `networking/coredns-plugin/` for plugin, separate Corefile):
  - Forward all queries upstream (no policy filtering yet)
  - Listen on port 53
- Build and test the image locally: `docker build -t sandbox-gateway networking/gateway/`
- Verify all components start and health check passes

**Exit criteria:** `docker build` produces a working gateway image. Container starts, all three components (Envoy, mitmproxy, CoreDNS) are running and healthy. Health check endpoint returns OK.

---

### M3-S2: Per-session Docker bridge networking

**Entry criteria:** M2 complete.

**Tasks:**
- Implement `NetworkManager` in `sandbox-core` (Linux implementation):
  - `create_network(session_id) -> Result<NetworkInfo>` — create Docker bridge with /30 subnet from pool
  - `delete_network(session_id) -> Result<()>` — remove Docker bridge
  - `network_info(session_id) -> Result<NetworkInfo>` — gateway IP, VM IP, subnet, bridge name
- Subnet allocator:
  - Configurable base range (default `10.209.0.0/24`)
  - Carve /30 subnets: `.0/.1` pair, `.4/.5` pair, etc. (gateway gets .1, VM gets .2 within each /30)
  - Track allocated subnets in session store
  - Release on session destroy
- Docker bridge creation: shell out to `docker network create` with specific subnet, gateway, and labels
- Bridge naming: `sandbox-{session_id}` (truncated if needed for interface name length limits)
- Unit tests: subnet allocation, exhaustion handling, release
- Integration test: create bridge, inspect it, verify subnet, destroy it

**Exit criteria:** `NetworkManager` creates and destroys per-session Docker bridges with correct /30 subnets. Subnet allocation is correct and handles pool exhaustion. Integration tests pass.

---

### M3-S3: Gateway lifecycle and nftables injection

**Entry criteria:** M3-S1 and M3-S2 complete (gateway image + network module).

**Tasks:**
- Implement `GatewayManager` in `sandbox-core`:
  - `create_gateway(session_id, network_info) -> Result<()>` — `docker run` gateway container on session network
  - `stop_gateway(session_id) -> Result<()>` — `docker stop` + `docker rm`
  - `gateway_status(session_id) -> Result<GatewayStatus>` — health check query
- Gateway container run options:
  - `--network sandbox-{session_id}`
  - `--ip {gateway_ip}` (the .1 address on the /30)
  - `--sysctl net.ipv4.ip_forward=1`
  - `--sysctl net.ipv6.conf.all.forwarding=0`
  - `--read-only` with tmpfs mounts for writable paths
  - Volume mount for per-session config (Envoy config, CA cert, etc.)
  - Container naming: `sandbox-gw-{session_id}`
- nftables rule injection: sandboxd runs `nft` from the host, using `nsenter --net` to enter the gateway container's network namespace. The container itself has no nftables tools and no `CAP_NET_ADMIN`:
  - Deny-by-default rules (first thing applied)
  - PREROUTING DNAT: redirect TCP to Envoy port, redirect DNS (port 53) to CoreDNS
  - IPv6 blanket drop
  - Add explicit nftables rule to drop traffic to 169.254.169.254 (cloud metadata service)
  - IP forwarding chain: forward from VM subnet to gateway
  - Implement as a shell script or nft ruleset template, rendered per session
  - Use REJECT (not DROP) for denied traffic to provide fast failure to the client
- Readiness gates: wait for each component (mitmproxy health, Envoy health, CoreDNS test query) before applying DNAT rules
- Startup ordering per the networking design: nftables deny-all -> mitmproxy -> Envoy -> CoreDNS -> nftables DNAT

**Exit criteria:** Gateway container starts on the session network with correct IP. nftables rules are injected. Health checks pass. Shutdown removes DNAT rules first, then stops components, then removes deny-all rules.

---

### M3-S4: VM networking integration

**Entry criteria:** M3-S3 complete.

**Tasks:**
- Update Lima template to connect VM to the gateway:
  - Connect VM's QEMU TAP device to the session's Docker bridge
  - Static IP assignment on the /30 (VM gets .2)
  - Default route to gateway (.1)
  - `/etc/resolv.conf` points to gateway IP
  - Disable IPv6 on the VM NIC
- Verify: VM can ping the gateway IP, DNS queries reach CoreDNS

**Exit criteria:** VM boots with networking through the Docker bridge. VM can reach the gateway. DNS queries from the VM arrive at CoreDNS (visible in CoreDNS logs).

---

### M3-S5: CA certificate lifecycle

**Entry criteria:** M3-S4 complete (VM connected to gateway).

**Tasks:**
- sandboxd generates per-session CA keypair at session create time, writes to `~/.sandboxd/sessions/{session_id}/ca/` (cert.pem + key.pem)
- Inject CA cert (public only) into VM via cloud-init:
  - System trust store
  - Environment variables (`SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE`, `NODE_EXTRA_CA_CERTS`, `CURL_CA_BUNDLE`)
  - Docker daemon trust store
- Mount CA private key into gateway container as read-only volume for mitmproxy
- Verify: curl from VM to an HTTPS site goes through mitmproxy (check mitmproxy logs for the request, verify cert chain shows mitmproxy CA)

**Exit criteria:** Per-session CA is generated and trusted inside the VM. HTTPS traffic from the VM is intercepted by mitmproxy using the session CA. mitmproxy logs show the request and the cert chain includes the mitmproxy CA.

---

### M3-S6: Session orchestration and E2E

**Entry criteria:** M3-S5 complete.

**Tasks:**
- Wire the full session create flow:
  1. Allocate session, create network
  2. Create and start gateway container
  3. Inject nftables rules, wait for readiness
  4. Create and start VM (connected to same bridge)
  5. Wait for vsock connectivity
  6. Report Running
- Wire session stop/rm teardown in correct order
- Extend daemon `start` handler to include network and gateway recreation: recreate per-session network with the session's deterministic /30 subnet, create and start gateway container and pipeline, start the Lima VM (boots from preserved disk state), wait for vsock connectivity, report Running
- Extend daemon startup reconciliation to cover gateway containers and per-session networks (not just VMs)
- Implement `sandbox logs <session> [--component <name>]` — tail gateway container logs (Envoy, mitmproxy, CoreDNS) via `docker logs` or reading log files from the gateway volume
- Implement periodic health monitoring: poll gateway components (nftables rules present, Envoy health, mitmproxy health, CoreDNS responds to test query). Update session health status. Wire into `sandbox ps` output.
- Implement gateway crash detection via Docker container events. On crash: restart gateway container, re-inject nftables rules, log the recovery. VM networking resumes automatically (same gateway IP on /30).
- Add `docs/networking.md` — user-level networking guide: how traffic flows through the gateway, what gets intercepted, how DNS works. Written for users, not implementers.
- E2E tests in `tests/e2e/test_m3_networking.py`:
  - `test_gateway_traffic_flow` — create session, curl an allowed HTTPS endpoint from inside VM, verify it succeeds and goes through mitmproxy (check mitmproxy logs)
  - `test_denied_traffic` — attempt direct connection from VM to an IP that would bypass the pipeline — verify nftables blocks it. At M3, the pipeline is pass-through (no policy engine), so this tests topology enforcement, not policy denial.
  - `test_dns_interception` — resolve a domain from inside VM, verify it goes through CoreDNS (check CoreDNS logs)
  - `test_stop_start_with_networking` — create session, pull a Docker image, stop, start, verify Docker image persists and networking works
  - `test_concurrent_sessions` — create two sessions, verify both work independently, verify no IP conflicts, verify no cross-session traffic
  - `test_daemon_restart_recovery` — create a session, kill sandboxd, restart it, verify session is recovered and functional
  - `test_gateway_crash_recovery` — kill gateway container, verify sandboxd restarts it, verify nftables rules are re-injected, verify traffic flows again
- Verify all M1 and M2 E2E tests still pass

**Exit criteria:** Full session lifecycle works: create provisions VM with networking through gateway. Traffic from VM flows through the gateway pipeline. Allowed HTTPS works, direct IP access is denied, DNS goes through CoreDNS. All previous E2E tests pass.

---

## M4: Policy Engine

### M4-S1: Policy schema and level 0+1 compilation

**Entry criteria:** M3 complete (gateway pipeline operational).

**Tasks:**
- Define policy schema in `sandbox-core`:
  - Versioned document (semver)
  - Rules: list of policy entries, each with: destination (domain or IP), assurance level (0-3), protocol (TCP/UDP/HTTP/HTTPS), optional method/path constraints (level 3 only), optional reason (for bypasses)
  - Presets: common policy bundles (e.g., "allow-github", "allow-npm-registry")
  - JSON Schema document generated from the Rust types (using `schemars` or manual)
- Define config file interfaces consumed by gateway components: CoreDNS policy file format, mitmproxy policy config format. These formats are the contracts that M4-S3 (CoreDNS plugin) and M4-S4 (mitmproxy addon) implement against.
- Implement policy compiler framework in `sandbox-core`:
  - `PolicyCompiler::compile(policy) -> CompiledPolicy`
  - `CompiledPolicy` contains: nftables rules, Envoy filter chain config, mitmproxy addon config, CoreDNS plugin config
  - Validation: reject unknown schema versions, reject contradictory rules, reject level 3 for non-HTTP protocols
- Nftables rule generation:
  - Deny-by-default + IP/port allow rules for level 1
  - UDP allow/deny rules (level 1)
  - TCP redirect to Envoy (level 1)
- Envoy config generation for level 1:
  - Filter chain match by destination IP+port
  - Opaque TCP passthrough to destination
- Unit tests: schema validation, level 0 denial, level 1 TCP passthrough

**Exit criteria:** Policy schema is defined with JSON Schema. Config file interfaces for CoreDNS and mitmproxy are defined. Compiler produces correct nftables and Envoy configs for level 0 and level 1 policies. Unit tests cover each level and edge cases.

---

### M4-S2: Level 2+3 compilation

**Entry criteria:** M4-S1 complete.

**Tasks:**
- Envoy config generation for level 2:
  - TLS passthrough with SNI extraction/validation
  - Filter chain match by SNI
- Envoy config generation for level 3:
  - Forward to mitmproxy
- mitmproxy config generation:
  - Per-destination rules: allowed hosts, methods, paths
  - Deny-by-default for unmatched requests
- Unit tests: level 2 TLS config, level 3 HTTP inspection config

**Exit criteria:** Compiler produces correct Envoy and mitmproxy configs for level 2 and level 3 policies. Unit tests cover each level and edge cases.

---

### M4-S3: CoreDNS policy plugin (Go)

**Entry criteria:** M4-S1 complete (config file interfaces defined).

**Tasks:**
- Implement custom CoreDNS plugin in `networking/coredns-plugin/`:
  - Plugin name: `sandboxpolicy` (or similar)
  - Config file: list of allowed domains, loaded from a file that sandboxd writes (format defined in M4-S1)
  - On query: if domain is in allowed list, forward upstream and return result; otherwise return NXDOMAIN
  - Strip AAAA records from all responses (IPv4-only)
  - Strip HTTPS/SVCB records carrying ECHConfig (ECH stripping)
  - Log all queries (domain, result, resolved IPs)
  - Report resolved IPs: write domain->IP mappings to a file or expose via an API for sandboxd to consume
  - Config reload: watch config file for changes (inotify or polling), reload without restart
- Build CoreDNS with the custom plugin (follow CoreDNS external plugin build pattern)
- Update gateway Dockerfile to use the custom CoreDNS build
- Unit tests (Go): allowed domain resolves, denied domain gets NXDOMAIN, AAAA stripping, ECH stripping, config reload
- Integration test: run CoreDNS with plugin, query allowed domain, query denied domain

**Exit criteria:** CoreDNS with custom plugin builds. Allowed domains resolve, denied domains get NXDOMAIN. AAAA and ECH records are stripped. Resolved IPs are reported. Config reload works without restart.

---

### M4-S4: mitmproxy policy addon (Python)

**Entry criteria:** M4-S1 complete (config file interfaces defined).

**Tasks:**
- Implement mitmproxy addon in `networking/mitmproxy/policy_addon.py`:
  - Load policy config from file (JSON, written by sandboxd, format defined in M4-S1)
  - On HTTP request: validate `Host`/`:authority` against allowed hosts
  - On HTTP request: validate method and path against policy rules (if level 3 with constraints)
  - Deny: return HTTP 599 with body identifying sandbox policy denial
  - Log all requests: method, host, path, decision (allow/deny)
  - Config reload: watch file for changes, reload without restart
  - Health endpoint: simple `/health` that returns 200
- Update gateway mitmproxy startup to load the addon
- Unit tests (Python): host validation, method/path constraints, deny response format, config reload
- Integration test: run mitmproxy with addon, send allowed request (passes), send denied request (gets 599)

**Exit criteria:** mitmproxy addon enforces host-level and method/path-level policy. Denied requests get HTTP 599. Config reload works. Health endpoint responds.

---

### M4-S5: DNS-to-IP propagation and policy distribution

**Entry criteria:** M4-S1, M4-S2, M4-S3, and M4-S4 complete.

**Tasks:**
- Implement DNS-to-IP propagation in `sandboxd`:
  - Read resolved IP mappings from CoreDNS plugin (file or API)
  - Maintain TTL-aware domain->IP cache
  - On IP change: update nftables rules (add new IPs, remove old IPs)
  - On IP change: update Envoy filter chain config (destination match)
  - On resolution failure: remove IPs for failed domain (fail-closed), log, update health
  - Re-resolve on TTL expiry with configurable max interval
- Implement `sandbox policy update <session> <policy-path>`:
  - Compile new policy
  - Distribute configs to gateway components (write files, trigger reload)
  - Update nftables rules
  - Wait for component readiness
  - Policy distribution must be atomic — rollback on partial failure. If any component fails to load the new config, revert all components to the previous config.
- Implement policy loading at session create time (`--policy` flag)
- Wire DNS propagation loop into daemon (background task per session)

**Exit criteria:** Policy is compiled and distributed to all components. DNS resolution triggers nftables IP rule updates. Policy update command works live. IP propagation handles TTL expiry and resolution failure correctly.

---

### M4-S6: Policy E2E tests

**Entry criteria:** M4-S5 complete.

**Tasks:**
- Write comprehensive E2E tests for all 4 assurance levels in `tests/e2e/test_m4_policy.py`:
  - `test_level0_denied` — request to a non-allowed domain is denied (NXDOMAIN from DNS, connection refused from nftables)
  - `test_level1_transport_tcp` — allowed TCP connection to a declared level-1 destination succeeds as opaque TCP
  - `test_level1_transport_udp` — allowed UDP to a declared level-1 destination succeeds
  - `test_level2_tls_verified` — allowed TLS connection to a declared level-2 destination succeeds without interception (cert is real, not mitmproxy CA)
  - `test_level3_http_inspected` — allowed HTTPS request to a declared level-3 destination succeeds through mitmproxy (cert is mitmproxy CA)
  - `test_level3_host_mismatch` — request with mismatched Host header is denied (599)
  - `test_level3_method_restriction` — disallowed HTTP method is denied
  - `test_level3_path_restriction` — disallowed path is denied
  - `test_policy_update` — change policy live, verify new rules take effect
  - `test_dns_nxdomain` — resolve denied domain, get NXDOMAIN
  - `test_dns_ip_propagation` — allowed domain's resolved IP is added to nftables
- Add `docs/policy.md` — policy authoring guide: how to write a policy file, assurance levels explained with examples, common presets, how to apply and update policies
- Verify all M1, M2, M3 E2E tests still pass

**Exit criteria:** All E2E tests pass across all 4 assurance levels. Policy changes take effect live. DNS propagation works. All previous E2E tests still pass.

---

## M5: Workspace Provisioning

### M5-S1: Clone mode and `sandbox cp`

**Entry criteria:** M4 complete (policy works, HTTPS through gateway works).

**Tasks:**
- Implement clone mode (default workspace provisioning):
  - `sandbox create --repo <url>` clones the repo during boot command phase
  - Relies on level 3 policy allowing the git host (e.g., github.com)
  - Clone runs inside VM via cloud-init boot command or vsock exec
  - Workspace at `/home/agent/workspace/`
- Implement `--boot-cmd <cmd>` flag on create — execute command inside VM after boot (via vsock exec)
- Implement `sandbox cp`:
  - `sandbox cp <local-path> <session>:<remote-path>` (host to VM)
  - `sandbox cp <session>:<remote-path> <local-path>` (VM to host)
  - Transfer over vsock (not through proxy pipeline)
  - Use rsync or tar-over-vsock for efficiency
  - Path validation: VM-side paths must be within allowed directories (prevent path traversal)
  - Bounded transfer size (configurable)
- Implement vsock file transfer protocol:
  - Extension to the vsock protocol from M2: `FileTransfer { direction, path, data }` / `FileTransferResult`
  - Chunked transfer for large files
  - VM-side agent handles file I/O
- E2E tests in `tests/e2e/test_m5_workspace.py`:
  - `test_clone_repo` — create session with `--repo`, verify repo is available at `/home/agent/workspace/`
  - `test_cp_host_to_vm` — copy a file into the VM, verify contents
  - `test_cp_vm_to_host` — copy a file from the VM, verify contents
- Verify all previous E2E tests pass

**Exit criteria:** `sandbox create --repo <url>` clones the repo. `sandbox cp` transfers files both directions over vsock. E2E tests pass.

---

### M5-S2: Git remote over vsock

**Entry criteria:** M5-S1 complete.

**Tasks:**
- Implement git-over-vsock transport:
  - Host-side: `sandbox git <session>` exposes a git remote URL (e.g., `ext::sandbox git-remote %S <session>`)
  - VM-side: the vsock agent acts as a git transport helper, forwarding git protocol to a local bare repo or working tree
  - Standard git push/pull workflow works
  - sandboxd validates VM-side paths (no path traversal)
- Update vsock protocol:
  - `GitUploadPack` / `GitReceivePack` message types
  - Stream-based (git protocol is bidirectional streaming)
  - Bounded per-stream
- E2E tests in `tests/e2e/test_m5_git_remote.py`:
  - `test_git_push_from_vm` — make a commit inside the VM, git push over vsock, verify on host
  - `test_git_pull_to_vm` — push a branch from host, git pull inside VM, verify
- Verify all previous E2E tests pass

**Exit criteria:** Bidirectional git operations work over vsock. E2E tests pass. All previous tests pass.

---

### M5-S3: Shared mount mode (virtio-fs)

**Entry criteria:** M5-S2 complete.

**Tasks:**
- Implement `--workspace shared:<host-path>` flag on create:
  - Configure Lima virtio-fs mount from host directory to `/home/agent/workspace/` in VM
  - This is opt-in — adds virtio-fs device to the VM, which expands the attack surface (documented trade-off)
  - Mutually exclusive with `--repo` (clone mode)
- Update Lima template generation to conditionally add virtio-fs mount
- Bidirectional file visibility: changes on host are immediately visible in VM and vice versa
- Add `docs/workspaces.md` — workspace modes guide: clone (default), git-over-vsock, shared mount (virtio-fs), `sandbox cp` usage
- E2E tests:
  - `test_shared_mount` — create session with shared mount, write a file on host, verify visible in VM; write a file in VM, verify visible on host
- Verify all previous E2E tests pass

**Exit criteria:** `sandbox create --workspace shared:/path/to/project` mounts the host directory into the VM via virtio-fs. Bidirectional file visibility works. E2E tests pass. All previous tests pass.

---

## M6: Hardening

### M6-S1: QEMU sandboxing

**Entry criteria:** M5 complete.

**Tasks:**
- Configure QEMU process hardening on Linux:
  - Unprivileged user for QEMU process
  - Seccomp: `-sandbox on,obsolete=deny,elevateprivileges=deny,spawn=deny`
  - Namespace isolation: mount, PID, IPC
  - Cgroup limits: CPU, memory, PIDs
- Update Lima template to pass QEMU hardening flags
- Verify VM still boots and operates correctly with hardening enabled
- E2E tests: all existing tests pass with QEMU sandboxing active

**Exit criteria:** QEMU runs as unprivileged user with seccomp, namespaces, and cgroup limits. All existing E2E tests pass.

---

### M6-S2: Device model lockdown

**Entry criteria:** M5 complete.

**Tasks:**
- Verify minimal device model in Lima template:
  - Only virtio-net, virtio-blk, virtio-rng, virtio-vsock
  - No USB, display, sound, floppy, legacy ISA, virtio-serial
- Explicitly disable unnecessary devices in QEMU command line
- Test that VM functions correctly with minimal device model
- E2E tests: all existing tests pass with locked-down device model

**Exit criteria:** VM boots with exactly 4 virtio devices. No unnecessary devices present. All existing E2E tests pass.

---

### M6-S3: Hardening E2E and verification

**Entry criteria:** M6-S1 and M6-S2 complete.

**Tasks:**
- Run full E2E suite with all hardening enabled
- Document hardening configuration (as code comments and config file comments, not separate docs)
- Update `docs/README.md` with hardening section: what's enabled by default, QEMU sandboxing details for operators

**Exit criteria:** All hardening active. Full E2E suite passes. Hardening is the default, not opt-in.

---

## M7: Documentation

### M7-S1: User documentation

**Entry criteria:** M6 complete (all features on Linux working and hardened).

**Tasks:**
- Polish and consolidate all docs written during M0-M6 into a coherent documentation set
- `docs/README.md` — project overview, prerequisites, installation, quickstart (revise and polish)
- `docs/installation.md` — detailed installation guide: building from source, Lima setup, Docker setup, KVM verification, first run
- `docs/cli-reference.md` — complete CLI reference for all commands: create, start, stop, rm, ps, ls, ssh, cp, logs, policy update. Each command with synopsis, options, examples
- `docs/networking.md` — revise and expand: architecture overview for operators, traffic flow, gateway components, health monitoring, troubleshooting
- `docs/policy.md` — revise and expand: full policy reference, schema documentation, all assurance levels with examples, bypass framework, presets
- `docs/workspaces.md` — revise and expand: all three modes with trade-offs, setup instructions, examples
- `docs/hardening.md` — operator guide: what's hardened by default, QEMU sandboxing, device model, guest OS hardening, how to enable optional hardening (custom kernel, non-root agent)
- `docs/architecture.md` — high-level architecture overview for contributors and operators: how components fit together, session lifecycle, security model summary. Not a copy of the design docs — a readable orientation document
- `docs/troubleshooting.md` — common issues and solutions: VM won't boot, gateway health check fails, TLS interception errors, DNS resolution issues

**Exit criteria:** A new user can install, configure, and use the sandbox by following the docs alone. An operator can understand the security model and hardening options. All docs are internally consistent and cross-referenced.

---

## M8: Polish and Deferred TODOs

### M8-S1: Logging and error quality

**Entry criteria:** M7 complete.

**Tasks:**
- Audit logging quality: consistent log levels across all components, structured log fields, no sensitive data leaked in logs, useful context in error paths
- Review error messages for actionability: user-facing errors should guide the user toward resolution, not expose raw internal details
- Add useful debug-level logs at key decision points and state transitions to support troubleshooting without requiring code changes

**Exit criteria:** All components use consistent, structured logging. No sensitive data in logs. User-facing errors are actionable. Key decision points have debug-level logs.

---

### M8-S2: Code cleanup and verification

**Entry criteria:** M8-S1 complete.

**Tasks:**
- Clean up technical debt: dead code, unused dependencies, inconsistent error messages, stale configuration
- Verify all E2E tests pass as a suite (not just individually per-milestone)
- Cross-check CLI help text, error messages, and log output for consistency and clarity
- Final review of `docs/` for accuracy against actual implementation (docs written during M7-S1 may reference planned behavior that diverged during implementation)

**Exit criteria:** All E2E tests pass as a full suite. CLI output is consistent. Documentation matches implemented behavior.

---

### M8-S3: Deferred TODOs

**Entry criteria:** M8-S2 complete.

**Tasks:**
- Review and resolve any TODO/FIXME/HACK markers accumulated in the codebase during M0–M7
- Address medium-severity review findings from the session plan review that were deferred during implementation (e.g., session sizing issues, dependency clarifications, E2E coverage gaps)

**Exit criteria:** No unresolved TODO/FIXME/HACK markers remain without explicit justification. All deferred review findings addressed or explicitly documented as out of scope. The Linux implementation is release-ready.

---

## M8.5: E2E Fix-up — Portability, Privilege Model, and Runtime Correctness

> **Remediation milestone.** M0–M8 wrote E2E tests but never ran them against real infrastructure. Running them revealed gateway container failures, QEMU wrapper portability issues, and a fundamental privilege model problem: the daemon was designed assuming root access, but Lima refuses root. This milestone redesigns the privilege model (no root, no sudo) and fixes all runtime issues.
>
> **Key architectural decision:** sandboxd runs as a regular user (docker + kvm groups). Privileged operations are handled by purpose-built mechanisms: `qemu-bridge-helper` (setuid, ships with QEMU) for TAP device creation, `docker exec` with `CAP_NET_ADMIN` for nftables inside the gateway container. No sudo, no sudoers, no root daemon.

### M8.5-S1: Gateway fixes and privilege model design

**Entry criteria:** M8 complete. Gateway container fails to start; QEMU wrapper has portability issues; privilege model needs redesign.

**Tasks (completed):**
- Fix CoreDNS plugin Corefile parser: removed `c.NextArg()` guard that rejected `{` as unexpected argument.
- Add tmpfs mounts: `/etc/coredns:rw`, move Corefile to `/opt/coredns/Corefile`.
- Move mitmproxy policy path to `/tmp/mitmproxy/policy.json` (already on tmpfs).
- Fix QEMU wrapper: PATH resolution, probe passthrough, self-recursion prevention, cgroup headroom, remove `-no-hpet`.
- Fix limactl PATH resolution (no hardcoded paths).
- Simplify `parse_limactl_error` to preserve raw stderr.
- **Design decisions:** Reversed root-daemon architecture after discovering limactl refuses root. Evaluated three approaches: (A) regular user + targeted sudo, (B) root daemon + privilege de-escalation for Lima, (C) regular user + docker exec + qemu-bridge-helper. Chose (C) — strictly better security, no sudo/sudoers/setuid in sandboxd.

**Exit criteria:** Gateway image builds clean. Rust workspace compiles. Privilege model design decided and documented.

---

### M8.5-S2: Privilege model implementation — docker exec and qemu-bridge-helper

**Entry criteria:** M8.5-S1 complete. Design decided: no root, docker exec for nftables, qemu-bridge-helper for TAP.

**Tasks:**
- **Gateway container (Dockerfile):** Add `nftables` package so `nft` is available inside the container.
- **gateway.rs — docker exec for nftables:**
  - Replace `inject_nftables_ruleset()`: change from `nsenter --net=/proc/{pid}/ns/net nft -f -` to `docker exec -i <container> nft -f -`. Remove `container_pid()` method (no longer needed).
  - Add `CAP_NET_ADMIN` to container creation (`--cap-add NET_ADMIN` in docker run args).
  - Update all nftables injection call sites (deny-all, DNAT, policy).
  - Update gateway.rs doc comments to reflect docker exec model.
- **policy_distributor.rs — docker exec for reads/writes:**
  - Replace nsenter-based `read_nftables_state()` with `docker exec <container> nft list table ...`.
  - Replace nsenter-based policy file writes with `docker exec -i <container> tee /path/to/file`.
- **network.rs — qemu-bridge-helper for TAP:**
  - Remove entire host-side bridge/TAP/veth setup (`run_privileged()` calls, `run_nsenter()` calls).
  - Remove `run_privileged()` and `run_nsenter()` helper functions.
  - Configure QEMU second NIC via Lima template to use `-netdev bridge,br=<docker_bridge>` which invokes `qemu-bridge-helper`.
  - Update `NetworkInfo` struct if bridge/TAP/veth fields are no longer needed.
  - Ensure `/etc/qemu/bridge.conf` allows the Docker bridge (document in installation.md).
- **lima.rs — QEMU wrapper update:**
  - Update QEMU wrapper script to handle bridge-based networking (no manual TAP creation).
- **main.rs — remove root model:**
  - Remove `is_running_as_root()` function and root check.
  - Remove sandbox group / socket permission code. Socket uses default permissions in user's home dir (`~/.sandboxd/`).
- **conftest.py — remove sudo:**
  - Remove `sudo` from daemon launch (`Popen`).
  - Remove `sudo kill` from teardown.
  - Remove `groupadd` setup.
- **Update tests:** Fix any unit tests that reference nsenter, run_privileged, or root.

**Exit criteria:** `cargo build --workspace` compiles clean. `cargo test --workspace` passes. No references to nsenter, sudo, run_privileged, or is_running_as_root remain in non-test production code. Gateway container starts with `CAP_NET_ADMIN`. Single E2E test (`test_create_and_destroy`) passes.

---

### M8.5-S3: Full E2E suite green and documentation update

**Entry criteria:** M8.5-S2 complete. Single VM lifecycle test passes with new privilege model.

**Tasks:**
- Run the full E2E suite (`make test-e2e`) and fix any remaining failures.
- Expected areas: networking (bridge-helper integration, Docker bridge discovery), policy distribution (docker exec writes), workspace provisioning.
- Add pre-flight checks to `conftest.py`: Docker accessible, KVM available, Lima installed, gateway image exists, `qemu-bridge-helper` installed. Skip with clear message if prerequisites missing.
- Update documentation:
  - `installation.md`: remove root daemon / sandbox group sections; document docker + kvm group membership; document qemu-bridge-helper setup and `/etc/qemu/bridge.conf`.
  - `networking-design.md` / `sandbox-design.md`: update privilege model sections to reflect docker exec + bridge-helper architecture.
  - `hardening.md`: update security layer table.

**Exit criteria:** All E2E tests pass. Documentation reflects the actual privilege model. No manual setup beyond group membership, `make gateway-image`, `cargo build`, and bridge.conf is required.

### M85-S4: Comprehensive review

**Entry criteria:** M8.5-S3 complete. 30/30 E2E tests pass. All docs updated.

**Tasks — 5 parallel review tracks:**

1. **Implementation vs plan review.** Compare the final implementation against what was originally planned in each milestone (M0–M8.5). Identify: features delivered as planned, features that diverged (and why), features dropped, features added beyond the plan.

2. **Code quality review.** Review all Rust code in `sandboxd/` for: error handling, resource cleanup, naming consistency, dead code, unnecessary complexity, unsafe patterns, and adherence to idiomatic Rust.

3. **Unit tests quality review.** Review all unit tests for: tautological assertions (tests that pass by construction, not by testing real behaviour), coverage gaps, test isolation, and meaningful assertions. Set up code coverage reporting (`cargo-tarpaulin` or similar) and identify under-tested modules.

4. **E2E tests quality review.** Review all E2E tests in `tests/e2e/` for: tautological assertions, coverage of edge cases, brittleness (timing-dependent assertions, race conditions), cleanup reliability, and whether the tests actually exercise the feature they claim to test.

5. **Documentation quality review.** Review all docs in `docs/` for: accuracy against the actual implementation, completeness, internal consistency, broken references, and stale content.

**Exit criteria:**
- All review findings fixed (code, tests, docs).
- Report of the final implementation against what was originally planned and promised.

---

## M9: User Polish and Refactors

### M9-S1: XDG Base Directory Specification

**Entry criteria:** M8.5 complete.

**Tasks:**
- Replace hardcoded `~/.sandboxd/` with XDG-compliant paths:
  - `$XDG_DATA_HOME/sandboxd/` (default `~/.local/share/sandboxd/`) — session database, Lima VM data, CA certificates
  - `$XDG_CONFIG_HOME/sandboxd/` (default `~/.config/sandboxd/`) — configuration files
  - `$XDG_RUNTIME_DIR/sandboxd/` (default `/run/user/$UID/sandboxd/`) — Unix socket, PID file, transient runtime state
- Update `default_socket_path()` and `default_base_dir()` in `sandboxd/src/main.rs`
- Update CLI `--socket` default and any path references in sandbox-cli
- Update Lima template paths if they reference the base directory
- Update docs to reflect new default paths
- Ensure backwards compatibility: if `~/.sandboxd/` exists and XDG dirs don't, log a migration hint
- Update E2E test helpers if they reference `~/.sandboxd/`
- Update unit tests for path defaults

**Exit criteria:** All paths follow XDG spec. Socket in `$XDG_RUNTIME_DIR`, data in `$XDG_DATA_HOME`, config in `$XDG_CONFIG_HOME`. All tests pass. Old `~/.sandboxd/` no longer created on fresh installs.

---

### M9-S2: Root-level documentation

**Entry criteria:** M9-S1 complete.

**Tasks:**
- Create root-level `README.md`:
  - Project description: what sandboxd is and what problem it solves
  - Architecture overview: daemon, CLI, guest agent, gateway container
  - Prerequisites: Lima, QEMU, Docker, KVM
  - Quick start: build, run daemon, create a session
  - Link to `docs/` for detailed documentation
- Create root-level `CLAUDE.md`:
  - Project structure overview (crate names and roles, not file-by-file)
  - Build and test commands (`make build`, `make test`, `make test-e2e`, `make test-integration`)
  - Key architectural conventions (async handlers, spawn_blocking for process commands, error response pattern)
  - Pointer to `docs/session-plan.md` for implementation history
  - Keep it stable — describe conventions and structure, not current implementation details that change with each commit

**Exit criteria:** Both files exist at repo root. README gives a newcomer enough to build and try sandboxd. CLAUDE.md gives an AI coding agent enough context to navigate and contribute to the codebase without frequent updates.

---

### M9-S3: Timeout protection for session creation flow

**Entry criteria:** M9-S2 complete. Flaky E2E test (`test_dns_nxdomain`) identified — 50% failure rate due to `sandbox create` hanging indefinitely.

**Tasks:**
- Add HTTP request timeout in CLI (`sandbox-cli`): hard cap on request to daemon
- Add per-step timeouts in daemon create handler (`sandboxd/src/main.rs`):
  - Lima VM create/start
  - Guest agent install and ping
  - Docker network and gateway creation
  - NIC hot-add and guest network configuration
- Add timeouts to external process calls (`limactl`, `docker`) in sandbox-core
- Ensure timeout errors propagate clearly: log which step timed out
- Proper cleanup on timeout: if creation fails mid-way, clean up partial state
- Verify fix: run `test_dns_nxdomain` repeatedly to confirm stability

**Exit criteria:** All external process calls have bounded timeouts. CLI has HTTP timeout. Timeout failures report which step stalled. E2E test flakiness resolved.

---

## Risks

| Risk | Impact | Mitigation |
|------|--------|------------|
| Lima vsock support is incomplete or buggy | Blocks M2 | Verify vsock works in a manual Lima VM before starting M2. Fall back to SSH-over-IP as temporary bridge if needed. |
| Lima TAP-on-Docker-bridge networking doesn't work as expected | Blocks M3 | Test Lima network attachment to a Docker bridge manually before M3-S4. Lima's `networks` YAML stanza should support this. |
| nftables injection into gateway container namespace is fragile | Blocks M3 | Prefer `nsenter --net` over `docker exec` for reliability. Test the injection approach in isolation before M3-S3. |
| CoreDNS external plugin build process is complex | Delays M4-S3 | Follow the documented external plugin pattern exactly. Build in a Docker container for reproducibility. |
| Envoy filter chain config for 4 assurance levels is complex | Delays M4-S1/M4-S2 | Start with level 0 (deny) and level 1 (TCP passthrough) in M4-S1. Add level 2 and 3 in M4-S2. |
| socket_vmnet availability on macOS | Blocks F1 | socket_vmnet must be installed separately (Homebrew). Document as a prerequisite. Test early on a macOS machine. |
| QEMU hardening flags conflict with Lima's defaults | Delays M6 | Lima may set its own QEMU flags. Check for conflicts. May need to use Lima's `qemu.args` override mechanism. |

## Completed session count

| Milestone | Sessions |
|-----------|----------|
| M0 | 1 |
| M1 | 4 |
| M2 | 3 |
| M3 | 6 |
| M4 | 6 |
| M5 | 3 |
| M6 | 3 |
| M7 | 1 |
| M8 | 3 |
| M8.5 | 4 |
| M9 | 3 |
| **Total** | **37** |

---

## Future Milestones

### F1: macOS Support (2 sessions)

> **Separate track.** macOS support requires access to macOS hardware and can be executed independently. It is not on the critical path for Linux-only deployments.

#### F1-S1: socket_vmnet and Colima integration

**Entry criteria:** M5 complete.

**Tasks:**
- Implement macOS-specific `NetworkManager`:
  - socket_vmnet pool management: pre-provision N instances at daemon startup
  - Claim/release vmnet slots at session start/stop
  - Pool exhaustion detection and error reporting
- Implement Colima management in sandboxd:
  - Create/start sandboxd-managed Colima instance (separate from user's Docker)
  - Non-default socket path (`~/.sandboxd/colima/docker.sock`)
  - NIC attach/detach to vmnet instances
  - Colima health monitoring and crash recovery
- Implement macOS-specific gateway deployment:
  - macvlan (private mode) on the vmnet-facing Colima NIC
  - Gateway container on the macvlan network
  - Same gateway image as Linux
- Platform detection: runtime check, select Linux or macOS `NetworkManager`
- Update Lima template for macOS:
  - Apple VZ backend
  - Connect to session's vmnet instance
  - Same cloud-init provisioning as Linux
- E2E tests: run the full existing E2E suite on macOS

**Exit criteria:** All existing E2E tests pass on macOS. socket_vmnet pool works. Colima is managed automatically. Gateway containers deploy correctly via macvlan.

---

#### F1-S2: Colima failure recovery and cross-platform consolidation

**Entry criteria:** F1-S1 complete.

**Tasks:**
- Implement Colima crash detection and recovery:
  - Monitor Colima VM health
  - On crash: restart Colima, recreate all gateway containers, re-inject nftables rules
  - Sessions experience networking interruption but recover
- Test Colima failure scenarios:
  - Kill Colima, verify recovery
  - Verify sessions remain usable after recovery
- Cross-platform test matrix documentation
- Verify all E2E tests pass on both Linux and macOS

**Exit criteria:** Colima crash recovery works. All E2E tests pass on both platforms.
