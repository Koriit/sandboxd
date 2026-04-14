# Final Review Report

**Date:** 2026-04-14
**Scope:** M85-S4 comprehensive review — implementation vs plan, code quality, unit tests, E2E tests, documentation

## Implementation vs Plan

### Linux critical path (M0–M8.5): 100% complete

All 10 milestones delivered:

| Milestone | Status | Notes |
|-----------|--------|-------|
| M0: Project scaffolding | Complete | 4 crates, Makefile, CI placeholder, docs structure |
| M1: sandboxd + Lima VM lifecycle | Complete | CLI, HTTP API, SessionStore (SQLite), LimaManager |
| M2: Guest agent | Complete | TCP-over-SSH transport, exec, file transfer, git protocol |
| M3: Gateway + networking | Complete | Docker bridge, Envoy/mitmproxy/CoreDNS, nftables, crash recovery |
| M4: Policy engine | Complete | 4 assurance levels, CoreDNS plugin, mitmproxy addon, live updates |
| M5: Workspace provisioning | Complete | Clone, shared mount (9p), `sandbox cp`, git remote transport |
| M6: Hardening | Complete | QEMU seccomp, device lockdown, cgroup limits |
| M7: Documentation | Complete | 9 docs covering all aspects |
| M8: Polish | Complete | Structured logging, error handling, no outstanding TODOs |
| M8.5: Privilege model fix-up | Complete | No root/sudo, docker exec for nftables, qemu-bridge-helper |

### Justified divergences from plan

| Planned | Implemented | Reason |
|---------|-------------|--------|
| Kernel vsock for guest agent | TCP-over-SSH via `limactl shell` + `socat` | Lima doesn't support AF_VSOCK; TCP-over-SSH is simpler and transport-agnostic |
| virtio-fs for shared mounts | 9p built into QEMU | virtiofs requires virtiofsd + memfd, incompatible with QEMU seccomp sandbox |
| QMP NIC hot-add | qemu-bridge-helper at boot | Simpler, avoids boot-time delay, no QMP complexity |
| Host-side nftables via sudo/nsenter | docker exec with CAP_NET_ADMIN | Eliminates all sudo/root requirements |

### Features added beyond plan

- Health endpoint (`GET /sessions/{id}/health`)
- Session reconciliation on daemon startup
- Gateway crash recovery (automatic restart)
- Health monitoring background loop
- Comprehensive E2E preflight checks

### Not implemented (expected)

- M9: macOS support (socket_vmnet, Colima, VZ backend) — explicitly deferred per plan

## Findings Fixed

### Code quality (4 fixes)
1. **`envoy_written` flag never set** — rollback tracking was dead code. Fixed.
2. **Shell metacharacter risk** in `write_file_to_container` — path now quoted.
3. **7 tautological unit tests removed** — gateway construction, QMP JSON self-equality, policy_distributor defaults.
4. **Weak timestamp assertion** — `>=` changed to `>` to match test intent.

### E2E tests (4 fixes)
1. **Missing UDP assertion** in `test_denied_traffic` — UDP traffic blocking was completely untested.
2. **False-pass metadata assertion** in `test_denied_traffic` — `or`-logic allowed test to pass when endpoint was reachable.
3. **False-pass HTTP assertion** in `test_level0_denied` — same `or`-logic issue.
4. **Helper duplication** — 9 functions duplicated across 6 test files, extracted to conftest.py.

### Documentation (8 fixes)
1. **Non-existent `--force` flag** referenced in troubleshooting.md.
2. **Stale vsock references** in README (4 places), cli-reference (1 place).
3. **Stale nsenter commands** in troubleshooting.md (2 places), policy.md (1 place).
4. **Stale QMP hot-add reference** in troubleshooting.md.
5. **Incorrect MemoryMax** in hardening.md (4096M → 4608M with 512MB headroom).
6. **Incorrect mitmproxy listen address** in networking.md (127.0.0.1 → 0.0.0.0).
7. **Source doc comments** still said "virtio-fs" in 3 files — updated to "9p".
8. **"git-over-vsock" naming** — renamed to "git remote transport" throughout workspaces.md.

## Deferred Items Resolved (M85-S5)

All 4 deferred items from the review have been resolved:

1. **Blocking I/O on async threads** — All `std::process::Command` calls in HTTP handlers wrapped in `tokio::task::spawn_blocking`. Handlers use match on `Ok(Ok(v))/Ok(Err(e))/Err(e)` pattern since `impl IntoResponse` doesn't support `?`.
2. **Duplicated CA injection logic** — Extracted `inject_ca_into_vm` async helper called from both `setup_session_networking` and `restore_session_networking`.
3. **Git remote tests don't test actual transport** — Rewritten to use proper `git-remote-sandbox` remote helper with `sandbox::` URLs. Tests exercise real host-to-VM git push/fetch through the daemon via SSH tunnel.
4. **sandboxd daemon binary has zero unit tests** — Added 15 unit tests covering `error_response` status code mapping, JSON body serialization, and utility functions.

### Additional improvements (M85-S5)

- **Proper git remote helper** — Replaced `ext::` transport (blocked by modern git) with `git-remote-sandbox` implementing the git remote helper protocol. Uses `connect` capability with bidirectional SSH transport via `sandbox ssh`.
- **5 new CLI unit tests** — URL parsing for the remote helper (`parse_remote_helper_url`).

## Review 2 Findings (M85-S8)

Comprehensive 6-track audit with cargo-llvm-cov code coverage analysis.

### Code quality (4 fixes)
1. **Clippy warning** — `vec_init_then_push` in policy.rs, replaced with array literal.
2. **`#[allow(dead_code)]` on unused field** — `prefix_len` in SubnetAllocator renamed to `_prefix_len`.
3. **`expect()` in HTTP handler** — could crash daemon on edge-case filesystem state. Replaced with proper error handling.
4. **Blocking `std::process::Command` in 3 async background loops** — `dns_propagation_loop`, `gateway_monitor`, `reconcile_networking` now use `spawn_blocking` (10+ call sites wrapped).

### Unit test quality (4 fixes)
1. **4 tautological tests removed** from gateway.rs — tested compiler-derived traits (PartialEq, Debug, Clone) and duplicated exact-value test.
2. **8 new unit tests added** — 6 for YAML path sanitization in lima.rs, 2 for symlink traversal protection in guest agent.

### E2E test quality (6 fixes)
1. **Created `test_m6_hardening.py`** — 3 new E2E tests for QEMU hardening verification (seccomp, device lockdown, cgroup limits, `--no-hardening` flag).
2. **Strengthened 4 "example" substring assertions** in test_m4_policy.py — now check for `"Example Domain"` instead of `"example"`.
3. **Strengthened TLS certificate verification** — now checks for Organization field in issuer, not just string presence.

### Security (2 fixes)
1. **YAML template injection** — SharedWorkspace `host_path` now validated against shell/YAML metacharacters before interpolation into Lima template.
2. **Symlink traversal in guest agent** — path validation now canonicalizes paths through symlinks and re-checks against allowlist. Handles non-existent paths by canonicalizing the nearest existing ancestor.

### Documentation (3 fixes)
1. **Wrong DB filename** — architecture.md said `sandboxd.db`, actual code uses `sessions.db`.
2. **Wrong session create ordering** — architecture.md listed VM before networking. Corrected: networking (Docker bridge) is created first so it exists at VM boot time for `qemu-bridge-helper`.
3. **Wrong E2E test count** — CLAUDE.md said "30 tests across 8 files", corrected to "33 tests across 7 files".

### Coverage report

| File | Line Coverage |
|------|-------------|
| policy.rs | 99.45% |
| api.rs | 100% |
| error.rs | 100% |
| session.rs | 98.26% |
| dns_propagation.rs | 87.41% |
| guest.rs (sandbox-guest) | 87.78% |
| store.rs | 85.44% |
| ca.rs | 81.31% |
| guest.rs (connector) | 82.83% |
| lima.rs | 58.10% |
| qmp.rs | 56.18% |
| network.rs | 48.26% |
| sandbox-cli/main.rs | 49.33% |
| vm_network.rs | 42.67% |
| gateway.rs | 22.97% (Docker integration) |
| sandboxd/main.rs | 8.00% (HTTP handlers) |
| policy_distributor.rs | 0% (Docker integration) |
| **TOTAL** | **62.77%** |

Low-coverage files are integration-heavy (Docker/Lima operations). The pure logic modules (policy, api, error, session, store) have excellent coverage.

## Final Numbers

| Metric | Value |
|--------|-------|
| Unit tests | 409 passing, 5 ignored |
| E2E tests | 33 (across 7 files) |
| Tautological tests removed | 11 total (7 in review 1, 4 in review 2) |
| Stale doc references fixed | 18+ |
| Bug fixes | 1 (envoy_written) |
| Security fixes | 3 (shell quoting, YAML injection, symlink traversal) |
| Async correctness fixes | 2 rounds (handlers in M85-S5, background loops in M85-S8) |
| Deferred items resolved | 4/4 |
| Overall line coverage | 62.77% |
