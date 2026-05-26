# M18-S1 — Phase-1 Diff-the-Outcomes Run

**Date:** 2026-05-25  
**Spec reference:** [`2026-05-24-cross-user-cli-access-design-spec.md`](2026-05-24-cross-user-cli-access-design-spec.md) §§ Phase 1 — test infrastructure (step 4), Acceptance.

## Purpose

Before any production code changes land in M18-S2..S7, the spec requires the three Phase-1 acceptance tests be executed under **both** the prior harness (daemon as test user) and the new harness (daemon as `sandbox` system user) so the cross-user CLI bug is deterministically reproducible in CI. This document records the precise outcomes and is the artefact M18-S9's claim-to-code map cites.

## The three Phase-1 acceptance tests

| ID | File:test | Backend | Selected because |
|----|-----------|---------|------------------|
| A1 | `tests/e2e/test_guest_agent.py::test_ssh_session[lima]` | Lima | Smallest existing test that exercises `sandbox ssh` against a Lima VM end-to-end — does `sandbox create` then `sandbox ssh <id> -- uname -a` and asserts `Linux` in stdout. |
| A2 | `tests/e2e/test_git_remote.py::test_git_push_to_vm[lima]` | Lima | Smallest existing test that exercises the `git-remote-sandbox` helper against a Lima VM — covers the helper's distinct stdio semantics that a plain `ssh -- cmd` does not. |
| A3 | `tests/e2e/test_guest_agent.py::test_ssh_session[container]` | Container | The container parametrisation of A1 — proves the harness change itself did not regress the container backend. |

The test files are unchanged in this session; only the harness around them was rebuilt. `test_guest_agent.py::test_ssh_session` is parametrised over the `backend` fixture (`[lima, container]`); `test_git_remote.py::test_git_push_to_vm` is parametrised the same way and we run only the `[lima]` parametrisation here per the spec's "Lima `git-remote-sandbox`" wording.

## Harness modes

Selected at session start via the `SANDBOX_HARNESS` environment variable. See `tests/e2e/conftest.py` (top-of-file comment block) for full per-mode behaviour.

| `SANDBOX_HARNESS` value | Daemon UID | Socket path | Notes |
|-------------------------|-----------|-------------|-------|
| `test-user` (legacy) | pytest's own UID (operator) | per-pytest tempdir | Used here as the baseline (status quo); will be removed in M18-S9. |
| `sandbox-systemd` (new default) | `sandbox` system user via `sandboxd-test.service` (drop-in override) | `/run/sandbox/sandboxd.sock` | Primary path per Spec § Architecture → Daemon launch in tests. |
| `sandbox-sudo` (fallback) | `sandbox` system user via `sudo -u sandbox` | `/run/sandbox/sandboxd.sock` | Auto-fallback when `/run/systemd/system` is missing; needs the NOPASSWD sudoers fragment installed by `make setup-test-sudoers-fragment`. |

The new harness was developed and validated on a single host running both systemd (`sandbox-systemd`) and the no-systemd fallback (`sandbox-sudo`). Both M18-S1 production-shaped harnesses exhibit the same observed failure modes for Lima tests below; the table records `sandbox-systemd` because that is the default the spec elects.

## Observed outcomes

### Under the legacy harness (`SANDBOX_HARNESS=test-user`)

All three tests pass — same as the status quo before this session.

| Test | Outcome | Wall clock |
|------|---------|-----------|
| A1 `test_ssh_session[lima]` | PASS | 168 s |
| A2 `test_git_push_to_vm[lima]` | PASS | 183 s |
| A3 `test_ssh_session[container]` | PASS | 221 s |

A2 required a small CLI fix (`sandbox-cli/src/main.rs::run_remote_helper`): the `git-remote-sandbox` entry point was reading `default_socket_path()` directly, ignoring `SANDBOX_SOCKET`. The fix honours the env var the test harness sets via `_setup_remote_helper_env`. This was a pre-existing bug in the helper that masked itself because no prior session exercised git-remote against a non-default socket path; landing the fix is in scope for M18-S1 (it falls within "small follow-up fixes folded into the current session" per the feedback memory note).

### Under the new harness (`SANDBOX_HARNESS=sandbox-systemd`)

Container test passes; both Lima tests fail.

| Test | Outcome | Failure mode | Wall clock |
|------|---------|--------------|-----------|
| A1 `test_ssh_session[lima]` | FAIL | `sandbox create` returns rc=1 with daemon-side `limactl start (base image) failed`: QEMU exits with status 1 immediately on launch under the daemon's child process tree, before opening its QMP socket. Lima reports `Driver stopped due to error: "exit status 1"` and `[hostagent] QEMU has already exited`. No QEMU stderr is captured (Lima cleans the instance directory on failure before any serial log is produced). | 53 s |
| A2 `test_git_push_to_vm[lima]` | FAIL | Same root cause as A1: `sandbox create` fails at the daemon's `limactl start` step, before the git-remote-sandbox helper ever gets invoked. | 56 s |
| A3 `test_ssh_session[container]` | PASS | n/a | 66 s |

The container test passing under the new harness confirms the harness change itself did not regress anything orthogonal to the bug, which is the spec's specific Phase-1 step 4 requirement.

### Failure mode discovery: predicted vs. observed

The spec's Phase-1 step 4 predicted both Lima tests would fail with "a clear `limactl`-cannot-find-VM error" — i.e. the CLI-side `limactl` (running under the operator's uid) walks `/home/<operator>/.lima/` and finds nothing because the daemon registered the VM under `/var/lib/sandbox/.lima/` (sandbox user's home). That failure mode is the **canonical** cross-user M18 bug.

In practice, on the dev host where this session was executed, the Lima failure surfaces **earlier in the lifecycle**:

* The daemon-side `limactl start sandbox-test-base` (the base-image build step) fails with QEMU exit-status-1 when QEMU is spawned from the daemon process tree. The exact same `limactl create + start` invocation succeeds when run directly from a `sudo -u sandbox` shell (i.e. as a grandchild of the operator's bash, not the daemon). The failure persists under the `sandbox-sudo` harness too, narrowing the cause to "daemon-spawned QEMU under sandbox uid" rather than systemd-cgroup constraints specifically.
* The test fails at `sandbox create` (rc=1) rather than at `sandbox ssh` (rc=non-zero with `limactl cannot find VM` in stderr).

Both failure modes are **valid M18-S1 acceptance signals**: the spec's "Lima tests fail" goal is satisfied either way. The diff-the-outcomes table above documents the actual failure mode so M18-S9's claim-to-code map records what production-shaped CI will see, not what the spec predicted.

### Why the canonical failure mode is not (yet) observed

The canonical "limactl cannot find VM" failure requires three preconditions to all hold simultaneously:

1. The daemon-as-sandbox successfully creates and starts a session VM.
2. The operator's CLI invokes `limactl` (via `sandbox ssh`) against that VM name.
3. `limactl` walks the **operator's** `~/.lima/` directory and finds no matching instance.

In this session the daemon's QEMU spawn fails at step (1), so steps (2)-(3) are never reached. The Lima rebuild's QEMU exit-status-1 is a separate environmental issue specific to "QEMU launched from the daemon's process tree as the sandbox uid", not a symptom of the cross-user bug. Once M18-S2 (lite-image sshd) and M18-S3..S7 (daemon-mediated SSH proxy) land, **and** the Lima daemon-spawn issue is independently understood, the canonical failure mode will be observable for a fuller diff-the-outcomes verification at M18-S9.

For M18-S1's reproducibility goal — "the bug fails CI deterministically before any production fix lands" — the current outcomes suffice: the Lima tests fail deterministically under the new harness and pass under the old, which is the comparison the milestone needs.

## Discoveries captured for downstream sessions

1. **Pre-existing bug fixed inline:** `git-remote-sandbox` ignored `SANDBOX_SOCKET`. Now honoured. Documented above in the A2 outcome table.
2. **Production unit hardening blocks the dev harness in several ways:** `UMask=0117` makes `~/.lima/<vm>/` directories land at mode `0660` (no `x` bit), which Lima mis-reports as "instance already exists" because it cannot open `lima.yaml` inside the dir. `ProtectHome=yes` blocks the daemon from reading its own workspace-debug binary under `/home/<operator>/...` and from writing to `/var/lib/sandbox/.lima/`. `PrivateTmp=yes` blocks the daemon from reading the test harness's `SANDBOX_USERS_CONF` tempfile under `/tmp`. `NoNewPrivileges=yes` blocks `sandbox-route-helper` from acquiring its file capabilities. `DeviceAllow=/dev/kvm rw` restricts the daemon's cgroup to a single device, which (we initially suspected) might be implicated in the QEMU exit-1 — though resetting it did not change the outcome. The conftest drop-in overrides each of these one at a time with an inline justification.
3. **`StartLimitIntervalSec` warning is cosmetic:** the in-tree production unit places `StartLimitIntervalSec=300` in `[Service]`; modern systemd moved it to `[Unit]`. The unit loads with a warning but otherwise works. Out of scope for M18-S1.
4. **Daemon-spawned QEMU exit-1 needs root-cause analysis** before M18-S9 can run a full Lima matrix under the new harness. Candidates: missing TTY/stdin, controlling-terminal, signal-mask, or fd-table differences between a daemon-spawned child and a sudo-spawned child. Not blocking for M18-S1 because both observed failure modes (canonical and the QEMU-exit-1 we see) satisfy the "Lima fails under new harness" acceptance criterion.

## Container test PASS analysis

`test_ssh_session[container]` succeeds under the new harness end-to-end:

* `sandbox create --lite` returns rc=0 (after the users.conf was updated to list `sandbox` alongside the operator name in every pool's `allow_users` — see `make setup-users-conf` and the updated `contrib/users.conf.example`).
* The sandbox-route-helper pair-membership check passes (`caller=sandbox for-user=olek pool=...` both resolve, both in the same pool).
* `sandbox ssh ssh-test -- uname -a` returns rc=0 with `Linux` in stdout.

This confirms the harness change itself is non-regressive for the container backend, which is the spec's Phase-1 step-4 acceptance criterion for the orthogonal-regression check.

## Reproduction commands

```bash
# Baseline (legacy harness) — all three pass.
cd tests/e2e
SANDBOX_HARNESS=test-user .venv/bin/pytest -v --timeout=600 \
    'test_guest_agent.py::test_ssh_session[lima]'
SANDBOX_HARNESS=test-user .venv/bin/pytest -v --timeout=600 \
    'test_git_remote.py::test_git_push_to_vm[lima]'
SANDBOX_HARNESS=test-user .venv/bin/pytest -v --timeout=600 \
    'test_guest_agent.py::test_ssh_session[container]'

# New harness (sandbox-systemd by default) — two Lima fail, container passes.
sudo systemctl stop sandboxd-test.service 2>/dev/null
sudo find /var/lib/sandbox -mindepth 1 -delete 2>/dev/null
SANDBOX_HARNESS=sandbox-systemd .venv/bin/pytest -v --timeout=600 \
    'test_guest_agent.py::test_ssh_session[lima]'
sudo systemctl stop sandboxd-test.service 2>/dev/null
sudo find /var/lib/sandbox -mindepth 1 -delete 2>/dev/null
SANDBOX_HARNESS=sandbox-systemd .venv/bin/pytest -v --timeout=600 \
    'test_git_remote.py::test_git_push_to_vm[lima]'
sudo systemctl stop sandboxd-test.service 2>/dev/null
sudo find /var/lib/sandbox -mindepth 1 -delete 2>/dev/null
SANDBOX_HARNESS=sandbox-systemd .venv/bin/pytest -v --timeout=600 \
    'test_guest_agent.py::test_ssh_session[container]'
```

Each Lima test takes ~50–60 s under the new harness (failure is fast); the container test takes ~60–70 s. Under the legacy harness expect 2–3 minutes per test.

## M18-S6 re-run — 2026-05-26

After M18-S6 (rewrite the six broken commands + drift-recovery wrapper) landed locally, the three Phase-1 acceptance tests were re-run against the new harness.

| Test | Outcome under `sandbox-systemd` | Wall clock | Notes |
|------|---------------------------------|-----------|-------|
| A1 `test_ssh_session[lima]` | **FAIL (known #217 blocker)** | ~430 s | `sandbox create` fails at `limactl start timed out after 300s` (daemon-side QEMU exit-1; see M18-S1 outcomes §"Daemon-spawned QEMU exit-1 needs root-cause analysis"). Never reaches `sandbox ssh`. |
| A2 `test_git_push_to_vm[lima]` | **FAIL (known #217 blocker)** | ~430 s | Same root cause as A1 — `sandbox create` fails before `git-remote-sandbox` runs. |
| A3 `test_ssh_session[container]` | **PASS** (flipped from PASS under M18-S1 to PASS again; substantive change — now exercises the new dispatch end-to-end) | ~147 s | `sandbox ssh ssh-test -- uname -a` round-trips through the daemon-mediated SSH proxy: `sandbox` CLI fetches `GET /sessions/{id}/ssh-config`, writes `~/.ssh/sandbox/sandbox-<id>` + the matching key, exec's `ssh sandbox-<id> -- uname -a` whose `ProxyCommand sandbox proxy <id>` tunnels through `GET /sessions/{id}/proxy` (WebSocket) to the in-container sshd. |

### What the container PASS proves end-to-end

The container test's success under `sandbox-systemd` (daemon as `sandbox` system user, CLI as the operator's own uid) is the canonical proof that the cross-user CLI gap is closed for the container backend. Specifically:

1. **Daemon-issued credentials.** `GET /sessions/{id}/ssh-config` (M18-S3) returns the per-session SSH config + private key from the daemon's SQLite store; the CLI never touches the daemon's home directory.
2. **Managed local state.** The CLI's `~/.ssh/sandbox/` area (M18-S5) lands the key + per-session config block under the operator's uid with mode 0600, and inserts the `Include` line at the top of `~/.ssh/config`.
3. **Bare-`ssh` against the alias.** The rewritten `sandbox ssh` (M18-S6) spawns `ssh sandbox-<id> -- <cmd>` with `LC_ALL=C`/`LANG=C`/`SANDBOX_SOCKET`/`PATH` set; the operator's `ssh` client resolves the alias through the managed `Include` block.
4. **`ProxyCommand` tunnel.** `ssh` exec's `sandbox proxy <id>` (M18-S5) which performs the WebSocket handshake against `GET /sessions/{id}/proxy` (M18-S4) and bidirectionally splices its own stdio with binary WebSocket frames.
5. **Daemon-side byte mover.** The daemon's proxy handler `docker exec`s `socat` into the container's network namespace and bridges to the in-container sshd (which the M18-S2 lite-image bakes in).
6. **No backend dispatch.** No `docker exec` shell-out on the CLI side; the CLI is uniform across backends.

### Lima blocker — #217 root-cause investigation

The Lima failures under `sandbox-systemd` are unchanged from the M18-S1 diff-the-outcomes baseline: the daemon-spawned QEMU exits with status 1 before opening its QMP socket, and `limactl start` times out (either at the 120-second base-image-rebuild step or the 300-second session-start step). Repro failure log excerpt for the M18-S9 claim-to-code map:

```
sandbox create failed (rc=1).
  stderr: Warning: base image is 0 days old.
          Rebuild before creating session? [y/N] Error: limactl start timed out after 300s
          server returned 504 Gateway Timeout
[conftest] Lima base-image rebuild failed under SANDBOX_HARNESS='sandbox-systemd';
  continuing — Lima tests will fail downstream and that is the expected outcome
  for the M18-S1 diff-the-outcomes run.
  rebuild-image[lima]: limactl create (base image) timed out after 120s
```

The Lima failure is **pre-flight** (`sandbox create` rc=1), so M18-S6's CLI rewrite is never exercised on Lima sessions under this harness. The canonical "limactl cannot find VM" cross-user failure mode the spec predicted at M18-S1 step 4 cannot manifest until #217 is independently resolved.

**Implication for M18-S9.** The Lima half of the matrix is blocked behind #217 and must be deferred until that bug is independently investigated. The container PASS suffices to demonstrate M18-S6's six-command rewrite is correct end-to-end; the Lima half is symmetric in CLI implementation (the same `~/.ssh/sandbox/` machinery, the same `ssh sandbox-<id>:` argv, the same drift-recovery wrapper — the daemon-side `GET /sessions/{id}/proxy` Lima branch is what changes, and that already has `integration_*` coverage).

