# Sandbox Daemon (sandboxd)

Sandbox daemon providing isolated Linux environments for coding agents — Lima/QEMU VMs (full backend) and default-hardened Docker containers (lite-mode backend), with a shared per-session network gateway that enforces egress policy.

## Project structure

- `sandboxd/` — Rust workspace, 12 crates:
  - `sandbox-core` — shared library (backends, store, policy, events, guest protocol)
  - `sandboxd` — daemon binary (HTTP API over unix socket)
  - `sandbox-cli` — `sandbox` CLI binary (also installed as `git-remote-sandbox`)
  - `sandbox-guest` — guest-agent binary that runs inside each VM/container
  - `sandbox-agent` — the macOS operator-execution seam, and a privilege boundary in its own right. A per-operator LaunchAgent running in the operator's own login session: it connects *out* to the daemon's broker socket, is identified by the kernel-supplied peer credential, and then runs the typed `limactl`, `docker` and in-VM operations the daemon asks for — as the operator, against a VM and a Docker socket the daemon account cannot touch. It is what replaces `sandbox-lima-helper`'s `cap_setuid` pivot on macOS. It also self-gates at startup — `getgrouplist(3)` for `_sandboxd` membership of its own `getuid()`, then a clean exit if absent — but that is a respawn-loop guard, not the authorization boundary: enrollment is decided by the daemon against the peer credential, which the agent cannot influence. It deliberately does **not** depend on `sandbox-core`, which is what keeps it small enough to review as a boundary; its `sandbox_agent_protocol` lib target holds the broker wire types so both sides of the channel serialize from one definition.
  - `sandbox-route-helper` — privileged setcap binary that installs the default route inside a container netns on behalf of an authorized caller
  - `sandbox-lima-helper` — privileged setcap binary that pivots to an operator's uid before exec'ing `limactl` for every Lima control-plane operation
  - `sandbox-docker-argv` — zero-dependency leaf crate of pure functions from typed values to `docker` argv fragments. Both sides of the broker channel build the same invocation from it (`sandbox-core → sandbox-docker-argv ← sandbox-agent`, no edge between those two), so the shape the daemon assumes and the shape the agent runs cannot drift. No I/O, no spawning, no policy — whether an invocation is *allowed* is decided on the agent side. Builds on every target: the Linux lite backend uses it too.
  - `sandbox-invm-argv` — the same leaf-crate shape for work done *inside* the gateway Lima VM (`limactl shell`, `limactl copy`) rather than against a Docker daemon. Separate from the Docker crate because the trust story differs: a `limactl shell` runs in the VM hosting the containers, as its login user with passwordless `sudo`. It is pure data with no `cfg` gates and compiles into the Linux build via `sandbox-core`; the gateway-VM path it serves is macOS-only.
  - `sandbox-event-emitter` — shared lib used by both nft-loggers (JSONL writer + record types)
  - `sandbox-nft-deny-logger` — gateway-container binary that emits `deny` records (TCP DNAT + UDP NFLOG)
  - `sandbox-nft-allow-logger` — gateway-container binary that audits allowed UDP flows via NFCT
- `networking/` — Gateway container (five-process pipeline: Envoy, mitmproxy, CoreDNS, nft-deny-logger, nft-allow-logger) plus the in-tree CoreDNS plugin
- `tests/e2e/` — Python E2E test suite (pytest)
- `docs/` — Project documentation

## Build and test

The Rust workspace builds, lints (`cargo clippy --workspace`), and format-checks (`cargo fmt --all --check`) cleanly on Apple-Silicon macOS. Three crates ship Linux-only binaries (`sandbox-route-helper`, `sandbox-nft-deny-logger`, `sandbox-nft-allow-logger`) and one (`sandbox-lima-helper`) is a Linux-only privileged helper — all four compile on macOS as stub binaries that print `error: this binary runs on Linux only` and exit 2; the Linux implementation is compiled only when `cfg(target_os = "linux")`. Note this concerns only the *macOS-host* build: the inert stub is the host-side artifact. On macOS the gateway and sandbox guests are Linux VMs, and the lite path still builds and runs `sandbox-route-helper` (and the nft-loggers, baked into the gateway image) as real Linux-aarch64 binaries *inside* those VMs — `sandbox-route-helper` is cross-built for the gateway VM via `make build-route-helper-linux-aarch64` and installed at `/usr/local/libexec/sandboxd/sandbox-route-helper` in the VM. `sandbox-lima-helper` is the genuinely macOS-absent one: its `cap_setuid` role is replaced on macOS by the per-operator `sandbox-agent` LaunchAgent.

```bash
make build                  # cargo build --workspace (preceded by fmt-check)
make test                   # hermetic unit tests only — fast, no Docker/Lima/nft
make test-integration       # every `integration_*`-prefixed test in the workspace (Docker required)
make test-e2e-container     # PR-time E2E: container backend only (~5-10 min)
make test-e2e-matrix        # full E2E matrix: Lima + container (~30-45 min, needs /dev/kvm for the Lima half)
make test-e2e               # back-compat alias for test-e2e-matrix
make gateway-image          # docker build for the gateway container
make lite-image             # docker build for the lite-mode container image
make setup-dev-env          # one-shot per-host install/configure; the target branches on host OS — Linux: the cap'd helper installs, qemu bridge.conf, users.conf, qemu-bridge-helper setuid; macOS: none of those, and instead the socket_vmnet launchd plists, staged images, test-binary codesigning
```

### `make setup-dev-env` is assumed by the integration & e2e suites

Run `make setup-dev-env` once per host before `make test-integration` /
e2e (it's deliberately not a make dep — it mutates the host). Re-run it
after `make clean` or after changing a cap'd helper. If skipped, the
daemon can't find its prod-cap helper and aborts at startup, surfacing
as a cryptic 30 s *"sandboxd socket did not appear"* timeout.

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

### `make test-integration` is Linux-only — it cannot run on a macOS host

The target's prerequisites include `install-route-helper-test-cap` and
`install-lima-helper-test-cap`. Both stamp recipes call `getcap` to
compare installed capabilities and `setcap` to install them; neither
tool exists on macOS, and the guard's `cmp -s` against the (absent)
`/usr/local/libexec/sandboxd-test/` binary always takes the `setcap`
branch. So the target dies in its prerequisites, before `cargo nextest`
is ever reached. This is structural, not a missing-setup problem —
Linux capabilities have no macOS equivalent, and `sandbox-route-helper`
/ `sandbox-lima-helper` are inert stubs on a macOS host anyway.

Do **not** work around it by running the profile bare. `cargo nextest
run --workspace --profile integration` without
`--features sandbox-route-helper/test-env-override,sandbox-lima-helper/test-env-override`
yields ~17 spurious failures, and even with the features the tests
checksum the installed cap'd binary and reject a missing one as stale.

On macOS the honest answer for the integration tier is **not
applicable**: run `make test` (hermetic) plus the macOS-relevant e2e
files, and get integration coverage from a Linux host or CI.

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

### Two selection axes: backend and platform

E2E selection is controlled by two orthogonal marker pairs, and the
distinction matters because they answer different questions:

- **Backend** — `lima` / `container`. Which session backend the test
  drives. Unmarked cross-backend tests are parametrized over both.
- **Platform** — `linux_only` / `macos_only`. Which *host* the test can
  run on at all. Unmarked is the majority and means "both".

Apply a platform marker only when the test body asserts on a host facility
the other platform does not have — systemd scopes, cgroup v2,
`sandbox-lima-helper` and `/etc/sandboxd/users.conf` on the Linux side;
the `socket_vmnet` pool, gateway-Lima lifecycle and the launchd agent on
the macOS side. A test that merely *fails* on the other platform because
the harness points at something absent there is a harness bug; marking it
converts a fixable defect into a permanent exclusion, and the coverage
never comes back. State the evidence at the mark — name the assertion and
the facility it needs — so a later reader can re-examine the claim.

The platform markers are enforced per-test by conftest's autouse
`_platform_axis_gate` and consumed as deselect filters by the
platform-specific make targets (`-m "not linux_only"` on macOS,
`-m "not macos_only"` on Linux). A declared marker applied to zero tests
deselects nothing while appearing to gate — a state the suite has been in
before, with the macOS entry point silently collecting the whole
Linux-authored matrix — so conftest's `pytest_configure` refuses to start
a run in which either marker is unapplied. The full-file marker
declaration is the usual home for both, since the platform axis is
normally a property of the whole file.

### Cross-user harness

The suite runs the e2e daemon as the dedicated `sandbox-test` system user via `sudo -u sandbox-test`, while the test runner acts as the *operator* (a separate uid) — the real cross-user path. `make test-e2e` is the single env-agnostic trigger. All sudo is pre-authorized by `make setup-dev-env`, which installs a NOPASSWD sudoers fragment (`/etc/sudoers.d/sandboxd-test`) granting the operator blanket passwordless impersonation of both `sandbox` and `sandbox-test`.

Isolation between the production daemon and the e2e harness is structural: each daemon user gets its own per-uid state tree under `/var/lib/sandboxd/<uid>/`. The production daemon (user `sandbox`) owns `/var/lib/sandboxd/<sandbox-uid>/`; the e2e daemon (user `sandbox-test`) owns `/var/lib/sandboxd/<sandbox-test-uid>/`. The two trees are structurally disjoint — the harness's state-dir reset operates only inside the `sandbox-test` uid's subtree and can never name a path inside the production tree. Runtime sudo is exclusively `sudo -u sandbox-test` for the e2e daemon — no root, no systemd. When running or debugging:

- **`sandbox-test`-group membership must be live.** The e2e daemon socket is `0660`, group `sandbox-test`; the pytest process must carry that group in its credentials. `usermod -aG sandbox-test <you>` only takes effect at next login, so `make test-e2e-matrix` / `test-e2e-container` unconditionally wrap pytest in `sg sandbox-test -c` to activate the group without requiring a re-login.
- **Per-operator LIMA_HOME.** Lima VMs, configs, and the SSH key live under `/var/lib/sandboxd/<sandbox-test-uid>/<operator_uid>/lima/` (3-level path: state-root / daemon-uid / operator-uid), owned by the operator uid. The key is a plain `0600` file: OpenSSH StrictKeyfileMode reads `st_mode`, and a POSIX-ACL *named-user* entry surfaces its mask in the group bits (tripping OpenSSH), so the per-operator LIMA_HOME deliberately carries no default named-user ACL. Test-side `limactl` must run **as the operator** with `LIMA_HOME` set (`limactl_cmd()` in conftest), never `sudo -u sandbox-test` — the daemon uid cannot read the operator-owned files.
- **Socket path:** `/var/lib/sandboxd/<sandbox-test-uid>/sandboxd.sock` (inside the e2e daemon's per-uid base dir; daemon creates it with no elevated privileges). A *production* install's daemon uses `/run/sandbox/sandboxd.sock` with base dir `/var/lib/sandboxd/<sandbox-uid>` — separate from the harness on both axes.
- **The test-cap'd helpers are reinstalled only when needed.** `make install-lima-helper-test-cap` and `make install-route-helper-test-cap` (and, on Linux, `make setup-dev-env`, whose prerequisite list names both — the Darwin branch of that target has no cap'd-helper prerequisites at all) each route through a `.PHONY` cargo-build prerequisite, then compare the freshly-built debug binary against the installed copy with `cmp -s` and check the expected caps via `getcap`. Sudo only fires when the binary differs or the caps are wrong; an up-to-date install prints `✓ already current` and skips sudo entirely. Any helper source change causes cargo to produce a new binary, the `cmp -s` fails, and the recipe reinstalls. No manual stamp deletion is needed after a helper change.

### Debugging a red matrix

The cross-user matrix boots real VMs and runs ~1.5–2h on the 8 GB host. Launch it detached (or via a background agent) and poll the log rather than blocking. When triaging:

- **Isolate failures one at a time** — never two VMs/containers at once (8 GB). A long full run can *cascade* (e.g. the gateway degrading mid-run fails later policy/preset tests); an isolated rerun separates a real bug from load/cascade.
- **Container-backend failures are independent of the Lima cross-user path** (the container backend never runs `limactl` through `sandbox-lima-helper`) — a fast discriminator for whether a failure involves the helper / cross-user execution at all.
- Read a background agent's **log/output file**, not its full JSONL transcript, for ground truth.
- Guard long docker/Lima runs against ENOSPC — see **Disk pressure** below.

### Disk pressure (ENOSPC)

`/` (≈96 GB) holds `/var/lib/docker` (image layers + build cache), the Lima VM disk images under `/var/lib/sandboxd/<daemon-uid>/<op-uid>/lima/`, and `/tmp`. Long or repeated e2e / integration runs accumulate fast: every `make gateway-image` / `lite-image` rebuild adds build-cache layers (tens of GB over a session), each Lima VM is a multi-GB qcow2, and a crashed run can leave an orphaned QEMU process still holding its disk image. When `/` fills, the failure is usually **confusing rather than an obvious "disk full"** — `cargo` dies mid-link, `docker build` fails, or VM creation hangs.

**Watch it.** `df -h /`. During a long background run, arm a watcher that alerts when free space drops below a threshold (e.g. a poll loop that emits only when free space is under ~10–12 GB) rather than discovering ENOSPC after a wasted hour.

**Reclaim it** (most-reclaimable first; these preserve tagged images):

- `docker builder prune -f` — build cache is usually the largest reclaimable chunk (tens of GB).
- `docker image prune -f` — dangling/untagged layers only; leaves the tagged `gateway` / `lite` images intact.
- `pkill -f qemu-system` — reap orphaned/leaked sandbox VMs; a crashed run can leave a multi-GB QEMU holding its disk image.
- Remove leftover Lima instance dirs under the per-operator LIMA_HOME if a run died before teardown.

Do **not** blanket `docker system prune -a` mid-session — it evicts the tagged `gateway` / `lite` images and forces slow rebuilds.

### `target/` bloat stalls exec on macOS (distinct from ENOSPC)

A `target/` dir that has grown without a `cargo clean` for a long time
stops binaries from *starting*, independently of free disk space. It has
two presentations, and the second is routinely misattributed:

- A freshly-built binary hangs at `_dyld_start`, which hangs `make test`
  with no useful output.
- A test run exits **144 with an empty run phase** after a clean build,
  and fails to reproduce on a retry.

**The observable is the hard-link count, not the size.** Two instances
of the identical failure measured ~150 GB / ~1.4 M files and ~25 GB /
~489 k files — a sixfold spread in size and a threefold spread in file
count. Any size threshold you carry in your head will therefore talk you
out of the diagnosis on the smaller one. What is invariant is
`target/debug/deps` reaching the 65535 hard-link cap, so measure that
directly instead of eyeballing `du`:

```bash
find sandboxd/target/debug/deps -type f -exec stat -f '%l' {} + \
  | sort -rn | head -1
```

`65535` is the fault; a healthy tree reads `2`.

**The reason this goes undiagnosed is that the obvious instrument is
live, correct, and blind.** `df` read 653 GiB free before the fix and
678 GiB after, and would have read healthy at every instant in between.
It never lies and never wobbles — it measures a quantity uncorrelated
with the failure, so it emits a steady, accurate green throughout, and
a steady green is more persuasive than a fluctuating one. Free space is
not a signal here in either direction.

The instrument gets picked from the *name* of the failure. "The tree
got too big" files itself under disk space, and size and link count are
the same phrase in English while having nothing to do with each other
in the kernel. Run the probe above, which reads the cause directly and
costs nothing when the answer is no.

This is **not** covered by the `make test` self-signing step — signing
and this are separate failures that present almost identically, so
having handled one does not rule out the other.

**Diagnose before treating.** Copy the built binary to `/tmp` and run it
from there. If it starts fine outside `target/`, the tree is the
problem. Do **not** `pkill -9 amfid` / `syspolicyd` chasing a suspected
code-signing stall — those are system daemons, killing them destabilizes
the host, and they are usually not the cause.

**Fix:** `cargo clean` (in `sandboxd/`), then rebuild. Worth doing
periodically on a long-lived dev host rather than waiting for the hang —
run the link-count probe above as the early signal, not a size check.

`cargo clean` will report a byte total much larger than the space the
filesystem gives back: one run printed `Removed 485938 files, 55.0GiB
total` while free space moved by 25 GiB. **That disagreement is the
fingerprint of this bug, not a discrepancy to reconcile** — cargo sums
file sizes, the filesystem counts a hard-linked file once, and the gap
is exactly the duplication that caused the failure. Do not repeat
cargo's figure as space reclaimed.

Confirming the fix is a different operation from diagnosing it. The
`/tmp` copy above diagnoses; only running a binary **in place** under
`target/` shows the failure is gone, because that is where it happened.
On a shared tree, tell the other agents afterwards — their next compile
is a full cold rebuild, not a new fault.

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
- **Async-I/O carve-out for long-lived streams.** The `spawn_blocking` rule above applies to one-shot Command invocations (e.g. `limactl list`, `docker inspect`). It does **not** apply to the streams that are held open for as long as the thing at the far end lasts: an SSH session under VS Code Remote-SSH or JetBrains Gateway runs for hours, and a blocking-task slot occupied for that long deadlocks the executor under load. These use `tokio::process::Command` (or `tokio::net::TcpStream`) with async pipes. Any future "uniformly wrap Command in spawn_blocking" sweep must leave every site below alone. **Four streams are in the carve-out, and three of them are one mechanism:**
  - The **SSH proxy** (`sandboxd/sandboxd/src/proxy_http.rs`), the **guest-agent transport** (`sandbox-core::backend::container::ContainerTransport`) and the **DNS-policy gate bridge** (`sandbox-core::dns_gate_bridge`, which opens one stream *per DNS query*, on the egress-allow path) are all `docker exec … socat` and all go through `DockerRoute::open_stream` (`sandbox-core::docker`). That seam is where the exception now lives, and its two implementations are the sites a sweep would find: `open_stream_locally` in `sandbox-core::docker` spawns the child in-process, and `handle_docker_stream` in `sandbox-agent::handler` spawns it inside the operator's agent when the VM is theirs. The agent's case is stronger, not weaker: its runtime is current-thread, so blocking it stalls the heartbeat and every other op.
  - The proxy's **Lima path** holds an analogous `tokio::net::TcpStream`; the one-shot `limactl list` probe beside it does use `spawn_blocking`, and that contrast is the boundary.
  - The full rationale is the Async-I/O carve-out doc-comment in `sandboxd/sandboxd/src/proxy_http.rs`; the other sites point back to it rather than restating it.
- Guest agent communication is already async — do not wrap in spawn_blocking. Transport is a per-backend `socat`-bridged pipe (`limactl shell <vm> -- socat - TCP:127.0.0.1:5123` for Lima, `docker exec <ctr> socat - TCP:127.0.0.1:5123` for container) selected via the `SessionRuntime::guest_transport` seam in `sandbox-core::backend`
- Error responses use `error_response()` helper that maps `SandboxError` variants to HTTP status codes
- Handler return type is `impl IntoResponse` — use `match` on spawn_blocking results, not `?` operator
- Socket path default: `$XDG_RUNTIME_DIR/sandboxd/sandboxd.sock` (falls back to `~/.local/share/sandboxd/sandboxd.sock`). Both the daemon and CLI honor the `SANDBOX_SOCKET` env var as an override; an explicit `--socket` flag takes precedence over the env var.
- Git remote helper: `git-remote-sandbox` symlink to `sandbox` binary, uses `sandbox::session/repo-path` URLs
- Config files: all config files (daemon, CLI, per-session metadata) use JSON — not TOML, not YAML
- **No milestone tags in code or tests.** Comments like `// M11-S10 added X` or `// M12-S2 Decision N` belong in git log and PR descriptions, not in source. Code should explain itself in its own terms.
- **Privilege model: narrowly-scoped setcap helpers over broad daemon capabilities.** The daemon (`sandboxd`) runs as the unprivileged `sandbox` system user without elevated capabilities. When an operation genuinely needs `CAP_*`, factor it into a separate setcap helper binary rather than granting the capability to the daemon itself. Two helpers are installed at `/usr/local/libexec/sandboxd/`:
  - `sandbox-route-helper` — `cap_net_admin,cap_sys_ptrace,cap_sys_admin=eip`; installs the default route inside a container netns; pair-membership check on the caller. (`cap_sys_ptrace` is required because the container runs as the operator's uid, so the helper enters a foreign-uid netns and the `pidfd`+`setns` path hits a cross-uid `ptrace_may_access` check.)
  - `sandbox-lima-helper` — `cap_setuid+ep`; pivots to an operator's uid via `setresuid` before exec'ing `limactl` for every Lima control-plane operation; gates both sides of that pivot. Caller gates: `getuid()==sandbox-user-uid` (kernel-checked) + sandbox-group membership. Target gates: the `--op-uid` it is asked to become must be non-zero, must resolve via `getpwuid_r`, and must be in the sandbox group — all three checked before the `setresuid`. The daemon **never invokes `limactl` directly** — every limactl call goes through this helper.
  Do NOT add `AmbientCapabilities` / `CapabilityBoundingSet` to `sandboxd.service`, do NOT setcap the daemon binary itself, and do NOT run the daemon as root. The narrow-helper approach keeps the privileged surface ~50–100 lines per capability, separately reviewable, and tightly scoped to its specific purpose.

## On-disk compatibility

Session state persists across daemon restarts in `{base_dir}/sessions.db` (SQLite). `SessionStore::new` (in `sandbox-core/src/store.rs`) opens the DB and runs every pending migration via `refinery` against `sandbox-core/migrations/`. Schema evolution rules:

- **SQLite columns** (`sessions`, `network_info`, etc.) — adding or changing a column requires a new `V<NNN>__<name>.sql` file in `sandbox-core/migrations/`. Never drop a column without verifying no older daemon needs it; refinery enforces forward-only application of the migration set.
- **JSON blob fields** (columns like `config_json`, `network_info` JSON payloads) — when adding a field to a persisted struct (`SessionConfig`, `NetworkInfo`, etc.), make it `Option<T>` with `#[serde(default)]` so records written by older versions still deserialize. Never remove or rename a persisted blob field without a migration.
- **Forward-compat on rollback** — records written by a newer daemon may be read by an older one during rollback. Use `#[serde(default)]` + unknown-field tolerance to keep this safe.
- **An applied migration is frozen, byte for byte.** Once a `V<NNN>__<name>.sql` file has shipped, never edit it — not the SQL, not the comments, not the whitespace. `embed_migrations!` embeds each file with `include_str!`, and refinery's checksum is `SipHasher13` over (name, version, *the whole file*), so a single changed byte anywhere in it — including inside a `--` comment — produces a different checksum. `verify_migrations` compares every **already-applied** migration against its filesystem counterpart, and `abort_divergent` defaults to `true` and is never overridden anywhere in the workspace. The result is not a warning: the run fails with `DivergentVersion`, `SessionStore::new` propagates it as `migration error (…)`, and the daemon does not start — on every database that already ran the old bytes, including hosts you cannot see and cannot fix. To change what a migration *does*, add a new one. Do NOT reach for `set_abort_divergent(false)` to make an edit go through; it disables the check for the whole migration set, on every host, permanently.

### Correcting a claim written into a frozen migration

A migration's comments are frozen along with its SQL, so a comment that turns out to be **wrong** cannot be fixed where it is written. Neither escape is available: editing it breaks startup, and softening it to "the comment is out of date" leaves a false statement that the next reader will act on. Relocate the correction instead, to the editable code that would otherwise rely on the claim — quote the frozen sentence verbatim so a reader who finds the migration first can match the two up, say why it does not hold, and put it on the declaration the claim is about. `Session::operator_uid` (`sandbox-core/src/session.rs`) is the worked example — V009's header concludes that after its one-shot `DELETE FROM sessions WHERE operator_uid IS NULL` the assertion "`session.operator_uid` must be `Some`" is "unconditionally satisfied", which describes the rows that survived at the instant it ran and constrains no subsequent write.

## Releasing

Cutting a `vX.Y.Z` release means bumping the single
`[workspace.package].version` in `sandboxd/Cargo.toml` (every crate
inherits it via `version.workspace = true`; the tag must match it, and it
drives the runtime gateway/lite image tags), then committing on `master`
and pushing the tag — which fires the signed-artifact pipeline. Full
procedure and rationale:
[docs/internal/releasing.md](docs/internal/releasing.md).
