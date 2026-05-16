# QEMU virtio-balloon with an in-daemon adaptive pulse controller

## Summary

This spec adds dynamic host-memory reclaim to every Lima/QEMU sandbox
session. A `virtio-balloon-pci` device is attached unconditionally at
boot, and a per-session controller task running inside the daemon
drives it on an observation-based pulse loop: when the guest's
estimated slack crosses a configurable threshold, the controller
inflates the balloon to claim that slack, waits for the guest to
hand the pages back, then immediately deflates so the guest sees
its full `MemTotal` again. The reclaimed host pages stay reclaimed
until the guest organically rewrites them.

This is the virtio-balloon half of issue #4
(`Koriit/sandboxd#4` — "QEMU memory ballooning + KSM to reduce host
memory pressure (mimic macOS VZ behaviour)"). KSM is the second
mechanism named in that issue and is explicitly **out of scope** here:
it is a host-side page-deduplication knob, orthogonal to the
guest-hinting mechanism this spec adds, and warrants its own design
note if pursued.

## Context

### What the code does today

Every Lima session inherits the QEMU wrapper installed as the
`QEMU_WRAPPER_SCRIPT` constant in `sandbox-core/src/lima.rs`. The
wrapper always initialises `EXTRA_ARGS` with a PCIe root-port,
optionally appends a bridge NIC in its `SANDBOX_DOCKER_BRIDGE`
branch, and — when `SANDBOX_QEMU_HARDENED=1` — appends a
device-lockdown block plus `virtio-rng-pci` in its
`SANDBOX_QEMU_HARDENED` branch. Probe invocations
(`-machine help`, `--version`, etc.) bypass `EXTRA_ARGS` via the
probe-passthrough early-exec guard at the top of
`QEMU_WRAPPER_SCRIPT`. No balloon device is attached today.

Memory is set by Lima from the `SessionConfig::memory_mb` field
(`sandbox-core/src/session.rs`) as a fixed `-m <N>M` argument.
QEMU's allocator commits a host page the first time the guest
touches it and never returns those pages to the host on its own; on
Linux, only an explicit reclaim mechanism (balloon, FPR, or host-side
`madvise(MADV_DONTNEED)`) releases the backing. The macOS Virtualization
Framework (VZ), which the issue contrasts us against, performs this
reclaim natively.

The existing QMP client is the `QmpClient` struct in
`sandbox-core/src/qmp.rs`. It exposes a single general-purpose
`execute(command, arguments)` primitive (`QmpClient::execute`) plus
one specialised helper, `QmpClient::add_tap_nic`. QMP I/O is
intentionally synchronous; the module-header comment in
`sandbox-core/src/qmp.rs` commits to that decision. Sockets are
located via `QmpClient::for_session`, which derives
`~/.lima/{vm_name}/qmp.sock` from the `crate::lima::vm_name`
function in `sandbox-core/src/lima.rs`.

### What this costs us

For a fleet of N idle sessions, the host commits N × (peak working
set ever touched) of RAM. The "peak ever touched" floor is sticky:
a guest that built a project once and then sat idle keeps every page
the build process dirtied. Operators running several long-lived
sessions in parallel on a workstation see this as steady-state RAM
pressure that does not track the foreground workload.

The user-facing report in issue #4 frames this as "macOS VZ handles
it; Linux/QEMU does not by default". The fix is not Linux-vs-macOS
but configuration-vs-default: virtio-balloon is the standard
mechanism for this on QEMU and we simply do not turn it on.

### Why we did not choose Free Page Reporting

`virtio-balloon-pci,free-page-reporting=on` enables the guest driver
to proactively push free-page hints to QEMU on a kernel timer; QEMU
then `madvise(MADV_DONTNEED)`s the corresponding host ranges. It is
the most hands-off mechanism — no controller, no host-side policy,
no `actual` field manipulation. We do not adopt it as the v1
mechanism for two reasons:

1. **Less control over reclaim ceiling and pacing.** FPR fires on
   guest-kernel timers and discovers ranges via the guest's own
   page-allocator hooks. The host has no knob for "reclaim now",
   "reclaim no more than N MiB at a time", or "stop reclaiming if
   the guest is approaching pressure". For a multi-session host
   running heterogeneous workloads, the operator-tunable
   pulse controller this spec ships is closer to what we want to
   observe and reason about than an opaque driver-paced loop.

2. **Empirical evaluation pending.** FPR's behaviour under our
   actual workload mix (long-idle build VMs, JVM-heavy guests,
   short-lived ephemeral sessions) is not measured. The pulse
   approach makes the trade-offs explicit — `inflate_threshold`,
   `max_pulse_bytes`, `safety_floor` — and is amenable to logging,
   metrics, and per-session overrides.

FPR is a viable v2 complement: it can run alongside the pulse
controller (the device supports both) and would shave the
between-pulse drift. The decision to defer is "ship the explicit
mechanism first, evaluate FPR against it once we have a baseline",
not "FPR is wrong".

### Why we did not choose static `-m` reduction

The trivial alternative is to lower `SessionConfig.memory_mb`. This
trades peak-tolerance for steady-state footprint and is incompatible
with the workloads sandbox sessions are designed for: builds, JVM
heaps sized off `MemTotal`, container daemons, language servers
with bursty resident sets. The whole point of giving a VM 4 GiB is
that it occasionally needs 4 GiB; we should not pretend otherwise
and we do not need to — virtio-balloon lets us keep the ceiling
while reclaiming the slack.

### Why we did not choose KSM

Kernel Same-page Merging operates on host-side page contents,
deduplicating identical pages across processes (i.e., across VMs).
It is orthogonal to virtio-balloon: KSM reclaims by collapsing
duplicates, balloon reclaims by returning unused pages. They
compose, but they are not substitutes. KSM is also a host-wide
sysadmin knob (`/sys/kernel/mm/ksm/run`), not a per-session daemon
behaviour. Treating it as part of the same spec would conflate two
distinct surfaces. Out of scope here; the second-mechanism question
in issue #4 is acknowledged in "Known gaps" and may become its own
spec.

### Why we chose pulse over continuous-target ballooning

The naïve controller maintains `actual = mem_total − working_set −
headroom` continuously: as the guest grows, deflate; as it shrinks,
inflate. We rejected this in favour of a **pulse** pattern —
inflate to claim slack, observe completion, then immediately deflate
back to `mem_total` — for two reasons:

1. **Predictable for guest apps.** The balloon spends >95% of its
   wall-clock time fully deflated (`actual = mem_total`). Guest
   applications reading `/proc/meminfo` see `MemAvailable`
   unaffected by the controller's bookkeeping for almost the entire
   lifetime. Apps that size themselves off `MemTotal` at startup
   (e.g. JVM `-XX:MaxRAMPercentage`) are wholly unaffected — the
   balloon does not move `MemTotal`. Apps that read `MemAvailable`
   to decide on background work see a clean read between pulses;
   only during the brief pulse window (sub-second to ~15 s) is the
   visible figure depressed.

2. **Reclaim persists after deflate.** When the balloon driver
   releases its pinned pages back to the guest free-list at deflate
   time, the host has already `madvise(MADV_DONTNEED)`'d the
   backing. The host does not re-back those pages until the guest
   writes to them. Net effect: the physical reclaim sticks across
   the pulse-then-deflate cycle until the next workload organically
   reuses that address range. We get the host-side benefit
   without paying the guest-side `MemAvailable` distortion for any
   meaningful length of time.

The pulse pattern is also **self-regulating in observed state**:

- If the guest is active, working-set is large, slack metric stays
  near zero, pulse never fires, no churn.
- If the guest is idle, working-set is small, slack accumulates,
  pulse fires, reclaim happens, slack drops, pulse stops firing.

The controller does not need to track "intent" or predict load. The
slack metric is a direct observation of "host RAM the guest is
holding but not using"; firing on it is sufficient.

We retain `deflate-on-oom=on` on the balloon device as a passive
safety floor — if the controller ever holds the balloon inflated
through a guest memory spike, the driver auto-deflates before OOM-
kill fires. It does **not** substitute for the active controller
(it cannot reclaim slack; it can only rescue from a pulse that
overshot), but pairing it with the pulse is free. If `deflate-on-
oom` fires mid-pulse, the balloon driver auto-deflates and `actual`
swings back toward `mem_total`; the pulse loop never observes
`actual ≤ target_actual + tolerance_bytes`, so it never returns
`Reached` and eventually exits via `AbortedTimeout`. The deflate-
guard's `Drop` (see "Always-deflate invariant" below) then issues
the final restore — a no-op against an already-deflated balloon.
Net effect is safe.

## Goals and non-goals

### Goals

1. Attach `virtio-balloon-pci` to every Lima session unconditionally
   at boot, with `deflate-on-oom=on` and an initial
   `stats-polling-interval` of 15 s.
2. Ship an in-daemon per-session controller that estimates guest
   slack and drives balloon-inflate/deflate pulses to reclaim it.
3. Expose a single binary CLI knob (`--balloon=enabled|disabled`)
   that stops the controller from issuing pulses without removing
   the device.
4. Persist controller tuning forward- and backward-compatibly via
   `Option<BalloonConfig>` on `SessionConfig`, following the
   CLAUDE.md "On-disk compatibility" rule.
5. Confine the change to the Lima/QEMU backend; the container
   backend is a no-op surface.
6. Document the mechanism, the pulse pattern, the `MemAvailable`
   trade-off, and how `--balloon=disabled` interacts with the
   always-attached device.

### Non-goals

- Enabling Free Page Reporting in v1 (parked pending evaluation
  against the pulse baseline).
- KSM configuration (host-wide concern, separate spec if pursued).
- Cross-session memory budgeting (each controller is independent;
  no global "VM A is loaded, squeeze VM B harder" logic).
- Granular per-knob CLI tuning of thresholds, intervals, or the
  cache divisor — only `--balloon=enabled|disabled` ships on the
  CLI. Operators who need per-VM tuning edit the persisted
  `config_json` blob directly.
- Container-backend dynamic reclaim. Memory limits on container
  sessions are imposed by Docker via cgroups (`--memory`), a
  separate mechanism that already exists and is not extended here.
- macOS host support. VZ reclaims natively; we do not run QEMU
  there.
- Per-application "suppress" hooks or guest-side lock files that
  let workloads gate the controller. Parked.

## Target design

### QEMU wrapper additions

Extend the always-on `EXTRA_ARGS` assembly inside
`QEMU_WRAPPER_SCRIPT` (`sandbox-core/src/lima.rs`) so that,
immediately after the existing PCIe root-port initialisation line,
the wrapper appends:

```sh
EXTRA_ARGS="$EXTRA_ARGS \
    -device virtio-balloon-pci,id=balloon0,deflate-on-oom=on,stats-polling-interval=15"
```

Properties of this addition:

- **Unconditional.** The device is attached on every boot,
  including when the session is created with `--balloon=disabled`.
  Disabled means "the controller never issues pulses"; the device
  remains present at `actual = mem_total` and inert. Keeping the
  wrapper agnostic of per-session controller config keeps it
  testable from a single `test_qemu_wrapper_*` site.
- **`deflate-on-oom=on`** — guest auto-deflates the balloon before
  OOM-kill fires. Free safety floor; pairs with the controller's
  own `safety_floor_bytes` exit condition but does not depend on
  it.
- **`stats-polling-interval=15`** — initial value, hardcoded in
  the wrapper from the `BalloonConfig::Default`
  `idle_stats_interval_secs` field (15). The choice is read once
  at boot and baked into the QEMU command line; updates to
  `cfg.idle_stats_interval_secs` after boot do not propagate
  without a VM restart. The controller dynamically bumps to
  `cfg.pulse_stats_interval_secs` (default `1`) immediately before
  each pulse and restores `cfg.idle_stats_interval_secs` immediately
  after, via `qom-set` on the device's `stats-polling-interval`
  property. Idle baseline is therefore one virtio-balloon stats
  refresh every 15 s — near-zero overhead.
- **No explicit `bus=`.** virtio-balloon-pci lands on `pcie.0`
  (the q35 root complex) by default. The wrapper already
  provisions the `pcie-hotplug-port` root-port via its `EXTRA_ARGS`
  initialisation for NIC hot-add, but balloon is cold-plugged at
  boot and does not need a hot-pluggable slot.
- **Probe-call bypass.** Probe invocations (`-machine help`,
  `--version`, etc.) hit the probe-passthrough early-exec guard at
  the top of `QEMU_WRAPPER_SCRIPT` and never touch `EXTRA_ARGS`.
  The balloon line is inert under probe, like the existing
  pcie-root-port line.

### `QmpClient` extensions

Layer four new methods on the `QmpClient` struct
(`sandbox-core/src/qmp.rs`), each implemented in terms of the
existing `QmpClient::execute(command, arguments)` primitive:

```rust
/// Returns the balloon's `actual` field: bytes currently visible to
/// the guest. Equals `mem_total − balloon_size`. Real-time; pushed
/// by the driver on every change (not gated by stats-polling).
pub fn balloon_actual_bytes(&self) -> Result<u64, SandboxError>;

/// Requests QEMU drive `actual` to `target_bytes`. Asynchronous —
/// the driver takes time to allocate or release pages; poll
/// `balloon_actual_bytes` to observe convergence.
pub fn balloon_set_actual(&self, target_bytes: u64) -> Result<(), SandboxError>;

/// Returns the most recent guest memory stats reported via
/// virtio-balloon. Freshness is bounded by the device's current
/// `stats-polling-interval`.
pub fn balloon_guest_stats(&self) -> Result<BalloonGuestStats, SandboxError>;

/// Changes the device's `stats-polling-interval` property at
/// runtime. The controller bumps to
/// `cfg.pulse_stats_interval_secs` (default `1`) pre-pulse and
/// restores `cfg.idle_stats_interval_secs` (default `15`) post-
/// pulse.
pub fn set_balloon_polling_interval_secs(&self, secs: u8) -> Result<(), SandboxError>;
```

QMP commands used internally:

- `balloon` with `{"value": <bytes>}` — drives `actual`.
- `query-balloon` returning `{"actual": <bytes>}` — real-time, not
  gated by stats-polling-interval.
- `qom-get` with `{"path": "/machine/peripheral/balloon0",
  "property": "guest-stats"}` — returns the stats snapshot.
- `qom-set` with the same path and `"property":
  "stats-polling-interval"` — runtime polling-interval change.

The `BalloonGuestStats` struct (new, alongside `QmpClient`):

```rust
#[derive(Debug, Clone, Copy, Default)]
pub struct BalloonGuestStats {
    pub total_memory: u64,
    pub free_memory: u64,
    pub available_memory: u64,
    pub disk_caches: u64,
    pub major_faults: u64,
    pub minor_faults: u64,
}
```

Field sources, from the `qom-get guest-stats` response. The
response is a two-level object of the shape

```json
{
    "last-update": <u64 seconds>,
    "stats": {
        "stat-total-memory": <u64>,
        "stat-free-memory": <u64>,
        "stat-available-memory": <u64>,
        "stat-disk-caches": <u64>,
        "stat-major-faults": <u64>,
        "stat-minor-faults": <u64>
    }
}
```

Each value is read as `serde_json::Number::as_u64().unwrap_or(0)`
— a hand-rolled `as u64` against a JSON `f64` would lose precision
on stats above `2^53`, so the typed-`Number` accessor is mandatory.
Missing fields saturate to `0` rather than failing; older guest
drivers report only a subset, and the slack estimator tolerates
zeros gracefully.

`last-update == 0` is a distinct signal — it means the guest
driver has not yet emitted a snapshot (typical during the first
seconds after boot, before the stats-polling timer fires).
`balloon_guest_stats` returns
`Err(SandboxError::BalloonStatsUnready)` in that case rather than
a zeroed `BalloonGuestStats`. The controller treats this error
identically to a transient QMP failure: log at `tracing::debug!`
and skip the tick. Returning zeroed stats would collapse
`guest_used_real` to `0` and produce maximum-positive slack, which
would cause a spurious pulse on every cold boot — exactly the
opposite of what we want.

The synchronous-I/O posture of `QmpClient`, locked in by the
module-header comment in `sandbox-core/src/qmp.rs`, is unchanged.
All four new methods are sync and run inside
`tokio::task::spawn_blocking` at every async call site, per
CLAUDE.md.

### Balloon controller

A new module `sandbox-core/src/balloon.rs` houses three components:
a pure slack-estimator function, a synchronous pulse routine, and
an async controller task.

#### Slack estimator

```rust
pub fn estimate_slack(
    rss_bytes: u64,
    stats: &BalloonGuestStats,
    cfg: &BalloonConfig,
) -> u64
```

Formula, with every subtraction `saturating_sub` so under-flowing
inputs collapse to `0` instead of wrapping:

```text
guest_used_real     = stats.total_memory
                          .saturating_sub(stats.free_memory)
                          .saturating_sub(stats.disk_caches)
cache_discounted    = stats.disk_caches / max(cfg.cache_divisor, 1)
host_backed_usable  = rss_bytes.saturating_sub(cfg.qemu_overhead_bytes)
slack               = host_backed_usable
                          .saturating_sub(guest_used_real)
                          .saturating_sub(cache_discounted)
```

Returns unsigned `u64`; the result is zero-or-positive. `0` means
"no slack worth claiming" — for example, a wildly stale `rss_bytes`
smaller than `qemu_overhead_bytes` produces `host_backed_usable =
0`, which then saturates the final `slack` to `0`. Stale or
rounded stats where `free + caches > total` momentarily likewise
collapse `guest_used_real` to `0` rather than wrapping. The
controller's threshold comparison treats `0` the same as any sub-
threshold value: no pulse fires.

Pure function — no I/O, no logging beyond what the caller wraps in.
Fully unit-testable with table-driven cases.

Rationale for each term:

- **`rss_bytes`** — real host RAM committed to this QEMU process
  (`VmRSS` from `/proc/{pid}/status`). The upper bound on what we
  can possibly reclaim.
- **`cfg.qemu_overhead_bytes`** (default 1 GiB) — QEMU's
  irreducible footprint (firmware, device-emulation buffers, code).
  Not subject to balloon reclaim; subtracted out so slack is not
  attributed to it.
- **`guest_used_real`** — the guest's actual working set excluding
  cache. Not reclaimable: the guest will fault these pages back
  immediately if we squeeze them.
- **`cache_discounted`** — cache pages, weighted by
  `cfg.cache_divisor`. Cache is reclaimable in principle but
  costs I/O performance to reclaim. `cache_divisor = 1` credits
  cache fully (suits idle / I/O-light VMs); `2` (the default)
  credits half; large values (e.g. `255`) credit essentially none
  (suits I/O-heavy VMs).

#### Pulse function

```rust
pub fn pulse(
    qmp: &QmpClient,
    target_actual: u64,
    mem_total: u64,
    cfg: &BalloonConfig,
) -> Result<PulseOutcome, SandboxError>

pub struct PulseOutcome {
    pub reason: PulseReason,
    pub claimed_bytes_observed: u64,
    pub elapsed_ms: u64,
}

pub enum PulseReason { Reached, AbortedPressure, AbortedTimeout }
```

Sequence:

1. Construct a `BalloonDeflateGuard` (see "Always-deflate
   invariant" below) holding a borrow of `qmp`, the
   `mem_total` figure, and `cfg.idle_stats_interval_secs`. From
   this point forward, every exit path — `Ok`, `Err`, or panic —
   restores `actual = mem_total` and the idle stats-polling
   interval via the guard's `Drop` impl.
2. `qmp.set_balloon_polling_interval_secs(cfg.pulse_stats_interval_secs)`
   — bump freshness (default `1` s) so `balloon_guest_stats`
   returns recent data within the pulse window.
3. `qmp.balloon_set_actual(target_actual)` — request inflate.
4. Loop:
   1. `sleep(cfg.poll_interval_ms)` (default 500 ms).
   2. `actual = qmp.balloon_actual_bytes()`.
   3. `stats = qmp.balloon_guest_stats()`.
   4. Exit on any of:
      - `actual ≤ target_actual + cfg.tolerance_bytes` →
        `Reached`.
      - `stats.free_memory < cfg.safety_floor_bytes` →
        `AbortedPressure`.
      - elapsed ≥ `cfg.max_pulse_ms` → `AbortedTimeout`.
5. Call `guard.disarm()` — marks the guard's internal `disarmed`
   flag so its `Drop` skips the restore work that we are about
   to perform synchronously and report on.
6. `qmp.balloon_set_actual(mem_total)` — full deflate.
7. `qmp.set_balloon_polling_interval_secs(cfg.idle_stats_interval_secs)`
   — restore the low-overhead baseline (default `15` s).
8. Return `PulseOutcome { reason, claimed_bytes_observed:
   mem_total.saturating_sub(min_actual_seen), elapsed_ms }`.

Error handling: any QMP call that fails between guard
construction (step 1) and `disarm` (step 5) short-circuits the
function with `Err`; the guard's `Drop` runs the deflate +
interval restore as the function unwinds. The original error is
surfaced to the caller. If the post-disarm steps 6 or 7 fail, the
caller sees that error directly; the guard does not re-fire (it
is already disarmed).

Pulse is synchronous — it runs entirely inside a `spawn_blocking`
boundary at its single async caller (`run_controller` below).

##### Always-deflate invariant

The hard invariant is "the balloon never stays inflated past the
end of `pulse()`". Cleanup in steps 6-7 is the happy-path
implementation; `BalloonDeflateGuard` is the safety net that
covers `Err` returns and panics.

```rust
struct BalloonDeflateGuard<'a> {
    qmp: &'a QmpClient,
    mem_total: u64,
    idle_interval_secs: u8,
    disarmed: bool,
}

impl<'a> BalloonDeflateGuard<'a> {
    fn new(qmp: &'a QmpClient, mem_total: u64, idle_interval_secs: u8) -> Self {
        Self { qmp, mem_total, idle_interval_secs, disarmed: false }
    }

    fn disarm(&mut self) {
        self.disarmed = true;
    }
}

impl<'a> Drop for BalloonDeflateGuard<'a> {
    fn drop(&mut self) {
        if self.disarmed {
            return;
        }
        // Best-effort. Errors here are logged at `tracing::warn!`
        // and swallowed — Drop cannot return Result, and we are
        // already on an exceptional exit path.
        let _ = self.qmp.balloon_set_actual(self.mem_total);
        let _ = self.qmp.set_balloon_polling_interval_secs(self.idle_interval_secs);
    }
}
```

Construction site: step 1 of `pulse()`, immediately on entry,
before any QMP call. Disarm site: step 5, after the loop has
exited with a definite `PulseReason` and before the synchronous
deflate. This ordering means the guard covers:

- **Pre-loop QMP failures.** If step 2's polling-interval bump
  fails, the guard's `Drop` still issues the deflate (a no-op,
  since the balloon was never inflated) and the interval restore.
  Cheap; no harm.
- **In-loop errors.** Any QMP call inside step 4 returning `Err`
  propagates through `?`; the guard's `Drop` runs on unwind.
- **Panics.** A panic in stats parsing, in `sleep`, or anywhere
  else between steps 1 and 5 unwinds through the guard, which
  fires its restore in `Drop`.

The guard's `Drop` issuing a no-op deflate against an already-
deflated balloon is harmless — QEMU treats `balloon` with `value
== mem_total` as "set actual to mem_total", which is the steady
state. The double-restore that would happen if both the guard and
steps 6-7 ran is what `disarm` exists to prevent: after a clean
loop exit, the synchronous steps 6-7 do the work, observe any
errors, and the guard skips its restore.

#### Controller task

```rust
pub async fn run_controller(
    session_id: SessionId,
    mem_total_bytes: u64,
    cfg: BalloonConfig,
    cancel: CancellationToken,
)
```

Loop body, gated on `cancel`:

1. `sleep(jitter(cfg.loop_interval_ms, ±10%))`. Per-controller
   jitter staggers multiple sessions naturally, so a host running
   N sessions does not see N synchronised pulses.
2. Resolve the QEMU PID from `~/.lima/{vm_name}/qemu.pid` (the
   path Lima writes; `vm_name` is
   `crate::lima::vm_name(&session_id)` from
   `sandbox-core/src/lima.rs`).
3. `spawn_blocking` → read `/proc/{qemu_pid}/status`, parse the
   `VmRSS:` line into `rss_bytes`.
4. `spawn_blocking` → open `QmpClient::for_session(&session_id)`
   (from `sandbox-core/src/qmp.rs`); call `balloon_guest_stats()`.
5. `slack = estimate_slack(rss_bytes, &stats, &cfg)`.
6. If `slack ≥ cfg.inflate_threshold_bytes`:
   1. `claim = min(slack.saturating_sub(cfg.safety_margin_bytes),
      cfg.max_pulse_bytes)`.
   2. `target_actual = mem_total_bytes − claim`.
   3. `spawn_blocking` → `pulse(&qmp, target_actual,
      mem_total_bytes, &cfg)`.
   4. Log `PulseOutcome` at `tracing::info!` (`session_id`,
      `reason`, `claimed_bytes_observed`, `elapsed_ms`).
7. Else: log `slack < threshold` at `tracing::debug!`. Continue.

Lifecycle:

- **Spawn point.** Daemon-side, at session-create completion, but
  only when `Session.backend == BackendKind::Lima` (the
  `BackendKind` enum lives in
  `sandbox-core/src/backend/capabilities.rs`). For
  `BackendKind::Container`, the controller is not spawned at all.
- **Stop point.** Daemon-side, at session-destroy initiation,
  before VM teardown. Cancellation token is wired both to the
  per-session destroy path and to daemon shutdown. The controller
  exits cleanly without firing a *new* pulse on cancel.
- **Token storage.** The daemon owns a
  `HashMap<SessionId, (CancellationToken, JoinHandle<()>)>` —
  call it `balloon_controllers` — keyed by session id. Insertion
  happens at controller spawn; lookup-and-remove happens at
  session destroy and at daemon shutdown. The map lives on the
  same daemon-state struct that already holds the session store
  and the other per-session task handles, so balloon controllers
  are managed identically to existing daemon-owned tasks (no new
  lifecycle pattern).

All `std::process::Command` / synchronous `/proc` reads / sync QMP
calls in this loop are wrapped in `tokio::task::spawn_blocking`
per CLAUDE.md "Key conventions".

##### Failure modes

Three edge cases the controller must handle explicitly:

1. **Cancel arrives mid-pulse.** The `pulse` function runs
   synchronously inside `spawn_blocking`; a cancellation token
   cannot preempt it. Cancellation is checked at the *top* of
   the controller loop (before the sleep + tick). If cancel fires
   while a pulse is in flight, the controller waits for the
   pulse — including its always-deflate restore via
   `BalloonDeflateGuard` — to complete, then exits cleanly on
   the next loop check. Worst case: a destroy waits up to
   `cfg.max_pulse_ms` (default `15` s) plus the deflate round-
   trip before VM teardown begins. The daemon's session-destroy
   path **awaits** the `JoinHandle` from `balloon_controllers`
   before tearing the VM down — VM teardown does not race the
   guard's deflate.
2. **QMP socket unreachable at controller tick.** During slow VM
   boot, transient Lima restart, or any other QMP outage,
   `QmpClient::for_session().connect()` returns `Err`. The
   controller logs the error at `tracing::warn!` on the first
   occurrence and at `tracing::debug!` for every subsequent
   consecutive tick (per-session "connect failure" counter, reset
   to zero on the first successful tick). No backoff, no max-
   retries: ticks are cheap (one stat read + one connect attempt)
   and the connect failure is normally cleared in seconds. The
   controller never fails terminally — it sits in the retry loop
   until cancel.
3. **No new pulse after cancel.** "Exits cleanly without firing a
   final pulse" means the cancel check at the top of the loop
   skips the next pulse decision. A pulse already running when
   cancel arrives is allowed to finish through its
   `BalloonDeflateGuard`-protected exit. Restated: cancel
   prevents *new* pulses; it does not abort an in-flight one.

### Configuration

A new `BalloonConfig` struct is added (in
`sandbox-core/src/balloon.rs`, re-exported from `sandbox-core/lib.rs`
alongside the other public config types) and surfaced on the
`SessionConfig` struct (`sandbox-core/src/session.rs`) as a new
optional field:

```rust
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case", default)]
pub struct BalloonConfig {
    pub enabled: bool,
    pub loop_interval_ms: u64,
    pub inflate_threshold_bytes: u64,
    pub max_pulse_bytes: u64,
    pub safety_margin_bytes: u64,
    pub safety_floor_bytes: u64,
    pub max_pulse_ms: u64,
    pub poll_interval_ms: u64,
    pub cache_divisor: u8,
    pub qemu_overhead_bytes: u64,
    pub tolerance_bytes: u64,
    pub idle_stats_interval_secs: u8,
    pub pulse_stats_interval_secs: u8,
}

impl Default for BalloonConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            loop_interval_ms: 60_000,
            inflate_threshold_bytes: 500 * 1024 * 1024,        // 500 MiB
            max_pulse_bytes: 2 * 1024 * 1024 * 1024,           // 2 GiB
            safety_margin_bytes: 256 * 1024 * 1024,            // 256 MiB
            safety_floor_bytes: 256 * 1024 * 1024,             // 256 MiB
            max_pulse_ms: 15_000,
            poll_interval_ms: 500,
            cache_divisor: 2,
            qemu_overhead_bytes: 1024 * 1024 * 1024,           // 1 GiB
            tolerance_bytes: 64 * 1024 * 1024,                 // 64 MiB
            idle_stats_interval_secs: 15,
            pulse_stats_interval_secs: 1,
        }
    }
}
```

Extend `SessionConfig`:

```rust
/// Per-session balloon controller configuration. `None` on records
/// written before this field existed (forward-compatible via
/// `#[serde(default)]` per CLAUDE.md "On-disk compatibility");
/// resolves to `BalloonConfig::default()` at controller-spawn time.
/// Lima sessions only — container sessions ignore this field.
#[serde(default, skip_serializing_if = "Option::is_none")]
pub balloon: Option<BalloonConfig>,
```

Persistence and rollback compatibility:

- **Old daemon reading new record.** Unknown `balloon` field
  → serde discards. Old daemon never starts a controller for any
  session (it has no controller code). Behaviour unchanged from
  pre-spec.
- **New daemon reading old record.** `balloon` absent → `None`
  → controller resolves to `BalloonConfig::default()` at spawn
  time, which has `enabled: true`. Old Lima sessions begin
  reclaiming on next daemon start, with default tuning.

The new daemon writes `balloon: Some(_)` on every Lima session
create — `--balloon=enabled` with otherwise default values still
emits `Some(BalloonConfig::default())` so the recorded config is
self-describing rather than relying on the binary's `Default` at
read time.

The inner `#[serde(default)]` on `BalloonConfig` lets future field
additions land safely: a daemon reading an older `Some(...)` blob
that lacks a newly-added field fills it from `Default`.

### CLI surface

One new binary flag on `sandbox create`:

```
--balloon=enabled         # default
--balloon=disabled        # opt-out: device still attached at boot,
                          #          controller never spawns
```

Semantics:

- `--balloon=enabled` (or omitted) → `SessionConfig.balloon =
  Some(BalloonConfig::default())` if other knobs are default,
  else `Some(BalloonConfig { enabled: true, ... })`.
- `--balloon=disabled` → `SessionConfig.balloon = Some(BalloonConfig
  { enabled: false, ..Default::default() })`. The QEMU wrapper
  still attaches the device (it is wrapper-unconditional); the
  daemon does not spawn `run_controller` for the session.

No granular CLI knobs (thresholds, intervals, divisor) ship in v1.
Operators who need per-VM tuning edit `config_json` directly; we
may grow env-var defaults or a config file later if real demand
appears. Avoiding the surface area here is deliberate — most
operators should never need to think about the tuning, and the
defaults are sized to be conservative.

### Container backend

The container backend (`sandbox-core/src/backend/container.rs`) has
no QEMU process and no virtio-balloon mechanism. Container memory
limits are imposed by Docker via cgroups (`--memory`), a separate
mechanism already in place via the `format_cpus`/`memory_arg`
plumbing inside the `build_create_argv` function and the
`Capabilities` returned by the `capabilities_for_container`
function (both in `sandbox-core/src/backend/container.rs`).

Behaviour:

- At controller-spawn time, the daemon switches on
  `session.backend` (the `Session::backend` field in
  `sandbox-core/src/session.rs`). For `BackendKind::Container`,
  `run_controller` is **not spawned**. No error, no warning.
- `--balloon=enabled` or `--balloon=disabled` on a container
  session is a no-op at runtime. `SessionConfig` is backend-
  uniform, so the field is set unconditionally on the CLI parse
  path; the controller-spawn check on `session.backend` is what
  gates behaviour. A create-time warning ("balloon flag is ignored
  on container sessions") is not part of v1; if operators trip
  over the silence, we add it as a follow-on.

The container backend's `Capabilities` (returned by the
`capabilities_for_container` function in
`sandbox-core/src/backend/container.rs`) is **not** extended with a
balloon capability bit. Balloon is a Lima-internal mechanism;
surfacing it through the capabilities API would imply it might be
selectable per backend, which it is not.

### Persistence

No SQL migration. The new `BalloonConfig` value rides inside
`SessionConfig.balloon`, which is serialised into the existing
`config_json` TEXT column. The persisted-blob-evolution rules from
CLAUDE.md apply:

- `SessionConfig.balloon` is `Option<BalloonConfig>` with
  `#[serde(default, skip_serializing_if = "Option::is_none")]`.
- `BalloonConfig` is declared `#[serde(rename_all = "snake_case",
  default)]` so individual field additions in the future
  deserialise cleanly against records written today.
- No persisted-blob field is ever renamed or removed without a
  migration; we add only.

### Verification

#### Unit tests

In `sandbox-core/src/balloon.rs`:

- `estimate_slack` table-driven cases:
  - Positive slack with sufficient free + half-credited cache
    (`cache_divisor = 2`): asserts the returned value matches the
    formula to within one byte.
  - Zero slack when `rss < qemu_overhead`: asserts the saturating
    subtraction returns `0` and never panics.
  - Zero slack when `stats.free_memory + stats.disk_caches >
    stats.total_memory` (stale or rounded snapshot): asserts the
    chained `saturating_sub` on `guest_used_real` collapses to `0`
    and the final result is `0`, never a wraparound.
  - Cache fully discounted (`cache_divisor = 255`): asserts cache
    contribution to slack is essentially zero.
  - Cache fully credited (`cache_divisor = 1`): asserts cache
    contribution equals `stats.disk_caches`.
- `BalloonConfig` round-trip via `serde_json`:
  - `Default::default()` serialises and deserialises to itself.
  - JSON blob with a subset of fields → missing fields fill from
    `Default`.
  - JSON blob without `balloon` on `SessionConfig` →
    deserialises with `balloon: None`; resolving at controller-
    spawn time produces `BalloonConfig::default()`.
- `pulse` against a mock `QmpClient` (a trait abstraction over the
  four new methods, or a feature-gated test-only impl injected via
  generic):
  - Successful inflate to target → returns `Reached`; the deflate
    QMP call to `mem_total` was issued.
  - Mock returns ever-decreasing `free_memory` below
    `safety_floor_bytes` → returns `AbortedPressure`; deflate
    issued.
  - Mock never converges within `max_pulse_ms` → returns
    `AbortedTimeout`; deflate issued.
  - Mock returns an error on inflate → guard's `Drop` issues the
    deflate as the function unwinds; final result surfaces the
    original error.
  - `BalloonDeflateGuard` directly: panic-injection between
    construction and `disarm` exercises the `Drop` path; assert
    the mock observed a `balloon_set_actual(mem_total)` call and
    a `set_balloon_polling_interval_secs(idle)` call.
  - `BalloonDeflateGuard::disarm` then drop → assert the mock
    observed **no** restore calls (the guard is correctly
    disarmed).

In `sandbox-core/src/lima.rs`:

- Extend the existing `QEMU_WRAPPER_SCRIPT` content tests (the
  module already has wrapper-content assertions) to assert the
  rendered script contains
  `-device virtio-balloon-pci,id=balloon0,deflate-on-oom=on,stats-polling-interval=15`
  in the always-on `EXTRA_ARGS` section.

In `sandbox-core/src/session.rs`:

- `SessionConfig::default()` round-trips with `balloon: None` (the
  existing default-round-trip test already exercises the shape).
- A `config_json` blob predating the `balloon` field deserialises
  with `balloon: None` (forward-compat).
- A `config_json` blob with `balloon: { "enabled": false }` and no
  other fields deserialises into `BalloonConfig` with `enabled:
  false` and every other field at `Default::default()`.

#### Integration tests

All under the `integration_balloon_*` prefix per CLAUDE.md
("Integration-test convention" in CLAUDE.md). Each requires a real
Lima VM and is selected by the `integration` nextest profile
(`sandboxd/.config/nextest.toml`).

- `integration_balloon_device_present_at_boot` — create a session;
  open `QmpClient::for_session`; call `query-balloon`; assert
  `actual == mem_total_bytes` ± `tolerance_bytes`; call
  `balloon_guest_stats`; assert `total_memory > 0`.
- `integration_balloon_pulse_reclaims_rss` — create a session;
  record QEMU `VmRSS` baseline; via the guest connector, fill
  `/dev/shm/blob` with N MiB; record `VmRSS` post-fill; remove
  the blob; invoke a single pulse via a test-only helper; assert
  `VmRSS` post-pulse < (`VmRSS` post-fill − (N MiB −
  `safety_margin_bytes`)).
- `integration_balloon_polling_interval_dynamic` — during a
  pulse, observe via `qom-get` that
  `stats-polling-interval == 1`; after the pulse, observe it is
  back to `15`.
- `integration_balloon_abort_on_pressure` — start a guest-side
  memory-stress task that reserves close to (`mem_total −
  safety_floor_bytes`); invoke a pulse with a small target;
  assert `PulseOutcome.reason == AbortedPressure` and that the
  final `query-balloon.actual == mem_total`.

#### E2E tests

In `tests/e2e/test_balloon.py` (new file, marked
`@pytest.mark.lima` so it is excluded from the container-only
matrix):

- `test_idle_session_rss_decreases` — create a Lima session with
  default config; wait 90 s (enough for at least one controller
  tick plus jitter); assert the QEMU process's `VmRSS` has
  dropped by ≥ 200 MiB from the peak captured at session-ready.
  The minimum reclaim at the firing edge of the controller is
  `inflate_threshold_bytes − safety_margin_bytes = 500 MiB −
  256 MiB = 244 MiB`; the 200 MiB bound sits well below that
  floor to absorb stat-sampling jitter and short-lived guest
  activity. The bound can be tightened after a few weeks of
  empirical baselining.

### Docs

- `docs/guides/hardening.md` (around `## Layer 1 — QEMU wrapper`,
  line 24 in the current file) — add a "Memory reclaim" subsection
  alongside the existing "Cgroup resource limits" and "Seccomp is
  deliberately off" notes. Explain that the balloon is always
  attached, that `deflate-on-oom=on` provides a guest-side safety
  floor, and that pulse windows may briefly depress `MemAvailable`
  seen by guest applications (but never `MemTotal`).
- `docs/guides/workspaces.md` — no changes; balloon is orthogonal
  to workspace mode.
- `docs/concepts/architecture.md` (the existing top-level
  architecture document) — add a short paragraph in the runtime-
  responsibilities section pointing at the new internal note.
- `docs/internal/balloon-controller.md` (new file) — pulse pattern
  overview, the slack formula, dynamic polling-interval rationale,
  why pulse over continuous-target, and external references
  (QEMU virtio-balloon manpage, the `qom-set` reference, the
  upstream Linux `virtio_balloon` driver source). This is the
  document a future maintainer should read to debug the
  controller; it is internal because the user-facing surface is a
  single CLI flag.
- `--balloon` is documented under `sandbox create` in
  `docs/reference/` (the existing CLI reference). One paragraph
  on when to use `--balloon=disabled`: when investigating
  memory-related behaviour in a guest application, or in
  latency-sensitive workloads where the brief pulse window (sub-
  second to ~15 s, several minutes apart) is unacceptable.

## Out of scope

- **KSM.** Orthogonal mechanism; host-wide
  `/sys/kernel/mm/ksm/run` configuration; separate spec if pursued.
  Issue #4 named both; this spec ships only the virtio-balloon half.
- **Free Page Reporting.** Viable alternative or complement;
  evaluation against the pulse baseline is a v2 follow-on item.
- **Cross-session memory budgeting.** Each controller observes its
  own session only. No global "VM A is busy, squeeze VM B harder"
  logic.
- **Per-application coordination hooks** (guest-side lock files,
  pulse-suppress sentinels). Apps that want to read `MemAvailable`
  outside pulse windows must currently rely on the >95%
  not-pulsing property of the design.
- **Granular per-knob CLI tuning** of thresholds, intervals, or
  the cache divisor. Only `--balloon=enabled|disabled` is exposed
  in v1.
- **Container-backend dynamic memory reclaim.** cgroup-based
  mechanism, separate concern. `--balloon=disabled` on a container
  session is a silent no-op.
- **macOS host.** VZ handles reclaim natively; the QEMU/Lima path
  does not run there.
- **Balloon-aware capabilities API.** Balloon is Lima-internal and
  not surfaced through `backend::Capabilities`.
- **A way to flip `--balloon` on an existing session.** Creation-
  time only in v1; operators who want to toggle a long-running
  session edit the persisted `config_json` and restart the daemon
  (or destroy/recreate).

## Known gaps / deferred decisions

- **Adaptive `cache_divisor`.** The divisor ships as a static
  config knob. A feedback-driven version (raise the divisor if
  `stat-major-faults` jumps in the minutes following a pulse,
  indicating we squeezed too much cache) is plausible and
  deferred. Static defaults are conservative enough that this is
  unlikely to be the limiting factor.
- **Cross-session pulse staggering.** Per-controller jitter
  (±10% on `loop_interval_ms`) prevents synchronised pulses
  across sessions in practice but is not a hard guarantee. A
  daemon-wide scheduler that enforces "at most one pulse in
  flight host-wide" is plausible if jitter proves insufficient.
- **Pulse-aware app coordination.** Lock files or guest-side
  sentinels that let an in-VM workload temporarily suppress the
  controller. Parked; revisit if real workloads complain about
  the pulse window.
- **FPR vs pulse comparison.** Needs a controlled experiment
  under realistic session-count and workload-mix. Track as a v2
  evaluation item; the device option (`free-page-reporting=on`)
  can be flipped on in the wrapper independently of the
  controller.
- **KSM.** Orthogonal host-config mechanism; not addressed here.
  Operators may set `/sys/kernel/mm/ksm/run=1` independently and
  observe additional reclaim on top of the pulse baseline.
- **Container-backend silent no-op.** A
  `--balloon=disabled` on a container session is currently
  accepted without warning. If operators trip on this, surface a
  create-time warning ("flag is ignored on container sessions");
  no functional change.
- **Controller restart on daemon crash.** The controller is a
  daemon-owned task. Daemon crash drops every controller; on
  restart, the new daemon iterates persisted Lima sessions and
  re-spawns controllers from `SessionConfig.balloon`. The
  re-spawn path is described above but is not exhaustively tested
  in v1; an integration test specifically for daemon-restart
  re-spawn is a follow-on.
