# macOS e2e baseline

The measured state of the end-to-end suite on a macOS host, and the defect
catalogue behind it. It exists so that the next person to work on macOS
conformance starts from evidence instead of from a fresh run.

**Baseline measured at commit `436ce35`** (*fix(daemon): run startup
reconciliation on a blocking task*), workspace version **0.1.10**, on an
Apple-Silicon macOS host. Everything below is marked **[M]** — measured on that
host — or **[I]** — inferred. The distinction is load-bearing: several
attractive conclusions here are inferences that a fix should confirm before
relying on them, and they say so at the point of use.

This document is self-contained by design. Nothing in it depends on logs,
scratch directories, or classifier scripts, all of which were ephemeral and are
gone.

---

## 1. Headline: the macOS full backend has no egress at all

**The Lima guest never receives its gateway default route, so no legitimate
traffic can leave a full-backend session.** [M]

The suite makes this unusually easy to see, because the split is perfect:

- **Every `[lima]` test that asserts traffic is *blocked* passes.**
- **Not one `[lima]` test that requires working egress passes.**

The eleven `[lima]` tests that pass in the second half of the run pass for
exactly two reasons — they assert a denial (`test_level0_denied`,
`test_level3_host_mismatch`, `test_empty_policy_denies_dns`), they validate CLI
config without moving a packet
(`test_policy_rejects_http_level_with_udp_protocol`), or they use the guest
*transport* (`exec`/`socat`) rather than network egress (the `test_cp_*` and
`test_sync_*` families). [M]

The mechanism is measured directly, not inferred from that pattern. A test that
dumps the guest's routing table produces:

```
AssertionError: gateway default route via 10.209.128.3 was not present before mutation.
  routes:
assert 'via 10.209.128.3' in ''
  where '' = CompletedProcess(args=[… 'exec', 'net-slirp-bypass-test', '--',
                                    'ip', 'route', 'show', 'default'],
                              returncode=0, stdout='', stderr='')
```

`ip route show default` returns **rc=0 with empty output** — the guest has **no
default route at all**. The gateway route was never installed, and the SLIRP
default is absent too (expected: `slirp-restrict` removes it by design, which is
what those two tests exist to check). The daemon side is healthy for the same
session — it logs `setting up macOS gateway … nic=lima0
gateway_ip=10.209.128.3`, then `all gateway components are ready`, then `macOS
gateway fully initialised with nftables rules`. **The gateway is up and armed;
the guest simply has no path to it.** [M]

**Read the consequence precisely.** The backend **fails closed**. Enforcement
holds, the core promise is intact, and this is not a security regression — it is
a capability gap that makes the full backend unusable for real work. It is also
the single largest cause in the run: 24 of 85 failures (28%).

Two things it is **not**, both ruled out by measurement:

- **Not the `rewrite_vm_network_slot` EACCES defect** (see D5). That fires
  **3** times across roughly 135 sessions in the run. It cannot explain 24
  failures. [M]
- **Not `generate_guest_network_script`** (`sandbox-core/src/qmp.rs:335`, the
  `ip route add default via {gateway_ip} … metric 50` line). The daemon log
  contains **zero** mentions of QMP, NIC hot-add, or that script — it is the
  Linux path and is never reached on macOS. [M]

Which leads to the most valuable open question in this document: **on the macOS
Lima backend there appears to be no code path that installs the guest default
route at all.** That clause is **[I]**, from log absence plus a code read.
Confirm it directly before writing a fix — "installs the wrong route" and "has
no route-installing code" are different fixes.

One corroborating observation, deliberately marked weak: across all nine
guest-agent `local_ports` dumps captured in the run, the guest's bound addresses
are only ever `192.168.5.x` (SLIRP), never `10.209.128.x`. That is **[I]** and
not conclusive — `local_ports` lists listening sockets, not interface addresses,
so a configured-but-idle vmnet NIC would look identical. The empty routing table
is the load-bearing measurement.

---

## 2. Running the suite

```bash
make test-e2e-macos SCOPE=full     # the baseline run: full macOS matrix
make test-e2e-macos SCOPE=container # container-only slice (PR-time gate)
make test-e2e                       # auto-detects the host and dispatches here
make test-e2e-macos TEST=tests/e2e/test_networking.py   # single file or node id
```

The baseline was produced by `make test-e2e-macos SCOPE=full`, with
`PATH=$HOME/.cargo/bin:$PATH` exported so the recipe's cargo build resolves.

`SCOPE=full` selects `-m "not linux_only"`; `SCOPE=container` selects
`-m "not lima and not linux_only" -k "not [lima]"`. The target hard-fails on a
non-Darwin host.

### Grading a run

**A green exit does not mean the suite ran.** Grade on collected/passed counts,
never on the exit status. The harness *skips* rather than fails when the host is
unprovisioned — conftest's session-scoped autouse preflight calls `pytest.skip`
when `docker info` fails or the versioned gateway image is absent, and a
session-wide skip leaves pytest at exit 0 with every collected test skipped. The
target passes `-rs`, which prints every skip reason; read them.

Note also that this target is the most exposed of the e2e targets: it is the
only one that does not take `gateway-image` as a prerequisite, so nothing in it
builds the image its preflight demands.

### Host preconditions

`make setup-dev-env` provisions the accounts, groups, sudoers fragment and agent
binary the harness needs. It was deliberately **not** run before the baseline
measurement; the host already satisfied its requirements. What the harness
enforces itself, loudly, before launching the daemon:

- an **active** `_sandboxd-test` group membership in the calling shell (macOS
  has no `sg`, and the target does not substitute for it — a freshly added
  membership requires a re-login),
- the daemon base dir `/var/lib/sandboxd/<daemon-uid>`,
- the NOPASSWD sudoers fragment.

An absent `_sandboxd-test` user causes a skip rather than a failure. The
`macos_only` and `lima` tests additionally need an operator agent — either the
test-feature binary the harness launches itself, or the production LaunchAgent
loaded via launchctl. With neither, those tests skip; `SCOPE=container` selects
none of them.

The `sandboxd-gateway` Lima VM is **not** a host precondition — the daemon
creates it when absent and starts it when stopped. The socket_vmnet pool is.

### Timing

The baseline run took **1h19m58s** of pytest wall clock (`4797.85s`). That
figure includes a one-time base-image rebuild of **7m14s**, which does not
recur when the golden base image is already present. Budget ~80 minutes.

Do not run this in a foreground call with a short timeout. Detach it, or
delegate it, and poll the log.

### Starting state the baseline assumed

Recorded so a later run can be compared like-for-like rather than guessed at.
All [M], verified before launch:

| check | state at launch |
|---|---|
| `sandboxd` processes | 0 (`/usr/libexec/sandboxd` in `ps` is Apple's own daemon, not this one) |
| session QEMUs | 0 |
| gateway VM QEMU | running |
| vmnet pool | 8 `socket_vmnet` processes, `--socket-group=_sandboxd` |
| gateway VM containers | 0 |
| gateway VM networks | `bridge`/`host`/`none`/`sandboxd-egress`; no `sandbox-net-*` |
| gateway VM images | `sandbox-gateway:0.1.10`, `sandboxd-lite:0.1.10` (matching workspace version) |
| `sessions.db` | 0 rows |
| operator LIMA_HOME | config + base-image metadata, no instance dirs |
| disk | 743 GiB free |

The gateway VM has **~1.9 GiB** of RAM (`docker info` → `MemTotal 2050310144`),
which matters when reasoning about anything crash-looping inside it.

---

## 3. The graded baseline

| metric | value |
|---|---|
| collected | 168 |
| deselected (`-m "not linux_only"`) | 8 |
| **selected** | **160** |
| **executed** | **160** (every selected test produced a result line) |
| **passed** | **74** |
| **failed** | **85** |
| **errors** (fixture/setup) | **0** |
| **skipped** | **1** |
| non-passing total | 86 |
| pytest exit | 1 |
| wall clock | 1h19m58s |

Two independent tallies agree — pytest's own summary line and a direct count of
result lines — so nothing silently no-opped. [M]

The single skip is intentional and documented at the test site: the host-path-echo
default for a lite `local:` workspace created without an explicit guest path,
declared a limitation rather than a defect. `-rs` prints the full reason.

### How the run got here

Four full runs were executed. Their trajectory is worth keeping, because it is
what licenses the "no regressions" and "deterministic" claims below.

| run | passed | failed | errors | skipped | wall | what changed before it |
|---|---|---|---|---|---|---|
| 1 | 36 | 123 | 0 | 1 | 24m50s | first full-suite run ever |
| 2 | 50 | 104 | 5 | 1 | 36m00s | session-name collision fixed |
| 3 | 36 | 123 | 0 | 1 | 23m47s | three harness fixes (agent log to a file; restart tests kill the real daemon; container reaper) |
| **4 (baseline)** | **74** | **85** | **0** | **1** | **1h19m58s** | daemon startup reconciliation moved onto a blocking task |

Runs 1 and 3 share the 36/123 figure by coincidence; their composition is
completely different.

**Compare regions, not totals.** Runs 1–3 differ in how far they got — run 3
died at position 63 and its last 97 positions never executed, so its totals are
not comparable to run 4's. The region-scoped view:

| positions | run 1 | run 2 | run 3 | **run 4** |
|---|---|---|---|---|
| 1–62 (every run reached) | 35 P / 26 F | 25 P / 31 F / 5 E | 36 P / 25 F | **36 P / 25 F** |
| 63 (first restart test) | FAIL | FAIL | FAIL | **PASS** |
| 64–160 (run 3 never measured) | 1 P / 96 F | 25 P / 72 F | 0 P / 97 F | **37 P / 60 F** |

Region 1–62 in the baseline is **identical to run 3 — same count, same 25
failures, same signatures.** The run-4 fix cost nothing where comparison is
valid. Region 64–160 is where the baseline earns its name: 37 passing where run
3 had none.

Per-test deltas into the baseline: **38 newly passing vs run 3, 24 vs run 2, 38
vs run 1 — and 0 regressions against any of them, at any position.** [M]

### About "position" numbers

Positions below are the 1-based index of a test in the deterministic selection
order of the 160 selected tests, as the suite stood at the baseline. They are
convenient for reasoning about regions and cascades and they will **drift the
moment a test is added or removed**. The test *name* is the durable identifier;
treat a position as a hint about ordering, not an address.

---

## 4. Defect catalogue

**18 classes are catalogued: 16 that produce test failures, and 2 that produce
none but are real.** The 16 account for all 85 failures exactly.

| class | n | positions |
|---|---|---|
| **D2** Lima guest has no gateway default route | **24** | 56, 57, 58, 62, 67, 68, 72, 74, 76, 78, 80, 84, 85, 91, 93, 97, 99, 101, 105, 107, 111, 113, 117, 119 |
| **D15** gateway event never reaches the ring | **11** | 77, 79, 81, 82, 83, 114, 115, 116, 118, 120, 121 |
| **D6** test queries host Docker, not gateway-VM Docker | **10** | 39, 52, 53, 54, 55, 65, 66, 87, 88, 102 |
| **D12** local-workspace rsync fails (lite macOS) | **10** | 144, 146, 150, 152, 153, 154, 155, 156, 157, 158 |
| **D16** Lima guest cannot see its workspace | **7** | 125, 141, 143, 145, 149, 151, 159 |
| **D4** git-remote `empty session name in URL` | **5** | 10, 11, 12, 13, 35 |
| **D11** golden-image family | **3** | 14, 15, 16 |
| **D5** `rewrite_vm_network_slot` EACCES | **3** | 28, 60, 124 |
| **D8** lite `shared:` path outside the shared root | **3** | 37, 142, 160 |
| **D3** deny events absent under empty policy | **2** | 4, 5 |
| **D13** host `getent` missing | **2** | 95, 96 |
| **D7** `/proc/meminfo` on macOS | **1** | 34 |
| **D9** TCC warning never emitted | **1** | 51 |
| **D14** CoreDNS log missing `example.com` | **1** | 59 |
| **D17** dead session still `Running` after reconcile | **1** | 69 |
| **D18** create not rejected for unreadable host file | **1** | 147 |
| *(no test failures)* DNS-gate bridge retry spin | — | — |
| *(no test failures)* agent check-in startup race | — | — |

Failures were classified from **assertion text only**, with Lima hostagent JSON
dumps excluded. That exclusion is not fussiness: an earlier classification pass
had to be hand-corrected because a 300 KB daemon-log dump embedded in one
assertion tripped keyword rules. Four labels still needed manual correction in
the baseline pass (positions 51, 119, 120, 147); the table above is the
corrected version.

**Assertion text fixes a failure's signature reliably and its product-vs-harness
attribution only by luck.** One string — a missing event, a failed `docker
exec`, an unmet expectation — is emitted both by a daemon that is broken and by
a test pointed at something this host does not have. A later pass re-derived
three of these classes from the source rather than the log, and the answer moved
each time: D15's signatures (`expected event absent`, `ring empty`) are exactly
what a test looking in the wrong place produces, so assertion text alone files
all 11 as test-side, while the code shows the events have no transport out of
the container at all; D4's mechanism is not where its message points; and D9's
remedy is inverted — the fix belongs in the test, not the daemon. The three
worked examples are written up under their own entries below. Treat every
product-vs-harness label in this document as provisional until someone has
opened the code path it names. [M]

### D2 — Lima guest has no gateway default route (24)

Fully described in §1. Two caveats stated rather than buried:

- **D2 is one label over two sub-shapes** — "no default route / cannot reach the
  gateway" (positions 56, 57, 62, 67, 68) and "DNS/TCP/TLS/HTTP from the guest
  times out" (the rest). There is a single measured mechanism for the first and
  a strong shared shape for the second, but **one mechanism was not proved for
  all 24**. The grouping is **[I]**; the individual failures are **[M]**.
- Expect a **second crop of failures behind the fix**. Once traffic flows, the
  L2/L3 and preset assertions become meaningful for the first time, and some
  will fail on their own merits.

### D15 — gateway allow/deny events never reach the ring (11)

Enforcement works; the event is lost. Signatures: `0 nft-allow events captured`,
`expected event absent`, `0 mitmproxy.request_denied events`, `ring empty`,
`lifecycle.policy_applied{status=ok}` absent.

**Attribution is split and should stay split.** The **8 `[container]` rows are
genuine** — that backend's traffic demonstrably works and the events are still
missing. The **3 `[lima]` rows (82, 115, 121) may be D2 downstream**: if no
packet leaves the guest, no allow/deny event can be produced. Treat this class
as *8 confirmed + 3 possibly-D2* until D2 is fixed. [M] on the counts, [I] on
the split.

Same territory as D3 — both are "enforcement holds, the event is lost".

**Mechanism for the 8 `[container]` rows: the macOS gateway container is created
with no bind-mounts at all, and the JSONL event files are the one artifact that
never got a replacement transport.** [M]

On Linux the gateway is started with `-v <events-host-dir>:/var/log/gateway/events`
(`create_gateway` in `sandbox-core/src/gateway.rs`; the container-side constant
is `EVENTS_DIR_IN_CONTAINER` in `sandbox-core/src/events/mod.rs`), and the
daemon's inotify ingestor reads the host side of that mount. On macOS the
gateway runs *inside the gateway Lima VM*, where a macOS host path would mount
nothing — so the run args carry no `-v` at all. That is deliberate and pinned by
a unit test: `test_macos_gateway_hardening_args` in
`sandbox-core/src/macos_session.rs` asserts `gateway run args must NOT contain
-v / --volume bind-mounts`.

Two artifacts that crossed that boundary were each given a purpose-built
replacement and work. The Envoy listener is written directly into the
container's tmpfs (`write_gateway_file`, with the rationale in the comment above
the Envoy seeding loop in `macos_session.rs`), and the DNS-gate socket is
bridged (`sandbox-core/src/dns_gate_bridge.rs`, whose module doc states the
no-bind-mount premise independently). The five JSONL producers — `envoy.jsonl`,
`coredns.jsonl`, `mitmproxy.jsonl`, `nft-deny.jsonl`, `nft-allow.jsonl`, named
as constants in `sandbox-core/src/events/ingest/watcher.rs` — got none. They are
still written, inside the container, onto a tmpfs that nothing reads.

The daemon arms the reader anyway: `create_session_macos_lite` in
`sandboxd/src/main.rs` calls `spawn_session_ingestor` unconditionally, which
creates the host events directory and starts an inotify watch on a directory no
container will ever write to. Nothing errors, and nothing logs a warning.

**The operator-visible consequence is wider than these 8 tests: `sandbox events`
returns an empty stream for every macOS lite session, and reports no failure
while doing it.** The tests are not the only thing this breaks; they are just
the only thing currently noticing. [M]

**Why this entry is load-bearing: the code's own record of the gap has already
thinned.** The design comment in `macos_session.rs` previously covered "the
listener **and events** host directories"; it now names only the listener. The
gap did not close — a sentence narrowed, and the only in-code trace that the
*events* transport was also missing went with it. Read on its own today, the
remaining comment looks complete and correct, and the five orphaned producers
read as an oversight nobody ever noticed rather than one that was noticed and
recorded. That erosion is why the mechanism is written out here in full rather
than left as a pointer to a comment. [M]

### D6 — tests query host Docker, not the gateway VM's (10)

Test-side, not product. The affected tests shell out to plain `docker`, which
reaches the **host's** Docker daemon rather than the one inside the gateway VM
where session and gateway containers actually live. Signatures: `Gateway
container sandbox-gw-… is not running`, `Error response from daemon: No such
container: sandbox-gw-…`, `docker exec` into the gateway container failing, and
an orphan-cleanup test seeing only an unrelated host container.

`_gateway_vm_docker_argv()` already exists in conftest; the remaining call sites
are in `test_lite.py` and `test_networking.py`. This is the cheapest
failures-per-line fix in the run, and it has grown across the series (6 → 4 → 5
→ 10) as more of the suite became reachable.

Fixing it also repairs the daemon fixture's leak-cleanup net, which is why an
early run left five gateway containers crash-looping inside the gateway VM.

### D12 — local-workspace rsync fails on lite macOS (10)

Daemon log: `local-workspace rsync failed (lite macOS)`, across 11 sessions in
the run. Test-visible as the `test_workspace_local.py` family failing on the
container backend. Historically this surfaced as `rsync failed (exit 23)`.

**It has a downstream sibling — see the DNS-gate bridge spin below.** One fix,
two payoffs.

### D16 — Lima guest cannot see its workspace (7)

Distinct from D12: that one is the lite/container backend, this is the Lima
mount/push path. Signatures: expected README absent from
`/home/sandbox/workspace/`; `cat from-host.txt` failing in the VM; a host file
not visible at `/home/sandbox/work/hello.txt`; `Directory nonexistent` when
writing in the guest; an operator-supplied `:<guest_path>` not mounting at
`/srv/work`.

Diagnose as one family before splitting it.

### D4 — git-remote `empty session name in URL` (5)

`empty session name in URL: /var/lib/sandboxd/<daemon-uid>/sandboxd.sock`,
rc=128. One code path in the git-remote URL parser. Stable at exactly 5 failures
in every run of the series — one of the determinism control rows.

**The defect is not in the URL parser, and the message points away from it.**
(The sentence above, written from the assertion text, is the mis-attribution
this entry corrects; it is left in place so the two readings can be compared.)
Read the reported URL: it is the *daemon socket path*, not a `sandbox::` URL.
The tests configure a well-formed remote (`sandbox::<session>/<path>`) and set
`SANDBOX_SOCKET` rather than passing `--socket`, so the URL git hands the helper
is correct. The socket path can only arrive at the parser from one place. [M]

`run_remote_helper` (`sandbox-cli/src/main.rs`) takes its URL from `args[2]`.
The helper's own re-exec spawns the binary with
`["--socket", <socket>, "ssh", <session>, "--", <service>, <repo_path>]` — an
argv whose `args[2]` *is* the socket path. That child is meant to take the
ordinary clap path, and it does so only if `invoked_as_remote_helper()` returns
false; that function tests whether the basename of `argv[0]` is
`git-remote-sandbox`. The child's `argv[0]` is whatever
`std::env::current_exe()` returned in the parent.

So the observed error entails that on macOS `current_exe()` yields the
**unresolved symlink** — basename `git-remote-sandbox` — and the child therefore
re-enters remote-helper mode and parses `--socket`'s argument as its URL. On
Linux `/proc/self/exe` resolves to the real `sandbox` binary, the basename test
fails as intended, clap parses the subcommand, and the path works. That is why
this class is macOS-only and why it is perfectly stable.

**Confirmed by direct probe. [M]** The premise that step rests on — that Darwin's
`std::env::current_exe()` does not resolve a symlink — was measured standalone,
with no daemon, Lima, Docker or session involved: a binary that prints
`current_exe()`, a symlink beside it under a second name, and exec through each.
On Darwin arm64, all three symlink invocation forms — relative, absolute, and
PATH lookup, which is the form git uses — return `current_exe()` equal to the
**symlink path**, basename `git-remote-probe`. The negative control
discriminates: exec through the real path returns the real basename, so the
probe is not reporting the symlink name unconditionally.

**The toolchain is not an unvaried factor here.** All four arms were run under
both `rustc 1.96.0`, the host's default `stable`, and `rustc 1.88.0`, the
version `sandboxd/rust-toolchain.toml` pins and therefore the one the daemon is
actually built with. The output was identical. That agreement is the
load-bearing fact rather than either version alone: `current_exe()` is std
behaviour and could differ across releases, so a single-toolchain result would
leave the std implementation silently scoping the conclusion.

A child spawned as `Command::new(current_exe())` therefore carries `argv[0]`
whose basename is the symlink's name, which is exactly the predicate
`invoked_as_remote_helper()` tests. Linux cannot reproduce this: `current_exe()`
reads `/proc/self/exe`, a kernel-maintained link to the resolved inode of the
running image, so it is structurally incapable of reporting the symlink used to
launch. That asymmetry is the whole of the platform difference.

Fix at the spawn, not in the parser. Resolve the symlink before re-exec'ing, or
pass an explicit marker that suppresses helper-mode detection in the child. A
parser-side fix would silence the message while leaving the child running in the
wrong mode.

### D11 — golden-image family (3)

Three failures, **two different mechanisms**, and they should not be fixed as one:

- **Positions 14 and 15 are a harness bug.** The tests read the daemon fixture's
  `_stdout_log`, which on macOS is **0 bytes** — tracing goes to
  `--log-file /var/lib/sandboxd/<daemon-uid>/sandboxd.log` instead. The daemon
  demonstrably logged the very string position 14 asserts on and reported as
  absent (`sandbox_core::lima: cloning base image session_id=…`). The macOS lite
  tests already read the correct file; these should too. [M]
- **Position 16 is a product/environment defect**: the lite image build inside
  the gateway VM cannot resolve `registry-1.docker.io`, giving `failed to
  resolve reference "docker.io/library/ubuntu:24.04"`. This carried its own
  label in the earliest classification and was later folded into the
  golden-image family; do not lose it in the fold. [M]

A standalone reproduction of position 14 also failed *earlier and differently*
than it does in-suite (the base image was reported missing and not rebuilt), so
there may be a third, order-dependent shape here.

### D5 — `rewrite_vm_network_slot` EACCES (3)

`rewrite_vm_network_slot: failed to read …/lima.yaml: Permission denied`. The
daemon reads the operator-owned `lima.yaml` directly; on the cross-user path it
must go through the agent. Correctness, not cosmetics — but note it fires only
3 times in the whole run, so it explains almost nothing else.

### D8 — lite `shared:` path outside the shared root (3)

The lite backend rejects a `shared:` host path that falls outside the shared
root (`/tmp/sandbox-shared` on the measured host).

### D3 — deny events absent under empty policy (2)

**A genuine product defect on *both* macOS backends, and its mechanism is fully
measured.** [M]

`setup_macos_gateway` (`sandbox-core/src/macos_session.rs`) runs the gateway
container attached **only** to `sandboxd-egress`, and attaches the VM-facing
macvlan NIC afterwards (line 328) — a deliberate split so health checks always
have an uplink. But the entrypoint, already running by then, resolves
`GATEWAY_IP="$(hostname -i | awk '{print $1}')"`
(`networking/gateway/entrypoint.sh:231`) and passes it to
`sandbox-nft-deny-logger --bind-ip`. `inject_dnat` (`macos_session.rs:377`) then
targets `network_info.gateway_ip`.

Measured live on a Lima-backend session gateway:

```
entrypoint: Discovered gateway bridge IP: 172.18.0.7
entrypoint: Starting sandbox-nft-deny-logger on 172.18.0.7:10001 ...
hostname -i (now, both NICs up): 172.18.0.7 10.209.128.3
nft: ip saddr 10.209.128.0/29 meta l4proto 6 dnat ip to 10.209.128.3:10001
```

**The logger listens on the egress address; TCP denies are DNAT'd to the
session-facing address, where nothing is bound.** Enforcement still fails
closed — only the event is lost.

Two fix shapes: pass the session gateway IP into the container explicitly
(`GATEWAY_IP` is already overridable via env) rather than deriving it from
`hostname -i`, or attach the session NIC before the entrypoint reaches that line.

This was originally recorded as a lite-only observability gap. It is not — it
affects the full backend too, and both parametrizations of the discovery test
reproduce it standalone.

### D13 — host `getent` missing (2)

Test-side: the tests call `getent` on the **host**, which macOS does not have.

### D7 — `/proc/meminfo` on macOS (1)

Test-side `FileNotFoundError: '/proc/meminfo'`. It also exposes a **product
gap**: the container backend cannot read host RAM on macOS and falls back to a
hardcoded value, logging `container backend: /proc/meminfo unreadable; using
fallback host RAM 4096 MB` — **708 times** in the baseline run (197 in the
previous run). One test failure, a lot of noise, and a wrong resource default.

### D9 — TCC warning never emitted (1)

The daemon never emits the `access runs as _sandboxd (gateway VM user)` warning
that the test asserts on. Worth stating that this test reads the **correct** log
file (302,821 bytes of it), so unlike D11 this is not the log-source bug — the
warning is genuinely absent.

**It is absent because it was removed on purpose. The stale artifact is the
test, not the daemon.** [M] Commit `bbd9d6f`, *"stop advising TCC avoidance
after a lite shared: path is accepted"*, deleted it deliberately: the warning
fired on the success path, after the shared-root check had already passed, so
advising the operator to keep the source out of Desktop / Documents / Downloads
was — in the commit's own words — *"both unactionable and wrong (a path under
the shared root is in none of them)"*. The one fact worth keeping, that the
host-side read runs as the daemon user rather than the operator, was retained
and dropped from `warn!` to `debug!`.

Two consequences, and the second is the one that costs an afternoon if missed.
The asserted substring now appears nowhere in the Rust tree — only in
`tests/e2e/test_lite_macos.py` and in this document. And because that commit
rewrote the *wording* as well as lowering the level, **raising the daemon's log
level would not turn this test green either**; the surviving line reads
`host-side access runs as the sandboxd daemon user (gateway VM owner), not the
operator`. The remedy is to update the test's expectation to the surviving line
or drop the assertion.

A reader who takes "the warning is genuinely absent" at face value will go
looking for a bug that was removed intentionally. This entry is the correction
to that reading, not a softening of it.

**Resolved since the baseline.** The remedy above was taken: the test now
asserts on a slice of the line the daemon actually emits, copied from the emit
site rather than transcribed. It was renamed in the same change —
`test_shared_workspace_tcc_warning` →
`test_shared_workspace_under_root_is_accepted_and_names_its_reader` — because
the old name described an assertion that no longer exists. Position 51 in the
table below still carries the old name: it is the measurement, and renaming a
recorded observation would make the baseline unreproducible.

One quoted string above did **not** survive to the fix, and it is worth being
explicit about which. The surviving line is no longer `host-side access runs as
the sandboxd daemon user (gateway VM owner), not the operator`. That wording
stated a mode-dependent fact flatly: the reading account is `_sandboxd` only
while per-operator gateways are off, and is the operator's own account when
they are on. It now reads `lite shared: workspace — the host side is read by
the gateway VM's owner, not necessarily by the operator`, and carries the
reading uid as a structured `reader_uid` field so the identity is observable
rather than asserted. Quote the emit site, not this paragraph — that is exactly
the failure mode that produced D9.

### D14 — CoreDNS log missing `example.com` (1)

The gateway's CoreDNS log does not contain the queried name. Stable at 1 in
every run that reached it.

### D17 — dead session still `Running` after reconcile (1)

A session whose VM has died must not remain in state `Running` after the
daemon's reconcile pass; it does. Surfaced by the slot-reclamation test.

### D18 — create not rejected for unreadable host file (1)

`create` with an unreadable host file in the workspace must fail and tear down;
it returned rc=0 instead.

Position 147 is the `[lima]` parametrization of
`test_workspace_local_create_failure_tears_down`. **Its `[container]` sibling is
green and carries no information** — see the next entry, which is about that
green rather than about any failure.

### A passing test that never reaches its own injection

**`test_workspace_local_create_failure_tears_down[container]` passes, and passes
without exercising the condition it injects.** It appears nowhere in the
inventory above because it does not fail. It is recorded here because a green
row carrying no information is worse than a red one: every red row in this
document announces itself, and this does not. [M]

The test injects `chmod 000` on a file inside a host source directory, then
asserts (1) `sandbox create` exits non-zero and (2) the output contains
`local-workspace rsync failed`. On macOS lite both assertions are satisfied by a
**different failure than the injected one**. The source comes from
`tempfile.mkdtemp(prefix="sandbox-local-failure-")` with no `dir=`, so it lands
in the per-user private temp tree, which the daemon user cannot traverse; the
rsync described in D12 above dies at the source root with exit 23 before it ever
visits the unreadable file. Both assertions pass. The `chmod 000` is never
reached.

Its own docstring calls it *"its sole end-to-end pin"* for the daemon's
`cleanup_and_return!` teardown path, noting that the integration test
`integration_local_create_failure_tears_down` exercises only the library-level
error variant. **So the only end-to-end coverage of that teardown path is green
and testing nothing.**

The evidence is a same-test comparison rather than an inference from the
mechanism alone: across the run series the `[container]` parametrization passed
8 times and never failed, while the `[lima]` parametrization of the same
function is position 147 / D18 above, failing with `got rc=0` — the honest
report of that same injection failing to produce a failure. One backend
announces the gap; the other conceals it behind a pass. [M]

The repair is the one D12 already needs — re-point the fixture at a directory
the daemon user can traverse. Note what that repair will look like from
outside: the result line does not change. It stays green, and silently starts
meaning something. Nobody would learn it had been vacuous, which is the reason
for writing it down here rather than folding it into D12.

### DNS-gate bridge retry spin (no test failures)

A hot retry loop in the daemon: `DNS-gate bridge listener errored; re-arming
after backoff`, **3,155 lines** — roughly 12 attempts/second for four minutes,
across 11 sessions — all on `connect host gate UDS
…/events/<session-id>/dns-gate.sock: No such file or directory`. [M]

**It is strictly downstream of D12, not independent**: 11 sessions logged the
rsync failure, 11 logged the DNS-gate error, and the intersection is **11 of 11
with zero on either side alone**. A failed workspace setup leaves the bridge
task spinning instead of giving up. [M]

It is nonetheless its own defect: **even with D12 fixed, the bridge should back
off or give up rather than spin.**

### Agent check-in startup race (no test failures)

Two daemon-log `session agent for … is not running` errors land inside the
**~270 ms** window between the daemon binding its broker socket and the agent's
first check-in. One comes from the daemon's own Lima orphan reaper, one from a
handler that returns 500. A real ordering gap; it costs at most one test, and
the window has already narrowed from ~2.3 s earlier in the series. Unfixed. [M]

### Unattributed observations

Not defect classes, but quantified and worth not rediscovering:

- `handler error status=500` appears **24** times in the daemon log across the
  run. Not traced to a single cause.
- The run created roughly **135 gateway containers** and **48 session
  containers**, never more than **2 alive at once**.

### Classes resolved during the measurement series

Listed so their absence from the table above is legible, and so nobody
re-diagnoses them:

- **Session-name collision.** With a Lima create failing, a session row in state
  `Error` kept the test's session name; the `[container]` parametrization then
  created a second live session with the *same* name (no `UNIQUE` on
  `sessions.name`, no collision check), and the test's cleanup `rm` resolved the
  name to the *first* row — removing the stale one and orphaning the live
  session plus its pool token. Eight such orphans filled the session cap and
  caused 71 of run 1's 123 failures. Fixed; the fix's `already in use` and
  `is ambiguous` paths have fired 0 times since.
- **Agent survivability (two defects).** The agent wedged after ~109 brokered
  streams because the harness left its stdout on an unread 64 KiB pipe; and
  killing the `sudo` wrapper in restart tests left the real daemon reparented to
  launchd, so restarts *added* daemons instead of replacing them and no agent
  could ever check in again. Both fixed — see §6.
- **Daemon restart startup panic.** `reconcile` called a Lima operation
  synchronously from the async `main`, and the cross-user path reached a
  `Handle::block_on` that panics unconditionally when called on a runtime
  thread. Every restart against a populated `sessions.db` panicked with `Cannot
  start a runtime from within a runtime`; the first daemon of a run survived only
  because the harness resets the state dir, so its store was empty. This blocked
  every position past 63 in run 3 (98 of 123 failures) and would have broken
  production macOS daemon restarts, since daemon-uid ≠ operator-uid is the normal
  macOS deployment. Fixed by commit `436ce35`, which is where this baseline was
  measured. Zero panics, zero `Connection refused`, 4 of 4 restarts successful.

### A note on the class identifiers

The `D<n>` labels come from a classification that evolved across four runs, and
two of them moved. **`D2` originally denoted a different defect** (agent death,
now resolved), and was later reassigned to the guest-route family used
throughout this document — the reassignment is applied consistently here.
**`D10`** was the "lite build inside the gateway VM cannot resolve the registry"
defect and was folded into the D11 golden-image family; it is recorded inside
D11 above rather than given its own row. `D1` was the session-name collision and
is retired. The gaps at D1 and D10 are therefore expected, not omissions.

The identifiers have no meaning outside this document. If they get in the way,
rename them — the signatures and positions are what carry the information.

---

## 5. Full failure inventory

All 85 failures, so a fix can be checked against the tests it should turn green.

**Compare the set, never the total.** A later run that also reports 85 has not
reproduced this baseline — it has reported the same cardinality, which is the
one quantity a swap cannot move. A run measured 181 commits after `436ce35`
matched at 85 while differing in both directions: position 51 had been fixed
and passed, and `test_policy_survives_daemon_restart[container]` — passing
here — had failed. Either one alone would have shifted the total and been
noticed; together they cancelled. Diff the names.

That comparison is what this table is for, so two things about its shape
matter. Names are abbreviated where they were long (`test_discovery…closes_them`),
so matching is prefix-and-suffix, not equality; and the positions are ordinals
from the recorded run's collection order, not stable identifiers — a run with
different collection cannot be aligned to them positionally.

### Positions 1–62

| pos | test | class | assertion |
|---|---|---|---|
| 4 | `test_discovery…closes_them[lima]` | D3 | no deny output under empty policy |
| 5 | `test_discovery…closes_them[container]` | D3 | ″ |
| 10 | `test_git_push_to_vm[lima]` | D4 | `empty session name in URL` (rc=128) |
| 11 | `test_git_push_to_vm[container]` | D4 | ″ |
| 12 | `test_git_fetch_from_vm[lima]` | D4 | ″ |
| 13 | `test_git_fetch_from_vm[container]` | D4 | ″ |
| 14 | `test_session_uses_clone_path` | D11 | reads the empty `_stdout_log`; daemon logged the string it asserts on |
| 15 | `test_staleness_detection` | D11 | ″ |
| 16 | `test_rebuild_image_from_scratch` | D11 | gateway-VM lite build cannot resolve `registry-1.docker.io` |
| 28 | `test_lima_guest_refresh_backend` | D5 | `rewrite_vm_network_slot … lima.yaml: Permission denied` |
| 34 | `test_lite_resource_defaults_match_host_80pct` | D7 | `FileNotFoundError: '/proc/meminfo'` |
| 35 | `test_lite_git_remote_sandbox` | D4 | `empty session name in URL` |
| 37 | `test_lite_workspace_uid_alignment` | D8 | `shared:` path outside the shared root |
| 39 | `test_lite_orphan_cleanup_on_daemon_restart` | D6 | plain `docker ps -a` → host Docker |
| 51 | `TestLiteMacosWorkspace.test_shared_workspace_tcc_warning` (renamed since — see D9) | D9 | TCC warning absent from the daemon log |
| 52 | `test_gateway_traffic_flow[lima]` | D6 | gateway container "not running" per host Docker |
| 53 | `test_gateway_traffic_flow[container]` | D6 | ″ |
| 54 | `test_denied_traffic[lima]` | D6 | `No such container: sandbox-gw-…` |
| 55 | `test_denied_traffic[container]` | D6 | ″ |
| 56 | `test_lima_slirp_route_fallback_cannot_bypass_gateway` | D2 | `via 10.209.128.3` absent; `ip route show default` empty |
| 57 | `test_macos_slirp_restrict_on_blocks_egress_after_gateway_route_deleted` | D2 | ″ |
| 58 | `test_dns_interception[lima]` | D2 | `communications error to 127.0.0.53#53: timed out` ×3 |
| 59 | `test_dns_interception[container]` | D14 | CoreDNS log does not contain `example.com` |
| 60 | `test_stop_start_with_networking[lima]` | D5 | `rewrite_vm_network_slot` EACCES |
| 62 | `test_concurrent_sessions` | D2 | `bash: connect: Network is unreachable` to `10.209.128.3` |

Positions 63 and 64 (`test_daemon_restart_recovery[lima]` and `[container]`)
**pass** in the baseline; they were the wall that ended the previous run.

### Positions 64–160

| pos | test | class | assertion |
|---|---|---|---|
| 65 | `test_gateway_crash_recovery[lima]` | D6 | gateway container "not running" per host Docker |
| 66 | `test_gateway_crash_recovery[container]` | D6 | ″ |
| 67 | `test_macos_gateway_lima_crash_recovery` | D2 | Session A gateway not reachable before crash test (gw=10.209.128.3) |
| 68 | `test_macos_gateway_lima_recovery_one_session_errors_others_continue` | D2 | session gateway not reachable before crash |
| 69 | `test_macos_slot_reclaimed_after_vm_death` | D17 | dead session must not remain `Running` after reconcile |
| 72 | `test_level1_transport_tcp[lima]` | D2 | curl to example.com failed at transport level |
| 74 | `test_level1_transport_udp[lima]` | D2 | DNS query to 8.8.8.8 failed |
| 76 | `test_udp_allow_ntp[lima]` | D2 | nslookup time.cloudflare.com failed inside VM |
| 77 | `test_udp_allow_ntp[container]` | D15 | 0 nft-allow events captured |
| 78 | `test_udp_bidirectional_echo[lima]` | D2 | nslookup failed |
| 79 | `test_udp_bidirectional_echo[container]` | D15 | 0 allow events |
| 80 | `test_udp_multi_port_same_host[lima]` | D2 | nslookup failed |
| 81 | `test_udp_multi_port_same_host[container]` | D15 | 0 allow events |
| 82 | `test_udp_allowed_ip_cidr_edge[lima]` | D15 (or D2) | 0 allow events for 162.159.200.1:123/udp under a CIDR rule |
| 83 | `test_udp_allowed_ip_cidr_edge[container]` | D15 | ″ |
| 84 | `test_ubuntu_preset_smoke` | D2 | nslookup ntp.ubuntu.com failed inside VM |
| 85 | `test_level2_tls_verified[lima]` | D2 | curl https://example.com failed at TLS level |
| 87 | `test_level3_http_inspected[lima]` | D6 | `docker exec` into gateway container failed |
| 88 | `test_level3_http_inspected[container]` | D6 | ″ |
| 91 | `test_level3_method_restriction[lima]` | D2 | expected HTTP 200 for allowed GET, got 000 |
| 93 | `test_level3_path_restriction[lima]` | D2 | expected HTTP 599, got 000 |
| 95 | `test_l3_fail_closed_before_dns_propagation[lima]` | D13 | host `getent` missing |
| 96 | `test_l3_fail_closed_before_dns_propagation[container]` | D13 | ″ |
| 97 | `test_policy_update[lima]` | D2 | curl to example.com failed with initial policy |
| 99 | `test_dns_nxdomain[lima]` | D2 | DNS lookup for allowed example.com failed |
| 101 | `test_dns_ip_propagation[lima]` | D2 | DNS lookup for example.com failed |
| 102 | `test_dns_ip_propagation[container]` | D6 | gateway-container exec failed |
| 105 | `test_policy_clear_reverts_to_deny_all[lima]` | D2 | initial curl should have succeeded with active policy |
| 107 | `test_svcb_record_without_ech_reaches_vm[lima]` | D2 | dig TYPE65 cloudflare.com failed inside VM |
| 111 | `test_policy_survives_daemon_restart[lima]` | D2 | pre-restart curl to allowed example.com failed (rc=28) |
| 113 | `test_npm_preset_allows_npm_install[lima]` | D2 | curl to registry.npmjs.org failed under the npm preset |
| 114 | `test_npm_preset_allows_npm_install[container]` | D15 | expected event absent |
| 115 | `test_npm_preset_denies_non_preset_host[lima]` | D15 (or D2) | deny event for example.com absent; ring empty |
| 116 | `test_npm_preset_denies_non_preset_host[container]` | D15 | ″ |
| 117 | `test_cargo_preset_allows_cargo_fetch[lima]` | D2 | preset-allowed fetch failed |
| 118 | `test_cargo_preset_allows_cargo_fetch[container]` | D15 | expected event absent |
| 119 | `test_github_repo_preset_scopes_to_one_repo[lima]` | D2 | preset-allowed git clone failed |
| 120 | `test_github_repo_preset_scopes_to_one_repo[container]` | D15 | 0 `mitmproxy.request_denied` events |
| 121 | `test_preset_expand_round_trip[lima]` | D15 (or D2) | 0 events total; `lifecycle.policy_applied{status=ok}` absent |
| 124 | `test_stop_and_start` | D5 | `rewrite_vm_network_slot` EACCES on `lima.yaml` |
| 125 | `test_clone_repo[lima]` | D16 | expected README in `/home/sandbox/workspace/`, got nothing |
| 141 | `test_shared_mount[lima]` | D16 | `cat from-host.txt` failed in VM |
| 142 | `test_shared_mount[container]` | D8 | `shared:` path outside the shared root |
| 143 | `test_workspace_local_create_and_describe[lima]` | D16 | host file not visible at `/home/sandbox/work/hello.txt` |
| 144 | `test_workspace_local_create_and_describe[container]` | D12 | rsync failed |
| 145 | `test_workspace_local_gitignore_filter[lima]` | D16 | non-ignored file missing under the default filter |
| 146 | `test_workspace_local_gitignore_filter[container]` | D12 | rsync failed |
| 147 | `test_workspace_local_create_failure_tears_down[lima]` | D18 | create with an unreadable host file must fail; got rc=0 |
| 149 | `test_workspace_local_push_propagates_host_edit[lima]` | D16 | create-time push must seed `edited.txt` |
| 150 | `test_workspace_local_push_propagates_host_edit[container]` | D12 | rsync failed |
| 151 | `test_workspace_local_pull_propagates_guest_edit[lima]` | D16 | `Directory nonexistent` writing in guest |
| 152 | `test_workspace_local_pull_propagates_guest_edit[container]` | D12 | rsync failed |
| 153 | `test_workspace_local_push_dry_run` | D12 | ″ |
| 154 | `test_workspace_local_pull_dest_override` | D12 | ″ |
| 155 | `test_workspace_local_push_no_gitignore` | D12 | ″ |
| 156 | `test_workspace_lock_blocks_stop_during_push` | D12 | ″ |
| 157 | `test_workspace_lock_unlock_force_recovery` | D12 | ″ |
| 158 | `test_workspace_unlock_idempotent` | D12 | ″ |
| 159 | `test_workspace_shared_explicit_guest_path[lima]` | D16 | operator-supplied `:<guest_path>` did not mount at `/srv/work` |
| 160 | `test_workspace_shared_explicit_guest_path[container]` | D8 | `shared:` path outside the shared root |

---

## 6. Recommended fix order

The reasoning matters as much as the order; both are recorded.

1. **D2 — install the guest default route on the macOS Lima path (24).** The
   biggest single win, and the only one that is a *capability* gap rather than
   an observability or test-plumbing gap: today the macOS full backend cannot
   pass allowed traffic at all. **Confirm first** whether any macOS code path is
   meant to install that route, because "installs the wrong route" and "has no
   route-installing code" are different fixes. Expect a second crop of failures
   behind it — once traffic flows, the L2/L3 and preset assertions become
   meaningful for the first time.
2. **D6 — point the remaining tests at the gateway VM's Docker endpoint (10).**
   Pure test plumbing; the helper already exists in conftest and only the call
   sites remain. Cheapest failures-per-line in the run, and it has grown across
   the series rather than shrinking.
3. **D12 plus the DNS-gate spin (10 failures + 3,155 log lines).** One fix, two
   payoffs — they are co-resident 11 sessions out of 11. Even before the rsync
   fix lands, the bridge should back off or give up rather than spin at ~12/s.
4. **D16 — the Lima guest cannot see its workspace (7).** Distinct from D12;
   this is the Lima mount/push path. Diagnose as one family before splitting.
5. **D15 with D3 — events never reach the ring (11, of which 8 are confirmed on
   the container backend; plus D3's 2).** Same territory: enforcement works, the
   event is lost. D3's mechanism is already fully measured (§4), so it is
   cheap to carry along.
6. **D4 git-remote URL parsing (5)**, then the remainder: **D5, D8, D11, D13,
   D17, D18, D9, D7, D14**.

Then the two classes that produce no test failures: the **DNS-gate spin** (rides
along with step 3) and the **agent check-in startup race**.

> The source ordering named D3 twice — once alongside D15 and once again in the
> tail after D4. The pairing with D15 is the substantive reading and is what is
> written above; the duplicate is noted rather than silently dropped.

---

## 7. Confirmed healthy

Properties that were *measured* to hold, so that a future regression in any of
them is recognisable as a regression rather than mistaken for a known problem.
All [M].

**The operator agent survives a long run.** It brokered **483 GuestSocat
streams** in the baseline — 4.4× the ~109-stream wall it used to wedge at, and
3.2× the previous run's 150 — over a run 3.4× longer, and was still healthy two
minutes before pytest exited. Zero `dropping dead agent`, zero `no StreamReady
from agent`, zero `dropped before responding`, zero `session agent … is not
running` in the pytest log. It also survived **four daemon restarts**,
re-checking in each time within ~1 s of the new daemon binding its socket.

**Daemon restarts work.** 5 daemon starts, 4 intentional restarts, 4 of 4
successful. Zero panics, zero `Connection refused`, zero `sandboxd exited early`.
The panic's precondition was genuinely exercised, not merely absent: each
restarted daemon logged `restoring network allocator state from existing
sessions count=2` and provisioned a per-operator LIMA_HOME for an operator uid
different from the daemon's — the exact two conditions that used to panic — and
then continued serving.

**The gateway VM's dockerd does not stall.** Zero `Docker daemon unreachable`,
zero `gateway Lima recovery`, zero `gateway-docker.sock: no such file`. An
independent 20-second poller got rc=0 on **all 246 in-window samples**. The
gateway VM's QEMU process kept the **same PID across two consecutive full
suites** — it was never restarted.

**Runs leave the host clean.** On exit: 0 `sandboxd` processes, 0 session
QEMUs, 0 gateway VM containers, no orphan `sandbox-net-*` networks, 0 rows in
`sessions.db`, no leftover Lima instance dirs, the staged daemon dir removed by
the harness, host Docker unchanged, and disk free never dipping more than 1 GiB
below its start value across 246 samples. Two consecutive runs now end in the
state they started in without manual intervention.

**No container is disturbed mid-test.** Across 246 snapshots covering ~135
gateway containers and 48 session containers, there was **exactly one**
non-`running` observation in the entire run (a container caught mid-create).
Nothing vanished while its test was running; nothing entered a restart loop.

**The suite is deterministic and reproduces position-for-position.** Test order
is byte-identical across all four runs — verified by position-for-position
test-id comparison, not assumed. Several classes hold *exactly* constant in
every run that reached them (D4 = 5, D11 = 3, D3 = 2, D7 = 1, D9 = 1, D14 = 1),
which is a useful control: it shows the movement in the other classes is real
signal rather than run-to-run noise.

**The session cap is no longer hit.** `max concurrent sessions reached` has been
0 for three consecutive runs, since the session-name collision fix.

---

## 8. Not proven

Recorded separately from §7 because the distinction is the point.

**The between-tests container reaper's removal path has never fired against a
real leak.** Across three consecutive full runs, `reaped orphaned gateway-VM
Docker resources` appears **0** times. What *is* established:

- It removed nothing it should not have — conclusive by construction, since with
  zero removals it cannot have deleted a live session's container, and the
  snapshot evidence in §7 independently agrees. [M]
- It was not inhibited, so "removed nothing" means "found nothing" rather than
  "declined to look": the inhibit path triggers when the session-list API query
  returns nothing, and the daemon was reachable for the whole run. This is
  **[I, strong]** — conftest only prints on removal, so "ran and found nothing"
  versus "was inhibited" is not directly distinguishable from the log.

**So the removal path remains confirmed only against planted resources.** That
outstanding confirmation is now *more* outstanding, not less: three runs deep
with nothing to catch. It will only be exercised by a run that genuinely leaks —
which, given §7, is not something to arrange by waiting.

**D2's single-mechanism grouping is inferred** across 24 failures (§4), as is
the claim that no macOS code path installs the guest route at all (§1). Both are
the first things a fix should confirm.

**Three D15 rows may be D2 downstream** (§4). The other eight are confirmed.
