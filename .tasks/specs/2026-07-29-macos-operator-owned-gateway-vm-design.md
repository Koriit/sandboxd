# macOS: operator-owned gateway Lima VM — design

**Date:** 2026-07-29
**Status:** Draft
**Issue:** [#82](https://github.com/Koriit/sandboxd/issues/82)
**Related issues:** #83, #84, #85
**Builds on:** `.tasks/specs/2026-05-02-macos-support-design.md` (canonical macOS
architecture), `.tasks/handoffs/20260727-165300-lite-shared-design-macos-lite-shared-workspaces.md`
(Option A′ addendum, line 487)

All paths are relative to the repository root. Line numbers are against `master`
@ `7e5fa0c` unless stated otherwise.

---

## Framing

Issue #82 proposes making the macOS lite backend's gateway Lima VM **operator-owned**,
so that a `shared:` workspace can reference a real project path under the operator's
home instead of a staging root at `/tmp/sandbox-shared`. Today the VM belongs to the
daemon user, the daemon reads the host side of the 9p export, and it cannot traverse
an operator's `0750` home — which is why `validate_shared_path`
(`sandboxd/sandbox-core/src/lite_macos.rs:159-167`) exists and why the shared root
exists.

This document does **not** commit to that migration. It specifies two things that
must land first, and the conditions under which the migration proceeds:

1. **Per-operator vmnet slot partitioning** (§1, §2) — the isolation prerequisite.
2. **A narrow, networking-only egress validation gate** (§3) — the go/no-go.

### Why a gate, and why it comes first

The operator-owned-VM spike proved the control plane and both stream classes, but
it **never exercised egress enforcement at all**: `socket_vmnet` was unavailable in
the spike environment, so the gateway pipeline (Envoy / mitmproxy / CoreDNS / nft)
was never in the loop, and the stream measurements were taken on a `vz`-type VM
rather than the production `qemu` configuration. Absolute, unbypassable egress
control is the project's reason to exist. A change that moves the VM hosting every
enforcement point into a different trust domain must have that property re-proven
**before** three-to-five weeks of migration work, not after.

### Why partition slots first, rather than defer multi-operator NIC consumption

Issue #82 places "multi-operator NIC/slot consumption" out of scope on the grounds
that lite sessions consume no vmnet NIC — `claim_lite_token`
(`sandboxd/sandbox-core/src/network.rs:1202-1216`) takes a session-count token only,
while `claim_lima_slot` (`network.rs:1143-1196`) takes both a token and a NIC slot.
That is true, and it means a *lite-only* per-operator VM could indeed sidestep the
problem.

It does not survive contact with the full backend. The gateway container for a
full-backend session must sit on the session VM's isolated L2 segment, which means
the gateway VM must hold a NIC on that session's slot. `generate_gateway_template`
(`sandbox-core/src/gateway_lima.rs:334-381`) therefore emits one `socket:` entry per
pool slot, and the single gateway VM attaches to **all** of them at creation. Under
any per-operator gateway model, two operators' VMs built from that template both
attach to the same N sockets: the same L2 segments, the same `/29`s, the same
`--vmnet-network-identifier` UUIDs. `vmnet_slot_addresses` (`network.rs:954`) would
hand both operators the same `B+3` gateway-container IP and the same `B+4` VM IP.
That is an address collision and a cross-operator exposure, not merely
over-subscription.

Solving it only for lite defers the problem to whenever the full backend joins the
model. Partitioning is load-bearing for the isolation claim the whole design rests
on, so it is designed here rather than documented away.

---

## 1. Ownership model and slot identity

### 1.1 Per-operator gateway VM, driven through the broker

Each operator gets their own gateway Lima VM in their own `LIMA_HOME`, and every
control-plane operation on it goes through the existing operator-execution seam.

The cheapest part of the migration is already in place. `AgentBrokerExecutor::run`
(`sandboxd/sandboxd/src/broker.rs:1688`) branches on `op_uid == self.daemon_uid`:
equal routes to `run_limactl_direct` (`broker.rs:1962`), unequal routes to the
operator's checked-in agent. `GatewayLimaManager` deliberately passes
`self.daemon_uid` as `op_uid` on all six executor calls
(`gateway_lima.rs:1245, 1323, 1362, 1931, 2122, 2164`) to take the degenerate direct
path. **Passing a real operator uid there routes to the broker with no code change.**

Likewise, `operator_lima_home(op_uid)` (`sandbox-core/src/lima.rs:214-223`) already
takes an operator uid; the gateway's `{state_root}/{daemon_uid}/{daemon_uid}/lima`
path is the degenerate case of a general formula, so re-pointing it is a parameter
change rather than a structural one.

What is genuinely new is that there is more than one manager. The in-tree precedent
to copy is `LimaManagerRegistry` (`sandbox-core/src/lima.rs:1245-1280`) — a
`Mutex<HashMap<u32, Arc<LimaManager>>>` keyed by operator uid, monotonically
growing, with a shared executor and an injected home-provisioning function. A
`GatewayLimaManagerRegistry` takes the same shape.

Five `limactl` invocations inside `GatewayLimaManager` bypass the seam entirely
today, building `Command::new("limactl")` directly: `run_gateway_shell`
(`gateway_lima.rs:1614`), `run_gateway_shell_argv` (`:1642`), two `limactl copy`
calls (`:1757`, `:1865`), and `limactl --version` (`:2082`). `LimaOp`
(`lima.rs:766-810`) has no `shell` or `copy` variant. Under operator ownership these
need either typed variants or replacement by brokered Docker / route-helper ops
(§4.2, phases 3–4).

### 1.2 Per-operator `VmnetPool` in a uid-keyed registry

**The pool struct and its claim/release semantics are unchanged.** There is simply
more than one of it.

`VmnetPool` (`network.rs:1090-1421`) holds `allocated_slots`, `session_count`, and a
`SessionId`-keyed `networks` map — all in memory, with no operator dimension
anywhere in the type. Adding an owner field to the claim tuple would work, but
`session_count` is also a global admission cap that has to become per-operator, so
the cleaner shape is **a `VmnetPool` instance per operator, held in a uid-keyed
registry mirroring `LimaManagerRegistry`**, each seeded with a disjoint contiguous
slot range.

This is re-instantiation, not new allocation logic:

- `claim_lima_slot`'s lowest-free-index scan (`network.rs:1143-1196`) becomes a scan
  over the operator's own range rather than `(0..max_slots)`. Same algorithm, smaller
  domain.
- `claim_lite_token` (`:1202-1216`) is unchanged in shape; its cap becomes the
  operator's quota.
- `release_lima_slot` (`:1261-1287`) and `release_lite_token` (`:1290-1297`) are
  unchanged.
- `restore_from_infos` (`:1320-1354`) already validates `idx < max_slots` and errors
  otherwise; under partitioning the equivalent check is "inside the operator's
  assigned range", which is a tightening of an existing check rather than a new one.
- `claimed_slot_sessions` (`:1406-1415`) — the leak-detection accessor consumed by
  the diagnostics endpoint at `sandboxd/src/main.rs:11156-11157` — needs an operator
  dimension in its output, nothing more.

The operator's VM attaches to **every slot in its own range at creation**, exactly
as today's singleton attaches to all 8. The isolation property is inherited for free:
both `vmnet_slot_network_identifier` (`network.rs:897`) and `vmnet_slot_addresses`
(`network.rs:954`) are pure functions of slot index, so slots 4–7 keep distinct L2
segments and distinct `/29`s regardless of who consumes them. No plist regeneration,
no privileged work — the plists are slot-indexed, not operator-indexed, and the
sockets are already reachable by any enrolled operator (`--socket-group` in the plist
generator at `network.rs:1027`; membership installed by
`make setup-darwin-operator-group-membership`).

### 1.3 Range assignment, lifetime, and quota

- A range is **claimed at VM creation** and **released on VM deletion**.
- It is **persisted daemon-side**. §2.1 gives the two reasons; the second is the
  decisive one.

**Quota defaults to the entire pool.** A single-operator host must behave exactly as
it does today — same 8 concurrent sessions, same slot indices, same segments.
Partitioning is otherwise a straight concurrency regression: with 8 slots split
across 2 operators an operator hits the cap at 4, and at 4 operators at 2.
Multi-operator partitioning is therefore **opt-in via explicit configuration**, not
an automatic division of the pool by the number of enrolled operators.

This is the one place where the default and the disjointness requirement of §1.2
meet: if operator A's pool is seeded with the whole range and operator B then
requests a VM on a host with no explicit quota configuration, the two cannot both be
satisfied. What happens at that moment — refuse B's create with an actionable
message, or auto-divide and accept a silent concurrency reduction for A — **is not
settled** (Open questions).

Growing the pool toward the 32 the `/24` at `MACOS_VMNET_BASE` (`network.rs:858`)
allows is **one-time privileged installer work**, not daemon work: the daemon
explicitly refuses to regenerate root-owned plists — that is the entire
`RefuseNeedsPrivilegedRegen` arm of `decide_pool_resize`
(`gateway_lima.rs:2287-2378`). `SANDBOX_MAX_MACOS_SESSIONS` has exactly one
production read site (`main.rs:13403-13440`, validated to `1..=32`, hard-failing
startup on a bad value), so adding a per-operator quota dimension touches one parse
site plus the policy decision, with no scattered reads to chase.

### 1.4 Slot identity stops being positional

This is the highest-risk item in §1, and it is a correctness/isolation concern
rather than a cosmetic one.

Guest NIC names are assigned by neither udev, the socket filename, nor sandboxd.
Lima renders a cloud-init `network-config` document into `cidata.iso` mapping MAC →
name, where the name is `$nw.Interface` for that `networks:` entry, defaulting to
`lima<array-index>` (Lima 2.1.2 documents this at
`/opt/homebrew/Cellar/lima/2.1.2/share/lima/templates/default.yaml:471`). **Naming is
positional, not socket-derived.** A VM given slots `{4,5,6,7}` names its NICs
`lima0..lima3`.

The consequence matters because the NIC name becomes the **macvlan parent interface**
for the session's Docker network inside the gateway VM (`setup_macos_gateway`,
`sandbox-core/src/macos_session.rs:137-165`) — i.e. it selects which L2 segment the
session lands on. It is also persisted as `NetworkInfo.bridge_name`
(`main.rs:4373`), so a wrong name is durable rather than transient.

Four fixes:

1. **Pin identity with Lima's per-entry `interface:` key.** Emitting

   ```yaml
   networks:
     - socket: /var/run/sandbox/vmnet/slot-4.sock
       interface: lima4
   ```

   should preserve name↔slot identity and make an offset range behave exactly like a
   contiguous one from slot 0. This is cheap **but unverified for `socket:` networks**
   — the field is documented under a `- lima: shared` example
   (`default.yaml:470-471`), and the supporting evidence is structural (the
   network-config template renders `{{$nw.Interface}}` while iterating *all* networks
   with no kind-specific branch, and Lima's uniqueness-validation message indexes the
   field generically across the whole list). The gate checks this first (§3.1).

2. **Key the NIC parser by suffix, not position.** `discover_nics_from_ip_json`
   (`gateway_lima.rs:282-316`) sorts `limaN` interfaces by numeric suffix and then
   discards the suffix, re-keying by `enumerate()` position. With NICs `lima4..lima7`
   present it produces `slot 0 → lima4`. The fix is one line — key by the parsed
   suffix — but it changes the meaning of `NicMap` for the contiguous case too, so
   the existing tests at `gateway_lima.rs:2502-2543` change with it.

3. **Take an explicit slot set in template generation.** The three `(0..max_slots)`
   loops in `generate_gateway_template` (`gateway_lima.rs:334-381`) — the `networks:`
   stanza (`:336`), the netplan per-NIC entries (`:367`), and the IPv6-disable
   sysctls (`:379`) — assume a contiguous zero-based range and must take a slot set.
   The set must be **derived from the pool at call time, not snapshotted at
   construction** (§1.5). This changes the public signature of
   `generate_gateway_template`, called from `create_instance` (`:1286`) and six unit
   tests.

4. **Make the silent NIC-name fallback a hard error.** Three sites carry
   `.unwrap_or_else(|| format!("lima{}", vmnet_slot.index))`: create
   (`main.rs:4369`), restart (`main.rs:9891`), recovery (`main.rs:12819`). If the NIC
   map lookup misses, the session's macvlan is parented on a *guessed* interface
   name. Under partitioning a miss attaches the session to the wrong segment instead
   of failing.

   **This last change is correct independent of this design.** Silently guessing an
   L2 parent interface in the egress-control path should not have a fallback at all;
   the guess is only ever right by coincidence, and the failure mode it produces is
   silent misplacement rather than a refused create.

If `interface:` turns out not to be honoured for `socket:` entries, fixes 2–4 still
apply and the fallback is an explicit slot→NIC translation layer: more code, no more
risk, but it must be decided before §1's template work starts.

### 1.5 The `config_n` / `effective_n` divergence — prevention, not repair

`GatewayLimaManager` copies `max_slots` from a **throwaway** `VmnetPool::new(config_n)`
at construction (`main.rs:13514-13521`, copy at `gateway_lima.rs:813`), and the
manager is never rebuilt. The live pool is constructed separately at `effective_n`
(`main.rs:13721`), which genuinely differs from `config_n` in the
`WarnRunningSessions` and `RefuseNeedsPrivilegedRegen` arms
(`gateway_lima.rs:2296-2314`). So the two values do diverge as stored state.

**This is a latent stored-state inconsistency, not an active bug, and it should not
be written up as a defect being repaired.** `self.max_slots` has exactly one
consumer — `generate_gateway_template(self.max_slots)` at `gateway_lima.rs:1286`,
inside `create_instance` — and `create_instance` has one call site, `ensure_ready`
(`gateway_lima.rs:872`), on the instance-absent branch. `ensure_ready` has **three
production call sites, all inside the macOS startup block** (`main.rs:13525, 13637,
13666`) and **zero runtime call sites**. The recovery path does not reach it:
`restart_instance_for_recovery` (`gateway_lima.rs:2209-2215`) is force-stop plus
start, never create. Within startup the sequencing is self-consistent, and the pool
is always re-sized from the actually-discovered NIC count
(`main.rs:13644-13647, 13669-13672`).

It becomes real under either of two changes, one of which is this design:

- anything calls `ensure_ready()` at runtime — a "recreate the gateway if it went
  missing" recovery arm is a natural thing to add; or
- **partitioning makes the manager carry a slot *set* rather than a count**, at which
  point a stale snapshot stops being a wrong number and becomes a wrong set of L2
  segments.

Hence the rule in §1.4 fix 3: derive the slot set from the pool at call time. The
justification is prevention.

(A genuinely-active sibling defect is unaffected and out of scope here:
`start_instance` passes `memory_mb: 2048, cpus: 2` as literals at
`gateway_lima.rs:1373-1374` rather than reading `GATEWAY_VM_MEMORY_MB` /
`GATEWAY_VM_CPUS`.)

---

## 2. Lifecycle and failure modes

### 2.1 Range recovery is daemon-persisted

The tempting recovery mechanism — after a daemon restart, read each operator's
`networks:` list out of their VM's `lima.yaml` — **does not work, and should not be
made to work.**

**Reason 1: the daemon cannot traverse into the operator's instance directory.**
`ensure_operator_lima_home` (`sandbox-core/src/lima.rs:574-660`) does two things on
macOS (`lima.rs:616-648`): `chmod 0700` on the `LIMA_HOME`, then `chmod +a` with a
single ACE for the operator **on the directory itself only**. The rationale
(`lima.rs:602-610`) is explicit and load-bearing: inheritance would propagate into
every child including `_config/user`, Lima's SSH private key, and OpenSSH
StrictKeyfileMode rejects a key with a non-empty ACL. Because the ACE does not
inherit, *every* operator-created child — directories included — defaults to
owner-only with no ACL. Observed on this host in the cross-uid tree
`/var/lib/sandboxd/309/501/lima`: `_config/` is `drwx------ olek:_sandboxd-test` with
no ACL, and `sandbox-test-base.yaml` is `0600 olek`. A Lima instance directory has
exactly that provenance.

*Stated limit of the evidence:* there is no cross-uid VM instance directory on this
host to observe directly. The conclusion rests on three converging pieces — the
operator-owned `0700` `_config/` with no ACL inside the cross-uid tree, the
operator-owned `0600` YAML in the same tree, and the non-inheritance invariant quoted
from the code — rather than on a directly observed cross-uid `lima.yaml`.

**Reason 2, the stronger one: the operator can write that file.** Recovering a range
by reading `lima.yaml` would make an operator-controlled file the input to a
security-relevant allocation decision — *which L2 segment you land on* — routing
authority through the least trusted party in the model. This holds even if the
permissions were different. It is independently fragile as a source of truth as
well: `lima.yaml` is Lima's file with Lima's schema, not sandboxd's.

**Decision: the daemon assigns the range and persists it itself.** The daemon made
the assignment; re-reading it from elsewhere is a round trip through a party with no
authority over it. Two candidate locations, both daemon-owned:

- `sessions.db` (schema evolution rules in `CLAUDE.md` § On-disk compatibility apply
  — a new `V<NNN>__<name>.sql` migration for a column, or `Option<T>` +
  `#[serde(default)]` for a JSON blob field), or
- a daemon-written file under `{state_root}/{daemon_uid}/{op_uid}/`, which is
  `drwxr-xr-x` daemon-owned and freely writable by the daemon.

**The choice between these is open** — see Open questions.

**Documentation correction:** `CLAUDE.md` states the per-operator `LIMA_HOME` is
"owned by the operator uid". It is **daemon-owned with a single non-inheriting
operator ACE**. The practical claim it supports — the operator can create and read
their own files there, and test-side `limactl` must run as the operator — holds; the
mechanism differs, and the difference is exactly what makes reason 1 true.

### 2.2 Exhaustion becomes a per-operator condition

Three sites construct the same error, all in `network.rs`: `claim_lima_slot`'s
count cap (`network.rs:1161-1166`), its no-free-index arm (`:1171-1176`, unreachable
while the count cap holds), and `claim_lite_token` (`:1208-1213`). Message, verbatim:

```
max concurrent sessions reached ({running} running).
To increase the limit, set max_macos_sessions in config and restart sandboxd.
```

`SandboxError::Network` maps to **500 Internal Server Error** with the message passed
through verbatim (`sandboxd/src/error.rs:70`; body shape pinned by
`main.rs:15132-15137`).

Two changes:

1. **Status class.** Capacity exhaustion is a client-visible quota condition, not a
   server fault, and under partitioning it stops being rare. **429 Too Many Requests**
   is the right shape and needs a new `SandboxError` variant.
   `SandboxError::Conflict → 409` already exists (`error.rs:69`) and passes its
   message through verbatim, so a 409 re-classification would need no new variant —
   but 429 is the more precise answer and this design takes it.
2. **Remediation text.** "set max_macos_sessions in config and restart sandboxd"
   becomes actively misleading once the binding constraint is the operator's *share*:
   raising the host total does not help, and the host total cannot exceed 32
   regardless. The message must distinguish "your share is full" from "the host is
   full", and in the latter case point at the privileged pool-regeneration step
   rather than a config edit.

### 2.3 Bootstrap gains a login dependency

Today the daemon brings the gateway VM up during its own startup with no operator
present (`ensure_ready` at `main.rs:13525, 13637, 13666`). Operator-owned, VM
creation runs through the broker and therefore **requires a checked-in agent**:
`take_stream_for_guest_socat` / `send_op` return `agent_not_running_error`
(`broker.rs:278`) — *"session agent for `<user>` is not running — the operator must be
logged in for Lima VM operations"* — when no registry entry exists for that uid.

That error becomes a **gateway bring-up failure**, and the consequence is
user-visible: an operator's sessions cannot exist before that operator logs in. This
is consistent with the spec's existing login-scoped deployment assumption, but it is a
new failure mode at a new point in the lifecycle and **belongs in the user-facing
docs**, not only in the design.

### 2.4 Logout breaks recovery and reaping

Both `gateway_recovery.rs` and the orphan reapers assume the daemon can reach the
gateway VM at any time.

- `gateway_recovery.rs` production code is `gateway_recovery.rs:1-396` — a generic,
  injectable state machine with no `limactl`, no `docker`, and no reference to
  `GATEWAY_INSTANCE_NAME`. Discovery is the caller's job (`recover_gateway_lima`,
  `main.rs:12766`). Its restart thunk becomes unreachable for a logged-out operator.
- The Docker orphan reaper (`sandbox-core/src/backend/orphan_reaper.rs:566`, wired at
  `main.rs:13978, 13984`) runs against `CliDockerOpsWithSocket` bound to one forwarded
  socket. Under N VMs it runs once per operator VM, and it **cannot reach a
  logged-out operator's VM at all.**

**Precedent for the fix, and it is a clean one:** startup reconcile already gates on
`AgentRegistry::connected_uids` (`broker.rs:680-683`) and reconciles the rest lazily
on check-in (`broker.rs:1202-1205`, `on_admit_tx`; wiring at `main.rs:13245`,
`:13289-13294`). "Garbage accumulates while an operator is logged out, and is
reconciled on their next check-in" should be an **explicitly accepted behaviour**,
stated in the docs rather than discovered.

A related site needs the same treatment: `SessionStore::new`'s V006 orphan scan
shells `docker ps` / `volume ls` / `network ls` at store-open time
(`sandbox-core/src/store.rs:342-360`), before any agent exists. The Lima half of that
same scan was already neutered for exactly this reason — `v006_scan_lima_vms`
(`store.rs:327-336`) is a no-op stub whose comment says per-operator `LIMA_HOME`s
require the daemon registry, unavailable at store-open time. The Docker half needs
the same treatment.

### 2.5 Agent eviction can cancel a gateway op mid-flight

`limactl start` detaches QEMU, so a VM survives an agent restart — but the *in-flight
operation* dies with the connection. Per-operator, this can strand a VM that other
sessions of the same operator depend on, mid-create or mid-start, with the daemon's
view of it unresolved.

The same hazard arrives via last-writer-wins eviction: `AgentRegistry::register`
(`broker.rs:629-658`) drops the prior connection's eviction sender when a second
check-in arrives for the same uid, which happens on re-login and on fast-user-switch.

Two properties of the existing control connection sharpen this. It is a **hard
serialization point** — `drive_agent_connection_outer` polls the request channel only
when no op is outstanding (`broker.rs:1323`), and the `TakeStream` inner loop
(`:1372-1411`) blocks the whole task — so every op for a given operator is strictly
serialized behind one connection, with `REQUEST_CHANNEL_CAPACITY = 4`
(`broker.rs:209`). And a **wedged stream open costs the whole control connection**:
the absolute deadline burns up to the 60 s `HEARTBEAT_TIMEOUT` (`broker.rs:133`)
during which no other op for that operator can dispatch, then `break 'outer`
(`broker.rs:1382-1384`) fails every in-flight and queued op.

This is not a blocker for §1–§2, but it is the regime the later Docker-ops phase
creates (§4.3), and the mitigation — pipelining by `request_id`, which the protocol
already reserves for it (`sandbox-agent/src/protocol.rs:99-101`), or a second
connection class for stream opens — should be a decision made up front rather than
discovered under load.

### 2.6 Two singletons that must become per-operator

**The global recovery latch.** `AppState.gateway_recovering: Arc<AtomicBool>`
(`main.rs:1373`) is one latch for "the" gateway being recovered, read at
`main.rs:12350` to suppress per-session gateway re-creates. With N gateway VMs, one
operator's recovery would suppress every other operator's per-session gateway
monitor. It must be keyed by operator uid; `gateway_recovery.rs`'s
`latch: Arc<AtomicBool>` parameter (`gateway_recovery.rs:250`) follows.

`run_gateway_recovery` also currently snapshots **all** sessions from the store
(`gateway_recovery.rs:247`), so it needs an operator scope — filter to the operator
whose VM restarted, or invoke the orchestrator once per operator.
`run_bounded_recovery`, `GatewayRecoveringGuard`, and `GatewayRecoveryDeps` are
already generic and need no change. `networking_status` is keyed by `SessionId`
(`gateway_recovery.rs:249`) and needs no change.

**The Lima orphan-reaper landmine.** The gateway VM survives the reaper today **only
because its name fails a parse.** `decide_lima_vm` (`lima.rs:350`) classifies each
VM; `sandboxd-gateway` fails `parse_session_id_from_name` (`lima.rs:4203`, which
expects the `sandbox-<12hex>` shape) and yields `SkipNoSessionId`. A live gateway VM
has no session row, so if a per-operator naming scheme happens to parse, the reaper
classifies it `Reap` and **deletes a running gateway VM**. Reaping runs at
`lima.rs:460` / `:550`, wired at `main.rs:14007`. Note also that
`enumerate_operator_uids_from_fs` (`lima.rs:263`) already enumerates the daemon's own
uid as an "operator uid", because the gateway's `LIMA_HOME` is
`{state_root}/{daemon_uid}/{daemon_uid}/lima`.

This needs an **explicit exclusion**, not a name-shape accident. The per-operator
gateway naming scheme is not yet decided (Open questions).

### 2.7 Bounce-to-resize: available, deliberately unbuilt

Changing an operator's slot range does not require destroying their VM. Verified
feasible: stop → edit `lima.yaml` → start picks up `networks:` changes. Three pieces
of evidence:

- Nothing about networks is baked into the disk image. The Lima hostagent composes
  the QEMU command line at start time, opening each socket_vmnet unix socket itself
  and passing the fd (`-netdev socket,id=netN,fd=N+2` observed in the live instance's
  `ha.stderr.log`).
- `cidata.iso` is written by the start path, not the create path — in the live
  instance dir it postdates `lima.yaml` by ~15 hours, and generation lives in
  `pkg/cidata.ExecuteTemplateCIDataISO` / `GenerateISO9660` / `writeCIDataDir`.
  *Caveat:* that is one mtime data point, proving start-path generation but not
  per-start regeneration. §3.1 turns it into a 30-second check.
- Lima ships `limactl edit INSTANCE` with `--network`, arbitrary `--set` yq mutation,
  and `--start`.

Provision scripts self-correct across a NIC-set change: Lima processes provisions
**per boot** via cloud-init (`default.yaml:282-303`), and sandboxd's netplan script
truncates with `>` before re-appending per-slot entries
(`gateway_lima.rs:367-376, 491-510`). The same holds for the IPv6-disable sysctls,
the `eth0` MTU clamp, the `0666` docker.sock chmod, and the route-helper sudoers
drop-in.

**It is nonetheless not built in this design**, and the reason is issue #83: bouncing
an operator's gateway VM kills their lite sessions, and container-backend sessions
are **never recovered** — `sessions_to_recover` filters `backend == BackendKind::Lima`
(`gateway_recovery.rs:77-82`), and sandbox containers are created `--restart no`
(`sandbox-core/src/backend/container.rs:853-854`). Until #83 lands, resize means
"restart the daemon" and the ranges are re-derived from persisted state.

---

## 3. The egress validation gate

**Purpose:** answer one question — *is egress still enforced when the gateway VM is
owned by the operator instead of the daemon?*

**Scope, deliberately narrow:** networking only. No daemon, no broker, no real
sessions, no `shared:` mounts, no session store. A checked-in, re-runnable scripted
harness that stands the topology up, asserts, and tears it down.

**Explicitly not wired into the pytest e2e suite.** It is a decision instrument with
a different lifetime and a different audience from the regression suite. The suite's
own retarget is phase 6 (§4.2).

### 3.1 Two pre-checks, before anything else

Both are ~30 seconds, and either can invalidate §1.

1. **Does Lima's per-entry `interface:` key work for `socket:` networks?** Render a
   one-NIC template with `socket: .../slot-4.sock` + `interface: lima4`, boot, run
   `ip -json link show`. If yes, §1.4 fix 1 stands and partitioning is nearly free.
   If no, §1.4 needs an explicit slot→NIC translation layer instead, and that
   decision must be made before the template work starts.
2. **Does `cidata.iso` regenerate on every boot or only the first?** Record
   `stat -f %m cidata.iso`, stop, edit `networks:`, start, re-stat. A changed mtime
   plus the new NIC in `ip link` closes the residual uncertainty in §2.7. Current
   evidence is a single mtime data point.

### 3.2 Not a precondition: `net.inet.ip.forwarding=0`

The macOS daemon refuses to start when host IP forwarding is enabled, and that has
already blocked an e2e run once. **Do not make it a gate precondition.** There is a
separate ticket to remove the requirement, and holding the gate to a condition
intended to disappear would encode a dependency this design does not want.

The harness **records** the host's forwarding state and reports it as interpretive
context — useful when reading a result, not a pass/fail input. No hard fail, no
design weight.

### 3.3 Stand-up

Reuse `generate_gateway_template` (`gateway_lima.rs:334`) with an explicit slot set
and the 9p `mounts_stanza` dropped (`lite_shared_root_9p_stanza`,
`lite_macos.rs:110-115`, interpolated at `gateway_lima.rs:409-415` — the gate does not
exercise workspaces).

Inside the VM:

1. A `sandboxd-egress` uplink bridge (the same Docker bridge `ensure_egress_bridge`
   creates, `gateway_lima.rs:1502`) plus a `/28` session bridge.
2. The gateway container on the uplink bridge with `--cap-add NET_ADMIN`,
   `--sysctl net.ipv4.ip_forward=1`, and **`SANDBOX_COREDNS_UPSTREAM` set
   explicitly** — mirroring `build_macos_gateway_docker_args`
   (`macos_session.rs:567-640`, env at `:612`). This env var is macOS-specific and
   load-bearing: the entrypoint's baked Linux default `127.0.0.11`
   (`networking/gateway/entrypoint.sh:304`) is a dead end inside the VM, because its
   own upstream — the VM's `127.0.0.53` stub — does not answer, and **allowed domains
   SERVFAIL** without it. A gate that omits it produces a false red on the allow half.
3. Attach the gateway container's second NIC on the session bridge at `.2`.
4. Wait on `docker exec gw /healthcheck.sh` — the image ships the same five component
   probes the daemon uses (`networking/gateway/Dockerfile:148, 174`).
5. Inject the four DNAT rules and seed the deny-all Envoy listener.
6. Run the probe container with `--ip .3 --dns .2 --cap-drop ALL`.

### 3.4 The critical step: the probe's default route

`nsenter` into the probe's netns and `ip route replace default via .2`.

Docker points a container's default route at the bridge `.1`, not at the gateway
container. **Without this step the probe bypasses the gateway entirely and
everything passes** — including the deny assertions, which then prove nothing.

This is also precisely why the production sandbox container runs `--cap-drop ALL`
and cannot install its own route, and why `sandbox-route-helper` exists: on macOS
lite the route is installed from *outside* the container by
`sandbox-route-helper --vm-gateway-mode` (`build_in_vm_route_helper_argv`,
`lite_macos.rs:262-277`), invoked at `main.rs:5360-5364` (create) and `main.rs:6091`
(restart). The gate's `nsenter` stands in for the helper.

### 3.5 Assertions — deny first, and the ordering is a correctness property

**Order matters.** A missing or wrong default route makes the *allow* case pass and
the *deny* case fail. Asserting deny first turns the single most likely harness bug
into a loud, immediate failure instead of a false green that would authorize a
multi-week migration on no evidence.

| # | Assertion | Shape |
|---|---|---|
| 1 | **Deny** | CIDR-only policy (`10.0.0.0/8:443`) so DNS is out of the deny path, probing `203.0.113.1:8080` (TEST-NET-3, guaranteed unroutable). Assert with `_BLOCK_CURL_EXITS = {6,7,28,35,56}` (`tests/e2e/test_lite_macos.py:410`). |
| 2 | **Allow** | `example.com:80/tcp` at transport level, with the `nslookup` warm-up poll (L1 transport is fail-closed at empty cache). Assert exit 0 **and** `Example Domain` in stdout — the shape already proven at `test_lite_macos.py:448`. |
| 3 | **Structural** | `nft list ruleset` against the existing structural regexes (`tests/e2e/test_networking.py:384, 388, 398, 412`), and tables exactly `{sandbox, sandbox_dnat, sandbox_policy}` (the property pinned on Linux by `sandboxd/tests/gateway_deny_pipeline.rs:779`). |
| 4 | **Bypass resistance** | Delete the default route inside the probe, install a slirp route via `192.168.5.2`, assert the internet is still unreachable. |

Assertion 4 is **the only one that proves topological control rather than policy
control** — that egress is forced through the gateway by the shape of the network
rather than by a rule the probe is obeying. That is precisely the property changing
VM ownership puts at risk, and it is the macOS analogue of the spec-mandated
delete-the-gateway-route regression (`test_networking.py:698`, slirp gateway
`192.168.5.2` at `:799-809`).

**Explicitly not asserting on the deny-event JSONL.** The project already made this
call, and the reasoning is recorded at `tests/e2e/test_lite_macos.py:422-427`: the
JSONL event capture proved unreliable to assert on, because **the event stream is a
best-effort observability sink, not the enforcement mechanism.** Events stay in the
gate as diagnostics — useful when reading a red run, never a pass condition.

### 3.6 The second-operator probe

A second VM on a **disjoint slot range**, and three assertions:

1. It gets its own segment (distinct `/29`, distinct `--vmnet-network-identifier`).
2. Egress is enforced in **both** VMs — assertions 1–4 above hold on each.
3. **Neither VM can see the other's segment.**

Assertion 3 is the isolation claim all of §1 rests on. Without it, partitioning is
asserted rather than demonstrated. The in-tree precedent for the mechanism is
`integration_vmnet_inter_slot_l2_isolation` (`sandbox-core/src/network.rs:3021`),
which establishes inter-slot L2 isolation for the *singleton* case; the gate extends
it to two independently-owned VMs.

### 3.7 Failure discrimination — a red run must say which

The gate is worthless if a red result cannot be attributed. It must distinguish three
outcomes:

| Outcome | Meaning | Effect on the decision |
|---|---|---|
| **(a) Socket-permission failure** | the operator uid cannot open the slot socket, or the forwarded Docker socket is unreachable | fixable; the decision **survives** |
| **(b) Per-operator segment-allocation failure** | ranges/identity do not partition cleanly — e.g. `interface:` unhonoured *and* the translation layer insufficient, or address collision across VMs | points at a split model (lite-only per-operator, full backend staying on a shared VM); the decision **survives, modified** |
| **(c) Fundamental interception coupling to daemon ownership** | egress cannot be enforced when the VM belongs to the operator, for a reason that is not (a) or (b) | the decision **dies**; `shared:` needs another mechanism entirely (the prior design's options G / F) |

For (a) specifically, the environment evidence is favourable: access is group-scoped,
never uid-scoped (`--socket-group` at `network.rs:1027`), the sockets carry no ACLs,
and **sandbox session VMs already run operator-owned QEMU against these sockets
today** — so the operator→socket_vmnet path is proven in production code. Moving the
gateway VM changes *which* uid opens all N sockets, not *whether* that uid is
permitted to.

### 3.8 Harness form — open

Three candidates, none yet chosen (Open questions):

- Shell under `tests/` — lowest ceremony, matches what the topology work actually is.
- Python outside the pytest suite — reuses assertion idioms and `_BLOCK_CURL_EXITS`
  without inheriting conftest's daemon/host-Docker assumptions.
- A Rust integration test reusing the existing harness: `DirectLimaExecutor` and
  `build_test_manager` (`sandbox-core/tests/integration_gateway_lima.rs:45, 123`) on
  top of the shipped `sandbox-core/src/test_support/direct_executor.rs`. Highest
  reuse of existing lifecycle code; carries the `integration_*` prefix convention and
  the `integration` nextest profile for free.

---

## 4. Staging, deltas, corrections

### 4.1 What a green gate authorizes

A green gate means the decision **survives** and migration starts at phase 1. It does
not mean the design is finished — §1 and §2 still have open questions, and the cost
estimate still needs revising (§4.3).

A red gate routes to one of the three branches in §3.7. Only branch (c) kills the
decision.

### 4.2 Phases

| Phase | Work | Notes |
|---|---|---|
| **0** | Pre-checks (§3.1) + egress validation gate (§3) | Decision gate. Nothing downstream starts before it is green. |
| **1** | Slot partitioning — §1 and §2, including the `main.rs:4369` (+`:9891`, `:12819`) hard error | Independent of ownership; correct on its own terms. |
| **2** | Per-operator gateway VM ownership | **The cost driver.** `GatewayLimaManager` + registry, per-operator recovery, reaper exclusion, login-dependent bootstrap. |
| **3** | Docker broker ops **and** streams, together | Deliberately not split — the stream classes are the same surface as the ops and share the serialization concern in §2.5. |
| **4** | Typed route-helper op (`InstallContainerRoute { container_pid, gateway_ip }`) | Maps cleanly onto `build_in_vm_route_helper_argv`'s only two caller-supplied values (`lite_macos.rs:262-277`). |
| **5** | Shared-root removal — `validate_shared_path`, `SharedPathError`, `DEFAULT_LITE_SHARED_ROOT`, `LITE_SHARED_ROOT_ENV`, the 9p stanza | The feature the issue is *named for*. |
| **6** | Test and docs retarget | **Runs continuously across phases 1–5, not at the end.** |

**Be explicit about the ordering consequence: the feature #82 is named for lands
last.** `shared:` with real project paths cannot work until the VM is operator-owned,
which cannot land until the gateway manager is per-operator, which should not land
until slots partition and egress is proven. Every phase before 5 is infrastructure
for a user-visible change that appears only at the end.

Phase 6 runs continuously because the test surface is not a tail: 34 occurrences of
`sandboxd-gateway` across `tests/e2e/`, a singleton name hard-coded in a
delete-everything-else state-dir sweep (`tests/e2e/conftest.py:1062`), two disagreeing
daemon-`LIMA_HOME` formulas (`conftest.py:1049` 3-level vs
`tests/e2e/test_networking.py:1508` 2-level), and — the larger coupling — the
cross-backend suite's structural gateway assertions written against a **host** Docker
daemon that does not exist on macOS (`conftest.py:629-638`, `test_networking.py:374`,
`test_policy.py:61, 112`). Two recovery tests also encode the singleton's blast radius
as behaviour (`test_networking.py:1765`); under per-operator VMs the correct assertion
inverts — operator A's gateway loss must **not** affect operator B — which is a new
test, not a retarget.

### 4.3 The 3–5 week estimate needs revising upward

Issue #82's estimate assumed a Docker surface of "~11 distinct verb shapes behind
three command builders". The measured surface is roughly triple:

- **15 distinct `-H unix://<sock>` injection sites across 13 files**, of which **9 are
  inline and behind no builder at all** — among them `network.rs:399, 643, 678`,
  `dns_propagation.rs:307`, `lds_ack.rs:190`, and `main.rs:9566, 10372`, with a
  further cluster in `gateway_lima.rs` (`:1027, 1065, 1160, 1190, 1453, 1508, 1975,
  2017, 2051, 2230`).
- **6 named prefix builders**, not three (`container.rs:516`, `:531`, `:1619`;
  `gateway.rs:380`; `macos_session.rs:90`; `policy_distributor.rs:23`), plus two
  near-duplicate funnels in the orphan reaper (`orphan_reaper.rs:449`, `:494`).
- **13 distinct top-level verbs** and **~35 distinct argv shapes**, with three
  coexisting assembly idioms: fluent `Command::args([...])` chains, pure
  `Vec<String>` builders, and **one assembled as a shell string** — `format!("docker
  -H unix://{sock} exec -i")` passed as rsync's `--rsh` transport
  (`sandbox-core/src/workspace_rsync.rs:195`), which rsync re-parses as a shell word
  list. Any typed-op refactor must cover that shape.
- Two shapes that do not fit a plain request/response op: **stdin-fed one-shots**
  (`nft -f -` at `gateway.rs:1307`; `sh -c 'cat > path'` at
  `policy_distributor.rs:512`, `macos_session.rs:788`,
  `atomic_listener_writer.rs:410`), which put multi-KB JSON-escaped file bodies on a
  newline-delimited JSON channel; and **three long-lived streams, not two** (§4.5).

**Do not invent a replacement number.** The point is that the bucket most likely to
be under-scoped in the original estimate has measurably more surface than the
estimate assumed, and re-estimation should happen against these figures — after the
gate, when phase 3's shape is actually decided.

Two counterweights, for honesty: `gateway_recovery.rs` is far cheaper than #82
suggests (§4.5), and the `op_uid` routing change in §1.1 is free.

### 4.4 Accepted deltas

**Workspace-axis widening — accepted, and it is the feature.** Confining `shared:` to
a fixed shared root structurally bounds what a container escape can touch on the
host. The entire point of this change is to let `shared:` reach real project paths,
so an escape that reaches the operator's uid now lands on **their real working
tree**. Any mechanism that makes lite `shared:` usable has this property. It must be
recorded explicitly, in two places:

- `docs/guides/hardening.md:213` (`## Security trade-offs you choose`) — the only doc
  that frames deltas as operator-chosen trade-offs, alongside the existing `9p shared
  mounts` and `local: snapshot workspace` entries.
- `.tasks/specs/2026-05-02-macos-support-design.md:964-972` (§ Security posture →
  Known deltas) — the canonical list, currently four entries.

**Critically: the mitigation #82 proposes does not currently work.** The issue offers
"mount only the requested workspace subtree, never the operator's home" as a cheap
mitigation worth building in from the start. As written it is not a mitigation,
because `validate_shared_path` (`lite_macos.rs:159-167`) is a bare `strip_prefix` with
**no canonicalization** — deliberately, since the path may not exist yet and the
function is kept pure (`lite_macos.rs:138-142`). Consequently `..` traversal and
symlinks go unresolved: `/tmp/sandbox-shared/../../Users/alice` passes `strip_prefix`
today and would be handed to `docker create --mount src=…`. **The same textual-prefix
weakness would let a crafted path escape a subtree-only mount.** Canonicalization —
with the existence problem solved explicitly, e.g. canonicalizing the longest existing
ancestor — is required for the mitigation to mean anything.

**Gateway-axis improvement — conditional, not automatic.** #82 claims per-operator
VMs shrink the blast radius from "every concurrent session" to "every session of one
operator". That is true **only with slot partitioning in place**. Without it, an
operator-owned gateway VM attaches to *every* slot, including slots serving other
operators' sessions — one operator's process bridging every segment on the host. In
that configuration the delta runs the *other* way: worse than today, not better.
Partitioning is what makes the claimed improvement true, which is the strongest single
argument for the ordering in §4.2.

### 4.5 Corrections issue #82 needs

| # | Claim in #82 | Correction |
|---|---|---|
| 1 | "**Narrower on the gateway axis**" | Backwards as written. The improvement is **conditional on slot partitioning** (§4.4). Unconditionally stated, it is wrong. |
| 2 | "Deliberately out of scope: multi-operator NIC/slot consumption. It may never be a real constraint; document it rather than solve it." | Untenable. Partitioning is **load-bearing for the isolation claim** the rest of the issue makes (§Framing, §4.4). It cannot be documented away. |
| 3 | "Move the argv builders into the shared protocol crate so the daemon sends typed session parameters and the *agent* composes the argv." | The mechanism is right; the location does not work. `sandbox-agent` **deliberately does not depend on `sandbox-core`** — a TCB boundary, stated at `sandbox-agent/src/handler.rs:37-38` and confirmed by `sandbox-agent/Cargo.toml:36-59`. The Docker argv builders live in `sandbox-core` (`backend/container.rs:751` etc.) and are used **on Linux too**; putting them in the macOS-only `sandbox_agent_protocol` lib would either break Linux or force `sandbox-core → sandbox-agent`, inverting TCB minimalism. It needs a **new zero-dependency leaf crate** depended on by both. |
| 4 | "Streams: ~two long-lived streams" | There are **three**. The missed one is the **DNS-gate bridge** (`sandbox-core/src/dns_gate_bridge.rs:164` → `:224` → `:248`), which opens **one `docker exec` per DNS query** — it runs `socat UNIX-LISTEN` without `,fork` on purpose (`:30-42`), because `,fork` would corrupt concurrent gate frames. It is fail-closed (`:44-54`) and sits on the egress-**allow** critical path, i.e. the core promise. Its open-rate interacts directly with the serialization concern in §2.5. |
| 5 | "a **single VM** hosting both lite workloads and the gateway containers" | Blurs two distinct VMs. The prior design's Option A′ keeps the **gateway container in the daemon-owned VM** and moves only the **lite workloads** to a per-operator VM. This design goes further — the gateway VM itself becomes operator-owned — but the issue's phrasing describes neither shape precisely and should say which VM hosts what. |
| 6 | "`gateway_recovery.rs` at ~1200 lines" | The file is 1236 lines but **only `:1-396` is production code (~330 lines)**; `:402-1236` is the hermetic test module. It is a generic injectable state machine with no discovery logic — one of the **cheapest** parts of the migration (a ~4-item change plus a caller rewrite), not one of the expensive ones. |

Two doc-comment corrections fall out of the ownership change and should land with
phase 2 rather than being left stale:

- **The authorization perimeter claim.** `lite_macos.rs:241-256` and
  `sandbox-route-helper/src/main.rs:55-84` (repeated at `:307-318`) both state that
  "the gateway VM is single-tenant `_sandboxd` infra — no operator user can
  independently reach its sudo path." Under an operator-owned VM that is **false** —
  the operator owns the `LIMA_HOME` and the SSH credentials. The root-uid gate inside
  the VM (`sandbox-route-helper/src/main.rs:329-339`) still holds, but the *stated
  outer perimeter* does not, and the design must say what replaces it: a per-operator
  VM means an operator can only affect their own VM's containers, on a kernel-isolated
  no-NAT segment.
- **Residual TCC framing.** `gateway_lima.rs:351-354` (Rust comment) and
  `gateway_lima.rs:413-414` (**inside the generated Lima YAML**, so it ships into
  every gateway VM's `lima.yaml`) both restate the TCC framing that commits `8da105c`
  / `bbd9d6f` corrected away from — and which `lite_macos.rs:442-470` now has a test
  asserting the operator-facing message must **not** contain. They survived because
  they are comments, not message text.

### 4.6 Related issues

| Issue | Bearing on this design |
|---|---|
| **#83** — gateway-VM recovery silently skips container-backend sessions (`sessions_to_recover` filters `backend == Lima`, `gateway_recovery.rs:77-82`) | **Blocks bounce-to-resize** (§2.7). Bouncing an operator's VM kills their lite sessions, and those are never recovered — containers are `--restart no` (`container.rs:853-854`). |
| **#84** — `linux_only` marker declared, enforced, applied to zero tests | Phase 6 depends on it. `make test-e2e-macos SCOPE=full` currently collects the entire Linux-authored matrix on macOS, including host-Docker and cgroup assertions. The marker discipline must close before "retarget the suite" means anything. |
| **#85** — `make setup-dev-env` regenerates the vmnet plists to reference `_sandboxd`, an account only `install.sh` creates | **Actively dangerous on dev hosts**, and directly in the gate's path: the failure is deferred to the next boot, at which point the whole vmnet socket pool is gone. This host is currently running pre-rename plists (`--socket-group=_sandbox`, gid 60 — Apple's reserved Seatbelt group) with no `_sandboxd` account present, so re-running `setup-dev-env` here before `install.sh` would break the pool the gate needs. |

---

## Open questions

1. **Range persistence location** (§2.1) — `sessions.db` (with a refinery migration
   or an `Option<T>` + `#[serde(default)]` blob field) versus a daemon-written file
   under `{state_root}/{daemon_uid}/{op_uid}/`. Both are daemon-owned and both satisfy
   the trust requirement; the choice is about schema-evolution cost versus a second
   persistence mechanism.
2. **Gate harness language and location** (§3.8) — shell under `tests/`, Python
   outside the pytest suite, or a Rust `integration_*` test reusing
   `DirectLimaExecutor`.
3. **Quota default value and configuration surface** (§1.3) — "entire pool" is
   settled as the *default*; the config shape that expresses a non-default
   per-operator quota is not. Config files are JSON per project convention, and
   `SANDBOX_MAX_MACOS_SESSIONS` currently has one parse site
   (`main.rs:13403-13440`). Sub-question, and the sharper one: **what happens when a
   second operator requests a VM on a host with no explicit quota configuration** —
   refuse with an actionable message, or auto-divide and silently halve the first
   operator's concurrency. The default and the disjointness requirement cannot both
   hold in that case.
4. **Does `interface:` pinning work for `socket:` networks?** (§1.4, §3.1) — the
   single highest-value pre-check. Evidence is structural and converging, not
   observed. A negative answer changes §1.4's approach but not the design's
   direction.
5. **Per-operator gateway VM naming scheme** (§2.6) — undecided, and it is a
   correctness constraint rather than a cosmetic one: whatever is chosen must
   provably fail `parse_session_id_from_name` (`lima.rs:4203`) *and* carry an explicit
   reaper exclusion, so the VM does not survive only by name-shape accident as it does
   today.
6. **Which second uid plays "operator B" in the gate's second-operator probe**
   (§3.6) — it must be enrolled in the vmnet socket group and able to run `limactl`.
   On this host both `olek` (501) and `_sandboxd-test` (309) qualify against the
   *currently installed* plists, but those plists are stale (`_sandbox`/gid 60), and
   #85 means the obvious remediation would take the pool down. The gate's environment
   prerequisites need settling before it is written.

---

## Evidence and prior work

Reconnaissance backing this document (read-only, no files modified in any of them):

- `.tasks/handoffs/20260728-explore-gateway-lima-manager.md` — `GatewayLimaManager`
  surface, daemon-uid coupling, singleton assumptions, `limactl` invocation classes,
  `gateway_recovery.rs` sizing, per-operator-ization candidates.
- `.tasks/handoffs/20260728-explore-slot-partitioning.md` — NIC-set mutability, the
  index-identity landmine, `VmnetPool` lifecycle, exhaustion behaviour.
- `.tasks/handoffs/20260729-explore-lima-home-perms.md` — LIMA_HOME permission walk,
  the `config_n`/`effective_n` correction, exhaustion error verbatim.
- `.tasks/handoffs/20260728-explore-broker-protocol.md` — op enum, protocol crate
  layout, `PendingStreamRegistry`, auth chain, Docker surface, heartbeat behaviour.
- `.tasks/handoffs/20260728-explore-lite-macos.md` — `lite_macos.rs`, the shared root,
  `validate_shared_path`, workspace kinds, Docker command construction, route-helper
  interaction, the Linux/macOS seam.
- `.tasks/handoffs/20260728-explore-vmnet-env.md` — installed socket_vmnet state,
  socket permission model, codebase configuration, host staleness flags.
- `.tasks/handoffs/20260728-explore-tests-docs.md` — e2e structure, singleton
  assumptions in tests, egress coverage inventory, `shared:` coverage.
- `.tasks/handoffs/20260727-165300-lite-shared-design-macos-lite-shared-workspaces.md`
  — the prior options analysis (A–G) and the Option A′ addendum at line 487.

This design **supersedes and refines** the Option A′ addendum in two ways. A′ moved
only the *lite workloads* to a per-operator VM and kept the gateway container in the
daemon-owned VM; this design moves the gateway VM itself. And A′ listed static slot
partitioning as a *fallback* for multi-operator hosts (its §1c, resolution 3); here it
is a **prerequisite**, designed first, because the gateway-axis security claim is
false without it. A′'s verification criteria (line 444) and its addendum criteria
(line 792) remain valid and are not contradicted: the gate in §3 is a strict subset of
them, narrowed to the egress question and run earlier.
