# macOS: operator-owned gateway Lima VM — design

**Date:** 2026-07-29
**Status:** Draft
**Issue:** [#82](https://github.com/Koriit/sandboxd/issues/82)
**Related issues:** #83, #84, #85
**Platform:** macOS (Apple Silicon) only. Nothing here changes Linux behaviour.

---

## How to read this document

This spec is written to be picked up by an engineer who was **not** part of the
design conversation. It assumes competence with Rust, Docker and Linux networking,
and assumes **no** prior knowledge of this codebase.

- **[Background](#background)** orients you: what the macOS lite backend is, why a
  gateway VM exists, what a vmnet slot is, what the broker does, and what breaks
  today. Read it once; skip it if you already know the macOS architecture.
- **[Before you start](#before-you-start)** is environment setup. **Read it even if
  you skip everything else** — one of its warnings will otherwise cost you a day.
- **[§1](#1-ownership-model-and-slot-identity)** and **[§2](#2-lifecycle-and-failure-modes)**
  are the design: what changes and why.
- **[§3](#3-the-egress-validation-gate)** is a runnable procedure, not a
  description. It is the go/no-go for everything after it.
- **[§4](#4-phases)** breaks the work into seven independently actionable phases,
  each with its own acceptance criteria. **If you own one phase, go straight there**
  — each phase links back to the design sections it implements.
- **[§5](#5-deltas-corrections-and-related-issues)** records accepted security
  deltas and the corrections issue #82 itself needs.
- **[Open questions](#open-questions)** are genuinely undecided. Do not invent
  answers; raise them.

Every claim cites a `file:line` in this repository. Line numbers are against `master`
@ `7e5fa0c`. Where a line may have moved, the code is quoted inline so you can
recognise it.

**Claims marked ⚠️ UNVERIFIED are exactly that.** They are flagged at the point of
use, each with a check you can run in under a minute. Do not build on one without
running its check first.

---

## Background

### The two backends

sandboxd gives coding agents isolated Linux environments and enforces an egress
policy on them. It has two backends:

- **Full backend** — one Lima/QEMU **virtual machine** per session. Strongest
  isolation, expensive per session.
- **Lite backend** — one hardened Docker **container** per session. Cheap per
  session, shared kernel.

On Linux the lite backend simply uses the host's Docker daemon. **macOS has no native
Docker**, so containers must live inside a Linux VM.

### Why there is a gateway VM on macOS

Every session — either backend — gets a **gateway container** running a five-process
pipeline (Envoy, mitmproxy, CoreDNS, and two nftables loggers) that is the *only*
path to the internet. Egress policy is enforced there.

On macOS those gateway containers need a Linux Docker daemon, so sandboxd runs one
persistent Lima VM (`sandboxd/sandbox-core/src/gateway_lima.rs:84`):

```rust
pub const GATEWAY_INSTANCE_NAME: &str = "sandboxd-gateway";
```

That VM hosts **all** gateway containers for **all** sessions and **all** operators,
plus every lite session's sandbox container. It is created and driven by
`GatewayLimaManager` (`gateway_lima.rs:771-2272`), and — the fact this whole design
turns on — **it is owned by the daemon user (`_sandboxd`), not by any operator.** The
daemon reaches its Docker daemon through a forwarded Unix socket at
`<daemon_lima_home>/sandboxd-gateway/gateway-docker.sock` (`gateway_lima.rs:810-812`).

### vmnet slots: one slot, one isolated L2 segment

macOS cannot give a QEMU VM an isolated network without privileges, so sandboxd
pre-provisions a fixed pool of **slots**. A slot is a root-installed launchd daemon
running `socket_vmnet` — not a dynamically created resource.

Per slot `n`:

| Component | Value | Source |
|---|---|---|
| launchd label | `io.sandboxd.vmnet.<n>` | `network.rs:971` |
| Unix socket | `/var/run/sandbox/vmnet/slot-<n>.sock` | `network.rs:862`, `:965` |
| L2 identity | deterministic UUIDv5 from a fixed namespace + slot index | `network.rs:897` |
| Addressing | the `/29` at `10.209.128.0 + 8·n` | `network.rs:858`, `:954` |

The UUID is the load-bearing isolation control. From the plist generator's own doc
(`network.rs:993-996`):

> `--vmnet-network-identifier=<uuid>`: deterministic, per-slot UUID … **each unique
> identifier gets its own isolated L2 bridge, preventing cross-slot traffic**

`--vmnet-mode=host` means the segment has **no NAT to the internet**. So a slot is a
private wire between exactly the endpoints attached to it, and the only way off it is
through the gateway container.

The `/29` role map (`network.rs:938-947`), where `B` is the slot's base address:

| Offset | Role |
|---|---|
| `B+1` | host-side vmnet gateway (`bridgeN` on the Mac) — reachable, but no internet transit |
| `B+2` | gateway VM's slot NIC — link-up only, no L3 address (it is a macvlan parent) |
| `B+3` | **gateway container IP** |
| `B+4` | **sandbox VM IP**, default route = `B+3` |

The pool is capped at 8 by default and 32 hard, because a `/24` holds 32 `/29`s. It
is read from the environment at exactly one place (`main.rs:13403-13440`):

```rust
const DEFAULT_MAX_MACOS_SESSIONS: u16 = 8;
const MAX_MACOS_SESSIONS_ENV: &str = "SANDBOX_MAX_MACOS_SESSIONS";
let config_n: u16 = match std::env::var(MAX_MACOS_SESSIONS_ENV) {
    Ok(val) => match val.parse::<u16>() {
        Ok(n) if (1..=32).contains(&n) => { /* … */ n }
```

**The two backends consume the pool differently.** `VmnetPool`
(`network.rs:1090-1104`):

```rust
pub struct VmnetPool {
    /// Claimed NIC slot indices (0..max_slots-1).
    allocated_slots: Mutex<HashSet<u16>>,
    /// In-use session-count tokens.
    session_count: Mutex<u32>,
    /// Maximum slots (= max concurrent sessions; from `max_macos_sessions`).
    max_slots: u16,
    networks: Mutex<HashMap<SessionId, (u16, Option<NetworkInfo>)>>,
}
```

A **full-backend** session calls `claim_lima_slot` (`network.rs:1143`) and takes a NIC
slot **and** a token. A **lite** session calls `claim_lite_token` (`network.rs:1202`)
and takes **only a token — no NIC**. Remember this: it is why issue #82 believed slot
consumption could be deferred, and [Decision](#decision-and-sequencing) explains why
it cannot.

**The gateway VM attaches to every slot.** `generate_gateway_template`
(`gateway_lima.rs:334`) emits one `socket:` entry per slot:

```rust
let networks_section = (0..max_slots)
    .map(|slot| format!("  - socket: {}\n",
        crate::network::vmnet_slot_socket_path(slot)))
    .collect::<String>();
```

so the single VM holds NICs `lima0..limaN-1`, one per slot, simultaneously and
permanently. Each session's gateway container is then a **macvlan child** on the NIC
for that session's slot — that is how it lands on the session's isolated segment
(`macos_session.rs:158-165`):

> The macvlan network is parented on `limaN` (the slot NIC), giving the gateway
> container an isolated L2 segment on the session's `/29` block.

### The broker: how the daemon acts as an operator on macOS

The daemon runs unprivileged as `_sandboxd`. To create a VM that belongs to an
*operator*, it must run `limactl` as that operator's uid.

On Linux that is a `cap_setuid` helper (`sandbox-lima-helper`). **macOS has no
equivalent.** Instead each operator runs a `sandbox-agent` LaunchAgent inside their
own login session, and the daemon sends it typed operations over a Unix-socket
**broker**. The agent already *is* the operator, so no privilege escalation exists at
all.

The op set is a closed, typed enum (`sandbox-agent/src/protocol.rs:181`), and the file
opens with an explicit NON-FEATURES block (`protocol.rs:1-32`) stating the trust
model: no argv pass-through, no shell, no operation not in the enum. That closed enum
is what bounds a compromised daemon.

The routing decision that matters here is one `if` (`sandboxd/src/broker.rs:1688`):

```rust
if op_uid == self.daemon_uid {
    // Degenerate case: daemon is the operator — run limactl directly.
    return run_limactl_direct(op_uid, op, timeout, label);
}
// Route to the operator's agent via the broker channel. …
```

Per-session sandbox VMs already pass a real operator uid and go through the broker.
`GatewayLimaManager` deliberately passes `daemon_uid` on all six of its executor calls
(`gateway_lima.rs:1245, 1323, 1362, 1931, 2122, 2164`) so the gateway VM takes the
degenerate direct path. **Changing that one argument is most of the ownership
change.**

Each operator gets their own `LIMA_HOME` at `{state_root}/{daemon_uid}/{op_uid}/lima`
(`lima.rs:214-223`). The gateway's is the degenerate
`{state_root}/{daemon_uid}/{daemon_uid}/lima`.

### `shared:` workspaces, and what breaks

A session can mount a host directory live into the sandbox:
`--workspace shared:<host-path>[:<guest-path>]` (`session.rs:176-219`, parsed at
`session.rs:406-452`). On the **full** backend this works with any path, because the
QEMU process exporting the directory over 9p **is the operator's own process**.

On **macOS lite** it does not, and the reason is ownership. The gateway VM belongs to
`_sandboxd`, so `_sandboxd` reads the host side of the 9p export — and it cannot
traverse an operator's home (`/Users/<you>` is mode `0750` and `_sandboxd` is not in
its group). So lite `shared:` is confined to a staging root, `/tmp/sandbox-shared`
(`lite_macos.rs:54`), enforced at create time by `validate_shared_path`
(`lite_macos.rs:159-167`):

```rust
pub fn validate_shared_path(host_path: &Path, shared_root: &Path) -> Result<(), SharedPathError> {
    host_path
        .strip_prefix(shared_root)
        .map(|_| ())
        .map_err(|_| SharedPathError::OutsideRoot {
            host_path: host_path.to_path_buf(),
            shared_root: shared_root.to_path_buf(),
        })
}
```

Staging projects under `/tmp/sandbox-shared` is not a workflow anyone wants, and it is
independently fragile: macOS periodically clears `/private/tmp` under a long-lived VM,
leaving a stale 9p export that fails every subsequent `shared:` create until the VM is
bounced.

### The problem statement

Issue #82: **make the gateway Lima VM operator-owned**, so the QEMU process exporting
9p is the operator's own and `shared:` can reference real project paths.

This document does not commit to that migration. It specifies what must land first
and the conditions under which it proceeds.

---

## Before you start

### Required software

Versions below are what the reference macOS host runs and what this design was
reasoned against. Newer is probably fine; older Lima is not — the gateway template
sets `minimumLimaVersion` (`gateway_lima.rs:390`, constant at `:97`).

```bash
limactl --version                    # reference: 2.1.2
qemu-system-aarch64 --version        # reference: 11.0.1
brew list --versions socket_vmnet    # reference: 1.2.2
uname -r                             # reference host: Darwin 25.4.0
```

`socket_vmnet` must additionally be **staged root-owned** at
`/Library/sandboxd/socket_vmnet` (`network.rs:869`) — the launchd daemons exec that
path, never the admin-writable Homebrew one.

### Confirm the vmnet pool is live and reachable by your uid

The pool's launchd jobs are **system-domain**, so a plain `launchctl list` shows
nothing — a common time-waster. Use:

```bash
launchctl print system/io.sandboxd.vmnet.0     # expect: state = running
ls -la /var/run/sandbox/vmnet/                 # expect: slot-0.sock … slot-7.sock
ps aux | grep '[s]ocket_vmnet'                 # expect: one process per slot
```

Access is **group-scoped, never uid-scoped** — the plist passes
`--socket-group=<group>` (`network.rs:1027`) and the sockets are
`srwxrwx--- root:<group>`. Confirm your uid carries that group:

```bash
stat -f '%Sg' /var/run/sandbox/vmnet/slot-0.sock   # the group that matters
id                                                  # must list that group
```

If the group was added after your login, the membership is not live in your session —
start a new login session, or wrap commands in `sg <group> -c '…'`.

### ⚠️ Do NOT run `make setup-dev-env` on a host with pre-rename plists

**This is the warning that costs a day.** See issue #85.

sandboxd renamed its daemon account from `_sandbox` to `_sandboxd`. The plist
generator now emits a root pre-exec preamble referencing `_sandboxd`
(`network.rs:1021-1027`):

```
install -d -o _sandboxd -g _sandboxd -m 0750 /var/run/sandbox && \
install -d -o _sandboxd -g _sandboxd -m 0750 /var/run/sandbox/vmnet && \
codesign --verify --strict /Library/sandboxd/socket_vmnet || { … exit 1; } && \
exec /Library/sandboxd/socket_vmnet --vmnet-mode=host \
  --vmnet-network-identifier=<uuid> --socket-group=_sandboxd <socket_path>
```

**Only `scripts/install.sh` ever creates the `_sandboxd` account. No make target
does.** On a host that has never run `install.sh`, `make setup-dev-env` rewrites the
plists to reference an account that does not exist **and exits green** — it never
reloads launchd, so the already-loaded jobs keep serving and every slot keeps working.
The failure is deferred to the next boot: `install -d -o _sandboxd` fails, the `&&`
chain short-circuits, `socket_vmnet` never execs, and — because `/var/run` is cleared
on every macOS boot — there is no prior state to fall back on. `KeepAlive` turns it
into a retry loop, not a recovery. **The entire vmnet pool is gone and macOS
networking is down**, days after the command that broke it, with nothing linking the
two.

Check before running anything:

```bash
dscl . -read /Groups/_sandboxd >/dev/null 2>&1 \
  && echo "OK: _sandboxd exists" \
  || echo "DANGER: _sandboxd missing — run scripts/install.sh BEFORE make setup-dev-env"

grep -o 'socket-group=[a-z_]*' /Library/LaunchDaemons/io.sandboxd.vmnet.0.plist
```

If the account is missing, run `scripts/install.sh` first. If the installed plists say
`--socket-group=_sandbox` (the old name), you are on a pre-rename host: fix the
account first, regenerate the plists, then **reboot or explicitly reload the jobs**
rather than trusting the green exit.

### Gateway VM state

The gateway VM is often stopped; egress work needs it running:

```bash
export LIMA_HOME=/var/lib/sandboxd/<daemon_uid>/<op_uid>/lima
limactl list --json | grep sandboxd-gateway
```

Note the **3-level** path (`state-root / daemon-uid / operator-uid / lima`). A 2-level
form appears in one test helper and is wrong — see phase 6.

### What "unverified" means here

Two claims this design leans on were reasoned from Lima's source and templates but
**not observed**. Both are cheap to check, and both are pre-checks in §3.1:

1. Lima honours a per-entry `interface:` key for `socket:` networks.
2. `cidata.iso` regenerates on **every** VM start, not only the first.

They are flagged ⚠️ at each point of use.

---

## Decision and sequencing

### Why the egress gate comes first

The spike behind issue #82 proved the control plane and both stream classes. It
**never exercised egress enforcement at all** — `socket_vmnet` was unavailable in that
environment, so the gateway pipeline was never in the loop, and the stream
measurements were taken on a `vz`-type VM rather than the production `qemu`
configuration. (VZ cannot attach `socket_vmnet` at all, which is precisely why
production is QEMU — `.tasks/specs/2026-05-02-macos-support-design.md:10`.)

Absolute, unbypassable egress control is the project's reason to exist. Moving the VM
that hosts every enforcement point into a different trust domain must have that
property **re-proven before** three-to-five weeks of migration work, not after.

### Why slot partitioning comes before ownership

Issue #82 places multi-operator NIC/slot consumption out of scope, reasoning that lite
sessions consume no NIC. That is true (`claim_lite_token`, `network.rs:1202`), and a
*lite-only* per-operator VM would indeed sidestep the problem.

It does not survive contact with the full backend. A full-backend session's gateway
container must sit on that session's isolated segment, which means the gateway VM must
hold a NIC on that session's slot — hence the `(0..max_slots)` template loop above.
Under **any** per-operator gateway model, two operators' VMs built from that template
both attach to the same N sockets: same L2 segments, same `/29`s, same identifiers.
`vmnet_slot_addresses` (`network.rs:954`) would hand both operators the same `B+3` and
`B+4`. That is an address collision **and** a cross-operator exposure — operator A's
VM would sit on the segment carrying operator B's session traffic and could address
both endpoints on it.

Solving it only for lite defers the problem to whenever the full backend joins the
model. Partitioning is what makes the isolation claim in §5.1 true, so it is designed
here rather than documented away.

### Phase map

| Phase | Goal | Gated on |
|---|---|---|
| **0** | Pre-checks + egress validation gate | — |
| **1** | Per-operator slot partitioning | 0 green |
| **2** | Per-operator gateway VM ownership | 1 |
| **3** | Docker broker ops + brokered streams | 2 |
| **4** | Typed route-helper broker op | 3 |
| **5** | Shared-root removal — *the feature #82 is named for* | 2, 3 |
| **6** | Test and docs retarget | runs continuously across 1–5 |

Full detail in [§4](#4-phases).

---

## 1. Ownership model and slot identity

### 1.1 Per-operator gateway VM, driven through the broker

Each operator gets their own gateway Lima VM in their own `LIMA_HOME`, with every
control-plane operation routed through the existing operator-execution seam.

Three things make this cheaper than it looks:

- **The uid branch already exists.** Passing a real operator uid to
  `AgentBrokerExecutor::run` (`broker.rs:1688`, quoted in Background) routes to the
  broker with no code change.
- **The path formula already generalises.** `operator_lima_home(op_uid)`
  (`lima.rs:214-223`) already takes an operator uid; the gateway's path is the
  degenerate case of a general formula.
- **The registry shape already exists in-tree.** `LimaManagerRegistry`
  (`lima.rs:1245-1280`) is a `Mutex<HashMap<u32, Arc<LimaManager>>>` keyed by operator
  uid, monotonically growing, with a shared executor and an injected
  home-provisioning function. Copy it; do not invent a new shape.

What does **not** generalise: five `limactl` calls inside `GatewayLimaManager` bypass
the seam entirely, building `Command::new("limactl")` directly and applying the
daemon's `LIMA_HOME` via `apply_limactl_env(&mut cmd, self.daemon_uid)`
(`gateway_lima.rs:672`):

| Site | Call |
|---|---|
| `gateway_lima.rs:1614` | `limactl shell <gw> -- bash -c <cmd>` |
| `gateway_lima.rs:1642` | `limactl shell <gw> -- <argv…>` |
| `gateway_lima.rs:1757` | `limactl copy <host> <gw>:/tmp/…` (route helper) |
| `gateway_lima.rs:1865` | `limactl copy <host> <gw>:<stage>/<file>` (lite session files) |
| `gateway_lima.rs:2082` | `limactl --version` |

`LimaOp` (`lima.rs:766-810`) has **no `shell` or `copy` variant**. These become either
new typed variants or — preferably — are replaced outright by brokered Docker and
route-helper ops (phases 3–4).

### 1.2 Per-operator `VmnetPool` in a uid-keyed registry

**The pool struct and its claim/release semantics do not change.** There is simply
more than one of it, each seeded with a disjoint contiguous slot range.

`VmnetPool` (`network.rs:1090-1421`) has no operator dimension anywhere — the claim map
is keyed by `SessionId` only, with value `(u16, Option<NetworkInfo>)`. You could add an
owner field to that tuple, but `session_count` is *also* a global admission cap that
must become per-operator, so **one pool per operator behind a uid-keyed registry** is
the cleaner shape and mirrors `LimaManagerRegistry`.

What changes inside the pool:

| Item | Location | Change |
|---|---|---|
| `claim_lima_slot` free-index scan | `network.rs:1171` — `(0..self.max_slots).find(\|i\| !slots.contains(i))` | scan the operator's range instead |
| `claim_lima_slot` cap check | `network.rs:1161-1166` | cap becomes the operator's quota; message rewritten (§2.2) |
| `claim_lite_token` cap check | `network.rs:1208-1213` | same |
| `restore_from_infos` bounds check | `network.rs:1320-1354` | already validates `idx < max_slots`; becomes "inside the operator's range" — a tightening of an existing check |
| `claimed_slot_sessions` | `network.rs:1406-1415` | leak-detection accessor consumed by `/diagnostics` (`main.rs:11156-11157`); gains an operator dimension |

Unchanged: `set_lima_network_info` (`:1226`), `release_lima_slot` (`:1261`),
`release_lite_token` (`:1290`), `restore_lite_tokens` (`:1373`), and the two-phase
placeholder-write invariant that lets a partial-create rollback always free its slot.

**Isolation is inherited for free.** Both `vmnet_slot_network_identifier`
(`network.rs:897`) and `vmnet_slot_addresses` (`network.rs:954`) are pure functions of
slot index, so slots 4–7 keep distinct L2 segments and distinct `/29`s regardless of
who consumes them. Partitioning therefore needs **no plist regeneration and no
privileged work**: the plists are slot-indexed rather than operator-indexed, and the
sockets are already reachable by every enrolled operator via the socket group.

### 1.3 Range assignment, lifetime and quota

- Claimed at **VM creation**, released on **VM deletion**.
- **Persisted daemon-side.** §2.1 gives two reasons; the second is decisive.

**Quota defaults to the entire pool, and the first operator to create a gateway VM
claims all of it.** This is first-claim-wins, and the reason for it is the
single-operator host: it must behave **exactly** as it does today — same 8 concurrent
sessions, same slot indices, same segments. Without that default, partitioning is a
straight concurrency regression: 8 slots across 2 operators caps each at 4; across 4
operators, at 2.

**Multi-operator is opt-in via explicit quota configuration.** In this version there is
**no automatic rebalancing, no lazy claiming, and no bouncing of an existing operator's
VM to make room.** (Bounce-driven rebalancing is a plausible future enhancement and is
explicitly out of scope — §2.7.)

The concrete shape of that quota configuration — which file, which field — is left to
phase 1 as an implementation detail. Two constraints on it: config files are JSON per
project convention, and `SANDBOX_MAX_MACOS_SESSIONS` has exactly one parse site today
(`main.rs:13403-13440`), so the per-operator dimension should land there rather than
growing a second ingestion path.

**A second operator requesting a gateway VM when no disjoint range is available fails
explicitly.** This is a *configuration conflict*, not a capacity ceiling; §2.2 gives the
two distinct error shapes and why they must not be conflated. The error must state:

- how many slots the pool has;
- that they are already claimed — and by which operator, if the daemon can name it;
- the remediation: **configure a per-operator quota and recreate the existing VM.**

Someone hitting this must not have to read the source to understand what happened.

Growing the pool toward the 32 the `/24` allows is **one-time privileged installer
work**, not daemon work. The daemon explicitly refuses to regenerate root-owned
plists; that refusal is the `RefuseNeedsPrivilegedRegen` arm of `decide_pool_resize`
(`gateway_lima.rs:2287-2378`).

### 1.4 Slot identity stops being positional

**This is the highest-risk item in §1.** It is a correctness and isolation concern, not
a cosmetic one, and one of its sites fails *silently*.

**How guest NIC names are actually assigned.** Not by udev, not by the socket filename,
not by sandboxd. Lima renders a cloud-init `network-config` document into `cidata.iso`
mapping MAC → name, where the name is `$nw.Interface` for that `networks:` entry,
defaulting to `lima<array-index>` — documented in Lima 2.1.2 at
`/opt/homebrew/Cellar/lima/2.1.2/share/lima/templates/default.yaml:471` ("Interface
name, defaults to `lima0`, `lima1`, etc.").

**Naming is positional, not socket-derived. A VM given slots `{4,5,6,7}` names its NICs
`lima0..lima3`.**

That matters because the NIC name selects the **macvlan parent**, i.e. which L2 segment
the session lands on (`macos_session.rs:158-165`), and it is persisted as
`NetworkInfo.bridge_name` (`main.rs:4373`) — so a wrong name is durable, not transient.

#### Fix 1 — pin identity with Lima's per-entry `interface:` key

```yaml
networks:
  - socket: /var/run/sandbox/vmnet/slot-4.sock
    interface: lima4
```

⚠️ **UNVERIFIED for `socket:` networks.** The `interface:` field is documented under a
`- lima: shared` example (`default.yaml:470-471`). The evidence that it applies to
`socket:` entries is structural, not observed: Lima's network-config template renders
`{{$nw.Interface}}` while iterating *all* networks with no kind-specific branch, and
Lima carries a uniqueness-validation message that indexes the field generically across
the whole list (`field '%s.interface' value %#q has already been used by field
'networks[%d].interface'`). **Run pre-check A (§3.1) before relying on this.** If it
fails, fixes 2–4 still apply and you need an explicit slot→NIC translation layer
instead — more code, no more risk, but decide it before writing template code.

#### Fix 2 — key the NIC parser by suffix, not position

`discover_nics_from_ip_json` (`gateway_lima.rs:282-316`) sorts by numeric suffix and
then **throws the suffix away**:

```rust
// Sort by numeric suffix so slot 0 → lima0, slot 1 → lima1, etc.
lima_nics.sort_by_key(|(n, _)| *n);

// Build the slot_index → interface_name map: the nth entry (0-indexed) in
// the sorted list maps to slot n.
let slot_to_iface: HashMap<u16, String> = lima_nics
    .into_iter()
    .enumerate()
    .map(|(idx, (_, name))| (idx as u16, name))   // <- position, not suffix
    .collect();
```

With NICs `lima4..lima7` present this yields `slot 0 → lima4`. Key by the parsed suffix
`n` instead. One line — but it changes `NicMap`'s meaning for the contiguous case too,
so the tests at `gateway_lima.rs:2502-2543` change with it.

#### Fix 3 — take an explicit slot set in template generation

Three `(0..max_slots)` loops in `generate_gateway_template` (`gateway_lima.rs:334-381`)
assume a contiguous zero-based range:

```rust
let networks_section = (0..max_slots)                          // :336
    .map(|slot| format!("  - socket: {}\n", vmnet_slot_socket_path(slot)))…

let netplan_lima_entries = (0..max_slots)                      // :367
    .map(|slot| format!("      printf '    lima{slot}:\\n      dhcp4: no\\n…"))…

let ipv6_disable_lines = (0..max_slots)                        // :379
    .map(|slot| format!("      sysctl -w net.ipv6.conf.lima{slot}.disable_ipv6=1\n"))…
```

All three must take a slot set (`&[u16]`). The set must be **derived from the pool at
call time, not snapshotted at construction** (§1.5). This changes the public signature
of `generate_gateway_template`, called from `create_instance` (`gateway_lima.rs:1286`)
and six unit tests.

#### Fix 4 — make the silent NIC-name fallback a hard error

Three sites carry the same guess. Create path (`main.rs:4362-4370`):

```rust
let nic_name = {
    let nic_map = state.gateway_lima_manager.nic_map();
    nic_map
        .and_then(|m| m.interface_for_slot(vmnet_slot.index).map(|s| s.to_string()))
        .unwrap_or_else(|| format!("lima{}", vmnet_slot.index))
};
```

Duplicated at `main.rs:9891` (restart) and `main.rs:12819` (recovery).

If the map lookup misses, the session's macvlan is parented on a **guessed** interface.
Under partitioning a miss attaches the session to the **wrong segment** instead of
failing.

**Make this a hard error regardless of whether the rest of this design proceeds.**
Silently guessing an L2 parent interface in the egress-control path should not have a
fallback: the guess is only ever right by coincidence, and the failure mode is silent
misplacement rather than a refused create.

### 1.5 The `config_n` / `effective_n` divergence — prevention, not repair

**Be precise about this one; it is easy to overstate.**

`GatewayLimaManager::new` copies `max_slots` from a **throwaway** pool
(`main.rs:13514-13521`, copy at `gateway_lima.rs:813`):

```rust
pub fn new(daemon_lima_home: PathBuf, executor: Arc<dyn LimaExecutor>,
           daemon_uid: u32, pool: &VmnetPool) -> Self {
    // …
    let max_slots = pool.max_slots();
```

The manager is never rebuilt. The live pool is constructed separately at `effective_n`
(`main.rs:13721`), which genuinely differs from `config_n` in the `WarnRunningSessions`
and `RefuseNeedsPrivilegedRegen` arms (`gateway_lima.rs:2296-2314`). So the two values
**do** diverge as stored state.

**It is a latent stored-state inconsistency, not an active bug. Do not write it up or
fix it as a defect being repaired.** Why it is inert today:

- `self.max_slots` has exactly one consumer —
  `generate_gateway_template(self.max_slots)` at `gateway_lima.rs:1286`, inside
  `create_instance`.
- `create_instance` has one call site: `ensure_ready` (`gateway_lima.rs:872`), on the
  instance-absent branch.
- `ensure_ready` has **three production call sites, all in the macOS startup block**
  (`main.rs:13525, 13637, 13666`) and **zero runtime call sites**.
- Recovery does not reach it — `restart_instance_for_recovery`
  (`gateway_lima.rs:2209-2215`) is force-stop plus start, never create.
- Within startup the sequencing is self-consistent, and the pool is always re-sized
  from the actually-discovered NIC count (`main.rs:13644-13647, 13669-13672`).

It becomes real under either of two changes, one of which is this design:

- anything calls `ensure_ready()` at runtime — a "recreate the gateway if it went
  missing" arm is a natural thing to add; or
- **partitioning makes the manager carry a slot *set* rather than a count**, at which
  point a stale snapshot stops being a wrong number and becomes a **wrong set of L2
  segments**.

Hence fix 3 above. The justification is prevention.

*(A genuinely active sibling defect is out of scope here: `start_instance` passes
`memory_mb: 2048, cpus: 2` as literals at `gateway_lima.rs:1373-1374` instead of
reading `GATEWAY_VM_MEMORY_MB` / `GATEWAY_VM_CPUS`.)*

---

## 2. Lifecycle and failure modes

### 2.1 Range recovery is daemon-persisted

The tempting mechanism — after a daemon restart, read each operator's `networks:` list
out of their VM's `lima.yaml` — **does not work, and must not be made to work.**

**Reason 1: the daemon cannot traverse into the operator's instance directory.**

`ensure_operator_lima_home` (`lima.rs:574-660`) does two things on macOS
(`lima.rs:616-648`): `chmod 0700` on the LIMA_HOME, then grant the operator a single
ACE **on that directory only**. The rationale is explicit and load-bearing
(`lima.rs:601-610`):

```
//    CRITICAL — no `file_inherit` / `directory_inherit` in the ACE.
//    Inheritance would propagate into every child, including
//    `_config/user` (Lima's SSH private key).  OpenSSH StrictKeyfileMode
//    calls stat(2) and rejects any key with a non-empty ACL (the `+` bit
//    in `ls -le` output) whose effective mode & 077 ≠ 0.  Without
//    inheritance the SSH key is a plain 0600 file with no ACL.
//    The operator runs limactl via the helper post-setresuid, so it owns
//    every file it creates and accesses them via owner bits — no
//    propagation needed.
```

That last sentence is the governing invariant: **the operator owns every file it
creates.** Because the ACE does not inherit, every operator-created child — directories
included — defaults to owner-only with no ACL. Observed on the reference host's genuine
cross-uid tree (`/var/lib/sandboxd/309/501/lima`, daemon uid 309, operator uid 501):
`_config/` is `drwx------ olek:_sandboxd-test` with **no** ACL, and an operator-created
template YAML in the same tree is `0600 olek`. A Lima instance directory has exactly
that provenance — `limactl create` runs as the operator.

*Limit of the evidence, stated rather than glossed:* there is no cross-uid VM instance
directory on the reference host to observe directly. The conclusion rests on three
converging pieces — the operator-owned `0700` `_config/` with no ACL inside a cross-uid
tree, the operator-owned `0600` YAML beside it, and the non-inheritance invariant quoted
above — not on a directly observed cross-uid `lima.yaml`. Settle it definitively by
creating one VM as a second uid and running `sudo -u <daemon-user> ls -le <instance-dir>`.

**Reason 2, the decisive one: the operator can write that file.** Recovering a range by
reading `lima.yaml` makes an **operator-controlled file the input to a security-relevant
allocation** — which L2 segment you land on — routing authority through the least
trusted party in the model. **This holds even if the permissions were different.** It is
independently fragile as a source of truth too: `lima.yaml` is Lima's file with Lima's
schema, not sandboxd's.

**Decision: the daemon assigns the range and persists it itself.** Two candidate
locations, both daemon-owned and both requiring no permission change:

- `sessions.db` — follow `CLAUDE.md` § On-disk compatibility: a new
  `V<NNN>__<name>.sql` in `sandbox-core/migrations/` for a column, or `Option<T>` +
  `#[serde(default)]` for a JSON blob field.
- A daemon-written file under `{state_root}/{daemon_uid}/{op_uid}/`, which is
  `drwxr-xr-x` daemon-owned.

**The choice is open** — see [Open questions](#open-questions).

**Documentation correction.** `CLAUDE.md` states the per-operator LIMA_HOME is "owned by
the operator uid". It is **daemon-owned with a single non-inheriting operator ACE**. The
practical guidance it supports (run test-side `limactl` as the operator, never as the
daemon user) is correct; the mechanism differs, and the difference is exactly what makes
reason 1 true.

### 2.2 Exhaustion and range conflict — two distinct failures

Partitioning produces **two** client-visible failures that are easy to conflate and
must not be. They have different causes, different remediations, and different status
codes.

| # | Condition | Cause | Status | Variant |
|---|---|---|---|---|
| 1 | **Per-operator session exhaustion** | the operator *has* a range, but every slot in it is in use | **429 Too Many Requests** | **new** `SandboxError` variant |
| 2 | **No range available for a new operator** | first-claim-wins (§1.3): the pool is already claimed and no quota config carves out a share | **409 Conflict** | existing `SandboxError::Conflict` |

Condition 1 is a capacity ceiling — wait, or stop a session. Condition 2 is a
configuration conflict — no amount of waiting fixes it; an administrator must act.
Returning the same code for both would tell the operator to retry when retrying can
never work.

#### Condition 1 — per-operator session exhaustion (the existing path, re-shaped)

Three sites build the same error. `claim_lima_slot`'s count cap
(`network.rs:1161-1166`):

```rust
let running = *count;
if running >= self.max_slots as u32 {
    return Err(SandboxError::Network(format!(
        "max concurrent sessions reached ({running} running).\n\
         To increase the limit, set max_macos_sessions in config and restart sandboxd."
    )));
}
```

Repeated at `network.rs:1171-1176` (no free index — unreachable while the count cap
holds) and `network.rs:1208-1213` (`claim_lite_token`).

It surfaces as **500 Internal Server Error**, message passed through verbatim
(`sandboxd/src/error.rs:70`):

```rust
SandboxError::Network(msg) => (StatusCode::INTERNAL_SERVER_ERROR, msg.clone()),
```

Two changes:

1. **Status class → 429.** Capacity exhaustion is a client-visible quota condition, not
   a server fault, and under partitioning it stops being rare: 8 slots across 2
   operators means an operator hits it at 4 sessions, across 4 operators at 2.
   `429 Too Many Requests` needs a **new `SandboxError` variant** plus an arm in
   `error_response`.
2. **Rewrite the remediation text.** "set max_macos_sessions in config and restart
   sandboxd" becomes actively misleading once the binding constraint is the operator's
   *share*: raising the host total does not help, and the host total cannot exceed 32
   regardless. The message must distinguish "your share is full" from "the host is
   full", and for the latter point at the privileged pool-regeneration step rather than
   a config edit.

#### Condition 2 — no range available for a new operator (new path)

Raised when an operator without a range requests a gateway VM and first-claim-wins
(§1.3) has already handed the pool out. **Reuse `SandboxError::Conflict`** — it maps to
`409` at `error.rs:69` and, like `Network`, passes its message through verbatim, so this
condition costs no new variant:

```rust
SandboxError::Conflict(msg) => (StatusCode::CONFLICT, msg.clone()),
```

The message carries the three facts from §1.3 — pool size, that it is already claimed
(naming the holding operator when the daemon can resolve it), and the remediation
(configure a per-operator quota, then recreate the existing VM). Do **not** reuse
condition 1's text: "max concurrent sessions reached" is wrong here, because the
requester holds no sessions at all.

### 2.3 Bootstrap gains a login dependency

Today the daemon brings the gateway VM up during its own startup with no operator
present (`ensure_ready` at `main.rs:13525, 13637, 13666`). Operator-owned, VM creation
goes through the broker and therefore **requires a checked-in agent**. With no registry
entry for that uid the broker returns `agent_not_running_error` (`broker.rs:278`):

```rust
fn agent_not_running_error(uid: u32) -> String {
    format!(
        "session agent for {} is not running — \
         the operator must be logged in for Lima VM operations",
        uid_display(uid)
    )
}
```

That error becomes a **gateway bring-up failure**, and the consequence is user-visible:
**an operator's sessions cannot exist before that operator logs in.** This is consistent
with the spec's existing login-scoped deployment assumption
(`.tasks/specs/2026-05-02-macos-support-design.md:39`), but it is a new failure mode at a
new point in the lifecycle and **belongs in the user-facing docs**, not only here.

### 2.4 Logout breaks recovery and reaping

Both `gateway_recovery.rs` and the orphan reapers assume the daemon can reach the
gateway VM at any time.

- `gateway_recovery.rs` production code is `:1-396` — a generic, injectable state
  machine with no `limactl`, no `docker`, and no reference to `GATEWAY_INSTANCE_NAME`.
  Discovery is entirely the caller's job (`recover_gateway_lima`, `main.rs:12766`, which
  closes over the singleton manager). Its restart thunk becomes unreachable for a
  logged-out operator.
- The Docker orphan reaper (`backend/orphan_reaper.rs:566`, wired at
  `main.rs:13978, 13984`) runs against one forwarded socket. Under N VMs it runs once
  per operator VM, and **cannot reach a logged-out operator's VM at all**.

**Precedent for the fix, and it is clean:** startup reconcile already gates on
`AgentRegistry::connected_uids` (`broker.rs:680-683`) and reconciles the rest lazily on
check-in (`broker.rs:1202-1205` `on_admit_tx`; wiring at `main.rs:13245`,
`:13289-13294`). "Garbage accumulates while an operator is logged out and is reconciled
on their next check-in" must be an **explicitly accepted, documented behaviour**.

A third site needs the same treatment: `SessionStore::new` shells `docker ps` /
`volume ls` / `network ls` at store-open time (`sandbox-core/src/store.rs:342-360`),
before any agent exists. **The Lima half of that same scan was already neutered for
exactly this reason** — `v006_scan_lima_vms` (`store.rs:327-336`) is a no-op stub whose
comment says per-operator LIMA_HOMEs require the daemon registry, unavailable at
store-open time. Do the same to the Docker half.

### 2.5 Agent eviction can cancel a gateway op mid-flight

`limactl start` detaches QEMU, so a VM survives an agent restart — but the **in-flight
operation dies with the connection**. Per-operator, this can strand a VM that other
sessions of the same operator depend on, mid-create or mid-start, with the daemon's view
of it unresolved.

The same hazard arrives via last-writer-wins eviction. `AgentRegistry::register`
(`broker.rs:629-658`) drops the prior connection's eviction sender when a second check-in
arrives for the same uid:

```rust
/// If an entry already exists for this uid, its eviction sender is dropped,
/// waking the prior task's eviction receiver (last-writer-wins).
```

which happens on re-login and on fast-user-switch.

Two properties sharpen this for later phases:

- **The control connection is a hard serialization point.**
  `drive_agent_connection_outer` polls the request channel only when no op is
  outstanding (`broker.rs:1323`), and the `TakeStream` inner loop (`:1372-1411`) blocks
  the whole task. Every op for a given operator — one-shot and stream-open alike — is
  strictly serialized behind one connection, with `REQUEST_CHANNEL_CAPACITY = 4`
  (`broker.rs:209`).
- **A wedged stream open costs the whole connection.** The absolute deadline burns up to
  the 60 s `HEARTBEAT_TIMEOUT` (`broker.rs:133`), during which no other op for that
  operator dispatches, then `break 'outer` (`broker.rs:1382-1384`) fails every in-flight
  and queued op.

Today that lane carries ~12 Lima ops per session. Phase 3 would put the entire lite
control plane on it, plus the DNS-gate bridge's **one stream open per DNS query**
(§5.2). **Decide the mitigation up front** — pipeline by `request_id`, which the
protocol already reserves for exactly this (`sandbox-agent/src/protocol.rs:99-101`), or
add a second connection class for stream opens. Do not discover it under load.

### 2.6 Two singletons that must become per-operator

**The global recovery latch.** `AppState.gateway_recovering: Arc<AtomicBool>`
(`main.rs:1373`) is one latch for "the" gateway being recovered, read at `main.rs:12350`
to suppress per-session gateway re-creates. With N VMs, **one operator's recovery would
suppress every other operator's per-session gateway monitor.** Key it by operator uid;
`gateway_recovery.rs`'s `latch: Arc<AtomicBool>` parameter (`:250`) follows.

`run_gateway_recovery` also snapshots **all** sessions from the store (`:247`), so it
needs an operator scope — filter to the operator whose VM restarted, or invoke it once
per operator. `run_bounded_recovery`, `GatewayRecoveringGuard` and `GatewayRecoveryDeps`
are already generic and need no change. `networking_status` (`:249`) is keyed by
`SessionId` and needs no change.

**The Lima orphan-reaper landmine.** The gateway VM survives the reaper today **only
because its name fails a parse.** `decide_lima_vm` (`lima.rs:350`) classifies each VM;
`sandboxd-gateway` fails `parse_session_id_from_name` (`lima.rs:4202-4205`):

```rust
pub const VM_NAME_PREFIX: &str = "sandbox-";

pub fn parse_session_id_from_name(name: &str) -> Option<SessionId> {
    name.strip_prefix(VM_NAME_PREFIX)
        .and_then(|s| SessionId::parse(s).ok())
}
```

so it yields `SkipNoSessionId`. A live gateway VM has **no session row**, so if a
per-operator naming scheme happens to parse, the reaper classifies it `Reap` and
**deletes a running gateway VM**. Reaping runs at `lima.rs:460` / `:550`, wired at
`main.rs:14007`. Note also that `enumerate_operator_uids_from_fs` (`lima.rs:263`) already
enumerates the daemon's own uid as an "operator uid", because the gateway's LIMA_HOME is
`{state_root}/{daemon_uid}/{daemon_uid}/lima`.

**Add an explicit exclusion.** Do not rely on a name-shape accident. The naming scheme
itself is undecided — see [Open questions](#open-questions).

### 2.7 Bounce-to-resize: available, deliberately unbuilt

Changing an operator's slot range does **not** require destroying their VM. Verified
feasible: stop → edit `lima.yaml` → start picks up `networks:` changes.

Three pieces of evidence:

1. **Nothing about networks is baked into the disk image.** The Lima hostagent composes
   the QEMU command line at start time, opening each socket_vmnet socket itself and
   passing the fd. From a live instance's `ha.stderr.log`:
   `-netdev socket,id=net1,fd=3` … `-netdev socket,id=net8,fd=10`.
2. **`cidata.iso` is written by the start path, not the create path.** In the reference
   instance dir it postdates `lima.yaml` by ~15 hours, and generation lives in
   `pkg/cidata.ExecuteTemplateCIDataISO` / `GenerateISO9660` / `writeCIDataDir`.
   ⚠️ **UNVERIFIED that it regenerates on *every* start** — that is one mtime data
   point. Pre-check B (§3.1) settles it in 30 seconds.
3. Lima ships `limactl edit INSTANCE` with `--network`, arbitrary `--set` yq mutation,
   and `--start`.

**Provision scripts self-correct** across a NIC-set change: Lima processes provisions
**per boot** via cloud-init (`default.yaml:282-303`), and sandboxd's netplan script
truncates with `>` before re-appending per-slot entries
(`gateway_lima.rs:367-376, 491-510`). The same holds for the IPv6-disable sysctls, the
`eth0` MTU clamp, the `0666` docker.sock chmod, and the route-helper sudoers drop-in.

**It is nonetheless not built here, and the reason is issue #83.** Bouncing an
operator's gateway VM kills their lite sessions, and container-backend sessions are
**never recovered** — `sessions_to_recover` (`gateway_recovery.rs:77-82`):

```rust
pub fn sessions_to_recover(all: Vec<Session>) -> Vec<Session> {
    use crate::backend::BackendKind;
    all.into_iter()
        .filter(|s| s.state == SessionState::Running && s.backend == BackendKind::Lima)
        .collect()
}
```

and sandbox containers are created `--restart no` (`backend/container.rs:853-854`), so
they do not return when the VM's Docker daemon restarts. Until #83 lands, resizing a
range means restarting the daemon and re-deriving ranges from persisted state.

#### Future enhancement, explicitly out of scope: bounce-driven rebalancing

The mechanism above is exactly what a **rebalancing** policy would need — shrink
operator A's range by bouncing A's VM so a newly-arriving operator B can be given a
disjoint share, instead of refusing B under first-claim-wins (§1.3).

**This version deliberately does not do that, and the omission is a decision rather
than an oversight.** It is gated on issue #83: bouncing an operator's VM kills that
operator's lite sessions, and container-backend sessions are not recovered today. Until
that holds, automatic rebalancing would silently destroy running work belonging to an
operator who did nothing but be first. Refusing B with an actionable 409 (§2.2 condition
2) is the honest behaviour in the meantime.

Revisit once #83 lands. The pieces it would need — persisted ranges (§2.1), a slot set
derived at call time (§1.4 fix 3), and self-correcting provision scripts — are all
already required by this design, so the future work is policy, not plumbing.

---

## 3. The egress validation gate

**The question:** *is egress still enforced when the gateway VM is owned by the operator
instead of the daemon?*

**Scope, deliberately narrow.** Networking only. **No** daemon, **no** broker, **no**
real sessions, **no** session store, **no** `shared:` mounts. Stand the topology up by
hand as an operator uid, assert, tear down.

**Not wired into the pytest e2e suite.** It is a decision instrument with a different
lifetime and audience from the regression suite. The suite's own retarget is phase 6.

Set these once; every command below uses them:

```bash
export OP_UID=$(id -u)
export LIMA_HOME=/var/lib/sandboxd/<daemon_uid>/${OP_UID}/lima
export GW=egress-gate-${OP_UID}      # throwaway VM name — never `sandboxd-gateway`
```

### 3.1 Pre-checks — run these first

Both take about 30 seconds. **Either can invalidate §1.** Do not proceed to 3.4 without
them.

#### Pre-check A — does `interface:` work for `socket:` networks?

Settles the ⚠️ in §1.4 fix 1.

```bash
cat > /tmp/iface-probe.yaml <<'YAML'
vmType: "qemu"
images:
  - location: "<UBUNTU_NOBLE_ARM64_URL — copy the value from gateway_lima.rs>"
    arch: aarch64
cpus: 2
memory: "2GiB"
networks:
  - socket: /var/run/sandbox/vmnet/slot-4.sock
    interface: lima4
containerd:
  system: false
  user: false
YAML

limactl create --name=iface-probe --tty=false /tmp/iface-probe.yaml
limactl start iface-probe
limactl shell iface-probe -- ip -json link show \
  | python3 -c 'import json,sys; print([e["ifname"] for e in json.load(sys.stdin)])'
```

- **Success:** the list contains `lima4`.
- **Failure signature:** the list contains `lima0` instead — `interface:` is not
  honoured for `socket:` entries.
- **If it fails:** §1.4 fix 1 is out. Record the decision, replace it with an explicit
  slot→NIC translation layer in phase 1, and continue with the gate — this does not
  block the egress question.

```bash
limactl stop --force iface-probe && limactl delete iface-probe
```

#### Pre-check B — does `cidata.iso` regenerate on every start?

Settles the ⚠️ in §2.7. Uses any existing stopped instance.

```bash
INST=<some stopped instance>
stat -f %m "$LIMA_HOME/$INST/cidata.iso"       # record
limactl start "$INST" && limactl stop "$INST"
stat -f %m "$LIMA_HOME/$INST/cidata.iso"       # compare
```

- **Success:** the mtime changed.
- **If unchanged:** bounce-to-resize (§2.7) is not viable as described; a NIC-set change
  would need instance recreation. Record it; it does not block the gate.

### 3.2 Not a precondition: `net.inet.ip.forwarding`

The macOS daemon refuses to start when host IP forwarding is enabled. **Do not make that
a gate precondition.** There is a separate ticket to remove the requirement, and holding
the gate to a condition intended to disappear would encode a dependency this design does
not want.

Record it, do not gate on it:

```bash
sysctl net.inet.ip.forwarding net.inet6.ip6.forwarding   # log the values
```

Report them alongside the result as interpretive context. No hard fail, no design
weight.

### 3.3 What the gate builds

The topology mirrors the **lite** shape (an in-VM Docker bridge), not the full-backend
macvlan shape — lite sessions consume no vmnet NIC, and the question is about the VM's
ownership, not about macvlan.

```
  operator-owned Lima VM ($GW)
  ┌──────────────────────────────────────────────────────────┐
  │  eth0 (slirp)  ──► the VM's only real uplink             │
  │                                                          │
  │  docker bridge `sandboxd-egress` ── gateway container    │
  │                                      (uplink side)       │
  │                                           │              │
  │  docker bridge `gate-session` /28         │              │
  │     .1 = bridge   .2 = gateway container (2nd NIC)       │
  │                   .3 = probe container                   │
  └──────────────────────────────────────────────────────────┘
```

The probe container stands in for a sandbox container. Its default route must point at
`.2`, not at `.1` — see 3.5, which is the step everything hinges on.

### 3.4 Stand-up

**Step 0 — pick a slot and confirm its socket.**

```bash
export SLOT=0
export SLOT_SOCK=/var/run/sandbox/vmnet/slot-${SLOT}.sock
test -S "$SLOT_SOCK" && echo "slot socket present"
```

The single-VM case does not strictly need a vmnet NIC (the probe's egress rides the VM's
slirp `eth0` via the gateway container). The **second-operator probe (3.7) does** —
distinct segments are the whole point there. Attach one anyway so both paths are the
same shape.

**Step 1 — create and start the VM as the operator.**

Render the template with `generate_gateway_template` using an explicit slot set and
**the 9p `mounts_stanza` dropped** — the gate does not exercise workspaces, and the
stanza (`lite_macos.rs:110-115`, interpolated at `gateway_lima.rs:409-415`) would
require the shared root to exist.

```bash
limactl create --name="$GW" --tty=false /tmp/gate-template.yaml
limactl start "$GW"
limactl shell "$GW" -- docker info >/dev/null && echo "docker up"
```

- **Failure here is outcome (a) or an environment problem**, not an egress finding. If
  `limactl start` fails on the socket, re-check the socket group
  ([Before you start](#before-you-start)).

**Step 2 — create the two bridges.**

```bash
limactl shell "$GW" -- docker network create sandboxd-egress || true   # name: gateway_lima.rs:89

# Derive a /28 that does not collide with anything already on the VM:
limactl shell "$GW" -- docker network ls --format '{{.Name}}' \
  | xargs -I{} limactl shell "$GW" -- docker network inspect {} \
      --format '{{range .IPAM.Config}}{{.Subnet}} {{end}}'

export SESSION_NET=10.211.0.0/28      # any non-overlapping RFC1918 /28
limactl shell "$GW" -- docker network create --subnet "$SESSION_NET" gate-session
```

With `10.211.0.0/28`: `.1` is the bridge, `.2` the gateway container, `.3` the probe.

**Step 3 — run the gateway container on the uplink bridge.**

Mirror `build_macos_gateway_docker_args` (`macos_session.rs:567-640`):

```bash
limactl shell "$GW" -- docker run -d --name gw \
  --network sandboxd-egress \
  --read-only \
  --cap-add NET_ADMIN \
  --tmpfs /var/log:rw,noexec,nosuid \
  --tmpfs /var/run:rw,noexec,nosuid \
  --tmpfs /tmp:rw,exec,nosuid \
  --tmpfs /root/.mitmproxy:rw \
  --tmpfs /etc/coredns:rw,noexec,nosuid \
  --tmpfs /etc/envoy:rw,noexec,nosuid \
  --sysctl net.ipv4.ip_forward=1 \
  --sysctl net.ipv6.conf.all.forwarding=0 \
  --env 'SANDBOX_COREDNS_UPSTREAM=8.8.8.8 8.8.4.4 1.1.1.1' \
  sandbox-gateway:<version>
```

**`SANDBOX_COREDNS_UPSTREAM` is macOS-specific and load-bearing. Omitting it produces a
false red on the allow half.** The entrypoint's baked Linux default is `127.0.0.11`
(`networking/gateway/entrypoint.sh:304`), which is a dead end inside the VM: its own
upstream — the VM's `127.0.0.53` systemd-resolved stub — does not answer, so an allowed
domain **SERVFAILs on the forward even though DNS policy admits it**. The rationale is
spelled out in the code at `macos_session.rs:610-611`.

**Step 4 — attach the gateway container's second NIC at `.2`.**

```bash
limactl shell "$GW" -- docker network connect --ip 10.211.0.2 gate-session gw
```

**Step 5 — wait for the pipeline to be healthy.**

The image ships the same five component probes the daemon uses
(`networking/gateway/Dockerfile:148, 174`):

```bash
for i in $(seq 1 60); do
  limactl shell "$GW" -- docker exec gw /healthcheck.sh && break
  sleep 2
done
```

- **Expected:** exit 0 within ~60 s.
- **Failure signature:** persistent non-zero. Read `docker logs gw` — a CoreDNS failure
  here usually means step 3's env var was omitted or the image tag is wrong.

**Step 6 — inject the nft ruleset and seed the policy artifacts.**

Do **not** hand-write the rules. `generate_dnat_ruleset(vm_subnet, gateway_ip)` is
`pub` at `gateway.rs:1616` and produces the exact ruleset; a Rust harness calls it
directly (a strong argument for the Rust option in §3.10). Its output for
`vm_subnet=10.211.0.0/28`, `gateway_ip=10.211.0.2`:

```
table inet sandbox_dnat {
    set policy_allow_tcp { type ipv4_addr . inet_service ; flags interval }
    set policy_allow_udp { type ipv4_addr . inet_service ; flags interval }

    chain prerouting {
        type nat hook prerouting priority dstnat;

        ip saddr 10.211.0.0/28 udp dport 53 dnat to 10.211.0.2:53
        ip saddr 10.211.0.0/28 tcp dport 53 dnat to 10.211.0.2:53
        ip saddr 10.211.0.0/28 meta l4proto tcp ip daddr . tcp dport @policy_allow_tcp dnat to 10.211.0.2:10000
        ip saddr 10.211.0.0/28 meta l4proto udp ip daddr . udp dport @policy_allow_udp accept
        ip saddr 10.211.0.0/28 meta l4proto tcp dnat to 10.211.0.2:10001
        ip saddr 10.211.0.0/28 meta l4proto udp log group 1
        ip saddr 10.211.0.0/28 meta l4proto udp drop
        ip daddr 169.254.169.254 drop
        ip6 daddr != ::1 drop
    }

    chain postrouting {
        type nat hook postrouting priority srcnat;
        masquerade
    }
}
```

Port constants: DNS `53` (`gateway.rs:248`), Envoy `10000` (`:253`), deny-logger TCP
`10001` (`:259`), NFLOG group `1` (`:276`).

**The empty sets are the fail-closed default** — until a policy lands, every non-53
packet from the subnet DNATs to the deny-logger.

```bash
printf '%s' "$RULESET" | limactl shell "$GW" -- docker exec -i gw nft -f -
```

Two further artifacts are needed before the allow half (assertion 2) can pass. **Read
the functions that produce them and replicate their output rather than inventing file
contents:**

- **Envoy listener** — Envoy will not start without one. The daemon seeds a deny-all
  listener into `/etc/envoy/listeners/` via `docker exec`;
  `write_listener_into_container` (`sandbox-core/src/atomic_listener_writer.rs:384`).
- **CoreDNS policy** — written to `/etc/coredns/policy.conf`
  (`sandbox-core/src/policy_distributor.rs:151`).

**Step 7 — run the probe container.**

```bash
limactl shell "$GW" -- docker run -d --name probe \
  --network gate-session --ip 10.211.0.3 \
  --dns 10.211.0.2 \
  --cap-drop ALL \
  <a minimal image providing curl and nslookup>
```

### 3.5 The critical step — the probe's default route

```bash
PROBE_PID=$(limactl shell "$GW" -- docker inspect -f '{{.State.Pid}}' probe)
limactl shell "$GW" -- sudo nsenter -t "$PROBE_PID" -n \
  ip route replace default via 10.211.0.2
```

**Docker points a container's default route at the bridge `.1`, not at the gateway
container. Without this step the probe bypasses the gateway entirely and everything
passes — including the deny assertions, which then prove nothing.**

This is also exactly why the production sandbox container runs `--cap-drop ALL`
(`backend/container.rs`, `build_create_argv`) and therefore cannot install its own
route, and why `sandbox-route-helper` exists: on macOS lite the route is installed from
*outside* the container by `sandbox-route-helper --vm-gateway-mode`
(`lite_macos.rs:262-277`):

```rust
vec![
    "shell".to_string(),
    gateway_vm_name.to_string(),
    "--".to_string(),
    "sudo".to_string(),
    IN_VM_ROUTE_HELPER_PATH.to_string(),
    "--vm-gateway-mode".to_string(),
    vm_pid.to_string(),
    gateway_ip.to_string(),
]
```

invoked at `main.rs:5360-5364` (create) and `main.rs:6091` (restart). The gate's
`nsenter` stands in for the helper.

**Verify before asserting anything:**

```bash
limactl shell "$GW" -- sudo nsenter -t "$PROBE_PID" -n ip route show default
# expect: default via 10.211.0.2
```

### 3.6 Assertions — deny first

**The order is a correctness property, not a style preference.** A missing or wrong
default route makes the **allow** case pass and the **deny** case fail. Asserting deny
first turns the single most likely harness bug into a loud, immediate failure instead of
a false green that would authorize weeks of migration on no evidence.

#### Assertion 1 — deny (run this first)

Load a **CIDR-only** policy that does not cover the probe target, then probe an IP
literal:

```bash
limactl shell "$GW" -- docker exec gw nft add element inet sandbox_dnat \
  policy_allow_tcp '{ 10.0.0.0/8 . 443 }'

limactl shell "$GW" -- docker exec probe \
  curl -sS --max-time 8 http://203.0.113.1:8080/
echo "exit=$?"
```

- **Why a CIDR policy rather than an empty one:** a deny that passes because *nothing*
  is configured is weak evidence. A live policy that simply does not cover the target
  proves the pipeline is loaded and still denying.
- **Why an IP literal:** `203.0.113.1` is TEST-NET-3, guaranteed unroutable, and a
  literal keeps DNS entirely out of the deny path.
- **Expected exit code:** one of `{6, 7, 28, 35, 56}` — the block signature already in
  use at `tests/e2e/test_lite_macos.py:410` (`_BLOCK_CURL_EXITS`), covering
  could-not-resolve / connection-refused / timeout / SSL-connect-error / recv-reset.
- **Exit 0 means the probe reached the internet. Stop.** Re-check 3.5 first — a wrong
  default route is by far the most likely cause. If the route is verified correct and
  this still passes, that is **outcome (c)** in §3.8.

#### Assertion 2 — allow

```bash
# Policy: example.com:80/tcp at transport level (L1).
# Seed the DNS policy (step 6) and the transport allow tuple, then warm the cache:
for i in $(seq 1 30); do
  limactl shell "$GW" -- docker exec probe nslookup example.com && break
  sleep 1
done

limactl shell "$GW" -- docker exec probe \
  curl -sS --max-time 15 http://example.com/
echo "exit=$?"
```

- **The `nslookup` warm-up poll is required, not optional.** L1 transport policy is
  fail-closed against an empty resolved-IP cache — the allow tuple is keyed on resolved
  addresses, so the first request can legitimately be denied before DNS propagation
  lands. The same poll shape is at `tests/e2e/test_lite_macos.py:501-516`.
- **Expected:** exit `0` **and** `Example Domain` present in stdout. Assert both — exit
  0 alone can be produced by an unexpected intermediary.
- **Failure signature — SERVFAIL on an allowed domain:** re-check that
  `SANDBOX_COREDNS_UPSTREAM` was set in step 3.

#### Assertion 3 — structural

```bash
limactl shell "$GW" -- docker exec gw nft list ruleset > /tmp/ruleset.txt
```

Assert against the same regexes the existing suite uses
(`tests/e2e/test_networking.py:384, 388, 398, 412`):

| Regex | Meaning |
|---|---|
| `udp dport 53 dnat` | DNS UDP redirected to CoreDNS |
| `tcp dport 53 dnat` | DNS TCP redirected to CoreDNS |
| `meta l4proto 6 dnat` | non-DNS TCP catch-all lands on the deny-logger |
| `meta l4proto 17 log group 1` | non-DNS UDP mirrored to NFLOG before drop |

Plus: the table set is **exactly** `{sandbox, sandbox_dnat, sandbox_policy}` — the
property pinned on Linux by `sandboxd/tests/gateway_deny_pipeline.rs:779`
(`integration_session_start_produces_exactly_sandbox_sandbox_dnat_sandbox_policy_tables`).

#### Assertion 4 — bypass resistance (**the most important one**)

```bash
limactl shell "$GW" -- sudo nsenter -t "$PROBE_PID" -n ip route del default
limactl shell "$GW" -- sudo nsenter -t "$PROBE_PID" -n \
  ip route add default via 192.168.5.2 dev eth0 metric 1
limactl shell "$GW" -- docker exec probe curl -sS --max-time 8 http://example.com/
echo "exit=$?"
```

`192.168.5.2` is Lima's slirp gateway — the same address the existing full-backend
regression uses (`tests/e2e/test_networking.py:799-809`).

- **Expected:** a block exit code from `{6, 7, 28, 35, 56}`. The internet remains
  unreachable.
- **This is the only assertion that proves *topological* control rather than *policy*
  control** — that egress is forced through the gateway by the shape of the network
  rather than by a rule the probe is choosing to obey. It is precisely the property that
  changing VM ownership puts at risk, and it is the lite-side analogue of the
  spec-mandated delete-the-gateway-route regression
  (`.tasks/specs/2026-05-02-macos-support-design.md:610`;
  `tests/e2e/test_networking.py:698`).
- **Exit 0 here is outcome (c). The decision dies.**

#### Explicitly **not** asserted: the deny-event JSONL

The project already made this call, and the reasoning is recorded at
`tests/e2e/test_lite_macos.py:422-427`: the JSONL event capture proved unreliable to
assert on, because **the event stream is a best-effort observability sink, not the
enforcement mechanism.** Capture events in the gate as **diagnostics** — they help when
reading a red run — but never as a pass condition.

### 3.7 Second-operator probe

Stand up a **second** VM as a **different uid**, on a **disjoint slot range**, and repeat
3.4–3.6 against it. Then assert the property all of §1 rests on.

```
VM A (operator A): slots {0..3}
VM B (operator B): slots {4..7}
```

Three assertions:

1. **B gets its own segment** — distinct `/29` from `vmnet_slot_addresses`, distinct
   identifier from `vmnet_slot_network_identifier`.
2. **Egress is enforced in both** — assertions 1–4 hold independently in each VM.
3. **Neither VM can see the other's segment.** From inside VM A, addresses on B's `/29`
   must be unreachable, and vice versa:

   ```bash
   # From VM A, with B_BASE = 10.209.128.0 + 8*<B's slot>:
   limactl shell "$GW_A" -- ping -c 2 -W 2 <B_BASE+3>    # expect: 100% packet loss
   limactl shell "$GW_A" -- arping -c 2 <B_BASE+3>       # expect: no reply
   ```

**Assertion 3 is the isolation claim.** Without it, partitioning is asserted rather than
demonstrated. The in-tree precedent for the mechanism is
`integration_vmnet_inter_slot_l2_isolation` (`network.rs:3021`), which establishes
inter-slot L2 isolation for the singleton case; the gate extends it to two
independently-owned VMs.

⚠️ **Environment dependency:** this needs a second uid enrolled in the vmnet socket group
and able to run `limactl`. See [Open questions](#open-questions) — on the reference host
the obvious candidates are entangled with issue #85.

### 3.8 Failure discrimination — a red run must say which

The gate is worthless if a red result cannot be attributed. Structure the harness so its
output names one of these three:

| Outcome | Signature | Effect on the decision |
|---|---|---|
| **(a) Socket-permission failure** | `limactl start` cannot open the slot socket; the forwarded Docker socket is unreachable; permission errors before any assertion runs | fixable; the decision **survives** |
| **(b) Per-operator segment-allocation failure** | VMs start and enforce, but §3.7 assertion 1 or 3 fails — NIC identity wrong, address collision, or cross-segment reachability | points at a split model (lite-only per-operator, full backend on a shared VM); the decision **survives, modified** |
| **(c) Interception coupled to daemon ownership** | assertion 1 or 4 fails with a **verified-correct** default route, for a reason that is not (a) or (b) | the decision **dies**; `shared:` needs a different mechanism entirely |

For **(a)** specifically, the prior evidence is favourable: access is group-scoped rather
than uid-scoped (`network.rs:1027`), the sockets carry no ACLs, and **sandbox session VMs
already run operator-owned QEMU against these very sockets in production**
(`lima.rs:3607, 3617-3618` emit `vmType: "qemu"` plus a single `socket:` entry for the
claimed slot). Moving the gateway VM changes *which* uid opens all N sockets, not
*whether* that uid is permitted to.

### 3.9 Teardown

```bash
limactl shell "$GW" -- docker rm -f probe gw || true
limactl shell "$GW" -- docker network rm gate-session sandboxd-egress || true
limactl stop --force "$GW" && limactl delete "$GW"
```

The gate must be re-runnable: teardown is idempotent and **must not touch
`sandboxd-gateway` or any real instance**.

### 3.10 Harness form — open

Three candidates; **the choice is open** (see [Open questions](#open-questions)).
Decision inputs:

| Option | For | Against |
|---|---|---|
| **Shell under `tests/`** | lowest ceremony; matches what the work actually is | must hand-render the nft ruleset and the Envoy/CoreDNS artifacts, and keep them in sync with `gateway.rs` by hand |
| **Python outside the pytest suite** | reuses assertion idioms and `_BLOCK_CURL_EXITS` without inheriting conftest's daemon/host-Docker assumptions | same rendering-drift problem as shell |
| **Rust `integration_*` test** | calls `generate_dnat_ruleset` (`gateway.rs:1616`) and `generate_gateway_template` (`gateway_lima.rs:334`) **directly**, so the rules cannot drift; reuses `DirectLimaExecutor` and `build_test_manager` (`sandbox-core/tests/integration_gateway_lima.rs:45, 123`) and the shipped `sandbox-core/src/test_support/direct_executor.rs`; gets the `integration` nextest profile for free | heaviest to iterate on; the two-uid case in §3.7 is awkward inside one test process |

The rendering-drift argument is strong: step 6's ruleset and the policy artifacts are
generated code today, and a hand-maintained copy in a shell script will silently rot.

---

## 4. Phases

Each phase states its goal, dependencies, the files and functions to change, and
**acceptance criteria you can execute**. Phases are ordered; phase 6 runs continuously.

**Note the ordering consequence up front: the feature issue #82 is named for lands
last.** `shared:` with real project paths cannot work until the VM is operator-owned,
which cannot land until the gateway manager is per-operator, which should not land until
slots partition and egress is proven. Everything before phase 5 is infrastructure for a
user-visible change that appears only at the end. Say so when reporting progress;
otherwise phases 1–4 look like no progress at all.

---

### Phase 0 — Pre-checks and the egress validation gate

**Goal.** Answer whether egress remains enforced when the gateway VM is operator-owned,
before committing to the migration.

**Depends on.** Nothing. Requires the environment in
[Before you start](#before-you-start).

**Implements.** §3.

**Files.** New harness only (location open, §3.10). **No production code changes.**

**Acceptance criteria.**

- [ ] Pre-check A (§3.1) run; result recorded as "`interface:` honoured for `socket:`
      networks: yes/no". If no, phase 1's scope is updated before it starts.
- [ ] Pre-check B (§3.1) run; result recorded.
- [ ] Host `net.inet.ip.forwarding` recorded (not gated on, §3.2).
- [ ] Single-VM gate: assertions 1–4 (§3.6) all pass, **in that order**, with §3.5's
      route verified before assertion 1 runs.
- [ ] Second-operator probe (§3.7): all three assertions pass.
- [ ] The harness is re-runnable — a second consecutive run passes with no manual
      cleanup — and its teardown touches no real instance.
- [ ] A deliberately broken run (skip §3.5) produces a **red** result, not a green one.
      *Test your test.*
- [ ] Any red result names outcome (a), (b) or (c) per §3.8.

**Exit.** Green → phase 1 starts. Red → route per §3.8; only (c) kills the decision.

---

### Phase 1 — Per-operator slot partitioning

**Goal.** More than one `VmnetPool`, each owning a disjoint contiguous slot range, with
slot identity no longer positional.

**Depends on.** Phase 0 green, and pre-check A's answer (which selects fix 1 vs. a
translation layer).

**Implements.** §1.2, §1.3, §1.4, §1.5, §2.2.

**Files and functions.**

| File | Change |
|---|---|
| `sandbox-core/src/network.rs:1090-1421` | `VmnetPool` unchanged in shape; range-scoped `claim_lima_slot` scan (`:1171`), quota-scoped cap checks (`:1161`, `:1208`), range-aware `restore_from_infos` (`:1320`), operator dimension on `claimed_slot_sessions` (`:1406`) |
| new | uid-keyed `VmnetPoolRegistry`, modelled on `LimaManagerRegistry` (`lima.rs:1245-1280`) |
| `sandbox-core/src/gateway_lima.rs:282-316` | `discover_nics_from_ip_json` — key by parsed suffix, not `enumerate()` position |
| `sandbox-core/src/gateway_lima.rs:334-381` | `generate_gateway_template` — take a slot set; emit `interface:` per entry (or the translation layer) |
| `sandbox-core/src/gateway_lima.rs:1286` | `create_instance` — derive the slot set from the pool **at call time** |
| `sandboxd/src/main.rs:4362-4370`, `:9884-9896`, `:12811-12820` | replace `unwrap_or_else(\|\| format!("lima{}", …))` with a hard error |
| `sandboxd/src/main.rs:13403-13440` | `SANDBOX_MAX_MACOS_SESSIONS` parse — add the per-operator quota dimension |
| `sandboxd/src/error.rs:57-79` | new `SandboxError` variant → `429` (per-operator exhaustion) + new arm in `error_response`; **reuse** existing `Conflict → 409` (`:69`) for range-unavailable |
| `sandbox-core/src/network.rs:1161-1176`, `:1208-1213` | rewrite the exhaustion message (§2.2 condition 1) |
| range-claim path (new) | first-claim-wins; `Conflict` with pool size + holder + remediation when no disjoint range is available (§1.3, §2.2 condition 2) |
| persistence | range record — `sessions.db` migration **or** `{state_root}/{daemon_uid}/{op_uid}/` file (**open**, §2.1) |
| `sandbox-core/src/gateway_lima.rs:2502-2543` | NicMap tests follow the re-keying |

**Acceptance criteria.**

- [ ] `cd sandboxd && cargo build --workspace && cargo clippy --workspace && cargo fmt --all --check`
      all clean.
- [ ] `make test` passes (hermetic, ~5 s).
- [ ] A unit test proves `discover_nics_from_ip_json` maps `lima4..lima7` to slots
      **4..7**, not 0..3.
- [ ] A unit test proves `generate_gateway_template(&[4,5,6,7])` emits exactly four
      `socket:` entries naming `slot-4..slot-7`, with matching netplan and IPv6-disable
      lines.
- [ ] A unit test proves a missing NIC-map entry returns `Err`, not a `limaN` guess, at
      all three sites.
- [ ] Two pools with disjoint ranges never hand out the same slot index, and a pool
      cannot hand out an index outside its range — **including via
      `restore_from_infos`**.
- [ ] **Per-operator exhaustion returns 429** with a message distinguishing "your share"
      from "the host". Assert the status code, not just the string.
- [ ] **Range-unavailable returns 409** — claiming a range for a second operator when
      none is available yields `Conflict`, and the message names the pool size, that it
      is already claimed, and the remediation (§1.3). Assert the status code and that
      the text is **not** condition 1's "max concurrent sessions reached". *Assert this
      at the range-claim level: phase 1 has no per-operator gateway VM to create yet, so
      the end-to-end refusal on VM creation is phase 2's criterion.*
- [ ] The two conditions are distinguishable by status code alone — a client can tell
      "wait or stop a session" from "an administrator must act" without parsing prose.
- [ ] **First-claim-wins holds**: the first operator to create a gateway VM is given the
      whole pool; nothing rebalances it afterwards, and no existing VM is bounced.
- [ ] **Single-operator behaviour is unchanged**: with default config, one operator still
      gets 8 concurrent sessions and slot indices still start at 0. This is the
      regression that matters most.
- [ ] Persisted ranges survive a daemon restart: stop, restart, confirm the same operator
      gets the same range **without reading any operator-owned file**.

**Notes.** Phase 1 is independently valuable and independently correct — the hard-error
change especially. It does not require phase 2 to ship.

---

### Phase 2 — Per-operator gateway VM ownership

**Goal.** One gateway Lima VM per operator, created and driven as that operator through
the broker.

**Depends on.** Phase 1 (an operator VM must be given a range).

**Implements.** §1.1, §2.1, §2.3, §2.4, §2.5, §2.6.

**Files and functions.**

| File | Change |
|---|---|
| `sandbox-core/src/gateway_lima.rs:771-2272` | `GatewayLimaManager` takes an `op_uid`; the six executor calls (`:1245, 1323, 1362, 1931, 2122, 2164`) pass the operator uid |
| new | `GatewayLimaManagerRegistry`, modelled on `LimaManagerRegistry` (`lima.rs:1245-1280`) |
| `sandbox-core/src/gateway_lima.rs:672` | `apply_limactl_env` — operator LIMA_HOME |
| `sandbox-core/src/gateway_lima.rs:84` + 14 use sites | per-operator instance naming; **must fail `parse_session_id_from_name` (`lima.rs:4202`)** |
| `sandbox-core/src/lima.rs:350` (`decide_lima_vm`) | **explicit** gateway exclusion, not a name-shape accident |
| `sandboxd/src/main.rs:1339`, `:1349`, `:1373` | `AppState` — pool, manager and recovery latch become uid-keyed |
| `sandbox-core/src/gateway_recovery.rs:247-250` | operator scope + per-operator latch |
| `sandboxd/src/main.rs:12766`, `:12910` | `recover_gateway_lima` / `gateway_lima_monitor` — per-operator |
| `sandbox-core/src/backend/orphan_reaper.rs:566`; `sandboxd/src/main.rs:13978, 13984` | reap once per operator VM; gate on `connected_uids` (`broker.rs:680-683`) |
| `sandbox-core/src/store.rs:342-360` | neuter the V006 Docker scan as `v006_scan_lima_vms` (`:327-336`) already is |
| `sandboxd/src/main.rs:13327-13724` | startup block no longer builds exactly one pair; untangle the throwaway pool (`:13514-13521`) |
| `Makefile:1220, 1268, 1946, 1995, 2042` | image / route-helper staging targets gain an operator-uid dimension |
| docs | login dependency (§2.3) and logged-out reaping (§2.4) are user-visible |

**Acceptance criteria.**

- [ ] **With per-operator quotas configured**, two operators each get their own gateway
      VM, in their own LIMA_HOME, with disjoint slot ranges.
- [ ] **With default config** (no quotas), the second operator's gateway-VM create is
      refused with the **409** of §2.2 condition 2 — first-claim-wins is in force, and
      operator A's VM is neither bounced nor resized. Assert this explicitly; it is the
      behaviour a multi-operator host hits first.
- [ ] `limactl list` as operator A does not show operator B's gateway VM.
- [ ] With the orphan reaper enabled and a gateway VM running, a full reap cycle **does
      not delete it** — assert explicitly; this is the §2.6 landmine.
- [ ] Recovering operator A's gateway VM does **not** suppress operator B's per-session
      gateway monitor (the §2.6 latch).
- [ ] Creating a session for a **logged-out** operator fails with the
      `agent_not_running_error` text (`broker.rs:278`) — not a hang, not a panic.
- [ ] Killing an operator's agent mid-`limactl start` leaves recoverable state: the VM
      either exists and is usable, or is absent and re-creatable. No stranded half-state
      (§2.5).
- [ ] `cargo nextest run --workspace --profile integration` passes (Docker required).
- [ ] The §3 gate, re-run against a VM created in this new shape, still passes all four
      assertions.

---

### Phase 3 — Docker broker ops and brokered streams

**Goal.** The daemon stops talking to the operator's in-VM Docker daemon directly; typed
ops go through the agent, which composes the argv.

**Depends on.** Phase 2.

**Deliberately not split from streams.** The stream classes are the same surface as the
ops and share the serialization concern in §2.5.

**Implements.** §1.1 (the five direct `limactl` sites), §2.5, §5.2 correction 3.

**Files and functions.**

| File | Change |
|---|---|
| new leaf crate (e.g. `sandbox-docker-argv`) | zero-dependency argv builders shared by `sandbox-core` **and** `sandbox-agent`. **Do not put them in `sandbox_agent_protocol`** — §5.2 correction 3 |
| `sandbox-agent/src/protocol.rs:181-304` | new typed op variants; `op_uid()` (`:319-334`) is an exhaustive match, so a missed variant is a compile error |
| `sandbox-agent/src/handler.rs`, `validation.rs` | dispatch + per-op field re-validation |
| `sandboxd/src/broker.rs:157-170`, `:745-838` | `embed_guest_socat_token` / `take_stream_for_guest_socat` — generalise beyond `GuestSocat` |
| `sandbox-agent/src/main.rs:559`, `:682` | control loop — match over stream-class ops |
| `sandbox-core/src/lima.rs:895-899` | `LimaExecutor::guest_socat` — second method or a generalised one |
| `sandboxd/src/proxy_http.rs:277-309` | `pump_container` — brokered stream instead of `TokioCommand` |
| `sandbox-core/src/workspace_rsync.rs:195` | the `--rsh` **shell-string** shape must be covered |
| `sandbox-core/src/dns_gate_bridge.rs:164, 224, 248` | one stream open per DNS query — see §2.5 |

**Acceptance criteria.**

- [ ] No production `docker` invocation targets an operator VM's socket directly from the
      daemon.
- [ ] The op enum remains closed: **no** `DockerExec { args: Vec<String> }` or equivalent
      argv pass-through. A reviewer can enumerate every op.
- [ ] Env hygiene lives on the agent: `DOCKER_HOST` / `DOCKER_CONFIG` scrubbed,
      `-H unix://<own socket>` the sole target authority. `docker` resolved from a fixed
      candidate list, not a `PATH` search (mirror `resolve_rsync`,
      `handler.rs:935-948`, not `resolve_limactl`, `:125-143`).
- [ ] Any `sh -c` path built from daemon-supplied input is validated agent-side against an
      allowlist. The shapes to watch: `policy_distributor.rs:39-48` (no escaping of
      embedded quotes) and `macos_session.rs:786` (guarded only by a `debug_assert!`,
      compiled out in release).
- [ ] Concurrency: N concurrent lite sessions for one operator complete without
      control-connection starvation. **Measure it** — §2.5's serialization is the
      predicted failure mode.
- [ ] `make test-e2e-container` passes.

---

### Phase 4 — Typed route-helper broker op

**Goal.** Replace the `limactl shell … sudo sandbox-route-helper` argv path with a typed
op.

**Depends on.** Phase 3.

**Files.** `sandbox-agent/src/protocol.rs` — add
`InstallContainerRoute { container_pid, gateway_ip }`;
`sandbox-core/src/lite_macos.rs:262-277` — `build_in_vm_route_helper_argv` moves
agent-side; call sites `main.rs:5360-5364` and `:6091`; doc corrections in
`lite_macos.rs:241-256` and `sandbox-route-helper/src/main.rs:55-84`, `:307-318` (§5.2).

**Acceptance criteria.**

- [ ] The op carries exactly two caller-supplied values (`container_pid`, `gateway_ip`);
      VM name, `sudo`, helper path and mode flag are agent-side constants.
- [ ] Route installation works on create **and** on restart.
- [ ] The stale authorization claim ("only the daemon can reach the gateway VM's sudo
      path") is corrected in **both** files, and states what replaces the perimeter.

---

### Phase 5 — Shared-root removal (the feature #82 is named for)

**Goal.** `--workspace shared:<any operator-readable path>` works on macOS lite.

**Depends on.** Phases 2 and 3.

**Files.** `sandbox-core/src/lite_macos.rs` — delete `validate_shared_path` (`:159`),
`translate_shared_path` (`:134`, already dead in production), `SharedPathError`
(`:172-216`), `lite_shared_root` (`:76`), `DEFAULT_LITE_SHARED_ROOT` (`:54`),
`LITE_SHARED_ROOT_ENV` (`:32`), `lite_shared_root_9p_stanza` (`:110`); the call site
`main.rs:5072`; the template interpolation `gateway_lima.rs:355-356, 409-415`;
`Makefile:2110-2135` (`setup-darwin-sandbox-shared`); `docs/guides/lite-mode.md:55-95`.

**Acceptance criteria.**

- [ ] `sandbox create --lite --workspace shared:$HOME/Projects/foo` succeeds and the
      container sees the real directory.
- [ ] **Bidirectional write**: host→container and container→host, with host-side files
      landing owned by the operator. This is the coverage gap that hid the original
      defect — do not ship without it.
- [ ] **Canonicalization lands with the subtree mount** (§5.1): a `shared:` path
      containing `..` or a symlink that escapes the requested subtree is **rejected**.
- [ ] Linux lite `shared:` with an arbitrary host path is unchanged.
- [ ] Full-backend `shared:` is unchanged on both platforms.
- [ ] `docs/guides/lite-mode.md`'s macOS section matches what the code now does; the
      obsolete `SharedPathError` message and its test
      (`outside_root_error_names_cause_and_alternatives`, `lite_macos.rs:442-470`) are
      **removed**, not left asserting a refusal that no longer exists.

---

### Phase 6 — Test and docs retarget (continuous)

**Goal.** The suite stops assuming one daemon-owned gateway VM and a host Docker daemon.

**Depends on.** Runs alongside phases 1–5. Do not defer it to the end.

**Why continuous.** The surface is not a tail:

- `sandboxd-gateway` appears **34 times** across `tests/e2e/`.
- `tests/e2e/conftest.py:1062` hard-codes the singleton name in a
  **delete-everything-else** state-dir sweep — under per-operator VMs it would delete
  every operator's instance dir on every pytest session.
- Two disagreeing daemon-LIMA_HOME formulas: `conftest.py:1049` (3-level, correct) vs
  `tests/e2e/test_networking.py:1508` (2-level). Resolve; do not paper over.
- **The larger coupling:** the cross-backend suite's structural gateway assertions run
  against a **host** Docker daemon that does not exist on macOS — `conftest.py:629-638`
  (`_preflight_checks` skips the entire session when `docker info` fails),
  `test_networking.py:374`, `test_policy.py:61, 112`. Retargeting these to a
  **per-operator** forwarded socket is the real work, and is likely a bigger share of
  the estimate than the `sandboxd-gateway` string hits.
- `test_lite_macos.py:184-238` (`_gateway_vm_sees_path`) drives the VM as the **daemon**
  user and exists only to guard against a stale 9p export. Under operator-owned VMs both
  the probe and the failure mode disappear — **replace it, do not port it.**
- `test_networking.py:1765`
  (`test_macos_gateway_lima_recovery_one_session_errors_others_continue`) asserts the
  singleton's cross-session blast radius **as behaviour**. Under per-operator VMs the
  correct assertion **inverts**: operator A's gateway loss must **not** affect operator
  B. That is a new test, not a retarget.

**Acceptance criteria.**

- [ ] Issue #84 closed first — `linux_only` applied to the tests whose bodies assert on
      systemd, cgroup v2 or `sandbox-lima-helper` (`test_hardening.py:37` and
      `test_cross_user_helper_pivot.py:42` are the named candidates). Until then
      "retarget the macOS suite" is meaningless, because `make test-e2e-macos SCOPE=full`
      collects the whole Linux matrix.
- [ ] No test hard-codes a single gateway instance name in a destructive sweep.
- [ ] The two LIMA_HOME formulas agree.
- [ ] A cross-operator isolation test exists and asserts the **inverted** property.
- [ ] `make test-e2e-container` and `make test-e2e-macos SCOPE=full` pass.
- [ ] Docs updated: `docs/concepts/networking.md:265` ("A single daemon-owned Lima VM …
      hosts all gateway containers across all sessions"), `:271-273`;
      `docs/guides/macos-operations.md:82` ("One per host; shared across all operators");
      `docs/guides/lite-mode.md:56, 62`; `docs/guides/troubleshooting.md:29-32`;
      `docs/reference/cli.md:1326`; `README.md:60`; `networking-design.md:262, 283`.

---

## 5. Deltas, corrections and related issues

### 5.1 Accepted security deltas

**Workspace-axis widening — accepted, and it *is* the feature.**

Confining `shared:` to a fixed shared root structurally bounds what a container escape
can touch on the host. The entire point of this change is to let `shared:` reach real
project paths, so **an escape that reaches the operator's uid now lands on their real
working tree.** Any mechanism that makes lite `shared:` usable has this property. Record
it explicitly in two places:

- `docs/guides/hardening.md:213` — `## Security trade-offs you choose`, the only doc that
  frames deltas as operator-chosen trade-offs, alongside the existing `9p shared mounts`
  (`:215`) and `local: snapshot workspace` (`:246`) entries.
- `.tasks/specs/2026-05-02-macos-support-design.md:964-972` — § Security posture → Known
  deltas, the canonical list (currently four entries).

**⚠️ The mitigation issue #82 proposes does not currently work.** #82 offers "mount only
the requested workspace subtree, never the operator's home" as a cheap mitigation. As
written it is not a mitigation, because `validate_shared_path` (`lite_macos.rs:159-167`,
quoted in Background) is a bare `strip_prefix` with **no canonicalization** —
deliberately so, since the path may not exist yet and the function is kept pure
(`lite_macos.rs:138-142`).

Consequently `..` traversal and symlinks go unresolved. `/tmp/sandbox-shared/../../Users/alice`
passes `strip_prefix` **today** and would be handed to `docker create --mount src=…`.
**The same textual-prefix weakness would let a crafted path escape a subtree-only
mount.** Canonicalization is required for the mitigation to mean anything — with the
non-existent-path problem solved explicitly (e.g. canonicalize the longest existing
ancestor, then verify containment). This is an acceptance criterion of phase 5.

**Gateway-axis improvement — conditional, not automatic.**

#82 claims per-operator VMs shrink the blast radius from "every concurrent session" to
"every session of one operator", relative to the accepted delta at
`.tasks/specs/2026-05-02-macos-support-design.md:970`. **That is true only with slot
partitioning in place.** Without it, an operator-owned gateway VM attaches to *every*
slot — one operator's process bridging every segment on the host, including slots
carrying other operators' sessions. In that configuration the delta runs the **other
way**: worse than today, not better.

Partitioning is what makes the claimed improvement true. This is the strongest single
argument for the phase ordering in §4.

### 5.2 Corrections issue #82 needs

| # | Claim in #82 | Correction |
|---|---|---|
| 1 | "**Narrower on the gateway axis**" | Backwards as written. The improvement is **conditional on slot partitioning** (§5.1). Stated unconditionally it is wrong. |
| 2 | "Deliberately out of scope: multi-operator NIC/slot consumption … document it rather than solve it." | Untenable. Partitioning is **load-bearing for the isolation claim the issue itself makes**. It cannot be documented away. |
| 3 | "Move the argv builders into the shared protocol crate" | Mechanism right, location wrong. `sandbox-agent` **deliberately does not depend on `sandbox-core`** — a TCB boundary stated at `sandbox-agent/src/handler.rs:37-38` and confirmed by `sandbox-agent/Cargo.toml:36-59`. The Docker argv builders live in `sandbox-core` (`backend/container.rs:751` etc.) and are used **on Linux too**; putting them in the macOS-only `sandbox_agent_protocol` lib would either break Linux or force `sandbox-core → sandbox-agent`, inverting TCB minimalism. Needs a **new zero-dependency leaf crate** depended on by both. |
| 4 | "the two long-lived streams" | There are **three**. The missed one is the **DNS-gate bridge** (`sandbox-core/src/dns_gate_bridge.rs:164` → `:224` → `:248`), which opens **one `docker exec` per DNS query**. It runs `socat UNIX-LISTEN` **without** `,fork` on purpose (`:30-42`), because `,fork` would multiplex concurrent gate frames onto one stdio stream and corrupt them. It is fail-closed (`:44-54`) and sits on the egress-**allow** critical path — i.e. the core promise. Its open rate interacts directly with §2.5. |
| 5 | "a **single VM** hosting both lite workloads and the gateway containers" | Blurs two distinct VMs. An earlier evaluation of a per-operator model kept the **gateway container in the daemon-owned VM** and moved only the **lite workloads**. This design goes further — the gateway VM itself becomes operator-owned. The issue's phrasing describes neither shape precisely and should say which VM hosts what. |
| 6 | "`gateway_recovery.rs` at ~1200 lines" | The file is 1236 lines but **only `:1-396` is production code (~330 lines)**; `:402-1236` is the hermetic test module. It is a generic injectable state machine with **no** discovery logic — one of the **cheapest** parts of the migration (a ~4-item change plus a caller rewrite), not one of the expensive ones. |

**Two doc-comment corrections** fall out of the ownership change and should land with
their phase rather than rotting:

- **The authorization perimeter claim** (phase 4). `lite_macos.rs:241-256` and
  `sandbox-route-helper/src/main.rs:55-84` (repeated at `:307-318`) both assert that "the
  gateway VM is single-tenant `_sandboxd` infra — no operator user can independently
  reach its sudo path." Under an operator-owned VM that is **false** — the operator owns
  the LIMA_HOME and the SSH credentials. The root-uid gate inside the VM
  (`sandbox-route-helper/src/main.rs:329-339`) still holds, but the *stated outer
  perimeter* does not. State what replaces it: a per-operator VM means an operator can
  affect only their own VM's containers, on a kernel-isolated no-NAT segment.
- **Residual TCC framing** (phase 5). `gateway_lima.rs:351-354` (a Rust comment) and
  `gateway_lima.rs:413-414` — the latter **inside the generated Lima YAML, so it ships
  into every gateway VM's `lima.yaml`** — both restate a TCC framing that was
  deliberately corrected away from elsewhere, and which `lite_macos.rs:442-470` now has a
  test asserting the operator-facing message must **not** contain. They survived because
  they are comments, not message text.

### 5.3 Cost re-estimation

Issue #82 estimates 3–5 weeks, assuming "~11 distinct verb shapes behind three command
builders". The measured Docker surface is roughly triple:

- **15 distinct `-H unix://<sock>` injection sites across 13 files**, of which **9 are
  inline and behind no builder at all** — among them `network.rs:399, 643, 678`,
  `dns_propagation.rs:307`, `lds_ack.rs:190`, `main.rs:9566, 10372`, plus a cluster in
  `gateway_lima.rs` (`:1027, 1065, 1160, 1190, 1453, 1508, 1975, 2017, 2051, 2230`).
- **6 named prefix builders, not three** — `container.rs:516`, `:531`, `:1619`;
  `gateway.rs:380`; `macos_session.rs:90`; `policy_distributor.rs:23` — plus two
  near-duplicate funnels in the orphan reaper (`orphan_reaper.rs:449`, `:494`).
- **13 distinct top-level verbs**, **~35 distinct argv shapes**, and **three coexisting
  assembly idioms**: fluent `Command::args([...])` chains, pure `Vec<String>` builders,
  and **one assembled as a shell string** — `format!("docker -H unix://{sock} exec -i")`
  passed as rsync's `--rsh` transport (`workspace_rsync.rs:195`), which rsync re-parses
  as a shell word list.
- **Two shapes that do not fit a plain request/response op**: stdin-fed one-shots
  (`nft -f -` at `gateway.rs:1307`; `sh -c 'cat > path'` at `policy_distributor.rs:512`,
  `macos_session.rs:788`, `atomic_listener_writer.rs:410`), which put multi-KB
  JSON-escaped file bodies on a newline-delimited JSON channel; and the three long-lived
  streams (§5.2 correction 4).

**Do not invent a replacement number.** The bucket most likely to be under-scoped in the
original estimate has measurably more surface than the estimate assumed. Re-estimate
against these figures **after** the gate, when phase 3's shape is actually decided.

Two counterweights, for honesty: `gateway_recovery.rs` is far cheaper than #82 suggests
(correction 6), and the `op_uid` routing change in §1.1 is free.

### 5.4 Related issues

| Issue | Bearing |
|---|---|
| **#83** — gateway-VM recovery skips container-backend sessions (`gateway_recovery.rs:77-82`) | **Blocks bounce-to-resize** (§2.7). Bouncing an operator's VM kills their lite sessions and those are never recovered — containers are `--restart no` (`container.rs:853-854`). |
| **#84** — `linux_only` declared and enforced but applied to zero tests | **Phase 6 depends on it.** `make test-e2e-macos SCOPE=full` currently collects the whole Linux-authored matrix on macOS. Close it first. |
| **#85** — `make setup-dev-env` regenerates vmnet plists referencing an account only `install.sh` creates | **Actively dangerous, and directly in phase 0's path.** See [Before you start](#before-you-start). The failure is deferred to the next boot and takes the whole vmnet pool down. |

---

## Open questions

Do not invent answers to these. Raise them.

*Previously open, now decided: the quota model. Resolved 2026-07-30 as first-claim-wins
with an explicit 409 for a second operator — the decision lives in §1.3, its error
shapes in §2.2, and its acceptance criteria in phases 1 and 2.*

1. **Range persistence location** (§2.1) — `sessions.db` (refinery migration or
   `Option<T>` + `#[serde(default)]` blob field) versus a daemon-written file under
   `{state_root}/{daemon_uid}/{op_uid}/`. Both are daemon-owned and both satisfy the
   trust requirement; the trade is schema-evolution cost versus a second persistence
   mechanism. **Blocks phase 1.**
2. **Gate harness language and location** (§3.10) — shell under `tests/`, Python outside
   the pytest suite, or a Rust `integration_*` test. The rendering-drift argument favours
   Rust. **Blocks phase 0.**
3. **Does `interface:` pinning work for `socket:` networks?** (§1.4, pre-check A) — the
   highest-value pre-check. Evidence is structural and converging, not observed. A
   negative answer changes phase 1's approach but not the design's direction.
   **Answered by phase 0.**
4. **Per-operator gateway VM naming scheme** (§2.6) — undecided, and a correctness
   constraint rather than a cosmetic one: whatever is chosen must provably fail
   `parse_session_id_from_name` (`lima.rs:4202`) **and** carry an explicit reaper
   exclusion, so the VM does not survive only by name-shape accident as it does today.
   **Blocks phase 2.**
5. **Which second uid plays "operator B" in the gate's second-operator probe** (§3.7) —
   it must be enrolled in the vmnet socket group and able to run `limactl`. On the
   reference host the candidate uids qualify against the *currently installed* plists,
   but those plists are stale and issue #85 means the obvious remediation takes the pool
   down. Settle the gate's environment prerequisites before writing it.
   **Blocks phase 0.**

---

## Appendix — file index

Everything this design touches, in one place.

| Area | Location |
|---|---|
| Gateway VM manager | `sandboxd/sandbox-core/src/gateway_lima.rs:771-2272` |
| Gateway instance name (singleton) | `gateway_lima.rs:84` (+14 use sites) |
| Gateway template generator | `gateway_lima.rs:334-381` |
| NIC discovery / slot→iface map | `gateway_lima.rs:282-316` |
| LIMA_HOME env coupling | `gateway_lima.rs:672` |
| Pool-resize decision | `gateway_lima.rs:2287-2378` |
| Egress bridge name | `gateway_lima.rs:89` |
| vmnet pool | `sandbox-core/src/network.rs:1090-1421` |
| Slot addressing / identifier / socket / plist | `network.rs:858, 897, 954, 965, 999` |
| Exhaustion errors | `network.rs:1161-1176, 1208-1213` |
| Inter-slot L2 isolation test | `network.rs:3021` |
| Error → HTTP mapping | `sandboxd/src/error.rs:57-79` |
| Lima executor seam / op enum | `sandbox-core/src/lima.rs:870-899`, `:766-810` |
| Per-operator LIMA_HOME + ACE | `lima.rs:214-223`, `:574-660` (rationale `:601-610`) |
| Manager registry precedent | `lima.rs:1245-1280` |
| Lima orphan reaper | `lima.rs:250-558`; name parse `:4202-4205` |
| Broker uid branch / direct path | `sandboxd/src/broker.rs:1688`, `:1962` |
| Agent-not-running error | `broker.rs:278` |
| Agent registry / eviction | `broker.rs:629-658` |
| Connected-uid gating precedent | `broker.rs:680-683`, `:1202-1205` |
| Broker op enum | `sandbox-agent/src/protocol.rs:181-334` |
| Gateway recovery state machine | `sandbox-core/src/gateway_recovery.rs:1-396` |
| macOS gateway container args | `sandbox-core/src/macos_session.rs:567-640` |
| macvlan parent / segment binding | `macos_session.rs:137-165` |
| nft ruleset generator | `sandbox-core/src/gateway.rs:1616` (ports `:248-276`) |
| Envoy listener writer | `sandbox-core/src/atomic_listener_writer.rs:384` |
| CoreDNS policy path | `sandbox-core/src/policy_distributor.rs:151` |
| DNS-gate bridge | `sandbox-core/src/dns_gate_bridge.rs:164, 224, 248` |
| Lite shared root + validation | `sandbox-core/src/lite_macos.rs:32, 54, 76, 110, 134, 159` |
| In-VM route-helper argv | `lite_macos.rs:262-277` |
| Startup block (pool + manager) | `sandboxd/src/main.rs:13327-13724` |
| NIC-name fallback sites | `main.rs:4362-4370`, `:9884-9896`, `:12811-12820` |
| Max-sessions parse | `main.rs:13403-13440` |
| Gateway image healthcheck | `networking/gateway/Dockerfile:148, 174` |
| CoreDNS upstream default | `networking/gateway/entrypoint.sh:304` |
| Block-exit-code set (e2e) | `tests/e2e/test_lite_macos.py:410` |
| Canonical macOS spec | `.tasks/specs/2026-05-02-macos-support-design.md` |
