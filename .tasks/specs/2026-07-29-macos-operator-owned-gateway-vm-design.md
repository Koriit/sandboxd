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
- **⚠️ §1.6 documents an active, exploitable defect on `master` that has no tracker
  issue** — this spec is its only record. If you read nothing else, read that. Its fix is
  independently shippable ahead of the rest of this design.
- **[Open questions](#open-questions)** is empty — every design question is decided. What
  it holds is a trail of those decisions and where each one lives, plus a short list of
  facts still to be **verified** (not chosen), each with a 30-second check.

Every claim cites a `file:line` in this repository. Line numbers are against `master`
@ `7e5fa0c`. Where a line may have moved, the code is quoted inline so you can
recognise it.

**One claim is still marked ⚠️ UNVERIFIED** (§2.7, `cidata.iso` regeneration). It is
flagged at its point of use with a check you can run in under a minute. Do not build on
it without running that check.

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
(`network.rs:989-992`):

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
is read from the environment at exactly one place (`main.rs:13402-13440`):

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
sets `minimumLimaVersion` (`gateway_lima.rs:390`, constant at `:99`).

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

**This warning has a resolution path — it is not a permanent dead end.** Repairing the
host per issue #85 (create the real `_sandboxd` account, regenerate the vmnet plists
correctly, reload) is what makes `make setup-dev-env` safe to run again. Do that rather
than working around it.

**That repair is also a prerequisite for part of phase 0.** The second-operator isolation
probe (§3.7) needs a purpose-made test-operator account in the **correct** group. Adding
another member to Apple's reserved `_sandbox` (gid 60) was considered and **rejected** —
it deepens exactly the problem #85 describes. Fix #85, then create a dedicated
test-operator account in the proper group.

**The single-operator half of the gate does not need any of this** and can proceed on the
host as it stands.

### Gateway VM state

**⚠️ Resolve `<daemon_uid>` before using it — it is not obvious and picking wrong is
destructive.** The obvious command fails on a host that has not run `install.sh`, and the
reference host has **two** candidate trees:

```bash
$ ls -ld /var/lib/sandboxd/*/
drwxr-x---  _sandboxd-test  _sandboxd-test  /var/lib/sandboxd/309/    # e2e harness daemon
drwx------  olek            staff           /var/lib/sandboxd/501/    # a daemon that ran as the operator
```

**Resolution procedure:**

```bash
# 1. The production daemon account, if install.sh has run:
dscl . -read /Users/_sandboxd UniqueID 2>/dev/null

# 2. Otherwise pick by which tree you mean, and be deliberate:
#    <uid> of the account the daemon you are targeting runs as.
ls -ld /var/lib/sandboxd/*/
```

**Do not put a throwaway VM in the e2e harness's tree.** `tests/e2e/conftest.py:1049-1062`
sweeps that subtree destructively on every pytest session, preserving only a hard-coded
keep-list. A gate VM created under the harness daemon's uid will be deleted out from under
you by an unrelated test run.

The gateway VM is often stopped; egress work needs it running:

```bash
export LIMA_HOME=/var/lib/sandboxd/<daemon_uid>/<op_uid>/lima
limactl list --json | grep sandboxd-gateway
```

Note the **3-level** path (`state-root / daemon-uid / operator-uid / lima`). Several
2-level forms exist in the tree and in user-facing docs, and all are wrong — see phase 6.

### This is macOS-only code

`VmnetPool`, `GatewayLimaManager`, `generate_gateway_template`,
`discover_nics_from_ip_json` and the NIC-name sites are all `#[cfg(target_os = "macos")]`.
On a Linux box, `cargo build --workspace`, `cargo clippy --workspace` and `make test`
compile and lint **none** of it — they will pass without having checked anything you
changed. Work on a Mac, and read every phase-1 build criterion as "on macOS".

### What "unverified" means here

**One** claim this design leans on is still reasoned from Lima's source rather than
observed: that `cidata.iso` regenerates on **every** VM start, not only the first. It is
flagged ⚠️ at its point of use (§2.7) and pre-check B in §3.1 settles it in 30 seconds.

Its sibling — whether Lima honours a per-entry `interface:` key on `socket:` networks —
**has been verified** and is no longer an assumption; see §1.4 fix 1 for the evidence.

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
property **re-proven before** the migration work, not after — and that work is now known
to be larger than issue #82's three-to-five week estimate (§5.3).

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
model, so partitioning is designed here rather than documented away.

**But be precise about what partitioning buys.** It removes the *addressing collision*
above. It does **not** by itself make the isolation claim in §5.1 true — every enrolled
operator can open every slot socket regardless of who the daemon thinks owns it. That is
§1.6's job, and §1.6 is an active defect record, not a refinement. An earlier draft
credited partitioning with the isolation property; it partitions the ledger, not the
kernel's access control.

### Phase map

| Phase | Goal | Gated on |
|---|---|---|
| **0** | Pre-checks + egress validation gate | Part A: nothing. **Part B (isolation probe): issue #85 fixed first** |
| **1** | Per-operator slot partitioning **and socket groups** | starts on 0 Part A green; **completes** on Part B green |
| **2** | Docker broker ops + brokered streams | 1 |
| **3** | Typed route-helper broker op | 2 |
| **4** | Per-operator gateway VM ownership | **2 and 3 — hard boundary** |
| **5** | Real `shared:` workspaces — *the feature #82 is named for* | 4. **Not #83** — declared export roots bounce the VM only on a root change, not per create |
| **6** | Test and docs retarget | runs continuously across 1–5; **phase 4 depends on it**; gated on #84 |

**⚠️ Ownership moved from phase 2 to phase 4.** The forwarded Docker socket lives inside
the operator-owned instance directory, so the daemon loses Docker access the instant
ownership flips — the brokered control plane has to exist first. Full reasoning, and the
per-phase detail, in [§4](#4-phases).

---

## 1. Ownership model and slot identity

### 1.1 Per-operator gateway VM, driven through the broker

Each operator gets their own gateway Lima VM in their own `LIMA_HOME`, with every
control-plane operation routed through the existing operator-execution seam.

Three things make the *routing* cheaper than it looks:

- **The uid branch already exists.** `AgentBrokerExecutor::run` (`broker.rs:1688`,
  quoted in Background) dispatches on the uid, so a real operator uid reaches the
  broker without touching the executor.
- **The path formula already generalises.** `operator_lima_home(op_uid)`
  (`lima.rs:214-223`) already takes an operator uid; the gateway's path is the
  degenerate case of a general formula.
- **The registry shape already exists in-tree.** `LimaManagerRegistry`
  (`lima.rs:1245-1280`) is a `Mutex<HashMap<u32, Arc<LimaManager>>>` keyed by operator
  uid, monotonically growing. **Copy its locking discipline** — one `Mutex<HashMap<u32, …>>`,
  lock held only across lookup/insert, monotonic growth — **not its fields.** It carries
  an executor, `base_vm_name`, `owner_pool`, `is_macos` and an injected
  `provision_lima_home` closure; a `VmnetPoolRegistry` needs none of those and would
  inherit five dead fields.

### 1.1a ⚠️ The agent rejects gateway ops — "no code change" is false

**An earlier draft of this spec claimed that changing the uid argument was "most of the
ownership change" and that the routing was free. That is wrong, and the correction is
load-bearing enough to have its own subsection.**

The agent independently re-validates every op before executing it. Today the gateway VM
takes `run_limactl_direct`, which skips all of it, and the code says so at
`gateway_lima.rs:1320-1324`:

```rust
// The gateway VM is daemon infrastructure; it always runs as the
// daemon uid and goes through run_limactl_direct, bypassing the
// agent's socket_vmnet check.
is_hardened_session: true,
```

Flip the uid and **four** validators fire:

| # | Validator | What the gateway sends | Result |
|---|---|---|---|
| 1 | `validate_cidr_owner("owner", …)` (`handler.rs:416`, `validation.rs:196`) | `owner: ""` (`gateway_lima.rs:1327`) | rejected — empty is not `a.b.c.d/n` |
| 2 | `validate_networks_entry` — **exactly one** entry (`validation.rs:506-511`) | N entries, one per slot | rejected |
| 3 | same — each entry must have **exactly one key**, `socket` (`validation.rs:541-547`) | §1.4 fix 1 adds `interface: lima<n>` | rejected |
| 4 | `validate_qemu_wrapper`, unconditional in `handle_start` (`handler.rs:512`) | `qemu_wrapper: Path::new("")` (`gateway_lima.rs:1367`) | rejected — must be absolute |

Row 3 is the trap: **phase 1's fix 1 and the ownership phase are in direct conflict, and
phase 1 cannot detect it**, because phase 1 still runs on the direct path. Fix 1 would
ship green — with a unit test asserting the `interface:` key on every entry — and the
conflict would surface only when ownership flips.

**This is a TCB-boundary change, not a detail.** `validate_lima_yaml_shape`
(`validation.rs:363`) states its own purpose at `:346-353`: *"this is the egress-control
boundary: a bypass here defeats sandboxd's core unbypassable-egress promise."* The
function is shared with session VMs, where "exactly one socket entry, no other keys" is
what stops a compromised daemon booting a sandbox VM with a second NIC.

**Required approach — split the validator by VM class, do not relax it in place.**

- **Session-VM rule: unchanged.** Exactly one entry, exactly one `socket` key.
- **Gateway-VM rule: new, and stricter than a simple relaxation.** N entries; each entry
  exactly `{socket, interface}`; and **`interface` must equal `lima<n>` where `n` is
  parsed from the socket path's `slot-<n>.sock`**.

That last clause is the valuable part: it moves §1.4 fix 1a's invariant from *"the
generator promises"* to *"the agent, which does not trust the daemon, checks"* — the one
place a compromised daemon cannot skip. Rows 1 and 4 need gateway-shaped variants too
(an empty `owner` and an empty `qemu_wrapper` are legitimate for this VM class).

**Do not describe this as free.** State what the validator must still guarantee, class by
class, and review the split on its own terms.

*Mitigating context, not a reason to skip it:* with per-operator socket groups (§1.6) the
**OS** enforces what this validator approximates, so a gateway VM that lies about its
`interface:` mapping can only reach sockets its owner may open anyway. The validator
becomes defence in depth rather than the sole control. That makes the split less alarming
— it does not make it optional.

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

`LimaOp` (`lima.rs:766-837`) has **no `shell` or `copy` variant**. These become either
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

**Addressing is inherited for free; isolation is not.** Both
`vmnet_slot_network_identifier` (`network.rs:897`) and `vmnet_slot_addresses`
(`network.rs:954`) are pure functions of slot index, so slots 4–7 keep distinct L2
segments and distinct `/29`s regardless of who consumes them. That removes the
*addressing collision* described in [Decision and sequencing](#decision-and-sequencing).

**It does not remove the exposure, and the exposure is a live defect.** Every enrolled
operator can open every slot socket on `master` today, so the pool assignment described
above is **daemon-side bookkeeping, not an access control**. On a host with two or more
enrolled operators that is exploitable now, and the consequence is that one operator can
void another's egress policy.

An earlier draft of this spec filed that fact as a cost saving — "no privileged work
needed, the sockets are already reachable by every enrolled operator". That is backwards:
it stated the vulnerability and counted it as a benefit.

**§1.6 carries the full defect record** — mechanism, impact, fix and test. **It is not
filed as a tracker issue, so that section is the only record**, and its fix is
independently shippable ahead of the rest of this design.

### 1.3 Range assignment, lifetime and quota

- **Assigned at operator enrollment**, which writes root-owned state (the slot plists'
  group and that group's membership). Not claimed at VM creation, not released at VM
  deletion.
- **Derived by the daemon, not stored by it** — the daemon reads the assignment back off
  the running sockets rather than from a config file or a database. See *How the daemon
  learns a range* below, and §2.1 for what it consequently does **not** persist.

**⚠️ This section reverses an earlier decision.** Ranges were previously claimed at VM
creation and persisted by the daemon. §1.6 moves the enforcement into root-owned static
configuration, and the assignment has to live where the enforcement lives.

**Ranges are assigned at operator enrollment, not claimed at VM creation.** Enrollment is
already a privileged, one-time act — it is when the operator is added to the group that
lets them reach sandboxd at all — and §1.6 makes it the moment the per-operator socket
group and its slot set are created. The daemon does not allocate ranges; it *reads* them.

**Default: a single-operator host gets the whole pool.** It must behave **exactly** as it
does today — same 8 concurrent sessions, same slot indices, same segments. Without that
default, partitioning is a straight concurrency regression: 8 slots across 2 operators
caps each at 4; across 4 operators, at 2.

**Multi-operator is opt-in and privileged.** Enrolling a second operator with a disjoint
range is installer work, not daemon work. In this version there is **no automatic
rebalancing, no lazy claiming, and no bouncing of an existing operator's VM to make
room.** (Bounce-driven rebalancing is a plausible future enhancement and is explicitly
out of scope — §2.7.)

**Adding an operator therefore becomes a privileged operation**, in the same class as
pool growth, which `decide_pool_resize`'s `RefuseNeedsPrivilegedRegen` arm
(`gateway_lima.rs:2287-2378`) already routes to the installer. This is a real cost and it
should be stated rather than discovered: the earlier draft sold "no privileged work" as a
benefit of partitioning, and §1.6 is why that is no longer true.

**How the daemon learns a range: it derives it from the live sockets.** No config file, no
new ingestion path. At startup and on demand, the daemon `stat`s each
`/var/run/sandbox/vmnet/slot-N.sock`, reads its **gid**, and resolves which operator is a
member of that group. That mapping *is* the operator's range.

**Why derivation beats a config file.** This is §2.1's reasoning taken to its conclusion:
read the strongest available authority. Here that authority is root-owned and
kernel-mediated — the same bits the kernel itself checks on `connect(2)`.

- **It cannot drift from enforcement, because it *is* the enforcement.** A config file
  stating a range is a second copy that can disagree with the plists; the socket's gid
  cannot disagree with itself.
- **It self-heals in the #85 scenario.** When installed plists and running sockets
  disagree — exactly what #85 produces, silently, until a reboot — the daemon sees **what
  is actually running**, not what someone intended.
- The daemon needs only traverse on `/var/run/sandbox/vmnet/` to `stat` the sockets, which
  it already has; it does not need to open them.

**Misconfiguration must have a defined response, not an assumption.** Two cases:

| Slot's group contains | Response |
|---|---|
| **zero** operators | The slot is **unassignable**. Not a startup failure — a partially-enrolled host is a normal state — but log it and surface it in diagnostics, because it is silently lost capacity. |
| **more than one** operator | The slot is **unassignable**, and this is the loud case. Two operators sharing a slot group is the §1.6 defect in miniature: assigning the slot to either would give the other undetectable access to it. **Refuse to assign it and surface it prominently.** Do not pick one. |

Both cases mean a slot that exists and is running but is claimed by nobody, which is the
correct fail-closed behaviour: capacity is lost, isolation is not.

**A second operator with no assigned range fails explicitly.** This is a *configuration
conflict*, not a capacity ceiling; §2.2 gives the two error shapes and why they must not
be conflated. The error must state how many slots the pool has, that none are assigned to
the requesting operator, and the remediation — **enroll the operator with a slot range**.
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

#### Fix 1 — pin identity with Lima's per-entry `interface:` key ✅ CONFIRMED

```yaml
networks:
  - socket: /var/run/sandbox/vmnet/slot-6.sock
    interface: lima6
  - socket: /var/run/sandbox/vmnet/slot-7.sock
    interface: lima7
```

**Verified empirically** on Lima 2.1.2 / socket_vmnet 1.2.2, unelevated as an ordinary
operator uid in a throwaway LIMA_HOME.

**Baseline** — one network on `slot-6.sock` with **no** `interface:` key. The guest
reports the positional name, reproducing the hazard exactly:

```
3: lima0: ... link/ether 52:55:55:ec:c3:59
```

**Test** — two networks pinned non-positionally, using the YAML above:

```
3: lima6: ... link/ether 52:55:55:fc:23:77
4: lima7: ... link/ether 52:55:55:f3:cb:4b
```

`limactl validate` returns OK with no warning; the key survives into the effective
`lima.yaml` and into cloud-init's netplan as `set-name:`, keyed by MAC.

**It is a real binding, not a relabel.** This matters — "the name sticks" alone would not
have been sufficient evidence, because a name that stuck while pointing at the wrong
socket is precisely the failure this fix exists to prevent. Lima dials each socket itself
and hands QEMU the fd, so correlating fds via `lsof` gives an end-to-end chain, and it
agrees at every hop:

| fd | QEMU netdev | MAC | guest name | peer socket |
|---|---|---|---|---|
| 3 | `net1` | `52:55:55:fc:23:77` | `lima6` | `slot-6.sock` |
| 4 | `net2` | `52:55:55:f3:cb:4b` | `lima7` | `slot-7.sock` |

So an offset range behaves exactly like a contiguous one from slot 0, and the slot→NIC
translation layer that would otherwise have been needed is **not** required.

⚠️ **What this does *not* establish.** The check drove `limactl` **directly**, in a
throwaway LIMA_HOME — which is *not* the path the ownership phase routes through. The
Lima behaviour is confirmed; the **end-to-end path is not**, and §1.1a explains why it
currently fails: the agent's `validate_networks_entry` rejects any entry carrying a second
key, which is exactly what `interface:` is. Re-run this check **through the broker** as
part of the validator-split work before treating the path as proven.

⚠️ **Version floor.** The template declares `minimumLimaVersion: "1.2.0"`
(`gateway_lima.rs:99`); the check ran on **2.1.2**. Nothing establishes that 1.2.0 honours
`interface:`, and an older Lima that ignores an unknown key yields positional names on a
non-positional range — the exact silent wrong-segment failure this fix exists to prevent.
Note that **fix 1a would not catch it**: the generator asserts what it *emits*, not what
Lima *honours*.

**This is already closed by fix 2, not left open.** Fix 2 requires the daemon to build the
`NicMap` itself and use `ip -json link show` only to *verify* that each expected interface
is present, failing closed on a mismatch — so an older Lima that ignored `interface:`
produces a refused create rather than a silently misplaced session. Bumping
`MIN_LIMA_VERSION` above 1.2.0 remains available as cheaper, earlier hardening (it fails at
template validation instead of at NIC discovery), but it is **optional**: the hazard has a
mandated backstop either way. An earlier draft framed this as an unresolved either/or,
which double-counted a decision fix 2 had already made.

#### Fix 1a — the generator must now guard the invariant itself

The confirmation comes with an obligation. **Lima honours whatever name you ask for and
never warns about a non-positional one** — `limactl validate` passed on names that do not
match array position, and it would equally pass on `interface: lima2` sitting on
`slot-7.sock`.

That means the `lima<N>` ⇔ slot N correspondence stops being something Lima enforces and
becomes **the generator's responsibility**. Left implicit, it is exactly the same species
of accident as the reaper exclusion in §2.6: a property that currently holds, that
nothing checks, and whose violation is silent and routes traffic onto the wrong L2
segment.

**Requirement:** `generate_gateway_template` must emit
`interface == format!("lima{slot}")` for **every** entry, and a unit test must assert it
for every emitted entry rather than spot-checking one. Replace the accidental invariant
with a deliberate one.

**And assert it agent-side too.** The generator's assertion binds only a daemon that is
behaving. §1.1a's gateway-class validator re-derives `n` from the socket path's
`slot-<n>.sock` and requires `interface == lima<n>` — the same invariant, checked by the
component that does not trust the daemon. Put it in both places; they fail differently and
the agent-side one is the one a compromised daemon cannot skip.

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

**This fix stands on its own terms and is not contingent on fix 1.** Now that pinning is
confirmed, threading the slot explicitly through the parser is no longer a *fallback* for
a missing Lima feature — it is simply correct. The parser claims to build a slot→interface
map and instead builds a position→interface map; those coincide only while the range is
contiguous and zero-based. Fix it because it is wrong, not because something else failed.

**⚠️ But do not stop at re-keying — the input is operator-controlled.** `discover_nics`
(`gateway_lima.rs:1482-1495`) obtains this JSON by running `ip -json link show` **inside
the gateway VM**. After ownership flips, that VM is the operator's, so the string this
parser trusts is operator-supplied — and the map it produces selects the macvlan parent,
i.e. **which L2 segment the session lands on** (`macos_session.rs:158-165`), persisted as
`NetworkInfo.bridge_name` (`main.rs:4373`).

Re-keying by suffix actually *increases* that trust: today the guest string merely orders
a list; afterwards it directly selects the segment. This is the same species of problem as
§2.1 reason 2 (*"the operator can write that file"*), which this design caught for
`lima.yaml` and missed here.

**Required shape:** the daemon already knows the answer — it rendered the template with an
explicit slot set and fix 1a pins `interface: lima<slot>`. **Construct the `NicMap`
daemon-side from the assigned slot set**, and use `ip -json link show` only to *verify*
that each expected interface is present, failing closed on any mismatch. Never derive the
mapping from guest output. (That verification also covers the `MIN_LIMA_VERSION` hazard
above: an older Lima that ignored `interface:` fails the check instead of silently
misplacing the session.)

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

All three must take a slot set (`&[u16]`).

**Call sites: 15, not seven.** One production (`create_instance`, `gateway_lima.rs:1286`)
and **14 in tests** across 13 test functions (`gateway_lima.rs:2556, 2570, 2585, 2593,
2603, 2616, 2629, 2655, 2664, 2677, 2686, 2695, 2708, 2744` — `:2585` and `:2593` are both
inside `template_contains_correct_socket_count`). An earlier draft said "six unit tests",
which under-scoped phase 1's most invasive signature change by more than 2×.

**Where the slot set comes from — resolving a contradiction in earlier drafts.** Two
incompatible designs were asserted simultaneously: "derive from the pool at call time, not
snapshotted at construction" (here and §1.5) versus "the manager carries a slot *set*"
(§1.5). The second is a snapshot; the first forbids one. Neither fits the code as it
stands: `GatewayLimaManager` holds no pool — only `max_slots: u16` copied in `new()`
(`gateway_lima.rs:786`, `:813`) — and `create_instance(&self)` takes no arguments.

**Decision: pass the slot set as an argument.** `create_instance(&self, slots: &[u16])`,
supplied by the caller from the operator's assigned range at the moment of the call. It is
neither a constructor snapshot nor a pool reach-in: the manager stays ignorant of the pool,
which keeps §1.5's hazard structurally impossible rather than merely discouraged. The cost
is threading the argument through `ensure_ready` (`gateway_lima.rs:872`) and its three
startup call sites — which the ownership phase touches anyway.

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

If the map lookup misses, the session's macvlan is parented on a **guessed** interface.
Under partitioning a miss attaches the session to the **wrong segment** instead of
failing.

**⚠️ The three sites are not the same guess — an earlier draft said they were, and
hard-erroring all three would cause a regression.**

**Create (`main.rs:4369`) and recovery (`main.rs:12819`) are bare guesses.** Hard-error
both.

**Restart (`main.rs:9894-9900`) is not.** It falls back to the *persisted* value first:

```rust
.unwrap_or_else(|| {
    if network_info.bridge_name.is_empty() {
        format!("lima{slot_idx}")
    } else {
        network_info.bridge_name.clone()
    }
})
```

`NetworkInfo.bridge_name` was written at create time from the authoritative NIC map
(`main.rs:4373`). Reading the durable record is **correct**, not a coincidence — and
`nic_map()` returns `None` until `ensure_ready` completes (`gateway_lima.rs:833`), so
hard-erroring here breaks restart whenever the map is merely not yet populated. **At the
restart site, hard-error only when the persisted `bridge_name` is also empty**, and state
which source wins when the map and the record disagree. (Recommendation: the persisted
record, because it is what the session's existing macvlan is actually parented on;
disagreement is a signal to refuse, not to re-parent a running session.)

**The real silent guess is one line above, at two of the three sites, and no earlier draft
mentioned it:**

```rust
let slot_idx = network_info.vmnet_slot.as_ref().map(|s| s.index).unwrap_or(0u16);
```

(`main.rs:9884-9888` restart, `main.rs:12811-12816` recovery.) This defaults **the slot
index itself** to 0 when a session carries no `vmnet_slot`. Under partitioning slot 0
belongs to whichever operator holds the range containing it, so a session with missing slot
state is recovered **onto another operator's segment** — a strictly worse outcome than the
NIC-name guess this fix was written for. **Hard-error it.**

**Make these hard errors regardless of whether the rest of this design proceeds.**
Silently guessing an L2 parent interface — or an L2 *segment* — in the egress-control path
should not have a fallback: the guess is only ever right by coincidence, and the failure
mode is silent misplacement rather than a refused create.

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
- **partitioning makes the slot *set* rather than a count the thing that must reach the
  template**, at which point a stale value stops being a wrong number and becomes a
  **wrong set of L2 segments**.

Hence fix 3 above, which resolves it by passing the set as an argument — so there is no
stored copy to go stale. The justification is prevention.

*(A sibling of the same kind, also out of scope: `start_instance` passes
`memory_mb: 2048, cpus: 2` as literals at `gateway_lima.rs:1372-1373` rather than reading
`GATEWAY_VM_CPUS` (`:111`) / `GATEWAY_VM_MEMORY_MB` (`:118`). **The literals currently
match the constants**, and `template_cpus_and_memory_match_published_constants`
(`:2569-2579`) pins the constants — so this is latent drift, exactly the category this
section insists must not be mislabelled. An earlier draft called it "a genuinely active
sibling defect" four lines after arguing against precisely that error. It is not active.)*

### 1.6 Per-operator socket groups — what makes the partition real

> ### ⚠️ ACTIVE DEFECT ON `master` — and this document is its only record
>
> **There is no tracker issue for this.** It was found during the review of this design
> and deliberately recorded here rather than filed, so §1.6 has to carry the whole
> analysis: the mechanism, the impact, the fix, and how to test it.
>
> **Status: exploitable today**, on any host with two or more enrolled operators, against
> `master`. It is **not** introduced by this design — see *Provenance* below. If you are
> reading this after the migration landed, do not conclude the operator-owned VM work
> caused it.
>
> **Impact:** an operator can place themselves on another operator's isolated L2 segment
> and become the next hop for that operator's sandbox traffic. **The victim's egress
> policy is void** — traffic leaves through the attacker's unfiltered uplink instead of
> the victim's gateway container, and their TLS is terminated by the attacker. Nothing in
> the victim's session, in the daemon, or in the deny-event stream reflects it. That is a
> direct failure of the project's stated core promise.
>
> **The fix in this section is independently shippable.** Per-operator socket groups plus
> enrollment-time range assignment depend on **nothing else** in this design — not on
> ownership, not on the brokered control plane, not on the gate. They can land ahead of
> the rest of the migration as a standalone fix, and on a multi-operator host they
> probably should. Everything else here is sequencing; this part is not.

**The mechanism.** `generate_vmnet_plist` (`network.rs:999`) hardcodes one group for every
slot (`network.rs:1027`):

```
--socket-group=_sandboxd \
```

and `scripts/install.sh:2679` enrols every operator in that same group
(`dseditgroup -o edit -a "$_OPERATOR" -t user _sandboxd`). There is no operator dimension
anywhere in the plist — the only per-slot variation is the label, the socket path and the
network-identifier UUID. `docs/concepts/networking.md:301` says it plainly: the group
*"restricts socket access to the daemon and enrolled operators."* **All operators, all
slots.**

The canonical macOS spec confirms there is no second gate: the slot sockets have *no*
application-layer check, because `socket_vmnet` is a byte pump — the group bit plus the
`0750` directory traversal **is** the control.

**Why that is sufficient to break isolation.** A slot socket is the *entire* admission
control for its L2 segment. Anything that can `connect(2)` to `slot-N.sock` becomes a
peer on segment N — a `socket_vmnet` client is just a process speaking a framing protocol,
so this needs neither a VM nor sandboxd's cooperation. The victim's sandbox VM and its
gateway container are both addressable on that segment, and the sandbox VM's default route
points at the gateway container's IP; ordinary L2 address-resolution behaviour is enough
for a same-segment peer to be believed as that next hop.

**The consequence, stated without softening:** the victim's traffic can be made to leave
through the attacker's uplink instead of the victim's gateway container. **The victim's
egress policy is void, and their TLS is terminated by the attacker.** The victim's
session, the daemon, and the deny-event stream all continue to look normal, because no
traffic reaches the enforcement point that would have logged it.

**Provenance — pre-existing, not introduced by this design.** An operator can do this on
`master` today. Nothing about the operator-owned VM work creates it. Two things change,
which is why this design must fix it rather than inherit it:

1. **The design claimed to close it.** §5.1's gateway-axis improvement was stated as
   "true with slot partitioning in place". Partitioning the daemon's ledger does not
   partition the kernel's access control.
2. **After ownership flips, the operator's routine configuration surface becomes the file
   that decides which segments their VM joins.** §2.1 reason 2 makes exactly this argument
   about `lima.yaml` — and then applies it only to range *recovery*, never to range
   *enforcement*.

**Decision: slot plists carry a `--socket-group` naming only the owning operator, and
slot ranges are assigned at operator enrollment (§1.3).**

Each slot's launchd plist is generated with a group that only its assigned operator
belongs to, so the kernel refuses a connect from anyone else. Equivalently the socket may
live in a per-operator directory at `0750 root:<opgroup>`; either binds slot→operator in
**root-owned state**.

**Why it has to be static, privileged configuration.** The sockets are created by root
launchd daemons, and `/var/run` is cleared on every boot, so the plist preamble recreates
the directory from scratch each time. The daemon is unprivileged by design — the whole
privilege model in `CLAUDE.md` rests on it — so it can neither `chgrp` a socket nor change
group membership at runtime. **The control cannot live in the daemon.** That is not a
limitation to work around; it is why this is the right layer.

**Benefit worth stating.** Who can reach which segment becomes readable straight off the
filesystem — `ls -l /var/run/sandbox/vmnet/` and `dscl . -read /Groups/<opgroup>` answer
it completely — and is auditable by anyone with shell access, rather than being runtime
state inside a daemon process.

**Costs, stated plainly.**

- Quota changes become privileged installer work (§1.3).
- The plist generator gains an operator dimension it does not have today, and the
  installer must keep three things in step: the plist's group, the group's membership,
  and whatever the daemon reads to learn the range.
- `make setup-darwin-vmnet-plists` and the `install.sh` plist path both change, in a
  codebase where issue #85 already shows how a plist/account mismatch fails *silently
  until the next boot*. Treat any change here with the same caution as that warning.

**What this does not fix.** An operator remains free to attach a hand-made VM to **their
own** slots and misconfigure it. That is inherent to operator ownership and is accepted —
the boundary this restores is *between* operators, not between an operator and their own
sessions.

#### De-enrollment — specify it with enrollment, not after

**Enrollment and de-enrollment are two halves of one mechanism**, and phase 1 must
specify both. Leaving the second half to "later" is not a scheduling choice here; it is a
correctness hole.

**⚠️ Reclaiming a range without revoking the departing operator's group membership
recreates this section's defect exactly.** The new owner is given the slots, the old owner
retains group membership and therefore socket access, and **nothing detects it** — the
plists look right, the daemon's derived mapping (§1.3) names the new owner, and the old
owner's continued reach is invisible at every layer that anyone inspects.

So the ordering is a requirement, not an implementation detail:

1. **Revoke group membership first.**
2. Only then may the range be reassigned to another operator.

Note that under §1.3's derivation this is also what makes the daemon's view correct: while
both operators are in the group, the slot has **two** members and is therefore
*unassignable* by the rule above — so a half-done de-enrollment fails closed and shows up
as lost capacity rather than as silent shared access. That is the behaviour to preserve;
do not "fix" the two-member case by picking the newer operator.

**§3.6 assertion 5 is already the right test.** Run it as the *departed* operator against
the reassigned slot: it must fail at connect.

#### Why no existing test catches this, and how to test the fix

**Nothing in the suite can detect it, and the obvious test shape cannot either.** The
isolation checks that exist — including §3.7's original cross-VM reachability probe —
stand up two VMs whose configurations were both written by the harness, each given NICs
only on its own slots, and then confirm they cannot reach each other. Of course they
cannot: neither was configured to try. **Those assertions measure the daemon's
configuration, not the boundary**, so they pass whether or not the boundary exists.

`integration_vmnet_inter_slot_l2_isolation` (`network.rs:3021`) has the same shape — it
establishes that *distinct slots* are distinct segments, which is true and is not the
question. The question is who may attach to a given slot.

**The test that does detect it is §3.6 assertion 5**, added for exactly this reason: a VM
configured by its *own owner* to name a slot it was not assigned. That is the only shape
that exercises the DAC check rather than the bookkeeping.

**To verify a fix:** run assertion 5 as a second operator against a slot belonging to the
first. It succeeds today — that success *is* the reproduction — and must fail at connect
once per-operator groups land. §3.8 outcome (d) exists to catch the case where it still
succeeds afterwards, which would mean the mechanism was applied incompletely.

---

## 2. Lifecycle and failure modes

### 2.1 Where a range may come from — never from a file the operator can write

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

**⚠️ This section previously specified a `sessions.db` refinery migration to persist
ranges. That is no longer needed and has been removed.** §1.3 assigns ranges at
enrollment and §1.6 enforces them in root-owned plists and group membership, and §1.3
has the daemon **derive** the range from the live socket gids rather than read it from
anywhere. Persisting a copy in `sessions.db` would add a store that can disagree with the
thing that actually enforces — the precise failure this section exists to avoid.

**Decision: the daemon derives the range from the running sockets (§1.3); it persists
nothing new for ranges.**

- **Ranges** — static from enrollment, read from operator-unwritable config (§1.3). No
  migration, no new table, no new file.
- **Per-session slot claims within a range** — **unchanged from today**. `VmnetPool`
  stays in-memory and is rebuilt at startup from each session's persisted
  `NetworkInfo.vmnet_slot` via `restore_from_infos` (`network.rs:1320-1354`), exactly as
  it is now. The only change is that there are several pools and each validates against
  its own range rather than `0..max_slots`.

#### One new persisted field: which operator a session belongs to

Restore has to route each persisted session to the right operator's pool, and it currently
cannot: `NetworkInfo` carries no operator identity, and `Session.owner_username`
(`session.rs:935`) is a **username**, not a uid.

**Decision: persist `operator_uid: Option<u32>` on `NetworkInfo`**, `#[serde(default)]`,
per `CLAUDE.md`'s blob-field rules — a new optional field, so records written by an older
daemon still deserialize and a newer daemon's records survive a rollback.

**Why not derive it from the slot index?** It looks elegant — the slot already implies the
range, and the range implies the operator — and it is wrong twice over. **Lite sessions
claim a token, not a slot** (`claim_lite_token`, `network.rs:1202`), so it would cover only
half the cases; and it would break **silently** if a slot's owner ever changed, attributing
an old session to a new operator. An explicit field covers both backends uniformly and
cannot be quietly wrong.

**Older records lacking the field:** fall back to resolving `owner_username` → uid. If that
fails — the account was removed, renamed, or is not resolvable at startup — **decline to
restore the claim and surface it in diagnostics**. Do not guess, and do not drop it
silently.

⚠️ **A wrinkle worth naming:** the pool's existing leak-reporting accessor
`claimed_slot_sessions` (`network.rs:1406-1415`) reports slots that *are* claimed, so it
cannot by itself surface a claim that was **declined** — that is the inverse condition.
Report it through the **same diagnostics endpoint** (`main.rs:11156-11157`) rather than a
new channel, but expect it to need its own list alongside the claimed-slot one.

The reasoning above still applies to anything that *is* persisted: an operator-writable
file must never be the input to a security-relevant allocation.

**A note on `CLAUDE.md`.** Its sentence — *"Lima VMs, configs, and the SSH key live under
`/var/lib/sandboxd/<…>/lima/`, owned by the operator uid"* — has the *contents* as its
subject, and that is **true**: the operator owns every file it creates there
(`lima.rs:692-695`). The **directory** is daemon-owned with a single non-inheriting ACE,
which is the fact reason 1 turns on and is worth knowing. An earlier draft billed this as
a "documentation correction"; it is a clarification of a sentence that was not wrong.

### 2.2 Exhaustion and range conflict — two distinct failures

Partitioning produces **two** client-visible failures that are easy to conflate and
must not be. They have different causes, different remediations, and different status
codes.

| # | Condition | Cause | Status | Variant |
|---|---|---|---|---|
| 1 | **Per-operator session exhaustion** | the operator *has* a range, but every slot in it is in use | **429 Too Many Requests** | **new** `SandboxError` variant |
| 2 | **No range assigned to this operator** | the operator was never enrolled with a slot range (§1.3), or the whole pool is assigned elsewhere | **409 Conflict** | existing `SandboxError::Conflict` |

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
   `429 Too Many Requests` needs a **new `SandboxError` variant** (in
   `sandbox-core/src/error.rs:9`) plus an arm in `error_response`.

   **Make it structured, not string-wrapped.** Carry the operator uid, the in-use count
   and the quota as fields, and render the operator-facing text from a `Display` impl —
   unlike `Network`/`Conflict`, which pass a pre-formatted string through verbatim
   (`error.rs:69-70`). Name it for the domain condition rather than the HTTP code;
   `QuotaExhausted { .. }` is indicative, not mandated — pick what fits the module.

   **The deciding reason is that it collapses duplication rather than preserving it.** The
   exhaustion message exists today as **three byte-identical copies**
   (`network.rs:1161-1166`, `:1171-1176`, `:1208-1213`). A structured variant renders it in
   one place; a string-wrapped one would keep three call sites free to drift — and they are
   being rewritten anyway (point 2), which is exactly when drift gets introduced.
2. **Rewrite the remediation text.** "set max_macos_sessions in config and restart
   sandboxd" becomes actively misleading once the binding constraint is the operator's
   *share*: raising the host total does not help, and the host total cannot exceed 32
   regardless. The message must distinguish "your share is full" from "the host is
   full", and for the latter point at the privileged pool-regeneration step rather than
   a config edit.

#### Condition 2 — no range available for a new operator (new path)

Raised when an operator with no assigned slot range (§1.3) requests a gateway VM —
because they were never enrolled with one, or because the pool is assigned elsewhere.
**Reuse `SandboxError::Conflict`** — it maps to
`409` at `error.rs:69` and, like `Network`, passes its message through verbatim, so this
condition costs no new variant:

```rust
SandboxError::Conflict(msg) => (StatusCode::CONFLICT, msg.clone()),
```

The message carries the facts from §1.3 — pool size, that no range is assigned to the
requesting operator, and the remediation (enroll the operator with a slot range). Do
**not** reuse condition 1's text: "max concurrent sessions reached" is wrong here, because
the requester holds no sessions at all.

**Do not name the holding operator in the response body.** Any enrolled operator can
trigger this error, so naming who holds the pool leaks the roster of sandboxd users on a
shared machine. Put the holder in the daemon log or behind `/diagnostics`, where the
audience is the administrator who can act on it, and keep the client-facing body to the
requester's own situation plus the remediation.

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
`:13289-13294`).

**⚠️ But "garbage accumulates" understates it, and the earlier framing was too mild.**
What the daemon loses track of is not inert residue — it is **running sandbox containers
with live network access** that the daemon can no longer stop, re-policy or reap. A
session the daemon believes is gone keeps egressing under whatever policy was last pushed,
indefinitely, if the operator never logs back in. That belongs in §5.1 as a delta (it is
listed there), not here as a hygiene note.

**And it rests on an unverified assumption — see §2.9.** Everything above presumes the VM
*survives* logout. §2.5's supporting evidence is about **agent restart**, which is a
different event. If macOS tears down the per-user domain at logout and kills QEMU, the
behaviour is fail-closed and most of this section is unnecessary. The design does not know
which, and §2.9 adds the check.

**A related site, for a different reason.** `SessionStore::new` shells `docker ps` /
`volume ls` / `network ls` at store-open time (verbs at `store.rs:245, 266, 286`; the
shared runner at `:342-360`), before any agent exists. It should be neutered like its Lima
counterpart `v006_scan_lima_vms` (`store.rs:327-336`) — **but not for the reason an
earlier draft gave.** It builds `Command::new("docker")` with **no `-H`**
(`store.rs:348`), so it targets the *host* Docker daemon, which could never reach the
gateway VM in the first place. On macOS it either finds no docker (already a
warn-and-return-0 no-op, `:350-359`) or finds an unrelated Docker Desktop and reports
**false orphans**. It is also log-only and says so — *"Do NOT auto-delete; review each
orphan before cleanup"* (`store.rs:311-313`) — so nothing accumulates and nothing is
destroyed. The fix is right; the justification is "it targets the wrong daemon", not
"the daemon cannot reach a logged-out operator".

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

Today that lane carries ~12 Lima ops per session. The brokered-ops phase puts the entire
lite control plane on it, plus the DNS-gate bridge's **one stream open per DNS query**
(§5.2).

**Decision: pipeline by `request_id`**, which the protocol already reserves for exactly
this (`sandbox-agent/src/protocol.rs:99-101`).

The alternative — a second connection class for stream opens — was rejected because it
only takes *stream* opens off the critical path. This design moves roughly 28 Docker call
sites onto the broker (§5.3), and **most of them are request/response, not streams**, so
control ops would still queue behind one another on a connection that handles one at a
time. The narrower fix does not address the larger half of the new load.

**Protocol ordering is not the risk.** A dependent sequence — create, then start — is
already serialized by the caller awaiting each response before issuing the next.
Pipelining adds concurrency only *between independent operations*, which is precisely the
case that is safe.

**⚠️ The real risk is agent-side shared state**, and it is easy to overlook because the
protocol change looks like the whole job. Handlers that today can assume they run one at a
time may touch process-global state, filesystem staging paths, or `limactl` invocations
whose working set collides. **Auditing the agent's handlers for concurrency safety is an
explicit phase 2 work item**, not an implementation detail of the protocol change.

**A second, sharper reason it matters — the exposure while an op is queued.** Container
create today is `docker create` (`main.rs:5262`) → **`docker start` (`:5285`)** → **in-VM
route helper (`:5328`)**. Between start and route-install the container holds Docker's own
default route to the bridge `.1`, which masquerades to the internet. That window exists
today as one `limactl shell` round trip. Brokered, it becomes a queued op behind a
serialization point with a 60 s deadline — and after the shared-root phase there is a real
project tree inside the container from the first instant.

**Make the pre-route state fail closed rather than racing it.** Either create the
per-session network with masquerade disabled
(`--opt com.docker.network.bridge.enable_ip_masquerade=false`, where the create argv is
built at `network.rs:401-415`), or `docker create --network none` and attach the session
network only after the route is installed. The first also closes the bypass in §3.6
assertion 4 structurally rather than only testing for it. **Verify the Linux lite path
does not depend on that NAT before applying it cross-platform.**

### 2.6 Two singletons that must become per-operator

**The global recovery latch.** `AppState.gateway_recovering: Arc<AtomicBool>`
(`main.rs:1373`) is one latch for "the" gateway being recovered, read at `main.rs:12353-12355`
to suppress per-session gateway re-creates. With N VMs, **one operator's recovery would
suppress every other operator's per-session gateway monitor.** Key it by operator uid;
`gateway_recovery.rs`'s `latch: Arc<AtomicBool>` parameter (`:250`) follows.

`run_gateway_recovery` also snapshots **all** sessions from the store (via
`deps.list_sessions()` at `gateway_recovery.rs:266`), so it needs an operator scope.
`run_bounded_recovery` and `GatewayRecoveringGuard` are generic and need no change;
`networking_status` (`:249`) is keyed by `SessionId` and needs none either.

**`GatewayRecoveryDeps` does need one, though** — an earlier draft said it did not.
`list_sessions()` (`:179`) is unfiltered and `sessions_to_recover` (`:77-82`) filters only
on state and backend, so "invoke it once per operator" against an unfiltered list would
tag and recover **every** operator's sessions once per operator. Either the trait gains an
operator scope or the caller supplies a filtering impl — **decide which in the ownership
phase**; do not leave it to the implementer to discover at the Nth invocation.

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

**Naming decision: `sandboxd-gateway-<operator_uid>`.** It keeps the existing
`sandboxd-gateway` prefix, so the VM stays greppable and instantly recognisable in
`limactl list` output and in logs; it encodes the owner; and it **structurally cannot
match** the session grammar, which requires the `sandbox-` prefix followed by a parseable
12-hex session id.

**Pair it with an explicit reaper exclusion.** Do **not** rely on the parse failing —
that reliance is precisely the accident that makes today's arrangement a landmine, and a
future change to either the session-id grammar or the gateway naming scheme would arm it
silently.

**⚠️ Placement correction.** An earlier draft said to put the exclusion in
`decide_lima_vm` (`lima.rs:350`). **That function never sees a name:**

```rust
pub fn decide_lima_vm(
    session_id: Option<&crate::session::SessionId>,
    marker: Option<&str>,
    live: &std::collections::HashSet<crate::session::SessionId>,
    my_pool: &str,
) -> LimaVmDecision
```

The caller parses the name and only `Option<SessionId>` reaches the classifier. So the
exclusion goes **either** in `reap_lima_orphans_inner` (`lima.rs:460-490`), before the
classifier is consulted — the cheaper option — **or** `decide_lima_vm` gains a `name:
&str` parameter, which also touches its hermetic tests. Pick one in the ownership phase.
The surrounding reasoning is unaffected: the parse-failure protection at
`lima.rs:4203-4206` genuinely is accidental, and an explicit exclusion is genuinely
required.

**Consequence for daemon-side data structures.** The instance name alone is no longer
unique in the way daemon-side code may assume: two operators' gateway VMs have distinct
names, but they live in **different LIMA_HOMEs**, and a name is only meaningful together
with the LIMA_HOME it resolves in. Any daemon-side map keyed on instance name must
therefore be keyed by **(operator uid, name)** — or simply by operator uid, since each
operator has exactly one gateway VM. Audit for name-keyed lookups when implementing
phase 4 (ownership).

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
range is privileged re-enrollment (§1.6) plus a VM bounce — not something the daemon can
do, and not something it can do without destroying that operator's running lite
sessions.

#### Future enhancement, explicitly out of scope: bounce-driven rebalancing

The mechanism above is exactly what a **rebalancing** policy would need — shrink
operator A's range so a newly-arriving operator B can be given a disjoint share, instead
of requiring a privileged re-enrollment (§1.3). Note that under §1.6 rebalancing is not
purely a VM bounce: the plists and group membership would have to change too, which is
root work.

**This version deliberately does not do that, and the omission is a decision rather
than an oversight.** It is gated on issue #83: bouncing an operator's VM kills that
operator's lite sessions, and container-backend sessions are not recovered today. Until
that holds, automatic rebalancing would silently destroy running work belonging to an
operator who did nothing but be first. Refusing B with an actionable 409 (§2.2 condition
2) is the honest behaviour in the meantime.

Revisit once #83 lands. Two of the pieces it would need already exist here — a slot set
passed per call (§1.4 fix 3) and self-correcting provision scripts — but note that a third
does **not**: rebalancing has to rewrite root-owned plists and group membership (§1.6),
which the daemon cannot do. So the future work is policy **plus a privileged step**, not
policy alone. An earlier draft called it "policy, not plumbing" while ranges were
daemon-persisted; that is no longer the shape.

---

### 2.8 Constraint: LIMA_HOME path depth (`UNIX_PATH_MAX = 104`)

**Lima instances cannot live at an arbitrarily deep path.** Lima creates a Unix domain
socket at `<instance-dir>/ssh.sock`, and a Unix socket address is bounded by
`UNIX_PATH_MAX`, which on macOS is **104 bytes** including the terminator. Exceed it and
the VM fails to start.

Discovered the hard way while verifying §1.4 fix 1: a throwaway LIMA_HOME under a deep
scratchpad directory produced a 117-character socket path and failed. **A symlink does
not help — Lima resolves it** before binding, so shortening the path you type does not
shorten the path that gets bound.

This bears directly on this design, because per-operator instances live at
`{state_root}/{daemon_uid}/{op_uid}/lima/<instance>/` and §2.6 *lengthened* the instance
name to `sandboxd-gateway-<operator_uid>`. The arithmetic for the real shape:

| Path | Length | Headroom |
|---|---|---|
| `/var/lib/sandboxd/309/501/lima/sandboxd-gateway-501/ssh.sock` | 60 | 44 |
| `/var/lib/sandboxd/309/501/lima/sandbox-a1b2c3d4e5f6/ssh.sock` (a session VM) | 60 | 44 |
| `/var/lib/sandboxd/12345/98765/lima/sandboxd-gateway-98765/ssh.sock` (5-digit uids) | 66 | 38 |

**Headroom is comfortable today — roughly 40 characters — and the §2.6 naming decision
does not threaten it.** A gateway instance name is the same length as a session VM name,
so nothing regressed.

**But it is finite, and three things consume it:** a longer `{state_root}`, another level
of nesting under it, and a longer instance-name scheme. Do not add any of them without
recomputing against 104. In particular, do not "temporarily" relocate a LIMA_HOME into a
scratchpad or temp directory to test something — that is exactly what failed here, and
the error does not name path length as the cause.

### 2.9 ⚠️ Unverified: does an operator's VM survive logout?

**§2.3, §2.4 and §2.5 all presuppose that it does**, and none of them checks.

The evidence offered for survival is about a **different event**: §2.5 observes that
`limactl start` detaches QEMU, so a VM survives an *agent restart*. Logout is not an agent
restart. On macOS, launchd tears down the per-user domain at logout, and if that kills
QEMU it takes every one of that operator's lite sessions with it.

**Which is true flips the security character of §2.4 entirely:**

| If the VM… | Then §2.4 describes… | Character |
|---|---|---|
| **dies at logout** | nothing — there is no unreachable VM to reason about | fail-closed; most of §2.4 is unnecessary |
| **survives logout** | running sandbox containers with live egress that the daemon cannot stop, re-policy or reap | fail-open; belongs in §5.1 as a delta (it is there) |

**Pre-check C, in the same 30-second shape as pre-check B:** create a VM as an operator,
log that operator out, log back in, and observe whether the QEMU process survived and
whether the agent re-registers cleanly. Run it alongside the other pre-checks; it costs a
logout and it decides whether a whole section is describing a real state.

### 2.10 Resource multiplication — N VMs, not one

The central change replaces one shared VM with one per active operator, and the runtime
cost of that has not been stated anywhere in this design.

Per gateway VM: **2 vCPU / 2 GiB RAM** (`gateway_lima.rs:111`, `:118`), a multi-GB disk
image, and a staged gateway-image tarball in its LIMA_HOME. `docs/guides/macos-operations.md:82`
gives the per-VM footprint the project already documents; the ownership phase's Makefile
work multiplies the tarballs too, since staging becomes per-operator.

Going from 1 to N multiplies all three. On a shared development Mac that is the binding
constraint well before the 32-slot pool ceiling is — a host can exhaust memory with far
fewer operators than slots. §5.3 re-estimates *engineering* cost; this is the runtime cost,
and for a design whose motivating platform is explicitly a development platform it belongs
in the document.

**Not a blocker, and no mitigation is proposed here** — the per-operator model is the
point. But it should be sized before a multi-operator host is recommended, and the
"how many operators fit" question should be answered from memory, not from slot count.

---

## 3. The egress validation gate

**The question:** *is egress still enforced when the gateway VM is owned by the operator
instead of the daemon?*

**Scope, deliberately narrow.** Networking only. **No** daemon, **no** broker, **no**
real sessions, **no** session store, **no** `shared:` mounts. Stand the topology up by
hand as an operator uid, assert, tear down.

### Form and lifetime: a throwaway shell script

**The gate is a one-off shell script that answers one question and is then deleted.** It
is not a regression harness, it is not wired into the pytest suite, and it is not
maintained.

The reasoning: **phase 6 retargets the real e2e suite and runs continuously**, so
regression coverage during the migration already has an owner. Building a parallel
bespoke harness would mean maintaining two systems that can disagree about what "egress
is enforced" means — and when they disagree, you have to work out which one is wrong
before you can act on either.

So:

- Section 3 is a procedure **executed once, during phase 0**. Its findings are recorded
  in this spec and on issue #82 — the *findings* are the durable artifact, not the code.
- The script **may be committed during phase 0** for reproducibility while the question
  is live. **Deleting it is part of phase 0's exit.** Nobody should inherit it as a
  maintenance burden.
- **The script hand-writes everything it needs** — the Lima YAML and the nft rulesets are
  literal text in the script, copied from the generators once. **In any durable artifact
  those copies would be drift hazards**; they are acceptable here *only* because the
  script's lifetime is measured in days, which is exactly why it must not be kept.

Ongoing egress regression coverage is phase 6's job — specifically its durable
bypass-resistance test — not this script's.

Set these once; every command below uses them:

```bash
export OP_UID=$(id -u)
export LIMA_HOME=/var/lib/sandboxd/<daemon_uid>/${OP_UID}/lima   # resolve per Before you start
export GW=egress-gate-${OP_UID}      # throwaway VM name — never `sandboxd-gateway`
```

⚠️ **Resolve `<daemon_uid>` deliberately** — see [Before you start](#before-you-start).
Creating this VM under the e2e harness daemon's uid puts it in a tree that
`conftest.py:1049-1062` sweeps destructively.

### 3.1 Pre-checks

Two were originally scoped here. **A is already answered** — its result is folded into
§1.4 and shaped phase 1, though note its two limits there (bare `limactl`, not the broker
path; Lima 2.1.2, not the declared 1.2.0 floor). **B is still outstanding**, takes about
30 seconds, and should be done before §3.4.

**Pre-check C (§2.9) also belongs here** — does an operator's VM survive logout? Create a
VM, log the operator out, log back in, observe whether QEMU survived and whether the agent
re-registers. It decides whether §2.4 and one §5.1 delta describe a real state.

#### Pre-check A — ✅ ALREADY ANSWERED, do not re-run

**`interface:` works on `socket:` networks.** Verified on Lima 2.1.2 / socket_vmnet
1.2.2, unelevated, in a throwaway LIMA_HOME. The full result — baseline, pinned test, and
the `lsof` fd-correlation chain proving it binds rather than merely relabels — is in
§1.4 fix 1.

Nothing to run here. Three things it produced that later phases must carry:

- §1.4 **fix 1a** — the generator must assert `interface == format!("lima{slot}")` itself,
  because Lima validates neither the correspondence nor anything about it.
- §1.1a — the **agent** must assert the same thing, and today rejects the key outright.
- §2.8 — the `UNIX_PATH_MAX` path-depth constraint, found while setting this up.

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

### 3.2 Host IP forwarding — record it, and know what it means

⚠️ **An earlier draft of this section had the premise backwards.** It said the daemon
refuses to start when host IP forwarding is enabled and that a ticket existed to remove
that requirement. **The requirement was already removed**, and the ticket tracks the
*unfixed bypass the check used to paper over*:

> `NOTE(#80): Host IP forwarding is no longer gated here. A root sandbox guest can bypass
> the gateway by routing via the host bridge when the host has IP forwarding + NAT (e.g.
> Internet Sharing) enabled. This is a known open issue; the structural fix is deferred
> and tracked in #80.`
>
> — `sandboxd/src/main.rs:13344-13347`, repeated at `sandbox-core/src/macos_session.rs:744-748`

So: **host IP forwarding is a live, unfixed egress bypass (#80)** for the **full**
backend, where sessions sit on a host-visible segment. It is out of scope for this gate,
which builds a lite-shaped topology with no host bridge in the path.

Record the values as interpretive context; do not gate on them:

```bash
sysctl net.inet.ip.forwarding net.inet6.ip6.forwarding
```

Carry the correct model into phase 4: this is a known hole, not a retired concern.

### 3.3 What the gate builds

The topology mirrors the **lite** shape (an in-VM Docker bridge), not the full-backend
macvlan shape — lite sessions consume no vmnet NIC, and the question is about the VM's
ownership.

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
`.2`, not at `.1` — see §3.5, the step everything hinges on.

**Note for §3.7:** the second-operator probe additionally needs each VM attached to its own
vmnet slots with **endpoints actually addressed on the `/29`s**, because that is where
cross-operator isolation lives. The bridge topology above proves egress; it says nothing
about slots.

### 3.4 Stand-up

**Step 0 — pick a slot and confirm its socket.**

```bash
export SLOT=0
export SLOT_SOCK=/var/run/sandbox/vmnet/slot-${SLOT}.sock
test -S "$SLOT_SOCK" && echo "slot socket present"
```

**Step 1 — hand-write the Lima YAML, then create and start the VM as the operator.**

⚠️ **Do not try to render this with `generate_gateway_template`.** An earlier draft said
to, and it cannot work: that function takes `max_slots: u16` rather than a slot set, and
unconditionally interpolates the 9p stanza (`gateway_lima.rs:349-350`) — both of which are
phase 1 changes, while this phase forbids production code changes. It is also a
`#[cfg(target_os = "macos")]` library function with no binary that prints YAML, so a shell
script cannot call it at all. That instruction was a fossil from when this harness was
going to be Rust.

**Write the YAML literally in the script.** It is a throwaway; a hand-written copy is
acceptable here and nowhere else. Mirror the real template's load-bearing parts — `vmType:
"qemu"`, the Ubuntu image, `cpus`/`memory`, one `socket:` entry with its matching
`interface:`, no `mounts:` stanza — and keep the instance name out of the
`sandbox-<12hex>` shape.

```bash
cat > /tmp/${GW}.yaml <<YAML
vmType: "qemu"
images:
  - location: "<UBUNTU_NOBLE_ARM64_URL — copy from gateway_lima.rs>"
    arch: aarch64
cpus: 2
memory: "2GiB"
disk: "20GiB"
networks:
  - socket: "${SLOT_SOCK}"
    interface: "lima${SLOT}"
portForwards:
  - guestSocket: "/var/run/docker.sock"
    hostSocket: "{{.Dir}}/gateway-docker.sock"
containerd:
  system: false
  user: false
YAML

limactl create --name="$GW" --tty=false /tmp/${GW}.yaml
limactl start "$GW"
limactl shell "$GW" -- docker info >/dev/null && echo "docker up"
```

- **Failure here is outcome (a) or an environment problem**, not an egress finding. If
  `limactl start` fails on the socket, re-check the socket group
  ([Before you start](#before-you-start)).

**Step 2 — get the gateway image into the VM.**

⚠️ **There is no registry, and the VM is brand new.** An earlier draft ended step 3 with
`sandbox-gateway:<version>` and never said where the image comes from — `docker run` would
fail with image-not-found.

Production loads a staged tarball: `GATEWAY_IMAGE_TARBALL_FILENAME = "gateway-image.tar"`
(`gateway_lima.rs:179`), copied in and piped to `docker load` by
`load_gateway_image_if_needed` (`gateway_lima.rs:957-1121`). The `make` staging targets
are keyed to the **daemon's** LIMA_HOME and the `sandboxd-gateway` instance name, so they
do not help here. Do it by hand:

```bash
make gateway-image                          # build it if you have not
docker save sandbox-gateway:<version> -o /tmp/gateway-image.tar
limactl copy /tmp/gateway-image.tar "$GW":/tmp/gateway-image.tar
limactl shell "$GW" -- docker load -i /tmp/gateway-image.tar
limactl shell "$GW" -- docker image inspect sandbox-gateway:<version> >/dev/null
```

Resolve `<version>` from the workspace version in `sandboxd/Cargo.toml`
(`[workspace.package].version`), which is what drives the runtime image tags.

**Step 3 — create the two bridges.**

```bash
limactl shell "$GW" -- docker network create sandboxd-egress || true   # name: gateway_lima.rs:89

limactl shell "$GW" -- docker network ls --format '{{.Name}}' \
  | xargs -I{} limactl shell "$GW" -- docker network inspect {} \
      --format '{{range .IPAM.Config}}{{.Subnet}} {{end}}'

export SESSION_NET=10.211.0.0/28      # any non-overlapping RFC1918 /28
limactl shell "$GW" -- docker network create --subnet "$SESSION_NET" gate-session
```

With `10.211.0.0/28`: `.1` is the bridge, `.2` the gateway container, `.3` the probe.

**Steps 4–10 — mirror the production order exactly.**

⚠️ **The order matters and an earlier draft had it wrong**, waiting for health *before*
seeding the artifacts Envoy blocks on. `entrypoint.sh:184-190` blocks Envoy on **both**
the bootstrap and the listener file, with `ENVOY_CONFIG_WAIT_TIMEOUT` defaulting to 30 s
(`entrypoint.sh:47`) — so the container's own wait expires long before a 120 s health poll
gives up, and the health check can never pass first. That deadlock is not any of §3.8's
outcomes; it would have been misattributed.

The production sequence for the lite shape is `setup_macos_lite_gateway`
(`macos_session.rs:439-544`). Follow it:

| Step | Action | Production reference |
|---|---|---|
| 4 | `docker run` the gateway container on `sandboxd-egress` | `macos_session.rs:439` |
| 5 | **provision the mitmproxy CA** | `provision_mitmproxy_ca`, `:460` |
| 6 | **write the Envoy static bootstrap** to `/etc/envoy/envoy-bootstrap.yaml` | `PolicyCompiler::compile_envoy_bootstrap`, `:465`; path const `policy.rs:569` |
| 7 | **write the deny-all Envoy listener** to `/etc/envoy/listeners/listener.yaml` | `:480`; path const `policy.rs:584` |
| 8 | **write the CoreDNS policy** to `/etc/coredns/policy.conf` | `policy_distributor.rs:151` |
| 9 | attach the second NIC at `.2` | `docker network connect`, `:523` |
| 10 | **inject the deny-all base ruleset** | `gm.inject_deny_all`, `:543`; generator `gateway.rs:1554` |
| 11 | wait for health | `gm.wait_for_components`, `:544` |
| 12 | inject the DNAT ruleset | `inject_dnat`; generator `gateway.rs:1616` |

**Four artifacts, not two.** An earlier draft listed only the listener and the CoreDNS
policy. The **Envoy bootstrap** is a third and is what the container actually blocks on;
the **mitmproxy CA** is a fourth, and while assertion 2 uses plain HTTP, `mitmdump` must be
running for `/healthcheck.sh` to pass, so a missing CA fails the health wait opaquely.

Step 4's flags mirror `build_macos_gateway_docker_args` (`macos_session.rs:567-640`):

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
(`networking/gateway/entrypoint.sh:304`), a dead end inside the VM: its own upstream — the
VM's `127.0.0.53` stub — does not answer, so an allowed domain **SERVFAILs on the forward
even though DNS policy admits it**. Rationale in code at `macos_session.rs:599-610`.

Step 9:

```bash
limactl shell "$GW" -- docker network connect --ip 10.211.0.2 gate-session gw
```

Step 11:

```bash
for i in $(seq 1 60); do
  limactl shell "$GW" -- docker exec gw /healthcheck.sh && break
  sleep 2
done
```

- **Expected:** exit 0 within ~60 s (`networking/gateway/Dockerfile:148, 174`).
- **Failure signature:** persistent non-zero. Read `docker logs gw`. A stall on "Envoy
  bootstrap file" or "Envoy listener file" means steps 6–7 were skipped or wrote empty
  files; a CoreDNS failure usually means step 4's env var was omitted.

Step 12's ruleset — `generate_dnat_ruleset(vm_subnet, gateway_ip)` is `pub` at
`gateway.rs:1616`. **Render it once and paste the literal output into the script**; the
block below is illustrative and elides the real output's comments and multi-line set
bodies:

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

Ports: DNS `53` (`gateway.rs:248`), Envoy `10000` (`:253`), deny-logger TCP `10001`
(`:259`), NFLOG group `1` (`:276`). **The empty sets are the fail-closed default.**

**Step 13 — run the probe container.**

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
container. Without this step the probe bypasses the gateway entirely.**

This is also why the production sandbox container runs `--cap-drop ALL` and cannot install
its own route, and why `sandbox-route-helper` exists: on macOS lite the route is installed
from *outside* the container by `sandbox-route-helper --vm-gateway-mode`
(`lite_macos.rs:262-277`), invoked at `main.rs:5360-5364` (create) and `main.rs:6091`
(restart). The gate's `nsenter` stands in for the helper.

**Verify before asserting anything:**

```bash
limactl shell "$GW" -- sudo nsenter -t "$PROBE_PID" -n ip route show default
# expect: default via 10.211.0.2
```

### 3.6 Assertions — deny first

**The order is a correctness property.** A missing or wrong default route makes the
**allow** case pass, so asserting deny first turns the most likely harness bug into an
immediate failure rather than a false green.

⚠️ **That argument only works if the deny assertion discriminates** — and in an earlier
draft it did not. It accepted `{6, 7, 28, 35, 56}`, borrowed from
`tests/e2e/test_lite_macos.py:410`, where the set is applied to a **denied domain that
NXDOMAINs** (exit 6) with DNS in the path. Against an IP literal that breadth is fatal:

| Route | Path | curl |
|---|---|---|
| **Correct** (`via .2`) | prerouting DNATs unmatched TCP to the deny-logger (`gateway.rs:1651`), which accepts, logs and **closes with RST** | connect-then-reset → **52 or 56** |
| **Bypassed** (via `.1`) | Docker NAT → VM slirp → internet → TEST-NET-3 is unrouted | **28** (timeout) or 7 |

Both landed inside the accepted set, so **skipping §3.5 left assertion 1 green** and the
"test your test" criterion was unsatisfiable.

#### Assertion 1 — deny (run this first)

```bash
limactl shell "$GW" -- docker exec gw nft add element inet sandbox_dnat \
  policy_allow_tcp '{ 10.0.0.0/8 . 443 }'

limactl shell "$GW" -- docker exec probe \
  curl -sS --max-time 8 http://203.0.113.1:8080/
echo "exit=$?"
```

- **Why a CIDR policy rather than an empty one:** a deny that passes because *nothing* is
  configured is weak evidence. A live policy that does not cover the target proves the
  pipeline is loaded and still denying.
- **Why an IP literal:** `203.0.113.1` is TEST-NET-3, guaranteed unroutable, and it keeps
  DNS out of the deny path.
- **Assert `{52, 56}` — connect-then-reset.** A correctly-routed denied connection always
  reaches the deny-logger and is reset.
- **Exit 28 (timeout) is a harness failure, not a block.** It means the probe never
  reached the deny-logger — almost always a wrong or missing default route. Treat it as
  red and re-check §3.5.
- **Exit 0** means the probe reached the internet: **outcome (c)** in §3.8.

#### Assertion 2 — allow

```bash
for i in $(seq 1 30); do
  limactl shell "$GW" -- docker exec probe nslookup example.com && break
  sleep 1
done

# Read back the resolved addresses and add the allow tuple for each:
#   docker exec gw nft add element inet sandbox_dnat policy_allow_tcp '{ <ip> . 80 }'

limactl shell "$GW" -- docker exec probe \
  curl -sS --max-time 15 http://example.com/
echo "exit=$?"
```

⚠️ **The allow tuple is a third artifact and the ordering is load-bearing** — an earlier
draft implied step 6 produced it. It cannot: `policy_allow_tcp` is keyed on **resolved
addresses**, so the real order is *resolve → read the resolved IPs → `nft add element` →
curl*. The `nslookup` warm-up is not just cache-warming; it is what produces the input to
the rule you must add.

- **Expected:** exit `0` **and** `Example Domain` in stdout. Assert both.
- **SERVFAIL on an allowed domain:** re-check `SANDBOX_COREDNS_UPSTREAM` in step 4.

#### Assertion 3 — structural

```bash
limactl shell "$GW" -- docker exec gw nft list ruleset > /tmp/ruleset.txt
```

Assert the same regexes the existing suite uses — **all five**, not four. An earlier draft
omitted `:416`, which is the rule that actually **drops** denied UDP; `:412` only mirrors
it to NFLOG. A ruleset with the log rule and without the drop rule logs every denied UDP
packet and forwards it — the worst possible regex to omit from an egress gate.

| Source | Regex | Meaning |
|---|---|---|
| `test_networking.py:384` | `udp dport 53 dnat` | DNS UDP → CoreDNS |
| `:388` | `tcp dport 53 dnat` | DNS TCP → CoreDNS |
| `:398` | `meta l4proto 6 dnat` | non-DNS TCP → deny-logger |
| `:412` | `meta l4proto 17 log group 1` | denied UDP mirrored to NFLOG |
| **`:416`** | **`meta l4proto 17 drop`** | **denied UDP actually dropped** |

**Table set: assert exactly `{sandbox, sandbox_dnat}`.** ⚠️ An earlier draft required
`{sandbox, sandbox_dnat, sandbox_policy}` while the procedure injected only one table —
structurally impossible. With step 10 restored, `sandbox` exists (`generate_deny_all_ruleset`,
`gateway.rs:1554`) and `sandbox_dnat` exists. **`sandbox_policy` is legitimately absent**:
it is created by the policy-apply path, which needs the daemon, and §3 has no daemon. Say
so in the script's output so a reader does not think it is missing by accident.

Restoring step 10 matters for more than the assertion. Without `inject_deny_all` the gate
never establishes the `sandbox` input chain's `policy drop` + trailing `reject`, so it
would certify a **weaker topology than production** — proving egress control on a gateway
container with no inbound filter at all.

#### Assertion 4 — bypass resistance (**the most important one**)

⚠️ **An earlier draft tested the wrong next hop and would have passed having proved
nothing.** It installed a route via `192.168.5.2`, Lima's slirp gateway — borrowed from the
full-backend regression (`test_networking.py:698, 799-809`), where the sandbox is a **VM**
whose `eth0` genuinely is a slirp NIC. The probe here is a **container** whose only NIC is
on `10.211.0.0/28`, so `192.168.5.2` is off-link and `ip route add … via …` fails with
"Nexthop has invalid gateway". No route is installed, `curl` fails, and the assertion
records a block having tested nothing.

**The reachable bypass in this topology is the Docker bridge gateway**, which masquerades
straight out `eth0` — the gateway VM's own nft policy deliberately declares no FORWARD
chain, so Docker NAT is untouched.

```bash
limactl shell "$GW" -- sudo nsenter -t "$PROBE_PID" -n ip route del default
limactl shell "$GW" -- sudo nsenter -t "$PROBE_PID" -n \
  ip route replace default via 10.211.0.1

# ASSERT THE ROUTE INSTALLED — this is what the earlier version missed:
limactl shell "$GW" -- sudo nsenter -t "$PROBE_PID" -n ip route show default \
  | grep -q "via 10.211.0.1" || { echo "FAIL: route not installed; assertion is vacuous"; exit 1; }

limactl shell "$GW" -- docker exec probe curl -sS --max-time 8 http://example.com/
echo "exit=$?"
```

- **Expected:** a block. **Exit 0 is outcome (c)** — the decision dies.
- **This is the only assertion that proves *topological* control rather than *policy*
  control**, and it is the lite analogue of the spec-mandated full-backend regression
  (`.tasks/specs/2026-05-02-macos-support-design.md:610`).
- **It also has no durable successor unless phase 6 builds one.** The script is deleted at
  phase 0's exit and `test_lite_macos.py` has no route-manipulation test. Phase 6 carries
  an explicit criterion for this; do not let it lapse.

#### Assertion 5 — hostile VM (the §1.6 property)

**New, and it is the one assertion that can detect the cross-operator hole.** §3.7's
existing isolation check pings between two **cooperatively configured** VMs, so of course
they cannot see each other — neither was given a NIC on the other's slots. It measures the
daemon's configuration, not the boundary.

As operator B, hand-write an instance naming one of **operator A's** slot sockets — the
same one-line YAML any operator can write — and try to start it:

```bash
# as operator B, with SLOT_A belonging to operator A:
cat > /tmp/hostile.yaml <<YAML
vmType: "qemu"
images: [{location: "<image>", arch: aarch64}]
networks:
  - socket: "/var/run/sandbox/vmnet/slot-${SLOT_A}.sock"
YAML
limactl create --name=hostile --tty=false /tmp/hostile.yaml && limactl start hostile
```

- **Expected once §1.6 lands: failure at connect** — the kernel refuses, because the
  socket's group does not include B.
- **Expected today: success.** That is the point of the assertion, and a green here before
  §1.6 is the finding, not a bug in the gate. Record which.
- **If it succeeds after §1.6 lands:** outcome (d) in §3.8.

#### Explicitly **not** asserted: the deny-event JSONL

The project already made this call, and the reasoning is recorded at
`tests/e2e/test_lite_macos.py:422-427`: the JSONL event capture proved unreliable to
assert on, because **the event stream is a best-effort observability sink, not the
enforcement mechanism.** Capture events in the gate as **diagnostics** — they help when
reading a red run — but never as a pass condition.

### 3.7 Second-operator probe

Stand up a **second** VM as a **different uid**, on a **disjoint slot range**, and repeat
§3.4–§3.6 against it.

⚠️ **Attach and address the slots.** An earlier draft asserted that operator B "gets a
distinct `/29` from `vmnet_slot_addresses` and a distinct identifier from
`vmnet_slot_network_identifier`" — but both are pure functions of the slot index
(`network.rs:954`, `:897`), so with nothing attached that reduces to calling two pure
functions and comparing their outputs. It proves arithmetic, not isolation. Both VMs must
hold NICs on their own slots **with endpoints actually addressed on the `/29`s** for the
reachability assertions to mean anything.

```
VM A (operator A): slots {0..3}, endpoint on slot 0's /29
VM B (operator B): slots {4..7}, endpoint on slot 4's /29
```

Assertions:

1. **Egress is enforced in both** — §3.6 assertions 1–4 hold independently in each VM.
2. **Neither VM can reach the other's segment**, with endpoints actually present:

   ```bash
   # From VM A, with B_BASE = 10.209.128.0 + 8*<B's slot>:
   limactl shell "$GW_A" -- ping -c 2 -W 2 <B_BASE+3>    # expect: 100% packet loss
   limactl shell "$GW_A" -- arping -c 2 <B_BASE+3>       # expect: no reply
   ```

   The in-tree precedent is `integration_vmnet_inter_slot_l2_isolation` (`network.rs:3021`).

3. **The hostile-VM assertion (§3.6 assertion 5)** — the one that tests the boundary
   rather than the configuration.

⚠️ **Prerequisite: issue #85 must be fixed first**, and the second operator must be a
**dedicated account in the correct group** — not another member of Apple's reserved
`_sandbox` (gid 60), which was considered and rejected as deepening #85. It also needs a
daemon-provisioned LIMA_HOME; it cannot create one itself
(`ensure_operator_lima_home`, `lima.rs:574-660`, is daemon-side only).

### 3.8 Failure discrimination — a red run must say which

| Outcome | Signature | Effect on the decision |
|---|---|---|
| **(a) Socket-permission failure** | `limactl start` cannot open the slot socket; the forwarded Docker socket is unreachable; permission errors before any assertion runs | fixable; decision **survives** |
| **(b) Per-operator segment-allocation failure** | VMs start and enforce, but §3.7 assertion 1 or 2 fails — NIC identity wrong, address collision, or cross-segment reachability between cooperating VMs | points at a split model; decision **survives, modified** |
| **(c) Interception coupled to daemon ownership** | assertion 1 or 4 fails with a **verified-correct** route, for a reason that is not (a) or (b) | decision **dies**; `shared:` needs another mechanism |
| **(d) Socket DAC does not bind slot→operator** | §3.6 assertion 5 succeeds **after §1.6 lands** — a hostile VM still attaches to a foreign slot | §1.6's mechanism is wrong or incompletely applied. Decision survives; the isolation claim does not, and §5.1's gateway-axis delta must be retracted rather than qualified |

**Outcome (d) is new.** An earlier draft had three outcomes, none of which covered the
cross-operator hole — so the gate could have gone green with it wide open and the failure
would have had no bucket. Two other conditions previously had no bucket either and are now
prevented rather than classified: the health-wait deadlock (fixed by the §3.4 ordering) and
a structurally impossible table assertion (fixed in assertion 3).

For **(a)** the prior evidence is favourable: access is group-scoped rather than uid-scoped
(`network.rs:1027`), the sockets carry no ACLs, and **sandbox session VMs already run
operator-owned QEMU against these sockets in production** (`lima.rs:3607, 3617-3618`).

### 3.9 Teardown

```bash
limactl shell "$GW" -- docker rm -f probe gw || true
limactl shell "$GW" -- docker network rm gate-session sandboxd-egress || true
limactl stop --force "$GW" && limactl delete "$GW"
limactl delete hostile 2>/dev/null || true
```

**Assert it worked** — "no residue" without a check is not a criterion:

```bash
limactl list --json | grep -q "egress-gate-" && echo "FAIL: gate instance survived"
```

Teardown is idempotent, so a failed run can be cleaned up and the procedure repeated while
the question is live. It **must not touch `sandboxd-gateway` or any real instance**.

When the question is answered, **delete the script** (see
[Form and lifetime](#form-and-lifetime-a-throwaway-shell-script)).

---

## 4. Phases

Each phase states its goal, dependencies, the files and functions to change, and
**acceptance criteria you can execute**. Phases are ordered; phase 6 runs continuously.

**⚠️ The phase order changed.** Ownership used to be phase 2, before the brokered-ops
work. It is now phase 4, and the boundary is hard. The reason is §4's single most
important sequencing fact:

> The forwarded Docker socket lives **inside the Lima instance directory** —
> `daemon_lima_home.join(GATEWAY_INSTANCE_NAME).join("gateway-docker.sock")`
> (`gateway_lima.rs:775-777`). By §2.1's own argument that directory is created by the
> operator's `limactl` and lands `0700` operator-owned. **The instant ownership flips, the
> daemon cannot reach Docker at all** — not through a different path, not with an env
> change: `gateway_docker_socket()` has ~35 call sites, and the five direct
> `limactl shell|copy` sites (`gateway_lima.rs:1614, 1642, 1757, 1865, 2082`) would
> additionally need the operator-owned SSH key at `_config/user`.

An earlier draft treated this as one env-var row in the ownership phase's file table. It
is not: ownership landing before the brokered ops produces a gateway manager that cannot
reach its own VM, with acceptance criteria that are unreachable by construction.

**Accepted cost of the reorder.** The new ops (phases 2–3) cannot be exercised
end-to-end until ownership flips in phase 4 — they are built against a daemon-owned VM
that does not yet need them. **Mitigation, and it is required, not optional:** phases 2
and 3 each stand up a **scratch operator-owned VM inside an integration test** and
exercise their ops against it. They must not ship on unit tests alone.

**The feature issue #82 is named for still lands last.** `shared:` with real project
paths cannot work until the VM is operator-owned, which cannot land until the brokered
control plane exists, which should not land until slots partition and egress is proven.
Everything before phase 5 is infrastructure for a user-visible change that appears only at
the end. Say so when reporting progress; otherwise phases 1–4 look like no progress at
all.

---

### Phase 0 — Pre-checks and the egress validation gate

**Goal.** Answer whether egress remains enforced when the gateway VM is operator-owned,
before committing to the migration.

**Depends on.**

- **Part A (§3.1–§3.6, single-operator):** nothing beyond the environment in
  [Before you start](#before-you-start).
- **Part B (§3.7, second-operator isolation): issue #85 must be fixed first** — create the
  real `_sandboxd` account, regenerate the vmnet plists correctly, then add a dedicated
  test-operator account to the proper group. A prerequisite, not a related concern.

**Implements.** §3.

**Files.** One throwaway shell script. **No production code changes** — §3.4 step 1 now
hand-writes the Lima YAML precisely so this holds. The script may be committed for
reproducibility while the question is live, and **deleting it is part of this phase's
exit**.

**Acceptance criteria — Part A (runnable immediately).**

- [x] ~~Pre-check A~~ — **done.** `interface:` is honoured on `socket:` networks
      (§1.4 fix 1). Note its two limits: verified through bare `limactl`, **not** the
      broker path (§1.1a), and on Lima 2.1.2, **not** the declared 1.2.0 floor.
- [ ] Pre-check B (§3.1) run; result recorded.
- [ ] **Pre-check C (§2.9) run** — does an operator's VM survive logout? Records whether
      §2.4 and the §5.1 logged-out delta describe a real state.
- [ ] Host `net.inet.ip.forwarding` recorded as context (§3.2) — **not** gated on.
- [ ] Single-VM gate: assertions **1–4** (§3.6) all pass, **in that order**, with §3.5's
      route verified before assertion 1 runs. (Assertion 5, hostile VM, needs a second
      operator and is Part B.)
- [ ] A deliberately broken run (skip §3.5) produces a **red** result at **assertion 1**,
      not later. *Test your test* — and note this is only satisfiable because assertion 1
      now asserts the discriminating signature (§3.6).
- [ ] Any red result names outcome (a), (b), (c) or (d) per §3.8.
- [ ] Teardown leaves no residue: `limactl list` shows no `egress-gate-*` instance, and
      `docker network ls` inside any surviving VM shows no `gate-session`. Assert both;
      "no residue" without a check is not a criterion.

**Acceptance criteria — Part B (gated on issue #85).**

- [ ] `_sandboxd` account exists, vmnet plists regenerated correctly **and reloaded**, and
      a **dedicated test-operator account** exists in the proper group (not gid 60).
- [ ] That account has a provisioned LIMA_HOME. It cannot create one itself — the parent
      `{state_root}/{daemon_uid}/{op_uid}` is daemon-owned and provisioning is
      `ensure_operator_lima_home` (`lima.rs:574-660`), daemon-side only. Budget a
      daemon-driven provision step.
- [ ] Second-operator isolation probe (§3.7): all assertions pass, **including the hostile
      VM assertion** — which is expected to **fail** until §1.6 lands. Record which.

**Exit (both parts).**

- [ ] Findings recorded in this spec and on issue #82. The findings are the durable
      artifact.
- [ ] **The gate script is deleted.** It is not carried into phase 1 and not inherited by
      anyone.

**Gating rule — this was previously ambiguous and is now explicit.**

**Phase 1 may start on a green Part A. Part B gates phase 1's *completion*, not its
start.** The rationale: Part A proves the enforcement substrate works at all — it is what
detects outcome (c), the decision-killing one — while Part B validates the isolation
property phase 1 exists to deliver. Starting phase 1 without Part B is acceptable;
*finishing* it without Part B would mean shipping partitioning whose central claim is
untested.

Red → route per §3.8; only (c) kills the decision.

---

### Phase 1 — Per-operator slot partitioning and socket groups

**Goal.** More than one `VmnetPool`, each owning a disjoint slot range that the **kernel**
enforces, with slot identity no longer positional.

**Depends on.** Phase 0 Part A green. Part B green before this phase completes.

**Implements.** §1.2, §1.3, §1.4, §1.5, §1.6, §2.2.

**Files and functions.**

| File | Change |
|---|---|
| `sandbox-core/src/network.rs:999-1030` (`generate_vmnet_plist`) | **§1.6** — emit a per-operator `--socket-group`; the plist gains an operator dimension it has never had |
| `Makefile` `setup-darwin-vmnet-plists`; `scripts/install.sh` plist + enrollment path (`:2679`) | **§1.6** — create the per-operator group and assign the slot range at enrollment; **and specify de-enrollment in the same change**, revoking group membership *before* a range may be reassigned |
| new, daemon-side | **§1.3** — derive each operator's range by `stat`-ing `/var/run/sandbox/vmnet/slot-N.sock`, reading its gid and resolving members. No config file. Defined behaviour for zero-member and multi-member groups (both: slot unassignable) |
| `sandbox-core/src/network.rs` (`NetworkInfo`) | **§2.1** — new `operator_uid: Option<u32>` with `#[serde(default)]`; `restore_from_infos` shards by it, falling back to `owner_username` and declining the claim if that fails |
| `sandboxd/src/main.rs:11156-11157` | diagnostics gains a declined-restore list alongside the claimed-slot one (§2.1) |
| `sandbox-core/src/network.rs:1090-1421` | `VmnetPool` unchanged in shape; range-scoped `claim_lima_slot` scan (`:1169-1170`), quota-scoped cap checks (`:1161`, `:1208`), range-aware `restore_from_infos` (`:1320`), operator dimension on `claimed_slot_sessions` (`:1406`) |
| new | uid-keyed `VmnetPoolRegistry` — copy `LimaManagerRegistry`'s **locking discipline** (`lima.rs:1245-1280`), not its fields (§1.1) |
| `sandbox-core/src/gateway_lima.rs:282-316` | `discover_nics_from_ip_json` — key by parsed suffix; **and** build the map daemon-side, using guest output only to verify (§1.4 fix 2) |
| `sandbox-core/src/gateway_lima.rs:334-381` | `generate_gateway_template` — take a slot set; emit `interface: lima<slot>` per entry; **guard the correspondence in the generator** (§1.4 fix 1a) |
| `sandbox-core/src/gateway_lima.rs:1286`, `:872` | `create_instance(&self, slots: &[u16])` — slot set passed as an argument (§1.4 fix 3); threads through `ensure_ready` |
| 15 call sites | `generate_gateway_template` — 1 production + 14 in tests across 13 test functions (§1.4 fix 3) |
| `sandboxd/src/main.rs:4362-4370`, `:12811-12820` | replace the bare `unwrap_or_else(\|\| format!("lima{}", …))` with a hard error |
| `sandboxd/src/main.rs:9884-9900` | **different site** — hard-error only when the persisted `bridge_name` is also empty (§1.4 fix 4) |
| `sandboxd/src/main.rs:9884-9888`, `:12811-12816` | hard-error `unwrap_or(0u16)` on the **slot index** — the silent segment guess (§1.4 fix 4) |
| `sandbox-core/src/gateway_lima.rs:99` | decide whether to bump `MIN_LIMA_VERSION` above 1.2.0, or add the runtime NIC-name assertion (§1.4 fix 1) |
| `sandboxd/src/main.rs:13402-13440` | `SANDBOX_MAX_MACOS_SESSIONS` parse — reconcile with the per-operator range read |
| `sandbox-core/src/error.rs:9` | **new structured `SandboxError` variant** for 429 — operator uid, in-use count, quota, with a `Display` impl (§2.2). The enum lives here, not in `sandboxd/src/error.rs` |
| `sandboxd/src/error.rs:57-79` | new arm in `error_response`; reuse existing `Conflict → 409` (`:69`) for range-unavailable |
| `sandbox-core/src/network.rs:1161-1176`, `:1208-1213` | rewrite the exhaustion message (§2.2 condition 1) |

**Acceptance criteria.**

- [ ] `cd sandboxd && cargo build --workspace && cargo clippy --workspace && cargo fmt --all --check`
      all clean, **on macOS** — see the platform note below.
- [ ] `make test` passes.
- [ ] A unit test proves `discover_nics_from_ip_json` maps `lima4..lima7` to slots
      **4..7**, not 0..3.
- [ ] A unit test proves `generate_gateway_template(&[4,5,6,7])` emits exactly four
      `socket:` entries naming `slot-4..slot-7`, with matching netplan and IPv6-disable
      lines.
- [ ] A unit test proves that for **every** emitted network entry,
      `interface == format!("lima{slot}")` — iterate the entries, do not spot-check one.
- [ ] A unit test proves a missing NIC-map entry returns `Err` at the **create** and
      **recovery** sites; and at the **restart** site returns `Err` only when the
      persisted `bridge_name` is also empty. Assert the restart site still succeeds from
      the persisted value with an unpopulated map — this is the regression an earlier
      draft would have caused.
- [ ] A unit test proves a missing `vmnet_slot` returns `Err` rather than defaulting the
      slot index to 0.
- [ ] Two pools with disjoint ranges never hand out the same slot index, and a pool cannot
      hand out an index outside its range — **including via `restore_from_infos`**.
- [ ] **Per-operator exhaustion returns 429**; **range-unavailable returns 409**; the two
      are distinguishable by status code alone, and the 409 body does **not** name the
      holding operator (§2.2).
- [ ] **Single-operator behaviour is unchanged**: with a default single-operator
      enrollment, one operator still gets 8 concurrent sessions and slot indices still
      start at 0. This is the regression that matters most.
- [ ] **§1.6 holds at the kernel, not the ledger:** as operator B, `limactl start` on a
      hand-written instance naming one of operator A's slot sockets **fails at connect**.
      This is the criterion that distinguishes this phase from bookkeeping. It is the same
      assertion as §3.7's hostile-VM probe.
- [ ] **De-enrollment revokes before it reassigns** (§1.6): after de-enrolling operator A
      and reassigning their range to operator B, the **same hostile-VM assertion run as A**
      fails at connect. Assert the ordering too — a reassignment attempted while A is still
      in the group leaves the slot unassignable rather than shared.
- [ ] **Range derivation matches the sockets** (§1.3): changing a slot socket's group
      changes the derived owner with no config edit and no daemon restart beyond a
      re-read. A slot whose group has **zero** members is unassignable and reported; a slot
      whose group has **two or more** is unassignable and reported prominently — assert
      that the daemon refuses to pick one.
- [ ] **Restore shards correctly** (§2.1): sessions carrying `operator_uid` land in the
      right pool; a record lacking it is resolved via `owner_username`; and one where that
      resolution fails is **declined and surfaced in diagnostics**, not guessed and not
      dropped silently.
- [ ] The 429 variant is **structured** and renders its message from `Display`, and the
      three former message copies (`network.rs:1161-1176`, `:1208-1213`) are gone rather
      than rewritten in place (§2.2).
- [ ] The instance socket path stays under `UNIX_PATH_MAX` — assert with a computed check
      against 104, not by inspection (§2.8).

**Platform note.** `VmnetPool`, `GatewayLimaManager`, `generate_gateway_template`,
`discover_nics_from_ip_json` and the NIC-name sites are all `#[cfg(target_os = "macos")]`.
On Linux, `cargo build --workspace`, `cargo clippy --workspace` and `make test` compile and
lint **none** of this phase's code. These criteria are only meaningful on a Mac.

**Previously open, now specified above:** the range configuration surface (derived from
socket gids, §1.3), `restore_from_infos` sharding (`operator_uid` on `NetworkInfo`, §2.1),
the 429 variant's shape (structured, §2.2), and de-enrollment (§1.6). None of them is an
open question any more; all four are acceptance criteria.

---

### Phase 2 — Docker broker ops and brokered streams

**Goal.** A brokered control plane for the operator's in-VM Docker daemon, in place
**before** ownership flips and takes the direct socket away.

**Depends on.** Phase 1.

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
| `sandbox-core/src/network.rs:401-415` | create the per-session network with masquerade disabled, so the pre-route window fails closed (§2.5) |

**Acceptance criteria.**

- [ ] **A scratch operator-owned VM is stood up in an integration test and the new ops are
      exercised against it.** This phase must not ship on unit tests alone — it is built
      before the thing that needs it, and this is the mitigation for that.
- [ ] No production `docker` invocation targets an operator VM's socket directly from the
      daemon.
- [ ] The op enum remains closed: **no** `DockerExec { args: Vec<String> }` or equivalent
      argv pass-through. A reviewer can enumerate every op.
- [ ] Env hygiene lives on the agent: `DOCKER_HOST` / `DOCKER_CONFIG` scrubbed,
      `-H unix://<own socket>` the sole target authority. `docker` resolved from a fixed
      candidate list, not a `PATH` search (mirror `resolve_rsync`, `handler.rs:935-948`,
      not `resolve_limactl`, `:125-143`).
- [ ] Any `sh -c` path built from daemon-supplied input is validated agent-side against an
      allowlist. Watch `policy_distributor.rs:39-48` (no escaping of embedded quotes) and
      `macos_session.rs:786` (guarded only by a `debug_assert!`, compiled out in release).
- [ ] The pre-route window fails closed: a container whose route helper has not yet run
      **cannot** reach the internet (§2.5). Assert it directly.
- [ ] **Pipelining by `request_id` is implemented** (§2.5): independent ops for one
      operator complete concurrently rather than strictly serially, and a dependent
      sequence (create → start) still completes in order because the caller awaits each
      response.
- [ ] **The agent's handlers have been audited for concurrency safety** — process-global
      state, filesystem staging paths, colliding `limactl` working sets. This is a
      **named work item**, not a side effect of the protocol change; record what was
      audited and what was found (§2.5).
- [ ] `make test-e2e-container` passes.

---

### Phase 3 — Typed route-helper broker op

**Goal.** Replace the `limactl shell … sudo sandbox-route-helper` argv path with a typed
op — and restore the authorization control that ownership removes.

**Depends on.** Phase 2. **Must precede phase 4** for the same reason phase 2 does: the
current invocation is one of the five `limactl shell` sites the daemon loses at ownership.

**Files.** `sandbox-agent/src/protocol.rs` — add
`InstallContainerRoute { container_pid, gateway_ip }`; `sandbox-core/src/lite_macos.rs:262-277`
— `build_in_vm_route_helper_argv` moves agent-side; call sites `main.rs:5360-5364` and
`:6091`; `sandbox-route-helper/src/main.rs:327-338` (`run_vm_gateway_mode`);
`gateway_lima.rs:471` (the sudoers grant); doc comments in `lite_macos.rs:241-256` and
`sandbox-route-helper/src/main.rs:55-84`, `:311-319`.

**Acceptance criteria.**

- [ ] The op carries exactly two caller-supplied values (`container_pid`, `gateway_ip`);
      VM name, `sudo`, helper path and mode flag are agent-side constants.
- [ ] Route installation works on create **and** on restart.
- [ ] **`run_vm_gateway_mode` rejects a `gateway_ip` that is not on the container's own
      subnet.** This is a new control, not a doc change — it enforces what the module doc
      at `:81-84` already claims (§5.2).
- [ ] The blanket `ALL ALL=(root) NOPASSWD:` sudoers grant (`gateway_lima.rs:471`) is
      narrowed, so an interactive `limactl shell` is not automatically a route-rewrite
      primitive.
- [ ] Only then: the stale perimeter claim is corrected in **both** files, describing the
      perimeter that now exists.
- [ ] A scratch operator-owned VM integration test exercises the op (same rationale as
      phase 2).

---

### Phase 4 — Per-operator gateway VM ownership

**Goal.** One gateway Lima VM per operator, created and driven as that operator through
the broker.

**Depends on.** Phases 2 and 3 — **hard boundary**, for the reason in this section's
preamble. Phase 1 supplies the range.

**Implements.** §1.1, §1.1a, §2.1, §2.3, §2.4, §2.6, §2.9.

**Files and functions.**

| File | Change |
|---|---|
| `sandbox-agent/src/validation.rs:363`, `:491-547`; `handler.rs:416`, `:430`, `:512` | **§1.1a — split the YAML validator by VM class.** Session rule unchanged; new gateway rule allowing N entries and `{socket, interface}`, requiring `interface == lima<n>` parsed from the socket path. Gateway-shaped variants for `validate_cidr_owner` and `validate_qemu_wrapper`. **Separately reviewable; this is a TCB boundary** |
| `sandbox-core/src/gateway_lima.rs:771-2272` | `GatewayLimaManager` takes an `op_uid`; the six executor calls (`:1245, 1323, 1362, 1931, 2122, 2164`) pass the operator uid |
| new | `GatewayLimaManagerRegistry` — locking discipline from `LimaManagerRegistry` (`lima.rs:1245-1280`) |
| `sandbox-core/src/gateway_lima.rs:672` | `apply_limactl_env` — operator LIMA_HOME |
| `sandbox-core/src/gateway_lima.rs:84` + use sites | instance name becomes `sandboxd-gateway-<operator_uid>` (§2.6) |
| `sandbox-core/src/lima.rs:460-490` (`reap_lima_orphans_inner`) **or** `:350` with a new `name` parameter | **explicit** gateway exclusion — `decide_lima_vm` never sees a name (§2.6) |
| daemon-side name-keyed maps | re-key by operator uid — a name is only meaningful with its LIMA_HOME (§2.6) |
| `sandboxd/src/main.rs:1339`, `:1349`, `:1373` | `AppState` — pool, manager and recovery latch become uid-keyed |
| `sandbox-core/src/gateway_recovery.rs:179`, `:249-266` | operator scope on `GatewayRecoveryDeps` **or** a filtering impl — decide which (§2.6); per-operator latch |
| `sandboxd/src/main.rs:12766`, `:12910` | `recover_gateway_lima` / `gateway_lima_monitor` — per-operator |
| `sandbox-core/src/backend/orphan_reaper.rs:566`; `sandboxd/src/main.rs:13978, 13984` | reap once per operator VM; gate on `connected_uids` (`broker.rs:680-683`) |
| `sandbox-core/src/store.rs:245, 266, 286, 342-360` | neuter the V006 Docker scan — because it targets the **host** daemon with no `-H` (§2.4), not because of logout |
| `sandboxd/src/main.rs:13327-13724` | startup block no longer builds exactly one pair; untangle the throwaway pool (`:13514-13521`) |
| `Makefile:1220, 1268, 1946, 1995, 2042` **and** `scripts/install.sh:3030`, `:3240` | image / route-helper staging gains an operator dimension. **There is no production `stage-gateway-image` make target** — production staging lives in `install.sh`, which an earlier draft's file list omitted |
| docs | login dependency (§2.3) and the logged-out behaviour (§2.4, §2.9) are user-visible |

**Acceptance criteria.**

- [ ] **With per-operator enrollment configured**, two operators each get their own gateway
      VM, in their own LIMA_HOME, on disjoint slot ranges.
- [ ] **With a single-operator enrollment**, a second operator's gateway-VM create is
      refused with the **409** of §2.2 condition 2 — no rebalancing, no bouncing of the
      first operator's VM.
- [ ] `limactl list` as operator A does not show operator B's gateway VM.
- [ ] The validator split holds: a **session** VM template with two `networks:` entries, or
      with an `interface:` key, is still **rejected**; a **gateway** template with N
      entries and correct `interface: lima<n>` values is accepted; and a gateway template
      whose `interface:` disagrees with its socket path's `slot-<n>` is **rejected**.
      Assert all four.
- [ ] With the orphan reaper enabled and a gateway VM running, a full reap cycle **does
      not delete it** — assert by changing the exclusion and watching the reap test fail.
- [ ] Recovering operator A's gateway VM does **not** suppress operator B's per-session
      gateway monitor, and does **not** tag or recover operator B's sessions (§2.6).
- [ ] Creating a session for a **logged-out** operator fails with the
      `agent_not_running_error` text (`broker.rs:278`) — not a hang, not a panic.
- [ ] Agent eviction mid-operation leaves recoverable state. **Procedure:** send `SIGKILL`
      to the agent while a `Create` is outstanding, then assert the VM is either absent
      (`limactl list` shows nothing, and a re-create succeeds) or present and startable.
      A stranded half-state is a VM that exists and cannot start.
- [ ] **The instance socket path still fits `UNIX_PATH_MAX`** (§2.8). This phase is where
      the name grows to `sandboxd-gateway-<operator_uid>`, so assert it here with a
      computed check against 104 — phase 1's identical criterion was evaluated against the
      old, shorter name.
- [ ] `cargo nextest run --workspace --profile integration` passes (Docker required).
- [ ] Egress enforcement is re-verified on the new shape. **The §3 gate script no longer
      exists** — deleted at phase 0's exit — so this rests on phase 6's retargeted e2e
      coverage. **If that coverage is not in place when this phase lands, building it is
      part of this phase.** Do not resurrect the throwaway script, and do not land
      ownership with no egress test at all.

---

### Phase 5 — Real `shared:` workspaces (the feature #82 is named for)

**Goal.** `--workspace shared:<path under a declared export root>` works on macOS lite.

**Depends on.** Phase 4. **Not on issue #83** — the declared-roots mechanism bounces the VM
only when the *roots* change, not on every `shared:` create (§5.1).

**Mechanism: operator-declared export roots** (§5.1). An earlier draft specified this phase
as a list of deletions with no replacement, which does not work: the deleted
`lite_shared_root_9p_stanza` is *how a host path becomes visible inside the gateway VM at
all* (`gateway_lima.rs:355-356` → interpolated at `:409-415`), and Docker's `--mount src=`
resolves **inside** the VM (`backend/container.rs:772`), so a bind can only reach what 9p
already exported.

**This is a generalisation of the existing mechanism**: one fixed root becomes N declared
roots. The stanza generator is re-pointed, not removed.

**Files.**

| File | Change |
|---|---|
| `sandbox-core/src/lite_macos.rs:110` | `lite_shared_root_9p_stanza` — generalise from one root to a declared set; **keep it**, do not delete |
| `sandbox-core/src/gateway_lima.rs:355-356`, `:409-415` | template interpolation takes the declared set |
| new | where an operator declares roots (JSON per project convention), and validation that each is an absolute, existing, operator-readable directory |
| `sandbox-core/src/lite_macos.rs` | **delete** `validate_shared_path` (`:159`), `translate_shared_path` (`:134`, already dead), `SharedPathError` (`:172-216`), `lite_shared_root` (`:76`), `DEFAULT_LITE_SHARED_ROOT` (`:54`), `LITE_SHARED_ROOT_ENV` (`:32`) |
| new, replacing them | containment check against the **declared roots**, with canonicalization (§5.1) |
| `sandboxd/src/main.rs:5072` | call site moves to the new check |
| `Makefile:2110-2135` | `setup-darwin-sandbox-shared` — the fixed root is no longer created |
| `docs/guides/lite-mode.md:55-95` | rewrite; **document the Apply-&-Restart UX** (§5.1) |

**Acceptance criteria.**

- [ ] With `~/Projects` declared as an export root,
      `sandbox create --lite --workspace shared:$HOME/Projects/foo` succeeds and the
      container sees the real directory.
- [ ] **A path outside every declared root is refused at create**, naming the declared
      roots and how to add one.
- [ ] **Bidirectional write**: host→container and container→host. Assert host-side
      ownership with `stat -f '%u'` and state the expected uid — 9p `mapped-xattr` does not
      necessarily produce the operator's uid on the host, and "owned by the operator" is
      not a testable claim without naming the mapping.
- [ ] **Canonicalization against the declared roots** — resolve the requested path, then
      require containment in a declared root. A path using `..` or a symlink to escape a
      declared root is rejected. (This criterion is now well-defined precisely because the
      roots are declared; against "the requested subtree" it was circular.)
- [ ] Changing the declared roots takes effect after a VM bounce, and the operator is told
      so rather than seeing a silently stale export set.
- [ ] `src=` values containing `,` or `=` are rejected (§5.1).
- [ ] The replacement refusal names the cause and the working alternatives, preserving the
      intent of the deleted `outside_root_error_names_cause_and_alternatives` test.
- [ ] Linux lite `shared:` with an arbitrary host path is unchanged.
- [ ] Full-backend `shared:` is unchanged on both platforms.
- [ ] `docs/guides/lite-mode.md`'s macOS section matches what the code now does.

---

### Phase 6 — Test and docs retarget (continuous)

**Goal.** The suite stops assuming one daemon-owned gateway VM and a host Docker daemon.

**Depends on.** Runs alongside phases 1–5. Do not defer it to the end. **Phase 4's egress
criterion depends on this phase**, so the chain phase 4 → phase 6 → issue #84 is real and
#84 currently has no owner in this plan.

**Why continuous.** The surface is not a tail:

- `sandboxd-gateway` appears **31 times** across `tests/e2e/` (conftest 5,
  `test_networking` 16, `test_lite_macos` 8, `test_fullbackend_macos` 2).
- `tests/e2e/conftest.py:1062` hard-codes the singleton name in a
  **delete-everything-else** state-dir sweep — under per-operator VMs it would delete
  every operator's instance dir on every pytest session.
- **The LIMA_HOME formula disagreement is wider than two sites — there are seven.** Truth
  is `{root}/{daemon_uid}/{op_uid}/lima` (`lima.rs:197-199`). Wrong 2-level forms:
  `gateway_lima.rs:7` (module doc), `:772`, `:797`, `docs/concepts/networking.md:272` and
  `:273`, `tests/e2e/test_networking.py:1511`, and — **user-facing and currently broken** —
  `docs/guides/troubleshooting.md:32`, a `GW_SOCK=` snippet operators are told to run.
  (`gateway_lima.rs:776-777` states the socket path relative to `daemon_lima_home`, so it
  inherits the error rather than repeating it — fix the root and it becomes correct.)
- **The larger coupling:** the cross-backend suite's structural gateway assertions run
  against a **host** Docker daemon that does not exist on macOS — `conftest.py:629-638`
  (`_preflight_checks` skips the entire session when `docker info` fails),
  `test_networking.py:374`, `test_policy.py:61, 112`.
- `test_lite_macos.py:184-238` (`_gateway_vm_sees_path`) drives the VM as the **daemon**
  user and exists only to guard against a stale 9p export. Both it and the failure mode
  disappear — **replace it, do not port it.**
- `test_networking.py:1765` asserts the singleton's cross-session blast radius **as
  behaviour**. Under per-operator VMs the correct assertion **inverts**. New test, not a
  retarget.

**Acceptance criteria.**

- [ ] Issue #84 closed first — `linux_only` applied to the tests whose bodies assert on
      systemd, cgroup v2 or `sandbox-lima-helper` (`test_hardening.py:37`,
      `test_cross_user_helper_pivot.py:42`). Until then `make test-e2e-macos SCOPE=full`
      collects the whole Linux matrix and this phase cannot run.
- [ ] No test hard-codes a single gateway instance name in a destructive sweep.
- [ ] **All seven** LIMA_HOME sites agree, including the user-facing `GW_SOCK=` snippet at
      `troubleshooting.md:32` and the module doc at `gateway_lima.rs:7`.
- [ ] A cross-operator isolation test exists and asserts the **inverted** property.
- [ ] **A durable macOS-lite bypass-resistance test exists** — delete the helper-installed
      route, install one via the Docker bridge gateway, assert the block. This is the lite
      analogue of the mandated full-backend regression (`test_networking.py:698`), and it
      must not die with the throwaway gate script. Phase 4's egress criterion rests on it.
- [ ] `make test-e2e-container` and `make test-e2e-macos SCOPE=full` pass.
- [ ] Docs updated: `docs/concepts/networking.md:265`, `:271-273`, `:301`;
      `docs/guides/macos-operations.md:82`; `docs/guides/lite-mode.md:56, 62`;
      `docs/guides/troubleshooting.md:29-32`; `docs/reference/cli.md:1326`; `README.md:60`;
      `networking-design.md:262, 283` (repo root, not under `docs/`).

---


## 5. Deltas, corrections and related issues

### 5.1 Accepted security deltas

#### The export mechanism: operator-declared roots

**Decided.** The operator declares which host roots are exportable — `~/Projects`, say.
Those roots are 9p-exported into their gateway VM **at VM creation**, and each session's
Docker bind `src=` selects a subtree within them.

**Frame this as a generalisation, not a new mechanism.** Today there is exactly one
exportable root and it is fixed at `/tmp/sandbox-shared` (`lite_macos.rs:54`). This
replaces *fixed* with *operator-declared*. The export plumbing, the identity mount, and the
bind-selects-a-subtree shape are all unchanged.

Consequences:

- **No VM bounce per `shared:` create**, because the roots are already exported. **Phase 5
  therefore does not depend on issue #83** — an earlier draft said it might.
- **Blast radius on a container escape is the declared roots**, not the operator's whole
  home. That is what makes the workspace delta below bounded enough to accept.
- **§5.1's canonicalization requirement now has well-defined roots to resolve against**,
  which is what turns it from aspirational into enforceable: resolve the requested path and
  require containment within a declared root.
- **UX: changing your export roots requires bouncing your VM** — exactly Docker Desktop's
  "Apply & Restart". Familiar and acceptable, but say it in the docs rather than letting
  operators discover it.

⚠️ **One residual edge, stated because it is easy to miss:** a *root change* still bounces
the VM, and under issue #83 that destroys the operator's running lite sessions with no
recovery. The per-create dependency on #83 is gone; a per-root-change one remains. It is
far milder — root changes are rare and operator-initiated, unlike every `shared:` create —
but "phase 5 does not depend on #83" is true only for the create path.

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

Consequently `..` traversal and symlinks go unresolved: `/tmp/sandbox-shared/../../Users/alice`
passes `strip_prefix` and would be handed to `docker create --mount src=…`.

**This is prospective, not a live hole — an earlier draft implied otherwise.** Today the
`src=` path is resolved by dockerd **inside the gateway VM**, where only the shared root is
9p-mounted, so the traversed path resolves to the *VM's* `/Users/alice`, which does not
exist — and `--mount type=bind` errors on a missing source rather than creating it
(`container.rs:866-874`). The correct statement is: **the textual check is unsound and
becomes exploitable the moment the export root widens**, which is exactly what the
shared-root phase does.

**Canonicalization is necessary but not sufficient**, and the criterion an earlier draft
wrote for it was circular — "reject a path that escapes the requested subtree" is vacuous
when the requested path *defines* the subtree. Two further requirements:

- **Name the containment root explicitly.** With declared export roots (above) the roots
  are exactly that: resolve the requested path, then require containment within one of the
  operator's declared roots. This is what makes the requirement enforceable — against "the
  requested subtree" it was circular, because the requested path defined the subtree.
- **Close the resolve-then-mount race structurally.** The daemon canonicalizes; Docker
  resolves `src=` again later, inside the VM, from a different process. A sandboxed agent
  with write access to the tree — which is the feature — can swap a path component for a
  symlink in between. Re-checking the string narrows the window; it does not close it.
  **Make the resolved path the 9p export root**, so a later symlink swap cannot widen what
  the VM can see.
- **Reject `,` and `=` in the path**, or stop using a comma-delimited mount spec.
  `format!("type=bind,src={},dst={}", …)` (`container.rs:772-785`) has no escaping, so
  once operators supply arbitrary paths, `…/proj,bind-propagation=rshared` is a well-formed
  extra mount option. Operator-supplied, so robustness rather than escalation — but it
  lives in the function being changed.

**Also preserve the refusal's quality.** The shared-workspace phase deletes
`outside_root_error_names_cause_and_alternatives` (`lite_macos.rs:442-470`). Its *intent* —
name the cause and the working alternatives — must survive into whatever refusal replaces
it, or the feature ships with a worse error than the one it removes.

**Gateway-axis improvement — conditional on §1.6, not on bookkeeping.**

#82 claims per-operator VMs shrink the blast radius from "every concurrent session" to
"every session of one operator", relative to the accepted delta at
`.tasks/specs/2026-05-02-macos-support-design.md:970`. **That is true only once the socket
groups are per-operator (§1.6).** With slot ranges as daemon-side bookkeeping alone, an
operator can attach to any slot regardless of assignment, and an operator-owned gateway VM
becomes a process that can bridge every segment on the host. In that configuration the
delta runs the **other way**: worse than today, not better.

An earlier draft attributed the improvement to partitioning as such. Partitioning the
ledger does not partition the kernel's access control; §1.6 does.

**Until §1.6 ships, the gateway axis is not merely unimproved — it is a live defect**
(§1.6, §5.4). Do not record a gateway-axis improvement in any external document before
that lands.

**New delta — the operator uid becomes a path into the enforcement plane.**

This is the largest single change in the document's threat picture and it was previously
absent.

After ownership flips, the operator has root in the VM enforcing egress for **all of that
operator's sessions**. The remaining gate on the route helper is "you are root in this
VM": `run_vm_gateway_mode` (`sandbox-route-helper/src/main.rs:327-338`) checks caller uid 0
and that the container's own addresses are RFC1918 — it does **not** check that
`gateway_ip` is the session's assigned gateway, or even that it is in the container's
subnet, though the module doc at `:81-84` claims it must be. And the gateway template
installs `ALL ALL=(root) NOPASSWD:` for that helper (`gateway_lima.rs:471`).

So anything running as the operator can point a sandbox container's default route
somewhere else and unfilter that session's egress, while the daemon still reports it
healthy and no deny events fire — because no traffic reaches the gateway.

**Why "the operator is trusted" is not a sufficient answer.** The adversary sandboxd exists
to contain is the *agent*, not the operator. The shared-workspace phase makes `shared:`
point at real project trees — that is the feature — and a project tree contains things the
operator executes on the host: `Makefile`, `.git/hooks/*`, `package.json` scripts, `.envrc`,
`.vscode/tasks.json`. The agent may write them; `docs/guides/hardening.md` § 9p shared
mounts already concedes *"Writes flow both ways with no review or approval step."* The
operator then runs `make` or opens the editor. Agent-authored code now runs as the operator
— and the operator uid now holds a path into the egress-enforcement plane.

Before this design that chain terminated at the operator's uid, which had no route into the
enforcement plane at all: the gateway VM belonged to the daemon, and the operator's own
session VMs were already theirs to subvert (accepted). **This design connects the two
ends.** State it as a delta, and see §5.2 for the control the route-helper phase must
restore rather than merely re-document.

**New delta — unreapable sessions with live egress while an operator is logged out.**

If a VM survives logout (**unverified — §2.9**), its sandbox containers keep running with
whatever policy was last pushed, and the daemon can neither stop nor re-policy nor reap
them until the operator returns. If they do not survive, this delta does not exist. Resolve
§2.9's pre-check C before publishing this list.

### 5.2 Corrections issue #82 needs

| # | Claim in #82 | Correction |
|---|---|---|
| 1 | "**Narrower on the gateway axis**" | Backwards as written. The improvement is **conditional on slot partitioning** (§5.1). Stated unconditionally it is wrong. |
| 2 | "Deliberately out of scope: multi-operator NIC/slot consumption … document it rather than solve it." | Untenable. Partitioning is **load-bearing for the isolation claim the issue itself makes**. It cannot be documented away. |
| 3 | "Move the argv builders into the shared protocol crate" | Mechanism right, location wrong. `sandbox-agent` **deliberately does not depend on `sandbox-core`** — a TCB boundary stated at `sandbox-agent/src/handler.rs:37-38` and confirmed by `sandbox-agent/Cargo.toml:36-59`. The Docker argv builders live in `sandbox-core` (`backend/container.rs:751` etc.) and are used **on Linux too**; putting them in the macOS-only `sandbox_agent_protocol` lib would either break Linux or force `sandbox-core → sandbox-agent`, inverting TCB minimalism. Needs a **new zero-dependency leaf crate** depended on by both. |
| 4 | "the two long-lived streams" | There are **three**. The missed one is the **DNS-gate bridge** (`sandbox-core/src/dns_gate_bridge.rs:164` → `:224` → `:248`), which opens **one `docker exec` per DNS query**. It runs `socat UNIX-LISTEN` **without** `,fork` on purpose (`:30-42`), because `,fork` would multiplex concurrent gate frames onto one stdio stream and corrupt them. It is fail-closed (`:44-54`) and sits on the egress-**allow** critical path — i.e. the core promise. Its open rate interacts directly with §2.5. |
| 5 | "a **single VM** hosting both lite workloads and the gateway containers" | Blurs two distinct VMs. An earlier evaluation of a per-operator model kept the **gateway container in the daemon-owned VM** and moved only the **lite workloads**. This design goes further — the gateway VM itself becomes operator-owned. The issue's phrasing describes neither shape precisely and should say which VM hosts what. |
| 6 | "`gateway_recovery.rs` at ~1200 lines" | The file is 1236 lines but **only `:1-396` is production code (~330 lines)**; `:402-1236` is the hermetic test module. It is a generic injectable state machine with **no** discovery logic — one of the **cheapest** parts of the migration (a ~4-item change plus a caller rewrite), not one of the expensive ones. |
| 7 | "it matches how Docker Desktop and Colima already work on macOS" — offered as the rationale for the whole direction | **Architecturally sound; not a security precedent, and it must not be read as one.** Docker Desktop does take the broad-export approach: a configured File Sharing set exported into its VM, binds selecting subtrees, changes requiring a restart. But **Docker Desktop has no adversary inside the container** — your containers are your code running on your files, so its file sharing is plumbing. sandboxd's premise is the exact opposite: the thing inside the container is what the product exists to contain. So the **mechanism** transfers and the **security posture** does not. What genuinely transfers is the **allowlist**: Docker Desktop refuses binds outside its configured set, and that is the property §5.1's declared roots reproduce. |

**Two doc-comment corrections** fall out of the ownership change and should land with
their phase rather than rotting:

- **The authorization perimeter — restore a control, do not just rewrite the paragraph.**
  `lite_macos.rs:241-256` and `sandbox-route-helper/src/main.rs:55-84` (repeated at
  `:311-319`) both assert that "the gateway VM is single-tenant `_sandboxd` infra — no
  operator user can independently reach its sudo path." Under an operator-owned VM that is
  **false**.

  **An earlier draft filed this as a doc correction with the remedy "state what replaces
  it". Nothing replaces it — that is the finding.** The perimeter was the *only* thing
  making "you are root in this VM" a meaningful gate, and §5.1 traces how a sandboxed agent
  can reach the operator uid. Concretely, the route-helper phase must:

  1. **Validate `gateway_ip`** in `run_vm_gateway_mode` — require it to be on the
     container's own subnet. Cheap, and it merely enforces what the module doc at
     `:81-84` already claims is true.
  2. **Narrow the sudoers grant.** `gateway_lima.rs:471` installs a blanket
     `ALL ALL=(root) NOPASSWD:` for the helper, so any interactive `limactl shell` is a
     route-rewrite primitive. Scope it to the account the daemon's ops actually use.
  3. Only then rewrite the doc comments to describe the perimeter that now exists.
- **Residual TCC framing** (phase 5). `gateway_lima.rs:351-354` (a Rust comment) and
  `gateway_lima.rs:413-414` — the latter **inside the generated Lima YAML, so it ships
  into every gateway VM's `lima.yaml`** — both restate a TCC framing that was
  deliberately corrected away from elsewhere, and which `lite_macos.rs:442-470` now has a
  test asserting the operator-facing message must **not** contain. They survived because
  they are comments, not message text.

### 5.3 Cost re-estimation

Issue #82 estimates 3–5 weeks, assuming "~11 distinct verb shapes behind three command
builders". The measured Docker surface is roughly triple:

- **Roughly 28 `-H unix://<sock>` injection sites across ~12 files.** An earlier draft
  said "15 across 13 files, of which 9 are inline" and then enumerated 17 inline sites —
  arithmetic that does not close under any reading. The enumerated lines were each
  correct; the totals were not, and the enumeration additionally omitted
  `atomic_listener_writer.rs:470-471`, `workspace_rsync.rs:447-448`, `network.rs:829-830`,
  `container.rs:1378` and `orphan_reaper.rs:469`. **The true surface is about twice the
  figure the estimate was built on, which strengthens the under-scoping argument rather
  than weakening it** — but only if the numbers are right, so re-count before quoting.
- **6 named prefix builders, not three** — `container.rs:516`, `:531`, `:1619`;
  `gateway.rs:380`; `macos_session.rs:90`; `policy_distributor.rs:23` — plus two
  near-duplicate funnels in the orphan reaper (`orphan_reaper.rs:449`, `:494`; note `:494`
  `run_docker_raw` injects **no** `-H` at all — it is the host-daemon variant).
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
against these figures **after** the gate, when phase 2's shape — the brokered Docker
control plane — is actually decided.

Two counterweights, for honesty: `gateway_recovery.rs` is far cheaper than #82 suggests
(correction 6), and the `op_uid` routing change in §1.1 is free.

### 5.4 Related issues, and one that is not an issue

**⚠️ Read this first: the most serious defect this design touches has no tracker entry.**

Cross-operator slot access (§1.6) is an **active, exploitable defect on `master`** with no
GitHub issue. It was found reviewing this design and deliberately recorded in the spec
instead. It is therefore absent from every issue list, triage board and search anyone
would normally use to find it — **which is exactly why it is repeated here**.

| | |
|---|---|
| **What** | Every slot plist hardcodes one socket group (`network.rs:1027`) and enrollment adds every operator to it (`scripts/install.sh:2679`), so any enrolled operator can attach to any operator's vmnet slot socket. |
| **Impact** | The victim's egress policy is void: their traffic can be diverted through the attacker's unfiltered uplink and their TLS terminated, with the daemon and the deny-event stream showing nothing. |
| **Applies to** | Any host with **two or more enrolled operators**. Single-operator hosts are unaffected in practice. |
| **Introduced by** | Nothing here — it **predates** this design. |
| **Fix** | §1.6. **Independently shippable**; depends on no other part of this design. |
| **Test** | §3.6 assertion 5 (hostile VM). No existing test can detect it — see §1.6. |
| **Record** | §1.6 is the only one. If this design is abandoned, the defect and its analysis must be carried somewhere else before this document is. |

| Issue | Bearing |
|---|---|
| **#83** — gateway-VM recovery skips container-backend sessions (`gateway_recovery.rs:77-82`) | **Blocks bounce-to-resize** (§2.7). **It does not block phase 5** — the declared-roots mechanism (§5.1) bounces the VM only when the roots change, not per `shared:` create. It does still bite on that rarer path: a root change destroys the operator's running lite sessions with no recovery, because containers are `--restart no` (`container.rs:853-854`). |
| **#84** — `linux_only` declared and enforced but applied to zero tests | **Phase 6 depends on it.** `make test-e2e-macos SCOPE=full` currently collects the whole Linux-authored matrix on macOS. Close it first. |
| **#85** — `make setup-dev-env` regenerates vmnet plists referencing an account only `install.sh` creates | **A prerequisite, not merely related.** The second-operator isolation probe (§3.7) cannot run until it is fixed, because the host has no honest second operator to offer: pre-rename plists, no real `_sandboxd` account, and the existing candidates enrolled in Apple's reserved gid 60 (adding another there was rejected — it deepens the same problem). Fixing it is also what makes `make setup-dev-env` safe again. **The single-operator gate does not depend on it.** See [Before you start](#before-you-start). |

---

## Open questions

**No design questions remain open.** Every question raised by review has been answered;
the decisions live in the sections named in the table below, and the items in *Still
unverified* are facts to check rather than choices to make.

This section once claimed to be empty when it was not — §2.5 had left a mitigation open
while the section declared the design closed. So the claim above is deliberately narrower
than "nothing is undecided", and here is exactly what it excludes:

**Two bounded implementation choices are delegated to their phase**, with both options
stated and neither affecting anything outside the phase that makes it:

| Choice | Options | Phase |
|---|---|---|
| Where the reaper's gateway exclusion lives (§2.6) | in `reap_lima_orphans_inner`, or `decide_lima_vm` gains a `name` parameter | 4 |
| How `run_gateway_recovery` gets operator scope (§2.6) | operator scope on `GatewayRecoveryDeps`, or a filtering impl supplied by the caller | 4 |

Those are implementation shape, not design. If either turns out to have a consequence
outside its phase, it becomes an open question again — say so rather than absorbing it.


### Still unverified (facts, not decisions)

- **`cidata.iso` regeneration on every start** (§2.7) — pre-check B.
- **Whether an operator's VM survives logout** (§2.9) — pre-check C. Decides whether §2.4
  and one §5.1 delta describe a real state.
- **`interface:` on the broker path and at the version floor** (§1.4 fix 1) — the Lima
  behaviour is confirmed; the production path and Lima 1.2.0 are not.

**And the gate itself can still change the answer.** Phase 0 exists because the egress
question is unproven. A red gate routes to §3.8 — outcome (c) reopens the whole decision,
not merely a question within it.

### Previously open, now decided

Kept as a trail so the reasoning stays traceable. Each decision lives in the section
named, not here.

| Question | Resolution | Where it lives |
|---|---|---|
| Range persistence location | **Superseded.** Ranges are no longer persisted by the daemon at all — they are assigned at enrollment and enforced in root-owned plists and group membership (§1.6), so the daemon reads them rather than storing them. The earlier `sessions.db` migration decision is withdrawn | §1.3, §1.6, §2.1 |
| Cross-operator slot isolation | **Per-operator socket groups**, statically assigned at enrollment. Slot ranges as daemon-side bookkeeping are advisory — every enrolled operator can open every slot socket today — so the control moves into root-owned static configuration, which is the only layer an unprivileged daemon cannot undo | §1.6; phase 1 |
| Quota model | **Superseded in part.** "First-claim-wins at VM creation" is withdrawn: ranges are assigned at enrollment. What survives is the *default* (a single-operator host gets the whole pool, so nothing regresses) and the two distinct error shapes | §1.3, §2.2 |
| Gate harness form and lifetime | **A throwaway shell script**, executed once in phase 0 and **deleted at that phase's exit**; phase 6's retargeted e2e suite owns ongoing regression coverage, and a parallel bespoke harness would be a second system that can disagree with it | §3 *Form and lifetime*; phase 0 files + exit |
| Per-operator gateway VM naming | **`sandboxd-gateway-<operator_uid>`** — keeps the greppable prefix, encodes the owner, structurally cannot match the `sandbox-<12hex>` session grammar; paired with an **explicit** reaper exclusion rather than reliance on the parse failing | §2.6; phase 2 files + criteria |
| Which second uid plays "operator B" | **Fix issue #85 first**, then a dedicated test-operator account in the proper group; adding another member to Apple's reserved gid 60 was rejected as making #85 worse | §3.7; [Before you start](#before-you-start); phase 0 Part B |
| Does `interface:` pinning work on `socket:` networks | **Yes — verified**, and it is a real fd-level binding rather than a relabel. Brings two obligations with it: the generator must guard the `lima<slot>` correspondence itself (Lima does not), and `UNIX_PATH_MAX` bounds how deep a LIMA_HOME may sit | §1.4 fix 1 + fix 1a; §2.8; phase 1 criteria |
| `shared:` export mechanism | **Operator-declared export roots** — neither per-session subtree export nor a blanket home export. The operator declares which roots are exportable; they are exported at VM creation and the Docker bind `src=` selects the subtree per session. A **generalisation of today's fixed `/tmp/sandbox-shared`**, not a new mechanism | §5.1; phase 5 |
| Broker serialization mitigation | **Pipeline by `request_id`.** A stream-only fix leaves ~28 request/response Docker call sites queueing on a one-at-a-time connection. Protocol ordering is not the risk; **agent-side shared state is**, and auditing it is an explicit phase 2 work item | §2.5; phase 2 |
| Per-operator range configuration surface | **Derived from the live sockets** — `stat` each `slot-N.sock`, read its gid, resolve members. No config file, no new ingestion path. **The earlier constraint that this land at the `SANDBOX_MAX_MACOS_SESSIONS` parse site is withdrawn** — that site is an env-var parse of a single `u16` and cannot express a per-operator map. Do not reintroduce it | §1.3, §1.6; phase 1 |
| `restore_from_infos` sharding | **Persist `operator_uid: Option<u32>` on `NetworkInfo`** (`#[serde(default)]`). Covers Lima and lite uniformly; slot-derivation was rejected because lite sessions claim a token, not a slot | §2.1; phase 1 |
| The 429 variant's shape | **Structured, not string-wrapped** — carries operator uid, in-use count and quota, with a `Display` impl. Collapses three byte-identical message copies into one | §2.2; phase 1 |
| De-enrollment | **Specified in phase 1 alongside enrollment.** Reclaiming a range without revoking the departing operator's group membership **recreates the §1.6 defect exactly** | §1.6; phase 1 |

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
| **Hardcoded slot socket group (§1.6)** | `network.rs:1027`; enrollment at `scripts/install.sh:2679` |
| **Agent YAML shape validator (§1.1a)** | `sandbox-agent/src/validation.rs:363`, `:491-547`; callers `handler.rs:416, 430, 512` |
| Route-helper in-VM mode + sudoers grant | `sandbox-route-helper/src/main.rs:327-338`; `gateway_lima.rs:471` |
| Per-session network create argv (masquerade) | `sandbox-core/src/network.rs:401-415` |
| Create ordering (create → start → route) | `sandboxd/src/main.rs:5262`, `:5285`, `:5328` |
| Production gateway-image staging | `scripts/install.sh:3030`, `:3240` |
| Exhaustion errors | `network.rs:1161-1176, 1208-1213` |
| Inter-slot L2 isolation test | `network.rs:3021` |
| `SandboxError` enum (where new variants go) | `sandbox-core/src/error.rs:9` |
| Error → HTTP mapping (arms only) | `sandboxd/src/error.rs:57-79` |
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
| Max-sessions parse | `main.rs:13402-13440` |
| Gateway image healthcheck | `networking/gateway/Dockerfile:148, 174` |
| CoreDNS upstream default | `networking/gateway/entrypoint.sh:304` |
| Block-exit-code set (e2e) | `tests/e2e/test_lite_macos.py:410` |
| Canonical macOS spec | `.tasks/specs/2026-05-02-macos-support-design.md` |
