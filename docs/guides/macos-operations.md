# macOS Operations Guide

This guide covers macOS-specific operational topics: coexistence with other
Lima-based tools, disk usage and APFS accounting, and DNS resolver behavior
across host network changes.

## Coexistence with existing Lima and Colima setups

sandboxd uses Lima internally but is completely isolated from any Lima or
Colima installation you use for personal development.

**Separate home directories.** sandboxd stores all its Lima instance state
under `/var/lib/sandboxd/<_sandboxd-uid>/<op-uid>/lima/` (gateway VM, per-operator base
images). Your personal Lima home (`~/.lima/`) and any Colima state are never
read or written by sandboxd.

**Separate vmnet sockets.** sandboxd registers its own pool of `socket_vmnet`
instances under the LaunchDaemon labels `io.sandboxd.vmnet.<n>`. These are
separate from any Homebrew-managed `socket_vmnet` instance that Colima or Lima
uses. sandboxd writes no shared `networks.yaml` configuration; each VM's
template specifies its vmnet socket path directly.

**No shared Docker.** sandboxd does not use the host Docker daemon, Docker
Desktop, OrbStack, or Rancher Desktop. It communicates exclusively with Docker
inside the `sandboxd-gateway` Lima VM via a forwarded Unix socket.

**CPU and memory ceilings are shared.** macOS gives each process its own
scheduling context, but QEMU VMs compete for host RAM and vCPUs with any other
VMs running at the same time. If you run large personal Lima VMs alongside
sandboxd sessions, budget accordingly — there is no hypervisor-level
reservation isolating them.

**Summary of what sandboxd touches (and does not touch):**

| Resource | sandboxd uses | Personal Lima/Colima |
|---|---|---|
| Lima home | `/var/lib/sandboxd/<daemon-uid>/<op-uid>/lima/` | `~/.lima/` |
| vmnet sockets | `/var/run/sandbox/vmnet/` | `/var/run/lima/` (Homebrew default) |
| Docker daemon | Inside gateway VM only | Host Docker / Desktop / OrbStack |
| `networks.yaml` | Never written | Managed by Lima/Colima |

## Operator login is a prerequisite for VM operations

On macOS the daemon does not run `limactl` or talk to Docker itself. Every VM
operation it performs on your behalf is executed by `io.sandboxd.agent`, a
LaunchAgent in your own login session, against a `LIMA_HOME` and a Docker
socket the daemon account cannot reach. That is the privilege boundary. The
operational consequence is that **anything needing a VM operation requires you
to be logged in**, and it is worth checking the agent before diagnosing
anything downstream of it:

```bash
launchctl print gui/$(id -u)/io.sandboxd.agent >/dev/null 2>&1 \
    && echo loaded || echo "NOT loaded"
```

**Creating a session while logged out fails, and says why.** The message names
the operator by username, falling back to the numeric uid when the account
cannot be resolved:

```
session agent for bob is not running — the operator must be logged in for
Lima VM operations
```

Remedy: log in. There is no daemon-side override, and adding one would mean
giving the daemon a path to your VMs that does not go through your agent —
which is the thing the boundary exists to prevent. There is likewise no
supported way to keep the agent running across a logout: the deployment model
assumes an operator with a login session, so on a host where sessions must
outlive interactive logins the answer today is to keep that session logged in.

**Where the gateway is per-operator, the dependency reaches back further than
session creation.** A host runs its gateway in one of two shapes, and
`limactl list` names which one you have:

| Instance | Shape |
|---|---|
| `sandboxd-gateway` | One gateway for the whole host, in the daemon's own `LIMA_HOME`. The daemon brings it up during its own startup, with no operator present. |
| `sandboxd-gateway-<uid>` | One gateway per operator, in that operator's `LIMA_HOME`, brought up through that operator's agent. |

In the second shape the gateway is itself a VM operation, which puts it under
the same rule as everything else in this section: **an operator's sessions
cannot exist before that operator has logged in.** The failure lands earlier
than the one above — at gateway bring-up, before any session-specific work
begins — and carries the same message, naming the operator whose agent is
missing. Log in and retry. There is no supported way to pre-create a gateway
on another operator's behalf, for the same reason there is no daemon-side
override above: the path would not go through their agent.

**Sessions already running do not stop when you log out.** launchd tears down
your GUI domain at logout and kills the agent with it, but a sandbox VM is a
detached QEMU orphaned to pid 1 and is not a launchd-managed job, so it
survives. It keeps running — and keeps egressing under whatever policy was
last pushed to it — until the host goes down or the process is killed. In the
meantime the daemon can neither stop, re-policy nor reap it, and orphan
reaping cannot reach it either. This is an accepted trade-off rather
than a defect; it is stated as one in
[hardening → operator logout](/sandboxd/guides/hardening/#operator-logout-macos).

**De-enrolling the operator does not end such a session either.** Membership
is checked at `connect(2)`, so a QEMU that already holds its slot socket keeps
it — the same reason [de-enrollment](#de-enrolling-an-operator) runs a residue
check before releasing a range. Killing the process is what ends the session.
The Lima instance name appears in the QEMU argv as a path segment, so it can
be targeted without reaping every VM on the host:

```bash
# Confirm the match first — this prints the argv, kills nothing:
/bin/ps -Ao pid,args | grep "lima/<instance-name>/disk" | grep -v grep

sudo pkill -f "lima/<instance-name>/disk"
```

Killing QEMU leaves the session record behind and the slot still on the
operator's ledger. Clear both with `sandbox rm <id>` once that operator is
logged back in — the removal is itself a VM operation, so it cannot be done
while they are away either.

## Resizing the session pool (`max_macos_sessions`)

`max_macos_sessions` (env `SANDBOX_MAX_MACOS_SESSIONS`, default 8, range
1–32) caps how many full-backend sessions run concurrently: it fixes the size
of the `socket_vmnet` pool and the number of NICs the gateway VM is created
with. Because Lima fixes a VM's NIC set at creation and the pool daemons are
root-owned, a changed value is picked up at daemon startup — and applied only
when it can be applied without disrupting live sessions.

**Changing the value while sessions are running is safe.** When sandboxd
starts and finds `max_macos_sessions` no longer matches the gateway's actual
NIC count while one or more full-backend sessions are still `Running`, it does
not rebuild or resize the pool. It keeps the currently-discovered set of vmnet
slots and their launchd daemons, logs a warning, and continues serving the
running sessions with the existing pool. This holds in both directions,
including when the new limit is set *below* the number of sessions currently
live — running sessions are never torn down to satisfy a lowered limit. The
resize is deferred, not rejected.

**Applying a deferred change.** Stop all full-backend sessions, then restart
sandboxd; with nothing running, startup rebuilds the gateway to the new NIC
count. A resize also requires the root-owned vmnet daemon set to match the new
size; if it does not, startup logs that requirement and again keeps the
current pool rather than rebuilding. Re-provision the daemon set with the
setup step — run it as yourself, not under `sudo`; it invokes `sudo` for the
privileged commands it needs and refuses to start as root — and restart
sandboxd once more:

```
make setup-dev-env DARWIN_VMNET_SLOTS=<n>
```

## The `socket_vmnet` pool and its daemon account

The pool is `DARWIN_VMNET_SLOTS` root LaunchDaemons (default 8), labelled
`io.sandboxd.vmnet.0` … `io.sandboxd.vmnet.7`, installed at
`/Library/LaunchDaemons/<label>.plist`. Each one's `ProgramArguments` is a
`/bin/sh -c` preamble that creates the socket directory, verifies the staged
binary's code signature, and only then execs `socket_vmnet`:

```
install -d -o _sandboxd -g _sandboxd -m 0750 /var/run/sandbox && \
install -d -o _sandboxd -g _sandboxd -m 0750 /var/run/sandbox/vmnet && \
codesign --verify --strict /Library/sandboxd/socket_vmnet || { …; exit 1; } && \
exec /Library/sandboxd/socket_vmnet --vmnet-mode=host … --socket-group=_sandboxd …
```

macOS clears `/var/run` at every boot, so that first `install -d` is what
recreates the socket directory each time the machine starts. If `_sandboxd`
does not resolve as both a user and a group, `install` exits non-zero with
`install: unknown group _sandboxd`, the `&&`-chain short-circuits, no slot ever
execs `socket_vmnet`, and `KeepAlive` retries the same failure every
`ThrottleInterval` seconds. Every full-backend session then fails to get a
network segment.

Nothing about that is visible when the plists are written — only at the next
boot, arbitrarily long after. So **every emitter refuses to write a plist
naming an account that does not resolve**: `network.rs`, the
`setup-darwin-vmnet-plists` make target, and `scripts/install.sh` all check
first and exit non-zero with the account name. Create the account with
`make setup-darwin-sandboxd-user` (a dev host; `make setup-dev-env` runs it as
a prerequisite) or by running `scripts/install.sh` (a production install).

### Is a loaded daemon still running what its plist says?

launchd caches a job's definition in memory when it is bootstrapped. Rewriting
the plist afterwards changes nothing: the running job keeps the argv it was
bootstrapped with until it is booted out and bootstrapped again, and
`launchctl kickstart -k` does **not** re-read the plist — it restarts the
cached job. "The job is loaded" is therefore not "the job is up to date", and
a provisioning run that installs a corrected plist, sees the job loaded, and
reports success can leave the old definition serving until the next reboot
silently swaps it in.

```bash
scripts/darwin-vmnet-drift.sh io.sandboxd.vmnet.0 \
    /Library/LaunchDaemons/io.sandboxd.vmnet.0.plist
```

Exit `0` in sync, `3` drift (the two argvs are printed to stderr), `4` not
loaded, `1` error. It needs no sudo — `launchctl print` reads the in-memory
job. `make setup-darwin-vmnet-daemons` runs it for every slot and re-bootstraps
the ones that diverge. The manual equivalent, if you want to eyeball it:

```bash
launchctl print system/io.sandboxd.vmnet.0 | sed -n '/arguments = {/,/^	}$/p'
plutil -extract ProgramArguments.2 raw -o - \
    /Library/LaunchDaemons/io.sandboxd.vmnet.0.plist
```

### Repairing a pool provisioned with an account that does not exist

If a host was provisioned before the account existed, the plists on disk name
an unresolvable account and the failure is queued for the next boot. The
procedure below repairs it *and* makes the deferred failure immediate, so the
repair is verified without rebooting: booting the jobs out and removing
`/var/run/sandbox` reproduces exactly the state a boot leaves behind.

It is disruptive — it stops every full-backend session — and it is not run by
any target automatically. Run it deliberately, as the operator, with sudo.

```bash
# 1. Stop the daemon so nothing tries to claim a slot mid-repair.
sudo launchctl stop system/io.sandboxd.daemon

# 2. Tear down all eight pool jobs and the socket directory. After this the
#    host is in the state a fresh boot leaves it in.
for slot in $(seq 0 7); do
    sudo launchctl bootout system/io.sandboxd.vmnet.$slot 2>/dev/null || true
done
sudo rm -rf /var/run/sandbox

# 3. Create the account, then rewrite the plists. In this order: the
#    generator refuses to emit a plist for an account that does not resolve.
make setup-darwin-sandboxd-user
make setup-darwin-vmnet-plists

# 4. Bring the pool back. This re-reads the plists from disk.
make setup-darwin-vmnet-daemons

# 5. Verify. Every slot must have a socket, owned by the group the plist
#    names, and every loaded job must match its plist.
ls -l /var/run/sandbox/vmnet/
for slot in $(seq 0 7); do
    scripts/darwin-vmnet-drift.sh io.sandboxd.vmnet.$slot \
        /Library/LaunchDaemons/io.sandboxd.vmnet.$slot.plist || echo "slot $slot: FAILED"
done

# 6. Restart the daemon.
sudo launchctl start system/io.sandboxd.daemon
```

Step 5 is the part that matters. A repair that skips it has verified only that
the plists were written, which is precisely the check that let the original
failure through.

## Per-operator vmnet slot groups

A slot socket is the *entire* admission control for its L2 segment. Anything
that can `connect(2)` to `slot-N.sock` becomes a peer on segment N — no VM and
no cooperation from sandboxd required — and the sandbox VM on that segment
points its default route at the gateway container's IP, so an ordinary
same-segment peer can be believed as that next hop.

That matters because the group in `--socket-group` is the whole check. With one
group for every slot and every operator enrolled in it, **any enrolled operator
can reach any other operator's segment**: the victim's traffic can be made to
leave through the attacker's uplink instead of their gateway container, their
egress policy is void and their TLS is terminated by the attacker, and the
victim's session, the daemon and the deny-event stream all keep looking normal.
Single-operator hosts are unaffected in practice.

Enrollment therefore creates a group scoped to one operator and records the
slots that operator owns:

```bash
# The whole pool, for the only operator on the host:
sudo scripts/darwin-operator-group.sh enroll --operator alice

# A second operator, with an explicit disjoint range:
sudo scripts/darwin-operator-group.sh enroll --operator bob --slots 4-7

sudo scripts/darwin-operator-group.sh status
```

`make setup-dev-env` runs the first form for `$USER`; `scripts/install.sh` runs
it for the installing operator. Both are idempotent — a second run is a no-op.

### What is assigned, and what enforces it

The slot socket carries the owning operator's group, so the assignment *is* the
access control rather than a record of one. A `connect(2)` from an operator
outside a slot's group fails `EACCES` and the pool logs no accepted connection
for it. On a two-operator host with slots 0-3 and 4-7 split between them, each
principal connects on its own range and is refused on the other's, while
`stat(2)` on both sockets succeeds from both — which is what separates a group
refusal from a directory-traversal failure, and confirms traversal stays intact
for every operator. The refusal reaches a VM the same way: a gateway whose
operator is not in the slot's group dies at its first `socket:` entry with
`dial unix …/slot-N.sock: connect: permission denied` and never reaches a guest.

Two memberships are deliberate and must not be "tidied up":

- **Every daemon account is in every per-operator group.** It has to be — the
  gateway VM holds a NIC on every slot, so a daemon outside one operator's group
  fails `limactl start` at the first `socket:` entry, and then no macOS session
  of *any* operator can be created or recovered. This is not a weakening: the
  daemon is the principal operators are isolated around, not from. Read *every*
  literally on a host that runs more than one daemon account — the e2e harness
  account owns a state tree and a gateway beside the production one, and a
  daemon account left out of the split loses every slot at the moment the
  sockets move.
- **Operators stay in the shared `_sandboxd` group.** It gates the daemon socket
  itself, and it owns `/var/run/sandbox/vmnet` (0750) — an operator outside it
  cannot traverse to a slot socket whatever group the socket carries. The
  per-operator group is a *second* group; enrollment adds one rather than moving
  anybody out of the other.

A single-operator host gets the whole pool and behaves exactly as it does today
— same 8 concurrent sessions, same slot indices, same segments. Partitioning is
opt-in: 8 slots across 2 operators caps each at 4.

The daemon *does* honour the assignment from here on, even though the sockets
have not moved: a slot recorded against an operator's group is theirs, and a
slot no group records is still shared. So enrolling a second operator with
`--slots 4-7` does reduce the first operator's concurrency to the four slots
left over, before anything about socket permissions changes.

### De-enrolling an operator

**Reclaiming a range without revoking the departing operator's membership
recreates the defect exactly.** The new owner is given the slots, the old owner
keeps group membership and therefore socket access, and *nothing detects it* —
the plists look right and the daemon's derived mapping names the new owner. So
revocation strictly precedes reassignment, and the tooling enforces that rather
than trusting the order: a range still recorded against another operator's group
cannot be handed out.

```bash
sudo scripts/darwin-operator-group.sh deenroll --operator bob

# Reclaim the range but leave bob an operator of this host:
sudo scripts/darwin-operator-group.sh deenroll --operator bob --keep-daemon-access
```

The command stops the operator's VMs, revokes their membership, verifies no live
process still holds a slot socket, and only then releases the range.

⚠️ **Revocation does not reach credentials already held**, which is why the
residue check is part of the sequence rather than an afterthought. Membership is
checked at `connect(2)`, not continuously: a detached QEMU keeps the fd it
already opened and stays on the segment, and a live login session keeps the
supplementary groups it was granted at login until the operator logs out.

If that check fails the command **stops before releasing the range**, and exits
5. The group is then left with no operator member, which makes its slots
unassignable — the half-done state surfaces as **lost capacity**, which is loud,
rather than as shared access, which is silent. That is the behaviour to
preserve; do not resolve a group with two operator members by picking the newer
one. Stop the process, have the operator log out, and re-run the command — the
sequence is resumable.

Nothing deletes a departed operator's gateway VM. Stopping it is part of
de-enrollment; removing it is a deliberate administrative act, because automatic
deletion of a VM that may hold running sessions is its own hazard:

```bash
sudo -u bob env LIMA_HOME=/var/lib/sandboxd/<daemon-uid>/<bob-uid>/lima \
    limactl delete --force <instance>
```

### Costs of the mechanism, stated plainly

- **Changing an operator's quota is privileged installer work.** There is no
  automatic rebalancing, no lazy claiming, and no bouncing of an existing
  operator's VM to make room — the same class of operation as growing the pool,
  which the daemon already refuses and routes to the installer.
- **Three things must stay in step** once the sockets move: the plist's group,
  that group's membership, and whatever the daemon reads to learn the range.
- **The plist generator gains an operator dimension**, in a codebase where a
  plist/account mismatch is already known to fail *silently until the next
  boot*. `make setup-darwin-vmnet-plists` and the `install.sh` plist path both
  change; treat any edit there with the caution the pool-repair procedure above
  describes.
- **Create the group before any plist names it.** `socket_vmnet` given a
  `--socket-group` that does not resolve exits 1 at bind, before
  `vmnet.framework` initializes, with **no fallback to a default group** — so a
  mis-ordered enrollment fails closed rather than widening a segment. On this
  plist shape "fails closed" means at the *next boot*: the pre-exec preamble is
  an `&&` chain and the job carries `KeepAlive`, so the symptom is a retry loop
  in the launchd log. The failed run leaves a stale `root:wheel` socket at the
  path with no listener — "path exists, nothing serves it" rather than "job
  missing". A corrected retry over that stale path succeeds; no manual socket
  cleanup is needed.

### The migration window

**Regenerating a plist does not take effect until reboot or an explicit reload**
— the same deferred-failure shape as the pool-repair procedure above. So a new
daemon can run against old sockets for an unbounded period. The upgrade sequence
is therefore:

1. **Regenerate** the slot plists with their per-operator groups.
2. **Reload** the pool jobs so the running argv matches what is on disk
   (`make setup-darwin-vmnet-daemons`, then `scripts/darwin-vmnet-drift.sh` per
   slot to confirm — "loaded" is not "up to date"). ⚠️ A `bootout` followed
   immediately by a `bootstrap` of the same label fails with `Bootstrap failed:
   5: Input/output error`: the bootout takes effect and the bootstrap does not.
   Looped over eight slots that takes the **whole pool offline** while reporting
   an errno naming nothing relevant — `plutil -lint` calls the plist fine, so
   the plist is the wrong place to look. Retrying the failed label seconds later
   succeeds. Read a slot that is down after a reload as un-bootstrapped rather
   than as misconfigured, which is why step 2 confirms per slot instead of
   trusting the reload's exit status.
3. **Split membership**: enroll each operator into their own group.
4. **Start the new daemon.**

The in-between state is survivable rather than an outage because a slot still
carrying the legacy shared group is treated as an unmigrated install: the daemon
falls back to current behaviour and warns, naming the migration, rather than
refusing. Every host that exists today is in that state, so refusing would be a
total outage with no upgrade path.

### What the daemon does with the assignment

At startup the daemon reads the assignment back rather than storing a copy of
it: for each slot it stats the socket, resolves the group, and asks
`getgrouplist(3)` which enrolled operators are in it. It keeps one slot pool
per operator, each over that operator's range, plus **one shared pool** for
every slot still on the legacy group — shared, because that is what
single-pool behaviour was, and giving each operator a private pool over the
same indices would let two of them land on one segment.

The result is visible in `GET /diagnostics`:

| Field | What it holds |
|---|---|
| `vmnet_pool_size` | slots on the host, across every operator |
| `vmnet_pool_claimed` | slots claimed right now, across every pool |
| `vmnet_slot_assignment` | one line per slot: assigned to whom, legacy, or why unassignable |
| `vmnet_assignment_warnings` | the unmigrated-install notice, chiefly |
| `vmnet_claimed_by_operator` | slot → session → operator uid |
| `vmnet_declined_restores` | claims restore refused to re-register (see below) |

Membership is resolved with `getgrouplist(3)` rather than by reading a group's
member list, because a member list omits any account whose *primary* gid is the
group — which the daemon account's own record is. Service accounts
(`_sandboxd`, `_sandboxd-test`) are excluded from the operator count by an
explicit list, not by an underscore prefix; they are in these groups by design
and counting them would make every correctly-enrolled group look contested.

Enrollment takes effect at the next daemon start. There is no lazy claiming
and no rebalancing on a running daemon.

### Two failure shapes, and why they are different

Partitioning produces two client-visible failures that are easy to confuse.
They have different causes, different remedies, and deliberately different
status codes — returning one code for both would tell an operator to retry
something retrying can never fix.

**`429 Too Many Requests` — your share is full.** Every slot in this
operator's range is in use. A capacity ceiling: stopping one of their own
sessions clears it. The message states the in-use count against the share and,
when the operator holds the whole pool, points at the privileged
pool-regeneration step instead — raising `max_macos_sessions` cannot lift
either case, because it cannot exceed the number of provisioned slot sockets.

```
max concurrent sessions reached for operator uid 528: 4 running against a
share of 4 vmnet slots.
```

Remedy: `sandbox session stop <name>`, or enroll the operator with a larger
range (which needs a daemon restart, and slots that some other operator does
not already hold).

**`409 Conflict` — you have no share at all.** No slot range is assigned to
this operator *and* nothing is left shared, because the whole pool is assigned
elsewhere. A configuration conflict: no amount of waiting changes it, and an
administrator has to act.

```
no vmnet slot range is assigned to operator uid 501. This host's pool has 8
slots; none are assigned to you and none are still shared.
```

Remedy: `sudo scripts/darwin-operator-group.sh enroll --operator <name>
--slots <range>`, then restart the daemon.

⚠️ **The 409 body does not name who holds the pool, and must not be changed to.**
Any enrolled operator can provoke this error, so naming the holders would hand
each of them the roster of sandboxd users on a shared machine. The holders are
in the daemon log and in `/diagnostics` → `vmnet_slot_assignment`, where the
audience is the administrator who can act on it.

### Sessions the daemon declines to restore

A restart routes each running session back into its owner's pool using the
operator uid persisted with the session. A session created by an older daemon
does not carry one, so its owner name is resolved instead — and when *that*
fails (the account was removed or renamed), the daemon **declines the claim**
rather than guessing at a pool. Guessing would put a running VM's slot on
another operator's ledger.

A declined claim is real capacity that is still consumed by a running VM but
that no pool is tracking, so it is surfaced rather than dropped:

```bash
curl --unix-socket /var/run/sandbox/sandboxd.sock \
  http://localhost/diagnostics | python3 -m json.tool | grep -A5 declined
```

Each line names the session, the slot it held and why it could not be routed.
Remedy: stop the session (`sandbox session stop <id>`), which releases the
slot for real, or restore the account the session was created under.

### `gateway_recovery_declined_sessions` — inert in this build

A second `/diagnostics` field, unrelated to the pool declines above:

| Field | What it holds |
|---|---|
| `gateway_recovery_declined_sessions` | one line per session the last gateway recovery could not attribute to any gateway |

**On a host with the shared `sandboxd-gateway` — the default — it is always
`[]`, and no operator action can put a line in it.** The daemon holds one
gateway VM, so a recovery has exactly one gateway to drive and every session it
recovers goes to that one — there is no attribution to get wrong, and the code
path that declines a session is not the path this daemon takes. The field is
there for per-operator gateways, where a session whose operator cannot be
determined would have no gateway of its own to recover against and would be
declined rather than recovered against a guessed one.

So the field is worth reading only to confirm it is empty:

```bash
curl --unix-socket /var/run/sandbox/sandboxd.sock \
  http://localhost/diagnostics | python3 -m json.tool \
  | grep -A5 gateway_recovery_declined
```

and an empty list carries no information about recoveries: it is the state on a
host that has never run one and the state on a host that has run a hundred. If
you ever see it non-empty on this build, that contradicts the code rather than
telling you about a session — treat it as a bug report, not an operational
condition.

For "did a recovery fail to rebuild a session's gateway container?", use the
per-session status instead. A recovery that reads the session list and then
cannot restart the gateway VM leaves every session in that list reporting
`"networking_status": "degraded"` on `GET /sessions` and `GET /sessions/<id>`.
That surface is live here; this one is not.

Read `degraded` for what it is: the flag lives in the daemon's memory, so a
daemon restart clears it whether or not the VM has come back, and nothing
clears it when the gateway monitor re-creates an unhealthy session's gateway
container on its own. So it records that a recovery pass did not complete for
that session — not that the session has no gateway container, and not anything
about what its traffic can currently do.

### Preconditions this does not cover

- **Operators must not be able to become root**, as in any multi-user isolation
  model. A root-capable operator can start their own `socket_vmnet` on any
  segment identifier and bypass the socket permissions entirely.
- **`net.inet.ip.forwarding` must be `0`.** The host holds an interface on every
  segment (`bridge100`–`bridge107`), so at `1` all of them become mutually
  routable *through the host* — no socket, group or plist involved, and nothing
  here changes that. Unlike the root precondition this is one command away and is
  flipped by ordinary features such as Internet Sharing, so check it:
  `sysctl net.inet.ip.forwarding`.
- **An operator can still misconfigure a VM on their own slots.** The boundary
  this restores is *between* operators, not between an operator and their own
  sessions.

## Disk usage and APFS accounting

sandboxd stores sandbox VM disk images under the daemon's LIMA_HOME. On APFS
volumes (the default on Apple Silicon Macs), APFS copy-on-write means that
clones share unchanged blocks with the base image at no extra cost.

### Footprint components

| Component | Typical size | Notes |
|---|---|---|
| Gateway Lima VM | ~4–6 GB | `sandboxd-gateway`: one per host, shared across all operators. `sandboxd-gateway-<uid>`: one per operator — budget one for each enrolled operator |
| `sandbox-base` Lima VM (per operator) | ~4–6 GB | One per operator; clones diverge from here |
| Session VM clone | < 1 GB initially | Grows as the session writes files |
| Gateway image tarball | ~500 MB | Staged in the daemon base dir; copied into a gateway's LIMA_HOME on first load, so budget for two copies |
| Lite container image | ~300 MB | Same two-copy pattern as the gateway tarball |

### APFS accounting notes

**`du` overstates usage.** The `du` command reports apparent size and does not
account for APFS block sharing between clones. A base VM plus N clones each
report their full apparent size in `du` output even though most blocks are
shared.

**Use `diskutil` or `df` for actual free space.** `diskutil apfs cliInfo
<volume>` and `df -h /` report the volume's true free space after APFS
deduplication. These are the authoritative numbers to watch.

**APFS GC is async.** When `sandbox rm` deletes a session, the diverged
blocks specific to that session's clone are freed, but APFS garbage-collects
them asynchronously. Free space may not increase immediately after a delete.

**Boot-volume accounting.** All sandbox state lives on the boot volume by
default. Finder and macOS system tools (Storage → System Information) see the
sandbox disk images as ordinary files and report the space as used. This is
expected.

**Disk space warning.** `sandbox doctor` warns when free space on the sandbox
state volume drops below 10 GiB. There is no hard enforcement threshold —
`sandbox create` does not consult free space before starting. The 10 GiB
threshold is a conservative starting point; refine it based on your session
workload.

### Reclaiming disk space

```
# Build cache (largest reclaimable chunk; does NOT remove tagged images):
docker builder prune -f

# Dangling/untagged image layers only:
docker image prune -f

# Reap orphaned QEMU processes from crashed sessions:
pkill -f qemu-system

# Remove a session and its VM clone:
sandbox rm <session-name>
```

Do **not** run `docker system prune -a` while sandboxd is in use — it removes
the tagged `sandbox-gateway` and `sandbox-lite` images and forces the daemon to
reload them from the retained tarballs on next start.

## DNS resolver staleness across host network changes

### How resolvers are configured

When the `sandboxd-gateway` Lima VM starts, the daemon reads the host's
current DNS resolvers from `scutil --dns` and writes them into the gateway
VM's `/etc/resolv.conf`. CoreDNS inside the gateway VM uses these resolvers
as its upstream for all sandbox sessions.

### The staleness scenario

The gateway VM is **persistent** — it keeps running across daemon restarts and
across host sleep/wake cycles. If you change networks (e.g., move from your
office Wi-Fi to a home network or a VPN), the gateway VM's `/etc/resolv.conf`
still contains the resolvers from the time it last booted. Those resolvers may
be unreachable from the new network, causing DNS resolution to fail for all
sandbox sessions.

**Symptoms:** sandbox sessions can reach IP addresses directly but cannot
resolve domain names. `sandbox doctor` may report DNS-related health issues.

### Remedy

Restart the gateway VM to pick up the new resolvers:

```sh
# Option 1: restart the daemon (also restarts the gateway VM):
sudo launchctl kickstart -k system/io.sandboxd.daemon

# Option 2: direct limactl restart (daemon must be stopped first):
# sudo launchctl stop system/io.sandboxd.daemon
# limactl stop sandboxd-gateway && limactl start sandboxd-gateway
# sudo launchctl start system/io.sandboxd.daemon
```

Running sessions survive a daemon restart if their VMs are still up; the
daemon reconciles and reconnects their gateway containers on startup.

**Note:** Automatic detection of host network changes and live re-injection of
resolvers into the running gateway VM is not implemented in the current
release. The manual restart is the supported remedy. Watch the issue tracker
for a future `sandbox update-resolvers` command or a daemon-triggered
auto-refresh.

## Workspace access and TCC (Transparency, Consent, and Control)

macOS TCC governs access to user data in protected directories: `~/Documents`,
`~/Desktop`, `~/Downloads`, `~/Pictures`, `~/Movies`, `~/Music`, and similar
locations. sandboxd interacts with TCC only through `shared:` workspace mounts
on the full Lima backend.

### Zero-prompt default

If you keep your workspace outside protected directories — for example
`~/projects/my-repo`, `~/dev/work`, `/tmp/scratch` — TCC never triggers.
No consent dialog, no System Settings entry needed. This is the recommended
starting point.

```sh
# No TCC involvement:
sandbox create --workspace shared:~/projects/my-repo
```

### One-time TCC consent for protected directories

`sandbox create --workspace shared:~/Documents/my-project` makes the sandbox
VM access `~/Documents` on the host via a 9p shared mount whose host-side file
access is performed by the `sandbox-agent` process running in your login
session.

Because the agent runs in your Aqua session as your own uid, macOS can show you
a normal "allow access to your Documents?" consent prompt — the first time you
use a protected directory. After you click Allow, the grant persists across
subsequent uses.

**Which binary triggers the prompt** depends on how macOS TCC attributes the
file access within the `sandbox-agent` → `limactl` → `qemu-system` process
chain. The possible outcomes are:

| Attribution | Effect |
|---|---|
| `sandbox-agent` | One clean grant, stable across `brew upgrade qemu` and `brew upgrade lima` |
| `qemu-system` or `limactl` | Grant re-triggers on every `brew upgrade qemu`/`lima` because the cdhash changes |

Both cases produce a working grant; only the upgrade-invalidation behavior
differs. See the manual verification procedure at the end of this section for
the step to confirm which binary your system attributes the access to.

### Full Disk Access fallback

If no TCC prompt appears when you first use a protected directory — possible
when `qemu-system` is fully daemonized and detached from the agent's
responsibility chain — the access is silently denied. The remedy is a one-time
manual grant via System Settings:

1. Open **System Settings → Privacy & Security → Full Disk Access**.
2. Click the `+` button and add the binary that owns the access (either
   `sandbox-agent` at `/usr/local/libexec/sandboxd/sandbox-agent`, or
   `/opt/homebrew/bin/qemu-system-aarch64` if TCC attributed the access there).
3. Toggle the switch to On and authenticate.

After granting Full Disk Access, the protected-directory mount works without
further prompts.

**`brew upgrade` caveat.** If TCC granted access to `qemu-system` or `limactl`
rather than to `sandbox-agent`, any `brew upgrade qemu` or `brew upgrade lima`
changes the binary's cdhash and invalidates the grant, re-triggering a prompt
on next use. To avoid repeated grants, either use the Full Disk Access option
(which is stable across upgrades) or keep workspaces outside protected
directories.

### TCC and the lite (container) backend

The lite backend uses `_sandboxd` (the system daemon user) to perform host-side
file access for `shared:` mounts, not the operator's session. TCC consent from
the operator does not apply to the daemon user — access is silently denied for
protected directories regardless of any per-operator grant. Keep lite-backend
`shared:` sources outside TCC-protected directories.

### `sandbox doctor` TCC check

`sandbox doctor` displays a **C23 — TCC workspace access** row. This row is
informational only; it does not block doctor from passing or prevent session
creation. If a `shared:` mount into a protected directory fails, consult
the Full Disk Access grant steps above rather than the doctor row.

---

## Real-chain TCC verification procedure (manual, Aqua GUI session required)

This procedure records which binary in the agent → `limactl` → `qemu-system`
chain TCC attributes a protected-directory file access to, and whether a
consent prompt appears at all. Run it on a real Apple-Silicon Mac with an
active GUI login session. It cannot be performed headlessly or in a CI
environment.

**Prerequisites before starting:**

- [ ] sandboxd installed and the daemon running (`sandbox doctor` reports
      healthy).
- [ ] The `io.sandboxd.agent` LaunchAgent is loaded in your login session
      (check: `launchctl print gui/$(id -u)/io.sandboxd.agent` — should not
      return error).
- [ ] No existing TCC grant for `sandbox-agent`, `qemu-system-aarch64`, or
      `limactl` in **System Settings → Privacy & Security → Full Disk Access**.
      Remove any pre-existing grants before running this test to avoid masking
      a denial.
- [ ] `~/Documents/tcc-test/` directory exists and contains at least one file
      the test session can read.

**Steps:**

1. Open a terminal in your GUI login session (not SSH-only).

2. Confirm the agent is running in your Aqua session:
   ```sh
   launchctl print gui/$(id -u)/io.sandboxd.agent
   ```
   The output should show `state = running`. If it shows `state = not running`,
   the agent has not checked in with the daemon yet — wait a moment and retry,
   or check `/var/log/sandbox/agent.stderr.log` for errors.

3. Create a full-backend session with a `shared:` mount into `~/Documents`:
   ```sh
   sandbox create --workspace shared:~/Documents/tcc-test my-tcc-test
   ```

4. **Observe:** Does a TCC consent dialog appear?

   - **If yes:** Note the binary name shown in the dialog. It is either
     `sandbox-agent`, `limactl`, or `qemu-system-aarch64`. Record it in the
     results table below.
   - **If no dialog appears and the mount fails:** TCC silently denied access
     (fully daemonized qemu with no Aqua responsibility chain). Record
     "no prompt, access denied" and use the Full Disk Access fallback.
   - **If no dialog appears and the mount succeeds:** A pre-existing grant
     is masking the test. Re-check and clear all relevant grants, then retry.

5. If a dialog appeared, click **Allow**.

6. Verify the mount works:
   ```sh
   sandbox exec my-tcc-test -- ls /workspace
   ```
   You should see the files from `~/Documents/tcc-test/`.

7. Test grant persistence across a session restart:
   ```sh
   sandbox stop my-tcc-test
   sandbox start my-tcc-test
   sandbox exec my-tcc-test -- ls /workspace
   ```
   No second prompt should appear; the mount should succeed.

8. Test upgrade invalidation (only relevant if the dialog named `qemu-system`
   or `limactl`):
   ```sh
   brew upgrade qemu  # or: brew upgrade lima
   sandbox stop my-tcc-test
   sandbox start my-tcc-test
   sandbox exec my-tcc-test -- ls /workspace
   ```
   If a new consent prompt appears after the upgrade, the grant was keyed to
   the Homebrew binary's cdhash. Record this behavior in the table below.

9. Clean up:
   ```sh
   sandbox rm --force my-tcc-test
   ```

**Results table — record outcome here:**

| Item | Result |
|---|---|
| macOS version | |
| Apple Silicon model | |
| Prompt appeared on first `shared:~/Documents` access? | yes / no |
| If yes — binary named in the prompt | sandbox-agent / qemu-system-aarch64 / limactl / other |
| Mount succeeded after Allow? | yes / no |
| Grant persisted across session restart? | yes / no |
| After `brew upgrade qemu` — new prompt appeared? | yes / no / not tested |
| Full Disk Access required as fallback? | yes / no |
| Notes | |
