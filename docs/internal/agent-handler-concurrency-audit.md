# Agent handler concurrency audit

**Subject.** Every surface the per-operator macOS agent (`sandbox-agent`)
touches while executing a brokered op, examined for safety when several ops run
at the same time.

**Why it was done.** The broker channel between the daemon and each operator's
agent is pipelined: the daemon may have several ops outstanding on one control
connection and correlates responses by `request_id`. The protocol change is the
visible half of that work and the easy half to mistake for all of it. Handlers
written when ops arrived one at a time may touch process-global state,
filesystem staging paths, or `limactl` working sets that collide — none of
which the protocol change would surface.

**What "already existed" means here.** Part of this audit covers behaviour that
predates pipelining. The agent already dispatched each one-shot op on
`tokio::spawn` (so a long op could not stall the heartbeat) and already ran
stream connections concurrently with one-shot ops. Concurrency between handlers
was therefore already reachable; pipelining makes it ordinary rather than
incidental. That makes the audit cheaper than it sounds and does not make it
optional — several findings below are about surfaces that were already exposed
and had simply never been enumerated.

**Verdict.** Two changes were required and made; everything else was examined
and left alone, with the invariant each surface depends on recorded so a later
change cannot quietly break it.

---

## What was examined

Every handler reachable from the agent's op dispatch, plus the connection-level
state they share:

| Surface | Handlers |
|---|---|
| VM lifecycle | create, start, stop, delete, clone |
| Inventory | list, read owner marker, read user key |
| In-VM installation | install guest agent |
| Workspace sync | run rsync |
| Boot verification | restrict-on verify (QMP + wrapper marker) |
| Streaming | guest socat byte-pump |
| Docker ops | container / network / volume / image lifecycle; the stdin-fed egress-plane writes |
| Connection-level | control-connection writer, request/response framing, run context |

Along the three axes concurrency actually breaks things:

1. **Process-global state** — anything a handler sets that another handler
   observes: `umask`, environment, statics, current directory.
2. **Filesystem staging paths** — any path a handler writes that is not keyed
   by something unique to the op.
3. **Colliding `limactl` working sets** — two invocations that touch the same
   instance directory, cache, or control socket.

---

## Findings

### 1. The agent's runtime is single-threaded — blocking it stalls everything

**Found.** The agent runs on a current-thread Tokio runtime. Any handler that
performs synchronous blocking work occupies the *only* runtime thread, which
stalls the heartbeat and every other op in progress, not just its own caller.
Two handlers did:

- **Boot verification's QMP query.** A synchronous Unix-socket exchange with
  QEMU carrying a 10-second read timeout and a 5-second write timeout — up to
  ~15 seconds of blocked runtime per call.
- **Operator home-directory resolution** (`getpwuid_r`), performed once per
  `limactl` invocation. On a directory-backed account this is a Directory
  Services round trip and can be slow; the daemon already treats the analogous
  group-membership lookup as blocking work for exactly this reason.

Under strictly-serial ops this cost at most the one op that was running. Under
pipelining it costs every op that was supposed to be running alongside it, and
the concurrency the transport provides would be silently unavailable whenever
one of these was in flight.

**Changed.** Both moved to the blocking pool via `spawn_blocking`, which a
current-thread runtime still has. The QMP call additionally treats a
task-join failure as "inconclusive" and falls back to the wrapper marker,
rather than reporting a restrict-off finding it did not actually make.

### 2. `umask` is process-global, and safe only because it is uniform

**Found.** Three handler sites call `libc::umask(0o077)` immediately before
creating a file, so the file lands at `0600`. `umask` is process-wide: a
concurrently running handler's file creation sees whatever value was last set.

**Not changed, and here is the invariant.** Every setter sets the same value,
none restores a previous one, and no agent code path wants a looser umask. The
value therefore converges after the first call and every interleaving produces
the same result. Each call site is also immediately followed by its write with
no `await` in between, so the handler cannot be suspended between setting and
using it.

The constraint this places on future work: **a handler that needs a different
umask cannot get one this way.** It would have to create the file and `chmod`
it, or set the mode at open time. Adding a second umask value to this process
would make the outcome depend on interleaving.

(The `umask` calls in `pre_exec` hooks are a separate matter — those run in the
forked child, after `fork` and before `exec`, and affect nothing else.)

### 3. Staging paths are keyed by VM name — except one, inside the guest

**Found.** Host-side staging paths (the rendered instance YAML, the owner
marker) are all under the per-operator home and named after the VM, so two ops
for different VMs cannot collide. The one exception is on the *guest* side: the
guest-agent install copies its binary to a fixed path in the VM's `/tmp` and
then moves it into place.

That path is per-VM (different VMs have different filesystems) but **not
per-op**. Two concurrent installs targeting the *same* VM would race: one
copy could overwrite the other's staged binary between its copy and its move.

**Not changed.** The daemon installs the guest agent once per VM boot, from one
call site, so two concurrent installs for one VM do not occur. Recording it
because the safety here rests on a **daemon-side invariant, not on anything the
agent enforces** — and because it is the template a second in-VM staging path
would be copied from. A new one should carry a per-op suffix rather than
inherit this shape.

### 4. Shared `limactl` state: the download cache and the QMP socket

**Found.** Two pieces of state are shared between concurrent `limactl`-touching
ops for one operator:

- **The download cache.** Every invocation is given the same `XDG_CACHE_HOME`
  inside the operator's home, so concurrent image-fetching operations would use
  one cache directory. Whether Lima's own cache handling is safe against that
  was **not verified here** — it was not needed, because the daemon issues at
  most one image-fetching op per operator (the base-image build is a one-off).
  If that changes, the check belongs there and not in this document.
- **The QEMU control socket.** Boot verification connects to the per-VM QMP
  socket. Two concurrent verifications of the *same* VM would open two QMP
  sessions against one QEMU process. The daemon issues one verification per VM
  boot, so this does not arise.

Per-instance operations that Lima itself serializes (two ops against one
instance) are unchanged by pipelining: the daemon sequences them because the
caller awaits each response before issuing the next.

**Not changed.** Both are safe under current daemon-side call patterns, and
both would be unsafe under call patterns nobody has a reason to introduce.

### 5. Connection-level state holds under concurrent writers — verified, not assumed

**Found and left alone**, because it was already correct:

- **The control-connection writer** is shared between the heartbeat loop and
  every op task through one lock. The lock is held across a complete frame —
  JSON body *and* terminating newline — so frames from concurrent tasks cannot
  interleave mid-frame no matter how many op tasks are writing.
- **Response order is not meaningful and nothing depends on it.** Each op task
  writes when its own op finishes, so a fast op started second can answer
  first. Correlation is by `request_id` on both sides. The daemon's request
  ids come from an atomic counter, so concurrent callers cannot be issued the
  same id.
- **Per-op context is cloned, not shared.** Each op task gets its own copy of
  the immutable run context (uid, per-operator home, socket path). There is no
  shared mutable handler state.
- **Validation statics** are lazily-initialised compiled regexes, immutable
  after initialisation and used through shared references.
- **The environment is read-only after startup.** The agent sets its `PATH`
  once, before the runtime exists; handlers only read environment variables.
  (The remaining environment mutations in the crate are in test code.)

One pre-existing path was re-examined and its comment corrected rather than its
code: the legacy single-connection streaming fallback needs sole ownership of
the connection's writer, which it can only have if no op task is running. Its
comment justified that by asserting the daemon sends one op at a time — an
assertion pipelining retires. The path is unreachable from a daemon new enough
to pipeline (such a daemon always uses the multiplexed form), and the
combination that "cannot happen" is already handled: the agent closes the
connection and reconnects, which is what the legacy path does after every
stream anyway.

### 6. Small synchronous file I/O — examined and accepted

Several handlers read or write small local files synchronously (a marker file,
the rendered YAML, the SSH key). These are local-filesystem operations on files
of a few kilobytes, bounded and sub-millisecond in the ordinary case, and they
are not what makes an op slow. They are recorded as examined rather than
overlooked. The line drawn in finding 1 is deliberate: work whose duration is
governed by a *timeout in seconds* or by a *directory service* goes to the
blocking pool; a local file read does not.

### 7. The Docker op handler — no agent-side shared state, and one rule about stdin

The Docker handler arrived after this audit was first written and is examined
here on the same three axes.

**Process-global state: none.** The handler builds a `Command`, clears *its*
environment and reconstructs `PATH` and `HOME` on the child. That mutates the
child's environment, not the agent's, so two handlers preparing invocations at
the same time cannot see each other's. The one process-global read is `PATH`,
which finding 5 already establishes is read-only after startup. The Docker
socket is derived from the per-op run context, which is cloned rather than
shared, so no two ops can disagree about it and none can change what another
sees.

**Filesystem staging paths: none on the agent.** The egress-plane writes put
their artifact inside a *container*, and the path they write is a constant. The
only agent-side path in the family is the staged image tarball, which is opened
read-only. Nothing here writes a temp file on the agent, so finding 3's
"per-op suffix" rule has nothing to apply to.

**Colliding working sets: two, both safe, and for different reasons.**

- **Two writes to the same file in one container.** The listener — the one
  artifact rewritten repeatedly while a session runs, by the DNS-propagation
  loop — is delivered by write-to-staging plus rename, so a reader sees one
  generation or the other and never a mixture. That property exists for Envoy's
  LDS watcher and it happens to be the right answer here too. The other writes
  are `Replace`, which would interleave if two ran at once; they do not, because
  each is issued from an awaited step of a single distribution.
- **Two `nft -f -` applications in one netns.** `nft` applies an input as one
  transaction, so concurrent applications produce one ruleset or the other,
  never half of each. This is the property the egress plane already depends on
  for a single application and it extends to concurrent ones.

**One change, and it is about the runtime, not about sharing.** The artifact
goes to the child on a pipe, and a pipe fills. Writing it with a synchronous
`write_all` would block the agent's *only* runtime thread until the child
drained it — finding 1's failure, reached by a new route, and reached by a
handler whose payload can be megabytes rather than milliseconds. The write is
therefore `tokio`'s async `write_all` on an async child pipe: it yields while
the pipe is full instead of holding the thread. **The constraint on future
work:** a stdin-fed op must keep its write async. It is the one place in this
family where the obvious synchronous call is the wrong one, and it does not
look wrong.

---

## Summary

| # | Surface | Outcome |
|---|---|---|
| 1 | Blocking calls on a single-threaded runtime | **Changed** — QMP query and home-directory resolution moved to the blocking pool |
| 2 | Process-global `umask` | Unchanged — safe by uniformity; invariant recorded |
| 3 | In-guest install staging path | Unchanged — safe by a daemon-side invariant, not by construction |
| 4 | Shared download cache, QMP socket | Unchanged — safe under current call patterns; one property deliberately not verified, and why |
| 5 | Connection writer, ids, per-op context, statics, environment | Unchanged — verified correct under concurrent writers |
| 6 | Small synchronous file I/O | Unchanged — examined and accepted, with the rule that distinguishes it from finding 1 |
| 7 | Docker ops, including the stdin-fed egress-plane writes | No shared agent-side state; the stdin write is async so a full pipe cannot stall the runtime |
