# Lite mode: container backend for sandboxd

Base commit: 148818f30c07b5b12aad3d98dd80ee5ef1e05de2

## Summary

This spec introduces a second session backend for `sandboxd`: a Docker
container, selected via `--lite` (or `--backend container`). It sits
alongside the existing Lima/QEMU VM backend behind a new backend
abstraction. The user promise is **full UX parity with VM sessions and
much faster session creation**, traded for **container-level isolation**
rather than VM-grade isolation. The trade-off is surfaced at every
`--lite` create — never hidden.

Work breakdown is deferred; this spec describes the target state and the
component changes required, not the implementation work items.

## Context

### Why this is needed

VM-backed sessions are the right default for untrusted code, but they
are heavy for small ad-hoc work. VM boot plus guest-agent install is the
dominant cost of session creation today — the path runs through QEMU
spin-up, SSH availability, the guest-agent handshake, and gateway
attach. For an operator running a throwaway shell or a short CI-style
check, that step is what makes sessions feel expensive.

A container session collapses the runtime spin-up into a `docker
create` + `docker start` against a pre-built image. The gateway + CA +
policy path that follows is shared with VMs and unchanged. Lite turns
the common VM-time setup into a one-shot image build (paid lazily on
first use of a given daemon version), making throwaway and scripted
session use practical in a way VMs don't support today.

### The trade-off

Containers share the host kernel. Lite sessions are hardened by default
(read-only rootfs, seccomp, `no-new-privileges`, `cap-drop=ALL`,
non-root user, pids/memory/cpu limits), but this is not VM-grade
isolation. A kernel exploit in the guest workload escapes the container;
the equivalent exploit in a VM guest is bounded by QEMU + KVM.

This spec does not pretend otherwise. Lite is the right choice when the
workload is trusted-enough (the operator's own code, a known-good CI
image, an agent the operator supervises). VMs remain the default and the
recommended choice for untrusted workloads.

### Operating constraints

**No external back-compat required.** sandboxd has no production users.
The session DB adds a new column; rollback to a pre-lite daemon is
documented with a "purge lite sessions before rolling back" caveat
rather than a two-way migration.

**No regressions on the Lima path.** The backend abstraction preserves
Lima's external behavior end-to-end — same performance, same test
coverage. The architecture around Lima is genuinely new; the behavior
through that architecture is unchanged. Container is a second
implementation behind the same traits.

### Install-time setup

Lite introduces three install-time prerequisites. These are operator
contract, not deployment convention — the daemon refuses to serve
lite-backed sessions without them in place.

- **`setcap cap_sys_admin+ep` on `sandbox-route-helper`.** Applied to
  the installed binary. Mirrors the existing requirement for
  `qemu-bridge-helper` (setuid-root); packaging guidance points to the
  same install step. No setuid bit is applied — file capabilities
  only.
- **`/etc/sandboxd/users.conf` populated with at least the sandboxd
  user's subnet entry.** Root-owned, mode `0644`, JSON. The daemon
  fails to start without a matching entry and emits an error pointing
  at the file and the install docs. See "Networking → Config file"
  below for the shape.
- **Linux kernel 5.8+.** The helper uses `pidfd_open(2)` (Linux 5.3+)
  and `setns(pidfd, CLONE_NEWNET)` (Linux 5.8+) for its netns-entry
  step. 5.8 is a reasonable floor for the sandboxd project overall and
  does not materially constrain supported hosts.

These are one-time per host.

**Deployment model.** The helper's `allow_users` check uses `getuid()`
as ground truth for session ownership. This assumes each OS user runs
their own `sandboxd` instance under their own uid — the daemon and the
sessions it manages share that identity. A shared system-level daemon
serving multiple end-users via API (with `sandboxd` itself running as
a service user separate from the end-user identities) is a different
deployment model and is not supported by this design. Multi-user on a
single host means _multiple OS users each running their own
`sandboxd`_, each with their own subnet entry; the single-user case is
the degenerate form (one subnet, one username in `allow_users`).
Multi-user sandboxd UX is out of scope (see Non-goals); the config
shape is multi-user-compatible by construction, not a multi-user
feature surface.

---

## Architecture

### Two traits

New module: `sandbox-core/src/backend/`.

```rust
pub trait SessionRuntime: Send + Sync {
    fn kind(&self) -> BackendKind;
    fn capabilities(&self) -> &Capabilities;

    async fn create(&self, spec: &SessionSpec) -> Result<RuntimeHandle>;
    async fn start(&self, handle: &RuntimeHandle) -> Result<()>;
    async fn stop(&self, handle: &RuntimeHandle) -> Result<()>;
    async fn delete(&self, handle: &RuntimeHandle) -> Result<()>;
    async fn status(&self, handle: &RuntimeHandle) -> Result<RuntimeStatus>;
    async fn ip(&self, handle: &RuntimeHandle) -> Result<IpAddr>;

    fn guest_transport(&self, handle: &RuntimeHandle) -> Arc<dyn GuestTransport>;

    async fn exec_interactive(
        &self,
        handle: &RuntimeHandle,
        cmd: Vec<String>,
        stdin: Box<dyn AsyncRead + Unpin + Send>,
        stdout: Box<dyn AsyncWrite + Unpin + Send>,
        stderr: Box<dyn AsyncWrite + Unpin + Send>,
    ) -> Result<ExitCode>;
}

pub trait GuestTransport: Send + Sync {
    async fn connect(&self) -> Result<Box<dyn AsyncReadWrite>>;
}
```

`GuestTransport` and `exec_interactive` do different jobs:

| Path                        | Consumer                                            | Payload                                                           |
| --------------------------- | --------------------------------------------------- | ----------------------------------------------------------------- |
| `GuestTransport::connect()` | sandboxd → in-sandbox `sandbox-guest` agent         | Structured JSON protocol: `ping`, `exec`, `file upload`, `status` |
| `exec_interactive()`        | `sandbox ssh`, `sandbox exec`, `git-remote-sandbox` | Raw process exec; stdio streamed through                          |

Keeping them separate lets the transport evolve (e.g. future gRPC,
multiplexed channels) without churning the lifecycle contract.

`RuntimeHandle` is an opaque per-backend blob. Lima stores an instance
name; container stores a container name. Daemon code does not inspect it
— each backend's own impl dereferences it.

### Two implementations

| Trait impl                                | Notes                                                                                                                                                                                                         |
| ----------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `LimaRuntime` + `LimaTransport`           | Refactor of today's `LimaManager` in `sandbox-core/src/lima.rs`. Transport wraps `limactl shell <vm> -- socat - TCP:127.0.0.1:5123` (the existing agent transport; unchanged).                                |
| `ContainerRuntime` + `ContainerTransport` | New. Transport wraps `docker exec <container> socat - TCP:127.0.0.1:5123` — mirrors Lima exactly. The `sandbox-guest` agent binds TCP on `127.0.0.1:5123` in both backends; no agent-side changes are needed. |

Both implementations are stateless over `RuntimeHandle`: one instance
per `BackendKind`, shared across all sessions of that kind.

### What stays put

Reused verbatim across both backends:

- `NetworkManager` (bridge allocation, IP assignment)
- `GatewayManager` (per-session gateway container boot, CA plumbing,
  policy distribution)
- `CaManager` (per-session CA issuance)
- `PolicyCompiler` (nftables, Envoy, CoreDNS, mitmproxy outputs)
- `SessionStore` (session DB + persistence rules from CLAUDE.md)
- `git-remote-sandbox` (calls `exec_interactive` through the session's
  runtime — backend-agnostic)
- The HTTP surface on `sandboxd.sock`

**Propagation tracking is backend-agnostic.** Per-session
`PropagationStates` are exposed via
`GET /sessions/{id}/policy/propagation-status` and the
`sandbox policy status --wait` CLI. Policy application is not
synchronous from the caller's perspective: the daemon records an
"applied" hash at distribution time and a "propagated" hash when the
gateway components confirm the ruleset is live. Both Lima and
container sessions use this path identically — propagation tracking
hangs off the gateway and session-id, not off the runtime
abstraction, and neither `SessionRuntime` impl needs propagation-
specific code.

### AppState composition

```rust
pub struct AppState {
    // existing fields ...
    pub runtimes: HashMap<BackendKind, Arc<dyn SessionRuntime>>,
    pub session_store: Arc<SessionStore>,
    pub network_manager: Arc<NetworkManager>,
    pub gateway_manager: Arc<GatewayManager>,
    // ...
}
```

`BackendKind::{Lima, Container}`. Daemon routes by the `backend` column
on the session row (see "Persistence") to the matching `runtimes` entry.

### Paths summary

| Concern                                                         | Path                                                                                                  |
| --------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------- |
| New traits and `BackendKind`, `Capabilities`, `BackendSpecific` | `sandbox-core/src/backend/`                                                                           |
| Lima impl (refactor)                                            | `sandbox-core/src/backend/lima.rs` (from `sandbox-core/src/lima.rs`)                                  |
| Container impl (new)                                            | `sandbox-core/src/backend/container.rs`                                                               |
| Dockerfile + agent binary staging                               | `sandboxd/images/lite/Dockerfile` (source), materialized at `{runtime_dir}/images/lite/` at first use |
| Route helper (new standalone crate)                             | `sandboxd/sandbox-route-helper/`                                                                      |
| E2E lite tests                                                  | `tests/e2e/test_lite.py`                                                                              |

---

## Image building

### First-use build, not startup-time

The lite image is built **locally on first create when missing**, not at
daemon startup. This mirrors Lima's golden-image behavior: the heavy
setup step is paid lazily, once, on first use of a given version.

### Mechanics

- `ContainerRuntime::create()` calls `ensure_image()` before any
  `docker create`.
- `ensure_image()` is serialized by a dedicated `container_image_lock:
Mutex<()>` on `ContainerRuntime`, sibling to the existing
  `base_image_lock` used for the Lima golden image.
- Image tag: `sandboxd-lite:<daemon-version>`. A daemon version bump
  invalidates the tag; next first-use triggers a rebuild.
- Build context: staged at `{runtime_dir}/images/lite/` at
  `ensure_image()` time, then `docker build -t sandboxd-lite:<ver>` is
  invoked with that directory as the context. Two inputs feed the
  staging directory:
  - **Dockerfile** — baked into the `sandboxd` binary via
    `include_str!` (it is small, static text) and written out at
    staging time.
  - **`sandbox-guest` binary** — located on disk at
    `{exe_parent}/sandbox-guest`, same convention Lima already uses
    (`sandbox-core/src/lima.rs` finds the agent at that path and
    `limactl copy`s it into the VM). `ensure_image()` copies the
    binary from `{exe_parent}/sandbox-guest` into the staging dir.
    The binary is **not** embedded in `sandboxd`; no `build.rs`
    cross-workspace embedding, no binary bloat.

### First-use warning

Printed by the daemon (surfaced via the HTTP create response so the CLI
can echo it) on every first-use rebuild:

```
lite: first use on this daemon version — building lite image
```

Subsequent `create` calls on the same daemon version skip the warning
entirely (image already present).

### Dockerfile shape

```dockerfile
FROM ubuntu:24.04

RUN apt-get update && apt-get install -y --no-install-recommends \
      bash coreutils git socat ca-certificates iproute2 curl tini \
    && rm -rf /var/lib/apt/lists/*

# Ubuntu 24.04 ships a default `ubuntu` user at uid 1000; remove it so the
# agent user can take that uid as the spec requires.
RUN userdel --remove ubuntu 2>/dev/null || true \
    && useradd --uid 1000 --user-group --create-home --shell /bin/bash agent

COPY sandbox-guest /usr/local/bin/sandbox-guest
RUN chmod +x /usr/local/bin/sandbox-guest

USER 1000:1000
ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/sandbox-guest"]
```

- **Base:** Ubuntu 24.04 (noble), same userland as the Lima VM image
  (also noble). Package installs and shell-script invariants match
  between backends.
- **`tini`** as PID 1 reaps zombies and forwards signals correctly to
  the agent.
- **Non-root `agent` user** at uid 1000 / gid 1000.
- **Agent transport:** `sandbox-guest` binds TCP on `127.0.0.1:5123`
  (the same endpoint Lima uses today). No flags, no Unix-socket path.
  The container-side transport reaches the agent via `docker exec
<container> socat - TCP:127.0.0.1:5123`, matching Lima's
  `limactl shell <vm> -- socat - TCP:127.0.0.1:5123`.

### Explicit non-goals for image building

- **Registry pull.** The image is always built locally. Distribution
  via a registry is a future feature applicable to both backends.
- **BYO Dockerfile.** Future feature, same category.
- **Multi-stage layer caching across daemon versions.** A version bump
  rebuilds from scratch. No intermediate-layer reuse.

---

## Container specifics

### Networking

Attach the lite container to the same per-session Docker bridge the
gateway container uses. Docker handles bridge attach and DNS pointer;
the **default route inside the container is installed from the host by
a small setcap helper the daemon invokes** (`sandbox-route-helper`),
not by Docker, so that traffic flows through the gateway container
rather than around it. The daemon itself stays unprivileged — see
"Daemon privilege (unchanged)" below.

#### Per-session IP layout

Unchanged from today (see `sandbox-core/src/network.rs` — per-session
`/28` blocks):

| Address | Role                                                        |
| ------- | ----------------------------------------------------------- |
| `.0`    | Network address                                             |
| `.1`    | Docker bridge interface, host side (auto-claimed by Docker) |
| `.2`    | Gateway container                                           |
| `.3`    | Session peer (VM today, container tomorrow)                 |

#### Why Docker's default route is wrong for lite

Docker's automatic default-route assignment points the container at the
bridge's **host-side** interface — `.1` — not at the gateway container
at `.2`. A lite container left at Docker defaults would route to the
host and bypass the gateway entirely, skipping all policy enforcement.
Lima VMs today work around this inside the guest via cloud-init (which
needs `CAP_NET_ADMIN`); the lite container's hardening envelope drops
that capability, so the fix cannot live inside the container.

#### Fix: setcap route helper

The default route is installed from the host, after `docker start` and
before the agent is declared ready, by a narrow setcap helper binary —
`sandbox-route-helper`. The daemon itself stays unprivileged; it shells
out to the helper for this one operation and nothing else.

**Invocation.** The daemon calls:

```
sandbox-route-helper <container-pid> <gateway-ip>
```

and checks the helper's exit code before proceeding to the agent-ready
wait. No other arguments, no stdin, no environment inputs.

**Setcap pattern — `qemu-bridge-helper` analogy.** `sandbox-route-helper`
is installed with file capabilities (`setcap cap_sys_admin+ep`) and no
setuid bit. The setns + route-install syscalls require `CAP_SYS_ADMIN`;
granting it to the helper binary alone — rather than to the daemon
process — keeps the privilege bounded to one 200-line program with a
single well-defined job. This mirrors the existing `qemu-bridge-helper`
pattern already in use by the VM backend: a small privileged binary
performing one host-side operation on behalf of an otherwise
unprivileged caller. Operators already apply `setcap` at install time
for `qemu-bridge-helper`; `sandbox-route-helper` reuses that operator
contract rather than introducing a new one.

**Lifecycle phase.** Between container start and transport handshake:

1. `docker start <container>`.
2. Daemon reads the container's PID: `docker inspect -f
'{{.State.Pid}}' <container>` — the host-namespace PID of the
   container's init process.
3. Daemon invokes `sandbox-route-helper <container-pid> <gateway-ip>`.
4. Helper performs the eight-step authorization flow (below) and, on
   success, installs the default route in the container's netns.
5. Daemon proceeds to the agent-ready wait on `TCP:127.0.0.1:5123`
   (via `docker exec`).

The `--cap-drop=ALL` envelope stays absolute — no `CAP_NET_ADMIN` is
ever present inside the container, at any point in its lifetime.

#### Helper authorization flow

The helper runs eight ordered steps per invocation. Any failed step is
a deny: non-zero exit, no action taken on the container's netns.

1. `getuid()` → caller uid; resolve to username via `getpwuid`.
2. Parse `<gateway-ip>` argument.
3. Load `/etc/sandboxd/users.conf`. Find the subnet entry whose `cidr`
   contains `<gateway-ip>`. No match → deny.
4. Check caller's username is in that subnet's `allow_users`. Not
   present → deny.
5. Open a pidfd for the target and join its netns atomically:

   ```c
   int pidfd = pidfd_open(container_pid, 0);
   if (pidfd < 0) deny("pid vanished");
   if (setns(pidfd, CLONE_NEWNET) < 0) { close(pidfd); deny("setns failed"); }
   ```

   `pidfd_open(2)` (Linux 5.3+) returns a file descriptor that the
   kernel invalidates if the referenced process dies; the kernel will
   not reuse a pidfd for another process. `setns(pidfd, CLONE_NEWNET)`
   (Linux 5.8+) joins the network namespace of the referenced process
   atomically against the pidfd.

6. Enumerate all non-loopback interface addresses in the target netns.
   **Every** non-`lo` address must be in the same subnet matched in
   step 3. If any address is outside that subnet, deny.
7. `ip route replace default via <gateway-ip>`.
8. Exit 0.

Usernames appear in the config for admin readability; the helper
compares numeric uids internally, so admin renames (e.g. `usermod`)
take effect immediately — there is no silent caching layer.

**PID TOCTOU closure.** Between the daemon's `docker inspect` and the
helper's netns entry, the container could in principle exit and the
kernel could recycle its pid for an unrelated process. A naked integer
pid passed to `setns(open("/proc/<pid>/ns/net"))` would then operate on
the wrong namespace. Using `pidfd_open` closes that window: if the
container exits between `docker inspect` and `pidfd_open`, the call
returns `-1` with `ESRCH`; the helper denies and exits without touching
any netns. There is no window in which the helper can operate on a
reused pid.

**Cross-user MITM closure (step 6).** Step 6 is the one that closes
the cross-user MITM vector in multi-user deployments: without it, a
caller whose own gateway sits in their own authorized subnet could
retarget another user's container — one whose netns addresses belong
to that other user's subnet — at the caller's gateway, and intercept
the victim's traffic. Requiring every container netns address to live
in the caller's matched subnet forbids that cross-subnet retargeting.
It also subsumes container identity: if a container has IPs in a
sandbox-allocated subnet, it is by construction a sandbox container
(no other allocator uses those ranges), so a separate "is this a
sandbox container?" check would be redundant.

#### Config file: `/etc/sandboxd/users.conf`

Single source of truth for subnet → user authorization. Root-owned,
mode `0644`, JSON (per project convention — see
`/home/olek/Projects/claude-sandbox_specs/CLAUDE.md` on config format).
Shape:

```json
{
  "subnets": [
    { "cidr": "10.209.0.0/20", "allow_users": ["olek"] },
    { "cidr": "10.210.0.0/20", "allow_users": ["alice", "bob"] }
  ]
}
```

Two parties read this file:

- **Daemon at startup.** Finds the subnet entry whose `allow_users`
  contains the daemon's own user's username; uses that `cidr` to scope
  `NetworkManager`'s per-session `/28` allocation. If no matching
  section exists, the daemon refuses to start, with an error pointing
  at `/etc/sandboxd/users.conf` and the install docs.
- **Helper per-invocation.** Uses it for the authorization flow above.

Neither party writes to the file; admins populate it at install time.
The daemon remains unprivileged — it only reads.

#### Attack table

| Attack                                                                              | Blocked by                                                                                                                              |
| ----------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------- |
| Caller not in any `allow_users`                                                     | Step 4                                                                                                                                  |
| Target container in another user's subnet + gateway in own subnet (cross-user MITM) | Step 6 — container netns IP not in caller's subnet                                                                                      |
| Target container in own subnet + gateway in own subnet                              | Allowed (legitimate)                                                                                                                    |
| Gateway IP outside any defined subnet                                               | Step 3                                                                                                                                  |
| Non-sandbox container targeted                                                      | Step 6 — a non-sandbox container would not have an IP in any `allow_users`-gated subnet, and is rejected by the subnet-membership check |
| Container exits between `docker inspect` and helper's netns entry (pid reuse)       | Step 5 — `pidfd_open` returns `ESRCH`; helper denies before any netns operation                                                         |
| Tampered config                                                                     | Root-owned, `0644` — non-root can't modify                                                                                              |

#### Daemon privilege (unchanged)

The daemon process runs with no host capabilities — unchanged from
today. It needs only `docker` group membership (to talk to the Docker
daemon socket) and `kvm` group membership (for the VM backend). All
privileged operations are delegated: VM path to `qemu-bridge-helper`
(setuid-root), lite path to `sandbox-route-helper` (file capabilities
via `setcap`), volume and container management to the Docker daemon
via `docker.sock`.

Granting `CAP_SYS_ADMIN` to the daemon process itself was considered
during design of this backend and rejected. Today's daemon runs
completely unprivileged; adding `CAP_SYS_ADMIN` to it — even "only for
the nsenter call" — would be a real privilege escalation versus the
status quo, because the capability is ambient across the entire daemon
process's lifetime, not scoped to the one call site that needs it. The
helper pattern preserves the existing privilege envelope exactly: the
daemon's attack surface is unchanged, and the new privileged code
surface is a single small binary with one entry point.

**Timing invariant.** Between `docker start` and the helper call, the
container's default route points at `.1` (host). The lite agent
(`sandbox-guest`) is a TCP listener only — it never initiates outbound
traffic during startup. The daemon's readiness probe reaches the agent
via `docker exec`, which does not traverse the container's default
route. As long as the agent does no outbound I/O before the daemon
signals ready, the window is benign. Any future entrypoint change
that adds outbound startup traffic (phoning home, reporting health
over HTTP, pulling config) must be reconciled with this invariant —
either by deferring that traffic until after the agent becomes ready,
or by moving the route-install earlier in the lifecycle.

**Deny-logger compatibility.** The deny-logger and the
`sandbox_dnat` / `sandbox_policy` two-table split were both delivered
as part of the M10 work, not as part of lite-mode; the lite backend
inherits this infrastructure unchanged. The gateway's
`sandbox-deny-logger` component sits alongside Envoy, CoreDNS, and
mitmproxy, with the nftables ruleset split into `sandbox_dnat`
(egress DNAT via `dst_ip` rewrite) and `sandbox_policy` (layer-based
filtering). The deny-logger observes container-originated traffic
through the same gateway DNAT path it observes VM traffic through;
no backend-specific integration is required. The route-installation sequence above
(gateway up → route installed via helper → agent ready) is compatible
with the deny-logger DNAT + UDP observability path — lite containers
are indistinguishable from VMs from the gateway's point of view once
the default route points at `.2`.

#### Flags and phases

| Concern       | Mechanism                                                         | Value                                                                              |
| ------------- | ----------------------------------------------------------------- | ---------------------------------------------------------------------------------- |
| Bridge        | `--network` at `docker create`                                    | `sb-{session_id}` (per-session bridge allocated by `NetworkManager`, as today)     |
| Session IP    | `--ip` at `docker create`                                         | Allocated by `NetworkManager` from the bridge's subnet (`.3`)                      |
| DNS           | `--dns` at `docker create`                                        | Gateway container's bridge IP (`.2`). DNS pointer is independent of default route. |
| Default route | `sandbox-route-helper` invoked by the daemon, post-`docker start` | `ip route replace default via <gateway-container-ip>` inside the container's netns |

L3 nftables DNAT in the gateway container: unchanged. The gateway does
not know or care whether its session peer is a VM or a container.

### Hardening

Applied at `docker create` time. These are the defaults for every lite
container; operators cannot relax them.

| Flag             | Value                                               | Rationale                                                                                           |
| ---------------- | --------------------------------------------------- | --------------------------------------------------------------------------------------------------- |
| `--read-only`    | —                                                   | Rootfs immutable; mutations only via tmpfs + volumes                                                |
| `--tmpfs /tmp`   | `rw,nosuid,nodev,size=256m`                         | Scratch space                                                                                       |
| `--tmpfs /run`   | `rw,nosuid,nodev,size=16m`                          | Process-runtime state (pid files, lockfiles); not on the agent's critical path — the agent uses TCP |
| `--security-opt` | `no-new-privileges`                                 | Prevents setuid escalation                                                                          |
| `--security-opt` | `seccomp=builtin`                                   | Docker's default seccomp profile                                                                    |
| `--cap-drop`     | `ALL`                                               | No Linux capabilities                                                                               |
| `--user`         | `1000:1000` (or calling uid/gid if host uid ≠ 1000) | Non-root; uid alignment for workspace bind mount                                                    |
| `--pids-limit`   | `512`                                               | Fork-bomb ceiling                                                                                   |
| `--memory`       | configured or default                               | See "Resource defaults"                                                                             |
| `--cpus`         | configured or default                               | See "Resource defaults"                                                                             |
| `--restart`      | `no`                                                | Daemon owns restart semantics                                                                       |

#### What this breaks (documented for users)

- **Docker-in-Docker.** No privileged mode, no `/var/run/docker.sock`
  mount.
- **FUSE.** Requires `CAP_SYS_ADMIN` or device nodes not exposed.
- **Kernel modules.** Not loadable in a userns-less default-seccomp
  container.
- **Raw network sockets.** `CAP_NET_RAW` dropped; `ping` and similar
  tools fail.
- **`/proc` writes.** Dropped; `sysctl -w` fails.

Documented in `docs/lite.md` (new, Phase 3).

### Workspace

Bind mount `/host/path → /home/agent/workspace/`, same as Lima's workspace
mount semantics (the bind target is unified across both backends).

**UID alignment:** pass `--user <host-uid>:<host-gid>` when the host uid
is not 1000, so files written inside the container are owned by the
operator on the host. Do **not** use userns-remap — that would force
chown on host files, which is destructive and surprising.

### Per-session home volume

`/home/agent` lives in a named Docker volume: `sandbox-home-{session_id}`.

- **Survives `stop` / `start`.** Operators can stop and resume a session
  with their shell history, caches, and dotfiles intact.
- **Deleted with `sandbox delete`.** No cross-session persistence.

This is the "β" (middle-ground) option between ephemeral (`/home/agent`
on tmpfs) and cross-session-persistent (a shared host directory). It
matches what a Lima session offers: state within a session, clean slate
between sessions.

### Resource defaults — container only

If `memory_mb` is unset: `host_ram × 0.8`, rounded down to a whole MB.
If `cpus` is unset: `host_cpus × 0.8`, rounded to 1 decimal place.

- Computed **once at daemon startup** and applied per-session on
  creation.
- Treated as **ceilings** (OOM and CFS bound): multiple concurrent lite
  sessions share the same 80% host envelope rather than each getting a
  private slice. This matches operator intuition ("lite is for small
  stuff; don't reserve 80% of my laptop per session").
- Lima defaults are **unchanged** (2 GB / 2 CPUs today). Tuning Lima
  defaults is a separate conversation (called out in non-goals).

### Lifecycle

- `create`: `docker create` → stashes the container id on the
  `RuntimeHandle`.
- `start`: `docker start`, followed by the daemon invoking
  `sandbox-route-helper` to install the default route into the
  container's netns (see "Networking").
- `stop`: `docker stop` (with a bounded timeout).
- `delete`: `docker rm -f <name>` + `docker volume rm
sandbox-home-{session_id}`.
- `exec_interactive`: `docker exec -it <container> <cmd>`, streaming
  stdio through. This is the backend's raw-process-exec path (used by
  `sandbox ssh`, `sandbox exec`, `git-remote-sandbox`); it bypasses
  the agent entirely, mirroring how Lima uses `limactl shell -- <cmd>`
  for the same path.

Restart behavior is owned by the daemon (`--restart=no`). On daemon
startup, the reconcile loop (see "Persistence") drops any stray
containers that don't match a known session.

---

## Capabilities model

The capabilities surface is a single struct per backend, plus an enum of
the features a spec can demand.

### `Capabilities`

```rust
#[non_exhaustive]
pub struct Capabilities {
    pub isolation: IsolationLevel,
    pub nested_virt: bool,
    pub privileged_ops: bool,
    pub raw_network: bool,
    pub hardening_flag: bool,            // QEMU --hardened flag
    pub per_session_no_cache: bool,      // Lima: yes; container: no
    pub workspace_modes: EnumSet<WorkspaceMode>,
}

pub enum IsolationLevel { Vm, Container }
```

Notes:

- `#[non_exhaustive]` — new fields do not silently default in literals;
  backends must explicitly populate them.
- Backend `capabilities()` returns a reference; callers use it for
  validation and for operator-facing capability display.

### `BackendKind` and `BackendSpecific`

```rust
pub enum BackendKind { Lima, Container }

#[serde(tag = "backend", rename_all = "lowercase")]
pub enum BackendSpecific {
    Lima      { hardened: bool, memory_mb: u32, cpus: u32 },
    Container { memory_mb: u32, cpus: u32 },
}
```

`BackendSpecific` is the per-backend config carried by `SessionSpec`. The
container variant is intentionally a near-clone of Lima's minus
`hardened`; it exists now (rather than being collapsed into Lima's
variant) so future divergence does not require a schema migration.

### `UnsupportedFeature`

```rust
#[non_exhaustive]
pub enum UnsupportedFeature {
    Hardening,
    WorkspaceMode(WorkspaceMode, BackendKind),
    PerSessionNoCache(BackendKind),
    // extensible
}
```

`#[non_exhaustive]` — matching on this enum in the CLI's error printer
forces review when new variants are added, so new capability mismatches
don't silently fall through to a generic error.

### Validation sites

```rust
impl SessionSpec {
    pub fn validate(&self, caps: &Capabilities) -> Result<(), UnsupportedFeature> { ... }
}
```

Called **twice**, by design:

| Site               | When                   | Purpose                                                |
| ------------------ | ---------------------- | ------------------------------------------------------ |
| CLI, after parse   | Before any network I/O | Fast, friendly error; user stays local                 |
| Daemon, on request | Authoritative, always  | Defense in depth; CLI might be out of date or bypassed |

### CLI learns capabilities via `GET /backends`

New endpoint:

```
GET /backends
→ [{"kind": "lima", "capabilities": {...}}, {"kind": "container", "capabilities": {...}}]
```

The CLI fetches this **once per invocation**, caches it for the
invocation's lifetime, and uses it to drive client-side validation and
`sandbox inspect -v` display. The daemon's response is the authoritative
source; a CLI version mismatch manifests as either a stricter CLI
(rejects something the daemon would accept — fine, operator can bypass
with `--backend` override) or a laxer CLI (daemon rejects; operator sees
the authoritative error).

### What's deliberately not done

Evaluated during brainstorming and rejected for this round:

- **Marker traits** (`SupportsHardening: SessionRuntime`) — downcasting
  from `dyn SessionRuntime` adds no real safety and complicates the
  registry.
- **Phantom-typed config variants** — overkill for a handful of runtime
  bool checks.
- **Separate per-backend config types not unified under
  `BackendSpecific`** — serde tagging handles this cleanly; divergent
  types would fragment the `SessionSpec` schema.

---

## CLI & UX

### Invocation

Precedence order (first wins):

1. `--lite` flag (sugar for `--backend container`)
2. `--backend container` flag
3. `SANDBOX_DEFAULT_BACKEND=container` env var
4. `default_backend` in user config (`~/.config/sandboxd/config.json`)
5. Hardcoded default: `lima`

```bash
sandbox create --lite                    # container backend
sandbox create --backend container       # same
SANDBOX_DEFAULT_BACKEND=container sandbox create  # same
# with default_backend: "container" in config:
sandbox create                           # same
```

### Isolation warning

**Every** `--lite` / `--backend container` create prints one line to
stderr, followed by a reference to `docs/lite.md`:

```
lite: container-backed session — container-level isolation only (not VM-grade)
      see docs/lite.md for the trade-off details
```

Not once-per-shell. Not buried in `-v`. Per-create. The operator types
`--lite`, the operator sees the warning.

### `sandbox list`

Gains a `BACKEND` column. Sessions from either backend list side-by-side
with an explicit backend identifier.

### `sandbox inspect`

- Default view: shows `backend` prominently alongside session id, state,
  and IP.
- `-v` view: adds a full capability matrix (the `Capabilities` struct
  rendered as a key/value table), fetched from `GET /backends` for the
  matching backend.

### Feature-mismatch errors

Shape:

```
error: `--hardened` requires a VM-backed session, but `--lite` selects the container backend
   help: lite containers apply default hardening automatically
   help: remove `--hardened`, or drop `--lite` to get QEMU-level hardening
```

Exit code **2** (misuse). Distinct from exit code 1 (runtime failure).
Hits before the daemon is contacted (client-side validation); daemon-
side validation produces the same message shape if it ever fires.

### Config file

`~/.config/sandboxd/config.json` — **JSON**, per project convention.

```json
{
  "default_backend": "lima",
  "backends": {
    "container": {}
  }
}
```

The `backends` map is present for future per-backend config (resource
defaults overrides, image tag pins, etc.). Empty objects are valid.

**XDG plumbing.** The `default_backend` loader shares the CLI
config-path resolver used for the preset catalog under
`~/.config/sandboxd/`: honor `XDG_CONFIG_HOME`, treat a missing file
as not-an-error, treat a malformed file as a hard error with a
pointer to the path. One resolver, not two.

### `rebuild-image`: extend the existing flat command

The existing `sandbox rebuild-image` command is extended — no admin
subcommand group is introduced (there is no precedent in the CLI for
that).

```
sandbox rebuild-image [--backend lima|container|all] [--no-cache]
```

- Default `--backend` is `all` — rebuilds each installed backend's
  image. For Lima, "rebuild" means cache-bust the golden image; for
  container, it means rebuild the lite image.
- `--no-cache` passes through to `docker build --no-cache` for the
  container path, and to the equivalent cache-bust mechanism for Lima's
  golden image rebuild.
- Non-zero exit if any selected backend fails. Per-backend errors are
  printed with backend identifier prefix.

### `sandbox create --no-cache` is forbidden on container

`per_session_no_cache: false` is a container capability. `--no-cache` at
session create time is rejected:

```
error: `--no-cache` is not supported with `--lite` / container backend
   help: containers have no per-session slow-path equivalent to Lima's full-VM-create
   help: to rebuild the shared lite image, use:
         sandbox rebuild-image --backend container --no-cache
```

Exit code 2.

**Rationale.** Lima's `--no-cache` means "per-session slow path: full VM
create + guest agent install instead of golden-image clone." For
container, the guest agent is baked into the image at build time; there
is no per-session install step to skip, and no analogous slow path that
would make `--no-cache` at create-time meaningful. The help text routes
the operator to the right tool (`rebuild-image`) for the intent they
probably had.

### What's deliberately not done

- **`sandbox admin` subcommand group.** No precedent today; adding one
  for a single command (`rebuild-image`) is scope creep.
- **`prune-images` command.** YAGNI; `docker image rm` handles the
  container side, and the Lima golden image has one path to delete.
- **Gating flag for `--lite`.** No "set this env var to unlock lite"
  gating; the feature ships usable.
- **Auto-fallback between backends.** An operator asking for `--lite`
  gets `--lite` or an error. No silent VM fallback.
- **Separate `sandbox-lite` command.** The backend is a flag on the
  existing commands, not a parallel binary.

---

## Persistence

sandboxd has no live users (project is in early development). The
persistence design is deliberately boring — no migration shim code, no
one-shot config-rewrite pass.

### Schema change

Single new column on `sessions`:

```sql
ALTER TABLE sessions ADD COLUMN backend TEXT NOT NULL DEFAULT 'lima'
  CHECK (backend IN ('lima', 'container'));
```

- `NOT NULL DEFAULT 'lima'` — existing rows fill with `lima` on upgrade.
- `CHECK` constraint follows the project convention (strict SQL schemas,
  per CLAUDE.md feedback doc).
- **Migration:** `V005__session_backend_column.sql`. The migration
  operates only on the `sessions` table and does not touch
  `policy_rules` or any other schema; it is independently upgradable
  against any prior migration.

### Handle persistence: none, by convention

`RuntimeHandle` is **not** a persisted blob. Both backends derive their
handle from the session id via a naming convention:

| Backend   | Name format            | Recovery         |
| --------- | ---------------------- | ---------------- |
| Lima      | `sandbox-{session_id}` | `limactl list`   |
| Container | `sandbox-{session_id}` | `docker inspect` |

Daemon restart rehydrates handles by reading the sessions row and
constructing the handle from the session id. YAGNI on persisted handle
blobs until a backend has state that can't be cheaply re-derived from
the session id.

### Orphan cleanup on daemon start

Extend the existing gateway-container reconcile pattern:

- On daemon boot, `docker ps -a --filter name=sandbox-*` enumerates all
  containers under the sandbox namespace.
- Any container whose derived session id is **not** in `sessions.db` is
  removed (`docker rm -f`) — including any orphaned `sandbox-home-<id>`
  volumes with no owning session row.
- Runs once at startup; same code path handles crash recovery.

### Rollback scenario

If a V4 daemon (has `backend` column, creates container sessions) gets
rolled back to a V3 daemon (no `backend` column), V3 does not understand
container rows. Mitigation is documented, not coded:

> Before rolling back from a lite-capable daemon to a pre-lite daemon,
> run `sandbox delete` on all lite sessions. The rollback otherwise
> leaves orphan Docker containers and volumes on the host that V3 has
> no way to reconcile.

No marker rows, no version sentinels. Boring and explicit.

### Disk footprint

| Item                            | Size                       | Lifetime                                    |
| ------------------------------- | -------------------------- | ------------------------------------------- |
| Lite image (Docker image store) | ~300 MB per daemon version | Daemon-version-bound (rebuilt on bump)      |
| Per-session home volume         | User-controlled            | Session-bound (deleted on `sandbox delete`) |

---

## Testing

### Unit tests (Rust, `cargo nextest`)

In `sandbox-core`:

- `Capabilities` validation tables: every `UnsupportedFeature` variant
  has a test that constructs a `SessionSpec` triggering it against each
  relevant backend's `Capabilities`.
- `BackendSpecific` serde roundtrip: forward and backward, including
  unknown-field tolerance per CLAUDE.md blob-field rules.
- `GuestConnector` over a mock `GuestTransport`: verifies the structured
  JSON protocol is backend-agnostic.
- `handle_from_session(session_id) -> RuntimeHandle`: pure function, one
  test per backend.
- `ContainerRuntime` resource-math helpers: 80% defaults, rounding
  behavior, ceilings.

### Integration tests (Rust, `make test-integration`)

Requires Docker. In `sandboxd/sandbox-core/tests/` (or the crate's
existing integration-test location):

- `ContainerRuntime` lifecycle against real Docker:
  `create/start/stop/delete` round-trip.
- `ensure_image()`:
  - First build when image missing.
  - No-op when tag already present.
  - Rebuild when daemon version tag changes.
- `GuestTransport` for container: round-trip the agent protocol
  end-to-end (ping, trivial exec, file upload).

**Harness convention.** Lite-mode integration tests follow the same
convention as the existing Docker-touching tests in
`sandbox-core/tests/validators.rs`: tests are named with the
`integration_` prefix and are selected by the `integration` nextest
profile (`sandboxd/.config/nextest.toml`); the default profile
filters them out, so `make test` stays hermetic with no Docker
dependency, while `make test-integration` runs the integration set
after building the gateway image. `TestContainer` RAII wrappers
manage Docker lifecycles; `ContainerRuntime` lifecycle and
`ensure_image()` coverage reuse the same wrapper rather than rolling
a new one. Any lite-mode validator tests added later follow the same
shape: named `integration_*`, living in a file selected by the
integration profile, with no env gate and no `#[ignore]`.

### E2E tests (Python pytest, `tests/e2e/`)

**Parametrization.** Backend-agnostic existing tests are parametrized:

```python
@pytest.fixture(params=["lima", "container"])
def backend(request):
    return request.param
```

Lima-specific tests (nested virt checks, `--hardened` behavior) are
guarded:

```python
@pytest.mark.skipif(backend != "lima", reason="VM-only feature")
```

**New file: `tests/e2e/test_lite.py`** — lite-specific assertions:

- Feature rejection: `--hardened` fails with exit code 2; `sandbox
create --no-cache` fails with exit code 2.
- Hardening posture: read-only rootfs (write to `/` fails), no DinD
  (mounting `/var/run/docker.sock` rejected or unusable), no `unshare
--user` (capability dropped).
- Resource defaults match the host's 80% ceiling (asserted against
  `HostResources` helper; see below).
- Git remote parity: `git-remote-sandbox` works against a lite session.
- Gateway parity: policy rules land, CoreDNS + Envoy + mitmproxy
  operate as in VM tests.
- Workspace UID alignment: files written in-session are host-readable
  as the host uid.
- β volume lifecycle: `/home/agent` state survives stop/start, is gone
  after delete.
- Orphan cleanup: kill the daemon mid-create, restart, assert orphan
  container and volume are reaped.

**Route-helper authorization.** Three tests, one per deny branch,
covering both layers of the authorization model (subnet match + user
match):

- **Cross-user MITM attempt rejected (step 6).** Set up a fixture
  `users.conf` with two subnets, `A` and `B`, each with a distinct
  `allow_users`. Create a container whose netns addresses belong to
  subnet `B`. Invoke the helper from a caller in subnet `A` with a
  gateway IP in subnet `A`. Assert: non-zero exit, stderr matches the
  "container netns IP outside caller subnet" pattern, no route change
  applied to the container's netns.
- **Caller not in `allow_users` rejected (step 4).** Fixture
  `users.conf` with one subnet whose `allow_users` excludes the test
  user. Invoke the helper. Assert: non-zero exit, stderr matches the
  "caller not authorized for subnet" pattern.
- **Gateway IP outside any defined subnet rejected (step 3).** Fixture
  `users.conf` with subnet `10.209.0.0/20`. Invoke the helper with a
  gateway IP outside that range (e.g., `192.168.1.1`). Assert:
  non-zero exit, stderr matches the "gateway IP not in any defined
  subnet" pattern.

Each test fixes the helper's fixture `users.conf` to a tmp path
injected via test-only env var (or by running the helper with a
bind-mounted config), so tests do not touch `/etc/sandboxd/users.conf`
on the host.

**Helpers.** Added under `tests/e2e/helpers/`:

- `LiteBackendHarness`: Python class wrapping lite session lifecycle,
  with hooks that can assert hardening invariants at any session
  lifetime point.
- `HostResources`: helper for expected-default computation (reads
  `/proc/meminfo` and `os.cpu_count()`, applies 80%).

### CI policy

| Trigger           | Scope                           | Wall clock |
| ----------------- | ------------------------------- | ---------- |
| **PR**            | Full E2E against container only | ~5-10 min  |
| **Merge to main** | Full E2E matrix (both backends) | ~30-45 min |
| **Nightly**       | Matrix + perf benchmarks        | longer     |

PR-time container-only exists because lite is fast enough to run on
every PR; the full matrix on every PR would reintroduce the cost that
lite exists to avoid.

### What we are not testing

- **Kernel exploits / container escape.** Explicitly not a goal; lite is
  honest about container-level isolation.
- **Extreme resource exhaustion beyond configured limits.** Limits
  applied is the bar; tracking what Docker+kernel do past that is
  out-of-scope.
- **Cross-backend session migration.** Not a feature. Sessions are
  created on one backend and stay there.

### Flake risk

Docker contention in parallel E2E is a known risk. Mitigation: the
existing `/28` bridge allocator already serializes per-test networking;
no additional isolation is needed. This matches production, where lite
and VM sessions also share the Docker daemon.

---

## Rollout

Four phases. Each gate is a green CI state on the scope of that phase.

### Phase 1 — backend-abstraction refactor (Lima behavior preserved)

- Introduce `sandbox-core/src/backend/` with `SessionRuntime`,
  `GuestTransport`, `BackendKind`, `Capabilities`, `BackendSpecific`.
- Refactor `LimaManager` behind `LimaRuntime` + `LimaTransport`.
- Add `backend` column on `sessions` with `CHECK (backend IN ('lima',
'container'))` and `DEFAULT 'lima'`.
- Populate `AppState.runtimes` with Lima only.
- All existing tests green. No new feature surface, no user-visible
  change.

**AppState threading.** `event_bus`, `ingestors`, `vm_ip_map`,
`propagation_states`, and `component_health_state` already exist on
`AppState` today (not introduced by lite-mode work); the Phase 1
task is to thread them through the new backend abstraction, not to
introduce them. Container sessions register with the event bus,
spawn per-session ingestors over the same gateway JSONL sinks
(Envoy, CoreDNS, mitmproxy, deny-logger), and populate `vm_ip_map`
(the name is historical; the map is really "session-peer IP →
session id", keyed on `.3`) identically to VM sessions. The trait
signature and lifecycle phases admit this directly — the Phase 1
gate is not complete until the Lima runtime still stamps events,
spawns ingestors, and updates propagation state through the new
abstraction exactly as it does today.

**Gate:** full Lima E2E green.

### Phase 2 — container runtime (feature-flagged off)

- Implement `ContainerRuntime`, `ContainerTransport`, Dockerfile, and
  `ensure_image()`.
- New `sandbox-route-helper` crate at `sandboxd/sandbox-route-helper/`.
  Ships as a standalone binary alongside `sandboxd`; install-time
  `setcap cap_sys_admin+ep` is part of the packaging contract.
- New `users.conf` loader in `sandbox-core` — shared between daemon
  (startup subnet-scope lookup) and helper (per-invocation
  authorization). Single parse path, one struct, one set of tests.
- Daemon startup validates `users.conf`: loads the file, finds the
  subnet entry whose `allow_users` contains the daemon's user. No
  matching entry → refuse to start with an error pointing at the file.
- New `GET /backends` endpoint.
- `ContainerRuntime` registered in `AppState.runtimes`.
- **No CLI surface yet** — test-only via direct API.

**Gate:** container integration tests green (including route-helper
authorization tests from "Testing"); Lima path unchanged.

### Phase 3 — user-facing feature

- `--lite` / `--backend container` flags.
- Capability validation (CLI-side via cached `GET /backends`,
  daemon-side authoritative).
- Per-create isolation warning line.
- Error UX: feature-mismatch errors, `--no-cache` rejection.
- `sandbox list` backend column.
- `sandbox inspect` + `-v` capability matrix.
- Config file (`~/.config/sandboxd/config.json`) with precedence chain
  wired.
- `rebuild-image` extended with `--backend`.
- User-facing docs: `docs/lite.md`.

**Gate:** lite E2E (`test_lite.py`) green.

### Phase 4 — parametrization + polish

- Parametrize existing E2E with `[lima, container]`.
- PR-time container-only CI policy in place.
- Orphan cleanup on startup wired in.
- `sandbox inspect -v` capability matrix display.

**Gate:** matrix E2E green on merge-to-main.

---

## Non-goals

Explicit, deliberate exclusions:

- **Bring-your-own image.** Future feature; applies to both backends
  when it lands, not lite-specific.
- **Rootless Docker, gVisor, Kata Containers.** Lite's target is
  **default-hardened Docker**. Alternative runtimes are a separate
  design.
- **Cross-backend session migration.** Not a feature and not on the
  roadmap. Sessions live on the backend they were created on.
- **Lima default resource tuning.** The 80%-of-host default is
  container-only. Whether Lima should move off its current 2 GB / 2
  CPUs is a separate conversation.
- **Registry distribution of the lite image.** First-use local build
  only, in this spec.
- **Lite-mode-specific policy presets.** Presets (see port-explicit
  policies spec) are backend-agnostic. No lite-only preset surface.
- **Multi-user sandboxd UX.** Multi-user deployment is supported as
  _multiple OS users each running their own `sandboxd` instance on
  the same host_ (each with their own subnet entry in `users.conf`).
  A shared system-level `sandboxd-service` serving multiple end-users
  via API — with `sandboxd` running under a service uid distinct from
  the end-user identities — is a different design and not addressed
  here; `allow_users`'s `getuid()`-based check does not meaningfully
  apply to that model. No multi-user-specific CLI, docs, or
  management surface ships in this spec. Single-user remains the
  shape of the supported operator workflow; the
  multi-user-compatible security model is a composition property,
  not a feature.
