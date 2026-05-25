# Cross-user CLI access for sandbox sessions

## Summary

The CLI breaks for six commands (`ssh`, `cp`, `sync`, `workspace push`,
`workspace pull`, and transitively `git-remote-sandbox`) when the
daemon runs as the `sandbox` system user but the CLI is invoked by an
unprivileged operator. The breakage is currently masked: e2e tests run
both the daemon and the CLI as the same user, so the cross-user code
path is never exercised in CI.

This spec adopts the **daemon-mediated** approach used by Docker,
libvirt, LXD, Kubernetes, and systemd-machined: every CLI operation
that needs to reach inside a session goes through the daemon socket.
For SSH-shaped operations (interactive shell, scp, rsync, git remote),
the daemon distributes a per-session SSH config that uses
`ProxyCommand` to tunnel through a daemon endpoint, so the VM's or
container's sshd is reachable only via the daemon — never as a
network endpoint exposed to the host.

To make this uniform across backends, the lite-image gains a minimal
sshd. With sshd inside both Lima VMs and lite-mode containers, a
single CLI code path covers every operation, and external SSH tooling
(VS Code Remote-SSH, JetBrains Gateway, ad-hoc `scp`/`rsync`) works
against either backend through the same generated config.

The CLI writes a **persistent** SSH config block under `~/.ssh/sandbox/`
on first connection to a session, and removes it on session deletion.
Subsequent `ssh sandbox-<id>` invocations — by our CLI, by IDEs, or by
any other SSH client — use the standard SSH config lookup path with
no per-invocation involvement from our CLI.

The proxy endpoint uses **WebSocket** as the daemon-side transport,
following the same evolution Kubernetes made for `kubectl exec`.

Test infrastructure is reworked first, before any production code
change, so the bug is reproducible in CI before fixes land.

The CLI is designed for forward compatibility with macOS hosts even
though the daemon is Linux-only (netfilter and Linux capabilities
are load-bearing on the daemon side). All paths, syscalls, and
filesystem operations on the CLI side are POSIX-portable.

## Context

### Current behaviour

Six CLI subcommands shell out to backend-native tools that are
user-scoped:

- `sandbox ssh` invokes `limactl shell sandbox-<id>` (Lima) or
  `docker exec -it sandbox-<id>` (container).
- `sandbox cp` invokes `limactl cp` (Lima) or container-native copy.
- `sandbox sync`, `sandbox workspace push`, `sandbox workspace pull`
  invoke `rsync` with `-e "limactl shell ..."` as the remote-shell
  transport for Lima.
- `git-remote-sandbox` shells out to `sandbox ssh` internally and
  inherits whatever brokenness `sandbox ssh` has.

For container sessions, `docker exec` and `docker cp` work
cross-user as long as the operator is in the `docker` group, because
Docker's daemon already mediates and does not key resources to the
calling user.

For Lima sessions, `limactl` walks the calling user's
`~/.lima/` directory to find VMs. When the daemon (running as
`sandbox`) created the VM, Lima registered it under
`/home/sandbox/.lima/sandbox-<id>/`. An operator running `limactl` as
their own user sees an empty Lima registry and the lookup fails.

### Why tests pass anyway

The e2e harness launches the daemon as the same user that runs the
test process. Lima registers the VM under that user; `limactl` from
the same user finds it; the cross-user gap is never exercised. The
project already ships a systemd unit for sandboxd, but the e2e
harness ignores it and starts the daemon directly.

### Other commands that touch sessions

All other CLI subcommands either go through the daemon HTTP API
(`create`, `start`, `stop`, `rm`, `ls`, `inspect`, `exec`, `health`,
`events`, `policy update`, `workspace unlock`, etc.) or are
purely local (`version`, `policy preset show`, migration tooling).
Those are unaffected by this bug because the daemon already mediates.

The existing `sandbox exec` subcommand is worth noting: it sends
`POST /sessions/{id}/exec` and the daemon dispatches via the
guest-agent protocol. That is the daemon-mediated pattern we want to
extend to the remaining six commands — though the implementation here
uses SSH as the wire protocol rather than the guest-agent protocol,
for reasons described under Decision.

## Decision: daemon-mediated SSH over a daemon-side TCP proxy

We adopt **Strategy A** in the sense that the daemon is the only
component that can reach the session's sshd; the operator's CLI never
opens a network connection to the VM or container. SSH protocol still
runs end-to-end between the operator's SSH client and the session's
sshd, but the bytes are tunnelled through a daemon endpoint via
`ProxyCommand`.

### Why not pure key distribution (Strategy B)

A "daemon returns SSH config + key, CLI runs `ssh` directly" approach
is simpler, but exposes the session's sshd as a network endpoint that
any process on the host can reach if it learns the key. With the
daemon-mediated tunnel, even a leaked key is useless without
operator-level daemon-socket access, and the daemon can audit every
connection. This recovers most of the per-call-authorization benefit
that pure Strategy A gives Docker/LXD/Kubernetes, while keeping
ergonomic SSH compatibility for both interactive shells and
SSH-speaking tools (scp, rsync, git remote helpers).

### Why not pure stream proxying with a custom protocol

A pure Kubernetes-style streaming exec endpoint (WebSocket with
channel-id framing for stdio/resize/signals) would also work, and is
what dominant multi-tenant daemons do. We pass on it here because:

- The five SSH-shaped commands (ssh, cp, sync, workspace push, pull,
  git-remote) all reduce to "exec a standard SSH client with the
  right config". A bespoke streaming protocol would require us to
  reimplement scp, rsync transport, and the git-remote pipe shape
  ourselves, or layer those on top of `sandbox exec` via `--rsh`.
- The lite-image is already a curated developer-sandbox image we
  control. Adding sshd is a small extension of an image whose whole
  reason for existing is that we get to pick what runs in it.
- External tools (VS Code Remote-SSH, JetBrains Gateway) speak SSH
  natively. A custom protocol would force every such tool to grow a
  sandboxd-specific plugin.

We keep the `sandbox exec` daemon-mediated path as-is for its
non-SSH command-execution use case and as the transport for the
guest-agent. Streaming-protocol design is therefore out of scope for
this spec.

### Why unify both backends on sshd

Operators should not learn two different mental models depending on
which backend a session was created with. With sshd in the lite-image,
the CLI flow is identical regardless of backend. External SSH tools
work against either. The only backend-specific code in the daemon is
"how do I forward bytes to the session's sshd," which is one well-
isolated function per backend.

## Architecture

### Lite-image: bundle sshd

The lite-image currently provisions a guest user named `agent`
(uid 1000). To keep the SSH-config template uniform across backends,
this milestone renames the lite-image guest user to `sandbox` so the
template's `User sandbox` line works without per-backend branching.
This rename is the only user-facing breakage in the lite-image and
is acceptable because the user identity is internal to the
container.

The lite-image Dockerfile gains an openssh-server install and a
launch wrapper that:

- Generates an ed25519 host key on container start. The key is
  ephemeral (lives only in the running container's filesystem) —
  there is no persistence requirement because the SSH config
  disables host-key verification (see Security considerations).
- Starts sshd listening on internal port 22, bound to localhost
  inside the container.
- Configures `sshd_config` so the `sandbox` user reads
  `AuthorizedKeysFile /run/sandbox/authorized_keys`, populated by
  the daemon at container start.

The container does not expose port 22 to the host. The daemon
reaches sshd by `docker exec`-ing into the container with `socat` (the
same pattern already used for the guest-agent transport).

### Daemon: per-session SSH credentials

At session create time:

- For container backend: the daemon generates an ed25519 keypair,
  writes the public key into the container at
  `/run/sandbox/authorized_keys` via a tmpfs bind-mount at start,
  and stores the keypair in a new dedicated SQLite column on the
  sessions row. The column is `ssh_keypair_json BLOB NULL` (a JSON
  envelope `{"public": "<ssh-ed25519 ...>", "private": "<PEM>"}`),
  added via a new forward-only migration
  `V007__add_ssh_keypair.sql`. We pick a dedicated column rather
  than embedding in an existing blob field because the keypair has
  a defined shape, must outlive any in-memory cache, and aligns with
  the project's "prefer strict DB schemas" preference for durable
  per-session state.
- For Lima backend: nothing new is persisted. Lima already manages
  per-VM SSH credentials under the daemon's home directory; the
  daemon reads them on demand when serving the `ssh-config`
  endpoint.

The keypair is plaintext at rest, protected only by the session
DB's file permissions (`{base_dir}/sessions.db`, owned `sandbox`).
This is intentional and matches the de-facto trust model: any
process that can reach the daemon socket can already request the
key via `GET /sessions/{id}/ssh-config`. Members of the `sandbox`
OS group are trusted with every session's private key. This is
restated explicitly in Security considerations.

**Session ownership** is single-operator throughout. The existing
`owner_username` column on the sessions table designates the one
operator entitled to access the session via the daemon API; no
multi-operator attach semantics are introduced or assumed. The
`ssh-config` and `proxy` endpoints reuse the same ownership check
as every other `/sessions/{id}/...` handler.

### Daemon API: two new endpoints

`GET /sessions/{id}/ssh-config` — returns the SSH config text plus
the private key, scoped to the calling operator. The daemon enforces
session-ownership the same way it does for every other
`/sessions/{id}/...` endpoint.

The response is a dedicated DTO (`SshConfigDto`) under the daemon's
`api::dto` module, not a flattened serialization of a domain
struct. Shape:

```
{
  "config": "<ssh config text>",
  "private_key": "<PEM-encoded ed25519 private key>"
}
```

For container sessions created before this milestone (no keypair
in the DB), the endpoint returns `404 Not Found` with a typed error
code `SSH_NOT_AVAILABLE`. The CLI translates this to a human
message instructing the operator to recreate the session — lazy
keypair generation is not supported because injecting a new
`authorized_keys` into a running container would require hot reload
that the lite-image is not designed for.

The config text is generated server-side and always has this shape:

```
Host sandbox-<id>
  HostName 127.0.0.1
  Port 22
  User sandbox
  ProxyCommand sandbox proxy <id>
  IdentityFile <CLI-rewrites-this>
  UserKnownHostsFile /dev/null
  StrictHostKeyChecking no
  ServerAliveInterval 30
  ControlMaster auto
  ControlPath ~/.ssh/sandbox/sockets/%C
  ControlPersist 60
```

`HostName`/`Port` are placeholders — the actual connection is
established by `ProxyCommand`, so the values are not used to open a
socket, but `ssh` requires them syntactically. `IdentityFile` is left
as a placeholder string the CLI replaces with the path to the
persistent key file at `~/.ssh/sandbox/keys/<id>`. The `Host` alias
is the session-id-prefixed name so multiple sessions can coexist in
a single SSH client.

`ControlMaster`/`ControlPath`/`ControlPersist` enable SSH connection
multiplexing. The first SSH invocation opens the tunnel through
`ProxyCommand` and registers a control socket under
`~/.ssh/sandbox/sockets/`. Subsequent invocations within
`ControlPersist` seconds (here 60) attach to the existing tunnel and
skip the WebSocket handshake plus SSH key exchange entirely. This is
a meaningful performance win for `git-remote-sandbox`, which fires
many small SSH operations during a single push/fetch.

A daemon restart (or a session stop/start) closes the proxy
WebSocket, which propagates to the local SSH master process and
causes it to exit. The next ssh invocation falls back to a fresh
`ProxyCommand` and reconnects. No special handling is required on
the CLI side; the only operator-visible effect is the first
post-restart SSH paying the handshake cost again.

`GET /sessions/{id}/proxy` — WebSocket endpoint. Client performs the
standard HTTP-to-WebSocket upgrade handshake; daemon responds with
`101 Switching Protocols` and the connection becomes a WebSocket.
After the handshake, the daemon forwards bytes between binary
WebSocket frames and the session's sshd:

- Lima backend: daemon discovers the per-VM SSH port by running
  `limactl list --format=json` and reading the `sshLocalPort` field
  on the matching instance; this is Lima's documented machine-
  readable surface and is stable across Lima minor versions. The
  daemon caches the port in memory per session for the duration of
  the proxy connection, but re-queries on each new proxy request
  (Lima may reassign on instance restart). Bytes flow
  CLI ↔ daemon ↔ Lima sshd on `127.0.0.1:<sshLocalPort>`.
- Container backend: daemon `exec`s the container with
  `socat - TCP:127.0.0.1:22` and splices the streams. Bytes flow
  CLI ↔ daemon ↔ docker exec stdio ↔ socat ↔ container sshd.

**Async I/O note**: the project convention is to wrap
`std::process::Command` calls in `tokio::task::spawn_blocking`.
That convention is **not** applicable here. A long-lived
`docker exec`/`socat` byte-pipe held inside `spawn_blocking` would
occupy a blocking task slot for the entire SSH session (potentially
hours for an IDE) and deadlock the executor under load. The proxy
handler instead uses `tokio::process::Command` with async pipes and
`tokio::io::copy_bidirectional` between the WebSocket and the
spawned child's stdio. The `limactl` invocation, which is one-shot
and short, follows the existing `spawn_blocking` convention. This
deviation must be called out in code comments so a future drive-by
"add spawn_blocking everywhere" pass does not regress it.

The proxy endpoint does no SSH-protocol parsing — it is a dumb byte
mover. Binary WebSocket frames carry raw SSH bytes with no additional
framing layer. SSH authentication and channel multiplexing happen
end-to-end between the operator's SSH client and the session's sshd.

We follow Kubernetes' choice of WebSocket over a bespoke upgrade
token (the KEP-4006 transition from SPDY). For a local Unix-socket
daemon the "works through L7 proxies" benefit does not apply, but
WebSocket libraries exist in every language we might later expose a
client in, and the per-frame framing overhead is negligible relative
to SSH's own framing.

We do **not** use Kubernetes' channel-id-prefix framing here. K8s
uses channels to multiplex stdin/stdout/stderr/error/resize. Our
proxy carries a single raw byte stream; the SSH protocol does its
own multiplexing inside the tunnel. If we later add a non-SSH
streaming-exec endpoint (out of scope for this spec), that one would
adopt the channel-id pattern.

### CLI: persistent ssh-config + thin `sandbox proxy`

The CLI maintains a managed area at `~/.ssh/sandbox/`:

```
~/.ssh/sandbox/
  config              # one block per known session
  keys/<session-id>   # ed25519 private key, mode 0600
  sockets/            # SSH ControlMaster sockets, ephemeral
  .lock               # flock target for config mutations
```

`~/.ssh/sandbox/` is mode `0700`; `~/.ssh/sandbox/config` is mode
`0600`; key files are mode `0600`; the sockets directory is mode
`0700`. If `~/.ssh/` itself does not exist, the CLI creates it with
mode `0700` before touching anything inside.

The CLI ensures `~/.ssh/config` contains an
`Include ~/.ssh/sandbox/config` line between marker comments:

```
# >>> sandbox managed >>>
Include ~/.ssh/sandbox/config
# <<< sandbox managed <<<
```

The block is inserted **at the very top of `~/.ssh/config`**,
before any other `Host` or `Match` blocks. SSH's first-match-wins
semantics mean an existing `Host *` or `Host sandbox-*` block
earlier in the file would shadow our config; inserting at the top
avoids the shadowing entirely and keeps the block outside any
`Match` scope. The marker comments let the CLI detect its own block
idempotently and remove it cleanly if the operator ever runs an
uninstall.

`sandbox proxy <id>` is registered as a **hidden subcommand**
(`#[command(hide = true)]` or equivalent), so it does not appear in
`sandbox --help` and operators do not invoke it directly. The
generated SSH config is the only intended caller. The subcommand
name is treated as wire format from this point on; changes to it
must be coordinated with the generated config template.

`sandbox proxy <id>` is a new subcommand whose job is to be used as
`ProxyCommand` from the generated SSH config. It connects to the
daemon's `/sessions/{id}/proxy` endpoint, performs the WebSocket
handshake, and bidirectionally splices its own stdio with the
WebSocket binary frames. It is a thin shim — no business logic.

**Per-session entry write**, triggered on first CLI command for a
session (`ssh`, `cp`, `sync`, `workspace push`, `workspace pull`):

1. CLI calls `GET /sessions/{id}/ssh-config` to fetch config + key.
2. CLI writes the key to `~/.ssh/sandbox/keys/<id>` (mode `0600`),
   atomic rename from a sibling tempfile. **The rename must complete
   before any subsequent step references the key path**, so a
   concurrent CLI invocation that observes the path always sees the
   committed bytes.
3. CLI rewrites the `IdentityFile` line in the config block to
   point at the key file path.
4. CLI appends the rewritten block to `~/.ssh/sandbox/config` if
   no block for this session exists yet. The block is delimited by
   marker comments containing the session id so the CLI can locate
   and edit/remove it later.
5. CLI ensures the `Include` line in `~/.ssh/config` is present
   (creating `~/.ssh/config` with mode `0600` if absent).
6. CLI execs the appropriate standard tool with `LC_ALL=C` set in
   the child environment (see drift recovery below).

**Per-session entry removal**, triggered on `sandbox rm <id>`:

1. CLI removes `~/.ssh/sandbox/keys/<id>`.
2. CLI removes the marker-delimited block for `<id>` from
   `~/.ssh/sandbox/config`.

**Lazy cleanup**: if `sandbox proxy <id>` receives a 404 from the
daemon (session does not exist), the CLI removes the local entry
before exiting.

**Reconcile on listing**: `sandbox ls` opportunistically reconciles
the local config against the daemon's authoritative session list,
removing local entries the daemon does not know about. Specifics:

- Reconcile fires only when the daemon returns the full session
  list for the calling operator (the default `ls` invocation). It
  does **not** fire on single-id queries (`sandbox inspect`,
  `sandbox describe`) where the absence of one id does not imply
  the others are stale.
- If the daemon is unreachable, reconcile is skipped silently and
  `ls` falls through to whatever cached/local behaviour the existing
  command already exposes — no regression in error mode.
- A `--no-reconcile` flag opts out for tooling consumers that need
  strict read-only semantics (e.g. machine-readable `--output json`
  pipelines).
- The reconcile pass acquires the same `flock` on
  `~/.ssh/sandbox/.lock` as the write path, so a concurrent
  `sandbox ssh` cannot race against entry removal.

No separate `gc` command. The three mechanisms above (explicit
removal on `rm`, lazy cleanup on proxy 404, reconcile on `ls`)
cover every realistic code path. Stale entries are harmless: the
proxy endpoint 404s if anyone attempts to use one, and the
reconcile catches them on next listing.

**Concurrency and atomicity**: all mutations of
`~/.ssh/sandbox/config` go through an exclusive `flock` on
`~/.ssh/sandbox/.lock` (mode `0600`). Every config rewrite is
staged into a sibling tempfile under `~/.ssh/sandbox/` and
committed by atomic rename onto `config`, so a SIGKILL mid-rewrite
never leaves a half-written file. Key files are written and
committed the same way. Touching `~/.ssh/config` for the managed
Include also uses tempfile + rename, and is similarly guarded by
the lock.

`~/.ssh/sandbox/sockets/` accumulates ControlMaster sockets named
by `%C`. OpenSSH cleans these up when the master process exits
normally; SIGKILL of the master leaks one socket file. Leaked
socket files are harmless (they are stale Unix sockets, not
credentials) and SSH will silently overwrite them on the next
master start. No explicit cleanup is required from `sandbox rm` or
reconcile.

**Key drift recovery**: if the daemon's session-side key ever
diverges from the local copy (DB reset, manual edit, bug), `ssh`
fails with `Permission denied (publickey)` on stderr. To make the
match locale-independent the CLI sets `LC_ALL=C` and `LANG=C` in
the spawned client's environment, so the substring is stable. The
CLI matches that exact substring once per command invocation: on
match, it re-fetches the SSH config from the daemon, overwrites the
local key + block, and re-execs the underlying SSH tool a single
time. Single retry only — a second failure propagates the error to
the operator so we never loop. The retry is performed only at the
outermost CLI command dispatch (`sandbox ssh|cp|sync|workspace`),
never inside `sandbox proxy`, so nested invocations from
`git-remote-sandbox` cannot stack retries. Other SSH failures
(connection refused, remote command non-zero exit, host
unreachable) are passed through unchanged.

Per-command translation (after the entry exists):

- `sandbox ssh <id> [-- cmd]` → `ssh sandbox-<id> [cmd]`
- `sandbox cp [src ...] [dst]` → `scp sandbox-<id>:...` (path
  expansion follows existing semantics)
- `sandbox sync [--direction]` → `rsync ... sandbox-<id>:...`
- `sandbox workspace push|pull` → same `rsync` wrapper
- `git-remote-sandbox` is unchanged in source — it already invokes
  `sandbox ssh` internally, which now works cross-user

External tools (VS Code Remote-SSH, JetBrains Gateway, ad-hoc
`scp`/`rsync`, anything that reads `~/.ssh/config`) see the same
`Host sandbox-<id>` alias and use it without our CLI being in the
data path beyond the `ProxyCommand` shim.

TTY allocation, terminal resize, and signal forwarding are handled
by the standard `ssh` client; no daemon-side work is required for
those.

### Daemon launch in tests

The e2e harness is changed to start sandboxd via its existing
systemd unit (or `sudo -u sandbox sandboxd` if systemd is
unavailable in the test environment) instead of running the daemon
as the test user. The test user is added to the `sandbox` group by
the existing install/setup script so it can talk to the daemon
socket.

## Phase 1 — test infrastructure

**Goal: reproduce the bug in CI before changing any production
code.**

1. Extend `make setup-dev-env` (and/or `install.sh`) so that on
   first run it creates the `sandbox` user/group if missing, and
   adds the invoking operator to the `sandbox` group. When the
   fallback `sudo -u sandbox sandboxd` path is taken, the same
   script provisions a `NOPASSWD` sudoers fragment scoped to that
   single invocation so CI hosts without it do not silently hang
   on the password prompt.
2. Update the e2e harness to launch sandboxd via the existing
   systemd unit. Provide a fallback path for environments without
   systemd that uses `sudo -u sandbox sandboxd ...`.
3. Identify a small, fast existing e2e test that exercises
   `sandbox ssh` against the Lima backend, plus a `git-remote-sandbox`
   push or fetch test against a Lima-backend session, plus a
   matching container-backend `ssh` test. These three become the
   Phase-1 acceptance tests. `git-remote-sandbox` is included
   because its stdio semantics differ from a plain `ssh -- command`
   and an `ssh`-only acceptance does not prove the primary use case.
4. Run the three targeted tests under **both** the current harness
   (daemon as test user) and the new harness (daemon as `sandbox`)
   and diff the outcomes. Under the current harness all three
   should pass (status quo). Under the new harness, the two Lima
   tests should fail (confirming the bug) and the container test
   should pass (confirming the harness change itself did not break
   anything unrelated).
5. The full e2e matrix is **not** run in Phase 1; it stays for
   Phase 3 regression verification.

Acceptance: under the new harness, both Lima tests fail with a
clear limactl-cannot-find-VM error and the container test passes;
under the old harness, all three pass.

## Phase 2 — implementation

**Goal: make the targeted tests pass.**

Order chosen to minimise the time the system is half-broken. Each
step lists its test layer (hermetic unit, `integration_*`, or
e2e per the project's nextest profile convention).

1. **Lite-image gains sshd and renames guest user to `sandbox`.**
   Modify the Dockerfile and its launch wrapper to install
   openssh-server, generate an ephemeral host key on start, bind
   sshd to internal port 22, and configure the `AuthorizedKeysFile`
   directive to read `/run/sandbox/authorized_keys`. Rename the
   in-container guest user from `agent` to `sandbox`. No daemon
   changes yet; existing `docker exec`-based `sandbox ssh` keeps
   working for containers. Test layer: image-build integration test
   that launches the image and asserts the guest user and sshd
   presence.
2. **Daemon SSH credential management.** Add the
   `V007__add_ssh_keypair.sql` migration. For container sessions,
   generate an ed25519 keypair at session create and store it in
   the new column; inject the public key into the container at
   start via tmpfs bind-mount. Forward-compat per the project
   convention. Test layer: hermetic for the keypair generation
   helper, `integration_*` for the session-create end-to-end on
   container backend.
3. **`GET /sessions/{id}/ssh-config` endpoint.** Implement for both
   backends with the dedicated `SshConfigDto`. Reuse the
   session-ownership check pattern from existing `/sessions/{id}/...`
   handlers. Return `404 SSH_NOT_AVAILABLE` for pre-existing
   container sessions without a keypair. Test layer:
   `integration_*` against a real session per backend.
4. **`GET /sessions/{id}/proxy` endpoint.** Implement the WebSocket
   handshake and the per-backend byte-forwarding. Use
   `tokio::process::Command` with async pipes for the long-lived
   byte pumps (Lima TCP connection, container `docker exec socat`)
   per the async-I/O note above; the one-shot `limactl list` query
   uses `spawn_blocking` as usual. Test layer: `integration_*`
   that opens a proxy connection and exchanges bytes through a
   stub-sshd inside the session.
5. **CLI: `sandbox proxy <id>`.** Hidden subcommand that performs
   the WebSocket handshake and splices stdio with binary frames.
   Test layer: hermetic against a mock daemon WebSocket.
6. **CLI: persistent ssh-config management.** Module that owns
   `~/.ssh/sandbox/`, inserts the `Include` line at the top of
   `~/.ssh/config`, and provides write/remove/reconcile operations
   protected by flock with tempfile+rename atomic writes. Reusable
   across the five SSH-shaped commands. Test layer: hermetic
   against a tempdir `$HOME`.
7. **CLI: rewrite `sandbox ssh`** to ensure the per-session entry
   exists, then exec `ssh sandbox-<id>` with `LC_ALL=C`. Wire up
   the single-retry drift-recovery path. Verify Phase-1 targeted
   Lima ssh test passes. Test layer: existing e2e moved under the
   new harness.
8. **CLI: rewrite `sandbox cp`, `sandbox sync`, `sandbox workspace
   push`, `sandbox workspace pull`** to use `scp`/`rsync` against
   the `sandbox-<id>` alias. Verify against targeted tests for each.
   Test layer: existing e2e under the new harness.
9. **CLI: hook `sandbox rm` to remove the local config entry.**
   Test layer: hermetic for the removal helper; e2e for the full
   create/use/rm cycle.
10. **CLI: hook `sandbox ls` to opportunistically reconcile local
    entries against the daemon's session list, plus the lazy 404
    cleanup path in `sandbox proxy`.** Test layer: hermetic with a
    mock daemon list response; e2e for the user-visible behaviour.
11. **`git-remote-sandbox`** is verified by the Phase-1 git-remote
    acceptance test under the new harness — no source change
    expected.

After each step, the corresponding targeted test runs under the
Phase-1 harness.

## Phase 3 — validation

1. Run the full e2e matrix (Lima + container) under the new
   harness. Expect parity with current passing baseline plus the
   originally-failing Lima ssh test now passing.
2. Manually exercise `git-remote-sandbox` end-to-end against a Lima
   session.
3. Manually point VS Code Remote-SSH at a generated config to
   sanity-check external tool compatibility (one-time check, not
   part of CI).

## Persisted state forward-compat

- Schema change: a new `ssh_keypair_json BLOB NULL` column is added
  to the sessions table via the forward-only migration
  `V007__add_ssh_keypair.sql`. The column is nullable so existing
  rows continue to deserialize without changes. The column value
  is a JSON envelope of `{"public": ..., "private": ...}` for the
  container backend; null for the Lima backend (Lima manages its
  own keys outside the daemon DB).
- The session-row Rust struct gains an `ssh_keypair: Option<SshKeypair>`
  field with `#[serde(default)]` so older daemons reading newer
  rows skip the field. Newer daemons reading older rows see `None`.
- Behaviour on `None` for container sessions: the
  `ssh-config` endpoint returns `404 SSH_NOT_AVAILABLE` and the CLI
  surfaces an actionable message telling the operator to recreate
  the session. Lazy keypair generation on demand is rejected because
  injecting a new `authorized_keys` into a running container would
  require sshd hot-reload that the lite-image is not designed for.
- Behaviour on `None` for Lima sessions: expected and normal; the
  daemon reads Lima's own keys when serving the endpoint.

## Security considerations

- The session sshd in containers is bound to the loopback inside
  the container's network namespace. Nothing outside that namespace
  can reach it except via `docker exec`, which is gated by the
  daemon's group permissions on the docker socket.
- The daemon's proxy endpoint enforces session ownership before
  opening the WebSocket. Bytes after the handshake are not
  inspected, but they cannot reach a session the calling operator
  does not own.
- The per-session SSH private key lives at
  `~/.ssh/sandbox/keys/<session-id>` with mode `0600`, same as any
  other key under `~/.ssh/`. Persistence is the explicit trade-off
  for IDE compatibility — IDEs cannot use a per-call tempfile they
  cannot read. Stale keys are cleaned up on session removal, on
  proxy-endpoint 404, and on `sandbox ls` reconcile; an undetected
  stale key on disk gives the holder no useful access because the
  corresponding session no longer exists.
- Host-key verification is disabled (`StrictHostKeyChecking no`,
  `UserKnownHostsFile=/dev/null`) because the sshd is reached only
  through the daemon-mediated tunnel — there is no MITM surface
  between the SSH client and the sshd. This matches Lima's stance.

## Alternatives considered

### Per-UID directory under `/var/lib/sandbox` with ACLs

Daemon writes the SSH config and key under
`/var/lib/sandbox/users/<uid>/sessions/<id>/` with a POSIX ACL
granting the operator UID read access. The CLI just reads the path
directly; no API call, no tempfile.

Rejected because:

- Requires ACL-capable filesystem (universally available on Linux
  in practice, but adds a deployment constraint).
- More on-disk state to garbage-collect on session deletion.
- Doesn't unify cleanly with the proxy endpoint we need anyway for
  daemon-mediated tunnelling.

### Per-user directory under `$HOME/.sandbox/`

Daemon writes session credentials into a directory inside the
operator's home, exposed to the daemon either via ACL or a special
group.

Rejected because the daemon (as `sandbox`) needs traversal access
to `/home/<operator>/`, which standard home permissions (0750 or
0700 depending on distro) deny. Granting it requires either an ACL
on the home directory itself or `chmod o+x /home/<operator>`, both
of which are distro-variable and invasive.

### Returning key bytes in the API response (no on-disk shared storage)

The daemon returns the key inline in the JSON response; CLI writes
to its own tempfile. This is essentially the path adopted, with the
additional refinement that the daemon also mediates the network
path via `ProxyCommand`, so a leaked key alone is not sufficient to
reach the session.

### Per-call tempfile / memfd (no persistent on-disk key)

Instead of writing the key persistently to `~/.ssh/sandbox/`, the
CLI could fetch it on each invocation, hold it in a tempfile
(`$XDG_RUNTIME_DIR/sandbox-ssh-XXX`) or a Linux `memfd_create`-backed
anonymous file referenced as `/proc/self/fd/N`, and clean up at
process exit.

This minimises on-disk exposure window but breaks IDE workflows —
VS Code Remote-SSH and similar tools read `~/.ssh/config` and
expect to invoke `ssh sandbox-<id>` themselves, with no opportunity
for us to materialise an ephemeral key first. memfd in particular
is also Linux-only, conflicting with the CLI's macOS forward-compat
goal.

Adopted persistent storage instead. The exposure trade is acceptable
because (a) the key alone does not grant session access — the
daemon proxy is still required, and (b) the lifecycle hooks
(`sandbox rm`, lazy 404 cleanup, reconcile on `sandbox ls`) limit
stale-key accumulation.

### Custom streaming protocol (Kubernetes-style)

WebSocket with a 1-byte channel-id prefix per frame, separate
channels for stdio and resize/signals. Rejected for this milestone
because it requires us to reimplement scp/rsync/git-remote pipe
shapes on top of our own protocol — significantly more work than
extending the lite-image to host sshd.

We may still want this protocol later for `sandbox exec`'s
interactive PTY case, but it is not on the critical path for fixing
the six broken commands.

### Adding sshd inside containers via guest-agent at start instead of baked into the image

The keypair could be generated and injected entirely at session
start via the guest-agent, rather than relying on the lite-image to
contain sshd. This decouples the credential lifecycle from image
builds and avoids leaving a dormant sshd in offline images.

Possible follow-up but not required for this milestone: baking sshd
into the lite-image is the simpler first cut. Once it works, moving
to a lazier "sshd started on first ssh request" model is a
straightforward optimisation.

### Daemon-issued short-lived SSH certificates

Instead of persistent static keys, the daemon could act as an SSH
CA and issue short-lived signed user certificates (e.g. valid for
8 hours, re-issued automatically on each `sandbox ssh`). This
shrinks the blast radius of a leaked on-disk key — a stolen
certificate stops working when it expires — without breaking IDE
workflows (IDEs re-read `IdentityFile` on each connect, so the CLI
can refresh the cert transparently).

Rejected for this milestone as additional complexity (CA key
management, sshd `TrustedUserCAKeys` configuration, certificate
renewal logic in the CLI) for a security improvement that is
incremental, not categorical: the daemon proxy is still required
to reach the sshd regardless of certificate vs. key. Worth
revisiting if we later add multi-machine operators or longer-lived
sessions, where on-disk-key exposure windows grow meaningfully.

### Unix-domain-socket transport instead of WebSocket

For the local-daemon case, the proxy could be exposed as a per-session
Unix domain socket in `$XDG_RUNTIME_DIR/sandboxd/sessions/<id>.sock`
with group `sandbox`. `ProxyCommand` becomes `socat - UNIX-CONNECT:<path>`,
removing the HTTP-upgrade handshake and WebSocket framing overhead.

Rejected because the CLI is intended to remain forward-compatible
with macOS (and potentially with a remote-daemon scenario in the
future). A Unix-socket-per-session transport works only against a
local daemon on the same host. WebSocket over the existing HTTP-on-
Unix-socket surface generalises trivially to TCP-mounted remote
daemons without changes to the CLI's `sandbox proxy` shim.

## Open questions

- Exact behaviour when `~/.ssh/config` already contains an
  unrelated `Host sandbox-*` block authored by the operator. The
  managed Include is additive, so collisions are unlikely in
  practice (session ids are unique), but the reconcile pass must
  not touch anything outside its marker-delimited region.

## Non-goals

- Streaming-protocol design for the non-SSH `sandbox exec` path.
- VS Code / JetBrains Gateway integration polish (the generated
  config will work for them, but documenting the install dance is
  separate).
- Multi-tenant policy on per-operation authorization (audit hooks,
  per-command policies). The daemon proxy endpoint is positioned
  to support these later but does not enforce anything beyond
  session ownership in this milestone.
