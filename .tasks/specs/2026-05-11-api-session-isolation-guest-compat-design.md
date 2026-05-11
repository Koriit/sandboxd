# API Session Isolation + Guest Version Compatibility — Design

**Date:** 2026-05-11
**Status:** Approved
**Scope:** `sessions` schema bump (V006) that adds `owner_username`, `guest_protocol_version`, `guest_binary_version`; per-caller filtering at the `SessionStore` boundary; `SO_PEERCRED`-resolved owner stamping at `create_session`; daemon-side protocol-version compatibility check on `start_session` with an in-place guest-binary refresh seam; explicit handshake on the guest wire so the compatibility decision has ground truth.

---

## 0 · Sequence context

This spec is **Spec 2 of a five-spec arc** that prepares `sandboxd` for an end-user
install / uninstall / update story. The arc:

1. **Spec 1** — Helper identity assertion (committed at
   `.tasks/specs/2026-05-11-helper-identity-assertion-design.md`)
2. **Spec 2 (this one)** — API session isolation + guest version compatibility
3. **Spec 3** — Daemon productionization (dedicated `sandbox` system user, systemd
   unit, state at `/var/lib/sandbox/`, file modes, `sandbox doctor`, version pinning)
4. **Spec 4** — Release & install infrastructure (signed builds, install/uninstall
   scripts on GH Pages, Lima test harness)
5. **Spec 5** — Update infrastructure (`sandbox update` CLI, config migration
   framework, backups, lock file)

Dependency graph: Specs 1 and 2 are parallel; Spec 3 depends on **both** (the
dedicated `sandbox` user only makes API isolation meaningful — without per-caller
filtering, every operator in the `sandbox` group can see every session via the
daemon's API). Specs 4 and 5 depend on Spec 3.

This spec **does not** cover the dedicated `sandbox` system user, the systemd
unit, the move of state under `/var/lib/sandbox/`, file modes, install/uninstall
scripts, the `sandbox update` CLI, or the config-migration framework. See § 8 for
the explicit out-of-scope list.

## 1 · Motivation

Two unrelated trust gaps share one schema-evolution event, so they are
specified — and will be implemented — together.

**Gap 1 — API filtering.** Today, every endpoint under `/sessions/...` performs
session lookup by ID (or name, or unique-ID prefix) with **no caller context**.
The daemon currently runs as the operator, so this is harmless — there's exactly
one operator per daemon. After Spec 3 lands, the daemon runs as a dedicated
`sandbox` system user; operators added to the `sandbox` group then share the
daemon socket, and the route-helper's pair-check (Spec 1) keeps them from
disrupting each other's networking, but the API layer would still happily show
alice's session to bob (and let bob `POST /sessions/{alice_id}/stop`). That's
inconsistent with the per-user CIDR pool isolation the route-helper enforces and
removes the trust boundary Spec 3 needs to be useful.

**Gap 2 — Guest binary compatibility.** A `sandboxd` upgrade (Spec 5's
`sandbox update`) can ship a new daemon ↔ guest protocol. Stopped sessions
persist their existing VM disk image (Lima) or container layers (lite-mode); the
old `sandbox-guest` binary inside them was compiled against the old protocol.
On the next `POST /sessions/{id}/start`, the daemon will dial the agent and
exchange messages that the old guest doesn't recognise — today the failure
surfaces as opaque deserialization errors and timeouts inside `GuestConnector`.
The daemon needs to **know** the session's guest protocol version before
choosing what to do (start as-is, refresh the binary in place, or refuse with a
clear "recreate this session" message).

The two gaps land together because both write to the `sessions` table: V006 adds
all three columns in one migration, and the same `SO_PEERCRED` plumbing that
stamps `owner_username` at create time is the foundation Spec 1 also needs
(see § 4).

## 2 · API session isolation

### 2.1 · Schema change — migration V006

Three new columns on `sessions`. All `NOT NULL` so any code path that reads a
row sees a value; backfill is **not** attempted in the dev path because dev
sessions are volatile (see § 6).

| Column                   | Type     | Constraint                                      | Source                                                       |
|--------------------------|----------|-------------------------------------------------|--------------------------------------------------------------|
| `owner_username`         | TEXT     | NOT NULL                                        | `SO_PEERCRED` → `getpwuid_r` at `POST /sessions`             |
| `guest_protocol_version` | INTEGER  | NOT NULL                                        | `DAEMON_GUEST_PROTO_VERSION` constant at `POST /sessions`    |
| `guest_binary_version`   | TEXT     | NOT NULL                                        | `SANDBOX_GUEST_VERSION` (semver string) at `POST /sessions`  |

Migration file: `sandboxd/sandbox-core/migrations/V006__add_owner_and_guest_versions.sql`.
The existing migration set (`V001__create_sessions.sql` … `V005__session_backend_column.sql`,
listed at `sandbox-core/migrations/`) is run forward-only by refinery in
`SessionStore::new` (`sandbox-core/src/store.rs:114-123`), so V006 lands behind
the V004 two-pass split without touching it.

```sql
-- V006__add_owner_and_guest_versions.sql
-- Spec 2: API session isolation + guest version compatibility.
--
-- This migration is destructive on the dev-mode upgrade path: it deletes
-- every existing row in `sessions` and its policy-cascade descendants
-- before adding the three NOT NULL columns. The handoff settled on this
-- shape over a `__legacy__` backfill marker because:
--   * Dev sessions are volatile (stopped VMs are routinely thrown away).
--   * The backfill marker leaks an unresolvable owner name into the
--     filter and would force a "treat __legacy__ as any caller" carve-out
--     that contradicts the spec's only-own-sessions rule.
--   * End-user installs (Spec 4) are greenfield — there is no `sessions.db`
--     to migrate. The destructive step only fires on developer machines
--     that already have a stopped-session row from before V006.
--
-- The cascade lands via the existing foreign keys (V003): deleting a
-- `sessions` row cascades to `session_policies` → `policy_rules` →
-- `policy_rule_http_filters`. The single DELETE below is sufficient.

DELETE FROM sessions;

ALTER TABLE sessions
    ADD COLUMN owner_username TEXT NOT NULL DEFAULT '';
ALTER TABLE sessions
    ADD COLUMN guest_protocol_version INTEGER NOT NULL DEFAULT 0;
ALTER TABLE sessions
    ADD COLUMN guest_binary_version TEXT NOT NULL DEFAULT '';
```

Notes on the SQL shape:

- SQLite's `ALTER TABLE ADD COLUMN` requires a default for `NOT NULL`. The
  defaults (`''`, `0`, `''`) are placeholders for the empty post-`DELETE`
  table and are never observed by any read — every subsequent
  `INSERT INTO sessions` writes real values from `SessionStore::create_session_with_backend`
  (see § 2.4).
- `CHECK (owner_username <> '')` is **not** added, on purpose. Refinery's
  one-shot apply ordering applies the migration atomically; the empty-string
  default is internal to the migration body and never survives outside the
  transaction in any non-empty state. Adding a CHECK would force a separate
  migration step on Spec 5's `sandbox update` rollforward path; the
  daemon-side enforcement (§ 2.4 — `create_session` always passes a non-empty
  username, never `''`) is sufficient.

### 2.1.1 · Substrate-orphan footprint of the destructive migration

V006's `DELETE FROM sessions` clears the daemon's catalogue of every
existing session row, and the V003 FK cascade unwinds the policy
descendants. It does **not** touch:

1. The per-session **filesystem state** under `{base_dir}/sessions/<id>/`
   (per-session CA material, persisted events, optional volume
   payloads).
2. **Lima VMs** named `sandbox-<id>` registered with the host's Lima
   installation.
3. **Docker containers and volumes** named `sandbox-<id>` /
   `sandbox-home-<id>` on the host's Docker daemon.
4. The corresponding **gateway containers** (`sandbox-gw-<id>`) and
   **docker networks** (`sandbox-net-<id>`) the daemon's
   `NetworkManager` and `GatewayManager` allocated.

After V006 applies, the reconciler at `main.rs:2465-2487` iterates
`list_sessions` (now empty) and never reaches the runtime state — so
no automatic cleanup occurs. The substrate state is orphaned, and the
orphan list is unrecoverable from the daemon side (the DB row was the
only catalogue tying a session ID to a substrate name).

**Spec 2's response is a single `warn!` log emitted by `SessionStore::new`
when refinery reports that V006 was applied in this run.** The log is
emitted exactly once per daemon process (refinery's migration history
table records the apply event; the log fires only when the V006 row is
freshly inserted, not on subsequent boots where V006 is already in the
history). The log carries a fixed message body so test assertions can
match it:

```
WARN refinery applied V006 — pre-V006 sessions were deleted; the
following substrate resources may now be orphaned:
  - per-session directories under {base_dir}/sessions/
  - Lima VMs named `sandbox-*`        (host: `limactl list`)
  - Docker containers `sandbox-*`     (host: `docker ps -a --filter name=sandbox-`)
  - Docker volumes `sandbox-home-*`   (host: `docker volume ls --filter name=sandbox-home-`)
  - Docker networks `sandbox-net-*`   (host: `docker network ls --filter name=sandbox-net-`)
  - Gateway containers `sandbox-gw-*` (host: `docker ps -a --filter name=sandbox-gw-`)
Run `sandbox doctor` after upgrade to see the catalogue of orphans
detected on this host. Manual cleanup recipe lives in the upgrade
notes for the daemon version that introduced V006.
```

The log is `warn!` rather than `error!` because the daemon is fully
operational — the orphans are operational debt, not a correctness
failure. The cross-reference to `sandbox doctor` is a **forward
pointer to Spec 3**, which is adding check C13 (orphan substrate
detection) in parallel. **Spec 2 does not implement the doctor side
and does not add a Rust-side sweep here.** The reasoning:

- A Rust-side sweep at migration time runs inside the daemon's
  startup path, before `AppState` is built; the runtime registry
  (`runtime_for(&state, ...)`), Docker connection, and Lima manager are
  not yet available. Shelling out to `docker` and `limactl` from
  refinery's migration callback is the wrong place for runtime work.
- A migration-time sweep would also be hard to test in isolation
  (refinery's migration runner is purely SQL-shaped today; adding a
  post-migration Rust hook would force a new test fixture).
- The diagnostic surface is Spec 3's responsibility (`sandbox
  doctor`); funneling the orphan check there gives operators one
  place to look. The `warn!` log is the breadcrumb that tells them
  to look.

The dev-mode walkthrough at § 6.1 expands on the operator impact.

### 2.2 · API-level filtering — the rule

> Every endpoint that **accepts a session ID** filters that lookup by
> `owner_username = name(SO_PEERCRED.uid)`. Every endpoint that **lists**
> sessions returns only the caller's own rows. Foreign session IDs return
> **404 Not Found**, not 403 Forbidden. Existence is information; leaking it
> would let alice enumerate bob's session UUIDs via timing or response shape.

The filter is enforced at the `SessionStore` boundary, not at each handler.
This is the deliberate pin from the handoff: enforcement at the storage
boundary makes the safety property hold for any future endpoint that talks to
the store, including endpoints not yet written. A wrapper layer in the HTTP
handler would require every new contributor to remember to invoke it.

### 2.3 · Affected endpoints — concrete enumeration

Every session-ID-shaped endpoint in the daemon today, listed by call site, with
the current authorization (none) and the new check. Routes live in three
sub-routers merged at `sandboxd/sandboxd/src/main.rs:843-862`.

| # | Endpoint                                    | Route line                              | Handler                                              | Today's auth | After Spec 2                                  |
|---|---------------------------------------------|-----------------------------------------|------------------------------------------------------|--------------|-----------------------------------------------|
| H1 | `POST   /sessions`                          | `main.rs:844`                           | `create_session`         (`main.rs:899`)             | none         | Stamps `owner_username` from `SO_PEERCRED`    |
| H2 | `GET    /sessions`                          | `main.rs:845`                           | `list_sessions`          (`main.rs:2447`)            | none         | Filters list to caller's own sessions         |
| H3 | `GET    /sessions/{id}`                     | `main.rs:846`                           | `get_session`            (`main.rs:2506`)            | none         | 404 on foreign ID                             |
| H4 | `DELETE /sessions/{id}`                     | `main.rs:847`                           | `remove_session`         (`main.rs:2924`)            | none         | 404 on foreign ID                             |
| H5 | `POST   /sessions/{id}/start`               | `main.rs:848`                           | `start_session`          (`main.rs:2661`)            | none         | 404 on foreign ID; plus § 3 compat gate       |
| H6 | `POST   /sessions/{id}/stop`                | `main.rs:849`                           | `stop_session`           (`main.rs:2810`)            | none         | 404 on foreign ID                             |
| H7 | `POST   /sessions/{id}/exec`                | `main.rs:850`                           | `exec_in_session`        (`main.rs:3065`)            | none         | 404 on foreign ID                             |
| H8 | `POST   /sessions/{id}/policy`              | `main.rs:852-854`                       | `update_policy`          (`main.rs:3128`)            | none         | 404 on foreign ID                             |
| H9 | `DELETE /sessions/{id}/policy`              | `main.rs:852-854`                       | `clear_policy`           (`main.rs:3179`)            | none         | 404 on foreign ID                             |
| H10 | `GET   /sessions/{id}/health`              | `main.rs:855`                           | `session_health`         (`main.rs:5086`)            | none         | 404 on foreign ID                             |
| H11 | `GET   /sessions/{id}/events`              | `events_http.rs:103`                    | `get_session_events`     (`events_http.rs:107`+)     | none         | 404 on foreign ID                             |
| H12 | `GET   /sessions/{id}/policy/propagation-status` | `policy_http.rs:85-88`             | `propagation_status`     (`policy_http.rs:92`+)      | none         | 404 on foreign ID                             |

Three top-level non-session endpoints are **not** affected:
`POST /rebuild-image` (`main.rs:856`), `GET /base-image-status` (`main.rs:857`),
`GET /health` (`main.rs:858`), and `GET /backends` (`backends_http.rs:55`).
These do not take a session ID and have no per-user surface; Spec 2 leaves them
alone.

### 2.4 · `SessionStore` API — where the filter lives

Every `SessionStore` method that today reads or mutates a session by ID gains a
mandatory `caller_username: &str` parameter. The methods affected, by name and
current signature line in `sandbox-core/src/store.rs`:

| Method                                       | Today's line | New signature shape                                                       |
|----------------------------------------------|--------------|---------------------------------------------------------------------------|
| `create_session_with_backend`                | 265          | gains `owner_username: &str, guest_proto: u32, guest_bin_ver: &str`       |
| `create_session` (back-compat shim)          | 249          | gains the same trio; test-only callers pass `("__test__", 0, "0.0.0-test")` |
| `get_session`                                | 330          | gains `caller_username: &str`; returns `Ok(None)` when row exists but `owner_username` differs |
| `list_sessions`                              | 349          | gains `caller_username: &str`; SQL `WHERE owner_username = ?1`            |
| `update_state`                               | 388          | gains `caller_username: &str`; checks ownership before the transition     |
| `update_state_reconcile` (renamed from `update_state_forced`) | 432 | **No `caller_username`.** Reconciler-only by contract — bypasses the storage-boundary filter by design. See "Reconciler hot path" below. |
| `get_session_by_name_or_id`                  | 468          | gains `caller_username: &str`; every fallback path filters                |
| `resolve_id_prefix`                          | 523          | gains `caller_username: &str`; prefix matching scoped to caller's rows    |
| `set_network_info`                           | 582          | gains `caller_username: &str`                                             |
| `get_network_info`                           | 609          | gains `caller_username: &str`                                             |
| `list_sessions_with_network_info`            | 642          | **no `caller_username`** — see "Daemon-internal callers" below            |
| `set_policy`                                 | 689          | gains `caller_username: &str`                                             |
| `delete_policy`                              | 763          | gains `caller_username: &str`                                             |
| `get_policy`                                 | 786          | gains `caller_username: &str`                                             |
| `load_all_policies`                          | 811          | **no `caller_username`** — see "Daemon-internal callers" below            |
| `delete_session`                             | 859          | gains `caller_username: &str`                                             |

For every method gaining the parameter:

- The SQL `SELECT`/`UPDATE`/`DELETE` adds `AND owner_username = ?N` to its
  `WHERE`.
- Row-existence with a different owner returns the same shape as no row at all
  — `Ok(None)` for reads, `Err(SandboxError::SessionNotFound(_))` for mutations.
  The handler layer maps both to HTTP 404 unchanged (the existing
  `error_response` mapping at `sandboxd/sandboxd/src/error.rs:62` already
  resolves `SessionNotFound` to `404`).

**Daemon-internal callers**: `list_sessions_with_network_info` (rebuilds the
subnet allocator on startup) and `load_all_policies` (rehydrates the in-memory
policy map) are not driven by an HTTP caller — they run inside
`sandboxd::main::main` during startup. These keep their unfiltered signatures.
They are pure read-only fan-outs over every session, used to reconstruct
daemon-internal data structures; introducing a caller filter here would be
incoherent.

**Reconciler hot path — pinned rule.** The reconciler block inside
`list_sessions` and `get_session` (the "DB-vs-Lima/Container state
reconciliation" pattern at `main.rs:2465-2487` and `main.rs:2524-2545`)
must adjust persisted state after observing a divergence between the DB
and the runtime's status. That path is not "alice's API request against
alice's session" — it is "the daemon reconciling externally-observed
substrate state against the catalogue" — and it cannot meaningfully
participate in the caller-filter check (there is no HTTP caller in scope;
the reconciler runs inside `list_sessions` / `get_session` after the
session row has already been read).

Spec 2 resolves this with a hard rule:

> Today's `update_state_forced` is renamed to `update_state_reconcile`
> and takes **no `caller_username`**. The method is reconciler-internal
> by contract; **HTTP handlers must never call it.** All operator-driven
> state transitions go through `update_state` (which takes
> `caller_username` and enforces ownership). The rename is a deliberate
> tripwire: a future contributor reaching for "force this state change"
> sees the new name and the doc-comment, not the old one.

The trait method's doc-comment carries this rule verbatim:

```rust
/// Forcibly set the state of a session, bypassing both state-machine
/// validation and the storage-boundary ownership filter.
///
/// **INTERNAL: only the daemon's startup / reconciliation paths may
/// call this method.** HTTP handlers must use [`Self::update_state`],
/// which enforces ownership via the `caller_username` filter (Spec 2
/// § 2.4). A call from a request handler is a security bug — it
/// bypasses the per-caller 404-on-foreign-id property the rest of the
/// store guarantees.
///
/// Authorized callers, exhaustively (Spec 2 § 7.3.1 enforces this
/// list via a static-analysis test):
/// - `list_sessions` and `get_session` reconciler blocks in
///   `sandboxd::main` (DB-vs-runtime status divergence).
/// - The `Creating`→`Running`/`Error` transitions in `create_session`
///   and `start_session` *before* the session is owner-stamped (only
///   on the error/cleanup branch; the happy path uses `update_state`).
/// - Startup reconciliation in `sandboxd::main::main`.
pub fn update_state_reconcile(
    &self,
    id: &SessionId,
    state: SessionState,
) -> Result<(), SandboxError>;
```

The allow-list is enforced by a unit test (§ 7.3.1 below) that greps the
entire `sandboxd/` source tree for callers of `update_state_reconcile`
and fails when the call set is not a subset of the named locations. The
test reads as a static-analysis check, not a behaviour test, but it
lives in the test suite so it runs on every `cargo nextest run`.

### 2.5 · Stable identity — username, not UID

Owner identity is the **username string**, not the UID. Rationale:

- UIDs are reassignable. `useradd --uid 1003 …` after a `userdel` could land
  on a UID a previous user owned; rows stamped with the old UID would suddenly
  be visible to the new account. Usernames are unique in `/etc/passwd` (within
  one host install) and immutable until the admin runs `usermod -l`. Per-host
  username stability is the same property Spec 1 leans on for
  `users.conf::allow_users` membership.
- The daemon resolves `SO_PEERCRED.uid` to a username via `getpwuid_r` (wrapped
  by `nix::unistd::User::from_uid`, already in scope per Spec 1 § 6.1 —
  `sandbox-core/Cargo.toml:13` and `sandboxd/Cargo.toml:49` both pull `nix`
  with the `user` feature).
- If lookup **fails** (`Err`) or returns **no record** (`Ok(None)`), the
  daemon refuses the request — same strict policy Spec 1 specifies for the
  helper. Do **not** silently fall back to a UID string; an unresolvable
  identity is an integrity failure and must surface, not be papered over.

### 2.6 · Decisions explicitly carried forward

State these so they are not re-litigated during implementation:

- **404 over 403** for foreign IDs. Existence is information; we do not leak
  it.
- **No admin override in v1.** If a future spec needs a "sandbox admin sees
  every session" surface, it lives in a dedicated config file (e.g.
  `/etc/sandboxd/admins.conf`), **not** in `users.conf` — Spec 1's
  `users.conf` is scoped to per-subnet `allow_users` for the route-helper,
  not to API-layer policy. The handoff explicitly defers this; mention it in
  § 8 as out of scope.
- **No cross-user mutation paths.** Every mutating endpoint (H1, H4, H5, H6,
  H7, H8, H9) is strictly owner-only. There is no "owner can grant access"
  surface in v1.
- **Internal endpoints (`/rebuild-image`, `/base-image-status`, `/health`,
  `/backends`) are not gated.** They have no per-user surface and are read by
  every CLI invocation regardless of operator.

## 3 · Guest version compatibility

### 3.1 · Two version fields, two different roles

`sessions.guest_protocol_version` and `sessions.guest_binary_version` carry
distinct meanings and are read by distinct code paths.

| Field                       | Type | Role                                                                                                                                                                                                                                          |
|-----------------------------|------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `guest_protocol_version`    | u32  | The wire-protocol version the daemon expects to talk to the in-VM/in-container guest. Bumped **only when the daemon ↔ guest protocol changes** (a new `GuestRequest`/`GuestResponse` variant; renamed enum tag; changed framing). The compatibility predicate (§ 3.3) reads this. |
| `guest_binary_version`      | String (semver) | The semver of the `sandbox-guest` binary currently inside the VM/container. Bumped on **every guest binary release**, even ones that don't change the protocol (logging tweaks, dependency bumps). Used for `sandbox describe`/`sandbox inspect` diagnostics and the audit trail. **Not** used by any decision-making code. |

Both fields are stamped on `POST /sessions`. The daemon already knows both:
the protocol version is a `pub const u32` baked into `sandbox-core`, the
binary version is `env!("CARGO_PKG_VERSION")` from the `sandbox-guest` crate
(the daemon's workspace dependency on `sandbox-guest` for `include_bytes!`-like
delivery already gives compile-time access — see § 3.6).

The pair refreshes together on every successful refresh (§ 3.4). They never
update independently — the daemon never claims a binary version it didn't
just write into the guest.

### 3.2 · Where the constants live

Two new constants in `sandbox-core`:

```rust
// sandbox-core/src/guest.rs (alongside the existing GUEST_AGENT_PORT
// and MAX_MESSAGE_SIZE constants at lines 35 / 38).

/// Wire-protocol version the daemon speaks to `sandbox-guest`. Bumped
/// when a `GuestRequest` or `GuestResponse` variant is added, removed,
/// renamed, or changes shape — i.e., when an old guest binary would no
/// longer round-trip a message exchanged with a new daemon.
///
/// **Not** bumped for guest-binary changes that don't touch the wire
/// (e.g. an exec timeout adjustment, internal logging change).
pub const DAEMON_GUEST_PROTO_VERSION: u32 = 1;

/// Semver of the embedded `sandbox-guest` binary. Stamped into
/// `sessions.guest_binary_version` on create and on every refresh.
pub const SANDBOX_GUEST_VERSION: &str = env!("CARGO_PKG_VERSION_GUEST_REEXPORT");
```

For the binary version, the workspace already builds `sandbox-guest` as a
sibling crate at `sandboxd/sandbox-guest/`. The cleanest delivery is a
`build.rs` in `sandbox-core` that emits `CARGO_PKG_VERSION_GUEST_REEXPORT`
from the guest crate's `Cargo.toml`, or — simpler — define a
`pub const SANDBOX_GUEST_VERSION: &str = "0.1.0";` directly inside
`sandbox-guest/src/lib.rs` (currently the guest is binary-only;
this spec promotes it to lib + bin so `sandbox-core` can `use sandbox_guest::SANDBOX_GUEST_VERSION;`)
and re-export it. The implementation will pick whichever shape integrates
more cleanly; the spec is agnostic on the mechanism so long as the constant
ends up readable from `sandboxd::main::create_session`.

The protocol-version constant lives in `sandbox-core/src/guest.rs` because
that file already owns the protocol types (`GuestRequest` /
`GuestResponse` at lines 50/59); bumping the const is the same diff event as
bumping the enum, so they sit together.

### 3.3 · Compatibility predicate

A single function in `sandbox-core`:

```rust
// sandbox-core/src/guest.rs (next to the constants above).

/// `true` when this daemon can drive the wire protocol of a session
/// last touched at `session_proto`. For v1 the daemon supports exactly
/// one protocol version (its own); future widening (a multi-version
/// range, e.g. `DAEMON_GUEST_PROTO_VERSION-1 ..= DAEMON_GUEST_PROTO_VERSION`)
/// lands in a follow-up spec and only edits this function.
pub fn is_protocol_compatible(session_proto: u32) -> bool {
    session_proto == DAEMON_GUEST_PROTO_VERSION
}
```

The predicate is intentionally tiny — the *seam* is the value, not the
shape. Spec 2 lays the field down and pins the call sites; widening the
predicate to a range, or admitting "transitional" sessions that can be
gracefully upgraded mid-flight, is a follow-up's job.

### 3.4 · Refresh decision tree on `start_session`

The new gate sits at the top of `start_session` (`main.rs:2661`), immediately
after the session is loaded (line 2665) and before the existing state-transition
check (line 2672). Pseudo-code:

```
on start_session(caller_username, session_id):
    session = SessionStore.get_session_by_name_or_id(caller_username, session_id)
              # Returns Ok(None) -> 404 if session does not exist or
              # exists but is owned by someone else.
              # No special case for guest version — that's downstream.

    if session.state != Stopped:
        return 400 InvalidState (existing behavior, main.rs:2672)

    if is_protocol_compatible(session.guest_protocol_version):
        // Normal start path — what `start_session` does today.
        proceed to existing main.rs:2680+

    elif can_refresh_in_place(session):
        // Refresh the guest binary in place, then resume normal start.
        match runtime.refresh_guest_binary(&handle).await:
            Ok(()) ->
                SessionStore.update_guest_versions(
                    caller_username,
                    session_id,
                    DAEMON_GUEST_PROTO_VERSION,
                    SANDBOX_GUEST_VERSION,
                )?
                proceed to existing main.rs:2680+
            Err(e) ->
                return 500 with "guest-refresh failed for session {id}: {e}"

    else:
        // Refuse — refresh is not viable for this session.
        return 409 Conflict with the structured error from § 3.5.
```

`can_refresh_in_place(session)` is the seam — its v1 body is described in
§ 3.7. The two distinct refusal paths matter: refresh-failed is a transient
infrastructure problem (try again), refresh-not-viable is a permanent
mismatch (the operator must recreate).

### 3.5 · Refusal error shape

The "refuse with recreate guidance" path is the operator's primary debugging
surface, so its shape is pinned here.

The daemon adds one new `SandboxError` variant in
`sandbox-core/src/error.rs`:

```rust
#[error(
    "session {session_id} was created with guest protocol {session_proto}; \
     daemon supports {daemon_proto}; refresh is not viable for this session \
     (reason: {reason}); recreate the session: \
     `sandbox session rm {session_id} && sandbox session create ...`"
)]
GuestProtocolIncompatible {
    session_id: String,
    session_proto: u32,
    daemon_proto: u32,
    reason: String,
}
```

HTTP mapping: **`409 Conflict`** — the request is well-formed and authorized,
but the session's persisted state is incompatible with the current daemon. Add
the new variant to the `error_response` match in
`sandboxd/sandboxd/src/error.rs:60-73` (between `RootlessDockerRefused` and
`Network`).

The verbatim message body has three load-bearing pieces:

1. The literal session ID (so the operator can paste it into `sandbox session rm`).
2. Both protocol numbers (so a `sandbox describe` output can be cross-checked
   without involving the daemon).
3. A copy-pasteable `sandbox` command. The full `session create` argv is
   omitted because it depends on what the operator originally created the
   session with — the message tells them what to do, not how to reconstruct
   their config (Spec 5's `sandbox update --pre-flight` is where the
   "recreate with these args" surface lives).

The JSON wire shape uses the daemon's existing `ApiError` body
(`sandbox-core/src/error.rs:93`): a single `error` field carrying the
verbatim message above. No structured fields are added on the wire today —
the prose **is** the contract surface, and pinning the message tokens
(`refresh is not viable`, `recreate the session`) is the assertion anchor
for integration tests (see § 7.5).

### 3.6 · Where the embedded guest binary comes from

The daemon already embeds the lite-mode Dockerfile via `include_str!`
(`sandbox-core/src/backend/container.rs:144`) and **separately** locates the
`sandbox-guest` binary at runtime via the `guest_agent_path` resolver
(`sandbox-core/src/lima.rs:1926-1955`), which falls back to the directory
next to the running `sandboxd` executable. Both backends use the same
resolver today (the container build copies the binary into a staging
tempdir at `container.rs:1276-1283`, the Lima `install_guest_agent` path
copies it via `limactl copy` at `lima.rs:631-650`).

For refresh, two delivery shapes are viable:

- **A. `include_bytes!` the guest binary into `sandboxd`.** The Dockerfile
  precedent at `container.rs:144` (and the comment block at lines 138-144
  motivating it) says the daemon embeds artefacts that must travel with the
  daemon binary to user machines without a Rust toolchain. The guest binary
  is a strictly larger version of the same constraint — at refresh time the
  daemon ships a guest binary into a session that was originally created
  by an *older* daemon (which built and embedded a different guest). Today's
  `guest_agent_path` resolver answers "where is the *current* daemon's
  sibling guest binary?", which is exactly what refresh needs, but only on
  developer machines where the build artefacts coexist on disk. End-user
  installs (Spec 4) place `sandboxd` under `/usr/local/bin/` and the guest
  binary alongside at `/usr/local/bin/sandbox-guest` — but rollback to an
  older daemon would invalidate that path. `include_bytes!` makes the
  daemon ↔ guest version pair atomic.

- **B. Keep the sibling-file model.** Cheaper to build (no embed), but the
  refresh ergonomics get murky around partial upgrades. Out of scope for
  Spec 2 to make this call across the install/upgrade arc.

Spec 2 picks **option A — embed the guest binary via `include_bytes!`**
inside `sandbox-core` (alongside `LITE_DOCKERFILE`), with a small write-to-
tempfile shim at refresh time. The container build path
(`build_lite_image` at `container.rs:1255`) can continue using the
`guest_agent_path` resolver because that path is dev-only — production
builds (Spec 4) will switch it to the same embedded source, but Spec 2 does
not pre-empt that decision. The dev-mode coexistence holds: the embedded
bytes resolve to the just-compiled guest binary at workspace build time
(via a `build.rs` `cargo:rerun-if-changed` on the sibling crate's output).

### 3.7 · `can_refresh_in_place` — v1 body

A coarse predicate. The function is in `sandbox-core/src/guest.rs` next to
the compatibility predicate:

```rust
/// `true` when this daemon's refresh path can realistically install its
/// embedded guest binary into a session at `session_proto`. For v1 the
/// answer is "yes for every protocol version we recognise"; the seam
/// exists so a future protocol change with an irreconcilable break
/// (e.g. a wire framing change that an old guest cannot understand even
/// to read the "please upgrade yourself" message) can flip its arm to
/// `false` without touching the daemon dispatch.
///
/// `session_proto == 0` is treated as "unknown / pre-V006 record" — but
/// V006 deletes all rows on apply (§ 2.1), so this arm is defensive: in
/// practice every row reaches this function with a real proto value.
pub fn can_refresh_in_place(session_proto: u32) -> bool {
    // v1: every persisted session is refreshable. Future irreconcilable
    // breaks would special-case the relevant proto range here.
    session_proto != 0
}
```

The function takes only the proto version, not the whole session — backends
do not differ in v1 on what "refreshable" means. If they ever do, this
function widens to take `&Session`; the call site at § 3.4 already loads
the full session.

### 3.8 · Per-backend refresh mechanics

The `SessionRuntime` trait at `sandbox-core/src/backend/mod.rs:236-303` gains
one new method:

```rust
/// Push the daemon's embedded `sandbox-guest` binary into the session
/// addressed by `handle` and (re)start the in-session agent so the
/// daemon's next protocol exchange talks to the new binary.
///
/// Implementations are responsible for the order of operations
/// (start the runtime if it was stopped, push the binary, restart the
/// guest service, stop the runtime back to its previous state if it
/// wasn't already started for this call) and for atomicity within their
/// own substrate. The daemon orchestrator (see § 3.4) only resumes the
/// normal start path after `Ok(())`.
async fn refresh_guest_binary(
    &self,
    handle: &RuntimeHandle,
) -> Result<(), SandboxError>;
```

The two backends implement it differently. The current invocation seams are
the call sites of `LimaManager::install_guest_agent`
(`sandboxd/sandboxd/src/main.rs:2055`) for Lima and the lite-mode container
image build (`sandbox-core/src/backend/container.rs:1276`) for container.

#### 3.8.1 · Container backend

Reality check first: the lite-mode container has **no init system**. Its
`Dockerfile` (`sandboxd/images/lite/Dockerfile:45`) sets
`ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/sandbox-guest"]`. There is
no systemd, no `service` command, no supervisord — `sandbox-guest` runs as
PID 2 under `tini` as PID 1. Restarting the guest binary in place means
**stopping and starting the container**, because the entrypoint exec is the
only way the new binary becomes the live process.

The container also runs with `--read-only` rootfs
(`container.rs:482`), but `docker cp` writes to the container's mutable
layer through the docker daemon's storage driver (not the container's view
of `/`), so it works on both running and stopped containers regardless of
`--read-only`. The constraint that matters is the init reality, not the
filesystem flag.

Refresh procedure for the container backend
(`sandbox-core/src/backend/container.rs:537-566` is where the new method
lives, next to `start`):

```
fn refresh_guest_binary(handle):
    container_name = handle.as_str()                    # "sandbox-{session_id}"

    # 1. Ensure the container is stopped — refresh runs only from
    #    `start_session`, which enforces session.state == Stopped, so
    #    the container is almost certainly already stopped. A defensive
    #    `docker stop` is a no-op for an already-stopped container.
    docker stop -t 5 <container_name>     # idempotent; ignore "is not running"

    # 2. Stage the embedded guest binary to a host tempfile.
    let tempfile = write_embedded_guest_to_tempfile()?;

    # 3. Push it into the container's writable layer at the canonical path.
    docker cp <tempfile> <container_name>:/usr/local/bin/sandbox-guest
    docker exec --user 0 ... chmod is NOT possible (container is stopped, and
        --user 0 is forbidden by the spec hardening anyway).
    # docker cp preserves source mode; the tempfile is written with 0755
    # so the in-container file inherits +x. Verified by the integration
    # test in § 7.4.

    # 4. Drop the host tempfile — its contents are now inside the container.
    drop(tempfile);

    # 5. Return Ok. The orchestrator (§ 3.4) calls `runtime.start(handle, args)`
    #    next, which runs `docker start` and the existing tini-->sandbox-guest
    #    entrypoint exec picks up the new binary.
```

This means `refresh_guest_binary` for the container backend is logically
**`docker cp` only** — it does not start the container itself. The
orchestrator's next step (the existing `runtime.start` at `main.rs:2730`) is
the start. This keeps refresh idempotent: a daemon that crashes between
"binary pushed" and "container started" leaves the session in `Stopped` with
the new binary on disk, and the next `start_session` re-runs the compat check,
finds the proto still mismatched (DB wasn't updated), re-pushes the same
binary (a no-op `docker cp`), then starts. Atomicity is provided by the
single `SessionStore.update_guest_versions` call **after** the runtime start
succeeds (§ 3.9).

#### 3.8.2 · Lima/QEMU backend

Lima provisions a full VM with systemd inside; the existing
`LimaManager::install_guest_agent` (`sandbox-core/src/lima.rs:608-795`) is
the existing "land the guest binary in a VM and turn it on" path. The
service unit (`GUEST_AGENT_SERVICE_UNIT` at `lima.rs:126-141`) is a systemd
`Type=simple` service named `sandbox-guest.service` running as user
`agent`.

Refresh procedure for the Lima backend
(`sandbox-core/src/backend/lima.rs`, the new method lives alongside the
existing trait methods):

```
fn refresh_guest_binary(handle):
    vm_name = handle.as_str()                            # "sandbox-{session_id}"

    # 1. Ensure the VM is running. `limactl copy` requires a running VM
    #    (the existing install_guest_agent call at main.rs:2055 only
    #    runs after a successful runtime.start, so the VM is up; for
    #    refresh, the session is Stopped, so we have to start it first).
    if vm_status != Running:
        limactl start <vm_name>

    # 2. Stage the embedded binary to a host tempfile.
    let tempfile = write_embedded_guest_to_tempfile()?;

    # 3. Use the same two-step pattern install_guest_agent already
    #    implements (lima.rs:631-706):
    #      a. limactl copy <tempfile> <vm_name>:/tmp/sandbox-guest
    #      b. limactl shell <vm_name> -- sudo mv /tmp/sandbox-guest \
    #             /usr/local/bin/sandbox-guest
    #      c. limactl shell <vm_name> -- sudo chmod +x \
    #             /usr/local/bin/sandbox-guest

    # 4. Restart the systemd service. The service unit name is
    #    "sandbox-guest" (lima.rs:774 / 1874).
    limactl shell <vm_name> -- sudo systemctl restart sandbox-guest

    # 5. Stop the VM back to its previous state so the orchestrator's
    #    runtime.start call sees the same Stopped → Running transition
    #    it would have seen without refresh.
    limactl stop <vm_name>

    # 6. Return Ok.
```

Unlike the container case, the Lima refresh **does** start and re-stop the
VM, because `limactl copy` requires a running VM. The orchestrator's
following `runtime.start` then re-starts the VM cleanly — the second start
is fast (VMs that were just-stopped have warm caches), and the alternative
(leaving the VM running and having `runtime.start` no-op for already-running)
introduces a state divergence between Lima's view and `Session.state`.

The reuse of the existing `install_guest_agent` body is deliberate: the spec
recommends extracting steps 2-4 above into a private
`install_guest_agent_files_only(vm_name, binary_bytes)` helper inside
`LimaManager`, called both from the existing
`install_guest_agent(session_id, binary_path)` at `lima.rs:613` (read the
sibling binary, call the helper) and from `LimaRuntime::refresh_guest_binary`
(read the embedded bytes, call the helper).

Both backend impls' new method must be on the trait (not on a concrete
type) so the orchestrator at § 3.4 dispatches through the existing
`runtime_for(&state, session.backend)` resolution
(`sandboxd/sandboxd/src/main.rs:2723`).

### 3.9 · Atomic version update on successful refresh

After `runtime.refresh_guest_binary(&handle).await` returns `Ok(())` and
the subsequent `runtime.start(&handle, &args).await` also returns `Ok(())`,
the daemon calls a single new `SessionStore` method:

```rust
/// Update both guest-version fields for the session in one transaction.
/// Atomic on the storage side; the caller must hold the orchestration
/// invariant that the in-VM/in-container binary really is at the new
/// version before this is invoked.
pub fn update_guest_versions(
    &self,
    caller_username: &str,
    id: &SessionId,
    proto: u32,
    binary_version: &str,
) -> Result<(), SandboxError>;
```

The transaction shape mirrors `set_policy` (`store.rs:689`) — open
`conn.transaction()`, run a single `UPDATE` keyed by `id AND owner_username`,
commit. Failure modes:

- **Update succeeds**: the next `start_session` for this session takes the
  fast path (compat passes), no refresh recurs.
- **Update fails** (DB I/O error, lock contention): the in-VM/in-container
  binary is already the new one, but the DB still records the old version.
  The daemon logs the failure at `error!` and returns the runtime-start's
  successful response to the operator (the session is, in fact, running).
  The next `start_session` for this session re-runs the compat check, finds
  the still-old version, calls `refresh_guest_binary` again, the runtime's
  refresh is **idempotent** (a `docker cp` of the same bytes is a no-op,
  same for the Lima sequence — the systemctl restart is a no-op when the
  service has just been started and is healthy), the start succeeds, and the
  DB update gets a second chance. **No state can permanently diverge** — the
  worst outcome is one extra refresh cycle on the next start.
- **Refresh succeeds, runtime.start fails**: the orchestrator marks the
  session `Error` (existing behavior, `main.rs:2733`). The DB still records
  the old version, but the session is now `Error` and any subsequent
  `start_session` call refuses with `InvalidState` (the session must
  transition through stop/remove). Operator recreates if the runtime is
  wedged; no need to roll back the version.

Why the order matters: we update the DB **only after both** refresh and
runtime.start succeed, not after refresh alone. This means a daemon crash
between refresh and start re-runs refresh on the next attempt (cheap and
idempotent) rather than leaving the DB claiming "this session speaks the
new protocol" against an unstarted runtime.

### 3.10 · On-demand guest version query — stopped vs. running trust rule

The compatibility predicate (§ 3.3) reads the **persisted**
`sessions.guest_protocol_version` column. That value is authoritative
**when the session is stopped** — the daemon is the sole writer of the
column and writes it only at create time and after a successful refresh
(§ 3.9), so on the start path the DB and the on-disk binary inside the
session cannot diverge unless an operator manually edits one or the other.
For a stopped session about to be started, DB-side state is good enough:
**the refresh decision tree in § 3.4 stays exactly as specified**.

But once the session is **running**, the daemon can talk to the guest
directly. A diagnostic surface — what `sandbox doctor` will eventually
report, what an integration test wants to assert post-start — benefits
from asking the runtime "what version are you actually running?"
rather than trusting the DB column alone. To support that, Spec 2 adds an
on-demand version-query primitive to the guest wire protocol.

The new request and reply pair:

```rust
// sandbox-core/src/guest.rs — extending the existing GuestRequest /
// GuestResponse enums at lines 50 / 59. Tag-on-deserialise matches the
// existing `#[serde(tag = "type")]` shape so old guest binaries that
// don't recognise the new variant still produce a structured error.

pub enum GuestRequest {
    Ping,
    Exec { command: String, args: Vec<String> },
    Status,
    Version,                              // <-- new
}

pub enum GuestResponse {
    Pong,
    ExecResult { exit_code: i32, stdout: String, stderr: String },
    StatusResult { hostname: String, uptime_secs: u64, load_average: f64 },
    Error { message: String },
    VersionResult {                        // <-- new
        protocol_version: u32,             // guest's compile-time DAEMON_GUEST_PROTO_VERSION
        binary_version: String,            // guest's compile-time SANDBOX_GUEST_VERSION
    },
}
```

Guest-side handler is trivial — read its own compiled-in constants and
return them. The handler lives in `sandbox-guest/src/main.rs` next to
the existing `handle_request` dispatch at line 90:

```rust
async fn handle_request(request: GuestRequest) -> GuestResponse {
    match request {
        GuestRequest::Ping => GuestResponse::Pong,
        GuestRequest::Exec { command, args } => handle_exec(command, args).await,
        GuestRequest::Status => handle_status().await,
        GuestRequest::Version => GuestResponse::VersionResult {
            protocol_version: sandbox_core::guest::DAEMON_GUEST_PROTO_VERSION,
            binary_version: sandbox_core::guest::SANDBOX_GUEST_VERSION.to_string(),
        },
    }
}
```

The trust rule the daemon follows:

| Session state | Compatibility decision input                                      | Why                                                                                                            |
|---------------|-------------------------------------------------------------------|---------------------------------------------------------------------------------------------------------------|
| `Stopped`     | persisted `sessions.guest_protocol_version`                       | Guest is not running; no live wire to query. Daemon wrote the column itself; safe to trust.                  |
| `Running`     | live `GuestRequest::Version` reply (when the caller needs ground truth) | Guest is reachable; the daemon can ask. Decision is **for diagnostics / drift detection only**, not for the refresh-on-start path which never sees a running session. |

This is **not** a connect-time handshake. The daemon does not
automatically issue `Version` on every accepted guest connection or every
start. The primitive exists so callers that genuinely need the live
value (Spec 3's `sandbox doctor`; an opt-in defense-in-depth check
described below) can request it on demand. Every other code path
continues to use the persisted column.

#### Forward note — Spec 3's `sandbox doctor`

Spec 3 will design the `sandbox doctor` surface. That spec will use
`GuestRequest::Version` to compare running-guest reports against the DB
column and surface drift to operators. **Spec 2 only provides the protocol
primitive; it does not design or implement the doctor side.** The query
is added now because it shares the same wire-protocol diff as the new
version constants and the same `GuestRequest` enum that
`DAEMON_GUEST_PROTO_VERSION` already gates — splitting it across two
specs would force `DAEMON_GUEST_PROTO_VERSION` to bump twice.

#### Optional defense-in-depth post-start cross-check

After a successful `start_session` (compatible path or refresh path), the
daemon **may** issue `GuestRequest::Version` and compare the reply to the
DB column. If they disagree, log a warning at `warn!` level. This is a
forward note for implementer judgment — useful for catching the rare
case where someone manually replaced `/usr/local/bin/sandbox-guest`
inside a session out-of-band — but is **not a hard requirement** for
Spec 2. The implementer can ship without it; if added, the cross-check
must not block the start response (the session is, by then, running and
serving the operator's request).

## 4 · `SO_PEERCRED` plumbing — relationship to Spec 1

Spec 2 needs the operator's username to stamp `owner_username` on create and
to filter every subsequent endpoint by caller. Spec 1 needs the same value to
populate the route-helper's `--for-user` argument. They use the **same**
mechanism — `SO_PEERCRED` on every accepted socket connection, resolved via
`getpwuid_r` to a username, stashed in axum's request `Extension` so handlers
extract it through a typed extractor.

Spec 1 § 6 specifies the plumbing in detail: a custom acceptor wrapping
`tokio::net::UnixListener` calls `stream.peer_cred()`
(`tokio::net::unix::UCred`) immediately after `accept`, resolves the uid via
`nix::unistd::User::from_uid`, refuses the connection on resolution failure,
and attaches a typed `OperatorIdentity { uid, name }` value to the request
via `Request::extensions_mut().insert(...)`. Handlers extract it via the
`axum::Extension<OperatorIdentity>` extractor.

**Recommendation for Spec 2's implementer**: if Spec 1 has already landed by
the time Spec 2 begins, **reuse it as-is** — every handler enumerated in § 2.3
(H1 - H12) gains an `Extension<OperatorIdentity>` parameter, and the
`caller_username` arg threaded down through `SessionStore` calls is
`operator.name`. If Spec 2 lands first, implement the plumbing described in
Spec 1 § 6 verbatim (`OperatorIdentity` struct, custom acceptor, refuse-on-
unresolved policy) and Spec 1's implementer consumes the same extractor.

The shared seam — `OperatorIdentity` + the custom acceptor — should live in
`sandbox-core` rather than the daemon binary so both specs reference one
copy. The exact module placement is implementation detail
(`sandbox-core/src/caller_identity.rs` or `sandboxd/src/peer_cred.rs` —
Spec 1 § 11 places it in `sandboxd/src/main.rs` because the acceptor wraps
axum's listener; if Spec 2 lands first, prefer the same placement so Spec 1
slots in without code-move).

Username-resolution failure: refuse the request. Do **not** silently fall
back to UID strings. Spec 1 § 9.1 walks through the failure surface area
(rare in practice — host `/etc/passwd` corruption, race during `userdel`);
the daemon-side behavior is identical for Spec 2: a connection whose UID
doesn't resolve is closed without a response. The CLI sees a connection
reset and reports the daemon's generic "cannot connect" error. A future
spec can add a structured 4xx if the operator-facing surface needs more
detail; both Spec 1 and Spec 2 accept the bare-reset behavior because the
failure mode is rare and the alternative (parse the HTTP request first
just to write a richer error) breaks the layering.

### 4.1 · CI implications of strict resolution

The strict policy is a **deliberate production hardening** and a
**deliberate CI regression** that adopters must address. Today's daemon
runs the connection-acceptor without any uid → username dependency; an
operator whose uid has no `/etc/passwd` entry (a routine state in
minimal container-CI images, or in nspawn / chroot sandboxes that share
the host kernel's uid space but not its passwd file) reaches the API
without trouble. Spec 2's strict policy closes their connection.

CI authors using the daemon in such environments have three remediation
paths:

1. Add `useradd` to the CI image's prep step so the runner uid has a
   passwd entry. The common ten-line CI prep snippet
   (`useradd --uid $(id -u) --create-home ci`) suffices and is the path
   the spec recommends.
2. Bind-mount a passwd file with the runner's uid present, if the CI
   environment supports it.
3. For ephemeral sandboxes that intentionally have no passwd file,
   skip the daemon integration tests entirely until a passwd entry is
   provisioned.

The strictness is **not configurable** in v1 — the failure mode it
protects against (an attacker-controlled passwd race during `userdel`)
is a real correctness concern, and adding a "lax mode" knob would force
every future contributor to reason about both branches. Spec 2 commits
to the regression and provides the test coverage below so the failure
mode is observable rather than silently mysterious.

The matching integration test
(`integration_daemon_refuses_unresolvable_peer_cred`) is specified in
§ 7.5; it asserts the daemon closes the connection cleanly without
crashing when the connecting uid has no passwd entry. The same property
on the route-helper side is covered by Spec 1 § 8.4
(`integration_route_helper_denies_when_username_unresolvable` covers
the `for_user` arg; § 7.5 here covers the **caller-uid** path that
Spec 1's test does not exercise).

## 5 · Wire snapshot — before / after

Today's `POST /sessions` request (sketch):

```
POST /sessions HTTP/1.1
Host: localhost
Content-Type: application/json

{
  "name": "alice-feat-xyz",
  "config": { "cpus": 2, "memory_mb": 4096, "disk_gb": 20, ... }
}
```

Response (existing `SessionDto` shape; reflecting only the relevant fields):

```json
{
  "id": "0123456789ab",
  "name": "alice-feat-xyz",
  "state": "Creating",
  "backend": "container",
  ...
}
```

Post-Spec-2:

- Request body unchanged. The daemon reads the operator from `SO_PEERCRED`
  (no request-body field can spoof it).
- Response gains two new fields in the SQL row (and therefore in any
  `sandbox describe` rendering, depending on the DTO mapping —
  not specified here, that's a downstream UX call): `owner_username`,
  `guest_protocol_version`, `guest_binary_version`. Whether `owner_username`
  appears on the wire is a `SessionDto` decision; the spec recommends
  including it because the operator already knows their own name and
  surfacing it gives a sanity check.

`POST /sessions/{id}/start` against a session created with an older
protocol version, refused:

```
POST /sessions/0123456789ab/start HTTP/1.1
Host: localhost
```

Response:

```
HTTP/1.1 409 Conflict
Content-Type: application/json

{
  "error": "session 0123456789ab was created with guest protocol 1; daemon supports 2; refresh is not viable for this session (reason: protocol pre-dates refresh seam); recreate the session: `sandbox session rm 0123456789ab && sandbox session create ...`"
}
```

`POST /sessions/{bob_id}/get` from alice:

```
HTTP/1.1 404 Not Found
Content-Type: application/json

{
  "error": "session not found: <bob_id>"
}
```

The 404 body is verbatim what the daemon already emits today for a truly-
nonexistent ID via `SandboxError::SessionNotFound` →
`error_response` (`sandboxd/sandboxd/src/error.rs:62`). Alice cannot
distinguish "doesn't exist" from "exists but isn't mine".

### 5.1 · Guest wire protocol — request/reply additions

The existing wire protocol uses JSON over a length-prefixed framing
(`sandbox-core/src/guest.rs:80-103` for `write_message` / `read_message`;
4-byte big-endian u32 length + payload, max 1 MiB). The `GuestRequest`
and `GuestResponse` enums are tagged via `#[serde(tag = "type")]`
(`guest.rs:49` and `guest.rs:58`). The new variants extend each enum
unobtrusively — old guest binaries that don't recognise `Version` return
`GuestResponse::Error { message: "..." }` from serde's default
unknown-variant rejection, which the daemon already handles via its
`GuestResponse::Error` arm.

Wire shape, request:

```json
{ "type": "Version" }
```

Wire shape, reply (success):

```json
{
  "type": "VersionResult",
  "protocol_version": 1,
  "binary_version": "0.1.0"
}
```

Wire shape, reply from an old guest that doesn't know `Version`:

```json
{
  "type": "Error",
  "message": "unknown variant `Version`, expected one of `Ping`, `Exec`, `Status`"
}
```

(Exact error text depends on the serde rendering; the daemon does not
parse it — it falls through to "guest does not support Version" and the
caller of the query handles that case as "guest is too old to self-report"
— the persisted column remains the only available answer.)

The guest's `Version` reply is **not** mapped onto an HTTP endpoint by
Spec 2. The primitive lives on the daemon ↔ guest wire only. Surfacing
it on the daemon's HTTP API (`GET /sessions/{id}/version`,
`sandbox doctor`, etc.) is Spec 3's job.

## 6 · Backward compatibility — dev mode

`make setup-dev-env` developers run the daemon as themselves. There is no
dedicated `sandbox` system user yet (Spec 3). Spec 2's behavior in this mode:

### 6.1 · One-time stopped-session loss and substrate-orphan footprint

On first daemon start after V006 lands, refinery applies the migration. The
migration's first statement (`DELETE FROM sessions;`) removes every persisted
session row. The cascade through V003's foreign keys removes policy rows for
each. The reconciler (`main.rs:2465-2487`) then iterates the now-empty
session list on every `list_sessions` call and never reaches the runtime
state, so the daemon performs no automatic substrate cleanup.

`SessionStore::new` emits the `warn!` log specified in § 2.1.1
exactly once on the boot where V006 applies. Developers running
`make setup-dev-env` see the log on first daemon restart after pulling
in the V006-bearing daemon binary.

The orphan footprint, by substrate:

| Resource                                    | Identifier pattern             | Manual cleanup                                                                                                |
|---------------------------------------------|--------------------------------|---------------------------------------------------------------------------------------------------------------|
| Per-session directories                     | `{base_dir}/sessions/<id>/`    | `rm -rf $XDG_DATA_HOME/sandboxd/sessions/<id>/` (or the dir matching the daemon's `--base-dir` argv).         |
| Lima VMs                                    | `sandbox-<id>`                 | `limactl delete --force sandbox-<id>` per VM.                                                                  |
| Docker containers                           | `sandbox-<id>`                 | `docker rm -f sandbox-<id>` per container.                                                                     |
| Docker volumes                              | `sandbox-home-<id>`            | `docker volume rm sandbox-home-<id>` per volume.                                                               |
| Docker networks                             | `sandbox-net-<id>`             | `docker network rm sandbox-net-<id>` per network.                                                              |
| Gateway containers                          | `sandbox-gw-<id>`              | `docker rm -f sandbox-gw-<id>` per gateway.                                                                    |

For developers, the realistic cleanup path is to wait for **Spec 3's
`sandbox doctor` check C13** (in-design at audit time, landing in
parallel) to enumerate the orphans, then run the substrate `rm` commands
or the doctor's optional `--fix` flag if Spec 3 chooses to expose one.
Pre-Spec-3, the manual `docker ps -a --filter name=sandbox-` and
`limactl list` walk surface the orphans by hand.

The spec considered three alternatives, all rejected:

- **Add a Rust-side sweep at migration time** — refinery's `.sql`
  migrations are intentionally code-free, and the runtime / Docker /
  Lima clients are not constructed yet when refinery runs (the daemon's
  `AppState` builds them after `SessionStore::new` returns).
- **Defer V006 itself behind an operator-driven `sandbox update
  --confirm`** — V006 cannot be deferred; the schema bump is a daemon
  startup precondition (every subsequent `INSERT INTO sessions` writes
  the three new columns), and refusing to start until the operator
  confirms would block dev iteration on every daemon update.
- **Stamp the orphans with a marker (`__legacy__`) and let the
  reconciler clean them up** — the marker leaks an unresolvable owner
  identity into the filter and forces a special-case carve-out (§ 2.1
  rejected this for the same reason).

End-user installs (Spec 4) are greenfield: the V006-bearing daemon is
the first daemon they run, `sessions.db` does not exist, and no
substrate orphans can pre-exist. The orphan footprint is a dev-mode
upgrade concern only.

### 6.2 · Single-operator visibility — identical

Alice runs the daemon as `alice`. `SO_PEERCRED` resolves every connection's
uid to `alice`. `create_session` stamps `owner_username = "alice"`.
`list_sessions` filters `WHERE owner_username = 'alice'` and returns every
session she creates (because they all share that owner). `get_session`
returns 200 for any of her sessions. There is no UX difference from today
for the single-operator case.

### 6.3 · Guest version stamps in dev

Every session created by a dev daemon stamps the dev daemon's
`DAEMON_GUEST_PROTO_VERSION` (the constant baked into the just-built daemon
binary) and `SANDBOX_GUEST_VERSION` (the just-built guest binary's semver).
On restart, `is_protocol_compatible` returns `true` and the existing
fast-path runs. Dev iteration cycles (rebuild daemon, restart, restart
session) are unaffected.

### 6.4 · Exercising the refresh path in dev

Developers test the refresh path by:

1. Creating a session with the current daemon.
2. Bumping `DAEMON_GUEST_PROTO_VERSION` from 1 to 2 in
   `sandbox-core/src/guest.rs`.
3. Rebuilding sandboxd.
4. Stopping the daemon, restarting it, calling `sandbox session start`.

The compat check fires, `can_refresh_in_place` returns `true`, the refresh
runs, the version columns update. The same path covers Spec 5's eventual
production refresh on `sandbox update`.

A second iteration (bumping to 3, restarting) exercises the multi-hop case:
v1 → v2 → v3 each refresh successfully, the binary version stamps update
each time, the proto version too.

### 6.5 · Refuse path in dev

To exercise the refuse arm, a developer manually edits `can_refresh_in_place`
to return `false` for the prior proto, rebuilds, and tries to start an old
session. The 409 with the structured error message renders; the integration
test in § 7.5 (`integration_guest_refresh_refuses_when_unsalvageable`)
covers this without manual editing by feeding a synthetic
`session.guest_protocol_version = 0` row through a test-only
`SessionStore` constructor (the V006 default-`0` SQL placeholder is the
seam — § 3.7 documents that the predicate treats 0 as unrefreshable).

## 7 · Test plan

Hermetic by default, integration when out-of-process state is needed. Project
convention from `CLAUDE.md` § "Integration-test convention": tests requiring
real Docker / real Lima / a live gateway are named `integration_*` and
selected by the `integration` nextest profile
(`sandboxd/.config/nextest.toml`).

### 7.1 · Migration tests

| Test name                                            | Behavior |
|------------------------------------------------------|----------|
| `v006_applies_cleanly_to_fresh_db`                   | Empty DB; refinery runs V001 - V006; final schema has the three new columns. |
| `v006_deletes_existing_sessions_on_dev_upgrade`      | Seed V005-shape DB with two sessions + policy rows; apply V006; assert sessions and policy descendants are gone. |
| `v006_columns_have_correct_constraints`              | After migration, attempt `INSERT` without `owner_username` — fails. |
| `v006_idempotent_on_reapply`                         | Second `SessionStore::new` does not re-apply V006 (refinery's migration table prevents this); the table is still empty on the second open if no creates happened between. |

These live alongside the existing migration tests at
`sandbox-core/src/store.rs:2370+` (the V004 integration tests follow the
same shape).

### 7.2 · Unit tests for `SessionStore` filtering

Run under the default nextest profile (hermetic — no Docker, no Lima):

| Test name                                                              | Setup                                                                  | Assertion |
|------------------------------------------------------------------------|------------------------------------------------------------------------|-----------|
| `create_stamps_caller_username`                                        | Create as `alice`                                                      | Row's `owner_username == "alice"` |
| `get_returns_own_session`                                              | Alice creates; alice gets                                              | `Ok(Some(_))` with the row |
| `get_returns_none_for_foreign_session`                                 | Alice creates; bob gets                                                | `Ok(None)` |
| `list_returns_only_callers_sessions`                                   | Alice creates two; bob creates one; alice lists                        | Length 2, neither row is bob's |
| `list_empty_for_caller_with_no_sessions`                               | Alice creates one; carol lists                                         | Length 0 |
| `update_state_refuses_foreign_session`                                 | Alice creates; bob tries `update_state` Running→Stopped                | `Err(SessionNotFound)` |
| `delete_refuses_foreign_session`                                       | Alice creates; bob tries `delete_session`                              | `Err(SessionNotFound)` |
| `prefix_resolution_scoped_to_caller`                                   | Alice creates `0123456789ab`; bob creates `0fedcba98765`; bob resolves prefix `01`            | `ResolveOutcome::NotFound` (alice's row not visible to bob) |
| `name_resolution_scoped_to_caller`                                     | Alice creates session named `staging`; bob creates session named `staging`; bob fetches by name | Returns bob's row, not alice's |

### 7.3 · Unit tests for compatibility predicate

`sandbox-core/src/guest.rs`:

| Test name                                            | Input                                          | Expected |
|------------------------------------------------------|------------------------------------------------|----------|
| `is_compatible_matches_current_version`              | `DAEMON_GUEST_PROTO_VERSION`                   | `true` |
| `is_compatible_rejects_older_version`                | `DAEMON_GUEST_PROTO_VERSION - 1` (assuming ≥1) | `false` |
| `is_compatible_rejects_future_version`               | `DAEMON_GUEST_PROTO_VERSION + 1`               | `false` |
| `is_compatible_rejects_zero`                         | `0`                                            | `false` |
| `can_refresh_in_place_accepts_known_versions`        | `1` (and `DAEMON_GUEST_PROTO_VERSION`)          | `true` |
| `can_refresh_in_place_rejects_zero`                  | `0`                                            | `false` |

### 7.3.1 · Static-analysis test for `update_state_reconcile` callers

Hermetic. Lives at `sandboxd/sandbox-core/tests/update_state_reconcile_allow_list.rs`
(or equivalent; the file location is implementation detail, but it must
run under `cargo nextest run` in the default profile so a careless PR
fails CI immediately).

The test greps the `sandboxd/` workspace (excluding `target/`,
`tests/`, and the trait definition itself) for the string
`update_state_reconcile`, parses each hit's file:line, and asserts the
set of caller locations is **exactly** the allow-list pinned in § 2.4's
doc-comment:

```rust
const ALLOW_LIST: &[&str] = &[
    // Reconciler blocks inside session-read handlers.
    "sandboxd/sandboxd/src/main.rs::list_sessions",
    "sandboxd/sandboxd/src/main.rs::get_session",
    // Error/cleanup branches in create/start; the happy path uses
    // update_state, not _reconcile.
    "sandboxd/sandboxd/src/main.rs::create_session::error_cleanup",
    "sandboxd/sandboxd/src/main.rs::start_session::error_cleanup",
    // Startup reconciliation.
    "sandboxd/sandboxd/src/main.rs::main::startup_reconcile",
];
```

| Test name                                                  | Behavior |
|------------------------------------------------------------|----------|
| `update_state_reconcile_callers_match_allow_list`          | Walk the workspace tree, collect every file:function that mentions `update_state_reconcile`, compare against `ALLOW_LIST`. Fails if any new caller is added without updating the list; also fails if a listed caller is removed (catches drift in both directions). |
| `update_state_reconcile_not_called_from_request_handlers`  | Sub-check: assert no caller location is inside an `async fn` annotated with axum extractors (e.g., a function whose signature includes `State<Arc<AppState>>` or `Extension<OperatorIdentity>`). Belt-and-suspenders against the "developer adds a new handler that calls `_reconcile`" foot-gun. |

The walk uses simple line-based string matching (not a full Rust parser).
The signal-to-noise is high because the method name is distinctive; the
"function annotated with axum extractors" sub-check uses `regex` to
match the function signature within ±10 lines of each hit. If the
implementer prefers, the second check can be downgraded to a code
review checklist item — but the first check is mandatory.

### 7.4 · Unit tests for guest version-reporting handler

Hermetic — live in `sandbox-guest/src/main.rs` alongside the existing
`test_handle_ping` (`main.rs:260`) and `test_handle_status`
(`main.rs:329`) handler tests. The handler is pure (reads compile-time
constants, builds a `VersionResult`), so a direct call is sufficient:

| Test name                                              | Behavior |
|--------------------------------------------------------|----------|
| `test_handle_version_returns_compiled_constants`       | Call `handle_request(GuestRequest::Version)`; assert the reply is `VersionResult` with `protocol_version == DAEMON_GUEST_PROTO_VERSION` and `binary_version == SANDBOX_GUEST_VERSION`. |
| `test_end_to_end_version_over_loopback`                | Bind a `TcpListener` on `127.0.0.1:0`, spawn the existing `handle_connection` loop, send `GuestRequest::Version`, assert the deserialised reply matches the compile-time constants. Mirrors the existing `test_end_to_end_local` shape at `main.rs:458`. |

### 7.5 · Integration tests

Under `integration_*` prefix, selected by the `integration` nextest profile.
The tests run **single-uid** (the test-runner's own uid); the alice/bob
partition is verified at the storage layer by § 7.2's unit tests, not by
faking peer-cred. See § 9.2 for why Spec 2 picks this option.

| Test name                                                              | Backend     | Behavior |
|------------------------------------------------------------------------|-------------|----------|
| `integration_create_stamps_owner_from_peercred`                        | container   | One create over the real Unix socket; assert the persisted row's `owner_username` matches `whoami` (the test-runner's username resolved via `getpwuid_r`). Verifies the `SO_PEERCRED` → handler-extractor → store-stamp threading. |
| `integration_synthetic_foreign_owner_returns_404`                      | container   | Open the `SessionStore` directly and insert a row with `owner_username = "synthetic-other"` via the create-session-with-backend method (test fixture passes the synthetic name). Then issue `GET /sessions/<id>` over the daemon socket as the real test runner. Expect `404`. Repeats the request against every session-id endpoint (H3, H5, H6, H7, H8, H9, H10, H11, H12) and asserts each returns `404`. Verifies that the storage-boundary filter rejects the synthetic-owner row when reached via the HTTP layer threaded with the real peer-cred. |
| `integration_list_returns_only_callers_sessions`                       | container   | Same fixture: insert one synthetic-owner row and one runner-owned row. `GET /sessions` over the socket returns one entry — the runner-owned one. |
| `integration_daemon_refuses_unresolvable_peer_cred`                    | container   | Required by § 4.1. Run the daemon-side acceptor against a connection whose uid does not resolve. Implementation note: the test creates a synthetic uid in a fixture chroot whose `/etc/passwd` lacks that uid, opens a Unix socket connection from inside the chroot, and asserts the daemon's acceptor refuses the connection cleanly (`peer_cred` succeeds, `User::from_uid` returns `Ok(None)`, the daemon closes the stream and continues accepting). The daemon process must not crash; subsequent connections from a valid uid must succeed. If the chroot fixture overshoots the test's value, the implementer may downgrade to a unit test against `OperatorIdentity::from_peer_cred` with a synthetic non-resolvable uid — flagged in § 9.2. |
| `integration_guest_refresh_container_backend`                          | container   | Seed a session row with `guest_protocol_version = 0` and an old `sandbox-guest` binary baked into the container; call `start_session`; assert (a) the refresh ran (binary mtime in the container changed; binary version inside the container reports the new value via the new `GuestRequest::Version` query), (b) the DB columns updated, (c) the session reached `Running`. |
| `integration_guest_refresh_lima_backend`                               | lima        | Same as above. Marked `#[cfg_attr(not(has_kvm), ignore)]` or equivalent so CI runners without `/dev/kvm` skip it (existing convention for Lima integration tests). |
| `integration_guest_refresh_refuses_when_unsalvageable`                 | container   | Seed a session row with `guest_protocol_version = 0` AND patch `can_refresh_in_place` (via a test-only `set_can_refresh_in_place_override` hook on the daemon) to return `false`; call `start_session`; assert the response is `409 Conflict` with body substring `refresh is not viable for this session` and `recreate the session`. |
| `integration_guest_version_columns_persist_through_create_and_start`   | container   | Standard happy-path session create; read the row back; assert all three new columns hold non-default values and `guest_binary_version` matches `env!("CARGO_PKG_VERSION")` of the `sandbox-guest` crate. |
| `integration_guest_version_query_returns_compiled_constants`           | container   | Standard happy-path session create + start; issue `GuestRequest::Version` through the `GuestConnector` against the running guest; assert the reply is `VersionResult` and that `protocol_version == DAEMON_GUEST_PROTO_VERSION` and `binary_version == SANDBOX_GUEST_VERSION`. Confirms the wire-level primitive works end-to-end against a real running session. |
| `integration_v006_emits_orphan_warning_log`                            | container   | Seed a V005-shape `sessions.db` with one row; open it through `SessionStore::new`; capture `tracing` events; assert the `warn!` from § 2.1.1 fired exactly once with the fixed-message substring `pre-V006 sessions were deleted`. Re-open on the next iteration and assert the log does **not** fire (refinery's migration history table prevents the re-fire). |

The tests above are single-uid by design (see § 9.2). The synthetic-
foreign-owner approach gives integration-layer coverage of the `404` shape
without the multi-uid harness cost; the unit tests in § 7.2 cover the
genuine alice-vs-bob partition at the storage layer with synthetic names.

### 7.6 · `sandbox describe` / `sandbox inspect` output

The new `owner_username` and version fields surface (or not) on these CLI
commands per the existing DTO mapping rules at
`sandbox-core/src/api.rs`. Spec 2 does **not** specify the CLI rendering;
the implementation adds fields to `SessionDto` (or its derived DTOs) as
optional and the CLI follows existing patterns for inspect/describe (see
`.tasks/specs/2026-04-17-sandbox-inspect-describe-design.md`). Test
assertions on the CLI surface are added only if the implementer keeps
parity with the existing inspect/describe coverage; the spec leaves the
DTO shape decision to that author rather than pre-empting it.

## 8 · Out of scope

The following are **not** in Spec 2:

- **Spec 3** — The dedicated `sandbox` system user, the systemd unit, the
  move of state to `/var/lib/sandbox/`, file modes, socket ACLs, the
  `sandbox doctor` command, version pinning. Spec 2 assumes Spec 3 lands
  but does not depend on it for the API isolation story — the per-caller
  filter is meaningful today (any non-trivial dev environment with
  multiple operators on one box benefits immediately).
- **Specs 4 / 5** — The release pipeline, signed builds, `install.sh` /
  `uninstall.sh` on GH Pages, the Lima test harness, the `sandbox update`
  CLI, the config-migration framework, the lock file, the backup folder.
  None of this affects Spec 2.
- **Admin override** in the API. If a future need surfaces, it lives in a
  dedicated config (e.g. `/etc/sandboxd/admins.conf`), not in `users.conf`
  (which is helper-scoped per Spec 1) and not in `sessions.db`.
- **Multi-version protocol negotiation** (daemon ↔ guest, daemon ↔ CLI).
  v1 is exact-match. The seam (`is_protocol_compatible` /
  `can_refresh_in_place`) is in place so a follow-up can widen it without
  touching the call sites; widening itself is a separate spec.
- **`sandbox describe` / `sandbox inspect` field additions for the new
  columns.** Their addition follows the existing DTO mapping conventions
  (Spec 2 doesn't pre-empt how `SessionDto` evolves), and is best handled
  alongside the broader install/inspect UX work Specs 3/4/5 will surface.
- **Cross-user mutation / sharing surfaces.** A "share this session with
  bob" endpoint is not in v1 and is not expected for the foreseeable
  future — the sandbox model is per-operator isolation, not
  multi-tenant collaboration.

## 9 · Risks and open questions

### 9.1 · `sandbox-guest`'s wire-protocol version surface today (and what Spec 2 adds)

Verified by inspection of `sandboxd/sandbox-guest/src/main.rs` (580 lines,
covered in full) and `sandboxd/sandbox-core/src/guest.rs:50-74` (the
`GuestRequest` / `GuestResponse` enums). The wire protocol today carries
**no** version surface — no `Hello`, no version-stamped framing, no
self-report.

Spec 2 adds **two distinct pieces** of version surface, used in
**two distinct trust regimes**:

1. **Persisted column** (`sessions.guest_protocol_version`, § 3.1) — read
   on the **stopped-session refresh-on-start path** in § 3.4. Daemon is
   the sole writer (create time, post-refresh). Authoritative on the start
   path because there is no live wire to ask. No handshake is added at
   connect time, deliberately — a guest-side handshake on every connect
   would force every existing `Ping` / `Exec` / `Status` call site to
   negotiate, which the predicate (§ 3.3) does not need.

2. **On-demand `GuestRequest::Version` primitive** (§ 3.10, § 5.1) — used
   on the **running-session diagnostic path**. When the session is up and
   a caller (Spec 3's `sandbox doctor`, an opt-in defense-in-depth check)
   needs the ground truth from inside the session, it issues the query.
   The reply carries both the guest's compile-time
   `DAEMON_GUEST_PROTO_VERSION` and its `SANDBOX_GUEST_VERSION`.

The reasoning for the split: a connect-time handshake **on every guest
exchange** buys nothing — the daemon already knows what it shipped on the
last refresh, the persisted column tracks that, and every wire exchange
would pay a round-trip for information the daemon usually already has. An
**on-demand** query, on the other hand, is the natural primitive for the
diagnostic surfaces Spec 3 will build, and for cross-checking the
persisted column on a running session if the implementer wants
defense-in-depth (see § 3.10's "optional post-start cross-check" note).

What this resolves about the original CLARIFY signal: the wire protocol
**does** gain a version surface in Spec 2, but only as the on-demand
primitive — not as a handshake, not as part of the refresh decision tree,
and not on a daemon HTTP endpoint. The refresh-on-start tree (§ 3.4)
continues to be DB-driven; that path doesn't need a live query because
the session it's reasoning about is, by definition, stopped.

The remaining divergence risk: a running session whose
`/usr/local/bin/sandbox-guest` has been replaced out-of-band (operator
error or external automation) could report a `binary_version` that
disagrees with the DB column. The `Version` query is what makes that
detectable; how that surfaces to operators is Spec 3's design surface.
Spec 2 only owns the primitive.

### 9.2 · Faking `SO_PEERCRED` in integration tests — Spec 2 picks single-uid

`SO_PEERCRED` is kernel-set on connect; you can't lie about it from
userspace without dropping privileges first. Multi-uid integration tests
either run under sudo and `setuid` between connects, or spawn setuid
helper subprocesses owned by a second test user — both options bring
real CI setup cost (a setuid helper to install with `chmod u+s`, a
second uid to provision with `useradd`, root in the GitHub Actions
runner to do both, and a corresponding tear-down to keep the workflow
hermetic).

**Spec 2 commits to option (b) — single-uid integration tests, paired
with full storage-layer coverage of the filter.** The reasoning:

- The storage-boundary filter (§ 2.4) is **where the safety property
  lives**. Every `SessionStore` method gains `caller_username`, every
  query gains the SQL `AND owner_username = ?`, and every method that
  filters has a unit test in § 7.2 asserting alice-vs-bob isolation
  against an in-memory store. That is the strongest possible test of
  the filter itself — it directly exercises the SQL with synthetic
  usernames passed as plain strings, no peer-cred involved.
- The integration layer above it is responsible for the **threading**
  of the caller identity from `SO_PEERCRED` into the `caller_username`
  arg. That threading is a one-liner in each handler
  (`Extension(operator): Extension<OperatorIdentity>` →
  `store.get_session(&operator.name, ...)`). A single-uid integration
  test against a real daemon validates that the threading runs and the
  resolution succeeds; it cannot validate the per-caller partition
  directly without a second uid.
- The single-uid coverage gap is bounded: the only property the
  single-uid integration cannot verify is "alice's HTTP request really
  cannot reach bob's row through the daemon". The unit-level filter
  test does verify it; the integration-layer test verifies the
  threading is wired. A regression that bypasses both layers
  simultaneously (filter wired correctly but handler forgets to pass
  the operator name) is not the realistic failure mode — the typed
  `caller_username: &str` parameter on `SessionStore` is mandatory and
  the compiler catches the omission.

The single-uid integration tests in § 7.5 therefore assert:

- The connecting uid's resolved username **is** stamped into the
  persisted row (`owner_username`).
- The daemon's response shape for foreign-id lookups is `404` (this is
  tested by **synthesizing** a foreign-owner row directly through the
  store with a fake `caller_username = "synthetic-other"`, then issuing
  the HTTP request as the real test-runner uid; the foreign owner is
  not the test runner, so the request returns 404).
- The daemon closes the connection cleanly when the connecting uid has
  no passwd entry (§ 7.5's `integration_daemon_refuses_unresolvable_peer_cred`,
  required by § 4.1).

**Forward note for Spec 4's CI infrastructure.** A future spec can
upgrade the integration coverage to option (a) — the full multi-uid
harness — when the CI setup appetite exists. The setup would entail:

- A small setuid helper at `sandboxd/tests/helpers/peercred-connector`
  that takes `--username=<name>` and an HTTP request body on stdin and
  connects on behalf of the named uid.
- A test fixture that runs `useradd ci-isolation-second` (and
  `userdel` on tear-down) so the helper has a real second uid to drop
  to.
- A CI workflow setup step that runs the helper-install with
  `chmod u+s` against the just-built test binary.

The forward note exists so Spec 4's CI infrastructure design has a
hook to attach to if the upgrade is requested. Spec 2 itself **does
not require this**, and the test list in § 7.5 has been scoped to what
single-uid coverage can verify.

### 9.3 · Lima refresh's stop-then-start cycle

The Lima refresh procedure starts the VM, runs `limactl copy`, restarts
the systemd service, then stops the VM back. The orchestrator then runs
the existing `runtime.start` which starts it again. That's two warm starts
in sequence. On modern hosts this costs ~5-10s of extra wall-clock time
per refresh; on slow hosts it could double the start time. The alternative
(skip the second stop, have `runtime.start` no-op for already-running)
mixes state machines in a way that makes the start-after-refresh path
diverge from the start-without-refresh path, and silent no-ops have a
history of biting later. Spec 2 accepts the double-start cost: refresh is
rare (a sandboxd update boundary), and start time on the refresh path is
already secondary to the refresh's content (the binary copy + service
restart dominates).

### 9.4 · `docker cp` on a `--read-only` container

Verified above (§ 3.8.1) that `docker cp` writes through the docker
daemon's storage driver and is unaffected by `--read-only`. There's one
caveat: the writable layer for a `--read-only` container is implementation-
specific (overlay2 mounts the upperdir read-only; rootless docker uses
fuse-overlayfs; some storage drivers may behave differently). The
container backend already requires default-hardened docker (per
`SandboxError::RootlessDockerRefused` at `sandbox-core/src/error.rs:73`,
and the rootless-docker probe at `sandbox-core/src/backend/container_rootless_probe.rs`),
so the supported surface is overlay2 on regular dockerd. The
`integration_guest_refresh_container_backend` test pins this for the
storage driver the CI runner uses; if production lands a host with a
non-overlay2 driver, the failure surfaces in that integration test before
it reaches operators.

### 9.5 · The "session created by an older daemon, refresh runs, refresh fails partway" path

The window between "binary pushed into VM/container" and
"systemctl restart succeeded" (Lima) or "container started with new
binary" (container) is the window where the in-session state is
**ahead** of the on-disk daemon-side state. § 3.9 walks through the
failure modes and concludes that the worst case is one extra refresh
on the next start. The integration test
`integration_guest_refresh_container_backend` covers the happy path;
adding a fault-injection variant that kills the daemon between
refresh-runtime-start and DB-update would harden this further, but is
discretionary — the orchestration is simple enough that a unit test on
the orchestration function itself (mocking `refresh_guest_binary` and
`runtime.start`) covers the same property without needing real Docker.

### 9.6 · UID re-use after `userdel`/`useradd`

If alice is deleted and a new account is created at the same UID, that
account's `getpwuid_r` resolves to the **new** username. The daemon
filters by `owner_username = <new-name>`, which doesn't match alice's
old rows. The new account therefore cannot see alice's sessions — which
is the correct behavior. The rows are orphaned (no live user owns them);
operator recovery is either to recreate alice (her sessions become visible
again) or `DELETE FROM sessions WHERE owner_username = 'alice'` directly
(a Spec 3 / Spec 5 admin task, not exposed via the API). Spec 2 doesn't
solve orphan cleanup; it's accepted as a multi-user-host operational
concern.

### 9.7 · `getpwuid_r` failure mode under load

A connection's UID may fail to resolve during a brief race window after
`userdel`. The daemon refuses; the CLI sees a connection reset; the
operator re-runs after the rename settles. Spec 1 § 9.1 walked through
this and arrived at the same conclusion. No correctness invariant is
at stake; the impact is a transient API failure, which is recoverable
without daemon involvement.

## 10 · Implementation notes (light)

| Path | Kind of change |
|---|---|
| `sandboxd/sandbox-core/migrations/V006__add_owner_and_guest_versions.sql` | New migration — `DELETE FROM sessions;` + three `ALTER TABLE ADD COLUMN`. |
| `sandboxd/sandbox-core/src/store.rs` | `SessionStore` methods gain `caller_username: &str` (§ 2.4 table). `row_to_session` reads the three new columns. New method `update_guest_versions(caller_username, id, proto, binary_version)`. `update_state_forced` is renamed to `update_state_reconcile` and **does not gain `caller_username`** (§ 2.4 "Reconciler hot path — pinned rule"). The doc-comment carries the allow-list-of-callers contract verbatim. After refinery applies migrations, emit the V006 orphan-warning `warn!` per § 2.1.1 when V006 was freshly applied in this run (refinery's history table is the seam — log fires only when V006's row is newly inserted). |
| `sandboxd/sandbox-core/src/session.rs` | `Session` struct gains three new fields (`owner_username: String`, `guest_protocol_version: u32`, `guest_binary_version: String`); each `#[serde(default)]` for on-disk forward-compat per CLAUDE.md "On-disk compatibility". |
| `sandboxd/sandbox-core/src/guest.rs` | New constants `DAEMON_GUEST_PROTO_VERSION: u32 = 1`, `SANDBOX_GUEST_VERSION: &str`. New `pub fn is_protocol_compatible(u32) -> bool`. New `pub fn can_refresh_in_place(u32) -> bool`. New `GuestRequest::Version` variant and `GuestResponse::VersionResult { protocol_version: u32, binary_version: String }` reply variant. |
| `sandboxd/sandbox-guest/src/main.rs` | Handler for `GuestRequest::Version` returning `VersionResult` from the compile-time constants in `sandbox-core::guest`. Unit tests per § 7.4. |
| `sandboxd/sandbox-core/src/error.rs` | New `SandboxError::GuestProtocolIncompatible { session_id, session_proto, daemon_proto, reason }` variant. |
| `sandboxd/sandbox-core/src/backend/mod.rs` | `SessionRuntime` trait gains `async fn refresh_guest_binary(&self, handle: &RuntimeHandle) -> Result<(), SandboxError>`. |
| `sandboxd/sandbox-core/src/backend/container.rs` | `ContainerRuntime::refresh_guest_binary` — `docker cp` of the embedded guest binary; container is expected to be Stopped on entry. |
| `sandboxd/sandbox-core/src/backend/lima.rs` | `LimaRuntime::refresh_guest_binary` — start VM if stopped, `limactl copy` + sudo-mv + chmod + systemctl restart sandbox-guest, stop VM back to Stopped. Extract the file-only steps from `LimaManager::install_guest_agent` (`lima.rs:613`) into a shared helper. |
| `sandboxd/sandbox-core/src/lib.rs` | Re-export the new public symbols (`DAEMON_GUEST_PROTO_VERSION`, `SANDBOX_GUEST_VERSION`, `is_protocol_compatible`, `can_refresh_in_place`, `GuestProtocolIncompatible`). |
| `sandboxd/sandbox-guest/Cargo.toml`, `sandboxd/sandbox-guest/src/lib.rs` | Promote `sandbox-guest` to a hybrid lib + bin crate so `sandbox-core` can `use sandbox_guest::SANDBOX_GUEST_VERSION;`. The bin keeps using its own `main.rs`. |
| `sandboxd/sandbox-core/build.rs` (or equivalent) | If the embedding shape from § 3.6 needs a build script: `cargo:rerun-if-changed=../target/<profile>/sandbox-guest` to keep the embedded bytes in sync with the workspace build. Implementation detail. |
| `sandboxd/sandboxd/src/main.rs` | Custom acceptor + `OperatorIdentity` extension per Spec 1 § 6 (if Spec 1 hasn't already landed). Every session-id handler (H1 - H10) gains `Extension<OperatorIdentity>` and threads `operator.name` through to the store. `start_session` gains the compat-and-refresh gate per § 3.4. `error_response` matches the new `GuestProtocolIncompatible` variant → `409 Conflict`. |
| `sandboxd/sandboxd/src/events_http.rs`, `sandboxd/sandboxd/src/policy_http.rs` | H11, H12 — add `Extension<OperatorIdentity>` to the handlers, thread through to the store calls inside. |
| `sandboxd/sandboxd/src/error.rs` | `error_response` adds the `GuestProtocolIncompatible` arm (→ `409 Conflict`). |
| `sandboxd/sandbox-core/src/api.rs` | `SessionDto` decision (out of scope per § 8 — implementer's call on whether to surface the new columns on the wire). |
| `sandboxd/sandbox-cli/src/main.rs` | No changes required for Spec 2. CLI flags and command structure are unchanged. |
| `sandboxd/sandbox-core/tests/update_state_reconcile_allow_list.rs` | New: static-analysis test per § 7.3.1 (greps the workspace tree, asserts the caller set matches the pinned allow-list; runs under the default nextest profile). |
| `sandboxd/sandboxd/tests/` | New file(s) for the integration tests in § 7.5 — `integration_session_isolation.rs` (synthetic-foreign-owner 404, `integration_daemon_refuses_unresolvable_peer_cred`, etc.), `integration_guest_refresh_container.rs`, `integration_guest_refresh_lima.rs`. |

Coordination with Spec 1: if Spec 1 lands first, Spec 2 reuses its
`OperatorIdentity` + custom acceptor verbatim. If Spec 2 lands first,
Spec 2 implements the plumbing as Spec 1 § 6 describes (same struct
name, same module placement) and Spec 1 consumes it without code-move.
Either ordering is fine; the only invariant is that the resolution
function (`getpwuid_r` via `nix::unistd::User::from_uid`, refuse-on-
unresolved) is identical between specs so the two trust paths reason
about the same set of UIDs.

## 11 · Affected files — summary

| Path | Touch type |
|---|---|
| `sandboxd/sandbox-core/migrations/V006__add_owner_and_guest_versions.sql` | New |
| `sandboxd/sandbox-core/src/store.rs` | Edit: storage-boundary `caller_username` filter on every session-touching method; `update_guest_versions`; `update_state_forced` renamed to `update_state_reconcile` (no caller filter; doc-comment pins allow-list); V006-applied `warn!` log per § 2.1.1 |
| `sandboxd/sandbox-core/src/session.rs` | Edit: three new fields on `Session`; `#[serde(default)]` for forward-compat |
| `sandboxd/sandbox-core/src/guest.rs` | Edit: constants + compatibility predicates + `GuestRequest::Version` / `GuestResponse::VersionResult` variants |
| `sandboxd/sandbox-guest/src/main.rs` | Edit: handler for `GuestRequest::Version`; unit tests for the handler and end-to-end loopback |
| `sandboxd/sandbox-core/src/error.rs` | Edit: `GuestProtocolIncompatible` variant |
| `sandboxd/sandbox-core/src/backend/mod.rs` | Edit: `SessionRuntime::refresh_guest_binary` trait method |
| `sandboxd/sandbox-core/src/backend/container.rs` | Edit: `refresh_guest_binary` impl (docker cp of embedded bytes) |
| `sandboxd/sandbox-core/src/backend/lima.rs` | Edit: `refresh_guest_binary` impl (limactl copy + systemctl restart) |
| `sandboxd/sandbox-core/src/lima.rs` | Edit: extract `install_guest_agent` file-only steps into a shared helper |
| `sandboxd/sandbox-core/src/lib.rs` | Edit: re-export new public symbols |
| `sandboxd/sandbox-guest/Cargo.toml` | Edit: hybrid lib + bin |
| `sandboxd/sandbox-guest/src/lib.rs` | New: `pub const SANDBOX_GUEST_VERSION` (or equivalent constant re-export) |
| `sandboxd/sandboxd/src/main.rs` | Edit: peer-cred acceptor (if not from Spec 1); `OperatorIdentity` threaded through every session handler; `start_session` compat gate |
| `sandboxd/sandboxd/src/events_http.rs` | Edit: thread caller identity through `get_session_events` |
| `sandboxd/sandboxd/src/policy_http.rs` | Edit: thread caller identity through `propagation_status` |
| `sandboxd/sandboxd/src/error.rs` | Edit: `GuestProtocolIncompatible` → 409 |
| `sandboxd/sandbox-core/tests/update_state_reconcile_allow_list.rs` | New: static-analysis test for the reconciler-only caller contract (§ 7.3.1) |
| `sandboxd/sandboxd/tests/integration_session_isolation.rs` | New |
| `sandboxd/sandboxd/tests/integration_guest_refresh_container.rs` | New |
| `sandboxd/sandboxd/tests/integration_guest_refresh_lima.rs` | New |
| `docs/start/installation.md` | Edit: brief note about per-user session visibility, the recreate-on-incompat-upgrade behavior, and the strict-resolution CI implications from § 4.1 (operators in container-CI images need to provision a passwd entry for the runner uid) |
