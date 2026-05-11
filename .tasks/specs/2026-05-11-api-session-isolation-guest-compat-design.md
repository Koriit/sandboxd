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
| `update_state_forced`                        | 432          | gains `caller_username: &str`; reconciler path passes the persisted owner |
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

The reconciler block inside `list_sessions` and `get_session` (the
"DB-vs-Lima/Container state reconciliation" pattern at `main.rs:2465-2487`
and `main.rs:2524-2545`) calls `update_state_forced` after observing a
divergence between the persisted state and the runtime's status. That path
uses the session's own `owner_username` (already loaded via `get_session`) as
the caller value — the reconciler is not "alice's daemon-level action against
alice's session", it is "the daemon reconciling alice's session against
external reality", and the storage-boundary filter has to admit it. Two
options: route the reconciler through a separate `update_state_reconcile`
method without the filter, or have it pass `session.owner_username` as the
caller. The spec recommends the **explicit `update_state_reconcile` method**
because it documents the trust path at the call site rather than relying on
the reconciler to launder the right username.

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
for integration tests (see § 7.4).

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

## 6 · Backward compatibility — dev mode

`make setup-dev-env` developers run the daemon as themselves. There is no
dedicated `sandbox` system user yet (Spec 3). Spec 2's behavior in this mode:

### 6.1 · One-time stopped-session loss

On first daemon start after V006 lands, refinery applies the migration. The
migration's first statement (`DELETE FROM sessions;`) removes every persisted
session row. The cascade through V003's foreign keys removes policy rows for
each. The per-session directories under `{base_dir}/sessions/{id}/` are
**not** swept — the migration is a SQL transform; on-disk artefacts unwind
through `delete_session`'s `fs::remove_dir_all` (`store.rs:872-876`), which
the migration doesn't call. Operators see leftover directories with no
matching DB rows; `sandbox session ls` returns empty. Cleanup is manual
(`rm -rf $XDG_DATA_HOME/sandboxd/sessions/`) or deferred until the next
`sandbox session create` reuses an ID (collision-free given the 48-bit ID
space). The spec considered making the migration call into Rust to do the
directory sweep; rejected because (a) refinery's `.sql` migrations are
intentionally code-free for forward-port safety, and (b) the per-session
directories on dev machines are cheap kilobytes, not the multi-gigabyte VM
images (those live under Lima's own state, not under `sandboxd/sessions/`).

This is the dev-mode loss the handoff calls out: stopped Lima/container
sessions become unreferenceable. They cost a developer one `limactl delete`
or `docker rm` per orphan to recover the resources; it is not catastrophic.

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
test in § 7.4 (`integration_guest_refresh_refuses_when_unsalvageable`)
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

### 7.4 · Integration tests

Under `integration_*` prefix, selected by the `integration` nextest profile:

| Test name                                                              | Backend     | Behavior |
|------------------------------------------------------------------------|-------------|----------|
| `integration_session_isolation_404_on_foreign_id`                      | container   | Two daemon connections faking different `SO_PEERCRED` uids each create a session; alice tries every endpoint (H3, H5, H6, H7, H8, H9, H10, H11, H12) against bob's ID; every response is `404`. |
| `integration_session_list_per_caller_partition`                        | container   | Same setup; alice's `GET /sessions` returns only alice's session, bob's returns only bob's. |
| `integration_create_stamps_owner_from_peercred`                        | container   | One create; assert the persisted row's `owner_username` matches the test runner's username. |
| `integration_guest_refresh_container_backend`                          | container   | Seed a session row with `guest_protocol_version = 0` and an old `sandbox-guest` binary baked into the container; call `start_session`; assert (a) the refresh ran (binary mtime in the container changed; binary version inside the container reports the new value via a debug rpc), (b) the DB columns updated, (c) the session reached `Running`. |
| `integration_guest_refresh_lima_backend`                               | lima        | Same as above. Marked `#[cfg_attr(not(has_kvm), ignore)]` or equivalent so CI runners without `/dev/kvm` skip it (existing convention for Lima integration tests). |
| `integration_guest_refresh_refuses_when_unsalvageable`                 | container   | Seed a session row with `guest_protocol_version = 0` AND patch `can_refresh_in_place` (via a test-only `set_can_refresh_in_place_override` hook on the daemon) to return `false`; call `start_session`; assert the response is `409 Conflict` with body substring `refresh is not viable for this session` and `recreate the session`. |
| `integration_guest_version_columns_persist_through_create_and_start`   | container   | Standard happy-path session create; read the row back; assert all three new columns hold non-default values and `guest_binary_version` matches `env!("CARGO_PKG_VERSION")` of the `sandbox-guest` crate. |

The fake-peercred plumbing for the isolation tests: the daemon-test fixture
already exists for the container backend (the existing
`tests/integration_*` infrastructure under
`sandboxd/sandboxd/tests/`). For peer-cred faking, the cleanest path is to
spin up two separate Unix-socket connections from the test process with
distinct `SO_PEERCRED`s. Linux allows `SO_PEERCRED` to be set on a socket
created via a different uid only via `setsockopt`-like paths that require
privileges; the practical test approach is to run the test as one user and
**spawn a helper subprocess** that connects as a different uid (the
existing test harness already manages multiple service identities for
gateway-container tests — same pattern). The handoff explicitly does not
require Spec 2 to add new test infrastructure; if the path turns out to
require it, that's a finding to be raised before implementation (this is a
real risk — see § 9.2).

### 7.5 · `sandbox describe` / `sandbox inspect` output

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

### 9.1 · `sandbox-guest` has no wire-protocol version concept today

Verified by inspection of `sandboxd/sandbox-guest/src/main.rs` (580 lines,
covered in full) and `sandboxd/sandbox-core/src/guest.rs:50-74` (the
`GuestRequest` / `GuestResponse` enums). There is no version field on the
wire, no handshake, no version-stamped framing.

**Spec 2 adds the version concept on the host side only.** The version is
known to the daemon (compile-time `pub const`) and persisted in
`sessions.guest_protocol_version`. The daemon does **not** consult the
guest binary at runtime to learn its version — the persisted value is the
source of truth, refreshed by `update_guest_versions` after every successful
refresh.

This is a deliberate scoping decision. Adding a `GuestRequest::Hello`
handshake variant that returns the guest's own `DAEMON_GUEST_PROTO_VERSION`
constant is **possible** and would let the daemon double-check the
persisted value against the guest's self-report — but it doesn't change the
decision (the daemon already knows what it shipped on the last refresh)
and it doesn't survive a deliberately-modified guest binary anyway. The
risk-of-divergence is real but bounded: the only path that writes the
persisted value is the daemon's own refresh, which writes both the
in-VM/in-container binary and the DB column. The two cannot disagree
unless someone (a) manually edits `sessions.db`, or (b) manually replaces
`/usr/local/bin/sandbox-guest` inside a session. Both are operator-error
scenarios; the daemon's compat check is **enough** to gate the start path
on persisted state, and the runtime-error surface (deserialization errors
from a mismatched guest) already exists as the fallback when persisted
state is wrong.

A future spec could add the `Hello` handshake and use it to populate a
**diagnostic** field (e.g., "DB says proto 2; guest reports proto 1") on
`sandbox describe` output. Out of scope for Spec 2.

If, during implementation, this turns out to be a load-bearing assumption
that doesn't hold — e.g., the protocol bumps frequently enough that the
DB column drifts in practice — raise it and revisit before broadening the
spec. The CLARIFY signal the handoff calls out: today there is no wire
handshake, this spec does not add one, and it relies on the daemon being
the sole writer of the persisted version column for that to be safe.

### 9.2 · Faking `SO_PEERCRED` in integration tests

`SO_PEERCRED` is kernel-set on connect; you can't lie about it from
userspace without dropping privileges first. Multi-uid integration tests
either run under sudo and `setuid` between connects, or spawn helper
subprocesses under different uids. The existing daemon test harness uses
the test-runner's own uid; the new isolation tests at § 7.4 are the
first ones in the codebase that genuinely need **two** uids.

Realistic path: the integration-test harness gains a small helper binary
under `sandboxd/tests/helpers/peercred-connector` that takes
`--username=<name>` and `--session-id=<id>` argv, the runner installs it
setuid in test setup (a one-time `chmod u+s` against a privileged helper),
and the test invokes it to drive the foreign-uid requests. The complexity
is non-trivial; if the implementer finds the harness work overshoots the
isolation-test value, dropping to a single-process unit-level
`SessionStore` filter test (per § 7.2) plus a smaller integration test
that asserts the **404-shape** without faking peer-cred is an acceptable
fallback. The spec leans on the unit tests (§ 7.2) for the core property
and treats the multi-uid integration test as a high-confidence add-on.

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
| `sandboxd/sandbox-core/src/store.rs` | `SessionStore` methods gain `caller_username: &str` (§ 2.4 table). `row_to_session` reads the three new columns. New method `update_guest_versions(caller_username, id, proto, binary_version)`. Reconciler-only paths split into `update_state_reconcile` to keep the storage boundary safe. |
| `sandboxd/sandbox-core/src/session.rs` | `Session` struct gains three new fields (`owner_username: String`, `guest_protocol_version: u32`, `guest_binary_version: String`); each `#[serde(default)]` for on-disk forward-compat per CLAUDE.md "On-disk compatibility". |
| `sandboxd/sandbox-core/src/guest.rs` | New constants `DAEMON_GUEST_PROTO_VERSION: u32 = 1`, `SANDBOX_GUEST_VERSION: &str`. New `pub fn is_protocol_compatible(u32) -> bool`. New `pub fn can_refresh_in_place(u32) -> bool`. |
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
| `sandboxd/sandboxd/tests/` | New file(s) for the integration tests in § 7.4 — `integration_session_isolation.rs`, `integration_guest_refresh_container.rs`, `integration_guest_refresh_lima.rs`. |

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
| `sandboxd/sandbox-core/src/store.rs` | Edit: storage-boundary `caller_username` filter on every session-touching method; `update_guest_versions`; `update_state_reconcile` split |
| `sandboxd/sandbox-core/src/session.rs` | Edit: three new fields on `Session`; `#[serde(default)]` for forward-compat |
| `sandboxd/sandbox-core/src/guest.rs` | Edit: constants + compatibility predicates |
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
| `sandboxd/sandboxd/tests/integration_session_isolation.rs` | New |
| `sandboxd/sandboxd/tests/integration_guest_refresh_container.rs` | New |
| `sandboxd/sandboxd/tests/integration_guest_refresh_lima.rs` | New |
| `docs/start/installation.md` | Edit: brief note about per-user session visibility and the recreate-on-incompat-upgrade behavior (forward-compat for operators upgrading) |
