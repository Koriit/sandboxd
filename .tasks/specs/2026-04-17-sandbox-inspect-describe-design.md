# `sandbox inspect` / `sandbox describe` — Design

**Date:** 2026-04-17
**Status:** Draft for review
**Scope:** New CLI commands to view session state + policy persistence fix + `HttpConstraints` domain model refactor.

---

## 1 · Motivation

Today there is no way for a user to see the current configuration of a running sandbox session. `sandbox ps` shows a compact table, `sandbox health` shows runtime health, but neither surfaces the session's size (CPUs/memory/disk), workspace mode, creation inputs (repo URL, boot command, template), or the currently active network policy.

While investigating the gap we discovered two additional issues that this spec corrects:

1. **Network policy is not persisted.** The daemon holds applied policies only in an in-memory `HashMap`. On daemon restart, the map is empty and gateways are reconstituted with an allow-all DNS policy. This is a silent security regression that persists until the user re-applies the policy.

2. **`HttpConstraints` domain model is semantically weaker than intended.** It expresses constraints as two independent `Vec<String>` fields (`methods`, `paths`) that the addon enforces as a cartesian product. This cannot express mixed-method rules like "GET /foo but POST /bar" — the intent that a caller writing policy almost certainly has.

This spec delivers all three changes together because they are tightly coupled: `inspect`/`describe` must show policy, and showing policy is only meaningful once it survives restart and has a trustworthy shape.

## 2 · CLI surface

Two commands accept one or more session names or UUIDs and resolve each via the existing name-or-id lookup.

| Command | Output | Style |
|---|---|---|
| `sandbox inspect <session>...` | Pretty-printed JSON array, one object per session, in input order | `docker inspect` |
| `sandbox describe <session>...` | Human-readable sections, blank line between sessions | `kubectl describe` |

### Error behaviour

Strict and atomic. All N session ids are resolved against the daemon first. If any one is missing, the CLI writes an error to stderr naming the first missing id, exits non-zero, and emits **no** stdout. Successful sessions earlier in the argument list are not printed. Rationale: keeps scripting predictable and aligns with the other `sandbox` subcommands.

### `describe` output layout

```
Session:      <id>
Name:         <name-or-->
State:        running
Created:      2026-04-17 12:34:56 UTC (5m ago)
Updated:      2026-04-17 12:40:02 UTC

Config:
  CPUs:        2
  Memory:      4096 MB
  Disk:        20 GB
  Workspace:   shared:/home/olek/project
  Hardened:    true
  Repo:        https://github.com/example/app.git
  Boot cmd:    make setup
  Template:    -

Runtime:
  Guest agent: connected
  Gateway:     running

Policy (v1.0, 3 rules):
  [0] allow http      github.com:443
        protocol:    tcp
        http_filters: GET /repos/*
        reason:      fetch repo metadata
  [1] allow tls       registry.npmjs.org:443
        protocol:    tcp
  [2] deny            *:*
        protocol:    any
        reason:      default deny
```

When no policy is applied, the policy block is replaced by a single line:

```
Policy: none
```

### `inspect` output

Pretty-printed JSON array. The element schema is defined by the `SessionDto` described in Section 3. `inspect <a> <b>` with two sessions produces `[{...}, {...}]`.

### Multi-session semantics

Both commands accept N arguments. `inspect` emits a JSON array of length N. `describe` emits N blocks separated by a single blank line. Input order is preserved.

## 3 · API surface

No new endpoint. Extend the existing `GET /sessions/{id}` response.

### DTO layer

API DTOs are defined separately from domain types; no `#[serde(flatten)]` of domain structs into wire types. Adding a field to a domain struct must not silently change the wire contract.

**`SessionDto`** (wire type for `GET /sessions/{id}` and `GET /sessions`):

```rust
pub struct SessionDto {
    pub id: String,
    pub name: Option<String>,
    pub state: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub config: SessionConfigDto,
    pub guest_agent_status: Option<String>,
    pub gateway_status: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy: Option<PolicyDto>,
}

pub struct SessionConfigDto {
    pub cpus: u32,
    pub memory_mb: u32,
    pub disk_gb: u32,
    pub workspace_mode: Option<String>,
    pub hardened: bool,
    pub repo: Option<String>,
    pub boot_cmd: Option<String>,
    pub template: Option<String>,
}
```

`PolicyDto` is a wrapper over the domain `Policy` that controls wire representation independently from the domain type.

Conversion from domain to DTO lives in a dedicated module (e.g. `sandbox-core/src/api/mapper.rs`) via explicit `From<&Session>`/`From<&Policy>` impls. Adding a new domain field is inert on the wire until the mapper is updated.

### Endpoint behaviour

| Endpoint | `policy` populated? | Persisted config fields visible? |
|---|---|---|
| `GET /sessions` | No — serde skips `None` | Yes (free — already loaded from `config_json`) |
| `GET /sessions/{id}` | Yes — looked up from in-memory map | Yes |
| `POST /sessions` | n/a | Yes (echoes created session) |
| `POST /sessions/{id}/policy` | n/a | Unchanged |
| `GET /sessions/{id}/health` | n/a | Unchanged — `health` keeps its focused schema |

### CLI call shape

For `inspect <a> <b> <c>` / `describe <a> <b> <c>`, the CLI issues N parallel `GET /sessions/{id}` calls, collects responses in input order, and renders. No batch endpoint is introduced — the per-session cost is negligible compared to the current UX.

## 4 · Session persistence schema

`SessionConfig` (domain) gains three optional fields:

| Field | Type | `serde` attribute | Default on existing records |
|---|---|---|---|
| `repo` | `Option<String>` | `#[serde(default)]` | `None` |
| `boot_cmd` | `Option<String>` | `#[serde(default)]` | `None` |
| `template` | `Option<String>` | `#[serde(default)]` | `None` |

No SQL migration required — `SessionConfig` is persisted as a JSON blob in the existing `config_json` column, and `#[serde(default)]` handles forward-compat. Records written before this change deserialize cleanly with `None` on all three fields.

The `POST /sessions` handler copies `repo`/`boot_cmd`/`template` from `CreateSessionRequest` into the new `SessionConfig` fields before persisting. No new write site.

## 5 · Policy persistence (normalized)

### Domain refactor (prerequisite)

Before persistence, the domain types are corrected. `HttpConstraints` loses its ambiguous cartesian-product shape and `AssuranceLevel` becomes a tagged enum that carries per-variant data.

```rust
#[derive(Serialize, Deserialize)]
#[serde(tag = "level", rename_all = "snake_case")]
pub enum AssuranceLevel {
    Deny,
    Transport,
    Tls,
    Http { http_filters: Vec<HttpFilter> },
}

pub struct HttpFilter {
    pub method: HttpMethod,   // closed enum
    pub path:   String,       // glob, e.g. "/api/*" or "/*"
}

pub enum HttpMethod {
    Get, Post, Put, Delete, Patch, Head, Options, Trace, Connect,
    Any,                      // explicit wildcard — no "empty = all" magic
}
```

The old `HttpConstraints` wrapper struct is dropped — it held a single field, no invariants.

`PolicyRule` carries common data; `level` is flattened into the JSON top level:

```rust
pub struct PolicyRule {
    pub destination: Destination,
    pub protocol:    Protocol,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason:      Option<String>,
    #[serde(flatten)]
    pub level:       AssuranceLevel,
}
```

Wire format is flat and human-friendly:

```json
{"destination": {"domain": "github.com"}, "protocol": "tcp", "level": "deny"}
{"destination": {"domain": "github.com"}, "protocol": "tcp", "level": "http",
 "http_filters": [{"method": "GET", "path": "/*"}]}
```

**Validation rules** (enforced in `PolicyCompiler::compile`):

- `AssuranceLevel::Http { http_filters }` must be non-empty.
- `HttpMethod` is a closed enum — no free-form strings pass deserialization.

### Clean break

Old-format policy JSON files (`{methods: [], paths: []}`) are not auto-converted. Loading them fails with a clear error referencing the new shape. There are no existing users to protect.

### Downstream touches

| Area | Change |
|---|---|
| `sandbox-core/src/policy.rs` | New `AssuranceLevel`, `HttpFilter`, `HttpMethod`; drop `HttpConstraints`; regenerate JSON schema via `schemars` |
| `PolicyCompiler` | Match arm `Full` → `Http { http_filters }`; mitmproxy JSON emits filter pairs |
| `networking/mitmproxy/` addon | Request-match logic iterates filter pairs; matches `(method, path)` — not cartesian |
| `AssuranceLevel::as_u8` | `Self::Http => 3` |
| Policy unit tests | Fixtures and assertions updated |
| Policy JSON schema consumers | Regenerated; `"full"` becomes `"http"` in any published schema |
| nftables / CoreDNS / Envoy compilation | Unaffected — none handle HTTP-level filters |

### Storage schema — three tables

All tables use `ON DELETE CASCADE` rooted at `session_policies`. `CHECK` constraints enforce enum values at insert time.

```sql
CREATE TABLE IF NOT EXISTS session_policies (
    session_id TEXT PRIMARY KEY,
    version    TEXT NOT NULL,
    FOREIGN KEY(session_id) REFERENCES sessions(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS policy_rules (
    session_id        TEXT    NOT NULL,
    rule_order        INTEGER NOT NULL,
    destination_kind  TEXT    NOT NULL CHECK (destination_kind IN ('domain', 'cidr')),
    destination_value TEXT    NOT NULL,
    level             TEXT    NOT NULL CHECK (level IN ('deny', 'transport', 'tls', 'http')),
    protocol          TEXT    NOT NULL CHECK (protocol IN ('tcp', 'udp', 'http', 'https', 'any')),
    reason            TEXT,
    PRIMARY KEY(session_id, rule_order),
    FOREIGN KEY(session_id) REFERENCES session_policies(session_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS policy_rule_http_filters (
    session_id   TEXT    NOT NULL,
    rule_order   INTEGER NOT NULL,
    filter_order INTEGER NOT NULL,
    method       TEXT    NOT NULL CHECK (method IN
                     ('GET','POST','PUT','DELETE','PATCH','HEAD','OPTIONS','TRACE','CONNECT','ANY')),
    path_pattern TEXT    NOT NULL,
    PRIMARY KEY(session_id, rule_order, filter_order),
    FOREIGN KEY(session_id, rule_order) REFERENCES policy_rules(session_id, rule_order) ON DELETE CASCADE
);
```

Migrations are idempotent `CREATE TABLE IF NOT EXISTS` statements added to `SessionStore::open`. There is no pre-existing persisted policy data to migrate.

### Write path — atomic

`POST /sessions/{id}/policy` handler:

```
1. Validate + compile the policy                      (existing)
2. Distribute to gateway components                   (existing)
3. Begin SQLite transaction
4.   DELETE FROM session_policies WHERE session_id=?  — cascades to children
5.   INSERT INTO session_policies (session_id, version)
6.   For each rule i:
7.     INSERT INTO policy_rules (...)
8.     If level == Http: for each (j, filter): INSERT INTO policy_rule_http_filters (...)
9. Commit
10. session_policies.lock().insert(id, policy)        (memory write)
```

DB writes happen inside step 3–9 before the in-memory map is touched. If the DB transaction fails, the client sees an error and the memory map is untouched. If the daemon crashes between step 9 and step 10, the next startup reloads the memory map from the DB and recovers.

### Read path

1. `SELECT version FROM session_policies WHERE session_id = ?` — absent row means no policy.
2. `SELECT * FROM policy_rules WHERE session_id = ? ORDER BY rule_order`.
3. For rules with `level = 'http'`: `SELECT method, path_pattern FROM policy_rule_http_filters WHERE session_id = ? AND rule_order = ? ORDER BY filter_order`.
4. Reassemble `Policy { version, rules }`.

### Startup hydration

Before `reconcile_networking` runs, the daemon iterates `session_policies` and loads each policy into `state.session_policies`. By the time gateway restore runs, the map is warm. `reapply_session_policy` finds the policy and pushes it to the fresh gateway container, closing the silent-allow-all regression.

### Corrupt data handling

If a persisted policy cannot be reassembled (e.g. missing parent row, constraint violation, deserialization failure), the daemon logs a warning with the `session_id` and the error, and leaves that session's map entry absent. On next policy apply the data is overwritten. The daemon does not crash.

## 6 · Testing

### Rust unit tests (`sandbox-core`)

| Test | Covers |
|---|---|
| `SessionConfigDto` round-trips existing `config_json` without new fields | Forward-compat — `serde(default)` on `repo`/`boot_cmd`/`template` |
| `From<&Session> for SessionDto` omits `policy` when `None` | DTO separation |
| `PolicyDto` serializes `AssuranceLevel::Http` with flattened `http_filters` | Wire shape |
| `AssuranceLevel::Http { http_filters: vec![] }` fails validation | Non-empty invariant |
| Old-format policy JSON (`{methods, paths}`) fails to deserialize | Clean break |
| `SessionStore::set_policy` and `get_policy` round-trip | Store basic CRUD |
| `SessionStore::load_all_policies` returns every persisted policy | Startup hydration source |

### Rust integration tests (`sandboxd`)

| Test | Covers |
|---|---|
| `GET /sessions` does not include `policy` | Lean list endpoint |
| `GET /sessions/{id}` includes `policy` after `POST /sessions/{id}/policy` | Single endpoint surfaces applied policy |
| `GET /sessions/{id}` on a session without policy → `policy` field absent on wire | Empty-case |
| `POST /sessions` with `repo`/`boot_cmd`/`template` → fields persisted and visible on later GET | Create→read round-trip |
| Apply policy → reopen `SessionStore` → in-memory map rebuilt from DB | Restart survival |

### CLI unit tests (`sandbox-cli`)

| Test | Covers |
|---|---|
| `inspect` with two session ids → output parses as JSON array of length 2 | Multi-session shape |
| `inspect` with a missing session → non-zero exit, stderr message, no stdout | Strict error |
| `describe` renders `Policy: none` when DTO has no `policy` field | Empty-case render |
| `describe` renders full rule block for N rules including `http_filters` lines | Rule dump fidelity |
| `describe` sections for M sessions are separated by blank lines | Multi-session render |

### E2E test (`tests/e2e/`)

One new test covering the restart-regression fix end-to-end:

1. Start the sandbox daemon (via the test harness's standard `sandboxd` fixture).
2. Create a session and apply a restrictive policy (e.g. allow `github.com:443` only, deny everything else).
3. Verify enforcement with two curls from inside the guest: one to an allowed destination (succeeds), one to a denied destination (fails).
4. Stop the daemon process (SIGTERM; await exit) and restart it with the same `base_dir`.
5. Re-run the same two curls. Assert: allowed still succeeds, denied still fails — without re-posting the policy.

The restart is a plain process stop/start; no systemd or supervisor is involved. The existing e2e harness already exposes helpers for stopping and starting the daemon.

## 7 · Out of scope — parked as `F2`

Two concerns surfaced during this design and are explicitly deferred to a future milestone (`session-plan.md` → `F2: Policy Persistence Hardening`):

- `F2-S1` — Policy domain-model migration playbook. Playbook and tooling for evolving `Policy` or its nested types, requiring SQL `ALTER`/data transforms.
- `F2-S2` — Policy-at-rest encryption. Evaluate whether the `policy_rules` / `policy_rule_http_filters` tables require encryption beyond filesystem permissions.

## 8 · Affected files — summary

| Path | Kind of change |
|---|---|
| `sandboxd/sandbox-core/src/policy.rs` | Refactor `AssuranceLevel`, add `HttpFilter`/`HttpMethod`, drop `HttpConstraints` |
| `sandboxd/sandbox-core/src/session.rs` | Add `repo`/`boot_cmd`/`template` to `SessionConfig` |
| `sandboxd/sandbox-core/src/api.rs` | New DTO layer (`SessionDto`, `SessionConfigDto`, `PolicyDto`) |
| `sandboxd/sandbox-core/src/api/mapper.rs` (new) | Domain → DTO conversions |
| `sandboxd/sandbox-core/src/store.rs` | New tables, new `set_policy`/`get_policy`/`load_all_policies` |
| `sandboxd/sandboxd/src/main.rs` | Policy write-through on `POST /sessions/{id}/policy`; startup hydration before `reconcile_networking` |
| `sandboxd/sandbox-cli/src/main.rs` | New `inspect` and `describe` subcommands; describe renderer |
| `networking/mitmproxy/` | Addon rewrite to match filter pairs |
| `docs/cli-reference.md` | New sections for `inspect` and `describe` |
| `docs/policy.md` | Update examples to new shape |
| `tests/e2e/` | New test for policy-survives-restart |

## 9 · Open follow-ups beyond this spec

- `CLAUDE.md` now documents on-disk compatibility rules (added as part of this design work).
- The `F2` milestone has been added to `session-plan.md` — see there for session breakdown.
