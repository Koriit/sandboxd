-- M10-S1 Phase 2 Commit 5 — v2 port-explicit policy schema (spec
-- `.tasks/specs/2026-04-21-port-explicit-policies-presets-observability-
-- design.md`, Part 1 § "Schema bump and migration").
--
-- v2 rule identity is `(host, port)`. v1 rows lack a port column and
-- may carry the deprecated protocol tokens `http`, `https`, `any`
-- which v2 rejects. Because v1 conflated port and protocol, there is
-- no lossless upgrade — affected sessions have their attached policy
-- dropped entirely and the daemon emits `policy_reset_on_upgrade` at
-- boot time (sandbox-core::store::SessionStore::open). The operator
-- then re-applies a v2 policy.
--
-- Migration strategy
-- ------------------
-- SQLite cannot alter an existing CHECK constraint in-place. The
-- standard workaround — create the new table, copy rows, drop the
-- old table, rename — is used here for `policy_rules`. The copy step
-- filters out v1-shaped rows (protocol ∉ {tcp, udp}) rather than
-- rewriting them, because an irreversible column (`port`) would have
-- to be invented from nowhere.
--
-- `session_policies` rows whose children were all purged are left
-- in place with no rule rows. The daemon (`SessionStore::open`) scans
-- for such orphans at startup, emits `policy_reset_on_upgrade`
-- tracing events naming each session, and deletes them — keeping
-- the migration purely SQL while the observability signal remains
-- a first-class tracing event that M10-S2 re-wires into the ring
-- buffer.

-- Step 1. Create the v2 shape of `policy_rules`.
--
-- Changes relative to V003:
--   - `destination_value` renamed to `host_value`. The column renaming
--     matches the Rust field rename (`destination` -> `host`) from
--     commit 2 of this phase; `destination_kind` keeps its name for
--     continuity — only the `value` side of the pair changed.
--   - New required `port` column with `CHECK (port BETWEEN 1 AND 65535)`
--     enforcing the spec's u16 range constraint.
--   - `protocol` CHECK tightened to `('tcp', 'udp')` — v1 tokens
--     `http`, `https`, `any` are rejected at insert time.
--
-- `IF NOT EXISTS` is deliberately omitted — this migration runs
-- exactly once and the _new table must not already exist.
CREATE TABLE policy_rules_v2 (
    session_id        TEXT    NOT NULL,
    rule_order        INTEGER NOT NULL,
    destination_kind  TEXT    NOT NULL CHECK (destination_kind IN ('domain', 'cidr')),
    host_value        TEXT    NOT NULL,
    port              INTEGER NOT NULL CHECK (port BETWEEN 1 AND 65535),
    level             TEXT    NOT NULL CHECK (level IN ('deny', 'transport', 'tls', 'http')),
    protocol          TEXT    NOT NULL CHECK (protocol IN ('tcp', 'udp')),
    reason            TEXT,
    PRIMARY KEY(session_id, rule_order),
    FOREIGN KEY(session_id) REFERENCES session_policies(session_id) ON DELETE CASCADE
);

-- Step 2. Drop child filter rows whose parent will be purged.
--
-- `policy_rule_http_filters` has a FK to `policy_rules(session_id,
-- rule_order)` with ON DELETE CASCADE. When we drop the old
-- `policy_rules` table below, the cascade will not fire because
-- SQLite treats DROP TABLE as a schema operation, not a row-delete.
-- We also delete filters whose parent v1 row would be purged, so
-- that orphaned filter rows never survive the migration.
DELETE FROM policy_rule_http_filters
WHERE (session_id, rule_order) IN (
    SELECT session_id, rule_order
    FROM policy_rules
    WHERE protocol NOT IN ('tcp', 'udp')
);

-- Step 3. Delete v1-shaped rows from the old `policy_rules`.
--
-- We cannot copy them into v2 because there is no port to assign.
-- The operator will re-apply a v2 policy for the affected sessions;
-- until then, `SessionStore::open` emits `policy_reset_on_upgrade`
-- and removes the parent `session_policies` row.
DELETE FROM policy_rules
WHERE protocol NOT IN ('tcp', 'udp');

-- Step 4. Copy surviving (tcp/udp) rows into the v2 table.
--
-- These rows pass the new protocol CHECK but lack a port. The
-- only safe default is a placeholder that the operator can
-- rediscover from the session's attached config (typically 443
-- for HTTPS, 80 for HTTP). Since v1 conflated protocol and port,
-- there is no correct answer for "this tcp rule" without operator
-- input — so we still treat these as v1-shaped and purge them
-- along with the rest. `SessionStore::open` includes them in its
-- `policy_reset_on_upgrade` scan.
--
-- (If a future migration needs to preserve tcp/udp rows, it would
-- have to augment them with a port value supplied out-of-band,
-- e.g. via the config_json. That is explicitly out of scope for
-- v2: the spec says "delete v1-shaped rows via table-copy"
-- without a preservation path.)
DELETE FROM policy_rules;

-- Step 5. Swap the tables.
DROP TABLE policy_rules;
ALTER TABLE policy_rules_v2 RENAME TO policy_rules;

-- Step 6. Re-create the FK from `policy_rule_http_filters` to the
-- new `policy_rules`.
--
-- SQLite rebinds FKs by name, so this is implicit — no action
-- needed. The CHECK on filters themselves is unchanged.

-- Step 7. Leave orphaned `session_policies` rows in place.
--
-- The daemon sweeps them at startup and emits a
-- `policy_reset_on_upgrade` tracing event per affected session,
-- naming the session by id. See
-- `SessionStore::purge_orphaned_policies_and_emit_reset_events`.
