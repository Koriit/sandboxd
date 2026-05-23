-- V006__add_owner_and_guest_versions.sql
-- V006: API session isolation + guest version compatibility.
--
-- This migration is destructive on the dev-mode upgrade path: it deletes
-- every existing row in `sessions` and its policy-cascade descendants
-- before adding the three NOT NULL columns. The handoff settled on this
-- shape over a `__legacy__` backfill marker because:
--   * Dev sessions are volatile (stopped VMs are routinely thrown away).
--   * The backfill marker leaks an unresolvable owner name into the
--     filter and would force a "treat __legacy__ as any caller" carve-out
--     that contradicts the per-caller isolation rule.
--   * End-user installs are greenfield — there is no `sessions.db`
--     to migrate. The destructive step only fires on developer machines
--     that already have a stopped-session row from before V006.
--
-- The cascade lands via the existing foreign keys (V003): deleting a
-- `sessions` row cascades to `session_policies` -> `policy_rules` ->
-- `policy_rule_http_filters`. The single DELETE below is sufficient.

DELETE FROM sessions;

ALTER TABLE sessions
    ADD COLUMN owner_username TEXT NOT NULL DEFAULT '';
ALTER TABLE sessions
    ADD COLUMN guest_protocol_version INTEGER NOT NULL DEFAULT 0;
ALTER TABLE sessions
    ADD COLUMN guest_binary_version TEXT NOT NULL DEFAULT '';
