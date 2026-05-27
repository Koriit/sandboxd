-- V008__add_operator_uid.sql
-- Adds per-session operator uid + gid columns used by the supervisor-
-- fork-as-operator architecture: every runtime spawn (QEMU for Lima,
-- container init for the lite-mode backend) goes through the new
-- `sandbox-spawn-helper` binary which `setresuid`'s to the operator's
-- numeric uid before `execve`'ing the runtime tool. The numeric uid
-- is captured at session-create time from the daemon socket's
-- `SO_PEERCRED` and persisted here so the post-restart spawn path can
-- recover the operator identity without re-resolving via NSS.
--
-- Forward-only. Both columns are `INTEGER NULL` so existing rows
-- continue to deserialise without a backfill; pre-V008 sessions read
-- back with `operator_uid = None` / `operator_gid = None` and route
-- through the legacy spawn-as-daemon path. This keeps rollback safe:
-- a downgrade to a pre-V008 daemon binary continues to read rows it
-- wrote (the columns are simply absent from its SELECT list).
--
-- The forward-compat story on the Rust side is the same `#[serde(default)]`
-- + `Option<u32>` shape used by every other recent session-row field
-- addition — see `Persisted state forward-compat` in the cross-user
-- CLI access spec.
--
-- The trust model is the existing § Security considerations premise:
-- members of the `sandbox` OS group are trusted with every session's
-- private key, and (transitively) with the `setresuid(operator_uid)`
-- primitive exposed by the cap'd helper. The numeric uid stored here
-- is not itself a credential; it is the well-known identity the
-- operator authenticates as via the `SO_PEERCRED` exchange on session
-- create. Capturing it on the session row only allows post-restart
-- spawn paths to recover the same identity without an additional
-- daemon round-trip.

ALTER TABLE sessions
    ADD COLUMN operator_uid INTEGER NULL;

ALTER TABLE sessions
    ADD COLUMN operator_gid INTEGER NULL;
