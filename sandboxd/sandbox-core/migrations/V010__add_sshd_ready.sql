-- V010: Add nullable sshd_ready column to sessions.
--
-- Nullable (no NOT-NULL / no DEFAULT) so older rows added before this
-- migration read back as NULL / None -- the proxy short-circuit treats
-- None as "unknown / not probed" and preserves today's behaviour
-- (attempt the tunnel). Only container sessions that have been probed
-- after V010 carry Some(true|false); Lima sessions and pre-V010 rows
-- stay NULL.
ALTER TABLE sessions ADD COLUMN sshd_ready INTEGER;
