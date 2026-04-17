-- Normalized storage for session network policies.
--
-- Three tables, joined by (session_id, rule_order, filter_order):
--   session_policies        - one row per session with an applied policy
--   policy_rules            - ordered rules under a policy
--   policy_rule_http_filters - ordered (method, path) filters for http rules
--
-- ON DELETE CASCADE is rooted at session_policies (which itself cascades
-- from sessions) so deleting a session or re-applying a policy tears down
-- all descendants cleanly.
--
-- CHECK constraints enforce enum values at insert time so the store
-- cannot silently persist an unknown level / protocol / method / kind
-- that would fail to round-trip through serde.

CREATE TABLE IF NOT EXISTS session_policies (
    session_id TEXT PRIMARY KEY NOT NULL,
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
