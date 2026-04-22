"""
Sandbox policy enforcement addon for mitmproxy.

Validates HTTP requests against policy rules loaded from a JSON config file.
Denied requests receive HTTP 599 response with a JSON body describing the
reason for denial.

When no config file is present, operates in pass-through mode (allow all)
for backwards compatibility.

Config format (from sandboxd MitmproxyConfig, M10-S1 v2 schema):

    {
      "rules": [
        {
          "host": "api.github.com",
          "port": 443,
          "filters": [
            {"method": "GET",  "path": "/repos/*"},
            {"method": "POST", "path": "/user/*"}
          ]
        },
        {
          "host": "registry.npmjs.org",
          "port": 443,
          "filters": [
            {"method": "ANY", "path": "/*"}
          ]
        }
      ]
    }

- Rule identity on the wire is `(host, port)`: a rule only matches a
  request whose destination port equals the rule's `port`.  A port
  mismatch skips the rule — if no other rule matches on both host and
  port, the deny reason distinguishes the two cases:
  `"host matched but port <port> not in policy"` when at least one rule
  matched the host at a different port, and `"host not in policy"`
  when no rule matched the host at all.  This lets policies express
  "HTTP to api.example.com:443 only, nothing on :8443" without a
  separate deny rule, and lets operators reading deny events tell a
  missing-port entry apart from a missing-host entry.  Added in M10-S1
  — prior versions omitted the field.
- Each `filters[i]` is a `(method, path)` pair — both must match
  together.  This differs from the pre-M9-S10 shape (independent
  `methods` / `paths` lists with cartesian-product semantics).
- `method` is an uppercase HTTP method name (`GET`, `POST`, ...) or the
  special marker `ANY` meaning "match any method".
- `path` is a per-segment glob (M10-S1):
    * `?` matches exactly one non-`/` character.
    * `*` matches zero or more non-`/` characters — within a single
      path segment, never crossing `/`.
    * `**` (only when it is a whole segment) matches zero or more
      complete path segments, including `/` separators.
    * Any other character is a literal (case-sensitive, anchored
      full-path match).
  Examples: `/api/*` matches `/api/users` but *not* `/api/v1/users`;
  `/api/**` matches both; `/repos/?/commits` matches `/repos/a/commits`
  but not `/repos/ab/commits`.
- An empty `filters` list means no request matches — sandboxd's policy
  compiler rejects such configurations at compile time, so the addon
  never receives them in practice.  If it does (hand-edited config),
  all requests to that host are denied with `"no filter matched"`.

M10-S2 Phase 6b: in addition to the human-readable ``logger.info`` /
``logger.warning`` lines, each decision is also emitted as a
structured JSONL event via :class:`events.EventEmitter` when
``SANDBOX_MITMPROXY_EVENTS`` is set in the environment.  The JSONL
stream is the machine-readable contract consumed by sandboxd's
ingester; ``logger`` lines remain for human operators tailing the
container.  Emission is **additive** — it never alters request
handling, and write failures are logged-and-swallowed so they cannot
turn into HTTP 500s.
"""

from __future__ import annotations

import fnmatch
import json
import logging
import os
import re
import threading
import time
from typing import Any

from mitmproxy import http

from events import EventEmitter

logger = logging.getLogger("policy_addon")

# Environment variable for config file path (set by sandboxd).
CONFIG_PATH_ENV = "SANDBOX_MITMPROXY_CONFIG"
# Default config file location inside the gateway container.
DEFAULT_CONFIG_PATH = "/tmp/mitmproxy/policy.json"
# Environment variable for the JSONL event stream path.  When set, the
# addon emits a structured event per decision to this file in addition
# to the existing ``logger.info`` line.  See ``events.py`` for the
# envelope definition.  Unset → no structured emission (unit tests).
EVENTS_PATH_ENV = "SANDBOX_MITMPROXY_EVENTS"
# How often (seconds) to poll the config file for changes.
CONFIG_POLL_INTERVAL = 5
# Internal health-check endpoint.
HEALTH_PATH = "/__sandbox_health"


def _peer_ip(flow: "http.HTTPFlow") -> "str | None":
    """Extract the client IP from a flow, tolerant of missing peers.

    ``flow.client_conn.peername`` is ``Optional[tuple[str, int]]`` on
    real mitmproxy flows; on our ``_FakeHTTPFlow`` test fixtures it's
    not set at all.  Either case is fine — we serialize the absence as
    JSON ``null`` in the event envelope so the ingest parser can tell
    "unknown peer" apart from "missing field".
    """
    try:
        peer = getattr(flow.client_conn, "peername", None)
    except AttributeError:
        return None
    if peer is None:
        return None
    # ``peername`` is a 2- or 4-tuple (IPv4 vs. IPv6).  Element 0 is
    # always the address literal.
    try:
        return str(peer[0])
    except (IndexError, TypeError):
        return None


# ── Per-segment path glob matcher ───────────────────────────────────
#
# Request paths are matched against a glob in which:
#
#   * ``?``  matches exactly one non-``/`` character
#   * ``*``  matches zero or more non-``/`` characters — does not
#            cross ``/``
#   * ``**`` matches zero or more characters *including* ``/`` (the
#            recursive wildcard; spans segments)
#   * every other character is a literal
#
# Matching is anchored (full-path) and case-sensitive.  Worked examples:
#
#   pattern           path                          match
#   ----------------  ----------------------------  -----
#   /api/*            /api                          no  (pattern needs `/`+segment)
#   /api/*            /api/users                    yes
#   /api/*            /api/v1/users                 no  (``*`` doesn't cross ``/``)
#   /api/**           /api                          no  (pattern needs literal ``/``)
#   /api/**           /api/                         yes (``**`` matches empty)
#   /api/**           /api/users                    yes
#   /api/**           /api/v1/users                 yes
#   /repos/?/commits  /repos/a/commits              yes
#   /repos/?/commits  /repos/ab/commits             no
#   /v?/users         /v1/users                     yes
#   /v?/users         /v10/users                    no
#   /exact            /exact                        yes
#   /exact            /exact/                       no  (trailing ``/`` not in pattern)
#
# Implementation: compile the pattern to a regular expression once per
# call.  Patterns are tiny (≤64 chars, ≤10 metachars) so
# ``re.fullmatch`` is cheap and we don't cache — simpler wins.
# Reference implementations exist in Express.js ``path-to-regexp`` and
# Go ``path.Match``; the spec calls them out as precedent.


def _path_glob_match(pattern: str, path: str) -> bool:
    """Return True iff *path* matches *pattern* under the glob above."""
    return _compile_path_glob(pattern).fullmatch(path) is not None


def _compile_path_glob(pattern: str) -> re.Pattern[str]:
    """Translate a path glob into a compiled :mod:`re` pattern.

    Each metacharacter is rewritten into its regex equivalent and every
    other character is regex-escaped so ``.``, ``+``, ``(`` etc. in
    real paths stay literal.  Done in a single left-to-right pass with
    a two-character lookahead for ``**``.
    """
    out: list[str] = ["^"]
    i = 0
    n = len(pattern)
    while i < n:
        ch = pattern[i]
        if ch == "*":
            # ``**`` → ``.*`` (any chars including ``/``);
            # ``*``  → ``[^/]*`` (within-segment wildcard).
            if i + 1 < n and pattern[i + 1] == "*":
                out.append(".*")
                i += 2
            else:
                out.append("[^/]*")
                i += 1
        elif ch == "?":
            # Single non-``/`` character.
            out.append("[^/]")
            i += 1
        else:
            out.append(re.escape(ch))
            i += 1
    out.append("$")
    return re.compile("".join(out))


class PolicyAddon:
    """Mitmproxy addon that enforces sandbox network policy.

    Loads policy rules from a JSON config file and validates each HTTP
    request against them.  Denied requests receive an HTTP 599 response.
    If no config file exists, all requests are allowed (pass-through mode).
    """

    def __init__(
        self,
        config_path: str | None = None,
        events: EventEmitter | None = None,
    ) -> None:
        self._config_path: str = (
            config_path
            or os.environ.get(CONFIG_PATH_ENV, "")
            or DEFAULT_CONFIG_PATH
        )
        self._rules: list[dict[str, Any]] = []
        self._passthrough: bool = True
        self._lock = threading.Lock()
        self._last_mtime: float = 0.0
        # When ``events`` is None (unit tests, or production with
        # SANDBOX_MITMPROXY_EVENTS unset) we skip structured emission
        # and keep only the human-readable ``logger.info`` line.
        self._events: EventEmitter | None = events

        self._load_config()
        self._start_watcher()

    # ── mitmproxy hook ──────────────────────────────────────────────

    def request(self, flow: http.HTTPFlow) -> None:
        """Main request hook — validate the request against policy."""
        host = flow.request.pretty_host
        method = flow.request.method
        path = flow.request.path
        # `flow.request.port` is the destination L4 port.  In M10-S1 the
        # addon matches on `(host, port)`, so a missing attribute on a
        # fake/test request defaults to 0 — which will never match a
        # real rule (rule ports are `1..=65535`).
        port = int(getattr(flow.request, "port", 0) or 0)

        # Health endpoint — always respond, regardless of policy.
        if path == HEALTH_PATH:
            flow.response = http.Response.make(
                200,
                json.dumps({"status": "ok"}),
                {"Content-Type": "application/json"},
            )
            return

        client_ip = _peer_ip(flow)

        # Pass-through mode: no config loaded → allow everything.
        if self._passthrough:
            logger.info(
                "[ALLOW] %s %s:%d%s (pass-through)", method, host, port, path
            )
            if self._events is not None:
                self._events.emit_request_allowed(
                    host=host,
                    port=port,
                    method=method,
                    path=path,
                    client_ip=client_ip,
                )
            return

        allowed, reason = self._check_request(host, port, method, path)
        if allowed:
            logger.info("[ALLOW] %s %s:%d%s", method, host, port, path)
            if self._events is not None:
                self._events.emit_request_allowed(
                    host=host,
                    port=port,
                    method=method,
                    path=path,
                    client_ip=client_ip,
                )
        else:
            logger.warning(
                "[DENY] %s %s:%d%s (%s)", method, host, port, path, reason
            )
            if self._events is not None:
                # ``reason`` is the exact string `_check_request`
                # returned — the character-for-character match between
                # the human log line above and the JSONL event is the
                # contract consumed by `sandbox events --decision=deny`.
                self._events.emit_request_denied(
                    host=host,
                    port=port,
                    method=method,
                    path=path,
                    reason=reason,
                    client_ip=client_ip,
                )
            flow.response = http.Response.make(
                599,
                json.dumps({
                    "error": "sandbox_policy_denied",
                    "reason": reason,
                    "host": host,
                    "port": port,
                    "method": method,
                    "path": path,
                }),
                {"Content-Type": "application/json"},
            )

    # ── Config loading ──────────────────────────────────────────────

    def _load_config(self) -> None:
        """Parse the JSON config file and update rules atomically."""
        path = self._config_path
        if not os.path.isfile(path):
            logger.info(
                "Config file %s not found — running in pass-through mode.", path
            )
            with self._lock:
                self._rules = []
                self._passthrough = True
            return

        try:
            with open(path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            new_rules: list[dict[str, Any]] = data.get("rules", [])
            with self._lock:
                self._rules = new_rules
                self._passthrough = False
            self._last_mtime = os.path.getmtime(path)
            logger.info(
                "Loaded policy config from %s (%d rules).", path, len(new_rules)
            )
        except (json.JSONDecodeError, OSError) as exc:
            logger.error("Failed to load config from %s: %s", path, exc)
            # Keep existing rules on reload failure; on first load this
            # means pass-through mode stays active.

    # ── Request validation ──────────────────────────────────────────

    def _check_request(
        self, host: str, port: int, method: str, path: str
    ) -> tuple[bool, str]:
        """Check a request against the loaded rules.

        Returns (allowed, reason).  *reason* is meaningful only when
        *allowed* is False.

        Semantics (M10-S1 v2): rule identity is `(host, port)`.  A rule
        only matches when its host pattern matches the request host
        **and** its `port` field equals the request's destination port.
        Rules with a host match but port mismatch are skipped — if no
        other rule matches, the deny reason distinguishes the two
        cases:

        * `"host not in policy"` — no rule matched the request host at
          any port.
        * `"host matched but port <port> not in policy"` — at least one
          rule matched the host, but none at the request's destination
          port.  This is the discovery signal operators need to tell a
          missing-port entry apart from a missing-host entry; the
          string is part of the deny-event schema consumed by
          `sandbox events --decision=deny` (M10-S2+).

        When at least one rule matches on both host and port, their
        `filters` lists contribute as a union: the request is permitted
        iff at least one filter from any matching rule matches the
        `(method, path)` pair.  This lets users split a single
        `(host, port)` policy across multiple rules without losing any
        allowed pair.
        """
        with self._lock:
            rules = list(self._rules)

        request_method = method.upper()

        # Walk every rule whose (host, port) matches and look for a
        # filter pair that matches (method, path).  Track host-only
        # matches separately so a port mismatch produces a distinct
        # deny reason from a genuine no-host-match — operators reading
        # deny events need to tell these cases apart.
        matched_any_rule = False
        matched_host_only = False
        for rule in rules:
            rule_host = rule.get("host", "")
            if not self._match_host(host, rule_host):
                continue
            # v2 schema: rule must carry a `port` and it must equal the
            # request's destination port.  A missing or non-integer
            # `port` means this is a legacy/malformed rule — skip it
            # rather than silently allowing.
            rule_port = rule.get("port")
            if not isinstance(rule_port, int):
                continue
            if rule_port != port:
                # Host matched but this rule is for a different port.
                # Remember that so we can emit the port-miss reason if
                # no other rule matches both host and port.
                matched_host_only = True
                continue
            matched_any_rule = True

            for flt in rule.get("filters", []):
                if self._filter_matches(flt, request_method, path):
                    return True, ""

        if not matched_any_rule:
            if matched_host_only:
                # Host appears in policy but not at this port — this is
                # the discovery signal operators need.  The string is
                # part of the deny-event schema; do not change without
                # coordinating with consumers of `sandbox events`.
                return False, f"host matched but port {port} not in policy"
            return False, "host not in policy"

        return False, f"no filter matched {method} {path}"

    @staticmethod
    def _filter_matches(flt: dict[str, Any], method: str, path: str) -> bool:
        """Return True iff `flt` permits this (method, path) pair.

        `flt` is a `{method, path}` object from the config.  `method` must
        equal the filter's method (uppercase) or the filter's method must
        be the wildcard marker `ANY`.  `path` is matched against the
        filter's path with the per-segment glob matcher (see
        :func:`_path_glob_match`) — case-sensitive, anchored, with
        segment-aware ``*`` / ``?`` and a recursive ``**`` wildcard.
        """
        flt_method = str(flt.get("method", "")).upper()
        flt_path = str(flt.get("path", ""))
        if not flt_method or not flt_path:
            return False
        if flt_method != "ANY" and flt_method != method:
            return False
        return _path_glob_match(flt_path, path)

    @staticmethod
    def _match_host(host: str, rule_host: str) -> bool:
        """Match a request host against a rule host pattern.

        Supports exact match and wildcard patterns like ``*.example.com``.
        Matching is case-insensitive.  Host globs use ``fnmatch`` because
        hostnames are a flat dot-separated namespace where a single
        ``*`` is the idiomatic subdomain wildcard; the per-segment glob
        semantics used for request paths are inappropriate here.
        """
        return fnmatch.fnmatch(host.lower(), rule_host.lower())

    # ── Config file watcher ─────────────────────────────────────────

    def _start_watcher(self) -> None:
        """Start a daemon thread that polls the config file for changes."""
        thread = threading.Thread(
            target=self._watch_config, name="policy-config-watcher", daemon=True
        )
        thread.start()

    def _watch_config(self) -> None:
        """Poll the config file and reload when its mtime changes."""
        while True:
            time.sleep(CONFIG_POLL_INTERVAL)
            try:
                path = self._config_path
                if not os.path.isfile(path):
                    continue

                mtime = os.path.getmtime(path)
                if mtime != self._last_mtime:
                    logger.info("Config file changed — reloading.")
                    self._load_config()
            except OSError as exc:
                logger.error("Error watching config file: %s", exc)


# ── mitmproxy addon registration ────────────────────────────────────

def _resolve_config_path() -> str:
    """Determine the config path from the environment."""
    return os.environ.get(CONFIG_PATH_ENV, "") or DEFAULT_CONFIG_PATH


def _build_event_emitter() -> EventEmitter | None:
    """Construct a shared :class:`EventEmitter` from the environment.

    When ``SANDBOX_MITMPROXY_EVENTS`` is set (populated by
    ``gateway/entrypoint.sh`` before launching mitmdump), the addon
    writes one structured JSONL line per decision to that file.  When
    it is unset (typical in unit tests) we return ``None`` and the
    addon falls back to human-readable ``logger.info`` only.

    Failures are swallowed: if the events directory is missing or
    unwritable we log and keep going — structured emission is
    additive, never a gate on request handling.
    """
    path = os.environ.get(EVENTS_PATH_ENV, "")
    if not path:
        return None
    try:
        # Make sure the parent directory exists; in production the
        # bind-mount target ``/var/log/gateway/events/`` is present
        # because sandboxd pre-creates the host side, but in local
        # runs (e.g. ``make test-validators``) we want to be resilient.
        parent = os.path.dirname(path)
        if parent:
            os.makedirs(parent, exist_ok=True)
        return EventEmitter(path)
    except OSError as exc:
        logger.error(
            "Failed to open events file %s: %s — structured emission disabled",
            path,
            exc,
        )
        return None


addons = [PolicyAddon(_resolve_config_path(), _build_event_emitter())]
