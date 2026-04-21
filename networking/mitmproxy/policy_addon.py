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
  mismatch skips the rule — the request is denied with
  `"host not in policy"` if no other rule matches.  This lets policies
  express "HTTP to api.example.com:443 only, nothing on :8443" without
  a separate deny rule.  Added in M10-S1 — prior versions omitted the
  field.
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
"""

from __future__ import annotations

import fnmatch
import json
import logging
import os
import threading
import time
from typing import Any

from mitmproxy import http

logger = logging.getLogger("policy_addon")

# Environment variable for config file path (set by sandboxd).
CONFIG_PATH_ENV = "SANDBOX_MITMPROXY_CONFIG"
# Default config file location inside the gateway container.
DEFAULT_CONFIG_PATH = "/tmp/mitmproxy/policy.json"
# How often (seconds) to poll the config file for changes.
CONFIG_POLL_INTERVAL = 5
# Internal health-check endpoint.
HEALTH_PATH = "/__sandbox_health"


class PolicyAddon:
    """Mitmproxy addon that enforces sandbox network policy.

    Loads policy rules from a JSON config file and validates each HTTP
    request against them.  Denied requests receive an HTTP 599 response.
    If no config file exists, all requests are allowed (pass-through mode).
    """

    def __init__(self, config_path: str | None = None) -> None:
        self._config_path: str = (
            config_path
            or os.environ.get(CONFIG_PATH_ENV, "")
            or DEFAULT_CONFIG_PATH
        )
        self._rules: list[dict[str, Any]] = []
        self._passthrough: bool = True
        self._lock = threading.Lock()
        self._last_mtime: float = 0.0

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

        # Pass-through mode: no config loaded → allow everything.
        if self._passthrough:
            logger.info(
                "[ALLOW] %s %s:%d%s (pass-through)", method, host, port, path
            )
            return

        allowed, reason = self._check_request(host, port, method, path)
        if allowed:
            logger.info("[ALLOW] %s %s:%d%s", method, host, port, path)
        else:
            logger.warning(
                "[DENY] %s %s:%d%s (%s)", method, host, port, path, reason
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
        other rule matches, the request is denied with "host not in
        policy".

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
        # filter pair that matches (method, path).
        matched_any_rule = False
        for rule in rules:
            rule_host = rule.get("host", "")
            if not self._match_host(host, rule_host):
                continue
            # v2 schema: rule must carry a `port` and it must equal the
            # request's destination port.  A missing or non-integer
            # `port` means this is a legacy/malformed rule — skip it
            # rather than silently allowing.
            rule_port = rule.get("port")
            if not isinstance(rule_port, int) or rule_port != port:
                continue
            matched_any_rule = True

            for flt in rule.get("filters", []):
                if self._filter_matches(flt, request_method, path):
                    return True, ""

        if not matched_any_rule:
            return False, "host not in policy"

        return False, f"no filter matched {method} {path}"

    @staticmethod
    def _filter_matches(flt: dict[str, Any], method: str, path: str) -> bool:
        """Return True iff `flt` permits this (method, path) pair.

        `flt` is a `{method, path}` object from the config.  `method` must
        equal the filter's method (uppercase) or the filter's method must
        be the wildcard marker `ANY`.  `path` is matched against the
        filter's path with `fnmatch`.
        """
        flt_method = str(flt.get("method", "")).upper()
        flt_path = str(flt.get("path", ""))
        if not flt_method or not flt_path:
            return False
        if flt_method != "ANY" and flt_method != method:
            return False
        return fnmatch.fnmatchcase(path, flt_path)

    @staticmethod
    def _match_host(host: str, rule_host: str) -> bool:
        """Match a request host against a rule host pattern.

        Supports exact match and wildcard patterns like ``*.example.com``.
        Matching is case-insensitive.
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


addons = [PolicyAddon(_resolve_config_path())]
