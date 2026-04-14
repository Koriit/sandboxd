"""
Sandbox policy enforcement addon for mitmproxy.

Validates HTTP requests against policy rules loaded from a JSON config file.
Denied requests receive HTTP 599 response with a JSON body describing the
reason for denial.

When no config file is present, operates in pass-through mode (allow all)
for backwards compatibility.

Config format (from sandboxd MitmproxyConfig):

    {
      "rules": [
        {"host": "api.github.com", "methods": ["GET", "POST"], "paths": ["/repos/", "/user/"]},
        {"host": "registry.npmjs.org", "methods": null, "paths": null}
      ]
    }

- methods: null → all methods allowed
- paths: null → all paths allowed
- methods: ["GET"] → only GET allowed
- paths: ["/api/"] → path must start with one of the listed prefixes
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
            logger.info("[ALLOW] %s %s%s (pass-through)", method, host, path)
            return

        allowed, reason = self._check_request(host, method, path)
        if allowed:
            logger.info("[ALLOW] %s %s%s", method, host, path)
        else:
            logger.warning("[DENY] %s %s%s (%s)", method, host, path, reason)
            flow.response = http.Response.make(
                599,
                json.dumps({
                    "error": "sandbox_policy_denied",
                    "reason": reason,
                    "host": host,
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
        self, host: str, method: str, path: str
    ) -> tuple[bool, str]:
        """Check a request against the loaded rules.

        Returns (allowed, reason).  *reason* is meaningful only when
        *allowed* is False.
        """
        with self._lock:
            rules = list(self._rules)

        # Find a matching rule by host.
        matching_rule: dict[str, Any] | None = None
        for rule in rules:
            rule_host = rule.get("host", "")
            if self._match_host(host, rule_host):
                matching_rule = rule
                break

        if matching_rule is None:
            return False, "host not in policy"

        # Check method constraint.
        allowed_methods = matching_rule.get("methods")
        if allowed_methods is not None:
            upper_methods = [m.upper() for m in allowed_methods]
            if method.upper() not in upper_methods:
                return False, f"method {method} not allowed"

        # Check path constraint.
        allowed_paths = matching_rule.get("paths")
        if allowed_paths is not None:
            if not any(path.startswith(prefix) for prefix in allowed_paths):
                return False, f"path {path} not allowed"

        return True, ""

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
