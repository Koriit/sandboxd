"""
Unit tests for the sandbox policy enforcement mitmproxy addon.

Since mitmproxy is not available in the test environment, we mock
the mitmproxy.http module and test the addon logic in isolation.
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
import textwrap
import time
import types
from typing import Any
from unittest import mock

import pytest

# ── Mock mitmproxy module before importing the addon ────────────────
#
# The addon imports ``from mitmproxy import http``, which is only
# available inside the mitmproxy runtime.  We inject a lightweight
# fake module so we can import and test the addon locally.


class _FakeRequest:
    """Minimal stand-in for ``mitmproxy.net.http.Request``."""

    def __init__(
        self,
        method: str = "GET",
        host: str = "example.com",
        path: str = "/",
        pretty_host: str | None = None,
    ) -> None:
        self.method = method
        self.host = host
        self.path = path
        self.pretty_host = pretty_host or host


class _FakeResponse:
    """Minimal stand-in for ``mitmproxy.net.http.Response``."""

    def __init__(self, status_code: int = 200, content: bytes = b"", headers: dict[str, str] | None = None) -> None:
        self.status_code = status_code
        self.content = content
        self.headers = headers or {}

    @staticmethod
    def make(
        status_code: int,
        content: str | bytes = b"",
        headers: dict[str, str] | None = None,
    ) -> "_FakeResponse":
        if isinstance(content, str):
            content = content.encode("utf-8")
        return _FakeResponse(status_code, content, headers or {})


class _FakeHTTPFlow:
    """Minimal stand-in for ``mitmproxy.http.HTTPFlow``."""

    def __init__(self, request: _FakeRequest) -> None:
        self.request = request
        self.response: _FakeResponse | None = None


# Build a fake ``mitmproxy.http`` module and inject it into sys.modules
# so that ``from mitmproxy import http`` succeeds.
_fake_http = types.ModuleType("mitmproxy.http")
_fake_http.HTTPFlow = _FakeHTTPFlow  # type: ignore[attr-defined]
_fake_http.Response = _FakeResponse  # type: ignore[attr-defined]

_fake_mitmproxy = types.ModuleType("mitmproxy")
_fake_mitmproxy.http = _fake_http  # type: ignore[attr-defined]

sys.modules.setdefault("mitmproxy", _fake_mitmproxy)
sys.modules.setdefault("mitmproxy.http", _fake_http)

# Now we can safely import the addon.
# We need to bypass the module-level ``addons = [PolicyAddon(...)]``
# line which would try to create an addon with the default path.
# Patch the environment so the module-level init works harmlessly.

# Import the module — the module-level addons list will create an
# instance pointing at the default (non-existent) path, which triggers
# pass-through mode.  That's fine for tests.
import policy_addon as mod
from policy_addon import PolicyAddon


# ── Helpers ─────────────────────────────────────────────────────────


def _write_config(path: str, rules: list[dict[str, Any]]) -> None:
    """Write a policy config file."""
    with open(path, "w", encoding="utf-8") as fh:
        json.dump({"rules": rules}, fh)


def _make_addon(rules: list[dict[str, Any]]) -> PolicyAddon:
    """Create a PolicyAddon with the given rules written to a temp file."""
    fd, path = tempfile.mkstemp(suffix=".json")
    os.close(fd)
    _write_config(path, rules)
    addon = PolicyAddon(config_path=path)
    # Store path for later cleanup / modification.
    addon._test_config_path = path  # type: ignore[attr-defined]
    return addon


def _make_flow(
    method: str = "GET",
    host: str = "example.com",
    path: str = "/",
) -> _FakeHTTPFlow:
    """Create a fake HTTPFlow for testing."""
    return _FakeHTTPFlow(_FakeRequest(method=method, host=host, path=path))


# ── Tests ───────────────────────────────────────────────────────────


class TestAllowMatchingHost:
    def test_allow_matching_host(self) -> None:
        addon = _make_addon([
            {"host": "api.github.com", "methods": None, "paths": None},
        ])
        flow = _make_flow(host="api.github.com", path="/repos/foo")
        addon.request(flow)
        assert flow.response is None, "Allowed request should not set a response"


class TestDenyUnknownHost:
    def test_deny_unknown_host(self) -> None:
        addon = _make_addon([
            {"host": "api.github.com", "methods": None, "paths": None},
        ])
        flow = _make_flow(host="evil.com", path="/")
        addon.request(flow)
        assert flow.response is not None
        assert flow.response.status_code == 599
        body = json.loads(flow.response.content)
        assert body["reason"] == "host not in policy"


class TestMethodRestriction:
    def test_method_restriction(self) -> None:
        addon = _make_addon([
            {"host": "api.github.com", "methods": ["GET"], "paths": None},
        ])
        # GET should pass.
        flow_get = _make_flow(method="GET", host="api.github.com", path="/")
        addon.request(flow_get)
        assert flow_get.response is None

        # POST should be denied.
        flow_post = _make_flow(method="POST", host="api.github.com", path="/")
        addon.request(flow_post)
        assert flow_post.response is not None
        assert flow_post.response.status_code == 599
        body = json.loads(flow_post.response.content)
        assert "method POST not allowed" in body["reason"]


class TestPathRestriction:
    def test_path_restriction(self) -> None:
        addon = _make_addon([
            {"host": "api.github.com", "methods": None, "paths": ["/repos/", "/user/"]},
        ])
        # Allowed path prefix.
        flow_ok = _make_flow(host="api.github.com", path="/repos/foo")
        addon.request(flow_ok)
        assert flow_ok.response is None

        # Disallowed path.
        flow_bad = _make_flow(host="api.github.com", path="/admin/settings")
        addon.request(flow_bad)
        assert flow_bad.response is not None
        assert flow_bad.response.status_code == 599
        body = json.loads(flow_bad.response.content)
        assert "path /admin/settings not allowed" in body["reason"]


class TestWildcardHost:
    def test_wildcard_host(self) -> None:
        addon = _make_addon([
            {"host": "*.github.com", "methods": None, "paths": None},
        ])
        flow = _make_flow(host="api.github.com", path="/")
        addon.request(flow)
        assert flow.response is None, "Wildcard *.github.com should match api.github.com"

    def test_wildcard_does_not_match_root(self) -> None:
        addon = _make_addon([
            {"host": "*.github.com", "methods": None, "paths": None},
        ])
        flow = _make_flow(host="github.com", path="/")
        addon.request(flow)
        assert flow.response is not None, "*.github.com should not match github.com"
        assert flow.response.status_code == 599


class TestDenyResponseFormat:
    def test_deny_response_format(self) -> None:
        addon = _make_addon([
            {"host": "allowed.com", "methods": None, "paths": None},
        ])
        flow = _make_flow(host="evil.com", method="POST", path="/hack")
        addon.request(flow)
        assert flow.response is not None
        assert flow.response.status_code == 599
        body = json.loads(flow.response.content)
        assert body == {
            "error": "sandbox_policy_denied",
            "reason": "host not in policy",
            "host": "evil.com",
            "method": "POST",
            "path": "/hack",
        }
        assert flow.response.headers.get("Content-Type") == "application/json"


class TestConfigReload:
    def test_config_reload(self) -> None:
        addon = _make_addon([
            {"host": "old.com", "methods": None, "paths": None},
        ])

        # Initially old.com is allowed.
        flow1 = _make_flow(host="old.com")
        addon.request(flow1)
        assert flow1.response is None

        # new.com is denied.
        flow2 = _make_flow(host="new.com")
        addon.request(flow2)
        assert flow2.response is not None
        assert flow2.response.status_code == 599

        # Update the config file.
        config_path = addon._test_config_path  # type: ignore[attr-defined]
        # Ensure the mtime changes (filesystem resolution may be 1s).
        time.sleep(0.05)
        _write_config(config_path, [
            {"host": "new.com", "methods": None, "paths": None},
        ])

        # Trigger reload directly (don't wait for the watcher thread).
        addon._load_config()

        # Now new.com should be allowed.
        flow3 = _make_flow(host="new.com")
        addon.request(flow3)
        assert flow3.response is None

        # And old.com should be denied.
        flow4 = _make_flow(host="old.com")
        addon.request(flow4)
        assert flow4.response is not None
        assert flow4.response.status_code == 599


class TestHealthEndpoint:
    def test_health_endpoint(self) -> None:
        addon = _make_addon([
            {"host": "allowed.com", "methods": None, "paths": None},
        ])
        flow = _make_flow(host="anything.com", path="/__sandbox_health")
        addon.request(flow)
        assert flow.response is not None
        assert flow.response.status_code == 200
        body = json.loads(flow.response.content)
        assert body == {"status": "ok"}

    def test_health_endpoint_in_passthrough_mode(self) -> None:
        """Health endpoint works even with no config (pass-through mode)."""
        # Create addon with non-existent config → pass-through.
        addon = PolicyAddon(config_path="/nonexistent/path.json")
        flow = _make_flow(host="anything.com", path="/__sandbox_health")
        addon.request(flow)
        assert flow.response is not None
        assert flow.response.status_code == 200


class TestNullMethodsAllowsAll:
    def test_null_methods_allows_all(self) -> None:
        addon = _make_addon([
            {"host": "api.example.com", "methods": None, "paths": None},
        ])
        for method in ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"]:
            flow = _make_flow(method=method, host="api.example.com")
            addon.request(flow)
            assert flow.response is None, f"{method} should be allowed when methods is null"


class TestNullPathsAllowsAll:
    def test_null_paths_allows_all(self) -> None:
        addon = _make_addon([
            {"host": "api.example.com", "methods": None, "paths": None},
        ])
        for path in ["/", "/foo", "/bar/baz", "/deeply/nested/path"]:
            flow = _make_flow(host="api.example.com", path=path)
            addon.request(flow)
            assert flow.response is None, f"Path {path} should be allowed when paths is null"


class TestEmptyRulesDenyAll:
    def test_empty_rules_deny_all(self) -> None:
        addon = _make_addon([])
        flow = _make_flow(host="anything.com")
        addon.request(flow)
        assert flow.response is not None
        assert flow.response.status_code == 599

    def test_empty_rules_still_serves_health(self) -> None:
        addon = _make_addon([])
        flow = _make_flow(host="anything.com", path="/__sandbox_health")
        addon.request(flow)
        assert flow.response is not None
        assert flow.response.status_code == 200


class TestCaseInsensitiveHost:
    def test_case_insensitive_host(self) -> None:
        addon = _make_addon([
            {"host": "API.GitHub.Com", "methods": None, "paths": None},
        ])
        flow = _make_flow(host="api.github.com")
        addon.request(flow)
        assert flow.response is None, "Host matching should be case-insensitive"

    def test_case_insensitive_host_reverse(self) -> None:
        addon = _make_addon([
            {"host": "api.github.com", "methods": None, "paths": None},
        ])
        flow = _make_flow(host="API.GITHUB.COM")
        addon.request(flow)
        assert flow.response is None, "Host matching should be case-insensitive (uppercase request)"


class TestPassthroughMode:
    def test_no_config_allows_all(self) -> None:
        """When config file does not exist, all requests are allowed."""
        addon = PolicyAddon(config_path="/nonexistent/path.json")
        flow = _make_flow(host="anything.com", path="/any/path")
        addon.request(flow)
        assert flow.response is None, "Pass-through mode should allow all requests"


class TestCheckRequestDirect:
    """Test the _check_request method directly for edge cases."""

    def test_multiple_rules_first_match_wins(self) -> None:
        addon = _make_addon([
            {"host": "api.github.com", "methods": ["GET"], "paths": None},
            {"host": "api.github.com", "methods": ["POST"], "paths": None},
        ])
        # First rule matches — only GET allowed.
        allowed, reason = addon._check_request("api.github.com", "POST", "/")
        assert not allowed
        assert "method POST not allowed" in reason

    def test_path_prefix_matching(self) -> None:
        addon = _make_addon([
            {"host": "api.com", "methods": None, "paths": ["/v1/", "/v2/"]},
        ])
        allowed1, _ = addon._check_request("api.com", "GET", "/v1/users")
        assert allowed1

        allowed2, _ = addon._check_request("api.com", "GET", "/v2/data")
        assert allowed2

        allowed3, reason = addon._check_request("api.com", "GET", "/v3/other")
        assert not allowed3
        assert "path /v3/other not allowed" in reason

    def test_method_case_insensitive(self) -> None:
        """Methods in rules are compared case-insensitively."""
        addon = _make_addon([
            {"host": "api.com", "methods": ["get", "post"], "paths": None},
        ])
        allowed, _ = addon._check_request("api.com", "GET", "/")
        assert allowed
        allowed2, _ = addon._check_request("api.com", "Post", "/")
        assert allowed2


class TestMatchHost:
    def test_exact_match(self) -> None:
        assert PolicyAddon._match_host("example.com", "example.com")

    def test_wildcard_match(self) -> None:
        assert PolicyAddon._match_host("sub.example.com", "*.example.com")

    def test_wildcard_no_match_bare_domain(self) -> None:
        assert not PolicyAddon._match_host("example.com", "*.example.com")

    def test_case_insensitive(self) -> None:
        assert PolicyAddon._match_host("Example.COM", "example.com")

    def test_no_match(self) -> None:
        assert not PolicyAddon._match_host("other.com", "example.com")


class TestConfigFileWatcher:
    def test_watcher_thread_is_daemon(self) -> None:
        """The config watcher thread should be a daemon so it doesn't
        block process exit."""
        addon = _make_addon([])
        import threading

        watcher_threads = [
            t for t in threading.enumerate() if t.name == "policy-config-watcher"
        ]
        # At least one watcher should exist and be a daemon.
        assert any(t.daemon for t in watcher_threads)

    def test_load_config_handles_invalid_json(self) -> None:
        """Invalid JSON in config file should not crash — existing rules
        should be preserved."""
        addon = _make_addon([
            {"host": "good.com", "methods": None, "paths": None},
        ])

        # Write invalid JSON to the config file.
        config_path = addon._test_config_path  # type: ignore[attr-defined]
        with open(config_path, "w") as fh:
            fh.write("NOT VALID JSON {{{")

        addon._load_config()

        # Rules should still be the original ones.
        flow = _make_flow(host="good.com")
        addon.request(flow)
        assert flow.response is None, "Original rules should be preserved after bad config reload"

    def test_config_file_appears_later(self) -> None:
        """If config file didn't exist at startup, loading it later works."""
        fd, path = tempfile.mkstemp(suffix=".json")
        os.close(fd)
        os.unlink(path)  # Remove so it doesn't exist at startup.

        addon = PolicyAddon(config_path=path)
        assert addon._passthrough is True

        # Now create the file.
        _write_config(path, [
            {"host": "new.com", "methods": None, "paths": None},
        ])
        addon._load_config()
        assert addon._passthrough is False

        flow = _make_flow(host="new.com")
        addon.request(flow)
        assert flow.response is None
