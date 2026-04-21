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
        port: int = 443,
        pretty_host: str | None = None,
    ) -> None:
        self.method = method
        self.host = host
        self.path = path
        # `port` mirrors mitmproxy's `request.port` — the destination
        # L4 port.  M10-S1 rules match on `(host, port)`, so every test
        # flow must carry one.  443 is the default for the HTTPS path
        # we're actually MITM-ing in production.
        self.port = port
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


# A filter object that permits every (method, path) pair — useful
# shorthand for tests that only care about host matching.
ANY_FILTER: dict[str, Any] = {"method": "ANY", "path": "/*"}


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
    port: int = 443,
) -> _FakeHTTPFlow:
    """Create a fake HTTPFlow for testing."""
    return _FakeHTTPFlow(
        _FakeRequest(method=method, host=host, path=path, port=port)
    )


# ── Tests ───────────────────────────────────────────────────────────


class TestAllowMatchingHost:
    def test_allow_matching_host(self) -> None:
        addon = _make_addon([
            {"host": "api.github.com", "port": 443, "filters": [ANY_FILTER]},
        ])
        flow = _make_flow(host="api.github.com", path="/repos/foo")
        addon.request(flow)
        assert flow.response is None, "Allowed request should not set a response"


class TestDenyUnknownHost:
    def test_deny_unknown_host(self) -> None:
        addon = _make_addon([
            {"host": "api.github.com", "port": 443, "filters": [ANY_FILTER]},
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
            {"host": "api.github.com", "port": 443, "filters": [
                {"method": "GET", "path": "/*"},
            ]},
        ])
        # GET should pass.
        flow_get = _make_flow(method="GET", host="api.github.com", path="/")
        addon.request(flow_get)
        assert flow_get.response is None

        # POST should be denied — no filter matches POST.
        flow_post = _make_flow(method="POST", host="api.github.com", path="/")
        addon.request(flow_post)
        assert flow_post.response is not None
        assert flow_post.response.status_code == 599
        body = json.loads(flow_post.response.content)
        assert body["reason"] == "no filter matched POST /"


class TestPathRestriction:
    def test_path_restriction(self) -> None:
        addon = _make_addon([
            {"host": "api.github.com", "port": 443, "filters": [
                {"method": "ANY", "path": "/repos/*"},
                {"method": "ANY", "path": "/user/*"},
            ]},
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
        assert body["reason"] == "no filter matched GET /admin/settings"


class TestWildcardHost:
    def test_wildcard_host(self) -> None:
        addon = _make_addon([
            {"host": "*.github.com", "port": 443, "filters": [ANY_FILTER]},
        ])
        flow = _make_flow(host="api.github.com", path="/")
        addon.request(flow)
        assert flow.response is None, "Wildcard *.github.com should match api.github.com"

    def test_wildcard_does_not_match_root(self) -> None:
        addon = _make_addon([
            {"host": "*.github.com", "port": 443, "filters": [ANY_FILTER]},
        ])
        flow = _make_flow(host="github.com", path="/")
        addon.request(flow)
        assert flow.response is not None, "*.github.com should not match github.com"
        assert flow.response.status_code == 599


class TestDenyResponseFormat:
    def test_deny_response_format(self) -> None:
        addon = _make_addon([
            {"host": "allowed.com", "port": 443, "filters": [ANY_FILTER]},
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
            "port": 443,
            "method": "POST",
            "path": "/hack",
        }
        assert flow.response.headers.get("Content-Type") == "application/json"


class TestConfigReload:
    def test_config_reload(self) -> None:
        addon = _make_addon([
            {"host": "old.com", "port": 443, "filters": [ANY_FILTER]},
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
            {"host": "new.com", "port": 443, "filters": [ANY_FILTER]},
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
            {"host": "allowed.com", "port": 443, "filters": [ANY_FILTER]},
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


class TestAnyMethodAllowsAll:
    def test_any_method_allows_all(self) -> None:
        addon = _make_addon([
            {"host": "api.example.com", "port": 443, "filters": [ANY_FILTER]},
        ])
        for method in ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"]:
            flow = _make_flow(method=method, host="api.example.com")
            addon.request(flow)
            assert flow.response is None, f"{method} should be allowed when filter method is ANY"


class TestWildcardPathAllowsAll:
    def test_wildcard_path_allows_all(self) -> None:
        addon = _make_addon([
            {"host": "api.example.com", "port": 443, "filters": [ANY_FILTER]},
        ])
        for path in ["/", "/foo", "/bar/baz", "/deeply/nested/path"]:
            flow = _make_flow(host="api.example.com", path=path)
            addon.request(flow)
            assert flow.response is None, f"Path {path} should be allowed when filter path is /*"


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
            {"host": "API.GitHub.Com", "port": 443, "filters": [ANY_FILTER]},
        ])
        flow = _make_flow(host="api.github.com")
        addon.request(flow)
        assert flow.response is None, "Host matching should be case-insensitive"

    def test_case_insensitive_host_reverse(self) -> None:
        addon = _make_addon([
            {"host": "api.github.com", "port": 443, "filters": [ANY_FILTER]},
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


class TestLegacyPreM9S10ShapeIsRejected:
    """Regression guard against the M9-S10 wire-format drift.

    Pre-M9-S10, the addon accepted top-level `methods` / `paths` arrays on
    each rule and treated both being absent/null as "allow every request on
    this host".  Post-M9-S10, the contract is strict `filters = [{method,
    path}, ...]` pair matching.

    If a stale addon (old code) is paired with a new-shape config file —
    exactly what happened in CI when the gateway image wasn't rebuilt after
    the addon rewrite — every request to a matched host was silently
    allowed, defeating all level-3 HTTP filtering.  The failing E2E tests
    (`test_level3_method_restriction`, `test_level3_path_restriction`)
    surfaced the drift by observing that supposedly-blocked requests
    reached upstream and came back as 404 rather than the expected 599.

    The fix lives in the Makefile (rebuild on source change), but this
    test pins the runtime behavior: feeding the addon a legacy-shape
    rule object MUST NOT silently allow traffic — missing `filters`
    means no match, which is a 599 deny.
    """

    def test_legacy_shape_with_null_method_and_path_denies(self) -> None:
        """Old shape `{host, methods: null, paths: null}` denies."""
        addon = _make_addon([
            {"host": "httpbin.org", "methods": None, "paths": None},
        ])
        flow = _make_flow(method="GET", host="httpbin.org", path="/anything")
        addon.request(flow)
        assert flow.response is not None, (
            "Legacy-shape rule must not silently pass — missing `filters` "
            "means no filter matched, which is deny."
        )
        assert flow.response.status_code == 599

    def test_legacy_shape_with_method_and_path_arrays_denies(self) -> None:
        """Old shape `{host, methods: [...], paths: [...]}` denies."""
        addon = _make_addon([
            {
                "host": "httpbin.org",
                "methods": ["GET"],
                "paths": ["/api/"],
            },
        ])
        flow = _make_flow(method="GET", host="httpbin.org", path="/api/thing")
        addon.request(flow)
        assert flow.response is not None
        assert flow.response.status_code == 599

    def test_failing_e2e_method_restriction_denies_post(self) -> None:
        """Replica of `test_level3_method_restriction`.

        Policy `{httpbin.org:443, filters: [{GET, /*}]}` must deny POST.
        This is the exact shape sandboxd writes for the E2E test; it
        exists here so a future addon regression is caught in <1 second
        instead of a ~3-minute E2E round-trip.
        """
        addon = _make_addon([
            {
                "host": "httpbin.org",
                "port": 443,
                "filters": [{"method": "GET", "path": "/*"}],
            },
        ])
        flow = _make_flow(method="POST", host="httpbin.org", path="/post")
        addon.request(flow)
        assert flow.response is not None
        assert flow.response.status_code == 599

    def test_failing_e2e_path_restriction_denies_other_path(self) -> None:
        """Replica of `test_level3_path_restriction`.

        Policy `{httpbin.org:443, filters: [{ANY, /api/*}]}` must deny a
        request to `/other/path`.
        """
        addon = _make_addon([
            {
                "host": "httpbin.org",
                "port": 443,
                "filters": [{"method": "ANY", "path": "/api/*"}],
            },
        ])
        flow = _make_flow(method="GET", host="httpbin.org", path="/other/path")
        addon.request(flow)
        assert flow.response is not None
        assert flow.response.status_code == 599


class TestPairMatching:
    """(method, path) pairs must match together — not cartesian product.

    Under the pre-M9-S10 shape, two independent lists `methods=[GET, POST]`
    and `paths=[/a, /b]` would permit the cartesian product {GET /a, GET /b,
    POST /a, POST /b}.  The new shape expresses the mixed pairs directly:
    `filters=[{GET /a}, {POST /b}]` means *exactly* those two pairs.
    """

    def test_mixed_pairs_are_not_cartesian(self) -> None:
        """`GET /foo` and `POST /bar` must NOT also allow `POST /foo` or
        `GET /bar`."""
        addon = _make_addon([
            {"host": "api.com", "port": 443, "filters": [
                {"method": "GET", "path": "/foo"},
                {"method": "POST", "path": "/bar"},
            ]},
        ])

        # Declared pairs succeed.
        flow_get_foo = _make_flow(method="GET", host="api.com", path="/foo")
        addon.request(flow_get_foo)
        assert flow_get_foo.response is None, "GET /foo should be allowed"

        flow_post_bar = _make_flow(method="POST", host="api.com", path="/bar")
        addon.request(flow_post_bar)
        assert flow_post_bar.response is None, "POST /bar should be allowed"

        # Cross pairs (cartesian product) must be denied.
        flow_post_foo = _make_flow(method="POST", host="api.com", path="/foo")
        addon.request(flow_post_foo)
        assert flow_post_foo.response is not None
        assert flow_post_foo.response.status_code == 599
        body_pf = json.loads(flow_post_foo.response.content)
        assert body_pf["reason"] == "no filter matched POST /foo"

        flow_get_bar = _make_flow(method="GET", host="api.com", path="/bar")
        addon.request(flow_get_bar)
        assert flow_get_bar.response is not None
        assert flow_get_bar.response.status_code == 599
        body_gb = json.loads(flow_get_bar.response.content)
        assert body_gb["reason"] == "no filter matched GET /bar"


class TestFnmatchGlobs:
    """Filter paths support fnmatch-style globs (*, ?, [...]).

    NOTE (M10-S1 Commit 1): these tests still assert the old fnmatch
    behaviour where `*` crosses `/`.  Commit 2 renames this class to
    ``TestPerSegmentGlob`` and inverts the expected semantics to match
    the new per-segment matcher.
    """

    def test_star_matches_single_segment(self) -> None:
        addon = _make_addon([
            {"host": "api.com", "port": 443, "filters": [
                {"method": "GET", "path": "/repos/*"},
            ]},
        ])
        # `*` in fnmatch matches any characters including slashes.
        flow_ok = _make_flow(host="api.com", path="/repos/foo")
        addon.request(flow_ok)
        assert flow_ok.response is None

        flow_deeper = _make_flow(host="api.com", path="/repos/foo/commits")
        addon.request(flow_deeper)
        assert flow_deeper.response is None

    def test_question_mark_matches_single_char(self) -> None:
        addon = _make_addon([
            {"host": "api.com", "port": 443, "filters": [
                {"method": "GET", "path": "/v?/users"},
            ]},
        ])
        flow_ok = _make_flow(host="api.com", path="/v1/users")
        addon.request(flow_ok)
        assert flow_ok.response is None

        flow_bad = _make_flow(host="api.com", path="/v10/users")
        addon.request(flow_bad)
        assert flow_bad.response is not None
        assert flow_bad.response.status_code == 599


class TestMultipleRulesCompose:
    """Multiple rules for the same host compose — any matching filter in any
    matching rule permits the request."""

    def test_two_rules_same_host_compose(self) -> None:
        addon = _make_addon([
            {"host": "api.github.com", "port": 443, "filters": [
                {"method": "GET", "path": "/*"},
            ]},
            {"host": "api.github.com", "port": 443, "filters": [
                {"method": "POST", "path": "/*"},
            ]},
        ])
        # GET allowed by rule 1.
        allowed_get, _ = addon._check_request("api.github.com", 443, "GET", "/")
        assert allowed_get

        # POST allowed by rule 2 (must not be blocked by rule 1's filters).
        allowed_post, _ = addon._check_request("api.github.com", 443, "POST", "/")
        assert allowed_post


class TestCheckRequestDirect:
    """Test the _check_request method directly for edge cases."""

    def test_path_glob_matching(self) -> None:
        addon = _make_addon([
            {"host": "api.com", "port": 443, "filters": [
                {"method": "ANY", "path": "/v1/*"},
                {"method": "ANY", "path": "/v2/*"},
            ]},
        ])
        allowed1, _ = addon._check_request("api.com", 443, "GET", "/v1/users")
        assert allowed1

        allowed2, _ = addon._check_request("api.com", 443, "GET", "/v2/data")
        assert allowed2

        allowed3, reason = addon._check_request("api.com", 443, "GET", "/v3/other")
        assert not allowed3
        assert reason == "no filter matched GET /v3/other"

    def test_method_case_insensitive(self) -> None:
        """Request methods are uppercased before comparison."""
        addon = _make_addon([
            {"host": "api.com", "port": 443, "filters": [
                {"method": "GET", "path": "/*"},
                {"method": "POST", "path": "/*"},
            ]},
        ])
        allowed, _ = addon._check_request("api.com", 443, "GET", "/")
        assert allowed
        allowed2, _ = addon._check_request("api.com", 443, "Post", "/")
        assert allowed2

    def test_empty_filters_list_denies(self) -> None:
        """A rule with an empty `filters` list matches the host but no
        filter matches, so every request is denied with 'no filter matched'."""
        addon = _make_addon([
            {"host": "api.com", "port": 443, "filters": []},
        ])
        allowed, reason = addon._check_request("api.com", 443, "GET", "/")
        assert not allowed
        assert reason == "no filter matched GET /"


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


class TestFilterMatches:
    """Direct tests of the `_filter_matches` helper."""

    def test_any_method_wildcard(self) -> None:
        flt = {"method": "ANY", "path": "/foo"}
        assert PolicyAddon._filter_matches(flt, "GET", "/foo")
        assert PolicyAddon._filter_matches(flt, "POST", "/foo")
        assert PolicyAddon._filter_matches(flt, "DELETE", "/foo")

    def test_method_must_match_exactly(self) -> None:
        flt = {"method": "GET", "path": "/foo"}
        assert PolicyAddon._filter_matches(flt, "GET", "/foo")
        assert not PolicyAddon._filter_matches(flt, "POST", "/foo")

    def test_path_fnmatch(self) -> None:
        flt = {"method": "ANY", "path": "/repos/*"}
        assert PolicyAddon._filter_matches(flt, "GET", "/repos/foo")
        assert not PolicyAddon._filter_matches(flt, "GET", "/users/foo")

    def test_empty_fields_reject(self) -> None:
        """A filter with a missing method or path rejects every request."""
        assert not PolicyAddon._filter_matches({"method": "", "path": "/foo"}, "GET", "/foo")
        assert not PolicyAddon._filter_matches({"method": "GET", "path": ""}, "GET", "/foo")
        assert not PolicyAddon._filter_matches({}, "GET", "/foo")


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
            {"host": "good.com", "port": 443, "filters": [ANY_FILTER]},
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
            {"host": "new.com", "port": 443, "filters": [ANY_FILTER]},
        ])
        addon._load_config()
        assert addon._passthrough is False

        flow = _make_flow(host="new.com")
        addon.request(flow)
        assert flow.response is None
