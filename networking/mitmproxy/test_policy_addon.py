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
#
# The path is ``/**`` (recursive wildcard) rather than ``/*`` because
# under the v2 per-segment glob semantics ``*`` does not cross ``/`` —
# ``/*`` alone matches a single path segment (``/foo`` but not
# ``/foo/bar``).  ``/**`` is the "any path" pattern.
ANY_FILTER: dict[str, Any] = {"method": "ANY", "path": "/**"}


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
    """Regression guard against wire-format drift across schema flips.

    Two historical hazards are pinned here:

    1. **Pre-M9-S10 shape** — the addon accepted top-level ``methods``
       / ``paths`` arrays on each rule and treated both being
       absent/null as "allow every request on this host".  Post-M9-S10,
       the contract is strict ``filters = [{method, path}, ...]`` pair
       matching.  A stale addon paired with a new-shape config file
       (exactly what happened in CI when the gateway image wasn't
       rebuilt after the addon rewrite) silently allowed every request
       to a matched host, defeating all level-3 HTTP filtering.  The
       failing E2E tests (``test_level3_method_restriction``,
       ``test_level3_path_restriction``) surfaced the drift by
       observing supposedly-blocked requests reaching upstream as 404
       rather than the expected 599.

    2. **Missing-port (pre-M10-S1)** — v1 rules had no ``port`` field;
       v2 treats the field as mandatory.  A v1-shape rule paired with
       a v2 addon must deny, not silently allow — a rule without an
       integer ``port`` is skipped by ``_check_request``.

    The fix for #1 lives in the Makefile (rebuild on source change);
    #2 lives in the addon's port-integer check.  This class pins the
    runtime behaviour — feeding the addon any legacy-shape rule MUST
    NOT silently allow traffic.
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

    def test_v1_rule_without_port_denies(self) -> None:
        """v1-shape rule (no ``port`` field) must deny every request.

        This is the M10-S1 analogue of the M9-S10 legacy-shape guard:
        if a v2 addon is fed a v1 config file, the port check short-
        circuits the rule-walk and every request falls through to
        "host not in policy".
        """
        addon = _make_addon([
            {
                "host": "httpbin.org",
                "filters": [{"method": "GET", "path": "/*"}],
            },
        ])
        flow = _make_flow(method="GET", host="httpbin.org", path="/anything")
        addon.request(flow)
        assert flow.response is not None, (
            "v1 rule without `port` must not silently pass — missing port "
            "means no rule matched, which is deny."
        )
        assert flow.response.status_code == 599
        body = json.loads(flow.response.content)
        assert body["reason"] == "host not in policy"

    def test_v1_rule_with_null_port_denies(self) -> None:
        """Explicit ``port: null`` is treated the same as missing."""
        addon = _make_addon([
            {
                "host": "httpbin.org",
                "port": None,
                "filters": [{"method": "GET", "path": "/*"}],
            },
        ])
        flow = _make_flow(method="GET", host="httpbin.org", path="/anything")
        addon.request(flow)
        assert flow.response is not None
        assert flow.response.status_code == 599

    def test_v1_rule_with_string_port_denies(self) -> None:
        """A ``port`` field of the wrong type (stringly-typed config)
        must also deny — the check is ``isinstance(rule_port, int)``."""
        addon = _make_addon([
            {
                "host": "httpbin.org",
                "port": "443",
                "filters": [{"method": "GET", "path": "/*"}],
            },
        ])
        flow = _make_flow(method="GET", host="httpbin.org", path="/anything")
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


class TestPortMatching:
    """Rule identity is ``(host, port)``: a port mismatch denies.

    Introduced in M10-S1.  The addon reads ``flow.request.port`` and
    compares against the rule's ``port`` field before walking its
    ``filters``.  A request whose destination port differs from every
    matching-host rule is denied — the deny reason distinguishes the
    port-miss case from a genuine host-miss so operators reading
    ``sandbox events --decision=deny`` can tell a missing-port policy
    entry apart from a missing-host one.
    """

    def test_matching_host_wrong_port_denies(self) -> None:
        """Rule for `(httpbin.org, 443)` must deny a request to
        `httpbin.org:8443`, even with a filter that permits the
        `(method, path)` pair.  The deny reason must call out the
        port mismatch rather than pretending the host is unknown —
        this is the M10-S2 deny-event discovery signal."""
        addon = _make_addon([
            {"host": "httpbin.org", "port": 443, "filters": [ANY_FILTER]},
        ])
        flow = _make_flow(host="httpbin.org", path="/anything", port=8443)
        addon.request(flow)
        assert flow.response is not None, (
            "Rule port is 443 but request port is 8443 — must deny."
        )
        assert flow.response.status_code == 599
        body = json.loads(flow.response.content)
        assert body["reason"] == "host matched but port 8443 not in policy"
        assert body["port"] == 8443

    def test_multiple_rules_same_host_different_ports(self) -> None:
        """Two rules for the same host but different ports select by
        the request's port; filters from non-selected rules do not
        contribute."""
        addon = _make_addon([
            {"host": "api.com", "port": 443, "filters": [
                {"method": "GET", "path": "/**"},
            ]},
            {"host": "api.com", "port": 8443, "filters": [
                {"method": "POST", "path": "/**"},
            ]},
        ])
        # :443 permits GET; POST must deny (rule for :8443 can't help).
        flow_get = _make_flow(method="GET", host="api.com", path="/x", port=443)
        addon.request(flow_get)
        assert flow_get.response is None, "GET to api.com:443 should pass (rule 1)"

        flow_post_443 = _make_flow(
            method="POST", host="api.com", path="/x", port=443
        )
        addon.request(flow_post_443)
        assert flow_post_443.response is not None, (
            "POST to api.com:443 must deny — rule 2's filters only apply to :8443"
        )
        assert flow_post_443.response.status_code == 599
        body_post = json.loads(flow_post_443.response.content)
        # Host+port did match rule 1, so this is a filter-miss (not host-miss).
        assert body_post["reason"] == "no filter matched POST /x"

        # :8443 permits POST symmetrically.
        flow_post_8443 = _make_flow(
            method="POST", host="api.com", path="/x", port=8443
        )
        addon.request(flow_post_8443)
        assert flow_post_8443.response is None, (
            "POST to api.com:8443 should pass (rule 2)"
        )


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


class TestPerSegmentGlob:
    """Filter paths use a per-segment glob (M10-S1 v2 semantics).

    - ``?``  matches exactly one non-``/`` character.
    - ``*``  matches zero or more non-``/`` characters — within a
             single path segment, never crossing ``/``.
    - ``**`` matches zero or more characters *including* ``/`` —
             the recursive wildcard that spans segments.
    - All other characters are literal (case-sensitive, anchored
      full-path match).

    This is a deliberate tightening of the pre-v2 ``fnmatch``
    semantics — ``/api/*`` used to match ``/api/v1/users`` and now
    does not.  Operators migrating policies must review path filters
    during the v1→v2 rewrite.  The spec at
    ``.tasks/specs/2026-04-21-port-explicit-policies-presets-observability-design.md``
    (lines 221-243) is authoritative.
    """

    def test_star_does_not_cross_slash(self) -> None:
        """The single-star metachar must not match across ``/``.

        A pattern like ``/repos/*`` permits exactly one additional
        segment after ``/repos``.  A deeper path must fail — this is
        the concrete safety property that motivated the v1→v2
        matcher flip (``github-pr`` preset could be bypassed with
        ``/pulls/PR/attacker-crafted-subpath``).
        """
        addon = _make_addon([
            {"host": "api.com", "port": 443, "filters": [
                {"method": "GET", "path": "/repos/*"},
            ]},
        ])
        # One segment after `/repos` — allowed.
        flow_ok = _make_flow(host="api.com", path="/repos/foo")
        addon.request(flow_ok)
        assert flow_ok.response is None, "/repos/* must match /repos/foo"

        # Two segments after `/repos` — denied under v2.
        flow_deeper = _make_flow(host="api.com", path="/repos/foo/commits")
        addon.request(flow_deeper)
        assert flow_deeper.response is not None, (
            "/repos/* must NOT match /repos/foo/commits under per-segment glob"
        )
        assert flow_deeper.response.status_code == 599

    def test_star_matches_zero_chars_within_segment(self) -> None:
        """``*`` matches the empty string within a segment."""
        addon = _make_addon([
            {"host": "api.com", "port": 443, "filters": [
                {"method": "GET", "path": "/api/*"},
            ]},
        ])
        # Exactly `/api/` — empty segment after the slash, matches `*`
        # against zero characters.
        flow = _make_flow(host="api.com", path="/api/")
        addon.request(flow)
        assert flow.response is None, "/api/* must match /api/ (empty trailing segment)"

    def test_double_star_crosses_segments(self) -> None:
        """``**`` spans ``/`` — the recursive wildcard."""
        addon = _make_addon([
            {"host": "api.com", "port": 443, "filters": [
                {"method": "GET", "path": "/api/**"},
            ]},
        ])
        # Zero trailing segments: the pattern still needs the literal
        # trailing ``/`` so plain ``/api`` (no slash) must not match.
        flow_no_slash = _make_flow(host="api.com", path="/api")
        addon.request(flow_no_slash)
        assert flow_no_slash.response is not None, (
            "/api/** requires the literal trailing /, so /api (no slash) must deny"
        )
        assert flow_no_slash.response.status_code == 599

        # `/api/` — `**` matches the empty remainder.
        flow_slash = _make_flow(host="api.com", path="/api/")
        addon.request(flow_slash)
        assert flow_slash.response is None, "/api/** must match /api/"

        # One segment and deeper — both allowed.
        for path in ["/api/users", "/api/v1/users", "/api/a/b/c/d"]:
            flow = _make_flow(host="api.com", path=path)
            addon.request(flow)
            assert flow.response is None, f"/api/** must match {path}"

    def test_question_mark_matches_single_non_slash_char(self) -> None:
        """``?`` is a single non-``/`` character."""
        addon = _make_addon([
            {"host": "api.com", "port": 443, "filters": [
                {"method": "GET", "path": "/v?/users"},
            ]},
        ])
        flow_ok = _make_flow(host="api.com", path="/v1/users")
        addon.request(flow_ok)
        assert flow_ok.response is None

        # Two characters — rejected.
        flow_two = _make_flow(host="api.com", path="/v10/users")
        addon.request(flow_two)
        assert flow_two.response is not None
        assert flow_two.response.status_code == 599

        # Zero characters — rejected (``?`` requires exactly one).
        flow_zero = _make_flow(host="api.com", path="/v/users")
        addon.request(flow_zero)
        assert flow_zero.response is not None
        assert flow_zero.response.status_code == 599

    def test_literals_are_case_sensitive(self) -> None:
        """Path matching is case-sensitive (unlike host matching)."""
        addon = _make_addon([
            {"host": "api.com", "port": 443, "filters": [
                {"method": "GET", "path": "/API/users"},
            ]},
        ])
        flow_lower = _make_flow(host="api.com", path="/api/users")
        addon.request(flow_lower)
        assert flow_lower.response is not None, (
            "/API/users must not match /api/users (path is case-sensitive)"
        )
        assert flow_lower.response.status_code == 599

    def test_pattern_is_anchored(self) -> None:
        """Patterns match the full path — not a prefix."""
        addon = _make_addon([
            {"host": "api.com", "port": 443, "filters": [
                {"method": "GET", "path": "/exact"},
            ]},
        ])
        # Exact match.
        flow_exact = _make_flow(host="api.com", path="/exact")
        addon.request(flow_exact)
        assert flow_exact.response is None

        # Trailing slash — not the same path.
        flow_trailing = _make_flow(host="api.com", path="/exact/")
        addon.request(flow_trailing)
        assert flow_trailing.response is not None

        # Prefix — rejected.
        flow_prefix = _make_flow(host="api.com", path="/exactly")
        addon.request(flow_prefix)
        assert flow_prefix.response is not None

    def test_regex_metacharacters_are_literal(self) -> None:
        """Regex specials (``.``, ``+``, ``(`` ...) in a pattern must
        be literal — the matcher is a glob, not a regex."""
        addon = _make_addon([
            {"host": "api.com", "port": 443, "filters": [
                {"method": "GET", "path": "/api.v1/users"},
            ]},
        ])
        # The literal ``.`` must match only itself, not "any char".
        flow_ok = _make_flow(host="api.com", path="/api.v1/users")
        addon.request(flow_ok)
        assert flow_ok.response is None

        # If ``.`` were interpreted as a regex metachar, this would
        # match; under glob semantics it must not.
        flow_bad = _make_flow(host="api.com", path="/apiXv1/users")
        addon.request(flow_bad)
        assert flow_bad.response is not None
        assert flow_bad.response.status_code == 599


class TestQueryStringStrippedBeforeMatching:
    """Query strings on the request URL must not defeat path filters.

    ``mitmproxy.http.Request.path`` returns the full request-target —
    path **and** query string (``/info/refs?service=git-upload-pack``).
    Policy filter paths describe the URI path only and never carry
    query strings, so the addon strips ``?<query>`` before matching.

    This is the concrete bug that blocked the ``github-repo`` preset:
    ``git clone`` issues
    ``GET /<owner>/<repo>.git/info/refs?service=git-upload-pack`` and
    the filter path ``/<owner>/<repo>.git/info/refs`` must match it.
    """

    def test_path_with_query_matches_filter_without_query(self) -> None:
        """The real-world github-repo preset case — a GET carrying a
        query string is allowed by a filter whose path is the same
        URI path without the query."""
        addon = _make_addon([
            {"host": "github.com", "port": 443, "filters": [
                {"method": "GET", "path": "/rust-lang/rustlings.git/info/refs"},
            ]},
        ])
        flow = _make_flow(
            method="GET",
            host="github.com",
            path="/rust-lang/rustlings.git/info/refs?service=git-upload-pack",
        )
        addon.request(flow)
        assert flow.response is None, (
            "Filter path without query must match request path that "
            "carries a query — git smart-HTTP depends on this."
        )

    def test_query_does_not_extend_path_match(self) -> None:
        """Query string doesn't smuggle characters into the matched
        path.  A filter for ``/exact`` must not accidentally start
        matching ``/exacty`` just because the query string exists."""
        addon = _make_addon([
            {"host": "api.com", "port": 443, "filters": [
                {"method": "GET", "path": "/exact"},
            ]},
        ])
        # The URI path part ``/exacty`` is not ``/exact`` even though
        # stripping ``?x=1`` yields the right-hand portion unchanged.
        flow = _make_flow(host="api.com", path="/exacty?x=1")
        addon.request(flow)
        assert flow.response is not None
        assert flow.response.status_code == 599

    def test_deny_event_retains_query_in_path(self) -> None:
        """When a request with a query string is denied, the deny
        response (and by extension the deny event) keeps the original
        ``path`` so operators see the exact request the client made —
        query string included — not the stripped match form."""
        addon = _make_addon([
            {"host": "api.com", "port": 443, "filters": [
                {"method": "GET", "path": "/allowed"},
            ]},
        ])
        flow = _make_flow(
            host="api.com", path="/blocked?token=secret"
        )
        addon.request(flow)
        assert flow.response is not None
        assert flow.response.status_code == 599
        body = json.loads(flow.response.content)
        assert body["path"] == "/blocked?token=secret", (
            "Deny response must echo the full request path (including "
            "query) so operators can see what was actually requested."
        )
        # The deny reason is computed against the stripped path so the
        # message names the path-only form the filter compares against.
        assert body["reason"] == "no filter matched GET /blocked"


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

    def test_path_glob(self) -> None:
        """Per-segment glob (v2): ``*`` is segment-local, ``**`` is
        recursive.  See ``TestPerSegmentGlob`` for the full matrix."""
        flt = {"method": "ANY", "path": "/repos/*"}
        assert PolicyAddon._filter_matches(flt, "GET", "/repos/foo")
        # Different first segment — deny.
        assert not PolicyAddon._filter_matches(flt, "GET", "/users/foo")
        # Deeper than one segment — deny under v2.
        assert not PolicyAddon._filter_matches(flt, "GET", "/repos/foo/commits")

        flt_deep = {"method": "ANY", "path": "/repos/**"}
        assert PolicyAddon._filter_matches(flt_deep, "GET", "/repos/foo")
        assert PolicyAddon._filter_matches(flt_deep, "GET", "/repos/foo/commits")

    def test_empty_fields_reject(self) -> None:
        """A filter with a missing method or path rejects every request."""
        assert not PolicyAddon._filter_matches({"method": "", "path": "/foo"}, "GET", "/foo")
        assert not PolicyAddon._filter_matches({"method": "GET", "path": ""}, "GET", "/foo")
        assert not PolicyAddon._filter_matches({}, "GET", "/foo")


class TestPathGlobMatcher:
    """Direct tests of the ``_path_glob_match`` helper.

    These exercise the matcher in isolation from the addon plumbing —
    they catch regressions in the per-segment glob semantics before
    they manifest as mysterious 599s.  The table covers the full
    documented behaviour plus the edge cases noted in the spec:
    anchoring, case-sensitivity, regex-metachar escaping, empty
    inputs, trailing-slash distinction.
    """

    @pytest.mark.parametrize(
        ("pattern", "path", "expected"),
        [
            # Single-star: one segment only.
            ("/api/*", "/api", False),
            ("/api/*", "/api/", True),
            ("/api/*", "/api/users", True),
            ("/api/*", "/api/v1/users", False),
            # Double-star: recursive, requires literal ``/`` before.
            ("/api/**", "/api", False),
            ("/api/**", "/api/", True),
            ("/api/**", "/api/users", True),
            ("/api/**", "/api/v1/users", True),
            ("/api/**", "/api/a/b/c/d", True),
            # Question mark: single non-``/`` character.
            ("/repos/?/commits", "/repos/a/commits", True),
            ("/repos/?/commits", "/repos/ab/commits", False),
            ("/repos/?/commits", "/repos//commits", False),
            ("/v?/users", "/v1/users", True),
            ("/v?/users", "/v10/users", False),
            # Literals and anchoring.
            ("/exact", "/exact", True),
            ("/exact", "/exact/", False),
            ("/exact", "/exactly", False),
            ("/", "/", True),
            ("/", "", False),
            # Top-level single-star.
            ("/*", "/", True),
            ("/*", "/foo", True),
            ("/*", "/foo/bar", False),
            # Top-level double-star.
            ("/**", "/", True),
            ("/**", "/foo", True),
            ("/**", "/foo/bar", True),
            ("/**", "", False),
            # Case-sensitive literals.
            ("/API/users", "/api/users", False),
            ("/API/users", "/API/users", True),
            # Regex metacharacters must be treated as literals.
            ("/api.v1", "/api.v1", True),
            ("/api.v1", "/apiXv1", False),
            ("/a+b", "/a+b", True),
            ("/a+b", "/ab", False),
            ("/(x)", "/(x)", True),
            # Empty pattern.
            ("", "", True),
            ("", "/", False),
        ],
    )
    def test_matcher_behaviour(
        self, pattern: str, path: str, expected: bool
    ) -> None:
        from policy_addon import _path_glob_match

        assert _path_glob_match(pattern, path) is expected, (
            f"pattern={pattern!r} path={path!r}: expected {expected}"
        )


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


# ── JSONL event emission wiring (M10-S2 Phase 6b) ──────────────────
#
# The addon must call ``EventEmitter.emit_request_allowed`` /
# ``emit_request_denied`` at every point it would emit a ``logger.info``
# / ``logger.warning`` line.  These tests plug a mock emitter into the
# addon and exercise each of the four decision sites:
#
#   1. allow (policy match)
#   2. deny — host not in policy
#   3. deny — host matched but port not in policy
#   4. deny — no filter matched
#
# plus the pass-through path (no config loaded → always allow) and the
# "no emitter wired" case (production-style env where
# SANDBOX_MITMPROXY_EVENTS is unset — addon must still work).


def _make_addon_with_events(
    rules: list[dict[str, Any]],
    events: Any,
) -> PolicyAddon:
    """Build a PolicyAddon with an injected events emitter (mock or real)."""
    fd, path = tempfile.mkstemp(suffix=".json")
    os.close(fd)
    _write_config(path, rules)
    addon = PolicyAddon(config_path=path, events=events)
    addon._test_config_path = path  # type: ignore[attr-defined]
    return addon


class _FakeClientConn:
    """Stand-in for ``mitmproxy.connection.Client``'s ``peername``."""

    def __init__(self, peername: Any) -> None:
        self.peername = peername


def _flow_with_peer(
    *,
    method: str = "GET",
    host: str = "example.com",
    path: str = "/",
    port: int = 443,
    peername: Any = ("192.168.87.2", 51234),
) -> _FakeHTTPFlow:
    flow = _make_flow(method=method, host=host, path=path, port=port)
    # Attach a fake client_conn so `_peer_ip` returns a real value.
    flow.client_conn = _FakeClientConn(peername)  # type: ignore[attr-defined]
    return flow


class TestEventEmissionAllow:
    def test_allow_emits_request_allowed(self) -> None:
        mock_events = mock.MagicMock()
        addon = _make_addon_with_events(
            [{"host": "api.github.com", "port": 443, "filters": [ANY_FILTER]}],
            mock_events,
        )
        flow = _flow_with_peer(
            host="api.github.com", path="/repos/foo", peername=("10.0.0.5", 4321)
        )
        addon.request(flow)
        # Flow was allowed (no 599 response).
        assert flow.response is None
        # Emitter saw a single allow call with expected kwargs.
        mock_events.emit_request_allowed.assert_called_once_with(
            host="api.github.com",
            port=443,
            method="GET",
            path="/repos/foo",
            client_ip="10.0.0.5",
        )
        mock_events.emit_request_denied.assert_not_called()


class TestEventEmissionDenyHostNotInPolicy:
    def test_host_miss_emits_deny_with_exact_reason(self) -> None:
        mock_events = mock.MagicMock()
        addon = _make_addon_with_events(
            [{"host": "api.github.com", "port": 443, "filters": [ANY_FILTER]}],
            mock_events,
        )
        flow = _flow_with_peer(
            host="evil.com", path="/", peername=("10.0.0.7", 1111)
        )
        addon.request(flow)
        # Deny produces 599 response.
        assert flow.response is not None
        assert flow.response.status_code == 599
        # And a deny event with the same reason the logger line uses.
        mock_events.emit_request_denied.assert_called_once_with(
            host="evil.com",
            port=443,
            method="GET",
            path="/",
            reason="host not in policy",
            client_ip="10.0.0.7",
        )
        mock_events.emit_request_allowed.assert_not_called()


class TestEventEmissionDenyPortMismatch:
    def test_port_miss_emits_deny_with_exact_reason(self) -> None:
        mock_events = mock.MagicMock()
        addon = _make_addon_with_events(
            [{"host": "api.github.com", "port": 443, "filters": [ANY_FILTER]}],
            mock_events,
        )
        # Request lands on port 8443 — the host matches but port does not.
        flow = _flow_with_peer(host="api.github.com", path="/", port=8443)
        addon.request(flow)
        assert flow.response is not None
        assert flow.response.status_code == 599
        mock_events.emit_request_denied.assert_called_once()
        _, kwargs = mock_events.emit_request_denied.call_args
        # Reason string must match the deny-event contract verbatim
        # (consumed by ``sandbox events --decision=deny``).
        assert kwargs["reason"] == "host matched but port 8443 not in policy"
        assert kwargs["port"] == 8443


class TestEventEmissionDenyNoFilterMatch:
    def test_filter_miss_emits_deny_with_exact_reason(self) -> None:
        mock_events = mock.MagicMock()
        addon = _make_addon_with_events(
            [{"host": "api.github.com", "port": 443, "filters": [
                {"method": "GET", "path": "/repos/*"},
            ]}],
            mock_events,
        )
        # POST doesn't match any GET-only filter.
        flow = _flow_with_peer(
            method="POST", host="api.github.com", path="/secret"
        )
        addon.request(flow)
        assert flow.response is not None
        assert flow.response.status_code == 599
        mock_events.emit_request_denied.assert_called_once()
        _, kwargs = mock_events.emit_request_denied.call_args
        # Again, reason must be identical to the logger.warning string.
        assert kwargs["reason"] == "no filter matched POST /secret"


class TestEventEmissionPassthrough:
    def test_passthrough_emits_request_allowed(self) -> None:
        """When no policy is loaded, every request is allowed and each
        allow should still emit a structured event."""
        mock_events = mock.MagicMock()
        # Pass an unreadable config path so the addon enters passthrough.
        fd, path = tempfile.mkstemp(suffix=".json")
        os.close(fd)
        os.unlink(path)
        addon = PolicyAddon(config_path=path, events=mock_events)
        assert addon._passthrough is True

        flow = _flow_with_peer(
            host="anywhere.invalid",
            path="/x",
            peername=("10.0.0.9", 55555),
        )
        addon.request(flow)
        mock_events.emit_request_allowed.assert_called_once_with(
            host="anywhere.invalid",
            port=443,
            method="GET",
            path="/x",
            client_ip="10.0.0.9",
        )


class TestEventEmissionOptional:
    """The addon must keep working when no emitter is wired — this is
    the unit-test default and also what happens in production if
    ``SANDBOX_MITMPROXY_EVENTS`` is unset."""

    def test_no_emitter_allow_succeeds(self) -> None:
        addon = _make_addon([
            {"host": "api.github.com", "port": 443, "filters": [ANY_FILTER]},
        ])
        assert addon._events is None
        flow = _flow_with_peer(host="api.github.com", path="/repos/x")
        addon.request(flow)
        assert flow.response is None  # Allowed, no crash on missing emitter.

    def test_no_emitter_deny_succeeds(self) -> None:
        addon = _make_addon([
            {"host": "api.github.com", "port": 443, "filters": [ANY_FILTER]},
        ])
        flow = _flow_with_peer(host="evil.com")
        addon.request(flow)
        assert flow.response is not None
        assert flow.response.status_code == 599


class TestEventEmissionClientIpMissing:
    """When ``flow.client_conn`` is missing or ``peername`` is None,
    ``client_ip`` must round-trip as ``None`` (serialized JSON null)."""

    def test_no_client_conn_attr(self) -> None:
        mock_events = mock.MagicMock()
        addon = _make_addon_with_events(
            [{"host": "api.github.com", "port": 443, "filters": [ANY_FILTER]}],
            mock_events,
        )
        # Use the vanilla flow (no client_conn attached).
        flow = _make_flow(host="api.github.com", path="/x")
        addon.request(flow)
        _, kwargs = mock_events.emit_request_allowed.call_args
        assert kwargs["client_ip"] is None

    def test_peername_is_none(self) -> None:
        mock_events = mock.MagicMock()
        addon = _make_addon_with_events(
            [{"host": "api.github.com", "port": 443, "filters": [ANY_FILTER]}],
            mock_events,
        )
        flow = _flow_with_peer(host="api.github.com", path="/x", peername=None)
        addon.request(flow)
        _, kwargs = mock_events.emit_request_allowed.call_args
        assert kwargs["client_ip"] is None
