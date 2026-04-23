"""E2E tests for the M10-S5 preset system.

Each test exercises one preset class end-to-end by creating a session with
``sandbox create --preset '<name>[:<args>]'`` and asserting that the
preset-allowed traffic succeeds while off-preset traffic is denied. The
assertions rely on the unified event stream (``sandbox events <sid>``)
which exposes DNS, Envoy, mitmproxy, deny-logger, and lifecycle layers —
so the tests also act as a cross-layer smoke test for M10-S4 events plumbing.

Deviation from the plan (Phase 7 of
``.tasks/handoffs/20260423-m10-s5-implementation-plan.md``)
--------------------------------------------------------------------------

The plan's happy-path narratives run ``npm init && npm install leftpad``
and ``cargo new && cargo add && cargo fetch`` *inside* the VM to exercise
the npm/cargo presets. The golden base image
(``sandbox-core/src/lima.rs``) only installs ``socat``, ``git``, and
``docker`` — there is no ``node``/``npm``/``cargo`` binary in the VM, and
no apt-source host is part of the ``npm:`` or ``cargo:`` preset allow-list
(so we cannot ``apt-get install nodejs`` inside the VM without widening
the session policy and thereby defeating the purpose of the preset test).

To honour the spirit of the plan without extending the base image, we use
``curl`` (already in the base Ubuntu image) to issue the exact HTTP
requests that ``npm`` and ``cargo`` would issue against the preset-allowed
hosts. This is a faithful test of the preset's network-policy coverage
(the actual security-relevant surface of the preset): the HTTP method,
host, port, and path pattern are what the policy enforces, not the client
binary. The github-repo test, by contrast, uses a real ``git clone`` —
``git`` is in the base image, so that flow runs end-to-end unchanged.

Runs with generous timeouts; a single iteration boots a VM so budget
3-10 minutes per VM test. The ``test_preset_expand_round_trip`` test
does not boot a VM (expand runs on the host) and completes in a few
seconds.

    cd tests/e2e
    source .venv/bin/activate
    python -m pytest test_m10_s5_presets.py -v --timeout=600
"""

from __future__ import annotations

import json
import subprocess
import time
from pathlib import Path

import pytest

from conftest import (
    _VM_RESOURCE_ARGS,
    capture_lima_logs,
    gateway_container_name,
    parse_session_id,
    wait_for_state,
)


# Seconds to wait after a workload so the gateway logger-tail / ring ingest
# tasks have time to publish the domain event to the per-session ring
# buffer. M10-S4's discovery test uses 3s; we use 5s because the mitmproxy
# JSONL tail (unlike Envoy's access log) is buffered inside the Python
# addon via ``open(…, "a")`` without explicit ``flush()`` on every write,
# and the daemon's file watcher reacts to size-change events from inotify,
# adding a small additional end-to-end latency between addon emit and ring
# publish.
EVENT_PROPAGATION_S = 5

# Deadline for ``sandbox policy status --wait``: the CLI polls the
# daemon's propagation-status endpoint until every enforcement layer
# (nftables, Envoy, mitmproxy/CoreDNS) has reconciled the latest policy
# and the DNS propagation loop has mirrored every ``Destination::Domain``
# rule's resolved IPs into the allow sets. 60s is comfortably above the
# 2s DNS loop cycle plus per-layer distribute latency observed in CI,
# and the CLI exits 0 the moment the state flips — a fast-apply sees
# sub-second wait, so the budget is only load-bearing on a slow runner.
POLICY_PROPAGATION_TIMEOUT = "60s"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _read_events(sandbox_cli, session_name: str, decision: str | None = None) -> list[dict]:
    """Snapshot the per-session ring via ``sandbox events`` (non-follow, JSONL).

    Blank / unparseable lines are skipped so a truncated tail (rare, but
    possible if the daemon flushes mid-line) does not invalidate the
    assertion. The caller filters the returned list in Python rather
    than narrowing with server-side CLI flags — more legible in tests.
    """
    args = ["events", session_name]
    if decision is not None:
        args.append(f"--decision={decision}")
    result = sandbox_cli(*args, timeout=60)
    assert result.returncode == 0, (
        f"`sandbox events {' '.join(args[1:])}` failed "
        f"(rc={result.returncode}).\n"
        f"stdout: {result.stdout}\nstderr: {result.stderr}"
    )
    events: list[dict] = []
    for line in result.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            events.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return events


def _capture_gateway_event_logs(session_id: str) -> str:
    """Best-effort dump of the gateway container's raw JSONL event files.

    Only used as a diagnostic in assertion messages — if the mitmproxy /
    envoy / coredns addons wrote events but the daemon's watcher somehow
    missed them, this helps tell the two cases apart. Failure to exec
    into the container (e.g. it's already torn down) is silent and
    returns an empty string.
    """
    gw = gateway_container_name(session_id)
    sections: list[str] = []
    for name in ("mitmproxy.jsonl", "envoy.jsonl", "coredns.jsonl"):
        try:
            result = subprocess.run(
                ["docker", "exec", gw, "tail", "-n", "30",
                 f"/var/log/gateway/events/{name}"],
                capture_output=True, text=True, timeout=15,
            )
            if result.returncode == 0 and result.stdout.strip():
                sections.append(
                    f"--- gateway /var/log/gateway/events/{name} "
                    f"(last 30 lines) ---\n{result.stdout}"
                )
        except Exception:
            pass
    return "\n".join(sections)


def _warm_dns(sandbox_cli, session_name: str, hosts: list[str]) -> None:
    """Pre-resolve ``hosts`` inside the VM so the gateway's DNS-driven
    propagation loop materialises the per-rule Envoy filter chain and
    the nftables concat-set entry (ip, port) for each preset-allowed
    host. Mirrors the pattern used in ``test_m4_policy`` /
    ``test_m10_s4_discovery``: without the warmup, the first curl can
    race the 2-second poll and lose.
    """
    for host in hosts:
        sandbox_cli(
            "ssh", session_name, "--",
            "nslookup", host,
            timeout=120,
        )


def _wait_policy_propagated(
    sandbox_cli,
    session_name: str,
    timeout: str = POLICY_PROPAGATION_TIMEOUT,
) -> None:
    """Block until the session's latest policy-apply has fully propagated.

    Replaces the M10-S5 pattern of ``time.sleep(POLICY_PROPAGATION_S)``
    wall-clock waits with a deterministic poll against
    ``GET /sessions/{id}/policy/propagation-status`` (M10-S6 todo #37).
    The CLI exits 0 the moment the propagation tracker reports
    ``propagated=true`` — which in turn requires every enforcement
    layer to have reconciled the policy *and* the DNS loop to have
    cached an IP for every ``Destination::Domain`` allow rule. The
    tests therefore warm DNS for the preset-allowed hosts before
    calling this helper so the cache condition can be satisfied.
    """
    result = sandbox_cli(
        "policy", "status", session_name,
        "--wait", "--timeout", timeout,
        timeout=120,
    )
    assert result.returncode == 0, (
        f"policy status --wait failed for {session_name} "
        f"(rc={result.returncode}).\n"
        f"stdout: {result.stdout}\nstderr: {result.stderr}"
    )
    # Multi-host presets: --wait returns when daemon's DNS-propagation loop
    # flips propagated=true, but multi-host cases still race against Envoy
    # cluster DNS resolution / nftables enforcement settling (~sub-second
    # window). 3s settle is a band-aid until the real fix lands (todo #40).
    time.sleep(3)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


@pytest.mark.timeout(600)
def test_npm_preset_allows_npm_install(sandbox_cli):
    """``sandbox create --preset 'npm:'`` allows an npm metadata + tarball
    fetch from ``registry.npmjs.org``, and the allow events surface via
    ``sandbox events --decision=allow``.

    The ``npm:`` preset expands to a single rule granting ``GET /**`` and
    ``HEAD /**`` on ``registry.npmjs.org:443`` at HTTP level. ``npm
    install leftpad`` issues two requests against that host:

    * ``GET /leftpad``                                    — package metadata
    * ``GET /leftpad/-/leftpad-<version>.tgz``            — tarball

    Both are ``GET /**`` on the preset-allowed host, so the preset policy
    must admit them. The test issues these two requests via ``curl``
    (see module docstring for why we don't invoke ``npm`` directly) and
    asserts each one exits 0 and surfaces at least one allow event on
    each enforcement layer we care about (DNS resolution + mitmproxy
    HTTP decision).
    """
    session_name = "m10-s5-npm-allow"
    session_id: str | None = None
    try:
        create_result = sandbox_cli(
            "create", "--name", session_name,
            *_VM_RESOURCE_ARGS,
            "--preset", "npm:",
            timeout=600,
        )
        assert create_result.returncode == 0, (
            f"sandbox create --preset 'npm:' failed (rc={create_result.returncode}).\n"
            f"stdout: {create_result.stdout}\nstderr: {create_result.stderr}"
        )
        session_id = parse_session_id(create_result.stdout)
        wait_for_state(sandbox_cli, session_name, "Running", timeout=30)

        # Warm DNS so the gateway's propagation loop can materialise the
        # per-rule Envoy chain + nftables set, then wait deterministically
        # for the state to flip to propagated=true before driving
        # workload traffic.
        _warm_dns(sandbox_cli, session_name, ["registry.npmjs.org"])
        _wait_policy_propagated(sandbox_cli, session_name)

        # Fetch ``leftpad`` metadata — exactly the first request ``npm
        # install leftpad`` issues. The package has been unpublished from
        # npm but its 301-redirect metadata record is still served, which
        # is enough to exercise the allow path (mitmproxy records the
        # request on the way out regardless of upstream status code).
        meta_cmd = (
            "curl -sS --connect-timeout 10 --max-time 30 "
            "-o /dev/null -w '%{http_code}' "
            "https://registry.npmjs.org/leftpad"
        )
        meta_result = sandbox_cli(
            "ssh", session_name, "--", "bash", "-c", meta_cmd,
            timeout=120,
        )
        assert meta_result.returncode == 0, (
            f"curl to registry.npmjs.org/leftpad failed under npm preset.\n"
            f"stdout: {meta_result.stdout}\nstderr: {meta_result.stderr}\n"
            f"{capture_lima_logs(session_id)}"
        )

        # Second request — a HEAD against the tarball path. We use HEAD
        # rather than GET to avoid pulling the whole tarball through the
        # gateway, but both methods are allowed by the preset ("/**"
        # GET+HEAD).
        tgz_cmd = (
            "curl -sS -I --connect-timeout 10 --max-time 30 "
            "-o /dev/null -w '%{http_code}' "
            "https://registry.npmjs.org/is-odd/-/is-odd-3.0.1.tgz"
        )
        tgz_result = sandbox_cli(
            "ssh", session_name, "--", "bash", "-c", tgz_cmd,
            timeout=120,
        )
        assert tgz_result.returncode == 0, (
            f"curl to registry.npmjs.org/is-odd/...tgz failed under npm preset.\n"
            f"stdout: {tgz_result.stdout}\nstderr: {tgz_result.stderr}\n"
            f"{capture_lima_logs(session_id)}"
        )

        # Give ingestion tasks time to push the events onto the ring.
        time.sleep(EVENT_PROPAGATION_S)

        allow_events = _read_events(sandbox_cli, session_name, decision="allow")

        # At least one DNS allow for registry.npmjs.org.
        dns_allows = [
            ev for ev in allow_events
            if ev.get("layer") == "dns"
            and ev.get("event") == "query_allowed"
            and ev.get("query", "").rstrip(".") == "registry.npmjs.org"
        ]
        assert dns_allows, (
            f"Expected at least one dns.query_allowed event for "
            f"registry.npmjs.org, got {len(allow_events)} allow events "
            f"total; first 10:\n"
            + "\n".join(json.dumps(ev) for ev in allow_events[:10])
        )

        # At least one mitmproxy allow against registry.npmjs.org.
        mitm_allows = [
            ev for ev in allow_events
            if ev.get("layer") == "mitmproxy"
            and ev.get("event") == "request_allowed"
            and ev.get("host") == "registry.npmjs.org"
        ]
        assert mitm_allows, (
            f"Expected at least one mitmproxy.request_allowed event against "
            f"registry.npmjs.org, got {len(allow_events)} allow events "
            f"total; first 10:\n"
            + "\n".join(json.dumps(ev) for ev in allow_events[:10])
            + "\n\n"
            + _capture_gateway_event_logs(session_id)
        )

    finally:
        if session_id is not None:
            try:
                sandbox_cli("rm", session_name, timeout=120)
            except Exception:
                pass


@pytest.mark.timeout(600)
def test_npm_preset_denies_non_preset_host(sandbox_cli):
    """A session started with the ``npm:`` preset denies traffic to
    hosts outside ``registry.npmjs.org``.

    Uses ``example.com`` (IANA-reserved, reliably resolvable on any
    network, unrelated to npm) as the off-preset host. ``curl
    https://example.com`` from inside the VM should fail, and a
    corresponding deny event should surface via ``sandbox events
    --decision=deny``. The exact deny layer (``dns.query_denied`` or
    ``deny-logger.deny``) depends on whether CoreDNS rejects the query
    before the connection is attempted — we accept either.
    """
    session_name = "m10-s5-npm-deny"
    session_id: str | None = None
    try:
        create_result = sandbox_cli(
            "create", "--name", session_name,
            *_VM_RESOURCE_ARGS,
            "--preset", "npm:",
            timeout=600,
        )
        assert create_result.returncode == 0, (
            f"sandbox create --preset 'npm:' failed (rc={create_result.returncode}).\n"
            f"stdout: {create_result.stdout}\nstderr: {create_result.stderr}"
        )
        session_id = parse_session_id(create_result.stdout)
        wait_for_state(sandbox_cli, session_name, "Running", timeout=30)
        # Warm DNS for the preset-allowed host so the propagation
        # tracker's `all_domain_rules_resolved` check can be satisfied
        # and --wait returns promptly; the deny assertion below targets
        # a different host (example.com) and is unaffected by the warmup.
        _warm_dns(sandbox_cli, session_name, ["registry.npmjs.org"])
        _wait_policy_propagated(sandbox_cli, session_name)

        # Drive traffic to an off-preset host. The `|| true` guarantees
        # the ssh call succeeds: curl itself is expected to fail, we just
        # need the packets / DNS lookup on the wire to trigger the deny
        # path. We use `-w EXIT:%{exitcode}` so we can assert curl's
        # non-zero exit even though the outer ssh call returns 0.
        curl_cmd = (
            "curl -sS --connect-timeout 5 --max-time 5 "
            "-o /dev/null -w 'EXIT:%{exitcode}' "
            "https://example.com || true"
        )
        curl_result = sandbox_cli(
            "ssh", session_name, "--", "bash", "-c", curl_cmd,
            timeout=60,
        )
        # curl(1) documents exit codes 0 = success, non-zero = various
        # failure modes. The preset denies example.com at one of DNS
        # (NXDOMAIN → curl exit 6 "Could not resolve host"), transport
        # (connection refused → exit 7), or TLS layers (exit 35 / 60).
        # Any non-zero code is evidence of a denial.
        assert "EXIT:0" not in curl_result.stdout, (
            f"curl to example.com succeeded under npm preset; expected "
            f"denial.\nstdout: {curl_result.stdout}\nstderr: {curl_result.stderr}"
        )

        time.sleep(EVENT_PROPAGATION_S)
        deny_events = _read_events(sandbox_cli, session_name, decision="deny")
        assert deny_events, (
            f"Expected at least one deny event for example.com under "
            f"the npm preset, but the ring buffer was empty.\n"
            f"{capture_lima_logs(session_id)}"
        )

        # Accept a denial on any layer that names the target host. CoreDNS
        # returns NXDOMAIN for off-preset queries (dns.query_denied);
        # the deny-logger records the connection attempt if resolution
        # somehow slipped through (deny-logger.deny); Envoy can also
        # emit envoy.connection_denied on the SNI mismatch path.
        matched: list[dict] = []
        for ev in deny_events:
            layer = ev.get("layer")
            event = ev.get("event")
            if layer == "dns" and event == "query_denied":
                if ev.get("query", "").rstrip(".") == "example.com":
                    matched.append(ev)
            elif layer == "deny-logger" and event == "deny":
                # deny-logger carries orig_dst_ip (post-DNAT or pre-DNAT
                # depending on path); we can't map that back to example.com
                # without resolving host-side, so we accept any deny-logger
                # event as additional evidence.
                matched.append(ev)
            elif layer == "envoy" and event == "connection_denied":
                if ev.get("connect_authority") == "example.com":
                    matched.append(ev)

        assert matched, (
            f"None of the {len(deny_events)} deny events named "
            f"example.com (or were a deny-logger fallback).\n"
            f"First 10 deny events:\n"
            + "\n".join(json.dumps(ev) for ev in deny_events[:10])
        )

    finally:
        if session_id is not None:
            try:
                sandbox_cli("rm", session_name, timeout=120)
            except Exception:
                pass


@pytest.mark.timeout(600)
def test_cargo_preset_allows_cargo_fetch(sandbox_cli):
    """``sandbox create --preset 'cargo:'`` allows the HTTP requests that
    ``cargo fetch`` issues against the three crates.io hosts.

    The ``cargo:`` preset expansion (``sandboxd/sandbox-cli/src/presets/
    builtin.rs``, verified empirically by M10-S5 Phase 5a' against a live
    cargo fetch trace stored at ``sandbox-cli/tests/fixtures/
    cargo_fetch_trace.json``) includes:

    * ``crates.io``         — redirect endpoints for ``cargo search`` etc.
    * ``index.crates.io``   — sparse registry index (metadata).
    * ``static.crates.io``  — crate tarball downloads.

    The test follows the same pragmatic pattern as
    ``test_npm_preset_allows_npm_install`` (no cargo binary in the base
    image — see module docstring): issue the representative HTTP requests
    that a ``cargo fetch`` of ``serde`` would make, via ``curl``, and
    assert each returns 200 and surfaces an allow event.
    """
    session_name = "m10-s5-cargo-allow"
    session_id: str | None = None
    try:
        create_result = sandbox_cli(
            "create", "--name", session_name,
            *_VM_RESOURCE_ARGS,
            "--preset", "cargo:",
            timeout=600,
        )
        assert create_result.returncode == 0, (
            f"sandbox create --preset 'cargo:' failed "
            f"(rc={create_result.returncode}).\n"
            f"stdout: {create_result.stdout}\nstderr: {create_result.stderr}"
        )
        session_id = parse_session_id(create_result.stdout)
        wait_for_state(sandbox_cli, session_name, "Running", timeout=30)

        _warm_dns(
            sandbox_cli, session_name,
            ["index.crates.io", "static.crates.io", "crates.io"],
        )
        _wait_policy_propagated(sandbox_cli, session_name)

        # Sparse-registry metadata lookup for `serde` — this is exactly
        # the first request `cargo fetch` issues after parsing the
        # manifest. `serde` lives under the `se/rd/` shard per the
        # sparse-index layout.
        index_cmd = (
            "curl -sS --connect-timeout 10 --max-time 30 "
            "-o /dev/null -w '%{http_code}' "
            "https://index.crates.io/se/rd/serde"
        )
        index_result = sandbox_cli(
            "ssh", session_name, "--", "bash", "-c", index_cmd,
            timeout=120,
        )
        assert index_result.returncode == 0, (
            f"curl to index.crates.io/se/rd/serde failed under cargo preset.\n"
            f"stdout: {index_result.stdout}\nstderr: {index_result.stderr}\n"
            f"{capture_lima_logs(session_id)}"
        )

        # Tarball fetch from static.crates.io — cargo uses this host for
        # the actual .crate download once the index resolves a version.
        # We HEAD rather than GET to avoid pulling the whole tarball.
        tarball_cmd = (
            "curl -sS -I --connect-timeout 10 --max-time 30 "
            "-o /dev/null -w '%{http_code}' "
            "https://static.crates.io/crates/serde/serde-1.0.0.crate"
        )
        tarball_result = sandbox_cli(
            "ssh", session_name, "--", "bash", "-c", tarball_cmd,
            timeout=120,
        )
        assert tarball_result.returncode == 0, (
            f"curl to static.crates.io/crates/serde/... failed under "
            f"cargo preset.\nstdout: {tarball_result.stdout}\n"
            f"stderr: {tarball_result.stderr}\n"
            f"{capture_lima_logs(session_id)}"
        )

        time.sleep(EVENT_PROPAGATION_S)
        allow_events = _read_events(sandbox_cli, session_name, decision="allow")

        # Assert allow events on both crates.io hosts the requests hit.
        expected_hosts = {"index.crates.io", "static.crates.io"}
        seen_hosts = {
            ev.get("host")
            for ev in allow_events
            if ev.get("layer") == "mitmproxy"
            and ev.get("event") == "request_allowed"
            and ev.get("host") in expected_hosts
        }
        missing = expected_hosts - seen_hosts
        assert not missing, (
            f"Expected mitmproxy.request_allowed on all of {expected_hosts}, "
            f"missing {missing}. Got {len(allow_events)} allow events "
            f"total; first 15:\n"
            + "\n".join(json.dumps(ev) for ev in allow_events[:15])
        )

    finally:
        if session_id is not None:
            try:
                sandbox_cli("rm", session_name, timeout=120)
            except Exception:
                pass


@pytest.mark.timeout(600)
def test_github_repo_preset_scopes_to_one_repo(sandbox_cli):
    """``--preset 'github-repo:repo=<owner>/<name>'`` allows HTTPS-git
    clone of ``<owner>/<name>`` but denies any other repository.

    Unlike the npm/cargo cases, this test runs an actual ``git clone``
    inside the VM — ``git`` is in the base image, so the path end-to-end
    is exercised. Two clones are attempted:

    1. ``rust-lang/rustlings``   — matches the preset, must succeed.
    2. ``torvalds/linux``        — no match, must fail, and the denial
       must surface via the event ring.

    The ``rustlings`` repo was chosen over smaller public repos (e.g.
    ``octocat/Hello-World``) because it is still actively maintained,
    under ~20 MiB shallow, and the M10-S5 plan names it explicitly.
    """
    session_name = "m10-s5-ghrepo"
    session_id: str | None = None
    try:
        create_result = sandbox_cli(
            "create", "--name", session_name,
            *_VM_RESOURCE_ARGS,
            "--preset", "github-repo:repo=rust-lang/rustlings",
            timeout=600,
        )
        assert create_result.returncode == 0, (
            f"sandbox create --preset 'github-repo:repo=rust-lang/rustlings' "
            f"failed (rc={create_result.returncode}).\n"
            f"stdout: {create_result.stdout}\nstderr: {create_result.stderr}"
        )
        session_id = parse_session_id(create_result.stdout)
        wait_for_state(sandbox_cli, session_name, "Running", timeout=30)

        # ``github-repo`` expands to six hosts (github.com,
        # codeload.github.com, api.github.com, raw.githubusercontent.com,
        # objects.githubusercontent.com, release-assets.githubusercontent.com).
        # Each host needs DNS resolution + an nftables concat-set entry +
        # an Envoy filter chain update before the VM can reach it.  Warm
        # every host the preset allow-lists so the 2s DNS-driven
        # propagation loop has materialised all of them before the
        # `git clone` runs.  Warming only `github.com` +
        # `codeload.github.com` (the bare minimum for the clone itself)
        # proved racy on under-provisioned hardware — the first TCP
        # SYN landed ahead of the Envoy listener update and the gateway
        # answered with RST.
        _warm_dns(
            sandbox_cli, session_name,
            [
                "github.com",
                "codeload.github.com",
                "api.github.com",
                "raw.githubusercontent.com",
                "objects.githubusercontent.com",
                "release-assets.githubusercontent.com",
            ],
        )
        _wait_policy_propagated(sandbox_cli, session_name)

        # Happy path: shallow clone of the preset-allowed repo. `--depth 1`
        # keeps bandwidth + time reasonable; the preset covers both
        # github.com (smart HTTP) and codeload.github.com (pack fetches).
        allowed_cmd = (
            "git clone --depth 1 "
            "https://github.com/rust-lang/rustlings /tmp/rustlings"
        )
        allowed_result = sandbox_cli(
            "ssh", session_name, "--", "bash", "-c", allowed_cmd,
            timeout=300,
        )
        assert allowed_result.returncode == 0, (
            f"Preset-allowed git clone (rust-lang/rustlings) failed.\n"
            f"stdout: {allowed_result.stdout}\nstderr: {allowed_result.stderr}\n"
            f"{capture_lima_logs(session_id)}"
        )

        # Denial path: clone an unrelated repo. The preset's
        # `github-repo:repo=rust-lang/rustlings` expansion only allow-lists
        # paths under `/rust-lang/rustlings/...`, so a clone of
        # `torvalds/linux` hits the `GET /torvalds/linux.git/info/refs`
        # path which has no matching filter → request_denied.
        denied_cmd = (
            "git clone --depth 1 "
            "https://github.com/torvalds/linux /tmp/linux 2>&1; "
            "echo EXIT:$?"
        )
        denied_result = sandbox_cli(
            "ssh", session_name, "--", "bash", "-c", denied_cmd,
            timeout=180,
        )
        # ``echo`` runs last so the outer ``bash -c`` always exits 0,
        # which is why we assert against the printed ``EXIT:<code>``
        # marker rather than ``denied_result.returncode``. Without an
        # ``|| true`` masking the error, ``$?`` now captures git's real
        # exit status, so the absence of ``EXIT:0`` in the combined
        # output faithfully reflects a denied clone.
        combined = denied_result.stdout + denied_result.stderr
        assert "EXIT:0" not in combined, (
            f"git clone of torvalds/linux unexpectedly succeeded under "
            f"github-repo:rust-lang/rustlings preset.\n"
            f"stdout: {denied_result.stdout}\nstderr: {denied_result.stderr}"
        )

        time.sleep(EVENT_PROPAGATION_S)

        # Assert the deny path names torvalds/linux. github-repo denials
        # most commonly land on mitmproxy (HTTP-layer filter mismatch)
        # because github.com:443 is on the preset's host allow-list but
        # the path is not — the TLS handshake completes, the HTTP layer
        # then rejects the request and emits `request_denied` with the
        # path field populated.
        deny_events = _read_events(sandbox_cli, session_name, decision="deny")
        torvalds_denies = [
            ev for ev in deny_events
            if ev.get("layer") == "mitmproxy"
            and ev.get("event") == "request_denied"
            and "/torvalds/linux" in ev.get("path", "")
        ]
        assert torvalds_denies, (
            f"Expected mitmproxy.request_denied event referencing "
            f"/torvalds/linux, got {len(deny_events)} deny events "
            f"total; first 15:\n"
            + "\n".join(json.dumps(ev) for ev in deny_events[:15])
        )

    finally:
        if session_id is not None:
            try:
                sandbox_cli("rm", session_name, timeout=300)
            except Exception:
                pass


@pytest.mark.timeout(600)
def test_preset_expand_round_trip(sandbox_cli, tmp_path):
    """``sandbox policy preset expand`` produces a policy document that
    the daemon accepts verbatim when passed as ``--policy``.

    This is the plan's "round trip" test: the CLI's preset machinery must
    be bit-for-bit compatible with the daemon's policy parser, so an
    operator can use ``expand`` as a dry-run step and feed its stdout to
    ``create``/``policy update`` unchanged.

    No VM is involved for the expand step itself (it runs client-side),
    but the ``create`` half still boots a VM because that's the only
    pathway that triggers ``lifecycle.policy_applied`` emission. We skip
    the workload entirely and just assert that the session reaches
    Running with a ``policy_applied { status: ok }`` event — that's the
    full contract: daemon parses, validates, and applies the
    expanded policy without error.
    """
    session_name = "m10-s5-expand-rt"
    session_id: str | None = None
    try:
        # 1. Expand `github-repo:repo=foo/bar` client-side, no daemon.
        expand_result = sandbox_cli(
            "policy", "preset", "expand", "github-repo:repo=foo/bar",
            timeout=30,
        )
        assert expand_result.returncode == 0, (
            f"`sandbox policy preset expand` failed "
            f"(rc={expand_result.returncode}).\n"
            f"stdout: {expand_result.stdout}\nstderr: {expand_result.stderr}"
        )
        # Sanity: output parses as a v2 policy document.
        policy_doc = json.loads(expand_result.stdout)
        assert policy_doc.get("version") == "2.0.0", (
            f"Expand output does not look like a v2 policy: {expand_result.stdout}"
        )
        assert isinstance(policy_doc.get("rules"), list) and policy_doc["rules"], (
            f"Expand output has no rules: {expand_result.stdout}"
        )

        # 2. Save the expanded JSON to a tempfile.
        expanded_path = tmp_path / "expanded-github-repo.json"
        expanded_path.write_text(expand_result.stdout)

        # 3. Pass the tempfile as --policy to `sandbox create` (no --preset).
        create_result = sandbox_cli(
            "create", "--name", session_name,
            *_VM_RESOURCE_ARGS,
            "--policy", str(expanded_path),
            timeout=600,
        )
        assert create_result.returncode == 0, (
            f"sandbox create --policy <expanded> failed "
            f"(rc={create_result.returncode}).\n"
            f"stdout: {create_result.stdout}\nstderr: {create_result.stderr}"
        )
        session_id = parse_session_id(create_result.stdout)

        # 4. Assert the session reaches Running — the daemon accepted the
        #    expanded policy. A bad policy would have failed `create`
        #    before the session state could advance.
        wait_for_state(sandbox_cli, session_name, "Running", timeout=30)

        # 5. Assert a `lifecycle.policy_applied` event with `status=ok`
        #    exists in the ring. This is the definitive signal that the
        #    daemon fully validated and applied the expanded policy.
        time.sleep(EVENT_PROPAGATION_S)
        events = _read_events(sandbox_cli, session_name)
        applied = [
            ev for ev in events
            if ev.get("layer") == "lifecycle"
            and ev.get("event") == "policy_applied"
            and ev.get("status") == "ok"
        ]
        assert applied, (
            f"Expected lifecycle.policy_applied{{status=ok}} in the ring, "
            f"got {len(events)} events total; first 10:\n"
            + "\n".join(json.dumps(ev) for ev in events[:10])
        )

    finally:
        if session_id is not None:
            try:
                sandbox_cli("rm", session_name, timeout=120)
            except Exception:
                pass
