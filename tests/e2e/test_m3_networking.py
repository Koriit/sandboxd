"""E2E tests for M3 networking: gateway traffic flow, nftables enforcement,
DNS interception, stop/start with networking, concurrent sessions, daemon
restart recovery, and gateway crash recovery.

These tests boot real Lima/QEMU VMs with full networking (Docker bridge,
gateway container, nftables, TAP NIC) and are SLOW (3-10 minutes per test).
Run with generous timeouts:

    cd tests/e2e
    source .venv/bin/activate
    python -m pytest test_m3_networking.py -v --timeout=600

Backend coverage: every test in this file is parametrized over
``[lima, container]`` via the ``backend`` fixture. The gateway
container, nftables ruleset, CoreDNS interception, and daemon /
gateway crash-recovery monitors are shared between backends per the
M11 gap-#70 closure. The three tests previously pinned to Lima via an
in-body ``pytest.skip()`` for the ``10.209.x.x/28`` regex —
``test_gateway_traffic_flow``, ``test_stop_start_with_networking``,
``test_concurrent_sessions`` — now read the gateway / session IP /
subnet CIDR from ``sandbox inspect <name>`` (M11-S7 Bundle Y / todo
#72) and run on both backends. The Lima-only RAM precondition in
``test_concurrent_sessions`` (two 2 GB Lima VMs require ≥6 GB host
RAM; container sessions are tens of MB) remains scoped to
``backend == "lima"``.
"""

from __future__ import annotations

import json
import os
import re
import signal
import subprocess
import time

import pytest

from conftest import (
    capture_lima_logs,
    cleanup_policy_file,
    gateway_container_name,
    make_create_args,
    parse_session_id,
    wait_for_state,
    write_policy_file,
)


def _networking_smoke_policy_file() -> str:
    """Write a minimal v2 policy covering the hosts these M3 networking
    tests nslookup / curl from inside the VM, and return the file path.

    M10-S1 removed the ``--unrestricted`` discovery escape hatch; tests
    that previously used it to get "any working session" must now carry
    an explicit allow-list. These tests do not assert on policy
    enforcement — they exercise the gateway container, second NIC, DNS
    interception path, stop/start persistence, and gateway crash
    recovery. They need the DNS allow-list to let ``nslookup
    google.com`` and ``nslookup example.com`` resolve so the DNS-plane
    assertions don't fall back to NXDOMAIN. No :80 / :443 traffic
    leaves the VM in these tests, so transport-level rules on :443/tcp
    are sufficient — they seed CoreDNS's allow list without opening any
    L7 path.
    """
    policy = {
        "version": "2.0.0",
        "rules": [
            {
                "host": "google.com",
                "port": 443,
                "protocol": "tcp",
                "level": "transport",
            },
            {
                "host": "example.com",
                "port": 443,
                "protocol": "tcp",
                "level": "transport",
            },
        ],
    }
    return write_policy_file(policy)

# ---------------------------------------------------------------------------
# Helpers (file-specific)
# ---------------------------------------------------------------------------


def docker_ps_containers(label_filter: str | None = None) -> list[dict]:
    """Run `docker ps` and return parsed container info.

    If label_filter is provided, filters by that label (e.g.
    'sandbox.session_id=<uuid>').
    """
    args = ["docker", "ps", "--format", "{{json .}}", "--no-trunc"]
    if label_filter:
        args.extend(["--filter", f"label={label_filter}"])
    result = subprocess.run(args, capture_output=True, text=True, timeout=30)
    containers = []
    for line in (result.stdout or "").strip().splitlines():
        line = line.strip()
        if line:
            try:
                containers.append(json.loads(line))
            except json.JSONDecodeError:
                pass
    return containers


def docker_container_running(container_name: str) -> bool:
    """Check if a Docker container is running."""
    result = subprocess.run(
        ["docker", "inspect", "--format", "{{.State.Running}}", container_name],
        capture_output=True, text=True, timeout=30,
    )
    return result.returncode == 0 and result.stdout.strip() == "true"


def docker_container_exists(container_name: str) -> bool:
    """Check if a Docker container exists (running or stopped)."""
    result = subprocess.run(
        ["docker", "inspect", container_name],
        capture_output=True, text=True, timeout=30,
    )
    return result.returncode == 0


def inspect_session_network(sandbox_cli, name: str) -> dict:
    """Fetch a session's backend-neutral network block via `sandbox inspect`.

    `sandbox inspect <name>` emits a JSON array of one ``SessionDto`` per
    argument (one element here). The DTO carries a ``network`` object
    populated by the daemon's ``GET /sessions/{id}`` handler with the
    session's gateway IP, session-side IP, and per-session /28 CIDR —
    same field names for both backends, so backend-parametrized tests
    can read the operationally-equivalent values without backend-shape
    regexes.

    Returns the ``network`` sub-object verbatim. Asserts (rather than
    skipping) on a missing block: the three Y.3 callers all create a
    session and then read its network info, so a missing block here is
    a daemon bug to surface, not a runtime quirk to paper over.
    """
    result = sandbox_cli("inspect", name, timeout=60)
    assert result.returncode == 0, (
        f"sandbox inspect {name} failed (rc={result.returncode}).\n"
        f"stdout: {result.stdout}\nstderr: {result.stderr}"
    )
    payload = json.loads(result.stdout)
    assert isinstance(payload, list) and len(payload) == 1, (
        f"sandbox inspect must emit a JSON array of one element; got: {payload!r}"
    )
    dto = payload[0]
    assert "network" in dto, (
        f"SessionDto must surface a `network` block via inspect; got keys "
        f"{sorted(dto.keys())}"
    )
    net = dto["network"]
    for key in ("gateway_ip", "session_ip", "session_subnet_cidr"):
        assert key in net, (
            f"SessionDto.network missing `{key}`; got keys {sorted(net.keys())}"
        )
    return net


def _ip_in_cidr(ip: str, cidr: str) -> bool:
    """Return True if ``ip`` falls inside ``cidr`` (e.g. ``10.209.0.0/28``).

    Uses the stdlib ``ipaddress`` module so the helper is backend-neutral
    (works for any /N block, not just the Lima-default /28). Imported
    lazily so the import is colocated with its only consumer here, the
    cross-session isolation assertion in ``test_concurrent_sessions``.
    """
    import ipaddress
    return ipaddress.ip_address(ip) in ipaddress.ip_network(cidr, strict=False)


def _probe_gateway_tcp(sandbox_cli, name: str, ip: str, port: int = 53,
                       timeout: int = 30):
    """Backend-neutral L3+L4 reachability probe to the per-session gateway.

    Replaces the legacy ``ping <gateway_ip>`` check used across the
    M3 networking suite. ``ping`` relies on raw ICMP sockets, which
    require ``CAP_NET_RAW`` — but the lite container backend's
    spec-mandated hardening posture drops every Linux capability
    (spec § Hardening line 547: ``--cap-drop ALL``) and § "What this
    breaks" line 561-562 explicitly enumerates ``ping`` as a
    by-design forbidden tool: *"Raw network sockets. ``CAP_NET_RAW``
    dropped; ``ping`` and similar tools fail."* The Lima backend
    runs an unhardened guest where ICMP is fine, but the test must
    work on both backends, so we replace the L3 ICMP probe with an
    L3+L4 TCP probe to a port the gateway always serves.

    Probe primitive: bash's ``</dev/tcp/<ip>/<port>`` builtin. It is
    a pure-bash redirection that opens a TCP socket without needing
    raw-socket capabilities; available unconditionally in the lite
    image (``bash`` installed in the Dockerfile) and the Lima image
    (Ubuntu cloud-init image ships bash). No extra package needed.

    Target port: 53 (CoreDNS, the gateway's DNS listener). The
    gateway's nftables ruleset DNATs TCP/53 to CoreDNS for every
    session (verified structurally by ``test_denied_traffic`` which
    asserts the ``tcp dport 53 dnat`` rule is present), and CoreDNS
    listens on both UDP and TCP 53 by default. So a successful TCP
    connect to ``gateway_ip:53`` is equivalent — for reachability
    purposes — to a successful ``ping``: it round-trips through the
    same nftables DNAT path and the same per-session bridge.

    The outer ``timeout 5`` wrapper bounds the wait when the route
    is unreachable (e.g. the cross-session negative check), so the
    test fails cleanly rather than hanging on an unanswered SYN.
    On success, ``echo OK`` is emitted to stdout — callers assert
    on ``rc == 0`` and ``"OK" in stdout``. On failure, returncode
    is non-zero (124 from ``timeout`` or 1 from bash on connection
    refused / network unreachable).

    The wider ``sandbox_cli`` ``timeout`` argument is the upper
    bound on the whole ``sandbox exec`` round-trip and is set with
    a comfortable margin over the inner 5s probe.
    """
    return sandbox_cli(
        "exec", name, "--",
        "timeout", "5", "bash", "-c",
        f"</dev/tcp/{ip}/{port} && echo OK",
        timeout=timeout,
    )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

@pytest.mark.timeout(600)
def test_gateway_traffic_flow(sandbox_cli, backend):
    """Create a session and verify the full gateway networking pipeline:
    gateway container running, session can reach gateway, DNS works.

    Backend-neutral: gateway IP is read from ``sandbox inspect`` (the
    daemon-side network block populated for both backends from the
    same persisted ``NetworkInfo`` row), not from a regex against
    in-VM ``ip addr`` output.
    """
    session_id = None
    policy_path = None
    try:
        # 1. Create a session with a minimal v2 policy (post-M10-S1
        #    replacement for the legacy --unrestricted flag).
        policy_path = _networking_smoke_policy_file()
        result = sandbox_cli(
            "create",
            *make_create_args(backend, "net-flow-test", "--policy", policy_path),
            timeout=600,
        )
        assert result.returncode == 0, (
            f"sandbox create failed (rc={result.returncode}).\n"
            f"stdout: {result.stdout}\nstderr: {result.stderr}"
        )
        session_id = parse_session_id(result.stdout)
        gw_container = gateway_container_name(session_id)

        wait_for_state(sandbox_cli, "net-flow-test", "Running", timeout=10)

        # 2. Verify gateway container is running.
        assert docker_container_running(gw_container), (
            f"Gateway container {gw_container} is not running.\n"
            f"Docker ps: {subprocess.run(['docker', 'ps', '-a'], capture_output=True, text=True, timeout=30).stdout}"
        )

        # 3. Pull the gateway / session IPs and the session subnet CIDR
        #    from `sandbox inspect`. The daemon's `network` block is
        #    populated from the persisted `NetworkInfo` row for both
        #    backends, so the field names and meanings are the same
        #    regardless of `backend`.
        net = inspect_session_network(sandbox_cli, "net-flow-test")
        gateway_ip = net["gateway_ip"]
        session_ip = net["session_ip"]
        subnet_cidr = net["session_subnet_cidr"]

        assert _ip_in_cidr(session_ip, subnet_cidr), (
            f"session_ip {session_ip} must fall inside the session's "
            f"subnet {subnet_cidr}; inspect block: {net!r}"
        )
        assert _ip_in_cidr(gateway_ip, subnet_cidr), (
            f"gateway_ip {gateway_ip} must fall inside the session's "
            f"subnet {subnet_cidr}; inspect block: {net!r}"
        )

        # 4. Verify the session can reach its gateway IP. Backend-neutral
        #    TCP probe to the gateway's CoreDNS listener (port 53),
        #    replacing the legacy ICMP ping — `CAP_NET_RAW` is dropped on
        #    the lite container backend (spec § Hardening line 561-562),
        #    so ping is by-design unavailable there. See
        #    `_probe_gateway_tcp` for the rationale.
        reach_result = _probe_gateway_tcp(sandbox_cli, "net-flow-test", gateway_ip)
        assert reach_result.returncode == 0 and "OK" in reach_result.stdout, (
            f"Session cannot reach gateway {gateway_ip} (TCP/53).\n"
            f"stdout: {reach_result.stdout}\nstderr: {reach_result.stderr}\n"
            f"{capture_lima_logs(session_id)}"
        )

        # 5. Verify DNS works from the session via gateway's CoreDNS.
        dns_result = sandbox_cli(
            "exec", "net-flow-test", "--",
            "nslookup", "google.com",
            timeout=120,
        )
        assert dns_result.returncode == 0, (
            f"DNS lookup failed inside session.\n"
            f"stdout: {dns_result.stdout}\nstderr: {dns_result.stderr}"
        )
        # nslookup should return at least one address.
        assert re.search(r"Address:\s+\d+\.\d+\.\d+\.\d+", dns_result.stdout), (
            f"DNS lookup did not return an IP address.\n"
            f"nslookup output:\n{dns_result.stdout}"
        )

        # 6. Clean up.
        sandbox_cli("rm", "net-flow-test", timeout=120)
        session_id = None

    finally:
        if session_id is not None:
            sandbox_cli("rm", "net-flow-test", timeout=120)
        if policy_path is not None:
            cleanup_policy_file(policy_path)


@pytest.mark.timeout(600)
def test_denied_traffic(sandbox_cli, backend):
    """Verify nftables blocks direct outbound traffic that bypasses the gateway.

    The gateway container has nftables rules that DNAT all VM traffic through
    the gateway pipeline. Direct connections from the VM to external IPs
    on port ranges not covered by the DNAT rules (or to the cloud metadata
    endpoint) should be blocked.
    """
    session_id = None
    try:
        # 1. Create a session.
        result = sandbox_cli(
            "create", *make_create_args(backend, "net-deny-test"),
            timeout=600,
        )
        assert result.returncode == 0, (
            f"sandbox create failed (rc={result.returncode}).\n"
            f"stdout: {result.stdout}\nstderr: {result.stderr}"
        )
        session_id = parse_session_id(result.stdout)
        wait_for_state(sandbox_cli, "net-deny-test", "Running", timeout=10)

        # 2. Verify the cloud metadata endpoint (169.254.169.254) is blocked.
        #    The DNAT ruleset explicitly drops traffic to this IP.
        #    Use a short timeout so the test doesn't hang.
        metadata_result = sandbox_cli(
            "exec", "net-deny-test", "--",
            "bash", "-c",
            "curl -s --connect-timeout 5 --max-time 10 http://169.254.169.254/ 2>&1; echo EXIT:$?",
            timeout=120,
        )
        # The connection should fail (timeout or connection refused).
        # We check that it did NOT successfully return HTTP content.
        output = metadata_result.stdout
        assert "EXIT:0" not in output, (
            f"Cloud metadata endpoint (169.254.169.254) was reachable but should be blocked.\n"
            f"Output:\n{output}"
        )

        # 3. Structural check: verify nftables rules in the gateway container.
        gw_container = gateway_container_name(session_id)
        nft_result = subprocess.run(
            ["docker", "exec", gw_container, "nft", "list", "ruleset"],
            capture_output=True, text=True, timeout=30,
        )
        assert nft_result.returncode == 0, (
            f"Failed to list nftables rules in gateway container.\n"
            f"stdout: {nft_result.stdout}\nstderr: {nft_result.stderr}"
        )
        nft_rules = nft_result.stdout

        # Verify DNS DNAT rules exist (UDP and TCP port 53 -> CoreDNS).
        assert re.search(r"udp dport 53 dnat", nft_rules), (
            f"Missing UDP DNS DNAT rule in gateway nftables.\n"
            f"nftables output:\n{nft_rules}"
        )
        assert re.search(r"tcp dport 53 dnat", nft_rules), (
            f"Missing TCP DNS DNAT rule in gateway nftables.\n"
            f"nftables output:\n{nft_rules}"
        )

        # Verify non-DNS TCP catch-all DNAT to the deny-logger TCP sink
        # (port 10001). Post-M9-S10 + M10-S3 the ruleset uses an
        # l4proto catch-all (`meta l4proto 6` = TCP) rather than the
        # older `tcp dport != 53` shape, landing non-policy-allowed TCP
        # on the deny-logger for visibility before being rejected.
        assert re.search(r"meta l4proto 6 dnat", nft_rules), (
            f"Missing non-DNS TCP catch-all DNAT (meta l4proto 6) in "
            f"gateway nftables.\nnftables output:\n{nft_rules}"
        )

        # Verify non-DNS UDP catch-all DNAT to the deny-logger UDP sink
        # (port 10002). Same l4proto shape as TCP — the catch-all exists
        # specifically so denied UDP is observed by the deny-logger
        # rather than silently dropped.
        assert re.search(r"meta l4proto 17 dnat", nft_rules), (
            f"Missing non-DNS UDP catch-all DNAT (meta l4proto 17) in "
            f"gateway nftables.\nnftables output:\n{nft_rules}"
        )

        # Verify cloud metadata (169.254.169.254) is blocked in the rules.
        assert "169.254.169.254" in nft_rules and "drop" in nft_rules, (
            f"Missing cloud metadata block rule in gateway nftables.\n"
            f"nftables output:\n{nft_rules}"
        )

        # Verify the forward chain restricts traffic to the gateway IP
        # (not a blanket accept from VM subnet).  After DNAT, legitimate
        # traffic has its destination rewritten to the gateway.  The forward
        # chain should require "ip daddr <gateway_ip>" so non-DNS UDP
        # (which was NOT DNAT'd) gets rejected.
        forward_lines = []
        in_forward = False
        for line in nft_rules.splitlines():
            if "chain forward" in line:
                in_forward = True
            elif in_forward and "}" in line:
                break
            elif in_forward:
                forward_lines.append(line.strip())

        # The forward chain should have "ip daddr" restriction — no blanket accept.
        accept_lines = [l for l in forward_lines if "accept" in l and "saddr" in l]
        for line in accept_lines:
            assert "daddr" in line, (
                f"Forward chain has blanket accept without daddr restriction: {line!r}\n"
                f"Non-DNS UDP would escape the sandbox unproxied.\n"
                f"nftables output:\n{nft_rules}"
            )

        # Note: we do NOT behaviorally test UDP blocking here. UDP is
        # connectionless — nc -u sendto() succeeds immediately before the
        # kernel's ICMP reject arrives, making behavioral assertions unreliable.
        # The structural check above (forward chain requires daddr match)
        # verifies the rules are correct; the kernel enforces them.

        # 4. Clean up.
        sandbox_cli("rm", "net-deny-test", timeout=120)
        session_id = None

    finally:
        if session_id is not None:
            sandbox_cli("rm", "net-deny-test", timeout=120)


@pytest.mark.timeout(600)
def test_dns_interception(sandbox_cli, backend):
    """Verify DNS queries from the VM go through the gateway's CoreDNS.

    Resolve a domain from inside the VM, then check CoreDNS logs in the
    gateway container to confirm the query was intercepted.
    """
    session_id = None
    policy_path = None
    try:
        # 1. Create a session with a minimal v2 policy (post-M10-S1
        #    replacement for the legacy --unrestricted flag).
        policy_path = _networking_smoke_policy_file()
        result = sandbox_cli(
            "create",
            *make_create_args(backend, "net-dns-test", "--policy", policy_path),
            timeout=600,
        )
        assert result.returncode == 0, (
            f"sandbox create failed (rc={result.returncode}).\n"
            f"stdout: {result.stdout}\nstderr: {result.stderr}"
        )
        session_id = parse_session_id(result.stdout)
        gw_container = gateway_container_name(session_id)
        wait_for_state(sandbox_cli, "net-dns-test", "Running", timeout=10)

        # 2. Resolve a distinctive domain from inside the VM.
        #    Use a well-known domain that CoreDNS will definitely forward.
        dns_result = sandbox_cli(
            "exec", "net-dns-test", "--",
            "nslookup", "example.com",
            timeout=120,
        )
        assert dns_result.returncode == 0, (
            f"DNS lookup for example.com failed.\n"
            f"stdout: {dns_result.stdout}\nstderr: {dns_result.stderr}"
        )

        # 3. Check CoreDNS logs for evidence the query was intercepted.
        #    CoreDNS logs to /var/log/gateway/coredns.log inside the container.
        coredns_log_result = subprocess.run(
            [
                "docker", "exec", gw_container,
                "cat", "/var/log/gateway/coredns.log",
            ],
            capture_output=True, text=True, timeout=30,
        )

        # CoreDNS may also log to stdout, captured by docker logs.
        docker_logs_result = subprocess.run(
            ["docker", "logs", "--tail", "100", gw_container],
            capture_output=True, text=True, timeout=30,
        )

        # Combine all log sources and look for evidence of the DNS query.
        all_logs = "\n".join([
            coredns_log_result.stdout or "",
            coredns_log_result.stderr or "",
            docker_logs_result.stdout or "",
            docker_logs_result.stderr or "",
        ])

        # CoreDNS logs queries in its log plugin format, typically containing
        # the queried domain name.
        assert "example.com" in all_logs.lower(), (
            f"CoreDNS logs do not contain 'example.com'.\n"
            f"CoreDNS log file:\n{coredns_log_result.stdout}\n"
            f"Docker logs:\n{docker_logs_result.stdout}\n"
            f"Docker logs stderr:\n{docker_logs_result.stderr}"
        )

        # 4. Clean up.
        sandbox_cli("rm", "net-dns-test", timeout=120)
        session_id = None

    finally:
        if session_id is not None:
            sandbox_cli("rm", "net-dns-test", timeout=120)


@pytest.mark.timeout(600)
def test_stop_start_with_networking(sandbox_cli, backend):
    """Create a session, verify networking, stop, verify gateway gone,
    start, verify persistence and networking restoration.

    Backend-neutral: gateway IP is read from ``sandbox inspect`` (M11-S7
    Bundle Y / todo #72) so the same assertion shape works for both
    Lima and container sessions.
    """
    session_id = None
    policy_path = None
    try:
        # 1. Create a session with a minimal v2 policy (post-M10-S1
        #    replacement for the legacy --unrestricted flag).
        policy_path = _networking_smoke_policy_file()
        result = sandbox_cli(
            "create",
            *make_create_args(backend, "net-restart-test", "--policy", policy_path),
            timeout=600,
        )
        assert result.returncode == 0, (
            f"sandbox create failed (rc={result.returncode}).\n"
            f"stdout: {result.stdout}\nstderr: {result.stderr}"
        )
        session_id = parse_session_id(result.stdout)
        gw_container = gateway_container_name(session_id)
        wait_for_state(sandbox_cli, "net-restart-test", "Running", timeout=10)

        # 2. Pull the gateway IP from `sandbox inspect`. The daemon
        #    surfaces a backend-neutral `network` block populated from
        #    the persisted `NetworkInfo` row; we use it instead of an
        #    in-VM `ip addr` regex so the test runs on both backends.
        net = inspect_session_network(sandbox_cli, "net-restart-test")
        gateway_ip = net["gateway_ip"]
        subnet_cidr = net["session_subnet_cidr"]
        assert _ip_in_cidr(gateway_ip, subnet_cidr), (
            f"gateway_ip {gateway_ip} must fall inside session's "
            f"subnet {subnet_cidr}; inspect block: {net!r}"
        )

        # 3. Write a file inside VM to verify persistence across stop/start.
        #    Use home dir, not /tmp (tmpfs, cleared on reboot).
        test_file = "/home/agent/net-persist-test.txt"
        write_result = sandbox_cli(
            "exec", "net-restart-test", "--",
            "bash", "-c", f"echo net-persist-marker > {test_file}",
            timeout=120,
        )
        assert write_result.returncode == 0, (
            f"Failed to write file in VM.\n"
            f"stdout: {write_result.stdout}\nstderr: {write_result.stderr}"
        )

        # 4. Stop the session.
        stop_result = sandbox_cli("stop", "net-restart-test", timeout=120)
        assert stop_result.returncode == 0, (
            f"sandbox stop failed (rc={stop_result.returncode}).\n"
            f"stdout: {stop_result.stdout}\nstderr: {stop_result.stderr}"
        )
        wait_for_state(sandbox_cli, "net-restart-test", "Stopped", timeout=30)

        # 5. Verify gateway container is gone after stop.
        assert not docker_container_running(gw_container), (
            f"Gateway container {gw_container} is still running after stop."
        )

        # 6. Start the session.
        start_result = sandbox_cli("start", "net-restart-test", timeout=600)
        assert start_result.returncode == 0, (
            f"sandbox start failed (rc={start_result.returncode}).\n"
            f"stdout: {start_result.stdout}\nstderr: {start_result.stderr}"
        )
        wait_for_state(sandbox_cli, "net-restart-test", "Running", timeout=10)

        # 7. Verify the file persists.
        read_result = sandbox_cli(
            "exec", "net-restart-test", "--", "cat", test_file,
            timeout=120,
        )
        assert read_result.returncode == 0, (
            f"Failed to read file after restart.\n"
            f"stdout: {read_result.stdout}\nstderr: {read_result.stderr}"
        )
        assert read_result.stdout.strip() == "net-persist-marker", (
            f"File contents mismatch. "
            f"Expected 'net-persist-marker', got: {read_result.stdout.strip()!r}"
        )

        # 8. Verify networking works again: TCP-probe the gateway. Also
        #    re-pull the network block via `sandbox inspect` and assert
        #    it surfaces the same gateway IP / subnet — the daemon
        #    re-uses the same persisted /28 block on stop/start
        #    (NetworkManager keeps the subnet allocation across the
        #    pair of `delete_network`/`ensure_network` calls), so any
        #    drift here is a daemon-side regression. The reachability
        #    probe targets gateway TCP/53 (CoreDNS) instead of ICMP
        #    ping; the lite container backend drops `CAP_NET_RAW` per
        #    spec § Hardening line 561-562, so ping is by-design
        #    unavailable there. See `_probe_gateway_tcp` for the
        #    rationale.
        post_restart_net = inspect_session_network(sandbox_cli, "net-restart-test")
        assert post_restart_net["gateway_ip"] == gateway_ip, (
            f"gateway IP changed across stop/start: "
            f"pre={gateway_ip!r}, post={post_restart_net['gateway_ip']!r}"
        )
        assert post_restart_net["session_subnet_cidr"] == subnet_cidr, (
            f"session subnet changed across stop/start: "
            f"pre={subnet_cidr!r}, post={post_restart_net['session_subnet_cidr']!r}"
        )
        reach_result = _probe_gateway_tcp(sandbox_cli, "net-restart-test", gateway_ip)
        assert reach_result.returncode == 0 and "OK" in reach_result.stdout, (
            f"Session cannot reach gateway {gateway_ip} (TCP/53) after restart.\n"
            f"stdout: {reach_result.stdout}\nstderr: {reach_result.stderr}"
        )

        # 9. Verify DNS works after restart.
        dns_result = sandbox_cli(
            "exec", "net-restart-test", "--",
            "nslookup", "google.com",
            timeout=120,
        )
        assert dns_result.returncode == 0, (
            f"DNS lookup failed after restart.\n"
            f"stdout: {dns_result.stdout}\nstderr: {dns_result.stderr}"
        )

        # 10. Clean up.
        sandbox_cli("rm", "net-restart-test", timeout=120)
        session_id = None

    finally:
        if session_id is not None:
            sandbox_cli("rm", "net-restart-test", timeout=120)
        if policy_path is not None:
            cleanup_policy_file(policy_path)


@pytest.mark.timeout(600)
def test_concurrent_sessions(sandbox_cli, backend):
    """Create two sessions and verify network isolation.

    Backend-neutral isolation property (M11-S7 Bundle Y / todo #72):

    * Session A's session/gateway IPs are NOT inside session B's
      subnet (and vice versa) — each session lives in a distinct /28
      block, regardless of whether the underlying carrier is a Lima
      Docker bridge or a per-session ``sandbox-net-<id>`` container
      network.
    * Both sessions can reach their own gateway.
    * Session A cannot reach session B's gateway — the per-session
      subnets are isolated, so routing between them must not exist.
      (Behaviourally exercised on Lima only; on the container backend
      the gateway DNAT prerouting rewrites every TCP/UDP packet from
      the session's own saddr, so cross-session L4 isolation is
      invisible from inside the session — see step 7's in-line
      comment for the full rationale.)

    Subnet shape (the old ``10.209.x.x/28`` Lima-pool regex) is no
    longer asserted here; the daemon owns the subnet allocator and
    `sandbox inspect` surfaces whatever it picked per backend.
    """
    # RAM precondition is Lima-only: the test boots two Lima VMs at 2 GB
    # each, so a 6 GB host floor is required. Container sessions are tens
    # of MB and have no such precondition; gating the check on
    # backend == "lima" keeps the container parameterization runnable on
    # memory-constrained hosts.
    if backend == "lima" and (
        os.sysconf("SC_PAGE_SIZE") * os.sysconf("SC_PHYS_PAGES") < 6 * 1024**3
    ):
        pytest.skip("Requires >= 6GB RAM for concurrent Lima VMs")
    session_id_a = None
    session_id_b = None
    try:
        # 1. Create first session.
        result_a = sandbox_cli(
            "create", *make_create_args(backend, "net-multi-a"),
            timeout=600,
        )
        assert result_a.returncode == 0, (
            f"sandbox create (session A) failed (rc={result_a.returncode}).\n"
            f"stdout: {result_a.stdout}\nstderr: {result_a.stderr}"
        )
        session_id_a = parse_session_id(result_a.stdout)
        wait_for_state(sandbox_cli, "net-multi-a", "Running", timeout=10)

        # 2. Create second session.
        result_b = sandbox_cli(
            "create", *make_create_args(backend, "net-multi-b"),
            timeout=600,
        )
        assert result_b.returncode == 0, (
            f"sandbox create (session B) failed (rc={result_b.returncode}).\n"
            f"stdout: {result_b.stdout}\nstderr: {result_b.stderr}"
        )
        session_id_b = parse_session_id(result_b.stdout)
        wait_for_state(sandbox_cli, "net-multi-b", "Running", timeout=10)

        # 3. Pull the network block for each session via `sandbox inspect`.
        net_a = inspect_session_network(sandbox_cli, "net-multi-a")
        net_b = inspect_session_network(sandbox_cli, "net-multi-b")
        gw_ip_a = net_a["gateway_ip"]
        gw_ip_b = net_b["gateway_ip"]
        session_ip_a = net_a["session_ip"]
        session_ip_b = net_b["session_ip"]
        subnet_a = net_a["session_subnet_cidr"]
        subnet_b = net_b["session_subnet_cidr"]

        # 4. Self-consistency: each session's gateway / session IP
        #    must fall inside its own subnet.
        assert _ip_in_cidr(session_ip_a, subnet_a) and _ip_in_cidr(gw_ip_a, subnet_a), (
            f"session A's IPs do not fall inside its subnet; "
            f"network block: {net_a!r}"
        )
        assert _ip_in_cidr(session_ip_b, subnet_b) and _ip_in_cidr(gw_ip_b, subnet_b), (
            f"session B's IPs do not fall inside its subnet; "
            f"network block: {net_b!r}"
        )

        # 5. Subnet-isolation property: session A's IPs must NOT fall
        #    inside session B's subnet (and vice versa). Replaces the
        #    old `10.209.x.x/28`-shaped block-index comparison with a
        #    backend-neutral CIDR-membership check.
        assert subnet_a != subnet_b, (
            f"Both sessions landed in the same subnet: {subnet_a!r}"
        )
        assert not _ip_in_cidr(session_ip_a, subnet_b), (
            f"Session A's session_ip {session_ip_a} falls inside session B's "
            f"subnet {subnet_b}; subnets must be disjoint."
        )
        assert not _ip_in_cidr(gw_ip_a, subnet_b), (
            f"Session A's gateway_ip {gw_ip_a} falls inside session B's "
            f"subnet {subnet_b}; subnets must be disjoint."
        )
        assert not _ip_in_cidr(session_ip_b, subnet_a), (
            f"Session B's session_ip {session_ip_b} falls inside session A's "
            f"subnet {subnet_a}; subnets must be disjoint."
        )
        assert not _ip_in_cidr(gw_ip_b, subnet_a), (
            f"Session B's gateway_ip {gw_ip_b} falls inside session A's "
            f"subnet {subnet_a}; subnets must be disjoint."
        )

        # 6. Verify both can reach their respective gateways. TCP probe
        #    to the gateway's CoreDNS listener (port 53), replacing the
        #    legacy ICMP ping — `CAP_NET_RAW` is dropped on the lite
        #    container backend (spec § Hardening line 561-562), so ping
        #    is by-design unavailable there. See `_probe_gateway_tcp`
        #    for the rationale.
        reach_a = _probe_gateway_tcp(sandbox_cli, "net-multi-a", gw_ip_a)
        assert reach_a.returncode == 0 and "OK" in reach_a.stdout, (
            f"Session A cannot reach its gateway {gw_ip_a} (TCP/53).\n"
            f"stdout: {reach_a.stdout}\nstderr: {reach_a.stderr}"
        )

        reach_b = _probe_gateway_tcp(sandbox_cli, "net-multi-b", gw_ip_b)
        assert reach_b.returncode == 0 and "OK" in reach_b.stdout, (
            f"Session B cannot reach its gateway {gw_ip_b} (TCP/53).\n"
            f"stdout: {reach_b.stdout}\nstderr: {reach_b.stderr}"
        )

        # 7. Verify no cross-session traffic: session A cannot reach
        #    session B's gateway. The per-session subnets are isolated,
        #    so routing between them must not exist.
        #
        #    Lima-only: the gateway's prerouting nftables ruleset
        #    (``sandbox-core/src/gateway.rs:1462-1486``) DNATs every
        #    TCP/UDP packet originating from the session's VM subnet
        #    to one of three local sinks (CoreDNS for dport 53, Envoy
        #    for policy-allowed (ip,port) pairs, deny-logger for
        #    everything else) on A's *own* gateway IP. So a TCP probe
        #    from session A to session B's gateway IP gets its
        #    destination rewritten by A's gateway before the packet
        #    ever leaves A's bridge — the connect succeeds against A's
        #    deny-logger / CoreDNS regardless of whether B's bridge is
        #    actually reachable, making behavioural cross-session
        #    isolation untestable via TCP. ICMP is not DNAT'd by these
        #    rules so a Lima ping cleanly observes the
        #    no-route-to-host outcome, but the lite container backend
        #    drops ``CAP_NET_RAW`` (spec § Hardening line 561-562) and
        #    has no working ICMP path. The structural disjoint-subnet
        #    check at step 5 above is the architecturally-binding
        #    contract on both backends; behavioural isolation
        #    coverage is retained via Lima only.
        if backend == "lima":
            cross_ping = sandbox_cli(
                "exec", "net-multi-a", "--",
                "ping", "-c", "2", "-W", "3", gw_ip_b,
                timeout=120,
            )
            assert cross_ping.returncode != 0, (
                f"Session A should NOT be able to reach session B's gateway "
                f"{gw_ip_b}, but ping succeeded.\n"
                f"stdout: {cross_ping.stdout}\nstderr: {cross_ping.stderr}"
            )

        # 8. Clean up both sessions.
        sandbox_cli("rm", "net-multi-a", timeout=120)
        session_id_a = None
        sandbox_cli("rm", "net-multi-b", timeout=120)
        session_id_b = None

    finally:
        if session_id_a is not None:
            sandbox_cli("rm", "net-multi-a", timeout=120)
        if session_id_b is not None:
            sandbox_cli("rm", "net-multi-b", timeout=120)


@pytest.mark.timeout(600)
def test_daemon_restart_recovery(sandbox_binaries, sandbox_daemon, sandbox_cli, backend):
    """Create a session, kill the daemon, restart it, verify the session
    is recovered and functional.
    """
    session_id = None
    restarted_proc = None
    try:
        # 1. Create a session.
        result = sandbox_cli(
            "create", *make_create_args(backend, "net-daemon-test"),
            timeout=600,
        )
        assert result.returncode == 0, (
            f"sandbox create failed (rc={result.returncode}).\n"
            f"stdout: {result.stdout}\nstderr: {result.stderr}"
        )
        session_id = parse_session_id(result.stdout)
        wait_for_state(sandbox_cli, "net-daemon-test", "Running", timeout=10)

        # 2. Kill the daemon process.
        daemon_proc = sandbox_daemon["process"]
        socket_path = sandbox_daemon["socket"]
        base_dir = sandbox_daemon["base_dir"]

        daemon_proc.send_signal(signal.SIGKILL)
        daemon_proc.wait(timeout=10)
        assert daemon_proc.poll() is not None, "Daemon did not die after SIGKILL"

        # Wait briefly for the socket to be cleaned up.
        time.sleep(1)

        # 3. Restart the daemon with the same socket and base-dir.
        #    The daemon should reconcile state from the session store and
        #    Lima VM inventory on startup.
        #
        #    Redirect stdout/stderr to the existing daemon log files so the
        #    restarted daemon doesn't deadlock on a full pipe buffer once the
        #    session-scoped fixture adopts it for the rest of the suite.
        stdout_log = sandbox_daemon["_stdout_log"]
        stderr_log = sandbox_daemon["_stderr_log"]
        new_stdout_fh = open(stdout_log, "a")
        new_stderr_fh = open(stderr_log, "a")
        restarted_proc = subprocess.Popen(
            [
                str(sandbox_binaries.sandboxd),
                "--socket", socket_path,
                "--base-dir", base_dir,
            ],
            stdout=new_stdout_fh,
            stderr=new_stderr_fh,
        )

        # Wait for the new socket to appear.
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            if os.path.exists(socket_path):
                break
            if restarted_proc.poll() is not None:
                new_stdout_fh.close()
                new_stderr_fh.close()
                pytest.fail(
                    f"Restarted daemon exited early (code {restarted_proc.returncode}).\n"
                    f"stdout: {stdout_log.read_text()}\n"
                    f"stderr: {stderr_log.read_text()}"
                )
            time.sleep(0.2)
        else:
            restarted_proc.kill()
            new_stdout_fh.close()
            new_stderr_fh.close()
            pytest.fail("Restarted daemon socket did not appear within 15s")

        # Allow time for reconciliation (gateway restart, network restoration).
        time.sleep(5)

        # 4. Verify session is recovered: ps shows it as Running.
        ps_result = sandbox_cli("ps")
        assert ps_result.returncode == 0
        found = False
        for line in ps_result.stdout.splitlines():
            if "net-daemon-test" in line and "Running" in line:
                found = True
                break
        assert found, (
            f"Session net-daemon-test not found in Running state after "
            f"daemon restart.\nps output:\n{ps_result.stdout}"
        )

        # 5. Verify we can exec commands in the recovered session.
        exec_result = sandbox_cli(
            "exec", "net-daemon-test", "--", "uname", "-a",
            timeout=120,
        )
        assert exec_result.returncode == 0, (
            f"exec failed on recovered session.\n"
            f"stdout: {exec_result.stdout}\nstderr: {exec_result.stderr}"
        )
        assert "Linux" in exec_result.stdout

        # 6. Clean up.
        sandbox_cli("rm", "net-daemon-test", timeout=120)
        session_id = None

        # 7. Hand the restarted daemon back to the session-scoped fixture so
        #    subsequent tests (and fixture teardown) use the live process.
        sandbox_daemon["process"] = restarted_proc
        sandbox_daemon["_stdout_fh"] = new_stdout_fh
        sandbox_daemon["_stderr_fh"] = new_stderr_fh
        restarted_proc = None  # prevent finally from killing it

    finally:
        if session_id is not None:
            sandbox_cli("rm", "net-daemon-test", timeout=120)

        # Ensure a live daemon exists for subsequent tests.  If the handoff
        # already happened (restarted_proc is None), the fixture is fine.
        # Otherwise we need to either adopt the restarted proc or start a
        # fresh one so the session-scoped daemon isn't left dead.
        if restarted_proc is not None:
            if restarted_proc.poll() is None:
                # Restarted daemon is alive but wasn't handed off — adopt it.
                sandbox_daemon["process"] = restarted_proc
            else:
                # Restarted daemon also died.  Start a fresh one.
                restarted_proc = None  # fall through to recovery below

        # If the daemon (original or restarted) is dead, start a fresh one
        # so subsequent tests don't cascade-fail.  Redirect output to the
        # existing log files (see comment in step 3 for rationale).
        if sandbox_daemon["process"].poll() is not None:
            fresh_stdout_fh = open(sandbox_daemon["_stdout_log"], "a")
            fresh_stderr_fh = open(sandbox_daemon["_stderr_log"], "a")
            fresh_proc = subprocess.Popen(
                [
                    str(sandbox_binaries.sandboxd),
                    "--socket", sandbox_daemon["socket"],
                    "--base-dir", sandbox_daemon["base_dir"],
                ],
                stdout=fresh_stdout_fh,
                stderr=fresh_stderr_fh,
            )
            deadline = time.monotonic() + 15
            while time.monotonic() < deadline:
                if os.path.exists(sandbox_daemon["socket"]):
                    break
                if fresh_proc.poll() is not None:
                    break
                time.sleep(0.2)
            sandbox_daemon["process"] = fresh_proc
            sandbox_daemon["_stdout_fh"] = fresh_stdout_fh
            sandbox_daemon["_stderr_fh"] = fresh_stderr_fh


@pytest.mark.timeout(600)
def test_gateway_crash_recovery(sandbox_cli, backend):
    """Kill the gateway container and verify the daemon's background monitor
    detects and restarts it within the poll interval (30 seconds).
    """
    session_id = None
    policy_path = None
    try:
        # 1. Create a session with a minimal v2 policy (post-M10-S1
        #    replacement for the legacy --unrestricted flag).
        policy_path = _networking_smoke_policy_file()
        result = sandbox_cli(
            "create",
            *make_create_args(backend, "net-gwcrash-test", "--policy", policy_path),
            timeout=600,
        )
        assert result.returncode == 0, (
            f"sandbox create failed (rc={result.returncode}).\n"
            f"stdout: {result.stdout}\nstderr: {result.stderr}"
        )
        session_id = parse_session_id(result.stdout)
        gw_container = gateway_container_name(session_id)
        wait_for_state(sandbox_cli, "net-gwcrash-test", "Running", timeout=10)

        # 2. Verify gateway is initially running.
        assert docker_container_running(gw_container), (
            f"Gateway container {gw_container} is not running before kill test."
        )

        # 3. Record the container's creation time so we can detect a new one.
        inspect_result = subprocess.run(
            ["docker", "inspect", "--format", "{{.Id}}", gw_container],
            capture_output=True, text=True, timeout=30,
        )
        old_container_id = inspect_result.stdout.strip()

        # 4. Kill the gateway container.
        kill_result = subprocess.run(
            ["docker", "kill", gw_container],
            capture_output=True, text=True, timeout=30,
        )
        assert kill_result.returncode == 0, (
            f"docker kill failed.\n"
            f"stdout: {kill_result.stdout}\nstderr: {kill_result.stderr}"
        )

        # 5. Wait for crash recovery.  The daemon's gateway_monitor polls
        #    every 30 seconds.  We wait up to 90 seconds to allow for
        #    poll timing plus the restart sequence (component readiness).
        #
        #    The daemon may recover so quickly that the container is already
        #    running again before we can observe it being dead.  Instead of
        #    asserting the container is dead (race-prone), we wait for a NEW
        #    container to appear -- identified by a different container ID.
        recovered = False
        deadline = time.monotonic() + 90
        while time.monotonic() < deadline:
            # The recovered container will have the same name because
            # restart_gateway removes the old one and creates a fresh one.
            if docker_container_running(gw_container):
                new_inspect = subprocess.run(
                    ["docker", "inspect", "--format", "{{.Id}}", gw_container],
                    capture_output=True, text=True, timeout=30,
                )
                new_container_id = new_inspect.stdout.strip()
                if new_container_id != old_container_id:
                    recovered = True
                    break
            time.sleep(5)

        assert recovered, (
            f"Gateway container {gw_container} was not recreated within 90s.\n"
            f"Old container ID: {old_container_id}\n"
            f"docker ps -a:\n"
            f"{subprocess.run(['docker', 'ps', '-a'], capture_output=True, text=True, timeout=30).stdout}"
        )

        # 5. Verify networking works again after recovery.
        #    Give the gateway a moment to finish nftables injection.
        time.sleep(5)

        # Pull the gateway IP from `sandbox inspect` (M11-S7 Bundle Y /
        # todo #72) — the daemon-side `network` block populated from the
        # persisted `NetworkInfo` row works for both backends, replacing
        # the legacy in-VM `ip -4 addr show` regex against
        # `10.209.x.x/28` plus octet arithmetic that this test used to
        # carry. Brings this test in line with its three Bundle Y
        # siblings (`test_gateway_traffic_flow`,
        # `test_stop_start_with_networking`, `test_concurrent_sessions`).
        net = inspect_session_network(sandbox_cli, "net-gwcrash-test")
        gateway_ip = net["gateway_ip"]

        # Verify the session can reach its gateway after crash recovery.
        # Backend-neutral TCP probe to gateway TCP/53 (CoreDNS) — replaces
        # the prior backend-conditional ping (skipped on container per
        # spec § Hardening line 561-562: `CAP_NET_RAW` dropped, ping
        # by-design fails on the lite container backend). The TCP probe
        # works on both backends without raw sockets; see
        # `_probe_gateway_tcp` for the rationale.
        probe_result = _probe_gateway_tcp(
            sandbox_cli, "net-gwcrash-test", gateway_ip,
        )
        assert probe_result.returncode == 0 and "OK" in probe_result.stdout, (
            f"Gateway TCP/53 not reachable after crash recovery (backend={backend}, "
            f"gw={gateway_ip}).\n"
            f"stdout: {probe_result.stdout}\nstderr: {probe_result.stderr}"
        )

        # Verify DNS works after recovery.
        dns_result = sandbox_cli(
            "exec", "net-gwcrash-test", "--",
            "nslookup", "google.com",
            timeout=120,
        )
        assert dns_result.returncode == 0, (
            f"DNS lookup failed after gateway crash recovery.\n"
            f"stdout: {dns_result.stdout}\nstderr: {dns_result.stderr}"
        )

        # 6. Clean up.
        sandbox_cli("rm", "net-gwcrash-test", timeout=120)
        session_id = None

    finally:
        if session_id is not None:
            sandbox_cli("rm", "net-gwcrash-test", timeout=120)
        if policy_path is not None:
            cleanup_policy_file(policy_path)
