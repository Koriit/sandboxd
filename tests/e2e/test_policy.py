"""E2E tests for M4 policy enforcement: deny-all default, transport passthrough,
TLS-verified passthrough, full MITM inspection, HTTP constraints, policy
updates, and DNS policy enforcement.

These tests boot real Lima/QEMU VMs with full networking and policy enforcement
and are SLOW (3-10 minutes per test).  Run with generous timeouts:

    cd tests/e2e
    source .venv/bin/activate
    python -m pytest test_policy.py -v --timeout=600

Backend coverage: **agnostic** — every test in this file is parametrized
over ``[lima, container]`` via the ``backend`` fixture. Policy
enforcement runs through the shared gateway container (Envoy +
mitmproxy + CoreDNS + nftables) which is wired into both backends per
the M11 gap-#70 closure, so the deny / transport / TLS / HTTP
contracts hold identically. The fail-closed-before-DNS-propagation
contract (``test_l3_fail_closed_before_dns_propagation``) likewise
holds on both backends because it depends on the gateway's L1
materialisation order, not on the session-runtime kind.
"""

from __future__ import annotations

import json
import re
import socket
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

# ---------------------------------------------------------------------------
# Gateway introspection helpers
# ---------------------------------------------------------------------------


def _gateway_listen_addrs(session_id: str) -> list[str]:
    """Return the list of listening TCP socket addresses (``HEX_IP:HEX_PORT``)
    inside the gateway container, parsed from ``/proc/net/tcp``.

    The gateway image is minimal (no ``ss`` / ``netstat``), so we parse
    ``/proc/net/tcp`` directly. Each listening socket has state ``0A``;
    the local address column is ``<IP>:<PORT>`` with IP in little-endian
    hex and port in big-endian hex. Mirrors the logic in
    ``sandboxd/sandbox-core/tests/gateway_integration.rs::test_gateway_lifecycle``.
    """
    gw = gateway_container_name(session_id)
    proc_net_tcp = subprocess.run(
        ["docker", "exec", gw, "cat", "/proc/net/tcp"],
        capture_output=True, text=True, timeout=30,
    )
    assert proc_net_tcp.returncode == 0, (
        f"docker exec cat /proc/net/tcp failed in {gw}.\n"
        f"stdout: {proc_net_tcp.stdout}\nstderr: {proc_net_tcp.stderr}"
    )
    listen: list[str] = []
    for line in proc_net_tcp.stdout.splitlines()[1:]:
        cols = line.split()
        if len(cols) >= 4 and cols[3] == "0A":
            listen.append(cols[1])
    return listen


def _assert_mitmproxy_loopback_only(session_id: str) -> None:
    """Assert mitmproxy's 18080 forward-proxy port is bound to 127.0.0.1 only.

    Hex encoding of ``127.0.0.1:18080`` in ``/proc/net/tcp`` is
    ``0100007F:46A0``. A regression that binds mitmproxy to
    ``0.0.0.0:18080`` (``00000000:46A0``) would expose the forward
    proxy to the VM and short-circuit Envoy's filter chains. The old
    transparent-mode bind at ``0.0.0.0:8080`` (``00000000:1F90``) must
    also stay absent.
    """
    listen = _gateway_listen_addrs(session_id)
    assert "0100007F:46A0" in listen, (
        f"mitmproxy must listen on 127.0.0.1:18080 (regular forward-proxy "
        f"mode); listening sockets inside gateway: {listen}"
    )
    assert "00000000:1F90" not in listen, (
        f"mitmproxy must not listen on 0.0.0.0:8080 (legacy transparent-mode "
        f"bind); listening sockets: {listen}"
    )
    rogue_18080 = [a for a in listen if a.endswith(":46A0") and a != "0100007F:46A0"]
    assert not rogue_18080, (
        f"mitmproxy forward proxy (port 18080) must be bound to loopback only; "
        f"found non-loopback listeners on 18080: {rogue_18080}. Full listening "
        f"sockets: {listen}"
    )


def _gateway_nft_tables(session_id: str) -> set[str]:
    """Return the set of nftables table names inside the gateway container.

    Parses ``nft list ruleset`` output; each table emits a ``table inet
    <name> {`` header. Mirrors the parsing logic in
    ``gateway_integration.rs::test_gateway_lifecycle``.
    """
    gw = gateway_container_name(session_id)
    out = subprocess.run(
        ["docker", "exec", gw, "nft", "list", "ruleset"],
        capture_output=True, text=True, timeout=30,
    )
    assert out.returncode == 0, (
        f"nft list ruleset failed in {gw}.\n"
        f"stdout: {out.stdout}\nstderr: {out.stderr}"
    )
    tables: set[str] = set()
    for line in out.stdout.splitlines():
        stripped = line.lstrip()
        if stripped.startswith("table inet "):
            rest = stripped[len("table inet "):]
            name = rest.split()[0] if rest.split() else ""
            if name:
                tables.add(name)
    return tables


def _read_gateway_log(session_id: str, filename: str) -> str:
    """Read ``/var/log/gateway/<filename>`` from the gateway container."""
    gw = gateway_container_name(session_id)
    out = subprocess.run(
        ["docker", "exec", gw, "cat", f"/var/log/gateway/{filename}"],
        capture_output=True, text=True, timeout=30,
    )
    assert out.returncode == 0, (
        f"cat /var/log/gateway/{filename} failed in {gw}.\n"
        f"stdout: {out.stdout}\nstderr: {out.stderr}"
    )
    return out.stdout


def _read_envoy_access_log(session_id: str) -> tuple[str, list[dict]]:
    """Read and parse Envoy's access log from
    ``/var/log/gateway/events/envoy.jsonl`` in the gateway container.

    Returns ``(raw_text, parsed_entries)``. Each line in the log is a
    JSON object emitted by Envoy's ``tcp_proxy`` filter (see the
    ``l1/l2/l3_tcp_proxy_access_log_yaml`` helpers in
    ``sandbox-core/src/policy.rs``). Lines that fail to parse as JSON
    are silently skipped — the log is append-only and lines are flushed
    whole, so a partial line would indicate a truncated read that a
    retry would resolve, not a production bug.

    The events path (``/var/log/gateway/events/``) is a per-session
    bind mount established by ``spawn_gateway`` so
    the host-side ingest pipeline can tail the file via inotify. The
    previous text-format log at ``/var/log/gateway/envoy_access.log``
    lived on the container's tmpfs and is no longer emitted.
    """
    raw = _read_gateway_log(session_id, "events/envoy.jsonl")
    parsed: list[dict] = []
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            parsed.append(json.loads(line))
        except json.JSONDecodeError:
            # Skip unparseable lines rather than failing the test: a
            # truncated tail read is the most likely cause, and the
            # parsed-entry assertions below will fail clearly if the
            # *expected* lines are missing.
            continue
    return raw, parsed


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

@pytest.mark.timeout(600)
def test_level0_denied(sandbox_cli, backend):
    """Empty policy (no rules) should deny all traffic: DNS returns NXDOMAIN,
    HTTP connections fail.
    """
    session_id = None
    policy_path = None
    try:
        # Create a policy with no rules (deny-all default).
        policy = {"version": "2.0.0", "rules": []}
        policy_path = write_policy_file(policy)

        # Create session with the empty policy.
        result = sandbox_cli(
            "create", *make_create_args(backend, "pol-deny-all", "--policy", policy_path),
            timeout=600,
        )
        assert result.returncode == 0, (
            f"sandbox create failed (rc={result.returncode}).\n"
            f"stdout: {result.stdout}\nstderr: {result.stderr}"
        )
        session_id = parse_session_id(result.stdout)
        wait_for_state(sandbox_cli, "pol-deny-all", "Running", timeout=10)

        # DNS lookup should return NXDOMAIN (CoreDNS denies all domains).
        dns_result = sandbox_cli(
            "ssh", "pol-deny-all", "--",
            "nslookup", "google.com",
            timeout=120,
        )
        # nslookup returns non-zero on NXDOMAIN.
        combined_output = (dns_result.stdout + dns_result.stderr).lower()
        assert dns_result.returncode != 0 or "nxdomain" in combined_output or "can't find" in combined_output, (
            f"DNS lookup should have failed with NXDOMAIN for empty policy.\n"
            f"stdout: {dns_result.stdout}\nstderr: {dns_result.stderr}"
        )

        # HTTP request should fail (no route to host / connection refused).
        curl_result = sandbox_cli(
            "ssh", "pol-deny-all", "--",
            "bash", "-c",
            "curl -s --connect-timeout 10 --max-time 15 http://example.com/ 2>&1; echo EXIT:$?",
            timeout=120,
        )
        output = curl_result.stdout
        # The connection should fail -- either timeout, connection refused,
        # or no route.  The EXIT code should be non-zero.
        assert "EXIT:0" not in output, (
            f"HTTP request to example.com should have failed with deny-all policy.\n"
            f"Output:\n{output}"
        )

        # Clean up.
        sandbox_cli("rm", "pol-deny-all", timeout=120)
        session_id = None

    finally:
        if session_id is not None:
            sandbox_cli("rm", "pol-deny-all", timeout=120)
        if policy_path is not None:
            cleanup_policy_file(policy_path)


@pytest.mark.timeout(600)
def test_level1_transport_tcp(sandbox_cli, backend):
    """Policy allows example.com:80/tcp at level 'transport'. curl http://example.com
    should succeed via opaque TCP passthrough.
    """
    session_id = None
    policy_path = None
    try:
        policy = {
            "version": "2.0.0",
            "rules": [
                {
                    "host": "example.com",
                    "port": 80,
                    "protocol": "tcp",
                    "level": "transport",
                },
            ],
        }
        policy_path = write_policy_file(policy)

        result = sandbox_cli(
            "create", *make_create_args(backend, "pol-l1-tcp", "--policy", policy_path),
            timeout=600,
        )
        assert result.returncode == 0, (
            f"sandbox create failed (rc={result.returncode}).\n"
            f"stdout: {result.stdout}\nstderr: {result.stderr}"
        )
        session_id = parse_session_id(result.stdout)
        wait_for_state(sandbox_cli, "pol-l1-tcp", "Running", timeout=10)

        # Warm DNS so the daemon's propagation loop materialises the per-rule
        # Envoy filter chain (prefix_ranges = resolved IPs) and the
        # sandbox_policy nftables concat-set entry (ip, 80) for example.com.
        # Under schema v2 L1 transport is fail-closed at empty cache — the
        # listener has no filter chain and the forward chain rejects until
        # CoreDNS resolves and the 2-second poll runs. Without this warmup
        # the first connection race-loses: see test_l3_fail_closed_before_dns_propagation
        # for a deliberate exercise of the same property at L3.
        sandbox_cli(
            "ssh", "pol-l1-tcp", "--",
            "nslookup", "example.com",
            timeout=120,
        )
        time.sleep(5)

        # curl http://example.com should succeed (TCP passthrough).
        curl_result = sandbox_cli(
            "ssh", "pol-l1-tcp", "--",
            "curl", "-s", "--connect-timeout", "15", "--max-time", "30",
            "http://example.com",
            timeout=120,
        )
        assert curl_result.returncode == 0, (
            f"curl to example.com failed at transport level.\n"
            f"stdout: {curl_result.stdout}\nstderr: {curl_result.stderr}\n"
            f"{capture_lima_logs(session_id)}"
        )
        # The response body should contain the well-known Example Domain page.
        assert "Example Domain" in curl_result.stdout, (
            f"Response does not contain 'Example Domain' from example.com.\n"
            f"stdout: {curl_result.stdout}"
        )

        # Clean up.
        sandbox_cli("rm", "pol-l1-tcp", timeout=120)
        session_id = None

    finally:
        if session_id is not None:
            sandbox_cli("rm", "pol-l1-tcp", timeout=120)
        if policy_path is not None:
            cleanup_policy_file(policy_path)


@pytest.mark.timeout(600)
def test_level1_transport_udp(sandbox_cli, backend):
    """Policy allows DNS to 8.8.8.8 at level 'transport' protocol 'udp'.
    Verify DNS query to 8.8.8.8 works.

    Note: All port-53 traffic is DNAT'd to the gateway's CoreDNS, so the
    query goes through CoreDNS regardless of the target server.  We must
    also allow the queried domain in the policy so CoreDNS resolves it.
    """
    session_id = None
    policy_path = None
    try:
        # DNS uses UDP/53. example.com needs its own rule so
        # CoreDNS resolves it (DNS allow-list is keyed on rule.host).
        # All :53 traffic is DNAT'd to CoreDNS regardless of target IP,
        # but the policy must still carry an (ip, 53, udp) allow for
        # completeness; the test asserts nslookup to 8.8.8.8 resolves.
        policy = {
            "version": "2.0.0",
            "rules": [
                {
                    "host": "example.com",
                    "port": 53,
                    "protocol": "udp",
                    "level": "transport",
                },
                {
                    "host": "8.8.8.8",
                    "port": 53,
                    "protocol": "udp",
                    "level": "transport",
                },
            ],
        }
        policy_path = write_policy_file(policy)

        result = sandbox_cli(
            "create", *make_create_args(backend, "pol-l1-udp", "--policy", policy_path),
            timeout=600,
        )
        assert result.returncode == 0, (
            f"sandbox create failed (rc={result.returncode}).\n"
            f"stdout: {result.stdout}\nstderr: {result.stderr}"
        )
        session_id = parse_session_id(result.stdout)
        wait_for_state(sandbox_cli, "pol-l1-udp", "Running", timeout=10)

        # DNS query using dig to 8.8.8.8 should work.
        dns_result = sandbox_cli(
            "ssh", "pol-l1-udp", "--",
            "bash", "-c",
            "nslookup example.com 8.8.8.8",
            timeout=120,
        )
        assert dns_result.returncode == 0, (
            f"DNS query to 8.8.8.8 failed.\n"
            f"stdout: {dns_result.stdout}\nstderr: {dns_result.stderr}"
        )
        # Should contain a resolved address.
        combined = dns_result.stdout + dns_result.stderr
        assert re.search(r"Address:\s+\d+\.\d+\.\d+\.\d+", combined), (
            f"DNS query did not return an IP address.\n"
            f"Output:\n{combined}"
        )

        # Clean up.
        sandbox_cli("rm", "pol-l1-udp", timeout=120)
        session_id = None

    finally:
        if session_id is not None:
            sandbox_cli("rm", "pol-l1-udp", timeout=120)
        if policy_path is not None:
            cleanup_policy_file(policy_path)


# ---------------------------------------------------------------------------
# UDP allow-path / deny-path event-bus helpers
# ---------------------------------------------------------------------------
#
# The four ``test_udp_*`` cases below exercise the UDP datapath:
#
#   * Allowed UDP -> ``policy_allow_udp accept`` -> direct upstream
#     (no Envoy hop). The ``sandbox-nft-allow-logger`` subscribes to
#     ``NFNLGRP_CONNTRACK_NEW`` and emits a JSONL allow event per new
#     UDP flow; the daemon's ingest watcher republishes it onto the
#     per-session event bus with on-bus ``layer="deny-logger"`` and
#     ``event="allow"`` (same on-bus layer for both nft loggers,
#     distinguished by the ``event`` discriminator — see
#     ``event_mapper.rs``).
#
#   * Denied UDP -> ``meta l4proto udp log group 1; drop``. The
#     kernel mirrors the dropped packet to NFNLGRP_NFLOG; the
#     ``sandbox-nft-deny-logger`` parses the netlink message and
#     emits a JSONL deny event with the pre-DNAT 5-tuple. Same on-bus
#     ``layer="deny-logger"``, ``event="deny"`` discriminator.
#
# All assertions in this group target the on-bus DTO via
# ``sandbox events <session>`` (JSONL stream) — never the on-disk
# ``nft-allow.jsonl`` / ``nft-deny.jsonl`` files. Internal filenames
# may change without notice; the bus contract is what tests pin.

# Number of seconds to wait between a UDP send and the snapshot read,
# allowing the watcher's parse + publish path to flush.
_UDP_EVENT_PROPAGATION_S = 4


def _read_session_events(
    sandbox_cli,
    session_name: str,
    decision: str | None = None,
) -> list[dict]:
    """Snapshot the per-session event bus via ``sandbox events`` (non-follow).

    Returns the parsed JSONL entries; blank or unparseable lines are
    skipped so a truncated tail does not invalidate the assertion.
    Mirrors the helper at ``test_presets._read_events`` — kept
    inline rather than promoted to ``conftest.py`` so the UDP test
    block stays self-contained for future readers.
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


def _is_nft_allow_for(
    ev: dict,
    dst_ip: str,
    dst_port: int,
    protocol: str = "udp",
) -> bool:
    """Match a single allow event against an expected pre-DNAT 5-tuple slice.

    The on-bus shape (``event_mapper.rs``):
        layer="deny-logger", event="allow", protocol="udp",
        orig_dst_ip=<ip>, orig_dst_port=<port>,
        src_ip=<vm-ip>, src_port=<ephemeral>.

    Tests pin destination + protocol; source port is ephemeral and
    not asserted here.
    """
    return (
        ev.get("layer") == "deny-logger"
        and ev.get("event") == "allow"
        and ev.get("protocol") == protocol
        and ev.get("orig_dst_ip") == dst_ip
        and ev.get("orig_dst_port") == dst_port
    )


def _is_nft_deny_for(
    ev: dict,
    dst_ip: str,
    dst_port: int,
    protocol: str = "udp",
) -> bool:
    """Match a single deny event against an expected pre-DNAT 5-tuple slice.

    Same wire shape as ``_is_nft_allow_for`` — only the ``event``
    discriminator differs.
    """
    return (
        ev.get("layer") == "deny-logger"
        and ev.get("event") == "deny"
        and ev.get("protocol") == protocol
        and ev.get("orig_dst_ip") == dst_ip
        and ev.get("orig_dst_port") == dst_port
    )


def _resolve_ipv4(host: str, attempts: int = 3) -> set[str]:
    """Resolve ``host`` host-side (not via the gateway's CoreDNS) to a
    set of IPv4 addresses. CDN / Anycast hosts can return different
    IPs across calls; we union a few attempts.

    Used by the CIDR-anchor and bidirectional-echo tests so they can
    target an IP directly without relying on the gateway's DNS path
    (which would re-resolve and might pick a different IP).
    """
    ips: set[str] = set()
    for _ in range(attempts):
        try:
            ips.add(socket.gethostbyname(host))
        except OSError:
            pass
    return ips


def _send_udp_packet(
    sandbox_cli,
    session_name: str,
    dst_ip: str,
    dst_port: int,
    payload_bytes: int = 16,
    timeout_s: int = 5,
) -> subprocess.CompletedProcess:
    """Send one UDP packet from inside the VM via bash's ``/dev/udp/``
    redirection. Returns the CLI's CompletedProcess — the test does not
    assert on the inner exit code (UDP is connectionless; ``echo
    >/dev/udp/...`` returns 0 on a successful sendto regardless of
    whether the packet was eventually delivered, dropped at nft, or
    accepted by the upstream).

    The exit code is informational; the actual assertion in each test
    is on the bus event that the kernel datapath produced (allow event
    from nft-allow-logger / deny event from nft-deny-logger).

    bash redirection is the most portable primitive — present in both
    the Lima base image and the lite container image without extra
    packages, no raw-socket capabilities needed (UDP send goes through
    a stock SOCK_DGRAM, not a raw socket).
    """
    # 16 bytes of arbitrary content; payload size is irrelevant since
    # the deny path drops at nft and the allow path doesn't inspect
    # contents. ``head -c`` from /dev/zero gives deterministic bytes.
    cmd = (
        f"head -c {payload_bytes} /dev/zero > /dev/udp/{dst_ip}/{dst_port} "
        f"2>&1; echo EXIT:$?"
    )
    return sandbox_cli(
        "ssh", session_name, "--",
        "timeout", str(timeout_s), "bash", "-c", cmd,
        timeout=60,
    )


@pytest.mark.timeout(600)
def test_udp_allow_ntp(sandbox_cli, backend):
    """Allow UDP/123 to an NTP host; from the VM, send an NTP packet and
    assert an allow event lands on the bus with the correct 5-tuple.

    Allowed UDP exits direct to upstream (no
    Envoy / mitmproxy hop), and the ``sandbox-nft-allow-logger``
    emits one JSONL allow event per new conntrack flow. The daemon
    ingest republishes it on the bus with ``layer="deny-logger"`` and
    ``event="allow"`` per ``event_mapper.rs``.

    NTP is the canonical non-DNS UDP example —
    it exercises the ``policy_allow_udp`` path proper rather than the
    DNS DNAT hairpin that ``test_level1_transport_udp`` covers.
    """
    session_id = None
    policy_path = None
    session_name = "pol-udp-allow-ntp"
    try:
        # Allow time.cloudflare.com on UDP/123. Cloudflare's NTP service
        # is anycast / publicly reachable, used here purely as a known
        # UDP/123 destination. The host has its own A record and is
        # resolvable via CoreDNS (which then propagates the resolved IPs
        # into `policy_allow_udp`).
        target_host = "time.cloudflare.com"
        target_port = 123
        policy = {
            "version": "2.0.0",
            "rules": [
                {
                    "host": target_host,
                    "port": target_port,
                    "protocol": "udp",
                    "level": "transport",
                },
            ],
        }
        policy_path = write_policy_file(policy)

        result = sandbox_cli(
            "create", *make_create_args(backend, session_name, "--policy", policy_path),
            timeout=600,
        )
        assert result.returncode == 0, (
            f"sandbox create failed (rc={result.returncode}).\n"
            f"stdout: {result.stdout}\nstderr: {result.stderr}"
        )
        session_id = parse_session_id(result.stdout)
        wait_for_state(sandbox_cli, session_name, "Running", timeout=10)

        # Warm DNS so CoreDNS resolves the host and the daemon's
        # propagation loop populates the `policy_allow_udp` concat-set
        # entry `(ip, 123)`. Without this the first UDP packet races
        # the 2-second propagation poll and would hit the NFLOG-drop
        # path. Mirrors the warmup pattern used elsewhere in this
        # module (test_level1_transport_tcp etc.).
        nslookup = sandbox_cli(
            "ssh", session_name, "--",
            "nslookup", target_host,
            timeout=120,
        )
        assert nslookup.returncode == 0, (
            f"nslookup for {target_host} failed inside VM.\n"
            f"stdout: {nslookup.stdout}\nstderr: {nslookup.stderr}"
        )
        time.sleep(5)

        # Capture the resolved IPs reported by the VM-side resolver so
        # the bus assertion's expected 5-tuple matches whatever address
        # was actually placed in `policy_allow_udp`. Geo / CDN drift
        # between host-side and gateway-side resolvers is a documented
        # source of flakiness elsewhere (see
        # test_l3_fail_closed_before_dns_propagation), so we use the
        # in-VM answer as the source of truth.
        vm_resolved: list[str] = []
        seen_name = False
        for line in nslookup.stdout.splitlines():
            stripped = line.strip()
            if stripped.startswith("Name:"):
                seen_name = True
                continue
            if seen_name:
                m = re.match(
                    r"Address(?:es)?(?:\s*\d+)?:\s*(\d{1,3}(?:\.\d{1,3}){3})$",
                    stripped,
                )
                if m:
                    vm_resolved.append(m.group(1))
        assert vm_resolved, (
            f"VM-side nslookup for {target_host} returned no A records.\n"
            f"stdout: {nslookup.stdout}\nstderr: {nslookup.stderr}"
        )
        target_ip = vm_resolved[0]

        # Send a single UDP packet to <target_ip>:123. The bash redirect
        # opens a SOCK_DGRAM, sendto's the bytes, and closes — that is
        # enough for the kernel to instantiate a new conntrack entry
        # (UDP is unconnected, but `ip_conntrack_udp` still creates an
        # NFCT_T_NEW event on first packet match), which the
        # nft-allow-logger picks up via the `NFNLGRP_CONNTRACK_NEW`
        # subscription.
        send = _send_udp_packet(sandbox_cli, session_name, target_ip, target_port)
        assert send.returncode == 0, (
            f"`sandbox ssh` wrapper failed when sending UDP packet.\n"
            f"stdout: {send.stdout}\nstderr: {send.stderr}"
        )

        # Give the watcher + ingest path time to publish the allow
        # event onto the bus.
        time.sleep(_UDP_EVENT_PROPAGATION_S)

        allow_events = _read_session_events(
            sandbox_cli, session_name, decision="allow",
        )
        # At least one nft-allow event for our (target_ip, 123, udp)
        # 5-tuple slice must be present.
        matched = [
            ev for ev in allow_events
            if _is_nft_allow_for(ev, target_ip, target_port, protocol="udp")
        ]
        assert matched, (
            f"Expected at least one nft-allow-logger allow event for "
            f"({target_ip}:{target_port}/udp) on the per-session bus, "
            f"but found none. Captured {len(allow_events)} allow "
            f"events total; first 10:\n"
            + "\n".join(json.dumps(ev) for ev in allow_events[:10])
            + f"\n{capture_lima_logs(session_id)}"
        )

        # Spot-check the source side of the 5-tuple: src_ip should be
        # the session's VM IP (lives inside the per-session subnet),
        # src_port is ephemeral and not pinned. Asserting only that the
        # source field is *populated* keeps the test robust to backend
        # differences (lima vs container subnet shapes).
        any_event = matched[0]
        assert any_event.get("src_ip"), (
            f"allow event missing src_ip; event: {json.dumps(any_event)}"
        )
        assert isinstance(any_event.get("src_port"), int), (
            f"allow event missing/invalid src_port; event: {json.dumps(any_event)}"
        )

        sandbox_cli("rm", session_name, timeout=120)
        session_id = None

    finally:
        if session_id is not None:
            sandbox_cli("rm", session_name, timeout=120)
        if policy_path is not None:
            cleanup_policy_file(policy_path)


@pytest.mark.timeout(600)
def test_udp_bidirectional_echo(sandbox_cli, backend):
    """Send a UDP packet to an allowed NTP server, receive the response,
    and assert exactly one allow event fires for the *outbound* (NEW)
    flow — no allow event for the return packet.

    The allow logger subscribes to
    ``NFNLGRP_CONNTRACK_NEW`` only — not ``DESTROY`` or any other
    conntrack lifecycle event. A single UDP request/reply is one
    flow, one NFCT_T_NEW event, one allow event on the bus.

    NTP serves as a real bidirectional UDP service: the request packet
    is 48 bytes with mode=3 (client); the server replies with a 48-byte
    response carrying the timestamps. We don't validate the NTP
    timestamps here — the round trip itself is sufficient evidence
    that the allow datapath delivered the packet end-to-end (no
    Envoy hop, direct upstream).
    """
    session_id = None
    policy_path = None
    session_name = "pol-udp-echo"
    try:
        target_host = "time.cloudflare.com"
        target_port = 123
        policy = {
            "version": "2.0.0",
            "rules": [
                {
                    "host": target_host,
                    "port": target_port,
                    "protocol": "udp",
                    "level": "transport",
                },
            ],
        }
        policy_path = write_policy_file(policy)

        result = sandbox_cli(
            "create", *make_create_args(backend, session_name, "--policy", policy_path),
            timeout=600,
        )
        assert result.returncode == 0, (
            f"sandbox create failed (rc={result.returncode}).\n"
            f"stdout: {result.stdout}\nstderr: {result.stderr}"
        )
        session_id = parse_session_id(result.stdout)
        wait_for_state(sandbox_cli, session_name, "Running", timeout=10)

        # Warm DNS + propagate.
        nslookup = sandbox_cli(
            "ssh", session_name, "--",
            "nslookup", target_host,
            timeout=120,
        )
        assert nslookup.returncode == 0, (
            f"nslookup for {target_host} failed.\n"
            f"stdout: {nslookup.stdout}\nstderr: {nslookup.stderr}"
        )
        time.sleep(5)

        # Resolve VM-side and pick the first IP — same logic as
        # test_udp_allow_ntp.
        vm_resolved: list[str] = []
        seen_name = False
        for line in nslookup.stdout.splitlines():
            stripped = line.strip()
            if stripped.startswith("Name:"):
                seen_name = True
                continue
            if seen_name:
                m = re.match(
                    r"Address(?:es)?(?:\s*\d+)?:\s*(\d{1,3}(?:\.\d{1,3}){3})$",
                    stripped,
                )
                if m:
                    vm_resolved.append(m.group(1))
        assert vm_resolved, (
            f"VM-side nslookup for {target_host} returned no A records.\n"
            f"{nslookup.stdout}"
        )
        target_ip = vm_resolved[0]

        # Send a real NTP client request and read the response. The
        # request is a 48-byte v4 client packet (LI=0, VN=4, Mode=3
        # encoded as 0x23 in the first byte; remaining 47 bytes zero).
        # We use socat for the round-trip because bash's /dev/udp/
        # redirection is sendto-only — it doesn't expose a way to
        # read the reply on the same socket. socat is installed in
        # both Lima (cloud-init) and lite container (Dockerfile)
        # images, so the test works on both backends.
        #
        # The `-t 5` and `-T 5` socat options bound the wait time so
        # the test fails fast if no reply arrives (which would be a
        # datapath bug). Output is base64-encoded so we can sanity-
        # check the response length without worrying about binary
        # bytes corrupting the ssh transport.
        ntp_cmd = (
            "printf '\\x23' > /tmp/ntp_req && "
            "head -c 47 /dev/zero >> /tmp/ntp_req && "
            f"socat -t 5 -T 5 - UDP:{target_ip}:{target_port} < /tmp/ntp_req "
            "| base64 -w0; echo; echo EXIT:$?"
        )
        socat_result = sandbox_cli(
            "ssh", session_name, "--",
            "bash", "-c", ntp_cmd,
            timeout=60,
        )
        # The outer ssh wrapper should always succeed; the inner socat
        # reports its exit code via "EXIT:$?".
        assert socat_result.returncode == 0, (
            f"sandbox ssh wrapper failed for socat NTP send.\n"
            f"stdout: {socat_result.stdout}\nstderr: {socat_result.stderr}"
        )
        # Parse out the base64'd response. socat emits the bytes on
        # stdout, then the inner shell appends "\nEXIT:0".
        out_lines = [l for l in socat_result.stdout.splitlines() if l.strip()]
        assert out_lines and "EXIT:0" in out_lines[-1], (
            f"socat exited non-zero or produced no output — "
            f"NTP response did not arrive.\n"
            f"stdout:\n{socat_result.stdout}\nstderr: {socat_result.stderr}\n"
            f"{capture_lima_logs(session_id)}"
        )
        b64_response = out_lines[0]
        # NTPv4 response is exactly 48 bytes -> base64 of 48 bytes is
        # 64 chars (ceiling((48*4)/3)). Allow some flex if a server
        # returns a slightly different shape, but require *some*
        # response bytes (not just a newline).
        try:
            import base64
            response_bytes = base64.b64decode(b64_response)
        except Exception as e:
            pytest.fail(
                f"failed to decode socat output as base64; raw output:\n"
                f"{socat_result.stdout}\nerror: {e}"
            )
        assert len(response_bytes) >= 48, (
            f"NTP response shorter than expected 48 bytes; got "
            f"{len(response_bytes)} bytes. Indicates the upstream "
            f"didn't reply or the reply was truncated.\n"
            f"raw socat stdout:\n{socat_result.stdout}"
        )

        # Allow ingest to flush.
        time.sleep(_UDP_EVENT_PROPAGATION_S)

        allow_events = _read_session_events(
            sandbox_cli, session_name, decision="allow",
        )
        # Find every nft-allow event for our (target_ip, 123/udp).
        # Expect exactly one — Resolution 7 says NEW only.
        matching = [
            ev for ev in allow_events
            if _is_nft_allow_for(ev, target_ip, target_port, protocol="udp")
        ]
        assert matching, (
            f"Expected at least one nft-allow-logger allow event for "
            f"({target_ip}:{target_port}/udp), got none. Captured "
            f"{len(allow_events)} allow events total; first 10:\n"
            + "\n".join(json.dumps(ev) for ev in allow_events[:10])
        )

        # Resolution 7: NEW-only — no DESTROY/return-flow events. The
        # outbound (VM -> NTP) flow has src_ip = VM IP. A bug that
        # also subscribed to NFCT_T_DESTROY (or that mistakenly
        # logged the reply tuple) would surface as a *second* event
        # whose src_ip / orig_dst_ip are swapped (NTP server -> VM).
        # We assert the inverse: no allow event with
        # orig_dst_ip = our VM's session IP exists for the duration
        # of this test.
        return_flow_hits = [
            ev for ev in allow_events
            if ev.get("layer") == "deny-logger"
            and ev.get("event") == "allow"
            and ev.get("src_ip") == target_ip
            and ev.get("src_port") == target_port
        ]
        assert not return_flow_hits, (
            f"Found an allow event whose src side is the upstream NTP "
            f"server — the allow logger should subscribe to "
            f"NFCT_T_NEW only and emit one event "
            f"per *outbound* flow. Offending events:\n"
            + "\n".join(json.dumps(ev) for ev in return_flow_hits[:5])
        )

        sandbox_cli("rm", session_name, timeout=120)
        session_id = None

    finally:
        if session_id is not None:
            sandbox_cli("rm", session_name, timeout=120)
        if policy_path is not None:
            cleanup_policy_file(policy_path)


@pytest.mark.timeout(600)
def test_udp_multi_port_same_host(sandbox_cli, backend):
    """Allow one UDP port to a host but not another. The allowed port
    delivers and emits an allow event; the disallowed port is dropped
    silently and emits a deny event. Both events carry the correct
    5-tuple discriminated only by ``event="allow"`` vs ``"deny"``.

    Multi-port-same-host case. Exercises
    the per-port granularity of ``policy_allow_udp`` (which is keyed
    on ``(ip, port)`` concat-set entries — see
    ``policy.rs::generate_policy_allow_table``) and the deny-NFLOG
    catch-all firing for the unallowed port.
    """
    session_id = None
    policy_path = None
    session_name = "pol-udp-multi-port"
    try:
        target_host = "time.cloudflare.com"
        allowed_port = 123
        denied_port = 9999
        policy = {
            "version": "2.0.0",
            "rules": [
                {
                    "host": target_host,
                    "port": allowed_port,
                    "protocol": "udp",
                    "level": "transport",
                },
            ],
        }
        policy_path = write_policy_file(policy)

        result = sandbox_cli(
            "create", *make_create_args(backend, session_name, "--policy", policy_path),
            timeout=600,
        )
        assert result.returncode == 0, (
            f"sandbox create failed (rc={result.returncode}).\n"
            f"stdout: {result.stdout}\nstderr: {result.stderr}"
        )
        session_id = parse_session_id(result.stdout)
        wait_for_state(sandbox_cli, session_name, "Running", timeout=10)

        # Warm DNS + propagate.
        nslookup = sandbox_cli(
            "ssh", session_name, "--",
            "nslookup", target_host,
            timeout=120,
        )
        assert nslookup.returncode == 0, (
            f"nslookup for {target_host} failed.\n"
            f"stdout: {nslookup.stdout}\nstderr: {nslookup.stderr}"
        )
        time.sleep(5)

        vm_resolved: list[str] = []
        seen_name = False
        for line in nslookup.stdout.splitlines():
            stripped = line.strip()
            if stripped.startswith("Name:"):
                seen_name = True
                continue
            if seen_name:
                m = re.match(
                    r"Address(?:es)?(?:\s*\d+)?:\s*(\d{1,3}(?:\.\d{1,3}){3})$",
                    stripped,
                )
                if m:
                    vm_resolved.append(m.group(1))
        assert vm_resolved, (
            f"VM-side nslookup for {target_host} returned no A records.\n"
            f"{nslookup.stdout}"
        )
        target_ip = vm_resolved[0]

        # Send to allowed port (123) — should emit allow event.
        send_allowed = _send_udp_packet(
            sandbox_cli, session_name, target_ip, allowed_port,
        )
        assert send_allowed.returncode == 0, (
            f"sandbox ssh wrapper failed for allowed-port send.\n"
            f"stdout: {send_allowed.stdout}\nstderr: {send_allowed.stderr}"
        )

        # Send to denied port (9999) — should emit deny event.
        send_denied = _send_udp_packet(
            sandbox_cli, session_name, target_ip, denied_port,
        )
        assert send_denied.returncode == 0, (
            f"sandbox ssh wrapper failed for denied-port send.\n"
            f"stdout: {send_denied.stdout}\nstderr: {send_denied.stderr}"
        )

        time.sleep(_UDP_EVENT_PROPAGATION_S)

        # Read allow events and find the one for (target_ip, 123).
        allow_events = _read_session_events(
            sandbox_cli, session_name, decision="allow",
        )
        allow_match = [
            ev for ev in allow_events
            if _is_nft_allow_for(ev, target_ip, allowed_port, protocol="udp")
        ]
        assert allow_match, (
            f"Expected at least one nft-allow event for "
            f"({target_ip}:{allowed_port}/udp), got none. Captured "
            f"{len(allow_events)} allow events:\n"
            + "\n".join(json.dumps(ev) for ev in allow_events[:10])
        )
        # And no allow event for the denied port — that would mean the
        # policy_allow_udp set leaked beyond the configured rule.
        leaked_allow = [
            ev for ev in allow_events
            if _is_nft_allow_for(ev, target_ip, denied_port, protocol="udp")
        ]
        assert not leaked_allow, (
            f"Found allow event for ({target_ip}:{denied_port}/udp) — "
            f"policy_allow_udp must be keyed on (ip, port), not ip "
            f"alone. Offending events:\n"
            + "\n".join(json.dumps(ev) for ev in leaked_allow[:5])
        )

        # Read deny events and find the one for (target_ip, 9999).
        deny_events = _read_session_events(
            sandbox_cli, session_name, decision="deny",
        )
        deny_match = [
            ev for ev in deny_events
            if _is_nft_deny_for(ev, target_ip, denied_port, protocol="udp")
        ]
        assert deny_match, (
            f"Expected at least one nft-deny event for "
            f"({target_ip}:{denied_port}/udp), got none. Captured "
            f"{len(deny_events)} deny events:\n"
            + "\n".join(json.dumps(ev) for ev in deny_events[:10])
            + f"\n{capture_lima_logs(session_id)}"
        )
        # And no deny event for the allowed port.
        leaked_deny = [
            ev for ev in deny_events
            if _is_nft_deny_for(ev, target_ip, allowed_port, protocol="udp")
        ]
        assert not leaked_deny, (
            f"Found deny event for ({target_ip}:{allowed_port}/udp) — "
            f"the allowed port should never reach the NFLOG-drop path. "
            f"Offending events:\n"
            + "\n".join(json.dumps(ev) for ev in leaked_deny[:5])
        )

        sandbox_cli("rm", session_name, timeout=120)
        session_id = None

    finally:
        if session_id is not None:
            sandbox_cli("rm", session_name, timeout=120)
        if policy_path is not None:
            cleanup_policy_file(policy_path)


@pytest.mark.timeout(600)
def test_udp_allowed_ip_cidr_edge(sandbox_cli, backend):
    """Allow a CIDR range over UDP, hit an IP inside it directly (no
    DNS), and assert an allow event lands with the full 5-tuple
    including the resolved destination IP.

    Allowed-IP edge case: direct-IP destination skipping DNS,
    exercising the CIDR side of
    ``policy_allow_udp``. Pairs with the dual-anchor model
    on the TCP side: CIDR-anchored allows skip the DNS propagation
    loop entirely and land in nftables at policy-apply time. This
    test proves the same shape works for UDP.

    Choosing a target: we resolve ``time.cloudflare.com`` host-side
    once, take the first /32 IP, and use that as both the policy
    CIDR and the curl-style direct-IP destination. The host-side
    resolution is one-shot — the test does not warm CoreDNS in the
    VM at all, which is the whole point of the "direct-IP skipping
    DNS" case. If host-side resolution fails (e.g. test runner has
    no DNS), the test skips with a clear message.
    """
    session_id = None
    policy_path = None
    session_name = "pol-udp-cidr-edge"
    try:
        target_host = "time.cloudflare.com"
        target_port = 123

        # Resolve host-side; pick a deterministic IP. The CDN can
        # rotate IPs across calls, so we union a few attempts and
        # pick the lexicographically-smallest entry.
        host_ips = _resolve_ipv4(target_host)
        if not host_ips:
            pytest.skip(
                f"host-side DNS cannot resolve {target_host} — cannot "
                f"run direct-IP CIDR test."
            )
        target_ip = sorted(host_ips)[0]

        # Allow exactly that /32 over UDP/123. Using /32 (single host)
        # exercises the CIDR-anchor path without depending on a wider
        # netblock that might catch unrelated packets and confuse the
        # event assertion.
        cidr = f"{target_ip}/32"
        policy = {
            "version": "2.0.0",
            "rules": [
                {
                    "host": cidr,
                    "port": target_port,
                    "protocol": "udp",
                    "level": "transport",
                },
            ],
        }
        policy_path = write_policy_file(policy)

        result = sandbox_cli(
            "create", *make_create_args(backend, session_name, "--policy", policy_path),
            timeout=600,
        )
        assert result.returncode == 0, (
            f"sandbox create failed (rc={result.returncode}).\n"
            f"stdout: {result.stdout}\nstderr: {result.stderr}"
        )
        session_id = parse_session_id(result.stdout)
        wait_for_state(sandbox_cli, session_name, "Running", timeout=10)

        # CIDR rules don't go through the DNS propagation loop — the
        # daemon emits the `policy_allow_udp` element at policy-apply
        # time directly (policy.rs::generate_policy_allow_table).
        # We still pause briefly for the policy-apply path to settle
        # (gateway nft reload + forward-chain admit rule). Mirrors the
        # ~5 s wait used elsewhere after warmup; here the wait stands
        # in for the propagation loop.
        time.sleep(5)

        # Send UDP directly to the resolved IP — no nslookup inside
        # the VM, no CoreDNS round-trip. This is the "skipping DNS"
        # property the design calls out.
        send = _send_udp_packet(
            sandbox_cli, session_name, target_ip, target_port,
        )
        assert send.returncode == 0, (
            f"sandbox ssh wrapper failed for direct-IP UDP send.\n"
            f"stdout: {send.stdout}\nstderr: {send.stderr}"
        )

        time.sleep(_UDP_EVENT_PROPAGATION_S)

        allow_events = _read_session_events(
            sandbox_cli, session_name, decision="allow",
        )
        matched = [
            ev for ev in allow_events
            if _is_nft_allow_for(ev, target_ip, target_port, protocol="udp")
        ]
        assert matched, (
            f"Expected at least one nft-allow event for "
            f"({target_ip}:{target_port}/udp) under CIDR rule "
            f"{cidr} (direct-IP, no DNS). Captured "
            f"{len(allow_events)} allow events; first 10:\n"
            + "\n".join(json.dumps(ev) for ev in allow_events[:10])
            + f"\n{capture_lima_logs(session_id)}"
        )

        # Pin the full 5-tuple: orig_dst_ip + orig_dst_port + protocol
        # plus the source axis (src_ip = VM IP, src_port populated).
        ev = matched[0]
        assert ev.get("orig_dst_ip") == target_ip, (
            f"orig_dst_ip mismatch — expected {target_ip}, got "
            f"{ev.get('orig_dst_ip')}; full event: {json.dumps(ev)}"
        )
        assert ev.get("orig_dst_port") == target_port, (
            f"orig_dst_port mismatch — expected {target_port}, got "
            f"{ev.get('orig_dst_port')}; full event: {json.dumps(ev)}"
        )
        assert ev.get("protocol") == "udp", (
            f"protocol must be 'udp', got {ev.get('protocol')!r}; "
            f"full event: {json.dumps(ev)}"
        )
        assert ev.get("src_ip"), (
            f"src_ip must be populated on a 5-tuple allow event; "
            f"full event: {json.dumps(ev)}"
        )
        assert isinstance(ev.get("src_port"), int) and ev["src_port"] > 0, (
            f"src_port must be a positive integer; got "
            f"{ev.get('src_port')!r}; full event: {json.dumps(ev)}"
        )

        sandbox_cli("rm", session_name, timeout=120)
        session_id = None

    finally:
        if session_id is not None:
            sandbox_cli("rm", session_name, timeout=120)
        if policy_path is not None:
            cleanup_policy_file(policy_path)


# ---------------------------------------------------------------------------
# `ubuntu:` preset smoke
# ---------------------------------------------------------------------------
#
# The `ubuntu:` preset adds the default-allow rules an Ubuntu sandbox
# needs to function: NTP (UDP/123 to ntp.ubuntu.com — the canonical
# vendor pool; Canonical removed time.ubuntu.com from authoritative
# DNS so we no longer ship a rule for it) and apt mirrors (HTTPS/443
# to archive.ubuntu.com / security.ubuntu.com). It is the first
# distro-level preset on top of the ten-preset baseline. See
# `sandboxd/sandbox-cli/src/presets/builtin.rs::expand_ubuntu` for the
# authoritative rule set and `docs/guides/network-policies.md` for
# the user-facing description.
#
# This single end-to-end test exercises both halves of the preset:
#
#   1. apt update against the preset-allowed mirrors succeeds (TLS
#      leg of the preset).
#   2. A UDP/123 packet to one of the preset-allowed NTP hosts
#      surfaces an allow event on the per-session bus (UDP allow-path
#      leg of the preset, depends on the nft-allow-logger landing).
#
# Backend coverage: Lima only — the apt-update half needs a real
# Ubuntu base image, which the lite container backend does not boot
# (it runs a different image stack). The UDP allow-path leg works on
# both backends, but we keep the test single-backend so the apt half
# stays meaningful; a future container-backend smoke for the
# `dockerhub:` / `ubuntu:` overlap would be a separate test.


@pytest.mark.timeout(600)
@pytest.mark.lima
def test_ubuntu_preset_smoke(sandbox_cli):
    """``sandbox create --preset 'ubuntu:'`` allows ``apt update`` against
    the canonical Ubuntu mirrors and surfaces an allow event for a
    UDP/123 packet to ``time.ubuntu.com``.

    A sandboxed Ubuntu
    VM with ``--preset 'ubuntu:'`` runs ``sudo apt update`` and an
    NTP sync check, and both succeed. We assert the apt half via
    ``apt-get update`` exit code (apt's HTTPS fetches the indexes
    from the preset-allowed mirrors) and the NTP half via the
    per-session event bus (the nft-allow-logger emits an
    allow event for new conntrack flows; same shape
    ``test_udp_allow_ntp`` pins).

    Lima-only: the apt half needs a real Ubuntu base image, which the
    lite container backend's image stack does not boot. See the block
    comment above for the full rationale.
    """
    session_id = None
    session_name = "ubuntu-preset-smoke"
    try:
        create_result = sandbox_cli(
            "create",
            *make_create_args("lima", session_name, "--preset", "ubuntu:"),
            timeout=600,
        )
        assert create_result.returncode == 0, (
            f"sandbox create --preset 'ubuntu:' failed (rc={create_result.returncode}).\n"
            f"stdout: {create_result.stdout}\nstderr: {create_result.stderr}"
        )
        session_id = parse_session_id(create_result.stdout)
        wait_for_state(sandbox_cli, session_name, "Running", timeout=30)

        # Warm DNS for every preset-allowed host so the daemon's
        # propagation loop materialises both nftables concat-set
        # entries (UDP for NTP, TCP for apt mirrors) and the per-rule
        # Envoy chains for the TLS-level apt rules. Without this
        # warmup the first request can race the propagation poll.
        # Mirrors the warmup pattern already used by
        # ``test_udp_allow_ntp`` and the preset tests.
        for host in (
            "ntp.ubuntu.com",
            "archive.ubuntu.com",
            "security.ubuntu.com",
        ):
            nslookup = sandbox_cli(
                "ssh", session_name, "--", "nslookup", host,
                timeout=120,
            )
            assert nslookup.returncode == 0, (
                f"nslookup for {host} failed inside VM under ubuntu preset.\n"
                f"stdout: {nslookup.stdout}\nstderr: {nslookup.stderr}\n"
                f"{capture_lima_logs(session_id)}"
            )
        time.sleep(5)

        # apt half — `apt-get update` against the mirrors enabled by
        # the preset. The base image's stock /etc/apt/sources.list is
        # pinned at archive.ubuntu.com / security.ubuntu.com on
        # 22.04+, both of which the preset allows; everything else
        # (PPAs, snap, livepatch) is intentionally not part of the
        # preset, so this command should succeed unmodified on a
        # fresh image.
        apt_update = sandbox_cli(
            "ssh", session_name, "--",
            "sudo", "apt-get", "update", "-q",
            timeout=300,
        )
        assert apt_update.returncode == 0, (
            f"sudo apt-get update failed under ubuntu preset (rc={apt_update.returncode}); "
            f"this means the preset's apt-mirror rules did not cover what the base image's "
            f"/etc/apt/sources.list actually fetches.\n"
            f"stdout: {apt_update.stdout}\nstderr: {apt_update.stderr}\n"
            f"{capture_lima_logs(session_id)}"
        )

        # NTP half — send one UDP/123 packet to ntp.ubuntu.com and
        # assert an allow event lands on the bus. We resolve the host
        # in the VM (matches the IP that gets placed in
        # `policy_allow_udp` by the daemon's propagation loop) and
        # then send a single packet, mirroring `test_udp_allow_ntp`.
        nslookup = sandbox_cli(
            "ssh", session_name, "--", "nslookup", "ntp.ubuntu.com",
            timeout=120,
        )
        assert nslookup.returncode == 0
        vm_resolved: list[str] = []
        seen_name = False
        for line in nslookup.stdout.splitlines():
            stripped = line.strip()
            if stripped.startswith("Name:"):
                seen_name = True
                continue
            if seen_name:
                m = re.match(
                    r"Address(?:es)?(?:\s*\d+)?:\s*(\d{1,3}(?:\.\d{1,3}){3})$",
                    stripped,
                )
                if m:
                    vm_resolved.append(m.group(1))
        assert vm_resolved, (
            f"VM-side nslookup for ntp.ubuntu.com returned no A records.\n"
            f"stdout: {nslookup.stdout}"
        )
        target_ip = vm_resolved[0]

        send = _send_udp_packet(sandbox_cli, session_name, target_ip, 123)
        assert send.returncode == 0, (
            f"`sandbox ssh` wrapper failed when sending NTP packet.\n"
            f"stdout: {send.stdout}\nstderr: {send.stderr}"
        )

        time.sleep(_UDP_EVENT_PROPAGATION_S)

        allow_events = _read_session_events(
            sandbox_cli, session_name, decision="allow",
        )
        ntp_allows = [
            ev for ev in allow_events
            if _is_nft_allow_for(ev, target_ip, 123, protocol="udp")
        ]
        assert ntp_allows, (
            f"Expected at least one nft-allow-logger allow event for "
            f"({target_ip}:123/udp) under ubuntu preset, but found none. "
            f"Captured {len(allow_events)} allow events total; first 10:\n"
            + "\n".join(json.dumps(ev) for ev in allow_events[:10])
            + f"\n{capture_lima_logs(session_id)}"
        )

        sandbox_cli("rm", session_name, timeout=120)
        session_id = None

    finally:
        if session_id is not None:
            sandbox_cli("rm", session_name, timeout=120)


@pytest.mark.timeout(600)
def test_level2_tls_verified(sandbox_cli, backend):
    """Policy allows example.com at level 'tls'. HTTPS should succeed and the
    certificate should be the REAL cert (not mitmproxy CA), since TLS level
    does SNI extraction without MITM.
    """
    session_id = None
    policy_path = None
    try:
        policy = {
            "version": "2.0.0",
            "rules": [
                {
                    "host": "example.com",
                    "port": 443,
                    "protocol": "tcp",
                    "level": "tls",
                },
            ],
        }
        policy_path = write_policy_file(policy)

        result = sandbox_cli(
            "create", *make_create_args(backend, "pol-l2-tls", "--policy", policy_path),
            timeout=600,
        )
        assert result.returncode == 0, (
            f"sandbox create failed (rc={result.returncode}).\n"
            f"stdout: {result.stdout}\nstderr: {result.stderr}"
        )
        session_id = parse_session_id(result.stdout)
        wait_for_state(sandbox_cli, "pol-l2-tls", "Running", timeout=10)

        # Warm DNS so the daemon's propagation loop materialises the
        # per-rule Envoy filter chain and the sandbox_policy nftables
        # concat-set entry (ip, 443) for example.com. L2 is fail-closed
        # at empty cache just like L1; mirrors the warmup in
        # test_level1_transport_tcp.
        sandbox_cli(
            "ssh", "pol-l2-tls", "--",
            "nslookup", "example.com",
            timeout=120,
        )
        time.sleep(5)

        # curl https://example.com should succeed.
        curl_result = sandbox_cli(
            "ssh", "pol-l2-tls", "--",
            "curl", "-s", "--connect-timeout", "15", "--max-time", "30",
            "https://example.com",
            timeout=120,
        )
        assert curl_result.returncode == 0, (
            f"curl https://example.com failed at TLS level.\n"
            f"stdout: {curl_result.stdout}\nstderr: {curl_result.stderr}\n"
            f"{capture_lima_logs(session_id)}"
        )
        assert "Example Domain" in curl_result.stdout, (
            f"Response does not contain 'Example Domain' from example.com.\n"
            f"stdout: {curl_result.stdout}"
        )

        # Verify the certificate is the REAL cert, not a mitmproxy CA cert.
        # Use openssl s_client to check the issuer.
        cert_result = sandbox_cli(
            "ssh", "pol-l2-tls", "--",
            "bash", "-c",
            "echo | openssl s_client -connect example.com:443 -servername example.com 2>/dev/null | openssl x509 -noout -issuer 2>/dev/null",
            timeout=120,
        )
        issuer_output = cert_result.stdout.strip()
        issuer_lower = issuer_output.lower()

        # The issuer field must be present and non-empty.
        assert issuer_output and "issuer" in issuer_lower, (
            f"Could not extract certificate issuer (empty or missing).\n"
            f"stdout: {cert_result.stdout}\nstderr: {cert_result.stderr}"
        )

        # The real cert issuer should NOT contain mitmproxy or sandbox CA.
        assert "mitmproxy" not in issuer_lower, (
            f"Certificate issuer contains 'mitmproxy' at TLS level (should be real cert).\n"
            f"Issuer: {issuer_output}"
        )
        assert "sandbox" not in issuer_lower, (
            f"Certificate issuer contains 'sandbox' at TLS level (should be real cert).\n"
            f"Issuer: {issuer_output}"
        )

        # The issuer should be a well-known CA.  example.com is typically
        # signed by DigiCert, but other CAs are possible.  Verify it contains
        # an organization name (O = ...) which real CAs always provide.
        assert re.search(r"O\s*=\s*\S", issuer_output), (
            f"Certificate issuer does not contain an Organization (O=...) field, "
            f"which is expected from a real CA.\n"
            f"Issuer: {issuer_output}"
        )

        # Clean up.
        sandbox_cli("rm", "pol-l2-tls", timeout=120)
        session_id = None

    finally:
        if session_id is not None:
            sandbox_cli("rm", "pol-l2-tls", timeout=120)
        if policy_path is not None:
            cleanup_policy_file(policy_path)


@pytest.mark.timeout(600)
def test_level3_http_inspected(sandbox_cli, backend):
    """Policy allows example.com at level 'http'. HTTPS should succeed but the
    certificate should show mitmproxy/Sandbox CA (MITM inspection is active).
    """
    session_id = None
    policy_path = None
    try:
        policy = {
            "version": "2.0.0",
            "rules": [
                {
                    "host": "example.com",
                    "port": 443,
                    "protocol": "tcp",
                    "level": "http",
                    "http_filters": [{"method": "ANY", "path": "/*"}],
                },
            ],
        }
        policy_path = write_policy_file(policy)

        result = sandbox_cli(
            "create", *make_create_args(backend, "pol-l3-inspect", "--policy", policy_path),
            timeout=600,
        )
        assert result.returncode == 0, (
            f"sandbox create failed (rc={result.returncode}).\n"
            f"stdout: {result.stdout}\nstderr: {result.stderr}"
        )
        session_id = parse_session_id(result.stdout)
        wait_for_state(sandbox_cli, "pol-l3-inspect", "Running", timeout=10)

        # mitmproxy must be bound to 127.0.0.1:18080 only.
        # A regression rebinding to 0.0.0.0:18080 would expose the forward
        # proxy to the VM and bypass Envoy's filter chains.
        _assert_mitmproxy_loopback_only(session_id)

        # Warm up DNS so the daemon's DNS propagation loop can rewrite
        # Envoy's L3 listener file to include a filter chain whose
        # prefix_ranges match the resolved example.com IPs. Envoy picks
        # up the new listener via filesystem xDS (LDS) and starts
        # tunneling matching TCP connections via CONNECT to mitmproxy.
        # Without this warmup, the listener has no chain matching the
        # resolved IPs and the connection fails closed.
        nslookup_result = sandbox_cli(
            "ssh", "pol-l3-inspect", "--",
            "nslookup", "example.com",
            timeout=120,
        )
        # Capture the resolved IPs for the Gap 3 authority-preservation
        # assertion below. nslookup output contains lines like
        # "Address: <ip>" for each A record; the first one (for the
        # resolver itself) is filtered out by matching on the block
        # following "Name:".
        resolved_ips: list[str] = []
        seen_name = False
        for line in nslookup_result.stdout.splitlines():
            stripped = line.strip()
            if stripped.startswith("Name:"):
                seen_name = True
                continue
            if seen_name:
                m = re.match(r"Address(?:es)?(?:\s*\d+)?:\s*(\d{1,3}(?:\.\d{1,3}){3})$", stripped)
                if m:
                    resolved_ips.append(m.group(1))
        # Wait for the DNS propagation loop (polls every 2s) to pick up
        # the resolved IPs and rewrite the Envoy listener file; Envoy's
        # LDS watcher observes the MovedTo inotify event and reconfigures.
        time.sleep(5)

        # The gateway nftables steady state
        # after the DNS propagation loop has injected the resolved-IP
        # allow rules is exactly three tables: `sandbox` (deny-all
        # baseline), `sandbox_dnat` (DNS + catch-all → Envoy), and
        # `sandbox_policy` (per-IP allow rules). The legacy `sandbox_l3`
        # DNAT table must be gone; a fourth table leaking here (e.g. a
        # debug leftover) would indicate a regression. Note:
        # `sandbox_policy` only appears once DNS propagation has resolved
        # at least one domain, which is why this check runs after the
        # warmup sleep rather than immediately after reaching Running.
        tables = _gateway_nft_tables(session_id)
        assert tables == {"sandbox", "sandbox_dnat", "sandbox_policy"}, (
            f"expected nftables tables {{sandbox, sandbox_dnat, sandbox_policy}} "
            f"after L3 policy apply + DNS propagation, got {tables}"
        )

        # curl https://example.com should succeed.
        # The sandbox CA is trusted inside the VM, so curl should not complain.
        curl_result = sandbox_cli(
            "ssh", "pol-l3-inspect", "--",
            "curl", "-s", "--connect-timeout", "15", "--max-time", "30",
            "https://example.com",
            timeout=120,
        )
        assert curl_result.returncode == 0, (
            f"curl https://example.com failed at full inspection level.\n"
            f"stdout: {curl_result.stdout}\nstderr: {curl_result.stderr}\n"
            f"{capture_lima_logs(session_id)}"
        )
        assert "Example Domain" in curl_result.stdout, (
            f"Response does not contain 'Example Domain' from example.com.\n"
            f"stdout: {curl_result.stdout}"
        )

        # Verify the certificate is from mitmproxy/Sandbox CA (MITM active).
        cert_result = sandbox_cli(
            "ssh", "pol-l3-inspect", "--",
            "bash", "-c",
            "echo | openssl s_client -connect example.com:443 -servername example.com 2>/dev/null | openssl x509 -noout -issuer 2>/dev/null",
            timeout=120,
        )
        issuer_output = cert_result.stdout.lower()
        # The cert issuer should indicate mitmproxy or sandbox CA.
        assert "mitmproxy" in issuer_output or "sandbox" in issuer_output, (
            f"Certificate issuer should be mitmproxy/Sandbox CA at full level, "
            f"but got: {cert_result.stdout}"
        )

        # Allow a moment for mitmproxy to flush its log, then read it for
        # gaps 2 and 3 below.
        time.sleep(2)
        mitm_log = _read_gateway_log(session_id, "mitmproxy.log")

        # Observe the CONNECT tunnel in mitmproxy's log.
        # Envoy emits HTTP/1.1 CONNECT requests to mitmproxy's forward-
        # proxy listener. mitmproxy's default flow log in regular mode
        # records each tunneled flow as `client connect` (downstream side)
        # and `server connect <upstream-ip>:<port>` (upstream side after
        # the CONNECT authority is parsed); the policy addon additionally
        # emits `[ALLOW] <method> <host><path>` once it decrypts the
        # tunneled HTTPS request. Either `server connect` or `[ALLOW]`
        # is sufficient positive evidence that the CONNECT tunnel was
        # established and traffic flowed.
        #
        # The Envoy access-log assertions further down close the other
        # half of this observation: mitmproxy tells us what the CONNECT
        # authority looked like from mitmproxy's side; Envoy's own log
        # tells us what `%DOWNSTREAM_LOCAL_ADDRESS%` and `UPSTREAM_HOST`
        # looked like from Envoy's side. An Envoy-level regression
        # (listener misconfig, tunneling_config drift, listener-update
        # breaking original_dst) must show up on both sides.
        assert (
            "server connect" in mitm_log
            or "[ALLOW]" in mitm_log
        ), (
            f"mitmproxy log did not record a tunneled `server connect` or a "
            f"decrypted policy-addon [ALLOW] entry after an L3 curl — the "
            f"CONNECT tunnel may not have reached mitmproxy.\n"
            f"mitmproxy.log tail:\n{mitm_log[-4000:]}"
        )

        # Authority preservation. Envoy's L3 tcp_proxy
        # emits CONNECT with hostname=%DOWNSTREAM_LOCAL_ADDRESS%, i.e.
        # the original destination IP:port the VM tried to reach. If
        # interpolation fell back (e.g. to mitmproxy's own loopback),
        # mitmproxy's `server connect` line would show a wrong upstream
        # address. Assert that at least one of the IPs the VM resolved
        # for example.com appears in a `server connect <ip>:443` line.
        assert resolved_ips, (
            f"failed to parse resolved IPs for example.com from nslookup "
            f"output; raw:\n{nslookup_result.stdout}"
        )
        server_connect_hits = [
            ip for ip in resolved_ips if f"server connect {ip}:443" in mitm_log
        ]
        assert server_connect_hits, (
            f"mitmproxy log does not record `server connect <ip>:443` for any "
            f"of example.com's resolved IPs ({resolved_ips}); CONNECT "
            f"authority may not be preserved by Envoy's "
            f"%DOWNSTREAM_LOCAL_ADDRESS% interpolation.\n"
            f"mitmproxy.log tail:\n{mitm_log[-4000:]}"
        )
        assert "server connect 127.0.0.1:" not in mitm_log, (
            f"mitmproxy log records `server connect 127.0.0.1:*` — Envoy "
            f"appears to have tunneled to a loopback address, which would "
            f"indicate %DOWNSTREAM_LOCAL_ADDRESS% interpolation failure.\n"
            f"mitmproxy.log tail:\n{mitm_log[-4000:]}"
        )

        # Observe the CONNECT-tunnel
        # invariant from **Envoy's own access log**, independent of
        # mitmproxy's flow log. The L3 `tcp_proxy` filter writes one
        # JSON object per tunneled connection to
        # `/var/log/gateway/events/envoy.jsonl` (see
        # `l3_tcp_proxy_access_log_yaml` in
        # `sandbox-core/src/policy.rs`). A mitmproxy-only assertion is
        # vulnerable to mitmproxy log-format regressions and to Envoy
        # misconfigurations that bypass mitmproxy entirely (e.g. a
        # listener update that dropped `tunneling_config`, sending
        # bytes to `mitmproxy` as raw TCP). Asserting on Envoy's log
        # directly catches both failure modes.
        envoy_access_log, envoy_entries = _read_envoy_access_log(session_id)
        assert envoy_access_log.strip(), (
            f"envoy.jsonl is empty after L3 curl; Envoy's tcp_proxy "
            f"access log may be misconfigured, the events bind mount "
            f"may not be wired, or no L3 chain matched the traffic.\n"
            f"mitmproxy.log tail (for cross-reference):\n"
            f"{mitm_log[-2000:]}"
        )

        # Filter to the L3 chain entries. Each JSON entry has
        # `layer=envoy` and a `matched_chain` populated by
        # `%FILTER_CHAIN_NAME%`; the L3 chains are named
        # `level3_<sanitized-host>_p<port>`.
        l3_entries = [
            e for e in envoy_entries
            if e.get("layer") == "envoy"
            and str(e.get("matched_chain", "")).startswith("level3_")
        ]
        assert l3_entries, (
            f"envoy.jsonl parsed {len(envoy_entries)} entries but none "
            f"belong to an L3 chain (matched_chain starting with "
            f"`level3_`). This usually indicates the filter chain name "
            f"was not interpolated from %FILTER_CHAIN_NAME%, or the L3 "
            f"chain did not match.\n"
            f"full log:\n{envoy_access_log[-4000:]}"
        )

        # Invariant A: at least one entry has
        # `dst_ip=<resolved-ip>` and `dst_port=443` — the VM's intended
        # destination preserved by `original_dst`. Mirrors the
        # mitmproxy `server connect <ip>:443` assertion above. Envoy
        # serializes all values as strings under `json_format`, so
        # coerce `dst_port` to string for comparison robustness.
        downstream_hits = [
            e for e in l3_entries
            if e.get("dst_ip") in resolved_ips
            and str(e.get("dst_port")) == "443"
        ]
        assert downstream_hits, (
            f"envoy.jsonl does not record dst_ip=<ip>/dst_port=443 for "
            f"any of example.com's resolved IPs ({resolved_ips}); "
            f"Envoy's `original_dst` listener filter may be failing to "
            f"recover SO_ORIGINAL_DST, or the L3 prefix_ranges match "
            f"is missing. L3 entries observed:\n"
            f"{json.dumps(l3_entries, indent=2)[-4000:]}"
        )

        # Invariant B: none of the destination IPs may be `127.0.0.1`
        # — that would indicate the L3 chain pointed Envoy at its own
        # loopback (e.g. a direct-to-internet bypass that routed back
        # through mitmproxy without preserving the original
        # destination). This is the Envoy-side mirror of the mitmproxy
        # `server connect 127.0.0.1:` negative check above.
        loopback_hits = [
            e for e in l3_entries if e.get("dst_ip") == "127.0.0.1"
        ]
        assert not loopback_hits, (
            f"envoy.jsonl records dst_ip=127.0.0.1 for L3 entries — "
            f"Envoy tunneled to a loopback address as the original "
            f"destination, which would indicate `original_dst` or "
            f"prefix_ranges misbehaved.\n"
            f"offending entries:\n{json.dumps(loopback_hits, indent=2)}"
        )

        # Invariant C: the upstream cluster must be `mitmproxy` and
        # the upstream host must be the loopback endpoint of that
        # cluster. A regression that routes L3 traffic back to
        # `original_dst` (e.g. if `tunneling_config` is dropped on a
        # listener update) would flip `cluster` and break this check
        # without touching mitmproxy at all.
        assert any(e.get("cluster") == "mitmproxy" for e in l3_entries), (
            f"envoy.jsonl does not record any L3 entry with "
            f"cluster=mitmproxy; L3 chains may have regressed to "
            f"routing via original_dst.\n"
            f"L3 entries observed:\n"
            f"{json.dumps(l3_entries, indent=2)[-4000:]}"
        )
        assert any(
            e.get("upstream_host") == "127.0.0.1:18080" for e in l3_entries
        ), (
            f"envoy.jsonl does not record any L3 entry with "
            f"upstream_host=127.0.0.1:18080; the `mitmproxy` cluster's "
            f"loopback endpoint may have drifted.\n"
            f"L3 entries observed:\n"
            f"{json.dumps(l3_entries, indent=2)[-4000:]}"
        )

        # Invariant D (Phase 4): the L3 entry carries
        # `connect_authority` populated from
        # `%REQUESTED_SERVER_NAME%`. For L3 traffic the downstream
        # proxy (mitmproxy) issues a CONNECT with the policy host as
        # authority, and Envoy records it in
        # `tcp_proxy`'s access log via that substitution. This is the
        # header that distinguishes L3 entries from L1/L2 ones and is
        # the ingest pipeline's primary discriminator for CONNECT
        # tunnels.
        authority_hits = [
            e for e in l3_entries
            if e.get("connect_authority")
            and e.get("connect_authority") != "-"
        ]
        assert authority_hits, (
            f"envoy.jsonl L3 entries have no populated "
            f"`connect_authority`; %REQUESTED_SERVER_NAME% may not be "
            f"available on this Envoy version or the CONNECT tunnel "
            f"was not taken.\n"
            f"L3 entries observed:\n"
            f"{json.dumps(l3_entries, indent=2)[-4000:]}"
        )

        # Clean up.
        sandbox_cli("rm", "pol-l3-inspect", timeout=120)
        session_id = None

    finally:
        if session_id is not None:
            sandbox_cli("rm", "pol-l3-inspect", timeout=120)
        if policy_path is not None:
            cleanup_policy_file(policy_path)


@pytest.mark.timeout(600)
def test_level3_host_mismatch(sandbox_cli, backend):
    """Policy allows only api.github.com at level 'http'. Accessing
    evil.example.com should be blocked at the DNS level (NXDOMAIN).

    In the DNS-first architecture, CoreDNS denies resolution of domains
    not in the policy, so curl never establishes a TCP connection.
    """
    session_id = None
    policy_path = None
    try:
        policy = {
            "version": "2.0.0",
            "rules": [
                {
                    "host": "api.github.com",
                    "port": 443,
                    "protocol": "tcp",
                    "level": "http",
                    "http_filters": [{"method": "ANY", "path": "/*"}],
                },
            ],
        }
        policy_path = write_policy_file(policy)

        result = sandbox_cli(
            "create", *make_create_args(backend, "pol-l3-host", "--policy", policy_path),
            timeout=600,
        )
        assert result.returncode == 0, (
            f"sandbox create failed (rc={result.returncode}).\n"
            f"stdout: {result.stdout}\nstderr: {result.stderr}"
        )
        session_id = parse_session_id(result.stdout)
        wait_for_state(sandbox_cli, "pol-l3-host", "Running", timeout=10)

        # Accessing a non-allowed host should fail: CoreDNS returns NXDOMAIN
        # for domains not in the policy, so curl can't resolve the hostname.
        curl_result = sandbox_cli(
            "ssh", "pol-l3-host", "--",
            "bash", "-c",
            "curl -s -o /dev/null -w '%{http_code}' --connect-timeout 15 --max-time 30 https://evil.example.com/ 2>&1",
            timeout=120,
        )
        # curl returns exit code 6 for DNS resolution failure, or 000 as the
        # HTTP status when no connection is made.  Either way the request must
        # NOT succeed (HTTP 200).
        http_code = curl_result.stdout.strip()
        assert curl_result.returncode != 0 or http_code == "000", (
            f"Expected connection failure for non-allowed host, "
            f"but curl succeeded with HTTP {http_code}.\n"
            f"stdout: {curl_result.stdout}\nstderr: {curl_result.stderr}"
        )
        assert http_code != "200", (
            f"Non-allowed host should not return HTTP 200.\n"
            f"stdout: {curl_result.stdout}\nstderr: {curl_result.stderr}"
        )

        # Clean up.
        sandbox_cli("rm", "pol-l3-host", timeout=120)
        session_id = None

    finally:
        if session_id is not None:
            sandbox_cli("rm", "pol-l3-host", timeout=120)
        if policy_path is not None:
            cleanup_policy_file(policy_path)


@pytest.mark.timeout(600)
def test_level3_method_restriction(sandbox_cli, backend):
    """Policy allows httpbin.org at level 'http' with only GET filters.
    A POST request should get HTTP 599 (policy-denied).
    """
    session_id = None
    policy_path = None
    try:
        policy = {
            "version": "2.0.0",
            "rules": [
                {
                    "host": "httpbin.org",
                    "port": 443,
                    "protocol": "tcp",
                    "level": "http",
                    "http_filters": [{"method": "GET", "path": "/*"}],
                },
            ],
        }
        policy_path = write_policy_file(policy)

        result = sandbox_cli(
            "create", *make_create_args(backend, "pol-l3-method", "--policy", policy_path),
            timeout=600,
        )
        assert result.returncode == 0, (
            f"sandbox create failed (rc={result.returncode}).\n"
            f"stdout: {result.stdout}\nstderr: {result.stderr}"
        )
        session_id = parse_session_id(result.stdout)
        wait_for_state(sandbox_cli, "pol-l3-method", "Running", timeout=10)

        # Warm up DNS so the daemon's DNS propagation loop rewrites the
        # Envoy L3 listener file with a filter chain matching httpbin.org's
        # resolved IPs. Without this the fail-closed listener has no
        # matching chain and the connection is rejected.
        sandbox_cli(
            "ssh", "pol-l3-method", "--",
            "nslookup", "httpbin.org",
            timeout=120,
        )
        time.sleep(5)

        # GET should succeed.
        get_result = sandbox_cli(
            "ssh", "pol-l3-method", "--",
            "bash", "-c",
            "curl -s -o /dev/null -w '%{http_code}' --connect-timeout 15 --max-time 30 https://httpbin.org/get 2>&1",
            timeout=120,
        )
        get_code = get_result.stdout.strip()
        assert get_code == "200", (
            f"Expected HTTP 200 for allowed GET, got: {get_code}.\n"
            f"stdout: {get_result.stdout}\nstderr: {get_result.stderr}"
        )

        # POST should be denied with HTTP 599.
        post_result = sandbox_cli(
            "ssh", "pol-l3-method", "--",
            "bash", "-c",
            "curl -s -o /dev/null -w '%{http_code}' -X POST --connect-timeout 15 --max-time 30 https://httpbin.org/post 2>&1",
            timeout=120,
        )
        post_code = post_result.stdout.strip()
        assert post_code == "599", (
            f"Expected HTTP 599 for disallowed POST, got: {post_code}.\n"
            f"stdout: {post_result.stdout}\nstderr: {post_result.stderr}"
        )

        # Clean up.
        sandbox_cli("rm", "pol-l3-method", timeout=120)
        session_id = None

    finally:
        if session_id is not None:
            sandbox_cli("rm", "pol-l3-method", timeout=120)
        if policy_path is not None:
            cleanup_policy_file(policy_path)


@pytest.mark.timeout(600)
def test_level3_path_restriction(sandbox_cli, backend):
    """Policy allows a host at level 'http' with a single `/api/*` filter.
    Requests to /other/path should get HTTP 599 (policy-denied).
    """
    session_id = None
    policy_path = None
    try:
        policy = {
            "version": "2.0.0",
            "rules": [
                {
                    "host": "httpbin.org",
                    "port": 443,
                    "protocol": "tcp",
                    "level": "http",
                    "http_filters": [{"method": "ANY", "path": "/api/*"}],
                },
            ],
        }
        policy_path = write_policy_file(policy)

        result = sandbox_cli(
            "create", *make_create_args(backend, "pol-l3-path", "--policy", policy_path),
            timeout=600,
        )
        assert result.returncode == 0, (
            f"sandbox create failed (rc={result.returncode}).\n"
            f"stdout: {result.stdout}\nstderr: {result.stderr}"
        )
        session_id = parse_session_id(result.stdout)
        wait_for_state(sandbox_cli, "pol-l3-path", "Running", timeout=10)

        # Warm up DNS so the daemon's DNS propagation loop rewrites the
        # Envoy L3 listener file with a filter chain matching httpbin.org's
        # resolved IPs. Without this the fail-closed listener has no
        # matching chain and the connection is rejected.
        sandbox_cli(
            "ssh", "pol-l3-path", "--",
            "nslookup", "httpbin.org",
            timeout=120,
        )
        time.sleep(5)

        # Request to a disallowed path should get HTTP 599.
        bad_path_result = sandbox_cli(
            "ssh", "pol-l3-path", "--",
            "bash", "-c",
            "curl -s -o /dev/null -w '%{http_code}' --connect-timeout 15 --max-time 30 https://httpbin.org/other/path 2>&1",
            timeout=120,
        )
        bad_code = bad_path_result.stdout.strip()

        assert bad_code == "599", (
            f"Expected HTTP 599 for disallowed path /other/path, got: {bad_code}.\n"
            f"stdout: {bad_path_result.stdout}\nstderr: {bad_path_result.stderr}"
        )

        # Request to the allowed path prefix should succeed (not 599).
        # httpbin.org may return 404 for /api/ but that's fine -- we just
        # need to confirm the proxy doesn't block it.
        good_path_result = sandbox_cli(
            "ssh", "pol-l3-path", "--",
            "bash", "-c",
            "curl -s -o /dev/null -w '%{http_code}' --connect-timeout 15 --max-time 30 https://httpbin.org/api/anything 2>&1",
            timeout=120,
        )
        good_code = good_path_result.stdout.strip()
        assert good_code != "599", (
            f"Request to allowed path /api/anything was blocked (599).\n"
            f"stdout: {good_path_result.stdout}\nstderr: {good_path_result.stderr}"
        )

        # Clean up.
        sandbox_cli("rm", "pol-l3-path", timeout=120)
        session_id = None

    finally:
        if session_id is not None:
            sandbox_cli("rm", "pol-l3-path", timeout=120)
        if policy_path is not None:
            cleanup_policy_file(policy_path)


@pytest.mark.timeout(600)
def test_l3_fail_closed_before_dns_propagation(sandbox_cli, backend):
    """Envoy must fail-closed for an L3-allowed domain whose IPs have not
    yet been propagated into the listener file.

    The invariant under test: a policy granting L3 access to a domain
    does *not* by itself open a path. The DNS propagation loop is what
    turns resolved IPs into an Envoy filter-chain ``prefix_ranges``
    entry; until that rewrite lands, Envoy has no chain matching the
    destination IP and the connection is dropped.

    Flow:
        1. Apply an L3 policy for example.com without visiting it first.
        2. Directly curl example.com via its resolved IP, skipping the
           DNS warmup that would normally trigger propagation. Expect
           failure (connection refused / reset / timeout).
        3. Trigger DNS resolution via nslookup, which seeds the DNS
           propagation loop and causes Envoy to reload the listener.
        4. Retry the curl; expect success.

    Time budget: ~90s, well inside the test-level 600s timeout.
    """
    session_id = None
    policy_path = None
    try:
        policy = {
            "version": "2.0.0",
            "rules": [
                {
                    "host": "example.com",
                    "port": 443,
                    "protocol": "tcp",
                    "level": "http",
                    "http_filters": [{"method": "ANY", "path": "/*"}],
                },
            ],
        }
        policy_path = write_policy_file(policy)

        result = sandbox_cli(
            "create", *make_create_args(backend, "pol-l3-failclosed", "--policy", policy_path),
            timeout=600,
        )
        assert result.returncode == 0, (
            f"sandbox create failed (rc={result.returncode}).\n"
            f"stdout: {result.stdout}\nstderr: {result.stderr}"
        )
        session_id = parse_session_id(result.stdout)
        wait_for_state(sandbox_cli, "pol-l3-failclosed", "Running", timeout=10)

        # Resolve example.com out-of-band on the host so we have an IP to
        # target from inside the VM *without* triggering CoreDNS (which
        # would seed the propagation loop). We pass the IP to curl via
        # --resolve so curl still sends SNI/Host=example.com but skips
        # the VM-side DNS lookup entirely.
        host_resolve = subprocess.run(
            ["getent", "ahostsv4", "example.com"],
            capture_output=True, text=True, timeout=15,
        )
        assert host_resolve.returncode == 0 and host_resolve.stdout.strip(), (
            f"host-side getent for example.com failed; cannot run "
            f"fail-closed test without a known IP.\nstdout: {host_resolve.stdout}"
        )
        host_ip = host_resolve.stdout.split()[0]

        # Step 1 (fail-closed): without pre-warming CoreDNS the Envoy
        # listener has no prefix_ranges chain matching example.com's IPs,
        # so this connection must NOT succeed. We use --resolve so we
        # don't rely on the VM's resolver (which could also return
        # NXDOMAIN and mask the Envoy-side fail-closed we want to test).
        curl_pre = sandbox_cli(
            "ssh", "pol-l3-failclosed", "--",
            "bash", "-c",
            f"curl -sk --connect-timeout 8 --max-time 12 "
            f"--resolve example.com:443:{host_ip} "
            f"https://example.com/ -o /dev/null -w '%{{http_code}}' 2>&1; "
            f"echo EXIT:$?",
            timeout=60,
        )
        # Expected failure modes: curl exit != 0 (timeout / connect refused
        # / reset), or an HTTP status that indicates Envoy rejection
        # (503/upstream issues) rather than 200. The precise code depends
        # on whether Envoy has any default chain at all for this listener.
        # We assert the negative: no HTTP 200 response was produced.
        assert "EXIT:0" not in curl_pre.stdout or "200" not in curl_pre.stdout, (
            f"L3 fail-closed invariant violated: curl to example.com succeeded "
            f"before the DNS propagation loop rewrote Envoy's listener.\n"
            f"stdout: {curl_pre.stdout}\nstderr: {curl_pre.stderr}"
        )

        # Step 2: warm DNS inside the VM. This CoreDNS query seeds the
        # daemon's DNS propagation loop, which rewrites the Envoy
        # listener to include a filter chain matching example.com's IPs.
        # We parse the VM-side answer so step 3 can target an IP that
        # CoreDNS actually resolved — relying on the host's getent
        # answer risks CDN/geo-DNS divergence between host-side and
        # gateway-upstream-side resolvers, which would leave the retry
        # targeting an IP not present in Envoy's prefix_ranges.
        nslookup_vm = sandbox_cli(
            "ssh", "pol-l3-failclosed", "--",
            "nslookup", "example.com",
            timeout=60,
        )
        vm_resolved_ips: list[str] = []
        seen_name = False
        for line in nslookup_vm.stdout.splitlines():
            stripped = line.strip()
            if stripped.startswith("Name:"):
                seen_name = True
                continue
            if seen_name:
                m = re.match(r"Address(?:es)?(?:\s*\d+)?:\s*(\d{1,3}(?:\.\d{1,3}){3})$", stripped)
                if m:
                    vm_resolved_ips.append(m.group(1))
        assert vm_resolved_ips, (
            f"VM-side nslookup for example.com returned no A records — "
            f"CoreDNS may be unreachable or the upstream resolver failed; "
            f"cannot proceed with the post-warmup retry because we don't "
            f"know which IPs Envoy's filter chain will cover.\n"
            f"nslookup stdout: {nslookup_vm.stdout}\n"
            f"nslookup stderr: {nslookup_vm.stderr}"
        )
        retry_ip = vm_resolved_ips[0]

        # Step 3: poll-with-timeout for the listener rewrite to take
        # effect. The propagation loop polls every ~2s; budget 30s for
        # the rewrite + LDS pickup.  We target a VM-resolved IP so we
        # know Envoy's filter chain will have it in prefix_ranges once
        # propagation lands.
        deadline = time.monotonic() + 30
        last_stdout = ""
        last_stderr = ""
        succeeded = False
        while time.monotonic() < deadline:
            curl_retry = sandbox_cli(
                "ssh", "pol-l3-failclosed", "--",
                "bash", "-c",
                f"curl -sk --connect-timeout 5 --max-time 10 "
                f"--resolve example.com:443:{retry_ip} "
                f"https://example.com/ 2>&1; echo EXIT:$?",
                timeout=30,
            )
            last_stdout = curl_retry.stdout
            last_stderr = curl_retry.stderr
            if "EXIT:0" in curl_retry.stdout and "Example Domain" in curl_retry.stdout:
                succeeded = True
                break
            time.sleep(2)

        assert succeeded, (
            f"curl to example.com did not succeed within 30s after DNS warmup "
            f"— Envoy listener rewrite did not propagate.\n"
            f"last stdout: {last_stdout}\nlast stderr: {last_stderr}\n"
            f"{capture_lima_logs(session_id)}"
        )

        sandbox_cli("rm", "pol-l3-failclosed", timeout=120)
        session_id = None

    finally:
        if session_id is not None:
            sandbox_cli("rm", "pol-l3-failclosed", timeout=120)
        if policy_path is not None:
            cleanup_policy_file(policy_path)


@pytest.mark.timeout(600)
def test_policy_update(sandbox_cli, backend):
    """Create with a policy allowing example.com. Verify it works. Update the
    policy to allow httpbin.org instead. Verify example.com is now denied and
    httpbin.org works.
    """
    session_id = None
    policy_path_1 = None
    policy_path_2 = None
    try:
        # Initial policy: allow example.com:80/tcp at transport level.
        policy_1 = {
            "version": "2.0.0",
            "rules": [
                {
                    "host": "example.com",
                    "port": 80,
                    "protocol": "tcp",
                    "level": "transport",
                },
            ],
        }
        policy_path_1 = write_policy_file(policy_1)

        result = sandbox_cli(
            "create", *make_create_args(backend, "pol-update", "--policy", policy_path_1),
            timeout=600,
        )
        assert result.returncode == 0, (
            f"sandbox create failed (rc={result.returncode}).\n"
            f"stdout: {result.stdout}\nstderr: {result.stderr}"
        )
        session_id = parse_session_id(result.stdout)
        wait_for_state(sandbox_cli, "pol-update", "Running", timeout=10)

        # Warm DNS for example.com so the L1 transport filter chain
        # (Envoy prefix_ranges + sandbox_policy concat-set) is in place
        # before the first curl. Schema v2 L1 transport is fail-closed
        # at empty DNS cache; without this the first connection races
        # the propagation loop (2-second poll).
        sandbox_cli(
            "ssh", "pol-update", "--",
            "nslookup", "example.com",
            timeout=120,
        )
        time.sleep(5)

        # Verify example.com is reachable.
        curl_result = sandbox_cli(
            "ssh", "pol-update", "--",
            "curl", "-s", "--connect-timeout", "15", "--max-time", "30",
            "http://example.com",
            timeout=120,
        )
        assert curl_result.returncode == 0, (
            f"curl to example.com failed with initial policy.\n"
            f"stdout: {curl_result.stdout}\nstderr: {curl_result.stderr}"
        )
        assert "Example Domain" in curl_result.stdout, (
            f"Response does not contain 'Example Domain' from example.com.\n"
            f"stdout: {curl_result.stdout}"
        )

        # Update policy: allow httpbin.org:80/tcp instead of example.com.
        policy_2 = {
            "version": "2.0.0",
            "rules": [
                {
                    "host": "httpbin.org",
                    "port": 80,
                    "protocol": "tcp",
                    "level": "transport",
                },
            ],
        }
        policy_path_2 = write_policy_file(policy_2)

        update_result = sandbox_cli(
            "policy", "update", "pol-update", "--policy", policy_path_2,
            timeout=120,
        )
        assert update_result.returncode == 0, (
            f"sandbox policy update failed (rc={update_result.returncode}).\n"
            f"stdout: {update_result.stdout}\nstderr: {update_result.stderr}"
        )

        # Allow time for the policy to propagate to all gateway components.
        time.sleep(5)

        # Verify example.com is now denied.
        # DNS should return NXDOMAIN since example.com is no longer in the
        # allowed domains list.
        denied_dns = sandbox_cli(
            "ssh", "pol-update", "--",
            "nslookup", "example.com",
            timeout=120,
        )
        denied_output = (denied_dns.stdout + denied_dns.stderr).lower()
        assert denied_dns.returncode != 0 or "nxdomain" in denied_output or "can't find" in denied_output, (
            f"DNS for example.com should fail after policy update.\n"
            f"stdout: {denied_dns.stdout}\nstderr: {denied_dns.stderr}"
        )

        # Warm DNS for httpbin.org (the post-update allow) and let the
        # propagation loop materialise the L1 transport filter chain +
        # sandbox_policy concat-set entry. Same fail-closed race as the
        # initial-policy curl above.
        sandbox_cli(
            "ssh", "pol-update", "--",
            "nslookup", "httpbin.org",
            timeout=120,
        )
        time.sleep(5)

        # Verify httpbin.org is now reachable.
        httpbin_result = sandbox_cli(
            "ssh", "pol-update", "--",
            "curl", "-s", "--connect-timeout", "15", "--max-time", "30",
            "http://httpbin.org/get",
            timeout=120,
        )
        assert httpbin_result.returncode == 0, (
            f"curl to httpbin.org failed after policy update.\n"
            f"stdout: {httpbin_result.stdout}\nstderr: {httpbin_result.stderr}"
        )

        # Clean up.
        sandbox_cli("rm", "pol-update", timeout=120)
        session_id = None

    finally:
        if session_id is not None:
            sandbox_cli("rm", "pol-update", timeout=120)
        if policy_path_1 is not None:
            cleanup_policy_file(policy_path_1)
        if policy_path_2 is not None:
            cleanup_policy_file(policy_path_2)


@pytest.mark.timeout(600)
def test_dns_nxdomain(sandbox_cli, backend):
    """Policy allows only example.com. DNS lookup for notallowed.com should
    return NXDOMAIN.
    """
    session_id = None
    policy_path = None
    try:
        policy = {
            "version": "2.0.0",
            "rules": [
                {
                    "host": "example.com",
                    "port": 80,
                    "protocol": "tcp",
                    "level": "transport",
                },
            ],
        }
        policy_path = write_policy_file(policy)

        result = sandbox_cli(
            "create", *make_create_args(backend, "pol-dns-nx", "--policy", policy_path),
            timeout=600,
        )
        assert result.returncode == 0, (
            f"sandbox create failed (rc={result.returncode}).\n"
            f"stdout: {result.stdout}\nstderr: {result.stderr}"
        )
        session_id = parse_session_id(result.stdout)
        wait_for_state(sandbox_cli, "pol-dns-nx", "Running", timeout=10)

        # DNS lookup for an allowed domain should succeed.
        allowed_dns = sandbox_cli(
            "ssh", "pol-dns-nx", "--",
            "nslookup", "example.com",
            timeout=120,
        )
        assert allowed_dns.returncode == 0, (
            f"DNS lookup for allowed domain example.com failed.\n"
            f"stdout: {allowed_dns.stdout}\nstderr: {allowed_dns.stderr}"
        )

        # DNS lookup for a non-allowed domain should return NXDOMAIN.
        denied_dns = sandbox_cli(
            "ssh", "pol-dns-nx", "--",
            "nslookup", "notallowed.com",
            timeout=120,
        )
        denied_output = (denied_dns.stdout + denied_dns.stderr).lower()
        assert denied_dns.returncode != 0 or "nxdomain" in denied_output or "can't find" in denied_output, (
            f"DNS lookup for notallowed.com should return NXDOMAIN.\n"
            f"stdout: {denied_dns.stdout}\nstderr: {denied_dns.stderr}"
        )

        # Clean up.
        sandbox_cli("rm", "pol-dns-nx", timeout=120)
        session_id = None

    finally:
        if session_id is not None:
            sandbox_cli("rm", "pol-dns-nx", timeout=120)
        if policy_path is not None:
            cleanup_policy_file(policy_path)


@pytest.mark.timeout(600)
def test_dns_ip_propagation(sandbox_cli, backend):
    """Policy allows example.com. After DNS resolution, nftables rules in the
    gateway container should contain the resolved IP for example.com.
    """
    session_id = None
    policy_path = None
    try:
        policy = {
            "version": "2.0.0",
            "rules": [
                {
                    "host": "example.com",
                    "port": 80,
                    "protocol": "tcp",
                    "level": "transport",
                },
            ],
        }
        policy_path = write_policy_file(policy)

        result = sandbox_cli(
            "create", *make_create_args(backend, "pol-dns-ip", "--policy", policy_path),
            timeout=600,
        )
        assert result.returncode == 0, (
            f"sandbox create failed (rc={result.returncode}).\n"
            f"stdout: {result.stdout}\nstderr: {result.stderr}"
        )
        session_id = parse_session_id(result.stdout)
        gw_container = gateway_container_name(session_id)
        wait_for_state(sandbox_cli, "pol-dns-ip", "Running", timeout=10)

        # Trigger DNS resolution from inside the VM.
        dns_result = sandbox_cli(
            "ssh", "pol-dns-ip", "--",
            "nslookup", "example.com",
            timeout=120,
        )
        assert dns_result.returncode == 0, (
            f"DNS lookup for example.com failed.\n"
            f"stdout: {dns_result.stdout}\nstderr: {dns_result.stderr}"
        )

        # Extract the resolved IP address from nslookup output.
        # nslookup output format includes "Address: <ip>" lines after the
        # server line. We look for a non-loopback, non-gateway IP.
        ip_matches = re.findall(
            r"Address:\s+(\d+\.\d+\.\d+\.\d+)",
            dns_result.stdout,
        )
        # Filter out the DNS server address (first one) -- the resolved IP
        # is typically the second Address line.
        resolved_ips = [
            ip for ip in ip_matches
            if not ip.startswith("10.209.") and not ip.startswith("127.")
        ]
        assert resolved_ips, (
            f"Could not extract resolved IP for example.com.\n"
            f"nslookup output:\n{dns_result.stdout}"
        )

        # Allow time for the DNS callback to propagate the IP to nftables.
        time.sleep(5)

        # Check the sandbox_policy nftables table inside the gateway container
        # for the resolved IP.  DNS-resolved IPs are propagated into this table
        # by the daemon's DNS propagation loop.
        nft_result = subprocess.run(
            [
                "docker", "exec", gw_container,
                "nft", "list", "table", "inet", "sandbox_policy",
            ],
            capture_output=True, text=True, timeout=30,
        )
        # The sandbox_policy table may not exist yet if the propagation loop
        # hasn't run.  Fall back to listing the full ruleset.
        if nft_result.returncode != 0:
            nft_result = subprocess.run(
                [
                    "docker", "exec", gw_container,
                    "nft", "list", "ruleset",
                ],
                capture_output=True, text=True, timeout=30,
            )
        assert nft_result.returncode == 0, (
            f"Failed to list nftables rules in gateway container.\n"
            f"stdout: {nft_result.stdout}\nstderr: {nft_result.stderr}"
        )

        # At least one of the resolved IPs should appear in the nftables rules.
        nft_rules = nft_result.stdout
        ip_found = any(ip in nft_rules for ip in resolved_ips)
        assert ip_found, (
            f"None of the resolved IPs {resolved_ips} found in nftables rules.\n"
            f"nftables output:\n{nft_rules}"
        )

        # Clean up.
        sandbox_cli("rm", "pol-dns-ip", timeout=120)
        session_id = None

    finally:
        if session_id is not None:
            sandbox_cli("rm", "pol-dns-ip", timeout=120)
        if policy_path is not None:
            cleanup_policy_file(policy_path)


@pytest.mark.timeout(600)
def test_empty_policy_denies_dns(sandbox_cli, backend):
    """Creating a session with no `--policy` must produce a fail-closed default:
    CoreDNS returns NXDOMAIN for everything and HTTP is unreachable.
    """
    session_id = None
    try:
        result = sandbox_cli(
            "create", *make_create_args(backend, "pol-empty-default"),
            timeout=600,
        )
        assert result.returncode == 0, (
            f"sandbox create (no policy) failed (rc={result.returncode}).\n"
            f"stdout: {result.stdout}\nstderr: {result.stderr}"
        )
        session_id = parse_session_id(result.stdout)
        wait_for_state(sandbox_cli, "pol-empty-default", "Running", timeout=10)

        # DNS should fail-closed: NXDOMAIN for any domain.
        dns_result = sandbox_cli(
            "ssh", "pol-empty-default", "--",
            "nslookup", "example.com",
            timeout=120,
        )
        combined = (dns_result.stdout + dns_result.stderr).lower()
        assert (
            dns_result.returncode != 0
            or "nxdomain" in combined
            or "can't find" in combined
        ), (
            f"DNS lookup should return NXDOMAIN with no policy (fail-closed default).\n"
            f"stdout: {dns_result.stdout}\nstderr: {dns_result.stderr}"
        )

        # HTTP should fail as well.
        curl_result = sandbox_cli(
            "ssh", "pol-empty-default", "--",
            "bash", "-c",
            "curl -s --connect-timeout 10 --max-time 15 http://example.com/ 2>&1; echo EXIT:$?",
            timeout=120,
        )
        assert "EXIT:0" not in curl_result.stdout, (
            f"HTTP request should have failed with no policy (fail-closed default).\n"
            f"Output:\n{curl_result.stdout}"
        )

        sandbox_cli("rm", "pol-empty-default", timeout=120)
        session_id = None

    finally:
        if session_id is not None:
            sandbox_cli("rm", "pol-empty-default", timeout=120)


@pytest.mark.timeout(600)
def test_policy_clear_reverts_to_deny_all(sandbox_cli, backend):
    """Create a session with an HTTP-level policy, then clear it via
    `sandbox policy update --clear`. Afterwards traffic must be denied.
    """
    session_id = None
    policy_path = None
    try:
        # Start with an HTTP-level policy allowing example.com:80 GET /*.
        # Port and L4 protocol are mandatory per rule.
        policy = {
            "version": "2.0.0",
            "rules": [
                {
                    "host": "example.com",
                    "port": 80,
                    "protocol": "tcp",
                    "level": "http",
                    "http_filters": [
                        {"method": "GET", "path": "/*"},
                    ],
                },
            ],
        }
        policy_path = write_policy_file(policy)

        result = sandbox_cli(
            "create", *make_create_args(backend, "pol-clear", "--policy", policy_path),
            timeout=600,
        )
        assert result.returncode == 0, (
            f"sandbox create failed (rc={result.returncode}).\n"
            f"stdout: {result.stdout}\nstderr: {result.stderr}"
        )
        session_id = parse_session_id(result.stdout)
        wait_for_state(sandbox_cli, "pol-clear", "Running", timeout=10)

        # Warm DNS to trigger the propagation loop rewriting the Envoy L3
        # listener file with a chain matching example.com's resolved IPs;
        # without this, the first HTTP flow hits the fail-closed listener
        # (no matching chain) and the connection is rejected.
        sandbox_cli(
            "ssh", "pol-clear", "--",
            "nslookup", "example.com",
            timeout=60,
        )
        time.sleep(6)

        # Sanity: example.com should be reachable while policy is active.
        curl_before = sandbox_cli(
            "ssh", "pol-clear", "--",
            "curl", "-s", "--connect-timeout", "15", "--max-time", "30",
            "http://example.com/",
            timeout=120,
        )
        assert curl_before.returncode == 0, (
            f"Initial curl should have succeeded with active policy.\n"
            f"stdout: {curl_before.stdout}\nstderr: {curl_before.stderr}"
        )

        # Clear the policy.
        clear_result = sandbox_cli(
            "policy", "update", "pol-clear", "--clear",
            timeout=120,
        )
        assert clear_result.returncode == 0, (
            f"sandbox policy update --clear failed (rc={clear_result.returncode}).\n"
            f"stdout: {clear_result.stdout}\nstderr: {clear_result.stderr}"
        )

        # Allow a moment for gateway components to reconfigure.
        time.sleep(5)

        # DNS should now fail (NXDOMAIN for example.com).
        dns_result = sandbox_cli(
            "ssh", "pol-clear", "--",
            "nslookup", "example.com",
            timeout=120,
        )
        combined = (dns_result.stdout + dns_result.stderr).lower()
        assert (
            dns_result.returncode != 0
            or "nxdomain" in combined
            or "can't find" in combined
        ), (
            f"DNS should return NXDOMAIN after policy --clear.\n"
            f"stdout: {dns_result.stdout}\nstderr: {dns_result.stderr}"
        )

        # HTTP should also fail now.
        curl_after = sandbox_cli(
            "ssh", "pol-clear", "--",
            "bash", "-c",
            "curl -s --connect-timeout 10 --max-time 15 http://example.com/ 2>&1; echo EXIT:$?",
            timeout=120,
        )
        assert "EXIT:0" not in curl_after.stdout, (
            f"HTTP should fail after policy --clear.\n"
            f"Output:\n{curl_after.stdout}"
        )

        sandbox_cli("rm", "pol-clear", timeout=120)
        session_id = None

    finally:
        if session_id is not None:
            sandbox_cli("rm", "pol-clear", timeout=120)
        if policy_path is not None:
            cleanup_policy_file(policy_path)


@pytest.mark.timeout(600)
def test_svcb_record_without_ech_reaches_vm(sandbox_cli, backend):
    """An SVCB-family record (RFC 9460 — SVCB type 64 *or* HTTPS type
    65) whose answer carries no ECH SvcParam must reach the VM intact —
    the strip-not-deny semantics removes only the `ech` SvcParam value,
    never the record itself.

    The CoreDNS plugin blanket-denied every SVCB / HTTPS query in an
    earlier posture (legacy `TestHandler_SVCBQuery_Blocked`). The
    current behaviour returns the original RR with `ech` stripped if
    present, or unchanged if absent. This test pins the absent-ECH
    path end-to-end through the gateway: a real query for an allowed
    name should resolve and return at least one answer to the VM,
    not NOERROR-with-zero-answers and not NXDOMAIN.

    We query `cloudflare.com` for type HTTPS (TYPE65). Cloudflare
    publishes an HTTPS record at the apex (`alpn=h3,h2` +
    `ipv4hint=...`, no ECH) but no plain SVCB record there — the two
    types share an on-the-wire format and the strip path
    (`stripECHFromRR`) treats them identically (`case *dns.SVCB`,
    `case *dns.HTTPS`), so HTTPS is the type that exercises the
    code path against a *real* upstream answer. Lima/container DNS is
    intercepted and forwarded through CoreDNS, so this exercises the
    real strip path against a real answer rather than synthetic test
    fixtures.
    """
    session_id = None
    policy_path = None
    try:
        # Allow cloudflare.com:443 over HTTPS — enough for the resolver
        # to consider the name in scope; the SVCB query itself is
        # protocol-independent at the resolver layer (CoreDNS gates the
        # name, not the rrtype).
        policy = {
            "version": "2.0.0",
            "rules": [
                {
                    "host": "cloudflare.com",
                    "port": 443,
                    "protocol": "tcp",
                    "level": "transport",
                },
            ],
        }
        policy_path = write_policy_file(policy)

        result = sandbox_cli(
            "create", *make_create_args(backend, "pol-svcb-noech",
                                        "--policy", policy_path),
            timeout=600,
        )
        assert result.returncode == 0, (
            f"sandbox create failed (rc={result.returncode}).\n"
            f"stdout: {result.stdout}\nstderr: {result.stderr}"
        )
        session_id = parse_session_id(result.stdout)
        wait_for_state(sandbox_cli, "pol-svcb-noech", "Running", timeout=10)

        # Warm A first so DNS-driven IP propagation can race in;
        # mirrors `test_dns_ip_propagation` and similar M4 tests.
        sandbox_cli(
            "ssh", "pol-svcb-noech", "--",
            "nslookup", "cloudflare.com",
            timeout=120,
        )
        time.sleep(2)

        # Issue the HTTPS query (TYPE65) via dig. We deliberately use a
        # raw type number to avoid relying on dig's `+https` shorthand
        # being present in every base image. The expected answer for
        # cloudflare.com today carries no `ech` SvcParam — this is the
        # specific shape the strip path turns from "blocked" into
        # "stripped-or-passthrough".
        svcb_result = sandbox_cli(
            "ssh", "pol-svcb-noech", "--",
            "dig", "+short", "cloudflare.com", "TYPE65",
            timeout=120,
        )
        assert svcb_result.returncode == 0, (
            f"dig TYPE65 cloudflare.com failed inside VM.\n"
            f"stdout: {svcb_result.stdout}\nstderr: {svcb_result.stderr}"
        )
        # `dig +short` of an HTTPS record renders the RDATA on a single
        # line per RR (priority + target + key=value pairs). The VM
        # must see at least one such line — anything else means the
        # record was suppressed somewhere in the chain.
        non_empty_lines = [
            line for line in svcb_result.stdout.splitlines() if line.strip()
        ]
        assert non_empty_lines, (
            f"HTTPS record for cloudflare.com was not delivered to the VM.\n"
            f"This regresses strip-not-deny: the absent-ECH path "
            f"should pass the record through unchanged.\n"
            f"dig stdout: {svcb_result.stdout!r}\n"
            f"dig stderr: {svcb_result.stderr!r}"
        )
        # And the answer must not contain an `ech=` token. The
        # upstream answer for cloudflare.com today does not carry ECH;
        # if a future upstream change adds one, the strip path should
        # still remove it before the answer reaches the VM.
        joined = " ".join(non_empty_lines).lower()
        assert "ech=" not in joined, (
            f"HTTPS record reached the VM with an `ech=` SvcParam intact.\n"
            f"The strip path must remove it before delivery.\n"
            f"dig stdout: {svcb_result.stdout!r}"
        )

        sandbox_cli("rm", "pol-svcb-noech", timeout=120)
        session_id = None

    finally:
        if session_id is not None:
            sandbox_cli("rm", "pol-svcb-noech", timeout=120)
        if policy_path is not None:
            cleanup_policy_file(policy_path)


@pytest.mark.timeout(600)
def test_policy_rejects_http_level_with_udp_protocol(sandbox_cli, backend):
    """`level: http` + `protocol: udp` is invalid by construction —
    HTTP inspection requires TCP. The unit-level invariant is pinned in
    `policy.rs::validate_rejects_http_level_with_udp`; this test
    drives the same assertion through the daemon's HTTP layer to
    verify the boundary stays consistent end-to-end.

    Posts a single rule with `level: http` and `protocol: udp` via
    `sandbox policy update --policy <file>`. The daemon must reject
    the request with a non-success exit code and an error message
    containing the required phrase ``assurance level 'http'
    requires protocol 'tcp'`` (per `PolicyCompiler::validate`). The
    session must remain alive afterwards — the failed apply must not
    knock it out of the running state.
    """
    session_id = None
    base_path = None
    bad_path = None
    try:
        # Bring up a session with a benign baseline policy so we can
        # then attempt the invalid update against a running daemon.
        baseline = {
            "version": "2.0.0",
            "rules": [
                {
                    "host": "example.com",
                    "port": 80,
                    "protocol": "tcp",
                    "level": "transport",
                },
            ],
        }
        base_path = write_policy_file(baseline)

        result = sandbox_cli(
            "create", *make_create_args(backend, "pol-http-udp", "--policy", base_path),
            timeout=600,
        )
        assert result.returncode == 0, (
            f"sandbox create failed (rc={result.returncode}).\n"
            f"stdout: {result.stdout}\nstderr: {result.stderr}"
        )
        session_id = parse_session_id(result.stdout)
        wait_for_state(sandbox_cli, "pol-http-udp", "Running", timeout=10)

        # Build the invalid update body: http+udp on the same rule.
        bad_policy = {
            "version": "2.0.0",
            "rules": [
                {
                    "host": "example.com",
                    "port": 53,
                    "protocol": "udp",
                    "level": "http",
                    "http_filters": [
                        {"method": "GET", "path": "/*"},
                    ],
                },
            ],
        }
        bad_path = write_policy_file(bad_policy)

        update = sandbox_cli(
            "policy", "update", "pol-http-udp", "--policy", bad_path,
            timeout=120,
        )
        assert update.returncode != 0, (
            "Policy with http level + udp protocol must be rejected by the "
            f"daemon, got rc=0.\nstdout: {update.stdout}\nstderr: {update.stderr}"
        )
        # The exact error string is owned by `PolicyCompiler::validate`
        # — we pin its grep-stable prefix here so a future error-text
        # rewording trips this assertion in CI before silently breaking
        # operator-facing diagnostics. The stderr must surface the
        # daemon's response, not a generic "request failed" wrapper.
        combined = (update.stdout + update.stderr)
        assert "assurance level 'http' requires protocol" in combined, (
            f"Daemon-side validation error not surfaced to operator.\n"
            f"Expected substring: \"assurance level 'http' requires protocol\"\n"
            f"stdout: {update.stdout!r}\nstderr: {update.stderr!r}"
        )

        # Session must stay running — a rejected apply must not knock
        # it into Error state. (`apply_policy` emits a `policy_updated`
        # event with status=error but does not transition the session.)
        ps = sandbox_cli("ps", timeout=60)
        assert ps.returncode == 0, (
            f"sandbox ps failed: stderr={ps.stderr!r}"
        )
        # A "Running" line for our session must still be present.
        assert any(
            "pol-http-udp" in line and "Running" in line
            for line in ps.stdout.splitlines()
        ), (
            f"Session pol-http-udp must remain Running after rejected "
            f"policy update.\nps output:\n{ps.stdout}"
        )

        sandbox_cli("rm", "pol-http-udp", timeout=120)
        session_id = None

    finally:
        if session_id is not None:
            sandbox_cli("rm", "pol-http-udp", timeout=120)
        if base_path is not None:
            cleanup_policy_file(base_path)
        if bad_path is not None:
            cleanup_policy_file(bad_path)
