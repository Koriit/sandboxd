"""E2E tests for M4 policy enforcement: deny-all default, transport passthrough,
TLS-verified passthrough, full MITM inspection, HTTP constraints, policy
updates, and DNS policy enforcement.

These tests boot real Lima/QEMU VMs with full networking and policy enforcement
and are SLOW (3-10 minutes per test).  Run with generous timeouts:

    cd tests/e2e
    source .venv/bin/activate
    python -m pytest test_m4_policy.py -v --timeout=600
"""

from __future__ import annotations

import re
import subprocess
import time

import pytest

from conftest import (
    _VM_RESOURCE_ARGS,
    capture_lima_logs,
    cleanup_policy_file,
    gateway_container_name,
    parse_session_id,
    wait_for_state,
    write_policy_file,
)

# ---------------------------------------------------------------------------
# Gateway introspection helpers (M9-S20)
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


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

@pytest.mark.timeout(600)
def test_level0_denied(sandbox_cli):
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
            "create", "--name", "pol-deny-all",
            *_VM_RESOURCE_ARGS, "--policy", policy_path,
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
def test_level1_transport_tcp(sandbox_cli):
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
            "create", "--name", "pol-l1-tcp",
            *_VM_RESOURCE_ARGS, "--policy", policy_path,
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
def test_level1_transport_udp(sandbox_cli):
    """Policy allows DNS to 8.8.8.8 at level 'transport' protocol 'udp'.
    Verify DNS query to 8.8.8.8 works.

    Note: All port-53 traffic is DNAT'd to the gateway's CoreDNS, so the
    query goes through CoreDNS regardless of the target server.  We must
    also allow the queried domain in the policy so CoreDNS resolves it.
    """
    session_id = None
    policy_path = None
    try:
        # M10-S1 v2: DNS uses UDP/53. example.com needs its own rule so
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
            "create", "--name", "pol-l1-udp",
            *_VM_RESOURCE_ARGS, "--policy", policy_path,
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


@pytest.mark.timeout(600)
def test_level2_tls_verified(sandbox_cli):
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
            "create", "--name", "pol-l2-tls",
            *_VM_RESOURCE_ARGS, "--policy", policy_path,
            timeout=600,
        )
        assert result.returncode == 0, (
            f"sandbox create failed (rc={result.returncode}).\n"
            f"stdout: {result.stdout}\nstderr: {result.stderr}"
        )
        session_id = parse_session_id(result.stdout)
        wait_for_state(sandbox_cli, "pol-l2-tls", "Running", timeout=10)

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
def test_level3_http_inspected(sandbox_cli):
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
            "create", "--name", "pol-l3-inspect",
            *_VM_RESOURCE_ARGS, "--policy", policy_path,
            timeout=600,
        )
        assert result.returncode == 0, (
            f"sandbox create failed (rc={result.returncode}).\n"
            f"stdout: {result.stdout}\nstderr: {result.stderr}"
        )
        session_id = parse_session_id(result.stdout)
        wait_for_state(sandbox_cli, "pol-l3-inspect", "Running", timeout=10)

        # M9-S20 gap 1: mitmproxy must be bound to 127.0.0.1:18080 only.
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

        # M9-S20 gap 5: post-M9-S19 the gateway nftables steady state
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

        # M9-S20 gap 2: observe the CONNECT tunnel in mitmproxy's log.
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

        # M9-S20 gap 3: authority preservation. Envoy's L3 tcp_proxy
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

        # M9-S20 gap 4: observe the CONNECT-tunnel invariant from
        # **Envoy's own access log**, independent of mitmproxy's flow
        # log. The L3 `tcp_proxy` filter writes one line per tunneled
        # connection to `/var/log/gateway/envoy_access.log` with
        # key=value columns (see `l3_tcp_proxy_access_log_yaml` in
        # `sandbox-core/src/policy.rs`). A mitmproxy-only assertion is
        # vulnerable to mitmproxy log-format regressions and to Envoy
        # misconfigurations that bypass mitmproxy entirely (e.g. a
        # listener update that dropped `tunneling_config`, sending
        # bytes to `mitmproxy` as raw TCP). Asserting on Envoy's log
        # directly catches both failure modes.
        envoy_access_log = _read_gateway_log(session_id, "envoy_access.log")
        assert envoy_access_log.strip(), (
            f"envoy_access.log is empty after L3 curl; Envoy's tcp_proxy "
            f"access log may be misconfigured or no L3 chain matched the "
            f"traffic.\nmitmproxy.log tail (for cross-reference):\n"
            f"{mitm_log[-2000:]}"
        )

        # Split into lines and filter to the L3 chain entries. Every
        # line the format produces starts with `[<timestamp>] `, so a
        # prefix test is adequate.
        envoy_lines = [
            line for line in envoy_access_log.splitlines()
            if line.startswith("[") and "downstream_local=" in line
        ]
        assert envoy_lines, (
            f"envoy_access.log has content but no parseable L3 entries "
            f"(lines starting with `[` and carrying `downstream_local=`).\n"
            f"full log:\n{envoy_access_log[-4000:]}"
        )

        # Invariant A: at least one line has
        # `downstream_local=<resolved-ip>:443` — the VM's intended
        # destination IP preserved by `original_dst`. Mirrors the
        # mitmproxy `server connect <ip>:443` assertion above.
        downstream_hits = [
            line for line in envoy_lines
            if any(
                f"downstream_local={ip}:443" in line for ip in resolved_ips
            )
        ]
        assert downstream_hits, (
            f"envoy_access.log does not record downstream_local=<ip>:443 for "
            f"any of example.com's resolved IPs ({resolved_ips}); Envoy's "
            f"`original_dst` listener filter may be failing to recover "
            f"SO_ORIGINAL_DST, or the L3 prefix_ranges match is missing.\n"
            f"envoy_access.log tail:\n{envoy_access_log[-4000:]}"
        )

        # Invariant B: none of the downstream-local addresses may be
        # `127.0.0.1` — that would indicate the L3 chain pointed Envoy
        # at its own loopback (e.g. a direct-to-internet bypass that
        # routed back through mitmproxy without preserving the original
        # destination). This is the Envoy-side mirror of the mitmproxy
        # `server connect 127.0.0.1:` negative check above.
        assert "downstream_local=127.0.0.1:" not in envoy_access_log, (
            f"envoy_access.log records downstream_local=127.0.0.1:* — Envoy "
            f"tunneled to a loopback address as the original destination, "
            f"which would indicate `original_dst` or prefix_ranges misbehaved.\n"
            f"envoy_access.log tail:\n{envoy_access_log[-4000:]}"
        )

        # Invariant C: the upstream cluster must be `mitmproxy` and the
        # upstream host must be the loopback endpoint of that cluster.
        # A regression that routes L3 traffic back to `original_dst`
        # (e.g. if `tunneling_config` is dropped on a listener update)
        # would flip `upstream_cluster` and break this check without
        # touching mitmproxy at all.
        assert any("upstream_cluster=mitmproxy" in line for line in envoy_lines), (
            f"envoy_access.log does not record any line with "
            f"upstream_cluster=mitmproxy; L3 chains may have regressed to "
            f"routing via original_dst.\n"
            f"envoy_access.log tail:\n{envoy_access_log[-4000:]}"
        )
        assert any(
            "upstream_host=127.0.0.1:18080" in line for line in envoy_lines
        ), (
            f"envoy_access.log does not record any line with "
            f"upstream_host=127.0.0.1:18080; the `mitmproxy` cluster's "
            f"loopback endpoint may have drifted.\n"
            f"envoy_access.log tail:\n{envoy_access_log[-4000:]}"
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
def test_level3_host_mismatch(sandbox_cli):
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
            "create", "--name", "pol-l3-host",
            *_VM_RESOURCE_ARGS, "--policy", policy_path,
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
def test_level3_method_restriction(sandbox_cli):
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
            "create", "--name", "pol-l3-method",
            *_VM_RESOURCE_ARGS, "--policy", policy_path,
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
def test_level3_path_restriction(sandbox_cli):
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
            "create", "--name", "pol-l3-path",
            *_VM_RESOURCE_ARGS, "--policy", policy_path,
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
def test_l3_fail_closed_before_dns_propagation(sandbox_cli):
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
            "create", "--name", "pol-l3-failclosed",
            *_VM_RESOURCE_ARGS, "--policy", policy_path,
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
def test_policy_update(sandbox_cli):
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
            "create", "--name", "pol-update",
            *_VM_RESOURCE_ARGS, "--policy", policy_path_1,
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
def test_dns_nxdomain(sandbox_cli):
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
            "create", "--name", "pol-dns-nx",
            *_VM_RESOURCE_ARGS, "--policy", policy_path,
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
def test_dns_ip_propagation(sandbox_cli):
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
            "create", "--name", "pol-dns-ip",
            *_VM_RESOURCE_ARGS, "--policy", policy_path,
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
def test_empty_policy_denies_dns(sandbox_cli):
    """Creating a session with no `--policy` must produce a fail-closed default:
    CoreDNS returns NXDOMAIN for everything and HTTP is unreachable.
    """
    session_id = None
    try:
        result = sandbox_cli(
            "create", "--name", "pol-empty-default",
            *_VM_RESOURCE_ARGS,
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


# Note: the M9-era `test_unrestricted_allows_and_logs` test was removed in
# M10-S1. The spec (`.tasks/specs/2026-04-21-port-explicit-policies-
# presets-observability-design.md`, Part 1) removes `--unrestricted` /
# `Policy::unrestricted()` as an escape hatch; the discovery workflow it
# supported is replaced by deny-log-driven iteration delivered in Part 3
# (`sandbox events --decision=deny --follow`), which lands in later M10
# sessions. Until that ships there is no functional equivalent to assert
# here.


@pytest.mark.timeout(600)
def test_policy_clear_reverts_to_deny_all(sandbox_cli):
    """Create a session with an HTTP-level policy, then clear it via
    `sandbox policy update --clear`. Afterwards traffic must be denied.
    """
    session_id = None
    policy_path = None
    try:
        # Start with an HTTP-level policy allowing example.com:80 GET /*.
        # M10-S1 v2: port and L4 protocol are mandatory per rule.
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
            "create", "--name", "pol-clear",
            *_VM_RESOURCE_ARGS, "--policy", policy_path,
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
