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
        policy = {"version": "1.0.0", "rules": []}
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
    """Policy allows example.com at level 'transport'. curl http://example.com
    should succeed via opaque TCP passthrough.
    """
    session_id = None
    policy_path = None
    try:
        policy = {
            "version": "1.0.0",
            "rules": [
                {"destination": "example.com", "level": "transport"},
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
        # The response body should contain HTML from example.com.
        assert "example" in curl_result.stdout.lower(), (
            f"Response does not contain expected content from example.com.\n"
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
        policy = {
            "version": "1.0.0",
            "rules": [
                {"destination": "example.com", "level": "transport"},
                {
                    "destination": "8.8.8.8",
                    "level": "transport",
                    "protocol": "udp",
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
            "version": "1.0.0",
            "rules": [
                {"destination": "example.com", "level": "tls"},
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
        assert "example" in curl_result.stdout.lower(), (
            f"Response does not contain expected content from example.com.\n"
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
        issuer_output = cert_result.stdout.lower()
        # The real cert issuer should NOT contain mitmproxy or sandbox CA.
        assert "mitmproxy" not in issuer_output, (
            f"Certificate issuer contains 'mitmproxy' at TLS level (should be real cert).\n"
            f"Issuer: {cert_result.stdout}"
        )
        assert "sandbox" not in issuer_output, (
            f"Certificate issuer contains 'sandbox' at TLS level (should be real cert).\n"
            f"Issuer: {cert_result.stdout}"
        )
        # The issuer should be a well-known CA (DigiCert, Let's Encrypt, etc.)
        # We just verify the field is non-empty and looks like a real issuer.
        assert "issuer" in issuer_output, (
            f"Could not extract certificate issuer.\n"
            f"stdout: {cert_result.stdout}\nstderr: {cert_result.stderr}"
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
    """Policy allows example.com at level 'full'. HTTPS should succeed but the
    certificate should show mitmproxy/Sandbox CA (MITM inspection is active).
    """
    session_id = None
    policy_path = None
    try:
        policy = {
            "version": "1.0.0",
            "rules": [
                {"destination": "example.com", "level": "full"},
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

        # Warm up DNS so the daemon's DNS propagation loop can install
        # sandbox_l3 nftables DNAT rules that redirect HTTPS traffic to
        # mitmproxy. Without this, the first HTTPS connection goes through
        # Envoy (opaque passthrough) and uses the real server certificate
        # instead of the mitmproxy-issued one.
        sandbox_cli(
            "ssh", "pol-l3-inspect", "--",
            "nslookup", "example.com",
            timeout=120,
        )
        # Wait for the DNS propagation loop (polls every 2s) to pick up
        # the resolved IPs and install the sandbox_l3 nftables rules.
        time.sleep(5)

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
        assert "example" in curl_result.stdout.lower(), (
            f"Response does not contain expected content from example.com.\n"
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
    """Policy allows only api.github.com at level 'full'. Accessing
    evil.example.com should be blocked at the DNS level (NXDOMAIN).

    In the DNS-first architecture, CoreDNS denies resolution of domains
    not in the policy, so curl never establishes a TCP connection.
    """
    session_id = None
    policy_path = None
    try:
        policy = {
            "version": "1.0.0",
            "rules": [
                {"destination": "api.github.com", "level": "full"},
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
    """Policy allows httpbin.org at level 'full' with methods=["GET"].
    A POST request should get HTTP 599 (policy-denied).
    """
    session_id = None
    policy_path = None
    try:
        policy = {
            "version": "1.0.0",
            "rules": [
                {
                    "destination": "httpbin.org",
                    "level": "full",
                    "constraints": {"methods": ["GET"]},
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

        # Warm up DNS so sandbox_l3 nftables rules redirect traffic to
        # mitmproxy (required for method/path enforcement).
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
    """Policy allows a host at level 'full' with paths=["/api/"].
    Requests to /other/path should get HTTP 599 (policy-denied).
    """
    session_id = None
    policy_path = None
    try:
        policy = {
            "version": "1.0.0",
            "rules": [
                {
                    "destination": "httpbin.org",
                    "level": "full",
                    "constraints": {"paths": ["/api/"]},
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

        # Warm up DNS so sandbox_l3 nftables rules redirect traffic to
        # mitmproxy (required for path enforcement).
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
def test_policy_update(sandbox_cli):
    """Create with a policy allowing example.com. Verify it works. Update the
    policy to allow httpbin.org instead. Verify example.com is now denied and
    httpbin.org works.
    """
    session_id = None
    policy_path_1 = None
    policy_path_2 = None
    try:
        # Initial policy: allow example.com at transport level.
        policy_1 = {
            "version": "1.0.0",
            "rules": [
                {"destination": "example.com", "level": "transport"},
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
        assert "example" in curl_result.stdout.lower(), (
            f"Response does not contain expected content from example.com.\n"
            f"stdout: {curl_result.stdout}"
        )

        # Update policy: allow httpbin.org instead of example.com.
        policy_2 = {
            "version": "1.0.0",
            "rules": [
                {"destination": "httpbin.org", "level": "transport"},
            ],
        }
        policy_path_2 = write_policy_file(policy_2)

        update_result = sandbox_cli(
            "policy", "update", "pol-update", policy_path_2,
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
            "version": "1.0.0",
            "rules": [
                {"destination": "example.com", "level": "transport"},
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
            "version": "1.0.0",
            "rules": [
                {"destination": "example.com", "level": "transport"},
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
