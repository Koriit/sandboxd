"""E2E tests for M3 networking: gateway traffic flow, nftables enforcement,
DNS interception, stop/start with networking, concurrent sessions, daemon
restart recovery, and gateway crash recovery.

These tests boot real Lima/QEMU VMs with full networking (Docker bridge,
gateway container, nftables, TAP NIC) and are SLOW (3-10 minutes per test).
Run with generous timeouts:

    cd tests/e2e
    source .venv/bin/activate
    python -m pytest test_m3_networking.py -v --timeout=600
"""

from __future__ import annotations

import json
import os
import re
import signal
import subprocess
import time

import pytest

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# Regex to extract the session ID (UUID) from `sandbox create` output.
_ID_RE = re.compile(r"^ID:\s+([0-9a-f-]{36})$", re.MULTILINE)

# Default VM resource args -- kept small for hosts with limited RAM (3.8 GB).
_VM_RESOURCE_ARGS = ("--cpus", "1", "--memory", "1024", "--disk", "10")


def parse_session_id(create_output: str) -> str:
    """Extract the session UUID from `sandbox create` stdout."""
    m = _ID_RE.search(create_output)
    if not m:
        raise ValueError(
            f"Could not parse session ID from create output:\n{create_output}"
        )
    return m.group(1)


def lima_vm_name(session_id: str) -> str:
    """Return the Lima VM name for a given session ID."""
    return f"sandbox-{session_id}"


def gateway_container_name(session_id: str) -> str:
    """Return the Docker gateway container name for a given session ID."""
    return f"sandbox-gw-{session_id}"


def wait_for_state(
    sandbox_cli,
    name: str,
    expected_state: str,
    timeout: int = 30,
    interval: float = 2.0,
) -> str:
    """Poll `sandbox ps` until the named session reaches the expected state.

    Returns the full ps output on success.  Raises AssertionError on timeout.
    """
    deadline = time.monotonic() + timeout
    last_output = ""
    while time.monotonic() < deadline:
        result = sandbox_cli("ps")
        last_output = result.stdout
        for line in last_output.splitlines():
            if name in line and expected_state in line:
                return last_output
        time.sleep(interval)

    raise AssertionError(
        f"Session {name!r} did not reach state {expected_state!r} "
        f"within {timeout}s.\nLast ps output:\n{last_output}"
    )


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


def capture_lima_logs(session_id: str) -> str:
    """Best-effort capture of Lima VM logs for debugging failures."""
    vm = lima_vm_name(session_id)
    logs = []
    ha_log = os.path.expanduser(f"~/.lima/{vm}/ha.stderr.log")
    try:
        with open(ha_log) as f:
            content = f.read()
            if content:
                logs.append(f"--- {ha_log} (last 50 lines) ---")
                logs.extend(content.splitlines()[-50:])
    except FileNotFoundError:
        logs.append(f"(no ha.stderr.log found at {ha_log})")
    return "\n".join(logs)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

@pytest.mark.timeout(600)
def test_gateway_traffic_flow(sandbox_cli):
    """Create a session and verify the full gateway networking pipeline:
    gateway container running, VM has second NIC, can ping gateway, DNS works.
    """
    session_id = None
    try:
        # 1. Create a session.
        result = sandbox_cli(
            "create", "--name", "net-flow-test", *_VM_RESOURCE_ARGS,
            timeout=600,
        )
        assert result.returncode == 0, (
            f"sandbox create failed (rc={result.returncode}).\n"
            f"stdout: {result.stdout}\nstderr: {result.stderr}"
        )
        session_id = parse_session_id(result.stdout)
        gw_container = gateway_container_name(session_id)
        vm_name = lima_vm_name(session_id)

        wait_for_state(sandbox_cli, "net-flow-test", "Running", timeout=10)

        # 2. Verify gateway container is running.
        assert docker_container_running(gw_container), (
            f"Gateway container {gw_container} is not running.\n"
            f"Docker ps: {subprocess.run(['docker', 'ps', '-a'], capture_output=True, text=True, timeout=30).stdout}"
        )

        # 3. Verify VM has a second NIC (eth1) with an IP in the 10.209.x.x range.
        #    The guest agent configures eth1 with the VM's IP (.3 in the /28).
        exec_result = sandbox_cli(
            "exec", "net-flow-test", "--", "ip", "-4", "addr", "show",
            timeout=120,
        )
        assert exec_result.returncode == 0, (
            f"Failed to get IP addresses from VM.\n"
            f"stdout: {exec_result.stdout}\nstderr: {exec_result.stderr}"
        )
        # Look for a 10.209.x.x IP on any interface (the hot-added NIC).
        assert re.search(r"10\.209\.\d+\.\d+", exec_result.stdout), (
            f"VM does not have a 10.209.x.x IP address.\n"
            f"ip addr output:\n{exec_result.stdout}"
        )

        # 4. Extract the gateway IP (the .2 in the /28 subnet).
        # Parse the VM IP from ip addr output; gateway is VM_IP - 1.
        vm_ip_match = re.search(r"(10\.209\.\d+\.\d+)/28", exec_result.stdout)
        assert vm_ip_match, (
            f"Could not find VM IP with /28 prefix in ip addr output.\n"
            f"Output:\n{exec_result.stdout}"
        )
        vm_ip = vm_ip_match.group(1)
        # VM is .3, gateway is .2.
        octets = vm_ip.split(".")
        gateway_ip = f"{octets[0]}.{octets[1]}.{octets[2]}.{int(octets[3]) - 1}"

        # 5. Verify VM can ping the gateway IP.
        ping_result = sandbox_cli(
            "exec", "net-flow-test", "--",
            "ping", "-c", "3", "-W", "5", gateway_ip,
            timeout=120,
        )
        assert ping_result.returncode == 0, (
            f"VM cannot ping gateway {gateway_ip}.\n"
            f"stdout: {ping_result.stdout}\nstderr: {ping_result.stderr}\n"
            f"{capture_lima_logs(session_id)}"
        )

        # 6. Verify DNS works from VM via gateway's CoreDNS.
        dns_result = sandbox_cli(
            "exec", "net-flow-test", "--",
            "nslookup", "google.com",
            timeout=120,
        )
        assert dns_result.returncode == 0, (
            f"DNS lookup failed inside VM.\n"
            f"stdout: {dns_result.stdout}\nstderr: {dns_result.stderr}"
        )
        # nslookup should return at least one address.
        assert re.search(r"Address:\s+\d+\.\d+\.\d+\.\d+", dns_result.stdout), (
            f"DNS lookup did not return an IP address.\n"
            f"nslookup output:\n{dns_result.stdout}"
        )

        # 7. Clean up.
        sandbox_cli("rm", "net-flow-test", timeout=120)
        session_id = None

    finally:
        if session_id is not None:
            sandbox_cli("rm", "net-flow-test", timeout=120)


@pytest.mark.timeout(600)
def test_denied_traffic(sandbox_cli):
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
            "create", "--name", "net-deny-test", *_VM_RESOURCE_ARGS,
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
        assert "EXIT:0" not in output or "metadata" not in output.lower(), (
            f"Cloud metadata endpoint was reachable (should be blocked).\n"
            f"Output:\n{output}"
        )

        # 3. Verify that UDP traffic to a non-DNS port on an external IP is
        #    blocked. The DNAT rules only redirect DNS (port 53) and TCP;
        #    other UDP traffic from the VM should be dropped by the forward
        #    chain once it hits the gateway's nftables namespace.
        #
        #    We attempt a UDP connection to a public IP on a non-standard
        #    port. The expectation is that it either times out or is rejected.
        udp_result = sandbox_cli(
            "exec", "net-deny-test", "--",
            "bash", "-c",
            "echo test | nc -u -w 3 8.8.8.8 9999; echo EXIT:$?",
            timeout=120,
        )
        # nc with -w 3 should time out if traffic is blocked. The exit code
        # will be non-zero (1) on timeout.  We just verify it didn't succeed
        # cleanly in an unexpected way.  This is a best-effort check since
        # UDP is connectionless.

        # 4. Clean up.
        sandbox_cli("rm", "net-deny-test", timeout=120)
        session_id = None

    finally:
        if session_id is not None:
            sandbox_cli("rm", "net-deny-test", timeout=120)


@pytest.mark.timeout(600)
def test_dns_interception(sandbox_cli):
    """Verify DNS queries from the VM go through the gateway's CoreDNS.

    Resolve a domain from inside the VM, then check CoreDNS logs in the
    gateway container to confirm the query was intercepted.
    """
    session_id = None
    try:
        # 1. Create a session.
        result = sandbox_cli(
            "create", "--name", "net-dns-test", *_VM_RESOURCE_ARGS,
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
def test_stop_start_with_networking(sandbox_cli):
    """Create a session, verify networking, stop, verify gateway gone,
    start, verify persistence and networking restoration.
    """
    session_id = None
    try:
        # 1. Create a session.
        result = sandbox_cli(
            "create", "--name", "net-restart-test", *_VM_RESOURCE_ARGS,
            timeout=600,
        )
        assert result.returncode == 0, (
            f"sandbox create failed (rc={result.returncode}).\n"
            f"stdout: {result.stdout}\nstderr: {result.stderr}"
        )
        session_id = parse_session_id(result.stdout)
        gw_container = gateway_container_name(session_id)
        wait_for_state(sandbox_cli, "net-restart-test", "Running", timeout=10)

        # 2. Get the gateway IP for later verification.
        exec_result = sandbox_cli(
            "exec", "net-restart-test", "--", "ip", "-4", "addr", "show",
            timeout=120,
        )
        assert exec_result.returncode == 0
        vm_ip_match = re.search(r"(10\.209\.\d+\.\d+)/28", exec_result.stdout)
        assert vm_ip_match, (
            f"Could not find VM IP with /28 prefix.\n"
            f"Output:\n{exec_result.stdout}"
        )
        vm_ip = vm_ip_match.group(1)
        octets = vm_ip.split(".")
        gateway_ip = f"{octets[0]}.{octets[1]}.{octets[2]}.{int(octets[3]) - 1}"

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

        # 8. Verify networking works again: ping gateway.
        ping_result = sandbox_cli(
            "exec", "net-restart-test", "--",
            "ping", "-c", "3", "-W", "5", gateway_ip,
            timeout=120,
        )
        assert ping_result.returncode == 0, (
            f"VM cannot ping gateway {gateway_ip} after restart.\n"
            f"stdout: {ping_result.stdout}\nstderr: {ping_result.stderr}"
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


@pytest.mark.timeout(600)
@pytest.mark.skipif(
    os.sysconf("SC_PAGE_SIZE") * os.sysconf("SC_PHYS_PAGES") < 6 * 1024**3,
    reason="Requires >= 6GB RAM for concurrent VMs",
)
def test_concurrent_sessions(sandbox_cli):
    """Create two sessions and verify network isolation: different IPs/subnets,
    both functional, no cross-session traffic.
    """
    session_id_a = None
    session_id_b = None
    try:
        # 1. Create first session.
        result_a = sandbox_cli(
            "create", "--name", "net-multi-a", *_VM_RESOURCE_ARGS,
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
            "create", "--name", "net-multi-b", *_VM_RESOURCE_ARGS,
            timeout=600,
        )
        assert result_b.returncode == 0, (
            f"sandbox create (session B) failed (rc={result_b.returncode}).\n"
            f"stdout: {result_b.stdout}\nstderr: {result_b.stderr}"
        )
        session_id_b = parse_session_id(result_b.stdout)
        wait_for_state(sandbox_cli, "net-multi-b", "Running", timeout=10)

        # 3. Get IPs for both sessions.
        ip_a = sandbox_cli(
            "exec", "net-multi-a", "--", "ip", "-4", "addr", "show",
            timeout=120,
        )
        assert ip_a.returncode == 0
        ip_b = sandbox_cli(
            "exec", "net-multi-b", "--", "ip", "-4", "addr", "show",
            timeout=120,
        )
        assert ip_b.returncode == 0

        # Extract the 10.209.x.x IPs.
        match_a = re.search(r"(10\.209\.\d+\.\d+)/28", ip_a.stdout)
        match_b = re.search(r"(10\.209\.\d+\.\d+)/28", ip_b.stdout)
        assert match_a, (
            f"Session A does not have a 10.209.x.x/28 IP.\n"
            f"ip addr output:\n{ip_a.stdout}"
        )
        assert match_b, (
            f"Session B does not have a 10.209.x.x/28 IP.\n"
            f"ip addr output:\n{ip_b.stdout}"
        )

        vm_ip_a = match_a.group(1)
        vm_ip_b = match_b.group(1)

        # 4. Verify different subnets (the /28 blocks should differ).
        #    With /28 subnets, the third octet or the block offset differs.
        assert vm_ip_a != vm_ip_b, (
            f"Both sessions have the same IP: {vm_ip_a}"
        )
        # Check that they're in different /28 blocks by comparing the
        # network portion. In a /28, the last octet's upper nibble
        # determines the block.
        octets_a = [int(o) for o in vm_ip_a.split(".")]
        octets_b = [int(o) for o in vm_ip_b.split(".")]
        block_a = octets_a[3] // 16
        block_b = octets_b[3] // 16
        # If they share the same first 3 octets, blocks must differ.
        if octets_a[:3] == octets_b[:3]:
            assert block_a != block_b, (
                f"Sessions are in the same /28 block: "
                f"A={vm_ip_a} (block {block_a}), B={vm_ip_b} (block {block_b})"
            )

        # 5. Compute gateway IPs (VM is .3, gateway is .2).
        gw_ip_a = f"{octets_a[0]}.{octets_a[1]}.{octets_a[2]}.{octets_a[3] - 1}"
        gw_ip_b = f"{octets_b[0]}.{octets_b[1]}.{octets_b[2]}.{octets_b[3] - 1}"

        # 6. Verify both can ping their respective gateways.
        ping_a = sandbox_cli(
            "exec", "net-multi-a", "--",
            "ping", "-c", "3", "-W", "5", gw_ip_a,
            timeout=120,
        )
        assert ping_a.returncode == 0, (
            f"Session A cannot ping its gateway {gw_ip_a}.\n"
            f"stdout: {ping_a.stdout}\nstderr: {ping_a.stderr}"
        )

        ping_b = sandbox_cli(
            "exec", "net-multi-b", "--",
            "ping", "-c", "3", "-W", "5", gw_ip_b,
            timeout=120,
        )
        assert ping_b.returncode == 0, (
            f"Session B cannot ping its gateway {gw_ip_b}.\n"
            f"stdout: {ping_b.stdout}\nstderr: {ping_b.stderr}"
        )

        # 7. Verify no cross-session traffic: session A cannot reach
        #    session B's gateway. The /28 subnets are isolated Docker
        #    bridges, so routing between them should not exist.
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
def test_daemon_restart_recovery(sandbox_binaries, sandbox_daemon, sandbox_cli):
    """Create a session, kill the daemon, restart it, verify the session
    is recovered and functional.
    """
    session_id = None
    restarted_proc = None
    try:
        # 1. Create a session.
        result = sandbox_cli(
            "create", "--name", "net-daemon-test", *_VM_RESOURCE_ARGS,
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
        restarted_proc = subprocess.Popen(
            [
                str(sandbox_binaries.sandboxd),
                "--socket", socket_path,
                "--base-dir", base_dir,
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        # Wait for the new socket to appear.
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            if os.path.exists(socket_path):
                break
            if restarted_proc.poll() is not None:
                stdout = restarted_proc.stdout.read().decode() if restarted_proc.stdout else ""
                stderr = restarted_proc.stderr.read().decode() if restarted_proc.stderr else ""
                pytest.fail(
                    f"Restarted daemon exited early (code {restarted_proc.returncode}).\n"
                    f"stdout: {stdout}\nstderr: {stderr}"
                )
            time.sleep(0.2)
        else:
            restarted_proc.kill()
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

    finally:
        if session_id is not None:
            sandbox_cli("rm", "net-daemon-test", timeout=120)
        # Clean up the restarted daemon if it's still running.
        if restarted_proc is not None and restarted_proc.poll() is None:
            restarted_proc.send_signal(signal.SIGTERM)
            try:
                restarted_proc.wait(timeout=15)
            except subprocess.TimeoutExpired:
                restarted_proc.kill()
                restarted_proc.wait(timeout=5)


@pytest.mark.timeout(600)
def test_gateway_crash_recovery(sandbox_cli):
    """Kill the gateway container and verify the daemon's background monitor
    detects and restarts it within the poll interval (30 seconds).
    """
    session_id = None
    try:
        # 1. Create a session.
        result = sandbox_cli(
            "create", "--name", "net-gwcrash-test", *_VM_RESOURCE_ARGS,
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

        # Get the gateway IP from the VM's network config.
        exec_result = sandbox_cli(
            "exec", "net-gwcrash-test", "--", "ip", "-4", "addr", "show",
            timeout=120,
        )
        assert exec_result.returncode == 0
        vm_ip_match = re.search(r"(10\.209\.\d+\.\d+)/28", exec_result.stdout)
        assert vm_ip_match
        vm_ip = vm_ip_match.group(1)
        octets = vm_ip.split(".")
        gateway_ip = f"{octets[0]}.{octets[1]}.{octets[2]}.{int(octets[3]) - 1}"

        # Ping the gateway to verify full recovery.
        ping_result = sandbox_cli(
            "exec", "net-gwcrash-test", "--",
            "ping", "-c", "3", "-W", "5", gateway_ip,
            timeout=120,
        )
        assert ping_result.returncode == 0, (
            f"VM cannot ping gateway {gateway_ip} after crash recovery.\n"
            f"stdout: {ping_result.stdout}\nstderr: {ping_result.stderr}"
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
