"""E2E test for policy persistence — restart-survival regression.

Previously, applied policies lived only in the daemon's in-memory
``HashMap``. When the daemon restarted, the map was empty, so
``reconcile_networking`` rebuilt the gateway with the default allow-all
DNS policy — a silent security regression. Normalized SQL
persistence via ``SessionStore::{set_policy,get_policy,load_all_policies}``
plus startup hydration in ``sandboxd::main`` before
``reconcile_networking`` runs closes this gap.

This test covers spec § 6 "E2E test" end-to-end:

1. Create a session and apply a restrictive policy (allow ``example.com``
   only; everything else denied by the implicit default-deny).
2. Verify enforcement from inside the guest: curl to the allowed host
   succeeds; curl to the denied host fails.
3. SIGTERM the daemon, await graceful exit, restart with the same
   ``base_dir`` and ``socket``.
4. Re-run the same two curls *without re-posting the policy*. The
   allowed destination still succeeds and the denied destination still
   fails — this is the invariant that would have regressed silently
   before this session.

Pattern follows ``test_networking.py::test_daemon_restart_recovery``
for the restart mechanics (reuses the same stdout/stderr log files so the
fixture can adopt the restarted process). Uses SIGTERM (not SIGKILL) per
spec § 6 step 4: "Stop the daemon process (SIGTERM; await exit) and
restart it with the same base_dir."

These tests boot real Lima/QEMU VMs and are SLOW. Run with:

    cd tests/e2e
    source .venv/bin/activate
    python -m pytest test_policy_persistence.py -v --timeout=600

Backend coverage: **agnostic** — parametrized over ``[lima, container]``
via the ``backend`` fixture. The persistence path lives in
``SessionStore`` and the daemon's startup hydration; both backends
share that machinery (the policy is keyed on session id, not on
backend kind), so the restart-survival contract is identical.
"""

from __future__ import annotations

import os
import signal
import subprocess
import time

import pytest

from conftest import (
    cleanup_policy_file,
    make_create_args,
    parse_session_id,
    wait_for_state,
    write_policy_file,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _curl_allowed(sandbox_cli, name: str) -> subprocess.CompletedProcess:
    """Curl the allowed host (example.com) from inside the guest.

    Returns the CompletedProcess so callers can assert on both the exit
    code and the response body.
    """
    return sandbox_cli(
        "ssh", name, "--",
        "curl", "-s", "--connect-timeout", "15", "--max-time", "30",
        "http://example.com",
        timeout=120,
    )


def _curl_denied(sandbox_cli, name: str) -> subprocess.CompletedProcess:
    """Curl the denied host from inside the guest.

    Uses a domain that is NOT in the policy so CoreDNS returns NXDOMAIN
    and curl fails during resolution. Returns the CompletedProcess.
    """
    # We write the combined output + exit status to stdout so the assertion
    # can inspect both regardless of what layer rejects the request (DNS,
    # TCP, or HTTP).
    return sandbox_cli(
        "ssh", name, "--",
        "bash", "-c",
        "curl -s -o /dev/null -w '%{http_code}' --connect-timeout 10 "
        "--max-time 15 http://denied.test/ 2>&1; echo EXIT:$?",
        timeout=120,
    )


def _assert_allowed_succeeds(
    result: subprocess.CompletedProcess, context: str
) -> None:
    assert result.returncode == 0, (
        f"[{context}] curl to allowed example.com failed (rc={result.returncode}).\n"
        f"stdout: {result.stdout}\nstderr: {result.stderr}"
    )
    assert "Example Domain" in result.stdout, (
        f"[{context}] response from example.com missing 'Example Domain'.\n"
        f"stdout: {result.stdout}"
    )


def _assert_denied_fails(
    result: subprocess.CompletedProcess, context: str
) -> None:
    # curl exits non-zero on DNS resolution failure / connection refused.
    # When it does write an http_code it's "000" (no response received).
    # Either is a pass; "200" is a fail.
    combined = result.stdout
    assert "EXIT:0" not in combined, (
        f"[{context}] curl to denied host unexpectedly succeeded.\n"
        f"stdout: {result.stdout}\nstderr: {result.stderr}"
    )
    assert "200" not in combined.split("EXIT:")[0], (
        f"[{context}] curl to denied host returned HTTP 200.\n"
        f"stdout: {result.stdout}\nstderr: {result.stderr}"
    )


# ---------------------------------------------------------------------------
# Test
# ---------------------------------------------------------------------------


@pytest.mark.timeout(600)
def test_policy_survives_daemon_restart(
    sandbox_binaries, sandbox_daemon, sandbox_cli, backend
):
    """Apply a restrictive policy, verify enforcement, SIGTERM+restart the
    daemon on the same ``base_dir``, and verify the policy still enforces
    without re-posting it.
    """
    session_id = None
    policy_path = None
    restarted_proc = None
    session_name = "pol-persist-restart"

    try:
        # 1. Build a restrictive policy: allow example.com only.
        #    Everything else is denied by the implicit default-deny that
        #    CoreDNS enforces (NXDOMAIN for any domain not in the policy).
        #    Policy v2 schema: (host, port) identity with explicit L4
        #    protocol. The restart-recovery assertions curl
        #    `http://example.com` (port 80), so the rule pins :80/tcp.
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

        # 2. Create the session with the restrictive policy applied.
        create_result = sandbox_cli(
            "create",
            *make_create_args(backend, session_name, "--policy", policy_path),
            timeout=600,
        )
        assert create_result.returncode == 0, (
            f"sandbox create failed (rc={create_result.returncode}).\n"
            f"stdout: {create_result.stdout}\nstderr: {create_result.stderr}"
        )
        session_id = parse_session_id(create_result.stdout)
        wait_for_state(sandbox_cli, session_name, "Running", timeout=10)

        # Warm DNS for example.com so the daemon's DNS propagation loop
        # materialises the L1 transport filter chain (Envoy prefix_ranges
        # + sandbox_policy concat-set entry). Schema v2 L1 transport is
        # fail-closed at an empty DNS cache; without this warm-up the
        # pre-restart curl would race the 2-second propagation poll.
        # Post-restart curl does not need a repeat warm-up — the gateway
        # container survives daemon restart, so CoreDNS's resolved.json
        # stays populated and the hydrated policy re-propagates with the
        # cached IPs.
        sandbox_cli(
            "ssh", session_name, "--",
            "nslookup", "example.com",
            timeout=120,
        )
        time.sleep(5)

        # 3. Sanity-check enforcement BEFORE the restart. The allowed
        #    destination must succeed and the denied destination must fail.
        _assert_allowed_succeeds(
            _curl_allowed(sandbox_cli, session_name),
            context="pre-restart allowed",
        )
        _assert_denied_fails(
            _curl_denied(sandbox_cli, session_name),
            context="pre-restart denied",
        )

        # 4. SIGTERM the daemon and await graceful exit.
        daemon_proc = sandbox_daemon["process"]
        socket_path = sandbox_daemon["socket"]
        base_dir = sandbox_daemon["base_dir"]

        daemon_proc.send_signal(signal.SIGTERM)
        try:
            daemon_proc.wait(timeout=15)
        except subprocess.TimeoutExpired:
            pytest.fail(
                "Daemon did not exit within 15s after SIGTERM — graceful "
                "shutdown contract broken."
            )
        assert daemon_proc.poll() is not None, (
            "Daemon did not exit after SIGTERM"
        )

        # The daemon's shutdown handler removes the socket file; give it a
        # moment to settle before we rebind on the same path.
        time.sleep(1)

        # 5. Restart the daemon with the same socket and base_dir.
        #    The startup path must hydrate session_policies from SQLite
        #    before reconcile_networking rebuilds the gateway; if it does
        #    not, the gateway will come back with allow-all DNS and step 7
        #    will wrongly observe the denied destination as reachable.
        #
        #    Append to the existing log files (same pattern as
        #    test_networking::test_daemon_restart_recovery) so the
        #    session-scoped fixture can adopt the restarted process
        #    without ending up with a dangling pipe.
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

        # Wait for the restarted daemon's socket to reappear.
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            if os.path.exists(socket_path):
                break
            if restarted_proc.poll() is not None:
                new_stdout_fh.close()
                new_stderr_fh.close()
                pytest.fail(
                    f"Restarted daemon exited early "
                    f"(code {restarted_proc.returncode}).\n"
                    f"stdout: {stdout_log.read_text()}\n"
                    f"stderr: {stderr_log.read_text()}"
                )
            time.sleep(0.2)
        else:
            restarted_proc.kill()
            new_stdout_fh.close()
            new_stderr_fh.close()
            pytest.fail(
                "Restarted daemon socket did not appear within 15s"
            )

        # 6. Allow reconciliation to finish (gateway restart + DNS
        #    propagation after the hydrated policy lands in the map).
        time.sleep(5)

        # 7. Verify session is recovered as Running.
        ps_result = sandbox_cli("ps")
        assert ps_result.returncode == 0, (
            f"sandbox ps failed after restart.\n"
            f"stdout: {ps_result.stdout}\nstderr: {ps_result.stderr}"
        )
        found = any(
            session_name in line and "Running" in line
            for line in ps_result.stdout.splitlines()
        )
        assert found, (
            f"Session {session_name!r} not in Running state after restart.\n"
            f"ps output:\n{ps_result.stdout}"
        )

        # 8. THE INVARIANT: re-run both curls WITHOUT re-posting the
        #    policy. If hydration is broken, the gateway falls back to
        #    allow-all DNS and the denied destination would start to
        #    resolve — that is exactly the silent regression policy persistence closes.
        _assert_allowed_succeeds(
            _curl_allowed(sandbox_cli, session_name),
            context="post-restart allowed",
        )
        _assert_denied_fails(
            _curl_denied(sandbox_cli, session_name),
            context="post-restart denied",
        )

        # 9. Clean up the session while the restarted daemon is still
        #    the live process.
        sandbox_cli("rm", session_name, timeout=120)
        session_id = None

        # 10. Hand the restarted daemon back to the session-scoped fixture
        #     so subsequent tests (and fixture teardown) operate on the
        #     live process.
        sandbox_daemon["process"] = restarted_proc
        sandbox_daemon["_stdout_fh"] = new_stdout_fh
        sandbox_daemon["_stderr_fh"] = new_stderr_fh
        restarted_proc = None  # prevent finally from killing it

    finally:
        if session_id is not None:
            sandbox_cli("rm", session_name, timeout=120)
        if policy_path is not None:
            cleanup_policy_file(policy_path)

        # Recovery path mirrors test_networking::test_daemon_restart_recovery:
        # the session-scoped sandbox_daemon fixture MUST end the test with
        # a live daemon process, otherwise every subsequent test in the
        # module will cascade-fail.
        if restarted_proc is not None:
            if restarted_proc.poll() is None:
                # Alive but not yet handed off — adopt it.
                sandbox_daemon["process"] = restarted_proc
            else:
                # Restarted daemon died too; fall through to recovery.
                restarted_proc = None

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
