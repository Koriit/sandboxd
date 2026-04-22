"""E2E test for the M10-S4 discovery workflow.

Exercises the capstone scenario from the M10-S4 plan (Phase 6): an
empty-policy session first surfaces deny events via
``sandbox events <id> --decision=deny --follow``, then a policy update
that allow-lists the target hosts causes a subsequent workload run to
emit no *new* deny events for those hosts.

Rationale: the M10 "discovery workflow" pitch is that operators and
agents can spot their own unintended denials by tailing the event
stream, refine the policy, and re-run — without reading gateway logs or
rebuilding the session. This test is the end-to-end guard for that
pitch.

Notes:

- The workload is **TCP-only on port 80**.  UDP would be a cleaner
  match for the deny-logger's bare-IP path, but todo #29 tracks a
  post-DNAT destination bug on UDP that makes UDP assertions flaky.
  Do NOT flip this to UDP.

- curl targets the **resolved IP** of each host (not the hostname) via
  ``--resolve`` so the connect attempt reaches the gateway even though
  an empty policy causes CoreDNS to return NXDOMAIN. The deny-logger
  emits events on the *pre-DNAT* 5-tuple, so ``orig_dst_ip`` on the
  wire equals the IP we resolved host-side and the ``--resolve``
  mapping fed to curl.

- ``socket.gethostbyname`` is called once up front; Anycast / CDN can
  return different IPs on different calls, so the assertion matches
  the logger's ``orig_dst_ip`` against the cached set resolved at test
  start.

- The background ``sandbox events`` subprocess is terminated via
  ``SIGINT`` to hit its documented exit path (the CLI installs a
  ``tokio::signal::ctrl_c`` handler and exits 130). We accept 130,
  -2, and 0 as valid exit codes per the M10-S4 plan's "exit code
  reflects SIGINT" note.

Runs with generous timeouts; a single iteration boots a VM so budget
3-10 minutes.

    cd tests/e2e
    source .venv/bin/activate
    python -m pytest test_m10_s4_discovery.py -v --timeout=600
"""

from __future__ import annotations

import datetime
import json
import os
import signal
import socket
import subprocess
import time
from pathlib import Path

import pytest

from conftest import (
    _VM_RESOURCE_ARGS,
    SANDBOX_BIN,
    capture_lima_logs,
    cleanup_policy_file,
    parse_session_id,
    wait_for_state,
    write_policy_file,
)


SESSION_NAME = "m10-s4-disc"
TARGET_HOSTS = ("example.com", "example.org")
TARGET_PORT = 80

# Seconds to wait after a workload burst so the deny-logger parser task
# (watcher.rs) has time to read the JSONL tail and publish the domain
# event to the ring. 3s is the plan's suggested propagation budget.
EVENT_PROPAGATION_S = 3

# Seconds to wait between launching the background `sandbox events`
# subprocess and the first workload. Gives the CLI's streaming HTTP
# client time to connect and subscribe to the per-session broadcast
# before events start flowing; otherwise the early burst may race the
# subscribe and rely on ring-replay only (which would still work, but
# we prefer exercising the live path).
FOLLOW_STARTUP_S = 2


def _resolve_targets() -> dict[str, set[str]]:
    """Resolve each target host to its set of known IPv4 addresses.

    CDN / Anycast backends can swap IPs between calls, so we collect a
    few resolutions and union them. Single-call coverage is good
    enough for the two IANA example domains in practice, but we err on
    the side of robustness.
    """
    resolved: dict[str, set[str]] = {}
    for host in TARGET_HOSTS:
        ips: set[str] = set()
        for _ in range(3):
            try:
                ips.add(socket.gethostbyname(host))
            except OSError:
                pass
        if not ips:
            pytest.skip(
                f"Could not resolve {host} on the test host; cannot run "
                f"discovery E2E without ground-truth IPs.",
            )
        resolved[host] = ips
    return resolved


def _curl_both_targets(sandbox_cli, host_to_ips: dict[str, set[str]]) -> None:
    """Issue one ``curl`` per target inside the VM, against the host's
    resolved IP directly (``--resolve <host>:<port>:<ip>``).

    Uses ``|| true`` so the workload never fails the test — these
    connections *should* fail (policy denies them); we just need the
    packets on the wire to trigger the deny-logger path.
    """
    for host, ips in host_to_ips.items():
        ip = sorted(ips)[0]  # deterministic pick, matches the assertion cache
        cmd = (
            f"curl -sS --max-time 5 --connect-timeout 3 "
            f"--resolve {host}:{TARGET_PORT}:{ip} "
            f"http://{host}:{TARGET_PORT}/ || true"
        )
        sandbox_cli("ssh", SESSION_NAME, "--", "bash", "-c", cmd, timeout=60)


def _parse_jsonl(path: Path) -> list[dict]:
    """Parse a JSONL file, skipping blank / unparseable lines.

    Blank / unparseable lines are skipped rather than raising — if the
    parse-able entries satisfy the assertions, a truncated tail (from
    a race between SIGINT and stdout flush) does not invalidate the
    result.
    """
    events: list[dict] = []
    if not path.exists():
        return events
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            events.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return events


def _is_deny_for_target(
    event: dict,
    host_ip_set: set[str],
    port: int,
) -> bool:
    """Return True if the event represents a deny against one of our
    target IPs on the target port.

    Accepts the deny-logger ``deny`` variant (the primary expectation)
    OR the alternative layers mentioned in the plan (``dns.query_denied``,
    ``envoy.connection_denied``).  The real assertion is "at least one
    deny event per target host" — the exact layer is not fixed.
    """
    layer = event.get("layer")
    event_name = event.get("event")

    if layer == "deny-logger" and event_name == "deny":
        ip = event.get("orig_dst_ip")
        port_ = event.get("orig_dst_port")
        return ip in host_ip_set and port_ == port

    if layer == "envoy" and event_name == "connection_denied":
        # Envoy logs post-DNAT dst; not useful for IP matching, but
        # a deny on port 80 still counts as "traffic to this host was
        # denied". Fall through to port-only match.
        return event.get("dst_port") == port

    if layer == "dns" and event_name == "query_denied":
        # DNS-layer denials are keyed on the query name. We only hit
        # this path if curl happens to resolve via CoreDNS instead of
        # --resolve; we still accept it as evidence the workflow
        # surfaced a denial for this host.
        # Caller passes the host-IP set, not the name; keep a
        # best-effort "query matches target host" check via the
        # event's own 'query' field below in the outer helper.
        return False

    return False


def _parse_ts(raw: str) -> datetime.datetime | None:
    """Parse an RFC 3339 timestamp to a tz-aware datetime, or None if
    unparseable. The daemon emits ``...Z`` which ``fromisoformat``
    accepts only from Python 3.11+; we explicitly normalize to
    ``+00:00`` for compatibility with older stdlib, even though the
    test environment pins Python 3.12+.
    """
    if not isinstance(raw, str):
        return None
    # Normalize the "Z" suffix for fromisoformat.
    normalized = raw.replace("Z", "+00:00") if raw.endswith("Z") else raw
    try:
        dt = datetime.datetime.fromisoformat(normalized)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=datetime.timezone.utc)
    return dt


@pytest.mark.timeout(600)
def test_discovery_workflow_surfaces_denials_then_policy_update_closes_them(
    sandbox_cli,
    sandbox_daemon,
    tmp_path,
):
    """Empty policy + workload produces deny events via ``sandbox events
    --follow``; a subsequent policy update that allow-lists the targets
    closes the deny stream for those targets.
    """
    session_id: str | None = None
    policy_path_deny: str | None = None
    policy_path_allow: str | None = None
    events_proc: subprocess.Popen | None = None

    # Resolve target hostnames on the host once; the assertion below
    # compares the deny-logger's orig_dst_ip against this set.
    host_to_ips = _resolve_targets()

    # Paths for the background CLI's stdout / stderr capture.
    events_stdout = tmp_path / "events.jsonl"
    events_stderr = tmp_path / "events.stderr.log"

    try:
        # 1-2. Create session with empty policy (creates AND starts).
        policy_deny = {"version": "2.0.0", "rules": []}
        policy_path_deny = write_policy_file(policy_deny)

        create_result = sandbox_cli(
            "create", "--name", SESSION_NAME,
            *_VM_RESOURCE_ARGS, "--policy", policy_path_deny,
            timeout=600,
        )
        assert create_result.returncode == 0, (
            f"sandbox create failed (rc={create_result.returncode}).\n"
            f"stdout: {create_result.stdout}\n"
            f"stderr: {create_result.stderr}"
        )
        session_id = parse_session_id(create_result.stdout)
        wait_for_state(sandbox_cli, SESSION_NAME, "Running", timeout=30)

        # 3. Spawn `sandbox events <session> --decision=deny --follow`
        #    in the background. Stdout goes to events.jsonl (raw JSONL),
        #    stderr is captured for debugging.
        socket_path = sandbox_daemon["socket"]
        events_stdout_fh = events_stdout.open("w")
        events_stderr_fh = events_stderr.open("w")
        events_proc = subprocess.Popen(
            [
                str(SANDBOX_BIN), "--socket", socket_path,
                "events", SESSION_NAME,
                "--decision=deny", "--follow",
            ],
            stdout=events_stdout_fh,
            stderr=events_stderr_fh,
        )
        # Give the CLI time to connect + subscribe before the first burst.
        time.sleep(FOLLOW_STARTUP_S)
        assert events_proc.poll() is None, (
            f"`sandbox events --follow` subprocess exited unexpectedly "
            f"before the first workload.\n"
            f"exit code: {events_proc.returncode}\n"
            f"stderr: {events_stderr.read_text() if events_stderr.exists() else '<none>'}"
        )

        # 4. Run TCP-only workload inside the VM against both hosts.
        #    curl is invoked with `--resolve` so it skips CoreDNS
        #    (which returns NXDOMAIN under the empty policy) and dials
        #    the raw IP directly, ensuring the deny-logger path fires.
        _curl_both_targets(sandbox_cli, host_to_ips)

        # 5. Wait for events to propagate to the deny-logger ring and
        #    through the `--follow` streaming pipe.
        time.sleep(EVENT_PROPAGATION_S)

        # 6. SIGINT the background CLI; give it a moment to flush,
        #    then wait. Accept 130 (documented SIGINT exit), -2
        #    (Popen reports -SIGINT on premature kernel-delivered
        #    signal termination), or 0 (clean EOF if the daemon
        #    closed the stream first).
        events_proc.send_signal(signal.SIGINT)
        try:
            rc = events_proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            events_proc.kill()
            rc = events_proc.wait(timeout=5)
        events_stdout_fh.close()
        events_stderr_fh.close()
        assert rc in (0, 130, -2, -signal.SIGINT), (
            f"`sandbox events --follow` exited with unexpected code {rc}.\n"
            f"stderr: {events_stderr.read_text() if events_stderr.exists() else '<none>'}"
        )

        # 7-8. Parse the captured JSONL and assert at least one deny
        #      event per target host appeared while the empty policy
        #      was in effect.
        events_before = _parse_jsonl(events_stdout)
        assert events_before, (
            f"`sandbox events --decision=deny --follow` produced no output "
            f"while empty policy was active.\n"
            f"stderr: {events_stderr.read_text() if events_stderr.exists() else '<none>'}\n"
            f"{capture_lima_logs(session_id)}"
        )

        # For each target host, require at least one deny event whose
        # orig_dst_ip matches the cached resolved set (deny-logger
        # path) OR an envoy.connection_denied on the target port
        # OR a dns.query_denied for the target host's query name.
        for host, ips in host_to_ips.items():
            def _matches(ev: dict, host=host, ips=ips) -> bool:
                if _is_deny_for_target(ev, ips, TARGET_PORT):
                    return True
                # DNS-layer fallback: the deny-logger may miss a host
                # if curl's --resolve is overridden by some hook; we
                # still accept a DNS denial against the target name.
                if ev.get("layer") == "dns" and ev.get("event") == "query_denied":
                    q = ev.get("query", "").rstrip(".")
                    return q == host
                return False

            matched = [ev for ev in events_before if _matches(ev)]
            assert matched, (
                f"Expected at least one deny event for {host}:{TARGET_PORT} "
                f"(IPs {sorted(ips)}) in the --follow stream while the empty "
                f"policy was active, but found none. Captured events "
                f"({len(events_before)} total):\n"
                + "\n".join(
                    json.dumps(ev) for ev in events_before[:20]
                )
            )

        # 9-10. Apply a new policy allowing both hosts at transport
        #       level on port 80 (TCP).
        policy_allow = {
            "version": "2.0.0",
            "rules": [
                {
                    "host": host,
                    "port": TARGET_PORT,
                    "protocol": "tcp",
                    "level": "transport",
                }
                for host in TARGET_HOSTS
            ],
        }
        policy_path_allow = write_policy_file(policy_allow)

        update_result = sandbox_cli(
            "policy", "update", SESSION_NAME, "--policy", policy_path_allow,
            timeout=120,
        )
        assert update_result.returncode == 0, (
            f"sandbox policy update failed (rc={update_result.returncode}).\n"
            f"stdout: {update_result.stdout}\n"
            f"stderr: {update_result.stderr}"
        )

        # 11. Record a tz-aware UTC timestamp right after the update
        #     lands. Events with timestamp >= this are "new" deny
        #     events that must NOT appear for our two target hosts.
        policy_update_ts = datetime.datetime.now(datetime.timezone.utc)

        # Warm DNS so the daemon's propagation loop materialises the per-rule
        # Envoy filter chain and the sandbox_policy nftables concat-set entry
        # (ip, port) for each target host. Under schema v2 L1 transport is
        # fail-closed at empty cache — without this warmup the curl --resolve
        # workload would race against the 2-second DNS-driven propagation loop
        # and lose. See test_m4_policy.test_level1_transport_tcp for the same
        # pattern on a fresh session.
        for host in TARGET_HOSTS:
            sandbox_cli(
                "ssh", SESSION_NAME, "--", "nslookup", host,
                timeout=120,
            )
        time.sleep(5)

        # 12. Re-run the same workload. With the new policy in effect,
        #     the deny-logger path should not fire for these hosts.
        _curl_both_targets(sandbox_cli, host_to_ips)

        # 13. Propagation budget for any late deny events.
        time.sleep(EVENT_PROPAGATION_S)

        # 14. Run `sandbox events <session> --decision=deny` (non-follow)
        #     to snapshot the current ring contents.
        snapshot_result = sandbox_cli(
            "events", SESSION_NAME, "--decision=deny",
            timeout=60,
        )
        assert snapshot_result.returncode == 0, (
            f"`sandbox events --decision=deny` failed "
            f"(rc={snapshot_result.returncode}).\n"
            f"stdout: {snapshot_result.stdout}\n"
            f"stderr: {snapshot_result.stderr}"
        )

        snapshot_events: list[dict] = []
        for line in snapshot_result.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                snapshot_events.append(json.loads(line))
            except json.JSONDecodeError:
                continue

        # 15. Assert no NEW deny events for our targets with
        #     timestamp >= policy_update_ts. Older deny events from
        #     the first workload burst remain in the ring and are
        #     allowed — the test is specifically about post-update
        #     continued denials.
        new_denies_after_update: list[dict] = []
        for ev in snapshot_events:
            ts = _parse_ts(ev.get("timestamp", ""))
            if ts is None or ts < policy_update_ts:
                continue
            for host, ips in host_to_ips.items():
                if _is_deny_for_target(ev, ips, TARGET_PORT):
                    new_denies_after_update.append(ev)
                    break
                if ev.get("layer") == "dns" and ev.get("event") == "query_denied":
                    if ev.get("query", "").rstrip(".") == host:
                        new_denies_after_update.append(ev)
                        break

        assert not new_denies_after_update, (
            f"After applying a policy that allows "
            f"{list(TARGET_HOSTS)} on port {TARGET_PORT}, expected no new "
            f"deny events for those hosts, but found "
            f"{len(new_denies_after_update)}:\n"
            + "\n".join(json.dumps(ev) for ev in new_denies_after_update[:20])
        )

    finally:
        # Best-effort cleanup of the background CLI.
        if events_proc is not None and events_proc.poll() is None:
            try:
                events_proc.send_signal(signal.SIGINT)
                events_proc.wait(timeout=5)
            except Exception:
                events_proc.kill()
                try:
                    events_proc.wait(timeout=5)
                except Exception:
                    pass

        if session_id is not None:
            try:
                sandbox_cli("rm", SESSION_NAME, timeout=120)
            except Exception:
                pass

        for p in (policy_path_deny, policy_path_allow):
            if p is not None:
                cleanup_policy_file(p)
