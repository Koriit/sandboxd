"""E2E regression for the test-daemon / production-daemon CIDR-pool isolation.

Asserts that a session created through the test daemon allocates from
the e2e test pool (``10.220.0.0/20``), not the production pool
(``10.209.0.0/20``). The test daemon is launched by ``conftest.py``
with ``SANDBOX_USERS_CONF`` pointing at a tempfile users.conf that
lists only the test pool — but the production route helper continues
reading the canonical ``/etc/sandboxd/users.conf``, which after
``make setup-users-conf`` lists *both* pools so authorization for
the test pool's gateway IP succeeds. See
``docs/internal/milestones/M12.md`` § S13 for the full rationale.

If the operator has not re-run ``make setup-users-conf`` since the
dual-pool change landed, the canonical file still lists only the
production pool and the route helper rejects the test daemon's
authorization request. This test detects that state up-front and
emits a ``pytest.skip`` pointing at ``make setup-users-conf`` rather
than failing inside session-create with a generic
"`route-helper authorization failed`".
"""

from __future__ import annotations

import ipaddress
import json
from pathlib import Path

import pytest

from conftest import (
    E2E_TEST_POOL_CIDR,
    cleanup_policy_file,
    make_create_args,
    parse_session_id,
    wait_for_state,
    write_policy_file,
)


# Production pool CIDR — the operator's canonical pool that the test
# daemon must NOT touch. Intentionally hard-coded here rather than
# imported: this is the asserted-against value, not the configured
# value, and decoupling them keeps the regression honest.
PRODUCTION_POOL_CIDR = "10.209.0.0/20"

# Canonical users.conf path read by the production route helper. The
# helper hard-codes this path; honoring `SANDBOX_USERS_CONF` inside a
# `cap_sys_admin+ep` binary would be a privilege escalation (see
# `sandbox-core::users_conf` module docs).
CANONICAL_USERS_CONF = Path("/etc/sandboxd/users.conf")


def _isolation_smoke_policy_file() -> str:
    """Minimal v2 policy. The test does not exercise policy enforcement
    — we only need *some* policy so ``sandbox create`` accepts the
    request and runs through the full network-allocation path.
    """
    policy = {
        "version": "2.0.0",
        "rules": [
            {
                "host": "example.com",
                "port": 443,
                "protocol": "tcp",
                "level": "transport",
            }
        ],
    }
    return write_policy_file(policy)


def _canonical_users_conf_has_test_pool() -> bool:
    """Return True iff ``/etc/sandboxd/users.conf`` lists the e2e test
    pool's CIDR among its ``subnets[]`` entries.

    The production route helper reads this file unconditionally (it
    ignores ``SANDBOX_USERS_CONF`` in the hardened build). For the test
    daemon's session-create to succeed end-to-end the canonical file
    must authorize the test pool's gateway IP — i.e. list
    ``10.220.0.0/20`` with the operator's username in
    ``allow_users``. Operators who have not re-run
    ``make setup-users-conf`` since the dual-pool change still carry a
    single-pool canonical file; this helper detects that state so the
    test can ``pytest.skip`` rather than fail mid-create with a
    generic route-helper error.

    Returns ``False`` on any read or parse error — including a missing
    file — so the skip path covers every "canonical file is not in the
    expected dual-pool shape" failure mode uniformly. The skip message
    points at ``make setup-users-conf`` as the fix.
    """
    try:
        with CANONICAL_USERS_CONF.open() as f:
            cfg = json.load(f)
    except (OSError, json.JSONDecodeError):
        return False
    subnets = cfg.get("subnets", []) if isinstance(cfg, dict) else []
    return any(
        isinstance(s, dict) and s.get("cidr") == E2E_TEST_POOL_CIDR
        for s in subnets
    )


def _inspect_session_network(sandbox_cli, name: str) -> dict:
    """Return the ``network`` block from ``sandbox inspect <name>``.

    Standalone copy of ``test_networking.inspect_session_network`` —
    both backends populate the same ``gateway_ip`` /
    ``session_subnet_cidr`` fields, so a single helper covers the
    parametrized test below without depending on ``test_networking.py``
    imports (which carry their own gateway-traffic-flow assumptions).
    """
    result = sandbox_cli("inspect", name, timeout=60)
    assert result.returncode == 0, (
        f"sandbox inspect {name} failed (rc={result.returncode}).\n"
        f"stdout: {result.stdout}\nstderr: {result.stderr}"
    )
    payload = json.loads(result.stdout)
    assert isinstance(payload, list) and len(payload) == 1, (
        f"sandbox inspect must emit a JSON array of one element; "
        f"got: {payload!r}"
    )
    dto = payload[0]
    assert "network" in dto, (
        f"SessionDto must surface a `network` block via inspect; "
        f"got keys {sorted(dto.keys())}"
    )
    return dto["network"]


@pytest.mark.timeout(600)
def test_session_allocates_from_e2e_test_pool(sandbox_cli, backend):
    """Create a session via the test daemon; assert its CIDR is in the
    test pool (``10.220.0.0/20``) and not in the production pool
    (``10.209.0.0/20``).

    Skips if the canonical ``/etc/sandboxd/users.conf`` does not list
    the test pool — this happens on hosts that ran
    ``make setup-dev-env`` before the dual-pool change landed. The
    skip message points at ``make setup-users-conf`` as the fix.
    """
    if not _canonical_users_conf_has_test_pool():
        pytest.skip(
            f"{CANONICAL_USERS_CONF} does not list the e2e test pool "
            f"({E2E_TEST_POOL_CIDR}). The production route helper reads "
            f"this file unconditionally (it ignores SANDBOX_USERS_CONF "
            f"in the hardened build) and would reject the test daemon's "
            f"authorization request for a test-pool gateway IP. Re-run "
            f"`make setup-users-conf` to idempotently append the test "
            f"pool entry, then re-run this test. See "
            f"docs/internal/milestones/M12.md § S13 for the rationale."
        )

    test_pool = ipaddress.ip_network(E2E_TEST_POOL_CIDR, strict=False)
    prod_pool = ipaddress.ip_network(PRODUCTION_POOL_CIDR, strict=False)

    session_id = None
    policy_path = None
    try:
        policy_path = _isolation_smoke_policy_file()
        result = sandbox_cli(
            "create",
            *make_create_args(
                backend, "isolation-test", "--policy", policy_path
            ),
            timeout=600,
        )
        assert result.returncode == 0, (
            f"sandbox create failed (rc={result.returncode}).\n"
            f"stdout: {result.stdout}\nstderr: {result.stderr}"
        )
        session_id = parse_session_id(result.stdout)
        wait_for_state(sandbox_cli, "isolation-test", "Running", timeout=10)

        net = _inspect_session_network(sandbox_cli, "isolation-test")
        subnet_cidr = net["session_subnet_cidr"]
        gateway_ip = net["gateway_ip"]
        session_subnet = ipaddress.ip_network(subnet_cidr, strict=False)
        gateway_addr = ipaddress.ip_address(gateway_ip)

        assert session_subnet.subnet_of(test_pool), (
            f"session_subnet_cidr {subnet_cidr} must fall inside the "
            f"e2e test pool {E2E_TEST_POOL_CIDR}; inspect block: {net!r}"
        )
        assert not session_subnet.overlaps(prod_pool), (
            f"session_subnet_cidr {subnet_cidr} overlaps the production "
            f"pool {PRODUCTION_POOL_CIDR} — the test daemon must not "
            f"allocate from production CIDRs; inspect block: {net!r}"
        )
        assert gateway_addr in test_pool, (
            f"gateway_ip {gateway_ip} must fall inside the e2e test "
            f"pool {E2E_TEST_POOL_CIDR}; inspect block: {net!r}"
        )
    finally:
        if session_id is not None:
            sandbox_cli("rm", "-f", "isolation-test", timeout=300)
        if policy_path is not None:
            cleanup_policy_file(policy_path)
