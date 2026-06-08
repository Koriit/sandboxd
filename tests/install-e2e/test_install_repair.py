"""Health-gated repair tests for install.sh.

When install.sh detects a same-version install whose recorded status is
``complete`` but whose invariants are broken, it falls through to the normal
install flow (full reinstall) rather than no-op'ing. These tests verify that
re-running the installer after deliberately breaking an invariant:

1. Exits 0.
2. Emits ``action=repair`` (not ``action=skip``) in the install log.
3. Leaves the host in a correct state (broken invariant restored).

Covered scenarios (each is a separate test so failures are independently
attributable):

- ``test_repair_stripped_route_helper_caps`` — strip ``setcap`` off the route
  helper (H2 unhealthy); repair restores the expected capabilities.
- ``test_repair_corrupted_users_conf_schema`` — zero out ``_schema_version`` in
  ``users.conf`` (H4 unhealthy); repair runs ``apply-config-migrations`` which
  bumps the schema back to 1.
- ``test_repair_daemon_stopped`` — ``systemctl stop sandboxd`` (H6 unhealthy);
  repair re-enables and starts the daemon.
- ``test_healthy_host_still_skips`` — a healthy same-version host must still
  produce ``action=skip`` (regression guard: the health check must not become
  a false positive).
"""

from __future__ import annotations

import pytest

from conftest import (
    assert_full_install_landed,
    copy_tarball_to_vm,
    install_sh_cmd,
    parse_install_log_actions,
    wait_for_socket,
    wait_for_systemd_active,
)


# ---------------------------------------------------------------------------
# Helpers.
# ---------------------------------------------------------------------------

def _assert_repair_log(log: str) -> None:
    """Assert the install log shows ``action=repair``, not ``action=skip``.

    The health-gated repair path emits::

        step=preexist ... action=repair health=unhealthy reasons=...

    A skip would emit ``action=skip``, which this guard forbids.
    """
    actions = parse_install_log_actions(log)
    assert "preexist" in actions, (
        f"no preexist line in repair-run log:\n{log}"
    )
    assert "repair" in actions["preexist"], (
        f"re-run did not enter repair path (preexist actions: "
        f"{actions['preexist']});\nlog:\n{log}"
    )
    assert "skip" not in actions["preexist"], (
        f"re-run produced skip instead of repair (preexist actions: "
        f"{actions['preexist']});\nlog:\n{log}"
    )


# ---------------------------------------------------------------------------
# Tests.
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("distro_template", ["ubuntu-22.04"])
def test_repair_stripped_route_helper_caps(
    distro_template, vm_factory, release_tarball_x86_64, sigstore_stack,
):
    """Strip route-helper capabilities → re-run repairs them (H2).

    After a successful install we deliberately strip the file capabilities
    from ``sandbox-route-helper``. The health check (H2) detects the mismatch
    and the re-run falls through to the normal install flow, which re-runs
    ``setcap`` in the privileged batch (step 4) and restores the expected caps.
    """
    vm = vm_factory(distro_template)
    tarball_in_vm = copy_tarball_to_vm(vm, release_tarball_x86_64)

    # First install.
    r1 = vm.shell(
        install_sh_cmd(tarball_in_vm, vm=vm, sigstore_stack=sigstore_stack),
        timeout=600,
    )
    assert r1.returncode == 0, (
        f"initial install failed (exit {r1.returncode}):\n{r1.stdout}\n{r1.stderr}"
    )

    # Verify caps are present after the first install.
    caps_before = vm.shell(
        "getcap /usr/local/libexec/sandboxd/sandbox-route-helper",
        check=True, timeout=10,
    ).stdout
    assert "cap_net_admin" in caps_before, (
        f"route-helper caps unexpectedly absent after first install: {caps_before!r}"
    )

    # Break invariant: strip all file capabilities.
    vm.shell(
        "sudo setcap -r /usr/local/libexec/sandboxd/sandbox-route-helper",
        check=True, timeout=10,
    )
    caps_stripped = vm.shell(
        "getcap /usr/local/libexec/sandboxd/sandbox-route-helper",
    ).stdout.strip()
    assert "cap_net_admin" not in caps_stripped, (
        f"setcap -r did not strip caps: {caps_stripped!r}"
    )

    # Truncate the install log so we only see the repair run.
    vm.shell("sudo truncate -s 0 /var/log/sandbox-install.log", check=True)

    # Repair run.
    r2 = vm.shell(
        install_sh_cmd(tarball_in_vm, vm=vm, sigstore_stack=sigstore_stack),
        timeout=600,
    )
    assert r2.returncode == 0, (
        f"repair run failed (exit {r2.returncode}):\n{r2.stdout}\n{r2.stderr}"
    )

    log2 = vm.shell(
        "sudo cat /var/log/sandbox-install.log", check=True, timeout=10,
    ).stdout

    _assert_repair_log(log2)

    # Caps must be restored.
    caps_after = vm.shell(
        "getcap /usr/local/libexec/sandboxd/sandbox-route-helper",
        check=True, timeout=10,
    ).stdout
    assert "cap_net_admin,cap_sys_ptrace,cap_sys_admin=eip" in caps_after, (
        f"repair did not restore route-helper caps: {caps_after!r}"
    )

    # Full filesystem state must still be coherent.
    assert_full_install_landed(vm)


@pytest.mark.parametrize("distro_template", ["ubuntu-22.04"])
def test_repair_corrupted_users_conf_schema(
    distro_template, vm_factory, release_tarball_x86_64, sigstore_stack,
):
    """Zero out users.conf _schema_version → re-run repairs it (H4).

    The health check (H4) treats a ``_schema_version`` below the daemon
    minimum (1) as unhealthy. We simulate the incident scenario: overwrite the
    field with ``0`` (a missing field reads as 0 in the daemon code). The repair
    run falls through to the normal install, which re-runs
    ``apply-config-migrations`` in step 8 and brings the schema back to 1.
    """
    vm = vm_factory(distro_template)
    tarball_in_vm = copy_tarball_to_vm(vm, release_tarball_x86_64)

    # First install.
    r1 = vm.shell(
        install_sh_cmd(tarball_in_vm, vm=vm, sigstore_stack=sigstore_stack),
        timeout=600,
    )
    assert r1.returncode == 0, (
        f"initial install failed:\n{r1.stdout}\n{r1.stderr}"
    )

    # Verify schema version is 1 after first install.
    schema_before = vm.shell(
        "sudo jq -r '._schema_version' /etc/sandboxd/users.conf",
        check=True, timeout=10,
    ).stdout.strip()
    assert schema_before == "1", (
        f"expected _schema_version=1 after install; got: {schema_before!r}"
    )

    # Break invariant: overwrite _schema_version with 0 in-place.
    # Use a temp file + atomic rename so the file is never empty during
    # the update (jq writes stdout, not in-place).
    vm.shell(
        "tmp=$(mktemp); "
        "sudo jq '._schema_version = 0' /etc/sandboxd/users.conf | sudo tee \"$tmp\" > /dev/null; "
        "sudo mv \"$tmp\" /etc/sandboxd/users.conf",
        check=True, timeout=15,
    )
    schema_broken = vm.shell(
        "sudo jq -r '._schema_version' /etc/sandboxd/users.conf",
        check=True, timeout=10,
    ).stdout.strip()
    assert schema_broken == "0", (
        f"failed to set _schema_version to 0: got {schema_broken!r}"
    )

    # Truncate the install log.
    vm.shell("sudo truncate -s 0 /var/log/sandbox-install.log", check=True)

    # Repair run.
    r2 = vm.shell(
        install_sh_cmd(tarball_in_vm, vm=vm, sigstore_stack=sigstore_stack),
        timeout=600,
    )
    assert r2.returncode == 0, (
        f"repair run failed:\n{r2.stdout}\n{r2.stderr}"
    )

    log2 = vm.shell(
        "sudo cat /var/log/sandbox-install.log", check=True, timeout=10,
    ).stdout

    _assert_repair_log(log2)

    # Schema must be back at 1.
    schema_after = vm.shell(
        "sudo jq -r '._schema_version' /etc/sandboxd/users.conf",
        check=True, timeout=10,
    ).stdout.strip()
    assert schema_after == "1", (
        f"repair did not restore _schema_version to 1; got: {schema_after!r}"
    )

    assert_full_install_landed(vm)


@pytest.mark.parametrize("distro_template", ["ubuntu-22.04"])
def test_repair_daemon_stopped(
    distro_template, vm_factory, release_tarball_x86_64, sigstore_stack,
):
    """Stop the daemon → re-run detects inactive + repairs (H6).

    ``systemctl stop sandboxd`` leaves the daemon inactive (not failed).
    The health check (H6) treats anything other than ``active`` as
    unhealthy. The repair run falls through to the full batch, which
    runs ``systemctl reset-failed + enable --now`` in step 13 and
    brings the daemon back to active.
    """
    vm = vm_factory(distro_template)
    tarball_in_vm = copy_tarball_to_vm(vm, release_tarball_x86_64)

    # First install.
    r1 = vm.shell(
        install_sh_cmd(tarball_in_vm, vm=vm, sigstore_stack=sigstore_stack),
        timeout=600,
    )
    assert r1.returncode == 0, (
        f"initial install failed:\n{r1.stdout}\n{r1.stderr}"
    )

    # Wait for the daemon to be active (step 13 starts it).
    wait_for_systemd_active(vm.name, "sandboxd", timeout=60)

    # Break invariant: stop the daemon.
    vm.shell("sudo systemctl stop sandboxd", check=True, timeout=15)
    state_after_stop = vm.shell(
        "systemctl is-active sandboxd || true", timeout=10,
    ).stdout.strip()
    assert state_after_stop != "active", (
        f"systemctl stop did not stop the daemon: state={state_after_stop!r}"
    )

    # Truncate log so we only inspect the repair run.
    vm.shell("sudo truncate -s 0 /var/log/sandbox-install.log", check=True)

    # Repair run.
    r2 = vm.shell(
        install_sh_cmd(tarball_in_vm, vm=vm, sigstore_stack=sigstore_stack),
        timeout=600,
    )
    assert r2.returncode == 0, (
        f"repair run failed:\n{r2.stdout}\n{r2.stderr}"
    )

    log2 = vm.shell(
        "sudo cat /var/log/sandbox-install.log", check=True, timeout=10,
    ).stdout

    _assert_repair_log(log2)

    # Daemon must be active again.
    wait_for_systemd_active(vm.name, "sandboxd", timeout=60)
    wait_for_socket(vm.name, "/run/sandbox/sandboxd.sock", timeout=60)

    assert_full_install_landed(vm)


@pytest.mark.parametrize("distro_template", ["ubuntu-22.04"])
def test_healthy_host_still_skips(
    distro_template, vm_factory, release_tarball_x86_64, sigstore_stack,
):
    """A healthy same-version host must still produce action=skip (regression guard).

    Verifies that the health check does not introduce false positives:
    a fresh, unmodified install leaves all invariants healthy, so the second
    run must short-circuit at ``preexist`` with ``action=skip``, exactly as
    before the health-gated repair was introduced.
    """
    vm = vm_factory(distro_template)
    tarball_in_vm = copy_tarball_to_vm(vm, release_tarball_x86_64)

    # First install.
    r1 = vm.shell(
        install_sh_cmd(tarball_in_vm, vm=vm, sigstore_stack=sigstore_stack),
        timeout=600,
    )
    assert r1.returncode == 0, (
        f"initial install failed:\n{r1.stdout}\n{r1.stderr}"
    )

    # Daemon must be active (step 13 starts it) — H6 healthy.
    wait_for_systemd_active(vm.name, "sandboxd", timeout=60)

    # Truncate so only the second run is visible.
    vm.shell("sudo truncate -s 0 /var/log/sandbox-install.log", check=True)

    # Second run — no invariant broken.
    r2 = vm.shell(
        install_sh_cmd(tarball_in_vm, vm=vm, sigstore_stack=sigstore_stack),
        timeout=120,
    )
    assert r2.returncode == 0, (
        f"second run on healthy host failed:\n{r2.stdout}\n{r2.stderr}"
    )

    log2 = vm.shell(
        "sudo cat /var/log/sandbox-install.log", check=True, timeout=10,
    ).stdout

    actions = parse_install_log_actions(log2)
    assert "preexist" in actions, (
        f"no preexist line in second-run log:\n{log2}"
    )
    assert "skip" in actions["preexist"], (
        f"healthy host did not skip on second run (preexist actions: "
        f"{actions['preexist']});\nlog:\n{log2}"
    )
    assert "repair" not in actions["preexist"], (
        f"healthy host entered repair path unexpectedly (false positive): "
        f"preexist actions={actions['preexist']};\nlog:\n{log2}"
    )
