"""Idempotency + partial-failure recovery tests for install.sh.

Spec §§ 6.3, 8.3, 8.4. Two cases:

- ``test_install_idempotent_double_run`` — second run is all-skip.
- ``test_install_partial_failure_recovery`` — kill install mid-step,
   re-run, verify it completes.
"""

from __future__ import annotations

import pytest

from conftest import copy_tarball_to_vm, install_sh_cmd, parse_install_log_actions


@pytest.mark.parametrize("distro_template", ["ubuntu-22.04"])
def test_install_idempotent_double_run(
    distro_template, vm_factory, release_tarball_x86_64, sigstore_stack,
):
    """Second run of install.sh is a full no-op.

    Asserts every mutating step in the second-run log is in the
    skip-only allow-list. Specifically, the second run hits install.sh's
    pre-existing-install detection (step 5) and short-circuits to exit
    0 before the bulk of the script runs — so we look for the
    ``step=preexist action=skip`` line plus exit code 0.
    """
    vm = vm_factory(distro_template)
    tarball_in_vm = copy_tarball_to_vm(vm, release_tarball_x86_64)

    # First run.
    r1 = vm.shell(
        install_sh_cmd(tarball_in_vm, vm=vm, sigstore_stack=sigstore_stack),
        timeout=600,
    )
    assert r1.returncode == 0, f"first run failed:\n{r1.stdout}\n{r1.stderr}"

    # Truncate the log so we only see the second run.
    vm.shell("sudo truncate -s 0 /var/log/sandbox-install.log", check=True)

    # Second run.
    r2 = vm.shell(
        install_sh_cmd(tarball_in_vm, vm=vm, sigstore_stack=sigstore_stack),
        timeout=120,
    )
    assert r2.returncode == 0, f"second run failed:\n{r2.stdout}\n{r2.stderr}"

    log2 = vm.shell(
        "sudo cat /var/log/sandbox-install.log", check=True,
    ).stdout
    actions = parse_install_log_actions(log2)

    # The script short-circuits at preexist → no install_* lines.
    assert "preexist" in actions, f"no preexist line in second log:\n{log2}"
    assert "skip" in actions["preexist"], (
        f"second run did not short-circuit at preexist:\n{log2}"
    )
    # Allow-list inversion: every action emitted on the second pass MUST
    # be in this allow-list. A forbidden-list lets new mutating actions
    # (e.g. a future ``add`` / ``replace`` step) slip through; allow-
    # listing fails closed instead.
    allowed_actions = {"skip"}
    for step, step_actions in actions.items():
        for a in step_actions:
            assert a in allowed_actions, (
                f"second run emitted disallowed action: "
                f"step={step} action={a} (allowed: {allowed_actions})\n{log2}"
            )


# Marker injected into install.sh by the partial-failure test. Centralised
# so the regex used to remove it later stays in sync.
_PARTIAL_FAILURE_MARKER = "# PARTIAL_FAILURE_INJECTION"


@pytest.mark.parametrize("distro_template", ["ubuntu-22.04"])
def test_install_partial_failure_recovery(
    distro_template, vm_factory, release_tarball_x86_64, sigstore_stack,
):
    """Kill the install mid-step, re-run, verify continuation.

    Strategy: patch the in-VM install.sh to ``exit 1`` immediately after
    ``add_operator_to_group`` (step 13). The first run aborts after
    user creation but BEFORE any binaries land. The patch is then
    reverted; the second run re-enters with no /usr/local/bin/sandboxd
    on disk, so the preexist guard passes and the remaining steps fire.
    Prior steps (useradd, operator_add) emit action=skip since they
    are inherently idempotent against an already-created user.

    This is the genuine "mid-step kill" recovery shape from spec § 8.4
    — previously this test removed the binary post-hoc, which only
    exercised "binary disappeared" and not "install was interrupted
    before binaries were copied".
    """
    vm = vm_factory(distro_template)
    tarball_in_vm = copy_tarball_to_vm(vm, release_tarball_x86_64)

    # Patch the in-VM install.sh: insert `exit 1` immediately after the
    # add_operator_to_group call inside main(). awk is used rather than
    # sed because the multi-line edit is awkward in sed; the marker
    # comment lets us locate (and later remove) the injection exactly.
    inject_cmd = (
        f"sudo awk '"
        f"{{ print }} "
        f"/^    add_operator_to_group$/ "
        f"{{ print \"    {_PARTIAL_FAILURE_MARKER}\"; "
        f"   print \"    exit 1\" }}' "
        f"/tmp/install.sh > /tmp/install.sh.patched "
        f"&& sudo mv /tmp/install.sh.patched /tmp/install.sh "
        f"&& sudo chmod +x /tmp/install.sh"
    )
    vm.shell(inject_cmd, check=True, timeout=30)
    # Confirm the marker landed.
    marker_check = vm.shell(
        f"grep -c '{_PARTIAL_FAILURE_MARKER}' /tmp/install.sh",
        check=True, timeout=10,
    )
    assert marker_check.stdout.strip() == "1", (
        f"injection marker did not appear in install.sh:\n{marker_check.stdout}"
    )

    # First run aborts mid-script with exit 1.
    r1 = vm.shell(
        install_sh_cmd(tarball_in_vm, vm=vm, sigstore_stack=sigstore_stack),
        timeout=600,
    )
    assert r1.returncode != 0, (
        f"injected install.sh exited 0 — injection point did not fire:\n"
        f"{r1.stdout}\n{r1.stderr}"
    )

    # The sandbox user was created in step 12 (before the injection),
    # but the binary was NOT installed (step 14 is after the injection).
    assert vm.shell("id sandbox").returncode == 0, (
        "sandbox user not created before injection — injection point too early"
    )
    assert vm.shell("test -x /usr/local/bin/sandboxd").returncode != 0, (
        "sandboxd installed before injection — injection point too late"
    )

    # Un-patch by removing both injected lines. The marker line tags the
    # next line (`exit 1`); delete the marker and the line immediately
    # following.
    vm.shell(
        f"sudo sed -i '/{_PARTIAL_FAILURE_MARKER}/,+1d' /tmp/install.sh",
        check=True, timeout=10,
    )
    # Confirm the injection is gone.
    assert vm.shell(
        f"grep -c '{_PARTIAL_FAILURE_MARKER}' /tmp/install.sh "
        f"|| true",
        timeout=10,
    ).stdout.strip() == "0", "marker still present after un-patch"

    # Truncate the log so the recovery run is what we read back.
    vm.shell("sudo truncate -s 0 /var/log/sandbox-install.log", check=True)

    # Recovery run.
    r2 = vm.shell(
        install_sh_cmd(tarball_in_vm, vm=vm, sigstore_stack=sigstore_stack),
        timeout=600,
    )
    assert r2.returncode == 0, (
        f"recovery run failed:\n{r2.stdout}\n{r2.stderr}"
    )

    # Binary is now in place.
    assert vm.shell("test -x /usr/local/bin/sandboxd").returncode == 0

    # The recovery run should show the sandbox user step as skip (the
    # user already exists from the aborted first run) and the
    # install_binary step as install (binaries were missing).
    log2 = vm.shell(
        "sudo cat /var/log/sandbox-install.log", check=True,
    ).stdout
    actions = parse_install_log_actions(log2)

    assert "useradd" in actions
    assert "skip" in actions["useradd"], (
        f"useradd should have skipped on recovery; got {actions['useradd']}"
    )
    assert "install_binary" in actions
    assert "install" in actions["install_binary"], (
        f"recovery did not install missing binaries; "
        f"got {actions['install_binary']}\nLog:\n{log2}"
    )
