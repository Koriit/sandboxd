"""Idempotency + partial-failure recovery tests for install.sh.



- ``test_install_idempotent_double_run`` — second run is all-skip.
- ``test_install_partial_failure_recovery`` — kill install mid-privileged-step,
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


@pytest.mark.parametrize("distro_template", ["ubuntu-22.04"])
def test_install_partial_failure_recovery(
    distro_template, vm_factory, release_tarball_x86_64, sigstore_stack,
):
    """Kill the install after the sandbox-user step, re-run, verify continuation.

    Strategy: set SANDBOX_INSTALL_PRIV_CHILD_FAIL_AFTER=sandbox-user so
    the privileged child exits 1 immediately after creating the sandbox
    system user but BEFORE copying any binaries. The first run therefore
    aborts with the user present but no sandboxd binary on disk.

    On the recovery run (no fail hook), the planning pass detects that
    the sandbox user already exists (action=skip for useradd) and that
    the binaries are absent (action=install for each binary). The full
    install completes.

    This exercises the genuine "mid-privileged-batch failure" recovery
    shape: the planning pass re-detects completed work on re-run, so the
    re-run resumes naturally from where it stopped.
    """
    vm = vm_factory(distro_template)
    tarball_in_vm = copy_tarball_to_vm(vm, release_tarball_x86_64)

    # First run: force the privileged child to abort after sandbox-user.
    r1 = vm.shell(
        install_sh_cmd(
            tarball_in_vm,
            vm=vm,
            sigstore_stack=sigstore_stack,
            env={"SANDBOX_INSTALL_PRIV_CHILD_FAIL_AFTER": "sandbox-user"},
        ),
        timeout=600,
    )
    assert r1.returncode != 0, (
        f"install.sh exited 0 despite SANDBOX_INSTALL_PRIV_CHILD_FAIL_AFTER — "
        f"fail hook did not fire:\n{r1.stdout}\n{r1.stderr}"
    )

    # The sandbox user was created in the privileged child (sandbox-user step
    # ran), but the binary was NOT installed (install-binaries comes after).
    assert vm.shell("id sandbox").returncode == 0, (
        "sandbox user not created before privileged child aborted — "
        "SANDBOX_INSTALL_PRIV_CHILD_FAIL_AFTER may have fired too early"
    )
    assert vm.shell("test -x /usr/local/libexec/sandboxd/sandboxd").returncode != 0, (
        "sandboxd binary present after partial failure — "
        "SANDBOX_INSTALL_PRIV_CHILD_FAIL_AFTER may have fired too late"
    )

    # Truncate the log so the recovery run is what we read back.
    vm.shell("sudo truncate -s 0 /var/log/sandbox-install.log", check=True)

    # Recovery run (no fail hook).
    r2 = vm.shell(
        install_sh_cmd(tarball_in_vm, vm=vm, sigstore_stack=sigstore_stack),
        timeout=600,
    )
    assert r2.returncode == 0, (
        f"recovery run failed:\n{r2.stdout}\n{r2.stderr}"
    )

    # Binary is now in place.
    assert vm.shell("test -x /usr/local/libexec/sandboxd/sandboxd").returncode == 0

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
