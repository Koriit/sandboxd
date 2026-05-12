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
    distro_template, vm_factory, release_tarball_x86_64
):
    """Second run of install.sh is a full no-op.

    Asserts every mutating step in the second-run log emits
    ``action=skip``. Specifically, the second run hits install.sh's
    pre-existing-install detection (step 5) and short-circuits to exit
    0 before the bulk of the script runs — so we look for the
    ``step=preexist action=skip`` line plus exit code 0.
    """
    vm = vm_factory(distro_template)
    tarball_in_vm = copy_tarball_to_vm(vm, release_tarball_x86_64)

    # First run.
    r1 = vm.shell(
        install_sh_cmd(tarball_in_vm),
        timeout=600,
    )
    assert r1.returncode == 0, f"first run failed:\n{r1.stdout}\n{r1.stderr}"

    # Truncate the log so we only see the second run.
    vm.shell("sudo truncate -s 0 /var/log/sandbox-install.log", check=True)

    # Second run.
    r2 = vm.shell(
        install_sh_cmd(tarball_in_vm),
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
    # Belt and suspenders: any step that did run on the second pass
    # MUST be in action=skip (the script reached preexist and exited).
    forbidden_actions = {"install", "load", "create", "set", "append"}
    for step, step_actions in actions.items():
        for a in step_actions:
            assert a not in forbidden_actions, (
                f"second run mutated state at step={step} action={a}\n{log2}"
            )


@pytest.mark.parametrize("distro_template", ["ubuntu-22.04"])
def test_install_partial_failure_recovery(
    distro_template, vm_factory, release_tarball_x86_64
):
    """Kill the install mid-step, re-run, verify continuation.

    Strategy: delete a key artifact (the route-helper binary) after a
    successful install, then re-run install.sh. The pre-existing-install
    guard short-circuits BEFORE we can re-install, so we exercise a
    different recovery shape: run install.sh, manually remove the
    sandboxd binary to simulate a botched binary copy, and then run
    install.sh again to verify the binary lands.

    Specifically: simulate a partial install where the sandboxd binary
    didn't end up on disk (e.g. `install -m 0755` was interrupted between
    binaries), but the state file is present. install.sh's preexist guard
    keys off `/usr/local/bin/sandboxd` so removing it puts us back into
    the "no install detected, proceed" path; the rest of the steps
    individually idempotent-skip (user already exists, caps already
    set, etc.) and the binary copy re-runs to completion.
    """
    vm = vm_factory(distro_template)
    tarball_in_vm = copy_tarball_to_vm(vm, release_tarball_x86_64)

    # Successful first install.
    r1 = vm.shell(
        install_sh_cmd(tarball_in_vm),
        timeout=600,
    )
    assert r1.returncode == 0, f"initial install failed:\n{r1.stdout}\n{r1.stderr}"

    # Simulate a partial install: keep the user / caps / state but drop
    # the sandboxd binary.
    vm.shell("sudo rm -f /usr/local/bin/sandboxd", check=True)

    # Truncate the log so we only see the recovery run.
    vm.shell("sudo truncate -s 0 /var/log/sandbox-install.log", check=True)

    r2 = vm.shell(
        install_sh_cmd(tarball_in_vm),
        timeout=600,
    )
    assert r2.returncode == 0, f"recovery run failed:\n{r2.stdout}\n{r2.stderr}"

    # Binary is back.
    assert vm.shell("test -x /usr/local/bin/sandboxd").returncode == 0

    # The recovery run should show the sandbox user step as skip
    # (already exists) and the install_binary step as install
    # (sandboxd) plus skip (sandbox CLI + route-helper, already
    # matching sha256).
    log2 = vm.shell(
        "sudo cat /var/log/sandbox-install.log", check=True,
    ).stdout
    actions = parse_install_log_actions(log2)

    assert "useradd" in actions
    assert "skip" in actions["useradd"], (
        f"useradd should have skipped on recovery; got {actions['useradd']}"
    )
    # install_binary appears 3 times (once per binary); at least one
    # should be 'install' (sandboxd was missing) and others 'skip'.
    assert "install_binary" in actions
    assert "install" in actions["install_binary"], (
        f"recovery did not re-install the sandboxd binary; "
        f"got {actions['install_binary']}\nLog:\n{log2}"
    )
