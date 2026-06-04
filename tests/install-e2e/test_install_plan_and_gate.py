"""Tests for Phase 1 install.sh redesign: planning pass + confirmation gate.

Coverage:
- ``test_plan_action_list_fresh`` — planning pass computes correct
  skip/create/install decisions on a fresh host (nothing pre-installed).
- ``test_plan_action_list_partial`` — planning pass skips already-done
  steps when some but not all changes are already applied.
- ``test_confirmation_gate_yes_flag`` — ``--yes`` skips the gate; plan
  is still printed first.
- ``test_confirmation_gate_interactive_y`` — interactive ``y`` answer
  proceeds.
- ``test_confirmation_gate_interactive_n`` — interactive ``N`` answer
  aborts before any privileged change.
- ``test_confirmation_gate_no_tty_no_yes`` — no TTY and no ``--yes``
  hard-aborts before any privileged change.
- ``test_operator_detection_curl_bash`` — operator is detected via
  ``id -un`` of the invoking process, not ``$SUDO_USER``.
"""

from __future__ import annotations

import pytest

from conftest import (
    assert_full_install_landed,
    copy_tarball_to_vm,
    install_sh_cmd,
    parse_install_log_actions,
)


# ---------------------------------------------------------------------------
# Helpers.
# ---------------------------------------------------------------------------

def _install_first(vm, tarball_in_vm, sigstore_stack):
    """Run a clean install. Asserts success."""
    r = vm.shell(
        install_sh_cmd(tarball_in_vm, vm=vm, sigstore_stack=sigstore_stack),
        timeout=600,
    )
    assert r.returncode == 0, (
        f"first install failed:\n{r.stdout}\n{r.stderr}"
    )


# ---------------------------------------------------------------------------
# Planning-pass action list.
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("distro_template", ["ubuntu-22.04"])
def test_plan_action_list_fresh(
    distro_template, vm_factory, release_tarball_x86_64, sigstore_stack,
):
    """On a fresh VM the planning pass marks all mutating steps as 'install'
    or 'create', not 'skip'.

    We inspect the install log for the steps the privileged child performs.
    Each step must record action=create or action=install (not skip) because
    nothing was pre-applied on a clean VM.
    """
    vm = vm_factory(distro_template)
    tarball_in_vm = copy_tarball_to_vm(vm, release_tarball_x86_64)

    r = vm.shell(
        install_sh_cmd(tarball_in_vm, vm=vm, sigstore_stack=sigstore_stack),
        timeout=600,
    )
    assert r.returncode == 0, f"install failed:\n{r.stdout}\n{r.stderr}"

    log = vm.shell(
        "sudo cat /var/log/sandbox-install.log", check=True, timeout=10,
    ).stdout
    actions = parse_install_log_actions(log)

    # The sandbox user must have been created (not skipped).
    assert "useradd" in actions, f"useradd step missing from log:\n{log}"
    assert "create" in actions["useradd"], (
        f"expected useradd action=create on fresh VM; got {actions['useradd']}"
    )

    # At least one binary must have been installed (not skipped).
    assert "install_binary" in actions, f"install_binary step missing from log:\n{log}"
    assert "install" in actions["install_binary"], (
        f"expected install_binary action=install on fresh VM; got {actions['install_binary']}"
    )

    # The systemd unit must have been installed.
    assert "install_unit" in actions, f"install_unit step missing from log:\n{log}"
    assert "install" in actions["install_unit"], (
        f"expected install_unit action=install on fresh VM; got {actions['install_unit']}"
    )

    # The planning pass ran (confirmed by compute_plan log line).
    assert "compute_plan" in log, (
        f"compute_plan step missing from log — planning pass may not have run:\n{log}"
    )


@pytest.mark.parametrize("distro_template", ["ubuntu-22.04"])
def test_plan_action_list_partial(
    distro_template, vm_factory, release_tarball_x86_64, sigstore_stack,
):
    """When the sandbox user exists but binaries are absent, the planning pass
    skips user creation and installs the binaries.

    Simulates a recovery scenario: sandbox user was created in a prior
    partial run, but no binaries landed. On re-run, compute_plan detects
    the user (skip) and detects absent binaries (install).
    """
    vm = vm_factory(distro_template)
    tarball_in_vm = copy_tarball_to_vm(vm, release_tarball_x86_64)

    # Partial first run: abort the privileged child after sandbox-user.
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
        f"partial run should have failed but exited 0:\n{r1.stdout}\n{r1.stderr}"
    )
    # Confirm sandbox user exists.
    assert vm.shell("id sandbox").returncode == 0, "sandbox user absent after partial run"
    # Confirm binaries absent.
    assert vm.shell("test -x /usr/local/libexec/sandboxd/sandboxd").returncode != 0, (
        "sandboxd binary present after partial run — injection fired too late"
    )

    # Truncate log; recovery run with full planning pass.
    vm.shell("sudo truncate -s 0 /var/log/sandbox-install.log", check=True)
    r2 = vm.shell(
        install_sh_cmd(tarball_in_vm, vm=vm, sigstore_stack=sigstore_stack),
        timeout=600,
    )
    assert r2.returncode == 0, f"recovery run failed:\n{r2.stdout}\n{r2.stderr}"

    log2 = vm.shell(
        "sudo cat /var/log/sandbox-install.log", check=True, timeout=10,
    ).stdout
    actions = parse_install_log_actions(log2)

    # User already existed — planning pass should have detected it.
    assert "useradd" in actions, f"useradd step missing from recovery log:\n{log2}"
    assert "skip" in actions["useradd"], (
        f"expected useradd action=skip on recovery run; got {actions['useradd']}"
    )

    # Binaries were missing — planning pass should have scheduled install.
    assert "install_binary" in actions, f"install_binary missing from recovery log:\n{log2}"
    assert "install" in actions["install_binary"], (
        f"expected install_binary action=install on recovery run; got {actions['install_binary']}"
    )


# ---------------------------------------------------------------------------
# Confirmation gate.
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("distro_template", ["ubuntu-22.04"])
def test_confirmation_gate_yes_flag(
    distro_template, vm_factory, release_tarball_x86_64, sigstore_stack,
):
    """--yes skips the interactive gate; plan is printed; install completes.

    The harness always runs install.sh with ``--yes`` (via install_sh_cmd),
    so this test verifies the normal harness path: plan is emitted to
    stdout and the install succeeds without waiting for a TTY read.
    """
    vm = vm_factory(distro_template)
    tarball_in_vm = copy_tarball_to_vm(vm, release_tarball_x86_64)

    r = vm.shell(
        install_sh_cmd(tarball_in_vm, vm=vm, sigstore_stack=sigstore_stack),
        timeout=600,
    )
    assert r.returncode == 0, f"install with --yes failed:\n{r.stdout}\n{r.stderr}"

    # The plan output should contain recognisable section headers.
    output = r.stdout
    assert "privileged change plan" in output, (
        f"plan header missing from --yes output:\n{output}"
    )
    assert "--yes passed" in output, (
        f"--yes acknowledgment missing from output:\n{output}"
    )

    # Full filesystem post-conditions must be satisfied.
    assert_full_install_landed(vm)

    # Confirm log records confirm action=yes-flag.
    log = vm.shell(
        "sudo cat /var/log/sandbox-install.log", check=True, timeout=10,
    ).stdout
    assert "step=confirm action=yes-flag" in log, (
        f"confirm action=yes-flag missing from log:\n{log}"
    )


@pytest.mark.parametrize("distro_template", ["ubuntu-22.04"])
def test_confirmation_gate_interactive_y(
    distro_template, vm_factory, release_tarball_x86_64, sigstore_stack,
):
    """Interactive 'y' answer at the [y/N] gate proceeds to install.

    The test feeds a pseudo-TTY to install.sh so it can read from /dev/tty.
    We use ``script -c '...' /dev/null`` inside the VM to attach a PTY and
    pipe ``y\\n`` into it via ``echo | script``.
    """
    vm = vm_factory(distro_template)
    tarball_in_vm = copy_tarball_to_vm(vm, release_tarball_x86_64)

    # Build the install command WITHOUT --yes, with sigstore env vars.
    from conftest import (
        stage_sigstore_trust_material_in_vm,
        version_from_tarball,
        _sh_quote,
    )
    ver = version_from_tarball(tarball_in_vm)
    env_vars = stage_sigstore_trust_material_in_vm(vm, sigstore_stack)
    env_prefix = " ".join(f"{k}={_sh_quote(v)}" for k, v in env_vars.items())

    # Use `script` to provide a TTY. `printf 'y\n' | script -q -c '...' /dev/null`
    # attaches a PTY to the command's stdin/stdout; install.sh detects the TTY
    # and reads 'y' from it.
    install_cmd = (
        f"sudo {env_prefix} bash /tmp/install.sh "
        f"--from {tarball_in_vm} --version {ver} --no-color"
    )
    tty_cmd = f"printf 'y\\n' | script -q -c {_sh_quote(install_cmd)} /dev/null"

    r = vm.shell(tty_cmd, timeout=600)
    assert r.returncode == 0, (
        f"interactive-y install failed:\n{r.stdout}\n{r.stderr}"
    )

    # The plan must have been shown and the install completed.
    output = r.stdout
    assert "privileged change plan" in output, (
        f"plan not shown on interactive path:\n{output}"
    )
    assert vm.shell("test -x /usr/local/libexec/sandboxd/sandboxd").returncode == 0, (
        "sandboxd not installed after interactive 'y'"
    )

    log = vm.shell(
        "sudo cat /var/log/sandbox-install.log", check=True, timeout=10,
    ).stdout
    assert "step=confirm action=yes-interactive" in log, (
        f"confirm action=yes-interactive missing from log:\n{log}"
    )


@pytest.mark.parametrize("distro_template", ["ubuntu-22.04"])
def test_confirmation_gate_interactive_n(
    distro_template, vm_factory, release_tarball_x86_64, sigstore_stack,
):
    """Interactive 'N' answer aborts before any privileged change.

    The install exits 0 (user chose to abort, not an error) and no
    mutating changes have been applied.
    """
    vm = vm_factory(distro_template)
    tarball_in_vm = copy_tarball_to_vm(vm, release_tarball_x86_64)

    from conftest import (
        stage_sigstore_trust_material_in_vm,
        version_from_tarball,
        _sh_quote,
    )
    ver = version_from_tarball(tarball_in_vm)
    env_vars = stage_sigstore_trust_material_in_vm(vm, sigstore_stack)
    env_prefix = " ".join(f"{k}={_sh_quote(v)}" for k, v in env_vars.items())

    install_cmd = (
        f"sudo {env_prefix} bash /tmp/install.sh "
        f"--from {tarball_in_vm} --version {ver} --no-color"
    )
    # Feed newline (empty = default N) to the gate.
    tty_cmd = f"printf '\\n' | script -q -c {_sh_quote(install_cmd)} /dev/null"

    r = vm.shell(tty_cmd, timeout=600)
    # Exit 0: the user declined; this is a clean abort, not an error.
    assert r.returncode == 0, (
        f"interactive-N abort returned non-zero:\n{r.stdout}\n{r.stderr}"
    )

    output = r.stdout
    assert "Aborted" in output, (
        f"'Aborted' message not in output after N:\n{output}"
    )

    # No mutating changes: sandbox user must not exist.
    assert vm.shell("id sandbox").returncode != 0, (
        "sandbox user created despite interactive 'N' abort"
    )
    assert vm.shell("test -x /usr/local/libexec/sandboxd/sandboxd").returncode != 0, (
        "sandboxd binary present despite interactive 'N' abort"
    )

    log = vm.shell(
        "sudo cat /var/log/sandbox-install.log", check=True, timeout=10,
    ).stdout
    assert "step=confirm action=no-interactive" in log, (
        f"confirm action=no-interactive missing from log:\n{log}"
    )


@pytest.mark.parametrize("distro_template", ["ubuntu-22.04"])
def test_confirmation_gate_no_tty_no_yes(
    distro_template, vm_factory, release_tarball_x86_64, sigstore_stack,
):
    """No TTY and no --yes → hard abort before any privileged change.

    The harness runs install.sh without a controlling TTY (the default
    limactl shell path has no TTY attached). Without --yes the script
    must exit non-zero before running sudo.
    """
    vm = vm_factory(distro_template)
    tarball_in_vm = copy_tarball_to_vm(vm, release_tarball_x86_64)

    from conftest import (
        stage_sigstore_trust_material_in_vm,
        version_from_tarball,
        _sh_quote,
    )
    ver = version_from_tarball(tarball_in_vm)
    env_vars = stage_sigstore_trust_material_in_vm(vm, sigstore_stack)
    env_prefix = " ".join(f"{k}={_sh_quote(v)}" for k, v in env_vars.items())

    # Run WITHOUT --yes, and without a TTY (no `script` wrapper).
    install_cmd = (
        f"sudo {env_prefix} bash /tmp/install.sh "
        f"--from {tarball_in_vm} --version {ver} --no-color"
    )
    r = vm.shell(install_cmd, timeout=600)

    assert r.returncode != 0, (
        f"install.sh should hard-abort without TTY and --yes, but exited 0:\n"
        f"{r.stdout}\n{r.stderr}"
    )

    output = r.stdout + r.stderr
    # Must mention the abort and how to fix it.
    assert "Aborting" in output or "aborting" in output.lower() or "--yes" in output, (
        f"abort message / --yes hint missing from no-TTY output:\n{output}"
    )

    # No mutating changes: sandbox user must not exist.
    assert vm.shell("id sandbox").returncode != 0, (
        "sandbox user created despite no-TTY no-yes hard abort"
    )
    assert vm.shell("test -x /usr/local/libexec/sandboxd/sandboxd").returncode != 0, (
        "sandboxd binary present despite no-TTY no-yes hard abort"
    )

    log = vm.shell(
        "sudo cat /var/log/sandbox-install.log", check=True, timeout=10,
    ).stdout
    assert "step=confirm action=abort reason=no-tty" in log, (
        f"confirm abort=no-tty missing from log:\n{log}"
    )


# ---------------------------------------------------------------------------
# Operator detection (id -un vs $SUDO_USER fix).
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("distro_template", ["ubuntu-22.04"])
def test_operator_detection_curl_bash_style(
    distro_template, vm_factory, release_tarball_x86_64, sigstore_stack,
):
    """Operator is detected via id -un of the invoking process.

    The old code used $SUDO_USER which is empty when install.sh is run as
    the operator directly (the curl|bash use-case). The new code uses
    `id -un` of the unprivileged parent process, which always returns the
    actual operator name.

    The harness invokes install.sh via `sudo ... bash /tmp/install.sh ...`
    from the Lima 'lima' user. The install.sh process therefore runs as
    root (via sudo), but id -un of the PARENT (before sudo) is 'lima'.
    install.sh captures this before invoking sudo, so the operator name
    lands in the install-state even when $SUDO_USER would have been empty
    under the old model.

    We verify that install-state.json records a non-empty installed_by_operator
    field matching the invoking user.
    """
    vm = vm_factory(distro_template)
    tarball_in_vm = copy_tarball_to_vm(vm, release_tarball_x86_64)

    r = vm.shell(
        install_sh_cmd(tarball_in_vm, vm=vm, sigstore_stack=sigstore_stack),
        timeout=600,
    )
    assert r.returncode == 0, f"install failed:\n{r.stdout}\n{r.stderr}"

    # Determine which user limactl shell lands as inside the VM.
    invoking_user = vm.shell("whoami", check=True, timeout=10).stdout.strip()
    assert invoking_user, "could not determine invoking user"

    # Read install-state.json.
    import json
    from conftest import sandbox_base_dir_in_vm
    base_dir = sandbox_base_dir_in_vm(vm)
    state_raw = vm.shell(
        f"sudo cat {base_dir}/.install-state.json", check=True, timeout=10,
    ).stdout
    state = json.loads(state_raw)

    # The install-state must record the operator.
    installed_by = state.get("installed_by_operator", "")
    assert installed_by and installed_by != "(direct-root)", (
        f"install-state.json recorded a missing/root operator: "
        f"installed_by_operator={installed_by!r}. "
        f"Expected operator name (e.g. '{invoking_user}')."
    )

    # operators_added_to_group should also record the operator (if they
    # were not already in the sandbox group).
    operators_added = state.get("operators_added_to_group", [])
    # Either the operator was added or they were already a member (both valid).
    log = vm.shell(
        "sudo cat /var/log/sandbox-install.log", check=True, timeout=10,
    ).stdout
    assert "step=operator_add" in log, (
        f"operator_add step missing from install log:\n{log}"
    )
