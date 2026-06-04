"""Phase 2 install.sh tests: incremental checkpointing + structured failure report.

Coverage:
- ``test_checkpoint_status_complete_on_success`` — a successful install writes
  install-state.json with status=complete and last_completed_step=write-install-state.
- ``test_checkpoint_after_partial_failure`` — a forced mid-batch failure leaves
  install-state.json with status=failed, the correct last_completed_step, and the
  correct partial we_* provenance flags.
- ``test_failure_report_stdout`` — the parent prints a structured failure report to
  stdout when the child exits non-zero: contains which step failed, applied steps,
  recovery hint, log path.
- ``test_idempotent_resume_after_checkpoint`` — a re-run after a partial failure
  reads the prior checkpoint, re-detects completed work, and resumes; the final
  install-state.json has status=complete.
"""

from __future__ import annotations

import json
import pytest

from conftest import (
    assert_full_install_landed,
    copy_tarball_to_vm,
    install_sh_cmd,
    parse_install_log_actions,
    sandbox_base_dir_in_vm,
)


# ---------------------------------------------------------------------------
# Helpers.
# ---------------------------------------------------------------------------

def _read_state(vm, base_dir):
    """Parse install-state.json from the VM; return dict."""
    raw = vm.shell(
        f"sudo cat {base_dir}/.install-state.json",
        check=True, timeout=10,
    ).stdout
    return json.loads(raw)


def _state_exists(vm, base_dir):
    """Return True if install-state.json is readable inside the VM."""
    return vm.shell(
        f"sudo test -r {base_dir}/.install-state.json",
        timeout=10,
    ).returncode == 0


# ---------------------------------------------------------------------------
# Tests.
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("distro_template", ["ubuntu-22.04"])
def test_checkpoint_status_complete_on_success(
    distro_template, vm_factory, release_tarball_x86_64, sigstore_stack,
):
    """Successful install writes status=complete and last_completed_step=write-install-state.

    The final install-state.json must pass the existing ``assert_full_install_landed``
    post-conditions AND carry the new Phase 2 fields with the expected values.
    """
    vm = vm_factory(distro_template)
    tarball_in_vm = copy_tarball_to_vm(vm, release_tarball_x86_64)

    r = vm.shell(
        install_sh_cmd(tarball_in_vm, vm=vm, sigstore_stack=sigstore_stack),
        timeout=600,
    )
    assert r.returncode == 0, f"install failed:\n{r.stdout}\n{r.stderr}"

    base_dir = sandbox_base_dir_in_vm(vm)
    state = _read_state(vm, base_dir)

    assert state.get("status") == "complete", (
        f"expected status=complete on successful install; got {state.get('status')!r}"
    )
    assert state.get("last_completed_step") == "write-install-state", (
        f"expected last_completed_step=write-install-state; "
        f"got {state.get('last_completed_step')!r}"
    )

    # Forward-compat: older fields must still be present and correct.
    assert state.get("installed_version"), "installed_version missing"
    assert state.get("we_created_sandbox_user") is True, (
        "we_created_sandbox_user should be true on a fresh install"
    )
    # jq validation inside the VM.
    assert vm.shell(
        f"sudo jq -e . {base_dir}/.install-state.json", timeout=10,
    ).returncode == 0, "install-state.json not parseable by jq after success"


@pytest.mark.parametrize("distro_template", ["ubuntu-22.04"])
def test_checkpoint_after_partial_failure(
    distro_template, vm_factory, release_tarball_x86_64, sigstore_stack,
):
    """A forced mid-batch failure leaves install-state.json with status=failed.

    We use SANDBOX_INSTALL_PRIV_CHILD_FAIL_AFTER=install-binaries to let the
    sandbox-user and operator-group-add steps complete, then abort. The checkpoint
    written after the binary-install step (before the abort) should reflect:
      - status=failed
      - last_completed_step=install-binaries
      - we_created_sandbox_user=true (sandbox user was created)
      - we_created_users_conf=false (that step hadn't run yet)
    """
    vm = vm_factory(distro_template)
    tarball_in_vm = copy_tarball_to_vm(vm, release_tarball_x86_64)

    # Abort after install-binaries step.
    r = vm.shell(
        install_sh_cmd(
            tarball_in_vm,
            vm=vm,
            sigstore_stack=sigstore_stack,
            env={"SANDBOX_INSTALL_PRIV_CHILD_FAIL_AFTER": "install-binaries"},
        ),
        timeout=600,
    )
    assert r.returncode != 0, (
        f"expected non-zero exit on forced failure; got 0:\n{r.stdout}\n{r.stderr}"
    )

    # The sandbox user exists (step 1 ran).
    assert vm.shell("id sandbox").returncode == 0, (
        "sandbox user missing — fail hook fired too early"
    )

    # install-state.json must exist (written by incremental checkpoint).
    base_dir = sandbox_base_dir_in_vm(vm)
    assert _state_exists(vm, base_dir), (
        "install-state.json missing after partial failure — incremental checkpoint not written"
    )

    state = _read_state(vm, base_dir)

    assert state.get("status") == "failed", (
        f"expected status=failed; got {state.get('status')!r}"
    )
    # last_completed_step is the last SUCCESSFULLY completed step. The test
    # hook fires after install-binaries succeeds and is checkpointed, so
    # last_completed_step is install-binaries.
    assert state.get("last_completed_step") == "install-binaries", (
        f"expected last_completed_step=install-binaries; "
        f"got {state.get('last_completed_step')!r}"
    )
    # failed_step names the step that triggered the failure (the test hook
    # fires after install-binaries, naming that step as the failure trigger).
    assert state.get("failed_step") == "install-binaries", (
        f"expected failed_step=install-binaries; "
        f"got {state.get('failed_step')!r}"
    )
    # Sandbox user was created.
    assert state.get("we_created_sandbox_user") is True, (
        f"expected we_created_sandbox_user=true; state={state!r}"
    )
    # Users.conf was NOT created yet (that step comes after install-binaries).
    assert state.get("we_created_users_conf") is False, (
        f"expected we_created_users_conf=false; state={state!r}"
    )
    # jq validation.
    assert vm.shell(
        f"sudo jq -e . {base_dir}/.install-state.json", timeout=10,
    ).returncode == 0, "install-state.json not parseable by jq after partial failure"


@pytest.mark.parametrize("distro_template", ["ubuntu-22.04"])
def test_failure_report_stdout(
    distro_template, vm_factory, release_tarball_x86_64, sigstore_stack,
):
    """Structured failure report is printed to stdout on child failure.

    Checks for the required elements per the spec:
    - Which step died (N of M format)
    - Steps applied listed
    - Recovery hint mentioning re-run
    - Log path
    """
    vm = vm_factory(distro_template)
    tarball_in_vm = copy_tarball_to_vm(vm, release_tarball_x86_64)

    # Force failure after install-binaries.
    r = vm.shell(
        install_sh_cmd(
            tarball_in_vm,
            vm=vm,
            sigstore_stack=sigstore_stack,
            env={"SANDBOX_INSTALL_PRIV_CHILD_FAIL_AFTER": "install-binaries"},
        ),
        timeout=600,
    )
    assert r.returncode != 0, (
        f"expected non-zero exit; got 0:\n{r.stdout}\n{r.stderr}"
    )

    output = r.stdout + r.stderr

    # "N of M" step count.
    assert "of" in output and "install-binaries" in output, (
        f"failure report missing 'N of M' or step name:\n{output}"
    )

    # Applied steps listed (sandbox-user ran before the failure).
    assert "sandbox-user" in output, (
        f"failure report missing applied step 'sandbox-user':\n{output}"
    )

    # Recovery hint.
    assert "re-run" in output.lower() or "re-run" in output or "Recovery" in output, (
        f"failure report missing recovery hint:\n{output}"
    )

    # Install log path.
    assert "/var/log/sandbox-install.log" in output or "Install log" in output, (
        f"failure report missing install log path:\n{output}"
    )


@pytest.mark.parametrize("distro_template", ["ubuntu-22.04"])
def test_idempotent_resume_after_checkpoint(
    distro_template, vm_factory, release_tarball_x86_64, sigstore_stack,
):
    """Re-run after partial failure resumes correctly; final state is complete.

    1. First run aborts after install-binaries.
    2. Recovery run (no fail hook) completes.
    3. Final install-state.json has status=complete.
    4. Applied steps from first run are skipped on recovery run (log check).
    """
    vm = vm_factory(distro_template)
    tarball_in_vm = copy_tarball_to_vm(vm, release_tarball_x86_64)

    # Partial first run.
    r1 = vm.shell(
        install_sh_cmd(
            tarball_in_vm,
            vm=vm,
            sigstore_stack=sigstore_stack,
            env={"SANDBOX_INSTALL_PRIV_CHILD_FAIL_AFTER": "install-binaries"},
        ),
        timeout=600,
    )
    assert r1.returncode != 0, (
        f"first run should have failed; got 0:\n{r1.stdout}\n{r1.stderr}"
    )

    # Truncate log to isolate recovery-run output.
    vm.shell("sudo truncate -s 0 /var/log/sandbox-install.log", check=True)

    # Recovery run — no fail hook.
    r2 = vm.shell(
        install_sh_cmd(tarball_in_vm, vm=vm, sigstore_stack=sigstore_stack),
        timeout=600,
    )
    assert r2.returncode == 0, (
        f"recovery run failed:\n{r2.stdout}\n{r2.stderr}"
    )

    # Final state must be complete.
    base_dir = sandbox_base_dir_in_vm(vm)
    state = _read_state(vm, base_dir)
    assert state.get("status") == "complete", (
        f"expected status=complete after recovery; got {state.get('status')!r}"
    )
    assert state.get("last_completed_step") == "write-install-state", (
        f"expected last_completed_step=write-install-state; "
        f"got {state.get('last_completed_step')!r}"
    )

    # Recovery log: sandbox user step should be skip (user already existed).
    log2 = vm.shell(
        "sudo cat /var/log/sandbox-install.log", check=True, timeout=10,
    ).stdout
    actions = parse_install_log_actions(log2)
    assert "useradd" in actions, f"useradd missing from recovery log:\n{log2}"
    assert "skip" in actions["useradd"], (
        f"useradd should skip on recovery; got {actions['useradd']}"
    )

    # Full filesystem post-conditions.
    assert_full_install_landed(vm)
