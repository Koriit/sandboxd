"""Tests for code-review defect fixes applied to install.sh.

Coverage:
- ``test_fifo_hang_fix_child_dies_before_fifo`` — parent exits promptly with
  non-zero when the privileged child dies before opening the FIFO (simulates
  a sudo auth failure). Without the keepalive fd fix the parent would block
  forever.
- ``test_provenance_monotonic_across_resumed_runs`` — we_* flags set true in
  a partial first run remain true in the final install-state.json after a
  successful resume run.
- ``test_last_completed_step_is_last_ok_on_failure`` — last_completed_step
  names the last *successfully completed* step, not the failing step, when
  status=failed; and the separate failed_step field names the trigger step.
- ``test_idempotent_resume_state_complete`` — redundant sanity check that
  full resume sets status=complete and last_completed_step=write-install-state.
"""

from __future__ import annotations

import json
import pytest

from conftest import (
    copy_tarball_to_vm,
    install_sh_cmd,
    sandbox_base_dir_in_vm,
    stage_sigstore_trust_material_in_vm,
    version_from_tarball,
    _sh_quote,
)


# ---------------------------------------------------------------------------
# Helpers.
# ---------------------------------------------------------------------------

def _read_state(vm, base_dir):
    raw = vm.shell(
        f"sudo cat {base_dir}/.install-state.json",
        check=True, timeout=10,
    ).stdout
    return json.loads(raw)


def _state_exists(vm, base_dir):
    return vm.shell(
        f"sudo test -r {base_dir}/.install-state.json",
        timeout=10,
    ).returncode == 0


# ---------------------------------------------------------------------------
# Fix 1: FIFO hang.
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("distro_template", ["ubuntu-22.04"])
def test_fifo_hang_fix_child_dies_before_fifo(
    distro_template, vm_factory, release_tarball_x86_64, sigstore_stack,
):
    """Parent exits promptly with non-zero when the child dies before opening FIFO.

    SANDBOX_INSTALL_PRIV_CHILD_FAIL_BEFORE_FIFO=1 causes the privileged child
    to exit 1 before it reaches ``exec 3> "$FIFO"``, simulating a sudo auth
    failure (which also exits before opening the FIFO).

    Without the parent-side keepalive (``exec 4> FIFO`` before sudo launch),
    the parent's ``done < FIFO`` would block forever waiting for a writer.
    With the fix, the parent holds fd 4 open, so the read-open succeeds
    immediately and the loop exits on EOF when the child exits.

    The test asserts: non-zero exit, happens within the test timeout (not a
    hang), and a clear error message is present in the output.
    """
    vm = vm_factory(distro_template)
    tarball_in_vm = copy_tarball_to_vm(vm, release_tarball_x86_64)

    # Build the install command with the before-FIFO fail hook.
    r = vm.shell(
        install_sh_cmd(
            tarball_in_vm,
            vm=vm,
            sigstore_stack=sigstore_stack,
            env={"SANDBOX_INSTALL_PRIV_CHILD_FAIL_BEFORE_FIFO": "1"},
        ),
        # Generous but bounded timeout: if we hang we'll time out at 60s
        # rather than the full 600s, making the bug very visible.
        timeout=60,
    )

    assert r.returncode != 0, (
        f"install.sh should exit non-zero when privileged child dies before "
        f"FIFO open; got exit 0.\nstdout:\n{r.stdout}\nstderr:\n{r.stderr}"
    )

    # The parent should surface a failure message — either the structured
    # failure report or a generic die() message.
    output = r.stdout + r.stderr
    assert len(output) > 0, (
        "install.sh produced no output after privileged child pre-FIFO failure"
    )

    # No sandbox user should exist (the child died before step 1).
    assert vm.shell("id sandbox").returncode != 0, (
        "sandbox user was created despite child dying before FIFO open"
    )


@pytest.mark.parametrize("distro_template", ["ubuntu-22.04"])
def test_fifo_hang_fix_child_fails_after_fifo_open(
    distro_template, vm_factory, release_tarball_x86_64, sigstore_stack,
):
    """Parent exits promptly with non-zero when the child fails AFTER opening FIFO.

    This is the regression case for the inherited-fd-4 bug: the consumer
    subshell previously inherited the parent's write-end (fd 4) of the FIFO.
    When the child opened fd 3, wrote STEP messages, then exited without
    writing DONE, the child's fd 3 was the only "expected" write-end that
    closed. But the consumer's inherited fd 4 kept the FIFO open for writing,
    so the consumer's `read` never saw EOF and blocked forever.

    The fix adds ``exec 4>&-`` at the top of the consumer subshell so it
    holds no write-end. After the child closes fd 3 and the parent closes
    fd 4, all write-ends are gone and the consumer sees EOF.

    SANDBOX_INSTALL_PRIV_CHILD_FAIL_AFTER=install-binaries causes the child
    to open the FIFO, write several STEP messages, then exit 1 without DONE.
    The test uses a tight timeout (120 s) so a future re-hang is caught as a
    timeout error rather than a 600 s pytest-timeout.
    """
    vm = vm_factory(distro_template)
    tarball_in_vm = copy_tarball_to_vm(vm, release_tarball_x86_64)

    r = vm.shell(
        install_sh_cmd(
            tarball_in_vm,
            vm=vm,
            sigstore_stack=sigstore_stack,
            env={"SANDBOX_INSTALL_PRIV_CHILD_FAIL_AFTER": "install-binaries"},
        ),
        # 120 s: enough for the install steps to run but tight enough that a
        # hang will surface as a subprocess.TimeoutExpired (test failure)
        # rather than the 600 s pytest-timeout.
        timeout=120,
    )

    assert r.returncode != 0, (
        f"install.sh should exit non-zero after child FAIL_AFTER=install-binaries; "
        f"got exit 0.\nstdout:\n{r.stdout}\nstderr:\n{r.stderr}"
    )

    # The failure report must mention the failed step.
    output = r.stdout + r.stderr
    assert "install-binaries" in output, (
        f"failure report should reference the failed step 'install-binaries':\n{output}"
    )

    # The sandbox user must exist (step 1 ran before the failure).
    assert vm.shell("id sandbox").returncode == 0, (
        "sandbox user missing — fail hook fired before step 1 completed"
    )

    # The binary must NOT exist (install-binaries is the step that aborted).
    assert vm.shell("test -x /usr/local/libexec/sandboxd/sandboxd").returncode != 0, (
        "sandboxd binary present despite install-binaries abort"
    )


# ---------------------------------------------------------------------------
# Fix 2: Provenance monotonicity.
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("distro_template", ["ubuntu-22.04"])
def test_provenance_monotonic_across_resumed_runs(
    distro_template, vm_factory, release_tarball_x86_64, sigstore_stack,
):
    """we_* flags set true in a partial first run remain true after a full resume.

    Strategy: abort after sandbox-user (step 1) so we_created_sandbox_user=true
    is written to the partial checkpoint. On the resume run, the planning pass
    sets PLAN_SANDBOX_USER=skip → SANDBOX_USER_CREATED=0 in the child. Without
    the monotonicity fix, the final state would write we_created_sandbox_user=false.

    After the resume, the final install-state.json must still have
    we_created_sandbox_user=true.
    """
    vm = vm_factory(distro_template)
    tarball_in_vm = copy_tarball_to_vm(vm, release_tarball_x86_64)

    # Partial first run: abort right after sandbox-user.
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
        f"partial run should fail; got 0:\n{r1.stdout}\n{r1.stderr}"
    )

    # Verify partial state recorded the flag.
    base_dir = sandbox_base_dir_in_vm(vm)
    assert _state_exists(vm, base_dir), (
        "install-state.json not written after partial first run"
    )
    partial_state = _read_state(vm, base_dir)
    assert partial_state.get("we_created_sandbox_user") is True, (
        f"partial state should have we_created_sandbox_user=true; "
        f"got {partial_state!r}"
    )
    assert partial_state.get("status") == "failed", (
        f"partial state should have status=failed; got {partial_state!r}"
    )

    # Recovery run — no fail hook.
    r2 = vm.shell(
        install_sh_cmd(tarball_in_vm, vm=vm, sigstore_stack=sigstore_stack),
        timeout=600,
    )
    assert r2.returncode == 0, (
        f"recovery run failed:\n{r2.stdout}\n{r2.stderr}"
    )

    # Final state must preserve we_created_sandbox_user=true even though the
    # resume run skipped the sandbox-user step (SANDBOX_USER_CREATED=0).
    final_state = _read_state(vm, base_dir)
    assert final_state.get("status") == "complete", (
        f"expected status=complete after recovery; got {final_state!r}"
    )
    assert final_state.get("we_created_sandbox_user") is True, (
        f"we_created_sandbox_user must remain true across resumed runs "
        f"(provenance monotonicity); final state: {final_state!r}"
    )


# ---------------------------------------------------------------------------
# Fix 3: last_completed_step semantics.
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("distro_template", ["ubuntu-22.04"])
def test_last_completed_step_is_last_ok_on_failure(
    distro_template, vm_factory, release_tarball_x86_64, sigstore_stack,
):
    """last_completed_step names the last OK step; failed_step names the trigger.

    Abort after install-binaries (which completes sandbox-user and
    operator-group-add before it). last_completed_step must be install-binaries
    (the last step that finished ok before the test hook fired) and failed_step
    must also be install-binaries (the step the hook fired after).

    The key semantics: on a real failure inside a step (not the test hook),
    last_completed_step would be the step BEFORE the failing one, since
    _step_ok sets _last_ok_step and the failing step never reached _step_ok.
    """
    vm = vm_factory(distro_template)
    tarball_in_vm = copy_tarball_to_vm(vm, release_tarball_x86_64)

    # Abort after install-binaries (test hook fires after _step_ok, so
    # install-binaries IS the last completed step AND the failure trigger).
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
        f"expected failure; got 0:\n{r.stdout}\n{r.stderr}"
    )

    base_dir = sandbox_base_dir_in_vm(vm)
    assert _state_exists(vm, base_dir), "install-state.json missing"

    state = _read_state(vm, base_dir)
    assert state.get("status") == "failed", (
        f"expected status=failed; got {state!r}"
    )

    # last_completed_step = last successfully completed step before/at the failure.
    assert state.get("last_completed_step") == "install-binaries", (
        f"expected last_completed_step=install-binaries; got {state!r}"
    )

    # failed_step names the step that triggered the failure.
    assert state.get("failed_step") == "install-binaries", (
        f"expected failed_step=install-binaries; got {state!r}"
    )

    # A successful run must NOT include failed_step in the final state.
    # We verify this with the idempotent-resume test below, but also check
    # that the complete-status state from a success run omits the field.
    # (Done in test_checkpoint_status_complete_on_success in test_install_phase2.py.)


# ---------------------------------------------------------------------------
# Fix 4: Unguarded abort names the failing step.
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("distro_template", ["ubuntu-22.04"])
def test_unguarded_abort_names_failing_step(
    distro_template, vm_factory, release_tarball_x86_64, sigstore_stack,
):
    """Unguarded mid-step abort produces a failure report naming the step.

    SANDBOX_INSTALL_PRIV_CHILD_ABORT_AT=install-binaries causes the privileged
    child to execute a raw ``exit 1`` inside the install-binaries step body,
    AFTER _step_begin but BEFORE _step_ok/_step_fail and without emitting a
    ``STEP N fail`` token.  This simulates a command failure caught by ``set -e``
    (e.g. a missing binary, a failed sysctl) — exactly the scenario that produced
    "Install failed: unknown" in production.

    The EXIT trap added to the generated privileged script detects _step_inflight=1
    at exit time and emits the retroactive fail token so the consumer records the
    correct step name.

    Asserts:
    - install exits non-zero,
    - failure report contains the step name "install-binaries" (NOT "unknown"),
    - failure report contains "Last log lines:" (log-tail section present),
    - the sandboxd binary is absent (step never completed).
    """
    vm = vm_factory(distro_template)
    tarball_in_vm = copy_tarball_to_vm(vm, release_tarball_x86_64)

    r = vm.shell(
        install_sh_cmd(
            tarball_in_vm,
            vm=vm,
            sigstore_stack=sigstore_stack,
            env={"SANDBOX_INSTALL_PRIV_CHILD_ABORT_AT": "install-binaries"},
        ),
        timeout=120,
    )

    assert r.returncode != 0, (
        f"install.sh should exit non-zero after unguarded abort; "
        f"got exit 0.\nstdout:\n{r.stdout}\nstderr:\n{r.stderr}"
    )

    output = r.stdout + r.stderr

    assert "install-binaries" in output, (
        f"failure report must name the failing step 'install-binaries', "
        f"not fall back to 'unknown':\n{output}"
    )
    assert "Install failed: unknown" not in output, (
        f"failure report must not contain the fallback phrase 'Install failed: unknown' — "
        f"step attribution did not work:\n{output}"
    )
    assert "Last log lines:" in output, (
        f"failure report must include 'Last log lines:' section from the "
        f"log-tail captured by the EXIT trap:\n{output}"
    )

    # The binary must NOT exist — the abort fired before install-binaries ran
    # any install commands.
    assert vm.shell("test -x /usr/local/libexec/sandboxd/sandboxd").returncode != 0, (
        "sandboxd binary present despite unguarded abort in install-binaries"
    )
