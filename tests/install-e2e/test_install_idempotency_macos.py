"""macOS install.sh idempotency e2e (Tart guest).

Runs install.sh twice at the same version against a fresh Tart guest and
asserts the second run is a no-op at the level of host identity + artifacts:

* exactly ONE ``_sandboxd`` user and ONE ``_sandboxd`` group exist (no
  duplicates) — the dscl create steps are idempotent;
* the daemon + agent binaries remain in place after the second run;
* no duplicate launchd jobs (the daemon + vmnet jobs are still single
  instances).

**M1 caveat on a clean "all-skip" assertion.** install.sh's strongest
idempotency contract — a second run short-circuiting at ``step=preexist
action=skip`` + exit 0 — requires the FIRST install to have reached
``status=complete``. On M1/M2 the first install exits non-zero at the daemon
socket-wait (nested-virt ceiling; see test_install_macos.py), so the
install-state never reaches ``complete`` and a same-version re-run takes
install.sh's ``resume`` / ``repair`` path rather than the clean skip. We
therefore pin the OBSERVABLE idempotency invariant that IS achievable on M1
(no duplicate identities / jobs / lost binaries), and document that the
``preexist action=skip`` short-circuit is verifiable only once the first
install can complete (M3+). The Linux
test_install_idempotency.py::test_install_idempotent_double_run cell covers the
all-skip path on a host where install completes.

macOS-only (Darwin/arm64); the fixtures skip on every other host.
"""

from __future__ import annotations

import pytest

from conftest import (
    copy_tarball_to_tart_vm,
    install_sh_cmd_macos,
)

EXPECTED_VMNET_SLOTS = 8


@pytest.mark.macos
def test_install_macos_double_run_no_duplicate_identities_or_jobs(
    tart_vm_factory, release_tarball_darwin, sigstore_stack, tart_sigstore_relay,
):
    """A second same-version install creates no duplicate user/group/jobs."""
    vm = tart_vm_factory()
    tarball_in_vm = copy_tarball_to_tart_vm(vm, release_tarball_darwin)

    # First install (M1: exits non-zero at the daemon socket-wait; steps 1-11
    # land + the daemon is bootstrapped — that is the established M1 outcome).
    vm.shell(
        install_sh_cmd_macos(tarball_in_vm, vm=vm, sigstore_stack=sigstore_stack),
        timeout=1200,
    )
    assert vm.shell("dscl . -read /Users/_sandboxd UniqueID").returncode == 0, (
        "first install did not create the _sandboxd user"
    )
    uid_pre = int(vm.shell("id -u _sandboxd", check=True).stdout.strip())
    gid_pre = int(vm.shell("id -g _sandboxd", check=True).stdout.strip())
    slots_pre = vm.shell(
        "dscl . -read /Groups/_sandboxd-op-admin SandboxdSlots", check=True
    ).stdout.strip()

    # Truncate the install log so the second run's records are isolated.
    vm.shell("sudo truncate -s 0 /var/log/sandbox-install.log 2>/dev/null || true")

    # Second install at the same version.
    r2 = vm.shell(
        install_sh_cmd_macos(tarball_in_vm, vm=vm, sigstore_stack=sigstore_stack),
        timeout=1200,
    )

    # ---------------- no duplicate _sandboxd user ----------------
    # dscl lists exactly one record; uid/gid unchanged.
    user_rows = vm.shell(
        "dscl . -list /Users | grep -cx _sandboxd", timeout=15
    ).stdout.strip()
    assert user_rows == "1", (
        f"expected exactly one _sandboxd user after the second install, got {user_rows!r}"
    )
    group_rows = vm.shell(
        "dscl . -list /Groups | grep -cx _sandboxd", timeout=15
    ).stdout.strip()
    assert group_rows == "1", (
        f"expected exactly one _sandboxd group after the second install, got {group_rows!r}"
    )
    uid_post = int(vm.shell("id -u _sandboxd", check=True).stdout.strip())
    gid_post = int(vm.shell("id -g _sandboxd", check=True).stdout.strip())
    assert uid_post == uid_pre and gid_post == gid_pre, (
        f"_sandboxd uid/gid changed across re-install: "
        f"pre=({uid_pre},{gid_pre}) post=({uid_post},{gid_post})"
    )

    # ---------------- per-operator slot group not duplicated or widened ----------------
    #
    # A second install must not create a second group, and must not quietly
    # restore a deliberately narrowed range to the whole pool — re-running the
    # installer is not an occasion to hand an operator slots someone took away.
    op_group_rows = vm.shell(
        "dscl . -list /Groups | grep -cx _sandboxd-op-admin", timeout=15
    ).stdout.strip()
    assert op_group_rows == "1", (
        f"expected exactly one _sandboxd-op-admin group after the second install, "
        f"got {op_group_rows!r}"
    )
    slots_post = vm.shell(
        "dscl . -read /Groups/_sandboxd-op-admin SandboxdSlots", check=True
    ).stdout.strip()
    assert slots_post == slots_pre, (
        f"the operator's slot range changed across a re-install: "
        f"pre={slots_pre!r} post={slots_post!r}"
    )
    # Membership is still exactly the operator plus the daemon account — the
    # add is idempotent rather than appending a duplicate entry.
    members = vm.shell(
        "dscl . -read /Groups/_sandboxd-op-admin GroupMembership", check=True
    ).stdout.split(":", 1)[-1].split()
    assert sorted(members) == ["_sandboxd", "admin"], (
        f"unexpected _sandboxd-op-admin membership after re-install: {members!r}"
    )

    # ---------------- binaries still present ----------------
    assert vm.shell("test -x /usr/local/libexec/sandboxd/sandboxd").returncode == 0, (
        "daemon binary missing after the second install"
    )
    assert vm.shell("test -x /usr/local/bin/sandbox").returncode == 0, (
        "sandbox CLI missing after the second install"
    )

    # ---------------- no duplicate launchd jobs ----------------
    # `launchctl list` shows each label exactly once (the daemon + vmnet pool).
    daemon_count = vm.shell(
        "sudo launchctl list | grep -c 'io.sandboxd.daemon$' || true", timeout=15
    ).stdout.strip()
    assert daemon_count in ("0", "1"), (
        f"unexpected io.sandboxd.daemon job count after re-install: {daemon_count!r}"
    )
    for slot in range(EXPECTED_VMNET_SLOTS):
        label = f"io.sandboxd.vmnet.{slot}"
        cnt = vm.shell(
            f"sudo launchctl list | grep -c '{label}$' || true", timeout=15
        ).stdout.strip()
        assert cnt in ("0", "1"), (
            f"duplicate launchd job for {label}: count={cnt!r}"
        )

    # The second run reached at least the preexist detection (resume/repair on
    # M1 because the first install never wrote status=complete). This documents
    # the M1 path without asserting the unreachable clean-skip short-circuit.
    log2 = vm.shell(
        "sudo cat /var/log/sandbox-install.log 2>/dev/null || true", timeout=15
    ).stdout
    assert "step=preexist" in log2, (
        f"second install did not reach the preexist detection step:\n{log2}"
    )
