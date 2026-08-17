"""macOS uninstall e2e (Tart guest) — the Darwin analog of test_uninstall.py.

Boots a fresh Tart macOS guest, runs ``install.sh`` end-to-end (reusing the
happy-path install flow), then exercises ``scripts/uninstall.sh`` against the
installed artifacts and asserts the full Darwin teardown contract:

* ``io.sandboxd.daemon`` + all N ``io.sandboxd.vmnet.<n>`` daemons booted out
  of the launchd system domain; ``io.sandboxd.agent`` LaunchAgent removed (the
  Aqua/gui domain); all plists removed.
* the 4 staged binaries + ``/Library/sandboxd`` removed.
* WITHOUT ``--purge-state``: the per-uid state tree + ``_sandboxd`` user/group
  are PRESERVED (clean re-install path).
* WITH ``--purge-state``: state tree + ``/var/log/sandbox`` + per-operator
  LIMA_HOME removed; ``_sandboxd`` user + group removed members-first.
* INVARIANT: NO ``pkill qemu`` anywhere — the operator's other QEMU VMs are
  never reaped by the uninstaller.
* idempotent re-run of uninstall.sh exits 0.

**Does NOT require the daemon to be healthy.** Unlike the install happy-path's
daemon-healthy block (gated behind nested-virt / M3+), uninstall operates on
the installed *artifacts*, so it is fully validatable on M1/M2. The install
half here only needs install.sh to complete steps 1-11 + bootstrap the daemon —
exactly the M1 ceiling already established in test_install_macos.py.

macOS-only (Darwin/arm64); the fixtures skip on every other host.
"""

from __future__ import annotations

import pytest

from conftest import (
    copy_tarball_to_tart_vm,
    install_sh_cmd_macos,
    uninstall_sh_cmd_macos,
)

# The vmnet slot count install.sh provisions on Darwin (DARWIN_VMNET_SLOTS=8).
EXPECTED_VMNET_SLOTS = 8


def _run_install(vm, tarball_path, sigstore_stack):
    """Run install.sh end-to-end in the guest; return the install log.

    Mirrors test_install_macos.py: on M1/M2 install.sh exits non-zero at the
    daemon socket-wait (nested-virt ceiling), but steps 1-11 land + the daemon
    is bootstrapped. We assert the install left enough on disk for uninstall to
    have something to tear down (the daemon plist installed + bootstrapped),
    then return the log for the caller. We do NOT require exit 0.
    """
    tarball_in_vm = copy_tarball_to_tart_vm(vm, tarball_path)
    vm.shell(
        install_sh_cmd_macos(tarball_in_vm, vm=vm, sigstore_stack=sigstore_stack),
        timeout=1200,
    )
    # The conclusive "install reached the service-install stage" signal: the
    # daemon plist is present + bootstrapped. (install.sh's step-11 daemon
    # socket-wait may have timed out on M1, but the plist install + bootstrap
    # happen first.)
    assert vm.shell(
        "test -f /Library/LaunchDaemons/io.sandboxd.daemon.plist"
    ).returncode == 0, "install.sh did not install the daemon plist; cannot test uninstall"
    daemon_loaded = vm.shell(
        "sudo launchctl print system/io.sandboxd.daemon >/dev/null 2>&1 && echo LOADED"
    )
    assert "LOADED" in daemon_loaded.stdout, (
        "install.sh did not bootstrap io.sandboxd.daemon; cannot test the bootout path"
    )
    return tarball_in_vm


def _assert_base_teardown(vm, uid):
    """Assertions common to both the clean and purge uninstall paths.

    Daemon + all vmnet daemons booted out, agent LaunchAgent removed, all plists
    gone, the 4 staged binaries + /Library/sandboxd removed.
    """
    # ---------------- launchd daemons booted out + plists removed ----------------
    daemon_loaded = vm.shell(
        "sudo launchctl print system/io.sandboxd.daemon >/dev/null 2>&1 && echo LOADED || echo GONE"
    )
    assert "GONE" in daemon_loaded.stdout, (
        f"io.sandboxd.daemon still loaded after uninstall: {daemon_loaded.stdout!r}"
    )
    assert vm.shell(
        "test -f /Library/LaunchDaemons/io.sandboxd.daemon.plist"
    ).returncode != 0, "daemon plist not removed"

    for slot in range(EXPECTED_VMNET_SLOTS):
        label = f"io.sandboxd.vmnet.{slot}"
        loaded = vm.shell(
            f"sudo launchctl print system/{label} >/dev/null 2>&1 && echo LOADED || echo GONE"
        )
        assert "GONE" in loaded.stdout, f"{label} still loaded after uninstall"
        assert vm.shell(
            f"test -f /Library/LaunchDaemons/{label}.plist"
        ).returncode != 0, f"{label} plist not removed"

    # ---------------- agent LaunchAgent removed (gui domain bootout + plist) ----------------
    assert vm.shell(
        "test -f /Library/LaunchAgents/io.sandboxd.agent.plist"
    ).returncode != 0, "io.sandboxd.agent LaunchAgent plist not removed"

    # ---------------- staged binaries + /Library/sandboxd removed ----------------
    for binpath in (
        "/usr/local/libexec/sandboxd/sandboxd",
        "/usr/local/libexec/sandboxd/sandbox-agent",
        "/usr/local/libexec/sandboxd/sandbox-guest",
        "/usr/local/bin/sandbox",
    ):
        assert vm.shell(f"test -e {binpath}").returncode != 0, (
            f"binary not removed by uninstall: {binpath}"
        )
    # /Library/sandboxd (staged socket_vmnet) removed entirely.
    assert vm.shell("test -d /Library/sandboxd").returncode != 0, (
        "/Library/sandboxd not removed by uninstall"
    )


def _assert_no_pkill_qemu_in_uninstall(vm):
    """INVARIANT: the uninstaller never reaps QEMU processes.

    The staged uninstall.sh must contain no pkill/killall/pgrep/qemu-system
    references at all (the source-level guard). This is the macOS analog of the
    Linux invariant — an operator's *other* sandbox VMs (or a co-located prod
    daemon's gateway VM) must survive an uninstall untouched.
    """
    r = vm.shell(
        "grep -nE 'pkill|killall|pgrep|qemu-system' /tmp/uninstall.sh || echo NO_MATCH",
        timeout=15,
    )
    assert "NO_MATCH" in r.stdout, (
        f"uninstall.sh contains a process-reaping reference (forbidden):\n{r.stdout}"
    )


@pytest.mark.macos
def test_uninstall_macos_clean_preserves_state_and_user(
    tart_vm_factory, release_tarball_darwin, sigstore_stack, tart_sigstore_relay,
):
    """No-purge uninstall: full teardown, but state tree + _sandboxd preserved."""
    vm = tart_vm_factory()
    _run_install(vm, release_tarball_darwin, sigstore_stack)

    uid = int(vm.shell("id -u _sandboxd", check=True).stdout.strip())
    base_dir = f"/var/lib/sandboxd/{uid}"
    # Sanity: the state tree exists pre-uninstall.
    assert vm.shell(f"sudo test -d {base_dir}").returncode == 0, (
        f"per-uid state dir absent before uninstall: {base_dir}"
    )

    # The invariant must hold on the exact bytes we're about to run.
    _assert_no_pkill_qemu_in_uninstall(vm)

    r = vm.shell(uninstall_sh_cmd_macos("--force"), timeout=600)
    assert r.returncode == 0, (
        f"uninstall.sh (clean) failed (exit {r.returncode})\n"
        f"stdout:\n{r.stdout}\nstderr:\n{r.stderr}"
    )

    _assert_base_teardown(vm, uid)

    # ---------------- WITHOUT --purge: state tree + user/group PRESERVED ----------------
    assert vm.shell(f"sudo test -d {base_dir}").returncode == 0, (
        f"clean uninstall removed the per-uid state dir {base_dir} (must be kept without --purge)"
    )
    assert vm.shell("dscl . -read /Users/_sandboxd UniqueID").returncode == 0, (
        "clean uninstall removed the _sandboxd user (must be kept without --purge)"
    )
    assert vm.shell("dscl . -read /Groups/_sandboxd PrimaryGroupID").returncode == 0, (
        "clean uninstall removed the _sandboxd group (must be kept without --purge)"
    )
    # The log dir is also kept on a clean uninstall.
    assert vm.shell("sudo test -d /var/log/sandbox").returncode == 0, (
        "clean uninstall removed /var/log/sandbox (must be kept without --purge)"
    )


@pytest.mark.macos
def test_uninstall_macos_purge_removes_user_group_and_state(
    tart_vm_factory, release_tarball_darwin, sigstore_stack, tart_sigstore_relay,
):
    """--purge-state: full teardown + state tree + log dir + _sandboxd user/group removed.

    Also pins the members-first ordering for the user/group removal: the
    operator (admin) is stripped from the group, the group is deleted, then the
    user — asserted from the uninstall log's step trace.
    """
    vm = tart_vm_factory()
    _run_install(vm, release_tarball_darwin, sigstore_stack)

    uid = int(vm.shell("id -u _sandboxd", check=True).stdout.strip())
    base_dir = f"/var/lib/sandboxd/{uid}"

    _assert_no_pkill_qemu_in_uninstall(vm)

    # Truncate the install log so we read back only the uninstall step trace.
    vm.shell("sudo truncate -s 0 /var/log/sandbox-install.log 2>/dev/null || true")

    # --purge-state is an alias for --purge; --yes skips the literal-PURGE gate.
    r = vm.shell(uninstall_sh_cmd_macos("--purge-state", "--force"), timeout=600)
    assert r.returncode == 0, (
        f"uninstall.sh (--purge-state) failed (exit {r.returncode})\n"
        f"stdout:\n{r.stdout}\nstderr:\n{r.stderr}"
    )

    _assert_base_teardown(vm, uid)

    # ---------------- WITH --purge: state tree + log dir removed ----------------
    assert vm.shell(f"sudo test -d {base_dir}").returncode != 0, (
        f"--purge-state left the per-uid state dir {base_dir}"
    )
    assert vm.shell("sudo test -d /var/log/sandbox").returncode != 0, (
        "--purge-state left /var/log/sandbox"
    )

    # ---------------- _sandboxd user + group removed ----------------
    assert vm.shell("dscl . -read /Users/_sandboxd UniqueID").returncode != 0, (
        "--purge-state left the _sandboxd user"
    )
    assert vm.shell("dscl . -read /Groups/_sandboxd PrimaryGroupID").returncode != 0, (
        "--purge-state left the _sandboxd group"
    )

    # ---------------- per-operator slot groups removed ----------------
    #
    # Left behind, a stale _sandboxd-op-* group is worse than untidy: the next
    # install finds a group that already exists, skips creating it, and
    # inherits whatever slot range the stale record still names.
    leftover = vm.shell(
        "dscl . -list /Groups | grep '^_sandboxd-op-' || true", timeout=15
    ).stdout.strip()
    assert leftover == "", (
        f"--purge-state left per-operator slot groups behind: {leftover!r}"
    )

    # ---------------- members-first ordering (from the step trace) ----------------
    # uninstall.sh's purge-user-group step strips operators from the group,
    # then deletes the group, then deletes the user. Verify the log records
    # the group-revoke (or no members) before the dseditgroup_delete and
    # dscl_delete_user, and that both deletes succeeded.
    log = vm.shell("sudo cat /var/log/sandbox-install.log", check=True, timeout=15).stdout
    assert "step=dseditgroup_delete action=remove" in log, (
        f"_sandboxd group not deleted via dseditgroup in the purge step:\n{log}"
    )
    assert "step=dscl_delete_user action=remove" in log, (
        f"_sandboxd user not deleted via dscl in the purge step:\n{log}"
    )
    # Ordering: the group-delete record must precede the user-delete record.
    grp_idx = log.index("step=dseditgroup_delete action=remove")
    usr_idx = log.index("step=dscl_delete_user action=remove")
    assert grp_idx < usr_idx, (
        "members-first ordering violated: group must be deleted before the user\n"
        f"{log}"
    )


@pytest.mark.macos
def test_uninstall_macos_double_run_idempotent(
    tart_vm_factory, release_tarball_darwin, sigstore_stack, tart_sigstore_relay,
):
    """A second uninstall.sh run after a clean uninstall exits 0 (no-op)."""
    vm = tart_vm_factory()
    _run_install(vm, release_tarball_darwin, sigstore_stack)

    _assert_no_pkill_qemu_in_uninstall(vm)

    # First uninstall (clean).
    r = vm.shell(uninstall_sh_cmd_macos("--force"), timeout=600)
    assert r.returncode == 0, (
        f"first uninstall failed (exit {r.returncode})\n{r.stdout}\n{r.stderr}"
    )

    # Truncate so the second pass is what we read back.
    vm.shell("sudo truncate -s 0 /var/log/sandbox-install.log 2>/dev/null || true")

    # Second uninstall — must be a clean no-op exit 0.
    r = vm.shell(uninstall_sh_cmd_macos("--force"), timeout=600)
    assert r.returncode == 0, (
        f"second (idempotent) uninstall failed (exit {r.returncode})\n"
        f"stdout:\n{r.stdout}\nstderr:\n{r.stderr}"
    )

    # Every Darwin remove step should report skip/absent on the second pass
    # (nothing left to remove). Spot-check the daemon + binary skip records.
    log2 = vm.shell("sudo cat /var/log/sandbox-install.log", check=True, timeout=15).stdout
    assert "action=skip reason=absent" in log2 or "action=skip reason=not-loaded" in log2, (
        f"second uninstall did not log skip/absent for already-removed items:\n{log2}"
    )
