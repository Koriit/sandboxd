"""macOS happy-path install e2e (Tart guest).

The Darwin analog of ``test_install_happy_path.py``: boots a fresh Tart
macOS guest, ``brew install``s the prerequisites (socket_vmnet + lima +
qemu), copies the locally-built ``aarch64-apple-darwin`` tarball + the
unmodified (freshly-assembled) install.sh in, runs the install path
end-to-end against the local Sigstore stack (reached via the host-side
relay), and asserts the full set of Darwin post-conditions:

* ``_sandboxd`` user + group created at a low (<500) uid/gid via dscl;
* host binaries staged to /usr/local/libexec/sandboxd/ + /usr/local/bin/sandbox;
* socket_vmnet staged root:wheel 0755 at /Library/sandboxd/;
* the 8 ``io.sandboxd.vmnet.<n>`` daemons + slot sockets;
* ``/etc/sandboxd/users.conf`` created;
* the per-operator agent LaunchAgent installed;
* the ``io.sandboxd.daemon`` system daemon plist installed + bootstrapped;
* vmnet socket dir owned ``_sandboxd:_sandboxd`` 0750.

**Daemon-healthy vs. the M1/M2 nested-virt ceiling.** Reaching "healthy"
on macOS means the daemon boots its mandatory gateway QEMU VM
(``-machine virt,accel=hvf``), which needs nested virtualization —
available to a Tart guest only on **M3+** hosts. On M1/M2 the daemon
crash-loops on ``HV_UNSUPPORTED``, so install.sh's step-12 daemon
socket-wait times out and install.sh exits non-zero. That is the EXPECTED
outcome on M1/M2 and is NOT a failure of the install mechanics: this test
asserts install.sh completed steps 1–11 and the daemon was bootstrapped +
ran its startup checks, then stops. On M3+ (``host_supports_nested_virt()``)
the test additionally requires install.sh to exit 0, the daemon socket to
appear, and ``sandbox doctor`` to report green.

macOS-only (Darwin/arm64); the fixtures skip on every other host.
"""

from __future__ import annotations

import json

import pytest

from conftest import (
    assert_doctor_passes_macos,
    copy_tarball_to_tart_vm,
    install_sh_cmd_macos,
    parse_install_log_actions,
)
from tart_harness import host_supports_nested_virt

# Number of vmnet slots install.sh provisions on Darwin (DARWIN_VMNET_SLOTS,
# default 8 → io.sandboxd.vmnet.0 .. io.sandboxd.vmnet.7).
EXPECTED_VMNET_SLOTS = 8

# The 11 install-state checkpoints that must complete before the daemon
# socket-wait (step 12). install.sh's privileged-child step names.
EXPECTED_STEPS_THROUGH_AGENT = [
    "sandbox_group",
    "sandbox_user",
    "install_binary",
    "install_cosign",
    "state_dirs",
    "stage_socket_vmnet",
    "install_vmnet_plists",
    "bootstrap_vmnet_daemons",
    "users_conf",
    "install_agent",
    "install_daemon_plist",
]


@pytest.mark.macos
def test_install_macos_fresh_then_doctor_passes(
    tart_vm_factory, release_tarball_darwin, sigstore_stack, tart_sigstore_relay,
):
    nested = host_supports_nested_virt()

    vm = tart_vm_factory()
    tarball_in_vm = copy_tarball_to_tart_vm(vm, release_tarball_darwin)

    r = vm.shell(
        install_sh_cmd_macos(tarball_in_vm, vm=vm, sigstore_stack=sigstore_stack),
        timeout=1200,
    )

    # Pull the install log for step-level assertions (parsed regardless of the
    # script's exit code — it's the authoritative record of what landed).
    log = vm.shell("sudo cat /var/log/sandbox-install.log", check=True, timeout=15).stdout
    actions = parse_install_log_actions(log)

    if nested:
        # M3+: the full install must succeed, including the daemon reaching a
        # healthy socket.
        assert r.returncode == 0, (
            f"install.sh failed (exit {r.returncode}) on a nested-virt-capable host\n"
            f"stdout:\n{r.stdout}\nstderr:\n{r.stderr}"
        )
    else:
        # M1/M2: install.sh is EXPECTED to exit non-zero, failing precisely at
        # the daemon socket-wait (the daemon cannot boot its gateway QEMU VM
        # without nested virt). Assert that is the ONLY failing step and that
        # everything up to and including the daemon-plist install succeeded.
        assert r.returncode != 0, (
            "expected install.sh to fail at the daemon socket-wait on a host "
            "without nested virtualization, but it exited 0"
        )
        assert "step=install_daemon_plist action=socket-wait-fail" in log, (
            "expected the daemon socket-wait to be the failing step on M1/M2; "
            f"install log:\n{log}"
        )
        # No step before the daemon socket-wait may have failed.
        assert "step=install_binary path=/usr/local/libexec/sandboxd/sandboxd action=fail" not in log
        for step in EXPECTED_STEPS_THROUGH_AGENT:
            ok = any(
                a == "create" or a == "install" or a == "bootstrap-enable" or a == "ready"
                for a in actions.get(step, [])
            )
            assert ok, (
                f"expected install step {step!r} to have completed (status=ok) "
                f"before the daemon socket-wait; actions seen: {actions.get(step)!r}"
            )

    # ---------------- _sandboxd user + group (dscl) ----------------
    user_row = vm.shell("dscl . -read /Users/_sandboxd UniqueID PrimaryGroupID NFSHomeDirectory UserShell")
    assert user_row.returncode == 0, (
        f"_sandboxd user not created via dscl:\n{user_row.stdout}\n{user_row.stderr}"
    )
    uid = int(vm.shell("id -u _sandboxd", check=True).stdout.strip())
    gid = int(vm.shell("id -g _sandboxd", check=True).stdout.strip())
    assert uid < 500, f"_sandboxd uid should be a system uid (<500), got {uid}"
    assert gid < 500, f"_sandboxd gid should be a system gid (<500), got {gid}"
    # Dedicated group, distinct from Apple's _sandbox (gid 60).
    grp = vm.shell("dscl . -read /Groups/_sandboxd PrimaryGroupID", check=True)
    grp_gid = int(grp.stdout.split()[-1])
    assert grp_gid == gid and grp_gid != 60, (
        f"_sandboxd group gid unexpected: group={grp_gid} user-primary={gid}"
    )
    # Daemon user has no login shell.
    assert "/usr/bin/false" in user_row.stdout, (
        f"_sandboxd should have a no-login shell: {user_row.stdout!r}"
    )

    # ---------------- binaries ----------------
    assert vm.shell("test -x /usr/local/libexec/sandboxd/sandboxd").returncode == 0
    assert vm.shell("test -x /usr/local/bin/sandbox").returncode == 0
    assert vm.shell("test -x /usr/local/libexec/sandboxd/sandbox-guest").returncode == 0
    assert vm.shell("test -x /usr/local/libexec/sandboxd/sandbox-agent").returncode == 0

    # ---------------- socket_vmnet staged root-owned ----------------
    svmnet = vm.shell("stat -f '%Su:%Sg %Lp' /Library/sandboxd/socket_vmnet", check=True)
    assert svmnet.stdout.strip().startswith("root:wheel 755"), (
        f"socket_vmnet not staged root:wheel 0755: {svmnet.stdout!r}"
    )

    # ---------------- vmnet pool daemons + slot sockets ----------------
    for slot in range(EXPECTED_VMNET_SLOTS):
        label = f"io.sandboxd.vmnet.{slot}"
        loaded = vm.shell(f"sudo launchctl print system/{label} >/dev/null 2>&1 && echo LOADED")
        assert "LOADED" in loaded.stdout, f"{label} not bootstrapped"
        sock = f"/var/run/sandbox/vmnet/slot-{slot}.sock"
        assert vm.shell(f"sudo test -S {sock} && echo OK").stdout.strip() == "OK", (
            f"vmnet slot socket missing: {sock}"
        )

    # vmnet socket dir owned _sandboxd:_sandboxd 0750.
    dirstat = vm.shell("sudo stat -f '%Su:%Sg %Lp' /var/run/sandbox/vmnet", check=True)
    assert dirstat.stdout.strip() == "_sandboxd:_sandboxd 750", (
        f"/var/run/sandbox/vmnet not _sandboxd:_sandboxd 0750: {dirstat.stdout!r}"
    )

    # ---------------- per-operator vmnet slot group ----------------
    #
    # Every slot socket carries one group today and every operator is enrolled
    # in it, so on a multi-operator host any of them can attach to any other's
    # isolated segment. Enrollment therefore also creates a group scoped to
    # this operator alone and records the slots they own.
    #
    # Asserted against the group the install actually created, via
    # dseditgroup -o checkmember — not by reading the script, and not against
    # Apple's reserved _sandbox (gid 60) or the shared _sandboxd group, neither
    # of which would demonstrate anything about the partition.
    op_group = "_sandboxd-op-admin"
    assert vm.shell(f"dseditgroup -o checkmember -m admin {op_group}").returncode == 0, (
        f"operator 'admin' is not a member of its own slot group {op_group}"
    )
    # The daemon account is in every per-operator group by design: the gateway
    # VM runs as the daemon uid and holds a NIC on every slot, so a daemon
    # outside one operator's group would fail limactl start at the first socket
    # entry and no macOS session of any operator could be created or recovered.
    assert vm.shell(f"dseditgroup -o checkmember -m _sandboxd {op_group}").returncode == 0, (
        f"the daemon account is not a member of {op_group} — every operator's "
        f"sessions break, not only the daemon's own"
    )
    # The per-operator group is a SECOND group. The shared one gates the daemon
    # socket and owns the 0750 socket directory, so operators stay in it.
    assert vm.shell("dseditgroup -o checkmember -m admin _sandboxd").returncode == 0, (
        "operator 'admin' was moved out of the shared _sandboxd group; it is the "
        "daemon-socket enrollment gate and the socket directory's owner"
    )
    assert vm.shell("dseditgroup -o checkmember -m admin _sandbox").returncode != 0, (
        "operator 'admin' was enrolled in Apple's reserved _sandbox group (gid 60)"
    )
    # A single-operator install keeps the whole pool — partitioning a pool
    # nobody else uses would be a straight concurrency regression.
    slots = vm.shell(f"dscl . -read /Groups/{op_group} SandboxdSlots", check=True).stdout
    assert slots.strip().endswith(f"0-{EXPECTED_VMNET_SLOTS - 1}"), (
        f"expected the single operator to hold the whole pool, got: {slots!r}"
    )
    # Enforcement is not this phase's: the sockets keep the shared group until
    # VM ownership moves, because until then the daemon's own gateway VM has to
    # keep opening every slot.
    for slot in range(EXPECTED_VMNET_SLOTS):
        sock_grp = vm.shell(
            f"sudo stat -f '%Sg' /var/run/sandbox/vmnet/slot-{slot}.sock", check=True
        ).stdout.strip()
        assert sock_grp == "_sandboxd", (
            f"slot-{slot}.sock moved onto {sock_grp!r}; the socket group must stay "
            f"shared until the gateway VM is operator-owned"
        )

    # ---------------- users.conf created ----------------
    assert vm.shell("sudo test -f /etc/sandboxd/users.conf && echo OK").stdout.strip() == "OK", (
        "/etc/sandboxd/users.conf not created on the Darwin path"
    )
    users_conf = vm.shell("sudo cat /etc/sandboxd/users.conf", check=True).stdout
    uc = json.loads(users_conf)
    assert uc.get("_schema_version") == 1, f"users.conf _schema_version != 1: {uc!r}"
    # The macOS daemon user (_sandboxd) must be in the allow list.
    allow = uc["subnets"][0]["allow_users"]
    assert "_sandboxd" in allow, f"users.conf allow_users missing _sandboxd: {allow!r}"

    # ---------------- per-operator agent LaunchAgent ----------------
    assert vm.shell("test -f /Library/LaunchAgents/io.sandboxd.agent.plist").returncode == 0, (
        "io.sandboxd.agent LaunchAgent plist not installed"
    )

    # ---------------- system daemon bootstrapped ----------------
    daemon_loaded = vm.shell("sudo launchctl print system/io.sandboxd.daemon >/dev/null 2>&1 && echo LOADED")
    assert "LOADED" in daemon_loaded.stdout, "io.sandboxd.daemon not bootstrapped"

    # ---------------- daemon-healthy contract (M3+ only) ----------------
    # The daemon socket + status=complete install-state + doctor-green all
    # require the gateway QEMU VM to have booted (nested virt; M3+ only). On
    # M1/M2 the install mechanics above are fully asserted; the remaining
    # daemon-healthy contract is deferred to an M3+ host.
    if not nested:
        pytest.skip(
            "daemon-healthy assertions require nested virtualization (M3+) for "
            "the gateway QEMU VM; this host (M1/M2) cannot boot it. install.sh "
            "completed steps 1-11 + bootstrapped the daemon (asserted above)."
        )

    base_dir = f"/var/lib/sandboxd/{uid}"
    state_path = f"{base_dir}/.install-state.json"
    state = json.loads(vm.shell(f"sudo cat {state_path}", check=True).stdout)
    assert state.get("status") == "complete", f"install-state not complete: {state!r}"
    assert state.get("installed_version"), f"install-state missing installed_version: {state!r}"

    assert vm.shell("sudo test -S /var/run/sandbox/sandboxd.sock && echo OK").stdout.strip() == "OK", (
        "daemon socket /var/run/sandbox/sandboxd.sock missing"
    )

    # ---------------- doctor green ----------------
    assert_doctor_passes_macos(vm)
