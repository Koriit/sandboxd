"""macOS happy-path install e2e (Tart guest).

The Darwin analog of ``test_install_happy_path.py``: boots a fresh Tart
macOS guest, ``brew install``s install.sh's hard prereqs (socket_vmnet +
lima), copies the locally-built ``aarch64-apple-darwin`` tarball + the
unmodified install.sh in, runs the install path end-to-end against the
local Sigstore stack (reached via the host-side relay), and asserts the
full set of Darwin post-conditions:

* ``_sandboxd`` user + group created at a low (<500) uid/gid;
* host binaries staged to /usr/local/libexec/sandboxd/ + /usr/local/bin/sandbox;
* socket_vmnet staged root:wheel 0755 at /Library/sandboxd/;
* N ``io.sandboxd.vmnet.<n>`` daemons + the ``io.sandboxd.daemon`` system
  daemon bootstrapped, enabled, and healthy (slot sockets + daemon socket);
* the per-operator agent LaunchAgent installed;
* vmnet slot sockets owned ``_sandboxd:_sandboxd`` 0750;
* ``.install-state.json`` present + well-formed under the per-uid base dir;
* ``sandbox doctor`` reports green.

macOS-only (Darwin/arm64); the fixtures skip on every other host.
"""

from __future__ import annotations

import json

import pytest

from conftest import (
    assert_doctor_passes_macos,
    copy_tarball_to_tart_vm,
    install_sh_cmd_macos,
)
from tart_harness import host_supports_nested_virt

# Number of vmnet slots install.sh provisions on Darwin (DARWIN_VMNET_SLOTS,
# default 8 → io.sandboxd.vmnet.0 .. io.sandboxd.vmnet.7).
EXPECTED_VMNET_SLOTS = 8


@pytest.mark.macos
def test_install_macos_fresh_then_doctor_passes(
    tart_vm_factory, release_tarball_darwin, sigstore_stack, tart_sigstore_relay,
):
    vm = tart_vm_factory()
    tarball_in_vm = copy_tarball_to_tart_vm(vm, release_tarball_darwin)

    r = vm.shell(
        install_sh_cmd_macos(tarball_in_vm, vm=vm, sigstore_stack=sigstore_stack),
        timeout=900,
    )
    assert r.returncode == 0, (
        f"install.sh failed (exit {r.returncode})\n"
        f"stdout:\n{r.stdout}\nstderr:\n{r.stderr}"
    )

    # ---------------- _sandboxd user + group ----------------
    user_row = vm.shell("dscl . -read /Users/_sandboxd UniqueID PrimaryGroupID NFSHomeDirectory UserShell")
    assert user_row.returncode == 0 and "_sandboxd" not in user_row.stderr, (
        f"_sandboxd user not created via dscl:\n{user_row.stdout}\n{user_row.stderr}"
    )
    uid = int(vm.shell("id -u _sandboxd", check=True).stdout.strip())
    gid = int(vm.shell("id -g _sandboxd", check=True).stdout.strip())
    assert uid < 500, f"_sandboxd uid should be a system uid (<500), got {uid}"
    assert gid < 500, f"_sandboxd gid should be a system gid (<500), got {gid}"
    # The dedicated group exists and is distinct from Apple's _sandbox (gid 60).
    grp = vm.shell("dscl . -read /Groups/_sandboxd PrimaryGroupID", check=True)
    grp_gid = int(grp.stdout.split()[-1])
    assert grp_gid == gid and grp_gid != 60, (
        f"_sandboxd group gid unexpected: group={grp_gid} user-primary={gid}"
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

    # ---------------- per-operator agent LaunchAgent ----------------
    assert vm.shell("test -f /Library/LaunchAgents/io.sandboxd.agent.plist").returncode == 0, (
        "io.sandboxd.agent LaunchAgent plist not installed"
    )

    # ---------------- system daemon bootstrapped + healthy ----------------
    daemon_loaded = vm.shell("sudo launchctl print system/io.sandboxd.daemon >/dev/null 2>&1 && echo LOADED")
    assert "LOADED" in daemon_loaded.stdout, "io.sandboxd.daemon not bootstrapped"

    # install-state status=complete + the daemon socket + doctor-green all
    # require the daemon to reach "healthy", which on macOS means its mandatory
    # gateway QEMU VM (accel=hvf) booted. That needs nested virtualization,
    # available only on M3+ Tart hosts (M1/M2 lack it — see the nested-virt
    # ceiling in the M22-S8 findings handoff). Skip the daemon-healthy contract
    # on hosts that cannot satisfy it; the install-completed + filesystem +
    # launchd-loaded contract above still ran in full.
    if not host_supports_nested_virt():
        pytest.skip(
            "daemon-healthy assertions require nested virtualization (M3+) for "
            "the gateway QEMU VM; host lacks it. Install steps + launchd "
            "bootstrap asserted above."
        )

    base_dir = f"/var/lib/sandboxd/{uid}"
    state_path = f"{base_dir}/.install-state.json"
    state_raw = vm.shell(f"sudo cat {state_path}", check=True)
    state = json.loads(state_raw.stdout)
    assert state.get("installed_version"), f"install-state missing installed_version: {state!r}"

    assert vm.shell("sudo test -S /var/run/sandbox/sandboxd.sock && echo OK").stdout.strip() == "OK", (
        "daemon socket /var/run/sandbox/sandboxd.sock missing"
    )

    # ---------------- doctor green ----------------
    assert_doctor_passes_macos(vm)
