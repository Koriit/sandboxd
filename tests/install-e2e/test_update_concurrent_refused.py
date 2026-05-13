"""Two concurrent `sandbox update` runs — second refuses with the
"another update is in progress" message — Spec 5 §§ 6.2, 9.1.

The first invocation acquires the kernel ``flock`` on
``/var/lib/sandbox/.update.lock`` and writes the JSON payload (PID,
target version, started_at, ...). Any second invocation that tries to
acquire while the first is alive sees the held flock and refuses with
exit 1 + the error message from ``lock::LockError::LockHeld``.

Strategy: synthesise a pre-acquired lock file inside the VM by writing
the JSON payload + holding the flock from a sibling ``flock -n`` process
that ``sleep``s for the duration of the test. Then run ``sandbox update``
and assert the refusal. This is more reliable than racing two real
``sandbox update`` invocations — the lock-held branch is what we're
pinning, and the synthesised holder lets us exercise it deterministically.
"""

from __future__ import annotations

import json

import pytest

from conftest import (
    copy_tarball_to_vm,
    install_sh_cmd,
    version_from_tarball,
    wait_for_socket,
    wait_for_systemd_active,
)


@pytest.mark.parametrize("distro_template", ["ubuntu-22.04"])
def test_update_concurrent_refused(
    distro_template,
    vm_factory,
    release_tarball_x86_64,
    release_tarball_x86_64_bumped,
):
    """A held flock on `/var/lib/sandbox/.update.lock` forces the second
    `sandbox update` to refuse with "another update is in progress".

    Assertions:
      * Second invocation exit code != 0.
      * stderr (or stdout) contains the documented "another sandbox
        update is in progress" substring.
      * The held lock file (synthesised by the test) survives the
        refusal — the refused process did not unlink it.
    """
    vm = vm_factory(distro_template)
    base_tarball = copy_tarball_to_vm(vm, release_tarball_x86_64)
    base_ver = version_from_tarball(base_tarball)

    r = vm.shell(install_sh_cmd(base_tarball), timeout=600)
    assert r.returncode == 0, f"install failed:\n{r.stdout}\n{r.stderr}"
    vm.shell("sudo systemctl enable --now sandboxd", check=True, timeout=60)
    wait_for_systemd_active(vm.name, "sandboxd", timeout=60)
    wait_for_socket(vm.name, "/run/sandbox/sandboxd.sock", timeout=60)

    # Stage a genuine bumped tarball so the version-compare branch
    # reports "update available" and the run reaches the lock-acquire
    # step (same-version short-circuits before any lock is taken).
    bumped_ver = version_from_tarball(release_tarball_x86_64_bumped)
    bumped_in_vm = copy_tarball_to_vm(vm, release_tarball_x86_64_bumped)

    # Synthesise a held lock: a background `flock -n <lock> sleep 60`
    # holds the kernel flock. We write the payload first (mode 0664
    # owner sandbox:sandbox per Spec 5 § 10.1), then hand the FD to flock.
    payload = json.dumps({
        "pid": 999999,  # any int — the live holder is the sleep proc
        "target_version": bumped_ver,
        "from_version": base_ver,
        "started_at": "2026-05-12T00:00:00Z",
        "was_running": True,
    })
    vm.shell(
        f"sudo install -d -m 0755 -o sandbox -g sandbox /var/lib/sandbox && "
        f"echo {_sh_quote(payload)} | "
        f"sudo -u sandbox tee /var/lib/sandbox/.update.lock >/dev/null && "
        f"sudo chmod 0664 /var/lib/sandbox/.update.lock",
        check=True, timeout=30,
    )
    # Hold the flock and run the refused `sandbox update` inside the
    # SAME `vm.shell()` call. A prior shape used a background `setsid
    # nohup ... &` holder across two separate `vm.shell()` calls;
    # systemd-logind on the guest reaps user processes when the SSH
    # session that spawned them exits (`KillUserProcesses=yes`), so
    # by the time the second `vm.shell()` ran `sandbox update`, the
    # holder was dead and the update succeeded by adopting the dead
    # PID's lock. Consolidating into one SSH session keeps the holder
    # alive for the concurrency window.
    #
    # Sanity-check exit codes (70/71) surface as a recipe-side
    # failure with a distinct rc so test assertions can tell harness
    # bugs apart from update-side regressions.
    refusal_recipe = f"""
set -u
sudo -u sandbox flock -n /var/lib/sandbox/.update.lock -c "sleep 60" &
HOLDER_PID=$!
sleep 1
# Sanity 1: holder process alive.
if ! ps -p "$HOLDER_PID" >/dev/null; then
    echo 'flock holder died before sandbox update launched' >&2
    exit 70
fi
# Sanity 2: lock truly held (a competing non-blocking flock must fail).
if sudo -u sandbox flock -n /var/lib/sandbox/.update.lock -c true; then
    echo 'flock holder did not actually take the lock' >&2
    kill "$HOLDER_PID" 2>/dev/null
    exit 71
fi
# The real test: `sandbox update` must refuse.
sudo sandbox update --from {bumped_in_vm} --yes
RC=$?
kill "$HOLDER_PID" 2>/dev/null
wait "$HOLDER_PID" 2>/dev/null
exit $RC
"""
    r = vm.shell(refusal_recipe, timeout=120)
    assert r.returncode not in (70, 71), (
        f"test harness failure (not a sandbox update regression):\n"
        f"stdout:\n{r.stdout}\nstderr:\n{r.stderr}"
    )
    assert r.returncode != 0, (
        f"`sandbox update` should have refused while flock was held; "
        f"got exit 0\nstdout:\n{r.stdout}\nstderr:\n{r.stderr}"
    )
    combined = r.stdout + r.stderr
    assert "another" in combined and "update" in combined and "in progress" in combined, (
        f"refusal message missing 'another ... update ... in progress' marker:\n"
        f"{combined}"
    )

    # The lock file survives the refused run (the refused process did
    # NOT take ownership, so it did NOT unlink at Drop).
    assert vm.shell(
        "sudo test -e /var/lib/sandbox/.update.lock"
    ).returncode == 0, "held lock file disappeared during refused run"


def _sh_quote(s):
    return "'" + s.replace("'", r"'\''") + "'"
