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
    make_bumped_tarball,
    retag_gateway_image_in_vm,
    version_from_tarball,
    wait_for_socket,
    wait_for_systemd_active,
)


@pytest.mark.parametrize("distro_template", ["ubuntu-22.04"])
def test_update_concurrent_refused(
    distro_template, vm_factory, release_tarball_x86_64, tmp_path
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

    # Build a bumped tarball so the version-compare branch reports
    # "update available" and the run reaches the lock-acquire step
    # (same-version short-circuits before any lock is taken).
    bumped_ver = _bump_patch(base_ver)
    bumped = make_bumped_tarball(release_tarball_x86_64, bumped_ver,
                                 dst_dir=tmp_path)
    bumped_in_vm = copy_tarball_to_vm(vm, bumped)
    retag_gateway_image_in_vm(
        vm,
        from_tag=f"sandbox-gateway:{base_ver}",
        to_tag=f"sandbox-gateway:{bumped_ver}",
    )

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
    # Background flock holder — runs as user `sandbox` (matches the
    # lock file's owner) so it has rw access. setsid+nohup so it
    # survives the shell session exit; flock -n returns 0 only if it
    # acquired the lock (which it should since we just wrote a fresh
    # file).
    vm.shell(
        "sudo -u sandbox sh -c 'setsid nohup flock -n "
        "/var/lib/sandbox/.update.lock -c \"sleep 60\" "
        ">/tmp/flock-holder.log 2>&1 &' && sleep 1",
        check=True, timeout=15,
    )
    # Sanity: confirm the flock is actually held by attempting a
    # non-blocking acquisition that must fail.
    sanity = vm.shell(
        "sudo -u sandbox flock -n /var/lib/sandbox/.update.lock -c true",
        timeout=10,
    )
    assert sanity.returncode != 0, (
        "background flock did not take the lock — concurrent test cannot "
        "proceed (the second sandbox update would succeed in acquiring)"
    )

    # Now run the real `sandbox update` — it MUST refuse.
    r = vm.shell(
        f"sudo sandbox update --from {bumped_in_vm} --yes",
        timeout=30,
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


def _bump_patch(version):
    """Return version with the patch component incremented by one.

    ``1.0.0`` → ``1.0.1``; ``0.1.0`` → ``0.1.1``; etc.
    """
    parts = version.split(".")
    if len(parts) != 3:
        raise AssertionError(f"unexpected version shape: {version}")
    parts[-1] = str(int(parts[-1]) + 1)
    return ".".join(parts)


def _sh_quote(s):
    return "'" + s.replace("'", r"'\''") + "'"
