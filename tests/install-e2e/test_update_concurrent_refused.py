"""Two concurrent `sandbox update` runs — second refuses with the
"another update is in progress" message — the install framework.2, 9.1.

The first invocation acquires the kernel ``flock`` on the lock file
under the per-uid base-dir and writes the JSON payload (PID,
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
    sigstore_stack,
):
    """A held flock on the per-uid base-dir `.update.lock` forces the second
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

    r = vm.shell(
        install_sh_cmd(base_tarball, vm=vm, sigstore_stack=sigstore_stack),
        timeout=600,
    )
    assert r.returncode == 0, f"install failed:\n{r.stdout}\n{r.stderr}"
    vm.shell("sudo systemctl enable --now sandboxd", check=True, timeout=60)
    wait_for_systemd_active(vm.name, "sandboxd", timeout=60)
    wait_for_socket(vm.name, "/run/sandbox/sandboxd.sock", timeout=60)

    # Stage a genuine bumped tarball so the version-compare branch
    # reports "update available" and the run reaches the lock-acquire
    # step (same-version short-circuits before any lock is taken).
    bumped_ver = version_from_tarball(release_tarball_x86_64_bumped)
    bumped_in_vm = copy_tarball_to_vm(vm, release_tarball_x86_64_bumped)

    # Extract the bumped tarball and feed the staged-directory shape
    # (`--from <dir>`) to `sandbox update`. The CLI's § 3.1.10 sigstore
    # precondition runs BEFORE the lock acquire (§ 3.2.13); since the
    # gate only fires when `from.is_file()`, the directory shape skips
    # the cosign call and lets execution reach the lock-acquire branch
    # under test. A `--from <tarball>` invocation here would route
    # through cosign verify-blob, which adds noise that obscures the
    # lock-acquire contract under test.
    stage_dir = "/tmp/sandbox-update-concurrent-stage"
    arch = "x86_64-unknown-linux-gnu"
    vm.shell(
        f"sudo rm -rf {stage_dir} && mkdir -p {stage_dir} && "
        f"tar xzf {bumped_in_vm} -C {stage_dir}",
        check=True, timeout=60,
    )
    extracted_root = f"{stage_dir}/sandboxd-{bumped_ver}-{arch}"

    # Synthesise a held lock: a background `flock -n <lock> sleep 60`
    # holds the kernel flock. We write the payload first (mode 0664
    # owner sandbox:sandbox per the install framework.1), then hand the FD to flock.
    #
    # `started_at` is rendered dynamically as "5 minutes ago" so the
    # payload appears RECENT against the lock's 24-hour staleness
    # threshold (
    # than 24h). A fixed timestamp like "2026-05-12T00:00:00Z" was
    # safe when first written but drifts past 24h as the calendar
    # advances, eventually crossing the adopt-vs-adopt-stale
    # boundary. The dynamic value pins the test against the
    # `HeldByLivePid` refusal path the design contract names; an
    # adopt-stale outcome would mean a different code path which
    # this test is not designed to exercise.
    started_at = vm.shell(
        "date -u -d '5 minutes ago' '+%Y-%m-%dT%H:%M:%SZ'",
        check=True, timeout=10,
    ).stdout.strip()
    assert len(started_at) > 0, "date(1) must produce an RFC3339 timestamp"
    payload = json.dumps({
        "pid": 999999,  # any int — the live holder is the sleep proc
        "target_version": bumped_ver,
        "from_version": base_ver,
        "started_at": started_at,
        "was_running": True,
    })
    # The per-uid base-dir is created by install.sh; the lock file lives
    # inside it. Resolve the uid at runtime so the path is correct.
    vm.shell(
        f"SUID=$(id -u sandbox) && "
        f"echo {_sh_quote(payload)} | "
        f"sudo -u sandbox tee /var/lib/sandboxd/$SUID/.update.lock >/dev/null && "
        f"sudo chmod 0664 /var/lib/sandboxd/$SUID/.update.lock",
        check=True, timeout=30,
    )
    # Hold the flock and run the refused `sandbox update` inside the
    # SAME `vm.shell()` call. Two earlier shapes did not work:
    #   1. Background `setsid nohup sudo -u sandbox flock ... &` across
    #      two separate `vm.shell()` calls — the guest's systemd-logind
    #      reaped the holder between SSH sessions.
    #   2. Consolidated `sudo -u sandbox flock -c "sleep 60"` in one
    #      call — `sandbox` has `nologin` as its shell, and although
    #      `sudo -u sandbox <cmd>` works for direct commands, `flock`'s
    #      `-c` arg internally invokes a shell which on this user's
    #      PAM/account stack rejects with "This account is currently
    #      not available", so the holder exits immediately.
    #
    # Hold the flock as root. The kernel `flock` is advisory on the
    # file inode and is per-process; the daemon-side update code runs
    # as root via `sudo sandbox update` but that's a DIFFERENT process,
    # so the lock still blocks. The test asserts the daemon's
    # concurrency guard fires when ANY process holds the flock — it
    # doesn't care about the holder's identity.
    #
    # Sanity-check exit codes (70/71) surface as a recipe-side
    # failure with a distinct rc so test assertions can tell harness
    # bugs apart from update-side regressions.
    refusal_recipe = f"""
set -u
SUID=$(id -u sandbox)
LOCK_FILE="/var/lib/sandboxd/$SUID/.update.lock"
sudo flock -n "$LOCK_FILE" -c "sleep 60" &
HOLDER_PID=$!
sleep 1
# Sanity 1: holder process alive.
if ! ps -p "$HOLDER_PID" >/dev/null; then
    echo 'flock holder died before sandbox update launched' >&2
    exit 70
fi
# Sanity 2: lock truly held (a competing non-blocking flock must fail).
if sudo flock -n "$LOCK_FILE" -c true; then
    echo 'flock holder did not actually take the lock' >&2
    sudo kill "$HOLDER_PID" 2>/dev/null
    exit 71
fi
# The real test: `sandbox update` must refuse.
sudo sandbox update --from {extracted_root} --yes
RC=$?
sudo kill "$HOLDER_PID" 2>/dev/null
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
    # 
    # (the CLI's standard error-rendering path), so the refusal
    # message must land on STDERR only — stdout should be empty
    # modulo any `log_step` lines that fire before the lock probe.
    # The previous shape asserted on `r.stdout + r.stderr` combined,
    # which would have passed even if the refusal silently leaked to
    # stdout (a regression that swapped `eprintln!` for `println!`).
    assert (
        "another" in r.stderr
        and "update" in r.stderr
        and "in progress" in r.stderr
    ), (
        f"refusal message must land on stderr (.2 — error rendering via "
        f"eprintln!); missing 'another ... update ... in progress' marker.\n"
        f"stderr:\n{r.stderr}\nstdout (for diagnostic context only):\n{r.stdout}"
    )

    # The lock file survives the refused run (the refused process did
    # NOT take ownership, so it did NOT unlink at Drop).
    assert vm.shell(
        "SUID=$(id -u sandbox); sudo test -e /var/lib/sandboxd/$SUID/.update.lock"
    ).returncode == 0, "held lock file disappeared during refused run"


def _sh_quote(s):
    return "'" + s.replace("'", r"'\''") + "'"
