"""`sandbox update` refuses on dev installs — the install framework.

A dev install is detected by either:

* missing systemd unit at ``/etc/systemd/system/sandboxd.service``, OR
* missing / unreadable install state at
  ``/var/lib/sandboxd/<daemon-uid>/.install-state.json``.

In that case ``sandbox update`` exits 2 with the dev-install message
that points operators at ``make build`` / ``make gateway-image`` /
``make setup-dev-env``. No lock is acquired.

This test boots a VM, copies the ``sandbox`` CLI into ``/usr/local/bin``
WITHOUT running install.sh (so neither the unit nor the install state
exist), and runs ``sandbox update``. The refusal message must include
the dev-mode markers from § 11.
"""

from __future__ import annotations

import pytest


@pytest.mark.parametrize("distro_template", ["ubuntu-22.04"])
def test_update_rejects_dev_install(
    distro_template, vm_factory, release_tarball_x86_64
):
    """`sandbox update` on a dev-shaped install exits 2 with the
    documented refusal message and does not touch state.

    Strategy:
      * Extract just the ``sandbox`` binary from the release tarball
        and drop it at ``/usr/local/bin/sandbox`` (chmod +x, root-owned).
      * Verify no systemd unit + no install state file exist.
      * Run ``sandbox update``; assert exit 2 + refusal substrings.
      * Assert the per-uid ``.update.lock`` was never created.
    """
    vm = vm_factory(distro_template)
    # Copy tarball into VM and extract just the sandbox CLI.
    src = str(release_tarball_x86_64)
    vm.cp(src, "/tmp/sandbox-rel.tar.gz")
    vm.shell(
        "set -eux; "
        "cd /tmp && tar -xzf sandbox-rel.tar.gz && "
        "ls -d /tmp/sandboxd-*/ > /tmp/staged.path && "
        "sudo install -m 0755 -o root -g root "
        "$(cat /tmp/staged.path)bin/sandbox /usr/local/bin/sandbox",
        check=True, timeout=120,
    )

    # Pre-conditions for dev-mode detection: no unit, no install state
    # (neither per-uid path nor legacy path should exist on this fresh VM).
    assert vm.shell(
        "test -f /etc/systemd/system/sandboxd.service"
    ).returncode != 0, "systemd unit should NOT be installed for this test"
    assert vm.shell(
        "sudo test -r /var/lib/sandbox/.install-state.json && "
        "sudo sh -c 'SUID=$(id -u sandbox 2>/dev/null || true); "
        "[ -n \"$SUID\" ] && test -r /var/lib/sandboxd/$SUID/.install-state.json'"
    ).returncode != 0, "install state should NOT exist for this test"

    # Run the update — should refuse with dev-mode message.
    r = vm.shell("/usr/local/bin/sandbox update", timeout=20)
    assert r.returncode == 2, (
        f"`sandbox update` on dev install should exit 2; got {r.returncode}\n"
        f"stdout:\n{r.stdout}\nstderr:\n{r.stderr}"
    )
    combined = r.stdout + r.stderr
    # Anchored on the install framework. The per-uid path placeholder
    # "/var/lib/sandboxd/<daemon-uid>/.install-state.json" matches the
    # literal text emitted by dev_mode_refusal_text() in update/mod.rs.
    for marker in (
        "system installs only",
        "/etc/systemd/system/sandboxd.service",
        "/var/lib/sandboxd/<daemon-uid>/.install-state.json",
        "make build",
        "make gateway-image",
        "make setup-dev-env",
    ):
        assert marker in combined, (
            f"dev-mode refusal missing marker {marker!r}:\n{combined}"
        )

    # No lock file was created (the gate fires BEFORE the lock acquire).
    # Check both the legacy path and per-uid path — neither should exist.
    assert vm.shell(
        "sudo test -e /var/lib/sandbox/.update.lock"
    ).returncode != 0, (
        "legacy /var/lib/sandbox/.update.lock must not exist after dev-mode refusal"
    )
    assert vm.shell(
        "SUID=$(id -u sandbox 2>/dev/null || true); "
        "[ -n \"$SUID\" ] && sudo test -e /var/lib/sandboxd/$SUID/.update.lock"
    ).returncode != 0, (
        "per-uid .update.lock must not exist after dev-mode refusal"
    )
