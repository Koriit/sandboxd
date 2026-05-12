"""systemd unit smoke test deferred from M14-S3.

Per `docs/internal/milestones/M14.md` and `M15.md`, the
``integration_systemd_unit_smokes`` test was deferred to this milestone
because it requires a Lima-controlled VM with systemd-inside. The Lima
install harness ships that environment; the test lives here rather
than in a Rust `integration_*` test because the assertions are about
the systemd unit's runtime behavior on a stock Linux distro, not about
the daemon binary in isolation.

What it checks (per M15 § "The integration_systemd_unit_smokes test"):

1. install.sh lands the unit at /etc/systemd/system/sandboxd.service.
2. ``systemctl enable --now sandboxd`` succeeds.
3. The unit reaches `active (running)`.
4. /run/sandbox/sandboxd.sock exists with mode 0660.
5. sandbox doctor exits 0.
"""

from __future__ import annotations

import pytest

from conftest import (
    copy_tarball_to_vm,
    install_sh_cmd,
    wait_for_socket,
    wait_for_systemd_active,
)


@pytest.mark.parametrize("distro_template", ["ubuntu-22.04"])
def integration_systemd_unit_smokes(
    distro_template, vm_factory, release_tarball_x86_64
):
    """systemd unit installs, starts, listens, and passes doctor.

    Function name is `integration_*` (rather than `test_*`) per the
    project's `integration_*` profile naming convention; the harness's
    pyproject.toml lists this prefix in ``python_functions`` so pytest
    collects it.
    """
    vm = vm_factory(distro_template)
    tarball_in_vm = copy_tarball_to_vm(vm, release_tarball_x86_64)

    r = vm.shell(
        install_sh_cmd(tarball_in_vm),
        timeout=600,
    )
    assert r.returncode == 0, f"install failed:\n{r.stdout}\n{r.stderr}"

    # 1. Unit file installed.
    assert vm.shell(
        "test -f /etc/systemd/system/sandboxd.service"
    ).returncode == 0

    # 2. systemctl enable --now sandboxd succeeds.
    r = vm.shell(
        "sudo systemctl enable --now sandboxd", timeout=60,
    )
    assert r.returncode == 0, (
        f"systemctl enable --now sandboxd failed:\n{r.stdout}\n{r.stderr}"
    )

    # 3. Active (running). systemctl enable --now returns once the unit is
    # enqueued; the daemon may still be in 'activating' when it returns, so
    # poll until it reaches 'active' (or short-circuit on 'failed').
    wait_for_systemd_active(vm.name, "sandboxd", timeout=30)

    # 4. Socket exists with the expected mode.
    wait_for_socket(vm.name, "/run/sandbox/sandboxd.sock", timeout=30)
    # `sudo` because /run/sandbox is mode 0750 sandbox:sandbox and the
    # default lima user has no traversal rights into it (same reason
    # wait_for_socket sudos its test -S probe).
    r = vm.shell(
        "sudo stat -c '%a %U %G' /run/sandbox/sandboxd.sock", check=True,
    )
    parts = r.stdout.strip().split()
    assert len(parts) == 3, f"unexpected stat output: {r.stdout!r}"
    mode, owner, group = parts
    assert mode == "660", f"socket mode is {mode}, expected 660"
    assert owner == "sandbox", f"socket owner is {owner}, expected sandbox"
    assert group == "sandbox", f"socket group is {group}, expected sandbox"

    # 5. sandbox doctor exits 0.
    #
    # We invoke as the ``sandbox`` daemon user so the "current user in
    # 'sandbox' group" check is unambiguously green — running as root
    # fails that check (root is not in the group), and running as the
    # default Lima user requires a re-login for the install.sh-issued
    # ``usermod -aG sandbox`` to take effect. The operator-group
    # plumbing for non-daemon operators is exercised by the happy-path
    # tests, which re-login between install and doctor.
    #
    # The systemd unit binds the socket at /run/sandbox/sandboxd.sock,
    # so we point the CLI at it via SANDBOX_SOCKET rather than relying
    # on the per-user XDG default.
    r = vm.shell(
        "sudo -u sandbox env"
        " SANDBOX_SOCKET=/run/sandbox/sandboxd.sock"
        " /usr/local/bin/sandbox doctor",
        timeout=60,
    )
    text = r.stdout + r.stderr
    assert r.returncode == 0, f"sandbox doctor exited {r.returncode}\n{text}"
    # Just confirm doctor produced output; we don't pin specific lines.
    assert text, "sandbox doctor produced no output"
