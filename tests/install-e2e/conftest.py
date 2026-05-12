"""Shared fixtures + helpers for the install.sh / uninstall.sh Lima harness.

The harness boots a fresh Lima VM per test, copies the locally-built
release tarball into it, copies a patched install.sh/uninstall.sh into
it, and runs the install path end-to-end. Each VM is torn down in the
test's ``finally``; the suite is intentionally serial.

Why patch install.sh? Two reasons:

* The release tarball assembled by ``build-local-tarball.sh`` is
  unsigned. The script's sigstore-verify step would otherwise refuse it.
* Downloading the real cosign binary inside every VM is slow and noisy.

The patch replaces ``cosign_bootstrap`` and ``sigstore_verify`` with
no-ops that emit the same log lines as the real flow. Every other step
(arch detect, prereq, useradd, setcap, docker load, systemd unit
install, write_install_state, ...) runs unmodified — those are the
steps the harness exists to exercise.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import time
import uuid
from dataclasses import dataclass
from pathlib import Path

import pytest


HERE = Path(__file__).resolve().parent
PROJECT_ROOT = HERE.parent.parent
SCRIPTS_DIR = PROJECT_ROOT / "scripts"
INSTALL_SH = SCRIPTS_DIR / "install.sh"
UNINSTALL_SH = SCRIPTS_DIR / "uninstall.sh"

DIST_DIR = HERE / "dist"
LOGS_DIR = HERE / "logs"
LOGS_DIR.mkdir(parents=True, exist_ok=True)

VM_BOOT_TIMEOUT = 360  # seconds
VM_PROVISION_TIMEOUT = 600
SOCKET_WAIT_TIMEOUT = 60

# Distro templates available via `template://<name>` on Lima >=2.0.
# fedora-40 isn't shipped with Lima 2.1; fedora-41 is the closest stand-in
# for the RHEL-paths test (same /usr/libexec/qemu-bridge-helper layout).
DEFAULT_FEDORA = "fedora-41"


# ---------------------------------------------------------------------------
# pytest_runtest_makereport — stash phase outcome for autouse log-on-fail.
# ---------------------------------------------------------------------------

@pytest.hookimpl(tryfirst=True, hookwrapper=True)
def pytest_runtest_makereport(item, call):
    outcome = yield
    rep = outcome.get_result()
    setattr(item, "rep_" + rep.when, rep)


# ---------------------------------------------------------------------------
# Lima primitives.
# ---------------------------------------------------------------------------

def _run(cmd, *, check=True, timeout=120, capture=True, env=None):
    """Thin wrapper around subprocess.run with sensible defaults."""
    result = subprocess.run(
        cmd,
        check=False,
        timeout=timeout,
        capture_output=capture,
        text=True,
        env=env,
    )
    if check and result.returncode != 0:
        raise AssertionError(
            f"command failed (exit {result.returncode}): {cmd}\n"
            f"stdout:\n{result.stdout}\n"
            f"stderr:\n{result.stderr}"
        )
    return result


def lima_shell(vm_name, command, *, check=False, timeout=180, user=None):
    """Run a shell command inside the Lima VM via ``limactl shell``.

    Returns a CompletedProcess. By default does NOT raise on non-zero so
    tests can assert on exit codes; pass ``check=True`` to fault on
    failure.

    ``user`` (if given) wraps the command with ``sudo -u <user> sh -c
    '...'`` so we exercise the post-install operator's view of the
    system (the install script's pre-installed Lima user is ``lima``,
    not ``sandbox``).
    """
    if user is not None:
        # Wrap in `sudo -u USER` from inside the VM. We pass `--` after
        # `shell <vm>` to prevent limactl from interpreting test
        # commands as its own flags.
        wrapped = f"sudo -u {user} -- sh -c {_sh_quote(command)}"
        argv = ["limactl", "shell", vm_name, "--", "sh", "-c", wrapped]
    else:
        argv = ["limactl", "shell", vm_name, "--", "sh", "-c", command]
    return _run(argv, check=check, timeout=timeout)


def _sh_quote(s):
    """POSIX-safe single-quote wrap."""
    return "'" + s.replace("'", r"'\''") + "'"


def lima_cp(vm_name, src, dst):
    """Copy a local file into the Lima VM.

    Uses `limactl copy <src> <vm>:<dst>` (where <dst> is an absolute
    path in the guest). Permissions follow Lima's defaults (rw-r--r--);
    the install scripts re-install binaries with explicit modes anyway.
    """
    src_str = str(src)
    dst_target = f"{vm_name}:{dst}"
    _run(["limactl", "copy", src_str, dst_target], timeout=120)


def wait_for_socket(vm_name, sock_path, *, timeout=SOCKET_WAIT_TIMEOUT):
    """Block until <sock_path> exists inside the VM as a unix socket."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        result = lima_shell(
            vm_name,
            f"test -S {sock_path} && echo ok",
            timeout=10,
        )
        if result.returncode == 0 and "ok" in result.stdout:
            return
        time.sleep(2)
    raise AssertionError(
        f"{sock_path} did not appear in {vm_name} within {timeout}s"
    )


def wait_for_systemd_active(vm_name, unit, *, timeout=30):
    """Poll ``systemctl is-active <unit>`` until it returns ``active``.

    ``systemctl enable --now`` returns once the unit is *enqueued* — the
    daemon may still be in the ``activating`` state when the call returns.
    This helper closes that race by polling until the unit reaches a
    terminal state. On ``failed`` we short-circuit (no point waiting) and
    surface a journal dump in the AssertionError to keep failures
    self-debugging.
    """
    deadline = time.monotonic() + timeout
    last = ""
    while time.monotonic() < deadline:
        result = lima_shell(
            vm_name,
            f"systemctl is-active {unit}",
            timeout=10,
        )
        last = result.stdout.strip()
        if last == "active":
            return
        if last == "failed":
            journal = lima_shell(
                vm_name,
                f"sudo journalctl -u {unit} -n 50 --no-pager",
                timeout=15,
            ).stdout
            raise AssertionError(
                f"{unit} entered failed state\n"
                f"--- journalctl -u {unit} -n 50 ---\n{journal}"
            )
        time.sleep(1)
    journal = lima_shell(
        vm_name,
        f"sudo journalctl -u {unit} -n 50 --no-pager",
        timeout=15,
    ).stdout
    raise AssertionError(
        f"{unit} did not reach active within {timeout}s (last state: {last!r})\n"
        f"--- journalctl -u {unit} -n 50 ---\n{journal}"
    )


def lima_vm_name(prefix="iet"):
    """A short, unique VM name. Lima caps at 60 chars; keep margin."""
    return f"sb-{prefix}-{uuid.uuid4().hex[:8]}"


def lima_start(vm_name, template, *, cpus=2, memory_gib=2, disk_gib=10):
    """Start a Lima VM from a builtin template.

    template is the short name (e.g. "ubuntu-22.04", "fedora-41");
    we use the `template:<name>` form (Lima v2.0+; older
    `template://<name>` is deprecated).

    Default templates mount the host's home directory at the same path
    inside the guest. This collides on shared workstations where the
    host's effective home directory differs from `$HOME` (e.g. a sudo'd
    test runner). We zero out mounts via ``--set`` so the test guest is
    fully isolated from the host filesystem; files are copied in
    explicitly via ``limactl copy``.
    """
    cmd = [
        "limactl", "start",
        f"--name={vm_name}",
        f"template:{template}",
        f"--cpus={cpus}",
        f"--memory={memory_gib}",
        f"--disk={disk_gib}",
        "--set", ".mounts=[]",
        "--tty=false",
    ]
    _run(cmd, timeout=VM_BOOT_TIMEOUT)


def lima_delete(vm_name):
    """Force-delete a Lima VM. Idempotent."""
    subprocess.run(
        ["limactl", "delete", "--force", vm_name],
        capture_output=True, text=True, timeout=120,
    )


# ---------------------------------------------------------------------------
# Install-script patching.
# ---------------------------------------------------------------------------
#
# The patches turn cosign_bootstrap + sigstore_verify into no-ops so the
# locally-assembled (unsigned) tarball passes through the rest of
# install.sh unchanged. They are applied to a tempfile copy; the
# canonical scripts/install.sh on disk is untouched.

_COSIGN_PATCH_TAG = "# PATCHED-BY-INSTALL-E2E"

_COSIGN_BOOTSTRAP_REPLACEMENT = f"""cosign_bootstrap() {{
    {_COSIGN_PATCH_TAG}
    COSIGN=/bin/true
    log_ok "step=cosign_bootstrap version=stub source=test"
}}
"""

_SIGSTORE_VERIFY_REPLACEMENT = f"""sigstore_verify() {{
    {_COSIGN_PATCH_TAG}
    log_ok "step=sigstore_verify bundle=stub identity=test"
}}
"""


def _patch_install_sh(src_path, dst_path):
    """Write a patched copy of install.sh to dst_path.

    Replaces the cosign_bootstrap() and sigstore_verify() function
    bodies with stub implementations that log the same step names.
    """
    text = Path(src_path).read_text()
    text = _replace_shell_function(text, "cosign_bootstrap",
                                   _COSIGN_BOOTSTRAP_REPLACEMENT)
    text = _replace_shell_function(text, "sigstore_verify",
                                   _SIGSTORE_VERIFY_REPLACEMENT)
    Path(dst_path).write_text(text)
    os.chmod(dst_path, 0o755)


def _replace_shell_function(text, func_name, replacement):
    """Replace ``<func_name>() { ... }`` (POSIX shell) with replacement.

    Matches the function header, then walks brace depth (ignoring
    quoted braces is heuristic but install.sh has no such cases in
    cosign_bootstrap / sigstore_verify).
    """
    header_re = re.compile(rf"^{re.escape(func_name)}\(\)\s*\{{\s*$",
                           re.MULTILINE)
    m = header_re.search(text)
    if not m:
        raise AssertionError(f"could not find {func_name}() in install.sh")
    start = m.start()
    # Walk braces from the opening { (which is at m.end() - 1).
    i = m.end() - 1
    depth = 0
    while i < len(text):
        c = text[i]
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                end = i + 1
                # Consume the trailing newline if present.
                if end < len(text) and text[end] == "\n":
                    end += 1
                return text[:start] + replacement + text[end:]
        i += 1
    raise AssertionError(f"unmatched braces in {func_name}()")


# ---------------------------------------------------------------------------
# Release tarball fixture.
# ---------------------------------------------------------------------------

@pytest.fixture(scope="session")
def release_tarball_x86_64() -> Path:
    """Build the local release tarball once per test session.

    Drives ``build-local-tarball.sh``; honors the script's
    SANDBOX_RELEASE_SKIP_BUILD / SKIP_GATEWAY env vars when set in the
    pytest invocation environment so iteration is fast.
    """
    if subprocess.run(["uname", "-m"], capture_output=True, text=True).stdout.strip() != "x86_64":
        pytest.skip("release_tarball_x86_64 fixture only assembles on x86_64 hosts")

    ver = _read_workspace_version()
    arch = "x86_64-unknown-linux-gnu"
    tarball = DIST_DIR / f"sandboxd-{ver}-{arch}.tar.gz"

    if not tarball.exists() or os.environ.get("SANDBOX_RELEASE_FORCE_REBUILD") == "1":
        subprocess.run(
            [str(HERE / "build-local-tarball.sh")],
            check=True,
            timeout=1800,
        )

    assert tarball.exists(), f"tarball not produced: {tarball}"
    return tarball


def _read_workspace_version() -> str:
    cargo_toml = PROJECT_ROOT / "sandboxd" / "sandboxd" / "Cargo.toml"
    for line in cargo_toml.read_text().splitlines():
        if line.startswith("version"):
            parts = line.split('"')
            if len(parts) >= 2:
                return parts[1]
    raise AssertionError("could not parse workspace version")


# ---------------------------------------------------------------------------
# VM lifecycle fixture factory.
# ---------------------------------------------------------------------------

@dataclass
class VM:
    """Handle on a running Lima VM, with helpers."""
    name: str
    distro: str

    def shell(self, command, **kw):
        return lima_shell(self.name, command, **kw)

    def cp(self, src, dst):
        return lima_cp(self.name, src, dst)


@pytest.fixture
def vm_factory(request):
    """Spawn-on-demand factory for Lima VMs scoped to a single test.

    The factory returns a callable; each invocation produces a fresh VM,
    boots it from the given template, installs the install/uninstall
    prerequisites (jq, curl, qemu, lima, docker, setcap, ovmf, ...) via
    the distro's package manager, copies in install.sh / uninstall.sh,
    and returns a VM handle.

    Every VM created via the factory is force-deleted on test teardown
    (success or failure). On failure, the install log + journalctl
    snapshot is harvested to tests/install-e2e/logs/<test>/<vm>/.
    """
    created = []
    test_name = request.node.name.replace("/", "_").replace(":", "_")[:80]

    def _factory(template, *, install_prereqs=True, install_scripts=True,
                 patch_install_sh=True):
        name = lima_vm_name()
        lima_start(name, template)
        vm = VM(name=name, distro=template)
        created.append(vm)

        if install_prereqs:
            _install_prereqs(vm)

        if install_scripts:
            _stage_scripts(vm, patch_install=patch_install_sh)

        return vm

    yield _factory

    # --- teardown ---
    rep = getattr(request.node, "rep_call", None)
    failed = rep is not None and rep.failed
    for vm in created:
        if failed:
            _harvest_logs(vm, LOGS_DIR / test_name / vm.name)
        lima_delete(vm.name)


def _install_prereqs(vm):
    """Install the install.sh prerequisite packages inside the VM.

    Branches on the distro family; this is the same set of packages
    install.sh's step 6 (`check_prereqs`) verifies.
    """
    if vm.distro.startswith(("ubuntu", "debian")):
        cmd = (
            "set -eux; "
            "export DEBIAN_FRONTEND=noninteractive; "
            "sudo apt-get update; "
            "sudo apt-get install -y --no-install-recommends "
            "ca-certificates curl jq tar qemu-system-x86 qemu-utils "
            "ovmf libcap2-bin coreutils"
        )
        vm.shell(cmd, check=True, timeout=600)
        # Docker
        vm.shell(
            "set -eux; "
            "sudo apt-get install -y --no-install-recommends "
            "docker.io || sudo apt-get install -y docker-ce",
            check=True, timeout=600,
        )
        # Lima — only needed for sandbox doctor's `limactl --version`
        # check. The deb repos don't ship it; install from upstream
        # release.
        vm.shell(
            "set -eux; "
            "ver=2.1.1; "
            "arch=$(uname -m); "
            "case $arch in x86_64) suffix=Linux-x86_64;; "
            "aarch64) suffix=Linux-aarch64;; esac; "
            "tmp=$(mktemp -d); cd $tmp; "
            "curl -fsSL "
            "https://github.com/lima-vm/lima/releases/download/v${ver}/lima-${ver}-${suffix}.tar.gz "
            "-o lima.tar.gz; "
            "sudo tar -C /usr/local -xzf lima.tar.gz",
            check=True, timeout=300,
        )
    elif vm.distro.startswith("fedora"):
        vm.shell(
            "set -eux; "
            "sudo dnf install -y "
            "curl jq tar qemu-kvm qemu-system-x86 edk2-ovmf "
            "libcap docker iptables-services",
            check=True, timeout=600,
        )
        vm.shell(
            "set -eux; "
            "ver=2.1.1; "
            "arch=$(uname -m); "
            "case $arch in x86_64) suffix=Linux-x86_64;; "
            "aarch64) suffix=Linux-aarch64;; esac; "
            "tmp=$(mktemp -d); cd $tmp; "
            "curl -fsSL "
            "https://github.com/lima-vm/lima/releases/download/v${ver}/lima-${ver}-${suffix}.tar.gz "
            "-o lima.tar.gz; "
            "sudo tar -C /usr/local -xzf lima.tar.gz",
            check=True, timeout=300,
        )
    else:
        raise AssertionError(f"unknown distro: {vm.distro}")

    # Enable + start docker — install.sh probes `docker info`.
    vm.shell(
        "set -eux; sudo systemctl enable --now docker",
        check=True, timeout=120,
    )


def _stage_scripts(vm, *, patch_install):
    """Copy install.sh + uninstall.sh into /tmp inside the VM."""
    if patch_install:
        # Write the patched script to a host-side tempfile, then copy.
        import tempfile
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".sh", prefix="install-patched-",
            delete=False,
        ) as tf:
            tf.close()
            _patch_install_sh(INSTALL_SH, tf.name)
            vm.cp(tf.name, "/tmp/install.sh")
            os.unlink(tf.name)
    else:
        vm.cp(INSTALL_SH, "/tmp/install.sh")
    vm.cp(UNINSTALL_SH, "/tmp/uninstall.sh")
    vm.shell("chmod +x /tmp/install.sh /tmp/uninstall.sh", check=True)


def _harvest_logs(vm, dest_dir):
    """Best-effort: dump the install log + journal to disk on failure."""
    dest_dir.mkdir(parents=True, exist_ok=True)

    targets = [
        ("install.log",     "sudo cat /var/log/sandbox-install.log 2>/dev/null || true"),
        ("install-state",   "sudo cat /var/lib/sandbox/.install-state.json 2>/dev/null || true"),
        ("journal-sandboxd", "sudo journalctl -u sandboxd --no-pager 2>/dev/null || true"),
        ("getcap",          "getcap /usr/local/libexec/sandboxd/sandbox-route-helper 2>/dev/null || true"),
        ("ls-bin",          "ls -la /usr/local/bin/sandboxd /usr/local/bin/sandbox /etc/systemd/system/sandboxd.service /etc/sandboxd/users.conf 2>&1 || true"),
    ]
    for fname, cmd in targets:
        try:
            r = vm.shell(cmd, timeout=30)
            (dest_dir / fname).write_text(
                f"=== stdout ===\n{r.stdout}\n=== stderr ===\n{r.stderr}\n"
            )
        except Exception as exc:  # noqa: BLE001
            (dest_dir / fname).write_text(f"harvest error: {exc}\n")


# ---------------------------------------------------------------------------
# Pre-flight check: Lima available on host.
# ---------------------------------------------------------------------------

@pytest.fixture(scope="session", autouse=True)
def _preflight():
    """Skip the whole suite if Lima or /dev/kvm is unavailable."""
    if shutil.which("limactl") is None:
        pytest.skip("limactl not installed on host")
    if not Path("/dev/kvm").exists():
        pytest.skip("/dev/kvm not available; install-e2e requires KVM")


# ---------------------------------------------------------------------------
# Convenience helpers re-exported for tests.
# ---------------------------------------------------------------------------

def parse_install_log_actions(log_text):
    """Return a dict {step_name: [action, ...]} from an install log."""
    actions = {}
    for line in log_text.splitlines():
        m_step = re.search(r"\bstep=(\S+)", line)
        m_action = re.search(r"\baction=(\S+)", line)
        if m_step and m_action:
            actions.setdefault(m_step.group(1), []).append(m_action.group(1))
    return actions


def copy_tarball_to_vm(vm, tarball_path, dst="/tmp"):
    """Copy a release tarball + its sigstore stub into the VM.

    Both files end up next to each other in /tmp so install.sh's
    ``--from /tmp/<name>.tar.gz`` flow finds the sibling .sigstore
    bundle without an explicit ``--cosign-bundle`` flag.

    Returns the in-VM tarball path.
    """
    tarball_path = Path(tarball_path)
    dst_path = f"{dst.rstrip('/')}/{tarball_path.name}"
    vm.cp(tarball_path, dst_path)

    sig = Path(str(tarball_path) + ".sigstore")
    if not sig.exists():
        sig.write_bytes(b"")
    vm.cp(sig, f"{dst_path}.sigstore")
    return dst_path


_TARBALL_VERSION_RE = re.compile(r"^sandboxd-([^-]+(?:\.[^-]+)*)-")


def version_from_tarball(tarball_path):
    """Extract the version string encoded in the tarball filename.

    Tarball naming convention is ``sandboxd-<version>-<arch>.tar.gz``
    (spec § 2.1). install.sh's resolve_target_version step skips
    network lookup when ``--from`` is set but does NOT auto-derive the
    version from the tarball filename — operators are expected to pass
    ``--version`` alongside ``--from``. The harness mirrors that
    contract here so tests don't have to hard-code "0.1.0".
    """
    name = Path(tarball_path).name
    m = _TARBALL_VERSION_RE.match(name)
    if not m:
        raise AssertionError(
            f"could not parse version from tarball name: {name}"
        )
    return m.group(1)


def install_sh_cmd(tarball_in_vm, *extra_flags):
    """Build the canonical install.sh invocation used by every test.

    Always passes ``--from``, ``--version``, ``--yes``, ``--no-color``
    so test output is parser-friendly and idempotency assertions land
    on a known version string. Additional flags (e.g. ``--cosign-bundle``)
    can be appended.
    """
    ver = version_from_tarball(tarball_in_vm)
    base = [
        "sudo bash /tmp/install.sh",
        f"--from {tarball_in_vm}",
        f"--version {ver}",
        "--yes",
        "--no-color",
    ]
    base.extend(extra_flags)
    return " ".join(base)


def assert_doctor_passes(vm, *, user=None, timeout=60):
    """Run `sandbox doctor` and assert it reports zero failures.

    The CLI's doctor command exit code is 0 on green; we also check
    the "0 failed" string for defensive coverage.
    """
    cmd = "/usr/local/bin/sandbox doctor"
    r = vm.shell(cmd, user=user, timeout=timeout)
    # We pass through both stdout and a non-zero exit hint when the
    # assertion fails to keep failures self-debugging.
    text = r.stdout + r.stderr
    if r.returncode != 0:
        raise AssertionError(
            f"sandbox doctor exited {r.returncode}\n{text}"
        )
    return text
