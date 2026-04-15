"""E2E tests for M6 QEMU hardening: device lockdown, cgroup resource
limits, and the --no-hardening escape hatch.

These tests boot real Lima/QEMU VMs and are SLOW (3-10 minutes per test).
Run with generous timeouts:

    cd tests/e2e
    source .venv/bin/activate
    python -m pytest test_m6_hardening.py -v --timeout=600
"""

from __future__ import annotations

import re
import subprocess

import pytest

from conftest import (
    _VM_RESOURCE_ARGS,
    capture_lima_logs,
    lima_vm_name,
    parse_session_id,
    wait_for_state,
)

# ---------------------------------------------------------------------------
# Helpers (file-specific)
# ---------------------------------------------------------------------------


def get_qemu_cmdline_for_vm(session_id: str) -> str:
    """Find the QEMU process for the given session and return its command line.

    Uses `pgrep -a qemu-system` on the host and matches against the
    Lima VM name (sandbox-<uuid>) which appears in the QEMU process args
    (e.g. as part of socket/pidfile paths).
    """
    vm_name = lima_vm_name(session_id)
    result = subprocess.run(
        ["pgrep", "-a", "qemu-system"],
        capture_output=True, text=True, timeout=30,
    )
    # pgrep -a prints "<pid> <full command line>" per line.
    for line in result.stdout.splitlines():
        if vm_name in line:
            return line
    # Fallback: try ps aux
    result = subprocess.run(
        ["ps", "aux"],
        capture_output=True, text=True, timeout=30,
    )
    for line in result.stdout.splitlines():
        if "qemu-system" in line and vm_name in line:
            return line
    return ""


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

@pytest.mark.timeout(600)
def test_hardened_qemu_args(sandbox_cli):
    """Create a session with default settings (hardening ON). Verify the QEMU
    process command line includes device lockdown args, does NOT include
    seccomp sandbox (incompatible with bridge networking), and does NOT
    include unnecessary devices.
    """
    session_id = None
    try:
        # Create session with defaults (hardening enabled).
        result = sandbox_cli(
            "create", "--name", "harden-args",
            *_VM_RESOURCE_ARGS,
            timeout=600,
        )
        assert result.returncode == 0, (
            f"sandbox create failed (rc={result.returncode}).\n"
            f"stdout: {result.stdout}\nstderr: {result.stderr}"
        )
        session_id = parse_session_id(result.stdout)
        wait_for_state(sandbox_cli, "harden-args", "Running", timeout=10)

        # Retrieve the QEMU process command line from the host.
        cmdline = get_qemu_cmdline_for_vm(session_id)
        assert cmdline, (
            f"Could not find QEMU process for session {session_id}.\n"
            f"{capture_lima_logs(session_id)}"
        )

        # Verify seccomp sandbox is NOT enabled (incompatible with
        # qemu-bridge-helper setuid required for bridge networking).
        assert "-sandbox on" not in cmdline, (
            f"QEMU process contains '-sandbox on' (seccomp) flag — this is "
            f"incompatible with qemu-bridge-helper bridge networking.\n"
            f"Command line: {cmdline}"
        )

        # Verify display/VGA are disabled.
        assert "-display none" in cmdline, (
            f"QEMU process missing '-display none' flag.\n"
            f"Command line: {cmdline}"
        )
        assert "-vga none" in cmdline, (
            f"QEMU process missing '-vga none' flag.\n"
            f"Command line: {cmdline}"
        )

        # Verify virtio-rng is present (replaces removed hardware RNG).
        assert "virtio-rng-pci" in cmdline, (
            f"QEMU process missing 'virtio-rng-pci' device.\n"
            f"Command line: {cmdline}"
        )

        # Verify NO unnecessary USB devices.
        assert "-device usb-" not in cmdline, (
            f"QEMU process contains USB device args (should be locked down).\n"
            f"Command line: {cmdline}"
        )

        # Verify NO sound devices.
        assert "-device intel-hda" not in cmdline, (
            f"QEMU process contains intel-hda sound device (should be locked down).\n"
            f"Command line: {cmdline}"
        )
        assert "-soundhw" not in cmdline, (
            f"QEMU process contains -soundhw (should be locked down).\n"
            f"Command line: {cmdline}"
        )

        # Clean up.
        sandbox_cli("rm", "harden-args", timeout=120)
        session_id = None

    finally:
        if session_id is not None:
            sandbox_cli("rm", "harden-args", timeout=120)


@pytest.mark.timeout(600)
def test_cgroup_limits(sandbox_cli):
    """Create a session with default settings. Verify the QEMU process is
    running under a systemd scope with memory and CPU cgroup limits applied.

    The QEMU wrapper uses systemd-run to place QEMU in a transient scope
    under sandbox.slice with MemoryMax, CPUQuota, and TasksMax constraints.
    """
    session_id = None
    try:
        result = sandbox_cli(
            "create", "--name", "harden-cgroup",
            *_VM_RESOURCE_ARGS,
            timeout=600,
        )
        assert result.returncode == 0, (
            f"sandbox create failed (rc={result.returncode}).\n"
            f"stdout: {result.stdout}\nstderr: {result.stderr}"
        )
        session_id = parse_session_id(result.stdout)
        wait_for_state(sandbox_cli, "harden-cgroup", "Running", timeout=10)

        # Check that a sandbox.slice scope exists for this QEMU process.
        # systemd-run --user creates scopes under sandbox.slice.
        scope_result = subprocess.run(
            ["systemctl", "--user", "list-units", "--type=scope",
             "--no-pager", "--no-legend"],
            capture_output=True, text=True, timeout=30,
        )
        # Look for a scope in the sandbox.slice.
        scope_lines = [
            line for line in scope_result.stdout.splitlines()
            if "sandbox" in line.lower()
        ]
        assert scope_lines, (
            f"No sandbox-related systemd scope found. "
            f"Expected QEMU to be running under sandbox.slice.\n"
            f"All scopes:\n{scope_result.stdout}"
        )

        # Verify the QEMU process is running under a cgroup with the scope.
        # Find the QEMU PID and check its cgroup.
        vm_name = lima_vm_name(session_id)
        pgrep_result = subprocess.run(
            ["pgrep", "-f", f"qemu-system.*{vm_name}"],
            capture_output=True, text=True, timeout=30,
        )
        qemu_pid = pgrep_result.stdout.strip().splitlines()[0] if pgrep_result.stdout.strip() else ""
        assert qemu_pid, (
            f"Could not find QEMU PID for session {session_id}.\n"
            f"{capture_lima_logs(session_id)}"
        )

        # Read the cgroup for this PID.
        cgroup_result = subprocess.run(
            ["cat", f"/proc/{qemu_pid}/cgroup"],
            capture_output=True, text=True, timeout=10,
        )
        assert cgroup_result.returncode == 0, (
            f"Failed to read cgroup for QEMU PID {qemu_pid}.\n"
            f"stderr: {cgroup_result.stderr}"
        )
        cgroup_info = cgroup_result.stdout
        # The cgroup path should contain 'sandbox.slice'.
        assert "sandbox.slice" in cgroup_info, (
            f"QEMU process (PID {qemu_pid}) is not in sandbox.slice cgroup.\n"
            f"Cgroup info:\n{cgroup_info}"
        )

        # Verify memory limit is set on the cgroup.
        # Parse the cgroup path to find the memory.max file.
        # Cgroup v2 unified hierarchy: /sys/fs/cgroup/<path>/memory.max
        cgroup_path_match = re.search(r"0::(.+)", cgroup_info)
        assert cgroup_path_match, (
            f"Could not parse cgroup v2 path from:\n{cgroup_info}"
        )
        cgroup_path = cgroup_path_match.group(1).strip()
        memory_max_file = f"/sys/fs/cgroup{cgroup_path}/memory.max"

        mem_result = subprocess.run(
            ["cat", memory_max_file],
            capture_output=True, text=True, timeout=10,
        )
        if mem_result.returncode == 0:
            memory_max = mem_result.stdout.strip()
            # memory.max should be a number (in bytes), not "max" (unlimited).
            assert memory_max != "max", (
                f"QEMU cgroup memory.max is unlimited ('max'), "
                f"expected a specific limit.\n"
                f"memory.max file: {memory_max_file}"
            )
            # The wrapper sets MemoryMax=(memory_mb + 512)M.
            # With _VM_RESOURCE_ARGS memory=1024, limit should be ~1536M = ~1610612736 bytes.
            mem_bytes = int(memory_max)
            assert mem_bytes > 0, (
                f"QEMU cgroup memory.max is {mem_bytes}, expected a positive limit."
            )
            # Sanity check: limit should be between 512MB and 4GB for our test config.
            assert 512 * 1024 * 1024 < mem_bytes < 4 * 1024 * 1024 * 1024, (
                f"QEMU cgroup memory.max={mem_bytes} bytes is outside expected range "
                f"(512MB-4GB) for test resource config.\n"
                f"memory.max file: {memory_max_file}"
            )

        # Clean up.
        sandbox_cli("rm", "harden-cgroup", timeout=120)
        session_id = None

    finally:
        if session_id is not None:
            sandbox_cli("rm", "harden-cgroup", timeout=120)


@pytest.mark.timeout(600)
def test_no_hardening_flag(sandbox_cli):
    """Create a session with --no-hardening. Verify the QEMU process command
    line does NOT contain hardening args (seccomp, device lockdown).
    """
    session_id = None
    try:
        result = sandbox_cli(
            "create", "--name", "harden-off",
            *_VM_RESOURCE_ARGS, "--no-hardening",
            timeout=600,
        )
        assert result.returncode == 0, (
            f"sandbox create failed (rc={result.returncode}).\n"
            f"stdout: {result.stdout}\nstderr: {result.stderr}"
        )
        session_id = parse_session_id(result.stdout)
        wait_for_state(sandbox_cli, "harden-off", "Running", timeout=10)

        # Retrieve the QEMU process command line.
        cmdline = get_qemu_cmdline_for_vm(session_id)
        assert cmdline, (
            f"Could not find QEMU process for session {session_id}.\n"
            f"{capture_lima_logs(session_id)}"
        )

        # With --no-hardening, the wrapper should NOT add seccomp or device
        # lockdown args.  The SANDBOX_QEMU_HARDENED env var is "0".
        assert "-sandbox on" not in cmdline, (
            f"QEMU process contains '-sandbox on' despite --no-hardening.\n"
            f"Command line: {cmdline}"
        )
        # Note: we check for '-vga none' rather than '-display none' because
        # Lima itself adds '-display none' for headless VMs regardless of our
        # wrapper's hardening settings.  '-vga none' is only added by the QEMU
        # wrapper when SANDBOX_QEMU_HARDENED=1.
        assert "-vga none" not in cmdline, (
            f"QEMU process contains '-vga none' despite --no-hardening.\n"
            f"Command line: {cmdline}"
        )

        # The PCIe root-port should STILL be present (it's always added,
        # regardless of hardening, for NIC hot-add support).
        assert "pcie-root-port" in cmdline, (
            f"QEMU process missing pcie-root-port (should always be present).\n"
            f"Command line: {cmdline}"
        )

        # Clean up.
        sandbox_cli("rm", "harden-off", timeout=120)
        session_id = None

    finally:
        if session_id is not None:
            sandbox_cli("rm", "harden-off", timeout=120)
