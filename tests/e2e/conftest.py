"""Shared fixtures for sandbox E2E tests."""

from __future__ import annotations

import json
import os
import signal
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
CARGO_WORKSPACE = PROJECT_ROOT / "sandboxd"
SANDBOXD_BIN = CARGO_WORKSPACE / "target" / "debug" / "sandboxd"
SANDBOX_BIN = CARGO_WORKSPACE / "target" / "debug" / "sandbox"

# Maximum time to wait for the daemon socket to appear (seconds).
DAEMON_STARTUP_TIMEOUT = 10


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class SandboxBinaries:
    """Paths to the compiled sandbox binaries."""
    sandboxd: Path
    sandbox: Path


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="session")
def sandbox_binaries() -> SandboxBinaries:
    """Build the Rust workspace and return paths to sandboxd and sandbox binaries.

    Scoped to the test session so we only build once.
    """
    env = os.environ.copy()
    # Ensure cargo is available
    cargo_env = Path.home() / ".cargo" / "env"
    if cargo_env.exists():
        # Source the cargo env to get the PATH
        result = subprocess.run(
            ["bash", "-c", f"source {cargo_env} && echo $PATH"],
            capture_output=True, text=True, check=True,
        )
        env["PATH"] = result.stdout.strip()

    subprocess.run(
        ["cargo", "build", "--workspace"],
        cwd=str(CARGO_WORKSPACE),
        env=env,
        check=True,
        timeout=300,
        capture_output=True,
    )

    assert SANDBOXD_BIN.exists(), f"sandboxd binary not found at {SANDBOXD_BIN}"
    assert SANDBOX_BIN.exists(), f"sandbox binary not found at {SANDBOX_BIN}"

    return SandboxBinaries(sandboxd=SANDBOXD_BIN, sandbox=SANDBOX_BIN)


@pytest.fixture
def sandbox_daemon(sandbox_binaries: SandboxBinaries, tmp_path: Path):
    """Start a sandboxd instance with a temporary socket and base-dir.

    Yields a dict with:
      - socket: path to the Unix socket
      - base_dir: path to the temporary base directory
      - process: the Popen object for the daemon

    Shuts down the daemon (SIGTERM) and cleans up on teardown, even if the
    test fails.  Also force-deletes any Lima VMs that were created during the
    test (identified by the daemon's session database).
    """
    socket_path = tmp_path / "sandboxd.sock"
    base_dir = tmp_path / "state"
    base_dir.mkdir(parents=True, exist_ok=True)

    proc = subprocess.Popen(
        [
            str(sandbox_binaries.sandboxd),
            "--socket", str(socket_path),
            "--base-dir", str(base_dir),
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    # Wait for the socket to appear.
    deadline = time.monotonic() + DAEMON_STARTUP_TIMEOUT
    while time.monotonic() < deadline:
        if socket_path.exists():
            break
        # Check if the daemon crashed.
        if proc.poll() is not None:
            stdout = proc.stdout.read().decode() if proc.stdout else ""
            stderr = proc.stderr.read().decode() if proc.stderr else ""
            pytest.fail(
                f"sandboxd exited early (code {proc.returncode}).\n"
                f"stdout: {stdout}\nstderr: {stderr}"
            )
        time.sleep(0.1)
    else:
        proc.kill()
        pytest.fail(f"sandboxd socket did not appear within {DAEMON_STARTUP_TIMEOUT}s")

    info = {
        "socket": str(socket_path),
        "base_dir": str(base_dir),
        "process": proc,
    }

    yield info

    # --- Teardown ---

    # Collect any Lima VM names from the daemon's session db so we can clean
    # them up even if the test forgot to `rm`.
    vm_names_to_clean: list[str] = []
    try:
        lima_output = subprocess.run(
            ["limactl", "list", "--json"],
            capture_output=True, text=True, timeout=30,
        )
        if lima_output.stdout.strip():
            for line in lima_output.stdout.strip().splitlines():
                try:
                    entry = json.loads(line)
                    name = entry.get("name", "")
                    if name.startswith("sandbox-"):
                        vm_names_to_clean.append(name)
                except json.JSONDecodeError:
                    pass
    except Exception:
        pass

    # Send SIGTERM and wait for graceful shutdown.
    if proc.poll() is None:
        proc.send_signal(signal.SIGTERM)
        try:
            proc.wait(timeout=15)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=5)

    # Force-delete any leftover VMs.
    for vm_name in vm_names_to_clean:
        try:
            subprocess.run(
                ["limactl", "delete", "--force", vm_name],
                capture_output=True, timeout=60,
            )
        except Exception:
            pass


@pytest.fixture
def sandbox_cli(sandbox_binaries: SandboxBinaries, sandbox_daemon):
    """Return a helper that invokes the sandbox CLI with the correct --socket.

    The helper returns a subprocess.CompletedProcess.  By default it does NOT
    raise on non-zero exit (check=False) so tests can inspect the result.
    """
    socket_path = sandbox_daemon["socket"]

    def run(
        *args: str,
        check: bool = False,
        timeout: int = 600,
    ) -> subprocess.CompletedProcess:
        return subprocess.run(
            [str(sandbox_binaries.sandbox), "--socket", socket_path, *args],
            capture_output=True,
            text=True,
            check=check,
            timeout=timeout,
        )

    return run
