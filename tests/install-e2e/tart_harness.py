"""Tart-VM primitives for the macOS install.sh e2e harness.

This module is the macOS analog of the Lima primitives in ``conftest.py``.
Where the Linux harness boots a fresh Lima/QEMU guest per test, copies the
locally-built release tarball + the unmodified install.sh into it, and runs
the install path end-to-end, this module does the same against a fresh
**Tart** macOS guest on Apple Silicon.

Key differences from the Lima path, and how they are handled:

* **No ``limactl copy`` / ``limactl shell``.** Tart guests are reached over
  SSH on the guest's vmnet IP (``tart ip``). The cirruslabs base image ships
  ``admin``/``admin`` with passwordless sudo; on first contact we seed an
  ephemeral ed25519 public key into the guest's ``authorized_keys`` (via
  ``expect``, since the base image only offers password auth initially) and
  use key auth for everything after. File transfer is ``scp`` over the same
  key.

* **Sigstore-stack reachability.** The local Sigstore stack runs on the host
  under ``docker compose`` and publishes Fulcio (:5555) / Rekor (:3000) on the
  host's ``127.0.0.1`` only — which a Tart guest cannot reach (that loopback
  is the guest's own). Tart's default *shared* (NAT) networking puts the guest
  on a ``192.168.N.0/24`` segment whose gateway (``.1``) is the host. We run a
  tiny host-side TCP relay bound to ``0.0.0.0:PORT`` that forwards to
  ``127.0.0.1:PORT`` for each sigstore port, so the guest reaches the stack at
  ``<gateway-ip>:PORT``. This is the macOS analog of Lima's
  ``hostResolver.hosts`` → ``host.lima.internal`` indirection — see
  ``SigstoreRelay`` below and ``stage_sigstore_trust_material_in_tart_vm`` in
  ``conftest.py``.

* **macOS prerequisites.** install.sh's Darwin ``check_prereqs`` hard-requires
  ``socket_vmnet`` (at ``/opt/homebrew/opt/socket_vmnet/bin/socket_vmnet``) and
  ``limactl`` >= 1.2.0; QEMU is *not* checked (Lima bundles it on macOS) and
  cosign is auto-bootstrapped (pinned download) or read from the staged copy.
  The factory ``brew install``s the two hard prereqs.
"""

from __future__ import annotations

import os
import shutil
import socket
import subprocess
import threading
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path


# Homebrew on Apple Silicon lives under /opt/homebrew; non-login ssh sessions
# don't pick it up, so we prepend it explicitly for every guest command.
GUEST_PATH_PREFIX = "/opt/homebrew/bin:/opt/homebrew/sbin:/usr/local/bin"

TART_BASE_IMAGE = os.environ.get(
    "SANDBOX_TART_BASE_IMAGE",
    "ghcr.io/cirruslabs/macos-sequoia-base:latest",
)

# Per-VM resources. macOS guests need a few GB; the host is 8-16 GB so we
# stay modest. Overridable via env for constrained hosts.
TART_VM_CPUS = int(os.environ.get("SANDBOX_TART_VM_CPUS", "4"))
TART_VM_MEMORY_MIB = int(os.environ.get("SANDBOX_TART_VM_MEMORY_MIB", "6144"))

VM_BOOT_TIMEOUT = 240  # seconds to acquire an IP + open ssh
SSH_READY_TIMEOUT = 180


def _run(cmd, *, check=True, timeout=120, capture=True, env=None):
    """subprocess.run wrapper mirroring conftest._run (text mode)."""
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
            f"stdout:\n{result.stdout!r}\n"
            f"stderr:\n{result.stderr!r}"
        )
    return result


def _sh_quote(s):
    """POSIX-safe single-quote wrap (mirrors conftest._sh_quote)."""
    return "'" + str(s).replace("'", r"'\''") + "'"


# ---------------------------------------------------------------------------
# Host-side TCP relay: <gateway-ip>:PORT  ->  127.0.0.1:PORT
# ---------------------------------------------------------------------------
#
# colima / docker on this host publish the sigstore ports on 127.0.0.1 only.
# A Tart guest's loopback is its own, so it cannot reach them there. Binding
# the relay's listener to 0.0.0.0 exposes the forwarded port on every host
# interface — including the vmnet bridge gateway the guest routes through —
# without mutating the shared docker-compose.yml (which the Linux harness also
# consumes). Pure stdlib; no socat/external dep.


class SigstoreRelay:
    """A set of host-side TCP forwarders for the sigstore stack ports.

    For each ``port`` it opens a listener on ``0.0.0.0:port`` and pumps bytes
    bidirectionally to ``127.0.0.1:port``. Threads are daemonised; ``stop()``
    closes the listeners and lets the pumps drain.
    """

    def __init__(self, ports):
        self._ports = list(ports)
        self._listeners = []
        self._threads = []
        self._stop = threading.Event()

    def start(self):
        for port in self._ports:
            lsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            lsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            lsock.bind(("0.0.0.0", port))
            lsock.listen(64)
            lsock.settimeout(0.5)
            self._listeners.append(lsock)
            t = threading.Thread(
                target=self._accept_loop, args=(lsock, port), daemon=True
            )
            t.start()
            self._threads.append(t)
        return self

    def _accept_loop(self, lsock, port):
        while not self._stop.is_set():
            try:
                client, _ = lsock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(
                target=self._handle, args=(client, port), daemon=True
            ).start()

    def _handle(self, client, port):
        try:
            upstream = socket.create_connection(("127.0.0.1", port), timeout=10)
        except OSError:
            client.close()
            return

        def pump(src, dst):
            try:
                while True:
                    data = src.recv(65536)
                    if not data:
                        break
                    dst.sendall(data)
            except OSError:
                pass
            finally:
                for s in (src, dst):
                    try:
                        s.shutdown(socket.SHUT_RDWR)
                    except OSError:
                        pass

        ta = threading.Thread(target=pump, args=(client, upstream), daemon=True)
        tb = threading.Thread(target=pump, args=(upstream, client), daemon=True)
        ta.start()
        tb.start()

    def stop(self):
        self._stop.set()
        for lsock in self._listeners:
            try:
                lsock.close()
            except OSError:
                pass


# ---------------------------------------------------------------------------
# Tart VM lifecycle primitives.
# ---------------------------------------------------------------------------


def tart_vm_name(prefix="iet"):
    """A short, unique Tart VM name."""
    return f"sb-{prefix}-{uuid.uuid4().hex[:8]}"


def tart_clone(base, name):
    """Clone ``base`` to a local VM ``name`` (COW; near-instant on APFS)."""
    _run(["tart", "clone", base, name], timeout=600)


def tart_set_resources(name, *, cpus=TART_VM_CPUS, memory_mib=TART_VM_MEMORY_MIB):
    """Set CPU/memory on the cloned VM before boot."""
    _run(
        ["tart", "set", name, "--cpu", str(cpus), "--memory", str(memory_mib)],
        timeout=60,
    )


def tart_run_headless(name, log_path, *, nested=False):
    """Start ``tart run --no-graphics [--nested] <name>`` detached.

    Returns the Popen handle. The process stays alive for the VM's lifetime;
    teardown stops the VM (``tart stop``) which causes this to exit.

    ``nested=True`` adds ``--nested`` so the guest gets nested virtualization
    — REQUIRED for the daemon's gateway QEMU VM (which uses ``accel=hvf``) to
    boot inside the Tart guest. Only available on **M3+** hosts; ``tart run``
    errors on M1/M2 ("Nested virtualization is available for Mac with the M3
    chip, and later"). Gate via ``host_supports_nested_virt()``.
    """
    log_f = open(log_path, "w")
    argv = ["tart", "run", "--no-graphics"]
    if nested:
        argv.append("--nested")
    argv.append(name)
    proc = subprocess.Popen(argv, stdout=log_f, stderr=subprocess.STDOUT)
    return proc


_NESTED_SUPPORT_CACHE = None


def host_supports_nested_virt():
    """Return True iff the host can run a Tart guest with --nested (M3+).

    The daemon's macOS full backend boots a QEMU gateway VM with
    ``-machine virt,accel=hvf``. Inside a Tart guest, Hypervisor.framework is
    only exposed when the guest was started with ``--nested``, which Apple's
    Virtualization.framework supports on **M3 and later** only. On M1/M2 the
    daemon's mandatory gateway VM cannot boot, so the daemon can never reach
    "healthy" inside a Tart guest. Detection probes the CPU brand string;
    cached after the first call.
    """
    global _NESTED_SUPPORT_CACHE
    if _NESTED_SUPPORT_CACHE is not None:
        return _NESTED_SUPPORT_CACHE
    import re as _re
    brand = subprocess.run(
        ["sysctl", "-n", "machdep.cpu.brand_string"],
        capture_output=True, text=True,
    ).stdout.strip()
    m = _re.search(r"Apple M(\d+)", brand)
    _NESTED_SUPPORT_CACHE = bool(m) and int(m.group(1)) >= 3
    return _NESTED_SUPPORT_CACHE


def tart_ip(name, *, timeout=VM_BOOT_TIMEOUT):
    """Poll ``tart ip <name>`` until it returns an address."""
    deadline = time.monotonic() + timeout
    last = ""
    while time.monotonic() < deadline:
        r = subprocess.run(
            ["tart", "ip", name], capture_output=True, text=True, timeout=20
        )
        ip = r.stdout.strip()
        if ip:
            return ip
        last = r.stderr.strip()
        time.sleep(2)
    raise AssertionError(f"tart ip {name} did not return an address in {timeout}s: {last!r}")


def tart_stop(name):
    """Stop a running Tart VM. Idempotent (ignores 'not running')."""
    subprocess.run(["tart", "stop", name], capture_output=True, text=True, timeout=60)


def tart_delete(name):
    """Delete a Tart VM. Idempotent."""
    subprocess.run(["tart", "delete", name], capture_output=True, text=True, timeout=120)


def host_gateway_for_ip(vm_ip):
    """Return the host's gateway IP for a guest on a /24 vmnet segment.

    Tart's shared (NAT) networking puts the guest on ``192.168.N.0/24`` whose
    ``.1`` is the host (the vmnet bridge gateway). We derive it from the
    guest's IP rather than parsing ifconfig because the segment number varies
    per boot and per host.
    """
    octets = vm_ip.split(".")
    if len(octets) != 4:
        raise AssertionError(f"unexpected VM IP shape: {vm_ip!r}")
    return ".".join(octets[:3] + ["1"])


# ---------------------------------------------------------------------------
# SSH key seeding + transport.
# ---------------------------------------------------------------------------

SSH_COMMON_OPTS = [
    "-o", "StrictHostKeyChecking=no",
    "-o", "UserKnownHostsFile=/dev/null",
    "-o", "LogLevel=ERROR",
]


def wait_for_ssh(ip, *, timeout=SSH_READY_TIMEOUT):
    """Block until TCP port 22 on ``ip`` accepts connections."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with socket.create_connection((ip, 22), timeout=3):
                return
        except OSError:
            time.sleep(2)
    raise AssertionError(f"ssh port 22 on {ip} did not open within {timeout}s")


def generate_keypair(dest_dir):
    """Generate an ephemeral ed25519 keypair under ``dest_dir``.

    Returns the private-key Path. The base image's ``admin`` account uses
    password auth out of the box; we seed the public key once and use the
    private key thereafter.
    """
    dest_dir.mkdir(parents=True, exist_ok=True)
    key = dest_dir / "id_ed25519"
    if key.exists():
        return key
    _run(
        ["ssh-keygen", "-t", "ed25519", "-N", "", "-f", str(key), "-q"],
        timeout=30,
    )
    key.chmod(0o600)
    return key


def seed_ssh_key(ip, pubkey_path, *, password="admin", user="admin", timeout=60):
    """Seed ``pubkey_path`` into ``user``'s authorized_keys on the guest.

    The cirruslabs base image only offers password auth initially. We use
    ``expect`` to drive a single password login that appends our public key.
    ``expect`` is part of the macOS base install (``/usr/bin/expect``).

    The remote command is passed as one ssh argument and stays free of the
    host shell's ``&&`` so ``expect``'s ``spawn`` word-splitting doesn't break
    the command chain. We force ``PreferredAuthentications=password`` /
    ``PubkeyAuthentication=no`` so the very first contact (before any key is
    installed) doesn't waste auth attempts on absent keys.
    """
    if shutil.which("expect") is None:
        raise AssertionError(
            "expect not found on host — required to seed the ssh key into the "
            "Tart base image (which ships password-only auth initially)"
        )
    pub = Path(pubkey_path).read_text().strip()
    remote = (
        "umask 077; mkdir -p $HOME/.ssh; "
        f"printf '%s\\n' {_sh_quote(pub)} >> $HOME/.ssh/authorized_keys; "
        "echo SEEDED_OK"
    )
    ssh_argv = " ".join(
        SSH_COMMON_OPTS
        + [
            "-o", "PreferredAuthentications=password",
            "-o", "PubkeyAuthentication=no",
            "-o", "ConnectTimeout=10",
        ]
    )
    expect_script = f"""\
set timeout {timeout}
spawn ssh {ssh_argv} {user}@{ip} {{{remote}}}
expect {{
  -re "(?i)password" {{ send "{password}\\r"; exp_continue }}
  "SEEDED_OK" {{ puts "\\nSEED_DONE"; exp_continue }}
  timeout {{ puts "\\nSEED_TIMEOUT"; exit 1 }}
  eof {{}}
}}
"""
    r = subprocess.run(
        ["expect", "-"],
        input=expect_script,
        capture_output=True,
        text=True,
        timeout=timeout + 15,
    )
    if "SEED_DONE" not in r.stdout:
        raise AssertionError(
            f"ssh key seeding failed for {user}@{ip}\n"
            f"stdout:\n{r.stdout}\nstderr:\n{r.stderr}"
        )


@dataclass
class TartVM:
    """Handle on a running Tart macOS VM, with Lima-VM-shaped helpers.

    Mirrors conftest.VM's surface (``shell``, ``cp``) so test code reads the
    same regardless of backend, but transport is SSH/scp over the guest IP.
    """

    name: str
    ip: str
    key_path: Path
    user: str = "admin"
    gateway_ip: str = field(default="")

    def __post_init__(self):
        if not self.gateway_ip:
            self.gateway_ip = host_gateway_for_ip(self.ip)

    def _ssh_base(self):
        return [
            "ssh",
            *SSH_COMMON_OPTS,
            "-i",
            str(self.key_path),
            "-o",
            "BatchMode=yes",
            "-o",
            "ConnectTimeout=15",
            f"{self.user}@{self.ip}",
        ]

    def shell(self, command, *, check=False, timeout=180, user=None):
        """Run a command in the guest over SSH.

        Prepends the Homebrew prefix to PATH (non-login ssh sessions don't
        inherit it). ``user`` (if given) wraps in ``sudo -u <user>`` to
        exercise the post-install operator view, mirroring conftest.lima_shell.
        """
        inner = f"export PATH={GUEST_PATH_PREFIX}:$PATH; {command}"
        if user is not None:
            wrapped = f"sudo -u {user} -- sh -c {_sh_quote(inner)}"
            remote = wrapped
        else:
            remote = inner
        argv = self._ssh_base() + [remote]
        return _run(argv, check=check, timeout=timeout)

    def cp(self, src, dst):
        """Copy a host file into the guest via scp.

        scp can only write where the ``admin`` user can write, so absolute
        system paths (``/usr/local/...``) must be staged to a writable spot
        (e.g. /tmp or ~) and ``sudo install``-ed into place by the caller —
        the same pattern install.sh's tests use. This helper targets the
        guest path verbatim; callers pass guest-writable destinations.
        """
        argv = [
            "scp",
            *SSH_COMMON_OPTS,
            "-i",
            str(self.key_path),
            "-o",
            "BatchMode=yes",
            str(src),
            f"{self.user}@{self.ip}:{dst}",
        ]
        return _run(argv, timeout=300)
