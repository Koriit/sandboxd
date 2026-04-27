"""Probes for the local Docker daemon's runtime mode.

E2E tests that assert UID-alignment semantics (spec § Workspace,
``2026-04-22-lite-mode-container-backend-design-spec.md`` lines
572–574) only hold under default-hardened Docker. Rootless Docker
remaps the container uid through ``/etc/subuid``, so a file written
from inside the container as ``host_uid`` lands on the host as a
sub-uid — the test would fail through no fault of the lite backend.

The lite spec calls out rootless Docker as out of scope (§
"Out of scope" line 1175: *"Lite's target is **default-hardened
Docker**. Alternative runtimes are a separate design."*); tests
guarded by :func:`is_rootless_docker` skip on rootless rigs and run
as live coverage on the spec's actual target environment.

The probe runs ``docker info --format '{{.SecurityOptions}}'`` and
matches ``name=rootless`` in the resulting list. The result is
cached at module level: re-shelling out for every test would add
~50ms per call to no benefit.
"""

from __future__ import annotations

import subprocess

__all__ = ["is_rootless_docker"]


# Module-level cache. ``None`` means "not yet probed"; once probed
# the result is cached as a ``bool`` for the lifetime of the pytest
# process. Tests run inside a single ``pytest`` invocation so the
# Docker daemon mode cannot change underneath us mid-suite.
_cached: bool | None = None


def is_rootless_docker() -> bool:
    """Return ``True`` if the local Docker daemon is running in
    rootless mode, ``False`` otherwise.

    Implementation: ``docker info --format '{{.SecurityOptions}}'``
    returns a Go-formatted list like
    ``[name=seccomp,profile=default name=rootless]``; we look for
    the literal substring ``name=rootless`` in the captured stdout.

    On any failure to invoke ``docker info`` (binary missing, daemon
    unreachable, non-zero exit) the function returns ``False`` —
    the intent is "skip on confirmed rootless"; if we cannot
    confirm, the caller (the test) should run and fail loudly
    rather than skip silently. The session-scoped
    ``_preflight_checks`` fixture in ``conftest.py`` already skips
    the entire suite when Docker is unavailable, so a ``False``
    return here in practice means "Docker is up and is not
    rootless".
    """
    global _cached
    if _cached is not None:
        return _cached

    try:
        result = subprocess.run(
            ["docker", "info", "--format", "{{.SecurityOptions}}"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        _cached = False
        return _cached

    if result.returncode != 0:
        _cached = False
        return _cached

    _cached = "name=rootless" in result.stdout
    return _cached
