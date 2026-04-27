"""Host CPU + RAM snapshot with the lite-mode 80% ceiling pre-computed.

Mirrors the daemon's ``compute_default_resource_limits`` in
``sandboxd/sandbox-core/src/backend/container.rs`` so E2E tests can
verify the daemon's choice of resource defaults without re-implementing
the formula by hand at every assertion site.

The formula is the spec § "Resource defaults — container only":

* ``memory_mb = floor(host_ram_mb * 0.8)``  (whole MB)
* ``cpus = round(host_cpus * 0.8 * 10) / 10``  (one decimal place)

The daemon caches the result on ``ContainerRuntime`` at startup (see
``ContainerRuntime::new``) and substitutes it whenever a request leaves
``cpus``/``memory_mb`` at 0 (the "unset" sentinel). Surfacing the same
formula here lets ``test_lite_resource_defaults_match_host_80pct``
assert the ceiling end-to-end without depending on cgroup introspection.
"""

from __future__ import annotations

import math
import os
from dataclasses import dataclass


@dataclass(frozen=True)
class HostResources:
    """Snapshot of host CPU + RAM with the lite-mode 80% defaults
    pre-computed.

    Attributes:
        cpus_total: Number of logical CPUs reported by the OS.
        memory_mb_total: Total RAM in megabytes (parsed from
            ``/proc/meminfo``).
        expected_lite_cpus: ``cpus_total * 0.8`` rounded to one decimal
            place — matches the daemon-side rounding so Docker's
            ``--cpus`` formatter (``{:.1}``) sees the same value.
        expected_lite_memory_mb: ``memory_mb_total * 0.8`` floored to a
            whole MB.
    """

    cpus_total: int
    memory_mb_total: int
    expected_lite_cpus: float
    expected_lite_memory_mb: int

    @classmethod
    def from_host(cls) -> "HostResources":
        """Snapshot the current host's CPU + RAM and pre-compute the
        80% ceiling.

        Falls back to ``cpus_total = 1`` if ``os.cpu_count()`` returns
        ``None`` — matches the daemon's ``read_host_cpus_or_default``
        fallback shape (the daemon falls back to 2 CPUs internally, but
        either fallback only fires on hosts where the helper itself
        cannot be trusted, so the test asserting "match the daemon"
        would fail with a mismatched fallback regardless; the more
        important property here is determinism on real Linux hosts).
        """
        cpus_total = os.cpu_count() or 1
        memory_mb_total = _read_meminfo_total_mb()

        # The daemon-side formula uses f64 arithmetic; mirror exactly.
        # See compute_default_resource_limits in
        # sandboxd/sandbox-core/src/backend/container.rs:945.
        expected_lite_memory_mb = math.floor(memory_mb_total * 0.8)
        expected_lite_cpus = round(cpus_total * 0.8 * 10) / 10

        return cls(
            cpus_total=cpus_total,
            memory_mb_total=memory_mb_total,
            expected_lite_cpus=expected_lite_cpus,
            expected_lite_memory_mb=expected_lite_memory_mb,
        )


def _read_meminfo_total_mb() -> int:
    """Parse ``/proc/meminfo`` and return ``MemTotal`` in megabytes.

    Matches the daemon's ``read_host_ram_mb_or_default`` (kB → MB via
    integer division by 1024), so the E2E expected value lines up with
    the daemon's stored default to the byte.
    """
    with open("/proc/meminfo", "r", encoding="utf-8") as f:
        for line in f:
            if line.startswith("MemTotal:"):
                # Format: "MemTotal:        16329048 kB"
                parts = line.split()
                if len(parts) >= 3 and parts[2].lower() == "kb":
                    kb = int(parts[1])
                    return kb // 1024
    raise RuntimeError(
        "/proc/meminfo did not contain a MemTotal line; cannot snapshot "
        "host RAM for the HostResources helper."
    )
