"""
Structured JSONL event emission for mitmproxy addons.

Part of the observability pipeline: the gateway's CoreDNS plugin,
Envoy access logs, and mitmproxy addons each emit one JSON-encoded event
per decision into ``/var/log/gateway/events/<layer>.jsonl``.  sandboxd's
per-session ingester tails these files, stamps the session ID based on
the source IP, and republishes into its in-process event bus for HTTP
API / CLI consumers.

This module is the mitmproxy half.  It is additive to the existing
``logger.info`` lines in ``policy_addon.py`` and ``passthrough_addon.py``
(which remain in place for human operators tailing container logs) —
the JSONL stream is the machine-readable contract.

Event envelope (one JSON object per line, UTF-8, newline-terminated):

    {
      "timestamp":  "2026-04-22T09:45:00.123Z",
      "layer":      "mitmproxy",
      "event":      "request_allowed" | "request_denied",
      "host":       "api.github.com",
      "port":       443,
      "method":     "GET",
      "path":       "/repos/foo",
      "reason":     "host not in policy",      // deny only
      "client_ip":  "192.168.87.2"             // or null
    }

- ``timestamp`` is RFC 3339 with millisecond precision and a literal
  ``Z`` suffix; generated from :func:`time.time` (UTC) — the gateway
  container's clock is the event timeline reference.
- ``client_ip`` is ``flow.client_conn.peername[0]`` when available; the
  field is **always present** and serialized as JSON ``null`` when the
  socket peer is unknown.  Do not rely on the ``session`` field here —
  sandboxd stamps that at ingest via ``vm_ip_map.lookup(client_ip)``, to
  keep the gateway container session-agnostic (it serves multiple
  sessions over its lifetime).
- ``reason`` appears only on ``request_denied`` and matches the string
  used in the addon's ``logger.warning`` line character-for-character.
  This is externally observable — operators and the ``sandbox events
  --decision=deny`` CLI rely on the exact text.

Thread safety: each decision is written under a per-emitter lock so
concurrent flows never interleave partial lines.  ``buffering=1``
enables line-buffering on text-mode files; we also call ``flush()``
under the lock for parity across Python builds that handle buffered
text I/O slightly differently.
"""

from __future__ import annotations

import json
import logging
import threading
import time
from typing import Any, Optional

logger = logging.getLogger("mitmproxy_events")


def _rfc3339_millis() -> str:
    """Return the current UTC time in RFC 3339 form with ms precision.

    Example: ``2026-04-22T09:45:00.123Z``.  The trailing ``Z`` is the
    canonical UTC marker consumed by the ingest-side parser
    (``sandbox-core::events::ingest::mitmproxy``).
    """
    now = time.time()
    # `gmtime` + explicit millisecond suffix beats `datetime.isoformat`
    # which produces microsecond precision with a ``+00:00`` offset — we
    # want the compact ``Z`` form and exactly three fractional digits.
    secs = int(now)
    millis = int((now - secs) * 1000)
    struct_time = time.gmtime(secs)
    return "%04d-%02d-%02dT%02d:%02d:%02d.%03dZ" % (
        struct_time.tm_year,
        struct_time.tm_mon,
        struct_time.tm_mday,
        struct_time.tm_hour,
        struct_time.tm_min,
        struct_time.tm_sec,
        millis,
    )


class EventEmitter:
    """Append-only JSONL writer with thread-safe line emission.

    One instance per process is the intended usage: both the policy
    addon and the pass-through addon share a single emitter so all
    events land in one file in the order they were produced.  The file
    is opened once (``open(path, "a", buffering=1)``); no reopening on
    failure — if the file becomes unavailable, we log the error and
    swallow, so a failed write cannot propagate back into mitmproxy's
    flow handler (which would 500 the request).
    """

    def __init__(self, path: str) -> None:
        self._path = path
        self._lock = threading.Lock()
        # Line-buffered text-mode append.  `buffering=1` only takes
        # effect on text-mode files; we still call `.flush()` under the
        # lock (see `_write`) for parity across Python builds where
        # buffering semantics differ at the edges.
        self._file = open(path, "a", buffering=1, encoding="utf-8")

    # ── Emit ────────────────────────────────────────────────────────

    def emit_request_allowed(
        self,
        host: str,
        port: int,
        method: str,
        path: str,
        client_ip: Optional[str],
    ) -> None:
        """Append one ``request_allowed`` event."""
        payload: dict[str, Any] = {
            "timestamp": _rfc3339_millis(),
            "layer": "mitmproxy",
            "event": "request_allowed",
            "host": host,
            "port": port,
            "method": method,
            "path": path,
            # Explicitly include `client_ip` even when None — the ingest
            # parser distinguishes "unknown peer" (null) from "field
            # missing" (malformed event, dropped with a warning).
            "client_ip": client_ip,
        }
        self._write(payload)

    def emit_request_denied(
        self,
        host: str,
        port: int,
        method: str,
        path: str,
        reason: str,
        client_ip: Optional[str],
    ) -> None:
        """Append one ``request_denied`` event."""
        payload: dict[str, Any] = {
            "timestamp": _rfc3339_millis(),
            "layer": "mitmproxy",
            "event": "request_denied",
            "host": host,
            "port": port,
            "method": method,
            "path": path,
            # `reason` must match the string emitted by the addon's
            # human-readable log line character-for-character — see the
            # three variants in `policy_addon._check_request`.  The
            # `sandbox events --decision=deny` CLI treats this as a
            # stable, externally observable contract.
            "reason": reason,
            "client_ip": client_ip,
        }
        self._write(payload)

    # ── Internals ───────────────────────────────────────────────────

    def _write(self, payload: dict[str, Any]) -> None:
        """Serialize and append one JSONL line under the emitter lock.

        We use ``separators=(",", ":")`` for compact output (no trailing
        whitespace — matters for partial-line detection on the reader
        side).  ``sort_keys`` is left False so the dict insertion order
        above is preserved in the output for human readability.
        """
        try:
            line = json.dumps(payload, separators=(",", ":"), sort_keys=False)
        except (TypeError, ValueError) as exc:
            # An un-serializable payload is a bug in the caller; log
            # and drop so we don't poison the JSONL stream with a
            # half-written line.
            logger.error("Failed to serialize event %r: %s", payload, exc)
            return

        with self._lock:
            try:
                self._file.write(line)
                self._file.write("\n")
                self._file.flush()
            except (OSError, ValueError) as exc:
                # Disk full, file closed out from under us, etc.  The
                # only safe response is to log and move on — raising
                # here would cause mitmproxy to 500 the caller's flow.
                # ``ValueError`` is what Python raises for writes to a
                # closed file, so we include it in the catch to keep
                # the "never raise out of the addon" contract intact
                # even if someone misuses the emitter.
                logger.error(
                    "Failed to write event to %s: %s", self._path, exc
                )

    def close(self) -> None:
        """Close the underlying file (best-effort).

        Safe to call multiple times.  Intended for test teardown and
        graceful shutdown; mitmproxy itself has no ``done`` hook we use
        here, so in production the file simply stays open until the
        container exits.
        """
        with self._lock:
            try:
                self._file.close()
            except OSError:
                pass
