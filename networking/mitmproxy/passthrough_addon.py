"""
mitmproxy transport-level passthrough addon for assurance levels 0-1.

Logs all HTTP requests without modifying or blocking anything.
Used for sessions with no policy enforcement or transport-level-only policies.

In addition to the existing human-readable ``logger.info`` lines, when
``SANDBOX_MITMPROXY_EVENTS`` is set this addon emits one structured
``request_allowed`` JSONL event per request to the configured file (see
``events.py`` for the envelope).  Pass-through flows are allowed by
definition — this addon is only selected for sessions with no L7
enforcement — so every request maps to ``request_allowed``.

For bare TCP tunnels, ``method`` and ``path`` may be unavailable on the
flow.  In that case we emit with ``method=""`` / ``path=""`` rather than
dropping the event: the ingest parser will still produce a
``TrafficEvent`` record for operators tailing
``sandbox events --decision=allow``.
"""

from __future__ import annotations

import logging
import os

from mitmproxy import http

from events import EventEmitter

logger = logging.getLogger("passthrough")

# Mirror of ``policy_addon.EVENTS_PATH_ENV`` — kept local so each addon
# file is self-contained (mitmproxy loads exactly one of them at a time).
EVENTS_PATH_ENV = "SANDBOX_MITMPROXY_EVENTS"


def _peer_ip(flow: "http.HTTPFlow") -> "str | None":
    """Return the client IP from a flow, tolerant of missing peers.

    Pass-through flows are often plain CONNECT tunnels where
    ``client_conn.peername`` is populated as an ``(ip, port)`` tuple.
    We still guard defensively: the ingest parser treats ``client_ip``
    absence as a malformed event, so we must not omit the field even
    when the peer is genuinely unknown — we serialize ``None`` as JSON
    ``null`` instead.
    """
    try:
        peer = getattr(flow.client_conn, "peername", None)
    except AttributeError:
        return None
    if peer is None:
        return None
    try:
        return str(peer[0])
    except (IndexError, TypeError):
        return None


class PassthroughAddon:
    """Pass-through addon that logs requests without enforcement."""

    def __init__(self, events: EventEmitter | None = None) -> None:
        # ``events is None`` keeps the addon operable in unit tests
        # and in environments where structured emission is disabled
        # (e.g. ``SANDBOX_MITMPROXY_EVENTS`` unset).
        self._events: EventEmitter | None = events

    def request(self, flow: http.HTTPFlow) -> None:
        method = flow.request.method
        host = flow.request.host
        path = flow.request.path
        port = int(getattr(flow.request, "port", 0) or 0)
        logger.info("pass-through: %s %s%s", method, host, path)
        if self._events is not None:
            # Pass-through flows are allowed by definition — no
            # ``request_denied`` path from this addon.  For bare TCP
            # tunnels, ``method`` / ``path`` may be empty; we emit the
            # event anyway with empty strings rather than dropping it.
            self._events.emit_request_allowed(
                host=host,
                port=port,
                method=method or "",
                path=path or "",
                client_ip=_peer_ip(flow),
            )

    def response(self, flow: http.HTTPFlow) -> None:
        # We keep the human-readable response log so operators tailing
        # the container can see status codes.  No second structured
        # event is emitted on response: ``request_allowed`` above is
        # the canonical decision record, and the ingest layer doesn't
        # model per-response events.
        logger.info(
            "pass-through: %s %s%s -> %s",
            flow.request.method,
            flow.request.host,
            flow.request.path,
            flow.response.status_code if flow.response else "no-response",
        )


def _build_event_emitter() -> EventEmitter | None:
    """Build an :class:`EventEmitter` from the environment.

    Returns ``None`` (emission disabled) when
    ``SANDBOX_MITMPROXY_EVENTS`` is unset or the path cannot be opened.
    Matches ``policy_addon._build_event_emitter`` so the two addons
    behave identically with respect to env configuration.
    """
    path = os.environ.get(EVENTS_PATH_ENV, "")
    if not path:
        return None
    try:
        parent = os.path.dirname(path)
        if parent:
            os.makedirs(parent, exist_ok=True)
        return EventEmitter(path)
    except OSError as exc:
        logger.error(
            "Failed to open events file %s: %s — structured emission disabled",
            path,
            exc,
        )
        return None


addons = [PassthroughAddon(_build_event_emitter())]
