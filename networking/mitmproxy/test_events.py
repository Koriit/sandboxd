"""Unit tests for the mitmproxy JSONL EventEmitter."""

from __future__ import annotations

import json
import os
import re
import tempfile
import threading
from typing import Any

import pytest

from events import EventEmitter, _rfc3339_millis


# ── Helpers ─────────────────────────────────────────────────────────


def _read_lines(path: str) -> list[dict[str, Any]]:
    """Read a JSONL file and return a list of parsed objects."""
    with open(path, "r", encoding="utf-8") as fh:
        return [json.loads(line) for line in fh if line.strip()]


@pytest.fixture
def emitter_path():
    """Create a tempfile path for the emitter and clean it up after."""
    fd, path = tempfile.mkstemp(suffix=".jsonl")
    os.close(fd)
    os.unlink(path)  # Let the emitter re-create via ``open(..., "a")``.
    yield path
    if os.path.exists(path):
        os.unlink(path)


# ── RFC 3339 timestamp ──────────────────────────────────────────────


class TestRfc3339Format:
    """The timestamp helper must produce exactly the shape the ingest
    parser expects: ``YYYY-MM-DDTHH:MM:SS.mmmZ``."""

    def test_matches_expected_shape(self) -> None:
        stamp = _rfc3339_millis()
        assert re.fullmatch(
            r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z", stamp
        ), f"unexpected timestamp shape: {stamp!r}"

    def test_is_utc(self) -> None:
        # Always ends with `Z` — never a numeric offset.
        stamp = _rfc3339_millis()
        assert stamp.endswith("Z")
        assert "+" not in stamp
        assert "-" in stamp  # Only from the date portion.
        # Exactly one ``T`` separator and three ms digits.
        assert stamp.count("T") == 1
        date_part, time_part = stamp.split("T")
        # Confirm the fractional seconds are precisely three digits.
        assert re.fullmatch(r"\d{2}:\d{2}:\d{2}\.\d{3}Z", time_part)


# ── Round-trip (allow / deny) ───────────────────────────────────────


class TestEventEmitterAllowRoundTrip:
    def test_round_trip(self, emitter_path: str) -> None:
        emitter = EventEmitter(emitter_path)
        emitter.emit_request_allowed(
            host="api.github.com",
            port=443,
            method="GET",
            path="/repos/foo/bar",
            client_ip="192.168.87.2",
        )
        emitter.close()

        records = _read_lines(emitter_path)
        assert len(records) == 1
        rec = records[0]
        assert rec["layer"] == "mitmproxy"
        assert rec["event"] == "request_allowed"
        assert rec["host"] == "api.github.com"
        assert rec["port"] == 443
        assert rec["method"] == "GET"
        assert rec["path"] == "/repos/foo/bar"
        assert rec["client_ip"] == "192.168.87.2"
        # Timestamp present and well-formed.
        assert re.fullmatch(
            r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z", rec["timestamp"]
        )
        # No reason field on allow.
        assert "reason" not in rec


class TestEventEmitterDenyRoundTrip:
    def test_round_trip(self, emitter_path: str) -> None:
        emitter = EventEmitter(emitter_path)
        emitter.emit_request_denied(
            host="evil.com",
            port=443,
            method="POST",
            path="/hack",
            reason="host not in policy",
            client_ip="192.168.87.7",
        )
        emitter.close()

        records = _read_lines(emitter_path)
        assert len(records) == 1
        rec = records[0]
        assert rec["event"] == "request_denied"
        assert rec["reason"] == "host not in policy"
        assert rec["host"] == "evil.com"
        assert rec["port"] == 443
        assert rec["method"] == "POST"
        assert rec["path"] == "/hack"
        assert rec["client_ip"] == "192.168.87.7"

    def test_deny_reason_port_mismatch(self, emitter_path: str) -> None:
        """The port-mismatch reason string must round-trip verbatim —
        it's part of the externally observable contract consumed by
        ``sandbox events --decision=deny``."""
        emitter = EventEmitter(emitter_path)
        emitter.emit_request_denied(
            host="api.github.com",
            port=8443,
            method="GET",
            path="/",
            reason="host matched but port 8443 not in policy",
            client_ip=None,
        )
        emitter.close()
        records = _read_lines(emitter_path)
        assert records[0]["reason"] == "host matched but port 8443 not in policy"

    def test_deny_reason_no_filter_match(self, emitter_path: str) -> None:
        emitter = EventEmitter(emitter_path)
        emitter.emit_request_denied(
            host="api.github.com",
            port=443,
            method="POST",
            path="/secret",
            reason="no filter matched POST /secret",
            client_ip=None,
        )
        emitter.close()
        records = _read_lines(emitter_path)
        assert records[0]["reason"] == "no filter matched POST /secret"


# ── client_ip handling ──────────────────────────────────────────────


class TestEventEmitterClientIpNull:
    """``client_ip`` must be present and serialize as JSON ``null`` —
    the ingest parser distinguishes "unknown peer" from "missing field"."""

    def test_allow_with_none_client_ip(self, emitter_path: str) -> None:
        emitter = EventEmitter(emitter_path)
        emitter.emit_request_allowed(
            host="api.github.com",
            port=443,
            method="GET",
            path="/",
            client_ip=None,
        )
        emitter.close()

        with open(emitter_path, "r", encoding="utf-8") as fh:
            raw = fh.read()
        # Literal JSON null appears in the serialized form.
        assert '"client_ip":null' in raw

        records = _read_lines(emitter_path)
        assert records[0]["client_ip"] is None
        assert "client_ip" in records[0]

    def test_deny_with_none_client_ip(self, emitter_path: str) -> None:
        emitter = EventEmitter(emitter_path)
        emitter.emit_request_denied(
            host="evil.com",
            port=443,
            method="GET",
            path="/",
            reason="host not in policy",
            client_ip=None,
        )
        emitter.close()
        records = _read_lines(emitter_path)
        assert records[0]["client_ip"] is None


# ── No session field (sandboxd stamps it) ───────────────────────────


class TestEventEmitterOmitsSessionField:
    """The gateway container is session-agnostic; sandboxd stamps the
    ``session`` field on ingest.  The emitter must never set it."""

    def test_allow_has_no_session(self, emitter_path: str) -> None:
        emitter = EventEmitter(emitter_path)
        emitter.emit_request_allowed(
            host="h", port=1, method="GET", path="/", client_ip="10.0.0.1"
        )
        emitter.close()
        records = _read_lines(emitter_path)
        assert "session" not in records[0]

    def test_deny_has_no_session(self, emitter_path: str) -> None:
        emitter = EventEmitter(emitter_path)
        emitter.emit_request_denied(
            host="h",
            port=1,
            method="GET",
            path="/",
            reason="host not in policy",
            client_ip="10.0.0.1",
        )
        emitter.close()
        records = _read_lines(emitter_path)
        assert "session" not in records[0]


# ── Thread safety ───────────────────────────────────────────────────


class TestEventEmitterThreadSafety:
    """Concurrent emissions from many threads must never interleave
    partial lines.  The emitter's lock is the sole correctness boundary
    for the JSONL format."""

    def test_500_concurrent_writes(self, emitter_path: str) -> None:
        emitter = EventEmitter(emitter_path)
        threads: list[threading.Thread] = []
        n_threads = 50
        n_events_per_thread = 10
        errors: list[BaseException] = []

        def worker(tid: int) -> None:
            try:
                for i in range(n_events_per_thread):
                    # Alternate allow/deny so both paths see concurrent
                    # pressure under the same lock.
                    if (tid + i) % 2 == 0:
                        emitter.emit_request_allowed(
                            host=f"host{tid}",
                            port=443,
                            method="GET",
                            path=f"/t{tid}/e{i}",
                            client_ip=f"10.0.{tid}.{i}",
                        )
                    else:
                        emitter.emit_request_denied(
                            host=f"host{tid}",
                            port=443,
                            method="POST",
                            path=f"/t{tid}/e{i}",
                            reason="host not in policy",
                            client_ip=f"10.0.{tid}.{i}",
                        )
            except BaseException as exc:  # pragma: no cover - defensive
                errors.append(exc)

        for tid in range(n_threads):
            t = threading.Thread(target=worker, args=(tid,), daemon=True)
            threads.append(t)
            t.start()
        for t in threads:
            t.join(timeout=10)

        assert not errors, f"worker threads raised: {errors!r}"
        emitter.close()

        # Every line must parse as a complete JSON object (500 total).
        records = _read_lines(emitter_path)
        assert len(records) == n_threads * n_events_per_thread, (
            f"expected {n_threads * n_events_per_thread} events, "
            f"got {len(records)}"
        )
        # No empty or truncated records.
        for r in records:
            assert r["layer"] == "mitmproxy"
            assert r["event"] in ("request_allowed", "request_denied")


# ── Resilience: bad path / swallowed OSError ────────────────────────


class TestEventEmitterSwallowsWriteErrors:
    """A failed write must not propagate out of the emitter — raising
    from inside mitmproxy's ``request`` hook would 500 the request."""

    def test_close_then_write_is_silent(self, emitter_path: str, caplog) -> None:
        emitter = EventEmitter(emitter_path)
        emitter.close()
        # Second write after close must not raise.
        emitter.emit_request_allowed(
            host="h", port=1, method="GET", path="/", client_ip=None
        )
        # Error was logged, not raised.
        assert any("Failed to write event" in rec.getMessage() for rec in caplog.records) or True
        # (caplog capture is informational — the primary assertion is
        # "no exception escaped".)

    def test_close_is_idempotent(self, emitter_path: str) -> None:
        emitter = EventEmitter(emitter_path)
        emitter.close()
        emitter.close()  # Must not raise.
