"""
Integration test for the policy enforcement addon with mitmproxy.

Requires mitmproxy (mitmdump) to be installed and available on PATH.
Sends real HTTP requests through the proxy and validates behavior.

Run manually:
    cd networking/mitmproxy && python3 -m pytest test_integration.py -v

Skip reason: requires mitmproxy binary and network access.
"""

from __future__ import annotations

import json
import os
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time

import pytest

# Skip the entire module if mitmdump is not available.
pytestmark = pytest.mark.skipif(
    shutil.which("mitmdump") is None,
    reason="requires mitmproxy binary (mitmdump) on PATH",
)

# Also need the requests library for HTTP calls through the proxy.
try:
    import requests as _requests
except ImportError:
    _requests = None  # type: ignore[assignment]

pytestmark = [
    pytestmark,
    pytest.mark.skipif(
        _requests is None,
        reason="requires 'requests' library (pip install requests)",
    ),
]


def _free_port() -> int:
    """Find an available TCP port on localhost."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _wait_for_port(port: int, timeout: float = 10.0) -> bool:
    """Wait until a TCP port is accepting connections."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=1.0):
                return True
        except OSError:
            time.sleep(0.2)
    return False


class TestMitmproxyIntegration:
    """Start mitmdump with the policy addon and send requests through it."""

    @pytest.fixture(autouse=True)
    def setup_proxy(self, tmp_path: str) -> None:
        """Start mitmdump with the policy addon and a config file."""
        self.port = _free_port()
        self.config_path = os.path.join(str(tmp_path), "policy.json")

        # Write a policy that allows only httpbin.org GET requests.
        with open(self.config_path, "w") as fh:
            json.dump(
                {
                    "rules": [
                        {
                            "host": "httpbin.org",
                            "methods": ["GET"],
                            "paths": None,
                        }
                    ]
                },
                fh,
            )

        addon_path = os.path.join(
            os.path.dirname(os.path.abspath(__file__)), "policy_addon.py"
        )

        env = os.environ.copy()
        env["SANDBOX_MITMPROXY_CONFIG"] = self.config_path

        self.proc = subprocess.Popen(
            [
                "mitmdump",
                "--mode", "regular",
                "--listen-host", "127.0.0.1",
                "--listen-port", str(self.port),
                "-s", addon_path,
            ],
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        if not _wait_for_port(self.port):
            self.proc.terminate()
            pytest.fail(f"mitmdump did not start on port {self.port}")

        self.proxies = {
            "http": f"http://127.0.0.1:{self.port}",
            "https": f"http://127.0.0.1:{self.port}",
        }

        yield  # type: ignore[misc]

        self.proc.send_signal(signal.SIGTERM)
        self.proc.wait(timeout=5)

    def test_health_endpoint(self) -> None:
        """Health endpoint responds through the proxy."""
        resp = _requests.get(
            f"http://127.0.0.1:{self.port}/__sandbox_health",
        )
        assert resp.status_code == 200
        assert resp.json() == {"status": "ok"}

    def test_allowed_request_passes(self) -> None:
        """GET to httpbin.org is allowed by policy."""
        resp = _requests.get(
            "http://httpbin.org/get",
            proxies=self.proxies,
            timeout=10,
        )
        assert resp.status_code == 200

    def test_denied_host_gets_599(self) -> None:
        """Request to unlisted host gets 599."""
        resp = _requests.get(
            "http://evil.example.com/",
            proxies=self.proxies,
            timeout=10,
        )
        assert resp.status_code == 599
        body = resp.json()
        assert body["error"] == "sandbox_policy_denied"
        assert body["reason"] == "host not in policy"

    def test_denied_method_gets_599(self) -> None:
        """POST to GET-only host gets 599."""
        resp = _requests.post(
            "http://httpbin.org/post",
            proxies=self.proxies,
            timeout=10,
        )
        assert resp.status_code == 599
        body = resp.json()
        assert body["error"] == "sandbox_policy_denied"
        assert "method POST not allowed" in body["reason"]
