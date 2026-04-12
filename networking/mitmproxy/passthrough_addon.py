"""
mitmproxy pass-through addon — M3 (no policy enforcement).

Logs all HTTP requests without modifying or blocking anything.
In M4, this will be replaced with a policy-enforcement addon that
checks each request against the session's network policy.
"""

from mitmproxy import http
import logging

logger = logging.getLogger("passthrough")


class PassthroughAddon:
    """Pass-through addon that logs requests without enforcement."""

    def request(self, flow: http.HTTPFlow) -> None:
        logger.info(
            "pass-through: %s %s%s",
            flow.request.method,
            flow.request.host,
            flow.request.path,
        )

    def response(self, flow: http.HTTPFlow) -> None:
        logger.info(
            "pass-through: %s %s%s -> %s",
            flow.request.method,
            flow.request.host,
            flow.request.path,
            flow.response.status_code if flow.response else "no-response",
        )


addons = [PassthroughAddon()]
