"""
mitmproxy transport-level passthrough addon for assurance levels 0-1.

Logs all HTTP requests without modifying or blocking anything.
Used for sessions with no policy enforcement or transport-level-only policies.
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
