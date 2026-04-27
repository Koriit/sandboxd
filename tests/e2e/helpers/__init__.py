"""Shared E2E helpers for the sandbox test suite.

Re-exports the helper classes used across multiple test files so call
sites can write ``from helpers import LiteBackendHarness, HostResources``
without juggling individual module paths.
"""

from __future__ import annotations

from .docker_info import is_rootless_docker
from .host_resources import HostResources
from .lite_harness import LiteBackendHarness

__all__ = [
    "HostResources",
    "LiteBackendHarness",
    "is_rootless_docker",
]
