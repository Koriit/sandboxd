"""Spec 5 § 9.1 tests that fundamentally require a multi-version
harness — documented skips.

The bumped-tarball helper (``conftest.make_bumped_tarball``)
synthesises a v' tarball by rewriting MANIFEST.version on the v
tarball's bytes. That covers most of the § 9.1 contract, but two
tests strictly need a binary whose compiled-in workspace version
differs from v's:

* ``test_update_fresh_install_to_next_version`` — asserts the daemon
  reports v' on ``/version`` after the upgrade. The binary's
  ``CARGO_PKG_VERSION`` is baked in at build time; rewriting MANIFEST
  doesn't change it.

* ``test_update_with_recreate_session_classification`` — asserts the
  recreate-classification logic for a session whose
  ``guest_protocol_version`` is older than the new daemon's
  ``DAEMON_GUEST_PROTO_VERSION``. The constant is a compile-time
  literal; building a tarball with a higher constant requires source
  modification + a second build.

Both are skipped here with an explicit pointer to the multi-version
harness that would unblock them. The skip is loud rather than silent
so the gap stays visible in CI output.
"""

from __future__ import annotations

import pytest


@pytest.mark.parametrize("distro_template", ["ubuntu-22.04"])
def test_update_fresh_install_to_next_version(
    distro_template, vm_factory, release_tarball_x86_64
):
    """Daemon at v' after upgrade — requires a v' binary (skipped)."""
    pytest.skip(
        "requires a tarball built from a different workspace version — "
        "the harness builds a single tarball per session and the bumped "
        "tarball helper only rewrites MANIFEST. A future multi-version "
        "harness (build under two cargo versions, cache both) would "
        "unblock this. The lock + backup + state-flip contracts are "
        "covered by test_update_idempotency / test_update_rollback / "
        "test_update_air_gapped against the synthesised bumped tarball."
    )


@pytest.mark.parametrize("distro_template", ["ubuntu-22.04"])
def test_update_with_recreate_session_classification(
    distro_template, vm_factory, release_tarball_x86_64
):
    """Session is classified `recreate` when guest proto advances —
    requires a tarball with a bumped ``DAEMON_GUEST_PROTO_VERSION``.
    """
    pytest.skip(
        "requires a tarball whose binary has DAEMON_GUEST_PROTO_VERSION "
        "advanced past the installed version. The constant is a "
        "compile-time literal in sandbox-core; modifying it requires a "
        "source patch + second build. Tracked as a multi-version-harness "
        "follow-up. The unit-level recreate classification logic is "
        "exercised by `integration_session_create_image_contracts` and "
        "the guest-proto compat-gate tests in sandbox-core."
    )
