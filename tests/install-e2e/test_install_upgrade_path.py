"""Upgrade-path regression tests for install.sh.

Two bugs are exercised here, both triggered only when installing over an
existing sandboxd installation:

Bug 1 — helper binaries left uncapped after reinstall
    install(1) strips the ``security.capability`` xattr when it overwrites a
    file.  install.sh's ``compute_plan`` phase used to read ``getcap`` on the
    OLD binary before overwriting it; if the old binary was already capped the
    plan recorded ``skip``, and the stale ``skip`` left the freshly-written
    binary uncapped.  The fix forces ``PLAN_*_CAPS=set`` whenever the binary
    plan entry is ``install:`` (i.e. the file will be overwritten).

Bug 2 — pre-existing v0 users.conf causes daemon crash-loop after install
    A ``users.conf`` written by a pre-migration build has no ``_schema_version``
    field (treated as version 0).  The daemon requires
    ``_schema_version >= DAEMON_MIN_SUPPORTED_USERS_CONF_SCHEMA`` (currently 1)
    and aborts with ``SchemaTooOld`` if it reads a v0 file.  install.sh used to
    leave an existing ``users.conf`` untouched (``PLAN_USERS_CONF=skip``), so
    the stale file persisted and the daemon crash-looped.  The fix invokes the
    installed binary's config-migration chain from within the installer's root
    batch, idempotently migrating the file to the current schema.

Each test seeds a fresh Lima VM with pre-existing state that reproduces the
bug, runs install.sh from a rebuilt tarball, and asserts the post-install
invariants.  Both tests skip automatically if Lima or /dev/kvm is unavailable
(handled by the session-scoped ``_preflight`` fixture in conftest.py).
"""

from __future__ import annotations

import json

import pytest

from conftest import (
    copy_tarball_to_vm,
    install_sh_cmd,
    parse_install_log_actions,
    wait_for_systemd_active,
)

# ---------------------------------------------------------------------------
# v0 users.conf template — no _schema_version field.
#
# Mirrors the shape written by pre-migration builds: a top-level subnets
# array with allow_users entries that do NOT include "sandbox" (the V001
# migration prepends it).  The daemon rejects this file at startup because
# _schema_version defaults to 0 which is below DAEMON_MIN_SUPPORTED (1).
# ---------------------------------------------------------------------------
_V0_USERS_CONF = json.dumps(
    {
        "subnets": [
            {
                "comment": "Production pool — pre-migration shape, no _schema_version",
                "cidr": "10.209.0.0/20",
                "allow_users": ["operator"],
            }
        ]
    },
    indent=2,
)

# ---------------------------------------------------------------------------
# Capability strings (must match PLAN_ROUTE_CAPS_STR / PLAN_LIMA_CAPS_STR
# in install.sh; these are what getcap reports AFTER setcap).
# ---------------------------------------------------------------------------
_ROUTE_HELPER_CAPS = "cap_net_admin,cap_sys_ptrace,cap_sys_admin=eip"
_LIMA_HELPER_CAPS = "cap_setuid=ep"  # getcap normalises =ep from +ep

_ROUTE_HELPER_PATH = "/usr/local/libexec/sandboxd/sandbox-route-helper"
_LIMA_HELPER_PATH = "/usr/local/libexec/sandboxd/sandbox-lima-helper"


def _seed_capped_helpers(vm):
    """Simulate a prior install that left helpers with their expected caps.

    We install dummy executables at the helper paths and apply the expected
    capability sets so that a subsequent ``compute_plan`` sees the caps as
    already present.  The binaries are deliberately byte-different from the
    tarball's copies so the ``cmp`` check in compute_plan records
    ``install:`` (not ``skip-identical:``) — ensuring the upgrade path
    exercises the overwrite + re-cap flow.
    """
    # Create the libexec directory and install placeholder binaries.
    vm.shell(
        "sudo install -d -m 0755 -o root -g root "
        "/usr/local/libexec/sandboxd",
        check=True, timeout=10,
    )
    for path in (_ROUTE_HELPER_PATH, _LIMA_HELPER_PATH):
        vm.shell(
            # A minimal ELF-like file — one byte different from the real
            # binary so cmp(1) reports a difference and the plan records
            # "install:".
            f"printf '#!/bin/sh\\n# placeholder\\n' | "
            f"sudo tee {path} > /dev/null && "
            f"sudo chmod 0755 {path}",
            check=True, timeout=10,
        )

    # Apply the capability sets so getcap returns non-empty values,
    # matching the "previous install capped helpers" scenario.
    vm.shell(
        f"sudo setcap '{_ROUTE_HELPER_CAPS}' {_ROUTE_HELPER_PATH}",
        check=True, timeout=10,
    )
    vm.shell(
        f"sudo setcap 'cap_setuid+ep' {_LIMA_HELPER_PATH}",
        check=True, timeout=10,
    )

    # Verify the caps are genuinely present before the reinstall.
    r = vm.shell(f"getcap {_ROUTE_HELPER_PATH}", timeout=10)
    assert r.returncode == 0 and r.stdout.strip(), (
        f"seed: route-helper not capped after setcap: {r.stdout!r}"
    )
    r = vm.shell(f"getcap {_LIMA_HELPER_PATH}", timeout=10)
    assert r.returncode == 0 and r.stdout.strip(), (
        f"seed: lima-helper not capped after setcap: {r.stdout!r}"
    )


def _seed_v0_users_conf(vm):
    """Write a v0 users.conf (no _schema_version) into /etc/sandboxd/."""
    vm.shell(
        "sudo install -d -m 0755 -o root -g root /etc/sandboxd",
        check=True, timeout=10,
    )
    vm.shell(
        f"printf '%s\\n' {_sh_quote(_V0_USERS_CONF)} | "
        f"sudo tee /etc/sandboxd/users.conf > /dev/null && "
        f"sudo chmod 0644 /etc/sandboxd/users.conf && "
        f"sudo chown root:root /etc/sandboxd/users.conf",
        check=True, timeout=10,
    )
    # Verify: jq must report null for _schema_version.
    r = vm.shell(
        "sudo jq '._schema_version' /etc/sandboxd/users.conf",
        timeout=10,
    )
    assert r.returncode == 0 and r.stdout.strip() == "null", (
        f"seed: _schema_version not null in planted v0 file: {r.stdout!r}"
    )


def _sh_quote(s):
    return "'" + s.replace("'", r"'\''") + "'"


# ---------------------------------------------------------------------------
# Bug 1 regression test — helper caps survive reinstall
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("distro_template", ["ubuntu-22.04"])
def test_upgrade_caps_survive_reinstall(
    distro_template,
    vm_factory,
    release_tarball_x86_64,
    sigstore_stack,
):
    """Reinstalling over a previously-capped helper leaves it capped.

    Seed: both helpers exist on disk with their expected capability sets.
    The new tarball's binaries are byte-different from the placeholders,
    so compute_plan records ``install:`` for each helper (triggering the
    xattr-strip path).  After reinstall the helpers must still carry their
    caps.

    This exercises the fix to compute_plan's caps override block: the
    plan forces ``PLAN_*_CAPS=set`` whenever ``PLAN_BINARIES`` contains
    ``install:<helper-path>;``, regardless of what ``getcap`` reported on
    the pre-overwrite binary.
    """
    vm = vm_factory(distro_template)

    # Seed: capped placeholder helpers at the install paths.
    _seed_capped_helpers(vm)

    # Copy the tarball and run install.sh.
    tarball_in_vm = copy_tarball_to_vm(vm, release_tarball_x86_64)
    r = vm.shell(
        install_sh_cmd(tarball_in_vm, vm=vm, sigstore_stack=sigstore_stack),
        timeout=600,
    )
    assert r.returncode == 0, (
        f"install.sh failed on upgrade:\nstdout:\n{r.stdout}\nstderr:\n{r.stderr}"
    )

    # Both helper binaries must have been overwritten (plan action=install).
    log = vm.shell(
        "sudo cat /var/log/sandbox-install.log", check=True, timeout=15,
    ).stdout
    actions = parse_install_log_actions(log)
    assert "install_binary" in actions, (
        f"no install_binary step logged; plan may have skipped both helpers:\n{log}"
    )
    assert "install" in actions["install_binary"], (
        f"helpers were not overwritten (no 'install' action); "
        f"got {actions['install_binary']}\n{log}"
    )

    # The setcap steps must have run (action=set, not skip).
    setcap_actions = actions.get("setcap", [])
    assert "set" in setcap_actions, (
        f"setcap action=set not logged; stale 'skip' may have fired:\n{log}"
    )
    assert "skip" not in setcap_actions, (
        f"setcap recorded 'skip' despite binary being overwritten;\n{log}"
    )

    # The installed binaries must genuinely carry the capability sets.
    r_route = vm.shell(f"getcap {_ROUTE_HELPER_PATH}", timeout=10)
    assert r_route.returncode == 0, (
        f"getcap returned non-zero for route-helper: {r_route.stderr!r}"
    )
    assert r_route.stdout.strip(), (
        f"route-helper has empty caps after reinstall; "
        f"Bug 1 not fixed: {r_route.stdout!r}"
    )
    assert _ROUTE_HELPER_CAPS in r_route.stdout, (
        f"route-helper caps mismatch; "
        f"got {r_route.stdout.strip()!r}, expected to contain {_ROUTE_HELPER_CAPS!r}"
    )

    r_lima = vm.shell(f"getcap {_LIMA_HELPER_PATH}", timeout=10)
    assert r_lima.returncode == 0, (
        f"getcap returned non-zero for lima-helper: {r_lima.stderr!r}"
    )
    assert r_lima.stdout.strip(), (
        f"lima-helper has empty caps after reinstall; "
        f"Bug 1 not fixed: {r_lima.stdout!r}"
    )
    assert _LIMA_HELPER_CAPS in r_lima.stdout, (
        f"lima-helper caps mismatch; "
        f"got {r_lima.stdout.strip()!r}, expected to contain {_LIMA_HELPER_CAPS!r}"
    )


# ---------------------------------------------------------------------------
# Bug 2 regression test — pre-existing v0 users.conf migrated by installer
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("distro_template", ["ubuntu-22.04"])
def test_upgrade_v0_users_conf_migrated_by_installer(
    distro_template,
    vm_factory,
    release_tarball_x86_64,
    sigstore_stack,
):
    """A pre-existing v0 users.conf is migrated to v1 during install.

    Seed: /etc/sandboxd/users.conf exists but has no _schema_version (v0).
    The daemon requires _schema_version >= 1 and crash-loops on a v0 file.

    After install.sh completes, the installer must have invoked the
    config-migration chain (via the installed binary's hidden subcommand),
    bringing the file to _schema_version=1 and prepending "sandbox" to every
    subnet's allow_users — matching the V001 migration's two-part transform.
    The daemon must then reach the active state (not failed).

    The migration must also be idempotent: running install.sh again on an
    already-migrated file must leave users.conf unchanged and the daemon
    must remain active.
    """
    vm = vm_factory(distro_template)

    # Seed: a v0 users.conf with a single subnet, no _schema_version.
    _seed_v0_users_conf(vm)

    # Run install.sh (upgrade/reinstall).
    tarball_in_vm = copy_tarball_to_vm(vm, release_tarball_x86_64)
    r = vm.shell(
        install_sh_cmd(tarball_in_vm, vm=vm, sigstore_stack=sigstore_stack),
        timeout=600,
    )
    assert r.returncode == 0, (
        f"install.sh failed on upgrade:\nstdout:\n{r.stdout}\nstderr:\n{r.stderr}"
    )

    # Assert (1): users.conf is now _schema_version=1.
    raw = vm.shell(
        "sudo cat /etc/sandboxd/users.conf", check=True, timeout=10,
    ).stdout
    conf = json.loads(raw)
    assert conf.get("_schema_version") == 1, (
        f"users.conf not migrated to v1 after install; "
        f"_schema_version={conf.get('_schema_version')!r}\n{raw}"
    )

    # Assert (2): every subnet's allow_users contains "sandbox" (V001 transform).
    for subnet in conf.get("subnets", []):
        assert "sandbox" in subnet.get("allow_users", []), (
            f"V001 migration did not prepend 'sandbox' to subnet "
            f"{subnet.get('cidr')!r}: allow_users={subnet.get('allow_users')!r}"
        )

    # Assert (3): the daemon reaches active after systemctl enable --now.
    vm.shell("sudo systemctl enable --now sandboxd", check=True, timeout=60)
    wait_for_systemd_active(vm.name, "sandboxd", timeout=60)

    # Idempotency: a second install run on an already-v1 file is a no-op.
    vm.shell("sudo truncate -s 0 /var/log/sandbox-install.log", check=True)
    r2 = vm.shell(
        install_sh_cmd(tarball_in_vm, vm=vm, sigstore_stack=sigstore_stack),
        timeout=600,
    )
    assert r2.returncode == 0, (
        f"second install run failed:\nstdout:\n{r2.stdout}\nstderr:\n{r2.stderr}"
    )
    raw2 = vm.shell(
        "sudo cat /etc/sandboxd/users.conf", check=True, timeout=10,
    ).stdout
    conf2 = json.loads(raw2)
    assert conf2.get("_schema_version") == 1, (
        f"users.conf reverted after second install run; "
        f"_schema_version={conf2.get('_schema_version')!r}"
    )
    # Schema-version and subnets must be identical to the post-first-run state.
    assert conf == conf2, (
        f"users.conf content changed between first and second install runs; "
        f"migration is not idempotent.\nAfter first:\n{raw}\nAfter second:\n{raw2}"
    )


# ---------------------------------------------------------------------------
# Combined upgrade path: both seeds, full smoke
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("distro_template", ["ubuntu-22.04"])
def test_upgrade_combined_caps_and_migration(
    distro_template,
    vm_factory,
    release_tarball_x86_64,
    sigstore_stack,
):
    """Reinstall over both seeded preconditions — capped helpers AND v0 conf.

    This mirrors the exact failure scenario from the live host: a prior
    install left the helpers capped and the conf at v0.  After reinstall
    both invariants must hold simultaneously, and the daemon must start.
    """
    vm = vm_factory(distro_template)

    _seed_capped_helpers(vm)
    _seed_v0_users_conf(vm)

    tarball_in_vm = copy_tarball_to_vm(vm, release_tarball_x86_64)
    r = vm.shell(
        install_sh_cmd(tarball_in_vm, vm=vm, sigstore_stack=sigstore_stack),
        timeout=600,
    )
    assert r.returncode == 0, (
        f"install.sh failed on combined upgrade:\nstdout:\n{r.stdout}\nstderr:\n{r.stderr}"
    )

    # Bug 1: both helpers must be capped.
    r_route = vm.shell(f"getcap {_ROUTE_HELPER_PATH}", timeout=10)
    assert r_route.stdout.strip() and _ROUTE_HELPER_CAPS in r_route.stdout, (
        f"route-helper uncapped after combined upgrade: {r_route.stdout!r}"
    )
    r_lima = vm.shell(f"getcap {_LIMA_HELPER_PATH}", timeout=10)
    assert r_lima.stdout.strip() and _LIMA_HELPER_CAPS in r_lima.stdout, (
        f"lima-helper uncapped after combined upgrade: {r_lima.stdout!r}"
    )

    # Bug 2: users.conf must be v1 with "sandbox" in allow_users.
    raw = vm.shell(
        "sudo cat /etc/sandboxd/users.conf", check=True, timeout=10,
    ).stdout
    conf = json.loads(raw)
    assert conf.get("_schema_version") == 1, (
        f"users.conf not migrated in combined upgrade: "
        f"_schema_version={conf.get('_schema_version')!r}\n{raw}"
    )
    for subnet in conf.get("subnets", []):
        assert "sandbox" in subnet.get("allow_users", []), (
            f"V001 migration missing in combined upgrade for subnet "
            f"{subnet.get('cidr')!r}: allow_users={subnet.get('allow_users')!r}"
        )

    # Daemon must start cleanly with both fixes in place.
    vm.shell("sudo systemctl enable --now sandboxd", check=True, timeout=60)
    wait_for_systemd_active(vm.name, "sandboxd", timeout=60)
