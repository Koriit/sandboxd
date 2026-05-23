"""`sandbox update` confirmation prompt classifies stopped sessions — the install framework.1.7.

When an operator runs ``sandbox update`` and the target binary's
``DAEMON_GUEST_PROTO_VERSION`` is incompatible with a stopped
session's persisted ``guest_protocol_version``, the pre-flight
classifies that session into one of three buckets in the
confirmation prompt: ``ok``, ``refresh-in-place``, or ``recreate``.

This test pins the ``recreate`` arm end-to-end. It installs the base
release, injects a synthetic stopped session directly into
``sessions.db`` with ``guest_protocol_version=0`` (the value a
freshly-created session carries before its first refresh — and the
canonical "unsalvageable" sentinel per ``classify_session_compat``
in ``sandbox-cli/src/update/mod.rs``), then drives ``sandbox update
--from <bumped-dir>`` past the pre-flight far enough to render the
confirmation summary but answers ``n`` at the prompt so no actual
mutation lands. The summary's ``stopped sessions compat`` block and
the per-session row are then asserted on.

Why a synthetic row rather than a created-and-stopped real session:
the production code that stamps ``guest_protocol_version`` runs
during ``start_session``'s refresh path (``sandboxd/src/main.rs``
``update_guest_versions`` call), so a real session would only land
in the ``recreate`` bucket if the host's
``DAEMON_GUEST_PROTO_VERSION`` had advanced relative to the stamp.
Today the constant is ``1`` and bumping it would be feature work
outside this test's scope. The synthetic-row shape matches the one
``test_peercred_isolation.py`` already uses for its session-isolation
proofs (the documented contract) — same column set, same SQL shape, lifted to
this test for the proto-version classification proof.

Why ``n`` at the prompt rather than ``--yes`` or ``--dry-run``:
``--dry-run`` exits before the staging step that resolves the target
binary's proto version (``sandbox-cli/src/update/mod.rs`` exit gate
at the dry-run branch), so the dry-run renderer only ever shows the
flat stopped-session count — no per-session classification verbs.
``--yes`` would proceed past the prompt and apply the full update,
which (a) is expensive, (b) re-installs the same bumped binary
proven by ``test_update_fresh_install_to_next_version``, (c) would
make this test fail open if the classification code path moves
without an output-shape regression. Aborting with ``n`` exercises
the exact code path that renders the classification while leaving
no state mutated, so the test pins the operator-visible contract
directly.
"""

from __future__ import annotations

import pytest

from conftest import (
    copy_tarball_to_vm,
    install_sh_cmd,
    version_from_tarball,
    wait_for_socket,
    wait_for_systemd_active,
)


def _inject_synthetic_stopped_session(
    vm, *, session_id, owner_username, guest_protocol_version
):
    """INSERT a stopped session row into sessions.db with a chosen
    ``guest_protocol_version``.

    Mirrors the shape used by ``test_peercred_isolation.py``'s
    ``_inject_synthetic_session`` helper, but with the proto-version
    parameterised so this test can land a row in the ``recreate``
    bucket (``guest_protocol_version=0`` against a target proto of
    ``1``; see ``classify_session_compat``'s
    ``session_proto != 0`` arm).
    """
    vm.shell(
        "set -eux; "
        "export DEBIAN_FRONTEND=noninteractive; "
        "if ! command -v sqlite3 >/dev/null 2>&1; then "
        "  sudo apt-get install -y --no-install-recommends sqlite3; "
        "fi",
        check=True,
        timeout=120,
    )

    config_json = (
        '{"cpus":2,"memory_mb":4096,"disk_gb":20,"hardened":true}'
    )
    now = "2026-05-17T00:00:00Z"
    sql = (
        "INSERT INTO sessions "
        "(id, name, state, config, created_at, updated_at, backend, "
        " owner_username, guest_protocol_version, guest_binary_version) "
        f"VALUES ('{session_id}', NULL, 'Stopped', '{config_json}', "
        f"'{now}', '{now}', 'lima', '{owner_username}', "
        f"{guest_protocol_version}, '0.0.0');"
    )
    vm.shell(
        f"sudo sqlite3 /var/lib/sandbox/sessions.db <<'SQL'\n{sql}\nSQL",
        check=True,
        timeout=10,
    )


@pytest.mark.parametrize("distro_template", ["ubuntu-22.04"])
def test_update_classifies_stopped_session_with_zero_proto_as_recreate(
    distro_template,
    vm_factory,
    release_tarball_x86_64,
    release_tarball_x86_64_bumped,
    sigstore_stack,
):
    """Confirmation summary shows ``recreate`` for an unsalvageable session.

    Assertions:

    * The ``stopped sessions compat`` aggregate line lists
      ``recreate=1`` (and the bucket counts of the other two buckets
      sum with it to the total stopped count).
    * The per-session breakdown row for the synthetic session id is
      present, shows ``proto=0 -> 1``, and ends with the ``recreate``
      label.
    * The CLI exits 0 (operator answered ``n`` — clean abort, not a
      pre-flight failure).
    * No mutation: the install state's ``installed_version`` is
      unchanged afterwards (the prompt-abort path runs purely in the
      read-only pre-flight; no lock acquisition, no binary install).
    """
    vm = vm_factory(distro_template)

    # Stage and install the base (v) tarball.
    base_tarball_in_vm = copy_tarball_to_vm(vm, release_tarball_x86_64)
    base_ver = version_from_tarball(base_tarball_in_vm)
    r = vm.shell(
        install_sh_cmd(base_tarball_in_vm, vm=vm, sigstore_stack=sigstore_stack),
        timeout=600,
    )
    assert r.returncode == 0, f"base install failed:\n{r.stdout}\n{r.stderr}"
    vm.shell("sudo systemctl enable --now sandboxd", check=True, timeout=60)
    wait_for_systemd_active(vm.name, "sandboxd", timeout=60)
    wait_for_socket(vm.name, "/run/sandbox/sandboxd.sock", timeout=60)

    # Inject a synthetic stopped session owned by root (peercred uid 0).
    # `sudo sandbox update` runs as root, so the daemon's per-caller
    # filter on /sessions returns this row to the update pre-flight.
    session_id = "abcdef012345"
    _inject_synthetic_stopped_session(
        vm,
        session_id=session_id,
        owner_username="root",
        guest_protocol_version=0,
    )

    # Stage the bumped (v') tarball. Feed `--from <dir>` rather than
    # the tarball: the directory shape short-circuits the sigstore
    # precondition (`verify_signature` runs only when
    # `from.is_file()`), keeping the test focused on the prompt
    # contract rather than re-exercising signature verification —
    # which is already covered by other install-e2e files.
    bumped_tarball_in_vm = copy_tarball_to_vm(vm, release_tarball_x86_64_bumped)
    bumped_ver = version_from_tarball(bumped_tarball_in_vm)
    assert bumped_ver != base_ver, (
        f"bumped fixture produced the same version as base: {bumped_ver}; "
        "the multi-version harness requires distinct versions"
    )
    stage_dir = "/tmp/sandbox-update-recreate-stage"
    arch = "x86_64-unknown-linux-gnu"
    vm.shell(
        f"sudo rm -rf {stage_dir} && mkdir -p {stage_dir} && "
        f"tar xzf {bumped_tarball_in_vm} -C {stage_dir}",
        check=True, timeout=60,
    )
    extracted_root = f"{stage_dir}/sandboxd-{bumped_ver}-{arch}"

    # Run `sandbox update` with `n\n` on stdin so the prompt renders
    # the classification summary, then aborts cleanly (`read_yes_no`
    # in `update/mod.rs` returns false for any non-`y` token, which
    # routes to the `aborted.` exit path with status 0).
    #
    # Pin `SANDBOX_SOCKET` via `sudo env` because sudo's default env
    # scrub would otherwise drop the variable and the CLI would fall
    # back to `$XDG_RUNTIME_DIR/sandboxd/sandboxd.sock` (or
    # `$HOME/.local/...` for root), neither of which match the
    # production daemon's `/run/sandbox/sandboxd.sock`. Without the
    # socket the `/sessions` probe in `classify_stopped_sessions`
    # silently degrades to an empty list — the flat `stopped sessions: N`
    # fallback fires and the classification block never appears.
    r = vm.shell(
        "printf 'n\\n' | sudo env "
        "SANDBOX_SOCKET=/run/sandbox/sandboxd.sock "
        f"sandbox update --from {extracted_root}",
        timeout=300,
    )
    assert r.returncode == 0, (
        f"update prompt-abort path exited non-zero ({r.returncode}); "
        f"the read-only pre-flight should land on the prompt without "
        f"errors:\nstdout:\n{r.stdout}\nstderr:\n{r.stderr}"
    )
    assert "aborted." in r.stdout, (
        f"`n` at the prompt should produce `aborted.` on stdout, but "
        f"that token was not seen:\nstdout:\n{r.stdout}\nstderr:\n{r.stderr}"
    )

    # ---- Classification assertions ----

    # 1. Aggregate `stopped sessions compat` line: total >=1, recreate>=1.
    # Use `recreate=1` to pin exactly the synthetic row landed in the
    # `recreate` bucket. Any other stopped session injected by an
    # earlier flow would tip the count past 1 — the test owns its VM
    # so no other rows should exist; assert tightly.
    assert "stopped sessions compat:    1 sessions" in r.stdout, (
        f"aggregate `stopped sessions compat` line missing or "
        f"unexpected; the synthetic session should be the sole "
        f"stopped row in a freshly-installed VM:\n{r.stdout}"
    )
    assert "(ok=0, refresh-in-place=0, recreate=1)" in r.stdout, (
        f"bucket counts do not match: expected recreate=1 (and zeros "
        f"on the other two buckets — `guest_protocol_version=0` "
        f"is the canonical unsalvageable sentinel per "
        f"classify_session_compat):\n{r.stdout}"
    )

    # 2. Per-session row: synthetic id + proto=0 -> 1 + `recreate` label.
    expected_row = f"- {session_id}  proto=0 -> 1  recreate"
    assert expected_row in r.stdout, (
        f"per-session classification row missing or malformed; "
        f"expected substring {expected_row!r}:\n{r.stdout}"
    )

    # 3. No mutation: install state's installed_version is still v.
    # The prompt-abort path runs entirely in the read-only pre-flight
    # ; no lock acquisition, no install-state write.
    post_state = vm.shell(
        "sudo cat /var/lib/sandbox/.install-state.json",
        check=True, timeout=10,
    ).stdout
    assert f'"installed_version": "{base_ver}"' in post_state or \
        f'"installed_version":"{base_ver}"' in post_state, (
        f"install state mutated despite `n` at the prompt; expected "
        f"installed_version still {base_ver}:\n{post_state}"
    )
