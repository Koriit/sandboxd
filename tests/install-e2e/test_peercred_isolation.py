"""Multi-uid peercred / session-isolation Lima E2E tests.

This file lands three integration tests that close GitHub issues
#148, #150, and #151. All three exercise behaviors that cannot be
verified on the developer host (they need two distinct real operator
uids on the same Linux kernel) and therefore run inside the
install-e2e Lima VM harness rather than the host-level
``cargo nextest`` profile:

* ``integration_route_helper_uid_without_passwd_denies_cleanly``
  (closes #148, pins Spec 1 § 8.4 / § 3.4) — a uid that does not
  resolve in ``/etc/passwd`` is denied at the route-helper's
  pair-check step before any netns work, and the deny lands in the
  JSON-Lines audit log per Spec 1 § 3.5.

* ``integration_owner_isolation_uid_without_passwd_closes_connection``
  (closes #150, pins Spec 2 § 4.1 / § 7.5) — a connection from a uid
  with no passwd entry is closed cleanly by the daemon's peercred-
  aware acceptor; no panic, no response body, no leaked socket.

* ``integration_session_isolation_404_on_foreign_id``
  (closes #151, pins Spec 2 § 5 / § 7.5 / § 9.2) — a session owned
  by operator alice returns 404 when operator bob queries it by id.
  Wire shape matches Spec 2 § 5: status 404, body
  ``{"error":"session not found: <id>"}``.

The harness pieces (peercred-connector helper, alice/bob users,
audit-log scraping) live in ``conftest.py``; this file consumes them.

All three tests are memory-constrained — each boots its own Lima VM
and the host is intentionally serial (one VM at a time, never two
together).
"""

from __future__ import annotations

import json
import re
import time
import uuid

import pytest

from conftest import (
    PEERCRED_CONNECTOR_VM_PATH,
    TEST_UID_BOB,
    TEST_UID_NOPASSWD,
    copy_tarball_to_vm,
    install_multi_operator_users_conf,
    install_sh_cmd,
    provision_peercred_connector_in_vm,
    provision_test_operators_in_vm,
    read_route_helper_audit_log,
    restart_sandboxd,
    vm_invoking_user,
    wait_for_socket,
    wait_for_systemd_active,
)


# ---------------------------------------------------------------------------
# Shared VM setup
# ---------------------------------------------------------------------------
#
# The three tests share an end-to-end shape: boot a VM, install
# sandboxd, provision the multi-uid harness (alice + bob + users.conf
# rewrite + peercred-connector binary), bounce sandboxd so the
# rewritten users.conf is in effect. Factored out so each test reads
# top-to-bottom as a single sequence of assertions, not as a re-
# implementation of the setup boilerplate.

# Production paths (Spec 3, install.sh):
DAEMON_SOCK = "/run/sandbox/sandboxd.sock"
ROUTE_HELPER = "/usr/local/libexec/sandboxd/sandbox-route-helper"

# Audit-log path the route-helper resolves to when XDG_RUNTIME_DIR is
# set to a writable test tempdir (Spec 1 § 3.5 lookup order, step 2:
# ``$XDG_RUNTIME_DIR/sandboxd/route-helper-audit.log``). Tests that
# invoke the helper directly via ``setpriv`` pin this path by setting
# ``XDG_RUNTIME_DIR`` in the invocation environment.
TEST_AUDIT_DIR_VM = "/tmp/sandboxd-test-audit"
TEST_AUDIT_LOG_VM = f"{TEST_AUDIT_DIR_VM}/sandboxd/route-helper-audit.log"


def _bring_up_peercred_vm(
    vm_factory,
    distro_template,
    release_tarball_x86_64,
    peercred_connector_binary,
):
    """Common setup for all three multi-uid peercred tests.

    Returns ``(vm, invoking_user)`` once the daemon is up, alice and
    bob exist, and the peercred-connector is installed setuid-root.
    ``invoking_user`` is the in-VM username that ``limactl shell``
    lands as (i.e. the user that install.sh's ``add_operator_to_group``
    joined to the ``sandbox`` group, host-dependent — ``lima`` on the
    stock Lima default, but matches the host's ``$USER`` when the host
    user differs).

    Steps:
      1. Boot a fresh VM, copy the tarball, run install.sh end-to-end.
      2. Enable + start sandboxd, wait for the unix socket.
      3. Create alice (uid 4001) and bob (uid 4002), both in the
         ``sandbox`` group.
      4. Rewrite ``/etc/sandboxd/users.conf`` so the daemon's startup
         subnet-resolver matches the daemon (``sandbox``) AND alice
         AND bob. The default install only lists the install-time
         operator, not alice or bob.
      5. Restart sandboxd so the rewritten users.conf takes effect.
      6. Provision the peercred-connector setuid-root binary into
         ``/usr/local/lib/sandboxd-tests/peercred-connector``.
      7. Capture the invoking-user name for tests that need to invoke
         the setuid-root peercred-connector from a uid already in the
         ``sandbox`` group.
    """
    vm = vm_factory(distro_template)
    tarball_in_vm = copy_tarball_to_vm(vm, release_tarball_x86_64)

    r = vm.shell(install_sh_cmd(tarball_in_vm), timeout=600)
    assert r.returncode == 0, (
        f"install.sh failed (exit {r.returncode})\n"
        f"stdout:\n{r.stdout}\nstderr:\n{r.stderr}"
    )

    vm.shell(
        "sudo systemctl enable --now sandboxd", check=True, timeout=60,
    )
    wait_for_systemd_active(vm.name, "sandboxd", timeout=60)
    wait_for_socket(vm.name, DAEMON_SOCK, timeout=60)

    # alice + bob with stable uids; both in ``sandbox`` group so they
    # can connect through the daemon socket's 0660 mode.
    provision_test_operators_in_vm(vm)

    # Rewrite users.conf so the daemon's startup subnet-resolver finds
    # itself in a pool; alice and bob join that pool. The default
    # install only listed the invoking operator (and sometimes nothing
    # — when the install was run as root with no SUDO_USER); the rewrite
    # makes the test independent of which user invoked sudo.
    install_multi_operator_users_conf(vm)

    # Bounce the daemon so the rewritten users.conf takes effect.
    restart_sandboxd(vm)

    # Provision peercred-connector setuid-root. Done last because the
    # helper is only consumed by the tests, not by install.sh.
    provision_peercred_connector_in_vm(vm, peercred_connector_binary)

    # Resolve the in-VM invoking user once (host-dependent — ``lima``
    # on Lima's default user mapping, host ``$USER`` otherwise).
    invoking_user = vm_invoking_user(vm)

    return vm, invoking_user


# ---------------------------------------------------------------------------
# #148 — route-helper uid without passwd denies cleanly
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("distro_template", ["ubuntu-22.04"])
def integration_route_helper_uid_without_passwd_denies_cleanly(
    distro_template,
    vm_factory,
    release_tarball_x86_64,
    peercred_connector_binary,
):
    """A route-helper invocation from a uid with no /etc/passwd entry
    must be denied at the caller-identity step (Spec 1 § 3.4), with
    the deny landing in the audit log (Spec 1 § 3.5).

    Behavior pinned:
      * Helper exits ``DENY_EXIT`` (1).
      * stderr contains ``caller uid <n> does not resolve to a username``
        verbatim (the Spec § 3.4 wording).
      * An audit-log JSON-Lines record is written with
        ``decision == "denied"``, ``reason == "caller-uid-unresolvable"``,
        and the caller field falls back to ``uid:<n>`` since there is
        no name to record.
      * No netns mutation occurs (the deny short-circuits before any
        privileged step; we observe this indirectly by asserting the
        helper exits non-zero within seconds — a successful netns
        traversal takes longer and would touch the host bridge).

    Synthesizing the unresolvable uid:
      The test uses ``setpriv --reuid=7777 --regid=7777`` to drop into
      a uid with no passwd entry. ``setpriv`` operates on numeric uids
      directly (no NSS lookup), so no ``useradd``/``userdel`` dance is
      needed inside the VM — uid 7777 simply does not exist in the
      stock template's ``/etc/passwd`` and ``setpriv`` does not put
      it there. The peercred-connector binary uses the same shape
      (``setresuid``); ``setpriv`` is shorter for tests that don't
      need the socket-connect post-condition.

    Audit-log path:
      The helper resolves the audit log via
      ``$XDG_RUNTIME_DIR/sandboxd/route-helper-audit.log`` when
      ``XDG_RUNTIME_DIR`` is set (Spec 1 § 3.5 step 2 of the lookup
      order). The test sets ``XDG_RUNTIME_DIR`` to a world-writable
      tempdir so the audit-log write succeeds even from a uid that
      has no homedir or default runtime dir.
    """
    vm, _invoking_user = _bring_up_peercred_vm(
        vm_factory,
        distro_template,
        release_tarball_x86_64,
        peercred_connector_binary,
    )

    # Stage a world-writable XDG_RUNTIME_DIR so uid 7777 can write the
    # audit-log line. The helper ``create_dir_all``s the ``sandboxd/``
    # subdir at first write, so we only need the parent to be 0777.
    vm.shell(
        f"sudo rm -rf {TEST_AUDIT_DIR_VM} && sudo install -d -m 0777 -o root -g root {TEST_AUDIT_DIR_VM}",
        check=True,
    )

    # Invoke the route-helper as uid 7777 (no /etc/passwd entry).
    #
    # ``setpriv --reuid --regid --clear-groups``:
    #   * Drops to numeric uid/gid 7777 without NSS lookup.
    #   * Clears all supplementary groups so the kernel sees a process
    #     whose entire credential set is uid:gid:groups = 7777:7777:{}.
    #
    # The route-helper has file caps ``cap_net_admin,cap_sys_admin=eip``
    # set at install time; setpriv's reuid does NOT strip them
    # (caps are file caps, not setuid). The helper still receives its
    # caps, runs its argv parser, then short-circuits at the
    # caller-identity step where ``User::from_uid(7777)`` returns
    # ``Ok(None)``.
    #
    # The positional argv values are placeholders: container_pid=1
    # (any valid integer) and gateway_ip=10.209.0.2. The pair-check
    # deny fires before any netns or pid resolution.
    helper_cmd = (
        f"sudo XDG_RUNTIME_DIR={TEST_AUDIT_DIR_VM} "
        f"setpriv --reuid={TEST_UID_NOPASSWD} --regid={TEST_UID_NOPASSWD} "
        "--clear-groups "
        f"-- {ROUTE_HELPER} --for-user=alice 1 10.209.0.2"
    )
    start_t = time.monotonic()
    r = vm.shell(helper_cmd, timeout=30)
    elapsed = time.monotonic() - start_t

    # Per § 3.3, every deny exits with ``DENY_EXIT`` (1) — the stderr
    # carries the load-bearing distinction.
    assert r.returncode == 1, (
        f"helper exited {r.returncode}, expected 1 (DENY_EXIT)\n"
        f"stdout:\n{r.stdout}\nstderr:\n{r.stderr}"
    )

    # Spec § 3.4 wording. Substring match — the helper formats the
    # numeric uid into the string, so we anchor on the verbatim
    # prefix and the explicit "does not resolve to a username" suffix.
    expected_substring = (
        f"caller uid {TEST_UID_NOPASSWD} does not resolve to a username"
    )
    assert expected_substring in r.stderr, (
        f"stderr did not contain Spec § 3.4 wording {expected_substring!r}:\n"
        f"stderr:\n{r.stderr}"
    )

    # No netns mutation: the deny short-circuits before any privileged
    # step. We assert wall time as a coarse correctness probe (a true
    # netns enter + route install would not return in under a second
    # even on warm hosts; the helper's deny path is sub-100ms in
    # practice). 5s is a generous ceiling that still catches the case
    # where the deny fell through.
    assert elapsed < 5.0, (
        f"helper took {elapsed:.2f}s — deny path should short-circuit "
        "well under 1s; >5s suggests netns work happened"
    )

    # ---------------- Audit-log assertions ----------------

    records = read_route_helper_audit_log(vm, TEST_AUDIT_LOG_VM)
    assert len(records) == 1, (
        f"expected exactly one audit record, got {len(records)}:\n"
        f"{records!r}"
    )
    rec = records[0]
    assert rec.get("decision") == "denied", (
        f"audit record decision: expected 'denied', got {rec.get('decision')!r}\n"
        f"full record: {rec!r}"
    )
    # Per Spec § 3.5, the reason tag for an unresolvable caller uid is
    # ``caller-uid-unresolvable`` (matching the route-helper's literal
    # at sandbox-route-helper/src/main.rs).
    assert rec.get("reason") == "caller-uid-unresolvable", (
        f"audit record reason: expected 'caller-uid-unresolvable', "
        f"got {rec.get('reason')!r}\nfull record: {rec!r}"
    )
    # The caller field falls back to ``uid:<n>`` since no name resolves
    # (Spec § 3.4 deny-record-completeness invariant: include as much
    # identity as the helper could establish, never silently drop).
    assert rec.get("caller") == f"uid:{TEST_UID_NOPASSWD}", (
        f"audit record caller: expected 'uid:{TEST_UID_NOPASSWD}', "
        f"got {rec.get('caller')!r}\nfull record: {rec!r}"
    )
    # The for_user was given on argv, so it lands as a literal name.
    assert rec.get("for_user") == "alice", (
        f"audit record for_user: expected 'alice', "
        f"got {rec.get('for_user')!r}\nfull record: {rec!r}"
    )
    # ``pid`` field carries the container_pid positional arg verbatim.
    assert rec.get("pid") == 1, (
        f"audit record pid: expected 1, got {rec.get('pid')!r}"
    )
    assert rec.get("gateway_ip") == "10.209.0.2", (
        f"audit record gateway_ip: expected '10.209.0.2', "
        f"got {rec.get('gateway_ip')!r}"
    )

    # ---------------- Negative side-effect assertions ----------------

    # The daemon should be untouched: the route-helper was invoked
    # directly, not through the daemon's helper-dispatch path, so
    # sandboxd's lifecycle is unaffected. A doctor-passes smoke
    # confirms the daemon did not get into a weird state.
    r = vm.shell(
        f"sudo -u sandbox env SANDBOX_SOCKET={DAEMON_SOCK} "
        "/usr/local/bin/sandbox doctor",
        timeout=30,
    )
    assert r.returncode == 0, (
        f"sandbox doctor reports unhealthy after route-helper deny:\n"
        f"stdout:\n{r.stdout}\nstderr:\n{r.stderr}"
    )




# ---------------------------------------------------------------------------
# #150 — daemon closes connection from uid without passwd
# ---------------------------------------------------------------------------

def _request_bytes(line, headers=None):
    """Compose an HTTP/1.1 request blob with CRLF framing.

    ``line`` is the request line (``GET /foo HTTP/1.1``); ``headers``
    is an iterable of ``(name, value)`` tuples. The body is always
    empty — these tests don't POST. ``Connection: close`` is added so
    the daemon hangs up after the response, letting peercred-connector
    return promptly.
    """
    if headers is None:
        headers = []
    hdrs = list(headers) + [("Host", "localhost"), ("Connection", "close")]
    head = line + "\r\n"
    head += "".join(f"{n}: {v}\r\n" for n, v in hdrs)
    head += "\r\n"
    return head


@pytest.mark.parametrize("distro_template", ["ubuntu-22.04"])
def integration_owner_isolation_uid_without_passwd_closes_connection(
    distro_template,
    vm_factory,
    release_tarball_x86_64,
    peercred_connector_binary,
):
    """The daemon's peercred acceptor closes connections from uids
    that do not resolve in ``/etc/passwd``, per Spec 2 § 4.1.

    Behavior pinned:
      * peercred-connector's ``setresuid(7777)`` succeeds (the helper
        is installed setuid-root).
      * The unix-socket connect completes (TCP-level handshake; the
        kernel does not reject the connect based on peercred).
      * The daemon's acceptor reads ``SO_PEERCRED`` → uid 7777, calls
        ``getpwuid_r`` → ``None``, ``drop(stream)``s, no bytes flow
        back to the helper.
      * peercred-connector reports zero bytes read; its stdout is
        empty.
      * The daemon journal shows the per-connection ``warn!`` line
        documenting the no-resolve close. No panic, no error response,
        no leaked socket.
      * Subsequent connections from a resolvable uid (alice) succeed,
        proving the daemon recovered cleanly.

    Wire-level note: ``UnixStream`` connect is a synchronous primitive
    that returns once both endpoints have the socket-pair, regardless
    of any in-band protocol. The daemon's ``drop(stream)`` after the
    failed resolve closes the kernel socket; depending on whether any
    bytes are queued in the receive buffer when close() runs, the
    kernel may emit either a graceful FIN (peer reads ``n == 0`` and
    the connector exits 0) or RST (peer reads ``ECONNRESET`` and the
    connector exits 4 with "Connection reset by peer" on stderr).
    Spec 2 § 4.1 specifies "close the connection without sending a
    response" — both close shapes satisfy that invariant, since the
    observable contract is "no response bytes flowed back to the
    client". This test therefore accepts either arm.
    """
    vm, invoking_user = _bring_up_peercred_vm(
        vm_factory,
        distro_template,
        release_tarball_x86_64,
        peercred_connector_binary,
    )

    # Compose a GET /sessions request. The exact endpoint does not
    # matter — the daemon never parses HTTP because the connection
    # closes before the first read; the request bytes are flushed but
    # discarded.
    req = _request_bytes("GET /sessions HTTP/1.1")
    vm.shell(
        f"cat > /tmp/req-7777 <<'EOF'\n{req}EOF",
        check=True,
    )

    # Mark the journal cursor so the subsequent assertion only inspects
    # events from this test rather than the install-time noise.
    cursor_line = vm.shell(
        "sudo journalctl -u sandboxd --show-cursor -n 1 --no-pager | tail -1",
        check=True,
    ).stdout.strip()
    # ``--show-cursor`` prints ``-- cursor: s=...`` on the last line.
    cursor_match = re.search(r"cursor:\s*(\S+)", cursor_line)
    assert cursor_match, (
        f"could not extract journal cursor from: {cursor_line!r}"
    )
    cursor = cursor_match.group(1)

    # Invoke peercred-connector as the install-time operator (host-
    # dependent — ``lima`` on Lima's default user mapping, host
    # ``$USER`` otherwise). That user was added to the ``sandbox``
    # group by install.sh's ``add_operator_to_group``. The helper
    # inherits their supplementary groups, then ``setresuid(7777)``
    # drops the real/effective/saved uid+gid; supplementary groups
    # (including ``sandbox``) are NOT touched by ``setresgid`` and so
    # the helper retains group-read access to the 0660 daemon socket.
    # This is the same shape Spec 2 § 9.2 specifies for the multi-uid
    # harness.
    r = vm.shell(
        f"sudo -u {invoking_user} {PEERCRED_CONNECTOR_VM_PATH} "
        f"--uid {TEST_UID_NOPASSWD} "
        f"--request-file /tmp/req-7777 "
        f"--socket {DAEMON_SOCK}",
        timeout=30,
    )

    # Spec 2 § 4.1 invariant: the daemon closed the connection without
    # sending a response. Two observable shapes both satisfy this:
    #
    #   - exit 0, empty stdout, empty stderr: the kernel delivered a
    #     graceful FIN; the connector's read loop saw ``n == 0`` and
    #     treated EOF as a clean close.
    #   - exit 4, empty stdout, stderr containing "Connection reset by
    #     peer": the kernel delivered RST (daemon's ``drop(stream)``
    #     closed the fd with the request bytes still queued in the
    #     receive buffer); the connector's ``read_response`` returned
    #     ECONNRESET and it exited with code 4.
    #
    # Both arms pin the same wire-level invariant: no response bytes
    # flowed back to the client. The choice between FIN and RST is a
    # kernel-side function of whether unread data is queued at close-
    # time (see TODO note at the end of the test about whether the
    # daemon SHOULD prefer graceful FIN — out of scope for this test).
    if r.returncode == 0:
        assert r.stdout == "" and r.stderr == "", (
            f"daemon close-without-response (FIN arm): expected empty "
            f"stdout/stderr; got stdout={r.stdout!r} stderr={r.stderr!r}"
        )
    elif r.returncode == 4:
        assert r.stdout == "" and "Connection reset by peer" in r.stderr, (
            f"daemon close-without-response (RST arm): expected empty "
            f"stdout and 'Connection reset by peer' in stderr; got "
            f"stdout={r.stdout!r} stderr={r.stderr!r}"
        )
    else:
        raise AssertionError(
            f"peercred-connector exited {r.returncode}; expected 0 "
            f"(graceful FIN) or 4 (RST). Both satisfy Spec 2 § 4.1's "
            f"'close without sending a response' invariant.\n"
            f"stdout:\n{r.stdout!r}\nstderr:\n{r.stderr!r}"
        )

    # ---------------- Journal assertion ----------------

    # The acceptor's no-resolve branch logs a structured ``warn!`` line
    # documenting the close. Read from the cursor we stashed pre-
    # invocation so we don't get false positives from install-time
    # log noise. The match is on the substring the acceptor emits.
    journal = vm.shell(
        f"sudo journalctl -u sandboxd --after-cursor='{cursor}' --no-pager",
        check=True,
        timeout=15,
    ).stdout
    # Two substrings to look for, both from the acceptor's branch:
    #   1. ``peer uid does not resolve to a username; closing connection``
    #   2. ``uid=7777``
    # Combining them protects against an unrelated warn line that
    # happens to mention "uid=7777" or "closing connection".
    assert "peer uid does not resolve to a username" in journal, (
        f"sandboxd journal missing acceptor's no-resolve warn line:\n"
        f"{journal}"
    )
    assert f"uid={TEST_UID_NOPASSWD}" in journal or f"uid=\"{TEST_UID_NOPASSWD}\"" in journal, (
        f"sandboxd journal missing uid={TEST_UID_NOPASSWD} marker:\n"
        f"{journal}"
    )

    # ---------------- Recovery assertion ----------------
    #
    # The daemon recovered cleanly: a subsequent connection from a
    # resolvable uid (alice) lands and the daemon emits a valid
    # response. We use the CLI ``sandbox ps`` as the simplest probe —
    # it sends ``GET /sessions`` which the daemon handles end-to-end
    # for any caller in the ``sandbox`` group. Empty session list is
    # fine; we only need a 200.
    r = vm.shell(
        f"sudo -u alice env SANDBOX_SOCKET={DAEMON_SOCK} "
        "/usr/local/bin/sandbox ps",
        timeout=30,
    )
    assert r.returncode == 0, (
        f"sandbox ps as alice failed after the no-passwd close (the daemon "
        f"should have recovered):\nstdout:\n{r.stdout}\nstderr:\n{r.stderr}"
    )


# ---------------------------------------------------------------------------
# #151 — session isolation: 404 on foreign session id
# ---------------------------------------------------------------------------

def _inject_synthetic_session(vm, *, session_id, owner_username, backend="lima"):
    """INSERT a session row directly into sessions.db with the given
    owner. Bypasses the create-session HTTP path so the test does not
    have to pay the cost of booting a real backend (Lima VM or
    container).

    The row's ``config_json`` is the minimal valid SessionConfig
    serialization (``cpus``, ``memory_mb``, ``disk_gb``, ``hardened``).
    The ``state`` is ``Stopped`` so the GET handler's runtime-status
    enrichment short-circuits without attempting to probe a non-
    existent backend handle.

    Note: the daemon holds the sqlite connection over a mutex; SQLite
    file-level locking lets a separate ``sqlite3`` process write while
    the daemon is running, with brief contention at worst. For a
    single small INSERT this is well within tolerance.

    sqlite3 CLI dependency: the install-e2e VM's package set
    (`_install_prereqs`) only installs what install.sh's
    ``check_prereqs`` verifies — ``sqlite3`` is NOT in that set. This
    helper is the only consumer of the sqlite3 CLI in the test suite,
    so we install it lazily here. ``apt-get install`` is idempotent;
    if the package is already present the call is a near-noop.
    """
    # Lazy install of the sqlite3 CLI. Scoped to this helper because
    # only the synthetic-injection path uses it; we don't want to bloat
    # ``_install_prereqs`` with a dependency that install.sh itself
    # does not require.
    vm.shell(
        "set -eux; "
        "export DEBIAN_FRONTEND=noninteractive; "
        "if ! command -v sqlite3 >/dev/null 2>&1; then "
        "  sudo apt-get install -y --no-install-recommends sqlite3; "
        "fi",
        check=True,
        timeout=120,
    )

    config_json = json.dumps(
        {
            "cpus": 2,
            "memory_mb": 4096,
            "disk_gb": 20,
            "hardened": True,
        }
    )
    # ISO-8601 timestamps with 'Z' suffix to match the daemon's
    # ``DateTime<Utc>::to_rfc3339()`` output. SQLite stores them as
    # TEXT; the daemon parses with ``DateTime::parse_from_rfc3339``.
    now = "2026-05-16T00:00:00Z"
    # Escape single quotes for shell. The values we're inserting are
    # under our control (no operator-supplied substrings), so a
    # heredoc-into-sqlite3 is safe.
    sql = (
        "INSERT INTO sessions "
        "(id, name, state, config, created_at, updated_at, backend, "
        " owner_username, guest_protocol_version, guest_binary_version) "
        f"VALUES ('{session_id}', NULL, 'Stopped', '{config_json}', "
        f"'{now}', '{now}', '{backend}', '{owner_username}', 1, '0.1.0');"
    )
    vm.shell(
        f"sudo sqlite3 /var/lib/sandbox/sessions.db \"{sql}\"",
        check=True,
        timeout=10,
    )


def _parse_http_status(response_bytes):
    """Return the integer status code from an HTTP/1.1 response, or
    raise AssertionError with the raw bytes on a malformed response.

    peercred-connector dumps the daemon's raw response to stdout; we
    parse the status line directly rather than depending on a Python
    HTTP client (none of which understand reading from a string).
    """
    text = response_bytes
    if isinstance(text, bytes):
        text = text.decode("utf-8", errors="replace")
    first_line, _, rest = text.partition("\r\n")
    parts = first_line.split(" ", 2)
    if len(parts) < 2 or not parts[1].isdigit():
        raise AssertionError(
            f"malformed HTTP status line: {first_line!r}\n"
            f"full response:\n{text!r}"
        )
    return int(parts[1]), rest


@pytest.mark.parametrize("distro_template", ["ubuntu-22.04"])
def integration_session_isolation_404_on_foreign_id(
    distro_template,
    vm_factory,
    release_tarball_x86_64,
    peercred_connector_binary,
):
    """A session owned by alice returns 404 when queried by bob.

    Behavior pinned (Spec 2 § 5 + § 7.5 + § 9.2):
      * A session row owned by ``owner_username = alice`` is invisible
        to a peercred caller resolved as ``bob`` — the SessionStore
        filter rejects foreign-owner rows from every per-id endpoint
        (H3, H5, H6, ...; for this test we exercise H3 ``GET /sessions/{id}``).
      * The 404 body matches ``{"error":"session not found: <id>"}``
        verbatim (Spec § 5 wire-shape: indistinguishable from a truly
        nonexistent id, so bob cannot infer existence-but-not-owned).
      * No 403 leaks through — the spec is explicit that the response
        is 404, not 403, to avoid telegraphing whether the id exists.

    Mechanism:
      * A fake row is INSERTed directly into ``/var/lib/sandbox/sessions.db``
        via ``sqlite3`` (run as root), owner = alice. The daemon's
        in-memory state holds nothing; reads go through the open
        sqlite handle and see the new row on next query.
      * ``peercred-connector --uid <bob>`` opens the daemon socket
        under bob's uid (kernel-set SO_PEERCRED), writes the GET
        request, and forwards the daemon's response to stdout.
      * The test asserts on the parsed status code (404) and the
        response body shape.

    Why not create via the CLI as alice? The full create path runs
    backend provisioning (Lima VM boot or container start) plus
    network + CA setup, which is expensive and orthogonal to the
    invariant under test (the per-caller storage filter). The
    synthetic-row injection is the same technique Spec 2 § 7.5 uses
    for the host-level ``integration_synthetic_foreign_owner_returns_404``
    test; here we lift it into the Lima multi-uid harness so the
    peercred path is end-to-end real.
    """
    vm, invoking_user = _bring_up_peercred_vm(
        vm_factory,
        distro_template,
        release_tarball_x86_64,
        peercred_connector_binary,
    )

    # Synthesize a session id alice owns. The id format is 12 lowercase
    # hex chars per Spec § "session id format"; we generate one fresh
    # for the test so we never collide with anything else in the DB.
    session_id = uuid.uuid4().hex[:12]
    _inject_synthetic_session(
        vm,
        session_id=session_id,
        owner_username="alice",
    )

    # Sanity check: alice CAN see her own row through the daemon.
    # Use ``sandbox ps`` as the simplest probe — running as alice via
    # the CLI exercises the peercred path end-to-end. The CLI renders
    # a text table with the full session id in the first column; we
    # only need the presence of the id to confirm alice's filter view
    # returned the synthetic row.
    r = vm.shell(
        f"sudo -u alice env SANDBOX_SOCKET={DAEMON_SOCK} "
        "/usr/local/bin/sandbox ps",
        timeout=30,
    )
    assert r.returncode == 0, (
        f"sandbox ps as alice failed:\n"
        f"stdout:\n{r.stdout}\nstderr:\n{r.stderr}"
    )
    assert session_id in r.stdout, (
        f"alice's `sandbox ps` did not list the synthetic row "
        f"{session_id!r}:\nstdout:\n{r.stdout}\nstderr:\n{r.stderr}"
    )

    # ---------------- The actual isolation assertion ----------------

    # Compose GET /sessions/<session_id> as the request body.
    req = _request_bytes(f"GET /sessions/{session_id} HTTP/1.1")
    vm.shell(
        f"cat > /tmp/req-bob-get <<'EOF'\n{req}EOF",
        check=True,
    )

    # Run peercred-connector as bob's uid. ``sudo -u <invoking_user>``
    # invokes the helper from the install-time operator (host-dependent
    # — ``lima`` on Lima's default user mapping, host ``$USER``
    # otherwise; in either case in the ``sandbox`` group via install.sh's
    # ``add_operator_to_group``) so the helper inherits the sandbox
    # supplementary group through the setuid-exec; then setresuid(bob)
    # drops to bob, retaining the supplementary group -> socket connect
    # works -> peercred reports bob's uid to the daemon.
    r = vm.shell(
        f"sudo -u {invoking_user} {PEERCRED_CONNECTOR_VM_PATH} "
        f"--uid {TEST_UID_BOB} "
        f"--request-file /tmp/req-bob-get "
        f"--socket {DAEMON_SOCK}",
        timeout=30,
    )
    assert r.returncode == 0, (
        f"peercred-connector --uid={TEST_UID_BOB} exited {r.returncode}\n"
        f"stdout:\n{r.stdout!r}\nstderr:\n{r.stderr!r}"
    )

    status, rest = _parse_http_status(r.stdout)
    assert status == 404, (
        f"GET /sessions/{session_id} as bob: expected 404, got {status}\n"
        f"full response:\n{r.stdout!r}"
    )

    # Body shape per Spec § 5: ``{"error":"session not found: <id>"}``.
    # The body is at the tail of the response after the blank line
    # separating headers from body.
    body_split = rest.split("\r\n\r\n", 1)
    assert len(body_split) == 2, (
        f"could not separate headers from body in:\n{rest!r}"
    )
    body = body_split[1]
    body_json = json.loads(body)
    assert body_json == {"error": f"session not found: {session_id}"}, (
        f"body did not match Spec § 5 shape; got: {body_json!r}"
    )

    # ---------------- Sanity: bob ALSO cannot see it via list ----------------

    # Spec § 5 also pins ``GET /sessions`` (the list endpoint) — bob's
    # ``sandbox ps`` must not surface alice's row. Re-using the CLI
    # path because it's the operator-visible surface for the list
    # endpoint.
    r = vm.shell(
        f"sudo -u bob env SANDBOX_SOCKET={DAEMON_SOCK} "
        "/usr/local/bin/sandbox ps",
        timeout=30,
    )
    assert r.returncode == 0, (
        f"sandbox ps as bob failed:\nstdout:\n{r.stdout}\nstderr:\n{r.stderr}"
    )
    assert session_id not in r.stdout, (
        f"bob's `sandbox ps` leaked alice's session id {session_id!r}:\n"
        f"{r.stdout}"
    )
