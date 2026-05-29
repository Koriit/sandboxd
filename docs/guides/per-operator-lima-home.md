# Per-operator LIMA_HOME and the `sandbox-lima-helper`

## Overview

When the Lima backend creates a session, the daemon (running as the `sandbox`
system user, uid 999) must invoke `limactl` as the **operator's** uid so that
the per-VM SSH key (`_config/user`) is owned by the operator.  OpenSSH's
`StrictKeyfileMode` rejects keys whose owning uid does not match the calling
uid, so a key written by the daemon uid is unusable by the operator's `ssh`
client.

The solution is a narrowly-scoped setcap helper, `sandbox-lima-helper`, that:

1. Validates the caller is the daemon (uid check + sandbox-group check).
2. Validates the target operator uid (non-root, sandbox-group member).
3. Drops to the operator uid via `setresuid`.
4. Clears all capabilities.
5. Execs `limactl` with a sanitised env block that includes
   `LIMA_HOME=/var/lib/sandboxd/<op_uid>/lima/`.

This mirrors the `sandbox-route-helper` privilege model documented in
`CLAUDE.md`.

---

## Required directories

### `/var/lib/sandboxd/`

Root of all per-operator Lima state.  Must exist before the daemon starts.

| Property  | Value              |
|-----------|--------------------|
| Owner     | `sandbox:sandbox`  |
| Mode      | `0750`             |

Created by `make setup-dev-env` (via the `setup-sandboxd-state-dir` target).
If the directory is absent at daemon startup the daemon attempts to create it;
`EACCES` is a fatal startup error.

### `/var/lib/sandboxd/<op_uid>/lima/`

Per-operator LIMA_HOME.  Created automatically at first session-create for
each operator by `ensure_operator_lima_home()` in `sandbox-core`.

| Property           | Value                          |
|--------------------|--------------------------------|
| Owner              | `sandbox:sandbox`              |
| Mode               | `0750`                         |
| Access ACL         | `u:<op_uid>:rwx`               |
| Default ACL        | `d:u:<op_uid>:rwx`             |

The access ACL grants the operator directory-level rwx.  The default ACL
propagates that rwx to every child that `limactl create` writes inside the
directory — including `_config/user` (mode 0600, owned by the operator after
the helper pivot) — without any subsequent `chown` step.

**Note on `_config/user`:** the key file itself does **not** receive an ACL.
It is written by helper-pivoted `limactl` running as the operator, so it ends
up owned `<op_uid>:<op_gid>` mode 0600, satisfying `StrictKeyfileMode` via
plain `st_mode`/owner match.  Adding an ACL to the key file would be
unnecessary and would cause `ls -l` to display the `+` marker on a file that
operators reasonably expect to be vanilla.

---

## Install prerequisites

### `acl` package

`setfacl` and `getfacl` must be installed:

```
# Debian/Ubuntu
apt install acl

# RHEL/Fedora
dnf install acl
```

`make setup-dev-env` warns if `setfacl` is missing.  The daemon calls
`setfacl` at session-create time; a missing binary is a fatal error for the
first Lima session of each new operator.

### `sandbox-lima-helper`

The helper must be installed at `/usr/local/libexec/sandboxd/sandbox-lima-helper`
with `cap_setuid+ep`:

```
make install-lima-helper-prod-cap
```

The daemon resolves the helper at startup via `$SANDBOX_LIMA_HELPER_PATH`
(override) or the canonical install path.  A missing or un-cap'd helper is a
**fatal startup error** — the daemon refuses to boot with a clear log line:

```
ERROR sandbox-lima-helper not usable; daemon cannot start
```

For the test environment, the test-cap'd build is installed at
`/usr/local/libexec/sandboxd-test/sandbox-lima-helper` by
`make install-lima-helper-test-cap`.  Integration tests point at this path
via `$SANDBOX_LIMA_HELPER_PATH`.

---

## Per-operator base-image serialization

Each operator's first session-create triggers a base-image build (5–10 min).
The daemon holds a `LimaManagerRegistry` — a `Mutex<HashMap<u32, Arc<LimaManager>>>`
keyed by operator uid.  Concurrent session-creates from the **same** operator
queue on the per-instance build mutex; concurrent creates from **different**
operators are fully independent.

One `LimaManager` (and therefore one base image) per operator; the registry
entries persist for the daemon's lifetime.

---

## Upgrade notes

Sessions created before V008 (`operator_uid IS NULL`) are dropped by the
V009 migration (`DELETE FROM sessions WHERE operator_uid IS NULL`).  Their
VMs live in the old host-global LIMA_HOME at `/var/lib/sandbox/.lima/` which
the new per-operator model does not use.  After upgrading, recreate any
affected sessions with `sandbox create`.

The old LIMA_HOME at `/var/lib/sandbox/.lima/` becomes abandoned filesystem
state; it can be deleted manually once all sessions have been recreated.
