---
title: Per-operator LIMA_HOME and the sandbox-lima-helper
description: Why the daemon runs every limactl operation through the sandbox-lima-helper setcap binary, pivoting to the operator's uid so the per-VM SSH key is owned by the operator and passes OpenSSH's StrictKeyfileMode.
---

## Overview

When the Lima backend creates a session, the daemon (running as the `sandbox`
system user, uid 999) must invoke `limactl` as the **operator's** uid so that
the per-VM SSH key (`_config/user`) is owned by the operator. OpenSSH's
`StrictKeyfileMode` rejects keys whose owning uid does not match the calling
uid, so a key written by the daemon uid is unusable by the operator's `ssh`
client.

The solution is a narrowly-scoped setcap helper, `sandbox-lima-helper`, that:

1. Validates the caller is the daemon (uid check + sandbox-group check).
2. Validates the target operator uid (non-root, sandbox-group member).
3. Drops to the operator uid via `setresuid`.
4. Clears all capabilities.
5. Execs `limactl` with a sanitised env block that includes
   `LIMA_HOME=/var/lib/sandboxd/<daemon_uid>/<op_uid>/lima/`.

This mirrors the `sandbox-route-helper` privilege model documented in
`CLAUDE.md`.

---

## Why the daemon never calls `limactl` directly

Every Lima control-plane operation — session create, start, stop, delete, clone,
shell, list, proxy-port lookup, and base-image build — runs through
`sandbox-lima-helper`. No limactl call bypasses it. The reason is structural:
Lima writes and reads files in `LIMA_HOME` as the calling uid. If any limactl
invocation ran as the daemon uid (uid 999, `sandbox`), it would either write
files the operator cannot own (breaking `StrictKeyfileMode`), or read from the
wrong per-operator LIMA_HOME and silently miss the session. The per-operator
LIMA_HOME model only holds if the isolation is airtight — a single daemon-uid
limactl call leaks across the boundary. This is why every call site uses the
helper unconditionally, including the orphan-scan path that runs at daemon
startup.

---

## Required directories

### `/var/lib/sandboxd/`

State root, shared by all daemon users on the host. Must be world-traversable
so each daemon user (`sandbox`, `sandbox-test`, …) can reach its own per-uid
subtree.

| Property | Value      |
| -------- | ---------- |
| Owner    | `root:root` |
| Mode     | `0755`     |

Created by `make setup-dev-env` (via the `setup-sandboxd-state-dir` target)
and by `install.sh` on a production host.

### `/var/lib/sandboxd/<daemon_uid>/`

Per-daemon subtree. Each daemon user owns exactly one subtree keyed on its
numeric uid. All daemon state (sessions.db, sessions/, events/, backups/,
.install-state.json, .update.lock) lives here, as does the socket and the
per-operator Lima homes.

| Property | Value                    |
| -------- | ------------------------ |
| Owner    | `<daemon_user>:<daemon_user>` |
| Mode     | `0750`                   |

### `/var/lib/sandboxd/<daemon_uid>/<op_uid>/lima/`

Per-operator LIMA_HOME, nested under the daemon uid's subtree. Created
automatically at first session-create for each operator by
`ensure_operator_lima_home()` in `sandbox-core`.

| Property   | Value             |
| ---------- | ----------------- |
| Owner      | `sandbox:sandbox` |
| Mode       | `0750`            |
| Access ACL | `u:<op_uid>:rwx`  |
| Default ACL | `d:g::---`, `d:o::---` |

The access ACL grants the operator directory-level `rwx` on the LIMA_HOME
root so helper-pivoted `limactl` (running as `op_uid`) can create instance
subdirectories and write files inside them. The default ACLs suppress group
and world read on all children — a belt-and-suspenders guard for the ACL mask.

There is deliberately **no** default named-user ACL (`d:u:<op_uid>:rwx`).
A default named-user ACL would propagate into every child, including
`_config/user` (Lima's SSH private key). Linux's ACL mask rule forces
`st_mode` group bits ≥ the mask whenever a named-user entry exists; OpenSSH's
`StrictKeyfileMode` calls `stat(2)` and rejects any key whose `st_mode & 077
≠ 0` — causing the host agent to loop "bad permissions" for the full 600 s
start timeout. Because helper-pivoted `limactl` runs as the operator and
**owns** every file it creates, owner-bit access is sufficient; no named-user
ACL propagation is needed.

**Note on `_config/user`:** the key file does **not** receive an ACL. It is
written by helper-pivoted `limactl` running as the operator, so it ends up
owned `<op_uid>:<op_gid>` mode 0600, satisfying `StrictKeyfileMode` via plain
`st_mode`/owner match.

---

## Install prerequisites

### `acl` package

`setfacl` and `getfacl` must be installed:

```text
# Debian/Ubuntu
apt install acl

# RHEL/Fedora
dnf install acl
```

`make setup-dev-env` warns if `setfacl` is missing. The daemon calls
`setfacl` at session-create time; a missing binary is a fatal error for the
first Lima session of each new operator.

### `sandbox-lima-helper`

The helper must be installed at `/usr/local/libexec/sandboxd/sandbox-lima-helper`
with `cap_setuid+ep`:

```text
make install-lima-helper-prod-cap
```

The daemon resolves the helper at startup via `$SANDBOX_LIMA_HELPER_PATH`
(override) or the canonical install path. A missing or un-cap'd helper is a
**fatal startup error** — the daemon refuses to boot with a clear log line:

```text
ERROR sandbox-lima-helper not usable; daemon cannot start
```

For the test environment, the test-cap'd build is installed at
`/usr/local/libexec/sandboxd-test/sandbox-lima-helper` by
`make install-lima-helper-test-cap`. Integration tests point at this path
via `$SANDBOX_LIMA_HELPER_PATH`.

---

## Per-operator base-image serialization

Each operator has their own base image seeded inside their per-operator LIMA_HOME.
This is a structural consequence of the per-operator LIMA_HOME design: Lima's clone
operation reads from the source VM's directory under LIMA_HOME, so the template must
live in the same LIMA_HOME the operator's sessions will use. A shared base image in a
global LIMA_HOME would require the daemon to access that global path with daemon-uid
permissions, contradicting the invariant that every limactl call runs as the operator.
The first session-create for a new operator therefore triggers a base-image build
(5–10 min on first run, image cached for subsequent creates from the same operator).

The daemon holds a `LimaManagerRegistry` — a `Mutex<HashMap<u32, Arc<LimaManager>>>`
keyed by operator uid. Concurrent session-creates from the **same** operator
queue on the per-instance build mutex; concurrent creates from **different**
operators are fully independent.

One `LimaManager` (and therefore one base image) per operator; the registry
entries persist for the daemon's lifetime.

---

## Upgrade notes

Sessions created before V008 (`operator_uid IS NULL`) are dropped by the
V009 migration (`DELETE FROM sessions WHERE operator_uid IS NULL`). Their
VMs live in the old host-global LIMA_HOME at `/var/lib/sandbox/.lima/` which
the new per-operator model does not use. After upgrading, recreate any
affected sessions with `sandbox create`.

The old LIMA_HOME at `/var/lib/sandbox/.lima/` becomes abandoned filesystem
state; it can be deleted manually once all sessions have been recreated.
