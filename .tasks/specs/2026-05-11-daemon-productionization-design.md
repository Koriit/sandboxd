# Daemon Productionization — Design

**Date:** 2026-05-11
**Status:** Approved
**Scope:** Dedicated `sandbox` system user, systemd unit, state at `/var/lib/sandbox/`, file modes, `sandbox doctor` subcommand, CLI ↔ daemon strict version equality on every connect, version-pinned image tags, and removal of the hardcoded `qemu-bridge-helper` install path. Spec 3 specifies the *deployment shape* that Spec 4 will install and Spec 5 will operate on.

---

## 0 · Sequence context

This spec is **Spec 3 of a five-spec arc** that prepares `sandboxd` for an end-user
install / uninstall / update story. The arc:

1. **Spec 1** — Helper identity assertion (committed at
   `.tasks/specs/2026-05-11-helper-identity-assertion-design.md`, SHA `246bbdd`)
2. **Spec 2** — API session isolation + guest version compatibility (committed at
   `.tasks/specs/2026-05-11-api-session-isolation-guest-compat-design.md`, revision
   SHA `7c026aa`)
3. **Spec 3 (this one)** — Daemon productionization
4. **Spec 4** — Release & install infrastructure
5. **Spec 5** — Update infrastructure (`sandbox update` CLI, config migration
   framework, backups, lock file)

Spec 3 depends on **both** Specs 1 and 2. Spec 1 makes a dedicated `sandbox` user
safe at the *helper authorization* layer: the route-helper's pair-check validates
that both `name(getuid()) == "sandbox"` (the daemon's uid post-Spec-3) and the
asserted `--for-user <operator>` are in the pool's `allow_users`, so per-user CIDR
pool isolation survives the move of the daemon out of the operator's account.
Spec 2 makes a dedicated `sandbox` user safe at the *API* layer: every
session-ID-shaped endpoint filters by `owner_username = name(SO_PEERCRED.uid)`, so
operators added to the `sandbox` group can talk to the daemon socket without
seeing each other's sessions. Without both, the dedicated-user shape is a
regression rather than a hardening: every operator sharing the socket could
disrupt every other operator's network (without Spec 1) or session (without
Spec 2).

What Spec 3 builds on top: the deployment-shape changes are what Spec 4 will
install (the install script materializes the `sandbox` user, lays down the
systemd unit, sets `/var/lib/sandbox/` permissions, installs the `sandbox`
binary, `sandboxd` binary, and `sandbox-route-helper`) and what Spec 5's
`sandbox update` operates on (replaces the binaries, leaves the unit's drop-in
dir intact, prunes nothing automatically). Spec 3 does **not** design any of
those scripts or pipelines — see § 14.

## 1 · Motivation

Today's `make setup-dev-env` (`Makefile:210`) configures the developer's host so
the developer's own user runs the daemon: the helper is cap'd, the bridge config
is laid down, the `users.conf` file lists the developer in `allow_users`. The
daemon process is the developer's process. That works for development. It is
the wrong shape for end-user or operator deployment for three reasons:

- **Daemon compromise = operator account compromise.** The daemon today runs as
  the same uid that owns `~/.ssh`, browser tokens, dotfiles, and any other
  ambient credentials the operator's account holds. A bug or attacker
  controlling the daemon can read or modify any of them. The standard hardening
  for long-running services — dedicated system user with no shell, no home,
  membership only in the groups it needs to do its job — is missing.
- **No standard process-management surface.** There is no systemd unit, so no
  `systemctl start sandboxd`, no auto-restart on crash, no boot-time
  activation, no journald integration. Operators run the daemon by hand under
  whatever shell session happens to be open, or with home-grown scripts.
- **State commingled with the operator's XDG data.** The daemon's database,
  per-session CA material, embedded gateway / lite images, and event JSONL live
  under `$XDG_DATA_HOME/sandboxd/` (or `~/.local/share/sandboxd/`). Backups,
  rotations, and access audits all become "scan the operator's home" rather
  than "scan one path everyone agrees is system state."

Spec 1 makes a dedicated `sandbox` user safe for the route-helper authorization
model; Spec 2 makes it safe for API-level session visibility. With both in
place, Spec 3 actually moves the shape and ships a service that an end user or
operator can install, start, stop, query, and update through standard system
mechanisms.

## 2 · Threat model

Walk through the post-Spec-3 boundary explicitly. The model is "single
single-tenant host, multiple mutually-trusted operators added to one group,
daemon mediates everything." § 2.4 records the one cross-user attack vector we
deliberately do not mitigate.

### 2.1 · What the dedicated `sandbox` user buys

- The daemon process runs as `sandbox` (a system user — UID < `SYS_UID_MAX`, no
  login shell, no home dir of its own beyond `/var/lib/sandbox/` which systemd
  creates). The user is a member of the `docker` group (so the daemon can talk
  to `dockerd`) and the `kvm` group (so it can open `/dev/kvm` for Lima).
- Compromise of the daemon yields control of the `sandbox` user only. The
  operator's `~/.ssh`, `~/.aws`, browser tokens, dotfiles, and editor history
  remain at filesystem-mode-level isolation from the daemon process.
- The shape is consistent with how `postgres`, `nginx`, `redis`, and similar
  long-running services are deployed: dedicated UID, dedicated state dir,
  systemd-managed lifecycle.

### 2.2 · What the `sandbox` group is and isn't

The `sandbox` group exists for **socket access**, not filesystem access.

- The daemon's Unix socket at `/run/sandbox/sandboxd.sock` is mode `0660`,
  owner `sandbox:sandbox`. Operators added to the `sandbox` group can `connect()`
  to it; operators outside the group get `EACCES`.
- Operators are added by the install script (for the installing operator) and
  by ad-hoc `sudo usermod -aG sandbox <user>` thereafter. Group membership is
  the install-time gate for "this user can talk to the daemon."
- Operators in the `sandbox` group **cannot** read or modify any file in
  `/var/lib/sandbox/` directly. The parent dir is `0750 sandbox:sandbox`
  (group can list and traverse but not write or chmod); the sensitive files
  inside — `sessions.db`, per-session CA keys, route-helper audit log — are
  `0600 sandbox:sandbox`; subdirectories are `0700 sandbox:sandbox`. Group
  membership grants nothing the daemon's API doesn't grant.
- All session interaction goes through the daemon's API, where Spec 2's
  `owner_username` filter enforces per-operator visibility. The daemon is the
  enforcement point; the filesystem modes are belt-and-suspenders, not the
  primary control.

### 2.3 · What's still shared

- Multiple operators in the `sandbox` group share **one daemon process**.
  After Spec 2, they cannot see or modify each other's sessions through the
  API; the daemon is the enforcement point and a daemon bug that bypasses
  the filter is a vulnerability in the daemon, not in the deployment shape.
- They share the underlying `dockerd` (via `sandbox`'s membership in the
  `docker` group). The daemon, not the operators, mediates Docker operations
  on operators' behalf. Direct `docker` invocations from operators against
  the daemon's containers are out of scope of this trust model — operators
  with `sandbox` group membership do **not** automatically gain `docker`
  group membership, and direct `docker ps` against the daemon's containers
  is an admin task, not an operator task.

### 2.4 · Known limitation — `qemu-bridge-helper` is cross-user

**Confirmed limitation, lifted from `.tasks/handoffs/spec-arc-followups.md`.
Tracked as GitHub issue [#8](https://github.com/Koriit/sandboxd/issues/8).**
Spec 3 does not attempt to mitigate this.

- `qemu-bridge-helper` is a setuid-root binary shipped and owned by QEMU. By
  design it does not implement per-user access control. The only rules it
  enforces are bridge-*name* allow-lists in `/etc/qemu/bridge.conf` — it does
  not constrain *callers*.
- Any local user on the host (in or out of the `sandbox` group) who can
  invoke `qemu-bridge-helper` could ask it to create bridges in the `sb-*`
  namespace that the daemon manages, potentially interfering with daemon-
  managed bridges and other operators' sandboxes.
- This is a property of QEMU's design. Sandboxd does not attempt to fix it
  without forking or replacing the helper, which is out of the project's
  scope.
- Spec 1's per-user pair-check on `sandbox-route-helper` is the analogous
  control sandboxd *does* enforce — but it covers only our route-helper,
  not the QEMU bridge helper.
- Spec 3 also *removes* the rootless-Docker code path that previously
  generated a per-invocation nsenter wrapper around `qemu-bridge-helper`
  inside `QEMU_WRAPPER_SCRIPT` (see § 9). The supported envelope is
  rootful Docker; rootless Docker is explicitly not supported (§ 14).

The deployment model therefore assumes operators on a multi-tenant box are
**mutually-trusted members of the `sandbox` group**. The API-level trust
boundary documented in Spec 2 is the primary control; the filesystem modes
in this spec are defense-in-depth; the bridge-helper gap is a deliberate
known limitation that operators must understand. We state it explicitly
because hiding it would mislead readers about the deployment's security
posture.

## 3 · The `sandbox` system user

### 3.1 · User properties

Spec 4's install script will create the user and group with the following
properties. Spec 3 fixes the contract so that script can be written:

| Property        | Value                                       |
|-----------------|---------------------------------------------|
| Username        | `sandbox`                                   |
| Primary group   | `sandbox`                                   |
| UID range       | system (`< SYS_UID_MAX`, picked by `useradd -r`) |
| Login shell     | `/usr/sbin/nologin`                          |
| Home dir        | `/var/lib/sandbox`                           |
| Home creation   | `--no-create-home` (systemd's `StateDirectory` creates it on first start) |
| Supplementary   | `docker`, `kvm`                              |

Construction (Spec 4 implements this verbatim):

```
useradd --system \
    --user-group \
    --no-create-home \
    --home-dir /var/lib/sandbox \
    --shell /usr/sbin/nologin \
    --comment "sandboxd — isolated environment broker" \
    sandbox
usermod -aG docker sandbox
usermod -aG kvm    sandbox
```

The `docker` group is **required** for both backends — the container backend
talks to `dockerd`, and the Lima backend uses Lima's `dockerCompat` mode for
bridge resolution. The `kvm` group is required so the daemon can open
`/dev/kvm` to run Lima VMs. Neither is optional.

### 3.2 · What the `sandbox` group is for

The `sandbox` group's sole purpose is **operator-to-socket access**.

- Owns the daemon's Unix socket at `/run/sandbox/sandboxd.sock` (mode `0660`).
- Operators are added to the group by the install script (for the installing
  user, automatically) and by `sudo usermod -aG sandbox <user>` (ad-hoc, for
  additional operators). New group membership takes effect on next login;
  doctor's check (§ 6.2) explicitly tests for it and surfaces the hint when
  missing.
- Group membership does **not** grant filesystem write access to
  `/var/lib/sandbox/`. The parent dir's `0750` group-perm permits listing and
  traversal only; the sensitive files inside are `0600`/`0700` and
  group-membership does not promote them.

A single group named `sandbox` exists; there is no separate `sandbox-admin`
or `sandbox-ops` group in v1. If an admin override surface ever lands (Spec 2
§ 2.6 explicitly defers this), it would be implemented by a future spec via
a dedicated `/etc/sandboxd/admins.conf` and not by widening this group's
authority.

## 4 · The systemd unit

### 4.1 · Unit file content

Ship verbatim. Installed to `/etc/systemd/system/sandboxd.service`:

```ini
[Unit]
Description=sandboxd — isolated environment broker
Documentation=https://github.com/kontaktio/sandbox-daemon
After=docker.service
Wants=docker.service

[Service]
Type=simple
User=sandbox
Group=sandbox

# State and runtime dirs are auto-created with correct ownership/modes.
# systemd will mkdir /var/lib/sandbox and /run/sandbox if they do not
# exist, and chown sandbox:sandbox + chmod 0750 on each.
StateDirectory=sandbox
StateDirectoryMode=0750
RuntimeDirectory=sandbox
RuntimeDirectoryMode=0750

# Operators customize via `systemctl edit sandboxd` (drop-in override),
# not by editing this file. See § 4.3.
ExecStart=/usr/local/bin/sandboxd \
    --base-dir /var/lib/sandbox \
    --socket /run/sandbox/sandboxd.sock

# Restart policy: any crash bounces; stop bouncing if it crashes >5 times
# in 5 minutes (likely a config problem that won't fix itself).
Restart=on-failure
RestartSec=5s
StartLimitIntervalSec=300
StartLimitBurst=5

# Hardening — each directive has a one-line rationale in § 4.2.
NoNewPrivileges=yes
ProtectSystem=full
ProtectHome=yes
PrivateTmp=yes
DeviceAllow=/dev/kvm rw

[Install]
WantedBy=multi-user.target
```

### 4.2 · Hardening directive rationale

Each `[Service]` hardening directive has one job:

| Directive | What it does | Why it's safe / necessary |
|---|---|---|
| `NoNewPrivileges=yes` | Process and all descendants cannot acquire new privileges via setuid/setcap on exec. | The daemon does not need to gain new privileges; it spawns `sandbox-route-helper` which already has file caps. **Verification:** file caps survive `NoNewPrivileges=yes` — they apply at exec, not at fork; the helper's `cap_net_admin,cap_sys_admin=eip` are honored. **Caveat:** this is the same constraint that prevented Lima's QEMU wrapper from using `-sandbox on` (`sandbox-core/src/lima.rs:2822-2825`), so the daemon side and Lima-VM side share the same reasoning. |
| `ProtectSystem=full` | `/usr`, `/boot`, `/efi`, `/etc` mounted read-only for the unit. | The daemon reads `/etc/sandboxd/users.conf` (`sandbox-core/src/users_conf.rs:81`) and `/etc/qemu/bridge.conf` (consumed by `qemu-bridge-helper`, not directly by the daemon) but **never writes** to either. Verified by inspection: `users_conf.rs` exposes only `load_users_config*` readers and the `validate_canonical_users_conf_security` predicate; there is no writer. Writes to those paths happen via `sandbox update` (Spec 5) running as root under `sudo` — the systemd unit does not constrain that. |
| `ProtectHome=yes` | `/home`, `/root`, `/run/user/*` mounted as empty `tmpfs` for the unit. | The daemon never needs to read operator home directories. Workspace-mode bind mounts (e.g. `sandbox create --workspace shared:/home/alice/repo`) are mediated by Docker / Lima, which run outside the daemon's namespace and are unaffected. **Caveat:** in dev mode (developer runs `sandboxd` from a `cargo run` shell), there is no systemd unit and `ProtectHome` does not apply — dev's existing access to its own home is unchanged. |
| `PrivateTmp=yes` | Private `/tmp` per unit. | The daemon writes nothing important to `/tmp` (the route-helper-audit-log lives under `/var/lib/sandbox/` post-Spec-3, see Spec 1 § 3.5; the embedded guest binary refresh tempfile from Spec 2 § 3.8 goes through `tempfile::NamedTempFile` which honors `TMPDIR` and `PrivateTmp` is `TMPDIR`-aware). |
| `DeviceAllow=/dev/kvm rw` | Whitelist `/dev/kvm` access. Implicit `DevicePolicy=auto` denies everything else. | Lima needs `/dev/kvm` for KVM-accelerated VMs. **No other devices** are listed: no `/dev/net/tun` (TAP creation happens inside the netns by the route-helper, not the daemon), no `/dev/vsock`, no `/dev/loop*`. If a future backend needs a new device, this list widens. |

The unit deliberately does **not** set `CapabilityBoundingSet=`,
`PrivateDevices=`, `RestrictAddressFamilies=`, or `SystemCallFilter=`. The
daemon's surface area (Docker IPC, Unix socket, raw netlink via Lima/QEMU
indirection) is broad enough that pinning these down precisely is its own
multi-week work item, and a misconfigured filter will silently break things
months later. We ship the directives whose semantics are bounded and well-
understood; we leave the long-tail filters for a follow-up that gets the
test coverage they require.

### 4.3 · Customization via drop-ins

Operators customize the unit through systemd's drop-in mechanism:

- `sudo systemctl edit sandboxd` opens
  `/etc/systemd/system/sandboxd.service.d/override.conf` for editing (creates
  the dir and file on first run).
- Common customizations: extra daemon flags (e.g. `--events-persist`),
  `LimitNOFILE=` overrides, environment variables for testing.
- Drop-in changes survive reinstalls of the base unit. **Spec 5's
  `sandbox update` must replace only `/etc/systemd/system/sandboxd.service`,
  not anything under `…/sandboxd.service.d/`.** This is a forward
  constraint on Spec 5, recorded here so the operator's customizations
  survive across updates.

Drop-in shape (operator-authored, for illustration):

```ini
# /etc/systemd/system/sandboxd.service.d/override.conf
[Service]
# Reset the existing ExecStart=, then re-declare it with --events-persist.
# This is the standard systemd "reset and re-set" idiom.
ExecStart=
ExecStart=/usr/local/bin/sandboxd \
    --base-dir /var/lib/sandbox \
    --socket /run/sandbox/sandboxd.sock \
    --events-persist

LimitNOFILE=65536
```

### 4.4 · What's *not* in the unit

Make explicit:

- **No daemon config file** (e.g. `/etc/sandboxd/daemon.conf`) in v1. All
  configuration is flags on `ExecStart`, customizable via drop-ins. The
  project's "config files are JSON" convention (CLAUDE.md) applies to
  config *files* the daemon reads — `users.conf`, presets — not to the
  daemon's own startup flags.
- **No `Wants=lima.service`.** Lima has no system service; `limactl` is
  invoked per-VM by the daemon. Adding `Wants=` to a nonexistent unit
  would fail at parse time.
- **No `User=` substitution mechanism for "the installing user".** The
  unit ships verbatim with `User=sandbox`. Install scripts do not template
  the unit. Pinning this here forecloses Spec 4 from inventing a
  templating layer; the deployment shape is single-instance, single-user.
- **No `socket` activation.** `RuntimeDirectory=sandbox` creates
  `/run/sandbox/` before `ExecStart`; the daemon binds its socket itself
  (`sandboxd/sandboxd/src/main.rs:6496`). Socket activation would
  complicate the start-up ordering for no benefit — the daemon's
  startup cost is dominated by SQLite migrations and the gateway-image
  presence check, not by socket bind latency.

## 5 · State location and file modes

### 5.1 · Path layout

Every path the daemon creates or touches under its base dir, with the mode,
owner, and creator. Modes are documented as the *daemon's responsibility* to
honor; the install script and systemd handle the parent dirs.

| Path                                                | Mode | Owner            | Created by                     | Notes |
|-----------------------------------------------------|------|------------------|--------------------------------|-------|
| `/var/lib/sandbox/`                                 | 0750 | sandbox:sandbox  | systemd `StateDirectory=`      | Group lists/traverses only; no write. |
| `/var/lib/sandbox/sessions.db`                      | 0600 | sandbox:sandbox  | daemon at first start (SQLite open) | Daemon-only. Created via `SessionStore::new` → `Connection::open` (`sandbox-core/src/store.rs:89-90`). The current open path inherits process umask; § 5.4 documents the explicit chmod the daemon performs to pin it at `0600` regardless of umask. |
| `/var/lib/sandbox/sessions/`                        | 0700 | sandbox:sandbox  | daemon at first start          | Per-session CA material and (post-Spec-2 V006) per-session event JSONL. |
| `/var/lib/sandbox/sessions/<id>/`                   | 0700 | sandbox:sandbox  | daemon on session create       | Created by `SessionStore::create_session_with_backend` (`store.rs:279`). |
| `/var/lib/sandbox/sessions/<id>/ca/`                | 0700 | sandbox:sandbox  | `CaManager::generate_session_ca` (`sandbox-core/src/ca.rs:47-100`) | Per-session CA cert and key. |
| `/var/lib/sandbox/sessions/<id>/events/`            | 0700 | sandbox:sandbox  | `events::persist::writer` (`sandbox-core/src/events/persist/writer.rs:100`) when `--events-persist` | JSONL event files. |
| `/var/lib/sandbox/events/`                          | 0700 | sandbox:sandbox  | daemon at first start          | Reserved for future cross-session event aggregation; created unconditionally for consistency. |
| `/var/lib/sandbox/backups/`                         | 0700 | sandbox:sandbox  | daemon at first start          | Populated by Spec 5's `sandbox update` (config migration backups). |
| `/var/lib/sandbox/route-helper-audit.log`           | 0600 | sandbox:sandbox  | route-helper on first invocation (Spec 1 § 3.5) | Append-only JSONL audit. |
| `/run/sandbox/`                                     | 0750 | sandbox:sandbox  | systemd `RuntimeDirectory=`    | Cleared on stop by systemd. |
| `/run/sandbox/sandboxd.sock`                        | 0660 | sandbox:sandbox  | daemon at start (`UnixListener::bind`, `main.rs:6496`) | Group access for operators. |

systemd takes care of `/var/lib/sandbox/` and `/run/sandbox/` (creation,
ownership, mode). The daemon takes care of every entry below those two
directories — see § 5.4 for the startup logic.

### 5.2 · The `--base-dir` flag and XDG fallback

Resolution precedence is **already implemented** in `default_base_dir` at
`sandboxd/sandboxd/src/main.rs:116-122`:

```rust
fn default_base_dir() -> String {
    if let Ok(data_home) = std::env::var("XDG_DATA_HOME") {
        return format!("{data_home}/sandboxd");
    }
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".into());
    format!("{home}/.local/share/sandboxd")
}
```

The clap arg definition at `main.rs:56-58` makes the default value the
output of `default_base_dir()`:

```rust
/// Base directory for daemon state (database, session data).
#[arg(long, default_value_t = default_base_dir())]
base_dir: String,
```

`clap` honors `--base-dir <path>` when given on the command line and falls
back to the computed default otherwise. Spec 3 changes nothing about this
resolver. The systemd unit always passes `--base-dir /var/lib/sandbox`
explicitly (§ 4.1 `ExecStart`), so the system-service path never invokes
the XDG fallback. Developers running `make setup-dev-env` invoke `sandboxd`
without `--base-dir`, hit the XDG fallback, and land in
`~/.local/share/sandboxd/` (or `$XDG_DATA_HOME/sandboxd/`).

The precedence chain composes cleanly with the new system-service default
because the unit's explicit `--base-dir` flag wins over any environment
variable systemd might pass through. No code change needed.

### 5.3 · Socket path resolution

Same shape, same resolver location. `default_socket_path` at
`sandboxd/sandboxd/src/main.rs:102-114`:

```rust
fn default_socket_path() -> String {
    if let Ok(sock) = std::env::var("SANDBOX_SOCKET") {
        return sock;
    }
    if let Ok(runtime_dir) = std::env::var("XDG_RUNTIME_DIR") {
        return format!("{runtime_dir}/sandboxd/sandboxd.sock");
    }
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".into());
    format!("{home}/.local/share/sandboxd/sandboxd.sock")
}
```

Precedence: `--socket` flag → `SANDBOX_SOCKET` env → `XDG_RUNTIME_DIR` →
`HOME`. The CLI has the symmetric resolver at
`sandboxd/sandbox-cli/src/main.rs:473-485`.

The systemd unit passes `--socket /run/sandbox/sandboxd.sock` explicitly.
The CLI under a system-service install has two paths to find the socket:

1. Operator sets `SANDBOX_SOCKET=/run/sandbox/sandboxd.sock` in their shell
   (or `/etc/profile.d/sandbox.sh` for everyone — Spec 4 territory).
2. `XDG_RUNTIME_DIR` is unset or doesn't contain a `sandboxd/sandboxd.sock`,
   so the CLI falls through to the `HOME` default and fails to connect with
   a clear error.

To keep ergonomics tractable, Spec 4 will ship a `/etc/profile.d/sandbox.sh`
that exports `SANDBOX_SOCKET=/run/sandbox/sandboxd.sock` for interactive
shells. Spec 3 does not specify that file; it only documents the
expectation. The doctor check in § 6.2 reports clearly when the CLI
resolves a socket path that doesn't exist or doesn't connect.

### 5.4 · Subdir mode enforcement at startup

The daemon, on every startup, ensures its base-dir subdirectory layout has
the modes documented in § 5.1. The logic lives in a new function
`ensure_base_dir_layout(base_dir: &Path) -> Result<(), SandboxError>` called
from `sandboxd/sandboxd/src/main.rs` immediately after the existing
`tokio::fs::create_dir_all(&base_dir).await?` at line 6130 and before the
`SessionStore::new(base_dir.clone())` call at line 6190.

Behavior, per subdir (`sessions/`, `events/`, `backups/`):

1. If the subdir does not exist → create it with mode `0700`.
2. If the subdir exists with mode `!= 0700` → log a `warn!` line naming the
   path and current mode, then call `set_permissions` to correct it to
   `0700`. Continue startup.
3. If the subdir exists with mode `0700` → no-op.
4. If the chmod in step 2 fails (e.g. read-only filesystem, permission
   denied because the path is owned by a different user) → log `error!`,
   return `SandboxError::Internal(...)`, daemon refuses to start.

For `sessions.db`: SQLite's `Connection::open` does not let us pass a
mode. After the first successful open, the daemon `chmod`s the file to
`0600`. If the chmod fails the daemon logs `error!` and refuses to start
(an unprotected `sessions.db` is a security regression we will not let
slide silently).

Pseudo-Rust shape (lives near `default_base_dir`):

```rust
fn ensure_base_dir_layout(base_dir: &Path) -> Result<(), SandboxError> {
    for sub in &["sessions", "events", "backups"] {
        let path = base_dir.join(sub);
        match std::fs::metadata(&path) {
            Ok(md) if md.is_dir() => {
                let mode = md.permissions().mode() & 0o777;
                if mode != 0o700 {
                    warn!(path = %path.display(), current = format!("{mode:o}"),
                          "subdir mode is not 0700; correcting");
                    let mut perms = md.permissions();
                    perms.set_mode(0o700);
                    std::fs::set_permissions(&path, perms)?;
                }
            }
            Ok(_) => return Err(SandboxError::Internal(format!(
                "{} exists but is not a directory", path.display()))),
            Err(e) if e.kind() == ErrorKind::NotFound => {
                std::fs::create_dir(&path)?;
                std::fs::set_permissions(&path,
                    std::fs::Permissions::from_mode(0o700))?;
            }
            Err(e) => return Err(e.into()),
        }
    }
    Ok(())
}
```

The `sessions.db` chmod happens inside `SessionStore::new` immediately after
`Connection::open(&db_path)?` at `sandbox-core/src/store.rs:90`. The change
is two lines and the unit test in § 11 pins it.

## 6 · `sandbox doctor` subcommand

### 6.1 · CLI surface

```
sandbox doctor [--verbose]
```

- Default output: one line per check that **fails**, terminal-color-coded
  (red `✗ ` prefix for failures, yellow `~ ` for skipped). Passing checks
  are suppressed by default so the failure list is the actionable
  surface. The trailing summary line reads `N checks passed, M failed,
  K skipped` regardless.
- `--verbose` shows every check (green `✓ ` prefix for passes), useful
  for "everything looks fine, why doesn't it work?" diagnosis.
- Exit codes per § 6.4.

### 6.2 · Check list

Doctor's check inventory, in execution order. "Mechanism" describes what
the check actually does on the host; "Failure hint" is the exact text
appended to the failure line so the operator can copy-paste a fix.

| # | Check | Mechanism | Failure hint |
|---|---|---|---|
| C1 | daemon process running | `systemctl is-active sandboxd` (system-service mode) or `connect()` to the resolved socket path (dev mode — no systemd unit exists; fall through to C2) | `sudo systemctl status sandboxd; sudo journalctl -u sandboxd -n 50` |
| C2 | daemon reachable via socket | `UnixStream::connect(socket_path)`; on failure inspect socket file existence and mode | `socket missing or wrong perms; restart sandboxd: sudo systemctl restart sandboxd` |
| C3 | CLI ↔ daemon version match | Daemon `/version` endpoint (§ 7.2); compare to CLI's `env!("CARGO_PKG_VERSION")` | `versions differ — reinstall to align (Spec 5 sandbox update — both at once)` |
| C4 | current user in `sandbox` group | `nix::unistd::getgroups()` + `Group::from_gid` lookup; check that `"sandbox"` is in the list | `sudo usermod -aG sandbox $USER; log out and back in` |
| C5 | socket perms | `stat(socket_path)` → mode `0660`, owner `sandbox`, group `sandbox` | `restart sandboxd: sudo systemctl restart sandboxd` |
| C6 | KVM accessible from daemon's uid | Daemon-side `/diagnostics` endpoint (§ 13 sketch) reports `[ -r /dev/kvm ] && [ -w /dev/kvm ]` as evaluated **inside the daemon process** | `add daemon user to kvm group: sudo usermod -aG kvm sandbox; sudo systemctl restart sandboxd; verify /dev/kvm exists` |
| C7 | gateway image present (**hard**) | `docker image inspect sandbox-gateway:<daemon-version>` exits 0 (daemon-side, since the daemon runs `docker`). Hard failure — sessions cannot be created without it (§ 8.5). | `sandbox update` to load the image (Spec 5); or in dev: `make gateway-image && docker load` |
| C8 | lite image present (**informational**) | `docker image inspect sandboxd-lite:<daemon-version>` exits 0 (daemon-side). Reported as `~ SKIPPED` with informational annotation when missing; daemon builds it on first session create (§ 8.4). Does not contribute to exit-code-1. | image will be built on first session create; or pre-build: `sandbox rebuild-image --backend container` |
| C9 | route-helper has caps | `getcap /usr/local/libexec/sandboxd/sandbox-route-helper` reports `cap_net_admin,cap_sys_admin=eip`. Path resolved via `resolve_route_helper_path` (`sandboxd/sandboxd/src/main.rs:405`). | `sandbox update` re-runs setcap (Spec 5); or `make install-route-helper-prod-cap` in dev |
| C10 | state dir mode | `stat /var/lib/sandbox/` (mode `0750`, owner `sandbox:sandbox`); plus `sessions/`, `events/`, `backups/` at `0700`; `sessions.db` at `0600` | `sudo chmod 0750 /var/lib/sandbox; sudo chown sandbox:sandbox /var/lib/sandbox` (the daemon corrects subdirs at next start; see § 5.4) |
| C11 | users.conf reachable + parses + daemon's uid is in a pool | Daemon-side; the daemon's own startup already enforces this (`sandboxd/sandboxd/src/main.rs:6156-6177`), but the doctor surfaces it on a clean response surface rather than `journalctl` | If the daemon is running, this can't be failing; if it's not, the failure rolls up into C1 |
| C12 | running sessions guest-version drift (verbose only) | For each running session, the daemon issues `GuestRequest::Version` (Spec 2 § 3.10) and compares to `sessions.guest_protocol_version`. Skipped in default mode to keep doctor cheap. | `recreate the session: sandbox session rm <id> && sandbox session create ...` |

Execution flow:

1. Doctor runs C1; if it fails, C2-C11 fall through (they require a
   running, reachable daemon). They are reported as `SKIPPED`, not
   `FAILED`, with an `(requires daemon)` annotation. C4 (group
   membership) and C9 (route-helper caps) can still run — they don't
   depend on the daemon — and are evaluated. C10 (state-dir mode) needs
   read access to `/var/lib/sandbox/`; the parent dir is `0750` so an
   operator in `sandbox` group can stat it. If they're not in the group,
   doctor reports C10 as `SKIPPED (requires sandbox group membership)`.
2. Doctor runs C2; if it fails (socket missing or `EACCES`), C3-C8,
   C11-C12 fall through (they need the socket). Same `SKIPPED` shape.
3. Otherwise doctor runs all remaining checks in parallel (they're
   independent HTTP calls plus a few syscalls).

`SKIPPED` is distinct from `FAILED`: skipped checks don't contribute to
the exit-code-1 condition. A skipped check that is the consequence of
a failed predecessor is the natural output (don't yell about C7 when
the daemon isn't running; one error line is enough).

### 6.3 · Output format

**Happy-path output** (all checks pass; verbose mode shows them):

```
$ sandbox doctor --verbose
sandbox doctor — checking deployment

✓ daemon process running                 (sandboxd.service: active)
✓ daemon reachable                       (/run/sandbox/sandboxd.sock)
✓ CLI ↔ daemon version match             (1.0.3 == 1.0.3)
✓ current user in 'sandbox' group        (alice ∈ docker,kvm,sandbox)
✓ socket perms                           (srw-rw---- sandbox:sandbox)
✓ KVM accessible                         (/dev/kvm readable+writable by daemon)
✓ gateway image present                  (sandbox-gateway:1.0.3)
✓ lite image present                     (sandboxd-lite:1.0.3)
✓ route-helper caps                      (cap_net_admin,cap_sys_admin=eip)
✓ state dir mode                         (/var/lib/sandbox 0750 sandbox:sandbox)
✓ users.conf has daemon pool             (10.209.0.0/20 → ['sandbox'])

11 checks passed, 0 failed, 0 skipped
```

**Mixed output — daemon healthy but lite image not yet built**
(verbose mode; the lite-image skip is informational, not a failure):

```
$ sandbox doctor --verbose
sandbox doctor — checking deployment

✓ daemon process running                 (sandboxd.service: active)
✓ daemon reachable                       (/run/sandbox/sandboxd.sock)
✓ CLI ↔ daemon version match             (1.0.3 == 1.0.3)
✓ current user in 'sandbox' group        (alice ∈ docker,kvm,sandbox)
✓ socket perms                           (srw-rw---- sandbox:sandbox)
✓ KVM accessible                         (/dev/kvm readable+writable by daemon)
✓ gateway image present                  (sandbox-gateway:1.0.3)
~ lite image present                     SKIPPED (not built yet)
    hint: image will be built on first session create; or pre-build:
    sandbox rebuild-image --backend container
✓ route-helper caps                      (cap_net_admin,cap_sys_admin=eip)
✓ state dir mode                         (/var/lib/sandbox 0750 sandbox:sandbox)
✓ users.conf has daemon pool             (10.209.0.0/20 → ['sandbox'])

10 checks passed, 0 failed, 1 skipped
```

Exit code is `0` — the informational skip on C8 does not flip the run
to failure.

**Partial-fail output** (daemon-down, default mode — failures only):

```
$ sandbox doctor
sandbox doctor — checking deployment

✗ daemon process running                 (sandboxd.service: inactive)
    hint: sudo systemctl status sandboxd; sudo journalctl -u sandboxd -n 50

~ daemon reachable                       SKIPPED (requires daemon)
~ CLI ↔ daemon version match             SKIPPED (requires daemon)
~ socket perms                           SKIPPED (requires daemon)
~ KVM accessible                         SKIPPED (requires daemon)
~ gateway image present                  SKIPPED (requires daemon)
~ lite image present                     SKIPPED (requires daemon)
~ users.conf has daemon pool             SKIPPED (requires daemon)

3 checks passed, 1 failed, 7 skipped
```

The two checks that **do** pass (C4 group membership, C9 route-helper caps,
C10 state-dir mode) are listed in the summary count but not echoed in
default mode. `--verbose` would render them.

**Partial-fail output** (version skew):

```
$ sandbox doctor
sandbox doctor — checking deployment

✗ CLI ↔ daemon version match             (CLI=1.0.4, daemon=1.0.3)
    hint: versions differ — reinstall to align (Spec 5 sandbox update — both at once)

10 checks passed, 1 failed, 0 skipped
```

Each failure line is `✗ <check name> <one-line detail>` followed by a
hint line indented by four spaces with `hint:` prefix. The format is
stable (load-bearing for the integration tests in § 11).

### 6.4 · Exit codes

| Code | Meaning |
|---|---|
| `0` | All checks passed (skipped checks do **not** fail the run; they're typically a consequence of a single root-cause failure already reported). |
| `1` | At least one check failed. Reading the failure list shows the order of issues to fix. |
| `2` | Doctor itself could not run (e.g., CLI cannot parse its own config, cannot resolve socket path). Distinct from "checks failed" so wrappers can disambiguate "daemon broken" from "doctor broken". |

The exit-code semantics match `make` and `git`: `0` for clean, `1` for
"the thing we were checking was wrong", `2` for "we couldn't perform the
check at all".

### 6.5 · Code placement

| Path | Kind of change |
|---|---|
| `sandboxd/sandbox-cli/src/doctor.rs` | New file. Hosts the `Check` trait, the registry, the parallel-execution scaffolding, and the output formatter. |
| `sandboxd/sandbox-cli/src/main.rs` | Add `Doctor { #[arg(long)] verbose: bool }` variant to the `Command` enum (line 41 — next to `Health` at line 255 and `Inspect` at line 265, both of which establish the convention). Add the dispatch arm in `main()`. |
| `sandboxd/sandboxd/src/main.rs` | New `/version` route (§ 7.2). Optional `/diagnostics` route (§ 13) hosting C6 (KVM access from daemon's UID) and the C7/C8/C11/C12 daemon-side surfaces. |

Doctor itself is a CLI-side concern; the daemon's responsibility is
exposing the surfaces doctor reads. The split is intentional — doctor's
output is operator-facing UX, the daemon is the source of truth.

## 7 · CLI ↔ daemon strict version equality

### 7.1 · The rule

> On every connection from the CLI to the daemon, the CLI calls a
> `/version` endpoint and compares the daemon's reported version to its
> own `env!("CARGO_PKG_VERSION")`. If they differ, the CLI refuses to
> proceed with a clear error and exits with a non-zero code.

This is the deliberate, locked-in choice: exact-match, no compatibility
range, no semver-aware "patch versions are OK" reasoning. The same install
must place both binaries together; mismatched versions on one host are an
operational error, not a supported configuration. Spec 5's `sandbox update`
upgrades both binaries atomically (replace, then `systemctl restart`).

### 7.2 · The `/version` endpoint

**Endpoint does not exist today.** Confirmed by grep over
`sandboxd/sandboxd/src/main.rs`: there are routes for `/sessions/...`,
`/health`, `/rebuild-image`, `/base-image-status` (lines 843-858), plus
`/backends` (`backends_http.rs:55`). No `/version`. Spec 3 introduces it.

```
GET /version
```

Response body (JSON):

```json
{ "version": "1.0.3" }
```

Implementation: trivial handler that returns
`env!("CARGO_PKG_VERSION")`. Lives in `sandboxd/sandboxd/src/main.rs`
next to `health_check` at line 5347. Route declaration goes alongside
`/health` at `main.rs:858`:

```rust
.route("/health", get(health_check))
.route("/version", get(version_handler))
```

Handler shape:

```rust
async fn version_handler() -> impl IntoResponse {
    (StatusCode::OK, Json(serde_json::json!({
        "version": env!("CARGO_PKG_VERSION"),
    }))).into_response()
}
```

Auth: none required. The socket is already group-restricted at `0660
sandbox:sandbox`; anyone who can connect is an operator. The endpoint
exposes only the daemon's version string — no session data, no operator
identities.

### 7.3 · Error format

When the CLI detects a mismatch, it writes the following to stderr
verbatim (the message tokens `version mismatch`, `CLI is`, `daemon is`,
and `both must match` are load-bearing for the integration test in § 11):

```
sandbox: version mismatch
  CLI is 1.0.4
  daemon is 1.0.3
  both must match — reinstall to align (sandbox update)
```

Exit code: `2` (CLI-side preflight refusal, distinct from `1` which the
CLI uses for daemon-side errors after a successful handshake).

### 7.4 · Where the version constant lives

The CLI's compile-time version is `env!("CARGO_PKG_VERSION")` resolved
against `sandboxd/sandbox-cli/Cargo.toml`'s `version` field (currently
`"0.1.0"`). The daemon's is the same expression against
`sandboxd/sandboxd/Cargo.toml`. The workspace ships both crates with the
same version because `make build` runs `cargo build --workspace` and
Cargo's workspace inheritance keeps the version field in lockstep —
when version is bumped (release process, Spec 4 territory), both crates
bump together.

There is no new constant. `env!("CARGO_PKG_VERSION")` is already used by
the daemon at `sandboxd/sandboxd/src/main.rs:1122` and `5305` and `6236`
(for `lite_image_tag_for_version`). The CLI introduces it at the
`/version` call site and the doctor check (C3).

### 7.5 · Bypass for `sandbox version` and `sandbox doctor`

Two subcommands must remain functional under version skew:

- `sandbox version` — print only the CLI's own version, do not connect
  to the daemon. Mechanically: returns immediately from `main()` before
  the socket-resolution path. Useful for "what version of the CLI do I
  have?" alongside `sandbox doctor`'s "what version of the daemon?"
- `sandbox doctor` — connect tolerantly. The doctor's C3 check is the
  primary surface for reporting version skew; refusing to run doctor
  under skew would mean the operator has no way to diagnose. Doctor
  reads `/version`, expects to see a mismatch, surfaces it as the C3
  failure line, and continues with subsequent checks.

Every other subcommand performs the strict-equality check inside
`send_request` (`sandbox-cli/src/main.rs:1107`) immediately after
`UnixStream::connect` (line 1122) and before the HTTP request the
operator actually invoked is sent. Failure short-circuits with the
§ 7.3 message.

Pseudo-Rust shape (in `send_request`):

```rust
async fn send_request(socket_path: &str, req: Request<Body>)
    -> Result<...> {
    let stream = UnixStream::connect(socket_path).await?;
    // ... HTTP handshake ...
    let daemon_version = fetch_daemon_version(&mut sender).await?;
    let cli_version = env!("CARGO_PKG_VERSION");
    if daemon_version != cli_version {
        eprintln!("sandbox: version mismatch");
        eprintln!("  CLI is {cli_version}");
        eprintln!("  daemon is {daemon_version}");
        eprintln!("  both must match — reinstall to align (sandbox update)");
        process::exit(2);
    }
    // ... proceed with caller's request ...
}
```

The version handshake adds one HTTP round-trip on every CLI invocation.
The cost is one socket read/write of a ~30-byte JSON response — well
under a millisecond on a Unix socket — and the safety property is worth
it. We deliberately do **not** cache "this daemon was version X two
seconds ago" because the cache complicates the failure mode (cached-stale
skew is harder to diagnose than always-fresh).

## 8 · Image tag pinning

### 8.1 · The rule

> The daemon picks `sandbox-gateway:<DAEMON_VERSION>` and
> `sandboxd-lite:<DAEMON_VERSION>` for every new session it creates.
> Never `:latest`. Never an unpinned reference.

The constant `DAEMON_VERSION` is `env!("CARGO_PKG_VERSION")` baked into
the daemon at compile time. Both images carry the daemon's version as
their tag; that is the deliberate pinning strategy. Old containers from
prior daemon versions hold references to prior image tags by docker's
reference-by-id semantics; they are not invalidated by a new daemon's
tag preference.

### 8.2 · Two image lifecycles, two contracts

The lite and gateway images differ in **how they reach the host**, and
the daemon's behavior around each differs accordingly. The table below
fixes the contract:

| Aspect                  | Lite image (`sandboxd-lite:<ver>`)                                                | Gateway image (`sandbox-gateway:<ver>`)                                              |
|-------------------------|-----------------------------------------------------------------------------------|---------------------------------------------------------------------------------------|
| Source                  | Dockerfile embedded in the daemon via `include_str!` (`container.rs:144`)         | Built from `networking/gateway/Dockerfile` against the workspace                       |
| Where it's built        | **By the daemon itself**, on demand, on first need                                  | **By GitHub Actions** at release time (Spec 4); shipped in the release tarball         |
| Distribution to host    | Not shipped in the release tarball; daemon builds locally on first session create | Shipped in the release tarball as a `docker save` tar; install does `docker load`     |
| Build trigger           | `ensure_image(daemon_version)` (`container.rs:1194`) called from `create_session` (`main.rs:1123`); explicit operator rebuild via `sandbox rebuild-image --backend container` | Build happens in CI; daemon never builds it. `sandbox rebuild-image --backend gateway` is **not supported** (Spec 4 territory). |
| Tagging                 | Already pinned via `lite_image_tag_for_version(daemon_version)` (`container.rs:126`); daemon calls it with `env!("CARGO_PKG_VERSION")` at `main.rs:6236` | **Currently unpinned** — `GATEWAY_IMAGE` at `gateway.rs:127` is the bare name `"sandbox-gateway"`, which docker resolves as `:latest`. Spec 3 changes this. |
| First-start check       | Informational only (§ 8.4) — daemon does **not** refuse to start; image is built on first need | **Hard contract** (§ 8.5) — daemon logs a clear error, refuses session-create until the image is loaded, but still starts so doctor can report |
| Doctor check            | Informational (`~`); hint: image will be built on first session, or pre-build via `sandbox rebuild-image --backend container` | Hard failure (`✗`); hint: `sandbox update` (or in dev: `make gateway-image && docker load`) |

The split exists because the lite image's Dockerfile depends only on
public Debian packages and the daemon's embedded source — the daemon
can rebuild it self-sufficiently. The gateway image's Dockerfile pulls
the Envoy / CoreDNS / mitmproxy stack and links in the workspace's nft
loggers (`networking/gateway/Dockerfile`); reproducing that build
requires the full source tree and a non-trivial toolchain, which the
release tarball cannot reasonably ship.

### 8.3 · Where the image tags are selected

**Lite image — already pinned, no change.**
`lite_image_tag_for_version` at `sandbox-core/src/backend/container.rs:126`
produces `sandboxd-lite:<daemon_version>`. The daemon already calls it
with `env!("CARGO_PKG_VERSION")` at `sandboxd/sandboxd/src/main.rs:6236`:

```rust
ContainerRuntime::new(
    lite_image_tag_for_version(env!("CARGO_PKG_VERSION")),
    ...
)
```

`ensure_image(daemon_version)` (`container.rs:1194`) builds the image at
that tag on first need. The existing self-test
`daemon_lite_image_tag_matches_ensure_image_for_same_version`
(`main.rs:8007`) pins the tag-shape contract. Spec 3 does not change
this.

**Gateway image — not pinned today; Spec 3 pins it.**
`gateway.rs:127` declares:

```rust
pub const GATEWAY_IMAGE: &str = "sandbox-gateway";
```

and the gateway-launch site at `gateway.rs:489` uses
`GATEWAY_IMAGE.to_string()` as the final `docker run` positional arg.
Docker resolves a bare image reference as `<name>:latest` — exactly
what § 8.1 forbids. Spec 3 changes this to a version-pinned tag.

Replacement: introduce a function symmetric to
`lite_image_tag_for_version`:

```rust
// sandbox-core/src/gateway.rs (next to GATEWAY_IMAGE).

pub const GATEWAY_IMAGE_REPOSITORY: &str = "sandbox-gateway";

pub fn gateway_image_tag_for_version(daemon_version: &str) -> String {
    format!("{GATEWAY_IMAGE_REPOSITORY}:{daemon_version}")
}
```

The `GATEWAY_IMAGE` constant becomes `GATEWAY_IMAGE_REPOSITORY` (parallel
to `LITE_IMAGE_REPOSITORY` at `container.rs:118`); a deprecated
`pub const GATEWAY_IMAGE: &str = "sandbox-gateway"` may remain as a
soft alias so dependents like `policy.rs:1130` (Envoy cluster name —
unrelated to the docker tag) keep compiling, **but** the gateway-run
call site at `gateway.rs:489` switches to
`gateway_image_tag_for_version(env!("CARGO_PKG_VERSION"))`.

The change to `Makefile:139` mirrors `make lite-image`:

```make
gateway-image:
	docker build -t sandbox-gateway:$(GATEWAY_VERSION) -f networking/gateway/Dockerfile .
```

where `GATEWAY_VERSION := $(shell awk -F'"' '/^version/ { print $$2; exit }' sandboxd/sandbox-core/Cargo.toml)` — symmetric to the existing
`LITE_VERSION` at `Makefile:160`. (The gateway image's tag must match the
**daemon's** version, which is the same as `sandbox-core`'s version by
workspace inheritance.) Spec 4 will replace this dev-only `docker build`
with the CI-built artefact shipped in the release tarball, but the tag
shape is the same.

### 8.4 · Lite image — first-start behavior

The lite image is **not** required at daemon startup. The daemon may
start with `sandboxd-lite:<ver>` absent; it will be built the first
time a session creation needs it via the existing `ensure_image` path
(`container.rs:1194`), and the resulting image is tagged with the
daemon's compile-time version.

Doctor's C8 check (§ 6.2) treats lite-image absence as **informational**:

```
~ lite image not built yet           (sandboxd-lite:1.0.3)
    hint: image will be built on first session create; or pre-build
    with: sandbox rebuild-image --backend container
```

Skipped checks do not contribute to the failure exit-code. The
operator-visible message is "this is fine, here's how to pre-warm if
you want."

Operator-driven rebuild remains supported via the existing
`POST /rebuild-image` endpoint and the `sandbox rebuild-image
--backend container` CLI subcommand. **Automatic periodic rebuild of
the lite image is explicitly out of scope** — see § 14 and the
deferred feature tracked as GitHub issue
[Koriit/sandboxd#7](https://github.com/Koriit/sandboxd/issues/7).

### 8.5 · Gateway image — first-start behavior

The gateway image is **required** for session creation. The daemon
checks for its presence at startup:

1. After `ensure_base_dir_layout` (§ 5.4), before
   `SessionStore::new` (`main.rs:6190`), run `docker image inspect
   sandbox-gateway:<daemon_version>`.
2. **Image missing** → log `error!` line naming the missing tag and
   the daemon's version, with hint:
   `gateway image missing: sandbox-gateway:1.0.3 — run 'sandbox update' to load (Spec 5), or 'docker load < gateway-image.tar' for the manual path`.
3. **The daemon still starts** so `sandbox doctor` can report the
   issue properly. Refusing to start would block diagnostics.
4. Session-create requests for any backend that needs the gateway
   (container and Lima both do — every session has a per-session
   gateway container) return a clear `SandboxError` with the same
   hint. This is the hard-failure surface operators see.

Doctor's C7 check (§ 6.2) reports this as a hard failure (`✗`):

```
✗ gateway image present              (sandbox-gateway:1.0.3 not found)
    hint: sandbox update (Spec 5); or in dev: make gateway-image && docker load
```

The gateway image is **not** rebuilt by the daemon. There is no
`ensure_image`-equivalent for it; the daemon refuses to invent the
image even if it had the source. The contract is: install lands
the image, `sandbox update` replaces it, operators don't build it.

### 8.6 · Old images persist after update

Containers from prior daemon versions hold image-id references, not
tag references — docker won't garbage-collect the underlying image
layers as long as some container or recent image-tag points at them.
After `sandbox update` (Spec 5) replaces the daemon binary with version
`1.0.4`, the old `sandbox-gateway:1.0.3` and `sandboxd-lite:1.0.3` tags
survive (a container may still hold them; docker won't sweep them).
Operators reclaim the disk with `docker image prune` manually.

Spec 5's `sandbox update` is **explicitly forbidden** from auto-pruning
old images. The reasoning: pruning is destructive, the operator may have
a stopped session that still needs the old image to start (Spec 5
§ "Stopped session refresh"), and the disk cost is bounded (~200 MB per
prior daemon version for gateway + lite). Operators run `docker image
prune` when they want it.

## 9 · Removing explicit `helper=` references and the rootless-Docker code path

### 9.1 · The principle

> Sandboxd does not reference `qemu-bridge-helper`'s install path
> anywhere. QEMU's `-netdev bridge,...` accepts an optional
> `helper=<path>` parameter; when omitted, QEMU resolves the helper via
> its compile-time `libexecdir` (different on Ubuntu/Debian vs
> RHEL/Fedora). Sandboxd omits the parameter entirely and lets distro
> packaging do its job.

This is a **clean removal**, not a conditional. Sandboxd does not
support rootless Docker (§ 14), so the previous rootless-Docker code
path — which existed *only* to substitute a nsenter wrapper for the
real bridge helper — is deleted outright. With rootless out of the
supported envelope, there is nothing left that needs a runtime-
substituted helper path.

Verified via `qemu-system-x86_64 --help`:

```
-netdev bridge,id=str[,br=bridge][,helper=helper]
                configure a host TAP network backend with ID 'str' that is
                connected to a bridge (default=br0)
                using the program 'helper (default=/usr/lib/qemu/qemu-bridge-helper)
```

The `helper=` parameter is optional; QEMU falls back to a compile-time
default path that differs by distro. Letting QEMU resolve its own
helper restores distro-portability.

### 9.2 · Audit — every occurrence in the codebase

Comprehensive grep result, every reference to `qemu-bridge-helper`,
`helper=`, `rootless`-bridge-helper plumbing, or related rootless
artefacts in source (the four `target/` build artefacts and `docs/`
references that read as comments only are out of scope):

| # | File:line | Reference | Action |
|---|---|---|---|
| H1 | `sandboxd/sandbox-core/src/lima.rs:155` | `# 2. Adds a second NIC connected to the Docker bridge via qemu-bridge-helper.` (comment header for `QEMU_WRAPPER_SCRIPT`) | **Edit.** Drop the second sentence about rootless: the wrapper no longer has a rootless branch. Final comment: `# 2. Adds a second NIC connected to the Docker bridge via qemu-bridge-helper.` |
| H2 | `sandboxd/sandbox-core/src/lima.rs:156-157` | `#    For rootless Docker the bridge lives inside rootlesskit's network` / `#    namespace, so a wrapper helper runs qemu-bridge-helper via nsenter.` (comment) | **Delete.** Rootless code path is removed. |
| H3 | `sandboxd/sandbox-core/src/lima.rs:194` | `# Bridge networking: if SANDBOX_DOCKER_BRIDGE is set, add a second NIC` / `# connected to the Docker bridge via qemu-bridge-helper.` (comment in script body) | **Keep.** Accurate, distro-agnostic comment. |
| H4 | `sandboxd/sandbox-core/src/lima.rs:196` | `BRIDGE_HELPER="${SANDBOX_BRIDGE_HELPER:-/usr/lib/qemu/qemu-bridge-helper}"` | **Delete.** The `BRIDGE_HELPER` shell variable is gone. The `SANDBOX_BRIDGE_HELPER` env override is also retired (it existed solely to point the rootless wrapper at a custom helper for testing; with rootless gone, the override has no remaining callers in source). § 11.5 includes a grep test to ensure `SANDBOX_BRIDGE_HELPER` does not re-appear. |
| H5 | `sandboxd/sandbox-core/src/lima.rs:198-202` | Five-line `# Rootless Docker: the bridge lives inside rootlesskit's network+user` / `# namespace. QEMU stays on the host (so Lima SSH port-forwarding works),` / `# but qemu-bridge-helper must run inside the namespace to find the bridge` / `# and create the TAP device there. The TAP fd is passed back over a unix` / `# socket, which works across namespace boundaries.` (comment block) | **Delete.** Rootless code path is removed. |
| H6 | `sandboxd/sandbox-core/src/lima.rs:203` | `CHILD_PID_FILE="/run/user/$(id -u)/dockerd-rootless/child_pid"` | **Delete.** Rootlesskit-discovery line; no longer reachable after the rest of the rootless block is gone. |
| H7 | `sandboxd/sandbox-core/src/lima.rs:204-218` | The full rootless conditional: `if [ -f "$CHILD_PID_FILE" ]; then ... fi`, including the generated `NSHELPER` script that nsenter-shims `qemu-bridge-helper`, `export SANDBOX_RLKIT_PID`, `export SANDBOX_REAL_BRIDGE_HELPER`, and the `BRIDGE_HELPER="$NSHELPER"` override. | **Delete.** Entire rootless-Docker branch removed in one block. The generated `bridge-helper-ns` script disappears with it; no caller remains. |
| H8 | `sandboxd/sandbox-core/src/lima.rs:220-222` | `-netdev bridge,id=net_sandbox,br=$SANDBOX_DOCKER_BRIDGE,helper=$BRIDGE_HELPER` | **Edit.** Drop the `,helper=$BRIDGE_HELPER` segment entirely. The netdev line becomes `-netdev bridge,id=net_sandbox,br=$SANDBOX_DOCKER_BRIDGE`. QEMU resolves the helper via its compile-time `libexecdir` default. |
| H9 | `sandboxd/sandbox-core/src/lima.rs:228` | `# PR_SET_NO_NEW_PRIVS, which strips setuid from qemu-bridge-helper` (comment in hardened-mode block) | **Keep.** The PR_SET_NO_NEW_PRIVS constraint is still in force and the comment is accurate (the hardened block intentionally avoids `-sandbox` for this reason). |
| H10 | `sandboxd/sandbox-core/src/lima.rs:424` | `/// second NIC connected to the Docker bridge via qemu-bridge-helper.` (doc comment on `LimaConfig`) | **Keep.** Accurate, distro-agnostic doc. |
| H11 | `sandboxd/sandbox-core/src/lima.rs:2806-2807` | Test: `assert!(QEMU_WRAPPER_SCRIPT.contains("qemu-bridge-helper"), "wrapper must reference qemu-bridge-helper")` | **Keep.** After the changes the wrapper still references `qemu-bridge-helper` in the surviving comment (H3) and in the `# PR_SET_NO_NEW_PRIVS` comment (H9). Assertion remains green. |
| H12 | `sandboxd/sandbox-core/src/lima.rs:2822-2825` | Test: `"wrapper must NOT use -sandbox on (incompatible with qemu-bridge-helper setuid)"` | **Keep.** Unrelated to path resolution; about the `-sandbox` QEMU flag. |
| H13 | `sandboxd/sandbox-core/src/vm_network.rs:3, 25, 99` | Doc comments referencing `qemu-bridge-helper` | **Keep.** Comments only. |
| H14 | `sandboxd/sandboxd/src/main.rs:2683, 4372, 4807, 5188` | Comments referencing `qemu-bridge-helper` | **Keep.** Comments only. |
| H15 | `sandboxd/sandbox-core/src/backend/mod.rs:80` | Doc comment referencing `qemu-bridge-helper` | **Keep.** Comment only. |
| H16 | `Makefile:208` | `QEMU_BRIDGE_HELPER_PATH := /usr/lib/qemu/qemu-bridge-helper` | **Keep for dev mode.** Install-time setuid path for `make setup-dev-env`. Spec 4's install script will probe the helper's path independently on production hosts; that's a Spec 4 concern (§ 9.4). |
| H17 | `Makefile:419-433` | `setup-bridge-helper-setuid` target | **Keep.** Dev-mode setuid setup. |
| H18 | `Makefile:118` | Comment about bridge-helper test skips | **Keep.** Comment only. |
| H19 | `Makefile:318, 350` | Comments / mkdir for `/etc/qemu/bridge.conf` | **Keep.** Unrelated to helper path. |
| R1 | `sandboxd/sandbox-core/src/error.rs:43-73, 169-182` | `SandboxError::RootlessDockerRefused` variant + its `Display` body + a regression test pinning the `rootless docker` greppable token | **Keep.** This is the *refusal* infrastructure that defends against running on rootless hosts — it's the mechanism by which "we don't support rootless Docker" is enforced today. Removing it would silently re-admit rootless. Spec 3 does **not** touch it. |
| R2 | `sandboxd/sandbox-core/src/backend/container_rootless_probe.rs` (file) | The rootless-Docker detector module | **Keep.** Same reasoning as R1 — this is the probe that triggers `RootlessDockerRefused`. Removing it would defeat the refusal. |
| R3 | `sandboxd/sandbox-core/src/session.rs:357-410, 543, 702, 761, 799` | `SessionConfig::rootless_docker: Option<SessionRootlessDocker>` and the persisted `SessionRootlessDocker` struct (detected/forced bools) | **Keep.** This is the persisted *audit record* of what the rootless probe decided at session-create time; it surfaces in `sandbox inspect` output. It records the no-support enforcement, it does not enable rootless. On-disk forward-compat (`#[serde(default)]`) means leaving the field intact is safe; removing it would break older daemons reading newer DB rows. |
| R4 | `sandboxd/sandboxd/src/main.rs:1020-1110, 1847-1859, 2391-2405, 2570-` | `--force-rootless-docker` opt-in plumbing + probe invocation + DTO projection | **Keep.** Explicit escape hatch for operators who accept the risk per-invocation (`sandbox create --force-rootless-docker`). The flag stays as documented in `sandbox-cli/src/main.rs:150-151`. Removing it without removing the refusal would leave the operator no way to test on a rootless host even when they intentionally accept the consequences. |
| R5 | `sandboxd/sandbox-core/src/api/mapper.rs:86-172, 753-781` | `SessionDto::rootless: Option<SessionRootlessDockerDto>` + `with_rootless` setter + serializer tests | **Keep.** DTO projection of R3; on-the-wire forward-compat. |

**Net code change:** seven shell-script edits inside `QEMU_WRAPPER_SCRIPT`
(H1, H2, H4, H5, H6, H7, H8) collapsing the rootless branch and dropping
the `helper=` parameter. Zero changes to the `RootlessDockerRefused`
refusal path (R1-R5). One new grep test (§ 11.5).

The distinction is critical and worth restating: the artefacts in R1-R5
**enforce** the no-rootless-support policy at the API layer (refuse to
create sessions on rootless hosts). The artefacts in H4-H7 **enabled
rootless to work at the QEMU-networking layer**. Removing R1-R5 would
silently re-admit rootless. Removing H4-H7 closes the door at the
networking layer too, in keeping with "we don't support rootless
Docker." The two layers are independent; this revision touches only
the networking layer.

### 9.3 · The post-removal wrapper logic

Updated `QEMU_WRAPPER_SCRIPT` bridge-networking block (the rest of the
script — PCIe root-port, real-QEMU resolution, hardened-mode block —
is unchanged):

```sh
# Bridge networking: if SANDBOX_DOCKER_BRIDGE is set, add a second NIC
# connected to the Docker bridge via qemu-bridge-helper.
# QEMU resolves the helper via its compile-time libexecdir default
# (different on Ubuntu/Debian (/usr/lib/qemu/) vs RHEL/Fedora
# (/usr/libexec/)); sandboxd does not pin the path.
if [ -n "$SANDBOX_DOCKER_BRIDGE" ]; then
    EXTRA_ARGS="$EXTRA_ARGS \
        -netdev bridge,id=net_sandbox,br=$SANDBOX_DOCKER_BRIDGE \
        -device virtio-net-pci,netdev=net_sandbox,mac=$SANDBOX_VM_MAC,bus=pcie-hotplug-port"
fi
```

Three properties of the new shape:

1. No `BRIDGE_HELPER` variable. The `SANDBOX_BRIDGE_HELPER` env override
   is retired with it.
2. No nsenter wrapper, no `bridge-helper-ns` file generation, no
   rootlesskit pid lookup. The wrapper script is roughly 20 lines
   shorter.
3. The `-netdev bridge,...` line emits no `helper=` parameter; QEMU
   uses its compile-time default.

### 9.4 · Implications for Spec 4

Forward note. Spec 4's install script may still want to *probe* the
helper's path to setuid it (the helper is shipped setuid-root by
`qemu-system` packages on most distros, but custom rebuilds or
selinux-stripped variants sometimes need the bit re-applied). The
probed path may be recorded in Spec 4's install state file as a fact
about what install did — useful for `sandbox uninstall` to undo. **The
daemon never reads that file.** It is not daemon config; it is install
metadata. The daemon stays distro-agnostic about helper resolution.

## 10 · Daemon-side wiring of operator identity

Spec 1 specifies that the daemon resolves `SO_PEERCRED` on every accepted
socket connection, maps the UID to a username via `getpwuid_r`
(`nix::unistd::User::from_uid`), and threads the username through to the
route-helper as `--for-user`. Spec 2 specifies that the same username is
used to stamp `sessions.owner_username` and to filter every session-ID
endpoint at the `SessionStore` boundary. Spec 3 changes the daemon's own
uid from "the operator" to "the dedicated `sandbox` system user" — and
the wiring composes without re-design.

The end-to-end flow under Spec 3:

1. Alice runs `sandbox session create ...` (CLI).
2. Alice's CLI does `UnixStream::connect("/run/sandbox/sandboxd.sock")`
   (`sandboxd/sandbox-cli/src/main.rs:1122`).
3. Socket perms (`0660 sandbox:sandbox`, alice ∈ sandbox group) admit
   the connection.
4. Daemon's acceptor reads `SO_PEERCRED` on the accepted UnixStream:
   `peer_cred.uid()` returns alice's uid (per `SO_PEERCRED` semantics —
   kernel-set, not client-spoofable). Spec 2 § 4 / Spec 1 § 6 specify
   the acceptor; this spec depends on but does not re-design it.
5. Daemon resolves alice's uid via `getpwuid_r` → username `"alice"`.
   Attaches `OperatorIdentity { uid, name: "alice" }` to the request.
6. `create_session` handler stamps `sessions.owner_username = "alice"`
   (Spec 2 § 2.4) and dispatches `runtime.start` for container backend
   with `RuntimeStartArgs::for_user = Some("alice")` (Spec 1 § 6.3).
7. `ContainerRuntime::start` calls `invoke_route_helper(helper, pid,
   gateway_ip, "alice")` (Spec 1 § 6.3).
8. The route-helper binary is `setcap`-armed at
   `/usr/local/libexec/sandboxd/sandbox-route-helper`
   (`ROUTE_HELPER_INSTALL_PATH` at `sandboxd/sandboxd/src/main.rs:363`).
   The daemon spawns it as a child of the daemon process; the child
   inherits the daemon's uid (`sandbox`, post-Spec-3).
9. Helper sees `getuid() == sandbox`, `--for-user == "alice"`. Pair-check
   reads the pool whose CIDR contains `gateway_ip`; the pool's
   `allow_users` is `["sandbox", "alice"]` after V001 (Spec 1 § 4.2).
   Both names ∈ pool. **Allowed.**

Each invariant holds independently of the daemon's uid:

| Invariant | Why it holds for `User=sandbox` |
|---|---|
| `SO_PEERCRED` returns alice's uid | Kernel-set on the accepted socket connection; depends on the CLI's uid, not the daemon's. |
| `getpwuid_r(alice_uid)` resolves | Alice is a real local user on the host. |
| Pool contains `"sandbox"` | V001 added it (Spec 1 § 4.2 / § 5). |
| Pool contains `"alice"` | Operator-provided when the pool was created. |
| `caller_name == "sandbox"` | Daemon runs as `sandbox`, fork-inherits to helper. |
| `for_user == "alice"` | Daemon read alice's uid from `SO_PEERCRED`, passed her name as `--for-user`. |

No re-design needed. The composition is the point of Specs 1 and 2 —
they make this transition non-disruptive.

## 11 · Test plan

Hermetic by default per `CLAUDE.md` § "Integration-test convention".
Tests requiring out-of-process state (a real systemd, real Docker, real
Lima) are named with the `integration_*` prefix and selected via the
`integration` nextest profile (`sandboxd/.config/nextest.toml`).

### 11.1 · Unit tests — startup subdir layout

Hermetic. Live next to `default_base_dir` in `sandboxd/sandboxd/src/main.rs`,
or in a sibling module if `ensure_base_dir_layout` is extracted.

| Test name | Behavior |
|---|---|
| `ensure_base_dir_layout_creates_missing_subdirs` | Base dir empty; call function; assert `sessions/`, `events/`, `backups/` exist with mode `0700`. |
| `ensure_base_dir_layout_corrects_wrong_mode` | Create `sessions/` with mode `0755`; call function; assert mode is now `0700`; assert a `warn!` event was logged. |
| `ensure_base_dir_layout_noop_when_correct` | Pre-create all three subdirs with `0700`; call function; assert no log events. |
| `ensure_base_dir_layout_errors_when_subdir_is_file` | Create `sessions` as a regular file; call function; assert it returns `SandboxError::Internal`. |

### 11.2 · Unit tests — `/version` endpoint

Hermetic; spin up the daemon's `app(...)` router in-process.

| Test name | Behavior |
|---|---|
| `version_endpoint_returns_cargo_pkg_version` | Hit `GET /version`; assert body `{"version": "<env!(CARGO_PKG_VERSION)>"}`. |
| `version_endpoint_returns_200_with_application_json` | Assert content-type and status. |

### 11.3 · Unit tests — CLI version-equality check

Hermetic; uses an in-process mock of `send_request`'s `/version` call.

| Test name | Behavior |
|---|---|
| `cli_version_check_proceeds_on_match` | Mock daemon returns `{"version": "1.0.3"}`; CLI's compile-time version is `1.0.3` (via a test-only override hook); assertion: caller's HTTP request is sent. |
| `cli_version_check_refuses_on_skew` | Mock daemon returns `{"version": "1.0.4"}`; CLI version is `1.0.3`; assertion: stderr substring `version mismatch`, `CLI is 1.0.3`, `daemon is 1.0.4`; exit code is `2`. |
| `cli_version_check_bypassed_for_doctor` | Invoke `sandbox doctor`; mock daemon returns mismatched version; assertion: doctor still runs; C3 reports mismatch as a failed check, not as a refusal-to-run. |
| `cli_version_check_bypassed_for_version_subcommand` | Invoke `sandbox version`; assertion: CLI does not call `/version` at all (no daemon connection); prints CLI's own version. |

### 11.4 · Unit tests — doctor check registry

Hermetic; per-check happy-path + failing-condition table.

| Test name | Mechanism | Setup | Expected |
|---|---|---|---|
| `doctor_check_socket_perms_passes_on_0660` | mock `stat` returns `0660 sandbox:sandbox` | — | check passes |
| `doctor_check_socket_perms_fails_on_0664` | mock `stat` returns `0664 sandbox:sandbox` | — | check fails; hint substring `restart sandboxd` |
| `doctor_check_version_passes_when_equal` | mock `/version` returns CLI version | — | check passes |
| `doctor_check_version_fails_on_skew` | mock `/version` returns different version | — | check fails; line substring `CLI=X, daemon=Y` |
| `doctor_check_group_membership_passes` | mock `getgroups()` includes `sandbox` GID | — | check passes |
| `doctor_check_group_membership_fails_with_hint` | mock `getgroups()` does not include `sandbox` | — | check fails; hint substring `usermod -aG sandbox` |
| `doctor_skips_dependent_checks_when_daemon_down` | mock socket connect fails | — | C3 / C5-C8 / C11-C12 report `SKIPPED`; final summary counts them as skipped, not failed |
| `doctor_exits_0_when_all_pass` | every mock returns success | — | process exit code `0` |
| `doctor_exits_1_on_any_failure` | one mock fails | — | exit code `1` |
| `doctor_exits_2_on_internal_error` | inject a panic in the check runner | — | exit code `2` |

### 11.5 · Unit tests — `helper=` and rootless removal regression

Hermetic; static-asserts on `QEMU_WRAPPER_SCRIPT` and grep-based lints.

| Test name | Behavior |
|---|---|
| `qemu_wrapper_emits_netdev_without_helper_param` | Assert that `QEMU_WRAPPER_SCRIPT` contains the substring `-netdev bridge,id=net_sandbox,br=$SANDBOX_DOCKER_BRIDGE \` (with no `,helper=` suffix). Anchor: the literal token `,helper=` does **not** appear in the netdev line. |
| `qemu_wrapper_has_no_bridge_helper_variable` | Assert that the literal token `BRIDGE_HELPER=` does **not** appear anywhere in `QEMU_WRAPPER_SCRIPT`. Pins the deletion of the shell variable. |
| `qemu_wrapper_has_no_rootlesskit_artefacts` | Assert that `QEMU_WRAPPER_SCRIPT` does **not** contain `dockerd-rootless`, `rootlesskit`, `nsenter`, `RLKIT_PID`, `NSHELPER`, `bridge-helper-ns`, or `SANDBOX_REAL_BRIDGE_HELPER`. Pins the rootless-Docker code path's removal. |
| `qemu_wrapper_still_references_qemu_bridge_helper_in_comments` | Asserts the literal string `qemu-bridge-helper` is still present (surviving in comments + the `PR_SET_NO_NEW_PRIVS` block) so the assertion at `lima.rs:2806` keeps passing. |
| `grep_test_no_hardcoded_helper_path_in_source` | CI-level grep test (in `tests/lints/`): assert that `/usr/lib/qemu/qemu-bridge-helper` does not appear in `sandboxd/sandbox-core/src/`, `sandboxd/sandboxd/src/`, or `sandboxd/sandbox-cli/src/`. The Makefile's `QEMU_BRIDGE_HELPER_PATH` for dev-mode setuid is explicitly out of scope (separate file class). Trivial-but-pays-back: blocks a future contributor from re-introducing the hardcoded path. |
| `grep_test_no_sandbox_bridge_helper_env_var` | CI-level grep: assert `SANDBOX_BRIDGE_HELPER` does not appear in source (only-callers were the rootless wrapper; with that gone, the env override is retired). |

### 11.6 · Integration tests — `integration_*` profile

These require real out-of-process state.

| Test name | Behavior |
|---|---|
| `integration_systemd_unit_smokes` | Inside a Lima-controlled VM test environment (Spec 4 provides the harness), install the unit, `systemctl daemon-reload`, `systemctl start sandboxd`, verify it reaches `active (running)`, verify `/run/sandbox/sandboxd.sock` exists with mode `0660`, verify `sandbox doctor` succeeds. |
| `integration_subdir_mode_correction_at_startup` | Pre-create `/var/lib/sandbox/sessions/` with mode `0755`; start daemon (via systemd); after start, assert mode is now `0700`; assert journald shows the `warn!` event. |
| `integration_version_endpoint_real_socket` | Real daemon, real socket; `curl --unix-socket /run/sandbox/sandboxd.sock http://localhost/version`; assert body shape and `Content-Type`. |
| `integration_cli_refuses_on_version_skew` | Daemon built at version `0.1.0-test-a`; CLI built at `0.1.0-test-b`; CLI invocation refuses with the documented error; exit code `2`. (Two distinct cargo builds with `[patch]`-overridden version in a test workspace.) |
| `integration_gateway_image_pinned_to_daemon_version` | Build the gateway image at the daemon's `CARGO_PKG_VERSION`; start a session; inspect the running gateway container; assert its image tag matches `sandbox-gateway:<daemon-version>`, not `:latest`. |
| `integration_doctor_hard_fails_on_missing_gateway_image` | Daemon started without first running `make gateway-image`; `sandbox doctor` reports C7 (gateway image present) as `✗ FAILED` with the documented hint; doctor's exit code is `1`. |
| `integration_doctor_informational_on_missing_lite_image` | Daemon started without first running `make lite-image`; `sandbox doctor` reports C8 (lite image present) as `~ SKIPPED` with hint about first-session build or `sandbox rebuild-image --backend container`; doctor's exit code is `0` (informational does not fail). |
| `integration_session_create_builds_lite_image_on_demand` | Daemon started without lite image present; `sandbox session create --lite` succeeds; assert the lite image now exists at `sandboxd-lite:<daemon-version>`. |
| `integration_session_create_refused_on_missing_gateway_image` | Daemon started without gateway image; attempt `sandbox session create`; assert the response is a clear error referencing the missing gateway image and pointing at `sandbox update`. |
| `integration_doctor_full_pass_against_running_daemon` | Standard happy-path harness with both images pre-built; `sandbox doctor --verbose` exits 0 and reports all checks passed. |
| `integration_kvm_check_via_daemon_diagnostics` | Daemon configured without `kvm` group membership; doctor's C6 reports the failure with the documented hint (the daemon-side `/diagnostics` route returns the diagnostic). |
| `integration_qemu_wrapper_no_helper_param_in_netdev` | Trigger Lima VM start; capture the QEMU argv emitted by the wrapper; assert the `-netdev bridge,...` argument has no `helper=` segment. Pins the runtime behavior of the post-removal wrapper. |

### 11.7 · Notes on the systemd integration harness

The `integration_systemd_unit_smokes` test (and any sibling that wants
to drive a real systemd) requires either:

- a Lima-controlled VM with systemd inside (the harness Spec 4 will
  build), or
- a CI runner with systemd available (GitHub Actions hosted runners
  generally don't expose systemd; self-hosted Linux runners do).

For the duration of Spec 3's implementation phase, this single test is
acceptable to mark `#[cfg_attr(not(has_systemd), ignore)]` (mirroring
the Lima KVM convention from Spec 2 § 7.5 and the existing
`integration_*` Lima/Docker gating in the workspace). The marker
disappears when Spec 4's harness lands.

## 12 · Backward compatibility — dev mode

Dev mode is the developer's host where `make setup-dev-env` configures
the user's own account to run the daemon. Spec 3 must leave this path
working. Walk-through:

### 12.1 · `make setup-dev-env` continues to work

- The Makefile target (`Makefile:210`) is unchanged. It still
  installs the route-helper at the production path
  (`/usr/local/libexec/sandboxd/sandbox-route-helper`) with `setcap`,
  lays down `/etc/qemu/bridge.conf`, lays down
  `/etc/sandboxd/users.conf` with the developer in `allow_users`, and
  setuids `qemu-bridge-helper`.
- The developer runs the daemon by hand (`cargo run -p sandboxd` or
  `make build && ./sandboxd/target/release/sandboxd`).
- No systemd unit is installed. `sandbox doctor`'s C1 (daemon process
  running via `systemctl is-active`) falls back to `connect()` to the
  socket — the dev mode entry point — so the check passes when the
  developer has the daemon running in another terminal.
- State lives at `~/.local/share/sandboxd/` (the XDG fallback at
  `default_base_dir`). The `--base-dir` flag is not passed, so the
  resolver hits the fallback. No change.

### 12.2 · `sandbox doctor` in dev mode

Doctor's checks degrade gracefully:

| Check | Dev behavior |
|---|---|
| C1 daemon running | `systemctl is-active sandboxd` returns `inactive` or `not-found`; doctor falls back to `connect()`; if the developer has the daemon running, the fallback succeeds and C1 passes. |
| C4 user in `sandbox` group | The developer's own group is the daemon-owning group; the "sandbox" group does not exist on dev boxes. Doctor reports this as **SKIPPED** with annotation `(no 'sandbox' group; dev mode)` rather than as a failure. |
| C5 socket perms | Dev's socket is `srwxr-xr-x <developer>:<developer>` under `$XDG_RUNTIME_DIR/sandboxd/`. Doctor's expected mode is `0660`; **the check is environment-aware**: if there's no `sandbox` group, doctor reads the dev-mode expected mode (`0700` or whatever the daemon set) and reports `SKIPPED (dev mode)`. |
| C7 / C8 images | Dev runs `make gateway-image` / `make lite-image` once; the images get tagged with the workspace version. Doctor's check is the same. |
| C9 route-helper caps | Dev's route-helper is at the same path. Check passes. |
| C10 state dir mode | Dev's `~/.local/share/sandboxd/` is owner-only by HOME convention. Check passes as long as the daemon's subdir-mode enforcement (§ 5.4) ran. |
| C12 guest-version drift | Same as production. |

In effect: doctor in dev mode skips the system-service-specific checks
(C4, C5 strict-mode interpretation) and runs the rest. The output's
summary line distinguishes "passed" from "skipped" clearly so a
developer can tell at a glance that they are in dev mode.

### 12.3 · `helper=` removal in dev

The `qemu-bridge-helper` change (§ 9) applies equally — devs benefit
from the same cross-distro robustness. On Ubuntu/Debian dev hosts
(where the helper lives at `/usr/lib/qemu/`), the QEMU compile-time
default matches the previous hardcoded path; no behavioral change. On
RHEL/Fedora dev hosts (where it lives at `/usr/libexec/qemu-bridge-helper`),
the change unblocks them. The `Makefile:208`
`QEMU_BRIDGE_HELPER_PATH` is unaffected (it's the install-time setuid
path, not a runtime resolution path).

### 12.4 · Image pinning in dev

Already in effect for the lite image (§ 8.2 confirms). For the gateway
image, `make gateway-image` (Makefile:139-140) currently produces
`sandbox-gateway` (which docker tags as `:latest`). After Spec 3, the
Makefile target produces `sandbox-gateway:$(GATEWAY_VERSION)` — the
same shape `make lite-image` already uses (`Makefile:160-167`).
Devs running `make gateway-image` get a versioned tag automatically.

### 12.5 · CLI ↔ daemon strict equality in dev

Devs build the workspace with one `cargo build`. CLI and daemon share
`CARGO_PKG_VERSION`. Strict equality passes by construction. The first
time the developer touches the version field is at release prep (Spec 4
territory).

The one dev-mode workflow Spec 3 disrupts: a developer who edits the
daemon, runs `cargo build -p sandboxd`, but does **not** rebuild the
CLI, will now hit the version check (the version literal is the same
because both crates share the workspace version, but cached binaries
on disk may diverge if the developer ran `cargo build -p sandbox-cli`
at a different commit). In practice this is rare; devs invoking the
CLI typically run `cargo run -p sandbox-cli` (which rebuilds) or
`make build`. The version mismatch error tells them clearly to rebuild.

## 13 · Risks and open questions

### 13.1 · `ProtectSystem=full` and `/etc` writes

Confirmed by inspection: the daemon reads `/etc/sandboxd/users.conf`
(`sandbox-core/src/users_conf.rs:81, 397`) and never writes to `/etc`.
The audit-log path post-Spec-3 is `/var/lib/sandbox/route-helper-audit.log`
(Spec 1 § 3.5), not `/etc`. The lite-mode image consumes
`/etc/qemu/bridge.conf` but that's read by QEMU, not by the daemon
process. `ProtectSystem=full` is safe.

The one scenario where this would break: a future feature that has the
daemon write to a `/etc/sandboxd/` file (e.g. a "save preset to system
catalog" command). Such a feature would have to use `sudo` indirection
or land outside the daemon process; the unit's hardening blocks the
straight path. We accept this as a future constraint rather than
loosening today.

### 13.2 · KVM check from CLI's UID

The doctor check C6 (`KVM accessible`) cannot be implemented inside
the CLI process: the CLI runs as the operator (alice), but the
operative question is "can the **daemon's** uid (sandbox) read/write
`/dev/kvm`?". Alice's KVM access is irrelevant to whether the daemon
can run Lima VMs.

Solution: a new daemon-side endpoint `GET /diagnostics` that the
doctor consults for daemon-uid-scoped checks (C6, C7, C8, C11, C12).
The endpoint returns a JSON object:

```json
{
  "daemon_uid":          1003,
  "daemon_user":         "sandbox",
  "kvm_readable":        true,
  "kvm_writable":        true,
  "gateway_image_present": true,
  "lite_image_present":  true,
  "users_conf_pool":     { "cidr": "10.209.0.0/20", "allow_users": ["sandbox"] },
  "guest_version_drift": [
    {
      "session_id":      "0123456789ab",
      "db_proto":        1,
      "live_proto":      1,
      "db_binary_version":   "0.1.0",
      "live_binary_version": "0.1.0",
      "drift":           false
    }
  ]
}
```

The endpoint runs each check inside the daemon process (so the
relevant uid is the daemon's, not the caller's), and returns the
aggregated result. The doctor renders the response as the C6-C8 /
C11-C12 lines. Auth: none required (the socket is already group-
restricted, and the response leaks only filesystem facts + version
info, no per-operator data).

Place the route alongside `/version` and `/health` at
`sandboxd/sandboxd/src/main.rs:858`.

### 13.3 · No per-operator sandboxd instances

A multi-user host that wants per-user daemons (rather than the shared
system instance) is **out of scope** in v1. The deployment model is
single-system-instance, single-`/var/lib/sandbox/`, all operators
mediated through one daemon. Operators on shared hosts who want
isolation from each other rely on Spec 2's API-level filter and
Spec 1's pair-check on the route-helper.

The escape hatch for operators who genuinely need their own daemon
(e.g. trying out a custom build) is dev mode: don't use the system
service; run sandboxd as themselves with their own `--base-dir` and
`--socket`. Two daemons can coexist on one host this way as long as
they pick distinct CIDR pools (validated at startup against
`users.conf`).

### 13.4 · journald log visibility

The daemon writes to stderr by default (`sandboxd/sandboxd/src/main.rs:62-65`
documents the `--log-file` flag and the stderr fallback). systemd captures
stderr to journald automatically for `Type=simple` units without
`StandardOutput=` overrides. Operators running `journalctl -u sandboxd`
will see the daemon's tracing output.

The one subtlety: the daemon's `tracing` subscriber is configured for
its own format; journald reads it as plain-text lines. There is no
field-structured log shipping (e.g. RFC 5424 sd_journal-native fields).
Adding native journald integration is a follow-up; the spec mentions
the gap so an operator who expects per-field structured records knows
to add a `--log-file` and ship logs through a different path. No
doctor check needed — `journalctl -u sandboxd` is the canonical
diagnostic and works out of the box.

### 13.5 · QEMU's helper-path resolution depends on distro packaging

After § 9's removal, the QEMU wrapper emits `-netdev bridge,...`
without `helper=<path>`. QEMU resolves the bridge helper via its
compile-time `libexecdir` default — typically
`/usr/lib/qemu/qemu-bridge-helper` on Debian/Ubuntu and
`/usr/libexec/qemu-bridge-helper` on RHEL/Fedora.

This delegation works as long as the host's `qemu-system` package
ships the bridge helper at the path QEMU was compiled to look for.
That is the standard packaging contract; we have not found a distro
that violates it. If a host arrives with a custom-built QEMU whose
`libexecdir` disagrees with where the helper actually sits, the Lima
backend will fail at session-start with a clear QEMU error
(`qemu-bridge-helper not found`) — the operator can either reinstall
the matching `qemu-system-common` package or point QEMU at the helper
via `/etc/qemu/bridge.conf`. Sandboxd does not try to paper over a
broken QEMU install.

There is **no** `SANDBOX_BRIDGE_HELPER` env override anymore (§ 9.2 H4).
The test harness paths that previously relied on it have no remaining
callers — verified via the grep test in § 11.5.

### 13.6 · Doctor's parallel-check ordering

Some doctor checks have implicit dependencies (C2 depends on C1; C3
depends on C2). Running them in strict serial would be slow but
safe. Running them in parallel risks racing — e.g. C2 says "socket
exists" but then C5 says "permission denied stat'ing the socket"
because the daemon restarted between the two checks. The spec
recommends a two-phase approach:

1. Phase 1 (serial): C1, C2. If either fails, skip downstream checks
   and exit.
2. Phase 2 (parallel): C3-C12. Each check is independent and idempotent.

This keeps the wall-clock cost low (~200ms typical) while preserving
the "skip dependents" semantics.

## 14 · Out of scope

The following are **not** in Spec 3:

- **`install.sh`, `uninstall.sh`, GH Pages hosting, sigstore
  attestations, signed builds** — all Spec 4.
- **GitHub Actions release workflow + tarball assembly** — Spec 4.
- **Lima-based E2E test harness for install/uninstall/update** —
  Spec 4 (the `integration_systemd_unit_smokes` test in § 11 marks the
  shape Spec 4's harness needs but doesn't build it).
- **`sandbox update` CLI**, **config migration framework**, **lock
  file under `/run/sandbox/`**, **backup mechanics** under
  `/var/lib/sandbox/backups/` — all Spec 5.
- **Doctor-side display of stopped-session compatibility status.**
  The brainstorm scoped this as a `sandbox update --pre-flight`
  feature (does this update need to recreate any of my stopped
  sessions?). It lives in Spec 5, not Spec 3's `sandbox doctor`. The
  protocol primitive (`GuestRequest::Version`) exists already from
  Spec 2 § 3.10; Spec 3 surfaces only running-session drift (C12),
  not stopped-session compatibility.
- **Multi-instance daemons** — single system instance per host in v1.
- **A daemon config file** — flags only; drop-ins for customization
  (§ 4.3).
- **Re-design of helper identity (Spec 1) or API isolation (Spec 2)** —
  both settled.
- **Doctor on systems without systemd.** macOS / BSD use launchd or
  rc.d; their integration is Spec 4+ territory. Doctor's C1 falls back
  to `connect()` so dev-mode-on-non-Linux is functional even without
  the systemd check, but a launchd-aware doctor variant is not in v1.
- **Logrotate / journald-retention policy** for the daemon's logs. The
  daemon writes through journald; journald's own retention applies.
- **A `sandbox-admin` group or admin-override API surface** — Spec 2 § 2.6
  defers this; Spec 3 does not introduce it.
- **Rootless-Docker support.** Sandboxd does not support rootless
  Docker, by design. The `RootlessDockerRefused` error
  (`sandbox-core/src/error.rs:43-73`) actively refuses container-backend
  session creation on hosts where `docker info` reports rootless mode;
  `sandbox create --force-rootless-docker` is the explicit
  per-invocation escape hatch for operators who accept the
  consequences. Spec 3 *additionally* removes the rootless code path
  that previously generated an nsenter wrapper around
  `qemu-bridge-helper` for Lima networking (§ 9.2). Future contributors:
  do not re-introduce rootless-aware code; the supported envelope is
  rootful Docker only.
- **Automatic periodic rebuild of the lite image.** Deferred during
  the spec-arc brainstorm; tracked as GitHub issue
  [Koriit/sandboxd#7](https://github.com/Koriit/sandboxd/issues/7).
  The `/rebuild-image` endpoint (`sandboxd/src/main.rs:5252+`) and
  `sandbox rebuild-image --backend container` CLI subcommand
  (`sandbox-cli/src/main.rs:349`) are present for operator-driven
  rebuilds; operators can wire them to a systemd timer or cron
  themselves until the daemon-internal periodic rebuild lands.
- **Daemon rebuild of the gateway image.** The `sandbox rebuild-image`
  endpoint supports `--backend lima` and `--backend container`; there
  is no `--backend gateway` variant and Spec 3 does not introduce one.
  Gateway image refresh is `sandbox update` territory (Spec 5) since
  the image is shipped pre-built per release (§ 8.2).

## 15 · Implementation notes (light)

Short, indicative bullets — not a plan, just a sanity check that the
spec's scope maps to a tractable change-set.

- `sandboxd/sandbox-cli/src/doctor.rs` (new) — `Check` trait, check
  registry, parallel runner, output formatter.
- `sandboxd/sandbox-cli/src/main.rs` — wire `Command::Doctor { verbose: bool }`
  variant near the existing `Health` / `Inspect` / `Describe` variants
  (lines 255-290). Wire the dispatch arm in `main()` after `Inspect`'s
  handler. Add the strict-equality `/version` check inside
  `send_request` (line 1107) with `Doctor` / `Version` subcommand
  bypass.
- `sandboxd/sandboxd/src/main.rs` — new `version_handler` next to
  `health_check` (line 5347); new `/version` and `/diagnostics`
  routes near `main.rs:858`; new `ensure_base_dir_layout` function
  near `default_base_dir` (line 116); call site immediately after
  `tokio::fs::create_dir_all(&base_dir)` (line 6130).
- `sandboxd/sandbox-core/src/store.rs` — chmod `sessions.db` to `0600`
  immediately after `Connection::open` (line 90).
- `sandboxd/sandbox-core/src/gateway.rs` — rename `GATEWAY_IMAGE` to
  `GATEWAY_IMAGE_REPOSITORY`; add `gateway_image_tag_for_version`;
  update the `docker run` call site at line 489 to use
  `gateway_image_tag_for_version(env!("CARGO_PKG_VERSION"))`.
- `sandboxd/sandbox-core/src/lima.rs` — edit `QEMU_WRAPPER_SCRIPT` per
  § 9.3; update the existing tests at lines 2806-2825 to match the new
  shape (the assertion strings tolerate the wrapper-line change).
- `Makefile:139-140` — change `gateway-image` to tag with
  `$(GATEWAY_VERSION)` mirroring `lite-image`.
- `/etc/systemd/system/sandboxd.service` — ships in the release
  tarball Spec 4 assembles; Spec 3 lands the file's content in
  `sandboxd/contrib/systemd/sandboxd.service` (or similar non-installed
  artifact path) so the workspace owns its canonical copy.

The version constant is `env!("CARGO_PKG_VERSION")` everywhere — no
new constant introduced.

## 16 · Affected files — summary

| Path | Touch type |
|---|---|
| `sandboxd/sandbox-cli/src/doctor.rs` | New: check trait, registry, runner, output formatter |
| `sandboxd/sandbox-cli/src/main.rs` | Edit: `Command::Doctor { verbose: bool }` variant + dispatch; strict-equality `/version` check in `send_request`; bypass for `version` / `doctor` |
| `sandboxd/sandboxd/src/main.rs` | Edit: `/version` route + handler; `/diagnostics` route + handler (KVM access, image presence, guest-version drift); `ensure_base_dir_layout` function + call site |
| `sandboxd/sandbox-core/src/store.rs` | Edit: chmod `sessions.db` to `0600` after `Connection::open` |
| `sandboxd/sandbox-core/src/gateway.rs` | Edit: `GATEWAY_IMAGE_REPOSITORY` + `gateway_image_tag_for_version`; gateway-run call site uses version-pinned tag |
| `sandboxd/sandbox-core/src/lima.rs` | Edit: `QEMU_WRAPPER_SCRIPT` body — delete the entire rootless-Docker branch (lima.rs:156-218); drop the `BRIDGE_HELPER` variable; emit `-netdev bridge,...` with no `helper=` parameter |
| `Makefile` | Edit: `gateway-image` target tags with `$(GATEWAY_VERSION)` (mirrors existing `lite-image` shape) |
| `sandboxd/contrib/systemd/sandboxd.service` | New: canonical copy of the unit file (Spec 4 installs it) |
| `sandboxd/sandbox-cli/tests/` | New tests per § 11.2, 11.3, 11.4 |
| `sandboxd/sandboxd/tests/` | New tests per § 11.1, 11.5, 11.6 |
| `tests/lints/no_hardcoded_helper_path.rs` (or similar) | New CI lint per § 11.5 (covers `/usr/lib/qemu/qemu-bridge-helper` and `SANDBOX_BRIDGE_HELPER` greps) |
| `docs/start/installation.md` | Edit: brief note about the system-service install model + `sandbox doctor` for diagnostics; the detailed install docs are Spec 4 territory |

**Files explicitly *not* touched** (called out to forestall confusion):

| Path | Reason untouched |
|---|---|
| `sandboxd/sandbox-core/src/error.rs` (the `RootlessDockerRefused` variant) | The rootless *refusal* path stays. § 9.2 R1-R5 enumerate the artefacts that enforce the no-rootless policy at the API layer; this revision removes only the QEMU-networking enabler (H4-H8). |
| `sandboxd/sandbox-core/src/backend/container_rootless_probe.rs` | Same — this is the probe that triggers `RootlessDockerRefused`. |
| `sandboxd/sandbox-core/src/session.rs` (`SessionConfig::rootless_docker`) | On-disk audit record of probe outcome. Forward-compat (`#[serde(default)]`) means leaving it intact is safe. |
| `sandboxd/sandbox-cli/src/main.rs` (`--force-rootless-docker` arg) | Per-invocation operator escape hatch; unchanged. |
