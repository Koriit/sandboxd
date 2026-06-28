---
title: Roll back a sandboxd upgrade
description: Manual recipe for restoring binaries, /etc configuration, and sessions.db from a previous release's backup set after `sandbox update`.
---

> **Platform note.** The recipe below is for the **Linux** install (systemd, `setcap`, `/etc` config, host Docker gateway image). On **macOS** the backup set, the service-control commands, and the restored file list all differ — skip to [Rolling back on macOS](#rolling-back-on-macos) for the Apple-Silicon variant.

`sandbox update` keeps a versioned backup of every file it touched in `/var/lib/sandboxd/<sandbox-uid>/backups/<timestamp>-from-<v>-to-<v>/`. If a recent upgrade caused a regression — daemon refusing to start, sessions misbehaving, a network-policy bug — you can restore the previous release by running the manual recipe below.

There is no automated `sandbox rollback` subcommand in this release. The rationale is documented at the bottom of this page; in short, the recipe gives operators every primitive they need to recover without committing the project to a UX choice for backup-set selection or DB-schema-downgrade.

## Pre-flight: pick a backup set

Backup sets are timestamped directories under `/var/lib/sandboxd/<sandbox-uid>/backups/`. Each ships a `manifest.json` recording from/to versions, arch, and a per-file sha256 of the captured bytes. `<sandbox-uid>` is the numeric uid of the `sandbox` system user — resolve it with `id -u sandbox`.

```bash
SANDBOX_UID=$(id -u sandbox)
# The backups directory is mode 0700 sandbox:sandbox, so the glob has
# to expand inside a shell running as the sandbox user. The `sh -c`
# wrapper is what gives the shell access to traverse the directory.
sudo -u sandbox sh -c "ls -ld /var/lib/sandboxd/${SANDBOX_UID}/backups/*/"
sudo -u sandbox sh -c "jq -r '\"\(.from_version) → \(.to_version) (completed_ok=\(.completed_ok))\"' /var/lib/sandboxd/${SANDBOX_UID}/backups/*/manifest.json"
```

The most-recent set with `completed_ok: true` is the default target — it captures the state immediately before the last successful upgrade. Sets with `completed_ok: false` are forensic (a failed or interrupted upgrade) — restorable but the operator should understand they correspond to an aborted upgrade rather than a clean checkpoint.

## The recipe

Copy-paste verbatim. Every step is announced before its `sudo`; review what is about to change before authenticating.

```bash
# 1. Identify the backup set to restore. Default: most-recent successful set.
#    The outer `sh -c` wrapping is required: the backups directory is
#    mode 0700 sandbox:sandbox, and the glob has to expand inside a
#    shell running as the sandbox user.
SANDBOX_UID=$(id -u sandbox)
BACKUPS_ROOT="/var/lib/sandboxd/${SANDBOX_UID}/backups"
BACKUP_DIR=$(sudo -u sandbox sh -c "ls -td ${BACKUPS_ROOT}/*/" \
               | xargs -I{} sudo -u sandbox sh -c \
                   'test "$(jq -r .completed_ok < "{}/manifest.json")" = "true" && echo "{}"' \
               | head -1)
if [ -z "$BACKUP_DIR" ]; then
    echo "No backup set with completed_ok=true under ${BACKUPS_ROOT}." >&2
    echo "Either no successful update has run on this host, or every backup" >&2
    echo "set is forensic (completed_ok=false)." >&2
    echo "Inspect the directory directly:" >&2
    echo "    sudo -u sandbox sh -c \"ls -la ${BACKUPS_ROOT}/\"" >&2
    echo "and pick a set manually by setting BACKUP_DIR yourself." >&2
    exit 1
fi
echo "Rolling back from backup: $BACKUP_DIR"
sudo -u sandbox cat "$BACKUP_DIR/manifest.json"

# 2. Verify the prior gateway image is still loaded. If pruned, re-load it
#    from the prior release tarball BEFORE starting the rolled-back daemon
#    (the daemon refuses to start without its versioned gateway image).
PREV_VERSION=$(sudo -u sandbox jq -r '.from_version' "$BACKUP_DIR/manifest.json")
if ! sudo docker image inspect "sandbox-gateway:${PREV_VERSION}" >/dev/null 2>&1; then
    echo "Prior gateway image sandbox-gateway:${PREV_VERSION} is missing (likely pruned)."
    echo "Re-load it from the prior release tarball, e.g.:"
    echo "    sudo docker load -i sandboxd-${PREV_VERSION}-$(uname -m)-unknown-linux-gnu/images/sandbox-gateway-${PREV_VERSION}.tar"
    echo "Re-fetch the tarball from https://github.com/Koriit/sandboxd/releases/tag/v${PREV_VERSION}"
    echo "Then re-run this rollback script from step 3."
    exit 1
fi

# 3. Stop the daemon.
sudo systemctl stop sandboxd

# 4. Restore binaries — install with proper mode/owner.
sudo install -m 0755 -o root -g root "$BACKUP_DIR/sandboxd.bak"             /usr/local/libexec/sandboxd/sandboxd
sudo install -m 0755 -o root -g root "$BACKUP_DIR/sandbox.bak"              /usr/local/bin/sandbox
sudo install -m 0755 -o root -g root "$BACKUP_DIR/sandbox-route-helper.bak" /usr/local/libexec/sandboxd/sandbox-route-helper

# 5. Re-apply route-helper file caps.
sudo setcap cap_net_admin,cap_sys_ptrace,cap_sys_admin=eip /usr/local/libexec/sandboxd/sandbox-route-helper

# 6. Restore /etc files.
sudo install -m 0644 -o root -g root "$BACKUP_DIR/users.conf.bak"  /etc/sandboxd/users.conf
sudo install -m 0644 -o root -g root "$BACKUP_DIR/bridge.conf.bak" /etc/qemu/bridge.conf

# 7. Restore sessions.db plus its WAL companion files. The daemon runs SQLite
#    in WAL journal mode, so committed-but-not-checkpointed transactions live
#    in `sessions.db-wal` (with offsets indexed in `sessions.db-shm`).
#    Restoring only `sessions.db` would drop those in-flight commits.
#    The `-wal` / `-shm` files may legitimately be absent in the backup set
#    (SQLite removes them on clean close); restore each only if present.
#    All three files are owned sandbox:sandbox at mode 0600; the explicit
#    -o sandbox -g sandbox restores ownership.
BASE_DIR="/var/lib/sandboxd/${SANDBOX_UID}"
sudo install -m 0600 -o sandbox -g sandbox "$BACKUP_DIR/sessions.db.bak" "${BASE_DIR}/sessions.db"
if [ -f "$BACKUP_DIR/sessions.db-wal.bak" ]; then
    sudo install -m 0600 -o sandbox -g sandbox "$BACKUP_DIR/sessions.db-wal.bak" "${BASE_DIR}/sessions.db-wal"
else
    sudo rm -f "${BASE_DIR}/sessions.db-wal"
fi
if [ -f "$BACKUP_DIR/sessions.db-shm.bak" ]; then
    sudo install -m 0600 -o sandbox -g sandbox "$BACKUP_DIR/sessions.db-shm.bak" "${BASE_DIR}/sessions.db-shm"
else
    sudo rm -f "${BASE_DIR}/sessions.db-shm"
fi

# 8. Remove the stale lock file (if present from a failed update). The lock survives
#    until the final step of the upgrade; if the upgrade exited before then, the
#    lock remains.
sudo rm -f "${BASE_DIR}/.update.lock"

# 9. Start the daemon.
sudo systemctl start sandboxd

# 10. Verify.
sandbox doctor
```

`sandbox doctor` is the load-bearing verification — every check should pass, `/version` reports the previous version, and any sessions in the restored DB are visible.

## Rolling back on macOS

The macOS backup set lives under the same `backups/` directory, but resolved against the `_sandboxd` daemon user's per-uid base dir (`/var/lib/sandboxd/<_sandboxd-uid>/backups/`). The macOS install has no systemd, no `setcap`, no `/etc/sandboxd/users.conf` or `/etc/qemu/bridge.conf`, and no host gateway image — so the recipe substitutes accordingly:

- **What the set captures.** Binaries `sandboxd`, `sandbox`, `sandbox-agent`, `sandbox-guest`, and `cosign` (there is no `sandbox-route-helper` or `sandbox-lima-helper` on macOS — those are Linux-only setcap helpers), plus the two launchd plists `io.sandboxd.daemon.plist` and `io.sandboxd.agent.plist` (in place of the Linux `users.conf`/`bridge.conf`), plus `sessions.db` and its WAL companions.
- **No `setcap` step.** macOS does not use file capabilities; skip the route-helper `setcap`.
- **No host gateway-image reload.** The gateway image lives inside the persistent `sandboxd-gateway` Lima VM, not the host Docker daemon, so there is no host `docker load` gate. If the rolled-back daemon cannot reach the gateway VM, `sandbox doctor --verbose` reports it; bootstrap the gateway with `sudo launchctl bootstrap system /Library/LaunchDaemons/io.sandboxd.daemon.plist`.
- **Service control is `launchctl`, not `systemctl`.** Stop with `sudo launchctl bootout system/io.sandboxd.daemon`; start with `sudo launchctl bootstrap system /Library/LaunchDaemons/io.sandboxd.daemon.plist`.

```bash
# 1. Pick the backup set (most-recent successful), resolved against _sandboxd's base dir.
SANDBOX_UID=$(id -u _sandboxd)
BACKUPS_ROOT="/var/lib/sandboxd/${SANDBOX_UID}/backups"
BACKUP_DIR=$(sudo -u _sandboxd sh -c "ls -td ${BACKUPS_ROOT}/*/" \
               | xargs -I{} sudo -u _sandboxd sh -c \
                   'test "$(jq -r .completed_ok < "{}/manifest.json")" = "true" && echo "{}"' \
               | head -1)
[ -z "$BACKUP_DIR" ] && { echo "No completed_ok backup set under ${BACKUPS_ROOT}." >&2; exit 1; }
echo "Rolling back from backup: $BACKUP_DIR"
sudo -u _sandboxd cat "$BACKUP_DIR/manifest.json"

# 2. Stop the daemon.
sudo launchctl bootout system/io.sandboxd.daemon || true

# 3. Restore binaries (root:wheel; no setcap on macOS).
sudo install -m 0755 -o root -g wheel "$BACKUP_DIR/sandboxd.bak"      /usr/local/libexec/sandboxd/sandboxd
sudo install -m 0755 -o root -g wheel "$BACKUP_DIR/sandbox.bak"       /usr/local/bin/sandbox
sudo install -m 0755 -o root -g wheel "$BACKUP_DIR/sandbox-agent.bak" /usr/local/libexec/sandboxd/sandbox-agent
sudo install -m 0755 -o root -g wheel "$BACKUP_DIR/sandbox-guest.bak" /usr/local/libexec/sandboxd/sandbox-guest
sudo install -m 0755 -o root -g wheel "$BACKUP_DIR/cosign.bak"        /usr/local/libexec/sandboxd/cosign

# 4. Restore the launchd plists (root:wheel 0644).
sudo install -m 0644 -o root -g wheel "$BACKUP_DIR/io.sandboxd.daemon.plist.bak" /Library/LaunchDaemons/io.sandboxd.daemon.plist
sudo install -m 0644 -o root -g wheel "$BACKUP_DIR/io.sandboxd.agent.plist.bak"  /Library/LaunchAgents/io.sandboxd.agent.plist

# 5. Restore sessions.db + WAL companions (owned _sandboxd:_sandboxd, mode 0600).
BASE_DIR="/var/lib/sandboxd/${SANDBOX_UID}"
sudo install -m 0600 -o _sandboxd -g _sandboxd "$BACKUP_DIR/sessions.db.bak" "${BASE_DIR}/sessions.db"
if [ -f "$BACKUP_DIR/sessions.db-wal.bak" ]; then
    sudo install -m 0600 -o _sandboxd -g _sandboxd "$BACKUP_DIR/sessions.db-wal.bak" "${BASE_DIR}/sessions.db-wal"
else
    sudo rm -f "${BASE_DIR}/sessions.db-wal"
fi
if [ -f "$BACKUP_DIR/sessions.db-shm.bak" ]; then
    sudo install -m 0600 -o _sandboxd -g _sandboxd "$BACKUP_DIR/sessions.db-shm.bak" "${BASE_DIR}/sessions.db-shm"
else
    sudo rm -f "${BASE_DIR}/sessions.db-shm"
fi

# 6. Remove a stale update lock, if any.
sudo rm -f "${BASE_DIR}/.update.lock"

# 7. Start the daemon (RunAtLoad starts it immediately on bootstrap).
sudo launchctl bootstrap system /Library/LaunchDaemons/io.sandboxd.daemon.plist
sudo launchctl enable system/io.sandboxd.daemon

# 8. Verify.
sandbox doctor
```

The DB-schema-downgrade, no-partial-rollback, and lock-file caveats below apply identically on macOS; only the service-config-snapshot caveat differs (macOS captures the plists in the set, so they *are* snapshotted — unlike the Linux systemd unit).

## Caveats

### DB schema downgrade is implicit

Restoring `sessions.db.bak` restores the *pre-update schema and data* together. The restored daemon binary matches that schema (it's the same binary that originally wrote it). The two restore as a unit. If the operator restores only the binary without the DB (or vice versa), the daemon refuses to start with a clear schema-mismatch error.

### No partial rollback

The recipe restores everything in the backup set as a unit. There is no supported workflow for "roll back the binary only" or "roll back the config file only" — both are footguns where the daemon's invariants no longer hold.

### systemd unit not snapshotted

The backup set captures binaries + `/etc` files + `sessions.db`, not the prior `/etc/systemd/system/sandboxd.service`. If the new release shipped a different unit and you want to roll the unit back too, hand-edit or use `git`. In practice the unit shape is stable across releases; this is a documented limitation.

### Lock file cleanup is the operator's job

After rollback the operator must remove `/var/lib/sandboxd/<sandbox-uid>/.update.lock` so future `sandbox update` runs can acquire it. The recipe step 8 includes this.

### Gateway image absence requires manual reload

Step 2 gates the rest of the recipe on `docker image inspect sandbox-gateway:<prev>` succeeding. If you've run `docker image prune` since the upgrade and no longer have the prior release tarball locally, re-fetch it from the [GitHub Releases page](https://github.com/Koriit/sandboxd/releases) before continuing.

### Operator group memberships unaffected

Rollback does not revoke group memberships granted during install (or during prior upgrades — upgrades don't add or remove members). The `sandbox` group is stable across the rollback.

## Why is there no automated `sandbox rollback`?

Three reasons:

* **DB schema downgrade is non-trivial.** The daemon's migration framework is forward-only; an automated `sandbox rollback` would have to either (a) restore the prior `sessions.db.bak` (already in the recipe), or (b) generate reverse SQL on the fly. Option (b) requires migration authors to write `up.sql` + `down.sql` pairs and validate the round-trip; the developer cost is significant and the rare-event benefit doesn't justify it yet.
* **Backup-set selection is operator judgment.** "Roll back to the most recent successful set" is the obvious default, but operators triaging a corrupted install may want a specific older set. A flag-driven automation would need to enumerate sets, present a UX for selection, and validate the operator's choice. The documented recipe gives operators the same primitives without committing the project to a UX choice.
* **Concurrent-update guard.** An automated rollback would need its own lock-file semantics; today's lock at `/var/lib/sandboxd/<sandbox-uid>/.update.lock` guards updates only. A rollback while an update is in progress (or vice versa) is a footgun. Extending the mutex to cover both is doable but adds surface area.

If you have a recurring need for automated rollback, please open an issue on [GitHub](https://github.com/Koriit/sandboxd/issues) with your use case.

## Related

* [Installation](/sandboxd/start/installation/#to-upgrade) — the `sudo sandbox update` flow and how backup sets are created.
* [Troubleshooting](/sandboxd/guides/troubleshooting/) — diagnose a misbehaving daemon before deciding to roll back.
