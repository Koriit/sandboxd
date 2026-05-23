---
title: Update sandboxd
description: Operator walkthrough of `sandbox update` — pre-flight checks, the stateful upgrade flow, backup mechanics, lock semantics, and the rollback path.
---

`sandbox update` applies an in-place upgrade of the sandboxd binaries, systemd unit, and configuration migrations. It is idempotent: re-running after an interrupted upgrade converges to the same end state without operator intervention. This page is the operator's reference for what the command does, what it leaves behind, and how to recover if something goes wrong.

For the per-flag CLI reference, see [`sandbox update`](/sandboxd/reference/cli/#sandbox-update).

## Operator preconditions

Before the first upgrade on a host, confirm:

- **Production install.** `sandbox update` refuses to run against a developer build. Detection is by *both* the systemd unit at `/etc/systemd/system/sandboxd.service` and the install-state file at `/var/lib/sandbox/.install-state.json` being present; if either is missing the host is treated as a dev install. Dev installs upgrade by re-running `make setup-dev-env`.
- **`cosign` on PATH (or available to bootstrap).** The CLI verifies the release tarball's sigstore signature before any state change. `install.sh` already installs `cosign` at a pinned version + sha256; the update flow reuses that. If cosign is missing entirely, the CLI bootstraps it on first run.
- **`sandbox` group membership.** The lock file at `/var/lib/sandbox/.update.lock` is mode `0664 sandbox:sandbox`; the operator running `sandbox update` must be in the `sandbox` group to acquire it directly. Membership is granted by `install.sh` (the invoking operator is added to `sandbox`) and re-granted by `useradd -aG sandbox <other>` for additional operators.
- **The install log is writable.** `/var/log/sandbox-install.log` (mode `0640 root:root`) is the shared forensic record for `install.sh`, `uninstall.sh`, and `sandbox update`. Each step appends one `step=<name> action=<verb> status=<ok|fail>` line. The path is overridable via the `SANDBOXD_INSTALL_LOG` env var when `/var/log` is read-only.

## Pre-flight modes (read-only)

Two flags inspect the upgrade without touching state. Neither acquires the update lock, contacts cosign, or extracts anything. Both can be run without `sudo`.

### `sandbox update --check`

Reports the installed and available versions, the daemon status, the active and stopped session counts, and any pending config-migration headlines. Exit codes:

| Code | Meaning |
|------|---------|
| `0` | Already up to date. |
| `1` | Error (cannot reach the daemon, network failure, cosign-verify dry-run failed). Investigate before retrying. |
| `2` | Argument-parse failure or a refused flag combination. |
| `3` | An update is available. Machine-readable signal for "an update is waiting." |

Scripted usage:

```bash
sandbox update --check; rc=$?
[ $rc -eq 1 ] && { echo "check failed; investigate before updating" >&2; exit 1; }
[ $rc -eq 3 ] && sudo sandbox update --yes
```

### `sandbox update --dry-run`

Prints the same data as `--check`, plus the step-by-step plan: for each of the 18 stateful steps (§ 3.2 below), the projection shows `would execute` or `would skip` based on the current on-disk state. The dry-run output is the safest preview before applying — a `would skip` annotation on a step like `install binaries` means the target version's binary sha256 already matches the on-disk binary, so the upgrade is partially applied and the re-run would only complete the remaining steps.

`--dry-run` exits `0` if the plan is internally consistent (all pre-flight checks would pass) or `1` if any pre-flight blocks the plan (insufficient disk space, sigstore verification would fail, etc.).

## The stateful update flow

A full upgrade has two phases. **Pre-flight** (§ 3.1, steps 1–12) is read-only and side-effect-free; it ends with the confirmation prompt. **Stateful** (§ 3.2, steps 13–30) begins with lock-file acquisition and ends with the install-state finalisation. Each stateful step inspects the on-disk state and skips if it already matches the target — a re-run after a partial failure converges without re-doing completed work.

The 18 stateful steps, condensed:

| # | Step | What it does |
|---|------|-------------|
| 13 | `acquire_lock` | `flock -n -x` against `/var/lib/sandbox/.update.lock`; capture sticky `was_running` (§ "Lock file" below). |
| 14 | `stop_daemon` | `systemctl stop sandboxd` (only if `was_running`). |
| 15 | `backup_sessions_db` | `install -m 0600` `sessions.db`, `.db-wal`, `.db-shm` into the backup set. Idempotent via `cmp -s`. |
| 16 | `backup_etc_files` | `users.conf` + `bridge.conf` copied at mode `0644`. |
| 17 | `backup_binaries` | `sandboxd`, `sandbox`, `sandbox-route-helper` stashed at mode `0640` (not executable in place). |
| 18 | `record_previous_version` | Write `previous_version` into `.install-state.json`. |
| 19 | `write_backup_manifest` | Drop `manifest.json` with `completed_ok: false` into the set. The "in progress" marker. |
| 20 | `docker_load_gateway` | Load the new release's gateway image. Image load runs **before** binary swap so an interrupted upgrade is never left running new binaries against an old gateway image. |
| 21 | `install_binaries` | Install new `sandboxd`, `sandbox`, `sandbox-route-helper`. Each binary is sha256-compared first; identical binaries skip. |
| 22 | `setcap` | Re-apply `cap_net_admin,cap_sys_admin=eip` on the new `sandbox-route-helper`. |
| 23 | `install_systemd_unit` | Install the new unit file (replaces `/etc/systemd/system/sandboxd.service`). Identical content skips. |
| 24 | `apply_config_migration` | Run each pending config migration (e.g. V001 `add_sandbox_to_allow_users`). Each runs in-memory + atomic-rename; mid-flight failure never leaves a half-written file. |
| 25 | `prune_backups` | Delete backup sets older than the last 2 with `completed_ok: true`. Forensic sets (`completed_ok: false`) are **never** auto-pruned. |
| 26 | `daemon_reload` | `systemctl daemon-reload` so systemd picks up the new unit. |
| 27 | `start_daemon` | `systemctl start sandboxd` (only if `was_running`). |
| 28 | `verify_version` | `curl --unix-socket .../version` against the running daemon; assert the reported version matches the target. |
| 29 | `run_doctor` | `sandbox doctor`; assert every check passes. |
| 30 | `finalize_state` | Set `completed_ok: true` + `completed_at` in the backup manifest; update `.install-state.json` with `installed_version` and `installed_at`; release the lock by removing the file. |

If any step fails, the lock survives and the next `sandbox update` invocation **adopts** it: same `was_running`, same target version, resuming from the first incomplete step. The CLI prints `action=skip reason=already-done` for every step whose on-disk state already matches the target — this is the audit signal that idempotency is working.

The confirmation prompt at the end of pre-flight summarises:

```
sandbox update will apply:
  from version:                1.0.0
  to version:                  1.1.0
  pending config migrations:   V001 (add `sandbox` to `allow_users`)
  daemon status now:           active (will be stopped, upgraded, restarted)
  stopped sessions:            3

Proceed? [y/N]:
```

Lower-case `y` proceeds; anything else aborts (exit `0`). `--yes` skips the prompt.

## Backup mechanics

Every stateful upgrade produces one backup set under `/var/lib/sandbox/backups/<ISO8601>-from-<v>-to-<v>/`. The set captures **everything `sandbox update` touched**: binaries, `/etc` files, and `sessions.db` (with its WAL/SHM siblings). Anything the upgrade left alone (operator drop-ins, group memberships, the systemd unit's parent directory, image tags) survives the rollback by virtue of never having been changed.

### Layout

```
/var/lib/sandbox/backups/
├── 2026-05-11T14:23:11Z-from-1.0.0-to-1.1.0/
│   ├── manifest.json                # completed_ok + per-file sha256
│   ├── sandboxd.bak                 # mode 0640 sandbox:sandbox
│   ├── sandbox.bak                  # mode 0640
│   ├── sandbox-route-helper.bak     # mode 0640
│   ├── sessions.db.bak              # mode 0600
│   ├── sessions.db-wal.bak          # mode 0600 (if present)
│   ├── sessions.db-shm.bak          # mode 0600 (if present)
│   ├── users.conf.bak               # mode 0644
│   └── bridge.conf.bak              # mode 0644
├── 2026-05-09T09:11:42Z-from-0.9.5-to-1.0.0/  ← prior successful upgrade, kept
└── 2026-05-07T12:00:00Z-from-0.9.4-to-0.9.5/  ← older, eligible for prune
```

The directory is mode `0700 sandbox:sandbox`. Operators in the `sandbox` group cannot read it directly; inspection goes through `sudo -u sandbox`:

```bash
sudo -u sandbox sh -c 'ls -ld /var/lib/sandbox/backups/*/'
sudo -u sandbox sh -c 'jq -r .from_version,.to_version,.completed_ok /var/lib/sandbox/backups/*/manifest.json'
```

The mode-`0700` boundary mirrors the per-operator API filter: `sessions.db.bak` carries every operator's session metadata, so the backup directory inherits the same filesystem-level scope.

### Retention

Keep the **last 2 successful** sets. A "successful" set has `manifest.json.completed_ok: true`. Failed or in-progress sets (`completed_ok: false`) are **never** auto-pruned — they preserve forensic evidence of failed updates. The prune step (§ 3.2.25) runs before the current set is finalised, so even an immediate re-run cannot accidentally prune the in-flight set.

### Manifest shape

```json
{
  "from_version":  "1.0.0",
  "to_version":    "1.1.0",
  "started_at":    "2026-05-11T14:23:11Z",
  "completed_at":  "2026-05-11T14:24:30Z",
  "completed_ok":  true,
  "arch":          "x86_64-unknown-linux-gnu",
  "files": {
    "sandboxd.bak":            {"sha256": "...", "size": 67234567},
    "sandbox.bak":             {"sha256": "...", "size": 7234567},
    "sandbox-route-helper.bak":{"sha256": "...", "size": 5234567},
    "sessions.db.bak":         {"sha256": "...", "size": 12345},
    "users.conf.bak":          {"sha256": "...", "size": 1234},
    "bridge.conf.bak":         {"sha256": "...", "size":  234}
  }
}
```

The manifest's `arch` field is a sanity check for rollback — a cross-arch restore would fail at exec time. The `files` map lets the rollback recipe verify each `.bak` byte-for-byte before installing.

### Why `.bak`, not `.previous` in PATH

Every binary backup lands under `/var/lib/sandbox/backups/<set>/` at mode `0640` (not executable). `.previous` files in `/usr/local/bin/` would create duplicate, confusable binaries on operator PATH. The rollback recipe explicitly `install`s each `.bak` back to its original path with mode `0755` and re-applies setcap as a separate step.

## Lock file

`sandbox update` serialises itself via `/var/lib/sandbox/.update.lock`, a JSON file holding the in-flight upgrade's pid + target version + the sticky `was_running` flag. Mode is `0664 sandbox:sandbox` so operators in the `sandbox` group can `O_RDWR|O_CREAT` it directly; acquisition is a non-blocking `flock -n -x` on an FD held open by the running shell.

Payload shape:

```json
{
  "pid":            22345,
  "started_at":     "2026-05-11T14:23:11Z",
  "target_version": "1.1.0",
  "from_version":   "1.0.0",
  "was_running":    true
}
```

Contention behavior:

- **Live holder.** If another `sandbox update` is in progress (the `pid` in the payload is alive), the new invocation refuses with `another sandbox update is in progress (pid <N>); wait for it to finish.` Exit `1`.
- **Dead-PID adoption.** If `pid` no longer exists (the previous run crashed, the host rebooted), the new invocation **adopts** the lock: same `was_running`, same target version, resuming from the first incomplete step. The sticky `was_running` flag is the key — without it, a re-run after `stop_daemon` would see `inactive` from `systemctl is-active` and skip the eventual `start_daemon`, leaving the daemon stopped contrary to the operator's intent.

The lock is **persistent**, not under `/run/`, so it survives a reboot mid-upgrade. On successful completion (§ 3.2.30), the lock file is removed.

### Sticky `was_running`

Captured once at first acquisition (`systemctl is-active sandboxd` returns `active` or `inactive` at that moment); every subsequent re-run reads the prior payload's `was_running` and carries it forward unchanged. This is the only piece of state the system cannot infer from on-disk inspection between re-runs.

`--check` and `--dry-run` do **not** acquire the lock or write `was_running`; they use a transient `is-active` call for display only.

## Rollback

There is no `sandbox rollback` subcommand in v1. The recipe is manual but copy-pasteable: identify the backup set to restore (default: most recent with `completed_ok: true`), verify the prior gateway image is still loaded (or re-load it from the prior release tarball), stop the daemon, restore binaries + `/etc` files + `sessions.db` from the backup set, re-apply route-helper setcap, remove the lock file, start the daemon, and verify with `sandbox doctor`.

See [Roll back a sandboxd upgrade](/sandboxd/guides/rollback/) for the verbatim recipe. The recipe is what `sandbox doctor` post-rollback is designed to gate — every check should pass, `/version` should report the previous version, and any sessions in the restored database should be visible.

Why is there no automated rollback? Three reasons:

- **DB schema downgrade is non-trivial.** The daemon's refinery migrations are forward-only; the recipe restores `sessions.db.bak` (which carries the pre-upgrade schema), not a generated reverse SQL.
- **Backup-set selection is operator judgment.** Operators triaging a corrupted upgrade may want a specific older set; a flag-driven automation would need its own selection UX.
- **Concurrent-update guard.** A rollback while an upgrade is in progress (or vice versa) is a footgun. Extending today's lock to cover both adds surface area without strong demand.

If you have a recurring need for automated rollback, open an issue describing the use case.

## What's preserved untouched

`sandbox update` does **not** touch:

- Operator drop-ins under `/etc/systemd/system/sandboxd.service.d/`.
- Operator-added `allow_users` entries in `/etc/sandboxd/users.conf` (only the `sandbox` system user is added by the V001 migration; existing entries pass through).
- Operator-added `allow` lines in `/etc/qemu/bridge.conf` beyond the daemon-managed `sb-*` line.
- Group memberships in the `sandbox` group (additions during install survive; the upgrade neither adds nor removes members).
- Per-session state on disk under `/var/lib/sandbox/sessions/<id>/`.
- `/var/log/sandbox-install.log` itself (the upgrade appends; it does not rotate).

The contract: the backup set captures everything `sandbox update` touched. Anything it left alone survives the upgrade, and would survive a rollback, by never having been changed.

## Failure modes and operator response

| Symptom | Diagnosis | Operator response |
|---------|-----------|-------------------|
| `another sandbox update is in progress (pid N)` | Live holder. | Wait, or `kill <N>` if you know the process is wedged. |
| `another sandbox update is in progress (pid N is dead, lock will adopt)` | Dead-PID adoption pending. | Re-run `sudo sandbox update`; it will adopt the lock and resume. |
| `dev-mode install detected — refusing to upgrade` | The host is a dev install. | Use `make setup-dev-env` to rebuild; `sandbox update` is operator-mode only. |
| `cosign verify-blob failed` | Tarball signature mismatch. | Verify the tarball provenance; refuse to proceed if the signature is wrong (this is the trust boundary). |
| `verify_version failed: expected X, got Y` | Step 28 saw the wrong version on `/version`. | Daemon may have failed to start cleanly; consult `journalctl -u sandboxd`. The lock survives so re-running converges. |
| `sandbox doctor failed` | Step 29 found a post-upgrade health problem. | The lock survives; investigate the specific doctor probe, then re-run or roll back. |
| `daemon-reload failed` | Step 26 could not reload systemd. | Check `journalctl -u sandboxd`; ensure `/etc/systemd/system/sandboxd.service` is readable. Re-run after fixing. |

Every failure path leaves the lock in place. The next invocation adopts and resumes. The only operator action that breaks adoption is `rm /var/lib/sandbox/.update.lock` — do that only when the previous run is known-wedged and you have a recovery plan.

## Related

- [`sandbox update`](/sandboxd/reference/cli/#sandbox-update) — per-flag CLI reference.
- [Roll back a sandboxd upgrade](/sandboxd/guides/rollback/) — verbatim recipe for restoring from a backup set.
- [Installation](/sandboxd/start/installation/#to-upgrade) — first-time `sudo sandbox update` walkthrough.
- [Troubleshooting](/sandboxd/guides/troubleshooting/) — diagnose a misbehaving daemon before deciding to roll back.
