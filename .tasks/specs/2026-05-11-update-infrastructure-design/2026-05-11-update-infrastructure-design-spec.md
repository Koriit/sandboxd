# Update Infrastructure — Design

**Date:** 2026-05-11
**Status:** Approved
**Scope:** `sandbox update` CLI subcommand (fetch + verify + pre-flight + backup + stop + atomic file swap + config migration + image load + start + verify); the config migration framework (`sandbox-cli/src/cfg_migrations/`) that applies Spec 1 V001+ to `/etc/sandboxd/users.conf` and `/etc/qemu/bridge.conf`; backup mechanics at `/var/lib/sandbox/backups/` with a 2-retention policy; the lock file at `/var/lib/sandbox/.update.lock` (mode `0664 sandbox:sandbox`) with sticky `was_running`; idempotency contract; documented manual rollback recipe; and the `sandbox rebuild-image --backend container|lima|all` CLI surface with `--backend gateway` explicitly refused client-side. The daemon-side `_schema_version`-mismatch refusal that closes the safety loop also lands here.

---

## 0 · Sequence context

Spec 5 closes the five-spec arc that prepares `sandboxd` for an end-user
install / uninstall / update story:

1. **Spec 1** — Helper identity assertion (committed at
   `.tasks/specs/2026-05-11-helper-identity-assertion-design.md`, SHA `246bbdd`)
2. **Spec 2** — API session isolation + guest version compatibility (committed
   revised at `.tasks/specs/2026-05-11-api-session-isolation-guest-compat-design.md`,
   SHA `7c026aa`)
3. **Spec 3** — Daemon productionization (committed revised at
   `.tasks/specs/2026-05-11-daemon-productionization-design.md`, SHA `7284c44`)
4. **Spec 4** — Release & install infrastructure (committed at
   `.tasks/specs/2026-05-11-release-and-install-infrastructure-design.md`, SHA `6525264`)
5. **Spec 5 (this one)** — Update infrastructure

Spec 5 strictly depends on Spec 4: `sandbox update` consumes the same release
tarball Spec 4 produces (§ 2.2), verifies it through the same cosign-OIDC
trust chain (Spec 4 § 7.1), and reads / mutates the install state file Spec 4
lays down at `/var/lib/sandbox/.install-state.json` (Spec 4 § 4.5). Spec 5 is
also the first user of the framework that wraps Spec 1's V001 — the pure
`migrate_v001(serde_json::Value) -> serde_json::Value` transform (Spec 1 § 5)
becomes one entry in Spec 5's `ConfigMigration` registry. Spec 5 uses Spec 2's
guest version primitive (`GuestRequest::Version`, Spec 2 § 3.10) for the
pre-flight enumeration of stopped sessions' compatibility status. Spec 5
preserves Spec 3's deployment shape verbatim: the systemd drop-in directory at
`/etc/systemd/system/sandboxd.service.d/` (Spec 3 § 4.3), the `0600
sandbox:sandbox` mode on `sessions.db` (Spec 3 § 5.1), the route-helper file
capabilities (Spec 3 § 6.2 C9), and the strict-equality CLI ↔ daemon `/version`
contract (Spec 3 § 7) all carry through the upgrade unchanged.

After Spec 5 lands, the end-to-end story closes: GitHub Actions builds a
release; `install.sh` bootstraps a fresh box; `sandbox update` upgrades
between releases without manual reinstall, without losing session state,
without dropping operator customisations under `…service.d/`, and with a
documented rollback path if something breaks.

## 1 · Motivation

After Spec 4, operators can install and uninstall sandboxd. They cannot
upgrade in place without a manual reinstall sequence — uninstall (preserving
or losing state by `--purge` choice), then install a newer tarball. The
manual sequence has four problems:

- **State loss risk.** A `uninstall.sh --purge` followed by a fresh install
  loses every session in `/var/lib/sandbox/sessions.db`. Operators who
  remember to omit `--purge` keep the DB, but the binary swap is then
  unsupervised — nothing checks that the new daemon can open the existing
  DB, nothing applies any config migrations, nothing verifies that operator
  customisations under `…service.d/` survive.
- **Drifted `/etc` files.** Spec 1 V001's `_schema_version` field needs to
  be added to `/etc/sandboxd/users.conf`, every pool needs `"sandbox"`
  prepended to `allow_users`. install.sh on a fresh install writes the
  conformant file from scratch (Spec 4 § 4.4.19); on an upgrade, the
  *existing* file must be migrated. install.sh has no upgrade path; it
  refuses on pre-existing install (Spec 4 § 4.4.5). The migration logic
  must live somewhere.
- **Half-applied changes.** If the operator reinstalls the binary but
  forgets to `docker load` the new gateway image tarball (or vice versa),
  the daemon either refuses to start (Spec 3 § 8.5 — gateway image hard
  requirement) or runs with a stale gateway. Idempotent multi-step
  orchestration is the only way to make a partial-completion safely
  re-runnable.
- **No rollback path.** When something breaks, the operator's only option
  today is "find the prior tarball and reinstall." Backups taken
  unsupervised are unverified; rollback is ad-hoc.

`sandbox update` makes the upgrade one auditable atomic-ish operation, with
state preservation, schema migration applied in order, and a clean documented
rollback recipe. It is the **only supported upgrade path** for end-user
deployments after Spec 4 lands; install.sh's pre-existing-install refusal
points at `sandbox update` explicitly (Spec 4 § 4.4.5 — the message body
literally reads `sudo sandbox update --version $TARGET_VER`).

The config migration framework is the second motivation for why `sandbox
update` exists as a first-class command rather than as a re-run of install.sh
on top of itself. Config files — `users.conf`, possibly `bridge.conf` in
future migrations — need ordered, type-safe transforms that shell can't do
cleanly (and that install.sh's fresh-install path doesn't exercise because
fresh installs write the file already at the latest schema). The framework
mirrors refinery's pattern but applies to filesystem files rather than SQL.

## 2 · `sandbox update` CLI surface

`sandbox update` is a new top-level subcommand on the existing
`sandbox-cli/src/main.rs`'s `Command` enum (line 41). It sits next to
`Health`, `Inspect`, `Describe`, `RebuildImage` (line 349), and the
`Doctor` variant Spec 3 § 6.5 added.

### 2.1 · Invocation patterns

```
sandbox update                                # fetch latest from GitHub Releases, apply
sandbox update --version 1.2.0                # pin to a specific release
sandbox update --from <local-tarball>         # air-gapped — operator pre-staged
sandbox update --cosign-bundle <path>         # air-gap sigstore verification (requires --from)
sandbox update --check                        # read-only: report installed vs available, exit
sandbox update --dry-run                      # print the plan; no privileged calls, no state mutation
sandbox update --yes                          # skip the interactive confirmation prompt
sandbox update --force                        # proceed past the "active sessions exist" guard (§ 3.1.6)
sandbox update --quiet | --verbose            # log volume
sandbox update --source-url <base-url>        # tarball mirror (default: GitHub Releases)
```

The flag set is deliberately a superset of install.sh's flag vocabulary
(Spec 4 § 4.2). Operators who learned install.sh's surface read `sandbox
update --version`, `--from`, `--cosign-bundle`, `--yes`, `--verbose`,
`--quiet`, `--source-url` as the same primitives applied to an upgrade.
`--check` and `--dry-run` are upgrade-specific affordances; `--force`
gates the active-session refusal in § 3.1.6.

All other update-specific behavior — confirmation prompt, audit log
destination, sticky `was_running` — does not require new flags.

### 2.2 · What `--check` prints

`--check` is read-only. It connects to the daemon (the strict-equality
`/version` check from Spec 3 § 7.2 still fires), reads the install state
file at `/var/lib/sandbox/.install-state.json`, fetches the latest release
manifest (or reads MANIFEST from `--from`), and prints a status report. It
does **not** acquire the lock file, does **not** mutate any state, does
**not** require sudo.

Sample output (upgrade available):

```
Installed: sandboxd 1.0.0  (installed 2026-05-08T14:23:11Z by alice)
Available: sandboxd 1.1.0  (released 2026-05-10T09:00:00Z, x86_64-unknown-linux-gnu)
Status:    update available

Pending config migrations (current installation):
  config: V002 (add per-pool rate limit metadata)

Stopped sessions: 3
  (for per-session target-protocol compatibility, use `sandbox update --dry-run`)

Run `sudo sandbox update` to apply.
```

Up-to-date case:

```
Installed: sandboxd 1.1.0
Available: sandboxd 1.1.0
Status:    up to date
```

**Scope of `--check` output.** `--check` reports only information the
*current* binary already has — no tarball fetch, no cosign verification,
no extraction. This gives it a fast, no-sudo, no-network profile:

- `Installed` row reads `installed_version`, `installed_at`,
  `installed_by_operator` from `/var/lib/sandbox/.install-state.json`
  (Spec 4 § 4.5). The file is `0640 sandbox:sandbox` — readable by any
  operator in the `sandbox` group without sudo.
- `Available` row reads the GH Releases API latest-release tag (or the
  `MANIFEST.version` from a local `--from` tarball).
- `Pending config migrations` lists config migrations with a pending
  `_schema_version` delta, read from the *current* CLI's
  `cfg_migrations` registry (§ 4.2). No extraction needed. DB migrations
  are **not** listed in `--check` output — they require invoking the new
  daemon binary with `--dump-migration-set` (available only after tarball
  extraction at § 3.1.10, which `--check` skips). Use `--dry-run` for
  the full pending-migrations list including DB migrations.
- `Stopped sessions` count uses the *current* daemon's
  `DAEMON_GUEST_PROTO_VERSION` for classification. Per-session
  `compatible`/`refreshable`/`recreate` detail — which requires the
  *target* binary's `can_refresh_in_place` — is not shown by `--check`.
  Use `--dry-run` for target-protocol per-session classification.

`--check` exit codes:
- `0` — up to date (installed version == available version; no action needed).
- `1` — error (cannot reach daemon, cannot read state file, network
  failure, cosign-verify failed). The operator should investigate before
  deciding whether to update.
- `2` — argument parse failure / read-only-preflight refusal (e.g.
  `--cosign-bundle` without `--from`).
- `3` — update available (installed version < available version; action
  recommended).

Exit 3 is the machine-readable signal that an update is waiting. Scripts
can use it without parsing stdout:

```sh
# Check; if an update is available (exit 3), apply it.
sandbox update --check; rc=$?
[ $rc -eq 1 ] && { echo "check failed; investigate before updating" >&2; exit 1; }
[ $rc -eq 3 ] && sudo sandbox update --yes
```

Or as a one-liner (POSIX-portable):

```sh
sandbox update --check || { [ $? -eq 3 ] && sudo sandbox update --yes; }
```

### 2.3 · What `--dry-run` prints

Same data as `--check` (§ 2.2), plus a simulated step-by-step plan of
what `sandbox update` would do. For each step in § 3, `--dry-run`
inspects the current state and reports `would-execute` or `skip`.

```
$ sudo sandbox update --dry-run
Installed: sandboxd 1.0.0
Available: sandboxd 1.1.0
Status:    update available

Pre-flight (§ 3.1) — read-only:
  ✓ § 3.1.5  version compare            update available (1.0.0 → 1.1.0)
  ✓ § 3.1.6  active sessions check      0 active sessions
  ✓ § 3.1.7  stopped sessions compat    3 sessions, all compatible
  ✓ § 3.1.8  disk space check           ok
  ✓ § 3.1.9  cosign bootstrap           ok
  ✓ § 3.1.10 sigstore verify            ok
  ✓ § 3.1.11 migration dry-run          V002 pending for users.conf
  ✓ § 3.1.12 confirmation prompt        (would prompt; --dry-run skips)

Stateful (§ 3.2) — would execute:
  ✓ § 3.2.13 acquire lock               would execute
  ✓ § 3.2.14 stop daemon (was_running=1) would execute
  ✓ § 3.2.15 backup sessions.db         would execute
  ✓ § 3.2.16 backup /etc files          would execute
  ✓ § 3.2.17 backup binaries            would execute
  ✓ § 3.2.18 record previous_version    would execute
  ✓ § 3.2.19 write backup manifest      would execute
  ✓ § 3.2.20 docker load gateway image  would execute
  ✓ § 3.2.21 install binaries  (sandbox: skip — sha256 match / sandboxd: install / sandbox-route-helper: install)
  ✓ § 3.2.22 setcap on route-helper     would execute
  ✓ § 3.2.23 install systemd unit       would skip (identical)
  ✓ § 3.2.24 apply config migration V002 → users.conf
  ✓ § 3.2.25 prune older backups        would execute (keep last 2)
  ✓ § 3.2.26 start daemon               would execute
  ✓ § 3.2.27 verify /version            would execute
  ✓ § 3.2.28 run sandbox doctor         would execute
  ✓ § 3.2.29 update install state       would execute
  ✓ § 3.2.30 release lock               would execute

Run `sudo sandbox update` (without --dry-run) to apply.
```

`--dry-run` requires sudo only insofar as it reads files mode-`0640
sandbox:sandbox` (the install state file at § 4.5 of Spec 4) — but the
read-only flow can also be invoked by an operator in the `sandbox` group
without sudo, and the script downgrades gracefully (prints "unknown" for
any field it can't read). The `--dry-run` flow does not invoke any
`sudo -k` calls; the `would execute` annotation is purely a projection.

`--dry-run` exit code: `0` if the plan is consistent (all pre-flight
checks pass), `1` if any pre-flight blocks the plan from being
applicable (e.g., disk space short, sigstore verification would fail).

### 2.4 · Confirmation prompt

After pre-flight succeeds (§ 3.1.12, the confirmation prompt itself) and
before the first stateful change (§ 3.2.13 — lock acquisition), `sandbox
update` summarises the operation and prompts for confirmation. The prompt summarises:

```
sandbox update will apply:
  from version:        1.0.0
  to version:          1.1.0
  pending config migrations:  V002 (add per-pool rate limit metadata)
  pending db migrations:      V0007__add_rate_limit_columns.sql (run on daemon start)
  daemon status now:          active (will be stopped, upgraded, restarted)
  stopped sessions:           3 (compatible: 2, recreate: 1)

Proceed? [y/N]:
```

`--yes` skips the prompt. The summary echoes the sticky `was_running`
state captured at lock acquisition (§ 6.4) — "active" if the daemon was
running, "inactive" if it was already stopped. The `stopped sessions:
recreate: N` line, if `N > 0`, is followed by a per-session list at
`--verbose`.

The prompt's question is `Proceed? [y/N]:` — lowercase `y` to proceed,
anything else aborts. The literal token shape (`Proceed?`) is the
assertion anchor for the idempotency E2E test (§ 9.1).

### 2.5 · Privilege

Operator runs `sudo sandbox update`. Inside the script, each privileged
step uses `sudo -k <action>` rather than relying on the outer `sudo`'s
credential cache. The `-k` flag invalidates the timestamp before each
elevated call so re-authentication is required — same pattern install.sh
follows (Spec 4 § 4.3) and the dev-mode Makefile honors (`Makefile:236`).

Rationale for `sudo -k` per step rather than one outer `sudo`:

- **Auditability.** Every elevation is its own log line in
  `/var/log/sandbox-install.log` (the same file install.sh writes; we
  do not introduce a separate `/var/log/sandbox-update.log` — see
  § 2.6). Wrapping the whole script in one `sudo` would hide individual
  elevations from operators reading the log.
- **Idle abort.** An operator who walks away after `sudo sandbox update`
  starts and the script reaches a long step (tarball fetch, gateway image
  load) must re-authenticate to proceed. This forecloses "I forgot what I
  was running" mistakes mid-upgrade.
- **Consistency with install.sh.** The two scripts share the audit
  shape; future contributors don't need to learn two privilege models.

The CLI binary itself is unprivileged. The decision to elevate per step
keeps `sandbox` (the CLI binary at `/usr/local/bin/sandbox`) safe to
chmod `0755 root:root` without `setuid` — no caller can use it as a
privilege ladder.

### 2.6 · Where the update log lives

`sandbox update` appends to the **same** file install.sh and
uninstall.sh write — `/var/log/sandbox-install.log` (Spec 4 § 4.6) —
distinguished from install-script lines by the second token: install.sh
writes `install.sh`, uninstall.sh writes `uninstall.sh`, `sandbox update`
writes `sandbox-update`. Example:

```
2026-05-11T14:23:11Z install.sh    step=useradd action=create we_created=1 status=ok pid=12345
...
2027-02-03T09:11:42Z sandbox-update step=acquire_lock pid=22345 target_version=1.1.0 was_running=1 status=ok
2027-02-03T09:11:43Z sandbox-update step=fetch_tarball source=github size=312456KB status=ok
2027-02-03T09:11:45Z sandbox-update step=sigstore_verify bundle=/tmp/sandbox-update.XXX/release.tar.gz.sigstore identity=Koriit/sandboxd/release.yml status=ok
```

Rationale for sharing the file rather than introducing
`/var/log/sandbox-update.log`:

- **One forensic file per host.** Operators investigating an issue
  read one file. A reinstall, an upgrade, a re-run, all appear in
  chronological order interleaved.
- **Shared format and infrastructure.** install.sh creates the file
  with the right mode (`0640 root:root`, Spec 4 § 4.6) and the
  ISO8601 prefix format. `sandbox update` appends; no per-script
  bootstrap. The "second token is the script name" convention Spec 4
  documents already enables both scripts to share one file.
- **Logrotate parity.** Any logrotate snippet an operator installs
  on `/var/log/sandbox-install.log` covers update activity too.

The CLI uses the same shape (`step=NAME action=ACTION status=ok pid=NNN
[other-keys]`). On the first run after a fresh install (where the log
file already exists with `0640 root:root`), `sandbox update` opens the
file with `O_APPEND` via `sudo -k tee -a` and writes one line per step.

## 3 · The update flow

This section walks through the full update operation step by step. For
each step: what it does, the exact privileged commands, the inspection
that makes it idempotent (so a re-run after partial failure converges),
and the log line written.

The flow has two phases: **pre-flight** (§ 3.1) is read-only and
side-effect-free, ending with the operator confirmation prompt (§ 3.1.12);
**stateful steps** (§ 3.2) begin with lock-file acquisition (§ 3.2.13)
and end with the install-state update (§ 3.2.30).

### 3.1 · Pre-flight (read-only)

#### § 3.1.1. Arg parse + sanity checks

Parse flags per § 2.1; reject incompatible combinations (`--cosign-bundle`
without `--from`, `--from` and `--source-url` together — `--from` is
local-only). Set defaults: `VERSION=latest`, `YES=0`, `VERBOSE=0`,
`QUIET=0`, `FORCE=0`, `DRY_RUN=0`, `CHECK=0`. Initial log:
`step=parse_args version=<v> from=<path-or-->`.

#### § 3.1.2. Detect dev mode and refuse

Per § 11 (back-compat — dev mode), refuse if this looks like a dev
install. Detection:

- `/etc/systemd/system/sandboxd.service` does **not** exist; **and/or**
- `/var/lib/sandbox/` does not exist or is not owned by `sandbox:sandbox`;
- the operator's `$XDG_DATA_HOME/sandboxd/` (or `$HOME/.local/share/sandboxd/`)
  exists with a populated `sessions.db`.

Refuse with the message from § 11; exit `2`. Log:
`step=dev_mode_check is_dev=<0|1> action=<continue|refuse>`.

#### § 3.1.3. Read install state file

The install-state file `/var/lib/sandbox/.install-state.json` is mode
`0640 sandbox:sandbox`. Operators in the `sandbox` group have group-read
(`4` in `0640`) and can read it without elevation. The read strategy
differs by invocation mode:

**`--check` and `--dry-run` mode (no sudo):**

```sh
state=/var/lib/sandbox/.install-state.json
if [ -r "$state" ]; then
    CURRENT_VERSION=$(jq -r '.installed_version // ""' "$state")
    CURRENT_ARCH=$(jq -r    '.installed_arch // ""'    "$state")
    CURRENT_INSTALLED_AT=$(jq -r '.installed_at // ""' "$state")
else
    # Operator not in sandbox group, or file absent — degrade gracefully.
    CURRENT_VERSION="unknown"
    CURRENT_ARCH=$(uname -m | sed 's/x86_64/x86_64-unknown-linux-gnu/;s/aarch64/aarch64-unknown-linux-gnu/')
    CURRENT_INSTALLED_AT="unknown"
fi
```

`--check` output prints "installed version: unknown" when the file is
unreadable, and continues. `--dry-run` does the same. Neither mode
exits hard on a missing state file — the available-version comparison
still works; only the installed-version side of the diff is incomplete.

**Full-update mode (with sudo):**

```sh
state=/var/lib/sandbox/.install-state.json
[ -r "$state" ] || \
    sudo -k test -r "$state" || \
    die "install state file missing: $state — was this host installed via install.sh?"
CURRENT_VERSION=$(sudo -k jq -r '.installed_version // ""' "$state")
CURRENT_ARCH=$(sudo -k    jq -r '.installed_arch // ""'    "$state")
CURRENT_INSTALLED_AT=$(sudo -k jq -r '.installed_at // ""' "$state")
```

In full-update mode, if the state file is absent or unreadable (e.g.,
the host was installed before Spec 4 shipped, or someone deleted it),
refuse with: "install state file missing; re-install with `install.sh`
or set up the file manually per Spec 4 § 4.5." Spec 5 does **not**
auto-bootstrap the state file — that would mask a corrupted install.

Log: `step=read_state installed_version=<v> installed_arch=<arch> degraded=<true|false>`.

#### § 3.1.4. Determine target version, fetch / read MANIFEST

If `--from <tarball>` is supplied, the target tarball is local; otherwise
fetch from GitHub Releases (or `--source-url` mirror). The
target-version logic mirrors install.sh § 4.4.9:

```sh
if [ -n "$FROM" ]; then
    [ -f "$FROM" ] || die "tarball not found: $FROM"
    cp "$FROM" "$tmpdir/release.tar.gz"
    TARBALL_FROM=$FROM
else
    if [ "$VERSION" = "latest" ]; then
        VERSION=$(curl -fsSL https://api.github.com/repos/Koriit/sandboxd/releases/latest \
            | jq -r '.tag_name' | sed 's/^v//')
    fi
    TARBALL_NAME="sandboxd-${VERSION}-${CURRENT_ARCH}.tar.gz"
    curl -fsSL --retry 3 --retry-delay 2 -o "$tmpdir/release.tar.gz" \
        "${SOURCE_URL}/v${VERSION}/${TARBALL_NAME}"
    TARBALL_FROM=$SOURCE_URL
fi
TARGET_VERSION=$VERSION
```

Log: `step=fetch_tarball source=<url-or-local> version=<v> size=NKB status=ok`.

The DB migration set the staged daemon ships embeds via refinery's
`embed_migrations!` macro (`sandbox-core/src/store.rs:18`). To enumerate
pending DB migrations for `--dry-run` and the full-update confirmation
prompt, the staged daemon is invoked with a hidden
`--dump-migration-set` flag immediately after extraction (§ 3.1.10), it
prints a JSON list of `(version, name)` tuples to stdout, and the CLI
diffs against the live DB's `refinery_schema_history` table. The
`--dump-migration-set` flag is a Spec 5-introduced daemon affordance,
unprivileged and read-only. It is **not** used by `--check` — `--check`
skips tarball extraction (§ 3.1.5) and therefore cannot invoke the new
daemon binary. DB migration lines are omitted from `--check` output (§ 2.2).

#### § 3.1.5. Compare versions

If `CURRENT_VERSION == TARGET_VERSION`, print "Status: up to date" (§ 2.2
wording) and exit 0. No lock acquisition, no further work. Log:
`step=version_compare current=<v> target=<v> action=skip reason=up-to-date`.

**`--check` exit gate:** If `--check` mode *and* versions differ, do **not**
proceed to § 3.1.6 or beyond. Instead:

1. Run § 3.1.6 (active session count — display only, no refusal).
2. Run § 3.1.7 (stopped session count with *current*-binary protocol
   classification — display only).
3. Run § 3.1.11 (config-migration dry-run from the *current* CLI's
   registry — display only; DB migrations are **not** enumerated since
   that requires the extracted new daemon binary via `--dump-migration-set`).
4. Print the `--check` output from § 2.2.
5. Exit 3 (update available). Skip §§ 3.1.8–3.1.10, 3.1.12 (confirmation),
   and all of § 3.2 (including lock acquisition at § 3.2.13).

The `--check` path never acquires the lock (§ 6.4 — consistent with
§ 3.2.13 being the first stateful step), never fetches a tarball, never
contacts cosign, never extracts a tarball, and never prompts for
confirmation. Its no-sudo, no-network, read-only character is enforced
structurally here — a single early-exit gate — rather than relying on
downstream per-step guards.

#### § 3.1.6. Active sessions check

Query the daemon for active (non-Stopped) sessions:

```sh
active=$(sandbox session ls --output json 2>/dev/null \
    | jq '[.[] | select(.state != "Stopped")] | length // 0')
if [ "$active" -gt 0 ] && [ "$FORCE" -eq 0 ]; then
    die "$active session(s) active. Stop them first:
    sandbox session ls
    sandbox session stop <id>
Or re-run with --force to upgrade despite active sessions
(the daemon stop will terminate them mid-flight)."
fi
```

Rationale: stopping the daemon with active container/Lima sessions
running would orphan their runtimes (Docker keeps the container running
when sandboxd dies; Lima keeps the VM running). Refusing by default is
the safe choice. `--force` is the escape hatch for "this host's daemon
is wedged and we want to upgrade anyway." Log:
`step=active_session_check active=<n> force=<0|1> status=<ok|refuse>`.

#### § 3.1.7. Stopped sessions compatibility enumeration

Query the daemon for stopped sessions; for each, read
`guest_protocol_version` (Spec 2 § 3.1) and classify against a protocol
range. The result is purely informational at this step — no state
mutated, no sessions refreshed. The refresh-on-next-start mechanism
(Spec 2 § 3.4) runs lazily after the upgrade lands.

**Which binary's protocol range is used, by mode:**

- **`--check` mode:** the *current* running daemon's
  `DAEMON_GUEST_PROTO_VERSION` (already known, no extraction needed).
  Classification is limited to `compatible` / `not-compatible` against
  the current binary. Per-session `recreate` verdicts — which require
  calling `can_refresh_in_place` from the *new* binary — are not shown;
  `--check` output instead reports the session count and defers per-session
  detail to `--dry-run` (§ 2.2).
- **`--dry-run` and full-update mode:** the *target* binary's
  `DAEMON_GUEST_PROTO_VERSION` (obtained via `--dump-migration-set` after
  extraction at § 3.1.10). Full `compatible` / `compatible (refreshable)`
  / `recreate` classification is available.

Sessions classified as `recreate` (in `--dry-run` / full-update mode)
are listed by ID + name + reason in the confirmation prompt (§ 2.4); the
operator can choose to abort and `sandbox session rm` those sessions
before re-running update, or to proceed and accept that those sessions
will return a `409 Conflict` with the recreate-guidance error (Spec 2
§ 3.5) on next `start_session`.

Log: `step=stopped_sessions count=<n> compatible=<n> refreshable=<n> recreate=<n>`.

#### § 3.1.8. Disk space pre-flight

Same shape as install.sh § 4.4.7, but the budget is upgrade-specific:

| Path                  | Approx. need | Reason                                                                            |
|-----------------------|--------------|-----------------------------------------------------------------------------------|
| `/usr/local/`         | 50 MB        | new binaries (similar size to existing)                                            |
| `/var/lib/sandbox/`   | 600 MB       | backup set: full copy of `sessions.db`, both `/etc` files, three binaries × 2 (retention) |
| `/var/lib/docker/`    | 500 MB       | new gateway image; old image persists until operator prunes (Spec 3 § 8.6)         |
| `/tmp/`               | 1 GB         | staging dir for the tarball extraction (the tarball compresses 250–500 MB, expands to ~600 MB) |

Refuse with a clear free-space report if any are short. Log:
`step=disk_check tmp_free=NMB var_free=NMB docker_free=NMB status=<ok|fail>`.

#### § 3.1.9. Cosign bootstrap

Identical mechanism to install.sh § 4.4.8. The pinned cosign version is
the **same constant** install.sh uses (Spec 4 § 7.3 — `cosign v2.4.1` at
write time). Both consumers source it from `scripts/lib.sh`:

```sh
# scripts/lib.sh  (sourced by both install.sh and sandbox update's shell path)
COSIGN_VERSION="v2.4.1"
COSIGN_SHA256_AMD64="<hex>"
COSIGN_SHA256_ARM64="<hex>"
```

`scripts/lib.sh` is a **required** shared library, not optional. Spec 4
§ 12 listed it as "inline vs factored, author's discretion"; now that
`sandbox update` is a second consumer of the same pinned constant, inlining
independently guarantees hash drift between the two code paths over time. A
single bump to `COSIGN_VERSION` and its sha256 in `lib.sh` updates both
install.sh and `sandbox update` atomically, in one diff, in one PR.

Any future cosign pin bump touches exactly one file — `scripts/lib.sh`.

Air-gapped path (`--from` + no cosign binary downloaded) probes
`/usr/local/bin/cosign` as fallback; refuses with a clear
stage-cosign-locally message if absent. Log:
`step=cosign_bootstrap version=v2.4.1 source=<download|local> status=ok`.

#### § 3.1.10. Sigstore verification + tarball extraction

Identical to install.sh §§ 4.4.10–4.4.11:

```sh
"$COSIGN" verify-blob \
    --bundle "$tmpdir/release.tar.gz.sigstore" \
    --certificate-identity-regexp '^https://github\.com/Koriit/sandboxd/\.github/workflows/release\.yml@' \
    --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
    "$tmpdir/release.tar.gz"

tar -xzf "$tmpdir/release.tar.gz" -C "$tmpdir"
stage="$tmpdir/sandboxd-${TARGET_VERSION}-${CURRENT_ARCH}"

# MANIFEST sanity + per-file sha256 check (matches install.sh § 4.4.11)
manifest="$stage/MANIFEST"
mver=$(jq -r '.version' "$manifest")
march=$(jq -r '.arch'    "$manifest")
[ "$mver"  = "$TARGET_VERSION" ] || die "MANIFEST version mismatch"
[ "$march" = "$CURRENT_ARCH"   ] || die "MANIFEST arch mismatch"
jq -r '.artifacts | to_entries[] | "\(.value.sha256)  \(.value.path)"' "$manifest" \
    | (cd "$stage" && sha256sum -c --status -)
```

The arch check uses `$CURRENT_ARCH` (read from install state) rather than
re-detecting `uname -m`. An operator who upgrades on a host that
somehow has mismatched install-state arch and `uname -m` arch sees the
mismatch surface immediately — the install state file is the source of
truth for what the operator has installed today. Log:
`step=sigstore_verify identity=<matched> status=ok`,
`step=extract version=<v> arch=<arch> manifest_ok=true status=ok`.

#### § 3.1.11. Migration dry-run

This step is the key safety property. Before any state changes,
materialise the post-migration content of every framework-managed
config file in memory and validate the round-trip parses.

```rust
// pseudocode — full apply loop in § 4.3
for file in registry::managed_files() {
    let current_bytes = read_file(file)?;
    let current_version = read_schema_version(&current_bytes, file)?;
    let target_version = registry::latest_for(file);
    if current_version == target_version { continue; }
    let mut bytes = current_bytes;
    for migration in registry::pending(file, current_version, target_version) {
        let new_bytes = migration.apply(&bytes)?;
        let validated = validate_against_target_schema(&new_bytes, migration)?;
        bytes = validated;
    }
}
```

Errors at this step are pre-state-mutation. The operator sees a clear
error pointing at the broken migration. No backup taken, no daemon
stopped, no binary swapped. The mistake is recoverable by
investigating the migration's input or fixing the file by hand.

Log: `step=migration_dry_run files=<list> status=ok` or
`step=migration_dry_run files=<list> error='<msg>' status=fail`.

#### § 3.1.12. Confirmation prompt (§ 2.4)

The prompt summarises from-version → to-version, pending migrations,
stopped session classification, and `was_running`. `--yes` skips.
`--dry-run` ends here (prints the rest of the plan as "would-execute"
lines per § 2.3 and exits 0). Log:
`step=confirm answered=<y|N|yes-flag>`.

### 3.2 · Stateful steps (idempotent)

From here on, every step inspects the current state and skips if it
already matches the desired state. The flow can be re-run safely
after any failure; convergence is the contract.

#### § 3.2.13. Acquire lock

The first stateful step: acquire the lock before any filesystem mutation.
See § 6 for the full lock-file contract. Briefly: the lock file is
`0664 sandbox:sandbox`; operators in the `sandbox` group can open it
directly. Acquisition uses `flock -n -x` on an FD held open by the
shell process itself (no helper subprocess). The full shell sequence
is in § 6.2.1.

Log: `step=acquire_lock pid=$$ target_version=<v> from_version=<v> was_running=<true|false> action=<acquire|adopt> status=ok`.

#### § 3.2.14. Stop daemon (only if `was_running`)

```sh
if [ "$WAS_RUNNING" = "true" ]; then
    sudo -k systemctl stop sandboxd
fi
```

`WAS_RUNNING` holds the string `"true"` or `"false"` (JSON boolean
representation from the lock-file payload via `jq -r '.was_running'`,
and from `echo true`/`echo false` at first lock acquisition in § 6.2.1).
The comparison uses `=` (string equality), not `-eq 1` (integer
arithmetic), which would produce `integer expression expected` on a
non-integer string and silently evaluate to false.

`systemctl stop` is idempotent: it returns 0 immediately if the unit is
already inactive. The conditional on `was_running` is so the upgrade
preserves the operator's chosen run-state — if the daemon was already
stopped (a maintenance window scenario), the upgrade leaves it stopped
unless the operator manually `systemctl start`s afterward. The sticky
`was_running` flag captured at lock acquisition (§ 6.4) carries this
intent through any re-runs.

Log: `step=stop_daemon was_running=<true|false> action=<stop|skip> status=ok`.

#### § 3.2.15. Backup sessions.db

Create the backup set directory under `/var/lib/sandbox/backups/` (the
dir was created by the daemon at first start per Spec 3 § 5.1, mode
`0700 sandbox:sandbox`). The set directory name encodes start time and
version range:

```sh
backup_set="/var/lib/sandbox/backups/$(date -u +%Y-%m-%dT%H:%M:%SZ)-from-${CURRENT_VERSION}-to-${TARGET_VERSION}"
sudo -k -u sandbox mkdir -p "$backup_set"
```

The `sudo -u sandbox` matters: the backup dir is `0700
sandbox:sandbox`, so a root `mkdir` would land at the right mode but
slightly inconsistent ownership semantics. Doing the mkdir as `sandbox`
keeps everything consistent.

Backup sessions.db. Idempotent via hash compare:

```sh
src=/var/lib/sandbox/sessions.db
dst=$backup_set/sessions.db.bak
if [ -f "$dst" ] && cmp -s "$src" "$dst"; then
    log_ok "step=backup_sessions_db action=skip reason=identical"
else
    sudo -k -u sandbox install -m 0600 "$src" "$dst"
fi
```

Log: `step=backup_sessions_db path=<dst> sha256=<hex> action=<copy|skip>`.

#### § 3.2.16. Backup /etc files

`users.conf` is mode `0644 root:root` (Spec 4 § 4.4.19). `bridge.conf`
is mode `0644 root:root` (`Makefile:355` / Spec 4 § 4.4.18 — matches
QEMU's distro convention, where `bridge.conf` is world-readable in
every distro's `qemu-system-common` package). The backup must preserve
readable content but lives under the `sandbox:sandbox` backup set:

```sh
for src_dst_mode in \
    "/etc/sandboxd/users.conf $backup_set/users.conf.bak 0644" \
    "/etc/qemu/bridge.conf    $backup_set/bridge.conf.bak 0644"
do
    src=${src_dst_mode% * *}; dst=$(echo $src_dst_mode | awk '{print $2}'); mode=$(echo $src_dst_mode | awk '{print $3}')
    [ -f "$src" ] || { log_ok "step=backup_etc src=$src action=skip reason=absent"; continue; }
    if [ -f "$dst" ]; then
        src_sha=$(sudo -k sha256sum "$src" | awk '{print $1}')
        dst_sha=$(sudo -k sha256sum "$dst" | awk '{print $1}')
        if [ "$src_sha" = "$dst_sha" ]; then
            log_ok "step=backup_etc src=$src action=skip reason=identical"
            continue
        fi
    fi
    sudo -k cat "$src" | sudo -k -u sandbox tee "$dst" >/dev/null
    sudo -k -u sandbox chmod "$mode" "$dst"
done
```

The `cat | sudo -u sandbox tee` two-step is so the daemon-user can
write into its own backup set. Both files are mode `0644` (root-only
write, world-readable) so `sudo -k cat` reads as root and pipes the
bytes to the `sandbox`-owned destination unchanged. The mode
restoration via `chmod` after the write ensures `.bak` matches the
original mode bit-for-bit, which the rollback recipe (§ 7.2) relies on.

Log: `step=backup_etc path=<dst> sha256=<hex> action=<copy|skip>`.

#### § 3.2.17. Backup binaries

Each of `/usr/local/bin/sandboxd`, `/usr/local/bin/sandbox`, and
`/usr/local/libexec/sandboxd/sandbox-route-helper` is stashed under the
backup set as `<name>.bak`, **at mode 0640** (not 0755). Rationale: the
backups must not be executable in place. A backup that lands at mode
`0755` in a path Bash's `$PATH` happens to include (it doesn't here, but
defense-in-depth) would create a duplicate, confusable binary. The
rollback recipe (§ 7.2) explicitly re-`install`s each `.bak` to its
original path with mode `0755 root:root`, reapplying setcap as a
separate step.

```sh
for binary in sandboxd sandbox sandbox-route-helper; do
    case "$binary" in
        sandbox-route-helper)
            src=/usr/local/libexec/sandboxd/$binary
            ;;
        *)
            src=/usr/local/bin/$binary
            ;;
    esac
    dst=$backup_set/$binary.bak
    [ -f "$src" ] || { log_warn "step=backup_binary src=$src action=skip reason=absent"; continue; }
    if [ -f "$dst" ] && cmp -s "$src" "$dst"; then
        log_ok "step=backup_binary src=$src action=skip reason=identical"
        continue
    fi
    sudo -k -u sandbox install -m 0640 "$src" "$dst"
done
```

Log: `step=backup_binary src=<p> dst=<p> sha256=<hex> action=<copy|skip>`.

#### § 3.2.18. Update install state's `previous_version`

Before installing new binaries, record the old version in
`.install-state.json` so that on a subsequent rollback the operator (or
a future `sandbox rollback` if it ever lands) knows what to restore to.

```sh
state_tmp=$(mktemp)
sudo -k jq --arg pv "$CURRENT_VERSION" '.previous_version = $pv' \
    /var/lib/sandbox/.install-state.json > "$state_tmp"
sudo -k -u sandbox install -m 0640 "$state_tmp" /var/lib/sandbox/.install-state.json
```

**Implementation note:** the shell pseudo-code is illustrative. The `>`
redirect creates `state_tmp` owned by the outer shell's user (root or
the operator), but the subsequent `sudo -k -u sandbox install` runs as
`sandbox`, which cannot read a `0600` file owned by another user. In the
Rust implementation (§ 13), the tmpfile is written by the `sandbox` user
via `std::process::Command` — not via shell stdout redirect — so this
ownership mismatch does not occur at runtime.

`previous_version` is a new optional field on the install state schema
(it didn't exist in install.sh's initial write per Spec 4 § 4.5).
Per CLAUDE.md "On-disk compatibility", it is read-defensively with
`jq '.previous_version // ""'`; older install state files without the
field are tolerated.

Log: `step=record_previous_version previous=<v> status=ok`.

#### § 3.2.19. Write backup manifest (in-progress marker)

Before installing binaries, write a `manifest.json` at the backup-set
root with `completed_ok: false`. This marks the set as "in progress" —
the retention prune step (§ 3.2.25) considers a set without
`completed_ok: true` as forensic-only and never auto-deletes it.

```sh
sudo -k -u sandbox tee "$backup_set/manifest.json" >/dev/null <<EOF
{
  "from_version":  "$CURRENT_VERSION",
  "to_version":    "$TARGET_VERSION",
  "started_at":    "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "completed_at":  null,
  "completed_ok":  false,
  "arch":          "$CURRENT_ARCH",
  "files":         { ... }   # each backup's sha256 + size
}
EOF
```

The `files` map is populated from § 3.2.15–17 outputs. Log:
`step=backup_manifest status=in-progress`.

**Ordering note (binding):** the locked-in brainstorm decision is
**"image load BEFORE binary swap, to avoid leaving the system
half-updated."** The reasoning: if an upgrade is interrupted between
binary install and image load, a `systemctl start` would launch the
**new** daemon binary against the **old** gateway image tag — and the
new daemon refuses to start (Spec 3 § 8.5 — gateway image is a hard
requirement). By loading the image first, an interruption mid-flight
leaves the system at "old binary, old image still present plus new
image present alongside" — the old daemon still runs cleanly, and a
re-run picks up where it left off without any half-state. The
following steps are sequenced accordingly: docker load (§ 3.2.20),
then binary swap (§ 3.2.21), then setcap, unit, migrations.

Idempotency contract under this ordering:

| Re-entry point                                 | Convergence outcome                                                                                  |
|-----------------------------------------------|-------------------------------------------------------------------------------------------------------|
| Interrupted before § 3.2.20                   | Old binary, old image. Daemon if `was_running` is still healthy. Re-run resumes from § 3.2.20.       |
| Interrupted after § 3.2.20, before § 3.2.21  | Old binary, **both** images present (idempotent: `docker image inspect` short-circuits on re-run).   |
| Interrupted after § 3.2.21, before § 3.2.26  | New binary on disk, daemon stopped. Re-run resumes from the failing step; old image still present unless operator pruned, but the new image is also present (§ 3.2.20 ran). The new daemon's start passes Spec 3 § 8.5's check. |
| Interrupted between §§ 3.2.26 and 3.2.30      | New binary running. Lock file persists until § 3.2.30; re-run adopts and reaches the failing post-start step. |

The post-load image-tag table check (`docker image inspect "$tag"`) at
§ 3.2.20's idempotency check is the convergence anchor — once a tag is
present, the step short-circuits on every subsequent run.

#### § 3.2.20. `docker load` new gateway image

Image load happens **before** the binary swap, per the binding ordering
note above. Same shape as install.sh § 4.4.20:

```sh
tag="sandbox-gateway:${TARGET_VERSION}"
if docker image inspect "$tag" >/dev/null 2>&1; then
    log_ok "step=docker_load image=$tag action=skip reason=already-loaded"
else
    sudo -k docker load -i "$stage/images/sandbox-gateway-${TARGET_VERSION}.tar"
    docker image inspect "$tag" >/dev/null || die "docker load did not produce expected tag $tag"
fi
```

**Old image not pruned.** Spec 3 § 8.6 forbids auto-pruning the prior
version's gateway image during upgrade — stopped sessions may still
reference the prior tag's image-id, and the disk cost is bounded.
Operators run `docker image prune` manually when they want.

Log: `step=docker_load image=<tag> action=<load|skip> status=ok`.

#### § 3.2.21. Install new binaries

Mirrors install.sh § 4.4.14 — sha256 compare for idempotency, atomic
install via `install -D -m <mode> -o root -g root`:

```sh
install_binary() {
    src="$1"; dst="$2"; mode="$3"
    if [ -f "$dst" ] && cmp -s "$src" "$dst"; then
        log_ok "step=install_binary path=$dst action=skip reason=identical"
        return 0
    fi
    sudo -k install -D -m "$mode" -o root -g root "$src" "$dst"
}

install_binary "$stage/bin/sandboxd"             /usr/local/bin/sandboxd                            0755
install_binary "$stage/bin/sandbox"              /usr/local/bin/sandbox                             0755
install_binary "$stage/bin/sandbox-route-helper" /usr/local/libexec/sandboxd/sandbox-route-helper   0755
```

The new daemon binary lands at `0755 root:root`. The route-helper's file
caps are *not* preserved by `install` — they're stripped on file
overwrite (Linux removes file caps on any chmod/chown/write that
touches the inode). The setcap step (§ 3.2.22) restores them.

Log: `step=install_binary path=<dst> sha256=<hex> action=<install|skip> status=ok`.

#### § 3.2.22. Setcap on route-helper

Identical to install.sh § 4.4.15:

```sh
helper=/usr/local/libexec/sandboxd/sandbox-route-helper
current=$(getcap "$helper" 2>/dev/null | sed -e "s|^.*= ||")
expected='cap_net_admin,cap_sys_admin=eip'
if [ "$current" = "$expected" ]; then
    log_ok "step=setcap action=skip reason=already-set"
else
    sudo -k setcap "$expected" "$helper"
    new=$(getcap "$helper" | sed -e "s|^.*= ||")
    [ "$new" = "$expected" ] || die "setcap verification failed: got '$new'"
fi
```

Log: `step=setcap caps=<v> action=<set|skip> status=ok`.

#### § 3.2.23. Install systemd unit (idempotent)

The new release's `systemd/sandboxd.service` may differ from the
installed one (Spec 3 § 4.1 fixes the unit shape; future releases may
adjust hardening directives). The install is a one-shot sha256 compare:

```sh
unit_src="$stage/systemd/sandboxd.service"
unit_dst="/etc/systemd/system/sandboxd.service"
if [ -f "$unit_dst" ] && cmp -s "$unit_src" "$unit_dst"; then
    log_ok "step=install_unit action=skip reason=identical"
else
    sudo -k install -m 0644 -o root -g root "$unit_src" "$unit_dst"
    sudo -k systemctl daemon-reload
fi
```

**The drop-in directory `/etc/systemd/system/sandboxd.service.d/` is never
touched.** Spec 3 § 4.3 promises drop-ins survive upgrades; § 3.3 below
walks through the invariant. The check looks at the unit file only; the
`.service.d/` directory and its contents are out of scope for this step.

Log: `step=install_unit path=<p> sha256=<hex> action=<install|skip> status=ok`.

#### § 3.2.24. Apply config migrations (per file, atomically)

The framework runs its apply loop (§ 4.3) for each managed file. For
each pending migration, in numeric order:

1. Read current bytes of the file.
2. Apply the migration's transform (§ 4.2).
3. Validate the round-trip parses against the target schema.
4. Write to a temp file under the same filesystem as the destination
   (so the subsequent `rename` is atomic — same-FS rename is the only
   way to guarantee no observer sees a half-written state).
5. `rename` over the destination via `sudo -k mv` (which calls
   `rename(2)` under the hood).
6. Log the migration ID as applied.

```sh
for file in users.conf bridge.conf; do
    case "$file" in
        users.conf)  target=/etc/sandboxd/users.conf;  tmp_dir=/etc/sandboxd ;;
        bridge.conf) target=/etc/qemu/bridge.conf;     tmp_dir=/etc/qemu ;;
    esac
    [ -f "$target" ] || { log_ok "step=migrate_$file action=skip reason=absent"; continue; }

    current_version=$(read_schema_version "$target" "$file")
    target_version=$(registry_latest_for "$file")
    if [ "$current_version" = "$target_version" ]; then
        log_ok "step=migrate_$file action=skip reason=already-at-v$target_version"
        continue
    fi

    # Apply each pending migration in registry order. The CLI binary
    # invokes itself with a hidden `--apply-config-migration` subcommand
    # so the actual transform runs in-process with the Rust framework,
    # writing to a sudo-controlled tempfile.
    for mig in $(registry_pending "$file" "$current_version" "$target_version"); do
        tmp_path="$tmp_dir/.$file.tmp.$mig"
        sudo -k sandbox --apply-config-migration \
            --file "$target" \
            --migration "$mig" \
            --out "$tmp_path"
        # Atomic rename. mv calls rename(2) which is atomic on the same FS.
        sudo -k mv "$tmp_path" "$target"
        log_ok "step=migrate_$file migration=V$mig path=$target status=ok"
    done
done
```

The `--apply-config-migration` flag is a Spec 5-introduced hidden CLI
affordance — it exists so the orchestrating script can leverage the
in-process Rust framework for the actual transform while running the
sudo elevation outside.

Idempotency: if a re-run finds the file already at or beyond the
migration's `to_version`, the loop skips that migration. The daemon-side
schema-mismatch refusal (§ 4.7) is the safety net — a partially-applied
migration would leave the file at the version of the last successful
hop, and on a subsequent run the framework continues from there.

Log: `step=migrate_<file> migration=V<NNN> path=<p> action=<apply|skip>`.

#### § 3.2.25. Prune older backup sets

Only **successful** (`completed_ok: true`) backup sets are pruned. The
current in-progress set (this run's manifest still says `false`) is
skipped automatically by the filter.

```sh
sudo -k -u sandbox bash -c '
cd /var/lib/sandbox/backups
# Sort by `started_at` from manifest.json, descending.
mapfile -t completed_sets < <(
    for d in */; do
        ok=$(jq -r ".completed_ok // false" "$d/manifest.json" 2>/dev/null)
        ts=$(jq -r ".started_at // \"\""    "$d/manifest.json" 2>/dev/null)
        [ "$ok" = "true" ] && echo "$ts $d"
    done | sort -r | cut -d" " -f2-
)
# Keep the most-recent two.
keep=2
i=0
for d in "${completed_sets[@]}"; do
    i=$((i + 1))
    [ $i -le $keep ] && continue
    rm -rf "$d"
    echo "pruned: $d"
done
'
```

The current run's manifest is updated to `completed_ok: true` at
step § 3.2.29 below, so this prune step **runs before** the final
manifest update — but the filter on `completed_ok: true` already
excludes the current set (its manifest still says `false` from step
§ 3.2.19), so even if the prune ran twice it wouldn't touch this run's
state. The re-ordering of binary swap and docker load (steps 20–21
above) does not affect this property — the prune step looks only at
already-completed sibling backup sets' manifests, not at the current
run's binaries or images.

Log: `step=prune_backups kept=2 pruned=<n>`.

#### § 3.2.26. Start daemon (only if `was_running`)

```sh
if [ "$WAS_RUNNING" = "true" ]; then
    sudo -k systemctl start sandboxd
fi
```

The daemon's startup runs refinery DB migrations automatically
(`SessionStore::new` at `sandbox-core/src/store.rs:114-123`); the
update flow does **not** call refinery from the CLI side. The daemon
also runs the `_schema_version` check (§ 4.7) on `users.conf` /
`bridge.conf` at startup. If the file is **ahead** of the daemon's
supported max (downgrade scenario, or interrupted upgrade), the daemon
refuses to start and `systemctl start` exits non-zero; the CLI surfaces
the journald error and points at the rollback recipe. If the file is
**behind** (someone bumped the binary without running the framework),
the daemon also refuses — the rollforward path is "run `sandbox
update`," but we're already inside one. § 4.7 walks through this
loop-prevention property.

Log: `step=start_daemon was_running=<true|false> action=<start|skip> status=<ok|fail>`.

#### § 3.2.27. Verify post-start

Wait for the daemon's socket to accept connections (Spec 3 §§ 4.1 / 5.1
say systemd creates `/run/sandbox/` and the daemon binds the socket
itself), then query `/version` (Spec 3 § 7.2):

```sh
sock=/run/sandbox/sandboxd.sock
for attempt in $(seq 1 30); do
    [ -S "$sock" ] && break
    sleep 1
done
[ -S "$sock" ] || die "daemon socket did not appear within 30s; consult: sudo journalctl -u sandboxd -n 50"

daemon_ver=$(curl -fsSL --unix-socket "$sock" http://localhost/version | jq -r '.version')
[ "$daemon_ver" = "$TARGET_VERSION" ] || die "post-upgrade /version mismatch: daemon reports $daemon_ver, expected $TARGET_VERSION"
```

Log: `step=verify_version daemon=<v> target=<v> status=<ok|fail>`.

#### § 3.2.28. Run `sandbox doctor`

Final sanity check. Spec 3 § 6 designs doctor; on a healthy post-upgrade
host, every check passes:

```sh
sandbox doctor --verbose || die "sandbox doctor reported failures; investigate before relying on this install. rollback recipe at /var/lib/sandbox/backups/$(basename $backup_set)/manifest.json"
```

Doctor's exit code 1 (one or more checks failed) is upgrade-fatal: the
update is incomplete. The operator sees the failed-checks list and the
pointer to the backup set; the rollback recipe in § 7.2 is the
recovery path. Log: `step=doctor result=<pass|fail>`.

#### § 3.2.29. Update install state + finalize backup manifest

Atomic update of the install state file — record the new
`installed_version`, `installed_at` (now), `updated_by_operator` (from
`$SUDO_USER`), and keep the just-set `previous_version` from step
§ 3.2.18:

```sh
state_tmp=$(mktemp)
sudo -k jq --arg v "$TARGET_VERSION" \
          --arg at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
          --arg op "${SUDO_USER:-(direct-root)}" \
          '. + {
             "installed_version":     $v,
             "installed_at":          $at,
             "updated_by_operator":   $op
           }' \
    /var/lib/sandbox/.install-state.json > "$state_tmp"
sudo -k -u sandbox install -m 0640 "$state_tmp" /var/lib/sandbox/.install-state.json
```

(**Implementation note:** same ownership caveat as § 3.2.18 — in the
Rust implementation the tmpfile is written by the `sandbox` user via
`std::process::Command`, not via shell stdout redirect.)

Finalize the backup set's manifest with `completed_at` and
`completed_ok: true`:

```sh
manifest_tmp=$(mktemp)
sudo -k -u sandbox jq --arg at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    '. + {"completed_at": $at, "completed_ok": true}' \
    "$backup_set/manifest.json" > "$manifest_tmp"
sudo -k -u sandbox install -m 0644 -o sandbox -g sandbox "$manifest_tmp" "$backup_set/manifest.json"
```

Log: `step=finalize_state installed_version=<v> previous_version=<v> status=ok`,
`step=finalize_backup_manifest path=<p> status=ok`.

#### § 3.2.30. Release the lock

```sh
sudo -k rm -f /var/lib/sandbox/.update.lock
exec {lock_fd}>&-     # close the FD → kernel releases flock
```

Log: `step=release_lock status=ok`,
`step=done version=<v> elapsed=<seconds> status=ok`.

### 3.3 · What's preserved untouched

The upgrade explicitly does **not** touch:

| Path / artefact                                                     | Why preserved |
|---------------------------------------------------------------------|---------------|
| `/etc/systemd/system/sandboxd.service.d/`                           | Spec 3 § 4.3 promise: operator drop-ins survive base-unit replacement. § 3.2.23 above touches only `sandboxd.service`, never the sibling `.service.d/`. |
| `/var/lib/sandbox/sessions.db` (after the backup-then-upgrade)      | Backed up before the swap; refinery applies forward-only DB migrations on next daemon start (no CLI-side touch). |
| Per-session directories under `/var/lib/sandbox/sessions/<id>/`     | Session state is owned by the daemon; the upgrade never reaches into per-session storage. |
| `/var/lib/sandbox/route-helper-audit.log`                           | Appendable forensic log; the upgrade does not rotate or truncate it. The route-helper's audit-write policy (Spec 1's revision: deny-path write failure escalates with `DENY_EXIT`; allow-path write failure continues) is unaffected by the upgrade — Spec 5 inherits the policy as-is and the upgrade flow does not touch the audit log's file mode, owner, or content. |
| `/var/log/sandbox-install.log`                                      | Appended to with `sandbox-update` second token (§ 2.6); never rotated or truncated. |
| The `sandbox` system user, group, and `docker`/`kvm` memberships    | Only install.sh creates them; uninstall.sh removes them under `--purge`. The upgrade leaves them alone. |
| Operator group memberships (operators in `sandbox` group)           | install.sh records `operators_added_to_group`; the upgrade does not modify the list. |
| `/etc/qemu/bridge.conf` rules added by install.sh                   | Unless a future config migration explicitly changes them, the upgrade leaves them alone. |
| `/etc/sandboxd/users.conf` operator-added entries                   | Operators may have added subnets / pools / comments; V001+ migrations are designed (Spec 1 § 4.3) to preserve operator-added content outside the fields they touch. |

The integration test in § 9.1 (`migration with operator-customized
users.conf → verify custom fields preserved`) pins this property.

### 3.4 · Failure handling

The flow is idempotent, so transient failures are recovered by re-running
`sudo sandbox update`. Specific failure modes:

| Failure                                                | Where it surfaces | Recovery                                                                                                  |
|--------------------------------------------------------|--------------------|-----------------------------------------------------------------------------------------------------------|
| Network failure during tarball fetch                   | § 3.1.4            | Re-run. No state mutated yet.                                                                              |
| Sigstore verification failure                          | § 3.1.10           | Refuse; suggest checking system clock, cosign binary version, network. No state mutated.                  |
| MANIFEST sha256 mismatch                               | § 3.1.10           | Refuse with the mismatched file name. Likely a corrupted download — re-fetch.                              |
| Migration dry-run failure                              | § 3.1.11           | Refuse with a clear error pointing at the failing migration's `to_version`. No state mutated; safe to abort. |
| Active sessions exist (no `--force`)                   | § 3.1.6            | Operator stops sessions or passes `--force` and re-runs.                                                   |
| Disk space short                                       | § 3.1.8            | Operator frees space; re-runs.                                                                              |
| Lock held by live PID                                  | § 6.2              | Refuse with PID; operator investigates (probably another update in progress).                              |
| Lock held by dead PID                                  | § 6.2              | Adopt the lock; log adoption; continue with the sticky `was_running` preserved.                            |
| Migration apply failure (mid-§ 3.2.24)                 | § 3.2.24           | File at version of last successful migration; daemon refuses to start (§ 4.7); operator re-runs `sandbox update` or rolls back per § 7.2. |
| Daemon fails to start after upgrade                    | § 3.2.26           | `sandbox doctor` reports it (Spec 3 § 6.2); `journalctl -u sandboxd` shows the daemon-side error. Rollback recipe in § 7.2 is available. |
| `sandbox doctor` reports failures post-upgrade         | § 3.2.28           | Backup set's `manifest.json` has `completed_ok: false`. The kernel flock is released when the process exits (FD closed); only the JSON payload file remains on disk. Re-running adopts the payload's `was_running` and re-attempts § 3.2.28 (and any subsequent step that was skipped). Operators either fix the underlying issue and re-run, or invoke the rollback recipe (§ 7.2) — step 8 of which removes the stale lock file. |
| Refinery DB migration failure on next daemon start     | Daemon `tracing` → journald | Daemon refuses to start. `sandbox doctor` C1 reports it. Operator inspects journald; if the DB is corrupt the rollback recipe (§ 7.2) restores `sessions.db.bak` and the prior daemon binary together. |
| Operator's CLI binary swapped mid-flight (§ 10.3)      | inside `sandbox update` itself | Linux file semantics: an executable mapped into a running process keeps its inode references until exit. The running `sandbox update` continues to its end with the **old** CLI binary's code; the new binary on disk is unaffected. |

The kernel flock is released when the process exits (FD closed). The JSON
payload file remains on disk after any non-§ 3.2.30 exit, so re-runs see
the stale payload, find the dead PID, and adopt with the sticky
`was_running`. A failure between binary install (§ 3.2.21) and lock release
leaves the payload present; the idempotent inspections in §§ 3.2.15–29
skip already-completed work and the re-run reaches the failing step.

## 4 · Config migration framework

The framework is a small Rust module set inside `sandbox-cli/`. Its
shape mirrors refinery's pattern (versioned migrations, numeric ordering,
idempotent apply, validation before commit) but applies to filesystem
files rather than SQL tables.

### 4.1 · Where the registry lives

```
sandboxd/sandbox-cli/src/cfg_migrations/
├── mod.rs                                   # registry + apply loop + traits
├── v001_add_sandbox_to_allow_users.rs       # Spec 1 § 5 (the framework's first user)
└── (future: v002_..., v003_...)
```

The framework lives in `sandbox-cli/` rather than `sandbox-core/`
because the only invoker is the CLI's `sandbox update` orchestration —
the daemon never applies migrations itself. The daemon's role is to
**refuse to start** on schema mismatch (§ 4.7); that refusal lives in
the daemon side (`sandbox-core/src/users_conf.rs`) but does not need the
framework or its registry.

Spec 1 § 11 already places the pure `migrate_v001(serde_json::Value) ->
serde_json::Value` transform in `sandbox-core/src/users_conf.rs`. Spec 5
**does not move it**; instead, the framework's `v001_add_sandbox_to_allow_users.rs`
adapter calls `sandbox_core::users_conf::migrate_v001` from a thin
`ConfigMigration` impl. This keeps the pure-transform code together
with the schema struct definition (the natural place to test the
content-level invariant) and keeps the file-IO orchestration in the CLI.

### 4.2 · The `Migration` trait

```rust
// sandbox-cli/src/cfg_migrations/mod.rs

use std::path::PathBuf;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum MigrationError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("parse: {0}")]
    Parse(String),
    #[error("transform: {0}")]
    Transform(String),
    #[error("validation: post-migration content did not parse against target schema: {0}")]
    Validation(String),
    #[error("schema version unreadable from {0}: {1}")]
    SchemaUnreadable(String, String),
}

/// Which on-disk file a migration applies to. Each managed file has its
/// own version sequence; V001 on `UsersConf` is distinct from a future
/// V001 on `BridgeConf`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TargetFile {
    /// `/etc/sandboxd/users.conf` (JSON; `_schema_version` top-level
    /// integer per Spec 1 § 4.2).
    UsersConf,
    /// `/etc/qemu/bridge.conf` (text; header-comment-versioned per § 4.5
    /// below). Reserved — no migration ships against it in v1.
    BridgeConf,
}

impl TargetFile {
    pub fn canonical_path(&self) -> PathBuf {
        match self {
            TargetFile::UsersConf  => PathBuf::from("/etc/sandboxd/users.conf"),
            TargetFile::BridgeConf => PathBuf::from("/etc/qemu/bridge.conf"),
        }
    }
}

pub trait ConfigMigration: Sync {
    /// Stable numeric ID. Migrations are applied in ascending order.
    /// Convention: V001..V999 zero-padded in module names; integer here.
    fn id(&self) -> u32;
    /// Short human-readable name (matches the module suffix —
    /// `add_sandbox_to_allow_users`).
    fn name(&self) -> &'static str;
    /// File this migration applies to. A migration touches exactly one
    /// file; cross-file migrations would compose two migrations with
    /// the same `id()` on different `TargetFile`s.
    fn target_file(&self) -> TargetFile;
    /// `from_version` it expects to read. Used by the apply loop to
    /// pick the next pending migration; also documents intent.
    fn from_version(&self) -> u32;
    /// `to_version` it produces. After apply, the file's
    /// `_schema_version` (or header marker) reads this value.
    fn to_version(&self) -> u32;
    /// Pure transform — read bytes in, return bytes out.
    /// Implementations are expected to round-trip through whatever
    /// parser is appropriate (`serde_json` for JSON files;
    /// line-by-line preservation for text files). The framework
    /// validates the result against the target schema after the call.
    fn apply(&self, file_contents: &[u8]) -> Result<Vec<u8>, MigrationError>;
}
```

The trait is intentionally tiny. The framework owns the file IO,
sudo elevation, atomic-rename, and validation; migrations own only the
content transform. The split keeps each new migration a focused unit:
the test for V001's transform is the unit test in Spec 1 § 8.2 — no
file-IO mocking required.

**Selection rule (binding):** every migration advances **exactly one
version**: `to_version() == from_version() + 1`. Multi-version skips
are composed by chaining migrations (e.g., upgrading a file from
version 0 to version 3 walks V001 0→1, V002 1→2, V003 2→3 in order).
This forbids a single migration with `from_version() == 0, to_version()
== 3` that would collapse three steps; such a transform must be split
into three single-step migrations.

Two consequences:

1. The apply loop's filter `m.from_version() == current` is exact
   (§ 4.3 — never picks more than one migration per iteration; walks
   the chain by re-reading `current` after each apply).
2. Spec 1's V001 idempotency contract (Spec 1 § 5.3 — "A file with
   `_schema_version: 1` already at the top level → V001 does
   nothing") is a **defense-in-depth guarantee unobservable by the
   framework's selection rule**: the apply loop short-circuits at
   `current >= target` (§ 4.3) before calling V001's `apply` on a
   file already at version 1. Spec 1 documents the transform-level
   idempotency for the case where a test or future contributor calls
   the pure transform directly; the framework never observes it.

The selection rule is verified by a unit test in § 9.2
(`registry_migrations_advance_exactly_one_version`).

The registry is a static slice of `&'static dyn ConfigMigration`,
initialized at compile time:

```rust
pub fn registry() -> &'static [&'static dyn ConfigMigration] {
    &[
        &v001_add_sandbox_to_allow_users::Migration,
        // (future: V002, V003, ...)
    ]
}

/// Return the full ordered list of pending migrations for `file` from
/// `current` (exclusive) to `target` (inclusive). Used for display
/// purposes — the `--check` pending-migrations summary and the
/// confirmation prompt. The `apply_pending` loop in § 4.3 does NOT
/// call this; it uses `find()` on the registry directly for sequential
/// one-step-at-a-time application. Both are consistent with the
/// "exactly one version per migration" contract: the list returned here
/// is contiguous (V(current+1), V(current+2), … V(target)) because each
/// entry advances from N to N+1.
pub fn pending(file: TargetFile, current: u32, target: u32) -> Vec<&'static dyn ConfigMigration> {
    registry()
        .iter()
        .copied()
        .filter(|m| m.target_file() == file && m.from_version() >= current && m.to_version() <= target)
        .collect()
}

pub fn latest_for(file: TargetFile) -> u32 {
    registry()
        .iter()
        .filter(|m| m.target_file() == file)
        .map(|m| m.to_version())
        .max()
        .unwrap_or(0)
}
```

(`pending` and `latest_for` shown for illustration. The real apply loop
walks the chain — § 4.3.)

### 4.3 · The apply loop

For each managed file, the loop reads the current `_schema_version`,
finds the chain of migrations from current to target, and applies them
in order. Each application is its own atomic write — the file is at
a consistent version after every successful migration, never in a
half-applied state.

```rust
// sandbox-cli/src/cfg_migrations/mod.rs

pub fn apply_pending(file: TargetFile) -> Result<Vec<u32>, MigrationError> {
    let path = file.canonical_path();
    let mut applied = Vec::new();
    loop {
        let bytes = std::fs::read(&path)?;
        let current = read_schema_version(&bytes, file)?;
        let target = latest_for(file);
        if current >= target {
            return Ok(applied);
        }
        // Find the migration that takes us from `current` to the next step.
        let migration = registry()
            .iter()
            .copied()
            .find(|m| m.target_file() == file && m.from_version() == current)
            .ok_or_else(|| MigrationError::Transform(format!(
                "no migration available for {file:?} at version {current} (target: {target})"
            )))?;

        let new_bytes = migration.apply(&bytes)?;
        validate_against_target_schema(&new_bytes, migration)?;
        atomic_write(&path, &new_bytes)?;

        applied.push(migration.id());
    }
}

fn atomic_write(path: &Path, bytes: &[u8]) -> Result<(), MigrationError> {
    // Write to a temp file under the same FS as `path`, then rename.
    // Same-FS rename is the only way to guarantee atomicity — rename(2)
    // is atomic when src and dst are on the same filesystem.
    let parent = path.parent().ok_or_else(|| /* internal: orphan path */)?;
    let mut tmp = tempfile::NamedTempFile::new_in(parent)?;
    tmp.write_all(bytes)?;
    tmp.persist(path)?;       // rename(2) under the hood
    Ok(())
}
```

The CLI shim that the `sandbox update` shell flow invokes
(`sandbox --apply-config-migration --file <path> --migration V<NNN>
--out <tmp>`) drives this in-process: it reads, applies the
specified migration in memory, validates, and writes to `--out`. The
outer flow then renames `--out` into place via `sudo -k mv`. The split
between the in-process apply and the outer sudo-rename exists because
the CLI binary itself runs as the operator; only the `mv` step needs
root.

The `--dry-run` mode (§ 2.3 / § 3.1.12) calls `apply_pending` against
an in-memory copy of each file (read once, transforms threaded
through, validation invoked) but never writes — the validation step
catches any broken migration before any sudo elevation occurs.

#### Access gating for `--apply-config-migration` (security)

The hidden flag is clap-`hide(true)` so it doesn't surface in
`--help`, but `hide` is **not access control** — the flag is callable
by any local user against `/usr/local/bin/sandbox` (mode `0755 root:root`,
world-callable per Spec 3 § 5.1). Without explicit gating, an
unprivileged user could ask the CLI to apply migration V001 against an
attacker-controlled `--file /tmp/their-fake.json` with `--out
/var/lib/sandbox/whatever`, which is a parser-confusion hazard at
minimum and a privesc-shaped bug if a future migration writes
attacker-controlled bytes to a path with downstream effects.

The `--apply-config-migration` subcommand enforces, in this order:

1. **Caller must be root.** `getuid() != 0` → refuse with
   `--apply-config-migration is internal to sandbox update and requires
   root; run via `sudo sandbox update` instead` and exit non-zero.
   This rules out unprivileged callers entirely; the only legitimate
   caller is `sudo -k sandbox --apply-config-migration` invoked by
   `sandbox update`'s own orchestration.
2. **`--file` is a registry-canonical path.** The argument is parsed
   into a `TargetFile` (via `TargetFile::from_canonical_path(&Path)`,
   a new helper that returns `Some(TargetFile::UsersConf)` for
   exactly `/etc/sandboxd/users.conf` and `Some(TargetFile::BridgeConf)`
   for exactly `/etc/qemu/bridge.conf`). Anything else → refuse with
   `--file must be one of the registry's canonical paths
   (/etc/sandboxd/users.conf, /etc/qemu/bridge.conf); got: <path>`.
3. **`--out` is a tempfile under a registry-known parent dir.** The
   argument's parent must be the same parent as `--file`'s canonical
   path, and the basename must match the pattern
   `\.<basename>\.tmp\.V[0-9]+$` (e.g., `/etc/sandboxd/.users.conf.tmp.V001`).
   Anything else → refuse with `--out must be a tempfile under the
   same directory as --file; got: <out>`.
4. **`--migration` exists in the registry for the target file.** The
   migration ID must resolve to a registered `ConfigMigration` whose
   `target_file()` matches the validated `TargetFile`. Anything else
   → refuse with `migration V<NNN> not found in registry for <target>`.

Same rules for `--dump-migration-set` (§ 3.1.4), narrower:

1. Caller must be the operator or root (no privilege requirement; the
   flag is read-only).
2. No argument validation beyond clap's parsing (it takes no
   path-like arguments).
3. Output goes to stdout; no file is written.

The gating logic lives in `sandbox-cli/src/main.rs`'s subcommand
dispatch (a precondition guard at the top of the handler). Unit tests
in § 9.2 cover each refusal path.

### 4.4 · Atomic write semantics

Atomic write requires:

1. **Write to a temp file under the same filesystem as the destination.**
   `/etc/sandboxd/.users.conf.tmp.V<NNN>` (next to `users.conf`) and
   `/etc/qemu/.bridge.conf.tmp.V<NNN>` (next to `bridge.conf`). Linux
   `rename(2)` is atomic only when src and dst are on the same FS;
   crossing FS boundaries falls back to a copy+unlink that has a
   half-written window.
2. **`rename(2)` the temp file over the destination.** This swaps the
   inode directory entry in one syscall — no observer ever sees a
   half-written file. POSIX guarantees this on the same filesystem.
3. **The temp file is owned/mode-set to the daemon's expectation
   before rename.** `install -m 0644 -o root -g root` on the temp
   file, then `mv`. Once renamed, the file is at the correct mode
   and owner immediately.

The framework's `atomic_write` (Rust side) uses `tempfile::NamedTempFile::new_in(parent)`
+ `persist(path)` for the in-process path (the `--apply-config-migration`
CLI subcommand's output). The outer shell loop (§ 3.2.24) then does the
sudo-`mv` because the rename target lives under `/etc/`, owned by root.

For `users.conf` specifically (Spec 4 § 4.4.19 sets it `0644 root:root`):
the rename leaves the file at the right mode automatically (assuming the
temp file is installed at `0644 root:root` before the mv). For
`bridge.conf` (`0644 root:root` per `Makefile:355` / Spec 4 § 4.4.18 —
matches QEMU's distro convention): same pattern, mode 0644. The CLI
must reference the canonical mode constants rather than re-stating them
inline (a single shared `MODE_USERS_CONF: u32 = 0o644` and
`MODE_BRIDGE_CONF: u32 = 0o644` in the framework's `version.rs` or
`mod.rs`) so future migrations that touch new files declare their mode
once.

### 4.5 · Version detection per file

- **`users.conf` (JSON):** top-level `_schema_version: <int>` field.
  Spec 1 § 4.2 specifies it. Read with `serde_json::Value` and look up
  the key. A file with no `_schema_version` is treated as version `0`
  and V001 applies. Spec 1's V001 transform (which adds the field with
  value `1`) is idempotent: re-running on a file already at `1` is a
  no-op.

- **`bridge.conf` (text):** first-line comment `# sandbox-schema-version:
  <int>`. The QEMU bridge helper's parser ignores `#`-prefixed lines
  (verified in Spec 3 § 9), so the marker is transparent to QEMU. A
  file with no marker is treated as version `0`. Spec 1 § 4.3 flagged
  comment-headers as one option but didn't pin it; Spec 5 commits to
  the `# sandbox-schema-version: <int>` form on the first line.

`read_schema_version` is a small helper module:

```rust
// sandbox-cli/src/cfg_migrations/version.rs

pub fn read_schema_version(bytes: &[u8], file: TargetFile) -> Result<u32, MigrationError> {
    match file {
        TargetFile::UsersConf => {
            let v: serde_json::Value = serde_json::from_slice(bytes)
                .map_err(|e| MigrationError::Parse(format!("users.conf is not valid JSON: {e}")))?;
            Ok(v.get("_schema_version")
                .and_then(|v| v.as_u64())
                .map(|n| n as u32)
                .unwrap_or(0))
        }
        TargetFile::BridgeConf => {
            // Look at the first line; if it matches
            // `^# sandbox-schema-version: (\d+)$`, return the int.
            let first = std::str::from_utf8(bytes)
                .map_err(|e| MigrationError::Parse(format!("bridge.conf not utf-8: {e}")))?
                .lines()
                .next()
                .unwrap_or("");
            const PREFIX: &str = "# sandbox-schema-version:";
            Ok(first.strip_prefix(PREFIX)
                .map(str::trim)
                .and_then(|s| s.parse::<u32>().ok())
                .unwrap_or(0))
        }
    }
}
```

If the version marker is absent (pre-V001 file from an older install),
the file is at version `0` and the framework applies V001+ in order.

If `users.conf` does not parse as JSON at all, the framework refuses
with a `MigrationError::Parse`. This shape matches Spec 1 § 9.2's
existing behavior — a corrupted file is not silently migrated.

### 4.6 · Preserving operator content

V001's transform (Spec 1 § 4.3) uses `serde_json::Value` so unknown
keys / operator-added fields are preserved through the round-trip.
Future JSON migrations should follow the same pattern. The
`#[serde(deny_unknown_fields)]` on `UsersConfig` (Spec 1 § 4.2) is
**enforced by the daemon at load time**, not by the migration
framework — the framework round-trips `Value`, which preserves
unknowns silently.

For `bridge.conf`, future migrations parse line-by-line, modify only
matched patterns, preserve all unmatched lines verbatim. The
operator-added `allow XXX-*` lines that Spec 4 § 4.4.18 documents
(or that a custom operator added for QEMU workloads unrelated to
sandboxd) are preserved.

Tests must include: a `users.conf` with operator-added custom fields
→ migration runs → custom fields still present after migration. See
§ 9.1 (`migration with operator-customized users.conf → verify custom
fields preserved`).

### 4.7 · Daemon-side schema-mismatch refusal

This is the safety property that makes idempotent re-runs converge.
The daemon, on startup, parses `users.conf`, reads `_schema_version`,
compares to its supported range, and refuses to start on mismatch.

Today's startup load is at `sandboxd/sandboxd/src/main.rs:6156`:

```rust
let users_config = match load_users_config() {
    Ok(cfg) => cfg,
    Err(err) => {
        let sandbox_err: SandboxError = err.into();
        eprintln!("sandboxd: {sandbox_err}");
        return Err(sandbox_err.into());
    }
};
```

Spec 5 layers the schema check on top, immediately after the load
succeeds:

```rust
// sandbox-core/src/users_conf.rs (new helper)

pub const DAEMON_MAX_SUPPORTED_USERS_CONF_SCHEMA: u32 = 1;
/// At v1, MIN equals MAX (both 1) because only one schema version exists.
/// The MIN constant exists to establish the pattern: when a future daemon
/// can accept both v1 and v2 files (e.g. a rolling-upgrade window where
/// some operators have run `sandbox update` but others haven't yet), MIN
/// stays at 1 and MAX advances to 2. The validator's `MIN <= v <= MAX`
/// range check is written once and covers both eras without modification.
pub const DAEMON_MIN_SUPPORTED_USERS_CONF_SCHEMA: u32 = 1;

pub fn validate_users_conf_schema_version(cfg: &UsersConfig) -> Result<(), UsersConfigError> {
    let v = cfg.schema_version.unwrap_or(0);
    if v > DAEMON_MAX_SUPPORTED_USERS_CONF_SCHEMA {
        return Err(UsersConfigError::SchemaTooNew {
            file_version: v,
            daemon_max: DAEMON_MAX_SUPPORTED_USERS_CONF_SCHEMA,
            hint: format!(
                "users.conf schema version {v} is newer than this binary supports (max: {}). \
                 This typically indicates a downgrade or an interrupted update. \
                 Run `sandbox update` to fix, or restore from backup at \
                 /var/lib/sandbox/backups/<latest>/users.conf.bak.",
                DAEMON_MAX_SUPPORTED_USERS_CONF_SCHEMA,
            ),
        });
    }
    if v < DAEMON_MIN_SUPPORTED_USERS_CONF_SCHEMA {
        return Err(UsersConfigError::SchemaTooOld {
            file_version: v,
            daemon_min: DAEMON_MIN_SUPPORTED_USERS_CONF_SCHEMA,
            hint: format!(
                "users.conf schema version {v} is older than this binary supports (min: {}). \
                 The config migration framework has not yet applied pending migrations. \
                 Run `sandbox update` to bring the file up to date.",
                DAEMON_MIN_SUPPORTED_USERS_CONF_SCHEMA,
            ),
        });
    }
    Ok(())
}
```

Spec 1 § 4.2 added `schema_version: Option<u32>` to `UsersConfig` (with
`#[serde(default, rename = "_schema_version")]`). Spec 5 wires the
validator into the daemon's startup right after `load_users_config()`:

```rust
let users_config = match load_users_config() {
    Ok(cfg) => cfg,
    Err(err) => { /* existing error path */ }
};

if let Err(err) = validate_users_conf_schema_version(&users_config) {
    let sandbox_err: SandboxError = err.into();
    eprintln!("sandboxd: {sandbox_err}");
    return Err(sandbox_err.into());
}
```

The two new `UsersConfigError` variants are `SchemaTooNew` and
`SchemaTooOld`; both map to clear stderr lines via the existing
`Display` impl. The daemon's process exits non-zero, systemd's
`Restart=on-failure` (Spec 3 § 4.1) keeps trying until
`StartLimitBurst=5` is hit — at which point `systemctl status
sandboxd` shows the rate-limit refusal and `journalctl -u sandboxd`
shows the schema-mismatch error.

The error wording explicitly names the backup location so the
operator's recovery path is one read away. The hint also names
`sandbox update` as the rollforward path — if the file is **behind**
(schema-too-old), the framework hasn't run; the next `sudo sandbox
update` walks the apply loop.

**For first-install greenfield:** install.sh writes `users.conf` at
the binary's max schema version directly (Spec 4 § 4.4.19 — V001
content from the start). So this case shouldn't fire on a fresh
install. The check exists to defend against rollback scenarios and
partial-upgrade corruption.

A symmetric check for `bridge.conf` is added at the same site (Spec 5
introduces a `bridge_conf.rs` loader, since the daemon does **not**
currently parse `bridge.conf` — only `qemu-bridge-helper` does). The
daemon's role is to read the header-comment version marker and refuse
if ahead or behind its supported range. The daemon does not parse the
rest of `bridge.conf` — that file is QEMU's, not sandboxd's. v1 ships
with `bridge.conf` at version `0` (no migration applies to it yet);
`DAEMON_MAX_SUPPORTED_BRIDGE_CONF_SCHEMA = 0` and the validator is a
no-op until a future migration bumps it.

## 5 · Backup mechanics

### 5.1 · Layout

`/var/lib/sandbox/backups/` is created at daemon first start (Spec 3
§ 5.1) with mode `0700 sandbox:sandbox`. Each successful update produces
one backup set as a subdirectory:

```
/var/lib/sandbox/backups/
├── 2026-05-11T14:23:11Z-from-1.0.0-to-1.1.0/      ← in-progress or completed
│   ├── manifest.json                # § 5.3
│   ├── sandboxd.bak                 # mode 0640 sandbox:sandbox
│   ├── sandbox.bak                  # mode 0640
│   ├── sandbox-route-helper.bak     # mode 0640
│   ├── sessions.db.bak              # mode 0600
│   ├── users.conf.bak               # mode 0644 (matches /etc/sandboxd/users.conf)
│   └── bridge.conf.bak              # mode 0644 (matches /etc/qemu/bridge.conf per Spec 4 § 4.4.18)
├── 2026-05-09T09:11:42Z-from-0.9.5-to-1.0.0/      ← prior successful upgrade, kept
└── 2026-05-07T12:00:00Z-from-0.9.4-to-0.9.5/      ← older, eligible for prune
```

The directory naming convention `<ISO8601>-from-<v1>-to-<v2>/` is
explicit enough that `ls -td /var/lib/sandbox/backups/*/` lists in
chronological order. The rollback recipe (§ 7.2) uses this property —
`head -1` finds the most recent set.

### 5.2 · Retention policy

Keep the **last 2 successful** backup sets. "Successful" means the
`manifest.json` has `completed_ok: true`. Failed / in-progress sets
(missing the flag or with `completed_ok: false`) are **never**
auto-pruned — they preserve forensic evidence of failed updates until
the operator decides to delete them.

The pruning runs at § 3.2.25, before § 3.2.29 sets the current set's
`completed_ok: true`. The filter on `completed_ok: true` excludes the
current run's set automatically — even if the prune ran twice in a
row, no race would prune the current set. The filter is the safety
property.

Two is enough for the recovery story: the most recent backup
corresponds to "before the last successful upgrade"; the second-most
recent gives one extra step back if the most recent is itself broken.
Anything older is rolled-back ground the operator probably no longer
needs.

### 5.3 · Backup manifest format

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

Fields:

| Field          | Meaning |
|----------------|---------|
| `from_version` | The `installed_version` before the upgrade. Read from `.install-state.json` at lock acquisition. |
| `to_version`   | The target version of this upgrade. Same as `--version <v>` if explicit. |
| `started_at`   | ISO8601 UTC at backup-set creation (§ 3.2.15). |
| `completed_at` | ISO8601 UTC at the end of § 3.2.29. `null` until the upgrade completes. |
| `completed_ok` | `false` until § 3.2.29 finalizes; `true` thereafter. The filter for `--prune` retention; the filter for "is this set safe to delete?". |
| `arch`         | Matches `installed_arch`; sanity check for rollback (cross-arch restore would fail at exec). |
| `files`        | Map of basename → `{sha256, size}`. Populated incrementally by §§ 3.2.15–17. The rollback recipe (§ 7.2) can verify the `.bak` files' integrity against this map. |

Mode: `0644 sandbox:sandbox`. The daemon does not read this file; only
the CLI (`sandbox update` and the documented rollback recipe) reads it.

The manifest is **not** included in the `.bak` set's sha256 self-hash —
adding the manifest's hash to itself would be circular. The `.bak`
files have their hashes captured; the manifest itself is a
forensic-and-recovery aid.

### 5.4 · Why `.bak` not `.previous` in PATH

Spec 3 § 5 explicitly avoided placing `.previous` binaries in
`/usr/local/bin/` to keep PATH clean of duplicate binaries with
ambiguous behavior. Spec 5 confirms: every binary backup lands in
`/var/lib/sandbox/backups/<set>/`, never anywhere in PATH, mode
`0640` (not executable). The rollback recipe (§ 7.2) `install`s the
`.bak` back to its original path with mode `0755`.

### 5.5 · Operator access to backups

`/var/lib/sandbox/backups/` is mode `0700 sandbox:sandbox`. Operators
in the `sandbox` group **cannot** read it directly (mode `0700`, not
`0750`). They must:

```sh
# Inspect a backup
sudo -u sandbox cat /var/lib/sandbox/backups/<set>/manifest.json

# Or, for the rollback recipe, sudo for each restore step (per § 7.2).
```

Rationale: backups contain `sessions.db.bak` with operator-specific data
(session metadata, per-session CA material — all the things Spec 2's
API filter is meant to keep per-operator-private). The group-share-via-API
model from Spec 2 § 2 applies: operators interact with sessions only
through the daemon's API, which enforces per-caller filtering. The
backup directory's mode `0700` is the filesystem-level mirror of that
contract.

## 6 · Lock file

### 6.1 · Path and shape

`/var/lib/sandbox/.update.lock`. Mode **`0664 sandbox:sandbox`**. Created
on first `sandbox update` invocation; deleted at successful completion
(§ 3.2.30). The path is **persistent** (under `/var/lib/`, not `/run/`)
because it must survive a system reboot mid-update so re-runs can
detect and adopt.

**Mode rationale:** `0664` (`rw-rw-r--`) allows any operator in the
`sandbox` group (Spec 3 § 3.2 — all operators that can reach the daemon
socket are in the `sandbox` group) to open the file with
`O_RDWR|O_CREAT`. This lets the acquisition shell pseudo-code use a
direct `exec {fd}<>"$lockfile"` without `sudo`, which in turn keeps the
flock on an FD the running process owns — no long-lived helper child or
subprocess is required. The file owner is `sandbox:sandbox` so a fresh
create sets the right owner automatically (file is created in
`/var/lib/sandbox/` which is `0750 sandbox:sandbox`; only
`sandbox:sandbox` processes or root can create files there without a
prior `sudo`; the first write under `sudo -k` sets ownership correctly).
Operators outside the `sandbox` group cannot run `sandbox update` in a
meaningful way (the daemon socket is `0660 sandbox:sandbox`), so the
relaxed mode does not expand the privilege surface.

Lock-file payload (JSON):

```json
{
  "pid":            22345,
  "started_at":     "2026-05-11T14:23:11Z",
  "target_version": "1.1.0",
  "from_version":   "1.0.0",
  "was_running":    true
}
```

`was_running` is the sticky flag described in § 6.4.

### 6.2 · Acquisition

Mode `0664 sandbox:sandbox` means operator-level open succeeds.
Acquisition uses the `flock(1)` utility (available everywhere on Linux
via `util-linux`) for the kernel advisory lock, and `sudo -k` only for
the payload write (which must be done as root since the file was created
with `O_CREAT` under sudo on fresh acquisition, and the group-write
permission means the operator can take the lock but the payload write
targets a directory that requires root to write in).

#### 6.2.1 · Shell pseudo-code

```sh
lockfile=/var/lib/sandbox/.update.lock

# Step 1: Ensure the lock file exists at mode 0664 before the exec+flock.
#         `install -m 0664` creates the file atomically at the target mode
#         in a single syscall, avoiding the EACCES window that a two-step
#         `touch`+`chmod` would create (between the `touch` at mode 0600
#         and the subsequent `chmod 0664`, a racing operator's
#         `exec {fd}<>` would fail with EACCES). If the file already
#         exists, `install` overwrites it — this is safe here because the
#         old payload is read *after* we hold the flock (step 3 below).
if [ ! -f "$lockfile" ]; then
    sudo -k -u sandbox install -m 0664 /dev/null "$lockfile"
fi

# Step 2: Try non-blocking exclusive flock. The flock FD stays open
#         for the lifetime of the shell process (held via exec trick).
exec {lock_fd}<>"$lockfile"
if ! flock -n -x "$lock_fd"; then
    # EWOULDBLOCK — another process holds the lock. Inspect payload.
    held_pid=$(jq -r '.pid // 0' "$lockfile" 2>/dev/null || echo 0)
    if [ "$held_pid" -gt 0 ] && kill -0 "$held_pid" 2>/dev/null; then
        die "another sandbox update is in progress (pid $held_pid); wait for it to finish."
    else
        # PID is dead. The kernel released its flock; our non-blocking
        # attempt just failed because we lost the race against another
        # adopting process. Retry once with a short wait. In the common
        # single-user case there is no race; the retry loop is purely
        # defensive.
        sleep 1
        if ! flock -n -x "$lock_fd"; then
            die "lock busy after retry; another adoption is in progress."
        fi
        log_warn "step=acquire_lock adopted_from_dead_pid=$held_pid action=adopt"
        ADOPT=1
    fi
fi

# Step 3: We hold the lock. Decide: fresh acquisition or dead-PID adoption.
#         Ordering is binding: flock is held BEFORE reading or writing
#         the payload — no racing reader or writer can observe a
#         partial/stale payload under the held flock.
existing=$(cat "$lockfile" 2>/dev/null || echo "")
prior_was_running=$(echo "$existing" | jq -r '.was_running // null' 2>/dev/null)
prior_started_at=$(echo  "$existing" | jq -r '.started_at  // ""'   2>/dev/null)
stale_hours=0
if [ -n "$prior_started_at" ]; then
    prior_epoch=$(date -d "$prior_started_at" +%s 2>/dev/null || echo 0)
    stale_hours=$(( ($(date +%s) - prior_epoch) / 3600 ))
fi

if [ -z "$prior_was_running" ] || [ -z "${ADOPT:-}" ]; then
    # Fresh acquisition. Sample daemon state NOW — this is the one
    # point where was_running is determined; every re-run inherits it.
    WAS_RUNNING=$(systemctl is-active sandboxd >/dev/null 2>&1 && echo true || echo false)
    ACTION=acquire
elif [ "$stale_hours" -gt 24 ]; then
    WAS_RUNNING=${prior_was_running}
    ACTION="adopt-stale"
    log_warn "step=acquire_lock stale_hours=$stale_hours action=adopt-stale"
else
    # Normal dead-PID adoption. Preserve prior was_running.
    WAS_RUNNING=${prior_was_running}
    ACTION=adopt
fi

# Step 4: Write new payload under the held lock.
#         sudo is needed here because /var/lib/sandbox/ is 0750 and
#         writing to the existing 0664 file is allowed by group perm,
#         but using sudo -u sandbox ensures the owner stays correct.
sudo -k -u sandbox tee "$lockfile" >/dev/null <<EOF
{
  "pid":            $$,
  "started_at":     "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "target_version": "$TARGET_VERSION",
  "from_version":   "$CURRENT_VERSION",
  "was_running":    $WAS_RUNNING
}
EOF

log_ok "step=acquire_lock pid=$$ was_running=$WAS_RUNNING action=$ACTION"
```

#### 6.2.2 · Ordering rule: flock before payload read/write

The binding rule: **flock first, then read-and-write the payload**. This
prevents two simultaneously-racing `sandbox update` processes from both
reading the prior payload before either holds the lock.

Under the held flock:

- **Read:** the payload reflects the last completed write (either the
  previous run's final state, or empty on first creation).
- **Write:** `tee` writes atomically from the shell's perspective (the
  flock serialises it); any other process attempting to acquire will
  block until we release.

A racing `sandbox update` that hits `flock -n -x` while we hold it gets
`EWOULDBLOCK` immediately (step 2 above). It reads the payload **without
the flock** (since we hold the exclusive lock), which means it may see
a partial in-progress write. The code tolerates this: `jq` parse failure
returns `held_pid=0`, and `kill -0 0` always fails, triggering the
"PID dead" branch which retries via `sleep 1` + second flock attempt.
At that point our write is complete and the retry sees a full payload
with the current PID (alive), so it correctly refuses.

#### 6.2.3 · Lock acquisition outcomes

| State                                          | Outcome                                                                                     |
|------------------------------------------------|---------------------------------------------------------------------------------------------|
| File absent → create (sudo) + acquire flock   | Fresh acquisition. Sample `systemctl is-active`; write payload. Continue.                   |
| File present, flock held by live PID           | `EWOULDBLOCK`; read payload; PID alive → refuse with "another update in progress (pid X)".  |
| File present, flock released (process dead)    | `EWOULDBLOCK` then retry; flock acquired on second attempt; dead PID confirmed → adopt with sticky `was_running`. |
| File present with `started_at > 24h old`       | Adopt with additional `step=acquire_lock action=adopt-stale` log line.                      |

### 6.3 · Release

On successful completion of § 3.2.29, § 3.2.30 removes the lock file
and closes the FD (which also releases the kernel flock):

```sh
# § 3.2.30: Release.
sudo -k rm -f "$lockfile"
exec {lock_fd}>&-     # close the FD → kernel releases the flock
```

If `sandbox update` exits non-zero before § 3.2.30, the process ends
and the shell closes all open FDs — the kernel releases the flock
automatically when `lock_fd` closes on exit. The JSON payload file
**remains on disk** (the `rm` at § 3.2.30 didn't run). A re-run will
`flock -n -x` successfully (the prior process's flock is gone), read
the stale payload, see the dead PID, and adopt with the sticky
`was_running`.

This "file remains, flock released" property is the whole point of the
dead-PID adoption branch: the payload is the durable state across process
restarts; the flock is the live-process-only mutex.

**Rollback recipe note (§ 7.2 step 8):** after invoking the rollback,
remove the stale lock file manually:

```sh
sudo rm -f /var/lib/sandbox/.update.lock
```

This prevents future `sandbox update` runs from adopting a stale payload
that reflects the abandoned update's versions.

### 6.4 · The sticky `was_running` flag

This is the only piece of state the system cannot infer between re-runs.
After § 3.2.14 (stop daemon), `systemctl is-active sandboxd` returns
`inactive`. A fresh re-run that re-evaluates `is-active` would see
`inactive` and conclude `was_running=false`, then skip § 3.2.26
(re-start) — even though the operator's intent was "it was running before
the upgrade, start it back when done."

Solution: the flag is captured **once**, at the initial lock acquisition
(§ 6.2.1 step 3). Every subsequent re-run that adopts the lock reads the
payload's `was_running` and carries it forward unchanged.

Lifecycle:

1. **Fresh acquisition:** evaluate `systemctl is-active sandboxd`; write
   as `was_running` in the JSON payload.
2. **Dead-PID adoption:** read prior payload's `was_running`; do **not**
   re-evaluate `is-active`. The sticky flag is the one from step 1.
3. **Use in §§ 3.2.14 / 3.2.26:** stop daemon only if `was_running`;
   start daemon only if `was_running`.
4. **Release at § 3.2.30:** `rm` the file; sticky flag discarded.
5. **Next fresh run:** evaluates `is-active` again from current state.

The `--check` and `--dry-run` modes do **not** acquire the lock or write
`was_running` — they are read-only and use a transient `is-active` call
for display purposes only.

## 7 · Documented rollback recipe

Rollback is a **manual** operation in v1. No `sandbox rollback`
subcommand. The handoff is explicit (§ 7.4 below) that automated
rollback is footguns territory — DB schema downgrade is non-trivial,
each rollback scenario has subtleties that an automation would have to
encode, and the documented recipe is enough until demand emerges.

### 7.1 · What's reversible

| Artefact                                       | Reversibility                                                                          |
|------------------------------------------------|----------------------------------------------------------------------------------------|
| Daemon binary (`/usr/local/bin/sandboxd`)      | Direct restore from `sandboxd.bak`.                                                    |
| CLI binary (`/usr/local/bin/sandbox`)          | Direct restore from `sandbox.bak`.                                                     |
| Route-helper binary                            | Direct restore from `sandbox-route-helper.bak` + re-setcap.                            |
| Gateway image                                  | Old image tag **may** survive if the operator hasn't run `docker image prune` since the upgrade. The daemon does **not** rebuild the gateway image (Spec 3 § 8.5 — gateway is shipped pre-built per release, not built on demand), and Spec 3 § 8.6 actively encourages operators to prune old tags. If the prior tag (`sandbox-gateway:<previous-version>`) is **absent**, rollback requires re-loading from the prior release tarball (operator's responsibility — keep prior tarballs locally, or re-download from GH Releases). The recipe at § 7.2 includes an explicit `docker image inspect` step that gates whether re-load is required. |
| `/etc/sandboxd/users.conf`                     | Direct restore from `users.conf.bak`. The config migration framework is forward-only at the framework level, but the file's pre-update bytes are preserved bit-for-bit in the backup. |
| `/etc/qemu/bridge.conf`                        | Direct restore from `bridge.conf.bak`.                                                  |
| `sessions.db`                                  | Direct restore from `sessions.db.bak`. Refinery DB migrations are forward-only, so restoring the prior daemon binary and an upgraded sessions.db would refuse to start (Spec 5 inherits Spec 2 § 6.1's "DB ahead of binary" failure mode). Restoring both as a unit is the contract. |
| systemd unit                                   | The new unit may differ from the old; the backup set does not snapshot the prior unit file. Operators wanting unit rollback hand-edit (or use `git log` on `/etc/systemd/system/sandboxd.service` if the operator manages `/etc` under version control). § 7.3 documents this caveat. |
| Operator drop-ins under `…service.d/`           | Untouched by the upgrade; nothing to roll back.                                          |
| Operator group memberships                     | Untouched by the upgrade; nothing to roll back.                                          |

The contract: the backup set captures everything `sandbox update`
touched. Anything it left alone (drop-ins, group memberships, system
user, image tags) survives the rollback by virtue of never having
been changed.

### 7.2 · The recipe

A copy-pasteable shell sequence. The operator runs this manually — no
automation. The recipe assumes the operator has identified the
specific backup set they want to restore; the default-most-recent
selector via `ls -td … | head -1` is given but should be reviewed.

```sh
# 1. Identify the backup set to restore. Default: most-recent successful set.
BACKUP_DIR=$(sudo -u sandbox ls -td /var/lib/sandbox/backups/*/ \
               | xargs -I{} sudo -u sandbox sh -c \
                   'test "$(jq -r .completed_ok < "{}/manifest.json")" = "true" && echo "{}"' \
               | head -1)
echo "Rolling back from backup: $BACKUP_DIR"
sudo -u sandbox cat "$BACKUP_DIR/manifest.json"

# 2. Verify the prior gateway image is still present. If pruned, re-load it
#    from the prior release tarball BEFORE starting the rolled-back daemon
#    (Spec 3 § 8.5 — the daemon refuses to start without its versioned gateway image).
PREV_VERSION=$(sudo -u sandbox jq -r '.from_version' "$BACKUP_DIR/manifest.json")
if ! docker image inspect "sandbox-gateway:${PREV_VERSION}" >/dev/null 2>&1; then
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
sudo install -m 0755 -o root -g root "$BACKUP_DIR/sandboxd.bak"             /usr/local/bin/sandboxd
sudo install -m 0755 -o root -g root "$BACKUP_DIR/sandbox.bak"              /usr/local/bin/sandbox
sudo install -m 0755 -o root -g root "$BACKUP_DIR/sandbox-route-helper.bak" /usr/local/libexec/sandboxd/sandbox-route-helper

# 5. Re-apply route-helper file caps.
sudo setcap cap_net_admin,cap_sys_admin=eip /usr/local/libexec/sandboxd/sandbox-route-helper

# 6. Restore /etc files. bridge.conf is mode 0644 per Spec 4 § 4.4.18 / Makefile:355.
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
sudo install -m 0600 -o sandbox -g sandbox "$BACKUP_DIR/sessions.db.bak" /var/lib/sandbox/sessions.db
if [ -f "$BACKUP_DIR/sessions.db-wal.bak" ]; then
    sudo install -m 0600 -o sandbox -g sandbox "$BACKUP_DIR/sessions.db-wal.bak" /var/lib/sandbox/sessions.db-wal
else
    sudo rm -f /var/lib/sandbox/sessions.db-wal
fi
if [ -f "$BACKUP_DIR/sessions.db-shm.bak" ]; then
    sudo install -m 0600 -o sandbox -g sandbox "$BACKUP_DIR/sessions.db-shm.bak" /var/lib/sandbox/sessions.db-shm
else
    sudo rm -f /var/lib/sandbox/sessions.db-shm
fi

# 8. Remove the stale lock file (if present from a failed update). The lock survives
#    until § 3.2.30; if the upgrade exited before then, the lock remains.
sudo rm -f /var/lib/sandbox/.update.lock

# 9. Start the daemon.
sudo systemctl start sandboxd

# 10. Verify.
sandbox doctor
```

The recipe is verbatim copy-pasteable; operators reading the doctor
output afterward can confirm the rollback succeeded (every check
passes, `/version` reports the previous version, sessions in the
restored DB are visible).

### 7.3 · Caveats to document

- **DB schema downgrade is implicit.** Restoring `sessions.db.bak`
  restores the *pre-update schema and data* together. The restored
  daemon binary matches that schema (it's the same binary that wrote
  it originally). The two restore as a unit. If the operator restores
  only the binary without the DB (or vice versa), refinery's schema
  check on the old daemon will refuse to open an upgraded DB (Spec 2
  § 6.1 documents this failure mode), and the operator sees a clear
  daemon-start error.

- **No partial rollback.** The recipe restores everything in the
  backup set as a unit. There is no supported workflow for "roll
  back the binary only" or "roll back the config file only" — both
  are footguns where the daemon's invariants no longer hold.

- **systemd unit not snapshotted.** The backup set captures binaries +
  `/etc` files + sessions.db, not the prior `/etc/systemd/system/sandboxd.service`.
  If the new release shipped a different unit and the operator wants
  to roll back the unit too, they hand-edit or use `git`. In practice
  the unit shape is fixed at Spec 3 § 4.1 and changes rarely; we
  accept the caveat rather than expanding the backup set with one more
  artefact that's rarely needed.

- **Lock file cleanup is the operator's job.** After rollback the
  operator must `rm /var/lib/sandbox/.update.lock` so future
  `sandbox update` runs can acquire it. The recipe (§ 7.2 step 8)
  includes this.

- **Gateway image absence requires manual reload.** § 7.2 step 2 gates
  the rest of the recipe on `docker image inspect
  sandbox-gateway:<prev>` succeeding. If the operator has run
  `docker image prune` since the upgrade (Spec 3 § 8.6 encourages
  this) and no longer has the prior release tarball locally, they
  must re-fetch it from GH Releases before continuing. The recipe
  short-circuits with a clear `docker load` hint pointing at the GH
  Releases tag URL.

- **Operator group memberships unaffected.** Rollback does not revoke
  group memberships granted during install (or during prior upgrades —
  upgrades don't add or remove members). The `sandbox` group is
  stable across the rollback.

### 7.4 · Why not automated?

The brainstorm reached this conclusion explicitly:

- **DB schema downgrade is non-trivial.** Refinery's migrations are
  forward-only; a `sandbox rollback` would have to either (a) restore
  the prior `sessions.db.bak` (already in the recipe) or (b) generate
  reverse SQL on the fly. Option (b) requires migration authors to
  write `up.sql` + `down.sql` pairs and validate the round-trip; the
  developer cost is significant and the rare-event benefit doesn't
  justify it in v1.
- **Backup-set selection is operator judgment.** "Roll back to the
  most recent successful set" is the obvious default, but operators
  triaging a corrupted install might want a specific older set. A
  flag-driven automation would have to enumerate sets, present a UX
  for selection, and validate the operator's choice. The documented
  recipe gives operators the same primitives without committing the
  project to a UX choice.
- **Concurrent-update guard.** A `sandbox rollback` would need its
  own lock-file semantics; today's lock at `/var/lib/sandbox/.update.lock`
  guards updates, and a rollback while an update is in progress (or
  vice versa) is a footgun. Extending the mutex to cover both is
  doable but adds surface area.

Future work: if demand emerges, a `sandbox rollback` subcommand could
add automation. The handoff is explicit (§ 12 — out of scope) that
this is **not** in v1.

## 8 · `sandbox rebuild-image` subcommand

Manual entry point for the deferred auto-rebuild feature
([GitHub issue #7](https://github.com/Koriit/sandboxd/issues/7)).

### 8.1 · Surface

```
sandbox rebuild-image --backend container   # rebuild the lite (container) image
sandbox rebuild-image --backend lima        # rebuild the Lima golden VM image
sandbox rebuild-image --backend all         # rebuild both (default when no flag given)
sandbox rebuild-image --backend gateway     # refused — gateway is pre-built per release
sandbox rebuild-image --no-cache --backend container  # force a cache-busting rebuild
```

Spec 5 **does not introduce a positional variant**. The existing
`--backend container|lima|all` flag (already at `sandbox-cli/src/main.rs:349`
via `RebuildImageBackend`) is the complete CLI surface for valid backends.
A positional `lite|gateway` was considered and rejected:

- `lite` vs `container` is an unnecessary alias for users who already
  learned `--backend container`; adding it creates two spellings for the
  same thing.
- `gateway` as a positional would introduce a clap variant that exists
  only to error, which is confusing in `--help` output.
- Adding a `lima` positional on top risks the variant token colliding
  with `--backend lima` on older `clap` behaviour.

Instead, Spec 5 adds a single refused dispatch arm for the (currently
non-existent) `--backend gateway` flag to the existing `RebuildImageBackend`
enum, and documents `gateway` as a client-side refused option so operators
who try it get a clear error message pointing at `sandbox update`.

Extended `RebuildImageBackend` (adds `Gateway` variant):

```rust
// sandbox-cli/src/backend.rs — adds one variant to the existing enum.

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
#[clap(rename_all = "lowercase")]
pub enum RebuildImageBackend {
    Lima,
    Container,
    All,
    /// Gateway image: refused. The gateway image is shipped pre-built
    /// per release and loaded by `sandbox update`. Building it locally
    /// requires the full source tree + Docker + network access to
    /// upstream registries.
    Gateway,
}
```

Dispatch arm added to `dispatch_rebuild_image`
(`sandbox-cli/src/main.rs:4003`):

```rust
match backend {
    RebuildImageBackend::Gateway => {
        eprintln!(
            "sandbox: --backend gateway is not supported for rebuild-image.\n  \
             The gateway image is shipped pre-built per release and loaded by \
             `sandbox update`.\n  To refresh the gateway image, run: sudo sandbox update"
        );
        process::exit(2);
    }
    // ... existing Lima / Container / All arms unchanged ...
}
```

### 8.2 · Implementation

The `--backend container` and `--backend lima` paths are thin CLI wrappers
around the daemon's existing `POST /rebuild-image` endpoint at
`sandboxd/sandboxd/src/main.rs:5265-5317`. The endpoint's request body
shape is `{"backend": "lima"|"container", "no_cache": bool}` — the CLI
translates the `RebuildImageBackend` flag directly into that body.
**No daemon-side change is required** for `container` or `lima`: the
existing endpoint already handles them.

The `--backend gateway` refusal happens **client-side** in the CLI — the
daemon never receives a "rebuild gateway" request because the dispatch arm
for `RebuildImageBackend::Gateway` (§ 8.1) exits non-zero before any HTTP
call. This keeps the daemon's surface unchanged.

### 8.3 · Operator scheduling (informational)

For operators who want periodic rebuilds of the lite image before the
auto-rebuild feature (#7) lands, document the systemd timer pattern.
Spec 5 does **not** ship this timer; it's operator self-service.

```ini
# /etc/systemd/system/sandbox-rebuild-lite.timer
[Unit]
Description=Periodically rebuild the sandbox lite image

[Timer]
OnCalendar=weekly
Persistent=true

[Install]
WantedBy=timers.target
```

```ini
# /etc/systemd/system/sandbox-rebuild-lite.service
[Unit]
Description=Rebuild the sandbox lite image
After=sandboxd.service
Requires=sandboxd.service

[Service]
Type=oneshot
ExecStart=/usr/local/bin/sandbox rebuild-image --backend container
User=<operator>
Environment=SANDBOX_SOCKET=/run/sandbox/sandboxd.sock
```

Operator enables with `sudo systemctl enable --now
sandbox-rebuild-lite.timer`. The `User=<operator>` ensures the rebuild
runs under an operator's identity (the daemon's session-isolation
filter from Spec 2 doesn't gate `/rebuild-image`, but the daemon-side
audit log records the operator anyway).

## 9 · Test plan

Hermetic by default per CLAUDE.md § "Integration-test convention".
Tests requiring out-of-process state (real Lima, real Docker, real
systemd) are `integration_*`-prefixed and selected by the
`integration` nextest profile.

### 9.1 · Lima E2E (extends Spec 4 § 6)

These tests extend the Lima-based install/uninstall harness from
Spec 4 § 6.4, adding `sandbox update` scenarios. Each test starts from
a `template://ubuntu-22.04` VM, drives install.sh to a known starting
version, then exercises an update flow.

| Test                                                                 | Behavior |
|----------------------------------------------------------------------|----------|
| `test_update_fresh_install_to_next_version`                          | Install v1.0.0; build v1.1.0 tarball locally; run `sudo sandbox update --from <v1.1.0.tar.gz> --yes`; verify daemon at v1.1.0, sessions.db intact, doctor green. |
| `test_update_interrupted_then_resumed`                              | Install v1.0.0; start `sandbox update --from <v1.1.0> --yes`; kill the process at § 3.2.20 (mid-binary-install); re-run; verify the second run converges to v1.1.0 with mostly `action=skip` log lines. |
| `test_update_then_manual_rollback`                                   | Install v1.0.0; update to v1.1.0; run the rollback recipe verbatim from § 7.2; verify daemon at v1.0.0, sessions.db at pre-update state. |
| `test_update_air_gapped`                                             | Install v1.0.0; disable network egress; run `sudo sandbox update --from <local-tarball> --cosign-bundle <local-bundle> --yes`; verify success without any outbound network. |
| `test_update_check_does_not_mutate`                                  | Install v1.0.0; stage v1.1.0 tarball; run `sandbox update --check --from <v1.1.0>`; assert no state mutated (lock file absent, install state unchanged, daemon still v1.0.0). |
| `test_update_concurrent_refused`                                     | Install v1.0.0; start `sandbox update` in background; immediately run a second `sandbox update`; verify the second invocation refuses with `another update is in progress`. |
| `test_update_preserves_customized_users_conf`                        | Install v1.0.0 (writes `users.conf` with V001 content); operator adds a custom subnet via direct edit; update to v1.1.0; verify the custom subnet survives in the post-update `users.conf`. |
| `test_update_preserves_systemd_drop_in`                              | Install v1.0.0; operator drops in `/etc/systemd/system/sandboxd.service.d/override.conf`; update to v1.1.0; verify the drop-in is bit-for-bit unchanged. |
| `test_update_with_recreate_session_classification`                   | Install v1.0.0; create one session (stamps `guest_protocol_version=1`); build a hypothetical v1.1.0 tarball with `DAEMON_GUEST_PROTO_VERSION=2` and `can_refresh_in_place(1) == false`; run `sandbox update --dry-run --from <tarball>`; assert the dry-run plan lists the session as `recreate` (uses target binary's `can_refresh_in_place`); assert `--check` output shows "Stopped sessions: 1" without per-session classification; then apply and assert the session's `start_session` returns 409 with the recreate message (Spec 2 § 3.5). |
| `test_update_rejects_dev_install`                                    | On a dev-mode VM (no systemd unit installed, `~/.local/share/sandboxd/` populated), run `sandbox update`; verify refusal with the dev-mode message (§ 11). |
| `test_update_backup_retention_prunes_oldest`                         | Install v1.0.0; update v1.0.0 → v1.1.0; update v1.1.0 → v1.2.0; update v1.2.0 → v1.3.0; verify exactly 2 successful backup sets remain (v1.1.0→v1.2.0 and v1.2.0→v1.3.0); the v1.0.0→v1.1.0 set is pruned. |
| `test_update_partial_failure_backup_set_preserved`                   | Install v1.0.0; inject a failure at § 3.2.24 (migration apply); verify the backup set's `manifest.json` has `completed_ok: false` and is **not** pruned on a subsequent successful update. |

### 9.2 · Unit tests (hermetic)

Live under `sandbox-cli/src/cfg_migrations/` and `sandbox-core/src/users_conf.rs`.

| Test                                                              | Where                                                  | Behavior |
|-------------------------------------------------------------------|--------------------------------------------------------|----------|
| `migration_v001_round_trip`                                       | `sandbox-cli/src/cfg_migrations/v001_*.rs`             | Table-driven: input → expected output for Spec 1 § 5.5 inputs A/B/C/D, plus a pre-V001 file with operator-added subnet (verifies preservation). |
| `migration_v001_idempotent_when_already_applied`                  | same                                                   | Apply V001 to a file at `_schema_version: 1`; assert output == input (bit-for-bit). |
| `read_schema_version_users_conf_default_zero`                     | `sandbox-cli/src/cfg_migrations/version.rs`            | File without `_schema_version` key → returns `0`. |
| `read_schema_version_users_conf_reads_present`                    | same                                                   | File with `{"_schema_version": 3, ...}` → returns `3`. |
| `read_schema_version_users_conf_refuses_invalid_json`             | same                                                   | File with malformed JSON → returns `MigrationError::Parse`. |
| `read_schema_version_bridge_conf_default_zero`                    | same                                                   | File without `# sandbox-schema-version:` header → returns `0`. |
| `read_schema_version_bridge_conf_reads_present`                   | same                                                   | File with `# sandbox-schema-version: 2\n...` → returns `2`. |
| `apply_pending_walks_chain`                                       | `sandbox-cli/src/cfg_migrations/mod.rs`                | Synthetic registry with V001 (0→1) and V002 (1→2); seed a tempfile at V0; run `apply_pending`; assert applied = `[1, 2]` and final version = 2. |
| `apply_pending_skips_already_at_target`                           | same                                                   | Seed a tempfile at V2; run; assert applied = `[]`. |
| `apply_pending_atomic_write_visible_only_after_complete`          | same                                                   | Inject a filesystem fault between `write_all` and `persist`; assert the file at `path` is still the pre-write content (NamedTempFile's rename-or-nothing). |
| `registry_migrations_advance_exactly_one_version`                 | `sandbox-cli/src/cfg_migrations/mod.rs`                | Iterate the static registry; for every migration assert `m.to_version() == m.from_version() + 1`. Pins the binding selection rule in § 4.2 — a future contributor adding a multi-version-skip migration trips the test at compile-time-adjacent (unit-test) granularity. |
| `apply_config_migration_refuses_non_root_caller`                  | `sandbox-cli/src/main.rs` (subcommand gate)            | Invoke `sandbox --apply-config-migration` with `getuid() != 0` (test runs as the test user); assert refusal with substring `requires root` and exit non-zero. |
| `apply_config_migration_refuses_non_canonical_file`               | same                                                   | Invoke with `--file /tmp/fake.json`; assert refusal with substring `canonical paths`. |
| `apply_config_migration_refuses_arbitrary_out_path`               | same                                                   | Invoke with `--file /etc/sandboxd/users.conf --out /tmp/whatever`; assert refusal with substring `tempfile under the same directory as --file`. |
| `apply_config_migration_refuses_unknown_migration_id`             | same                                                   | Invoke with `--migration V999`; assert refusal with substring `not found in registry`. |
| `validate_users_conf_schema_version_accepts_supported`            | `sandbox-core/src/users_conf.rs`                       | `UsersConfig { schema_version: Some(1), .. }` → `Ok(())` (when `DAEMON_MAX_SUPPORTED_USERS_CONF_SCHEMA == 1`). |
| `validate_users_conf_schema_version_rejects_too_new`              | same                                                   | `schema_version: Some(3)` (with max 1) → `Err(SchemaTooNew { file_version: 3, daemon_max: 1, .. })`; assert hint substring `Run \`sandbox update\``. |
| `validate_users_conf_schema_version_rejects_too_old`              | same                                                   | `schema_version: Some(0)` (with min 1) → `Err(SchemaTooOld { .. })`; assert hint substring `Run \`sandbox update\``. |
| `validate_users_conf_schema_version_treats_absent_as_zero`        | same                                                   | `schema_version: None` → treated as 0 → SchemaTooOld if min > 0. |
| `lock_file_acquisition_refuses_on_live_holder`                    | `sandbox-cli/src/update/lock.rs`                       | Pre-acquire `LOCK_EX` on a tempfile in the test process (the FD stays open); run the acquisition logic in a thread; assert it returns the "another update is in progress" error. |
| `lock_file_acquisition_adopts_on_dead_pid_payload`                | same                                                   | Pre-write a lock file with a payload claiming PID `999999` (non-existent); run acquisition; assert the adopt branch runs, returned `was_running` matches the pre-written payload. |
| `lock_file_acquisition_preserves_was_running_across_adopt`        | same                                                   | Pre-write lock with `was_running: true` and dead PID; adopt; assert `was_running == true` regardless of current `systemctl is-active` output. |
| `lock_file_flock_acquired_before_payload_write`                   | same                                                   | Instrument the acquire logic with a tracing hook; assert the flock is held before the payload `write` call (pins the ordering rule in § 6.2.2). |
| `lock_file_released_on_process_exit`                              | same                                                   | Acquire lock in a subprocess; kill the subprocess; assert the FD-based flock is automatically released and a second acquisition succeeds immediately. |
| `version_lifecycle_check_then_dry_run_then_apply`                 | `sandbox-cli/src/update/mod.rs`                        | Synthetic update flow with mocked daemon `/version` endpoint; run `--check` then `--dry-run` then a real apply; assert each phase's output shape and that no privileged calls fire in `--check` or `--dry-run`. |
| `rebuild_image_gateway_backend_refuses_with_pointer_to_update`    | `sandbox-cli/src/main.rs`                              | Invoke `sandbox rebuild-image --backend gateway`; assert stderr substring `sandbox update`; assert exit code 2; assert no HTTP request was sent. |
| `rebuild_image_container_backend_sends_correct_body`              | `sandbox-cli/src/main.rs`                              | Invoke `sandbox rebuild-image --backend container` against a mock daemon; assert HTTP body is `{"backend":"container",...}`. |
| `rebuild_image_lima_backend_sends_correct_body`                   | `sandbox-cli/src/main.rs`                              | Invoke `sandbox rebuild-image --backend lima` against a mock daemon; assert HTTP body is `{"backend":"lima",...}`. |

### 9.3 · Integration tests (`integration_*` prefix)

Live under `sandboxd/sandbox-cli/tests/` (CLI-side integration with
real filesystem state) and `sandboxd/sandboxd/tests/` (daemon-side
integration with schema-mismatch refusal).

| Test                                                                  | Behavior |
|-----------------------------------------------------------------------|----------|
| `integration_config_migration_applies_v001_to_legacy_file`            | Stage a pre-V001 `users.conf` in a temp dir; run the framework's `apply_pending(UsersConf)` against it (via a test-only path-override for `TargetFile::canonical_path`); assert the file post-condition matches Spec 1 § 5.5 Output B. |
| `integration_update_flow_idempotent`                                  | Set up a stub install in a temp tree (binaries at `/tmp/.../bin/sandboxd` etc., synthetic install-state.json, synthetic users.conf); run a simulated `sandbox update` (with mocked sigstore + mocked daemon stop/start); re-run; assert second run's log lines are all `action=skip`. |
| `integration_daemon_refuses_start_on_schema_too_new`                  | Boot daemon with `users.conf` at `_schema_version: 99`; assert process exit non-zero, stderr substring `users.conf schema version 99 is newer than this binary supports`. |
| `integration_daemon_refuses_start_on_schema_too_old`                  | Boot daemon with `users.conf` at `_schema_version: 0` (or absent) and `DAEMON_MIN_SUPPORTED_USERS_CONF_SCHEMA == 1`; assert refusal with `older than this binary supports`. |
| `integration_daemon_accepts_start_on_schema_at_max`                   | Boot daemon with `users.conf` at the supported schema version; assert process starts normally and serves /version. |

The Lima E2E tests in § 9.1 cover the end-to-end flow; the integration
tests here are focused on the pieces that don't need a full VM (the
framework apply loop, the daemon-side refusal logic, the lock file).

## 10 · Risks and open questions

### 10.1 · Lock file mode choice

The lock file is at `/var/lib/sandbox/.update.lock`, mode `0664
sandbox:sandbox`. Three modes were considered:

**`0600`** (originally proposed): operators in the `sandbox` group
cannot open it without `sudo`. Requires a root-level Rust helper subprocess
to hold the flock FD alive, which is a significant implementation burden
and difficult to test. Rejected.

**`0664`** (chosen): operators in the `sandbox` group can open it
directly (`O_RDWR|O_CREAT`), take the kernel flock via `flock(1)`,
and write the JSON payload (via `sudo -k -u sandbox tee` for correct
ownership). This allows straightforward shell-level acquisition with no
long-lived helper subprocess. The `sandbox` group is the *socket-access*
group (Spec 3 § 3.2), meaning all operators who can use `sandbox update`
at all already have group membership. The `0664` mode does not expand
the attack surface: the lock file contains only PID, timestamps, and
version strings — no secrets, no session data.

**`/var/run/sandbox/.update.lock`** (tmpfs): would lose the sticky
`was_running` flag across reboots mid-update. Rejected.

Status: **`0664 sandbox:sandbox`** under `/var/lib/sandbox/`. The only
`sudo` calls in the lock path are for the payload write (to keep
`sandbox:sandbox` ownership consistent) and the final `rm -f`.

### 10.2 · The systemd `StateDirectory=` interaction

Spec 3 § 4.1 configures the unit's `StateDirectory=sandbox`, which
systemd creates / chowns / chmods on every daemon start. The lock file
sits inside that directory; if systemd ever decides to **clean** the
state directory (e.g. via a future `StateDirectoryClean=` directive
that doesn't exist today), the lock could be removed mid-update.

Mitigation: the unit shipped at Spec 3 § 4.1 does not set
`StateDirectoryClean=` or `RuntimeDirectoryPreserve=no` to wipe
state. systemd's default is "preserve state directory contents
across unit start/stop". The lock file is safe as long as the unit
keeps that default.

If a future version of the unit ships a cleaner directive, that's a
breaking change for Spec 5's lock file. The check-list note: any spec
that changes the unit's `StateDirectory*` behavior must update Spec 5
to use a different lock-file location.

### 10.3 · Self-replacement: CLI swaps its own binary mid-flight

`sandbox update` runs the `sandbox` CLI; the same step (§ 3.2.20)
also installs a new `sandbox` binary at `/usr/local/bin/sandbox`. The
running `sandbox update` process — which is the very binary being
replaced — keeps running.

Linux file semantics handle this correctly: `install` (and the
`rename(2)` it uses underneath) updates the directory entry but does
not modify the inode of the running process. The kernel maintains
the open mapping to the old inode until the process exits; only then
is the inode reclaimable. The running process continues executing the
old binary's code; the new binary is on disk waiting to be exec'd by
the next invocation.

Status: **safe, no special handling needed**. A one-line confirmation
note in the spec; the test in § 9.1 (`test_update_fresh_install_to_next_version`)
covers it implicitly — the update completes and the next CLI
invocation runs the new binary.

### 10.4 · Daemon-side schema-mismatch refusal as the convergence anchor

The handoff specifies: schema-mismatch is a "refuse" (not "auto-apply
on startup"), so that update flows are explicit and re-runs converge
through the framework. Spec 5 § 4.7 reaffirms this:

- **File ahead of binary** (downgrade or interrupted upgrade) →
  daemon refuses with `SchemaTooNew`. Operator runs `sandbox update`
  forward (to a binary that supports the file's version) or restores
  from backup (§ 7.2).
- **File behind binary** (framework didn't run, or operator bumped
  binary manually) → daemon refuses with `SchemaTooOld`. Operator
  runs `sandbox update`, which walks the framework's apply chain and
  brings the file to a version the binary supports.

This avoids two failure modes that "auto-apply on startup" would
introduce:

- **Silent misinterpretation.** A daemon that auto-migrates would
  rewrite operator config without the audit trail Spec 5 provides
  (the migration framework's log lines, the backup set).
- **Concurrent-update races.** Auto-apply on startup races with
  `sandbox update`'s framework apply (which also runs while the
  daemon is stopped). One agent would race the other.

Refuse-and-redirect-to-`sandbox update` is the consistent
single-entry-point model.

### 10.5 · DB migrations and config migrations evolve independently

Refinery DB migrations live in `sandbox-core/migrations/`. Spec 5's
config migrations live in `sandbox-cli/src/cfg_migrations/`. Two
independent migration sets means two independent evolution trajectories:

- DB migrations run on **daemon startup** via refinery. The daemon
  refuses to start if a refinery migration fails.
- Config migrations run on **CLI invocation** of `sandbox update`
  (via the framework, in `--apply-config-migration` mode for the
  actual transform). The daemon never applies config migrations.

The two are loosely coupled: the daemon's `_schema_version` check
expects config to be at a specific version; the daemon's refinery
expects DB to be at a specific version (and runs migrations forward
to that version on every start). They are **independently
rollback-able** — Spec 5's backup set captures both pre-update DB and
pre-update config; the rollback recipe restores both.

Risk: a future bump that requires a coupling (e.g. a DB migration
that requires a specific config-file shape to apply) is **forbidden
by Spec 5's contract**. If such a coupling ever becomes necessary, the
spec needs revisiting — but the project's "config files are JSON,
schema-versioned independently" convention from CLAUDE.md already
discourages it.

### 10.6 · Skipping a major version (e.g., 1.0 → 3.0)

The framework handles this naturally. The apply loop (§ 4.3) walks the
chain from `current_version` to `target_version` step by step. An
operator skipping from 1.0 (users.conf at `_schema_version: 1`) to
3.0 (where the registry has V002 and V003) would have the framework
apply V002 (1→2) then V003 (2→3) in order, each atomic. The
intermediate version-2 file exists on disk only between the V002
rename and the V003 read; if the daemon were to start between them,
it would refuse with `SchemaTooNew` (because the binary is at v3 and
the file is at v2 — assuming `DAEMON_MIN_SUPPORTED_USERS_CONF_SCHEMA`
is bumped along with the binary's `MAX`). The daemon is stopped
during the apply loop (§ 3.2.14), so this scenario doesn't fire in
practice.

§ 9.1 should add `test_update_skipping_major_version` if a v3 release
ships during Spec 5's lifetime; for now (v1 → v2 future-bump path),
the existing tests cover the chain mechanism.

### 10.7 · Downgrade is not supported

`sandbox update --version 1.0.0` against a daemon at v1.1.0 is a
downgrade. Spec 5 § 12 lists this explicitly out of scope:
config-migration framework is forward-only; refinery DB migrations
are forward-only; rolling back through the framework would require
reverse migrations the spec does not design.

The supported recovery path from a bad upgrade is the **rollback
recipe** (§ 7.2), which restores from `.bak` files captured before the
upgrade. The recipe is operator-driven; the CLI does not enforce
"only-rollback-via-recipe", but `sandbox update --version <older>`
will fail at the migration dry-run step (no `down` migration in the
registry).

### 10.8 · Interaction with refinery DB migrations on failure

If refinery's V006+ migration (Spec 2 § 2.1's `DELETE FROM sessions`
or any future destructive migration) fails on the new daemon's first
start, the daemon refuses to start (Spec 2 § 7.1 documents this).
`sandbox doctor`'s C1 (Spec 3 § 6.2) reports it. The operator's
recovery is the rollback recipe (§ 7.2) — restore `sessions.db.bak`
and the prior daemon binary together. The lock file is still in place
(release wasn't reached); after rollback, step 7 of the recipe
removes it.

The integration test `integration_daemon_refuses_start_on_schema_too_new`
(§ 9.3) covers the schema-mismatch refusal mechanism; a more elaborate
test injecting a refinery failure (e.g. a corrupted seed DB) is
discretionary — the orchestration is simple enough that a unit test
on the post-start verify path (mocking `systemctl start` failure)
covers the same property without real refinery integration.

## 11 · Backward compatibility — dev mode

`sandbox update` is **not for dev installs**. Developers use `make` for
everything: `make build` rebuilds binaries, `make gateway-image`
rebuilds the gateway image, `make setup-dev-env` (one-time) lays down
the dev-mode `/etc` files. There is no system service, no
`/var/lib/sandbox/`, no install state file.

If `sandbox update` is invoked on a dev install, it refuses with a
clear message and exits without acquiring the lock.

Detection (§ 3.1.2):

```sh
is_dev_mode() {
    # System install requires:
    #   1. systemd unit at /etc/systemd/system/sandboxd.service
    #   2. install state file at /var/lib/sandbox/.install-state.json
    # If either is missing, this is a dev install (or a corrupted install).
    [ -f /etc/systemd/system/sandboxd.service ] || return 0
    [ -r /var/lib/sandbox/.install-state.json ]  || { sudo -k test -r /var/lib/sandbox/.install-state.json || return 0; }
    return 1
}
```

The presence of dev-mode state at `$XDG_DATA_HOME/sandboxd/` or
`~/.local/share/sandboxd/` is a *hint* but not the gate — an operator
may have both a system install and a stale dev tree. The gate is
"system service unit exists + install state file readable."

Refusal message:

```
sandbox update is for system installs only.

This host looks like a dev install:
  - no systemd unit at /etc/systemd/system/sandboxd.service
  - no install state file at /var/lib/sandbox/.install-state.json

Use `make` to upgrade in development:
  - `make build`              rebuilds binaries
  - `make gateway-image`      rebuilds the gateway image
  - `make setup-dev-env`      reapplies dev-mode /etc files

To switch from dev to system install, follow:
  https://Koriit.github.io/sandboxd/docs/migrate-dev-to-system
```

The migration URL is a forward note — the documentation page is
authored separately; Spec 5 commits to the refusal message including
the URL.

## 12 · Out of scope

The following are **not** in Spec 5:

- **Automated rollback (`sandbox rollback` subcommand).** v1 ships only
  the documented manual recipe in § 7.2. § 7.4 records the reasoning.
- **Automatic periodic rebuild of the lite image.** Deferred; tracked
  as [GitHub issue #7](https://github.com/Koriit/sandboxd/issues/7).
  `sandbox rebuild-image --backend container` is the manual entry point (§ 8).
- **CHANGELOG / release notes display during `sandbox update`.** A
  future enhancement could fetch GH Releases' auto-generated notes
  and show them at the confirmation prompt; not in v1. Spec 4 § 10.8
  also flags the absent CHANGELOG process; both specs agree on
  punting.
- **CLI-side telemetry / phone-home.** No-telemetry policy. The only
  outbound calls `sandbox update` makes are:
  - GitHub Releases API (release manifest fetch) — operator opt-out
    via `--from`.
  - GitHub Releases tarball CDN — operator opt-out via `--from`.
  - Sigstore Rekor (transparency log) for cosign verify — operator
    opt-out via `--cosign-bundle` (offline mode).
- **Cross-machine update orchestration.** sandboxd is per-host; if an
  operator manages a fleet, they orchestrate runs externally (Ansible,
  SSH-loop, etc.). The lock file is per-host.
- **`sandbox update --downgrade`.** § 10.7 documents the refusal.
  Operator uses the rollback recipe.
- **DB schema downgrade.** Refinery is forward-only by design;
  downgrade requires `down.sql` pairs the project doesn't write.
- **A `sandbox rollback` automated subcommand.** Same as the first
  bullet; called out separately because it's the most common
  follow-up question.
- **Modifying the gateway image build process.** Spec 4 § 3 ships the
  CI-built gateway image in the release tarball; Spec 5 loads it.
  Building it locally is dev-mode only (`make gateway-image`).
- **Pre-flight UX additions.** `--pre-flight` as a separate flag
  (e.g. "tell me what `update` would do, without prompting at the
  confirmation"): subsumed by `--check` + `--dry-run`.
- **Adding `down` migrations to the config framework.** The framework
  is forward-only. Reverse transforms would need design work the spec
  doesn't undertake.

## 13 · Implementation notes (light)

| Path                                                                         | Kind of change |
|------------------------------------------------------------------------------|----------------|
| `sandboxd/sandbox-cli/src/main.rs`                                           | New `Command::Update { ... }` variant (next to `Health` line 255, `Inspect` line 265, `RebuildImage` line 349, `Doctor` (Spec 3 § 6.5)). `Command::RebuildImage` gains a `--backend gateway` arm (refused with pointer to `sandbox update`) per § 8.1 — no positional added. Two new hidden subcommands gated by `getuid() == 0` (§ 4.3 / § 6.2): `Command::ApplyConfigMigration { file, migration, out }` (per-migration apply, path-validated); `Command::DumpMigrationSet` (refinery introspection from `--check`, read-only). Lock acquisition is handled by `sandbox-cli/src/update/lock.rs` (pure Rust, no new subcommand — uses shell-level `flock` via a helper function that the `sandbox update` orchestration calls). Dispatch wiring in `main()`. |
| `sandboxd/sandbox-cli/src/update/mod.rs`                                     | New module. Orchestration of the full update flow — pre-flight, lock, fetch, verify, extract, migrate-dry-run, confirm, stop, backup, install, setcap, migrate-apply, docker-load, start, verify, doctor, finalize, release-lock. |
| `sandboxd/sandbox-cli/src/update/lock.rs`                                    | New. Lock file acquisition / adoption / release; flock + sticky `was_running` handling. |
| `sandboxd/sandbox-cli/src/update/fetch.rs`                                   | New. Release tarball fetch (URL or local), cosign verify, MANIFEST parse + sha256 verify. |
| `sandboxd/sandbox-cli/src/update/backup.rs`                                  | New. Backup set creation, manifest writes, retention prune. |
| `sandboxd/sandbox-cli/src/update/migrate.rs`                                 | New. Wraps the `cfg_migrations` framework; handles temp-file paths under `/etc/sandboxd/` and `/etc/qemu/`, sudo rename, validation. |
| `sandboxd/sandbox-cli/src/cfg_migrations/mod.rs`                             | New. `ConfigMigration` trait, `TargetFile` enum, `MigrationError`, registry, `apply_pending`, `read_schema_version`, `atomic_write`. |
| `sandboxd/sandbox-cli/src/cfg_migrations/version.rs`                         | New (or inlined). `read_schema_version` per `TargetFile`. |
| `sandboxd/sandbox-cli/src/cfg_migrations/v001_add_sandbox_to_allow_users.rs` | New. Adapter `impl ConfigMigration` calling `sandbox_core::users_conf::migrate_v001` (Spec 1 § 5). |
| `sandboxd/sandbox-core/src/users_conf.rs`                                    | Edit. Add `UsersConfigError::SchemaTooNew { file_version, daemon_max, hint }` and `SchemaTooOld { .. }` variants; add `pub const DAEMON_MAX_SUPPORTED_USERS_CONF_SCHEMA: u32 = 1` and `DAEMON_MIN_SUPPORTED_USERS_CONF_SCHEMA: u32 = 1`; add `pub fn validate_users_conf_schema_version(&UsersConfig) -> Result<(), UsersConfigError>`. Spec 1 already adds the `schema_version: Option<u32>` field. |
| `sandboxd/sandbox-core/src/bridge_conf.rs`                                   | New (small). Header-comment schema version reader (`read_bridge_conf_schema_version`) + validator + constants `DAEMON_MAX_SUPPORTED_BRIDGE_CONF_SCHEMA: u32 = 0`. v1 ships as no-op (no migrations land against bridge.conf). |
| `sandboxd/sandboxd/src/main.rs`                                              | Edit. Right after `load_users_config()` (line 6156), call `validate_users_conf_schema_version(&users_config)`; emit clear stderr and exit non-zero on `Err`. Add a parallel `bridge.conf` check (call `bridge_conf::validate_schema_version()` against a path read by the daemon directly — the daemon doesn't otherwise parse bridge.conf, so this is a small new read). |
| `sandboxd/sandbox-core/src/error.rs`                                         | Edit. Map `UsersConfigError::SchemaTooNew` / `SchemaTooOld` into `SandboxError` and through to clear stderr `Display`. |
| `scripts/sandbox-update.sh` (or inline in CLI)                               | Indicative. The CLI is the canonical entry point; a thin shell wrapper isn't required — clap-driven Rust binary handles arg parse and dispatch. Privileged commands (`sudo -k systemctl stop`, `sudo -k install`, `sudo -k mv`, etc.) are invoked from the Rust code via `std::process::Command`. |
| `sandboxd/sandbox-cli/tests/integration_config_migration_*.rs`               | New per § 9.3. |
| `sandboxd/sandboxd/tests/integration_users_conf_schema_*.rs`                 | New per § 9.3. |
| `tests/install-e2e/test_update_*.py`                                         | New per § 9.1 — extends Spec 4 § 6.4's harness. |
| `docs/start/installation.md`                                                 | Edit. Add brief paragraph: "To upgrade, run `sudo sandbox update`. See `sandbox update --help` for the full flag list." |
| `docs/operate/update.md`                                                     | New. Operator-facing documentation: the upgrade flow narrative, the rollback recipe (links to § 7.2), the backup layout (§ 5.1), the `--check` / `--dry-run` usage. Spec 5 commits to creating this page; full content is operator-doc work. |

The new CLI subcommands are wired into `sandbox-cli/src/main.rs`'s
existing `Command` enum and dispatch table; no new top-level binaries
are introduced.

## 14 · Affected files — summary

| Path                                                                          | Touch type |
|-------------------------------------------------------------------------------|------------|
| `sandboxd/sandbox-cli/src/main.rs`                                            | Edit: `Update` variant; `RebuildImage` gains `--backend gateway` refused arm; `ApplyConfigMigration` (hidden, root-gated) + `DumpMigrationSet` (hidden) variants + dispatch |
| `sandboxd/sandbox-cli/src/update/mod.rs`                                      | New: update orchestration |
| `sandboxd/sandbox-cli/src/backend.rs`                                         | Edit: `RebuildImageBackend::Gateway` variant added; refused dispatch arm in `dispatch_rebuild_image` |
| `sandboxd/sandbox-cli/src/update/lock.rs`                                     | New: lock-file acquisition logic (shell-level `flock` wrapper), dead-PID adoption, sticky `was_running` read/write |
| `sandboxd/sandbox-cli/src/update/fetch.rs`                                    | New: tarball fetch, cosign verify, MANIFEST verify |
| `sandboxd/sandbox-cli/src/update/backup.rs`                                   | New: backup set + manifest + retention |
| `sandboxd/sandbox-cli/src/update/migrate.rs`                                  | New: framework + sudo-rename glue |
| `sandboxd/sandbox-cli/src/cfg_migrations/mod.rs`                              | New: trait, registry, apply loop, atomic write |
| `sandboxd/sandbox-cli/src/cfg_migrations/version.rs`                          | New: `read_schema_version` per `TargetFile` |
| `sandboxd/sandbox-cli/src/cfg_migrations/v001_add_sandbox_to_allow_users.rs`  | New: V001 adapter for the Spec 1 transform |
| `sandboxd/sandbox-core/src/users_conf.rs`                                     | Edit: `SchemaTooNew` / `SchemaTooOld` variants; `DAEMON_*_SUPPORTED_USERS_CONF_SCHEMA` constants; `validate_users_conf_schema_version` |
| `sandboxd/sandbox-core/src/bridge_conf.rs`                                    | New: header-comment schema reader + validator + constants |
| `sandboxd/sandboxd/src/main.rs`                                               | Edit: post-load schema-mismatch refusal hook for users.conf (after line 6156) + bridge.conf parallel check |
| `sandboxd/sandbox-core/src/error.rs`                                          | Edit: `SchemaTooNew` / `SchemaTooOld` mapping into `SandboxError`, error-response shape |
| `sandboxd/sandbox-cli/tests/integration_config_migration_applies_v001_to_legacy_file.rs` | New |
| `sandboxd/sandbox-cli/tests/integration_update_flow_idempotent.rs`            | New |
| `sandboxd/sandboxd/tests/integration_users_conf_schema_refusal.rs`            | New |
| `tests/install-e2e/test_update_fresh_to_next.py`                              | New per § 9.1 |
| `tests/install-e2e/test_update_interrupted_then_resumed.py`                   | New |
| `tests/install-e2e/test_update_manual_rollback.py`                            | New |
| `tests/install-e2e/test_update_air_gapped.py`                                 | New |
| `tests/install-e2e/test_update_check_no_mutation.py`                          | New |
| `tests/install-e2e/test_update_concurrent_refused.py`                         | New |
| `tests/install-e2e/test_update_preserves_users_conf.py`                       | New |
| `tests/install-e2e/test_update_preserves_drop_in.py`                          | New |
| `tests/install-e2e/test_update_recreate_classification.py`                    | New |
| `tests/install-e2e/test_update_rejects_dev.py`                                | New |
| `tests/install-e2e/test_update_backup_retention.py`                           | New |
| `tests/install-e2e/test_update_partial_failure_backup_preserved.py`           | New |
| `docs/start/installation.md`                                                  | Edit: pointer to `sandbox update` for upgrades |
| `docs/operate/update.md`                                                      | New: operator-facing upgrade narrative + rollback recipe link |

**Files explicitly *not* touched** (called out to forestall confusion):

| Path                                                                         | Reason untouched |
|------------------------------------------------------------------------------|------------------|
| `sandboxd/sandbox-core/migrations/V00*.sql`                                  | Refinery DB migrations are forward-only; Spec 5 does not author DB migrations, only triggers them via daemon restart. |
| `scripts/install.sh` / `scripts/uninstall.sh`                                | Spec 4 owns these. Spec 5's update flow appends to the same `/var/log/sandbox-install.log` but does not modify the install/uninstall scripts. |
| `.github/workflows/release.yml`                                              | Spec 4 owns the release pipeline. Spec 5's tarball-consumption logic reuses the artefacts as-is. |
| `/etc/systemd/system/sandboxd.service`                                       | Replaced via the upgrade flow per § 3.2.23 but the *content* is owned by Spec 3 § 4.1. Spec 5 inherits the shape. |
| `sandboxd/sandbox-core/src/guest.rs`                                         | Spec 2 owns `GuestRequest::Version` and the compatibility predicates. Spec 5 only **consumes** them at § 3.1.8. |
| `sandboxd/contrib/systemd/sandboxd.service`                                  | Workspace's canonical unit copy (Spec 3 § 15.5). Spec 5 reads it via the tarball. |
