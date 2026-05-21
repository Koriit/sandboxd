---
title: Use workspaces
description: Provision source code into a session using clone, shared mount, local snapshot, sandbox cp / sync, or git remote transport.
---

This guide shows you how to use each workspace mode with copy-pasteable commands. For background on the modes and their trade-offs, see [workspaces concepts](/concepts/workspaces/).

## Before you start

You need:

- A running `sandboxd` daemon — see [Quickstart](/start/quickstart/) if you have not set one up.
- The `sandbox` CLI on your `PATH`.
- For git remote transport, the `git-remote-sandbox` symlink on your `PATH` alongside `sandbox`.

All commands below assume these are in place.

## Clone a repository at session creation

Clone is the default way to bring a remote repository into a new session. The clone runs inside the VM during provisioning.

```bash
sandbox create --name dev \
    --repo https://github.com/octocat/Hello-World.git
```

For a private or gated repository, pair `--repo` with a policy that allows the git host:

```bash
sandbox create --name dev \
    --policy ./policy.json \
    --repo https://github.com/myorg/private-repo.git
```

The repository lands in `/home/agent/workspace/` inside the VM. Verify it cloned:

```bash
sandbox exec dev -- ls /home/agent/workspace
```

### Troubleshooting clone

- **Clone fails, session still comes up.** Clone failure is non-fatal. The session reaches `Running` with an empty workspace. Check the daemon logs for the `git clone` error, then fix the policy or URL and redo.
- **`NXDOMAIN` on the git host.** The domain is not in the policy. See [network policies](/guides/network-policies/).
- **`Connection refused`.** DNS resolved but the IP is not allowed. Check the policy's assurance level and CIDR coverage.

## Mount a host directory (shared mode)

Shared mode exposes a host directory live inside the VM via 9p. Use it for interactive development when you want the host IDE and the in-VM toolchain to share the same files.

The full grammar of the flag value is:

```text
shared:<host>[:<guest>][:<security-model>]
```

Both optional tokens are positional. `<guest>` is the in-VM mount point; when omitted it **defaults to `<host>` verbatim**. `<security-model>` selects the 9p model and is one of `mapped-xattr` (default) or `none`.

Mount the current directory:

```bash
sandbox create --name dev \
    --workspace "shared:$(pwd)"
```

Combine with a boot command to install dependencies after the mount. Because the guest path now defaults to the host path, refer to it directly:

```bash
sandbox create --name dev \
    --workspace "shared:$(pwd)" \
    --boot-cmd "cd $(pwd) && npm install"
```

Three forms of the same flag, from minimal to fully explicit:

```bash
# Host path only; guest path = host path, security model = mapped-xattr.
sandbox create --workspace "shared:/home/user/proj"

# Explicit guest path; security model still defaults to mapped-xattr.
sandbox create --workspace "shared:/home/user/proj:/srv/work"

# Full triple — host, guest, and security model.
sandbox create --workspace "shared:/home/user/proj:/srv/work:none"
```

> **Footgun: colons in paths.** The parser tokenizes on `:` from right to left. A host path containing a colon (e.g. `/data:archive`) will be misclassified — the rightmost token after the mode prefix is read as the security model or guest path. Avoid colons in host paths, or pass an explicit guest path (e.g. `shared:/data:archive:/srv/work`) to disambiguate. The same applies to a guest path that happens to be literally `/none` or `/mapped-xattr`, either of which would be classified as a security model.

> **Breaking default.** The historical fixed mount point `/home/agent/workspace` is gone. The guest path now defaults to the host path so that build artefacts and tool output that reference absolute host directories survive a host-to-guest round trip without translation. If you relied on the old layout, pass an explicit guest path (e.g. `shared:$(pwd):/home/agent/workspace`).

### Pick a guest path

Set `<guest>` when:

- You need the in-VM path to differ from the host path — for example, mounting `/Users/alice/proj` (macOS-style) into `/home/agent/proj` so guest-side scripts that assume a Linux home directory still work.
- The host path contains characters that the in-VM toolchain handles poorly (spaces, mixed case on a case-insensitive host).
- You want to preserve the legacy `/home/agent/workspace` layout for an existing pipeline; pass it explicitly.

Leave `<guest>` off when the host path is already a valid absolute Linux path and you want the simplest configuration — that is the new default.

A leading `~` in the host token expands against the CLI process's `$HOME` (the same expansion the shell would do for an unquoted argument). A leading `~` in the guest token is a literal substitution to `/home/agent` — it is not a lookup inside the VM.

> **Note: shell globs expand before the CLI sees them.** `--workspace shared:~/projects/*` is expanded by your shell, not by sandboxd, so the CLI sees whatever paths the glob produced (often more than one, or none). Quote the value or pass a literal path to keep the parser's view aligned with what you typed.

### Pick a security model

`<security-model>` selects the 9p file-attribute strategy:

- `mapped-xattr` (default) — file ownership and permissions on the host side are stored in extended attributes. Sandbox-side files are not owned by the operator's uid on the host filesystem; that is the safer default.
- `none` — opt in when you need real-symlink interop in both directions. A build step inside the guest that creates a symlink will land on the host as a real symlink, not as a 9p-encoded placeholder. The price is that file ownership reflects the guest's view, which is less restrictive than `mapped-xattr`.

The 9p models `passthrough` and `mapped-file` are deliberately not exposed by `sandboxd`. See [hardening — 9p shared mounts](/guides/hardening/#9p-shared-mounts) for the full trade-off and the rationale.

Constraints:

- The host path must be absolute (after `~` expansion) and must already exist.
- The guest path must be absolute. A leading `~` on the guest token is rewritten to `/home/agent` literally.
- `--workspace` and `--repo` are mutually exclusive.

Verify the mount, substituting your chosen guest path:

```bash
sandbox exec dev -- ls "$(pwd)"
```

Changes on either side appear immediately on the other — no sync step needed.

Shared mount reduces VM isolation. If your workload does not need live bidirectional visibility, prefer clone plus `sandbox cp` or git remote transport. See [hardening](/guides/hardening/#9p-shared-mounts) for the full trade-off.

## Snapshot a host directory (`local:` mode)

`local:` is the snapshot-style cousin of `shared:`. At session-creation time the daemon `rsync`s your host directory into the guest; after that, no live host-to-guest link exists. The guest sees a static copy of the tree as it was at create time. There is no 9p surface, no bind mount, and no path through which a guest write reaches your host filesystem.

Reach for `local:` when you want the convenience of seeding the session with a directory you already have on disk, but do not need (or do not want) live bidirectional visibility. Typical fits: a non-git scratch tree, generated files you do not want to commit, or a directory where isolation matters more than ergonomic in-place editing. See [hardening](/guides/hardening/#local-snapshot-workspace) for the isolation-trade-off notes that justify reaching for `local:` over `shared:`.

`shared:` vs. `local:`, at a glance:

| Property | `shared:` | `local:` |
|---|---|---|
| Host-side writes appear in guest | Instantly | Only at create time (snapshot) |
| Guest-side writes appear on host | Instantly | Never (no live link) |
| Filesystem surface added to VM | 9p | None |
| Best for | Interactive IDE-driven dev | Isolated runs over a known tree |

The flag grammar is `local:<host>[:<guest>]`. `<host>` must be an existing absolute directory after `~` expansion. `<guest>` is the in-VM path; **when omitted it defaults to `<host>` verbatim**, matching the new default rule for `shared:`. There is no security-model token — `local:` has no 9p surface, so the `mapped-xattr` / `none` choice does not apply.

Three forms of the flag, from minimal to fully explicit:

```bash
# Host path only; guest path = host path.
sandbox create --workspace "local:/home/user/proj"

# Explicit guest path.
sandbox create --workspace "local:/home/user/proj:/srv/work"

# With the current directory.
sandbox create --workspace "local:$(pwd):/home/agent/work"
```

> **Rollback caveat.** Daemons older than this release cannot read records written with `local:` workspaces — the `WorkspaceMode::Local` variant is not in their schema. Roll forward; do not roll back across a session created with `local:`.

By default, the create-time push honours each `.gitignore` in the source tree (rsync `--filter=':- .gitignore'`). Files matched by an ignore rule do not land in the guest. To transfer everything, pass `--no-gitignore`:

```bash
sandbox create --name dev \
    --workspace "local:$(pwd)" \
    --no-gitignore
```

`--no-gitignore` is meaningful only with `--workspace local:`; the CLI refuses it for any other mode (the daemon enforces the same gate, so a hand-rolled HTTP request gets a 400 with the same text).

Verify the snapshot landed:

```bash
sandbox exec dev -- ls "$(pwd)"
```

`sandbox describe dev` renders the chosen mode and paths under the `Workspace:` block:

```text
Workspace:
  Mode:        local
  Host path:   /home/user/proj
  Guest path:  /srv/work
```

### Create-time rsync failure tears the session down

The initial push runs after the VM/container reaches `Running` but before `sandbox create` returns. If `rsync` exits non-zero — for example, a host file with `chmod 000` that the daemon cannot read — the create call surfaces an HTTP 5xx with `local-workspace rsync failed (exit <N>): <rsync stderr>`, and the daemon tears the VM/container, network, and CA state down before responding. You will not see a half-seeded session in `sandbox ps`; the failed create leaves no orphan resources on the host. Fix the underlying issue (permissions, missing path) and re-run.

### Push and pull edits between host and guest

After the create-time snapshot, `sandbox workspace push` mirrors changes from the host into the guest, and `sandbox workspace pull` mirrors changes from the guest back to the host. Both commands operate on the `host_path` and `guest_path` the session was created with (`sandbox describe` shows them).

Push host edits into the guest:

```bash
# Inspect first — see what would change without modifying the guest.
sandbox workspace push -n dev

# Then mirror the host tree into the guest.
sandbox workspace push -f dev
```

Pull guest edits back to the host:

```bash
sandbox workspace pull -n dev
sandbox workspace pull -f dev
```

Exactly one of `-f`/`--force` and `-n`/`--dry-run` is required. The CLI refuses bare `sandbox workspace push <s>` with a usage error — the `-f`/`-n` gate is intentional, since both commands always run with `--delete` semantics: deletions on the source are mirrored to the destination. Use `-n` to inspect first, `-f` to apply.

The default flag set is `rsync -aL --delete --filter=':- .gitignore'` plus the backend-appropriate `-e` shell transport (`limactl shell` for Lima, `docker exec -i` for the container backend). Two flags adjust this baseline:

- `--safe-links` — replace the default `-L` with `--safe-links`. In-tree symlinks are preserved as symlinks; out-of-tree symlinks (anything that resolves outside the source root) are skipped instead of followed. Use this when your tree contains intentional symlinks you want to keep as symlinks, or when you want to avoid following a symlink that points outside the workspace.
- `--no-gitignore` — drop the `:- .gitignore` filter so the push or pull transfers everything, including ignored files. Useful for `.env`-style files you want copied but cannot un-ignore in your `.gitignore`.
- `--dest <path>` (pull only) — override the host destination. The default is the session's recorded `host_path`. A leading `~` expands against your `$HOME`; the CLI rejects `--dest` pointing at an existing file (it must be a directory, existing or to be created), and it calls `mkdir -p` on the parent of `--dest` before invoking rsync.

```bash
# Pull a snapshot into a sibling directory without touching the original.
sandbox workspace pull -f --dest ~/work/dev-snapshot dev
```

`.gitignore` is read from the **source** side of each operation: push respects the host's `.gitignore`, pull respects the guest's. This is rsync's filter-source semantics, not a sandboxd choice. If you keep `.gitignore` in sync between the two sides (the usual case — a `push -f` from the host overwrites the guest's copy on the next push), the two filters agree. If the guest's `.gitignore` has diverged (e.g. you edited it inside the session), a subsequent pull will use the divergent guest copy, which can surprise. The simplest fix is to keep `.gitignore` versioned and committed.

While a push or pull is running, the session is locked: a second `push`/`pull` on the same session returns `409 Conflict` with a recovery hint, and `sandbox stop`/`sandbox rm` refuses with the same 409 until the in-flight operation completes. Two CLIs cannot race against the same `local:` snapshot.

### Recovering an orphan workspace lock

If a `sandbox workspace push` or `pull` CLI process is killed mid-flight (typically by `SIGKILL` — a non-catchable signal that bypasses the CLI's release-on-cancel guard), the daemon-side lock can outlive the CLI. Subsequent operations on the session then see:

```text
$ sandbox workspace push -f dev
Error: session has an active push operation; cancel the operation or run 'sandbox workspace unlock dev --force'
```

`sandbox stop dev` and `sandbox rm dev` surface the same 409 with the same hint. The recovery is the operator command the hint names:

```bash
sandbox workspace unlock dev --force
```

`--force` releases the lock unconditionally, ignoring the token check. The vanilla `sandbox workspace unlock dev` (no `--force`) is the graceful-release path for automation that retained the original `lock_token` from acquire; hand-operators almost always need `--force` because they never see the token. Either form is a 200 no-op against a session whose lock is not currently held, so it is safe to re-issue.

Daemon restarts also clear orphan locks — the lock state is in-memory only and resets on every daemon boot. If you can wait for the next daemon restart, no manual action is needed. `sandbox workspace unlock --force` is the recovery path you reach for when you cannot.

## Copy individual files with `sandbox cp`

`sandbox cp` moves single files or directories between the host and a session. The syntax mirrors `scp`: `session:path` for the session-side path, plain paths for host-side.

Upload to the session:

```bash
sandbox cp ./config.toml dev:/home/agent/workspace/config.toml
```

Download from the session:

```bash
sandbox cp dev:/home/agent/workspace/output.log ./output.log
```

Copy a directory (recursive by default):

```bash
sandbox cp ./dist dev:/home/agent/workspace/dist
```

Under the hood `sandbox cp` dispatches to the backend's native copy tool — `limactl cp` for Lima sessions and `docker cp` for container sessions — so file modes, sparse files, and directory trees are preserved by the same code path your operating system already trusts. Errors (missing source, permission denied, unreachable session) come from those tools verbatim, so they match the diagnostics you would see invoking them directly.

`sandbox cp` works regardless of which workspace mode you chose at creation time.

## Mirror a directory with `sandbox sync`

`sandbox sync` is the rsync-shaped sibling of `sandbox cp`. Reach for it when `cp`'s "retransfer everything" semantics are wrong for the workflow — typically tight edit-build-test loops where you want only the changed files to traverse the boundary, or CI-style runs where the destination must be a faithful mirror of the source on each invocation (no left-over files from a previous run).

The CLI shape mirrors `cp`: `session:path` for the session side, plain paths for host-side.

Upload a directory tree to the session:

```bash
sandbox sync ./src dev:/home/agent/workspace/src
```

Re-run the same command after editing a few files. Rsync only retransfers the changed files; an untouched tree finishes in milliseconds.

Pull a build directory back to the host:

```bash
sandbox sync dev:/home/agent/workspace/dist ./dist
```

Demonstrate the `--delete` mirror semantics — files removed on the source are removed on the destination on the next sync:

```bash
rm ./src/obsolete.go
sandbox sync ./src dev:/home/agent/workspace/src
# /home/agent/workspace/src/obsolete.go is now gone in the session too
```

Under the hood `sandbox sync` dispatches the host's `rsync` with the backend's native shell as rsync's remote-shell (`-e`) transport — `limactl shell` for Lima, `docker exec -i` for container. The baseline flag set is `-a --delete`: archive mode (perms, ownership, mtimes, symlinks, recursion) plus mirror semantics. Errors and progress reach you in rsync's native form. Out-of-scope: filter rules, partial transfers, bandwidth limits — operators wanting those can run `rsync` directly with the same `-e <rsh>` pattern this command uses.

`sandbox sync` and `local:` workspaces both require `rsync` on **both** the host and the guest. sandboxd-provisioned base images (Lima golden image, Lite container image) ship rsync by default. If you supply a custom image, install rsync yourself.

`cp` vs. `sync` vs. `local:` push/pull — pick by semantic, not by tree size:

| | `sandbox cp` | `sandbox sync` | `local:` push/pull |
|---|---|---|---|
| One-shot copy of a file or tree | Yes | Yes | Yes |
| Retransfers full source on re-run | Yes | No (only deltas) | No (only deltas) |
| Preserves attributes (mode, ownership, mtimes) | Yes (via `cp`/`scp`) | Yes (`-a`) | Yes (`-a`) |
| Deletes destination entries no longer on source | No | Yes (`--delete`) | Yes (`--delete`, always) |
| Honours `.gitignore` filter on the source side | No | No | Yes (default; opt out via `--no-gitignore`) |
| Operates on operator-supplied paths | Yes (any path) | Yes (any path) | No (paths fixed at session create) |
| Requires `local:` workspace mode | No | No | Yes |
| Lock-protected against concurrent invocations | No | No | Yes (per-session daemon mutex) |
| Backend tool dependency | `limactl` / `docker` | `rsync` (host + session) | `rsync` (host + session) |

## Sync via `git push` and `git pull`

Git remote transport lets you use standard git commands against a repository inside a session, without any network policy.

Add the session as a git remote:

```bash
git remote add sandbox sandbox::dev/home/agent/workspace
```

The URL format is `sandbox::<session>/<repo-path>`. If you omit the path, it defaults to `/home/agent/workspace`:

```bash
git remote add sandbox sandbox::dev
```

Push local commits into the VM:

```bash
git push sandbox main
```

Pull VM-side commits back to the host:

```bash
git pull sandbox main
```

Both `git-upload-pack` (fetch/pull) and `git-receive-pack` (push) are supported. The path is entirely host-local — no policy rules are needed.

### Troubleshooting git remote transport

- **`git-remote-sandbox: command not found`.** The symlink is missing from `PATH`. Install it next to the `sandbox` binary and re-check `which git-remote-sandbox`.
- **`Permission denied` opening the daemon socket.** Set `SANDBOX_SOCKET` to the socket path you are using, or start the daemon first.
- **Target path is not a git repository.** Initialise it inside the VM first: `sandbox exec dev -- git -C /home/agent/workspace init`.

## Run a command after provisioning

`--boot-cmd` runs an arbitrary shell command after the workspace is in place. It runs as the `agent` user; use `sudo` for root operations.

```bash
sandbox create --name dev \
    --repo https://github.com/example/app.git \
    --boot-cmd "cd /home/agent/workspace && npm install"
```

Boot command failure does not block the session from reaching `Running`. Re-run failed steps with `sandbox exec`.

## Common flows

### Interactive development

Share the current directory, install dependencies on boot, run tests via `exec`.

```bash
sandbox create --name dev \
    --workspace "shared:$(pwd)" \
    --boot-cmd "cd /home/agent/workspace && npm install"
sandbox exec dev -- bash -c "cd /home/agent/workspace && npm test"
sandbox rm dev
```

### CI-style run

Clone, build, test, pull artifacts back.

```bash
sandbox create --name ci-run \
    --policy ./ci-policy.json \
    --repo https://github.com/myorg/app.git \
    --boot-cmd "cd /home/agent/workspace && make build && make test"
sandbox cp ci-run:/home/agent/workspace/dist/app.tar.gz ./app.tar.gz
sandbox rm ci-run
```

### Push-test-pull loop

Create a blank session, push the local tree, run tests, pull results back.

```bash
sandbox create --name review
git remote add review sandbox::review/home/agent/workspace
git push review main
sandbox exec review -- bash -c "cd /home/agent/workspace && make test"
git pull review main
sandbox rm review
```

## Where to go next

- [Network policies](/guides/network-policies/) — open specific destinations so clone and other network operations can reach them.
- [First real session](/guides/first-real-session/) — put workspaces, policy, and the agent together in one flow.
- [Troubleshooting](/guides/troubleshooting/) — when something does not work.
