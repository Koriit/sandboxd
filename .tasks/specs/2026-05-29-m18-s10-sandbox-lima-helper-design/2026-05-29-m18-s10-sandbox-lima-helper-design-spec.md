# `sandbox-lima-helper` privileged setcap helper (M18-S10)

## Summary

This spec introduces a new narrowly-scoped setcap helper binary,
`sandbox-lima-helper`, that pivots the daemon (running as the
unprivileged `sandbox` system user) to an operator's uid before
exec'ing `limactl` for every session-context Lima operation. The
load-bearing architectural decision is that **the daemon never invokes
`limactl` directly anywhere in the codebase** — every limactl
invocation (session-context, per-operator base-image build, startup
orphan scan, proxy port lookup) goes through the helper after this
migration lands. The helper supersedes the `--prepare-lima-spawn`
chown-bracket inside `sandbox-spawn-helper` for the Lima path; POSIX
ACLs on a per-operator `LIMA_HOME` make file ownership a non-issue,
so helper-pivoted `limactl create` writes `_config/user` as the
operator uid directly, satisfying OpenSSH `StrictKeyfileMode` without
any chown step. Persisted state evolves via the V008 forward-only
migration which adds `operator_uid` / `operator_gid` columns to the
sessions table, and which is intentionally a hard break: pre-V008
session rows are deleted by the migration because their VMs live in
the old host-global `LIMA_HOME` and have no recoverable operator uid.

## Context

### Current behaviour (M18-S9 baseline)

The cross-user CLI access design that shipped on 2026-05-24
(`.tasks/specs/2026-05-24-cross-user-cli-access-design/...`) covered
the **CLI ↔ daemon** layer: it added daemon-mediated SSH for the six
broken CLI commands, captured operator identity at session-create via
`SO_PEERCRED` on the daemon socket, persisted it onto the sessions
row, and threaded it through to a `sandbox-spawn-helper`
setresuid+execve chain for QEMU and container init. That work shipped
its scope correctly. What it explicitly did not cover, and what M18-S9
matrix runs surfaced, is the layer below: the **daemon ↔ limactl**
control plane. Every Lima control-plane operation the daemon performs
— `limactl create`, `start`, `stop`, `delete`, `clone`, `copy`,
`shell`, `list --json` — still runs as the daemon's uid (typically
999, the `sandbox` system user), against a host-global `LIMA_HOME` at
`/var/lib/sandbox/.lima/`. Files inside the per-VM `_config/`
directory end up owned `sandbox:sandbox`, including `_config/user`,
the SSH private key that limactl generates and `ssh` later reads.

The M18-S9 matrix run exposed two distinct structural failure modes
in this baseline:

* **`StrictKeyfileMode` two-way symmetry.** OpenSSH refuses to use a
  private key whose owning uid does not match the calling uid, in
  either direction. `_config/user` owned `sandbox:sandbox` is
  unusable by the operator's `ssh` client; chown'd to the operator,
  it becomes unusable by `sandbox` for the daemon-side `limactl
  shell` path. There is no static ownership that satisfies both.
* **Chown-bracket race window.** A "chown to operator before spawn,
  chown back to `sandbox` after" approach (the `--prepare-lima-spawn`
  argv form added to `sandbox-spawn-helper` during M18-S9 hot-fixing)
  closes the symmetry problem in steady state, but every Lima
  operation that touches `_config/user` opens a small window during
  which the key is operator-owned. A concurrent daemon-uid `limactl
  shell` invocation arriving inside that window fails. The fix is
  per-operation serialisation, but the lock granularity needed to
  cover every limactl call site is large and the failure mode is
  difficult to reason about under load.

For background on the existing helper landscape, the closest
precedents are `sandbox-spawn-helper`
(`sandboxd/sandbox-spawn-helper/src/main.rs`) and
`sandbox-route-helper` (`sandboxd/sandbox-route-helper/src/main.rs`):

* **`sandbox-spawn-helper`** is a one-shot "setresuid then exec
  runtime tool" pivot. Argv form `sandbox-spawn-helper
  [--prepare-lima-spawn] <operator_uid> <runtime_argv0>
  [runtime_argv...]`. Caps `cap_setuid,cap_chown+ep` — `cap_chown`
  exists only for the chown-bracket on `LIMA_USER_KEY`, which goes
  away under the new ACL-based model. Caller-authz is `sandbox`
  group membership only (`getgrnam_r("sandbox")` + `getgid()` +
  `getgroups(2)`); no uid-equality check. Op-uid is an argv-supplied
  positional, validated via `User::from_uid`, and currently does
  not reject root. Exec target is PATH-resolved via `execvpe` with
  caller-controlled runtime argv. Env handling is an allow-list
  `[PATH, LANG, LC_ALL, HOME, TERM]`. Explicit `capset` of empty
  permitted/effective/inheritable + ambient drop after `setresuid`.
  Installed at `/usr/local/libexec/sandboxd/sandbox-spawn-helper`
  (FHS § 4.7). Daemon resolver
  `resolve_spawn_helper_path()` at `sandboxd/src/main.rs:809` uses
  env override `$SANDBOX_SPAWN_HELPER_PATH` and returns
  `Option<PathBuf>` with `None` as a soft fallback to direct
  daemon-uid spawn.
* **`sandbox-route-helper`** is the parallel structure for
  subcommand shape and FHS install location. It uses a `--for-user`
  pair-membership check in addition to `sandbox` group membership.
  The new helper mirrors its install/resolver shape but replaces
  the pair-membership with a strictly stronger `getuid() ==
  sandbox-user-uid` kernel check (the new helper is daemon-only by
  design — see § Decision).

### What got delivered, what didn't

The 2026-05-24 cross-user CLI spec shipped its scope (CLI ↔ daemon)
correctly. Daemon-mediated SSH, persistent ssh-config under
`~/.ssh/sandbox/`, the `proxy` WebSocket endpoint, and the V007 SSH
keypair migration are all in tree and exercised by the M18-S9 matrix.
What that spec deferred — and what the matrix run made unavoidable —
is the layer immediately below: every helper-pivoted runtime spawn
already runs as the operator, but `limactl` itself (the tool that
provisions the Lima VM the operator-uid'd QEMU then attaches to) is
still invoked as the daemon. This spec covers that gap.

## Decision

### Architectural choice: helper-pivot over alternatives

Four alternatives were considered for the daemon ↔ limactl layer.
Three are rejected; one — narrowly-scoped setcap helper — is adopted.

* **Grant `CAP_SETUID` to the daemon directly.** Rejected. The
  daemon is several thousand lines of Rust with hundreds of call
  sites; granting it `CAP_SETUID` would expand the privileged surface
  to all of it. This contradicts the privilege model documented in
  `CLAUDE.md` ("the daemon runs as the unprivileged `sandbox` system
  user without elevated capabilities") and the established pattern
  of factoring each capability into a separate setcap helper binary.
* **Run per-operator daemons.** One sandboxd instance per operator,
  each running as that operator's uid, eliminates the cross-user
  problem by construction. Rejected on operational grounds: the
  daemon owns the sessions database, the gateway-container
  lifecycle, the network policy machinery, and per-host singletons
  like the route helper's caller-authz state. Running N copies per
  host requires coordinating all of these, and the failure modes
  (one daemon down for one operator, conflicting policy updates,
  socket-path collisions, systemd-unit instantiation) compound badly.
* **Shared world-readable base image with the chown-bracket on
  `_config/user`.** The handoff baseline (`--prepare-lima-spawn` in
  `sandbox-spawn-helper`) chowns the per-VM key to the operator
  before each helper-spawned QEMU and back to `sandbox` afterwards.
  Rejected because the chown window is not eliminable: any
  daemon-uid `limactl` call arriving while the key is operator-owned
  fails, and the lock granularity needed to close the window covers
  every limactl call site in the codebase. The symmetry of OpenSSH's
  `StrictKeyfileMode` makes this structural, not tunable.
* **Narrowly-scoped setcap helper following the `sandbox-route-helper`
  precedent.** Adopted. Helper file caps `cap_setuid+ep` (no
  `cap_chown` — POSIX ACLs replace the chown-bracket entirely).
  Daemon stays uncapped. Per-operator `LIMA_HOME` at
  `/var/lib/sandboxd/<op-uid>/lima/` with ACLs granting the operator
  rwx; helper-pivoted `limactl create` writes `_config/user` as the
  operator uid directly, satisfying `StrictKeyfileMode` via plain
  `st_mode`/owner match. The privileged surface is one binary,
  ~50-100 lines of audit-able code, with a single load-bearing
  primitive (`setresuid`). This matches the
  `CLAUDE.md` "Privilege model: narrowly-scoped setcap helpers over
  broad daemon capabilities" guidance verbatim.

### Load-bearing decision: daemon never invokes limactl directly

The architectural commitment the rest of this spec rests on is that
**after the migration lands, the daemon contains zero direct
invocations of `limactl`.** Every call site — session-context,
per-operator base-image build, startup orphan scan, proxy port
lookup — goes through `sandbox-lima-helper`. There is no soft
fallback to direct daemon-uid spawn.

This is structurally enforced rather than left to discipline. The
helper resolver at daemon startup returns `Result<PathBuf,
SandboxError>` (not `Option<PathBuf>`): unresolvable helper is a
fatal startup error. `LimaManager::limactl_path()` at
`sandbox-core/src/lima.rs:319` is **deleted** as part of step 9 of
the implementation order; no daemon-side limactl path resolver
remains in the tree. The combination makes "daemon spawns limactl
directly" not a policy that could regress under future refactoring
— it does not have an entry point to regress from.

## Architecture

### Privilege model

Per-operator `LIMA_HOME` at `/var/lib/sandboxd/<op-uid>/lima/`. The
directory is created by the daemon at first session-create for that
operator, owned `sandbox:sandbox 0750`, with the following ACLs:

* Access ACL `u:<op>:rwx` — a **non-default** entry on the top dir
  only, granting the operator dir-level rwx for traversal.
* No default named-user ACL. The default ACL denies group and other
  (`d:g::---,d:o::---`); it carries **no** `d:u:<op>:rwx` entry.

A default named-user ACL (`d:u:<op>:rwx`) was deliberately rejected.
OpenSSH reads `st_mode`, not the ACL — and a default named-user entry
forces the POSIX ACL **mask** onto every child file, which surfaces
in the file's group bits. `_config/user` would then `stat(2)` as
`0640`, and OpenSSH `StrictKeyfileMode` would reject the key
(`bad permissions`), hanging the hostagent for the full start
timeout. Instead, the helper sets `umask(0o077)` before `exec`, so
`limactl create` (helper-pivoted, running as the operator) writes
`_config/user` as the operator uid at mode 0600 — no ACL, no mask,
no subsequent chown step. The operator owns the key outright; owner
bits alone satisfy OpenSSH, and `ls -l` shows a vanilla file with no
`+` ACL marker.

The helper itself has file caps `cap_setuid+ep` and no others. The
daemon has zero file caps. Caller authz inside the helper checks
both `getuid() == sandbox-user-uid` (primary gate, kernel-checked,
strictly stronger than spawn-helper's pair-membership) **and**
`sandbox` group membership (sanity check that supplementary groups
are wired correctly).

### Binary

* **Crate path:** `sandboxd/sandbox-lima-helper/` (new crate, mirrors
  `sandbox-spawn-helper/` and `sandbox-route-helper/`).
* **Binary name:** `sandbox-lima-helper`.
* **File caps:** `cap_setuid+ep`. No `cap_chown` — the chown-bracket
  pattern is dead; POSIX ACLs replace it.
* **Install path:** `/usr/local/libexec/sandboxd/sandbox-lima-helper`
  (FHS § 4.7).
* **Daemon resolver:** new `resolve_lima_helper_path()` in
  `sandboxd/src/main.rs`, parallel to `resolve_spawn_helper_path()`.
  Env override: `$SANDBOX_LIMA_HELPER_PATH`. **`None` is a hard
  error** — the cross-user model requires the helper, there is no
  soft fallback, and the daemon refuses to come up if no helper is
  resolvable. Returns `Result<PathBuf, SandboxError>`.
* **Username/group pins:** two compile-time constants
  `SANDBOX_USER_NAME = "sandbox"` and `SANDBOX_GROUP_NAME = "sandbox"`,
  resolved at runtime via `getpwnam_r` / `getgrnam_r`. A
  `test-env-override` Cargo feature exposes env-var seams
  (`SANDBOX_LIMA_HELPER_TEST_SANDBOX_USER`,
  `SANDBOX_LIMA_HELPER_TEST_SANDBOX_GROUP`) for integration tests
  that need to drive against synthetic accounts. Default builds
  ignore the env vars.

### Interface: subcommands

Argv form is `sandbox-lima-helper <subcommand> <flags...>`. The
subcommand keyword is positional; flags follow. **No flag
pass-through to limactl.** Every flag the helper passes to limactl is
hardcoded inside this binary, indexed by subcommand, with validated
flag values spliced in by position only.

Listed in source order. Each subcommand documents its argv shape,
the limactl invocation it execs, and any subcommand-specific notes.

#### `create`

```
sandbox-lima-helper create --op-uid N --vm <name> --yaml <path>
```

Execs `limactl create --name <vm> <yaml> --tty=false`.

#### `start`

```
sandbox-lima-helper start --op-uid N --vm <name>
                          --qemu-wrapper <path>
                          --hardened 0|1
                          --memory-mb <N>
                          --cpus <N>
                          --start-timeout-s <N>
                          [--bridge-name <name> --vm-mac <mac>]
```

Execs `limactl start <vm> --timeout=<N>s --tty=false`. The helper
sets the following env vars in the exec'd process, built from
validated flag values:

| Env var                  | Source                                |
|--------------------------|---------------------------------------|
| `QEMU_SYSTEM_X86_64`     | `--qemu-wrapper`                      |
| `SANDBOX_QEMU_HARDENED`  | `--hardened`                          |
| `SANDBOX_QEMU_MEMORY_MB` | `--memory-mb`                         |
| `SANDBOX_QEMU_CPUS`      | `--cpus`                              |
| `SANDBOX_DOCKER_BRIDGE`  | `--bridge-name` (if pair supplied)    |
| `SANDBOX_VM_MAC`         | `--vm-mac` (if pair supplied)         |

`--start-timeout-s` is required (no default) and maps to `limactl
start --timeout=<N>s`. It controls limactl's internal wait for VM
sshd reachability. This is functionally distinct from the daemon's
`run_with_timeout` wrapper around the helper invocation, which is a
host-side wall-clock kill; both layers are load-bearing and must be
set independently.

`--bridge-name` and `--vm-mac` are paired: both supplied or both
omitted. Mirrors today's daemon `if let (Some(bridge), Some(mac))`
pairing at `sandbox-core/src/lima.rs:519-522`.

Note the unit mismatch: `start --memory-mb` is megabytes; `clone
--memory` is gibibytes. The daemon's `mib_to_gib_string` helper at
`lima.rs:1416` does the conversion for the clone path. Implementer
must not unify the two units.

#### `clone`

```
sandbox-lima-helper clone --op-uid N --base <name> --vm <name>
                          --cpus <N>
                          --memory <GiB>
                          --disk <GiB>
```

Execs `limactl clone <base> <vm> --cpus <N> --memory <G> --disk <D>
--tty=false`. Both `<base>` and `<vm>` live in the same operator
`LIMA_HOME` — the base image is per-operator under this design, so
no cross-`LIMA_HOME` traversal is required.

#### `stop`

```
sandbox-lima-helper stop --op-uid N --vm <name> [--force]
```

Execs `limactl stop <vm> --tty=false` by default, or `limactl stop
-f <vm> --tty=false` when `--force` is set. `--force` is a bool flag
(present or absent, no value). It mirrors the daemon's existing
graceful-then-force-fallback sequence in `build_base_image_inner`
(`lima.rs:1238` + `:1266`): graceful `stop` first, then `stop
--force` on timeout. Force-stop does not destroy the VM dir — that
is `delete`'s job.

#### `delete`

```
sandbox-lima-helper delete --op-uid N --vm <name>
```

Execs `limactl delete --force <vm> --tty=false`. `--force` is
hardcoded — `limactl delete` without it refuses to operate on a
running VM. A future "graceful delete" mode, if needed, would be a
separate subcommand.

#### `copy`

```
sandbox-lima-helper copy --op-uid N --src <path> --dst <path>
```

Execs `limactl copy <src> <dst>`. No `--tty=false` (copy does not
open `/dev/tty`).

At least one of `<src>` or `<dst>` must carry a `<vm>:` prefix
(Lima's host:vm syntax marker); see § Universal entry sequence
step 6.

Host-side path validation (per step 5): the non-`<vm>:` portion
must be absolute and free of `..` traversal components. The in-VM
portion (after the `<vm>:` prefix) is forwarded verbatim — the
guest-VM kernel enforces its own access. Daemon callers must not
propagate operator-supplied paths through `copy` without their own
upstream validation; the helper's checks are defense in depth, not
the primary trust boundary.

#### `guest-socat`

```
sandbox-lima-helper guest-socat --op-uid N --vm <name>
```

Execs `limactl shell <vm> -- socat - TCP:127.0.0.1:5123`. No
`--tty=false` here — the flag has no anchor after `--`.

This is the long-lived async-I/O carve-out documented in `CLAUDE.md`.
The daemon spawns it via `tokio::process::Command` with async stdio
(not `spawn_blocking`); after `execvp` the child's stdin/stdout are
the inherited pipes from the daemon. The helper does nothing extra
here — its work ends at `execvp`.

#### `install-guest-agent`

```
sandbox-lima-helper install-guest-agent --op-uid N --vm <name>
```

Unlike every other subcommand, this one does **not** end in
`execvp`. The helper performs a deterministic sequence of six
`limactl` invocations against the named VM, with all argvs as
compile-time constants. Each step is `fork` + `exec` + `waitpid`;
the helper exits non-zero on the first non-zero step, surfacing
that step's stderr.

The host-side `sandbox-guest` binary path is pinned to a
compile-time constant:

```rust
const SANDBOX_GUEST_HOST_PATH: &str = "/usr/local/libexec/sandboxd/sandbox-guest";
```

(FHS § 4.7, parallel to the helper itself. The daemon installs it
there at 0755; world-readable so the post-`setresuid` operator can
read it.)

For integration/e2e tests the path is overridable via env var
`SANDBOX_LIMA_HELPER_TEST_GUEST_BINARY_PATH`, gated by the same
`test-env-override` Cargo feature that exposes the user/group
seams (parallel pattern to `SANDBOXD_GUEST_BINARY_PATH` that the
daemon's `guest_agent_path()` at `lima.rs:2271` honours). Default
builds without the feature ignore the env var and use only the
compile-time constant.

**Step sequence** (all invocations of `<limactl>`, where `<limactl>`
is resolved per § Universal entry sequence step 7, and `<vm>` is the
validated flag value):

1. `<limactl> copy <SANDBOX_GUEST_HOST_PATH> <vm>:/tmp/sandbox-guest`
2. `<limactl> shell <vm> -- sudo mv /tmp/sandbox-guest /usr/local/bin/sandbox-guest`
3. `<limactl> shell <vm> -- sudo chmod +x /usr/local/bin/sandbox-guest`
4. `<limactl> shell <vm> -- sudo bash -c 'cat > /etc/systemd/system/sandbox-guest.service << '"'"'UNIT_EOF'"'"'\n<unit body>\nUNIT_EOF'`
   — heredoc terminator is **single-quoted** (`'UNIT_EOF'`) per
   `lima.rs:877` and `:2115`; this prevents shell expansion of any
   `$` literals in the unit body. Helper must reproduce the
   single-quoted form verbatim.
5. `<limactl> shell <vm> -- sudo systemctl daemon-reload`
6. `<limactl> shell <vm> -- sudo systemctl enable --now sandbox-guest`

The unit body in step 4 is a compile-time-constant string inside the
helper crate (mirrors the current `GUEST_AGENT_SERVICE_UNIT` constant
in `sandbox-core/src/lima.rs`; the helper duplicates the literal
rather than depending on `sandbox-core` to keep TCB small).

**Final validation phase** (still part of this subcommand, runs only
if all six steps succeed): execute four probes, each `<limactl>
shell --tty=false <vm> command -v <tool>` for `tool ∈ {socat, git,
rsync, docker}` — pinned as a compile-time constant slice in the
helper crate. Any probe returning non-zero fails the subcommand with
stderr identifying which tool was missing.

This list mirrors `REQUIRED` at `sandbox-core/src/lima.rs:1314`. To
prevent silent drift if a future contributor adds a tool to one side
without the other, the helper crate includes a unit test that
asserts the helper's tool list equals the literal list at the
referenced line (string-compare against a `cargo expand`-style
captured snapshot, or — preferred — a `compile_error!`-guarded
constant pulled from a shared `sandbox-core::REQUIRED_BASE_TOOLS` if
the implementer chooses to depend on `sandbox-core`; if not, the
unit-test approach is acceptable).

**Partial-install cleanup** is the daemon's responsibility, not the
helper's. If any of the six steps or the four probes returns
non-zero, the helper exits non-zero immediately, leaving the VM in a
half-installed state. The daemon-side caller — the only entry point
under the new model — must handle cleanup
(`cleanup_partial_lima_instance` at `lima.rs:614` is the closest
existing pattern; for base-image build, `build_base_image`'s cleanup
path already deletes the partial base on failure). Helper guarantee:
atomic-fail (commits all six steps + four probes, or reports
failure). Recovery policy lives daemon-side.

Daemon contributes only `--op-uid` and `--vm`. Every other token
(binary path, unit body, sudo argvs, tool list) is helper-internal.

#### `list-json`

```
sandbox-lima-helper list-json --op-uid N
```

Execs `limactl list --json --tty=false`. Stdout is the child's
stdout (execvp inheritance); the daemon captures it via
`Command::output()` and parses the NDJSON as today.

### Interface: universal entry sequence

Every subcommand runs the same numbered steps 1–10. Step 11 is the
final exec for 8 of the 9 subcommands and the entry into the
deterministic step sequence for the 9th (`install-guest-agent`).
**`install-guest-agent` diverges only at step 11**; steps 1–10
(identity check, argv parse, validation, limactl resolution,
setresuid, capset, env block) are identical to every other
subcommand. Any step that denies prints a single
`sandbox-lima-helper: <reason>` line to stderr and exits with the
matching exit code; no privilege change happens before a deny.

```
1. Daemon identity check.
     - Resolve sandbox-user uid:   getpwnam_r(SANDBOX_USER_NAME).pw_uid
     - Resolve sandbox group gid:  getgrnam_r(SANDBOX_GROUP_NAME).gr_gid
     - Check getuid() == sandbox-user uid (primary gate).
     - Check caller is a member of sandbox group: getgid() or
       getgroups(2) contains sandbox-group gid (sanity check —
       verifies supplementary groups are wired correctly).
     - Either check failing → stderr "caller not sandbox
       (uid=<got>, expected=<want>)" or "caller not in sandbox
       group", exit EXIT_NOT_SANDBOX (2).
     - The user/group name literals come from compile-time
       constants; the `test-env-override` Cargo feature lets
       tests substitute synthetic names.

2. Argv parse.
     - args[1] must be one of: create, start, clone, stop, delete,
       copy, guest-socat, install-guest-agent, list-json.
     - Hand-rolled parser (no clap) for TCB minimisation.
     - Subcommand keyword absent / unknown → exit EXIT_BAD_ARGS (7).
     - Each subcommand has a fixed required flag set; any missing
       flag, unknown flag, repeated flag, or extra positional →
       exit EXIT_BAD_ARGS (7).

3. Validate --op-uid (every subcommand has it).
     - Parse as u32. Parse failure (non-numeric, overflow) →
       stderr "invalid --op-uid", exit EXIT_BAD_ARGS (7).
     - Reject == 0 explicitly: stderr "root op-uid rejected"
       exit EXIT_BAD_OP_UID (3).
     - getpwuid_r(op-uid) must return Some(_); else exit
       EXIT_BAD_OP_UID (3) with stderr "op-uid <N> not found in
       passwd".
     - Check op-uid is a member of the sandbox group via
       getgrouplist (or equivalent). THREE explicit cases:
         a. getgrouplist succeeds and sandbox-group gid is in
            the list → allow (continue to step 4).
         b. getgrouplist succeeds and sandbox-group gid is
            absent → stderr "op-uid not in sandbox group",
            exit EXIT_BAD_OP_UID (3).
         c. getgrouplist fails (errno-bearing — NSS service
            timeout, ENOMEM, EAGAIN, etc.) → stderr "op-uid
            group enumeration failed: errno <N>", exit
            EXIT_GENERIC (1).
       (c) is distinct from (b) so a flaky NSS layer surfaces
       as "internal error, retry" rather than "you don't have
       permission" — important on hosts with LDAP-backed NSS.

4. Validate --vm / --base where the subcommand has them.
     - Regex: ^[a-zA-Z0-9_-]{1,64}$
     - First character MUST NOT be '-' (defense in depth: regex
       allows '-' anywhere but a leading dash would be parsed as
       a flag by limactl).
     - Failure: stderr "invalid vm name" exit EXIT_BAD_ARGS (7).

5. Validate string args (--yaml, --src, --dst, --qemu-wrapper).
     - No interior NUL byte (CString::new check).
     - byte length <= libc::PATH_MAX (typically 4096 on Linux).
     - For --yaml, --qemu-wrapper, and the host-side portion of
       --src/--dst (the part NOT carrying the `<vm>:` prefix, if
       any): MUST begin with `/` (absolute path), MUST NOT contain
       any path component equal to `..`. Defense in depth — the
       kernel + post-setresuid uid enforce actual access, but
       rejecting relative and traversal paths catches daemon-side
       path-construction bugs cheaply.
     - The in-VM portion of --src/--dst (after the `<vm>:` prefix)
       is passed verbatim to limactl; the in-VM kernel enforces
       its own access. No host-side regex on it beyond byte
       sanity.
     - Numeric parse for integer flags (--op-uid, --cpus,
       --memory-mb, --memory, --disk, --start-timeout-s): use
       Rust's `str::parse::<u32>()`. Overflow / non-numeric →
       EXIT_BAD_ARGS (7) BEFORE range checks; range check
       failures (step 6) only run on successfully-parsed values.
     - Failure: stderr "invalid path arg: <reason>"
       exit EXIT_BAD_ARGS (7).

6. Subcommand-specific validation.
     - copy: at least one of --src / --dst must contain ':'
       (Lima's host:vm marker). The portion before ':' on that
       side must validate as a vm name per step 4. At most one
       ':' per side. Failure → EXIT_BAD_ARGS (7) with stderr
       "copy requires a <vm>: prefix on at least one side" or
       "copy: malformed <vm>: prefix".
     - start:
         - --hardened: literal "0" or "1".
         - --memory-mb: u32 in 256..=262144 (256 MiB to 256 GiB).
         - --cpus: u32 in 1..=64.
         - --start-timeout-s: u32 in 1..=600 (1 second to
           10 minutes). Maps to `limactl start --timeout=<N>s` —
           load-bearing for SSH-reachability wait inside limactl;
           do not drop. Daemon's `run_with_timeout` wraps this
           helper invocation as a host-side wall-clock kill, but
           the in-limactl wait is a separate concern.
         - --bridge-name (optional): regex
           ^[a-zA-Z0-9_-]{1,15}$ (Linux IFNAMSIZ-1 max, no dots —
           the current daemon's bridge names don't use dots; if a
           future config introduces dot-bearing bridges, update
           this regex and the corresponding generator together).
         - --vm-mac (optional): regex
           ^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$. After regex,
           parse the first octet hex and reject if the LSB
           (multicast bit) is set — QEMU/qemu-bridge-helper
           rejects multicast MACs downstream, so failing fast
           with EXIT_BAD_ARGS beats a confusing limactl error
           mid-startup.
         - --bridge-name and --vm-mac MUST be supplied together
           or omitted together (mirrors the daemon's existing
           `if let (Some(bridge), Some(mac))` pairing at
           `lima.rs:519-522`). Supplying exactly one →
           EXIT_BAD_ARGS (7) with stderr "--bridge-name and
           --vm-mac must be supplied together".
     - clone:
         - --cpus: u32 in 1..=64.
         - --memory: u32 in 1..=256 (GiB).
         - --disk: u32 in 1..=1024 (GiB).
     - stop:
         - --force: bool flag (present or absent). Parser rejects
           `=value` / trailing-value forms (e.g. `--force=true`,
           `--force 1`); mirrors route-helper's flag-parser at
           `sandbox-route-helper/src/main.rs:583-595`.
     - **Unit alignment note:** `start --memory-mb 262144` and
       `clone --memory 256` express the same physical cap
       (256 GiB == 262144 MiB), in different units. The daemon's
       `mib_to_gib_string` (`lima.rs:1416`) does the conversion
       for the clone path. Keep both caps in sync if either is
       bumped.
     - Any range / regex failure: EXIT_BAD_ARGS (7) with stderr
       naming which flag failed.

7. Resolve limactl absolute path.
     - pw_dir is captured once during step 3's getpwuid_r and
       reused here — re-resolving would expose a TOCTOU window
       against NSS state churn (nscd flush, LDAP update). The
       captured value is stable per helper invocation; this is
       a defense, not a bug.
     - Try in order, first existing-and-executable wins:
         a. <pw_dir>/.local/bin/limactl
         b. /usr/local/bin/limactl
         c. /usr/bin/limactl
     - Order is a deliberate contract: operator-local first
       allows per-operator limactl version pinning (operators
       who shim `~/.local/bin/limactl` accept responsibility
       for the resulting session behaviour). System paths
       fall back when no operator-local override exists.
     - All three are absolute. No PATH lookup. No '~' expansion.
       Existence + executable bit checked via stat() + access(_, X_OK).
       Note: stat() follows symlinks; an operator-controlled
       symlink at `~/.local/bin/limactl` resolves through to
       whatever it points to (operator-owned by definition, so
       no escalation surface — the operator could exec that
       binary themselves outside the helper).
     - None found → stderr "limactl not found for operator <uid>"
       exit EXIT_LIMACTL_NOT_FOUND (6).

8. Drop to operator uid.
     - setresuid(op-uid, op-uid, op-uid).
     - Failure: stderr "setresuid(<uid>) failed: errno <N>"
       exit EXIT_SETRESUID_FAILED (4).

9. Capability self-clear (defense in depth).
     - Four sequential `caps::clear` calls per the spawn-helper
       precedent at `sandbox-spawn-helper/src/main.rs:460-466`:
       Permitted, Effective, Inheritable, Ambient — each a
       fallible call. Implementer should mirror that pattern
       for consistency across helpers, not roll a raw `capset()`
       libc call.
     - After setresuid(non-root) in step 8, the kernel SECBIT
       rules already drop permitted+effective; the explicit
       clear is grep-able contract.
     - Failure semantics: partial clear failure is a HARD DENY,
       not a fall-through. After step 8 the helper is already
       running as the operator uid with permitted+effective
       dropped by the kernel; a capset failure here means the
       explicit ambient drop did not land, so we refuse to exec.
       This is correct — never exec with unverified ambient
       state. A misbehaving cgroup OOM / process-state perturbation
       between steps 8 and 9 surfaces as EXIT_CAPSET_FAILED, which
       is itself a safety guarantee (no elevated-priv path can
       continue), not a regression.
     - Failure: stderr "capset clear failed: <reason>"
       exit EXIT_CAPSET_FAILED (5).

10. Build sanitised env block.
      - From the parent env, inherit only:
          PATH, LANG, LC_ALL, HOME, TERM.
      - Set hardcoded:
          LIMA_HOME=/var/lib/sandboxd/<op-uid>/lima/
      - For `start` only, additionally set the six QEMU env vars
        from validated flag values (per the `start` subcommand
        table above). These are built from typed flags, not from
        env pass-through.
      - No other env vars survive.

11. Final exec (or step-sequence for install-guest-agent).
      - execvpe(<resolved-limactl>, <subcommand-specific argv>,
        <env block>).
      - argv built from compile-time-constant tokens + validated
        flag values; daemon contributes zero argv tokens beyond
        the typed flags.
      - On execvpe failure: stderr "execvpe(<limactl>) failed:
        errno <N>" exit EXIT_GENERIC (1).
      - For install-guest-agent: see that subcommand's step
        sequence. Each fork+exec+waitpid; first non-zero wins;
        successful completion → exit 0.
```

The helper sets `LIMA_HOME` to the per-operator path in every exec'd
environment (step 10). This is defense in depth: the daemon should
also set it, but pinning it inside the helper guarantees that
helper-pivoted limactl can never wander into another operator's
home, even if the daemon's env propagation regresses.

### Interface: exit codes

```
EXIT_GENERIC           = 1   // argv parse / execvpe failed
EXIT_NOT_SANDBOX       = 2   // getuid != sandbox-user uid, or caller not in sandbox group
EXIT_BAD_OP_UID        = 3   // --op-uid == 0, not in sandbox group, or unresolvable
EXIT_SETRESUID_FAILED  = 4
EXIT_CAPSET_FAILED     = 5
EXIT_LIMACTL_NOT_FOUND = 6
EXIT_BAD_ARGS          = 7   // bad vm name, malformed paths, range violation, missing/unknown flag, etc.
```

Distinct codes let the daemon (and integration tests) map rejection
categories without parsing stderr. Stderr message disambiguates
sub-cases (e.g. `EXIT_BAD_ARGS` covers both "bad vm name" and
"memory out of range" — the message names which).

### Non-features

The following is mirrored verbatim as a code comment block in the
helper crate's `main.rs`:

```
// NON-FEATURES — DO NOT ADD without revisiting the threat model.
//
// * No argv pass-through to limactl. Every flag the helper passes
//   to limactl is hardcoded inside this binary per subcommand;
//   daemon contributes only the typed flag values, by position.
//
// * No reading of sessions.db, sandboxd.sock, or any daemon state.
//   The helper is a pure setresuid + validate + exec pivot.
//
// * No general `shell --` subcommand. The only `limactl shell …`
//   invocations the helper performs are the hardcoded guest-socat
//   pump and the six steps of install-guest-agent (whose argvs are
//   compile-time constants). A future contributor needing a
//   different in-VM command must add a fresh typed subcommand.
//
// * No root op-uid. Even with cap_setuid, the helper refuses
//   --op-uid 0 explicitly.
//
// * No cap_chown. POSIX ACLs on /var/lib/sandboxd/<op-uid>/lima/
//   handle file ownership; the chown-bracket pattern of
//   sandbox-spawn-helper does not exist here.
//
// * No path content validation. Byte-level sanity only (no NUL,
//   length <= PATH_MAX). The kernel + post-setresuid uid enforce
//   what the operator can actually read or write.
//
// * No PATH lookup. limactl is resolved via three absolute paths
//   in a hardcoded order. No shell expansion. No '~' expansion.
//
// * Two timeouts, distinct concerns. start's --start-timeout-s
//   maps to limactl's internal SSH-reachability wait. The
//   daemon's run_with_timeout wraps the *helper invocation*
//   and is a host-side wall-clock kill. Both layers exist.
//
// * No JSON-on-stdin protocol. The helper takes argv only; no
//   stdin parsing. stdin is ignored (left open for inheritance
//   to the exec'd child where it matters, e.g. guest-socat).
//
// * No soft fallback to direct daemon-uid limactl. The daemon
//   either resolves a usable helper at startup or refuses to
//   come up.
```

### Daemon integration

#### Helper resolver

`sandboxd/src/main.rs` adds `resolve_lima_helper_path()` parallel to
`resolve_spawn_helper_path()`:

* Env override: `$SANDBOX_LIMA_HELPER_PATH` (when set, uses this
  path exclusively; missing or un-cap'd → daemon refuses startup
  with a clear log).
* Canonical install path: `/usr/local/libexec/sandboxd/sandbox-lima-helper`.
* Cap check: `cap_setuid` in the file's Permitted set. Inner helper
  `resolve_lima_helper_path_from(env_var: &str, canonical: &Path,
  is_usable: F)` is unit-testable and mirrors spawn-helper's
  `resolve_spawn_helper_path_from` / `is_usable` shape at
  `sandboxd/src/main.rs:809`.
* Returns `Result<PathBuf, SandboxError>` — there is no soft
  fallback. Daemon startup fatals on resolution failure. Error
  variant: `SandboxError::Internal` with a message naming the
  failure mode ("helper not found", "helper missing cap_setuid",
  "env override path unusable"). The daemon's `main()` propagates
  this as a non-zero exit (systemd service-level failure with a
  clear journal line).

#### Install requirements

The daemon expects `/var/lib/sandboxd/` to exist at startup as
`sandbox:sandbox 0750`, parallel to today's `/var/lib/sandbox/`
(note the trailing `d`; the two paths are distinct). The installer
(`scripts/install.sh`) must create it during `make setup-dev-env`,
and any runbook documentation for production deploys must mention
it. If absent at daemon startup, the daemon attempts to create it;
failure (EACCES) is a fatal startup error.

`/usr/local/libexec/sandboxd/` must also exist and be readable by
uid `sandbox`. Files inside need world-execute (`0755`) — the
helper, after `setresuid(operator)`, must still be able to `execvp`
the guest-binary path. Files installed there:

* `sandbox-lima-helper` (this binary, mode 0755, file caps
  `cap_setuid+ep`).
* `sandbox-spawn-helper` (existing, mode 0755, file caps downgraded
  to `cap_setuid+ep` per implementation order step 8a).
* `sandbox-route-helper` (existing, unchanged).
* `sandbox-guest` (the in-VM agent, mode 0755, no file caps — copied
  INTO the VM by `install-guest-agent`).

#### Per-operator LIMA_HOME setup

Daemon-side, before the first helper invocation for a given operator
uid, the daemon ensures the operator's LIMA_HOME exists and carries
the correct ACL:

1. `mkdir -p /var/lib/sandboxd/<op-uid>/lima/` (created as
   `sandbox:sandbox 0750`).
2. Apply a non-default access ACL `u:<op>:rwx` for operator traversal
   and a default ACL that denies group and other — but **no** default
   named-user entry — via a `setfacl` shell-out wrapped in the
   daemon's existing `run_with_timeout` envelope. Concrete invocation:

   ```
   setfacl -m u:<op-uid>:rwx,d:g::---,d:o::--- /var/lib/sandboxd/<op-uid>/lima/
   ```

   (numeric uid form, no NSS round-trip; the daemon already has the
   operator's uid from the session row.) The default named-user entry
   `d:u:<op-uid>:rwx` is intentionally omitted: it would force the
   POSIX ACL mask onto `_config/user`, surfacing in the key's group
   bits so OpenSSH `StrictKeyfileMode` rejects it (see § Privilege
   model). The operator-pivoted `limactl create` writes the key 0600
   under the helper's `umask(0o077)`; owner bits alone satisfy OpenSSH. The `acl` crate is rejected
   here — unmaintained since 2021, links against `libacl1`/`acl-dev`
   at build time, and a security-load-bearing operation should not
   depend on an unmaintained crate. `setfacl` is parallel to the
   existing `Command::new(...)` patterns in
   `sandbox-core/src/lima.rs`. Failure modes (binary missing, EPERM
   on path) classified via the typed-error envelope.

   **Note:** the key file `_config/user` inside this dir does NOT
   receive an ACL — it is created by helper-pivoted `limactl create`
   running as the operator, ends up owned operator:operator mode
   0600, satisfying OpenSSH `StrictKeyfileMode` via plain
   `st_mode`/owner match. ACL is only on the parent dir for
   traversal; the key file itself stays at vanilla unix permissions.

Idempotent; safe to re-run.

#### Per-operator base-image build serialization

Each operator's first session-create builds that operator's golden
base image (5-10 minutes). Concurrent session-creates from the same
operator must not race against a half-built base image. The daemon
serialises this via a per-operator-uid mutex: `LimaManager` is
parameterised by `op-uid` (one logical instance per operator) and
its `build_base_image` path holds a per-instance lock for the
duration of the build. Different operators build independently;
same operator queues.

Concurrent session-creates across *different* operators are not
affected — each operator's LIMA_HOME, base image, and lock are
isolated.

**Ownership model:** the Lima backend (daemon-level, replaces
today's single shared `Arc<LimaManager>`) holds an internal
`Mutex<HashMap<u32, Arc<LimaManager>>>` keyed by operator uid. On
the first `LimaManager`-needing call for a given operator, the
backend creates the per-op-uid entry and stores it; all subsequent
calls for the same operator reuse it (so the build-base-image mutex
inside a `LimaManager` actually serialises across calls). Entries
persist for the daemon's lifetime — memory footprint is small (one
`LimaManager` per active operator). No eviction policy in this
milestone; future work may add LRU eviction once operator counts
grow.

**Test fixtures:** `LimaManager::with_limactl_path` (~18 call sites
in `sandbox-core/src/lima.rs` test modules) is renamed to
`with_helper_path` and accepts a stub helper path for hermetic
tests. Tests that exercised direct daemon-uid `limactl` invocations
are obsolete under the new model and should be deleted; their
coverage moves to the integration suite against the setcap helper.
See implementation order step 9 / step 11 for the migration plan.

#### Session-context call sites

For every session-context limactl call (per the inventory table):

1. Daemon loads `Session` via `SessionStore::get_session(id,
   caller_name)`.
2. Extracts `session.operator_uid` (must be `Some` — pre-V008 rows
   are not supported under the new model; the migration to
   per-op LIMA_HOME requires an operator uid on every active
   session).
3. Ensures the operator's LIMA_HOME exists with the correct ACL.
4. Constructs the helper argv with `--op-uid <uid>` plus the
   subcommand's other typed flags. **Value sources for the
   non-trivial flags:**

   | Flag                          | Source                                                                                                                  |
   |-------------------------------|-------------------------------------------------------------------------------------------------------------------------|
   | `start --start-timeout-s`     | existing `START_VM_TIMEOUT` constant at `sandbox-core/src/lima.rs:21` (currently 300s). Pass `as_secs() as u32`.         |
   | `start --qemu-wrapper`        | daemon's resolved QEMU wrapper path (today set as env var, now passed as typed flag).                                   |
   | `start --hardened`            | session config / runtime defaults exactly as today (just delivered via typed flag instead of env-var pass-through).     |
   | `start --memory-mb`           | session config / runtime defaults (typed flag form).                                                                    |
   | `start --cpus`                | session config / runtime defaults (typed flag form).                                                                    |
   | `start --bridge-name --vm-mac`| optional, paired; from session config / runtime defaults (typed flag form).                                             |
   | `clone --cpus`                | session config.                                                                                                          |
   | `clone --memory` (GiB)        | session config.                                                                                                          |
   | `clone --disk` (GiB)          | session config.                                                                                                          |
   | `stop --force`                | only set in `build_base_image_inner`'s graceful-then-force fallback path; never set elsewhere.                          |

5. Spawns the helper via `spawn_blocking` (one-shot subcommands) or
   `tokio::process::Command` (long-lived `guest-socat`).

#### Backend transport integration

`LimaTransport::connect` (`sandbox-core/src/backend/lima.rs:647`) is
the long-lived async-I/O carve-out per `CLAUDE.md`. Today it calls
`Command::new(self.manager.limactl_path())` directly. Under the new
model:

* `LimaManager::limactl_path()` (`lima.rs:319`) is removed. Nothing
  inside the daemon resolves limactl directly anymore; resolution
  happens helper-side post-setresuid.
* `LimaManager` gains a `helper_path: PathBuf` field, set at
  construction from `resolve_lima_helper_path()`.
* `LimaTransport` gains an `operator_uid: u32` field, captured at
  construction. New constructor signature:

  ```rust
  pub fn new(manager: Arc<LimaManager>, operator_uid: u32) -> Arc<Self>
  ```

  The old `spawn_helper_path: Option<PathBuf>` parameter is removed
  (helper resolution lives on `LimaManager::helper_path` now; the
  Lima path no longer touches spawn-helper at all). Data-flow:
  session-create handler captures `operator_uid` from the `Session`
  row → threads through `RuntimeStartArgs` → `SessionRuntime` →
  `LimaManager::guest_transport(operator_uid)` →
  `LimaTransport::new(manager, operator_uid)`.
* `LimaTransport::connect` builds its `tokio::process::Command` as
  `Command::new(&self.manager.helper_path)`
  `.arg("guest-socat").arg("--op-uid").arg(self.operator_uid.to_string()).arg("--vm").arg(&self.vm_name)`
  — no change to the async-stdio carve-out, just a different argv0
  + arg set. The helper `execvp`s limactl after setresuid,
  inheriting the daemon's tokio pipes through the helper's own
  process and into limactl's stdio.

#### Host-side path construction

Every host-side filesystem operation that today targets
`LimaManager`'s host-global `base_dir` (`/var/lib/sandbox/.lima/`)
must redirect to `/var/lib/sandboxd/<op-uid>/lima/...`. Concrete
sites to rewrite:

* `template.yaml` writes at `lima.rs:344-345` and `:404-405`.
* `base-image-meta.json` writes at `lima.rs:1296`.
* `session_dir` builds at `lima.rs:2006`.
* Any other path concatenation off `LimaManager`'s host-global
  `base_dir`.

`LimaManager` is parameterised by `op-uid` (per the implementation
order step 8): one logical `LimaManager` instance per operator,
holding the operator's LIMA_HOME path. All host-side path
construction goes through that per-instance field, never a
host-global constant.

`relax_lima_instance_perms` (`lima.rs:692`) becomes dead code under
per-operator LIMA_HOME + ACLs: `limactl create` (helper-pivoted,
running as operator) writes files as the operator directly, so the
chmod-widening step has no purpose. Implementer deletes the function
and the call sites at `lima.rs:387, 440, 1450`.

#### Startup orphan scan (`v006_scan_lima_vms`)

Under per-operator LIMA_HOMEs, no single `limactl list --json`
enumerates every VM. The daemon's orphan scan at startup:

1. Queries `SELECT DISTINCT operator_uid FROM sessions WHERE
   operator_uid IS NOT NULL`.
2. For each uid, invokes `sandbox-lima-helper list-json --op-uid
   <uid>` and parses the NDJSON.
3. Merges results, `warn!`-logs each `sandbox-`-prefixed VM whose
   session row no longer exists.

Stays best-effort warn-only; adds a few seconds at startup if many
operators have sessions. Failure of any per-operator call does not
fatal startup — the scan is purely advisory.

#### Proxy port lookup (`ssh_local_port_for_session`)

Daemon already knows the session's `operator_uid` from the row.
Invokes `sandbox-lima-helper list-json --op-uid <uid>` once per
lookup, parses, filters to the target vm name.

### Call-site inventory

All paths are relative to `/home/olek/Projects/claude-sandbox/sandboxd/`.

Every row maps to a `sandbox-lima-helper` subcommand: **no row
survives as a direct daemon-uid limactl invocation.**

| File:line | Today's invocation | Maps to subcommand |
|---|---|---|
| `sandbox-core/src/lima.rs:360` (`LimaManager::create_vm`) | `limactl create --name <vm> <yaml> --tty=false` | `create` |
| `sandbox-core/src/lima.rs:417` (`LimaManager::create_vm_with_custom_template`) | `limactl create --name <vm> <dest> --tty=false` | `create` |
| `sandbox-core/src/lima.rs:497–526` (`LimaManager::start_vm`) | `limactl start <vm> --tty=false --timeout=<N>s` + 4–6 QEMU env vars | `start` |
| `sandbox-core/src/lima.rs:549` (`LimaManager::stop_vm`) | `limactl stop <vm> --tty=false` | `stop` |
| `sandbox-core/src/lima.rs:578` (`LimaManager::delete_vm`) | `limactl delete --force <vm> --tty=false` | `delete` |
| `sandbox-core/src/lima.rs:616` (`LimaManager::cleanup_partial_lima_instance`) | `limactl delete --force <vm> --tty=false` | `delete` |
| `sandbox-core/src/lima.rs:794` (`LimaManager::install_guest_agent` step 1) | `limactl copy <host_path> <vm>:/tmp/sandbox-guest` | `install-guest-agent` (subsumed) |
| `sandbox-core/src/lima.rs:815, 842, 872, 900, 926` (`install_guest_agent` steps 2–6) | 5× `limactl shell <vm> -- sudo …` | `install-guest-agent` (subsumed) |
| `sandbox-core/src/lima.rs:2032` (`install_guest_agent_by_vm_name` step 1) | `limactl copy <host_path> <vm>:/tmp/sandbox-guest` | `install-guest-agent` (subsumed — see § Notes on the table re: duplicate-function unification) |
| `sandbox-core/src/lima.rs:2053, 2080, 2110, 2138, 2164` (`install_guest_agent_by_vm_name` steps 2–6) | 5× `limactl shell <vm> -- sudo …` | `install-guest-agent` (subsumed — same as above) |
| `sandbox-core/src/lima.rs:1136` (`build_base_image` create) | `limactl create --name <base> <yaml> --tty=false` | `create` |
| `sandbox-core/src/lima.rs:1168` (`build_base_image` cleanup) | `limactl delete --force <base>` | `delete` |
| `sandbox-core/src/lima.rs:1185` (`build_base_image_inner` start) | `limactl start <base> --tty=false --timeout=<N>s` + QEMU env | `start` |
| `sandbox-core/src/lima.rs:1238` (`build_base_image_inner` stop graceful) | `limactl stop <base> --tty=false` | `stop` |
| `sandbox-core/src/lima.rs:1266` (`build_base_image_inner` stop -f fallback) | `limactl stop -f <base> --tty=false` | `stop --force` (mirrors current daemon behaviour exactly) |
| `sandbox-core/src/lima.rs:1319` (`validate_base_provisioning` probes) | `limactl shell --tty=false <base> command -v <tool>` × 4 | folded into `install-guest-agent` validation phase (see § Notes) |
| `sandbox-core/src/lima.rs:1357` (`rebuild_base_image` delete) | `limactl delete --force <base> --tty=false` | `delete` |
| `sandbox-core/src/lima.rs:1408` (`LimaManager::clone_vm`) | `limactl clone <base> <vm> --cpus <N> --memory <G> --disk <D>` | `clone` |
| `sandbox-core/src/lima.rs:2198` (`LimaManager::list_vms_raw`) | `limactl list --json` | `list-json` |
| `sandbox-core/src/backend/lima.rs:647` (`LimaTransport::connect`) | `limactl shell <vm> -- socat - TCP:127.0.0.1:5123` | `guest-socat` |
| `sandboxd/src/proxy_http.rs:289` (`pump_lima` → `ssh_local_port_for_session`) | indirect via `list_vms_raw` | `list-json` |
| `sandbox-core/src/store.rs:320` (`v006_scan_lima_vms`) | `Command::new("limactl").args(["list", "--json"])` | `list-json` (looped per operator uid — see § Daemon integration) |

#### Notes on the table

* **Base image now lives in the operator's LIMA_HOME**, not the
  daemon's. `build_base_image` and `build_base_image_inner` are
  helper-pivoted exactly like per-session VMs. The disk cost (one
  base image per operator) is accepted; the alternative
  (world-readable shared base) was rejected to keep the
  filesystem-isolation story uniform.
* **`limactl stop -f` (force) is expressed as an optional `--force`
  flag on the `stop` subcommand**, mirroring today's daemon
  behaviour exactly. `build_base_image_inner`'s
  graceful-then-force-fallback sequence stays intact: graceful
  `stop` first, then `stop --force` on timeout. The helper's
  `delete` subcommand also implies force-stop (`limactl delete
  --force` always works on a running VM); the two are distinct
  because force-stop alone does not destroy the VM dir.
* **`validate_base_provisioning`'s 4 `command -v <tool>` probes** are
  folded into the `install-guest-agent` subcommand as a final
  validation phase (the probes always run against a freshly-agent-
  installed base VM and only make sense in that context). They are
  not a separately invokable subcommand.
* **`install_guest_agent` and `install_guest_agent_by_vm_name` are
  duplicate sequences** (the former takes `&SessionId`, the latter
  takes `&str vm_name`; both run the same six-step install). They
  must be unified into a single daemon-side caller of the new
  `install-guest-agent` subcommand before (or as part of) this
  migration — otherwise an implementer rewriting one copy leaves
  the other as a raw daemon-uid `limactl` call path, silently
  violating the "daemon never invokes limactl directly" decision.

## Persisted state forward-compat

### V008 schema

**Migration:** `sandbox-core/migrations/V008__add_operator_uid.sql` —
adds `operator_uid INTEGER NULL` and `operator_gid INTEGER NULL` to
`sessions`. Forward-only; nullable for back-compat (pre-V008 rows
deserialize with both fields `None`).

**V008 is already shipped and applied.** This migration landed during
M18-S1..S9 (the SO_PEERCRED capture path below shipped with it). It
contains only the two `ADD COLUMN` statements and **no `DELETE`**. Its
header comment still references the abandoned supervisor-fork-as-operator
design — stale, and corrected when the cutover migration lands (below).
Because refinery is forward-only and checksums every applied migration,
the hard-break `DELETE` **must not** be added by editing V008 in place
(that trips a divergent-checksum error on every DB already at V008); it
lands as a **new** migration. See § Migration cutover.

**Column references the helper-pivoting daemon code uses:**

* `operator_uid` — column 11 in `row_to_session`
  (`sandbox-core/src/store.rs:1911`).
* `operator_gid` — column 12 (`store.rs:1912`).

**Session struct:** `Session { operator_uid: Option<u32>,
operator_gid: Option<u32>, … }`. Round-trip covered by
`test_operator_uid_gid_round_trip_with_values` and `…_with_none`.

**Capture path:** custom acceptor wraps `tokio::net::UnixListener`,
reads `SO_PEERCRED` on every accepted connection, resolves
`getpwuid_r(uid).pw_name`, constructs `OperatorIdentity { uid, gid,
name }` (`sandbox-core/src/caller_identity.rs`), attaches as axum
`Extension` for every request. Session-create handler
(`sandboxd/src/main.rs:~2966`) threads `(uid, gid)` into
`RuntimeStartArgs::operator_identity`, which
`SessionStore::create_session_with_backend` (`store.rs:588`) stamps
onto the row at INSERT.

`SO_PEERCRED` is the authoritative source. The session row's
`operator_uid` persists across daemon restarts so recovery does not
re-resolve identity from NSS.

### Migration cutover (V009 hard break)

The cutover is a **hard break**: legacy session rows that predate the
operator-uid contract are deleted, not preserved or backfilled. Because
V008 (which added the columns) is already applied in the field, the
`DELETE` cannot be folded into V008 — it lands as a **new forward-only
migration** `V009__drop_legacy_operatorless_sessions.sql`.

Rationale: the project is pre-1.0; legacy sessions reference VMs
in the old host-global `LIMA_HOME` (`/var/lib/sandbox/.lima/`),
which the new daemon does not use; their `_config/user` is
daemon-owned, which the new helper-pivoted model rejects; and
operator uid cannot be recovered from on-disk state (today's VM
dirs are uniformly daemon-uid-owned, so there is no signal to
backfill from). Quarantining them in-DB and refusing operations
would add deny branches that buy nothing operationally — the
sessions are not usable either way.

`V009__drop_legacy_operatorless_sessions.sql` contains:

```sql
-- Hard break: legacy sessions cannot run under the new
-- cross-user model (no recoverable operator uid, VMs in
-- the wrong LIMA_HOME). Drop them.
DELETE FROM sessions WHERE operator_uid IS NULL;
```

V009 applies cleanly on a DB already at V008 (refinery sees a new,
higher-numbered migration — no checksum divergence on the existing
V008). **V008 is left byte-for-byte untouched** — refinery checksums
the full migration file, so even a comment-only edit would trip the
divergence check on applied DBs. The correction for V008's stale
supervisor-fork header therefore lives in V009's own header comment,
which notes that V008's columns predate this spec and that the
operator-uid contract is completed here.

After migration: every surviving session row has `operator_uid IS
NOT NULL`, and the daemon-side assertion "session.operator_uid must
be Some" (§ Daemon integration / Session-context call sites) is
satisfied unconditionally.

On-disk VMs from deleted sessions become orphans under the **old**
`LIMA_HOME` path; the startup orphan scan (which only looks at
per-operator LIMA_HOMEs under the new model) does not see them.
Operator-facing impact: any session previously created under the
old daemon must be recreated via `sandbox create` after upgrade.
Documented in `docs/internal/milestones/M18.md` upgrade-notes
section.

The old `LIMA_HOME` at `/var/lib/sandbox/.lima/` becomes abandoned
filesystem state. Operators may delete it manually post-upgrade; a
one-time `make uninstall-legacy-lima` target in the Makefile is
OPTIONAL — implementer adds it if cleanup ergonomics matter, skips
it otherwise (the directory takes disk space but does not interfere
with the new daemon).

## Security considerations

### Trust model

`sandbox-lima-helper` is the load-bearing privileged surface for
every Lima control-plane operation under the new model. It is
daemon-only by construction: the `getuid() == sandbox-user-uid`
check at step 1 of the universal entry sequence is a kernel-checked
gate, strictly stronger than the pair-membership check
`sandbox-spawn-helper` uses today. The `sandbox` user is a system
user with no interactive login; reaching `getuid() == sandbox-uid`
requires already being able to run code as the daemon. The
additional `sandbox` group membership check is a sanity assertion,
not the load-bearing barrier.

The helper's design goal is "stupidly simple, auditable" — per
`CLAUDE.md`'s privilege-model paragraph, the privileged surface
should be ~50-100 lines per capability, separately reviewable, and
tightly scoped. `sandbox-lima-helper` lands inside that envelope:
hand-rolled argv parser (no clap), no daemon-state access (no
sessions.db, no socket, no shared memory), no flag pass-through
(every limactl flag is hardcoded by subcommand and indexed by
position from typed values), no JSON-on-stdin protocol, no
streaming I/O. The only privileged primitive is `setresuid`, used
exactly once per invocation, after every input has been validated.

### Threat analysis

**Compromised daemon.** A daemon-level compromise that can already
read `sessions.db` already has cross-operator read access by virtue
of the database row containing every operator's `operator_uid` and
session metadata. Adding `sandbox-lima-helper` does not change this
attack surface — the helper is not the load-bearing barrier between
operators. What the helper does change is the privilege model
*for daemon-spawned processes*: under the chown-bracket model a
compromised daemon with `cap_chown` could chown arbitrary files in
the per-VM dir; under the helper-pivoted model the daemon has no
caps at all, and a compromise gets only the daemon's uid (`sandbox`)
which has no `cap_setuid` and cannot pivot to other operators on
its own.

**Cross-operator pivot containment via op-uid validation.** The
helper rejects `--op-uid 0` explicitly (step 3, `EXIT_BAD_OP_UID`)
even with `cap_setuid` — no root op-uid path exists. The op-uid
must `getpwuid_r` to `Some(_)` (unresolvable uid is a deny) and
must be a member of the `sandbox` group (step 3, three-case
distinction). A compromised daemon attempting to pivot to an
unintended operator must already know that operator's numeric uid
and that operator must already be a member of `sandbox` — i.e. the
attacker has either read the sessions.db (which already gave them
that operator's identity) or guessed correctly. The deny branches
are not a security primitive in their own right; they are the
"check the obvious things before exec'ing as a different user"
hygiene that prevents accidental misuse.

**NSS failure mode.** The three-case distinction at step 3 (getgrouplist
succeeds + in group, getgrouplist succeeds + not in group,
getgrouplist fails) matters on hosts with LDAP-backed NSS. Conflating
"NSS timeout" with "not in group" would surface a flaky LDAP server
as a per-operator authorisation failure ("you don't have permission")
rather than a retryable internal error. Operators of such hosts must
be able to tell the two apart at the exit-code level.

**TOCTOU on `pw_dir` reuse.** Step 7 reuses the `pw_dir` value
captured during step 3's `getpwuid_r` rather than re-resolving it.
The captured value is stable per helper invocation; re-resolving
would expose a window during which nscd flush, LDAP update, or
similar NSS state churn could change the resolved path. This is a
defense, not a bug.

**Capset-partial-failure as hard deny.** Step 9's capability
self-clear is a hard deny on partial failure, not a fall-through.
After step 8 the helper is running as the operator uid with
permitted+effective dropped by the kernel; a capset failure here
means the explicit ambient drop did not land. The rule is "never
exec with unverified ambient state" — `EXIT_CAPSET_FAILED` is a
safety guarantee (no elevated-priv path can continue), not a
regression. A misbehaving cgroup OOM or process-state perturbation
between steps 8 and 9 surfaces here cleanly.

**PATH / symlink handling.** Step 7 resolves limactl via three
absolute paths in a hardcoded order; no PATH lookup, no `~`
expansion. `stat()` follows symlinks, so an operator-controlled
symlink at `~/.local/bin/limactl` resolves through to whatever it
points to. This is intentional: the operator could exec that
binary themselves outside the helper, so the helper following a
symlink the operator owns does not extend their capability.
System-path fallback (`/usr/local/bin`, `/usr/bin`) is always
available and not operator-overridable.

**`--vm-mac` multicast-bit early reject.** Step 6's MAC validation
parses the first octet's hex and rejects if the LSB (multicast bit)
is set. QEMU/qemu-bridge-helper rejects multicast MACs downstream;
catching it early surfaces a clear `EXIT_BAD_ARGS` rather than a
confusing limactl error mid-startup.

## Non-goals

This spec explicitly does not deliver:

* A shell wrapper or argv pass-through to limactl. Every flag the
  helper passes to limactl is hardcoded per subcommand.
* A general one-shot exec path (no equivalent of
  `sandbox-spawn-helper`'s caller-controlled `runtime_argv`).
* Any reading of sessions.db, `sandboxd.sock`, or daemon state from
  inside the helper.
* A general `shell --` subcommand. The only `limactl shell …`
  invocations the helper performs are the hardcoded guest-socat
  pump and the six steps of `install-guest-agent`.
* Root operator uid. `--op-uid 0` is rejected explicitly even with
  `cap_setuid`.
* The `cap_chown` file capability. POSIX ACLs replace the
  chown-bracket pattern entirely.
* Path content validation beyond byte-level sanity (NUL check,
  `PATH_MAX`, absolute-path/no-`..` for host-side paths). The
  kernel + post-setresuid uid enforce what the operator can
  actually read or write.
* PATH lookup or `~` expansion for limactl resolution.
* A `--timeout` host-side flag from the daemon. `--start-timeout-s`
  is now typed and required on `start`; the daemon's
  `run_with_timeout` wraps the helper invocation as a separate
  host-side wall-clock kill.
* JSON-on-stdin protocol. The helper takes argv only; stdin is
  ignored except for inheritance to the exec'd child where it
  matters (`guest-socat`).
* A soft fallback to direct daemon-uid limactl. The daemon either
  resolves a usable helper at startup or refuses to come up.
* Per-operation policy beyond session ownership + sandbox-group
  membership.
* GUI integration changes (VS Code Remote-SSH, JetBrains Gateway).
  The 2026-05-24 cross-user spec covers these via the generated
  ssh-config; this spec does not alter that surface.
* A streaming-protocol design for non-SSH exec. Out of scope —
  the `sandbox exec` path keeps its existing daemon-mediated
  guest-agent transport.
* A shared read-only base image with qcow2 operator-specific
  overlay files. One base image per operator (~2-5 GB; ~50 GB for
  ten active operators on one host) is the accepted cost of
  filesystem-isolation uniformity. A future disk-efficiency
  optimization could collapse the footprint via overlays without
  weakening isolation, but it is not part of this milestone and
  the per-operator base is the committed design point, not a
  stopgap.
* A fleet-wide `rebuild-all-bases` admin command. When the base
  template changes (kernel update, new pre-installed tool), each
  operator's base rebuilds independently — lazily, on that
  operator's next session-create that hits the
  validation-mismatch path (the existing `rebuild_base_image`
  flow, now per-operator). A single command that rebuilds every
  operator's base at once is a genuine future operability feature,
  not a gap in this milestone.

## Open questions

None. Every question raised during design and the two review
passes has been resolved into the contract above:

* The fate of `sandbox-spawn-helper` is resolved, not deferred —
  the helper-pivot of the Lima path removes its only caller, and
  the implementation **fully removes** the `sandbox-spawn-helper`
  crate (not merely its `--prepare-lima-spawn` form) once the
  call-site audit confirms no remaining consumer. See § Phases →
  spawn-helper removal.
* Per-operator base-image disk footprint and the golden-image
  upgrade story are settled design points recorded under
  § Non-goals, not unknowns.
* VS Code Remote-SSH / JetBrains Gateway need no re-verification:
  this spec does not touch the proxy/ssh-config path those tools
  consume (delivered and verified under the 2026-05-24 spec at
  M18-S9); the helper pivot is below that layer.

## Phases / Implementation order

Not prescriptive — listed for handoff continuity. An implementer's
own ordering is fine as long as the contract above is honoured.

### Phase 0 — pre-migration unification (prerequisite)

Unify the two `install_guest_agent` functions at `lima.rs:773`
(public, `&SessionId`) and `lima.rs:2015`
(`install_guest_agent_by_vm_name`, `&str`) into a single shared
method. Both run the same six-step install sequence and have
already drifted once. Without this unification, an implementer
rewriting one caller leaves the base-image build path on raw
daemon-uid `limactl` invocations, silently violating the "daemon
never invokes limactl directly" architectural decision.

**Unified signature:**

```rust
fn install_guest_agent(&self, op_uid: u32, vm_name: &str)
    -> Result<(), SandboxError>
```

The `binary_path: &Path` parameter from today's
`install_guest_agent` is removed — the helper hardcodes
`SANDBOX_GUEST_HOST_PATH`. Public name stays `install_guest_agent`;
the `_by_vm_name` variant is deleted entirely. Existing
`&SessionId`-passing callers adapt via `vm_name(session_id)`
(already exists). Folding the duplicate is mechanical (same body,
different argument shape) and unlocks step 9.

### Phase 1 — crate scaffold

`sandboxd/sandbox-lima-helper/Cargo.toml` + `src/main.rs`, mirroring
`sandbox-spawn-helper/` structure. Wire into workspace `Cargo.toml`.
Add the `test-env-override` Cargo feature seam for user/group name
pins AND for the `SANDBOX_LIMA_HELPER_TEST_GUEST_BINARY_PATH`
override.

### Phase 2 — argv parser + 9 subcommands

Each subcommand has a typed param struct; reject unknown / missing /
repeated flags and extra positionals at parse time. Per-subcommand
unit tests for parser shape only. Bool flags (`--force` on `stop`)
reject `=value` and trailing-value forms (mirror route-helper's
parser at `sandbox-route-helper/src/main.rs:583-595`).

### Phase 3 — validators

vm-name regex, copy `<vm>:` syntax, path-arg byte sanity +
absolute-path + no-`..`, op-uid range + non-root + group membership
(with the 3-case NSS distinction from § Universal entry sequence
step 3), numeric ranges for start/clone, interface-name and MAC
regexes (with multicast-bit check). All pure functions, fully
unit-testable.

### Phase 4 — limactl path resolver

Hardcoded three-candidate sequence keyed off
`getpwuid_r(op-uid).pw_dir`. Parameterised `is_executable` callback
for unit tests (mirrors `resolve_spawn_helper_path_from`'s
`is_usable` shape).

### Phase 5 — privilege flow

`getpwnam_r("sandbox")` + getuid check, group-membership check,
`setresuid_strict`, capability self-clear (four `caps::clear` calls
per spawn-helper precedent), env-block construction (allow-list +
`LIMA_HOME` + per-subcommand additions), `execvpe` (or step-sequence
for `install-guest-agent`). Integration tests against the
setcap-installed binary — hermetic unit tests cannot exercise
setresuid.

### Phase 6 — `install-guest-agent` step sequence

Six hardcoded limactl invocations via fork+exec+waitpid, followed
by four `command -v` probes. Unit tests for the deterministic argv
construction (including the single-quoted heredoc terminator per §
`install-guest-agent` step 4) and the `REQUIRED_BASE_TOOLS`-drift
assertion test. Integration tests for end-to-end behaviour against
a real VM.

### Phase 7 — daemon resolver

`resolve_lima_helper_path()` in `sandboxd/src/main.rs`, parallel to
spawn-helper. Returns `Result<PathBuf, SandboxError>` (no soft
fallback). Hard-error on resolution failure at daemon startup.

### Phase 8 — per-operator LIMA_HOME plumbing

Daemon-side `mkdir` of `/var/lib/sandboxd/<op-uid>/lima/` +
`setfacl` shell-out at first-touch. `LimaManager` parameterised by
`op-uid` (per-operator LIMA_HOME) rather than a single host-global
instance. Add a per-operator-uid mutex around base-image build so
concurrent first-session-creates from the same operator serialise.

### Phase 8a — spawn-helper removal (concurrent with phase 8)

`sandbox-spawn-helper` exists today solely to support the Lima
chown-bracket (`--prepare-lima-spawn`). The helper-pivot of the
Lima path removes its only caller. This phase **removes the crate
entirely**, not merely its `--prepare-lima-spawn` form — there is
no open question left to defer.

Step 1 — audit callers. Confirm the only consumer is the Lima
start path (`sandbox-core/src/lima.rs:463`, the
`spawn_helper_path: Option<&Path>` parameter on `start_vm`). The
container backend achieves cross-user uid alignment via Docker's
own `--user` mediation, not via spawn-helper, so it is not a
consumer. If the audit unexpectedly finds a non-Lima consumer,
that consumer must be migrated to `sandbox-lima-helper` (or an
equivalent narrow helper) in this same session — the spawn-helper
is removed regardless; nothing is left behind as a follow-up.

Step 2 — remove. Delete the `sandbox-spawn-helper` crate, its
workspace `Cargo.toml` member entry, its `make setup-dev-env`
install + setcap target, and the daemon-side
`resolve_spawn_helper_path()` resolver plus the `spawn_helper_path:
Option<&Path>` parameter threaded through `start_vm`. The
`cap_chown` file capability disappears with the binary (its only
consumer was the dead chown-bracket).

Exit: `rg sandbox-spawn-helper` returns zero hits in source,
Makefile, and systemd/contrib; the workspace builds without the
crate.

### Phase 9 — delete `relax_lima_instance_perms` and rewrite host-side path construction

Per § Host-side path construction: redirect every `LimaManager`
`base_dir` reference to the per-operator path; remove the
chmod-widening helper at `lima.rs:692` and its three call sites at
`:387, :440, :1450`. Rewrite remaining session-context call sites:
every row in the inventory becomes a helper invocation.
`LimaManager::limactl_path()` is removed; `LimaManager` gains a
`helper_path: PathBuf` field; `LimaTransport` gains an
`operator_uid: u32` field per § Backend transport integration.

**Test fixture migration:** every `with_limactl_path(...)` call
site in `sandbox-core/src/lima.rs` test modules (≈21 occurrences —
do not anchor on a count; the line list at lines 2531, 2623, 2672,
2708, 2785, 2823, 2858, 2906, 3064, 3105, 3152, 3174, 3204, 3256,
3428, 3680, 3718, 3827, 4030 is indicative, not exhaustive). Each
must:

* (a) migrate to a new `with_helper_path(...)` constructor that
  accepts a stub helper path, OR
* (b) be deleted as covering removed code paths (any test that
  exercises direct daemon-uid `limactl` invocations is obsolete;
  its coverage moves to the integration suite against the
  setcap-installed helper).

Done-condition is a **zero-residual grep**: `rg with_limactl_path`
returns no hits after migration. Implementer audits each site and
picks (a) or (b).

### Phase 10 — startup orphan scan rewrite

Loop per-operator-uid invocation of `list-json` with merged
results in `v006_scan_lima_vms`. Note bootstrap chicken-and-egg: a
fresh `sessions.db` (first daemon start ever) returns no operator
uids and runs no per-operator scan; orphans from an interrupted
prior daemon are not visible until after the first session-create
for that operator. Scan is advisory; this is acceptable.

### Phase 11 — tests

* Hermetic unit tests for parser, validators, resolver, and the
  `REQUIRED_BASE_TOOLS` drift assertion.
* Integration tests against the setcap-installed helper (parallel
  to `sandbox-spawn-helper`'s integration test pattern), covering
  each subcommand's privileged path and every deny branch
  (including the 3-case NSS distinction for op-uid group
  membership).
* E2E tests: two operators on one host, parallel sessions, each
  operator's `LIMA_HOME` and base image isolated.

### Phase 12 — docs

Update `docs/internal/milestones/M18.md` and the cross-user spec to
reference the new helper, its install path, and the per-operator
`LIMA_HOME` ACL convention. Update the `CLAUDE.md` "Privilege
model" bullet — today it mentions only `sandbox-route-helper`. Add
**`sandbox-lima-helper`** to the narrow-helper inventory; do **not**
add `sandbox-spawn-helper` — it is deleted in Phase 8a, so the
inventory lists `sandbox-route-helper` and `sandbox-lima-helper`
only. (An earlier draft of this phase said "add BOTH"; that
predated the decision to remove spawn-helper and is superseded.)
