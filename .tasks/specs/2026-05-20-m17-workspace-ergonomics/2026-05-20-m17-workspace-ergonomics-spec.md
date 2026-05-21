# M17 — Workspace ergonomics: shared guest path + `local:` mode

## Summary

This spec expands the M17 milestone in two directions on top of the
2026-05-14 9p `securityModel` work:

1. **Configurable guest path for `shared:`**, with the breaking-change
   default of *preserving the host path* inside the guest instead of
   always remapping to `/home/agent/workspace`.
2. **A new `local:` workspace mode**, which is a host-snapshot sync
   (rsync-based push on session create, plus operator-driven
   `sandbox workspace push` / `pull`) rather than a live bidirectional
   mount.

The `shared:<host>:<security-model>` grammar from the 2026-05-14 spec
becomes `shared:<host>[:<guest>][:<security-model>]`. A new
`local:<host>[:<guest>]` is parsed alongside. Default symbols default
to defaults that match user expectations: paths preserve, the security
model stays `mapped-xattr`, the `local:` filter set stays
gitignore-aware.

The project is pre-0.1.0 and the breaking default change for `shared:`
(guest path was historically hardcoded to `/home/agent/workspace`) is
explicitly accepted. Forward/backward-compat on disk is handled at the
serde layer, not via a database migration.

CLI shape:

```
sandbox create --workspace shared:<host-path>[:<guest-path>][:<security-model>]
sandbox create --workspace local:<host-path>[:<guest-path>] [--no-gitignore]
sandbox workspace push <session> {-f | -n} [--safe-links] [--no-gitignore]
sandbox workspace pull <session> {-f | -n} [--safe-links] [--no-gitignore] [--dest <path>]
```

One milestone (M17), four sessions: (S1) `shared:` parser + guest-path
+ securityModel; (S2) `local:` mode end-to-end with push/pull; (S3)
six-track review across both; (S4) spec-delivery verification.

## Motivation

### What the code does today

The Lima backend's 9p mount block is rendered from
`WorkspaceMode::Shared { host_path }`. Two things are hardcoded inline:

- The `securityModel` line (`mapped-xattr`) — covered by the
  2026-05-14 spec, already designed.
- The `mountPoint` (`/home/agent/workspace`) — uniformly remapped
  regardless of the operator's host path.

The container backend similarly anchors its bind-mount target at
`/home/agent/workspace/` (`backend/container.rs` →
`workspace_host_path` resolution and `--mount
type=bind,...,dst=/home/agent/workspace/`).

Both backends advertise only two workspace modes: `Shared` and
`Clone`. There is no host-snapshot mode — operators who want a
one-time `git clone`-shaped seed without the long-running 9p surface
end up running `sandbox cp` or `sandbox sync` against a freshly-created
session, which is workable but discoverability-poor and provides no
session-level record of "this session was seeded from `<host-path>`".

### What the change buys us

**Guest-path preservation.** A `shared:/home/user/project` invocation
gets the operator the *same* path inside the guest. This matters when
in-VM tooling (build systems, IDE indexes, editor jump-to-definition
records) bakes the working directory into emitted artefacts that the
host then reads back: a `compile_commands.json` referring to
`/home/user/project/src/main.c` resolves on the host without
translation; a stack-trace emitted from inside the VM is clickable in
the host IDE; the `pwd`-aware bits of build caches survive a
host↔guest round-trip. The historical "always `/home/agent/workspace`"
default lost this for free; the new default restores it. Operators who
specifically *want* the old behaviour pass an explicit guest path.

**`local:` mode.** `local:` is the explicit-sync sibling of `shared:`:
the daemon rsync-mirrors `host_path` into `guest_path` at session
create time, and `sandbox workspace push` / `pull` rsync the tree in
either direction on demand. Compared to `shared:`:

- No 9p (Lima) or bind-mount (container) device surface beyond what
  the rsync transport itself uses (`limactl shell` / `docker exec
  -i`). The guest sees normal local files in a normal local directory.
- Edits do not propagate live — desirable when the operator wants
  predictable snapshots, or wants the in-VM compiler to work against
  a copy without races against host edits.
- The host filesystem is not exposed for arbitrary guest read/write —
  the only host path the guest can affect is whatever the operator
  later `pull`s into.

Compared to `clone:`:

- Works for non-git trees (private packages, generated artefacts, mixed
  source/build directories).
- No network policy carve-out for the git host needed — the data
  travels over the same shell-transport rsync uses for `sandbox sync`.

## CLI shape

The `--workspace` flag value is a single colon-delimited string:

```text
shared:<host-path>[:<guest-path>][:<security-model>]
local:<host-path>[:<guest-path>]
```

Tokens after the mode prefix are optional but positional. The parser
disambiguates by content (`/` or `~`-prefix for path tokens, closed
enum for security-model tokens) rather than by position alone. See §
Parser for the full algorithm and grammar table.

`~` expands, but only on the CLI side of the wire:

- Host-side `~` resolves at parse time **only on the CLI invoking
  machine** (via `std::env::home_dir` equivalent), matching how shell
  expansion would behave if the operator typed the literal path. The
  CLI rewrites the `--workspace` value to carry an absolute host path
  before the request is sent to the daemon. The daemon parser rejects
  any unresolved `~` in `host_path` with an explicit error
  ("host_path must be absolute; CLI should have expanded `~` before
  sending"). This avoids the trap where the operator's `$HOME` is
  `/home/olek` but the daemon's `$HOME` is `/var/lib/sandbox` (the
  project convention has the daemon running as `sandbox:sandbox`):
  using a single parser on both sides with environment-dependent
  expansion would otherwise produce two different results from the
  same input string.
- Guest-side `~` is a **literal string replacement** to `/home/agent`
  — not a `$HOME` lookup inside the guest. The substitution runs at
  parse time and the resolved absolute path is what goes on the wire
  and into the session record. The choice of `/home/agent` is the
  canonical guest user home, hardcoded in the parser; the guest
  process environment is irrelevant to the rewrite.

Both sides store **resolved absolute paths** in the session record;
the `~` is never persisted. The serialised `WorkspaceMode::Shared` /
`WorkspaceMode::Local` payload always carries fully-qualified
absolute paths.

Examples (host `pwd` is `/home/user/proj` throughout):

```text
sandbox create --workspace shared:.
                  # ERROR — `.` is relative; both sides must be absolute or `~`-prefixed.

sandbox create --workspace shared:/home/user/proj
                  # host_path=/home/user/proj, guest_path=/home/user/proj,
                  # security_model=default (mapped-xattr).

sandbox create --workspace shared:~/proj
                  # host_path=/home/user/proj, guest_path=/home/user/proj.
                  # `~` resolves to the host user's home; the guest
                  # inherits the resolved host path because no
                  # explicit guest path was supplied. To get the
                  # historical /home/agent/... layout, pass an
                  # explicit guest path: `shared:~/proj:/home/agent/proj`.

sandbox create --workspace shared:~/proj:~/work
                  # host_path=/home/user/proj, guest_path=/home/agent/work.
                  # Host-side `~` resolves to the operator's `$HOME`
                  # on the CLI (e.g. /home/user) before the value
                  # goes on the wire; the daemon never sees a `~`.
                  # Guest-side `~` is a literal substitution to
                  # /home/agent — not a lookup inside the guest.

sandbox create --workspace shared:/home/user/proj:/srv/work
                  # host_path=/home/user/proj, guest_path=/srv/work,
                  # security_model=default.

sandbox create --workspace shared:/home/user/proj:none
                  # host_path=/home/user/proj, guest_path=/home/user/proj,
                  # security_model=none. (`none` is a model token, not a path —
                  # see § Parser.)

sandbox create --workspace shared:/home/user/proj:/srv/work:none
                  # host_path=/home/user/proj, guest_path=/srv/work,
                  # security_model=none.

sandbox create --workspace local:/home/user/proj
                  # local-snapshot, host=/home/user/proj, guest=/home/user/proj.

sandbox create --workspace local:/home/user/proj:/srv/work
                  # local-snapshot, host=/home/user/proj, guest=/srv/work.

sandbox create --workspace local:/home/user/proj --no-gitignore
                  # local-snapshot, initial push transfers gitignored files too.
```

The full flag value remains a single string on the wire — the
existing `CreateSessionRequest.workspace: Option<String>` DTO stays
unchanged.

### `--no-gitignore` on `sandbox create`

`--no-gitignore` is a top-level flag on `sandbox create` (not part of
the `--workspace` value). It is meaningful only when `--workspace`
resolves to `local:`; combined with any non-`local:` mode the daemon
rejects the request with `InvalidConfig` and the exact error string:

> `--no-gitignore is only meaningful for local: workspaces; this session uses <mode>:`

where `<mode>` is `shared` or `clone` depending on the parsed
`WorkspaceMode`. (`--repo` and `--workspace` are already mutually
exclusive at the clap surface via `conflicts_with`, so a
`--no-gitignore` + `--repo` combination is impossible to construct
on the CLI; the daemon error covers the case of a `--no-gitignore` +
`shared:` invocation and any non-CLI client that bypasses the clap
gate.)

The CLI pre-validates the same combination client-side and exits
with the equivalent message before the request goes on the wire —
fail-fast, mirroring the existing rsync-planner state-check pattern
in `sandbox-cli/src/main.rs`'s `plan_sync_command`. The daemon-side
check is the authoritative one (so a misbehaving CLI cannot bypass
the gate); the CLI-side check exists for operator latency only.

The flag drops the `--filter=':- .gitignore'` rule from the
initial-push rsync invocation (see § `local:` Mode). It is **not
persisted** to the session record — see § `--no-gitignore`
persistence below for the rationale and consequences.

### `--no-gitignore` persistence

The create-time `--no-gitignore` choice is **not** persisted to the
session record. It governs only the initial push at session-create
time; after creation, the flag has no ongoing semantics. Subsequent
`sandbox workspace push` / `pull` invocations carry their own
`--no-gitignore` flag — the operator's create-time choice does not
implicitly propagate forward.

Concretely, `SessionConfig` gains no `no_gitignore_on_create:
Option<bool>` field. The `--no-gitignore` value is consumed by the
create-time push code path and discarded thereafter; the only place
it is observable is the daemon's structured log line for the
initial-push rsync invocation (which records the actual rsync argv).

The create-time choice is **not retrievable** from `sandbox
describe`. Operators who want to remember whether they created a
session with `--no-gitignore` must consult their shell history; the
session record itself is the wrong place to carry per-invocation
flag state. The reasoning:

- The create-time push is a one-shot operation; the flag describes
  a transient input, not a persistent property of the session.
- Persisting the flag would imply "this session was created with
  `--no-gitignore`, so future push/pull invocations should default
  to that behaviour", which would surprise operators who expect
  their explicit flags to be authoritative on each invocation.
- The describe output already has enough variants to render
  (`shared` / `local` / `clone`; default vs explicit security
  model); adding a flag-derived field for `--no-gitignore`
  proliferates the surface without buying clarity.

### `sandbox workspace push` / `pull`

New subcommand group under `sandbox workspace`, alongside the existing
`sandbox cp` and `sandbox sync` top-level commands. The split is
intentional: `cp` and `sync` are generic file-movers that work on any
guest path on any session; `workspace push` / `pull` are
session-mode-aware and only mean something for `local:` sessions.

```text
sandbox workspace push <session> {-f | -n} [--safe-links] [--no-gitignore]
sandbox workspace pull <session> {-f | -n} [--safe-links] [--no-gitignore] [--dest <path>]
```

- `<session>` — session name or id, same resolution as every other
  per-session subcommand.
- `-f` / `--force` — required confirmation that the operator
  understands the mirror-with-delete semantics.
- `-n` / `--dry-run` — rsync's `--dry-run`; reports what *would*
  happen without writing. Mutually exclusive with `-f`.
- One of `-f` / `-n` is **required**. Bare `sandbox workspace push
  <session>` exits with a usage error pointing at the safety gate.
- `--safe-links` — by default, push/pull use `-L` to follow all
  symlinks (copying targets as regular files and directories). When
  `--safe-links` is passed, the `-L` default is dropped and rsync's
  `--safe-links` semantics apply instead: in-tree symlinks are
  preserved as symlinks on the destination; symlinks pointing
  outside the source tree are skipped entirely (no file, no symlink,
  no entry of any kind on the destination). Useful when the source
  tree contains symlinks to external locations that should not be
  dereferenced or transferred. The user-visible model is "default
  is `-L`; `--safe-links` opts out of dereferencing and protects
  against out-of-tree links".
- `--no-gitignore` — drops `--filter=':- .gitignore'` from the
  invocation. Includes gitignored files (typically `node_modules`,
  `.env`, build output) in transfer and in deletion consideration on
  the destination side.
- `--dest <path>` (pull only) — override the host destination path.
  Default: `host_path` recorded on the session at create time.
  Useful for pulling a snapshot to a sibling directory without
  clobbering the original. The `--dest` value follows the same
  absolute-or-`~`-expanded rule as `host_path` at create time.
  Semantics:
  - **`--delete` is always on** for both push and pull, regardless
    of `--dest`. The `-f`/`--force` gate is the destructive-op
    opt-in (the operator has already affirmed mirror-with-delete
    semantics by passing `-f`); `--dest` does not relax that gate.
    An operator who wants safe inspection of "what would change"
    uses `-n`/`--dry-run` first; `--dest` is not a way to escape
    the delete behaviour.
  - **Existing directory at `--dest`.** Contents-into-dir
    semantics: `<src>/...` lands at `<dest>/...`. Both source and
    destination carry trailing slashes (see § Push/pull commands
    → trailing-slash rule).
  - **Existing file at `--dest`.** Rejected with an error before
    rsync is spawned ("`--dest` <path> is an existing file; expected
    a directory or a non-existent path"). The CLI's `std::fs::metadata`
    check runs before argv construction.
  - **Missing parent directory.** The CLI calls
    `std::fs::create_dir_all(dirname(<--dest>))` before spawning
    rsync; rsync creates the leaf itself. So `--dest=/a/b/c` with
    neither `/a/b` nor `/a` existing creates `/a/b/` first, then
    rsync populates `c`.

Errors:

- Session not running → `error: session <id> is not running (state:
  <state>); start it first`. Exit code 1. The push/pull paths require
  the shell transport, which is only viable for running sessions.
- Session is not `local:` mode → `error: sandbox workspace push/pull
  only applies to local: workspaces; this session uses <mode>`. Exit
  code 2 (misuse, mirroring `clap`'s convention).
- Neither `-f` nor `-n` given → usage error, exit code 2.
- Both `-f` and `-n` given → usage error, exit code 2.

## Domain types

In `sandbox-core/src/session.rs`:

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum WorkspaceSecurityModel {
    #[default]
    #[serde(rename = "mapped-xattr")]
    MappedXattr,
    #[serde(rename = "none")]
    NoneMapping,
}

impl WorkspaceSecurityModel {
    pub fn as_yaml(&self) -> &'static str {
        match self {
            Self::MappedXattr => "mapped-xattr",
            Self::NoneMapping => "none",
        }
    }
}
```

The variant is named `NoneMapping` (not `None`) so it does not
visually collide with `Option::None` in `match` arms — `match
security_model { Some(WorkspaceSecurityModel::NoneMapping) => ... }`
is unambiguous in a way that `Some(WorkspaceSecurityModel::None)`
is not. The CLI token, JSON wire form, and rendered describe value
all stay `none` via the per-variant `#[serde(rename = ...)]`
attributes; the rename is a Rust-identifier-only change with no
user-facing impact. (The default `#[serde(rename_all =
"kebab-case")]` on the enum is replaced with per-variant renames
because `NoneMapping` would otherwise serialise as
`"none-mapping"`, which is not the desired wire form.)

```rust
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum WorkspaceMode {
    Shared {
        host_path: String,
        #[serde(default)]
        guest_path: String,           // see § Backward Compatibility
        #[serde(default, skip_serializing_if = "Option::is_none")]
        security_model: Option<WorkspaceSecurityModel>,
    },
    Clone {
        repo_url: String,
    },
    Local {
        host_path: String,
        #[serde(default)]
        guest_path: String,           // see § Backward Compatibility
    },
}
```

Both `guest_path` fields are *always* populated by the parser when
constructing a fresh `WorkspaceMode`. The `#[serde(default)]` exists
solely to handle legacy on-disk records — see § Backward Compatibility
for the custom-deserialiser shim that recovers `guest_path = host_path`
when the field is missing.

`WorkspaceModeKind` (the data-less companion used by
`Capabilities::workspace_modes`) gains a `Local` variant:

```rust
#[derive(Debug, EnumSetType, Serialize, Deserialize)]
#[enumset(serialize_repr = "list")]
#[serde(rename_all = "snake_case")]
pub enum WorkspaceModeKind {
    Shared,
    Clone,
    Local,
}
```

`WorkspaceMode::kind()` returns the matching variant. The container
and Lima backends both advertise `Local` in their
`workspace_modes` capability sets (see § Lima Backend, § Container
Backend).

**Forward-compat: unknown-variant tolerance on the wire.** The wire
serialisation of `EnumSet<WorkspaceModeKind>` (used by
`Capabilities::workspace_modes`, list-repr per the `#[enumset(
serialize_repr = "list")]` attribute above) **silently drops unknown
variants on deserialisation**. This is the forward-compat convention
for all `EnumSet`-typed capability fields exposed by the daemon.

Concretely: an older CLI built against a `WorkspaceModeKind` that
contains only `Shared` and `Clone`, when it receives
`["shared", "clone", "local"]` from a newer daemon, parses the
capabilities response successfully and exposes `{ Shared, Clone }`.
The unknown `"local"` entry is ignored; the response does not fail
to parse, and no other field on `Capabilities` is affected.

Implementation: either a custom `Deserialize` impl on the wire-side
wrapper (deserialising into `Vec<String>` first and filtering against
the known variants), or `#[serde(other)]` on a sentinel variant. The
choice is left to the implementer; the behavioural requirement is
"unknown variant on the wire → silently dropped, capability set
parse succeeds, the rest of the `Capabilities` response is unchanged".

This convention also extends to any other `EnumSet`-typed field that
may be added to `Capabilities` in future milestones.

## Parser

`WorkspaceMode::parse_flag` becomes the single entry point for the
extended grammar. The algorithm:

Normalization (applied to the input string before any other step,
in this order):

1. Trim leading and trailing ASCII whitespace from the whole input.
   `"shared:/srv/repo "` and `" shared:/srv/repo"` both parse the
   same as `shared:/srv/repo`. Internal whitespace is not touched
   and is preserved into `host_path` if present (it then fails the
   existence check, since paths with leading/trailing whitespace
   are vanishingly rare and the operator is most likely typing a
   typo).
2. The mode prefix is matched **case-sensitively** against the
   exact tokens `shared` / `clone` / `local`. `Shared:/srv/repo` is
   rejected with the existing "unknown workspace mode" error.
3. Trailing-slash stripping on `host_path` is deferred to step C
   (where the path is reassembled) — see step C below.

Algorithm:

1. **Mode prefix split.** Find the first `:`. The substring before is
   the mode (`shared`, `clone`, or `local`); the substring after is
   the `rest` payload. Reject unknown modes (or an empty mode
   prefix, e.g. `:/foo`) with the existing "unknown workspace mode"
   error. An input with no `:` at all (e.g. the literal `"shared"`)
   also yields this error — the mode prefix is required.
2. **Mode `clone:`.** Treat `rest` as the repo URL verbatim (no
   colon-tokenisation — git URLs contain colons). Return
   `Clone { repo_url: rest }`. Unchanged from current behaviour.
3. **Mode `shared:` / `local:`** — proceed to the colon-split below.

For the path-bearing modes, the grammar is positional but the parser
**right-to-left** classifies trailing tokens by content. Walking the
tokens right-to-left makes the path-token-with-colons case
(`/some/dir:none` as a literal path) at least observable rather than
silently mis-parsed:

```
tokens = rest.split(':')          # 1..=3 tokens for shared, 1..=2 for local
```

Step A — strip a trailing security-model token (shared only):

- If `len(tokens) >= 2` AND `tokens[-1]` ∈
  {`mapped-xattr`, `none`} AND mode is `shared`:
  consume `tokens[-1]` as `security_model`, leave the rest in
  `tokens`. Otherwise `security_model = None`.
- **Friendly-hint branch (shared only).** If `len(tokens) >= 2`
  AND `tokens[-1]` ∈ {`passthrough`, `mapped-file`} AND mode is
  `shared`: short-circuit with the explicit error
  "`passthrough` and `mapped-file` security models are not exposed;
  see `docs/guides/hardening.md`. Use `mapped-xattr` (default) or
  `none`." rather than folding the unrecognised model name into
  `host_path`. This is the one place where the parser pre-validates
  a suffix — the names are 9p security-model spellings, so an
  operator who types them clearly meant the security-model slot;
  surfacing the closed-enum boundary here is more useful than the
  generic "host_path does not exist" failure. See § Known Gaps for
  why other unrecognised suffixes are folded rather than hinted.

Step B — strip a trailing guest-path token:

- If `len(tokens) >= 2` AND `tokens[-1]` starts with `/` or `~`:
  consume `tokens[-1]` as `guest_path`, leave the rest in `tokens`.
  Otherwise `guest_path = None` (resolves to `host_path` at the
  resolution step below).
- For `shared:` this runs *after* step A, so the `:none` /
  `:mapped-xattr` form does not get mis-classified as a guest path
  (those tokens fail the `/`-or-`~` prefix check anyway, but the
  ordering is explicit).

Step C — the remaining tokens reassemble into `host_path`:

- `host_path = tokens.join(':')`.
- This is the only step that allows colons in the value, and it only
  happens when the trailing tokens were rejected as model/guest
  classifications. This is the documented compact-form footgun (see
  § Known Gaps): a literal host path of the form `/foo:none` cannot
  be expressed; the parser will see `host_path=/foo,
  security_model=Some(NoneMapping)`.
- **Trailing-slash strip.** After reassembly, a single trailing `/`
  on `host_path` is stripped (`/srv/repo/` → `/srv/repo`). The
  root path `/` is preserved. Multiple trailing slashes are
  collapsed to none (`/srv/repo//` → `/srv/repo`). This
  normalisation lives in `parse_flag` so the persisted
  `host_path` is canonical and round-trips through the renderer
  without churn. The same rule applies to `guest_path` when it
  was supplied via step B.

Step D — `~` expansion and absoluteness:

- `host_path` undergoes `~` expansion **only on the CLI side** (via
  `std::env`'s home dir, resolving to the operator's home). The
  daemon parser does NOT perform `~` expansion on `host_path`; it
  rejects any unresolved `~` with "host_path must be absolute; CLI
  should have expanded `~` before sending". This split keeps the
  parser a pure function on both sides while pinning the
  environment-dependent step to the side that actually has the right
  environment. See § CLI shape's `~` expansion paragraph for the
  rationale.
- `guest_path` undergoes `~` expansion on both sides as a literal
  string replacement to `/home/agent` — this is environment-free, so
  both the CLI and the daemon arrive at the same result.
- Both paths must be absolute after expansion. Reject with the
  existing "must be absolute" error otherwise.
- `host_path` must exist on the host (existing check). `guest_path`
  is not checked at parse time — it is created at session-creation
  time by the backend.
- **`local:`-only directory requirement.** When mode is `local`,
  `host_path` must additionally be a directory:
  `std::fs::metadata(path)?.is_dir()` must hold. A single-file
  `host_path` is rejected with a clear error pointing at
  `sandbox cp`: "host_path must be a directory for `local:`; to
  seed a single file, use `sandbox cp <file> <session>:<path>`
  after creating the session." `shared:` mode does not impose this
  extra check — the historical contract has always allowed
  whatever existence the host filesystem supports for `shared:`,
  and bind-mounts of single files are a legitimate (if niche)
  pattern.
- If `guest_path` was not provided in the input, set it equal to the
  resolved `host_path`.

Disambiguation rule (formal):

| Trailing token | Classified as       | Condition                                |
|----------------|---------------------|------------------------------------------|
| `mapped-xattr` | security model      | mode == `shared` AND `len >= 2`          |
| `none`         | security model      | mode == `shared` AND `len >= 2`          |
| `passthrough`  | friendly-hint error | mode == `shared` AND `len >= 2`          |
| `mapped-file`  | friendly-hint error | mode == `shared` AND `len >= 2`          |
| `/...`         | guest path          | starts with `/` (post-model-strip)       |
| `~/...`        | guest path          | starts with `~` (post-model-strip)       |
| anything else  | merges into host    | falls through to step C                  |

Note on unclassified trailing tokens: any token that fails every
classification rule above is **folded into `host_path` by step C**
(via `tokens.join(':')`). The parser does NOT pre-validate the
suffix or emit a "did you mean…?" diagnostic — instead the
host-path-exists check in step D rejects the resulting compound
path. This is the same compact-form footgun that the `/foo:none`
case exhibits in § Known Gaps, extended to arbitrary garbage
suffixes; both share one diagnosis ("`host_path` does not exist")
and one workaround (avoid colon-bearing host paths, or move the
directory). The exception to "no pre-validation" is the
`passthrough` / `mapped-file` early hint described in step A — see
that step for the rationale and behaviour.

Parser-unit-test matrix (minimum, see § Tests):

- `shared:/srv/repo` → `host=/srv/repo, guest=/srv/repo, model=None`
- `shared:/srv/repo:/srv/dest` → `host=/srv/repo, guest=/srv/dest, model=None`
- `shared:/srv/repo:mapped-xattr` → `host=/srv/repo, guest=/srv/repo, model=Some(MappedXattr)`
- `shared:/srv/repo:none` → `host=/srv/repo, guest=/srv/repo, model=Some(NoneMapping)`
- `shared:/srv/repo:/srv/dest:mapped-xattr` → full triple
- `shared:/srv/repo:/srv/dest:none` → full triple, `none` model
- `shared:~/proj` → `host=<HOME>/proj, guest=<HOME>/proj, model=None`
  (guest inherits the resolved host path; no explicit guest token)
- `shared:~/proj:~/work` → `host=<HOME>/proj, guest=/home/agent/work, model=None`
  (each `~` resolves against its own side)
- `shared:/srv/repo:bogus` → host has trailing colons accumulated;
  passes parse step C, then the host-path-exists check rejects.
  Parser does not pre-validate the suffix.
- `shared:/srv/repo:bogus:mapped-xattr` → tokens `[/srv/repo, bogus,
  mapped-xattr]`; step A consumes the trailing `mapped-xattr` as the
  security model; step B sees `bogus`, which does not start with `/`
  or `~`, and skips; step C folds the remainder into
  `host_path=/srv/repo:bogus`, `model=Some(MappedXattr)`, `guest`
  inherits the resolved host path. The host-path-exists check rejects
  `/srv/repo:bogus`. Documents that step-A consumption does not
  retroactively reclassify a non-path middle token.
- `shared:/srv/repo:/srv/dst:bogus` → tokens `[/srv/repo, /srv/dst,
  bogus]`; step A: `bogus` is not a model token, skip; step B:
  `bogus` does not start with `/` or `~`, skip; step C:
  `host_path=/srv/repo:/srv/dst:bogus`. The host-path-exists check
  rejects. Documents that an invalid trailing model name is folded
  into the host path rather than reported as "unknown model".
- `local:/srv/repo:bogus` → tokens `[/srv/repo, bogus]`; step A
  skipped (mode is `local`, not `shared`); step B: `bogus` does not
  start with `/`, skip; step C: `host_path=/srv/repo:bogus`. The
  host-path-exists check rejects.
- `local:/srv/repo` → `host=/srv/repo, guest=/srv/repo`
- `local:/srv/repo:/srv/dest` → `host=/srv/repo, guest=/srv/dest`
- `local:/srv/repo:none` → host-path-exists check rejects `/srv/repo:none`
  (no security model is meaningful for `local:`; the trailing
  `:none` is consumed into the host path).
- `shared:/srv/repo:passthrough` → step A's friendly-hint branch
  fires (see step A in § Parser): the parser returns
  "`passthrough` and `mapped-file` security models are not exposed;
  see `docs/guides/hardening.md`. Use `mapped-xattr` (default) or
  `none`." rather than folding `passthrough` into the host path.
- `shared:/srv/repo:mapped-file` → same friendly hint as
  `passthrough`.
- `""` (empty input) → "unknown workspace mode" error (mode-prefix
  split finds no `:`).
- `"shared"` (mode only, no colon) → "unknown workspace mode" error.
- `":/foo"` (empty mode prefix) → "unknown workspace mode" error.
- `shared:/srv/repo/` → trailing slash is **stripped** during
  parsing; resulting `host_path=/srv/repo`. Documents the
  normalization (see step C / step D normalization rules).
- `"shared:/srv/repo "` (trailing whitespace) → leading/trailing
  whitespace on the full input is **auto-trimmed** before parsing;
  resulting `host_path=/srv/repo`. Documents the normalization (see
  the normalization paragraph below).
- `Shared:/srv/repo` (mixed-case mode prefix) → "unknown workspace
  mode" error. Mode matching is **case-sensitive**.
- `clone:https://example.com/x.git` → unchanged.

The parser is a pure function returning `Result<WorkspaceMode,
String>`, parameterised on the caller side (CLI vs daemon) only to
the extent that the CLI performs host-side `~` expansion before
invoking it. CLI-side validation in `sandbox-cli/src/main.rs`
continues to call it directly so the operator sees parse errors
before the request goes on the wire; daemon-side validation calls
the same function (on the already-expanded payload) so a malformed
request body on the API surface is rejected at the same point. The
daemon parser path rejects any residual `~` in `host_path` with the
explicit error named in Step D — by construction this only fires if
the CLI failed to expand (a bug) or a non-CLI client constructed the
request directly.

## Backward Compatibility

`guest_path` is a new field on `WorkspaceMode::Shared`. Old
`config_json` records (written before this spec) carry `Shared
{ host_path: "..." }` without `guest_path`. Per CLAUDE.md "On-disk
compatibility" rules, the field is added with serde defaults so
legacy records continue to deserialise.

`#[serde(default)]` resolves to `String::default()` (empty string),
which is wrong for `guest_path` — the field is *load-bearing* (it
becomes the mount point); an empty value would let downstream code
construct a mount targeting `""`. Therefore the deserialisation is
not pure `#[serde(default)]`; a custom shim runs in the
deserialiser:

- Deserialise into a private mirror struct where `guest_path` is
  `Option<String>` with `#[serde(default)]`.
- Post-process: if `guest_path` is `None` or `Some("")`, set it to
  the value of `host_path`. This matches the historical semantics for
  any legacy `Shared` record (which always mounted at
  `/home/agent/workspace`) — except that the historical mount point
  was a fixed string, not `host_path`. The chosen recovery
  (`guest_path = host_path`) aligns the post-load record with the
  *new* default rather than the historical hardcoded value. The
  consequence: a legacy session resumed after a daemon upgrade will,
  on next start/restart cycle, see its workspace mounted at the host
  path inside the guest rather than at `/home/agent/workspace`.

This is acceptable because:

1. The project is pre-0.1.0; breaking changes have been explicitly
   accepted by the user.
2. A daemon-restart cycle for a `shared:` session already
   reconstructs the mount block from `WorkspaceMode::Shared`; the
   guest mount point only re-applies on the next VM/container start,
   which is an explicit operator action.
3. The session config record on disk has `host_path`; consequently
   the spec is fully recoverable without operator input.

A symmetric rule applies to `WorkspaceMode::Local`'s `guest_path`
(though no legacy records exist for `Local` — it's a new variant).
The custom deserialiser is shared between `Shared` and `Local` for
consistency.

No SQLite migration is added. The schema change lives entirely in the
JSON blob in `sessions.config_json`; the migration set in
`sandbox-core/migrations/` is untouched. This matches the CLAUDE.md
"persisted blob fields" rule.

### Forward-compat on rollback

- An older daemon (pre-this-spec) reading a record written by a newer
  daemon ignores the `guest_path` field on `Shared` entirely (unknown
  field; serde discards by default). The older daemon then mounts at
  its hardcoded `/home/agent/workspace`, which is its historical
  behaviour — no crash, no silent mis-mount. The operator who
  rolled back sees the workspace at the old path until they roll
  forward again.
- An older daemon reading a `WorkspaceMode::Local` record fails
  cleanly with serde's unknown-variant error — there is no
  `local` arm in the old enum. The session is unloadable until the
  daemon is rolled forward. This is the spec-accepted breaking-change
  envelope; documented in the upgrade notes (see § Docs Changes).

## `local:` Mode

### Lifecycle

`local:` is a one-shot-snapshot model with operator-driven refresh.
The lifecycle:

1. **Create** (`sandbox create --workspace local:<host>[:<guest>]`).
   The daemon stores `WorkspaceMode::Local { host_path, guest_path
   }` in the session record. The backend creates the VM/container,
   creates the parent directory of `guest_path` inside the guest,
   then runs an initial rsync push from `host_path` to `guest_path`.
   The push is **blocking**: if rsync exits non-zero, session
   creation fails (the session record is rolled back, the
   VM/container is torn down, the daemon returns `InvalidState` /
   `Internal` with the rsync stderr surfaced).
2. **Push** (`sandbox workspace push <session> -f`). Rsync from
   `host_path` to `guest_path`. The operator decides when to refresh.
3. **Pull** (`sandbox workspace pull <session> -f`). Rsync from
   `guest_path` to `host_path` (or to `--dest`).
4. **Delete** — no special handling; guest workspace contents go
   away with the VM/container as usual. The host directory is never
   touched on session deletion.

### Cancellation and timeout

The initial-push rsync runs inside the same blocking session-create
handler as VM/container provisioning. Three failure modes need
explicit semantics:

1. **Rsync non-zero exit during create.** The session is rolled back
   via the existing `cleanup_and_return!` macro in
   `sandboxd/src/main.rs`: the VM or container is torn down, the
   network teardown runs, the session record is removed from the
   store. Sessions are either complete or absent — there is no
   half-seeded `Running` state with a warning attached. (The
   alternative "leave the session Running and let the operator
   complete the seeding via `sandbox workspace push -f`" was
   considered and rejected: it splits the create contract into
   "complete" and "partially complete" buckets, complicates the
   describe-output story, and forces every downstream consumer of
   the session state machine to handle a new intermediate state.)
2. **Cancellation.** The daemon-side rsync is spawned via
   `tokio::process::Command`, **not** `std::process::Command`
   wrapped in `spawn_blocking`. The async-aware variant properly
   supports cancellation: when the request future is dropped (the
   CLI hits Ctrl+C, the daemon receives SIGTERM, the session-create
   timeout fires), the child process receives a `kill()` and exits
   cleanly. The cleanup macro then runs as for any other create
   failure.
3. **Timeout.** The rsync invocation runs inside the existing
   session-create timeout envelope. If rsync exceeds the timeout,
   the envelope's deadline cancellation fires `cleanup_and_return!`
   with an `Internal` response naming the rsync timeout (e.g.
   "initial rsync exceeded session-create timeout after Ns; session
   rolled back"). The operator's recovery path is documented below.

**Recovery for oversized trees.** If a session's source tree is
large enough to exceed the timeout envelope, the operator's path is
to create the session with a smaller subset (e.g. by adding entries
to `.gitignore` or by maintaining a `.local-only-ignore` sidecar
that the operator passes via custom rsync, etc.) and then add the
rest via `sandbox workspace push -f` after the session is up. The
push command is not subject to the session-create timeout — it runs
under the operator's terminal until it completes — so trees that
do not fit the create envelope can still be seeded incrementally.

### Default rsync invocation

The baseline flag set for both the create-time push and the
operator-driven push/pull commands:

```
rsync -aL --delete --filter=':- .gitignore' \
  -e <shell-transport> \
  <src> <dst>
```

Where:

- `-a` — archive (perms, ownership, times, group, recursion).
- `-L` (`--copy-links`) — follow symlinks during transfer, copying
  the resolved file rather than the link. Includes symlinks pointing
  outside the source tree. When `--safe-links` is passed on the
  push/pull commands, the `-L` default is dropped: in-tree symlinks
  are preserved as symlinks on the destination, and out-of-tree
  symlinks are skipped entirely. See § CLI shape for the full
  user-facing description.
- `--delete` — mirror semantics: destination entries absent on the
  source are deleted. Combined with `--filter=':- .gitignore'`, this
  means gitignored files on the destination are *protected* from
  deletion — see "filter interaction" below.
- `--filter=':- .gitignore'` — gitignore-aware filtering. The
  `:- .gitignore` is rsync's "per-directory merge-file, exclude
  matched entries" form. Matched files are excluded from both
  transfer and deletion consideration: if `node_modules` is in
  `.gitignore`, rsync neither pushes the source's `node_modules` nor
  deletes the destination's `node_modules`. Dropped by
  `--no-gitignore`.
- `-e <shell-transport>` — the backend's native shell as rsync's
  remote-shell transport (`limactl shell` for Lima, `docker exec
  -i` for container). Same pattern as `sandbox sync`.

Source/destination form for an upload push:

- `<src>` — host-side absolute path with trailing `/` (auto-appended
  when the source is a directory; see the `sandbox sync` planner's
  rationale for this convention).
- `<dst>` — `sandbox-<id>:<guest_path>/`.

Source/destination flip for pull.

**Trailing-slash rule (push and pull).** Both source and destination
always carry trailing slashes for `local:` push and pull. The
workspace is always a directory whose contents are mirrored — the
intended semantics is uniformly "mirror contents of A into B", and
the trailing-slash convention is what tells rsync to operate on the
directory's contents rather than the directory entry itself.
Concretely:

- **Push** (host → guest): `<host_path>/` → `sandbox-<id>:<guest_path>/`.
- **Pull** (guest → host): `sandbox-<id>:<guest_path>/` →
  `<host_path>/` (or `<--dest>/` when `--dest` is set).

The CLI ensures both ends carry trailing slashes before constructing
the rsync argv, regardless of whether the operator typed a path with
or without the slash. This includes `--dest`: a `--dest=/a/b`
invocation gets a `/a/b/` argv after the planner normalises it.
Uniform contents-into-dir semantics across every push/pull
combination.

### Filter interaction

A frequent question is "if `.env` is gitignored and I want it in the
guest, how do I get it there?". Two equally-acceptable answers,
documented as standard usage (not as gotchas):

1. **Use `--no-gitignore`** on the push: `sandbox workspace push <s>
   -f --no-gitignore` transfers everything, including `.env`.
2. **Copy it explicitly** with `sandbox cp ./.env
   <s>:<guest_path>/.env`. This is the right answer when the
   operator wants to keep the gitignored bulk (e.g. `node_modules`)
   off the guest but seed one specific file.

The gitignore default exists precisely to avoid transferring
`node_modules`, build artefacts, and similar — the same reason
`.gitignore` exists in the first place. Documenting both options as
ordinary usage avoids the "the default is wrong" trap.

### Rsync invocation: exit codes, stdio, ownership

The `-aL --delete --filter` baseline above leaves several invocation
details unstated; this subsection pins them.

1. **Exit codes.** All non-zero rsync exit codes are fatal — at
   create time (where they trigger `cleanup_and_return!` per §
   Cancellation and timeout) and on operator-driven push/pull
   (where they exit the CLI with the rsync exit code). Codes 23
   ("partial transfer due to errors") and 24 ("vanished source
   files") are **not** special-cased — they fail the operation just
   like catastrophic errors. The simpler "all-non-zero-fatal" rule
   keeps the contract uniform; operators who want partial-transfer
   tolerance can run rsync directly via the shell-transport
   escape hatch already documented in § Out of Scope.
2. **Stdout.** On the daemon-side initial push, rsync's stdout is
   captured and logged at INFO level on the daemon (so operators
   running with daemon log access see transfer summaries). On
   CLI-driven push/pull, stdio is inherited as the spec already
   states (the operator's terminal is the natural place for rsync's
   one-line completion summary).
3. **Stderr.** On the daemon-side initial push, stderr is captured;
   on non-zero exit, the captured stderr is surfaced verbatim in
   the daemon's error response so the operator sees rsync's own
   diagnostic (e.g. `rsync: command not found`, `permission denied`,
   `mkdir failed: EROFS`). On CLI-driven push/pull, stderr is
   inherited.
4. **`-z` / `--compress`.** Explicitly **not** passed. Local
   transport (`limactl shell`, `docker exec -i`) is not over a
   bandwidth-constrained link and does not benefit from rsync's
   compression — the CPU cost of compress/decompress exceeds the
   savings from a smaller wire payload on a loopback-class
   connection. Documented here explicitly so a reviewer comparing
   to a generic remote-rsync invocation does not second-guess the
   omission. (Mirrors the existing `plan_sync_command` convention.)
5. **Ownership semantics under `-a`.** The `-a` flag expands to
   `-rlptgoD`, which includes `-o` (preserve owner) and `-g`
   (preserve group). Rsync running unprivileged inside the guest
   (as the `agent` user, uid 1000) cannot chown files to other
   uids; rsync silently tolerates the chown failures and proceeds.
   Documented consequence: files inside the guest workspace are
   always owned by `agent`, regardless of the host file's
   ownership. This is the desired outcome (the guest user is
   the one who reads and writes the workspace inside the VM /
   container) and matches the existing `sandbox sync` contract;
   the `-a` flag is preserved unchanged.

### rsync prerequisites

The rsync binary must be present on both sides:

- **Host.** `sandbox` checks the local rsync exists when dispatching
  push/pull. If missing, the CLI emits "rsync not found on host;
  install rsync to use `sandbox workspace push/pull`" and exits 1.
- **Guest.** Both the Lima base image and the container ("lite")
  image already ship rsync (required for `sandbox sync`). The
  `local:` mode adds no new image dependency — the existing image
  prerequisite tightens from "rsync required for sync" to "rsync
  required for sync and `local:` mode". Documented in
  `docs/guides/workspaces.md` next to the `sandbox sync`
  prerequisite paragraph.
- **Version pin.** Both images ship rsync ≥ 3.2.7 (Ubuntu 24.04
  noble), which supports `--mkpath` (introduced in rsync 3.2.3).
  Implementers MAY use `--mkpath` for parent-dir creation;
  pre-create-via-shell is the fallback if the image's rsync is
  ever downgraded. Pinning the version here makes the
  `--mkpath`-vs-`mkdir -p` choice in § Parent-directory creation
  testable rather than implicit.

### Parent-directory creation

`guest_path` may live anywhere under `/` inside the guest. The
backend pre-creates `dirname(guest_path)` before the initial-push
rsync runs. Two equivalent implementations are acceptable:

- Pass `--mkpath` to the create-time rsync (rsync 3.2.3+). This
  delegates the parent creation to rsync.
- Pre-create via the backend's shell transport (`limactl shell
  sandbox-<id> -- mkdir -p <parent>` or `docker exec sandbox-<id>
  mkdir -p <parent>`).

Either works; the spec does not pin the choice. The implementer
picks whichever is simpler given the rsync version pinned in the base
images. If `--mkpath` is unavailable on either image, the pre-create
path is required.

For push/pull (post-create), the guest-side parent is already in
place; the host-side parent for `--dest` follows the same rule (the
CLI creates `dirname(--dest)` via `std::fs::create_dir_all` before
spawning rsync).

## Push/pull commands

See § CLI shape for the surface. Implementation notes:

- The push/pull planner is a sibling of `plan_sync_command` in
  `sandbox-cli`. It produces an `rsync ...` argv and `exec`s it with
  stdio inherited, the same way `sandbox sync` does today.
- The session resolution (name → id) and state check
  (must be Running) happen client-side before constructing the argv,
  to fail fast with operator-readable errors. The daemon-side
  validation happens too (so a misbehaving CLI can't bypass the
  state gate) but is redundant on the happy path.
- The session mode check (must be Local) happens by reading
  `GET /sessions/<id>` first, inspecting `workspace_mode`, and
  rejecting client-side if it's not local. The DTO already exposes
  `workspace_mode` as a rendered string (`render_workspace_mode`);
  parsing `local:` out of it is straightforward.
- `--dest` (pull only) defaults to the session's recorded
  `host_path`. The default is computed client-side from the same
  `GET /sessions/<id>` round-trip used for the mode check.
- `--dest <path>` follows the same CLI-only `~` expansion rule as
  `host_path` at create time: the CLI resolves any leading `~` to
  the operator's `$HOME` before constructing the rsync argv, so the
  daemon-facing surface and any persisted artefact carry only
  absolute paths. The invariant "the daemon never sees an
  unresolved `~`" holds uniformly across create-time and post-create
  paths.
- Argv layout, all variants:

  ```
  rsync -aL --delete --filter=':- .gitignore' \
    -e <shell> \
    [--dry-run|--mkpath] \
    [pass-through extras — none on push/pull surface] \
    <src> <dst>
  ```

  - `-L` swaps to `--safe-links` when `--safe-links` is passed.
  - `--filter=':- .gitignore'` drops when `--no-gitignore` is passed.
  - `--dry-run` appears when `-n` is passed.
  - The argv is constructed by the planner; no operator pass-through
    args are accepted on push/pull (unlike `sandbox sync` which
    accepts trailing `--`-separated rsync flags). This keeps the
    surface narrow and reviewable.

**Filter source asymmetry on push vs pull.** The gitignore filter
(`--filter=':- .gitignore'`) reads `.gitignore` from whichever side
is the rsync source: the host's `.gitignore` on push, the guest's
`.gitignore` on pull. Rsync's filter engine is source-relative either
way, so this is a property of rsync's contract rather than a choice
this spec makes. The practical implication: if the operator has
edited `.gitignore` inside the session without syncing it back to the
host (e.g. added a new ignore entry in the guest workspace), push
and pull will filter differently. Push uses the host's older
`.gitignore`, pull uses the guest's newer one. Operators wanting
symmetric filter rules between the two directions should keep the
two `.gitignore` files in sync (which a `push -f` from the host
naturally accomplishes, modulo the gitignore filter itself).

## Lima Backend

### Shared mount block

`shared:` mode renders the existing 9p mount block, with two
substitutions versus today:

- `mountPoint` is the resolved `guest_path` instead of the hardcoded
  `/home/agent/workspace`.
- `securityModel` is the resolved value (default `mapped-xattr`),
  per the 2026-05-14 spec.

Pseudocode at `sandbox-core/src/lima.rs` (the template render site):

```rust
match &config.workspace_mode {
    Some(WorkspaceMode::Shared { host_path, guest_path, security_model }) => {
        let safe_host = sanitize_yaml_path(host_path);
        let safe_guest = sanitize_yaml_path(guest_path);
        let model = security_model.unwrap_or_default().as_yaml();
        format!(
            "mountType: \"9p\"\n\
mounts:\n\
- location: \"{safe_host}\"\n\
  mountPoint: \"{safe_guest}\"\n\
  writable: true\n\
  9p:\n    securityModel: {model}\n    cache: mmap"
        )
    }
    _ => "mounts: []".to_string(),
}
```

The `sanitize_yaml_path` helper applies to both paths — the same
injection-prevention story the 2026-05-14 spec calls out for
`host_path` applies symmetrically to `guest_path`.

`cache: mmap` is unchanged, orthogonal to all of this.

### `local:` mode

`WorkspaceMode::Local` does *not* render a `mounts:` block in the
Lima template — there is no live mount. The template behaves
identically to a workspace-less session at template-render time
(`mounts: []`).

After the VM reaches Running, the backend:

1. Ensures `dirname(guest_path)` exists inside the VM (via
   `limactl shell sandbox-<id> -- mkdir -p <parent>` or `--mkpath`
   on the rsync below).
2. Runs `rsync -aL --delete --filter=':- .gitignore'
   [--no-gitignore-effect] -e 'limactl shell' <host_path>/
   sandbox-<id>:<guest_path>/`. Blocking; failure tears down the
   session.

`Capabilities::workspace_modes` for Lima becomes `{Shared, Clone,
Local}` — `EnumSet::all()` once `Local` joins the kind enum.

### Cache-path interaction

The daemon's session-create path picks between a fast cached-image
clone and a slow template-render boot. The current heuristic
(`sandboxd/src/main.rs`) keys on `has_shared_mount` and disables the
cache whenever a `Shared` workspace is configured, because the cached
golden image does not carry mount configuration. With three workspace
modes, the rule expands to:

- **`Shared`** (any `guest_path`, any `security_model`) — fast-path
  cache stays **disabled**. The 9p mount block must be
  template-rendered at boot; the cached golden image lacks the mount
  configuration regardless of whether the guest path is the default
  or explicit. Unchanged from current behaviour.
- **`Local`** — fast-path cache is **enabled**. The Lima template
  emits no `mounts:` block for `local:` mode (see § Lima Backend →
  `local:` mode), so the cached image is fully compatible. The
  post-create rsync runs after the VM reaches Running and is
  independent of how the VM was booted (cached clone vs template
  render). This saves the ~30s of template-render latency that the
  current rule imposes on every workspace-bearing session.
- **`Clone`** — unchanged (whatever the current fast-path/slow-path
  decision is for clone-mode sessions). This spec does not alter
  clone-mode cache eligibility.

Concretely, the `has_shared_mount` predicate in `sandboxd/src/main.rs`
expands to "is the workspace mode `Shared`?" — `Local` returns
`false` and remains cache-eligible, `Shared` returns `true` and forces
the slow path as today. The variable name should probably evolve with
the predicate (`workspace_requires_template_render` or similar), but
the underlying choice is mechanical.

### Daemon-side rsync orchestration

The create-time push is a daemon-side rsync invocation. CLAUDE.md's
"All `std::process::Command` calls in async handlers are wrapped in
`tokio::task::spawn_blocking`" rule has an explicit carve-out for
async-aware variants: the rsync spawn uses `tokio::process::Command`
directly, **not** `std::process::Command` wrapped in
`spawn_blocking`. The async-aware variant properly supports
cancellation — dropping the future or calling `child.kill()` cleanly
terminates the rsync child process — which is load-bearing for the
cancellation, daemon-SIGTERM, and session-create-timeout paths
described in § `local:` Mode → Cancellation and timeout.

Stdout/stderr are captured per § Rsync invocation: exit codes,
stdio, ownership: stdout is logged at INFO level on the daemon;
stderr is captured and, on non-zero exit, surfaced verbatim in the
daemon's `InvalidState` / `Internal` response so the operator sees
rsync's own error (e.g. `rsync: command not found`, permission
denied, EROFS on the container-rootfs case). The container backend
follows the same orchestration pattern via its own `docker exec -i`
transport.

## Container Backend

### Shared bind-mount

The container backend's bind-mount target gains the
`guest_path` substitution. The existing
`ContainerNetwork.workspace_host_path: Option<PathBuf>` widens to a
struct (or a tuple/option pair) that also carries the guest-side
mount point:

```rust
pub struct WorkspaceBind {
    pub host_path: PathBuf,
    pub guest_path: PathBuf,
}
// or: workspace_host_path -> workspace_bind: Option<WorkspaceBind>
```

The `--mount` argv at `backend/container.rs:521` becomes:

```rust
format!(
    "type=bind,src={},dst={}",
    bind.host_path.to_string_lossy(),
    bind.guest_path.to_string_lossy(),
)
```

`security_model` on `WorkspaceMode::Shared` is meaningless for the
container backend (no 9p layer). Per the 2026-05-14 spec, the
container backend rejects `Some(_)` with `InvalidConfig` and a
message naming `security_model`. `None` is accepted.

The bind-mount target may now be any guest path. Docker normally
auto-creates the mountpoint directory for a `--mount` target, but
the container image runs with `--read-only`, which forbids new
directories on the rootfs. If `guest_path` is not under an existing
writable mount (i.e. `/home/agent` via the home volume, or
`/tmp`/`/run` via tmpfs), `docker create` rejects the mount with a
clear error referencing the unwritable target. The recommended idiom
documented in `docs/guides/workspaces.md` is to keep `guest_path`
under `/home/agent` on the container backend; operators who need a
path outside this envelope should use the Lima backend.

### `local:` mode

`WorkspaceMode::Local` produces *no* bind-mount on the container
backend. The `docker create` argv has no `--mount` for the workspace
(it still carries the home-volume bind and the guest-binary bind).

After the container starts:

1. `docker exec sandbox-<id> mkdir -p <dirname(guest_path)>` (or
   `--mkpath` on rsync).
2. `rsync -aL --delete --filter=':- .gitignore' -e 'docker exec -i'
   <host_path>/ sandbox-<id>:<guest_path>/`. Same flags, same
   blocking-on-create-failure semantics as Lima.

`Capabilities::workspace_modes` for container becomes `{Shared,
Clone, Local}`. The existing `EnumSet::all()` continues to express
the full set once the kind enum gains the third variant.

### Read-only rootfs interaction

The container ("lite") image is launched with `--read-only`. The
writable surfaces the image actually exposes — and therefore the
viable destinations for a `local:` rsync write or a `shared:`
bind-mount target — are:

- **`/home/agent/...`** — Docker volume mount, owned by uid 1000
  (the `agent` user). Rsync running as `agent` can freely `mkdir`
  subdirectories anywhere under this prefix; the home volume is the
  primary writable area.
- **`/tmp/...`** — tmpfs.
- **`/run/...`** — tmpfs.

Everything outside this set sits on the read-only rootfs and is not
writable.

For `local:` mode, a `guest_path` outside the writable set fails at
rsync time with EROFS: the parent-dir creation step (`mkdir -p` or
rsync `--mkpath`) cannot create directories on the read-only rootfs.
The daemon does **not** pre-validate the `guest_path`-vs-rootfs
constraint — the relevant writable paths depend on the image (the
home-volume mount point and the tmpfs locations are part of the image
contract, not the daemon's), and the rsync EROFS error names the
offending path directly.

Two practical patterns:

1. **Default `guest_path = host_path` with a host path outside the
   writable set**. The operator hits the EROFS failure on create;
   they retry with an explicit `:guest_path` inside `/home/agent`,
   `/tmp`, or `/run`.
2. **Explicit `:<guest_path>` inside the writable set**. Works for
   any host path. The `/home/agent` choice is the recommended idiom
   for persistent work (the home volume survives restarts);
   `/tmp/...` and `/run/...` are legitimate ephemeral choices for
   `local:` mode where the operator wants tmpfs-backed work — fast,
   ephemeral, useful for build-heavy workloads that fit in RAM. The
   default `guest_path = host_path` will not land on tmpfs unless
   the operator explicitly sets a tmpfs path.

Documented as the recommended idiom in
`docs/guides/workspaces.md`'s `local:` section.

## `sandbox describe`

The describe output today renders `Workspace:` as a single string
produced by `render_workspace_mode`, which formats as `shared:<host>`
or `clone:<url>`. With three variants and additional fields, the
renderer expands into a multi-line block per workspace.

### Wire surface

`SessionConfigDto` grows a new optional field
`workspace_mode_detail: Option<WorkspaceModeDetailDto>` carrying the
structured workspace fields. The legacy `workspace_mode: Option<String>`
flat-string field is **retained** for back-compat with existing JSON
consumers; the daemon populates both fields from the same in-memory
`WorkspaceMode`. New consumers (including the in-tree CLI) read
`workspace_mode_detail` and ignore the flat string; old consumers
keep working unchanged.

The new DTO type is **explicit** — per the
`feedback_api_dto_separation` memory note ("API responses must be
explicit DTOs, not flattened domain structs"), the wire shape is a
purpose-built DTO mirroring (but not equalling) the domain
`WorkspaceMode`:

```rust
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum WorkspaceModeDetailDto {
    Shared {
        host_path: String,
        guest_path: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        security_model: Option<WorkspaceSecurityModelDto>,
    },
    Clone {
        repo_url: String,
    },
    Local {
        host_path: String,
        guest_path: String,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum WorkspaceSecurityModelDto {
    #[serde(rename = "mapped-xattr")]
    MappedXattr,
    #[serde(rename = "none")]
    NoneMapping,
}
```

`WorkspaceSecurityModelDto` is a parallel DTO type that mirrors
`WorkspaceSecurityModel`'s wire form (`mapped-xattr` / `none`) but
lives on the API surface in `sandbox-core/src/api/dto.rs`, separate
from the domain enum in `sandbox-core/src/session.rs`. The two are
kept in lock-step by the mapper; the duplication is the cost of the
DTO-vs-domain split required by the memory note.

The flat `workspace_mode` string field continues to render as
before:

- `shared:<host_path>` — default guest path, no security-model
  override (`security_model = None`).
- `shared:<host_path>:<guest_path>` — explicit guest, no
  security-model override.
- `shared:<host_path>:<security_model>` — default guest, explicit
  `Some(_)` security model.
- `shared:<host_path>:<guest_path>:<security_model>` — full triple,
  explicit `Some(_)` security model.
- `clone:<repo_url>` — unchanged.
- `local:<host_path>` / `local:<host_path>:<guest_path>` — new.

The "skip default values for compactness" rule applies **only to
`Option::None`**: a `security_model` of `None` (no override
specified) renders without the `:<security-model>` token, but any
`Some(_)` value renders the token verbatim regardless of whether
its inner variant happens to match `WorkspaceSecurityModel`'s
`#[default]`. This preserves explicit operator intent — a
`Some(MappedXattr)` set deliberately at create time round-trips
through the renderer and `parse_flag` back to `Some(MappedXattr)`,
not collapsed to `None`. The DTO field `Option<WorkspaceSecurityModel>`
is faithful to the wire-rendered string in both directions. An
output string round-trips through `parse_flag` to the same
`WorkspaceMode`.

Cross-version skew on the wire surface:

- **Older client, newer daemon.** The unknown `workspace_mode_detail`
  field is ignored cleanly (serde's default behaviour for unknown
  fields on a `Deserialize`-derived struct). The client continues to
  read the flat `workspace_mode` string as today.
- **Newer client, older daemon.** The new client sees
  `workspace_mode_detail = None` and falls back to printing the flat
  `workspace_mode` string verbatim — matching today's CLI behaviour.

### `sandbox describe` rendering

The CLI renders the `Workspace:` block by reading
`SessionConfigDto.workspace_mode_detail` directly. No re-parsing on
the CLI side, no `parse_flag` call on the display path: the
structured fields arrive structured, the renderer formats them.
This avoids the host-path-existence-check failure that re-parsing
would impose when the CLI runs on a different machine from the
daemon (e.g. host paths recorded by the daemon that do not exist on
the operator's laptop), and removes a parser dependency from the
display code.

If `workspace_mode_detail` is absent (an older daemon talking to a
newer CLI), the CLI falls back to printing the flat-string
`workspace_mode` verbatim on the single-line form
(`Workspace:   shared:/home/user/proj`), matching today's behaviour.
The multi-line block format only renders when the structured detail
is available.

The `Config:` block in `render_describe_one` currently has:

```
  Workspace:   shared:/home/user/proj
```

Extended to a multi-line block whenever a workspace is configured,
and the bare `Workspace:   -` single-line form when no workspace
exists. The multi-line form is used uniformly across the three
configured variants — no "promote to single line if all fields are
default" rule, because the variability that would introduce in
operator scripts is not worth the saved row:

```
Config:
  ...
  Workspace:
    Mode:       shared
    Host path:  /home/user/proj
    Guest path: /home/user/proj
    Security:   mapped-xattr        # only shown for shared
  ...
```

For `clone:`:

```
  Workspace:
    Mode:       clone
    Repo:       https://github.com/example/x.git
```

For `local:`:

```
  Workspace:
    Mode:       local
    Host path:  /home/user/proj
    Guest path: /srv/work
```

For no workspace (clone-less, shared-less, local-less session):

```
  Workspace:   -
```

(Single-line form retained for the empty case to minimise vertical
churn.)

Indentation matches the existing two-space-then-key-pad pattern in
`render_describe_one`.

Field name choices:

- `Mode:` — `shared` / `clone` / `local` (lowercase, matching
  `WorkspaceModeKind` serde form).
- `Host path:` — the resolved absolute path on the host.
- `Guest path:` — the resolved absolute path inside the VM/container.
  Omitted for `clone:` (which has no guest path concept beyond the
  hardcoded `/home/agent/workspace/`).
- `Security:` — `mapped-xattr` / `none`. Only emitted for
  `shared:`. When `security_model` is `Option::None` (no operator
  override at create time), the rendered value is
  `mapped-xattr (default)` to make the inheritance visible to the
  operator. When `security_model` is `Some(MappedXattr)` (the
  operator explicitly typed `:mapped-xattr` at create time), the
  rendered value is `mapped-xattr` (no `(default)` annotation)
  because the value is now operator-asserted, not inherited.
  `Some(NoneMapping)` renders as `none`. This mirrors the wire
  surface rule (§ Wire surface): explicit `Some(_)` is preserved
  through render.
- `Repo:` — repo URL. `clone:` only.

The byte-for-byte format above is what the unit test in § Tests
asserts; the e2e suite pins the substring matches that scripts may
rely on.

## Tests

### Unit tests

`sandbox-core/src/session.rs` (parser):

- `parse_flag` — every row of the parser-unit-test matrix in § Parser
  becomes a test. Each test asserts the full
  `WorkspaceMode::Shared { host_path, guest_path, security_model }`
  payload (or the `WorkspaceMode::Local { host_path, guest_path }`
  payload), not just one field.
- `parse_flag` — `~` expansion (host side): a fixture sets
  `HOME=/tmp/parser-home`, creates that dir, asserts `shared:~/proj`
  resolves to `host_path=/tmp/parser-home/proj` and
  `guest_path=/tmp/parser-home/proj` (guest inherits resolved host).
- `parse_flag` — `~` expansion (both sides): same fixture, asserts
  `shared:~/proj:~/work` resolves to
  `host_path=/tmp/parser-home/proj` and `guest_path=/home/agent/work`
  (each `~` expands against its own side).
- `parse_flag` — relative path rejection: `shared:./proj`, `local:proj`,
  `shared:./proj:/srv/dst` all return an error containing "must be
  absolute".
- `parse_flag` — empty-tokens rejection: `shared:`, `local:`,
  `shared:/srv::/dst` (double colon) all return an error.
- `parse_flag` — input normalization (SF-16 cases):
  - Empty input `""` → "unknown workspace mode" error.
  - Mode-only `"shared"` (no `:`) → "unknown workspace mode" error.
  - Empty mode prefix `:/foo` → "unknown workspace mode" error.
  - Mixed-case mode `Shared:/srv/repo` → "unknown workspace mode"
    error (case-sensitive matching).
  - Trailing slash `shared:/srv/repo/` → parses with
    `host_path=/srv/repo` (strip applied in step C).
  - Trailing whitespace `"shared:/srv/repo "` → parses with
    `host_path=/srv/repo` (whitespace trimmed in the normalization
    step).
- `parse_flag` — friendly-hint branch (SF-18 cases):
  - `shared:/srv/repo:passthrough` → error containing
    "passthrough and mapped-file security models are not exposed".
  - `shared:/srv/repo:mapped-file` → same friendly error.
- `parse_flag` — local-mode directory requirement (SF-11):
  asserting `local:<file-path>` (a regular file, not a directory)
  fails with an error containing "must be a directory" and naming
  `sandbox cp` as the alternative.
- `parse_flag` — daemon-side `~` rejection (MF-1): asserting that
  the daemon-side entry point rejects an unresolved `~` in
  `host_path` (e.g. `shared:~/proj` on the daemon side after the
  CLI has been bypassed) with the error
  "host_path must be absolute; CLI should have expanded `~` before
  sending". CLI-side parsing of the same input still expands and
  succeeds.
- `render_workspace_mode` round-trip — `Some(_)` preservation
  (SF-17): construct `Shared { host=/a, guest=/a,
  model=Some(MappedXattr) }`, render to wire string, assert it
  contains `:mapped-xattr`. Parse the rendered string, assert the
  parsed `security_model` equals `Some(MappedXattr)` (not collapsed
  to `None`).

`sandbox-core/src/session.rs` (backward-compat):

- Legacy `Shared` blob (no `guest_path` key) deserialises with
  `guest_path == host_path`. Construct the JSON manually
  (`{"type":"shared","host_path":"/srv/repo"}`) and assert.
- Forward-compat: serialise a current `Shared { host=/a, guest=/b,
  model=None }`, deserialise into the same struct, assert equality
  on all three fields.
- Forward-compat with `security_model`: serialise a `Shared` with
  `model=Some(NoneMapping)`, round-trip, assert preserved.
- Local round-trip: serialise/deserialise `Local { host=/a, guest=/b }`,
  assert equality.

`sandbox-core/src/lima.rs` (template):

- `Shared { host=/a, guest=/a, model=None }` renders a 9p mount
  block with `location: "/a"`, `mountPoint: "/a"`, `securityModel:
  mapped-xattr`.
- `Shared { host=/a, guest=/srv/work, model=None }` renders
  `mountPoint: "/srv/work"`.
- `Shared { host=/a, guest=/a, model=Some(NoneMapping) }` renders
  `securityModel: none`.
- `Shared { host=/a, guest=/srv/work, model=Some(NoneMapping) }` renders both
  guest path and `securityModel: none`.
- `Local { host=/a, guest=/srv/work }` renders `mounts: []` (no 9p
  block).
- YAML-injection probe: `Shared` with a `guest_path` containing
  newlines or quotes round-trips through `sanitize_yaml_path` (the
  same property the host-path test asserts) and the rendered YAML
  is still parseable (or the path is rejected outright at parse time
  — the implementer picks the closer-to-existing convention).

`sandbox-core/src/backend/container.rs` (argv):

- `Shared { host=/a, guest=/a, model=None }` produces
  `--mount type=bind,src=/a,dst=/a`.
- `Shared { host=/a, guest=/home/agent/workspace, model=None }`
  produces `--mount type=bind,src=/a,dst=/home/agent/workspace`.
- `Shared { ..., model=Some(_) }` returns `InvalidConfig` with a
  message containing `security_model` (pre-existing test, kept
  passing under the new struct shape).
- `Local { ... }` produces *no* `--mount` for the workspace
  (asserts the argv contains the home-volume and CA mounts but no
  bind-mount with `dst=<guest_path>`).
- Capability set: container backend's `workspace_modes` contains
  `Local`.

`sandbox-cli/src/main.rs` (push/pull planner):

- Push, Lima, force, defaults: `rsync -aL --delete
  --filter=':- .gitignore' -e 'limactl shell' /a/
  sandbox-<id>:/b/`.
- Push, container, force, defaults: `rsync -aL --delete
  --filter=':- .gitignore' -e 'docker exec -i' /a/
  sandbox-<id>:/b/`.
- Push, Lima, dry-run: `--dry-run` appears in the argv, no `-f` is
  required to construct the argv but the CLI gate enforces one of
  the two flags is present.
- Push with `--safe-links`: `-L` replaced with `--safe-links`.
- Push with `--no-gitignore`: `--filter` flag absent.
- Pull, default dest: `<src>=sandbox-<id>:/b/`, `<dst>=/a/`.
- Pull with `--dest=/c`: `<dst>=/c/`.
- Both `-f` and `-n` set: planner returns a usage error (or the
  command parser rejects before the planner — pick one).
- Neither set: usage error.

`sandbox-cli/src/main.rs` (describe rendering):

- Expand existing `render_describe_one` tests with golden-form
  outputs for each `WorkspaceMode` variant, rendered from
  `SessionConfigDto.workspace_mode_detail`. Byte-for-byte assertion
  on the `Workspace:` block for shared (with and without explicit
  guest/security tokens), clone, local, and the no-workspace case.
- Older-daemon fallback: construct a `SessionConfigDto` with
  `workspace_mode = Some("shared:/home/user/proj")` and
  `workspace_mode_detail = None` (simulating a newer CLI talking to
  an older daemon); assert the rendered output is the historical
  single-line `Workspace:   shared:/home/user/proj` form, not the
  new multi-line block.

### Integration tests (named `integration_*`, run under
`make test-integration`)

- `integration_lima_local_create_and_push` — boots a Lima session with
  `local:/tmp/<tempdir>:/srv/work`, asserts the create-time push
  populated `/srv/work` inside the guest, then runs `sandbox
  workspace push -f` after touching a file, asserts the new file
  appears guest-side.
- `integration_lima_local_pull` — counterpart pull test: edits a file
  guest-side, runs `sandbox workspace pull -f`, asserts host-side
  change visible.
- `integration_container_local_create_and_push` — same shape against
  the container backend.
- `integration_container_local_pull` — same shape against the
  container backend.
- `integration_local_gitignore_filter` — create `local:` with a
  `.gitignore` containing `excluded/`, drop a file in `excluded/`
  on the host, assert it is *not* in the guest after create.
  Re-run with `--no-gitignore`, assert the file *is* in the guest.
- `integration_local_create_failure_tears_down` — make the host path
  unreadable to the daemon (`chmod 000`), assert session create
  fails with rsync's error in the response, assert no orphaned
  VM/container/network artefacts remain.
- `integration_shared_guest_path_lima` — create a Lima session with
  `shared:/tmp/<tempdir>:/srv/work`, assert the mount appears at
  `/srv/work` inside the guest and writes round-trip to the host.
- `integration_shared_guest_path_container` — same shape against
  the container backend.

### E2E tests (`tests/e2e/`)

- `test_workspace_local.py` — exercises the full `local:` happy
  path across both backends (matrix parameterisation; the file uses
  `@pytest.mark.lima` / `@pytest.mark.container` per M12-S13's
  marker convention):
  - Create a session with `local:<tempdir>`.
  - Assert workspace contents present inside the session.
  - Run `sandbox workspace push -f` after editing host-side, assert
    the edit propagated.
  - Run `sandbox workspace pull -f` after editing guest-side, assert
    the edit propagated.
  - `sandbox describe` shows `Mode: local`, the right paths.
- `test_workspace_shared_guest_path.py` — exercises the guest-path
  branch of `shared:`:
  - Create a session with `shared:<tempdir>:/srv/work`.
  - Assert the mount appears at `/srv/work`.
  - Cross-check writes round-trip to the host.

Both new e2e files follow the existing `tests/e2e/conftest.py`
session-lifecycle pattern. The full e2e matrix run
(`make test-e2e-matrix`) covers both backends; the container-only
PR-time run (`make test-e2e-container`) covers the container
branches.

## Docs Changes

### `docs/guides/workspaces.md`

- The "Mount a host directory (shared mode)" section gains a
  paragraph describing the guest-path token: how to set it, what the
  default (`= host_path`) is, why preserving the host path is the
  new default. Two example invocations: default-preserve and
  explicit-guest.
- The same section gains the `:<security-model>` paragraph already
  designed in the 2026-05-14 spec (now joined by the guest-path
  layer; the order of the optional tokens in the example is
  `:<guest-path>:<security-model>`).
- A new top-level section "Snapshot a host directory (`local:`
  mode)" sits between "Mount a host directory" and "Copy individual
  files with `sandbox cp`". The section covers:
  - When to pick `local:` vs `shared:` (one-shot snapshot vs live
    mount; isolation vs convenience).
  - `sandbox create --workspace local:<path>` invocation, with and
    without `--no-gitignore`.
  - `sandbox workspace push -f` / `pull -f` invocations, the
    `-f`/`-n` safety gate.
  - The filter-interaction note ("if you have a gitignored file
    like `.env` that you want in the guest, pass `--no-gitignore`
    or use `sandbox cp ./.env <s>:<guest>/`").
- The "`cp` vs. `sync`" table extends to cover `local:` push/pull
  as a separate row, clarifying the "this is mode-aware, not a
  generic file mover" distinction.

### `docs/guides/hardening.md`

- The "9p shared mounts" section is updated to note that the
  per-session security model decision (mapped-xattr default, opt-in
  `none`) is now exposed, picking up the 2026-05-14 spec's content.
- A new bullet under "Security trade-offs you choose":
  - **`local:` snapshot.** No 9p surface, no live host writes.
    The trade-off is staleness — the operator decides when to
    push/pull. A `local:` session's guest cannot reach the host
    filesystem outside the rsync transport's push/pull window.

### `docs/concepts/workspaces.md`

(Existing — referenced from the guides). Update the conceptual
overview to list five (not four) modes: clone, shared, local, cp,
git-remote. Place `local:` between `clone:` and `shared:` in the
trade-off table — it sits between them on the live-edits / isolation
axis.

### Upgrade notes

A short paragraph in `docs/internal/upgrade-notes.md` (or
`docs/changelog.md` — wherever the project tracks operator-facing
breaking changes) documents:

- The default `shared:` guest path is no longer
  `/home/agent/workspace`; it is the host path. Operators relying on
  the old default must add an explicit `:<guest_path>` token.
- Daemons older than this spec cannot read records written with
  `local:` workspaces. Roll forward, do not roll back across a
  `local:` session.

### Reference docs

- `docs/reference/cli.md` — `sandbox create` workspace value
  reference table updated for the three-token grammar. New
  `sandbox workspace push/pull` subcommands documented.
- `docs/internal/api.md` (if one exists) — `CreateSessionRequest`
  workspace shape unchanged at the wire level (single string), but
  the parser grammar is documented for daemon-side consumers.

## Out of Scope

- A separate `--workspace-guest-path` flag. The colon-delimited
  grammar is chosen as the single surface; splitting into separate
  flags would double the create-time surface and complicate the
  parser.
- A separate `--security-model` flag. Same reason; the 2026-05-14
  spec already explicitly excluded this.
- A way to *change* `host_path`, `guest_path`, or `security_model`
  on an existing session. Creation-time only. Editing the session
  record post-create requires `sandbox rm` + re-create.
- Exposing rsync's `--include`, `--exclude`, `--filter` as
  first-class flags on push/pull. The fixed
  `--filter=':- .gitignore'` (or absent under `--no-gitignore`) is
  the complete filter surface. Operators wanting more can run rsync
  directly using `-e 'limactl shell'` / `-e 'docker exec -i'` and
  the session's container name (same pattern `sandbox sync` uses).
- A live two-way sync watcher for `local:` (filesystem-watcher
  daemon, inotify-driven push, etc.). `local:` is explicitly
  snapshot-with-operator-trigger.
- Bind-mount-as-`shared:` on the container backend with a guest
  path outside `/home/agent` that survives the read-only rootfs
  layer. The image is `--read-only`; bind-mounts work for paths
  under existing mount points only. Operators picking a `guest_path`
  outside `/home/agent` on the container backend see rsync (`local:`)
  or `docker create` (`shared:`) reject the value with the native
  error.
- Auto-detection of "this is a git repo, gitignore is fine" vs "this
  is not a git repo, gitignore is meaningless". Rsync's
  `:- .gitignore` filter handles the no-gitignore case gracefully
  (no filter file = no filter rules); we lean on that rather than
  pre-flighting.
- Exposing rsync's `--info=progress2` or any progress UI on
  push/pull. Operators see whatever rsync prints by default
  (one-line summary on completion); for verbose progress, run
  rsync directly.
- A `sandbox workspace status` subcommand that diffs `host_path` vs
  `guest_path` to show "what would push". Deferred — rsync's
  `--dry-run` (the `-n` flag on push/pull) already serves this need.

## Known Gaps

- **Compact-form path-with-colons footgun (carried forward from
  2026-05-14).** A literal host path of the form `/foo:none`
  collides with the trailing `:none` security-model token. Extended
  by this spec: a literal host path of the form `/foo:/bar` collides
  with the guest-path token. The right-to-left parsing rule (§
  Parser) makes the collision predictable but not avoidable.
  Operators with such paths can move the directory or use a
  symlink; a `--workspace-host-path` / `--workspace-guest-path`
  separate-flag surface would eliminate the ambiguity — left
  deferred until a real user hits it.
- **Unclassified-trailing-token folding.** An unrecognised trailing
  token (e.g. `shared:/srv/repo:bogus`, `local:/srv/repo:bogus`,
  `shared:/srv/repo:/srv/dst:bogus`) is folded into `host_path` by
  step C rather than diagnosed as "unknown model" or "bad guest
  path". The host-path-exists check in step D then rejects the
  compound path with "host_path does not exist". Operators see a
  generic error pointing at a path they probably did not intend
  to type. The parser does not pre-validate the suffix in the
  general case (the `passthrough` / `mapped-file` early hint in
  step A is the one exception — those strings are recognisable as
  attempted security-model spellings, so the targeted hint there
  pays off). A richer per-token diagnostic surface
  ("token `bogus` is neither a path nor a known security model")
  would close this gap — left deferred until operator feedback
  shows the generic error is misleading in practice.
- **Container `--read-only` interaction with `guest_path` outside
  the image's writable set.** The writable surfaces on the lite
  image (`/home/agent/...`, `/tmp/...`, `/run/...`) are listed in §
  Container Backend → Read-only rootfs interaction. A `guest_path`
  outside that set fails at rsync time with EROFS, not pre-validated
  by the daemon. A pre-flight that probes the container image for
  writable mount points would catch this before session-create
  proceeds — deferred; the rsync error is legible and the documented
  idioms (`:<guest_path>` inside `/home/agent`, `/tmp`, or `/run`)
  sidestep it.
- **Rollback past a `local:` session is destructive.** A daemon
  predating this spec cannot deserialise `WorkspaceMode::Local`; the
  session is unloadable. Acceptable given the pre-0.1.0 envelope,
  but worth surfacing in the upgrade notes; long-term, a more
  forgiving rollback story (e.g. an `unknown_variant` arm that
  marks the session as "needs-newer-daemon") would close this gap.
  Deferred.
- **`guest_path` collisions with default agent home contents.** If
  the operator picks `guest_path=/home/agent` or
  `/home/agent/<something-the-image-already-uses>`, the bind-mount
  (`shared:`) or rsync target (`local:`) shadows or overwrites the
  image's content. Documented in `docs/guides/workspaces.md` as a
  caveat; not pre-validated by the daemon — the surface of
  "paths the image already uses" is image-defined, not daemon-defined.
- **Oversized `local:` source trees exceeding the session-create
  timeout envelope.** The behaviour is now pinned (see § `local:`
  Mode → Cancellation and timeout): the rsync runs inside the
  existing timeout envelope, a timeout triggers
  `cleanup_and_return!` with an `Internal` response, and the
  recovery path is "create with a smaller subset, push the rest
  afterwards via `sandbox workspace push -f`". The remaining open
  question is purely empirical — does the existing envelope (Lima
  base provisioning routinely takes 30-60s) leave headroom for
  rsync of a typical workspace, or does the envelope itself need to
  grow? Verification pinned in M17-S4's example replay; not a
  blocker, since the recovery path is in place either way.

## Sessions

### M17-S1 — `shared:` guest-path + securityModel + breaking default

**Entry criteria.** Fresh.

**Spec reference.** This document, §§ CLI shape (shared variant),
Domain types, Parser (shared variant), Backward Compatibility, Lima
Backend (shared), Container Backend (shared), `sandbox describe`,
Tests (shared subset), Docs Changes (shared subset).

**Rationale.** The shared-side changes are small in surface but
fan-out-y in destructure sites: every `match` on
`WorkspaceMode::Shared` across the workspace gains the new
`guest_path` field in the same diff or the build breaks. Splitting
the domain change from the template/integration would leave a
non-compiling intermediate, so the entire shared-mode surface lands
as one PR. The breaking default change (`guest_path = host_path`
instead of `/home/agent/workspace`) lands here too — it cannot be
phased without confusing operators about which version they're on.
Docs ship in the same session because the new grammar is invisible
without them.

**In scope.**

- `WorkspaceSecurityModel` enum and the `Shared { ..., guest_path,
  security_model }` shape per § Domain types.
- `WorkspaceMode::parse_flag` extended to handle the
  `shared:<host>[:<guest>][:<model>]` grammar per § Parser.
- Replace the hand-rolled CLI-side `--workspace` validation in
  `sandbox-cli/src/main.rs` (currently the `strip_prefix("shared:")`
  + `Path::exists()` block in the `Create` arm, around lines
  815-835 as a hint) with a call to `WorkspaceMode::parse_flag(...)`
  so the new grammar (`shared:<host>[:<guest>][:<model>]`,
  `local:<host>[:<guest>]`) is accepted on both sides without
  divergence. The `local:` mode token is accepted at parse time in
  S1 but the resulting `WorkspaceMode::Local` value is rejected by
  the existing `SessionSpec::validate(&caps)` capability check
  until S2 advertises `Local` in `Capabilities::workspace_modes`
  for the relevant backend. Operators on S1 see a clear "backend
  does not support local workspaces" message rather than a
  CLI-side "unknown mode" error.
- Update the clap doc string for `--workspace` (around lines 99-104
  as a hint) to describe the new grammar accurately. The current
  text — "mounts a host directory into the VM at
  /home/agent/workspace via 9p" — is outdated on two counts (it
  omits `local:`, and the default guest path is no longer
  `/home/agent/workspace`). New text covers all three modes, both
  optional tokens for `shared:`, and the
  `guest_path = host_path` default.
- DTO/mapper updates per § `sandbox describe` → Wire surface:
  - Add `workspace_mode_detail: Option<WorkspaceModeDetailDto>` to
    `SessionConfigDto` in `sandbox-core/src/api/dto.rs` (with
    `#[serde(skip_serializing_if = "Option::is_none")]` for the
    older-client back-compat path).
  - Add the `WorkspaceModeDetailDto` and `WorkspaceSecurityModelDto`
    types in the same file per the DTO shape in § Wire surface.
  - Update `sandbox-core/src/api/mapper.rs` to populate
    `workspace_mode_detail` from the in-memory `WorkspaceMode`
    alongside the existing `render_workspace_mode` flat-string
    population.
  - Update the `SessionMountInfo.workspace_path` docstring in the
    same file to reflect the new semantics: the value is now
    `guest_path` from `WorkspaceMode::Shared`, defaulting to
    `host_path` (no longer the historical hardcoded
    `/home/agent/workspace/`).
  - Update `sandbox-core/src/api/mapper.rs` to populate
    `SessionMountInfo.workspace_path` from the resolved
    `guest_path` rather than the hardcoded constant.
- `EnumSet<WorkspaceModeKind>` unknown-variant tolerance on the
  wire per § Domain types ("Forward-compat: unknown-variant
  tolerance on the wire"). The tolerance applies as soon as
  `Capabilities` carries any newly-introduced variant, so it
  lands in S1 even though `Local` itself is not yet advertised by
  any backend until S2.
- Custom deserialiser shim per § Backward Compatibility (handles
  legacy `Shared` records without `guest_path`).
- Match-site fan-out: every destructure of
  `WorkspaceMode::Shared` across the workspace updated to include
  the new fields.
- Lima template: `mountPoint` interpolated from `guest_path`,
  `securityModel` from the resolved model. Symmetric YAML-injection
  sanitisation across both paths.
- Container backend: `--mount` argv emits `dst=<guest_path>`.
  Rejection of `security_model: Some(_)` retained from the
  2026-05-14 spec.
- `sandbox describe` rendering updated to the new
  `Workspace:` block format per § `sandbox describe` (shared and
  clone variants only — local lands in S2). The CLI consumes the
  new `workspace_mode_detail` DTO field directly (no re-parsing
  via `parse_flag`); the older-daemon fallback prints the flat
  `workspace_mode` string verbatim.
- Unit tests enumerated in § Tests (parser, backward-compat,
  template, container argv, describe — shared subset).
- Docs updates for the shared layer:
  `docs/guides/workspaces.md` syntax and when-to-use,
  `docs/guides/hardening.md` per-session model note,
  `docs/internal/upgrade-notes.md` breaking-default note.

**Explicitly deferred.**

- `local:` mode end-to-end → M17-S2.
- Six-track review of S1+S2 → M17-S3.
- Spec-delivery verification → M17-S4.

**Exit criteria.**

- All shared-subset unit tests from § Tests pass under the default
  nextest profile.
- `cargo nextest run --workspace` default profile clean;
  `cargo nextest run --workspace --profile integration` clean.
- `cargo clippy --workspace` clean; `cargo fmt --check` clean.
- Manual example replay (Lima): `sandbox create --workspace
  shared:/tmp/sbx-a:/srv/work:none` produces a guest mount at
  `/srv/work` with `securityModel: none` in the rendered YAML;
  guest-side `ln -s a b` round-trips as a real symlink to the host
  at `/tmp/sbx-a/b`.
- Manual example replay (container): same shape, asserting
  `--mount type=bind,src=/tmp/sbx-a,dst=/srv/work` in the daemon's
  `docker create` argv (visible in daemon logs).
- Docs updates landed and reviewed.

### M17-S2 — `local:` mode end-to-end

**Entry criteria.** M17-S1 complete — shared layer landed, tests
green.

**Spec reference.** This document, §§ CLI shape (local variant),
Domain types (Local + WorkspaceModeKind::Local), Parser (local
variant), `local:` Mode (full section), Push/Pull Commands, Lima
Backend (local), Container Backend (local), `sandbox describe`
(local), Tests (local subset, including integration + E2E), Docs
Changes (local subset).

**Rationale.** `local:` mode is additive — new enum variant, new
parser arm, new CLI subcommands, new backend orchestration. The
parser surface from S1 is the foundation; the rsync orchestration
and the workspace-aware CLI subcommands are isolated additions that
do not destabilise S1's match-site fan-out. The integration tests
require real backends (Lima VM, Docker container), so this session
is heavier than S1 in test infrastructure but lighter in destructure
fan-out. Docs ship in the same session because the new mode is
discoverability-zero without them.

**In scope.**

- `WorkspaceMode::Local { host_path, guest_path }` variant +
  `WorkspaceModeKind::Local` enum value per § Domain types.
- `WorkspaceMode::parse_flag` extended to handle the
  `local:<host>[:<guest>]` grammar per § Parser. Sharing the
  right-to-left token classifier with the shared grammar (no
  duplicated parsing logic).
- `--no-gitignore` flag on `sandbox create`, gated to `local:`
  workspaces with the conflict error for other modes.
- Daemon-side rsync orchestration: parent-dir creation, initial
  push at session-create, blocking failure semantics. Implemented
  for both Lima and container backends per § Lima Backend (local)
  and § Container Backend (local).
- `Capabilities::workspace_modes` for both backends advertises
  `Local`.
- `sandbox workspace push <session> {-f|-n} [--safe-links]
  [--no-gitignore]` CLI subcommand.
- `sandbox workspace pull <session> {-f|-n} [--safe-links]
  [--no-gitignore] [--dest <path>]` CLI subcommand.
- Client-side state and mode checks (must be Running, must be
  `local:`) with the documented error messages.
- `sandbox describe` rendering of the `Local` variant in the
  `Workspace:` block.
- Unit tests for the local-subset of § Tests (parser variants,
  describe rendering, push/pull planner, container backend
  `Local` argv shape).
- Integration tests (`integration_*` prefix) enumerated in §
  Tests → Integration tests.
- E2E tests (`tests/e2e/test_workspace_local.py` +
  `test_workspace_shared_guest_path.py`) enumerated in § Tests →
  E2E tests.
- Docs updates for the local layer:
  - `docs/guides/workspaces.md` new "Snapshot a host directory
    (`local:`)" section.
  - `docs/guides/hardening.md` trade-off bullet under "Security
    trade-offs you choose".
  - `docs/concepts/workspaces.md` updated mode list and trade-off
    table.
  - `docs/internal/upgrade-notes.md` rollback caveat for
    `local:` records.

**Explicitly deferred.**

- Six-track review → M17-S3.
- Spec-delivery verification → M17-S4.

**Exit criteria.**

- All local-subset unit, integration, and E2E tests from § Tests
  pass.
- `cargo nextest run --workspace` default profile clean;
  `cargo nextest run --workspace --profile integration` clean;
  `make test-e2e-matrix` clean (both backends).
- `cargo clippy --workspace` clean; `cargo fmt --check` clean.
- Manual example replay (Lima): `sandbox create --workspace
  local:/tmp/sbx-l` populates `/tmp/sbx-l` inside the guest;
  `sandbox workspace push -f` after host edit propagates the edit;
  `sandbox workspace pull -f` after guest edit propagates back.
- Manual example replay (container): same shape against the
  container backend.
- Manual example replay (filter): `local:` with a `.gitignore`
  excluding `excluded/` does not transfer that directory; the same
  source with `--no-gitignore` does.
- Docs landed and reviewed.

### M17-S3 — Six-track review (covering S1 + S2)

**Entry criteria.** M17-S2 complete — both shared and local layers
landed, all tests green.

**Spec reference.** This document, all sections.

**Rationale.** The expanded M17 touches a security-relevant surface
(hardening posture via `securityModel`), a persistence-relevant
surface (`config_json` blob shape, with a custom deserialiser shim),
and adds a new orchestration code path (daemon-side rsync at
session-create). The parser has documented footguns. A multi-track
review calibrated to this spec's actual surface catches
spec-vs-impl drift, parser corner cases, docs-vs-code contradictions,
and premature widening that compile-and-test cannot.

**In scope.**

Six tracks, each delegated to a separate review agent in parallel:

- **Track 1 — Implementation vs. spec.** Re-read the spec
  section-by-section; compare every concrete claim (CLI shape,
  default values, parser grammar table, persistence semantics, exact
  match between `WorkspaceSecurityModel` variants and accepted
  tokens, `as_yaml` output vs YAML in the template, container
  `--mount` argv shape, push/pull argv shape, `sandbox describe`
  block format, capability set membership) against the
  implementation; flag any divergence. Confirm both `host_path` and
  `guest_path` are sanitised on the Lima path.
- **Track 2 — Code quality.** Review every touched file
  (`sandbox-core/src/session.rs`, `lima.rs`,
  `backend/container.rs`, every match-site updated for the new
  fields, `sandbox-cli/src/main.rs`'s push/pull planner) for:
  idiomatic Rust; no superfluous clones in the parser or planner;
  error-message clarity (rsync stderr surfaced verbatim, container
  rejection naming `security_model`, push/pull errors naming the
  session and mode); no `unwrap`/`expect` in non-test paths around
  new code; no accidental `pub` widening; `WorkspaceSecurityModel`
  remains `Copy`; field names consistent across struct definitions,
  match patterns, JSON wire form, YAML output, CLI rendering.
- **Track 3 — Unit test quality.** For every unit test in S1+S2:
  verify the assertion is non-tautological. Parser tests must
  assert all three fields of `Shared` and both fields of `Local`
  (not just `host_path`). Template tests must assert exact
  `mountPoint:` and `securityModel:` substrings. Container backend
  tests must assert exact `--mount type=bind,src=...,dst=...`
  shape. Push/pull planner tests must assert the full argv vector,
  not just the binary name. Backward-compat tests must construct
  legacy JSON manually (no `guest_path` key) — not JSON with
  `null`. Describe-render tests must assert byte-for-byte block
  format.
- **Track 4 — Integration / E2E test quality.** Confirm the
  example replays from S1 and S2 were performed; artefacts recorded
  (Lima YAML excerpts, `docker create` argv from daemon logs,
  host-side stat outputs, rsync stderr captures). Confirm
  `integration_local_create_failure_tears_down` actually drives the
  rsync failure (chmod or similar) rather than mocking it. Confirm
  E2E tests run on both backends per their marker decorators.
- **Track 5 — Docs quality.** Verify
  `docs/guides/workspaces.md` documents the three-token shared
  grammar accurately (including footguns), the new
  `local:` section reads as a peer mode (not as an afterthought),
  the cp/sync/local-push/pull distinction is clear. Verify
  `docs/guides/hardening.md` covers both the per-session model
  decision (shared) and the no-9p-surface bullet (local). Verify
  `docs/concepts/workspaces.md` lists five modes. Verify
  `docs/internal/upgrade-notes.md` documents both breaking changes
  (shared default, local rollback).
- **Track 6 — Workarounds + deprecated patterns.** Grep touched
  files for: new `unwrap()`/`expect()` in non-test paths;
  `TODO`/`FIXME` introduced in S1+S2; any milestone tag (`M17` /
  `S1` / `S2`) embedded in code or test comments per CLAUDE.md's
  "no milestone tags in code or tests" convention; any
  hardcoded `/home/agent/workspace` that survived the shared-side
  guest-path migration; any duplicated rsync orchestration between
  the daemon and the CLI (push/pull); any
  `passthrough`/`mapped-file` token sneaking into a code path.

**Explicitly deferred.**

- Claim-to-code map + example replay write-up → M17-S4.

**Exit criteria.**

- All six review tracks complete; findings collated into a single
  prioritised list.
- Every "must-fix" finding addressed, re-implemented where needed,
  and re-tested.
- `cargo nextest run --workspace` default and integration profiles
  clean post-fixes; `cargo clippy --workspace` clean;
  `cargo fmt --check` clean.
- `make test-e2e-matrix` clean post-fixes.

### M17-S4 — Spec-delivery verification

**Entry criteria.** M17-S3 complete — all review findings addressed,
all tests passing.

**Spec reference.** This document, all sections.

**Rationale.** M17 is the terminal milestone for this spec. The
verification session closes the incentive gap that decomposition
creates: S1's and S2's exit criteria measure "are the in-scope tests
green?", not "is every spec claim provably delivered?". Re-reading
the spec end-to-end as if unfamiliar with the implementation and
mapping every concrete claim to a code+test locator (or to an
explicit out-of-scope bullet, or to a tracked follow-on) is what
proves the spec landed.

**In scope.**

- **Claim-to-code map.** Every concrete claim across § Summary, §
  Motivation, § CLI shape, § Domain types, § Parser, § Backward
  Compatibility, § `local:` Mode, § Push/pull commands, § Lima
  Backend, § Container Backend, § `sandbox describe`, § Tests, §
  Docs Changes, § Out of Scope, § Known Gaps maps to (a) a code
  locator (file path + function/symbol) + a test locator, (b) an
  explicit out-of-scope bullet from the spec, or (c) a `progress`
  todo for future work. Format per the project's claim-to-code
  convention.
- **Example replay (Lima)**, against a live session in hardened
  mode:
  - `shared:/tmp/sbx-a` → `mountPoint: /tmp/sbx-a` in the rendered
    YAML; default `securityModel: mapped-xattr`.
  - `shared:/tmp/sbx-a:/srv/work` → `mountPoint: /srv/work`.
  - `shared:/tmp/sbx-a:/srv/work:none` → both substitutions; a
    guest-side `ln -s` round-trips as a real host symlink at
    `/tmp/sbx-a/b`.
  - `shared:~/proj` → with `HOME=/home/user`, host=`/home/user/proj`,
    `mountPoint: /home/user/proj` (guest inherits resolved host).
  - `shared:~/proj:~/work` → host=`/home/user/proj`,
    `mountPoint: /home/agent/work` (each `~` expands per side).
  - `local:/tmp/sbx-l` → on-create push populates `/tmp/sbx-l` in
    the guest; `push -f` after host edit propagates; `pull -f` after
    guest edit propagates back.
  - `local:/tmp/sbx-l:/srv/work` → guest content lands at
    `/srv/work` instead.
  - `local:/tmp/sbx-l --no-gitignore` → gitignored host content
    transfers into the guest at create time.
- **Example replay (container)**, against a live container session:
  - `shared:/tmp/sbx-a:/srv/work` → `--mount
    type=bind,src=/tmp/sbx-a,dst=/srv/work` in the `docker
    create` argv (captured from daemon logs).
  - `local:/tmp/sbx-l:/home/agent/local` → on-create rsync
    populates `/home/agent/local` inside the container;
    `push -f` and `pull -f` work.
- **Compact-form footgun probe.** `sandbox create --workspace
  shared:/tmp/sbx-foo:none` against a host path that genuinely
  exists at `/tmp/sbx-foo:none` (literal). Record the observed
  behaviour and confirm § Known Gaps's caveat matches.
  Repeat for `shared:/tmp/foo:/tmp/bar` (literal path with colon).
- **Out-of-scope conformance.** Grep verify that the § Out of
  scope list is genuinely absent from new code: no
  `--workspace-guest-path` flag, no `--security-model` flag, no
  rsync `--include`/`--exclude` plumbing, no filesystem-watcher
  daemon, no `sandbox workspace status` subcommand.
- **Persistence round-trip probe.** Serialise a `SessionConfig`
  with `WorkspaceMode::Shared { host=/a, guest=/b, model=Some(NoneMapping) }`,
  persist via the store, re-load, confirm round-trip.
  Serialise `WorkspaceMode::Local { host=/a, guest=/b }`, persist,
  re-load, confirm round-trip. Hand-craft a legacy JSON blob with no
  `guest_path` key on `Shared`, persist as raw text into a row,
  reload via the daemon, confirm `guest_path = host_path` recovery.
- **Known-gap reconciliation.** Each `Known Gaps` bullet is either
  resolved or tracked as a `progress` todo (compact-form path
  footgun, container read-only / guest-path interaction, rollback
  past `local:`, guest-path collisions with image contents,
  initial-push timeout envelope).
- **Deliverable.** Write the delivery file at
  `.tasks/specs/2026-05-20-m17-workspace-ergonomics/2026-05-20-m17-workspace-ergonomics-delivery.md`.

**Explicitly deferred.** Nothing — this session closes the spec.

**Exit criteria.** Conjunctive — ALL must hold before M17-S4 is
marked complete:

- Delivery file exists; every BLOCKER-tagged item in the
  claim-to-code map is resolved.
- Every concrete claim across all spec sections has a code
  locator, an out-of-scope citation, or a named follow-on tracking
  reference.
- All example replays complete without deviation: rendered YAML
  exact, `docker create` argv exact, rsync command-line exact,
  push/pull behaviour matches the spec on both backends.
- Compact-form footgun observations recorded with concrete output
  and reconciled against § Known Gaps.
- Out-of-scope items absent from new code (grep for each item).
- Persistence round-trip probe completes without deviation,
  including the legacy-record recovery case.
- Known-gap reconciliation: each bullet either resolved or tracked.
- `cargo nextest run --workspace` default profile clean.
- `cargo nextest run --workspace --profile integration` clean.
- `make test-e2e-matrix` clean.
- Code review of the delivery artefact approved.
