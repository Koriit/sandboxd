# Configurable 9p `securityModel` on `sandbox create`

## Summary

This spec makes the 9p `securityModel` of the shared-workspace mount
selectable per session via the existing `--workspace` CLI flag. The
default stays `mapped-xattr` — the value the Lima backend currently
hardcodes. The new option is `none`, which gives real symlinks in both
directions at the cost of silently no-op'ing privileged guest-side
metadata operations (`chown`/`mknod`/setuid bits). `passthrough` is
intentionally **not** exposed — it would require running QEMU with
elevated capabilities, which contradicts the project's hardening
posture; the trade-off is documented inline rather than as a code
option.

CLI shape: `sandbox create --workspace shared:<host-path>[:<model>]`.
One milestone (M17), three sessions: domain + parser change, Lima
template + backend integration, docs + verification.

## Context

### What the code does today

The Lima backend renders a 9p mount block when the session is created
with `WorkspaceMode::Shared`
(`sandboxd/sandbox-core/src/lima.rs:1446-1466`). The
`securityModel: mapped-xattr` line is **hardcoded**:

```yaml
9p:
  securityModel: mapped-xattr
  cache: mmap
```

`mapped-xattr` was chosen during the M9 shared-workspace rework that
replaced virtio-fs with 9p (the virtio-fs daemon needed shared memory
that conflicted with QEMU's seccomp sandbox; see
`docs/guides/hardening.md` and the M9 progress notes). With
`mapped-xattr`, QEMU's 9p server stores file mode, uid/gid, and
special-file types (symlinks, devices, FIFOs) in xattrs on the host
filesystem and re-presents them to the guest as real special files.
Inside the guest this works transparently: `ln -s` creates a symlink
the guest can traverse normally.

The model is set once per session at template-render time and cannot
be changed later. The container backend
(`sandboxd/sandbox-core/src/backend/container.rs:476-488`) implements
the same `WorkspaceMode::Shared` semantics through a bind mount and
has no 9p layer.

### What `mapped-xattr` costs us

`mapped-xattr` is a one-way illusion: the guest sees real symlinks
because the 9p server fakes them, but the host sees the underlying
regular files with `user.virtfs.*` xattrs.

Concretely:

- A guest-side `ln -s ./a ./b` inside `/home/agent/workspace` lands on
  the host as a regular file `b` containing the target string, with
  `user.virtfs.mode` flagged as `S_IFLNK` and
  `user.virtfs.symlink.target` set. Host tools (`ls -l`, `cat`, `git`,
  editors) treat it as a regular file with garbage content.
- A host-side `ln -s` in the shared directory lacks the xattrs the 9p
  server expects, so the guest does not see a symlink — it sees either
  nothing usable or the resolved target's contents inlined as a file,
  depending on the kernel path.
- Round-tripping a tree with `rsync`/`tar`/`cp -a` from the host into
  the shared directory loses symlink semantics.
- Host-side git operations against the shared workspace cannot
  faithfully commit or check out symlinked files (e.g. dotfile repos,
  symlinked `node_modules`, repo-local symlink fixtures).

These are workflows shared-workspace users currently hit and have
worked around informally (clone mode, sandbox `cp`, manual rsync via
`sandbox sync`). None of those are wrong — but none of them are what
the user reached for `shared:` to get.

### Why we did not choose `passthrough`

`passthrough` makes the host file system the ground truth: guest
ownership and mode operations apply literally on the host. That gives
faithful symlink semantics in both directions, but it requires the
QEMU process to be able to honour those ops — practically, root or
`CAP_CHOWN`+`CAP_FOWNER`+`CAP_DAC_OVERRIDE`. A compromised in-VM agent
then gains a primitive to flip host file ownership and mode bits on
the shared directory (e.g. drop a setuid binary that survives session
teardown, chown host-side files to the calling user, etc.). The
sandbox runs untrusted code as a feature, so this is a meaningful
loosening of the seccomp + unprivileged-QEMU posture documented in
`docs/guides/hardening.md`.

The cost (handing the agent a host-side privilege primitive) exceeds
the benefit (host tools see guest symlinks as symlinks). Therefore
`passthrough` is **not exposed** as a session-level option in this
spec. If a concrete user need ever materialises for it, the path
forward is a separate spec gating it behind a privilege model and an
explicit opt-in — not a quiet additional value in the existing flag.

### Why we did not choose `mapped-file`

`mapped-file` is functionally equivalent to `mapped-xattr` for our
workload — same illusion, same trade-offs, just metadata stored in a
sidecar `.virtfs_metadata/` directory instead of xattrs. The host
filesystems we target (ext4, btrfs, xfs) all support xattrs; there is
no portability story `mapped-file` would unlock for us. Not exposed.

### What `none` actually gets us

`none` is `passthrough` minus the strict error reporting on
unprivileged metadata operations. Files round-trip as real symlinks
both directions; `chmod`/`chown` invocations from the guest that the
host user cannot honour silently succeed with no underlying effect
(rather than returning EPERM). For the shared-workspace use case —
editing code, running builds, git operations from either side — this
is the right trade-off:

- Symlinks work both ways for `rsync`, `tar`, host git, host editors.
- Guest-side ownership and special bits stop being meaningful, which
  is already the case for most code-edit workloads.
- No additional QEMU privileges required; the seccomp sandbox stays
  on; the hardening posture is unchanged.

The visible cost surface for `none` is small and well-bounded: if a
guest-side tool depends on observing its own chown taking effect on a
file shared with the host, it will see the call succeed and the
ownership unchanged on a subsequent stat. This is documented as the
trade-off; users who need ownership preservation either stay on
`mapped-xattr` or pick clone mode.

## Goals and non-goals

### Goals

1. Make the 9p `securityModel` a per-session decision exposed through
   `sandbox create --workspace`.
2. Default stays `mapped-xattr` — no behaviour change for existing
   invocations or persisted sessions.
3. Add `none` as the only additional option.
4. Persist the choice forward- and backward-compatibly (per CLAUDE.md
   "On-disk compatibility").
5. Document the option, the trade-off, and the explicit non-exposure
   of `passthrough`/`mapped-file`.

### Non-goals

- Exposing `passthrough` or `mapped-file`.
- Changing the default for any existing or new session.
- Adding the option to the container backend (which has no 9p layer
  and uses a bind mount).
- Exposing 9p `cache` policy as a flag (kept at `mmap`).
- A separate `sandbox` subcommand to mutate the model after creation;
  the value is creation-time only.
- Host-side tooling that translates xattr-flagged "symlinks" produced
  by past `mapped-xattr` sessions into real symlinks. If the user wants
  symlink interop, they pick `none` at create time on a fresh session.

## Target design

### CLI surface

Extend the existing `--workspace` flag. The string is parsed as:

```
--workspace shared:<absolute-host-path>[:<security-model>]
```

`<security-model>` ∈ {`mapped-xattr`, `none`}. Omitted ⇒
`mapped-xattr` (current default).

Examples:

```text
sandbox create --workspace shared:/srv/repo                # mapped-xattr
sandbox create --workspace shared:/srv/repo:mapped-xattr   # explicit default
sandbox create --workspace shared:/srv/repo:none           # opt-in to none
```

The full flag value remains a single string on the wire — the existing
`CreateSessionRequest.workspace: Option<String>` DTO stays unchanged.

### Domain types

In `sandbox-core/src/session.rs`, introduce:

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum WorkspaceSecurityModel {
    #[default]
    MappedXattr,
    None,
}

impl WorkspaceSecurityModel {
    pub fn as_yaml(&self) -> &'static str {
        match self {
            Self::MappedXattr => "mapped-xattr",
            Self::None => "none",
        }
    }
}
```

Extend `WorkspaceMode::Shared`:

```rust
pub enum WorkspaceMode {
    Shared {
        host_path: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        security_model: Option<WorkspaceSecurityModel>,
    },
    Clone { repo_url: String },
}
```

`Option<T>` + `#[serde(default)]` is required by the persisted-blob
rule in CLAUDE.md: old `config_json` blobs written before this field
existed must still deserialize cleanly. `None` is treated as "default"
at template-render time.

### Parsing

`WorkspaceMode::parse_flag` (currently
`sandbox-core/src/session.rs:190-211`) gains the following behaviour
after the existing `shared:` prefix strip:

1. Take the remainder `rest`.
2. `rest.rsplit_once(':')`:
   - If the right side equals `"mapped-xattr"` or `"none"` and the
     left side starts with `/`, treat the right side as the model
     token and the left side as the path.
   - Otherwise, the whole `rest` is the path and `security_model`
     defaults to `None` (resolves to `MappedXattr` at template time).
3. Apply the existing path validation (absolute, exists) to the
   resolved path.

A literal host path of the form `/some/dir:none` is a pathological
case that this rule would mis-parse as `path=/some/dir, model=none`.
This is documented as the compact-form footgun; the closed enum of
valid model tokens keeps the surface narrow.

### Lima template

At `sandbox-core/src/lima.rs:1446-1466`, replace the hardcoded
`securityModel: mapped-xattr` with the chosen model:

```rust
let model = security_model
    .unwrap_or_default()
    .as_yaml();
format!(
    "...\n  9p:\n    securityModel: {model}\n    cache: mmap"
)
```

`cache: mmap` stays — orthogonal to the security model.

### Container backend

The container backend implements shared workspaces with a bind mount
(`sandbox-core/src/backend/container.rs:476-488`) and has no 9p layer.
A `security_model: Some(_)` on `WorkspaceMode::Shared` is meaningless
there.

Behaviour: at the container backend's workspace handling site, reject
`Some(_)` with a clear error variant
(`SandboxError::InvalidConfig` or the existing equivalent) stating
`security_model is only meaningful for the Lima backend; the container
backend uses a bind mount`. This fails fast and visibly rather than
silently dropping the request.

A `None` value remains accepted (the default; backend can ignore it).

### Persistence

`SessionConfig` is unchanged at the struct level — the new field rides
along inside `WorkspaceMode::Shared`'s payload, which is itself
already `Option<WorkspaceMode>` on `SessionConfig` with
`#[serde(skip_serializing_if = "Option::is_none")]`. No migration is
required. Forward and backward compat:

- **Old daemon reading new record.** `security_model` field unknown ⇒
  serde discards (default behaviour); record still deserialises;
  template-time rendering picks `mapped-xattr` (the only model the old
  daemon knew).
- **New daemon reading old record.** Field absent ⇒
  `#[serde(default)]` resolves to `None` ⇒ template renders
  `mapped-xattr` (preserves prior behaviour).

### Verification

The spec ships these tests as a minimum:

- **Parser** (`sandbox-core/src/session.rs` unit tests):
  - `parse_flag("shared:/srv/repo")` → `Shared { host_path: "/srv/repo", security_model: None }`.
  - `parse_flag("shared:/srv/repo:mapped-xattr")` →
    `Shared { ..., security_model: Some(MappedXattr) }`.
  - `parse_flag("shared:/srv/repo:none")` → `Shared { ..., security_model: Some(None) }`.
  - `parse_flag("shared:/srv/repo:bogus")` → falls through (whole
    string treated as path; existing path-exists check rejects).
- **Template** (`sandbox-core/src/lima.rs` unit tests, extending the
  existing `test_generate_template_with_shared_workspace`):
  - Default → asserts rendered YAML contains
    `securityModel: mapped-xattr`.
  - Explicit `MappedXattr` → same.
  - Explicit `None` → asserts `securityModel: none`.
- **Persistence forward-compat** (`sandbox-core/src/session.rs` test
  module or wherever `SessionConfig` round-trip lives): deserialise a
  `config_json` blob that pre-dates the new field; assert
  `security_model` resolves to `None` and the resulting template
  renders `mapped-xattr`.
- **Container backend rejection** (`backend/container.rs` unit test):
  passing a `Shared { security_model: Some(_) }` to the container
  workspace-handling path returns the expected `InvalidConfig` error
  with a message containing `security_model`.
- **Example replay** (manual or integration test, against the Lima
  backend in hardened mode):
  - `sandbox create --workspace shared:/tmp/sbx-default` ⇒ the
    generated lima YAML contains `securityModel: mapped-xattr`; a
    guest-side `ln -s a b` produces a host-side regular file with
    `user.virtfs.symlink.target` xattr.
  - `sandbox create --workspace shared:/tmp/sbx-none:none` ⇒ generated
    YAML contains `securityModel: none`; the same guest-side `ln -s`
    produces a host-side real symlink (`stat -c %F /tmp/sbx-none/b`
    reports `symbolic link`).

### Docs

- `docs/guides/workspaces.md` (around the existing
  `--workspace shared:...` documentation): document the new optional
  `:<model>` suffix. One short paragraph on when to pick `none` (you
  need real symlinks visible to host tools or to rsync/tar/git
  round-trips). Reference the trade-off (ownership/mode ops silently
  no-op) explicitly.
- `docs/guides/hardening.md` (around the existing 9p trade-off
  paragraph): note that the security model is now per-session, that
  `mapped-xattr` remains the default, that `none` does **not** alter
  the QEMU privilege model, and that `passthrough` is deliberately not
  exposed because it would.

## Out of scope

- Exposing `passthrough` or `mapped-file`.
- A way to change the model on an existing session.
- A host-side tool that materialises real symlinks from
  `mapped-xattr` xattrs.
- A bind-mount equivalent option for the container backend.
- Exposing `cache` (`mmap` / `loose` / `none`) as a flag.
- A `sandbox describe` enhancement to surface the chosen model in the
  inspect output (covered organically by serialising
  `WorkspaceMode::Shared`'s payload, but no dedicated UX work).

## Known gaps / deferred decisions

- The compact-form parser cannot disambiguate a literal host path of
  the form `/foo:none`. The closed model enum and required
  absolute-path prefix keep the surface narrow, but this is a
  documented footgun; a `--security-model` separate flag would
  eliminate it. Deferred: would only matter if real users hit it.
- No integration test currently exercises the container backend's
  shared-workspace path with the new rejection error; this spec adds
  a unit-level test, and the E2E suite may surface coverage gaps to
  be addressed as follow-on `progress` todos.
