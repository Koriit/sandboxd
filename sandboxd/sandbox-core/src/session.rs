use std::path::Path;
use std::str::FromStr;

use chrono::{DateTime, Utc};
use enumset::EnumSetType;
use serde::{Deserialize, Deserializer, Serialize};
use uuid::Uuid;

/// Docker-style 12-hex-character session identifier.
///
/// Generated from the first 12 hex characters of a UUID v4 (simple form).
/// Provides a compact, copy-pastable ID (like Docker container IDs) while
/// maintaining uniform distribution and ~48 bits of entropy.
///
/// Internal storage is a fixed-size `[u8; 12]` of ASCII hex bytes so the
/// type is `Copy`, matching the ergonomics of `uuid::Uuid`.
///
/// Validation: exactly 12 characters, all lowercase hexadecimal `[0-9a-f]`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct SessionId([u8; Self::LEN]);

impl SessionId {
    /// Length of a session ID in characters.
    pub const LEN: usize = 12;

    /// Generate a new random session ID.
    ///
    /// Uses the first 12 hex characters of a UUID v4 (simple form). The
    /// uniform distribution of UUID v4 means the truncated prefix is also
    /// uniformly distributed — but with only 48 bits, callers should catch
    /// and retry on collision when inserting into a unique index.
    pub fn generate() -> Self {
        let full = Uuid::new_v4().simple().to_string();
        // simple() is always 32 hex chars.
        debug_assert!(full.len() >= Self::LEN);
        let mut bytes = [0u8; Self::LEN];
        bytes.copy_from_slice(&full.as_bytes()[..Self::LEN]);
        Self(bytes)
    }

    /// Parse a session ID from a string.
    ///
    /// Requires exactly 12 characters of lowercase hexadecimal.
    pub fn parse(s: &str) -> Result<Self, crate::SandboxError> {
        if s.len() != Self::LEN {
            return Err(crate::SandboxError::Internal(format!(
                "invalid session id: expected {} chars, got {}",
                Self::LEN,
                s.len()
            )));
        }
        if !s
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(crate::SandboxError::Internal(format!(
                "invalid session id: must be lowercase hex [0-9a-f], got {s:?}"
            )));
        }
        let mut bytes = [0u8; Self::LEN];
        bytes.copy_from_slice(s.as_bytes());
        Ok(Self(bytes))
    }

    /// Return the raw string representation.
    ///
    /// Since `parse` / `generate` guarantee ASCII hex bytes, the conversion
    /// from `&[u8; 12]` to `&str` is infallible.
    pub fn as_str(&self) -> &str {
        // SAFETY: bytes are validated to be ASCII hex (UTF-8 compatible)
        // by parse()/generate(), so this is sound.
        std::str::from_utf8(&self.0).expect("session id bytes are validated ASCII hex")
    }

    /// Decode the ID into its 6 raw bytes.
    ///
    /// Used for deriving deterministic MAC addresses. Since `parse` /
    /// `generate` guarantee 12 hex chars, this decode is infallible.
    pub fn as_bytes_array(&self) -> [u8; 6] {
        let mut out = [0u8; 6];
        for (i, chunk) in self.0.chunks_exact(2).enumerate() {
            out[i] = (hex_val(chunk[0]) << 4) | hex_val(chunk[1]);
        }
        out
    }
}

#[inline]
fn hex_val(b: u8) -> u8 {
    match b {
        b'0'..=b'9' => b - b'0',
        b'a'..=b'f' => b - b'a' + 10,
        // parse() guarantees only [0-9a-f] bytes reach here.
        _ => unreachable!("non-hex byte in validated SessionId"),
    }
}

impl std::fmt::Display for SessionId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for SessionId {
    type Err = crate::SandboxError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

impl TryFrom<String> for SessionId {
    type Error = crate::SandboxError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::parse(&value)
    }
}

impl From<SessionId> for String {
    fn from(id: SessionId) -> Self {
        id.as_str().to_string()
    }
}

impl AsRef<str> for SessionId {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

/// Per-mount choice of 9p `securityModel` for [`WorkspaceMode::Shared`].
///
/// `mapped-xattr` is the default and keeps the QEMU process unprivileged
/// by storing guest ownership/symlink metadata in host xattrs rather than
/// applying them to the host filesystem directly. `none` (`NoneMapping`)
/// trades that property for real-symlink interop in both directions, at
/// the cost of guest-side chown/mknod/setuid being silently no-ops.
///
/// The variant is named `NoneMapping` rather than `None` so it does not
/// visually collide with `Option::None` at match sites: matching on
/// `Some(WorkspaceSecurityModel::NoneMapping)` is unambiguous in a way
/// that `Some(WorkspaceSecurityModel::None)` is not. The wire form,
/// CLI token, and rendered describe value all stay `none` via the
/// per-variant `#[serde(rename)]` attributes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum WorkspaceSecurityModel {
    #[default]
    #[serde(rename = "mapped-xattr")]
    MappedXattr,
    #[serde(rename = "none")]
    NoneMapping,
}

impl WorkspaceSecurityModel {
    /// Return the wire token used in CLI flags, JSON serialization, and
    /// the rendered Lima `securityModel:` line.
    pub fn as_yaml(&self) -> &'static str {
        match self {
            Self::MappedXattr => "mapped-xattr",
            Self::NoneMapping => "none",
        }
    }
}

/// How the workspace directory is made available inside the VM.
///
/// The serde representation uses a custom deserializer (see the
/// `Deserialize` impl below) so that legacy persisted records that
/// pre-date the `guest_path` field still load cleanly: a missing
/// `guest_path`, or an empty-string `guest_path`, recovers as
/// `guest_path = host_path`. The serializer side is the default derive.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum WorkspaceMode {
    /// Mount a host directory into the VM via 9p (bidirectional, live).
    Shared {
        /// Absolute path on the host to mount.
        host_path: String,
        /// Absolute path inside the guest at which the host directory
        /// appears. Defaults to `host_path` when the operator does not
        /// supply an explicit value; the parser always populates this
        /// field on fresh constructions. Legacy on-disk records lacking
        /// the field recover via the custom deserializer below.
        #[serde(default)]
        guest_path: String,
        /// 9p security model. `None` means "use the backend default"
        /// (`mapped-xattr` on Lima; the container backend rejects any
        /// `Some(_)` value as the bind-mount has no 9p layer).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        security_model: Option<WorkspaceSecurityModel>,
    },
    /// Clone a git repository into the VM at /home/sandbox/workspace/.
    Clone {
        /// Git repository URL.
        repo_url: String,
    },
    /// One-shot host-snapshot sync: rsync `host_path` into `guest_path`
    /// at session-create time. Unlike `Shared` there is no 9p device or
    /// bind-mount — the guest sees ordinary local files refreshed only
    /// when the operator explicitly invokes `sandbox workspace push` /
    /// `pull`.
    ///
    /// `guest_path` defaults to the resolved `host_path` (per the
    /// parser); the custom deserializer below recovers a missing or
    /// empty `guest_path` symmetrically with `Shared` so a record
    /// hand-edited to drop the field still loads.
    Local {
        /// Absolute path on the host whose contents are mirrored
        /// into the guest at create time.
        host_path: String,
        /// Absolute path inside the guest at which the mirror lands.
        /// Defaults to `host_path` when the operator does not supply
        /// an explicit value.
        #[serde(default)]
        guest_path: String,
    },
}

impl<'de> Deserialize<'de> for WorkspaceMode {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        // Private mirror with `guest_path` modelled as `Option<String>` so
        // that legacy records (missing the field, or with an empty-string
        // value) can be detected and recovered to `host_path`. The
        // recovery rule matches the new default semantics: legacy records
        // without `guest_path` recover with `guest_path = host_path`.
        #[derive(Deserialize)]
        #[serde(tag = "type", rename_all = "snake_case")]
        enum Wire {
            Shared {
                host_path: String,
                #[serde(default)]
                guest_path: Option<String>,
                #[serde(default)]
                security_model: Option<WorkspaceSecurityModel>,
            },
            Clone {
                repo_url: String,
            },
            Local {
                host_path: String,
                #[serde(default)]
                guest_path: Option<String>,
            },
        }

        match Wire::deserialize(deserializer)? {
            Wire::Shared {
                host_path,
                guest_path,
                security_model,
            } => {
                let guest_path = match guest_path {
                    Some(g) if !g.is_empty() => g,
                    _ => host_path.clone(),
                };
                Ok(WorkspaceMode::Shared {
                    host_path,
                    guest_path,
                    security_model,
                })
            }
            Wire::Clone { repo_url } => Ok(WorkspaceMode::Clone { repo_url }),
            Wire::Local {
                host_path,
                guest_path,
            } => {
                let guest_path = match guest_path {
                    Some(g) if !g.is_empty() => g,
                    _ => host_path.clone(),
                };
                Ok(WorkspaceMode::Local {
                    host_path,
                    guest_path,
                })
            }
        }
    }
}

/// Kind discriminator for [`WorkspaceMode`], without the variant payload.
///
/// `WorkspaceMode` is data-bearing (`Shared { host_path, guest_path,
/// security_model }`, `Clone { repo_url }`), so it cannot itself
/// participate in [`enumset::EnumSet`] — `EnumSetType` requires unit
/// variants only. `WorkspaceModeKind` is the companion unit-only enum
/// used by [`crate::backend::Capabilities::workspace_modes`] to declare
/// which kinds of workspace handoff a backend supports, independent of
/// any concrete instance.
///
/// The kind is derivable from a `WorkspaceMode` via [`WorkspaceMode::kind`].
///
/// **Forward-compat wire tolerance.** When deserializing an
/// `EnumSet<WorkspaceModeKind>` (e.g. from a newer daemon's capability
/// response), unknown variants are silently dropped. This is implemented
/// via a sentinel `Unknown` variant attached to `#[serde(other)]`; the
/// kind is gated as private and stripped by [`Capabilities`] when the
/// `EnumSet` is constructed from the wire form. See the
/// [`deserialize_workspace_mode_kind_set`] free function used by
/// capability fields for the filtered round-trip.
#[derive(Debug, EnumSetType, Serialize, Deserialize)]
#[enumset(serialize_repr = "list")]
#[serde(rename_all = "snake_case")]
pub enum WorkspaceModeKind {
    /// 9p host-mount; corresponds to [`WorkspaceMode::Shared`].
    Shared,
    /// Git clone into the VM/container; corresponds to [`WorkspaceMode::Clone`].
    Clone,
    /// Host-snapshot rsync; corresponds to [`WorkspaceMode::Local`].
    ///
    /// Declared **after** `Clone` so the source-order-sensitive
    /// renderers (`serialize_repr = "list"`,
    /// `sandbox-cli::render_workspace_modes`) emit a stable
    /// `["shared", "clone", "local"]` sequence.
    Local,
}

/// Deserialize an `EnumSet<WorkspaceModeKind>` from a list of string
/// tokens, silently dropping any token that does not match a known
/// variant.
///
/// This is the forward-compat convention for `EnumSet`-typed
/// capability fields exposed by the daemon: an older CLI built against
/// `WorkspaceModeKind = { Shared, Clone }` that receives
/// `["shared", "clone", "local"]` from a newer daemon must parse the
/// response successfully and expose `{ Shared, Clone }`. The unknown
/// `"local"` token is ignored without failing the parse.
///
/// Wire format: a JSON array of lower-snake-case strings, matching the
/// `serialize_repr = "list"` shape of `EnumSet<WorkspaceModeKind>`.
pub fn deserialize_workspace_mode_kind_set<'de, D>(
    deserializer: D,
) -> Result<enumset::EnumSet<WorkspaceModeKind>, D::Error>
where
    D: Deserializer<'de>,
{
    let raw: Vec<String> = Vec::deserialize(deserializer)?;
    let mut set = enumset::EnumSet::<WorkspaceModeKind>::empty();
    for token in raw {
        match token.as_str() {
            "shared" => {
                set |= WorkspaceModeKind::Shared;
            }
            "clone" => {
                set |= WorkspaceModeKind::Clone;
            }
            "local" => {
                set |= WorkspaceModeKind::Local;
            }
            _ => {
                // Unknown variant on the wire — silently drop.
            }
        }
    }
    Ok(set)
}

impl WorkspaceMode {
    /// Return the kind discriminator for this workspace mode.
    ///
    /// Used for capability checks where the payload (paths, URLs) is
    /// irrelevant — only whether the backend supports the *kind*.
    pub fn kind(&self) -> WorkspaceModeKind {
        match self {
            Self::Shared { .. } => WorkspaceModeKind::Shared,
            Self::Clone { .. } => WorkspaceModeKind::Clone,
            Self::Local { .. } => WorkspaceModeKind::Local,
        }
    }

    /// Parse a workspace mode from the CLI `--workspace` flag value.
    ///
    /// Accepted grammar:
    ///
    /// ```text
    /// shared:<host-path>[:<guest-path>][:<security-model>]
    /// clone:<repo-url>
    /// local:<host-path>[:<guest-path>]
    /// ```
    ///
    /// Path tokens are absolute (start with `/`); guest-side `~` is a
    /// literal substitution to `/home/sandbox`. Host-side `~` must be
    /// expanded by the caller before invoking this function — the
    /// daemon parser explicitly rejects any residual `~` in `host_path`
    /// because the operator's `$HOME` does not match the daemon's.
    /// The CLI is the sole site that performs host-`~` expansion;
    /// `parse_flag` is otherwise environment-free and pure.
    ///
    /// Security-model tokens are the closed set `{mapped-xattr, none}`.
    /// The 9p models `passthrough` and `mapped-file` are deliberately
    /// not exposed; passing either as the trailing token short-circuits
    /// with an explicit pointer at `mapped-xattr` / `none`.
    ///
    /// Normalization (applied before any other step):
    /// 1. Trim leading and trailing ASCII whitespace from the whole input.
    /// 2. Mode prefixes are matched case-sensitively
    ///    (`Shared:/srv/repo` → unknown mode).
    /// 3. A single trailing `/` on `host_path` and `guest_path` is
    ///    stripped after reassembly (`/srv/repo/` → `/srv/repo`).
    ///    Multiple trailing slashes collapse the same way. The root
    ///    path `/` is preserved.
    pub fn parse_flag(value: &str) -> Result<Self, String> {
        // Normalization: trim leading/trailing ASCII whitespace from the
        // whole input. Internal whitespace is preserved into the path
        // and will be caught by the absolute-path or existence checks
        // downstream.
        let input = value.trim();
        if input.is_empty() {
            return Err(format!(
                "unknown workspace mode: {value:?}. Expected \
                 'shared:<host-path>[:<guest-path>][:<security-model>]', \
                 'clone:<repo-url>', or \
                 'local:<host-path>[:<guest-path>]'"
            ));
        }

        // Mode-prefix split: find the first `:`. Mode matching is
        // case-sensitive.
        let (mode, rest) = match input.split_once(':') {
            Some((m, r)) => (m, r),
            None => {
                return Err(format!(
                    "unknown workspace mode: {value:?}. Expected \
                     'shared:<host-path>[:<guest-path>][:<security-model>]', \
                     'clone:<repo-url>', or \
                     'local:<host-path>[:<guest-path>]'"
                ));
            }
        };

        match mode {
            "shared" => parse_shared(rest),
            "clone" => {
                if rest.is_empty() {
                    return Err("clone workspace repo url must not be empty".into());
                }
                Ok(Self::Clone {
                    repo_url: rest.to_string(),
                })
            }
            "local" => parse_local(rest),
            _ => Err(format!(
                "unknown workspace mode: {value:?}. Expected \
                 'shared:<host-path>[:<guest-path>][:<security-model>]', \
                 'clone:<repo-url>', or \
                 'local:<host-path>[:<guest-path>]'"
            )),
        }
    }
}

/// Parse the payload of `shared:<rest>` per the grammar in
/// [`WorkspaceMode::parse_flag`].
///
/// Pulled out into a free function so the (slightly long) right-to-left
/// classifier algorithm stays readable next to the per-step documentation
/// in the design.
fn parse_shared(rest: &str) -> Result<WorkspaceMode, String> {
    if rest.is_empty() {
        return Err(
            "shared workspace requires a host path: shared:<host-path>[:<guest-path>][:<security-model>]"
                .into(),
        );
    }

    // Tokenise on `:`. For `shared:` we accept 1..=3 tokens after the
    // mode prefix. Empty tokens (`shared:/srv::/dst`) are rejected here:
    // every position carries semantic meaning, so a literal empty token
    // is always a mistake.
    let tokens: Vec<&str> = rest.split(':').collect();
    if tokens.iter().any(|t| t.is_empty()) {
        return Err(format!(
            "shared workspace contains an empty token: {rest:?}"
        ));
    }
    if tokens.len() > 3 {
        return Err(format!(
            "shared workspace expects at most 3 tokens (host, guest, security-model), got {n}: {rest:?}",
            n = tokens.len()
        ));
    }

    // We'll work with a `Vec` that we pop trailing tokens off as we
    // classify them right-to-left.
    let mut tokens: Vec<String> = tokens.into_iter().map(str::to_string).collect();

    // Step A — strip a trailing security-model token. The closed enum
    // is { mapped-xattr, none }. The friendly-hint branch fires for the
    // deliberately-unexposed 9p models { passthrough, mapped-file }.
    // Step A is exclusive to `shared:` — `local:` mode has no security
    // model.
    let mut security_model: Option<WorkspaceSecurityModel> = None;
    if tokens.len() >= 2 {
        match tokens.last().map(String::as_str) {
            Some("mapped-xattr") => {
                security_model = Some(WorkspaceSecurityModel::MappedXattr);
                tokens.pop();
            }
            Some("none") => {
                security_model = Some(WorkspaceSecurityModel::NoneMapping);
                tokens.pop();
            }
            Some("passthrough") | Some("mapped-file") => {
                return Err(format!(
                    "`passthrough` and `mapped-file` security models are not exposed; \
                     see `docs/guides/hardening.md`. Use `mapped-xattr` (default) or `none`. \
                     (Got: {tok:?})",
                    tok = tokens.last().unwrap()
                ));
            }
            _ => {}
        }
    }

    let (host_path, guest_path) = parse_host_guest_pair_from_tokens(tokens, "shared")?;

    Ok(WorkspaceMode::Shared {
        host_path,
        guest_path,
        security_model,
    })
}

/// Parse the payload of `local:<rest>` per the grammar in
/// [`WorkspaceMode::parse_flag`].
///
/// Shares the right-to-left token classifier with `parse_shared` via
/// [`parse_host_guest_pair`]; the `local:` mode does not accept a
/// security-model token (the corresponding step A in `parse_shared`
/// is skipped here). After the classifier resolves the host/guest
/// pair, the SF-11 directory-required check rejects single-file
/// or missing host paths with a pointer at `sandbox cp`.
fn parse_local(rest: &str) -> Result<WorkspaceMode, String> {
    let (host_path, guest_path) = parse_host_guest_pair(rest, "local")?;

    // SF-11 — `local:`-only directory-required check. A regular-file
    // `host_path` (or any other non-directory) is rejected with the
    // explicit pointer at `sandbox cp`. The check is intentionally
    // `unwrap_or(false)`: any metadata failure (ENOENT, EACCES, …)
    // resolves to "not a directory" so the operator sees the same
    // crisp error regardless of the underlying syscall failure.
    let is_dir = std::fs::metadata(&host_path)
        .map(|m| m.is_dir())
        .unwrap_or(false);
    if !is_dir {
        return Err(format!(
            "host_path must be a directory for `local:`; to seed a single file, \
             use `sandbox cp <file> <session>:<path>` after creating the session. \
             (Got: {host_path:?})"
        ));
    }

    Ok(WorkspaceMode::Local {
        host_path,
        guest_path,
    })
}

/// Tokenise `rest` and run the right-to-left host/guest classifier
/// (spec steps B/C/D) shared between `parse_shared` and `parse_local`.
///
/// `mode_label` is the user-facing prefix used in error messages
/// (`"shared"` or `"local"`).
///
/// Step A (security-model strip) is exclusive to `parse_shared` and
/// runs on the caller's side before delegating to
/// [`parse_host_guest_pair_from_tokens`]. `parse_local` has no
/// security-model concept, so it calls this entry point which performs
/// tokenisation, empty-token rejection, and the same 1..=2 cap from the
/// grammar (`local:<host>[:<guest>]`).
fn parse_host_guest_pair(rest: &str, mode_label: &str) -> Result<(String, String), String> {
    if rest.is_empty() {
        return Err(format!(
            "{mode_label} workspace requires a host path: {mode_label}:<host-path>[:<guest-path>]"
        ));
    }

    let tokens: Vec<&str> = rest.split(':').collect();
    if tokens.iter().any(|t| t.is_empty()) {
        return Err(format!(
            "{mode_label} workspace contains an empty token: {rest:?}"
        ));
    }
    if tokens.len() > 2 {
        return Err(format!(
            "{mode_label} workspace expects at most 2 tokens (host, guest), got {n}: {rest:?}",
            n = tokens.len()
        ));
    }

    let tokens: Vec<String> = tokens.into_iter().map(str::to_string).collect();
    parse_host_guest_pair_from_tokens(tokens, mode_label)
}

/// Apply parsing steps B/C/D to an already-tokenised `tokens` vector that
/// has had any security-model trailing token popped off by the caller.
///
/// `mode_label` is the user-facing prefix used in error messages
/// (`"shared"` or `"local"`). Returns the resolved `(host_path,
/// guest_path)` pair after `~` expansion (guest side), trailing-slash
/// normalisation, absolute-path enforcement, and the host-path-exists
/// check.
fn parse_host_guest_pair_from_tokens(
    mut tokens: Vec<String>,
    mode_label: &str,
) -> Result<(String, String), String> {
    // Step B — strip a trailing guest-path token. The classifier accepts
    // tokens that start with `/` (absolute) or `~` (literal `/home/sandbox`
    // substitution per the design).
    let guest_path: Option<String> = if tokens.len() >= 2 {
        let last = tokens.last().expect("len >= 2");
        if last.starts_with('/') || last.starts_with('~') {
            let g = tokens.pop().expect("len >= 2");
            Some(g)
        } else {
            None
        }
    } else {
        None
    };

    // Step C — the remaining tokens reassemble into `host_path`. The
    // join recovers literal colons inside the host path that survived
    // the right-to-left classification.
    let raw_host_path = tokens.join(":");
    let host_path = strip_trailing_slashes(&raw_host_path);

    // Step D — `~` expansion and absoluteness.
    //
    // `parse_flag` is a single pure function; the CLI is responsible
    // for expanding host-side `~` before invoking us. Any residual
    // `~` in `host_path` is a sign that the caller bypassed the
    // CLI's expansion step and constructed the request directly —
    // reject with an explicit pointer at the contract.
    if host_path.starts_with('~') {
        return Err(format!(
            "host_path must be absolute; CLI should have expanded `~` before sending. \
             (Got: {host_path:?})"
        ));
    }
    if !Path::new(&host_path).is_absolute() {
        return Err(format!(
            "{mode_label} workspace host_path must be absolute, got: {host_path:?}"
        ));
    }

    // `guest_path` undergoes `~` expansion on both sides as a literal
    // string replacement to `/home/sandbox` — environment-free, so the
    // CLI and the daemon arrive at the same result. The substituted
    // value must still be absolute.
    let guest_path = match guest_path {
        Some(g) => {
            let expanded = expand_guest_tilde(&g);
            let normalized = strip_trailing_slashes(&expanded);
            if !Path::new(&normalized).is_absolute() {
                return Err(format!(
                    "{mode_label} workspace guest_path must be absolute, got: {normalized:?}"
                ));
            }
            normalized
        }
        None => host_path.clone(),
    };

    // Host path existence is checked at parse time per the historical
    // contract: surfacing typos at the CLI before the request hits
    // the daemon is part of what makes the operator-facing error path
    // friendly. The daemon-side parse re-runs the same check; on the
    // daemon's host the operator's typed path resolves to the same
    // filesystem entry (or it doesn't, and the daemon emits the same
    // error verbatim).
    if !Path::new(&host_path).exists() {
        return Err(format!(
            "{mode_label} workspace host_path does not exist: {host_path:?}"
        ));
    }

    Ok((host_path, guest_path))
}

/// Strip a single trailing `/` (or any run of trailing slashes) from a
/// path string, while preserving the root `/`.
fn strip_trailing_slashes(path: &str) -> String {
    if path == "/" {
        return path.to_string();
    }
    let trimmed = path.trim_end_matches('/');
    if trimmed.is_empty() {
        // The whole string was slashes; collapse to the root.
        return "/".to_string();
    }
    trimmed.to_string()
}

/// Expand a leading `~` in a guest-side path to the canonical guest user
/// home (`/home/sandbox`). The substitution is environment-free and runs
/// identically on the CLI and the daemon, per the design.
fn expand_guest_tilde(path: &str) -> String {
    if path == "~" {
        return "/home/sandbox".to_string();
    }
    if let Some(rest) = path.strip_prefix("~/") {
        return format!("/home/sandbox/{rest}");
    }
    path.to_string()
}

/// Current state of a sandbox session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionState {
    Creating,
    Running,
    Stopped,
    Error,
}

impl SessionState {
    /// Check whether a transition from `self` to `new_state` is valid.
    ///
    /// Valid transitions:
    /// - Creating -> Running | Error
    /// - Running -> Stopped | Error
    /// - Stopped -> Running | Error
    /// - Error -> (terminal, no transitions)
    pub fn can_transition_to(self, new_state: SessionState) -> bool {
        matches!(
            (self, new_state),
            (SessionState::Creating, SessionState::Running)
                | (SessionState::Creating, SessionState::Error)
                | (SessionState::Running, SessionState::Stopped)
                | (SessionState::Running, SessionState::Error)
                | (SessionState::Stopped, SessionState::Running)
                | (SessionState::Stopped, SessionState::Error)
        )
    }
}

impl std::fmt::Display for SessionState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Creating => write!(f, "Creating"),
            Self::Running => write!(f, "Running"),
            Self::Stopped => write!(f, "Stopped"),
            Self::Error => write!(f, "Error"),
        }
    }
}

impl FromStr for SessionState {
    type Err = crate::SandboxError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "Creating" => Ok(Self::Creating),
            "Running" => Ok(Self::Running),
            "Stopped" => Ok(Self::Stopped),
            "Error" => Ok(Self::Error),
            other => Err(crate::SandboxError::Internal(format!(
                "unknown session state: {other}"
            ))),
        }
    }
}

/// Resource configuration for a sandbox session.
///
/// Persisted on disk as a JSON blob in the `sessions.config_json` column.
/// Any new field here MUST be `Option<T>` with `#[serde(default)]` so
/// records written by older daemons still deserialize cleanly and records
/// written by newer daemons can be read back on rollback.  See
/// `CLAUDE.md` → "On-disk compatibility" for the full rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionConfig {
    /// Number of CPU cores allocated, integer-valued for backward
    /// compatibility with the persisted `config_json` blob (a daemon
    /// rollback to a pre-todo-#67 build must still be able to read
    /// the integer field). On the container backend this carries the
    /// floored representation of the operator-supplied fractional
    /// value; the precise value lives in [`Self::cpus_decimal`] and
    /// is the authoritative one for HTTP and runtime consumers when
    /// present.
    pub cpus: u32,
    /// Memory in megabytes.
    pub memory_mb: u32,
    /// Disk size in gigabytes.
    pub disk_gb: u32,
    /// How the workspace is provided to the VM (if at all).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub workspace_mode: Option<WorkspaceMode>,
    /// Enable QEMU hardening (device lockdown, cgroup limits).
    ///
    /// When `true` (the default), the QEMU wrapper disables unnecessary
    /// devices and applies cgroup resource limits.  Set to `false` for debugging
    /// or when the hardened configuration causes compatibility issues.
    #[serde(default = "default_hardened")]
    pub hardened: bool,
    /// Git repository URL cloned into `/home/sandbox/workspace/` at creation.
    ///
    /// Captured so `sandbox inspect`/`sandbox describe` can surface the
    /// original creation input.  `None` on records written by daemons
    /// predating this field (forward-compatible via `#[serde(default)]`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub repo: Option<String>,
    /// Command executed inside the VM once setup completes.
    ///
    /// Captured so `sandbox inspect`/`sandbox describe` can surface the
    /// original creation input.  `None` on records written by daemons
    /// predating this field (forward-compatible via `#[serde(default)]`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub boot_cmd: Option<String>,
    /// Path to a custom Lima template used for creation, if any.
    ///
    /// Captured so `sandbox inspect`/`sandbox describe` can surface the
    /// original creation input.  `None` on records written by daemons
    /// predating this field (forward-compatible via `#[serde(default)]`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub template: Option<String>,
    /// 1-decimal CPU value for the container backend (`0.8`, `1.5`,
    /// `2.0`, …). The wire boundary is `f32` so the resource-defaults
    /// precision survives end-to-end (the
    /// historical `u32` shape silently truncated `1.5` to `1` in
    /// `ContainerRuntime::resource_ceilings`).
    ///
    /// Persisted alongside the integer [`Self::cpus`] field rather
    /// than replacing it: an older daemon rolling back must still
    /// see a usable value in the original column. When this field is
    /// `Some`, it is the authoritative precise value (used by the
    /// runtime and the HTTP DTO render); `cpus` then carries the
    /// floored representation as a fallback for older readers.
    /// `None` on records written by daemons predating fractional cpus
    /// (and on every Lima session, where only integer CPUs are supported).
    /// Forward-compatible via `#[serde(default)]` per CLAUDE.md
    /// "On-disk compatibility".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cpus_decimal: Option<f32>,
    /// Rootless-Docker probe outcome captured at session-create time.
    /// `Some(_)` only for container sessions where the daemon ran
    /// the probe; `None` for every Lima session and for legacy
    /// container records written before the probe was introduced.
    ///
    /// Surfaced on the wire by the [`crate::api::SessionDto::rootless`]
    /// field so `sandbox inspect` and `sandbox describe` can render
    /// the operator-relevant pair (`detected`, `forced`) without
    /// re-running the probe. Persisted in `config_json` alongside
    /// the rest of the session config; forward-compatible via
    /// `#[serde(default)]` (older daemons rolling back ignore the
    /// unknown field, newer daemons reading older records get
    /// `None`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rootless_docker: Option<SessionRootlessDocker>,
}

/// Persisted rootless-Docker probe outcome for a container session.
///
/// Captured at `POST /sessions` time and stamped into
/// [`SessionConfig::rootless_docker`] so `GET /sessions/{id}` can
/// render the same pair without re-probing — the per-daemon-lifetime
/// probe cache (`backend::container_rootless_probe`) means the value
/// stamped here would never disagree with a fresh re-probe inside
/// the same daemon process anyway, but threading the recorded value
/// through the wire keeps the inspect surface consistent across
/// daemon restarts and across the create-vs-inspect call boundary.
///
/// `forced` implies `detected`: the daemon only sets `forced = true`
/// when the probe returned `true` AND the operator passed
/// `--force-rootless-docker`. A default-hardened host stamps
/// `detected: false, forced: false`; a rootless host without the
/// override is refused at create time and never reaches this struct;
/// a rootless host with the override stamps `detected: true,
/// forced: true`.
///
/// Lima sessions never construct this — the probe is gated to the
/// container backend only.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct SessionRootlessDocker {
    /// `true` when the host's `docker info` reported `name=rootless`
    /// at session-create time.
    pub detected: bool,
    /// `true` when the operator passed `--force-rootless-docker` AND
    /// the probe detected rootless mode (i.e., the override actually
    /// applied). `false` on default-hardened hosts even if the
    /// operator passed the flag — the override is only meaningful in
    /// the detected-rootless case.
    pub forced: bool,
}

fn default_hardened() -> bool {
    true
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            cpus: 2,
            memory_mb: 4096,
            disk_gb: 20,
            workspace_mode: None,
            hardened: true,
            repo: None,
            boot_cmd: None,
            template: None,
            cpus_decimal: None,
            rootless_docker: None,
        }
    }
}

/// A sandbox session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    pub id: SessionId,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    pub state: SessionState,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub config: SessionConfig,
    /// Which backend owns this session's runtime resources.
    ///
    /// Persisted as the `sessions.backend` SQLite column (V005
    /// migration); legacy rows written before V005 default to
    /// `BackendKind::Lima` via the column's SQL `DEFAULT 'lima'`,
    /// so any session that pre-dates the column is unambiguously a
    /// Lima session. The container backend threads this kind through
    /// `runtime_for(...)` so handlers dispatch to the right
    /// `SessionRuntime` for each persisted row, without re-deriving
    /// the kind from per-handler heuristics.
    ///
    /// `#[serde(default)]` so JSON snapshots written by older code
    /// paths still deserialize cleanly (defaulting to Lima); the
    /// authoritative source remains the SQLite column.
    #[serde(default)]
    pub backend: crate::backend::BackendKind,
    /// Username of the operator who created this session. Stamped at
    /// `POST /sessions` from `SO_PEERCRED`-resolved identity and used
    /// as the per-caller filter on every subsequent
    /// `SessionStore` read or mutation. Persisted as the `sessions.owner_username` SQLite column
    /// added by migration V006; legacy rows written before V006 are
    /// erased by V006's destructive `DELETE FROM sessions` step, so
    /// every row reaching this field has a real value.
    ///
    /// `#[serde(default)]` so JSON snapshots written by older code
    /// paths still deserialize cleanly (defaulting to the empty string);
    /// the authoritative source remains the SQLite column.
    #[serde(default)]
    pub owner_username: String,
    /// Daemon ↔ guest wire-protocol version stamped at session-create
    /// time. Bumped only when the protocol shape changes; the
    /// `start_session` compat gate (per-caller isolation)
    /// reads this to decide whether to take the fast path, refresh the
    /// guest binary, or refuse.
    ///
    /// `#[serde(default)]` so JSON snapshots written by older code
    /// paths still deserialize cleanly (defaulting to `0`).
    #[serde(default)]
    pub guest_protocol_version: u32,
    /// Semver of the `sandbox-guest` binary running inside this
    /// session's VM/container. Bumped on every guest release; surfaced
    /// in `sandbox describe` / diagnostic paths only (no decision
    /// logic reads this — that's `guest_protocol_version`'s role).
    ///
    /// `#[serde(default)]` so JSON snapshots written by older code
    /// paths still deserialize cleanly (defaulting to the empty string).
    #[serde(default)]
    pub guest_binary_version: String,
    /// Per-session SSH keypair used by the daemon-mediated SSH proxy.
    /// Generated at session-create time for container sessions and
    /// persisted in `sessions.ssh_keypair_json` (V007 migration).
    ///
    /// `None` for:
    /// * Lima sessions — Lima manages per-VM SSH credentials on the
    ///   daemon-side `~/.lima/`, so the daemon reads them on demand
    ///   when serving the `GET /sessions/{id}/ssh-config` endpoint.
    /// * Pre-V007 container sessions — the `ssh-config` endpoint
    ///   returns `404 SSH_NOT_AVAILABLE` for these; lazy keypair
    ///   generation is explicitly out of scope (would require sshd
    ///   hot-reload, which the lite-image is not designed for).
    ///
    /// **Trust-model note**: the private half is stored plaintext at
    /// rest under the SQLite file's 0600 mode (enforced in
    /// `SessionStore::new`). Any member of the `sandbox` OS group can
    /// already retrieve it through the `GET /sessions/{id}/ssh-config`
    /// endpoint, so the file mode is the boundary — do not weaken it
    /// without revisiting the cross-user CLI access spec's security
    /// considerations. See [`crate::ssh::SshKeypair`] for the full
    /// rationale.
    ///
    /// `#[serde(default, skip_serializing_if = "Option::is_none")]`
    /// keeps the JSON envelope omitted when absent so an older daemon
    /// rolling back over a record this newer daemon wrote silently
    /// skips the unknown field. Mirrors the forward-compat convention
    /// every additive `Session` / `SessionConfig` field follows.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ssh_keypair: Option<crate::ssh::SshKeypair>,
    /// Numeric uid of the operator who created this session, captured
    /// at `POST /sessions` time via `SO_PEERCRED`. Persisted in the
    /// `sessions.operator_uid` column (V008 migration) so the
    /// supervisor-fork spawn path can recover the operator identity
    /// after a daemon restart without re-resolving via NSS.
    ///
    /// `None` on pre-V008 rows (the column is nullable; the migration
    /// does not backfill). Sessions with `None` route through the
    /// legacy spawn-as-daemon path — no operator-uid alignment, no
    /// `--user <uid>:<gid>` flag on `docker create`, no Lima cloud-init
    /// usermod step. Newly created sessions on V008+ daemons always
    /// carry `Some(uid)`.
    ///
    /// `#[serde(default, skip_serializing_if = "Option::is_none")]`
    /// keeps the JSON envelope omitted when absent so an older daemon
    /// rolling back over a record this newer daemon wrote silently
    /// skips the unknown field. Mirrors the forward-compat convention
    /// every additive `Session` field follows (see CLAUDE.md
    /// "On-disk compatibility").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operator_uid: Option<u32>,
    /// Numeric primary gid of the operator who created this session,
    /// captured alongside [`Self::operator_uid`]. Persisted in the
    /// `sessions.operator_gid` column (V008 migration).
    ///
    /// Travels with `operator_uid` because the supervisor-fork's
    /// `setresuid` + container `--user <uid>:<gid>` flag both need
    /// the full pair. `None` semantics match [`Self::operator_uid`]
    /// (pre-V008 row, route through the legacy spawn path).
    ///
    /// `#[serde(default, skip_serializing_if = "Option::is_none")]`
    /// per the forward-compat convention.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operator_gid: Option<u32>,
    /// Whether sshd came up inside the container after `docker start`.
    ///
    /// Probed once at session-create time on the container backend via
    /// a best-effort `docker exec <ctr> ss -tlnH "( sport = :22 )"`.
    /// `Some(true)` — sshd is listening on port 22 inside the container.
    /// `Some(false)` — probe ran; sshd was not listening. The proxy
    ///   short-circuit refuses the tunnel with `BACKEND_UNAVAILABLE`
    ///   (4001) rather than opening a hang-prone connection.
    /// `None` — probe not yet run, probe failed, Lima backend, or a
    ///   pre-V010 row; the proxy falls back to the legacy "attempt the
    ///   tunnel" behaviour so no existing sessions regress.
    ///
    /// Only set for container-backed sessions. Lima sessions never probe
    /// this (cloud-init manages sshd on that path) and always read `None`.
    ///
    /// Persisted in the `sessions.sshd_ready` column (V010 migration).
    /// `#[serde(default, skip_serializing_if = "Option::is_none")]`
    /// per the forward-compat convention (CLAUDE.md "On-disk
    /// compatibility").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sshd_ready: Option<bool>,
}

impl Session {
    /// Create a new session with the given name and default config.
    ///
    /// Defaults the backend to `Lima` to preserve the historical
    /// shape of `Session::new`. New code paths that need a non-Lima
    /// backend should use [`Session::with_config_and_backend`].
    pub fn new(name: Option<String>) -> Self {
        let now = Utc::now();
        Self {
            id: SessionId::generate(),
            name,
            state: SessionState::Creating,
            created_at: now,
            updated_at: now,
            config: SessionConfig::default(),
            backend: crate::backend::BackendKind::Lima,
            owner_username: String::new(),
            guest_protocol_version: 0,
            guest_binary_version: String::new(),
            ssh_keypair: None,
            operator_uid: None,
            operator_gid: None,
            sshd_ready: None,
        }
    }

    /// Create a new session with a specific config (Lima backend).
    ///
    /// Retained as a back-compat shim for tests and pre-Phase-3D
    /// call sites; container-backed sessions go through
    /// [`Session::with_config_and_backend`].
    pub fn with_config(name: Option<String>, config: SessionConfig) -> Self {
        Self::with_config_and_backend(name, config, crate::backend::BackendKind::Lima)
    }

    /// Create a new session with a specific config and backend.
    pub fn with_config_and_backend(
        name: Option<String>,
        config: SessionConfig,
        backend: crate::backend::BackendKind,
    ) -> Self {
        let now = Utc::now();
        Self {
            id: SessionId::generate(),
            name,
            state: SessionState::Creating,
            created_at: now,
            updated_at: now,
            config,
            backend,
            owner_username: String::new(),
            guest_protocol_version: 0,
            guest_binary_version: String::new(),
            ssh_keypair: None,
            operator_uid: None,
            operator_gid: None,
            sshd_ready: None,
        }
    }

    /// Transition to a new state, updating the `updated_at` timestamp.
    ///
    /// Valid transitions:
    /// - Creating -> Running | Error
    /// - Running -> Stopped | Error
    /// - Stopped -> Running | Error
    /// - Error -> (terminal, no transitions)
    pub fn transition_to(&mut self, new_state: SessionState) -> Result<(), crate::SandboxError> {
        if !self.state.can_transition_to(new_state) {
            return Err(crate::SandboxError::InvalidState(format!(
                "cannot transition from {} to {}",
                self.state, new_state
            )));
        }

        self.state = new_state;
        self.updated_at = Utc::now();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_session_has_creating_state() {
        let session = Session::new(Some("test".into()));
        assert_eq!(session.state, SessionState::Creating);
        assert_eq!(session.name, Some("test".into()));
        assert_eq!(session.config.cpus, 2);
        assert_eq!(session.config.memory_mb, 4096);
        assert_eq!(session.config.disk_gb, 20);
    }

    #[test]
    fn new_session_without_name() {
        let session = Session::new(None);
        assert_eq!(session.state, SessionState::Creating);
        assert!(session.name.is_none());
    }

    #[test]
    fn session_with_custom_config() {
        let config = SessionConfig {
            cpus: 4,
            memory_mb: 8192,
            disk_gb: 50,
            workspace_mode: None,
            hardened: true,
            repo: None,
            boot_cmd: None,
            template: None,
            cpus_decimal: None,
            rootless_docker: None,
        };
        let session = Session::with_config(Some("custom".into()), config);
        assert_eq!(session.config.cpus, 4);
        assert_eq!(session.config.memory_mb, 8192);
        assert_eq!(session.config.disk_gb, 50);
    }

    #[test]
    fn valid_state_transitions() {
        let mut session = Session::new(None);
        assert_eq!(session.state, SessionState::Creating);

        // Creating -> Running
        session.transition_to(SessionState::Running).unwrap();
        assert_eq!(session.state, SessionState::Running);

        // Running -> Stopped
        session.transition_to(SessionState::Stopped).unwrap();
        assert_eq!(session.state, SessionState::Stopped);

        // Stopped -> Running (restart)
        session.transition_to(SessionState::Running).unwrap();
        assert_eq!(session.state, SessionState::Running);
    }

    #[test]
    fn invalid_state_transition() {
        let mut session = Session::new(None);
        // Creating -> Stopped is not valid
        let result = session.transition_to(SessionState::Stopped);
        assert!(result.is_err());
        // State should be unchanged
        assert_eq!(session.state, SessionState::Creating);
    }

    #[test]
    fn error_state_is_terminal() {
        let mut session = Session::new(None);
        session.transition_to(SessionState::Error).unwrap();
        assert_eq!(session.state, SessionState::Error);

        // Cannot transition out of Error
        let result = session.transition_to(SessionState::Running);
        assert!(result.is_err());
        assert_eq!(session.state, SessionState::Error);
    }

    #[test]
    fn can_transition_to_valid() {
        assert!(SessionState::Creating.can_transition_to(SessionState::Running));
        assert!(SessionState::Creating.can_transition_to(SessionState::Error));
        assert!(SessionState::Running.can_transition_to(SessionState::Stopped));
        assert!(SessionState::Running.can_transition_to(SessionState::Error));
        assert!(SessionState::Stopped.can_transition_to(SessionState::Running));
        assert!(SessionState::Stopped.can_transition_to(SessionState::Error));
    }

    #[test]
    fn can_transition_to_invalid() {
        // Error is terminal
        assert!(!SessionState::Error.can_transition_to(SessionState::Running));
        assert!(!SessionState::Error.can_transition_to(SessionState::Stopped));
        assert!(!SessionState::Error.can_transition_to(SessionState::Creating));

        // Creating cannot go directly to Stopped
        assert!(!SessionState::Creating.can_transition_to(SessionState::Stopped));

        // No self-transitions
        assert!(!SessionState::Running.can_transition_to(SessionState::Running));
        assert!(!SessionState::Stopped.can_transition_to(SessionState::Stopped));
        assert!(!SessionState::Creating.can_transition_to(SessionState::Creating));
        assert!(!SessionState::Error.can_transition_to(SessionState::Error));
    }

    #[test]
    fn transition_updates_timestamp() {
        let mut session = Session::new(None);
        let original = session.updated_at;

        // Small sleep to ensure timestamps differ
        std::thread::sleep(std::time::Duration::from_millis(10));

        session.transition_to(SessionState::Running).unwrap();
        assert!(session.updated_at > original);
    }

    #[test]
    fn serialization_round_trip() {
        let session = Session::new(Some("round-trip".into()));
        let json = serde_json::to_string(&session).unwrap();
        let deserialized: Session = serde_json::from_str(&json).unwrap();

        assert_eq!(session.id, deserialized.id);
        assert_eq!(session.name, deserialized.name);
        assert_eq!(session.state, deserialized.state);
        assert_eq!(session.created_at, deserialized.created_at);
        assert_eq!(session.config.cpus, deserialized.config.cpus);
        assert_eq!(session.config.memory_mb, deserialized.config.memory_mb);
        assert_eq!(session.config.disk_gb, deserialized.config.disk_gb);
    }

    /// Pre-V008 serialised `Session` records carry no `operator_uid` /
    /// `operator_gid` keys at all. Both fields must deserialise to
    /// `None` via `#[serde(default)]` so an older row hand-edited or
    /// produced by a pre-V008 daemon still loads cleanly. The
    /// rollback-from-newer-daemon case is the same shape: an older
    /// reader sees the unknown keys and silently drops them (per
    /// `Session`'s deny-unknown-fields-off default).
    #[test]
    fn operator_uid_gid_default_to_none_on_legacy_record() {
        // Minimal Session JSON without the V008 fields. Keys that
        // pre-date V008: id, state, created_at, updated_at, config,
        // backend, owner_username, guest_protocol_version,
        // guest_binary_version.
        let json = r#"{
            "id": "abcdef012345",
            "state": "running",
            "created_at": "2026-01-01T00:00:00Z",
            "updated_at": "2026-01-01T00:00:00Z",
            "config": {"cpus": 2, "memory_mb": 4096, "disk_gb": 20},
            "owner_username": "alice"
        }"#;
        let session: Session = serde_json::from_str(json).unwrap();
        assert!(
            session.operator_uid.is_none(),
            "pre-V008 record must deserialise with operator_uid = None; got {:?}",
            session.operator_uid
        );
        assert!(
            session.operator_gid.is_none(),
            "pre-V008 record must deserialise with operator_gid = None; got {:?}",
            session.operator_gid
        );
    }

    /// `operator_uid` / `operator_gid` round-trip through serde when
    /// stamped with concrete values — the wire form emits both keys,
    /// and the deserialiser recovers the integer pair. Companion to
    /// the legacy-record test above.
    #[test]
    fn operator_uid_gid_round_trip_with_values() {
        let mut session = Session::new(Some("with-operator".into()));
        session.operator_uid = Some(1234);
        session.operator_gid = Some(5678);
        let json = serde_json::to_string(&session).unwrap();
        assert!(
            json.contains("\"operator_uid\":1234"),
            "operator_uid must be emitted on the wire when Some; got {json}"
        );
        assert!(
            json.contains("\"operator_gid\":5678"),
            "operator_gid must be emitted on the wire when Some; got {json}"
        );
        let deser: Session = serde_json::from_str(&json).unwrap();
        assert_eq!(deser.operator_uid, Some(1234));
        assert_eq!(deser.operator_gid, Some(5678));
    }

    /// `operator_uid` / `operator_gid` are omitted from the wire when
    /// `None` (per `#[serde(skip_serializing_if = "Option::is_none")]`).
    /// This pins the rollback shape: a newer daemon's record that
    /// happens to have `None` for both fields persists no `operator_uid`
    /// / `operator_gid` keys, so an older reader sees exactly the
    /// pre-V008 wire form.
    #[test]
    fn operator_uid_gid_omitted_when_none() {
        let session = Session::new(Some("legacy-shape".into()));
        let json = serde_json::to_string(&session).unwrap();
        assert!(
            !json.contains("operator_uid"),
            "operator_uid must be omitted from wire when None; got {json}"
        );
        assert!(
            !json.contains("operator_gid"),
            "operator_gid must be omitted from wire when None; got {json}"
        );
    }

    #[test]
    fn session_state_serialization() {
        // Verify snake_case serialization
        let json = serde_json::to_string(&SessionState::Creating).unwrap();
        assert_eq!(json, "\"creating\"");

        let json = serde_json::to_string(&SessionState::Running).unwrap();
        assert_eq!(json, "\"running\"");

        let json = serde_json::to_string(&SessionState::Stopped).unwrap();
        assert_eq!(json, "\"stopped\"");

        let json = serde_json::to_string(&SessionState::Error).unwrap();
        assert_eq!(json, "\"error\"");

        // Round-trip
        let state: SessionState = serde_json::from_str("\"running\"").unwrap();
        assert_eq!(state, SessionState::Running);
    }

    #[test]
    fn default_session_config() {
        let config = SessionConfig::default();
        assert_eq!(config.cpus, 2);
        assert_eq!(config.memory_mb, 4096);
        assert_eq!(config.disk_gb, 20);
        assert!(config.workspace_mode.is_none());
        assert!(config.hardened, "hardened should default to true");
        assert!(config.repo.is_none(), "repo defaults to None");
        assert!(config.boot_cmd.is_none(), "boot_cmd defaults to None");
        assert!(config.template.is_none(), "template defaults to None");
    }

    #[test]
    fn hardened_defaults_true_on_deserialization() {
        // When the `hardened` field is missing from JSON, it should
        // default to true via the serde default function.
        let json = r#"{"cpus": 2, "memory_mb": 4096, "disk_gb": 20}"#;
        let config: SessionConfig = serde_json::from_str(json).unwrap();
        assert!(
            config.hardened,
            "hardened should default to true when absent from JSON"
        );
    }

    #[test]
    fn hardened_false_roundtrip() {
        let config = SessionConfig {
            cpus: 2,
            memory_mb: 4096,
            disk_gb: 20,
            workspace_mode: None,
            hardened: false,
            repo: None,
            boot_cmd: None,
            template: None,
            cpus_decimal: None,
            rootless_docker: None,
        };
        let json = serde_json::to_string(&config).unwrap();
        let deser: SessionConfig = serde_json::from_str(&json).unwrap();
        assert!(
            !deser.hardened,
            "hardened=false should survive serialization round-trip"
        );
    }

    #[test]
    fn legacy_config_json_deserializes_with_none_for_new_fields() {
        // A record written by an older daemon has no `repo`,
        // `boot_cmd`, or `template` keys at all.  These fields must
        // deserialize to `None` via `#[serde(default)]` so that rolling
        // upgrades (and mid-conversation rollbacks) do not fail to load.
        let json = r#"{"cpus": 2, "memory_mb": 4096, "disk_gb": 20, "hardened": true}"#;
        let config: SessionConfig = serde_json::from_str(json).unwrap();
        assert_eq!(config.cpus, 2);
        assert_eq!(config.memory_mb, 4096);
        assert_eq!(config.disk_gb, 20);
        assert!(config.hardened);
        assert!(config.workspace_mode.is_none());
        assert!(
            config.repo.is_none(),
            "repo must default to None on legacy records"
        );
        assert!(
            config.boot_cmd.is_none(),
            "boot_cmd must default to None on legacy records"
        );
        assert!(
            config.template.is_none(),
            "template must default to None on legacy records"
        );
        assert!(
            config.cpus_decimal.is_none(),
            "cpus_decimal must default to None on legacy records"
        );
    }

    /// Forward-compat round-trip for [`SessionConfig::cpus_decimal`].
    /// A daemon that persists a fractional cpus value sets both
    /// `cpus` (floored) and `cpus_decimal`; on
    /// rollback an older daemon ignores the unknown field and reads
    /// the integer one. On forward read the new daemon picks up the
    /// precise float value.
    #[test]
    fn cpus_decimal_round_trips_through_serde() {
        let config = SessionConfig {
            cpus: 1, // floor of 1.5
            memory_mb: 4096,
            disk_gb: 20,
            workspace_mode: None,
            hardened: false,
            repo: None,
            boot_cmd: None,
            template: None,
            cpus_decimal: Some(1.5),
            rootless_docker: None,
        };
        let json = serde_json::to_string(&config).unwrap();
        // Wire-form sanity: both keys present, integer is the floor.
        assert!(
            json.contains("\"cpus_decimal\""),
            "cpus_decimal must be emitted when Some; got {json}"
        );
        let deser: SessionConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(deser.cpus, 1);
        assert_eq!(deser.cpus_decimal, Some(1.5));
    }

    /// Forward-compat: a legacy record with no `cpus_decimal` key
    /// must deserialise cleanly with `cpus_decimal: None`. This is
    /// the rollback-from-newer-daemon scenario: the older daemon (us
    /// here) reads a record that *might* be missing the field and
    /// must not fail.
    #[test]
    fn legacy_record_without_cpus_decimal_deserialises() {
        let json = r#"{"cpus": 2, "memory_mb": 4096, "disk_gb": 20, "hardened": true}"#;
        let config: SessionConfig = serde_json::from_str(json).unwrap();
        assert_eq!(config.cpus, 2);
        assert!(config.cpus_decimal.is_none());
    }

    #[test]
    fn new_fields_round_trip_through_serde() {
        let config = SessionConfig {
            cpus: 4,
            memory_mb: 8192,
            disk_gb: 50,
            workspace_mode: None,
            hardened: true,
            repo: Some("https://github.com/example/app.git".into()),
            boot_cmd: Some("make setup".into()),
            template: Some("/tmp/custom.yaml".into()),
            cpus_decimal: None,
            rootless_docker: None,
        };
        let json = serde_json::to_string(&config).unwrap();
        let deser: SessionConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(
            deser.repo.as_deref(),
            Some("https://github.com/example/app.git")
        );
        assert_eq!(deser.boot_cmd.as_deref(), Some("make setup"));
        assert_eq!(deser.template.as_deref(), Some("/tmp/custom.yaml"));
    }

    #[test]
    fn none_fields_are_omitted_from_wire() {
        let config = SessionConfig::default();
        let json = serde_json::to_string(&config).unwrap();
        // workspace_mode, repo, boot_cmd, template, cpus_decimal all
        // skip when None — keeps the persisted blob shape stable for
        // the legacy Lima sessions that never carry these fields.
        assert!(!json.contains("workspace_mode"), "wire JSON: {json}");
        assert!(!json.contains("\"repo\""), "wire JSON: {json}");
        assert!(!json.contains("boot_cmd"), "wire JSON: {json}");
        assert!(!json.contains("template"), "wire JSON: {json}");
        assert!(!json.contains("cpus_decimal"), "wire JSON: {json}");
    }

    // -----------------------------------------------------------------
    // WorkspaceMode + parse_flag tests
    // -----------------------------------------------------------------

    /// Helper: assemble the canonical `Shared` payload for a parser
    /// expected-value assertion. Most parser tests construct the same
    /// shape so a tiny constructor keeps the tests readable.
    fn shared(host: &str, guest: &str, model: Option<WorkspaceSecurityModel>) -> WorkspaceMode {
        WorkspaceMode::Shared {
            host_path: host.into(),
            guest_path: guest.into(),
            security_model: model,
        }
    }

    // -- Parser positive cases ----------------------------------------

    #[test]
    fn parse_flag_shared_host_only_defaults_guest_to_host() {
        // `/tmp` is guaranteed to exist on every host the test runs on.
        let mode = WorkspaceMode::parse_flag("shared:/tmp").unwrap();
        assert_eq!(mode, shared("/tmp", "/tmp", None));
    }

    #[test]
    fn parse_flag_shared_with_explicit_guest_path() {
        let mode = WorkspaceMode::parse_flag("shared:/tmp:/srv/work").unwrap();
        assert_eq!(mode, shared("/tmp", "/srv/work", None));
    }

    #[test]
    fn parse_flag_shared_with_security_model_mapped_xattr() {
        // SF-17: explicit `mapped-xattr` token is preserved as
        // `Some(MappedXattr)`, NOT collapsed to `None`. The describe
        // renderer relies on this distinction.
        let mode = WorkspaceMode::parse_flag("shared:/tmp:mapped-xattr").unwrap();
        assert_eq!(
            mode,
            shared("/tmp", "/tmp", Some(WorkspaceSecurityModel::MappedXattr))
        );
    }

    #[test]
    fn parse_flag_shared_with_security_model_none() {
        let mode = WorkspaceMode::parse_flag("shared:/tmp:none").unwrap();
        assert_eq!(
            mode,
            shared("/tmp", "/tmp", Some(WorkspaceSecurityModel::NoneMapping))
        );
    }

    #[test]
    fn parse_flag_shared_with_explicit_guest_and_security_model_mapped_xattr() {
        let mode = WorkspaceMode::parse_flag("shared:/tmp:/srv/work:mapped-xattr").unwrap();
        assert_eq!(
            mode,
            shared(
                "/tmp",
                "/srv/work",
                Some(WorkspaceSecurityModel::MappedXattr),
            )
        );
    }

    #[test]
    fn parse_flag_shared_with_explicit_guest_and_security_model_none() {
        let mode = WorkspaceMode::parse_flag("shared:/tmp:/srv/work:none").unwrap();
        assert_eq!(
            mode,
            shared(
                "/tmp",
                "/srv/work",
                Some(WorkspaceSecurityModel::NoneMapping)
            )
        );
    }

    #[test]
    fn parse_flag_shared_guest_path_that_looks_like_a_model_name() {
        // Step A only classifies the closed enum tokens
        // {mapped-xattr, none} as security models. A guest path that
        // happens to live at `/path-named-none` is absolute and starts
        // with `/`, so step B consumes it as a guest path; it does
        // NOT get reclassified as `NoneMapping`. The slot
        // disambiguation is "model token must be the *exact* enum
        // spelling, otherwise it is treated as a path classification
        // candidate."
        let mode = WorkspaceMode::parse_flag("shared:/tmp:/path-named-none").unwrap();
        assert_eq!(mode, shared("/tmp", "/path-named-none", None));
    }

    #[test]
    fn parse_flag_shared_strips_trailing_whitespace() {
        // SF-16: leading/trailing whitespace on the whole input is
        // trimmed before any other step.
        let mode = WorkspaceMode::parse_flag("  shared:/tmp  ").unwrap();
        assert_eq!(mode, shared("/tmp", "/tmp", None));
    }

    #[test]
    fn parse_flag_shared_strips_trailing_slash_on_host_path() {
        // SF-16: a single trailing `/` on host_path is stripped during
        // parsing. The persisted host_path is the canonical form.
        let mode = WorkspaceMode::parse_flag("shared:/tmp/").unwrap();
        assert_eq!(mode, shared("/tmp", "/tmp", None));
    }

    #[test]
    fn parse_flag_shared_strips_trailing_slash_on_guest_path() {
        let mode = WorkspaceMode::parse_flag("shared:/tmp:/srv/work/").unwrap();
        assert_eq!(mode, shared("/tmp", "/srv/work", None));
    }

    #[test]
    fn parse_flag_shared_collapses_multiple_trailing_slashes_on_host() {
        let mode = WorkspaceMode::parse_flag("shared:/tmp//").unwrap();
        assert_eq!(mode, shared("/tmp", "/tmp", None));
    }

    #[test]
    fn parse_flag_shared_preserves_root_host_path() {
        // The root path `/` must be preserved; the trailing-slash strip
        // doesn't reduce it to an empty string.
        let mode = WorkspaceMode::parse_flag("shared:/").unwrap();
        assert_eq!(mode, shared("/", "/", None));
    }

    #[test]
    fn parse_flag_shared_with_guest_tilde_expands_to_home_sandbox() {
        // Guest-side `~` is a literal substitution to `/home/sandbox`,
        // environment-independent.
        let mode = WorkspaceMode::parse_flag("shared:/tmp:~/work").unwrap();
        assert_eq!(mode, shared("/tmp", "/home/sandbox/work", None));
    }

    #[test]
    fn parse_flag_shared_with_guest_tilde_only_expands_to_home_sandbox() {
        let mode = WorkspaceMode::parse_flag("shared:/tmp:~").unwrap();
        assert_eq!(mode, shared("/tmp", "/home/sandbox", None));
    }

    #[test]
    fn parse_flag_clone_repo_url() {
        let mode = WorkspaceMode::parse_flag("clone:https://github.com/example/repo.git").unwrap();
        assert_eq!(
            mode,
            WorkspaceMode::Clone {
                repo_url: "https://github.com/example/repo.git".into()
            }
        );
    }

    // -- Parser negative cases ----------------------------------------

    #[test]
    fn parse_flag_empty_input_errors() {
        let err = WorkspaceMode::parse_flag("").unwrap_err();
        assert!(err.contains("unknown workspace mode"), "err = {err}");
    }

    #[test]
    fn parse_flag_mode_only_no_colon_errors() {
        let err = WorkspaceMode::parse_flag("shared").unwrap_err();
        assert!(err.contains("unknown workspace mode"), "err = {err}");
    }

    #[test]
    fn parse_flag_empty_mode_prefix_errors() {
        let err = WorkspaceMode::parse_flag(":/tmp").unwrap_err();
        assert!(err.contains("unknown workspace mode"), "err = {err}");
    }

    #[test]
    fn parse_flag_shared_colon_only_errors() {
        // `shared:` — `rest` after stripping the mode prefix is the
        // empty string, so the parser takes the
        // `rest.is_empty()` arm in `parse_shared` and surfaces
        // "requires a host path". The other empty-token arm fires for
        // `shared::` (see neighbouring test); this input never reaches
        // tokenisation.
        let err = WorkspaceMode::parse_flag("shared:").unwrap_err();
        assert!(err.contains("requires a host path"), "err = {err}");
    }

    #[test]
    fn parse_flag_shared_double_colon_errors() {
        // `shared::` — the rest is `:`, which splits to two empty
        // tokens. Empty tokens are rejected.
        let err = WorkspaceMode::parse_flag("shared::").unwrap_err();
        assert!(err.contains("empty"), "err = {err}");
    }

    #[test]
    fn parse_flag_shared_triple_colon_errors() {
        let err = WorkspaceMode::parse_flag("shared:::").unwrap_err();
        assert!(err.contains("empty"), "err = {err}");
    }

    #[test]
    fn parse_flag_shared_internal_empty_token_errors() {
        // `shared:/srv::/dst` — empty middle token.
        let err = WorkspaceMode::parse_flag("shared:/srv::/dst").unwrap_err();
        assert!(err.contains("empty"), "err = {err}");
    }

    #[test]
    fn parse_flag_shared_relative_host_path_errors() {
        let err = WorkspaceMode::parse_flag("shared:rel/path").unwrap_err();
        assert!(err.contains("must be absolute"), "err = {err}");
    }

    #[test]
    fn parse_flag_shared_relative_guest_path_errors() {
        // `rel/guest` does not start with `/` or `~`, so step B does
        // NOT classify it as a guest path. Instead it falls through
        // step C and merges into the host path
        // (`/tmp:rel/guest`), which fails the host-path-exists check.
        let err = WorkspaceMode::parse_flag("shared:/tmp:rel/guest").unwrap_err();
        assert!(err.contains("does not exist"), "err = {err}");
    }

    #[test]
    fn parse_flag_shared_unresolved_tilde_in_host_errors() {
        // Q4: `parse_flag` is a single pure function. The CLI is
        // responsible for expanding host-side `~` before invocation;
        // any residual `~` in `host_path` reaching the parser is a
        // bypass-the-CLI bug.
        let err = WorkspaceMode::parse_flag("shared:~/proj").unwrap_err();
        assert!(
            err.contains("CLI should have expanded `~` before sending"),
            "err = {err}"
        );
    }

    #[test]
    fn parse_flag_shared_friendly_hint_for_passthrough() {
        // SF-18: `passthrough` short-circuits with the friendly hint
        // naming the two supported values.
        let err = WorkspaceMode::parse_flag("shared:/tmp:passthrough").unwrap_err();
        assert!(
            err.contains("passthrough") && err.contains("mapped-file"),
            "err = {err}"
        );
        assert!(
            err.contains("mapped-xattr") && err.contains("none"),
            "err = {err}"
        );
    }

    #[test]
    fn parse_flag_shared_friendly_hint_for_mapped_file() {
        let err = WorkspaceMode::parse_flag("shared:/tmp:mapped-file").unwrap_err();
        assert!(
            err.contains("passthrough") && err.contains("mapped-file"),
            "err = {err}"
        );
        assert!(
            err.contains("mapped-xattr") && err.contains("none"),
            "err = {err}"
        );
    }

    #[test]
    fn parse_flag_shared_mixed_case_mode_prefix_errors() {
        // Mode matching is case-sensitive.
        let err = WorkspaceMode::parse_flag("Shared:/tmp").unwrap_err();
        assert!(err.contains("unknown workspace mode"), "err = {err}");
    }

    #[test]
    fn parse_flag_shared_nonexistent_path_errors() {
        let err = WorkspaceMode::parse_flag("shared:/nonexistent/path/xyzzy").unwrap_err();
        assert!(err.contains("does not exist"), "err = {err}");
    }

    #[test]
    fn parse_flag_unknown_mode_errors() {
        let err = WorkspaceMode::parse_flag("foobar:/some/path").unwrap_err();
        assert!(err.contains("unknown workspace mode"), "err = {err}");
    }

    #[test]
    fn parse_flag_shared_too_many_tokens_errors() {
        // Four tokens after `shared:` is unparseable — even with the
        // right-to-left classifier, only host + guest + model are
        // meaningful slots. `shared:/a:/b:/c:none` tokenises to
        // `["/a", "/b", "/c", "none"]` (no empties), so the parser
        // surfaces the `len() > 3` arm verbatim; the empty-token arm
        // never fires for this input.
        let err = WorkspaceMode::parse_flag("shared:/a:/b:/c:none").unwrap_err();
        assert!(err.contains("at most 3 tokens"), "err = {err}");
    }

    // -- Backward-compatibility / round-trip --------------------------

    #[test]
    fn workspace_mode_legacy_blob_without_guest_path_recovers_to_host_path() {
        // Legacy on-disk records pre-date the `guest_path` field.
        // The custom deserializer must recover `guest_path = host_path`.
        let json = r#"{"type":"shared","host_path":"/srv/repo"}"#;
        let mode: WorkspaceMode = serde_json::from_str(json).unwrap();
        assert_eq!(mode, shared("/srv/repo", "/srv/repo", None));
    }

    #[test]
    fn workspace_mode_legacy_blob_with_empty_guest_path_recovers_to_host_path() {
        // Defensive arm: hand-edited records with an empty-string
        // `guest_path` are treated the same as missing.
        let json = r#"{"type":"shared","host_path":"/srv/repo","guest_path":""}"#;
        let mode: WorkspaceMode = serde_json::from_str(json).unwrap();
        assert_eq!(mode, shared("/srv/repo", "/srv/repo", None));
    }

    #[test]
    fn workspace_mode_round_trip_with_security_model_mapped_xattr() {
        // SF-17: an explicit `Some(MappedXattr)` survives serialization
        // and deserialization without collapsing to `None`.
        let mode = shared("/a", "/b", Some(WorkspaceSecurityModel::MappedXattr));
        let json = serde_json::to_string(&mode).unwrap();
        assert!(
            json.contains("\"security_model\":\"mapped-xattr\""),
            "wire JSON: {json}"
        );
        let deser: WorkspaceMode = serde_json::from_str(&json).unwrap();
        assert_eq!(deser, mode);
    }

    #[test]
    fn workspace_mode_round_trip_with_security_model_none_mapping() {
        let mode = shared("/a", "/b", Some(WorkspaceSecurityModel::NoneMapping));
        let json = serde_json::to_string(&mode).unwrap();
        assert!(
            json.contains("\"security_model\":\"none\""),
            "wire JSON: {json}"
        );
        let deser: WorkspaceMode = serde_json::from_str(&json).unwrap();
        assert_eq!(deser, mode);
    }

    #[test]
    fn workspace_mode_round_trip_without_security_model_omits_field() {
        // `#[serde(skip_serializing_if = "Option::is_none")]` keeps the
        // field off the wire when unset; the round-trip then preserves
        // `None`.
        let mode = shared("/a", "/b", None);
        let json = serde_json::to_string(&mode).unwrap();
        assert!(
            !json.contains("security_model"),
            "security_model should be omitted when None; wire JSON: {json}"
        );
        let deser: WorkspaceMode = serde_json::from_str(&json).unwrap();
        assert_eq!(deser, mode);
    }

    #[test]
    fn workspace_mode_round_trip_shared_default_security_model() {
        // Forward-compat (default-shape arm): serialise the
        // `security_model: None` payload, deserialise, check every
        // field round-trips. The companion test below exercises the
        // `Some(_)` arm so both branches of the
        // `skip_serializing_if = "Option::is_none"` attribute stay
        // pinned.
        let mode = shared("/a", "/b", None);
        let json = serde_json::to_string(&mode).unwrap();
        let deser: WorkspaceMode = serde_json::from_str(&json).unwrap();
        assert_eq!(deser, mode);
    }

    #[test]
    fn workspace_mode_round_trip_shared_with_security_model() {
        // Forward-compat (explicit-Some arm): serialise a payload that
        // carries `security_model: Some(MappedXattr)`, deserialise,
        // check the inner variant survives the wire trip. Without
        // this companion the round-trip suite would only exercise the
        // `skip_serializing_if` branch — a regression that broke the
        // serialize/deserialize of `Some(_)` payloads would slip past
        // the default-shape test.
        let mode = shared("/a", "/b", Some(WorkspaceSecurityModel::MappedXattr));
        let json = serde_json::to_string(&mode).unwrap();
        assert!(
            json.contains("\"security_model\""),
            "Some(_) variant must be present on the wire; got {json}"
        );
        let deser: WorkspaceMode = serde_json::from_str(&json).unwrap();
        assert_eq!(deser, mode);
    }

    #[test]
    fn workspace_mode_round_trip_clone() {
        let mode = WorkspaceMode::Clone {
            repo_url: "https://github.com/example/repo.git".into(),
        };
        let json = serde_json::to_string(&mode).unwrap();
        let deser: WorkspaceMode = serde_json::from_str(&json).unwrap();
        assert_eq!(deser, mode);
    }

    #[test]
    fn workspace_security_model_default_is_mapped_xattr() {
        assert_eq!(
            WorkspaceSecurityModel::default(),
            WorkspaceSecurityModel::MappedXattr
        );
    }

    #[test]
    fn workspace_security_model_as_yaml_matches_wire_form() {
        assert_eq!(
            WorkspaceSecurityModel::MappedXattr.as_yaml(),
            "mapped-xattr"
        );
        assert_eq!(WorkspaceSecurityModel::NoneMapping.as_yaml(), "none");
    }

    #[test]
    fn workspace_security_model_serializes_with_kebab_case_tokens() {
        let mapped = serde_json::to_string(&WorkspaceSecurityModel::MappedXattr).unwrap();
        assert_eq!(mapped, "\"mapped-xattr\"");
        let none = serde_json::to_string(&WorkspaceSecurityModel::NoneMapping).unwrap();
        assert_eq!(none, "\"none\"");
        // And the round-trip preserves identity.
        let deser: WorkspaceSecurityModel = serde_json::from_str(&mapped).unwrap();
        assert_eq!(deser, WorkspaceSecurityModel::MappedXattr);
        let deser: WorkspaceSecurityModel = serde_json::from_str(&none).unwrap();
        assert_eq!(deser, WorkspaceSecurityModel::NoneMapping);
    }

    // -- EnumSet<WorkspaceModeKind> unknown-variant tolerance ---------

    #[test]
    fn workspace_mode_kind_set_drops_unknown_variants_on_deserialize() {
        // An older CLI built against `{Shared, Clone, Local}` may
        // receive a newer daemon's capability response that contains
        // additional variants (e.g. a future `"sftp"` mode). The
        // unknown variant must be silently dropped — the set parses
        // to the known variants only.
        #[derive(Deserialize)]
        struct Wrapper {
            #[serde(deserialize_with = "deserialize_workspace_mode_kind_set")]
            kinds: enumset::EnumSet<WorkspaceModeKind>,
        }

        let json = r#"{"kinds":["shared","clone","local","quantum_blockchain"]}"#;
        let w: Wrapper = serde_json::from_str(json).unwrap();
        assert!(w.kinds.contains(WorkspaceModeKind::Shared));
        assert!(w.kinds.contains(WorkspaceModeKind::Clone));
        assert!(w.kinds.contains(WorkspaceModeKind::Local));
        assert_eq!(w.kinds.len(), 3);
    }

    #[test]
    fn workspace_mode_kind_set_empty_array_parses_to_empty_set() {
        #[derive(Deserialize)]
        struct Wrapper {
            #[serde(deserialize_with = "deserialize_workspace_mode_kind_set")]
            kinds: enumset::EnumSet<WorkspaceModeKind>,
        }

        let json = r#"{"kinds":[]}"#;
        let w: Wrapper = serde_json::from_str(json).unwrap();
        assert!(w.kinds.is_empty());
    }

    #[test]
    fn workspace_mode_kind_set_all_unknown_yields_empty_set() {
        #[derive(Deserialize)]
        struct Wrapper {
            #[serde(deserialize_with = "deserialize_workspace_mode_kind_set")]
            kinds: enumset::EnumSet<WorkspaceModeKind>,
        }

        let json = r#"{"kinds":["sftp","foobar"]}"#;
        let w: Wrapper = serde_json::from_str(json).unwrap();
        assert!(w.kinds.is_empty());
    }

    #[test]
    fn workspace_mode_kind_default_serialize_still_uses_list_repr() {
        // Sanity check that the existing `serialize_repr = "list"`
        // shape continues to work — the new free-function deserializer
        // is opt-in via `#[serde(deserialize_with = ...)]` on
        // consuming structs, so the underlying `EnumSet<T>` round-trip
        // is unchanged for callers that don't need tolerance.
        let mut set = enumset::EnumSet::<WorkspaceModeKind>::empty();
        set |= WorkspaceModeKind::Shared;
        let json = serde_json::to_string(&set).unwrap();
        assert_eq!(json, r#"["shared"]"#);
    }

    #[test]
    fn workspace_mode_kind_matches_workspace_mode_variant() {
        let m = shared("/tmp", "/tmp", None);
        assert_eq!(m.kind(), WorkspaceModeKind::Shared);
        let m = WorkspaceMode::Clone {
            repo_url: "x".into(),
        };
        assert_eq!(m.kind(), WorkspaceModeKind::Clone);
        let m = WorkspaceMode::Local {
            host_path: "/tmp".into(),
            guest_path: "/tmp".into(),
        };
        assert_eq!(m.kind(), WorkspaceModeKind::Local);
    }

    // -----------------------------------------------------------------
    // `local:` parser + serde
    // -----------------------------------------------------------------

    /// Helper: assemble the canonical `Local` payload for a parser
    /// expected-value assertion.
    fn local(host: &str, guest: &str) -> WorkspaceMode {
        WorkspaceMode::Local {
            host_path: host.into(),
            guest_path: guest.into(),
        }
    }

    // -- Parser positive cases (`local:`) ----------------------------------

    #[test]
    fn parse_flag_local_host_only_defaults_guest_to_host() {
        // `host=/srv/repo, guest=/srv/repo`. `/tmp` is guaranteed to
        // exist and be a directory on every host the test runs on.
        let mode = WorkspaceMode::parse_flag("local:/tmp").unwrap();
        assert_eq!(mode, local("/tmp", "/tmp"));
    }

    #[test]
    fn parse_flag_local_with_explicit_guest_path() {
        // `local:/srv/repo:/srv/dest` → `host=/srv/repo, guest=/srv/dest`.
        let mode = WorkspaceMode::parse_flag("local:/tmp:/srv/work").unwrap();
        assert_eq!(mode, local("/tmp", "/srv/work"));
    }

    #[test]
    fn parse_flag_local_with_guest_tilde_expands_to_home_sandbox() {
        // Guest-side `~` is the same environment-free substitution as
        // for `shared:` — the parser arm shares the classifier.
        let mode = WorkspaceMode::parse_flag("local:/tmp:~/work").unwrap();
        assert_eq!(mode, local("/tmp", "/home/sandbox/work"));
    }

    #[test]
    fn parse_flag_local_strips_trailing_slash_on_host_path() {
        let mode = WorkspaceMode::parse_flag("local:/tmp/").unwrap();
        assert_eq!(mode, local("/tmp", "/tmp"));
    }

    #[test]
    fn parse_flag_local_strips_trailing_slash_on_guest_path() {
        let mode = WorkspaceMode::parse_flag("local:/tmp:/srv/work/").unwrap();
        assert_eq!(mode, local("/tmp", "/srv/work"));
    }

    #[test]
    fn parse_flag_local_strips_leading_and_trailing_whitespace() {
        let mode = WorkspaceMode::parse_flag("  local:/tmp  ").unwrap();
        assert_eq!(mode, local("/tmp", "/tmp"));
    }

    // -- Parser negative cases (`local:`) ----------------------------------

    #[test]
    fn parse_flag_local_security_model_suffix_is_folded_into_host() {
        // `local:/srv/repo:none` → no `:none` security-model strip
        // (mode is `local`, not `shared`); step C folds the trailing
        // `:none` into `host_path=/srv/repo:none`; host-path-exists
        // check rejects.
        let err = WorkspaceMode::parse_flag("local:/srv/repo:none").unwrap_err();
        assert!(err.contains("does not exist"), "err = {err}");
    }

    #[test]
    fn parse_flag_local_unclassified_trailing_token_folds_into_host() {
        // `local:/srv/repo:bogus` → tokens [/srv/repo, bogus]; step B
        // skips (no `/` or `~` prefix); step C folds into
        // `host_path=/srv/repo:bogus`; host-path-exists rejects.
        let err = WorkspaceMode::parse_flag("local:/srv/repo:bogus").unwrap_err();
        assert!(err.contains("does not exist"), "err = {err}");
    }

    #[test]
    fn parse_flag_local_relative_host_path_errors() {
        // `local:proj` — relative path, rejected with "must be absolute".
        let err = WorkspaceMode::parse_flag("local:proj").unwrap_err();
        assert!(err.contains("must be absolute"), "err = {err}");
    }

    #[test]
    fn parse_flag_local_empty_payload_errors() {
        // `local:` — empty rest after the mode prefix. The parser
        // takes the `rest.is_empty()` arm in `parse_host_guest_pair`
        // and surfaces "requires a host path"; the empty-token arm
        // is unreachable for this input (no `:` to split).
        let err = WorkspaceMode::parse_flag("local:").unwrap_err();
        assert!(err.contains("requires a host path"), "err = {err}");
    }

    #[test]
    fn parse_flag_local_empty_token_errors() {
        // `local:/srv::/dst` — empty middle token, rejected.
        let err = WorkspaceMode::parse_flag("local:/srv::/dst").unwrap_err();
        assert!(err.contains("empty"), "err = {err}");
    }

    #[test]
    fn parse_flag_local_too_many_tokens_errors() {
        // `local:` accepts at most 2 tokens (host, guest). The third
        // token is not a security-model slot for `local:`, so the
        // parser rejects rather than silently dropping.
        // `local:/a:/b:/c` tokenises to `["/a", "/b", "/c"]` (no
        // empties), so the parser surfaces the `len() > 2` arm
        // verbatim; the empty-token arm never fires for this input.
        let err = WorkspaceMode::parse_flag("local:/a:/b:/c").unwrap_err();
        assert!(err.contains("at most 2 tokens"), "err = {err}");
    }

    #[test]
    fn parse_flag_local_unresolved_tilde_in_host_errors() {
        // Same Q4-style contract as `shared:` — daemon-side host-`~` is
        // a CLI-bypass bug.
        let err = WorkspaceMode::parse_flag("local:~/proj").unwrap_err();
        assert!(
            err.contains("CLI should have expanded `~` before sending"),
            "err = {err}"
        );
    }

    #[test]
    fn parse_flag_local_nonexistent_host_path_errors() {
        let err = WorkspaceMode::parse_flag("local:/nonexistent/path/xyzzy").unwrap_err();
        assert!(err.contains("does not exist"), "err = {err}");
    }

    /// SF-11 — `local:` requires `host_path` to be a directory. A
    /// regular-file `host_path` is rejected with the explicit pointer
    /// at `sandbox cp`.
    #[test]
    fn parse_flag_local_regular_file_host_path_errors() {
        // Build a tempfile under a unique-per-test path so we don't
        // race with other tests on the same host.
        let dir = std::env::temp_dir();
        let path = dir.join(format!(
            "sandbox-local-host-file-{}.tmp",
            std::process::id()
        ));
        std::fs::write(&path, b"single-file payload").expect("write temp file");
        let path_str = path.to_string_lossy().to_string();

        let input = format!("local:{path_str}");
        let err = WorkspaceMode::parse_flag(&input).unwrap_err();
        // The error must name the `sandbox cp` recovery and
        // require directory-ness explicitly.
        assert!(
            err.contains("must be a directory for `local:`"),
            "err = {err}"
        );
        assert!(
            err.contains("sandbox cp"),
            "err must point at `sandbox cp` for single-file seeding: {err}"
        );

        // Cleanup; failure is non-fatal (temp dir is reaped anyway).
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn parse_flag_local_nonexistent_path_rejected_before_directory_check() {
        // A path that does not exist is rejected by the host-path-exists
        // check in step D (shared with the `shared:` parser) — the
        // SF-11 directory check fires only on existing non-directory
        // paths. The user-facing error is "does not exist" rather than
        // the directory-required hint.
        let err = WorkspaceMode::parse_flag("local:/definitely/not/a/real/path").unwrap_err();
        assert!(err.contains("does not exist"), "err = {err}");
    }

    // -- Serde round-trip + legacy-record recovery (`Local`) ---------------

    #[test]
    fn workspace_mode_round_trip_local_default_guest_path() {
        let mode = local("/srv/repo", "/srv/repo");
        let json = serde_json::to_string(&mode).unwrap();
        let deser: WorkspaceMode = serde_json::from_str(&json).unwrap();
        assert_eq!(deser, mode);
    }

    #[test]
    fn workspace_mode_round_trip_local_explicit_guest_path() {
        let mode = local("/srv/repo", "/srv/dest");
        let json = serde_json::to_string(&mode).unwrap();
        let deser: WorkspaceMode = serde_json::from_str(&json).unwrap();
        assert_eq!(deser, mode);
    }

    #[test]
    fn workspace_mode_local_blob_without_guest_path_recovers_to_host_path() {
        // Symmetric with the `Shared` legacy-record recovery: a Local
        // record written without `guest_path` (e.g. by a hand-edited
        // record, or a future client that emits the compact form)
        // recovers `guest_path = host_path` via the custom
        // deserializer shim.
        let json = r#"{"type":"local","host_path":"/srv/repo"}"#;
        let mode: WorkspaceMode = serde_json::from_str(json).unwrap();
        assert_eq!(mode, local("/srv/repo", "/srv/repo"));
    }

    #[test]
    fn workspace_mode_local_blob_with_empty_guest_path_recovers_to_host_path() {
        // Defensive arm: hand-edited records with an empty-string
        // `guest_path` are treated the same as missing.
        let json = r#"{"type":"local","host_path":"/srv/repo","guest_path":""}"#;
        let mode: WorkspaceMode = serde_json::from_str(json).unwrap();
        assert_eq!(mode, local("/srv/repo", "/srv/repo"));
    }

    // -----------------------------------------------------------------
    // SessionId tests
    // -----------------------------------------------------------------

    #[test]
    fn session_id_generate_has_correct_format() {
        for _ in 0..32 {
            let id = SessionId::generate();
            let s = id.as_str();
            assert_eq!(s.len(), SessionId::LEN, "id={s}");
            assert!(
                s.bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
                "id {s} must be lowercase hex"
            );
        }
    }

    #[test]
    fn session_id_generate_uniqueness() {
        let mut seen = std::collections::HashSet::new();
        for _ in 0..1024 {
            assert!(
                seen.insert(SessionId::generate()),
                "collision in 1024 iterations"
            );
        }
    }

    #[test]
    fn session_id_parse_accepts_valid() {
        let id = SessionId::parse("0123456789ab").unwrap();
        assert_eq!(id.as_str(), "0123456789ab");
        let id = SessionId::parse("abcdef012345").unwrap();
        assert_eq!(id.as_str(), "abcdef012345");
    }

    #[test]
    fn session_id_parse_rejects_wrong_length() {
        assert!(SessionId::parse("").is_err());
        assert!(SessionId::parse("abc").is_err());
        assert!(SessionId::parse("0123456789a").is_err()); // 11
        assert!(SessionId::parse("0123456789abc").is_err()); // 13
        assert!(SessionId::parse(&"a".repeat(32)).is_err());
    }

    #[test]
    fn session_id_parse_rejects_uppercase() {
        assert!(SessionId::parse("ABCDEF012345").is_err());
        assert!(SessionId::parse("0123456789AB").is_err());
    }

    #[test]
    fn session_id_parse_rejects_non_hex() {
        assert!(SessionId::parse("0123456789ag").is_err());
        assert!(SessionId::parse("0123456789 a").is_err());
        assert!(SessionId::parse("gggggggggggg").is_err());
        assert!(SessionId::parse("xxxxxxxxxxxx").is_err());
    }

    #[test]
    fn session_id_from_str_roundtrip() {
        use std::str::FromStr;
        let id = SessionId::generate();
        let parsed = SessionId::from_str(id.as_str()).unwrap();
        assert_eq!(id, parsed);
    }

    #[test]
    fn session_id_display_matches_as_str() {
        let id = SessionId::parse("deadbeef0123").unwrap();
        assert_eq!(format!("{id}"), "deadbeef0123");
    }

    #[test]
    fn session_id_as_bytes_array_decodes_correctly() {
        let id = SessionId::parse("0123456789ab").unwrap();
        assert_eq!(id.as_bytes_array(), [0x01, 0x23, 0x45, 0x67, 0x89, 0xab]);
        let id = SessionId::parse("deadbeef0000").unwrap();
        assert_eq!(id.as_bytes_array(), [0xde, 0xad, 0xbe, 0xef, 0x00, 0x00]);
    }

    #[test]
    fn session_id_serialization_is_plain_string() {
        let id = SessionId::parse("abcdef012345").unwrap();
        let json = serde_json::to_string(&id).unwrap();
        assert_eq!(json, "\"abcdef012345\"");
        let deser: SessionId = serde_json::from_str(&json).unwrap();
        assert_eq!(deser, id);
    }

    #[test]
    fn session_id_deserialization_rejects_invalid() {
        let err = serde_json::from_str::<SessionId>("\"BADHEX!!!!!!\"");
        assert!(err.is_err());
        let err = serde_json::from_str::<SessionId>("\"short\"");
        assert!(err.is_err());
    }

    #[test]
    fn session_id_as_ref_str() {
        let id = SessionId::parse("0123456789ab").unwrap();
        let s: &str = id.as_ref();
        assert_eq!(s, "0123456789ab");
    }
}
