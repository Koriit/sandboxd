//! Backend resolution, CLI config loader, and feature-mismatch error
//! rendering for `sandbox create`.
//!
//! Spec § "CLI & UX → Invocation" defines a five-tier precedence chain
//! the CLI must apply when picking a backend (`--lite` / `--backend`
//! flags > `SANDBOX_DEFAULT_BACKEND` env > config file
//! `default_backend` > hardcoded `BackendKind::Lima`). [`resolve_backend`]
//! is the one place that chain is implemented; the same function is
//! exercised by unit tests with fake env + fake config so the precedence
//! does not depend on disk I/O.
//!
//! The config loader for `~/.config/sandboxd/config.json` is also here
//! ([`load_cli_config`]). Spec § "CLI & UX → Config file" mandates the
//! loader share its XDG resolver with the preset catalog (see
//! [`crate::cli_xdg`]).
//!
//! [`render_feature_mismatch`] and [`render_no_cache_rejection_for_container`]
//! emit the spec's exact `error:` + `help:` shapes used by both client-
//! side validation and the up-front `--no-cache` rejection. These
//! string shapes are part of a wire-format contract — the unit tests
//! pin them byte-for-byte.

use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use clap::ValueEnum;
use sandbox_core::backend::{BackendKind, UnsupportedFeature};
use sandbox_core::session::WorkspaceModeKind;
use serde::Deserialize;

// ---------------------------------------------------------------------------
// CLI value enum
// ---------------------------------------------------------------------------

/// Clap-friendly mirror of [`BackendKind`].
///
/// Lives here (rather than deriving `ValueEnum` directly on
/// `sandbox_core::BackendKind`) because `sandbox-core` does not depend
/// on `clap` and adding the dep just for this trait would balloon the
/// compile graph for non-CLI consumers (the daemon, integration test
/// crates). The mapping is total and lossless — see [`BackendKindArg::into_kind`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
#[clap(rename_all = "lowercase")]
pub enum BackendKindArg {
    /// QEMU/Lima virtual-machine backend.
    Lima,
    /// Docker container ("lite") backend.
    Container,
}

impl BackendKindArg {
    /// Project the CLI-only enum onto the canonical
    /// [`sandbox_core::backend::BackendKind`].
    pub fn into_kind(self) -> BackendKind {
        match self {
            Self::Lima => BackendKind::Lima,
            Self::Container => BackendKind::Container,
        }
    }
}

/// Clap-friendly enum for the `sandbox rebuild-image --backend` flag.
///
/// Adds the `All` variant on top of [`BackendKindArg`] — spec
/// § "`rebuild-image`: extend the existing flat command" defaults the
/// flag to `all`, so the CLI must accept a token that has no
/// counterpart in [`BackendKind`] (which only knows real backends).
/// Kept as its own enum rather than reusing [`BackendKindArg`] + an
/// `Option` so the default-value annotation on the clap arg stays
/// trivially expressible (`default_value_t = RebuildImageBackend::All`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
#[clap(rename_all = "lowercase")]
pub enum RebuildImageBackend {
    /// Rebuild only the Lima golden VM image.
    Lima,
    /// Rebuild only the container ("lite") image.
    Container,
    /// Rebuild every installed backend's image.
    All,
}

impl RebuildImageBackend {
    /// Project the flag value into the concrete [`BackendKind`]s the
    /// dispatcher must visit.
    ///
    /// The order is deterministic (Lima first, Container second) so the
    /// per-backend dispatch loop in [`crate`] can pin the request order
    /// in unit tests without juggling sets. Spec § "rebuild-image"
    /// says "fan out to each backend in turn" and pins exit semantics
    /// rather than ordering, but a stable order is the only way to keep
    /// the operator-facing stderr lines reproducible and the dispatch
    /// test deterministic.
    pub fn into_kinds(self) -> Vec<BackendKind> {
        match self {
            Self::Lima => vec![BackendKind::Lima],
            Self::Container => vec![BackendKind::Container],
            Self::All => vec![BackendKind::Lima, BackendKind::Container],
        }
    }
}

// ---------------------------------------------------------------------------
// Config file
// ---------------------------------------------------------------------------

/// Per-user CLI configuration file shape.
///
/// Loaded from `~/.config/sandboxd/config.json` (or
/// `$XDG_CONFIG_HOME/sandboxd/config.json`). Every field is `#[serde(default)]`
/// so older config files (and a missing file) round-trip cleanly. New
/// fields land here as `Option<T>` with `#[serde(default)]` per the same
/// forward-compat rule the persisted blob fields follow (CLAUDE.md
/// § "On-disk compatibility").
#[derive(Debug, Clone, Default, Deserialize)]
pub struct CliConfig {
    /// Default backend used when neither `--lite`/`--backend` flag nor
    /// `SANDBOX_DEFAULT_BACKEND` is set. Tier 4 of the precedence
    /// chain in [`resolve_backend`].
    #[serde(default)]
    pub default_backend: Option<BackendKind>,
    /// Per-backend config knobs. Spec keeps the map present so future
    /// per-backend overrides (resource defaults, image tag pins) land
    /// without bumping the schema; the inner objects are intentionally
    /// empty for Phase 4A.
    #[serde(default)]
    pub backends: BackendsConfig,
}

/// Per-backend configuration block.
///
/// Spec § "CLI & UX → Config file" shows
/// `{"backends": {"container": {}}}` as the canonical shape — empty
/// objects are legal. The `lima` knob is intentionally absent at this
/// phase to match the spec's example; an `Option<...>` field can be
/// added later without breaking forward-compat.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct BackendsConfig {
    /// Container-backend knobs. Spec example shows `{}`; this struct
    /// holds no fields today and exists as an extensibility hook.
    #[serde(default)]
    pub container: Option<ContainerBackendConfig>,
}

/// Container-backend configuration block.
///
/// Empty in Phase 4A. Future fields land here as `Option<T>` with
/// `#[serde(default)]`.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct ContainerBackendConfig {}

/// Errors the CLI config loader can produce.
///
/// A missing file is *not* an error — [`load_cli_config`] returns a
/// default [`CliConfig`] in that case. Only structural failures
/// (malformed JSON, IO errors that aren't `NotFound`) surface here.
#[derive(Debug)]
pub enum CliConfigError {
    /// I/O error reading the config file (other than `NotFound`).
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
    /// JSON parse error in the config file. Message includes the path
    /// so the operator can locate the broken file.
    Parse {
        path: PathBuf,
        source: serde_json::Error,
    },
}

impl std::fmt::Display for CliConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io { path, source } => {
                write!(
                    f,
                    "failed to read CLI config '{}': {source}",
                    path.display()
                )
            }
            Self::Parse { path, source } => {
                write!(f, "malformed CLI config '{}': {source}", path.display())
            }
        }
    }
}

impl std::error::Error for CliConfigError {}

/// Path the CLI config loader resolves to under the given XDG override.
///
/// `xdg_override` follows the same convention as
/// [`crate::cli_xdg::resolve_sandboxd_config_dir`] — `Some(path)` is
/// used as the `~/.config/sandboxd/` base directly, `None` walks the
/// env. Returns `None` when no `~/.config/sandboxd/` can be resolved
/// (no `$XDG_CONFIG_HOME` and no `$HOME`); callers treat that as
/// "no config file to load" and fall back to defaults.
pub fn cli_config_path(xdg_override: Option<&Path>) -> Option<PathBuf> {
    crate::cli_xdg::resolve_sandboxd_config_dir(xdg_override).map(|base| base.join("config.json"))
}

/// Load the per-user CLI config.
///
/// Behaviour:
///
/// - Missing file → `Ok(CliConfig::default())` (spec § "Config file":
///   "treat a missing file as not-an-error").
/// - Malformed JSON → `Err(CliConfigError::Parse)` carrying the file
///   path so the operator can locate the broken file (spec § "Config
///   file": "malformed file is a hard error with a pointer to the
///   path").
/// - Other IO errors → `Err(CliConfigError::Io)`.
///
/// `xdg_override` lets tests redirect away from the developer's real
/// `~/.config`. Production callers pass `None`.
pub fn load_cli_config(xdg_override: Option<&Path>) -> Result<CliConfig, CliConfigError> {
    let Some(path) = cli_config_path(xdg_override) else {
        // No `~/.config/sandboxd/` resolvable at all. Treated as
        // "missing file" per spec.
        return Ok(CliConfig::default());
    };

    let text = match fs::read_to_string(&path) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Ok(CliConfig::default());
        }
        Err(e) => return Err(CliConfigError::Io { path, source: e }),
    };

    serde_json::from_str(&text).map_err(|e| CliConfigError::Parse { path, source: e })
}

// ---------------------------------------------------------------------------
// Precedence resolver
// ---------------------------------------------------------------------------

/// Inputs to the backend precedence resolver.
///
/// Bundled into a struct so the unit tests can construct fake values
/// without needing real env access or disk I/O. In production
/// [`resolve_backend`] is called from the CLI's `Create` handler with
/// the actual flag values, the [`std::env::var`] reader, and the
/// loaded [`CliConfig`].
#[derive(Debug, Clone, Default)]
pub struct BackendResolutionInputs {
    /// `--lite` flag value (sugar for `--backend container`).
    pub lite_flag: bool,
    /// `--backend <kind>` flag value.
    pub backend_flag: Option<BackendKind>,
    /// Raw value of the `SANDBOX_DEFAULT_BACKEND` environment variable.
    /// `None` means the env var is unset; `Some("")` is treated the
    /// same as unset so empty values do not silently fall through to
    /// the config tier.
    pub env_default_backend: Option<String>,
    /// `default_backend` field from the loaded [`CliConfig`].
    pub config_default_backend: Option<BackendKind>,
}

/// Errors produced by [`resolve_backend`].
///
/// Currently the only failure mode is an unparseable
/// `SANDBOX_DEFAULT_BACKEND` value — a malformed env var should fail
/// fast rather than silently falling through to the config tier
/// (which would mask the operator's typo).
#[derive(Debug)]
pub enum BackendResolutionError {
    /// `SANDBOX_DEFAULT_BACKEND` was set but did not parse as a known
    /// backend kind.
    UnknownEnvBackend { value: String, source: String },
}

impl std::fmt::Display for BackendResolutionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnknownEnvBackend { value, source } => write!(
                f,
                "SANDBOX_DEFAULT_BACKEND={value:?} is not a known backend kind: {source}"
            ),
        }
    }
}

impl std::error::Error for BackendResolutionError {}

/// Apply the spec's five-tier precedence chain to pick a [`BackendKind`].
///
/// Order (first wins):
///
/// 1. `--lite` flag → [`BackendKind::Container`]
/// 2. `--backend <kind>` flag
/// 3. `SANDBOX_DEFAULT_BACKEND` environment variable
/// 4. `default_backend` field in the per-user CLI config
/// 5. Hardcoded fallback [`BackendKind::Lima`]
///
/// The function never reads env vars or disk itself — all inputs flow
/// through [`BackendResolutionInputs`] so the precedence is unit-
/// testable without a real environment.
pub fn resolve_backend(
    inputs: &BackendResolutionInputs,
) -> Result<BackendKind, BackendResolutionError> {
    if inputs.lite_flag {
        return Ok(BackendKind::Container);
    }
    if let Some(kind) = inputs.backend_flag {
        return Ok(kind);
    }
    if let Some(raw) = inputs.env_default_backend.as_deref() {
        if !raw.is_empty() {
            return BackendKind::from_str(raw).map_err(|source| {
                BackendResolutionError::UnknownEnvBackend {
                    value: raw.to_string(),
                    source,
                }
            });
        }
    }
    if let Some(kind) = inputs.config_default_backend {
        return Ok(kind);
    }
    Ok(BackendKind::Lima)
}

// ---------------------------------------------------------------------------
// Feature-mismatch error rendering
// ---------------------------------------------------------------------------

/// Inputs the CLI carries into [`render_feature_mismatch`] alongside an
/// [`UnsupportedFeature`].
///
/// The error message form depends on which user-facing flags surfaced
/// the mismatch. `lite` is `true` when `--lite` was on the command
/// line (vs. `--backend container`); the `help:` lines use this to
/// decide whether to suggest dropping `--lite` or `--backend container`.
#[derive(Debug, Clone, Copy)]
pub struct FeatureMismatchContext {
    /// True iff the operator passed `--lite` (vs. `--backend container`).
    /// Spec example uses the `--lite` form; the wording adapts when the
    /// flag was instead `--backend container`.
    pub lite_flag_used: bool,
    /// True iff the operator passed `--no-hardening`. Spec hardening
    /// example assumes the operator asked for hardening (no
    /// `--no-hardening`); when the operator passed `--no-hardening`
    /// the validation should not have fired in the first place, but
    /// the renderer takes the flag for completeness.
    pub no_hardening_flag_used: bool,
}

/// Render a spec-shaped feature-mismatch error to a string.
///
/// Spec § "CLI & UX → Feature-mismatch errors" mandates an `error:`
/// line followed by indented `help:` lines. The exact text varies per
/// [`UnsupportedFeature`] variant; the `error:` line names the asked-
/// for flag and the chosen backend; `help:` lines tell the operator
/// how to escape the conflict.
///
/// **This is a wire-format contract** — the unit tests pin every byte.
/// Any change here must update those tests in the same commit.
///
/// The leading prefix and indentation match the spec example:
///
/// ```text
/// error: `--hardened` requires a VM-backed session, but `--lite` selects the container backend
///    help: lite containers apply default hardening automatically
///    help: remove `--hardened`, or drop `--lite` to get QEMU-level hardening
/// ```
pub fn render_feature_mismatch(
    feature: &UnsupportedFeature,
    ctx: &FeatureMismatchContext,
) -> String {
    let mut out = String::new();

    // Each variant gets its own `error:` line and two `help:` lines.
    // The two `help:` lines route the operator to either side of the
    // conflict (drop the demanding flag, or switch backends).
    match feature {
        UnsupportedFeature::Hardening => {
            // Spec § "CLI & UX → Feature-mismatch errors": exact
            // wording for the `--hardened` ↔ `--lite` conflict. When
            // `--backend container` was used instead of `--lite`, we
            // swap the flag name in both lines so the suggestion
            // matches the operator's invocation.
            let backend_flag = if ctx.lite_flag_used {
                "`--lite`"
            } else {
                "`--backend container`"
            };
            let _ = writeln!(
                out,
                "error: `--hardened` requires a VM-backed session, but {backend_flag} selects the container backend"
            );
            let _ = writeln!(
                out,
                "   help: lite containers apply default hardening automatically"
            );
            let _ = writeln!(
                out,
                "   help: remove `--hardened`, or drop {backend_flag} to get QEMU-level hardening"
            );
        }
        UnsupportedFeature::PerSessionNoCache(backend) => {
            // Spec § "CLI & UX → `sandbox create --no-cache` is
            // forbidden on container" gives the exact three lines for
            // the container case. The `error:` line uses the backend
            // identifier the runtime advertised so a future backend
            // that also opts out of per-session no-cache surfaces
            // *its* identifier here, not a hardcoded "container".
            let backend_flag = if ctx.lite_flag_used {
                "`--lite`"
            } else if matches!(backend, BackendKind::Container) {
                "`--backend container`"
            } else {
                // Generic form for any future per-session-no-cache-
                // disabled backend.
                "`--backend ` selection"
            };
            let _ = writeln!(
                out,
                "error: `--no-cache` is not supported with {backend_flag} / {backend} backend"
            );
            let _ = writeln!(
                out,
                "   help: containers have no per-session slow-path equivalent to Lima's full-VM-create"
            );
            let _ = writeln!(out, "   help: to rebuild the shared lite image, use:");
            let _ = writeln!(
                out,
                "         sandbox rebuild-image --backend {backend} --no-cache"
            );
        }
        UnsupportedFeature::WorkspaceMode(kind, backend) => {
            // Workspace-mode mismatch is not in the spec's exact-text
            // examples but follows the same shape ("error: ... help:
            // ..."). The `WorkspaceModeKind::Display` is not
            // implemented; spell the kinds out by hand.
            let kind_str = match kind {
                WorkspaceModeKind::Shared => "shared",
                WorkspaceModeKind::Clone => "clone",
            };
            let backend_flag = if ctx.lite_flag_used {
                "`--lite`"
            } else if matches!(backend, BackendKind::Container) {
                "`--backend container`"
            } else {
                "`--backend lima`"
            };
            let _ = writeln!(
                out,
                "error: `--workspace {kind_str}` is not supported by the {backend} backend selected via {backend_flag}"
            );
            let _ = writeln!(
                out,
                "   help: drop `--workspace`, or pick a different `--workspace` mode the backend advertises"
            );
            let _ = writeln!(
                out,
                "   help: switch backends to one whose capabilities include `{kind_str}` — see `sandbox inspect -v` for the matrix"
            );
        }
        // `UnsupportedFeature` is `#[non_exhaustive]`. Adding a new
        // variant must show up here so it doesn't silently fall through
        // to a generic message — the spec emphasises that a new
        // capability mismatch should force review of the CLI's error
        // printer (see capabilities.rs's `#[non_exhaustive]` rationale).
        other => {
            let _ = writeln!(
                out,
                "error: feature unsupported by selected backend: {other}"
            );
            let _ = writeln!(
                out,
                "   help: this CLI does not yet know how to suggest a fix for this mismatch"
            );
            let _ = writeln!(
                out,
                "   help: see `sandbox inspect -v` for the backend's capability matrix"
            );
        }
    }

    out
}

/// Render the spec's per-create isolation warning for the container
/// backend.
///
/// Spec § "Isolation warning" (lines 751-762) mandates the **exact**
/// two-line shape below, character-for-character. Note the leading
/// `lite:` token, the em dash (`—`, U+2014) on line 1, and the **six**
/// spaces of indentation on line 2:
///
/// ```text
/// lite: container-backed session — container-level isolation only (not VM-grade)
///       see docs/lite.md for the trade-off details
/// ```
///
/// Returns the empty string for [`BackendKind::Lima`] — the warning is
/// container-specific. **Wire-format contract** — pinned by a
/// byte-equality unit test.
pub fn render_isolation_warning(backend: BackendKind) -> String {
    match backend {
        BackendKind::Container => {
            // Hard-code the exact bytes the spec requires. A multi-line
            // string literal preserves the em dash and the six-space
            // indent on line 2 verbatim.
            "lite: container-backed session \u{2014} container-level isolation only (not VM-grade)\n      see docs/lite.md for the trade-off details\n".to_string()
        }
        BackendKind::Lima => String::new(),
    }
}

/// Render the spec's `--no-cache` rejection error for the container
/// backend.
///
/// Spec § "CLI & UX → `sandbox create --no-cache` is forbidden on
/// container" gives the exact three-line shape this returns. Used by
/// the up-front rejection layer before the daemon is ever contacted.
pub fn render_no_cache_rejection_for_container(lite_flag_used: bool) -> String {
    // Same content as the [`UnsupportedFeature::PerSessionNoCache`]
    // arm of [`render_feature_mismatch`] — a single source of truth
    // would be cleaner but the up-front rejection runs *before* a
    // capability matrix is available (no daemon contact yet), so it
    // reuses the rendering helper directly.
    render_feature_mismatch(
        &UnsupportedFeature::PerSessionNoCache(BackendKind::Container),
        &FeatureMismatchContext {
            lite_flag_used,
            no_hardening_flag_used: false,
        },
    )
}

/// Render the M11-S8 Wave 2 misuse error for `--force-rootless-docker`
/// against a resolved Lima backend.
///
/// `--force-rootless-docker` is the operator's per-invocation opt-in
/// to allow container-backend session-create on a rootless-Docker
/// host (spec § Non-goals 1175). Lima sessions are unaffected by
/// Docker mode entirely, so the combination is operator confusion the
/// CLI rejects up-front before any daemon round-trip — same shape as
/// [`render_no_cache_rejection_for_container`] (multi-line `error:` /
/// `help:`), distinct text so `--no-cache`'s rejection and this one
/// stay greppable independently.
///
/// **Wire-format contract** — pinned by a byte-equality unit test in
/// this module so accidental drift in the operator-facing shape trips
/// the test suite, not a downstream consumer.
pub fn render_force_rootless_docker_lima_rejection() -> String {
    "\
error: `--force-rootless-docker` is only meaningful for the container backend
   help: rootless-Docker detection (spec § Non-goals 1175) is a container-backend gate
   help: drop `--force-rootless-docker`, or pass `--backend container` / `--lite` if you intended a container session
"
    .to_string()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------
    // BackendKindArg
    // -----------------------------------------------------------------

    #[test]
    fn backend_kind_arg_into_kind_roundtrip() {
        assert_eq!(BackendKindArg::Lima.into_kind(), BackendKind::Lima);
        assert_eq!(
            BackendKindArg::Container.into_kind(),
            BackendKind::Container
        );
    }

    // -----------------------------------------------------------------
    // RebuildImageBackend
    // -----------------------------------------------------------------

    /// Single-backend variants project to a one-element list.
    #[test]
    fn rebuild_image_backend_single_lima() {
        assert_eq!(
            RebuildImageBackend::Lima.into_kinds(),
            vec![BackendKind::Lima]
        );
    }

    #[test]
    fn rebuild_image_backend_single_container() {
        assert_eq!(
            RebuildImageBackend::Container.into_kinds(),
            vec![BackendKind::Container]
        );
    }

    /// `All` fans out to every kind in a stable Lima-then-Container
    /// order — the dispatch loop and its tests rely on this ordering.
    #[test]
    fn rebuild_image_backend_all_is_lima_then_container() {
        assert_eq!(
            RebuildImageBackend::All.into_kinds(),
            vec![BackendKind::Lima, BackendKind::Container]
        );
    }

    // -----------------------------------------------------------------
    // resolve_backend — precedence chain
    // -----------------------------------------------------------------

    /// Tier 1: `--lite` wins over every other input.
    #[test]
    fn resolve_backend_lite_flag_wins() {
        let inputs = BackendResolutionInputs {
            lite_flag: true,
            backend_flag: Some(BackendKind::Lima),
            env_default_backend: Some("lima".into()),
            config_default_backend: Some(BackendKind::Lima),
        };
        assert_eq!(resolve_backend(&inputs).unwrap(), BackendKind::Container);
    }

    /// Tier 2: `--backend lima` wins over env/config when `--lite` is
    /// absent, even if env says container.
    #[test]
    fn resolve_backend_explicit_flag_wins_over_env_and_config() {
        let inputs = BackendResolutionInputs {
            lite_flag: false,
            backend_flag: Some(BackendKind::Lima),
            env_default_backend: Some("container".into()),
            config_default_backend: Some(BackendKind::Container),
        };
        assert_eq!(resolve_backend(&inputs).unwrap(), BackendKind::Lima);
    }

    /// Tier 3: `SANDBOX_DEFAULT_BACKEND=container` wins over config
    /// when no flags are set.
    #[test]
    fn resolve_backend_env_wins_over_config() {
        let inputs = BackendResolutionInputs {
            lite_flag: false,
            backend_flag: None,
            env_default_backend: Some("container".into()),
            config_default_backend: Some(BackendKind::Lima),
        };
        assert_eq!(resolve_backend(&inputs).unwrap(), BackendKind::Container);
    }

    /// Tier 4: `default_backend` from config wins when neither flag
    /// nor env is set.
    #[test]
    fn resolve_backend_config_wins_when_nothing_else_set() {
        let inputs = BackendResolutionInputs {
            lite_flag: false,
            backend_flag: None,
            env_default_backend: None,
            config_default_backend: Some(BackendKind::Container),
        };
        assert_eq!(resolve_backend(&inputs).unwrap(), BackendKind::Container);
    }

    /// Tier 5: hardcoded fallback to Lima when nothing is set.
    #[test]
    fn resolve_backend_falls_back_to_lima() {
        let inputs = BackendResolutionInputs::default();
        assert_eq!(resolve_backend(&inputs).unwrap(), BackendKind::Lima);
    }

    /// An empty `SANDBOX_DEFAULT_BACKEND=` value is treated the same
    /// as unset — falls through to the config tier rather than failing.
    #[test]
    fn resolve_backend_empty_env_falls_through_to_config() {
        let inputs = BackendResolutionInputs {
            lite_flag: false,
            backend_flag: None,
            env_default_backend: Some(String::new()),
            config_default_backend: Some(BackendKind::Container),
        };
        assert_eq!(resolve_backend(&inputs).unwrap(), BackendKind::Container);
    }

    /// A malformed `SANDBOX_DEFAULT_BACKEND` value surfaces as a
    /// resolver error rather than silently falling through.
    #[test]
    fn resolve_backend_unknown_env_value_errors() {
        let inputs = BackendResolutionInputs {
            lite_flag: false,
            backend_flag: None,
            env_default_backend: Some("podman".into()),
            config_default_backend: Some(BackendKind::Lima),
        };
        let err = resolve_backend(&inputs).expect_err("podman is not a known backend");
        let msg = err.to_string();
        assert!(msg.contains("SANDBOX_DEFAULT_BACKEND"), "msg: {msg}");
        assert!(msg.contains("podman"), "msg: {msg}");
    }

    // -----------------------------------------------------------------
    // CLI config loader
    // -----------------------------------------------------------------

    /// Helper: write `body` into `<dir>/config.json` so the loader
    /// resolves it as the canonical config path for the given XDG
    /// override. Returns the path that was written so tests can refer
    /// to it.
    fn write_config(dir: &Path, body: &str) -> PathBuf {
        let path = dir.join("config.json");
        std::fs::write(&path, body).expect("write config.json");
        path
    }

    #[test]
    fn load_cli_config_missing_file_returns_default() {
        let tmp = tempfile::tempdir().expect("tempdir");
        // No config.json written.
        let cfg = load_cli_config(Some(tmp.path())).expect("missing file is not an error");
        assert!(cfg.default_backend.is_none());
        assert!(cfg.backends.container.is_none());
    }

    #[test]
    fn load_cli_config_empty_object_is_default() {
        let tmp = tempfile::tempdir().expect("tempdir");
        write_config(tmp.path(), "{}");
        let cfg = load_cli_config(Some(tmp.path())).expect("empty object parses");
        assert!(cfg.default_backend.is_none());
        assert!(cfg.backends.container.is_none());
    }

    #[test]
    fn load_cli_config_parses_default_backend_container() {
        let tmp = tempfile::tempdir().expect("tempdir");
        write_config(tmp.path(), r#"{"default_backend": "container"}"#);
        let cfg = load_cli_config(Some(tmp.path())).expect("parses");
        assert_eq!(cfg.default_backend, Some(BackendKind::Container));
    }

    #[test]
    fn load_cli_config_parses_full_spec_example() {
        // Spec § "Config file" canonical example.
        let tmp = tempfile::tempdir().expect("tempdir");
        write_config(
            tmp.path(),
            r#"{
                "default_backend": "lima",
                "backends": {
                    "container": {}
                }
            }"#,
        );
        let cfg = load_cli_config(Some(tmp.path())).expect("parses");
        assert_eq!(cfg.default_backend, Some(BackendKind::Lima));
        assert!(
            cfg.backends.container.is_some(),
            "empty container object should still deserialize as Some(_)"
        );
    }

    #[test]
    fn load_cli_config_malformed_json_is_hard_error_with_path() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let path = write_config(tmp.path(), "not-json-at-all");
        let err = load_cli_config(Some(tmp.path())).expect_err("malformed JSON must error");
        let msg = err.to_string();
        // Spec mandates the error pointer to the path.
        let path_str = path.display().to_string();
        assert!(
            msg.contains(&path_str),
            "error message must include path; got: {msg}"
        );
    }

    #[test]
    fn load_cli_config_tolerates_unknown_top_level_fields() {
        // Forward-compat: a future CLI may add new top-level fields;
        // an older CLI must still parse the file. `#[serde(default)]`
        // at every site provides this implicitly.
        let tmp = tempfile::tempdir().expect("tempdir");
        write_config(
            tmp.path(),
            r#"{
                "default_backend": "container",
                "future_field": "ignored"
            }"#,
        );
        let cfg = load_cli_config(Some(tmp.path())).expect("unknown fields tolerated");
        assert_eq!(cfg.default_backend, Some(BackendKind::Container));
    }

    // -----------------------------------------------------------------
    // Feature-mismatch error rendering — byte-equality contract
    // -----------------------------------------------------------------

    /// Spec § "CLI & UX → Feature-mismatch errors" shows the
    /// `--hardened` + `--lite` conflict verbatim. Pin every byte.
    #[test]
    fn render_hardening_with_lite_matches_spec_byte_for_byte() {
        let rendered = render_feature_mismatch(
            &UnsupportedFeature::Hardening,
            &FeatureMismatchContext {
                lite_flag_used: true,
                no_hardening_flag_used: false,
            },
        );
        let expected = "\
error: `--hardened` requires a VM-backed session, but `--lite` selects the container backend
   help: lite containers apply default hardening automatically
   help: remove `--hardened`, or drop `--lite` to get QEMU-level hardening
";
        assert_eq!(rendered, expected);
    }

    /// Same as above but with `--backend container` instead of
    /// `--lite`. The spec only shows the `--lite` example; the
    /// `--backend container` form is the same shape with the flag
    /// names swapped consistently in both `error:` and `help:` lines.
    #[test]
    fn render_hardening_with_backend_container_swaps_flag_name() {
        let rendered = render_feature_mismatch(
            &UnsupportedFeature::Hardening,
            &FeatureMismatchContext {
                lite_flag_used: false,
                no_hardening_flag_used: false,
            },
        );
        let expected = "\
error: `--hardened` requires a VM-backed session, but `--backend container` selects the container backend
   help: lite containers apply default hardening automatically
   help: remove `--hardened`, or drop `--backend container` to get QEMU-level hardening
";
        assert_eq!(rendered, expected);
    }

    /// Spec § "CLI & UX → `sandbox create --no-cache` is forbidden on
    /// container" gives the exact text. Pin every byte.
    #[test]
    fn render_no_cache_rejection_for_container_with_lite_matches_spec() {
        let rendered = render_no_cache_rejection_for_container(true);
        let expected = "\
error: `--no-cache` is not supported with `--lite` / container backend
   help: containers have no per-session slow-path equivalent to Lima's full-VM-create
   help: to rebuild the shared lite image, use:
         sandbox rebuild-image --backend container --no-cache
";
        assert_eq!(rendered, expected);
    }

    /// Same as above but with `--backend container`. The spec text
    /// uses `--lite` form; the `--backend container` variant swaps
    /// the flag identifier in the `error:` line.
    #[test]
    fn render_no_cache_rejection_for_container_with_backend_flag_swaps_name() {
        let rendered = render_no_cache_rejection_for_container(false);
        let expected = "\
error: `--no-cache` is not supported with `--backend container` / container backend
   help: containers have no per-session slow-path equivalent to Lima's full-VM-create
   help: to rebuild the shared lite image, use:
         sandbox rebuild-image --backend container --no-cache
";
        assert_eq!(rendered, expected);
    }

    /// M11-S8 Wave 2: `--force-rootless-docker` with a resolved Lima
    /// backend renders a three-line misuse error. Pin every byte so
    /// downstream tests (Wave 3's
    /// `integration_rootless_docker_force_flag_rejected_on_lima`) and
    /// the spec text stay aligned.
    #[test]
    fn render_force_rootless_docker_lima_rejection_matches_spec() {
        let rendered = render_force_rootless_docker_lima_rejection();
        let expected = "\
error: `--force-rootless-docker` is only meaningful for the container backend
   help: rootless-Docker detection (spec § Non-goals 1175) is a container-backend gate
   help: drop `--force-rootless-docker`, or pass `--backend container` / `--lite` if you intended a container session
";
        assert_eq!(rendered, expected);
    }

    // -----------------------------------------------------------------
    // Isolation warning — byte-equality contract
    // -----------------------------------------------------------------

    /// Spec § "Isolation warning" (lines 751-762) gives the exact two
    /// lines that the CLI must emit before each `--lite` /
    /// `--backend container` create. Pin every byte — including the
    /// em dash (U+2014) and the six-space indent on line 2.
    #[test]
    fn render_isolation_warning_container_matches_spec_byte_for_byte() {
        let rendered = render_isolation_warning(BackendKind::Container);
        let expected = "lite: container-backed session \u{2014} container-level isolation only (not VM-grade)\n      see docs/lite.md for the trade-off details\n";
        assert_eq!(rendered, expected);
    }

    /// Sanity: the em dash on the first line is U+2014, not a hyphen
    /// or U+2013. A copy-paste regression that swaps the codepoint
    /// would still pass byte-equality against an equally-broken
    /// expected string, so we read the codepoint out explicitly.
    #[test]
    fn render_isolation_warning_uses_em_dash_u2014() {
        let rendered = render_isolation_warning(BackendKind::Container);
        let dashes: Vec<char> = rendered.chars().filter(|c| *c == '\u{2014}').collect();
        assert_eq!(
            dashes.len(),
            1,
            "expected exactly one U+2014 em dash in warning, got rendered:\n{rendered}"
        );
    }

    /// Lima creates must NOT emit the warning — the spec scopes it to
    /// container-backed sessions only.
    #[test]
    fn render_isolation_warning_lima_is_empty() {
        let rendered = render_isolation_warning(BackendKind::Lima);
        assert!(
            rendered.is_empty(),
            "Lima must not emit the lite isolation warning, got: {rendered:?}"
        );
    }

    /// Workspace-mismatch shape — `Shared` against container.
    #[test]
    fn render_workspace_mode_shared_matches_expected_shape() {
        let rendered = render_feature_mismatch(
            &UnsupportedFeature::WorkspaceMode(WorkspaceModeKind::Shared, BackendKind::Container),
            &FeatureMismatchContext {
                lite_flag_used: true,
                no_hardening_flag_used: false,
            },
        );
        let expected = "\
error: `--workspace shared` is not supported by the container backend selected via `--lite`
   help: drop `--workspace`, or pick a different `--workspace` mode the backend advertises
   help: switch backends to one whose capabilities include `shared` — see `sandbox inspect -v` for the matrix
";
        assert_eq!(rendered, expected);
    }
}
