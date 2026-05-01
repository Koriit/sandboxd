//! User-configured presets loaded from `$XDG_CONFIG_HOME/sandboxd/presets/`.
//!
//! This module implements the XDG loader. It reads `*.json` files
//! from the user's preset directory, validates the structural and
//! semantic constraints the spec calls out (see
//! `.tasks/specs/2026-04-21-port-explicit-policies-presets-observability-design.md`
//! Part 2 § "User-configured presets"), and returns a list of
//! [`UserPreset`] values whose `${param}` references are preserved
//! verbatim for expansion at apply time.
//!
//! # Error handling contract
//!
//! The loader distinguishes two classes of errors:
//!
//! - **Per-file soft errors** (malformed JSON, bad `name` shape,
//!   unknown fields, IO errors reading a single file) emit a warning to
//!   stderr and skip the offending file. Sibling files still load. This
//!   is the "warn-and-skip" spec contract (Part 2 § "Loading errors").
//! - **Cross-file hard errors** (two files declaring the same `name`,
//!   a preset with more than one `repeatable: true` param) propagate
//!   out as a [`PresetError`]. These are operator bugs that silent
//!   skipping would hide.
//!
//! # Shadowing
//!
//! Shadow detection against built-ins is *not* done here. The
//! [`super::Catalog::load`] call intersects user names with built-in
//! names after this loader returns, and [`super::Catalog::find`]
//! surfaces the [`PresetError::ShadowedName`] error only when a
//! shadowed name is actually invoked. See [`super::Catalog`] for the
//! rationale.

use std::collections::HashMap;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use serde::Deserialize;

use super::PresetError;

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// A user-configured preset loaded from
/// `$XDG_CONFIG_HOME/sandboxd/presets/<name>.json`.
///
/// `rules` keeps the user's raw `PolicyRule`-shaped templates intact so
/// Phase 3's expander can substitute `${param}` references before
/// materializing them into real [`sandbox_core::PolicyRule`] values.
#[derive(Debug, Clone)]
pub struct UserPreset {
    /// Preset name — validated to match `^[A-Za-z0-9_-]+$`.
    pub name: String,
    /// Optional human-readable description surfaced by
    /// `sandbox policy preset show`.
    pub description: Option<String>,
    /// Parameter specifications declared by the preset.
    pub params: Vec<UserParamSpec>,
    /// Raw rule templates — string fields may contain `${param}`
    /// references that Phase 3 substitutes at expand time.
    pub rules: Vec<RawRuleTemplate>,
    /// Absolute path of the file this preset was loaded from.
    /// Load-bearing for shadowing and duplicate-source error messages.
    pub source_path: PathBuf,
}

/// A single `(name, type, required, repeatable)` parameter declaration
/// on a user preset.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserParamSpec {
    /// Parameter name as it appears in both the invocation
    /// (`--preset 'p:name=val'`) and in `${name}` template references.
    pub name: String,
    /// Parameter value type. Currently only [`ParamType::String`] is
    /// supported; the spec does not reserve any other types yet.
    #[serde(rename = "type")]
    pub r#type: ParamType,
    /// Whether the invocation must include this param.
    pub required: bool,
    /// Whether the param may appear more than once, with each value
    /// producing a copy of the enclosing rule with that value
    /// substituted.
    pub repeatable: bool,
}

/// Parameter value type.
///
/// `String` is the only variant — the spec says user presets get string
/// substitution only (no conditionals, no iteration). Extending this
/// enum would also require extending the template expander in Phase 3.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ParamType {
    String,
}

/// A raw policy rule template preserved verbatim from a user preset
/// file.
///
/// The shape mirrors [`sandbox_core::PolicyRule`] but keeps every
/// string-valued field as a plain [`String`] so `${param}` references
/// survive deserialization. The typed fields that do *not* admit
/// templates (`port`, `protocol`, `level`, `method`) are deserialized
/// into their concrete enums up-front so the preset file surfaces
/// structural errors (e.g. `protocol: "foo"`) at load time rather than
/// at expand time.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawRuleTemplate {
    /// Destination host — may contain `${param}` references.
    pub host: String,
    /// L4 port. Templating is not supported for ports.
    pub port: u16,
    /// L4 protocol (`tcp` or `udp`).
    pub protocol: RawProtocol,
    /// Assurance level tag. For `http` rules the accompanying
    /// `http_filters` array is required.
    pub level: RawLevel,
    /// `http`-level request filters. Ignored for other levels, but
    /// accepted in the file shape — presence on a non-http rule is a
    /// validation error surfaced at expand time, not here.
    #[serde(default)]
    pub http_filters: Option<Vec<RawHttpFilter>>,
    /// Optional human-readable reason — may contain `${param}`
    /// references.
    #[serde(default)]
    pub reason: Option<String>,
}

/// `level` tag for a raw rule template.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RawLevel {
    Deny,
    Transport,
    Tls,
    Http,
}

/// `protocol` field for a raw rule template.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RawProtocol {
    Tcp,
    Udp,
}

/// `http_filters` entry for a raw rule template.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawHttpFilter {
    /// HTTP method — closed enum, cannot be templated.
    pub method: RawHttpMethod,
    /// Request path — may contain `${param}` references.
    pub path: String,
}

/// `method` field for a raw HTTP filter.
///
/// Mirrors [`sandbox_core::HttpMethod`] one-for-one; kept local so this
/// module does not pull in a type that might get extended on the
/// `sandbox-core` side without a template-loader update.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum RawHttpMethod {
    Get,
    Post,
    Put,
    Delete,
    Patch,
    Head,
    Options,
    Trace,
    Connect,
    Any,
}

// ---------------------------------------------------------------------------
// File-level deserialization shape
// ---------------------------------------------------------------------------

/// On-disk JSON shape of one preset file.
///
/// Separate from [`UserPreset`] because the on-disk shape lacks the
/// `source_path` field — we only know the path after the file is
/// opened, and we want that field to be non-optional on the in-memory
/// type.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct UserPresetFile {
    name: String,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    params: Vec<UserParamSpec>,
    #[serde(default)]
    rules: Vec<RawRuleTemplate>,
}

// ---------------------------------------------------------------------------
// Loader
// ---------------------------------------------------------------------------

/// Load every valid user preset under
/// `$XDG_CONFIG_HOME/sandboxd/presets/` (or the override).
///
/// See the module docs for the per-file vs. cross-file error split.
/// Warnings for per-file skips are written to stderr via `eprintln!`.
/// Tests should prefer [`load_user_presets_with_warnings`] with an
/// in-memory sink — stderr capture is not reliable across threaded test
/// runners.
pub fn load_user_presets(xdg_override: Option<&Path>) -> Result<Vec<UserPreset>, PresetError> {
    load_user_presets_with_warnings(xdg_override, &mut |line| {
        eprintln!("{line}");
    })
}

/// Same as [`load_user_presets`] but routes warning lines through the
/// caller-supplied sink. Exposed for unit testing.
///
/// The sink receives already-formatted lines — no trailing newline, no
/// leading prefix beyond the spec's `warning: ...` form. The caller is
/// responsible for line-termination (stderr path adds a newline via
/// `eprintln!`).
pub fn load_user_presets_with_warnings(
    xdg_override: Option<&Path>,
    warn: &mut dyn FnMut(&str),
) -> Result<Vec<UserPreset>, PresetError> {
    // Resolve the base directory. Missing $HOME with no override and no
    // $XDG_CONFIG_HOME is a silent empty-return — not every machine has
    // a user config dir, and the CLI has to work on them.
    let Some(base_dir) = resolve_base_dir(xdg_override) else {
        return Ok(Vec::new());
    };

    // Probe the directory. ENOENT is the spec-defined "silent" case;
    // other IO errors are "warn and return empty".
    let entries = match fs::read_dir(&base_dir) {
        Ok(entries) => entries,
        Err(err) if err.kind() == io::ErrorKind::NotFound => {
            return Ok(Vec::new());
        }
        Err(err) => {
            warn(&format!(
                "warning: preset directory {}: {}; skipping user presets",
                base_dir.display(),
                err
            ));
            return Ok(Vec::new());
        }
    };

    // Collect `.json` paths first, then sort for deterministic order.
    // Directory iteration order is OS-dependent; explicit sort keeps
    // the duplicate-name error's path pair stable across test runs.
    let mut json_paths: Vec<PathBuf> = Vec::new();
    for entry in entries {
        match entry {
            Ok(entry) => {
                let path = entry.path();
                if is_json_file(&path) {
                    json_paths.push(path);
                }
            }
            Err(err) => {
                warn(&format!(
                    "warning: preset directory {}: {}; skipping an entry",
                    base_dir.display(),
                    err
                ));
            }
        }
    }
    json_paths.sort();

    // Track names we have already loaded so a second file with the
    // same `name` can surface both source paths.
    let mut seen: HashMap<String, PathBuf> = HashMap::new();
    let mut out: Vec<UserPreset> = Vec::new();

    for path in json_paths {
        let preset = match load_one(&path, warn) {
            Ok(Some(preset)) => preset,
            Ok(None) => continue, // soft-skipped with a warning
            Err(hard) => return Err(hard),
        };

        if let Some(existing_path) = seen.get(&preset.name) {
            return Err(PresetError::DuplicateUserPresetName {
                name: preset.name.clone(),
                path_a: existing_path.clone(),
                path_b: preset.source_path.clone(),
            });
        }
        seen.insert(preset.name.clone(), preset.source_path.clone());
        out.push(preset);
    }

    Ok(out)
}

/// Load and validate one preset file.
///
/// Returns:
/// - `Ok(Some(preset))` on success.
/// - `Ok(None)` on a soft, file-local failure (a warning has already
///   been emitted via `warn`).
/// - `Err(_)` on a hard failure that must abort the whole load pass.
fn load_one(path: &Path, warn: &mut dyn FnMut(&str)) -> Result<Option<UserPreset>, PresetError> {
    // Read the file. A read error on a single file is soft-skip — the
    // sibling files can still load.
    let contents = match fs::read_to_string(path) {
        Ok(s) => s,
        Err(err) => {
            warn(&format!(
                "warning: preset file {}: {}; skipping",
                path.display(),
                err
            ));
            return Ok(None);
        }
    };

    // Parse JSON. Any structural problem (malformed JSON, unknown
    // fields, wrong-typed values, missing required fields) is a soft
    // skip — sibling files must still load.
    let file: UserPresetFile = match serde_json::from_str(&contents) {
        Ok(f) => f,
        Err(err) => {
            warn(&format!(
                "warning: preset file {}: {}; skipping",
                path.display(),
                err
            ));
            return Ok(None);
        }
    };

    // Validate `name` shape — DNS-ish, no colons/dots/slashes. The
    // spec (D-2) reserves `:` and `,` and `=` in invocation strings;
    // the loader rejects those plus `.`/`/` proactively to stop a
    // user preset from ever tripping the invocation parser.
    if !is_valid_preset_name(&file.name) {
        warn(&format!(
            "warning: preset file {}: invalid preset name '{}'; \
             names must match [A-Za-z0-9_-]+; skipping",
            path.display(),
            file.name
        ));
        return Ok(None);
    }

    // At most one repeatable param per preset. This is the spec's
    // only hard multi-repeatable restriction (Part 2 lines 601-607).
    let repeatable_count = file.params.iter().filter(|p| p.repeatable).count();
    if repeatable_count > 1 {
        return Err(PresetError::TooManyRepeatableParams {
            path: path.to_path_buf(),
            count: repeatable_count,
        });
    }

    // Param names must be unique within a preset.
    let mut param_names: HashMap<&str, ()> = HashMap::new();
    for param in &file.params {
        if param_names.insert(param.name.as_str(), ()).is_some() {
            warn(&format!(
                "warning: preset file {}: duplicate param name '{}'; skipping",
                path.display(),
                param.name
            ));
            return Ok(None);
        }
    }

    Ok(Some(UserPreset {
        name: file.name,
        description: file.description,
        params: file.params,
        rules: file.rules,
        source_path: path.to_path_buf(),
    }))
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Resolve the XDG preset base directory.
///
/// Delegates to [`crate::cli_xdg::resolve_sandboxd_config_dir`] —
/// spec § "CLI & UX → Config file" mandates "one resolver, not two"
/// for `~/.config/sandboxd/presets/` and
/// `~/.config/sandboxd/config.json`. Both call sites append their own
/// per-feature subpath after the shared resolver returns the base.
///
/// Returns `None` when neither `$XDG_CONFIG_HOME` nor `$HOME` is set —
/// callers treat that as "no user presets to load".
fn resolve_base_dir(xdg_override: Option<&Path>) -> Option<PathBuf> {
    if let Some(path) = xdg_override {
        return Some(path.to_path_buf());
    }
    crate::cli_xdg::resolve_sandboxd_config_dir(None).map(|p| p.join("presets"))
}

/// Return true when `path` has a `.json` extension (case-sensitive,
/// per D-7).
fn is_json_file(path: &Path) -> bool {
    // `extension()` returns the raw bytes after the last `.` without
    // case-folding — exactly the case-sensitive check D-7 mandates.
    path.extension().map(|ext| ext == "json").unwrap_or(false)
}

/// Return true when `name` is a DNS-ish preset name: non-empty, only
/// `[A-Za-z0-9_-]`.
fn is_valid_preset_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use std::io::Write;
    use tempfile::TempDir;

    /// Test helper: collect warnings emitted by the loader into a Vec.
    fn capture_warnings(base: &Path) -> (Result<Vec<UserPreset>, PresetError>, Vec<String>) {
        let mut warnings: Vec<String> = Vec::new();
        let result = load_user_presets_with_warnings(Some(base), &mut |line| {
            warnings.push(line.to_string());
        });
        (result, warnings)
    }

    /// Write a JSON string to `<dir>/<filename>`.
    fn write_file(dir: &Path, filename: &str, body: &str) -> PathBuf {
        let path = dir.join(filename);
        let mut f = File::create(&path).expect("create preset file");
        f.write_all(body.as_bytes()).expect("write preset body");
        path
    }

    #[test]
    fn missing_base_dir_returns_empty_without_warning() {
        // Point at a subdir that does not exist — this is the common
        // case for a user who has never created the XDG preset dir.
        let tmp = TempDir::new().unwrap();
        let nonexistent = tmp.path().join("does-not-exist");
        let (result, warnings) = capture_warnings(&nonexistent);
        let presets = result.expect("missing dir should not be a hard error");
        assert!(presets.is_empty());
        assert!(
            warnings.is_empty(),
            "missing base dir must be silent; got {warnings:?}"
        );
    }

    #[test]
    fn empty_base_dir_returns_empty_without_warning() {
        let tmp = TempDir::new().unwrap();
        let (result, warnings) = capture_warnings(tmp.path());
        let presets = result.expect("empty dir should not be a hard error");
        assert!(presets.is_empty());
        assert!(
            warnings.is_empty(),
            "empty dir must be silent; got {warnings:?}"
        );
    }

    #[test]
    fn single_valid_json_file_is_loaded() {
        let tmp = TempDir::new().unwrap();
        let body = r#"{
            "name": "my-internal-api",
            "description": "Internal API access for the billing service",
            "params": [
                {"name": "tenant", "type": "string", "required": true, "repeatable": false}
            ],
            "rules": [
                {
                    "host": "${tenant}.api.internal.example.com",
                    "port": 443,
                    "protocol": "tcp",
                    "level": "http",
                    "http_filters": [{"method": "GET", "path": "/v1/**"}]
                }
            ]
        }"#;
        let path = write_file(tmp.path(), "my-internal-api.json", body);
        let (result, warnings) = capture_warnings(tmp.path());
        let presets = result.expect("valid file should load");
        assert!(
            warnings.is_empty(),
            "valid file must not warn; got {warnings:?}"
        );
        assert_eq!(presets.len(), 1);

        let preset = &presets[0];
        assert_eq!(preset.name, "my-internal-api");
        assert_eq!(
            preset.description.as_deref(),
            Some("Internal API access for the billing service")
        );
        assert_eq!(preset.source_path, path);
        assert_eq!(preset.params.len(), 1);
        assert_eq!(
            preset.params[0],
            UserParamSpec {
                name: "tenant".to_string(),
                r#type: ParamType::String,
                required: true,
                repeatable: false,
            }
        );
        assert_eq!(preset.rules.len(), 1);
        let rule = &preset.rules[0];
        assert_eq!(rule.host, "${tenant}.api.internal.example.com");
        assert_eq!(rule.port, 443);
        assert_eq!(rule.protocol, RawProtocol::Tcp);
        assert_eq!(rule.level, RawLevel::Http);
        let filters = rule.http_filters.as_ref().expect("http_filters present");
        assert_eq!(filters.len(), 1);
        assert_eq!(filters[0].method, RawHttpMethod::Get);
        assert_eq!(filters[0].path, "/v1/**");
    }

    #[test]
    fn two_valid_files_both_load_in_name_sorted_order() {
        let tmp = TempDir::new().unwrap();
        let body_a = r#"{
            "name": "preset-a",
            "params": [],
            "rules": []
        }"#;
        let body_b = r#"{
            "name": "preset-b",
            "params": [],
            "rules": []
        }"#;
        write_file(tmp.path(), "b.json", body_b);
        write_file(tmp.path(), "a.json", body_a);

        let (result, warnings) = capture_warnings(tmp.path());
        let presets = result.expect("both files should load");
        assert!(
            warnings.is_empty(),
            "valid files must not warn; got {warnings:?}"
        );
        assert_eq!(presets.len(), 2);
        // We sort by filename before loading, so `a.json` → preset-a
        // comes before `b.json` → preset-b deterministically.
        assert_eq!(presets[0].name, "preset-a");
        assert_eq!(presets[1].name, "preset-b");
    }

    #[test]
    fn malformed_json_warns_and_skips_while_siblings_load() {
        let tmp = TempDir::new().unwrap();
        // Valid sibling that must still load.
        let body_good = r#"{
            "name": "good",
            "params": [],
            "rules": []
        }"#;
        let good_path = write_file(tmp.path(), "good.json", body_good);
        // Broken JSON — missing closing brace.
        let bad_path = write_file(tmp.path(), "bad.json", "{ not json");

        let (result, warnings) = capture_warnings(tmp.path());
        let presets = result.expect("malformed sibling should not fail the load");
        assert_eq!(presets.len(), 1);
        assert_eq!(presets[0].name, "good");
        assert_eq!(presets[0].source_path, good_path);
        // A warning fired that mentions the bad file's absolute path.
        assert_eq!(
            warnings.len(),
            1,
            "exactly one warning expected: {warnings:?}"
        );
        assert!(
            warnings[0].contains(&bad_path.display().to_string()),
            "warning must name the bad file path: {}",
            warnings[0]
        );
        assert!(
            warnings[0].starts_with("warning: preset file"),
            "warning must start with spec-mandated prefix: {}",
            warnings[0]
        );
    }

    #[test]
    fn invalid_name_warns_and_skips() {
        let tmp = TempDir::new().unwrap();
        let body = r#"{
            "name": "foo.bar",
            "params": [],
            "rules": []
        }"#;
        let path = write_file(tmp.path(), "foo-bar.json", body);
        let (result, warnings) = capture_warnings(tmp.path());
        let presets = result.expect("invalid name is soft-skip, not hard error");
        assert!(presets.is_empty());
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("invalid preset name 'foo.bar'"));
        assert!(warnings[0].contains(&path.display().to_string()));
    }

    #[test]
    fn duplicate_name_across_files_is_hard_error() {
        let tmp = TempDir::new().unwrap();
        let body = r#"{
            "name": "samename",
            "params": [],
            "rules": []
        }"#;
        // Sort order places `a.json` before `b.json`, so `a` is the
        // `path_a` side of the error and `b` is `path_b`.
        let path_a = write_file(tmp.path(), "a.json", body);
        let path_b = write_file(tmp.path(), "b.json", body);

        let (result, warnings) = capture_warnings(tmp.path());
        let err = result.expect_err("duplicate name must be a hard error");
        assert!(warnings.is_empty(), "no soft warning on the hard path");
        match err {
            PresetError::DuplicateUserPresetName {
                name,
                path_a: got_a,
                path_b: got_b,
            } => {
                assert_eq!(name, "samename");
                assert_eq!(got_a, path_a);
                assert_eq!(got_b, path_b);
            }
            other => panic!("expected DuplicateUserPresetName, got {other:?}"),
        }
    }

    #[test]
    fn two_repeatable_params_is_hard_error() {
        let tmp = TempDir::new().unwrap();
        let body = r#"{
            "name": "multirepeat",
            "params": [
                {"name": "a", "type": "string", "required": true, "repeatable": true},
                {"name": "b", "type": "string", "required": true, "repeatable": true}
            ],
            "rules": []
        }"#;
        let path = write_file(tmp.path(), "multirepeat.json", body);

        let (result, warnings) = capture_warnings(tmp.path());
        let err = result.expect_err("two repeatable params must be a hard error");
        assert!(warnings.is_empty(), "no soft warning on the hard path");
        match err {
            PresetError::TooManyRepeatableParams { path: got, count } => {
                assert_eq!(got, path);
                assert_eq!(count, 2);
            }
            other => panic!("expected TooManyRepeatableParams, got {other:?}"),
        }
    }

    #[test]
    fn txt_file_in_preset_dir_is_ignored() {
        let tmp = TempDir::new().unwrap();
        // A bogus `.txt` file whose content would fail JSON parsing
        // must not even be opened — if the loader tried, we would see
        // a warning.
        write_file(tmp.path(), "notes.txt", "not actually json");
        // Also drop a `.JSON` (uppercase) file — per D-7 the loader
        // is case-sensitive, so this should also be ignored.
        write_file(tmp.path(), "upper.JSON", "{}");

        let (result, warnings) = capture_warnings(tmp.path());
        let presets = result.expect("non-json files should be ignored silently");
        assert!(presets.is_empty());
        assert!(
            warnings.is_empty(),
            "non-json must not warn; got {warnings:?}"
        );
    }

    #[test]
    fn duplicate_param_names_warn_and_skip() {
        let tmp = TempDir::new().unwrap();
        let body = r#"{
            "name": "dupparam",
            "params": [
                {"name": "x", "type": "string", "required": true, "repeatable": false},
                {"name": "x", "type": "string", "required": false, "repeatable": false}
            ],
            "rules": []
        }"#;
        write_file(tmp.path(), "dupparam.json", body);
        let (result, warnings) = capture_warnings(tmp.path());
        let presets = result.expect("duplicate param is soft-skip");
        assert!(presets.is_empty());
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("duplicate param name 'x'"));
    }

    #[test]
    fn unknown_top_level_field_warns_and_skips() {
        // `deny_unknown_fields` on `UserPresetFile` turns typos like
        // `rulez` into a hard serde error, which we surface as a
        // soft-skip.
        let tmp = TempDir::new().unwrap();
        let body = r#"{
            "name": "typo",
            "params": [],
            "rulez": []
        }"#;
        write_file(tmp.path(), "typo.json", body);
        let (result, warnings) = capture_warnings(tmp.path());
        let presets = result.expect("unknown field is soft-skip");
        assert!(presets.is_empty());
        assert_eq!(warnings.len(), 1);
    }
}
