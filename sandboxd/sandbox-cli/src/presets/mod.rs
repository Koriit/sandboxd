//! Client-local preset system for `sandbox-cli`.
//!
//! Presets are fully client-local macros that expand to v2
//! [`sandbox_core::PolicyRule`] sets inside the CLI before the
//! effective policy is sent to the
//! daemon. The daemon has no awareness of presets — it only ever sees
//! the concrete, validated effective policy plus a `source_presets`
//! audit field.
//!
//! See `.tasks/specs/2026-04-21-port-explicit-policies-presets-observability-design.md`
//! Part 2 for the design, and `docs/internal/milestones/M10.md` § M10-S5
//! for the implementation milestone.
//!
//! # Current scope
//!
//! M10-S5 Phases 1–2 are live:
//!
//! - The [`Preset`] enum distinguishes [`BuiltinPreset`]s (compiled-in)
//!   from [`UserPreset`]s (loaded from `$XDG_CONFIG_HOME/sandboxd/presets/`).
//!   The split keeps the shadowing check (D-3) a trivial type-level
//!   discrimination.
//! - The [`Catalog`] composes both sources and exposes a read-only
//!   lookup surface (`find`, `list`). [`Catalog::load`] runs the Phase
//!   2 XDG loader in [`user::load_user_presets`], records shadow
//!   conflicts, and defers the hard error to invocation time inside
//!   [`Catalog::find`].
//! - Each [`BuiltinPreset`] carries an `expand` function pointer so
//!   that each built-in can implement its own expansion logic (trivial
//!   for `npm` / `pypi` / …, non-trivial for `github-repo` /
//!   `github-pr`). Phase 1 wired every expander to return
//!   [`PresetError::NotImplemented`]; Phase 3 replaces the stubs with
//!   real bodies and introduces the parameter-validation variants
//!   ([`PresetError::MissingRequiredParam`],
//!   [`PresetError::UnknownParamRef`], …) shared by built-ins and the
//!   user-preset expander.
//! - The [`PresetError`] hierarchy grows as phases need new failure
//!   shapes. Every variant has a `Display` impl that matches the
//!   wording called out in the spec and the Phase 0 decisions.

// Phase 1 of M10-S5 ships the type and parser surface but no call
// sites inside the binary (the `--preset` flag and the `sandbox policy
// preset` subcommand land in Phase 5).  Silence the transitive
// dead-code and unused-import warnings inside the module rather than
// sprinkling fine-grained attributes across every item.  Remove this
// allow when Phase 5 wires the surface into `main.rs`.
#![allow(dead_code)]
#![allow(unused_imports)]

use std::collections::HashMap;
use std::fmt;
use std::path::{Path, PathBuf};

pub mod builtin;
pub mod expand;
pub mod method;
pub mod param;
pub mod user;

// Re-export the public surface callers are expected to use in Phase 5.
pub use builtin::{BUILTINS, BuiltinPreset};
pub use expand::expand;
pub use param::ParsedInvocation;
pub use user::{
    ParamType, RawHttpFilter, RawHttpMethod, RawLevel, RawProtocol, RawRuleTemplate, UserParamSpec,
    UserPreset,
};

/// A preset is either a compile-time built-in or a user-configured
/// definition loaded from XDG.
///
/// The `Builtin` / `User` split is load-bearing: it lets the shadowing
/// check (D-3) be a type-level discrimination rather than a runtime
/// tag lookup, and it lets error messages naturally distinguish the
/// two sources.
#[derive(Debug)]
pub enum Preset {
    /// A compile-time built-in preset (embedded in the CLI binary).
    Builtin(&'static BuiltinPreset),
    /// A user-configured preset loaded from the XDG presets directory.
    User(UserPreset),
}

impl Preset {
    /// The preset's name — the string the user types before the `:` in
    /// a `--preset` invocation.
    pub fn name(&self) -> &str {
        match self {
            Preset::Builtin(b) => b.name,
            Preset::User(u) => &u.name,
        }
    }

    /// A human-readable description for `sandbox policy preset show`.
    pub fn description(&self) -> Option<&str> {
        match self {
            Preset::Builtin(b) => Some(b.description),
            Preset::User(u) => u.description.as_deref(),
        }
    }
}

/// In-memory index of all presets available to the running CLI
/// invocation.
#[derive(Debug)]
pub struct Catalog {
    /// Compile-time built-in presets.
    builtins: &'static [BuiltinPreset],
    /// User-configured presets loaded from the XDG presets dir.
    users: Vec<UserPreset>,
    /// Names that exist as both a built-in and a user preset.
    ///
    /// D-3 makes shadowing a hard error, but fires it only when the
    /// shadowed name is *invoked* — a latent user file that happens to
    /// collide with a new built-in release should not break every
    /// unrelated `sandbox` invocation. This map stores the path of the
    /// offending user file keyed by the shadowed name so
    /// [`Catalog::find`] can produce
    /// [`PresetError::ShadowedName`] with full source attribution.
    shadow_conflicts: HashMap<String, PathBuf>,
}

impl Catalog {
    /// Load the catalog, merging built-ins with user-configured presets.
    ///
    /// `cli_xdg_override` is a test hook honored by the XDG loader —
    /// unit tests point at a tempdir instead of the real
    /// `$XDG_CONFIG_HOME`. In production callers always pass `None`.
    ///
    /// Soft per-file errors (malformed JSON, invalid preset name,
    /// duplicate params inside one preset) are written as warnings to
    /// stderr by the loader and the offending file is skipped. Hard
    /// cross-file errors (two files with the same `name`, or a preset
    /// with more than one `repeatable` param) bubble up here as
    /// [`PresetError`] and the CLI fails fast — these are operator
    /// bugs that silent skipping would hide.
    pub fn load(cli_xdg_override: Option<&Path>) -> Result<Self, PresetError> {
        let users = user::load_user_presets(cli_xdg_override)?;

        // Shadow-name detection runs at load time but the error fires
        // only when the shadowed name is actually invoked (see
        // `Catalog::find`). Rationale: a latent `my-internal.json` file
        // that happens to collide with a future built-in must not break
        // every unrelated CLI invocation.
        let shadow_conflicts: HashMap<String, PathBuf> = users
            .iter()
            .filter(|u| BUILTINS.iter().any(|b| b.name == u.name.as_str()))
            .map(|u| (u.name.clone(), u.source_path.clone()))
            .collect();

        Ok(Catalog {
            builtins: BUILTINS,
            users,
            shadow_conflicts,
        })
    }

    /// Look up a preset by name.
    ///
    /// Resolution order (matches the spec's namespacing rule in Part 2
    /// § "User-configured presets"):
    /// 1. If `name` is in the shadow-conflict set (i.e. both a built-in
    ///    and a user preset file declare it), return
    ///    [`PresetError::ShadowedName`] naming the user file. D-3 is
    ///    emphatic that user files cannot override built-ins.
    /// 2. Otherwise return the matching built-in if any — built-ins
    ///    win in the absence of a conflict.
    /// 3. Otherwise return the matching user preset if any.
    /// 4. Otherwise [`PresetError::UnknownPreset`].
    ///
    /// The returned user preset is cloned; built-ins are returned by
    /// `&'static` reference.
    pub fn find(&self, name: &str) -> Result<Preset, PresetError> {
        if let Some(user_path) = self.shadow_conflicts.get(name) {
            return Err(PresetError::ShadowedName {
                name: name.to_string(),
                user_path: user_path.clone(),
            });
        }
        if let Some(b) = self.builtins.iter().find(|b| b.name == name) {
            return Ok(Preset::Builtin(b));
        }
        if let Some(u) = self.users.iter().find(|u| u.name == name) {
            return Ok(Preset::User(u.clone()));
        }
        Err(PresetError::UnknownPreset(name.to_string()))
    }

    /// Enumerate every preset in the catalog, sorted alphabetically by
    /// name.
    ///
    /// Used by `sandbox policy preset list` (Phase 5b).
    pub fn list(&self) -> Vec<PresetSummary> {
        let mut out: Vec<PresetSummary> = self
            .builtins
            .iter()
            .map(|b| PresetSummary {
                name: b.name.to_string(),
                source: PresetSource::Builtin,
                description: Some(b.description.to_string()),
            })
            .chain(self.users.iter().map(|u| PresetSummary {
                name: u.name.clone(),
                source: PresetSource::User {
                    path: u.source_path.clone(),
                },
                description: u.description.clone(),
            }))
            .collect();
        out.sort_by(|a, b| a.name.cmp(&b.name));
        out
    }
}

/// A single row in `sandbox policy preset list` output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PresetSummary {
    pub name: String,
    pub source: PresetSource,
    pub description: Option<String>,
}

/// Whether a preset row was sourced from a compiled-in built-in or a
/// user file on disk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PresetSource {
    Builtin,
    User { path: PathBuf },
}

/// Identifies the origin of a rule that contributed to a merged effective
/// policy. Used in [`PresetError::DuplicateDestination`] source lines
/// (D-4) so the operator can see every contributing source by name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuleSource {
    /// The rule came from the operator's `--policy <path>` file.
    PolicyFile { path: PathBuf },
    /// The rule came from a built-in preset (e.g. `github`).
    Builtin { name: String, invocation: String },
    /// The rule came from a user-configured preset file.
    UserPreset {
        name: String,
        invocation: String,
        path: PathBuf,
    },
}

impl fmt::Display for RuleSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RuleSource::PolicyFile { path } => {
                write!(f, "declared by policy file {}", path.display())
            }
            RuleSource::Builtin { name, invocation } => write!(
                f,
                "declared by preset invocation '{invocation}' (built-in '{name}')"
            ),
            RuleSource::UserPreset {
                invocation, path, ..
            } => write!(
                f,
                "declared by preset invocation '{invocation}' (user preset {})",
                path.display()
            ),
        }
    }
}

/// Payload for [`PresetError::DuplicateDestination`].
///
/// Kept as a separate struct so the error enum itself stays compact
/// (clippy's `result_large_err` lint). The field set mirrors the D-4
/// scaffold verbatim; Phase 4's merge logic constructs these and
/// [`PresetError::DuplicateDestination`] wraps each one in a `Box`.
#[derive(Debug, Clone)]
pub struct DuplicateDestination {
    pub host: String,
    pub port: u16,
    pub source_a: RuleSource,
    pub source_b: RuleSource,
}

/// All errors the preset subsystem can produce.
///
/// Variants are CLI-only: they map to `eprintln!` + `process::exit(1)`
/// at the top level, never to HTTP responses (the daemon has no preset
/// awareness).
#[derive(Debug)]
pub enum PresetError {
    /// `--preset 'foo:'` where `foo` is neither a built-in nor a user
    /// preset.
    UnknownPreset(String),

    /// A user-configured preset shadows a compile-time built-in. D-3
    /// makes this a hard error at invocation time — user configs cannot
    /// override built-ins.
    ShadowedName {
        name: String,
        /// Absolute path of the user preset file that attempted the
        /// shadow.
        user_path: PathBuf,
    },

    /// The invocation string could not be structurally parsed
    /// (missing `:`, empty name, param without `=`, empty key, …).
    MalformedInvocation { raw: String, reason: String },

    /// A param value contained one of the reserved characters `,`,
    /// `:`, or `=` (D-2 — no escape mechanism is supported).
    ForbiddenChar {
        preset: String,
        key: String,
        value: String,
        ch: char,
    },

    /// Two or more rules (across policy file + preset expansions) claim
    /// the same `(host, port)` identity. D-4 mandates that every
    /// contributing source is named in the error output. The actual
    /// merge logic that raises this variant lives in Phase 4; Phase 1
    /// defines the shape.
    ///
    /// Payload is boxed to keep the enum small — the primary `Result`
    /// path (parser / catalog lookup) is hot; this variant is
    /// error-only and cold.
    DuplicateDestination(Box<DuplicateDestination>),

    /// A built-in preset whose expander has not been implemented yet.
    /// Phase 1 seeds every built-in's `expand` fn pointer with this
    /// error; Phase 3 replaces each one with the real body.
    NotImplemented { name: String },

    /// Two user preset files in the XDG preset directory declare the
    /// same `name`. This is a hard error (not warn-and-skip) — silent
    /// skipping would let whichever file won the directory-iteration
    /// race determine the preset bodies, which is exactly the class of
    /// "explicit everything" bug the M10-S5 design exists to prevent.
    DuplicateUserPresetName {
        name: String,
        path_a: PathBuf,
        path_b: PathBuf,
    },

    /// A user preset file declared more than one `repeatable: true`
    /// param. Spec Part 2 lines 601-607 reserve multi-repeatable
    /// semantics for built-ins (the paired `repo=`/`pr=` shape of
    /// `github-pr`) because the CLI needs hand-written pairing logic
    /// that a JSON template cannot express.
    TooManyRepeatableParams { path: PathBuf, count: usize },

    /// An invocation omitted a parameter declared `required: true`.
    /// Raised by the user-preset expander and by parameterized
    /// built-ins (`github-repo`, `github-pr`) in Phase 3b.
    MissingRequiredParam { preset: String, param: String },

    /// A user preset's rule template references a `${param}` name
    /// that is not in the preset's declared `params` list, or an
    /// invocation carried an unknown param key.
    UnknownParamRef { preset: String, ref_name: String },
}

impl fmt::Display for PresetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PresetError::UnknownPreset(name) => {
                write!(f, "unknown preset '{name}'")
            }
            PresetError::ShadowedName { name, user_path } => write!(
                f,
                "preset '{name}' is defined by both a built-in and a user file at\n  {}\nuser presets cannot shadow built-ins; rename or delete the user file.",
                user_path.display()
            ),
            PresetError::MalformedInvocation { raw, reason } => {
                write!(f, "malformed preset invocation '{raw}': {reason}")
            }
            PresetError::ForbiddenChar {
                preset,
                key,
                value,
                ch,
            } => write!(
                f,
                "preset '{preset}': param '{key}={value}' contains forbidden character '{ch}' in value; preset params must not contain , : or ="
            ),
            PresetError::DuplicateDestination(dup) => {
                let DuplicateDestination {
                    host,
                    port,
                    source_a,
                    source_b,
                } = dup.as_ref();
                write!(
                    f,
                    "policy validation failed: duplicate destination ({host}, {port})\n  - {source_a}\n  - {source_b}"
                )
            }
            PresetError::NotImplemented { name } => {
                write!(f, "preset '{name}' expander is not implemented yet")
            }
            PresetError::DuplicateUserPresetName {
                name,
                path_a,
                path_b,
            } => write!(
                f,
                "preset '{name}' is defined by two user files:\n  - {}\n  - {}\nrename or delete one of them.",
                path_a.display(),
                path_b.display()
            ),
            PresetError::TooManyRepeatableParams { path, count } => write!(
                f,
                "user preset file {} declares {count} repeatable params; \
                 at most one is allowed (the built-in 'github-pr' is the only \
                 multi-repeatable shape supported, and it lives in CLI code)",
                path.display()
            ),
            PresetError::MissingRequiredParam { preset, param } => {
                write!(f, "preset '{preset}': missing required param '{param}'")
            }
            PresetError::UnknownParamRef { preset, ref_name } => write!(
                f,
                "preset '{preset}': rule template references unknown param '${{{ref_name}}}'"
            ),
        }
    }
}

impl std::error::Error for PresetError {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use std::io::Write;
    use tempfile::TempDir;

    /// Build an empty-but-existent XDG preset override directory so
    /// `Catalog::load` is hermetic with respect to the host
    /// `$XDG_CONFIG_HOME` / `$HOME`. Returned `TempDir` lives as long
    /// as the caller keeps the binding alive.
    fn empty_xdg_override() -> TempDir {
        TempDir::new().expect("tempdir")
    }

    /// Write a user preset file into the override dir.
    fn write_user_preset(dir: &Path, filename: &str, body: &str) -> PathBuf {
        let path = dir.join(filename);
        let mut f = File::create(&path).expect("create user preset file");
        f.write_all(body.as_bytes())
            .expect("write user preset body");
        path
    }

    #[test]
    fn find_unknown_preset_returns_unknown_preset_error() {
        let xdg = empty_xdg_override();
        let catalog = Catalog::load(Some(xdg.path())).expect("empty dir loads clean");
        let err = catalog.find("does-not-exist").expect_err("should fail");
        match err {
            PresetError::UnknownPreset(name) => assert_eq!(name, "does-not-exist"),
            other => panic!("expected UnknownPreset, got {other:?}"),
        }
    }

    #[test]
    fn find_known_builtin_returns_builtin_variant() {
        let xdg = empty_xdg_override();
        let catalog = Catalog::load(Some(xdg.path())).expect("empty dir loads clean");
        let preset = catalog.find("npm").expect("npm is a scaffolded built-in");
        assert!(matches!(preset, Preset::Builtin(_)));
        assert_eq!(preset.name(), "npm");
    }

    #[test]
    fn list_includes_all_eleven_builtins_sorted() {
        let xdg = empty_xdg_override();
        let catalog = Catalog::load(Some(xdg.path())).expect("empty dir loads clean");
        let summaries = catalog.list();
        // Phase 2 still ships only 11 built-ins (no user presets in
        // the empty override dir).
        assert_eq!(summaries.len(), 11);
        // Alphabetical sort.
        let names: Vec<&str> = summaries.iter().map(|s| s.name.as_str()).collect();
        let mut sorted = names.clone();
        sorted.sort();
        assert_eq!(names, sorted);
        // Every row is a built-in (no user presets in the empty
        // override).
        for s in &summaries {
            assert_eq!(s.source, PresetSource::Builtin);
        }
    }

    #[test]
    fn find_shadowed_name_returns_shadowed_error_with_user_path() {
        // A user file named `npm.json` tries to shadow the built-in
        // `npm`. Per D-3 this is an invocation-time hard error.
        let xdg = empty_xdg_override();
        let body = r#"{
            "name": "npm",
            "description": "internal override",
            "params": [],
            "rules": []
        }"#;
        let user_path = write_user_preset(xdg.path(), "npm.json", body);
        let catalog = Catalog::load(Some(xdg.path())).expect("load succeeds; shadow is deferred");

        let err = catalog.find("npm").expect_err("shadowed name must error");
        match err {
            PresetError::ShadowedName {
                name,
                user_path: got,
            } => {
                assert_eq!(name, "npm");
                assert_eq!(got, user_path);
            }
            other => panic!("expected ShadowedName, got {other:?}"),
        }

        // A non-shadowed built-in is unaffected by the latent shadow.
        let pypi = catalog.find("pypi").expect("pypi remains reachable");
        assert!(matches!(pypi, Preset::Builtin(_)));
    }

    #[test]
    fn find_non_shadowed_user_preset_returns_user_variant() {
        let xdg = empty_xdg_override();
        let body = r#"{
            "name": "my-internal",
            "description": "internal thing",
            "params": [
                {"name": "env", "type": "string", "required": true, "repeatable": false}
            ],
            "rules": [
                {
                    "host": "api.${env}.internal",
                    "port": 443,
                    "protocol": "tcp",
                    "level": "tls"
                }
            ]
        }"#;
        write_user_preset(xdg.path(), "my-internal.json", body);
        let catalog = Catalog::load(Some(xdg.path())).expect("load succeeds");

        let preset = catalog
            .find("my-internal")
            .expect("user preset should resolve when not shadowing");
        match preset {
            Preset::User(u) => {
                assert_eq!(u.name, "my-internal");
                assert_eq!(u.description.as_deref(), Some("internal thing"));
                assert_eq!(u.rules.len(), 1);
            }
            other => panic!("expected User variant, got {other:?}"),
        }
    }

    #[test]
    fn list_includes_user_presets() {
        let xdg = empty_xdg_override();
        let body = r#"{
            "name": "my-internal",
            "description": "internal thing",
            "params": [],
            "rules": []
        }"#;
        let user_path = write_user_preset(xdg.path(), "my-internal.json", body);
        let catalog = Catalog::load(Some(xdg.path())).expect("load succeeds");

        let summaries = catalog.list();
        assert_eq!(summaries.len(), 12, "11 built-ins + 1 user preset");
        let user_summary = summaries
            .iter()
            .find(|s| s.name == "my-internal")
            .expect("user preset must appear in list");
        assert_eq!(
            user_summary.source,
            PresetSource::User {
                path: user_path.clone()
            }
        );
        assert_eq!(user_summary.description.as_deref(), Some("internal thing"));
    }

    #[test]
    fn forbidden_char_display_matches_spec_verbatim() {
        // D-2 prescribes the exact wording.
        let err = PresetError::ForbiddenChar {
            preset: "github-repo".to_string(),
            key: "repo".to_string(),
            value: "foo/bar:extra".to_string(),
            ch: ':',
        };
        assert_eq!(
            err.to_string(),
            "preset 'github-repo': param 'repo=foo/bar:extra' contains forbidden character ':' in value; preset params must not contain , : or ="
        );
    }

    #[test]
    fn duplicate_destination_display_matches_spec_verbatim() {
        // Part 1 / lines 140-150 prescribe the exact wording. Two
        // source types exercised here: policy file path and built-in
        // preset invocation.
        let err = PresetError::DuplicateDestination(Box::new(DuplicateDestination {
            host: "api.github.com".to_string(),
            port: 443,
            source_a: RuleSource::Builtin {
                name: "github".to_string(),
                invocation: "github:".to_string(),
            },
            source_b: RuleSource::PolicyFile {
                path: PathBuf::from("/path/to/policy.json"),
            },
        }));
        assert_eq!(
            err.to_string(),
            "policy validation failed: duplicate destination (api.github.com, 443)\n  - declared by preset invocation 'github:' (built-in 'github')\n  - declared by policy file /path/to/policy.json"
        );
    }

    #[test]
    fn shadowed_name_display_matches_spec_verbatim() {
        let err = PresetError::ShadowedName {
            name: "npm".to_string(),
            user_path: PathBuf::from("/home/alice/.config/sandboxd/presets/npm.json"),
        };
        assert_eq!(
            err.to_string(),
            "preset 'npm' is defined by both a built-in and a user file at\n  /home/alice/.config/sandboxd/presets/npm.json\nuser presets cannot shadow built-ins; rename or delete the user file."
        );
    }

    #[test]
    fn duplicate_user_preset_name_display_names_both_paths() {
        let err = PresetError::DuplicateUserPresetName {
            name: "samename".to_string(),
            path_a: PathBuf::from("/etc/sandboxd/presets/a.json"),
            path_b: PathBuf::from("/etc/sandboxd/presets/b.json"),
        };
        assert_eq!(
            err.to_string(),
            "preset 'samename' is defined by two user files:\n  - /etc/sandboxd/presets/a.json\n  - /etc/sandboxd/presets/b.json\nrename or delete one of them."
        );
    }

    #[test]
    fn too_many_repeatable_params_display_names_file_and_count() {
        let err = PresetError::TooManyRepeatableParams {
            path: PathBuf::from("/etc/sandboxd/presets/x.json"),
            count: 3,
        };
        let rendered = err.to_string();
        assert!(rendered.contains("/etc/sandboxd/presets/x.json"));
        assert!(rendered.contains("3 repeatable params"));
        assert!(rendered.contains("at most one is allowed"));
    }
}
