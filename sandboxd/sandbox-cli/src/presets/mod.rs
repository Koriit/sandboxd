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
//! # Phase 1 scope
//!
//! This module in M10-S5 Phase 1 is scaffolding only:
//!
//! - The [`Preset`] enum distinguishes [`BuiltinPreset`]s (compiled-in)
//!   from [`UserPreset`]s (loaded from `$XDG_CONFIG_HOME/sandboxd/presets/`).
//!   The split lets the shadowing check in Phase 2 be a trivial type
//!   discrimination.
//! - The [`Catalog`] composes both sources and exposes a read-only
//!   lookup surface (`find`, `list`). Its [`Catalog::load`] is a no-op
//!   stub in Phase 1 — the XDG loader lands in Phase 2.
//! - Each [`BuiltinPreset`] carries an `expand` function pointer so that
//!   each built-in can implement its own expansion logic (trivial for
//!   `npm` / `pypi` / …, non-trivial for `github-repo` / `github-pr`).
//!   Phase 1 wires every expander to return
//!   [`PresetError::NotImplemented`]; real bodies land in Phase 3.
//! - The [`PresetError`] hierarchy is exhaustive at scaffolding time so
//!   that Phases 2–6 can attach to existing variants rather than
//!   growing the enum. Every variant has a `Display` impl that matches
//!   the exact wording called out in the spec and Phase 0 decisions.

// Phase 1 of M10-S5 ships the type and parser surface but no call
// sites inside the binary (the `--preset` flag and the `sandbox policy
// preset` subcommand land in Phase 5).  Silence the transitive
// dead-code and unused-import warnings inside the module rather than
// sprinkling fine-grained attributes across every item.  Remove this
// allow when Phase 5 wires the surface into `main.rs`.
#![allow(dead_code)]
#![allow(unused_imports)]

use std::fmt;
use std::path::{Path, PathBuf};

pub mod builtin;
pub mod param;

// Re-export the public surface callers are expected to use in Phase 5.
pub use builtin::{BUILTINS, BuiltinPreset};
pub use param::ParsedInvocation;

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

/// A user-configured preset loaded from
/// `$XDG_CONFIG_HOME/sandboxd/presets/<name>.json`.
///
/// Phase 1 defines the minimal shape. The Phase 2 XDG loader will
/// populate these from disk; the raw `rules` blob (kept as
/// `serde_json::Value`) is template-substituted at expand time in
/// Phase 3.
#[derive(Debug, Clone)]
pub struct UserPreset {
    /// Preset name (validated DNS-safe by the Phase 2 loader).
    pub name: String,
    /// Optional human-readable description.
    pub description: Option<String>,
    /// Raw `rules` JSON from the user file, retained verbatim so the
    /// Phase 3 expander can template-substitute `${param}` references
    /// in string positions before deserializing into [`sandbox_core::PolicyRule`]s.
    pub rules: serde_json::Value,
    /// Absolute path of the file this preset was loaded from.
    /// Load-bearing for shadowing and duplicate-source error messages.
    pub source_path: PathBuf,
}

/// In-memory index of all presets available to the running CLI
/// invocation.
#[derive(Debug)]
pub struct Catalog {
    /// Compile-time built-in presets.
    builtins: &'static [BuiltinPreset],
    /// User-configured presets loaded from the XDG presets dir.
    /// Phase 1: always empty (loader lands in Phase 2).
    users: Vec<UserPreset>,
}

impl Catalog {
    /// Load the catalog, merging built-ins with user-configured presets.
    ///
    /// `cli_xdg_override` is a test hook that the Phase 2 XDG loader
    /// will honor (lets unit tests point at a tempdir instead of the
    /// real `$XDG_CONFIG_HOME`). Phase 1's implementation ignores the
    /// argument — the loader itself is scheduled for Phase 2.
    pub fn load(cli_xdg_override: Option<&Path>) -> Self {
        // TODO(M10-S5 Phase 2): XDG loader — populate `users` from
        // `$XDG_CONFIG_HOME/sandboxd/presets/*.json`, honoring the
        // `cli_xdg_override` test hook and the
        // `$HOME/.config/sandboxd/presets/` fallback.
        let _ = cli_xdg_override;
        Catalog {
            builtins: BUILTINS,
            users: Vec::new(),
        }
    }

    /// Look up a preset by name.
    ///
    /// Resolution:
    /// - If the name exists as both a built-in and a user preset, this
    ///   is a shadow error (D-3) regardless of any other consideration.
    /// - Otherwise return the single matching preset.
    /// - If no match exists, return [`PresetError::UnknownPreset`].
    ///
    /// The returned user preset is cloned; built-ins are returned by
    /// `&'static` reference.  Phase 1 has no user presets in play (the
    /// XDG loader lands in Phase 2), so the clone cost is moot.
    pub fn find(&self, name: &str) -> Result<Preset, PresetError> {
        let user = self.users.iter().find(|u| u.name == name);
        let builtin = self.builtins.iter().find(|b| b.name == name);

        match (builtin, user) {
            (Some(_), Some(u)) => Err(PresetError::ShadowedName {
                name: name.to_string(),
                user_path: u.source_path.clone(),
            }),
            (Some(b), None) => Ok(Preset::Builtin(b)),
            (None, Some(u)) => Ok(Preset::User(u.clone())),
            (None, None) => Err(PresetError::UnknownPreset(name.to_string())),
        }
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
        }
    }
}

impl std::error::Error for PresetError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn find_unknown_preset_returns_unknown_preset_error() {
        let catalog = Catalog::load(None);
        let err = catalog.find("does-not-exist").expect_err("should fail");
        match err {
            PresetError::UnknownPreset(name) => assert_eq!(name, "does-not-exist"),
            other => panic!("expected UnknownPreset, got {other:?}"),
        }
    }

    #[test]
    fn find_known_builtin_returns_builtin_variant() {
        let catalog = Catalog::load(None);
        let preset = catalog.find("npm").expect("npm is a scaffolded built-in");
        assert!(matches!(preset, Preset::Builtin(_)));
        assert_eq!(preset.name(), "npm");
    }

    #[test]
    fn list_includes_all_eleven_builtins_sorted() {
        let catalog = Catalog::load(None);
        let summaries = catalog.list();
        // Phase 1 ships 11 built-ins (no user presets).
        assert_eq!(summaries.len(), 11);
        // Alphabetical sort.
        let names: Vec<&str> = summaries.iter().map(|s| s.name.as_str()).collect();
        let mut sorted = names.clone();
        sorted.sort();
        assert_eq!(names, sorted);
        // Every row is a built-in (no user presets in Phase 1).
        for s in &summaries {
            assert_eq!(s.source, PresetSource::Builtin);
        }
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
}
