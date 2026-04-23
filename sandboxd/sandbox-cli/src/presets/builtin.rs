//! Compile-time catalog of built-in presets.
//!
//! In M10-S5 Phase 1 this is scaffolding only: each [`BuiltinPreset`]
//! carries metadata (`name`, `description`) plus an `expand` function
//! pointer that currently returns [`PresetError::NotImplemented`].
//! Real expansion bodies land in Phase 3 (per the plan at
//! `.tasks/handoffs/20260423-m10-s5-implementation-plan.md` §
//! "Phase 3 — Built-in presets: definitions, method-filter split,
//! expansion").
//!
//! The 11 entries mirror Part 2 of the spec
//! (`.tasks/specs/2026-04-21-port-explicit-policies-presets-observability-design.md`
//! lines 428-444 for unparameterized presets and 494-568 for the
//! parameterized GitHub presets). The `github` preset unifies the two
//! rows in the spec's table (interactive hosts + asset CDN) under a
//! single preset name — both groups are expanded together at Phase 3.

use sandbox_core::PolicyRule;

use super::PresetError;
use super::param::ParsedInvocation;

/// A compile-time built-in preset.
///
/// The `expand` field is a function pointer rather than a trait object
/// so the whole struct can live in a `static` array without heap
/// allocation or dyn-dispatch overhead. Each built-in has its own
/// expander in Phase 3 — some are trivial (`npm` just emits one rule
/// per host) and some are not (`github-repo` fans out over a
/// repeatable `repo=` param).
#[derive(Debug)]
pub struct BuiltinPreset {
    /// Name typed before the `:` in a `--preset` invocation.
    pub name: &'static str,
    /// Short human-readable description for
    /// `sandbox policy preset list` / `show` output.
    pub description: &'static str,
    /// Expansion entrypoint. Returns the full set of [`PolicyRule`]s
    /// this preset contributes to the effective policy, or a
    /// [`PresetError`] (for parameter-validation failures such as
    /// `github-pr` receiving unequal counts of `repo=` and `pr=`).
    pub expand: fn(&ParsedInvocation) -> Result<Vec<PolicyRule>, PresetError>,
}

// ---------------------------------------------------------------------------
// Placeholder expanders.
//
// Each function below is a Phase 1 stub returning `NotImplemented`.
// Phase 3 replaces these with real bodies.  They live as named
// functions (not inline closures) so the Phase 3 diff is a body swap
// per preset rather than a restructure of the whole array.
// ---------------------------------------------------------------------------

fn not_implemented(name: &'static str) -> PresetError {
    PresetError::NotImplemented {
        name: name.to_string(),
    }
}

fn expand_npm(_inv: &ParsedInvocation) -> Result<Vec<PolicyRule>, PresetError> {
    // TODO(M10-S5 Phase 3): emit the `registry.npmjs.org:443 tcp http`
    // rule with `GET /**` + `HEAD /**` filters.
    Err(not_implemented("npm"))
}

fn expand_pypi(_inv: &ParsedInvocation) -> Result<Vec<PolicyRule>, PresetError> {
    // TODO(M10-S5 Phase 3): emit `pypi.org:443` + `files.pythonhosted.org:443`
    // tcp http rules with GET/HEAD filters.
    Err(not_implemented("pypi"))
}

fn expand_cargo(_inv: &ParsedInvocation) -> Result<Vec<PolicyRule>, PresetError> {
    // TODO(M10-S5 Phase 3): emit crates.io + index.crates.io rules.
    // TODO(M10-S5 Phase 5a'): verify static.crates.io empirically
    // against a live `cargo fetch` run (D-9).
    Err(not_implemented("cargo"))
}

fn expand_goproxy(_inv: &ParsedInvocation) -> Result<Vec<PolicyRule>, PresetError> {
    // TODO(M10-S5 Phase 3): proxy.golang.org + sum.golang.org.
    Err(not_implemented("goproxy"))
}

fn expand_maven(_inv: &ParsedInvocation) -> Result<Vec<PolicyRule>, PresetError> {
    // TODO(M10-S5 Phase 3): repo1.maven.org + repo.maven.apache.org.
    Err(not_implemented("maven"))
}

fn expand_gradle(_inv: &ParsedInvocation) -> Result<Vec<PolicyRule>, PresetError> {
    // TODO(M10-S5 Phase 3): plugins.gradle.org, services.gradle.org,
    // downloads.gradle.org.
    Err(not_implemented("gradle"))
}

fn expand_dockerhub(_inv: &ParsedInvocation) -> Result<Vec<PolicyRule>, PresetError> {
    // TODO(M10-S5 Phase 3): registry-1.docker.io, auth.docker.io,
    // production.cloudflare.docker.com.
    Err(not_implemented("dockerhub"))
}

fn expand_github(_inv: &ParsedInvocation) -> Result<Vec<PolicyRule>, PresetError> {
    // TODO(M10-S5 Phase 3): two logical groups merged into one preset
    // (spec lines 442-443):
    //   - interactive hosts: github.com, api.github.com — ANY /**
    //   - asset CDN:         codeload.github.com,
    //                        objects.githubusercontent.com,
    //                        raw.githubusercontent.com,
    //                        release-assets.githubusercontent.com
    //                        — GET /**, HEAD /**
    Err(not_implemented("github"))
}

fn expand_github_repo(_inv: &ParsedInvocation) -> Result<Vec<PolicyRule>, PresetError> {
    // TODO(M10-S5 Phase 3): parameterized preset over repeatable
    // `repo=owner/name`.  Validates each value against
    // `^[A-Za-z0-9._-]+/[A-Za-z0-9._-]+$`, substitutes `${repo}` into
    // the spec's path templates (lines 507-524), and stacks multiple
    // repos into the same per-host rule's `http_filters` array.
    Err(not_implemented("github-repo"))
}

fn expand_github_pr(_inv: &ParsedInvocation) -> Result<Vec<PolicyRule>, PresetError> {
    // TODO(M10-S5 Phase 3): paired repeatable `repo=owner/name` +
    // `pr=N` params.  `pr` must be a positive integer.  `len(repo) ==
    // len(pr)` is required.  Emits api.github.com + github.com rules
    // scoped to `/repos/${repo}/pulls/${pr}/**` + sibling paths.
    Err(not_implemented("github-pr"))
}

fn expand_github_interactive(_inv: &ParsedInvocation) -> Result<Vec<PolicyRule>, PresetError> {
    // TODO(M10-S5 Phase 3): reserved preset slot for the interactive
    // GitHub surface.  Spec Part 2 lines 442-443 merge this under the
    // plain `github` name; we keep a separate `github-interactive`
    // entry here so operators can opt into just the interactive
    // subset in a future revision without reshaping the built-in
    // array.  The Phase 1 plan explicitly lists this as one of the
    // eleven entries.
    Err(not_implemented("github-interactive"))
}

/// The compile-time list of built-in presets shipped with this CLI.
///
/// Ordering is deliberate — ecosystem presets first (alphabetical-ish
/// by common usage), then the GitHub family. The `sandbox policy
/// preset list` subcommand sorts alphabetically on its own (see
/// [`super::Catalog::list`]); this array's order does not leak to the
/// user.
pub const BUILTINS: &[BuiltinPreset] = &[
    // ----- Unparameterized ecosystem presets (spec lines 428-444) ----
    BuiltinPreset {
        name: "npm",
        description: "Allow npm registry reads (registry.npmjs.org).",
        expand: expand_npm,
    },
    BuiltinPreset {
        name: "pypi",
        description: "Allow PyPI package downloads (pypi.org, files.pythonhosted.org).",
        expand: expand_pypi,
    },
    BuiltinPreset {
        name: "cargo",
        description: "Allow crates.io fetches (crates.io, index.crates.io, static.crates.io).",
        expand: expand_cargo,
    },
    BuiltinPreset {
        name: "goproxy",
        description: "Allow Go module proxy fetches (proxy.golang.org, sum.golang.org).",
        expand: expand_goproxy,
    },
    BuiltinPreset {
        name: "maven",
        description: "Allow Maven Central downloads (repo1.maven.org, repo.maven.apache.org).",
        expand: expand_maven,
    },
    BuiltinPreset {
        name: "gradle",
        description: "Allow Gradle plugin and distribution downloads.",
        expand: expand_gradle,
    },
    BuiltinPreset {
        name: "dockerhub",
        description: "Allow Docker Hub image pulls (registry-1.docker.io and friends).",
        expand: expand_dockerhub,
    },
    // ----- GitHub family (spec lines 442-568) ------------------------
    BuiltinPreset {
        name: "github",
        description: "Allow broad GitHub access (github.com, api.github.com interactive + asset CDN).",
        expand: expand_github,
    },
    BuiltinPreset {
        name: "github-repo",
        description: "Allow narrow GitHub access scoped to one or more repos (param: repo=owner/name).",
        expand: expand_github_repo,
    },
    BuiltinPreset {
        name: "github-pr",
        description: "Allow GitHub access scoped to specific pull requests (params: repo=owner/name, pr=N).",
        expand: expand_github_pr,
    },
    BuiltinPreset {
        name: "github-interactive",
        description: "Allow only the interactive GitHub surfaces (github.com, api.github.com) with ANY /**.",
        expand: expand_github_interactive,
    },
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builtins_has_eleven_entries() {
        assert_eq!(BUILTINS.len(), 11);
    }

    #[test]
    fn builtin_names_are_unique() {
        let mut names: Vec<&str> = BUILTINS.iter().map(|b| b.name).collect();
        names.sort();
        let before = names.len();
        names.dedup();
        assert_eq!(
            before,
            names.len(),
            "duplicate preset name in BUILTINS: {names:?}"
        );
    }

    #[test]
    fn every_expander_returns_not_implemented_in_phase_1() {
        // Sanity: Phase 1 ships no preset bodies.  Any expander that
        // does anything other than `NotImplemented` is a Phase 3 leak.
        for preset in BUILTINS {
            let inv = ParsedInvocation::parse(&format!("{}:", preset.name))
                .expect("scaffolded builtin name should parse");
            let err = (preset.expand)(&inv).expect_err("phase 1 expanders are stubs");
            match err {
                PresetError::NotImplemented { name } => assert_eq!(name, preset.name),
                other => panic!(
                    "preset '{}' returned unexpected error {other:?}",
                    preset.name
                ),
            }
        }
    }
}
