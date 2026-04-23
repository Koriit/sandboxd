//! Compile-time catalog of built-in presets.
//!
//! Each [`BuiltinPreset`] carries metadata (`name`, `description`)
//! plus an `expand` function pointer that materialises the preset's
//! contribution to the effective policy as a `Vec<PolicyRule>`.
//!
//! Ordering of entries in this array is not user-visible
//! ([`super::Catalog::list`] sorts alphabetically); it is kept in
//! "ecosystem presets then GitHub family" order here only for
//! readability during review.
//!
//! # Relationship to the spec
//!
//! The 11 entries mirror Part 2 of the spec at
//! `.tasks/specs/2026-04-21-port-explicit-policies-presets-observability-design.md`
//! lines 428-568. The plain `github` preset unifies the two rows in
//! the spec's table (interactive hosts + asset CDN) under a single
//! preset name; `github-interactive` narrows that to the interactive
//! subset only for operators who want the plain `github` preset's
//! interactive posture without the asset-CDN surface.
//!
//! # Determinism
//!
//! Every expander returns rules in a fixed, source-order sequence
//! (the literal order of host entries in this file). Phase 4's merge
//! pass depends on this being stable so `(host, port)` collision
//! errors are reproducible across runs.
//!
//! # Phase 3 status
//!
//! This commit (Phase 3a) ships the seven consume-only presets plus
//! the mixed-posture `github` preset and its narrow `github-interactive`
//! alias. The parameterized `github-repo` and `github-pr` presets
//! remain stubbed with [`PresetError::NotImplemented`]; Phase 3b
//! (the next commit) replaces those stubs with full bodies.

use sandbox_core::{AssuranceLevel, Destination, HttpFilter, HttpMethod, PolicyRule, Protocol};

use super::PresetError;
use super::method;
use super::param::ParsedInvocation;

// ---------------------------------------------------------------------------
// BuiltinPreset struct + BUILTINS array
// ---------------------------------------------------------------------------

/// A compile-time built-in preset.
///
/// The `expand` field is a function pointer rather than a trait object
/// so the whole struct can live in a `static` array without heap
/// allocation or dyn-dispatch overhead. Each built-in has its own
/// expander — some are trivial (`npm` just emits one rule per host)
/// and some are not (`github-repo` fans out over a repeatable `repo=`
/// param).
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

// ---------------------------------------------------------------------------
// PolicyRule constructors (internal helpers)
//
// Every preset emits one `PolicyRule` per host (Part 1 uniqueness),
// so the per-host constructors live as tiny helpers to keep the
// expanders readable and ensure `port`, `protocol`, and `reason`
// defaults stay in one place.
// ---------------------------------------------------------------------------

/// Build an `http`-level rule for `(host, 443, tcp)` with the given
/// method-filter set.
fn http_rule(host: &str, filters: Vec<HttpFilter>) -> PolicyRule {
    PolicyRule {
        host: Destination::Domain(host.to_string()),
        port: 443,
        protocol: Protocol::Tcp,
        reason: None,
        level: AssuranceLevel::Http {
            http_filters: filters,
        },
    }
}

/// Emit one `http`-level rule per host in `hosts`, all sharing the
/// same method-filter shape. Used by every consume-only preset and
/// by the asset-CDN half of `github:`.
fn consume_rules(hosts: &[&str]) -> Vec<PolicyRule> {
    hosts
        .iter()
        .map(|host| http_rule(host, method::get_head()))
        .collect()
}

// ---------------------------------------------------------------------------
// Unparameterized ecosystem presets (spec lines 428-444)
// ---------------------------------------------------------------------------

fn expand_npm(_inv: &ParsedInvocation) -> Result<Vec<PolicyRule>, PresetError> {
    Ok(consume_rules(&["registry.npmjs.org"]))
}

fn expand_pypi(_inv: &ParsedInvocation) -> Result<Vec<PolicyRule>, PresetError> {
    Ok(consume_rules(&["pypi.org", "files.pythonhosted.org"]))
}

fn expand_cargo(_inv: &ParsedInvocation) -> Result<Vec<PolicyRule>, PresetError> {
    // TODO(M10-S5 Phase 5a): empirical verification per D-9. The spec
    // (line 437) marks `static.crates.io` as "pending empirical
    // verification"; Phase 5a will either confirm or trim this list
    // against a live `cargo fetch` trace and commit a fixture.
    Ok(consume_rules(&[
        "crates.io",
        "index.crates.io",
        "static.crates.io",
    ]))
}

fn expand_goproxy(_inv: &ParsedInvocation) -> Result<Vec<PolicyRule>, PresetError> {
    Ok(consume_rules(&["proxy.golang.org", "sum.golang.org"]))
}

fn expand_maven(_inv: &ParsedInvocation) -> Result<Vec<PolicyRule>, PresetError> {
    Ok(consume_rules(&["repo1.maven.org", "repo.maven.apache.org"]))
}

fn expand_gradle(_inv: &ParsedInvocation) -> Result<Vec<PolicyRule>, PresetError> {
    Ok(consume_rules(&[
        "plugins.gradle.org",
        "services.gradle.org",
        "downloads.gradle.org",
    ]))
}

fn expand_dockerhub(_inv: &ParsedInvocation) -> Result<Vec<PolicyRule>, PresetError> {
    Ok(consume_rules(&[
        "registry-1.docker.io",
        "auth.docker.io",
        "production.cloudflare.docker.com",
    ]))
}

// ---------------------------------------------------------------------------
// github (unparameterized, mixed-posture; spec lines 442-443)
// ---------------------------------------------------------------------------

/// Interactive GitHub hosts — accept `ANY /**` because legitimate
/// workflows (push, REST API writes, OAuth) routinely POST.
const GITHUB_INTERACTIVE_HOSTS: &[&str] = &["github.com", "api.github.com"];

/// GitHub asset-CDN hosts — read-only posture (`GET /**`, `HEAD /**`).
/// No legitimate workflow POSTs to a tarball or raw-file CDN.
const GITHUB_ASSET_CDN_HOSTS: &[&str] = &[
    "codeload.github.com",
    "objects.githubusercontent.com",
    "raw.githubusercontent.com",
    "release-assets.githubusercontent.com",
];

fn expand_github(_inv: &ParsedInvocation) -> Result<Vec<PolicyRule>, PresetError> {
    let mut rules =
        Vec::with_capacity(GITHUB_INTERACTIVE_HOSTS.len() + GITHUB_ASSET_CDN_HOSTS.len());
    for host in GITHUB_INTERACTIVE_HOSTS {
        rules.push(http_rule(host, method::any_all_paths()));
    }
    for host in GITHUB_ASSET_CDN_HOSTS {
        rules.push(http_rule(host, method::get_head()));
    }
    Ok(rules)
}

/// Interactive subset only: `github.com` + `api.github.com` with
/// `ANY /**`. Useful as a narrow alternative to the plain `github`
/// preset when the operator does not want the asset CDN surface.
fn expand_github_interactive(_inv: &ParsedInvocation) -> Result<Vec<PolicyRule>, PresetError> {
    Ok(GITHUB_INTERACTIVE_HOSTS
        .iter()
        .map(|host| http_rule(host, method::any_all_paths()))
        .collect())
}

// ---------------------------------------------------------------------------
// github-repo / github-pr — Phase 3b stubs
//
// The parameterized GitHub presets ship in the next commit. Phase 3a
// keeps the BUILTINS array shape stable (11 entries) by wiring the
// two parameterized slots to `NotImplemented` placeholders.
// ---------------------------------------------------------------------------

fn expand_github_repo(_inv: &ParsedInvocation) -> Result<Vec<PolicyRule>, PresetError> {
    Err(PresetError::NotImplemented {
        name: "github-repo".to_string(),
    })
}

fn expand_github_pr(_inv: &ParsedInvocation) -> Result<Vec<PolicyRule>, PresetError> {
    Err(PresetError::NotImplemented {
        name: "github-pr".to_string(),
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use sandbox_core::policy::SCHEMA_VERSION;
    use sandbox_core::{Policy, PolicyCompiler};

    fn parse_inv(raw: &str) -> ParsedInvocation {
        ParsedInvocation::parse(raw).expect("invocation should parse")
    }

    /// Wrap a rule set in a minimal Policy and run it through
    /// `PolicyCompiler::validate` to prove the preset's output is a
    /// structurally valid v2 policy on its own.
    fn assert_rules_round_trip(rules: Vec<PolicyRule>) {
        let policy = Policy {
            version: SCHEMA_VERSION.to_string(),
            rules,
        };
        PolicyCompiler::validate(&policy)
            .expect("preset expansion must be a valid v2 policy on its own");
    }

    /// Assert every rule has port 443, protocol tcp, level http, and
    /// `http_filters == method::get_head()`. Used for the seven
    /// consume-only presets.
    fn assert_consume_posture(rules: &[PolicyRule], expected_hosts: &[&str]) {
        assert_eq!(
            rules.len(),
            expected_hosts.len(),
            "rule count must match host count: {rules:?}"
        );
        for (rule, expected_host) in rules.iter().zip(expected_hosts.iter()) {
            assert_eq!(rule.port, 443);
            assert_eq!(rule.protocol, Protocol::Tcp);
            match &rule.host {
                Destination::Domain(d) => assert_eq!(d, expected_host),
                other => panic!("expected Domain host, got {other:?}"),
            }
            match &rule.level {
                AssuranceLevel::Http { http_filters } => {
                    assert_eq!(*http_filters, method::get_head());
                }
                other => panic!("expected Http level, got {other:?}"),
            }
        }
    }

    fn expand_builtin(name: &str, raw: &str) -> Vec<PolicyRule> {
        let preset = BUILTINS
            .iter()
            .find(|b| b.name == name)
            .unwrap_or_else(|| panic!("built-in '{name}' not registered"));
        let inv = parse_inv(raw);
        (preset.expand)(&inv).expect("expansion should succeed")
    }

    // ----- unparameterized presets -----------------------------------

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
    fn expand_npm_matches_spec() {
        let rules = expand_builtin("npm", "npm:");
        assert_consume_posture(&rules, &["registry.npmjs.org"]);
        assert_rules_round_trip(rules);
    }

    #[test]
    fn expand_pypi_matches_spec() {
        let rules = expand_builtin("pypi", "pypi:");
        assert_consume_posture(&rules, &["pypi.org", "files.pythonhosted.org"]);
        assert_rules_round_trip(rules);
    }

    #[test]
    fn expand_cargo_matches_spec() {
        let rules = expand_builtin("cargo", "cargo:");
        assert_consume_posture(
            &rules,
            &["crates.io", "index.crates.io", "static.crates.io"],
        );
        assert_rules_round_trip(rules);
    }

    #[test]
    fn expand_goproxy_matches_spec() {
        let rules = expand_builtin("goproxy", "goproxy:");
        assert_consume_posture(&rules, &["proxy.golang.org", "sum.golang.org"]);
        assert_rules_round_trip(rules);
    }

    #[test]
    fn expand_maven_matches_spec() {
        let rules = expand_builtin("maven", "maven:");
        assert_consume_posture(&rules, &["repo1.maven.org", "repo.maven.apache.org"]);
        assert_rules_round_trip(rules);
    }

    #[test]
    fn expand_gradle_matches_spec() {
        let rules = expand_builtin("gradle", "gradle:");
        assert_consume_posture(
            &rules,
            &[
                "plugins.gradle.org",
                "services.gradle.org",
                "downloads.gradle.org",
            ],
        );
        assert_rules_round_trip(rules);
    }

    #[test]
    fn expand_dockerhub_matches_spec() {
        let rules = expand_builtin("dockerhub", "dockerhub:");
        assert_consume_posture(
            &rules,
            &[
                "registry-1.docker.io",
                "auth.docker.io",
                "production.cloudflare.docker.com",
            ],
        );
        assert_rules_round_trip(rules);
    }

    #[test]
    fn expand_github_interactive_hosts_use_any_asset_cdn_uses_get_head() {
        // Spec lines 442-443: two rows under `github:`.
        //   interactive → ANY /**
        //   asset CDN   → GET /**, HEAD /**
        let rules = expand_builtin("github", "github:");
        assert_eq!(rules.len(), 6);

        // First two rules are the interactive hosts — ANY /** posture.
        for (rule, host) in rules[..2]
            .iter()
            .zip(["github.com", "api.github.com"].iter())
        {
            assert_eq!(rule.port, 443);
            assert_eq!(rule.protocol, Protocol::Tcp);
            match &rule.host {
                Destination::Domain(d) => assert_eq!(d, host),
                other => panic!("expected Domain, got {other:?}"),
            }
            match &rule.level {
                AssuranceLevel::Http { http_filters } => {
                    assert_eq!(http_filters.len(), 1);
                    assert_eq!(http_filters[0].method, HttpMethod::Any);
                    assert_eq!(http_filters[0].path, "/**");
                }
                other => panic!("expected Http level, got {other:?}"),
            }
        }

        // Remaining four rules are the asset CDN hosts — GET/HEAD posture.
        let asset_hosts = [
            "codeload.github.com",
            "objects.githubusercontent.com",
            "raw.githubusercontent.com",
            "release-assets.githubusercontent.com",
        ];
        for (rule, host) in rules[2..].iter().zip(asset_hosts.iter()) {
            match &rule.host {
                Destination::Domain(d) => assert_eq!(d, host),
                other => panic!("expected Domain, got {other:?}"),
            }
            match &rule.level {
                AssuranceLevel::Http { http_filters } => {
                    assert_eq!(*http_filters, method::get_head());
                }
                other => panic!("expected Http level, got {other:?}"),
            }
        }

        assert_rules_round_trip(rules);
    }

    #[test]
    fn expand_github_interactive_only_contains_interactive_hosts() {
        // The narrow variant: interactive hosts only.
        let rules = expand_builtin("github-interactive", "github-interactive:");
        assert_eq!(rules.len(), 2);
        let hosts: Vec<String> = rules
            .iter()
            .map(|r| match &r.host {
                Destination::Domain(d) => d.clone(),
                other => panic!("expected Domain, got {other:?}"),
            })
            .collect();
        assert_eq!(hosts, vec!["github.com", "api.github.com"]);
        for rule in &rules {
            match &rule.level {
                AssuranceLevel::Http { http_filters } => {
                    assert_eq!(*http_filters, method::any_all_paths());
                }
                other => panic!("expected Http level, got {other:?}"),
            }
        }
        assert_rules_round_trip(rules);
    }

    #[test]
    fn github_repo_and_github_pr_still_stubbed_in_phase_3a() {
        // Phase 3b adds the bodies. Phase 3a keeps the slots in
        // BUILTINS (so the array shape is stable) but both expanders
        // return `NotImplemented`.
        for name in ["github-repo", "github-pr"] {
            let preset = BUILTINS.iter().find(|b| b.name == name).unwrap();
            let inv = parse_inv(&format!("{name}:"));
            let err = (preset.expand)(&inv).expect_err("stub must error");
            match err {
                PresetError::NotImplemented { name: got } => assert_eq!(got, name),
                other => panic!("expected NotImplemented, got {other:?}"),
            }
        }
    }
}
