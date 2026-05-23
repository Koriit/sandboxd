//! Effective-policy merger and `(host, port)` uniqueness gate.
//!
//! The [`mod@super::expand`] module per invocation is intentionally permissive —
//! two presets may legitimately emit
//! overlapping `(host, port)` rows (e.g. `github:` and
//! `github-repo:repo=foo/bar` both declare `api.github.com:443`), and
//! user-preset repeatable fan-out can produce intra-preset duplicates
//! too.  [`merge_effective`] is the gate that catches either shape and
//! turns it into the required error naming every contributing
//! source.
//!
//! # Semantics
//!
//! Merge semantics (lines 344-362 of the event wire format spec):
//!
//! 1. Start with an empty `Vec<PolicyRule>`.
//! 2. Extend with the policy file's rules (if any).
//! 3. Extend with each preset expansion, in the order supplied by the
//!    caller.  That order is the CLI's `--preset` flag order, which is
//!    the order operators expect to see reflected in error blocks.
//! 4. Walk the merged list and group rule indices by `(host, port)`.
//!    For any group with more than one index, emit a
//!    [`DuplicateDestination`] listing *every* contributing source in
//!    first-seen order.  Collect *every* collision, not just the first —
//!    the error reports the full set so operators can fix them in one
//!    pass (D-6, strict duplicate error).
//! 5. Run [`PolicyCompiler::validate`] on the merged result.  That is a
//!    defensive step: it catches preset-internal rule-shape failures
//!    (e.g. a user preset that declares `level: http` but leaves
//!    `http_filters` empty) that expand-time validation did not surface.
//!
//! # Source attribution
//!
//! Each rule in the merged list carries a [`RuleSource`] built at merge
//! time:
//!
//! - Policy file rules → [`RuleSource::PolicyFile`] with the absolute
//!   path the caller passed in, or [`RuleSource::InlinePolicy`] as a
//!   defensive fallback when the caller supplied a `Policy` without a
//!   path (reserved for a future stdin-policy feature; today the CLI
//!   always pairs the two).
//! - Preset rules → [`RuleSource::Builtin`] or
//!   [`RuleSource::UserPreset`] depending on which catalog entry the
//!   invocation resolved to.  The `invocation` field carries the raw
//!   `--preset '<raw>'` string verbatim so the operator can copy-paste
//!   it back into the CLI.
//!
//! # Non-goals
//!
//! This module does not wire `--preset` into `main.rs` (Phase 5a), nor
//! does it own the `sandbox policy preset expand` client-local
//! subcommand (Phase 5b).  It is a pure library function with no
//! process, socket, or FS side-effects beyond what its callers pass in.

use std::collections::HashMap;
use std::path::Path;

use sandbox_core::policy::SCHEMA_VERSION;
use sandbox_core::{Policy, PolicyCompiler, PolicyRule};

use super::{Catalog, DuplicateDestination, ParsedInvocation, Preset, PresetError, RuleSource};

/// Merge a policy file and a set of preset expansions into a single
/// effective [`Policy`], enforcing `(host, port)` uniqueness with the
/// required source-attributed error shape.
///
/// # Arguments
///
/// - `file` — optional policy document loaded from `--policy <path>`.
///   When `None`, the effective policy starts empty.
/// - `file_path` — absolute path that `file` was loaded from.  Used
///   purely for source attribution in duplicate-destination errors.
///   When `file` is `Some(_)` but `file_path` is `None`, the file
///   rules are attributed to [`RuleSource::InlinePolicy`] as a
///   defensive fallback (reserved for a future stdin-policy feature —
///   the CLI always passes a path today).
/// - `catalog` — the preset catalog that produced `expansions`.  Used
///   to look up each invocation's [`Preset`] kind so the
///   [`RuleSource`] attached to each expanded rule distinguishes
///   built-in from user-preset origin.
/// - `expansions` — a slice of `(invocation, rules)` pairs.  Caller is
///   expected to pre-compute the expansions via [`super::expand()`]
///   — we do not re-expand here because the caller may want to run
///   each expansion through `sandbox policy preset expand`-style
///   diagnostics before committing to the merge.  Order is preserved:
///   the merged rule list places file rules first, then each
///   expansion's rules in the order given.
///
/// # Errors
///
/// - [`PresetError::DuplicateDestination`] when exactly one
///   `(host, port)` appears more than once.
/// - [`PresetError::DuplicateDestinations`] when two or more distinct
///   `(host, port)` each appear more than once (reported as one error
///   with one block per collision).
/// - [`PresetError::PolicyValidation`] when the merged policy fails
///   [`PolicyCompiler::validate`].  That validator itself enforces
///   `(host, port)` uniqueness too; by the time we call it here the
///   merged list is already unique, so in practice this variant fires
///   only for per-rule shape issues (empty `http_filters` on an
///   `http`-level rule, invalid CIDR, etc.).
/// - Any variant the caller's `expansions` precomputation raised is
///   surfaced *by the caller*, not by this function.
pub fn merge_effective(
    file: Option<&Policy>,
    file_path: Option<&Path>,
    catalog: &Catalog,
    expansions: &[(ParsedInvocation, Vec<PolicyRule>)],
) -> Result<Policy, PresetError> {
    // 1. Concatenate rules in order, recording each rule's source in a
    //    parallel `sources` vector.  The two vectors share an index so
    //    the uniqueness pass can rebuild the source list per collision
    //    without extra lookups.
    let mut rules: Vec<PolicyRule> = Vec::new();
    let mut sources: Vec<RuleSource> = Vec::new();

    if let Some(policy) = file {
        let file_source = match file_path {
            Some(path) => RuleSource::PolicyFile {
                path: path.to_path_buf(),
            },
            // Defensive fallback: the CLI always passes a path in
            // practice (see module docs).  Kept reachable so the shape
            // of this function is self-contained and testable without
            // a real FS path.
            None => RuleSource::InlinePolicy,
        };
        for rule in &policy.rules {
            rules.push(rule.clone());
            sources.push(file_source.clone());
        }
    }

    for (inv, expansion_rules) in expansions {
        let preset_source = rule_source_for_invocation(catalog, inv)?;
        for rule in expansion_rules {
            rules.push(rule.clone());
            sources.push(preset_source.clone());
        }
    }

    // 2. Uniqueness pass.  Keyed on the rule's `(host, port)` identity.
    //    A `Vec<usize>`
    //    preserves first-seen order — so the duplicate error lists
    //    sources in the exact order they appeared in the merged list,
    //    which matches what the operator sees when they read the
    //    command-line arguments left-to-right.
    let mut seen: HashMap<(String, u16), Vec<usize>> = HashMap::new();
    // `keys_in_order` lets us walk collisions in first-seen order of
    // the destination itself, so an error with two collisions reports
    // them in the order they appeared in the merged rule list rather
    // than in `HashMap` iteration order (non-deterministic).
    let mut keys_in_order: Vec<(String, u16)> = Vec::new();
    for (idx, rule) in rules.iter().enumerate() {
        let key = (rule.host.to_string(), rule.port);
        let slot = seen.entry(key.clone()).or_insert_with(|| {
            keys_in_order.push(key.clone());
            Vec::new()
        });
        slot.push(idx);
    }

    let mut duplicates: Vec<DuplicateDestination> = Vec::new();
    for key in &keys_in_order {
        let indices = seen.get(key).expect("key was inserted above");
        if indices.len() < 2 {
            continue;
        }
        let sources_for_key: Vec<RuleSource> =
            indices.iter().map(|&i| sources[i].clone()).collect();
        duplicates.push(DuplicateDestination {
            host: key.0.clone(),
            port: key.1,
            sources: sources_for_key,
        });
    }

    match duplicates.len() {
        0 => {}
        1 => {
            return Err(PresetError::DuplicateDestination(Box::new(
                duplicates.into_iter().next().expect("len == 1"),
            )));
        }
        _ => return Err(PresetError::DuplicateDestinations(duplicates)),
    }

    // 3. Wrap the merged rules as a `Policy` and validate.
    let merged = Policy {
        version: SCHEMA_VERSION.to_string(),
        rules,
    };

    // `validate` re-checks `(host, port)` uniqueness but we have
    // already ruled that out above; what remains is per-rule shape
    // (http_filters non-empty, CIDR syntax, domain syntax, …).  Defer
    // to `sandbox_core` so the error text stays consistent with the
    // daemon-side defensive revalidation.
    PolicyCompiler::validate(&merged).map_err(PresetError::PolicyValidation)?;

    Ok(merged)
}

/// Resolve an invocation against the catalog and return the
/// [`RuleSource`] that should be attached to every rule it produced.
///
/// Split out from [`merge_effective`] so the uniqueness pass can keep
/// the hot loop free of `catalog.find` work and so tests can exercise
/// the source-kind mapping in isolation.
fn rule_source_for_invocation(
    catalog: &Catalog,
    inv: &ParsedInvocation,
) -> Result<RuleSource, PresetError> {
    match catalog.find(&inv.name)? {
        Preset::Builtin(b) => Ok(RuleSource::Builtin {
            name: b.name.to_string(),
            invocation: inv.raw.clone(),
        }),
        Preset::User(u) => Ok(RuleSource::UserPreset {
            name: u.name.clone(),
            invocation: inv.raw.clone(),
            path: u.source_path.clone(),
        }),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::presets::expand::expand;
    use sandbox_core::{AssuranceLevel, Destination, PolicyRule, Protocol};
    use std::fs::File;
    use std::io::Write;
    use std::path::PathBuf;
    use tempfile::TempDir;

    // ----- test helpers ---------------------------------------------

    fn empty_catalog() -> (Catalog, TempDir) {
        let xdg = TempDir::new().expect("tempdir");
        let catalog = Catalog::load(Some(xdg.path())).expect("empty dir loads clean");
        (catalog, xdg)
    }

    fn write_user_preset(dir: &Path, filename: &str, body: &str) -> PathBuf {
        let path = dir.join(filename);
        let mut f = File::create(&path).expect("create user preset file");
        f.write_all(body.as_bytes())
            .expect("write user preset body");
        path
    }

    fn parse(raw: &str) -> ParsedInvocation {
        ParsedInvocation::parse(raw).expect("invocation should parse")
    }

    fn tls_rule(host: &str, port: u16) -> PolicyRule {
        PolicyRule {
            host: Destination::Domain(host.to_string()),
            port,
            protocol: Protocol::Tcp,
            reason: None,
            level: AssuranceLevel::Tls,
        }
    }

    fn policy_of(rules: Vec<PolicyRule>) -> Policy {
        Policy {
            version: SCHEMA_VERSION.to_string(),
            rules,
        }
    }

    /// Pre-expand every `--preset` invocation the way the CLI will do
    /// it in Phase 5.  Returned vector is what [`merge_effective`]
    /// consumes.
    fn pre_expand(
        catalog: &Catalog,
        invocations: &[&str],
    ) -> Vec<(ParsedInvocation, Vec<PolicyRule>)> {
        invocations
            .iter()
            .map(|raw| {
                let inv = parse(raw);
                let rules = expand(catalog, &inv).expect("expand");
                (inv, rules)
            })
            .collect()
    }

    // ----- case 1: clean merge ---------------------------------------

    #[test]
    fn clean_merge_concatenates_file_and_presets_in_order() {
        let (catalog, _xdg) = empty_catalog();
        let file_rules = vec![tls_rule("internal.example.com", 443)];
        let file = policy_of(file_rules.clone());
        let file_path = PathBuf::from("/tmp/policy.json");

        // github: and npm: do not overlap with each other nor with the
        // file rule, so this should be a clean extend.
        let expansions = pre_expand(&catalog, &["github:", "npm:"]);

        let merged = merge_effective(Some(&file), Some(&file_path), &catalog, &expansions)
            .expect("clean merge should succeed");

        // Order: file rules first, then github: rules, then npm: rules.
        assert_eq!(merged.version, SCHEMA_VERSION);
        assert!(
            merged.rules.len() > file_rules.len(),
            "presets must contribute additional rules"
        );
        // First rule is the file's rule.
        match &merged.rules[0].host {
            Destination::Domain(d) => assert_eq!(d, "internal.example.com"),
            other => panic!("expected the file's Domain first, got {other:?}"),
        }
        // The merged list must contain the npm registry host somewhere
        // (proves npm:'s rule was included).
        assert!(
            merged.rules.iter().any(|r| matches!(
                &r.host,
                Destination::Domain(d) if d == "registry.npmjs.org"
            )),
            "npm: rules must be present in merged output"
        );
        // ...and the github hosts (proves github:'s rules were included).
        assert!(
            merged.rules.iter().any(|r| matches!(
                &r.host,
                Destination::Domain(d) if d == "github.com"
            )),
            "github: rules must be present in merged output"
        );
    }

    // ----- case 2: two presets overlap -------------------------------

    #[test]
    fn two_presets_overlap_emits_duplicate_destination_naming_both_invocations() {
        let (catalog, _xdg) = empty_catalog();
        // github: and github-repo:repo=foo/bar both declare
        // api.github.com:443 (and github.com:443).  This is a
        // multi-collision case that exercises the N-block path.
        let expansions = pre_expand(&catalog, &["github:", "github-repo:repo=foo/bar"]);

        let err = merge_effective(None, None, &catalog, &expansions)
            .expect_err("overlapping presets must error");

        let rendered = err.to_string();

        // Both collisions must be listed — github.com:443 AND
        // api.github.com:443.  Order follows first-seen order of the
        // destination in the merged list, which is github:'s order
        // (GITHUB_INTERACTIVE_HOSTS = ["github.com", "api.github.com"]).
        assert!(
            rendered.contains("duplicate destination (github.com, 443)"),
            "error must mention github.com:443 collision, got:\n{rendered}"
        );
        assert!(
            rendered.contains("duplicate destination (api.github.com, 443)"),
            "error must mention api.github.com:443 collision, got:\n{rendered}"
        );
        // Each collision block names both preset invocations with the
        // required wording.
        assert!(
            rendered.contains("declared by preset invocation 'github:' (built-in 'github')"),
            "error must attribute to github: invocation, got:\n{rendered}"
        );
        assert!(
            rendered.contains(
                "declared by preset invocation 'github-repo:repo=foo/bar' (built-in 'github-repo')"
            ),
            "error must attribute to github-repo: invocation, got:\n{rendered}"
        );
    }

    // ----- case 3: file + preset overlap -----------------------------

    #[test]
    fn file_and_preset_overlap_names_both_sources_golden_string() {
        let (catalog, _xdg) = empty_catalog();
        // File declares api.github.com:443 at tls, github: declares it
        // at http with the same (host, port) — a strict duplicate.
        let file = policy_of(vec![tls_rule("api.github.com", 443)]);
        let file_path = PathBuf::from("/etc/sandboxd/policy.json");

        // Only one collision is *guaranteed* here — github: actually
        // emits github.com:443 too, but the file does not, so only
        // api.github.com has two sources.  That means the error is a
        // single-collision `DuplicateDestination`.
        //
        // (github.com:443 is single-source inside github:, not a
        // collision.)
        let expansions = pre_expand(&catalog, &["github:"]);

        let err = merge_effective(Some(&file), Some(&file_path), &catalog, &expansions)
            .expect_err("file/preset overlap must error");

        // Golden-string assertion — the exact wording (lines 140-150 of the
        // policy-rule spec) pins the error shape, with file
        // path first (it was the first-seen source) and built-in
        // preset invocation second.
        assert_eq!(
            err.to_string(),
            "policy validation failed: duplicate destination (api.github.com, 443)\n  - declared by policy file /etc/sandboxd/policy.json\n  - declared by preset invocation 'github:' (built-in 'github')"
        );
    }

    // ----- case 4: N-way overlap (>2 sources) -----------------------

    #[test]
    fn three_sources_claim_same_destination_lists_all_three() {
        // Construct three *user* presets that all emit
        // api.example.com:443.  Using user presets keeps the test
        // hermetic (no dependency on which built-ins happen to share
        // hosts).
        let xdg = TempDir::new().unwrap();
        let body = |name: &str| -> String {
            format!(
                r#"{{
                    "name": "{name}",
                    "params": [],
                    "rules": [
                        {{
                            "host": "api.example.com",
                            "port": 443,
                            "protocol": "tcp",
                            "level": "tls"
                        }}
                    ]
                }}"#
            )
        };
        write_user_preset(xdg.path(), "alpha.json", &body("alpha"));
        write_user_preset(xdg.path(), "beta.json", &body("beta"));
        write_user_preset(xdg.path(), "gamma.json", &body("gamma"));
        let catalog = Catalog::load(Some(xdg.path())).expect("load user presets");

        let expansions = pre_expand(&catalog, &["alpha:", "beta:", "gamma:"]);
        let err = merge_effective(None, None, &catalog, &expansions)
            .expect_err("three-way overlap must error");

        let rendered = err.to_string();
        // The header appears exactly once (single collision).
        assert_eq!(
            rendered
                .matches("duplicate destination (api.example.com, 443)")
                .count(),
            1,
            "expected exactly one collision block, got:\n{rendered}"
        );
        // All three preset invocations are attributed.
        assert!(rendered.contains("'alpha:'"), "rendered:\n{rendered}");
        assert!(rendered.contains("'beta:'"), "rendered:\n{rendered}");
        assert!(rendered.contains("'gamma:'"), "rendered:\n{rendered}");
        // Exactly three `declared by ...` lines.
        assert_eq!(
            rendered.matches("\n  - declared by ").count(),
            3,
            "expected exactly three source lines, got:\n{rendered}"
        );
    }

    // ----- case 5: multiple collisions -------------------------------

    #[test]
    fn multiple_destinations_collide_emits_one_block_per_collision() {
        // Two user presets, each declaring *both* api.example.com:443
        // and api.other.example.com:443.  Two distinct `(host, port)`
        // each have two contributing sources → two collision blocks.
        let xdg = TempDir::new().unwrap();
        let body = |name: &str| -> String {
            format!(
                r#"{{
                    "name": "{name}",
                    "params": [],
                    "rules": [
                        {{
                            "host": "api.example.com",
                            "port": 443,
                            "protocol": "tcp",
                            "level": "tls"
                        }},
                        {{
                            "host": "api.other.example.com",
                            "port": 443,
                            "protocol": "tcp",
                            "level": "tls"
                        }}
                    ]
                }}"#
            )
        };
        write_user_preset(xdg.path(), "alpha.json", &body("alpha"));
        write_user_preset(xdg.path(), "beta.json", &body("beta"));
        let catalog = Catalog::load(Some(xdg.path())).expect("load user presets");

        let expansions = pre_expand(&catalog, &["alpha:", "beta:"]);
        let err = merge_effective(None, None, &catalog, &expansions)
            .expect_err("two-collision merge must error");

        assert!(
            matches!(err, PresetError::DuplicateDestinations(ref d) if d.len() == 2),
            "expected DuplicateDestinations(2), got {err:?}"
        );
        let rendered = err.to_string();
        // One block per collision; blocks separated by a blank line.
        assert_eq!(
            rendered.matches("policy validation failed:").count(),
            2,
            "expected two `policy validation failed:` headers, got:\n{rendered}"
        );
        assert!(
            rendered.contains("duplicate destination (api.example.com, 443)"),
            "missing api.example.com block:\n{rendered}"
        );
        assert!(
            rendered.contains("duplicate destination (api.other.example.com, 443)"),
            "missing api.other.example.com block:\n{rendered}"
        );
        // Exactly one blank-line separator between the two blocks.
        assert_eq!(
            rendered.matches("\n\npolicy validation failed:").count(),
            1,
            "expected exactly one blank-line separator, got:\n{rendered}"
        );
    }

    // ----- case 6: internal duplicate within a single expansion -----

    #[test]
    fn internal_duplicate_within_single_expansion_surfaces_with_sole_invocation() {
        // A user preset whose repeatable `env=` param fans out a rule
        // whose host does *not* reference `${env}` — two invocations
        // of env produce two copies of the same `(host, port)` row.
        let xdg = TempDir::new().unwrap();
        let body = r#"{
            "name": "env-fanout",
            "params": [
                {"name": "env", "type": "string", "required": true, "repeatable": true}
            ],
            "rules": [
                {
                    "host": "fixed.example.com",
                    "port": 443,
                    "protocol": "tcp",
                    "level": "tls"
                }
            ]
        }"#;
        let user_path = write_user_preset(xdg.path(), "env-fanout.json", body);
        let catalog = Catalog::load(Some(xdg.path())).expect("load user preset");

        let expansions = pre_expand(&catalog, &["env-fanout:env=prod,env=stg"]);
        // Sanity check: the expansion produced two rules with the same
        // (host, port).
        assert_eq!(expansions[0].1.len(), 2);
        assert_eq!(
            (expansions[0].1[0].host.to_string(), expansions[0].1[0].port,),
            (expansions[0].1[1].host.to_string(), expansions[0].1[1].port,),
        );

        let err = merge_effective(None, None, &catalog, &expansions)
            .expect_err("internal duplicate must error");
        let rendered = err.to_string();

        assert!(
            rendered.contains("duplicate destination (fixed.example.com, 443)"),
            "rendered:\n{rendered}"
        );
        // Two source lines, both naming the *same* invocation and the
        // same user preset file path.
        assert_eq!(
            rendered.matches("'env-fanout:env=prod,env=stg'").count(),
            2,
            "both source lines must name the single invocation, got:\n{rendered}"
        );
        let path_str = user_path.display().to_string();
        assert_eq!(
            rendered.matches(path_str.as_str()).count(),
            2,
            "both source lines must name the user preset path, got:\n{rendered}"
        );
    }

    // ----- case 7: post-merge Policy::validate failure --------------

    #[test]
    fn post_merge_validation_failure_surfaces_policy_validation_variant() {
        // Craft a user preset that expands to a syntactically invalid
        // rule shape — a CIDR destination with a bogus mask.  The
        // merge pass itself is clean (one rule, no duplicates), so the
        // only failure path is the final `PolicyCompiler::validate`
        // call.
        let xdg = TempDir::new().unwrap();
        let body = r#"{
            "name": "bad-cidr",
            "params": [],
            "rules": [
                {
                    "host": "10.0.0.0/99",
                    "port": 443,
                    "protocol": "tcp",
                    "level": "tls"
                }
            ]
        }"#;
        write_user_preset(xdg.path(), "bad-cidr.json", body);
        let catalog = Catalog::load(Some(xdg.path())).expect("load user preset");

        let expansions = pre_expand(&catalog, &["bad-cidr:"]);
        let err = merge_effective(None, None, &catalog, &expansions)
            .expect_err("invalid CIDR must fail post-merge validation");

        // PolicyValidation wraps the underlying SandboxError; we check
        // the variant *and* that its Display surfaces the validator's
        // wording verbatim.
        match err {
            PresetError::PolicyValidation(ref inner) => {
                let rendered = inner.to_string();
                assert!(
                    rendered.contains("invalid CIDR") || rendered.contains("CIDR"),
                    "validator message must mention CIDR, got: {rendered}"
                );
            }
            other => panic!("expected PolicyValidation, got {other:?}"),
        }
    }

    // ----- case 7b: PolicyValidation Display golden -----------------

    #[test]
    fn policy_validation_display_defers_to_wrapped_sandbox_error() {
        // Golden string for the PolicyValidation Display impl itself —
        // independent of the specific preset that triggered it, so
        // this test stays stable if we introduce new validator messages
        // in the future.
        let inner = sandbox_core::SandboxError::Internal(
            "policy validation failed: rule 0 (host: bad, port: 443): invalid domain".to_string(),
        );
        let err = PresetError::PolicyValidation(inner);
        assert_eq!(
            err.to_string(),
            "internal error: policy validation failed: rule 0 (host: bad, port: 443): invalid domain"
        );
    }

    // ----- Display goldens for each duplicate variant ---------------

    #[test]
    fn duplicate_destinations_display_uses_one_block_per_collision() {
        // Pure-data golden string: pin the exact text of
        // DuplicateDestinations(Vec) with two blocks.  Blocks are
        // separated by a blank line and each starts with a fresh
        // `policy validation failed:` header.
        let err = PresetError::DuplicateDestinations(vec![
            DuplicateDestination {
                host: "github.com".to_string(),
                port: 443,
                sources: vec![
                    RuleSource::PolicyFile {
                        path: PathBuf::from("/etc/sandboxd/p.json"),
                    },
                    RuleSource::Builtin {
                        name: "github".to_string(),
                        invocation: "github:".to_string(),
                    },
                ],
            },
            DuplicateDestination {
                host: "api.github.com".to_string(),
                port: 443,
                sources: vec![
                    RuleSource::Builtin {
                        name: "github".to_string(),
                        invocation: "github:".to_string(),
                    },
                    RuleSource::Builtin {
                        name: "github-repo".to_string(),
                        invocation: "github-repo:repo=foo/bar".to_string(),
                    },
                ],
            },
        ]);
        assert_eq!(
            err.to_string(),
            "policy validation failed: duplicate destination (github.com, 443)\n  \
             - declared by policy file /etc/sandboxd/p.json\n  \
             - declared by preset invocation 'github:' (built-in 'github')\n\
             \n\
             policy validation failed: duplicate destination (api.github.com, 443)\n  \
             - declared by preset invocation 'github:' (built-in 'github')\n  \
             - declared by preset invocation 'github-repo:repo=foo/bar' (built-in 'github-repo')"
        );
    }

    #[test]
    fn user_preset_rule_source_display_matches_spec_wording() {
        // Golden for the UserPreset variant of RuleSource.  Covers the
        // exact path-attribution wording plan line 467 prescribes.
        let src = RuleSource::UserPreset {
            name: "my-internal".to_string(),
            invocation: "my-internal:env=prod".to_string(),
            path: PathBuf::from("/home/alice/.config/sandboxd/presets/my-internal.json"),
        };
        assert_eq!(
            src.to_string(),
            "declared by preset invocation 'my-internal:env=prod' (user preset /home/alice/.config/sandboxd/presets/my-internal.json)"
        );
    }

    #[test]
    fn inline_policy_rule_source_display_matches_defensive_wording() {
        // The InlinePolicy variant is defensive (reserved for a future
        // stdin-policy feature).  Pin its wording so future refactors
        // do not silently drift.
        let src = RuleSource::InlinePolicy;
        assert_eq!(src.to_string(), "declared by inline policy");
    }

    // ----- `None` file_path fallback --------------------------------

    #[test]
    fn file_without_path_uses_inline_policy_source_on_collision() {
        // Defensive branch: file provided without a path.  On
        // collision the file source must render as "inline policy".
        let (catalog, _xdg) = empty_catalog();
        let file = policy_of(vec![tls_rule("api.github.com", 443)]);
        let expansions = pre_expand(&catalog, &["github:"]);

        let err = merge_effective(Some(&file), None, &catalog, &expansions)
            .expect_err("file/preset overlap must error");
        let rendered = err.to_string();
        assert!(
            rendered.contains("declared by inline policy"),
            "missing inline-policy attribution, got:\n{rendered}"
        );
        assert!(
            rendered.contains("declared by preset invocation 'github:' (built-in 'github')"),
            "missing preset attribution, got:\n{rendered}"
        );
    }

    // ----- no-op merge (no file, no presets) ------------------------

    #[test]
    fn empty_merge_returns_empty_policy() {
        // Edge case: merge_effective with nothing produces a valid
        // empty policy at the current schema version.
        let (catalog, _xdg) = empty_catalog();
        let merged = merge_effective(None, None, &catalog, &[]).expect("empty merge");
        assert_eq!(merged.version, SCHEMA_VERSION);
        assert!(merged.rules.is_empty());
    }
}
