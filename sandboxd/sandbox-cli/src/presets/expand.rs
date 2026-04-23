//! Preset invocation → `Vec<PolicyRule>` expansion.
//!
//! The public entrypoint is [`expand`]: given a loaded [`Catalog`]
//! and a [`ParsedInvocation`], it resolves the preset (built-in or
//! user-configured) and returns the concrete [`PolicyRule`]s that
//! the preset contributes to the effective policy.
//!
//! - **Built-in presets** dispatch to the preset's own `expand` fn
//!   pointer (see [`super::builtin`]); every validation error shape
//!   is owned by that fn.
//! - **User-configured presets** substitute `${param}` into every
//!   string field of every [`RawRuleTemplate`], applying the
//!   Phase 2 parameter spec (required / optional, at most one
//!   repeatable param) and fanning out over the repeatable param
//!   when present. The result is a `Vec<PolicyRule>` whose
//!   `${param}` tokens have been resolved.
//!
//! Merge across invocations, `(host, port)` uniqueness, and the
//! `DuplicateDestination` source attribution are Phase 4's concerns;
//! Phase 3 may legitimately produce two rules with the same
//! `(host, port)` when a user preset's repeatable param fans out a
//! template that does not depend on the param (Phase 4 will either
//! merge or error). This is deliberate — each user repeat produces a
//! full copy of the rule set with substitution applied.
//!
//! See `.tasks/handoffs/20260423-m10-s5-implementation-plan.md`
//! § "Phase 3 — Built-in presets" for the plan that drives this
//! module.

use sandbox_core::{AssuranceLevel, Destination, HttpFilter, HttpMethod, PolicyRule, Protocol};

use super::user::{
    ParamType, RawHttpFilter, RawHttpMethod, RawLevel, RawProtocol, RawRuleTemplate, UserPreset,
};
use super::{Catalog, ParsedInvocation, Preset, PresetError};

/// Resolve `inv` against `catalog` and return its full rule set.
///
/// Built-in dispatch is a direct call to the preset's fn pointer.
/// User-preset dispatch walks the preset's `params` spec to validate
/// the invocation, then substitutes `${param}` into each rule
/// template, fanning out over the at-most-one repeatable param.
pub fn expand(catalog: &Catalog, inv: &ParsedInvocation) -> Result<Vec<PolicyRule>, PresetError> {
    match catalog.find(&inv.name)? {
        Preset::Builtin(bp) => (bp.expand)(inv),
        Preset::User(up) => expand_user_preset(&up, inv),
    }
}

/// Expand a user-configured preset by substituting each rule
/// template's `${param}` tokens.
///
/// Validation order (fail-fast):
///   1. Every invocation param name appears in the preset's spec.
///   2. Every required param appears at least once.
///   3. Non-repeatable params appear at most once.
///   4. Every `${param}` token in every template field names a
///      declared param.
///
/// Fan-out semantics: a preset may have at most one `repeatable: true`
/// param (enforced at load time by
/// [`PresetError::TooManyRepeatableParams`]). When present, the
/// expander produces one copy of the full rule set per repeatable
/// value, with that value substituted. Rule templates that do not
/// reference the repeatable param will produce duplicate
/// `(host, port)` entries — Phase 4's merge pass is responsible for
/// collapsing or erroring on those.
fn expand_user_preset(
    preset: &UserPreset,
    inv: &ParsedInvocation,
) -> Result<Vec<PolicyRule>, PresetError> {
    // 1. Unknown param names in the invocation are structural errors.
    for (k, _) in &inv.params {
        if !preset.params.iter().any(|p| &p.name == k) {
            return Err(PresetError::UnknownParamRef {
                preset: preset.name.clone(),
                ref_name: k.clone(),
            });
        }
    }

    // 2. Required params must appear. Also enforce non-repeatable
    //    appears at most once.
    for spec in &preset.params {
        let count = inv.params.iter().filter(|(k, _)| k == &spec.name).count();
        if spec.required && count == 0 {
            return Err(PresetError::MissingRequiredParam {
                preset: preset.name.clone(),
                param: spec.name.clone(),
            });
        }
        if !spec.repeatable && count > 1 {
            // Non-repeatable-appears-twice is returned as
            // `MalformedInvocation` intentionally: the grammar parser
            // cannot distinguish "legal syntax with a semantic
            // violation" from "malformed syntax" without carrying
            // repeatable-ness through the parser, which would leak
            // preset schema into `ParsedInvocation`. Operators see the
            // same diagnostic category either way and the `reason:`
            // field carries the specific cause.
            return Err(PresetError::MalformedInvocation {
                raw: inv.raw.clone(),
                reason: format!(
                    "param '{}' is not repeatable but appears {} times",
                    spec.name, count
                ),
            });
        }
    }

    // 3. Validate template references before substitution so the
    //    error names the unknown ref rather than silently leaving
    //    `${foo}` in the output.
    for rule in &preset.rules {
        check_template_refs(preset, rule)?;
    }

    // 4. Build the substitution list(s).
    //
    // `non_repeating` carries the singleton value for each
    // non-repeatable param (required or optional). `repeatable` is
    // either `None` (no repeatable param on this preset) or
    // `Some((name, values))` in invocation order.
    //
    // Missing optional non-repeatable params substitute to the empty
    // string. That is consistent with the Phase 2 scaffolding (which
    // preserves `${param}` in rule template strings verbatim and
    // leaves substitution to this expander) and with the spec's
    // reading that optional params are omitted rather than defaulted.

    let mut non_repeating: Vec<(String, String)> = Vec::new();
    let mut repeatable: Option<(String, Vec<String>)> = None;
    for spec in &preset.params {
        debug_assert!(matches!(spec.r#type, ParamType::String)); // only type today
        let values: Vec<String> = inv
            .params
            .iter()
            .filter(|(k, _)| k == &spec.name)
            .map(|(_, v)| v.clone())
            .collect();
        if spec.repeatable {
            repeatable = Some((spec.name.clone(), values));
        } else {
            let value = values.into_iter().next().unwrap_or_default();
            non_repeating.push((spec.name.clone(), value));
        }
    }

    // 5. Fan out.
    let materialise = |substitutions: &[(String, String)]| -> Vec<PolicyRule> {
        preset
            .rules
            .iter()
            .map(|tmpl| materialise_rule(tmpl, substitutions))
            .collect()
    };

    let out = match repeatable {
        None => materialise(&non_repeating),
        Some((_name, values)) if values.is_empty() => {
            // Repeatable-but-optional param with zero values: emit one
            // copy of the rule set with the `${name}` token substituted
            // to empty. In practice presets that want zero copies
            // should mark the param required; we preserve this
            // harmless fallback so the loader's soft optional/repeatable
            // combination does not blow up.
            materialise(&non_repeating)
        }
        Some((name, values)) => {
            let mut out = Vec::with_capacity(preset.rules.len() * values.len());
            for value in values {
                let mut subs = non_repeating.clone();
                subs.push((name.clone(), value));
                out.extend(materialise(&subs));
            }
            out
        }
    };

    Ok(out)
}

/// Check every string field of `rule` for `${name}` tokens whose
/// `name` is not declared in the preset's `params` list. The host,
/// each `http_filters[i].path`, and the `reason` field are scanned.
/// Port/protocol/level/method are closed enums at load time and
/// carry no templates.
fn check_template_refs(preset: &UserPreset, rule: &RawRuleTemplate) -> Result<(), PresetError> {
    let declared: Vec<&str> = preset.params.iter().map(|p| p.name.as_str()).collect();
    check_refs(preset, &rule.host, &declared)?;
    if let Some(filters) = rule.http_filters.as_ref() {
        for filter in filters {
            check_refs(preset, &filter.path, &declared)?;
        }
    }
    if let Some(reason) = rule.reason.as_deref() {
        check_refs(preset, reason, &declared)?;
    }
    Ok(())
}

fn check_refs(preset: &UserPreset, s: &str, declared: &[&str]) -> Result<(), PresetError> {
    for (_, name) in find_refs(s) {
        if !declared.iter().any(|d| *d == name) {
            return Err(PresetError::UnknownParamRef {
                preset: preset.name.clone(),
                ref_name: name,
            });
        }
    }
    Ok(())
}

/// Scan `s` for `${name}` tokens and return each `(range, name)`
/// pair. Only well-formed tokens (with a closing `}`) are returned;
/// an unterminated `${` is ignored (surfaces as the leftover literal
/// in the output, which the downstream validator will reject as an
/// invalid host/path rather than this layer pretending to diagnose).
fn find_refs(s: &str) -> Vec<(std::ops::Range<usize>, String)> {
    let mut out = Vec::new();
    let bytes = s.as_bytes();
    let mut i = 0;
    while i + 1 < bytes.len() {
        if bytes[i] == b'$' && bytes[i + 1] == b'{' {
            if let Some(end_rel) = s[i + 2..].find('}') {
                let end = i + 2 + end_rel;
                let name = &s[i + 2..end];
                if !name.is_empty() {
                    out.push((i..end + 1, name.to_string()));
                }
                i = end + 1;
                continue;
            }
        }
        i += 1;
    }
    out
}

/// Replace every `${name}` in `s` whose `name` appears in
/// `substitutions` with the corresponding value. Unmatched references
/// are left verbatim — [`check_template_refs`] will have rejected
/// them earlier, so in practice every reference is matched here.
fn substitute(s: &str, substitutions: &[(String, String)]) -> String {
    let refs = find_refs(s);
    if refs.is_empty() {
        return s.to_string();
    }
    let mut out = String::with_capacity(s.len());
    let mut cursor = 0;
    for (range, name) in refs {
        out.push_str(&s[cursor..range.start]);
        if let Some((_, value)) = substitutions.iter().find(|(k, _)| k == &name) {
            out.push_str(value);
        } else {
            // Unmatched — emit verbatim. (Unreachable if callers ran
            // check_template_refs first.)
            out.push_str(&s[range.clone()]);
        }
        cursor = range.end;
    }
    out.push_str(&s[cursor..]);
    out
}

/// Build a concrete [`PolicyRule`] from a raw template by
/// substituting `${name}` tokens and converting the raw enums to
/// their `sandbox_core` equivalents.
fn materialise_rule(tmpl: &RawRuleTemplate, substitutions: &[(String, String)]) -> PolicyRule {
    let host_str = substitute(&tmpl.host, substitutions);
    // `Destination::try_from` picks Domain vs. CIDR based on syntax;
    // an empty string is the only rejected value and would also fail
    // `PolicyCompiler::validate` downstream. We default to Domain on
    // error to keep error surfacing in one place (the validator).
    let host = Destination::try_from(host_str.clone()).unwrap_or(Destination::Domain(host_str));

    let protocol = match tmpl.protocol {
        RawProtocol::Tcp => Protocol::Tcp,
        RawProtocol::Udp => Protocol::Udp,
    };

    let level = match tmpl.level {
        RawLevel::Deny => AssuranceLevel::Deny,
        RawLevel::Transport => AssuranceLevel::Transport,
        RawLevel::Tls => AssuranceLevel::Tls,
        RawLevel::Http => {
            // Downstream validator requires a non-empty filter list
            // for http-level rules. We emit whatever the template
            // declares (even the empty vec) and let the validator
            // surface the error with a consistent message shape.
            let filters = tmpl
                .http_filters
                .as_ref()
                .map(|vs| {
                    vs.iter()
                        .map(|f| materialise_filter(f, substitutions))
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            AssuranceLevel::Http {
                http_filters: filters,
            }
        }
    };

    let reason = tmpl.reason.as_ref().map(|r| substitute(r, substitutions));

    PolicyRule {
        host,
        port: tmpl.port,
        protocol,
        reason,
        level,
    }
}

fn materialise_filter(raw: &RawHttpFilter, substitutions: &[(String, String)]) -> HttpFilter {
    HttpFilter {
        method: match raw.method {
            RawHttpMethod::Get => HttpMethod::Get,
            RawHttpMethod::Post => HttpMethod::Post,
            RawHttpMethod::Put => HttpMethod::Put,
            RawHttpMethod::Delete => HttpMethod::Delete,
            RawHttpMethod::Patch => HttpMethod::Patch,
            RawHttpMethod::Head => HttpMethod::Head,
            RawHttpMethod::Options => HttpMethod::Options,
            RawHttpMethod::Trace => HttpMethod::Trace,
            RawHttpMethod::Connect => HttpMethod::Connect,
            RawHttpMethod::Any => HttpMethod::Any,
        },
        path: substitute(&raw.path, substitutions),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::presets::Catalog;
    use std::fs::File;
    use std::io::Write;
    use std::path::Path;
    use tempfile::TempDir;

    // ----- test helpers ---------------------------------------------

    fn empty_catalog() -> (Catalog, TempDir) {
        let xdg = TempDir::new().expect("tempdir");
        let catalog = Catalog::load(Some(xdg.path())).expect("empty dir loads clean");
        (catalog, xdg)
    }

    fn write_user_preset(dir: &Path, filename: &str, body: &str) {
        let mut f = File::create(dir.join(filename)).expect("create user preset file");
        f.write_all(body.as_bytes())
            .expect("write user preset body");
    }

    fn parse(raw: &str) -> ParsedInvocation {
        ParsedInvocation::parse(raw).expect("invocation should parse")
    }

    // ----- unknown preset -------------------------------------------

    #[test]
    fn unknown_preset_is_unknown_preset_error() {
        let (catalog, _xdg) = empty_catalog();
        let err = expand(&catalog, &parse("nosuch:")).expect_err("should fail");
        match err {
            PresetError::UnknownPreset(name) => assert_eq!(name, "nosuch"),
            other => panic!("expected UnknownPreset, got {other:?}"),
        }
    }

    // ----- built-in dispatch ----------------------------------------

    #[test]
    fn builtin_preset_dispatches_to_fn_pointer() {
        let (catalog, _xdg) = empty_catalog();
        let rules = expand(&catalog, &parse("npm:")).expect("npm should expand");
        assert_eq!(rules.len(), 1);
    }

    // ----- user preset: happy path ----------------------------------

    #[test]
    fn user_preset_without_params_expands_rules_verbatim() {
        let xdg = TempDir::new().unwrap();
        let body = r#"{
            "name": "internal-api",
            "params": [],
            "rules": [
                {
                    "host": "api.internal.example.com",
                    "port": 443,
                    "protocol": "tcp",
                    "level": "tls"
                }
            ]
        }"#;
        write_user_preset(xdg.path(), "internal-api.json", body);
        let catalog = Catalog::load(Some(xdg.path())).expect("load");

        let rules = expand(&catalog, &parse("internal-api:")).expect("should expand");
        assert_eq!(rules.len(), 1);
        match &rules[0].host {
            Destination::Domain(d) => assert_eq!(d, "api.internal.example.com"),
            other => panic!("expected Domain, got {other:?}"),
        }
        assert_eq!(rules[0].port, 443);
        assert!(matches!(rules[0].level, AssuranceLevel::Tls));
    }

    #[test]
    fn user_preset_substitutes_required_param_in_host() {
        let xdg = TempDir::new().unwrap();
        let body = r#"{
            "name": "tenant-api",
            "params": [
                {"name": "tenant", "type": "string", "required": true, "repeatable": false}
            ],
            "rules": [
                {
                    "host": "${tenant}.api.internal.example.com",
                    "port": 443,
                    "protocol": "tcp",
                    "level": "http",
                    "http_filters": [{"method": "GET", "path": "/v1/${tenant}/**"}]
                }
            ]
        }"#;
        write_user_preset(xdg.path(), "tenant-api.json", body);
        let catalog = Catalog::load(Some(xdg.path())).expect("load");

        let rules = expand(&catalog, &parse("tenant-api:tenant=acme")).expect("should expand");
        assert_eq!(rules.len(), 1);
        match &rules[0].host {
            Destination::Domain(d) => assert_eq!(d, "acme.api.internal.example.com"),
            other => panic!("expected Domain, got {other:?}"),
        }
        match &rules[0].level {
            AssuranceLevel::Http { http_filters } => {
                assert_eq!(http_filters.len(), 1);
                assert_eq!(http_filters[0].method, HttpMethod::Get);
                assert_eq!(http_filters[0].path, "/v1/acme/**");
            }
            other => panic!("expected Http level, got {other:?}"),
        }
    }

    #[test]
    fn user_preset_missing_required_param_surfaces_missing_required_param() {
        let xdg = TempDir::new().unwrap();
        let body = r#"{
            "name": "tenant-api",
            "params": [
                {"name": "tenant", "type": "string", "required": true, "repeatable": false}
            ],
            "rules": [
                {
                    "host": "${tenant}.api.internal.example.com",
                    "port": 443,
                    "protocol": "tcp",
                    "level": "tls"
                }
            ]
        }"#;
        write_user_preset(xdg.path(), "tenant-api.json", body);
        let catalog = Catalog::load(Some(xdg.path())).expect("load");

        let err = expand(&catalog, &parse("tenant-api:")).expect_err("should fail");
        match err {
            PresetError::MissingRequiredParam { preset, param } => {
                assert_eq!(preset, "tenant-api");
                assert_eq!(param, "tenant");
            }
            other => panic!("expected MissingRequiredParam, got {other:?}"),
        }
    }

    #[test]
    fn user_preset_unknown_param_in_invocation_surfaces_unknown_param_ref() {
        let xdg = TempDir::new().unwrap();
        let body = r#"{
            "name": "tenant-api",
            "params": [
                {"name": "tenant", "type": "string", "required": false, "repeatable": false}
            ],
            "rules": [
                {
                    "host": "api.internal.example.com",
                    "port": 443,
                    "protocol": "tcp",
                    "level": "tls"
                }
            ]
        }"#;
        write_user_preset(xdg.path(), "tenant-api.json", body);
        let catalog = Catalog::load(Some(xdg.path())).expect("load");

        let err = expand(&catalog, &parse("tenant-api:nosuch=x")).expect_err("should fail");
        match err {
            PresetError::UnknownParamRef { preset, ref_name } => {
                assert_eq!(preset, "tenant-api");
                assert_eq!(ref_name, "nosuch");
            }
            other => panic!("expected UnknownParamRef, got {other:?}"),
        }
    }

    #[test]
    fn user_preset_unknown_template_ref_surfaces_unknown_param_ref() {
        let xdg = TempDir::new().unwrap();
        let body = r#"{
            "name": "typo-template",
            "params": [
                {"name": "tenant", "type": "string", "required": true, "repeatable": false}
            ],
            "rules": [
                {
                    "host": "${tenent}.api.internal.example.com",
                    "port": 443,
                    "protocol": "tcp",
                    "level": "tls"
                }
            ]
        }"#;
        write_user_preset(xdg.path(), "typo-template.json", body);
        let catalog = Catalog::load(Some(xdg.path())).expect("load");

        let err = expand(&catalog, &parse("typo-template:tenant=acme")).expect_err("should fail");
        match err {
            PresetError::UnknownParamRef { preset, ref_name } => {
                assert_eq!(preset, "typo-template");
                assert_eq!(ref_name, "tenent"); // the typo in the template
            }
            other => panic!("expected UnknownParamRef, got {other:?}"),
        }
    }

    #[test]
    fn user_preset_repeatable_param_fans_out_rules() {
        let xdg = TempDir::new().unwrap();
        let body = r#"{
            "name": "multi-env",
            "params": [
                {"name": "env", "type": "string", "required": true, "repeatable": true}
            ],
            "rules": [
                {
                    "host": "${env}.internal.example.com",
                    "port": 443,
                    "protocol": "tcp",
                    "level": "tls"
                }
            ]
        }"#;
        write_user_preset(xdg.path(), "multi-env.json", body);
        let catalog = Catalog::load(Some(xdg.path())).expect("load");

        let rules = expand(&catalog, &parse("multi-env:env=prod,env=stg")).expect("should expand");
        assert_eq!(rules.len(), 2);
        match &rules[0].host {
            Destination::Domain(d) => assert_eq!(d, "prod.internal.example.com"),
            other => panic!("expected Domain, got {other:?}"),
        }
        match &rules[1].host {
            Destination::Domain(d) => assert_eq!(d, "stg.internal.example.com"),
            other => panic!("expected Domain, got {other:?}"),
        }
    }

    #[test]
    fn user_preset_non_repeatable_param_twice_is_malformed_invocation() {
        let xdg = TempDir::new().unwrap();
        let body = r#"{
            "name": "once-only",
            "params": [
                {"name": "env", "type": "string", "required": true, "repeatable": false}
            ],
            "rules": []
        }"#;
        write_user_preset(xdg.path(), "once-only.json", body);
        let catalog = Catalog::load(Some(xdg.path())).expect("load");

        let err = expand(&catalog, &parse("once-only:env=a,env=b")).expect_err("should fail");
        assert!(matches!(err, PresetError::MalformedInvocation { .. }));
    }
}
