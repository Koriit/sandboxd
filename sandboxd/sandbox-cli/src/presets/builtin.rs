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
//! The first 10 entries mirror Part 2 of the spec at
//! `.tasks/specs/2026-04-21-port-explicit-policies-presets-observability-design.md`
//! lines 428-568. The plain `github` preset unifies the two rows in
//! the spec's table (interactive hosts + asset CDN) under a single
//! preset name; operators who need narrower scope than `github:`
//! use `github-repo` / `github-pr` instead. The 11th entry, `ubuntu`,
//! is the first distro-level default-allow preset.
//!
//! # Determinism
//!
//! Every expander returns rules in a fixed, source-order sequence
//! (the literal order of host entries in this file). Phase 4's merge
//! pass depends on this being stable so `(host, port)` collision
//! errors are reproducible across runs.

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
    // ----- OS / distro presets ----------------------------------------
    BuiltinPreset {
        name: "ubuntu",
        description: "Allow default-allow rules an Ubuntu sandbox needs to function (NTP + apt mirrors).",
        expand: expand_ubuntu,
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

/// Build a `tls`-level rule for `(host, 443, tcp)`. Used by
/// `github-repo` for `objects.githubusercontent.com` and
/// `release-assets.githubusercontent.com`, whose URLs are signed and
/// opaque so method/path filtering buys nothing.
fn tls_rule(host: &str) -> PolicyRule {
    PolicyRule {
        host: Destination::Domain(host.to_string()),
        port: 443,
        protocol: Protocol::Tcp,
        reason: None,
        level: AssuranceLevel::Tls,
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
    // Host set frozen against the documented cargo network endpoints
    // for Rust 1.70+ (sparse-index default). See
    // `tests/fixtures/cargo_fetch_trace.json` for the verified set and
    // the `cargo_preset_matches_frozen_trace` drift-detection test
    // below. When a future guest-network milestone makes live pcap
    // capture cheap, the fixture should be regenerated from a real
    // `cargo fetch` trace against an empty cache.
    //
    // Endpoint roles (per the fixture):
    // - `index.crates.io`  — sparse registry index.
    // - `crates.io`        — registry web API + download redirector.
    // - `static.crates.io` — CDN host that serves crate tarballs
    //                        (302 target of the download redirector).
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

// ---------------------------------------------------------------------------
// github-repo (parameterized; spec lines 500-535)
// ---------------------------------------------------------------------------
//
// Determinism contract: with one `repo=owner/name` value the http
// rules' `http_filters` arrays follow the template order declared
// below (git-pack templates, then API templates, etc.). With multiple
// `repo=` values the arrays fan out as
// `[repo0-filters..., repo1-filters..., ...]` — each repo's per-host
// template block appears in invocation order. The `GET /user` and
// `GET /rate_limit` probes are appended to `api.github.com`'s
// `http_filters` exactly once at the end regardless of repo count
// (they do not depend on `${repo}`).

/// Validate a `repo=owner/name` value against the DNS-ish shape
/// documented in the spec. Returns a structured error rather than a
/// string match so the CLI can surface a targeted message.
fn validate_repo_value(raw: &str) -> Result<(), String> {
    // Exactly one `/`, non-empty owner and name, each component
    // restricted to `[A-Za-z0-9._-]`. Keep the check explicit (no
    // regex dep) so the allowed alphabet is visible at the call site.
    let mut parts = raw.splitn(2, '/');
    let owner = parts.next().unwrap_or("");
    let name = parts.next();
    let Some(name) = name else {
        return Err("expected 'owner/name' (no '/' in value)".to_string());
    };
    if parts.next().is_some() {
        // `splitn(2, ...)` never returns a third part; defensive.
        return Err("expected exactly one '/'".to_string());
    }
    if owner.is_empty() {
        return Err("owner component is empty".to_string());
    }
    if name.is_empty() {
        return Err("name component is empty".to_string());
    }
    if raw.contains("//") {
        return Err("empty path component".to_string());
    }
    for (component, label) in [(owner, "owner"), (name, "name")] {
        for ch in component.chars() {
            if !(ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '-')) {
                return Err(format!(
                    "{label} component '{component}' contains disallowed character '{ch}' \
                     (allowed: A-Z, a-z, 0-9, '.', '_', '-')"
                ));
            }
        }
    }
    Ok(())
}

/// Path templates for one `repo` on one host. Each template is a
/// `(method, path_with_${repo})` pair. Substitution happens in
/// [`expand_github_repo`] once the repo values have been validated.
struct RepoTemplate {
    method: HttpMethod,
    /// A path with literal `${repo}` tokens that get substituted with
    /// the user-supplied `owner/name`.
    path: &'static str,
}

/// github-repo templates for `github.com`: git-pack URL set (both the
/// canonical `.git` form and the no-`.git` form GitHub also serves).
/// Spec lines 507-512.
const GITHUB_REPO_GITHUB_COM_TEMPLATES: &[RepoTemplate] = &[
    // `.git`-suffixed URLs — canonical.
    RepoTemplate {
        method: HttpMethod::Get,
        path: "/${repo}.git/info/refs",
    },
    RepoTemplate {
        method: HttpMethod::Head,
        path: "/${repo}.git/info/refs",
    },
    RepoTemplate {
        method: HttpMethod::Post,
        path: "/${repo}.git/git-upload-pack",
    },
    RepoTemplate {
        method: HttpMethod::Post,
        path: "/${repo}.git/git-receive-pack",
    },
    // No-`.git` URLs — GitHub serves both.
    RepoTemplate {
        method: HttpMethod::Get,
        path: "/${repo}/info/refs",
    },
    RepoTemplate {
        method: HttpMethod::Post,
        path: "/${repo}/git-upload-pack",
    },
    RepoTemplate {
        method: HttpMethod::Post,
        path: "/${repo}/git-receive-pack",
    },
];

/// github-repo templates for `api.github.com`: repo-scoped REST API.
/// Spec lines 513-515. `GET /user` and `GET /rate_limit` are shared
/// across all repos and appended once outside this list.
const GITHUB_REPO_API_TEMPLATES: &[RepoTemplate] = &[RepoTemplate {
    method: HttpMethod::Any,
    path: "/repos/${repo}/**",
}];

/// github-repo templates for `codeload.github.com` (archive downloads).
/// Spec lines 516-517.
const GITHUB_REPO_CODELOAD_TEMPLATES: &[RepoTemplate] = &[
    RepoTemplate {
        method: HttpMethod::Get,
        path: "/${repo}/**",
    },
    RepoTemplate {
        method: HttpMethod::Head,
        path: "/${repo}/**",
    },
];

/// github-repo templates for `raw.githubusercontent.com`. Spec lines
/// 523-524.
const GITHUB_REPO_RAW_TEMPLATES: &[RepoTemplate] = &[
    RepoTemplate {
        method: HttpMethod::Get,
        path: "/${repo}/**",
    },
    RepoTemplate {
        method: HttpMethod::Head,
        path: "/${repo}/**",
    },
];

/// Always-needed API probes that are not per-repo. Spec line 515.
fn api_github_com_shared_probes() -> Vec<HttpFilter> {
    vec![
        HttpFilter {
            method: HttpMethod::Get,
            path: "/user".to_string(),
        },
        HttpFilter {
            method: HttpMethod::Get,
            path: "/rate_limit".to_string(),
        },
    ]
}

/// Substitute `${repo}` in a template path and return the
/// concrete [`HttpFilter`].
fn instantiate_repo_template(tmpl: &RepoTemplate, repo: &str) -> HttpFilter {
    HttpFilter {
        method: tmpl.method,
        path: tmpl.path.replace("${repo}", repo),
    }
}

fn expand_github_repo(inv: &ParsedInvocation) -> Result<Vec<PolicyRule>, PresetError> {
    // Collect every `repo=` value in invocation order.
    let repos: Vec<&str> = inv
        .params
        .iter()
        .filter(|(k, _)| k == "repo")
        .map(|(_, v)| v.as_str())
        .collect();
    if repos.is_empty() {
        return Err(PresetError::MissingRequiredParam {
            preset: "github-repo".to_string(),
            param: "repo".to_string(),
        });
    }

    // Validate each value before building rules — we want the whole
    // invocation to fail fast with a concrete pointer to the bad
    // value rather than partially building rules.
    for repo in &repos {
        if let Err(reason) = validate_repo_value(repo) {
            return Err(PresetError::InvalidRepoValue {
                preset: "github-repo".to_string(),
                value: (*repo).to_string(),
                reason,
            });
        }
    }

    // Build per-host `http_filters` arrays with repo fan-out in
    // invocation order.
    let fan_out = |templates: &[RepoTemplate]| -> Vec<HttpFilter> {
        let mut out = Vec::with_capacity(templates.len() * repos.len());
        for repo in &repos {
            for tmpl in templates {
                out.push(instantiate_repo_template(tmpl, repo));
            }
        }
        out
    };

    let github_com_filters = fan_out(GITHUB_REPO_GITHUB_COM_TEMPLATES);

    let mut api_github_com_filters = fan_out(GITHUB_REPO_API_TEMPLATES);
    api_github_com_filters.extend(api_github_com_shared_probes());

    let codeload_filters = fan_out(GITHUB_REPO_CODELOAD_TEMPLATES);
    let raw_filters = fan_out(GITHUB_REPO_RAW_TEMPLATES);

    Ok(vec![
        http_rule("github.com", github_com_filters),
        http_rule("api.github.com", api_github_com_filters),
        http_rule("codeload.github.com", codeload_filters),
        http_rule("raw.githubusercontent.com", raw_filters),
        // Signed, opaque release-asset URLs: `tls` is the tightest
        // workable level (spec lines 518-522).
        tls_rule("objects.githubusercontent.com"),
        tls_rule("release-assets.githubusercontent.com"),
    ])
}

// ---------------------------------------------------------------------------
// github-pr (parameterized; spec lines 538-557)
// ---------------------------------------------------------------------------
//
// Determinism contract: pairs are walked in lockstep in invocation
// order. Each pair contributes its api.github.com / github.com
// template block to the shared `http_filters` arrays in pair order.
// `GET /user` and `GET /rate_limit` are appended once to
// api.github.com outside the fan-out.

/// Path template for one `(repo, pr)` pair on one host. Both
/// `${repo}` and `${pr}` are substituted at expand time.
struct PrTemplate {
    method: HttpMethod,
    path: &'static str,
}

/// github-pr templates for `api.github.com`. Spec lines 546-552.
const GITHUB_PR_API_TEMPLATES: &[PrTemplate] = &[
    PrTemplate {
        method: HttpMethod::Any,
        path: "/repos/${repo}/pulls/${pr}",
    },
    PrTemplate {
        method: HttpMethod::Any,
        path: "/repos/${repo}/pulls/${pr}/**",
    },
    PrTemplate {
        method: HttpMethod::Any,
        path: "/repos/${repo}/issues/${pr}",
    },
    PrTemplate {
        method: HttpMethod::Any,
        path: "/repos/${repo}/issues/${pr}/**",
    },
];

/// github-pr templates for `github.com` (PR UI paths). Spec lines
/// 554-555.
const GITHUB_PR_GITHUB_COM_TEMPLATES: &[PrTemplate] = &[
    PrTemplate {
        method: HttpMethod::Get,
        path: "/${repo}/pull/${pr}",
    },
    PrTemplate {
        method: HttpMethod::Get,
        path: "/${repo}/pull/${pr}/**",
    },
];

fn instantiate_pr_template(tmpl: &PrTemplate, repo: &str, pr: &str) -> HttpFilter {
    HttpFilter {
        method: tmpl.method,
        path: tmpl.path.replace("${repo}", repo).replace("${pr}", pr),
    }
}

fn expand_github_pr(inv: &ParsedInvocation) -> Result<Vec<PolicyRule>, PresetError> {
    // Collect repo and pr values in invocation order — preserving
    // order across keys is what makes the lockstep pairing work.
    let repos: Vec<&str> = inv
        .params
        .iter()
        .filter(|(k, _)| k == "repo")
        .map(|(_, v)| v.as_str())
        .collect();
    let prs: Vec<&str> = inv
        .params
        .iter()
        .filter(|(k, _)| k == "pr")
        .map(|(_, v)| v.as_str())
        .collect();

    if repos.is_empty() && prs.is_empty() {
        // Neither param was provided; surface the `repo` variant
        // first for determinism.
        return Err(PresetError::MissingRequiredParam {
            preset: "github-pr".to_string(),
            param: "repo".to_string(),
        });
    }
    if repos.is_empty() {
        return Err(PresetError::MissingRequiredParam {
            preset: "github-pr".to_string(),
            param: "repo".to_string(),
        });
    }
    if prs.is_empty() {
        return Err(PresetError::MissingRequiredParam {
            preset: "github-pr".to_string(),
            param: "pr".to_string(),
        });
    }
    if repos.len() != prs.len() {
        return Err(PresetError::UnbalancedPairedParams {
            preset: "github-pr".to_string(),
            a: "repo".to_string(),
            a_count: repos.len(),
            b: "pr".to_string(),
            b_count: prs.len(),
        });
    }

    // Validate every value up-front.
    for repo in &repos {
        if let Err(reason) = validate_repo_value(repo) {
            return Err(PresetError::InvalidRepoValue {
                preset: "github-pr".to_string(),
                value: (*repo).to_string(),
                reason,
            });
        }
    }
    for pr in &prs {
        if !is_positive_integer(pr) {
            return Err(PresetError::InvalidPrValue {
                preset: "github-pr".to_string(),
                value: (*pr).to_string(),
            });
        }
    }

    let pairs: Vec<(&str, &str)> = repos.iter().copied().zip(prs.iter().copied()).collect();

    let fan_out = |templates: &[PrTemplate]| -> Vec<HttpFilter> {
        let mut out = Vec::with_capacity(templates.len() * pairs.len());
        for (repo, pr) in &pairs {
            for tmpl in templates {
                out.push(instantiate_pr_template(tmpl, repo, pr));
            }
        }
        out
    };

    let mut api_github_com_filters = fan_out(GITHUB_PR_API_TEMPLATES);
    api_github_com_filters.extend(api_github_com_shared_probes());

    let github_com_filters = fan_out(GITHUB_PR_GITHUB_COM_TEMPLATES);

    Ok(vec![
        http_rule("api.github.com", api_github_com_filters),
        http_rule("github.com", github_com_filters),
    ])
}

/// Return true when `s` parses as a positive integer (≥ 1). Rejects
/// leading `+`, `-`, `0`, non-digits, empty input.
fn is_positive_integer(s: &str) -> bool {
    if s.is_empty() {
        return false;
    }
    if !s.chars().all(|c| c.is_ascii_digit()) {
        return false;
    }
    // Parse and check ≥ 1. `u64` is plenty for PR numbers.
    match s.parse::<u64>() {
        Ok(n) => n >= 1,
        Err(_) => false,
    }
}

// ---------------------------------------------------------------------------
// ubuntu (unparameterized)
// ---------------------------------------------------------------------------
//
// Default-allow rules an Ubuntu sandbox needs to function. Two
// concerns are covered:
//
//   * NTP — UDP/123 to the canonical Ubuntu pool / vendor hosts.
//     Sequencing note: the UDP allow-path datapath routes allowed
//     UDP direct to upstream via `policy_allow_udp`, with no Envoy
//     hop. Without that datapath this rule would fail closed at the
//     gateway; with it, the rule allows actual NTP traffic.
//
//   * apt — HTTPS/443 to the canonical Ubuntu mirrors used by stock
//     `/etc/apt/sources.list` on Ubuntu 22.04+. `tls`-level (not
//     `http`-level) because apt's debian-installer / signed-package
//     fetches are opaque blobs that don't benefit from
//     method/path-level inspection, and apt's transport already
//     verifies repo signatures end-to-end.
//
// Implementation-phase decisions:
//
//   * **HTTP/80 for first-boot apt: omitted.** Modern Ubuntu's stock
//     sources.list uses `https://` mirrors on 22.04+ (the test base
//     image is 24.04 per `lima.rs`), and apt's transport defaults
//     fetch over HTTPS first. Without an easy way to verify the
//     negative path on a fresh base image, the spec prescribes
//     defaulting to omit.
//
//   * **snap / livepatch / changelogs: omitted.** The spec says
//     scope by what an unmodified Ubuntu base image actually opens
//     during the first 60 s of boot + a sample `apt update` cycle;
//     without an easy way to measure that here, default to omit.
//     Real workloads that hit `api.snapcraft.io` etc. add a project
//     policy rule explicitly; the preset can grow later if those
//     hosts turn out to be load-bearing for the typical Ubuntu agent
//     workflow.
//
// The preset is unparameterized like `npm` / `pypi`. A future
// parameterized variant (`ubuntu:release=24.04` / `ubuntu:mirror=...`)
// is explicitly out of scope for v1.

/// NTP hosts for the `ubuntu` preset. UDP/123. The two canonical
/// vendor hosts published in `/etc/systemd/timesyncd.conf.d/` on a
/// fresh Ubuntu install.
const UBUNTU_NTP_HOSTS: &[&str] = &["ntp.ubuntu.com", "time.ubuntu.com"];

/// apt mirror hosts for the `ubuntu` preset. HTTPS/443. The two
/// canonical hosts referenced from a stock 22.04+ sources.list:
/// `archive.ubuntu.com` for the main / universe / multiverse
/// repositories and `security.ubuntu.com` for the
/// `*-security` repository.
const UBUNTU_APT_HOSTS: &[&str] = &["archive.ubuntu.com", "security.ubuntu.com"];

/// Build a UDP/transport rule for `(host, port)`. Mirrors the shape
/// `http_rule` / `tls_rule` use for TCP rules — kept as a tiny named
/// helper so the rule defaults (`reason: None`, transport-level)
/// stay in one place if the preset grows other UDP hosts later.
fn udp_transport_rule(host: &str, port: u16) -> PolicyRule {
    PolicyRule {
        host: Destination::Domain(host.to_string()),
        port,
        protocol: Protocol::Udp,
        reason: None,
        level: AssuranceLevel::Transport,
    }
}

fn expand_ubuntu(_inv: &ParsedInvocation) -> Result<Vec<PolicyRule>, PresetError> {
    let mut rules = Vec::with_capacity(UBUNTU_NTP_HOSTS.len() + UBUNTU_APT_HOSTS.len());
    // NTP — UDP/123, transport-level (no L7 to inspect).
    for host in UBUNTU_NTP_HOSTS {
        rules.push(udp_transport_rule(host, 123));
    }
    // apt mirrors — HTTPS/443. tls-level: apt fetches signed indexes
    // and packages whose URLs are deterministic but whose payloads
    // don't benefit from method/path-level inspection (apt verifies
    // signatures end-to-end above the transport).
    for host in UBUNTU_APT_HOSTS {
        rules.push(tls_rule(host));
    }
    Ok(rules)
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
        // 10 ecosystem presets + 1 `ubuntu` distro preset.
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

    /// Drift detection: the `cargo` built-in's host list AND its
    /// per-host method posture must match the frozen
    /// `tests/fixtures/cargo_fetch_trace.json` fixture. The fixture is
    /// the verified network surface of `cargo fetch` / `cargo build`
    /// against an empty cache on Rust 1.70+ (sparse-index default),
    /// scoped to the consume-only methods the preset is intended to
    /// allow.
    ///
    /// **Invariant (chosen path A — see todo #59).** Each domain host
    /// in the preset's expansion appears in the fixture with a
    /// `methods` array, and the set of methods emitted by the preset
    /// for that host is exactly equal to the fixture's set. Catches
    /// drift in both directions:
    ///   - preset adds a method (e.g. POST on `crates.io`) without
    ///     updating the fixture → test fails, forces a rationale;
    ///   - fixture is re-captured against a future cargo version that
    ///     uses a new method (e.g. PATCH on the sparse index) without
    ///     updating the preset → test fails, forces a preset edit.
    ///
    /// **Why per-method, not per-host alone.** The previous shape only
    /// compared host strings. A future cargo version that introduced a
    /// new HTTP method on an existing host (e.g. PATCH against the
    /// sparse index, or moving `cargo publish` to a different verb)
    /// would have left the fixture rotted while the test stayed green.
    /// The preset's posture is `(host, methods)`; the drift assertion
    /// matches.
    ///
    /// **Why sets, not method-list-as-vec.** The order of `HttpFilter`
    /// entries inside a preset rule is not load-bearing for any
    /// downstream consumer (mitmproxy / Envoy / nft only care about
    /// the membership). Comparing as sorted sets keeps the test
    /// resilient to a refactor that swaps GET-then-HEAD for
    /// HEAD-then-GET while still catching real drift.
    ///
    /// **Fixture `methods` semantics.** The `methods` field for each
    /// host encodes "what the consume-only preset should allow", not
    /// "every method the host's API technically accepts". For
    /// `crates.io` in particular, the host accepts POST / PUT /
    /// DELETE for publish / yank / owner management, but those
    /// mutating workflows are deliberately scoped to an explicit
    /// grant outside the built-in — see the fixture's `_comment`
    /// block for the rationale and the spec's "Known gaps" section.
    ///
    /// If you are intentionally changing the host set or per-host
    /// method posture, update the fixture in the same commit — the
    /// test asserts equality in both directions to catch adds and
    /// removes. Document the rationale in the fixture's leading
    /// `_comment` block and, if the change affects spec §"Known
    /// gaps", update that section too.
    #[test]
    fn cargo_preset_matches_frozen_trace() {
        use std::collections::BTreeMap;
        use std::collections::BTreeSet;

        // Resolve the fixture path relative to the crate root so the
        // test works from both `cargo test` and `cargo nextest run`
        // (nextest does not cd into the test's runtime dir).
        let fixture_path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/cargo_fetch_trace.json");
        let raw = std::fs::read_to_string(&fixture_path).unwrap_or_else(|e| {
            panic!(
                "failed to read cargo trace fixture at {}: {e}",
                fixture_path.display()
            )
        });
        let doc: serde_json::Value =
            serde_json::from_str(&raw).unwrap_or_else(|e| panic!("fixture is not valid JSON: {e}"));

        // Build a map host → BTreeSet<methods-as-uppercase-string> from
        // the fixture. Method strings are compared as their `Display`
        // form (`"GET"`, `"HEAD"`, ...) so we don't have to re-implement
        // a JSON-string -> HttpMethod parser here — the preset side
        // renders the same way via `HttpMethod::Display`.
        let fixture_methods: BTreeMap<String, BTreeSet<String>> = doc["hosts"]
            .as_array()
            .expect("`hosts` must be a JSON array")
            .iter()
            .map(|row| {
                let host = row["host"]
                    .as_str()
                    .expect("`hosts[].host` must be a string")
                    .to_string();
                let methods: BTreeSet<String> = row["methods"]
                    .as_array()
                    .unwrap_or_else(|| {
                        panic!("`hosts[].methods` must be a JSON array (host: {host})")
                    })
                    .iter()
                    .map(|m| {
                        m.as_str()
                            .unwrap_or_else(|| {
                                panic!("`hosts[].methods[]` must be a string (host: {host})")
                            })
                            .to_string()
                    })
                    .collect();
                assert!(
                    !methods.is_empty(),
                    "`hosts[].methods` must be non-empty (host: {host}); a host with no \
                     allowed methods would be dead weight in the preset"
                );
                (host, methods)
            })
            .collect();

        // Build the same shape from the preset expansion. The cargo
        // preset emits Domain + Http rules exclusively (asserted by
        // `expand_cargo_matches_spec` above), so a single match arm
        // covers every rule.
        let rules = expand_builtin("cargo", "cargo:");
        let preset_methods: BTreeMap<String, BTreeSet<String>> = rules
            .iter()
            .filter_map(|r| match (&r.host, &r.level) {
                (Destination::Domain(host), AssuranceLevel::Http { http_filters }) => {
                    let methods: BTreeSet<String> =
                        http_filters.iter().map(|f| f.method.to_string()).collect();
                    Some((host.clone(), methods))
                }
                _ => None,
            })
            .collect();

        // Single equality check first so the failure surface is the
        // whole map — easier to read at a glance than a per-host loop
        // when the preset adds or drops a host.
        if preset_methods != fixture_methods {
            // Build a per-host diff that names exactly which hosts'
            // method sets drifted. Engineers fixing the test can then
            // decide: update the preset (cargo really does use POST
            // now) or update the fixture (re-capture the trace).
            let mut diffs: Vec<String> = Vec::new();
            let all_hosts: BTreeSet<&String> = preset_methods
                .keys()
                .chain(fixture_methods.keys())
                .collect();
            for host in all_hosts {
                match (preset_methods.get(host), fixture_methods.get(host)) {
                    (Some(p), Some(f)) if p != f => {
                        diffs.push(format!("  host {host:?}: preset {p:?} != fixture {f:?}"));
                    }
                    (Some(p), None) => {
                        diffs.push(format!(
                            "  host {host:?}: preset has {p:?} but fixture has no entry"
                        ));
                    }
                    (None, Some(f)) => {
                        diffs.push(format!(
                            "  host {host:?}: fixture has {f:?} but preset emits no rule"
                        ));
                    }
                    _ => {}
                }
            }
            panic!(
                "`cargo` preset drifted from frozen fixture (per-host method posture).\n\
                 Drift:\n{}\n\
                 If this change is intentional, update \
                 `tests/fixtures/cargo_fetch_trace.json` in the same commit \
                 and document the rationale in the fixture's `_comment` block.\n\
                 See the test's docstring for the per-host method invariant.",
                diffs.join("\n")
            );
        }
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

    // ----- ubuntu (unparameterized) -----------------------------------

    /// The `ubuntu` preset is structurally distinct from every other
    /// unparameterized built-in: it mixes UDP/transport rules (NTP) with
    /// TCP/tls rules (apt mirrors), so it does not fit the
    /// `assert_consume_posture` shape used by `npm`/`pypi`/etc. The
    /// test asserts the expected rules explicitly — host, port,
    /// protocol, and assurance level — so a typo or shape drift fails
    /// loudly.
    #[test]
    fn expand_ubuntu_matches_spec() {
        let rules = expand_builtin("ubuntu", "ubuntu:");

        // Two NTP rules + two apt rules, in source-order. The preset
        // emits in a fixed sequence (UBUNTU_NTP_HOSTS then
        // UBUNTU_APT_HOSTS) so the test pins the order.
        assert_eq!(
            rules.len(),
            4,
            "ubuntu must emit four host rules (2 NTP + 2 apt mirrors); got {} rules: {rules:?}",
            rules.len()
        );

        // Rule 0: NTP — ntp.ubuntu.com:123/udp transport.
        let ntp_a = &rules[0];
        match &ntp_a.host {
            Destination::Domain(d) => assert_eq!(d, "ntp.ubuntu.com"),
            other => panic!("expected Domain(ntp.ubuntu.com), got {other:?}"),
        }
        assert_eq!(ntp_a.port, 123);
        assert_eq!(ntp_a.protocol, Protocol::Udp);
        assert_eq!(ntp_a.level, AssuranceLevel::Transport);

        // Rule 1: NTP — time.ubuntu.com:123/udp transport.
        let ntp_b = &rules[1];
        match &ntp_b.host {
            Destination::Domain(d) => assert_eq!(d, "time.ubuntu.com"),
            other => panic!("expected Domain(time.ubuntu.com), got {other:?}"),
        }
        assert_eq!(ntp_b.port, 123);
        assert_eq!(ntp_b.protocol, Protocol::Udp);
        assert_eq!(ntp_b.level, AssuranceLevel::Transport);

        // Rule 2: apt — archive.ubuntu.com:443/tcp tls.
        let apt_a = &rules[2];
        match &apt_a.host {
            Destination::Domain(d) => assert_eq!(d, "archive.ubuntu.com"),
            other => panic!("expected Domain(archive.ubuntu.com), got {other:?}"),
        }
        assert_eq!(apt_a.port, 443);
        assert_eq!(apt_a.protocol, Protocol::Tcp);
        assert_eq!(apt_a.level, AssuranceLevel::Tls);

        // Rule 3: apt — security.ubuntu.com:443/tcp tls.
        let apt_b = &rules[3];
        match &apt_b.host {
            Destination::Domain(d) => assert_eq!(d, "security.ubuntu.com"),
            other => panic!("expected Domain(security.ubuntu.com), got {other:?}"),
        }
        assert_eq!(apt_b.port, 443);
        assert_eq!(apt_b.protocol, Protocol::Tcp);
        assert_eq!(apt_b.level, AssuranceLevel::Tls);

        // The expansion must also be a structurally valid v2 policy on
        // its own — same round-trip check the other unparameterized
        // presets run.
        assert_rules_round_trip(rules);
    }

    /// The `ubuntu` preset must not surprise-overlap the default-deny
    /// baseline: every emitted rule's `(host, port)` identity is
    /// unique within the preset's expansion. This is the equivalent of
    /// the `(host, port)` uniqueness invariant `PolicyCompiler::validate`
    /// enforces across the merged effective policy — pinned here at
    /// the preset level so a future edit that accidentally duplicates
    /// `archive.ubuntu.com:443` (e.g. by adding both an `:80` and
    /// `:443` rule and getting one of them wrong) fails loudly in unit
    /// tests rather than only at preset-merge time when the operator
    /// runs `sandbox create`.
    #[test]
    fn ubuntu_preset_rules_are_unique_by_host_port() {
        use std::collections::HashSet;
        let rules = expand_builtin("ubuntu", "ubuntu:");
        let mut seen: HashSet<(String, u16)> = HashSet::new();
        for r in &rules {
            let key = (r.host.to_string(), r.port);
            assert!(
                seen.insert(key.clone()),
                "ubuntu preset emitted a duplicate (host, port) pair {key:?}: {rules:?}"
            );
        }
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

    // ----- github-repo (parameterized) --------------------------------

    /// Helper: find the first rule whose domain matches `host`.
    fn rule_for_host<'a>(rules: &'a [PolicyRule], host: &str) -> &'a PolicyRule {
        rules
            .iter()
            .find(|r| matches!(&r.host, Destination::Domain(d) if d == host))
            .unwrap_or_else(|| panic!("expected rule for host '{host}'"))
    }

    fn http_filters_of(rule: &PolicyRule) -> &[HttpFilter] {
        match &rule.level {
            AssuranceLevel::Http { http_filters } => http_filters.as_slice(),
            other => panic!("expected Http level, got {other:?}"),
        }
    }

    #[test]
    fn expand_github_repo_single_repo_emits_six_host_rules_with_substituted_paths() {
        let rules = expand_builtin("github-repo", "github-repo:repo=owner/proj");
        assert_eq!(
            rules.len(),
            6,
            "github-repo must emit six host rules (github.com, api.github.com, codeload, raw, objects, release-assets)"
        );

        // Domain hosts are emitted in a deterministic order.
        let domain_hosts: Vec<String> = rules
            .iter()
            .filter_map(|r| match &r.host {
                Destination::Domain(d) => Some(d.clone()),
                Destination::Cidr(_) => None,
            })
            .collect();
        assert_eq!(
            domain_hosts,
            vec![
                "github.com",
                "api.github.com",
                "codeload.github.com",
                "raw.githubusercontent.com",
                "objects.githubusercontent.com",
                "release-assets.githubusercontent.com",
            ]
        );

        // github.com: seven git-pack templates, each with `${repo}` -> `owner/proj`.
        let github_com = rule_for_host(&rules, "github.com");
        let filters = http_filters_of(github_com);
        assert_eq!(filters.len(), GITHUB_REPO_GITHUB_COM_TEMPLATES.len());
        for f in filters {
            assert!(
                f.path.contains("owner/proj"),
                "github.com path should carry the repo literal: {}",
                f.path
            );
            assert!(!f.path.contains("${repo}"), "unsubstituted token");
        }
        // Sanity: the expected method set (GET, HEAD, three POSTs on the
        // canonical form, GET + two POSTs on the no-.git form).
        assert_eq!(
            filters
                .iter()
                .filter(|f| f.method == HttpMethod::Post)
                .count(),
            4
        );

        // api.github.com: one per-repo ANY rule + two shared probes.
        let api = rule_for_host(&rules, "api.github.com");
        let api_filters = http_filters_of(api);
        assert_eq!(api_filters.len(), 1 + 2);
        assert_eq!(api_filters[0].method, HttpMethod::Any);
        assert_eq!(api_filters[0].path, "/repos/owner/proj/**");
        // Shared probes are appended at the end.
        assert_eq!(api_filters[1].method, HttpMethod::Get);
        assert_eq!(api_filters[1].path, "/user");
        assert_eq!(api_filters[2].method, HttpMethod::Get);
        assert_eq!(api_filters[2].path, "/rate_limit");

        // codeload + raw: GET+HEAD per-repo.
        for host in ["codeload.github.com", "raw.githubusercontent.com"] {
            let f = http_filters_of(rule_for_host(&rules, host));
            assert_eq!(f.len(), 2);
            assert_eq!(f[0].method, HttpMethod::Get);
            assert_eq!(f[0].path, "/owner/proj/**");
            assert_eq!(f[1].method, HttpMethod::Head);
            assert_eq!(f[1].path, "/owner/proj/**");
        }

        // Signed asset hosts: TLS-only (no http filters).
        for host in [
            "objects.githubusercontent.com",
            "release-assets.githubusercontent.com",
        ] {
            let rule = rule_for_host(&rules, host);
            assert!(
                matches!(rule.level, AssuranceLevel::Tls),
                "{host} should be tls-only, got {:?}",
                rule.level
            );
        }

        assert_rules_round_trip(rules);
    }

    #[test]
    fn expand_github_repo_multi_repo_fans_out_filters_in_invocation_order() {
        let rules = expand_builtin(
            "github-repo",
            "github-repo:repo=a/one,repo=b/two,repo=c/three",
        );

        let api = rule_for_host(&rules, "api.github.com");
        let api_filters = http_filters_of(api);
        // Three repo-specific ANY filters followed by two shared probes.
        assert_eq!(api_filters.len(), 3 + 2);
        assert_eq!(api_filters[0].path, "/repos/a/one/**");
        assert_eq!(api_filters[1].path, "/repos/b/two/**");
        assert_eq!(api_filters[2].path, "/repos/c/three/**");
        // Probes appear exactly once even with three repos.
        assert_eq!(api_filters[3].path, "/user");
        assert_eq!(api_filters[4].path, "/rate_limit");

        // codeload fans out each repo's GET+HEAD pair in invocation order.
        let codeload_filters = http_filters_of(rule_for_host(&rules, "codeload.github.com"));
        assert_eq!(codeload_filters.len(), 2 * 3);
        let paths: Vec<&str> = codeload_filters.iter().map(|f| f.path.as_str()).collect();
        assert_eq!(
            paths,
            vec![
                "/a/one/**",
                "/a/one/**",
                "/b/two/**",
                "/b/two/**",
                "/c/three/**",
                "/c/three/**",
            ]
        );

        assert_rules_round_trip(rules);
    }

    #[test]
    fn expand_github_repo_missing_repo_param_errors() {
        let preset = BUILTINS.iter().find(|b| b.name == "github-repo").unwrap();
        let inv = parse_inv("github-repo:");
        let err = (preset.expand)(&inv).expect_err("missing repo must error");
        match err {
            PresetError::MissingRequiredParam { preset, param } => {
                assert_eq!(preset, "github-repo");
                assert_eq!(param, "repo");
            }
            other => panic!("expected MissingRequiredParam, got {other:?}"),
        }
    }

    #[test]
    fn expand_github_repo_rejects_malformed_repo_value() {
        let preset = BUILTINS.iter().find(|b| b.name == "github-repo").unwrap();
        // No '/' → InvalidRepoValue.
        let inv = parse_inv("github-repo:repo=single-token");
        let err = (preset.expand)(&inv).expect_err("missing '/' must error");
        match err {
            PresetError::InvalidRepoValue { preset, value, .. } => {
                assert_eq!(preset, "github-repo");
                assert_eq!(value, "single-token");
            }
            other => panic!("expected InvalidRepoValue, got {other:?}"),
        }

        // Disallowed character → InvalidRepoValue.
        let inv = parse_inv("github-repo:repo=owner/proj$");
        let err = (preset.expand)(&inv).expect_err("disallowed char must error");
        match err {
            PresetError::InvalidRepoValue { value, reason, .. } => {
                assert_eq!(value, "owner/proj$");
                assert!(
                    reason.contains("disallowed character"),
                    "expected 'disallowed character' in reason: {reason}"
                );
            }
            other => panic!("expected InvalidRepoValue, got {other:?}"),
        }

        // Empty owner → InvalidRepoValue.
        let inv = parse_inv("github-repo:repo=/name");
        let err = (preset.expand)(&inv).expect_err("empty owner must error");
        match err {
            PresetError::InvalidRepoValue { reason, .. } => {
                assert!(
                    reason.contains("owner"),
                    "expected reason to mention 'owner': {reason}"
                );
            }
            other => panic!("expected InvalidRepoValue, got {other:?}"),
        }
    }

    // ----- github-pr (parameterized) ----------------------------------

    #[test]
    fn expand_github_pr_paired_repo_and_pr_emit_two_host_rules() {
        let rules = expand_builtin("github-pr", "github-pr:repo=owner/proj,pr=42");
        assert_eq!(rules.len(), 2);

        // api.github.com: four ANY per-pair filters + two shared probes.
        let api_filters = http_filters_of(rule_for_host(&rules, "api.github.com"));
        assert_eq!(api_filters.len(), 4 + 2);
        let api_paths: Vec<&str> = api_filters.iter().map(|f| f.path.as_str()).collect();
        assert_eq!(
            api_paths,
            vec![
                "/repos/owner/proj/pulls/42",
                "/repos/owner/proj/pulls/42/**",
                "/repos/owner/proj/issues/42",
                "/repos/owner/proj/issues/42/**",
                "/user",
                "/rate_limit",
            ]
        );
        for f in &api_filters[..4] {
            assert_eq!(f.method, HttpMethod::Any);
        }

        // github.com: two GET filters (PR UI).
        let github_filters = http_filters_of(rule_for_host(&rules, "github.com"));
        assert_eq!(github_filters.len(), 2);
        assert_eq!(github_filters[0].method, HttpMethod::Get);
        assert_eq!(github_filters[0].path, "/owner/proj/pull/42");
        assert_eq!(github_filters[1].method, HttpMethod::Get);
        assert_eq!(github_filters[1].path, "/owner/proj/pull/42/**");

        assert_rules_round_trip(rules);
    }

    #[test]
    fn expand_github_pr_multiple_pairs_walk_in_lockstep() {
        let rules = expand_builtin("github-pr", "github-pr:repo=a/one,pr=1,repo=b/two,pr=17");

        let api_filters = http_filters_of(rule_for_host(&rules, "api.github.com"));
        // 4 paths × 2 pairs + 2 shared probes.
        assert_eq!(api_filters.len(), 4 * 2 + 2);
        // Pair 0 filters come first, then pair 1 filters, then probes.
        let paths: Vec<&str> = api_filters.iter().map(|f| f.path.as_str()).collect();
        assert_eq!(
            paths,
            vec![
                "/repos/a/one/pulls/1",
                "/repos/a/one/pulls/1/**",
                "/repos/a/one/issues/1",
                "/repos/a/one/issues/1/**",
                "/repos/b/two/pulls/17",
                "/repos/b/two/pulls/17/**",
                "/repos/b/two/issues/17",
                "/repos/b/two/issues/17/**",
                "/user",
                "/rate_limit",
            ]
        );
    }

    #[test]
    fn expand_github_pr_missing_pr_param_errors() {
        let preset = BUILTINS.iter().find(|b| b.name == "github-pr").unwrap();
        let inv = parse_inv("github-pr:repo=owner/proj");
        let err = (preset.expand)(&inv).expect_err("missing pr must error");
        match err {
            PresetError::MissingRequiredParam { preset, param } => {
                assert_eq!(preset, "github-pr");
                assert_eq!(param, "pr");
            }
            other => panic!("expected MissingRequiredParam, got {other:?}"),
        }

        // Missing both → surface `repo` first for determinism.
        let inv = parse_inv("github-pr:");
        let err = (preset.expand)(&inv).expect_err("missing both must error");
        match err {
            PresetError::MissingRequiredParam { param, .. } => assert_eq!(param, "repo"),
            other => panic!("expected MissingRequiredParam, got {other:?}"),
        }
    }

    #[test]
    fn expand_github_pr_unbalanced_pair_counts_error() {
        let preset = BUILTINS.iter().find(|b| b.name == "github-pr").unwrap();
        let inv = parse_inv("github-pr:repo=a/one,pr=1,repo=b/two");
        let err = (preset.expand)(&inv).expect_err("unbalanced counts must error");
        match err {
            PresetError::UnbalancedPairedParams {
                preset,
                a,
                a_count,
                b,
                b_count,
            } => {
                assert_eq!(preset, "github-pr");
                assert_eq!(a, "repo");
                assert_eq!(a_count, 2);
                assert_eq!(b, "pr");
                assert_eq!(b_count, 1);
            }
            other => panic!("expected UnbalancedPairedParams, got {other:?}"),
        }
    }

    #[test]
    fn expand_github_pr_rejects_non_positive_integer_pr() {
        let preset = BUILTINS.iter().find(|b| b.name == "github-pr").unwrap();

        for bad in ["0", "-1", "abc", "1.0"] {
            let raw = format!("github-pr:repo=owner/proj,pr={bad}");
            let inv = parse_inv(&raw);
            let err = (preset.expand)(&inv)
                .err()
                .unwrap_or_else(|| panic!("pr='{bad}' must error but did not"));
            match err {
                PresetError::InvalidPrValue { preset, value } => {
                    assert_eq!(preset, "github-pr");
                    assert_eq!(value, bad);
                }
                other => panic!("expected InvalidPrValue for pr='{bad}', got {other:?}"),
            }
        }
    }

    #[test]
    fn is_positive_integer_accepts_one_rejects_zero_and_empty_and_signs() {
        assert!(is_positive_integer("1"));
        assert!(is_positive_integer("42"));
        assert!(is_positive_integer("1000000"));
        assert!(!is_positive_integer("0"));
        assert!(!is_positive_integer(""));
        assert!(!is_positive_integer("-1"));
        assert!(!is_positive_integer("+1"));
        assert!(!is_positive_integer("abc"));
        assert!(!is_positive_integer("1.0"));
    }
}
