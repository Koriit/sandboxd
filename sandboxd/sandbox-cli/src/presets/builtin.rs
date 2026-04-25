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
//! The 10 entries mirror Part 2 of the spec at
//! `.tasks/specs/2026-04-21-port-explicit-policies-presets-observability-design.md`
//! lines 428-568. The plain `github` preset unifies the two rows in
//! the spec's table (interactive hosts + asset CDN) under a single
//! preset name; operators who need narrower scope than `github:`
//! use `github-repo` / `github-pr` instead.
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

/// Build an `http`-level rule for `(cidr, 443, tcp)` with the given
/// method-filter set. Used by the github-repo preset to emit CIDR
/// rules covering GitHub's interactive-infrastructure pool — see
/// [`GITHUB_INTERACTIVE_CIDR_POOL`].
fn http_rule_cidr(cidr: &str, filters: Vec<HttpFilter>) -> PolicyRule {
    PolicyRule {
        host: Destination::Cidr(cidr.to_string()),
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
    let mut rules = consume_rules(&["crates.io", "index.crates.io", "static.crates.io"]);

    // DNS-rotation resilience: `index.crates.io` and `static.crates.io`
    // are served from Fastly's Anycast pool. Fastly publishes a low TTL
    // (≤2s on these hostnames at time of writing), and consecutive
    // resolutions from a guest VM's `getaddrinfo` can land on a
    // different Fastly POP than the one CoreDNS observed and reported
    // to sandboxd's nft propagation loop — so the v2 `policy_allow_tcp`
    // set is keyed on a stale IP set, and the curl that follows hits
    // the deny-logger and gets RST. The propagation loop's 2s poll
    // cannot reliably out-pace a TTL=2s rotation. Adding CIDR-host
    // rules covering the Fastly Anycast ranges admits all rotated IPs
    // at L3 and routes them through Envoy + mitmproxy, where the
    // domain rules (`host: index.crates.io`, ...) drive the HTTP-level
    // allow/deny decision. See [`CARGO_FASTLY_CIDR_POOL`] for the
    // ranges and rationale.
    let crates_io_filters = method::get_head();
    for cidr in CARGO_FASTLY_CIDR_POOL {
        rules.push(http_rule_cidr(cidr, crates_io_filters.clone()));
    }
    Ok(rules)
}

/// Fastly's published Anycast IPv4 pool serving `index.crates.io` and
/// `static.crates.io`.
///
/// Sourced from Fastly's public IP ranges
/// (`https://api.fastly.com/public-ip-list`); the two `/16`-class
/// supernets below collapse the dozens of Fastly POPs that crates.io's
/// CDN rotates through under DNS-based load balancing into the
/// minimal-viable allow-set. The v2 `policy_allow_tcp` nftables set is
/// keyed on the IP at the moment CoreDNS resolves the hostname, so a
/// guest that re-resolves `index.crates.io` between the propagation
/// loop's 2s ticks (Fastly TTL is ≤2s) can land on an IP outside the
/// cached set and get RST by the deny-logger. The CIDR rules emitted
/// from this pool give Envoy an L3 filter chain for those rotated-out
/// IPs, routing them through mitmproxy where the domain rules drive
/// the actual allow/deny decision.
///
/// `crates.io` (the redirector) is **not** Fastly-fronted — it
/// resolves to AWS / CloudFront IPs. We deliberately do not allow
/// AWS supernets here: the redirector's typical workflow returns a
/// 302 to `static.crates.io` quickly, the daemon's 2s poll picks up
/// the AWS IPs once observed, and any over-broad CIDR (e.g.
/// `3.0.0.0/8`) would let unrelated AWS infrastructure land in the
/// L3 chain — counter to least-privilege. The Fastly pool is the
/// minimum needed to fix the observed rotation race.
///
/// **Contract.** Each CIDR rule is `AssuranceLevel::Http` so it
/// generates an L3 (mitmproxy) filter chain in the Envoy listener.
/// mitmproxy then matches the request against the *domain* rules
/// (`host: index.crates.io`, `host: static.crates.io`) by fnmatch on
/// the HTTP `Host` header — a CIDR-string `host` never matches a
/// hostname, so the CIDR rule's `http_filters` list is structurally
/// required (validate rejects empty `http_filters`) but is dead at
/// runtime. We mirror the consume-posture filter shape (`GET /**`,
/// `HEAD /**`) so a future code path that *did* match by IP would
/// still scope to the same allowed surface.
const CARGO_FASTLY_CIDR_POOL: &[&str] = &[
    // Fastly Anycast — primary supernet that contains the
    // 151.101.x.137 IP set observed in pcap from a real
    // `cargo fetch` against `static.crates.io`.
    "151.101.0.0/16",
    // Fastly Anycast — secondary supernet that contains the
    // 146.75.x.137 IP set observed from `index.crates.io`.
    "146.75.0.0/17",
];

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

/// GitHub's published interactive-infrastructure IPv4 CIDR pool.
///
/// Sourced from `https://api.github.com/meta` (the `git`/`web` arrays).
/// These two ranges cover the IP addresses that `github.com`,
/// `codeload.github.com`, and `api.github.com` rotate through under
/// DNS-based load balancing — the v2 schema's per-`(host, port)`
/// nftables allow-set is keyed on the IP at the moment of CoreDNS
/// resolution, so a client that resolves `github.com` independently
/// (typical for `git`'s in-VM `getaddrinfo`) can land on an IP that
/// isn't in the gateway's cached set. See todo #39 in
/// `docs/internal/milestones/M10.md`.
///
/// The `185.199.108.0/22` (Pages CDN, raw.githubusercontent.com) and
/// `143.55.64.0/20` (additional infrastructure) ranges are deliberately
/// **excluded** from this pool: this preset routes
/// `objects.githubusercontent.com` and `release-assets.githubusercontent.com`
/// through TLS passthrough (`AssuranceLevel::Tls`) so they can hold
/// signed-URL integrity, and a CIDR allow-rule whose IP space happens to
/// overlap with those Fastly/Pages CDNs would risk pulling those flows
/// through mitmproxy via the L3 listener chain. Keeping the pool
/// constrained to the well-known interactive ranges (`140.82.112.0/20`
/// + `192.30.252.0/22`) makes the rotation-resilience fix targeted and
/// reversible.
///
/// **Contract.** A CIDR rule emitted from this pool is at
/// `AssuranceLevel::Http` so it generates an L3 (mitmproxy) filter
/// chain in the Envoy listener — that's the routing target for any
/// VM-resolved IP that landed outside the cached `github.com` set.
/// mitmproxy then matches the request against the *domain* rules
/// (`host: github.com`, `host: api.github.com`, `host: codeload.github.com`)
/// via fnmatch on the HTTP `Host` header — a CIDR-string `host`
/// (e.g. `"140.82.112.0/20"`) never matches a hostname, so the CIDR
/// rule's `http_filters` list is structurally required (validate
/// rejects empty `http_filters`) but never exercised at runtime.
/// We mirror the `github.com` filter shape on the CIDR rule so a
/// future code path that *did* match by IP (e.g. a CIDR-aware host
/// matcher) would still scope to the same allowed git-over-HTTPS
/// surface.
const GITHUB_INTERACTIVE_CIDR_POOL: &[&str] = &[
    // Primary GitHub infrastructure pool — github.com, codeload, api,
    // www. By far the most common rotation destination today.
    "140.82.112.0/20",
    // Legacy GitHub primary range; kept on the allow-set so historic
    // resolutions still pass.
    "192.30.252.0/22",
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

    let mut rules = vec![
        http_rule("github.com", github_com_filters.clone()),
        http_rule("api.github.com", api_github_com_filters),
        http_rule("codeload.github.com", codeload_filters),
        http_rule("raw.githubusercontent.com", raw_filters),
        // Signed, opaque release-asset URLs: `tls` is the tightest
        // workable level (spec lines 518-522).
        tls_rule("objects.githubusercontent.com"),
        tls_rule("release-assets.githubusercontent.com"),
    ];

    // DNS-rotation resilience: GitHub's interactive infrastructure
    // (github.com, codeload, api) load-balances across a rotating IPv4
    // pool. The v2 nftables allow-set is keyed on the IPs CoreDNS
    // resolved at the moment the propagation loop ran; a `git clone`
    // running its own `getaddrinfo` inside the VM can land on a
    // rotation that is not in the cached set, producing an L3 deny
    // (deny-logger) instead of an L7 deny (mitmproxy) when the path
    // does not match the preset's `${repo}` filters. Adding CIDR-host
    // rules covering the published pool admits those rotated-out IPs
    // at L3 + Envoy and routes them through mitmproxy where the
    // domain rule (`host: github.com`, ...) applies the path filter.
    // See todo #39 in `docs/internal/milestones/M10.md`.
    for cidr in GITHUB_INTERACTIVE_CIDR_POOL {
        rules.push(http_rule_cidr(cidr, github_com_filters.clone()));
    }

    Ok(rules)
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
    fn builtins_has_ten_entries() {
        assert_eq!(BUILTINS.len(), 10);
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

        // The cargo preset emits one consume-posture rule per domain
        // host (crates.io, index.crates.io, static.crates.io) plus one
        // CIDR-host rule per entry in the Fastly Anycast pool. The
        // domain rules carry the spec-mandated `(GET, HEAD) /**`
        // posture; the CIDR rules are exercised in
        // `expand_cargo_emits_cidr_pool_rules_at_http_level` below.
        let domain_rules: Vec<&PolicyRule> = rules
            .iter()
            .filter(|r| matches!(&r.host, Destination::Domain(_)))
            .collect();
        assert_eq!(domain_rules.len(), 3);
        let expected_hosts = ["crates.io", "index.crates.io", "static.crates.io"];
        for (rule, expected_host) in domain_rules.iter().zip(expected_hosts.iter()) {
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
        assert_rules_round_trip(rules);
    }

    /// Drift detection: the `cargo` built-in's host list must match the
    /// frozen `tests/fixtures/cargo_fetch_trace.json` fixture line for
    /// line. The fixture is the verified network surface of `cargo
    /// fetch` / `cargo build` against an empty cache on Rust 1.70+
    /// (sparse-index default).
    ///
    /// If you are intentionally changing the host set, update the
    /// fixture in the same commit — the test asserts equality in both
    /// directions to catch adds and removes. Document the rationale in
    /// the fixture's leading `_comment` block and, if the change
    /// affects spec §"Known gaps", update that section too.
    #[test]
    fn cargo_preset_matches_frozen_trace() {
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

        // Extract the `hosts[].host` list from the fixture.
        let fixture_hosts: Vec<String> = doc["hosts"]
            .as_array()
            .expect("`hosts` must be a JSON array")
            .iter()
            .map(|row| {
                row["host"]
                    .as_str()
                    .expect("`hosts[].host` must be a string")
                    .to_string()
            })
            .collect();

        // Build the preset's domain-host list by expanding and
        // collecting the unique domain strings from the emitted rules.
        // CIDR-host rules (the Fastly Anycast pool) are intentionally
        // excluded — the frozen fixture is a *hostname* trace; the
        // CIDR rules' coverage is validated by
        // `cargo_fastly_cidr_pool_covers_published_ranges` below.
        let rules = expand_builtin("cargo", "cargo:");
        let mut preset_hosts: Vec<String> = rules
            .iter()
            .filter_map(|r| match &r.host {
                Destination::Domain(d) => Some(d.clone()),
                Destination::Cidr(_) => None,
            })
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .collect();
        preset_hosts.sort();

        let mut expected = fixture_hosts.clone();
        expected.sort();

        assert_eq!(
            preset_hosts, expected,
            "`cargo` preset host list drifted from frozen fixture.\n\
             fixture hosts:\n  {expected:?}\n\
             preset hosts:\n  {preset_hosts:?}\n\
             If this change is intentional, update \
             `tests/fixtures/cargo_fetch_trace.json` in the same commit \
             and document the rationale."
        );
    }

    /// DNS-rotation resilience (todo #40): each entry in
    /// [`CARGO_FASTLY_CIDR_POOL`] becomes an HTTP-level
    /// `Destination::Cidr` rule on `(<cidr>, 443, tcp)` whose
    /// `http_filters` mirror the consume-posture (`GET /**`, `HEAD /**`)
    /// shape of the domain rules. This is the targeted fix for the
    /// `test_cargo_preset_allows_cargo_fetch` E2E flake — the
    /// CIDR rules let the `policy_allow_tcp` nft set admit any IP in
    /// Fastly's published Anycast pool, so a `cargo fetch` whose
    /// in-VM resolver lands on a rotated POP between the daemon's 2s
    /// propagation polls still reaches Envoy + mitmproxy where the
    /// host-header allow/deny decision happens.
    #[test]
    fn expand_cargo_emits_cidr_pool_rules_at_http_level() {
        let rules = expand_builtin("cargo", "cargo:");

        // Pull out the CIDR-host rules in declaration order.
        let cidr_rules: Vec<&PolicyRule> = rules
            .iter()
            .filter(|r| matches!(&r.host, Destination::Cidr(_)))
            .collect();
        assert_eq!(
            cidr_rules.len(),
            CARGO_FASTLY_CIDR_POOL.len(),
            "one rule per pool entry — got {} rules for {} pool entries",
            cidr_rules.len(),
            CARGO_FASTLY_CIDR_POOL.len(),
        );

        let expected_filters = method::get_head();

        for (rule, expected_cidr) in cidr_rules.iter().zip(CARGO_FASTLY_CIDR_POOL.iter()) {
            // Host is a CIDR with the exact pool value and order.
            match &rule.host {
                Destination::Cidr(c) => assert_eq!(c, expected_cidr),
                other => panic!("expected Cidr({expected_cidr}), got {other:?}"),
            }
            assert_eq!(rule.port, 443);
            assert_eq!(rule.protocol, Protocol::Tcp);
            // Level is Http with the consume-posture filter shape —
            // that's what gives Envoy an L3 chain routing the
            // (rotated-out) IP through mitmproxy. The filter list
            // itself is dead at runtime (mitmproxy host-matches by
            // fnmatch on the request's HTTP `Host` header, never a
            // CIDR string) but must be non-empty for
            // `PolicyCompiler::validate` to accept the rule shape.
            match &rule.level {
                AssuranceLevel::Http { http_filters } => {
                    assert_eq!(
                        *http_filters, expected_filters,
                        "CIDR rule's http_filters must mirror the consume-posture (GET, HEAD)"
                    );
                }
                other => panic!("expected Http level on CIDR rule, got {other:?}"),
            }
        }

        // The expanded policy must round-trip through the validator: a
        // CIDR-host rule alongside the existing domain rules is a legal
        // v2 shape (no `(host, port)` collisions because each CIDR
        // string and each domain is a distinct host key).
        assert_rules_round_trip(rules);
    }

    /// Pin that the CIDR rules cover Fastly's published Anycast IPv4
    /// pool. The Fastly public ranges (sourced from
    /// `https://api.fastly.com/public-ip-list`) include
    /// `151.101.0.0/16` and `146.75.0.0/17` — these supernets contain
    /// every `151.101.x.137` and `146.75.x.137` rotation we observed
    /// during the M10-S8 cargo-preset flake investigation. Pin both
    /// entries so a future intentional change requires updating this
    /// test.
    #[test]
    fn cargo_fastly_cidr_pool_covers_published_ranges() {
        assert!(
            CARGO_FASTLY_CIDR_POOL.contains(&"151.101.0.0/16"),
            "primary Fastly Anycast supernet 151.101.0.0/16 must be in the CIDR pool"
        );
        assert!(
            CARGO_FASTLY_CIDR_POOL.contains(&"146.75.0.0/17"),
            "secondary Fastly Anycast supernet 146.75.0.0/17 must be in the CIDR pool"
        );
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
            6 + GITHUB_INTERACTIVE_CIDR_POOL.len(),
            "github-repo must emit six host rules (github.com, api.github.com, codeload, raw, objects, release-assets) plus one CIDR-host rule per entry in the GitHub interactive-infrastructure pool"
        );

        // Domain hosts are emitted in a deterministic order, followed
        // by the CIDR pool entries appended at the tail.
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
        let cidr_hosts: Vec<String> = rules
            .iter()
            .filter_map(|r| match &r.host {
                Destination::Cidr(c) => Some(c.clone()),
                Destination::Domain(_) => None,
            })
            .collect();
        assert_eq!(
            cidr_hosts,
            GITHUB_INTERACTIVE_CIDR_POOL
                .iter()
                .map(|s| s.to_string())
                .collect::<Vec<_>>(),
            "CIDR-host rules must be emitted in the order declared by GITHUB_INTERACTIVE_CIDR_POOL"
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

    /// DNS-rotation resilience (todo #39): each entry in
    /// [`GITHUB_INTERACTIVE_CIDR_POOL`] becomes an HTTP-level
    /// `Destination::Cidr` rule on `(<cidr>, 443, tcp)` whose
    /// `http_filters` mirror the `github.com` git-pack template set.
    /// This is the targeted fix for the
    /// `test_github_repo_preset_scopes_to_one_repo` E2E flake — the
    /// CIDR rules let the `policy_allow_tcp` nft set admit any IP in
    /// the published GitHub interactive pool, so a `git clone` whose
    /// in-VM resolver lands on a rotated-out IP still reaches Envoy +
    /// mitmproxy where the path-level allow/deny decision happens.
    #[test]
    fn expand_github_repo_emits_cidr_pool_rules_at_http_level() {
        let rules = expand_builtin("github-repo", "github-repo:repo=owner/proj");

        // Pull out the CIDR-host rules in declaration order.
        let cidr_rules: Vec<&PolicyRule> = rules
            .iter()
            .filter(|r| matches!(&r.host, Destination::Cidr(_)))
            .collect();
        assert_eq!(
            cidr_rules.len(),
            GITHUB_INTERACTIVE_CIDR_POOL.len(),
            "one rule per pool entry — got {} rules for {} pool entries",
            cidr_rules.len(),
            GITHUB_INTERACTIVE_CIDR_POOL.len(),
        );

        // The expected http_filters shape — same as the github.com
        // domain rule, since mitmproxy never reaches the CIDR rule
        // (its `host` is a CIDR string, never matches a hostname);
        // the filters are kept consistent so a future code path that
        // matches by IP would still scope to the per-repo surface.
        let github_com_filters = http_filters_of(rule_for_host(&rules, "github.com")).to_vec();

        for (rule, expected_cidr) in cidr_rules.iter().zip(GITHUB_INTERACTIVE_CIDR_POOL.iter()) {
            // Host is a CIDR with the exact pool value.
            match &rule.host {
                Destination::Cidr(c) => assert_eq!(c, expected_cidr),
                other => panic!("expected Cidr({expected_cidr}), got {other:?}"),
            }
            assert_eq!(rule.port, 443);
            assert_eq!(rule.protocol, Protocol::Tcp);
            // Level is Http with the github.com filter shape — that's
            // what gives Envoy an L3 chain routing the (rotated-out)
            // IP through mitmproxy. The filter list itself is dead
            // (mitmproxy host-matches by fnmatch on the request's
            // HTTP `Host` header, never a CIDR string) but must be
            // non-empty for `PolicyCompiler::validate` to accept the
            // rule shape.
            match &rule.level {
                AssuranceLevel::Http { http_filters } => {
                    assert_eq!(
                        http_filters, &github_com_filters,
                        "CIDR rule's http_filters must mirror github.com's git-pack template set"
                    );
                }
                other => panic!("expected Http level on CIDR rule, got {other:?}"),
            }
        }

        // The expanded policy must round-trip through the validator:
        // a CIDR-host rule alongside the existing domain rules is a
        // legal v2 shape (no `(host, port)` collisions because each
        // CIDR string and each domain is a distinct host key).
        assert_rules_round_trip(rules);
    }

    /// Pin that the CIDR rules cover the known github.com IP space.
    /// `140.82.112.0/20` covers `140.82.112.0` through `140.82.127.255`
    /// — the rotation pool seen in the M10-S6 regression handoff
    /// (`140.82.121.4` was the failing IP).
    #[test]
    fn github_interactive_cidr_pool_covers_published_ranges() {
        // The two ranges below are the only published IPv4 ranges
        // shared across the `git` and `web` arrays in
        // `https://api.github.com/meta` that map to GitHub's own
        // interactive infrastructure (i.e. excluding the Pages /
        // Fastly / Azure CDN-backed `*.githubusercontent.com` pools).
        // Pin both ends so a future intentional change to the pool
        // still requires updating this test.
        assert!(
            GITHUB_INTERACTIVE_CIDR_POOL.contains(&"140.82.112.0/20"),
            "primary GitHub pool 140.82.112.0/20 must be in the CIDR pool"
        );
        assert!(
            GITHUB_INTERACTIVE_CIDR_POOL.contains(&"192.30.252.0/22"),
            "legacy GitHub pool 192.30.252.0/22 must be in the CIDR pool"
        );
    }

    /// Multi-repo invocation must keep the CIDR-pool rules emitted
    /// exactly once at the tail (the pool does not depend on `${repo}`,
    /// so it must not fan out per-repo — that would produce
    /// `(<cidr>, 443)` collisions in `merge_effective`).
    #[test]
    fn expand_github_repo_multi_repo_emits_cidr_pool_once() {
        let rules = expand_builtin(
            "github-repo",
            "github-repo:repo=a/one,repo=b/two,repo=c/three",
        );

        let cidr_rules: Vec<&PolicyRule> = rules
            .iter()
            .filter(|r| matches!(&r.host, Destination::Cidr(_)))
            .collect();
        assert_eq!(
            cidr_rules.len(),
            GITHUB_INTERACTIVE_CIDR_POOL.len(),
            "CIDR-pool rules must be emitted exactly once regardless of repo count, \
             got {} rules for {} pool entries on a 3-repo invocation",
            cidr_rules.len(),
            GITHUB_INTERACTIVE_CIDR_POOL.len(),
        );

        // The expanded policy must still round-trip through the
        // validator under multi-repo expansion (no
        // `(host, port)` duplicates).
        assert_rules_round_trip(rules);
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
