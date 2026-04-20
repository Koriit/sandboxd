use std::collections::HashMap;
use std::fmt;
use std::net::Ipv4Addr;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::error::SandboxError;
use crate::network::NetworkInfo;

// ---------------------------------------------------------------------------
// Schema version
// ---------------------------------------------------------------------------

/// Current policy schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

// ---------------------------------------------------------------------------
// Policy document types
// ---------------------------------------------------------------------------

/// Top-level policy document.
///
/// A policy contains an ordered list of rules that are evaluated to determine
/// which network destinations are allowed and at what assurance level. The
/// default (unmatched) destination is deny-all (level 0).
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct Policy {
    /// Schema version (semver). Must be compatible with [`SCHEMA_VERSION`].
    pub version: String,
    /// Policy rules, evaluated in order.
    pub rules: Vec<PolicyRule>,
}

impl Policy {
    /// Construct the synthetic **unrestricted** policy — a single Http rule
    /// allowing any method on any path for any destination.
    ///
    /// This is a real [`Policy`] value (not a sentinel / separate variant /
    /// sidecar flag): it round-trips through the DTO + store layers like any
    /// user-authored policy.  Compiled output is permissive **and** logged
    /// through mitmproxy — callers get a structured audit trail of every
    /// request.  Used by `sandbox create --unrestricted` and
    /// `sandbox policy update --unrestricted`.
    pub fn unrestricted() -> Policy {
        Policy {
            version: SCHEMA_VERSION.to_string(),
            rules: vec![PolicyRule {
                destination: Destination::Domain("*".to_string()),
                level: AssuranceLevel::Http {
                    http_filters: vec![HttpFilter {
                        method: HttpMethod::Any,
                        path: "/*".to_string(),
                    }],
                },
                protocol: Protocol::Any,
                reason: Some("unrestricted network access (logged)".to_string()),
            }],
        }
    }

    /// Return `true` when this policy matches the exact shape produced by
    /// [`Policy::unrestricted`]: a single Http rule on wildcard destination
    /// `*` with an `ANY /*` filter.
    ///
    /// Used by the `describe` renderer to print the `unrestricted (logged)`
    /// sentinel line instead of a full rule block.  Extra fields (`reason`,
    /// `protocol`) are ignored to keep the detection stable against cosmetic
    /// edits.
    pub fn is_unrestricted(&self) -> bool {
        if self.rules.len() != 1 {
            return false;
        }
        let rule = &self.rules[0];
        if !matches!(&rule.destination, Destination::Domain(d) if d == "*") {
            return false;
        }
        match &rule.level {
            AssuranceLevel::Http { http_filters } => {
                http_filters.len() == 1
                    && http_filters[0].method == HttpMethod::Any
                    && http_filters[0].path == "/*"
            }
            _ => false,
        }
    }
}

/// A single policy rule describing the allowed assurance level for a
/// destination.
///
/// The wire format is flat: the assurance level's tag (`"level"`) and any
/// per-variant data (currently `http_filters` for the `http` level) live
/// alongside `destination`, `protocol`, and `reason` at the rule object's
/// top level.  Example:
///
/// ```json
/// {
///   "destination": "github.com",
///   "protocol": "tcp",
///   "level": "http",
///   "http_filters": [{"method": "GET", "path": "/*"}]
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct PolicyRule {
    /// Destination: domain name, IP address, or CIDR block.
    pub destination: Destination,
    /// Protocol constraint.
    #[serde(default = "default_protocol")]
    pub protocol: Protocol,
    /// Human-readable reason for the rule.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Assurance level, flattened into the rule object.
    ///
    /// Deserializes from the `level` tag at the rule object's top level.
    /// For `http`, the `http_filters` array is read from the same level
    /// (not from a nested `constraints` object).
    #[serde(flatten)]
    pub level: AssuranceLevel,
}

/// Assurance level for a destination.
///
/// Each level provides different visibility and control over the traffic:
/// - **Deny** (0): No traffic allowed.
/// - **Transport** (1): Opaque TCP/UDP passthrough. No inspection.
/// - **Tls** (2): TLS-verified passthrough. SNI extraction, no MITM.
/// - **Http** (3): HTTPS through mitmproxy (MITM with session CA), with
///   `(method, path)` filter pairs enforced on every request.
///
/// The variant is tagged with a `"level"` discriminator on the wire.  When
/// flattened into a [`PolicyRule`], variant-carried data (`http_filters`)
/// appears alongside the tag at the rule object's top level.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(tag = "level", rename_all = "snake_case")]
pub enum AssuranceLevel {
    Deny,
    Transport,
    Tls,
    Http {
        /// Ordered list of `(method, path)` filter pairs.  Each incoming
        /// request is matched against the filters in order; the first pair
        /// whose method and path both match permits the request.  Must be
        /// non-empty (validated by [`PolicyCompiler::compile`]).
        http_filters: Vec<HttpFilter>,
    },
}

impl AssuranceLevel {
    /// Return the numeric value (0-3) of this assurance level.
    pub fn as_u8(&self) -> u8 {
        match self {
            Self::Deny => 0,
            Self::Transport => 1,
            Self::Tls => 2,
            Self::Http { .. } => 3,
        }
    }

    /// Return a stable short name for the variant (independent of any
    /// per-variant data).  Used for contradiction detection, where we want
    /// to compare levels without comparing `http_filters` content.
    pub fn variant_name(&self) -> &'static str {
        match self {
            Self::Deny => "deny",
            Self::Transport => "transport",
            Self::Tls => "tls",
            Self::Http { .. } => "http",
        }
    }
}

impl fmt::Display for AssuranceLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.variant_name())
    }
}

// Custom `Deserialize` impl for `AssuranceLevel` that emits a clear,
// targeted error when callers pass the old (pre-M9-S10) rule shape:
//
//   { "level": "full", "constraints": { "methods": [...], "paths": [...] } }
//
// Without this impl serde's default message would be
// "unknown variant `full`, expected one of `deny`, `transport`, `tls`, `http`",
// which is accurate but does not tell the caller where to put their methods
// and paths.  We spell it out.
impl<'de> Deserialize<'de> for AssuranceLevel {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::Error as _;

        // Materialize into a generic JSON value so we can:
        //   1. detect the legacy shape and return a targeted error,
        //   2. fall back to standard tagged-enum deserialization on the
        //      modern shape.
        let value = serde_json::Value::deserialize(deserializer)?;

        let obj = value.as_object().ok_or_else(|| {
            D::Error::custom(
                "AssuranceLevel must be an object with a `level` tag; \
                 expected one of `deny`, `transport`, `tls`, `http`",
            )
        })?;

        let level_tag = obj.get("level").and_then(|v| v.as_str());

        // Legacy sentinel: `"full"` was renamed to `"http"` in M9-S10 and
        // the `constraints: {methods, paths}` wrapper was replaced by a
        // flat `http_filters: [{method, path}, ...]` array.
        if level_tag == Some("full") {
            return Err(D::Error::custom(
                "policy rule uses legacy level `full` — rename to `http` and \
                 replace `constraints: {methods, paths}` with a flat \
                 `http_filters: [{method, path}, ...]` array",
            ));
        }

        // Any `constraints` field is a leftover from the legacy shape,
        // regardless of the current `level` value.  Surface it explicitly.
        if obj.contains_key("constraints") {
            return Err(D::Error::custom(
                "policy rule contains legacy `constraints` field — replace \
                 with `http_filters: [{method, path}, ...]` on an `http` \
                 level rule",
            ));
        }

        // Happy path: delegate to the derived tagged-enum deserializer.
        // We re-derive it on a private shadow type to avoid infinite
        // recursion through this impl.
        #[derive(Deserialize)]
        #[serde(tag = "level", rename_all = "snake_case")]
        enum Shadow {
            Deny,
            Transport,
            Tls,
            Http { http_filters: Vec<HttpFilter> },
        }

        let shadow = Shadow::deserialize(value).map_err(D::Error::custom)?;
        Ok(match shadow {
            Shadow::Deny => AssuranceLevel::Deny,
            Shadow::Transport => AssuranceLevel::Transport,
            Shadow::Tls => AssuranceLevel::Tls,
            Shadow::Http { http_filters } => AssuranceLevel::Http { http_filters },
        })
    }
}

/// A single HTTP method/path filter pair for an `http`-level rule.
///
/// Matching is evaluated as a pair: both `method` and `path` must match
/// for the filter to permit the request.  This is different from the
/// pre-M9-S10 shape that held two independent vectors and allowed any
/// combination — the new shape can express "GET /foo but POST /bar".
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct HttpFilter {
    /// Allowed HTTP method.
    pub method: HttpMethod,
    /// Allowed path glob pattern.  Supports `fnmatch`-style wildcards
    /// (`*`, `?`, `[...]`).  Examples: `/api/*`, `/*`, `/repos/?/commits`.
    pub path: String,
}

/// HTTP method accepted by an [`HttpFilter`].  Closed enum — no free-form
/// strings.  Use [`HttpMethod::Any`] as an explicit wildcard instead of
/// "empty means everything".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "UPPERCASE")]
pub enum HttpMethod {
    Get,
    Post,
    Put,
    Delete,
    Patch,
    Head,
    Options,
    Trace,
    Connect,
    /// Explicit "any method" marker.  Equivalent to listing every other
    /// variant; an empty filter list is never treated as "match all".
    Any,
}

impl fmt::Display for HttpMethod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Get => "GET",
            Self::Post => "POST",
            Self::Put => "PUT",
            Self::Delete => "DELETE",
            Self::Patch => "PATCH",
            Self::Head => "HEAD",
            Self::Options => "OPTIONS",
            Self::Trace => "TRACE",
            Self::Connect => "CONNECT",
            Self::Any => "ANY",
        })
    }
}

/// Destination for a policy rule.
///
/// Deserialized as an untagged enum: plain strings are interpreted as domains
/// if they contain no `/`, otherwise as CIDR blocks.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(try_from = "String", into = "String")]
pub enum Destination {
    /// Domain name (e.g. `"github.com"` or `"*.npmjs.org"`).
    Domain(String),
    /// IP address or CIDR block (e.g. `"140.82.112.0/20"` or `"1.2.3.4"`).
    Cidr(String),
}

impl TryFrom<String> for Destination {
    type Error = String;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        if s.is_empty() {
            return Err("destination must not be empty".to_string());
        }
        // A CIDR contains '/' or is a valid IPv4 address.
        if s.contains('/') || s.parse::<Ipv4Addr>().is_ok() {
            Ok(Destination::Cidr(s))
        } else {
            Ok(Destination::Domain(s))
        }
    }
}

impl From<Destination> for String {
    fn from(d: Destination) -> String {
        match d {
            Destination::Domain(s) | Destination::Cidr(s) => s,
        }
    }
}

impl fmt::Display for Destination {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Domain(d) => write!(f, "{d}"),
            Self::Cidr(c) => write!(f, "{c}"),
        }
    }
}

/// Protocol constraint for a policy rule.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    Tcp,
    Udp,
    Http,
    Https,
    #[default]
    Any,
}

fn default_protocol() -> Protocol {
    Protocol::default()
}

// NOTE: the old `HttpConstraints { methods, paths }` wrapper struct was
// removed in M9-S10.  Its cartesian-product semantics (any method × any
// path) could not express "GET /foo but POST /bar" rules.  Use
// [`AssuranceLevel::Http { http_filters }`] with explicit `(method, path)`
// pairs instead.

// ---------------------------------------------------------------------------
// JSON Schema generation
// ---------------------------------------------------------------------------

/// Generate a JSON Schema document for the [`Policy`] type.
pub fn generate_json_schema() -> serde_json::Value {
    let schema = schemars::schema_for!(Policy);
    serde_json::to_value(schema).expect("schema serialization should not fail")
}

// ---------------------------------------------------------------------------
// Preset policies
// ---------------------------------------------------------------------------

/// Preset rules for allowing GitHub access (level 1 — transport passthrough).
pub fn preset_allow_github() -> Vec<PolicyRule> {
    vec![
        PolicyRule {
            destination: Destination::Domain("github.com".to_string()),
            level: AssuranceLevel::Transport,
            protocol: Protocol::Https,
            reason: Some("GitHub web and API".to_string()),
        },
        PolicyRule {
            destination: Destination::Domain("*.github.com".to_string()),
            level: AssuranceLevel::Transport,
            protocol: Protocol::Https,
            reason: Some("GitHub subdomains (API, uploads, etc.)".to_string()),
        },
        PolicyRule {
            destination: Destination::Domain("*.githubusercontent.com".to_string()),
            level: AssuranceLevel::Transport,
            protocol: Protocol::Https,
            reason: Some("GitHub raw content and assets".to_string()),
        },
    ]
}

/// Preset rules for allowing npm registry access (level 1 — transport passthrough).
pub fn preset_allow_npm() -> Vec<PolicyRule> {
    vec![
        PolicyRule {
            destination: Destination::Domain("registry.npmjs.org".to_string()),
            level: AssuranceLevel::Transport,
            protocol: Protocol::Https,
            reason: Some("npm package registry".to_string()),
        },
        PolicyRule {
            destination: Destination::Domain("*.npmjs.org".to_string()),
            level: AssuranceLevel::Transport,
            protocol: Protocol::Https,
            reason: Some("npm registry CDN".to_string()),
        },
        PolicyRule {
            destination: Destination::Domain("*.npmjs.com".to_string()),
            level: AssuranceLevel::Transport,
            protocol: Protocol::Https,
            reason: Some("npm website and API".to_string()),
        },
    ]
}

// ---------------------------------------------------------------------------
// Config file interfaces
// ---------------------------------------------------------------------------

/// CoreDNS policy configuration.
///
/// Format: one allowed domain per line. Lines starting with `#` are comments.
/// CoreDNS uses this list to determine which domains may be resolved; all
/// other domains receive NXDOMAIN.
#[derive(Debug, Clone)]
pub struct CoreDnsConfig {
    /// Domains that CoreDNS is allowed to resolve.
    pub allowed_domains: Vec<String>,
}

impl CoreDnsConfig {
    /// Render the config as a text file suitable for CoreDNS consumption.
    pub fn to_file_content(&self) -> String {
        let mut content =
            String::from("# CoreDNS allowed domains (generated by sandbox policy engine)\n");
        content.push_str("# One domain per line. Wildcard entries start with *.\n");
        for domain in &self.allowed_domains {
            content.push_str(domain);
            content.push('\n');
        }
        content
    }

    /// Render the CoreDNS config that means **deny everything** — the two
    /// header comments and an empty allowed-domains body.  CoreDNS treats
    /// absence from the list as NXDOMAIN, so this is the fail-closed
    /// default used whenever a session has no policy installed yet.
    ///
    /// Shared helper so every call site that needs the "no policy" string
    /// produces byte-identical content (and so a single edit changes them
    /// all).
    pub fn empty_policy_file_content() -> String {
        CoreDnsConfig {
            allowed_domains: Vec::new(),
        }
        .to_file_content()
    }
}

/// mitmproxy policy configuration (JSON).
///
/// Consumed by the mitmproxy policy enforcement addon to decide which
/// requests to allow and what constraints to enforce.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MitmproxyConfig {
    /// Per-host rules for the mitmproxy addon.
    pub rules: Vec<MitmproxyRule>,
}

/// A single mitmproxy rule for a host.
///
/// A request is permitted when its host matches [`Self::host`] **and** at
/// least one of [`Self::filters`] matches its `(method, path)` pair.  The
/// addon iterates the list in order.  An empty list means no request is
/// allowed — the upstream [`PolicyCompiler`] rejects such configurations
/// at compile time.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MitmproxyRule {
    /// Hostname to match (exact or wildcard like `*.example.com`).
    pub host: String,
    /// Ordered `(method, path)` filter pairs.  Each request is checked
    /// against the list in order; the first matching pair permits it.
    pub filters: Vec<MitmproxyFilter>,
}

/// A `(method, path)` filter pair emitted into the mitmproxy addon config.
///
/// Method and path are both strings on the wire for the benefit of the
/// Python addon — the Rust-side [`HttpMethod`] / [`HttpFilter`] types are
/// stringified here.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MitmproxyFilter {
    /// Uppercase HTTP method name (`"GET"`, `"POST"`, ..., or `"ANY"`).
    pub method: String,
    /// Path glob pattern (`fnmatch` syntax).
    pub path: String,
}

impl MitmproxyConfig {
    /// Serialize to JSON.
    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).expect("mitmproxy config serialization should not fail")
    }
}

// ---------------------------------------------------------------------------
// Policy compiler
// ---------------------------------------------------------------------------

/// Compiles a [`Policy`] into component-specific configurations.
pub struct PolicyCompiler;

/// The output of policy compilation: per-component configuration strings
/// ready to be written to files or injected into containers.
#[derive(Debug, Clone)]
pub struct CompiledPolicy {
    /// nftables rules to inject (extends the base deny-all + DNAT ruleset).
    pub nftables_rules: String,
    /// Envoy static bootstrap configuration (YAML). Written once per session.
    ///
    /// Contains admin, clusters (including the `mitmproxy` cluster), and a
    /// `dynamic_resources.lds_config` pointing at a filesystem path where
    /// the listener is served via LDS. See [`LISTENER_FILE_NAME`] and
    /// [`LISTENER_DIR_IN_CONTAINER`].
    pub envoy_bootstrap_config: String,
    /// Envoy listener file content (LDS `DiscoveryResponse` YAML). Rewritten
    /// on each DNS-propagation event to update filter chains without a full
    /// listener drain. The file between the `FILTER_CHAINS_BEGIN_MARKER`
    /// and `FILTER_CHAINS_END_MARKER` comment markers is the only region
    /// allowed to differ between generations.
    pub envoy_listener_config: String,
    /// mitmproxy addon configuration (JSON).
    pub mitmproxy_config: String,
    /// CoreDNS policy file content (one domain per line).
    pub coredns_config: String,
}

impl CompiledPolicy {
    /// Concatenation of the bootstrap and listener YAML.
    ///
    /// Intended for **tests and ad-hoc diagnostics** that need to assert
    /// on the combined Envoy configuration without caring which file a
    /// particular piece of content lives in. Production call sites
    /// write each half to its own destination path and should use
    /// [`Self::envoy_bootstrap_config`] / [`Self::envoy_listener_config`]
    /// directly.
    pub fn envoy_config_combined(&self) -> String {
        format!(
            "{bootstrap}\n# --- listener ---\n{listener}",
            bootstrap = self.envoy_bootstrap_config,
            listener = self.envoy_listener_config,
        )
    }
}

/// Absolute path inside the gateway container for the Envoy static bootstrap.
///
/// Written once per session by [`policy_distributor`](crate::policy_distributor)
/// before Envoy starts. The bootstrap references the listener file at
/// [`LISTENER_FILE_IN_CONTAINER`] via `dynamic_resources.lds_config`.
pub const BOOTSTRAP_FILE_IN_CONTAINER: &str = "/etc/envoy/envoy-bootstrap.yaml";

/// Absolute path inside the gateway container for the LDS-watched directory.
///
/// Envoy's filesystem LDS subscription is pinned to this directory so that
/// `MovedTo` inotify events produced by atomic renames trigger a listener
/// reload. See Envoy upstream issue `#20474`.
pub const LISTENER_DIR_IN_CONTAINER: &str = "/etc/envoy/listeners";

/// Basename of the LDS-watched listener file inside
/// [`LISTENER_DIR_IN_CONTAINER`].
pub const LISTENER_FILE_NAME: &str = "listener.yaml";

/// Absolute path inside the gateway container for the LDS-served listener
/// file.
pub const LISTENER_FILE_IN_CONTAINER: &str = "/etc/envoy/listeners/listener.yaml";

/// Marker comment demarcating the start of the mutable filter-chains region
/// inside a listener file. Used by the atomic listener-file writer to
/// enforce the "only filter chains differ between generations" invariant.
pub const FILTER_CHAINS_BEGIN_MARKER: &str = "# >>> FILTER_CHAINS_BEGIN";

/// Marker comment demarcating the end of the mutable filter-chains region.
pub const FILTER_CHAINS_END_MARKER: &str = "# <<< FILTER_CHAINS_END";

impl PolicyCompiler {
    /// Validate and compile a policy into per-component configurations.
    ///
    /// The `network_info` provides subnet and gateway IP details needed for
    /// nftables and Envoy generation.
    pub fn compile(
        policy: &Policy,
        network_info: &NetworkInfo,
    ) -> Result<CompiledPolicy, SandboxError> {
        Self::validate(policy)?;

        let nftables_rules = Self::compile_nftables(policy, network_info);
        let envoy_bootstrap_config = Self::compile_envoy_bootstrap();
        let envoy_listener_config = Self::compile_envoy_listener(policy);
        let mitmproxy_config = Self::compile_mitmproxy(policy);
        let coredns_config = Self::compile_coredns(policy);

        Ok(CompiledPolicy {
            nftables_rules,
            envoy_bootstrap_config,
            envoy_listener_config,
            mitmproxy_config,
            coredns_config,
        })
    }

    /// Validate policy consistency and correctness.
    ///
    /// Checks:
    /// - Schema version is compatible
    /// - `Http`-level rules have a non-empty `http_filters` list and an
    ///   HTTP-capable protocol (`http`, `https`, `any`)
    /// - No contradictory rules (same destination with different assurance
    ///   level variants; duplicate `Http` entries are permitted and their
    ///   filter lists merged by the downstream addon)
    /// - CIDR blocks are syntactically valid
    /// - Domain names are syntactically valid
    pub fn validate(policy: &Policy) -> Result<(), SandboxError> {
        // Check schema version compatibility.
        let version = semver::Version::parse(&policy.version).map_err(|e| {
            SandboxError::Internal(format!(
                "invalid policy schema version '{}': {e}",
                policy.version
            ))
        })?;
        let required = semver::Version::parse(SCHEMA_VERSION).unwrap();
        if version.major != required.major {
            return Err(SandboxError::Internal(format!(
                "incompatible policy schema version: got {version}, expected {required}.x.x"
            )));
        }

        // Track destinations to detect contradictions.  Compare by variant
        // name (not full equality) so two `Http` rules on the same
        // destination with different filter lists are not flagged — they
        // compose rather than conflict.
        let mut seen_destinations: HashMap<String, &'static str> = HashMap::new();

        for (i, rule) in policy.rules.iter().enumerate() {
            let ctx = format!("rule {i} (destination: {})", rule.destination);

            // `Http`-specific invariants.
            if let AssuranceLevel::Http { http_filters } = &rule.level {
                if http_filters.is_empty() {
                    return Err(SandboxError::Internal(format!(
                        "{ctx}: assurance level 'http' requires a non-empty \
                         `http_filters` array — list at least one {{method, path}} pair"
                    )));
                }
                if !matches!(
                    rule.protocol,
                    Protocol::Http | Protocol::Https | Protocol::Any
                ) {
                    return Err(SandboxError::Internal(format!(
                        "{ctx}: assurance level 'http' requires protocol \
                         'http', 'https', or 'any' (got '{:?}')",
                        rule.protocol
                    )));
                }
            }

            // Validate destination syntax.
            match &rule.destination {
                Destination::Cidr(cidr) => {
                    Self::validate_cidr(cidr)
                        .map_err(|e| SandboxError::Internal(format!("{ctx}: invalid CIDR: {e}")))?;
                }
                Destination::Domain(domain) => {
                    Self::validate_domain(domain).map_err(|e| {
                        SandboxError::Internal(format!("{ctx}: invalid domain: {e}"))
                    })?;
                }
            }

            // Check for contradictory rules: same destination string with
            // different assurance-level variants.
            let dest_key = rule.destination.to_string();
            let variant = rule.level.variant_name();
            if let Some(prev_variant) = seen_destinations.get(&dest_key) {
                if *prev_variant != variant {
                    return Err(SandboxError::Internal(format!(
                        "{ctx}: contradicts earlier rule (level '{}' vs '{}')",
                        prev_variant, variant
                    )));
                }
            } else {
                seen_destinations.insert(dest_key, variant);
            }
        }

        Ok(())
    }

    // -- Private compilation helpers ------------------------------------------

    /// Compile nftables rules for the policy.
    ///
    /// Starts with the existing deny-all + DNAT base (generated elsewhere in
    /// gateway.rs). This method generates an *additional* table
    /// `sandbox_policy` with explicit allow rules for level >= 1 destinations.
    ///
    /// For level 0 (deny): no rules needed — the base deny-all handles it.
    /// For level 1 (transport): IP allow rules + TCP redirect to Envoy.
    fn compile_nftables(policy: &Policy, network_info: &NetworkInfo) -> String {
        let mut allow_rules = Vec::new();

        for rule in &policy.rules {
            if matches!(rule.level, AssuranceLevel::Deny) {
                continue;
            }

            match &rule.destination {
                Destination::Cidr(cidr) => {
                    // For CIDR destinations, generate direct IP-based rules.
                    // Use conntrack original-direction matching so rules work
                    // correctly after DNAT has rewritten packet headers.
                    let ip_or_cidr = cidr.as_str();

                    match rule.protocol {
                        Protocol::Tcp | Protocol::Https | Protocol::Http | Protocol::Any => {
                            allow_rules.push(format!(
                                "        ct original ip daddr {ip_or_cidr} tcp dport {{ 80, 443 }} accept"
                            ));
                        }
                        Protocol::Udp => {
                            allow_rules.push(format!(
                                "        ct original ip daddr {ip_or_cidr} udp dport {{ 80, 443 }} accept"
                            ));
                        }
                    }
                }
                Destination::Domain(domain) if domain == "*" => {
                    // Unrestricted wildcard destination: accept any daddr on
                    // 80/443 directly.  We emit a real allow rule rather than
                    // waiting for DNS propagation because `*` cannot be
                    // resolved — the DNS cache only ever holds concrete
                    // FQDNs, so `generate_domain_ip_rules` alone would never
                    // materialise an allow-rule for this shape.
                    //
                    // Match on the original-direction L4 port via
                    // `ct original proto-dst` so the rule still catches the
                    // pre-DNAT port 80/443 even after the base chain has
                    // redirected the flow to the gateway's Envoy listener
                    // on port 10000.  Bare `tcp dport { 80, 443 }` would
                    // only match traffic that had not yet been DNAT'd —
                    // which is never the case at the forward hook.  Pair
                    // with `meta l4proto` to keep the TCP/UDP split the
                    // other arms use.
                    match rule.protocol {
                        Protocol::Tcp | Protocol::Https | Protocol::Http | Protocol::Any => {
                            allow_rules.push(
                                "        meta l4proto tcp ct original proto-dst { 80, 443 } accept # unrestricted"
                                    .to_string(),
                            );
                        }
                        Protocol::Udp => {
                            allow_rules.push(
                                "        meta l4proto udp ct original proto-dst { 80, 443 } accept # unrestricted"
                                    .to_string(),
                            );
                        }
                    }
                }
                Destination::Domain(domain) => {
                    // Domain destinations require DNS resolution for IP-based
                    // firewall rules. For now, generate a comment placeholder.
                    // M4-S5 will implement DNS-to-nftables propagation.
                    allow_rules.push(format!(
                        "        # domain: {domain} (level: {level}, resolved IPs injected at runtime)",
                        level = rule.level,
                    ));
                }
            }
        }

        // If no *real* allow rules (excluding comment placeholders for
        // unresolved domains), return an empty string — the base deny-all
        // forward chain is sufficient.  Domain-only policies will rely on
        // the existing `sandbox` forward chain until the DNS propagation
        // loop resolves IPs and injects real rules via
        // `generate_domain_ip_rules`.
        let has_real_rules = allow_rules.iter().any(|r| !r.trim_start().starts_with('#'));
        if !has_real_rules {
            return String::new();
        }

        let rules_block = allow_rules.join("\n");
        format!(
            r#"table inet sandbox_policy {{
    chain forward {{
        type filter hook forward priority -1; policy drop;

        # Allow established/related return traffic
        ct state established,related accept

        # Allow DNS to gateway (CoreDNS)
        ip saddr {subnet} ip daddr {gateway_ip} udp dport 53 accept
        ip saddr {subnet} ip daddr {gateway_ip} tcp dport 53 accept

        # Policy allow rules
{rules_block}

        # Reject everything else (fast failure for denied destinations)
        reject
    }}
}}
"#,
            subnet = network_info.subnet,
            gateway_ip = network_info.gateway_ip,
        )
    }

    /// Compile the Envoy **static bootstrap** config.
    ///
    /// Written once per session before Envoy starts. Contains:
    /// - `admin` server on `127.0.0.1:9901`
    /// - all clusters (both `original_dst` and `mitmproxy`) — cluster
    ///   definitions never change during a session
    /// - `dynamic_resources.lds_config` pointing at a filesystem `path` for
    ///   the listener, with `watched_directory` set to the containing
    ///   directory (Envoy's filesystem LDS watcher keys on `MovedTo`
    ///   inotify events on the parent dir; see upstream issue `#20474`)
    ///
    /// The listener itself is served via LDS from
    /// [`LISTENER_FILE_IN_CONTAINER`] — Envoy refuses to promote a
    /// statically-defined listener to LDS mid-session, so the listener
    /// must ship via LDS from session start.
    ///
    /// The bootstrap is policy-agnostic: it has the same content for every
    /// session regardless of the policy rules. Per-policy content lives in
    /// the listener file (see [`Self::compile_envoy_listener`]).
    ///
    /// Public because `gateway::create_gateway` also calls this to seed
    /// the bootstrap file inside the container before Envoy starts.
    pub fn compile_envoy_bootstrap() -> String {
        // Cluster definitions. Both `original_dst` (L1 passthrough, L2
        // TLS forwarding) and `mitmproxy` (L3 CONNECT-tunneled target)
        // are defined statically. The `mitmproxy` cluster is defined
        // here from M9-S18 onwards; no filter chain routes to it yet
        // (that's M9-S19, which adds `tcp_proxy.tunneling_config`).
        //
        // `mitmproxy` cluster specifics:
        // - `127.0.0.1:18080` — loopback-only; not a VM-facing DNAT
        //   target. Port 18080 (rather than 8080) is a defence-in-depth
        //   signal: an accidental DNAT back to 8080 would fail closed.
        // - `typed_extension_protocol_options` pins HTTP/1.1 upstream
        //   via `HttpProtocolOptions.explicit_http_config.http_protocol_options`.
        //   mitmproxy does not implement HTTP/2 CONNECT (upstream issue
        //   `#1138`), so HTTP/2 upstream would break the CONNECT tunnel
        //   M9-S19 will wire up.
        // - No `upstream_proxy_protocol` transport-socket wrapping. The
        //   default `raw_buffer` upstream transport is used; the CONNECT
        //   preface is (will be, in M9-S19) emitted by a per-chain
        //   `tcp_proxy.tunneling_config`, not by a transport-socket
        //   header.
        // - TCP health check (1s timeout, 5s interval) so a dead
        //   mitmproxy surfaces in Envoy admin stats.
        //
        //   Transient M9-S18 behaviour: until M9-S19 flips the
        //   mitmproxy entrypoint to `--mode regular --listen-host
        //   127.0.0.1 --listen-port 18080`, mitmproxy still listens on
        //   `0.0.0.0:8080`, so this probe connects to a closed port
        //   and fails on every 5s tick. Expect a steady drip of
        //   "upstream cluster_mitmproxy health check failed" warnings
        //   and a climbing `cluster.mitmproxy.health_check.failure`
        //   stat for the duration of the one-session gap between
        //   M9-S18 and M9-S19 landing. Operators seeing "mitmproxy
        //   unhealthy" in `/clusters` during this window should treat
        //   it as expected, not as a bug. The health check stays in
        //   the cluster definition per spec — we're documenting the
        //   transient, not gating it behind a feature flag.
        let clusters_yaml = r#"    - name: original_dst
      type: ORIGINAL_DST
      lb_policy: CLUSTER_PROVIDED
      connect_timeout: 10s
    - name: mitmproxy
      type: STATIC
      lb_policy: ROUND_ROBIN
      connect_timeout: 10s
      load_assignment:
        cluster_name: mitmproxy
        endpoints:
          - lb_endpoints:
              - endpoint:
                  address:
                    socket_address:
                      address: 127.0.0.1
                      port_value: 18080
      typed_extension_protocol_options:
        envoy.extensions.upstreams.http.v3.HttpProtocolOptions:
          "@type": type.googleapis.com/envoy.extensions.upstreams.http.v3.HttpProtocolOptions
          explicit_http_config:
            http_protocol_options: {}
      health_checks:
        - timeout: 1s
          interval: 5s
          no_traffic_interval: 5s
          unhealthy_threshold: 2
          healthy_threshold: 1
          tcp_health_check: {}"#;

        format!(
            r#"# Envoy static bootstrap (generated by sandbox policy engine, M9-S18)
#
# The listener is served via LDS from a filesystem `path_config_source`;
# sandboxd writes the listener file via an atomic rename so Envoy's
# inotify watcher observes a `MovedTo` event (upstream issue `#20474`).
# Cluster definitions never change mid-session, so they stay here.
node:
  id: sandbox-gateway
  cluster: sandbox-gateway

dynamic_resources:
  lds_config:
    resource_api_version: V3
    path_config_source:
      path: {listener_file}
      watched_directory:
        path: {listener_dir}

static_resources:
  clusters:
{clusters_yaml}

admin:
  address:
    socket_address:
      address: 127.0.0.1
      port_value: 9901
"#,
            listener_file = LISTENER_FILE_IN_CONTAINER,
            listener_dir = LISTENER_DIR_IN_CONTAINER,
            clusters_yaml = clusters_yaml,
        )
    }

    /// Compile the Envoy **listener file** (LDS `DiscoveryResponse`).
    ///
    /// This is the only piece of Envoy config that changes during a
    /// session's lifetime. It is written initially alongside the bootstrap
    /// and will be rewritten by DNS propagation (wired up in M9-S19) on
    /// each change to the resolved-IP set.
    ///
    /// The format is a filesystem-LDS `DiscoveryResponse` with a single
    /// `envoy.config.listener.v3.Listener` resource. Between the
    /// [`FILTER_CHAINS_BEGIN_MARKER`] and [`FILTER_CHAINS_END_MARKER`]
    /// comment markers is the only region the atomic writer permits to
    /// differ between generations — changes to the framing region (bind
    /// address, `listener_filters`, `socket_options`, etc.) force a full
    /// listener drain and reset existing connections, destroying the
    /// connection-preservation property.
    ///
    /// Supports all assurance levels:
    /// - Level 1 (transport): default filter chain with TCP passthrough
    ///   to `original_dst`. nftables controls which IPs reach Envoy.
    /// - Level 2 (TLS): SNI-matched filter chains forwarding to
    ///   `original_dst`. The `tls_inspector` listener filter extracts
    ///   SNI from ClientHello.
    /// - Level 3 (full): SNI-matched filter chains forwarding to
    ///   `original_dst` (passthrough). **M9-S18 preserves the
    ///   pre-split chain shape byte-for-byte** so the cutover in
    ///   M9-S19 is a clean, isolated change. L3 traffic is currently
    ///   redirected to mitmproxy at the nftables level (`sandbox_l3`
    ///   DNAT rules); Envoy does not yet route L3 to the `mitmproxy`
    ///   cluster. That rewiring — and the per-chain
    ///   `tcp_proxy.tunneling_config` that emits the CONNECT preface —
    ///   lands in M9-S19.
    ///
    /// When L2 or L3 rules are present, `tls_inspector` is added as a
    /// listener filter. The `original_dst` listener filter is always
    /// present.
    ///
    /// Filter chain ordering: L2/L3 SNI-matched chains first (order does
    /// not matter among them since SNI matches are disjoint), then the
    /// L1 default catch-all chain last.
    pub fn compile_envoy_listener(policy: &Policy) -> String {
        let has_transport = policy
            .rules
            .iter()
            .any(|r| matches!(r.level, AssuranceLevel::Transport));
        let has_tls = policy
            .rules
            .iter()
            .any(|r| matches!(r.level, AssuranceLevel::Tls));
        let has_http = policy
            .rules
            .iter()
            .any(|r| matches!(r.level, AssuranceLevel::Http { .. }));

        // For a policy with only deny rules, or no rules at all, return
        // a listener with no filter chains — unmatched traffic is
        // closed (Envoy has no default passthrough chain unless
        // explicitly emitted by L1).
        if !has_transport && !has_tls && !has_http {
            return Self::envoy_deny_all_listener();
        }

        // -- Filter chains -----------------------------------------------------

        let mut filter_chains = Vec::new();

        // Level 2 (TLS): SNI-matched chains → original_dst.
        for rule in policy
            .rules
            .iter()
            .filter(|r| matches!(r.level, AssuranceLevel::Tls))
        {
            let domain = rule.destination.to_string();
            let stat_name = Self::sanitize_stat_prefix(&domain);
            filter_chains.push(format!(
                r#"    - filter_chain_match:
        server_names: ["{domain}"]
      filters:
        - name: envoy.filters.network.tcp_proxy
          typed_config:
            "@type": type.googleapis.com/envoy.extensions.filters.network.tcp_proxy.v3.TcpProxy
            cluster: original_dst
            stat_prefix: level2_{stat_name}"#
            ));
        }

        // Level 3 (full): SNI-matched chains → original_dst (passthrough).
        //
        // **M9-S18 note.** The listener file is emitted with today's
        // filter-chain shape byte-for-byte so the split is purely
        // additive — no traffic-path change, no new test baseline. L3
        // traffic still reaches mitmproxy via the `sandbox_l3` nftables
        // DNAT shortcut (which preserves `SO_ORIGINAL_DST`); Envoy does
        // not yet route L3 to the `mitmproxy` cluster. That cutover is
        // M9-S19, which wires each L3 chain through
        // `tcp_proxy.tunneling_config` (HTTP/1.1 CONNECT) to the
        // mitmproxy cluster defined in the static bootstrap.
        //
        // During the brief window before DNS propagation installs the
        // `sandbox_l3` rules (first ~2 seconds), L3 traffic falls
        // through Envoy as opaque passthrough. Once the `sandbox_l3`
        // rules are in place, traffic bypasses Envoy entirely. Both of
        // these properties go away in M9-S19.
        for rule in policy
            .rules
            .iter()
            .filter(|r| matches!(r.level, AssuranceLevel::Http { .. }))
        {
            let domain = rule.destination.to_string();
            let stat_name = Self::sanitize_stat_prefix(&domain);
            // Unrestricted wildcard (`*`) destination: Envoy's
            // `filter_chain_match.server_names` does not accept a bare
            // `*`, so emit a catch-all chain (no `filter_chain_match`).
            if domain == "*" {
                filter_chains.push(format!(
                    r#"    - filters:
        - name: envoy.filters.network.tcp_proxy
          typed_config:
            "@type": type.googleapis.com/envoy.extensions.filters.network.tcp_proxy.v3.TcpProxy
            cluster: original_dst
            stat_prefix: level3_{stat_name}"#
                ));
                continue;
            }
            filter_chains.push(format!(
                r#"    - filter_chain_match:
        server_names: ["{domain}"]
      filters:
        - name: envoy.filters.network.tcp_proxy
          typed_config:
            "@type": type.googleapis.com/envoy.extensions.filters.network.tcp_proxy.v3.TcpProxy
            cluster: original_dst
            stat_prefix: level3_{stat_name}"#
            ));
        }

        // Level 1 (transport): default catch-all chain → original_dst.
        // This must be last since it has no filter_chain_match and acts
        // as the default route for traffic that does not match any
        // SNI-specific chain.
        if has_transport {
            filter_chains.push(
                r#"    - filters:
        - name: envoy.filters.network.tcp_proxy
          typed_config:
            "@type": type.googleapis.com/envoy.extensions.filters.network.tcp_proxy.v3.TcpProxy
            stat_prefix: policy_tcp_passthrough
            cluster: original_dst"#
                    .to_string(),
            );
        }

        let filter_chains_yaml = filter_chains.join("\n");

        Self::listener_yaml_for_filter_chains(&format!(
            "    filter_chains:\n{filter_chains_yaml}"
        ))
    }

    /// Emit the listener YAML (head + filter-chains body + tail).
    ///
    /// The `filter_chains_body` argument contains the YAML fragment that
    /// sits between [`FILTER_CHAINS_BEGIN_MARKER`] and
    /// [`FILTER_CHAINS_END_MARKER`] — typically either `filter_chains: []`
    /// (deny-all) or a populated `filter_chains:` list.
    ///
    /// This helper guarantees that every listener generation we emit has
    /// the **same head and tail regions**, which is the core invariant
    /// the atomic listener writer enforces: only the filter-chains body
    /// may differ between generations, so Envoy's LDS update path does
    /// not drain the listener or reset in-flight connections.
    ///
    /// In particular this means `listener_filters` is populated with the
    /// same two filters (`tls_inspector`, `original_dst`) for every
    /// policy — including deny-all — so an L1-only policy and an
    /// L2/L3 policy can transition between each other without touching
    /// the head region. The `tls_inspector` listener filter is a no-op
    /// for non-TLS traffic (it simply peeks at the ClientHello and, if
    /// none is present, lets the connection proceed), so carrying it in
    /// every listener is correct.
    fn listener_yaml_for_filter_chains(filter_chains_body: &str) -> String {
        // Note: the preamble deliberately avoids embedding the literal
        // marker strings. The sentinel comments below must each occur
        // EXACTLY ONCE in the file so the atomic writer can split the
        // content cleanly — embedding them in prose would confuse the
        // split. The preamble therefore describes the markers in words.
        format!(
            r#"# Envoy listener (LDS DiscoveryResponse, generated by sandbox policy engine)
#
# Served via filesystem LDS from `{listener_file}`. sandboxd rewrites
# this file via atomic rename — see `atomic_listener_writer` in
# `sandbox-core`. Between any two generations, only the region framed
# by the filter-chains BEGIN and END sentinel comments below is
# permitted to differ; the writer enforces this invariant so that
# connection preservation holds across filter-chain updates (Envoy
# drains the listener on metadata, socket-option, bind-address, or
# listener-filter changes).
resources:
  - "@type": type.googleapis.com/envoy.config.listener.v3.Listener
    name: policy_listener
    address:
      socket_address:
        address: 0.0.0.0
        port_value: 10000
    listener_filters:
    - name: envoy.filters.listener.tls_inspector
      typed_config:
        "@type": type.googleapis.com/envoy.extensions.filters.listener.tls_inspector.v3.TlsInspector
    - name: envoy.filters.listener.original_dst
      typed_config:
        "@type": type.googleapis.com/envoy.extensions.filters.listener.original_dst.v3.OriginalDst
{begin_marker}
{filter_chains_body}
{end_marker}
"#,
            listener_file = LISTENER_FILE_IN_CONTAINER,
            begin_marker = FILTER_CHAINS_BEGIN_MARKER,
            end_marker = FILTER_CHAINS_END_MARKER,
            filter_chains_body = filter_chains_body,
        )
    }

    /// Sanitize a domain name into a valid Envoy stat prefix.
    ///
    /// Replaces dots, asterisks, and slashes with underscores.
    fn sanitize_stat_prefix(domain: &str) -> String {
        domain
            .replace('.', "_")
            .replace('*', "wildcard")
            .replace('/', "_")
    }

    /// Compile mitmproxy configuration for the policy.
    ///
    /// Only `Http`-level rules produce mitmproxy rules.  Each rule's
    /// `http_filters` list is emitted verbatim as `(method, path)` pairs
    /// — the addon matches them as pairs, not as a cartesian product.
    fn compile_mitmproxy(policy: &Policy) -> String {
        let rules: Vec<MitmproxyRule> = policy
            .rules
            .iter()
            .filter_map(|r| match &r.level {
                AssuranceLevel::Http { http_filters } => Some(MitmproxyRule {
                    host: r.destination.to_string(),
                    filters: http_filters
                        .iter()
                        .map(|f| MitmproxyFilter {
                            method: f.method.to_string(),
                            path: f.path.clone(),
                        })
                        .collect(),
                }),
                _ => None,
            })
            .collect();

        let config = MitmproxyConfig { rules };
        config.to_json()
    }

    /// Compile CoreDNS policy configuration.
    ///
    /// Extracts all domain-based destinations (level >= 1) into the allowed
    /// domains list. CoreDNS will return NXDOMAIN for anything not on this
    /// list.
    fn compile_coredns(policy: &Policy) -> String {
        let domains: Vec<String> = policy
            .rules
            .iter()
            .filter(|r| !matches!(r.level, AssuranceLevel::Deny))
            .filter_map(|r| match &r.destination {
                Destination::Domain(d) => Some(d.clone()),
                Destination::Cidr(_) => None,
            })
            .collect();

        let config = CoreDnsConfig {
            allowed_domains: domains,
        };
        config.to_file_content()
    }

    // -- Validation helpers ---------------------------------------------------

    /// Validate a CIDR string (IP/prefix or bare IP).
    fn validate_cidr(cidr: &str) -> Result<(), String> {
        if let Some((ip_str, prefix_str)) = cidr.split_once('/') {
            // IP/prefix form.
            ip_str
                .parse::<Ipv4Addr>()
                .map_err(|e| format!("invalid IP address '{ip_str}': {e}"))?;
            let prefix: u8 = prefix_str
                .parse()
                .map_err(|e| format!("invalid prefix length '{prefix_str}': {e}"))?;
            if prefix > 32 {
                return Err(format!("prefix length {prefix} exceeds 32"));
            }
        } else {
            // Bare IP address.
            cidr.parse::<Ipv4Addr>()
                .map_err(|e| format!("invalid IP address '{cidr}': {e}"))?;
        }
        Ok(())
    }

    /// Validate a domain name (basic checks).
    fn validate_domain(domain: &str) -> Result<(), String> {
        if domain.is_empty() {
            return Err("domain must not be empty".to_string());
        }

        // Bare `*` is the synthetic unrestricted-policy wildcard — it matches
        // every FQDN rather than a specific label.  It is intentionally only
        // producible by `Policy::unrestricted()`; humans authoring policy
        // files should use `*.foo.com` style instead.
        if domain == "*" {
            return Ok(());
        }

        // Allow wildcard prefix.
        let check = if let Some(rest) = domain.strip_prefix("*.") {
            rest
        } else {
            domain
        };

        if check.is_empty() {
            return Err("domain must have at least one label after wildcard".to_string());
        }

        // Basic label validation.
        for label in check.split('.') {
            if label.is_empty() {
                return Err("domain contains empty label".to_string());
            }
            if label.len() > 63 {
                return Err(format!("label '{}' exceeds 63 characters", &label[..20]));
            }
            if !label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
                return Err(format!("label '{label}' contains invalid characters"));
            }
            if label.starts_with('-') || label.ends_with('-') {
                return Err(format!("label '{label}' must not start or end with '-'"));
            }
        }

        Ok(())
    }

    /// Emit the initial (pre-policy) Envoy listener file written before
    /// Envoy first boots.
    ///
    /// This is identical to [`Self::envoy_deny_all_listener`] today — the
    /// initial listener is a framed deny-all that Envoy loads successfully
    /// but which closes every connection until the session policy is
    /// applied. It is published as its own method so call sites document
    /// the intent (first write vs. post-rollback recovery).
    ///
    /// # Behaviour change vs. pre-M9-S18
    ///
    /// Before M9-S18 the gateway shipped with `envoy-base.yaml` baked into
    /// the container, which installed an **L1 pass-through** listener on
    /// first boot. From M9-S18 onwards the bootstrap is policy-agnostic
    /// and the day-one listener is served via LDS — and Envoy refuses to
    /// promote a static listener to LDS mid-session, so the very first
    /// listener published on the filesystem must itself be deliverable
    /// via LDS. The simplest fail-closed default that satisfies this
    /// constraint is a framed deny-all (empty `filter_chains`).
    ///
    /// For sessions started without a policy (`--clear` / no-policy
    /// startup) this means the Envoy listener is deny-all instead of
    /// L1 pass-through. Net user-visible behaviour is unchanged because
    /// the nftables layers (`sandbox_policy`, `sandbox_l3`) gate traffic
    /// first and are also empty on a no-policy session, and DNS is
    /// deny-by-default since M9-S15. This is consistent with the
    /// fail-closed design principle — no-policy sessions must not leak.
    ///
    /// M9-S19 replaces this default with the policy-driven L3 filter
    /// chains; at that point the initial listener will carry the real
    /// compiled chains rather than a deny-all placeholder.
    pub fn compile_initial_envoy_listener() -> String {
        Self::envoy_deny_all_listener()
    }

    /// Emit a deny-all Envoy listener file (LDS `DiscoveryResponse`).
    ///
    /// Public so policy_distributor / gateway can emit it during
    /// rollback and initial-boot scenarios without going through the
    /// full `Policy` compilation path.
    ///
    /// The listener is still framed (bind address, empty
    /// `listener_filters`, marker comments) so the writer invariant
    /// check treats the transition to a populated policy as a pure
    /// filter-chains diff, not a framing change.
    pub fn envoy_deny_all_listener() -> String {
        // Deny-all is just an empty filter_chains list wrapped in the
        // common listener framing. Keeping the head/tail identical to
        // the policy-compiled listener is what lets sandboxd swap in a
        // populated policy without Envoy draining the listener.
        Self::listener_yaml_for_filter_chains("    filter_chains: []")
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // -- Test helpers --------------------------------------------------------

    fn test_network_info() -> NetworkInfo {
        NetworkInfo {
            bridge_name: "sb-test1234567".to_string(),
            subnet: "10.209.0.0/28".to_string(),
            gateway_ip: "10.209.0.2".to_string(),
            vm_ip: "10.209.0.3".to_string(),
            docker_network_name: "sandbox-net-test".to_string(),
        }
    }

    fn minimal_policy() -> Policy {
        Policy {
            version: SCHEMA_VERSION.to_string(),
            rules: vec![],
        }
    }

    fn transport_policy() -> Policy {
        Policy {
            version: SCHEMA_VERSION.to_string(),
            rules: vec![
                PolicyRule {
                    destination: Destination::Domain("github.com".to_string()),
                    level: AssuranceLevel::Transport,
                    protocol: Protocol::Https,
                    reason: Some("GitHub access".to_string()),
                },
                PolicyRule {
                    destination: Destination::Cidr("140.82.112.0/20".to_string()),
                    level: AssuranceLevel::Transport,
                    protocol: Protocol::Tcp,
                    reason: Some("GitHub IP range".to_string()),
                },
            ],
        }
    }

    fn http_filter(method: HttpMethod, path: &str) -> HttpFilter {
        HttpFilter {
            method,
            path: path.to_string(),
        }
    }

    // -- Policy parsing from JSON --------------------------------------------

    #[test]
    fn parse_policy_from_json() {
        let json = r#"{
            "version": "1.0.0",
            "rules": [
                {
                    "destination": "github.com",
                    "level": "transport",
                    "protocol": "https",
                    "reason": "GitHub access"
                },
                {
                    "destination": "140.82.112.0/20",
                    "level": "transport",
                    "reason": "GitHub IP range"
                }
            ]
        }"#;

        let policy: Policy = serde_json::from_str(json).unwrap();
        assert_eq!(policy.version, "1.0.0");
        assert_eq!(policy.rules.len(), 2);

        assert!(matches!(
            &policy.rules[0].destination,
            Destination::Domain(d) if d == "github.com"
        ));
        assert_eq!(policy.rules[0].level, AssuranceLevel::Transport);
        assert_eq!(policy.rules[0].protocol, Protocol::Https);

        assert!(matches!(
            &policy.rules[1].destination,
            Destination::Cidr(c) if c == "140.82.112.0/20"
        ));
        // Default protocol when omitted.
        assert_eq!(policy.rules[1].protocol, Protocol::Any);
    }

    #[test]
    fn parse_policy_with_http_filters() {
        let json = r#"{
            "version": "1.0.0",
            "rules": [
                {
                    "destination": "api.example.com",
                    "level": "http",
                    "protocol": "https",
                    "http_filters": [
                        {"method": "GET", "path": "/api/v1/*"},
                        {"method": "POST", "path": "/api/v1/*"}
                    ]
                }
            ]
        }"#;

        let policy: Policy = serde_json::from_str(json).unwrap();
        assert_eq!(policy.rules.len(), 1);

        let filters = match &policy.rules[0].level {
            AssuranceLevel::Http { http_filters } => http_filters.clone(),
            other => panic!("expected Http level, got {other:?}"),
        };
        assert_eq!(filters.len(), 2);
        assert_eq!(filters[0].method, HttpMethod::Get);
        assert_eq!(filters[0].path, "/api/v1/*");
        assert_eq!(filters[1].method, HttpMethod::Post);
        assert_eq!(filters[1].path, "/api/v1/*");
    }

    #[test]
    fn parse_rejects_legacy_full_level_with_clear_error() {
        // The pre-M9-S10 shape: `level: "full"` + `constraints: {methods,
        // paths}`.  No auto-conversion — the error must name the new shape.
        let json = r#"{
            "version": "1.0.0",
            "rules": [
                {
                    "destination": "api.example.com",
                    "level": "full",
                    "protocol": "https",
                    "constraints": {
                        "methods": ["GET", "POST"],
                        "paths": ["/api/v1/"]
                    }
                }
            ]
        }"#;

        let err = serde_json::from_str::<Policy>(json)
            .expect_err("legacy `full` level must fail to deserialize");
        let msg = err.to_string();
        assert!(
            msg.contains("legacy level `full`") && msg.contains("http_filters"),
            "error must explain the migration path; got: {msg}"
        );
    }

    #[test]
    fn parse_rejects_legacy_constraints_field_with_clear_error() {
        // Any `constraints` field — even without `level: "full"` — is a
        // leftover from the old shape.
        let json = r#"{
            "version": "1.0.0",
            "rules": [
                {
                    "destination": "api.example.com",
                    "level": "http",
                    "protocol": "https",
                    "constraints": {
                        "methods": ["GET"],
                        "paths": ["/api"]
                    }
                }
            ]
        }"#;

        let err = serde_json::from_str::<Policy>(json)
            .expect_err("legacy `constraints` field must fail to deserialize");
        let msg = err.to_string();
        assert!(
            msg.contains("legacy `constraints` field") && msg.contains("http_filters"),
            "error must explain the migration path; got: {msg}"
        );
    }

    #[test]
    fn parse_policy_with_bare_ip_destination() {
        let json = r#"{
            "version": "1.0.0",
            "rules": [
                {
                    "destination": "1.2.3.4",
                    "level": "transport"
                }
            ]
        }"#;

        let policy: Policy = serde_json::from_str(json).unwrap();
        assert!(matches!(
            &policy.rules[0].destination,
            Destination::Cidr(c) if c == "1.2.3.4"
        ));
    }

    #[test]
    fn parse_deny_level() {
        let json = r#"{
            "version": "1.0.0",
            "rules": [
                {
                    "destination": "evil.com",
                    "level": "deny"
                }
            ]
        }"#;

        let policy: Policy = serde_json::from_str(json).unwrap();
        assert_eq!(policy.rules[0].level, AssuranceLevel::Deny);
    }

    #[test]
    fn roundtrip_serialization() {
        let policy = transport_policy();
        let json = serde_json::to_string_pretty(&policy).unwrap();
        let parsed: Policy = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.version, policy.version);
        assert_eq!(parsed.rules.len(), policy.rules.len());
    }

    // -- JSON Schema generation ----------------------------------------------

    #[test]
    fn json_schema_is_valid() {
        let schema = generate_json_schema();

        // Must be an object with standard JSON Schema fields.
        assert!(schema.is_object(), "schema must be a JSON object");
        let obj = schema.as_object().unwrap();
        assert!(
            obj.contains_key("$schema") || obj.contains_key("title") || obj.contains_key("type"),
            "schema must contain standard JSON Schema fields"
        );

        // Must reference the Policy type.
        let schema_str = serde_json::to_string(&schema).unwrap();
        assert!(
            schema_str.contains("version") && schema_str.contains("rules"),
            "schema must describe Policy fields"
        );
    }

    #[test]
    fn json_schema_includes_assurance_levels() {
        let schema_str = serde_json::to_string(&generate_json_schema()).unwrap();
        assert!(
            schema_str.contains("deny"),
            "schema must include 'deny' level"
        );
        assert!(
            schema_str.contains("transport"),
            "schema must include 'transport' level"
        );
        assert!(
            schema_str.contains("tls"),
            "schema must include 'tls' level"
        );
        assert!(
            schema_str.contains("\"http\""),
            "schema must include 'http' level (renamed from 'full' in M9-S10)"
        );
        assert!(
            !schema_str.contains("\"full\""),
            "schema must not include legacy 'full' level"
        );
        assert!(
            schema_str.contains("http_filters"),
            "schema must describe `http_filters` array"
        );
    }

    // -- Validation tests ----------------------------------------------------

    #[test]
    fn validate_accepts_valid_policy() {
        let policy = transport_policy();
        assert!(PolicyCompiler::validate(&policy).is_ok());
    }

    #[test]
    fn validate_rejects_bad_version() {
        let policy = Policy {
            version: "not-semver".to_string(),
            rules: vec![],
        };
        let err = PolicyCompiler::validate(&policy).unwrap_err();
        assert!(
            err.to_string().contains("invalid policy schema version"),
            "expected version parse error, got: {err}"
        );
    }

    #[test]
    fn validate_rejects_incompatible_major_version() {
        let policy = Policy {
            version: "2.0.0".to_string(),
            rules: vec![],
        };
        let err = PolicyCompiler::validate(&policy).unwrap_err();
        assert!(
            err.to_string().contains("incompatible"),
            "expected incompatible version error, got: {err}"
        );
    }

    #[test]
    fn validate_accepts_compatible_minor_version() {
        let policy = Policy {
            version: "1.1.0".to_string(),
            rules: vec![],
        };
        assert!(PolicyCompiler::validate(&policy).is_ok());
    }

    #[test]
    fn validate_rejects_http_level_with_udp() {
        let policy = Policy {
            version: SCHEMA_VERSION.to_string(),
            rules: vec![PolicyRule {
                destination: Destination::Domain("example.com".to_string()),
                level: AssuranceLevel::Http {
                    http_filters: vec![http_filter(HttpMethod::Get, "/*")],
                },
                protocol: Protocol::Udp,
                reason: None,
            }],
        };
        let err = PolicyCompiler::validate(&policy).unwrap_err();
        assert!(
            err.to_string()
                .contains("assurance level 'http' requires protocol"),
            "expected http+udp protocol error, got: {err}"
        );
    }

    #[test]
    fn validate_rejects_http_level_with_empty_http_filters() {
        let policy = Policy {
            version: SCHEMA_VERSION.to_string(),
            rules: vec![PolicyRule {
                destination: Destination::Domain("example.com".to_string()),
                level: AssuranceLevel::Http {
                    http_filters: vec![],
                },
                protocol: Protocol::Https,
                reason: None,
            }],
        };
        let err = PolicyCompiler::validate(&policy).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("requires a non-empty") && msg.contains("http_filters"),
            "expected empty-http_filters error, got: {msg}"
        );
    }

    #[test]
    fn validate_rejects_contradictory_rules() {
        let policy = Policy {
            version: SCHEMA_VERSION.to_string(),
            rules: vec![
                PolicyRule {
                    destination: Destination::Domain("example.com".to_string()),
                    level: AssuranceLevel::Transport,
                    protocol: Protocol::Any,
                    reason: None,
                },
                PolicyRule {
                    destination: Destination::Domain("example.com".to_string()),
                    level: AssuranceLevel::Http {
                        http_filters: vec![http_filter(HttpMethod::Get, "/*")],
                    },
                    protocol: Protocol::Https,
                    reason: None,
                },
            ],
        };
        let err = PolicyCompiler::validate(&policy).unwrap_err();
        assert!(
            err.to_string().contains("contradicts"),
            "expected contradiction error, got: {err}"
        );
    }

    #[test]
    fn validate_allows_duplicate_rules_same_level() {
        let policy = Policy {
            version: SCHEMA_VERSION.to_string(),
            rules: vec![
                PolicyRule {
                    destination: Destination::Domain("example.com".to_string()),
                    level: AssuranceLevel::Transport,
                    protocol: Protocol::Any,
                    reason: None,
                },
                PolicyRule {
                    destination: Destination::Domain("example.com".to_string()),
                    level: AssuranceLevel::Transport,
                    protocol: Protocol::Https,
                    reason: None,
                },
            ],
        };
        assert!(PolicyCompiler::validate(&policy).is_ok());
    }

    #[test]
    fn validate_allows_duplicate_http_rules_with_different_filters() {
        // Two `Http` rules on the same destination with different filter
        // lists are NOT a contradiction — they compose.  The downstream
        // addon sees both filter sets for the same host.
        let policy = Policy {
            version: SCHEMA_VERSION.to_string(),
            rules: vec![
                PolicyRule {
                    destination: Destination::Domain("example.com".to_string()),
                    level: AssuranceLevel::Http {
                        http_filters: vec![http_filter(HttpMethod::Get, "/api/*")],
                    },
                    protocol: Protocol::Https,
                    reason: None,
                },
                PolicyRule {
                    destination: Destination::Domain("example.com".to_string()),
                    level: AssuranceLevel::Http {
                        http_filters: vec![http_filter(HttpMethod::Post, "/webhook")],
                    },
                    protocol: Protocol::Https,
                    reason: None,
                },
            ],
        };
        assert!(PolicyCompiler::validate(&policy).is_ok());
    }

    #[test]
    fn validate_rejects_invalid_cidr() {
        let policy = Policy {
            version: SCHEMA_VERSION.to_string(),
            rules: vec![PolicyRule {
                destination: Destination::Cidr("999.999.999.999/24".to_string()),
                level: AssuranceLevel::Transport,
                protocol: Protocol::Any,
                reason: None,
            }],
        };
        let err = PolicyCompiler::validate(&policy).unwrap_err();
        assert!(
            err.to_string().contains("invalid CIDR"),
            "expected CIDR error, got: {err}"
        );
    }

    #[test]
    fn validate_rejects_cidr_prefix_too_large() {
        let policy = Policy {
            version: SCHEMA_VERSION.to_string(),
            rules: vec![PolicyRule {
                destination: Destination::Cidr("10.0.0.0/33".to_string()),
                level: AssuranceLevel::Transport,
                protocol: Protocol::Any,
                reason: None,
            }],
        };
        let err = PolicyCompiler::validate(&policy).unwrap_err();
        assert!(
            err.to_string().contains("prefix length"),
            "expected prefix error, got: {err}"
        );
    }

    #[test]
    fn validate_rejects_invalid_domain() {
        let policy = Policy {
            version: SCHEMA_VERSION.to_string(),
            rules: vec![PolicyRule {
                destination: Destination::Domain("not a domain!".to_string()),
                level: AssuranceLevel::Transport,
                protocol: Protocol::Any,
                reason: None,
            }],
        };
        let err = PolicyCompiler::validate(&policy).unwrap_err();
        assert!(
            err.to_string().contains("invalid domain"),
            "expected domain error, got: {err}"
        );
    }

    #[test]
    fn validate_rejects_domain_with_leading_hyphen() {
        let policy = Policy {
            version: SCHEMA_VERSION.to_string(),
            rules: vec![PolicyRule {
                destination: Destination::Domain("-example.com".to_string()),
                level: AssuranceLevel::Transport,
                protocol: Protocol::Any,
                reason: None,
            }],
        };
        let err = PolicyCompiler::validate(&policy).unwrap_err();
        assert!(
            err.to_string().contains("must not start or end with '-'"),
            "expected hyphen error, got: {err}"
        );
    }

    #[test]
    fn validate_accepts_wildcard_domain() {
        let policy = Policy {
            version: SCHEMA_VERSION.to_string(),
            rules: vec![PolicyRule {
                destination: Destination::Domain("*.github.com".to_string()),
                level: AssuranceLevel::Transport,
                protocol: Protocol::Any,
                reason: None,
            }],
        };
        assert!(PolicyCompiler::validate(&policy).is_ok());
    }

    // -- Level 0 compilation (deny-all) --------------------------------------

    #[test]
    fn compile_deny_all_policy() {
        let policy = minimal_policy();
        let net = test_network_info();
        let compiled = PolicyCompiler::compile(&policy, &net).unwrap();

        // nftables: empty (base deny-all is sufficient).
        assert!(
            compiled.nftables_rules.is_empty(),
            "deny-all policy should produce no additional nftables rules"
        );

        // Envoy: deny-all config.
        assert!(
            compiled.envoy_config_combined().contains("filter_chains: []"),
            "deny-all policy should produce empty Envoy filter chains"
        );

        // mitmproxy: empty rules array.
        let mitmproxy: MitmproxyConfig = serde_json::from_str(&compiled.mitmproxy_config).unwrap();
        assert!(
            mitmproxy.rules.is_empty(),
            "deny-all policy should produce no mitmproxy rules"
        );

        // CoreDNS: only comments, no domains.
        assert!(
            !compiled.coredns_config.lines().any(|l| {
                let trimmed = l.trim();
                !trimmed.is_empty() && !trimmed.starts_with('#')
            }),
            "deny-all policy should list no domains in CoreDNS config"
        );
    }

    #[test]
    fn compile_explicit_deny_rules() {
        let policy = Policy {
            version: SCHEMA_VERSION.to_string(),
            rules: vec![PolicyRule {
                destination: Destination::Domain("blocked.com".to_string()),
                level: AssuranceLevel::Deny,
                protocol: Protocol::Any,
                reason: Some("Explicitly blocked".to_string()),
            }],
        };
        let net = test_network_info();
        let compiled = PolicyCompiler::compile(&policy, &net).unwrap();

        // Explicit deny should not produce any allow rules.
        assert!(compiled.nftables_rules.is_empty());

        // Denied domain should not appear in CoreDNS allowed list.
        assert!(
            !compiled.coredns_config.contains("blocked.com"),
            "denied domain should not appear in CoreDNS config"
        );
    }

    // -- Level 1 compilation (transport) ------------------------------------

    #[test]
    fn compile_level1_cidr_produces_nftables_rules() {
        let policy = transport_policy();
        let net = test_network_info();
        let compiled = PolicyCompiler::compile(&policy, &net).unwrap();

        // Should produce nftables rules for the CIDR destination.
        assert!(
            compiled.nftables_rules.contains("140.82.112.0/20"),
            "nftables should contain the CIDR allow rule"
        );
        assert!(
            compiled
                .nftables_rules
                .contains("table inet sandbox_policy"),
            "nftables should define sandbox_policy table"
        );
        assert!(
            compiled.nftables_rules.contains("accept"),
            "nftables should contain accept rules"
        );
    }

    #[test]
    fn compile_level1_domain_produces_placeholder() {
        let policy = transport_policy();
        let net = test_network_info();
        let compiled = PolicyCompiler::compile(&policy, &net).unwrap();

        // Domain destinations produce comments (resolved at runtime).
        assert!(
            compiled.nftables_rules.contains("# domain: github.com"),
            "nftables should contain domain placeholder comment"
        );
    }

    #[test]
    fn compile_domain_only_policy_skips_sandbox_policy_table() {
        // A policy with only domain-based rules (no CIDRs) should NOT create
        // the sandbox_policy table, because the only entries in allow_rules
        // are comment placeholders.  The base forward chain allows forwarding
        // until the DNS propagation loop resolves IPs and injects real rules.
        let policy = Policy {
            version: SCHEMA_VERSION.to_string(),
            rules: vec![PolicyRule {
                destination: Destination::Domain("github.com".to_string()),
                level: AssuranceLevel::Transport,
                protocol: Protocol::Https,
                reason: Some("GitHub access".to_string()),
            }],
        };
        let net = test_network_info();
        let compiled = PolicyCompiler::compile(&policy, &net).unwrap();

        assert!(
            compiled.nftables_rules.is_empty(),
            "domain-only policy should not produce sandbox_policy table; \
             got: {}",
            compiled.nftables_rules
        );
    }

    #[test]
    fn compile_level1_nftables_allows_dns() {
        let policy = transport_policy();
        let net = test_network_info();
        let compiled = PolicyCompiler::compile(&policy, &net).unwrap();

        assert!(
            compiled.nftables_rules.contains("udp dport 53 accept"),
            "nftables must allow DNS traffic to gateway"
        );
        assert!(
            compiled.nftables_rules.contains("tcp dport 53 accept"),
            "nftables must allow TCP DNS traffic to gateway"
        );
    }

    #[test]
    fn compile_level1_nftables_rejects_unmatched() {
        let policy = transport_policy();
        let net = test_network_info();
        let compiled = PolicyCompiler::compile(&policy, &net).unwrap();

        assert!(
            compiled.nftables_rules.contains("reject"),
            "nftables must reject unmatched traffic"
        );
    }

    #[test]
    fn compile_level1_nftables_uses_network_info() {
        let net = test_network_info();
        let policy = transport_policy();
        let compiled = PolicyCompiler::compile(&policy, &net).unwrap();

        assert!(
            compiled.nftables_rules.contains(&net.subnet),
            "nftables must reference the VM subnet"
        );
        assert!(
            compiled.nftables_rules.contains(&net.gateway_ip),
            "nftables must reference the gateway IP"
        );
    }

    #[test]
    fn compile_level1_envoy_has_tcp_passthrough() {
        let policy = transport_policy();
        let net = test_network_info();
        let compiled = PolicyCompiler::compile(&policy, &net).unwrap();

        assert!(
            compiled.envoy_config_combined().contains("tcp_proxy"),
            "Envoy config must include TCP proxy filter"
        );
        assert!(
            compiled.envoy_config_combined().contains("original_dst"),
            "Envoy config must use original_dst cluster"
        );
        assert!(
            compiled.envoy_config_combined().contains("policy_listener"),
            "Envoy config must define policy_listener"
        );
    }

    #[test]
    fn compile_level1_envoy_has_original_dst_listener_filter() {
        let policy = transport_policy();
        let net = test_network_info();
        let compiled = PolicyCompiler::compile(&policy, &net).unwrap();

        assert!(
            compiled
                .envoy_config_combined()
                .contains("envoy.filters.listener.original_dst"),
            "Envoy config must include original_dst listener filter"
        );
    }

    #[test]
    fn compile_level1_envoy_has_admin() {
        let policy = transport_policy();
        let net = test_network_info();
        let compiled = PolicyCompiler::compile(&policy, &net).unwrap();

        assert!(
            compiled.envoy_config_combined().contains("9901"),
            "Envoy config must include admin port 9901"
        );
    }

    // -- CoreDNS config generation -------------------------------------------

    #[test]
    fn coredns_config_includes_allowed_domains() {
        let policy = transport_policy();
        let net = test_network_info();
        let compiled = PolicyCompiler::compile(&policy, &net).unwrap();

        assert!(
            compiled.coredns_config.contains("github.com"),
            "CoreDNS config must include allowed domain"
        );
    }

    #[test]
    fn coredns_config_excludes_cidr_destinations() {
        let policy = transport_policy();
        let net = test_network_info();
        let compiled = PolicyCompiler::compile(&policy, &net).unwrap();

        // CIDR destinations should not appear as domains.
        assert!(
            !compiled.coredns_config.contains("140.82.112.0"),
            "CoreDNS config should not contain CIDR destinations"
        );
    }

    #[test]
    fn coredns_config_excludes_denied_domains() {
        let policy = Policy {
            version: SCHEMA_VERSION.to_string(),
            rules: vec![
                PolicyRule {
                    destination: Destination::Domain("allowed.com".to_string()),
                    level: AssuranceLevel::Transport,
                    protocol: Protocol::Any,
                    reason: None,
                },
                PolicyRule {
                    destination: Destination::Domain("denied.com".to_string()),
                    level: AssuranceLevel::Deny,
                    protocol: Protocol::Any,
                    reason: None,
                },
            ],
        };
        let net = test_network_info();
        let compiled = PolicyCompiler::compile(&policy, &net).unwrap();

        assert!(compiled.coredns_config.contains("allowed.com"));
        assert!(!compiled.coredns_config.contains("denied.com"));
    }

    #[test]
    fn coredns_config_format() {
        let config = CoreDnsConfig {
            allowed_domains: vec!["example.com".to_string(), "*.example.org".to_string()],
        };
        let content = config.to_file_content();

        // Must start with a comment header.
        assert!(content.starts_with('#'));

        // Must contain both domains.
        assert!(content.contains("example.com"));
        assert!(content.contains("*.example.org"));

        // Each domain on its own line.
        let domain_lines: Vec<&str> = content
            .lines()
            .filter(|l| !l.starts_with('#') && !l.is_empty())
            .collect();
        assert_eq!(domain_lines.len(), 2);
    }

    // -- mitmproxy config generation -----------------------------------------

    #[test]
    fn mitmproxy_config_empty_for_non_full_policy() {
        let policy = transport_policy();
        let net = test_network_info();
        let compiled = PolicyCompiler::compile(&policy, &net).unwrap();

        let config: MitmproxyConfig = serde_json::from_str(&compiled.mitmproxy_config).unwrap();
        assert!(
            config.rules.is_empty(),
            "transport-only policy should produce no mitmproxy rules"
        );
    }

    #[test]
    fn mitmproxy_config_includes_http_level_rules() {
        let policy = Policy {
            version: SCHEMA_VERSION.to_string(),
            rules: vec![PolicyRule {
                destination: Destination::Domain("api.example.com".to_string()),
                level: AssuranceLevel::Http {
                    http_filters: vec![http_filter(HttpMethod::Get, "/api/*")],
                },
                protocol: Protocol::Https,
                reason: None,
            }],
        };
        let net = test_network_info();
        let compiled = PolicyCompiler::compile(&policy, &net).unwrap();

        let config: MitmproxyConfig = serde_json::from_str(&compiled.mitmproxy_config).unwrap();
        assert_eq!(config.rules.len(), 1);
        assert_eq!(config.rules[0].host, "api.example.com");
        assert_eq!(config.rules[0].filters.len(), 1);
        assert_eq!(config.rules[0].filters[0].method, "GET");
        assert_eq!(config.rules[0].filters[0].path, "/api/*");
    }

    #[test]
    fn mitmproxy_config_emits_filter_pairs_not_cartesian_product() {
        // A rule with {GET /api, POST /webhook} should emit exactly two
        // filter pairs — not four (GET /api, GET /webhook, POST /api,
        // POST /webhook) as the old cartesian-product shape did.
        let policy = Policy {
            version: SCHEMA_VERSION.to_string(),
            rules: vec![PolicyRule {
                destination: Destination::Domain("api.example.com".to_string()),
                level: AssuranceLevel::Http {
                    http_filters: vec![
                        http_filter(HttpMethod::Get, "/api"),
                        http_filter(HttpMethod::Post, "/webhook"),
                    ],
                },
                protocol: Protocol::Https,
                reason: None,
            }],
        };
        let net = test_network_info();
        let compiled = PolicyCompiler::compile(&policy, &net).unwrap();

        let config: MitmproxyConfig = serde_json::from_str(&compiled.mitmproxy_config).unwrap();
        assert_eq!(config.rules.len(), 1);
        assert_eq!(config.rules[0].filters.len(), 2);

        let pairs: Vec<(&str, &str)> = config.rules[0]
            .filters
            .iter()
            .map(|f| (f.method.as_str(), f.path.as_str()))
            .collect();
        assert_eq!(pairs, vec![("GET", "/api"), ("POST", "/webhook")]);
    }

    #[test]
    fn mitmproxy_config_valid_json() {
        let config = MitmproxyConfig {
            rules: vec![MitmproxyRule {
                host: "example.com".to_string(),
                filters: vec![MitmproxyFilter {
                    method: "GET".to_string(),
                    path: "/*".to_string(),
                }],
            }],
        };
        let json = config.to_json();
        let parsed: MitmproxyConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.rules.len(), 1);
        assert_eq!(parsed.rules[0].filters.len(), 1);
    }

    /// Emits the compiled mitmproxy JSON for the two policies used by the
    /// failing E2E tests (`test_level3_method_restriction` and
    /// `test_level3_path_restriction`).  Locked down to a verbatim string so
    /// any accidental reshaping of the wire format — e.g., extra wrapper
    /// keys, key-case drift, or cartesian-product regression — trips the
    /// test instead of leaking to the runtime.
    #[test]
    fn mitmproxy_config_matches_e2e_failing_policies() {
        // M4 test_level3_method_restriction: `{GET /*}` — POST must deny.
        let method_policy = Policy {
            version: SCHEMA_VERSION.to_string(),
            rules: vec![PolicyRule {
                destination: Destination::Domain("httpbin.org".to_string()),
                level: AssuranceLevel::Http {
                    http_filters: vec![http_filter(HttpMethod::Get, "/*")],
                },
                protocol: Protocol::Https,
                reason: None,
            }],
        };
        // M4 test_level3_path_restriction: `{ANY /api/*}` — `/other/path`
        // must deny.
        let path_policy = Policy {
            version: SCHEMA_VERSION.to_string(),
            rules: vec![PolicyRule {
                destination: Destination::Domain("httpbin.org".to_string()),
                level: AssuranceLevel::Http {
                    http_filters: vec![http_filter(HttpMethod::Any, "/api/*")],
                },
                protocol: Protocol::Https,
                reason: None,
            }],
        };

        let net = test_network_info();
        let method_json = PolicyCompiler::compile(&method_policy, &net)
            .unwrap()
            .mitmproxy_config;
        let path_json = PolicyCompiler::compile(&path_policy, &net)
            .unwrap()
            .mitmproxy_config;

        // Intentionally verbatim — the wire format is a contract with the
        // Python addon, not an implementation detail.  Pretty-printed JSON
        // is intentional (see `MitmproxyConfig::to_json`): Python's
        // `json.load` parses both compact and pretty forms identically.
        let expected_method = "{\n  \"rules\": [\n    {\n      \"host\": \"httpbin.org\",\n      \"filters\": [\n        {\n          \"method\": \"GET\",\n          \"path\": \"/*\"\n        }\n      ]\n    }\n  ]\n}";
        let expected_path = "{\n  \"rules\": [\n    {\n      \"host\": \"httpbin.org\",\n      \"filters\": [\n        {\n          \"method\": \"ANY\",\n          \"path\": \"/api/*\"\n        }\n      ]\n    }\n  ]\n}";
        assert_eq!(method_json, expected_method);
        assert_eq!(path_json, expected_path);
    }

    // -- Preset policies -----------------------------------------------------

    #[test]
    fn preset_github_is_valid() {
        let rules = preset_allow_github();
        assert!(!rules.is_empty(), "GitHub preset must have rules");

        let policy = Policy {
            version: SCHEMA_VERSION.to_string(),
            rules,
        };
        assert!(
            PolicyCompiler::validate(&policy).is_ok(),
            "GitHub preset must be a valid policy"
        );
    }

    #[test]
    fn preset_github_covers_key_domains() {
        let rules = preset_allow_github();
        let domains: Vec<String> = rules
            .iter()
            .filter_map(|r| match &r.destination {
                Destination::Domain(d) => Some(d.clone()),
                _ => None,
            })
            .collect();

        assert!(domains.contains(&"github.com".to_string()));
        assert!(domains.iter().any(|d| d.contains("githubusercontent")));
    }

    #[test]
    fn preset_npm_is_valid() {
        let rules = preset_allow_npm();
        assert!(!rules.is_empty(), "npm preset must have rules");

        let policy = Policy {
            version: SCHEMA_VERSION.to_string(),
            rules,
        };
        assert!(
            PolicyCompiler::validate(&policy).is_ok(),
            "npm preset must be a valid policy"
        );
    }

    #[test]
    fn preset_npm_covers_registry() {
        let rules = preset_allow_npm();
        let domains: Vec<String> = rules
            .iter()
            .filter_map(|r| match &r.destination {
                Destination::Domain(d) => Some(d.clone()),
                _ => None,
            })
            .collect();

        assert!(domains.contains(&"registry.npmjs.org".to_string()));
    }

    #[test]
    fn preset_github_compiles() {
        let policy = Policy {
            version: SCHEMA_VERSION.to_string(),
            rules: preset_allow_github(),
        };
        let net = test_network_info();
        let compiled = PolicyCompiler::compile(&policy, &net).unwrap();

        // Should have domain entries in CoreDNS config.
        assert!(compiled.coredns_config.contains("github.com"));
    }

    #[test]
    fn preset_npm_compiles() {
        let policy = Policy {
            version: SCHEMA_VERSION.to_string(),
            rules: preset_allow_npm(),
        };
        let net = test_network_info();
        let compiled = PolicyCompiler::compile(&policy, &net).unwrap();

        assert!(compiled.coredns_config.contains("registry.npmjs.org"));
    }

    // -- Assurance level properties ------------------------------------------

    #[test]
    fn assurance_level_numeric_values() {
        assert_eq!(AssuranceLevel::Deny.as_u8(), 0);
        assert_eq!(AssuranceLevel::Transport.as_u8(), 1);
        assert_eq!(AssuranceLevel::Tls.as_u8(), 2);
        assert_eq!(
            AssuranceLevel::Http {
                http_filters: vec![http_filter(HttpMethod::Any, "/*")]
            }
            .as_u8(),
            3
        );
    }

    #[test]
    fn assurance_level_display() {
        assert_eq!(AssuranceLevel::Deny.to_string(), "deny");
        assert_eq!(AssuranceLevel::Transport.to_string(), "transport");
        assert_eq!(AssuranceLevel::Tls.to_string(), "tls");
        assert_eq!(
            AssuranceLevel::Http {
                http_filters: vec![http_filter(HttpMethod::Any, "/*")]
            }
            .to_string(),
            "http"
        );
    }

    // -- Destination parsing -------------------------------------------------

    #[test]
    fn destination_domain_from_string() {
        let dest: Destination = "example.com".to_string().try_into().unwrap();
        assert!(matches!(dest, Destination::Domain(d) if d == "example.com"));
    }

    #[test]
    fn destination_cidr_from_string() {
        let dest: Destination = "10.0.0.0/8".to_string().try_into().unwrap();
        assert!(matches!(dest, Destination::Cidr(c) if c == "10.0.0.0/8"));
    }

    #[test]
    fn destination_bare_ip_from_string() {
        let dest: Destination = "192.168.1.1".to_string().try_into().unwrap();
        assert!(matches!(dest, Destination::Cidr(c) if c == "192.168.1.1"));
    }

    #[test]
    fn destination_empty_string_rejected() {
        let result: Result<Destination, _> = "".to_string().try_into();
        assert!(result.is_err());
    }

    // -- CIDR validation -----------------------------------------------------

    #[test]
    fn validate_cidr_valid() {
        assert!(PolicyCompiler::validate_cidr("10.0.0.0/8").is_ok());
        assert!(PolicyCompiler::validate_cidr("192.168.1.0/24").is_ok());
        assert!(PolicyCompiler::validate_cidr("1.2.3.4").is_ok());
        assert!(PolicyCompiler::validate_cidr("0.0.0.0/0").is_ok());
    }

    #[test]
    fn validate_cidr_invalid() {
        assert!(PolicyCompiler::validate_cidr("999.0.0.0/8").is_err());
        assert!(PolicyCompiler::validate_cidr("10.0.0.0/33").is_err());
        assert!(PolicyCompiler::validate_cidr("not-an-ip").is_err());
        assert!(PolicyCompiler::validate_cidr("10.0.0.0/abc").is_err());
    }

    // -- Domain validation ---------------------------------------------------

    #[test]
    fn validate_domain_valid() {
        assert!(PolicyCompiler::validate_domain("example.com").is_ok());
        assert!(PolicyCompiler::validate_domain("sub.example.com").is_ok());
        assert!(PolicyCompiler::validate_domain("*.example.com").is_ok());
        assert!(PolicyCompiler::validate_domain("a-b.example.com").is_ok());
    }

    #[test]
    fn validate_domain_invalid() {
        assert!(PolicyCompiler::validate_domain("").is_err());
        assert!(PolicyCompiler::validate_domain("-example.com").is_err());
        assert!(PolicyCompiler::validate_domain("example-.com").is_err());
        assert!(PolicyCompiler::validate_domain("exam ple.com").is_err());
        assert!(PolicyCompiler::validate_domain("exam!ple.com").is_err());
    }

    #[test]
    fn validate_domain_accepts_bare_wildcard() {
        // Bare `*` is the synthetic unrestricted-policy destination — it
        // must pass validation even though label rules reject it.  Pinned
        // here so a future tightening of `validate_domain` does not
        // accidentally break `Policy::unrestricted()` compilation.
        assert!(PolicyCompiler::validate_domain("*").is_ok());
    }

    // -- Unrestricted policy --------------------------------------------------

    #[test]
    fn policy_unrestricted_shape() {
        let policy = Policy::unrestricted();
        assert_eq!(policy.version, SCHEMA_VERSION);
        assert_eq!(policy.rules.len(), 1);
        let rule = &policy.rules[0];
        assert!(matches!(&rule.destination, Destination::Domain(d) if d == "*"));
        assert_eq!(rule.protocol, Protocol::Any);
        match &rule.level {
            AssuranceLevel::Http { http_filters } => {
                assert_eq!(http_filters.len(), 1);
                assert_eq!(http_filters[0].method, HttpMethod::Any);
                assert_eq!(http_filters[0].path, "/*");
            }
            _ => panic!("unrestricted rule must be Http level"),
        }
        assert!(policy.is_unrestricted());
    }

    #[test]
    fn policy_is_unrestricted_rejects_mismatched_shapes() {
        // Empty policy is not unrestricted.
        let empty = Policy {
            version: SCHEMA_VERSION.to_string(),
            rules: vec![],
        };
        assert!(!empty.is_unrestricted());

        // Single Http rule but wrong destination.
        let wrong_dest = Policy {
            version: SCHEMA_VERSION.to_string(),
            rules: vec![PolicyRule {
                destination: Destination::Domain("example.com".into()),
                protocol: Protocol::Any,
                reason: None,
                level: AssuranceLevel::Http {
                    http_filters: vec![HttpFilter {
                        method: HttpMethod::Any,
                        path: "/*".into(),
                    }],
                },
            }],
        };
        assert!(!wrong_dest.is_unrestricted());

        // Right dest + Http but specific method.
        let specific_method = Policy {
            version: SCHEMA_VERSION.to_string(),
            rules: vec![PolicyRule {
                destination: Destination::Domain("*".into()),
                protocol: Protocol::Any,
                reason: None,
                level: AssuranceLevel::Http {
                    http_filters: vec![HttpFilter {
                        method: HttpMethod::Get,
                        path: "/*".into(),
                    }],
                },
            }],
        };
        assert!(!specific_method.is_unrestricted());

        // Right dest + Http but wrong level variant.
        let wrong_level = Policy {
            version: SCHEMA_VERSION.to_string(),
            rules: vec![PolicyRule {
                destination: Destination::Domain("*".into()),
                protocol: Protocol::Any,
                reason: None,
                level: AssuranceLevel::Transport,
            }],
        };
        assert!(!wrong_level.is_unrestricted());

        // Two rules that individually look unrestricted — still not the
        // canonical shape.
        let mut two_rules = Policy::unrestricted();
        two_rules.rules.push(two_rules.rules[0].clone());
        assert!(!two_rules.is_unrestricted());
    }

    #[test]
    fn policy_unrestricted_compiles_permissive_and_logged() {
        let policy = Policy::unrestricted();
        let net = test_network_info();
        let compiled = PolicyCompiler::compile(&policy, &net).expect("unrestricted must compile");

        // CoreDNS: wildcard entry in the allowed-domains body so CoreDNS
        // resolves anything the guest asks for.
        assert!(
            compiled.coredns_config.contains("\n*\n") || compiled.coredns_config.ends_with("*\n"),
            "CoreDNS config must include wildcard allow-all line:\n{}",
            compiled.coredns_config
        );

        // nftables: a non-empty allow rule covering tcp 80/443 without a
        // specific daddr (no IP literal).  This is the pre-DNS-resolve
        // allow-all rule that lets traffic through while awaiting
        // propagation.  It must match the *original-direction* L4 port
        // via `ct original proto-dst` — a bare `tcp dport { 80, 443 }`
        // would never fire because the gateway's base chain DNATs the
        // flow to the Envoy listener (port 10000) before the
        // sandbox_policy forward chain gets to evaluate it.  Regression
        // guard: the `ct original` statement must only pair with a ct
        // key (`proto-dst`, `ip daddr`, ...), never a plain L4 match
        // like `tcp dport` — that combination is a syntax error nftables
        // rejects at load time.
        assert!(
            compiled
                .nftables_rules
                .contains("ct original proto-dst { 80, 443 } accept"),
            "nftables ruleset must allow tcp 80/443 via ct original proto-dst:\n{}",
            compiled.nftables_rules
        );
        assert!(
            !compiled.nftables_rules.contains("ct original tcp dport"),
            "nftables ruleset must not pair `ct original` with `tcp dport` \
             (invalid nftables syntax):\n{}",
            compiled.nftables_rules
        );
        assert!(
            compiled.nftables_rules.contains("# unrestricted"),
            "nftables ruleset must mark the unrestricted allow line:\n{}",
            compiled.nftables_rules
        );

        // mitmproxy: one rule with host `*` and a single ANY /* filter.
        let config: MitmproxyConfig =
            serde_json::from_str(&compiled.mitmproxy_config).expect("mitmproxy config must parse");
        assert_eq!(config.rules.len(), 1);
        assert_eq!(config.rules[0].host, "*");
        assert_eq!(config.rules[0].filters.len(), 1);
        assert_eq!(config.rules[0].filters[0].method, "ANY");
        assert_eq!(config.rules[0].filters[0].path, "/*");

        // Envoy: the Http rule must emit a filter chain, but with no
        // `server_names` match (bare `*` is not a valid Envoy SNI value),
        // so traffic falls through to the default chain — i.e. original_dst
        // passthrough.  Pinned so a future compiler change cannot re-
        // introduce the invalid `server_names: ["*"]` shape.
        assert!(
            compiled.envoy_config_combined().contains("level3_wildcard"),
            "Envoy config must emit a level-3 chain for the `*` rule:\n{}",
            compiled.envoy_config_combined()
        );
        assert!(
            !compiled.envoy_config_combined().contains("server_names: [\"*\"]"),
            "Envoy config must NOT use `server_names: [\"*\"]` (invalid SNI match):\n{}",
            compiled.envoy_config_combined()
        );
    }

    #[test]
    fn policy_unrestricted_dto_round_trip() {
        use crate::api::{PolicyDto, PolicyLevelDto};

        let original = Policy::unrestricted();
        let dto: PolicyDto = (&original).into();
        assert_eq!(dto.rules.len(), 1);
        match &dto.rules[0].level {
            PolicyLevelDto::Http { http_filters } => {
                assert_eq!(http_filters.len(), 1);
                assert_eq!(http_filters[0].method, HttpMethod::Any);
                assert_eq!(http_filters[0].path, "/*");
            }
            _ => panic!("DTO must carry Http level"),
        }

        // JSON round-trip: serialize the domain Policy, parse it back,
        // and confirm the round-tripped Policy still satisfies
        // `is_unrestricted()` — this is the shape the daemon stores and
        // that `describe` detects.
        let json = serde_json::to_string(&original).expect("Policy must serialize");
        let parsed: Policy = serde_json::from_str(&json).expect("Policy must deserialize");
        assert!(parsed.is_unrestricted());
    }

    // -- End-to-end compilation with mixed levels ----------------------------

    #[test]
    fn compile_mixed_policy() {
        let policy = Policy {
            version: SCHEMA_VERSION.to_string(),
            rules: vec![
                PolicyRule {
                    destination: Destination::Domain("github.com".to_string()),
                    level: AssuranceLevel::Transport,
                    protocol: Protocol::Https,
                    reason: None,
                },
                PolicyRule {
                    destination: Destination::Domain("blocked.com".to_string()),
                    level: AssuranceLevel::Deny,
                    protocol: Protocol::Any,
                    reason: None,
                },
                PolicyRule {
                    destination: Destination::Cidr("10.0.0.0/8".to_string()),
                    level: AssuranceLevel::Transport,
                    protocol: Protocol::Tcp,
                    reason: None,
                },
            ],
        };
        let net = test_network_info();
        let compiled = PolicyCompiler::compile(&policy, &net).unwrap();

        // nftables should have allow for the CIDR.
        assert!(compiled.nftables_rules.contains("10.0.0.0/8"));

        // CoreDNS should include github.com but not blocked.com.
        assert!(compiled.coredns_config.contains("github.com"));
        assert!(!compiled.coredns_config.contains("blocked.com"));

        // mitmproxy should be empty (no full-level rules).
        let config: MitmproxyConfig = serde_json::from_str(&compiled.mitmproxy_config).unwrap();
        assert!(config.rules.is_empty());
    }

    // -- Protocol default behavior -------------------------------------------

    #[test]
    fn protocol_default_is_any() {
        assert_eq!(Protocol::default(), Protocol::Any);
    }

    #[test]
    fn protocol_serde_roundtrip() {
        let protocols = vec![
            Protocol::Tcp,
            Protocol::Udp,
            Protocol::Http,
            Protocol::Https,
            Protocol::Any,
        ];
        for proto in protocols {
            let json = serde_json::to_string(&proto).unwrap();
            let parsed: Protocol = serde_json::from_str(&json).unwrap();
            assert_eq!(parsed, proto);
        }
    }

    // -- UDP destination nftables -------------------------------------------

    #[test]
    fn compile_udp_cidr_produces_udp_rules() {
        let policy = Policy {
            version: SCHEMA_VERSION.to_string(),
            rules: vec![PolicyRule {
                destination: Destination::Cidr("8.8.8.0/24".to_string()),
                level: AssuranceLevel::Transport,
                protocol: Protocol::Udp,
                reason: Some("DNS servers".to_string()),
            }],
        };
        let net = test_network_info();
        let compiled = PolicyCompiler::compile(&policy, &net).unwrap();

        assert!(
            compiled.nftables_rules.contains("udp dport"),
            "UDP protocol should produce udp dport nftables rules"
        );
        assert!(
            compiled.nftables_rules.contains("8.8.8.0/24"),
            "nftables should contain the UDP CIDR"
        );
    }

    // -- Test helpers (L2/L3) -------------------------------------------------

    fn tls_policy() -> Policy {
        Policy {
            version: SCHEMA_VERSION.to_string(),
            rules: vec![
                PolicyRule {
                    destination: Destination::Domain("secure.example.com".to_string()),
                    level: AssuranceLevel::Tls,
                    protocol: Protocol::Https,
                    reason: Some("TLS passthrough".to_string()),
                },
                PolicyRule {
                    destination: Destination::Domain("api.secure.io".to_string()),
                    level: AssuranceLevel::Tls,
                    protocol: Protocol::Https,
                    reason: Some("Another TLS destination".to_string()),
                },
            ],
        }
    }

    /// Http-level policy with a single `(ANY, /*)` wildcard filter —
    /// semantically equivalent to pre-M9-S10 "level: full, no constraints"
    /// (permit any HTTP request to the host).
    fn full_policy() -> Policy {
        Policy {
            version: SCHEMA_VERSION.to_string(),
            rules: vec![PolicyRule {
                destination: Destination::Domain("inspected.example.com".to_string()),
                level: AssuranceLevel::Http {
                    http_filters: vec![http_filter(HttpMethod::Any, "/*")],
                },
                protocol: Protocol::Https,
                reason: Some("Full inspection".to_string()),
            }],
        }
    }

    fn full_policy_with_constraints() -> Policy {
        Policy {
            version: SCHEMA_VERSION.to_string(),
            rules: vec![PolicyRule {
                destination: Destination::Domain("api.example.com".to_string()),
                level: AssuranceLevel::Http {
                    http_filters: vec![
                        http_filter(HttpMethod::Get, "/api/v1/*"),
                        http_filter(HttpMethod::Get, "/health"),
                        http_filter(HttpMethod::Post, "/api/v1/*"),
                        http_filter(HttpMethod::Post, "/health"),
                    ],
                },
                protocol: Protocol::Https,
                reason: Some("Constrained API access".to_string()),
            }],
        }
    }

    fn mixed_l1_l2_l3_policy() -> Policy {
        Policy {
            version: SCHEMA_VERSION.to_string(),
            rules: vec![
                PolicyRule {
                    destination: Destination::Domain("github.com".to_string()),
                    level: AssuranceLevel::Transport,
                    protocol: Protocol::Https,
                    reason: Some("L1 transport".to_string()),
                },
                PolicyRule {
                    destination: Destination::Domain("pinned.example.com".to_string()),
                    level: AssuranceLevel::Tls,
                    protocol: Protocol::Https,
                    reason: Some("L2 TLS passthrough".to_string()),
                },
                PolicyRule {
                    destination: Destination::Domain("monitored.example.com".to_string()),
                    level: AssuranceLevel::Http {
                        http_filters: vec![http_filter(HttpMethod::Get, "/api/*")],
                    },
                    protocol: Protocol::Https,
                    reason: Some("L3 full inspection".to_string()),
                },
            ],
        }
    }

    // -- Level 2 compilation (TLS/SNI) ----------------------------------------

    #[test]
    fn compile_level2_envoy_has_tls_inspector() {
        let policy = tls_policy();
        let net = test_network_info();
        let compiled = PolicyCompiler::compile(&policy, &net).unwrap();

        assert!(
            compiled
                .envoy_config_combined()
                .contains("envoy.filters.listener.tls_inspector"),
            "L2 Envoy config must include tls_inspector listener filter"
        );
    }

    #[test]
    fn compile_level2_envoy_has_sni_filter_chains() {
        let policy = tls_policy();
        let net = test_network_info();
        let compiled = PolicyCompiler::compile(&policy, &net).unwrap();

        assert!(
            compiled
                .envoy_config_combined()
                .contains("server_names: [\"secure.example.com\"]"),
            "L2 Envoy config must have SNI match for secure.example.com"
        );
        assert!(
            compiled
                .envoy_config_combined()
                .contains("server_names: [\"api.secure.io\"]"),
            "L2 Envoy config must have SNI match for api.secure.io"
        );
    }

    #[test]
    fn compile_level2_envoy_routes_to_original_dst() {
        let policy = tls_policy();
        let net = test_network_info();
        let compiled = PolicyCompiler::compile(&policy, &net).unwrap();

        // Both L2 filter chains should route to original_dst (no MITM).
        assert!(
            compiled.envoy_config_combined().contains("level2_secure_example_com"),
            "L2 filter chain should have level2_ stat prefix"
        );
        assert!(
            compiled.envoy_config_combined().contains("level2_api_secure_io"),
            "L2 filter chain should have level2_ stat prefix for second domain"
        );
    }

    #[test]
    fn compile_level2_envoy_has_original_dst_listener_filter() {
        let policy = tls_policy();
        let net = test_network_info();
        let compiled = PolicyCompiler::compile(&policy, &net).unwrap();

        assert!(
            compiled
                .envoy_config_combined()
                .contains("envoy.filters.listener.original_dst"),
            "L2 Envoy config must still include original_dst listener filter"
        );
    }

    #[test]
    fn compile_level2_listener_does_not_route_to_mitmproxy() {
        let policy = tls_policy();
        let net = test_network_info();
        let compiled = PolicyCompiler::compile(&policy, &net).unwrap();

        // As of M9-S18 the mitmproxy cluster is **always present in the
        // bootstrap** — it is scaffolded now so that M9-S19's L3 cutover
        // to HTTP/1.1 CONNECT tunnelling is a pure listener change. The
        // behavioural guarantee for L2 is that no listener filter chain
        // routes traffic to the mitmproxy cluster; L2 traffic must still
        // flow through `original_dst`.
        assert!(
            !compiled
                .envoy_listener_config
                .contains("cluster: mitmproxy"),
            "L2 listener must not route any filter chain to the mitmproxy cluster\nlistener:\n{}",
            compiled.envoy_listener_config
        );
    }

    #[test]
    fn compile_level2_no_default_filter_chain() {
        let policy = tls_policy();
        let net = test_network_info();
        let compiled = PolicyCompiler::compile(&policy, &net).unwrap();

        // Without L1 transport rules, there should be no default (unmatch) chain.
        assert!(
            !compiled.envoy_config_combined().contains("policy_tcp_passthrough"),
            "L2-only Envoy config should not include a default passthrough chain"
        );
    }

    #[test]
    fn compile_level2_mitmproxy_config_empty() {
        let policy = tls_policy();
        let net = test_network_info();
        let compiled = PolicyCompiler::compile(&policy, &net).unwrap();

        let config: MitmproxyConfig = serde_json::from_str(&compiled.mitmproxy_config).unwrap();
        assert!(
            config.rules.is_empty(),
            "L2-only policy should produce no mitmproxy rules"
        );
    }

    #[test]
    fn compile_level2_coredns_includes_domains() {
        let policy = tls_policy();
        let net = test_network_info();
        let compiled = PolicyCompiler::compile(&policy, &net).unwrap();

        assert!(compiled.coredns_config.contains("secure.example.com"));
        assert!(compiled.coredns_config.contains("api.secure.io"));
    }

    #[test]
    fn compile_level2_domain_only_produces_no_nftables() {
        let policy = tls_policy();
        let net = test_network_info();
        let compiled = PolicyCompiler::compile(&policy, &net).unwrap();

        // Domain-only policies produce no sandbox_policy table; the DNS
        // propagation loop will inject real rules once IPs are resolved.
        assert!(
            compiled.nftables_rules.is_empty(),
            "TLS domain-only policy should not produce sandbox_policy table; \
             got: {}",
            compiled.nftables_rules
        );
    }

    // -- Level 3 compilation (full/mitmproxy) ---------------------------------

    #[test]
    fn compile_level3_envoy_has_tls_inspector() {
        let policy = full_policy();
        let net = test_network_info();
        let compiled = PolicyCompiler::compile(&policy, &net).unwrap();

        assert!(
            compiled
                .envoy_config_combined()
                .contains("envoy.filters.listener.tls_inspector"),
            "L3 Envoy config must include tls_inspector listener filter"
        );
    }

    #[test]
    fn compile_level3_envoy_routes_to_original_dst() {
        let policy = full_policy();
        let net = test_network_info();
        let compiled = PolicyCompiler::compile(&policy, &net).unwrap();

        assert!(
            compiled
                .envoy_config_combined()
                .contains("server_names: [\"inspected.example.com\"]"),
            "L3 Envoy config must have SNI match for the inspected domain"
        );
        // L3 traffic routes to original_dst (passthrough) in Envoy.
        // The actual redirect to mitmproxy happens at the nftables
        // level (sandbox_l3 DNAT rules) to preserve SO_ORIGINAL_DST.
        assert!(
            compiled.envoy_config_combined().contains("cluster: original_dst"),
            "L3 filter chain must route to original_dst (mitmproxy redirect is via nftables)"
        );
        assert!(
            !compiled.envoy_config_combined().contains("cluster: mitmproxy"),
            "L3 filter chain must NOT route to mitmproxy cluster (breaks SO_ORIGINAL_DST)"
        );
        assert!(
            compiled
                .envoy_config_combined()
                .contains("level3_inspected_example_com"),
            "L3 filter chain should have level3_ stat prefix"
        );
    }

    #[test]
    fn compile_level3_listener_does_not_route_to_mitmproxy_yet() {
        let policy = full_policy();
        let net = test_network_info();
        let compiled = PolicyCompiler::compile(&policy, &net).unwrap();

        // **M9-S18 semantics.** The mitmproxy cluster is defined in the
        // static bootstrap from this session onwards, but no filter
        // chain routes traffic to it yet — L3 traffic continues to reach
        // mitmproxy via the `sandbox_l3` nftables DNAT shortcut
        // established in M9-S6. M9-S19 will cut every L3 chain over to
        // the mitmproxy cluster via `tcp_proxy.tunneling_config` and
        // remove the `sandbox_l3` table.
        assert!(
            !compiled
                .envoy_listener_config
                .contains("cluster: mitmproxy"),
            "L3 listener must not route any filter chain to mitmproxy yet (that's M9-S19)\n\
             listener:\n{}",
            compiled.envoy_listener_config
        );
    }

    #[test]
    fn compile_level3_mitmproxy_has_rules() {
        let policy = full_policy();
        let net = test_network_info();
        let compiled = PolicyCompiler::compile(&policy, &net).unwrap();

        let config: MitmproxyConfig = serde_json::from_str(&compiled.mitmproxy_config).unwrap();
        assert_eq!(config.rules.len(), 1);
        assert_eq!(config.rules[0].host, "inspected.example.com");
        // `full_policy()` uses a wildcard filter `(ANY, /*)`.
        assert_eq!(config.rules[0].filters.len(), 1);
        assert_eq!(config.rules[0].filters[0].method, "ANY");
        assert_eq!(config.rules[0].filters[0].path, "/*");
    }

    #[test]
    fn compile_level3_with_constraints_mitmproxy() {
        let policy = full_policy_with_constraints();
        let net = test_network_info();
        let compiled = PolicyCompiler::compile(&policy, &net).unwrap();

        let config: MitmproxyConfig = serde_json::from_str(&compiled.mitmproxy_config).unwrap();
        assert_eq!(config.rules.len(), 1);
        assert_eq!(config.rules[0].host, "api.example.com");

        let pairs: Vec<(&str, &str)> = config.rules[0]
            .filters
            .iter()
            .map(|f| (f.method.as_str(), f.path.as_str()))
            .collect();
        assert_eq!(
            pairs,
            vec![
                ("GET", "/api/v1/*"),
                ("GET", "/health"),
                ("POST", "/api/v1/*"),
                ("POST", "/health"),
            ]
        );
    }

    #[test]
    fn compile_level3_coredns_includes_domain() {
        let policy = full_policy();
        let net = test_network_info();
        let compiled = PolicyCompiler::compile(&policy, &net).unwrap();

        assert!(compiled.coredns_config.contains("inspected.example.com"));
    }

    // -- Mixed policy (L1+L2+L3) ----------------------------------------------

    #[test]
    fn compile_mixed_l1_l2_l3_envoy_has_all_listener_filters() {
        let policy = mixed_l1_l2_l3_policy();
        let net = test_network_info();
        let compiled = PolicyCompiler::compile(&policy, &net).unwrap();

        assert!(
            compiled
                .envoy_config_combined()
                .contains("envoy.filters.listener.tls_inspector"),
            "mixed policy must include tls_inspector"
        );
        assert!(
            compiled
                .envoy_config_combined()
                .contains("envoy.filters.listener.original_dst"),
            "mixed policy must include original_dst listener filter"
        );
    }

    #[test]
    fn compile_mixed_l1_l2_l3_envoy_has_sni_chains() {
        let policy = mixed_l1_l2_l3_policy();
        let net = test_network_info();
        let compiled = PolicyCompiler::compile(&policy, &net).unwrap();

        // L2 SNI chain
        assert!(
            compiled
                .envoy_config_combined()
                .contains("server_names: [\"pinned.example.com\"]"),
            "mixed policy must have L2 SNI chain"
        );
        assert!(
            compiled.envoy_config_combined().contains("level2_pinned_example_com"),
            "mixed policy must have L2 stat prefix"
        );

        // L3 SNI chain
        assert!(
            compiled
                .envoy_config_combined()
                .contains("server_names: [\"monitored.example.com\"]"),
            "mixed policy must have L3 SNI chain"
        );
        assert!(
            compiled
                .envoy_config_combined()
                .contains("level3_monitored_example_com"),
            "mixed policy must have L3 stat prefix"
        );
    }

    #[test]
    fn compile_mixed_l1_l2_l3_envoy_has_default_chain() {
        let policy = mixed_l1_l2_l3_policy();
        let net = test_network_info();
        let compiled = PolicyCompiler::compile(&policy, &net).unwrap();

        assert!(
            compiled.envoy_config_combined().contains("policy_tcp_passthrough"),
            "mixed policy must have L1 default passthrough chain"
        );
    }

    #[test]
    fn compile_mixed_l1_l2_l3_envoy_default_chain_is_last() {
        let policy = mixed_l1_l2_l3_policy();
        let net = test_network_info();
        let compiled = PolicyCompiler::compile(&policy, &net).unwrap();

        // The default passthrough chain (no filter_chain_match) must come after
        // the SNI-specific chains. We verify by checking that
        // "policy_tcp_passthrough" appears after all "server_names" entries.
        let passthrough_pos = compiled
            .envoy_config_combined()
            .find("policy_tcp_passthrough")
            .expect("must contain passthrough");
        let last_sni_pos = compiled
            .envoy_config_combined()
            .rfind("server_names")
            .expect("must contain server_names");
        assert!(
            passthrough_pos > last_sni_pos,
            "default passthrough chain must come after all SNI-matched chains"
        );
    }

    #[test]
    fn compile_mixed_l1_l2_l3_bootstrap_has_both_clusters() {
        let policy = mixed_l1_l2_l3_policy();
        let net = test_network_info();
        let compiled = PolicyCompiler::compile(&policy, &net).unwrap();

        // As of M9-S18 the bootstrap defines **both** clusters
        // (`original_dst` and `mitmproxy`) on every session regardless
        // of policy content. The `mitmproxy` cluster is scaffolded so
        // M9-S19's cutover is an isolated listener change.
        assert!(
            compiled
                .envoy_bootstrap_config
                .contains("name: original_dst"),
            "bootstrap must define the original_dst cluster"
        );
        assert!(
            compiled.envoy_bootstrap_config.contains("name: mitmproxy"),
            "bootstrap must define the mitmproxy cluster (M9-S18+)"
        );
        // The behavioural guarantee survives the split: the listener
        // must not yet route traffic to mitmproxy (that's M9-S19).
        assert!(
            !compiled
                .envoy_listener_config
                .contains("cluster: mitmproxy"),
            "listener must not route to mitmproxy yet"
        );
    }

    #[test]
    fn compile_mixed_l1_l2_l3_mitmproxy_has_l3_rules_only() {
        let policy = mixed_l1_l2_l3_policy();
        let net = test_network_info();
        let compiled = PolicyCompiler::compile(&policy, &net).unwrap();

        let config: MitmproxyConfig = serde_json::from_str(&compiled.mitmproxy_config).unwrap();

        // Only L3 destinations appear in mitmproxy config.
        assert_eq!(config.rules.len(), 1);
        assert_eq!(config.rules[0].host, "monitored.example.com");

        // L3 rule with one `(GET, /api/*)` filter pair.
        assert_eq!(config.rules[0].filters.len(), 1);
        assert_eq!(config.rules[0].filters[0].method, "GET");
        assert_eq!(config.rules[0].filters[0].path, "/api/*");
    }

    #[test]
    fn compile_mixed_l1_l2_l3_coredns_includes_all_allowed() {
        let policy = mixed_l1_l2_l3_policy();
        let net = test_network_info();
        let compiled = PolicyCompiler::compile(&policy, &net).unwrap();

        assert!(compiled.coredns_config.contains("github.com"));
        assert!(compiled.coredns_config.contains("pinned.example.com"));
        assert!(compiled.coredns_config.contains("monitored.example.com"));
    }

    #[test]
    fn compile_mixed_l1_l2_l3_domain_only_produces_no_nftables() {
        let policy = mixed_l1_l2_l3_policy();
        let net = test_network_info();
        let compiled = PolicyCompiler::compile(&policy, &net).unwrap();

        // All rules are domain-based (no CIDRs), so only comment placeholders
        // are generated.  The sandbox_policy table should NOT be created;
        // the DNS propagation loop injects real rules once IPs are resolved.
        assert!(
            compiled.nftables_rules.is_empty(),
            "mixed domain-only policy should not produce sandbox_policy table; \
             got: {}",
            compiled.nftables_rules
        );
    }

    // -- Edge cases: wildcard domains in SNI -----------------------------------

    #[test]
    fn compile_level2_wildcard_domain_sni() {
        let policy = Policy {
            version: SCHEMA_VERSION.to_string(),
            rules: vec![PolicyRule {
                destination: Destination::Domain("*.example.com".to_string()),
                level: AssuranceLevel::Tls,
                protocol: Protocol::Https,
                reason: None,
            }],
        };
        let net = test_network_info();
        let compiled = PolicyCompiler::compile(&policy, &net).unwrap();

        // Wildcard domains are passed to Envoy SNI matching as-is. Envoy
        // supports wildcard SNI matching in filter_chain_match.
        assert!(
            compiled
                .envoy_config_combined()
                .contains("server_names: [\"*.example.com\"]"),
            "wildcard domain should appear in SNI match"
        );
        assert!(
            compiled
                .envoy_config_combined()
                .contains("level2_wildcard_example_com"),
            "wildcard stat prefix should use 'wildcard' replacement"
        );
    }

    #[test]
    fn compile_level3_wildcard_domain_sni() {
        let policy = Policy {
            version: SCHEMA_VERSION.to_string(),
            rules: vec![PolicyRule {
                destination: Destination::Domain("*.inspected.io".to_string()),
                level: AssuranceLevel::Http {
                    http_filters: vec![http_filter(HttpMethod::Any, "/*")],
                },
                protocol: Protocol::Https,
                reason: None,
            }],
        };
        let net = test_network_info();
        let compiled = PolicyCompiler::compile(&policy, &net).unwrap();

        assert!(
            compiled
                .envoy_config_combined()
                .contains("server_names: [\"*.inspected.io\"]"),
            "wildcard domain should appear in L3 SNI match"
        );
        assert!(
            compiled.envoy_config_combined().contains("cluster: original_dst"),
            "wildcard L3 chain must route to original_dst (mitmproxy redirect via nftables)"
        );
        assert!(
            !compiled.envoy_config_combined().contains("cluster: mitmproxy"),
            "wildcard L3 chain must not route to mitmproxy cluster"
        );
        assert!(
            compiled
                .envoy_config_combined()
                .contains("level3_wildcard_inspected_io"),
            "wildcard L3 stat prefix should use 'wildcard' replacement"
        );
    }

    // -- Edge cases: multiple destinations at same level -----------------------

    #[test]
    fn compile_multiple_level2_destinations() {
        let policy = Policy {
            version: SCHEMA_VERSION.to_string(),
            rules: vec![
                PolicyRule {
                    destination: Destination::Domain("a.example.com".to_string()),
                    level: AssuranceLevel::Tls,
                    protocol: Protocol::Https,
                    reason: None,
                },
                PolicyRule {
                    destination: Destination::Domain("b.example.com".to_string()),
                    level: AssuranceLevel::Tls,
                    protocol: Protocol::Https,
                    reason: None,
                },
                PolicyRule {
                    destination: Destination::Domain("c.example.com".to_string()),
                    level: AssuranceLevel::Tls,
                    protocol: Protocol::Https,
                    reason: None,
                },
            ],
        };
        let net = test_network_info();
        let compiled = PolicyCompiler::compile(&policy, &net).unwrap();

        // Each L2 destination gets its own filter chain.
        assert!(
            compiled
                .envoy_config_combined()
                .contains("server_names: [\"a.example.com\"]")
        );
        assert!(
            compiled
                .envoy_config_combined()
                .contains("server_names: [\"b.example.com\"]")
        );
        assert!(
            compiled
                .envoy_config_combined()
                .contains("server_names: [\"c.example.com\"]")
        );

        // All route to original_dst (not mitmproxy).
        assert!(!compiled.envoy_config_combined().contains("cluster: mitmproxy"));
    }

    #[test]
    fn compile_multiple_level3_destinations() {
        let policy = Policy {
            version: SCHEMA_VERSION.to_string(),
            rules: vec![
                PolicyRule {
                    destination: Destination::Domain("api.one.com".to_string()),
                    level: AssuranceLevel::Http {
                        http_filters: vec![http_filter(HttpMethod::Get, "/*")],
                    },
                    protocol: Protocol::Https,
                    reason: None,
                },
                PolicyRule {
                    destination: Destination::Domain("api.two.com".to_string()),
                    level: AssuranceLevel::Http {
                        http_filters: vec![http_filter(HttpMethod::Any, "/*")],
                    },
                    protocol: Protocol::Https,
                    reason: None,
                },
            ],
        };
        let net = test_network_info();
        let compiled = PolicyCompiler::compile(&policy, &net).unwrap();

        // Both L3 destinations get SNI chains to original_dst (L3 redirect via nftables).
        assert!(
            compiled
                .envoy_config_combined()
                .contains("server_names: [\"api.one.com\"]")
        );
        assert!(
            compiled
                .envoy_config_combined()
                .contains("server_names: [\"api.two.com\"]")
        );
        assert!(
            !compiled.envoy_config_combined().contains("cluster: mitmproxy"),
            "L3 filter chains must not route to mitmproxy cluster"
        );

        // mitmproxy config has rules for both.
        let config: MitmproxyConfig = serde_json::from_str(&compiled.mitmproxy_config).unwrap();
        assert_eq!(config.rules.len(), 2);
        let hosts: Vec<&str> = config.rules.iter().map(|r| r.host.as_str()).collect();
        assert!(hosts.contains(&"api.one.com"));
        assert!(hosts.contains(&"api.two.com"));

        let one_rule = config
            .rules
            .iter()
            .find(|r| r.host == "api.one.com")
            .unwrap();
        assert_eq!(one_rule.filters.len(), 1);
        assert_eq!(one_rule.filters[0].method, "GET");
        assert_eq!(one_rule.filters[0].path, "/*");

        let two_rule = config
            .rules
            .iter()
            .find(|r| r.host == "api.two.com")
            .unwrap();
        assert_eq!(two_rule.filters.len(), 1);
        assert_eq!(two_rule.filters[0].method, "ANY");
        assert_eq!(two_rule.filters[0].path, "/*");
    }

    // -- L2-only policy (no L1) does not produce default chain ----------------

    #[test]
    fn compile_level2_only_no_passthrough_chain() {
        let policy = tls_policy();
        let net = test_network_info();
        let compiled = PolicyCompiler::compile(&policy, &net).unwrap();

        // Without L1 rules, no default passthrough chain.
        assert!(
            !compiled.envoy_config_combined().contains("policy_tcp_passthrough"),
            "L2-only should not have a default passthrough chain"
        );

        // But should still have original_dst cluster (for L2 forwarding).
        assert!(compiled.envoy_config_combined().contains("name: original_dst"));
    }

    // -- L3-only policy (no L1) does not produce default chain ----------------

    #[test]
    fn compile_level3_only_no_passthrough_chain() {
        let policy = full_policy();
        let net = test_network_info();
        let compiled = PolicyCompiler::compile(&policy, &net).unwrap();

        assert!(
            !compiled.envoy_config_combined().contains("policy_tcp_passthrough"),
            "L3-only should not have a default passthrough chain"
        );
    }

    // -- Sanitize stat prefix -------------------------------------------------

    #[test]
    fn sanitize_stat_prefix_replaces_dots() {
        assert_eq!(
            PolicyCompiler::sanitize_stat_prefix("example.com"),
            "example_com"
        );
    }

    #[test]
    fn sanitize_stat_prefix_replaces_wildcards() {
        assert_eq!(
            PolicyCompiler::sanitize_stat_prefix("*.example.com"),
            "wildcard_example_com"
        );
    }

    #[test]
    fn sanitize_stat_prefix_complex_domain() {
        assert_eq!(
            PolicyCompiler::sanitize_stat_prefix("sub.deep.example.co.uk"),
            "sub_deep_example_co_uk"
        );
    }

    // -- M9-S18 invariant: listener framing is identical across policies ----
    //
    // Every listener generation (deny-all, L1-only, L2, L3, mixed) must
    // share the same `listener_filters` block so the atomic listener
    // writer can transition between them without draining the listener.
    // As a consequence `tls_inspector` is now present in every listener
    // — it is a no-op for non-TLS traffic and is necessary for L2/L3
    // SNI-based filter_chain_match routing.

    #[test]
    fn compile_level1_includes_tls_inspector_for_framing_stability() {
        let policy = transport_policy();
        let net = test_network_info();
        let compiled = PolicyCompiler::compile(&policy, &net).unwrap();

        assert!(
            compiled.envoy_config_combined().contains("tls_inspector"),
            "M9-S18: L1-only listener must include tls_inspector so the \
             listener-filters block stays identical across LDS generations \
             (required by the atomic listener writer's invariant)"
        );
    }

    // -- Envoy config YAML structure verification -----------------------------

    #[test]
    fn compile_level2_envoy_admin_present() {
        let policy = tls_policy();
        let net = test_network_info();
        let compiled = PolicyCompiler::compile(&policy, &net).unwrap();

        assert!(
            compiled.envoy_config_combined().contains("9901"),
            "L2 Envoy config must include admin port 9901"
        );
    }

    #[test]
    fn compile_level3_envoy_admin_present() {
        let policy = full_policy();
        let net = test_network_info();
        let compiled = PolicyCompiler::compile(&policy, &net).unwrap();

        assert!(
            compiled.envoy_config_combined().contains("9901"),
            "L3 Envoy config must include admin port 9901"
        );
    }

    // -- M9-S18: Bootstrap / listener split -----------------------------------
    //
    // These tests verify the xDS-based split introduced in M9-S18. The
    // invariants under test are:
    //   * The bootstrap is policy-agnostic and contains the LDS config,
    //     both clusters (`original_dst` + `mitmproxy`), and the admin
    //     endpoint.
    //   * The mitmproxy cluster carries the HTTP/1.1 pin required by
    //     mitmproxy's lack of HTTP/2 CONNECT support (upstream `#1138`)
    //     and a TCP health check.
    //   * The listener file is framed by the filter-chains marker
    //     comments and is written through the filesystem LDS path.
    //   * The listener file emitted today still routes every filter
    //     chain to `original_dst` (M9-S19 performs the L3 → mitmproxy
    //     cutover).

    #[test]
    fn bootstrap_is_policy_agnostic() {
        let net = test_network_info();
        let deny_all = Policy {
            version: SCHEMA_VERSION.to_string(),
            rules: vec![],
        };
        let compiled_deny = PolicyCompiler::compile(&deny_all, &net).unwrap();
        let compiled_l1 = PolicyCompiler::compile(&transport_policy(), &net).unwrap();
        let compiled_l2 = PolicyCompiler::compile(&tls_policy(), &net).unwrap();
        let compiled_l3 = PolicyCompiler::compile(&full_policy(), &net).unwrap();

        // Every policy produces the exact same bootstrap content —
        // changes go into the listener file, not the bootstrap.
        assert_eq!(
            compiled_deny.envoy_bootstrap_config,
            compiled_l1.envoy_bootstrap_config
        );
        assert_eq!(
            compiled_l1.envoy_bootstrap_config,
            compiled_l2.envoy_bootstrap_config
        );
        assert_eq!(
            compiled_l2.envoy_bootstrap_config,
            compiled_l3.envoy_bootstrap_config
        );
    }

    #[test]
    fn bootstrap_contains_lds_config_pointing_at_listener_file() {
        let compiled = PolicyCompiler::compile(&tls_policy(), &test_network_info()).unwrap();
        let bootstrap = &compiled.envoy_bootstrap_config;

        assert!(
            bootstrap.contains("dynamic_resources:"),
            "bootstrap must carry dynamic_resources:\n{bootstrap}"
        );
        assert!(
            bootstrap.contains("lds_config:"),
            "bootstrap must carry lds_config:\n{bootstrap}"
        );
        assert!(
            bootstrap.contains("path_config_source:"),
            "bootstrap must use path_config_source for filesystem LDS:\n{bootstrap}"
        );
        assert!(
            bootstrap.contains(&format!("path: {LISTENER_FILE_IN_CONTAINER}")),
            "lds_config.path must point at {LISTENER_FILE_IN_CONTAINER}\n{bootstrap}"
        );
        assert!(
            bootstrap.contains("watched_directory:"),
            "lds_config must set watched_directory (required for MovedTo inotify events, upstream #20474):\n{bootstrap}"
        );
        assert!(
            bootstrap.contains(&format!("path: {LISTENER_DIR_IN_CONTAINER}")),
            "watched_directory must be {LISTENER_DIR_IN_CONTAINER}\n{bootstrap}"
        );
    }

    #[test]
    fn bootstrap_has_no_static_listener() {
        let compiled = PolicyCompiler::compile(&tls_policy(), &test_network_info()).unwrap();
        let bootstrap = &compiled.envoy_bootstrap_config;

        // Envoy refuses to promote a statically-declared listener to
        // LDS mid-session. The bootstrap therefore **must not** declare
        // any listener — `static_resources` is clusters-only.
        assert!(
            !bootstrap.contains("listeners:"),
            "bootstrap must not declare a static listener (breaks LDS handover):\n{bootstrap}"
        );
    }

    #[test]
    fn bootstrap_defines_mitmproxy_cluster_with_http11_pin() {
        let compiled = PolicyCompiler::compile(&tls_policy(), &test_network_info()).unwrap();
        let bootstrap = &compiled.envoy_bootstrap_config;

        assert!(
            bootstrap.contains("name: mitmproxy"),
            "bootstrap must define the mitmproxy cluster:\n{bootstrap}"
        );
        assert!(
            bootstrap.contains("address: 127.0.0.1"),
            "mitmproxy cluster must target loopback 127.0.0.1:\n{bootstrap}"
        );
        assert!(
            bootstrap.contains("port_value: 18080"),
            "mitmproxy cluster must target port 18080 (not 8080 — see design spec):\n{bootstrap}"
        );
        assert!(
            bootstrap.contains("envoy.extensions.upstreams.http.v3.HttpProtocolOptions"),
            "mitmproxy cluster must pin HTTP/1.1 upstream via HttpProtocolOptions (mitmproxy lacks HTTP/2 CONNECT — upstream #1138):\n{bootstrap}"
        );
        assert!(
            bootstrap.contains("explicit_http_config:"),
            "HttpProtocolOptions must use explicit_http_config:\n{bootstrap}"
        );
        assert!(
            bootstrap.contains("http_protocol_options: {}"),
            "explicit_http_config must select http_protocol_options (HTTP/1.1 — not http2_protocol_options):\n{bootstrap}"
        );
    }

    #[test]
    fn mitmproxy_cluster_has_tcp_health_check() {
        let compiled = PolicyCompiler::compile(&tls_policy(), &test_network_info()).unwrap();
        let bootstrap = &compiled.envoy_bootstrap_config;

        // TCP health check — 1s timeout, 5s interval, failing after 2
        // unhealthy probes. A dead mitmproxy surfaces in Envoy admin
        // stats so operators can detect it before traffic impact.
        assert!(
            bootstrap.contains("tcp_health_check:"),
            "mitmproxy cluster must declare a tcp_health_check:\n{bootstrap}"
        );
        assert!(
            bootstrap.contains("timeout: 1s"),
            "tcp health-check must use 1s timeout:\n{bootstrap}"
        );
        assert!(
            bootstrap.contains("interval: 5s"),
            "tcp health-check must use 5s interval:\n{bootstrap}"
        );
    }

    #[test]
    fn mitmproxy_cluster_has_no_upstream_proxy_protocol_wrapper() {
        let compiled = PolicyCompiler::compile(&tls_policy(), &test_network_info()).unwrap();
        let bootstrap = &compiled.envoy_bootstrap_config;

        // The design spec explicitly forbids wrapping the upstream
        // transport socket in PROXY protocol. The CONNECT preface for
        // M9-S19 is emitted via per-chain `tcp_proxy.tunneling_config`,
        // not via a transport-socket header.
        assert!(
            !bootstrap.contains("upstream_proxy_protocol"),
            "mitmproxy cluster must NOT wrap its transport in upstream_proxy_protocol:\n{bootstrap}"
        );
    }

    #[test]
    fn listener_file_is_framed_by_filter_chains_markers() {
        let compiled = PolicyCompiler::compile(&tls_policy(), &test_network_info()).unwrap();
        let listener = &compiled.envoy_listener_config;

        assert!(
            listener.contains(FILTER_CHAINS_BEGIN_MARKER),
            "listener must contain BEGIN marker '{FILTER_CHAINS_BEGIN_MARKER}':\n{listener}"
        );
        assert!(
            listener.contains(FILTER_CHAINS_END_MARKER),
            "listener must contain END marker '{FILTER_CHAINS_END_MARKER}':\n{listener}"
        );

        let begin = listener.find(FILTER_CHAINS_BEGIN_MARKER).unwrap();
        let end = listener.find(FILTER_CHAINS_END_MARKER).unwrap();
        assert!(
            begin < end,
            "BEGIN marker must precede END marker\n{listener}"
        );

        // The region between the markers must contain `filter_chains:`.
        let between = &listener[begin + FILTER_CHAINS_BEGIN_MARKER.len()..end];
        assert!(
            between.contains("filter_chains:"),
            "mutable region must carry the filter_chains: key\nbetween:\n{between}"
        );
    }

    #[test]
    fn listener_file_is_lds_discovery_response() {
        let compiled = PolicyCompiler::compile(&tls_policy(), &test_network_info()).unwrap();
        let listener = &compiled.envoy_listener_config;

        assert!(
            listener.contains("resources:"),
            "listener file must be an LDS DiscoveryResponse (needs `resources:`):\n{listener}"
        );
        assert!(
            listener.contains("type.googleapis.com/envoy.config.listener.v3.Listener"),
            "LDS resource must carry the v3.Listener type URL:\n{listener}"
        );
        assert!(
            listener.contains("name: policy_listener"),
            "listener must be named `policy_listener`:\n{listener}"
        );
    }

    #[test]
    fn initial_listener_helper_matches_deny_all() {
        // The initial listener written at gateway-create time is the
        // same as the deny-all listener. Keeping them equal means the
        // atomic writer's invariant check treats the first post-policy
        // write as a pure filter_chains diff.
        assert_eq!(
            PolicyCompiler::compile_initial_envoy_listener(),
            PolicyCompiler::envoy_deny_all_listener()
        );
    }

    #[test]
    fn listener_routes_every_chain_to_original_dst_today() {
        // M9-S18 preserves today's chain shape byte-for-byte. Every
        // filter chain — L1, L2, L3 — must still target the
        // `original_dst` cluster so this session is purely additive.
        // M9-S19 flips L3 chains over to the `mitmproxy` cluster via
        // `tcp_proxy.tunneling_config`.
        let compiled = PolicyCompiler::compile(&full_policy(), &test_network_info()).unwrap();
        let listener = &compiled.envoy_listener_config;

        assert!(
            listener.contains("cluster: original_dst"),
            "listener must have at least one chain routing to original_dst:\n{listener}"
        );
        assert!(
            !listener.contains("cluster: mitmproxy"),
            "M9-S18 listener must NOT yet route any chain to mitmproxy (cutover is M9-S19):\n{listener}"
        );
    }

    /// Split a listener YAML into (head, middle, tail) at the filter-chains
    /// markers. Mirrors `atomic_listener_writer::split_at_markers`.
    fn listener_head_middle_tail(listener: &str) -> (String, String, String) {
        let begin = listener
            .find(FILTER_CHAINS_BEGIN_MARKER)
            .expect("listener must contain BEGIN marker");
        let after_begin = begin + FILTER_CHAINS_BEGIN_MARKER.len();
        let end_rel = listener[after_begin..]
            .find(FILTER_CHAINS_END_MARKER)
            .expect("listener must contain END marker");
        let end = after_begin + end_rel;
        (
            listener[..begin].to_string(),
            listener[after_begin..end].to_string(),
            listener[end + FILTER_CHAINS_END_MARKER.len()..].to_string(),
        )
    }

    /// CRITICAL M9-S18 INVARIANT: the listener file's head and tail regions
    /// (everything outside the filter-chains markers) must be IDENTICAL
    /// across every policy shape, otherwise
    /// [`AtomicListenerWriter`](crate::atomic_listener_writer::AtomicListenerWriter)
    /// will reject the transition with
    /// [`ListenerWriteError::InvariantViolated`](crate::atomic_listener_writer::ListenerWriteError::InvariantViolated)
    /// and policy updates will fail.
    ///
    /// This test caught a regression where `listener_filters` was emitted
    /// conditionally (only when `has_tls || has_http`), so a transition
    /// from the deny-all initial listener to an L1-only policy differed in
    /// the head region and was rejected by the writer — breaking every
    /// policy-applying E2E test.
    #[test]
    fn listener_framing_is_identical_across_policy_shapes() {
        // Reference: the deny-all initial listener that sandboxd seeds
        // into the bind-mount before Envoy starts.
        let (ref_head, _, ref_tail) =
            listener_head_middle_tail(&PolicyCompiler::envoy_deny_all_listener());

        // Exercise every distinct policy shape and confirm that each
        // listener's head/tail matches the reference exactly.
        let empty_policy = Policy {
            version: SCHEMA_VERSION.to_string(),
            rules: vec![],
        };
        let shapes: Vec<(&str, Policy)> = vec![
            ("empty policy (deny-all)", empty_policy),
            ("transport-only (L1)", transport_policy()),
            ("tls-only (L2)", tls_policy()),
            ("http-only (L3)", full_policy()),
            ("http-with-constraints (L3)", full_policy_with_constraints()),
        ];

        for (label, policy) in shapes {
            let compiled = PolicyCompiler::compile(&policy, &test_network_info()).unwrap();
            let (head, _, tail) = listener_head_middle_tail(&compiled.envoy_listener_config);
            assert_eq!(
                head, ref_head,
                "policy shape `{label}` produced a DIFFERENT head region — \
                 this will break the atomic listener writer's invariant:\n\
                 expected head:\n{ref_head}\n\nactual head:\n{head}"
            );
            assert_eq!(
                tail, ref_tail,
                "policy shape `{label}` produced a DIFFERENT tail region — \
                 this will break the atomic listener writer's invariant:\n\
                 expected tail:\n{ref_tail}\n\nactual tail:\n{tail}"
            );
        }
    }
}
