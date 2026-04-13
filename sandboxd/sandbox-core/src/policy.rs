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

/// A single policy rule describing the allowed assurance level for a
/// destination.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct PolicyRule {
    /// Destination: domain name, IP address, or CIDR block.
    pub destination: Destination,
    /// Assurance level (deny, transport, tls, full).
    pub level: AssuranceLevel,
    /// Protocol constraint.
    #[serde(default = "default_protocol")]
    pub protocol: Protocol,
    /// HTTP method/path constraints (level `full` only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub constraints: Option<HttpConstraints>,
    /// Human-readable reason for the rule.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// Assurance level for a destination.
///
/// Each level provides different visibility and control over the traffic:
/// - **Deny** (0): No traffic allowed.
/// - **Transport** (1): Opaque TCP/UDP passthrough. No inspection.
/// - **Tls** (2): TLS-verified passthrough. SNI extraction, no MITM.
/// - **Full** (3): HTTPS through mitmproxy (MITM with session CA).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum AssuranceLevel {
    Deny,
    Transport,
    Tls,
    Full,
}

impl AssuranceLevel {
    /// Return the numeric value (0-3) of this assurance level.
    pub fn as_u8(&self) -> u8 {
        match self {
            Self::Deny => 0,
            Self::Transport => 1,
            Self::Tls => 2,
            Self::Full => 3,
        }
    }
}

impl fmt::Display for AssuranceLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Deny => write!(f, "deny"),
            Self::Transport => write!(f, "transport"),
            Self::Tls => write!(f, "tls"),
            Self::Full => write!(f, "full"),
        }
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

/// HTTP-level constraints for assurance level `full`.
///
/// When present, the mitmproxy addon enforces these constraints on each
/// request. An empty list means "allow all" for that field.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct HttpConstraints {
    /// Allowed HTTP methods (e.g. `["GET", "POST"]`). Empty = allow all.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub methods: Vec<String>,
    /// Allowed path prefixes (e.g. `["/api/v1/"]`). Empty = allow all.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub paths: Vec<String>,
}

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
            constraints: None,
            reason: Some("GitHub web and API".to_string()),
        },
        PolicyRule {
            destination: Destination::Domain("*.github.com".to_string()),
            level: AssuranceLevel::Transport,
            protocol: Protocol::Https,
            constraints: None,
            reason: Some("GitHub subdomains (API, uploads, etc.)".to_string()),
        },
        PolicyRule {
            destination: Destination::Domain("*.githubusercontent.com".to_string()),
            level: AssuranceLevel::Transport,
            protocol: Protocol::Https,
            constraints: None,
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
            constraints: None,
            reason: Some("npm package registry".to_string()),
        },
        PolicyRule {
            destination: Destination::Domain("*.npmjs.org".to_string()),
            level: AssuranceLevel::Transport,
            protocol: Protocol::Https,
            constraints: None,
            reason: Some("npm registry CDN".to_string()),
        },
        PolicyRule {
            destination: Destination::Domain("*.npmjs.com".to_string()),
            level: AssuranceLevel::Transport,
            protocol: Protocol::Https,
            constraints: None,
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
        let mut content = String::from("# CoreDNS allowed domains (generated by sandbox policy engine)\n");
        content.push_str("# One domain per line. Wildcard entries start with *.\n");
        for domain in &self.allowed_domains {
            content.push_str(domain);
            content.push('\n');
        }
        content
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
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MitmproxyRule {
    /// Hostname to match (exact or wildcard like `*.example.com`).
    pub host: String,
    /// Allowed HTTP methods. `None` means allow all.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub methods: Option<Vec<String>>,
    /// Allowed path prefixes. `None` means allow all.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub paths: Option<Vec<String>>,
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
    /// Envoy filter chain configuration (YAML).
    pub envoy_config: String,
    /// mitmproxy addon configuration (JSON).
    pub mitmproxy_config: String,
    /// CoreDNS policy file content (one domain per line).
    pub coredns_config: String,
}

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
        let envoy_config = Self::compile_envoy(policy);
        let mitmproxy_config = Self::compile_mitmproxy(policy);
        let coredns_config = Self::compile_coredns(policy);

        Ok(CompiledPolicy {
            nftables_rules,
            envoy_config,
            mitmproxy_config,
            coredns_config,
        })
    }

    /// Validate policy consistency and correctness.
    ///
    /// Checks:
    /// - Schema version is compatible
    /// - HTTP constraints only appear on HTTP/HTTPS protocols at level `full`
    /// - No contradictory rules (same destination with conflicting levels)
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

        // Track destinations to detect contradictions.
        let mut seen_destinations: HashMap<String, AssuranceLevel> = HashMap::new();

        for (i, rule) in policy.rules.iter().enumerate() {
            let ctx = format!("rule {i} (destination: {})", rule.destination);

            // HTTP constraints require level full + HTTP/HTTPS protocol.
            if rule.constraints.is_some() {
                if rule.level != AssuranceLevel::Full {
                    return Err(SandboxError::Internal(format!(
                        "{ctx}: HTTP constraints are only valid at assurance level 'full'"
                    )));
                }
                if !matches!(rule.protocol, Protocol::Http | Protocol::Https | Protocol::Any) {
                    return Err(SandboxError::Internal(format!(
                        "{ctx}: HTTP constraints require protocol 'http', 'https', or 'any'"
                    )));
                }
            }

            // Level full requires HTTP-capable protocol.
            if rule.level == AssuranceLevel::Full
                && matches!(rule.protocol, Protocol::Udp)
            {
                return Err(SandboxError::Internal(format!(
                    "{ctx}: assurance level 'full' is not compatible with protocol 'udp'"
                )));
            }

            // Validate destination syntax.
            match &rule.destination {
                Destination::Cidr(cidr) => {
                    Self::validate_cidr(cidr).map_err(|e| {
                        SandboxError::Internal(format!("{ctx}: invalid CIDR: {e}"))
                    })?;
                }
                Destination::Domain(domain) => {
                    Self::validate_domain(domain).map_err(|e| {
                        SandboxError::Internal(format!("{ctx}: invalid domain: {e}"))
                    })?;
                }
            }

            // Check for contradictory rules: same destination string with
            // different assurance levels.
            let dest_key = rule.destination.to_string();
            if let Some(prev_level) = seen_destinations.get(&dest_key) {
                if *prev_level != rule.level {
                    return Err(SandboxError::Internal(format!(
                        "{ctx}: contradicts earlier rule (level '{}' vs '{}')",
                        prev_level, rule.level
                    )));
                }
            } else {
                seen_destinations.insert(dest_key, rule.level);
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
            if rule.level == AssuranceLevel::Deny {
                continue;
            }

            match &rule.destination {
                Destination::Cidr(cidr) => {
                    // For CIDR destinations, generate direct IP-based rules.
                    let ip_or_cidr = cidr.as_str();

                    match rule.protocol {
                        Protocol::Tcp | Protocol::Https | Protocol::Http | Protocol::Any => {
                            allow_rules.push(format!(
                                "        ip daddr {ip_or_cidr} tcp dport {{ 80, 443 }} accept"
                            ));
                        }
                        Protocol::Udp => {
                            allow_rules.push(format!(
                                "        ip daddr {ip_or_cidr} udp dport {{ 80, 443 }} accept"
                            ));
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

        // If no allow rules, return an empty string — the base deny-all is
        // sufficient.
        if allow_rules.is_empty() {
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

    /// Compile Envoy configuration for the policy.
    ///
    /// For level 1: opaque TCP passthrough. Generates per-destination filter
    /// chain entries that match by destination port and forward via TCP proxy
    /// using the `original_dst` cluster.
    fn compile_envoy(policy: &Policy) -> String {
        let has_transport_rules = policy
            .rules
            .iter()
            .any(|r| r.level == AssuranceLevel::Transport);

        // For a policy with only deny rules, or no rules at all, return a
        // minimal Envoy config that rejects everything.
        if !has_transport_rules && !policy.rules.iter().any(|r| r.level.as_u8() > 0) {
            return Self::envoy_deny_all();
        }

        // For level 1 transport rules, the existing base Envoy config
        // (original_dst cluster with TCP passthrough) is sufficient. We
        // regenerate it here to ensure it is self-contained.
        let mut filter_chains = Vec::new();

        // Collect all unique destinations with transport-level access.
        let transport_rules: Vec<&PolicyRule> = policy
            .rules
            .iter()
            .filter(|r| r.level == AssuranceLevel::Transport)
            .collect();

        if !transport_rules.is_empty() {
            // For level 1 transport, a single default filter chain with TCP
            // proxy to original_dst handles all allowed destinations. The
            // nftables layer controls which IPs reach Envoy.
            filter_chains.push(
                r#"        - filters:
            - name: envoy.filters.network.tcp_proxy
              typed_config:
                "@type": type.googleapis.com/envoy.extensions.filters.network.tcp_proxy.v3.TcpProxy
                stat_prefix: policy_tcp_passthrough
                cluster: original_dst"#
                    .to_string(),
            );
        }

        let filter_chains_yaml = filter_chains.join("\n");

        format!(
            r#"# Envoy configuration (generated by sandbox policy engine)
static_resources:
  listeners:
    - name: policy_listener
      address:
        socket_address:
          address: 0.0.0.0
          port_value: 10000
      listener_filters:
        - name: envoy.filters.listener.original_dst
          typed_config:
            "@type": type.googleapis.com/envoy.extensions.filters.listener.original_dst.v3.OriginalDst
      filter_chains:
{filter_chains_yaml}

  clusters:
    - name: original_dst
      type: ORIGINAL_DST
      lb_policy: CLUSTER_PROVIDED
      connect_timeout: 10s

admin:
  address:
    socket_address:
      address: 127.0.0.1
      port_value: 9901
"#
        )
    }

    /// Compile mitmproxy configuration for the policy.
    ///
    /// Only level `full` rules produce mitmproxy rules. For level 0-2,
    /// mitmproxy is not involved.
    fn compile_mitmproxy(policy: &Policy) -> String {
        let rules: Vec<MitmproxyRule> = policy
            .rules
            .iter()
            .filter(|r| r.level == AssuranceLevel::Full)
            .map(|r| {
                let host = r.destination.to_string();
                let methods = r
                    .constraints
                    .as_ref()
                    .and_then(|c| {
                        if c.methods.is_empty() {
                            None
                        } else {
                            Some(c.methods.clone())
                        }
                    });
                let paths = r
                    .constraints
                    .as_ref()
                    .and_then(|c| {
                        if c.paths.is_empty() {
                            None
                        } else {
                            Some(c.paths.clone())
                        }
                    });
                MitmproxyRule {
                    host,
                    methods,
                    paths,
                }
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
            .filter(|r| r.level != AssuranceLevel::Deny)
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
                return Err(format!(
                    "label '{}' exceeds 63 characters",
                    &label[..20]
                ));
            }
            if !label
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-')
            {
                return Err(format!("label '{label}' contains invalid characters"));
            }
            if label.starts_with('-') || label.ends_with('-') {
                return Err(format!("label '{label}' must not start or end with '-'"));
            }
        }

        Ok(())
    }

    /// Generate a minimal Envoy config that has no filter chains (deny all).
    fn envoy_deny_all() -> String {
        r#"# Envoy configuration (generated by sandbox policy engine)
# Deny-all: no filter chains configured.
static_resources:
  listeners:
    - name: policy_listener
      address:
        socket_address:
          address: 0.0.0.0
          port_value: 10000
      filter_chains: []

  clusters: []

admin:
  address:
    socket_address:
      address: 127.0.0.1
      port_value: 9901
"#
        .to_string()
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
                    constraints: None,
                    reason: Some("GitHub access".to_string()),
                },
                PolicyRule {
                    destination: Destination::Cidr("140.82.112.0/20".to_string()),
                    level: AssuranceLevel::Transport,
                    protocol: Protocol::Tcp,
                    constraints: None,
                    reason: Some("GitHub IP range".to_string()),
                },
            ],
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
    fn parse_policy_with_constraints() {
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

        let policy: Policy = serde_json::from_str(json).unwrap();
        assert_eq!(policy.rules.len(), 1);
        assert_eq!(policy.rules[0].level, AssuranceLevel::Full);

        let constraints = policy.rules[0].constraints.as_ref().unwrap();
        assert_eq!(constraints.methods, vec!["GET", "POST"]);
        assert_eq!(constraints.paths, vec!["/api/v1/"]);
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
        assert!(schema_str.contains("deny"), "schema must include 'deny' level");
        assert!(
            schema_str.contains("transport"),
            "schema must include 'transport' level"
        );
        assert!(schema_str.contains("tls"), "schema must include 'tls' level");
        assert!(schema_str.contains("full"), "schema must include 'full' level");
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
    fn validate_rejects_level_full_with_udp() {
        let policy = Policy {
            version: SCHEMA_VERSION.to_string(),
            rules: vec![PolicyRule {
                destination: Destination::Domain("example.com".to_string()),
                level: AssuranceLevel::Full,
                protocol: Protocol::Udp,
                constraints: None,
                reason: None,
            }],
        };
        let err = PolicyCompiler::validate(&policy).unwrap_err();
        assert!(
            err.to_string().contains("not compatible with protocol 'udp'"),
            "expected full+udp error, got: {err}"
        );
    }

    #[test]
    fn validate_rejects_constraints_on_non_full_level() {
        let policy = Policy {
            version: SCHEMA_VERSION.to_string(),
            rules: vec![PolicyRule {
                destination: Destination::Domain("example.com".to_string()),
                level: AssuranceLevel::Transport,
                protocol: Protocol::Https,
                constraints: Some(HttpConstraints {
                    methods: vec!["GET".to_string()],
                    paths: vec![],
                }),
                reason: None,
            }],
        };
        let err = PolicyCompiler::validate(&policy).unwrap_err();
        assert!(
            err.to_string()
                .contains("HTTP constraints are only valid at assurance level 'full'"),
            "expected constraints error, got: {err}"
        );
    }

    #[test]
    fn validate_rejects_constraints_on_udp_protocol() {
        let policy = Policy {
            version: SCHEMA_VERSION.to_string(),
            rules: vec![PolicyRule {
                destination: Destination::Domain("example.com".to_string()),
                level: AssuranceLevel::Full,
                protocol: Protocol::Udp,
                constraints: Some(HttpConstraints {
                    methods: vec!["GET".to_string()],
                    paths: vec![],
                }),
                reason: None,
            }],
        };
        // This should fail on both the full+udp check and the constraints+udp check.
        let err = PolicyCompiler::validate(&policy).unwrap_err();
        assert!(
            err.to_string().contains("not compatible with protocol 'udp'")
                || err.to_string().contains("HTTP constraints require"),
            "expected protocol incompatibility error, got: {err}"
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
                    constraints: None,
                    reason: None,
                },
                PolicyRule {
                    destination: Destination::Domain("example.com".to_string()),
                    level: AssuranceLevel::Full,
                    protocol: Protocol::Any,
                    constraints: None,
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
                    constraints: None,
                    reason: None,
                },
                PolicyRule {
                    destination: Destination::Domain("example.com".to_string()),
                    level: AssuranceLevel::Transport,
                    protocol: Protocol::Https,
                    constraints: None,
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
                constraints: None,
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
                constraints: None,
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
                constraints: None,
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
                constraints: None,
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
                constraints: None,
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
            compiled.envoy_config.contains("filter_chains: []"),
            "deny-all policy should produce empty Envoy filter chains"
        );

        // mitmproxy: empty rules array.
        let mitmproxy: MitmproxyConfig =
            serde_json::from_str(&compiled.mitmproxy_config).unwrap();
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
                constraints: None,
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
            compiled.nftables_rules.contains("table inet sandbox_policy"),
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
            compiled.envoy_config.contains("tcp_proxy"),
            "Envoy config must include TCP proxy filter"
        );
        assert!(
            compiled.envoy_config.contains("original_dst"),
            "Envoy config must use original_dst cluster"
        );
        assert!(
            compiled.envoy_config.contains("policy_listener"),
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
                .envoy_config
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
            compiled.envoy_config.contains("9901"),
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
                    constraints: None,
                    reason: None,
                },
                PolicyRule {
                    destination: Destination::Domain("denied.com".to_string()),
                    level: AssuranceLevel::Deny,
                    protocol: Protocol::Any,
                    constraints: None,
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
            allowed_domains: vec![
                "example.com".to_string(),
                "*.example.org".to_string(),
            ],
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

        let config: MitmproxyConfig =
            serde_json::from_str(&compiled.mitmproxy_config).unwrap();
        assert!(
            config.rules.is_empty(),
            "transport-only policy should produce no mitmproxy rules"
        );
    }

    #[test]
    fn mitmproxy_config_includes_full_level_rules() {
        let policy = Policy {
            version: SCHEMA_VERSION.to_string(),
            rules: vec![PolicyRule {
                destination: Destination::Domain("api.example.com".to_string()),
                level: AssuranceLevel::Full,
                protocol: Protocol::Https,
                constraints: Some(HttpConstraints {
                    methods: vec!["GET".to_string()],
                    paths: vec!["/api/".to_string()],
                }),
                reason: None,
            }],
        };
        let net = test_network_info();
        let compiled = PolicyCompiler::compile(&policy, &net).unwrap();

        let config: MitmproxyConfig =
            serde_json::from_str(&compiled.mitmproxy_config).unwrap();
        assert_eq!(config.rules.len(), 1);
        assert_eq!(config.rules[0].host, "api.example.com");
        assert_eq!(
            config.rules[0].methods.as_ref().unwrap(),
            &["GET".to_string()]
        );
        assert_eq!(
            config.rules[0].paths.as_ref().unwrap(),
            &["/api/".to_string()]
        );
    }

    #[test]
    fn mitmproxy_config_valid_json() {
        let config = MitmproxyConfig {
            rules: vec![MitmproxyRule {
                host: "example.com".to_string(),
                methods: None,
                paths: None,
            }],
        };
        let json = config.to_json();
        let parsed: MitmproxyConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.rules.len(), 1);
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
        assert_eq!(AssuranceLevel::Full.as_u8(), 3);
    }

    #[test]
    fn assurance_level_display() {
        assert_eq!(AssuranceLevel::Deny.to_string(), "deny");
        assert_eq!(AssuranceLevel::Transport.to_string(), "transport");
        assert_eq!(AssuranceLevel::Tls.to_string(), "tls");
        assert_eq!(AssuranceLevel::Full.to_string(), "full");
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
                    constraints: None,
                    reason: None,
                },
                PolicyRule {
                    destination: Destination::Domain("blocked.com".to_string()),
                    level: AssuranceLevel::Deny,
                    protocol: Protocol::Any,
                    constraints: None,
                    reason: None,
                },
                PolicyRule {
                    destination: Destination::Cidr("10.0.0.0/8".to_string()),
                    level: AssuranceLevel::Transport,
                    protocol: Protocol::Tcp,
                    constraints: None,
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
        let config: MitmproxyConfig =
            serde_json::from_str(&compiled.mitmproxy_config).unwrap();
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
                constraints: None,
                reason: Some("DNS servers".to_string()),
            }],
        };
        let net = test_network_info();
        let compiled = PolicyCompiler::compile(&policy, &net).unwrap();

        assert!(
            compiled.nftables_rules.contains("udp dport"),
            "UDP protocol should produce UDP nftables rules"
        );
        assert!(
            compiled.nftables_rules.contains("8.8.8.0/24"),
            "nftables should contain the UDP CIDR"
        );
    }
}
