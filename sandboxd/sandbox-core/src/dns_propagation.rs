use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::process::Command;
use std::time::{Duration, Instant};

use serde::Deserialize;
use tracing::{debug, info};

use crate::atomic_listener_writer::{AtomicListenerWriter, session_listener_host_path};
use crate::error::SandboxError;
use crate::gateway::{self, GatewayManager};
use crate::network::NetworkInfo;
use crate::policy::{
    AssuranceLevel, Destination, Policy, PolicyCompiler, render_two_table_ruleset,
};
use crate::session::SessionId;

// ---------------------------------------------------------------------------
// Resolved.json types (matches CoreDNS plugin output)
// ---------------------------------------------------------------------------

/// Top-level structure of the resolved.json report file written by CoreDNS.
#[derive(Debug, Clone, Deserialize)]
pub struct ResolvedReport {
    pub mappings: Vec<ResolvedMapping>,
}

/// A single domain-to-IP mapping from CoreDNS resolution.
#[derive(Debug, Clone, Deserialize)]
pub struct ResolvedMapping {
    pub domain: String,
    pub ips: Vec<String>,
    pub ttl: u32,
    pub timestamp: String,
}

// ---------------------------------------------------------------------------
// DNS cache
// ---------------------------------------------------------------------------

/// TTL-aware cache of domain-to-IP mappings resolved by CoreDNS.
#[derive(Debug, Clone)]
pub struct DnsCache {
    entries: HashMap<String, DnsCacheEntry>,
}

/// A single cached DNS resolution entry.
#[derive(Debug, Clone)]
pub struct DnsCacheEntry {
    pub domain: String,
    pub ips: Vec<Ipv4Addr>,
    pub ttl: Duration,
    pub resolved_at: Instant,
}

impl DnsCache {
    /// Create an empty DNS cache.
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
        }
    }

    /// Update the cache with fresh resolution data.
    ///
    /// Returns a list of domains whose IPs changed (added, removed, or modified).
    pub fn update(&mut self, report: &ResolvedReport) -> Vec<DnsChange> {
        let mut changes = Vec::new();
        let now = Instant::now();

        // Track which domains are still present in the report.
        let mut seen_domains: Vec<String> = Vec::new();

        for mapping in &report.mappings {
            seen_domains.push(mapping.domain.clone());

            let new_ips: Vec<Ipv4Addr> = mapping
                .ips
                .iter()
                .filter_map(|ip_str| ip_str.parse::<Ipv4Addr>().ok())
                .collect();

            if new_ips.is_empty() {
                continue;
            }

            let ttl = Duration::from_secs(u64::from(mapping.ttl));

            if let Some(existing) = self.entries.get(&mapping.domain) {
                // Check if IPs changed.
                let mut old_sorted = existing.ips.clone();
                old_sorted.sort();
                let mut new_sorted = new_ips.clone();
                new_sorted.sort();

                if old_sorted != new_sorted {
                    changes.push(DnsChange {
                        domain: mapping.domain.clone(),
                        old_ips: existing.ips.clone(),
                        new_ips: new_ips.clone(),
                        change_type: DnsChangeType::IpsChanged,
                    });
                }
            } else {
                changes.push(DnsChange {
                    domain: mapping.domain.clone(),
                    old_ips: Vec::new(),
                    new_ips: new_ips.clone(),
                    change_type: DnsChangeType::NewDomain,
                });
            }

            self.entries.insert(
                mapping.domain.clone(),
                DnsCacheEntry {
                    domain: mapping.domain.clone(),
                    ips: new_ips,
                    ttl,
                    resolved_at: now,
                },
            );
        }

        // Check for domains that were previously resolved but are now missing.
        let removed: Vec<String> = self
            .entries
            .keys()
            .filter(|d| !seen_domains.contains(d))
            .cloned()
            .collect();

        for domain in &removed {
            if let Some(entry) = self.entries.remove(domain) {
                changes.push(DnsChange {
                    domain: domain.clone(),
                    old_ips: entry.ips,
                    new_ips: Vec::new(),
                    change_type: DnsChangeType::Removed,
                });
            }
        }

        changes
    }

    /// Return all cached entries.
    pub fn entries(&self) -> &HashMap<String, DnsCacheEntry> {
        &self.entries
    }

    /// Check if any entries have expired TTLs.
    pub fn has_expired_entries(&self) -> bool {
        let now = Instant::now();
        self.entries
            .values()
            .any(|entry| now.duration_since(entry.resolved_at) > entry.ttl)
    }

    /// Return domains with expired TTLs.
    pub fn expired_domains(&self) -> Vec<String> {
        let now = Instant::now();
        self.entries
            .iter()
            .filter(|(_, entry)| now.duration_since(entry.resolved_at) > entry.ttl)
            .map(|(domain, _)| domain.clone())
            .collect()
    }
}

impl Default for DnsCache {
    fn default() -> Self {
        Self::new()
    }
}

/// A detected change in DNS resolution.
#[derive(Debug, Clone)]
pub struct DnsChange {
    pub domain: String,
    pub old_ips: Vec<Ipv4Addr>,
    pub new_ips: Vec<Ipv4Addr>,
    pub change_type: DnsChangeType,
}

/// Type of DNS change detected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnsChangeType {
    /// A new domain was resolved for the first time.
    NewDomain,
    /// The IPs for an existing domain changed.
    IpsChanged,
    /// A previously resolved domain is no longer in the report (fail-closed).
    Removed,
}

// ---------------------------------------------------------------------------
// DNS propagation
// ---------------------------------------------------------------------------

/// Read the resolved.json file from a gateway container via `docker exec`.
pub fn read_resolved_json(session_id: &SessionId) -> Result<ResolvedReport, SandboxError> {
    let container = gateway::container_name(session_id);

    let output = Command::new("docker")
        .args(["exec", &container, "cat", "/etc/coredns/resolved.json"])
        .output()
        .map_err(|e| {
            SandboxError::Gateway(format!(
                "failed to read resolved.json from {container}: {e}"
            ))
        })?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        // If the file doesn't exist yet, return an empty report rather than
        // failing hard. CoreDNS may not have written it yet.
        if stderr.contains("No such file") {
            return Ok(ResolvedReport {
                mappings: Vec::new(),
            });
        }
        return Err(SandboxError::Gateway(format!(
            "failed to read resolved.json from {container}: {stderr}"
        )));
    }

    let content = String::from_utf8_lossy(&output.stdout);
    if content.trim().is_empty() {
        return Ok(ResolvedReport {
            mappings: Vec::new(),
        });
    }

    serde_json::from_str(&content)
        .map_err(|e| SandboxError::Gateway(format!("failed to parse resolved.json: {e}")))
}

/// Generate nftables rules for resolved domain IPs.
///
/// This produces the full two-table ruleset (`sandbox_dnat` +
/// `sandbox_policy`) that admits traffic to the resolved IPs for
/// domains in the policy, joined with the rule's explicit port
/// (v2 schema). The shape matches [`PolicyCompiler::compile_nftables`]
/// byte-for-byte — both entry points delegate to the shared
/// [`render_two_table_ruleset`] helper so the chains stay in lockstep.
///
/// **v2 shape (M10-S1 / Phase 3B):** per-destination allowance lives in
/// two nftables concat sets keyed on `ipv4_addr . inet_service`, one per
/// L4 protocol (`policy_allow_tcp`, `policy_allow_udp`). Set elements
/// are `<ip_or_cidr> . <port>` pairs.
///
/// **M10-S3 shape (post deny-logger):** the filtering decision lives in
/// `sandbox_dnat.prerouting` as conditional DNAT — policy-allowed
/// destinations route to Envoy :10000; everything else falls through to
/// the deny-logger :10001 / :10002. `sandbox_policy` holds only an
/// `output` chain admitting gateway-originated egress to policy-allowed
/// destinations. Both tables carry identical copies of the concat sets
/// (cross-table set references are unsupported on the pinned nft 1.0.6
/// kernel — see policy.rs for details).
///
/// **DNS → policy join happens here.** The DNS cache itself
/// (CoreDNS `ReportEntry`) is unchanged — it stays a pure
/// `(domain, ip, ttl)` stream. This function attaches the rule's
/// `port` (and routes to the `tcp`/`udp` set based on the rule's
/// protocol) when it materialises the effective nftables ruleset.
/// See `.tasks/specs/2026-04-21-port-explicit-policies-presets-observability-design.md`
/// §"Compiler consequences — nftables" (Part 1, lines 173-177).
///
/// Called by the DNS propagation loop; both tables are fully
/// regenerated on each call (flush-and-redefine, not incremental
/// `nft add element`). One atomic `nft -f` transaction updates both
/// copies of each set.
///
/// Fail-closed: domains with no cache entry contribute no set elements,
/// so traffic to them falls through `sandbox_dnat.prerouting` to the
/// deny-logger.
pub fn generate_domain_ip_rules(
    policy: &Policy,
    cache: &DnsCache,
    network_info: &NetworkInfo,
) -> String {
    let mut tcp_elements: Vec<String> = Vec::new();
    let mut udp_elements: Vec<String> = Vec::new();

    for rule in &policy.rules {
        if matches!(rule.level, AssuranceLevel::Deny) {
            continue;
        }

        let port = rule.port;
        match &rule.host {
            Destination::Cidr(cidr) => {
                let element = format!("{cidr} . {port}");
                match rule.protocol {
                    crate::policy::Protocol::Tcp => tcp_elements.push(element),
                    crate::policy::Protocol::Udp => udp_elements.push(element),
                }
            }
            Destination::Domain(domain) => {
                // Join the DNS cache's (domain, ip) entries with the
                // rule's (port, protocol) to produce (ip, port) set
                // elements. A domain with no cache entry produces no
                // elements — fail-closed by default.
                let Some(entry) = cache.entries().get(domain.as_str()) else {
                    continue;
                };
                for ip in &entry.ips {
                    let element = format!("{ip} . {port}");
                    match rule.protocol {
                        crate::policy::Protocol::Tcp => tcp_elements.push(element),
                        crate::policy::Protocol::Udp => udp_elements.push(element),
                    }
                }
            }
        }
    }

    // If neither set has any elements, return empty — nothing to
    // inject. The gateway's initial `sandbox_dnat` rule shape (laid down
    // at create_gateway time) still fall-throughs to the deny-logger,
    // so pre-resolution traffic is fail-closed.
    if tcp_elements.is_empty() && udp_elements.is_empty() {
        return String::new();
    }

    // Two-table emission matching `PolicyCompiler::compile_nftables`.
    // The DNS propagation loop rewrites BOTH tables' concat sets on
    // every resolved-domain change: `sandbox_dnat` so the VM-egress
    // DNAT decision admits the new IPs, and `sandbox_policy` so the
    // gateway's upstream connections to those IPs are admitted too.
    render_two_table_ruleset(&tcp_elements, &udp_elements, network_info)
}

/// Propagate DNS changes by
///
/// 1. rewriting the session's Envoy listener file via the atomic
///    writer — this materialises L3 filter chains for any domain with
///    freshly resolved IPs so Envoy can start honouring matches for
///    them (xDS LDS picks up the `MovedTo` inotify event without
///    draining the listener);
/// 2. regenerating the `sandbox_policy` nftables ruleset — domain
///    `allow` rules carry the now-resolved IPs so the kernel can
///    accept VM → IP traffic before it reaches Envoy.
///
/// The listener is rewritten **first**, before the nftables injection,
/// so Envoy has a matching filter chain ready by the time nftables
/// starts admitting traffic for the new IPs.
pub fn propagate_dns_changes(
    session_id: &SessionId,
    policy: &Policy,
    cache: &DnsCache,
    gateway: &GatewayManager,
    network_info: &NetworkInfo,
) -> Result<(), SandboxError> {
    // (1) Envoy listener: compile the listener with the current DNS
    // cache and write it via the atomic writer. Envoy's filesystem LDS
    // watcher picks up the `MovedTo` rename and reloads the listener
    // without dropping existing connections (only filter chains differ
    // across generations; the writer enforces that invariant).
    let listener_yaml = PolicyCompiler::compile_envoy_listener(policy, cache);
    let listener_path = session_listener_host_path(session_id);
    info!(
        session_id = %session_id,
        listener_path = %listener_path.display(),
        "rewriting Envoy listener for DNS propagation"
    );
    AtomicListenerWriter::new(&listener_path)
        .write(&listener_yaml)
        .map_err(|e| SandboxError::Gateway(format!("listener rewrite failed: {e}")))?;

    // (2) nftables policy table: inject resolved-IP allow rules so the
    // kernel lets VM traffic through to Envoy. Rules for domains that
    // are still unresolved appear as comment placeholders (fail-closed).
    let ruleset = generate_domain_ip_rules(policy, cache, network_info);
    if ruleset.is_empty() {
        debug!(
            session_id = %session_id,
            "no domain IP rules to propagate (all domains unresolved or deny-only)"
        );
        return Ok(());
    }

    info!(
        session_id = %session_id,
        "propagating DNS-resolved IPs to nftables"
    );

    gateway.inject_nftables_ruleset_public(session_id, &ruleset, "policy-dns-update")?;

    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::NetworkInfo;
    use crate::policy::{
        AssuranceLevel, Destination, Policy, PolicyRule, Protocol, SCHEMA_VERSION,
    };

    fn test_network_info() -> NetworkInfo {
        NetworkInfo {
            bridge_name: "sb-test1234567".to_string(),
            subnet: "10.209.0.0/28".to_string(),
            gateway_ip: "10.209.0.2".to_string(),
            vm_ip: "10.209.0.3".to_string(),
            docker_network_name: "sandbox-net-test".to_string(),
        }
    }

    // -- DnsCache tests -------------------------------------------------------

    #[test]
    fn dns_cache_empty_by_default() {
        let cache = DnsCache::new();
        assert!(cache.entries().is_empty());
        assert!(!cache.has_expired_entries());
    }

    #[test]
    fn dns_cache_update_new_domain() {
        let mut cache = DnsCache::new();
        let report = ResolvedReport {
            mappings: vec![ResolvedMapping {
                domain: "example.com".to_string(),
                ips: vec!["93.184.216.34".to_string()],
                ttl: 3600,
                timestamp: "2024-01-01T00:00:00Z".to_string(),
            }],
        };

        let changes = cache.update(&report);
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].domain, "example.com");
        assert_eq!(changes[0].change_type, DnsChangeType::NewDomain);
        assert!(changes[0].old_ips.is_empty());
        assert_eq!(changes[0].new_ips.len(), 1);

        assert_eq!(cache.entries().len(), 1);
        let entry = cache.entries().get("example.com").unwrap();
        assert_eq!(
            entry.ips,
            vec!["93.184.216.34".parse::<Ipv4Addr>().unwrap()]
        );
    }

    #[test]
    fn dns_cache_update_no_change() {
        let mut cache = DnsCache::new();
        let report = ResolvedReport {
            mappings: vec![ResolvedMapping {
                domain: "example.com".to_string(),
                ips: vec!["93.184.216.34".to_string()],
                ttl: 3600,
                timestamp: "2024-01-01T00:00:00Z".to_string(),
            }],
        };

        cache.update(&report);
        let changes = cache.update(&report);
        assert!(
            changes.is_empty(),
            "no changes expected when IPs are the same"
        );
    }

    #[test]
    fn dns_cache_update_ip_changed() {
        let mut cache = DnsCache::new();

        let report1 = ResolvedReport {
            mappings: vec![ResolvedMapping {
                domain: "example.com".to_string(),
                ips: vec!["93.184.216.34".to_string()],
                ttl: 3600,
                timestamp: "2024-01-01T00:00:00Z".to_string(),
            }],
        };
        cache.update(&report1);

        let report2 = ResolvedReport {
            mappings: vec![ResolvedMapping {
                domain: "example.com".to_string(),
                ips: vec!["93.184.216.35".to_string()],
                ttl: 3600,
                timestamp: "2024-01-01T00:01:00Z".to_string(),
            }],
        };
        let changes = cache.update(&report2);

        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].domain, "example.com");
        assert_eq!(changes[0].change_type, DnsChangeType::IpsChanged);
        assert_eq!(
            changes[0].old_ips,
            vec!["93.184.216.34".parse::<Ipv4Addr>().unwrap()]
        );
        assert_eq!(
            changes[0].new_ips,
            vec!["93.184.216.35".parse::<Ipv4Addr>().unwrap()]
        );
    }

    #[test]
    fn dns_cache_update_domain_removed() {
        let mut cache = DnsCache::new();

        let report1 = ResolvedReport {
            mappings: vec![ResolvedMapping {
                domain: "example.com".to_string(),
                ips: vec!["93.184.216.34".to_string()],
                ttl: 3600,
                timestamp: "2024-01-01T00:00:00Z".to_string(),
            }],
        };
        cache.update(&report1);

        // Empty report -- domain is gone.
        let report2 = ResolvedReport {
            mappings: Vec::new(),
        };
        let changes = cache.update(&report2);

        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].domain, "example.com");
        assert_eq!(changes[0].change_type, DnsChangeType::Removed);
        assert!(changes[0].new_ips.is_empty());
        assert!(cache.entries().is_empty());
    }

    #[test]
    fn dns_cache_update_multiple_domains() {
        let mut cache = DnsCache::new();

        let report = ResolvedReport {
            mappings: vec![
                ResolvedMapping {
                    domain: "a.com".to_string(),
                    ips: vec!["1.2.3.4".to_string()],
                    ttl: 300,
                    timestamp: "2024-01-01T00:00:00Z".to_string(),
                },
                ResolvedMapping {
                    domain: "b.com".to_string(),
                    ips: vec!["5.6.7.8".to_string()],
                    ttl: 600,
                    timestamp: "2024-01-01T00:00:00Z".to_string(),
                },
            ],
        };

        let changes = cache.update(&report);
        assert_eq!(changes.len(), 2);
        assert_eq!(cache.entries().len(), 2);
    }

    #[test]
    fn dns_cache_ignores_invalid_ips() {
        let mut cache = DnsCache::new();

        let report = ResolvedReport {
            mappings: vec![ResolvedMapping {
                domain: "example.com".to_string(),
                ips: vec!["not-an-ip".to_string()],
                ttl: 3600,
                timestamp: "2024-01-01T00:00:00Z".to_string(),
            }],
        };

        let changes = cache.update(&report);
        // No valid IPs -> no entry added.
        assert!(changes.is_empty());
        assert!(cache.entries().is_empty());
    }

    #[test]
    fn dns_cache_multiple_ips_per_domain() {
        let mut cache = DnsCache::new();

        let report = ResolvedReport {
            mappings: vec![ResolvedMapping {
                domain: "cdn.example.com".to_string(),
                ips: vec![
                    "1.2.3.4".to_string(),
                    "5.6.7.8".to_string(),
                    "9.10.11.12".to_string(),
                ],
                ttl: 60,
                timestamp: "2024-01-01T00:00:00Z".to_string(),
            }],
        };

        let changes = cache.update(&report);
        assert_eq!(changes.len(), 1);
        let entry = cache.entries().get("cdn.example.com").unwrap();
        assert_eq!(entry.ips.len(), 3);
    }

    // -- generate_domain_ip_rules tests ---------------------------------------

    #[test]
    fn domain_ip_rules_empty_for_deny_only() {
        let policy = Policy {
            version: SCHEMA_VERSION.to_string(),
            rules: vec![PolicyRule {
                host: Destination::Domain("evil.com".to_string()),
                port: 443,
                protocol: Protocol::Tcp,
                level: AssuranceLevel::Deny,
                reason: None,
            }],
        };

        let cache = DnsCache::new();
        let net = test_network_info();
        let rules = generate_domain_ip_rules(&policy, &cache, &net);
        assert!(rules.is_empty());
    }

    #[test]
    fn domain_ip_rules_includes_resolved_ips() {
        let policy = Policy {
            version: SCHEMA_VERSION.to_string(),
            rules: vec![PolicyRule {
                host: Destination::Domain("github.com".to_string()),
                port: 443,
                protocol: Protocol::Tcp,
                level: AssuranceLevel::Transport,
                reason: None,
            }],
        };

        let mut cache = DnsCache::new();
        let report = ResolvedReport {
            mappings: vec![ResolvedMapping {
                domain: "github.com".to_string(),
                ips: vec!["140.82.121.3".to_string()],
                ttl: 3600,
                timestamp: "2024-01-01T00:00:00Z".to_string(),
            }],
        };
        cache.update(&report);

        let net = test_network_info();
        let rules = generate_domain_ip_rules(&policy, &cache, &net);

        // M10-S3 shape: the resolved `(ip, port)` pair is a concat-set
        // element inside `policy_allow_tcp`, duplicated across both
        // tables. The domain name itself does not appear in the
        // generated ruleset — the DNS-to-IP binding happens upstream in
        // the cache; what lands in nftables is the post-join `(ip, port)`
        // tuple. Both tables are emitted: `sandbox_dnat` routes VM-egress
        // to Envoy via conditional DNAT, `sandbox_policy` admits the
        // gateway's upstream connection to the resolved IP.
        assert!(rules.contains("table inet sandbox_dnat"));
        assert!(rules.contains("table inet sandbox_policy"));
        assert!(rules.contains("set policy_allow_tcp"));
        assert!(rules.contains("type ipv4_addr . inet_service"));
        assert!(
            rules.contains("140.82.121.3 . 443"),
            "policy_allow_tcp must contain the (ip . port) element for \
             the resolved domain; got:\n{rules}"
        );
        // sandbox_dnat.prerouting DNATs policy-allowed TCP to Envoy.
        assert!(
            rules.contains(
                "meta l4proto tcp ip daddr . tcp dport @policy_allow_tcp dnat to 10.209.0.2:10000"
            ),
            "sandbox_dnat.prerouting must DNAT policy-allowed TCP to \
             Envoy :10000; got:\n{rules}"
        );
        // sandbox_policy.output admits gateway-originated TCP to the
        // same destinations.
        assert!(
            rules.contains("ip saddr 10.209.0.2 ip daddr . tcp dport @policy_allow_tcp accept"),
            "sandbox_policy.output must admit gateway-originated TCP to \
             policy-allowed destinations; got:\n{rules}"
        );
    }

    #[test]
    fn domain_ip_rules_includes_cidr_directly() {
        let policy = Policy {
            version: SCHEMA_VERSION.to_string(),
            rules: vec![PolicyRule {
                host: Destination::Cidr("140.82.112.0/20".to_string()),
                port: 443,
                protocol: Protocol::Tcp,
                level: AssuranceLevel::Transport,
                reason: None,
            }],
        };

        let cache = DnsCache::new();
        let net = test_network_info();
        let rules = generate_domain_ip_rules(&policy, &cache, &net);

        // CIDR rules go directly into the concat set keyed on
        // `ipv4_addr . inet_service` — no DNS cache lookup needed.
        assert!(
            rules.contains("140.82.112.0/20 . 443"),
            "policy_allow_tcp must contain the (cidr . port) element for \
             the CIDR rule; got:\n{rules}"
        );
    }

    #[test]
    fn domain_ip_rules_unresolved_domain_denied() {
        let policy = Policy {
            version: SCHEMA_VERSION.to_string(),
            rules: vec![PolicyRule {
                host: Destination::Domain("not-resolved.com".to_string()),
                port: 443,
                protocol: Protocol::Tcp,
                level: AssuranceLevel::Transport,
                reason: None,
            }],
        };

        let cache = DnsCache::new();
        let net = test_network_info();
        let rules = generate_domain_ip_rules(&policy, &cache, &net);

        // Unresolved domain → no set element → empty ruleset → no
        // injection. Traffic to `not-resolved.com` is rejected by the
        // base deny-all forward chain (fail-closed).
        assert!(rules.is_empty());
    }

    #[test]
    fn domain_ip_rules_mixed_cidr_and_resolved() {
        let policy = Policy {
            version: SCHEMA_VERSION.to_string(),
            rules: vec![
                PolicyRule {
                    host: Destination::Cidr("10.0.0.0/8".to_string()),
                    port: 443,
                    protocol: Protocol::Tcp,
                    level: AssuranceLevel::Transport,
                    reason: None,
                },
                PolicyRule {
                    host: Destination::Domain("example.com".to_string()),
                    port: 443,
                    protocol: Protocol::Tcp,
                    level: AssuranceLevel::Transport,
                    reason: None,
                },
            ],
        };

        let mut cache = DnsCache::new();
        let report = ResolvedReport {
            mappings: vec![ResolvedMapping {
                domain: "example.com".to_string(),
                ips: vec!["93.184.216.34".to_string()],
                ttl: 3600,
                timestamp: "2024-01-01T00:00:00Z".to_string(),
            }],
        };
        cache.update(&report);

        let net = test_network_info();
        let rules = generate_domain_ip_rules(&policy, &cache, &net);

        assert!(
            rules.contains("10.0.0.0/8 . 443"),
            "CIDR element must appear in policy_allow_tcp; got:\n{rules}"
        );
        assert!(
            rules.contains("93.184.216.34 . 443"),
            "resolved-domain element must appear in policy_allow_tcp; \
             got:\n{rules}"
        );
    }

    #[test]
    fn domain_ip_rules_segregate_tcp_and_udp_rules() {
        // Pin that protocol routing is correct end-to-end through the
        // DNS-propagation layer: a TCP rule lands in `policy_allow_tcp`
        // only, a UDP rule lands in `policy_allow_udp` only. No
        // cross-protocol leakage, same invariant as the compiler-side
        // `compile_mixed_tcp_and_udp_cidrs_segregate_by_protocol` test.
        let policy = Policy {
            version: SCHEMA_VERSION.to_string(),
            rules: vec![
                PolicyRule {
                    host: Destination::Domain("tcp.example.com".to_string()),
                    port: 443,
                    protocol: Protocol::Tcp,
                    level: AssuranceLevel::Transport,
                    reason: None,
                },
                PolicyRule {
                    host: Destination::Domain("udp.example.com".to_string()),
                    port: 53,
                    protocol: Protocol::Udp,
                    level: AssuranceLevel::Transport,
                    reason: None,
                },
            ],
        };

        let mut cache = DnsCache::new();
        let report = ResolvedReport {
            mappings: vec![
                ResolvedMapping {
                    domain: "tcp.example.com".to_string(),
                    ips: vec!["1.2.3.4".to_string()],
                    ttl: 3600,
                    timestamp: "2024-01-01T00:00:00Z".to_string(),
                },
                ResolvedMapping {
                    domain: "udp.example.com".to_string(),
                    ips: vec!["5.6.7.8".to_string()],
                    ttl: 3600,
                    timestamp: "2024-01-01T00:00:00Z".to_string(),
                },
            ],
        };
        cache.update(&report);

        let net = test_network_info();
        let rules = generate_domain_ip_rules(&policy, &cache, &net);

        // Extract the TCP set body.
        let tcp_start = rules
            .find("set policy_allow_tcp")
            .expect("policy_allow_tcp set should exist");
        let tcp_end = rules[tcp_start..]
            .find("\n    }")
            .map(|i| tcp_start + i)
            .expect("policy_allow_tcp set should terminate");
        let tcp_body = &rules[tcp_start..tcp_end];

        // Extract the UDP set body.
        let udp_start = rules
            .find("set policy_allow_udp")
            .expect("policy_allow_udp set should exist");
        let udp_end = rules[udp_start..]
            .find("\n    }")
            .map(|i| udp_start + i)
            .expect("policy_allow_udp set should terminate");
        let udp_body = &rules[udp_start..udp_end];

        assert!(
            tcp_body.contains("1.2.3.4 . 443"),
            "TCP-rule resolved IP must be in policy_allow_tcp; got tcp \
             body:\n{tcp_body}"
        );
        assert!(
            !udp_body.contains("1.2.3.4"),
            "TCP-rule IP must not leak into policy_allow_udp; got udp \
             body:\n{udp_body}"
        );
        assert!(
            udp_body.contains("5.6.7.8 . 53"),
            "UDP-rule resolved IP must be in policy_allow_udp; got udp \
             body:\n{udp_body}"
        );
        assert!(
            !tcp_body.contains("5.6.7.8"),
            "UDP-rule IP must not leak into policy_allow_tcp; got tcp \
             body:\n{tcp_body}"
        );
    }

    // -- ResolvedReport parsing tests -----------------------------------------

    #[test]
    fn parse_resolved_report() {
        let json = r#"{
            "mappings": [
                {
                    "domain": "example.com",
                    "ips": ["93.184.216.34"],
                    "ttl": 3600,
                    "timestamp": "2024-01-01T00:00:00Z"
                }
            ]
        }"#;

        let report: ResolvedReport = serde_json::from_str(json).unwrap();
        assert_eq!(report.mappings.len(), 1);
        assert_eq!(report.mappings[0].domain, "example.com");
        assert_eq!(report.mappings[0].ips, vec!["93.184.216.34"]);
        assert_eq!(report.mappings[0].ttl, 3600);
    }

    #[test]
    fn parse_resolved_report_multiple() {
        let json = r#"{
            "mappings": [
                {
                    "domain": "a.com",
                    "ips": ["1.2.3.4", "5.6.7.8"],
                    "ttl": 300,
                    "timestamp": "2024-01-01T00:00:00Z"
                },
                {
                    "domain": "b.com",
                    "ips": ["9.10.11.12"],
                    "ttl": 600,
                    "timestamp": "2024-01-01T00:00:00Z"
                }
            ]
        }"#;

        let report: ResolvedReport = serde_json::from_str(json).unwrap();
        assert_eq!(report.mappings.len(), 2);
        assert_eq!(report.mappings[0].ips.len(), 2);
    }

    #[test]
    fn parse_resolved_report_empty() {
        let json = r#"{"mappings": []}"#;
        let report: ResolvedReport = serde_json::from_str(json).unwrap();
        assert!(report.mappings.is_empty());
    }
}
