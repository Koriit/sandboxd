use std::collections::{BTreeSet, HashMap};
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
    ///
    /// **UNION semantics for in-window rotations (todo #40).** When the
    /// gateway's CoreDNS upstream returns a *different* slot of a
    /// rotating multi-IP A-record (think `github.com` →
    /// `140.82.112.0/20`, TTL ≤ 60s), naively replacing the cache entry
    /// would evict an IP that the VM may have just observed via its own
    /// upstream lookup. Within the same TTL window we therefore
    /// **merge** the freshly-observed IPs into the existing entry's IP
    /// set rather than replacing it. The TTL window is refreshed on
    /// every observation so the merged entry survives as long as
    /// resolutions keep arriving — entries still expire (and are
    /// dropped from `self.entries` on the next [`Self::update`] call
    /// with no observation, or via [`Self::expired_domains`] /
    /// [`Self::has_expired_entries`]) when no further activity arrives
    /// before `resolved_at + ttl`.
    ///
    /// Concretely:
    /// * `NewDomain` — first time we see the domain; entry inserted as
    ///   before, change emitted with `old_ips=[]`.
    /// * `IpsChanged` — entry already exists and unexpired; merge new
    ///   IPs into existing set. If the merge added at least one IP, a
    ///   change is emitted carrying the merged IP set as `new_ips`
    ///   (so the listener writer adds the new IP to the allow set
    ///   without dropping the old). If the new IPs are a subset of the
    ///   existing set, `resolved_at` and `ttl` are still refreshed but
    ///   no change is emitted (nothing to propagate).
    /// * `Removed` — domain absent from the report and existing entry
    ///   has expired. The expiry check matters: a domain that is
    ///   simply quiet for one cycle (e.g. CoreDNS hasn't been queried
    ///   for it lately) does not get its allow rules torn down
    ///   prematurely.
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

            // Always UNION the new observation with any existing entry
            // (regardless of TTL state). The DNS rotation race that
            // motivated this design (todo #40) is precisely a case
            // where the gateway and the VM resolve the SAME domain to
            // DIFFERENT slots of the same authoritative pool within
            // the same wall-clock second — and many CDN hosts ship
            // single-digit-second TTLs (e.g. Fastly returns TTL=2 for
            // index.crates.io). A strict TTL gate around the merge
            // would erase the previously observed IPs literally one
            // poll cycle later, re-opening the race we're trying to
            // close. Instead the merge is unconditional; the
            // truly-stale eviction lives in the `removed` sweep below
            // (domain absent from the report AND past the entry's
            // TTL).
            //
            // BTreeSet gives a stable sorted dedup that the
            // emit_prefix_ranges_from_ips path can consume directly.
            match self.entries.get(&mapping.domain) {
                Some(existing) => {
                    let old_set: BTreeSet<Ipv4Addr> = existing.ips.iter().copied().collect();
                    let new_set: BTreeSet<Ipv4Addr> = new_ips.iter().copied().collect();
                    let merged_set: BTreeSet<Ipv4Addr> = old_set.union(&new_set).copied().collect();

                    let merged_vec: Vec<Ipv4Addr> = merged_set.iter().copied().collect();

                    if merged_set != old_set {
                        // Merge added at least one IP. Emit IpsChanged
                        // so the listener writer + nft injector pick
                        // up the expanded allow set; carry the merged
                        // set as `new_ips` and the previous set as
                        // `old_ips` so diagnostic logs show the full
                        // picture.
                        changes.push(DnsChange {
                            domain: mapping.domain.clone(),
                            old_ips: existing.ips.clone(),
                            new_ips: merged_vec.clone(),
                            change_type: DnsChangeType::IpsChanged,
                        });
                    }
                    // Whether or not the merge expanded the set,
                    // refresh `resolved_at` + `ttl` to the latest
                    // observation. This keeps the entry alive as long
                    // as observations keep arriving — even if every
                    // observation hits a strict subset of the cached
                    // IPs.
                    self.entries.insert(
                        mapping.domain.clone(),
                        DnsCacheEntry {
                            domain: mapping.domain.clone(),
                            ips: merged_vec,
                            ttl,
                            resolved_at: now,
                        },
                    );
                }
                None => {
                    changes.push(DnsChange {
                        domain: mapping.domain.clone(),
                        old_ips: Vec::new(),
                        new_ips: new_ips.clone(),
                        change_type: DnsChangeType::NewDomain,
                    });
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
            }
        }

        // Sweep entries that are absent from the report AND have
        // expired. A domain that is simply not in this cycle's report
        // (e.g. CoreDNS hasn't received a query for it lately) should
        // remain in the cache until its TTL elapses — otherwise we
        // would tear down allow rules between queries on a slow-traffic
        // domain. Combined with the UNION semantics above, this means
        // an entry only disappears once both (a) no fresh observation
        // arrives for the entire TTL window, and (b) the report stops
        // mentioning the domain.
        let removed: Vec<String> = self
            .entries
            .iter()
            .filter(|(d, entry)| {
                !seen_domains.contains(d) && now.duration_since(entry.resolved_at) > entry.ttl
            })
            .map(|(d, _)| d.clone())
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
/// (v2 schema). The shape matches `PolicyCompiler::compile_nftables`
/// byte-for-byte — both entry points delegate to the shared
/// `render_two_table_ruleset` helper so the chains stay in lockstep.
///
/// **Shape.** Per-destination allowance lives in two nftables concat
/// sets keyed on `ipv4_addr . inet_service`, one per L4 protocol
/// (`policy_allow_tcp`, `policy_allow_udp`). Set elements are
/// `<ip_or_cidr> . <port>` pairs. The filtering decision lives in
/// `sandbox_dnat.prerouting` as conditional DNAT — policy-allowed
/// destinations route to Envoy :10000; everything else falls through
/// to the deny-logger :10001 / :10002. `sandbox_policy` holds only an
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
/// Each allow element is `<ip> . <port>` keyed on the rule's explicit port
/// and protocol; the port-explicit design superseded the earlier hardcoded
/// `dport { 80, 443 }` approach.
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
    // BTreeSet gives stable sorted dedup so that two rules whose
    // hosts resolve to a shared (ip, port) tuple — e.g. mirrors of
    // the same archive backed by one IP — emit a single set element
    // and `nft -f` does not log `File exists` on the duplicate add.
    let mut tcp_elements: BTreeSet<String> = BTreeSet::new();
    let mut udp_elements: BTreeSet<String> = BTreeSet::new();

    for rule in &policy.rules {
        if matches!(rule.level, AssuranceLevel::Deny) {
            continue;
        }

        let port = rule.port;
        match &rule.host {
            Destination::Cidr(cidr) => {
                let element = format!("{cidr} . {port}");
                match rule.protocol {
                    crate::policy::Protocol::Tcp => {
                        tcp_elements.insert(element);
                    }
                    crate::policy::Protocol::Udp => {
                        udp_elements.insert(element);
                    }
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
                        crate::policy::Protocol::Tcp => {
                            tcp_elements.insert(element);
                        }
                        crate::policy::Protocol::Udp => {
                            udp_elements.insert(element);
                        }
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

    let tcp_elements: Vec<String> = tcp_elements.into_iter().collect();
    let udp_elements: Vec<String> = udp_elements.into_iter().collect();

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
    fn dns_cache_update_ip_changed_unions_within_ttl() {
        // Within the TTL window, a fresh observation that brings a
        // disjoint IP must UNION (not replace) the existing IP set —
        // this prevents a previously-allowed IP from being evicted
        // mid-rotation. (todo #40 root-cause fix.)
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
        // UNION semantics: the change carries BOTH the old and new IPs
        // as `new_ips` so the listener writer adds the new IP to the
        // allow set instead of dropping the old one.
        assert_eq!(
            changes[0].new_ips,
            vec![
                "93.184.216.34".parse::<Ipv4Addr>().unwrap(),
                "93.184.216.35".parse::<Ipv4Addr>().unwrap(),
            ]
        );
        // The cache entry now contains both IPs.
        let entry = cache.entries().get("example.com").unwrap();
        assert_eq!(
            entry.ips,
            vec![
                "93.184.216.34".parse::<Ipv4Addr>().unwrap(),
                "93.184.216.35".parse::<Ipv4Addr>().unwrap(),
            ]
        );
    }

    #[test]
    fn dns_cache_update_subset_no_change_emitted_but_ttl_refreshed() {
        // If the new observation is a SUBSET of the existing entry,
        // no change is emitted (nothing to add to the allow set), but
        // the entry's TTL window is refreshed so steady-state rotation
        // doesn't expire the merged set mid-window.
        let mut cache = DnsCache::new();

        let report1 = ResolvedReport {
            mappings: vec![ResolvedMapping {
                domain: "example.com".to_string(),
                ips: vec!["1.2.3.4".to_string(), "5.6.7.8".to_string()],
                ttl: 3600,
                timestamp: "2024-01-01T00:00:00Z".to_string(),
            }],
        };
        cache.update(&report1);

        let report2 = ResolvedReport {
            mappings: vec![ResolvedMapping {
                domain: "example.com".to_string(),
                ips: vec!["1.2.3.4".to_string()],
                ttl: 3600,
                timestamp: "2024-01-01T00:01:00Z".to_string(),
            }],
        };
        let changes = cache.update(&report2);

        assert!(
            changes.is_empty(),
            "subset observation must not emit a change"
        );
        // Both IPs still present in the cache.
        let entry = cache.entries().get("example.com").unwrap();
        let mut sorted = entry.ips.clone();
        sorted.sort();
        assert_eq!(
            sorted,
            vec![
                "1.2.3.4".parse::<Ipv4Addr>().unwrap(),
                "5.6.7.8".parse::<Ipv4Addr>().unwrap(),
            ]
        );
    }

    #[test]
    fn dns_cache_update_disjoint_unions_full_set() {
        // Observations of fully-disjoint IP sets within the TTL window
        // accumulate the full union — the gateway and VM may each see
        // a different rotation slot of a multi-IP A record.
        let mut cache = DnsCache::new();

        let report1 = ResolvedReport {
            mappings: vec![ResolvedMapping {
                domain: "github.com".to_string(),
                ips: vec!["140.82.121.4".to_string()],
                ttl: 60,
                timestamp: "2024-01-01T00:00:00Z".to_string(),
            }],
        };
        cache.update(&report1);

        let report2 = ResolvedReport {
            mappings: vec![ResolvedMapping {
                domain: "github.com".to_string(),
                ips: vec!["140.82.121.3".to_string()],
                ttl: 60,
                timestamp: "2024-01-01T00:00:30Z".to_string(),
            }],
        };
        let changes = cache.update(&report2);

        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].change_type, DnsChangeType::IpsChanged);
        let entry = cache.entries().get("github.com").unwrap();
        let mut sorted = entry.ips.clone();
        sorted.sort();
        assert_eq!(
            sorted,
            vec![
                "140.82.121.3".parse::<Ipv4Addr>().unwrap(),
                "140.82.121.4".parse::<Ipv4Addr>().unwrap(),
            ]
        );
    }

    #[test]
    fn dns_cache_update_after_expiry_still_unions() {
        // Even when an entry's TTL has elapsed, an observation that
        // re-mentions the domain UNIONs with the existing entry — the
        // expiration only fires when the domain is ALSO absent from
        // the report (see `dns_cache_update_domain_absent_after_ttl_removed`).
        //
        // Why: short-TTL CDN hosts (Fastly, e.g. `index.crates.io`
        // with TTL=2s) routinely return entries whose TTL has nominally
        // elapsed by the time the next 2-second poll cycle observes
        // them, yet the kernel-level connection from the VM is still
        // in flight against the previously-cached IP. Dropping the
        // cached IPs at the TTL boundary while CoreDNS keeps reporting
        // the same domain re-opens the rotation race that this whole
        // file exists to close. The truly-stale eviction lives in the
        // sweep at the end of `update`, gated on `seen_domains`.
        //
        // We construct the cache directly with a stale `resolved_at`
        // to avoid sleeping in the unit test (TTLs are seconds, not
        // milliseconds, so a real sleep would make the test slow).
        let mut cache = DnsCache::new();
        let stale_resolved_at = Instant::now() - Duration::from_secs(120);
        cache.entries.insert(
            "example.com".to_string(),
            DnsCacheEntry {
                domain: "example.com".to_string(),
                ips: vec!["1.2.3.4".parse().unwrap()],
                ttl: Duration::from_secs(60),
                resolved_at: stale_resolved_at,
            },
        );

        let report = ResolvedReport {
            mappings: vec![ResolvedMapping {
                domain: "example.com".to_string(),
                ips: vec!["5.6.7.8".to_string()],
                ttl: 60,
                timestamp: "2024-01-01T00:02:00Z".to_string(),
            }],
        };
        let changes = cache.update(&report);

        assert_eq!(changes.len(), 1);
        // Disjoint observation merges into the existing set; emit
        // IpsChanged carrying the merged list. `1.2.3.4` is preserved
        // alongside `5.6.7.8` so any in-flight VM connection against
        // the previously-cached IP survives the boundary.
        assert_eq!(changes[0].change_type, DnsChangeType::IpsChanged);
        let mut got: Vec<Ipv4Addr> = changes[0].new_ips.clone();
        got.sort();
        assert_eq!(
            got,
            vec![
                "1.2.3.4".parse::<Ipv4Addr>().unwrap(),
                "5.6.7.8".parse::<Ipv4Addr>().unwrap(),
            ]
        );
        let entry = cache.entries().get("example.com").unwrap();
        let mut entry_ips = entry.ips.clone();
        entry_ips.sort();
        assert_eq!(
            entry_ips,
            vec![
                "1.2.3.4".parse::<Ipv4Addr>().unwrap(),
                "5.6.7.8".parse::<Ipv4Addr>().unwrap(),
            ]
        );
        // resolved_at refreshed to the new observation so a subsequent
        // domain-absent cycle within the new TTL still keeps the entry.
        assert!(entry.resolved_at > stale_resolved_at);
    }

    #[test]
    fn dns_cache_update_domain_absent_within_ttl_kept() {
        // A domain that is simply absent from this cycle's report but
        // whose entry has not yet expired must remain in the cache —
        // the gateway may not have received another query for it yet.
        // Tearing down allow rules between queries on a slow-traffic
        // domain would cause unnecessary RST events.
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

        // Empty report — but the entry above has 3600s TTL so should
        // survive this cycle.
        let report2 = ResolvedReport {
            mappings: Vec::new(),
        };
        let changes = cache.update(&report2);

        assert!(
            changes.is_empty(),
            "in-window absent domain must not emit a Removed change"
        );
        assert_eq!(cache.entries().len(), 1);
    }

    #[test]
    fn dns_cache_update_domain_absent_after_ttl_removed() {
        // Once the TTL has elapsed AND the domain is absent from the
        // report, the entry is dropped and a `Removed` change fires
        // so downstream layers tear down the allow rules.
        let mut cache = DnsCache::new();
        let stale_resolved_at = Instant::now() - Duration::from_secs(120);
        cache.entries.insert(
            "example.com".to_string(),
            DnsCacheEntry {
                domain: "example.com".to_string(),
                ips: vec!["1.2.3.4".parse().unwrap()],
                ttl: Duration::from_secs(60),
                resolved_at: stale_resolved_at,
            },
        );

        let report = ResolvedReport {
            mappings: Vec::new(),
        };
        let changes = cache.update(&report);

        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].domain, "example.com");
        assert_eq!(changes[0].change_type, DnsChangeType::Removed);
        assert!(changes[0].new_ips.is_empty());
        assert!(cache.entries().is_empty());
    }

    #[test]
    fn rotation_race_listener_carries_both_ips() {
        // Pin the end-to-end behaviour the UNION fix is designed to
        // protect: when CoreDNS observes slot .4 then slot .3 of a
        // rotating multi-IP A record (the exact pattern observed in
        // the todo #40 baseline log against `github.com`), the
        // post-update Envoy listener YAML must carry BOTH IPs in the
        // rule's `prefix_ranges` so the in-flight VM connection to
        // .3 is not RST'd while a freshly-resolved .4 is being
        // installed (or vice versa).
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
        // Observation 1: gateway resolves slot .4
        let report1 = ResolvedReport {
            mappings: vec![ResolvedMapping {
                domain: "github.com".to_string(),
                ips: vec!["140.82.121.4".to_string()],
                ttl: 60,
                timestamp: "2024-01-01T00:00:30Z".to_string(),
            }],
        };
        cache.update(&report1);

        // Observation 2: a few seconds later, CoreDNS gets a different
        // rotation slot — this is the pattern the todo #40 baseline
        // captured between gateway-side resolution and VM-side
        // resolution within the same TTL window.
        let report2 = ResolvedReport {
            mappings: vec![ResolvedMapping {
                domain: "github.com".to_string(),
                ips: vec!["140.82.121.3".to_string()],
                ttl: 60,
                timestamp: "2024-01-01T00:00:33Z".to_string(),
            }],
        };
        cache.update(&report2);

        // Now compile the listener with the post-rotation cache and
        // assert both IPs appear in the L1 chain's prefix_ranges. The
        // pre-fix REPLACE semantics would have produced a listener
        // matching only .3, which is exactly what RST'd the in-flight
        // VM connection in the baseline log.
        let listener_yaml = crate::policy::PolicyCompiler::compile_envoy_listener(&policy, &cache);
        assert!(
            listener_yaml.contains("140.82.121.3"),
            "listener must include freshly-observed rotation slot .3 in \
             prefix_ranges; got:\n{listener_yaml}"
        );
        assert!(
            listener_yaml.contains("140.82.121.4"),
            "UNION semantics: listener must STILL include the \
             previously-observed rotation slot .4 so the in-flight VM \
             connection isn't RST'd; got:\n{listener_yaml}"
        );

        // Also verify the nftables generator picks up both IPs as
        // concat-set elements, since the gateway's upstream connection
        // depends on the `sandbox_policy` set admitting both rotation
        // slots.
        let net = test_network_info();
        let rules = generate_domain_ip_rules(&policy, &cache, &net);
        assert!(
            rules.contains("140.82.121.3 . 443"),
            "nft policy_allow_tcp must include rotation slot .3; got:\n{rules}"
        );
        assert!(
            rules.contains("140.82.121.4 . 443"),
            "UNION semantics: nft policy_allow_tcp must STILL include \
             rotation slot .4; got:\n{rules}"
        );
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

        // The resolved `(ip, port)` pair is a concat-set element
        // inside `policy_allow_tcp`, duplicated across both
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

    #[test]
    fn domain_ip_rules_dedup_shared_ip_across_hosts() {
        // Two allowed hosts whose A-records share an IP — e.g. archive
        // and security mirrors of the same Ubuntu pool — must contribute
        // a single `(ip . port)` element to `policy_allow_tcp`. Without
        // dedup, `nft -f` logs `File exists` on the duplicate add.
        let policy = Policy {
            version: SCHEMA_VERSION.to_string(),
            rules: vec![
                PolicyRule {
                    host: Destination::Domain("archive.ubuntu.com".to_string()),
                    port: 80,
                    protocol: Protocol::Tcp,
                    level: AssuranceLevel::Transport,
                    reason: None,
                },
                PolicyRule {
                    host: Destination::Domain("security.ubuntu.com".to_string()),
                    port: 80,
                    protocol: Protocol::Tcp,
                    level: AssuranceLevel::Transport,
                    reason: None,
                },
            ],
        };

        let mut cache = DnsCache::new();
        let report = ResolvedReport {
            mappings: vec![
                ResolvedMapping {
                    domain: "archive.ubuntu.com".to_string(),
                    ips: vec!["91.189.91.81".to_string()],
                    ttl: 3600,
                    timestamp: "2024-01-01T00:00:00Z".to_string(),
                },
                ResolvedMapping {
                    domain: "security.ubuntu.com".to_string(),
                    ips: vec!["91.189.91.81".to_string()],
                    ttl: 3600,
                    timestamp: "2024-01-01T00:00:00Z".to_string(),
                },
            ],
        };
        cache.update(&report);

        let net = test_network_info();
        let rules = generate_domain_ip_rules(&policy, &cache, &net);

        // The shared (ip . port) tuple appears once per table copy
        // (sandbox_dnat + sandbox_policy = 2 occurrences total), never
        // four — which is what the un-deduped pre-fix output produced.
        let occurrences = rules.matches("91.189.91.81 . 80").count();
        assert_eq!(
            occurrences, 2,
            "shared (ip . port) tuple must appear exactly once per table \
             copy (2 total across sandbox_dnat + sandbox_policy); got \
             {occurrences} occurrences in:\n{rules}"
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
