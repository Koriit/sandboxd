package sandboxpolicy

import (
	"context"
	"strings"
	"time"

	"github.com/coredns/coredns/plugin"
	"github.com/coredns/coredns/request"

	"github.com/miekg/dns"
)

// SandboxPolicy is the CoreDNS plugin that enforces DNS-level policy.
type SandboxPolicy struct {
	Next plugin.Handler

	policyFile     string
	reloadInterval time.Duration
	policy         *PolicyStore
	reporter       *Reporter
	// eventsFile is the path parsed from the `events_file` Corefile
	// directive. Empty means structured emission is disabled.
	eventsFile string
	// events, when non-nil, receives one JSONL line per query-allow /
	// query-deny decision. Structured output is additive — the existing
	// log.Infof lines stay for human debugging.
	events *EventWriter
}

// Name implements the plugin.Handler interface.
func (sp *SandboxPolicy) Name() string { return pluginName }

// ServeDNS implements the plugin.Handler interface. It checks the queried
// domain against the policy, blocks denied domains with NXDOMAIN, and strips
// AAAA/ECH records from allowed responses.
func (sp *SandboxPolicy) ServeDNS(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
	state := request.Request{W: w, Req: r}
	qname := state.Name() // lowercase, trailing dot
	qtype := state.QType()
	qtypeStr := dns.TypeToString[qtype]
	clientIP := state.IP()

	// Normalised name for logging (no trailing dot).
	displayName := strings.TrimSuffix(qname, ".")

	// If the query is for an AAAA record, respond with empty answer directly.
	// This avoids forwarding AAAA queries upstream at all.
	if qtype == dns.TypeAAAA {
		log.Infof("query %s %s -> denied (AAAA stripped)", displayName, qtypeStr)
		sp.emitDenied(displayName, qtypeStr, "AAAA stripped", clientIP)
		m := new(dns.Msg).SetReply(r)
		m.Authoritative = false
		m.RecursionAvailable = true
		w.WriteMsg(m)
		return dns.RcodeSuccess, nil
	}

	// For SVCB/HTTPS queries, respond with empty answer to prevent ECH negotiation.
	if qtype == dnsTypeSVCB || qtype == dnsTypeHTTPS {
		log.Infof("query %s %s -> denied (SVCB/HTTPS stripped)", displayName, qtypeStr)
		sp.emitDenied(displayName, qtypeStr, "SVCB/HTTPS stripped", clientIP)
		m := new(dns.Msg).SetReply(r)
		m.Authoritative = false
		m.RecursionAvailable = true
		w.WriteMsg(m)
		return dns.RcodeSuccess, nil
	}

	// Check policy.
	if !sp.policy.IsAllowed(qname) {
		log.Infof("query %s %s -> denied (policy)", displayName, qtypeStr)
		sp.emitDenied(displayName, qtypeStr, "policy", clientIP)
		m := new(dns.Msg).SetRcode(r, dns.RcodeNameError) // NXDOMAIN
		m.RecursionAvailable = true
		w.WriteMsg(m)
		return dns.RcodeSuccess, nil
	}

	// Domain is allowed — forward to the next plugin (forward) and intercept
	// the response so we can strip AAAA/ECH and report IPs.
	rw := &responseInterceptor{
		ResponseWriter: w,
		plugin:         sp,
		domain:         displayName,
		qtype:          qtype,
	}

	rcode, err := plugin.NextOrFailure(sp.Name(), sp.Next, ctx, rw, r)

	log.Infof("query %s %s -> allowed (rcode=%s, ips=%v)",
		displayName, qtypeStr, dns.RcodeToString[rcode], rw.resolvedIPs)
	sp.emitAllowed(displayName, qtypeStr, rw.resolvedIPs, clientIP)

	return rcode, err
}

// emitAllowed writes a structured `query_allowed` event if the plugin is
// configured with an events_file. Emission failures are logged but never
// propagated — the JSONL stream is a best-effort observability sink and
// must not break DNS service.
func (sp *SandboxPolicy) emitAllowed(query, qtype string, resolvedIPs []string, clientIP string) {
	if sp.events == nil {
		return
	}
	if err := sp.events.EmitQueryAllowed(query, qtype, resolvedIPs, clientIP); err != nil {
		log.Warningf("events write failed: %v", err)
	}
}

// emitDenied mirrors emitAllowed for the deny path.
func (sp *SandboxPolicy) emitDenied(query, qtype, reason, clientIP string) {
	if sp.events == nil {
		return
	}
	if err := sp.events.EmitQueryDenied(query, qtype, reason, clientIP); err != nil {
		log.Warningf("events write failed: %v", err)
	}
}

// responseInterceptor wraps a dns.ResponseWriter to post-process responses
// before they reach the client.
type responseInterceptor struct {
	dns.ResponseWriter
	plugin      *SandboxPolicy
	domain      string
	qtype       uint16
	resolvedIPs []string
}

// WriteMsg intercepts the response to strip AAAA and ECH records, then records
// domain→IP mappings for the report.
func (ri *responseInterceptor) WriteMsg(msg *dns.Msg) error {
	if msg == nil {
		return ri.ResponseWriter.WriteMsg(msg)
	}

	// Strip AAAA records from the response (even if the query was for A,
	// the additional/authority sections might contain AAAA).
	stripAAAA(msg)

	// Strip SVCB/HTTPS records carrying ECH parameters.
	stripECH(msg)

	// Collect resolved IPs for logging and reporting.
	for _, rr := range msg.Answer {
		if a, ok := rr.(*dns.A); ok {
			ri.resolvedIPs = append(ri.resolvedIPs, a.A.String())
		}
	}

	// Record the resolution for the IP report file.
	ri.plugin.reporter.RecordResponse(ri.domain, msg)

	return ri.ResponseWriter.WriteMsg(msg)
}
