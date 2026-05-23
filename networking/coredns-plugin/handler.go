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
	// gateSocketPath is the path to the per-session synchronous DNS
	// gate UDS bound by sandboxd. Empty means the gate is disabled
	// (legacy / fail-open path used by daemons that haven't enabled
	// the synchronous gate yet).
	gateSocketPath string
	// gateDeadline overrides the wall-clock deadline applied to each
	// gate round-trip. Zero means use the package default
	// (defaultGateDeadline).
	gateDeadline time.Duration
	// gate is the lazy-initialised client used by responseInterceptor.
	gate *gateClient
}

// Name implements the plugin.Handler interface.
func (sp *SandboxPolicy) Name() string { return pluginName }

// ServeDNS implements the plugin.Handler interface. It checks the queried
// domain against the policy, blocks denied domains with NXDOMAIN, denies
// AAAA queries with an empty answer (IPv4-only networking), and strips
// the ECH SvcParam from any SVCB/HTTPS records returned by the upstream
// resolver. SVCB/HTTPS records themselves and their non-ECH SvcParams
// pass through to the VM unchanged.
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

	// SVCB/HTTPS queries are forwarded upstream so that non-ECH SvcParams
	// (ALPN, port, IPv4 hints, etc.) reach the VM. The response interceptor
	// removes only the ECH SvcParam from each SVCB/HTTPS RR; records without
	// ECH are passed through unchanged. See `stripECH` in `strip.go`.

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

// WriteMsg intercepts the response to strip AAAA records and the ECH
// SvcParam from SVCB/HTTPS records, then records domain→IP mappings for
// the report.
//
// When the gate client is configured, this method
// emits a `propagate_and_ack` request to sandboxd with the resolved
// IPs and blocks on the daemon's ack until success or deadline. On
// success / noop the answer is released to the client; on rejection
// the answer is still released (fail-open) so a transient
// daemon issue does not punch a hole in DNS resolution. Every
// outcome is reported via the structured-events sink so operators can
// detect regressions.
func (ri *responseInterceptor) WriteMsg(msg *dns.Msg) error {
	if msg == nil {
		return ri.ResponseWriter.WriteMsg(msg)
	}

	// Strip AAAA records from the response (even if the query was for A,
	// the additional/authority sections might contain AAAA).
	stripAAAA(msg)

	// Strip the ECH SvcParam from SVCB/HTTPS records. Only the ECH key is
	// removed — other SvcParams (ALPN, port, IPv4 hints, …) and the records
	// themselves stay intact, so the VM still sees the SVCB/HTTPS payload.
	stripECH(msg)

	// Collect resolved IPs for logging and reporting.
	for _, rr := range msg.Answer {
		if a, ok := rr.(*dns.A); ok {
			ri.resolvedIPs = append(ri.resolvedIPs, a.A.String())
		}
	}

	// Record the resolution for the IP report file.
	ri.plugin.reporter.RecordResponse(ri.domain, msg)

	// Synchronous gate. Only A-record responses
	// with at least one resolved IP need gating: AAAA responses are
	// stripped above (no IPs to admit), and an empty-answer A
	// response carries nothing for sandboxd to propagate.
	if ri.qtype == dns.TypeA && len(ri.resolvedIPs) > 0 && ri.plugin.gate != nil && !ri.plugin.gate.disabled() {
		ttl := ttlFromMsg(msg)
		req := &gateRequest{
			Domain:     ri.domain,
			QType:      "A",
			IPs:        ri.resolvedIPs,
			TTLSeconds: ttl,
		}
		// Bound the entire gate round-trip by the configured
		// wall-clock deadline; the gate client also enforces a
		// connection-level deadline via SetDeadline.
		ctx, cancel := context.WithTimeout(context.Background(), ri.plugin.gateDeadlineOrDefault())
		outcome, ack := ri.plugin.gate.Submit(ctx, req)
		cancel()

		ri.plugin.emitGateOutcome(ri.domain, outcome, ack)

		// Fail-open posture: regardless of outcome, the answer is
		// released to the VM. The structured event makes the
		// degraded-mode visible to operators without dropping
		// queries.
		_ = outcome
	}

	return ri.ResponseWriter.WriteMsg(msg)
}

// ttlFromMsg returns the smallest TTL across the answer section, or
// 0 if no A records are present. The gate uses this to align the
// daemon-side cache window with the client-visible TTL.
func ttlFromMsg(msg *dns.Msg) uint32 {
	var minTTL uint32
	for _, rr := range msg.Answer {
		if a, ok := rr.(*dns.A); ok {
			t := a.Hdr.Ttl
			if minTTL == 0 || t < minTTL {
				minTTL = t
			}
		}
	}
	return minTTL
}

// gateDeadlineOrDefault returns the configured gate deadline, falling
// back to the package default when no override was set.
func (sp *SandboxPolicy) gateDeadlineOrDefault() time.Duration {
	if sp.gateDeadline > 0 {
		return sp.gateDeadline
	}
	return defaultGateDeadline
}

// emitGateOutcome writes a structured event and a log line for one
// gate round-trip. Best-effort: a write failure on the events file is
// logged but not propagated.
func (sp *SandboxPolicy) emitGateOutcome(domain string, outcome gateOutcome, ack *gateAck) {
	corr := ""
	reason := ""
	elapsed := uint64(0)
	if ack != nil {
		corr = ack.CorrelationID
		reason = ack.Reason
		elapsed = ack.ElapsedMS
		if reason == "" && ack.Message != "" {
			reason = ack.Message
		}
	}

	switch outcome {
	case gateOutcomeOK:
		log.Debugf("gate %s -> ok (cid=%s elapsed_ms=%d)", domain, corr, elapsed)
	case gateOutcomeRejected:
		log.Warningf("gate %s -> rejected (cid=%s reason=%q)", domain, corr, reason)
	case gateOutcomeTimedOut:
		log.Warningf("gate %s -> timed out (cid=%s reason=%q) — failing OPEN", domain, corr, reason)
	case gateOutcomeProtocolError:
		log.Warningf("gate %s -> protocol error (cid=%s reason=%q) — failing OPEN", domain, corr, reason)
	default:
		log.Warningf("gate %s -> unknown (cid=%s reason=%q) — failing OPEN", domain, corr, reason)
	}

	if sp.events == nil {
		return
	}
	if err := sp.events.EmitGateOutcome(domain, outcome.String(), corr, reason, elapsed); err != nil {
		log.Warningf("events write failed: %v", err)
	}
}
