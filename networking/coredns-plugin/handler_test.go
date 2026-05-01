package sandboxpolicy

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/miekg/dns"
)

// testResponseWriter is a minimal dns.ResponseWriter for testing.
type testResponseWriter struct {
	msg    *dns.Msg
	local  net.Addr
	remote net.Addr
}

func newTestResponseWriter() *testResponseWriter {
	return &testResponseWriter{
		local:  &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 53},
		remote: &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 40000},
	}
}

func (w *testResponseWriter) LocalAddr() net.Addr         { return w.local }
func (w *testResponseWriter) RemoteAddr() net.Addr        { return w.remote }
func (w *testResponseWriter) WriteMsg(msg *dns.Msg) error { w.msg = msg; return nil }
func (w *testResponseWriter) Write([]byte) (int, error)   { return 0, nil }
func (w *testResponseWriter) Close() error                { return nil }
func (w *testResponseWriter) TsigStatus() error           { return nil }
func (w *testResponseWriter) TsigTimersOnly(bool)         {}
func (w *testResponseWriter) Hijack()                     {}

// mockNextHandler simulates the upstream DNS resolver (the "forward" plugin).
// It responds with A records for any query it receives.
type mockNextHandler struct {
	// responses maps qname to A record IPs.
	responses map[string][]string
}

func (h *mockNextHandler) Name() string { return "mock" }

func (h *mockNextHandler) ServeDNS(_ context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
	m := new(dns.Msg).SetReply(r)

	qname := r.Question[0].Name
	if ips, ok := h.responses[qname]; ok {
		for _, ip := range ips {
			m.Answer = append(m.Answer, &dns.A{
				Hdr: dns.RR_Header{Name: qname, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 3600},
				A:   net.ParseIP(ip),
			})
		}
	}

	w.WriteMsg(m)
	return dns.RcodeSuccess, nil
}

func newTestPlugin(t *testing.T, policyContent string, nextResponses map[string][]string) (*SandboxPolicy, string) {
	t.Helper()
	dir := t.TempDir()

	policyPath := filepath.Join(dir, "policy.conf")
	if err := os.WriteFile(policyPath, []byte(policyContent), 0644); err != nil {
		t.Fatal(err)
	}

	reportPath := filepath.Join(dir, "resolved.json")

	ps := NewPolicyStore()
	if err := ps.LoadFile(policyPath); err != nil {
		t.Fatal(err)
	}

	sp := &SandboxPolicy{
		Next: &mockNextHandler{responses: nextResponses},

		policyFile: policyPath,
		policy:     ps,
		reporter:   NewReporter(reportPath),
	}

	return sp, reportPath
}

func TestHandler_AllowedDomain(t *testing.T) {
	sp, _ := newTestPlugin(t, "example.com\n", map[string][]string{
		"example.com.": {"93.184.216.34"},
	})

	w := newTestResponseWriter()
	r := new(dns.Msg).SetQuestion("example.com.", dns.TypeA)

	rcode, err := sp.ServeDNS(context.Background(), w, r)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rcode != dns.RcodeSuccess {
		t.Errorf("rcode = %d, want %d (success)", rcode, dns.RcodeSuccess)
	}

	if w.msg == nil {
		t.Fatal("no response written")
	}
	if len(w.msg.Answer) != 1 {
		t.Fatalf("answer count = %d, want 1", len(w.msg.Answer))
	}
	a, ok := w.msg.Answer[0].(*dns.A)
	if !ok {
		t.Fatalf("answer is not A record: %T", w.msg.Answer[0])
	}
	if a.A.String() != "93.184.216.34" {
		t.Errorf("resolved IP = %s, want 93.184.216.34", a.A.String())
	}
}

func TestHandler_DeniedDomain(t *testing.T) {
	sp, _ := newTestPlugin(t, "example.com\n", nil)

	w := newTestResponseWriter()
	r := new(dns.Msg).SetQuestion("evil.com.", dns.TypeA)

	rcode, err := sp.ServeDNS(context.Background(), w, r)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rcode != dns.RcodeSuccess {
		t.Errorf("rcode = %d, want %d (success — NXDOMAIN is in the message)", rcode, dns.RcodeSuccess)
	}
	if w.msg == nil {
		t.Fatal("no response written")
	}
	if w.msg.Rcode != dns.RcodeNameError {
		t.Errorf("message rcode = %d, want %d (NXDOMAIN)", w.msg.Rcode, dns.RcodeNameError)
	}
}

func TestHandler_WildcardAllowed(t *testing.T) {
	sp, _ := newTestPlugin(t, "*.example.com\n", map[string][]string{
		"foo.example.com.": {"1.2.3.4"},
	})

	w := newTestResponseWriter()
	r := new(dns.Msg).SetQuestion("foo.example.com.", dns.TypeA)

	_, err := sp.ServeDNS(context.Background(), w, r)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if w.msg == nil {
		t.Fatal("no response written")
	}
	if len(w.msg.Answer) != 1 {
		t.Fatalf("answer count = %d, want 1", len(w.msg.Answer))
	}
}

func TestHandler_WildcardDoesNotMatchBase(t *testing.T) {
	sp, _ := newTestPlugin(t, "*.example.com\n", nil)

	w := newTestResponseWriter()
	r := new(dns.Msg).SetQuestion("example.com.", dns.TypeA)

	_, err := sp.ServeDNS(context.Background(), w, r)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if w.msg == nil {
		t.Fatal("no response written")
	}
	if w.msg.Rcode != dns.RcodeNameError {
		t.Errorf("message rcode = %d, want %d (NXDOMAIN)", w.msg.Rcode, dns.RcodeNameError)
	}
}

func TestHandler_AAAAQuery_Blocked(t *testing.T) {
	// AAAA queries should be blocked regardless of policy.
	sp, _ := newTestPlugin(t, "example.com\n", nil)

	w := newTestResponseWriter()
	r := new(dns.Msg).SetQuestion("example.com.", dns.TypeAAAA)

	rcode, err := sp.ServeDNS(context.Background(), w, r)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rcode != dns.RcodeSuccess {
		t.Errorf("rcode = %d, want success", rcode)
	}
	if w.msg == nil {
		t.Fatal("no response written")
	}
	// Should return empty answer (no AAAA records).
	if len(w.msg.Answer) != 0 {
		t.Errorf("answer count = %d, want 0 (AAAA stripped)", len(w.msg.Answer))
	}
	// Should NOT be NXDOMAIN — it's a valid domain, just no AAAA.
	if w.msg.Rcode != dns.RcodeSuccess {
		t.Errorf("message rcode = %d, want success (not NXDOMAIN)", w.msg.Rcode)
	}
}

// TestHandler_SVCBQuery_StripsECHParam asserts that an SVCB query for
// an allowed domain is forwarded upstream and the response keeps the
// SVCB record while only the ECH SvcParam is stripped. Replaces the
// legacy blanket-deny posture (`TestHandler_SVCBQuery_Blocked`).
func TestHandler_SVCBQuery_StripsECHParam(t *testing.T) {
	sp := &SandboxPolicy{
		Next: &mockSVCBHTTPSNextHandler{
			svcb: []dns.SVCBKeyValue{
				&dns.SVCBAlpn{Alpn: []string{"h2"}},
				&dns.SVCBECHConfig{ECH: []byte{0xAB, 0xCD}},
			},
		},
		policy:   mustLoadPolicy(t, "example.com\n"),
		reporter: NewReporter(""),
	}

	w := newTestResponseWriter()
	r := new(dns.Msg).SetQuestion("example.com.", dnsTypeSVCB)

	rcode, err := sp.ServeDNS(context.Background(), w, r)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rcode != dns.RcodeSuccess {
		t.Errorf("rcode = %d, want success", rcode)
	}
	if w.msg == nil {
		t.Fatal("no response written")
	}
	if len(w.msg.Answer) != 1 {
		t.Fatalf("answer count = %d, want 1 (SVCB record must be preserved)", len(w.msg.Answer))
	}
	svcb, ok := w.msg.Answer[0].(*dns.SVCB)
	if !ok {
		t.Fatalf("answer is not SVCB: %T", w.msg.Answer[0])
	}
	if len(svcb.Value) != 1 || svcb.Value[0].Key() != dns.SVCB_ALPN {
		t.Errorf("remaining SvcParams = %v, want only ALPN", svcb.Value)
	}
	for _, kv := range svcb.Value {
		if kv.Key() == dns.SVCBKey(svcParamKeyECH) {
			t.Errorf("ECH SvcParam still present in response: %v", kv)
		}
	}
}

// TestHandler_HTTPSQuery_StripsECHParam mirrors the SVCB test for the
// HTTPS qtype.
func TestHandler_HTTPSQuery_StripsECHParam(t *testing.T) {
	sp := &SandboxPolicy{
		Next: &mockSVCBHTTPSNextHandler{
			https: []dns.SVCBKeyValue{
				&dns.SVCBAlpn{Alpn: []string{"h3"}},
				&dns.SVCBECHConfig{ECH: []byte{0x01, 0x02, 0x03}},
				&dns.SVCBPort{Port: 8443},
			},
		},
		policy:   mustLoadPolicy(t, "example.com\n"),
		reporter: NewReporter(""),
	}

	w := newTestResponseWriter()
	r := new(dns.Msg).SetQuestion("example.com.", dnsTypeHTTPS)

	rcode, err := sp.ServeDNS(context.Background(), w, r)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rcode != dns.RcodeSuccess {
		t.Errorf("rcode = %d, want success", rcode)
	}
	if w.msg == nil {
		t.Fatal("no response written")
	}
	if len(w.msg.Answer) != 1 {
		t.Fatalf("answer count = %d, want 1 (HTTPS record must be preserved)", len(w.msg.Answer))
	}
	https, ok := w.msg.Answer[0].(*dns.HTTPS)
	if !ok {
		t.Fatalf("answer is not HTTPS: %T", w.msg.Answer[0])
	}
	if len(https.Value) != 2 {
		t.Fatalf("remaining SvcParams = %d, want 2 (ALPN + Port preserved, ECH stripped)", len(https.Value))
	}
	for _, kv := range https.Value {
		if kv.Key() == dns.SVCBKey(svcParamKeyECH) {
			t.Errorf("ECH SvcParam still present in response: %v", kv)
		}
	}
}

// TestHandler_SVCBQuery_NonECHPassesThrough asserts the positive case
// the plan calls out: a SVCB record with no ECH SvcParam is delivered to
// the VM completely unchanged. Locks in the strip-only semantics so a
// future regression to blanket-deny would fail this test.
func TestHandler_SVCBQuery_NonECHPassesThrough(t *testing.T) {
	sp := &SandboxPolicy{
		Next: &mockSVCBHTTPSNextHandler{
			svcb: []dns.SVCBKeyValue{
				&dns.SVCBAlpn{Alpn: []string{"h2"}},
				&dns.SVCBPort{Port: 8443},
			},
		},
		policy:   mustLoadPolicy(t, "example.com\n"),
		reporter: NewReporter(""),
	}

	w := newTestResponseWriter()
	r := new(dns.Msg).SetQuestion("example.com.", dnsTypeSVCB)

	if _, err := sp.ServeDNS(context.Background(), w, r); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if w.msg == nil {
		t.Fatal("no response written")
	}
	if len(w.msg.Answer) != 1 {
		t.Fatalf("answer count = %d, want 1", len(w.msg.Answer))
	}
	svcb, ok := w.msg.Answer[0].(*dns.SVCB)
	if !ok {
		t.Fatalf("answer is not SVCB: %T", w.msg.Answer[0])
	}
	if len(svcb.Value) != 2 {
		t.Errorf("SvcParams = %d, want 2 (record must pass through unchanged)", len(svcb.Value))
	}
}

// TestHandler_SVCBQuery_DeniedDomain asserts that the SVCB pathway still
// honors policy: a query for a non-allowed domain returns NXDOMAIN, not
// an empty NOERROR. This guards against accidentally turning the
// strip-only path into an unconditional allow.
func TestHandler_SVCBQuery_DeniedDomain(t *testing.T) {
	sp, _ := newTestPlugin(t, "example.com\n", nil)

	w := newTestResponseWriter()
	r := new(dns.Msg).SetQuestion("evil.com.", dnsTypeSVCB)

	if _, err := sp.ServeDNS(context.Background(), w, r); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if w.msg == nil {
		t.Fatal("no response written")
	}
	if w.msg.Rcode != dns.RcodeNameError {
		t.Errorf("rcode = %d, want NXDOMAIN", w.msg.Rcode)
	}
}

func TestHandler_AAAAStrippedFromAResponse(t *testing.T) {
	// When the upstream returns both A and AAAA in the additional section,
	// the AAAA should be stripped.
	sp := &SandboxPolicy{
		Next: &mockNextHandlerWithAAAA{},

		policy:   mustLoadPolicy(t, "example.com\n"),
		reporter: NewReporter(""),
	}

	w := newTestResponseWriter()
	r := new(dns.Msg).SetQuestion("example.com.", dns.TypeA)

	_, err := sp.ServeDNS(context.Background(), w, r)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if w.msg == nil {
		t.Fatal("no response written")
	}

	// Check that AAAA is gone from answer section.
	for _, rr := range w.msg.Answer {
		if rr.Header().Rrtype == dns.TypeAAAA {
			t.Error("AAAA record found in answer section — should have been stripped")
		}
	}
	// Check A record is preserved.
	foundA := false
	for _, rr := range w.msg.Answer {
		if rr.Header().Rrtype == dns.TypeA {
			foundA = true
		}
	}
	if !foundA {
		t.Error("no A record in answer — should have been preserved")
	}
}

func TestHandler_IPReporting(t *testing.T) {
	sp, reportPath := newTestPlugin(t, "example.com\nfoo.org\n", map[string][]string{
		"example.com.": {"93.184.216.34", "93.184.216.35"},
		"foo.org.":     {"1.2.3.4"},
	})

	// Resolve example.com.
	w := newTestResponseWriter()
	r := new(dns.Msg).SetQuestion("example.com.", dns.TypeA)
	if _, err := sp.ServeDNS(context.Background(), w, r); err != nil {
		t.Fatal(err)
	}

	// Resolve foo.org.
	w = newTestResponseWriter()
	r = new(dns.Msg).SetQuestion("foo.org.", dns.TypeA)
	if _, err := sp.ServeDNS(context.Background(), w, r); err != nil {
		t.Fatal(err)
	}

	// Read the report file.
	data, err := os.ReadFile(reportPath)
	if err != nil {
		t.Fatalf("reading report: %v", err)
	}

	var report ReportFile
	if err := json.Unmarshal(data, &report); err != nil {
		t.Fatalf("parsing report: %v", err)
	}

	if len(report.Mappings) != 2 {
		t.Fatalf("mapping count = %d, want 2", len(report.Mappings))
	}

	// Build a map for easier lookup.
	byDomain := make(map[string]ReportEntry)
	for _, m := range report.Mappings {
		byDomain[m.Domain] = m
	}

	if entry, ok := byDomain["example.com"]; !ok {
		t.Error("missing example.com in report")
	} else {
		if len(entry.IPs) != 2 {
			t.Errorf("example.com IPs = %v, want 2 entries", entry.IPs)
		}
		if entry.TTL != 3600 {
			t.Errorf("example.com TTL = %d, want 3600", entry.TTL)
		}
		if entry.Timestamp == "" {
			t.Error("example.com timestamp is empty")
		}
	}

	if entry, ok := byDomain["foo.org"]; !ok {
		t.Error("missing foo.org in report")
	} else {
		if len(entry.IPs) != 1 || entry.IPs[0] != "1.2.3.4" {
			t.Errorf("foo.org IPs = %v, want [1.2.3.4]", entry.IPs)
		}
	}
}

func TestHandler_EmptyPolicy_DeniesEverything(t *testing.T) {
	sp, _ := newTestPlugin(t, "# empty\n", nil)

	w := newTestResponseWriter()
	r := new(dns.Msg).SetQuestion("anything.com.", dns.TypeA)

	_, err := sp.ServeDNS(context.Background(), w, r)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if w.msg == nil {
		t.Fatal("no response written")
	}
	if w.msg.Rcode != dns.RcodeNameError {
		t.Errorf("message rcode = %d, want %d (NXDOMAIN)", w.msg.Rcode, dns.RcodeNameError)
	}
}

func TestHandler_CaseInsensitiveQuery(t *testing.T) {
	sp, _ := newTestPlugin(t, "example.com\n", map[string][]string{
		"example.com.": {"1.2.3.4"},
	})

	// DNS queries with uppercase should still be allowed.
	// Note: request.Request.Name() lowercases for us, and CoreDNS itself
	// lowercases by convention, but the mock handler uses the raw qname.
	w := newTestResponseWriter()
	r := new(dns.Msg).SetQuestion("EXAMPLE.COM.", dns.TypeA)

	_, err := sp.ServeDNS(context.Background(), w, r)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if w.msg == nil {
		t.Fatal("no response written")
	}
	// The request.Request.Name() lowercases the qname, so policy check passes.
	// However, the mock handler may not have an entry for "EXAMPLE.COM."
	// This tests that our policy check uses the lowercased name.
	// With the mock, the forward won't find "EXAMPLE.COM." but that's fine —
	// what matters is we didn't return NXDOMAIN from the policy check.
	if w.msg.Rcode == dns.RcodeNameError {
		t.Error("expected query to be allowed (not NXDOMAIN) — case-insensitive matching should work")
	}
}

// mockSVCBHTTPSNextHandler responds to SVCB / HTTPS queries with a single
// record of the matching type, populated with the configured SvcParam set.
// Used to exercise the response-side ECH stripper end-to-end through
// ServeDNS without spinning up a real upstream resolver.
type mockSVCBHTTPSNextHandler struct {
	svcb  []dns.SVCBKeyValue // returned for SVCB qtype queries
	https []dns.SVCBKeyValue // returned for HTTPS qtype queries
}

func (h *mockSVCBHTTPSNextHandler) Name() string { return "mock-svcb-https" }

func (h *mockSVCBHTTPSNextHandler) ServeDNS(_ context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
	m := new(dns.Msg).SetReply(r)
	qname := r.Question[0].Name
	qtype := r.Question[0].Qtype

	switch qtype {
	case dnsTypeSVCB:
		m.Answer = append(m.Answer, &dns.SVCB{
			Hdr:      dns.RR_Header{Name: qname, Rrtype: dnsTypeSVCB, Class: dns.ClassINET, Ttl: 300},
			Priority: 1,
			Target:   ".",
			Value:    h.svcb,
		})
	case dnsTypeHTTPS:
		m.Answer = append(m.Answer, &dns.HTTPS{
			SVCB: dns.SVCB{
				Hdr:      dns.RR_Header{Name: qname, Rrtype: dnsTypeHTTPS, Class: dns.ClassINET, Ttl: 300},
				Priority: 1,
				Target:   ".",
				Value:    h.https,
			},
		})
	}

	w.WriteMsg(m)
	return dns.RcodeSuccess, nil
}

// mockNextHandlerWithAAAA responds with both A and AAAA records.
type mockNextHandlerWithAAAA struct{}

func (h *mockNextHandlerWithAAAA) Name() string { return "mock-aaaa" }

func (h *mockNextHandlerWithAAAA) ServeDNS(_ context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
	m := new(dns.Msg).SetReply(r)
	qname := r.Question[0].Name

	m.Answer = append(m.Answer,
		&dns.A{
			Hdr: dns.RR_Header{Name: qname, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
			A:   net.ParseIP("1.2.3.4"),
		},
		&dns.AAAA{
			Hdr:  dns.RR_Header{Name: qname, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 300},
			AAAA: net.ParseIP("::1"),
		},
	)

	w.WriteMsg(m)
	return dns.RcodeSuccess, nil
}

func mustLoadPolicy(t *testing.T, content string) *PolicyStore {
	t.Helper()
	ps := NewPolicyStore()
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.conf")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	if err := ps.LoadFile(path); err != nil {
		t.Fatal(err)
	}
	return ps
}
