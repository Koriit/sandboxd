package sandboxpolicy

import (
	"net"
	"testing"

	"github.com/miekg/dns"
)

func TestStripAAAA_RemovesAAAAKeepsA(t *testing.T) {
	msg := new(dns.Msg)
	msg.Answer = []dns.RR{
		&dns.A{
			Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
			A:   net.ParseIP("93.184.216.34"),
		},
		&dns.AAAA{
			Hdr:  dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 300},
			AAAA: net.ParseIP("2606:2800:220:1:248:1893:25c8:1946"),
		},
	}

	removed := stripAAAA(msg)

	if removed != 1 {
		t.Errorf("removed = %d, want 1", removed)
	}
	if len(msg.Answer) != 1 {
		t.Fatalf("answer count = %d, want 1", len(msg.Answer))
	}
	if msg.Answer[0].Header().Rrtype != dns.TypeA {
		t.Errorf("remaining record type = %d, want A (%d)", msg.Answer[0].Header().Rrtype, dns.TypeA)
	}
}

func TestStripAAAA_NoAAAAPresent(t *testing.T) {
	msg := new(dns.Msg)
	msg.Answer = []dns.RR{
		&dns.A{
			Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
			A:   net.ParseIP("93.184.216.34"),
		},
	}

	removed := stripAAAA(msg)

	if removed != 0 {
		t.Errorf("removed = %d, want 0", removed)
	}
	if len(msg.Answer) != 1 {
		t.Errorf("answer count = %d, want 1", len(msg.Answer))
	}
}

func TestStripAAAA_AllAAAA(t *testing.T) {
	msg := new(dns.Msg)
	msg.Answer = []dns.RR{
		&dns.AAAA{
			Hdr:  dns.RR_Header{Name: "a.com.", Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 300},
			AAAA: net.ParseIP("::1"),
		},
		&dns.AAAA{
			Hdr:  dns.RR_Header{Name: "b.com.", Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 300},
			AAAA: net.ParseIP("::2"),
		},
	}

	removed := stripAAAA(msg)

	if removed != 2 {
		t.Errorf("removed = %d, want 2", removed)
	}
	if len(msg.Answer) != 0 {
		t.Errorf("answer count = %d, want 0", len(msg.Answer))
	}
}

func TestStripAAAA_ExtraSection(t *testing.T) {
	msg := new(dns.Msg)
	msg.Extra = []dns.RR{
		&dns.AAAA{
			Hdr:  dns.RR_Header{Name: "ns.example.com.", Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 300},
			AAAA: net.ParseIP("::1"),
		},
		&dns.A{
			Hdr: dns.RR_Header{Name: "ns.example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
			A:   net.ParseIP("1.2.3.4"),
		},
	}

	removed := stripAAAA(msg)

	if removed != 1 {
		t.Errorf("removed = %d, want 1", removed)
	}
	if len(msg.Extra) != 1 {
		t.Fatalf("extra count = %d, want 1", len(msg.Extra))
	}
}

// TestStripECH_RemovesECHParamPreservesSVCBRecord asserts that an SVCB
// record carrying both ALPN and ECH SvcParams keeps its ALPN entry while
// the ECH key is dropped. The record itself remains in the answer — only
// the ECH SvcParam is stripped — and unrelated records (here, an A) are
// untouched.
func TestStripECH_RemovesECHParamPreservesSVCBRecord(t *testing.T) {
	msg := new(dns.Msg)
	msg.Answer = []dns.RR{
		&dns.SVCB{
			Hdr:      dns.RR_Header{Name: "example.com.", Rrtype: dnsTypeSVCB, Class: dns.ClassINET, Ttl: 300},
			Priority: 1,
			Target:   ".",
			Value: []dns.SVCBKeyValue{
				&dns.SVCBAlpn{Alpn: []string{"h2"}},
				&dns.SVCBECHConfig{ECH: []byte{0x01, 0x02}},
			},
		},
		&dns.A{
			Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
			A:   net.ParseIP("1.2.3.4"),
		},
	}

	stripped := stripECH(msg)

	if stripped != 1 {
		t.Errorf("stripped = %d, want 1", stripped)
	}
	if len(msg.Answer) != 2 {
		t.Fatalf("answer count = %d, want 2 (SVCB record must be preserved)", len(msg.Answer))
	}
	svcb, ok := msg.Answer[0].(*dns.SVCB)
	if !ok {
		t.Fatalf("first record is not SVCB: %T", msg.Answer[0])
	}
	if len(svcb.Value) != 1 {
		t.Fatalf("SVCB SvcParams = %d, want 1 (ECH stripped, ALPN preserved)", len(svcb.Value))
	}
	if svcb.Value[0].Key() != dns.SVCB_ALPN {
		t.Errorf("remaining SvcParam key = %d, want SVCB_ALPN", svcb.Value[0].Key())
	}
	if msg.Answer[1].Header().Rrtype != dns.TypeA {
		t.Errorf("second record type = %d, want A", msg.Answer[1].Header().Rrtype)
	}
}

// TestStripECH_PreservesSVCBWithoutECH asserts that an SVCB record with
// no ECH SvcParam is left entirely untouched.
func TestStripECH_PreservesSVCBWithoutECH(t *testing.T) {
	msg := new(dns.Msg)
	msg.Answer = []dns.RR{
		&dns.SVCB{
			Hdr:      dns.RR_Header{Name: "example.com.", Rrtype: dnsTypeSVCB, Class: dns.ClassINET, Ttl: 300},
			Priority: 1,
			Target:   ".",
			Value: []dns.SVCBKeyValue{
				&dns.SVCBAlpn{Alpn: []string{"h2"}},
			},
		},
	}

	stripped := stripECH(msg)

	if stripped != 0 {
		t.Errorf("stripped = %d, want 0", stripped)
	}
	if len(msg.Answer) != 1 {
		t.Errorf("answer count = %d, want 1", len(msg.Answer))
	}
	svcb, ok := msg.Answer[0].(*dns.SVCB)
	if !ok {
		t.Fatalf("first record is not SVCB: %T", msg.Answer[0])
	}
	if len(svcb.Value) != 1 || svcb.Value[0].Key() != dns.SVCB_ALPN {
		t.Errorf("SvcParams mutated unexpectedly: %v", svcb.Value)
	}
}

// TestStripECH_RemovesECHParamFromHTTPSRecord asserts that an HTTPS
// record carrying only an ECH SvcParam is preserved (with an empty
// SvcParam list) — i.e. the ECH-only case still keeps the record so the
// VM sees a valid HTTPS RR. Other params, when present, are preserved
// alongside the strip.
func TestStripECH_RemovesECHParamFromHTTPSRecord(t *testing.T) {
	msg := new(dns.Msg)
	msg.Answer = []dns.RR{
		&dns.HTTPS{
			SVCB: dns.SVCB{
				Hdr:      dns.RR_Header{Name: "example.com.", Rrtype: dnsTypeHTTPS, Class: dns.ClassINET, Ttl: 300},
				Priority: 1,
				Target:   ".",
				Value: []dns.SVCBKeyValue{
					&dns.SVCBAlpn{Alpn: []string{"h3"}},
					&dns.SVCBECHConfig{ECH: []byte{0xAB, 0xCD}},
					&dns.SVCBPort{Port: 8443},
				},
			},
		},
	}

	stripped := stripECH(msg)

	if stripped != 1 {
		t.Errorf("stripped = %d, want 1", stripped)
	}
	if len(msg.Answer) != 1 {
		t.Fatalf("answer count = %d, want 1 (HTTPS record must be preserved)", len(msg.Answer))
	}
	https, ok := msg.Answer[0].(*dns.HTTPS)
	if !ok {
		t.Fatalf("first record is not HTTPS: %T", msg.Answer[0])
	}
	if len(https.Value) != 2 {
		t.Fatalf("HTTPS SvcParams = %d, want 2 (ECH stripped, ALPN+Port preserved)", len(https.Value))
	}
	for _, kv := range https.Value {
		if kv.Key() == dns.SVCBKey(svcParamKeyECH) {
			t.Errorf("ECH SvcParam still present after strip: %v", kv)
		}
	}
}

// TestStripECH_HTTPSOnlyECHEndsWithEmptyParams covers the corner case of
// an HTTPS RR whose only SvcParam was ECH: the ECH key is removed and
// the record stays with an empty SvcParam slice. This is intentional —
// dropping the record would be a behavior change (record-level removal,
// the prior stance that the strip-the-param fix reverted).
func TestStripECH_HTTPSOnlyECHEndsWithEmptyParams(t *testing.T) {
	msg := new(dns.Msg)
	msg.Answer = []dns.RR{
		&dns.HTTPS{
			SVCB: dns.SVCB{
				Hdr:      dns.RR_Header{Name: "example.com.", Rrtype: dnsTypeHTTPS, Class: dns.ClassINET, Ttl: 300},
				Priority: 1,
				Target:   ".",
				Value: []dns.SVCBKeyValue{
					&dns.SVCBECHConfig{ECH: []byte{0xAB, 0xCD}},
				},
			},
		},
	}

	stripped := stripECH(msg)

	if stripped != 1 {
		t.Errorf("stripped = %d, want 1", stripped)
	}
	if len(msg.Answer) != 1 {
		t.Fatalf("answer count = %d, want 1 (record must remain even when only ECH was present)", len(msg.Answer))
	}
	https := msg.Answer[0].(*dns.HTTPS)
	if len(https.Value) != 0 {
		t.Errorf("HTTPS SvcParams = %d, want 0 (empty after ECH stripped)", len(https.Value))
	}
}

// TestStripECH_StripsAcrossSections asserts the stripper walks Answer,
// Authority (Ns), and Additional (Extra) sections.
func TestStripECH_StripsAcrossSections(t *testing.T) {
	mkSVCB := func(name string) *dns.SVCB {
		return &dns.SVCB{
			Hdr:      dns.RR_Header{Name: name, Rrtype: dnsTypeSVCB, Class: dns.ClassINET, Ttl: 300},
			Priority: 1,
			Target:   ".",
			Value: []dns.SVCBKeyValue{
				&dns.SVCBAlpn{Alpn: []string{"h2"}},
				&dns.SVCBECHConfig{ECH: []byte{0x01}},
			},
		}
	}
	msg := new(dns.Msg)
	msg.Answer = []dns.RR{mkSVCB("a.example.com.")}
	msg.Ns = []dns.RR{mkSVCB("ns.example.com.")}
	msg.Extra = []dns.RR{mkSVCB("ext.example.com.")}

	stripped := stripECH(msg)
	if stripped != 3 {
		t.Errorf("stripped = %d, want 3", stripped)
	}
	for i, rr := range append(append(append([]dns.RR{}, msg.Answer...), msg.Ns...), msg.Extra...) {
		svcb := rr.(*dns.SVCB)
		if len(svcb.Value) != 1 || svcb.Value[0].Key() != dns.SVCB_ALPN {
			t.Errorf("section RR %d: SvcParams=%v, want only ALPN", i, svcb.Value)
		}
	}
}

// TestStripECH_LeavesUnrelatedTypesAlone asserts non-SVCB/HTTPS records
// are untouched even if they happen to share a section with stripped
// records.
func TestStripECH_LeavesUnrelatedTypesAlone(t *testing.T) {
	msg := new(dns.Msg)
	msg.Answer = []dns.RR{
		&dns.A{
			Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
			A:   net.ParseIP("1.2.3.4"),
		},
		&dns.MX{
			Hdr:        dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeMX, Class: dns.ClassINET, Ttl: 300},
			Preference: 10,
			Mx:         "mail.example.com.",
		},
	}

	stripped := stripECH(msg)
	if stripped != 0 {
		t.Errorf("stripped = %d, want 0", stripped)
	}
	if len(msg.Answer) != 2 {
		t.Errorf("answer count = %d, want 2", len(msg.Answer))
	}
}

func TestStripECH_EmptyMessage(t *testing.T) {
	msg := new(dns.Msg)
	stripped := stripECH(msg)
	if stripped != 0 {
		t.Errorf("stripped = %d, want 0", stripped)
	}
}
