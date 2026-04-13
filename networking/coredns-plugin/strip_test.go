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

func TestStripECH_RemovesSVCBWithECH(t *testing.T) {
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

	removed := stripECH(msg)

	if removed != 1 {
		t.Errorf("removed = %d, want 1", removed)
	}
	if len(msg.Answer) != 1 {
		t.Fatalf("answer count = %d, want 1", len(msg.Answer))
	}
	if msg.Answer[0].Header().Rrtype != dns.TypeA {
		t.Errorf("remaining record type = %d, want A", msg.Answer[0].Header().Rrtype)
	}
}

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

	removed := stripECH(msg)

	if removed != 0 {
		t.Errorf("removed = %d, want 0", removed)
	}
	if len(msg.Answer) != 1 {
		t.Errorf("answer count = %d, want 1", len(msg.Answer))
	}
}

func TestStripECH_RemovesHTTPSWithECH(t *testing.T) {
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

	removed := stripECH(msg)

	if removed != 1 {
		t.Errorf("removed = %d, want 1", removed)
	}
	if len(msg.Answer) != 0 {
		t.Errorf("answer count = %d, want 0", len(msg.Answer))
	}
}

func TestStripECH_EmptyMessage(t *testing.T) {
	msg := new(dns.Msg)
	removed := stripECH(msg)
	if removed != 0 {
		t.Errorf("removed = %d, want 0", removed)
	}
}
