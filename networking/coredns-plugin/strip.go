package sandboxpolicy

import "github.com/miekg/dns"

// DNS record types for SVCB and HTTPS (RFC 9460).
const (
	dnsTypeSVCB  = 64
	dnsTypeHTTPS = 65
)

// SVCB/HTTPS SvcParamKey for ECH (Encrypted Client Hello).
// https://www.iana.org/assignments/dns-svcb/dns-svcb.xhtml
const svcParamKeyECH = 5

// stripAAAA removes all AAAA records from the answer, authority, and extra
// sections of a DNS response message. Returns the count of removed records.
func stripAAAA(msg *dns.Msg) int {
	removed := 0
	msg.Answer, removed = filterRRs(msg.Answer, dns.TypeAAAA)
	n := 0
	msg.Ns, n = filterRRs(msg.Ns, dns.TypeAAAA)
	removed += n
	msg.Extra, n = filterRRs(msg.Extra, dns.TypeAAAA)
	removed += n
	return removed
}

// stripECH removes SVCB (type 64) and HTTPS (type 65) records that carry
// ECHConfig parameters from all sections of a DNS response. This prevents
// Encrypted Client Hello, which would bypass SNI extraction at the gateway.
// Returns the count of removed records.
func stripECH(msg *dns.Msg) int {
	removed := 0
	msg.Answer, removed = filterECHRecords(msg.Answer)
	n := 0
	msg.Ns, n = filterECHRecords(msg.Ns)
	removed += n
	msg.Extra, n = filterECHRecords(msg.Extra)
	removed += n
	return removed
}

// filterRRs removes all RRs of the given type from the slice. Returns the
// filtered slice and the count of removed records.
func filterRRs(rrs []dns.RR, rrtype uint16) ([]dns.RR, int) {
	kept := rrs[:0]
	removed := 0
	for _, rr := range rrs {
		if rr.Header().Rrtype == rrtype {
			removed++
		} else {
			kept = append(kept, rr)
		}
	}
	return kept, removed
}

// filterECHRecords removes SVCB/HTTPS records that contain an ECH SvcParam.
// Records of type SVCB or HTTPS that do NOT carry ECH are preserved.
func filterECHRecords(rrs []dns.RR) ([]dns.RR, int) {
	kept := rrs[:0]
	removed := 0
	for _, rr := range rrs {
		if hasECHParam(rr) {
			removed++
		} else {
			kept = append(kept, rr)
		}
	}
	return kept, removed
}

// hasECHParam returns true if the RR is a SVCB or HTTPS record containing
// an ECH SvcParam (key 5).
func hasECHParam(rr dns.RR) bool {
	switch r := rr.(type) {
	case *dns.SVCB:
		return containsECHKey(r.Value)
	case *dns.HTTPS:
		return containsECHKey(r.Value)
	default:
		return false
	}
}

// containsECHKey checks a slice of SVCB key-value pairs for the ECH key.
func containsECHKey(params []dns.SVCBKeyValue) bool {
	for _, kv := range params {
		if kv.Key() == dns.SVCBKey(svcParamKeyECH) {
			return true
		}
	}
	return false
}
