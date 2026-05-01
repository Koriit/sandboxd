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

// stripECH removes the ECH (Encrypted Client Hello) SvcParam from every
// SVCB (type 64) and HTTPS (type 65) record in a DNS response — across
// the answer, authority, and extra sections — while leaving the records
// themselves and any other SvcParams (ALPN, port, IPv4 hints, …) intact.
// Records of unrelated types are untouched.
//
// This prevents Encrypted Client Hello (which would defeat SNI extraction
// at the gateway and break HTTP inspection) without dropping the rest of
// the SVCB/HTTPS information clients rely on. Returns the count of records
// from which an ECH SvcParam was removed.
func stripECH(msg *dns.Msg) int {
	removed := 0
	removed += stripECHFromSection(msg.Answer)
	removed += stripECHFromSection(msg.Ns)
	removed += stripECHFromSection(msg.Extra)
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

// stripECHFromSection walks one DNS message section and removes the ECH
// SvcParam from each SVCB / HTTPS record that carries it. The records
// themselves remain in place — only the ECH SvcParam is dropped. Returns
// the count of records from which an ECH SvcParam was removed.
func stripECHFromSection(rrs []dns.RR) int {
	stripped := 0
	for _, rr := range rrs {
		if stripECHFromRR(rr) {
			stripped++
		}
	}
	return stripped
}

// stripECHFromRR removes the ECH SvcParam from a single SVCB or HTTPS
// record's `Value` slice if present. Returns true if a param was removed.
// All other RR types and any SVCB/HTTPS without ECH are left untouched.
func stripECHFromRR(rr dns.RR) bool {
	switch r := rr.(type) {
	case *dns.SVCB:
		if filtered, removed := filterECHParams(r.Value); removed {
			r.Value = filtered
			return true
		}
	case *dns.HTTPS:
		if filtered, removed := filterECHParams(r.Value); removed {
			r.Value = filtered
			return true
		}
	}
	return false
}

// filterECHParams returns a copy of the SvcParam slice with any ECH entries
// removed, plus a flag indicating whether at least one ECH entry was
// removed. The original slice is not mutated.
func filterECHParams(params []dns.SVCBKeyValue) ([]dns.SVCBKeyValue, bool) {
	if !containsECHKey(params) {
		return params, false
	}
	kept := make([]dns.SVCBKeyValue, 0, len(params))
	for _, kv := range params {
		if kv.Key() == dns.SVCBKey(svcParamKeyECH) {
			continue
		}
		kept = append(kept, kv)
	}
	return kept, true
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
