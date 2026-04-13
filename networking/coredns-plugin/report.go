package sandboxpolicy

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// ReportEntry represents a single domain→IP mapping in the report file.
type ReportEntry struct {
	Domain    string   `json:"domain"`
	IPs       []string `json:"ips"`
	TTL       uint32   `json:"ttl"`
	Timestamp string   `json:"timestamp"`
}

// ReportFile is the top-level structure of the report JSON file.
type ReportFile struct {
	Mappings []ReportEntry `json:"mappings"`
}

// Reporter manages the domain→IP mapping report file. It accumulates mappings
// in memory and writes them atomically to the configured path.
type Reporter struct {
	path string

	mu       sync.Mutex
	mappings map[string]ReportEntry // keyed by domain
}

// NewReporter creates a Reporter that writes to the given path. If path is
// empty, reporting is disabled (RecordResponse is a no-op).
func NewReporter(path string) *Reporter {
	return &Reporter{
		path:     path,
		mappings: make(map[string]ReportEntry),
	}
}

// RecordResponse extracts A record IPs from a DNS response and writes an
// updated report file. Only A records are reported (AAAA is stripped by the
// plugin and the sandbox uses IPv4-only networking).
func (r *Reporter) RecordResponse(domain string, msg *dns.Msg) {
	if r.path == "" {
		return
	}

	var ips []string
	var minTTL uint32

	for _, rr := range msg.Answer {
		if a, ok := rr.(*dns.A); ok {
			ips = append(ips, a.A.String())
			ttl := rr.Header().Ttl
			if minTTL == 0 || ttl < minTTL {
				minTTL = ttl
			}
		}
	}

	if len(ips) == 0 {
		return
	}

	entry := ReportEntry{
		Domain:    domain,
		IPs:       ips,
		TTL:       minTTL,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	}

	r.mu.Lock()
	r.mappings[domain] = entry
	// Copy mappings under lock so we can release it before writing.
	entries := make([]ReportEntry, 0, len(r.mappings))
	for _, e := range r.mappings {
		entries = append(entries, e)
	}
	r.mu.Unlock()

	report := ReportFile{Mappings: entries}
	if err := writeAtomicJSON(r.path, report); err != nil {
		log.Warningf("report write failed: %v", err)
	}
}

// writeAtomicJSON writes data as JSON to a temporary file in the same
// directory as path, then atomically renames it to path. This ensures readers
// never see a partial file.
func writeAtomicJSON(path string, data interface{}) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".report-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()

	enc := json.NewEncoder(tmp)
	enc.SetIndent("", "  ")
	if err := enc.Encode(data); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return err
	}

	return os.Rename(tmpName, path)
}
