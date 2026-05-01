package sandboxpolicy

import (
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"
)

// EventWriter emits structured JSONL events (one JSON object per line) to a
// file that sandboxd tails via its per-layer ingestor.
//
// The writer appends to the file with an exclusive mutex around each write so
// concurrent emissions from multiple goroutines never produce torn lines.
// json.Encoder.Encode writes a trailing newline, which is exactly the JSONL
// framing the ingestor expects.
//
// EventWriter intentionally does NOT stamp a `session` field. sandboxd maps
// `client_ip` → session at ingest time (see vm_ip_map in sandbox-core), so the
// gateway container stays session-agnostic — the same Corefile/plugin binary
// is shared across all sessions.
type EventWriter struct {
	mu   sync.Mutex
	file *os.File
}

// dnsEventCommon carries the fields shared by every DNS event.
type dnsEventCommon struct {
	Timestamp string `json:"timestamp"`
	Layer     string `json:"layer"`
	Event     string `json:"event"`
	Query     string `json:"query"`
	QType     string `json:"qtype"`
	ClientIP  string `json:"client_ip"`
}

// dnsAllowedEvent is emitted when a query is resolved (success path).
type dnsAllowedEvent struct {
	dnsEventCommon
	ResolvedIPs []string `json:"resolved_ips"`
}

// dnsDeniedEvent is emitted when a query is denied by policy or type-based
// stripping (currently AAAA, which is denied at query time). SVCB/HTTPS
// queries are forwarded upstream and have only the ECH SvcParam stripped
// from the response — they do not produce deny events.
type dnsDeniedEvent struct {
	dnsEventCommon
	Reason string `json:"reason"`
}

// NewEventWriter opens (or creates) path for append-writes and returns a
// writer guarded by an internal mutex. The parent directory must already
// exist; in the gateway image it is the bind-mount target created by
// sandboxd.
func NewEventWriter(path string) (*EventWriter, error) {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return nil, fmt.Errorf("opening events file %q: %w", path, err)
	}
	return &EventWriter{file: f}, nil
}

// EmitQueryAllowed writes a `query_allowed` JSONL line.
// resolvedIPs may be empty (e.g. when upstream returned NODATA); in that case
// the emitted JSON contains `"resolved_ips": []` rather than being omitted so
// the ingest parser never needs to special-case a missing field.
func (w *EventWriter) EmitQueryAllowed(query, qtype string, resolvedIPs []string, clientIP string) error {
	if resolvedIPs == nil {
		resolvedIPs = []string{}
	}
	evt := dnsAllowedEvent{
		dnsEventCommon: dnsEventCommon{
			Timestamp: timestampNow(),
			Layer:     "dns",
			Event:     "query_allowed",
			Query:     query,
			QType:     qtype,
			ClientIP:  clientIP,
		},
		ResolvedIPs: resolvedIPs,
	}
	return w.writeEvent(&evt)
}

// EmitQueryDenied writes a `query_denied` JSONL line with a short free-text
// reason (e.g. "policy", "AAAA stripped").
func (w *EventWriter) EmitQueryDenied(query, qtype, reason, clientIP string) error {
	evt := dnsDeniedEvent{
		dnsEventCommon: dnsEventCommon{
			Timestamp: timestampNow(),
			Layer:     "dns",
			Event:     "query_denied",
			Query:     query,
			QType:     qtype,
			ClientIP:  clientIP,
		},
		Reason: reason,
	}
	return w.writeEvent(&evt)
}

// dnsGateEvent records the outcome of one synchronous DNS-policy
// gate round-trip (M10-S10 Phase 2). Outcome is one of `ok`,
// `rejected`, `timed_out`, `protocol_error`, `unknown`.
type dnsGateEvent struct {
	Timestamp     string `json:"timestamp"`
	Layer         string `json:"layer"`
	Event         string `json:"event"`
	Query         string `json:"query"`
	Outcome       string `json:"outcome"`
	CorrelationID string `json:"correlation_id,omitempty"`
	Reason        string `json:"reason,omitempty"`
	ElapsedMS     uint64 `json:"elapsed_ms,omitempty"`
}

// EmitGateOutcome writes a `dns_gate_*` JSONL line. The event name
// itself is `dns_gate_<outcome>` so existing event-name filters can
// pin a single outcome class without splitting on the inner field.
func (w *EventWriter) EmitGateOutcome(query, outcome, correlationID, reason string, elapsedMS uint64) error {
	evt := dnsGateEvent{
		Timestamp:     timestampNow(),
		Layer:         "dns",
		Event:         "dns_gate_" + outcome,
		Query:         query,
		Outcome:       outcome,
		CorrelationID: correlationID,
		Reason:        reason,
		ElapsedMS:     elapsedMS,
	}
	return w.writeEvent(&evt)
}

// Close releases the underlying file handle. Safe to call on a nil receiver
// so setup/shutdown paths don't need to branch.
func (w *EventWriter) Close() error {
	if w == nil {
		return nil
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.file == nil {
		return nil
	}
	err := w.file.Close()
	w.file = nil
	return err
}

// writeEvent serialises evt as one line under the mutex. json.Encoder.Encode
// appends '\n', which is the JSONL framing we want.
func (w *EventWriter) writeEvent(evt interface{}) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.file == nil {
		return fmt.Errorf("event writer is closed")
	}
	return json.NewEncoder(w.file).Encode(evt)
}

// timestampNow returns the current UTC instant formatted as RFC 3339 with
// millisecond precision and a `Z` suffix — the shape the ingest parsers
// expect for all layers.
func timestampNow() string {
	return time.Now().UTC().Format("2006-01-02T15:04:05.000Z")
}
