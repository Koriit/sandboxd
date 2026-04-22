package sandboxpolicy

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// decodeEventLine parses a single JSONL line into a generic map so tests can
// assert on field presence/absence without coupling to the internal struct
// shape.
func decodeEventLine(t *testing.T, line string) map[string]interface{} {
	t.Helper()
	var m map[string]interface{}
	if err := json.Unmarshal([]byte(line), &m); err != nil {
		t.Fatalf("decode %q: %v", line, err)
	}
	return m
}

// readAllLines returns all non-empty lines from path.
func readAllLines(t *testing.T, path string) []string {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	defer f.Close()
	var lines []string
	s := bufio.NewScanner(f)
	// Large buffer in case concurrency test lines stack (unlikely but safe).
	s.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for s.Scan() {
		line := s.Text()
		if line != "" {
			lines = append(lines, line)
		}
	}
	if err := s.Err(); err != nil {
		t.Fatalf("scan %s: %v", path, err)
	}
	return lines
}

func TestEventWriterAllowRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "coredns.jsonl")

	w, err := NewEventWriter(path)
	if err != nil {
		t.Fatalf("NewEventWriter: %v", err)
	}
	t.Cleanup(func() { _ = w.Close() })

	if err := w.EmitQueryAllowed("example.com", "A", []string{"93.184.216.34", "93.184.216.35"}, "10.0.0.2"); err != nil {
		t.Fatalf("EmitQueryAllowed: %v", err)
	}

	lines := readAllLines(t, path)
	if len(lines) != 1 {
		t.Fatalf("line count = %d, want 1 (lines=%v)", len(lines), lines)
	}

	m := decodeEventLine(t, lines[0])
	if got, want := m["layer"], "dns"; got != want {
		t.Errorf("layer = %v, want %v", got, want)
	}
	if got, want := m["event"], "query_allowed"; got != want {
		t.Errorf("event = %v, want %v", got, want)
	}
	if got, want := m["query"], "example.com"; got != want {
		t.Errorf("query = %v, want %v", got, want)
	}
	if got, want := m["qtype"], "A"; got != want {
		t.Errorf("qtype = %v, want %v", got, want)
	}
	if got, want := m["client_ip"], "10.0.0.2"; got != want {
		t.Errorf("client_ip = %v, want %v", got, want)
	}
	ts, ok := m["timestamp"].(string)
	if !ok || ts == "" {
		t.Errorf("timestamp missing or not a string: %v", m["timestamp"])
	}
	if !strings.HasSuffix(ts, "Z") {
		t.Errorf("timestamp does not end in Z: %q", ts)
	}
	ips, ok := m["resolved_ips"].([]interface{})
	if !ok {
		t.Fatalf("resolved_ips missing or wrong type: %T %v", m["resolved_ips"], m["resolved_ips"])
	}
	if len(ips) != 2 || ips[0] != "93.184.216.34" || ips[1] != "93.184.216.35" {
		t.Errorf("resolved_ips = %v, want [93.184.216.34 93.184.216.35]", ips)
	}
	if _, present := m["reason"]; present {
		t.Errorf("allow event must not carry reason field: %v", m)
	}
	if _, present := m["session"]; present {
		t.Errorf("plugin must not stamp session field: %v", m)
	}
}

func TestEventWriterDenyRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "coredns.jsonl")

	w, err := NewEventWriter(path)
	if err != nil {
		t.Fatalf("NewEventWriter: %v", err)
	}
	t.Cleanup(func() { _ = w.Close() })

	if err := w.EmitQueryDenied("evil.example", "A", "policy", "10.0.0.2"); err != nil {
		t.Fatalf("EmitQueryDenied: %v", err)
	}

	lines := readAllLines(t, path)
	if len(lines) != 1 {
		t.Fatalf("line count = %d, want 1", len(lines))
	}

	m := decodeEventLine(t, lines[0])
	if got, want := m["event"], "query_denied"; got != want {
		t.Errorf("event = %v, want %v", got, want)
	}
	if got, want := m["reason"], "policy"; got != want {
		t.Errorf("reason = %v, want %v", got, want)
	}
	if got, want := m["query"], "evil.example"; got != want {
		t.Errorf("query = %v, want %v", got, want)
	}
	if got, want := m["qtype"], "A"; got != want {
		t.Errorf("qtype = %v, want %v", got, want)
	}
	if got, want := m["client_ip"], "10.0.0.2"; got != want {
		t.Errorf("client_ip = %v, want %v", got, want)
	}
	if got, want := m["layer"], "dns"; got != want {
		t.Errorf("layer = %v, want %v", got, want)
	}
	if _, present := m["resolved_ips"]; present {
		t.Errorf("deny event must not carry resolved_ips field: %v", m)
	}
	if _, present := m["session"]; present {
		t.Errorf("plugin must not stamp session field: %v", m)
	}
}

func TestEventWriterConcurrency(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "coredns.jsonl")

	w, err := NewEventWriter(path)
	if err != nil {
		t.Fatalf("NewEventWriter: %v", err)
	}
	t.Cleanup(func() { _ = w.Close() })

	const goroutines = 100
	var wg sync.WaitGroup
	wg.Add(goroutines)
	start := make(chan struct{})
	for i := 0; i < goroutines; i++ {
		i := i
		go func() {
			defer wg.Done()
			<-start
			// Alternate allow / deny to exercise both code paths under the mutex.
			if i%2 == 0 {
				if err := w.EmitQueryAllowed("example.com", "A", []string{"1.2.3.4"}, "10.0.0.2"); err != nil {
					t.Errorf("EmitQueryAllowed: %v", err)
				}
			} else {
				if err := w.EmitQueryDenied("evil.example", "A", "policy", "10.0.0.3"); err != nil {
					t.Errorf("EmitQueryDenied: %v", err)
				}
			}
		}()
	}
	close(start)
	wg.Wait()

	lines := readAllLines(t, path)
	if len(lines) != goroutines {
		t.Fatalf("line count = %d, want %d", len(lines), goroutines)
	}

	allowCount, denyCount := 0, 0
	for i, line := range lines {
		m := decodeEventLine(t, line)
		// Every line must parse cleanly — torn writes would fail here.
		event, _ := m["event"].(string)
		switch event {
		case "query_allowed":
			allowCount++
			// Schema fields per layer.
			if m["reason"] != nil {
				t.Errorf("line %d: allow carries reason: %v", i, m)
			}
			if _, ok := m["resolved_ips"].([]interface{}); !ok {
				t.Errorf("line %d: allow missing resolved_ips: %v", i, m)
			}
		case "query_denied":
			denyCount++
			if _, ok := m["reason"].(string); !ok {
				t.Errorf("line %d: deny missing reason: %v", i, m)
			}
			if m["resolved_ips"] != nil {
				t.Errorf("line %d: deny carries resolved_ips: %v", i, m)
			}
		default:
			t.Errorf("line %d: unexpected event %q", i, event)
		}
		if m["layer"] != "dns" {
			t.Errorf("line %d: layer = %v, want dns", i, m["layer"])
		}
		if _, present := m["session"]; present {
			t.Errorf("line %d: plugin stamped session field: %v", i, m)
		}
	}
	if allowCount+denyCount != goroutines {
		t.Errorf("allow=%d deny=%d, want sum=%d", allowCount, denyCount, goroutines)
	}
}

func TestEventWriterOmitsSessionField(t *testing.T) {
	// Defence in depth: even though the struct has no session field, assert it
	// never appears in the serialised output for either variant. Session
	// stamping happens in sandboxd at ingest time.
	dir := t.TempDir()
	path := filepath.Join(dir, "coredns.jsonl")

	w, err := NewEventWriter(path)
	if err != nil {
		t.Fatalf("NewEventWriter: %v", err)
	}
	t.Cleanup(func() { _ = w.Close() })

	if err := w.EmitQueryAllowed("example.com", "A", []string{"1.2.3.4"}, "10.0.0.2"); err != nil {
		t.Fatalf("EmitQueryAllowed: %v", err)
	}
	if err := w.EmitQueryDenied("evil.example", "A", "policy", "10.0.0.3"); err != nil {
		t.Fatalf("EmitQueryDenied: %v", err)
	}

	lines := readAllLines(t, path)
	if len(lines) != 2 {
		t.Fatalf("line count = %d, want 2", len(lines))
	}
	for i, line := range lines {
		if strings.Contains(line, `"session"`) {
			t.Errorf("line %d contains session field: %s", i, line)
		}
	}
}

func TestEventWriterAppendsAcrossOpens(t *testing.T) {
	// The runtime path survives the plugin restart scenario (gateway restarts
	// but the host bind-mount persists). O_APPEND must preserve earlier lines.
	dir := t.TempDir()
	path := filepath.Join(dir, "coredns.jsonl")

	w1, err := NewEventWriter(path)
	if err != nil {
		t.Fatalf("NewEventWriter 1: %v", err)
	}
	if err := w1.EmitQueryAllowed("first.example", "A", []string{"1.1.1.1"}, "10.0.0.2"); err != nil {
		t.Fatalf("emit 1: %v", err)
	}
	if err := w1.Close(); err != nil {
		t.Fatalf("close 1: %v", err)
	}

	w2, err := NewEventWriter(path)
	if err != nil {
		t.Fatalf("NewEventWriter 2: %v", err)
	}
	t.Cleanup(func() { _ = w2.Close() })
	if err := w2.EmitQueryDenied("second.example", "A", "policy", "10.0.0.3"); err != nil {
		t.Fatalf("emit 2: %v", err)
	}

	lines := readAllLines(t, path)
	if len(lines) != 2 {
		t.Fatalf("line count = %d, want 2 (lines=%v)", len(lines), lines)
	}
	first := decodeEventLine(t, lines[0])
	second := decodeEventLine(t, lines[1])
	if first["query"] != "first.example" {
		t.Errorf("line 0 query = %v, want first.example", first["query"])
	}
	if second["query"] != "second.example" {
		t.Errorf("line 1 query = %v, want second.example", second["query"])
	}
}
