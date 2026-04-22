package sandboxpolicy

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/coredns/caddy"
)

// newController builds a caddy.Controller loaded with the given plugin block.
// The block contents go inside `sandboxpolicy { ... }`.
func newController(t *testing.T, block string) *caddy.Controller {
	t.Helper()
	input := "sandboxpolicy {\n" + block + "\n}\n"
	return caddy.NewTestController("dns", input)
}

func TestParseConfig_EventsFileOptional(t *testing.T) {
	// No events_file directive — parseConfig must succeed and leave eventsFile empty.
	c := newController(t, "policy_file /tmp/policy.conf")
	sp, err := parseConfig(c)
	if err != nil {
		t.Fatalf("parseConfig: %v", err)
	}
	if sp.eventsFile != "" {
		t.Errorf("eventsFile = %q, want empty (directive omitted)", sp.eventsFile)
	}
	if sp.events != nil {
		t.Errorf("events writer must be nil when directive is omitted")
	}
}

func TestParseConfig_EventsFileAccepted(t *testing.T) {
	dir := t.TempDir()
	eventsPath := filepath.Join(dir, "coredns.jsonl")
	policyPath := filepath.Join(dir, "policy.conf")

	c := newController(t, "policy_file "+policyPath+"\n        events_file "+eventsPath)
	sp, err := parseConfig(c)
	if err != nil {
		t.Fatalf("parseConfig: %v", err)
	}
	if sp.eventsFile != eventsPath {
		t.Errorf("eventsFile = %q, want %q", sp.eventsFile, eventsPath)
	}
}

func TestParseConfig_EventsFileRequiresArgument(t *testing.T) {
	c := newController(t, "policy_file /tmp/policy.conf\n        events_file")
	if _, err := parseConfig(c); err == nil {
		t.Fatal("parseConfig: expected error for events_file with no argument, got nil")
	}
}

func TestParseConfig_EventsFileRejectsMultipleArguments(t *testing.T) {
	c := newController(t, "policy_file /tmp/policy.conf\n        events_file /a /b")
	if _, err := parseConfig(c); err == nil {
		t.Fatal("parseConfig: expected error for events_file with two arguments, got nil")
	}
}

func TestParseConfig_EventsFileOpensWriterOnSetup(t *testing.T) {
	// Guards the two-step wiring: parseConfig records eventsFile, and the
	// corresponding block in setup() opens the EventWriter. We can't call
	// setup() directly in a unit test (it starts the reload goroutine with
	// no clean shutdown path), so this test exercises the same open logic
	// that setup() runs and asserts the file is created on disk.
	dir := t.TempDir()
	eventsPath := filepath.Join(dir, "coredns.jsonl")
	policyPath := filepath.Join(dir, "policy.conf")
	if err := os.WriteFile(policyPath, []byte("example.com\n"), 0644); err != nil {
		t.Fatal(err)
	}

	c := newController(t, "policy_file "+policyPath+"\n        events_file "+eventsPath)
	sp, err := parseConfig(c)
	if err != nil {
		t.Fatalf("parseConfig: %v", err)
	}
	if sp.eventsFile != eventsPath {
		t.Fatalf("eventsFile = %q, want %q", sp.eventsFile, eventsPath)
	}

	// Mirror the setup() block that opens the writer.
	ew, err := NewEventWriter(sp.eventsFile)
	if err != nil {
		t.Fatalf("NewEventWriter: %v", err)
	}
	t.Cleanup(func() { _ = ew.Close() })
	if _, err := os.Stat(eventsPath); err != nil {
		t.Fatalf("events file not created: %v", err)
	}
}
