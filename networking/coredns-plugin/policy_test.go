package sandboxpolicy

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestIsAllowed_ExactMatch(t *testing.T) {
	ps := NewPolicyStore()
	writePolicy(t, ps, "example.com\nfoo.org\n")

	tests := []struct {
		name    string
		domain  string
		allowed bool
	}{
		{"exact match with dot", "example.com.", true},
		{"exact match without dot", "example.com", true},
		{"exact match second domain", "foo.org.", true},
		{"not in list", "bar.com.", false},
		{"subdomain not matched by exact", "sub.example.com.", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ps.IsAllowed(tt.domain); got != tt.allowed {
				t.Errorf("IsAllowed(%q) = %v, want %v", tt.domain, got, tt.allowed)
			}
		})
	}
}

func TestIsAllowed_WildcardMatch(t *testing.T) {
	ps := NewPolicyStore()
	writePolicy(t, ps, "*.example.com\n")

	tests := []struct {
		name    string
		domain  string
		allowed bool
	}{
		{"wildcard matches subdomain", "foo.example.com.", true},
		{"wildcard matches another subdomain", "bar.example.com.", true},
		{"wildcard does NOT match base domain", "example.com.", false},
		{"wildcard does NOT match deeper subdomain", "a.b.example.com.", false},
		{"unrelated domain", "example.org.", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ps.IsAllowed(tt.domain); got != tt.allowed {
				t.Errorf("IsAllowed(%q) = %v, want %v", tt.domain, got, tt.allowed)
			}
		})
	}
}

func TestIsAllowed_CaseInsensitive(t *testing.T) {
	ps := NewPolicyStore()
	writePolicy(t, ps, "Example.COM\n*.Foo.ORG\n")

	tests := []struct {
		name    string
		domain  string
		allowed bool
	}{
		{"lowercase query", "example.com.", true},
		{"uppercase query", "EXAMPLE.COM.", true},
		{"mixed case query", "ExAmPlE.cOm.", true},
		{"wildcard lowercase", "bar.foo.org.", true},
		{"wildcard uppercase", "BAR.FOO.ORG.", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ps.IsAllowed(tt.domain); got != tt.allowed {
				t.Errorf("IsAllowed(%q) = %v, want %v", tt.domain, got, tt.allowed)
			}
		})
	}
}

func TestIsAllowed_EmptyPolicy(t *testing.T) {
	ps := NewPolicyStore()
	writePolicy(t, ps, "# only comments\n\n")

	if ps.IsAllowed("example.com.") {
		t.Error("empty policy should deny everything")
	}
	if ps.IsAllowed("anything.at.all.") {
		t.Error("empty policy should deny everything")
	}
}

func TestIsAllowed_CommentsAndBlankLines(t *testing.T) {
	ps := NewPolicyStore()
	writePolicy(t, ps, "# header comment\n\nexample.com\n  \n# another comment\nfoo.org\n")

	if !ps.IsAllowed("example.com.") {
		t.Error("expected example.com to be allowed")
	}
	if !ps.IsAllowed("foo.org.") {
		t.Error("expected foo.org to be allowed")
	}
}

func TestIsAllowed_TrailingDotInFile(t *testing.T) {
	ps := NewPolicyStore()
	// Domain in file has a trailing dot — should still work.
	writePolicy(t, ps, "example.com.\n")

	if !ps.IsAllowed("example.com.") {
		t.Error("expected example.com to be allowed even with trailing dot in file")
	}
}

func TestPolicyReload(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.conf")

	// Write initial policy.
	if err := os.WriteFile(path, []byte("example.com\n"), 0644); err != nil {
		t.Fatal(err)
	}

	ps := NewPolicyStore()
	if err := ps.LoadFile(path); err != nil {
		t.Fatalf("initial load: %v", err)
	}

	if !ps.IsAllowed("example.com.") {
		t.Error("expected example.com allowed after initial load")
	}
	if ps.IsAllowed("newdomain.com.") {
		t.Error("expected newdomain.com denied after initial load")
	}

	// Start reload with a short interval.
	ps.StartReload(path, 100*time.Millisecond)
	defer ps.StopReload()

	// Update the policy file.
	// Need to ensure mtime changes — sleep briefly then write.
	time.Sleep(50 * time.Millisecond)
	if err := os.WriteFile(path, []byte("newdomain.com\n"), 0644); err != nil {
		t.Fatal(err)
	}

	// Wait for reload to pick up the change.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if ps.IsAllowed("newdomain.com.") {
			// Verify old domain is no longer allowed.
			if ps.IsAllowed("example.com.") {
				t.Error("expected example.com denied after reload")
			}
			return // success
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Error("policy reload did not pick up changes within 2s")
}

func TestDomainCount(t *testing.T) {
	ps := NewPolicyStore()
	writePolicy(t, ps, "example.com\n*.foo.org\nbar.net\n")

	exact, wildcard := ps.DomainCount()
	if exact != 2 {
		t.Errorf("exact count = %d, want 2", exact)
	}
	if wildcard != 1 {
		t.Errorf("wildcard count = %d, want 1", wildcard)
	}
}

// writePolicy writes content to a temp file and loads it into the store.
func writePolicy(t *testing.T, ps *PolicyStore, content string) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.conf")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	if err := ps.LoadFile(path); err != nil {
		t.Fatal(err)
	}
}
