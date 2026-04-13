package sandboxpolicy

import (
	"bufio"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	clog "github.com/coredns/coredns/plugin/pkg/log"
)

var log = clog.NewWithPlugin(pluginName)

// domainSet is an immutable snapshot of allowed domains. It is swapped
// atomically so the request path never needs to acquire a lock.
type domainSet struct {
	// exact holds domains that must match exactly (e.g. "example.com").
	exact map[string]struct{}
	// wildcard holds parent domains from wildcard entries (e.g. "example.com"
	// from "*.example.com"). A query for "foo.example.com" matches if the
	// part after the first label is in this map.
	wildcard map[string]struct{}
}

// PolicyStore manages the allowed-domain set with lock-free reads and
// background reload support.
type PolicyStore struct {
	domains atomic.Value // *domainSet

	// reload control
	stopCh chan struct{}
	once   sync.Once
}

// NewPolicyStore returns a PolicyStore initialised with an empty (deny-all)
// domain set.
func NewPolicyStore() *PolicyStore {
	ps := &PolicyStore{
		stopCh: make(chan struct{}),
	}
	ps.domains.Store(&domainSet{
		exact:    make(map[string]struct{}),
		wildcard: make(map[string]struct{}),
	})
	return ps
}

// IsAllowed returns true if the given FQDN is permitted by the current policy.
// The name should be a DNS wire-format name (lowercase, trailing dot). The
// method normalises it internally.
func (ps *PolicyStore) IsAllowed(name string) bool {
	ds := ps.domains.Load().(*domainSet)
	// Normalise: lowercase, strip trailing dot.
	n := strings.TrimSuffix(strings.ToLower(name), ".")

	// Exact match.
	if _, ok := ds.exact[n]; ok {
		return true
	}

	// Wildcard match: strip the first label and check.
	if idx := strings.IndexByte(n, '.'); idx >= 0 {
		parent := n[idx+1:]
		if _, ok := ds.wildcard[parent]; ok {
			return true
		}
	}

	return false
}

// LoadFile reads an allowed-domain list from path and atomically replaces the
// current domain set. The file format is one domain per line; lines starting
// with '#' and empty lines are ignored.
func (ps *PolicyStore) LoadFile(path string) error {
	ds, err := parsePolicyFile(path)
	if err != nil {
		return err
	}
	ps.domains.Store(ds)
	log.Infof("loaded policy: %d exact, %d wildcard domains from %s",
		len(ds.exact), len(ds.wildcard), path)
	return nil
}

// StartReload begins a background goroutine that polls the policy file for
// changes (by mtime) and reloads when it detects a modification.
func (ps *PolicyStore) StartReload(path string, interval time.Duration) {
	go func() {
		var lastMod time.Time
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-ps.stopCh:
				return
			case <-ticker.C:
				info, err := os.Stat(path)
				if err != nil {
					log.Warningf("policy reload: stat %s: %v", path, err)
					continue
				}
				if info.ModTime().After(lastMod) {
					if err := ps.LoadFile(path); err != nil {
						log.Warningf("policy reload: %v", err)
					} else {
						lastMod = info.ModTime()
					}
				}
			}
		}
	}()
}

// StopReload signals the background reload goroutine to exit.
func (ps *PolicyStore) StopReload() {
	ps.once.Do(func() {
		close(ps.stopCh)
	})
}

// DomainCount returns the number of exact and wildcard domains in the current
// snapshot. Useful for tests and diagnostics.
func (ps *PolicyStore) DomainCount() (exact, wildcard int) {
	ds := ps.domains.Load().(*domainSet)
	return len(ds.exact), len(ds.wildcard)
}

// parsePolicyFile reads a policy file and returns a domainSet.
func parsePolicyFile(path string) (*domainSet, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	ds := &domainSet{
		exact:    make(map[string]struct{}),
		wildcard: make(map[string]struct{}),
	}

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Normalise: lowercase, strip trailing dot.
		domain := strings.TrimSuffix(strings.ToLower(line), ".")

		if strings.HasPrefix(domain, "*.") {
			// Wildcard entry: "*.example.com" → store "example.com" in wildcard map.
			parent := domain[2:]
			if parent != "" {
				ds.wildcard[parent] = struct{}{}
			}
		} else {
			ds.exact[domain] = struct{}{}
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return ds, nil
}
