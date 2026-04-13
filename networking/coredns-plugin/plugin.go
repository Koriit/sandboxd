// Package sandboxpolicy implements a CoreDNS plugin that enforces DNS-level
// policy for the claude-sandbox gateway. It loads an allowed-domain list from a
// file, returns NXDOMAIN for unlisted domains, strips AAAA/SVCB/HTTPS records,
// and reports resolved domain→IP mappings to a JSON file.
package sandboxpolicy

import (
	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/plugin"
)

const pluginName = "sandboxpolicy"

func init() {
	plugin.Register(pluginName, setup)

	// Insert our directive right before "forward" in the directive ordering.
	// This ensures sandboxpolicy intercepts queries before they are forwarded
	// upstream, but after log/health/ready have run.
	directives := dnsserver.Directives
	for i, d := range directives {
		if d == "forward" {
			updated := make([]string, 0, len(directives)+1)
			updated = append(updated, directives[:i]...)
			updated = append(updated, pluginName)
			updated = append(updated, directives[i:]...)
			dnsserver.Directives = updated
			break
		}
	}
}
