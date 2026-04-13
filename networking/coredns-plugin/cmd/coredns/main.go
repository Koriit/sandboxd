// Custom CoreDNS build that includes the sandboxpolicy plugin alongside the
// standard CoreDNS plugin set. The blank import of the sandboxpolicy package
// triggers its init() function, which registers the plugin and inserts its
// directive into the correct position in the processing chain.
package main

import (
	_ "github.com/anthropics/claude-sandbox/networking/coredns-plugin" // sandboxpolicy plugin

	_ "github.com/coredns/coredns/core/plugin" // standard CoreDNS plugins
	"github.com/coredns/coredns/coremain"
)

func main() {
	coremain.Run()
}
