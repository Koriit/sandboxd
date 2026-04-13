package sandboxpolicy

import (
	"fmt"
	"time"

	"github.com/coredns/caddy"
	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/plugin"
)

func setup(c *caddy.Controller) error {
	sp, err := parseConfig(c)
	if err != nil {
		return plugin.Error(pluginName, err)
	}

	// Load initial policy.
	if err := sp.policy.LoadFile(sp.policyFile); err != nil {
		return plugin.Error(pluginName, fmt.Errorf("loading policy file %q: %w", sp.policyFile, err))
	}

	// Start background policy file reload goroutine.
	sp.policy.StartReload(sp.policyFile, sp.reloadInterval)

	// Register shutdown hook to stop the reload goroutine.
	c.OnShutdown(func() error {
		sp.policy.StopReload()
		return nil
	})

	dnsserver.GetConfig(c).AddPlugin(func(next plugin.Handler) plugin.Handler {
		sp.Next = next
		return sp
	})

	return nil
}

func parseConfig(c *caddy.Controller) (*SandboxPolicy, error) {
	sp := &SandboxPolicy{
		policy:         NewPolicyStore(),
		reporter:       NewReporter(""),
		reloadInterval: 5 * time.Second,
	}

	for c.Next() {
		// No arguments expected on the directive line itself.
		if c.NextArg() {
			return nil, c.ArgErr()
		}

		for c.NextBlock() {
			switch c.Val() {
			case "policy_file":
				args := c.RemainingArgs()
				if len(args) != 1 {
					return nil, c.Errf("policy_file requires exactly one argument")
				}
				sp.policyFile = args[0]

			case "report_file":
				args := c.RemainingArgs()
				if len(args) != 1 {
					return nil, c.Errf("report_file requires exactly one argument")
				}
				sp.reporter = NewReporter(args[0])

			case "reload":
				args := c.RemainingArgs()
				if len(args) != 1 {
					return nil, c.Errf("reload requires exactly one argument (duration)")
				}
				d, err := time.ParseDuration(args[0])
				if err != nil {
					return nil, c.Errf("invalid reload duration %q: %v", args[0], err)
				}
				if d < 1*time.Second {
					return nil, c.Errf("reload interval must be >= 1s, got %v", d)
				}
				sp.reloadInterval = d

			default:
				return nil, c.Errf("unknown property %q", c.Val())
			}
		}
	}

	if sp.policyFile == "" {
		return nil, fmt.Errorf("policy_file is required")
	}

	return sp, nil
}
