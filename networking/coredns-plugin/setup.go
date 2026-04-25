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

	// Open the structured-events writer if a path was configured. This is
	// opened here (not in parseConfig) so the file is created once per
	// CoreDNS startup, matching the lifetime of the reload goroutine below.
	if sp.eventsFile != "" {
		ew, err := NewEventWriter(sp.eventsFile)
		if err != nil {
			return plugin.Error(pluginName, fmt.Errorf("opening events file %q: %w", sp.eventsFile, err))
		}
		sp.events = ew
	}

	// Initialise the synchronous DNS-gate client if a socket path was
	// configured. The dial itself is lazy (per request), so we don't
	// block plugin setup on sandboxd binding the listener — but the
	// path being set turns on gate behaviour on every WriteMsg.
	if sp.gateSocketPath != "" {
		sp.gate = newGateClient(sp.gateSocketPath, sp.gateDeadline)
	}

	// Start background policy file reload goroutine.
	sp.policy.StartReload(sp.policyFile, sp.reloadInterval)

	// Register shutdown hook to stop the reload goroutine and close the
	// events writer.
	c.OnShutdown(func() error {
		sp.policy.StopReload()
		if sp.events != nil {
			if err := sp.events.Close(); err != nil {
				log.Warningf("closing events file: %v", err)
			}
		}
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

			case "events_file":
				args := c.RemainingArgs()
				if len(args) != 1 {
					return nil, c.Errf("events_file requires exactly one argument")
				}
				sp.eventsFile = args[0]

			case "gate_socket":
				args := c.RemainingArgs()
				if len(args) != 1 {
					return nil, c.Errf("gate_socket requires exactly one argument (path)")
				}
				sp.gateSocketPath = args[0]

			case "gate_deadline":
				args := c.RemainingArgs()
				if len(args) != 1 {
					return nil, c.Errf("gate_deadline requires exactly one argument (duration)")
				}
				d, err := time.ParseDuration(args[0])
				if err != nil {
					return nil, c.Errf("invalid gate_deadline %q: %v", args[0], err)
				}
				if d <= 0 {
					return nil, c.Errf("gate_deadline must be > 0, got %v", d)
				}
				sp.gateDeadline = d

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
