# End-to-End Health-Check Design

## Status

Future enhancement — not part of initial implementation.

## Context

The networking subsystem uses per-component liveness probes for health monitoring (see [networking-design.md § Health monitoring](networking-design.md#health-monitoring)). sandboxd polls each gateway component individually — nftables rules are present, Envoy responds, mitmproxy responds, DNS resolver answers queries. These probes verify that components are alive but do not guarantee that traffic is actually being proxied through the full pipeline.

This document describes an end-to-end health-check mechanism that provides stronger assurance by exercising the complete data path.

## Design

### Component health validation

sandboxd runs health validation scripts inside the gateway container via Docker exec (or equivalent). These scripts verify:

* Envoy is listening on the expected port
* mitmproxy is responsive
* DNS resolver answers queries for a known-allowed domain
* nftables PREROUTING DNAT rules are loaded and active

This replaces external probing with direct in-container checks — no additional containers, volumes, or network policies required.

### Full path validation

sandboxd triggers a probe from inside the sandbox VM via the vsock control channel (see [sandbox-design.md § Control channel](sandbox-design.md#control-channel-vsock)). The probe process inside the VM makes an HTTPS request that traverses the full pipeline:

```
VM probe → virtio-net → bridge → gateway nftables PREROUTING DNAT → Envoy → mitmproxy → destination
```

The destination is a small health endpoint running inside the gateway container itself. This works because of how the gateway's nftables rules distinguish traffic:

* **From the VM (forwarded traffic):** hits PREROUTING DNAT, gets redirected through Envoy and mitmproxy. The probe exercises the entire enforcement pipeline.
* **From mitmproxy (locally-generated traffic):** mitmproxy's outbound connection to the health endpoint is locally-generated inside the gateway container and does not hit PREROUTING DNAT rules. It reaches the health endpoint directly.

This asymmetry keeps the health check self-contained — no external dependencies, no real outbound traffic required.

### Failure handling

When the end-to-end probe fails:

* log the failure with diagnostic context
* update session health status to reflect degraded networking
* send a system notification that the pipeline is degraded

sandboxd does **not** terminate the sandbox on probe failure. The sandbox may be running long-lived processes that do not require network access. The sandbox owner decides what action to take based on the reported status.

### Security properties

* sandboxd never exposes a network endpoint to the VM
* the health endpoint inside the gateway is only reachable through the proxy pipeline from the VM's perspective — there is no direct path that bypasses enforcement
* the probe is triggered by sandboxd via vsock, not by the agent
* no separate container, no shared volumes, no additional attack surface

## Why deferred

The per-component probes in the networking design provide sufficient diagnostics for initial implementation. The end-to-end probe adds confidence that the full pipeline works but requires:

* probe process management inside the VM (triggered via vsock)
* a health endpoint running in the gateway container
* integration between sandboxd, the vsock command interface, and the probe process

This is justified for higher-assurance deployments but not required for the initial release.
