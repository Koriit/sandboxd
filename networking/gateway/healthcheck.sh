#!/usr/bin/env bash
#
# Gateway container health check
# Checks all three pipeline components. Exits 0 if all healthy, 1 otherwise.

set -uo pipefail

healthy=true

# Check Envoy admin health endpoint
if ! curl -sf http://127.0.0.1:9901/ready >/dev/null 2>&1; then
    echo "UNHEALTHY: Envoy not ready (admin endpoint 127.0.0.1:9901/ready failed)"
    healthy=false
fi

# Check mitmproxy — verify process is running
# mitmdump does not have a built-in health endpoint, so we check the process
if ! pgrep -x mitmdump >/dev/null 2>&1; then
    echo "UNHEALTHY: mitmproxy (mitmdump) process not running"
    healthy=false
fi

# Check CoreDNS health endpoint
if ! curl -sf http://127.0.0.1:8180/health >/dev/null 2>&1; then
    echo "UNHEALTHY: CoreDNS not ready (health endpoint 127.0.0.1:8180/health failed)"
    healthy=false
fi

if [[ "$healthy" = true ]]; then
    echo "HEALTHY: all components running"
    exit 0
else
    exit 1
fi
