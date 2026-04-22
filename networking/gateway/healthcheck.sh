#!/usr/bin/env bash
#
# Gateway container health check
# Checks all four pipeline components. Exits 0 if all healthy, 1 otherwise.

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

# Check sandbox-deny-logger health endpoint.
#
# The listener is bound on the gateway bridge IP (see entrypoint:
# `--bind-ip ${GATEWAY_IP}`), not 127.0.0.1 — PREROUTING DNAT to
# loopback is dropped as a martian destination unless
# `route_localnet=1` is set, which the gateway container does not
# set (spec 2026-04-21 Part 3 / "Listener design / Bind address").
# The probe therefore has to go through the bridge IP. Discover it
# the same way the entrypoint does (`hostname -i`, first address) so
# the two scripts stay consistent.
#
# A non-200 here means a listener task has exited or failed to bind;
# Docker's HEALTHCHECK treats the non-zero exit as unhealthy, and
# sandboxd's gateway poller restarts the container (spec Part 3 /
# "Liveness posture" — observability of denials is a hard invariant,
# no degraded mode).
GATEWAY_IP_FOR_HEALTH="$(hostname -i | awk '{print $1}')"
if [[ -z "${GATEWAY_IP_FOR_HEALTH}" ]] \
    || ! curl -sf "http://${GATEWAY_IP_FOR_HEALTH}:10003/health" >/dev/null 2>&1; then
    echo "UNHEALTHY: sandbox-deny-logger not ready (health endpoint ${GATEWAY_IP_FOR_HEALTH:-<unknown>}:10003/health failed)"
    healthy=false
fi

if [[ "$healthy" = true ]]; then
    echo "HEALTHY: all components running"
    exit 0
else
    exit 1
fi
