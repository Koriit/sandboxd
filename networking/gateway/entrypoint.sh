#!/usr/bin/env bash
#
# Gateway container entrypoint
# Starts mitmproxy, Envoy, and CoreDNS in the design-specified order,
# waits for readiness, then monitors all processes.
#
# Startup order (per networking-design.md § Component lifecycle):
#   1. mitmproxy  (must be ready before Envoy, which forwards to it)
#   2. Envoy      (must be ready before DNS, which triggers resolution)
#   3. CoreDNS    (last — completing the pipeline)
#
# nftables rules are managed externally by sandboxd, not by this script.
#
# If any process exits, this script logs the failure and exits non-zero
# so Docker can restart the container.

set -euo pipefail

LOG_DIR="${LOG_DIR:-/var/log/gateway}"
READY_TIMEOUT="${READY_TIMEOUT:-30}"

# Ensure the log directory exists (tmpfs mounts wipe it out).
mkdir -p "${LOG_DIR}"

# PIDs of managed processes
MITM_PID=""
ENVOY_PID=""
COREDNS_PID=""

log() {
    echo "[gateway] $(date -u '+%Y-%m-%dT%H:%M:%SZ') $*"
}

# ── Signal handling ──────────────────────────────────────────────────

shutdown_all() {
    log "Shutting down components..."
    # Shutdown order (reverse of startup): CoreDNS, Envoy, mitmproxy
    for pid_var in COREDNS_PID ENVOY_PID MITM_PID; do
        local pid="${!pid_var}"
        if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
            log "Sending SIGTERM to ${pid_var}=${pid}"
            kill -TERM "$pid" 2>/dev/null || true
        fi
    done

    # Wait for all to exit (up to 10 seconds total)
    local deadline=$((SECONDS + 10))
    for pid_var in COREDNS_PID ENVOY_PID MITM_PID; do
        local pid="${!pid_var}"
        if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
            local remaining=$((deadline - SECONDS))
            if [[ $remaining -gt 0 ]]; then
                timeout "$remaining" tail --pid="$pid" -f /dev/null 2>/dev/null || true
            fi
            if kill -0 "$pid" 2>/dev/null; then
                log "Force-killing ${pid_var}=${pid}"
                kill -KILL "$pid" 2>/dev/null || true
            fi
        fi
    done
    log "All components stopped."
}

on_signal() {
    log "Received shutdown signal."
    shutdown_all
    exit 0
}

trap on_signal SIGTERM SIGINT SIGQUIT

# ── Readiness checks ────────────────────────────────────────────────

wait_for_ready() {
    local name="$1"
    local check_cmd="$2"
    local timeout_secs="${3:-$READY_TIMEOUT}"
    local deadline=$((SECONDS + timeout_secs))

    log "Waiting for ${name} to become ready (timeout=${timeout_secs}s)..."
    while [[ $SECONDS -lt $deadline ]]; do
        if eval "$check_cmd" >/dev/null 2>&1; then
            log "${name} is ready."
            return 0
        fi
        sleep 1
    done
    log "ERROR: ${name} failed to become ready within ${timeout_secs}s"
    return 1
}

# ── Start mitmproxy ─────────────────────────────────────────────────

log "Starting mitmproxy (mitmdump) on 127.0.0.1:8080..."
mitmdump \
    --mode regular \
    --listen-host 127.0.0.1 \
    --listen-port 8080 \
    --set stream_large_bodies=1 \
    -s /etc/mitmproxy/passthrough_addon.py \
    >>"${LOG_DIR}/mitmproxy.log" 2>&1 &
MITM_PID=$!
log "mitmproxy started (PID=${MITM_PID})"

# mitmdump has no health endpoint; check that the process is alive and
# the port is open. The port check is the real readiness signal.
wait_for_ready "mitmproxy" \
    "kill -0 ${MITM_PID} 2>/dev/null && bash -c '</dev/tcp/127.0.0.1/8080' 2>/dev/null"

# ── Start Envoy ─────────────────────────────────────────────────────

log "Starting Envoy..."
envoy \
    -c /etc/envoy/envoy.yaml \
    --log-level warning \
    --log-path "${LOG_DIR}/envoy.log" \
    &
ENVOY_PID=$!
log "Envoy started (PID=${ENVOY_PID})"

wait_for_ready "Envoy" "curl -sf http://127.0.0.1:9901/ready"

# ── Start CoreDNS ───────────────────────────────────────────────────

log "Starting CoreDNS..."
coredns \
    -conf /etc/coredns/Corefile \
    >>"${LOG_DIR}/coredns.log" 2>&1 &
COREDNS_PID=$!
log "CoreDNS started (PID=${COREDNS_PID})"

wait_for_ready "CoreDNS" "curl -sf http://127.0.0.1:8180/health"

# ── All components running ──────────────────────────────────────────

log "All components are running and healthy."
log "  mitmproxy  PID=${MITM_PID}  (127.0.0.1:8080)"
log "  Envoy      PID=${ENVOY_PID}  (0.0.0.0:10000, admin 127.0.0.1:9901)"
log "  CoreDNS    PID=${COREDNS_PID}  (DNS :53, health :8180)"

# ── Monitor processes ───────────────────────────────────────────────
# Wait for any child to exit. If any managed process dies, log and exit
# so Docker's restart policy can handle recovery.

while true; do
    for pid_var in MITM_PID ENVOY_PID COREDNS_PID; do
        local_pid="${!pid_var}"
        if [[ -n "$local_pid" ]] && ! kill -0 "$local_pid" 2>/dev/null; then
            # Process is gone. Retrieve exit code.
            set +e
            wait "$local_pid" 2>/dev/null
            exit_code=$?
            set -e
            log "FATAL: ${pid_var} (PID=${local_pid}) exited with code ${exit_code}"
            shutdown_all
            exit 1
        fi
    done
    # Sleep briefly between polls. Signals (SIGTERM etc.) interrupt sleep.
    sleep 2 &
    wait $! 2>/dev/null || true
done
