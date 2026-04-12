#!/usr/bin/env bash
# Integration test: starts sandboxd, runs sandbox CLI commands, verifies responses,
# sends SIGTERM, and verifies clean shutdown.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
SOCKET_PATH="/tmp/test-sandboxd-$$.sock"
DAEMON_PID=""

cleanup() {
    if [[ -n "$DAEMON_PID" ]] && kill -0 "$DAEMON_PID" 2>/dev/null; then
        kill "$DAEMON_PID" 2>/dev/null || true
        wait "$DAEMON_PID" 2>/dev/null || true
    fi
    rm -f "$SOCKET_PATH"
}
trap cleanup EXIT

echo "=== Integration Test: sandboxd + sandbox CLI ==="

# Build in release mode for faster startup
echo "Building workspace..."
cd "$WORKSPACE_DIR"
cargo build --workspace --quiet 2>&1

SANDBOXD="$WORKSPACE_DIR/target/debug/sandboxd"
SANDBOX="$WORKSPACE_DIR/target/debug/sandbox"

# Ensure binaries exist
if [[ ! -x "$SANDBOXD" ]]; then
    echo "FAIL: sandboxd binary not found at $SANDBOXD"
    exit 1
fi
if [[ ! -x "$SANDBOX" ]]; then
    echo "FAIL: sandbox binary not found at $SANDBOX"
    exit 1
fi

# Remove stale socket if present
rm -f "$SOCKET_PATH"

# Start the daemon in the background
echo "Starting sandboxd on $SOCKET_PATH..."
RUST_LOG=info "$SANDBOXD" --socket "$SOCKET_PATH" &
DAEMON_PID=$!

# Wait for the socket to appear (up to 5 seconds)
for i in $(seq 1 50); do
    if [[ -S "$SOCKET_PATH" ]]; then
        break
    fi
    sleep 0.1
done

if [[ ! -S "$SOCKET_PATH" ]]; then
    echo "FAIL: socket file did not appear within 5 seconds"
    exit 1
fi
echo "  Daemon started (PID $DAEMON_PID)"

# Test: list sessions (ps)
echo "Testing 'sandbox ps'..."
OUTPUT=$("$SANDBOX" --socket "$SOCKET_PATH" ps 2>&1)
if echo "$OUTPUT" | grep -q '"error"'; then
    echo "  OK: got expected error response: $OUTPUT"
else
    echo "  FAIL: unexpected output: $OUTPUT"
    exit 1
fi
if echo "$OUTPUT" | grep -q 'not implemented'; then
    echo "  OK: 501 not implemented response confirmed"
else
    echo "  FAIL: expected 'not implemented' in response"
    exit 1
fi

# Test: list sessions (ls, alias)
echo "Testing 'sandbox ls'..."
OUTPUT=$("$SANDBOX" --socket "$SOCKET_PATH" ls 2>&1)
if echo "$OUTPUT" | grep -q 'not implemented'; then
    echo "  OK: ls alias works correctly"
else
    echo "  FAIL: ls alias unexpected output: $OUTPUT"
    exit 1
fi

# Test: create session
echo "Testing 'sandbox create'..."
OUTPUT=$("$SANDBOX" --socket "$SOCKET_PATH" create 2>&1)
if echo "$OUTPUT" | grep -q 'not implemented'; then
    echo "  OK: create returns not implemented"
else
    echo "  FAIL: create unexpected output: $OUTPUT"
    exit 1
fi

# Test: create session with name
echo "Testing 'sandbox create --name mybox'..."
OUTPUT=$("$SANDBOX" --socket "$SOCKET_PATH" create --name mybox 2>&1)
if echo "$OUTPUT" | grep -q 'not implemented'; then
    echo "  OK: create with name returns not implemented"
else
    echo "  FAIL: create with name unexpected output: $OUTPUT"
    exit 1
fi

# Test: start session
echo "Testing 'sandbox start test-id'..."
OUTPUT=$("$SANDBOX" --socket "$SOCKET_PATH" start test-id 2>&1)
if echo "$OUTPUT" | grep -q 'not implemented'; then
    echo "  OK: start returns not implemented"
else
    echo "  FAIL: start unexpected output: $OUTPUT"
    exit 1
fi

# Test: stop session
echo "Testing 'sandbox stop test-id'..."
OUTPUT=$("$SANDBOX" --socket "$SOCKET_PATH" stop test-id 2>&1)
if echo "$OUTPUT" | grep -q 'not implemented'; then
    echo "  OK: stop returns not implemented"
else
    echo "  FAIL: stop unexpected output: $OUTPUT"
    exit 1
fi

# Test: rm session
echo "Testing 'sandbox rm test-id'..."
OUTPUT=$("$SANDBOX" --socket "$SOCKET_PATH" rm test-id 2>&1)
if echo "$OUTPUT" | grep -q 'not implemented'; then
    echo "  OK: rm returns not implemented"
else
    echo "  FAIL: rm unexpected output: $OUTPUT"
    exit 1
fi

# Test: graceful shutdown via SIGTERM
echo "Testing graceful shutdown..."
kill -TERM "$DAEMON_PID"

# Wait for process to exit (up to 5 seconds)
for i in $(seq 1 50); do
    if ! kill -0 "$DAEMON_PID" 2>/dev/null; then
        break
    fi
    sleep 0.1
done

if kill -0 "$DAEMON_PID" 2>/dev/null; then
    echo "  FAIL: daemon did not exit after SIGTERM within 5 seconds"
    kill -9 "$DAEMON_PID" 2>/dev/null || true
    exit 1
fi

wait "$DAEMON_PID" 2>/dev/null
EXIT_CODE=$?
DAEMON_PID=""
echo "  OK: daemon exited cleanly (exit code: $EXIT_CODE)"

# Verify socket file is cleaned up
if [[ -S "$SOCKET_PATH" ]]; then
    echo "  WARN: socket file still exists after shutdown (non-fatal)"
else
    echo "  OK: socket file cleaned up after shutdown"
fi

# Test: CLI connection error when daemon is not running
echo "Testing CLI error when daemon is down..."
OUTPUT=$("$SANDBOX" --socket "$SOCKET_PATH" ps 2>&1 || true)
if echo "$OUTPUT" | grep -qi 'cannot connect\|connection refused\|no such file'; then
    echo "  OK: CLI reports helpful error when daemon is not running"
else
    echo "  FAIL: expected connection error, got: $OUTPUT"
    exit 1
fi

echo ""
echo "=== All integration tests passed ==="
