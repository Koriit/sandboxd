// Package sandboxpolicy: synchronous DNS-policy gate client.
//
// The gate provides happens-before ordering between CoreDNS's answer
// emission and sandboxd's nft / Envoy LDS propagation: the plugin
// emits a `propagate_and_ack` request over a per-session Unix domain
// socket and blocks on the daemon's ack until success or a wall-clock
// deadline. On deadline the plugin fails OPEN (releases the response)
// and emits a `dns_gate_timed_out` structured event so operators can
// detect the regression — the alternative (failing closed on the
// happy path) would punch a hole in DNS resolution every time a
// transient daemon hiccup exceeds the deadline.
//
// Wire format mirrors the daemon-side Rust implementation in
// `sandbox-core/src/dns_gate.rs`: snake_case JSON, length-prefixed
// by a trailing `\n`. One request → one ack, one connection per
// request (the listener spawns a per-connection task).
package sandboxpolicy

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"sync"
	"time"
)

// gateProtocolVersion mirrors `GATE_PROTOCOL_VERSION` on the daemon
// side. Bumping it requires a coordinated change on both ends; the
// daemon rejects mismatched versions with a `protocol_error`.
const gateProtocolVersion = 1

// defaultGateDeadline mirrors the Rust `DEFAULT_DEADLINE_MS`. Picked
// as a balance between letting nft + Envoy LDS finish their reload
// (typical <250ms) and not stalling DNS responses indefinitely.
const defaultGateDeadline = 1500 * time.Millisecond

// gateRequestKindPropagate is the only request kind the daemon
// currently understands; future kinds (e.g. revalidate, drain) would
// follow the same shape.
const gateRequestKindPropagate = "propagate_and_ack"

// gateRequest is the JSON shape sent over the wire. Field order
// matches the Rust `GateRequest` struct so a side-by-side diff stays
// readable.
type gateRequest struct {
	Kind          string   `json:"kind"`
	Version       uint32   `json:"version"`
	CorrelationID string   `json:"correlation_id"`
	Domain        string   `json:"domain"`
	QType         string   `json:"qtype"`
	IPs           []string `json:"ips"`
	TTLSeconds    uint32   `json:"ttl_seconds"`
	DeadlineMS    uint64   `json:"deadline_ms"`
}

// gateAck is the response shape. The daemon may instead return a
// `propagate_error` envelope — both are surfaced via the same
// connection write, with `kind` discriminating. The plugin handles
// the error envelope as a degenerate ack (status: protocol_error).
type gateAck struct {
	Kind          string `json:"kind"`
	Version       uint32 `json:"version"`
	CorrelationID string `json:"correlation_id"`
	Status        string `json:"status,omitempty"`
	ElapsedMS     uint64 `json:"elapsed_ms"`
	Reason        string `json:"reason,omitempty"`
	// Error envelope fields (filled when Kind == "propagate_error").
	Code    string `json:"code,omitempty"`
	Message string `json:"message,omitempty"`
}

// gateOutcome is the plugin-internal classification of a single gate
// round-trip. Used as the event-emitter discriminator and (in the
// caller) the fail-open/fail-closed decision branch.
type gateOutcome int

const (
	// gateOutcomeOK: daemon acked status="ok" or "noop" — release the answer.
	gateOutcomeOK gateOutcome = iota
	// gateOutcomeRejected: daemon explicitly refused to propagate. The
	// caller should still release the answer to avoid creating a
	// resolution gap, but operators see a `dns_gate_rejected` event.
	gateOutcomeRejected
	// gateOutcomeTimedOut: deadline fired before the ack arrived.
	// Fail-open per spec.
	gateOutcomeTimedOut
	// gateOutcomeProtocolError: daemon returned an error envelope
	// (unsupported_version, malformed_request, etc.).
	gateOutcomeProtocolError
	// gateOutcomeUnknown: transport-level error connecting / reading
	// the daemon socket. Treat as fail-open with the same loud
	// emission as a timeout.
	gateOutcomeUnknown
)

// String renders an outcome for log lines.
func (o gateOutcome) String() string {
	switch o {
	case gateOutcomeOK:
		return "ok"
	case gateOutcomeRejected:
		return "rejected"
	case gateOutcomeTimedOut:
		return "timed_out"
	case gateOutcomeProtocolError:
		return "protocol_error"
	default:
		return "unknown"
	}
}

// gateClient is the plugin-side counterparty to the daemon's
// `serve_gate_listener`. One client instance is created per CoreDNS
// process (the gateway container hosts exactly one CoreDNS) and
// reused across all queries.
type gateClient struct {
	socketPath      string
	defaultDeadline time.Duration

	mu  sync.Mutex
	seq uint64 // Monotonic counter for default correlation IDs.
}

// newGateClient constructs a gate client targeting socketPath. An
// empty socketPath disables the gate (every Submit call short-circuits
// to gateOutcomeOK), so plugin-Corefile can omit the directive
// entirely without breaking the run.
func newGateClient(socketPath string, defaultDeadline time.Duration) *gateClient {
	if defaultDeadline <= 0 {
		defaultDeadline = defaultGateDeadline
	}
	return &gateClient{
		socketPath:      socketPath,
		defaultDeadline: defaultDeadline,
	}
}

// disabled reports whether the gate client is configured. Used by
// callers to skip request construction altogether when the directive
// was omitted.
func (c *gateClient) disabled() bool {
	return c == nil || c.socketPath == ""
}

// nextCorrelationID hands out monotonically increasing correlation
// IDs of the form `c<seq>`. Plugin-side log lines and daemon-side
// telemetry use these for join-by-key debugging.
func (c *gateClient) nextCorrelationID() string {
	c.mu.Lock()
	c.seq++
	id := c.seq
	c.mu.Unlock()
	return fmt.Sprintf("c%d", id)
}

// Submit drives one gate round-trip with the configured wall-clock
// deadline. Returns the outcome class plus the parsed ack for
// telemetry purposes. The caller is responsible for emitting any
// structured event — Submit only does the IPC.
//
// The connection is established lazily per request: the gate sees
// at most one query-rate's worth of ops (typically <100/s for an
// agent's working set), the daemon listener spawns a per-connection
// task anyway, and pinning a long-lived connection would force us
// to multiplex acks back to the right Submit call. Per-request
// connections sidestep that complexity.
func (c *gateClient) Submit(ctx context.Context, req *gateRequest) (gateOutcome, *gateAck) {
	if c.disabled() {
		return gateOutcomeOK, nil
	}
	if req.CorrelationID == "" {
		req.CorrelationID = c.nextCorrelationID()
	}
	if req.Version == 0 {
		req.Version = gateProtocolVersion
	}
	if req.Kind == "" {
		req.Kind = gateRequestKindPropagate
	}
	if req.DeadlineMS == 0 {
		req.DeadlineMS = uint64(c.defaultDeadline / time.Millisecond)
	}

	deadline := time.Now().Add(time.Duration(req.DeadlineMS) * time.Millisecond)

	conn, err := dialUnixWithDeadline(ctx, c.socketPath, deadline)
	if err != nil {
		return gateOutcomeUnknown, &gateAck{
			CorrelationID: req.CorrelationID,
			Reason:        fmt.Sprintf("dial: %v", err),
		}
	}
	defer conn.Close()

	// Hard deadline on the entire round-trip. The daemon is supposed
	// to enforce its own deadline server-side too (via tokio::time::
	// timeout in `serve_gate_listener`), but a belt-and-braces deadline
	// here protects against a wedged daemon that never returns.
	if err := conn.SetDeadline(deadline); err != nil {
		return gateOutcomeUnknown, &gateAck{
			CorrelationID: req.CorrelationID,
			Reason:        fmt.Sprintf("set deadline: %v", err),
		}
	}

	// Encode + write request. json.Encoder.Encode appends '\n', which
	// is exactly the framing the daemon's `read_line` expects.
	if err := json.NewEncoder(conn).Encode(req); err != nil {
		if isTimeoutErr(err) {
			return gateOutcomeTimedOut, &gateAck{
				CorrelationID: req.CorrelationID,
				Reason:        fmt.Sprintf("write: %v", err),
			}
		}
		return gateOutcomeUnknown, &gateAck{
			CorrelationID: req.CorrelationID,
			Reason:        fmt.Sprintf("write: %v", err),
		}
	}

	// Read one line from the daemon. bufio.Reader.ReadBytes('\n')
	// matches the daemon's frame boundary.
	br := bufio.NewReader(conn)
	line, err := br.ReadBytes('\n')
	if err != nil {
		if isTimeoutErr(err) {
			return gateOutcomeTimedOut, &gateAck{
				CorrelationID: req.CorrelationID,
				Reason:        fmt.Sprintf("read: %v", err),
			}
		}
		return gateOutcomeUnknown, &gateAck{
			CorrelationID: req.CorrelationID,
			Reason:        fmt.Sprintf("read: %v", err),
		}
	}

	var ack gateAck
	if err := json.Unmarshal(line, &ack); err != nil {
		return gateOutcomeProtocolError, &gateAck{
			CorrelationID: req.CorrelationID,
			Reason:        fmt.Sprintf("unmarshal: %v", err),
		}
	}

	switch ack.Kind {
	case "propagate_ack":
		switch ack.Status {
		case "ok", "noop":
			return gateOutcomeOK, &ack
		case "rejected", "unknown_session":
			return gateOutcomeRejected, &ack
		default:
			return gateOutcomeProtocolError, &ack
		}
	case "propagate_error":
		return gateOutcomeProtocolError, &ack
	default:
		return gateOutcomeProtocolError, &ack
	}
}

// dialUnixWithDeadline is a thin wrapper around net.DialUnix that
// honours both the request context and the wall-clock deadline. Either
// cancellation source yields a "timeout" classification at the caller.
func dialUnixWithDeadline(ctx context.Context, socketPath string, deadline time.Time) (net.Conn, error) {
	d := net.Dialer{Deadline: deadline}
	return d.DialContext(ctx, "unix", socketPath)
}

// isTimeoutErr reports whether err is a deadline-fired error.
// net.OpError's Timeout() returns true for SetDeadline-derived
// failures; a context.DeadlineExceeded wrap path is also covered.
func isTimeoutErr(err error) bool {
	if err == nil {
		return false
	}
	type timeoutErr interface{ Timeout() bool }
	if t, ok := err.(timeoutErr); ok && t.Timeout() {
		return true
	}
	return false
}
