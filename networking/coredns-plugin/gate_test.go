package sandboxpolicy

import (
	"bufio"
	"context"
	"encoding/json"
	"net"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// stubGateServer is a minimal Unix-domain-socket counterparty for the
// real `serve_gate_listener` daemon. It listens for one connection at
// a time, reads exactly one length-prefixed JSON line, and replies
// with whatever the test configured.
type stubGateServer struct {
	listener net.Listener
	wg       sync.WaitGroup

	// reply controls what the server writes back. If `withholdAck` is
	// true the server reads the request but never replies — used to
	// drive the client's deadline branch.
	reply       gateAck
	withholdAck bool

	// captured records the most recent request the server saw so
	// tests can pin field shape on the wire.
	mu       sync.Mutex
	captured *gateRequest
}

func newStubGateServer(t *testing.T) (*stubGateServer, string) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "gate.sock")
	l, err := net.Listen("unix", path)
	if err != nil {
		t.Fatalf("listen unix: %v", err)
	}
	s := &stubGateServer{listener: l}
	return s, path
}

func (s *stubGateServer) Start() {
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		for {
			conn, err := s.listener.Accept()
			if err != nil {
				return
			}
			s.handle(conn)
		}
	}()
}

func (s *stubGateServer) handle(conn net.Conn) {
	defer conn.Close()
	br := bufio.NewReader(conn)
	line, err := br.ReadBytes('\n')
	if err != nil {
		return
	}
	var req gateRequest
	if json.Unmarshal(line, &req) == nil {
		s.mu.Lock()
		s.captured = &req
		s.mu.Unlock()
	}
	if s.withholdAck {
		// Hold the connection open without replying. The client's
		// SetDeadline drives the timeout branch.
		time.Sleep(2 * time.Second)
		return
	}
	// Default reply uses the captured correlation_id when set so the
	// client's correlation-roundtrip pinning works without per-test
	// wiring.
	reply := s.reply
	if reply.CorrelationID == "" {
		reply.CorrelationID = req.CorrelationID
	}
	if reply.Version == 0 {
		reply.Version = gateProtocolVersion
	}
	if reply.Kind == "" {
		reply.Kind = "propagate_ack"
	}
	enc := json.NewEncoder(conn)
	_ = enc.Encode(&reply)
}

func (s *stubGateServer) Captured() *gateRequest {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.captured
}

func (s *stubGateServer) Close() {
	_ = s.listener.Close()
	s.wg.Wait()
}

// TestGateClientHonoursAckOk: the happy path. Client sends a
// propagate_and_ack, server replies with status: ok, client returns
// gateOutcomeOK and a populated ack.
func TestGateClientHonoursAckOk(t *testing.T) {
	srv, path := newStubGateServer(t)
	srv.reply = gateAck{Status: "ok", ElapsedMS: 17}
	srv.Start()
	defer srv.Close()

	client := newGateClient(path, 500*time.Millisecond)
	req := &gateRequest{
		Domain:     "example.com",
		QType:      "A",
		IPs:        []string{"203.0.113.1", "203.0.113.2"},
		TTLSeconds: 60,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	outcome, ack := client.Submit(ctx, req)
	if outcome != gateOutcomeOK {
		t.Fatalf("expected gateOutcomeOK, got %v (reason=%q)", outcome, func() string {
			if ack != nil {
				return ack.Reason
			}
			return ""
		}())
	}
	if ack.Status != "ok" {
		t.Fatalf("expected status=ok, got %q", ack.Status)
	}

	cap := srv.Captured()
	if cap == nil {
		t.Fatal("server did not capture a request")
	}
	if cap.Kind != "propagate_and_ack" {
		t.Errorf("expected kind=propagate_and_ack, got %q", cap.Kind)
	}
	if cap.Version != gateProtocolVersion {
		t.Errorf("expected version=%d, got %d", gateProtocolVersion, cap.Version)
	}
	if cap.CorrelationID == "" {
		t.Error("client must assign a correlation_id when none was provided")
	}
	if cap.Domain != "example.com" {
		t.Errorf("domain mismatch: got %q", cap.Domain)
	}
	if cap.QType != "A" {
		t.Errorf("qtype mismatch: got %q", cap.QType)
	}
	if len(cap.IPs) != 2 || cap.IPs[0] != "203.0.113.1" || cap.IPs[1] != "203.0.113.2" {
		t.Errorf("ips mismatch: got %v", cap.IPs)
	}
	if cap.TTLSeconds != 60 {
		t.Errorf("ttl mismatch: got %d", cap.TTLSeconds)
	}
	if cap.DeadlineMS == 0 {
		t.Error("client must populate deadline_ms with the configured default when none was supplied")
	}
}

// TestGateClientFailsClosedOnRejected: the daemon explicitly refuses
// to propagate. The client must surface gateOutcomeRejected so the
// caller can emit the corresponding structured event. (Caller-side
// fail-open is independent of this — it's a higher-level decision in
// WriteMsg, not a transport concern.)
func TestGateClientFailsClosedOnRejected(t *testing.T) {
	srv, path := newStubGateServer(t)
	srv.reply = gateAck{Status: "rejected", Reason: "nft inject failed: bad set"}
	srv.Start()
	defer srv.Close()

	client := newGateClient(path, 500*time.Millisecond)
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	outcome, ack := client.Submit(ctx, &gateRequest{
		Domain: "rejected.example.com",
		QType:  "A",
		IPs:    []string{"198.51.100.1"},
	})
	if outcome != gateOutcomeRejected {
		t.Fatalf("expected gateOutcomeRejected, got %v", outcome)
	}
	if ack == nil || ack.Reason == "" {
		t.Fatal("rejected ack must surface reason")
	}
}

// TestGateClientReleasesResponseOnTimeout: the server reads but never
// replies; the client must hit its wall-clock deadline and return
// gateOutcomeTimedOut. This is the spec's fail-open path — the
// caller releases the response without the daemon's ack.
func TestGateClientReleasesResponseOnTimeout(t *testing.T) {
	srv, path := newStubGateServer(t)
	srv.withholdAck = true
	srv.Start()
	defer srv.Close()

	client := newGateClient(path, 100*time.Millisecond)
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	start := time.Now()
	outcome, ack := client.Submit(ctx, &gateRequest{
		Domain: "slow.example.com",
		QType:  "A",
		IPs:    []string{"203.0.113.55"},
	})
	elapsed := time.Since(start)
	if outcome != gateOutcomeTimedOut {
		t.Fatalf("expected gateOutcomeTimedOut, got %v (reason=%q)", outcome, func() string {
			if ack != nil {
				return ack.Reason
			}
			return ""
		}())
	}
	// The client's wall-clock deadline is 100ms; we allow a generous
	// CI-tolerant ceiling.
	if elapsed > 1500*time.Millisecond {
		t.Errorf("Submit took %v; deadline should fire in ~100ms", elapsed)
	}
}

// TestGateClientDisabledShortCircuitsToOK: when no socket path is
// configured the client never dials and returns ok unconditionally.
// This is the fail-safe for daemons that haven't enabled the
// synchronous DNS-policy gate.
func TestGateClientDisabledShortCircuitsToOK(t *testing.T) {
	client := newGateClient("", 0)
	if !client.disabled() {
		t.Fatal("empty socket path should mark client disabled")
	}
	outcome, _ := client.Submit(context.Background(), &gateRequest{
		Domain: "anything.example.com",
	})
	if outcome != gateOutcomeOK {
		t.Fatalf("disabled client must short-circuit to ok, got %v", outcome)
	}
}

// TestGateClientHandlesUnknownSession: daemon returns a
// `unknown_session` ack — the listener exists but the daemon has no
// policy installed for the calling session (yet). The client maps
// this to gateOutcomeRejected so the caller emits the right
// structured event but still releases the answer (caller-side
// fail-open).
func TestGateClientHandlesUnknownSession(t *testing.T) {
	srv, path := newStubGateServer(t)
	srv.reply = gateAck{Status: "unknown_session"}
	srv.Start()
	defer srv.Close()

	client := newGateClient(path, 500*time.Millisecond)
	outcome, ack := client.Submit(context.Background(), &gateRequest{
		Domain: "x.example.com",
		QType:  "A",
		IPs:    []string{"203.0.113.99"},
	})
	if outcome != gateOutcomeRejected {
		t.Fatalf("expected gateOutcomeRejected for unknown_session, got %v", outcome)
	}
	if ack.Status != "unknown_session" {
		t.Fatalf("ack status passthrough broken: got %q", ack.Status)
	}
}

// TestGateClientHandlesProtocolError: daemon replies with a
// `propagate_error` envelope. The client returns
// gateOutcomeProtocolError so the caller logs it loudly and fails
// open.
func TestGateClientHandlesProtocolError(t *testing.T) {
	srv, path := newStubGateServer(t)
	srv.reply = gateAck{
		Kind:    "propagate_error",
		Code:    "unsupported_version",
		Message: "version 99 not supported",
	}
	srv.Start()
	defer srv.Close()

	client := newGateClient(path, 500*time.Millisecond)
	outcome, ack := client.Submit(context.Background(), &gateRequest{
		Domain: "x.example.com",
		QType:  "A",
		IPs:    []string{"203.0.113.7"},
	})
	if outcome != gateOutcomeProtocolError {
		t.Fatalf("expected gateOutcomeProtocolError, got %v", outcome)
	}
	if ack.Code != "unsupported_version" {
		t.Errorf("error code passthrough broken: got %q", ack.Code)
	}
}
