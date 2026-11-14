package syslog

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

// recordingSink captures what the listener delivers. Deliberately less
// capable than the real one: it cannot invent a tenant, cannot normalise,
// and fails when told to — which is the only way to see what the listener
// does with a failed publish.
type recordingSink struct {
	mu       sync.Mutex
	messages []*Message
	fail     error
	delivers int
}

func (s *recordingSink) Deliver(_ context.Context, messages []*Message) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.delivers++
	if s.fail != nil {
		return s.fail
	}
	s.messages = append(s.messages, messages...)
	return nil
}

func (s *recordingSink) snapshot() []*Message {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]*Message(nil), s.messages...)
}

// disabled is the empty address, named so a test reads as "this transport
// is off" rather than as a typo.
const disabled = ""

func newTestListener(t *testing.T, sink Sink, cfg Config) *Listener {
	t.Helper()
	if cfg.UDPAddr == "" && cfg.TCPAddr == "" {
		cfg.UDPAddr = "127.0.0.1:0"
		cfg.TCPAddr = "127.0.0.1:0"
	}
	if cfg.FlushInterval == 0 {
		cfg.FlushInterval = 20 * time.Millisecond
	}
	l, err := New(cfg, sink)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return l
}

func waitFor(t *testing.T, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("condition was not met within 3s")
}

func TestABindFailureIsAStartupErrorNotASilentNoOp(t *testing.T) {
	// A listener that failed to bind and a listener nobody is sending to
	// are indistinguishable from outside, which is why binding happens in
	// New and reports rather than in a goroutine that exits into a log.
	first := newTestListener(t, &recordingSink{}, Config{TCPAddr: "127.0.0.1:0", UDPAddr: disabled})
	_, tcp := first.Addrs()
	defer first.Stop(context.Background())

	_, err := New(Config{TCPAddr: tcp}, &recordingSink{})
	if err == nil {
		t.Fatal("binding an address already in use should be an error")
	}
	if !strings.Contains(err.Error(), "binding TCP") {
		t.Errorf("error should name the transport and the address: %v", err)
	}
}

func TestNoTransportAtAllIsRefused(t *testing.T) {
	if _, err := New(Config{}, &recordingSink{}); err == nil {
		t.Fatal("a listener bound to nothing should be refused, not started")
	}
}

func TestUDPDatagramsAreParsedAndDelivered(t *testing.T) {
	sink := &recordingSink{}
	l := newTestListener(t, sink, Config{UDPAddr: "127.0.0.1:0", TCPAddr: disabled})
	udp, _ := l.Addrs()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	l.Start(ctx)
	defer l.Stop(context.Background())

	conn, err := net.Dial("udp", udp)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = conn.Close() }()
	if _, err := conn.Write([]byte("<34>Oct 11 22:14:15 mymachine su: failed for lonvick")); err != nil {
		t.Fatalf("write: %v", err)
	}

	waitFor(t, func() bool { return len(sink.snapshot()) == 1 })
	got := sink.snapshot()[0]
	if got.Hostname != "mymachine" || got.AppName != "su" {
		t.Errorf("parsed wrong: %#v", got)
	}
}

func TestTCPReadsNonTransparentFraming(t *testing.T) {
	// LF-delimited. Not what RFC 6587 recommends, and what almost every
	// sender actually does.
	sink := &recordingSink{}
	l := newTestListener(t, sink, Config{TCPAddr: "127.0.0.1:0", UDPAddr: disabled})
	_, tcp := l.Addrs()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	l.Start(ctx)
	defer l.Stop(context.Background())

	conn, err := net.Dial("tcp", tcp)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = conn.Close() }()
	_, _ = conn.Write([]byte("<13>Oct 11 22:14:15 web01 sshd[1]: one\n<13>Oct 11 22:14:16 web01 sshd[2]: two\n"))

	waitFor(t, func() bool { return len(sink.snapshot()) == 2 })
	if got := sink.snapshot()[1].ProcID; got != "2" {
		t.Errorf("second message pid = %q, want 2", got)
	}
}

func TestTCPReadsOctetCounting(t *testing.T) {
	// RFC 6587 §3.4.1. The framing that exists because a message may
	// legitimately contain a newline — which an LF-framed reader splits
	// into two records, one of them nonsense.
	sink := &recordingSink{}
	l := newTestListener(t, sink, Config{TCPAddr: "127.0.0.1:0", UDPAddr: disabled})
	_, tcp := l.Addrs()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	l.Start(ctx)
	defer l.Stop(context.Background())

	conn, err := net.Dial("tcp", tcp)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = conn.Close() }()
	payload := "<13>Oct 11 22:14:15 web01 app: line one\nline two"
	_, _ = conn.Write([]byte(fmt.Sprintf("%d %s", len(payload), payload)))

	waitFor(t, func() bool { return len(sink.snapshot()) == 1 })
	if got := sink.snapshot()[0].Message; got != "line one\nline two" {
		t.Errorf("message = %q; octet-counted framing must not split on the newline", got)
	}
}

func TestAMessageStartingWithADigitIsNotMistakenForALengthPrefix(t *testing.T) {
	// The framing is decided per message by peeking at one byte, so a
	// non-framed line whose first character is a digit has to fall back to
	// LF framing rather than consuming the rest of the stream as payload.
	sink := &recordingSink{}
	l := newTestListener(t, sink, Config{TCPAddr: "127.0.0.1:0", UDPAddr: disabled})
	_, tcp := l.Addrs()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	l.Start(ctx)
	defer l.Stop(context.Background())

	conn, err := net.Dial("tcp", tcp)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = conn.Close() }()
	_, _ = conn.Write([]byte("2026-10-08 something happened\n"))

	waitFor(t, func() bool { return len(sink.snapshot()) == 1 })
	if got := sink.snapshot()[0].Message; got != "2026-10-08 something happened" {
		t.Errorf("message = %q", got)
	}
}

func TestAnImplausibleOctetCountClosesTheConnection(t *testing.T) {
	// The length comes off the wire. A reader that trusts it allocates
	// whatever a hostile or broken sender asks for.
	sink := &recordingSink{}
	l := newTestListener(t, sink, Config{TCPAddr: "127.0.0.1:0", UDPAddr: disabled})
	_, tcp := l.Addrs()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	l.Start(ctx)
	defer l.Stop(context.Background())

	conn, err := net.Dial("tcp", tcp)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = conn.Close() }()
	_, _ = conn.Write([]byte("99999999 hello"))

	// The connection is closed rather than the allocation made.
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 1)
	if _, err := conn.Read(buf); err == nil {
		t.Error("the connection should have been closed")
	}
	if len(sink.snapshot()) != 0 {
		t.Error("nothing should have been delivered")
	}
}

func TestTheBatchIsFlushedOnSizeAndOnTime(t *testing.T) {
	// Publishing one Kafka record per syslog line is what makes a receiver
	// fall over; holding a quiet source's single message forever is the
	// other failure. Both are tested because fixing one usually breaks the
	// other.
	sink := &recordingSink{}
	l := newTestListener(t, sink, Config{UDPAddr: "127.0.0.1:0", TCPAddr: disabled, BatchSize: 3, FlushInterval: 30 * time.Millisecond})
	udp, _ := l.Addrs()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	l.Start(ctx)
	defer l.Stop(context.Background())

	conn, err := net.Dial("udp", udp)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = conn.Close() }()
	for i := 0; i < 3; i++ {
		_, _ = conn.Write([]byte(fmt.Sprintf("<13>Oct 11 22:14:1%d web01 app: n%d", i, i)))
	}
	waitFor(t, func() bool { return len(sink.snapshot()) == 3 })

	// One more, on its own: it must not wait for a fourth that never comes.
	_, _ = conn.Write([]byte("<13>Oct 11 22:14:19 web01 app: lonely"))
	waitFor(t, func() bool { return len(sink.snapshot()) == 4 })
}

func TestAFailedPublishIsCountedRatherThanSilent(t *testing.T) {
	// Syslog has no acknowledgement to withhold, so a failed publish is a
	// lost message no matter what this does. What it must not do is lose it
	// quietly: the rejected counter and the readiness detail are the only
	// evidence an operator will ever get.
	sink := &recordingSink{fail: errors.New("kafka unreachable")}
	l := newTestListener(t, sink, Config{UDPAddr: "127.0.0.1:0", TCPAddr: disabled, BatchSize: 1})
	udp, _ := l.Addrs()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	l.Start(ctx)
	defer l.Stop(context.Background())

	conn, err := net.Dial("udp", udp)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = conn.Close() }()
	_, _ = conn.Write([]byte("<13>Oct 11 22:14:15 web01 app: hello"))

	waitFor(t, func() bool { return l.Health().Rejected > 0 })
	if detail := l.Health().LastError; !strings.Contains(detail, "kafka unreachable") {
		t.Errorf("readiness detail = %q; it must name the failure", detail)
	}
}

func TestReadinessNamesWhatIsBound(t *testing.T) {
	// "attached" alone is a lie of omission for a receiver that is
	// legitimately silent for hours.
	l := newTestListener(t, &recordingSink{}, Config{UDPAddr: "127.0.0.1:0", TCPAddr: "127.0.0.1:0"})
	defer l.Stop(context.Background())

	state := l.Health()
	if !state.UDPBound || !state.TCPBound {
		t.Fatalf("both transports should report bound: %#v", state)
	}
	if state.UDPAddr == "" || state.TCPAddr == "" {
		t.Error("readiness should report the address actually bound, which is not the one configured when the port was :0")
	}
}

func TestTheConnectionCapIsEnforced(t *testing.T) {
	// Without it, anything that can open sockets exhausts the process's
	// file descriptors and takes the HTTP ingest path down with it.
	sink := &recordingSink{}
	l := newTestListener(t, sink, Config{TCPAddr: "127.0.0.1:0", UDPAddr: disabled, MaxConnections: 1})
	_, tcp := l.Addrs()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	l.Start(ctx)
	defer l.Stop(context.Background())

	first, err := net.Dial("tcp", tcp)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = first.Close() }()
	// Give the accept loop time to take the only slot.
	_, _ = first.Write([]byte("<13>Oct 11 22:14:15 web01 app: one\n"))
	waitFor(t, func() bool { return len(sink.snapshot()) == 1 })

	second, err := net.Dial("tcp", tcp)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = second.Close() }()
	_ = second.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 1)
	if _, err := second.Read(buf); err == nil {
		t.Error("the second connection should have been refused immediately rather than held open")
	}
}
