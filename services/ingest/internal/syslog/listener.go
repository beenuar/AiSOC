package syslog

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/rs/zerolog/log"
)

// Sink receives parsed messages. An interface rather than the publisher so
// the listener can be tested without Kafka — and so the thing under test is
// the framing and the parse, which is where the defects are.
type Sink interface {
	Deliver(ctx context.Context, messages []*Message) error
}

// Config is one listener's worth of settings.
type Config struct {
	// UDPAddr and TCPAddr are host:port. An empty one disables that
	// transport; both empty is a configuration error rather than a silent
	// no-op, because a listener bound to nothing looks identical to a
	// listener nobody is sending to.
	UDPAddr string
	TCPAddr string

	// BatchSize and FlushInterval bound how long a message waits before it
	// is published. Syslog arrives one line at a time and publishing one
	// Kafka record per line is what makes a syslog receiver fall over, so
	// lines are batched — but a quiet source must not have its one message
	// held indefinitely, which is what the interval is for.
	BatchSize     int
	FlushInterval time.Duration

	// MaxConnections caps concurrent TCP sessions. Without it, anything
	// that can open sockets can exhaust the process's file descriptors and
	// take the HTTP ingest path down with it.
	MaxConnections int

	// ReadTimeout closes a TCP connection that has sent nothing for this
	// long. A forwarder that disappears without a FIN otherwise holds its
	// slot until the process restarts.
	ReadTimeout time.Duration
}

func (c Config) withDefaults() Config {
	if c.BatchSize <= 0 {
		c.BatchSize = 500
	}
	if c.FlushInterval <= 0 {
		c.FlushInterval = 2 * time.Second
	}
	if c.MaxConnections <= 0 {
		c.MaxConnections = 256
	}
	if c.ReadTimeout <= 0 {
		c.ReadTimeout = 5 * time.Minute
	}
	return c
}

var (
	syslogMessages = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "aisoc_ingest_syslog_messages_total",
			Help: "Syslog messages received, by transport and parsed format.",
		},
		[]string{"transport", "format"},
	)
	syslogRejected = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "aisoc_ingest_syslog_rejected_total",
			Help: "Syslog lines that could not be accepted, by transport and reason.",
		},
		[]string{"transport", "reason"},
	)
	syslogConnections = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "aisoc_ingest_syslog_tcp_connections",
			Help: "Open syslog TCP connections.",
		},
	)
)

// Listener accepts syslog over UDP and TCP and hands parsed messages to a
// Sink in batches.
type Listener struct {
	cfg  Config
	sink Sink

	udp *net.UDPConn
	tcp net.Listener

	mu       sync.Mutex
	pending  []*Message
	health   State
	wg       sync.WaitGroup
	connSlot chan struct{}
	// done is closed by Stop. The flush loop watches it as well as the
	// caller's context, because Stop waits on the goroutines and a loop
	// that only watches a context the caller has not cancelled yet never
	// returns — a deadlock on the shutdown path, which is the one path
	// nobody exercises until production.
	done     chan struct{}
	stopOnce sync.Once
}

// State is what readiness reports. A listener that is bound and a listener
// that failed to bind are indistinguishable from outside unless the state
// is named, and "nothing has arrived" is the normal condition for a syslog
// receiver, so silence proves nothing either way.
type State struct {
	UDPBound     bool
	TCPBound     bool
	UDPAddr      string
	TCPAddr      string
	LastError    string
	Received     uint64
	Rejected     uint64
	LastDelivery time.Time
}

// New binds the configured transports. Binding is done here rather than in
// Start so a port already in use is a startup error an operator sees,
// not a goroutine that exits into a log line nobody reads.
func New(cfg Config, sink Sink) (*Listener, error) {
	cfg = cfg.withDefaults()
	if cfg.UDPAddr == "" && cfg.TCPAddr == "" {
		return nil, errors.New("syslog: neither UDP nor TCP address configured; set at least one or leave the listener disabled")
	}
	if sink == nil {
		return nil, errors.New("syslog: no sink")
	}

	l := &Listener{cfg: cfg, sink: sink, connSlot: make(chan struct{}, cfg.MaxConnections), done: make(chan struct{})}

	if cfg.UDPAddr != "" {
		addr, err := net.ResolveUDPAddr("udp", cfg.UDPAddr)
		if err != nil {
			return nil, fmt.Errorf("syslog: resolving UDP address %q: %w", cfg.UDPAddr, err)
		}
		conn, err := net.ListenUDP("udp", addr)
		if err != nil {
			return nil, fmt.Errorf("syslog: binding UDP %q: %w (a port below 1024 needs a capability or a published container port)", cfg.UDPAddr, err)
		}
		l.udp = conn
		l.health.UDPBound = true
		l.health.UDPAddr = conn.LocalAddr().String()
	}

	if cfg.TCPAddr != "" {
		conn, err := net.Listen("tcp", cfg.TCPAddr)
		if err != nil {
			if l.udp != nil {
				_ = l.udp.Close()
			}
			return nil, fmt.Errorf("syslog: binding TCP %q: %w (a port below 1024 needs a capability or a published container port)", cfg.TCPAddr, err)
		}
		l.tcp = conn
		l.health.TCPBound = true
		l.health.TCPAddr = conn.Addr().String()
	}
	return l, nil
}

// Addrs reports what was actually bound, which is not what was configured
// when the port was `:0`.
func (l *Listener) Addrs() (udp string, tcp string) {
	return l.health.UDPAddr, l.health.TCPAddr
}

// Health is a snapshot for the readiness endpoint.
func (l *Listener) Health() State {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.health
}

// Start runs until ctx is cancelled.
func (l *Listener) Start(ctx context.Context) {
	if l.udp != nil {
		l.wg.Add(1)
		go func() {
			defer l.wg.Done()
			l.readUDP(ctx)
		}()
	}
	if l.tcp != nil {
		l.wg.Add(1)
		go func() {
			defer l.wg.Done()
			l.acceptTCP(ctx)
		}()
	}
	l.wg.Add(1)
	go func() {
		defer l.wg.Done()
		l.flushLoop(ctx)
	}()
}

// Stop closes the sockets and drains what is already buffered.
func (l *Listener) Stop(ctx context.Context) {
	l.stopOnce.Do(func() { close(l.done) })
	if l.udp != nil {
		_ = l.udp.Close()
	}
	if l.tcp != nil {
		_ = l.tcp.Close()
	}
	l.wg.Wait()
	l.flush(ctx)
}

func (l *Listener) readUDP(ctx context.Context) {
	buf := make([]byte, MaxLineBytes)
	for {
		if ctx.Err() != nil || l.stopping() {
			return
		}
		n, _, err := l.udp.ReadFromUDP(buf)
		if err != nil {
			if isClosed(err) || ctx.Err() != nil || l.stopping() {
				return
			}
			// A read error on a bound UDP socket is almost always
			// transient (an ICMP port-unreachable from a previous send).
			// Logged rather than fatal, and the loop continues, because
			// exiting here detaches the listener while the socket stays
			// bound — the shape that makes a dead consumer look idle.
			log.Warn().Err(err).Str("transport", "udp").Msg("syslog: read error, continuing")
			syslogRejected.WithLabelValues("udp", "read_error").Inc()
			continue
		}
		// One datagram is one message. A datagram carrying several
		// newline-separated lines is non-standard but common from
		// relays, so it is split.
		for _, line := range strings.Split(string(buf[:n]), "\n") {
			l.ingest(ctx, "udp", line)
		}
	}
}

func (l *Listener) acceptTCP(ctx context.Context) {
	for {
		conn, err := l.tcp.Accept()
		if err != nil {
			if isClosed(err) || ctx.Err() != nil || l.stopping() {
				return
			}
			log.Warn().Err(err).Msg("syslog: accept error, continuing")
			continue
		}
		select {
		case l.connSlot <- struct{}{}:
		default:
			// At the connection cap. Refused immediately and counted,
			// because silently holding the socket open would look to the
			// forwarder like a working receiver that never acknowledges.
			syslogRejected.WithLabelValues("tcp", "too_many_connections").Inc()
			log.Warn().Int("max", l.cfg.MaxConnections).Msg("syslog: refusing connection, at the configured cap")
			_ = conn.Close()
			continue
		}
		syslogConnections.Inc()
		l.wg.Add(1)
		go func() {
			defer l.wg.Done()
			defer func() { <-l.connSlot; syslogConnections.Dec() }()
			l.readTCPConn(ctx, conn)
		}()
	}
}

// readTCPConn reads one session, handling both framings RFC 6587 defines.
//
// Octet-counting (`123 <34>1 ...`) is the one the RFC recommends and the
// one that works when a message contains a newline. Non-transparent framing
// (LF-delimited) is what most senders actually use. A receiver has to read
// both, and it decides per message by looking at whether the next thing on
// the wire is a digit run followed by a space.
func (l *Listener) readTCPConn(ctx context.Context, conn net.Conn) {
	defer func() { _ = conn.Close() }()
	reader := bufio.NewReaderSize(conn, 64*1024)

	for {
		if ctx.Err() != nil || l.stopping() {
			return
		}
		if err := conn.SetReadDeadline(time.Now().Add(l.cfg.ReadTimeout)); err != nil {
			return
		}

		line, err := l.readFrame(reader)
		if err != nil {
			if !errors.Is(err, io.EOF) && !isClosed(err) && ctx.Err() == nil {
				var netErr net.Error
				if errors.As(err, &netErr) && netErr.Timeout() {
					log.Debug().Msg("syslog: closing an idle TCP connection")
				} else {
					syslogRejected.WithLabelValues("tcp", "frame_error").Inc()
					log.Warn().Err(err).Msg("syslog: framing error, closing connection")
				}
			}
			return
		}
		l.ingest(ctx, "tcp", line)
	}
}

func (l *Listener) readFrame(reader *bufio.Reader) (string, error) {
	peeked, err := reader.Peek(1)
	if err != nil {
		return "", err
	}
	if peeked[0] < '0' || peeked[0] > '9' {
		line, err := reader.ReadString('\n')
		if err != nil && line == "" {
			return "", err
		}
		return strings.TrimRight(line, "\r\n"), nil
	}

	// Octet-counting: MSG-LEN SP SYSLOG-MSG.
	var digits strings.Builder
	for {
		b, err := reader.ReadByte()
		if err != nil {
			return "", err
		}
		if b == ' ' {
			break
		}
		if b < '0' || b > '9' {
			// Not a length prefix after all — a message that happens to
			// start with a digit. Put the byte back and read to newline.
			if err := reader.UnreadByte(); err != nil {
				return "", err
			}
			rest, err := reader.ReadString('\n')
			if err != nil && rest == "" {
				return "", err
			}
			return digits.String() + strings.TrimRight(rest, "\r\n"), nil
		}
		digits.WriteByte(b)
		if digits.Len() > 10 {
			return "", fmt.Errorf("syslog: octet count %q is not a plausible length", digits.String())
		}
	}
	length, err := strconv.Atoi(digits.String())
	if err != nil || length < 0 {
		return "", fmt.Errorf("syslog: unreadable octet count %q", digits.String())
	}
	if length > MaxLineBytes {
		return "", fmt.Errorf("syslog: framed message of %d bytes is over the %d cap", length, MaxLineBytes)
	}
	buf := make([]byte, length)
	if _, err := io.ReadFull(reader, buf); err != nil {
		return "", err
	}
	return string(buf), nil
}

func (l *Listener) ingest(ctx context.Context, transport, line string) {
	msg, err := Parse(line)
	if err != nil {
		if !errors.Is(err, ErrEmpty) {
			syslogRejected.WithLabelValues(transport, "parse_error").Inc()
			l.mu.Lock()
			l.health.Rejected++
			l.health.LastError = err.Error()
			l.mu.Unlock()
		}
		return
	}
	syslogMessages.WithLabelValues(transport, string(msg.Format)).Inc()

	l.mu.Lock()
	l.pending = append(l.pending, msg)
	l.health.Received++
	full := len(l.pending) >= l.cfg.BatchSize
	l.mu.Unlock()

	if full {
		l.flush(ctx)
	}
}

func (l *Listener) flushLoop(ctx context.Context) {
	ticker := time.NewTicker(l.cfg.FlushInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-l.done:
			return
		case <-ticker.C:
			l.flush(ctx)
		}
	}
}

// Flush publishes whatever is buffered. Exported so a test can drive the
// boundary directly rather than sleeping on the interval.
func (l *Listener) Flush(ctx context.Context) { l.flush(ctx) }

func (l *Listener) flush(ctx context.Context) {
	l.mu.Lock()
	if len(l.pending) == 0 {
		l.mu.Unlock()
		return
	}
	batch := l.pending
	l.pending = nil
	l.mu.Unlock()

	if err := l.sink.Deliver(ctx, batch); err != nil {
		// Counted and named. Not re-queued: syslog is a fire-and-forget
		// transport with no acknowledgement to withhold, so a sender has
		// already moved on and holding the batch would only grow the
		// buffer until the process dies. Saying so is the honest part —
		// the alternative is a receiver that loses messages silently.
		syslogRejected.WithLabelValues("sink", "publish_error").Add(float64(len(batch)))
		l.mu.Lock()
		l.health.Rejected += uint64(len(batch))
		l.health.LastError = err.Error()
		l.mu.Unlock()
		log.Error().Err(err).Int("dropped", len(batch)).
			Msg("syslog: publish failed; these messages are lost because syslog has no acknowledgement to withhold")
		return
	}
	l.mu.Lock()
	l.health.LastDelivery = time.Now().UTC()
	l.mu.Unlock()
}

func (l *Listener) stopping() bool {
	select {
	case <-l.done:
		return true
	default:
		return false
	}
}

func isClosed(err error) bool {
	return errors.Is(err, net.ErrClosed) || errors.Is(err, io.EOF)
}
