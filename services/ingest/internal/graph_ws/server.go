// HTTP upgrade handler for the graph_ws broadcaster (T1.4 — v8.0).
//
// The handler is intentionally minimal: tenant-scoped channels keyed
// off the ?tenant_id=<id> query param, no auth (auth is enforced
// by the Python API proxy at services/api/app/api/v1/endpoints/
// graph_ws.py — this server is expected to listen on the internal
// service network only). Each connection registers a Subscriber with
// the Broadcaster and pumps envelopes from the bounded buffer to the
// websocket until the client disconnects.
//
// We deliberately avoid pulling in github.com/gorilla/websocket or
// github.com/coder/websocket here — every new transitive dep on the
// ingest binary widens the security surface and slows the build. The
// graph-updates payload is JSON and clients are friendly browsers, so
// a tiny stdlib-only RFC6455 upgrade implementation is enough. If we
// ever need binary frames, compression, or ping/pong tuning, swap to
// a library; the surface this server exports is small.
package graph_ws

import (
	"crypto/sha1"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// wsHandshakeMagic is the fixed GUID from RFC 6455 §1.3 used to
// derive the Sec-WebSocket-Accept response header.
const wsHandshakeMagic = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

// writeTimeout caps a single frame write so a wedged TCP socket
// can't pin the dispatcher goroutine.
const writeTimeout = 5 * time.Second

// Server is the HTTP upgrade entry point. It is created once,
// registered on the ingest router, and serves every websocket
// upgrade against the same Broadcaster.
type Server struct {
	broker *Broadcaster
}

// NewServer pairs a Broadcaster with an HTTP handler.
func NewServer(broker *Broadcaster) *Server {
	return &Server{broker: broker}
}

// Handler returns an http.Handler that upgrades GET requests to a
// websocket and pumps tenant-scoped graph updates to the client.
//
// Path-level routing is left to the host router; this handler does
// not care which URL it lives at as long as the request method is
// GET and the WebSocket handshake headers are present.
func (s *Server) Handler() http.Handler {
	return http.HandlerFunc(s.handle)
}

func (s *Server) handle(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	tenantID := strings.TrimSpace(r.URL.Query().Get("tenant_id"))
	if tenantID == "" {
		tenantID = strings.TrimSpace(r.Header.Get("X-Tenant-ID"))
	}
	if tenantID == "" {
		http.Error(w, "tenant_id required", http.StatusBadRequest)
		return
	}

	if !isWebSocketHandshake(r) {
		http.Error(w, "websocket upgrade required", http.StatusBadRequest)
		return
	}

	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "websocket not supported", http.StatusInternalServerError)
		return
	}

	key := r.Header.Get("Sec-WebSocket-Key")
	if key == "" {
		http.Error(w, "missing Sec-WebSocket-Key", http.StatusBadRequest)
		return
	}

	conn, brw, err := hj.Hijack()
	if err != nil {
		http.Error(w, "hijack failed", http.StatusInternalServerError)
		return
	}
	defer conn.Close()

	accept := computeAcceptKey(key)
	resp := "HTTP/1.1 101 Switching Protocols\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Accept: " + accept + "\r\n" +
		"\r\n"
	if _, err := brw.WriteString(resp); err != nil {
		return
	}
	if err := brw.Flush(); err != nil {
		return
	}

	sub := s.broker.Subscribe(tenantID)
	defer s.broker.Unsubscribe(sub)

	// Reader goroutine: we don't expect inbound application messages,
	// but we must drain any frames the client sends (pings, close)
	// to detect disconnects and to keep the TCP read side draining.
	clientGone := make(chan struct{})
	go func() {
		defer close(clientGone)
		for {
			opcode, _, err := readFrame(brw.Reader)
			if err != nil {
				return
			}
			if opcode == 0x8 { // close
				return
			}
			// ignore text/binary/ping for now; pong is handled by
			// browsers automatically when we send pings, which we do
			// not currently do.
		}
	}()

	for {
		select {
		case <-r.Context().Done():
			return
		case <-clientGone:
			return
		case env, ok := <-sub.Updates:
			if !ok {
				return
			}
			payload, err := MarshalEnvelope(env)
			if err != nil {
				continue
			}
			if err := writeTextFrame(conn, brw, payload); err != nil {
				return
			}
		}
	}
}

func isWebSocketHandshake(r *http.Request) bool {
	if !headerContains(r.Header, "Connection", "upgrade") {
		return false
	}
	if !headerContains(r.Header, "Upgrade", "websocket") {
		return false
	}
	if r.Header.Get("Sec-WebSocket-Version") != "13" {
		return false
	}
	return true
}

func headerContains(h http.Header, key, value string) bool {
	values := h.Values(key)
	lv := strings.ToLower(value)
	for _, v := range values {
		for _, tok := range strings.Split(v, ",") {
			if strings.EqualFold(strings.TrimSpace(tok), lv) {
				return true
			}
			if strings.Contains(strings.ToLower(tok), lv) {
				return true
			}
		}
	}
	return false
}

func computeAcceptKey(key string) string {
	h := sha1.New()
	h.Write([]byte(key + wsHandshakeMagic))
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

// writeTextFrame encodes payload as a single unmasked text frame and
// flushes it through the buffered writer.
func writeTextFrame(deadlineConn deadlineSetter, brw bufferedWriterFlusher, payload []byte) error {
	if err := deadlineConn.SetWriteDeadline(time.Now().Add(writeTimeout)); err != nil {
		return err
	}
	header := []byte{0x81} // FIN + opcode=text
	plen := len(payload)
	switch {
	case plen <= 125:
		header = append(header, byte(plen))
	case plen <= 65535:
		header = append(header, 126)
		header = append(header, byte(plen>>8), byte(plen))
	default:
		header = append(header, 127)
		for i := 7; i >= 0; i-- {
			header = append(header, byte(plen>>(uint(i)*8)))
		}
	}
	if _, err := brw.Write(header); err != nil {
		return err
	}
	if _, err := brw.Write(payload); err != nil {
		return err
	}
	return brw.Flush()
}

// readFrame parses a single RFC6455 frame from r. We only need the
// opcode and the payload length on the client→server direction, but
// we still consume the payload so the buffered reader advances.
func readFrame(r io.Reader) (opcode byte, payload []byte, err error) {
	hdr := make([]byte, 2)
	if _, err = io.ReadFull(r, hdr); err != nil {
		return 0, nil, err
	}
	opcode = hdr[0] & 0x0F
	masked := hdr[1]&0x80 != 0
	plen := int64(hdr[1] & 0x7F)
	switch plen {
	case 126:
		ext := make([]byte, 2)
		if _, err = io.ReadFull(r, ext); err != nil {
			return 0, nil, err
		}
		plen = int64(ext[0])<<8 | int64(ext[1])
	case 127:
		ext := make([]byte, 8)
		if _, err = io.ReadFull(r, ext); err != nil {
			return 0, nil, err
		}
		plen = 0
		for i := 0; i < 8; i++ {
			plen = plen<<8 | int64(ext[i])
		}
	}
	var mask [4]byte
	if masked {
		if _, err = io.ReadFull(r, mask[:]); err != nil {
			return 0, nil, err
		}
	}
	if plen > 0 {
		payload = make([]byte, plen)
		if _, err = io.ReadFull(r, payload); err != nil {
			return 0, nil, err
		}
		if masked {
			for i := range payload {
				payload[i] ^= mask[i%4]
			}
		}
	}
	return opcode, payload, nil
}

// deadlineSetter is the subset of net.Conn we need for write
// timeouts. Extracted so tests can stub the underlying connection.
type deadlineSetter interface {
	SetWriteDeadline(t time.Time) error
}

// bufferedWriterFlusher is the subset of *bufio.ReadWriter we need.
type bufferedWriterFlusher interface {
	io.Writer
	Flush() error
}

// Errors exported for callers that want to distinguish failure modes.
var (
	ErrNoSubscribers = errors.New("graph_ws: no subscribers")
)

// String returns a one-line summary of broadcaster state. Used by
// the `/internal/graph_ws/stats` debug endpoint.
func (s *Server) String() string {
	return fmt.Sprintf("graph_ws: subscribers=%d dropped=%d",
		s.broker.SubscriberCount(),
		s.broker.DroppedDeliveries(),
	)
}
