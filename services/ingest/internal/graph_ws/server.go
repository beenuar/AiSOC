// HTTP upgrade handler for the graph_ws broadcaster (T1.4 — v8.0).
//
// Each connection registers a Subscriber with the Broadcaster and pumps
// envelopes from the bounded buffer to the websocket until the client
// disconnects. The tenant that scopes those envelopes comes from the
// caller's credential, resolved by the same internal/ingestauth
// authenticator /v1/ingest runs.
//
// This comment previously said the handler took its tenant from a
// ?tenant_id=<id> query parameter and ran "no auth (auth is enforced by
// the Python API proxy ... this server is expected to listen on the
// internal service network only)". Both halves of that were a problem,
// and they were different problems:
//
//   - The proxy's authentication is real — services/api/app/api/v1/
//     endpoints/graph_ws.py resolves a JWT or API key, enforces
//     graph:read, and rebinds the tenant from the resolved user. It is
//     still only defence in depth, because nothing made it the *only*
//     way in. The root docker-compose.yml publishes this service's
//     port, so "listens on the internal service network" was an
//     assumption about somebody else's deployment, asserted here and
//     enforced nowhere.
//   - A tenant read out of the query string is a tenant the caller
//     chose. That is the one rule this codebase does not bend: the
//     scope has to come from the credential. The parameter is gone
//     rather than validated, because a parameter that looks
//     authoritative and is not is how it grows a reader again.
//
// So the handler authenticates first and derives the tenant from the
// resulting Principal. A browser still cannot reach this directly — it
// has no service token and cannot set headers on a WebSocket open — and
// the proxy remains the public entry point. It now presents a
// credential like every other internal caller instead of being trusted
// because of where it sits.
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

	"github.com/beenuar/aisoc/services/ingest/internal/ingestauth"
	"github.com/rs/zerolog/log"
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
	auth   *ingestauth.Authenticator
}

// NewServer pairs a Broadcaster with an HTTP handler.
//
// The server starts with no authenticator, which refuses every
// connection. Call SetAuthenticator to make it usable.
func NewServer(broker *Broadcaster) *Server {
	return &Server{broker: broker}
}

// SetAuthenticator wires in the credential check.
//
// Same contract as handler.SetAuthenticator, and for the same reason:
// nil is not a "feature disabled" signal. A nil *ingestauth.Authenticator
// refuses every connection, so a wiring regression closes this stream
// instead of opening it. There is no flag that turns the check off.
func (s *Server) SetAuthenticator(a *ingestauth.Authenticator) {
	s.auth = a
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
	// Authenticate before answering anything else about this service.
	// The credential is what decides the tenant, so nothing below can
	// run without it, and an unauthenticated caller should not learn
	// the broadcaster's health or whether its handshake was well formed.
	identity, authErr := s.auth.Authenticate(r.Context(), r)
	if authErr != nil {
		writeAuthError(w, r, authErr)
		return
	}

	// Intersection only, exactly as /v1/ingest does it. The tenant
	// header is honoured where it agrees with what the credential
	// authorises — that is how the API proxy names the tenant it is
	// relaying for — and naming any other tenant narrows the scope to
	// nothing and is refused here. There is deliberately no query
	// parameter in this path.
	tenantUUID, scopeErr := ingestauth.Resolve(identity.Principal, s.auth.DeclaredTenant(r))
	if scopeErr != nil {
		declared := strings.ReplaceAll(strings.ReplaceAll(s.auth.DeclaredTenant(r), "\r", ""), "\n", " ")
		if len(declared) > 128 {
			declared = declared[:128]
		}
		log.Warn().
			Str("subject", identity.Principal.Subject).
			Str("requested_tenant", declared).
			Bool("delegated", identity.Principal.Delegated).
			Msg("graph_ws: refused a subscription outside the credential's tenant scope")
		http.Error(w, scopeErr.Error(), http.StatusForbidden)
		return
	}
	tenantID := tenantUUID.String()

	if !isWebSocketHandshake(r) {
		http.Error(w, "websocket upgrade required", http.StatusBadRequest)
		return
	}

	// Refuse rather than complete a handshake onto a socket that will stay
	// silent. A client connected to a broadcaster whose source is detached
	// gets an open connection and no envelopes, which looks exactly like a
	// quiet estate — the same indistinguishability that made the consumer
	// defect invisible in the first place. The endpoint that depends on the
	// subscription is the right place to report on it, and 503 with the
	// reason lets a caller retry or escalate instead of waiting forever.
	if health := s.broker.Health(); !health.Healthy() {
		w.Header().Set("Retry-After", "30")
		http.Error(w, "graph_ws unavailable: "+health.Reason(), http.StatusServiceUnavailable)
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

// writeAuthError renders an *ingestauth.Error with its own status.
// Anything that is not one is reported as 401 rather than leaking an
// internal message to an unauthenticated caller.
//
// The refusal is an ordinary HTTP response, never a completed handshake
// followed by a close frame: a client that was upgraded and then closed
// cannot tell "refused" from "the estate is quiet", which is the same
// indistinguishability the 503 below exists to avoid.
func writeAuthError(w http.ResponseWriter, r *http.Request, err error) {
	var authErr *ingestauth.Error
	status, msg := http.StatusUnauthorized, "unauthorized"
	if errors.As(err, &authErr) {
		status, msg = authErr.Status, authErr.Msg
	}
	// CR/LF stripped and length bounded inline at the call site: the
	// taint tracker does not follow a helper across the boundary, and
	// both of these are caller-controlled.
	remote := strings.ReplaceAll(strings.ReplaceAll(r.RemoteAddr, "\r", ""), "\n", " ")
	if len(remote) > 128 {
		remote = remote[:128]
	}
	log.Warn().
		Int("status", status).
		Str("remote_addr", remote).
		Msg("graph_ws: refused an unauthenticated or unauthorized subscription")
	http.Error(w, msg, status)
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
//
// Source state is included because subscriber and drop counts describe the
// fan-out only: both read identically whether the topic is quiet or the
// consumer is detached from it.
func (s *Server) String() string {
	health := s.broker.Health()
	return fmt.Sprintf("graph_ws: subscribers=%d dropped=%d attached=%t not_resolving=%t",
		s.broker.SubscriberCount(),
		s.broker.DroppedDeliveries(),
		health.Attached,
		health.NotResolving,
	)
}
