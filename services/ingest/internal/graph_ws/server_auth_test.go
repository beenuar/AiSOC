// server_auth_test.go — the credential check on the graph-update WebSocket.
//
// These tests exist because the upgrade handler used to have no
// authentication at all. It took the tenant from a ?tenant_id= query
// parameter and subscribed the caller to that tenant's graph stream,
// relying on a deployment assumption written in a comment: that the port
// would only ever be reachable from the internal service network. The
// root docker-compose.yml publishes it, so the assumption was about
// somebody else's deployment rather than about the code.
//
// The load-bearing property is therefore not "a credentialled caller can
// subscribe" but "a credential for one tenant cannot read another
// tenant's stream", so that is what most of this file asserts — and it
// asserts it by watching for the envelope itself, not by watching the
// handshake. A refusal that still delivered the envelope would be worse
// than no refusal, because it would look fixed.
//
// Every cross-tenant case first proves the target tenant's stream is
// genuinely live, by delivering an envelope to a subscriber that is
// legitimately scoped to it. Without that, "no envelope arrived" is
// indistinguishable from a broadcaster that was never publishing, and
// the test would keep passing if the scope check were deleted.
package graph_ws

import (
	"bufio"
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/beenuar/aisoc/services/ingest/internal/graph"
	"github.com/beenuar/aisoc/services/ingest/internal/inbox"
	"github.com/beenuar/aisoc/services/ingest/internal/ingestauth"
	"github.com/google/uuid"
)

// ── two tenants ────────────────────────────────────────────────────────
//
// "acme" is the caller. "umbra" is the outsider — the tenant acme must
// not be able to read.

const (
	acmeTenantWS  = "11111111-1111-4111-8111-111111111111"
	umbraTenantWS = "22222222-2222-4222-8222-222222222222"
)

// pushSource is an EnvelopeSource a test can feed after a subscriber has
// connected. newFakeSource in broadcaster_test.go pre-loads its channel,
// which races the handshake; the cross-tenant assertion needs the
// envelope published strictly after the client is subscribed or "nothing
// arrived" would just mean "nothing was sent yet".
type pushSource struct {
	ch     chan graph.GraphUpdate
	closed chan struct{}
}

func newPushSource() *pushSource {
	return &pushSource{ch: make(chan graph.GraphUpdate, 8), closed: make(chan struct{})}
}

func (p *pushSource) Next(ctx context.Context) (graph.GraphUpdate, error) {
	select {
	case e := <-p.ch:
		return e, nil
	case <-ctx.Done():
		return graph.GraphUpdate{}, ctx.Err()
	case <-p.closed:
		return graph.GraphUpdate{}, context.Canceled
	}
}

func (p *pushSource) Close() error {
	select {
	case <-p.closed:
	default:
		close(p.closed)
	}
	return nil
}

func (p *pushSource) publish(tenant, entity string) {
	p.ch <- graph.GraphUpdate{
		EntityID:      entity,
		ChangeType:    graph.ChangeUpsertNode,
		TS:            time.Now(),
		Label:         graph.NodeAlert,
		TenantID:      tenant,
		SchemaVersion: graph.SchemaVersion,
	}
}

// liveBroadcaster returns a started broadcaster whose health reads
// attached, so the upgrade handler's 503 guard does not stand in for the
// credential check we are actually measuring.
func liveBroadcaster(t *testing.T) (*Broadcaster, *pushSource) {
	t.Helper()
	src := newPushSource()
	health := NewSourceState("test.graph_updates", 0)
	health.MarkAttached()
	b := New(src, Options{BufferSize: 16, Health: health})
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	b.Start(ctx)
	t.Cleanup(b.Stop)
	return b, src
}

// wsServer mounts the handler at the real route so a path change cannot
// silently move the surface out from under these tests.
func wsServer(t *testing.T, s *Server) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.Handle("/v1/graph_ws/stream", s.Handler())
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// dialWS performs a raw RFC6455 upgrade. We speak the handshake by hand
// rather than pulling in a client library, for the same reason the server
// does: the dependency is not worth it for one GET and one frame read.
//
// Returns the status line plus, on a successful upgrade, the live
// connection and its buffered reader.
func dialWS(t *testing.T, srv *httptest.Server, query string, headers map[string]string) (string, net.Conn, *bufio.Reader) {
	t.Helper()
	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatalf("parse server URL: %v", err)
	}
	conn, err := net.Dial("tcp", u.Host)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	path := "/v1/graph_ws/stream"
	if query != "" {
		path += "?" + query
	}
	var b strings.Builder
	b.WriteString("GET " + path + " HTTP/1.1\r\n")
	b.WriteString("Host: " + u.Host + "\r\n")
	b.WriteString("Upgrade: websocket\r\n")
	b.WriteString("Connection: Upgrade\r\n")
	b.WriteString("Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n")
	b.WriteString("Sec-WebSocket-Version: 13\r\n")
	for k, v := range headers {
		b.WriteString(k + ": " + v + "\r\n")
	}
	b.WriteString("\r\n")

	if err := conn.SetWriteDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("set write deadline: %v", err)
	}
	if _, err := conn.Write([]byte(b.String())); err != nil {
		t.Fatalf("write handshake: %v", err)
	}

	if err := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("set read deadline: %v", err)
	}
	br := bufio.NewReader(conn)
	status, err := br.ReadString('\n')
	if err != nil {
		t.Fatalf("read status line: %v", err)
	}
	status = strings.TrimSpace(status)

	// Drain the remaining response headers so the reader is positioned at
	// the first frame on an upgraded connection.
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			t.Fatalf("read headers: %v", err)
		}
		if strings.TrimSpace(line) == "" {
			break
		}
	}
	if !strings.Contains(status, "101") {
		return status, nil, nil
	}
	return status, conn, br
}

// awaitSubscribers blocks until the broadcaster has registered want
// subscribers.
//
// The handler writes the 101 response *before* it calls Subscribe, so a
// test that publishes as soon as it has read the status line is racing
// the registration — and this is a live tail with no replay, so an
// envelope published into zero subscribers is simply gone. That cost a
// CI run as a flaky positive, but the negative cases are the reason
// this helper is not optional: "no envelope arrived" would otherwise
// pass whenever the subscriber had not registered yet, which is a pass
// for entirely the wrong reason.
func awaitSubscribers(t *testing.T, b *Broadcaster, want int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if b.SubscriberCount() >= want {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("broadcaster registered %d subscriber(s), want %d", b.SubscriberCount(), want)
}

// awaitEnvelope reads one text frame, or reports that none arrived inside
// the window. The boolean is the whole assertion in the cross-tenant
// cases, so it must distinguish "nothing was sent" from "the read failed"
// — a connection the server closed is a refusal, not a delivery.
func awaitEnvelope(t *testing.T, conn net.Conn, br *bufio.Reader, window time.Duration) (string, bool) {
	t.Helper()
	if err := conn.SetReadDeadline(time.Now().Add(window)); err != nil {
		t.Fatalf("set read deadline: %v", err)
	}
	opcode, payload, err := readFrame(br)
	if err != nil {
		return "", false
	}
	if opcode != 0x1 {
		return "", false
	}
	return string(payload), true
}

// TestGraphWSRefusesAnUncredentialledConnection is the reporter's first
// proof of concept: connect with no token at all.
//
// On the tree this test was written against the handler answered 101 and
// began streaming, because the only thing it asked for was a tenant_id in
// the query string. A server constructed with no authenticator must
// refuse — nil is not a "feature disabled" signal on a write-adjacent
// surface, the same posture handler.SetAuthenticator documents.
func TestGraphWSRefusesAnUncredentialledConnection(t *testing.T) {
	b, _ := liveBroadcaster(t)
	srv := wsServer(t, NewServer(b))

	status, _, _ := dialWS(t, srv, "tenant_id="+acmeTenantWS, nil)

	if strings.Contains(status, "101") {
		t.Fatalf("an uncredentialled caller was upgraded onto the graph stream: %q", status)
	}
	t.Logf("uncredentialled connection refused with: %s", status)
}

// TestGraphWSQueryStringTenantGrantsNoStream is the reporter's second and
// sharpest proof of concept, reduced to its load-bearing half: naming a
// tenant in the query string must not deliver that tenant's envelopes.
//
// The positive control runs first and is what makes the negative half
// mean anything: a subscriber legitimately scoped to umbra receives the
// envelope, proving the stream is live and the envelope really was
// published, before we assert that the query-string caller does not
// receive it.
func TestGraphWSQueryStringTenantGrantsNoStream(t *testing.T) {
	b, src := liveBroadcaster(t)

	// Positive control: umbra's stream is genuinely live.
	control := b.Subscribe(umbraTenantWS)
	defer b.Unsubscribe(control)
	src.publish(umbraTenantWS, "control-entity")
	select {
	case env := <-control.Updates:
		if env.EntityID != "control-entity" {
			t.Fatalf("control subscriber got the wrong envelope: %+v", env)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("control subscriber received nothing; the broadcaster is not publishing, " +
			"so a later 'no envelope arrived' would prove nothing")
	}

	srv := wsServer(t, NewServer(b))
	status, conn, br := dialWS(t, srv, "tenant_id="+umbraTenantWS, nil)
	if !strings.Contains(status, "101") {
		t.Logf("query-string tenant refused at the handshake: %s", status)
		return
	}

	// The handshake succeeded, so the only remaining question is whether
	// umbra's envelopes reach this socket. Wait for the registration
	// before publishing: the control above is subscriber 1, so this
	// connection is subscriber 2, and publishing before it exists would
	// make the assertion below pass without testing anything.
	awaitSubscribers(t, b, 2)
	src.publish(umbraTenantWS, "leaked-entity")
	payload, got := awaitEnvelope(t, conn, br, 2*time.Second)
	if got {
		t.Fatalf("an uncredentialled caller naming ?tenant_id=%s in the query string received "+
			"that tenant's graph envelope: %s", umbraTenantWS, payload)
	}
}

// ── credentialled cases ────────────────────────────────────────────────

// fakeTokens is an in-memory stand-in for inbox.Store, mirroring the one
// in handler/ingest_auth_test.go.
type fakeTokens struct{ rows map[string]*inbox.Token }

func (f *fakeTokens) Resolve(_ context.Context, token string) (*inbox.Token, error) {
	row, ok := f.rows[token]
	if !ok {
		return nil, inbox.ErrTokenNotFound
	}
	return row, nil
}

type fakeTenants struct{ active map[uuid.UUID]bool }

func (f *fakeTenants) IsActive(_ context.Context, id uuid.UUID) (bool, error) {
	return f.active[id], nil
}

const acmeWSToken = "aitnb_acme_graph_token_aaaaaaaaaa"

// authenticatedWSServer wires the same authenticator /v1/ingest runs,
// with acme holding a connector-push token and both tenants active.
// Shared with source_health_test.go, whose route test has to get past
// the credential check to reach the health refusal it is about.
func authenticatedWSServer(t *testing.T, b *Broadcaster) *Server {
	t.Helper()
	tokens := &fakeTokens{rows: map[string]*inbox.Token{
		acmeWSToken: {
			Token:      acmeWSToken,
			TenantID:   uuid.MustParse(acmeTenantWS),
			TemplateID: ingestauth.PushTemplateID,
		},
	}}
	tenants := &fakeTenants{active: map[uuid.UUID]bool{
		uuid.MustParse(acmeTenantWS):  true,
		uuid.MustParse(umbraTenantWS): true,
	}}
	s := NewServer(b)
	s.SetAuthenticator(ingestauth.New(tokens, tenants, "", ""))
	return s
}

func authenticatedServer(t *testing.T, b *Broadcaster) *httptest.Server {
	t.Helper()
	return wsServer(t, authenticatedWSServer(t, b))
}

// TestGraphWSDeliversTheCredentialsOwnTenant is the positive control for
// the whole file. Everything else asserts a refusal, and a handler that
// refused unconditionally would satisfy all of them.
func TestGraphWSDeliversTheCredentialsOwnTenant(t *testing.T) {
	b, src := liveBroadcaster(t)
	srv := authenticatedServer(t, b)

	status, conn, br := dialWS(t, srv, "", map[string]string{
		"Authorization": "Bearer " + acmeWSToken,
	})
	if !strings.Contains(status, "101") {
		t.Fatalf("acme's own credential was refused: %s", status)
	}

	awaitSubscribers(t, b, 1)
	src.publish(acmeTenantWS, "acme-entity")
	payload, got := awaitEnvelope(t, conn, br, 5*time.Second)
	if !got {
		t.Fatal("acme received none of its own envelopes; the stream is closed to its owner")
	}
	if !strings.Contains(payload, "acme-entity") {
		t.Fatalf("unexpected envelope: %s", payload)
	}
}

// TestGraphWSTokenForOneTenantCannotReadAnother is the heart of the
// finding. Acme holds a real, valid, accepted credential — it is not an
// unauthenticated caller — and still must not reach umbra's stream, by
// the query string or by the header.
func TestGraphWSTokenForOneTenantCannotReadAnother(t *testing.T) {
	b, src := liveBroadcaster(t)

	// Positive control: umbra's stream is live and really does carry the
	// envelope we will later assert acme does not see.
	control := b.Subscribe(umbraTenantWS)
	defer b.Unsubscribe(control)
	src.publish(umbraTenantWS, "umbra-control")
	select {
	case <-control.Updates:
	case <-time.After(2 * time.Second):
		t.Fatal("umbra's stream is not publishing; a later absence would prove nothing")
	}

	srv := authenticatedServer(t, b)

	for _, tc := range []struct {
		name    string
		query   string
		headers map[string]string
	}{
		{
			name:  "tenant named in the query string",
			query: "tenant_id=" + umbraTenantWS,
			headers: map[string]string{
				"Authorization": "Bearer " + acmeWSToken,
			},
		},
		{
			name: "tenant named in the header",
			headers: map[string]string{
				"Authorization": "Bearer " + acmeWSToken,
				"X-Tenant-ID":   umbraTenantWS,
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			status, conn, br := dialWS(t, srv, tc.query, tc.headers)
			if !strings.Contains(status, "101") {
				// Refused at the handshake, which is the intended
				// outcome for the header case.
				return
			}
			// Subscriber 1 is the umbra control above; this connection
			// is subscriber 2. Publishing before it registers would let
			// the assertion below pass on a race rather than on scope.
			awaitSubscribers(t, b, 2)
			src.publish(umbraTenantWS, "umbra-secret")
			if payload, got := awaitEnvelope(t, conn, br, 2*time.Second); got {
				t.Fatalf("acme's credential reached umbra's stream via %s: %s", tc.name, payload)
			}
		})
	}
}

// TestGraphWSRefusesAnUnknownCredential keeps the check from degrading
// into "any Authorization header will do".
func TestGraphWSRefusesAnUnknownCredential(t *testing.T) {
	b, _ := liveBroadcaster(t)
	srv := authenticatedServer(t, b)

	status, _, _ := dialWS(t, srv, "", map[string]string{
		"Authorization": "Bearer not-a-real-token",
	})
	if strings.Contains(status, "101") {
		t.Fatalf("an unrecognised credential was upgraded: %s", status)
	}
}
