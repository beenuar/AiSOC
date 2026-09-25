// Package handler implements HTTP handlers for the ingest service
package handler

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/beenuar/aisoc/services/ingest/internal/config"
	"github.com/beenuar/aisoc/services/ingest/internal/graph"
	"github.com/beenuar/aisoc/services/ingest/internal/ingestauth"
	"github.com/beenuar/aisoc/services/ingest/internal/normalizer"
	"github.com/rs/zerolog/log"
)

// GraphWriter is the subset of *graph.Writer the handler depends on.
// Defined as an interface so the HTTP path can be unit-tested without
// constructing a real Neo4j-backed writer (and so a nil writer is allowed
// when graph projection is disabled).
type GraphWriter interface {
	WriteEvent(ctx context.Context, ev *graph.Event) error
}

// EventPublisher is the subset of *publisher.Publisher the HTTP path
// depends on. Declared as an interface for the same reason GraphWriter is:
// so a request can be driven end to end in a unit test — including which
// tenant its events were published for — without a Kafka broker.
type EventPublisher interface {
	PublishBatch(ctx context.Context, events []*normalizer.NormalizedEvent) error
	Ready(ctx context.Context) error
}

// SnapshotApplier mirrors *config_snapshot.Snapshotter.Apply. Defined as
// an interface so the handler can be unit-tested without standing up a
// real provider/cache pair, and so a nil applier is a clean "T1.2
// disabled" signal.
type SnapshotApplier interface {
	Apply(ctx context.Context, ev *graph.Event)
}

// SubscriptionStatus is what a background subscription reports about itself
// to /readyz. Declared here, with no dependency on the package that owns the
// subscription, so wiring one up cannot create an import cycle.
type SubscriptionStatus struct {
	// Attached: the loop is iterating its source right now.
	Attached bool `json:"attached"`
	// NotResolving: it has been failing for longer than a transient fault
	// explains, or the failure is one no retry can clear. This is the field
	// that separates "quiet" from "broken", which is the distinction a
	// probe reporting only on the process cannot make.
	NotResolving bool `json:"not_resolving"`
	// Detail is the operator-facing reason, empty when healthy.
	Detail string `json:"detail,omitempty"`
}

// Handler holds handler dependencies
type Handler struct {
	norm          *normalizer.Normalizer
	pub           EventPublisher
	graph         GraphWriter
	snapshot      SnapshotApplier
	cfg           *config.Config
	auth          *ingestauth.Authenticator
	subscriptions map[string]func() SubscriptionStatus
}

// New creates a new Handler
func New(norm *normalizer.Normalizer, pub EventPublisher, cfg *config.Config) *Handler {
	return &Handler{norm: norm, pub: pub, cfg: cfg, subscriptions: map[string]func() SubscriptionStatus{}}
}

// RegisterSubscription makes /readyz report on a background consumer.
//
// Call once per subscription the service owns, before serving. probe must be
// cheap and non-blocking — it runs on every readiness request — so it should
// read state the consumer already maintains rather than round-trip to a
// broker.
func (h *Handler) RegisterSubscription(name string, probe func() SubscriptionStatus) {
	if h.subscriptions == nil {
		h.subscriptions = map[string]func() SubscriptionStatus{}
	}
	h.subscriptions[name] = probe
}

// SetGraphWriter wires in the graph projection writer. nil disables graph
// fan-out — the rest of the pipeline behaves identically.
//
// The fan-out is intentional: the graph writer runs concurrently with the
// fusion publish, and a failure / queue-full in the graph writer must NOT
// block the fusion path (T1.1 acceptance criterion).
func (h *Handler) SetGraphWriter(g GraphWriter) {
	h.graph = g
}

// SetSnapshotApplier wires in the T1.2 config-snapshot applier. nil leaves
// graph projections without :Configuration nodes — the writer still upserts
// every other node and edge, so disabling snapshots NEVER stalls ingest.
func (h *Handler) SetSnapshotApplier(s SnapshotApplier) {
	h.snapshot = s
}

// SetAuthenticator wires in the /v1/ingest credential check.
//
// Unlike the other setters on this type, nil is not a "feature disabled"
// signal: a nil *ingestauth.Authenticator refuses every request. Ingest is
// a write path into tenant-owned data, so a wiring regression has to fail
// closed. There is no flag that turns this off — AISOC_DEV_MODE does not
// reach it, and services/api/tests/test_security_defaults.py exists to keep
// it that way.
func (h *Handler) SetAuthenticator(a *ingestauth.Authenticator) {
	h.auth = a
}

// IngestRequest is the API payload for submitting events
type IngestRequest struct {
	ConnectorID   string                   `json:"connector_id"`
	ConnectorType string                   `json:"connector_type"`
	SourceFormat  string                   `json:"source_format"`
	Events        []map[string]interface{} `json:"events"`
}

// IngestResponse reports processing results
type IngestResponse struct {
	Accepted  int      `json:"accepted"`
	Rejected  int      `json:"rejected"`
	RequestID string   `json:"request_id"`
	Errors    []string `json:"errors,omitempty"`
}

// IngestEvents handles POST /v1/ingest
func (h *Handler) IngestEvents(w http.ResponseWriter, r *http.Request) {
	// Authenticate before touching the body. An unauthenticated caller
	// should not get to spend this process's memory budget, and the
	// credential is what decides the tenant, so nothing below can run
	// without it.
	identity, authErr := h.auth.Authenticate(r.Context(), r)
	if authErr != nil {
		writeAuthError(w, r, authErr)
		return
	}

	body, ok := h.readIngestBody(w, r)
	if !ok {
		return
	}

	if err := ingestauth.VerifySignature(r, identity, body); err != nil {
		writeAuthError(w, r, err)
		return
	}

	// The tenant header is honoured only where it agrees with what the
	// credential authorises. Naming another tenant narrows the scope to
	// nothing and is refused here, rather than reaching into that tenant
	// — which is precisely what this endpoint used to do for anyone who
	// could reach the port.
	tenantUUID, scopeErr := ingestauth.Resolve(identity.Principal, h.auth.DeclaredTenant(r))
	if scopeErr != nil {
		log.Warn().
			Str("subject", sanitizeForLog(identity.Principal.Subject)).
			Str("requested_tenant", sanitizeForLog(h.auth.DeclaredTenant(r))).
			Bool("delegated", identity.Principal.Delegated).
			Msg("ingest: refused a write outside the credential's tenant scope")
		writeError(w, http.StatusForbidden, scopeErr.Error())
		return
	}
	tenantID := tenantUUID.String()

	var req IngestRequest
	if err := json.Unmarshal(body, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body: "+err.Error())
		return
	}

	if req.ConnectorID == "" || req.ConnectorType == "" {
		writeError(w, http.StatusBadRequest, "connector_id and connector_type are required")
		return
	}

	if len(req.Events) == 0 {
		writeJSON(w, http.StatusOK, IngestResponse{RequestID: newRequestID()})
		return
	}

	if len(req.Events) > h.cfg.MaxBatchSize {
		// strconv, not string(rune(…)): the conversion produces the *code point*
		// with that value, so a limit of 1000 rendered as "Ϩ" and the caller was
		// told their batch exceeded a maximum of one Greek letter.
		writeError(w, http.StatusRequestEntityTooLarge,
			"batch size exceeds maximum of "+strconv.Itoa(h.cfg.MaxBatchSize))
		return
	}

	normalized := make([]*normalizer.NormalizedEvent, 0, len(req.Events))
	errs := []string{}
	rejected := 0

	for i, payload := range req.Events {
		raw := &normalizer.RawEvent{
			ConnectorID:   req.ConnectorID,
			ConnectorType: req.ConnectorType,
			TenantID:      tenantID,
			ReceivedAt:    time.Now().UTC().Format(time.RFC3339Nano),
			Payload:       payload,
			SourceFormat:  req.SourceFormat,
		}

		event, err := h.norm.Normalize(raw)
		if err != nil {
			log.Warn().Err(err).Int("event_index", i).Msg("Normalization failed")
			errs = append(errs, err.Error())
			rejected++
			continue
		}

		normalized = append(normalized, event)
	}

	if len(normalized) > 0 {
		// Fan-out graph writer (T1.1, v8.0). Runs concurrently with fusion
		// publish. A failure in WriteEvent never propagates here — the
		// writer drops the event onto an internal queue with backpressure
		// handled by drop-and-metric, so this loop is non-blocking.
		if h.graph != nil {
			for _, ev := range normalized {
				gev := graph.ExtractFromOCSF(ev.ID, ev.TenantID, req.ConnectorType, ev.OcsfEvent)
				if gev == nil {
					continue
				}
				// T1.2 — attach :Configuration nodes + :CONFIGURED_AS
				// edges. Apply is best-effort: any provider failure is
				// logged + skipped; the rest of the projection still
				// flushes through WriteEvent below.
				if h.snapshot != nil {
					h.snapshot.Apply(r.Context(), gev)
				}
				// WriteEvent is non-blocking; ctx is only used to honor
				// shutdown. We deliberately don't wait on it.
				_ = h.graph.WriteEvent(r.Context(), gev)
			}
		}

		if err := h.pub.PublishBatch(r.Context(), normalized); err != nil {
			log.Error().Err(err).Str("tenant_id", tenantID).Msg("Failed to publish batch")
			writeError(w, http.StatusInternalServerError, "failed to publish events")
			return
		}
	}

	writeJSON(w, http.StatusOK, IngestResponse{
		Accepted:  len(normalized),
		Rejected:  rejected,
		RequestID: newRequestID(),
		Errors:    errs,
	})
}

// Health handles GET /health
// Health is liveness: is this process running at all? It deliberately checks
// nothing else, so a restart loop is distinguishable from a dependency
// outage.
func (h *Handler) Health(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":    "ok",
		"service":   "ingest",
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	})
}

// Livez is the Kubernetes spelling of Health. Same answer, conventional name.
func (h *Handler) Livez(w http.ResponseWriter, r *http.Request) {
	h.Health(w, r)
}

// Readyz is readiness: can this service do its job right now?
//
// For ingest that means one thing — is Kafka reachable. Without it every
// accepted event is dropped, and the service used to report a cheerful 200
// throughout, so "ingest is healthy" and "nothing is reaching the pipeline"
// were simultaneously true with no way to tell from the outside.
//
// 503 with the reason, rather than 200 with a status field, so a load
// balancer and a human both get a usable answer.
//
// Subscriptions are reported, not voted on
// ----------------------------------------
// Every registered background subscription is listed in the body whether or
// not anything is wrong, so a 200 says which ones were checked rather than
// only that nothing failed — a detached consumer behind a 200 with no
// mention of it is precisely what made the UEBA defect invisible.
//
// What a detached subscription does NOT do is flip the status code. Unlike
// the Python services, where consuming a topic IS the service's job, ingest
// serves two different kinds of traffic on one port: the publish path
// (/v1/ingest, /v1/inbox) and the opt-in graph-update WebSocket. Failing
// readiness for the second would pull the pipeline's front door out of the
// load balancer over an auxiliary feature, dropping events to fix a
// broadcast. The surface that depends on the subscription reports on it
// directly instead: /v1/graph_ws/stream answers 503 with the reason, and
// aisoc_graph_ws_source_not_resolving is the alertable signal.
func (h *Handler) Readyz(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()

	subs := h.subscriptionReport()
	body := map[string]interface{}{
		"service": "ingest",
		// Present on every response, including the failing ones. A field
		// that only renders on the happy path is absent at exactly the
		// moment somebody is reading the output to find out what is wrong.
		"subscriptions": subs,
		"timestamp":     time.Now().UTC().Format(time.RFC3339),
	}
	// Named at the top level as well, so the degraded case is legible
	// without reading the per-subscription map.
	if degraded := degradedSubscriptions(subs); len(degraded) > 0 {
		body["degraded_subscriptions"] = degraded
	}

	if h.pub == nil {
		body["status"] = "not_ready"
		body["reason"] = "no kafka publisher configured"
		writeJSON(w, http.StatusServiceUnavailable, body)
		return
	}
	if err := h.pub.Ready(ctx); err != nil {
		body["status"] = "not_ready"
		body["reason"] = err.Error()
		body["hint"] = "docker compose logs kafka | tail -40"
		writeJSON(w, http.StatusServiceUnavailable, body)
		return
	}
	body["status"] = "ready"
	body["checks"] = map[string]string{"kafka": "reachable"}
	if _, degraded := body["degraded_subscriptions"]; degraded {
		body["status"] = "ready_degraded"
	}
	writeJSON(w, http.StatusOK, body)
}

// subscriptionReport evaluates every registered probe. A probe that panics
// is reported as detached rather than taking the readiness endpoint down
// with it: asking a live object whether it is working must not be able to
// make the answer unavailable.
func (h *Handler) subscriptionReport() map[string]SubscriptionStatus {
	out := make(map[string]SubscriptionStatus, len(h.subscriptions))
	for name, probe := range h.subscriptions {
		out[name] = safeProbe(name, probe)
	}
	return out
}

func safeProbe(name string, probe func() SubscriptionStatus) (status SubscriptionStatus) {
	defer func() {
		if rec := recover(); rec != nil {
			log.Error().Str("subscription", name).Interface("panic", rec).
				Msg("readiness probe panicked; reporting the subscription as detached")
			status = SubscriptionStatus{Attached: false, NotResolving: true, Detail: "probe panicked"}
		}
	}()
	return probe()
}

func degradedSubscriptions(subs map[string]SubscriptionStatus) []string {
	var names []string
	for name, status := range subs {
		if !status.Attached || status.NotResolving {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	return names
}

// readIngestBody slurps the body under a size cap.
//
// The cap is new alongside authentication and belongs with it: MaxBatchSize
// is only checked after the payload has been decoded, so before this the
// only thing standing between the endpoint and a multi-gigabyte body was
// that nobody had sent one.
func (h *Handler) readIngestBody(w http.ResponseWriter, r *http.Request) ([]byte, bool) {
	limit := h.cfg.IngestMaxBodyBytes
	if limit <= 0 {
		limit = 10 * 1024 * 1024
	}
	r.Body = http.MaxBytesReader(w, r.Body, limit)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			writeError(w, http.StatusRequestEntityTooLarge,
				fmt.Sprintf("body exceeds %d bytes", limit))
			return nil, false
		}
		writeError(w, http.StatusBadRequest, "failed to read request body: "+err.Error())
		return nil, false
	}
	return body, true
}

// writeAuthError renders an *ingestauth.Error with its own status, and logs
// the refusal. Anything that is not one of those is reported as 401 rather
// than leaking an internal message to an unauthenticated caller.
func writeAuthError(w http.ResponseWriter, r *http.Request, err error) {
	var authErr *ingestauth.Error
	status, msg := http.StatusUnauthorized, "unauthorized"
	if errors.As(err, &authErr) {
		status, msg = authErr.Status, authErr.Msg
	}
	log.Warn().
		Int("status", status).
		Str("remote_addr", sanitizeForLog(r.RemoteAddr)).
		Str("path", sanitizeForLog(r.URL.Path)).
		Msg("ingest: refused an unauthenticated or unauthorized push")
	writeError(w, status, msg)
}

// sanitizeForLog strips CR/LF and bounds length inline at the call site.
// Done inline rather than behind a helper call for the values that matter:
// the taint tracker does not follow a helper across the boundary, and these
// values are caller-controlled.
func sanitizeForLog(v string) string {
	s := strings.ReplaceAll(strings.ReplaceAll(v, "\r", ""), "\n", " ")
	if len(s) > 128 {
		return s[:128]
	}
	return s
}

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		log.Error().Err(err).Msg("Failed to write JSON response")
	}
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func newRequestID() string {
	return fmt.Sprintf("req-%d", time.Now().UnixNano())
}
