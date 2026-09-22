package inbox

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/beenuar/aisoc/services/ingest/internal/normalizer"
	"github.com/beenuar/aisoc/services/ingest/internal/publisher"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/rs/zerolog/log"
)

// Handler serves the /v1/inbox/* push endpoints. It composes the token
// resolver, template registry, and Kafka publisher into one HTTP-shaped
// front door for any vendor that can post a webhook.
//
// The four routes share a common shape: resolve token → optionally
// verify HMAC → parse body → run template → publish. Differences are
// just in how we get to the "parse body" step (raw JSON, NDJSON, CEF
// syslog text, email-relay JSON).
type Handler struct {
	store       *Store
	registry    *Registry
	pub         *publisher.Publisher
	maxBodySize int64
	limiter     *Limiter
}

// NewHandler wires the inbox handler. maxBodySize caps a single request
// body — any vendor that paginates correctly stays well under the
// default 10MiB; only buggy vendors push the limit.
func NewHandler(store *Store, registry *Registry, pub *publisher.Publisher, maxBodySize int64) *Handler {
	return &Handler{
		store:       store,
		registry:    registry,
		pub:         pub,
		maxBodySize: maxBodySize,
	}
}

// WithLimiter attaches per-tenant rate limiting. A nil limiter allows
// everything, so this is safe to skip in tests and in deployments that
// terminate limiting at the edge.
func (h *Handler) WithLimiter(l *Limiter) *Handler {
	h.limiter = l
	return h
}

// Prometheus counters track the universal-capture path so freshness SLOs
// (Workstream 5) can include push-mode connectors and operators can
// alarm on token drift.
var (
	inboxRequests = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "aisoc_ingest_inbox_requests_total",
			Help: "Universal-capture inbox requests by route and outcome.",
		},
		[]string{"route", "template", "outcome"},
	)
	inboxEvents = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "aisoc_ingest_inbox_events_total",
			Help: "Events accepted via the universal-capture inbox by template.",
		},
		[]string{"template"},
	)
	inboxRateLimited = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "aisoc_ingest_inbox_rate_limited_total",
			Help: "Inbox requests rejected by the per-tenant limiter, by dimension.",
		},
		[]string{"route", "dimension"},
	)
)

// ServeJSON handles POST /v1/inbox/{tenant_token}.
//
// This is the workhorse route — vendors paste in a webhook URL of
// the form https://ingest.tryaisoc.com/v1/inbox/<token>, and whatever
// JSON they send gets translated by the template the operator picked
// at mint time.
//
// Body parsing accepts either:
//   - a single JSON object
//   - a JSON array of events
//   - newline-delimited JSON (NDJSON)
//
// We try each in that order; the parsing is forgiving because vendors
// disagree on shape and we don't want to fail closed.
func (h *Handler) ServeJSON(w http.ResponseWriter, r *http.Request) {
	token := chi.URLParam(r, "token")
	tok := h.resolveOrFail(w, r, "json", token)
	if tok == nil {
		return
	}
	tmpl, ok := h.templateOrFail(w, "json", tok)
	if !ok {
		return
	}

	body, ok := h.readBody(w, r, "json", tok.TemplateID)
	if !ok {
		return
	}
	if !h.verifyHMACOrFail(w, r, "json", tok, body) {
		return
	}

	events, err := decodeJSONEvents(body)
	if err != nil {
		inboxRequests.WithLabelValues("json", tok.TemplateID, "bad_json").Inc()
		writeErr(w, http.StatusBadRequest, fmt.Sprintf("inbox: invalid JSON body: %v", err))
		return
	}

	h.publishMany(r.Context(), w, "json", tmpl, tok, events)
}

// ServeEmail handles POST /v1/inbox/email/{tenant_token}.
//
// The email path expects the upstream relay (SES Inbound, SendGrid
// Inbound Parse, Postmark, Mailgun) to have already converted RFC 5322
// into a JSON envelope of {from,to,subject,text,html,headers,attachments}.
// We just run the email-forwarded template (or whichever the operator
// pinned to this token).
func (h *Handler) ServeEmail(w http.ResponseWriter, r *http.Request) {
	token := chi.URLParam(r, "token")
	tok := h.resolveOrFail(w, r, "email", token)
	if tok == nil {
		return
	}
	tmpl, ok := h.templateOrFail(w, "email", tok)
	if !ok {
		return
	}
	body, ok := h.readBody(w, r, "email", tok.TemplateID)
	if !ok {
		return
	}
	if !h.verifyHMACOrFail(w, r, "email", tok, body) {
		return
	}
	events, err := decodeJSONEvents(body)
	if err != nil {
		inboxRequests.WithLabelValues("email", tok.TemplateID, "bad_json").Inc()
		writeErr(w, http.StatusBadRequest, fmt.Sprintf("inbox: invalid email envelope: %v", err))
		return
	}
	h.publishMany(r.Context(), w, "email", tmpl, tok, events)
}

// ServeCEF handles POST /v1/inbox/cef.
//
// CEF doesn't use a path token — the syslog forwarder just opens an
// HTTP connection and POSTs lines. We require the token in the
// Authorization header instead:
//
//	Authorization: Bearer <inbox-token>
//
// or a custom X-Inbox-Token header for forwarders that can't set
// arbitrary auth headers (some old syslog-ng builds).
//
// Body is one CEF line per record, separated by \n; we parse, run the
// cef-syslog template, and publish.
func (h *Handler) ServeCEF(w http.ResponseWriter, r *http.Request) {
	token := tokenFromHeaders(r)
	if token == "" {
		inboxRequests.WithLabelValues("cef", "", "no_token").Inc()
		writeErr(w, http.StatusUnauthorized, "inbox: missing inbox token (Authorization: Bearer <token> or X-Inbox-Token)")
		return
	}
	tok := h.resolveOrFail(w, r, "cef", token)
	if tok == nil {
		return
	}
	// The CEF route always uses the cef-syslog template — operators who
	// want a different mapping should mint a separate JSON token.
	if tok.TemplateID != "cef-syslog" {
		inboxRequests.WithLabelValues("cef", tok.TemplateID, "wrong_template").Inc()
		writeErr(w, http.StatusBadRequest,
			"inbox: CEF route requires a token minted with the cef-syslog template")
		return
	}
	tmpl, ok := h.templateOrFail(w, "cef", tok)
	if !ok {
		return
	}
	body, ok := h.readBody(w, r, "cef", tok.TemplateID)
	if !ok {
		return
	}
	if !h.verifyHMACOrFail(w, r, "cef", tok, body) {
		return
	}

	records, badLines := ParseCEFBatch(string(body))
	if len(records) == 0 && len(badLines) > 0 {
		inboxRequests.WithLabelValues("cef", tok.TemplateID, "all_malformed").Inc()
		writeErr(w, http.StatusBadRequest,
			fmt.Sprintf("inbox: all %d CEF lines were malformed", len(badLines)))
		return
	}
	h.publishMany(r.Context(), w, "cef", tmpl, tok, records)
}

// ServeHEC handles POST /v1/inbox/hec.
//
// Speaks Splunk HEC's wire protocol so any tool that can ship to Splunk
// can ship to AiSOC by changing only the URL. Token comes via the
// Splunk-style "Authorization: Splunk <token>" header (or Bearer).
//
// Body is either a single HEC envelope ({"event": ..., "time": ...,
// "host": ..., ...}) or NDJSON of those envelopes. We extract the
// inner event for the template's field map and stash the envelope
// metadata for the template to pick up.
func (h *Handler) ServeHEC(w http.ResponseWriter, r *http.Request) {
	token := hecTokenFromHeaders(r)
	if token == "" {
		inboxRequests.WithLabelValues("hec", "", "no_token").Inc()
		writeErr(w, http.StatusUnauthorized,
			"inbox: missing HEC token (Authorization: Splunk <token>)")
		return
	}
	tok := h.resolveOrFail(w, r, "hec", token)
	if tok == nil {
		return
	}
	if tok.TemplateID != "splunk-hec" {
		inboxRequests.WithLabelValues("hec", tok.TemplateID, "wrong_template").Inc()
		writeErr(w, http.StatusBadRequest,
			"inbox: HEC route requires a token minted with the splunk-hec template")
		return
	}
	tmpl, ok := h.templateOrFail(w, "hec", tok)
	if !ok {
		return
	}
	body, ok := h.readBody(w, r, "hec", tok.TemplateID)
	if !ok {
		return
	}
	if !h.verifyHMACOrFail(w, r, "hec", tok, body) {
		return
	}

	events, err := decodeJSONEvents(body)
	if err != nil {
		inboxRequests.WithLabelValues("hec", tok.TemplateID, "bad_json").Inc()
		writeErr(w, http.StatusBadRequest, fmt.Sprintf("inbox: invalid HEC payload: %v", err))
		return
	}
	h.publishMany(r.Context(), w, "hec", tmpl, tok, events)
}

// resolveOrFail wraps Resolve with HTTP-shaped error responses.
func (h *Handler) resolveOrFail(w http.ResponseWriter, r *http.Request, route, token string) *Token {
	if h.store == nil {
		inboxRequests.WithLabelValues(route, "", "no_store").Inc()
		writeErr(w, http.StatusServiceUnavailable,
			"inbox: store not configured (set DATABASE_DSN)")
		return nil
	}
	tok, err := h.store.Resolve(r.Context(), token)
	if err != nil {
		switch {
		case errors.Is(err, ErrTokenNotFound):
			inboxRequests.WithLabelValues(route, "", "not_found").Inc()
			writeErr(w, http.StatusNotFound, "inbox: token not found")
		case errors.Is(err, ErrTokenRevoked):
			inboxRequests.WithLabelValues(route, "", "revoked").Inc()
			writeErr(w, http.StatusGone,
				"inbox: token has been revoked; ask the operator to mint a new one")
		default:
			log.Error().Err(err).Str("route", route).Msg("inbox: resolve failed")
			inboxRequests.WithLabelValues(route, "", "resolve_error").Inc()
			writeErr(w, http.StatusInternalServerError, "inbox: temporary lookup failure")
		}
		return nil
	}

	// Checked here rather than per route: all four routes resolve before
	// they parse, so one gate covers them and cannot drift out of sync
	// with a fifth route added later.
	if ok, wait := h.limiter.AllowRequest(tok.TenantID); !ok {
		inboxRequests.WithLabelValues(route, tok.TemplateID, "rate_limited").Inc()
		inboxRateLimited.WithLabelValues(route, "requests").Inc()
		w.Header().Set("Retry-After", strconv.Itoa(retryAfterSeconds(wait)))
		writeErr(w, http.StatusTooManyRequests,
			"inbox: request rate limit exceeded for this tenant; retry after the interval in Retry-After")
		return nil
	}

	return tok
}

func (h *Handler) templateOrFail(w http.ResponseWriter, route string, tok *Token) (*Template, bool) {
	tmpl, err := h.registry.Get(tok.TemplateID)
	if err != nil {
		inboxRequests.WithLabelValues(route, tok.TemplateID, "no_template").Inc()
		writeErr(w, http.StatusServiceUnavailable,
			fmt.Sprintf("inbox: template %q not registered on this ingest build", tok.TemplateID))
		return nil, false
	}
	return tmpl, true
}

// readBody slurps the request body honouring h.maxBodySize. A 413 is
// returned on overflow.
func (h *Handler) readBody(w http.ResponseWriter, r *http.Request, route, template string) ([]byte, bool) {
	limit := h.maxBodySize
	if limit <= 0 {
		limit = 10 * 1024 * 1024
	}
	r.Body = http.MaxBytesReader(w, r.Body, limit)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			inboxRequests.WithLabelValues(route, template, "too_large").Inc()
			writeErr(w, http.StatusRequestEntityTooLarge,
				fmt.Sprintf("inbox: body exceeds %d bytes", limit))
			return nil, false
		}
		inboxRequests.WithLabelValues(route, template, "read_error").Inc()
		writeErr(w, http.StatusBadRequest,
			fmt.Sprintf("inbox: read body failed: %v", err))
		return nil, false
	}
	return body, true
}

// verifyHMACOrFail enforces the optional HMAC-SHA256 signature header
// when the token has hmac_secret set. We accept either:
//
//   X-Signature: sha256=<hex>
//   X-Hub-Signature-256: sha256=<hex>   (GitHub-style)
//
// Constant-time comparison protects against timing oracles.
func (h *Handler) verifyHMACOrFail(w http.ResponseWriter, r *http.Request, route string, tok *Token, body []byte) bool {
	if tok.HMACSecret == "" {
		return true
	}
	provided := r.Header.Get("X-Signature")
	if provided == "" {
		provided = r.Header.Get("X-Hub-Signature-256")
	}
	if provided == "" {
		inboxRequests.WithLabelValues(route, tok.TemplateID, "missing_signature").Inc()
		writeErr(w, http.StatusUnauthorized,
			"inbox: token requires HMAC signature (set X-Signature: sha256=<hex>)")
		return false
	}
	provided = strings.TrimPrefix(provided, "sha256=")
	mac := hmac.New(sha256.New, []byte(tok.HMACSecret))
	mac.Write(body)
	expected := hex.EncodeToString(mac.Sum(nil))
	if !hmac.Equal([]byte(provided), []byte(expected)) {
		inboxRequests.WithLabelValues(route, tok.TemplateID, "bad_signature").Inc()
		writeErr(w, http.StatusUnauthorized, "inbox: HMAC signature mismatch")
		return false
	}
	return true
}

// publishMany runs the template against each event and pushes them to
// Kafka. We bundle into a single PublishBatch so that a busy webhook
// burst becomes one Kafka write, not N.
func (h *Handler) publishMany(ctx context.Context, w http.ResponseWriter, route string, tmpl *Template, tok *Token, events []map[string]any) {
	if len(events) == 0 {
		inboxRequests.WithLabelValues(route, tok.TemplateID, "empty").Inc()
		writeJSON(w, http.StatusOK, map[string]any{
			"accepted":    0,
			"template_id": tok.TemplateID,
			"label":       tok.Label,
		})
		return
	}

	// Event quota is applied after parsing because the count is not
	// knowable before then, and before normalising because rejecting is
	// cheaper than building events we will throw away. The batch is
	// rejected whole: a partial accept would split a vendor's payload
	// across a boundary it cannot observe, and make its retry duplicate
	// the accepted half.
	if ok, wait := h.limiter.AllowEvents(tok.TenantID, len(events)); !ok {
		inboxRequests.WithLabelValues(route, tok.TemplateID, "rate_limited").Inc()
		inboxRateLimited.WithLabelValues(route, "events").Inc()
		w.Header().Set("Retry-After", strconv.Itoa(retryAfterSeconds(wait)))
		writeErr(w, http.StatusTooManyRequests,
			fmt.Sprintf("inbox: event quota exceeded for this tenant (%d events in this batch); "+
				"retry after the interval in Retry-After", len(events)))
		return
	}

	receivedAt := time.Now().UTC().Format(time.RFC3339Nano)
	tenantID := tok.TenantID.String()
	connectorRef := "inbox:" + tok.TemplateID

	normalized := make([]*normalizer.NormalizedEvent, 0, len(events))
	for _, evt := range events {
		ocsf := tmpl.Apply(evt, tenantID, connectorRef, receivedAt)
		ne := &normalizer.NormalizedEvent{
			ID:                   uuid.NewString(),
			ConnectorID:          connectorRef,
			TenantID:             tenantID,
			OcsfEvent:            ocsf,
			NormalizationVersion: "inbox/1.0",
		}
		normalized = append(normalized, ne)
	}

	if err := h.pub.PublishBatch(ctx, normalized); err != nil {
		log.Error().Err(err).
			Str("route", route).
			Str("template", tok.TemplateID).
			Str("tenant_id", tenantID).
			Msg("inbox: kafka publish failed")
		inboxRequests.WithLabelValues(route, tok.TemplateID, "publish_error").Inc()
		writeErr(w, http.StatusBadGateway, "inbox: failed to enqueue events; please retry")
		return
	}

	inboxRequests.WithLabelValues(route, tok.TemplateID, "ok").Inc()
	inboxEvents.WithLabelValues(tok.TemplateID).Add(float64(len(normalized)))

	writeJSON(w, http.StatusOK, map[string]any{
		"accepted":    len(normalized),
		"template_id": tok.TemplateID,
		"label":       tok.Label,
	})
}

// decodeJSONEvents parses a request body into a slice of event maps.
// Accepts a JSON object, JSON array of objects, or NDJSON. Falls
// through in that order so vendors with inconsistent shapes still get
// sane handling.
func decodeJSONEvents(body []byte) ([]map[string]any, error) {
	trimmed := bytesTrimSpace(body)
	if len(trimmed) == 0 {
		return nil, nil
	}

	switch trimmed[0] {
	case '{':
		var single map[string]any
		if err := json.Unmarshal(body, &single); err != nil {
			// Fall through to NDJSON; some vendors send {}\n{}\n.
			return decodeNDJSON(body)
		}
		return []map[string]any{single}, nil
	case '[':
		var arr []map[string]any
		if err := json.Unmarshal(body, &arr); err != nil {
			return nil, fmt.Errorf("array decode: %w", err)
		}
		return arr, nil
	default:
		// Try NDJSON.
		return decodeNDJSON(body)
	}
}

func decodeNDJSON(body []byte) ([]map[string]any, error) {
	var out []map[string]any
	dec := json.NewDecoder(strings.NewReader(string(body)))
	for {
		var evt map[string]any
		if err := dec.Decode(&evt); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return out, err
		}
		out = append(out, evt)
	}
	return out, nil
}

// tokenFromHeaders pulls an inbox token from Authorization (Bearer) or
// X-Inbox-Token. Used by /v1/inbox/cef and /v1/inbox/hec.
func tokenFromHeaders(r *http.Request) string {
	if v := r.Header.Get("Authorization"); v != "" {
		// "Bearer <token>" or "Splunk <token>" or just "<token>".
		parts := strings.Fields(v)
		switch len(parts) {
		case 1:
			return parts[0]
		case 2:
			return parts[1]
		}
	}
	return r.Header.Get("X-Inbox-Token")
}

// hecTokenFromHeaders accepts the standard Splunk header form
// "Authorization: Splunk <token>", as well as Bearer and a bare X-
// header for forwarders that can't set Authorization.
func hecTokenFromHeaders(r *http.Request) string {
	if v := r.Header.Get("Authorization"); v != "" {
		parts := strings.Fields(v)
		switch len(parts) {
		case 1:
			return parts[0]
		case 2:
			return parts[1]
		}
	}
	if v := r.Header.Get("X-Splunk-Token"); v != "" {
		return v
	}
	return r.Header.Get("X-Inbox-Token")
}

// bytesTrimSpace is a small helper because bytes.TrimSpace requires an
// extra import and we only need it once.
func bytesTrimSpace(b []byte) []byte {
	start := 0
	for start < len(b) && (b[start] == ' ' || b[start] == '\n' || b[start] == '\r' || b[start] == '\t') {
		start++
	}
	end := len(b)
	for end > start && (b[end-1] == ' ' || b[end-1] == '\n' || b[end-1] == '\r' || b[end-1] == '\t') {
		end--
	}
	return b[start:end]
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}
