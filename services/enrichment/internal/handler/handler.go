package handler

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/beenuar/aisoc/enrichment/internal/enricher"
	"github.com/rs/zerolog/log"
)

// Handler holds dependencies for HTTP handlers.
type Handler struct {
	enricher *enricher.Enricher
	limiter  *enricher.RateLimiter
}

// New creates a new HTTP handler.
//
// `limiter` may be nil, which means unlimited. That is the honest default
// for a caller that has not been updated, and it is the direction the
// config already chose: RATE_LIMIT_RPS defaults to 100 and a malformed
// value parses to 0, so reading an unset rate as "allow nothing" would turn
// enrichment off across the deployment with no message anywhere.
func New(e *enricher.Enricher, limiter *enricher.RateLimiter) *Handler {
	return &Handler{enricher: e, limiter: limiter}
}

// rateLimitKey is the bucket a request spends from.
//
// Per tenant, with requests carrying no tenant sharing one bucket rather
// than bypassing the limit. A missing tenant must not be the way around the
// limiter, which is what an empty-means-unlimited rule would make it.
func rateLimitKey(tenantID string) string {
	if strings.TrimSpace(tenantID) == "" {
		return "_untenanted"
	}
	return tenantID
}

// refuse answers 429 with the header a client needs to behave.
func refuse(w http.ResponseWriter) {
	w.Header().Set("Retry-After", "1")
	writeError(w, http.StatusTooManyRequests, "enrichment rate limit exceeded for this tenant")
}

type errorResponse struct {
	Error   string `json:"error"`
	Code    int    `json:"code"`
	TraceID string `json:"trace_id,omitempty"`
}

// EnrichIOC handles POST /enrich - single IOC enrichment.
func (h *Handler) EnrichIOC(w http.ResponseWriter, r *http.Request) {
	var req enricher.EnrichRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	req.Value = strings.TrimSpace(req.Value)
	if req.Value == "" {
		writeError(w, http.StatusBadRequest, "ioc value is required")
		return
	}
	if req.IOCType == "" {
		writeError(w, http.StatusBadRequest, "ioc_type is required")
		return
	}

	if h.limiter != nil && !h.limiter.Allow(rateLimitKey(req.TenantID)) {
		refuse(w)
		return
	}

	ctx := r.Context()
	result, err := h.enricher.Enrich(ctx, req)
	if err != nil {
		log.Error().Err(err).Str("ioc", req.Value).Msg("Enrichment failed")
		writeError(w, http.StatusInternalServerError, "enrichment failed")
		return
	}

	writeJSON(w, http.StatusOK, result)
}

// BulkEnrich handles POST /enrich/bulk - batch IOC enrichment.
func (h *Handler) BulkEnrich(w http.ResponseWriter, r *http.Request) {
	var bulkReq enricher.BulkEnrichRequest
	if err := json.NewDecoder(r.Body).Decode(&bulkReq); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if len(bulkReq.Items) == 0 {
		writeError(w, http.StatusBadRequest, "items array is required and must not be empty")
		return
	}
	if len(bulkReq.Items) > 100 {
		writeError(w, http.StatusBadRequest, "maximum 100 items per bulk request")
		return
	}

	ctx := r.Context()
	results := make([]enricher.EnrichmentResult, 0, len(bulkReq.Items))
	errCount := 0

	for _, item := range bulkReq.Items {
		item.Value = strings.TrimSpace(item.Value)
		if item.Value == "" || item.IOCType == "" {
			errCount++
			continue
		}

		// One token per item, not one per request. A bulk call carrying a
		// hundred indicators reaches a hundred third-party lookups, so
		// charging it as a single request would make `/enrich/bulk` the way
		// around the limit rather than a convenience.
		if h.limiter != nil && !h.limiter.Allow(rateLimitKey(item.TenantID)) {
			errCount++
			results = append(results, enricher.EnrichmentResult{
				IOCType: item.IOCType,
				Value:   item.Value,
				// Named rather than silently dropped. An item missing from
				// a bulk response with no reason reads as "nothing known
				// about this indicator", which is a statement about the
				// indicator rather than about our budget.
				EnrichmentErrors: []string{"rate limit exceeded for this tenant; not enriched"},
				EnrichedAt:       time.Now(),
			})
			continue
		}

		result, err := h.enricher.Enrich(ctx, item)
		if err != nil {
			log.Warn().Err(err).Str("ioc", item.Value).Msg("Bulk enrichment item failed")
			errCount++
			results = append(results, enricher.EnrichmentResult{
				IOCType:          item.IOCType,
				Value:            item.Value,
				EnrichmentErrors: []string{err.Error()},
				EnrichedAt:       time.Now(),
			})
			continue
		}
		results = append(results, *result)
	}

	resp := enricher.BulkEnrichResponse{
		Results: results,
		Total:   len(results),
		Errors:  errCount,
	}

	writeJSON(w, http.StatusOK, resp)
}

// Health handles GET /health.
func (h *Handler) Health(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{
		"status":  "healthy",
		"service": "aisoc-enrichment",
	})
}

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		log.Error().Err(err).Msg("Failed to write JSON response")
	}
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, errorResponse{
		Error: msg,
		Code:  status,
	})
}
