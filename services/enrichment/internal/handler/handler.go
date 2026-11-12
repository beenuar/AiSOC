package handler

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/beenuar/aisoc/enrichment/internal/enricher"
	"github.com/beenuar/aisoc/enrichment/internal/tenantauth"
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
// Keyed on the *authenticated* tenant (GHSA-qf6m-hgwv-65f9). It used to be
// keyed on the body's `tenant_id`, so every previously unseen string minted a
// fresh token bucket and rotating the field defeated the limiter entirely.
// The principal's tenant is the one identity the caller cannot choose per
// request. The `_untenanted` fallback stays for defence in depth, but a
// resolved principal always carries a tenant.
func rateLimitKey(tenantID string) string {
	if strings.TrimSpace(tenantID) == "" {
		return "_untenanted"
	}
	return tenantID
}

// resolveTenant intersects the body's tenant claim with the authenticated
// principal, mirroring the Python services' scoped_tenant_or_403: a body
// naming the principal's own tenant (in any case form) is honoured, an empty
// body field inherits it, and anything else — another tenant's UUID, or an
// arbitrary bucket-minting string like "probe-a" — is refused rather than
// believed. The returned value is always the principal's canonical tenant.
func resolveTenant(p tenantauth.Principal, bodyTenant string) (string, bool) {
	if strings.TrimSpace(bodyTenant) == "" || p.Covers(bodyTenant) {
		return p.TenantID, true
	}
	return "", false
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
	principal, ok := tenantauth.FromContext(r.Context())
	if !ok {
		// The route is registered behind tenantauth.Middleware; reaching
		// here without a principal is a wiring defect, and the safe answer
		// to "who is asking" being unanswered is a refusal, not a guess.
		writeError(w, http.StatusUnauthorized, "request reached the handler without an authenticated principal")
		return
	}

	var req enricher.EnrichRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	tenant, covered := resolveTenant(principal, req.TenantID)
	if !covered {
		writeError(w, http.StatusForbidden, "request names a tenant this credential does not act for")
		return
	}
	req.TenantID = tenant

	req.Value = strings.TrimSpace(req.Value)
	if req.Value == "" {
		writeError(w, http.StatusBadRequest, "ioc value is required")
		return
	}
	if req.IOCType == "" {
		writeError(w, http.StatusBadRequest, "ioc_type is required")
		return
	}

	if h.limiter != nil && !h.limiter.Allow(rateLimitKey(principal.TenantID)) {
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
	principal, ok := tenantauth.FromContext(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "request reached the handler without an authenticated principal")
		return
	}

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

		// Each item's tenant claim is intersected with the principal, same
		// as the single route: distinct body tenant ids used to give every
		// item its own fresh limiter bucket (GHSA-qf6m-hgwv-65f9).
		tenant, covered := resolveTenant(principal, item.TenantID)
		if !covered {
			errCount++
			results = append(results, enricher.EnrichmentResult{
				IOCType:          item.IOCType,
				Value:            item.Value,
				EnrichmentErrors: []string{"item names a tenant this credential does not act for; not enriched"},
				EnrichedAt:       time.Now(),
			})
			continue
		}
		item.TenantID = tenant

		// One token per item, not one per request. A bulk call carrying a
		// hundred indicators reaches a hundred third-party lookups, so
		// charging it as a single request would make `/enrich/bulk` the way
		// around the limit rather than a convenience.
		if h.limiter != nil && !h.limiter.Allow(rateLimitKey(principal.TenantID)) {
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
