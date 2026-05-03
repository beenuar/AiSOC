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
}

// New creates a new HTTP handler.
func New(e *enricher.Enricher) *Handler {
	return &Handler{enricher: e}
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
