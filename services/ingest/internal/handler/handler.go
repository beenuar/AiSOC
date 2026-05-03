// Package handler implements HTTP handlers for the ingest service
package handler

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/beenuar/aisoc/services/ingest/internal/config"
	"github.com/beenuar/aisoc/services/ingest/internal/normalizer"
	"github.com/beenuar/aisoc/services/ingest/internal/publisher"
	"github.com/rs/zerolog/log"
)

// Handler holds handler dependencies
type Handler struct {
	norm *normalizer.Normalizer
	pub  *publisher.Publisher
	cfg  *config.Config
}

// New creates a new Handler
func New(norm *normalizer.Normalizer, pub *publisher.Publisher, cfg *config.Config) *Handler {
	return &Handler{norm: norm, pub: pub, cfg: cfg}
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
	tenantID := r.Header.Get(h.cfg.TenantHeaderKey)
	if tenantID == "" {
		writeError(w, http.StatusBadRequest, "missing tenant ID header")
		return
	}

	var req IngestRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
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
		writeError(w, http.StatusRequestEntityTooLarge,
			"batch size exceeds maximum of "+string(rune(h.cfg.MaxBatchSize)))
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
func (h *Handler) Health(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":    "ok",
		"service":   "ingest",
		"timestamp": time.Now().UTC().Format(time.RFC3339),
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
	writeJSON(w, status, map[string]string{"error": msg})
}

func newRequestID() string {
	return fmt.Sprintf("req-%d", time.Now().UnixNano())
}
