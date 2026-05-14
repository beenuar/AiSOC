// Package handler implements HTTP handlers for the ingest service
package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/beenuar/aisoc/services/ingest/internal/config"
	"github.com/beenuar/aisoc/services/ingest/internal/graph"
	"github.com/beenuar/aisoc/services/ingest/internal/normalizer"
	"github.com/beenuar/aisoc/services/ingest/internal/publisher"
	"github.com/rs/zerolog/log"
)

// GraphWriter is the subset of *graph.Writer the handler depends on.
// Defined as an interface so the HTTP path can be unit-tested without
// constructing a real Neo4j-backed writer (and so a nil writer is allowed
// when graph projection is disabled).
type GraphWriter interface {
	WriteEvent(ctx context.Context, ev *graph.Event) error
}

// SnapshotApplier mirrors *config_snapshot.Snapshotter.Apply. Defined as
// an interface so the handler can be unit-tested without standing up a
// real provider/cache pair, and so a nil applier is a clean "T1.2
// disabled" signal.
type SnapshotApplier interface {
	Apply(ctx context.Context, ev *graph.Event)
}

// Handler holds handler dependencies
type Handler struct {
	norm     *normalizer.Normalizer
	pub      *publisher.Publisher
	graph    GraphWriter
	snapshot SnapshotApplier
	cfg      *config.Config
}

// New creates a new Handler
func New(norm *normalizer.Normalizer, pub *publisher.Publisher, cfg *config.Config) *Handler {
	return &Handler{norm: norm, pub: pub, cfg: cfg}
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
