// k8s_audit.go — Kubernetes audit log webhook handler.
//
// This is the receive side of the Track D / v7.1.0 Kubernetes audit
// integration. The Kubernetes apiserver, when configured with an
// audit-webhook backend, POSTs batches of v1 audit events to a remote
// HTTP endpoint as a single JSON document of shape:
//
//     {
//       "kind":       "EventList",
//       "apiVersion": "audit.k8s.io/v1",
//       "items":      [ { ...one Event... }, ... ]
//     }
//
// The route is `POST /v1/ingest/k8s-audit/{tenant_id}`. We pull tenant
// from the URL (rather than a header) because audit-webhook config in
// the apiserver kubeconfig file is brittle to add custom headers to,
// but a path-templated URL is trivial. The webhook is authenticated
// with a single shared secret presented in `X-AiSOC-K8s-Token`. We
// only ever compare it with `subtle.ConstantTimeCompare` so a slow
// guesser can't shave bytes off via timing.
//
// Each item in the EventList becomes one normalized event with
// `connector_type: "kubernetes_audit"`, which the normalizer turns
// into an OCSF "API Activity" (class 6003) record. Severity is not
// emitted by the apiserver — we leave the heuristic to the
// `kubernetes_audit` Python connector path on the file_tail side, and
// here just pass the event verbatim and let the normalizer pick a
// default. The intent is that detection rules live downstream and key
// off `objectRef.resource`, `verb`, etc.; severity scoring is the
// detection engine's job, not the webhook's.
package handler

import (
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/beenuar/aisoc/services/ingest/internal/normalizer"
	"github.com/go-chi/chi/v5"
	"github.com/rs/zerolog/log"
)

// k8sAuditConnectorType is the connector_type stamped on every
// normalized event from this route. Must match the `kubernetes_audit`
// key in connectorProfiles — that's how the normalizer finds the right
// field map and product metadata.
const k8sAuditConnectorType = "kubernetes_audit"

// k8sAuditTokenHeader is the header the apiserver presents to prove
// it's allowed to push to this route. The value must equal
// cfg.K8sAuditSharedSecret. We chose a custom header rather than
// Authorization: Bearer to avoid colliding with the apiserver's own
// service-account-token plumbing in some hosted control planes.
const k8sAuditTokenHeader = "X-AiSOC-K8s-Token"

// k8sEventList mirrors the shape of audit.k8s.io/v1 EventList. We
// intentionally type Items as []json.RawMessage so the payload travels
// to the normalizer untouched — every interesting field
// (verb / objectRef / responseStatus / sourceIPs) is best parsed by
// the existing JSON-path-based normalizer config rather than by
// re-typing it here.
type k8sEventList struct {
	Kind       string            `json:"kind"`
	APIVersion string            `json:"apiVersion"`
	Items      []json.RawMessage `json:"items"`
}

// K8sAuditEvents handles POST /v1/ingest/k8s-audit/{tenant_id}.
//
// On the happy path it returns 200 with an IngestResponse summarizing
// counts, matching IngestEvents shape so apiserver operators see the
// same JSON regardless of which AiSOC ingest endpoint they pointed at.
// The apiserver's webhook backend treats any 2xx as success and won't
// retry, so we only return non-2xx for genuine "do not deliver this
// batch again" or "fix your config" conditions.
func (h *Handler) K8sAuditEvents(w http.ResponseWriter, r *http.Request) {
	// 1. The route is disabled at install time unless an operator
	// explicitly sets a shared secret. Returning 503 here (not 401)
	// is deliberate — apiserver operators get a louder signal that
	// the *server* isn't ready, not that *they* did something wrong.
	if h.cfg.K8sAuditSharedSecret == "" {
		writeError(w, http.StatusServiceUnavailable,
			"kubernetes audit webhook not enabled on this AiSOC installation")
		return
	}

	// 2. Tenant comes from the URL path, set by the chi route pattern.
	// This is the only auth boundary that ties an event to a specific
	// AiSOC tenant on this code path, which is why the secret is
	// installation-wide rather than per-tenant — the tenant binding
	// happens at apiserver-config time when the operator pastes the
	// URL into the audit webhook kubeconfig.
	tenantID := chi.URLParam(r, "tenant_id")
	if tenantID == "" {
		writeError(w, http.StatusBadRequest, "missing tenant_id in path")
		return
	}

	// 3. Constant-time secret comparison. If a header is missing the
	// length mismatch obviously fails, but ConstantTimeCompare also
	// covers the partial-prefix-match attacker. We log misses at warn
	// because brute-forcing this header is a reasonable thing to alert
	// on at the SIEM layer.
	presented := r.Header.Get(k8sAuditTokenHeader)
	expected := h.cfg.K8sAuditSharedSecret
	if subtle.ConstantTimeCompare([]byte(presented), []byte(expected)) != 1 {
		log.Warn().
			Str("tenant_id", tenantID).
			Str("remote_addr", r.RemoteAddr).
			Msg("k8s-audit webhook: shared-secret mismatch")
		writeError(w, http.StatusUnauthorized, "invalid or missing X-AiSOC-K8s-Token")
		return
	}

	// 4. Cap body size before we pay the cost of decoding. Without this,
	// a misconfigured apiserver could push a 1 GiB batch and OOM the
	// ingest pod. The default is 16 MiB which is generous for the
	// apiserver's own ~10 MiB batch ceiling.
	bodyLimit := h.cfg.K8sAuditMaxBodyBytes
	if bodyLimit <= 0 {
		bodyLimit = 16 * 1024 * 1024
	}
	bodyReader := http.MaxBytesReader(w, r.Body, bodyLimit)
	body, err := io.ReadAll(bodyReader)
	if err != nil {
		// http.MaxBytesReader returns *http.MaxBytesError on overflow.
		// Either way the right answer for the apiserver is 413 — it
		// will keep the batch around and probably retry with a smaller
		// one if the operator tightened audit-batch-max-size.
		log.Warn().Err(err).Str("tenant_id", tenantID).Msg("k8s-audit webhook: body read failed or oversized")
		writeError(w, http.StatusRequestEntityTooLarge,
			fmt.Sprintf("audit batch exceeds maximum of %d bytes", bodyLimit))
		return
	}

	// 5. Parse the EventList wrapper. We deliberately don't validate
	// kind / apiVersion strictly — the apiserver might be slightly
	// older or newer than what we know about, and rejecting on those
	// fields would prevent legitimate audit traffic from getting
	// through. We do want to reject obvious mis-targeted POSTs (some
	// other client pointed at this URL by accident), so a missing
	// `items` field becomes a 400.
	var list k8sEventList
	if err := json.Unmarshal(body, &list); err != nil {
		writeError(w, http.StatusBadRequest, "invalid EventList JSON: "+err.Error())
		return
	}

	// 6. An empty batch is normal — the apiserver's audit-batch-period
	// can fire even if no requests came in. Returning 200 with zero
	// counts is the polite answer.
	if len(list.Items) == 0 {
		writeJSON(w, http.StatusOK, IngestResponse{RequestID: newRequestID()})
		return
	}

	// 7. Per-batch cap. We use the global MaxBatchSize ceiling so a
	// runaway audit policy can't pump a million-item batch through and
	// stall the Kafka writer. The apiserver will retry the rejected
	// batch unchanged, so the operator gets a visible signal in the
	// apiserver logs and can tighten audit-batch-max-size.
	if len(list.Items) > h.cfg.MaxBatchSize {
		writeError(w, http.StatusRequestEntityTooLarge,
			fmt.Sprintf("batch size %d exceeds maximum of %d", len(list.Items), h.cfg.MaxBatchSize))
		return
	}

	// 8. Normalize each item. ConnectorID is a synthetic-but-stable
	// string — the apiserver doesn't carry connector identity through
	// audit, so we derive one per tenant. That keeps Kafka partition
	// keys (tenant + event id) well-distributed without forcing the
	// operator to invent a connector id at apiserver-config time.
	connectorID := "kubernetes-audit-" + tenantID
	receivedAt := time.Now().UTC().Format(time.RFC3339Nano)

	normalized := make([]*normalizer.NormalizedEvent, 0, len(list.Items))
	errs := []string{}
	rejected := 0

	for i, raw := range list.Items {
		var payload map[string]interface{}
		if err := json.Unmarshal(raw, &payload); err != nil {
			log.Warn().Err(err).Int("index", i).
				Str("tenant_id", tenantID).
				Msg("k8s-audit webhook: skipping item with invalid JSON")
			errs = append(errs, fmt.Sprintf("item %d: %s", i, err.Error()))
			rejected++
			continue
		}

		event, err := h.norm.Normalize(&normalizer.RawEvent{
			ConnectorID:   connectorID,
			ConnectorType: k8sAuditConnectorType,
			TenantID:      tenantID,
			ReceivedAt:    receivedAt,
			Payload:       payload,
			SourceFormat:  "k8s_audit_v1",
		})
		if err != nil {
			log.Warn().Err(err).Int("index", i).
				Str("tenant_id", tenantID).
				Msg("k8s-audit webhook: normalization failed")
			errs = append(errs, fmt.Sprintf("item %d: %s", i, err.Error()))
			rejected++
			continue
		}

		normalized = append(normalized, event)
	}

	// 9. Publish normalized events as one Kafka batch. If the publish
	// itself fails we return 5xx so the apiserver retries — losing
	// audit events to a transient broker hiccup would be a real
	// detection-coverage hole.
	if len(normalized) > 0 {
		if err := h.pub.PublishBatch(r.Context(), normalized); err != nil {
			log.Error().Err(err).
				Str("tenant_id", tenantID).
				Int("count", len(normalized)).
				Msg("k8s-audit webhook: kafka publish failed")
			writeError(w, http.StatusInternalServerError, "failed to publish events")
			return
		}
	}

	log.Info().
		Str("tenant_id", tenantID).
		Int("accepted", len(normalized)).
		Int("rejected", rejected).
		Msg("k8s-audit webhook: batch processed")

	writeJSON(w, http.StatusOK, IngestResponse{
		Accepted:  len(normalized),
		Rejected:  rejected,
		RequestID: newRequestID(),
		Errors:    errs,
	})
}
