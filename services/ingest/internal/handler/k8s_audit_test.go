// k8s_audit_test.go — auth/validation coverage for the Kubernetes
// apiserver audit-webhook target.
//
// These tests focus on the HTTP-edge behavior of K8sAuditEvents: what
// it returns and when, and what it never returns regardless of
// request shape. The behavior we care about most lives before we ever
// touch Kafka — the shared-secret check, the body-size cap, and the
// JSON envelope parse — because that's where every published audit
// event comes through. The Kafka publish path itself runs the same
// PublishBatch code shared with IngestEvents, so we don't redo that
// here; integration tests cover the round-trip.
package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/beenuar/aisoc/services/ingest/internal/config"
	"github.com/go-chi/chi/v5"
)

// newAuditHandler builds a Handler whose normalizer and publisher are
// nil. Every test below exits before either is dereferenced — these
// exercise the early-return guards (503/401/400/413) that protect the
// rest of the pipeline. If a future change to K8sAuditEvents causes a
// test to nil-panic, that's a real signal: the guard moved.
func newAuditHandler(secret string, maxBytes int64) *Handler {
	return &Handler{
		norm: nil,
		pub:  nil,
		cfg: &config.Config{
			K8sAuditSharedSecret: secret,
			K8sAuditMaxBodyBytes: maxBytes,
			MaxBatchSize:         500,
		},
	}
}

// auditReq builds a request with chi's URL-param machinery primed so
// chi.URLParam(req, "tenant_id") returns the value we want, without
// standing up a router. chi resolves URL params off a context value
// keyed on chi.RouteCtxKey; populating it directly is the documented
// pattern in chi's own tests.
func auditReq(t *testing.T, body []byte, tenantID, headerToken string) *http.Request {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/v1/ingest/k8s-audit/"+tenantID, bytes.NewReader(body))
	if headerToken != "" {
		req.Header.Set("X-AiSOC-K8s-Token", headerToken)
	}
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("tenant_id", tenantID)
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	return req
}

func TestK8sAuditEvents_DisabledByDefault(t *testing.T) {
	// A fresh install has no shared secret. Returning 503 (rather than
	// 401) is deliberate — the operator hasn't enabled the surface yet,
	// it's not that the apiserver presented bad credentials. Apiserver
	// operators reading their audit-webhook log get a clearer signal.
	h := newAuditHandler("", 16*1024*1024)
	rec := httptest.NewRecorder()
	h.K8sAuditEvents(rec, auditReq(t, []byte(`{"items":[]}`), "tenant-a", ""))

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("disabled webhook: status = %d, want %d", rec.Code, http.StatusServiceUnavailable)
	}
}

func TestK8sAuditEvents_RejectsMissingToken(t *testing.T) {
	h := newAuditHandler("expected-secret", 16*1024*1024)
	rec := httptest.NewRecorder()
	h.K8sAuditEvents(rec, auditReq(t, []byte(`{"items":[]}`), "tenant-a", ""))

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("missing token: status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

func TestK8sAuditEvents_RejectsWrongToken(t *testing.T) {
	h := newAuditHandler("expected-secret", 16*1024*1024)
	rec := httptest.NewRecorder()
	h.K8sAuditEvents(rec, auditReq(t, []byte(`{"items":[]}`), "tenant-a", "wrong-secret"))

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("wrong token: status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

func TestK8sAuditEvents_RejectsPartialPrefixToken(t *testing.T) {
	// Constant-time compare must reject a presented token that is a
	// strict prefix of the expected one. This catches a regression
	// where someone replaces subtle.ConstantTimeCompare with == plus
	// strings.HasPrefix.
	h := newAuditHandler("expected-secret-12345", 16*1024*1024)
	rec := httptest.NewRecorder()
	h.K8sAuditEvents(rec, auditReq(t, []byte(`{"items":[]}`), "tenant-a", "expected-secret"))

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("partial-prefix token: status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

func TestK8sAuditEvents_RejectsMissingTenantID(t *testing.T) {
	// chi normally won't dispatch a request without tenant_id at all,
	// but defense in depth: directly invoke the handler with an empty
	// path param to confirm it returns 400 rather than panicking or
	// publishing under a "" tenant.
	h := newAuditHandler("right-secret", 16*1024*1024)
	rec := httptest.NewRecorder()
	body := []byte(`{"items":[]}`)
	req := httptest.NewRequest(http.MethodPost, "/v1/ingest/k8s-audit/", bytes.NewReader(body))
	req.Header.Set("X-AiSOC-K8s-Token", "right-secret")
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("tenant_id", "")
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

	h.K8sAuditEvents(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("missing tenant: status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
}

func TestK8sAuditEvents_RejectsInvalidJSON(t *testing.T) {
	h := newAuditHandler("right-secret", 16*1024*1024)
	rec := httptest.NewRecorder()
	h.K8sAuditEvents(rec, auditReq(t, []byte(`not json`), "tenant-a", "right-secret"))

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("bad json: status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
}

func TestK8sAuditEvents_RejectsOversizedBody(t *testing.T) {
	// Cap small (1 KiB) and submit a body well over. Without this
	// guard a misconfigured apiserver could OOM the ingest pod.
	h := newAuditHandler("right-secret", 1024)
	rec := httptest.NewRecorder()

	big := bytes.Repeat([]byte("A"), 4096)
	body := append([]byte(`{"items":["`), big...)
	body = append(body, []byte(`"]}`)...)

	h.K8sAuditEvents(rec, auditReq(t, body, "tenant-a", "right-secret"))
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversize body: status = %d, want %d", rec.Code, http.StatusRequestEntityTooLarge)
	}
}

func TestK8sAuditEvents_RejectsBatchOverMaxBatchSize(t *testing.T) {
	// MaxBatchSize is per-batch, regardless of byte size. Helps catch
	// a runaway audit policy producing a million-item batch.
	h := newAuditHandler("right-secret", 16*1024*1024)
	h.cfg.MaxBatchSize = 2

	items := []string{`{"verb":"get"}`, `{"verb":"list"}`, `{"verb":"watch"}`}
	body := []byte(`{"items":[` + strings.Join(items, ",") + `]}`)

	rec := httptest.NewRecorder()
	h.K8sAuditEvents(rec, auditReq(t, body, "tenant-a", "right-secret"))

	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("over batch size: status = %d, want %d", rec.Code, http.StatusRequestEntityTooLarge)
	}
}

func TestK8sAuditEvents_AcceptsCorrectToken_EmptyBatch(t *testing.T) {
	// Empty batch is normal: the apiserver's audit-batch-period can
	// fire even when no requests landed. We must return 200, otherwise
	// the apiserver will retry the empty batch forever and tie up its
	// audit-webhook send queue.
	//
	// This case never reaches the publisher because there's nothing
	// to publish, so the nil pub field in newAuditHandler is fine.
	h := newAuditHandler("right-secret", 16*1024*1024)
	rec := httptest.NewRecorder()
	body := []byte(`{"kind":"EventList","apiVersion":"audit.k8s.io/v1","items":[]}`)
	h.K8sAuditEvents(rec, auditReq(t, body, "tenant-a", "right-secret"))

	if rec.Code != http.StatusOK {
		t.Fatalf("empty batch: status = %d body = %q, want %d", rec.Code, rec.Body.String(), http.StatusOK)
	}
	var resp map[string]interface{}
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if got, _ := resp["accepted"].(float64); got != 0 {
		t.Fatalf("empty batch: accepted=%v, want 0", resp["accepted"])
	}
	if got, _ := resp["rejected"].(float64); got != 0 {
		t.Fatalf("empty batch: rejected=%v, want 0", resp["rejected"])
	}
}
