// Tenant resolution on the enrichment handlers (GHSA-qf6m-hgwv-65f9).
//
// The handlers used to read `tenant_id` and `force` straight from the body of
// an unauthenticated request. The middleware now authenticates; these tests
// pin what the handlers do with the principal it resolves: the body's tenant
// claim is intersected with the credential, never believed on its own.
package handler

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/beenuar/aisoc/enrichment/internal/enricher"
	"github.com/beenuar/aisoc/enrichment/internal/tenantauth"
)

func TestAHandlerWithoutAPrincipalRefuses(t *testing.T) {
	// The route is registered behind the middleware; a request arriving
	// without a principal is a wiring defect and must refuse, not guess.
	h := New(realEnricher(), nil)
	payload, _ := json.Marshal(map[string]any{"ioc_type": "ip", "value": "198.51.100.9"})

	rec := httptest.NewRecorder()
	h.EnrichIOC(rec, httptest.NewRequest(http.MethodPost, "/enrich", bytes.NewReader(payload)))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("EnrichIOC with no principal answered %d, want 401", rec.Code)
	}

	bulk, _ := json.Marshal(map[string]any{"items": []map[string]any{{"ioc_type": "ip", "value": "198.51.100.9"}}})
	rec = httptest.NewRecorder()
	h.BulkEnrich(rec, httptest.NewRequest(http.MethodPost, "/enrich/bulk", bytes.NewReader(bulk)))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("BulkEnrich with no principal answered %d, want 401", rec.Code)
	}
}

func TestTheBodyCannotNameAnotherTenant(t *testing.T) {
	h := New(realEnricher(), nil)

	cross := post(h, console(tenantA), map[string]any{"ioc_type": "ip", "value": "198.51.100.9", "tenant_id": tenantB})
	if cross.Code != http.StatusForbidden {
		t.Fatalf("a body naming another tenant answered %d, want 403", cross.Code)
	}
	if !strings.Contains(cross.Body.String(), "does not act for") {
		t.Errorf("the refusal does not say why: %s", cross.Body.String())
	}

	own := post(h, console(tenantA), map[string]any{"ioc_type": "ip", "value": "198.51.100.9", "tenant_id": strings.ToUpper(tenantA)})
	if own.Code != http.StatusOK {
		t.Fatalf("a body naming the caller's own tenant (any case) answered %d, want 200", own.Code)
	}

	inherited := post(h, console(tenantA), map[string]any{"ioc_type": "ip", "value": "198.51.100.9"})
	if inherited.Code != http.StatusOK {
		t.Fatalf("an empty body tenant answered %d, want 200 (inherits the principal's)", inherited.Code)
	}
}

func TestBulkItemsAreScopedIndividually(t *testing.T) {
	h := New(realEnricher(), nil)
	body := map[string]any{"items": []map[string]any{
		{"ioc_type": "ip", "value": "198.51.100.9", "tenant_id": tenantA},
		{"ioc_type": "ip", "value": "198.51.100.10", "tenant_id": tenantB},
		{"ioc_type": "ip", "value": "198.51.100.11"},
	}}
	payload, _ := json.Marshal(body)
	request := httptest.NewRequest(http.MethodPost, "/enrich/bulk", bytes.NewReader(payload))
	request = request.WithContext(tenantauth.WithPrincipal(request.Context(), console(tenantA)))
	rec := httptest.NewRecorder()
	h.BulkEnrich(rec, request)

	if rec.Code != http.StatusOK {
		t.Fatalf("bulk answered %d, want 200 with per-item outcomes", rec.Code)
	}
	var resp enricher.BulkEnrichResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("bulk response did not parse: %v", err)
	}
	if resp.Errors != 1 {
		t.Fatalf("bulk reported %d errored items, want exactly 1 (the foreign tenant)", resp.Errors)
	}
	var foreignRefused bool
	for _, r := range resp.Results {
		if r.Value == "198.51.100.10" {
			for _, e := range r.EnrichmentErrors {
				if strings.Contains(e, "does not act for") {
					foreignRefused = true
				}
			}
		}
	}
	if !foreignRefused {
		t.Fatal("the foreign-tenant item was not refused with the named reason")
	}
}
