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

// Depth plan wave 2, item 8.3 — revised for GHSA-qf6m-hgwv-65f9.
//
// The limiter is tested through the real handler rather than directly,
// because the defect it closes is not a missing algorithm. `RATE_LIMIT_RPS`
// and `RATE_LIMIT_BURST` were parsed, assigned to struct fields and read by
// nothing: a correct token bucket with no caller would have looked exactly
// the same from outside, and would have been exactly as useless.
//
// The bucket key then moved once more: it was the *body's* `tenant_id`, so a
// caller rotating that string minted a fresh bucket per request and the
// limiter limited nothing. It is now the authenticated principal's tenant —
// the one identity a caller cannot choose per request — so these tests drive
// the handler with principals, the way the tenantauth middleware does.
//
// Every grant below has a partner refusal, for the same reason.

const (
	tenantA = "aaaaaaaa-0000-0000-0000-00000000000a"
	tenantB = "bbbbbbbb-0000-0000-0000-00000000000b"
)

func console(tenant string) tenantauth.Principal {
	return tenantauth.Principal{TenantID: tenant, Subject: "console:test", Role: "soc_analyst"}
}

func post(h *Handler, p tenantauth.Principal, body map[string]any) *httptest.ResponseRecorder {
	payload, _ := json.Marshal(body)
	request := httptest.NewRequest(http.MethodPost, "/enrich", bytes.NewReader(payload))
	request = request.WithContext(tenantauth.WithPrincipal(request.Context(), p))
	recorder := httptest.NewRecorder()
	h.EnrichIOC(recorder, request)
	return recorder
}

// realEnricher is the production orchestrator with no providers configured
// and no cache. Granted calls therefore reach the real Enrich, run the real
// tenant gate (which denies everything, because the request names no
// providers) and return an empty result. A nil enricher would have been
// simpler and would have meant the granted path was never exercised, which
// is the half that has to work.
func realEnricher() *enricher.Enricher { return enricher.New(enricher.Config{}) }

func TestTheHandlerRefusesPastTheLimit(t *testing.T) {
	h := New(realEnricher(), enricher.NewRateLimiter(1, 1))
	body := map[string]any{"ioc_type": "ip", "value": "198.51.100.9"}

	first := post(h, console(tenantA), body)
	if first.Code == http.StatusTooManyRequests {
		t.Fatal("the first call within burst was refused; the limiter is not granting at all")
	}

	second := post(h, console(tenantA), body)
	if second.Code != http.StatusTooManyRequests {
		t.Fatalf("second immediate call answered %d, want 429; the limiter does not refuse", second.Code)
	}
	if second.Header().Get("Retry-After") == "" {
		t.Error("a 429 with no Retry-After tells a client to guess")
	}
	if !strings.Contains(second.Body.String(), "rate limit") {
		t.Errorf("the refusal does not say why: %s", second.Body.String())
	}
}

func TestOneTenantCannotSpendAnothersBudget(t *testing.T) {
	h := New(realEnricher(), enricher.NewRateLimiter(1, 1))
	body := map[string]any{"ioc_type": "ip", "value": "198.51.100.9"}

	if code := post(h, console(tenantA), body).Code; code == http.StatusTooManyRequests {
		t.Fatal("tenant A was refused its first call")
	}
	if code := post(h, console(tenantB), body).Code; code == http.StatusTooManyRequests {
		t.Fatal("tenant B was refused because tenant A had spent the budget; the limiter is not per tenant")
	}
}

func TestRotatingTheBodyTenantDoesNotMintBuckets(t *testing.T) {
	// The advisory's limiter PoC: with the bucket keyed on the body,
	// `tenant_id: "probe-b"` was admitted after `"probe-a"` was refused.
	// The key is the principal now, so the rotation has nowhere to go: a
	// body naming anything but the caller's own tenant is refused outright,
	// and an empty one inherits the caller's bucket.
	h := New(realEnricher(), enricher.NewRateLimiter(1, 1))

	if code := post(h, console(tenantA), map[string]any{"ioc_type": "ip", "value": "198.51.100.9", "tenant_id": tenantA}).Code; code == http.StatusTooManyRequests {
		t.Fatal("tenant A was refused its first call")
	}
	if code := post(h, console(tenantA), map[string]any{"ioc_type": "ip", "value": "198.51.100.9", "tenant_id": "probe-b"}).Code; code != http.StatusForbidden {
		t.Fatalf("a rotated body tenant answered %d, want 403", code)
	}
	if code := post(h, console(tenantA), map[string]any{"ioc_type": "ip", "value": "198.51.100.9"}).Code; code != http.StatusTooManyRequests {
		t.Fatalf("the same principal's next call answered %d, want 429; the rotation bought a fresh bucket", code)
	}
}

func TestANilLimiterDoesNotRefuse(t *testing.T) {
	// The upgrade path. A caller that has not been updated must keep
	// working rather than have enrichment silently switch off.
	h := New(realEnricher(), nil)
	for i := 0; i < 5; i++ {
		_ = post(h, console(tenantA), map[string]any{"ioc_type": "ip", "value": "198.51.100.9"})
	}
	if code := post(h, console(tenantA), map[string]any{"ioc_type": "ip", "value": "198.51.100.9"}).Code; code == http.StatusTooManyRequests {
		t.Fatal("a nil limiter refused a request")
	}
}
