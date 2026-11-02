package handler

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/beenuar/aisoc/enrichment/internal/enricher"
)

// Depth plan wave 2, item 8.3.
//
// The limiter is tested through the real handler rather than directly,
// because the defect it closes is not a missing algorithm. `RATE_LIMIT_RPS`
// and `RATE_LIMIT_BURST` were parsed, assigned to struct fields and read by
// nothing: a correct token bucket with no caller would have looked exactly
// the same from outside, and would have been exactly as useless.
//
// Every grant below has a partner refusal, for the same reason.

func post(h *Handler, body map[string]any) *httptest.ResponseRecorder {
	payload, _ := json.Marshal(body)
	request := httptest.NewRequest(http.MethodPost, "/enrich", bytes.NewReader(payload))
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
	body := map[string]any{"ioc_type": "ip", "value": "198.51.100.9", "tenant_id": "t-a"}

	first := post(h, body)
	if first.Code == http.StatusTooManyRequests {
		t.Fatal("the first call within burst was refused; the limiter is not granting at all")
	}

	second := post(h, body)
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

	if code := post(h, map[string]any{"ioc_type": "ip", "value": "198.51.100.9", "tenant_id": "t-a"}).Code; code == http.StatusTooManyRequests {
		t.Fatal("tenant A was refused its first call")
	}
	if code := post(h, map[string]any{"ioc_type": "ip", "value": "198.51.100.9", "tenant_id": "t-b"}).Code; code == http.StatusTooManyRequests {
		t.Fatal("tenant B was refused because tenant A had spent the budget; the limiter is not per tenant")
	}
}

func TestAnUntenantedRequestIsLimitedRatherThanExempt(t *testing.T) {
	// A missing tenant must not be the way around the limiter. Everything
	// with no tenant shares one bucket; nothing bypasses.
	h := New(realEnricher(), enricher.NewRateLimiter(1, 1))
	body := map[string]any{"ioc_type": "ip", "value": "198.51.100.9"}

	_ = post(h, body)
	if code := post(h, body).Code; code != http.StatusTooManyRequests {
		t.Fatalf("an untenanted second call answered %d, want 429", code)
	}
}

func TestANilLimiterDoesNotRefuse(t *testing.T) {
	// The upgrade path. A caller that has not been updated must keep
	// working rather than have enrichment silently switch off.
	h := New(realEnricher(), nil)
	for i := 0; i < 5; i++ {
		_ = post(h, map[string]any{"ioc_type": "ip", "value": "198.51.100.9"})
	}
	if code := post(h, map[string]any{"ioc_type": "ip", "value": "198.51.100.9"}).Code; code == http.StatusTooManyRequests {
		t.Fatal("a nil limiter refused a request")
	}
}
