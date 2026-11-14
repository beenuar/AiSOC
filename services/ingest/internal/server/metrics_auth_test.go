// metrics_auth_test.go — the guard on GET /metrics.
//
// docker-compose.prod.yml makes METRICS_TOKEN a required variable for
// this service with the message "guards /metrics outside development",
// and scripts/ensure_env.py generates it. The ingest router mounted
// promhttp directly and read no token at all, so the guard the compose
// file promised did not exist here while it did exist in services/api
// and services/agents.
//
// The semantics under test are the sibling's, not a new set: a token
// when METRICS_TOKEN is set, and a refusal outside a development-class
// environment when it is not. Liveness stays open either way — pulling
// /livez and /readyz behind a credential would take the pipeline's front
// door out of a load balancer to protect a scrape endpoint.
package server

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/beenuar/aisoc/services/ingest/internal/config"
	"github.com/beenuar/aisoc/services/ingest/internal/handler"
)

func metricsRouter(t *testing.T) http.Handler {
	t.Helper()
	// A nil normalizer and publisher are enough: nothing below the router
	// is exercised by a /metrics or /livez request.
	h := handler.New(nil, nil, &config.Config{})
	return New(&config.Config{}, h, nil, nil, nil).httpServer.Handler
}

func get(t *testing.T, router http.Handler, path, authorization string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	if authorization != "" {
		req.Header.Set("Authorization", authorization)
	}
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	return rec
}

// TestMetricsRefusesAnUnauthenticatedScrapeWhenTokenIsSet is the
// reporter's proof of concept: request /metrics with no token while
// METRICS_TOKEN is set. On the tree this was written against it returned
// 200 and the full series.
func TestMetricsRefusesAnUnauthenticatedScrapeWhenTokenIsSet(t *testing.T) {
	t.Setenv("METRICS_TOKEN", "s3cret-metrics-token")
	router := metricsRouter(t)

	rec := get(t, router, "/metrics", "")

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated scrape returned %d with METRICS_TOKEN set; want 401. body=%.200s",
			rec.Code, rec.Body.String())
	}
}

// TestMetricsAcceptsTheConfiguredToken is the positive control. Without
// it a gate that refused every scrape unconditionally would pass the test
// above while making the endpoint useless.
func TestMetricsAcceptsTheConfiguredToken(t *testing.T) {
	t.Setenv("METRICS_TOKEN", "s3cret-metrics-token")
	router := metricsRouter(t)

	rec := get(t, router, "/metrics", "Bearer s3cret-metrics-token")

	if rec.Code != http.StatusOK {
		t.Fatalf("the configured token was refused: %d %.200s", rec.Code, rec.Body.String())
	}
}

// TestMetricsRefusesAWrongToken keeps the comparison honest: a gate that
// only checked for the presence of an Authorization header would pass
// both tests above.
func TestMetricsRefusesAWrongToken(t *testing.T) {
	t.Setenv("METRICS_TOKEN", "s3cret-metrics-token")
	router := metricsRouter(t)

	rec := get(t, router, "/metrics", "Bearer not-the-token")

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("a wrong token was accepted: %d", rec.Code)
	}
}

// TestMetricsRefusesWhenUnconfiguredOutsideDevelopment mirrors the
// sibling's second rule. An operator who never set METRICS_TOKEN in
// production has not opted into an open endpoint; they have a gap, and
// the refusal is what tells them so.
func TestMetricsRefusesWhenUnconfiguredOutsideDevelopment(t *testing.T) {
	t.Setenv("METRICS_TOKEN", "")
	t.Setenv("ENV", "production")
	t.Setenv("ENVIRONMENT", "production")
	router := metricsRouter(t)

	rec := get(t, router, "/metrics", "")

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("an unconfigured /metrics served %d in production; want 401", rec.Code)
	}
	if !contains(rec.Body.String(), "METRICS_TOKEN") {
		t.Fatalf("the refusal does not name the variable an operator must set: %.200s", rec.Body.String())
	}
}

// TestMetricsStaysOpenInDevelopment keeps `make up` usable: a local
// stack has no token and should still expose its own metrics.
func TestMetricsStaysOpenInDevelopment(t *testing.T) {
	t.Setenv("METRICS_TOKEN", "")
	t.Setenv("ENV", "development")
	t.Setenv("ENVIRONMENT", "development")
	router := metricsRouter(t)

	rec := get(t, router, "/metrics", "")

	if rec.Code != http.StatusOK {
		t.Fatalf("development scrape returned %d; want 200", rec.Code)
	}
}

// TestLivenessStaysUnauthenticated is the half that must not regress.
// An orchestrator's probe carries no credential, so putting /livez or
// /readyz behind the metrics token would fail every container.
func TestLivenessStaysUnauthenticated(t *testing.T) {
	t.Setenv("METRICS_TOKEN", "s3cret-metrics-token")
	t.Setenv("ENV", "production")
	t.Setenv("ENVIRONMENT", "production")
	router := metricsRouter(t)

	for _, path := range []string{"/health", "/livez"} {
		rec := get(t, router, path, "")
		if rec.Code == http.StatusUnauthorized {
			t.Fatalf("%s requires a credential; an orchestrator probe cannot send one", path)
		}
	}
}

func contains(haystack, needle string) bool {
	return len(haystack) >= len(needle) && (func() bool {
		for i := 0; i+len(needle) <= len(haystack); i++ {
			if haystack[i:i+len(needle)] == needle {
				return true
			}
		}
		return false
	})()
}
