package enricher

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestURLScanEnrichDomain_BrandImpersonationIsPhishing(t *testing.T) {
	body := `{
      "results": [
        {"task": {"url": "http://paypa1-login.example", "time": "2026-11-01T10:00:00.000Z"},
         "page": {"domain": "paypa1-login.example", "url": "http://paypa1-login.example"},
         "brand": [{"name": "PayPal"}],
         "_id": "abc"}
      ],
      "total": 1
    }`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("API-Key"); got != "uk" {
			t.Errorf("expected API-Key header uk, got %q", got)
		}
		if q := r.URL.Query().Get("q"); !strings.Contains(q, "domain:") {
			t.Errorf("expected domain query, got %q", q)
		}
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()

	c := NewURLScanClient("uk")
	c.baseURL = srv.URL
	res, err := c.EnrichDomain(context.Background(), "paypa1-login.example")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res == nil {
		t.Fatal("expected a result")
	}
	if res.RiskScore != 70.0 || res.ThreatCategory != "phishing" {
		t.Errorf("brand impersonation must flag phishing, got risk=%v cat=%q", res.RiskScore, res.ThreatCategory)
	}
	if res.BrandRisk == nil || res.BrandRisk.LookalikeOf != "PayPal" || !res.BrandRisk.Phishing {
		t.Errorf("brand risk not mapped: %+v", res.BrandRisk)
	}
	if res.LastSeen == nil {
		t.Error("expected LastSeen from scan time")
	}
}

func TestURLScanEnrichURL_NoPriorScanIsNil(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"results": [], "total": 0}`))
	}))
	defer srv.Close()
	c := NewURLScanClient("uk")
	c.baseURL = srv.URL
	res, err := c.EnrichURL(context.Background(), "http://unknown.example/")
	if err != nil || res != nil {
		t.Errorf("no prior scan must return nil,nil; got res=%v err=%v", res, err)
	}
}

func TestURLScanEnrichDomain_EmptyKeyIsNoOp(t *testing.T) {
	c := NewURLScanClient("")
	res, err := c.EnrichDomain(context.Background(), "x.example")
	if err != nil || res != nil {
		t.Errorf("empty key must no-op, got res=%v err=%v", res, err)
	}
}
