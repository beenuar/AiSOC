package enricher

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

const tiSearchBody = `{
  "total": 2,
  "iocs": [
    {"value": "185.220.101.88", "type": "ipv4-addr", "source": "otx",
     "tags": ["apt", "c2"], "malware_families": ["PlugX"], "attack_ids": ["T1071"],
     "pulse_name": "APT demo pulse"},
    {"value": "185.220.101.88", "type": "ipv4-addr", "source": "misp",
     "tags": ["phishing"], "malware_families": [], "attack_ids": ["T1566"]}
  ]
}`

func TestThreatIntelEnrichIP_FeedMatchEmitsSourcesAndClassification(t *testing.T) {
	var gotAuth, gotTenant, gotValue string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotTenant = r.Header.Get("X-AiSOC-Tenant-ID")
		gotValue = r.URL.Query().Get("value")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(tiSearchBody))
	}))
	defer srv.Close()

	c := NewThreatIntelClient(srv.URL, "svc-token")
	ctx := WithTenant(context.Background(), "11111111-1111-1111-1111-111111111111")

	res, err := c.EnrichIP(ctx, "185.220.101.88")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res == nil {
		t.Fatal("expected a result for a feed match")
	}

	// Request carried the service credential and the tenant.
	if gotAuth != "Bearer svc-token" {
		t.Errorf("Authorization not sent: %q", gotAuth)
	}
	if gotTenant != "11111111-1111-1111-1111-111111111111" {
		t.Errorf("tenant header not sent: %q", gotTenant)
	}
	if gotValue != "185.220.101.88" {
		t.Errorf("value param not sent: %q", gotValue)
	}

	// Both feed sources must surface by their exact names so the fusion
	// scorer's _SOURCE_TO_TI_KEY maps them into the TI confidence factor.
	names := map[string]bool{}
	for _, s := range res.Sources {
		names[s.Name] = true
	}
	if !names["otx"] || !names["misp"] {
		t.Errorf("expected otx + misp sources, got %+v", res.Sources)
	}
	// A curated feed match is a real malicious signal.
	if res.RiskScore <= 0 {
		t.Errorf("expected positive risk for a feed match, got %v", res.RiskScore)
	}
	// Classification is lifted from the pulse metadata.
	if !contains(res.Classification.MITRETechniques, "T1071") || !contains(res.Classification.MITRETechniques, "T1566") {
		t.Errorf("attack_ids not mapped to MITRE techniques: %+v", res.Classification.MITRETechniques)
	}
	if !contains(res.Classification.Malware, "PlugX") {
		t.Errorf("malware_families not mapped: %+v", res.Classification.Malware)
	}
}

func TestThreatIntelEnrichIP_NoMatchIsNil(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"total": 0, "iocs": []}`))
	}))
	defer srv.Close()
	c := NewThreatIntelClient(srv.URL, "t")
	ctx := WithTenant(context.Background(), "11111111-1111-1111-1111-111111111111")
	res, err := c.EnrichIP(ctx, "8.8.8.8")
	if err != nil || res != nil {
		t.Errorf("no feed match must return nil,nil; got res=%v err=%v", res, err)
	}
}

func TestThreatIntelEnrichIP_NoTokenIsNoOp(t *testing.T) {
	c := NewThreatIntelClient("http://threatintel:8005", "")
	ctx := WithTenant(context.Background(), "11111111-1111-1111-1111-111111111111")
	res, err := c.EnrichIP(ctx, "8.8.8.8")
	if err != nil || res != nil {
		t.Errorf("empty token must no-op, got res=%v err=%v", res, err)
	}
}

func TestThreatIntelEnrichIP_NoTenantIsNoOp(t *testing.T) {
	// Without a tenant the service call would 403, so skip it rather than fail.
	c := NewThreatIntelClient("http://threatintel:8005", "t")
	res, err := c.EnrichIP(context.Background(), "8.8.8.8")
	if err != nil || res != nil {
		t.Errorf("missing tenant must no-op, got res=%v err=%v", res, err)
	}
}

func contains(xs []string, want string) bool {
	for _, x := range xs {
		if x == want {
			return true
		}
	}
	return false
}
