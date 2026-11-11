package enricher

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestIPInfoEnrichIP_ParsesGeoASNAndPrivacy(t *testing.T) {
	body := `{
      "ip": "8.8.8.8",
      "city": "Mountain View",
      "region": "California",
      "country": "US",
      "loc": "37.3860,-122.0838",
      "org": "AS15169 Google LLC",
      "privacy": {"vpn": false, "tor": true, "proxy": false, "hosting": true}
    }`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer tok" {
			t.Errorf("expected Authorization=Bearer tok, got %q", got)
		}
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()

	c := NewIPInfoClient("tok")
	c.baseURL = srv.URL
	res, err := c.EnrichIP(context.Background(), "8.8.8.8")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res == nil || res.GeoLocation == nil {
		t.Fatal("expected geo result")
	}
	g := res.GeoLocation
	if g.ASN != 15169 || g.ASOrg != "Google LLC" {
		t.Errorf("org not split into ASN/ASOrg: asn=%d org=%q", g.ASN, g.ASOrg)
	}
	if g.City != "Mountain View" || g.CountryCode != "US" {
		t.Errorf("geo fields not mapped: %+v", g)
	}
	if g.Latitude == 0 || g.Longitude == 0 {
		t.Errorf("loc not parsed: lat=%v lng=%v", g.Latitude, g.Longitude)
	}
	// Privacy block → tor/hosting flags.
	if !res.IsTOR || !res.IsDatacenter {
		t.Errorf("privacy flags not mapped: tor=%v datacenter=%v", res.IsTOR, res.IsDatacenter)
	}
	// IPInfo is context, not a verdict — no risk.
	if res.RiskScore != 0 {
		t.Errorf("ipinfo must not assign risk, got %v", res.RiskScore)
	}
}

func TestIPInfoEnrichIP_EmptyTokenIsNoOp(t *testing.T) {
	c := NewIPInfoClient("")
	res, err := c.EnrichIP(context.Background(), "8.8.8.8")
	if err != nil || res != nil {
		t.Errorf("empty token must no-op, got res=%v err=%v", res, err)
	}
}
