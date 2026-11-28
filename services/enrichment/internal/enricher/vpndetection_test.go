package enricher

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func vpndetectionServer(t *testing.T, status int, body string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer key" {
			t.Errorf("expected Authorization=Bearer key, got %q", got)
		}
		if r.URL.RawQuery != "" {
			t.Errorf("the key must not travel in the URL, got query %q", r.URL.RawQuery)
		}
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
}

func TestVPNDetectionEnrichIP_ParsesVPNAndNetwork(t *testing.T) {
	// A live answer for a Mullvad exit, 2026-11-27.
	srv := vpndetectionServer(t, http.StatusOK, `{
      "ip": "185.65.135.230", "is_bogon": false, "is_vpn": true, "is_relay": false,
      "is_tor": false, "is_anycast": false, "relay": {}, "tor": {},
      "location": {"country": "SE", "country_name": "Sweden"},
      "asn": {"asn": 39351, "name": "31173 Services AB", "type": "isp"},
      "hostname": ""
    }`)
	defer srv.Close()

	c := NewVPNDetectionClient("key")
	c.baseURL = srv.URL
	res, err := c.EnrichIP(context.Background(), "185.65.135.230")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res == nil || !res.IsVPN || res.IsTOR {
		t.Fatalf("expected a VPN and no Tor, got %+v", res)
	}
	if g := res.GeoLocation; g == nil || g.CountryCode != "SE" || g.ASN != 39351 || g.ASOrg != "31173 Services AB" {
		t.Errorf("country and ASN not mapped: %+v", res.GeoLocation)
	}
	if len(res.Tags) != 1 || res.Tags[0] != "vpn" {
		t.Errorf("expected the vpn tag alone, got %v", res.Tags)
	}
	if res.RiskScore != 0 {
		t.Errorf("vpndetection must not assign risk, got %v", res.RiskScore)
	}
	if len(res.Sources) != 1 || res.Sources[0].Name != "vpndetection" {
		t.Errorf("source not named: %+v", res.Sources)
	}
}

func TestVPNDetectionEnrichIP_TorAndRelay(t *testing.T) {
	srv := vpndetectionServer(t, http.StatusOK, `{
      "ip": "172.224.226.1", "is_bogon": false, "is_vpn": false, "is_relay": true, "is_tor": true,
      "relay": {"provider": "apple_private_relay", "provider_name": "Apple iCloud Private Relay"},
      "tor": {"provider": "", "confidence": "high"},
      "location": {"country": "GB"}, "asn": {"asn": 36183, "name": "Akamai Technologies, Inc."}
    }`)
	defer srv.Close()

	c := NewVPNDetectionClient("key")
	c.baseURL = srv.URL
	res, err := c.EnrichIP(context.Background(), "172.224.226.1")
	if err != nil || res == nil {
		t.Fatalf("unexpected result: res=%v err=%v", res, err)
	}
	if !res.IsTOR || res.IsVPN {
		t.Errorf("flags not mapped: tor=%v vpn=%v", res.IsTOR, res.IsVPN)
	}
	want := []string{"tor", "privacy-relay", "relay:apple_private_relay"}
	if len(res.Tags) != len(want) {
		t.Fatalf("expected tags %v, got %v", want, res.Tags)
	}
	for i := range want {
		if res.Tags[i] != want[i] {
			t.Errorf("expected tags %v, got %v", want, res.Tags)
		}
	}
}

func TestVPNDetectionEnrichIP_BogonIsNoResult(t *testing.T) {
	srv := vpndetectionServer(t, http.StatusOK, `{"ip": "10.0.0.1", "is_bogon": true, "is_vpn": false}`)
	defer srv.Close()

	c := NewVPNDetectionClient("key")
	c.baseURL = srv.URL
	res, err := c.EnrichIP(context.Background(), "10.0.0.1")
	if err != nil || res != nil {
		t.Errorf("a bogon must return nothing, got res=%v err=%v", res, err)
	}
}

func TestVPNDetectionEnrichIP_HTTPErrorIsAnError(t *testing.T) {
	srv := vpndetectionServer(t, http.StatusBadRequest, `{"error": "not a valid IP address"}`)
	defer srv.Close()

	c := NewVPNDetectionClient("key")
	c.baseURL = srv.URL
	if _, err := c.EnrichIP(context.Background(), "not-an-ip"); err == nil {
		t.Error("expected an error for HTTP 400")
	}
}

func TestVPNDetectionEnrichIP_EmptyKeyIsNoOp(t *testing.T) {
	c := NewVPNDetectionClient("")
	res, err := c.EnrichIP(context.Background(), "185.65.135.230")
	if err != nil || res != nil {
		t.Errorf("empty key must no-op, got res=%v err=%v", res, err)
	}
}
