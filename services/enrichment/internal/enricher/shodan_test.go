package enricher

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const shodanHostBody = `{
  "ip_str": "185.220.101.88",
  "ports": [22, 443],
  "hostnames": ["exit.example.net"],
  "tags": ["tor", "compromised"],
  "vulns": ["CVE-2021-44228"],
  "org": "Example Hosting",
  "isp": "Example ISP",
  "asn": "AS64500",
  "country_name": "Germany",
  "country_code": "DE",
  "city": "Frankfurt",
  "latitude": 50.11,
  "longitude": 8.68,
  "data": [
    {"port": 443, "transport": "tcp", "product": "nginx", "data": "Server: nginx\r\n",
     "vulns": {"CVE-2021-44228": {"verified": false}}}
  ]
}`

func TestShodanEnrichIP_MapsPortsVulnsGeoAndRisk(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.Query().Get("key"); got != "test-key" {
			t.Errorf("expected key=test-key, got %q", got)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(shodanHostBody))
	}))
	defer srv.Close()

	c := NewShodanClient("test-key")
	c.baseURL = srv.URL

	res, err := c.EnrichIP(context.Background(), "185.220.101.88")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res == nil {
		t.Fatal("expected a result, got nil")
	}

	// Open ports come from the per-service entries.
	if len(res.OpenPorts) != 1 || res.OpenPorts[0].Port != 443 || res.OpenPorts[0].Service != "nginx" {
		t.Errorf("open ports not mapped: %+v", res.OpenPorts)
	}
	if len(res.OpenPorts[0].Vulns) != 1 || res.OpenPorts[0].Vulns[0] != "CVE-2021-44228" {
		t.Errorf("per-port vuln not mapped: %+v", res.OpenPorts[0].Vulns)
	}
	// Host-level vulnerabilities.
	if len(res.Vulnerabilities) != 1 || res.Vulnerabilities[0].CVE != "CVE-2021-44228" {
		t.Errorf("host vulns not mapped: %+v", res.Vulnerabilities)
	}
	// Geo + ASN parsed from "AS64500".
	if res.GeoLocation == nil || res.GeoLocation.ASN != 64500 || res.GeoLocation.Country != "Germany" {
		t.Errorf("geo not mapped: %+v", res.GeoLocation)
	}
	// A malicious tag drives the risk to 85.
	if res.RiskScore != 85.0 {
		t.Errorf("expected risk 85 for compromised tag, got %v", res.RiskScore)
	}
	if len(res.DNSRecords) != 1 || res.DNSRecords[0] != "exit.example.net" {
		t.Errorf("hostnames not mapped to DNS records: %+v", res.DNSRecords)
	}
	if len(res.Sources) != 1 || res.Sources[0].Name != "shodan" {
		t.Errorf("source not recorded: %+v", res.Sources)
	}
}

func TestShodanEnrichIP_VulnsOnlyRaiseModerateRisk(t *testing.T) {
	body := `{"ip_str":"1.2.3.4","ports":[80],"vulns":["CVE-2020-0001"],"asn":"AS1"}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()

	c := NewShodanClient("k")
	c.baseURL = srv.URL
	res, err := c.EnrichIP(context.Background(), "1.2.3.4")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.RiskScore != 50.0 {
		t.Errorf("expected risk 50 for exposed vuln without malicious tag, got %v", res.RiskScore)
	}
}

func TestShodanEnrichIP_EmptyKeyIsNoOp(t *testing.T) {
	c := NewShodanClient("")
	res, err := c.EnrichIP(context.Background(), "1.2.3.4")
	if err != nil || res != nil {
		t.Errorf("empty key must no-op, got res=%v err=%v", res, err)
	}
}

func TestShodanEnrichIP_404IsNil(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	c := NewShodanClient("k")
	c.baseURL = srv.URL
	res, err := c.EnrichIP(context.Background(), "1.2.3.4")
	if err != nil || res != nil {
		t.Errorf("404 must return nil,nil; got res=%v err=%v", res, err)
	}
}

func TestShodanTransportErrorNeverCarriesTheKey(t *testing.T) {
	// A *url.Error stringifies the URL it failed on, and Shodan's contract
	// puts the key in the query string — the error path must redact it
	// before anything can log it.
	c := NewShodanClient("sekrit-key-value")
	c.baseURL = "http://127.0.0.1:1" // nothing listens on port 1

	_, err := c.EnrichIP(context.Background(), "198.51.100.7")
	if err == nil {
		t.Fatal("expected a transport error")
	}
	if strings.Contains(err.Error(), "sekrit-key-value") {
		t.Fatalf("transport error leaks the API key: %q", err)
	}
	if !strings.Contains(err.Error(), "key=REDACTED") {
		t.Fatalf("expected the redaction marker in %q", err)
	}
}
