package enricher

import (
	"context"
	"strings"
	"testing"
)

// Anomali and DomainTools both carry their key in the query string, which a
// *url.Error stringifies in full. Without redaction the first connection
// failure writes the key into whatever log the caller uses — the same defect
// TestShodanTransportErrorNeverCarriesTheKey guards for Shodan.

func TestAnomaliTransportErrorNeverCarriesTheKey(t *testing.T) {
	c := NewAnomaliClient(AnomaliConfig{
		Username: "analyst",
		APIKey:   "sekrit-anomali-key",
		BaseURL:  "http://127.0.0.1:1", // nothing listens on port 1
	})

	_, err := c.EnrichIP(context.Background(), "198.51.100.7")
	if err == nil {
		t.Fatal("expected a transport error")
	}
	if strings.Contains(err.Error(), "sekrit-anomali-key") {
		t.Fatalf("transport error leaks the API key: %q", err)
	}
	if !strings.Contains(err.Error(), "REDACTED") {
		t.Fatalf("expected the redaction marker in %q", err)
	}
}

func TestDomainToolsTransportErrorNeverCarriesTheKey(t *testing.T) {
	c := NewDomainToolsClient("analyst", "sekrit-domaintools-key")
	c.baseURL = "http://127.0.0.1:1"

	_, err := c.EnrichDomain(context.Background(), "example.test")
	if err == nil {
		t.Fatal("expected a transport error")
	}
	if strings.Contains(err.Error(), "sekrit-domaintools-key") {
		t.Fatalf("transport error leaks the API key: %q", err)
	}
	if !strings.Contains(err.Error(), "REDACTED") {
		t.Fatalf("expected the redaction marker in %q", err)
	}
}

func TestAnomaliEmptyKeyIsNoOp(t *testing.T) {
	c := NewAnomaliClient(AnomaliConfig{BaseURL: "http://127.0.0.1:1"})
	res, err := c.EnrichIP(context.Background(), "198.51.100.7")
	if err != nil || res != nil {
		t.Errorf("empty key must no-op, got res=%v err=%v", res, err)
	}
}

func TestDomainToolsEmptyKeyIsNoOp(t *testing.T) {
	c := NewDomainToolsClient("", "")
	c.baseURL = "http://127.0.0.1:1"
	res, err := c.EnrichDomain(context.Background(), "example.test")
	if err != nil || res != nil {
		t.Errorf("empty key must no-op, got res=%v err=%v", res, err)
	}
}
