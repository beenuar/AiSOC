package enricher

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"
	"time"
)

// A trimmed /lookup response; addresses are from the documentation ranges.
const otiLabsSample = `{
  "domain": "example.com",
  "dns": {
    "A": ["192.0.2.10"],
    "AAAA": [],
    "MX": ["10 mail.example.com."],
    "NS": ["ns1.example.net.", "ns2.example.net."],
    "TXT": ["\"v=spf1 -all\""],
    "CAA": [],
    "SOA": ["ns1.example.net. hostmaster.example.com. 1 7200 3600 1209600 3600"]
  },
  "ssl": {"issuer": "CN=Example CA", "valid_to": "2027-01-01T00:00:00+00:00", "days_until_expiry": 90},
  "whois": {
    "registrar": "Example Registrar, Inc.",
    "created": "1995-08-14T04:00:00Z",
    "updated": "2026-08-14T08:01:43Z",
    "expires": "2027-08-13T04:00:00Z",
    "nameservers": ["NS1.EXAMPLE.NET", "NS2.EXAMPLE.NET"],
    "status": ["client delete prohibited", "client transfer prohibited"]
  },
  "subdomains": {"count": 3, "live_count": 2, "returned": 3, "subdomains": ["a.example.com", "b.example.com", "c.example.com"]},
  "email_security": {
    "spf": {"present": true, "records": ["v=spf1 -all"]},
    "dmarc": {"present": true, "records": ["v=DMARC1; p=reject; rua=mailto:dmarc@example.com"]},
    "dkim": {"found": ["google"], "records": [], "note": ""}
  }
}`

// otiLabsSeen records the request the test server received.
type otiLabsSeen struct {
	path   string
	header http.Header
}

func newOTILabsTestClient(t *testing.T, status int, body string) (*OTILabsClient, *otiLabsSeen) {
	t.Helper()
	got := &otiLabsSeen{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		got.path = req.URL.Path
		got.header = req.Header.Clone()
		w.WriteHeader(status)
		fmt.Fprint(w, body)
	}))
	t.Cleanup(srv.Close)
	c := NewOTILabsClient("test-key")
	c.baseURL = srv.URL
	return c, got
}

func TestOTILabsEnrichDomain(t *testing.T) {
	c, got := newOTILabsTestClient(t, http.StatusOK, otiLabsSample)

	r, err := c.EnrichDomain(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("EnrichDomain: %v", err)
	}
	if r == nil {
		t.Fatal("EnrichDomain returned no result")
	}

	if got.path != "/lookup/example.com" {
		t.Errorf("path = %q", got.path)
	}
	if got.header.Get("X-RapidAPI-Key") != "test-key" || got.header.Get("X-RapidAPI-Host") != otiLabsHost {
		t.Errorf("auth headers = %q, %q", got.header.Get("X-RapidAPI-Key"), got.header.Get("X-RapidAPI-Host"))
	}

	if r.IOCType != IOCTypeDomain || r.Value != "example.com" || r.RiskScore != 0 {
		t.Errorf("result header = %v %q risk %v", r.IOCType, r.Value, r.RiskScore)
	}
	wantWhois := map[string]string{
		"registrar":   "Example Registrar, Inc.",
		"created":     "1995-08-14T04:00:00Z",
		"updated":     "2026-08-14T08:01:43Z",
		"expires":     "2027-08-13T04:00:00Z",
		"nameservers": "ns1.example.net, ns2.example.net",
		"status":      "client delete prohibited, client transfer prohibited",
	}
	for key, want := range wantWhois {
		if r.Whois[key] != want {
			t.Errorf("whois[%s] = %q, want %q", key, r.Whois[key], want)
		}
	}
	if r.FirstSeen == nil || !r.FirstSeen.Equal(time.Date(1995, 8, 14, 4, 0, 0, 0, time.UTC)) {
		t.Errorf("FirstSeen = %v", r.FirstSeen)
	}
	wantDNS := []string{
		"A 192.0.2.10",
		"MX 10 mail.example.com.",
		"NS ns1.example.net.",
		"NS ns2.example.net.",
		`TXT "v=spf1 -all"`,
		"SOA ns1.example.net. hostmaster.example.com. 1 7200 3600 1209600 3600",
	}
	if !slices.Equal(r.DNSRecords, wantDNS) {
		t.Errorf("DNSRecords = %q", r.DNSRecords)
	}
	wantTags := []string{"otilabs:dmarc:reject", "otilabs:dkim:found", "otilabs:live-subdomains:2"}
	if !slices.Equal(r.Tags, wantTags) {
		t.Errorf("Tags = %q, want %q", r.Tags, wantTags)
	}
	if len(r.Sources) != 1 || r.Sources[0].Name != otiLabsSourceName {
		t.Errorf("Sources = %+v", r.Sources)
	}
}

func TestOTILabsRiskSignalTags(t *testing.T) {
	created := time.Now().Add(-5 * 24 * time.Hour).UTC().Format(time.RFC3339)
	body := `{
	  "whois": {"registrar": "Example Registrar, Inc.", "created": "` + created + `"},
	  "ssl": {"days_until_expiry": -3},
	  "email_security": {"spf": {"present": false, "records": []}, "dmarc": {"present": false, "records": []}, "dkim": {"found": []}},
	  "dns": {"error": "timeout"},
	  "subdomains": {"error": "timeout"}
	}`
	c, _ := newOTILabsTestClient(t, http.StatusOK, body)

	r, err := c.EnrichDomain(context.Background(), "example.com")
	if err != nil || r == nil {
		t.Fatalf("EnrichDomain = %v, %v", r, err)
	}
	wantTags := []string{"otilabs:new-domain", "otilabs:ssl:expired", "otilabs:spf:missing", "otilabs:dmarc:missing"}
	if !slices.Equal(r.Tags, wantTags) {
		t.Errorf("Tags = %q, want %q", r.Tags, wantTags)
	}
	if len(r.DNSRecords) != 0 {
		t.Errorf("DNSRecords from a failed section = %q", r.DNSRecords)
	}
}

func TestOTILabsSkipsFailedSections(t *testing.T) {
	body := `{"whois": {"error": "all RDAP and WHOIS sources failed"}, "dns": {"A": ["192.0.2.10"]}}`
	c, _ := newOTILabsTestClient(t, http.StatusOK, body)

	r, err := c.EnrichDomain(context.Background(), "example.com")
	if err != nil || r == nil {
		t.Fatalf("EnrichDomain = %v, %v", r, err)
	}
	if r.Whois != nil || r.FirstSeen != nil {
		t.Errorf("whois from a failed section: %v %v", r.Whois, r.FirstSeen)
	}
	if !slices.Equal(r.DNSRecords, []string{"A 192.0.2.10"}) {
		t.Errorf("DNSRecords = %q", r.DNSRecords)
	}
}

func TestOTILabsNoUsableData(t *testing.T) {
	body := `{"whois": {"error": "x"}, "dns": {"error": "x"}, "ssl": {"error": "x"}, "subdomains": {"error": "x"}, "email_security": {"error": "x"}}`
	c, _ := newOTILabsTestClient(t, http.StatusOK, body)

	r, err := c.EnrichDomain(context.Background(), "example.com")
	if err != nil || r != nil {
		t.Errorf("EnrichDomain = %v, %v; want nil, nil", r, err)
	}
}

func TestOTILabsHTTPErrors(t *testing.T) {
	for _, tc := range []struct {
		status  int
		wantErr bool
	}{
		{http.StatusUnauthorized, true},
		{http.StatusForbidden, true},
		{http.StatusTooManyRequests, true},
		{http.StatusBadGateway, true},
		{http.StatusNotFound, false},
	} {
		c, _ := newOTILabsTestClient(t, tc.status, `{"message": "nope"}`)
		r, err := c.EnrichDomain(context.Background(), "example.com")
		if r != nil || (err != nil) != tc.wantErr {
			t.Errorf("HTTP %d: EnrichDomain = %v, %v", tc.status, r, err)
		}
	}
}

func TestOTILabsMalformedBody(t *testing.T) {
	c, _ := newOTILabsTestClient(t, http.StatusOK, `not json`)
	if r, err := c.EnrichDomain(context.Background(), "example.com"); r != nil || err == nil {
		t.Errorf("EnrichDomain = %v, %v; want a parse error", r, err)
	}
}

func TestOTILabsNotConfigured(t *testing.T) {
	r, err := NewOTILabsClient("").EnrichDomain(context.Background(), "example.com")
	if r != nil || err != nil {
		t.Errorf("unconfigured client = %v, %v; want nil, nil", r, err)
	}
}

func TestOTILabsDMARCPolicy(t *testing.T) {
	for record, want := range map[string]string{
		"v=DMARC1; p=reject; rua=mailto:d@example.com": "reject",
		"v=DMARC1;p=quarantine;sp=none":                "quarantine",
		"v=DMARC1; P=None":                             "none",
		"v=DMARC1; rua=mailto:d@example.com":           "",
	} {
		if got := otiLabsDMARCPolicy(record); got != want {
			t.Errorf("otiLabsDMARCPolicy(%q) = %q, want %q", record, got, want)
		}
	}
}
