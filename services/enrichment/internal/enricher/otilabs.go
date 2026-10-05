package enricher

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// ──────────────────────────────────────────────────────────────────────────────
// OTI Labs Domain Intelligence
// ──────────────────────────────────────────────────────────────────────────────
//
// One request to /lookup/{domain} returns WHOIS/RDAP registration data, DNS
// records, the TLS certificate the domain serves, subdomains and SPF/DMARC/DKIM.
// The API reports facts rather than a verdict, so the client leaves RiskScore at
// zero and surfaces the signals an analyst triages on as tags (for example
// otilabs:new-domain or otilabs:dmarc:none), alongside the WHOIS fields and DNS
// records.

const (
	otiLabsBaseURL    = "https://domain-intelligence-api.p.rapidapi.com"
	otiLabsHost       = "domain-intelligence-api.p.rapidapi.com"
	otiLabsSourceName = "otilabs"

	// Registration age below which a domain is tagged otilabs:new-domain.
	otiLabsNewDomainAge = 30 * 24 * time.Hour
	// Days of certificate validity at or below which it is tagged otilabs:ssl:expires-soon.
	otiLabsCertExpiringDays = 14
	// Cap on the response body read into memory.
	otiLabsMaxBody = 8 << 20
)

// otiLabsDNSOrder fixes the order DNS records are listed in.
var otiLabsDNSOrder = []string{"A", "AAAA", "MX", "NS", "TXT", "CAA", "SOA"}

// OTILabsClient queries the OTI Labs Domain Intelligence API (a RapidAPI key).
type OTILabsClient struct {
	apiKey     string
	baseURL    string
	httpClient *http.Client
}

func NewOTILabsClient(apiKey string) *OTILabsClient {
	return &OTILabsClient{apiKey: apiKey, baseURL: otiLabsBaseURL, httpClient: defaultHTTPClient()}
}

func (c *OTILabsClient) configured() bool { return c != nil && c.apiKey != "" }

// otiLabsLookup holds the raw /lookup sections. Any section the API could not
// fetch comes back as {"error": "..."} and is skipped, so each one is decoded
// on its own.
type otiLabsLookup struct {
	DNS           json.RawMessage `json:"dns"`
	SSL           json.RawMessage `json:"ssl"`
	Whois         json.RawMessage `json:"whois"`
	Subdomains    json.RawMessage `json:"subdomains"`
	EmailSecurity json.RawMessage `json:"email_security"`
}

type otiLabsWhois struct {
	Registrar   string   `json:"registrar"`
	Created     string   `json:"created"`
	Updated     string   `json:"updated"`
	Expires     string   `json:"expires"`
	Nameservers []string `json:"nameservers"`
	Status      []string `json:"status"`
}

type otiLabsSSL struct {
	Issuer          string `json:"issuer"`
	ValidTo         string `json:"valid_to"`
	DaysUntilExpiry *int   `json:"days_until_expiry"`
}

type otiLabsSubdomains struct {
	Count     *int `json:"count"`
	LiveCount *int `json:"live_count"`
}

type otiLabsRecords struct {
	Present bool     `json:"present"`
	Records []string `json:"records"`
}

type otiLabsEmailSecurity struct {
	SPF   otiLabsRecords `json:"spf"`
	DMARC otiLabsRecords `json:"dmarc"`
	DKIM  struct {
		Found []string `json:"found"`
	} `json:"dkim"`
}

// otiLabsSection decodes one /lookup section into v. It reports false for a
// missing section, one the API could not fetch, or one that does not decode.
func otiLabsSection(raw json.RawMessage, v any) bool {
	if len(raw) == 0 || string(raw) == "null" {
		return false
	}
	var probe struct {
		Error json.RawMessage `json:"error"`
	}
	if err := json.Unmarshal(raw, &probe); err != nil || len(probe.Error) > 0 {
		return false
	}
	return json.Unmarshal(raw, v) == nil
}

// otiLabsDMARCPolicy returns the p= tag of a DMARC record ("none", "quarantine"
// or "reject"), or "" if the record has none.
func otiLabsDMARCPolicy(record string) string {
	for _, part := range strings.Split(record, ";") {
		key, value, ok := strings.Cut(strings.TrimSpace(part), "=")
		if ok && strings.EqualFold(strings.TrimSpace(key), "p") {
			return strings.ToLower(strings.TrimSpace(value))
		}
	}
	return ""
}

// EnrichDomain queries OTI Labs for registration, DNS, certificate, subdomain
// and email-authentication details of a domain.
func (c *OTILabsClient) EnrichDomain(ctx context.Context, domain string) (*EnrichmentResult, error) {
	if !c.configured() {
		return nil, nil
	}
	endpoint := fmt.Sprintf("%s/lookup/%s", c.baseURL, url.PathEscape(domain))

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-RapidAPI-Key", c.apiKey)
	req.Header.Set("X-RapidAPI-Host", otiLabsHost)
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("otilabs request failed: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, otiLabsMaxBody))
	if err != nil {
		return nil, fmt.Errorf("otilabs read failed: %w", err)
	}
	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}
	if resp.StatusCode >= 400 {
		msg := strings.TrimSpace(string(body))
		if len(msg) > 200 {
			msg = msg[:200]
		}
		return nil, fmt.Errorf("otilabs HTTP %d: %s", resp.StatusCode, msg)
	}
	var lr otiLabsLookup
	if err := json.Unmarshal(body, &lr); err != nil {
		return nil, fmt.Errorf("otilabs parse error: %w", err)
	}

	r := &EnrichmentResult{
		IOCType:    IOCTypeDomain,
		Value:      domain,
		Sources:    []EnrichmentSource{{Name: otiLabsSourceName, Timestamp: time.Now()}},
		EnrichedAt: time.Now(),
	}
	found := false

	var whois otiLabsWhois
	if otiLabsSection(lr.Whois, &whois) {
		w := map[string]string{}
		for key, value := range map[string]string{
			"registrar": whois.Registrar,
			"created":   whois.Created,
			"updated":   whois.Updated,
			"expires":   whois.Expires,
		} {
			if value != "" {
				w[key] = value
			}
		}
		if len(whois.Nameservers) > 0 {
			w["nameservers"] = strings.ToLower(strings.Join(whois.Nameservers, ", "))
		}
		if len(whois.Status) > 0 {
			w["status"] = strings.Join(whois.Status, ", ")
		}
		if len(w) > 0 {
			r.Whois = w
			found = true
		}
		if t, ok := parseCybleTime(whois.Created); ok {
			r.FirstSeen = &t
			if time.Since(t) < otiLabsNewDomainAge {
				r.Tags = append(r.Tags, "otilabs:new-domain")
			}
		}
	}

	var dns map[string][]string
	if otiLabsSection(lr.DNS, &dns) {
		for _, recordType := range otiLabsDNSOrder {
			for _, value := range dns[recordType] {
				r.DNSRecords = append(r.DNSRecords, recordType+" "+value)
			}
		}
		found = found || len(r.DNSRecords) > 0
	}

	var cert otiLabsSSL
	if otiLabsSection(lr.SSL, &cert) && cert.DaysUntilExpiry != nil {
		found = true
		switch days := *cert.DaysUntilExpiry; {
		case days < 0:
			r.Tags = append(r.Tags, "otilabs:ssl:expired")
		case days <= otiLabsCertExpiringDays:
			r.Tags = append(r.Tags, "otilabs:ssl:expires-soon")
		}
	}

	var email otiLabsEmailSecurity
	if otiLabsSection(lr.EmailSecurity, &email) {
		found = true
		if !email.SPF.Present {
			r.Tags = append(r.Tags, "otilabs:spf:missing")
		}
		if !email.DMARC.Present || len(email.DMARC.Records) == 0 {
			r.Tags = append(r.Tags, "otilabs:dmarc:missing")
		} else if policy := otiLabsDMARCPolicy(email.DMARC.Records[0]); policy != "" {
			r.Tags = append(r.Tags, "otilabs:dmarc:"+policy)
		}
		if len(email.DKIM.Found) > 0 {
			r.Tags = append(r.Tags, "otilabs:dkim:found")
		}
	}

	var subs otiLabsSubdomains
	if otiLabsSection(lr.Subdomains, &subs) && subs.LiveCount != nil {
		found = true
		r.Tags = append(r.Tags, fmt.Sprintf("otilabs:live-subdomains:%d", *subs.LiveCount))
	}

	if !found {
		return nil, nil
	}
	return r, nil
}
