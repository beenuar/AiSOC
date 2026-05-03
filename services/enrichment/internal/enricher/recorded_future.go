// Package enricher: Recorded Future Connect API client.
//
// Recorded Future scores indicators on a 0-99 scale and exposes a "Risk Rule"
// taxonomy explaining why. We map their `risk.score` → RiskScore and surface
// the matched risk rules as tags + threat categories.
//
// Docs: https://api.recordedfuture.com/v2/  (X-RFToken auth)
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

const (
	rfBaseURL    = "https://api.recordedfuture.com/v2"
	rfSourceName = "recorded-future"
	rfSourceTier = "commercial"
)

// RecordedFutureClient queries the Recorded Future Connect API.
type RecordedFutureClient struct {
	apiKey     string
	httpClient *http.Client
}

// NewRecordedFutureClient builds the client.
func NewRecordedFutureClient(apiKey string) *RecordedFutureClient {
	return &RecordedFutureClient{
		apiKey: apiKey,
		httpClient: &http.Client{
			Timeout: 12 * time.Second,
		},
	}
}

func (c *RecordedFutureClient) configured() bool { return c != nil && c.apiKey != "" }

// rfResponse models the subset of fields used across IP/domain/hash/URL endpoints.
type rfResponse struct {
	Data struct {
		Risk struct {
			Score             int      `json:"score"`            // 0-99
			Criticality       int      `json:"criticality"`      // 0-4
			CriticalityLabel  string   `json:"criticalityLabel"` // None | Unusual | Suspicious | Malicious | Very Malicious
			RiskString        string   `json:"riskString"`
			RiskSummary       string   `json:"riskSummary"`
			Rules             int      `json:"rules"` // count of triggered rules
			EvidenceDetails   []rfEvidenceDetail `json:"evidenceDetails"`
		} `json:"risk"`
		ThreatLists []struct {
			Name        string `json:"name"`
			Description string `json:"description"`
		} `json:"threatLists"`
		IntelCard string `json:"intelCard"`
		Timestamps struct {
			FirstSeen string `json:"firstSeen"`
			LastSeen  string `json:"lastSeen"`
		} `json:"timestamps"`
		Location struct {
			Location struct {
				Country struct {
					Name string `json:"name"`
				} `json:"country"`
				City struct {
					Name string `json:"name"`
				} `json:"city"`
			} `json:"location"`
			Organization string `json:"organization"`
			ASN          string `json:"asn"`
		} `json:"location"`
		RelatedEntities []struct {
			Type     string `json:"type"`
			Entities []struct {
				Entity struct {
					Name string `json:"name"`
					Type string `json:"type"`
				} `json:"entity"`
			} `json:"entities"`
		} `json:"relatedEntities"`
	} `json:"data"`
}

type rfEvidenceDetail struct {
	Rule              string `json:"rule"`
	EvidenceString    string `json:"evidenceString"`
	CriticalityLabel  string `json:"criticalityLabel"`
	Criticality       int    `json:"criticality"`
	Timestamp         string `json:"timestamp"`
	MitigationString  string `json:"mitigationString"`
}

// EnrichIP queries Recorded Future for IP risk + context.
func (c *RecordedFutureClient) EnrichIP(ctx context.Context, ip string) (*EnrichmentResult, error) {
	if !c.configured() {
		return nil, nil
	}
	return c.lookup(ctx, IOCTypeIP, "ip", ip)
}

// EnrichDomain queries Recorded Future for domain risk.
func (c *RecordedFutureClient) EnrichDomain(ctx context.Context, domain string) (*EnrichmentResult, error) {
	if !c.configured() {
		return nil, nil
	}
	return c.lookup(ctx, IOCTypeDomain, "domain", domain)
}

// EnrichHash queries Recorded Future for file-hash risk.
func (c *RecordedFutureClient) EnrichHash(ctx context.Context, hash string) (*EnrichmentResult, error) {
	if !c.configured() {
		return nil, nil
	}
	return c.lookup(ctx, IOCTypeHash, "hash", hash)
}

// EnrichURL queries Recorded Future for URL risk.
func (c *RecordedFutureClient) EnrichURL(ctx context.Context, u string) (*EnrichmentResult, error) {
	if !c.configured() {
		return nil, nil
	}
	return c.lookup(ctx, IOCTypeURL, "url", u)
}

func (c *RecordedFutureClient) lookup(ctx context.Context, iocType IOCType, kind, value string) (*EnrichmentResult, error) {
	endpoint := fmt.Sprintf("%s/%s/%s?fields=risk,threatLists,intelCard,timestamps,location,relatedEntities",
		rfBaseURL, kind, url.PathEscape(value))

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-RFToken", c.apiKey)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "AiSOC-Enrichment/1.0")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("recorded future request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("recorded future read error: %w", err)
	}

	switch {
	case resp.StatusCode == http.StatusNotFound:
		return nil, nil
	case resp.StatusCode == http.StatusUnauthorized,
		resp.StatusCode == http.StatusForbidden:
		return nil, fmt.Errorf("recorded future auth error (HTTP %d)", resp.StatusCode)
	case resp.StatusCode == http.StatusTooManyRequests:
		return nil, fmt.Errorf("recorded future rate-limited")
	case resp.StatusCode >= 400:
		return nil, fmt.Errorf("recorded future HTTP %d: %s",
			resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var rf rfResponse
	if err := json.Unmarshal(body, &rf); err != nil {
		return nil, fmt.Errorf("recorded future parse error: %w", err)
	}

	d := rf.Data
	// RF score is 0-99; rescale to 0-100.
	risk := float64(d.Risk.Score)
	if risk > 100 {
		risk = 100
	}

	result := &EnrichmentResult{
		IOCType:        iocType,
		Value:          value,
		RiskScore:      risk,
		Confidence:     float64(d.Risk.Criticality) * 25, // 0-100 from 0-4
		ThreatCategory: d.Risk.CriticalityLabel,
		Sources: []EnrichmentSource{
			{Name: rfSourceName, Tier: rfSourceTier, Timestamp: time.Now()},
		},
		EnrichedAt: time.Now(),
	}

	// Tags: triggered rules + threat lists
	for _, ev := range d.Risk.EvidenceDetails {
		if ev.Rule != "" {
			result.Tags = append(result.Tags, "rf:"+ev.Rule)
		}
	}
	for _, tl := range d.ThreatLists {
		result.Tags = append(result.Tags, "rf:list:"+tl.Name)
	}

	// Geo (IPs only)
	if d.Location.Location.Country.Name != "" || d.Location.ASN != "" {
		result.GeoLocation = &GeoLocation{
			Country: d.Location.Location.Country.Name,
			City:    d.Location.Location.City.Name,
			ASOrg:   d.Location.Organization,
		}
	}

	// Related entities → MITRE / actors / malware
	for _, rel := range d.RelatedEntities {
		for _, ent := range rel.Entities {
			switch strings.ToLower(ent.Entity.Type) {
			case "malwaresignature", "malware":
				result.Classification.Malware = append(result.Classification.Malware, ent.Entity.Name)
			case "threatactor":
				result.Classification.ThreatActors = append(result.Classification.ThreatActors, ent.Entity.Name)
			case "attackvector", "mitreattackidentifier":
				if strings.HasPrefix(ent.Entity.Name, "T") {
					result.Classification.MITRETechniques = append(result.Classification.MITRETechniques, ent.Entity.Name)
				}
			case "operation", "campaign":
				result.Classification.Campaigns = append(result.Classification.Campaigns, ent.Entity.Name)
			}
		}
	}

	if t, ok := parseCybleTime(d.Timestamps.FirstSeen); ok {
		result.FirstSeen = &t
	}
	if t, ok := parseCybleTime(d.Timestamps.LastSeen); ok {
		result.LastSeen = &t
	}

	return result, nil
}
