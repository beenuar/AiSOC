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

const vtBaseURL = "https://www.virustotal.com/api/v3"

// VirusTotalClient interacts with the VirusTotal v3 API.
type VirusTotalClient struct {
	apiKey     string
	httpClient *http.Client
}

// NewVirusTotalClient creates a new VirusTotal API client.
func NewVirusTotalClient(apiKey string) *VirusTotalClient {
	return &VirusTotalClient{
		apiKey: apiKey,
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

type vtAttributes struct {
	LastAnalysisStats map[string]int    `json:"last_analysis_stats"`
	Reputation        int               `json:"reputation"`
	Tags              []string          `json:"tags"`
	Country           string            `json:"country"`
	ASN               int64             `json:"asn"`
	ASOwner           string            `json:"as_owner"`
	Network           string            `json:"network"`
	LastModificationDate int64          `json:"last_modification_date"`
}

type vtResponse struct {
	Data struct {
		Attributes vtAttributes `json:"attributes"`
	} `json:"data"`
}

// EnrichIP queries VirusTotal for IP reputation data.
func (c *VirusTotalClient) EnrichIP(ctx context.Context, ip string) (*EnrichmentResult, error) {
	if c.apiKey == "" {
		return nil, nil // not configured
	}

	resp, err := c.get(ctx, fmt.Sprintf("/ip_addresses/%s", ip))
	if err != nil {
		return nil, err
	}

	var vtResp vtResponse
	if err := json.Unmarshal(resp, &vtResp); err != nil {
		return nil, fmt.Errorf("VT parse error: %w", err)
	}

	attrs := vtResp.Data.Attributes
	malicious := attrs.LastAnalysisStats["malicious"]
	harmless := attrs.LastAnalysisStats["harmless"]
	total := 0
	for _, v := range attrs.LastAnalysisStats {
		total += v
	}

	riskScore := 0.0
	if total > 0 {
		riskScore = float64(malicious) / float64(total) * 100
	}

	result := &EnrichmentResult{
		IOCType:        IOCTypeIP,
		Value:          ip,
		RiskScore:      riskScore,
		MaliciousVotes: malicious,
		HarmlessVotes:  harmless,
		TotalEngines:   total,
		Tags:           attrs.Tags,
		Reputation:     attrs.Reputation,
		Sources: []EnrichmentSource{
			{Name: "virustotal", Timestamp: time.Now(), Cached: false},
		},
		EnrichedAt: time.Now(),
	}

	if attrs.Country != "" {
		result.GeoLocation = &GeoLocation{
			CountryCode: attrs.Country,
			ASN:         attrs.ASN,
			ASOrg:       attrs.ASOwner,
		}
	}

	return result, nil
}

// EnrichDomain queries VirusTotal for domain reputation data.
func (c *VirusTotalClient) EnrichDomain(ctx context.Context, domain string) (*EnrichmentResult, error) {
	if c.apiKey == "" {
		return nil, nil
	}

	resp, err := c.get(ctx, fmt.Sprintf("/domains/%s", domain))
	if err != nil {
		return nil, err
	}

	var vtResp vtResponse
	if err := json.Unmarshal(resp, &vtResp); err != nil {
		return nil, fmt.Errorf("VT parse error: %w", err)
	}

	attrs := vtResp.Data.Attributes
	malicious := attrs.LastAnalysisStats["malicious"]
	harmless := attrs.LastAnalysisStats["harmless"]
	total := 0
	for _, v := range attrs.LastAnalysisStats {
		total += v
	}

	riskScore := 0.0
	if total > 0 {
		riskScore = float64(malicious) / float64(total) * 100
	}

	return &EnrichmentResult{
		IOCType:        IOCTypeDomain,
		Value:          domain,
		RiskScore:      riskScore,
		MaliciousVotes: malicious,
		HarmlessVotes:  harmless,
		TotalEngines:   total,
		Tags:           attrs.Tags,
		Reputation:     attrs.Reputation,
		Sources: []EnrichmentSource{
			{Name: "virustotal", Timestamp: time.Now(), Cached: false},
		},
		EnrichedAt: time.Now(),
	}, nil
}

// EnrichHash queries VirusTotal for file hash reputation.
func (c *VirusTotalClient) EnrichHash(ctx context.Context, hash string) (*EnrichmentResult, error) {
	if c.apiKey == "" {
		return nil, nil
	}

	resp, err := c.get(ctx, fmt.Sprintf("/files/%s", hash))
	if err != nil {
		return nil, err
	}

	var vtResp vtResponse
	if err := json.Unmarshal(resp, &vtResp); err != nil {
		return nil, fmt.Errorf("VT parse error: %w", err)
	}

	attrs := vtResp.Data.Attributes
	malicious := attrs.LastAnalysisStats["malicious"]
	harmless := attrs.LastAnalysisStats["harmless"]
	total := 0
	for _, v := range attrs.LastAnalysisStats {
		total += v
	}

	riskScore := 0.0
	if total > 0 {
		riskScore = float64(malicious) / float64(total) * 100
	}

	return &EnrichmentResult{
		IOCType:        IOCTypeHash,
		Value:          hash,
		RiskScore:      riskScore,
		MaliciousVotes: malicious,
		HarmlessVotes:  harmless,
		TotalEngines:   total,
		Tags:           attrs.Tags,
		Reputation:     attrs.Reputation,
		Sources: []EnrichmentSource{
			{Name: "virustotal", Timestamp: time.Now(), Cached: false},
		},
		EnrichedAt: time.Now(),
	}, nil
}

// EnrichURL queries VirusTotal for URL reputation.
func (c *VirusTotalClient) EnrichURL(ctx context.Context, rawURL string) (*EnrichmentResult, error) {
	if c.apiKey == "" {
		return nil, nil
	}

	// VT requires URL ID (base64url encoded without padding)
	urlID := url.QueryEscape(rawURL)
	resp, err := c.get(ctx, fmt.Sprintf("/urls/%s", urlID))
	if err != nil {
		return nil, err
	}

	var vtResp vtResponse
	if err := json.Unmarshal(resp, &vtResp); err != nil {
		return nil, fmt.Errorf("VT parse error: %w", err)
	}

	attrs := vtResp.Data.Attributes
	malicious := attrs.LastAnalysisStats["malicious"]
	harmless := attrs.LastAnalysisStats["harmless"]
	total := 0
	for _, v := range attrs.LastAnalysisStats {
		total += v
	}

	riskScore := 0.0
	if total > 0 {
		riskScore = float64(malicious) / float64(total) * 100
	}

	return &EnrichmentResult{
		IOCType:        IOCTypeURL,
		Value:          rawURL,
		RiskScore:      riskScore,
		MaliciousVotes: malicious,
		HarmlessVotes:  harmless,
		TotalEngines:   total,
		Tags:           attrs.Tags,
		Reputation:     attrs.Reputation,
		Sources: []EnrichmentSource{
			{Name: "virustotal", Timestamp: time.Now(), Cached: false},
		},
		EnrichedAt: time.Now(),
	}, nil
}

func (c *VirusTotalClient) get(ctx context.Context, path string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, vtBaseURL+path, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("x-apikey", c.apiKey)
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("VT request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("VT read error: %w", err)
	}

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("VT: IOC not found")
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("VT HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	return body, nil
}
