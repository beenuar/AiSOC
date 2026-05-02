package enricher

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

const abuseIPDBBaseURL = "https://api.abuseipdb.com/api/v2"

// AbuseIPDBClient queries the AbuseIPDB API for IP reputation.
type AbuseIPDBClient struct {
	apiKey     string
	httpClient *http.Client
}

// NewAbuseIPDBClient creates a new AbuseIPDB API client.
func NewAbuseIPDBClient(apiKey string) *AbuseIPDBClient {
	return &AbuseIPDBClient{
		apiKey: apiKey,
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

type abuseIPDBData struct {
	IPAddress            string    `json:"ipAddress"`
	IsPublic             bool      `json:"isPublic"`
	IPVersion            int       `json:"ipVersion"`
	IsWhitelisted        bool      `json:"isWhitelisted"`
	AbuseConfidenceScore int       `json:"abuseConfidenceScore"`
	CountryCode          string    `json:"countryCode"`
	UsageType            string    `json:"usageType"`
	ISP                  string    `json:"isp"`
	Domain               string    `json:"domain"`
	TotalReports         int       `json:"totalReports"`
	NumDistinctUsers     int       `json:"numDistinctUsers"`
	LastReportedAt       time.Time `json:"lastReportedAt"`
}

type abuseIPDBResponse struct {
	Data abuseIPDBData `json:"data"`
}

// EnrichIP queries AbuseIPDB for IP abuse reports.
func (c *AbuseIPDBClient) EnrichIP(ctx context.Context, ip string) (*EnrichmentResult, error) {
	if c.apiKey == "" {
		return nil, nil
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		fmt.Sprintf("%s/check?ipAddress=%s&maxAgeInDays=90&verbose", abuseIPDBBaseURL, ip), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Key", c.apiKey)
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("AbuseIPDB request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("AbuseIPDB read error: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("AbuseIPDB HTTP %d", resp.StatusCode)
	}

	var abuseResp abuseIPDBResponse
	if err := json.Unmarshal(body, &abuseResp); err != nil {
		return nil, fmt.Errorf("AbuseIPDB parse error: %w", err)
	}

	data := abuseResp.Data
	riskScore := float64(data.AbuseConfidenceScore)

	result := &EnrichmentResult{
		IOCType:   IOCTypeIP,
		Value:     ip,
		RiskScore: riskScore,
		Sources: []EnrichmentSource{
			{Name: "abuseipdb", Timestamp: time.Now(), Cached: false},
		},
		EnrichedAt: time.Now(),
	}

	if data.CountryCode != "" {
		result.GeoLocation = &GeoLocation{
			CountryCode: data.CountryCode,
			ISP:         data.ISP,
		}
	}

	if !data.LastReportedAt.IsZero() {
		t := data.LastReportedAt
		result.LastSeen = &t
	}

	// Tag based on usage type
	if data.UsageType != "" {
		result.Tags = append(result.Tags, data.UsageType)
	}
	if data.IsWhitelisted {
		result.Tags = append(result.Tags, "whitelisted")
	}

	return result, nil
}
