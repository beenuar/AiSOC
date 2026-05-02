package enricher

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

const greyNoiseBaseURL = "https://api.greynoise.io/v3/community"

// GreyNoiseClient queries GreyNoise for IP internet noise context.
type GreyNoiseClient struct {
	apiKey     string
	httpClient *http.Client
}

// NewGreyNoiseClient creates a new GreyNoise API client.
func NewGreyNoiseClient(apiKey string) *GreyNoiseClient {
	return &GreyNoiseClient{
		apiKey: apiKey,
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

type greyNoiseIPResponse struct {
	IP             string `json:"ip"`
	Noise          bool   `json:"noise"`
	Riot           bool   `json:"riot"`  // benign internet activity
	Classification string `json:"classification"` // benign, malicious, unknown
	Name           string `json:"name"`
	Link           string `json:"link"`
	LastSeen       string `json:"last_seen"`
	Message        string `json:"message"`
}

// EnrichIP queries GreyNoise for IP noise context.
func (c *GreyNoiseClient) EnrichIP(ctx context.Context, ip string) (*EnrichmentResult, error) {
	if c.apiKey == "" {
		return nil, nil
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		fmt.Sprintf("%s/%s", greyNoiseBaseURL, ip), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("key", c.apiKey)
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("GreyNoise request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("GreyNoise read error: %w", err)
	}

	// 404 means not in GreyNoise dataset (likely legit traffic or unknown)
	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GreyNoise HTTP %d", resp.StatusCode)
	}

	var gnResp greyNoiseIPResponse
	if err := json.Unmarshal(body, &gnResp); err != nil {
		return nil, fmt.Errorf("GreyNoise parse error: %w", err)
	}

	riskScore := 0.0
	if gnResp.Classification == "malicious" {
		riskScore = 80.0
	} else if gnResp.Classification == "benign" {
		riskScore = 5.0
	}

	communityScore := 0
	if gnResp.Noise {
		communityScore = 1
	}

	result := &EnrichmentResult{
		IOCType:        IOCTypeIP,
		Value:          ip,
		RiskScore:      riskScore,
		ThreatCategory: gnResp.Classification,
		IsBot:          gnResp.Noise,
		CommunityScore: &communityScore,
		Sources: []EnrichmentSource{
			{Name: "greynoise", Timestamp: time.Now(), Cached: false},
		},
		EnrichedAt: time.Now(),
	}

	if gnResp.Riot {
		result.Tags = append(result.Tags, "riot", "benign-internet-activity")
	}
	if gnResp.Noise {
		result.Tags = append(result.Tags, "internet-scanner")
	}
	if gnResp.Name != "" {
		result.Tags = append(result.Tags, gnResp.Name)
	}

	if gnResp.LastSeen != "" {
		if t, err := time.Parse("2006-01-02", gnResp.LastSeen); err == nil {
			result.LastSeen = &t
		}
	}

	return result, nil
}
