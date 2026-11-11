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

const urlscanBaseURL = "https://urlscan.io"

// URLScanClient queries urlscan.io's search API for prior scans of a URL or
// domain. It does not submit new scans (those are asynchronous); it reports
// whether the indicator has been seen, the most recent scanned page, and any
// brand-impersonation signal urlscan attached to a result.
type URLScanClient struct {
	apiKey     string
	baseURL    string
	httpClient *http.Client
}

// NewURLScanClient creates a urlscan.io client. An empty key makes every call a
// no-op (returns nil, nil).
func NewURLScanClient(apiKey string) *URLScanClient {
	return &URLScanClient{
		apiKey:  apiKey,
		baseURL: urlscanBaseURL,
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

type urlscanSearchResponse struct {
	Results []urlscanResult `json:"results"`
	Total   int             `json:"total"`
}

type urlscanResult struct {
	Task struct {
		URL  string `json:"url"`
		Time string `json:"time"`
	} `json:"task"`
	Page struct {
		Domain string `json:"domain"`
		URL    string `json:"url"`
		IP     string `json:"ip"`
	} `json:"page"`
	Brand []struct {
		Name string `json:"name"`
	} `json:"brand"`
	Result string `json:"result"`
	ID     string `json:"_id"`
}

// EnrichURL searches urlscan.io for prior scans of an exact URL.
func (c *URLScanClient) EnrichURL(ctx context.Context, rawURL string) (*EnrichmentResult, error) {
	return c.search(ctx, IOCTypeURL, rawURL, fmt.Sprintf(`page.url:"%s"`, rawURL))
}

// EnrichDomain searches urlscan.io for prior scans of a domain.
func (c *URLScanClient) EnrichDomain(ctx context.Context, domain string) (*EnrichmentResult, error) {
	return c.search(ctx, IOCTypeDomain, domain, fmt.Sprintf("domain:%s", domain))
}

func (c *URLScanClient) search(ctx context.Context, iocType IOCType, value, query string) (*EnrichmentResult, error) {
	if c.apiKey == "" {
		return nil, nil
	}

	endpoint := fmt.Sprintf("%s/api/v1/search/?q=%s", c.baseURL, url.QueryEscape(query))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("API-Key", c.apiKey)
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("URLScan request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("URLScan read error: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("URLScan HTTP %d", resp.StatusCode)
	}

	var sr urlscanSearchResponse
	if err := json.Unmarshal(body, &sr); err != nil {
		return nil, fmt.Errorf("URLScan parse error: %w", err)
	}

	// No prior scan: nothing to contribute.
	if sr.Total == 0 || len(sr.Results) == 0 {
		return nil, nil
	}

	result := &EnrichmentResult{
		IOCType: iocType,
		Value:   value,
		Tags:    []string{"urlscan-seen"},
		Sources: []EnrichmentSource{
			{Name: "urlscan", Tier: "free", Timestamp: time.Now(), Cached: false},
		},
		EnrichedAt: time.Now(),
	}

	// The search API returns results newest-first; the first carries the most
	// recent scan.
	latest := sr.Results[0]
	if latest.Task.Time != "" {
		if t, err := time.Parse(time.RFC3339, latest.Task.Time); err == nil {
			result.LastSeen = &t
		}
	}

	// Brand impersonation is urlscan's phishing signal.
	var brands []string
	for _, r := range sr.Results {
		for _, b := range r.Brand {
			if b.Name != "" {
				brands = append(brands, b.Name)
			}
		}
	}
	if len(brands) > 0 {
		result.RiskScore = 70.0
		result.ThreatCategory = "phishing"
		result.Tags = append(result.Tags, "brand-impersonation")
		result.BrandRisk = &BrandRisk{
			Score:       70,
			Phishing:    true,
			LookalikeOf: brands[0],
			Indicators:  dedupeStrings(brands),
		}
	}

	return result, nil
}

// dedupeStrings returns the input with duplicates removed, order preserved.
func dedupeStrings(in []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, s := range in {
		key := strings.ToLower(s)
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, s)
	}
	return out
}
