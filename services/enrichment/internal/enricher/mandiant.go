// Package enricher: Mandiant Threat Intelligence v4 client.
//
// Mandiant exchanges an API key + secret for a short-lived bearer token via
// /token, then services indicator lookups under /v4/indicator. The response
// includes mscore (0-100), threat-rating, and attribution to APT groups +
// malware families.
//
// Docs: https://docs.mandiant.com/home/mati-threat-intelligence-api-v4
package enricher

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

const (
	mandiantBaseURL    = "https://api.intelligence.mandiant.com"
	mandiantSourceName = "mandiant"
	mandiantSourceTier = "commercial"
)

// MandiantClient queries the Mandiant Threat Intelligence v4 API.
type MandiantClient struct {
	apiKey     string
	apiSecret  string
	httpClient *http.Client

	tokenMu     sync.Mutex
	bearer      string
	tokenExpiry time.Time
}

// NewMandiantClient builds the client.
func NewMandiantClient(apiKey, apiSecret string) *MandiantClient {
	return &MandiantClient{
		apiKey:    apiKey,
		apiSecret: apiSecret,
		httpClient: &http.Client{
			Timeout: 12 * time.Second,
		},
	}
}

func (c *MandiantClient) configured() bool {
	return c != nil && c.apiKey != "" && c.apiSecret != ""
}

type mandiantTokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"` // seconds
}

// token returns a cached bearer token, refreshing if expired.
func (c *MandiantClient) token(ctx context.Context) (string, error) {
	c.tokenMu.Lock()
	defer c.tokenMu.Unlock()

	if c.bearer != "" && time.Now().Before(c.tokenExpiry.Add(-30*time.Second)) {
		return c.bearer, nil
	}

	form := url.Values{"grant_type": {"client_credentials"}, "scope": {"appliance.search"}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		mandiantBaseURL+"/token", strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.SetBasicAuth(c.apiKey, c.apiSecret)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("mandiant token request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("mandiant token HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var tr mandiantTokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tr); err != nil {
		return "", fmt.Errorf("mandiant token parse: %w", err)
	}
	c.bearer = tr.AccessToken
	c.tokenExpiry = time.Now().Add(time.Duration(tr.ExpiresIn) * time.Second)
	return c.bearer, nil
}

// mandiantIndicator captures the v4 /indicator schema (subset).
type mandiantIndicator struct {
	ID          string  `json:"id"`
	Type        string  `json:"type"`
	Value       string  `json:"value"`
	Mscore      int     `json:"mscore"`        // 0-100
	FirstSeen   string  `json:"first_seen"`
	LastSeen    string  `json:"last_seen"`
	ThreatRating struct {
		ThreatScore int    `json:"threat_score"`
		Severity    string `json:"severity"`
	} `json:"threat_rating"`
	AttributedAssociations []struct {
		ID   string `json:"id"`
		Name string `json:"name"`
		Type string `json:"type"` // malware | threat-actor | campaign
	} `json:"attributed_associations"`
	Categories []string `json:"categories"`
	MISPTags   []string `json:"misp"`
	Sources []struct {
		FirstSeen  string `json:"first_seen"`
		LastSeen   string `json:"last_seen"`
		OsintURL   string `json:"osint_url"`
		SourceName string `json:"source_name"`
		Category   string `json:"category"`
	} `json:"sources"`
}

// EnrichIP queries Mandiant for IP indicator intel.
func (c *MandiantClient) EnrichIP(ctx context.Context, ip string) (*EnrichmentResult, error) {
	if !c.configured() {
		return nil, nil
	}
	return c.lookup(ctx, IOCTypeIP, "ipv4", ip)
}

// EnrichDomain queries Mandiant for FQDN intel.
func (c *MandiantClient) EnrichDomain(ctx context.Context, domain string) (*EnrichmentResult, error) {
	if !c.configured() {
		return nil, nil
	}
	return c.lookup(ctx, IOCTypeDomain, "fqdn", domain)
}

// EnrichURL queries Mandiant for URL intel.
func (c *MandiantClient) EnrichURL(ctx context.Context, u string) (*EnrichmentResult, error) {
	if !c.configured() {
		return nil, nil
	}
	return c.lookup(ctx, IOCTypeURL, "url", u)
}

// EnrichHash queries Mandiant for file-hash intel.
func (c *MandiantClient) EnrichHash(ctx context.Context, hash string) (*EnrichmentResult, error) {
	if !c.configured() {
		return nil, nil
	}
	// Mandiant accepts md5/sha1/sha256 under the same /indicator endpoint.
	return c.lookup(ctx, IOCTypeHash, "md5", hash)
}

func (c *MandiantClient) lookup(ctx context.Context, iocType IOCType, mType, value string) (*EnrichmentResult, error) {
	bearer, err := c.token(ctx)
	if err != nil {
		return nil, err
	}

	endpoint := fmt.Sprintf("%s/v4/indicator/%s/%s",
		mandiantBaseURL, mType, url.PathEscape(value))

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+bearer)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("X-App-Name", "AiSOC-Enrichment")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("mandiant request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("mandiant read error: %w", err)
	}

	switch {
	case resp.StatusCode == http.StatusNotFound:
		return nil, nil
	case resp.StatusCode == http.StatusUnauthorized,
		resp.StatusCode == http.StatusForbidden:
		// invalidate cached token so next call refreshes
		c.tokenMu.Lock()
		c.bearer = ""
		c.tokenMu.Unlock()
		return nil, fmt.Errorf("mandiant auth error (HTTP %d)", resp.StatusCode)
	case resp.StatusCode == http.StatusTooManyRequests:
		return nil, fmt.Errorf("mandiant rate-limited")
	case resp.StatusCode >= 400:
		return nil, fmt.Errorf("mandiant HTTP %d: %s",
			resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var ind mandiantIndicator
	if err := json.Unmarshal(body, &ind); err != nil {
		return nil, fmt.Errorf("mandiant parse error: %w", err)
	}

	result := &EnrichmentResult{
		IOCType:        iocType,
		Value:          value,
		RiskScore:      float64(ind.Mscore),
		Confidence:     float64(ind.ThreatRating.ThreatScore),
		ThreatCategory: ind.ThreatRating.Severity,
		Tags:           append([]string{}, ind.MISPTags...),
		Sources: []EnrichmentSource{
			{Name: mandiantSourceName, Tier: mandiantSourceTier, Timestamp: time.Now()},
		},
		EnrichedAt: time.Now(),
	}

	for _, cat := range ind.Categories {
		result.Tags = append(result.Tags, "mandiant:"+cat)
	}

	for _, a := range ind.AttributedAssociations {
		switch strings.ToLower(a.Type) {
		case "malware":
			result.Classification.Malware = append(result.Classification.Malware, a.Name)
		case "threat-actor", "threat_actor":
			result.Classification.ThreatActors = append(result.Classification.ThreatActors, a.Name)
		case "campaign":
			result.Classification.Campaigns = append(result.Classification.Campaigns, a.Name)
		}
	}

	if t, ok := parseCybleTime(ind.FirstSeen); ok {
		result.FirstSeen = &t
	}
	if t, ok := parseCybleTime(ind.LastSeen); ok {
		result.LastSeen = &t
	}

	return result, nil
}
