// Package enricher: Cyble Vision client.
//
// Cyble Vision is Cyble's flagship cyber-threat-intelligence platform. It
// surfaces IOC reputation, threat-actor attribution, malware family tracking,
// dark-web mentions, leaked-credential exposure, vulnerability intel, and
// brand-risk signals.
//
// API docs (gated, requires a tenant):
//   https://docs.cyble.com/cyble-vision/api/v2/
//
// This client targets the v2 REST surface and degrades gracefully:
//   - returns (nil, nil) when no API key is configured
//   - returns (nil, nil) on 404 ("indicator not seen by Cyble")
//   - returns (nil, error) on transport / parse failures so the orchestrator
//     can surface a per-source error without aborting the rest of the fan-out.
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
	cybleDefaultBaseURL = "https://api.cyble.com/v2"
	cybleSourceName     = "cyble-vision"
	cybleSourceTier     = "commercial"
)

// CybleClient queries Cyble Vision for unified threat intelligence.
type CybleClient struct {
	apiKey     string
	baseURL    string
	tenantID   string
	feeds      map[string]bool // enabled feed slugs
	httpClient *http.Client
}

// CybleConfig configures the Cyble Vision client.
type CybleConfig struct {
	APIKey   string
	BaseURL  string   // optional override, defaults to https://api.cyble.com/v2
	TenantID string   // optional, X-Tenant-Id header for multi-tenant orgs
	Feeds    []string // enabled feeds; defaults to all
}

// NewCybleClient creates a new Cyble Vision API client.
func NewCybleClient(cfg CybleConfig) *CybleClient {
	base := cfg.BaseURL
	if base == "" {
		base = cybleDefaultBaseURL
	}
	base = strings.TrimRight(base, "/")

	feeds := map[string]bool{
		"indicators":      true,
		"actors":          true,
		"vulnerabilities": true,
		"leaks":           true,
		"brand":           true,
	}
	if len(cfg.Feeds) > 0 {
		feeds = make(map[string]bool, len(cfg.Feeds))
		for _, f := range cfg.Feeds {
			feeds[strings.ToLower(strings.TrimSpace(f))] = true
		}
	}

	return &CybleClient{
		apiKey:   cfg.APIKey,
		baseURL:  base,
		tenantID: cfg.TenantID,
		feeds:    feeds,
		httpClient: &http.Client{
			Timeout: 12 * time.Second,
		},
	}
}

// configured returns true if the client has credentials.
func (c *CybleClient) configured() bool { return c != nil && c.apiKey != "" }

// cybleIndicatorResponse is the v2 indicator schema (subset).
type cybleIndicatorResponse struct {
	Data struct {
		Indicator   string  `json:"indicator"`
		Type        string  `json:"type"`
		RiskScore   float64 `json:"risk_score"`   // 0-100
		Confidence  float64 `json:"confidence"`   // 0-100
		Reputation  int     `json:"reputation"`   // -100 to 100
		FirstSeen   string  `json:"first_seen"`
		LastSeen    string  `json:"last_seen"`
		Verdict     string  `json:"verdict"` // malicious | suspicious | benign | unknown
		Categories  []string `json:"categories"`
		Tags        []string `json:"tags"`
		Actors      []string `json:"threat_actors"`
		Campaigns   []string `json:"campaigns"`
		MalwareFams []string `json:"malware_families"`
		MITRE       struct {
			Tactics    []string `json:"tactics"`
			Techniques []string `json:"techniques"`
		} `json:"mitre_attack"`
		Geo struct {
			Country     string  `json:"country"`
			CountryCode string  `json:"country_code"`
			City        string  `json:"city"`
			Region      string  `json:"region"`
			Latitude    float64 `json:"latitude"`
			Longitude   float64 `json:"longitude"`
			ASN         int64   `json:"asn"`
			ASOrg       string  `json:"as_org"`
			ISP         string  `json:"isp"`
		} `json:"geo,omitempty"`
		Network struct {
			IsTOR        bool `json:"is_tor"`
			IsVPN        bool `json:"is_vpn"`
			IsDatacenter bool `json:"is_datacenter"`
			IsBot        bool `json:"is_bot"`
		} `json:"network,omitempty"`
		DarkWeb struct {
			Mentions   int      `json:"mentions"`
			Sources    []string `json:"sources"`
			Categories []string `json:"categories"`
			FirstSeen  string   `json:"first_seen"`
			LastSeen   string   `json:"last_seen"`
			Excerpt    string   `json:"excerpt"`
		} `json:"dark_web,omitempty"`
		Vulnerabilities []struct {
			CVE         string  `json:"cve"`
			CVSS        float64 `json:"cvss"`
			EPSS        float64 `json:"epss"`
			Exploited   bool    `json:"exploited_in_wild"`
			KEV         bool    `json:"cisa_kev"`
			Description string  `json:"description"`
		} `json:"vulnerabilities,omitempty"`
		Brand struct {
			Score       int      `json:"risk_score"`
			LookalikeOf string   `json:"lookalike_of"`
			Phishing    bool     `json:"phishing"`
			Defacement  bool     `json:"defacement"`
			Indicators  []string `json:"indicators"`
		} `json:"brand_risk,omitempty"`
	} `json:"data"`
	Meta struct {
		RequestID string `json:"request_id"`
		Tenant    string `json:"tenant"`
	} `json:"meta"`
}

// EnrichIP queries Cyble Vision for IP reputation and threat context.
func (c *CybleClient) EnrichIP(ctx context.Context, ip string) (*EnrichmentResult, error) {
	if !c.configured() {
		return nil, nil
	}
	return c.lookup(ctx, IOCTypeIP, ip)
}

// EnrichDomain queries Cyble Vision for domain reputation.
func (c *CybleClient) EnrichDomain(ctx context.Context, domain string) (*EnrichmentResult, error) {
	if !c.configured() {
		return nil, nil
	}
	return c.lookup(ctx, IOCTypeDomain, domain)
}

// EnrichURL queries Cyble Vision for URL reputation.
func (c *CybleClient) EnrichURL(ctx context.Context, u string) (*EnrichmentResult, error) {
	if !c.configured() {
		return nil, nil
	}
	return c.lookup(ctx, IOCTypeURL, u)
}

// EnrichHash queries Cyble Vision for file-hash (md5/sha1/sha256) intel.
func (c *CybleClient) EnrichHash(ctx context.Context, hash string) (*EnrichmentResult, error) {
	if !c.configured() {
		return nil, nil
	}
	return c.lookup(ctx, IOCTypeHash, hash)
}

// lookup performs the indicator request against /indicators/{type}/{value}.
func (c *CybleClient) lookup(ctx context.Context, iocType IOCType, value string) (*EnrichmentResult, error) {
	if !c.feeds["indicators"] {
		return nil, nil
	}
	endpoint := fmt.Sprintf("%s/indicators/%s/%s",
		c.baseURL, iocType, url.PathEscape(value))

	body, err := c.get(ctx, endpoint)
	if err != nil {
		return nil, err
	}
	if body == nil {
		// 404 — indicator not in Cyble dataset
		return nil, nil
	}

	var resp cybleIndicatorResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("cyble parse error: %w", err)
	}
	return c.toResult(iocType, value, &resp), nil
}

// toResult maps the Cyble response into the unified EnrichmentResult.
func (c *CybleClient) toResult(iocType IOCType, value string, r *cybleIndicatorResponse) *EnrichmentResult {
	d := r.Data

	result := &EnrichmentResult{
		IOCType:        iocType,
		Value:          value,
		RiskScore:      d.RiskScore,
		Confidence:     d.Confidence,
		Reputation:     d.Reputation,
		Tags:           append([]string{}, d.Tags...),
		ThreatCategory: firstNonEmpty(d.Categories...),
		Classification: ThreatClassification{
			MITRETactics:    d.MITRE.Tactics,
			MITRETechniques: d.MITRE.Techniques,
			ThreatActors:    d.Actors,
			Campaigns:       d.Campaigns,
			Malware:         d.MalwareFams,
		},
		Sources: []EnrichmentSource{
			{
				Name:      cybleSourceName,
				Tier:      cybleSourceTier,
				Timestamp: time.Now(),
				Cached:    false,
			},
		},
		EnrichedAt: time.Now(),
	}

	// network signals
	result.IsTOR = d.Network.IsTOR
	result.IsVPN = d.Network.IsVPN
	result.IsDatacenter = d.Network.IsDatacenter
	result.IsBot = d.Network.IsBot

	// verdict-derived tags
	if d.Verdict != "" {
		result.Tags = append(result.Tags, "cyble:"+d.Verdict)
	}
	for _, cat := range d.Categories {
		result.Tags = append(result.Tags, "cyble:cat:"+cat)
	}

	// timestamps
	if t, ok := parseCybleTime(d.FirstSeen); ok {
		result.FirstSeen = &t
	}
	if t, ok := parseCybleTime(d.LastSeen); ok {
		result.LastSeen = &t
	}

	// geo
	if d.Geo.Country != "" || d.Geo.ASN != 0 {
		result.GeoLocation = &GeoLocation{
			Country:     d.Geo.Country,
			CountryCode: d.Geo.CountryCode,
			City:        d.Geo.City,
			Region:      d.Geo.Region,
			Latitude:    d.Geo.Latitude,
			Longitude:   d.Geo.Longitude,
			ASN:         d.Geo.ASN,
			ASOrg:       d.Geo.ASOrg,
			ISP:         d.Geo.ISP,
		}
	}

	// dark web
	if c.feeds["leaks"] && (d.DarkWeb.Mentions > 0 || len(d.DarkWeb.Sources) > 0) {
		dw := &DarkWebContext{
			Mentions:   d.DarkWeb.Mentions,
			Sources:    d.DarkWeb.Sources,
			Categories: d.DarkWeb.Categories,
			Excerpt:    d.DarkWeb.Excerpt,
		}
		if t, ok := parseCybleTime(d.DarkWeb.FirstSeen); ok {
			dw.FirstSeen = &t
		}
		if t, ok := parseCybleTime(d.DarkWeb.LastSeen); ok {
			dw.LastSeen = &t
		}
		result.DarkWeb = dw
		result.Tags = append(result.Tags, "cyble:dark-web")
	}

	// vulnerabilities
	if c.feeds["vulnerabilities"] && len(d.Vulnerabilities) > 0 {
		for _, v := range d.Vulnerabilities {
			result.Vulnerabilities = append(result.Vulnerabilities, VulnerabilityRef{
				CVE:         v.CVE,
				CVSS:        v.CVSS,
				EPSS:        v.EPSS,
				Exploited:   v.Exploited,
				KEV:         v.KEV,
				Description: v.Description,
			})
			if v.KEV {
				result.Tags = append(result.Tags, "cyble:kev:"+v.CVE)
			}
		}
	}

	// brand risk
	if c.feeds["brand"] && (d.Brand.Score > 0 || d.Brand.Phishing || d.Brand.Defacement) {
		result.BrandRisk = &BrandRisk{
			Score:       d.Brand.Score,
			LookalikeOf: d.Brand.LookalikeOf,
			Phishing:    d.Brand.Phishing,
			Defacement:  d.Brand.Defacement,
			Indicators:  d.Brand.Indicators,
		}
		if d.Brand.Phishing {
			result.Tags = append(result.Tags, "cyble:phishing")
		}
		if d.Brand.LookalikeOf != "" {
			result.Tags = append(result.Tags, "cyble:lookalike:"+d.Brand.LookalikeOf)
		}
	}

	return result
}

// get performs an authenticated GET against the Cyble Vision API.
// Returns (nil, nil) when the API responds 404.
func (c *CybleClient) get(ctx context.Context, endpoint string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.apiKey)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "AiSOC-Enrichment/1.0")
	if c.tenantID != "" {
		req.Header.Set("X-Tenant-Id", c.tenantID)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("cyble request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("cyble read error: %w", err)
	}

	switch {
	case resp.StatusCode == http.StatusNotFound:
		return nil, nil
	case resp.StatusCode == http.StatusUnauthorized,
		resp.StatusCode == http.StatusForbidden:
		return nil, fmt.Errorf("cyble auth error (HTTP %d): check CYBLE_VISION_API_KEY",
			resp.StatusCode)
	case resp.StatusCode == http.StatusTooManyRequests:
		return nil, fmt.Errorf("cyble rate-limited (HTTP 429); back off or increase quota")
	case resp.StatusCode >= 400:
		return nil, fmt.Errorf("cyble HTTP %d: %s",
			resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return body, nil
}

// parseCybleTime accepts RFC3339 / RFC3339Nano timestamps.
func parseCybleTime(s string) (time.Time, bool) {
	if s == "" {
		return time.Time{}, false
	}
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339, "2006-01-02"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t, true
		}
	}
	return time.Time{}, false
}

// firstNonEmpty returns the first non-empty string from the list.
func firstNonEmpty(ss ...string) string {
	for _, s := range ss {
		if s != "" {
			return s
		}
	}
	return ""
}
