package enricher

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const ipinfoBaseURL = "https://ipinfo.io"

// IPInfoClient resolves an IP to geolocation and network ownership via
// ipinfo.io. The free token returns geo/ASN only; paid plans add a "privacy"
// block (vpn/tor/proxy/hosting) which we surface when present. IPInfo provides
// context, never a maliciousness verdict, so it contributes no RiskScore.
type IPInfoClient struct {
	token      string
	baseURL    string
	httpClient *http.Client
}

// NewIPInfoClient creates an ipinfo.io client. An empty token makes every call
// a no-op (returns nil, nil).
func NewIPInfoClient(token string) *IPInfoClient {
	return &IPInfoClient{
		token:   token,
		baseURL: ipinfoBaseURL,
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

type ipinfoResponse struct {
	IP      string `json:"ip"`
	City    string `json:"city"`
	Region  string `json:"region"`
	Country string `json:"country"` // ISO code, e.g. "US"
	Loc     string `json:"loc"`     // "37.3860,-122.0838"
	Org     string `json:"org"`     // "AS15169 Google LLC"
	Privacy *struct {
		VPN     bool `json:"vpn"`
		Tor     bool `json:"tor"`
		Proxy   bool `json:"proxy"`
		Hosting bool `json:"hosting"`
	} `json:"privacy,omitempty"`
}

// EnrichIP resolves geolocation and network ownership for the given IP.
func (c *IPInfoClient) EnrichIP(ctx context.Context, ip string) (*EnrichmentResult, error) {
	if c.token == "" {
		return nil, nil
	}

	// The token travels in the Authorization header, never the URL: a
	// *url.Error stringifies the full URL it failed on, so a query-string
	// token would reach the logs through any wrapped transport error.
	// IPInfo documents Bearer auth alongside ?token=; the header costs
	// nothing and removes the leak path (same choice as the Cyble and
	// Mandiant clients in this package).
	endpoint := fmt.Sprintf("%s/%s/json", c.baseURL, url.PathEscape(ip))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.token)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("IPInfo request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("IPInfo read error: %w", err)
	}

	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("IPInfo HTTP %d", resp.StatusCode)
	}

	var ir ipinfoResponse
	if err := json.Unmarshal(body, &ir); err != nil {
		return nil, fmt.Errorf("IPInfo parse error: %w", err)
	}

	return c.toResult(ip, &ir), nil
}

func (c *IPInfoClient) toResult(ip string, ir *ipinfoResponse) *EnrichmentResult {
	geo := &GeoLocation{
		City:        ir.City,
		Region:      ir.Region,
		CountryCode: ir.Country,
	}
	if lat, lng, ok := parseLoc(ir.Loc); ok {
		geo.Latitude = lat
		geo.Longitude = lng
	}
	// Org arrives as "AS15169 Google LLC": split the AS number from the name.
	if ir.Org != "" {
		fields := strings.SplitN(ir.Org, " ", 2)
		geo.ASN = parseASN(fields[0])
		if len(fields) == 2 {
			geo.ASOrg = strings.TrimSpace(fields[1])
		} else if geo.ASN == 0 {
			geo.ASOrg = ir.Org
		}
	}

	result := &EnrichmentResult{
		IOCType: IOCTypeIP,
		Value:   ip,
		Sources: []EnrichmentSource{
			{Name: "ipinfo", Tier: "free", Timestamp: time.Now(), Cached: false},
		},
		EnrichedAt: time.Now(),
	}
	if geoHasData(geo) {
		result.GeoLocation = geo
	}

	if p := ir.Privacy; p != nil {
		result.IsVPN = p.VPN
		result.IsTOR = p.Tor
		result.IsDatacenter = p.Hosting
		if p.VPN {
			result.Tags = append(result.Tags, "vpn")
		}
		if p.Tor {
			result.Tags = append(result.Tags, "tor")
		}
		if p.Proxy {
			result.Tags = append(result.Tags, "proxy")
		}
		if p.Hosting {
			result.Tags = append(result.Tags, "hosting")
		}
	}

	return result
}

// parseLoc parses ipinfo's "lat,lng" string.
func parseLoc(loc string) (lat, lng float64, ok bool) {
	parts := strings.SplitN(loc, ",", 2)
	if len(parts) != 2 {
		return 0, 0, false
	}
	var err error
	if lat, err = strconv.ParseFloat(strings.TrimSpace(parts[0]), 64); err != nil {
		return 0, 0, false
	}
	if lng, err = strconv.ParseFloat(strings.TrimSpace(parts[1]), 64); err != nil {
		return 0, 0, false
	}
	return lat, lng, true
}
