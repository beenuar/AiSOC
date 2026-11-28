package enricher

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

const vpndetectionBaseURL = "https://api.vpndetection.io"

// VPNDetectionClient flags an IP as VPN, Tor or privacy relay (iCloud Private
// Relay and the like) via vpndetection.io, with its country and ASN. Like
// IPInfo it is context rather than a maliciousness verdict, so it contributes
// no RiskScore.
type VPNDetectionClient struct {
	apiKey     string
	baseURL    string
	httpClient *http.Client
}

// NewVPNDetectionClient creates a vpndetection.io client. An empty key makes
// every call a no-op (returns nil, nil), as for every provider here.
func NewVPNDetectionClient(apiKey string) *VPNDetectionClient {
	return &VPNDetectionClient{
		apiKey:  apiKey,
		baseURL: vpndetectionBaseURL,
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

type vpndetectionNetwork struct {
	Provider string `json:"provider"`
}

type vpndetectionResponse struct {
	IP       string              `json:"ip"`
	IsVPN    bool                `json:"is_vpn"`
	IsTor    bool                `json:"is_tor"`
	IsRelay  bool                `json:"is_relay"`
	IsBogon  bool                `json:"is_bogon"`
	Tor      vpndetectionNetwork `json:"tor"`
	Relay    vpndetectionNetwork `json:"relay"`
	Location struct {
		Country string `json:"country"`
	} `json:"location"`
	ASN struct {
		ASN  int64  `json:"asn"`
		Name string `json:"name"`
	} `json:"asn"`
}

// EnrichIP looks up the VPN, Tor and relay flags for the given IP.
func (c *VPNDetectionClient) EnrichIP(ctx context.Context, ip string) (*EnrichmentResult, error) {
	if c.apiKey == "" {
		return nil, nil
	}

	// The key travels in the Authorization header, never the URL, so a
	// wrapped *url.Error cannot carry it into the logs (as for IPInfo).
	endpoint := fmt.Sprintf("%s/%s", c.baseURL, url.PathEscape(ip))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.apiKey)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("VPNDetection request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("VPNDetection read error: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("VPNDetection HTTP %d", resp.StatusCode)
	}

	var vr vpndetectionResponse
	if err := json.Unmarshal(body, &vr); err != nil {
		return nil, fmt.Errorf("VPNDetection parse error: %w", err)
	}
	// A private or reserved address has no network to report on.
	if vr.IsBogon {
		return nil, nil
	}

	return c.toResult(ip, &vr), nil
}

func (c *VPNDetectionClient) toResult(ip string, vr *vpndetectionResponse) *EnrichmentResult {
	result := &EnrichmentResult{
		IOCType: IOCTypeIP,
		Value:   ip,
		Sources: []EnrichmentSource{
			{Name: "vpndetection", Tier: "free", Timestamp: time.Now(), Cached: false},
		},
		EnrichedAt: time.Now(),
		IsVPN:      vr.IsVPN,
		IsTOR:      vr.IsTor,
	}

	geo := &GeoLocation{
		CountryCode: vr.Location.Country,
		ASN:         vr.ASN.ASN,
		ASOrg:       vr.ASN.Name,
	}
	if geoHasData(geo) || geo.CountryCode != "" {
		result.GeoLocation = geo
	}

	if vr.IsVPN {
		result.Tags = append(result.Tags, "vpn")
	}
	if vr.IsTor {
		result.Tags = append(result.Tags, "tor")
	}
	if vr.IsRelay {
		result.Tags = append(result.Tags, "privacy-relay")
		if vr.Relay.Provider != "" {
			result.Tags = append(result.Tags, "relay:"+vr.Relay.Provider)
		}
	}

	return result
}
