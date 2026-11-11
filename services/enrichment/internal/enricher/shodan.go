package enricher

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const shodanBaseURL = "https://api.shodan.io"

// ShodanClient queries Shodan's host API for open ports, service banners,
// disclosed vulnerabilities and network geolocation. Shodan is the only
// provider in the fan-out that fills OpenPorts/Vulnerabilities from scan data
// rather than a reputation verdict.
type ShodanClient struct {
	apiKey     string
	baseURL    string
	httpClient *http.Client
}

// NewShodanClient creates a Shodan API client. An empty key makes every call a
// no-op (returns nil, nil), matching the other freemium clients.
func NewShodanClient(apiKey string) *ShodanClient {
	return &ShodanClient{
		apiKey:  apiKey,
		baseURL: shodanBaseURL,
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// shodanHostResponse captures the subset of /shodan/host/{ip} we map.
type shodanHostResponse struct {
	IPStr       string               `json:"ip_str"`
	Ports       []int                `json:"ports"`
	Hostnames   []string             `json:"hostnames"`
	Tags        []string             `json:"tags"`
	Vulns       []string             `json:"vulns"`
	Org         string               `json:"org"`
	ISP         string               `json:"isp"`
	ASN         string               `json:"asn"` // "AS15169"
	CountryName string               `json:"country_name"`
	CountryCode string               `json:"country_code"`
	City        string               `json:"city"`
	Region      string               `json:"region_code"`
	Latitude    float64              `json:"latitude"`
	Longitude   float64              `json:"longitude"`
	Data        []shodanServiceEntry `json:"data"`
}

type shodanServiceEntry struct {
	Port      int    `json:"port"`
	Transport string `json:"transport"`
	Product   string `json:"product"`
	Data      string `json:"data"`
	// Shodan returns vulns as an object keyed by CVE; we only need the keys.
	Vulns map[string]json.RawMessage `json:"vulns"`
}

// shodanMaliciousTags are Shodan tags that signal an actively bad host rather
// than mere exposure.
var shodanMaliciousTags = map[string]bool{
	"malware":     true,
	"compromised": true,
	"c2":          true,
	"botnet":      true,
	"phishing":    true,
}

// EnrichIP queries Shodan for host exposure on the given IP.
func (c *ShodanClient) EnrichIP(ctx context.Context, ip string) (*EnrichmentResult, error) {
	if c.apiKey == "" {
		return nil, nil
	}

	endpoint := fmt.Sprintf("%s/shodan/host/%s?key=%s",
		c.baseURL, url.PathEscape(ip), url.QueryEscape(c.apiKey))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		// Shodan's contract puts the key in the query string, and a
		// *url.Error stringifies the URL it failed on — redact the query
		// before the error can reach a log line.
		var uerr *url.Error
		if errors.As(err, &uerr) {
			if u, perr := url.Parse(uerr.URL); perr == nil {
				u.RawQuery = "key=REDACTED"
				uerr.URL = u.String()
			}
		}
		return nil, fmt.Errorf("Shodan request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("Shodan read error: %w", err)
	}

	// 404 means Shodan has no information on this IP — not an error.
	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Shodan HTTP %d", resp.StatusCode)
	}

	var host shodanHostResponse
	if err := json.Unmarshal(body, &host); err != nil {
		return nil, fmt.Errorf("Shodan parse error: %w", err)
	}

	return c.toResult(ip, &host), nil
}

func (c *ShodanClient) toResult(ip string, host *shodanHostResponse) *EnrichmentResult {
	result := &EnrichmentResult{
		IOCType:    IOCTypeIP,
		Value:      ip,
		DNSRecords: host.Hostnames,
		Tags:       host.Tags,
		Sources: []EnrichmentSource{
			{Name: "shodan", Tier: "free", Timestamp: time.Now(), Cached: false},
		},
		EnrichedAt: time.Now(),
	}

	// Open ports: prefer the per-service entries (they carry banners and
	// per-port vulns); fall back to the bare port list.
	if len(host.Data) > 0 {
		for _, svc := range host.Data {
			pi := PortInfo{
				Port:     svc.Port,
				Protocol: svc.Transport,
				Service:  svc.Product,
				Banner:   truncateBanner(svc.Data),
			}
			for cve := range svc.Vulns {
				pi.Vulns = append(pi.Vulns, cve)
			}
			result.OpenPorts = append(result.OpenPorts, pi)
		}
	} else {
		for _, p := range host.Ports {
			result.OpenPorts = append(result.OpenPorts, PortInfo{Port: p, Protocol: "tcp"})
		}
	}

	// Host-level disclosed vulnerabilities.
	for _, cve := range host.Vulns {
		result.Vulnerabilities = append(result.Vulnerabilities, VulnerabilityRef{CVE: cve})
	}

	// Geolocation / network ownership.
	geo := &GeoLocation{
		Country:     host.CountryName,
		CountryCode: host.CountryCode,
		City:        host.City,
		Region:      host.Region,
		Latitude:    host.Latitude,
		Longitude:   host.Longitude,
		ASOrg:       host.Org,
		ISP:         host.ISP,
	}
	geo.ASN = parseASN(host.ASN)
	if geoHasData(geo) {
		result.GeoLocation = geo
	}

	// Risk: an actively malicious tag outweighs mere exposure; disclosed
	// vulnerabilities are attack surface, not proof of compromise.
	risk := 0.0
	for _, tag := range host.Tags {
		if shodanMaliciousTags[strings.ToLower(tag)] {
			risk = 85.0
			break
		}
	}
	if risk == 0 && len(result.Vulnerabilities) > 0 {
		risk = 50.0
	}
	result.RiskScore = risk

	return result
}

// truncateBanner keeps raw service banners from bloating the cached result.
func truncateBanner(s string) string {
	const max = 256
	s = strings.TrimSpace(s)
	if len(s) > max {
		return s[:max]
	}
	return s
}

// parseASN turns Shodan's "AS15169" into 15169. Returns 0 when unparseable.
func parseASN(asn string) int64 {
	asn = strings.TrimSpace(asn)
	asn = strings.TrimPrefix(strings.ToUpper(asn), "AS")
	n, err := strconv.ParseInt(asn, 10, 64)
	if err != nil {
		return 0
	}
	return n
}

func geoHasData(g *GeoLocation) bool {
	return g.Country != "" || g.City != "" || g.ASN != 0 || g.ASOrg != "" || g.ISP != ""
}
