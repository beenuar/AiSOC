// Package enrichment provides external API enrichment for ingested events.
//
// The Shodan enricher performs host lookups against the Shodan API,
// caches results in an in-process TTL cache (Redis can be wired later),
// and augments OCSF events with exposure metadata (open ports, CVEs, ASN).
//
// AiSOC — open-source AI Security Operations Center (MIT License)
package enrichment

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

const (
	shodanHostURL     = "https://api.shodan.io/shodan/host/%s?key=%s"
	shodanCachePrefix = "shodan:host:"
)

// ShodanHost is the subset of Shodan /shodan/host/<ip> we use.
type ShodanHost struct {
	IP         string   `json:"ip_str"`
	Org        string   `json:"org"`
	ISP        string   `json:"isp"`
	ASN        string   `json:"asn"`
	Hostnames  []string `json:"hostnames"`
	Ports      []int    `json:"ports"`
	Tags       []string `json:"tags"`
	Vulns      []string `json:"vulns"` // CVE IDs
	Country    string   `json:"country_code"`
	City       string   `json:"city"`
	LastUpdate string   `json:"last_update"`
}

type cacheEntry struct {
	host    *ShodanHost
	expiry  time.Time
}

// ShodanEnricher looks up IP addresses using the Shodan Internet DB API
// and caches results in an in-process TTL cache.
type ShodanEnricher struct {
	apiKey      string
	cacheExpiry time.Duration
	httpClient  *http.Client
	log         *slog.Logger

	mu    sync.RWMutex
	cache map[string]cacheEntry
}

// NewShodanEnricher creates a new enricher.
func NewShodanEnricher(apiKey string, cacheExpiry time.Duration) *ShodanEnricher {
	return &ShodanEnricher{
		apiKey:      apiKey,
		cacheExpiry: cacheExpiry,
		httpClient:  &http.Client{Timeout: 10 * time.Second},
		log:         slog.Default().With("component", "shodan_enricher"),
		cache:       make(map[string]cacheEntry),
	}
}

// Enrich adds Shodan host metadata to the provided event map.
// Returns the event unmodified if no routable IP is found or the API call fails.
func (s *ShodanEnricher) Enrich(ctx context.Context, event map[string]interface{}) map[string]interface{} {
	ip := ExtractPublicIP(event)
	if ip == "" {
		return event
	}

	host, err := s.lookup(ctx, ip)
	if err != nil {
		// Log a sanitized IP only. `ip` is derived from an ingested (attacker-
		// influenceable) event, so strip control chars to prevent log
		// injection; and we deliberately do NOT log `err`, which can carry the
		// request URL (with the Shodan API key) or response-derived data.
		s.log.Warn("Shodan lookup failed", "ip", sanitizeLogValue(ip))
		return event
	}
	if host == nil {
		return event
	}

	event["shodan"] = map[string]interface{}{
		"ip":          host.IP,
		"org":         host.Org,
		"isp":         host.ISP,
		"asn":         host.ASN,
		"hostnames":   host.Hostnames,
		"open_ports":  host.Ports,
		"tags":        host.Tags,
		"cves":        host.Vulns,
		"country":     host.Country,
		"city":        host.City,
		"last_update": host.LastUpdate,
	}

	return event
}

// VulnsForIP returns CVE IDs Shodan associates with an IP, or nil.
func (s *ShodanEnricher) VulnsForIP(ctx context.Context, ip string) ([]string, error) {
	host, err := s.lookup(ctx, ip)
	if err != nil || host == nil {
		return nil, err
	}
	return host.Vulns, nil
}

// ─── Private helpers ──────────────────────────────────────────────────────────

func (s *ShodanEnricher) lookup(ctx context.Context, ip string) (*ShodanHost, error) {
	// Try cache first
	s.mu.RLock()
	if entry, ok := s.cache[ip]; ok && time.Now().Before(entry.expiry) {
		s.mu.RUnlock()
		return entry.host, nil
	}
	s.mu.RUnlock()

	// Call Shodan API
	url := fmt.Sprintf(shodanHostURL, ip, s.apiKey)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, nil // IP not in Shodan — not an error
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("shodan API returned %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var host ShodanHost
	if err := json.Unmarshal(body, &host); err != nil {
		return nil, err
	}

	// Cache the result
	s.mu.Lock()
	s.cache[ip] = cacheEntry{host: &host, expiry: time.Now().Add(s.cacheExpiry)}
	s.mu.Unlock()

	return &host, nil
}

// ExtractPublicIP scans common OCSF event fields for a routable IP address.
func ExtractPublicIP(event map[string]interface{}) string {
	candidates := []string{
		"src_ip", "source_ip", "dst_ip", "dest_ip",
		"remote_ip", "ip_address", "host_ip",
	}

	for _, field := range candidates {
		raw, ok := event[field]
		if !ok {
			continue
		}
		ip, ok := raw.(string)
		if !ok {
			continue
		}
		parsed := net.ParseIP(strings.TrimSpace(ip))
		if parsed == nil {
			continue
		}
		if parsed.IsLoopback() || parsed.IsPrivate() || parsed.IsLinkLocalUnicast() {
			continue
		}
		return ip
	}
	return ""
}

// sanitizeLogValue strips CR/LF and other control characters so a value
// derived from an ingested (attacker-influenceable) event cannot forge or
// inject additional log lines.
func sanitizeLogValue(s string) string {
	cleaned := strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, s)
	if len(cleaned) > 256 {
		return cleaned[:256]
	}
	return cleaned
}
