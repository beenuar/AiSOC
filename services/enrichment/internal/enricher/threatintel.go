package enricher

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

// threatIntelSearchPath is the threatintel service's per-IOC lookup over the
// IOCs its feed poll loop (TAXII / MISP / OTX / CISA KEV) has ingested.
const threatIntelSearchPath = "/api/v1/iocs/search"

// tenantCtxKey carries the request tenant through the fan-out so the
// threatintel client can declare it on the service call. The threatintel
// endpoint requires a service token *and* an X-AiSOC-Tenant-ID header, and an
// absent tenant is a 403, so the enricher threads it here rather than widening
// every provider's method signature.
type tenantCtxKey struct{}

// WithTenant returns a context carrying the tenant the enrichment runs for.
func WithTenant(ctx context.Context, tenantID string) context.Context {
	return context.WithValue(ctx, tenantCtxKey{}, tenantID)
}

func tenantFromContext(ctx context.Context) string {
	v, _ := ctx.Value(tenantCtxKey{}).(string)
	return v
}

// ThreatIntelClient looks an IOC up in the platform's own threat-intel feed
// store (services/threatintel). A hit means a curated feed — OTX, MISP, TAXII,
// CISA KEV — already carries the indicator; the match surfaces under that feed's
// source name so the fusion scorer's TI factor (which recognises `otx` / `misp`
// / `taxii`) counts it. This keeps OTX a threatintel feed, per the system
// design, while giving the per-IOC enrichment layer a way to reach it.
type ThreatIntelClient struct {
	baseURL    string
	token      string
	httpClient *http.Client
}

// NewThreatIntelClient creates the client. An empty base URL or token makes
// every call a no-op (returns nil, nil), as does a request with no tenant.
func NewThreatIntelClient(baseURL, token string) *ThreatIntelClient {
	return &ThreatIntelClient{
		baseURL: strings.TrimRight(baseURL, "/"),
		token:   token,
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

type threatIntelSearchResponse struct {
	Total int              `json:"total"`
	IOCs  []threatIntelIOC `json:"iocs"`
}

type threatIntelIOC struct {
	Value           string   `json:"value"`
	Type            string   `json:"type"`
	Source          string   `json:"source"`
	Tags            []string `json:"tags"`
	MalwareFamilies []string `json:"malware_families"`
	AttackIDs       []string `json:"attack_ids"`
	PulseName       string   `json:"pulse_name"`
}

// EnrichIP / EnrichDomain / EnrichURL / EnrichHash all search the same store by
// the IOC value; the feed store is keyed on value, not on our IOC-type labels.
func (c *ThreatIntelClient) EnrichIP(ctx context.Context, ip string) (*EnrichmentResult, error) {
	return c.lookup(ctx, IOCTypeIP, ip)
}

func (c *ThreatIntelClient) EnrichDomain(ctx context.Context, domain string) (*EnrichmentResult, error) {
	return c.lookup(ctx, IOCTypeDomain, domain)
}

func (c *ThreatIntelClient) EnrichURL(ctx context.Context, rawURL string) (*EnrichmentResult, error) {
	return c.lookup(ctx, IOCTypeURL, rawURL)
}

func (c *ThreatIntelClient) EnrichHash(ctx context.Context, hash string) (*EnrichmentResult, error) {
	return c.lookup(ctx, IOCTypeHash, hash)
}

func (c *ThreatIntelClient) lookup(ctx context.Context, iocType IOCType, value string) (*EnrichmentResult, error) {
	if c.baseURL == "" || c.token == "" {
		return nil, nil
	}
	tenant := tenantFromContext(ctx)
	if tenant == "" {
		// The service endpoint rejects a tenant-less service token (403);
		// treat an unknown tenant as "cannot check" rather than an error.
		return nil, nil
	}

	// Build the URL positionally rather than by string formatting: the IOC
	// value is attacker-influenced alert data, and this construction confines
	// it to the encoded query string — it can never reach the scheme, host or
	// path, which come from operator config and a package constant.
	base, err := url.Parse(c.baseURL)
	if err != nil {
		return nil, fmt.Errorf("threatintel base URL invalid: %w", err)
	}
	endpoint := *base
	endpoint.Path = strings.TrimRight(base.Path, "/") + threatIntelSearchPath
	query := url.Values{}
	query.Set("value", value)
	query.Set("limit", "25")
	endpoint.RawQuery = query.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("X-AiSOC-Tenant-ID", tenant)
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("threatintel request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("threatintel read error: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("threatintel HTTP %d", resp.StatusCode)
	}

	var sr threatIntelSearchResponse
	if err := json.Unmarshal(body, &sr); err != nil {
		return nil, fmt.Errorf("threatintel parse error: %w", err)
	}
	if sr.Total == 0 || len(sr.IOCs) == 0 {
		return nil, nil
	}

	return c.toResult(iocType, value, sr.IOCs), nil
}

func (c *ThreatIntelClient) toResult(iocType IOCType, value string, iocs []threatIntelIOC) *EnrichmentResult {
	sourceSet := map[string]bool{}
	tagSet := map[string]bool{}
	malwareSet := map[string]bool{}
	techSet := map[string]bool{}

	for _, ioc := range iocs {
		if s := strings.ToLower(strings.TrimSpace(ioc.Source)); s != "" {
			sourceSet[s] = true
		}
		for _, t := range ioc.Tags {
			if t != "" {
				tagSet[t] = true
			}
		}
		for _, m := range ioc.MalwareFamilies {
			if m != "" {
				malwareSet[m] = true
			}
		}
		for _, a := range ioc.AttackIDs {
			if a != "" {
				techSet[a] = true
			}
		}
	}

	result := &EnrichmentResult{
		IOCType:    iocType,
		Value:      value,
		EnrichedAt: time.Now(),
	}
	// Each matching feed surfaces by its own name so the scorer can recognise
	// it; keep the list stable for a deterministic merged result.
	for _, s := range sortedKeys(sourceSet) {
		result.Sources = append(result.Sources, EnrichmentSource{Name: s, Tier: "feed", Timestamp: time.Now()})
	}
	result.Tags = append(result.Tags, "ti-feed-match")
	result.Tags = append(result.Tags, sortedKeys(tagSet)...)
	result.Classification.Malware = sortedKeys(malwareSet)
	result.Classification.MITRETechniques = sortedKeys(techSet)

	// A curated feed carrying the indicator is a real known-bad signal;
	// corroboration across feeds raises it.
	if len(sourceSet) >= 2 {
		result.RiskScore = 85.0
	} else {
		result.RiskScore = 70.0
	}

	return result
}

// sortedKeys returns a set's keys in a stable order.
func sortedKeys(set map[string]bool) []string {
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
