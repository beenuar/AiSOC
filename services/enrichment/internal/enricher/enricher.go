package enricher

import (
	"context"
	"fmt"
	"time"

	"github.com/cyble/aisoc/enrichment/internal/cache"
	"github.com/rs/zerolog/log"
)

// Enricher orchestrates multi-source IOC enrichment with Redis caching.
type Enricher struct {
	cache      *cache.Client
	vtClient   *VirusTotalClient
	abuseClient *AbuseIPDBClient
	gnClient   *GreyNoiseClient
}

// Config holds Enricher dependencies configuration.
type Config struct {
	Cache            *cache.Client
	VirusTotalAPIKey string
	AbuseIPDBAPIKey  string
	GreyNoiseAPIKey  string
}

// New creates a new Enricher with all configured data sources.
func New(cfg Config) *Enricher {
	return &Enricher{
		cache:       cfg.Cache,
		vtClient:    NewVirusTotalClient(cfg.VirusTotalAPIKey),
		abuseClient: NewAbuseIPDBClient(cfg.AbuseIPDBAPIKey),
		gnClient:    NewGreyNoiseClient(cfg.GreyNoiseAPIKey),
	}
}

// Enrich performs IOC enrichment with caching, fan-out to multiple sources,
// and result merging. If force=true, bypasses the cache.
func (e *Enricher) Enrich(ctx context.Context, req EnrichRequest) (*EnrichmentResult, error) {
	cacheKey := cache.MakeKey(string(req.IOCType), req.Value)

	// Check cache first (unless forced)
	if !req.Force && e.cache != nil {
		var cached EnrichmentResult
		if err := e.cache.Get(ctx, cacheKey, &cached); err == nil && cached.Value != "" {
			cached.Sources = markCached(cached.Sources)
			log.Debug().Str("ioc", req.Value).Str("type", string(req.IOCType)).Msg("Cache hit")
			return &cached, nil
		}
	}

	var result *EnrichmentResult
	var err error

	switch req.IOCType {
	case IOCTypeIP:
		result, err = e.enrichIP(ctx, req.Value)
	case IOCTypeDomain:
		result, err = e.enrichDomain(ctx, req.Value)
	case IOCTypeHash:
		result, err = e.enrichHash(ctx, req.Value)
	case IOCTypeURL:
		result, err = e.enrichURL(ctx, req.Value)
	default:
		return nil, fmt.Errorf("unsupported IOC type: %s", req.IOCType)
	}

	if err != nil {
		return nil, err
	}

	if result == nil {
		result = &EnrichmentResult{
			IOCType:    req.IOCType,
			Value:      req.Value,
			EnrichedAt: time.Now(),
		}
	}

	// Store in cache
	if e.cache != nil {
		if cacheErr := e.cache.Set(ctx, cacheKey, result); cacheErr != nil {
			log.Warn().Err(cacheErr).Str("key", cacheKey).Msg("Cache write failed")
		}
	}

	return result, nil
}

// enrichIP fetches data from all IP-capable sources and merges results.
func (e *Enricher) enrichIP(ctx context.Context, ip string) (*EnrichmentResult, error) {
	results := make([]*EnrichmentResult, 0, 3)

	// VirusTotal
	if r, err := e.vtClient.EnrichIP(ctx, ip); err != nil {
		log.Warn().Err(err).Str("ip", ip).Msg("VirusTotal enrichment failed")
	} else if r != nil {
		results = append(results, r)
	}

	// AbuseIPDB
	if r, err := e.abuseClient.EnrichIP(ctx, ip); err != nil {
		log.Warn().Err(err).Str("ip", ip).Msg("AbuseIPDB enrichment failed")
	} else if r != nil {
		results = append(results, r)
	}

	// GreyNoise
	if r, err := e.gnClient.EnrichIP(ctx, ip); err != nil {
		log.Warn().Err(err).Str("ip", ip).Msg("GreyNoise enrichment failed")
	} else if r != nil {
		results = append(results, r)
	}

	return mergeResults(IOCTypeIP, ip, results), nil
}

func (e *Enricher) enrichDomain(ctx context.Context, domain string) (*EnrichmentResult, error) {
	var result *EnrichmentResult
	if r, err := e.vtClient.EnrichDomain(ctx, domain); err != nil {
		log.Warn().Err(err).Str("domain", domain).Msg("VirusTotal domain enrichment failed")
	} else {
		result = r
	}

	if result == nil {
		result = &EnrichmentResult{IOCType: IOCTypeDomain, Value: domain, EnrichedAt: time.Now()}
	}
	return result, nil
}

func (e *Enricher) enrichHash(ctx context.Context, hash string) (*EnrichmentResult, error) {
	var result *EnrichmentResult
	if r, err := e.vtClient.EnrichHash(ctx, hash); err != nil {
		log.Warn().Err(err).Str("hash", hash).Msg("VirusTotal hash enrichment failed")
	} else {
		result = r
	}

	if result == nil {
		result = &EnrichmentResult{IOCType: IOCTypeHash, Value: hash, EnrichedAt: time.Now()}
	}
	return result, nil
}

func (e *Enricher) enrichURL(ctx context.Context, rawURL string) (*EnrichmentResult, error) {
	var result *EnrichmentResult
	if r, err := e.vtClient.EnrichURL(ctx, rawURL); err != nil {
		log.Warn().Err(err).Str("url", rawURL).Msg("VirusTotal URL enrichment failed")
	} else {
		result = r
	}

	if result == nil {
		result = &EnrichmentResult{IOCType: IOCTypeURL, Value: rawURL, EnrichedAt: time.Now()}
	}
	return result, nil
}

// mergeResults combines results from multiple sources into a single enriched IOC.
func mergeResults(iocType IOCType, value string, results []*EnrichmentResult) *EnrichmentResult {
	if len(results) == 0 {
		return &EnrichmentResult{
			IOCType:    iocType,
			Value:      value,
			EnrichedAt: time.Now(),
		}
	}
	if len(results) == 1 {
		return results[0]
	}

	merged := &EnrichmentResult{
		IOCType:    iocType,
		Value:      value,
		EnrichedAt: time.Now(),
	}

	maxRisk := 0.0
	tagSet := map[string]bool{}
	for _, r := range results {
		if r.RiskScore > maxRisk {
			maxRisk = r.RiskScore
			// Carry over geo/fields from the highest-risk source
			if r.GeoLocation != nil {
				merged.GeoLocation = r.GeoLocation
			}
		}
		if r.MaliciousVotes > merged.MaliciousVotes {
			merged.MaliciousVotes = r.MaliciousVotes
			merged.HarmlessVotes = r.HarmlessVotes
			merged.TotalEngines = r.TotalEngines
		}
		if r.ThreatCategory != "" {
			merged.ThreatCategory = r.ThreatCategory
		}
		if r.IsBot {
			merged.IsBot = true
		}
		if r.IsTOR {
			merged.IsTOR = true
		}
		if r.CommunityScore != nil {
			merged.CommunityScore = r.CommunityScore
		}
		if r.LastSeen != nil {
			if merged.LastSeen == nil || r.LastSeen.After(*merged.LastSeen) {
				merged.LastSeen = r.LastSeen
			}
		}
		for _, tag := range r.Tags {
			tagSet[tag] = true
		}
		merged.Sources = append(merged.Sources, r.Sources...)
		merged.EnrichmentErrors = append(merged.EnrichmentErrors, r.EnrichmentErrors...)
	}

	merged.RiskScore = maxRisk
	for tag := range tagSet {
		merged.Tags = append(merged.Tags, tag)
	}

	// Confidence = proportion of sources that returned data
	merged.Confidence = float64(len(results)) / 3.0 * 100

	return merged
}

func markCached(sources []EnrichmentSource) []EnrichmentSource {
	for i := range sources {
		sources[i].Cached = true
	}
	return sources
}
