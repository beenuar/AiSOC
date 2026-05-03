package enricher

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/beenuar/aisoc/enrichment/internal/cache"
	"github.com/rs/zerolog/log"
)

// Enricher orchestrates multi-source IOC enrichment with Redis caching.
//
// Sources are split into three tiers:
//
//   - open-source: VirusTotal community, AbuseIPDB, GreyNoise community
//   - free / freemium: Shodan, IPinfo, URLscan (placeholders unless keys present)
//   - commercial: Cyble Vision, Recorded Future, Mandiant, Anomali, IBM X-Force,
//     Flashpoint, Intel 471, DomainTools Iris, RiskIQ / Defender XATP,
//     Crowdstrike Falcon Intelligence
//
// Every client gracefully no-ops (returns nil, nil) when not configured, so
// the orchestrator can fan out without branching on capability checks.
type Enricher struct {
	cache *cache.Client

	// Open-source / freemium clients
	vtClient    *VirusTotalClient
	abuseClient *AbuseIPDBClient
	gnClient    *GreyNoiseClient

	// Commercial clients
	cybleClient       *CybleClient
	rfClient          *RecordedFutureClient
	mandiantClient    *MandiantClient
	anomaliClient     *AnomaliClient
	xforceClient      *XForceClient
	flashpointClient  *FlashpointClient
	intel471Client    *Intel471Client
	domainToolsClient *DomainToolsClient
	riskIQClient      *RiskIQClient
	csIntelClient     *CrowdstrikeIntelClient
}

// Config holds Enricher dependency configuration.
type Config struct {
	Cache *cache.Client

	// Open-source / freemium
	VirusTotalAPIKey string
	AbuseIPDBAPIKey  string
	GreyNoiseAPIKey  string

	// Commercial
	CybleAPIKey            string
	CybleBaseURL           string
	RecordedFutureAPIKey   string
	MandiantAPIKey         string
	MandiantAPISecret      string
	AnomaliUsername        string
	AnomaliAPIKey          string
	AnomaliBaseURL         string
	XForceAPIKey           string
	XForceAPIPassword      string
	FlashpointAPIKey       string
	Intel471Username       string
	Intel471APIKey         string
	DomainToolsUsername    string
	DomainToolsAPIKey      string
	RiskIQUsername         string
	RiskIQAPIKey           string
	CrowdstrikeIntelID     string
	CrowdstrikeIntelSecret string
}

// New creates a new Enricher with all configured data sources.
func New(cfg Config) *Enricher {
	return &Enricher{
		cache:       cfg.Cache,
		vtClient:    NewVirusTotalClient(cfg.VirusTotalAPIKey),
		abuseClient: NewAbuseIPDBClient(cfg.AbuseIPDBAPIKey),
		gnClient:    NewGreyNoiseClient(cfg.GreyNoiseAPIKey),

		cybleClient: NewCybleClient(CybleConfig{
			APIKey:  cfg.CybleAPIKey,
			BaseURL: cfg.CybleBaseURL,
		}),
		rfClient:       NewRecordedFutureClient(cfg.RecordedFutureAPIKey),
		mandiantClient: NewMandiantClient(cfg.MandiantAPIKey, cfg.MandiantAPISecret),
		anomaliClient: NewAnomaliClient(AnomaliConfig{
			Username: cfg.AnomaliUsername,
			APIKey:   cfg.AnomaliAPIKey,
			BaseURL:  cfg.AnomaliBaseURL,
		}),
		xforceClient:      NewXForceClient(cfg.XForceAPIKey, cfg.XForceAPIPassword),
		flashpointClient:  NewFlashpointClient(cfg.FlashpointAPIKey),
		intel471Client:    NewIntel471Client(cfg.Intel471Username, cfg.Intel471APIKey),
		domainToolsClient: NewDomainToolsClient(cfg.DomainToolsUsername, cfg.DomainToolsAPIKey),
		riskIQClient:      NewRiskIQClient(cfg.RiskIQUsername, cfg.RiskIQAPIKey),
		csIntelClient:     NewCrowdstrikeIntelClient(cfg.CrowdstrikeIntelID, cfg.CrowdstrikeIntelSecret),
	}
}

// Enrich performs IOC enrichment with caching, fan-out to multiple sources,
// and result merging. If force=true, bypasses the cache.
func (e *Enricher) Enrich(ctx context.Context, req EnrichRequest) (*EnrichmentResult, error) {
	cacheKey := cache.MakeKey(string(req.IOCType), req.Value)

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

	if e.cache != nil {
		if cacheErr := e.cache.Set(ctx, cacheKey, result); cacheErr != nil {
			log.Warn().Err(cacheErr).Str("key", cacheKey).Msg("Cache write failed")
		}
	}

	return result, nil
}

// fanOutTask runs an enrichment call and routes the result/error onto the channel.
type fanOutTask struct {
	name string
	fn   func() (*EnrichmentResult, error)
}

// runFanOut executes all tasks concurrently and collects the non-nil results.
// Errors are logged but never short-circuit the fan-out — a single failing
// provider must not poison the merged result.
func runFanOut(ctx context.Context, ioc string, tasks []fanOutTask) []*EnrichmentResult {
	var (
		wg      sync.WaitGroup
		mu      sync.Mutex
		results = make([]*EnrichmentResult, 0, len(tasks))
	)

	for _, t := range tasks {
		t := t
		wg.Add(1)
		go func() {
			defer wg.Done()
			r, err := t.fn()
			if err != nil {
				log.Warn().Err(err).Str("source", t.name).Str("ioc", ioc).Msg("Enrichment failed")
				return
			}
			if r == nil {
				return
			}
			mu.Lock()
			results = append(results, r)
			mu.Unlock()
		}()
	}
	wg.Wait()
	_ = ctx
	return results
}

// enrichIP fans out to every IP-capable source in parallel.
func (e *Enricher) enrichIP(ctx context.Context, ip string) (*EnrichmentResult, error) {
	tasks := []fanOutTask{
		{"virustotal", func() (*EnrichmentResult, error) { return e.vtClient.EnrichIP(ctx, ip) }},
		{"abuseipdb", func() (*EnrichmentResult, error) { return e.abuseClient.EnrichIP(ctx, ip) }},
		{"greynoise", func() (*EnrichmentResult, error) { return e.gnClient.EnrichIP(ctx, ip) }},
		{"cyble", func() (*EnrichmentResult, error) { return e.cybleClient.EnrichIP(ctx, ip) }},
		{"recorded-future", func() (*EnrichmentResult, error) { return e.rfClient.EnrichIP(ctx, ip) }},
		{"mandiant", func() (*EnrichmentResult, error) { return e.mandiantClient.EnrichIP(ctx, ip) }},
		{"anomali", func() (*EnrichmentResult, error) { return e.anomaliClient.EnrichIP(ctx, ip) }},
		{"xforce", func() (*EnrichmentResult, error) { return e.xforceClient.EnrichIP(ctx, ip) }},
		{"flashpoint", func() (*EnrichmentResult, error) { return e.flashpointClient.EnrichIP(ctx, ip) }},
		{"intel471", func() (*EnrichmentResult, error) { return e.intel471Client.EnrichIP(ctx, ip) }},
		{"riskiq", func() (*EnrichmentResult, error) { return e.riskIQClient.EnrichIP(ctx, ip) }},
		{"crowdstrike-intel", func() (*EnrichmentResult, error) { return e.csIntelClient.EnrichIP(ctx, ip) }},
	}
	return mergeResults(IOCTypeIP, ip, runFanOut(ctx, ip, tasks)), nil
}

func (e *Enricher) enrichDomain(ctx context.Context, domain string) (*EnrichmentResult, error) {
	tasks := []fanOutTask{
		{"virustotal", func() (*EnrichmentResult, error) { return e.vtClient.EnrichDomain(ctx, domain) }},
		{"cyble", func() (*EnrichmentResult, error) { return e.cybleClient.EnrichDomain(ctx, domain) }},
		{"recorded-future", func() (*EnrichmentResult, error) { return e.rfClient.EnrichDomain(ctx, domain) }},
		{"mandiant", func() (*EnrichmentResult, error) { return e.mandiantClient.EnrichDomain(ctx, domain) }},
		{"anomali", func() (*EnrichmentResult, error) { return e.anomaliClient.EnrichDomain(ctx, domain) }},
		{"xforce", func() (*EnrichmentResult, error) { return e.xforceClient.EnrichDomain(ctx, domain) }},
		{"flashpoint", func() (*EnrichmentResult, error) { return e.flashpointClient.EnrichDomain(ctx, domain) }},
		{"intel471", func() (*EnrichmentResult, error) { return e.intel471Client.EnrichDomain(ctx, domain) }},
		{"domaintools", func() (*EnrichmentResult, error) { return e.domainToolsClient.EnrichDomain(ctx, domain) }},
		{"riskiq", func() (*EnrichmentResult, error) { return e.riskIQClient.EnrichDomain(ctx, domain) }},
		{"crowdstrike-intel", func() (*EnrichmentResult, error) { return e.csIntelClient.EnrichDomain(ctx, domain) }},
	}
	return mergeResults(IOCTypeDomain, domain, runFanOut(ctx, domain, tasks)), nil
}

func (e *Enricher) enrichHash(ctx context.Context, hash string) (*EnrichmentResult, error) {
	tasks := []fanOutTask{
		{"virustotal", func() (*EnrichmentResult, error) { return e.vtClient.EnrichHash(ctx, hash) }},
		{"cyble", func() (*EnrichmentResult, error) { return e.cybleClient.EnrichHash(ctx, hash) }},
		{"recorded-future", func() (*EnrichmentResult, error) { return e.rfClient.EnrichHash(ctx, hash) }},
		{"mandiant", func() (*EnrichmentResult, error) { return e.mandiantClient.EnrichHash(ctx, hash) }},
		{"flashpoint", func() (*EnrichmentResult, error) { return e.flashpointClient.EnrichHash(ctx, hash) }},
		{"intel471", func() (*EnrichmentResult, error) { return e.intel471Client.EnrichHash(ctx, hash) }},
		{"crowdstrike-intel", func() (*EnrichmentResult, error) { return e.csIntelClient.EnrichHash(ctx, hash) }},
	}
	return mergeResults(IOCTypeHash, hash, runFanOut(ctx, hash, tasks)), nil
}

func (e *Enricher) enrichURL(ctx context.Context, rawURL string) (*EnrichmentResult, error) {
	tasks := []fanOutTask{
		{"virustotal", func() (*EnrichmentResult, error) { return e.vtClient.EnrichURL(ctx, rawURL) }},
		{"cyble", func() (*EnrichmentResult, error) { return e.cybleClient.EnrichURL(ctx, rawURL) }},
		{"recorded-future", func() (*EnrichmentResult, error) { return e.rfClient.EnrichURL(ctx, rawURL) }},
		{"mandiant", func() (*EnrichmentResult, error) { return e.mandiantClient.EnrichURL(ctx, rawURL) }},
	}
	return mergeResults(IOCTypeURL, rawURL, runFanOut(ctx, rawURL, tasks)), nil
}

// mergeResults combines results from multiple sources into a single enriched IOC.
//
// Strategy:
//   - RiskScore = max of all sources (worst-case wins)
//   - Confidence scales with number of corroborating sources
//   - Geo/Whois/community fields take the highest-risk source's data
//   - Tags / classifications / sources / vulns / dark-web are union-merged
//   - Brand-risk takes the highest-scoring brand signal
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
	mitreTacticSet := map[string]bool{}
	mitreTechSet := map[string]bool{}
	actorSet := map[string]bool{}
	malwareSet := map[string]bool{}
	campaignSet := map[string]bool{}
	cveSet := map[string]bool{}

	for _, r := range results {
		if r.RiskScore > maxRisk {
			maxRisk = r.RiskScore
			if r.GeoLocation != nil {
				merged.GeoLocation = r.GeoLocation
			}
			if len(r.Whois) > 0 {
				merged.Whois = r.Whois
			}
		}
		if r.MaliciousVotes > merged.MaliciousVotes {
			merged.MaliciousVotes = r.MaliciousVotes
			merged.HarmlessVotes = r.HarmlessVotes
			merged.TotalEngines = r.TotalEngines
		}
		if r.ThreatCategory != "" && merged.ThreatCategory == "" {
			merged.ThreatCategory = r.ThreatCategory
		}
		if r.IsBot {
			merged.IsBot = true
		}
		if r.IsTOR {
			merged.IsTOR = true
		}
		if r.IsVPN {
			merged.IsVPN = true
		}
		if r.IsDatacenter {
			merged.IsDatacenter = true
		}
		if r.CommunityScore != nil && merged.CommunityScore == nil {
			merged.CommunityScore = r.CommunityScore
		}
		if r.LastSeen != nil {
			if merged.LastSeen == nil || r.LastSeen.After(*merged.LastSeen) {
				merged.LastSeen = r.LastSeen
			}
		}
		if r.FirstSeen != nil {
			if merged.FirstSeen == nil || r.FirstSeen.Before(*merged.FirstSeen) {
				merged.FirstSeen = r.FirstSeen
			}
		}
		for _, tag := range r.Tags {
			tagSet[tag] = true
		}
		for _, t := range r.Classification.MITRETactics {
			mitreTacticSet[t] = true
		}
		for _, t := range r.Classification.MITRETechniques {
			mitreTechSet[t] = true
		}
		for _, a := range r.Classification.ThreatActors {
			actorSet[a] = true
		}
		for _, m := range r.Classification.Malware {
			malwareSet[m] = true
		}
		for _, c := range r.Classification.Campaigns {
			campaignSet[c] = true
		}
		// Dark-web: prefer the source with the most mentions.
		if r.DarkWeb != nil {
			if merged.DarkWeb == nil || r.DarkWeb.Mentions > merged.DarkWeb.Mentions {
				merged.DarkWeb = r.DarkWeb
			}
		}
		// Brand risk: keep highest-score brand signal.
		if r.BrandRisk != nil {
			if merged.BrandRisk == nil || r.BrandRisk.Score > merged.BrandRisk.Score {
				merged.BrandRisk = r.BrandRisk
			}
		}
		for _, v := range r.Vulnerabilities {
			if !cveSet[v.CVE] {
				cveSet[v.CVE] = true
				merged.Vulnerabilities = append(merged.Vulnerabilities, v)
			}
		}
		merged.OpenPorts = append(merged.OpenPorts, r.OpenPorts...)
		merged.Sources = append(merged.Sources, r.Sources...)
		merged.EnrichmentErrors = append(merged.EnrichmentErrors, r.EnrichmentErrors...)
	}

	merged.RiskScore = maxRisk
	for tag := range tagSet {
		merged.Tags = append(merged.Tags, tag)
	}
	for t := range mitreTacticSet {
		merged.Classification.MITRETactics = append(merged.Classification.MITRETactics, t)
	}
	for t := range mitreTechSet {
		merged.Classification.MITRETechniques = append(merged.Classification.MITRETechniques, t)
	}
	for a := range actorSet {
		merged.Classification.ThreatActors = append(merged.Classification.ThreatActors, a)
	}
	for m := range malwareSet {
		merged.Classification.Malware = append(merged.Classification.Malware, m)
	}
	for c := range campaignSet {
		merged.Classification.Campaigns = append(merged.Classification.Campaigns, c)
	}

	// Confidence rises with corroborating sources, capped at 100.
	merged.Confidence = float64(len(results)) * 12.5
	if merged.Confidence > 100 {
		merged.Confidence = 100
	}

	return merged
}

func markCached(sources []EnrichmentSource) []EnrichmentSource {
	for i := range sources {
		sources[i].Cached = true
	}
	return sources
}
