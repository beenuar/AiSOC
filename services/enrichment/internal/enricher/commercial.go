// Package enricher: secondary commercial-TI clients.
//
// This file groups the commercial providers that share a similar shape:
// authenticate, query a per-IOC endpoint, map verdict/score/categories into
// the unified EnrichmentResult. Each client degrades to (nil, nil) when no
// credentials are configured so the orchestrator can fan-out cleanly.
//
// Providers covered here:
//
//   - Anomali ThreatStream            (X-Username + X-Key-Auth)
//   - IBM X-Force Exchange            (HTTP Basic: key:password)
//   - Flashpoint                      (Bearer token)
//   - Intel 471                       (HTTP Basic: username:key)
//   - DomainTools Iris                (api_username + api_key signed query)
//   - RiskIQ / Defender External ATP  (HTTP Basic: username:key)
//   - Crowdstrike Falcon Intelligence (OAuth2 client-credentials)
//
// For Cyble, Recorded Future, and Mandiant — see their dedicated files which
// implement richer schemas (dark web, evidence rules, mscore + threat-rating).
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

// ──────────────────────────────────────────────────────────────────────────────
// shared helpers
// ──────────────────────────────────────────────────────────────────────────────

func defaultHTTPClient() *http.Client {
	return &http.Client{Timeout: 12 * time.Second}
}

func clamp(v, lo, hi float64) float64 {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

// ──────────────────────────────────────────────────────────────────────────────
// Anomali ThreatStream
// ──────────────────────────────────────────────────────────────────────────────

const (
	anomaliDefaultBaseURL = "https://api.threatstream.com"
	anomaliSourceName     = "anomali-threatstream"
)

// AnomaliClient queries the Anomali ThreatStream Intelligence API.
type AnomaliClient struct {
	username   string
	apiKey     string
	baseURL    string
	httpClient *http.Client
}

// AnomaliConfig configures the Anomali client.
type AnomaliConfig struct {
	Username string
	APIKey   string
	BaseURL  string
}

func NewAnomaliClient(cfg AnomaliConfig) *AnomaliClient {
	base := cfg.BaseURL
	if base == "" {
		base = anomaliDefaultBaseURL
	}
	return &AnomaliClient{
		username:   cfg.Username,
		apiKey:     cfg.APIKey,
		baseURL:    strings.TrimRight(base, "/"),
		httpClient: defaultHTTPClient(),
	}
}

func (c *AnomaliClient) configured() bool {
	return c != nil && c.username != "" && c.apiKey != ""
}

type anomaliResponse struct {
	Objects []struct {
		Value      string   `json:"value"`
		Confidence int      `json:"confidence"`
		Severity   string   `json:"severity"` // low | medium | high | very-high
		Type       string   `json:"type"`
		Source     string   `json:"source"`
		Tags       []struct {
			Name string `json:"name"`
		} `json:"tags"`
		Classification string `json:"classification"`
		ITypes         []string `json:"itype"`
		Country        string `json:"country"`
		ASN            int64  `json:"asn"`
		Org            string `json:"org"`
		ModifiedTS     string `json:"modified_ts"`
		CreatedTS      string `json:"created_ts"`
	} `json:"objects"`
}

// EnrichIP queries Anomali for IP intel.
func (c *AnomaliClient) EnrichIP(ctx context.Context, ip string) (*EnrichmentResult, error) {
	if !c.configured() {
		return nil, nil
	}
	return c.lookup(ctx, IOCTypeIP, "ip", ip)
}

// EnrichDomain queries Anomali for domain intel.
func (c *AnomaliClient) EnrichDomain(ctx context.Context, domain string) (*EnrichmentResult, error) {
	if !c.configured() {
		return nil, nil
	}
	return c.lookup(ctx, IOCTypeDomain, "domain", domain)
}

func (c *AnomaliClient) lookup(ctx context.Context, iocType IOCType, kind, value string) (*EnrichmentResult, error) {
	q := url.Values{
		"username": {c.username},
		"api_key":  {c.apiKey},
		"value":    {value},
		"type":     {kind},
	}
	endpoint := fmt.Sprintf("%s/api/v2/intelligence/?%s", c.baseURL, q.Encode())

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("anomali request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("anomali read error: %w", err)
	}
	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("anomali HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var ar anomaliResponse
	if err := json.Unmarshal(body, &ar); err != nil {
		return nil, fmt.Errorf("anomali parse error: %w", err)
	}
	if len(ar.Objects) == 0 {
		return nil, nil
	}

	// Pick the highest-confidence record.
	top := ar.Objects[0]
	for _, o := range ar.Objects[1:] {
		if o.Confidence > top.Confidence {
			top = o
		}
	}

	severityScore := map[string]float64{
		"low": 25, "medium": 50, "high": 75, "very-high": 95,
	}[strings.ToLower(top.Severity)]

	result := &EnrichmentResult{
		IOCType:        iocType,
		Value:          value,
		RiskScore:      clamp(severityScore, 0, 100),
		Confidence:     float64(top.Confidence),
		ThreatCategory: top.Classification,
		Sources: []EnrichmentSource{
			{Name: anomaliSourceName, Tier: "commercial", Timestamp: time.Now()},
		},
		EnrichedAt: time.Now(),
	}
	for _, t := range top.Tags {
		result.Tags = append(result.Tags, "anomali:"+t.Name)
	}
	for _, it := range top.ITypes {
		result.Tags = append(result.Tags, "anomali:itype:"+it)
	}
	if top.Country != "" || top.ASN != 0 {
		result.GeoLocation = &GeoLocation{
			Country: top.Country,
			ASN:     top.ASN,
			ASOrg:   top.Org,
		}
	}
	if t, ok := parseCybleTime(top.CreatedTS); ok {
		result.FirstSeen = &t
	}
	if t, ok := parseCybleTime(top.ModifiedTS); ok {
		result.LastSeen = &t
	}
	return result, nil
}

// ──────────────────────────────────────────────────────────────────────────────
// IBM X-Force Exchange
// ──────────────────────────────────────────────────────────────────────────────

const (
	xforceBaseURL    = "https://api.xforce.ibmcloud.com"
	xforceSourceName = "ibm-xforce"
)

// XForceClient queries the IBM X-Force Exchange API.
type XForceClient struct {
	apiKey     string
	apiPass    string
	httpClient *http.Client
}

func NewXForceClient(apiKey, apiPass string) *XForceClient {
	return &XForceClient{apiKey: apiKey, apiPass: apiPass, httpClient: defaultHTTPClient()}
}

func (c *XForceClient) configured() bool {
	return c != nil && c.apiKey != "" && c.apiPass != ""
}

type xforceIPReport struct {
	IP    string  `json:"ip"`
	Score float64 `json:"score"` // 1-10
	Cats  map[string]int `json:"cats"`
	Geo   struct {
		Country     string `json:"country"`
		CountryCode string `json:"countrycode"`
	} `json:"geo"`
	Reason string `json:"reason"`
}

func (c *XForceClient) EnrichIP(ctx context.Context, ip string) (*EnrichmentResult, error) {
	if !c.configured() {
		return nil, nil
	}
	endpoint := fmt.Sprintf("%s/ipr/%s", xforceBaseURL, url.PathEscape(ip))
	body, err := c.get(ctx, endpoint)
	if err != nil || body == nil {
		return nil, err
	}
	var rep xforceIPReport
	if err := json.Unmarshal(body, &rep); err != nil {
		return nil, fmt.Errorf("xforce parse error: %w", err)
	}
	r := &EnrichmentResult{
		IOCType:    IOCTypeIP,
		Value:      ip,
		RiskScore:  clamp(rep.Score*10, 0, 100), // 0-10 → 0-100
		Sources:    []EnrichmentSource{{Name: xforceSourceName, Tier: "commercial", Timestamp: time.Now()}},
		EnrichedAt: time.Now(),
	}
	for cat := range rep.Cats {
		r.Tags = append(r.Tags, "xforce:"+cat)
	}
	if rep.Geo.Country != "" {
		r.GeoLocation = &GeoLocation{Country: rep.Geo.Country, CountryCode: rep.Geo.CountryCode}
	}
	return r, nil
}

func (c *XForceClient) EnrichDomain(ctx context.Context, domain string) (*EnrichmentResult, error) {
	if !c.configured() {
		return nil, nil
	}
	endpoint := fmt.Sprintf("%s/url/%s", xforceBaseURL, url.PathEscape(domain))
	body, err := c.get(ctx, endpoint)
	if err != nil || body == nil {
		return nil, err
	}
	var rep struct {
		Result struct {
			Score float64        `json:"score"`
			Cats  map[string]bool `json:"cats"`
		} `json:"result"`
	}
	if err := json.Unmarshal(body, &rep); err != nil {
		return nil, fmt.Errorf("xforce url parse error: %w", err)
	}
	r := &EnrichmentResult{
		IOCType:    IOCTypeDomain,
		Value:      domain,
		RiskScore:  clamp(rep.Result.Score*10, 0, 100),
		Sources:    []EnrichmentSource{{Name: xforceSourceName, Tier: "commercial", Timestamp: time.Now()}},
		EnrichedAt: time.Now(),
	}
	for cat := range rep.Result.Cats {
		r.Tags = append(r.Tags, "xforce:"+cat)
	}
	return r, nil
}

func (c *XForceClient) get(ctx context.Context, endpoint string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	req.SetBasicAuth(c.apiKey, c.apiPass)
	req.Header.Set("Accept", "application/json")
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("xforce request failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("xforce HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return body, nil
}

// ──────────────────────────────────────────────────────────────────────────────
// Flashpoint
// ──────────────────────────────────────────────────────────────────────────────

const (
	flashpointBaseURL    = "https://api.flashpoint.io"
	flashpointSourceName = "flashpoint"
)

// FlashpointClient queries the Flashpoint Ignite API for indicator + dark-web context.
type FlashpointClient struct {
	apiKey     string
	httpClient *http.Client
}

func NewFlashpointClient(apiKey string) *FlashpointClient {
	return &FlashpointClient{apiKey: apiKey, httpClient: defaultHTTPClient()}
}

func (c *FlashpointClient) configured() bool { return c != nil && c.apiKey != "" }

type flashpointResponse struct {
	Hits struct {
		Total struct {
			Value int `json:"value"`
		} `json:"total"`
		Hits []struct {
			Source struct {
				Indicator    string   `json:"indicator"`
				Type         string   `json:"type"`
				Confidence   int      `json:"confidence"`
				Tags         []string `json:"tags"`
				Categories   []string `json:"categories"`
				FirstSeen    string   `json:"first_observed_at"`
				LastSeen     string   `json:"last_observed_at"`
				ForumMentions int     `json:"forum_mentions"`
				Sources       []string `json:"sources"`
				Excerpt       string   `json:"excerpt"`
			} `json:"_source"`
		} `json:"hits"`
	} `json:"hits"`
}

func (c *FlashpointClient) EnrichIP(ctx context.Context, ip string) (*EnrichmentResult, error) {
	if !c.configured() {
		return nil, nil
	}
	return c.lookup(ctx, IOCTypeIP, ip)
}

func (c *FlashpointClient) EnrichDomain(ctx context.Context, domain string) (*EnrichmentResult, error) {
	if !c.configured() {
		return nil, nil
	}
	return c.lookup(ctx, IOCTypeDomain, domain)
}

func (c *FlashpointClient) EnrichHash(ctx context.Context, hash string) (*EnrichmentResult, error) {
	if !c.configured() {
		return nil, nil
	}
	return c.lookup(ctx, IOCTypeHash, hash)
}

func (c *FlashpointClient) lookup(ctx context.Context, iocType IOCType, value string) (*EnrichmentResult, error) {
	endpoint := fmt.Sprintf("%s/technical-intelligence/v1/indicator?value=%s",
		flashpointBaseURL, url.QueryEscape(value))

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.apiKey)
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("flashpoint request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("flashpoint read error: %w", err)
	}
	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("flashpoint HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var fr flashpointResponse
	if err := json.Unmarshal(body, &fr); err != nil {
		return nil, fmt.Errorf("flashpoint parse error: %w", err)
	}
	if len(fr.Hits.Hits) == 0 {
		return nil, nil
	}

	src := fr.Hits.Hits[0].Source
	r := &EnrichmentResult{
		IOCType:    iocType,
		Value:      value,
		RiskScore:  float64(src.Confidence),
		Confidence: float64(src.Confidence),
		Tags:       append([]string{}, src.Tags...),
		Sources:    []EnrichmentSource{{Name: flashpointSourceName, Tier: "commercial", Timestamp: time.Now()}},
		EnrichedAt: time.Now(),
	}
	for _, cat := range src.Categories {
		r.Tags = append(r.Tags, "fp:"+cat)
	}
	if src.ForumMentions > 0 || len(src.Sources) > 0 {
		dw := &DarkWebContext{
			Mentions: src.ForumMentions,
			Sources:  src.Sources,
			Excerpt:  src.Excerpt,
		}
		if t, ok := parseCybleTime(src.FirstSeen); ok {
			dw.FirstSeen = &t
		}
		if t, ok := parseCybleTime(src.LastSeen); ok {
			dw.LastSeen = &t
		}
		r.DarkWeb = dw
		r.Tags = append(r.Tags, "fp:dark-web")
	}
	return r, nil
}

// ──────────────────────────────────────────────────────────────────────────────
// Intel 471
// ──────────────────────────────────────────────────────────────────────────────

const (
	intel471BaseURL    = "https://api.intel471.com/v1"
	intel471SourceName = "intel471"
)

// Intel471Client queries the Intel 471 Indicators API for actor + malware context.
type Intel471Client struct {
	username   string
	apiKey     string
	httpClient *http.Client
}

func NewIntel471Client(username, apiKey string) *Intel471Client {
	return &Intel471Client{username: username, apiKey: apiKey, httpClient: defaultHTTPClient()}
}

func (c *Intel471Client) configured() bool {
	return c != nil && c.username != "" && c.apiKey != ""
}

type intel471Response struct {
	Indicators []struct {
		Data struct {
			Indicator struct {
				Type  string `json:"type"`
				Value string `json:"value"`
			} `json:"indicator"`
			Confidence string   `json:"confidence"` // low | medium | high
			MitreTactics []string `json:"mitreTactics"`
			Threat struct {
				Type string `json:"type"`
				Data struct {
					FamilyProfile struct {
						Name string `json:"name"`
					} `json:"familyProfile"`
					ActorSubject struct {
						Handle string `json:"handle"`
					} `json:"actorSubject"`
				} `json:"data"`
			} `json:"threat"`
		} `json:"data"`
		Activity struct {
			First int64 `json:"first"`
			Last  int64 `json:"last"`
		} `json:"activity"`
	} `json:"indicators"`
}

func (c *Intel471Client) EnrichIP(ctx context.Context, ip string) (*EnrichmentResult, error) {
	if !c.configured() {
		return nil, nil
	}
	return c.lookup(ctx, IOCTypeIP, ip)
}

func (c *Intel471Client) EnrichDomain(ctx context.Context, domain string) (*EnrichmentResult, error) {
	if !c.configured() {
		return nil, nil
	}
	return c.lookup(ctx, IOCTypeDomain, domain)
}

func (c *Intel471Client) EnrichHash(ctx context.Context, hash string) (*EnrichmentResult, error) {
	if !c.configured() {
		return nil, nil
	}
	return c.lookup(ctx, IOCTypeHash, hash)
}

func (c *Intel471Client) lookup(ctx context.Context, iocType IOCType, value string) (*EnrichmentResult, error) {
	endpoint := fmt.Sprintf("%s/indicators?indicator=%s", intel471BaseURL, url.QueryEscape(value))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	req.SetBasicAuth(c.username, c.apiKey)
	req.Header.Set("Accept", "application/json")
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("intel471 request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("intel471 read error: %w", err)
	}
	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("intel471 HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var ir intel471Response
	if err := json.Unmarshal(body, &ir); err != nil {
		return nil, fmt.Errorf("intel471 parse error: %w", err)
	}
	if len(ir.Indicators) == 0 {
		return nil, nil
	}
	ind := ir.Indicators[0]
	confScore := map[string]float64{"low": 30, "medium": 60, "high": 90}[strings.ToLower(ind.Data.Confidence)]

	r := &EnrichmentResult{
		IOCType:    iocType,
		Value:      value,
		RiskScore:  confScore,
		Confidence: confScore,
		Classification: ThreatClassification{
			MITRETactics: ind.Data.MitreTactics,
		},
		Sources:    []EnrichmentSource{{Name: intel471SourceName, Tier: "commercial", Timestamp: time.Now()}},
		EnrichedAt: time.Now(),
	}
	if mal := ind.Data.Threat.Data.FamilyProfile.Name; mal != "" {
		r.Classification.Malware = []string{mal}
		r.Tags = append(r.Tags, "intel471:malware:"+mal)
	}
	if actor := ind.Data.Threat.Data.ActorSubject.Handle; actor != "" {
		r.Classification.ThreatActors = []string{actor}
		r.Tags = append(r.Tags, "intel471:actor:"+actor)
	}
	if ind.Activity.First > 0 {
		t := time.Unix(ind.Activity.First/1000, 0)
		r.FirstSeen = &t
	}
	if ind.Activity.Last > 0 {
		t := time.Unix(ind.Activity.Last/1000, 0)
		r.LastSeen = &t
	}
	return r, nil
}

// ──────────────────────────────────────────────────────────────────────────────
// DomainTools Iris
// ──────────────────────────────────────────────────────────────────────────────

const (
	domainToolsBaseURL    = "https://api.domaintools.com/v1"
	domainToolsSourceName = "domaintools-iris"
)

// DomainToolsClient queries the DomainTools Iris Investigate API.
type DomainToolsClient struct {
	username   string
	apiKey     string
	httpClient *http.Client
}

func NewDomainToolsClient(username, apiKey string) *DomainToolsClient {
	return &DomainToolsClient{username: username, apiKey: apiKey, httpClient: defaultHTTPClient()}
}

func (c *DomainToolsClient) configured() bool {
	return c != nil && c.username != "" && c.apiKey != ""
}

type domainToolsResponse struct {
	Response struct {
		Results []struct {
			DomainRisk struct {
				RiskScore  int `json:"risk_score"` // 0-100
				Components []struct {
					Name      string `json:"name"`
					RiskScore int    `json:"risk_score"`
				} `json:"components"`
			} `json:"domain_risk"`
			Registrar struct {
				Value string `json:"value"`
			} `json:"registrar"`
			CreateDate struct {
				Value string `json:"value"`
			} `json:"create_date"`
		} `json:"results"`
	} `json:"response"`
}

// EnrichDomain queries DomainTools Iris for domain risk + registration details.
func (c *DomainToolsClient) EnrichDomain(ctx context.Context, domain string) (*EnrichmentResult, error) {
	if !c.configured() {
		return nil, nil
	}
	q := url.Values{
		"api_username": {c.username},
		"api_key":      {c.apiKey},
		"domain":       {domain},
	}
	endpoint := fmt.Sprintf("%s/iris-investigate/?%s", domainToolsBaseURL, q.Encode())

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("domaintools request failed: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("domaintools HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var dr domainToolsResponse
	if err := json.Unmarshal(body, &dr); err != nil {
		return nil, fmt.Errorf("domaintools parse error: %w", err)
	}
	if len(dr.Response.Results) == 0 {
		return nil, nil
	}
	res := dr.Response.Results[0]
	r := &EnrichmentResult{
		IOCType:    IOCTypeDomain,
		Value:      domain,
		RiskScore:  float64(res.DomainRisk.RiskScore),
		Confidence: float64(res.DomainRisk.RiskScore),
		Sources:    []EnrichmentSource{{Name: domainToolsSourceName, Tier: "commercial", Timestamp: time.Now()}},
		EnrichedAt: time.Now(),
	}
	for _, comp := range res.DomainRisk.Components {
		r.Tags = append(r.Tags, fmt.Sprintf("domaintools:%s:%d", comp.Name, comp.RiskScore))
		if comp.Name == "phishing" && comp.RiskScore > 50 {
			if r.BrandRisk == nil {
				r.BrandRisk = &BrandRisk{}
			}
			r.BrandRisk.Phishing = true
			r.BrandRisk.Score = comp.RiskScore
		}
	}
	if t, ok := parseCybleTime(res.CreateDate.Value); ok {
		r.FirstSeen = &t
	}
	if res.Registrar.Value != "" {
		r.Whois = map[string]string{"registrar": res.Registrar.Value}
	}
	return r, nil
}

// ──────────────────────────────────────────────────────────────────────────────
// RiskIQ / Microsoft Defender External ATP (PassiveTotal)
// ──────────────────────────────────────────────────────────────────────────────

const (
	riskIQBaseURL    = "https://api.passivetotal.org/v2"
	riskIQSourceName = "riskiq-passivetotal"
)

// RiskIQClient queries the RiskIQ PassiveTotal / Defender External ATP API.
type RiskIQClient struct {
	username   string
	apiKey     string
	httpClient *http.Client
}

func NewRiskIQClient(username, apiKey string) *RiskIQClient {
	return &RiskIQClient{username: username, apiKey: apiKey, httpClient: defaultHTTPClient()}
}

func (c *RiskIQClient) configured() bool {
	return c != nil && c.username != "" && c.apiKey != ""
}

type riskIQReputation struct {
	Score      int      `json:"score"` // 0-100
	Classification string `json:"classification"`
	Rules      []struct {
		Name        string `json:"name"`
		Description string `json:"description"`
		Severity    int    `json:"severity"`
	} `json:"rules"`
}

func (c *RiskIQClient) EnrichIP(ctx context.Context, ip string) (*EnrichmentResult, error) {
	if !c.configured() {
		return nil, nil
	}
	return c.reputation(ctx, IOCTypeIP, ip)
}

func (c *RiskIQClient) EnrichDomain(ctx context.Context, domain string) (*EnrichmentResult, error) {
	if !c.configured() {
		return nil, nil
	}
	return c.reputation(ctx, IOCTypeDomain, domain)
}

func (c *RiskIQClient) reputation(ctx context.Context, iocType IOCType, value string) (*EnrichmentResult, error) {
	endpoint := fmt.Sprintf("%s/reputation?query=%s", riskIQBaseURL, url.QueryEscape(value))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	req.SetBasicAuth(c.username, c.apiKey)
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("riskiq request failed: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("riskiq HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var rep riskIQReputation
	if err := json.Unmarshal(body, &rep); err != nil {
		return nil, fmt.Errorf("riskiq parse error: %w", err)
	}
	r := &EnrichmentResult{
		IOCType:        iocType,
		Value:          value,
		RiskScore:      float64(rep.Score),
		Confidence:     float64(rep.Score),
		ThreatCategory: rep.Classification,
		Sources:        []EnrichmentSource{{Name: riskIQSourceName, Tier: "commercial", Timestamp: time.Now()}},
		EnrichedAt:     time.Now(),
	}
	for _, rule := range rep.Rules {
		r.Tags = append(r.Tags, "riskiq:"+rule.Name)
	}
	return r, nil
}

// ──────────────────────────────────────────────────────────────────────────────
// Crowdstrike Falcon Intelligence (separate from EDR connector)
// ──────────────────────────────────────────────────────────────────────────────

const (
	crowdstrikeBaseURL    = "https://api.crowdstrike.com"
	crowdstrikeSourceName = "crowdstrike-falcon-intel"
)

// CrowdstrikeIntelClient queries Falcon Intelligence indicator endpoints
// (distinct from the Falcon EDR connector under /integrations/connectors).
type CrowdstrikeIntelClient struct {
	clientID     string
	clientSecret string
	httpClient   *http.Client

	tokenMu     sync.Mutex
	bearer      string
	tokenExpiry time.Time
}

func NewCrowdstrikeIntelClient(clientID, clientSecret string) *CrowdstrikeIntelClient {
	return &CrowdstrikeIntelClient{
		clientID:     clientID,
		clientSecret: clientSecret,
		httpClient:   defaultHTTPClient(),
	}
}

func (c *CrowdstrikeIntelClient) configured() bool {
	return c != nil && c.clientID != "" && c.clientSecret != ""
}

func (c *CrowdstrikeIntelClient) token(ctx context.Context) (string, error) {
	c.tokenMu.Lock()
	defer c.tokenMu.Unlock()

	if c.bearer != "" && time.Now().Before(c.tokenExpiry.Add(-30*time.Second)) {
		return c.bearer, nil
	}

	form := url.Values{
		"client_id":     {c.clientID},
		"client_secret": {c.clientSecret},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		crowdstrikeBaseURL+"/oauth2/token", strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("crowdstrike token failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("crowdstrike token HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var tr struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tr); err != nil {
		return "", fmt.Errorf("crowdstrike token parse: %w", err)
	}
	c.bearer = tr.AccessToken
	c.tokenExpiry = time.Now().Add(time.Duration(tr.ExpiresIn) * time.Second)
	return c.bearer, nil
}

type crowdstrikeIndicator struct {
	Resources []struct {
		Indicator     string   `json:"indicator"`
		Type          string   `json:"type"`
		MaliciousConfidence string `json:"malicious_confidence"` // high | medium | low | unverified
		PublishedDate int64    `json:"published_date"`
		LastUpdated   int64    `json:"last_updated"`
		Actors        []string `json:"actors"`
		MalwareFamilies []string `json:"malware_families"`
		KillChains    []string `json:"kill_chains"`
		Labels        []struct {
			Name string `json:"name"`
		} `json:"labels"`
	} `json:"resources"`
}

func (c *CrowdstrikeIntelClient) EnrichIP(ctx context.Context, ip string) (*EnrichmentResult, error) {
	if !c.configured() {
		return nil, nil
	}
	return c.lookup(ctx, IOCTypeIP, "ip_address", ip)
}

func (c *CrowdstrikeIntelClient) EnrichDomain(ctx context.Context, domain string) (*EnrichmentResult, error) {
	if !c.configured() {
		return nil, nil
	}
	return c.lookup(ctx, IOCTypeDomain, "domain", domain)
}

func (c *CrowdstrikeIntelClient) EnrichHash(ctx context.Context, hash string) (*EnrichmentResult, error) {
	if !c.configured() {
		return nil, nil
	}
	return c.lookup(ctx, IOCTypeHash, "hash_sha256", hash)
}

func (c *CrowdstrikeIntelClient) lookup(ctx context.Context, iocType IOCType, kind, value string) (*EnrichmentResult, error) {
	bearer, err := c.token(ctx)
	if err != nil {
		return nil, err
	}
	q := url.Values{"filter": {fmt.Sprintf("type:'%s'+indicator:'%s'", kind, value)}}
	endpoint := fmt.Sprintf("%s/intel/combined/indicators/v1?%s", crowdstrikeBaseURL, q.Encode())

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+bearer)
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("crowdstrike intel request failed: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}
	if resp.StatusCode == http.StatusUnauthorized {
		c.tokenMu.Lock()
		c.bearer = ""
		c.tokenMu.Unlock()
		return nil, fmt.Errorf("crowdstrike intel auth error")
	}
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("crowdstrike intel HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var ind crowdstrikeIndicator
	if err := json.Unmarshal(body, &ind); err != nil {
		return nil, fmt.Errorf("crowdstrike parse error: %w", err)
	}
	if len(ind.Resources) == 0 {
		return nil, nil
	}
	res := ind.Resources[0]
	confScore := map[string]float64{
		"high": 90, "medium": 60, "low": 30, "unverified": 15,
	}[strings.ToLower(res.MaliciousConfidence)]

	r := &EnrichmentResult{
		IOCType:    iocType,
		Value:      value,
		RiskScore:  confScore,
		Confidence: confScore,
		Classification: ThreatClassification{
			ThreatActors: res.Actors,
			Malware:      res.MalwareFamilies,
		},
		Sources:    []EnrichmentSource{{Name: crowdstrikeSourceName, Tier: "commercial", Timestamp: time.Now()}},
		EnrichedAt: time.Now(),
	}
	for _, kc := range res.KillChains {
		r.Tags = append(r.Tags, "cs:killchain:"+kc)
	}
	for _, lbl := range res.Labels {
		r.Tags = append(r.Tags, "cs:"+lbl.Name)
	}
	if res.PublishedDate > 0 {
		t := time.Unix(res.PublishedDate, 0)
		r.FirstSeen = &t
	}
	if res.LastUpdated > 0 {
		t := time.Unix(res.LastUpdated, 0)
		r.LastSeen = &t
	}
	return r, nil
}
