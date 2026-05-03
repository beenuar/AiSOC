package enricher

import "time"

// IOCType represents the type of Indicator of Compromise.
type IOCType string

const (
	IOCTypeIP     IOCType = "ip"
	IOCTypeDomain IOCType = "domain"
	IOCTypeURL    IOCType = "url"
	IOCTypeHash   IOCType = "hash"
	IOCTypeEmail  IOCType = "email"
)

// ThreatClassification maps to MITRE ATT&CK tactics/techniques.
type ThreatClassification struct {
	MITRETactics    []string `json:"mitre_tactics,omitempty"`
	MITRETechniques []string `json:"mitre_techniques,omitempty"`
	ThreatActors    []string `json:"threat_actors,omitempty"`
	Campaigns       []string `json:"campaigns,omitempty"`
	Malware         []string `json:"malware,omitempty"`
}

// GeoLocation represents geographic information for an IP.
type GeoLocation struct {
	Country     string  `json:"country,omitempty"`
	CountryCode string  `json:"country_code,omitempty"`
	City        string  `json:"city,omitempty"`
	Region      string  `json:"region,omitempty"`
	Latitude    float64 `json:"latitude,omitempty"`
	Longitude   float64 `json:"longitude,omitempty"`
	ASN         int64   `json:"asn,omitempty"`
	ASOrg       string  `json:"as_org,omitempty"`
	ISP         string  `json:"isp,omitempty"`
}

// PortInfo describes an open port detected by Shodan.
type PortInfo struct {
	Port      int      `json:"port"`
	Protocol  string   `json:"protocol"`
	Service   string   `json:"service,omitempty"`
	Banner    string   `json:"banner,omitempty"`
	Vulns     []string `json:"vulns,omitempty"`
}

// EnrichmentSource tracks which data sources contributed to enrichment.
type EnrichmentSource struct {
	Name      string    `json:"name"`
	Tier      string    `json:"tier,omitempty"` // "open-source", "free", "commercial"
	Timestamp time.Time `json:"timestamp"`
	Cached    bool      `json:"cached"`
}

// DarkWebContext captures dark-web / underground forum mentions
// (Cyble, Flashpoint, Intel 471).
type DarkWebContext struct {
	Mentions   int      `json:"mentions"`
	Sources    []string `json:"sources,omitempty"` // forum / market names
	FirstSeen  *time.Time `json:"first_seen,omitempty"`
	LastSeen   *time.Time `json:"last_seen,omitempty"`
	Categories []string `json:"categories,omitempty"` // e.g. "ransomware-leak", "credential-dump"
	Excerpt    string   `json:"excerpt,omitempty"`    // redacted snippet
}

// VulnerabilityRef links an IOC to disclosed vulnerabilities.
type VulnerabilityRef struct {
	CVE          string  `json:"cve"`
	CVSS         float64 `json:"cvss,omitempty"`
	EPSS         float64 `json:"epss,omitempty"`
	Exploited    bool    `json:"exploited"`
	KEV          bool    `json:"kev"`             // CISA Known Exploited Vuln
	Description  string  `json:"description,omitempty"`
}

// BrandRisk surfaces brand-protection signals (Cyble, RiskIQ, DomainTools).
type BrandRisk struct {
	Score        int      `json:"score"` // 0-100
	LookalikeOf  string   `json:"lookalike_of,omitempty"`
	Phishing     bool     `json:"phishing"`
	Defacement   bool     `json:"defacement"`
	Indicators   []string `json:"indicators,omitempty"`
}

// EnrichmentResult is the unified enrichment output for any IOC type.
type EnrichmentResult struct {
	IOCType          IOCType              `json:"ioc_type"`
	Value            string               `json:"value"`
	RiskScore        float64              `json:"risk_score"`        // 0-100
	Confidence       float64              `json:"confidence"`        // 0-100
	MaliciousVotes   int                  `json:"malicious_votes"`
	HarmlessVotes    int                  `json:"harmless_votes"`
	TotalEngines     int                  `json:"total_engines"`
	Tags             []string             `json:"tags,omitempty"`
	Reputation       int                  `json:"reputation"`        // -128 to 127
	ThreatCategory   string               `json:"threat_category,omitempty"`
	Classification   ThreatClassification `json:"classification"`
	GeoLocation      *GeoLocation         `json:"geo_location,omitempty"`
	OpenPorts        []PortInfo           `json:"open_ports,omitempty"`
	Whois            map[string]string    `json:"whois,omitempty"`
	DNSRecords       []string             `json:"dns_records,omitempty"`
	CommunityScore   *int                 `json:"community_score,omitempty"` // GreyNoise
	IsBot            bool                 `json:"is_bot"`
	IsTOR            bool                 `json:"is_tor"`
	IsVPN            bool                 `json:"is_vpn"`
	IsDatacenter     bool                 `json:"is_datacenter"`
	LastSeen         *time.Time           `json:"last_seen,omitempty"`
	FirstSeen        *time.Time           `json:"first_seen,omitempty"`
	DarkWeb          *DarkWebContext      `json:"dark_web,omitempty"`
	Vulnerabilities  []VulnerabilityRef   `json:"vulnerabilities,omitempty"`
	BrandRisk        *BrandRisk           `json:"brand_risk,omitempty"`
	Sources          []EnrichmentSource   `json:"sources"`
	EnrichmentErrors []string             `json:"enrichment_errors,omitempty"`
	EnrichedAt       time.Time            `json:"enriched_at"`
}

// EnrichRequest is the input for an enrichment request.
type EnrichRequest struct {
	IOCType IOCType `json:"ioc_type"`
	Value   string  `json:"value"`
	Force   bool    `json:"force"` // bypass cache
}

// BulkEnrichRequest handles multiple IOCs in one call.
type BulkEnrichRequest struct {
	Items []EnrichRequest `json:"items"`
}

// BulkEnrichResponse wraps multiple enrichment results.
type BulkEnrichResponse struct {
	Results []EnrichmentResult `json:"results"`
	Total   int                `json:"total"`
	Errors  int                `json:"errors"`
}
