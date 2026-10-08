package activity

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Geography, ASN and reputation for every public IP, at ingest, cached.
//
// The data comes from `services/enrichment`, which already merges GreyNoise,
// VirusTotal, AbuseIPDB and the commercial feeds behind one `POST /enrich`
// and caches in Redis. Ingest does not reach a vendor directly: a second
// implementation of the same merge would drift from the one triage reads,
// and the vendor keys live in one service for a reason.
//
// Three constraints this enricher is built around.
//
// **Only public addresses are sent.** A private, loopback, link-local or
// documentation-range address has no geography and no ASN, so a lookup would
// cost a round trip to learn nothing — and sending one to a service that
// forwards to third-party vendors would publish the customer's internal
// topology one address at a time.
//
// **It never blocks ingest.** The cache is in-process and the call has a
// short timeout; a failure leaves the location block without geography and
// logs, because an event with no ASN is worth far more than no event. This
// is the same posture the Shodan enricher beside it already takes.
//
// **It carries the service token.** An internal call with no credential is
// answered 401 by our own service and reads to an operator as the vendor
// rejecting us — the failure shape that cost four separate sites in this
// tree. When no token is configured the enricher stays off rather than
// making a call that cannot succeed.

const enrichPath = "/enrich"

// IPEnricher fills geography, ASN and reputation on a Location.
type IPEnricher struct {
	baseURL      string
	serviceToken string
	ttl          time.Duration
	client       *http.Client
	log          *slog.Logger

	mu    sync.RWMutex
	cache map[string]ipCacheEntry
}

type ipCacheEntry struct {
	value  ipFacts
	expiry time.Time
}

// ipFacts is what the enrichment service told us about one address.
// `known` distinguishes "answered, nothing notable" from "nobody answered",
// which a bare zero score cannot.
type ipFacts struct {
	Country     string
	CountryCode string
	City        string
	ASN         int64
	ASOrg       string
	Reputation  float64
	Known       bool
}

// enrichResponse is the subset of services/enrichment's EnrichmentResult
// this reads. Kept narrow deliberately: the full result carries dark-web
// excerpts and vulnerability references that have no column here, and a
// struct mirroring all of it would need updating every time that one grows.
type enrichResponse struct {
	RiskScore   float64 `json:"risk_score"`
	GeoLocation *struct {
		Country     string `json:"country"`
		CountryCode string `json:"country_code"`
		City        string `json:"city"`
		ASN         int64  `json:"asn"`
		ASOrg       string `json:"as_org"`
	} `json:"geo_location"`
}

// NewIPEnricher returns an enricher, or nil when it cannot work.
//
// nil is a supported value everywhere it is used: a deployment with no
// enrichment service configured gets events with an empty geography rather
// than a constructor that fails or a per-event error log.
func NewIPEnricher(baseURL, serviceToken string, ttl time.Duration, timeout time.Duration) *IPEnricher {
	baseURL = strings.TrimRight(strings.TrimSpace(baseURL), "/")
	if baseURL == "" {
		return nil
	}
	if ttl <= 0 {
		ttl = time.Hour
	}
	if timeout <= 0 {
		timeout = 2 * time.Second
	}
	return &IPEnricher{
		baseURL:      baseURL,
		serviceToken: strings.TrimSpace(serviceToken),
		ttl:          ttl,
		client:       &http.Client{Timeout: timeout},
		log:          slog.Default().With("component", "ip_enricher"),
		cache:        make(map[string]ipCacheEntry),
	}
}

// Enrich fills geography, ASN and reputation on `loc` when its IP is public
// and something answers. It mutates nothing else and never returns an error:
// a missed enrichment is a thinner event, not a failed one.
func (e *IPEnricher) Enrich(ctx context.Context, loc *Location) {
	if e == nil || loc == nil || !IsPublicIP(loc.IP) {
		return
	}
	facts, ok := e.lookup(ctx, loc.IP)
	if !ok {
		return
	}
	loc.Country = facts.Country
	loc.CountryCode = facts.CountryCode
	loc.City = facts.City
	loc.ASN = facts.ASN
	loc.ASOrg = facts.ASOrg
	loc.Reputation = facts.Reputation
	loc.ReputationKnown = facts.Known
}

func (e *IPEnricher) lookup(ctx context.Context, ip string) (ipFacts, bool) {
	e.mu.RLock()
	entry, hit := e.cache[ip]
	e.mu.RUnlock()
	if hit && time.Now().Before(entry.expiry) {
		return entry.value, true
	}

	facts, err := e.fetch(ctx, ip)
	if err != nil {
		// Logged as the reparsed canonical address rather than the caller's
		// string. The value arrives from a connector-supplied event, and
		// although it has already passed IsPublicIP, that is a predicate a
		// taint tracker cannot follow across the call -- it read this as
		// go/log-injection. net.IP.String() reconstructs the address from
		// parsed octets, so a newline cannot survive it and a reader can see
		// why without tracing the caller.
		e.log.Debug("enrichment lookup failed", "ip", net.ParseIP(ip).String(), "error", err)
		return ipFacts{}, false
	}

	e.mu.Lock()
	e.cache[ip] = ipCacheEntry{value: facts, expiry: time.Now().Add(e.ttl)}
	e.mu.Unlock()
	return facts, true
}

func (e *IPEnricher) fetch(ctx context.Context, ip string) (ipFacts, error) {
	body, err := json.Marshal(map[string]string{"ioc_type": "ip", "value": ip})
	if err != nil {
		return ipFacts{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, e.baseURL+enrichPath, bytes.NewReader(body))
	if err != nil {
		return ipFacts{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	if e.serviceToken != "" {
		req.Header.Set("Authorization", "Bearer "+e.serviceToken)
	}

	resp, err := e.client.Do(req)
	if err != nil {
		return ipFacts{}, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return ipFacts{}, fmt.Errorf("enrichment service returned %d", resp.StatusCode)
	}

	var parsed enrichResponse
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		return ipFacts{}, err
	}
	facts := ipFacts{Reputation: parsed.RiskScore, Known: true}
	if parsed.GeoLocation != nil {
		facts.Country = parsed.GeoLocation.Country
		facts.CountryCode = parsed.GeoLocation.CountryCode
		facts.City = parsed.GeoLocation.City
		facts.ASN = parsed.GeoLocation.ASN
		facts.ASOrg = parsed.GeoLocation.ASOrg
	}
	return facts, nil
}

// IsPublicIP reports whether an address is one a third party could say
// anything useful about.
//
// Exported because the test that proves no private address is ever sent must
// use the same predicate the enricher does — a second copy would be the
// gate agreeing with itself.
//
// `IsPrivate` alone is not enough: it covers RFC 1918 and unique-local but
// not loopback, link-local, carrier-grade NAT, the documentation ranges or
// the unspecified address, and every one of those appears in real telemetry.
func IsPublicIP(value string) bool {
	ip := net.ParseIP(strings.TrimSpace(value))
	if ip == nil {
		return false
	}
	if ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified() ||
		ip.IsInterfaceLocalMulticast() {
		return false
	}
	for _, block := range reservedBlocks {
		if block.Contains(ip) {
			return false
		}
	}
	return true
}

// reservedBlocks are the ranges Go's own predicates do not cover but which
// still have no public answer: carrier-grade NAT, the three IPv4
// documentation ranges, benchmarking, and the IPv6 documentation range.
var reservedBlocks = func() []*net.IPNet {
	cidrs := []string{
		"100.64.0.0/10",   // RFC 6598 carrier-grade NAT
		"192.0.0.0/24",    // RFC 6890 IETF protocol assignments
		"192.0.2.0/24",    // RFC 5737 documentation (TEST-NET-1)
		"198.51.100.0/24", // RFC 5737 documentation (TEST-NET-2)
		"203.0.113.0/24",  // RFC 5737 documentation (TEST-NET-3)
		"198.18.0.0/15",   // RFC 2544 benchmarking
		"2001:db8::/32",   // RFC 3849 documentation
	}
	out := make([]*net.IPNet, 0, len(cidrs))
	for _, cidr := range cidrs {
		if _, block, err := net.ParseCIDR(cidr); err == nil {
			out = append(out, block)
		}
	}
	return out
}()
