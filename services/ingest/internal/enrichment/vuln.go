// Package enrichment — CVE / vulnerability correlation.
//
// VulnCorrelator checks CVE IDs found in events (or from Shodan) against
// the CISA Known Exploited Vulnerabilities catalogue and emits structured
// VulnMatch objects for each hit.
//
// Cyble Open-Source AI Security Operations Center — MIT License
package enrichment

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"
)

const (
	cisaKevURL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
)

// VulnMatch is the payload emitted to Kafka when a CVE correlation fires.
type VulnMatch struct {
	EventID    string     `json:"event_id"`
	SourceIP   string     `json:"source_ip"`
	CVE        string     `json:"cve_id"`
	KEVEntry   *KevEntry  `json:"kev_entry,omitempty"`
	DetectedAt time.Time  `json:"detected_at"`
	TenantID   string     `json:"tenant_id,omitempty"`
}

// KevEntry represents a single CISA KEV catalogue entry.
type KevEntry struct {
	CVEID             string `json:"cveID"`
	VendorProject     string `json:"vendorProject"`
	Product           string `json:"product"`
	VulnerabilityName string `json:"vulnerabilityName"`
	DateAdded         string `json:"dateAdded"`
	ShortDescription  string `json:"shortDescription"`
	RequiredAction    string `json:"requiredAction"`
	DueDate           string `json:"dueDate"`
}

// VulnCorrelator cross-references CVE IDs against the CISA KEV catalogue.
type VulnCorrelator struct {
	httpClient  *http.Client
	kevIndex    map[string]*KevEntry
	lastUpdated time.Time
	mu          sync.RWMutex
	log         *slog.Logger
}

// NewVulnCorrelator creates a correlator; call LoadKEV before first use.
func NewVulnCorrelator() *VulnCorrelator {
	return &VulnCorrelator{
		httpClient: &http.Client{Timeout: 15 * time.Second},
		kevIndex:   make(map[string]*KevEntry),
		log:        slog.Default().With("component", "vuln_correlator"),
	}
}

// LoadKEV fetches the CISA KEV catalogue.
func (v *VulnCorrelator) LoadKEV(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, cisaKevURL, nil)
	if err != nil {
		return err
	}
	resp, err := v.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("CISA KEV returned %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	if err := v.parseKEV(body); err != nil {
		return err
	}

	v.log.Info("CISA KEV catalogue loaded", "entries", len(v.kevIndex))
	v.lastUpdated = time.Now()
	return nil
}

// Correlate checks an event plus optional Shodan CVEs for KEV matches.
// Returns a (potentially empty) slice of VulnMatch.
func (v *VulnCorrelator) Correlate(event map[string]interface{}, shodanCVEs []string) []VulnMatch {
	v.mu.RLock()
	defer v.mu.RUnlock()

	if len(v.kevIndex) == 0 {
		return nil
	}

	seen := make(map[string]bool)
	var matches []VulnMatch

	allCVEs := append(extractCVEsFromEvent(event), shodanCVEs...)

	for _, cve := range allCVEs {
		upper := strings.ToUpper(cve)
		if seen[upper] {
			continue
		}
		seen[upper] = true

		if entry, ok := v.kevIndex[upper]; ok {
			matches = append(matches, VulnMatch{
				EventID:    stringField(event, "event_id"),
				SourceIP:   stringField(event, "src_ip"),
				CVE:        upper,
				KEVEntry:   entry,
				DetectedAt: time.Now().UTC(),
				TenantID:   stringField(event, "tenant_uid"),
			})
		}
	}

	return matches
}

// Size returns the number of KEV entries loaded.
func (v *VulnCorrelator) Size() int {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return len(v.kevIndex)
}

// ─── Private helpers ──────────────────────────────────────────────────────────

type kevCatalog struct {
	Vulnerabilities []*KevEntry `json:"vulnerabilities"`
}

func (v *VulnCorrelator) parseKEV(data []byte) error {
	var cat kevCatalog
	if err := json.Unmarshal(data, &cat); err != nil {
		return err
	}

	v.mu.Lock()
	defer v.mu.Unlock()

	v.kevIndex = make(map[string]*KevEntry, len(cat.Vulnerabilities))
	for _, e := range cat.Vulnerabilities {
		entry := e
		v.kevIndex[strings.ToUpper(entry.CVEID)] = entry
	}
	return nil
}

func extractCVEsFromEvent(event map[string]interface{}) []string {
	cveFields := []string{"cve_id", "cve", "vuln_id", "vulnerability_id"}
	var ids []string
	for _, f := range cveFields {
		if v, ok := event[f]; ok {
			switch val := v.(type) {
			case string:
				if looksLikeCVE(val) {
					ids = append(ids, val)
				}
			case []interface{}:
				for _, item := range val {
					if s, ok := item.(string); ok && looksLikeCVE(s) {
						ids = append(ids, s)
					}
				}
			}
		}
	}
	return ids
}

func looksLikeCVE(s string) bool {
	return strings.HasPrefix(strings.ToUpper(strings.TrimSpace(s)), "CVE-")
}

func stringField(event map[string]interface{}, key string) string {
	if v, ok := event[key]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}
