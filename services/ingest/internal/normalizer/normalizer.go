// Package normalizer converts raw connector events to OCSF format
package normalizer

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/beenuar/aisoc/services/ingest/internal/attck"
	"github.com/beenuar/aisoc/services/ingest/internal/config"
	"github.com/beenuar/aisoc/services/ingest/internal/enrichment"
	"github.com/google/uuid"
	"github.com/rs/zerolog/log"
)

// OcsfBaseEvent is a minimal representation of an OCSF event for internal processing
type OcsfBaseEvent struct {
	ClassUID     int                    `json:"class_uid"`
	ClassName    string                 `json:"class_name"`
	CategoryUID  int                    `json:"category_uid"`
	CategoryName string                 `json:"category_name"`
	ActivityID   int                    `json:"activity_id"`
	TypeUID      int                    `json:"type_uid"`
	Time         string                 `json:"time"`
	SeverityID   int                    `json:"severity_id"`
	Severity     string                 `json:"severity"`
	Metadata     OcsfMetadata           `json:"metadata"`
	TenantUID    string                 `json:"tenant_uid"`
	ConnectorID  string                 `json:"source_connector_id"`
	IngestTime   string                 `json:"ingest_time"`
	EventID      string                 `json:"event_id"`
	RawData      string                 `json:"raw_data,omitempty"`
	Extra        map[string]interface{} `json:"-"`
}

// OcsfMetadata contains event metadata
type OcsfMetadata struct {
	Version     string      `json:"version"`
	Product     OcsfProduct `json:"product"`
	TenantUID   string      `json:"tenant_uid,omitempty"`
	IngestedAt  string      `json:"ingested_time"`
	OriginalAt  string      `json:"original_time,omitempty"`
}

// OcsfProduct identifies the source product
type OcsfProduct struct {
	Name       string `json:"name"`
	VendorName string `json:"vendor_name"`
	Version    string `json:"version,omitempty"`
}

// RawEvent is the input from a connector
type RawEvent struct {
	ConnectorID   string                 `json:"connector_id"`
	ConnectorType string                 `json:"connector_type"`
	TenantID      string                 `json:"tenant_id"`
	ReceivedAt    string                 `json:"received_at"`
	Payload       map[string]interface{} `json:"payload"`
	SourceFormat  string                 `json:"source_format"`
}

// NormalizedEvent is the output ready for Kafka
type NormalizedEvent struct {
	ID                    string                 `json:"id"`
	ConnectorID           string                 `json:"connector_id"`
	TenantID              string                 `json:"tenant_id"`
	OcsfEvent             map[string]interface{} `json:"ocsf_event"`
	NormalizationVersion  string                 `json:"normalization_version"`
	NormalizationWarnings []string               `json:"normalization_warnings,omitempty"`
}

// Normalizer converts raw events to OCSF
type Normalizer struct {
	cfg        *config.Config
	version    string
	shodan     *enrichment.ShodanEnricher
	vulnCorrel *enrichment.VulnCorrelator

	// VulnMatches is a channel where VULNERABILITY_MATCH events are published.
	// Nil if vuln correlation is disabled.
	VulnMatches chan enrichment.VulnMatch
}

// connectorProfile defines normalization rules for a connector type
type connectorProfile struct {
	product    OcsfProduct
	classUID   int
	className  string
	fieldMap   map[string]string
	severityMap map[string]int
}

var connectorProfiles = map[string]connectorProfile{
	"crowdstrike_falcon": {
		product:   OcsfProduct{Name: "Falcon", VendorName: "CrowdStrike"},
		classUID:  2001,
		className: "Security Finding",
		fieldMap: map[string]string{
			"event_simpleName": "activity_name",
			"ComputerName":     "device.name",
			"UserName":         "actor.user.name",
			"SHA256HashData":   "file.fingerprints[0].value",
			"timestamp":        "time",
		},
		severityMap: map[string]int{
			"Critical": 5, "High": 4, "Medium": 3, "Low": 2, "Informational": 1,
		},
	},
	"microsoft_sentinel": {
		product:   OcsfProduct{Name: "Sentinel", VendorName: "Microsoft"},
		classUID:  2002,
		className: "Security Finding",
		fieldMap: map[string]string{
			"TimeGenerated":  "time",
			"AlertName":      "message",
			"CompromisedEntity": "device.name",
			"Severity":       "severity",
		},
		severityMap: map[string]int{
			"High": 4, "Medium": 3, "Low": 2, "Informational": 1,
		},
	},
	"splunk_enterprise": {
		product:   OcsfProduct{Name: "Splunk Enterprise", VendorName: "Splunk"},
		classUID:  4001,
		className: "Network Activity",
		fieldMap: map[string]string{
			"_time": "time",
			"src":   "src_endpoint.ip",
			"dst":   "dst_endpoint.ip",
			"user":  "actor.user.name",
		},
		severityMap: map[string]int{},
	},
	"okta_system_log": {
		product:   OcsfProduct{Name: "Okta System Log", VendorName: "Okta"},
		classUID:  3002,
		className: "Authentication",
		fieldMap: map[string]string{
			"published":           "time",
			"actor.alternateId":   "actor.user.email_addr",
			"actor.displayName":   "actor.user.name",
			"client.ipAddress":    "src_endpoint.ip",
			"outcome.result":      "status",
		},
		severityMap: map[string]int{
			"ERROR": 4, "WARN": 3, "INFO": 1, "DEBUG": 1,
		},
	},
	"aws_security_hub": {
		product:   OcsfProduct{Name: "Security Hub", VendorName: "AWS"},
		classUID:  2001,
		className: "Security Finding",
		fieldMap: map[string]string{
			"UpdatedAt":   "time",
			"Title":       "message",
			"Description": "raw_data",
			"Severity.Label": "severity",
		},
		severityMap: map[string]int{
			"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFORMATIONAL": 1,
		},
	},
}

// New creates a new Normalizer instance and loads the ATT&CK corpus.
func New(cfg *config.Config) (*Normalizer, error) {
	// Best-effort ATT&CK corpus load — normalizer works without it
	if err := attck.Load(cfg.AttckDataPath); err != nil {
		log.Warn().Err(err).Msg("ATT&CK corpus unavailable; technique enrichment disabled")
	}

	n := &Normalizer{
		cfg:     cfg,
		version: "1.1.0",
	}

	// Set up Shodan enrichment if configured
	if cfg.ShodanEnrichEnabled && cfg.ShodanAPIKey != "" {
		n.shodan = enrichment.NewShodanEnricher(
			cfg.ShodanAPIKey,
			time.Duration(cfg.ShodanCacheExpirySecs)*time.Second,
		)
		log.Info().Msg("Shodan enrichment enabled")
	}

	// Set up vulnerability correlation
	if cfg.VulnCorrelEnabled {
		n.vulnCorrel = enrichment.NewVulnCorrelator()
		n.VulnMatches = make(chan enrichment.VulnMatch, 256)

		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		if err := n.vulnCorrel.LoadKEV(ctx); err != nil {
			log.Warn().Err(err).Msg("CISA KEV load failed; vulnerability correlation disabled")
			n.vulnCorrel = nil
			close(n.VulnMatches)
			n.VulnMatches = nil
		} else {
			log.Info().Int("entries", n.vulnCorrel.Size()).Msg("CISA KEV catalogue loaded")
		}
	}

	return n, nil
}

// Normalize converts a raw event to a NormalizedEvent
func (n *Normalizer) Normalize(raw *RawEvent) (*NormalizedEvent, error) {
	if raw.TenantID == "" {
		return nil, fmt.Errorf("tenant_id is required")
	}

	profile, ok := connectorProfiles[raw.ConnectorType]
	if !ok {
		if n.cfg.NormalizerMode == "strict" {
			return nil, fmt.Errorf("unknown connector type: %s", raw.ConnectorType)
		}
		// Lenient: use generic profile
		profile = connectorProfiles["splunk_enterprise"]
		log.Warn().Str("connector_type", raw.ConnectorType).Msg("Using generic profile for unknown connector")
	}

	warnings := []string{}
	ocsf := make(map[string]interface{})

	// Set base OCSF fields
	ocsf["class_uid"] = profile.classUID
	ocsf["class_name"] = profile.className
	ocsf["category_uid"] = profile.classUID / 1000
	ocsf["activity_id"] = 1

	eventTime := raw.ReceivedAt
	if t, ok := raw.Payload["time"].(string); ok && t != "" {
		eventTime = t
	} else if t, ok := raw.Payload["timestamp"].(string); ok && t != "" {
		eventTime = t
	}
	ocsf["time"] = normalizeTime(eventTime)
	ocsf["ingest_time"] = time.Now().UTC().Format(time.RFC3339Nano)

	// Apply field mappings
	for srcField, dstField := range profile.fieldMap {
		if val := getNestedField(raw.Payload, srcField); val != nil {
			setNestedField(ocsf, dstField, val)
		}
	}

	// Map severity
	if sevField, ok := raw.Payload["severity"].(string); ok {
		if sevID, found := profile.severityMap[sevField]; found {
			ocsf["severity_id"] = sevID
			ocsf["severity"] = sevField
		} else {
			ocsf["severity_id"] = 0
			ocsf["severity"] = "Unknown"
			warnings = append(warnings, fmt.Sprintf("unmapped severity: %s", sevField))
		}
	} else {
		ocsf["severity_id"] = 0
		ocsf["severity"] = "Unknown"
	}

	// Set metadata
	ocsf["metadata"] = map[string]interface{}{
		"version": n.version,
		"product": profile.product,
		"tenant_uid": raw.TenantID,
		"ingested_time": time.Now().UTC().Format(time.RFC3339),
	}

	ocsf["tenant_uid"] = raw.TenantID
	ocsf["source_connector_id"] = raw.ConnectorID
	ocsf["event_id"] = generateEventID(raw)

	// Preserve raw data
	if rawBytes, err := json.Marshal(raw.Payload); err == nil {
		ocsf["raw_data"] = string(rawBytes)
	}

	// ATT&CK technique enrichment
	if attck.Loaded() {
		if techIDs := extractTechniqueIDs(raw.Payload); len(techIDs) > 0 {
			var enriched []map[string]interface{}
			for _, tid := range techIDs {
				if tech := attck.Lookup(tid); tech != nil {
					enriched = append(enriched, map[string]interface{}{
						"technique_id":   tech.ID,
						"technique_name": tech.Name,
						"tactic_ids":     tech.TacticIDs,
						"tactic_names":   tech.TacticNames,
						"url":            tech.URL,
					})
				}
			}
			if len(enriched) > 0 {
				ocsf["mitre_attck"] = enriched
			}
		}
	}

	// Shodan enrichment (non-blocking; best-effort)
	var shodanCVEs []string
	if n.shodan != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		ocsf = n.shodan.Enrich(ctx, ocsf)
		cancel()

		// Collect CVEs from Shodan result for vuln correlation
		if shodanBlock, ok := ocsf["shodan"].(map[string]interface{}); ok {
			if cves, ok := shodanBlock["cves"].([]string); ok {
				shodanCVEs = cves
			}
		}
	}

	// Vulnerability correlation — emit to VulnMatches channel
	if n.vulnCorrel != nil {
		matches := n.vulnCorrel.Correlate(ocsf, shodanCVEs)
		for _, m := range matches {
			select {
			case n.VulnMatches <- m:
			default:
				// Channel full — drop to avoid blocking ingest pipeline
				log.Warn().Str("cve", m.CVE).Msg("VulnMatches channel full; dropping match")
			}
		}
		if len(matches) > 0 {
			ocsf["vulnerability_matches"] = matches
		}
	}

	eventID := uuid.New().String()

	return &NormalizedEvent{
		ID:                   eventID,
		ConnectorID:          raw.ConnectorID,
		TenantID:             raw.TenantID,
		OcsfEvent:            ocsf,
		NormalizationVersion: n.version,
		NormalizationWarnings: warnings,
	}, nil
}

// extractTechniqueIDs scans common fields in a raw payload for ATT&CK technique IDs.
func extractTechniqueIDs(payload map[string]interface{}) []string {
	seen := map[string]struct{}{}
	var results []string

	candidateKeys := []string{
		"technique_id", "mitre_technique", "attck_technique", "tactic_id",
		"mitre_techniques", "attack_technique",
	}
	for _, key := range candidateKeys {
		val, ok := payload[key]
		if !ok {
			continue
		}
		switch v := val.(type) {
		case string:
			if tid := normalizeTechniqueID(v); tid != "" {
				if _, dup := seen[tid]; !dup {
					seen[tid] = struct{}{}
					results = append(results, tid)
				}
			}
		case []interface{}:
			for _, item := range v {
				if s, ok := item.(string); ok {
					if tid := normalizeTechniqueID(s); tid != "" {
						if _, dup := seen[tid]; !dup {
							seen[tid] = struct{}{}
							results = append(results, tid)
						}
					}
				}
			}
		}
	}
	return results
}

// normalizeTechniqueID extracts a clean ATT&CK technique ID from a string.
func normalizeTechniqueID(s string) string {
	s = strings.TrimSpace(strings.ToUpper(s))
	// Accept T1234 or T1234.001
	if len(s) >= 5 && s[0] == 'T' {
		parts := strings.SplitN(s, ".", 2)
		if len(parts[0]) >= 5 && len(parts[0]) <= 7 {
			return s
		}
	}
	return ""
}

// normalizeTime attempts to parse and re-format a timestamp as RFC3339
func normalizeTime(t string) string {
	formats := []string{
		time.RFC3339Nano,
		time.RFC3339,
		"2006-01-02T15:04:05.000Z",
		"2006-01-02T15:04:05Z",
		"2006-01-02 15:04:05",
		"01/02/2006 15:04:05",
	}
	for _, f := range formats {
		if parsed, err := time.Parse(f, t); err == nil {
			return parsed.UTC().Format(time.RFC3339Nano)
		}
	}
	return time.Now().UTC().Format(time.RFC3339Nano)
}

// getNestedField retrieves a value from a nested map using dot notation
func getNestedField(m map[string]interface{}, path string) interface{} {
	parts := strings.SplitN(path, ".", 2)
	val, ok := m[parts[0]]
	if !ok {
		return nil
	}
	if len(parts) == 1 {
		return val
	}
	if nested, ok := val.(map[string]interface{}); ok {
		return getNestedField(nested, parts[1])
	}
	return nil
}

// setNestedField sets a value in a nested map using dot notation
func setNestedField(m map[string]interface{}, path string, val interface{}) {
	parts := strings.SplitN(path, ".", 2)
	if len(parts) == 1 {
		m[parts[0]] = val
		return
	}
	nested, ok := m[parts[0]].(map[string]interface{})
	if !ok {
		nested = make(map[string]interface{})
		m[parts[0]] = nested
	}
	setNestedField(nested, parts[1], val)
}

// generateEventID creates a deterministic event ID for deduplication
func generateEventID(raw *RawEvent) string {
	key := fmt.Sprintf("%s:%s:%s", raw.ConnectorID, raw.TenantID, raw.ReceivedAt)
	if id, ok := raw.Payload["id"].(string); ok && id != "" {
		key += ":" + id
	}
	return uuid.NewSHA1(uuid.NameSpaceOID, []byte(key)).String()
}
