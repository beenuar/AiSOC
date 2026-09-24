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
	// splunk — connector type emitted by SplunkConnector (#528). Its
	// fetch_alerts already returns a canonical envelope (external_id / title /
	// severity / src_ip / hostname / created_at + the original row under
	// raw_event), so the field map reads those lowercase canonical keys, NOT
	// raw Splunk fields. Class 2001 (Security Finding, category 2) means the
	// fusion promoter promotes a notable as a vendor-asserted finding
	// regardless of severity, so a Medium notable is never silently dropped.
	"splunk": {
		product:   OcsfProduct{Name: "Splunk", VendorName: "Splunk"},
		classUID:  2001,
		className: "Security Finding",
		fieldMap: map[string]string{
			"title":       "message",
			"external_id": "finding.uid",
			"src_ip":      "src_endpoint.ip",
			"hostname":    "device.name",
		},
		severityMap: map[string]int{
			"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1, "informational": 1,
		},
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
	// ai_runtime / ai_guardrail — the customer's AI estate.
	//
	// Two profiles rather than one, and the split is load-bearing. Routine AI
	// activity (a tool call, a model invocation, an MCP request) is 6003 API
	// Activity: category 6, so should_promote() leaves it in the lake unless
	// severity reaches high, and analysts hunt it. A guardrail finding is 2001
	// Security Finding: category 2, which the promoter always promotes,
	// because something has already judged it worth a human's attention.
	//
	// Collapsing them would fail in one of two ways. All-2001 means a chatty
	// agent floods the alert queue with its own normal operation. All-6003
	// means a detected prompt injection sits silently in the lake.
	//
	// Field names match the ai-runtime.yaml / ai-finding.yaml webhook
	// templates so the pull and push paths produce the same OCSF shape.
	"ai_runtime": {
		product:   OcsfProduct{Name: "AI Runtime", VendorName: "AiSOC"},
		classUID:  6003,
		className: "API Activity",
		fieldMap: map[string]string{
			"agent_id":     "actor.process.name",
			"agent_name":   "actor.process.path",
			"on_behalf_of": "actor.user.name",
			"tool_name":    "activity_name",
			"model":        "metadata.product.feature.name",
			"provider":     "cloud.provider",
			"server_name":  "resource.name",
			"source_ip":    "src_endpoint.ip",
			"hostname":     "src_endpoint.hostname",
			"outcome":      "status_detail",
			"latency_ms":   "duration",
			"timestamp":    "time",
		},
		severityMap: map[string]int{
			"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1, "informational": 1,
		},
	},
	"ai_guardrail": {
		product:   OcsfProduct{Name: "AI Guardrail", VendorName: "AiSOC"},
		classUID:  2001,
		className: "Security Finding",
		fieldMap: map[string]string{
			"finding_id":   "finding.uid",
			"finding_type": "activity_name",
			"title":        "message",
			"description":  "finding.desc",
			"agent_id":     "actor.process.name",
			"on_behalf_of": "actor.user.name",
			"model":        "metadata.product.feature.name",
			"provider":     "cloud.provider",
			"server_name":  "resource.name",
			"source_ip":    "src_endpoint.ip",
			"hostname":     "src_endpoint.hostname",
			"timestamp":    "time",
		},
		severityMap: map[string]int{
			"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1, "informational": 1,
		},
	},
	// kubernetes_audit — Track D, v7.1.0.
	//
	// The apiserver POSTs a v1 EventList batch and we explode it into
	// individual events upstream of Normalize, so by the time we get
	// here `payload` is one audit.k8s.io/v1 Event JSON object. Class
	// 6003 is the OCSF "API Activity" class which is the right shape
	// for a request/response style event with verb + resource + actor.
	// Severity is derived from the connector's heuristic and arrives
	// as a lowercase string; the map below mirrors KubernetesAuditConnector
	// so on-prem file_tail and webhook events end up with the same
	// severity_id.
	// email_inbox — the pull side of the forwarded-email path.
	//
	// EmailInboxConnector.normalize() deliberately returns the message
	// envelope unchanged, because it is shaped for the email-forwarded.yaml
	// template rather than for the canonical connector envelope. That left it
	// as the one registered connector whose events reach neither a profile nor
	// the canonical branch, so strict mode rejected them outright and lenient
	// mode resolved a title and nothing else.
	//
	// The field map mirrors email-forwarded.yaml so the pull and push paths
	// produce the same OCSF shape, the same way ai_runtime mirrors
	// ai-runtime.yaml. Keep the two aligned.
	"email_inbox": {
		product:   OcsfProduct{Name: "Forwarded Email", VendorName: "Email"},
		classUID:  2001,
		className: "Security Finding",
		fieldMap: map[string]string{
			"subject":    "finding.title",
			"body":       "finding.desc",
			"message_id": "finding.uid",
			"from":       "actor.user.email_addr",
			"to":         "target_user.email_addr",
		},
		severityMap: map[string]int{
			"critical": 5, "high": 4, "medium": 3, "normal": 3, "low": 2, "info": 1, "informational": 1,
		},
	},
	"kubernetes_audit": {
		product:   OcsfProduct{Name: "Kubernetes Audit", VendorName: "Kubernetes"},
		classUID:  6003,
		className: "API Activity",
		fieldMap: map[string]string{
			"auditID":              "finding.uid",
			"verb":                 "activity_name",
			"user.username":        "actor.user.name",
			"objectRef.resource":   "finding.title",
			"objectRef.namespace":  "cloud.account.uid",
			"objectRef.name":       "resource.name",
			"sourceIPs.0":          "src_endpoint.ip",
			"userAgent":            "http_request.user_agent",
			"responseStatus.code":  "status_code",
			"stage":                "status_detail",
			"stageTimestamp":       "time",
		},
		severityMap: map[string]int{
			"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1, "informational": 1,
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

// Canonical connector-envelope handling.
//
// Pull connectors normalize inside their own fetch_alerts and emit a canonical
// envelope (source + raw_event + external_id/title/severity/src_ip/hostname/
// created_at), NOT a raw vendor row. Only a handful of connector types have a
// hand-written raw profile above, so historically every other connector (incl.
// CrowdStrike and Okta, whose profile keys never matched their connector ids)
// fell to the generic Network-Activity profile and lost its class + severity.
// We instead detect the envelope and map its canonical fields directly,
// defaulting to an OCSF Security Finding (class 2001, category 2) so vendor
// alerts promote regardless of severity.
var _canonicalSeverityMap = map[string]int{
	"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1, "informational": 1,
}

var _canonicalFieldMap = map[string]string{
	"title":       "message",
	"external_id": "finding.uid",
}

// _canonicalAliases fills one OCSF destination from the first connector field
// that carries a value, in declared order.
//
// This is a slice and not more fieldMap entries because Go randomises map
// iteration: three entries pointing at actor.user.name would resolve to a
// different one of them per process, which is a correctness bug that only
// shows up as flakiness. Declared order is the precedence.
//
// The aliases exist because the canonical map recognised only `actor`, and a
// count across the 68 canonical-envelope connectors found 40 using `actor`
// but 11 using `username` or `user`. Those eleven lost their identity on the
// way through, and the fusion correlation key is {tenant}:{entity}:{tactic},
// so a missing actor does not merely blank a column — it collapses the
// entity segment to "unknown" and every one of that connector's alerts
// correlates into the same bucket.
//
// The dotted sources dig one level for a scalar. Replaying the registry's 84
// connectors through normalize() found 14 emitting `actor`, and four of those
// emit it as the vendor's nested object rather than a name. A bare key alone
// would hand that object to setNestedField and write a map into a slot the
// entity extractor reads as a name, so each bare key is followed by the
// scalar-bearing paths underneath it.
var _canonicalAliases = []struct {
	dst     string
	sources []string
}{
	{"actor.user.name", []string{"actor", "actor.name", "actor.displayName", "actor.username", "username", "user", "user.name", "user.username", "user_name"}},
	{"device.name", []string{"hostname", "host", "host.name", "device_name", "device", "device.name", "device.hostname"}},
	{"src_endpoint.ip", []string{"src_ip", "source_ip", "client_ip", "src_endpoint.ip", "client.ipAddress"}},
	// Not identity, but the same fill-the-blank rule and the same reason to
	// run everywhere. A vendor profile names the field its vendor's rows use
	// — crowdstrike_falcon reads event_simpleName, not title — so a pushed
	// payload that reaches a vendor profile left `message` empty and the
	// promoter fell back to generating "Security Finding from <product>",
	// discarding the title the caller actually sent. These two are the same
	// pair _canonicalFieldMap declares; listing them here extends their reach
	// to the vendor profiles without giving them a second mechanism.
	{"message", []string{"title"}},
	{"finding.uid", []string{"external_id"}},
}

// connectorTypeAliases maps a connector identifier the connectors service
// actually declares onto the profile key that carries its vendor field map.
//
// Two vocabularies grew up either side of the wire. services/connectors
// declares `crowdstrike` and `okta`; this file keyed their profiles
// `crowdstrike_falcon` and `okta_system_log`, and so does the rest of the
// platform — packages/types' ConnectorType union, the CLI's default, the
// graph extractor and the actions credential resolver all use the longer
// names. Renaming either side breaks the other, so both resolve instead.
//
// Without this an event whose connector_type is the name the product itself
// advertises — including the one the README tells a new user to paste — missed
// the profile lookup and fell to the generic fallback, taking generic vendor
// attribution with it.
//
// `splunk` is deliberately absent: it has its own profile for the canonical
// envelope SplunkConnector emits, which is a different shape from the raw
// rows `splunk_enterprise` maps.
var connectorTypeAliases = map[string]string{
	"crowdstrike": "crowdstrike_falcon",
	"okta":        "okta_system_log",
}

// canonicalClassByConnector overrides the default Security Finding class for
// connector types whose canonical alerts are better modeled as another OCSF
// class (identity providers -> Authentication 3002).
var canonicalClassByConnector = map[string]struct {
	classUID  int
	className string
}{
	"okta":         {3002, "Authentication"},
	"azure_entra":  {3002, "Authentication"},
	"auth0":        {3002, "Authentication"},
	"duo_security": {3002, "Authentication"},
	"onepassword":  {3002, "Authentication"},
}

func isCanonicalEnvelope(p map[string]interface{}) bool {
	if p == nil {
		return false
	}
	_, hasRaw := p["raw_event"]
	_, hasSource := p["source"]
	return hasRaw && hasSource
}

// genericProfile is the fallback for a connector type with no declared
// profile. It replaces a borrow of the splunk_enterprise profile, which was
// wrong in two compounding ways.
//
// First, attribution: splunk_enterprise stamps
// OcsfProduct{Name: "Splunk Enterprise", VendorName: "Splunk"}, and the
// promoter derives alert.source from metadata.product. Every profile-less
// connector's alerts therefore read as coming from Splunk. Only eight profiles
// are declared, so that was the majority of the catalogue.
//
// Second, and worse, promotion: splunk_enterprise is classUID 4001 (Network
// Activity) with an EMPTY severityMap. should_promote() requires OCSF category
// 2 or severity_id >= 4, and an empty map yields severity_id 0 — so category 4
// with severity 0 can satisfy neither branch. Those events were archived to the
// lake and could never become alerts, silently, for any connector without a
// profile.
//
// The generic profile uses 2001 Security Finding because a connector's
// fetch_alerts() contract is to return findings rather than raw telemetry, and
// carries the five-tier severity ladder so a vendor severity string maps.
// Product identity is derived from the connector type, so attribution is at
// worst uninformative rather than actively wrong.
func genericProfile(connectorType string) connectorProfile {
	name := connectorType
	if name == "" {
		name = "Connector"
	}
	return connectorProfile{
		product:     OcsfProduct{Name: name, VendorName: name},
		classUID:    2001,
		className:   "Security Finding",
		fieldMap:    _canonicalFieldMap,
		severityMap: _canonicalSeverityMap,
	}
}

func canonicalProfile(connectorType string) connectorProfile {
	classUID, className := 2001, "Security Finding"
	if override, ok := canonicalClassByConnector[connectorType]; ok {
		classUID, className = override.classUID, override.className
	}
	name := connectorType
	if name == "" {
		name = "Connector"
	}
	return connectorProfile{
		product:     OcsfProduct{Name: name, VendorName: name},
		classUID:    classUID,
		className:   className,
		fieldMap:    _canonicalFieldMap,
		severityMap: _canonicalSeverityMap,
	}
}

// Normalize converts a raw event to a NormalizedEvent
func (n *Normalizer) Normalize(raw *RawEvent) (*NormalizedEvent, error) {
	if raw.TenantID == "" {
		return nil, fmt.Errorf("tenant_id is required")
	}

	var profile connectorProfile
	isCanonical := isCanonicalEnvelope(raw.Payload)
	if isCanonical {
		// Connector-normalized envelope: map its canonical fields directly.
		profile = canonicalProfile(raw.ConnectorType)
	} else {
		var ok bool
		profile, ok = connectorProfiles[raw.ConnectorType]
		if !ok {
			if aliased, isAlias := connectorTypeAliases[raw.ConnectorType]; isAlias {
				profile, ok = connectorProfiles[aliased]
			}
		}
		if !ok {
			if n.cfg.NormalizerMode == "strict" {
				return nil, fmt.Errorf("unknown connector type: %s", raw.ConnectorType)
			}
			// Lenient: a vendor-neutral generic profile. This used to borrow
			// splunk_enterprise, which mis-attributed every profile-less
			// connector to Splunk and — because that profile is category 4
			// with an empty severity map — made its events unpromotable.
			profile = genericProfile(raw.ConnectorType)
			log.Warn().Str("connector_type", raw.ConnectorType).Msg("Using generic profile for unknown connector")
		}
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
	} else if t, ok := raw.Payload["created_at"].(string); ok && t != "" {
		// Canonical connector envelopes (e.g. Splunk, #528) carry the event
		// time under created_at; honor it so the notable's event time survives.
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

	// Resolve identity aliases in declared order for every profile, filling
	// only destinations the field map left empty.
	//
	// This used to run for canonical envelopes alone, which left the generic
	// fallback resolving nothing but title and external_id. Everything
	// downstream is keyed on identity — entity extraction, the Investigation
	// Rail's pivots, the {tenant}:{entity}:{tactic} correlation key, the
	// entity graph, UEBA — so an event that arrives through the fallback
	// became an alert with no host, no user and no IP, and nobody could pivot
	// from it. The alert appears, which is what makes it look like it worked.
	//
	// Filling only empty destinations is what keeps this safe to run over the
	// hand-written vendor profiles too: a profile that names its own field for
	// a slot always wins, and the aliases reach only the slots it left blank.
	for _, alias := range _canonicalAliases {
		if getNestedField(ocsf, alias.dst) != nil {
			continue
		}
		if val, found := firstIdentityString(raw.Payload, alias.sources); found {
			setNestedField(ocsf, alias.dst, val)
		}
	}

	// Map severity. A vendor profile's own ladder wins; the shared five-tier
	// ladder is consulted only when that ladder has no entry for the value.
	//
	// The fallback matters because a profile's ladder is spelled the way its
	// vendor spells it — crowdstrike_falcon's is capitalised — while a pushed
	// payload is written by whoever is pushing, and the README's is lowercase.
	// Without the fallback a "high" that the ladder spells "High" scores 0 and
	// renders as Unknown. Case folding alone would not do: the shared ladder
	// keeps `critical` a distinct fifth tier, so a vendor-native critical maps
	// to critical rather than collapsing into high.
	if sevField, ok := raw.Payload["severity"].(string); ok {
		sevID, found := profile.severityMap[sevField]
		if !found {
			sevID, found = _canonicalSeverityMap[strings.ToLower(strings.TrimSpace(sevField))]
		}
		if found {
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
	// Replay-stable id: derived from tenant + connector + a stable vendor id
	// (see generateEventID). Reused as the envelope ID + Kafka key below so a
	// re-ingested event dedups end-to-end (Kafka key + ClickHouse event_id).
	eventID := generateEventID(raw)
	ocsf["event_id"] = eventID

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

	return &NormalizedEvent{
		ID:                    eventID,
		ConnectorID:           raw.ConnectorID,
		TenantID:              raw.TenantID,
		OcsfEvent:             ocsf,
		NormalizationVersion:  n.version,
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

// firstIdentityString returns the first non-empty string among the given dotted
// payload paths, in the order given, and whether one was found.
//
// The string requirement is the point. An identity destination — actor.user.name,
// device.name, src_endpoint.ip — is a scalar the entity extractor turns into a
// pivotable chip and the correlator folds into {tenant}:{entity}:{tactic}.
// Several connectors pass the vendor's nested actor object through under the
// same key a scalar would use, and writing that object into the slot produces
// an entity that renders as a map and correlates as garbage. Skipping it lets
// the next path in the list — the scalar one underneath — resolve instead.
func firstIdentityString(payload map[string]interface{}, paths []string) (string, bool) {
	for _, p := range paths {
		if s, ok := getNestedField(payload, p).(string); ok {
			if trimmed := strings.TrimSpace(s); trimmed != "" {
				return trimmed, true
			}
		}
	}
	return "", false
}

// firstString returns the first non-empty string value among the given payload
// keys, or "" if none are present.
func firstString(payload map[string]interface{}, keys ...string) string {
	for _, k := range keys {
		if v, ok := payload[k].(string); ok && v != "" {
			return v
		}
	}
	return ""
}

// generateEventID creates a deterministic, replay-stable event ID for
// deduplication (#529).
//
// It is derived from the connector instance + tenant + a STABLE vendor
// identifier (external_id / event_id / id / _cd, in priority order) so
// re-ingesting the same event — overlapping poll windows, backfills, restarts —
// always yields the same canonical ID. ReceivedAt is deliberately excluded from
// this path; it is set per poll and previously made the ID change on every
// poll. When no stable vendor ID exists we fall back to the event time plus a
// content hash of the payload, so a byte-identical replay still collapses to
// one ID while two same-timestamp events with different content stay distinct.
func generateEventID(raw *RawEvent) string {
	base := fmt.Sprintf("%s:%s", raw.ConnectorID, raw.TenantID)
	for _, field := range []string{"external_id", "event_id", "id", "_cd"} {
		if v, ok := raw.Payload[field].(string); ok && v != "" {
			return uuid.NewSHA1(uuid.NameSpaceOID, []byte(base+":"+field+"="+v)).String()
		}
	}
	key := base
	if t := firstString(raw.Payload, "time", "created_at", "timestamp"); t != "" {
		key += ":t=" + t
	} else {
		key += ":r=" + raw.ReceivedAt
	}
	// json.Marshal sorts map keys, so the same payload always hashes to the
	// same content string — the hash is deterministic across replays.
	if rawBytes, err := json.Marshal(raw.Payload); err == nil {
		key += ":c=" + string(rawBytes)
	}
	return uuid.NewSHA1(uuid.NameSpaceOID, []byte(key)).String()
}
