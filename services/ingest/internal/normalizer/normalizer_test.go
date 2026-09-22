package normalizer

import (
	"testing"

	"github.com/beenuar/aisoc/services/ingest/internal/config"
)

func newTestNormalizer() *Normalizer {
	return &Normalizer{cfg: &config.Config{NormalizerMode: "strict"}, version: "test"}
}

// newLenientNormalizer exercises the fallback path. Strict mode rejects an
// unknown connector type outright, so the generic-profile behaviour is only
// reachable in lenient mode — which is the deployed default.
func newLenientNormalizer() *Normalizer {
	return &Normalizer{cfg: &config.Config{NormalizerMode: "lenient"}, version: "test"}
}

// A canonical Splunk envelope (what SplunkConnector.fetch_alerts emits) must
// normalize as an OCSF Security Finding with its fields preserved, so the
// fusion promoter promotes it regardless of severity (#528).
func TestSplunkProfileNormalizesNotableAsFinding(t *testing.T) {
	n := newTestNormalizer()
	raw := &RawEvent{
		ConnectorID:   "conn-1",
		ConnectorType: "splunk",
		TenantID:      "11111111-1111-1111-1111-111111111111",
		ReceivedAt:    "2026-08-02T00:00:00Z",
		Payload: map[string]interface{}{
			"source":      "splunk",
			"external_id": "NOTABLE-42",
			"event_id":    "NOTABLE-42",
			"title":       "Brute Force Access Behavior Detected",
			"severity":    "medium",
			"src_ip":      "10.0.0.9",
			"hostname":    "web-01",
			"created_at":  "2026-08-01T23:59:00Z",
			"raw_event":   map[string]interface{}{"_time": "2026-08-01T23:59:00Z"},
		},
	}

	ev, err := n.Normalize(raw)
	if err != nil {
		t.Fatalf("Normalize returned error: %v", err)
	}
	ocsf := ev.OcsfEvent

	if got := ocsf["class_uid"]; got != 2001 {
		t.Errorf("class_uid = %v, want 2001 (Security Finding)", got)
	}
	if got := ocsf["category_uid"]; got != 2 {
		t.Errorf("category_uid = %v, want 2 (Findings) so the promoter promotes it", got)
	}
	if got := ocsf["severity_id"]; got != 3 {
		t.Errorf("severity_id = %v, want 3 (medium preserved)", got)
	}
	if got := ocsf["message"]; got != "Brute Force Access Behavior Detected" {
		t.Errorf("message = %v, want the rule title", got)
	}
	// hostname -> device.name (nested)
	if dev, ok := ocsf["device"].(map[string]interface{}); !ok || dev["name"] != "web-01" {
		t.Errorf("device.name not preserved: %v", ocsf["device"])
	}
	// external_id must not become empty (the double-normalize regression, #528)
	if finding, ok := ocsf["finding"].(map[string]interface{}); !ok || finding["uid"] != "NOTABLE-42" {
		t.Errorf("finding.uid not preserved: %v", ocsf["finding"])
	}
}

// The canonical event ID must be stable across polls: same vendor id + tenant +
// connector => same ID even though ReceivedAt changes every poll (#529).
func TestGenerateEventIDStableAcrossPolls(t *testing.T) {
	poll1 := &RawEvent{
		ConnectorID: "conn-1", TenantID: "t1", ReceivedAt: "2026-08-02T00:00:00Z",
		Payload: map[string]interface{}{"external_id": "NOTABLE-42"},
	}
	poll2 := &RawEvent{
		ConnectorID: "conn-1", TenantID: "t1", ReceivedAt: "2026-08-02T00:05:00Z", // later poll
		Payload: map[string]interface{}{"external_id": "NOTABLE-42"},
	}
	if generateEventID(poll1) != generateEventID(poll2) {
		t.Error("event ID changed across polls despite identical vendor id (#529)")
	}
}

func TestGenerateEventIDDistinctForDifferentEvents(t *testing.T) {
	a := &RawEvent{ConnectorID: "c", TenantID: "t", Payload: map[string]interface{}{"external_id": "A"}}
	b := &RawEvent{ConnectorID: "c", TenantID: "t", Payload: map[string]interface{}{"external_id": "B"}}
	if generateEventID(a) == generateEventID(b) {
		t.Error("distinct vendor ids collided to the same event ID")
	}
}

// Two events with the same timestamp but different content and no stable vendor
// id must both be ingestible (distinct IDs), while a byte-identical replay
// collapses to one (#529).
func TestGenerateEventIDContentFallback(t *testing.T) {
	mk := func(msg string) *RawEvent {
		return &RawEvent{
			ConnectorID: "c", TenantID: "t", ReceivedAt: "2026-08-02T00:00:00Z",
			Payload: map[string]interface{}{"time": "2026-08-01T00:00:00Z", "message": msg},
		}
	}
	if generateEventID(mk("one")) == generateEventID(mk("two")) {
		t.Error("same-timestamp events with different content collided")
	}
	if generateEventID(mk("one")) != generateEventID(mk("one")) {
		t.Error("identical replay produced different IDs")
	}
}

// A canonical connector envelope (source + raw_event) must be recognised and
// mapped to an OCSF Security Finding regardless of connector_type, so
// CrowdStrike/SentinelOne/etc. stop falling to the generic Network-Activity
// profile (Wave 0).
func TestCanonicalEnvelopeMapsToFinding(t *testing.T) {
	n := newTestNormalizer()
	raw := &RawEvent{
		ConnectorID:   "c1",
		ConnectorType: "crowdstrike", // has no raw profile keyed "crowdstrike"
		TenantID:      "11111111-1111-1111-1111-111111111111",
		ReceivedAt:    "2026-08-02T00:00:00Z",
		Payload: map[string]interface{}{
			"source":      "crowdstrike",
			"external_id": "THREAT-9",
			"title":       "Malware Blocked",
			"severity":    "high",
			"src_ip":      "10.0.0.4",
			"hostname":    "ws-9",
			"created_at":  "2026-08-01T23:00:00Z",
			"raw_event":   map[string]interface{}{"id": "THREAT-9"},
		},
	}
	ev, err := n.Normalize(raw)
	if err != nil {
		t.Fatalf("Normalize error: %v", err)
	}
	ocsf := ev.OcsfEvent
	if ocsf["class_uid"] != 2001 {
		t.Errorf("class_uid = %v, want 2001 (Security Finding, not generic 4001)", ocsf["class_uid"])
	}
	if ocsf["severity_id"] != 4 {
		t.Errorf("severity_id = %v, want 4 (high preserved)", ocsf["severity_id"])
	}
	if ocsf["message"] != "Malware Blocked" {
		t.Errorf("message = %v, want the canonical title", ocsf["message"])
	}
	// The envelope ID must be the replay-stable event_id, not a random UUID.
	if ev.ID != ocsf["event_id"] {
		t.Errorf("envelope ID %q != ocsf event_id %q (should be the deterministic id)", ev.ID, ocsf["event_id"])
	}
	if ev.ID != generateEventID(raw) {
		t.Errorf("envelope ID is not the deterministic generateEventID value")
	}
}

// Identity-provider canonical envelopes map to Authentication (3002).
func TestCanonicalEnvelopeIdpMapsToAuthentication(t *testing.T) {
	n := newTestNormalizer()
	ev, err := n.Normalize(&RawEvent{
		ConnectorID: "c2", ConnectorType: "okta", TenantID: "t-okta-uuid-1111-1111-111111111111",
		Payload: map[string]interface{}{
			"source": "okta", "external_id": "EVT-1", "title": "Suspicious sign-in",
			"severity": "medium", "raw_event": map[string]interface{}{},
		},
	})
	if err != nil {
		t.Fatalf("Normalize error: %v", err)
	}
	if ev.OcsfEvent["class_uid"] != 3002 {
		t.Errorf("okta canonical class_uid = %v, want 3002 (Authentication)", ev.OcsfEvent["class_uid"])
	}
}

// A connector with no declared profile must not be attributed to Splunk, and
// must still produce a promotable event.
//
// The lenient fallback used to borrow the splunk_enterprise profile. That was
// wrong twice over. Attribution: the promoter derives alert.source from
// metadata.product, so every profile-less connector's alerts read as Splunk —
// and only eight profiles are declared, so that was most of the catalogue.
// Promotion: splunk_enterprise is classUID 4001 (Network Activity) with an
// EMPTY severityMap, and should_promote() needs OCSF category 2 or
// severity_id >= 4. Category 4 with severity 0 satisfies neither, so those
// events were archived to the lake and could never become alerts.
func TestUnknownConnectorFallbackIsVendorNeutralAndPromotable(t *testing.T) {
	n := newLenientNormalizer()
	raw := &RawEvent{
		ConnectorID:   "c-unknown",
		ConnectorType: "acme_xdr", // deliberately absent from connectorProfiles
		TenantID:      "11111111-1111-1111-1111-111111111111",
		ReceivedAt:    "2026-09-22T00:00:00Z",
		Payload: map[string]interface{}{
			// No "raw_event", so this is NOT a canonical envelope and the
			// profile lookup + fallback path is what runs.
			"title":    "Suspicious binary executed",
			"severity": "high",
			"hostname": "ws-42",
		},
	}
	ev, err := n.Normalize(raw)
	if err != nil {
		t.Fatalf("Normalize error: %v", err)
	}
	ocsf := ev.OcsfEvent

	meta, ok := ocsf["metadata"].(map[string]interface{})
	if !ok {
		t.Fatalf("metadata missing from normalized event")
	}
	product, ok := meta["product"].(OcsfProduct)
	if !ok {
		t.Fatalf("metadata.product has unexpected type %T", meta["product"])
	}
	if product.VendorName == "Splunk" || product.Name == "Splunk Enterprise" {
		t.Errorf("profile-less connector attributed to Splunk: %+v", product)
	}
	if product.VendorName != "acme_xdr" {
		t.Errorf("VendorName = %q, want the connector type", product.VendorName)
	}

	// Category 2 (Findings) is what makes this promotable at all.
	if ocsf["class_uid"] != 2001 {
		t.Errorf("class_uid = %v, want 2001 so the promoter accepts it", ocsf["class_uid"])
	}
	if ocsf["category_uid"] != 2 {
		t.Errorf("category_uid = %v, want 2", ocsf["category_uid"])
	}
	// And the severity ladder must actually map, rather than yielding 0.
	if ocsf["severity_id"] != 4 {
		t.Errorf("severity_id = %v, want 4 — an empty severity map was the second half of the bug", ocsf["severity_id"])
	}
}

// The routine/finding split for AI telemetry is the whole design of the
// AI-estate capability, so it gets a test rather than a comment.
//
// Routine AI activity must land in category 6 so `should_promote()` leaves it
// in the lake — otherwise a chatty agent floods the alert queue with its own
// normal operation. A guardrail finding must land in category 2 so the
// promoter always promotes it regardless of severity — otherwise a detected
// prompt injection sits silently in the lake.
func TestAiRuntimeActivityIsNotAFinding(t *testing.T) {
	n := newTestNormalizer()
	ev, err := n.Normalize(&RawEvent{
		ConnectorID:   "ai-1",
		ConnectorType: "ai_runtime",
		TenantID:      "11111111-1111-1111-1111-111111111111",
		ReceivedAt:    "2026-09-22T00:00:00Z",
		Payload: map[string]interface{}{
			"agent_id":  "agent-support-bot",
			"tool_name": "search_tickets",
			"severity":  "info",
			"timestamp": "2026-09-22T00:00:00Z",
		},
	})
	if err != nil {
		t.Fatalf("Normalize error: %v", err)
	}
	ocsf := ev.OcsfEvent
	if ocsf["class_uid"] != 6003 {
		t.Errorf("class_uid = %v, want 6003 (API Activity)", ocsf["class_uid"])
	}
	if ocsf["category_uid"] != 6 {
		t.Errorf("category_uid = %v, want 6 so routine activity is not auto-promoted", ocsf["category_uid"])
	}
	if ocsf["severity_id"] != 1 {
		t.Errorf("severity_id = %v, want 1 — an info tool call must not reach the promoter's floor", ocsf["severity_id"])
	}
	if ocsf["activity_name"] != "search_tickets" {
		t.Errorf("activity_name = %v, want the tool name", ocsf["activity_name"])
	}
}

func TestAiGuardrailFindingIsAlwaysPromotable(t *testing.T) {
	n := newTestNormalizer()
	ev, err := n.Normalize(&RawEvent{
		ConnectorID:   "ai-2",
		ConnectorType: "ai_guardrail",
		TenantID:      "11111111-1111-1111-1111-111111111111",
		ReceivedAt:    "2026-09-22T00:00:00Z",
		Payload: map[string]interface{}{
			"finding_id":   "gr-1",
			"finding_type": "prompt_injection",
			"title":        "Instruction override detected in retrieved document",
			"agent_id":     "agent-support-bot",
			// Deliberately low severity: category 2 must promote anyway,
			// because a guardrail has already judged this worth reporting.
			"severity":  "low",
			"timestamp": "2026-09-22T00:00:00Z",
		},
	})
	if err != nil {
		t.Fatalf("Normalize error: %v", err)
	}
	ocsf := ev.OcsfEvent
	if ocsf["class_uid"] != 2001 {
		t.Errorf("class_uid = %v, want 2001 (Security Finding)", ocsf["class_uid"])
	}
	if ocsf["category_uid"] != 2 {
		t.Errorf("category_uid = %v, want 2 so the promoter always promotes it", ocsf["category_uid"])
	}
	if ocsf["activity_name"] != "prompt_injection" {
		t.Errorf("activity_name = %v, want the finding type detections match on", ocsf["activity_name"])
	}
}
