package normalizer

import (
	"testing"

	"github.com/beenuar/aisoc/services/ingest/internal/config"
)

func newTestNormalizer() *Normalizer {
	return &Normalizer{cfg: &config.Config{NormalizerMode: "strict"}, version: "test"}
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
