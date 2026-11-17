package normalizer

import "testing"

// This is the canonical envelope contract exercised by
// services/connectors/tests/test_wazuh_event_identity.py. The vendor event's
// external_id must survive normalisation as both finding.uid and the input to
// the replay-stable event UUID; the rule id identifies a detection, not an
// occurrence of it.
func wazuhOccurrence(documentID, timestamp, host string) *RawEvent {
	return &RawEvent{
		ConnectorID:   "wazuh-connector-one",
		ConnectorType: "wazuh",
		TenantID:      "11111111-1111-1111-1111-111111111111",
		ReceivedAt:    "2026-11-17T03:13:00Z",
		Payload: map[string]interface{}{
			"source":      "wazuh",
			"category":    "siem",
			"event_type":  "wazuh_alert",
			"title":       "Repeated authentication failures",
			"severity":    "high",
			"alert_id":    documentID,
			"external_id": documentID,
			"rule_id":     "110300",
			"hostname":    host,
			"timestamp":   timestamp,
			"raw_event": map[string]interface{}{
				"rule":       map[string]interface{}{"id": "110300"},
				"@timestamp": timestamp,
			},
		},
	}
}

func TestWazuhOccurrenceIdentitySurvivesNormalization(t *testing.T) {
	n := newTestNormalizer()
	first, err := n.Normalize(wazuhOccurrence("document-first", "2026-11-16T02:57:34.421Z", "test-host-002"))
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name       string
		documentID string
		timestamp  string
		host       string
	}{
		{"next day", "document-next-day", "2026-11-17T03:11:51.099Z", "test-host-002"},
		{"same timestamp", "document-same-time", "2026-11-16T02:57:34.421Z", "test-host-002"},
		{"different host", "document-other-host", "2026-11-16T02:57:34.421Z", "test-host-003"},
		{"composite fallback", "110300::002::2026-11-17T03:11:51.099Z", "2026-11-17T03:11:51.099Z", "test-host-002"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw := wazuhOccurrence(tc.documentID, tc.timestamp, tc.host)
			event, err := n.Normalize(raw)
			if err != nil {
				t.Fatal(err)
			}
			if event.ID == first.ID {
				t.Fatal("distinct hits of one Wazuh rule became the same source event")
			}
			if got := event.OcsfEvent["event_id"]; got != event.ID {
				t.Errorf("OCSF event_id = %v, want envelope id %q", got, event.ID)
			}
			finding, ok := event.OcsfEvent["finding"].(map[string]interface{})
			if !ok || finding["uid"] != tc.documentID {
				t.Errorf("finding.uid must identify the vendor event, got %v", finding)
			}
			if got := event.OcsfEvent["time"]; got != tc.timestamp {
				t.Errorf("event time = %v, want %s", got, tc.timestamp)
			}

			raw.ReceivedAt = "2026-11-18T03:13:00Z"
			replay, err := n.Normalize(raw)
			if err != nil {
				t.Fatal(err)
			}
			if replay.ID != event.ID {
				t.Error("replaying the same document changed its event identity")
			}
		})
	}
}

func TestWazuhEventIdentityRemainsScopedToTenantAndConnector(t *testing.T) {
	n := newTestNormalizer()
	raw := wazuhOccurrence("same-document-id", "2026-11-17T03:11:51.099Z", "test-host-002")
	first, err := n.Normalize(raw)
	if err != nil {
		t.Fatal(err)
	}

	otherTenant := *raw
	otherTenant.TenantID = "22222222-2222-2222-2222-222222222222"
	otherConnector := *raw
	otherConnector.ConnectorID = "wazuh-connector-two"
	for _, other := range []*RawEvent{&otherTenant, &otherConnector} {
		event, err := n.Normalize(other)
		if err != nil {
			t.Fatal(err)
		}
		if event.ID == first.ID {
			t.Error("the same vendor id collided across tenants or connector instances")
		}
	}
}
