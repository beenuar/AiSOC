package normalizer

import "testing"

// Issue #1718, reported by gdncomm-dika-wibowo against ten alerts from one
// Entra tenant: every one named the Microsoft service that performed the
// change rather than the object that changed.
//
// The connector half of the fix lifts the target out of `targetResources`.
// This is the middle layer, and without it the fix stops here: the fusion
// promoter builds an alert's `username` from OCSF `actor.user.name` and its
// `hostname` from `device.name`, so a target sitting in the envelope under
// any other name reaches no column, no entity and no correlation key.
//
// The payloads are the connector envelopes
// `services/connectors/tests/connectors/test_entra_target_fields_issue_1718.py`
// asserts `AzureEntraConnector.normalize()` produces, trimmed to the keys
// this layer reads. The OCSF these assertions pin is in turn what
// `services/fusion/tests/test_entra_target_entities_issue_1718.py` feeds to
// the real promoter and alert sink.

func entraGroupAddEnvelope() map[string]interface{} {
	return map[string]interface{}{
		"source":         "azure_entra",
		"external_id":    "Directory_1a2b3c4d-0000-4000-8000-000000000001",
		"title":          "Add member to group",
		"severity":       "info",
		"activity":       "Add member to group",
		"actor":          "user-c@example.com",
		"actor_email":    "user-c@example.com",
		"initiator_type": "user",
		"target_type":    "User",
		"target_user":    "user-b@example.com",
		"target_name":    "User B",
		"created_at":     "2026-11-03T09:12:44.1234567Z",
		"raw_event":      map[string]interface{}{"id": "Directory_1a2b3c4d-0000-4000-8000-000000000001"},
	}
}

func entraDeviceUpdateEnvelope() map[string]interface{} {
	return map[string]interface{}{
		"source":          "azure_entra",
		"external_id":     "Directory_1a2b3c4d-0000-4000-8000-000000000003",
		"title":           "Update device",
		"severity":        "info",
		"activity":        "Update device",
		"actor":           "Intune Compliance Client Prod",
		"actor_app":       "Intune Compliance Client Prod",
		"initiator_type":  "app",
		"target_type":     "Device",
		"target_name":     "HOST-01",
		"target_hostname": "HOST-01",
		"created_at":      "2026-11-03T09:20:01.0000000Z",
		"raw_event":       map[string]interface{}{"id": "Directory_1a2b3c4d-0000-4000-8000-000000000003"},
	}
}

func entraEvent(payload map[string]interface{}) *RawEvent {
	return &RawEvent{
		ConnectorID:   "conn-entra",
		ConnectorType: "azure_entra",
		TenantID:      "11111111-1111-1111-1111-111111111111",
		ReceivedAt:    "2026-11-03T09:30:00Z",
		Payload:       payload,
	}
}

func TestEntraTargetUserReachesOCSFTargetUser(t *testing.T) {
	ocsf := normalizeOrFail(t, newTestNormalizer(), entraEvent(entraGroupAddEnvelope()))

	targetUser, ok := ocsf["target_user"].(map[string]interface{})
	if !ok {
		t.Fatalf("no target_user object on the OCSF event; keys: %v", keysOf(ocsf))
	}
	if got := targetUser["name"]; got != "user-b@example.com" {
		t.Errorf("target_user.name = %v, want user-b@example.com", got)
	}

	// The actor is still the actor. Fixing the target must not move it.
	actor, ok := ocsf["actor"].(map[string]interface{})
	if !ok {
		t.Fatalf("no actor object on the OCSF event")
	}
	user, ok := actor["user"].(map[string]interface{})
	if !ok {
		t.Fatalf("no actor.user object on the OCSF event")
	}
	if got := user["name"]; got != "user-c@example.com" {
		t.Errorf("actor.user.name = %v, want user-c@example.com", got)
	}
}

func TestEntraDeviceTargetReachesOCSFDeviceName(t *testing.T) {
	ocsf := normalizeOrFail(t, newTestNormalizer(), entraEvent(entraDeviceUpdateEnvelope()))

	device, ok := ocsf["device"].(map[string]interface{})
	if !ok {
		t.Fatalf("no device object on the OCSF event; keys: %v", keysOf(ocsf))
	}
	if got := device["name"]; got != "HOST-01" {
		t.Errorf("device.name = %v, want HOST-01", got)
	}
}

// A connector that names its own hostname keeps it. `target_hostname` is the
// last source consulted, so adding it cannot displace a device a connector
// already identified — which is what makes it safe to read for every
// canonical envelope rather than for Entra alone.
func TestConnectorHostnameWinsOverTargetHostname(t *testing.T) {
	payload := entraDeviceUpdateEnvelope()
	payload["hostname"] = "ACTOR-WORKSTATION"

	ocsf := normalizeOrFail(t, newTestNormalizer(), entraEvent(payload))

	device, _ := ocsf["device"].(map[string]interface{})
	if got := device["name"]; got != "ACTOR-WORKSTATION" {
		t.Errorf("device.name = %v, want the connector's own hostname ACTOR-WORKSTATION", got)
	}
}

// A user target must not be read as a device. `target_name` is the display
// name of whatever the target is, so mapping it onto `device.name` would put
// a person's name in the host column of every user-management event.
func TestUserTargetDoesNotBecomeADevice(t *testing.T) {
	ocsf := normalizeOrFail(t, newTestNormalizer(), entraEvent(entraGroupAddEnvelope()))

	if device, ok := ocsf["device"].(map[string]interface{}); ok {
		if name, present := device["name"]; present {
			t.Errorf("device.name = %v on a user-target event; want no device at all", name)
		}
	}
}

func keysOf(m map[string]interface{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
