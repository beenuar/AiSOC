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

// getNestedField on the produced OCSF event, for assertions that need to
// reach actor.user.name / device.name without re-implementing the walk.
func nested(t *testing.T, ocsf map[string]interface{}, path string) interface{} {
	t.Helper()
	return getNestedField(ocsf, path)
}

func canonicalEvent(payload map[string]interface{}) *RawEvent {
	return &RawEvent{
		ConnectorID:   "conn-1",
		ConnectorType: "crowdstrike",
		TenantID:      "11111111-1111-1111-1111-111111111111",
		ReceivedAt:    "2026-09-23T00:00:00Z",
		Payload:       payload,
	}
}

// The canonical field map recognised only `actor`. Eleven of the 68
// canonical-envelope connectors spell it `username` or `user`, and their
// alerts reached fusion anonymous — which matters beyond a blank column,
// because the correlation key is {tenant}:{entity}:{tactic} and every one of
// those alerts collapsed into the same "unknown" bucket.
func TestCanonicalEnvelopeResolvesActorAliases(t *testing.T) {
	for _, tc := range []struct {
		field string
		value string
	}{
		{"actor", "alice"},
		{"username", "bob"},
		{"user", "carol"},
		{"user_name", "dave"},
	} {
		t.Run(tc.field, func(t *testing.T) {
			n := newLenientNormalizer()
			ev, err := n.Normalize(canonicalEvent(map[string]interface{}{
				"source":    "crowdstrike",
				"title":     "Detection",
				"severity":  "high",
				tc.field:    tc.value,
				"raw_event": map[string]interface{}{},
			}))
			if err != nil {
				t.Fatalf("Normalize returned error: %v", err)
			}
			if got := nested(t, ev.OcsfEvent, "actor.user.name"); got != tc.value {
				t.Errorf("actor.user.name = %v, want %q from field %q", got, tc.value, tc.field)
			}
		})
	}
}

// Precedence must be the declared order, not Go's randomised map iteration.
// Expressing the aliases as extra fieldMap entries would pick a different
// winner per process, which surfaces as flake rather than as a bug.
func TestCanonicalActorPrecedenceIsDeterministic(t *testing.T) {
	for i := 0; i < 50; i++ {
		n := newLenientNormalizer()
		ev, err := n.Normalize(canonicalEvent(map[string]interface{}{
			"source":    "crowdstrike",
			"title":     "Detection",
			"severity":  "high",
			"actor":     "primary",
			"username":  "secondary",
			"user":      "tertiary",
			"raw_event": map[string]interface{}{},
		}))
		if err != nil {
			t.Fatalf("Normalize returned error: %v", err)
		}
		if got := nested(t, ev.OcsfEvent, "actor.user.name"); got != "primary" {
			t.Fatalf("iteration %d: actor.user.name = %v, want the declared-first source", i, got)
		}
	}
}

func TestCanonicalEnvelopeResolvesHostAndIPAliases(t *testing.T) {
	n := newLenientNormalizer()
	ev, err := n.Normalize(canonicalEvent(map[string]interface{}{
		"source":    "crowdstrike",
		"title":     "Detection",
		"severity":  "high",
		"host":      "web-01",
		"client_ip": "203.0.113.7",
		"raw_event": map[string]interface{}{},
	}))
	if err != nil {
		t.Fatalf("Normalize returned error: %v", err)
	}
	if got := nested(t, ev.OcsfEvent, "device.name"); got != "web-01" {
		t.Errorf("device.name = %v, want web-01 resolved from `host`", got)
	}
	if got := nested(t, ev.OcsfEvent, "src_endpoint.ip"); got != "203.0.113.7" {
		t.Errorf("src_endpoint.ip = %v, want the value resolved from `client_ip`", got)
	}
}

// A hand-written vendor profile's own field mapping always wins. The aliases
// run over every profile now, so this pins the precedence rather than the
// absence: they may fill a destination the vendor map left empty, they may
// never overwrite one it filled.
func TestAliasesDoNotApplyToRawVendorProfiles(t *testing.T) {
	n := newTestNormalizer()
	ev, err := n.Normalize(&RawEvent{
		ConnectorID:   "conn-1",
		ConnectorType: "crowdstrike_falcon",
		TenantID:      "11111111-1111-1111-1111-111111111111",
		ReceivedAt:    "2026-09-23T00:00:00Z",
		Payload: map[string]interface{}{
			"UserName":     "falcon-user",
			"ComputerName": "falcon-host",
			// A stray `username` must not override the profile's own mapping.
			"username": "should-not-win",
		},
	})
	if err != nil {
		t.Fatalf("Normalize returned error: %v", err)
	}
	if got := nested(t, ev.OcsfEvent, "actor.user.name"); got != "falcon-user" {
		t.Errorf("actor.user.name = %v, want the vendor profile's own mapping", got)
	}
}

// The generic fallback must resolve identity, not just a title.
//
// This is the README's own push example: a flat payload, a connector type with
// no profile of its own. Before, the fallback's field map held `title` and
// `external_id` and nothing else, and the alias pass was gated behind the
// canonical-envelope branch — so the event became an alert with no host, no
// user and no IP. Entity extraction, the Investigation Rail's pivots, the
// {tenant}:{entity}:{tactic} correlation key, the entity graph and UEBA all
// read those three fields, so the alert arrived with nothing to pivot from.
// The alert appearing at all is what made it look like it had worked.
func TestGenericProfileResolvesIdentityFields(t *testing.T) {
	n := newLenientNormalizer()
	ev, err := n.Normalize(&RawEvent{
		ConnectorID:   "edr-1",
		ConnectorType: "acme_xdr", // deliberately absent from connectorProfiles
		TenantID:      "11111111-1111-1111-1111-111111111111",
		ReceivedAt:    "2026-09-23T00:00:00Z",
		Payload: map[string]interface{}{
			"severity": "high",
			"title":    "Encoded PowerShell from Office",
			"host":     "WIN-FIN-01",
			"user":     "alice",
			"src_ip":   "10.20.30.40",
		},
	})
	if err != nil {
		t.Fatalf("Normalize returned error: %v", err)
	}
	for _, tc := range []struct{ path, want string }{
		{"device.name", "WIN-FIN-01"},
		{"actor.user.name", "alice"},
		{"src_endpoint.ip", "10.20.30.40"},
	} {
		if got := nested(t, ev.OcsfEvent, tc.path); got != tc.want {
			t.Errorf("%s = %v, want %q — the generic fallback must resolve identity", tc.path, got, tc.want)
		}
	}
	// Still promotable and still vendor-neutral, which the fallback already got right.
	if ev.OcsfEvent["class_uid"] != 2001 {
		t.Errorf("class_uid = %v, want 2001", ev.OcsfEvent["class_uid"])
	}
	if ev.OcsfEvent["severity_id"] != 4 {
		t.Errorf("severity_id = %v, want 4", ev.OcsfEvent["severity_id"])
	}
}

// The connector identifier the product advertises must reach the profile that
// carries its vendor field map.
//
// services/connectors declares `crowdstrike`; this file keyed the profile
// `crowdstrike_falcon`. The README tells a new user to push the former, so the
// example fell through to the generic fallback and was attributed to nothing
// in particular. Both names resolve now, because the longer one is load-bearing
// elsewhere — the ConnectorType union, the CLI default, the graph extractor.
func TestDeclaredConnectorIdResolvesToVendorProfile(t *testing.T) {
	for _, tc := range []struct {
		connectorType string
		wantVendor    string
		wantClass     int
	}{
		{"crowdstrike", "CrowdStrike", 2001},
		{"crowdstrike_falcon", "CrowdStrike", 2001},
		{"okta", "Okta", 3002},
		{"okta_system_log", "Okta", 3002},
	} {
		t.Run(tc.connectorType, func(t *testing.T) {
			n := newLenientNormalizer()
			ev, err := n.Normalize(&RawEvent{
				ConnectorID:   "c-1",
				ConnectorType: tc.connectorType,
				TenantID:      "11111111-1111-1111-1111-111111111111",
				ReceivedAt:    "2026-09-23T00:00:00Z",
				// Flat, human-authored, lowercase severity — a pushed payload,
				// not a vendor row.
				Payload: map[string]interface{}{
					"severity": "high",
					"title":    "Encoded PowerShell from Office",
					"host":     "WIN-FIN-01",
					"user":     "alice",
					"src_ip":   "10.20.30.40",
				},
			})
			if err != nil {
				t.Fatalf("Normalize returned error: %v", err)
			}
			meta := ev.OcsfEvent["metadata"].(map[string]interface{})
			product := meta["product"].(OcsfProduct)
			if product.VendorName != tc.wantVendor {
				t.Errorf("VendorName = %q, want %q — the declared id must reach the vendor profile", product.VendorName, tc.wantVendor)
			}
			if ev.OcsfEvent["class_uid"] != tc.wantClass {
				t.Errorf("class_uid = %v, want %d", ev.OcsfEvent["class_uid"], tc.wantClass)
			}
			// Reaching a vendor profile must not cost the identity fields the
			// generic fallback would have resolved.
			if got := nested(t, ev.OcsfEvent, "device.name"); got != "WIN-FIN-01" {
				t.Errorf("device.name = %v, want WIN-FIN-01", got)
			}
			if got := nested(t, ev.OcsfEvent, "actor.user.name"); got != "alice" {
				t.Errorf("actor.user.name = %v, want alice", got)
			}
			if got := nested(t, ev.OcsfEvent, "src_endpoint.ip"); got != "10.20.30.40" {
				t.Errorf("src_endpoint.ip = %v, want 10.20.30.40", got)
			}
			// ...nor the severity. crowdstrike_falcon's ladder is capitalised
			// and a pushed payload is lowercase; without the shared-ladder
			// fallback this scores 0 and renders as Unknown.
			if ev.OcsfEvent["severity_id"] != 4 {
				t.Errorf("severity_id = %v, want 4 for %q", ev.OcsfEvent["severity_id"], "high")
			}
			// ...nor the caller's own title. A vendor profile maps its
			// vendor's field name, so `message` was left empty and the
			// promoter generated "Security Finding from <product>" over the
			// top of the title the caller sent.
			if got := nested(t, ev.OcsfEvent, "message"); got != "Encoded PowerShell from Office" {
				t.Errorf("message = %v, want the caller's own title", got)
			}
		})
	}
}

// critical is the fifth tier, not a louder high. A vendor-native critical that
// collapses into high silently downgrades the most urgent thing in the queue.
func TestCriticalSeverityDoesNotCollapseIntoHigh(t *testing.T) {
	for _, connectorType := range []string{"acme_xdr", "crowdstrike"} {
		t.Run(connectorType, func(t *testing.T) {
			n := newLenientNormalizer()
			ev, err := n.Normalize(&RawEvent{
				ConnectorID:   "c-1",
				ConnectorType: connectorType,
				TenantID:      "11111111-1111-1111-1111-111111111111",
				ReceivedAt:    "2026-09-23T00:00:00Z",
				Payload:       map[string]interface{}{"title": "t", "severity": "critical"},
			})
			if err != nil {
				t.Fatalf("Normalize returned error: %v", err)
			}
			if ev.OcsfEvent["severity_id"] != 5 {
				t.Errorf("severity_id = %v, want 5 (critical is its own tier)", ev.OcsfEvent["severity_id"])
			}
		})
	}
}

// An identity destination is a scalar the entity extractor turns into a chip
// and the correlator folds into its key. Several connectors pass the vendor's
// nested actor object through under the same key a scalar would use; writing
// that object into the slot yields an entity that renders as a map.
func TestIdentityAliasesSkipNonScalarsAndDigForTheName(t *testing.T) {
	n := newLenientNormalizer()
	ev, err := n.Normalize(&RawEvent{
		ConnectorID:   "c-1",
		ConnectorType: "acme_xdr",
		TenantID:      "11111111-1111-1111-1111-111111111111",
		ReceivedAt:    "2026-09-23T00:00:00Z",
		Payload: map[string]interface{}{
			"title": "t",
			// The vendor's object under the key a scalar would use.
			"actor":  map[string]interface{}{"id": "u-1", "name": "alice"},
			"device": map[string]interface{}{"name": "WIN-01"},
		},
	})
	if err != nil {
		t.Fatalf("Normalize returned error: %v", err)
	}
	got := nested(t, ev.OcsfEvent, "actor.user.name")
	if _, isStr := got.(string); !isStr {
		t.Fatalf("actor.user.name = %#v (%T), want a string — a map here is an unpivotable entity", got, got)
	}
	if got != "alice" {
		t.Errorf("actor.user.name = %v, want alice dug out of the nested actor", got)
	}
	if got := nested(t, ev.OcsfEvent, "device.name"); got != "WIN-01" {
		t.Errorf("device.name = %v, want WIN-01", got)
	}
}

// Go randomises map iteration, so alias precedence has to come from a slice.
// Resolving the same payload repeatedly must yield the same answer every time;
// a map-ordered implementation passes this roughly one run in two.
func TestIdentityAliasResolutionIsDeterministic(t *testing.T) {
	payload := func() map[string]interface{} {
		return map[string]interface{}{
			"title": "t",
			// Every alias source for actor.user.name carries a distinct value,
			// so any ordering instability shows up as a different winner.
			"actor": "by-actor", "username": "by-username",
			"user": "by-user", "user_name": "by-user-name",
			"hostname": "by-hostname", "host": "by-host", "device_name": "by-device-name",
			"src_ip": "1.1.1.1", "source_ip": "2.2.2.2", "client_ip": "3.3.3.3",
		}
	}
	const runs = 200
	for i := 0; i < runs; i++ {
		n := newLenientNormalizer()
		ev, err := n.Normalize(&RawEvent{
			ConnectorID: "c-1", ConnectorType: "acme_xdr",
			TenantID:   "11111111-1111-1111-1111-111111111111",
			ReceivedAt: "2026-09-23T00:00:00Z", Payload: payload(),
		})
		if err != nil {
			t.Fatalf("Normalize returned error: %v", err)
		}
		if got := nested(t, ev.OcsfEvent, "actor.user.name"); got != "by-actor" {
			t.Fatalf("run %d: actor.user.name = %v, want by-actor (first declared source)", i, got)
		}
		if got := nested(t, ev.OcsfEvent, "device.name"); got != "by-hostname" {
			t.Fatalf("run %d: device.name = %v, want by-hostname", i, got)
		}
		if got := nested(t, ev.OcsfEvent, "src_endpoint.ip"); got != "1.1.1.1" {
			t.Fatalf("run %d: src_endpoint.ip = %v, want 1.1.1.1", i, got)
		}
	}
}

// Every connectorTypeAliases entry must point at a profile that exists, and
// must not shadow a connector type that already has its own profile.
func TestConnectorTypeAliasesPointAtRealProfiles(t *testing.T) {
	for alias, target := range connectorTypeAliases {
		if _, ok := connectorProfiles[target]; !ok {
			t.Errorf("alias %q -> %q, but %q is not in connectorProfiles", alias, target, target)
		}
		if _, ok := connectorProfiles[alias]; ok {
			t.Errorf("alias %q shadows its own profile entry; the alias is dead code", alias)
		}
	}
}
