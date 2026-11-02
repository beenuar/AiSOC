package normalizer

import "testing"

// Depth plan wave 2, item 8.2.
//
// A connector with no `connectorProfiles` entry hits the lenient fallback,
// which files events at `class_uid: 4001` (Network Activity) with the shared
// severity map. `should_promote()` in services/fusion requires OCSF category
// 2 or `severity_id >= 4`, so an ExtraHop detection scored `medium` would be
// archived to the lake and silently never become an alert. The symptom is a
// connector that polls successfully, reports healthy, and produces an empty
// queue.
//
// An NDR detection has already passed the vendor's own correlation, which is
// what class 2001 (Security Finding, category 2) means and why it promotes
// unconditionally. That is the same reasoning the `splunk` profile records
// for a notable, one comment block above.
func TestExtraHopHasASecurityFindingProfile(t *testing.T) {
	profile, ok := connectorProfiles["extrahop"]
	if !ok {
		t.Fatal("extrahop has no connectorProfiles entry; its detections would fall to the lenient 4001 fallback and never promote")
	}

	if profile.classUID != findingsCategory*1000+1 {
		t.Errorf("classUID = %d, want 2001: a vendor detection that passed the vendor's own correlation is a Security Finding", profile.classUID)
	}
	if profile.className != "Security Finding" {
		t.Errorf("className = %q, want %q", profile.className, "Security Finding")
	}
	if profile.product.VendorName != "ExtraHop" {
		t.Errorf("vendor = %q, want ExtraHop; a borrowed profile misattributes every event", profile.product.VendorName)
	}

	// The field map must read the connector's own canonical envelope keys,
	// not raw vendor field names. `fetch_alerts` normalises before publishing,
	// so a map keyed on `risk_score` or `participants` would read nothing.
	for _, key := range []string{"title", "external_id", "src_ip", "hostname"} {
		if _, ok := profile.fieldMap[key]; !ok {
			t.Errorf("fieldMap has no entry for the canonical key %q", key)
		}
	}
}

// ExtraHop publishes three risk bands and no fourth, so the profile's severity
// map has three entries plus the shared informational floor. A `critical`
// entry here would let a future connector change promote a detection to a tier
// the vendor never asserted.
func TestExtraHopSeverityMapMatchesThePublishedBands(t *testing.T) {
	profile, ok := connectorProfiles["extrahop"]
	if !ok {
		t.Fatal("extrahop has no connectorProfiles entry")
	}

	for tier, want := range map[string]int{"high": 4, "medium": 3, "low": 2} {
		got, ok := profile.severityMap[tier]
		if !ok {
			t.Errorf("severityMap has no %q entry", tier)
			continue
		}
		if got != want {
			t.Errorf("severityMap[%q] = %d, want %d", tier, got, want)
		}
	}

	// Promotion does not depend on a critical tier: class 2001 is category 2
	// and promotes unconditionally. So the absence below costs nothing and
	// keeps the ladder honest.
	if _, ok := profile.severityMap["critical"]; ok {
		t.Error("severityMap declares `critical`, which ExtraHop does not publish; asserting a tier the vendor never set is the mirror of collapsing one it did")
	}
}

// The whole point of the profile, asserted end to end rather than by reading
// the map: an ExtraHop detection at the vendor's middle band must reach the
// promoter as category 2.
func TestAnExtraHopDetectionNormalizesToAPromotableCategory(t *testing.T) {
	n := newLenientNormalizer()
	out, err := n.Normalize(&RawEvent{
		ConnectorID:   "c-ndr",
		ConnectorType: "extrahop",
		TenantID:      "11111111-1111-1111-1111-111111111111",
		Payload: map[string]interface{}{
			"external_id": "4211",
			"title":       "Suspicious SMB Session Activity",
			"severity":    "medium",
			"src_ip":      "10.4.1.9",
			"hostname":    "FILE-01",
			"raw_event":   map[string]interface{}{"id": 4211, "risk_score": 55},
		},
	})
	if err != nil {
		t.Fatalf("Normalize: %v", err)
	}

	if got, _ := out.OcsfEvent["category_uid"].(int); got != findingsCategory {
		t.Fatalf("category_uid = %v, want %d; anything else is archived to the lake and never alerts", out.OcsfEvent["category_uid"], findingsCategory)
	}
	if got, _ := out.OcsfEvent["class_uid"].(int); got != 2001 {
		t.Errorf("class_uid = %v, want 2001", out.OcsfEvent["class_uid"])
	}
	if got, _ := out.OcsfEvent["severity_id"].(int); got != 3 {
		t.Errorf("severity_id = %v, want 3 for the vendor's middle band", out.OcsfEvent["severity_id"])
	}
}
