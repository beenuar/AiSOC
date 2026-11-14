package normalizer

import "testing"

// GHSA-9q6p-m345-h3hj. `services/honeytokens` pushes a trip down the ingest
// spine so that it becomes an alert through the path every other signal
// takes. That only works if this package carries a profile for it.
//
// Without one the event falls to the lenient fallback, which files it as
// category 4 Network Activity with an empty severity map, and
// `should_promote()` requires category 2 or severity_id >= 4. The trip would
// be archived to the lake and silently never reach the queue — the same
// invisible outcome the advisory is about, one layer down, and nothing would
// have failed. This test is what makes removing the profile loud.
func TestHoneytokenTripIsAlwaysPromotable(t *testing.T) {
	n := newTestNormalizer()
	ev, err := n.Normalize(&RawEvent{
		ConnectorID:   "00000000-0000-0000-0000-000000686f6e",
		ConnectorType: "honeytoken",
		TenantID:      "11111111-1111-1111-1111-111111111111",
		ReceivedAt:    "2026-11-05T00:00:00Z",
		Payload: map[string]interface{}{
			"event":         "honeytoken.triggered",
			"honeytoken_id": "7f1a0f1e-0000-4000-8000-000000000001",
			"tenant_id":     "11111111-1111-1111-1111-111111111111",
			"token_type":    "aws_key",
			"token_name":    "decoy-prod-deploy-key",
			"trigger_id":    "7f1a0f1e-0000-4000-8000-000000000002",
			"source_ip":     "203.0.113.17",
			"triggered_at":  "2026-11-05T00:00:00Z",
		},
	})
	if err != nil {
		t.Fatalf("Normalize error: %v", err)
	}

	ocsf := ev.OcsfEvent
	if ocsf["class_uid"] != 2001 {
		t.Errorf("class_uid = %v, want 2001 (Security Finding)", ocsf["class_uid"])
	}
	// The assertion that matters: category 2 is what makes the promoter
	// create an alert unconditionally. A honeytoken has no benign reading,
	// so it must never depend on a severity the payload happens to carry.
	if ocsf["category_uid"] != 2 {
		t.Errorf("category_uid = %v, want 2 so the promoter always promotes a trip", ocsf["category_uid"])
	}
	if got := nested(t, ocsf, "src_endpoint.ip"); got != "203.0.113.17" {
		t.Errorf("src_endpoint.ip = %v, want the address that touched the token", got)
	}
	if got := nested(t, ocsf, "finding.title"); got != "decoy-prod-deploy-key" {
		t.Errorf("finding.title = %v, want the token name an analyst recognises", got)
	}
	if got := nested(t, ocsf, "finding.uid"); got != "7f1a0f1e-0000-4000-8000-000000000002" {
		t.Errorf("finding.uid = %v, want the trigger id the receiver deduplicates on", got)
	}
	if ocsf["activity_name"] != "aws_key" {
		t.Errorf("activity_name = %v, want the token type", ocsf["activity_name"])
	}
}

// The vendor label must not read as a third party. `aisoc_sample` and the
// AI-estate profiles already set VendorName to AiSOC for signals this
// platform produces itself, and `alert.source` is computed from this.
func TestHoneytokenTripIsAttributedToThisPlatform(t *testing.T) {
	n := newTestNormalizer()
	ev, err := n.Normalize(&RawEvent{
		ConnectorID:   "00000000-0000-0000-0000-000000686f6e",
		ConnectorType: "honeytoken",
		TenantID:      "11111111-1111-1111-1111-111111111111",
		ReceivedAt:    "2026-11-05T00:00:00Z",
		Payload:       map[string]interface{}{"token_name": "decoy", "trigger_id": "t-1"},
	})
	if err != nil {
		t.Fatalf("Normalize error: %v", err)
	}
	// `metadata.product` is an OcsfProduct struct rather than a nested map,
	// so getNestedField cannot walk into it and reading it that way returns
	// nil — which would make this assertion pass for the wrong reason if it
	// compared against nil instead of a name.
	meta, ok := ev.OcsfEvent["metadata"].(map[string]interface{})
	if !ok {
		t.Fatalf("metadata is %T, want a map", ev.OcsfEvent["metadata"])
	}
	product, ok := meta["product"].(OcsfProduct)
	if !ok {
		t.Fatalf("metadata.product is %T, want OcsfProduct", meta["product"])
	}
	if product.VendorName != "AiSOC" {
		t.Errorf("vendor_name = %q, want AiSOC", product.VendorName)
	}
	if product.Name != "Honeytokens" {
		t.Errorf("product name = %q, want Honeytokens", product.Name)
	}
}
