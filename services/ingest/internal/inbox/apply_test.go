package inbox

import (
	"strings"
	"testing"
	"time"
)

// Apply is the workhorse of the universal-capture path: every webhook
// hits it. These tests cover the rules the documentation promises:
//
//   * Field map projects vendor JSON onto OCSF dot-paths, including
//     nested ones, without losing other fields.
//   * Severity translation is case-insensitive and unknown vendor
//     severities surface as severity_id=0 rather than dropping the event.
//   * The receivedAt fallback fires when the configured time field is
//     missing or unparseable — we never lose an event because of a
//     timestamp typo.
//   * Constants always win — they're the operator's "force this value
//     onto every event" knob.
//   * Metadata carries tenant_uid + vendor/product so downstream
//     correlation can identify the event source without reparsing.

func newTestTemplate() *Template {
	return &Template{
		ID:          "pagerduty",
		VendorName:  "PagerDuty",
		ProductName: "Events API v2",
		ClassUID:    2001,
		ClassName:   "Security Finding",
		ActivityID:  1,
		FieldMap: map[string]string{
			"event.id":              "metadata.event_id",
			"event.title":           "finding.title",
			"event.urgency":         "severity_label_raw",
			"event.service.summary": "finding.product_name_raw",
			"event.html_url":        "finding.url",
		},
		SeverityField: "event.urgency",
		SeverityMap: map[string]int{
			"low":      2,
			"medium":   3,
			"high":     4,
			"critical": 5,
		},
		TimeField:    "event.occurred_at",
		MessageField: "event.title",
		Constants: map[string]any{
			"source": "pagerduty.events.v2",
		},
	}
}

func TestApply_BasicMapping(t *testing.T) {
	tmpl := newTestTemplate()
	payload := map[string]any{
		"event": map[string]any{
			"id":          "INC-12345",
			"title":       "prod-db-1: high CPU",
			"urgency":     "high",
			"occurred_at": "2026-05-08T12:30:00Z",
			"service":     map[string]any{"summary": "production-db"},
			"html_url":    "https://acme.pagerduty.com/incidents/INC-12345",
		},
	}

	receivedAt := "2026-05-08T12:30:01Z"
	out := tmpl.Apply(payload, "11111111-1111-1111-1111-111111111111", "inbox:abc", receivedAt)

	// Class metadata.
	if got := out["class_uid"]; got != 2001 {
		t.Fatalf("class_uid = %v, want 2001", got)
	}
	if got := out["class_name"]; got != "Security Finding" {
		t.Fatalf("class_name = %v, want %q", got, "Security Finding")
	}
	if got := out["category_uid"]; got != 2 {
		t.Fatalf("category_uid = %v, want 2 (=class_uid/1000)", got)
	}
	if got := out["activity_id"]; got != 1 {
		t.Fatalf("activity_id = %v, want 1", got)
	}

	// Field map landed nested values.
	meta, ok := out["metadata"].(map[string]any)
	if !ok {
		t.Fatalf("metadata is not a map: %T", out["metadata"])
	}
	if meta["event_id"] != "INC-12345" {
		t.Errorf("metadata.event_id = %v, want INC-12345", meta["event_id"])
	}
	finding, ok := out["finding"].(map[string]any)
	if !ok {
		t.Fatalf("finding is not a map: %T", out["finding"])
	}
	if finding["title"] != "prod-db-1: high CPU" {
		t.Errorf("finding.title = %v", finding["title"])
	}
	if finding["product_name_raw"] != "production-db" {
		t.Errorf("finding.product_name_raw = %v", finding["product_name_raw"])
	}
	if finding["url"] != "https://acme.pagerduty.com/incidents/INC-12345" {
		t.Errorf("finding.url = %v", finding["url"])
	}

	// Severity translation.
	if out["severity_id"] != 4 {
		t.Errorf("severity_id = %v, want 4 (high)", out["severity_id"])
	}
	if out["severity"] != "High" {
		t.Errorf("severity = %v, want High", out["severity"])
	}

	// Time normalised to RFC3339Nano.
	tStr, _ := out["time"].(string)
	if tStr == "" {
		t.Fatalf("time missing")
	}
	if _, err := time.Parse(time.RFC3339Nano, tStr); err != nil {
		t.Errorf("time = %q, want RFC3339Nano: %v", tStr, err)
	}

	// Constants stamped.
	if out["source"] != "pagerduty.events.v2" {
		t.Errorf("source = %v, want pagerduty.events.v2", out["source"])
	}

	// Tenant uid carried both at top level and in metadata.
	if out["tenant_uid"] != "11111111-1111-1111-1111-111111111111" {
		t.Errorf("tenant_uid = %v", out["tenant_uid"])
	}
	if meta["tenant_uid"] != "11111111-1111-1111-1111-111111111111" {
		t.Errorf("metadata.tenant_uid = %v", meta["tenant_uid"])
	}

	// Source connector ref propagated for queryability.
	if out["source_connector_id"] != "inbox:abc" {
		t.Errorf("source_connector_id = %v", out["source_connector_id"])
	}

	// Message defaulted to the configured field.
	if out["message"] != "prod-db-1: high CPU" {
		t.Errorf("message = %v", out["message"])
	}
}

func TestApply_UnknownSeverityFallsThroughAsZero(t *testing.T) {
	// Vendor sends a severity word we don't have in SeverityMap. We must
	// surface severity_id=0 ("Unknown") and keep the raw string in
	// severity rather than drop the event — over-deliver, never lose.
	tmpl := newTestTemplate()
	payload := map[string]any{
		"event": map[string]any{
			"urgency": "moderate", // not in map
		},
	}
	out := tmpl.Apply(payload, "tenant", "ref", "2026-05-08T12:30:00Z")

	if out["severity_id"] != 0 {
		t.Errorf("unknown severity should map to 0, got %v", out["severity_id"])
	}
	if out["severity"] != "moderate" {
		t.Errorf("severity should preserve raw, got %v", out["severity"])
	}
}

func TestApply_SeverityCaseInsensitive(t *testing.T) {
	tmpl := newTestTemplate()
	payload := map[string]any{
		"event": map[string]any{"urgency": "  HIGH  "}, // mixed case + whitespace
	}
	out := tmpl.Apply(payload, "tenant", "ref", "2026-05-08T12:30:00Z")
	if out["severity_id"] != 4 {
		t.Errorf("severity_id = %v, want 4 (high case-insensitive)", out["severity_id"])
	}
}

func TestApply_MissingSeverityYieldsUnknown(t *testing.T) {
	tmpl := newTestTemplate()
	payload := map[string]any{
		"event": map[string]any{}, // no urgency at all
	}
	out := tmpl.Apply(payload, "tenant", "ref", "2026-05-08T12:30:00Z")
	if out["severity_id"] != 0 {
		t.Errorf("missing severity should map to 0, got %v", out["severity_id"])
	}
	if out["severity"] != "Unknown" {
		t.Errorf("missing severity should be 'Unknown', got %v", out["severity"])
	}
}

func TestApply_TimeFallsBackToReceivedAt(t *testing.T) {
	tmpl := newTestTemplate()
	payload := map[string]any{
		"event": map[string]any{
			"occurred_at": "not-a-real-timestamp",
		},
	}
	receivedAt := "2026-05-08T12:30:01Z"
	out := tmpl.Apply(payload, "tenant", "ref", receivedAt)
	if out["time"] != receivedAt {
		t.Errorf("time = %v, want fallback %v", out["time"], receivedAt)
	}
}

func TestApply_TimeDefaultsToReceivedAtWhenMissing(t *testing.T) {
	tmpl := newTestTemplate()
	out := tmpl.Apply(map[string]any{}, "tenant", "ref", "2026-05-08T12:30:01Z")
	if out["time"] != "2026-05-08T12:30:01Z" {
		t.Errorf("time = %v, want fallback receivedAt", out["time"])
	}
}

func TestApply_ConstantsWinOverFieldMap(t *testing.T) {
	// If a field-map and a constant target the same path, the constant
	// must win — that's the operator's "force this value" guarantee.
	tmpl := &Template{
		ID:        "test",
		ClassUID:  2001,
		ClassName: "Security Finding",
		FieldMap: map[string]string{
			"vendor_label": "source",
		},
		Constants: map[string]any{
			"source": "constant-wins",
		},
	}
	payload := map[string]any{
		"vendor_label": "field-map-loses",
	}
	out := tmpl.Apply(payload, "tenant", "ref", "2026-05-08T12:30:00Z")
	if out["source"] != "constant-wins" {
		t.Errorf("constant should override field map, got %v", out["source"])
	}
}

func TestApply_DefaultsToActivityID1(t *testing.T) {
	// ActivityID==0 in the template means "use the OCSF default of 1
	// (Create)" rather than "stamp 0 onto every event".
	tmpl := &Template{
		ID:        "test",
		ClassUID:  4001,
		ClassName: "Network Activity",
	}
	out := tmpl.Apply(map[string]any{}, "tenant", "ref", "2026-05-08T12:30:00Z")
	if out["activity_id"] != 1 {
		t.Errorf("activity_id = %v, want 1 (default)", out["activity_id"])
	}
}

func TestApply_MetadataAlwaysCarriesProductIdentity(t *testing.T) {
	tmpl := newTestTemplate()
	out := tmpl.Apply(map[string]any{}, "tenant", "ref", "2026-05-08T12:30:00Z")
	meta := out["metadata"].(map[string]any)
	prod, ok := meta["product"].(map[string]any)
	if !ok {
		t.Fatalf("metadata.product not a map: %T", meta["product"])
	}
	if prod["vendor_name"] != "PagerDuty" {
		t.Errorf("vendor_name = %v", prod["vendor_name"])
	}
	if prod["name"] != "Events API v2" {
		t.Errorf("product.name = %v", prod["name"])
	}
	if meta["version"] != "1.1.0" {
		t.Errorf("metadata.version = %v, want 1.1.0", meta["version"])
	}
}

// ---------------------------------------------------------------------------
// Helper coverage. These are tiny but they're load-bearing for the field map
// language so we exercise them directly.
// ---------------------------------------------------------------------------

func TestGetNested_ReturnsLeafThroughNestedMaps(t *testing.T) {
	m := map[string]any{
		"a": map[string]any{"b": map[string]any{"c": "deep"}},
	}
	if v := getNested(m, "a.b.c"); v != "deep" {
		t.Errorf("getNested deep path = %v, want 'deep'", v)
	}
}

func TestGetNested_ReturnsNilForMissing(t *testing.T) {
	m := map[string]any{"a": map[string]any{}}
	if v := getNested(m, "a.b.c"); v != nil {
		t.Errorf("missing path should be nil, got %v", v)
	}
}

func TestGetNested_ReturnsNilWhenSegmentNotMap(t *testing.T) {
	// Walking through a non-map segment (e.g. a string) should fail safe.
	m := map[string]any{"a": "string-not-map"}
	if v := getNested(m, "a.b"); v != nil {
		t.Errorf("non-map segment should bail out, got %v", v)
	}
}

func TestSetNested_CreatesIntermediateMaps(t *testing.T) {
	m := map[string]any{}
	setNested(m, "a.b.c", "leaf")
	a, _ := m["a"].(map[string]any)
	b, _ := a["b"].(map[string]any)
	if b["c"] != "leaf" {
		t.Errorf("setNested didn't create intermediate maps: %#v", m)
	}
}

func TestSetNested_OverwritesPrimitiveOnConflict(t *testing.T) {
	// If an existing leaf is in the way of a deeper write we replace it
	// rather than panic — last-write-wins is the documented contract.
	m := map[string]any{"a": "old"}
	setNested(m, "a.b", "new")
	a, _ := m["a"].(map[string]any)
	if a == nil {
		t.Fatalf("expected map at 'a', got %T", m["a"])
	}
	if a["b"] != "new" {
		t.Errorf("setNested didn't write through, got %#v", m)
	}
}

func TestNormaliseTime_AcceptsCommonFormats(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"2026-05-08T12:30:00Z", true},
		{"2026-05-08T12:30:00.123Z", true},
		{"2026-05-08 12:30:00", true},
		{"05/08/2026 12:30:00", true},
		{"definitely-not-a-time", false},
	}
	const fallback = "FALLBACK"
	for _, c := range cases {
		got := normaliseTime(c.in, fallback)
		gotIsFallback := got == fallback
		if c.want == gotIsFallback {
			// want=true means "should parse, not fallback"
			t.Errorf("normaliseTime(%q) = %q, want parsable=%v", c.in, got, c.want)
		}
		if c.want && !strings.Contains(got, "2026-05-08") {
			t.Errorf("normaliseTime(%q) lost the date: got %q", c.in, got)
		}
	}
}

func TestCanonicalSeverity_CoversAllOCSFLevels(t *testing.T) {
	want := map[int]string{
		1: "Informational",
		2: "Low",
		3: "Medium",
		4: "High",
		5: "Critical",
		6: "Fatal",
		0: "Unknown",
		// Anything outside the table also returns Unknown — defensive.
		99: "Unknown",
	}
	for id, w := range want {
		if got := canonicalSeverity(id); got != w {
			t.Errorf("canonicalSeverity(%d) = %q, want %q", id, got, w)
		}
	}
}
