package normalizer

import (
	"strings"
	"testing"

	"github.com/beenuar/aisoc/services/ingest/internal/config"
	"github.com/beenuar/aisoc/services/ingest/internal/eventcatalog"
)

// A normalizer with the real catalogue loaded, which is what New() builds.
// The other constructors in this package build a Normalizer directly and so
// carry no catalogue; that is deliberate and the nil path is asserted below.
func newClassifyingNormalizer(t *testing.T) *Normalizer {
	t.Helper()
	catalog, err := eventcatalog.Load()
	if err != nil {
		t.Fatalf("loading the catalogue: %v", err)
	}
	return &Normalizer{cfg: &config.Config{NormalizerMode: "lenient"}, version: "test", catalog: catalog}
}

func normalizeWithVendorRecord(t *testing.T, connector string, vendor map[string]interface{}) *NormalizedEvent {
	t.Helper()
	ev, err := newClassifyingNormalizer(t).Normalize(&RawEvent{
		ConnectorID:   "c-1",
		ConnectorType: connector,
		TenantID:      "11111111-1111-1111-1111-111111111111",
		ReceivedAt:    "2026-10-07T00:00:00Z",
		Payload: map[string]interface{}{
			"source":    connector,
			"raw_event": vendor,
			"severity":  "medium",
			"title":     "an event",
		},
	})
	if err != nil {
		t.Fatalf("Normalize(%q): %v", connector, err)
	}
	return ev
}

// The classification lands on the event, carrying the vendor's own event
// type beside the normalized answer so a lake row can be checked against the
// catalogue without the raw payload.
func TestAClassifiedEventCarriesItsClassification(t *testing.T) {
	ev := normalizeWithVendorRecord(t, "aws_cloudtrail", map[string]interface{}{"eventName": "DeleteTrail"})
	classification, ok := ev.OcsfEvent["event_classification"].(*eventClassification)
	if !ok {
		t.Fatalf("no classification on the event: %T", ev.OcsfEvent["event_classification"])
	}
	if classification.Source != "aws_cloudtrail" || classification.EventType != "DeleteTrail" {
		t.Errorf("classification = %+v", classification)
	}
	if classification.Sensitivity != "critical" {
		t.Errorf("sensitivity = %q, want critical", classification.Sensitivity)
	}
	if classification.Action != "delete.trail" {
		t.Errorf("action = %q", classification.Action)
	}
	if len(classification.ATTACK) == 0 {
		t.Error("no ATT&CK hint carried through")
	}
	for _, w := range ev.NormalizationWarnings {
		if strings.Contains(w, "event catalogue") {
			t.Errorf("a classified event carried a catalogue warning: %s", w)
		}
	}
}

// The three shapes the declared paths cover, driven through the normalizer
// rather than the loader, so the `raw_event` unwrapping is exercised too.
func TestClassificationReadsEachSourcesOwnEventTypeShape(t *testing.T) {
	cases := []struct {
		connector string
		vendor    map[string]interface{}
		want      string
	}{
		{"okta", map[string]interface{}{"eventType": "system.api_token.create"}, "system.api_token.create"},
		{
			"azure_activity",
			map[string]interface{}{"operationName": map[string]interface{}{"value": "Microsoft.Authorization/roleAssignments/write"}},
			"Microsoft.Authorization/roleAssignments/write",
		},
		{
			"google_workspace",
			map[string]interface{}{"events": []interface{}{map[string]interface{}{"name": "GRANT_ADMIN_PRIVILEGE"}}},
			"GRANT_ADMIN_PRIVILEGE",
		},
		{"kubernetes_audit", map[string]interface{}{"verb": "impersonate"}, "impersonate"},
		{"slack_audit", map[string]interface{}{"action": "organization_export_started"}, "organization_export_started"},
	}
	for _, tc := range cases {
		t.Run(tc.connector, func(t *testing.T) {
			ev := normalizeWithVendorRecord(t, tc.connector, tc.vendor)
			classification, ok := ev.OcsfEvent["event_classification"].(*eventClassification)
			if !ok {
				t.Fatalf("no classification for %q", tc.connector)
			}
			if classification.EventType != tc.want {
				t.Errorf("event_type = %q, want %q", classification.EventType, tc.want)
			}
		})
	}
}

// An event type a catalogued source has never seen is the one case worth
// telling an operator about: it is how the catalogue learns it has fallen
// behind the vendor. The warning rides on the event and names the file to
// edit.
func TestAnUnknownEventTypeWarnsOnTheEvent(t *testing.T) {
	ev := normalizeWithVendorRecord(t, "aws_cloudtrail", map[string]interface{}{"eventName": "SomeNewApiCallAwsShippedLastWeek"})
	if _, present := ev.OcsfEvent["event_classification"]; present {
		t.Error("an unknown event type produced a classification")
	}
	var warning string
	for _, w := range ev.NormalizationWarnings {
		if strings.Contains(w, "event catalogue") {
			warning = w
		}
	}
	if warning == "" {
		t.Fatal("an unknown event type produced no warning; nothing would ever grow the catalogue")
	}
	if !strings.Contains(warning, "SomeNewApiCallAwsShippedLastWeek") {
		t.Errorf("the warning does not name the event type: %s", warning)
	}
	if !strings.Contains(warning, "schemas/event_catalog/aws_cloudtrail.yaml") {
		t.Errorf("the warning does not name the file to edit: %s", warning)
	}
}

// A source with no catalogue at all must be silent. Warning on every event
// from the seventy-four connectors with no catalogue would make the
// warnings field unreadable and the one actionable case invisible in it.
func TestASourceWithNoCatalogueIsSilent(t *testing.T) {
	ev := normalizeWithVendorRecord(t, "zscaler", map[string]interface{}{"action": "Allow"})
	if _, present := ev.OcsfEvent["event_classification"]; present {
		t.Error("a source with no catalogue produced a classification")
	}
	for _, w := range ev.NormalizationWarnings {
		if strings.Contains(w, "event catalogue") {
			t.Errorf("a source with no catalogue warned: %s", w)
		}
	}
}

// A record from a catalogued source that carries nothing at the declared
// path is also silent: several connectors emit shapes with no event type at
// all, and warning on each would drown the actionable case.
func TestARecordWithNoEventTypeIsSilent(t *testing.T) {
	ev := normalizeWithVendorRecord(t, "aws_cloudtrail", map[string]interface{}{"somethingElse": "x"})
	for _, w := range ev.NormalizationWarnings {
		if strings.Contains(w, "event catalogue") {
			t.Errorf("a record with no event type warned: %s", w)
		}
	}
}

// The classification must not change what the event is or whether it
// promotes. A `critical` sensitivity that raised a severity would let a
// one-line edit to a data file flood an alert queue, and the promotion
// contract belongs with the OCSF class and the vendor's severity.
func TestTheClassificationChangesNeitherSeverityNorClass(t *testing.T) {
	critical := normalizeWithVendorRecord(t, "aws_cloudtrail", map[string]interface{}{"eventName": "DeleteTrail"})
	informational := normalizeWithVendorRecord(t, "aws_cloudtrail", map[string]interface{}{"eventName": "DescribeInstances"})

	for _, field := range []string{"severity_id", "severity", "class_uid", "category_uid"} {
		if critical.OcsfEvent[field] != informational.OcsfEvent[field] {
			t.Errorf("%s differs between a critical-sensitivity and an info-sensitivity event (%v vs %v); "+
				"the catalogue must not move promotion",
				field, critical.OcsfEvent[field], informational.OcsfEvent[field])
		}
	}
}

// New() loads the catalogue, which is what makes "ingest reads it at boot"
// true rather than a claim. A failure there is fatal, so this asserts the
// successful path reaches a normalizer that can classify.
func TestNewLoadsTheCatalogueAtBoot(t *testing.T) {
	n, err := New(&config.Config{NormalizerMode: "lenient"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if n.catalog == nil {
		t.Fatal("New() returned a normalizer with no catalogue")
	}
	if n.catalog.Size() == 0 {
		t.Fatal("New() loaded an empty catalogue")
	}
}
