package eventcatalog

import (
	"testing"
)

func load(t *testing.T) *Catalog {
	t.Helper()
	c, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	return c
}

// The catalogue is embedded, so a missing or malformed file is a build-time
// or boot-time fact rather than a runtime surprise. A load that returned a
// partial catalogue would answer "never seen" for every type in the file
// that failed, which is indistinguishable from a source nobody classified.
func TestTheEmbeddedCatalogueLoads(t *testing.T) {
	c := load(t)
	if len(c.Sources()) == 0 {
		t.Fatal("no sources loaded")
	}
	if c.Size() == 0 {
		t.Fatal("no event types loaded")
	}
	t.Logf("%d sources, %d event types", len(c.Sources()), c.Size())
}

// The ten sources depth plan 2.2's corpus names. Listed here rather than
// derived from the directory, because the point is that *these* are covered
// — a derived list would agree with whatever shipped.
func TestTheSourcesThePlanNamesAreCovered(t *testing.T) {
	c := load(t)
	present := map[string]bool{}
	for _, source := range c.Sources() {
		present[source] = true
	}
	for _, source := range []string{
		"aws_cloudtrail", "gcp_cloud_audit", "azure_activity", "azure_entra", "okta",
		"google_workspace", "m365_audit", "github", "slack_audit", "kubernetes_audit",
	} {
		if !present[source] {
			t.Errorf("no catalogue for %q", source)
		}
	}
}

// Lookup distinguishes three answers, and only one of them is worth telling
// an operator about. Folding them together would either spam a warning for
// every event from an unclassified source or hide the one case that means
// the catalogue has fallen behind the vendor.
func TestLookupDistinguishesTheThreeAnswers(t *testing.T) {
	c := load(t)

	classification, status := c.Lookup("aws_cloudtrail", "DeleteTrail")
	if status != StatusClassified {
		t.Fatalf("DeleteTrail: status = %q, want classified", status)
	}
	if classification.Sensitivity != SensitivityCritical {
		t.Errorf("DeleteTrail: sensitivity = %q, want critical", classification.Sensitivity)
	}
	if len(classification.ATTACK) == 0 {
		t.Error("DeleteTrail: no ATT&CK hint")
	}

	if _, status := c.Lookup("aws_cloudtrail", "SomethingNobodyHasSeen"); status != StatusUnknown {
		t.Errorf("an unseen type in a catalogued source: status = %q, want unknown", status)
	}
	if _, status := c.Lookup("a_source_with_no_catalogue", "anything"); status != StatusNoCatalog {
		t.Errorf("an uncatalogued source: status = %q, want no_catalog", status)
	}
}

// A nil catalogue is a usable one. The normalizer's own test constructors
// build a Normalizer directly, so the classification path has to tolerate
// having no catalogue rather than panicking in a test nobody wrote.
func TestANilCatalogueIsSafe(t *testing.T) {
	var c *Catalog
	if _, status := c.Lookup("aws_cloudtrail", "DeleteTrail"); status != StatusNoCatalog {
		t.Errorf("status = %q, want no_catalog", status)
	}
	if _, ok := c.EventTypePath("aws_cloudtrail"); ok {
		t.Error("a nil catalogue claimed to know an event-type path")
	}
	if c.Size() != 0 || c.Sources() != nil {
		t.Error("a nil catalogue reported contents")
	}
}

// Every sensitivity in the loaded catalogue is one of the five tiers, and
// Load is what enforces it — a sixth tier would be invisible until a query
// filtered on it and found nothing.
func TestEverySensitivityIsOnTheLadder(t *testing.T) {
	c := load(t)
	allowed := map[Sensitivity]bool{}
	for _, s := range Sensitivities {
		allowed[s] = true
	}
	for _, source := range c.Sources() {
		for eventType, classification := range c.bySource[source] {
			if !allowed[classification.Sensitivity] {
				t.Errorf("%s/%s: sensitivity %q is not on the ladder", source, eventType, classification.Sensitivity)
			}
			if classification.Action == "" {
				t.Errorf("%s/%s: no normalized action", source, eventType)
			}
		}
	}
}

// The declared path is how the classification finds the event type on a
// vendor record. These are the shapes the ten sources actually use.
func TestEventTypeReadsTheDeclaredPath(t *testing.T) {
	cases := []struct {
		name   string
		record map[string]any
		path   string
		want   string
		found  bool
	}{
		{
			name:   "a bare key",
			record: map[string]any{"eventName": "CreateAccessKey"},
			path:   "eventName",
			want:   "CreateAccessKey",
			found:  true,
		},
		{
			name:   "a nested key, as Azure spells its operation",
			record: map[string]any{"operationName": map[string]any{"value": "Microsoft.Authorization/roleAssignments/write"}},
			path:   "operationName.value",
			want:   "Microsoft.Authorization/roleAssignments/write",
			found:  true,
		},
		{
			name: "a list hop, as Workspace bundles several events per activity",
			record: map[string]any{
				"events": []any{map[string]any{"name": "GRANT_ADMIN_PRIVILEGE"}, map[string]any{"name": "view"}},
			},
			path:  "events[].name",
			want:  "GRANT_ADMIN_PRIVILEGE",
			found: true,
		},
		{
			name:   "an empty list is not an event type",
			record: map[string]any{"events": []any{}},
			path:   "events[].name",
			found:  false,
		},
		{
			name:   "a path that is not there",
			record: map[string]any{"somethingElse": "x"},
			path:   "eventName",
			found:  false,
		},
		{
			name:   "a value that is not a string",
			record: map[string]any{"verb": 7},
			path:   "verb",
			found:  false,
		},
		{
			name:   "whitespace is not an event type",
			record: map[string]any{"verb": "   "},
			path:   "verb",
			found:  false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, found := EventType(tc.record, tc.path)
			if found != tc.found {
				t.Fatalf("found = %v, want %v", found, tc.found)
			}
			if found && got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}

// Every catalogue declares the path its own fixtures are read at, and the
// loader is what the classification uses. A path declared in the YAML that
// the loader does not expose would make the classification silently find
// nothing for that source.
func TestEverySourceDeclaresItsEventTypePath(t *testing.T) {
	c := load(t)
	for _, source := range c.Sources() {
		path, ok := c.EventTypePath(source)
		if !ok || path == "" {
			t.Errorf("%s declares no event-type path", source)
		}
	}
}
