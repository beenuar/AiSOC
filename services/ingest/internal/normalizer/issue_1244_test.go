package normalizer

import (
	"testing"

	"github.com/beenuar/aisoc/services/ingest/internal/attck"
)

// Issue #1244, reported against `POST /v1/ingest/batch` with
// `connector_type: crowdstrike` and generic field names.
//
// Two distinct losses on the ingest side:
//
//   - a top-level `description` reached no OCSF slot the fusion promoter
//     reads, so the alert's description resolved to its title;
//   - a vendor's `techniques: ["T1003.001"]` reached nothing either, because
//     `extractTechniqueIDs` did not list the plural bare key.

func normalizeOrFail(t *testing.T, n *Normalizer, raw *RawEvent) map[string]interface{} {
	t.Helper()
	ev, err := n.Normalize(raw)
	if err != nil {
		t.Fatalf("Normalize returned error: %v", err)
	}
	return ev.OcsfEvent
}

func pushedEvent(payload map[string]interface{}) *RawEvent {
	return &RawEvent{
		ConnectorID:   "conn-1",
		ConnectorType: "crowdstrike",
		TenantID:      "11111111-1111-1111-1111-111111111111",
		ReceivedAt:    "2026-08-02T00:00:00Z",
		Payload:       payload,
	}
}

func findingField(t *testing.T, ocsf map[string]interface{}, key string) interface{} {
	t.Helper()
	finding, ok := ocsf["finding"].(map[string]interface{})
	if !ok {
		return nil
	}
	return finding[key]
}

// ── A supplied description must reach a slot the promoter reads ───────────

func TestSuppliedDescriptionReachesFindingDesc(t *testing.T) {
	ocsf := normalizeOrFail(t, newLenientNormalizer(), pushedEvent(map[string]interface{}{
		"title":       "Credential dumping detected",
		"description": "lsass.exe memory read by rundll32.exe",
		"severity":    "high",
		"hostname":    "WIN-FIN-01",
	}))

	if got := findingField(t, ocsf, "desc"); got != "lsass.exe memory read by rundll32.exe" {
		t.Errorf("finding.desc = %v, want the supplied description", got)
	}
	// The title still owns `message`; the two must not collapse onto one slot.
	if got := ocsf["message"]; got != "Credential dumping detected" {
		t.Errorf("message = %v, want the supplied title", got)
	}
}

// A profile that names its own source for finding.desc keeps it: the alias
// only fills a destination the field map left empty. `email_inbox` resolves
// finding.desc from `body`, so a payload carrying both must not lose it.
func TestAProfilesOwnDescriptionFieldStillWins(t *testing.T) {
	raw := pushedEvent(map[string]interface{}{
		"subject":     "Invoice overdue",
		"body":        "the profile's own field",
		"description": "the generic key",
		"severity":    "medium",
	})
	raw.ConnectorType = "email_inbox"

	ocsf := normalizeOrFail(t, newLenientNormalizer(), raw)
	if got := findingField(t, ocsf, "desc"); got != "the profile's own field" {
		t.Errorf("finding.desc = %v, want the profile's own mapping to win over the alias", got)
	}
}

// Security Hub mapped `Description` onto `raw_data`, which Normalize
// overwrites unconditionally a few lines later with the serialized payload —
// so the vendor's description was mapped and then thrown away.
func TestSecurityHubDescriptionSurvivesTheRawDataOverwrite(t *testing.T) {
	raw := pushedEvent(map[string]interface{}{
		"Title":       "S3 bucket is publicly readable",
		"Description": "The bucket policy grants s3:GetObject to Principal *",
		"Severity":    map[string]interface{}{"Label": "HIGH"},
	})
	raw.ConnectorType = "aws_security_hub"

	ocsf := normalizeOrFail(t, newLenientNormalizer(), raw)

	if got := findingField(t, ocsf, "desc"); got != "The bucket policy grants s3:GetObject to Principal *" {
		t.Errorf("finding.desc = %v, want the Security Hub Description", got)
	}
	// raw_data is the serialized payload and nothing else.
	rawData, ok := ocsf["raw_data"].(string)
	if !ok {
		t.Fatalf("raw_data = %T, want the serialized payload string", ocsf["raw_data"])
	}
	if rawData == "The bucket policy grants s3:GetObject to Principal *" {
		t.Error("raw_data still holds the Description — the field map and the serializer are fighting over one slot")
	}
}

// ── A bare `techniques` key must yield techniques ─────────────────────────

func TestBareTechniquesKeyIsExtracted(t *testing.T) {
	for _, key := range []string{"techniques", "technique"} {
		t.Run(key, func(t *testing.T) {
			got := extractTechniqueIDs(map[string]interface{}{
				key: []interface{}{"T1003.001"},
			})
			if len(got) != 1 || got[0] != "T1003.001" {
				t.Errorf("extractTechniqueIDs(%q) = %v, want [T1003.001]", key, got)
			}
		})
	}
}

func TestTechniquesAcceptsAScalarAsWellAsAList(t *testing.T) {
	got := extractTechniqueIDs(map[string]interface{}{"techniques": "T1059.001"})
	if len(got) != 1 || got[0] != "T1059.001" {
		t.Errorf("extractTechniqueIDs = %v, want [T1059.001]", got)
	}
}

// A well-formed technique id must survive to `mitre_attck` even when the
// ATT&CK corpus is unavailable. The corpus is fetched from raw.githubusercontent.com
// at boot, so on an air-gapped or egress-filtered deployment `attck.Loaded()`
// is false forever — and gating the whole block on it meant no event anywhere
// ever carried a technique, no matter what the vendor sent.
func TestAWellFormedTechniqueIsCarriedWithoutTheCorpus(t *testing.T) {
	if attck.Loaded() {
		t.Skip("ATT&CK corpus is loaded in this process; this test covers the unloaded deployment")
	}

	ocsf := normalizeOrFail(t, newLenientNormalizer(), pushedEvent(map[string]interface{}{
		"title":      "Credential dumping detected",
		"severity":   "high",
		"techniques": []interface{}{"T1003.001"},
	}))

	block, ok := ocsf["mitre_attck"].([]map[string]interface{})
	if !ok || len(block) != 1 {
		t.Fatalf("mitre_attck = %#v, want one unverified entry", ocsf["mitre_attck"])
	}
	if got := block[0]["technique_id"]; got != "T1003.001" {
		t.Errorf("technique_id = %v, want T1003.001", got)
	}
	// The reader has to be able to tell an id we looked up from one we only
	// passed through, or an unverified id reads as corpus-confirmed.
	if verified, ok := block[0]["verified"].(bool); !ok || verified {
		t.Errorf("verified = %v, want false on an entry the corpus never confirmed", block[0]["verified"])
	}
}

// Garbage must not be carried: the pass-through is for well-formed ids only.
//
// `TA0006` is the one that matters here. It is a *tactic* id, and the old
// shape check (leading `T`, 5–7 characters before the dot) accepted it. That
// was invisible while every id had to survive `attck.Lookup`, which has no
// entry for a tactic — but an unverified pass-through would have written a
// tactic into `mitre_techniques`, so the shape check has to be exact for the
// carry to be safe.
func TestAMalformedTechniqueIsNotCarried(t *testing.T) {
	for _, bad := range []string{"not-a-technique", "T12", "TA0006", "T10591", "T1059.1", ""} {
		if got := extractTechniqueIDs(map[string]interface{}{"techniques": bad}); len(got) != 0 {
			t.Errorf("extractTechniqueIDs(%q) = %v, want none", bad, got)
		}
	}
}

// Stated against the shape check itself, because the table above goes through
// a key the extractor did not read before this change and so would have
// passed vacuously.
func TestNormalizeTechniqueIDRejectsATacticID(t *testing.T) {
	if got := normalizeTechniqueID("TA0006"); got != "" {
		t.Errorf("normalizeTechniqueID(\"TA0006\") = %q, want \"\" — TA0006 is a tactic, not a technique", got)
	}
	if got := normalizeTechniqueID("T10591"); got != "" {
		t.Errorf("normalizeTechniqueID(\"T10591\") = %q, want \"\"", got)
	}
	if got := normalizeTechniqueID("T1059.001"); got != "T1059.001" {
		t.Errorf("normalizeTechniqueID(\"T1059.001\") = %q, want it accepted unchanged", got)
	}
}

func TestWellFormedTechniqueShapesAreAccepted(t *testing.T) {
	for _, good := range []string{"T1059", "T1059.001", "t1003.001"} {
		if got := extractTechniqueIDs(map[string]interface{}{"techniques": good}); len(got) != 1 {
			t.Errorf("extractTechniqueIDs(%q) = %v, want one id", good, got)
		}
	}
}
