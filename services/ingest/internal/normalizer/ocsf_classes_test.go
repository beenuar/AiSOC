package normalizer

import (
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"testing"
)

// promotable mirrors should_promote() in
// services/fusion/app/services/promoter.py: OCSF category 2 (Findings) is
// promoted unconditionally, and anything else needs severity_id >= 4.
//
// Duplicated here rather than shared because the two services do not share a
// runtime — the same reasoning the `findingsCategory` constants in
// normalizer.go already carry, and TestUnpromotableWarningMatchesFusionPolicy
// is what keeps the pair honest.
func promotable(ocsf map[string]interface{}) bool {
	if category, ok := ocsf["category_uid"].(int); ok && category == findingsCategory {
		return true
	}
	severity, ok := ocsf["severity_id"].(int)
	return ok && severity >= promoteSeverityFloor
}

func normalizeCanonical(t *testing.T, connectorType string, payload map[string]interface{}) map[string]interface{} {
	t.Helper()
	full := map[string]interface{}{"source": connectorType, "raw_event": map[string]interface{}{"id": "1"}}
	for k, v := range payload {
		full[k] = v
	}
	ev, err := newLenientNormalizer().Normalize(&RawEvent{
		ConnectorID:   "c-1",
		ConnectorType: connectorType,
		TenantID:      "11111111-1111-1111-1111-111111111111",
		ReceivedAt:    "2026-10-07T00:00:00Z",
		Payload:       full,
	})
	if err != nil {
		t.Fatalf("Normalize(%q): %v", connectorType, err)
	}
	return ev.OcsfEvent
}

// The defect the class table exists for, stated as the behaviour that must
// now hold. On the pre-fix tree every one of these connectors reached the
// 2001 Security Finding default inside canonicalProfile(), which is category
// 2 and therefore promoted unconditionally — so a permitted DNS lookup, an
// allowed proxy request, an accepted VPC flow record and a routine Windows
// event each became an alert carrying severity "info".
//
// This test fails on that tree, by design: it is the negative control for the
// mapping as much as the assertion for it.
func TestRoutineTelemetryIsNotPromotedAsAFinding(t *testing.T) {
	// Each case is the shape the named connector's own normalize() emits for
	// its most common, least interesting record. Severity strings are the
	// ones those connectors actually produce for a benign record: Umbrella's
	// non-blocked verdict, Zscaler's Allow, a parsed ACCEPT flow line, a
	// Windows event id outside _HIGH_EVENT_IDS.
	cases := []struct {
		connector string
		why       string
	}{
		{"cisco_umbrella", "one record per DNS lookup, verdict not blocked"},
		{"zscaler", "one record per web request, action Allow"},
		{"aws_vpc_flow", "one record per accepted flow"},
		{"zeek_suricata", "network session telemetry"},
		{"windows_event", "a Windows event id outside the high-risk set"},
		{"auditd", "a syscall record with no matching audit key"},
		{"google_workspace", "a routine Workspace activity"},
		{"m365_audit", "a routine M365 audit record"},
		{"snowflake", "a completed warehouse query"},
		{"github", "a routine organisation audit entry"},
		{"box", "a routine file view in a file-hosting account"},
		{"vault", "a secret read against a path"},
		{"cloudflare", "a routine account audit entry"},
		{"mimecast", "a URL click the gateway did not block"},
	}
	for _, tc := range cases {
		t.Run(tc.connector, func(t *testing.T) {
			ocsf := normalizeCanonical(t, tc.connector, map[string]interface{}{
				"severity": "info",
				"title":    "routine activity",
			})
			if promotable(ocsf) {
				t.Errorf(
					"an info-severity event from %q (%s) is promotable: class_uid=%v category_uid=%v severity_id=%v. "+
						"Every record this source emits would become an alert",
					tc.connector, tc.why, ocsf["class_uid"], ocsf["category_uid"], ocsf["severity_id"],
				)
			}
		})
	}
}

// The other half, and the reason the mapping is per connector rather than a
// blanket demotion: a source whose fetch_alerts returns the vendor's own
// judged findings must still promote on class, so a Medium EDR detection or a
// Medium SIEM notable is never silently dropped.
func TestVendorFindingsStillPromoteOnClass(t *testing.T) {
	for _, connector := range []string{
		"crowdstrike", "sentinelone", "carbon_black", "aws_guardduty", "wiz",
		"splunk", "qradar", "elastic", "microsoft_sentinel", "aws_cloudtrail",
		// Verified against the endpoint each connector reads: an alert
		// stream, a blocked-message stream and a priority-filtered rule
		// stream are judgements, and demoting them would have silenced a
		// medium-severity vendor finding.
		"netskope", "proofpoint", "abnormal_security", "falco", "email_inbox",
	} {
		t.Run(connector, func(t *testing.T) {
			ocsf := normalizeCanonical(t, connector, map[string]interface{}{
				"severity": "medium",
				"title":    "vendor finding",
			})
			if !promotable(ocsf) {
				t.Errorf("a medium finding from %q is not promotable: class_uid=%v severity_id=%v",
					connector, ocsf["class_uid"], ocsf["severity_id"])
			}
		})
	}
}

// The gate counts a connector with a recorded reason as "on the generic
// mapping", and that count is the figure Phase 2 is graded against. It only
// means what it says if a recorded reason really does resolve to 2001 — a
// reason sitting beside a profile that moved the class would make the number
// describe the table rather than the events.
func TestARecordedReasonResolvesToSecurityFinding(t *testing.T) {
	for connector, entry := range connectorOCSFClass {
		if entry.genericReason == "" {
			continue
		}
		t.Run(connector, func(t *testing.T) {
			ocsf := normalizeCanonical(t, connector, map[string]interface{}{
				"severity": "medium",
				"title":    "vendor finding",
			})
			if ocsf["class_uid"] != classSecurityFinding {
				t.Errorf("%q records a reason for staying on the Security Finding default but resolves to "+
					"class_uid %v; the generic count would describe the table rather than the events",
					connector, ocsf["class_uid"])
			}
		})
	}
}

// Demoting a telemetry source out of category 2 only works if its severe
// events still get through on the other branch. A class with a severity map
// that cannot reach the floor is the `splunk_enterprise` defect wearing a new
// class uid: archived to the lake, never an alert, silently.
func TestMappedTelemetryClassesStillPromoteOnSeverity(t *testing.T) {
	for connector, entry := range connectorOCSFClass {
		if entry.classUID == 0 || entry.classUID/1000 == findingsCategory {
			continue
		}
		t.Run(connector, func(t *testing.T) {
			for _, severity := range []string{"high", "critical"} {
				ocsf := normalizeCanonical(t, connector, map[string]interface{}{
					"severity": severity,
					"title":    "something worth a human",
				})
				if !promotable(ocsf) {
					t.Errorf("a %s event from %q cannot promote: class_uid=%v severity_id=%v",
						severity, connector, ocsf["class_uid"], ocsf["severity_id"])
				}
			}
		})
	}
}

// Every connector the registry declares carries a decision. The registry is
// read off disk rather than listed here, because a hardcoded list drifts from
// it and then agrees with itself forever — the failure this whole area keeps
// producing.
func TestEveryDeclaredConnectorHasAnOCSFDecision(t *testing.T) {
	for id := range declaredConnectorIDs(t) {
		entry, ok := connectorOCSFClass[id]
		if !ok {
			t.Errorf("connector %q has no entry in connectorOCSFClass: its events take the 2001 default, "+
				"which is always promoted, and nothing records that as a decision", id)
			continue
		}
		if entry.classUID == 0 && entry.genericReason == "" {
			t.Errorf("connector %q has an entry carrying neither a class nor a reason", id)
		}
		if entry.classUID != 0 && entry.genericReason != "" {
			t.Errorf("connector %q declares both a class and a generic reason; one of them is not what happens", id)
		}
	}
}

// A class uid whose declared category disagrees with uid/1000 would change
// which promotion branch a connector's events take without anyone editing the
// mapping, because fusion derives the category from the uid alone.
func TestOCSFClassCategoryIsDerivedFromItsUID(t *testing.T) {
	if len(ocsfClasses) == 0 {
		t.Fatal("ocsfClasses is empty — refusing to pass on an empty table")
	}
	for uid, class := range ocsfClasses {
		if class.uid != uid {
			t.Errorf("ocsfClasses[%d] carries uid %d; a row must describe its own key", uid, class.uid)
		}
		if uid/1000 != class.category {
			t.Errorf("class %d (%s) declares category %d, but uid/1000 is %d",
				uid, class.caption, class.category, uid/1000)
		}
	}
}

// Nothing may map to a uid outside the closed set. Inventing one is how an
// event reaches the lake carrying a class no schema defines.
func TestConnectorClassesNameAKnownClass(t *testing.T) {
	for connector, entry := range connectorOCSFClass {
		if entry.classUID == 0 {
			continue
		}
		if _, ok := ocsfClasses[entry.classUID]; !ok {
			t.Errorf("connector %q maps to class uid %d, which ocsfClasses does not declare", connector, entry.classUID)
		}
	}
}

// The uids and captions above were read from schema.ocsf.io before use. This
// pins the pairing so a later edit cannot quietly rename a class into one the
// schema spells differently — the caption travels into `class_name` on every
// event and into the lake.
func TestClassCaptionsMatchThePublishedSchema(t *testing.T) {
	published := map[int]string{
		1001: "File System Activity",
		1007: "Process Activity",
		2001: "Security Finding",
		2002: "Vulnerability Finding",
		3001: "Account Change",
		3002: "Authentication",
		3005: "User Access Management",
		3006: "Group Management",
		4001: "Network Activity",
		4002: "HTTP Activity",
		4003: "DNS Activity",
		4009: "Email Activity",
		4012: "Email URL Activity",
		6001: "Web Resources Activity",
		6003: "API Activity",
		6005: "Datastore Activity",
		6006: "File Hosting Activity",
	}
	for uid, caption := range published {
		class, ok := ocsfClasses[uid]
		if !ok {
			t.Errorf("class %d (%s) is no longer declared", uid, caption)
			continue
		}
		if class.caption != caption {
			t.Errorf("class %d: caption %q, schema says %q", uid, class.caption, caption)
		}
	}
	for uid := range ocsfClasses {
		if _, ok := published[uid]; !ok {
			t.Errorf("class %d is declared but was not checked against the published schema; "+
				"add it to this table only after reading schema.ocsf.io", uid)
		}
	}
}

// A declared class nothing emits is the "exists but nothing calls it" shape
// one layer down: a reader sees the vocabulary and assumes the lake contains
// it. Every class must therefore be reached by a connector mapping, a
// hand-written profile or a webhook template, or be listed in
// `classesWithNoProducerYet` with the reason.
//
// The list is a ratchet in both directions. A class with no producer and no
// entry fails, and so does an entry for a class that has since acquired one —
// otherwise the record outlives the gap it describes, which is how a caveat
// becomes a lie.
func TestEveryDeclaredClassIsReachableOrRecorded(t *testing.T) {
	produced := map[int]string{}
	for connector, entry := range connectorOCSFClass {
		if entry.classUID != 0 {
			produced[entry.classUID] = "connector " + connector
		}
	}
	for key, profile := range connectorProfiles {
		produced[profile.classUID] = "profile " + key
	}
	for name, uid := range templateClassUIDs(t) {
		produced[uid] = "template " + name
	}

	for uid, class := range ocsfClasses {
		by, reached := produced[uid]
		reason, recorded := classesWithNoProducerYet[uid]
		switch {
		case reached && recorded:
			t.Errorf("class %d (%s) is produced by %s but is still listed as having no producer (%q); "+
				"remove the entry so the list keeps shrinking", uid, class.caption, by, reason)
		case !reached && !recorded:
			t.Errorf("class %d (%s) is declared and nothing emits it; map a connector to it or record why "+
				"it is declared ahead of its producer", uid, class.caption)
		case !reached && len(reason) < 30:
			t.Errorf("class %d (%s) is recorded as having no producer for the reason %q, which does not say "+
				"enough for a reviewer to disagree with it", uid, class.caption, reason)
		}
	}

	for uid := range classesWithNoProducerYet {
		if _, declared := ocsfClasses[uid]; !declared {
			t.Errorf("classesWithNoProducerYet names class %d, which ocsfClasses does not declare", uid)
		}
	}
}

// Webhook templates are the second producer of class uids — the push path to
// the connectors' pull path — and nothing checked them against the closed
// set. A template naming a uid no schema defines reaches the lake just as
// easily as a connector would.
func TestWebhookTemplatesNameAKnownClass(t *testing.T) {
	for name, uid := range templateClassUIDs(t) {
		if _, ok := ocsfClasses[uid]; !ok {
			t.Errorf("template %s declares class_uid %d, which ocsfClasses does not declare", name, uid)
		}
	}
}

// templateClassUIDs reads the class each webhook template stamps, off disk.
// The templates are embedded into the binary from this directory, so reading
// them here is reading what ships.
func templateClassUIDs(t *testing.T) map[string]int {
	t.Helper()
	entries, err := os.ReadDir("templates")
	if err != nil {
		t.Fatalf("cannot read templates: %v", err)
	}
	classUIDRe := regexp.MustCompile(`(?m)^class_uid:\s*(\d+)`)
	out := map[string]int{}
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".yaml" {
			continue
		}
		src, err := os.ReadFile(filepath.Join("templates", entry.Name()))
		if err != nil {
			t.Fatalf("cannot read template %s: %v", entry.Name(), err)
		}
		if m := classUIDRe.FindSubmatch(src); m != nil {
			uid, convErr := strconv.Atoi(string(m[1]))
			if convErr != nil {
				t.Fatalf("template %s: class_uid %q is not an integer", entry.Name(), m[1])
			}
			out[entry.Name()] = uid
		}
	}
	if len(out) == 0 {
		t.Fatal("parsed zero template class uids — refusing to pass on an empty read")
	}
	return out
}

// A connector with a hand-written profile takes that profile's class, not the
// table's. Declaring a class for one would be a decision nothing acts on, and
// a reader would believe it.
func TestClassTableDoesNotContradictAHandWrittenProfile(t *testing.T) {
	for connector, entry := range connectorOCSFClass {
		if entry.classUID == 0 {
			continue
		}
		profile, hasProfile := connectorProfiles[connector]
		if !hasProfile {
			if aliased, isAlias := connectorTypeAliases[connector]; isAlias {
				profile, hasProfile = connectorProfiles[aliased]
			}
		}
		if hasProfile && profile.classUID != entry.classUID {
			t.Errorf("connector %q maps to class %d in the table but its profile declares %d; "+
				"a flat payload takes the profile and a canonical envelope takes the table, so the two must agree",
				connector, entry.classUID, profile.classUID)
		}
	}
}
