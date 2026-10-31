package inbox

import (
	"testing"
)

// The Agentmetry template (GitHub Discussion #1577).
//
// Agentmetry (github.com/blitzcrieg1/agentmetry) records the tool calls AI
// coding agents make and correlates them into detections. Its webhook sink
// POSTs one canonical JSON event per request — routine activity and
// correlated detections down the same pipe — so one template serves both
// kinds and splits them by OCSF class via class_map, the same 6003/2001
// split ai-runtime.yaml / ai-finding.yaml encode.
//
// Every fixture here is the real canonical shape (schema v1.2.0), captured
// by running `agentmetry demo` (PyPI agentmetry 0.10.4) locally and reading
// the trail it wrote. Host and operator identity values were replaced with
// neutral ones; every key, nesting level and vocabulary word is as captured.
// A hand-invented fixture is how a template passes its tests against events
// no sensor ever sends.

func agentmetryRegistry(t *testing.T) *Registry {
	t.Helper()
	r := NewRegistry()
	if err := r.LoadEmbedded(); err != nil {
		t.Fatalf("LoadEmbedded failed: %v", err)
	}
	return r
}

func agentmetryTemplate(t *testing.T) *Template {
	t.Helper()
	tmpl, err := agentmetryRegistry(t).Get("agentmetry")
	if err != nil {
		t.Fatalf("agentmetry template not embedded: %v", err)
	}
	return tmpl
}

// agentmetryToolCall is a captured `run/tool_called` event: Cursor's Read
// tool touching a private key, with the sensor's own ATT&CK mapping on the
// tool block and an ATLAS block beside it.
func agentmetryToolCall() map[string]any {
	return map[string]any{
		"schema_version": "1.2.0",
		"event_id":       "5779eeaa-2844-492a-b3ad-9808b0dab20a",
		"session_id":     "",
		"correlation_id": "demo-session-1",
		"timestamp_utc":  "2026-10-31T21:13:17.091378+00:00",
		"host_id":        "dev-mbp-7.local",
		"source_topic":   "external/cursor/tool_called",
		"source":         map[string]any{"tier": "external", "app": "cursor", "adapter": "cursor_hook"},
		"initiator": map[string]any{
			"actor_type": "human", "trigger": "manual",
			"operator_id": "dev_01", "operator_source": "orchestrator_os",
		},
		"actor":  map[string]any{"type": "user", "id": "dev_01", "role": "operator"},
		"action": map[string]any{"type": "tool_called", "outcome": "success", "reason": ""},
		"agent":  map[string]any{"name": "cursor", "skill_id": ""},
		"model":  map[string]any{"id": "cursor", "provider": "cursor"},
		"tool": map[string]any{
			"name":                "Read",
			"qualified":           "cursor.Read",
			"server":              "cursor",
			"input_redaction":     "hash+command",
			"input_hash":          "",
			"parameters_redacted": false,
			"command":             "cat ~/.ssh/id_rsa",
			"mitre": map[string]any{
				"tactic_id": "TA0006", "tactic": "Credential Access",
				"technique_id": "T1552.004", "technique": "Private Keys",
			},
			"atlas": map[string]any{
				"framework": "MITRE ATLAS", "tactic_id": "AML.TA0013",
				"tactic": "Credential Access", "technique_id": "AML.T0098",
				"technique": "AI Agent Tool Credential Harvesting", "atlas_version": "2026.07",
			},
		},
	}
}

// agentmetryDetection is the captured `credential-exfil` correlated finding:
// action.type "detection", the severity in action.outcome AND in
// detection.severity, ATT&CK technique ids as a list on the detection block.
func agentmetryDetection() map[string]any {
	return map[string]any{
		"schema_version": "1.2.0",
		"event_id":       "58a23195-e035-44bd-a0d4-09b3bd3d9ac5",
		"session_id":     "",
		"correlation_id": "demo-session-1",
		"timestamp_utc":  "2026-10-31T21:13:17.104370+00:00",
		"host_id":        "dev-mbp-7.local",
		"source_topic":   "detection/credential-exfil",
		"source":         map[string]any{"tier": "external", "app": "claude", "adapter": "claude_hook"},
		"initiator": map[string]any{
			"actor_type": "human", "trigger": "manual",
			"operator_id": "dev_01", "operator_source": "orchestrator_os",
		},
		"actor": map[string]any{"type": "user", "id": "dev_01", "role": "operator"},
		"action": map[string]any{
			"type": "detection", "outcome": "critical",
			"reason": "cursor.Read accessed credentials, then WebFetch egressed to the network in the same session.",
		},
		"agent": map[string]any{"name": "claude", "skill_id": ""},
		"detection": map[string]any{
			"rule_id":        "credential-exfil",
			"title":          "Credential access followed by network egress",
			"severity":       "critical",
			"summary":        "cursor.Read accessed credentials, then WebFetch egressed to the network in the same session.",
			"correlation_id": "demo-session-1",
			"tactic_ids":     []any{"TA0006", "TA0011"},
			"technique_ids":  []any{"T1552.004", "T1071.001"},
			"event_ids":      []any{"5779eeaa-2844-492a-b3ad-9808b0dab20a", "68b649c5-b086-4606-8679-b1731b9689ae"},
			"first_seen_utc": "2026-10-31T21:13:17.091378+00:00",
			"last_seen_utc":  "2026-10-31T21:13:17.104370+00:00",
			"disposition":    nil,
		},
	}
}

func techniqueIDs(t *testing.T, out map[string]any) []string {
	t.Helper()
	block, ok := out["mitre_attck"].([]map[string]any)
	if !ok {
		// Also accept []interface{} in case the block shape evolves.
		raw, rawOK := out["mitre_attck"].([]any)
		if !rawOK {
			return nil
		}
		for _, item := range raw {
			if m, mOK := item.(map[string]any); mOK {
				block = append(block, m)
			}
		}
	}
	var ids []string
	for _, entry := range block {
		if tid, tidOK := entry["technique_id"].(string); tidOK {
			ids = append(ids, tid)
		}
	}
	return ids
}

func TestAgentmetryActivityStaysInTheLake(t *testing.T) {
	// Routine agent activity must land in category 6 so should_promote()
	// leaves it in the lake: a coding agent emits an event per tool call,
	// and promoting each one floods the queue with its normal operation.
	out := agentmetryTemplate(t).Apply(agentmetryToolCall(), "tenant-1", "inbox:agentmetry", "2026-10-31T21:13:18Z")

	if got := out["class_uid"]; got != 6003 {
		t.Errorf("class_uid = %v, want 6003 (API Activity)", got)
	}
	if got := out["category_uid"]; got != 6 {
		t.Errorf("category_uid = %v, want 6 so routine activity is not auto-promoted", got)
	}
	// Activity events carry no vendor severity — action.outcome is an
	// outcome word, not a severity — so the honest value is Unknown, which
	// sits below the promoter's severity floor.
	if got := out["severity_id"]; got != 0 {
		t.Errorf("severity_id = %v, want 0 (no vendor severity on activity)", got)
	}
	if got := out["activity_name"]; got != "Read" {
		t.Errorf("activity_name = %v, want the tool name", got)
	}
	if got := out["status_detail"]; got != "success" {
		t.Errorf("status_detail = %v, want action.outcome", got)
	}

	actor, _ := out["actor"].(map[string]any)
	proc, _ := actor["process"].(map[string]any)
	user, _ := actor["user"].(map[string]any)
	if proc["name"] != "cursor" {
		t.Errorf("actor.process.name = %v, want the agent name", proc["name"])
	}
	if user["name"] != "dev_01" {
		t.Errorf("actor.user.name = %v, want the operator account", user["name"])
	}
	src, _ := out["src_endpoint"].(map[string]any)
	if src["hostname"] != "dev-mbp-7.local" {
		t.Errorf("src_endpoint.hostname = %v, want host_id", src["hostname"])
	}

	// The event time is the sensor's timestamp_utc, not the receipt time.
	if got, _ := out["time"].(string); got == "2026-10-31T21:13:18Z" {
		t.Errorf("time fell back to receivedAt; timestamp_utc was not parsed")
	}

	// The sensor's own ATT&CK mapping on the tool block is carried.
	ids := techniqueIDs(t, out)
	if len(ids) != 1 || ids[0] != "T1552.004" {
		t.Errorf("mitre_attck technique ids = %v, want [T1552.004]", ids)
	}
	// The ATLAS id beside it must NOT be lifted into an ATT&CK-typed
	// field: Agentmetry's own docs warn an AML.T**** id there corrupts any
	// rollup that groups by technique.
	for _, id := range ids {
		if id == "AML.T0098" {
			t.Errorf("ATLAS id leaked into mitre_attck: %v", ids)
		}
	}
	// It is preserved, though — the inbox path retains no unmapped
	// payload, so the template carries it in an evidence field.
	finding, _ := out["finding"].(map[string]any)
	evidence, _ := finding["evidence"].(map[string]any)
	if evidence["tool_atlas_technique_id"] != "AML.T0098" {
		t.Errorf("finding.evidence.tool_atlas_technique_id = %v, want AML.T0098 preserved outside ATT&CK fields", evidence["tool_atlas_technique_id"])
	}
}

func TestAgentmetryDetectionIsAlwaysPromotable(t *testing.T) {
	// A correlated detection has already passed the sensor's own rule
	// engine — the same reasoning that puts a Splunk notable at 2001. It
	// must land in category 2, which the fusion promoter promotes
	// regardless of severity, so a medium detection is never dropped.
	out := agentmetryTemplate(t).Apply(agentmetryDetection(), "tenant-1", "inbox:agentmetry", "2026-10-31T21:13:18Z")

	if got := out["class_uid"]; got != 2001 {
		t.Errorf("class_uid = %v, want 2001 (Security Finding) via class_map", got)
	}
	if got := out["category_uid"]; got != 2 {
		t.Errorf("category_uid = %v, want 2 so the promoter always promotes it", got)
	}
	if got := out["severity_id"]; got != 5 {
		t.Errorf("severity_id = %v, want 5 — the critical tier must survive end-to-end", got)
	}
	if got := out["severity"]; got != "Critical" {
		t.Errorf("severity = %v, want Critical", got)
	}
	if got := out["message"]; got != "Credential access followed by network egress" {
		t.Errorf("message = %v, want the detection title", got)
	}

	finding, _ := out["finding"].(map[string]any)
	if finding["title"] != "Credential access followed by network egress" {
		t.Errorf("finding.title = %v", finding["title"])
	}
	if finding["desc"] != "cursor.Read accessed credentials, then WebFetch egressed to the network in the same session." {
		t.Errorf("finding.desc = %v, want the detection summary", finding["desc"])
	}
	if finding["uid"] != "58a23195-e035-44bd-a0d4-09b3bd3d9ac5" {
		t.Errorf("finding.uid = %v, want the vendor event_id", finding["uid"])
	}
	related, _ := finding["related_events"].(map[string]any)
	if related["id"] != "credential-exfil" {
		t.Errorf("finding.related_events.id = %v, want the rule id", related["id"])
	}

	// Both supplied technique ids are carried, as supplied, exactly once.
	ids := techniqueIDs(t, out)
	if len(ids) != 2 || ids[0] != "T1552.004" || ids[1] != "T1071.001" {
		t.Errorf("mitre_attck technique ids = %v, want [T1552.004 T1071.001]", ids)
	}
	// Tactic ids (TA####) have their own slot in the enrichment and must
	// not be misread as techniques.
	for _, id := range ids {
		if id == "TA0006" || id == "TA0011" {
			t.Errorf("tactic id misread as a technique: %v", ids)
		}
	}
}

func TestAgentmetrySeverityLadderPreservesEveryTier(t *testing.T) {
	// The five-tier house ladder, driven through the real template. The
	// critical case is the repo rule this pins: critical must map to its
	// own tier, never collapse into high.
	tmpl := agentmetryTemplate(t)
	for _, tc := range []struct {
		vendor string
		id     int
		label  string
	}{
		{"critical", 5, "Critical"},
		{"high", 4, "High"},
		{"medium", 3, "Medium"},
		{"low", 2, "Low"},
	} {
		payload := agentmetryDetection()
		det := payload["detection"].(map[string]any)
		det["severity"] = tc.vendor
		action := payload["action"].(map[string]any)
		action["outcome"] = tc.vendor

		out := tmpl.Apply(payload, "tenant-1", "inbox:agentmetry", "2026-10-31T21:13:18Z")
		if out["severity_id"] != tc.id {
			t.Errorf("severity %q → severity_id %v, want %d", tc.vendor, out["severity_id"], tc.id)
		}
		if out["severity"] != tc.label {
			t.Errorf("severity %q → label %v, want %q", tc.vendor, out["severity"], tc.label)
		}
	}
}

func TestAgentmetryUnknownKindKeepsTheDefaultClass(t *testing.T) {
	// An event kind with no class_map entry (mcp_schema, session_start,
	// a kind a future schema adds) degrades to the template's declared
	// class rather than vanishing or being promoted.
	payload := agentmetryToolCall()
	payload["action"] = map[string]any{"type": "mcp_schema", "outcome": "changed", "reason": ""}
	out := agentmetryTemplate(t).Apply(payload, "tenant-1", "inbox:agentmetry", "2026-10-31T21:13:18Z")
	if got := out["class_uid"]; got != 6003 {
		t.Errorf("class_uid = %v, want the 6003 default for an unmapped kind", got)
	}
}

func TestAgentmetryMalformedEventStillLands(t *testing.T) {
	// Over-deliver, never lose: an empty object and an event whose action
	// is a bare string must both land with the template defaults rather
	// than panic or drop.
	tmpl := agentmetryTemplate(t)
	for name, payload := range map[string]map[string]any{
		"empty object":     {},
		"action not a map": {"action": "detection", "detection": "critical"},
	} {
		out := tmpl.Apply(payload, "tenant-1", "inbox:agentmetry", "2026-10-31T21:13:18Z")
		if got := out["class_uid"]; got != 6003 {
			t.Errorf("%s: class_uid = %v, want the 6003 default", name, got)
		}
		if got := out["severity_id"]; got != 0 {
			t.Errorf("%s: severity_id = %v, want 0 (Unknown)", name, got)
		}
		if got := out["severity"]; got != "Unknown" {
			t.Errorf("%s: severity = %v, want Unknown", name, got)
		}
	}
}

// ---------------------------------------------------------------------------
// Discussion #1577 asked whether generic-json "should land" Agentmetry
// events, severity in action.outcome — stated as a claim to check, not a
// result. This is the check, against the real embedded generic-json
// template. The events land; what the claim misses is what the bundled
// template exists to fix.
// ---------------------------------------------------------------------------

func TestGenericJsonLandsAgentmetryEventsButFlattensThem(t *testing.T) {
	generic, err := agentmetryRegistry(t).Get("generic-json")
	if err != nil {
		t.Fatalf("generic-json not embedded: %v", err)
	}

	// 1. A critical detection lands — but generic-json reads severity from
	// a top-level `severity` field, and Agentmetry carries it at
	// action.outcome / detection.severity, so the critical tier flattens
	// to Unknown and the five-tier ladder is lost.
	det := generic.Apply(agentmetryDetection(), "tenant-1", "inbox:generic-json", "2026-10-31T21:13:18Z")
	if got := det["severity_id"]; got != 0 {
		t.Errorf("generic-json severity_id = %v for a critical detection; the claim's severity path is not read", got)
	}
	// The detection's own title is nested at detection.title, which
	// generic-json does not map, so the alert renders a fallback title.
	if _, ok := det["finding"].(map[string]any); ok {
		t.Errorf("finding block unexpectedly populated: %v", det["finding"])
	}
	// The supplied ATT&CK technique ids are dropped entirely.
	if _, ok := det["mitre_attck"]; ok {
		t.Errorf("mitre_attck unexpectedly populated by generic-json")
	}
	// timestamp_utc is not generic-json's time field, so the event time
	// falls back to receipt time.
	if got, _ := det["time"].(string); got != "2026-10-31T21:13:18Z" {
		t.Errorf("time = %v, expected the receivedAt fallback documenting the lost event time", got)
	}

	// 2. The deeper problem runs the other way: generic-json is class 2001
	// for every event, and category 2 is always promoted — so each routine
	// tool call becomes an alert. One coding agent is an alert flood.
	act := generic.Apply(agentmetryToolCall(), "tenant-1", "inbox:generic-json", "2026-10-31T21:13:18Z")
	if got := act["class_uid"]; got != 2001 {
		t.Fatalf("generic-json class_uid = %v; this test documents the always-promoted path", got)
	}
	if got := act["category_uid"]; got != 2 {
		t.Fatalf("generic-json category_uid = %v, want 2 (always promoted)", got)
	}
}
