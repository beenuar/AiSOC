package inbox

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

// These fixtures extend the captured events in agentmetry_test.go with
// synthetic optional fields from the canonical 1.2.0 contract. They are not
// captures of real accounts, machines or sessions.
func applyAgentmetryJSON(t *testing.T, payload map[string]any) map[string]any {
	t.Helper()
	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	events, err := decodeJSONEvents(body)
	if err != nil || len(events) != 1 {
		t.Fatalf("decode canonical JSON: count=%d, err=%v", len(events), err)
	}
	out := agentmetryTemplate(t).Apply(events[0], "tenant-1", "inbox:agentmetry", "2026-10-31T21:13:18Z")
	// Exercise the JSON boundary used when the normalized event is published:
	// arrays, false and zero must retain their meaning for downstream readers.
	wire, err := json.Marshal(out)
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(wire, &decoded); err != nil {
		t.Fatal(err)
	}
	return decoded
}

func agentmetryObservation(kind, outcome string) map[string]any {
	app, adapter, correlation, tier := "agentmetry", "heartbeat", "", "agentmetry"
	if kind == "mcp_schema" {
		app, adapter, correlation = "mcp_proxy", "mcp_audit_proxy", "synthetic-mcp-session"
		tier = "external"
	}
	return map[string]any{
		"schema_version": "1.2.0", "event_id": "00000000-0000-4000-8000-000000000001", "session_id": "",
		"timestamp_utc": "2026-10-31T21:13:17Z", "host_id": "synthetic-host",
		"correlation_id": correlation,
		"source_topic":   "agentmetry/" + kind,
		"source":         map[string]any{"tier": tier, "app": app, "adapter": adapter},
		"initiator":      map[string]any{"actor_type": "system", "trigger": "scheduled", "operator_id": ""},
		"actor":          map[string]any{"type": "system", "id": "agentmetry", "role": "recorder"},
		"agent":          map[string]any{"name": "agentmetry", "skill_id": ""},
		"action":         map[string]any{"type": kind, "outcome": outcome, "reason": ""},
	}
}

func TestAgentmetryContextLinksFindingToSourceEvents(t *testing.T) {
	payload := agentmetryDetection()
	out := applyAgentmetryJSON(t, payload)
	context, _ := getNested(out, "finding.evidence.agentmetry").(map[string]any)
	if got := context["event_type"]; got != "detection" {
		t.Errorf("event type = %v, want detection", got)
	}
	if got := context["schema_version"]; got != "1.2.0" {
		t.Errorf("source schema = %v, want 1.2.0", got)
	}
	if got := context["operator_source"]; got != "orchestrator_os" {
		t.Errorf("operator provenance = %v, want orchestrator_os", got)
	}
	if got := context["adapter"]; got != "claude_hook" {
		t.Errorf("capture adapter = %v, want claude_hook", got)
	}
	detection, _ := context["detection"].(map[string]any)
	for _, field := range []string{"event_ids", "first_seen_utc", "last_seen_utc"} {
		want := payload["detection"].(map[string]any)[field]
		if got := detection[field]; !reflect.DeepEqual(got, want) {
			t.Errorf("detection %s = %v, want %v", field, got, want)
		}
	}
	if getNested(out, "finding.evidence.session_id") != payload["correlation_id"] ||
		getNested(out, "finding.uid") != payload["event_id"] ||
		getNested(out, "src_endpoint.hostname") != payload["host_id"] {
		t.Error("source event, host or session join key changed")
	}
	if out["class_uid"] != float64(2001) || out["severity_id"] != float64(5) {
		t.Error("adding evidence changed finding routing or critical severity")
	}
	if getNested(out, "metadata.version") != "1.1.0" {
		t.Error("source schema must not replace the declared OCSF ingest version")
	}
}

func TestAgentmetryContextPreservesHostScopedCorrelation(t *testing.T) {
	payload := agentmetryDetection()
	host := payload["host_id"].(string)
	payload["correlation_id"] = host
	payload["action"].(map[string]any)["outcome"] = "high"
	detection := payload["detection"].(map[string]any)
	detection["rule_id"] = "host-subagent-swarm-burst"
	detection["title"] = "Subagent swarm across sessions on one host"
	detection["summary"] = "Synthetic starts across two sessions on one host."
	detection["severity"] = "high"
	detection["correlation_id"] = host
	detection["tactic_ids"] = []any{"TA0002"}
	detection["technique_ids"] = []any{"T1059"}
	out := applyAgentmetryJSON(t, payload)
	ids, _ := getNested(out, "finding.evidence.agentmetry.detection.event_ids").([]any)
	if len(ids) != 2 {
		t.Fatalf("host-wide finding lost its supporting event references: %v", ids)
	}
	if getNested(out, "finding.evidence.session_id") != host {
		t.Fatal("legacy session_id must preserve a host-scoped source correlation ID")
	}
	// Each referenced event can retain its own session. This checks the
	// projected join keys, not a database lookup or a UI pivot.
	for i, session := range []string{"synthetic-session-a", "synthetic-session-b"} {
		event := agentmetryToolCall()
		event["event_id"] = ids[i]
		event["correlation_id"] = session
		supporting := applyAgentmetryJSON(t, event)
		if getNested(supporting, "finding.uid") != ids[i] ||
			getNested(supporting, "src_endpoint.hostname") != host ||
			supporting["tenant_uid"] != out["tenant_uid"] ||
			getNested(supporting, "finding.evidence.session_id") != session {
			t.Error("source event references, host, tenant or independent session were rewritten")
		}
	}
}

func TestAgentmetryContextKeepsReportedAccountSeparateFromOperator(t *testing.T) {
	for _, source := range []string{"hook_payload", "otel", "local_config", "session_meta", "codex_auth"} {
		t.Run(source, func(t *testing.T) {
			payload := agentmetryToolCall()
			payload["account"] = map[string]any{
				"domain": "accounts.example", "source": source, "organization_id": "synthetic-org",
				"email": "invented-person@accounts.example", "account_id": "synthetic-account-id",
				"user_id": "synthetic-user-id", "future_credential": "synthetic-secret-do-not-copy",
			}
			out := applyAgentmetryJSON(t, payload)
			account := getNested(out, "finding.evidence.agentmetry.account")
			want := map[string]any{"domain": "accounts.example", "source": source, "organization_id": "synthetic-org"}
			if !reflect.DeepEqual(account, want) {
				t.Errorf("reported account evidence = %v, want selected claims %v", account, want)
			}
			if getNested(out, "actor.user.name") != "dev_01" || getNested(out, "actor.user.email_addr") != nil {
				t.Error("reported account must not replace or enrich the operator identity")
			}
			wire, _ := json.Marshal(out)
			for _, excluded := range []string{"invented-person@", "synthetic-account-id", "synthetic-user-id", "synthetic-secret-do-not-copy"} {
				if strings.Contains(string(wire), excluded) {
					t.Errorf("unselected account data reached normalized output: %s", excluded)
				}
			}
			if out["class_uid"] != float64(6003) || out["severity_id"] != float64(0) {
				t.Error("an account claim alone must not turn routine activity into a finding")
			}
		})
	}
}

func TestAgentmetryContextDoesNotInventDomainForPartialClaims(t *testing.T) {
	for _, tc := range []struct {
		name    string
		account map[string]any
		want    map[string]any
	}{
		{"ids only", map[string]any{"source": "session_meta", "account_id": "synthetic-account-id", "user_id": "synthetic-user-id"}, map[string]any{"source": "session_meta"}},
		{"organization only", map[string]any{"source": "otel", "organization_id": "synthetic-org"}, map[string]any{"source": "otel", "organization_id": "synthetic-org"}},
		{"source only", map[string]any{"source": "local_config"}, map[string]any{"source": "local_config"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			payload := agentmetryToolCall()
			payload["account"] = tc.account
			out := applyAgentmetryJSON(t, payload)
			if got := getNested(out, "finding.evidence.agentmetry.account"); !reflect.DeepEqual(got, tc.want) {
				t.Errorf("partial claim = %v, want %v without inferred domain or opaque IDs", got, tc.want)
			}
			if getNested(out, "actor.user.name") != "dev_01" || out["class_uid"] != float64(6003) || out["severity_id"] != float64(0) {
				t.Error("a partial account claim changed the operator identity or event routing")
			}
		})
	}
}

func TestAgentmetryContextKeepsMissingClaimsAbsent(t *testing.T) {
	for name, account := range map[string]any{
		"absent": nil, "empty": map[string]any{}, "malformed": "accounts.example",
		"email only": map[string]any{"email": "invented-person@accounts.example"},
	} {
		t.Run(name, func(t *testing.T) {
			payload := agentmetryToolCall()
			payload["account"] = account
			delete(payload["initiator"].(map[string]any), "operator_source")
			out := applyAgentmetryJSON(t, payload)
			for _, path := range []string{"account", "operator_source", "detection", "heartbeat", "mcp_schema"} {
				if getNested(out, "finding.evidence.agentmetry."+path) != nil {
					t.Errorf("absent context %s was synthesized", path)
				}
			}
		})
	}
}

func TestAgentmetryContextRetainsRecorderCoverageWithoutPromotingIt(t *testing.T) {
	payload := agentmetryObservation("heartbeat", "degraded")
	payload["heartbeat"] = map[string]any{
		"interval_seconds": 300, "spool_depth": 0, "hook_profile": "user",
		"hooks":           map[string]any{"claude": false, "cursor": true},
		"hooks_uncovered": []any{"claude"}, "hooks_unverified": []any{"codex"},
		"hooks_silent": []any{}, "mcp_config_digest": "synthetic-config-digest",
		"mcp_schema_digest": "synthetic-schema-digest", "mcp_schema_servers": 0,
	}
	out := applyAgentmetryJSON(t, payload)
	heartbeat, _ := getNested(out, "finding.evidence.agentmetry.heartbeat").(map[string]any)
	if getNested(out, "finding.evidence.agentmetry.event_type") != "heartbeat" || out["status_detail"] != "degraded" {
		t.Error("heartbeat kind or degradation outcome was lost")
	}
	wantJSON, _ := json.Marshal(payload["heartbeat"])
	gotJSON, _ := json.Marshal(heartbeat)
	if string(gotJSON) != string(wantJSON) {
		t.Errorf("coverage facts changed: got %s, want %s", gotJSON, wantJSON)
	}
	if out["class_uid"] != float64(6003) || out["severity_id"] != float64(0) {
		t.Error("coverage evidence must remain routine activity until a downstream rule judges it")
	}
}

func TestAgentmetryContextDistinguishesChangedAndUnavailableSchemas(t *testing.T) {
	for _, status := range []string{"new", "same", "changed", "rebaselined", "unavailable"} {
		t.Run(status, func(t *testing.T) {
			outcome := "success"
			if status == "changed" || status == "unavailable" {
				outcome = status
			}
			payload := agentmetryObservation("mcp_schema", outcome)
			schema := map[string]any{"server_id": "synthetic-server", "status": status}
			if status != "unavailable" {
				schema["fingerprint"] = "synthetic-fingerprint"
				schema["tool_count"] = 0
				schema["server_version"] = "synthetic-version"
				schema["list_changed"] = false
			}
			if status == "changed" {
				schema["tools_changed"] = []any{"synthetic-tool-digest"}
				schema["tools_added"] = 0
				schema["tools_removed"] = 1
			}
			if status == "rebaselined" {
				schema["unverified_baseline"] = true
			}
			payload["mcp_schema"] = schema
			out := applyAgentmetryJSON(t, payload)
			wantJSON, _ := json.Marshal(schema)
			gotJSON, _ := json.Marshal(getNested(out, "finding.evidence.agentmetry.mcp_schema"))
			if string(gotJSON) != string(wantJSON) {
				t.Errorf("schema observation changed: got %s, want %s", gotJSON, wantJSON)
			}
			if getNested(out, "finding.evidence.agentmetry.event_type") != "mcp_schema" || out["status_detail"] != outcome {
				t.Error("schema kind or observed outcome was lost")
			}
			if out["class_uid"] != float64(6003) || out["severity_id"] != float64(0) {
				t.Error("schema observation was promoted without a downstream rule")
			}
		})
	}
}
