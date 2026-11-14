package graph

import (
	"os"
	"strings"
	"testing"
)

// The AI estate projection (depth plan 6.1).
//
// Every payload here is built from the field map in
// internal/normalizer/templates/ai-runtime.yaml rather than from the
// extractor's expectations: agent_id lands on actor.process.name,
// on_behalf_of on actor.user.name, server_name on resource.name.

func aiRuntimeEvent() map[string]interface{} {
	return map[string]interface{}{
		"class_uid":   float64(6003),
		"source_type": "ai-runtime",
		"actor": map[string]interface{}{
			"process": map[string]interface{}{"name": "agent-7f2", "path": "/usr/local/bin/claude"},
			"user":    map[string]interface{}{"name": "ada@example.com"},
		},
		"src_endpoint": map[string]interface{}{"hostname": "ada-mbp"},
		"metadata": map[string]interface{}{
			"product": map[string]interface{}{"feature": map[string]interface{}{"name": "claude-sonnet-4"}},
		},
		"resource": map[string]interface{}{"name": "github-mcp"},
	}
}

func findNode(ev *Event, label NodeLabel) *Node {
	for i := range ev.Nodes {
		if ev.Nodes[i].Label == label {
			return &ev.Nodes[i]
		}
	}
	return nil
}

func hasEdge(ev *Event, relType RelType, from, to NodeLabel) bool {
	for _, e := range ev.Edges {
		if e.Type == relType && e.FromLabel == from && e.ToLabel == to {
			return true
		}
	}
	return false
}

// agentmetryEvent is built from the field map in
// internal/normalizer/templates/agentmetry.yaml, the same way aiRuntimeEvent
// mirrors ai-runtime.yaml: agent.name lands on actor.process.name, actor.id
// on actor.user.name, host_id on src_endpoint.hostname.
func agentmetryEvent() map[string]interface{} {
	return map[string]interface{}{
		"class_uid":   float64(6003),
		"source_type": "agentmetry",
		"actor": map[string]interface{}{
			"process": map[string]interface{}{"name": "claude"},
			"user":    map[string]interface{}{"name": "dev_01"},
		},
		"src_endpoint": map[string]interface{}{"hostname": "dev-mbp-7.local"},
		"metadata": map[string]interface{}{
			"product": map[string]interface{}{"feature": map[string]interface{}{"name": "claude"}},
		},
	}
}

func TestAgentmetryEventProducesAnAssetLinkedToPersonAndDevice(t *testing.T) {
	// Discussion #1577: Agentmetry telemetry arrives through its inbox
	// template, and the AI-estate projection must see those coding agents
	// or the inventory stays blind to exactly the activity source the
	// template adds.
	ev := ExtractFromOCSF("evt-agt", "tenant-a", "inbox:agentmetry", agentmetryEvent())
	if ev == nil {
		t.Fatal("expected a graph projection, got nil")
	}
	asset := findNode(ev, NodeAIAsset)
	if asset == nil {
		t.Fatal("no AIAsset node emitted for an agentmetry event")
	}
	if got := asset.Properties["kind"]; got != "coding_agent" {
		t.Errorf("kind = %v, want coding_agent (claude is in the match table)", got)
	}
	if got := asset.Properties["vendor"]; got != "Anthropic" {
		t.Errorf("vendor = %v, want Anthropic", got)
	}
	if !hasEdge(ev, RelOperates, NodeUser, NodeAIAsset) {
		t.Error("no (:User)-[:OPERATES]->(:AIAsset) edge")
	}
	if !hasEdge(ev, RelHosts, NodeEndpoint, NodeAIAsset) {
		t.Error("no (:Endpoint)-[:HOSTS]->(:AIAsset) edge")
	}
}

func TestAIRuntimeEventProducesAnAssetLinkedToPersonAndDevice(t *testing.T) {
	ev := ExtractFromOCSF("evt-1", "tenant-a", "ai_gateway", aiRuntimeEvent())
	if ev == nil {
		t.Fatal("expected a graph projection, got nil")
	}
	asset := findNode(ev, NodeAIAsset)
	if asset == nil {
		t.Fatal("no AIAsset node emitted")
	}
	if got := asset.Properties["kind"]; got != "coding_agent" {
		t.Errorf("kind = %v, want coding_agent", got)
	}
	if got := asset.Properties["vendor"]; got != "Anthropic" {
		t.Errorf("vendor = %v, want Anthropic", got)
	}
	if got := asset.Properties["model"]; got != "claude-sonnet-4" {
		t.Errorf("model = %v, want claude-sonnet-4", got)
	}
	// The two links depth 6.1 asks for.
	if !hasEdge(ev, RelOperates, NodeUser, NodeAIAsset) {
		t.Error("no (:User)-[:OPERATES]->(:AIAsset) edge")
	}
	if !hasEdge(ev, RelHosts, NodeEndpoint, NodeAIAsset) {
		t.Error("no (:Endpoint)-[:HOSTS]->(:AIAsset) edge")
	}
}

func TestUnrecognisedAgentIsAnAIAppRatherThanACodingAgent(t *testing.T) {
	// The honest answer. Claiming a vendor we have no evidence for would put
	// a confident, wrong name on an inventory row somebody acts on.
	ocsf := aiRuntimeEvent()
	ocsf["actor"] = map[string]interface{}{
		"process": map[string]interface{}{"name": "svc-42", "path": "/opt/inhouse/summariser"},
	}
	ev := ExtractFromOCSF("evt-2", "tenant-a", "ai_gateway", ocsf)
	asset := findNode(ev, NodeAIAsset)
	if asset == nil {
		t.Fatal("no AIAsset node emitted")
	}
	if got := asset.Properties["kind"]; got != "ai_app" {
		t.Errorf("kind = %v, want ai_app", got)
	}
}

func TestAnAssetWithNoPersonEmitsNoOperatesEdge(t *testing.T) {
	// Absent rather than guessed: an unlinked agent is the finding, and an
	// edge to a placeholder user would hide it.
	ocsf := aiRuntimeEvent()
	ocsf["actor"] = map[string]interface{}{
		"process": map[string]interface{}{"name": "agent-7f2", "path": "/usr/local/bin/claude"},
	}
	ev := ExtractFromOCSF("evt-3", "tenant-a", "ai_gateway", ocsf)
	if hasEdge(ev, RelOperates, NodeUser, NodeAIAsset) {
		t.Error("emitted an OPERATES edge for an event that named no person")
	}
}

func TestProcessActivityFindsACodingAgentOnADevice(t *testing.T) {
	ocsf := map[string]interface{}{
		"class_uid":   float64(1007),
		"source_type": "crowdstrike_falcon",
		"process":     map[string]interface{}{"name": "C:\\Program Files\\aider\\Aider.exe"},
		"device":      map[string]interface{}{"name": "win-dev-02"},
	}
	ev := ExtractFromOCSF("evt-4", "tenant-a", "crowdstrike_falcon", ocsf)
	asset := findNode(ev, NodeAIAsset)
	if asset == nil {
		t.Fatal("no AIAsset node emitted from process activity")
	}
	if got := asset.Properties["external_id"]; got != "aider" {
		t.Errorf("external_id = %v, want aider (basename, lowercased, .exe stripped)", got)
	}
	if !hasEdge(ev, RelHosts, NodeEndpoint, NodeAIAsset) {
		t.Error("no HOSTS edge from the device")
	}
}

func TestOrdinaryProcessActivityIsNotAnAIAsset(t *testing.T) {
	// The negative control for the match table. A substring heuristic on
	// "agent" would put every EDR sensor on the AI inventory.
	for _, name := range []string{"falcon-sensor", "chrome", "osqueryd", "MsMpEng.exe"} {
		ocsf := map[string]interface{}{
			"class_uid": float64(1007),
			"process":   map[string]interface{}{"name": name},
			"device":    map[string]interface{}{"name": "win-dev-02"},
		}
		ev := ExtractFromOCSF("evt-5", "tenant-a", "crowdstrike_falcon", ocsf)
		if ev != nil && findNode(ev, NodeAIAsset) != nil {
			t.Errorf("%s was classified as an AI asset", name)
		}
	}
}

func TestANonProcessClassNamingAnAgentIsIgnored(t *testing.T) {
	// A file event naming a binary is not evidence the binary ran.
	ocsf := map[string]interface{}{
		"class_uid": float64(1001),
		"process":   map[string]interface{}{"name": "claude"},
		"device":    map[string]interface{}{"name": "win-dev-02"},
	}
	ev := ExtractFromOCSF("evt-6", "tenant-a", "crowdstrike_falcon", ocsf)
	if ev != nil && findNode(ev, NodeAIAsset) != nil {
		t.Error("a file-system event was classified as a running AI asset")
	}
}

func TestAIAssetIsInTheCanonicalLabelEnumeration(t *testing.T) {
	// Declared and never enumerated is drift a schema gate can miss: the
	// constant exists, the YAML lists it, and AllNodeLabels — the list every
	// consumer reads — does not.
	for _, l := range AllNodeLabels {
		if l == NodeAIAsset {
			return
		}
	}
	t.Error("NodeAIAsset is not in AllNodeLabels")
}

func TestAIAssetIsNotGlobal(t *testing.T) {
	// An agent is somebody's. A global label is exempted from tenant-scoped
	// reads and from an offboarding purge, both of which would be wrong here.
	for _, l := range GlobalNodeLabels {
		if l == NodeAIAsset {
			t.Fatal("AIAsset is listed as a global reference label; it is tenant-scoped")
		}
	}
}

func TestAIAgentVocabularyMatchesTheFusionRecorder(t *testing.T) {
	// Two services, one meaning, and neither can import the other. A mirror
	// nothing compares is two copies that will drift, so this reads the
	// Python file rather than trusting the comment that says they match.
	data, err := os.ReadFile("../../../fusion/app/services/ai_asset_recorder.py")
	if err != nil {
		t.Skipf("fusion recorder not readable from here: %v", err)
	}
	recorder := string(data)
	for name := range aiAgentProcesses {
		if !strings.Contains(recorder, "\""+name+"\"") {
			t.Errorf("%q is in the Go match table and not in CODING_AGENT_PROCESSES", name)
		}
	}
}
