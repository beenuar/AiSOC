package graph

import "testing"

func ocsfWithSession(session map[string]interface{}, extra map[string]interface{}) map[string]interface{} {
	activity := map[string]interface{}{
		"actor": map[string]interface{}{"kind": "human", "id": "alice@corp.example"},
	}
	if session != nil {
		activity["session"] = session
	}
	ocsf := map[string]interface{}{
		"time":     "2026-03-04T05:06:07Z",
		"metadata": map[string]interface{}{"product": map[string]interface{}{"name": "aws_cloudtrail"}},
		"activity": activity,
	}
	for k, v := range extra {
		ocsf[k] = v
	}
	return ocsf
}

func sessionNodes(ev *Event) []Node {
	var out []Node
	for _, n := range ev.Nodes {
		if n.Label == NodeSession {
			out = append(out, n)
		}
	}
	return out
}

func edgesOfType(ev *Event, t RelType) []Edge {
	var out []Edge
	for _, e := range ev.Edges {
		if e.Type == t {
			out = append(out, e)
		}
	}
	return out
}

func TestTheSessionNodeCarriesTheVendorsKeyAndItsStrength(t *testing.T) {
	ev := ExtractFromOCSF("evt-1", "tenant-1", "okta_system_log", ocsfWithSession(map[string]interface{}{
		"key":        "102bFs0Aq6VQ1qjqVqk",
		"key_kind":   "vendor_session",
		"key_source": "authenticationContext.externalSessionId",
		"id":         "9ad0f0a1-0000-5000-8000-000000000001",
		"principal":  "alice@corp.example",
	}, nil))
	if ev == nil {
		t.Fatal("no projection")
	}

	nodes := sessionNodes(ev)
	if len(nodes) != 1 {
		t.Fatalf("got %d session nodes, want 1", len(nodes))
	}
	node := nodes[0]
	if node.Properties["session_key"] != "102bFs0Aq6VQ1qjqVqk" {
		t.Fatalf("session_key: %v", node.Properties["session_key"])
	}
	if node.Properties["key_kind"] != "vendor_session" {
		t.Fatalf("key_kind must travel with the node, got %v", node.Properties["key_kind"])
	}
	if node.Properties["id"] != "9ad0f0a1-0000-5000-8000-000000000001" {
		t.Fatalf("the Postgres id must ride along so the two stores join: %v", node.Properties["id"])
	}
	if node.TenantID != "tenant-1" {
		t.Fatalf("tenant: %q", node.TenantID)
	}
}

// An event whose source names no session must produce no node. A session of
// one invented for every unattributable event makes "what else did this
// session touch" answerable with a number that means nothing.
func TestNoSessionBlockMeansNoSessionNode(t *testing.T) {
	ev := ExtractFromOCSF("evt-2", "tenant-1", "okta_system_log", ocsfWithSession(nil, nil))
	if ev != nil && len(sessionNodes(ev)) != 0 {
		t.Fatalf("invented %d session nodes from an event that has none", len(sessionNodes(ev)))
	}
}

func TestAnEmptyKeyIsNotMergedOntoOneNode(t *testing.T) {
	ev := ExtractFromOCSF("evt-3", "tenant-1", "okta_system_log", ocsfWithSession(map[string]interface{}{
		"key": "", "key_kind": "vendor_session",
	}, nil))
	if ev != nil && len(sessionNodes(ev)) != 0 {
		t.Fatal("an empty key produced a node; every such event would MERGE onto it")
	}
}

// The chain is the reason the session projection reaches into the AssumeRole
// response at all.
func TestTheIssuedSessionGetsItsOwnNodeAndTheChainEdge(t *testing.T) {
	ev := ExtractFromOCSF("evt-4", "tenant-1", "aws_security_hub", ocsfWithSession(map[string]interface{}{
		"key":      "AKIAPARENT0000000EXM",
		"key_kind": "vendor_credential",
		"issued": map[string]interface{}{
			"key":                      "ASIACHILD0000000EXMP",
			"key_source":               "responseElements.credentials.accessKeyId",
			"principal":                "arn:aws:sts::1:assumed-role/Deploy/build-471",
			"originating_human":        "alice@corp.example",
			"originating_human_source": "requestParameters.sourceIdentity",
		},
	}, nil))
	if ev == nil {
		t.Fatal("no projection")
	}

	if n := len(sessionNodes(ev)); n != 2 {
		t.Fatalf("got %d session nodes, want the caller's and the one it issued", n)
	}
	edges := edgesOfType(ev, RelIssuedSession)
	if len(edges) != 1 {
		t.Fatalf("got %d chain edges, want 1", len(edges))
	}
	if edges[0].FromKey != "aws_cloudtrail|AKIAPARENT0000000EXM" {
		t.Fatalf("chain starts at %q", edges[0].FromKey)
	}
	if edges[0].ToKey != "aws_cloudtrail|ASIACHILD0000000EXMP" {
		t.Fatalf("chain ends at %q", edges[0].ToKey)
	}
	// A chain built from a caller-chosen roleSessionName is weaker evidence
	// than one built from sourceIdentity, and the edge has to say which.
	if edges[0].Properties["link_source"] != "requestParameters.sourceIdentity" {
		t.Fatalf("link_source: %v", edges[0].Properties["link_source"])
	}

	var child Node
	for _, n := range sessionNodes(ev) {
		if n.NaturalKey == "aws_cloudtrail|ASIACHILD0000000EXMP" {
			child = n
		}
	}
	if child.Properties["originating_human"] != "alice@corp.example" {
		t.Fatalf("the person must land on the child, which is the only place it is knowable: %v", child.Properties)
	}
}

func TestACallThatIssuedItsOwnCredentialIsNotItsOwnParent(t *testing.T) {
	ev := ExtractFromOCSF("evt-5", "tenant-1", "aws_security_hub", ocsfWithSession(map[string]interface{}{
		"key": "ASIASAME00000000EXMP", "key_kind": "vendor_credential",
		"issued": map[string]interface{}{"key": "ASIASAME00000000EXMP"},
	}, nil))
	if ev == nil {
		t.Fatal("no projection")
	}
	if n := len(edgesOfType(ev, RelIssuedSession)); n != 0 {
		t.Fatalf("got %d self-edges, want 0", n)
	}
}

// The key is namespaced by source because an Okta session id and a GitHub
// token hash share no namespace, and a bare MERGE on the value alone would
// collide them.
func TestTheNaturalKeyIsNamespacedBySource(t *testing.T) {
	okta := ExtractFromOCSF("evt-6", "t", "okta_system_log", map[string]interface{}{
		"time":     "2026-03-04T05:06:07Z",
		"metadata": map[string]interface{}{"product": map[string]interface{}{"name": "okta"}},
		"activity": map[string]interface{}{"session": map[string]interface{}{"key": "shared", "key_kind": "vendor_session"}},
	})
	github := ExtractFromOCSF("evt-7", "t", "github_audit", map[string]interface{}{
		"time":     "2026-03-04T05:06:07Z",
		"metadata": map[string]interface{}{"product": map[string]interface{}{"name": "github"}},
		"activity": map[string]interface{}{"session": map[string]interface{}{"key": "shared", "key_kind": "vendor_credential"}},
	})
	if okta == nil || github == nil {
		t.Fatal("no projection")
	}
	if sessionNodes(okta)[0].NaturalKey == sessionNodes(github)[0].NaturalKey {
		t.Fatal("two sources sharing one identifier collided onto one node")
	}
}

// Every label and relationship this file emits has to be in the published
// vocabulary, or the schema-drift gate and the live database disagree.
func TestTheSessionVocabularyIsPublished(t *testing.T) {
	labels := map[NodeLabel]bool{}
	for _, l := range AllNodeLabels {
		labels[l] = true
	}
	if !labels[NodeSession] {
		t.Fatal("Session is not in AllNodeLabels")
	}
	rels := map[RelType]bool{}
	for _, r := range AllRelTypes {
		rels[r] = true
	}
	for _, r := range []RelType{RelOpenedSession, RelIssuedSession, RelSessionRaised} {
		if !rels[r] {
			t.Fatalf("%s is not in AllRelTypes", r)
		}
	}
}
