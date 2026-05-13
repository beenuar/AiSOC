package graph

import (
	"testing"
	"time"
)

func TestExtractFromOCSF_AWS(t *testing.T) {
	ocsf := map[string]interface{}{
		"time":       "2026-05-13T10:00:00Z",
		"event_id":   "alert-123",
		"message":    "S3 bucket public",
		"severity":   "HIGH",
		"actor": map[string]interface{}{
			"user": map[string]interface{}{"name": "alice"},
		},
		"Resources": []interface{}{
			map[string]interface{}{
				"Id":     "arn:aws:s3:::secret-bucket",
				"Type":   "AwsS3Bucket",
				"Region": "us-east-1",
			},
		},
	}
	ev := ExtractFromOCSF("evt-1", "tenant-a", "aws_security_hub", ocsf)
	if ev == nil {
		t.Fatal("expected non-nil event")
	}

	hasUser, hasResource, hasAlert := false, false, false
	for _, n := range ev.Nodes {
		switch n.Label {
		case NodeUser:
			hasUser = true
			if n.NaturalKey != "user:tenant-a:alice" {
				t.Errorf("unexpected user key: %s", n.NaturalKey)
			}
		case NodeResource:
			hasResource = true
			if n.NaturalKey != "resource:tenant-a:arn:aws:s3:::secret-bucket" {
				t.Errorf("unexpected resource key: %s", n.NaturalKey)
			}
		case NodeAlert:
			hasAlert = true
		}
	}
	if !hasUser || !hasResource || !hasAlert {
		t.Errorf("missing nodes: user=%v resource=%v alert=%v", hasUser, hasResource, hasAlert)
	}

	hasOwns, hasOccurredOn := false, false
	for _, e := range ev.Edges {
		if e.Type == RelOwns {
			hasOwns = true
		}
		if e.Type == RelOccurredOn {
			hasOccurredOn = true
		}
	}
	if !hasOwns {
		t.Error("expected :OWNS edge from User to Resource")
	}
	if !hasOccurredOn {
		t.Error("expected :OCCURRED_ON edge from Alert to Resource")
	}
}

func TestExtractFromOCSF_GitHub(t *testing.T) {
	ocsf := map[string]interface{}{
		"time": "2026-05-13T10:00:00Z",
		"actor": map[string]interface{}{
			"user": map[string]interface{}{"name": "carol"},
		},
		"repo": map[string]interface{}{
			"full_name": "aisoc/aisoc",
		},
		"action": "push",
	}
	ev := ExtractFromOCSF("evt-2", "tenant-a", "github_audit", ocsf)
	if ev == nil {
		t.Fatal("expected non-nil event")
	}

	var foundWritesEdge bool
	for _, e := range ev.Edges {
		if e.Type == RelWritesTo && e.FromLabel == NodeUser && e.ToLabel == NodeRepo {
			foundWritesEdge = true
		}
	}
	if !foundWritesEdge {
		t.Error("expected :WRITES_TO edge for push action")
	}

	// 'view' verbs go to :READS_FROM.
	ocsf["action"] = "read"
	ev2 := ExtractFromOCSF("evt-3", "tenant-a", "github_audit", ocsf)
	var readsEdge bool
	for _, e := range ev2.Edges {
		if e.Type == RelReadsFrom {
			readsEdge = true
		}
	}
	if !readsEdge {
		t.Error("expected :READS_FROM edge for non-mutating action")
	}
}

func TestExtractFromOCSF_Okta(t *testing.T) {
	ocsf := map[string]interface{}{
		"time": "2026-05-13T10:00:00Z",
		"actor": map[string]interface{}{
			"id": "00uabc",
			"user": map[string]interface{}{
				"name":       "bob",
				"email_addr": "bob@example.com",
			},
		},
		"src_endpoint": map[string]interface{}{"ip": "192.0.2.10"},
		"target": map[string]interface{}{
			"app": map[string]interface{}{"name": "Slack"},
		},
	}
	ev := ExtractFromOCSF("evt-4", "tenant-a", "okta_system_log", ocsf)
	if ev == nil {
		t.Fatal("expected non-nil event")
	}

	hasIdentity, hasUser, hasNet, hasApp := false, false, false, false
	for _, n := range ev.Nodes {
		switch n.Label {
		case NodeIdentity:
			hasIdentity = true
		case NodeUser:
			hasUser = true
		case NodeNetworkPath:
			hasNet = true
		case NodeSaaSApp:
			hasApp = true
		}
	}
	if !hasIdentity || !hasUser || !hasNet || !hasApp {
		t.Errorf("missing nodes: identity=%v user=%v net=%v app=%v", hasIdentity, hasUser, hasNet, hasApp)
	}

	var assumedBy bool
	for _, e := range ev.Edges {
		if e.Type == RelAssumedBy {
			assumedBy = true
		}
	}
	if !assumedBy {
		t.Error("expected :ASSUMED_BY edge from Identity to User")
	}
}

func TestExtractFromOCSF_Kubernetes_ServiceAccount(t *testing.T) {
	ocsf := map[string]interface{}{
		"time": "2026-05-13T10:00:00Z",
		"actor": map[string]interface{}{
			"user": map[string]interface{}{"name": "system:serviceaccount:kube-system:default"},
		},
		"activity_name": "create",
		"finding": map[string]interface{}{
			"title": "pods",
		},
		"resource": map[string]interface{}{
			"name": "nginx-7b4c",
		},
		"cloud": map[string]interface{}{
			"account": map[string]interface{}{"uid": "default"},
		},
	}
	ev := ExtractFromOCSF("evt-5", "tenant-a", "kubernetes_audit", ocsf)
	if ev == nil {
		t.Fatal("expected non-nil event")
	}

	var sa bool
	for _, n := range ev.Nodes {
		if n.Label == NodeServiceAccount {
			sa = true
		}
	}
	if !sa {
		t.Error("expected ServiceAccount node for system:serviceaccount: actor")
	}

	var accesses bool
	for _, e := range ev.Edges {
		if e.Type == RelAccesses && e.Properties["verb"] == "create" {
			accesses = true
		}
	}
	if !accesses {
		t.Error("expected :ACCESSES edge with verb=create")
	}
}

func TestExtractFromOCSF_MITRE(t *testing.T) {
	ocsf := map[string]interface{}{
		"time": "2026-05-13T10:00:00Z",
		"actor": map[string]interface{}{
			"user": map[string]interface{}{"name": "alice"},
		},
		"mitre_attck": []interface{}{
			map[string]interface{}{
				"technique_id":   "T1078",
				"technique_name": "Valid Accounts",
				"url":            "https://attack.mitre.org/techniques/T1078/",
			},
		},
	}
	ev := ExtractFromOCSF("evt-6", "tenant-a", "okta_system_log", ocsf)
	if ev == nil {
		t.Fatal("expected non-nil event")
	}

	var det bool
	for _, n := range ev.Nodes {
		if n.Label == NodeDetection && n.NaturalKey == "detection:mitre:T1078" {
			det = true
		}
	}
	if !det {
		t.Error("expected :Detection node for T1078")
	}

	var triggered bool
	for _, e := range ev.Edges {
		if e.Type == RelTriggered && e.ToKey == "detection:mitre:T1078" {
			triggered = true
		}
	}
	if !triggered {
		t.Error("expected :TRIGGERED edge to Detection node")
	}
}

func TestExtractFromOCSF_GenericFallback(t *testing.T) {
	// Unknown connector type — generic path should still pull actor + endpoints.
	ocsf := map[string]interface{}{
		"time": "2026-05-13T10:00:00Z",
		"actor": map[string]interface{}{
			"user": map[string]interface{}{"name": "dave"},
		},
		"src_endpoint": map[string]interface{}{"ip": "10.0.0.1"},
		"dst_endpoint": map[string]interface{}{"ip": "10.0.0.2"},
	}
	ev := ExtractFromOCSF("evt-7", "tenant-a", "some_unknown_connector", ocsf)
	if ev == nil {
		t.Fatal("expected non-nil event from generic fallback")
	}
	want := map[NodeLabel]bool{
		NodeUser:        false,
		NodeNetworkPath: false,
	}
	for _, n := range ev.Nodes {
		if _, ok := want[n.Label]; ok {
			want[n.Label] = true
		}
	}
	for k, v := range want {
		if !v {
			t.Errorf("expected %s node from generic fallback", k)
		}
	}
}

func TestExtractFromOCSF_NilSafe(t *testing.T) {
	if ev := ExtractFromOCSF("e", "t", "anything", nil); ev != nil {
		t.Errorf("expected nil for nil ocsf, got %+v", ev)
	}
	if ev := ExtractFromOCSF("e", "t", "anything", map[string]interface{}{}); ev != nil {
		t.Errorf("expected nil for empty ocsf, got %+v", ev)
	}
}

func TestExtractFromOCSF_TimeFallback(t *testing.T) {
	// Missing time should fall back to "now"-ish.
	ocsf := map[string]interface{}{
		"actor": map[string]interface{}{"user": map[string]interface{}{"name": "eve"}},
	}
	ev := ExtractFromOCSF("e", "t", "okta_system_log", ocsf)
	if ev == nil {
		t.Fatal("expected non-nil event")
	}
	if ev.TS.IsZero() {
		t.Error("expected event TS to fall back to time.Now() when time field missing")
	}
	if time.Since(ev.TS) > time.Minute {
		t.Errorf("fallback TS too old: %v", ev.TS)
	}
}
