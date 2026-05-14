// snapshotter_test.go — fixture-driven tests for T1.2.
//
// Coverage:
//
//   - StaticProvider returns the time-correct config from a history
//   - Apply() attaches :Configuration node + :CONFIGURED_AS edge for a
//     :Resource node, and the edge carries the {ts, source_event_id}
//     properties the T1.2 contract demands.
//   - Cache hit short-circuits the provider — the second event for the
//     same hot resource doesn't re-fetch.
//   - ErrNotImplemented from the provider is a soft skip, NOT a graph
//     mutation failure.
//   - Provider errors increment the error counter but DO NOT stall the
//     event (the rest of the projection still flushes).
//   - The aws_config_history.json fixture round-trips via StaticProvider
//     and produces the (:Alert)-[:OCCURRED_ON]->(:Resource)-[:CONFIGURED_AS]->(:Configuration)
//     path the v8.0 plan requires.
package config_snapshot

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/beenuar/aisoc/services/ingest/internal/graph"
)

// helper: build a minimal :Resource event the snapshotter can chew on.
func newAWSEvent(ts time.Time, arn string) *graph.Event {
	return &graph.Event{
		EventID:  "evt-1",
		TenantID: "tenant-1",
		TS:       ts,
		Nodes: []graph.Node{
			{
				Label:      graph.NodeAlert,
				NaturalKey: "alert:tenant-1:alert-1",
				TenantID:   "tenant-1",
				Properties: map[string]interface{}{"title": "S3 bucket is public"},
			},
			{
				Label:      graph.NodeResource,
				NaturalKey: "resource:tenant-1:" + arn,
				TenantID:   "tenant-1",
				Properties: map[string]interface{}{
					"arn":      arn,
					"provider": "aws_security_hub",
				},
			},
		},
		Edges: []graph.Edge{
			{
				Type:      graph.RelOccurredOn,
				FromLabel: graph.NodeAlert, FromKey: "alert:tenant-1:alert-1",
				ToLabel: graph.NodeResource, ToKey: "resource:tenant-1:" + arn,
			},
		},
	}
}

func mustParseTime(t *testing.T, s string) time.Time {
	t.Helper()
	ts, err := time.Parse(time.RFC3339, s)
	if err != nil {
		t.Fatalf("parse %q: %v", s, err)
	}
	return ts
}

// ---------------------------------------------------------------------------
// StaticProvider history selection
// ---------------------------------------------------------------------------

func TestStaticProvider_ReturnsConfigAtOrBeforeTimestamp(t *testing.T) {
	t1 := mustParseTime(t, "2026-05-01T10:00:00Z")
	t2 := mustParseTime(t, "2026-05-01T12:00:00Z")
	p := NewStaticProvider(map[string]map[string][]ConfigSnapshot{
		"aws_security_hub": {
			"arn:aws:s3:::demo": {
				{Recorded: t1, Data: map[string]interface{}{"public": false}},
				{Recorded: t2, Data: map[string]interface{}{"public": true}},
			},
		},
	})

	// Before any history → falls back to earliest.
	cfg, err := p.GetResourceConfig(context.Background(), "aws_security_hub", "arn:aws:s3:::demo", t1.Add(-time.Hour))
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if cfg["public"] != false {
		t.Fatalf("pre-history fallback wrong: %v", cfg)
	}

	// Between → return earlier snapshot (most recent at-or-before).
	cfg, err = p.GetResourceConfig(context.Background(), "aws_security_hub", "arn:aws:s3:::demo", t1.Add(time.Hour))
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if cfg["public"] != false {
		t.Fatalf("between-history wrong: %v", cfg)
	}

	// After → return latest snapshot.
	cfg, err = p.GetResourceConfig(context.Background(), "aws_security_hub", "arn:aws:s3:::demo", t2.Add(time.Hour))
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if cfg["public"] != true {
		t.Fatalf("post-history wrong: %v", cfg)
	}

	// Unknown connector / resource → ErrNotImplemented.
	if _, err := p.GetResourceConfig(context.Background(), "github", "x", t1); !errors.Is(err, ErrNotImplemented) {
		t.Fatalf("expected ErrNotImplemented, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// Apply() attaches Configuration + CONFIGURED_AS
// ---------------------------------------------------------------------------

func TestApply_AttachesConfigurationAndEdge(t *testing.T) {
	ts := mustParseTime(t, "2026-05-01T13:00:00Z")
	provider := NewStaticProvider(map[string]map[string][]ConfigSnapshot{
		"aws_security_hub": {
			"arn:aws:s3:::demo": {
				{Recorded: ts.Add(-time.Hour), Data: map[string]interface{}{"public": true, "owner": "alice"}},
			},
		},
	})
	s, err := New(Config{Provider: provider, TTL: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	ev := newAWSEvent(ts, "arn:aws:s3:::demo")
	beforeNodeCount := len(ev.Nodes)
	beforeEdgeCount := len(ev.Edges)

	s.Apply(context.Background(), ev)

	// One Configuration node added.
	var cfgNode *graph.Node
	for i := range ev.Nodes {
		if ev.Nodes[i].Label == graph.NodeConfiguration {
			cfgNode = &ev.Nodes[i]
			break
		}
	}
	if cfgNode == nil {
		t.Fatalf("Apply did not append :Configuration node; nodes=%v", ev.Nodes)
	}
	if got := cfgNode.Properties["resource_id"]; got != "arn:aws:s3:::demo" {
		t.Fatalf("resource_id wrong: %v", got)
	}
	cfgPayload, ok := cfgNode.Properties["config"].(map[string]interface{})
	if !ok {
		t.Fatalf("config payload not a map: %T", cfgNode.Properties["config"])
	}
	if cfgPayload["public"] != true {
		t.Fatalf("config payload wrong: %v", cfgPayload)
	}

	// One CONFIGURED_AS edge added with the right shape.
	var rel *graph.Edge
	for i := range ev.Edges {
		if ev.Edges[i].Type == graph.RelConfiguredAs {
			rel = &ev.Edges[i]
			break
		}
	}
	if rel == nil {
		t.Fatalf("Apply did not append :CONFIGURED_AS edge")
	}
	if rel.FromLabel != graph.NodeResource {
		t.Fatalf("CONFIGURED_AS from wrong label: %s", rel.FromLabel)
	}
	if rel.ToLabel != graph.NodeConfiguration {
		t.Fatalf("CONFIGURED_AS to wrong label: %s", rel.ToLabel)
	}
	if rel.Properties["ts"] == "" {
		t.Fatalf("CONFIGURED_AS edge missing ts")
	}

	// SnapshotID populated for downstream dedupe.
	if ev.SnapshotID == "" {
		t.Fatalf("SnapshotID not set after Apply")
	}

	// Counters reflect the work done.
	stats := s.Stats()
	if stats.Misses != 1 || stats.Attached != 1 {
		t.Fatalf("stats wrong: %+v", stats)
	}

	if len(ev.Nodes) != beforeNodeCount+1 || len(ev.Edges) != beforeEdgeCount+1 {
		t.Fatalf("expected exactly +1 node and +1 edge: nodes %d→%d edges %d→%d",
			beforeNodeCount, len(ev.Nodes), beforeEdgeCount, len(ev.Edges))
	}
}

// ---------------------------------------------------------------------------
// Cache short-circuits the provider on the second hit
// ---------------------------------------------------------------------------

type countingProvider struct {
	inner Provider
	calls int
}

func (c *countingProvider) GetResourceConfig(ctx context.Context, connectorID, resourceID string, ts time.Time) (map[string]interface{}, error) {
	c.calls++
	return c.inner.GetResourceConfig(ctx, connectorID, resourceID, ts)
}

func TestApply_CacheHitSkipsProvider(t *testing.T) {
	ts := mustParseTime(t, "2026-05-01T14:00:00Z")
	inner := NewStaticProvider(map[string]map[string][]ConfigSnapshot{
		"aws_security_hub": {
			"arn:aws:s3:::demo": {{Recorded: ts.Add(-time.Hour), Data: map[string]interface{}{"public": true}}},
		},
	})
	counter := &countingProvider{inner: inner}
	s, err := New(Config{Provider: counter, Cache: NewMemoryCache(time.Minute), TTL: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	for i := 0; i < 3; i++ {
		ev := newAWSEvent(ts, "arn:aws:s3:::demo")
		s.Apply(context.Background(), ev)
	}

	if counter.calls != 1 {
		t.Fatalf("expected exactly 1 provider call (cache should hit twice), got %d", counter.calls)
	}
	stats := s.Stats()
	if stats.Hits < 2 {
		t.Fatalf("expected at least 2 cache hits: %+v", stats)
	}
}

// ---------------------------------------------------------------------------
// ErrNotImplemented is a soft skip — no graph mutation, no error counter
// ---------------------------------------------------------------------------

func TestApply_NotImplementedIsSoftSkip(t *testing.T) {
	ts := mustParseTime(t, "2026-05-01T15:00:00Z")
	s, err := New(Config{Provider: NoopProvider{}, TTL: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	ev := newAWSEvent(ts, "arn:aws:s3:::demo")
	beforeNodes := len(ev.Nodes)
	s.Apply(context.Background(), ev)
	if len(ev.Nodes) != beforeNodes {
		t.Fatalf("NoopProvider should NOT mutate event; nodes %d→%d", beforeNodes, len(ev.Nodes))
	}
	stats := s.Stats()
	if stats.Errors != 0 {
		t.Fatalf("NoopProvider should NOT increment error counter: %+v", stats)
	}
	if stats.Skipped == 0 {
		t.Fatalf("NoopProvider should bump skipped counter: %+v", stats)
	}
}

// ---------------------------------------------------------------------------
// Hard provider errors are isolated — graph projection still flushes
// ---------------------------------------------------------------------------

type errorProvider struct{}

func (errorProvider) GetResourceConfig(_ context.Context, _, _ string, _ time.Time) (map[string]interface{}, error) {
	return nil, errors.New("simulated downstream outage")
}

func TestApply_ProviderErrorIsIsolated(t *testing.T) {
	ts := mustParseTime(t, "2026-05-01T16:00:00Z")
	s, err := New(Config{Provider: errorProvider{}, TTL: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	ev := newAWSEvent(ts, "arn:aws:s3:::demo")
	beforeEdges := len(ev.Edges)
	beforeNodes := len(ev.Nodes)
	s.Apply(context.Background(), ev)
	if len(ev.Edges) != beforeEdges {
		t.Fatalf("provider error must NOT add edges")
	}
	if len(ev.Nodes) != beforeNodes {
		t.Fatalf("provider error must NOT add nodes")
	}
	if s.Stats().Errors != 1 {
		t.Fatalf("expected error counter == 1: %+v", s.Stats())
	}
}

// ---------------------------------------------------------------------------
// AWS Config history fixture → full Cypher path
// ---------------------------------------------------------------------------

// awsConfigHistory mirrors the JSON fixture format we ship in
// services/ingest/test_data/aws_config_history.json. Loading the fixture
// here exercises the same path operators will use for fixture-driven tests
// of their own connectors.
type awsConfigHistory struct {
	ConnectorID string                     `json:"connector_id"`
	Resources   map[string][]configHistory `json:"resources"`
}

type configHistory struct {
	Recorded string                 `json:"recorded"`
	Config   map[string]interface{} `json:"config"`
}

func loadAWSConfigHistoryFixture(t *testing.T) *StaticProvider {
	t.Helper()
	root, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	// services/ingest/internal/config_snapshot/ → walk up two dirs.
	path := filepath.Join(root, "..", "..", "test_data", "aws_config_history.json")
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read fixture %s: %v", path, err)
	}
	var hist awsConfigHistory
	if err := json.Unmarshal(b, &hist); err != nil {
		t.Fatalf("parse fixture: %v", err)
	}
	configs := map[string]map[string][]ConfigSnapshot{
		hist.ConnectorID: {},
	}
	for resourceID, history := range hist.Resources {
		entries := make([]ConfigSnapshot, 0, len(history))
		for _, h := range history {
			ts, err := time.Parse(time.RFC3339, h.Recorded)
			if err != nil {
				t.Fatalf("parse fixture ts %q: %v", h.Recorded, err)
			}
			entries = append(entries, ConfigSnapshot{Recorded: ts, Data: h.Config})
		}
		configs[hist.ConnectorID][resourceID] = entries
	}
	return NewStaticProvider(configs)
}

// TestAWSConfigHistory_FullCypherPath asserts the full T1.2 contract:
//
//	(:Alert)-[:OCCURRED_ON]->(:Resource)-[:CONFIGURED_AS {ts}]->(:Configuration)
//
// returns the *config that was effective at alert timestamp*, not the
// current config. This is the "S3 was public for 90 seconds before the
// exfil, even though it isn't anymore" story the v8.0 plan calls out.
func TestAWSConfigHistory_FullCypherPath(t *testing.T) {
	provider := loadAWSConfigHistoryFixture(t)
	s, err := New(Config{Provider: provider, TTL: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	// Alert timestamp is exactly between two recorded snapshots — the
	// snapshotter must return the *earlier* one (it was the live config
	// at alert time).
	alertTime := mustParseTime(t, "2026-04-15T10:30:00Z")
	ev := newAWSEvent(alertTime, "arn:aws:s3:::aisoc-demo-bucket")

	s.Apply(context.Background(), ev)

	// Walk the path: Alert -> OCCURRED_ON -> Resource -> CONFIGURED_AS -> Configuration
	var alertKey, resourceKey, configKey string
	for _, n := range ev.Nodes {
		switch n.Label {
		case graph.NodeAlert:
			alertKey = n.NaturalKey
		case graph.NodeResource:
			resourceKey = n.NaturalKey
		case graph.NodeConfiguration:
			configKey = n.NaturalKey
		}
	}
	if alertKey == "" || resourceKey == "" || configKey == "" {
		t.Fatalf("missing expected nodes: alert=%q resource=%q config=%q", alertKey, resourceKey, configKey)
	}

	hasOccurredOn := false
	hasConfiguredAs := false
	for _, e := range ev.Edges {
		if e.Type == graph.RelOccurredOn && e.FromKey == alertKey && e.ToKey == resourceKey {
			hasOccurredOn = true
		}
		if e.Type == graph.RelConfiguredAs && e.FromKey == resourceKey && e.ToKey == configKey {
			hasConfiguredAs = true
			if e.Properties["ts"] == "" {
				t.Fatalf("CONFIGURED_AS edge missing ts property")
			}
		}
	}
	if !hasOccurredOn {
		t.Fatalf("missing :OCCURRED_ON edge between alert and resource")
	}
	if !hasConfiguredAs {
		t.Fatalf("missing :CONFIGURED_AS edge between resource and config")
	}

	// Verify the *content* — the public=true / owner=alice snapshot is
	// the one effective at 10:30Z (recorded 10:00Z); the public=false
	// snapshot at 12:00Z is in the future and must NOT be selected.
	for _, n := range ev.Nodes {
		if n.Label != graph.NodeConfiguration {
			continue
		}
		cfg, ok := n.Properties["config"].(map[string]interface{})
		if !ok {
			t.Fatalf("config payload missing")
		}
		if cfg["public"] != true {
			t.Fatalf("expected at-time config public=true, got %v", cfg["public"])
		}
		if cfg["owner"] != "alice" {
			t.Fatalf("expected at-time config owner=alice, got %v", cfg["owner"])
		}
	}
}

// ---------------------------------------------------------------------------
// CacheKey TTL bucketing
// ---------------------------------------------------------------------------

func TestCacheKey_BucketsByTTL(t *testing.T) {
	t1 := mustParseTime(t, "2026-05-01T10:00:00Z")
	t2 := mustParseTime(t, "2026-05-01T10:00:30Z") // 30s later, same bucket
	t3 := mustParseTime(t, "2026-05-01T10:05:00Z") // > 1m TTL → new bucket

	if a, b := CacheKey("aws", "x", t1, time.Minute), CacheKey("aws", "x", t2, time.Minute); a != b {
		t.Fatalf("same bucket should produce same key:\n  %s\n  %s", a, b)
	}
	if a, b := CacheKey("aws", "x", t1, time.Minute), CacheKey("aws", "x", t3, time.Minute); a == b {
		t.Fatalf("different bucket should produce different key, got identical: %s", a)
	}
}
