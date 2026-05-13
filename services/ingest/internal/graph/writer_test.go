package graph

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/neo4j/neo4j-go-driver/v5/neo4j"
)

// fakeDriver records every Cypher query the writer issues so we can assert
// the UNWIND / MERGE shape and the ordering. It satisfies the local Driver
// interface (not neo4j.DriverWithContext), which is the whole reason that
// interface exists in writer.go.
type fakeDriver struct {
	mu       sync.Mutex
	queries  []recordedQuery
	closed   bool
	failNext error
}

type recordedQuery struct {
	cypher string
	params map[string]any
}

func (f *fakeDriver) NewSession(_ context.Context, _ neo4j.SessionConfig) Session {
	return &fakeSession{drv: f}
}

func (f *fakeDriver) Close(_ context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.closed = true
	return nil
}

func (f *fakeDriver) VerifyConnectivity(_ context.Context) error { return nil }

func (f *fakeDriver) record(q recordedQuery) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.queries = append(f.queries, q)
}

type fakeSession struct{ drv *fakeDriver }

func (s *fakeSession) ExecuteWrite(ctx context.Context, work func(tx Transaction) (any, error)) (any, error) {
	tx := &fakeTx{drv: s.drv}
	return work(tx)
}

func (s *fakeSession) Close(_ context.Context) error { return nil }

type fakeTx struct{ drv *fakeDriver }

func (t *fakeTx) Run(_ context.Context, cypher string, params map[string]any) error {
	t.drv.record(recordedQuery{cypher: cypher, params: params})
	if t.drv.failNext != nil {
		err := t.drv.failNext
		t.drv.failNext = nil
		return err
	}
	return nil
}

// recordingPublisher counts how many envelopes the writer fans out.
type recordingPublisher struct {
	mu      sync.Mutex
	updates []GraphUpdate
}

func (r *recordingPublisher) PublishGraphUpdate(_ context.Context, u GraphUpdate) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.updates = append(r.updates, u)
	return nil
}

func (r *recordingPublisher) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.updates)
}

func newTestEvent() *Event {
	return &Event{
		EventID:  "evt-1",
		TenantID: "tenant-a",
		TS:       time.Date(2026, 5, 13, 10, 0, 0, 0, time.UTC),
		Nodes: []Node{
			{Label: NodeUser, NaturalKey: "user:tenant-a:alice", TenantID: "tenant-a", Properties: map[string]interface{}{"name": "alice"}},
			{Label: NodeResource, NaturalKey: "resource:tenant-a:arn:aws:s3:::secret", TenantID: "tenant-a", Properties: map[string]interface{}{"arn": "arn:aws:s3:::secret"}},
		},
		Edges: []Edge{
			{Type: RelOwns, FromLabel: NodeUser, FromKey: "user:tenant-a:alice", ToLabel: NodeResource, ToKey: "resource:tenant-a:arn:aws:s3:::secret"},
		},
	}
}

func TestFlushBatch_NodeAndEdgeUpserts(t *testing.T) {
	drv := &fakeDriver{}
	pub := &recordingPublisher{}
	w := newWriterFromDriver(drv, Config{
		BatchSize:     10,
		FlushInterval: 24 * time.Hour, // never auto-flush
		QueueSize:     16,
		Publisher:     pub,
	})
	defer w.Close()

	ev := newTestEvent()

	if err := w.FlushBatch(context.Background(), []*Event{ev}); err != nil {
		t.Fatalf("FlushBatch: %v", err)
	}

	drv.mu.Lock()
	defer drv.mu.Unlock()
	if len(drv.queries) != 3 {
		t.Fatalf("expected 3 queries (2 node labels + 1 edge), got %d", len(drv.queries))
	}

	// Order is sorted by NodeLabel/RelType — Resource comes before User.
	gotLabels := []string{}
	for _, q := range drv.queries {
		gotLabels = append(gotLabels, q.cypher)
	}
	if !contains(gotLabels[0], "MERGE (n:Resource") {
		t.Errorf("expected first query to upsert Resource, got %q", gotLabels[0])
	}
	if !contains(gotLabels[1], "MERGE (n:User") {
		t.Errorf("expected second query to upsert User, got %q", gotLabels[1])
	}
	if !contains(gotLabels[2], "[r:OWNS]") {
		t.Errorf("expected third query to MERGE OWNS rel, got %q", gotLabels[2])
	}

	// Each row in the node-upsert params should carry the v1.0 schema_version
	// and a props_hash.
	for _, q := range drv.queries[:2] {
		rows, ok := q.params["rows"].([]map[string]interface{})
		if !ok {
			t.Fatalf("rows param missing or wrong type: %T", q.params["rows"])
		}
		for _, r := range rows {
			props := r["props"].(map[string]interface{})
			if props["schema_version"] != SchemaVersion {
				t.Errorf("expected schema_version=%q in props, got %v", SchemaVersion, props["schema_version"])
			}
			if r["props_hash"] == "" {
				t.Errorf("expected non-empty props_hash")
			}
		}
	}

	// 2 node upserts + 1 edge upsert = 3 publish envelopes.
	if pub.count() != 3 {
		t.Errorf("expected 3 graph-update publishes, got %d", pub.count())
	}
}

func TestWriteEvent_Idempotent_NaturalKey(t *testing.T) {
	drv := &fakeDriver{}
	w := newWriterFromDriver(drv, Config{BatchSize: 10, FlushInterval: 24 * time.Hour, QueueSize: 16})
	defer w.Close()

	ev1 := newTestEvent()
	ev2 := newTestEvent() // same natural keys
	ev2.EventID = "evt-2"

	if err := w.FlushBatch(context.Background(), []*Event{ev1, ev2}); err != nil {
		t.Fatalf("FlushBatch: %v", err)
	}

	// Each label gets ONE UNWIND query carrying TWO rows — that's the whole
	// point of batching. We don't issue 2 separate Cypher statements per
	// natural key.
	drv.mu.Lock()
	defer drv.mu.Unlock()
	for _, q := range drv.queries {
		if rows, ok := q.params["rows"].([]map[string]interface{}); ok {
			// Both events project the same node natural keys, so each
			// label should see exactly 2 rows (one per event).
			if len(rows) != 2 && contains(q.cypher, "MERGE (n:") {
				t.Errorf("expected 2 rows per node-label batch, got %d for %q", len(rows), q.cypher)
			}
		}
	}
}

func TestFlushBatch_PartialFailureSurfaced(t *testing.T) {
	drv := &fakeDriver{failNext: errors.New("boom")}
	w := newWriterFromDriver(drv, Config{BatchSize: 10, FlushInterval: 24 * time.Hour, QueueSize: 16})
	defer w.Close()

	err := w.FlushBatch(context.Background(), []*Event{newTestEvent()})
	if err == nil {
		t.Fatal("expected error from FlushBatch when driver fails")
	}
}

func TestWriteEvent_DropsWhenQueueFull(t *testing.T) {
	drv := &fakeDriver{}
	// QueueSize 1 + huge flush interval so events accumulate.
	w := newWriterFromDriver(drv, Config{
		BatchSize:     1000,
		FlushInterval: 24 * time.Hour,
		QueueSize:     1,
	})
	defer w.Close()

	// Saturate.
	for i := 0; i < 100; i++ {
		_ = w.WriteEvent(context.Background(), newTestEvent())
	}

	stats := w.Stats()
	if stats.EventsAccepted == 0 {
		t.Errorf("expected at least one event accepted, got %d", stats.EventsAccepted)
	}
	if stats.EventsDropped == 0 {
		t.Errorf("expected at least one event dropped (queue size 1 + 100 writes), got %d", stats.EventsDropped)
	}
	if stats.EventsAccepted+stats.EventsDropped != 100 {
		t.Errorf("expected accepted+dropped=100, got %d", stats.EventsAccepted+stats.EventsDropped)
	}
}

// TestWriteEvent_NeverBlocksOnFailure asserts the T1.1 contract: a graph
// writer that's failing every flush MUST NOT block the caller. We simulate
// "Neo4j is wedged" by making the fake driver block forever, and we time
// out a WriteEvent call that should return immediately.
func TestWriteEvent_NeverBlocksOnFailure(t *testing.T) {
	drv := &blockingFakeDriver{}
	w := newWriterFromDriver(drv, Config{
		BatchSize:     1,
		FlushInterval: 1 * time.Millisecond,
		QueueSize:     2,
	})
	defer w.Close()

	// Hammer the writer. With a queue of 2 and a flush that hangs, after a
	// few writes the queue should be full and subsequent writes must drop
	// instead of blocking.
	done := make(chan struct{})
	go func() {
		for i := 0; i < 100; i++ {
			_ = w.WriteEvent(context.Background(), newTestEvent())
		}
		close(done)
	}()
	select {
	case <-done:
		// Good — writes returned promptly even though Neo4j is hung.
	case <-time.After(2 * time.Second):
		t.Fatal("WriteEvent blocked while flusher was hung — T1.1 contract violated")
	}
}

// blockingFakeDriver hangs in NewSession.ExecuteWrite to simulate a wedged
// Neo4j. The flusher goroutine will get stuck on the first batch but the
// writer's WriteEvent must keep returning (drop-and-metric).
type blockingFakeDriver struct{}

func (b *blockingFakeDriver) NewSession(_ context.Context, _ neo4j.SessionConfig) Session {
	return &blockingSession{}
}
func (b *blockingFakeDriver) Close(_ context.Context) error           { return nil }
func (b *blockingFakeDriver) VerifyConnectivity(_ context.Context) error { return nil }

type blockingSession struct{}

func (s *blockingSession) ExecuteWrite(ctx context.Context, _ func(Transaction) (any, error)) (any, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}
func (s *blockingSession) Close(_ context.Context) error { return nil }

// TestPublisher_PublishesEveryUpsert asserts the security.graph_updates
// guarantee: every node and every edge produces an envelope.
func TestPublisher_PublishesEveryUpsert(t *testing.T) {
	drv := &fakeDriver{}
	pub := &recordingPublisher{}
	w := newWriterFromDriver(drv, Config{
		BatchSize:     10,
		FlushInterval: 24 * time.Hour,
		QueueSize:     16,
		Publisher:     pub,
	})
	defer w.Close()

	ev := newTestEvent()
	if err := w.FlushBatch(context.Background(), []*Event{ev}); err != nil {
		t.Fatalf("FlushBatch: %v", err)
	}
	if pub.count() != len(ev.Nodes)+len(ev.Edges) {
		t.Errorf("expected %d publishes, got %d", len(ev.Nodes)+len(ev.Edges), pub.count())
	}
}

func TestSchemaVersion_Stamped(t *testing.T) {
	drv := &fakeDriver{}
	pub := &recordingPublisher{}
	w := newWriterFromDriver(drv, Config{BatchSize: 10, FlushInterval: 24 * time.Hour, QueueSize: 16, Publisher: pub})
	defer w.Close()

	if err := w.FlushBatch(context.Background(), []*Event{newTestEvent()}); err != nil {
		t.Fatalf("FlushBatch: %v", err)
	}
	pub.mu.Lock()
	defer pub.mu.Unlock()
	for _, u := range pub.updates {
		if u.SchemaVersion != SchemaVersion {
			t.Errorf("update %q missing schema_version: %+v", u.EntityID, u)
		}
	}
}

// Sanity check: exercise the close path twice — Close must be idempotent.
func TestClose_Idempotent(t *testing.T) {
	drv := &fakeDriver{}
	w := newWriterFromDriver(drv, Config{BatchSize: 1, FlushInterval: 1 * time.Millisecond, QueueSize: 1})
	if err := w.Close(); err != nil {
		t.Fatalf("first close: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("second close: %v", err)
	}
}

// Sanity check: stats are concurrency-safe under hot load.
func TestStats_Concurrent(t *testing.T) {
	drv := &fakeDriver{}
	w := newWriterFromDriver(drv, Config{BatchSize: 10, FlushInterval: 1 * time.Millisecond, QueueSize: 256})
	defer w.Close()

	var wg sync.WaitGroup
	var n atomic.Int64
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				_ = w.WriteEvent(context.Background(), newTestEvent())
				n.Add(1)
			}
		}()
	}
	wg.Wait()

	// We dispatched 500 writes; some accepted, some maybe dropped.
	stats := w.Stats()
	if int64(stats.EventsAccepted+stats.EventsDropped) != n.Load() {
		t.Errorf("accepted+dropped=%d, expected %d", stats.EventsAccepted+stats.EventsDropped, n.Load())
	}
}

func contains(s, sub string) bool {
	if len(sub) > len(s) {
		return false
	}
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
