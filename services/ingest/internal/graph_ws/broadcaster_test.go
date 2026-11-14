// Tests for the graph_ws Broadcaster (T1.4 — v8.0).
package graph_ws

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/beenuar/aisoc/services/ingest/internal/graph"
)

// fakeSource is a deterministic EnvelopeSource backed by a buffered
// channel. The constructor pre-loads N envelopes; Next drains them
// in order and then blocks until ctx is cancelled.
type fakeSource struct {
	ch     chan graph.GraphUpdate
	closed chan struct{}
	once   sync.Once
}

func newFakeSource(envs []graph.GraphUpdate) *fakeSource {
	ch := make(chan graph.GraphUpdate, len(envs))
	for _, e := range envs {
		ch <- e
	}
	return &fakeSource{ch: ch, closed: make(chan struct{})}
}

func (f *fakeSource) Next(ctx context.Context) (graph.GraphUpdate, error) {
	select {
	case e, ok := <-f.ch:
		if !ok {
			return graph.GraphUpdate{}, fmt.Errorf("source drained")
		}
		return e, nil
	case <-ctx.Done():
		return graph.GraphUpdate{}, ctx.Err()
	case <-f.closed:
		return graph.GraphUpdate{}, fmt.Errorf("source closed")
	}
}

func (f *fakeSource) Close() error {
	f.once.Do(func() { close(f.closed) })
	return nil
}

// TestBroadcasterDelivers100EventsWithinOneSecond is the gate the
// T1.4 spec calls out: 100 envelopes pushed into a fake Kafka
// consumer must all reach a connected subscriber within 1s.
func TestBroadcasterDelivers100EventsWithinOneSecond(t *testing.T) {
	const eventCount = 100
	envs := make([]graph.GraphUpdate, 0, eventCount)
	for i := 0; i < eventCount; i++ {
		envs = append(envs, graph.GraphUpdate{
			EntityID:      fmt.Sprintf("entity-%d", i),
			ChangeType:    graph.ChangeUpsertNode,
			TS:            time.Now(),
			Label:         graph.NodeAlert,
			TenantID:      "tenant-A",
			SchemaVersion: graph.SchemaVersion,
		})
	}
	src := newFakeSource(envs)
	b := New(src, Options{BufferSize: eventCount * 2})

	sub := b.Subscribe("tenant-A")
	defer b.Unsubscribe(sub)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	b.Start(ctx)
	defer b.Stop()

	deadline := time.Now().Add(1 * time.Second)
	received := 0
	seen := make(map[string]struct{}, eventCount)
	for received < eventCount {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			t.Fatalf("only received %d/%d envelopes before 1s deadline", received, eventCount)
		}
		select {
		case env := <-sub.Updates:
			if _, dup := seen[env.EntityID]; dup {
				t.Fatalf("duplicate envelope for entity %s", env.EntityID)
			}
			seen[env.EntityID] = struct{}{}
			received++
		case <-time.After(remaining):
			t.Fatalf("only received %d/%d envelopes before 1s deadline", received, eventCount)
		}
	}

	if received != eventCount {
		t.Fatalf("expected %d envelopes, got %d", eventCount, received)
	}
	if dropped := b.DroppedDeliveries(); dropped != 0 {
		t.Fatalf("expected zero drops with a healthy subscriber, got %d", dropped)
	}
}

// TestBroadcasterTenantScope confirms a subscriber pinned to a
// tenant does not see other tenants' envelopes.
func TestBroadcasterTenantScope(t *testing.T) {
	envs := []graph.GraphUpdate{
		{EntityID: "e-A1", TenantID: "tenant-A", ChangeType: graph.ChangeUpsertNode, SchemaVersion: graph.SchemaVersion},
		{EntityID: "e-B1", TenantID: "tenant-B", ChangeType: graph.ChangeUpsertNode, SchemaVersion: graph.SchemaVersion},
		{EntityID: "e-A2", TenantID: "tenant-A", ChangeType: graph.ChangeUpsertNode, SchemaVersion: graph.SchemaVersion},
		{EntityID: "e-B2", TenantID: "tenant-B", ChangeType: graph.ChangeUpsertNode, SchemaVersion: graph.SchemaVersion},
	}
	src := newFakeSource(envs)
	b := New(src, Options{})
	subA := b.Subscribe("tenant-A")
	defer b.Unsubscribe(subA)
	subB := b.Subscribe("tenant-B")
	defer b.Unsubscribe(subB)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	b.Start(ctx)
	defer b.Stop()

	collect := func(ch <-chan graph.GraphUpdate, want int) []graph.GraphUpdate {
		t.Helper()
		out := make([]graph.GraphUpdate, 0, want)
		deadline := time.After(500 * time.Millisecond)
		for len(out) < want {
			select {
			case env := <-ch:
				out = append(out, env)
			case <-deadline:
				t.Fatalf("only got %d/%d envelopes", len(out), want)
			}
		}
		return out
	}

	gotA := collect(subA.Updates, 2)
	gotB := collect(subB.Updates, 2)
	for _, e := range gotA {
		if e.TenantID != "tenant-A" {
			t.Fatalf("subA leaked envelope from %s", e.TenantID)
		}
	}
	for _, e := range gotB {
		if e.TenantID != "tenant-B" {
			t.Fatalf("subB leaked envelope from %s", e.TenantID)
		}
	}
}

// TestBroadcasterBackpressureDropsForSlowClient confirms a slow
// subscriber records drops but never blocks the consumer loop or
// other (healthy) subscribers.
func TestBroadcasterBackpressureDropsForSlowClient(t *testing.T) {
	const eventCount = 50
	envs := make([]graph.GraphUpdate, 0, eventCount)
	for i := 0; i < eventCount; i++ {
		envs = append(envs, graph.GraphUpdate{
			EntityID:      fmt.Sprintf("entity-%d", i),
			TenantID:      "tenant-A",
			ChangeType:    graph.ChangeUpsertNode,
			SchemaVersion: graph.SchemaVersion,
		})
	}
	src := newFakeSource(envs)
	b := New(src, Options{})

	slow := b.SubscribeWithBuffer("tenant-A", 4)
	healthy := b.SubscribeWithBuffer("tenant-A", eventCount*2)
	defer b.Unsubscribe(slow)
	defer b.Unsubscribe(healthy)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	b.Start(ctx)
	defer b.Stop()

	deadline := time.After(1 * time.Second)
	received := 0
	for received < eventCount {
		select {
		case <-healthy.Updates:
			received++
		case <-deadline:
			t.Fatalf("healthy subscriber received only %d/%d envelopes", received, eventCount)
		}
	}
	if dropped := b.DroppedDeliveries(); dropped == 0 {
		t.Fatalf("expected drops from slow subscriber with buffer=4 and 50 envelopes, got 0")
	}
}

// TestBroadcasterStopReleases ensures Stop returns promptly and is
// idempotent.
func TestBroadcasterStopReleases(t *testing.T) {
	src := newFakeSource(nil)
	b := New(src, Options{})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	b.Start(ctx)
	done := make(chan struct{})
	go func() {
		b.Stop()
		b.Stop()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("Stop did not return within 500ms")
	}
}
