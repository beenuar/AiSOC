// Package graph_ws fans out security.graph_updates Kafka events to
// connected WebSocket clients in real time (T1.4 — v8.0).
//
// The broadcaster owns three responsibilities:
//
//  1. Consume the Kafka topic the ingest-side graph writer (T1.1)
//     publishes to. Each message is a graph.GraphUpdate envelope.
//  2. Demux per-tenant: the Kafka envelope carries tenant_id; the
//     broadcaster maintains a tenant -> subscribers map so a client
//     opened with ?tenant_id=X only receives updates whose tenant_id
//     matches X (or are unscoped, for the global cross-tenant admin
//     view which is currently not exposed to end users).
//  3. Fan out with backpressure: each subscriber has a bounded buffer.
//     If the buffer is full (a slow client) the broadcaster drops the
//     in-flight message for that subscriber and increments
//     droppedDeliveries — it must NEVER block the Kafka consumer
//     loop, because that would back-pressure into the producer.
//
// The package is consumer-only and stateless across restarts; it does
// not maintain Kafka offsets in any external store. A new pod that
// joins the consumer group will start from the configured offset
// (typically "latest"). This matches the realtime contract — the WS
// is a live tail, not a replay surface.
package graph_ws

import (
	"context"
	"encoding/json"
	"sync"
	"sync/atomic"
	"time"

	"github.com/beenuar/aisoc/services/ingest/internal/graph"
)

// subscriberBufferDefault is the per-client buffer size. Keep small —
// the goal is "live tail with backpressure", not "deliver every event
// no matter what". A slow client will see drops; a healthy client sees
// every event because the producer side runs ahead of any reasonable
// consumer pace.
const subscriberBufferDefault = 256

// EnvelopeSource is anything that yields graph.GraphUpdate envelopes.
// The production implementation wraps segmentio/kafka-go; tests inject
// a channel-backed fake (see broadcaster_test.go) so the broadcaster's
// fan-out semantics can be exercised without Kafka.
type EnvelopeSource interface {
	// Next blocks until the next envelope is available or ctx is
	// cancelled. On cancellation it returns (zero, ctx.Err()).
	Next(ctx context.Context) (graph.GraphUpdate, error)
	// Close releases resources. Idempotent.
	Close() error
}

// Subscriber represents a single connected WebSocket client. The
// broadcaster owns the lifecycle of the channel — Subscribe creates
// it, Unsubscribe drains and closes it.
type Subscriber struct {
	// TenantID is the scope this subscriber sees. Empty means "all
	// tenants"; reserved for cross-tenant admin tools and never
	// exposed via the tenant-scoped HTTP entry point.
	TenantID string

	// Updates is the read side. Each message is one envelope.
	Updates chan graph.GraphUpdate

	id uint64
}

// Broadcaster fans out envelopes from a single EnvelopeSource to many
// Subscribers. Safe for concurrent use.
type Broadcaster struct {
	src EnvelopeSource

	mu          sync.RWMutex
	subscribers map[uint64]*Subscriber

	nextID atomic.Uint64

	bufferSize int

	dropped atomic.Uint64

	// health is shared with the source, so an error the Kafka reader
	// swallows internally and an error the loop sees land in one place.
	health *SourceState

	stopCh chan struct{}
	doneCh chan struct{}
}

// Options tunes broadcaster construction.
type Options struct {
	// BufferSize overrides subscriberBufferDefault. Zero falls back
	// to the default; negative is rejected at construction.
	BufferSize int

	// Health is the failure state shared with the EnvelopeSource. Pass the
	// same *SourceState given to NewKafkaSource so the reader's internal
	// dial and rebalance failures are counted alongside the loop's. Nil
	// creates a private one, which is the right default for a fake source
	// in a test.
	Health *SourceState

	// Topic names the subscription in logs and metrics when Health is nil.
	Topic string

	// StuckAfter overrides how long a transient failure may persist before
	// it is reported as not resolving. Only consulted when Health is nil.
	StuckAfter time.Duration
}

// New constructs a broadcaster wired to src. Call Start to begin
// consuming; until then no envelopes flow.
func New(src EnvelopeSource, opts Options) *Broadcaster {
	buf := opts.BufferSize
	if buf <= 0 {
		buf = subscriberBufferDefault
	}
	health := opts.Health
	if health == nil {
		health = NewSourceState(opts.Topic, opts.StuckAfter)
	}
	return &Broadcaster{
		src:         src,
		subscribers: make(map[uint64]*Subscriber),
		bufferSize:  buf,
		health:      health,
		stopCh:      make(chan struct{}),
		doneCh:      make(chan struct{}),
	}
}

// Health reports the state of the subscription: attached or not, how long it
// has been failing, and whether the failure is one a retry can clear.
//
// Read by the /readyz probe and by the WebSocket upgrade handler, which
// refuses a connection it could not serve rather than completing a handshake
// onto a socket that will stay silent.
func (b *Broadcaster) Health() SourceHealth {
	return b.health.Health()
}

// Start launches the consumer goroutine. It returns immediately; the
// goroutine runs until ctx is cancelled or Stop is called. Calling
// Start more than once is a programmer error.
func (b *Broadcaster) Start(ctx context.Context) {
	// Derive a child context we control so Stop() can unblock a
	// consumer wedged inside src.Next without waiting for the
	// caller's ctx to be cancelled. We propagate cancellation in
	// both directions: parent ctx cancel propagates via the
	// context.WithCancel chain, and our stopCh fan-out below
	// triggers our local cancel.
	derived, cancel := context.WithCancel(ctx)
	go func() {
		select {
		case <-b.stopCh:
			cancel()
		case <-derived.Done():
		}
	}()
	go func() {
		defer cancel()
		b.consumeLoop(derived)
	}()
}

// Stop signals the consumer to exit and waits for it to finish.
// Safe to call multiple times.
func (b *Broadcaster) Stop() {
	select {
	case <-b.stopCh:
		// already closed
	default:
		close(b.stopCh)
	}
	<-b.doneCh
}

// Subscribe registers a new client with the broadcaster using the
// broadcaster's default buffer size. tenantID scopes which envelopes
// the subscriber sees; empty tenantID means "all" (admin-only, not
// reachable from the public HTTP path).
func (b *Broadcaster) Subscribe(tenantID string) *Subscriber {
	return b.SubscribeWithBuffer(tenantID, b.bufferSize)
}

// SubscribeWithBuffer is like Subscribe but lets the caller pick a
// per-subscriber buffer size. Tests use this to compose a "slow"
// subscriber (tiny buffer) alongside a "healthy" subscriber (large
// buffer) so the backpressure contract can be exercised against a
// single broadcaster.
func (b *Broadcaster) SubscribeWithBuffer(tenantID string, buf int) *Subscriber {
	if buf <= 0 {
		buf = b.bufferSize
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	id := b.nextID.Add(1)
	sub := &Subscriber{
		TenantID: tenantID,
		Updates:  make(chan graph.GraphUpdate, buf),
		id:       id,
	}
	b.subscribers[id] = sub
	return sub
}

// Unsubscribe removes the subscriber and closes its channel. Safe to
// call multiple times.
func (b *Broadcaster) Unsubscribe(sub *Subscriber) {
	if sub == nil {
		return
	}
	b.mu.Lock()
	_, ok := b.subscribers[sub.id]
	if ok {
		delete(b.subscribers, sub.id)
	}
	b.mu.Unlock()
	if ok {
		close(sub.Updates)
	}
}

// SubscriberCount returns the number of currently-connected
// subscribers. Useful for /metrics and tests.
func (b *Broadcaster) SubscriberCount() int {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return len(b.subscribers)
}

// DroppedDeliveries returns the cumulative count of envelopes dropped
// because a subscriber buffer was full. Reset on process restart.
func (b *Broadcaster) DroppedDeliveries() uint64 {
	return b.dropped.Load()
}

// consumeLoop pulls envelopes from the source and fans them out.
//
// What it used to do with an error was `continue` after a flat 50ms, with
// the error discarded. The loop survived, which is why this was not the
// UEBA defect — but a broker that was never coming back produced twenty
// silent reconnects a second behind a container reporting healthy, which is
// the same thing an operator cannot see. Every error now lands in
// SourceState: classified, counted, logged at a level that matches what can
// be done about it, and backed off in proportion to how long it has lasted.
//
// A permanent failure ends the loop rather than retrying it. That follows
// the UEBA consumer's reasoning: a loop over a fault no retry can clear
// turns a misconfiguration into indefinite churn, and churn reads as
// ordinary. The honest report is the error in the log, the detached state on
// /readyz, and a 503 from the WebSocket route — not a reconnect counter
// climbing forever.
func (b *Broadcaster) consumeLoop(ctx context.Context) {
	defer close(b.doneCh)
	b.health.MarkAttached()
	reason := "stopped"
	defer func() { b.health.MarkDetached(reason) }()

	for {
		select {
		case <-ctx.Done():
			return
		case <-b.stopCh:
			return
		default:
		}
		env, err := b.src.Next(ctx)
		if err != nil {
			// A cancelled context is the operator stopping the service. It
			// is not a fault and must not be counted as one, or every clean
			// shutdown would leave a failure as the last thing recorded.
			if ctx.Err() != nil || isContextError(err) {
				return
			}
			class, wait := b.health.RecordFailure(err)
			if class == ClassPermanent {
				reason = "permanent source failure: " + err.Error()
				return
			}
			if !sleepFor(ctx, b.stopCh, wait) {
				return
			}
			continue
		}
		b.health.RecordMessage()
		b.dispatch(env)
	}
}

func (b *Broadcaster) dispatch(env graph.GraphUpdate) {
	b.mu.RLock()
	targets := make([]*Subscriber, 0, len(b.subscribers))
	for _, sub := range b.subscribers {
		if sub.TenantID != "" && env.TenantID != "" && sub.TenantID != env.TenantID {
			continue
		}
		targets = append(targets, sub)
	}
	b.mu.RUnlock()
	for _, sub := range targets {
		select {
		case sub.Updates <- env:
		default:
			b.dropped.Add(1)
		}
	}
}

// MarshalEnvelope is a small helper exported for the server: the
// upgrade handler writes envelopes as JSON to the wire, and using a
// single marshal path keeps the on-wire contract stable.
func MarshalEnvelope(env graph.GraphUpdate) ([]byte, error) {
	return json.Marshal(env)
}
