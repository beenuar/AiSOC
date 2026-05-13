// writer.go — Neo4j-backed graph writer with batched UNWIND upserts.
//
// Design notes:
//
//   - The *real* path uses the Neo4j Bolt driver
//     (github.com/neo4j/neo4j-go-driver/v5). The writer holds a single
//     DriverWithContext as a connection pool and opens short-lived sessions
//     per flush — this is the idiomatic pattern from Neo4j's own examples
//     and avoids holding a session across goroutine boundaries.
//
//   - The hot path (``WriteEvent``) does NOT touch the network. It enqueues
//     onto an in-process channel that is drained by a background flusher.
//     This is what lets the Kafka consumer pipeline (handler.go) stay snappy
//     even when Neo4j stutters.
//
//   - Batched upserts use a single UNWIND query per (node-label, batch) and
//     per (edge-type, batch). MERGE is keyed on ``natural_key`` so the same
//     entity from two different events collapses to one node — critical for
//     the graph-as-state-of-the-world invariant.
//
//   - Failure mode: if Neo4j is unreachable or returns a transient error, we
//     log + emit a metric and DROP the batch. The caller already published
//     the event to the Kafka fusion topic, so fusion is unaffected. T1.2
//     will replace the drop with an outbox-style retry queue.
package graph

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/neo4j/neo4j-go-driver/v5/neo4j"
	"github.com/rs/zerolog/log"
)

// Driver is the subset of neo4j.DriverWithContext that ``Writer`` actually
// uses. Defined as an interface so unit tests can plug in a fake without
// running a real Neo4j instance — that's the contract writer_test.go relies
// on.
type Driver interface {
	NewSession(ctx context.Context, config neo4j.SessionConfig) Session
	Close(ctx context.Context) error
	VerifyConnectivity(ctx context.Context) error
}

// Session is the subset of neo4j.SessionWithContext we use during a flush.
type Session interface {
	ExecuteWrite(ctx context.Context, work func(tx Transaction) (any, error)) (any, error)
	Close(ctx context.Context) error
}

// Transaction is the subset of neo4j.ManagedTransaction we use.
type Transaction interface {
	Run(ctx context.Context, cypher string, params map[string]any) error
}

// UpdatePublisher receives one envelope per node/edge upsert. The Kafka
// publisher in services/ingest/internal/publisher implements this so the
// realtime service (T1.4) can stream changes without re-querying Neo4j.
//
// Implementations MUST be non-blocking — the writer holds the ingest
// pipeline open while it publishes, so a slow publisher pushes back on
// graph throughput.
type UpdatePublisher interface {
	PublishGraphUpdate(ctx context.Context, update GraphUpdate) error
}

// GraphUpdate is the envelope emitted on ``security.graph_updates`` for
// every node/edge mutation. Downstream consumers subscribe to this topic to
// drive realtime UI without re-querying Neo4j.
type GraphUpdate struct {
	EntityID   string     `json:"entity_id"`
	ChangeType ChangeType `json:"change_type"`
	TS         time.Time  `json:"ts"`

	// Optional payload describing the mutation in enough detail for a
	// downstream consumer to apply it locally without an extra round-trip.
	Label      NodeLabel              `json:"label,omitempty"`
	RelType    RelType                `json:"rel_type,omitempty"`
	From       string                 `json:"from,omitempty"`
	To         string                 `json:"to,omitempty"`
	Properties map[string]interface{} `json:"properties,omitempty"`

	SchemaVersion string `json:"schema_version"`
	TenantID      string `json:"tenant_id,omitempty"`
}

// Node represents an entity to upsert.
type Node struct {
	Label NodeLabel
	// NaturalKey uniquely identifies this entity across events. MERGE is
	// keyed on this — e.g. an AWS IAM user's ARN, a GitHub repo's full_name,
	// an Okta user's id.
	NaturalKey string
	TenantID   string
	Properties map[string]interface{}
}

// Edge represents a relationship to upsert.
type Edge struct {
	Type RelType
	// FromKey + FromLabel and ToKey + ToLabel jointly identify the endpoints.
	FromLabel  NodeLabel
	FromKey    string
	ToLabel    NodeLabel
	ToKey      string
	Properties map[string]interface{}
}

// Event is a graph projection of a single normalised OCSF event — the units
// the writer batches over.
type Event struct {
	EventID  string
	TenantID string
	TS       time.Time
	Nodes    []Node
	Edges    []Edge
	// SnapshotID is captured at event-time for the T1.2 config-snapshot
	// pattern. Empty in v1.0; reserved for the snapshot writer to fill in.
	SnapshotID string
}

// Writer batches graph upserts and flushes them to Neo4j.
type Writer struct {
	driver        Driver
	publisher     UpdatePublisher
	queue         chan *Event
	batchSize     int
	flushInterval time.Duration

	wg       sync.WaitGroup
	closed   chan struct{}
	rootCtx  context.Context
	rootDone context.CancelFunc

	// metrics — small atomic counters surfaced for the Prometheus collector
	mu              sync.Mutex
	eventsAccepted  uint64
	eventsDropped   uint64
	flushErrors     uint64
	lastFlushNodes  int
	lastFlushEdges  int
}

// Config configures Writer.
type Config struct {
	URI       string
	Username  string
	Password  string
	Database  string
	BatchSize int
	// FlushInterval is the maximum time the writer waits before flushing
	// even if BatchSize hasn't been reached.
	FlushInterval time.Duration
	// QueueSize is the size of the in-process event channel. Once full,
	// WriteEvent drops new events instead of blocking — this is intentional
	// (graph failures must NOT block fusion ingest, per T1.1 acceptance).
	QueueSize int
	// Publisher is the optional Kafka publisher for security.graph_updates.
	Publisher UpdatePublisher
}

// DefaultConfig returns the v8.0 production defaults.
func DefaultConfig() Config {
	return Config{
		URI:           "bolt://localhost:7687",
		Username:      "neo4j",
		Password:      "neo4j",
		Database:      "neo4j",
		BatchSize:     100,
		FlushInterval: 100 * time.Millisecond,
		QueueSize:     2048,
	}
}

// neo4jDriverWrapper adapts a real *neo4j.DriverWithContext to our local
// Driver interface so tests can swap it out.
type neo4jDriverWrapper struct {
	inner neo4j.DriverWithContext
}

func (d *neo4jDriverWrapper) NewSession(ctx context.Context, cfg neo4j.SessionConfig) Session {
	return &neo4jSessionWrapper{inner: d.inner.NewSession(ctx, cfg)}
}

func (d *neo4jDriverWrapper) Close(ctx context.Context) error {
	return d.inner.Close(ctx)
}

func (d *neo4jDriverWrapper) VerifyConnectivity(ctx context.Context) error {
	return d.inner.VerifyConnectivity(ctx)
}

type neo4jSessionWrapper struct {
	inner neo4j.SessionWithContext
}

func (s *neo4jSessionWrapper) ExecuteWrite(ctx context.Context, work func(tx Transaction) (any, error)) (any, error) {
	return s.inner.ExecuteWrite(ctx, func(tx neo4j.ManagedTransaction) (any, error) {
		return work(&neo4jTxWrapper{inner: tx})
	})
}

func (s *neo4jSessionWrapper) Close(ctx context.Context) error {
	return s.inner.Close(ctx)
}

type neo4jTxWrapper struct {
	inner neo4j.ManagedTransaction
}

func (t *neo4jTxWrapper) Run(ctx context.Context, cypher string, params map[string]any) error {
	res, err := t.inner.Run(ctx, cypher, params)
	if err != nil {
		return err
	}
	// Drain the result — Neo4j requires this before the tx commits.
	_, err = res.Consume(ctx)
	return err
}

// New connects to Neo4j and starts the background flusher.
func New(ctx context.Context, cfg Config) (*Writer, error) {
	if cfg.URI == "" {
		return nil, errors.New("graph: URI is required")
	}
	if cfg.BatchSize <= 0 {
		cfg.BatchSize = 100
	}
	if cfg.FlushInterval <= 0 {
		cfg.FlushInterval = 100 * time.Millisecond
	}
	if cfg.QueueSize <= 0 {
		cfg.QueueSize = 2048
	}

	driver, err := neo4j.NewDriverWithContext(cfg.URI, neo4j.BasicAuth(cfg.Username, cfg.Password, ""))
	if err != nil {
		return nil, fmt.Errorf("graph: connect to Neo4j: %w", err)
	}

	connectCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := driver.VerifyConnectivity(connectCtx); err != nil {
		_ = driver.Close(ctx)
		return nil, fmt.Errorf("graph: verify connectivity: %w", err)
	}

	w := newWriterFromDriver(&neo4jDriverWrapper{inner: driver}, cfg)
	return w, nil
}

// newWriterFromDriver is the test-friendly constructor — takes a Driver
// interface so writer_test.go can inject a fake without touching the
// network. Production code uses ``New``.
func newWriterFromDriver(driver Driver, cfg Config) *Writer {
	rootCtx, rootDone := context.WithCancel(context.Background())
	w := &Writer{
		driver:        driver,
		publisher:     cfg.Publisher,
		queue:         make(chan *Event, cfg.QueueSize),
		batchSize:     cfg.BatchSize,
		flushInterval: cfg.FlushInterval,
		closed:        make(chan struct{}),
		rootCtx:       rootCtx,
		rootDone:      rootDone,
	}
	w.wg.Add(1)
	go w.flushLoop()
	return w
}

// WriteEvent enqueues a graph projection for batched flush. NEVER blocks: if
// the queue is full we drop and increment the metric. This is the explicit
// guarantee from T1.1: graph-write failures must NOT block fusion ingest.
func (w *Writer) WriteEvent(ctx context.Context, ev *Event) error {
	if ev == nil {
		return nil
	}
	if ev.TS.IsZero() {
		ev.TS = time.Now().UTC()
	}
	select {
	case <-w.closed:
		return errors.New("graph: writer closed")
	case w.queue <- ev:
		w.mu.Lock()
		w.eventsAccepted++
		w.mu.Unlock()
		return nil
	default:
		w.mu.Lock()
		w.eventsDropped++
		w.mu.Unlock()
		log.Warn().Str("event_id", ev.EventID).Msg("graph: queue full, dropping event")
		return nil
	}
}

// Close drains the queue, flushes once more, and closes the driver. Safe to
// call multiple times. Cancels the root context after a short grace window
// so a wedged Neo4j flush returns promptly instead of stalling shutdown.
func (w *Writer) Close() error {
	select {
	case <-w.closed:
		return nil
	default:
	}
	close(w.closed)

	// Grace window: let the drain loop run normal-timeout flushes for a
	// short period. After that, cancel the root context so any in-flight
	// flush returns immediately and the goroutine can exit.
	if w.rootDone != nil {
		go func() {
			time.Sleep(500 * time.Millisecond)
			w.rootDone()
		}()
	}
	w.wg.Wait()
	if w.rootDone != nil {
		w.rootDone()
	}
	return w.driver.Close(context.Background())
}

// flushLoop drains the queue and flushes batches. Runs until Close().
func (w *Writer) flushLoop() {
	defer w.wg.Done()
	ticker := time.NewTicker(w.flushInterval)
	defer ticker.Stop()

	batch := make([]*Event, 0, w.batchSize)

	flush := func() {
		if len(batch) == 0 {
			return
		}
		// Per-flush timeout. We derive from rootCtx so Close() can interrupt
		// a wedged flush by closing the queue + cancelling rootCtx — a
		// production Neo4j outage shouldn't pin the ingest pod's shutdown.
		parent := w.rootCtx
		if parent == nil {
			parent = context.Background()
		}
		ctx, cancel := context.WithTimeout(parent, 10*time.Second)
		defer cancel()
		if err := w.flush(ctx, batch); err != nil {
			w.mu.Lock()
			w.flushErrors++
			w.mu.Unlock()
			log.Warn().Err(err).Int("batch_size", len(batch)).Msg("graph: flush failed")
		}
		batch = batch[:0]
	}

	for {
		select {
		case <-w.closed:
			// Drain remaining queued events so we don't lose them on shutdown.
			for {
				select {
				case ev := <-w.queue:
					batch = append(batch, ev)
					if len(batch) >= w.batchSize {
						flush()
					}
				default:
					flush()
					return
				}
			}
		case ev := <-w.queue:
			batch = append(batch, ev)
			if len(batch) >= w.batchSize {
				flush()
			}
		case <-ticker.C:
			flush()
		}
	}
}

// flush performs the batched upsert. Pure function over batch — exported as
// FlushBatch for the unit test so we can drive it deterministically.
func (w *Writer) flush(ctx context.Context, batch []*Event) error {
	return w.FlushBatch(ctx, batch)
}

// FlushBatch is the unit-testable seam — separates "decide to flush" from
// "execute the flush". writer_test.go calls this directly with a fake driver.
func (w *Writer) FlushBatch(ctx context.Context, batch []*Event) error {
	if len(batch) == 0 {
		return nil
	}

	// Group nodes by label and edges by type so each UNWIND runs against a
	// single label/type — Cypher requires this because labels/relationships
	// are part of the query shape, not parameters.
	nodesByLabel := map[NodeLabel][]map[string]interface{}{}
	edgesByType := map[RelType][]map[string]interface{}{}

	for _, ev := range batch {
		for _, node := range ev.Nodes {
			row := buildNodeRow(node, ev)
			nodesByLabel[node.Label] = append(nodesByLabel[node.Label], row)
		}
		for _, edge := range ev.Edges {
			row := buildEdgeRow(edge, ev)
			edgesByType[edge.Type] = append(edgesByType[edge.Type], row)
		}
	}

	w.mu.Lock()
	w.lastFlushNodes = totalLen(nodesByLabel)
	w.lastFlushEdges = totalLen(edgesByType)
	w.mu.Unlock()

	session := w.driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeWrite})
	defer func() { _ = session.Close(ctx) }()

	_, err := session.ExecuteWrite(ctx, func(tx Transaction) (any, error) {
		// Stable iteration order so unit tests can assert query order.
		for _, label := range sortedNodeLabels(nodesByLabel) {
			rows := nodesByLabel[label]
			if len(rows) == 0 {
				continue
			}
			cypher := buildNodeUpsertCypher(label)
			if err := tx.Run(ctx, cypher, map[string]any{"rows": rows}); err != nil {
				return nil, fmt.Errorf("node upsert (%s): %w", label, err)
			}
		}
		for _, rt := range sortedRelTypes(edgesByType) {
			rows := edgesByType[rt]
			if len(rows) == 0 {
				continue
			}
			// Edges need both endpoints' labels too. Group by (rel, fromLabel,
			// toLabel) inside the loop.
			for _, group := range groupEdgesByEndpointLabels(rows) {
				cypher := buildEdgeUpsertCypher(rt, group.fromLabel, group.toLabel)
				if err := tx.Run(ctx, cypher, map[string]any{"rows": group.rows}); err != nil {
					return nil, fmt.Errorf("edge upsert (%s): %w", rt, err)
				}
			}
		}
		return nil, nil
	})
	if err != nil {
		return err
	}

	// Publish change envelopes — best-effort. A publish failure does NOT
	// roll back the graph write; the realtime channel is informational.
	if w.publisher != nil {
		w.publishChanges(ctx, batch)
	}

	return nil
}

// buildNodeRow renders one node into the row shape that buildNodeUpsertCypher
// expects. Captures the v1.0 idempotency contract:
//
//   - MERGE on (label, natural_key)
//   - upsert properties via SET n += row.props
//   - hash(properties) lets the realtime channel detect "no-op" upserts
func buildNodeRow(n Node, ev *Event) map[string]interface{} {
	props := map[string]interface{}{}
	for k, v := range n.Properties {
		props[k] = v
	}
	props["tenant_id"] = nonEmpty(n.TenantID, ev.TenantID)
	props["schema_version"] = SchemaVersion
	props["last_seen_ts"] = ev.TS.UTC().Format(time.RFC3339Nano)
	props["last_event_id"] = ev.EventID
	if ev.SnapshotID != "" {
		props["snapshot_id"] = ev.SnapshotID
	}
	return map[string]interface{}{
		"natural_key": n.NaturalKey,
		"props":       props,
		"props_hash":  hashProperties(n.Properties),
	}
}

// buildEdgeRow renders one edge into a parameter row. Every event-edge
// carries {ts, source_event_id, snapshot_id} per the T1.1 contract.
func buildEdgeRow(e Edge, ev *Event) map[string]interface{} {
	props := map[string]interface{}{}
	for k, v := range e.Properties {
		props[k] = v
	}
	props["ts"] = ev.TS.UTC().Format(time.RFC3339Nano)
	props["source_event_id"] = ev.EventID
	props["schema_version"] = SchemaVersion
	if ev.SnapshotID != "" {
		props["snapshot_id"] = ev.SnapshotID
	}
	return map[string]interface{}{
		"from_key":   e.FromKey,
		"to_key":     e.ToKey,
		"from_label": string(e.FromLabel),
		"to_label":   string(e.ToLabel),
		"props":      props,
	}
}

// buildNodeUpsertCypher returns the UNWIND query for a given label.
func buildNodeUpsertCypher(label NodeLabel) string {
	return fmt.Sprintf(
		`UNWIND $rows AS row
MERGE (n:%s {natural_key: row.natural_key})
SET n += row.props,
    n.props_hash = row.props_hash`,
		string(label),
	)
}

// buildEdgeUpsertCypher returns the UNWIND query for a given (rel, fromLabel,
// toLabel) triple.
func buildEdgeUpsertCypher(rel RelType, fromLabel, toLabel NodeLabel) string {
	return fmt.Sprintf(
		`UNWIND $rows AS row
MERGE (a:%s {natural_key: row.from_key})
MERGE (b:%s {natural_key: row.to_key})
MERGE (a)-[r:%s]->(b)
SET r += row.props`,
		string(fromLabel), string(toLabel), string(rel),
	)
}

// edgeGroup is an internal grouping key for ``flush``.
type edgeGroup struct {
	fromLabel NodeLabel
	toLabel   NodeLabel
	rows      []map[string]interface{}
}

// groupEdgesByEndpointLabels splits a same-rel batch by (from_label, to_label).
func groupEdgesByEndpointLabels(rows []map[string]interface{}) []edgeGroup {
	groups := map[string]*edgeGroup{}
	for _, r := range rows {
		from := NodeLabel(r["from_label"].(string))
		to := NodeLabel(r["to_label"].(string))
		key := string(from) + "->" + string(to)
		g, ok := groups[key]
		if !ok {
			g = &edgeGroup{fromLabel: from, toLabel: to}
			groups[key] = g
		}
		g.rows = append(g.rows, r)
	}
	keys := make([]string, 0, len(groups))
	for k := range groups {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]edgeGroup, 0, len(groups))
	for _, k := range keys {
		out = append(out, *groups[k])
	}
	return out
}

// publishChanges fans out one envelope per node/edge mutation. Failures are
// logged but never returned — the realtime channel is informational.
func (w *Writer) publishChanges(ctx context.Context, batch []*Event) {
	for _, ev := range batch {
		for _, n := range ev.Nodes {
			update := GraphUpdate{
				EntityID:      n.NaturalKey,
				ChangeType:    ChangeUpsertNode,
				TS:            ev.TS,
				Label:         n.Label,
				SchemaVersion: SchemaVersion,
				TenantID:      nonEmpty(n.TenantID, ev.TenantID),
				Properties:    n.Properties,
			}
			if err := w.publisher.PublishGraphUpdate(ctx, update); err != nil {
				log.Debug().Err(err).Str("entity_id", n.NaturalKey).Msg("graph: publish update failed")
			}
		}
		for _, e := range ev.Edges {
			update := GraphUpdate{
				EntityID:      e.FromKey + "->" + e.ToKey,
				ChangeType:    ChangeUpsertEdge,
				TS:            ev.TS,
				RelType:       e.Type,
				From:          e.FromKey,
				To:            e.ToKey,
				SchemaVersion: SchemaVersion,
				TenantID:      ev.TenantID,
				Properties:    e.Properties,
			}
			if err := w.publisher.PublishGraphUpdate(ctx, update); err != nil {
				log.Debug().Err(err).Str("entity_id", update.EntityID).Msg("graph: publish edge update failed")
			}
		}
	}
}

// Stats is a snapshot of writer-internal counters used by the Prometheus
// collector and tests.
type Stats struct {
	EventsAccepted uint64
	EventsDropped  uint64
	FlushErrors    uint64
	LastFlushNodes int
	LastFlushEdges int
}

// Stats returns a snapshot of the internal counters.
func (w *Writer) Stats() Stats {
	w.mu.Lock()
	defer w.mu.Unlock()
	return Stats{
		EventsAccepted: w.eventsAccepted,
		EventsDropped:  w.eventsDropped,
		FlushErrors:    w.flushErrors,
		LastFlushNodes: w.lastFlushNodes,
		LastFlushEdges: w.lastFlushEdges,
	}
}

// hashProperties produces the short stable digest used in the idempotency
// key. Tied to the v1.0 contract: ``(entity_type, natural_key, hash(properties))``.
func hashProperties(props map[string]interface{}) string {
	keys := make([]string, 0, len(props))
	for k := range props {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	h := sha256.New()
	for _, k := range keys {
		h.Write([]byte(k))
		h.Write([]byte{0})
		// Best-effort encode; map keys/values that don't marshal fall back
		// to fmt to keep the hash stable for arbitrary value shapes.
		if b, err := json.Marshal(props[k]); err == nil {
			h.Write(b)
		} else {
			h.Write([]byte(fmt.Sprintf("%v", props[k])))
		}
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))[:16]
}

func nonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

func totalLen[K comparable, V any](m map[K][]V) int {
	n := 0
	for _, v := range m {
		n += len(v)
	}
	return n
}

func sortedNodeLabels(m map[NodeLabel][]map[string]interface{}) []NodeLabel {
	out := make([]NodeLabel, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func sortedRelTypes(m map[RelType][]map[string]interface{}) []RelType {
	out := make([]RelType, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}
