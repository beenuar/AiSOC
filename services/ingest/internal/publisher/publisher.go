// Package publisher handles publishing normalized events to Kafka
package publisher

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/beenuar/aisoc/services/ingest/internal/config"
	"github.com/beenuar/aisoc/services/ingest/internal/enrichment"
	"github.com/beenuar/aisoc/services/ingest/internal/graph"
	"github.com/beenuar/aisoc/services/ingest/internal/kafkatls"
	"github.com/beenuar/aisoc/services/ingest/internal/normalizer"
	"github.com/rs/zerolog/log"
	kafka "github.com/segmentio/kafka-go"
)

// Publisher sends normalized events to Kafka
type Publisher struct {
	writer      *kafka.Writer
	vulnWriter  *kafka.Writer // dedicated writer for VULNERABILITY_MATCH topic
	graphWriter *kafka.Writer // dedicated writer for security.graph_updates (T1.1, v8.0)
	cfg         *config.Config
}

// New creates a new Kafka publisher
func New(cfg *config.Config) (*Publisher, error) {
	// Resolved once and shared by all three writers. kafka-go's zero
	// Transport means plaintext, and none of them set one, so the ingest
	// service — the front door for every normalized event — spoke cleartext
	// to the broker. Resolve returns an error rather than a default in a
	// protected environment, so this fails at construction instead of
	// succeeding quietly.
	transport, err := kafkatls.Resolve()
	if err != nil {
		return nil, fmt.Errorf("kafka transport: %w", err)
	}
	kafkaTransport := transport.WriterTransport()

	w := &kafka.Writer{
		Transport:              kafkaTransport,
		Addr:                   kafka.TCP(cfg.KafkaBrokers),
		Topic:                  cfg.KafkaTopic,
		Balancer:               &kafka.Hash{},
		MaxAttempts:            5,
		BatchSize:              cfg.MaxBatchSize,
		RequiredAcks:           kafka.RequireAll,
		AllowAutoTopicCreation: true,
	}

	var vulnWriter *kafka.Writer
	if cfg.VulnCorrelEnabled && cfg.VulnKafkaTopic != "" {
		vulnWriter = &kafka.Writer{
			Transport:              kafkaTransport,
			Addr:                   kafka.TCP(cfg.KafkaBrokers),
			Topic:                  cfg.VulnKafkaTopic,
			Balancer:               &kafka.Hash{},
			MaxAttempts:            3,
			AllowAutoTopicCreation: true,
		}
	}

	// Graph-update writer (T1.1, v8.0). Created unconditionally when the
	// topic is configured so any service that wants to listen — including
	// the realtime websocket service in T1.4 — can subscribe even if the
	// graph writer is disabled and never publishes.
	var graphWriter *kafka.Writer
	if cfg.GraphUpdatesTopic != "" {
		graphWriter = &kafka.Writer{
			Transport:              kafkaTransport,
			Addr:                   kafka.TCP(cfg.KafkaBrokers),
			Topic:                  cfg.GraphUpdatesTopic,
			Balancer:               &kafka.Hash{},
			MaxAttempts:            3,
			AllowAutoTopicCreation: true,
		}
	}

	return &Publisher{
		writer:      w,
		vulnWriter:  vulnWriter,
		graphWriter: graphWriter,
		cfg:         cfg,
	}, nil
}

// PublishGraphUpdate sends a graph-mutation envelope to security.graph_updates.
// Implements graph.UpdatePublisher so the graph writer can fan out node/edge
// changes for downstream consumers (T1.4 realtime websocket).
//
// Failures are returned to the caller so the writer can record them, but the
// caller (graph.Writer.publishChanges) treats this as best-effort.
func (p *Publisher) PublishGraphUpdate(ctx context.Context, update graph.GraphUpdate) error {
	if p.graphWriter == nil {
		return nil
	}
	data, err := json.Marshal(update)
	if err != nil {
		return err
	}
	key := []byte(update.EntityID)
	if update.TenantID != "" {
		key = []byte(update.TenantID + ":" + update.EntityID)
	}
	msg := kafka.Message{
		Key:   key,
		Value: data,
		Headers: []kafka.Header{
			{Key: "change_type", Value: []byte(update.ChangeType)},
			{Key: "schema_version", Value: []byte(update.SchemaVersion)},
		},
	}
	if update.TenantID != "" {
		msg.Headers = append(msg.Headers, kafka.Header{Key: "tenant_id", Value: []byte(update.TenantID)})
	}
	if err := p.graphWriter.WriteMessages(ctx, msg); err != nil {
		log.Warn().Err(err).Str("entity_id", update.EntityID).Msg("Failed to publish graph update")
		return err
	}
	return nil
}

// PublishVulnMatch sends a VULNERABILITY_MATCH event to the dedicated Kafka topic.
func (p *Publisher) PublishVulnMatch(ctx context.Context, match enrichment.VulnMatch) error {
	if p.vulnWriter == nil {
		return nil
	}
	data, err := json.Marshal(match)
	if err != nil {
		return err
	}
	msg := kafka.Message{
		Key:   []byte(match.CVE + ":" + match.TenantID),
		Value: data,
		Headers: []kafka.Header{
			{Key: "event_type", Value: []byte("VULNERABILITY_MATCH")},
			{Key: "tenant_id", Value: []byte(match.TenantID)},
		},
	}
	if err := p.vulnWriter.WriteMessages(ctx, msg); err != nil {
		log.Warn().Err(err).Str("cve", match.CVE).Msg("Failed to publish vuln match")
		return err
	}
	return nil
}

// Publish sends a single normalized event to Kafka
func (p *Publisher) Publish(ctx context.Context, event *normalizer.NormalizedEvent) error {
	data, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("failed to marshal event: %w", err)
	}

	msg := kafka.Message{
		Key:   []byte(event.TenantID + ":" + event.ID),
		Value: data,
		Headers: []kafka.Header{
			{Key: "tenant_id", Value: []byte(event.TenantID)},
			{Key: "connector_id", Value: []byte(event.ConnectorID)},
			{Key: "content_type", Value: []byte("application/json")},
			{Key: "schema", Value: []byte("ocsf/1.1.0")},
		},
	}

	if err := p.writer.WriteMessages(ctx, msg); err != nil {
		log.Error().Err(err).
			Str("tenant_id", event.TenantID).
			Str("event_id", event.ID).
			Msg("Failed to publish event to Kafka")
		return fmt.Errorf("kafka publish failed: %w", err)
	}

	log.Debug().
		Str("tenant_id", event.TenantID).
		Str("event_id", event.ID).
		Str("connector_id", event.ConnectorID).
		Msg("Event published to Kafka")

	return nil
}

// PublishBatch sends multiple events in a single batch
// partitionKey decides which partition an event lands on, and therefore
// what fusion sees in order.
//
// Parity plan 6.9 / depth plan 4.4. The key used to be
// `tenant:event_id`, which is unique per event — so every event hashed to
// an arbitrary partition and nothing about one entity's events was
// ordered relative to another's. Fusion correlates on
// `{tenant}:{entity}:{tactic}` and the windowed engine stitches sequences
// by event time, so two events about one host arriving on two partitions
// and being consumed by two replicas is the case where a sequence is
// stitched out of order or split across two incidents.
//
// The key is `tenant:entity`, where entity is resolved in the same
// precedence the alert's own `correlation_key()` uses — source IP, then
// hostname, then username, then domain. Partitions are ordered, so all of
// one entity's events are ordered relative to each other; different
// entities still spread across the cluster, so this is ordering without
// serialising the topic.
//
// An event with no resolvable entity falls back to the event id. That
// keeps the spread even for telemetry that names nobody, and such an
// event has no sequence to be part of, so there is no ordering to lose.
// Falling back to the tenant id instead would put every anonymous event
// in one tenant onto one partition — a hot partition that is also the
// least useful one.
func partitionKey(event *normalizer.NormalizedEvent) []byte {
	entity := primaryEntity(event)
	if entity == "" {
		return []byte(event.TenantID + ":" + event.ID)
	}
	return []byte(event.TenantID + ":" + entity)
}

// entityFieldOrder is the precedence fusion's own correlation key uses
// (services/fusion/app/models/alert.py, `RawAlert.correlation_key`). Held
// in the same order deliberately: a partition key that disagrees with the
// correlation key routes an entity's events to a partition and then
// correlates them under a different name, which spreads one incident
// across replicas while looking correct from either end.
var entityFieldOrder = []struct {
	section string
	field   string
}{
	{"src_endpoint", "ip"},
	{"device", "hostname"},
	{"device", "name"},
	{"actor.user", "name"},
	{"", "src_ip"},
	{"", "hostname"},
	{"", "host"},
	{"", "user"},
	{"", "username"},
	{"", "domain"},
}

// primaryEntity pulls the entity out of the OCSF event, checking the
// structured locations first and the flat connector fields after.
func primaryEntity(event *normalizer.NormalizedEvent) string {
	ocsf := event.OcsfEvent
	if ocsf == nil {
		return ""
	}
	for _, candidate := range entityFieldOrder {
		var value string
		if candidate.section == "" {
			value = stringAt(ocsf, candidate.field)
		} else {
			value = stringAt(ocsf, strings.Split(candidate.section+"."+candidate.field, ".")...)
		}
		if value != "" {
			return value
		}
	}
	return ""
}

// stringAt walks a dotted path through nested maps and returns a non-empty
// string leaf, or "".
func stringAt(root map[string]interface{}, path ...string) string {
	var cur interface{} = root
	for _, key := range path {
		m, ok := cur.(map[string]interface{})
		if !ok {
			return ""
		}
		cur = m[key]
	}
	if s, ok := cur.(string); ok {
		return strings.TrimSpace(s)
	}
	return ""
}

func (p *Publisher) PublishBatch(ctx context.Context, events []*normalizer.NormalizedEvent) error {
	if len(events) == 0 {
		return nil
	}

	msgs := make([]kafka.Message, 0, len(events))
	for _, event := range events {
		data, err := json.Marshal(event)
		if err != nil {
			log.Warn().Err(err).Str("event_id", event.ID).Msg("Skipping event due to marshal error")
			continue
		}
		msgs = append(msgs, kafka.Message{
			Key:   partitionKey(event),
			Value: data,
			Headers: []kafka.Header{
				{Key: "tenant_id", Value: []byte(event.TenantID)},
				{Key: "connector_id", Value: []byte(event.ConnectorID)},
				{Key: "content_type", Value: []byte("application/json")},
				{Key: "schema", Value: []byte("ocsf/1.1.0")},
			},
		})
	}

	if err := p.writer.WriteMessages(ctx, msgs...); err != nil {
		return fmt.Errorf("kafka batch publish failed: %w", err)
	}

	log.Info().Int("count", len(msgs)).Msg("Batch published to Kafka")
	return nil
}

// Ready reports whether the Kafka broker is actually reachable.
//
// This is the difference between liveness and readiness for this service:
// the process can be perfectly alive while the broker is unreachable, and in
// that state every ingested event is accepted and then dropped. An operator
// or a load balancer needs to tell those apart, and /health could not --- it
// returned 200 unconditionally.
//
// Dialing is deliberate rather than reading a cached connection state:
// kafka-go reconnects lazily, so a cached "connected" flag is stale in
// exactly the situation this is meant to catch.
func (p *Publisher) Ready(ctx context.Context) error {
	addr := p.writer.Addr
	if addr == nil {
		return fmt.Errorf("no kafka address configured")
	}
	d := &net.Dialer{Timeout: 2 * time.Second}
	conn, err := d.DialContext(ctx, addr.Network(), addr.String())
	if err != nil {
		return fmt.Errorf("kafka unreachable at %s: %w", addr.String(), err)
	}
	return conn.Close()
}

// Close shuts down the Kafka writers
func (p *Publisher) Close() {
	if err := p.writer.Close(); err != nil {
		log.Error().Err(err).Msg("Error closing Kafka writer")
	}
	if p.vulnWriter != nil {
		if err := p.vulnWriter.Close(); err != nil {
			log.Error().Err(err).Msg("Error closing vuln Kafka writer")
		}
	}
	if p.graphWriter != nil {
		if err := p.graphWriter.Close(); err != nil {
			log.Error().Err(err).Msg("Error closing graph-updates Kafka writer")
		}
	}
}
