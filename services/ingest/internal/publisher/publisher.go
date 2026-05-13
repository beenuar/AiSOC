// Package publisher handles publishing normalized events to Kafka
package publisher

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/beenuar/aisoc/services/ingest/internal/config"
	"github.com/beenuar/aisoc/services/ingest/internal/enrichment"
	"github.com/beenuar/aisoc/services/ingest/internal/graph"
	"github.com/beenuar/aisoc/services/ingest/internal/normalizer"
	"github.com/rs/zerolog/log"
	kafka "github.com/segmentio/kafka-go"
)

// Publisher sends normalized events to Kafka
type Publisher struct {
	writer       *kafka.Writer
	vulnWriter   *kafka.Writer // dedicated writer for VULNERABILITY_MATCH topic
	graphWriter  *kafka.Writer // dedicated writer for security.graph_updates (T1.1, v8.0)
	cfg          *config.Config
}

// New creates a new Kafka publisher
func New(cfg *config.Config) (*Publisher, error) {
	w := &kafka.Writer{
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
			Key:   []byte(event.TenantID + ":" + event.ID),
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
