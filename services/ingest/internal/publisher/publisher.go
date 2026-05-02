// Package publisher handles publishing normalized events to Kafka
package publisher

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/cyble/aisoc/services/ingest/internal/config"
	"github.com/cyble/aisoc/services/ingest/internal/enrichment"
	"github.com/cyble/aisoc/services/ingest/internal/normalizer"
	"github.com/rs/zerolog/log"
	kafka "github.com/segmentio/kafka-go"
)

// Publisher sends normalized events to Kafka
type Publisher struct {
	writer      *kafka.Writer
	vulnWriter  *kafka.Writer // dedicated writer for VULNERABILITY_MATCH topic
	cfg         *config.Config
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

	return &Publisher{
		writer:     w,
		vulnWriter: vulnWriter,
		cfg:        cfg,
	}, nil
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
}
