// Package kafkainput consumes a customer's own Kafka topics and feeds them
// into the normal ingest path.
//
// Depth item 4.2 / parity 6.10. Some estates already have every log they
// care about on a broker, and asking them to stand up a forwarder that
// re-publishes those records over HTTP is asking them to run a second
// pipeline to feed the first one.
//
// Where the tenant comes from
// ---------------------------
// From a minted ingest token, and from nowhere else. This is the same
// reasoning the syslog listener records: a Kafka record carries no
// authenticated principal, so a tenant read out of the payload or a header
// is caller-controlled, and a tenant a producer can set is a cross-tenant
// write waiting for someone to notice. One source therefore serves one
// tenant, and a deployment reading several tenants' topics declares one
// source per tenant.
//
// What this loop does about failure
// ---------------------------------
// Everything in internal/streamhealth, which is shared with the graph
// broadcaster. Briefly: a dial failure is transient and backs off; a
// `TopicAuthorizationFailed` is permanent, stops the loop and names the
// operator action; an undecodable record is poison and is skipped without
// penalising a subscription that is demonstrably working. Readiness names
// every source and its state, including when it is healthy, because a
// consumer detached from its topic behind a 200 that never mentions it is
// indistinguishable from an idle one.
package kafkainput

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/beenuar/aisoc/services/ingest/internal/inbox"
	"github.com/beenuar/aisoc/services/ingest/internal/kafkatls"
	"github.com/beenuar/aisoc/services/ingest/internal/normalizer"
	"github.com/beenuar/aisoc/services/ingest/internal/streamhealth"
	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/rs/zerolog/log"
	kafka "github.com/segmentio/kafka-go"
)

// Names is the subsystem's half of the shared health machinery.
var names = streamhealth.Names{
	Subsystem:    "kafka_input",
	MetricPrefix: "aisoc_ingest_kafka_input",
	BrokersVar:   "AISOC_KAFKA_INPUT_SOURCES[].brokers",
	TopicVar:     "AISOC_KAFKA_INPUT_SOURCES[].topic",
	GroupVar:     "AISOC_KAFKA_INPUT_SOURCES[].group_id",
}

// Classifier is exported so a test can assert the table this input uses is
// the shared one rather than a second copy.
var Classifier = streamhealth.NewClassifier(names)

var recordsAccepted = promauto.NewCounterVec(prometheus.CounterOpts{
	Name: "aisoc_ingest_kafka_input_records_total",
	Help: "Customer Kafka records accepted, by source name.",
}, []string{"source"})

// SourceConfig describes one customer topic.
//
// Deserialised from AISOC_KAFKA_INPUT_SOURCES, a JSON array, rather than
// from a flat set of environment variables: a deployment that reads three
// tenants' topics needs three of everything, and numbered variables are how
// a fourth source silently gets the third one's token.
type SourceConfig struct {
	// Name identifies the source in logs, metrics and readiness. Required,
	// because "source 2 is detached" is not an operator-facing sentence.
	Name string `json:"name"`
	// Brokers is a comma-separated bootstrap list. Split before it reaches
	// kafka.TCP, which is variadic and panics on a comma-joined string.
	Brokers string `json:"brokers"`
	// Topic is the customer's topic.
	Topic string `json:"topic"`
	// GroupID is this deployment's consumer group on that topic. Defaulted
	// per source rather than per process, so two sources cannot silently
	// join one group and split each other's partitions.
	GroupID string `json:"group_id"`
	// Token is a minted ingest token. The tenant comes from it.
	Token string `json:"token"`
	// TemplateID is the OCSF template each record is projected through.
	TemplateID string `json:"template_id"`
	// FromBeginning replays the topic from its earliest retained offset on
	// the first run of a new group. Off by default: attaching to a
	// customer's production topic and replaying a week of history into the
	// detection pipeline is not a thing to do by accident.
	FromBeginning bool `json:"from_beginning"`
	// MaxBytes caps one fetch. Zero takes the default.
	MaxBytes int `json:"max_bytes"`
}

func (c SourceConfig) validate() error {
	switch {
	case strings.TrimSpace(c.Name) == "":
		return errors.New("a source needs a name; it is what readiness and the logs call it")
	case strings.TrimSpace(c.Brokers) == "":
		return fmt.Errorf("source %q has no brokers", c.Name)
	case strings.TrimSpace(c.Topic) == "":
		return fmt.Errorf("source %q has no topic", c.Name)
	case strings.TrimSpace(c.Token) == "":
		return fmt.Errorf("source %q has no ingest token, so there is no tenant to attribute its records to; mint one with POST /api/v1/inbox/tokens", c.Name)
	case strings.TrimSpace(c.TemplateID) == "":
		return fmt.Errorf("source %q has no template_id, so its records cannot be normalised", c.Name)
	}
	return nil
}

// ParseSources reads the JSON array an operator supplies.
//
// An empty string is "no sources", which is not an error. A non-empty
// string that does not parse *is* an error and the service says so rather
// than starting with the input silently off — the whole class of defect
// this repository keeps finding is a feature that looks configured and is
// not.
func ParseSources(raw string) ([]SourceConfig, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}
	var sources []SourceConfig
	if err := json.Unmarshal([]byte(raw), &sources); err != nil {
		return nil, fmt.Errorf("AISOC_KAFKA_INPUT_SOURCES is not a JSON array of sources: %w", err)
	}
	seen := map[string]bool{}
	for i := range sources {
		if err := sources[i].validate(); err != nil {
			return nil, err
		}
		if seen[sources[i].Name] {
			return nil, fmt.Errorf("two sources are both named %q; readiness reports by name, so they must differ", sources[i].Name)
		}
		seen[sources[i].Name] = true
		if sources[i].GroupID == "" {
			// Per source, not per process. Two sources sharing a group id
			// on different topics is legal in Kafka and is almost never
			// what the operator meant.
			sources[i].GroupID = "aisoc-ingest-" + sources[i].Name
		}
	}
	return sources, nil
}

// TokenResolver is the half of inbox.Store this package needs.
type TokenResolver interface {
	Resolve(ctx context.Context, token string) (*inbox.Token, error)
}

// TemplateSource resolves a template id to a template.
type TemplateSource interface {
	Get(id string) (*inbox.Template, error)
}

// Publisher is the half of publisher.Publisher this package needs.
type Publisher interface {
	PublishBatch(ctx context.Context, events []*normalizer.NormalizedEvent) error
}

// Reader is the half of kafka.Reader this package needs, so the loop can be
// driven in a test without a broker. The thing under test is the failure
// handling, which is where the defects are.
type Reader interface {
	FetchMessage(ctx context.Context) (kafka.Message, error)
	CommitMessages(ctx context.Context, msgs ...kafka.Message) error
	Close() error
}

// Source is one running subscription.
type Source struct {
	cfg       SourceConfig
	reader    Reader
	tokens    TokenResolver
	templates TemplateSource
	pub       Publisher
	health    *streamhealth.State

	stopOnce sync.Once
	stopCh   chan struct{}
	done     chan struct{}
}

// NewSource wires one subscription. The reader is built here so a dial
// failure is visible at startup, but the *token* is resolved on first
// delivery: a resolver needs a database, and refusing to start because
// Postgres was slow would take the whole ingest service down with it.
func NewSource(cfg SourceConfig, tokens TokenResolver, templates TemplateSource, pub Publisher) (*Source, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	if tokens == nil || templates == nil || pub == nil {
		return nil, fmt.Errorf("kafka_input: source %q needs a token resolver, a template source and a publisher", cfg.Name)
	}

	brokers := splitBrokers(cfg.Brokers)
	if len(brokers) == 0 {
		return nil, fmt.Errorf("kafka_input: source %q has no usable broker address", cfg.Name)
	}
	// A nil Dialer is plaintext. Resolve refuses cleartext in a protected
	// environment, and a reader that cannot be built securely must not be
	// built at all.
	transport, err := kafkatls.Resolve()
	if err != nil {
		return nil, fmt.Errorf("kafka_input: source %q transport: %w", cfg.Name, err)
	}

	health := streamhealth.NewState(Classifier, cfg.Topic, 0)
	start := kafka.LastOffset
	if cfg.FromBeginning {
		start = kafka.FirstOffset
	}
	maxBytes := cfg.MaxBytes
	if maxBytes <= 0 {
		maxBytes = 10 * 1024 * 1024
	}
	rd := kafka.NewReader(kafka.ReaderConfig{
		Dialer:      transport.Dialer(),
		Brokers:     brokers,
		Topic:       cfg.Topic,
		GroupID:     cfg.GroupID,
		StartOffset: start,
		MinBytes:    1,
		MaxBytes:    maxBytes,
		// Without this the reader falls back to a silent logger, and with a
		// GroupID set that is where every dial, join and rebalance failure
		// goes while FetchMessage stays blocked. The single most likely
		// permanent fault — an unreachable or misnamed broker — would be
		// discarded inside the library before this package could see it.
		ErrorLogger: kafka.LoggerFunc(func(format string, args ...interface{}) {
			health.ObserveReaderError(fmt.Sprintf(format, args...))
		}),
	})
	return newSourceWithReader(cfg, rd, tokens, templates, pub, health), nil
}

func newSourceWithReader(cfg SourceConfig, rd Reader, tokens TokenResolver, templates TemplateSource, pub Publisher, health *streamhealth.State) *Source {
	return &Source{
		cfg:       cfg,
		reader:    rd,
		tokens:    tokens,
		templates: templates,
		pub:       pub,
		health:    health,
		stopCh:    make(chan struct{}),
		done:      make(chan struct{}),
	}
}

// Name is the operator-facing identifier.
func (s *Source) Name() string { return s.cfg.Name }

// Health is what readiness reports.
func (s *Source) Health() streamhealth.Health { return s.health.Health() }

// Start runs the consume loop until ctx is cancelled, Stop is called, or a
// permanent failure is reached.
func (s *Source) Start(ctx context.Context) {
	go s.run(ctx)
}

// Stop ends the loop and closes the reader.
func (s *Source) Stop() {
	s.stopOnce.Do(func() { close(s.stopCh) })
	<-s.done
	_ = s.reader.Close()
}

func (s *Source) run(ctx context.Context) {
	defer close(s.done)
	s.health.MarkAttached()
	defer func() { s.health.MarkDetached("loop exited") }()

	for {
		select {
		case <-ctx.Done():
			return
		case <-s.stopCh:
			return
		default:
		}

		msg, err := s.reader.FetchMessage(ctx)
		if err != nil {
			if ctx.Err() != nil || streamhealth.IsContextError(err) || s.stopping() {
				return
			}
			class, wait := s.health.RecordFailure(err)
			if class == streamhealth.ClassPermanent {
				// Stop. The wait is meaningless because no number of
				// retries changes the answer, and a loop that keeps
				// retrying a misconfiguration turns it into churn an
				// operator has to filter out of the logs.
				return
			}
			if !streamhealth.SleepFor(ctx, s.stopCh, wait) {
				return
			}
			continue
		}

		if err := s.handle(ctx, msg); err != nil {
			class, wait := s.health.RecordFailure(err)
			switch class {
			case streamhealth.ClassPoison:
				// One record is unreadable and the subscription is fine.
				// Committed so the loop does not re-read it forever, which
				// is the other way a poison record stops a working
				// consumer.
				s.commit(ctx, msg)
				continue
			case streamhealth.ClassPermanent:
				return
			case streamhealth.ClassTransient:
				// Not committed: a transient publish failure means this
				// record has not been delivered, and committing it would
				// lose it. Kafka is the one input in this service that can
				// withhold an acknowledgement, which is exactly why syslog
				// cannot.
				if !streamhealth.SleepFor(ctx, s.stopCh, wait) {
					return
				}
				continue
			default:
				// Named rather than folded into the transient arm: a class
				// this switch has never heard of is a change in
				// streamhealth that nobody propagated here, and treating
				// it as transient would retry something that may well be
				// permanent.
				log.Error().Str("class", string(class)).Str("source", s.cfg.Name).
					Msg("kafka_input: unhandled failure class; treating as transient but this needs a code change")
				if !streamhealth.SleepFor(ctx, s.stopCh, wait) {
					return
				}
				continue
			}
		}

		s.health.RecordMessage()
		recordsAccepted.WithLabelValues(s.cfg.Name).Inc()
		s.commit(ctx, msg)
	}
}

func (s *Source) commit(ctx context.Context, msg kafka.Message) {
	if err := s.reader.CommitMessages(ctx, msg); err != nil && ctx.Err() == nil {
		// Not fatal and not silent: an uncommitted offset means a replay on
		// restart, which the sink deduplicates, but an operator should know
		// the group is not advancing.
		log.Warn().Err(err).Str("source", s.cfg.Name).Int64("offset", msg.Offset).
			Msg("kafka_input: offset commit failed; these records will be re-read after a restart")
	}
}

// handle projects one record and publishes it.
//
// Errors are classified at the point they are produced rather than by the
// caller guessing: a record that is not JSON is poison, a revoked token is
// permanent, a publish failure is transient.
func (s *Source) handle(ctx context.Context, msg kafka.Message) error {
	var payload map[string]interface{}
	if err := json.Unmarshal(msg.Value, &payload); err != nil {
		// Not every topic carries JSON. A record that is not an object is
		// still usable as a log line, so it is wrapped rather than
		// refused — a plain text topic is a legitimate source, and
		// refusing it would be a receiver that drops everything while
		// looking attached.
		if len(msg.Value) == 0 {
			return streamhealth.Poison(fmt.Errorf("kafka_input: empty record at offset %d", msg.Offset))
		}
		payload = map[string]interface{}{"message": string(msg.Value)}
	}

	tok, err := s.tokens.Resolve(ctx, s.cfg.Token)
	if err != nil {
		// A revoked token and an unreachable database are different
		// problems and only one of them is fixed by waiting, so the
		// resolver's own error text is carried through and classified by
		// the shared table rather than flattened here.
		return fmt.Errorf("kafka_input: resolving the ingest token for source %q: %w", s.cfg.Name, err)
	}
	if tok.TemplateID != s.cfg.TemplateID {
		return streamhealth.Permanent(
			fmt.Errorf("kafka_input: source %q names template %q but its token was minted with %q",
				s.cfg.Name, s.cfg.TemplateID, tok.TemplateID),
			"mint a token with the template this source declares, or change the source's template_id to match",
		)
	}
	tmpl, err := s.templates.Get(s.cfg.TemplateID)
	if err != nil {
		return streamhealth.Permanent(
			fmt.Errorf("kafka_input: this build has no %q template", s.cfg.TemplateID),
			"set template_id to one this build ships; GET /v1/inbox/templates lists them",
		)
	}

	// Kafka's own metadata, carried as fields so a rule can clause on which
	// topic and partition a record came from. Set before Apply so a
	// template that maps them can, and prefixed so they cannot collide with
	// a customer field of the same name.
	payload["kafka_topic"] = msg.Topic
	payload["kafka_partition"] = msg.Partition
	payload["kafka_offset"] = msg.Offset
	if len(msg.Key) > 0 {
		payload["kafka_key"] = string(msg.Key)
	}
	for _, h := range msg.Headers {
		// Headers are a flat namespace the producer controls; they are
		// carried for context and are explicitly *not* read for a tenant.
		payload["kafka_header_"+h.Key] = string(h.Value)
	}

	receivedAt := time.Now().UTC().Format(time.RFC3339Nano)
	tenantID := tok.TenantID.String()
	connectorRef := "kafka-input:" + s.cfg.Name
	ocsf := tmpl.Apply(payload, tenantID, connectorRef, receivedAt)

	return s.pub.PublishBatch(ctx, []*normalizer.NormalizedEvent{{
		ID:                   uuid.NewString(),
		ConnectorID:          connectorRef,
		TenantID:             tenantID,
		OcsfEvent:            ocsf,
		NormalizationVersion: "kafka-input/1.0",
	}})
}

func (s *Source) stopping() bool {
	select {
	case <-s.stopCh:
		return true
	default:
		return false
	}
}

// splitBrokers turns a comma-joined bootstrap list into the slice
// kafka.ReaderConfig wants. kafka.TCP is variadic and a comma-joined string
// reaches it as one hostname, which panics rather than failing to dial.
func splitBrokers(s string) []string {
	out := []string{}
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}
