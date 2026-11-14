// Package streamhealth answers one question for every long-lived consumer
// in this service: can this loop tell a condition that will never resolve
// from one that might, and does it say so?
//
// Why it is a package rather than a file in one consumer
// -----------------------------------------------------
// The machinery here was written for the graph-update broadcaster, where a
// permanently unreachable broker produced a healthy container, restarts 0,
// /health 200 and a WebSocket that delivered nothing. The Kafka input added
// for depth item 4.2 is the same shape with a different payload, and a
// second copy of a classifier is how two readers come to disagree about
// what an error means. One table, two subscriptions.
//
// The three answers a loop can give
// ---------------------------------
//
//	transient   retrying can clear it — a broker restarting, a rebalance,
//	            a leader election. Back off and retry, quietly at first.
//	permanent   retrying cannot. The broker has refused this principal or
//	            the configuration is wrong. Say so at error level with the
//	            operator action, and stop pretending a retry is progress.
//	poison      one message is unreadable. The subscription is fine; the
//	            envelope is not. Count it, log it, take the next message —
//	            do not back off, because nothing is wrong with the source.
//
// A fourth state is not a class but a duration. A `no such host` on a
// broker name can genuinely be a startup race for a few seconds, and can
// equally be a variable nobody set. Guessing either way is wrong, so a
// failure is reported as transient and then escalates once it has outlived
// any plausible transient explanation: after StuckAfter the same failure is
// reported as *not resolving*, which is the point at which the operator's
// next move stops being "wait" and becomes "go and look".
package streamhealth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/rs/zerolog/log"
	kafka "github.com/segmentio/kafka-go"
)

// FailureClass is what the consume loop can do about an error, which is the
// only distinction that changes its behaviour.
type FailureClass string

const (
	// ClassTransient — a retry can clear it.
	ClassTransient FailureClass = "transient"
	// ClassPermanent — a retry cannot. Needs an operator.
	ClassPermanent FailureClass = "permanent"
	// ClassPoison — this message is unreadable; the subscription is healthy.
	ClassPoison FailureClass = "poison"
)

// DefaultStuckAfter is how long a transient failure may persist before it is
// reported as not resolving. Two minutes is longer than a broker restart, a
// leader election, or a Kubernetes service coming up behind its DNS record,
// and far shorter than the "forever" a bare retry loop implies.
const DefaultStuckAfter = 2 * time.Minute

// repeatEvery bounds how often a failure that keeps happening is re-logged.
// The first occurrence is always logged; the cap is what stops a fast retry
// loop turning a real signal into a log flood that hides it.
const repeatEvery = 30 * time.Second

// Backoff bounds. A flat short sleep against an unreachable broker is twenty
// reconnect attempts a second, forever.
const (
	BackoffMin = 50 * time.Millisecond
	BackoffMax = 30 * time.Second
)

// Names parameterises the two things that are genuinely per-subsystem: what
// the operator is told to change, and what the published metric series are
// called. Everything else about a failing Kafka subscription is the same
// wherever it happens.
type Names struct {
	// Subsystem prefixes every log line, e.g. "graph_ws".
	Subsystem string
	// MetricPrefix is the published series stem, e.g.
	// "aisoc_graph_ws_source". Existing series keep their names rather than
	// being renamed into a generic one, because a metric is an interface.
	MetricPrefix string
	// BrokersVar, TopicVar and GroupVar are the environment variables an
	// operator would edit. Advice that says "check the configuration" is
	// not advice.
	BrokersVar string
	TopicVar   string
	GroupVar   string
}

func (n Names) withDefaults() Names {
	if n.Subsystem == "" {
		n.Subsystem = "stream"
	}
	if n.MetricPrefix == "" {
		n.MetricPrefix = "aisoc_" + n.Subsystem + "_source"
	}
	if n.BrokersVar == "" {
		n.BrokersVar = "KAFKA_BROKERS"
	}
	if n.TopicVar == "" {
		n.TopicVar = "the configured topic"
	}
	if n.GroupVar == "" {
		n.GroupVar = "the configured consumer group"
	}
	return n
}

// metrics is one set of series per MetricPrefix. Registering the same
// collector name twice panics, so the set is built once and shared by every
// State using that prefix.
type metrics struct {
	attached *prometheus.GaugeVec
	errors   *prometheus.CounterVec
	stuck    *prometheus.GaugeVec
}

var (
	metricsMu sync.Mutex
	metricsBy = map[string]*metrics{}
)

func metricsFor(prefix string) *metrics {
	metricsMu.Lock()
	defer metricsMu.Unlock()
	if m, ok := metricsBy[prefix]; ok {
		return m
	}
	m := &metrics{
		attached: promauto.NewGaugeVec(prometheus.GaugeOpts{
			Name: prefix + "_attached",
			Help: "1 when the consumer is attached to its topic, 0 when it is not.",
		}, []string{"topic"}),
		errors: promauto.NewCounterVec(prometheus.CounterOpts{
			Name: prefix + "_errors_total",
			Help: "Errors from the subscription, by class (transient, permanent, poison).",
		}, []string{"topic", "class"}),
		stuck: promauto.NewGaugeVec(prometheus.GaugeOpts{
			Name: prefix + "_not_resolving",
			Help: "1 when the subscription has been failing for longer than a transient fault explains.",
		}, []string{"topic"}),
	}
	metricsBy[prefix] = m
	return m
}

// permanentError marks an error the loop must not treat as retriable, and
// carries the action that would actually fix it.
type permanentError struct {
	err    error
	advice string
}

func (e *permanentError) Error() string { return e.err.Error() }
func (e *permanentError) Unwrap() error { return e.err }

// Permanent wraps err so the consume loop stops retrying and reports advice
// as the operator's next move. A source implementation calls this when it
// knows retrying is futile.
func Permanent(err error, advice string) error {
	if err == nil {
		return nil
	}
	return &permanentError{err: err, advice: advice}
}

// poisonError marks an error that is about one message rather than about the
// subscription.
type poisonError struct{ err error }

func (e *poisonError) Error() string { return e.err.Error() }
func (e *poisonError) Unwrap() error { return e.err }

// Poison wraps err so the loop skips this message without backing off or
// treating the source as unhealthy.
func Poison(err error) error {
	if err == nil {
		return nil
	}
	return &poisonError{err: err}
}

// advisedError is a transient error that still has a known remedy.
type advisedError struct {
	err    error
	advice string
}

func (e *advisedError) Error() string { return e.err.Error() }
func (e *advisedError) Unwrap() error { return e.err }

// Advised wraps a retriable error that nonetheless has a known remedy, so
// the operator reads the remedy rather than watching the retry.
func Advised(err error, advice string) error {
	if err == nil {
		return nil
	}
	return &advisedError{err: err, advice: advice}
}

// Classifier turns an error into a class and an operator action.
type Classifier struct {
	names     Names
	permanent map[kafka.Error]string
	patterns  []readerPattern
}

type readerPattern struct {
	substring string
	permanent bool
	advice    string
}

// NewClassifier builds the per-subsystem error table.
func NewClassifier(names Names) *Classifier {
	n := names.withDefaults()
	c := &Classifier{names: n}

	// The codes where no number of retries by this client changes the
	// answer: the broker has refused this principal, cannot speak to this
	// client, or was handed a name it will never accept. Each needs a
	// person.
	//
	// Enumerated rather than derived from kafka.Error.Temporary(), which is
	// upstream's transcription of the protocol's "retriable" column and
	// answers a subtly different question. RebalanceInProgress is not
	// retriable in that sense — the client is meant to rejoin, not resend —
	// but it is a routine event during every deploy, and stopping the
	// consumer on it would turn this into an outage.
	// UnknownTopicOrPartition is likewise retriable in the table and
	// genuinely clears when the topic is created. Deciding by negation
	// would have got both wrong.
	c.permanent = map[kafka.Error]string{
		kafka.TopicAuthorizationFailed:   "grant this client read on the topic, or point it at one it may read",
		kafka.GroupAuthorizationFailed:   "grant this client access to the consumer group, or change " + n.GroupVar,
		kafka.ClusterAuthorizationFailed: "the broker refused this principal; check the credentials this service runs with",
		kafka.SASLAuthenticationFailed:   "the broker rejected these credentials; they will not start working on their own",
		kafka.UnsupportedSASLMechanism:   "the broker does not offer this SASL mechanism; reconfigure the client",
		kafka.IllegalSASLState:           "the SASL handshake was attempted out of order; this is a client configuration fault",
		kafka.UnsupportedVersion:         "this client and this broker cannot agree on a protocol version",
		kafka.InvalidTopic:               "the topic name is not valid; check " + n.TopicVar,
		kafka.InvalidGroupId:             "the consumer group id is not valid; check " + n.GroupVar,
		kafka.SecurityDisabled:           "the broker has security disabled and cannot answer this request",
	}

	// The same set again, matched against the Title() spelling kafka-go
	// prints into its error logger. Stated twice because the two arrive by
	// different routes; EveryPermanentCodeIsRecognisedInAReaderLogLine
	// keeps them equal.
	c.patterns = []readerPattern{
		{"topic authorization failed", true, c.permanent[kafka.TopicAuthorizationFailed]},
		{"group authorization failed", true, c.permanent[kafka.GroupAuthorizationFailed]},
		{"cluster authorization failed", true, c.permanent[kafka.ClusterAuthorizationFailed]},
		{"sasl authentication failed", true, c.permanent[kafka.SASLAuthenticationFailed]},
		{"unsupported sasl mechanism", true, c.permanent[kafka.UnsupportedSASLMechanism]},
		{"illegal sasl state", true, c.permanent[kafka.IllegalSASLState]},
		{"unsupported version", true, c.permanent[kafka.UnsupportedVersion]},
		{"invalid topic", true, c.permanent[kafka.InvalidTopic]},
		{"invalid group id", true, c.permanent[kafka.InvalidGroupId]},
		{"security disabled", true, c.permanent[kafka.SecurityDisabled]},
		{"unknown topic or partition", false, "create the topic, or enable auto-creation on the broker"},
		{"connection refused", false, "nothing is listening on the broker address; check " + n.BrokersVar + " and that the broker is up"},
		{"no such host", false, "the broker hostname does not resolve; check " + n.BrokersVar},
		{"i/o timeout", false, "the broker accepted no answer in time; check network reachability between this service and the broker"},
	}
	return c
}

// Names reports the configured names, so a caller can quote the same
// variable an operator would edit.
func (c *Classifier) Names() Names { return c.names }

// PermanentCodes exposes the declared table so a test can walk it in both
// directions.
func (c *Classifier) PermanentCodes() map[kafka.Error]string {
	out := make(map[kafka.Error]string, len(c.permanent))
	for k, v := range c.permanent {
		out[k] = v
	}
	return out
}

// Classify answers the only question the loop needs: what can be done about
// this error, and what should an operator be told.
//
// Advice is returned for transient errors too when there is a known remedy.
// An absent topic is retriable — it appears the moment somebody creates it —
// but telling the operator that is the difference between a log line they
// can act on and one they can only watch.
func (c *Classifier) Classify(err error) (FailureClass, string) {
	if err == nil {
		return ClassTransient, ""
	}

	var poison *poisonError
	if errors.As(err, &poison) {
		return ClassPoison, "the message could not be decoded; the subscription is unaffected"
	}

	var permanent *permanentError
	if errors.As(err, &permanent) {
		return ClassPermanent, permanent.advice
	}

	var advised *advisedError
	if errors.As(err, &advised) {
		return ClassTransient, advised.advice
	}

	var kerr kafka.Error
	if errors.As(err, &kerr) {
		if advice, ok := c.permanent[kerr]; ok {
			return ClassPermanent, advice
		}
		if kerr == kafka.UnknownTopicOrPartition {
			return ClassTransient, "create the topic, or enable auto-creation on the broker"
		}
		return ClassTransient, ""
	}

	// A JSON decode reaching here unwrapped is still about one message.
	var syntax *json.SyntaxError
	var unmarshal *json.UnmarshalTypeError
	if errors.As(err, &syntax) || errors.As(err, &unmarshal) {
		return ClassPoison, "the message could not be decoded; the subscription is unaffected"
	}

	// Everything else — dial failures, EOF, timeouts, a broker mid-restart —
	// is transient by default, because assuming otherwise would stop a loop
	// that a retry really would have fixed. What keeps that default honest
	// is the elapsed-time escalation in State: a transient failure that
	// outlives StuckAfter is reported as not resolving.
	return ClassTransient, ""
}

// ReaderError turns kafka-go's formatted log line back into something
// Classify can reason about. The library hands over a string, never an error
// value, so the classification has to come from the text.
func (c *Classifier) ReaderError(message string) error {
	lower := strings.ToLower(message)
	for _, p := range c.patterns {
		if !strings.Contains(lower, p.substring) {
			continue
		}
		if p.permanent {
			return Permanent(errors.New(message), p.advice)
		}
		return Advised(errors.New(message), p.advice)
	}
	return errors.New(message)
}

// State is everything the loop and the readiness probe know about one
// subscription. One object shared by the reader and the loop, so the errors
// kafka-go notices on its own land in the same place as the ones the loop
// sees.
//
// Safe for concurrent use.
type State struct {
	classifier *Classifier
	metrics    *metrics
	topic      string
	stuckAfter time.Duration

	mu                  sync.Mutex
	attached            bool
	permanent           bool
	permanentAdvice     string
	consecutive         uint64
	transientFailures   uint64
	permanentFailures   uint64
	poisonMessages      uint64
	failingSince        time.Time
	lastError           string
	lastAdvice          string
	lastClass           FailureClass
	lastMessageAt       time.Time
	everReceived        bool
	messagesReceived    uint64
	lastLoggedAt        time.Time
	lastLoggedSignature string
}

// NewState builds the shared state for a subscription to topic. A
// stuckAfter of zero means DefaultStuckAfter.
func NewState(classifier *Classifier, topic string, stuckAfter time.Duration) *State {
	if classifier == nil {
		classifier = NewClassifier(Names{})
	}
	if stuckAfter <= 0 {
		stuckAfter = DefaultStuckAfter
	}
	if topic == "" {
		topic = "unknown"
	}
	m := metricsFor(classifier.names.MetricPrefix)
	m.attached.WithLabelValues(topic).Set(0)
	m.stuck.WithLabelValues(topic).Set(0)
	return &State{classifier: classifier, metrics: m, topic: topic, stuckAfter: stuckAfter}
}

// Health is a point-in-time copy, safe to serialise.
type Health struct {
	Topic               string        `json:"topic"`
	Attached            bool          `json:"attached"`
	NotResolving        bool          `json:"not_resolving"`
	PermanentFailure    bool          `json:"permanent_failure"`
	Advice              string        `json:"advice,omitempty"`
	ConsecutiveFailures uint64        `json:"consecutive_failures"`
	TransientFailures   uint64        `json:"transient_failures"`
	PermanentFailures   uint64        `json:"permanent_failures"`
	PoisonMessages      uint64        `json:"poison_messages"`
	FailingForSeconds   float64       `json:"failing_for_seconds,omitempty"`
	LastError           string        `json:"last_error,omitempty"`
	LastErrorClass      FailureClass  `json:"last_error_class,omitempty"`
	EverReceived        bool          `json:"ever_received"`
	MessagesReceived    uint64        `json:"messages_received"`
	SinceLastMessage    time.Duration `json:"-"`
}

// Healthy is the one-line verdict a readiness probe branches on: the loop is
// attached and is not sitting on a fault that has outlived a transient
// explanation.
func (h Health) Healthy() bool {
	return h.Attached && !h.NotResolving && !h.PermanentFailure
}

// Reason is a human sentence for the current state, or "" when healthy.
func (h Health) Reason() string {
	switch {
	case h.PermanentFailure:
		return fmt.Sprintf("permanent source failure on %s: %s (%s)", h.Topic, h.LastError, h.Advice)
	case !h.Attached:
		return fmt.Sprintf("not consuming %s", h.Topic)
	case h.NotResolving:
		reason := fmt.Sprintf("source for %s has been failing for %.0fs (%d consecutive): %s",
			h.Topic, h.FailingForSeconds, h.ConsecutiveFailures, h.LastError)
		if h.Advice != "" {
			reason += " — " + h.Advice
		}
		return reason
	default:
		return ""
	}
}

// Detail is what readiness shows for a *healthy* subscription as well as a
// broken one. "attached" alone is a lie of omission for a consumer: a quiet
// topic is a legitimate state, so the detail carries what it is attached to
// and how much it has seen, which is what separates "nothing is being sent"
// from "everything is being dropped".
func (h Health) Detail() string {
	if reason := h.Reason(); reason != "" {
		return reason
	}
	detail := fmt.Sprintf("consuming %s; received %d, poison %d", h.Topic, h.MessagesReceived, h.PoisonMessages)
	if !h.EverReceived {
		detail += " (nothing has arrived yet)"
	}
	return detail
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

// Health returns a copy of the current state.
func (s *State) Health() Health {
	if s == nil {
		return Health{}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	h := Health{
		Topic:               s.topic,
		Attached:            s.attached,
		NotResolving:        s.notResolvingLocked(),
		PermanentFailure:    s.permanent,
		Advice:              firstNonEmpty(s.permanentAdvice, s.lastAdvice),
		ConsecutiveFailures: s.consecutive,
		TransientFailures:   s.transientFailures,
		PermanentFailures:   s.permanentFailures,
		PoisonMessages:      s.poisonMessages,
		LastError:           s.lastError,
		LastErrorClass:      s.lastClass,
		EverReceived:        s.everReceived,
		MessagesReceived:    s.messagesReceived,
	}
	if !s.failingSince.IsZero() {
		h.FailingForSeconds = time.Since(s.failingSince).Seconds()
	}
	if !s.lastMessageAt.IsZero() {
		h.SinceLastMessage = time.Since(s.lastMessageAt)
	}
	return h
}

// notResolvingLocked reports whether the current run of failures has
// outlived any explanation a retry would fix. A permanent classification is
// immediately not-resolving; a transient one has to earn it by lasting.
//
// Deliberately not "no message in N seconds": a quiet topic is a legitimate
// state and judging it would make an idle deployment look broken, which is
// the mirror image of the defect this package exists for.
func (s *State) notResolvingLocked() bool {
	if s.permanent {
		return true
	}
	if s.failingSince.IsZero() {
		return false
	}
	return time.Since(s.failingSince) >= s.stuckAfter
}

// MarkAttached records that the loop has begun iterating the subscription.
func (s *State) MarkAttached() {
	if s == nil {
		return
	}
	s.mu.Lock()
	s.attached = true
	s.mu.Unlock()
	s.metrics.attached.WithLabelValues(s.topic).Set(1)
}

// MarkDetached records that the loop has stopped. reason is logged so a
// subscription that ends says so, which is the whole point.
func (s *State) MarkDetached(reason string) {
	if s == nil {
		return
	}
	s.mu.Lock()
	wasAttached := s.attached
	s.attached = false
	s.mu.Unlock()
	s.metrics.attached.WithLabelValues(s.topic).Set(0)
	if wasAttached {
		log.Warn().Str("topic", s.topic).Str("reason", reason).
			Msg(s.classifier.names.Subsystem + ": consumer detached from its topic; nothing further will be delivered")
	}
}

// RecordMessage resets the failure run after a message arrives, and says so
// if the source had been failing. A recovery that is not logged leaves the
// last line in the log describing a fault that has since cleared.
func (s *State) RecordMessage() {
	if s == nil {
		return
	}
	s.mu.Lock()
	failures := s.consecutive
	since := s.failingSince
	s.consecutive = 0
	s.failingSince = time.Time{}
	s.lastError = ""
	s.lastAdvice = ""
	s.lastClass = ""
	s.lastMessageAt = time.Now()
	s.everReceived = true
	s.messagesReceived++
	s.mu.Unlock()

	s.metrics.stuck.WithLabelValues(s.topic).Set(0)
	if failures > 0 {
		event := log.Info()
		if !since.IsZero() {
			event = event.Dur("failing_for", time.Since(since))
		}
		event.Str("topic", s.topic).Uint64("consecutive_failures", failures).
			Msg(s.classifier.names.Subsystem + ": source recovered")
	}
}

// RecordPoison counts one unreadable message.
//
// It clears the failure run for the same reason RecordMessage does: a poison
// message only exists because the read returned, so the subscription is
// demonstrably working. Leaving the run set would let a stream of malformed
// messages from one bad producer be reported as a source that is not
// resolving, which is the opposite of what is happening.
func (s *State) RecordPoison(err error) {
	if s == nil {
		return
	}
	s.mu.Lock()
	s.poisonMessages++
	count := s.poisonMessages
	s.consecutive = 0
	s.failingSince = time.Time{}
	s.lastMessageAt = time.Now()
	s.everReceived = true
	s.mu.Unlock()
	s.metrics.errors.WithLabelValues(s.topic, string(ClassPoison)).Inc()
	s.metrics.stuck.WithLabelValues(s.topic).Set(0)
	log.Warn().Err(err).Str("topic", s.topic).Uint64("poison_messages", count).
		Msg(s.classifier.names.Subsystem + ": undecodable message skipped; the subscription is unaffected")
}

// RecordFailure classifies err, updates the counters, and logs it at a level
// that matches what an operator can do about it.
//
// Returns the class and how long to wait before the next attempt. A caller
// that gets ClassPermanent should stop: the wait is meaningless because no
// number of retries changes the answer.
func (s *State) RecordFailure(err error) (FailureClass, time.Duration) {
	if s == nil {
		return ClassTransient, BackoffMin
	}
	class, advice := s.classifier.Classify(err)
	if class == ClassPoison {
		s.RecordPoison(err)
		return class, 0
	}

	now := time.Now()
	s.mu.Lock()
	s.consecutive++
	if s.failingSince.IsZero() {
		s.failingSince = now
	}
	s.lastError = truncate(err.Error(), 300)
	s.lastClass = class
	s.lastAdvice = advice
	if class == ClassPermanent {
		s.permanentFailures++
		s.permanent = true
		s.permanentAdvice = advice
	} else {
		s.transientFailures++
	}
	consecutive := s.consecutive
	failingFor := now.Sub(s.failingSince)
	notResolving := s.notResolvingLocked()
	// Rate limit on the *text* of the error, so a changed error is always
	// reported immediately and only genuine repetition is suppressed.
	signature := string(class) + "|" + s.lastError
	shouldLog := signature != s.lastLoggedSignature || now.Sub(s.lastLoggedAt) >= repeatEvery
	if shouldLog {
		s.lastLoggedAt = now
		s.lastLoggedSignature = signature
	}
	topic := s.topic
	s.mu.Unlock()

	s.metrics.errors.WithLabelValues(topic, string(class)).Inc()
	if notResolving {
		s.metrics.stuck.WithLabelValues(topic).Set(1)
	}
	if shouldLog {
		logFailure(s.classifier.names.Subsystem, class, topic, advice, err, consecutive, failingFor, notResolving)
	}
	return class, BackoffFor(consecutive)
}

// ObserveReaderError records an error the Kafka reader reported to its own
// error logger rather than returning from ReadMessage. Those are the dial,
// join and rebalance failures a consumer group retries internally — the ones
// that are otherwise discarded entirely.
func (s *State) ObserveReaderError(message string) {
	if s == nil {
		// Still logged: a source whose errors go nowhere is the defect this
		// package exists to close.
		log.Warn().Str("detail", message).Msg("stream: kafka reader error with no health state attached")
		return
	}
	s.RecordFailure(s.classifier.ReaderError(message))
}

func logFailure(subsystem string, class FailureClass, topic, advice string, err error, consecutive uint64, failingFor time.Duration, notResolving bool) {
	event := log.Warn()
	if class == ClassPermanent || notResolving {
		event = log.Error()
	}
	event = event.Err(err).
		Str("topic", topic).
		Str("class", string(class)).
		Uint64("consecutive_failures", consecutive)
	if failingFor > 0 {
		event = event.Dur("failing_for", failingFor)
	}
	if advice != "" {
		event = event.Str("operator_action", advice)
	}
	switch {
	case class == ClassPermanent:
		event.Msg(subsystem + ": source failure will not clear on its own; retrying is not progress")
	case notResolving:
		event.Msg(subsystem + ": source has been failing for longer than a transient fault explains; treat this as a misconfiguration, not churn")
	default:
		event.Msg(subsystem + ": source failure; retrying")
	}
}

// BackoffFor grows the wait with the length of the failure run, capped. The
// first few retries stay fast so a broker blip costs nothing; a sustained
// outage stops being a reconnect storm.
func BackoffFor(consecutive uint64) time.Duration {
	wait := BackoffMin
	for i := uint64(1); i < consecutive && wait < BackoffMax; i++ {
		wait *= 2
	}
	if wait > BackoffMax {
		wait = BackoffMax
	}
	return wait
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// SleepFor waits for d or until the loop is asked to stop, whichever first.
// Returns false if the loop should exit.
func SleepFor(ctx context.Context, stopCh <-chan struct{}, d time.Duration) bool {
	if d <= 0 {
		return true
	}
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-stopCh:
		return false
	case <-timer.C:
		return true
	}
}

// IsContextError keeps an ordinary shutdown out of the failure counters. A
// cancelled context is the operator stopping the service, not a fault.
func IsContextError(err error) bool {
	return errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
}
