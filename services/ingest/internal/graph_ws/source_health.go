// Failure classification and reporting for the graph_ws envelope source.
//
// Why this file exists
// --------------------
// The consume loop answered every source error the same way: a 50ms sleep
// and `continue`, with the error discarded. It could not die the way the
// UEBA consumer did — the loop survives — but it could do something no
// better. A broker that is never coming back produced a healthy container,
// restarts 0, /health 200, and a WebSocket that delivered nothing, with no
// line in any log and no counter anywhere. That is the same defect as a
// silent death: a permanent failure wearing the costume of a transient one.
//
// Worse, most of those errors never even reached the loop.
// `kafka.NewReader` falls back to a silent logger when `ErrorLogger` is nil
// (see reader.go `withErrorLogger`), and with a GroupID set the consumer
// group's dial, join, and rebalance failures are reported *only* through
// that logger — `ReadMessage` stays blocked. So the single most likely
// permanent fault, an unreachable or misnamed broker, was discarded inside
// the library before this package ever saw it. `NewKafkaSource` now wires
// `ErrorLogger` here.
//
// The three answers a loop can give
// ---------------------------------
// The question this file exists to answer is the one the repository already
// asked of the playbook bridge, where `BridgeUnavailable` was split into a
// permanent and a transient half: *can this loop distinguish a condition
// that will never resolve from one that might, and does it say so?*
//
//	transient   retrying can clear it — a broker restarting, a rebalance,
//	            a leader election. Back off and retry, quietly at first.
//	permanent   retrying cannot. The Kafka protocol's own error table says
//	            so (`kafka.Error.Temporary()` is the retriable set), or the
//	            configuration is wrong. Say so at error level with the
//	            operator action, and stop pretending a retry is progress.
//	poison      one message is unreadable. The subscription is fine; the
//	            envelope is not. Count it, log it, take the next message —
//	            do not back off, because nothing is wrong with the source.
//
// A fourth state is not a class but a duration. A `no such host` on a
// broker name can genuinely be a startup race for a few seconds, and can
// equally be a variable nobody set. Guessing either way is wrong, so the
// loop reports the first as transient and then escalates once the condition
// has outlived any plausible transient explanation: after `StuckAfter` the
// same failure is reported as *not resolving*, which is the point at which
// the operator's next move stops being "wait" and becomes "go and look".
package graph_ws

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
// and far shorter than the "forever" the previous code implied.
const DefaultStuckAfter = 2 * time.Minute

// repeatEvery bounds how often a failure that keeps happening is re-logged.
// The first occurrence is always logged; the cap is what stops a 50ms retry
// loop turning a real signal into a log flood that hides it.
const repeatEvery = 30 * time.Second

// Backoff bounds. The old loop used a flat 50ms, which against an
// unreachable broker is twenty reconnect attempts a second, forever.
const (
	backoffMin = 50 * time.Millisecond
	backoffMax = 30 * time.Second
)

var (
	sourceAttached = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "aisoc_graph_ws_source_attached",
		Help: "1 when the graph_ws broadcaster is consuming its topic, 0 when it is not.",
	}, []string{"topic"})

	sourceErrors = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "aisoc_graph_ws_source_errors_total",
		Help: "Errors from the graph_ws envelope source, by class (transient, permanent, poison).",
	}, []string{"topic", "class"})

	sourceStuck = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "aisoc_graph_ws_source_not_resolving",
		Help: "1 when the graph_ws source has been failing for longer than a transient fault explains.",
	}, []string{"topic"})
)

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

// permanentProtocolErrors are the Kafka error codes where no number of
// retries by this client changes the answer: the broker has refused this
// principal, cannot speak to this client, or was handed a name it will never
// accept. Each needs a person.
//
// Enumerated rather than derived from `kafka.Error.Temporary()`, which is
// upstream's transcription of the protocol's "retriable" column and answers
// a subtly different question. `RebalanceInProgress` is not retriable in
// that sense — the client is meant to rejoin, not resend — but it is a
// routine event during every deploy, and stopping the consumer on it would
// turn this fix into an outage. `UnknownTopicOrPartition` is likewise
// retriable in the table and genuinely clears when the topic is created.
// Deciding by negation would have got both wrong; TestClassifyCreditsOnly...
// walks the whole table so that stays true as the table grows.
var permanentProtocolErrors = map[kafka.Error]string{
	kafka.TopicAuthorizationFailed:   "grant this client read on the topic, or point it at one it may read",
	kafka.GroupAuthorizationFailed:   "grant this client access to the consumer group, or change AISOC_GRAPH_WS_GROUP_ID",
	kafka.ClusterAuthorizationFailed: "the broker refused this principal; check the credentials this service runs with",
	kafka.SASLAuthenticationFailed:   "the broker rejected these credentials; they will not start working on their own",
	kafka.UnsupportedSASLMechanism:   "the broker does not offer this SASL mechanism; reconfigure the client",
	kafka.IllegalSASLState:           "the SASL handshake was attempted out of order; this is a client configuration fault",
	kafka.UnsupportedVersion:         "this client and this broker cannot agree on a protocol version",
	kafka.InvalidTopic:               "the topic name is not valid; check AISOC_GRAPH_UPDATES_TOPIC",
	kafka.InvalidGroupId:             "the consumer group id is not valid; check AISOC_GRAPH_WS_GROUP_ID",
	kafka.SecurityDisabled:           "the broker has security disabled and cannot answer this request",
}

// classify answers the only question the loop needs: what can be done about
// this error, and what should an operator be told.
//
// Advice is returned for transient errors too when there is a known remedy.
// An absent topic is retriable — it appears the moment somebody creates it —
// but telling the operator that is the difference between a log line they
// can act on and one they can only watch.
func classify(err error) (FailureClass, string) {
	if err == nil {
		return ClassTransient, ""
	}

	var poison *poisonError
	if errors.As(err, &poison) {
		return ClassPoison, "the envelope could not be decoded; the subscription is unaffected"
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
		if advice, ok := permanentProtocolErrors[kerr]; ok {
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
		return ClassPoison, "the envelope could not be decoded; the subscription is unaffected"
	}

	// Everything else — dial failures, EOF, timeouts, a broker mid-restart —
	// is transient by default, because assuming otherwise would stop a loop
	// that a retry really would have fixed. What keeps that default honest
	// is the elapsed-time escalation in SourceState: a transient failure
	// that outlives DefaultStuckAfter is reported as not resolving.
	return ClassTransient, ""
}

// SourceState is everything the loop, the readiness probe, and the WebSocket
// upgrade handler know about the subscription. One object shared by the
// source and the broadcaster, so the errors the Kafka reader notices on its
// own land in the same place as the ones the loop sees.
//
// Safe for concurrent use.
type SourceState struct {
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
	lastLoggedAt        time.Time
	lastLoggedSignature string
}

// NewSourceState builds the shared state for a subscription to topic.
// stuckAfter of zero means DefaultStuckAfter.
func NewSourceState(topic string, stuckAfter time.Duration) *SourceState {
	if stuckAfter <= 0 {
		stuckAfter = DefaultStuckAfter
	}
	if topic == "" {
		topic = "unknown"
	}
	sourceAttached.WithLabelValues(topic).Set(0)
	sourceStuck.WithLabelValues(topic).Set(0)
	return &SourceState{topic: topic, stuckAfter: stuckAfter}
}

// SourceHealth is a point-in-time copy, safe to serialise.
type SourceHealth struct {
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
	SinceLastMessage    time.Duration `json:"-"`
}

// Healthy is the one-line verdict the WebSocket handler and the readiness
// probe branch on: the loop is attached and is not sitting on a fault that
// has outlived a transient explanation.
func (h SourceHealth) Healthy() bool {
	return h.Attached && !h.NotResolving && !h.PermanentFailure
}

// Reason is a human sentence for the current state, or "" when healthy.
func (h SourceHealth) Reason() string {
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

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

// Health returns a copy of the current state.
func (s *SourceState) Health() SourceHealth {
	if s == nil {
		return SourceHealth{}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	h := SourceHealth{
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
// the mirror image of the defect this file exists for.
func (s *SourceState) notResolvingLocked() bool {
	if s.permanent {
		return true
	}
	if s.failingSince.IsZero() {
		return false
	}
	return time.Since(s.failingSince) >= s.stuckAfter
}

// MarkAttached records that the loop has begun iterating the subscription.
func (s *SourceState) MarkAttached() {
	if s == nil {
		return
	}
	s.mu.Lock()
	s.attached = true
	s.mu.Unlock()
	sourceAttached.WithLabelValues(s.topic).Set(1)
}

// MarkDetached records that the loop has stopped. reason is logged so a
// subscription that ends says so, which is the whole point.
func (s *SourceState) MarkDetached(reason string) {
	if s == nil {
		return
	}
	s.mu.Lock()
	wasAttached := s.attached
	s.attached = false
	s.mu.Unlock()
	sourceAttached.WithLabelValues(s.topic).Set(0)
	if wasAttached {
		log.Warn().Str("topic", s.topic).Str("reason", reason).
			Msg("graph_ws: consumer detached from its topic; no envelopes will reach subscribers")
	}
}

// RecordMessage resets the failure run after a message arrives, and says so
// if the source had been failing. A recovery that is not logged leaves the
// last line in the log describing a fault that has since cleared.
func (s *SourceState) RecordMessage() {
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
	s.mu.Unlock()

	sourceStuck.WithLabelValues(s.topic).Set(0)
	if failures > 0 {
		event := log.Info()
		if !since.IsZero() {
			event = event.Dur("failing_for", time.Since(since))
		}
		event.Str("topic", s.topic).Uint64("consecutive_failures", failures).
			Msg("graph_ws: source recovered")
	}
}

// RecordPoison counts one unreadable envelope.
//
// It clears the failure run for the same reason RecordMessage does: a poison
// envelope only exists because ReadMessage returned, so the subscription is
// demonstrably working. Leaving the run set would let a stream of malformed
// envelopes from one bad producer be reported as a source that is not
// resolving, which is the opposite of what is happening.
func (s *SourceState) RecordPoison(err error) {
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
	sourceErrors.WithLabelValues(s.topic, string(ClassPoison)).Inc()
	sourceStuck.WithLabelValues(s.topic).Set(0)
	log.Warn().Err(err).Str("topic", s.topic).Uint64("poison_messages", count).
		Msg("graph_ws: undecodable envelope skipped; the subscription is unaffected")
}

// RecordFailure classifies err, updates the counters, and logs it at a level
// that matches what an operator can do about it.
//
// Returns the class and how long to wait before the next attempt. A caller
// that gets ClassPermanent should stop: the wait is meaningless because no
// number of retries changes the answer.
func (s *SourceState) RecordFailure(err error) (FailureClass, time.Duration) {
	class, advice := classify(err)
	if class == ClassPoison {
		s.RecordPoison(err)
		return class, 0
	}
	if s == nil {
		logFailure(class, "unknown", advice, err, 1, 0, false)
		return class, backoffMin
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

	sourceErrors.WithLabelValues(topic, string(class)).Inc()
	if notResolving {
		sourceStuck.WithLabelValues(topic).Set(1)
	}
	if shouldLog {
		logFailure(class, topic, advice, err, consecutive, failingFor, notResolving)
	}
	return class, backoffFor(consecutive)
}

// ObserveReaderError records an error the Kafka reader reported to its own
// error logger rather than returning from ReadMessage. Those are the dial,
// join, and rebalance failures a consumer group retries internally — the
// ones that were being discarded entirely.
func (s *SourceState) ObserveReaderError(message string) {
	s.RecordFailure(readerError(message))
}

// readerError turns kafka-go's formatted log line back into something
// classify can reason about.
//
// The library hands over a string, never an error value, so the
// classification has to come from the text. Every pattern is matched against
// the `Title()` spelling kafka-go prints for a protocol code, and the
// permanent ones are the same set `permanentProtocolErrors` names — stated
// twice because the two arrive by different routes, and kept honest by
// TestEveryPermanentCodeIsAlsoRecognisedInAReaderLogLine.
//
// A pattern that carries advice without being permanent is deliberate: an
// absent topic is worth explaining and is not worth stopping for.
func readerError(message string) error {
	lower := strings.ToLower(message)
	for _, p := range readerPatterns {
		if !strings.Contains(lower, p.substring) {
			continue
		}
		if p.permanent {
			return Permanent(errors.New(message), p.advice)
		}
		return &advisedError{err: errors.New(message), advice: p.advice}
	}
	return errors.New(message)
}

// advisedError is a transient error that still has a known remedy.
type advisedError struct {
	err    error
	advice string
}

func (e *advisedError) Error() string { return e.err.Error() }
func (e *advisedError) Unwrap() error { return e.err }

var readerPatterns = []struct {
	substring string
	permanent bool
	advice    string
}{
	{"topic authorization failed", true, "grant this client read on the topic, or point it at one it may read"},
	{"group authorization failed", true, "grant this client access to the consumer group, or change AISOC_GRAPH_WS_GROUP_ID"},
	{"cluster authorization failed", true, "the broker refused this principal; check the credentials this service runs with"},
	{"sasl authentication failed", true, "the broker rejected these credentials; they will not start working on their own"},
	{"unsupported sasl mechanism", true, "the broker does not offer this SASL mechanism; reconfigure the client"},
	{"illegal sasl state", true, "the SASL handshake was attempted out of order; this is a client configuration fault"},
	{"unsupported version", true, "this client and this broker cannot agree on a protocol version"},
	{"invalid topic", true, "the topic name is not valid; check AISOC_GRAPH_UPDATES_TOPIC"},
	{"invalid group id", true, "the consumer group id is not valid; check AISOC_GRAPH_WS_GROUP_ID"},
	{"security disabled", true, "the broker has security disabled and cannot answer this request"},
	{"unknown topic or partition", false, "create the topic, or enable auto-creation on the broker"},
	{"connection refused", false, "nothing is listening on the broker address; check KAFKA_BROKERS and that the broker is up"},
	{"no such host", false, "the broker hostname does not resolve; check KAFKA_BROKERS"},
	{"i/o timeout", false, "the broker accepted no answer in time; check network reachability between this service and the broker"},
}

func logFailure(class FailureClass, topic, advice string, err error, consecutive uint64, failingFor time.Duration, notResolving bool) {
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
		event.Msg("graph_ws: source failure will not clear on its own; retrying is not progress")
	case notResolving:
		event.Msg("graph_ws: source has been failing for longer than a transient fault explains; treat this as a misconfiguration, not churn")
	default:
		event.Msg("graph_ws: source failure; retrying")
	}
}

// backoffFor grows the wait with the length of the failure run, capped. The
// first few retries stay fast so a broker blip costs nothing; a sustained
// outage stops being a reconnect storm.
func backoffFor(consecutive uint64) time.Duration {
	wait := backoffMin
	for i := uint64(1); i < consecutive && wait < backoffMax; i++ {
		wait *= 2
	}
	if wait > backoffMax {
		wait = backoffMax
	}
	return wait
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// sleepFor waits for d or until the loop is asked to stop, whichever first.
// Returns false if the loop should exit.
func sleepFor(ctx context.Context, stopCh <-chan struct{}, d time.Duration) bool {
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

// isContextError keeps an ordinary shutdown out of the failure counters. A
// cancelled context is the operator stopping the service, not a fault.
func isContextError(err error) bool {
	return errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
}
