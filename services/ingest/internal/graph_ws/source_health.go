// Failure classification and reporting for the graph_ws envelope source.
//
// Why this file is now thirty lines instead of six hundred
// -------------------------------------------------------
// The machinery used to live here. The consume loop answered every source
// error the same way — a 50ms sleep and `continue`, with the error
// discarded — so a broker that was never coming back produced a healthy
// container, restarts 0, /health 200, and a WebSocket that delivered
// nothing. Worse, most of those errors never reached the loop:
// `kafka.NewReader` falls back to a silent logger when `ErrorLogger` is nil,
// and with a GroupID set the consumer group's dial, join and rebalance
// failures are reported *only* through that logger while `ReadMessage`
// stays blocked.
//
// Depth item 4.2 adds a second Kafka consumer — the customer-topic input —
// with exactly the same failure modes. A second copy of this table is how
// two readers come to disagree about what an error means, so the generic
// half moved to internal/streamhealth and both subscriptions share it. The
// names below are aliases, which keeps this package's API and its own test
// unchanged, and `graphWSNames` is the only thing that is still specific to
// graph_ws: the metric series keep their published names and the advice
// names the environment variables an operator would actually edit.
package graph_ws

import (
	"context"
	"time"

	"github.com/beenuar/aisoc/services/ingest/internal/streamhealth"
)

// FailureClass and its values, re-exported so callers and tests of this
// package do not have to know where the implementation lives.
type FailureClass = streamhealth.FailureClass

const (
	ClassTransient = streamhealth.ClassTransient
	ClassPermanent = streamhealth.ClassPermanent
	ClassPoison    = streamhealth.ClassPoison
)

// DefaultStuckAfter is how long a transient failure may persist before it is
// reported as not resolving.
const DefaultStuckAfter = streamhealth.DefaultStuckAfter

const (
	backoffMin = streamhealth.BackoffMin
	backoffMax = streamhealth.BackoffMax
)

// SourceState and SourceHealth keep their names here; they are
// streamhealth's State and Health.
type SourceState = streamhealth.State

// SourceHealth is a point-in-time copy, safe to serialise.
type SourceHealth = streamhealth.Health

// Permanent, Poison and the classifier entry points.
var (
	Permanent = streamhealth.Permanent
	Poison    = streamhealth.Poison
)

// graphWSNames is the only subsystem-specific thing left: the published
// metric series stem, which must not be renamed, and the environment
// variables the advice tells an operator to check.
var graphWSNames = streamhealth.Names{
	Subsystem:    "graph_ws",
	MetricPrefix: "aisoc_graph_ws_source",
	BrokersVar:   "KAFKA_BROKERS",
	TopicVar:     "AISOC_GRAPH_UPDATES_TOPIC",
	GroupVar:     "AISOC_GRAPH_WS_GROUP_ID",
}

var graphWSClassifier = streamhealth.NewClassifier(graphWSNames)

// permanentProtocolErrors is the declared permanent set for this
// subscription. Exposed as a package var because this package's test walks
// the whole kafka error table against it in both directions.
var permanentProtocolErrors = graphWSClassifier.PermanentCodes()

func classify(err error) (FailureClass, string) { return graphWSClassifier.Classify(err) }

func readerError(message string) error { return graphWSClassifier.ReaderError(message) }

func backoffFor(consecutive uint64) time.Duration { return streamhealth.BackoffFor(consecutive) }

// NewSourceState builds the shared state for a subscription to topic.
// stuckAfter of zero means DefaultStuckAfter.
func NewSourceState(topic string, stuckAfter time.Duration) *SourceState {
	return streamhealth.NewState(graphWSClassifier, topic, stuckAfter)
}

func sleepFor(ctx context.Context, stopCh <-chan struct{}, d time.Duration) bool {
	return streamhealth.SleepFor(ctx, stopCh, d)
}

func isContextError(err error) bool { return streamhealth.IsContextError(err) }
