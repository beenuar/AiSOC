// Tests for failure classification and reporting in the graph_ws consumer.
//
// The property under test is the one the consume loop could not express
// before: a condition that will never resolve is reported differently from
// one that might, and neither is silent.
package graph_ws

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/beenuar/aisoc/services/ingest/internal/graph"
	kafka "github.com/segmentio/kafka-go"
)

// scriptedSource returns each error in turn and then blocks, so a test can
// drive an exact failure sequence without timing assumptions.
type scriptedSource struct {
	mu      sync.Mutex
	steps   []step
	index   int
	calls   int
	blocked chan struct{}
}

type step struct {
	env graph.GraphUpdate
	err error
}

func newScriptedSource(steps ...step) *scriptedSource {
	return &scriptedSource{steps: steps, blocked: make(chan struct{})}
}

func (s *scriptedSource) Next(ctx context.Context) (graph.GraphUpdate, error) {
	s.mu.Lock()
	s.calls++
	if s.index < len(s.steps) {
		next := s.steps[s.index]
		s.index++
		s.mu.Unlock()
		return next.env, next.err
	}
	s.mu.Unlock()
	// Out of script: block like a real consumer waiting on a quiet topic.
	select {
	case <-ctx.Done():
		return graph.GraphUpdate{}, ctx.Err()
	case <-s.blocked:
		return graph.GraphUpdate{}, errors.New("closed")
	}
}

func (s *scriptedSource) Close() error { return nil }

// repeatingSource returns the same error on every call, forever.
type repeatingSource struct{ err error }

func (r *repeatingSource) Next(context.Context) (graph.GraphUpdate, error) {
	return graph.GraphUpdate{}, r.err
}
func (r *repeatingSource) Close() error { return nil }

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// TestClassifyNamesWhatCanBeDone enumerates what the classifier *credits* as
// transient, not only what it flags. A classifier that answered "transient"
// to everything would satisfy any test that only checked the permanent
// cases, and "transient" is the answer that makes a failure look like churn.
func TestClassifyNamesWhatCanBeDone(t *testing.T) {
	cases := []struct {
		name  string
		err   error
		want  FailureClass
		regex string
	}{
		{"a dial failure may clear", errors.New("dial tcp 10.0.0.1:9092: connect: connection refused"), ClassTransient, ""},
		{"a leader election may clear", kafka.LeaderNotAvailable, ClassTransient, ""},
		{"a rebalance in progress may clear", kafka.RebalanceInProgress, ClassTransient, ""},
		{"an absent topic may clear, and says who can clear it", kafka.UnknownTopicOrPartition, ClassTransient, "create the topic"},
		{"an authorization failure may not", kafka.TopicAuthorizationFailed, ClassPermanent, "grant this client read"},
		{"an unsupported SASL mechanism may not", kafka.UnsupportedSASLMechanism, ClassPermanent, "reconfigure the client"},
		{"an explicitly permanent error carries its advice", Permanent(errors.New("no brokers"), "set KAFKA_BROKERS"), ClassPermanent, "set KAFKA_BROKERS"},
		{"an undecodable envelope is about the message", Poison(errors.New("invalid character")), ClassPoison, "subscription is unaffected"},
		{"a raw json error is also about the message", &json.SyntaxError{}, ClassPoison, "subscription is unaffected"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, advice := classify(tc.err)
			if got != tc.want {
				t.Fatalf("classify(%v) = %q, want %q", tc.err, got, tc.want)
			}
			if tc.regex != "" && !strings.Contains(advice, tc.regex) {
				t.Fatalf("advice %q does not mention %q", advice, tc.regex)
			}
		})
	}
}

// TestReaderErrorClassification covers the strings kafka-go hands to its
// error logger, which is the only form those failures ever take.
func TestReaderErrorClassification(t *testing.T) {
	cases := []struct {
		name string
		line string
		want FailureClass
	}{
		{
			"an unreachable broker is retriable until it is not",
			"error initializing the kafka reader for partition 0 of graph: dial tcp 10.1.2.3:9092: i/o timeout",
			ClassTransient,
		},
		{
			"a refused ACL is not",
			"Error reading partition assignments for topic graph: [29] Topic Authorization Failed",
			ClassPermanent,
		},
		{
			// Retriable: it appears the moment somebody creates it. What
			// the operator gets is the advice, not a stopped consumer.
			"an absent topic keeps being retried but says who can fix it",
			"the kafka reader got an unknown error reading partition 0: [3] Unknown Topic Or Partition",
			ClassTransient,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, advice := classify(readerError(tc.line))
			if got != tc.want {
				t.Fatalf("classify(readerError(%q)) = %q, want %q", tc.line, got, tc.want)
			}
			if advice == "" {
				t.Fatalf("no operator action for %q", tc.line)
			}
		})
	}
}

// TestTransientFailureIsCountedAndRetried is the old behaviour made visible:
// the loop still survives, but the error is now recorded rather than dropped.
func TestTransientFailureIsCountedAndRetried(t *testing.T) {
	src := newScriptedSource(
		step{err: errors.New("dial tcp: connection refused")},
		step{env: graph.GraphUpdate{EntityID: "e1", TenantID: "t", SchemaVersion: graph.SchemaVersion}},
	)
	b := New(src, Options{Topic: "test-transient"})
	sub := b.Subscribe("t")
	defer b.Unsubscribe(sub)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	b.Start(ctx)
	defer b.Stop()

	select {
	case env := <-sub.Updates:
		if env.EntityID != "e1" {
			t.Fatalf("unexpected envelope %q", env.EntityID)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("loop did not recover from a transient failure")
	}

	health := b.Health()
	if health.TransientFailures != 1 {
		t.Fatalf("transient failures = %d, want 1", health.TransientFailures)
	}
	if !health.Attached {
		t.Fatal("a transient failure must not detach the subscription")
	}
	// Recovery clears the run, so the next report does not describe a fault
	// that has already cleared.
	if health.ConsecutiveFailures != 0 || health.NotResolving {
		t.Fatalf("after a delivered envelope: consecutive=%d not_resolving=%t, want 0/false",
			health.ConsecutiveFailures, health.NotResolving)
	}
}

// TestPermanentFailureStopsTheLoopAndSaysSo is the defect this change exists
// for, inverted: a fault no retry can clear must not be retried in silence.
func TestPermanentFailureStopsTheLoopAndSaysSo(t *testing.T) {
	src := &repeatingSource{err: Permanent(kafka.TopicAuthorizationFailed, "grant read on the topic")}
	b := New(src, Options{Topic: "test-permanent"})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	b.Start(ctx)
	defer b.Stop()

	waitFor(t, "the loop to stop on a permanent failure", func() bool {
		h := b.Health()
		return h.PermanentFailure && !h.Attached
	})

	health := b.Health()
	if !health.PermanentFailure {
		t.Fatal("a permanent failure must be reported as permanent")
	}
	if health.Healthy() {
		t.Fatal("Healthy() must be false while the source is permanently failed")
	}
	if !strings.Contains(health.Reason(), "grant read on the topic") {
		t.Fatalf("reason %q does not carry the operator action", health.Reason())
	}
	if health.PermanentFailures != 1 {
		t.Fatalf("permanent failures = %d, want exactly 1 — a permanent fault must not be retried",
			health.PermanentFailures)
	}
}

// TestTransientFailureEscalatesWhenItOutlivesItsExcuse covers the state that
// is a duration rather than a class: a `no such host` can be a startup race
// for a few seconds and a variable nobody set for ever. The loop reports the
// first and then stops calling it that.
func TestTransientFailureEscalatesWhenItOutlivesItsExcuse(t *testing.T) {
	src := &repeatingSource{err: errors.New("dial tcp: lookup kafka: no such host")}
	b := New(src, Options{Topic: "test-stuck", StuckAfter: 50 * time.Millisecond})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	b.Start(ctx)
	defer b.Stop()

	if h := b.Health(); h.NotResolving {
		t.Fatal("a failure must not be called not-resolving before it has lasted")
	}
	waitFor(t, "the failure to be reported as not resolving", func() bool {
		return b.Health().NotResolving
	})
	health := b.Health()
	if !health.Attached {
		t.Fatal("the loop should still be retrying — the condition may yet clear")
	}
	if health.PermanentFailure {
		t.Fatal("not-resolving is an observation about duration, not a protocol verdict")
	}
	if health.Healthy() {
		t.Fatal("a source failing past its transient explanation is not healthy")
	}
	if !strings.Contains(health.Reason(), "no such host") {
		t.Fatalf("reason %q does not name the failure", health.Reason())
	}
}

// TestBackoffGrowsAndIsCapped: a flat 50ms against an unreachable broker is
// twenty reconnects a second forever.
func TestBackoffGrowsAndIsCapped(t *testing.T) {
	if got := backoffFor(1); got != backoffMin {
		t.Fatalf("first retry waited %s, want %s", got, backoffMin)
	}
	if got := backoffFor(3); got != 4*backoffMin {
		t.Fatalf("third retry waited %s, want %s", got, 4*backoffMin)
	}
	if got := backoffFor(1000); got != backoffMax {
		t.Fatalf("a long outage waited %s, want the %s cap", got, backoffMax)
	}
}

// TestPoisonEnvelopeDoesNotDetachTheSubscription: one unreadable message is
// not a broken topic, and must not be reported as one.
func TestPoisonEnvelopeDoesNotDetachTheSubscription(t *testing.T) {
	src := newScriptedSource(
		step{err: Poison(errors.New("invalid character 'x'"))},
		step{env: graph.GraphUpdate{EntityID: "after-poison", TenantID: "t", SchemaVersion: graph.SchemaVersion}},
	)
	b := New(src, Options{Topic: "test-poison", StuckAfter: 20 * time.Millisecond})
	sub := b.Subscribe("t")
	defer b.Unsubscribe(sub)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	b.Start(ctx)
	defer b.Stop()

	select {
	case env := <-sub.Updates:
		if env.EntityID != "after-poison" {
			t.Fatalf("unexpected envelope %q", env.EntityID)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("a poison envelope stopped the subscription")
	}

	health := b.Health()
	if health.PoisonMessages != 1 {
		t.Fatalf("poison messages = %d, want 1", health.PoisonMessages)
	}
	if health.TransientFailures != 0 || health.PermanentFailures != 0 {
		t.Fatalf("a poison envelope was counted as a source failure: %+v", health)
	}
	if !health.Healthy() {
		t.Fatalf("the subscription is working; health says %q", health.Reason())
	}
}

// TestCleanShutdownIsNotAFailure: a cancelled context is an operator, not a
// fault, and must not leave a failure as the last thing recorded.
func TestCleanShutdownIsNotAFailure(t *testing.T) {
	src := &repeatingSource{err: context.Canceled}
	b := New(src, Options{Topic: "test-shutdown"})
	ctx, cancel := context.WithCancel(context.Background())
	b.Start(ctx)
	cancel()
	b.Stop()

	health := b.Health()
	if health.TransientFailures != 0 || health.PermanentFailures != 0 {
		t.Fatalf("shutdown was counted as a failure: %+v", health)
	}
	if health.Attached {
		t.Fatal("a stopped loop must report detached")
	}
}

// TestStreamRouteRefusesWhenTheSourceIsDetached. Completing the handshake
// would hand the client a socket that stays silent, which is exactly the
// state nobody could tell apart from a quiet estate.
func TestStreamRouteRefusesWhenTheSourceIsDetached(t *testing.T) {
	src := &repeatingSource{err: Permanent(errors.New("topic missing"), "create the topic")}
	b := New(src, Options{Topic: "test-route"})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	b.Start(ctx)
	defer b.Stop()
	waitFor(t, "the source to report a permanent failure", func() bool { return b.Health().PermanentFailure })

	req := httptest.NewRequest(http.MethodGet, "/v1/graph_ws/stream?tenant_id=t1", nil)
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Sec-WebSocket-Version", "13")
	req.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
	rec := httptest.NewRecorder()

	NewServer(b).Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "create the topic") {
		t.Fatalf("body %q does not say what to do about it", rec.Body.String())
	}
}

// TestAnUnreachableBrokerSaysSo drives a real kafka.Reader at a port nothing
// is listening on.
//
// This is the case the whole change is about, and it is the one a fake
// source cannot prove: with a GroupID set, kafka-go's dial failures never
// return from ReadMessage — they go to the reader's ErrorLogger, which
// defaults to a silent logger. Before this change the loop sat blocked and
// every one of those errors was discarded inside the library.
func TestAnUnreachableBrokerSaysSo(t *testing.T) {
	// A port that is closed rather than a hostname that does not resolve:
	// connection-refused is immediate and needs no DNS, so the test neither
	// touches the network nor waits on a resolver timeout.
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("cannot reserve a port: %v", err)
	}
	addr := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatalf("cannot close the reserved port: %v", err)
	}

	health := NewSourceState("test-unreachable-broker", 500*time.Millisecond)
	src, err := NewKafkaSource(KafkaSourceConfig{
		Brokers: addr,
		Topic:   "security.graph_updates",
		GroupID: "graph-ws-unreachable-test",
		Health:  health,
	})
	if err != nil {
		t.Fatalf("NewKafkaSource: %v", err)
	}
	defer func() { _ = src.Close() }()

	b := New(src, Options{Health: health})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	b.Start(ctx)
	defer b.Stop()

	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if h := b.Health(); h.ConsecutiveFailures > 0 {
			break
		}
		time.Sleep(25 * time.Millisecond)
	}

	h := b.Health()
	if h.ConsecutiveFailures == 0 {
		t.Fatal("an unreachable broker produced no recorded failure — the reader's errors are still being discarded")
	}
	if h.LastError == "" {
		t.Fatal("a failure was counted with no error text; an operator learns nothing from a counter alone")
	}
	if !strings.Contains(h.LastError, addr) && !strings.Contains(h.LastError, "connection refused") {
		t.Fatalf("last error %q names neither the broker nor the failure", h.LastError)
	}
	if h.Advice == "" {
		t.Fatal("no operator action was offered for an unreachable broker")
	}
	t.Logf("unreachable broker at %s reported after %d failure(s): %s (%s)",
		addr, h.ConsecutiveFailures, h.LastError, h.Advice)

	// It is reported as transient at first, because a broker coming back is
	// exactly what a retry is for. What must not happen is that it stays
	// described that way forever.
	waitFor(t, "the outage to stop being described as churn", func() bool {
		return b.Health().NotResolving
	})
	stuck := b.Health()
	if stuck.Healthy() {
		t.Fatalf("a source that cannot reach its broker reported healthy: %+v", stuck)
	}
	if !strings.Contains(stuck.Reason(), "failing for") {
		t.Fatalf("reason %q does not say how long it has been failing", stuck.Reason())
	}
	t.Logf("reason: %s", stuck.Reason())
}

// TestNewKafkaSourceRefusesAnEmptyBrokerList: a misconfiguration caught at
// construction is one that never becomes a silent retry.
func TestNewKafkaSourceRefusesAnEmptyBrokerList(t *testing.T) {
	for _, brokers := range []string{"", " ", ",", " , "} {
		if _, err := NewKafkaSource(KafkaSourceConfig{Brokers: brokers, Topic: "t"}); err == nil {
			t.Fatalf("NewKafkaSource accepted brokers=%q", brokers)
		}
	}
}

// TestHealthIsSafeWithoutAState: a nil SourceState must not panic, because
// the fallback path is the one taken when something is already wrong.
func TestHealthIsSafeWithoutAState(t *testing.T) {
	var nilState *SourceState
	nilState.MarkAttached()
	nilState.MarkDetached("test")
	nilState.RecordMessage()
	nilState.RecordPoison(errors.New("x"))
	nilState.ObserveReaderError("dial tcp: connection refused")
	if class, _ := nilState.RecordFailure(errors.New("boom")); class != ClassTransient {
		t.Fatalf("nil state classified as %q", class)
	}
	if h := nilState.Health(); h.Attached {
		t.Fatalf("a nil state reported attached: %+v", h)
	}
}

// TestClassifyCreditsOnlyTheCodesItMeansTo walks the entire Kafka protocol
// error table and prints what the classifier *credits*, rather than only
// asserting the handful of codes it flags.
//
// That direction is the one that finds the blind spot. A test listing three
// permanent codes passes just as well against a classifier that calls
// everything permanent, and a classifier that did would stop this consumer
// on every rebalance. Deriving the set from `kafka.Error.Temporary()` would
// have done exactly that: the protocol's "retriable" column says no for
// REBALANCE_IN_PROGRESS, which happens on every deploy.
func TestClassifyCreditsOnlyTheCodesItMeansTo(t *testing.T) {
	// Codes a consumer group resolves by rejoining, which upstream also
	// reports as non-retriable. Stopping the loop on any of these would be
	// an outage introduced by the fix.
	mustBeTransient := []kafka.Error{
		kafka.RebalanceInProgress,
		kafka.UnknownMemberId,
		kafka.IllegalGeneration,
		kafka.MemberIDRequired,
		kafka.UnknownTopicOrPartition,
		kafka.NotCoordinatorForGroup,
		kafka.GroupLoadInProgress,
		kafka.GroupCoordinatorNotAvailable,
		kafka.LeaderNotAvailable,
		kafka.RequestTimedOut,
		kafka.NetworkException,
	}
	for _, code := range mustBeTransient {
		if class, _ := classify(code); class != ClassTransient {
			t.Errorf("%v (code %d) classified %q; a retry or a rejoin clears it and stopping the loop would be an outage",
				code, int(code), class)
		}
	}

	// The whole table, both directions: nothing outside the declared set may
	// be permanent, and everything inside it must be.
	var credited, flagged []string
	for code := kafka.Error(1); code <= kafka.Error(110); code++ {
		if code.Title() == "" || (code.Title() == "Unknown" && code != kafka.Unknown) {
			continue // a gap in the table, not a code this client knows
		}
		class, advice := classify(code)
		_, declared := permanentProtocolErrors[code]
		switch {
		case class == ClassPermanent && !declared:
			t.Errorf("%v (code %d) classified permanent but is not in permanentProtocolErrors", code, int(code))
		case class != ClassPermanent && declared:
			t.Errorf("%v (code %d) is declared permanent but classified %q", code, int(code), class)
		}
		if class == ClassPermanent {
			if advice == "" {
				t.Errorf("%v is permanent with no operator action; a permanent verdict with no next move is just a louder silence", code)
			}
			flagged = append(flagged, code.Title())
		} else {
			credited = append(credited, code.Title())
		}
	}
	sort.Strings(flagged)
	t.Logf("permanent (%d): %s", len(flagged), strings.Join(flagged, ", "))
	t.Logf("retried (%d): %s", len(credited), strings.Join(credited, ", "))
	if len(credited) < 50 {
		t.Fatalf("only %d codes were walked; the enumeration is not covering the table", len(credited))
	}
	if len(flagged) != len(permanentProtocolErrors) {
		t.Fatalf("walked %d permanent codes, declared %d", len(flagged), len(permanentProtocolErrors))
	}
}

// TestEveryPermanentCodeIsAlsoRecognisedInAReaderLogLine closes the gap
// between the two routes a protocol error takes to this package. One arrives
// as a kafka.Error from ReadMessage; the other arrives as text in the
// reader's error logger, which is where the consumer group's failures go.
// A code recognised on one route and not the other is a permanent failure
// reported as churn on whichever route it happens to take.
func TestEveryPermanentCodeIsAlsoRecognisedInAReaderLogLine(t *testing.T) {
	for code := range permanentProtocolErrors {
		line := "kafka reader: [" + code.Title() + "] while fetching"
		class, advice := classify(readerError(line))
		if class != ClassPermanent {
			t.Errorf("%q from the reader log classified %q, but the same code from ReadMessage is permanent", line, class)
		}
		if advice == "" {
			t.Errorf("%q carries no operator action", line)
		}
	}
}
