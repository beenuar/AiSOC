package kafkainput

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/beenuar/aisoc/services/ingest/internal/inbox"
	"github.com/beenuar/aisoc/services/ingest/internal/normalizer"
	"github.com/beenuar/aisoc/services/ingest/internal/streamhealth"
	"github.com/google/uuid"
	kafka "github.com/segmentio/kafka-go"
)

// ---------------------------------------------------------------------------
// Doubles. Each is deliberately *less* capable than the real thing where the
// real thing would hide a defect: the token resolver answers only the token
// it was given, and the template source only the template it was given.
// ---------------------------------------------------------------------------

type fakeTokens struct {
	token string
	tok   *inbox.Token
	err   error
	calls int
}

func (f *fakeTokens) Resolve(_ context.Context, token string) (*inbox.Token, error) {
	f.calls++
	if f.err != nil {
		return nil, f.err
	}
	if token != f.token {
		return nil, errors.New("no such token")
	}
	return f.tok, nil
}

type fakeTemplates struct {
	id   string
	tmpl *inbox.Template
}

func (f *fakeTemplates) Get(id string) (*inbox.Template, error) {
	if id != f.id {
		return nil, inbox.ErrTemplateNotFound
	}
	return f.tmpl, nil
}

type fakePublisher struct {
	mu        sync.Mutex
	published []*normalizer.NormalizedEvent
	err       error
}

func (f *fakePublisher) PublishBatch(_ context.Context, events []*normalizer.NormalizedEvent) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return f.err
	}
	f.published = append(f.published, events...)
	return nil
}

func (f *fakePublisher) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.published)
}

func (f *fakePublisher) at(i int) *normalizer.NormalizedEvent {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.published[i]
}

// scriptedReader hands out a fixed sequence and then blocks on the context,
// which is what a real reader does on an idle topic.
type scriptedReader struct {
	mu        sync.Mutex
	msgs      []kafka.Message
	errs      []error
	idx       int
	committed []kafka.Message
	closed    bool
}

func (r *scriptedReader) FetchMessage(ctx context.Context) (kafka.Message, error) {
	r.mu.Lock()
	i := r.idx
	r.idx++
	r.mu.Unlock()
	if i < len(r.errs) && r.errs[i] != nil {
		return kafka.Message{}, r.errs[i]
	}
	if i < len(r.msgs) {
		return r.msgs[i], nil
	}
	<-ctx.Done()
	return kafka.Message{}, ctx.Err()
}

func (r *scriptedReader) CommitMessages(_ context.Context, msgs ...kafka.Message) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.committed = append(r.committed, msgs...)
	return nil
}

func (r *scriptedReader) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.closed = true
	return nil
}

func (r *scriptedReader) commitCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.committed)
}

// ---------------------------------------------------------------------------

const (
	testToken    = "tok_live_abcdef"
	testTemplate = "generic-json"
)

var testTenant = uuid.MustParse("00000000-0000-0000-0000-0000000000a1")

func testHarness(t *testing.T, msgs []kafka.Message, errs []error) (*Source, *scriptedReader, *fakePublisher, *fakeTokens) {
	t.Helper()
	rd := &scriptedReader{msgs: msgs, errs: errs}
	tokens := &fakeTokens{token: testToken, tok: &inbox.Token{
		Token: testToken, TenantID: testTenant, TemplateID: testTemplate,
	}}
	templates := &fakeTemplates{id: testTemplate, tmpl: &inbox.Template{
		ID:        testTemplate,
		ClassUID:  2001,
		ClassName: "Security Finding",
	}}
	pub := &fakePublisher{}
	cfg := SourceConfig{
		Name: "customer-a", Brokers: "broker:9092", Topic: "customer.security",
		GroupID: "aisoc-ingest-customer-a", Token: testToken, TemplateID: testTemplate,
	}
	health := streamhealth.NewState(Classifier, cfg.Topic, 50*time.Millisecond)
	return newSourceWithReader(cfg, rd, tokens, templates, pub, health), rd, pub, tokens
}

func runUntil(t *testing.T, s *Source, cond func() bool) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	s.Start(ctx)
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) && !cond() {
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	s.Stop()
	if !cond() {
		t.Fatalf("condition never held; last health: %+v", s.Health())
	}
}

// ---------------------------------------------------------------------------
// The happy path, and what it proves about the tenant.
// ---------------------------------------------------------------------------

func TestARecordIsNormalisedAndPublishedUnderTheTokensTenant(t *testing.T) {
	s, rd, pub, _ := testHarness(t, []kafka.Message{{
		Topic: "customer.security", Partition: 3, Offset: 41,
		Key:   []byte("host-7"),
		Value: []byte(`{"message":"root login","src_ip":"198.51.100.4"}`),
	}}, nil)

	runUntil(t, s, func() bool { return pub.count() == 1 })

	ev := pub.at(0)
	if ev.TenantID != testTenant.String() {
		t.Fatalf("tenant %q, want %q", ev.TenantID, testTenant)
	}
	if ev.ConnectorID != "kafka-input:customer-a" {
		t.Fatalf("connector ref %q", ev.ConnectorID)
	}
	if rd.commitCount() != 1 {
		t.Fatalf("committed %d offsets, want 1", rd.commitCount())
	}
}

// A tenant a producer can set is a cross-tenant write. The record carries
// one in its payload *and* in a header; neither may win.
func TestATenantInThePayloadOrAHeaderIsIgnored(t *testing.T) {
	attacker := "00000000-0000-0000-0000-00000000beef"
	s, _, pub, _ := testHarness(t, []kafka.Message{{
		Topic: "customer.security", Offset: 1,
		Value:   []byte(`{"message":"hello","tenant_id":"` + attacker + `"}`),
		Headers: []kafka.Header{{Key: "tenant_id", Value: []byte(attacker)}},
	}}, nil)

	runUntil(t, s, func() bool { return pub.count() == 1 })

	if got := pub.at(0).TenantID; got != testTenant.String() {
		t.Fatalf("tenant came from the record: %q", got)
	}
}

// ---------------------------------------------------------------------------
// The three classes. This is the whole reason the package exists.
// ---------------------------------------------------------------------------

// Poison: one record is unreadable, the subscription is not. It must be
// committed, or the loop re-reads it forever and a working consumer is
// stopped by one bad producer.
func TestAnEmptyRecordIsPoisonAndDoesNotStopTheSubscription(t *testing.T) {
	s, rd, pub, _ := testHarness(t, []kafka.Message{
		{Topic: "customer.security", Offset: 1, Value: []byte("")},
		{Topic: "customer.security", Offset: 2, Value: []byte(`{"message":"after the bad one"}`)},
	}, nil)

	runUntil(t, s, func() bool { return pub.count() == 1 })

	h := s.Health()
	if h.PoisonMessages != 1 {
		t.Fatalf("poison counted %d, want 1", h.PoisonMessages)
	}
	if h.NotResolving {
		t.Fatal("a poison record marked the subscription as not resolving; the subscription is demonstrably working")
	}
	if rd.commitCount() != 2 {
		t.Fatalf("committed %d, want 2 — a poison record that is not committed is re-read forever", rd.commitCount())
	}
}

// A topic of plain text is a legitimate source. Refusing it would be a
// receiver that looks attached and drops everything.
func TestANonJSONRecordIsCarriedAsALogLineRatherThanRefused(t *testing.T) {
	s, _, pub, _ := testHarness(t, []kafka.Message{{
		Topic: "customer.security", Offset: 1, Value: []byte("Oct 11 09:00:00 host sshd[1]: accepted"),
	}}, nil)

	runUntil(t, s, func() bool { return pub.count() == 1 })

	if s.Health().PoisonMessages != 0 {
		t.Fatal("a plain-text record was counted as poison")
	}
}

// Permanent: the loop stops and names the operator action. Retrying a
// misconfiguration turns it into churn an operator has to filter out.
func TestAPermanentProtocolErrorStopsTheLoopAndNamesTheAction(t *testing.T) {
	s, _, _, _ := testHarness(t, nil, []error{kafka.TopicAuthorizationFailed})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s.Start(ctx)

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if h := s.Health(); h.PermanentFailure && !h.Attached {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	s.Stop()

	h := s.Health()
	if !h.PermanentFailure {
		t.Fatal("a topic-authorization failure was not classified permanent")
	}
	if h.Attached {
		t.Fatal("the loop stayed attached after a permanent failure")
	}
	if !h.NotResolving {
		t.Fatal("a permanent failure must be not-resolving immediately")
	}
	if h.Advice == "" {
		t.Fatal("a permanent verdict with no next move is just a louder silence")
	}
	if !strings.Contains(h.Detail(), "grant this client read") {
		t.Fatalf("readiness detail does not carry the action: %q", h.Detail())
	}
}

// A rebalance happens on every deploy. Stopping on it would turn this into
// an outage, which is why permanence is enumerated rather than derived from
// kafka.Error.Temporary().
func TestARebalanceIsTransientAndTheLoopKeepsGoing(t *testing.T) {
	s, _, pub, _ := testHarness(t,
		[]kafka.Message{{}, {Topic: "customer.security", Offset: 9, Value: []byte(`{"message":"after rebalance"}`)}},
		[]error{kafka.RebalanceInProgress, nil},
	)

	runUntil(t, s, func() bool { return pub.count() == 1 })

	h := s.Health()
	if h.PermanentFailure {
		t.Fatal("a rebalance stopped the consumer; every deploy would be an outage")
	}
	if h.TransientFailures != 1 {
		t.Fatalf("transient failures %d, want 1", h.TransientFailures)
	}
}

// Transient on the *publish* side must not commit. Kafka is the one input
// in this service that can withhold an acknowledgement.
func TestAPublishFailureDoesNotCommitTheOffset(t *testing.T) {
	s, rd, pub, _ := testHarness(t, []kafka.Message{{
		Topic: "customer.security", Offset: 1, Value: []byte(`{"message":"x"}`),
	}}, nil)
	pub.err = errors.New("kafka publish: broker unreachable")

	ctx, cancel := context.WithCancel(context.Background())
	s.Start(ctx)
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && s.Health().TransientFailures == 0 {
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	s.Stop()

	if s.Health().TransientFailures == 0 {
		t.Fatal("the publish failure was never recorded")
	}
	if rd.commitCount() != 0 {
		t.Fatal("an undelivered record was committed; it is now lost")
	}
}

// A token minted with a different template is a configuration fault that no
// retry clears.
func TestATokenMintedWithAnotherTemplateIsPermanent(t *testing.T) {
	s, _, _, tokens := testHarness(t, []kafka.Message{{
		Topic: "customer.security", Offset: 1, Value: []byte(`{"message":"x"}`),
	}}, nil)
	tokens.tok.TemplateID = "splunk-hec"

	ctx, cancel := context.WithCancel(context.Background())
	s.Start(ctx)
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && !s.Health().PermanentFailure {
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	s.Stop()

	h := s.Health()
	if !h.PermanentFailure {
		t.Fatal("a template mismatch kept retrying")
	}
	if !strings.Contains(h.Advice, "mint a token") {
		t.Fatalf("advice %q does not name the fix", h.Advice)
	}
}

// ---------------------------------------------------------------------------
// Readiness has to be informative when healthy too. "attached" alone is a
// lie of omission: a quiet topic is a legitimate state.
// ---------------------------------------------------------------------------

func TestReadinessDetailIsInformativeWhenHealthy(t *testing.T) {
	s, _, pub, _ := testHarness(t, []kafka.Message{{
		Topic: "customer.security", Offset: 1, Value: []byte(`{"message":"x"}`),
	}}, nil)

	ctx, cancel := context.WithCancel(context.Background())
	s.Start(ctx)
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && pub.count() == 0 {
		time.Sleep(5 * time.Millisecond)
	}
	detail := s.Health().Detail()
	cancel()
	s.Stop()

	for _, want := range []string{"customer.security", "received 1"} {
		if !strings.Contains(detail, want) {
			t.Fatalf("healthy readiness detail %q does not mention %q", detail, want)
		}
	}
}

func TestAnIdleSubscriptionSaysNothingHasArrivedRatherThanLookingBroken(t *testing.T) {
	s, _, _, _ := testHarness(t, nil, nil)

	ctx, cancel := context.WithCancel(context.Background())
	s.Start(ctx)
	time.Sleep(50 * time.Millisecond)
	h := s.Health()
	cancel()
	s.Stop()

	if !h.Attached {
		t.Fatal("an idle subscription reported detached")
	}
	if h.NotResolving {
		t.Fatal("an idle subscription reported as not resolving; a quiet topic is legitimate")
	}
	if !strings.Contains(h.Detail(), "nothing has arrived yet") {
		t.Fatalf("idle detail %q does not distinguish quiet from broken", h.Detail())
	}
}

// ---------------------------------------------------------------------------
// Configuration.
// ---------------------------------------------------------------------------

func TestParseSourcesRejectsWhatWouldStartSilentlyBroken(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		want string
	}{
		{"not JSON", `{"name":"a"}`, "JSON array"},
		{"no name", `[{"brokers":"b:9092","topic":"t","token":"x","template_id":"generic-json"}]`, "needs a name"},
		{"no brokers", `[{"name":"a","topic":"t","token":"x","template_id":"generic-json"}]`, "no brokers"},
		{"no topic", `[{"name":"a","brokers":"b:9092","token":"x","template_id":"generic-json"}]`, "no topic"},
		{"no token", `[{"name":"a","brokers":"b:9092","topic":"t","template_id":"generic-json"}]`, "no ingest token"},
		{"no template", `[{"name":"a","brokers":"b:9092","topic":"t","token":"x"}]`, "no template_id"},
		{
			"duplicate names",
			`[{"name":"a","brokers":"b:9092","topic":"t","token":"x","template_id":"generic-json"},` +
				`{"name":"a","brokers":"b:9092","topic":"u","token":"y","template_id":"generic-json"}]`,
			"both named",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseSources(tc.raw)
			if err == nil {
				t.Fatalf("accepted %s", tc.name)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %q does not mention %q", err, tc.want)
			}
		})
	}
}

func TestAnEmptyConfigurationIsNoSourcesRatherThanAnError(t *testing.T) {
	sources, err := ParseSources("   ")
	if err != nil {
		t.Fatalf("empty configuration errored: %v", err)
	}
	if len(sources) != 0 {
		t.Fatalf("got %d sources", len(sources))
	}
}

// Two sources defaulting to one group id would split each other's
// partitions, which looks like message loss.
func TestGroupIDDefaultsPerSourceNotPerProcess(t *testing.T) {
	sources, err := ParseSources(`[
		{"name":"a","brokers":"b:9092","topic":"t","token":"x","template_id":"generic-json"},
		{"name":"b","brokers":"b:9092","topic":"u","token":"y","template_id":"generic-json"}
	]`)
	if err != nil {
		t.Fatal(err)
	}
	if sources[0].GroupID == sources[1].GroupID {
		t.Fatalf("both sources defaulted to group %q", sources[0].GroupID)
	}
}

// kafka.TCP is variadic; a comma-joined string reaches it as one hostname
// and panics rather than failing to dial.
func TestBrokerListIsSplitOnCommas(t *testing.T) {
	got := splitBrokers(" a:9092, b:9092 ,, c:9092 ")
	want := []string{"a:9092", "b:9092", "c:9092"}
	if len(got) != len(want) {
		t.Fatalf("split to %v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("split to %v, want %v", got, want)
		}
	}
}

// The input must use the shared classifier, not a second copy of the table.
func TestTheInputUsesTheSharedClassifier(t *testing.T) {
	shared := streamhealth.NewClassifier(names)
	if len(Classifier.PermanentCodes()) != len(shared.PermanentCodes()) {
		t.Fatal("the input's permanent set differs from streamhealth's")
	}
	for code, advice := range Classifier.PermanentCodes() {
		if advice == "" {
			t.Fatalf("%v is permanent with no operator action", code)
		}
	}
}
