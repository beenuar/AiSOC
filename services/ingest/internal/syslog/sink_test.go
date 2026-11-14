package syslog

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/beenuar/aisoc/services/ingest/internal/inbox"
	"github.com/beenuar/aisoc/services/ingest/internal/normalizer"
	"github.com/google/uuid"
)

type fakeTokens struct {
	token *inbox.Token
	err   error
	asked []string
}

func (f *fakeTokens) Resolve(_ context.Context, token string) (*inbox.Token, error) {
	f.asked = append(f.asked, token)
	if f.err != nil {
		return nil, f.err
	}
	return f.token, nil
}

type capturingPublisher struct {
	batches [][]*normalizer.NormalizedEvent
	err     error
}

func (p *capturingPublisher) PublishBatch(_ context.Context, events []*normalizer.NormalizedEvent) error {
	if p.err != nil {
		return p.err
	}
	p.batches = append(p.batches, events)
	return nil
}

// realTemplates loads the templates that ship in the binary, so these tests
// exercise the YAML the service actually applies rather than a stub whose
// field map agrees with whatever the test expects.
func realTemplates(t *testing.T) *inbox.Registry {
	t.Helper()
	r := inbox.NewRegistry()
	if err := r.LoadEmbedded(); err != nil {
		t.Fatalf("LoadEmbedded: %v", err)
	}
	return r
}

func tenantToken(template string) *inbox.Token {
	return &inbox.Token{
		Token:      "tok_abc",
		TenantID:   uuid.MustParse("3fa85f64-5717-4562-b3fc-2c963f66afa6"),
		TemplateID: template,
		Label:      "edge firewalls",
	}
}

func TestTheTenantComesFromTheTokenAndNowhereElse(t *testing.T) {
	// The reason the listener takes a token rather than reading a tenant
	// off the wire: syslog has no authenticated principal and no header, so
	// a tenant a sender could set would be a cross-tenant write requiring
	// no attacker effort at all.
	tokens := &fakeTokens{token: tenantToken(RequiredTemplateID)}
	pub := &capturingPublisher{}
	sink, err := NewPublishingSink(tokens, realTemplates(t), pub, "tok_abc")
	if err != nil {
		t.Fatalf("NewPublishingSink: %v", err)
	}

	// A sender doing its best to claim another tenant, in every field it
	// controls: the hostname, the app name, the message and a structured
	// data parameter.
	msg, err := Parse(`<34>1 2026-10-08T22:14:15Z 00000000-0000-0000-0000-000000000999 tenant_id - - ` +
		`[meta tenant_id="00000000-0000-0000-0000-000000000999"] tenant_id=00000000-0000-0000-0000-000000000999`)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if err := sink.Deliver(context.Background(), []*Message{msg}); err != nil {
		t.Fatalf("Deliver: %v", err)
	}

	if len(pub.batches) != 1 || len(pub.batches[0]) != 1 {
		t.Fatalf("expected one event, got %#v", pub.batches)
	}
	got := pub.batches[0][0]
	if got.TenantID != "3fa85f64-5717-4562-b3fc-2c963f66afa6" {
		t.Errorf("tenant = %q; it must come from the token, not from the message", got.TenantID)
	}
	metadata, _ := got.OcsfEvent["metadata"].(map[string]any)
	if metadata["tenant_uid"] != "3fa85f64-5717-4562-b3fc-2c963f66afa6" {
		t.Errorf("metadata.tenant_uid = %v", metadata["tenant_uid"])
	}
}

func TestEachFormatIsProjectedThroughItsOwnTemplate(t *testing.T) {
	// A CEF line carries a vendor, a product and a severity of its own.
	// Projecting it through the plain syslog template would throw all three
	// away and file an ArcSight finding as an anonymous log line — which
	// still looks like a complete record.
	tokens := &fakeTokens{token: tenantToken(RequiredTemplateID)}
	pub := &capturingPublisher{}
	sink, _ := NewPublishingSink(tokens, realTemplates(t), pub, "tok_abc")

	plain, _ := Parse("<34>Oct 11 22:14:15 mymachine su: failed")
	cef, _ := Parse("<134>Oct 11 22:14:15 fw01 CEF:0|Security|threatmanager|1.0|100|worm stopped|10|src=10.0.0.1")
	leef, _ := Parse("<134>Oct 11 22:14:15 qr01 LEEF:1.0|Lancope|StealthWatch|1.0|41|src=192.0.2.1\tsev=8")

	if err := sink.Deliver(context.Background(), []*Message{plain, cef, leef}); err != nil {
		t.Fatalf("Deliver: %v", err)
	}
	events := pub.batches[0]
	if len(events) != 3 {
		t.Fatalf("want 3 events, got %d", len(events))
	}

	// The plain line stays in category 1: the promoter promotes category 2
	// unconditionally, so filing routine daemon chatter as a finding would
	// make every line an alert.
	if got := events[0].OcsfEvent["class_uid"]; got != 1007 {
		t.Errorf("plain syslog class_uid = %v, want 1007", got)
	}
	if got := events[1].OcsfEvent["class_uid"]; got != 2001 {
		t.Errorf("CEF class_uid = %v, want 2001", got)
	}
	if got := events[2].OcsfEvent["class_uid"]; got != 2001 {
		t.Errorf("LEEF class_uid = %v, want 2001", got)
	}
	if events[1].ConnectorID != "syslog:cef-syslog" || events[2].ConnectorID != "syslog:leef-syslog" {
		t.Errorf("connector refs: %q, %q", events[1].ConnectorID, events[2].ConnectorID)
	}

	metadata, _ := events[1].OcsfEvent["metadata"].(map[string]any)
	product, _ := metadata["product"].(map[string]any)
	if product["vendor_name"] != "Security" {
		t.Errorf("the CEF vendor was lost: %v", product)
	}
}

func TestAVendorSeverityReachesTheOCSFLadder(t *testing.T) {
	tokens := &fakeTokens{token: tenantToken(RequiredTemplateID)}
	pub := &capturingPublisher{}
	sink, _ := NewPublishingSink(tokens, realTemplates(t), pub, "tok_abc")

	// syslog `crit` and CEF severity 10 both mean the top of their own
	// ladder. Neither may be collapsed into the tier below it.
	critical, _ := Parse("<34>Oct 11 22:14:15 mymachine su: failed")
	cef, _ := Parse("CEF:0|v|p|1.0|1|Name|10|src=10.0.0.1")
	if err := sink.Deliver(context.Background(), []*Message{critical, cef}); err != nil {
		t.Fatalf("Deliver: %v", err)
	}
	events := pub.batches[0]
	if got := events[0].OcsfEvent["severity_id"]; got != 5 {
		t.Errorf("syslog crit severity_id = %v, want 5", got)
	}
	if got := events[1].OcsfEvent["severity_id"]; got != 6 {
		t.Errorf("CEF severity 10 severity_id = %v, want 6", got)
	}
}

func TestATokenMintedWithTheWrongTemplateIsRefused(t *testing.T) {
	// Not silently reinterpreted. A token minted for a different vendor's
	// webhook would otherwise publish syslog under that vendor's name.
	tokens := &fakeTokens{token: tenantToken("pagerduty")}
	pub := &capturingPublisher{}
	sink, _ := NewPublishingSink(tokens, realTemplates(t), pub, "tok_abc")

	msg, _ := Parse("<34>Oct 11 22:14:15 mymachine su: failed")
	err := sink.Deliver(context.Background(), []*Message{msg})
	if err == nil {
		t.Fatal("a token minted with the wrong template should be refused")
	}
	if !strings.Contains(err.Error(), RequiredTemplateID) {
		t.Errorf("the error should name the template the listener needs: %v", err)
	}
	if len(pub.batches) != 0 {
		t.Error("nothing should have been published")
	}
}

func TestARevokedTokenIsNamedRatherThanGeneric(t *testing.T) {
	// A revoked token and an unreachable database are different problems
	// and only one of them is fixed by waiting.
	tokens := &fakeTokens{err: errors.New("token revoked")}
	pub := &capturingPublisher{}
	sink, _ := NewPublishingSink(tokens, realTemplates(t), pub, "tok_abc")

	msg, _ := Parse("<34>Oct 11 22:14:15 mymachine su: failed")
	err := sink.Deliver(context.Background(), []*Message{msg})
	if err == nil || !strings.Contains(err.Error(), "token revoked") {
		t.Errorf("err = %v; it should carry the resolver's own reason", err)
	}
}

func TestASinkWithNoTokenIsRefusedAtConstruction(t *testing.T) {
	// Starting a listener with no token would bind a port and attribute
	// every message to nobody.
	if _, err := NewPublishingSink(&fakeTokens{}, realTemplates(t), &capturingPublisher{}, ""); err == nil {
		t.Fatal("a sink with no token should be refused")
	}
}

func TestTheRawLineSurvivesIntoTheEvent(t *testing.T) {
	tokens := &fakeTokens{token: tenantToken(RequiredTemplateID)}
	pub := &capturingPublisher{}
	sink, _ := NewPublishingSink(tokens, realTemplates(t), pub, "tok_abc")

	line := "<34>Oct 11 22:14:15 mymachine su: 'su root' failed for lonvick"
	msg, _ := Parse(line)
	if err := sink.Deliver(context.Background(), []*Message{msg}); err != nil {
		t.Fatalf("Deliver: %v", err)
	}
	if got := pub.batches[0][0].OcsfEvent["raw_data"]; got != line {
		t.Errorf("raw_data = %v; every parse here is a lossy summary and the original is the only appeal", got)
	}
}
