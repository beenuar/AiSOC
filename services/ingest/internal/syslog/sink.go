package syslog

import (
	"context"
	"fmt"
	"time"

	"github.com/beenuar/aisoc/services/ingest/internal/inbox"
	"github.com/beenuar/aisoc/services/ingest/internal/normalizer"
	"github.com/google/uuid"
)

// TokenResolver is the half of inbox.Store this package needs. Narrowed to
// one method so a test can supply one without a Postgres pool.
type TokenResolver interface {
	Resolve(ctx context.Context, token string) (*inbox.Token, error)
}

// Publisher is the half of publisher.Publisher this package needs.
type Publisher interface {
	PublishBatch(ctx context.Context, events []*normalizer.NormalizedEvent) error
}

// TemplateSource resolves a template id to a template.
type TemplateSource interface {
	Get(id string) (*inbox.Template, error)
}

// RequiredTemplateID is the template a syslog token must be minted with.
//
// One token covers all four formats deliberately. A single appliance
// commonly emits RFC 3164 for its own daemons and CEF for its security
// events, and making the operator mint two tokens and run two ports for one
// device would be a configuration no vendor's documentation describes.
const RequiredTemplateID = "syslog"

//: Which OCSF template each parsed format is projected through. CEF and
//: LEEF carry vendor, product and severity of their own, so projecting them
//: through the plain syslog template would throw that away and file an
//: ArcSight finding as an anonymous log line.
var templateForFormat = map[Format]string{
	FormatRFC5424:      "syslog",
	FormatRFC3164:      "syslog",
	FormatUnstructured: "syslog",
	FormatCEF:          "cef-syslog",
	FormatLEEF:         "leef-syslog",
}

// PublishingSink turns parsed messages into OCSF events on Kafka.
//
// The tenant comes from the configured token and from nowhere else. That is
// the whole reason this is a token and not a field: syslog has no
// authenticated principal and no header, so anything taken off the wire is
// caller-controlled, and a tenant a sender can set is a cross-tenant write
// waiting for someone to notice. One listener therefore serves one tenant,
// and a multi-tenant deployment runs one port per tenant — stated in the
// setup guide rather than left to be discovered.
type PublishingSink struct {
	tokens    TokenResolver
	templates TemplateSource
	pub       Publisher
	token     string
}

// NewPublishingSink wires the sink. The token is not resolved here: a
// resolver needs a context and a database, and failing construction because
// Postgres was slow to start would take the whole ingest service down with
// it. It is resolved on the first delivery instead, where a failure is a
// counted, named error.
func NewPublishingSink(tokens TokenResolver, templates TemplateSource, pub Publisher, token string) (*PublishingSink, error) {
	if tokens == nil || templates == nil || pub == nil {
		return nil, fmt.Errorf("syslog: sink needs a token resolver, a template source and a publisher")
	}
	if token == "" {
		return nil, fmt.Errorf("syslog: no ingest token configured, so there is no tenant to attribute messages to")
	}
	return &PublishingSink{tokens: tokens, templates: templates, pub: pub, token: token}, nil
}

// Deliver projects a batch and publishes it.
func (s *PublishingSink) Deliver(ctx context.Context, messages []*Message) error {
	if len(messages) == 0 {
		return nil
	}
	tok, err := s.tokens.Resolve(ctx, s.token)
	if err != nil {
		// Named rather than generic: a revoked token and an unreachable
		// database are different problems and only one of them is fixed by
		// waiting.
		return fmt.Errorf("syslog: resolving the configured ingest token: %w", err)
	}
	if tok.TemplateID != RequiredTemplateID {
		return fmt.Errorf(
			"syslog: the configured token was minted with template %q; the listener needs one minted with %q",
			tok.TemplateID, RequiredTemplateID,
		)
	}

	receivedAt := time.Now().UTC().Format(time.RFC3339Nano)
	tenantID := tok.TenantID.String()
	events := make([]*normalizer.NormalizedEvent, 0, len(messages))

	for _, msg := range messages {
		templateID := templateForFormat[msg.Format]
		if templateID == "" {
			templateID = RequiredTemplateID
		}
		tmpl, err := s.templates.Get(templateID)
		if err != nil {
			// Falling back to the plain template would file a CEF finding
			// as an anonymous log line, which is worse than refusing: the
			// record would look complete.
			return fmt.Errorf("syslog: this build has no %q template, so %s messages cannot be normalised", templateID, msg.Format)
		}
		connectorRef := "syslog:" + templateID
		ocsf := tmpl.Apply(msg.Fields(), tenantID, connectorRef, receivedAt)
		events = append(events, &normalizer.NormalizedEvent{
			ID:                   uuid.NewString(),
			ConnectorID:          connectorRef,
			TenantID:             tenantID,
			OcsfEvent:            ocsf,
			NormalizationVersion: "syslog/1.0",
		})
	}

	return s.pub.PublishBatch(ctx, events)
}
