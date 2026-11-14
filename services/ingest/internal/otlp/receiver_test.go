package otlp

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/beenuar/aisoc/services/ingest/internal/inbox"
	"github.com/beenuar/aisoc/services/ingest/internal/normalizer"
	"github.com/google/uuid"
	collogs "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	logspb "go.opentelemetry.io/proto/otlp/logs/v1"
	resourcepb "go.opentelemetry.io/proto/otlp/resource/v1"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

const testToken = "tok_live_otlp"

var testTenant = uuid.MustParse("00000000-0000-0000-0000-0000000000b2")

type fakeTokens struct {
	tok *inbox.Token
	err error
}

func (f *fakeTokens) Resolve(_ context.Context, token string) (*inbox.Token, error) {
	if f.err != nil {
		return nil, f.err
	}
	if token != testToken {
		return nil, errors.New("no such token")
	}
	return f.tok, nil
}

type fakeTemplates struct{ tmpl *inbox.Template }

func (f *fakeTemplates) Get(id string) (*inbox.Template, error) {
	if f.tmpl == nil || id != f.tmpl.ID {
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

// The real template, loaded from the YAML that ships in the binary, so a
// test cannot pass against a template shape the service does not have.
func realTemplate(t *testing.T) *inbox.Template {
	t.Helper()
	reg := inbox.NewRegistry()
	if err := reg.LoadEmbedded(); err != nil {
		t.Fatalf("embedded templates: %v", err)
	}
	tmpl, err := reg.Get(TemplateID)
	if err != nil {
		t.Fatalf("this build has no %q template: %v", TemplateID, err)
	}
	return tmpl
}

func harness(t *testing.T) (*Receiver, *fakePublisher, *fakeTokens) {
	t.Helper()
	tokens := &fakeTokens{tok: &inbox.Token{Token: testToken, TenantID: testTenant, TemplateID: TemplateID}}
	pub := &fakePublisher{}
	r, err := New(tokens, &fakeTemplates{tmpl: realTemplate(t)}, pub)
	if err != nil {
		t.Fatal(err)
	}
	return r, pub, tokens
}

func exportRequest(records ...*logspb.LogRecord) *collogs.ExportLogsServiceRequest {
	return &collogs.ExportLogsServiceRequest{
		ResourceLogs: []*logspb.ResourceLogs{{
			Resource: &resourcepb.Resource{Attributes: []*commonpb.KeyValue{
				str("service.name", "checkout-api"),
				str("host.name", "node-14"),
			}},
			ScopeLogs: []*logspb.ScopeLogs{{
				Scope:      &commonpb.InstrumentationScope{Name: "app/auth", Version: "1.2.0"},
				LogRecords: records,
			}},
		}},
	}
}

func str(k, v string) *commonpb.KeyValue {
	return &commonpb.KeyValue{Key: k, Value: &commonpb.AnyValue{
		Value: &commonpb.AnyValue_StringValue{StringValue: v},
	}}
}

func record(body string, severity logspb.SeverityNumber, attrs ...*commonpb.KeyValue) *logspb.LogRecord {
	return &logspb.LogRecord{
		TimeUnixNano:   1760000000000000000,
		SeverityNumber: severity,
		Body:           &commonpb.AnyValue{Value: &commonpb.AnyValue_StringValue{StringValue: body}},
		Attributes:     attrs,
	}
}

func post(t *testing.T, r *Receiver, contentType string, body []byte, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/v1/logs", bytes.NewReader(body))
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	req.Header.Set("Authorization", "Bearer "+testToken)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	r.ServeLogs(w, req)
	return w
}

func mustProto(t *testing.T, m proto.Message) []byte {
	t.Helper()
	b, err := proto.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func mustJSON(t *testing.T, m proto.Message) []byte {
	t.Helper()
	b, err := protojson.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// ---------------------------------------------------------------------------
// Both encodings. A receiver that reads one of them is a receiver half the
// estates cannot use.
// ---------------------------------------------------------------------------

func TestProtobufAndJSONBothLand(t *testing.T) {
	for _, tc := range []struct {
		name        string
		contentType string
		encode      func(*testing.T, proto.Message) []byte
	}{
		{"protobuf", "application/x-protobuf", mustProto},
		{"json", "application/json", mustJSON},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, pub, _ := harness(t)
			body := tc.encode(t, exportRequest(record("login failed", logspb.SeverityNumber_SEVERITY_NUMBER_ERROR)))
			w := post(t, r, tc.contentType, body, nil)

			if w.Code != http.StatusOK {
				t.Fatalf("status %d: %s", w.Code, w.Body.String())
			}
			if len(pub.published) != 1 {
				t.Fatalf("published %d events", len(pub.published))
			}
			if got := pub.published[0].TenantID; got != testTenant.String() {
				t.Fatalf("tenant %q", got)
			}
		})
	}
}

// The specification says the response uses the request's encoding. A
// collector reading a protobuf response as JSON logs a decode error and
// treats a successful export as a failure.
func TestTheResponseUsesTheRequestEncoding(t *testing.T) {
	r, _, _ := harness(t)
	body := mustJSON(t, exportRequest(record("x", logspb.SeverityNumber_SEVERITY_NUMBER_INFO)))
	w := post(t, r, "application/json", body, nil)
	if ct := w.Header().Get("Content-Type"); ct != "application/json" {
		t.Fatalf("JSON request answered %q", ct)
	}

	r2, _, _ := harness(t)
	w2 := post(t, r2, "application/x-protobuf", mustProto(t, exportRequest(record("x", logspb.SeverityNumber_SEVERITY_NUMBER_INFO))), nil)
	if ct := w2.Header().Get("Content-Type"); ct != "application/x-protobuf" {
		t.Fatalf("protobuf request answered %q", ct)
	}
}

func TestAGzippedBodyIsAccepted(t *testing.T) {
	r, pub, _ := harness(t)
	raw := mustProto(t, exportRequest(record("compressed", logspb.SeverityNumber_SEVERITY_NUMBER_WARN)))
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	if _, err := gz.Write(raw); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}

	w := post(t, r, "application/x-protobuf", buf.Bytes(), map[string]string{"Content-Encoding": "gzip"})
	if w.Code != http.StatusOK {
		t.Fatalf("status %d: %s", w.Code, w.Body.String())
	}
	if len(pub.published) != 1 {
		t.Fatalf("published %d", len(pub.published))
	}
}

// ---------------------------------------------------------------------------
// Projection.
// ---------------------------------------------------------------------------

func TestResourceAndScopeAttributesReachTheOCSFEvent(t *testing.T) {
	r, pub, _ := harness(t)
	rec := record("disk full", logspb.SeverityNumber_SEVERITY_NUMBER_ERROR, str("process.pid", "4120"))
	rec.TraceId, _ = hex.DecodeString("0123456789abcdef0123456789abcdef")
	rec.SpanId, _ = hex.DecodeString("0123456789abcdef")

	if w := post(t, r, "application/x-protobuf", mustProto(t, exportRequest(rec)), nil); w.Code != http.StatusOK {
		t.Fatalf("status %d: %s", w.Code, w.Body.String())
	}

	ev := pub.published[0].OcsfEvent
	device, _ := ev["device"].(map[string]any)
	if device == nil || device["hostname"] != "node-14" {
		t.Fatalf("resource attribute host.name did not reach device.hostname: %#v", ev["device"])
	}
	actor, _ := ev["actor"].(map[string]any)
	process, _ := actor["process"].(map[string]any)
	if process == nil || process["name"] != "checkout-api" {
		t.Fatalf("service.name did not reach actor.process.name: %#v", actor)
	}
	if process["pid"] != "4120" {
		t.Fatalf("process.pid did not reach actor.process.pid: %#v", process)
	}
	meta, _ := ev["metadata"].(map[string]any)
	if meta["correlation_uid"] != "0123456789abcdef0123456789abcdef" {
		t.Fatalf("trace id did not reach metadata.correlation_uid: %#v", meta)
	}
	if meta["logged_by"] != "app/auth" {
		t.Fatalf("scope name did not reach metadata.logged_by: %#v", meta)
	}
	if ev["message"] != "disk full" {
		t.Fatalf("body did not reach message: %#v", ev["message"])
	}
}

// The number is the authoritative field. An emitter that sets only it must
// still get a severity, or every such record files as Unknown.
func TestSeverityIsDerivedFromTheNumberWhenTheTextIsAbsent(t *testing.T) {
	for _, tc := range []struct {
		number logspb.SeverityNumber
		wantID int
	}{
		{logspb.SeverityNumber_SEVERITY_NUMBER_DEBUG, 1},
		{logspb.SeverityNumber_SEVERITY_NUMBER_INFO, 1},
		{logspb.SeverityNumber_SEVERITY_NUMBER_WARN, 3},
		{logspb.SeverityNumber_SEVERITY_NUMBER_ERROR, 4},
		{logspb.SeverityNumber_SEVERITY_NUMBER_FATAL, 6},
	} {
		t.Run(tc.number.String(), func(t *testing.T) {
			r, pub, _ := harness(t)
			if w := post(t, r, "application/x-protobuf", mustProto(t, exportRequest(record("x", tc.number))), nil); w.Code != http.StatusOK {
				t.Fatalf("status %d", w.Code)
			}
			if got := pub.published[0].OcsfEvent["severity_id"]; got != tc.wantID {
				t.Fatalf("severity_id %v, want %d", got, tc.wantID)
			}
		})
	}
}

// Every attribute on a record is set by the emitter, so a tenant read from
// one would be a cross-tenant write any instrumented process could perform.
func TestATenantAttributeIsIgnored(t *testing.T) {
	r, pub, _ := harness(t)
	attacker := "00000000-0000-0000-0000-00000000beef"
	req := exportRequest(record("x", logspb.SeverityNumber_SEVERITY_NUMBER_INFO, str("tenant_id", attacker)))
	req.ResourceLogs[0].Resource.Attributes = append(req.ResourceLogs[0].Resource.Attributes, str("tenant_uid", attacker))

	if w := post(t, r, "application/x-protobuf", mustProto(t, req), nil); w.Code != http.StatusOK {
		t.Fatalf("status %d", w.Code)
	}
	if got := pub.published[0].TenantID; got != testTenant.String() {
		t.Fatalf("tenant came from the record: %q", got)
	}
	if got := pub.published[0].OcsfEvent["tenant_uid"]; got != testTenant.String() {
		t.Fatalf("tenant_uid in the OCSF event came from the record: %v", got)
	}
}

// ---------------------------------------------------------------------------
// What a client is told. This is the part receivers usually skip.
// ---------------------------------------------------------------------------

func TestAPublishFailureIs503WithRetryAfterRatherThan200Or400(t *testing.T) {
	r, pub, _ := harness(t)
	pub.err = errors.New("kafka: no brokers")

	w := post(t, r, "application/x-protobuf", mustProto(t, exportRequest(record("x", logspb.SeverityNumber_SEVERITY_NUMBER_INFO))), nil)

	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("status %d; a 200 tells the collector these landed and a 400 makes it discard them", w.Code)
	}
	if w.Header().Get("Retry-After") == "" {
		t.Fatal("no Retry-After, so the collector has nothing to pace its retry by")
	}
}

func TestAWellFormedEmptyBatchIsAcceptedRatherThanRetriedForever(t *testing.T) {
	r, _, _ := harness(t)
	w := post(t, r, "application/x-protobuf", mustProto(t, &collogs.ExportLogsServiceRequest{}), nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status %d: an empty batch is not the collector's fault", w.Code)
	}
}

func TestPartialSuccessIsReportedRatherThanABlanket200(t *testing.T) {
	r, pub, _ := harness(t)
	// One projectable record and one nil, which is what a buggy emitter
	// and a truncated batch both look like on the wire.
	req := exportRequest(record("good", logspb.SeverityNumber_SEVERITY_NUMBER_INFO), nil)

	w := post(t, r, "application/json", mustJSON(t, req), nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status %d", w.Code)
	}
	if len(pub.published) != 1 {
		t.Fatalf("published %d; the good record must still land", len(pub.published))
	}
	var resp collogs.ExportLogsServiceResponse
	if err := protojson.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("response is not an ExportLogsServiceResponse: %v", err)
	}
	if resp.GetPartialSuccess().GetRejectedLogRecords() != 1 {
		t.Fatalf("rejected_log_records %d, want 1", resp.GetPartialSuccess().GetRejectedLogRecords())
	}
	if resp.GetPartialSuccess().GetErrorMessage() == "" {
		t.Fatal("partial success with no message tells the operator nothing")
	}
}

// ---------------------------------------------------------------------------
// Refusals, each naming the operator's next move.
// ---------------------------------------------------------------------------

func TestRefusals(t *testing.T) {
	good := mustProto(t, exportRequest(record("x", logspb.SeverityNumber_SEVERITY_NUMBER_INFO)))

	t.Run("no token", func(t *testing.T) {
		r, _, _ := harness(t)
		req := httptest.NewRequest(http.MethodPost, "/v1/logs", bytes.NewReader(good))
		req.Header.Set("Content-Type", "application/x-protobuf")
		w := httptest.NewRecorder()
		r.ServeLogs(w, req)
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("status %d", w.Code)
		}
		var resp collogs.ExportLogsServiceResponse
		if err := proto.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(resp.GetPartialSuccess().GetErrorMessage(), "OTEL_EXPORTER_OTLP_HEADERS") {
			t.Fatalf("the message does not name the fix: %q", resp.GetPartialSuccess().GetErrorMessage())
		}
	})

	t.Run("no content type", func(t *testing.T) {
		r, _, _ := harness(t)
		w := post(t, r, "", good, nil)
		if w.Code != http.StatusUnsupportedMediaType {
			t.Fatalf("status %d", w.Code)
		}
	})

	t.Run("wrong content type", func(t *testing.T) {
		r, _, _ := harness(t)
		w := post(t, r, "text/plain", good, nil)
		if w.Code != http.StatusUnsupportedMediaType {
			t.Fatalf("status %d", w.Code)
		}
	})

	t.Run("token minted with another template", func(t *testing.T) {
		r, _, tokens := harness(t)
		tokens.tok.TemplateID = "splunk-hec"
		w := post(t, r, "application/x-protobuf", good, nil)
		if w.Code != http.StatusForbidden {
			t.Fatalf("status %d", w.Code)
		}
		var resp collogs.ExportLogsServiceResponse
		if err := proto.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(resp.GetPartialSuccess().GetErrorMessage(), TemplateID) {
			t.Fatalf("the message does not name the template needed: %q", resp.GetPartialSuccess().GetErrorMessage())
		}
	})

	t.Run("undecodable body", func(t *testing.T) {
		r, _, _ := harness(t)
		w := post(t, r, "application/json", []byte("{not json"), nil)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("status %d", w.Code)
		}
	})
}

// A collector a version ahead of this build must not have its whole batch
// refused over one field this build has never heard of.
func TestAnUnknownJSONFieldDoesNotRefuseTheBatch(t *testing.T) {
	r, pub, _ := harness(t)
	body := mustJSON(t, exportRequest(record("x", logspb.SeverityNumber_SEVERITY_NUMBER_INFO)))
	withUnknown := strings.Replace(string(body), "{", `{"somethingNewInOTLP":1,`, 1)

	w := post(t, r, "application/json", []byte(withUnknown), nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status %d: %s", w.Code, w.Body.String())
	}
	if len(pub.published) != 1 {
		t.Fatalf("published %d", len(pub.published))
	}
}

// ---------------------------------------------------------------------------
// Readiness.
// ---------------------------------------------------------------------------

func TestReadinessDistinguishesQuietFromRefusingEverything(t *testing.T) {
	r, _, _ := harness(t)
	if !strings.Contains(r.Detail(), "nothing has arrived yet") {
		t.Fatalf("a receiver nobody has exported to reports %q", r.Detail())
	}

	post(t, r, "application/x-protobuf", mustProto(t, exportRequest(record("x", logspb.SeverityNumber_SEVERITY_NUMBER_INFO))), nil)
	if !strings.Contains(r.Detail(), "records 1") {
		t.Fatalf("after one record readiness reports %q", r.Detail())
	}
}

// ---------------------------------------------------------------------------
// Attribute flattening.
// ---------------------------------------------------------------------------

func TestADottedAttributeBecomesNestedSoTheTemplateCanReadIt(t *testing.T) {
	payload, err := recordPayload(
		record("x", logspb.SeverityNumber_SEVERITY_NUMBER_INFO),
		map[string]any{"service.name": "api", "service.version": "2"},
		nil, "", "",
	)
	if err != nil {
		t.Fatal(err)
	}
	service, ok := payload["service"].(map[string]any)
	if !ok {
		t.Fatalf("service is %T, not a nested map", payload["service"])
	}
	if service["name"] != "api" || service["version"] != "2" {
		t.Fatalf("nested attributes wrong: %#v", service)
	}
}

// A scalar already in the way must not be clobbered, and the attribute
// must not be silently dropped either.
func TestAScalarInTheWayKeepsBothAttributes(t *testing.T) {
	payload, err := recordPayload(
		record("x", logspb.SeverityNumber_SEVERITY_NUMBER_INFO),
		map[string]any{"service": "api", "service.name": "checkout"},
		nil, "", "",
	)
	if err != nil {
		t.Fatal(err)
	}
	// Map iteration order is random, so one of the two orders happened.
	// Both attributes must survive whichever it was.
	switch svc := payload["service"].(type) {
	case string:
		if svc != "api" || payload["service.name"] != "checkout" {
			t.Fatalf("an attribute was lost: %#v", payload)
		}
	case map[string]any:
		if svc["name"] != "checkout" || payload["service"] == nil {
			t.Fatalf("an attribute was lost: %#v", payload)
		}
	default:
		t.Fatalf("service is %T", payload["service"])
	}
}

func TestRawDataIsAJSONStringLikeEverythingElseInThisService(t *testing.T) {
	r, pub, _ := harness(t)
	if w := post(t, r, "application/x-protobuf", mustProto(t, exportRequest(record("x", logspb.SeverityNumber_SEVERITY_NUMBER_INFO))), nil); w.Code != http.StatusOK {
		t.Fatalf("status %d", w.Code)
	}
	if _, ok := pub.published[0].OcsfEvent["raw_data"].(string); !ok {
		t.Fatalf("raw_data is %T, not a JSON string", pub.published[0].OcsfEvent["raw_data"])
	}
}
