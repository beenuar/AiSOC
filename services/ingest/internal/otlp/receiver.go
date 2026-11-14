// Package otlp implements an OpenTelemetry Protocol logs receiver.
//
// Depth item 4.2 / parity 6.10. An estate that already runs an OpenTelemetry
// Collector has a logs pipeline and an exporter; what it does not have is
// somewhere to point the exporter. This is that endpoint:
//
//	POST /v1/logs   Content-Type: application/x-protobuf
//	POST /v1/logs   Content-Type: application/json
//
// Both encodings are in the specification and real collectors emit both, so
// a receiver that reads one of them is a receiver half the estates cannot
// use. gzip request bodies are accepted because the OTLP/HTTP specification
// says a client may send them and the collector's default exporter does.
//
// Where the tenant comes from
// ---------------------------
// From a minted ingest token presented as `Authorization: Bearer <token>`,
// and from nowhere else. OTLP has no notion of a tenant, and every
// attribute on a record is set by the emitter, so a tenant read out of
// `resource.attributes` would be a cross-tenant write any instrumented
// process could perform. An OTLP exporter sets request headers through
// OTEL_EXPORTER_OTLP_HEADERS, which is how the token gets here.
//
// What a client is told
// ---------------------
// The specification's partial-success contract, which is the part receivers
// usually skip. A request whose records are partly unreadable returns 200
// with `partial_success.rejected_log_records` set and a human message —
// *not* a blanket 200, which would tell a collector everything landed, and
// not a 400, which would make it retry records that did land. A full
// failure returns 503 with Retry-After so the collector's queue retries
// rather than dropping.
package otlp

import (
	"compress/gzip"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/beenuar/aisoc/services/ingest/internal/inbox"
	"github.com/beenuar/aisoc/services/ingest/internal/normalizer"
	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/rs/zerolog/log"
	collogs "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	logspb "go.opentelemetry.io/proto/otlp/logs/v1"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

// TemplateID is the OCSF template an OTLP token must be minted with.
const TemplateID = "otlp-logs"

// MaxBodyBytes caps one request. An uncapped receiver is a way to make the
// ingest service run out of memory from the outside.
const MaxBodyBytes int64 = 16 << 20

var (
	otlpRecords = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "aisoc_ingest_otlp_log_records_total",
		Help: "OTLP log records accepted.",
	}, []string{"encoding"})
	otlpRejected = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "aisoc_ingest_otlp_rejected_total",
		Help: "OTLP log records or requests refused, by reason.",
	}, []string{"reason"})
)

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

// State is what readiness reports about the receiver. A receiver nobody is
// sending to and a receiver refusing everything look identical from outside
// unless the state is named, and silence is the normal condition for a logs
// endpoint.
type State struct {
	Enabled   bool
	Received  uint64
	Rejected  uint64
	LastError string
	LastAt    time.Time
}

// Receiver serves the OTLP logs endpoint.
type Receiver struct {
	tokens    TokenResolver
	templates TemplateSource
	pub       Publisher

	mu    sync.Mutex
	state State
}

// New wires the receiver.
func New(tokens TokenResolver, templates TemplateSource, pub Publisher) (*Receiver, error) {
	if tokens == nil || templates == nil || pub == nil {
		return nil, errors.New("otlp: receiver needs a token resolver, a template source and a publisher")
	}
	return &Receiver{tokens: tokens, templates: templates, pub: pub, state: State{Enabled: true}}, nil
}

// Health is a snapshot for the readiness endpoint.
func (r *Receiver) Health() State {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.state
}

// Detail is the sentence /readyz shows, healthy or not.
func (r *Receiver) Detail() string {
	s := r.Health()
	detail := fmt.Sprintf("accepting OTLP logs on POST /v1/logs; records %d, rejected %d", s.Received, s.Rejected)
	if s.Received == 0 && s.Rejected == 0 {
		detail += " (nothing has arrived yet)"
	}
	if s.LastError != "" {
		detail += "; last error: " + s.LastError
	}
	return detail
}

// encoding is how one request was framed, which also decides how the
// response must be framed: the specification requires the response to use
// the same encoding as the request.
type encoding string

const (
	encodingProtobuf encoding = "protobuf"
	encodingJSON     encoding = "json"
)

// ServeLogs handles POST /v1/logs.
func (r *Receiver) ServeLogs(w http.ResponseWriter, req *http.Request) {
	enc, err := encodingOf(req.Header.Get("Content-Type"))
	if err != nil {
		r.refuse(w, encodingProtobuf, http.StatusUnsupportedMediaType, "unsupported_media_type", err.Error())
		return
	}

	token := bearerToken(req)
	if token == "" {
		// Named rather than a bare 401: an OTLP exporter is configured by
		// someone who has never seen this product's token concept, and
		// "unauthorized" sends them to look at their collector.
		r.refuse(w, enc, http.StatusUnauthorized, "no_token",
			"no ingest token; set OTEL_EXPORTER_OTLP_HEADERS=\"Authorization=Bearer <token>\" with a token minted for the "+TemplateID+" template")
		return
	}

	body, err := readBody(req)
	if err != nil {
		r.refuse(w, enc, http.StatusBadRequest, "unreadable_body", err.Error())
		return
	}
	if len(body) == 0 && enc == encodingJSON {
		// An empty *protobuf* body is a well-formed empty batch — a
		// message with no fields set encodes to zero bytes — so only the
		// JSON encoding can say an empty body is wrong. Refusing both
		// would answer 400 to a request the specification allows.
		r.refuse(w, enc, http.StatusBadRequest, "unreadable_body", "empty body; OTLP/JSON needs at least {}")
		return
	}

	export := &collogs.ExportLogsServiceRequest{}
	switch enc {
	case encodingJSON:
		// DiscardUnknown: the OTLP schema gains fields, and a collector a
		// version ahead of this build must not have its whole batch
		// refused over one field this build has never heard of.
		if err := (protojson.UnmarshalOptions{DiscardUnknown: true}).Unmarshal(body, export); err != nil {
			r.refuse(w, enc, http.StatusBadRequest, "undecodable", "the body is not an OTLP ExportLogsServiceRequest in JSON: "+err.Error())
			return
		}
	default:
		if err := proto.Unmarshal(body, export); err != nil {
			r.refuse(w, enc, http.StatusBadRequest, "undecodable", "the body is not an OTLP ExportLogsServiceRequest in protobuf: "+err.Error())
			return
		}
	}

	tok, err := r.tokens.Resolve(req.Context(), token)
	if err != nil {
		r.refuse(w, enc, http.StatusUnauthorized, "bad_token", "the presented ingest token is not valid")
		return
	}
	if tok.TemplateID != TemplateID {
		r.refuse(w, enc, http.StatusForbidden, "wrong_template",
			fmt.Sprintf("this token was minted with template %q; the OTLP receiver needs one minted with %q", tok.TemplateID, TemplateID))
		return
	}
	tmpl, err := r.templates.Get(TemplateID)
	if err != nil {
		r.refuse(w, enc, http.StatusServiceUnavailable, "no_template", "this build has no "+TemplateID+" template, so OTLP records cannot be normalised")
		return
	}

	events, rejected, reason := r.project(export, tok, tmpl)

	if len(events) == 0 {
		if rejected == 0 {
			// An empty but well-formed batch. The collector did nothing
			// wrong and must be told so, or it retries forever.
			r.writeSuccess(w, enc, 0, "")
			return
		}
		r.note(0, rejected, reason)
		otlpRejected.WithLabelValues("unprojectable").Add(float64(rejected))
		r.writeSuccess(w, enc, rejected, reason)
		return
	}

	if err := r.pub.PublishBatch(req.Context(), events); err != nil {
		// 503 with Retry-After, not 200 and not 400. The collector's queue
		// is the thing that will hold these records until the broker is
		// back, and both of the other answers throw them away: 200 says
		// they landed, 400 says they never will.
		r.note(0, uint64(len(events)), err.Error())
		otlpRejected.WithLabelValues("publish_error").Add(float64(len(events)))
		log.Error().Err(err).Int("records", len(events)).Msg("otlp: publish failed; answering 503 so the collector retries")
		w.Header().Set("Retry-After", "5")
		r.refuse(w, enc, http.StatusServiceUnavailable, "publish_error", "the event bus is unreachable; retry")
		return
	}

	r.note(uint64(len(events)), rejected, reason)
	otlpRecords.WithLabelValues(string(enc)).Add(float64(len(events)))
	if rejected > 0 {
		otlpRejected.WithLabelValues("unprojectable").Add(float64(rejected))
	}
	r.writeSuccess(w, enc, rejected, reason)
}

// project turns an export request into normalised events.
//
// A record that cannot be projected is counted and skipped rather than
// failing the batch: one emitter sending something odd must not cost every
// other emitter in the same collector their records.
func (r *Receiver) project(export *collogs.ExportLogsServiceRequest, tok *inbox.Token, tmpl *inbox.Template) ([]*normalizer.NormalizedEvent, uint64, string) {
	receivedAt := time.Now().UTC().Format(time.RFC3339Nano)
	tenantID := tok.TenantID.String()
	var (
		events   []*normalizer.NormalizedEvent
		rejected uint64
		reason   string
	)

	for _, rl := range export.GetResourceLogs() {
		resourceAttrs := attributesToMap(rl.GetResource().GetAttributes())
		for _, sl := range rl.GetScopeLogs() {
			scope := sl.GetScope()
			scopeAttrs := attributesToMap(scope.GetAttributes())
			for _, record := range sl.GetLogRecords() {
				payload, err := recordPayload(record, resourceAttrs, scopeAttrs, scope.GetName(), scope.GetVersion())
				if err != nil {
					rejected++
					if reason == "" {
						reason = err.Error()
					}
					continue
				}
				ocsf := tmpl.Apply(payload, tenantID, "otlp:logs", receivedAt)
				events = append(events, &normalizer.NormalizedEvent{
					ID:                   uuid.NewString(),
					ConnectorID:          "otlp:logs",
					TenantID:             tenantID,
					OcsfEvent:            ocsf,
					NormalizationVersion: "otlp-logs/1.0",
				})
			}
		}
	}
	return events, rejected, reason
}

// recordPayload flattens one log record into the namespace the template
// reads.
//
// Attribute keys in OpenTelemetry are dotted by convention (`service.name`,
// `host.name`), and the template's path lookup splits on dots, so a dotted
// key is written as nested maps. A key that would have to overwrite a
// scalar already at that path is kept under its literal name instead —
// silently dropping it would lose an attribute, and clobbering would lose
// the other one.
func recordPayload(record *logspb.LogRecord, resourceAttrs, scopeAttrs map[string]any, scopeName, scopeVersion string) (map[string]any, error) {
	if record == nil {
		return nil, errors.New("a log record carrying no body, attributes, severity or timestamp")
	}
	// A record with nothing of its own is the one thing this receiver
	// refuses, and it is a real shape rather than a theoretical one: a
	// truncated or garbled batch arrives as empty records. The resource
	// and scope attributes are deliberately not counted here — they are
	// identical for every record in the batch and carry no event content,
	// so an empty record inside a well-described resource would still
	// project to an OCSF event that says nothing happened.
	//
	// Refusing them is also what gives the partial-success contract below
	// something to report, so it is exercised rather than being a
	// mechanism with no caller.
	if isEmptyRecord(record) {
		return nil, errors.New("a log record carrying no body, attributes, severity or timestamp")
	}
	payload := map[string]any{}

	// Resource first, then scope, then the record's own: the narrower
	// scope wins, which is the precedence the data model describes.
	for _, attrs := range []map[string]any{resourceAttrs, scopeAttrs, attributesToMap(record.GetAttributes())} {
		for k, v := range attrs {
			assign(payload, k, v)
		}
	}

	payload["body"] = anyValueToString(record.GetBody())
	payload["severity_number"] = int(record.GetSeverityNumber())
	severityText := strings.TrimSpace(record.GetSeverityText())
	if severityText == "" {
		// The number is the authoritative field; an emitter may set only
		// it. Deriving the text here is what keeps the template's ladder
		// from reading an empty string and filing everything as Unknown.
		severityText = severityTextFor(record.GetSeverityNumber())
	}
	payload["severity_text"] = severityText

	if ts := record.GetTimeUnixNano(); ts > 0 {
		payload["timestamp"] = time.Unix(0, int64(ts)).UTC().Format(time.RFC3339Nano)
	} else if ts := record.GetObservedTimeUnixNano(); ts > 0 {
		payload["timestamp"] = time.Unix(0, int64(ts)).UTC().Format(time.RFC3339Nano)
	}
	if id := record.GetTraceId(); len(id) > 0 {
		payload["trace_id"] = hex.EncodeToString(id)
	}
	if id := record.GetSpanId(); len(id) > 0 {
		payload["span_id"] = hex.EncodeToString(id)
	}
	if scopeName != "" {
		payload["scope_name"] = scopeName
	}
	if scopeVersion != "" {
		payload["scope_version"] = scopeVersion
	}
	if n := record.GetDroppedAttributesCount(); n > 0 {
		// Carried rather than ignored: a record that arrived with
		// attributes missing is a different thing from one that never had
		// them, and only the emitter knows which.
		payload["dropped_attributes_count"] = int(n)
	}

	// raw_data is written as a JSON string, which is what ingest does
	// everywhere else in this service; a reader expecting a map here is
	// the defect this convention exists to avoid.
	if raw, err := json.Marshal(payload); err == nil {
		payload["raw"] = string(raw)
	}
	return payload, nil
}

// isEmptyRecord reports a record that carries nothing of its own.
func isEmptyRecord(record *logspb.LogRecord) bool {
	return anyValueToString(record.GetBody()) == "" &&
		len(record.GetAttributes()) == 0 &&
		record.GetSeverityNumber() == logspb.SeverityNumber_SEVERITY_NUMBER_UNSPECIFIED &&
		strings.TrimSpace(record.GetSeverityText()) == "" &&
		record.GetTimeUnixNano() == 0 &&
		record.GetObservedTimeUnixNano() == 0 &&
		len(record.GetTraceId()) == 0 &&
		len(record.GetSpanId()) == 0
}

// assign writes a possibly-dotted attribute key into the payload as nested
// maps, refusing to overwrite a scalar that is already in the way.
func assign(payload map[string]any, key string, value any) {
	if key == "" {
		return
	}
	parts := strings.Split(key, ".")
	cur := payload
	for i, p := range parts {
		if i == len(parts)-1 {
			if existing, isMap := cur[p].(map[string]any); isMap {
				if _, incomingIsMap := value.(map[string]any); !incomingIsMap {
					// The mirror of the scalar-in-the-way case below, which
					// map iteration order decides: `service.name` arrived
					// first and built a map, and the scalar `service` would
					// overwrite it, silently dropping the attribute. Demote
					// the map's entries to their literal dotted names first —
					// the exact payload the opposite arrival order produces,
					// so the outcome stops depending on iteration order.
					flattenInto(payload, strings.Join(parts, "."), existing)
				}
			}
			cur[p] = value
			return
		}
		next, ok := cur[p].(map[string]any)
		if !ok {
			if _, occupied := cur[p]; occupied {
				// A scalar is in the way: `service` is already a string
				// and `service.name` wants it to be a map. Keep both by
				// writing the literal key at the top level.
				payload[key] = value
				return
			}
			next = map[string]any{}
			cur[p] = next
		}
		cur = next
	}
}

// flattenInto writes a nested map's leaves under their literal dotted names,
// never overwriting a key that already exists.
func flattenInto(payload map[string]any, prefix string, m map[string]any) {
	for k, v := range m {
		full := prefix + "." + k
		if sub, ok := v.(map[string]any); ok {
			flattenInto(payload, full, sub)
			continue
		}
		if _, occupied := payload[full]; !occupied {
			payload[full] = v
		}
	}
}

func attributesToMap(attrs []*commonpb.KeyValue) map[string]any {
	if len(attrs) == 0 {
		return nil
	}
	out := make(map[string]any, len(attrs))
	for _, kv := range attrs {
		if kv == nil || kv.GetKey() == "" {
			continue
		}
		out[kv.GetKey()] = anyValueToGo(kv.GetValue())
	}
	return out
}

// anyValueToGo unwraps an OTLP AnyValue. Arrays and maps are rendered as
// their JSON, because the OCSF event is a flat-ish document and a nested
// protobuf oneof is not something a detection rule can clause on.
func anyValueToGo(v *commonpb.AnyValue) any {
	if v == nil {
		return nil
	}
	switch value := v.GetValue().(type) {
	case *commonpb.AnyValue_StringValue:
		return value.StringValue
	case *commonpb.AnyValue_BoolValue:
		return value.BoolValue
	case *commonpb.AnyValue_IntValue:
		return value.IntValue
	case *commonpb.AnyValue_DoubleValue:
		return value.DoubleValue
	case *commonpb.AnyValue_BytesValue:
		return hex.EncodeToString(value.BytesValue)
	case *commonpb.AnyValue_ArrayValue:
		items := make([]any, 0, len(value.ArrayValue.GetValues()))
		for _, item := range value.ArrayValue.GetValues() {
			items = append(items, anyValueToGo(item))
		}
		return items
	case *commonpb.AnyValue_KvlistValue:
		return attributesToMap(value.KvlistValue.GetValues())
	default:
		return nil
	}
}

// anyValueToString renders a record body as the one line a log is.
func anyValueToString(v *commonpb.AnyValue) string {
	switch got := anyValueToGo(v).(type) {
	case nil:
		return ""
	case string:
		return got
	case bool:
		return strconv.FormatBool(got)
	case int64:
		return strconv.FormatInt(got, 10)
	case float64:
		return strconv.FormatFloat(got, 'f', -1, 64)
	default:
		if encoded, err := json.Marshal(got); err == nil {
			return string(encoded)
		}
		return fmt.Sprintf("%v", got)
	}
}

// severityTextFor maps the OTLP severity number onto the short name the
// specification defines for it. The ladder in otlp-logs.yaml reads the
// text, so a record carrying only a number still gets a severity.
func severityTextFor(n logspb.SeverityNumber) string {
	switch {
	case n >= 21:
		return "fatal"
	case n >= 17:
		return "error"
	case n >= 13:
		return "warn"
	case n >= 9:
		return "info"
	case n >= 5:
		return "debug"
	case n >= 1:
		return "trace"
	default:
		return ""
	}
}

func encodingOf(contentType string) (encoding, error) {
	media := strings.TrimSpace(strings.SplitN(contentType, ";", 2)[0])
	switch strings.ToLower(media) {
	case "application/x-protobuf", "application/protobuf":
		return encodingProtobuf, nil
	case "application/json":
		return encodingJSON, nil
	case "":
		// The specification requires the header. Defaulting silently to
		// protobuf would turn a JSON body into "undecodable", which sends
		// the operator to debug their payload instead of their header.
		return encodingProtobuf, errors.New("no Content-Type; OTLP/HTTP requires application/x-protobuf or application/json")
	default:
		return encodingProtobuf, fmt.Errorf("content type %q is not an OTLP encoding; use application/x-protobuf or application/json", media)
	}
}

func bearerToken(req *http.Request) string {
	if h := req.Header.Get("Authorization"); h != "" {
		if after, found := strings.CutPrefix(h, "Bearer "); found {
			return strings.TrimSpace(after)
		}
		if after, found := strings.CutPrefix(h, "bearer "); found {
			return strings.TrimSpace(after)
		}
	}
	// A collector that cannot be made to send Authorization can send the
	// same header every other push path on this service accepts.
	return strings.TrimSpace(req.Header.Get("X-Inbox-Token"))
}

func readBody(req *http.Request) ([]byte, error) {
	var reader io.Reader = http.MaxBytesReader(nil, req.Body, MaxBodyBytes)
	if strings.EqualFold(req.Header.Get("Content-Encoding"), "gzip") {
		gz, err := gzip.NewReader(reader)
		if err != nil {
			return nil, fmt.Errorf("Content-Encoding is gzip but the body is not: %w", err)
		}
		defer func() { _ = gz.Close() }()
		reader = io.LimitReader(gz, MaxBodyBytes)
	}
	body, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("reading the request body: %w", err)
	}
	return body, nil
}

func (r *Receiver) note(received, rejected uint64, lastError string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.state.Received += received
	r.state.Rejected += rejected
	if lastError != "" {
		r.state.LastError = lastError
	}
	r.state.LastAt = time.Now().UTC()
}

// writeSuccess answers 200 with the specification's partial-success body.
func (r *Receiver) writeSuccess(w http.ResponseWriter, enc encoding, rejected uint64, message string) {
	resp := &collogs.ExportLogsServiceResponse{}
	if rejected > 0 {
		if message == "" {
			message = "some records could not be projected"
		}
		resp.PartialSuccess = &collogs.ExportLogsPartialSuccess{
			RejectedLogRecords: int64(rejected),
			ErrorMessage:       message,
		}
	}
	r.writeProto(w, enc, http.StatusOK, resp)
}

// refuse answers a status with a body in the request's own encoding. The
// message is the operator's next move, not a restatement of the status.
func (r *Receiver) refuse(w http.ResponseWriter, enc encoding, status int, reason, message string) {
	otlpRejected.WithLabelValues(reason).Inc()
	r.note(0, 0, message)
	// The OTLP specification says a non-200 carries a google.rpc.Status.
	// Returning the partial-success shape with the message is what every
	// collector logs, and it keeps one body type on this endpoint.
	resp := &collogs.ExportLogsServiceResponse{
		PartialSuccess: &collogs.ExportLogsPartialSuccess{ErrorMessage: message},
	}
	r.writeProto(w, enc, status, resp)
}

func (r *Receiver) writeProto(w http.ResponseWriter, enc encoding, status int, resp *collogs.ExportLogsServiceResponse) {
	var (
		body []byte
		err  error
	)
	if enc == encodingJSON {
		w.Header().Set("Content-Type", "application/json")
		body, err = protojson.Marshal(resp)
	} else {
		w.Header().Set("Content-Type", "application/x-protobuf")
		body, err = proto.Marshal(resp)
	}
	if err != nil {
		log.Error().Err(err).Msg("otlp: encoding the response failed")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.WriteHeader(status)
	if _, err := w.Write(body); err != nil {
		log.Debug().Err(err).Msg("otlp: the client went away before the response was written")
	}
}
