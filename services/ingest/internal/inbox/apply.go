package inbox

import (
	"strings"
	"time"

	"github.com/beenuar/aisoc/services/ingest/internal/normalizer"
)

// Apply projects a vendor JSON payload onto an OCSF event using the
// rules in t. The output is a flat map[string]interface{} ready to hand
// off to the existing Kafka publisher's NormalizedEvent envelope.
//
// We deliberately reuse the existing OCSF v1.1.0 schema rather than
// invent a sidecar shape so universal-capture events flow through the
// same correlator / detection pipeline as connector-driven ones.
func (t *Template) Apply(payload map[string]any, tenantID, connectorRef, receivedAt string) map[string]any {
	ocsf := make(map[string]any, 16+len(t.FieldMap))

	ocsf["class_uid"] = t.ClassUID
	ocsf["class_name"] = t.ClassName
	if t.ClassUID > 0 {
		ocsf["category_uid"] = t.ClassUID / 1000
	}

	// Per-event class override. A sensor that pushes routine activity and
	// correlated findings through one URL needs them in different OCSF
	// categories — the promoter always promotes category 2 and leaves
	// category 6 in the lake — and the event kind is a payload field, not
	// a property of the token. An event whose kind has no entry keeps the
	// template's declared class, so an unknown kind degrades to the
	// default rather than vanishing.
	if t.ClassField != "" && len(t.ClassMap) > 0 {
		if kind := getNestedString(payload, t.ClassField); kind != "" {
			if o, ok := t.ClassMap[strings.ToLower(strings.TrimSpace(kind))]; ok {
				ocsf["class_uid"] = o.ClassUID
				ocsf["class_name"] = o.ClassName
				ocsf["category_uid"] = o.ClassUID / 1000
			}
		}
	}
	if t.ActivityID != 0 {
		ocsf["activity_id"] = t.ActivityID
	} else {
		ocsf["activity_id"] = 1
	}

	// Time. Prefer the configured field; fall back to RFC3339 receipt time.
	timeField := t.TimeField
	if timeField == "" {
		timeField = "time"
	}
	if v := getNestedString(payload, timeField); v != "" {
		ocsf["time"] = normaliseTime(v, receivedAt)
	} else {
		ocsf["time"] = receivedAt
	}
	ocsf["ingest_time"] = time.Now().UTC().Format(time.RFC3339Nano)

	// Seed metadata up front so subsequent FieldMap / Constants writes
	// targeting metadata.* paths (e.g. metadata.product.feature.name in
	// pagerduty.yaml) merge into it rather than getting clobbered by a
	// later overwrite. setNested grafts into the existing map.
	ocsf["metadata"] = map[string]any{
		"version":       "1.1.0",
		"tenant_uid":    tenantID,
		"ingested_time": time.Now().UTC().Format(time.RFC3339),
		"product": map[string]any{
			"name":        t.ProductName,
			"vendor_name": t.VendorName,
		},
	}

	// Field map — copy vendor paths onto OCSF paths.
	for src, dst := range t.FieldMap {
		if v := getNested(payload, src); v != nil {
			setNested(ocsf, dst, v)
		}
	}

	// Severity. Pull the vendor severity string (path configurable) and
	// translate via SeverityMap. Unknown severities surface as
	// severity_id=0 ("Unknown") rather than dropping the event — we'd
	// rather over-deliver than silently lose alerts.
	sevField := t.SeverityField
	if sevField == "" {
		sevField = "severity"
	}
	if raw := getNestedString(payload, sevField); raw != "" {
		key := strings.ToLower(strings.TrimSpace(raw))
		if id, ok := t.SeverityMap[key]; ok {
			ocsf["severity_id"] = id
			ocsf["severity"] = canonicalSeverity(id)
		} else {
			ocsf["severity_id"] = 0
			ocsf["severity"] = raw
		}
	} else if _, present := ocsf["severity_id"]; !present {
		ocsf["severity_id"] = 0
		ocsf["severity"] = "Unknown"
	}

	// Message — pull the configured "what happened" line into the OCSF
	// message field if not already set by the field map.
	msgField := t.MessageField
	if msgField == "" {
		msgField = "message"
	}
	if _, set := ocsf["message"]; !set {
		if m := getNestedString(payload, msgField); m != "" {
			ocsf["message"] = m
		}
	}

	// Constants — stamped last so they win over any field-map collision.
	for k, v := range t.Constants {
		setNested(ocsf, k, v)
	}

	// MITRE ATT&CK technique ids the vendor supplied, carried as supplied.
	// Same block and same contract as the connector path in
	// normalizer.Normalize: shape-validated ids only (an ATLAS AML.T****
	// or a tactic TA#### id never enters an ATT&CK-typed field), enriched
	// with name/tactics when the corpus confirms them and carried
	// verified:false when it cannot.
	if len(t.TechniqueFields) > 0 {
		ids := normalizer.TechniqueIDsFromPaths(payload, t.TechniqueFields)
		if enriched := normalizer.EnrichTechniqueIDs(ids); len(enriched) > 0 {
			ocsf["mitre_attck"] = enriched
		}
	}

	ocsf["tenant_uid"] = tenantID
	ocsf["source_connector_id"] = connectorRef

	return ocsf
}

// canonicalSeverity returns the OCSF-recommended severity name for a
// numeric severity_id. Used so the published event always has matching
// severity_id + severity strings even when the vendor severity word
// doesn't.
func canonicalSeverity(id int) string {
	switch id {
	case 1:
		return "Informational"
	case 2:
		return "Low"
	case 3:
		return "Medium"
	case 4:
		return "High"
	case 5:
		return "Critical"
	case 6:
		return "Fatal"
	default:
		return "Unknown"
	}
}

// getNested walks dot-notation paths and returns the leaf, or nil if
// any segment is missing. Arrays are not supported in the source path
// (vendor templates that need to address arrays are rare; if the user
// hits one they can use a real connector).
func getNested(m map[string]any, path string) any {
	if path == "" {
		return nil
	}
	parts := strings.Split(path, ".")
	var cur any = m
	for _, p := range parts {
		mm, ok := cur.(map[string]any)
		if !ok {
			return nil
		}
		cur = mm[p]
	}
	return cur
}

func getNestedString(m map[string]any, path string) string {
	v := getNested(m, path)
	if v == nil {
		return ""
	}
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

// setNested sets a leaf at dot-path, creating intermediate maps as
// needed. We don't try to merge with existing maps — last write wins —
// because the field-map use case is "stamp this value here", not
// "graft onto an existing tree".
func setNested(m map[string]any, path string, val any) {
	parts := strings.Split(path, ".")
	cur := m
	for i, p := range parts {
		if i == len(parts)-1 {
			cur[p] = val
			return
		}
		next, ok := cur[p].(map[string]any)
		if !ok {
			next = make(map[string]any)
			cur[p] = next
		}
		cur = next
	}
}

// normaliseTime parses a vendor timestamp into RFC3339Nano. We accept a
// generous list of formats because vendor APIs historically pick
// whichever ISO-ish flavour the original engineer was vaguely familiar
// with. Falls back to receivedAt if nothing parses.
func normaliseTime(s, fallback string) string {
	formats := []string{
		time.RFC3339Nano,
		time.RFC3339,
		"2006-01-02T15:04:05.000Z",
		"2006-01-02T15:04:05Z",
		"2006-01-02 15:04:05",
		"2006-01-02T15:04:05.000-0700",
		"01/02/2006 15:04:05",
	}
	for _, f := range formats {
		if t, err := time.Parse(f, s); err == nil {
			return t.UTC().Format(time.RFC3339Nano)
		}
	}
	return fallback
}
