package activity

import (
	"regexp"
	"strings"
)

// Action, resource, location and outcome.
//
// `action` is a normalized verb: a short, lower-case, dotted string the same
// across vendors, so a hunt for "somebody created a credential" does not have
// to enumerate `CreateAccessKey`, `system.api_token.create`,
// `Add service principal credentials` and `personal_access_token.create`.
//
// The normalization here is structural — it folds a vendor's own event
// identifier into a stable shape and lower-cases it. It deliberately does not
// try to map vendor verbs onto a semantic taxonomy: that is the event
// catalogue's job (depth plan 2.3), which is a reviewed data file rather than
// a regex, and which also carries the sensitivity and ATT&CK hint a verb
// alone cannot.

// actionSplitter breaks CamelCase at a lower-to-upper boundary so AWS's
// `CreateAccessKey` becomes `create.access.key` rather than one opaque token.
var actionSplitter = regexp.MustCompile(`([a-z0-9])([A-Z])`)

// actionCleaner collapses anything that is not alphanumeric into the dotted
// separator, so a vendor's spaces, slashes, colons and hyphens all land on
// one spelling.
var actionCleaner = regexp.MustCompile(`[^a-z0-9]+`)

// deriveAction returns the normalized verb, or "" when the source names no
// event type. An empty action is honest: several connectors emit only a
// human-readable title, and inventing a verb from prose would produce a
// vocabulary nothing else in the platform shares.
func deriveAction(connectorType string, payload, vendor, ocsf map[string]any) string {
	raw := vendorActionField(connectorType, payload, vendor, ocsf)
	return NormalizeAction(raw)
}

// vendorActionField reads the field whose documented meaning is "what
// happened", per source. Order within each case is precedence.
func vendorActionField(connectorType string, payload, vendor, ocsf map[string]any) string {
	switch connectorType {
	case "aws_cloudtrail":
		if v := firstStr(vendor, []string{"eventName"}, []string{"EventName"}); v != "" {
			return v
		}
	case "okta", "okta_system_log":
		if v := str(vendor, "eventType"); v != "" {
			return v
		}
	case "m365_audit":
		if v := str(vendor, "Operation"); v != "" {
			return v
		}
	case "google_workspace":
		if events, ok := nested(vendor, "events").([]any); ok && len(events) > 0 {
			if first, ok := events[0].(map[string]any); ok {
				if v := str(first, "name"); v != "" {
					return v
				}
			}
		}
	case "gcp_cloud_audit":
		if v := firstStr(vendor,
			[]string{"protoPayload", "methodName"},
			[]string{"methodName"},
		); v != "" {
			return v
		}
	case "azure_activity":
		if v := firstStr(vendor,
			[]string{"operationName", "value"},
			[]string{"operationName"},
		); v != "" {
			return v
		}
	case "azure_entra":
		if v := str(vendor, "activityDisplayName"); v != "" {
			return v
		}
	case "github", "gitlab":
		if v := firstStr(vendor, []string{"action"}, []string{"event_type"}); v != "" {
			return v
		}
	case "kubernetes_audit":
		// verb plus resource is the pair that means something: `create` on
		// its own says nothing about what was created.
		verb := str(vendor, "verb")
		resource := str(vendor, "objectRef", "resource")
		if verb != "" && resource != "" {
			return verb + "." + resource
		}
		return verb
	case "windows_event":
		// The event id *is* the verb on this source, and it is the thing
		// every Windows detection keys on.
		if v := firstStr(vendor, []string{"EventID"}, []string{"System", "EventID"}); v != "" {
			return "windows.event." + v
		}
	case "auditd":
		if v := str(vendor, "syscall"); v != "" {
			return "auditd." + v
		}
	}

	// The connector's own normalized `event_type`, which several emit, then
	// the OCSF activity name a profile mapped.
	if v := firstStr(payload, []string{"event_type"}, []string{"action"}); v != "" {
		return v
	}
	return str(ocsf, "activity_name")
}

// NormalizeAction folds a vendor's event identifier into the dotted
// lower-case shape. Exported because the event catalogue gate (depth plan
// 2.3) must normalize the same way this does, and two implementations would
// drift.
func NormalizeAction(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	// Bound an attacker-chosen event name the same way the user agent is
	// bounded; this string reaches a lake column and a graph property.
	const maxLen = 128
	if len(raw) > maxLen {
		raw = raw[:maxLen]
	}
	split := actionSplitter.ReplaceAllString(raw, "$1.$2")
	cleaned := actionCleaner.ReplaceAllString(strings.ToLower(split), ".")
	return strings.Trim(cleaned, ".")
}

// deriveResource names what was acted on. Type and id come from the source's
// own resource fields; owner is filled only where the source says who owns
// the thing, which most do not.
func deriveResource(connectorType string, payload, vendor, ocsf map[string]any) Resource {
	switch connectorType {
	case "aws_cloudtrail":
		// `resources` is CloudTrail's own array of {ARN, type, accountId}.
		if resources, ok := nested(vendor, "resources").([]any); ok && len(resources) > 0 {
			if first, ok := resources[0].(map[string]any); ok {
				return Resource{
					Type:  str(first, "type"),
					ID:    str(first, "ARN"),
					Owner: str(first, "accountId"),
				}
			}
		}
		return Resource{
			Type:  str(vendor, "eventSource"),
			Owner: str(vendor, "recipientAccountId"),
		}
	case "kubernetes_audit":
		ref, _ := nested(vendor, "objectRef").(map[string]any)
		if ref != nil {
			return Resource{
				Type:  str(ref, "resource"),
				Name:  str(ref, "name"),
				Owner: str(ref, "namespace"),
			}
		}
	case "gcp_cloud_audit":
		return Resource{
			Type: firstStr(vendor, []string{"protoPayload", "serviceName"}, []string{"resource", "type"}),
			ID:   firstStr(vendor, []string{"protoPayload", "resourceName"}, []string{"resourceName"}),
		}
	case "github":
		return Resource{Type: "repository", Name: str(vendor, "repo"), Owner: str(vendor, "org")}
	case "okta", "okta_system_log":
		if targets, ok := nested(vendor, "target").([]any); ok && len(targets) > 0 {
			if first, ok := targets[0].(map[string]any); ok {
				return Resource{
					Type: str(first, "type"),
					ID:   str(first, "id"),
					Name: firstStr(first, []string{"displayName"}, []string{"alternateId"}),
				}
			}
		}
	}

	// The OCSF resource block, which several profiles already fill.
	return Resource{
		Type: str(ocsf, "resource", "type"),
		ID:   str(ocsf, "resource", "uid"),
		Name: str(ocsf, "resource", "name"),
	}
}

// deriveOutcome reads whether the action succeeded.
//
// Unknown is a real answer and the default. A source that reports nothing
// must not be folded into "success", because a detection counting failed
// attempts would then read a silent source as a clean estate.
func deriveOutcome(payload, vendor, ocsf map[string]any) Outcome {
	// Explicit booleans first: a vendor that says `success: false` has said
	// the most unambiguous thing available.
	for _, m := range []map[string]any{vendor, payload} {
		for _, key := range []string{"success", "is_success", "IsSuccess"} {
			if v, ok := m[key].(bool); ok {
				if v {
					return OutcomeSuccess
				}
				return OutcomeFailure
			}
		}
	}

	// An error code present and non-empty is a failure on every source that
	// emits one.
	for _, m := range []map[string]any{vendor, payload} {
		if firstStr(m, []string{"errorCode"}, []string{"errorMessage"}, []string{"error"}) != "" {
			return OutcomeFailure
		}
	}

	// Documented string enumerations.
	candidates := []string{
		str(vendor, "outcome", "result"), // Okta: SUCCESS / FAILURE / SKIPPED / ALLOW / DENY / CHALLENGE
		str(vendor, "ResultStatus"),      // M365: Succeeded / Success / Failed / Failure / PartiallySucceeded
		str(vendor, "result"),
		str(vendor, "status"),
		str(payload, "outcome"),
		str(ocsf, "status"),
	}
	for _, candidate := range candidates {
		switch strings.ToUpper(strings.TrimSpace(candidate)) {
		case "":
			continue
		case "SUCCESS", "SUCCEEDED", "ALLOW", "ALLOWED", "OK", "COMPLETED":
			return OutcomeSuccess
		case "FAILURE", "FAILED", "DENY", "DENIED", "BLOCK", "BLOCKED", "ERROR":
			return OutcomeFailure
		}
	}

	// Kubernetes and HTTP sources carry the answer as a status code.
	for _, m := range []map[string]any{vendor, ocsf} {
		if code, ok := intField(m, "status_code"); ok && code > 0 {
			return httpOutcome(code)
		}
	}
	if code, ok := nestedInt(vendor, "responseStatus", "code"); ok && code > 0 {
		return httpOutcome(code)
	}
	return OutcomeUnknown
}

func httpOutcome(code int) Outcome {
	if code >= 200 && code < 400 {
		return OutcomeSuccess
	}
	return OutcomeFailure
}

func nestedInt(m map[string]any, path ...string) (int, bool) {
	switch v := nested(m, path...).(type) {
	case int:
		return v, true
	case int64:
		return int(v), true
	case float64:
		return int(v), true
	}
	return 0, false
}

// deriveLocation fills everything about where the action came from that is
// available without a network call. Geography, ASN and reputation are added
// afterwards by the enrichment pass, which needs one.
func deriveLocation(payload, vendor, ocsf map[string]any) Location {
	return Location{
		IP:     str(ocsf, "src_endpoint", "ip"),
		Device: firstStr(ocsf, []string{"device", "name"}, []string{"src_endpoint", "hostname"}),
		Client: ParseUserAgent(userAgentString(payload, vendor, ocsf)),
	}
}

// userAgentString finds the raw agent across the field names these sources
// actually use. Checked against the vendor records rather than guessed:
// CloudTrail spells it `userAgent`, Okta nests it under
// `client.userAgent.rawUserAgent`, Kubernetes uses `userAgent`, Workspace and
// M365 do not send one at all on most events, and the OCSF mapping puts it at
// `http_request.user_agent` where a profile named it.
func userAgentString(payload, vendor, ocsf map[string]any) string {
	if v := str(ocsf, "http_request", "user_agent"); v != "" {
		return v
	}
	for _, m := range []map[string]any{vendor, payload} {
		if v := firstStr(m,
			[]string{"userAgent"},
			[]string{"user_agent"},
			[]string{"client", "userAgent", "rawUserAgent"},
			[]string{"context", "ua"},
			[]string{"http_request", "user_agent"},
		); v != "" {
			return v
		}
	}
	return ""
}
