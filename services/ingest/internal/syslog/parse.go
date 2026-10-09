// Package syslog reads the four wire formats the long tail of security
// appliances speaks, and nothing else.
//
// Firewalls, proxies, load balancers, legacy IDS, printers and a great deal
// of custom gear emit syslog and will never grow a webhook. Before this,
// AiSOC's only syslog path was `POST /v1/inbox/cef`, which requires a
// forwarder in front of it that can already speak HTTP — so the appliance
// still could not reach AiSOC, something in front of it had to.
//
// Four formats, and the distinction between them is not cosmetic:
//
//	RFC 5424  the current standard: a version digit, an RFC 3339 timestamp,
//	          and structured data. Unambiguous to parse.
//	RFC 3164  the one most gear actually emits, and the one that cannot be
//	          parsed reliably: the timestamp carries no year and no zone,
//	          the hostname is optional, and the tag is delimited by a colon
//	          that may also appear in the message.
//	CEF       ArcSight's key/value format, carried *inside* a syslog line.
//	LEEF      QRadar's, likewise, with a delimiter the header may redefine.
//
// A parser that guesses between them is worse than one that refuses: a
// mis-split RFC 3164 line puts half the message in the hostname column, and
// an analyst reading that record sees a host that does not exist. So the
// format is decided by markers the formats themselves define — a version
// digit after the priority, a `CEF:` or `LEEF:` anchor — and anything that
// matches none of them is returned as an unstructured message with its text
// intact, never as a structured record with invented fields.
package syslog

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Format names the wire shape one line turned out to be.
type Format string

const (
	FormatRFC5424 Format = "rfc5424"
	FormatRFC3164 Format = "rfc3164"
	FormatCEF     Format = "cef"
	FormatLEEF    Format = "leef"
	// FormatUnstructured is a line with no recognisable framing. It is a
	// result, not an error: a device emitting bare text is still telling
	// you something, and dropping it loses the only copy.
	FormatUnstructured Format = "unstructured"
)

// ErrEmpty is returned for a line with nothing in it. Distinguished from a
// parse failure because an empty UDP datagram is a keepalive, not a fault,
// and counting it as malformed makes the malformed-line metric useless.
var ErrEmpty = errors.New("empty syslog line")

// MaxLineBytes caps one message. RFC 5424 requires a receiver to accept at
// least 2048 octets and permits more; 64 KiB is well above what any
// appliance emits and well below what a hostile sender could use to exhaust
// a connection's buffer.
const MaxLineBytes = 64 * 1024

// : The eight syslog severities, lowest number = most severe. Mapped onto
// : AiSOC's five tiers by the template's severity_map; kept here as the
// : vendor-native value so nothing downstream has to re-derive it.
var severityNames = [8]string{"emerg", "alert", "crit", "err", "warning", "notice", "info", "debug"}

var facilityNames = [24]string{
	"kern", "user", "mail", "daemon", "auth", "syslog", "lpr", "news",
	"uucp", "cron", "authpriv", "ftp", "ntp", "audit", "alert", "clock",
	"local0", "local1", "local2", "local3", "local4", "local5", "local6", "local7",
}

// Message is one parsed line. Every field is optional except Format and
// Message itself, because every field *is* optional in at least one of the
// four formats.
type Message struct {
	Format   Format
	Priority int
	Facility string
	Severity string
	// SeverityCode is the syslog 0-7 value. Kept beside the name because a
	// template maps on the string and a human reads the number, and
	// re-deriving either from the other at three call sites is how they
	// come to disagree.
	SeverityCode int
	Timestamp    string
	Hostname     string
	AppName      string
	ProcID       string
	MsgID        string
	// StructuredData is RFC 5424's SD-ELEMENT list, flattened to
	// "sdid@enterprise.param" keys so a template can address one.
	StructuredData map[string]string
	Message        string
	// Extension carries the CEF or LEEF key/value pairs and header fields.
	Extension map[string]string
	// Raw is the line exactly as it arrived. Kept because every parse here
	// is a lossy summary and an appliance emitting something this parser
	// misreads is itself the finding.
	Raw string
}

// Fields flattens the message into the shape an inbox template addresses.
func (m *Message) Fields() map[string]any {
	out := make(map[string]any, 12+len(m.Extension)+len(m.StructuredData))
	out["format"] = string(m.Format)
	out["priority"] = m.Priority
	out["facility"] = m.Facility
	out["severity"] = m.Severity
	out["severity_code"] = m.SeverityCode
	out["message"] = m.Message
	out["raw"] = m.Raw
	for key, value := range map[string]string{
		"timestamp": m.Timestamp,
		"hostname":  m.Hostname,
		"app_name":  m.AppName,
		"proc_id":   m.ProcID,
		"msg_id":    m.MsgID,
	} {
		if value != "" {
			out[key] = value
		}
	}
	for key, value := range m.StructuredData {
		out["sd."+key] = value
	}
	// CEF and LEEF keys are merged at the top level because that is where
	// the existing cef-syslog template addresses them (`src`, `suser`,
	// `act`). Nesting them would mean two templates for one format.
	for key, value := range m.Extension {
		out[key] = value
	}
	return out
}

// Parse reads one line. It never returns both a message and an error.
func Parse(line string) (*Message, error) {
	trimmed := strings.TrimRight(strings.TrimSpace(line), "\x00")
	if trimmed == "" {
		return nil, ErrEmpty
	}
	if len(trimmed) > MaxLineBytes {
		return nil, fmt.Errorf("syslog line is %d bytes, over the %d cap", len(trimmed), MaxLineBytes)
	}

	msg := &Message{Raw: line, StructuredData: map[string]string{}, Extension: map[string]string{}}
	rest := trimmed

	// <PRI> is optional on the wire — a device writing straight to a TCP
	// socket often omits it — so its absence is not a parse failure.
	if strings.HasPrefix(rest, "<") {
		if end := strings.Index(rest, ">"); end > 1 && end <= 4 {
			if pri, err := strconv.Atoi(rest[1:end]); err == nil && pri >= 0 && pri < 192 {
				msg.Priority = pri
				msg.SeverityCode = pri % 8
				msg.Severity = severityNames[pri%8]
				msg.Facility = facilityNames[pri/8]
				rest = rest[end+1:]
			}
		}
	} else {
		// No priority at all. `user.notice` is what the RFC names as the
		// default, and recording it explicitly beats leaving a zero that
		// reads as `kern.emerg` — the most severe value there is.
		msg.Priority = 13
		msg.SeverityCode = 5
		msg.Severity = severityNames[5]
		msg.Facility = facilityNames[1]
	}

	switch {
	case isRFC5424(rest):
		parseRFC5424(msg, rest)
	case anchorAt(rest, "LEEF:") >= 0:
		// Checked before RFC 3164 because a LEEF line usually carries a
		// 3164 header *and* a LEEF payload, and the payload is the part
		// worth having. The split is at the anchor rather than after the
		// header parse: the 3164 tag reader would otherwise take `LEEF`
		// for an application name and eat the anchor with it.
		at := anchorAt(rest, "LEEF:")
		parseRFC3164Header(msg, rest[:at])
		msg.Message = rest[at:]
		parseLEEF(msg, rest[at:])
	case anchorAt(rest, "CEF:") >= 0:
		at := anchorAt(rest, "CEF:")
		parseRFC3164Header(msg, rest[:at])
		msg.Message = rest[at:]
		parseCEF(msg, rest[at:])
	case looksLikeRFC3164(rest):
		parseRFC3164Header(msg, rest)
		msg.Format = FormatRFC3164
	default:
		msg.Format = FormatUnstructured
		msg.Message = rest
	}

	return msg, nil
}

// anchorAt finds a CEF or LEEF anchor, or -1. `LEEF:` is checked before
// `CEF:` by the caller because the two substrings do not overlap but a
// vendor name containing "CEF:" inside a message would; nothing here tries
// to be clever about that, because the anchor is the only marker either
// format defines and inventing a second one would change which lines parse.
func anchorAt(rest, anchor string) int {
	return strings.Index(rest, anchor)
}

// isRFC5424 looks for the version digit the format requires immediately
// after the priority. `1 ` is the only version ever assigned, and matching
// it is what keeps a 3164 line whose message happens to start with a digit
// from being read as 5424.
func isRFC5424(rest string) bool {
	return strings.HasPrefix(rest, "1 ")
}

func parseRFC5424(msg *Message, rest string) {
	msg.Format = FormatRFC5424
	// VERSION SP TIMESTAMP SP HOSTNAME SP APP-NAME SP PROCID SP MSGID SP SD [SP MSG]
	parts := strings.SplitN(rest, " ", 7)
	if len(parts) < 7 {
		// A header this short is still readable; what is missing is the
		// structured data and message, not the identity fields.
		parts = append(parts, make([]string, 7-len(parts))...)
	}
	nilable := func(v string) string {
		if v == "-" {
			return ""
		}
		return v
	}
	msg.Timestamp = normaliseTimestamp(nilable(parts[1]))
	msg.Hostname = nilable(parts[2])
	msg.AppName = nilable(parts[3])
	msg.ProcID = nilable(parts[4])
	msg.MsgID = nilable(parts[5])

	tail := parts[6]
	sd, message := splitStructuredData(tail)
	for key, value := range sd {
		msg.StructuredData[key] = value
	}
	message = strings.TrimPrefix(message, "\ufeff") // RFC 5424's optional BOM
	msg.Message = message

	// A 5424 line can still carry CEF or LEEF in its message.
	switch {
	case strings.Contains(message, "LEEF:"):
		parseLEEF(msg, message)
	case strings.Contains(message, "CEF:"):
		parseCEF(msg, message)
	}
}

// splitStructuredData separates the SD-ELEMENT list from the free-text
// message. Bracket counting rather than a regular expression, because a
// parameter value may contain `]` escaped as `\]` and a regex that ignores
// that truncates the structured data at the first one.
func splitStructuredData(tail string) (map[string]string, string) {
	sd := map[string]string{}
	if tail == "" {
		return sd, ""
	}
	if strings.HasPrefix(tail, "-") {
		return sd, strings.TrimSpace(tail[1:])
	}
	if !strings.HasPrefix(tail, "[") {
		return sd, tail
	}

	// Brackets inside a quoted PARAM-VALUE are data, not structure: rsyslog's
	// own `origin` element ships an `x-info` URL and operators routinely put
	// a bracketed note in one. Counting those as nesting leaves the scan at
	// depth 1 forever, and the whole SD block then falls through into the
	// message — silently, and the message still looks plausible.
	depth := 0
	escaped := false
	inQuotes := false
	end := -1
	for i := 0; i < len(tail) && end < 0; i++ {
		switch {
		case escaped:
			escaped = false
		case tail[i] == '\\':
			escaped = true
		case tail[i] == '"':
			inQuotes = !inQuotes
		case inQuotes:
			// Data.
		case tail[i] == '[':
			depth++
		case tail[i] == ']':
			depth--
			// Several SD-ELEMENTs may run together with no separator, so
			// the list only ends when the next byte is not another opening
			// bracket.
			if depth == 0 && (i+1 >= len(tail) || tail[i+1] != '[') {
				end = i
			}
		}
	}
	if end < 0 {
		// Unterminated: keep the whole thing as the message rather than
		// inventing a boundary.
		return sd, tail
	}
	for _, element := range splitElements(tail[:end+1]) {
		id, params := parseSDElement(element)
		for key, value := range params {
			sd[id+"."+key] = value
		}
	}
	return sd, strings.TrimSpace(tail[end+1:])
}

func splitElements(block string) []string {
	// Quote-aware for the same reason the scan above is: a bracket inside a
	// PARAM-VALUE is data. Without it this returns nothing for an element
	// carrying a bracketed value, and the caller then reports a line with
	// no structured data at all rather than failing.
	var out []string
	depth := 0
	escaped := false
	inQuotes := false
	start := 0
	for i := 0; i < len(block); i++ {
		switch {
		case escaped:
			escaped = false
		case block[i] == '\\':
			escaped = true
		case block[i] == '"':
			inQuotes = !inQuotes
		case inQuotes:
			// Data.
		case block[i] == '[':
			if depth == 0 {
				start = i
			}
			depth++
		case block[i] == ']':
			depth--
			if depth == 0 {
				out = append(out, block[start:i+1])
			}
		}
	}
	return out
}

func parseSDElement(element string) (string, map[string]string) {
	element = strings.TrimSuffix(strings.TrimPrefix(element, "["), "]")
	params := map[string]string{}
	fields := splitQuoted(element)
	if len(fields) == 0 {
		return "", params
	}
	id := fields[0]
	for _, field := range fields[1:] {
		key, value, found := strings.Cut(field, "=")
		if !found {
			continue
		}
		value = strings.TrimSuffix(strings.TrimPrefix(value, `"`), `"`)
		params[key] = unescapeSD(value)
	}
	return id, params
}

// splitQuoted splits on spaces that are not inside a quoted value.
func splitQuoted(s string) []string {
	var out []string
	var current strings.Builder
	inQuotes := false
	escaped := false
	for _, r := range s {
		switch {
		case escaped:
			current.WriteRune(r)
			escaped = false
		case r == '\\':
			current.WriteRune(r)
			escaped = true
		case r == '"':
			inQuotes = !inQuotes
			current.WriteRune(r)
		case r == ' ' && !inQuotes:
			if current.Len() > 0 {
				out = append(out, current.String())
				current.Reset()
			}
		default:
			current.WriteRune(r)
		}
	}
	if current.Len() > 0 {
		out = append(out, current.String())
	}
	return out
}

func unescapeSD(value string) string {
	replacer := strings.NewReplacer(`\"`, `"`, `\\`, `\`, `\]`, `]`)
	return replacer.Replace(value)
}

// looksLikeRFC3164 checks for the three-letter month the format opens with.
// Deliberately narrow: the alternative is "anything with a colon in it",
// which splits ordinary prose into a hostname and a message.
func looksLikeRFC3164(rest string) bool {
	if len(rest) < 15 {
		return false
	}
	months := "JanFebMarAprMayJunJulAugSepOctNovDec"
	return strings.Contains(months, rest[:3]) && rest[3] == ' '
}

func parseRFC3164Header(msg *Message, rest string) {
	if msg.Format == "" {
		msg.Format = FormatRFC3164
	}
	msg.Message = rest

	rest = strings.TrimSpace(rest)
	if !looksLikeRFC3164(rest) {
		return
	}
	// "MMM dd hh:mm:ss " is fixed-width at 16 octets including the trailing
	// space, which is the one thing about 3164 that *is* unambiguous.
	if len(rest) < 16 {
		return
	}
	msg.Timestamp = normaliseTimestamp(rest[:15])
	remainder := strings.TrimLeft(rest[15:], " ")

	host, tail, found := strings.Cut(remainder, " ")
	if !found {
		// Everything after the timestamp and nothing else. RFC 3164 puts
		// the hostname there, so reading it as the message would drop the
		// one identity field the format carries — which is the field a
		// responder needs most.
		msg.Hostname = remainder
		msg.Message = ""
		return
	}
	msg.Hostname = host
	msg.Message = tail

	// TAG[PID]: — the colon is only a delimiter when it arrives within the
	// 32 octets the RFC allows a tag, and only when what precedes it has no
	// space in it. Without both conditions, "Error: connection refused"
	// becomes an app name.
	if idx := strings.Index(tail, ":"); idx > 0 && idx <= 32 && !strings.Contains(tail[:idx], " ") {
		tag := tail[:idx]
		if open := strings.Index(tag, "["); open > 0 && strings.HasSuffix(tag, "]") {
			msg.AppName = tag[:open]
			msg.ProcID = tag[open+1 : len(tag)-1]
		} else {
			msg.AppName = tag
		}
		msg.Message = strings.TrimLeft(tail[idx+1:], " ")
	}
}

// normaliseTimestamp returns RFC 3339 where the input carries enough
// information, and the input unchanged where it does not.
//
// RFC 3164's timestamp has no year and no zone. Stamping the current year
// on it is the conventional move and it is wrong twice a year — at a new
// year boundary, and for any device whose clock is ahead — so the year is
// filled from the receiver's clock and the *original* stays in `raw`,
// which is the only honest option available.
func normaliseTimestamp(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339} {
		if t, err := time.Parse(layout, value); err == nil {
			return t.UTC().Format(time.RFC3339Nano)
		}
	}
	for _, layout := range []string{"Jan _2 15:04:05", "Jan 2 15:04:05"} {
		if t, err := time.Parse(layout, value); err == nil {
			now := time.Now().UTC()
			stamped := time.Date(now.Year(), t.Month(), t.Day(), t.Hour(), t.Minute(), t.Second(), 0, time.UTC)
			// A December log read in January is last year's, not next
			// year's. One day of slack absorbs clock skew without
			// re-dating an ordinary same-day message.
			if stamped.Sub(now) > 24*time.Hour {
				stamped = stamped.AddDate(-1, 0, 0)
			}
			return stamped.Format(time.RFC3339Nano)
		}
	}
	return value
}
