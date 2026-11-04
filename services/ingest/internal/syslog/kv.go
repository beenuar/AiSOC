package syslog

import (
	"strconv"
	"strings"
)

// CEF and LEEF are two vendors' answers to the same problem — carrying
// key/value pairs inside a syslog message — and they differ in exactly the
// way that makes one parser for both wrong: CEF separates pairs with
// spaces and escapes `=` inside values, while LEEF separates them with a
// delimiter the header may *redefine*, most often a tab.
//
// `inbox/cef.go` already parses CEF for the HTTP route. This is a second
// implementation only in the sense that it reads the same format; it is
// here because the listener has no HTTP request to hang the inbox handler
// off, and the two are pinned against each other by a test rather than
// left to drift.

const cefHeaderFields = 7

// parseCEF fills msg.Extension from a CEF payload and sets the format.
//
// CEF:Version|DeviceVendor|DeviceProduct|DeviceVersion|SignatureID|Name|Severity|Extension
//
// A pipe inside a header field is escaped as `\|`, which a plain Split
// would cut on — so the split honours the escape.
func parseCEF(msg *Message, payload string) {
	idx := strings.Index(payload, "CEF:")
	if idx < 0 {
		return
	}
	body := payload[idx+len("CEF:"):]
	fields := splitEscaped(body, '|', cefHeaderFields)
	if len(fields) < cefHeaderFields {
		// Not a CEF line after all. Left as whatever the syslog header
		// parse made of it rather than reported as CEF with empty fields,
		// because a record labelled CEF with no vendor reads as a product
		// bug rather than as a malformed line.
		return
	}
	msg.Format = FormatCEF
	for key, value := range map[string]string{
		"CEFVersion":    fields[0],
		"DeviceVendor":  unescapeCEF(fields[1]),
		"DeviceProduct": unescapeCEF(fields[2]),
		"DeviceVersion": unescapeCEF(fields[3]),
		"SignatureID":   unescapeCEF(fields[4]),
		"Name":          unescapeCEF(fields[5]),
		"Severity":      unescapeCEF(fields[6]),
	} {
		msg.Extension[key] = value
	}
	if len(fields) > cefHeaderFields {
		for key, value := range parseCEFExtension(fields[cefHeaderFields]) {
			msg.Extension[key] = value
		}
	}
	if name := msg.Extension["Name"]; name != "" && msg.Message == payload {
		msg.Message = name
	}
	if text := msg.Extension["msg"]; text != "" {
		msg.Message = text
	}
}

// parseCEFExtension reads the `k=v k=v` tail.
//
// The hard part is that values may contain spaces: `msg=connection refused
// src=10.0.0.1`. A split on spaces loses the message. So the scan finds the
// *next* unescaped `=`, walks back to the space before its key, and ends
// the previous value there — which is the only way to read the format
// without a schema.
func parseCEFExtension(ext string) map[string]string {
	out := map[string]string{}
	if strings.TrimSpace(ext) == "" {
		return out
	}

	type span struct {
		key   string
		start int
	}
	var spans []span
	for i := 0; i < len(ext); i++ {
		if ext[i] != '=' || (i > 0 && ext[i-1] == '\\') {
			continue
		}
		keyStart := strings.LastIndexByte(ext[:i], ' ') + 1
		key := ext[keyStart:i]
		if key == "" {
			continue
		}
		spans = append(spans, span{key: key, start: i + 1})
	}
	for i, s := range spans {
		end := len(ext)
		if i+1 < len(spans) {
			// Back up over the next key and the space before it.
			end = spans[i+1].start - len(spans[i+1].key) - 2
			if end < s.start {
				end = s.start
			}
		}
		out[s.key] = unescapeCEF(strings.TrimSpace(ext[s.start:end]))
	}
	return out
}

// LEEF 1.0 carries five header fields before the attributes; 2.0 inserts a
// delimiter field between the last of them and the attributes.
const leefHeaderFields = 5

// parseLEEF fills msg.Extension from a LEEF payload.
//
// LEEF:1.0|Vendor|Product|Version|EventID|key=value<TAB>key=value
// LEEF:2.0|Vendor|Product|Version|EventID|<delimiter>|key=value...
//
// The 2.0 delimiter field is the part that catches people: it may be a
// literal character, or `xHH` / `x09` naming one by hex code. Assuming tab
// means every pair in a caret-delimited line lands in one key.
//
// `|` separates header fields but stays legal *inside* an attribute value,
// which is the other half of the same trap: cutting more pipes than the
// header has truncates the value at its first pipe and drops every attribute
// after it. `cmd=powershell -enc AAA | iex` is the case that matters — the
// half a detection reads is the half past the pipe. So the header split cuts
// exactly the header's pipes, and 2.0's extra field is taken one cut at a
// time from the remainder.
func parseLEEF(msg *Message, payload string) {
	idx := strings.Index(payload, "LEEF:")
	if idx < 0 {
		return
	}
	body := payload[idx+len("LEEF:"):]
	fields := splitEscaped(body, '|', leefHeaderFields)
	if len(fields) < leefHeaderFields {
		return
	}
	msg.Format = FormatLEEF
	version := fields[0]
	msg.Extension["LEEFVersion"] = version
	msg.Extension["DeviceVendor"] = fields[1]
	msg.Extension["DeviceProduct"] = fields[2]
	msg.Extension["DeviceVersion"] = fields[3]
	msg.Extension["EventID"] = fields[4]

	delimiter := "\t"
	attrs := ""
	if len(fields) > leefHeaderFields {
		attrs = fields[leefHeaderFields]
	}
	if strings.HasPrefix(version, "2") {
		parts := splitEscaped(attrs, '|', 1)
		switch {
		case len(parts) > 1:
			delimiter = resolveLEEFDelimiter(parts[0])
			attrs = parts[1]
		case !strings.Contains(attrs, "="):
			// A 2.0 line declaring a delimiter and carrying no attributes.
			// A delimiter never contains `=`, so a field that does is a
			// vendor sending 1.0-shaped attributes under a 2.0 banner, and
			// reading those is better than discarding them.
			delimiter = resolveLEEFDelimiter(attrs)
			attrs = ""
		}
	}

	for _, pair := range strings.Split(attrs, delimiter) {
		key, value, found := strings.Cut(pair, "=")
		if !found {
			continue
		}
		key = strings.TrimSpace(key)
		if key != "" {
			msg.Extension[key] = strings.TrimSpace(value)
		}
	}
	if text := msg.Extension["msg"]; text != "" {
		msg.Message = text
	}
}

func resolveLEEFDelimiter(field string) string {
	field = strings.TrimSpace(field)
	if field == "" {
		return "\t"
	}
	if (strings.HasPrefix(field, "x") || strings.HasPrefix(field, "0x")) && len(field) >= 3 {
		hex := strings.TrimPrefix(strings.TrimPrefix(field, "0x"), "x")
		if code, err := strconv.ParseUint(hex, 16, 8); err == nil {
			return string(rune(code))
		}
	}
	return field[:1]
}

// splitEscaped splits on sep, honouring a backslash escape, cutting at most
// `limit` separators — so it returns at most `limit`+1 fields, with
// everything past the last cut left intact in the final one. Callers pass the
// number of *separators* their format has, not the number of fields they
// want; passing the field count cuts one pipe too many and truncates the
// remainder at its first separator.
func splitEscaped(s string, sep byte, limit int) []string {
	var out []string
	var current strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+1 < len(s) && s[i+1] == sep {
			current.WriteByte(sep)
			i++
			continue
		}
		if s[i] == sep && len(out) < limit {
			out = append(out, current.String())
			current.Reset()
			continue
		}
		current.WriteByte(s[i])
	}
	out = append(out, current.String())
	return out
}

func unescapeCEF(value string) string {
	return strings.NewReplacer(`\=`, `=`, `\|`, `|`, `\\`, `\`, `\n`, "\n", `\r`, "\r").Replace(value)
}
