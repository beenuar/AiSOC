package inbox

import (
	"bufio"
	"errors"
	"strings"
)

// ErrCEFMalformed is returned when a CEF line doesn't have the required
// 7 pipe-delimited prefix fields. The handler turns this into a 400 with
// a small hint so syslog operators can spot the problem.
var ErrCEFMalformed = errors.New("malformed CEF line")

// ParseCEF parses a single CEF line of the form:
//
//	CEF:Version|DeviceVendor|DeviceProduct|DeviceVersion|SignatureID|Name|Severity|Extension
//
// The Extension is a flat sequence of key=value pairs (whitespace-separated)
// where values may contain escaped characters (\=, \\, \n). Output is a
// flat map suitable for handing to the cef-syslog template's Apply().
//
// We deliberately don't try to interpret semantic meaning here — that's
// the template's job. ParseCEF only handles the wire format.
//
// Reference: https://docs.fortinet.com/document/fortianalyzer/7.4.0/cef-reference
func ParseCEF(line string) (map[string]any, error) {
	line = strings.TrimSpace(line)
	if line == "" {
		return nil, ErrCEFMalformed
	}

	// CEF prefix may be preceded by syslog header (date, host, tag).
	// Find "CEF:" anchor and trim to it.
	if idx := strings.Index(line, "CEF:"); idx > 0 {
		line = line[idx:]
	}
	if !strings.HasPrefix(line, "CEF:") {
		return nil, ErrCEFMalformed
	}

	// Split on unescaped pipes.
	parts := splitUnescaped(line, '|')
	if len(parts) < 8 {
		return nil, ErrCEFMalformed
	}

	// CEF allows a literal pipe inside any prefix field as "\|".
	// splitUnescaped keeps that backslash in the segment text — strip it
	// here so templates see the human-readable value.
	unescapePipe := func(s string) string {
		if !strings.Contains(s, `\|`) {
			return s
		}
		return strings.ReplaceAll(s, `\|`, "|")
	}

	out := make(map[string]any, 16)
	out["Version"] = strings.TrimPrefix(parts[0], "CEF:")
	out["DeviceVendor"] = unescapePipe(parts[1])
	out["DeviceProduct"] = unescapePipe(parts[2])
	out["DeviceVersion"] = unescapePipe(parts[3])
	out["SignatureID"] = unescapePipe(parts[4])
	out["Name"] = unescapePipe(parts[5])
	out["Severity"] = unescapePipe(parts[6])

	// Everything after the 7th pipe is the extension. Re-join in case
	// the extension itself contains pipes (escaped or otherwise).
	ext := strings.Join(parts[7:], "|")
	parseCEFExtension(ext, out)

	return out, nil
}

// ParseCEFBatch parses one CEF line per record from a multi-line body.
// Empty lines are skipped; malformed lines are returned alongside the
// successful results so the caller can include them in the response and
// the operator can fix the upstream agent.
func ParseCEFBatch(body string) ([]map[string]any, []string) {
	var (
		records []map[string]any
		errs    []string
	)
	sc := bufio.NewScanner(strings.NewReader(body))
	// CEF lines can be long when extensions carry full URLs or messages.
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		rec, err := ParseCEF(line)
		if err != nil {
			errs = append(errs, line)
			continue
		}
		records = append(records, rec)
	}
	return records, errs
}

// splitUnescaped splits s on sep, treating "\" + sep as an escaped
// literal sep. Necessary because CEF allows escaped pipes inside the
// Name field (rarely, but it's in the spec).
func splitUnescaped(s string, sep byte) []string {
	var (
		out  []string
		cur  strings.Builder
		prev byte
	)
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == sep && prev != '\\' {
			out = append(out, cur.String())
			cur.Reset()
			prev = c
			continue
		}
		cur.WriteByte(c)
		prev = c
	}
	out = append(out, cur.String())
	return out
}

// parseCEFExtension walks a CEF extension string ("key=value key2=value2 ...")
// and populates m. Values may contain escaped equals signs ("\=") and
// escaped newlines ("\n" → literal '\n').
//
// CEF extension grammar is "loose" — values run until the next space-key=
// pattern. We use a small state machine rather than a strings.Split because
// values often contain spaces (URLs, messages) and naive splitting drops
// them.
func parseCEFExtension(ext string, m map[string]any) {
	if ext == "" {
		return
	}
	// Find all key= positions. A key= is a sequence [a-zA-Z0-9._-]+
	// followed by '=' that is not preceded by '\'.
	type span struct {
		keyStart, keyEnd, valStart int
	}
	var spans []span

	i := 0
	for i < len(ext) {
		// Skip leading whitespace.
		for i < len(ext) && (ext[i] == ' ' || ext[i] == '\t') {
			i++
		}
		// Read key.
		ks := i
		for i < len(ext) && (isCEFKeyChar(ext[i])) {
			i++
		}
		ke := i
		if ke == ks || i >= len(ext) || ext[i] != '=' {
			// Not a key=val start. Advance until next space.
			for i < len(ext) && ext[i] != ' ' {
				i++
			}
			continue
		}
		// Skip the '='.
		valStart := i + 1
		spans = append(spans, span{ks, ke, valStart})
		// Move on; we'll bound the value when we find the next key.
		i = valStart
		// Skip until next " key=" boundary (space + identifier + =) so
		// that values containing spaces stay intact.
		for i < len(ext) {
			if ext[i] == ' ' && isCEFKeyStart(ext, i+1) {
				break
			}
			// Honour backslash escapes so "\=" inside values isn't read
			// as a key boundary.
			if ext[i] == '\\' && i+1 < len(ext) {
				i += 2
				continue
			}
			i++
		}
	}

	for idx, s := range spans {
		var endPos int
		if idx+1 < len(spans) {
			// Value runs up to the space before the next key=.
			endPos = spans[idx+1].keyStart
			// Trim the trailing space we matched on.
			for endPos > s.valStart && ext[endPos-1] == ' ' {
				endPos--
			}
		} else {
			endPos = len(ext)
		}
		key := ext[s.keyStart:s.keyEnd]
		val := unescapeCEF(ext[s.valStart:endPos])
		m[key] = val
	}
}

func isCEFKeyChar(c byte) bool {
	return (c >= 'a' && c <= 'z') ||
		(c >= 'A' && c <= 'Z') ||
		(c >= '0' && c <= '9') ||
		c == '.' || c == '_' || c == '-'
}

// isCEFKeyStart returns true if ext[i:] starts with [A-Za-z][A-Za-z0-9._-]*=.
// Used to decide where a value ends.
func isCEFKeyStart(ext string, i int) bool {
	if i >= len(ext) {
		return false
	}
	c := ext[i]
	if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')) {
		return false
	}
	j := i + 1
	for j < len(ext) && isCEFKeyChar(ext[j]) {
		j++
	}
	return j < len(ext) && ext[j] == '='
}

// unescapeCEF decodes the \=, \\, \n escape sequences from a CEF
// extension value. Other escapes pass through unchanged so we don't
// surprise downstream consumers.
func unescapeCEF(s string) string {
	if !strings.Contains(s, "\\") {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		if s[i] != '\\' || i+1 >= len(s) {
			b.WriteByte(s[i])
			continue
		}
		switch s[i+1] {
		case '=', '\\', '|':
			b.WriteByte(s[i+1])
			i++
		case 'n':
			b.WriteByte('\n')
			i++
		case 'r':
			b.WriteByte('\r')
			i++
		case 't':
			b.WriteByte('\t')
			i++
		default:
			b.WriteByte(s[i])
		}
	}
	return b.String()
}
