package syslog

import (
	"strings"
	"testing"
)

// A syslog listener reads from the network, so every prefix of a well-formed
// line is an input someone can send. These walk the truncation boundary one
// byte at a time because the header parsers index fixed field positions, and
// an index past the end is a panic that takes the listener down rather than a
// parse failure that drops one line.

func TestHeaderParsersSurviveEveryTruncation(t *testing.T) {
	lines := []string{
		`LEEF:2.0|Vendor|Product|1.0|4711|^|src=10.0.0.1^dst=10.0.0.2^sev=8`,
		"LEEF:1.0|Lancope|StealthWatch|1.0|41|src=192.0.2.1\tsev=5",
		"LEEF:2.0|Vendor|Product|1.0|4711|x09|src=10.0.0.1\tsev=2",
		`CEF:0|Security|threatmanager|1.0|100|worm stopped|10|src=10.0.0.1 msg=blocked`,
	}
	for _, line := range lines {
		for cut := 0; cut <= len(line); cut++ {
			// A panic here fails the test naming the offending prefix.
			if _, err := Parse(line[:cut]); err != nil {
				continue
			}
		}
	}
}

func TestLEEFHeaderWithMissingTrailingFields(t *testing.T) {
	// Each of these stops at a different field boundary, which is where an
	// off-by-one in the header indexing would land.
	for _, line := range []string{
		"LEEF:2.0",
		"LEEF:2.0|",
		"LEEF:2.0|Vendor",
		"LEEF:2.0|Vendor|Product",
		"LEEF:2.0|Vendor|Product|1.0",
		"LEEF:2.0|Vendor|Product|1.0|4711",
		"LEEF:2.0|Vendor|Product|1.0|4711|",
		"LEEF:2.0|Vendor|Product|1.0|4711|^",
		"LEEF:2.0|Vendor|Product|1.0|4711|^|",
		"LEEF:1.0|Vendor|Product|1.0|4711",
		"LEEF:1.0|Vendor|Product|1.0|4711|",
		"LEEF:|||||",
		"LEEF:",
	} {
		if _, err := Parse(line); err != nil {
			t.Fatalf("Parse(%q): %v", line, err)
		}
	}
}

// A LEEF line declares its own attribute delimiter, so `|` stays legal inside
// an attribute value. Splitting the header on more pipes than the format has
// fields silently drops whatever follows the first one in a value.
func TestLEEF2KeepsPipesInsideAttributeValues(t *testing.T) {
	msg, err := Parse(`LEEF:2.0|Vendor|Product|1.0|4711|^|src=10.0.0.1^cmd=a|b|c^sev=8`)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if got := msg.Extension["cmd"]; got != "a|b|c" {
		t.Fatalf("cmd = %q, want %q", got, "a|b|c")
	}
	if got := msg.Extension["sev"]; got != "8" {
		t.Fatalf("sev = %q, want %q", got, "8")
	}
}

func TestLEEF1KeepsPipesInsideAttributeValues(t *testing.T) {
	msg, err := Parse("LEEF:1.0|Vendor|Product|1.0|4711|src=10.0.0.1\tcmd=a|b|c\tsev=5")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if got := msg.Extension["cmd"]; got != "a|b|c" {
		t.Fatalf("cmd = %q, want %q", got, "a|b|c")
	}
	if got := msg.Extension["sev"]; got != "5" {
		t.Fatalf("sev = %q, want %q", got, "5")
	}
}

// The 2.0 delimiter field is a header field, not an attribute. Reading it as
// the attribute string is how a line carrying a delimiter and no attributes
// ends up with the delimiter itself offered as a pair.
func TestLEEF2WithNoAttributesReadsNoAttributes(t *testing.T) {
	msg, err := Parse("LEEF:2.0|Vendor|Product|1.0|4711|^")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if msg.Format != FormatLEEF {
		t.Fatalf("format = %q, want leef", msg.Format)
	}
	if got := msg.Extension["EventID"]; got != "4711" {
		t.Fatalf("EventID = %q, want 4711", got)
	}
	for key := range msg.Extension {
		if strings.HasPrefix(key, "^") {
			t.Fatalf("delimiter leaked into the attributes as %q", key)
		}
	}
}
