package inbox

import (
	"testing"
)

// TestParseCEF_Standard checks the common CEF wire format produced by
// security appliances. The example is taken from the public ArcSight
// reference and exercises both the prefix and the key=value extension.
func TestParseCEF_Standard(t *testing.T) {
	line := `CEF:0|Security|threatmanager|1.0|100|worm successfully stopped|10|src=10.0.0.1 dst=2.1.2.2 spt=1232`
	got, err := ParseCEF(line)
	if err != nil {
		t.Fatalf("ParseCEF unexpected error: %v", err)
	}
	checks := map[string]string{
		"Version":       "0",
		"DeviceVendor":  "Security",
		"DeviceProduct": "threatmanager",
		"DeviceVersion": "1.0",
		"SignatureID":   "100",
		"Name":          "worm successfully stopped",
		"Severity":      "10",
		"src":           "10.0.0.1",
		"dst":           "2.1.2.2",
		"spt":           "1232",
	}
	for k, want := range checks {
		if v, ok := got[k]; !ok || v != want {
			t.Errorf("ParseCEF[%q] = %v, want %q", k, v, want)
		}
	}
}

// TestParseCEF_Escapes verifies the documented escape rules in the
// extension: \\, \=, and \n. We need this to round-trip vendor
// payloads that include URLs, equals signs in messages, etc.
func TestParseCEF_Escapes(t *testing.T) {
	line := `CEF:0|Vendor|Prod|1.0|sig|name|3|msg=foo\=bar path=C:\\Users\\a act=allow`
	got, err := ParseCEF(line)
	if err != nil {
		t.Fatalf("ParseCEF unexpected error: %v", err)
	}
	if got["msg"] != "foo=bar" {
		t.Errorf("escape \\= not unescaped: msg=%q", got["msg"])
	}
	if got["path"] != `C:\Users\a` {
		t.Errorf("escape \\\\ not unescaped: path=%q", got["path"])
	}
	if got["act"] != "allow" {
		t.Errorf("trailing key not parsed: act=%q", got["act"])
	}
}

// TestParseCEF_PipeInName covers the case where the human-readable
// Name field contains a pipe escaped as \|. Without unescape the prefix
// would be miscounted.
func TestParseCEF_PipeInName(t *testing.T) {
	line := `CEF:0|Vendor|Prod|1.0|sig|alert\|critical|7|src=1.2.3.4`
	got, err := ParseCEF(line)
	if err != nil {
		t.Fatalf("ParseCEF unexpected error: %v", err)
	}
	if got["Name"] != "alert|critical" {
		t.Errorf("pipe-in-Name not unescaped: %q", got["Name"])
	}
}

// TestParseCEF_Malformed makes sure we reject obviously bad input
// rather than silently producing junk that downstream RAG would index.
func TestParseCEF_Malformed(t *testing.T) {
	cases := []string{
		"",
		"not cef at all",
		"CEF:0|too|few|fields",
	}
	for _, line := range cases {
		if _, err := ParseCEF(line); err == nil {
			t.Errorf("ParseCEF(%q) should have errored", line)
		}
	}
}

// TestParseCEFBatch covers the multi-line case where a syslog forwarder
// sends an HTTP body containing several CEF events separated by
// newlines. Blank and malformed lines should be skipped (returned as
// badLines for observability), not abort the whole batch — operators
// expect the syslog relay to keep flowing even if one record is junk.
func TestParseCEFBatch(t *testing.T) {
	body := `CEF:0|V|P|1|S|n|3|src=1.1.1.1
not a cef line
CEF:0|V|P|1|S|n|5|src=2.2.2.2
`
	got, bad := ParseCEFBatch(body)
	if len(got) != 2 {
		t.Fatalf("expected 2 valid events, got %d (bad=%v)", len(got), bad)
	}
	if got[0]["src"] != "1.1.1.1" || got[1]["src"] != "2.2.2.2" {
		t.Errorf("ParseCEFBatch wrong events: %+v", got)
	}
	if len(bad) != 1 || bad[0] != "not a cef line" {
		t.Errorf("expected 1 malformed line captured, got %v", bad)
	}
}
