package syslog

import (
	"strings"
	"testing"
	"time"
)

// Every line below is a wire sample from the format's own specification or
// from a vendor's published example, not one this parser produced. A sample
// built from the parser's output only proves the parser agrees with itself,
// and the defect this family has is mis-splitting a line nobody wrote down.

func TestRFC5424IsParsedIntoItsNamedFields(t *testing.T) {
	// RFC 5424 §6.5, Example 2, with the structured data from Example 3.
	line := "<165>1 2026-10-08T22:14:15.003Z mymachine.example.com evntslog 1234 ID47 " +
		`[exampleSDID@32473 iut="3" eventSource="Application" eventID="1011"] ` + "\ufeff" + "An application event log entry..."

	msg, err := Parse(line)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if msg.Format != FormatRFC5424 {
		t.Fatalf("format = %q, want rfc5424", msg.Format)
	}
	if msg.Hostname != "mymachine.example.com" || msg.AppName != "evntslog" || msg.ProcID != "1234" || msg.MsgID != "ID47" {
		t.Errorf("header fields wrong: host=%q app=%q proc=%q msgid=%q", msg.Hostname, msg.AppName, msg.ProcID, msg.MsgID)
	}
	if msg.Severity != "notice" || msg.Facility != "local4" {
		t.Errorf("priority 165 should be local4.notice, got %s.%s", msg.Facility, msg.Severity)
	}
	if got := msg.StructuredData["exampleSDID@32473.eventID"]; got != "1011" {
		t.Errorf("structured data eventID = %q, want 1011", got)
	}
	if !strings.HasPrefix(msg.Message, "An application event log entry") {
		t.Errorf("message = %q; the BOM should be stripped and nothing else", msg.Message)
	}
}

func TestAStructuredDataValueMayContainTheClosingBracket(t *testing.T) {
	// The reason the split counts brackets instead of using a regex: a
	// parameter value may contain an escaped `]`, and a reader that stops at
	// the first one truncates the structured data and puts the remainder in
	// the message.
	line := `<34>1 2026-10-08T22:14:15Z host app - - [origin software="rsyslogd" x-info="see [docs\]"] the message`

	msg, err := Parse(line)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if got := msg.StructuredData["origin.x-info"]; got != "see [docs]" {
		t.Errorf("x-info = %q, want %q", got, "see [docs]")
	}
	if msg.Message != "the message" {
		t.Errorf("message = %q, want %q", msg.Message, "the message")
	}
}

func TestRFC3164IsParsedWithoutSwallowingTheMessage(t *testing.T) {
	// RFC 3164 §5.4, Example 1.
	line := `<34>Oct 11 22:14:15 mymachine su: 'su root' failed for lonvick on /dev/pts/8`

	msg, err := Parse(line)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if msg.Format != FormatRFC3164 {
		t.Fatalf("format = %q, want rfc3164", msg.Format)
	}
	if msg.Hostname != "mymachine" || msg.AppName != "su" {
		t.Errorf("host = %q, app = %q", msg.Hostname, msg.AppName)
	}
	if msg.Message != "'su root' failed for lonvick on /dev/pts/8" {
		t.Errorf("message = %q", msg.Message)
	}
	if msg.Severity != "crit" {
		t.Errorf("priority 34 should be auth.crit, got %s.%s", msg.Facility, msg.Severity)
	}
}

func TestATagWithAPidIsSplit(t *testing.T) {
	msg, err := Parse(`<13>Oct 11 22:14:15 web01 sshd[4242]: Accepted publickey for root from 203.0.113.9`)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if msg.AppName != "sshd" || msg.ProcID != "4242" {
		t.Errorf("app = %q, pid = %q", msg.AppName, msg.ProcID)
	}
}

func TestAColonInProseIsNotATag(t *testing.T) {
	// The defect this guards: "Error: connection refused" read as an app
	// name called "Error". An analyst then sees a process that does not
	// exist, which is worse than seeing no process at all.
	msg, err := Parse(`<13>Oct 11 22:14:15 web01 the database said: connection refused`)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if msg.AppName != "" {
		t.Errorf("app name = %q; prose containing a colon is not a tag", msg.AppName)
	}
	if msg.Message != "the database said: connection refused" {
		t.Errorf("message = %q", msg.Message)
	}
}

func TestAnUnrecognisableLineKeepsItsText(t *testing.T) {
	// A device emitting bare text is still telling you something. Returning
	// an error here would drop the only copy.
	msg, err := Parse("a bare line from some appliance")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if msg.Format != FormatUnstructured {
		t.Errorf("format = %q, want unstructured", msg.Format)
	}
	if msg.Message != "a bare line from some appliance" {
		t.Errorf("message = %q", msg.Message)
	}
}

func TestAMissingPriorityDefaultsToNoticeRatherThanEmergency(t *testing.T) {
	// A zero priority decodes as kern.emerg — the most severe value there
	// is. A device that simply omitted the field would page someone.
	msg, err := Parse("Oct 11 22:14:15 web01 sshd: hello")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if msg.Severity != "notice" {
		t.Errorf("severity = %q, want notice (RFC 3164's stated default), not %q", msg.Severity, "emerg")
	}
}

func TestAnEmptyLineIsNotAParseFailure(t *testing.T) {
	// A zero-length UDP datagram is a keepalive. Counting it as malformed
	// makes the malformed-line metric useless.
	if _, err := Parse("   "); err != ErrEmpty {
		t.Errorf("err = %v, want ErrEmpty", err)
	}
}

func TestAnOversizedLineIsRefusedRatherThanTruncated(t *testing.T) {
	if _, err := Parse(strings.Repeat("x", MaxLineBytes+1)); err == nil {
		t.Error("an oversized line should be refused, not silently truncated")
	}
}

func TestCEFInsideASyslogLineIsParsed(t *testing.T) {
	// The header example from the CEF implementation standard, with a
	// syslog header in front of it the way a real forwarder sends it.
	line := `<134>Oct 11 22:14:15 fw01 CEF:0|Security|threatmanager|1.0|100|worm successfully stopped|10|src=10.0.0.1 dst=2.1.2.2 spt=1232`

	msg, err := Parse(line)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if msg.Format != FormatCEF {
		t.Fatalf("format = %q, want cef", msg.Format)
	}
	for key, want := range map[string]string{
		"DeviceVendor":  "Security",
		"DeviceProduct": "threatmanager",
		"SignatureID":   "100",
		"Name":          "worm successfully stopped",
		"Severity":      "10",
		"src":           "10.0.0.1",
		"dst":           "2.1.2.2",
		"spt":           "1232",
	} {
		if got := msg.Extension[key]; got != want {
			t.Errorf("%s = %q, want %q", key, got, want)
		}
	}
	if msg.Hostname != "fw01" {
		t.Errorf("the syslog header in front of the CEF payload should still parse; hostname = %q", msg.Hostname)
	}
}

func TestACEFValueMayContainSpaces(t *testing.T) {
	// This is the whole difficulty of the extension format: `msg=connection
	// refused src=10.0.0.1` has to yield two pairs, not four tokens. A
	// split on spaces loses the message, which is the field an analyst
	// reads first.
	line := `CEF:0|v|p|1.0|1|Name|5|msg=connection refused by policy src=10.0.0.1 suser=alice`

	msg, err := Parse(line)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if got := msg.Extension["msg"]; got != "connection refused by policy" {
		t.Errorf("msg = %q, want %q", got, "connection refused by policy")
	}
	if msg.Extension["src"] != "10.0.0.1" || msg.Extension["suser"] != "alice" {
		t.Errorf("later pairs lost: src=%q suser=%q", msg.Extension["src"], msg.Extension["suser"])
	}
}

func TestAnEscapedPipeStaysInsideItsCEFHeaderField(t *testing.T) {
	msg, err := Parse(`CEF:0|Vendor\|Inc|product|1.0|42|a name|3|src=10.0.0.1`)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if got := msg.Extension["DeviceVendor"]; got != "Vendor|Inc" {
		t.Errorf("DeviceVendor = %q, want %q", got, "Vendor|Inc")
	}
	if msg.Extension["SignatureID"] != "42" {
		t.Errorf("an escaped pipe shifted every later field: SignatureID = %q", msg.Extension["SignatureID"])
	}
}

func TestLEEF1UsesTabsByDefault(t *testing.T) {
	line := "<134>Oct 11 22:14:15 qr01 LEEF:1.0|Lancope|StealthWatch|1.0|41|src=192.0.2.1\tdst=172.16.0.1\tsev=5"

	msg, err := Parse(line)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if msg.Format != FormatLEEF {
		t.Fatalf("format = %q, want leef", msg.Format)
	}
	if msg.Extension["src"] != "192.0.2.1" || msg.Extension["sev"] != "5" || msg.Extension["EventID"] != "41" {
		t.Errorf("attributes wrong: %#v", msg.Extension)
	}
}

func TestLEEF2HonoursTheDelimiterTheHeaderDeclares(t *testing.T) {
	// The reason LEEF needs its own parser rather than a tab split: a
	// caret-delimited line read as tab-delimited puts every attribute into
	// one key, and the record still looks structurally fine.
	line := `LEEF:2.0|Vendor|Product|1.0|4711|^|src=10.0.0.1^dst=10.0.0.2^sev=8`

	msg, err := Parse(line)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if msg.Extension["src"] != "10.0.0.1" || msg.Extension["dst"] != "10.0.0.2" || msg.Extension["sev"] != "8" {
		t.Errorf("the declared ^ delimiter was ignored: %#v", msg.Extension)
	}
}

func TestLEEF2AcceptsAHexDelimiter(t *testing.T) {
	line := "LEEF:2.0|Vendor|Product|1.0|4711|x09|src=10.0.0.1\tsev=2"

	msg, err := Parse(line)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if msg.Extension["src"] != "10.0.0.1" || msg.Extension["sev"] != "2" {
		t.Errorf("x09 should resolve to a tab: %#v", msg.Extension)
	}
}

func TestA3164TimestampIsGivenAYearWithoutJumpingForward(t *testing.T) {
	// RFC 3164 carries no year. Stamping the current one is the
	// conventional move and it is wrong at a year boundary: a December log
	// read in January is last year's. One day of slack absorbs clock skew
	// without re-dating an ordinary same-day message.
	future := time.Now().UTC().AddDate(0, 0, 3)
	line := "<13>" + future.Format("Jan _2 15:04:05") + " host app: hello"

	msg, err := Parse(line)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	parsed, err := time.Parse(time.RFC3339Nano, msg.Timestamp)
	if err != nil {
		t.Fatalf("timestamp %q is not RFC 3339: %v", msg.Timestamp, err)
	}
	if parsed.After(time.Now().UTC().Add(24 * time.Hour)) {
		t.Errorf("timestamp %s is in the future; a year-boundary line was dated forward", msg.Timestamp)
	}
}

func TestTheRawLineIsAlwaysKept(t *testing.T) {
	// Every parse here is a lossy summary, and an appliance emitting
	// something this parser misreads is itself the finding.
	line := `<34>Oct 11 22:14:15 mymachine su: something`
	msg, err := Parse(line)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if msg.Raw != line {
		t.Errorf("raw = %q, want the line exactly as it arrived", msg.Raw)
	}
	if got := msg.Fields()["raw"]; got != line {
		t.Errorf("Fields()[raw] = %q", got)
	}
}
