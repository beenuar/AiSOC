package normalizer

import (
	"encoding/json"
	"testing"

	"github.com/beenuar/aisoc/services/ingest/internal/activity"
)

// Depth plan wave 2, item 1.6.
//
// The classes are stamped at ingest, on the activity projection, from a
// pinned local dataset. The test drives the real `Normalize` entry point
// rather than the stamper directly, because the defect this area keeps
// producing is a correct function nothing calls: an `ipclass` package with
// passing unit tests and no line in `Normalize` would look identical to a
// working feature from outside.
//
// A Tor exit relay address is read out of the committed dataset rather than
// hardcoded. Hardcoding one would turn a dataset refresh into a mystery test
// failure, and would also let the test pass against a dataset that had
// silently become empty.
func TestNormalizeStampsAnonymizerClass(t *testing.T) {
	torIP := activity.SampleIPForClass("tor_exit")
	if torIP == "" {
		t.Fatal("the committed dataset yielded no tor_exit sample; refusing to pass on an empty read")
	}
	hostingIP := activity.SampleIPForClass("hosting_provider")
	if hostingIP == "" {
		t.Fatal("the committed dataset yielded no hosting_provider sample; refusing to pass on an empty read")
	}

	cases := []struct {
		name      string
		ip        string
		wantClass string
	}{
		{"tor exit relay", torIP, "tor_exit"},
		{"cloud hosting range", hostingIP, "hosting_provider"},
		// RFC 5737 documentation space is not public, so no lookup is made
		// and the class stays empty. An unknown origin must never render as
		// "not an anonymizer".
		{"documentation range stays unclassified", "203.0.113.17", ""},
		// A public address in no shipped list is also unclassified: the
		// shipped dataset covers two classes, and the other three are
		// tenant-supplied. Absent, never false.
		{"unlisted public address stays unclassified", "198.18.250.250", ""},
	}

	n := newLenientNormalizer()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			raw := &RawEvent{
				ConnectorID:   "c-1",
				ConnectorType: "okta_system_log",
				TenantID:      "11111111-1111-1111-1111-111111111111",
				Payload: map[string]interface{}{
					"published": "2026-11-01T00:00:00Z",
					"client":    map[string]interface{}{"ipAddress": tc.ip},
					"actor":     map[string]interface{}{"alternateId": "user@example.com"},
				},
			}
			out, err := n.Normalize(raw)
			if err != nil {
				t.Fatalf("Normalize: %v", err)
			}
			act := activityOf(t, out.OcsfEvent)
			if act.Location.IPClass != tc.wantClass {
				t.Fatalf("ip %s: ip_class = %q, want %q", tc.ip, act.Location.IPClass, tc.wantClass)
			}
			if tc.wantClass == "" {
				if act.Location.IPClassDatasetVersion != "" {
					t.Fatalf("unclassified address carried dataset version %q", act.Location.IPClassDatasetVersion)
				}
				return
			}
			// The plan requires the dataset's version on the event: a class
			// with no version is a claim nobody can date or reproduce.
			if act.Location.IPClassDatasetVersion == "" {
				t.Fatal("class was stamped with no dataset version")
			}
			if act.Location.IPClassSource == "" {
				t.Fatal("class was stamped with no provider attribution")
			}
		})
	}
}

// TestIPClassIsNotStampedForPrivateAddresses pins the privacy property the
// IP enricher beside it already holds: an internal address is never looked
// up and never classified.
func TestIPClassIsNotStampedForPrivateAddresses(t *testing.T) {
	n := newLenientNormalizer()
	for _, ip := range []string{"10.1.2.3", "192.168.4.5", "127.0.0.1", "fe80::1"} {
		raw := &RawEvent{
			ConnectorID:   "c-1",
			ConnectorType: "okta_system_log",
			TenantID:      "11111111-1111-1111-1111-111111111111",
			Payload: map[string]interface{}{
				"published": "2026-11-01T00:00:00Z",
				"client":    map[string]interface{}{"ipAddress": ip},
			},
		}
		out, err := n.Normalize(raw)
		if err != nil {
			t.Fatalf("Normalize(%s): %v", ip, err)
		}
		if act := activityOf(t, out.OcsfEvent); act.Location.IPClass != "" {
			t.Fatalf("private address %s was classified as %q", ip, act.Location.IPClass)
		}
	}
}

func activityOf(t *testing.T, ocsf map[string]interface{}) activity.Activity {
	t.Helper()
	blob, err := json.Marshal(ocsf["activity"])
	if err != nil {
		t.Fatalf("marshal activity: %v", err)
	}
	var act activity.Activity
	if err := json.Unmarshal(blob, &act); err != nil {
		t.Fatalf("unmarshal activity: %v", err)
	}
	return act
}
