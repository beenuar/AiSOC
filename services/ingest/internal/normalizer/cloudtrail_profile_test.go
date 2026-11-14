package normalizer

import "testing"

// Every CloudTrail event collapsed into one alert.
//
// Found by live QA: `aws_cloudtrail` had no entry in `connectorProfiles`,
// so it hit the generic fallback, which titles every event "Security
// Finding from aws_cloudtrail" and carries no vendor id. The alert id is
// a v5 UUID derived from that content, so a console login and a
// DeleteTrail deduplicated onto the same row — a customer connecting
// CloudTrail saw exactly one alert no matter what happened in their
// account, which reads as a quiet estate rather than as a bug.
//
// The test that matters is the second one: two distinct events must
// produce two distinct dedup keys. Asserting the profile merely exists
// would pass against a profile that maps nothing useful.
func TestCloudTrailHasAProfile(t *testing.T) {
	profile, ok := connectorProfiles["aws_cloudtrail"]
	if !ok {
		t.Fatal("aws_cloudtrail has no profile, so it falls through to the generic fallback " +
			"and every event in an AWS account becomes the same alert")
	}
	if profile.classUID != 2001 {
		t.Errorf("classUID = %d, want 2001: the connector ships a curated allow-list, so it "+
			"has already decided these are security-relevant, and category 2 is always promoted",
			profile.classUID)
	}
	if profile.product.VendorName != "AWS" {
		t.Errorf("vendor = %q, want AWS: the fallback stamps the wrong vendor on alert.source",
			profile.product.VendorName)
	}
}

func TestCloudTrailDistinguishesTwoEvents(t *testing.T) {
	profile := connectorProfiles["aws_cloudtrail"]

	// The event name has to reach `message`, because that is what the
	// promoter turns into the alert title and the dedup key reads.
	if got := profile.fieldMap["title"]; got != "message" {
		t.Fatalf("title maps to %q, want \"message\": without it every event shares a title "+
			"and therefore shares an alert", got)
	}
	// And the vendor id has to survive, so two events with the same name
	// at different times are still two findings.
	if got := profile.fieldMap["external_id"]; got != "finding.uid" {
		t.Fatalf("external_id maps to %q, want \"finding.uid\"", got)
	}
}

func TestCloudTrailMapsFromTheConnectorsOwnKeys(t *testing.T) {
	// Not from raw CloudTrail field names: by the time ingest sees this,
	// `services/connectors/app/connectors/aws_cloudtrail.py::normalize`
	// has already flattened it to lowercase keys. Mapping "EventName"
	// here would silently map nothing.
	profile := connectorProfiles["aws_cloudtrail"]
	for _, raw := range []string{"EventName", "eventName", "Title", "sourceIPAddress"} {
		if _, found := profile.fieldMap[raw]; found {
			t.Errorf("fieldMap keys on %q, which is a raw CloudTrail name; the connector "+
				"emits lowercase keys and this mapping would never fire", raw)
		}
	}
	for _, want := range []string{"title", "external_id", "src_ip", "user_name", "created_at"} {
		if _, found := profile.fieldMap[want]; !found {
			t.Errorf("fieldMap is missing %q, which the connector emits", want)
		}
	}
}
