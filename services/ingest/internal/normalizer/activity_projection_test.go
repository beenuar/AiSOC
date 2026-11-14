package normalizer

import (
	"testing"

	"github.com/beenuar/aisoc/services/ingest/internal/activity"
)

// The projection is on *every* normalized event, not only the ones a
// derivation recognises. A consumer that has to check whether the block
// exists before reading it will eventually forget, and the honest answer for
// a source that says nothing is `unknown` rather than an absent field.
func TestEveryNormalizedEventCarriesTheProjection(t *testing.T) {
	n := newLenientNormalizer()
	for _, connector := range []string{
		"aws_cloudtrail", "okta", "kubernetes_audit", // have derivations
		"zscaler", "tailscale", "some_connector_nobody_wrote", // do not
	} {
		t.Run(connector, func(t *testing.T) {
			ev, err := n.Normalize(&RawEvent{
				ConnectorID:   "c-1",
				ConnectorType: connector,
				TenantID:      "11111111-1111-1111-1111-111111111111",
				ReceivedAt:    "2026-10-07T00:00:00Z",
				Payload: map[string]interface{}{
					"source":    connector,
					"raw_event": map[string]interface{}{"id": "1"},
					"severity":  "high",
					"title":     "something happened",
				},
			})
			if err != nil {
				t.Fatalf("Normalize: %v", err)
			}
			act, ok := ev.OcsfEvent["activity"].(activity.Activity)
			if !ok {
				t.Fatalf("no activity projection on the event: %T", ev.OcsfEvent["activity"])
			}
			if act.Actor.Kind == "" {
				t.Error("actor.kind is empty; a source that says nothing must report `unknown`, not nothing")
			}
			if act.Outcome == "" {
				t.Error("outcome is empty; a source that says nothing must report `unknown`")
			}
		})
	}
}

// The projection reads the OCSF event *after* the identity aliases have run,
// which is the only reason it can name an actor on a connector whose vendor
// record spells the field something else entirely.
func TestTheProjectionSeesTheResolvedIdentity(t *testing.T) {
	ev, err := newLenientNormalizer().Normalize(&RawEvent{
		ConnectorID:   "c-1",
		ConnectorType: "zscaler",
		TenantID:      "11111111-1111-1111-1111-111111111111",
		ReceivedAt:    "2026-10-07T00:00:00Z",
		Payload: map[string]interface{}{
			"source":    "zscaler",
			"raw_event": map[string]interface{}{"userAgent": "aws-cli/2.15.30 Python/3.11.8"},
			"severity":  "medium",
			"title":     "web request",
			// `actor` is one of the alias sources, not an OCSF field name.
			"actor":  "alice@example.com",
			"src_ip": "203.0.113.9",
		},
	})
	if err != nil {
		t.Fatalf("Normalize: %v", err)
	}
	act := ev.OcsfEvent["activity"].(activity.Activity)
	if act.Actor.Name != "alice@example.com" {
		t.Errorf("actor.name = %q; the projection must read the alias-resolved OCSF identity", act.Actor.Name)
	}
	if act.Location.IP != "203.0.113.9" {
		t.Errorf("location.ip = %q", act.Location.IP)
	}
	if act.Location.Client.Family != "aws-cli" {
		t.Errorf("client.family = %q, want the parsed user agent", act.Location.Client.Family)
	}
	if act.Location.Client.Raw == "" {
		t.Error("the raw user agent was dropped; it is attacker-controlled and a hunt needs the original")
	}
}

// No enrichment service configured means no geography, and that must be a
// quiet absence rather than a per-event error or a fabricated country.
func TestWithNoEnricherTheLocationCarriesNoGeography(t *testing.T) {
	ev, err := newLenientNormalizer().Normalize(&RawEvent{
		ConnectorID:   "c-1",
		ConnectorType: "zscaler",
		TenantID:      "11111111-1111-1111-1111-111111111111",
		ReceivedAt:    "2026-10-07T00:00:00Z",
		Payload: map[string]interface{}{
			"source":    "zscaler",
			"raw_event": map[string]interface{}{},
			"src_ip":    "8.8.8.8",
			"severity":  "low",
		},
	})
	if err != nil {
		t.Fatalf("Normalize: %v", err)
	}
	act := ev.OcsfEvent["activity"].(activity.Activity)
	if act.Location.Country != "" || act.Location.ASN != 0 {
		t.Errorf("geography appeared with no enrichment service configured: %+v", act.Location)
	}
	if act.Location.ReputationKnown {
		t.Error("reputation_known is true with no enrichment service configured")
	}
}
