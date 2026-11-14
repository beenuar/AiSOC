package publisher

import (
	"testing"

	"github.com/beenuar/aisoc/services/ingest/internal/normalizer"
)

func event(tenant, id string, ocsf map[string]interface{}) *normalizer.NormalizedEvent {
	return &normalizer.NormalizedEvent{ID: id, TenantID: tenant, OcsfEvent: ocsf}
}

// The whole point: two events about one host must land on one partition,
// or fusion correlates them on two replicas and stitches a sequence out of
// order or splits one incident in two.
func TestTwoEventsAboutOneEntityShareAKey(t *testing.T) {
	first := event("t1", "e1", map[string]interface{}{
		"device": map[string]interface{}{"hostname": "WS-014"},
	})
	second := event("t1", "e2", map[string]interface{}{
		"device": map[string]interface{}{"hostname": "WS-014"},
	})
	if string(partitionKey(first)) != string(partitionKey(second)) {
		t.Fatalf("%q != %q", partitionKey(first), partitionKey(second))
	}
}

func TestDifferentEntitiesGetDifferentKeys(t *testing.T) {
	a := event("t1", "e1", map[string]interface{}{"hostname": "WS-014"})
	b := event("t1", "e2", map[string]interface{}{"hostname": "WS-015"})
	if string(partitionKey(a)) == string(partitionKey(b)) {
		t.Fatal("two hosts hashed to one key; the topic is serialised, not partitioned")
	}
}

// A tenant's events must never share a partition with another tenant's by
// accident of having the same hostname.
func TestTheSameEntityInTwoTenantsIsTwoKeys(t *testing.T) {
	a := event("t1", "e1", map[string]interface{}{"hostname": "WS-014"})
	b := event("t2", "e2", map[string]interface{}{"hostname": "WS-014"})
	if string(partitionKey(a)) == string(partitionKey(b)) {
		t.Fatal("two tenants share a partition key")
	}
}

// The precedence has to be fusion's, or an entity is routed under one name
// and correlated under another.
func TestPrecedenceMatchesTheCorrelationKey(t *testing.T) {
	cases := []struct {
		name string
		ocsf map[string]interface{}
		want string
	}{
		{
			"source ip wins over hostname",
			map[string]interface{}{
				"src_endpoint": map[string]interface{}{"ip": "198.51.100.4"},
				"device":       map[string]interface{}{"hostname": "WS-014"},
			},
			"t1:198.51.100.4",
		},
		{
			"hostname wins over username",
			map[string]interface{}{
				"device":     map[string]interface{}{"hostname": "WS-014"},
				"actor.user": map[string]interface{}{"name": "alice"},
			},
			"t1:WS-014",
		},
		{
			"flat connector fields are read too",
			map[string]interface{}{"src_ip": "203.0.113.9"},
			"t1:203.0.113.9",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := string(partitionKey(event("t1", "e1", tc.ocsf))); got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
}

// An event naming nobody must not pile onto one partition per tenant: that
// is a hot partition and also the least useful one to serialise.
func TestAnEventWithNoEntityFallsBackToItsOwnId(t *testing.T) {
	a := partitionKey(event("t1", "e1", map[string]interface{}{"message": "something happened"}))
	b := partitionKey(event("t1", "e2", map[string]interface{}{"message": "something else"}))
	if string(a) == string(b) {
		t.Fatal("two anonymous events share a key; that is a hot partition")
	}
	if string(a) != "t1:e1" {
		t.Fatalf("fallback key is %q", a)
	}
}

func TestAnEmptyEntityStringIsNotUsedAsAKey(t *testing.T) {
	// A whitespace-only hostname is not an entity, and keying on it would
	// collapse every event that carries one onto a single partition.
	got := partitionKey(event("t1", "e1", map[string]interface{}{"hostname": "   "}))
	if string(got) != "t1:e1" {
		t.Fatalf("blank hostname produced key %q", got)
	}
}

func TestANilOcsfEventStillGetsAKey(t *testing.T) {
	if string(partitionKey(event("t1", "e1", nil))) != "t1:e1" {
		t.Fatal("a nil OCSF event produced no usable key")
	}
}
