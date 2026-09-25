// readyz_test.go — what the readiness probe says about background
// subscriptions.
//
// The property under test is the one the UEBA defect turned on: a consumer
// detached from its topic behind a 200 that never mentions it is
// indistinguishable from an idle one. Readiness has to name every
// subscription it knows about, in the healthy case too, or a clean answer
// only means "nothing I looked at was wrong" without saying what that was.
package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/beenuar/aisoc/services/ingest/internal/config"
)

func newReadyHandler() *Handler {
	// pub is nil, so readiness short-circuits on the publisher before any
	// Kafka round-trip. That is the path a test can drive deterministically,
	// and the subscription report has to survive it — a probe that only
	// renders on the happy path reports nothing at the moment it matters.
	return New(nil, nil, &config.Config{})
}

func decodeBody(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("readiness body is not JSON: %v (%s)", err, rec.Body.String())
	}
	return body
}

func callReadyz(t *testing.T, h *Handler) (*httptest.ResponseRecorder, map[string]any) {
	t.Helper()
	rec := httptest.NewRecorder()
	h.Readyz(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	return rec, decodeBody(t, rec)
}

func TestReadyzNamesAnAttachedSubscription(t *testing.T) {
	h := newReadyHandler()
	h.RegisterSubscription("graph_ws", func() SubscriptionStatus {
		return SubscriptionStatus{Attached: true}
	})

	_, body := callReadyz(t, h)
	subs, ok := body["subscriptions"].(map[string]any)
	if !ok {
		t.Fatalf("no subscriptions block in %v", body)
	}
	entry, ok := subs["graph_ws"].(map[string]any)
	if !ok {
		t.Fatalf("graph_ws not named in %v", subs)
	}
	if entry["attached"] != true {
		t.Fatalf("attached subscription reported as %v", entry)
	}
	if _, degraded := body["degraded_subscriptions"]; degraded {
		t.Fatalf("a healthy subscription was reported as degraded: %v", body)
	}
}

func TestReadyzReportsADetachedSubscription(t *testing.T) {
	h := newReadyHandler()
	h.RegisterSubscription("graph_ws", func() SubscriptionStatus {
		return SubscriptionStatus{Attached: false, NotResolving: true, Detail: "permanent source failure on security.graph_updates"}
	})

	_, body := callReadyz(t, h)
	subs := body["subscriptions"].(map[string]any)
	entry := subs["graph_ws"].(map[string]any)
	if entry["attached"] != false || entry["not_resolving"] != true {
		t.Fatalf("detached subscription reported as %v", entry)
	}
	if entry["detail"] != "permanent source failure on security.graph_updates" {
		t.Fatalf("the reason did not survive into the body: %v", entry)
	}
	degraded, ok := body["degraded_subscriptions"].([]any)
	if !ok || len(degraded) != 1 || degraded[0] != "graph_ws" {
		t.Fatalf("degraded subscriptions = %v, want [graph_ws]", body["degraded_subscriptions"])
	}
}

// A subscription that is attached but has been failing longer than a
// transient fault explains is the case a boolean cannot express. Attached
// alone would report it healthy, which is the distinction this whole change
// is about.
func TestReadyzReportsAnAttachedButNotResolvingSubscription(t *testing.T) {
	h := newReadyHandler()
	h.RegisterSubscription("graph_ws", func() SubscriptionStatus {
		return SubscriptionStatus{Attached: true, NotResolving: true, Detail: "failing for 300s"}
	})

	_, body := callReadyz(t, h)
	degraded, ok := body["degraded_subscriptions"].([]any)
	if !ok || len(degraded) != 1 {
		t.Fatalf("an attached-but-stuck subscription was not reported as degraded: %v", body)
	}
}

func TestReadyzSurvivesAProbeThatPanics(t *testing.T) {
	h := newReadyHandler()
	h.RegisterSubscription("exploding", func() SubscriptionStatus {
		panic("probe blew up")
	})

	rec, body := callReadyz(t, h)
	if rec.Code == 0 {
		t.Fatal("no response was written")
	}
	subs := body["subscriptions"].(map[string]any)
	entry := subs["exploding"].(map[string]any)
	if entry["attached"] != false || entry["not_resolving"] != true {
		t.Fatalf("a panicking probe was credited as healthy: %v", entry)
	}
}

// With no subscription registered the block is present and empty, so a
// reader can tell "nothing is registered" from "the field was dropped".
func TestReadyzAlwaysCarriesTheSubscriptionBlock(t *testing.T) {
	_, body := callReadyz(t, newReadyHandler())
	subs, ok := body["subscriptions"].(map[string]any)
	if !ok {
		t.Fatalf("subscriptions block missing entirely from %v", body)
	}
	if len(subs) != 0 {
		t.Fatalf("expected an empty block, got %v", subs)
	}
}
