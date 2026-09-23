// The HTTP provider's URL has to match the route the connectors service
// actually serves (T1.2).
//
// It did not, for four independent reasons at once — method, path prefix, path
// separator, and payload — and every one of them was invisible. A 404 maps to
// ErrNotImplemented, which the snapshotter treats as a soft skip, so an
// operator saw "T1.2 config snapshots enabled" and zero Configuration nodes
// with nothing written to the log.
//
// Nothing compared the two halves of the contract. These tests pin the shape
// of the request so a rename on either side fails here rather than in
// production silence.
package config_snapshot

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/beenuar/aisoc/services/ingest/internal/graph"
)

func TestHTTPProvider_RequestMatchesTheServedRoute(t *testing.T) {
	var gotMethod, gotPath, gotResourceID, gotTS string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotPath = r.URL.Path
		gotResourceID = r.URL.Query().Get("resource_id")
		gotTS = r.URL.Query().Get("ts")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"public": true}`))
	}))
	defer srv.Close()

	ts := time.Date(2026, 9, 23, 12, 0, 0, 0, time.UTC)
	cfg, err := NewHTTPProvider(srv.URL, time.Second).
		GetResourceConfig(context.Background(), "inst-123", "arn:aws:s3:::bucket", ts)
	if err != nil {
		t.Fatalf("GetResourceConfig: %v", err)
	}
	if cfg["public"] != true {
		t.Fatalf("config not returned: %#v", cfg)
	}

	if gotMethod != http.MethodGet {
		t.Errorf("method = %q, want GET", gotMethod)
	}
	// The instance-scoped route. The old URL omitted /api and used an
	// underscore, so it reached no handler.
	if want := "/api/v1/connectors/instances/inst-123/resource-config"; gotPath != want {
		t.Errorf("path = %q, want %q", gotPath, want)
	}
	if gotResourceID != "arn:aws:s3:::bucket" {
		t.Errorf("resource_id = %q", gotResourceID)
	}
	if gotTS != "2026-09-23T12:00:00Z" {
		t.Errorf("ts = %q", gotTS)
	}
}

func TestHTTPProvider_EscapesVendorSuppliedIdentifiers(t *testing.T) {
	// A resource id is vendor-supplied and can contain & / # — unescaped,
	// those truncate the URL or inject a parameter.
	var gotResourceID, gotTS string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotResourceID = r.URL.Query().Get("resource_id")
		gotTS = r.URL.Query().Get("ts")
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	hostile := "bucket?ts=1970-01-01T00:00:00Z&resource_id=other"
	if _, err := NewHTTPProvider(srv.URL, time.Second).
		GetResourceConfig(context.Background(), "inst-1", hostile, time.Unix(0, 0).UTC()); err != nil {
		t.Fatalf("GetResourceConfig: %v", err)
	}
	if gotResourceID != hostile {
		t.Errorf("resource_id was not round-tripped intact: %q", gotResourceID)
	}
	if gotTS != "1970-01-01T00:00:00Z" {
		t.Errorf("ts was overridden by the injected parameter: %q", gotTS)
	}
}

func TestHTTPProvider_TrailingSlashOnBaseURLDoesNotDoubleUp(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	if _, err := NewHTTPProvider(srv.URL+"/", time.Second).
		GetResourceConfig(context.Background(), "inst-1", "res-1", time.Now()); err != nil {
		t.Fatalf("GetResourceConfig: %v", err)
	}
	if strings.Contains(gotPath, "//") {
		t.Errorf("path has a doubled separator: %q", gotPath)
	}
}

func TestHTTPProvider_NotImplementedIsDistinctFromAnError(t *testing.T) {
	// 501 means "this connector cannot time-travel a config", which is a
	// routine skip. Anything else is a failure the operator should see.
	for _, tc := range []struct {
		status int
		soft   bool
	}{
		{http.StatusNotImplemented, true},
		{http.StatusNotFound, true},
		{http.StatusBadGateway, false},
		{http.StatusInternalServerError, false},
	} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(tc.status)
		}))
		_, err := NewHTTPProvider(srv.URL, time.Second).
			GetResourceConfig(context.Background(), "inst-1", "res-1", time.Now())
		srv.Close()

		if err == nil {
			t.Fatalf("status %d: expected an error", tc.status)
		}
		isSoft := err == ErrNotImplemented
		if isSoft != tc.soft {
			t.Errorf("status %d: soft-skip = %v, want %v (err=%v)", tc.status, isSoft, tc.soft, err)
		}
	}
}

func TestApply_WritesTheBiTemporalEdgeProperties(t *testing.T) {
	// schemas/graph-schema.yaml declares valid_from / valid_to / is_current
	// and the published schema doc advertises an O(1) latest-config lookup
	// via `:CONFIGURED_AS {is_current: true}`. None of the three was ever
	// written, so that query matched zero edges. The drift gate could not
	// catch it: it only validates properties on edges declared
	// `event_edge: true`, and CONFIGURED_AS is structural.
	ts := mustParseTime(t, "2026-05-01T13:00:00Z")
	provider := NewStaticProvider(map[string]map[string][]ConfigSnapshot{
		"aws_security_hub": {
			"arn:aws:s3:::demo": {
				{Recorded: ts.Add(-time.Hour), Data: map[string]interface{}{"public": true}},
			},
		},
	})
	s, err := New(Config{Provider: provider, TTL: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	ev := newAWSEvent(ts, "arn:aws:s3:::demo")
	s.Apply(context.Background(), ev)

	var rel *graph.Edge
	for i := range ev.Edges {
		if ev.Edges[i].Type == graph.RelConfiguredAs {
			rel = &ev.Edges[i]
			break
		}
	}
	if rel == nil {
		t.Fatal("no CONFIGURED_AS edge was attached")
	}
	if rel.Properties["is_current"] != true {
		t.Errorf("is_current = %v, want true", rel.Properties["is_current"])
	}
	if got := rel.Properties["valid_from"]; got != ts.UTC().Format(time.RFC3339Nano) {
		t.Errorf("valid_from = %v", got)
	}
	if v, ok := rel.Properties["snapshot_id"].(string); !ok || v == "" {
		t.Errorf("snapshot_id is required by the schema, got %v", rel.Properties["snapshot_id"])
	}
	// An open interval, not one that closed at the epoch: a reader filtering
	// `valid_to < now` would otherwise drop the current configuration.
	if _, present := rel.Properties["valid_to"]; present {
		t.Errorf("valid_to should be absent while the interval is open, got %v", rel.Properties["valid_to"])
	}
}
