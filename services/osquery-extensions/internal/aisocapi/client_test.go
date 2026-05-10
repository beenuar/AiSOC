package aisocapi_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/beenuar/aisoc/osquery-extensions/internal/aisocapi"
	"github.com/beenuar/aisoc/osquery-extensions/internal/config"
)

func newTestClient(t *testing.T, handler http.HandlerFunc) (*aisocapi.Client, *httptest.Server) {
	t.Helper()
	srv := httptest.NewServer(handler)
	cfg := &config.Config{
		APIURL:         srv.URL,
		APIToken:       "test-token",
		HostIdentifier: "test-host",
		HTTPTimeout:    5 * time.Second,
	}
	return aisocapi.New(cfg), srv
}

func TestGetPendingActions(t *testing.T) {
	want := []aisocapi.PendingAction{
		{
			ActionID:   "act-001",
			ActionType: "isolate",
			Target:     "test-host",
		},
	}
	client, srv := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/extensions/pending-actions" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer test-token" {
			t.Errorf("missing/wrong auth header")
		}
		_ = json.NewEncoder(w).Encode(want)
	})
	defer srv.Close()

	got, err := client.GetPendingActions(context.Background())
	if err != nil {
		t.Fatalf("GetPendingActions: %v", err)
	}
	if len(got) != 1 || got[0].ActionID != "act-001" {
		t.Errorf("unexpected result: %+v", got)
	}
}

func TestGetAlertCache(t *testing.T) {
	want := []aisocapi.AlertCacheEntry{
		{AlertID: "alr-999", Severity: "HIGH"},
	}
	client, srv := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/extensions/alert-cache" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode(want)
	})
	defer srv.Close()

	got, err := client.GetAlertCache(context.Background())
	if err != nil {
		t.Fatalf("GetAlertCache: %v", err)
	}
	if len(got) != 1 || got[0].AlertID != "alr-999" {
		t.Errorf("unexpected result: %+v", got)
	}
}

func TestHTTPError(t *testing.T) {
	client, srv := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "forbidden", http.StatusForbidden)
	})
	defer srv.Close()

	_, err := client.GetPendingActions(context.Background())
	if err == nil {
		t.Fatal("expected error for 403 response")
	}
}
