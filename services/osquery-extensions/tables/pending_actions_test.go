package tables_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/beenuar/aisoc/osquery-extensions/internal/aisocapi"
	"github.com/beenuar/aisoc/osquery-extensions/internal/config"
	"github.com/beenuar/aisoc/osquery-extensions/tables"
	"github.com/osquery/osquery-go/plugin/table"
)

func TestPendingActionsGenerate(t *testing.T) {
	fixture := []aisocapi.PendingAction{
		{
			ActionID:    "act-001",
			CaseID:      "case-42",
			ActionType:  "isolate",
			Target:      "web-01",
			RequestedBy: "analyst@example.com",
			RequestedAt: "2026-05-10T10:00:00Z",
			ExpiresAt:   "2026-05-11T10:00:00Z",
			Description: "Isolate suspected C2 host",
		},
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(fixture)
	}))
	defer srv.Close()

	cfg := &config.Config{
		APIURL:         srv.URL,
		APIToken:       "",
		HostIdentifier: "test",
		HTTPTimeout:    5 * time.Second,
	}
	client := aisocapi.New(cfg)
	gen := tables.PendingActionsGenerate(client)
	rows, err := gen(context.Background(), table.QueryContext{})
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("expected 1 row, got %d", len(rows))
	}
	if rows[0]["action_id"] != "act-001" {
		t.Errorf("unexpected action_id: %s", rows[0]["action_id"])
	}
	if rows[0]["action_type"] != "isolate" {
		t.Errorf("unexpected action_type: %s", rows[0]["action_type"])
	}
}

func TestPendingActionsGenerateAPIError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "server error", http.StatusInternalServerError)
	}))
	defer srv.Close()

	cfg := &config.Config{APIURL: srv.URL, HTTPTimeout: 2 * time.Second}
	client := aisocapi.New(cfg)
	gen := tables.PendingActionsGenerate(client)
	rows, err := gen(context.Background(), table.QueryContext{})
	if err != nil {
		t.Fatalf("generate should not propagate API error: %v", err)
	}
	if len(rows) != 0 {
		t.Errorf("expected empty rows on error, got %d", len(rows))
	}
}
