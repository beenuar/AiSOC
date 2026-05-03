package aisoc_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/beenuar/aisoc/plugin-sdk-go/aisoc"
)

// newTestServer returns a test HTTP server that handles the given pattern.
// The handler always returns the provided status code and JSON body.
func newTestServer(t *testing.T, pattern string, statusCode int, responseBody map[string]any) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc(pattern, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(statusCode)
		if responseBody != nil {
			_ = json.NewEncoder(w).Encode(responseBody)
		}
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func pctxFor(baseURL string) aisoc.PluginContext {
	return aisoc.PluginContext{APIBaseURL: baseURL, APIToken: "test-token"}
}

// ── GetCase ───────────────────────────────────────────────────────────────

func TestClientGetCase(t *testing.T) {
	srv := newTestServer(t, "/api/v1/cases/c1", http.StatusOK, map[string]any{"id": "c1", "title": "Test"})
	client := aisoc.NewClient(pctxFor(srv.URL), 0)

	data, err := client.GetCase(context.Background(), "c1")
	if err != nil {
		t.Fatalf("GetCase: %v", err)
	}
	if data["id"] != "c1" {
		t.Fatalf("expected id=c1, got %v", data["id"])
	}
}

// ── AddCaseNote ───────────────────────────────────────────────────────────

func TestClientAddCaseNote(t *testing.T) {
	srv := newTestServer(t, "/api/v1/cases/c1/notes", http.StatusCreated, map[string]any{"ok": true})
	client := aisoc.NewClient(pctxFor(srv.URL), 0)

	data, err := client.AddCaseNote(context.Background(), "c1", "evidence found")
	if err != nil {
		t.Fatalf("AddCaseNote: %v", err)
	}
	if data["ok"] != true {
		t.Fatalf("expected ok=true, got %v", data["ok"])
	}
}

// ── PatchIndicator ────────────────────────────────────────────────────────

func TestClientPatchIndicator(t *testing.T) {
	srv := newTestServer(t, "/api/v1/indicators/ind1", http.StatusOK, map[string]any{"updated": true})
	client := aisoc.NewClient(pctxFor(srv.URL), 0)

	data, err := client.PatchIndicator(context.Background(), "ind1", map[string]any{"geo": "US"})
	if err != nil {
		t.Fatalf("PatchIndicator: %v", err)
	}
	if data["updated"] != true {
		t.Fatalf("expected updated=true, got %v", data["updated"])
	}
}

// ── error handling ────────────────────────────────────────────────────────

func TestClientErrorOnNon2xx(t *testing.T) {
	srv := newTestServer(t, "/api/v1/cases/missing", http.StatusNotFound, map[string]any{"detail": "not found"})
	client := aisoc.NewClient(pctxFor(srv.URL), 0)

	_, err := client.GetCase(context.Background(), "missing")
	if err == nil {
		t.Fatal("expected error on 404")
	}
	var clientErr *aisoc.ClientError
	if cerr, ok := err.(*aisoc.ClientError); ok {
		clientErr = cerr
	}
	if clientErr == nil {
		t.Fatalf("expected *ClientError, got %T: %v", err, err)
	}
	if clientErr.StatusCode != http.StatusNotFound {
		t.Fatalf("expected status 404, got %d", clientErr.StatusCode)
	}
}

// ── CompletePlaybookStep ──────────────────────────────────────────────────

func TestClientCompletePlaybookStep(t *testing.T) {
	srv := newTestServer(t, "/api/v1/playbook-runs/run1/steps/step1/complete",
		http.StatusOK, map[string]any{"status": "done"})
	client := aisoc.NewClient(pctxFor(srv.URL), 0)

	data, err := client.CompletePlaybookStep(context.Background(), "run1", "step1",
		map[string]any{"output": "ok"})
	if err != nil {
		t.Fatalf("CompletePlaybookStep: %v", err)
	}
	if data["status"] != "done" {
		t.Fatalf("expected status=done, got %v", data["status"])
	}
}
