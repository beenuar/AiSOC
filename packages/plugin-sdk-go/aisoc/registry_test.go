package aisoc_test

import (
	"context"
	"testing"

	"github.com/beenuar/aisoc/plugin-sdk-go/aisoc"
)

// ── mock enricher ──────────────────────────────────────────────────────────

type mockEnricher struct {
	aisoc.BasePlugin
}

func (m *mockEnricher) Manifest() aisoc.PluginManifest {
	return aisoc.PluginManifest{
		ID:         "test.mock-enricher",
		Name:       "Mock Enricher",
		Version:    "1.0.0",
		PluginType: aisoc.PluginTypeEnricher,
	}
}

func (m *mockEnricher) Enrich(
	_ context.Context,
	req aisoc.EnrichmentRequest,
	_ aisoc.PluginContext,
) (aisoc.EnrichmentResult, error) {
	malicious := false
	return aisoc.EnrichmentResult{
		IndicatorType:  req.IndicatorType,
		IndicatorValue: req.IndicatorValue,
		Enrichments:    map[string]any{"source": "mock"},
		Malicious:      &malicious,
	}, nil
}

// ── mock action ────────────────────────────────────────────────────────────

type mockAction struct {
	aisoc.BasePlugin
}

func (m *mockAction) Manifest() aisoc.PluginManifest {
	return aisoc.PluginManifest{
		ID:         "test.mock-action",
		Name:       "Mock Action",
		Version:    "1.0.0",
		PluginType: aisoc.PluginTypeAction,
	}
}

func (m *mockAction) SupportedActions() []string { return []string{"mock_action"} }

func (m *mockAction) Execute(
	_ context.Context,
	req aisoc.ActionRequest,
	_ aisoc.PluginContext,
) (aisoc.ActionResult, error) {
	return aisoc.ActionResult{
		ActionID: req.ActionID,
		Success:  true,
		Summary:  "executed",
	}, nil
}

// ── tests ──────────────────────────────────────────────────────────────────

func TestRegistryRegisterAndLookup(t *testing.T) {
	reg := aisoc.NewRegistry()
	if err := reg.Register(&mockEnricher{}); err != nil {
		t.Fatalf("register enricher: %v", err)
	}
	if err := reg.Register(&mockAction{}); err != nil {
		t.Fatalf("register action: %v", err)
	}
	if reg.Len() != 2 {
		t.Fatalf("expected 2 plugins, got %d", reg.Len())
	}
	if len(reg.Enrichers()) != 1 {
		t.Fatalf("expected 1 enricher")
	}
	if len(reg.Actions()) != 1 {
		t.Fatalf("expected 1 action")
	}
	if p := reg.Get("test.mock-enricher"); p == nil {
		t.Fatal("expected to find test.mock-enricher")
	}
}

func TestRegistryDuplicateReturnsError(t *testing.T) {
	reg := aisoc.NewRegistry()
	_ = reg.Register(&mockEnricher{})
	if err := reg.Register(&mockEnricher{}); err == nil {
		t.Fatal("expected error on duplicate registration")
	}
}

func TestRegistryUnregister(t *testing.T) {
	reg := aisoc.NewRegistry()
	_ = reg.Register(&mockEnricher{})
	reg.Unregister("test.mock-enricher")
	if reg.Len() != 0 {
		t.Fatal("expected 0 plugins after unregister")
	}
}

func TestEnricherInvoke(t *testing.T) {
	e := &mockEnricher{}
	ctx := context.Background()
	pctx := aisoc.PluginContext{APIBaseURL: "http://localhost:8000", APIToken: "tok"}
	req := aisoc.EnrichmentRequest{
		IndicatorType:  aisoc.IndicatorIP,
		IndicatorValue: "1.2.3.4",
	}
	result, err := e.Enrich(ctx, req, pctx)
	if err != nil {
		t.Fatalf("enrich: %v", err)
	}
	if result.IndicatorValue != "1.2.3.4" {
		t.Fatalf("unexpected indicator value: %s", result.IndicatorValue)
	}
	if *result.Malicious != false {
		t.Fatal("expected malicious=false")
	}
}
