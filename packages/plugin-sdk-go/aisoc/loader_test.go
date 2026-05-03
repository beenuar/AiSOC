package aisoc_test

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/beenuar/aisoc/plugin-sdk-go/aisoc"
)

func writeManifest(t *testing.T, dir string, content map[string]any) {
	t.Helper()
	data, err := json.Marshal(content)
	if err != nil {
		t.Fatalf("marshal manifest: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "aisoc-plugin.json"), data, 0o600); err != nil {
		t.Fatalf("write manifest: %v", err)
	}
}

func TestLoadManifestValid(t *testing.T) {
	dir := t.TempDir()
	writeManifest(t, dir, map[string]any{
		"id":          "test.enricher",
		"name":        "Test Enricher",
		"version":     "1.0.0",
		"plugin_type": "enricher",
	})

	m, err := aisoc.LoadManifest(dir)
	if err != nil {
		t.Fatalf("LoadManifest: %v", err)
	}
	if m.ID != "test.enricher" {
		t.Fatalf("expected id=test.enricher, got %s", m.ID)
	}
	if m.PluginType != aisoc.PluginTypeEnricher {
		t.Fatalf("expected plugin_type=enricher, got %s", m.PluginType)
	}
}

func TestLoadManifestMissingFile(t *testing.T) {
	dir := t.TempDir()
	_, err := aisoc.LoadManifest(dir)
	if err == nil {
		t.Fatal("expected error for missing manifest")
	}
	var loaderErr *aisoc.LoaderError
	if !errors.As(err, &loaderErr) {
		t.Fatalf("expected *LoaderError, got %T", err)
	}
}

func TestLoadManifestInvalidJSON(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "aisoc-plugin.json"), []byte("not-json"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := aisoc.LoadManifest(dir)
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
	var loaderErr *aisoc.LoaderError
	if !errors.As(err, &loaderErr) {
		t.Fatalf("expected *LoaderError, got %T", err)
	}
}

func TestLoadManifestMissingRequiredFields(t *testing.T) {
	dir := t.TempDir()
	// missing 'name' and 'plugin_type'
	writeManifest(t, dir, map[string]any{
		"id":      "test.enricher",
		"version": "1.0.0",
	})
	_, err := aisoc.LoadManifest(dir)
	if err == nil {
		t.Fatal("expected error for missing required fields")
	}
}

func TestLoadManifestInvalidPluginType(t *testing.T) {
	dir := t.TempDir()
	writeManifest(t, dir, map[string]any{
		"id":          "test.bad",
		"name":        "Bad",
		"version":     "1.0.0",
		"plugin_type": "unsupported",
	})
	_, err := aisoc.LoadManifest(dir)
	if err == nil {
		t.Fatal("expected error for invalid plugin_type")
	}
}

func TestLoadManifestActionType(t *testing.T) {
	dir := t.TempDir()
	writeManifest(t, dir, map[string]any{
		"id":          "test.action",
		"name":        "Test Action",
		"version":     "2.0.0",
		"plugin_type": "action",
		"tags":        []string{"firewall", "block"},
	})
	m, err := aisoc.LoadManifest(dir)
	if err != nil {
		t.Fatalf("LoadManifest: %v", err)
	}
	if m.PluginType != aisoc.PluginTypeAction {
		t.Fatalf("expected action type, got %s", m.PluginType)
	}
	if len(m.Tags) != 2 {
		t.Fatalf("expected 2 tags, got %d", len(m.Tags))
	}
}
