package inbox

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Registry tests focus on the load-from-disk contract because that's
// where the operator-facing failure modes live: a typo in one YAML
// file must not poison the whole registry, and severity keys must be
// case-folded so vendors that send "High" / "HIGH" / "high" all hit the
// same lookup.

func writeTemplate(t *testing.T, dir, name, body string) {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func TestRegistry_Load_ReadsValidTemplates(t *testing.T) {
	dir := t.TempDir()
	writeTemplate(t, dir, "pagerduty.yaml", `
vendor_name: PagerDuty
product_name: Events API v2
class_uid: 2001
class_name: Security Finding
field_map:
  event.id: metadata.event_id
  event.title: finding.title
severity_field: event.urgency
severity_map:
  low: 2
  high: 4
  critical: 5
constants:
  source: pagerduty.events.v2
`)
	writeTemplate(t, dir, "opsgenie.yaml", `
vendor_name: Atlassian Opsgenie
product_name: Webhook v2
class_uid: 2001
class_name: Security Finding
field_map:
  alert.alertId: metadata.event_id
`)

	r := NewRegistry()
	if err := r.Load(dir); err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	pd, err := r.Get("pagerduty")
	if err != nil {
		t.Fatalf("Get(pagerduty) failed: %v", err)
	}
	if pd.VendorName != "PagerDuty" {
		t.Errorf("vendor_name = %q", pd.VendorName)
	}
	if pd.ClassUID != 2001 {
		t.Errorf("class_uid = %d", pd.ClassUID)
	}
	if pd.FieldMap["event.id"] != "metadata.event_id" {
		t.Errorf("field_map missing or wrong: %v", pd.FieldMap)
	}

	if _, err := r.Get("opsgenie"); err != nil {
		t.Errorf("Get(opsgenie) failed: %v", err)
	}

	ids := r.IDs()
	if len(ids) != 2 {
		t.Errorf("IDs() = %v, want 2 entries", ids)
	}
}

func TestRegistry_Load_DefaultsIDFromFilename(t *testing.T) {
	// Operators rarely set an explicit `id:` — the filename stem is the
	// convention. Verify the registry honours it.
	dir := t.TempDir()
	writeTemplate(t, dir, "github-security-advisory.yaml", `
vendor_name: GitHub
class_uid: 2002
class_name: Vulnerability Finding
field_map: {}
`)
	r := NewRegistry()
	if err := r.Load(dir); err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	if _, err := r.Get("github-security-advisory"); err != nil {
		t.Errorf("ID not derived from filename: %v", err)
	}
}

func TestRegistry_Load_NormalisesSeverityKeys(t *testing.T) {
	// Vendor severity strings come in every casing imaginable; the load
	// step lowercases keys so the runtime lookup with strings.ToLower
	// always hits.
	dir := t.TempDir()
	writeTemplate(t, dir, "shouty.yaml", `
class_uid: 2001
class_name: Security Finding
field_map: {}
severity_map:
  CRITICAL: 5
  "  High  ": 4
  low: 2
`)
	r := NewRegistry()
	if err := r.Load(dir); err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	tmpl, _ := r.Get("shouty")
	if tmpl.SeverityMap["critical"] != 5 {
		t.Errorf("CRITICAL not folded to lowercase: %v", tmpl.SeverityMap)
	}
	if tmpl.SeverityMap["high"] != 4 {
		t.Errorf("'  High  ' not trimmed/folded: %v", tmpl.SeverityMap)
	}
	if _, ok := tmpl.SeverityMap["CRITICAL"]; ok {
		t.Errorf("uppercase key still present: %v", tmpl.SeverityMap)
	}
}

func TestRegistry_Load_SkipsMalformedYAMLWithoutFailingTheRest(t *testing.T) {
	// One typo in pagerduty.yaml must not take down opsgenie.yaml — that's
	// what makes the registry safe to populate from a community-contributed
	// /app/templates dir.
	dir := t.TempDir()
	writeTemplate(t, dir, "broken.yaml", "this: is: not valid: yaml: ::::")
	writeTemplate(t, dir, "good.yaml", `
class_uid: 2001
class_name: Security Finding
field_map: {}
`)
	r := NewRegistry()
	if err := r.Load(dir); err != nil {
		t.Fatalf("Load returned error despite skip-on-bad-yaml contract: %v", err)
	}
	if _, err := r.Get("good"); err != nil {
		t.Errorf("good template missing after broken sibling: %v", err)
	}
	if _, err := r.Get("broken"); err == nil {
		t.Errorf("broken template should not be registered")
	}
}

func TestRegistry_Load_IgnoresNonYAMLFiles(t *testing.T) {
	dir := t.TempDir()
	writeTemplate(t, dir, "README.md", "# templates")
	writeTemplate(t, dir, "config.json", `{"id":"x"}`)
	writeTemplate(t, dir, "good.yml", `
class_uid: 2001
class_name: Security Finding
field_map: {}
`)
	r := NewRegistry()
	if err := r.Load(dir); err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	if len(r.IDs()) != 1 {
		t.Errorf("non-YAML files leaked in: %v", r.IDs())
	}
}

func TestRegistry_Load_MissingDirIsNotAnError(t *testing.T) {
	// Load is now the operator override on top of LoadEmbedded, so an absent
	// directory is the normal case rather than a failure. It used to be an
	// error, and the default it was pointed at — /app/templates — was a path
	// the container image never contained, so the "error" was logged as a
	// warning on every boot and the inbox 503'd regardless.
	r := NewRegistry()
	if err := r.Load("/nonexistent/template/dir/" + strings.Repeat("x", 10)); err != nil {
		t.Fatalf("missing override dir should not error: %v", err)
	}
}

func TestRegistry_LoadEmbedded_ShipsTemplatesInTheBinary(t *testing.T) {
	// The regression this pins: the runtime image copies only the compiled
	// binary, so a disk-only template path meant every /v1/inbox/* request
	// answered 503 on every deployment.
	r := NewRegistry()
	if err := r.LoadEmbedded(); err != nil {
		t.Fatalf("LoadEmbedded failed: %v", err)
	}
	ids := r.IDs()
	if len(ids) == 0 {
		t.Fatalf("no embedded templates registered")
	}
	// generic-json is the template the documented inbox quickstart uses.
	if _, err := r.Get("generic-json"); err != nil {
		t.Errorf("generic-json not embedded; got IDs %v", ids)
	}
}

func TestRegistry_LoadEmbedded_CoversEveryTemplateOnDisk(t *testing.T) {
	// A new template added to the directory but not reachable through the
	// embed would be invisible at runtime while looking present in the repo.
	entries, err := os.ReadDir("../normalizer/templates")
	if err != nil {
		t.Fatalf("read template source dir: %v", err)
	}
	r := NewRegistry()
	if err := r.LoadEmbedded(); err != nil {
		t.Fatalf("LoadEmbedded failed: %v", err)
	}
	for _, e := range entries {
		if e.IsDir() || !isTemplateFile(e.Name()) {
			continue
		}
		id := strings.TrimSuffix(strings.TrimSuffix(e.Name(), ".yaml"), ".yml")
		if _, err := r.Get(id); err != nil {
			t.Errorf("template %s exists on disk but is not embedded", e.Name())
		}
	}
}

func TestRegistry_Load_OverridesAnEmbeddedTemplate(t *testing.T) {
	r := NewRegistry()
	if err := r.LoadEmbedded(); err != nil {
		t.Fatalf("LoadEmbedded failed: %v", err)
	}
	before, err := r.Get("generic-json")
	if err != nil {
		t.Fatalf("generic-json not embedded: %v", err)
	}

	dir := t.TempDir()
	writeTemplate(t, dir, "generic-json.yaml", `
vendor_name: Operator
product_name: Override
class_uid: 2001
field_map: {}
`)
	if err := r.Load(dir); err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	after, err := r.Get("generic-json")
	if err != nil {
		t.Fatalf("generic-json vanished after override: %v", err)
	}
	if after.VendorName != "Operator" {
		t.Errorf("on-disk template did not override embedded one: vendor = %q (was %q)",
			after.VendorName, before.VendorName)
	}
}

func TestRegistry_Get_UnknownReturnsErrTemplateNotFound(t *testing.T) {
	r := NewRegistry()
	_, err := r.Get("does-not-exist")
	if !errors.Is(err, ErrTemplateNotFound) {
		t.Errorf("err = %v, want ErrTemplateNotFound", err)
	}
}

func TestRegistry_Register_AllowsTestsToInjectInMemory(t *testing.T) {
	// Test-only path. Confirms tests can register a template without a
	// real YAML file on disk — used by handler_test and apply_test.
	r := NewRegistry()
	r.Register(&Template{ID: "synthetic", ClassUID: 2001, ClassName: "Security Finding"})
	got, err := r.Get("synthetic")
	if err != nil {
		t.Fatalf("Get(synthetic) failed: %v", err)
	}
	if got.ClassUID != 2001 {
		t.Errorf("registered template not returned: %#v", got)
	}
}
