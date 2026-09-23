package inbox

import (
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"

	"github.com/rs/zerolog/log"
	"gopkg.in/yaml.v3"

	"github.com/beenuar/aisoc/services/ingest/internal/normalizer"
)

// ErrTemplateNotFound is returned when a token resolves to a template_id
// that wasn't shipped with the running ingest binary. Handlers translate
// this to 503 — the URL is valid but the running version of the service
// can't process it; the operator needs to upgrade the deployment or pick
// a different template.
var ErrTemplateNotFound = errors.New("inbox template not registered")

// Template defines how a vendor-specific JSON payload maps onto an OCSF
// event. Each YAML file in services/ingest/internal/normalizer/templates/
// produces one Template; the filename stem (without .yaml) is the
// template_id stored in tenant_inbox_tokens.
//
// The mapping language is intentionally minimal — dot-path source field
// to dot-path OCSF field, plus a small set of severity translations and
// constants — because the goal is "stamp out webhook adapters in
// minutes" not "build a general-purpose ETL DSL". Anything more complex
// belongs in a real connector under services/connectors/app/connectors/.
type Template struct {
	// ID is the filename stem — must match tenant_inbox_tokens.template_id.
	ID string `yaml:"id"`
	// VendorName / ProductName populate ocsf.metadata.product so
	// downstream queries can filter by vendor without parsing tenant_uid.
	VendorName  string `yaml:"vendor_name"`
	ProductName string `yaml:"product_name"`

	// OCSFClass identifies the destination OCSF class (Authentication,
	// Security Finding, etc). We carry both the numeric class_uid and the
	// human-readable class_name to keep the published event self-describing.
	ClassUID  int    `yaml:"class_uid"`
	ClassName string `yaml:"class_name"`

	// Activity overrides the default activity_id (1 = "Create") — useful
	// for auth events where vendor traffic is mostly login/logout.
	ActivityID int `yaml:"activity_id,omitempty"`

	// FieldMap projects vendor JSON paths onto OCSF JSON paths. Both
	// sides use dot notation; arrays are addressed with `[N]`.
	FieldMap map[string]string `yaml:"field_map"`

	// SeverityMap translates vendor severity strings (case-insensitive)
	// to OCSF severity_id 0-6. The key is normalised to lower-case at
	// load time.
	SeverityMap map[string]int `yaml:"severity_map,omitempty"`

	// SeverityField — JSON path to the vendor's severity string. Default
	// "severity"; templates override for vendors that use "priority"
	// (PagerDuty), "level" (Cloudflare), etc.
	SeverityField string `yaml:"severity_field,omitempty"`

	// TimeField — JSON path to the vendor's event time. Default "time";
	// templates override for vendors that use "timestamp", "@timestamp",
	// "created_at", etc.
	TimeField string `yaml:"time_field,omitempty"`

	// MessageField — JSON path the wizard's "what happened" line is
	// pulled from. Default "message".
	MessageField string `yaml:"message_field,omitempty"`

	// Constants — fields stamped onto every event regardless of payload.
	// Useful for vendor-specific tags ("source": "pagerduty.events.v2")
	// that downstream detection content keys on.
	Constants map[string]any `yaml:"constants,omitempty"`
}

// Registry holds the loaded templates indexed by ID.
//
// Templates are loaded once at startup; the registry is read-only after
// that, so we can serve concurrent webhooks without a mutex.
type Registry struct {
	mu        sync.RWMutex
	templates map[string]*Template
}

// NewRegistry returns an empty registry. Call Load() to populate from disk.
func NewRegistry() *Registry {
	return &Registry{templates: make(map[string]*Template)}
}

// parse turns one template file's bytes into a registered Template.
// Returns false when the YAML is malformed, so one typo cannot take down
// the whole ingest service.
func (r *Registry) parse(name string, raw []byte) bool {
	t := &Template{}
	if err := yaml.Unmarshal(raw, t); err != nil {
		log.Warn().Err(err).Str("template", name).Msg("inbox: malformed template YAML")
		return false
	}
	// Default the ID to the filename stem — operators usually leave
	// the explicit `id:` blank and rely on the convention.
	if t.ID == "" {
		t.ID = strings.TrimSuffix(strings.TrimSuffix(name, ".yaml"), ".yml")
	}
	// Normalise severity keys.
	if len(t.SeverityMap) > 0 {
		normalised := make(map[string]int, len(t.SeverityMap))
		for k, v := range t.SeverityMap {
			normalised[strings.ToLower(strings.TrimSpace(k))] = v
		}
		t.SeverityMap = normalised
	}

	r.mu.Lock()
	r.templates[t.ID] = t
	r.mu.Unlock()
	return true
}

func isTemplateFile(name string) bool {
	return strings.HasSuffix(name, ".yaml") || strings.HasSuffix(name, ".yml")
}

// LoadEmbedded registers the templates compiled into the binary.
//
// This is the load that must always succeed: the on-disk path below is an
// operator override, and for most of this service's life it pointed at a
// directory the container image never contained, so /v1/inbox/* answered 503
// for every template on every deployment.
func (r *Registry) LoadEmbedded() error {
	entries, err := normalizer.InboxTemplates.ReadDir(normalizer.InboxTemplateDir)
	if err != nil {
		return fmt.Errorf("inbox: read embedded templates: %w", err)
	}

	loaded := 0
	for _, e := range entries {
		if e.IsDir() || !isTemplateFile(e.Name()) {
			continue
		}
		raw, err := normalizer.InboxTemplates.ReadFile(path.Join(normalizer.InboxTemplateDir, e.Name()))
		if err != nil {
			log.Warn().Err(err).Str("template", e.Name()).Msg("inbox: skipping unreadable embedded template")
			continue
		}
		if r.parse(e.Name(), raw) {
			loaded++
		}
	}
	log.Info().Int("count", loaded).Msg("inbox: embedded templates loaded")
	if loaded == 0 {
		// The embed directive matched nothing, which means the binary shipped
		// without the templates it is supposed to carry. Saying so loudly is
		// the whole point of this change.
		return errors.New("inbox: no embedded templates found in the binary")
	}
	return nil
}

// Load reads every *.yaml file in dir and registers it as a template,
// overriding any embedded template of the same ID.
//
// Files with malformed YAML are logged and skipped so a typo in one
// template doesn't take down the whole ingest service. A missing directory
// is not an error: the embedded set is the baseline and this is the operator
// override on top of it.
func (r *Registry) Load(dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			log.Debug().Str("dir", dir).Msg("inbox: no on-disk template overrides")
			return nil
		}
		return fmt.Errorf("inbox: read template dir %s: %w", dir, err)
	}

	loaded := 0
	for _, e := range entries {
		if e.IsDir() || !isTemplateFile(e.Name()) {
			continue
		}
		p := filepath.Join(dir, e.Name())
		raw, err := os.ReadFile(p)
		if err != nil {
			log.Warn().Err(err).Str("path", p).Msg("inbox: skipping unreadable template")
			continue
		}
		if r.parse(e.Name(), raw) {
			loaded++
		}
	}
	log.Info().Int("count", loaded).Str("dir", dir).Msg("inbox: templates loaded")
	return nil
}

// Get returns a template by ID, or ErrTemplateNotFound.
func (r *Registry) Get(id string) (*Template, error) {
	r.mu.RLock()
	t, ok := r.templates[id]
	r.mu.RUnlock()
	if !ok {
		return nil, ErrTemplateNotFound
	}
	return t, nil
}

// Register inserts a template programmatically. Used by tests.
func (r *Registry) Register(t *Template) {
	r.mu.Lock()
	r.templates[t.ID] = t
	r.mu.Unlock()
}

// IDs returns the registered template IDs (for debug/introspection).
func (r *Registry) IDs() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]string, 0, len(r.templates))
	for k := range r.templates {
		out = append(out, k)
	}
	return out
}
