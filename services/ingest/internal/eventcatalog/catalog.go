// Package eventcatalog loads the event classification catalogue at boot and
// answers "what does this vendor event type mean" for every normalized event.
//
// The catalogue is a reviewed data file per source, mapping the vendor's own
// event type onto a normalized action, a sensitivity on the platform's
// five-tier ladder, and an optional ATT&CK hint. The authoritative copies
// live at `schemas/event_catalog/<source>.yaml`; the copies under `catalog/`
// here are byte-identical and are what the binary carries.
//
// Why a vendored copy rather than reading `schemas/` at run time
// --------------------------------------------------------------
// `go:embed` cannot reach above its own package, and the alternative —
// reading the directory from disk at a configurable path — is a failure this
// service has already shipped once: the webhook templates were read from
// `/app/templates`, a path the Dockerfile never populated, so every
// deployment answered 503 for every template behind a startup warning
// nothing was watching (see templates.go). Embedding removes the class
// rather than the instance, and `scripts/check_event_catalog.py` holds the
// two directories byte-identical in both directions so the copy cannot
// drift from the file a reviewer edits.
//
// Why a sensitivity does not change a severity
// --------------------------------------------
// Sensitivity says how security-relevant an event *type* is. The vendor's
// own severity on the record, and the OCSF class, still decide whether
// fusion promotes it. Letting a `critical` sensitivity force an alert would
// make this data file able to flood a queue from a one-line edit, and the
// promotion contract belongs where it already is. The classification rides
// on the event for detections, hunts and triage to read.
package eventcatalog

import (
	"embed"
	"fmt"
	"io/fs"
	"path"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

//go:embed catalog/*.yaml
var files embed.FS

const catalogDir = "catalog"

// Sensitivity is how security-relevant an event type is, on the same
// five-tier ladder the rest of the platform uses.
type Sensitivity string

const (
	SensitivityInfo     Sensitivity = "info"
	SensitivityLow      Sensitivity = "low"
	SensitivityMedium   Sensitivity = "medium"
	SensitivityHigh     Sensitivity = "high"
	SensitivityCritical Sensitivity = "critical"
)

// Sensitivities is the closed set, lowest first. A value outside it is a
// load error rather than a silently-kept string: the ladder is five tiers
// everywhere in this platform and a sixth would be invisible until a query
// filtered on it and found nothing.
var Sensitivities = []Sensitivity{
	SensitivityInfo, SensitivityLow, SensitivityMedium, SensitivityHigh, SensitivityCritical,
}

// Classification is one catalogue entry.
type Classification struct {
	Action      string      `yaml:"action"`
	Sensitivity Sensitivity `yaml:"sensitivity"`
	ATTACK      []string    `yaml:"attack,omitempty"`
}

// sourceFile is the on-disk shape of one `<source>.yaml`.
type sourceFile struct {
	Source string `yaml:"source"`
	// EventTypePath is where the vendor's event type lives on its own
	// record, in the dotted form `a.b` with `a[].b` for a list.
	EventTypePath string `yaml:"event_type_path"`
	// FixtureRequires are keys a record must also carry for the gate to
	// read it as this source's event. `action` alone appears on records
	// from several sources and in unrelated test dictionaries.
	FixtureRequires []string                  `yaml:"fixture_requires,omitempty"`
	FixtureFiles    []string                  `yaml:"fixture_files"`
	Events          map[string]Classification `yaml:"events"`
	// Unclassified is event type -> why it is deliberately not classified.
	// Read here as well as by the gate so a loaded catalogue can say "this
	// type is known and deliberately unclassified", which is a different
	// answer from "never seen".
	Unclassified map[string]string `yaml:"unclassified"`
}

// Catalog is every source's classifications, loaded.
type Catalog struct {
	bySource     map[string]map[string]Classification
	unclassified map[string]map[string]string
	paths        map[string]string
}

// Load reads the embedded catalogue. It returns an error rather than a
// partial catalogue: a source that failed to parse would answer "never seen"
// for every one of its event types, which is indistinguishable from a source
// nobody has written a catalogue for.
func Load() (*Catalog, error) {
	entries, err := fs.ReadDir(files, catalogDir)
	if err != nil {
		return nil, fmt.Errorf("reading the embedded catalogue: %w", err)
	}
	c := &Catalog{
		bySource:     map[string]map[string]Classification{},
		unclassified: map[string]map[string]string{},
		paths:        map[string]string{},
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".yaml") {
			continue
		}
		raw, err := files.ReadFile(path.Join(catalogDir, entry.Name()))
		if err != nil {
			return nil, fmt.Errorf("reading %s: %w", entry.Name(), err)
		}
		var parsed sourceFile
		if err := yaml.Unmarshal(raw, &parsed); err != nil {
			return nil, fmt.Errorf("parsing %s: %w", entry.Name(), err)
		}
		if parsed.Source == "" {
			return nil, fmt.Errorf("%s declares no source", entry.Name())
		}
		if parsed.EventTypePath == "" {
			return nil, fmt.Errorf("%s declares no event_type_path, so nothing can find its event type", entry.Name())
		}
		if existing, dup := c.paths[parsed.Source]; dup {
			return nil, fmt.Errorf("two catalogue files declare source %q (%s and %s)", parsed.Source, existing, entry.Name())
		}
		for eventType, classification := range parsed.Events {
			if !validSensitivity(classification.Sensitivity) {
				return nil, fmt.Errorf(
					"%s: %q declares sensitivity %q, which is not one of the five tiers",
					entry.Name(), eventType, classification.Sensitivity,
				)
			}
			if classification.Action == "" {
				return nil, fmt.Errorf("%s: %q declares no normalized action", entry.Name(), eventType)
			}
		}
		c.bySource[parsed.Source] = parsed.Events
		c.unclassified[parsed.Source] = parsed.Unclassified
		c.paths[parsed.Source] = parsed.EventTypePath
	}
	if len(c.bySource) == 0 {
		return nil, fmt.Errorf("the embedded catalogue is empty — refusing to load a catalogue that classifies nothing")
	}
	return c, nil
}

func validSensitivity(value Sensitivity) bool {
	for _, s := range Sensitivities {
		if s == value {
			return true
		}
	}
	return false
}

// Lookup returns the classification for one source's event type.
//
// The second return distinguishes the three answers that matter: a hit, a
// type the catalogue lists as deliberately unclassified, and one the
// catalogue has never seen. Only the third is worth a warning on the event.
func (c *Catalog) Lookup(source, eventType string) (Classification, Status) {
	if c == nil {
		return Classification{}, StatusNoCatalog
	}
	events, ok := c.bySource[source]
	if !ok {
		return Classification{}, StatusNoCatalog
	}
	if classification, hit := events[eventType]; hit {
		return classification, StatusClassified
	}
	if _, excused := c.unclassified[source][eventType]; excused {
		return Classification{}, StatusDeliberatelyUnclassified
	}
	return Classification{}, StatusUnknown
}

// Status is which of the three answers Lookup gave.
type Status string

const (
	StatusClassified Status = "classified"
	// StatusDeliberatelyUnclassified: somebody looked and decided.
	StatusDeliberatelyUnclassified Status = "unclassified"
	// StatusUnknown: this source has a catalogue and this type is not in
	// it. The only one worth telling an operator about, because it is how
	// the catalogue learns it is behind the vendor.
	StatusUnknown Status = "unknown"
	// StatusNoCatalog: no catalogue for this source at all.
	StatusNoCatalog Status = "no_catalog"
)

// EventTypePath is where a source keeps its event type, as declared.
func (c *Catalog) EventTypePath(source string) (string, bool) {
	if c == nil {
		return "", false
	}
	p, ok := c.paths[source]
	return p, ok
}

// Sources is every source with a catalogue, sorted.
func (c *Catalog) Sources() []string {
	if c == nil {
		return nil
	}
	out := make([]string, 0, len(c.bySource))
	for source := range c.bySource {
		out = append(out, source)
	}
	sort.Strings(out)
	return out
}

// Size is the total number of classified event types, for the boot log.
func (c *Catalog) Size() int {
	if c == nil {
		return 0
	}
	total := 0
	for _, events := range c.bySource {
		total += len(events)
	}
	return total
}

// EventType reads the vendor's event type out of a record, using the path
// the source declared.
//
// Supports one list hop (`events[].name`), which is the only shape any
// source here needs: Workspace bundles several events under one activity.
// A deeper grammar would be a parser nothing in the corpus exercises.
func EventType(record map[string]any, declaredPath string) (string, bool) {
	if record == nil || declaredPath == "" {
		return "", false
	}
	var cur any = record
	for _, segment := range strings.Split(declaredPath, ".") {
		listHop := strings.HasSuffix(segment, "[]")
		key := strings.TrimSuffix(segment, "[]")

		asMap, ok := cur.(map[string]any)
		if !ok {
			return "", false
		}
		cur = asMap[key]

		if listHop {
			items, ok := cur.([]any)
			if !ok || len(items) == 0 {
				return "", false
			}
			// The first element drives the classification, matching the
			// connectors, which already pick `events[0]` to drive severity
			// and the title.
			cur = items[0]
		}
	}
	value, ok := cur.(string)
	if !ok {
		return "", false
	}
	value = strings.TrimSpace(value)
	return value, value != ""
}
