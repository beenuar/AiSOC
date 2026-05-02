// Package attck provides a lightweight MITRE ATT&CK technique index
// built from the STIX 2.1 enterprise bundle.
package attck

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
)

const (
	cdnURL         = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
	cacheTTLHours  = 24
)

// Technique holds key ATT&CK technique fields.
type Technique struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	TacticIDs   []string `json:"tactic_ids"`
	TacticNames []string `json:"tactic_names"`
	Platforms   []string `json:"platforms"`
	URL         string   `json:"url"`
}

var (
	mu           sync.RWMutex
	techniques   = map[string]*Technique{}
	tacticMap    = map[string]string{} // phase_name → display_name
	loaded       bool
	loadedAt     time.Time
)

// Loaded returns true if the corpus has been successfully loaded.
func Loaded() bool {
	mu.RLock()
	defer mu.RUnlock()
	return loaded
}

// TechniqueCount returns the number of loaded techniques.
func TechniqueCount() int {
	mu.RLock()
	defer mu.RUnlock()
	return len(techniques)
}

// Lookup returns technique metadata for the given ATT&CK ID (e.g. "T1059").
// Returns nil if not found.
func Lookup(techniqueID string) *Technique {
	mu.RLock()
	defer mu.RUnlock()
	return techniques[techniqueID]
}

// LookupAll returns all loaded techniques.
func LookupAll() map[string]*Technique {
	mu.RLock()
	defer mu.RUnlock()
	out := make(map[string]*Technique, len(techniques))
	for k, v := range techniques {
		out[k] = v
	}
	return out
}

// Load loads (or reloads) the ATT&CK corpus from localPath or CDN.
func Load(localPath string) error {
	mu.Lock()
	defer mu.Unlock()

	// Honour cache TTL
	if loaded && time.Since(loadedAt) < cacheTTLHours*time.Hour {
		return nil
	}

	bundle, err := readBundle(localPath)
	if err != nil {
		log.Warn().Err(err).Msg("ATT&CK local bundle unavailable; downloading from CDN")
		bundle, err = downloadBundle(cdnURL)
		if err != nil {
			return fmt.Errorf("attck: failed to load corpus: %w", err)
		}
		if saveErr := saveBundle(localPath, bundle); saveErr != nil {
			log.Warn().Err(saveErr).Str("path", localPath).Msg("Failed to cache ATT&CK bundle locally")
		}
	}

	parseBundle(bundle)
	loaded = true
	loadedAt = time.Now()
	log.Info().
		Int("techniques", len(techniques)).
		Int("tactics", len(tacticMap)).
		Msg("MITRE ATT&CK corpus loaded")
	return nil
}

// ─── Internal helpers ─────────────────────────────────────────────────────────

type stixBundle struct {
	Objects []map[string]interface{} `json:"objects"`
}

func readBundle(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(f)
}

func downloadBundle(url string) ([]byte, error) {
	client := &http.Client{Timeout: 120 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("CDN returned %d", resp.StatusCode)
	}
	return io.ReadAll(resp.Body)
}

func saveBundle(path string, data []byte) error {
	if err := os.MkdirAll(dirOf(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

func dirOf(path string) string {
	idx := strings.LastIndex(path, "/")
	if idx < 0 {
		return "."
	}
	return path[:idx]
}

func parseBundle(raw []byte) {
	var bundle stixBundle
	if err := json.Unmarshal(raw, &bundle); err != nil {
		log.Error().Err(err).Msg("Failed to parse ATT&CK STIX bundle")
		return
	}

	// Clear previous state
	techniques = map[string]*Technique{}
	tacticMap = map[string]string{}

	// Index all objects by STIX ID
	byID := make(map[string]map[string]interface{}, len(bundle.Objects))
	for _, obj := range bundle.Objects {
		if id, ok := obj["id"].(string); ok {
			byID[id] = obj
		}
	}

	// Build tactic phase → name map
	for _, obj := range bundle.Objects {
		if t, ok := obj["type"].(string); !ok || t != "x-mitre-tactic" {
			continue
		}
		shortname, _ := obj["x_mitre_shortname"].(string)
		name, _ := obj["name"].(string)
		if shortname != "" && name != "" {
			tacticMap[shortname] = name
		}
	}

	// Build technique index
	for _, obj := range bundle.Objects {
		t, ok := obj["type"].(string)
		if !ok || t != "attack-pattern" {
			continue
		}
		// Skip deprecated/revoked
		if dep, ok := obj["x_mitre_deprecated"].(bool); ok && dep {
			continue
		}
		if rev, ok := obj["revoked"].(bool); ok && rev {
			continue
		}

		techID := extractAttckID(obj)
		if techID == "" {
			continue
		}

		name, _ := obj["name"].(string)
		desc, _ := obj["description"].(string)
		if len(desc) > 1000 {
			desc = desc[:1000]
		}

		tacticIDs, tacticNames := extractTactics(obj)
		platforms := extractStringSlice(obj, "x_mitre_platforms")
		url := extractAttckURL(obj)

		techniques[techID] = &Technique{
			ID:          techID,
			Name:        name,
			Description: desc,
			TacticIDs:   tacticIDs,
			TacticNames: tacticNames,
			Platforms:   platforms,
			URL:         url,
		}
	}
}

func extractAttckID(obj map[string]interface{}) string {
	refs, ok := obj["external_references"].([]interface{})
	if !ok {
		return ""
	}
	for _, r := range refs {
		ref, ok := r.(map[string]interface{})
		if !ok {
			continue
		}
		if src, _ := ref["source_name"].(string); src == "mitre-attack" {
			if id, ok := ref["external_id"].(string); ok {
				return id
			}
		}
	}
	return ""
}

func extractAttckURL(obj map[string]interface{}) string {
	refs, ok := obj["external_references"].([]interface{})
	if !ok {
		return ""
	}
	for _, r := range refs {
		ref, ok := r.(map[string]interface{})
		if !ok {
			continue
		}
		if src, _ := ref["source_name"].(string); src == "mitre-attack" {
			if u, ok := ref["url"].(string); ok {
				return u
			}
		}
	}
	return ""
}

func extractTactics(obj map[string]interface{}) ([]string, []string) {
	phases, ok := obj["kill_chain_phases"].([]interface{})
	if !ok {
		return nil, nil
	}
	var ids, names []string
	for _, p := range phases {
		phase, ok := p.(map[string]interface{})
		if !ok {
			continue
		}
		kcName, _ := phase["kill_chain_name"].(string)
		if kcName != "mitre-attack" {
			continue
		}
		phaseName, _ := phase["phase_name"].(string)
		if phaseName == "" {
			continue
		}
		ids = append(ids, phaseName)
		if displayName, ok := tacticMap[phaseName]; ok {
			names = append(names, displayName)
		} else {
			names = append(names, phaseName)
		}
	}
	return ids, names
}

func extractStringSlice(obj map[string]interface{}, key string) []string {
	raw, ok := obj[key].([]interface{})
	if !ok {
		return nil
	}
	out := make([]string, 0, len(raw))
	for _, v := range raw {
		if s, ok := v.(string); ok {
			out = append(out, s)
		}
	}
	return out
}
