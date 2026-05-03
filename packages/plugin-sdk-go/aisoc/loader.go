package aisoc

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// LoaderError is returned when a plugin manifest cannot be loaded or validated.
type LoaderError struct {
	Path string
	Err  error
}

func (e *LoaderError) Error() string {
	return fmt.Sprintf("plugin loader error (%s): %v", e.Path, e.Err)
}

func (e *LoaderError) Unwrap() error { return e.Err }

// manifestFile is the conventional name for the plugin manifest.
const manifestFile = "aisoc-plugin.json"

// LoadManifest reads and validates the aisoc-plugin.json file in pluginDir.
//
// The JSON schema must include at minimum: id, name, version, plugin_type.
func LoadManifest(pluginDir string) (PluginManifest, error) {
	path := filepath.Join(pluginDir, manifestFile)
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return PluginManifest{}, &LoaderError{Path: path, Err: fmt.Errorf("manifest file not found")}
		}
		return PluginManifest{}, &LoaderError{Path: path, Err: err}
	}

	var m PluginManifest
	if err := json.Unmarshal(data, &m); err != nil {
		return PluginManifest{}, &LoaderError{Path: path, Err: fmt.Errorf("invalid JSON: %w", err)}
	}

	if err := validateManifest(m, path); err != nil {
		return PluginManifest{}, err
	}
	return m, nil
}

func validateManifest(m PluginManifest, path string) error {
	var missing []string
	if strings.TrimSpace(m.ID) == "" {
		missing = append(missing, "id")
	}
	if strings.TrimSpace(m.Name) == "" {
		missing = append(missing, "name")
	}
	if strings.TrimSpace(m.Version) == "" {
		missing = append(missing, "version")
	}
	if strings.TrimSpace(string(m.PluginType)) == "" {
		missing = append(missing, "plugin_type")
	}
	if len(missing) > 0 {
		return &LoaderError{
			Path: path,
			Err:  fmt.Errorf("missing required fields: %s", strings.Join(missing, ", ")),
		}
	}
	validTypes := map[PluginType]struct{}{
		PluginTypeEnricher:  {},
		PluginTypeAction:    {},
		PluginTypeConnector: {},
	}
	if _, ok := validTypes[m.PluginType]; !ok {
		return &LoaderError{
			Path: path,
			Err:  fmt.Errorf("invalid plugin_type %q; must be enricher, action, or connector", m.PluginType),
		}
	}
	return nil
}
