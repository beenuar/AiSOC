package tables

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/osquery/osquery-go/plugin/table"
)

// BrowserExtensionsColumns returns the column schema for
// aisoc_browser_extensions.
func BrowserExtensionsColumns() []table.ColumnDefinition {
	return []table.ColumnDefinition{
		table.TextColumn("browser"),
		table.TextColumn("profile"),
		table.TextColumn("extension_id"),
		table.TextColumn("name"),
		table.TextColumn("version"),
		table.TextColumn("description"),
		table.IntegerColumn("enabled"),
	}
}

type chromeManifest struct {
	Name        string `json:"name"`
	Version     string `json:"version"`
	Description string `json:"description"`
}

// BrowserExtensionsGenerate walks Chrome/Chromium/Brave/Edge and Firefox
// profile directories for the running user and emits one row per installed
// browser extension.
func BrowserExtensionsGenerate(_ *struct{}) table.GenerateFunc {
	return func(ctx context.Context, queryContext table.QueryContext) ([]map[string]string, error) {
		home, err := os.UserHomeDir()
		if err != nil {
			log.Printf("aisoc_browser_extensions: cannot determine home dir: %v", err)
			return nil, nil
		}

		var rows []map[string]string
		rows = append(rows, chromeFamily(home, "Chrome", ".config/google-chrome")...)
		rows = append(rows, chromeFamily(home, "Chromium", ".config/chromium")...)
		rows = append(rows, chromeFamily(home, "Brave", ".config/BraveSoftware/Brave-Browser")...)
		rows = append(rows, chromeFamily(home, "Edge", ".config/microsoft-edge")...)
		// macOS paths
		rows = append(rows, chromeFamily(home, "Chrome", "Library/Application Support/Google/Chrome")...)
		rows = append(rows, chromeFamily(home, "Brave", "Library/Application Support/BraveSoftware/Brave-Browser")...)
		rows = append(rows, chromeFamily(home, "Edge", "Library/Application Support/Microsoft Edge")...)
		return rows, nil
	}
}

func chromeFamily(home, browser, relPath string) []map[string]string {
	base := filepath.Join(home, relPath)
	// profiles are directories directly under base: Default, Profile 1, …
	profiles, _ := filepath.Glob(filepath.Join(base, "*", "Extensions"))
	var rows []map[string]string
	for _, extRoot := range profiles {
		profile := filepath.Base(filepath.Dir(extRoot))
		extDirs, _ := filepath.Glob(filepath.Join(extRoot, "*"))
		for _, extDir := range extDirs {
			extID := filepath.Base(extDir)
			// Each extension may have multiple version sub-dirs; pick first.
			verDirs, _ := filepath.Glob(filepath.Join(extDir, "*"))
			for _, vdir := range verDirs {
				manifestPath := filepath.Join(vdir, "manifest.json")
				data, err := os.ReadFile(manifestPath)
				if err != nil {
					continue
				}
				var m chromeManifest
				if err := json.Unmarshal(data, &m); err != nil {
					continue
				}
				rows = append(rows, map[string]string{
					"browser":      browser,
					"profile":      profile,
					"extension_id": extID,
					"name":         m.Name,
					"version":      m.Version,
					"description":  fmt.Sprintf("%.200s", m.Description),
					"enabled":      "1",
				})
				break // only first version dir
			}
		}
	}
	return rows
}
