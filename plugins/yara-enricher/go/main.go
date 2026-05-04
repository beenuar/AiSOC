// Package main is the YARA file enricher reference implementation in Go.
//
// This is a reference skeleton for the AiSOC Go Plugin SDK. Production builds
// should compile against go-yara (github.com/hillu/go-yara/v4) which links
// against libyara. The skeleton uses an exec fallback to the `yara` CLI to
// avoid the cgo dependency in the reference build.
package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/beenuar/aisoc/plugin-sdk-go/aisoc"
)

// YaraEnricher implements aisoc.Enricher for file-based YARA scanning.
//
// The plugin treats the indicator value as a filesystem path. When the
// indicator type is "hash", a path lookup is attempted via Metadata["path"].
type YaraEnricher struct {
	aisoc.BasePlugin
}

func (y *YaraEnricher) Manifest() aisoc.PluginManifest {
	return aisoc.PluginManifest{
		ID:          "yara-enricher",
		Name:        "YARA File Enricher",
		Version:     "1.0.0",
		PluginType:  aisoc.PluginTypeEnricher,
		Description: "Scans files against a configurable set of YARA rules.",
		Author:      "AiSOC Core Team",
		Tags:        []string{"malware", "yara", "file-analysis", "enrichment"},
	}
}

func (y *YaraEnricher) Enrich(
	ctx context.Context,
	req aisoc.EnrichmentRequest,
	pctx aisoc.PluginContext,
) (aisoc.EnrichmentResult, error) {
	result := aisoc.EnrichmentResult{
		IndicatorType:  req.IndicatorType,
		IndicatorValue: req.IndicatorValue,
		Enrichments:    map[string]any{},
		Raw:            map[string]any{},
	}

	rulesDir, _ := pctx.Config["rules_dir"].(string)
	if rulesDir == "" {
		rulesDir = "/opt/aisoc/yara-rules"
	}

	target := req.IndicatorValue
	if target == "" {
		if path, ok := req.Metadata["path"].(string); ok {
			target = path
		}
	}
	if target == "" {
		return result, errors.New("indicator_value (or metadata.path) is required")
	}
	if _, err := os.Stat(target); err != nil {
		return result, fmt.Errorf("target file not accessible: %w", err)
	}

	rules, err := loadRulePaths(rulesDir)
	if err != nil {
		return result, fmt.Errorf("loading YARA rules: %w", err)
	}
	if len(rules) == 0 {
		result.Enrichments["matches"] = []string{}
		result.Enrichments["message"] = "no YARA rules loaded"
		return result, nil
	}

	matches, err := scan(ctx, rules, target)
	if err != nil {
		return result, fmt.Errorf("yara scan failed: %w", err)
	}

	result.Enrichments["target"] = target
	result.Enrichments["rules_dir"] = rulesDir
	result.Enrichments["rule_files"] = rules
	result.Enrichments["matches"] = matches
	result.Raw["match_count"] = len(matches)

	if len(matches) > 0 {
		mal := true
		conf := 0.85
		result.Malicious = &mal
		result.Confidence = &conf
		result.Tags = append(result.Tags, "yara-match", "malware")
		result.Tags = append(result.Tags, matches...)
	} else {
		mal := false
		conf := 0.6
		result.Malicious = &mal
		result.Confidence = &conf
	}

	return result, nil
}

func loadRulePaths(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var paths []string
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		ext := strings.ToLower(filepath.Ext(entry.Name()))
		if ext == ".yar" || ext == ".yara" {
			paths = append(paths, filepath.Join(dir, entry.Name()))
		}
	}
	return paths, nil
}

func scan(ctx context.Context, rules []string, target string) ([]string, error) {
	bin, err := exec.LookPath("yara")
	if err != nil {
		return nil, errors.New(
			"yara CLI not available; install yara or build with -tags=cgo against go-yara",
		)
	}
	args := []string{"-w", "-N"}
	args = append(args, rules...)
	args = append(args, target)
	cmd := exec.CommandContext(ctx, bin, args...)
	out, err := cmd.Output()
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) && ee.ExitCode() == 1 {
			return nil, nil
		}
		return nil, err
	}
	var matches []string
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) > 0 {
			matches = append(matches, fields[0])
		}
	}
	return matches, nil
}

func main() {
	registry := aisoc.NewRegistry()
	if err := registry.Register(&YaraEnricher{}); err != nil {
		panic(err)
	}
	fmt.Println("yara-enricher reference plugin loaded")
}
