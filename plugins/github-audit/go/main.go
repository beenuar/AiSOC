// Package main is the GitHub Audit Log connector reference implementation in Go.
//
// This file mirrors the Python plugin.py and demonstrates cross-language SDK
// parity. The AiSOC runtime currently invokes plugin.py at execution time;
// this Go reference is intended for operators who prefer to ship native
// binary plugins.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/beenuar/aisoc/plugin-sdk-go/aisoc"
)

// GitHubAuditConnector implements aisoc.Connector against the GitHub Audit Log API.
type GitHubAuditConnector struct {
	aisoc.BasePlugin

	httpClient *http.Client
}

func (g *GitHubAuditConnector) Manifest() aisoc.PluginManifest {
	return aisoc.PluginManifest{
		ID:          "github-audit",
		Name:        "GitHub Audit Log Connector",
		Version:     "1.0.0",
		PluginType:  aisoc.PluginTypeConnector,
		Description: "Pulls GitHub org audit log events and secret-scanning alerts.",
		Author:      "AiSOC Core Team",
		Tags:        []string{"vcs", "github", "audit", "supply-chain"},
	}
}

func (g *GitHubAuditConnector) OnLoad(ctx context.Context, pctx aisoc.PluginContext) error {
	g.httpClient = &http.Client{Timeout: 30 * time.Second}
	return nil
}

func (g *GitHubAuditConnector) TestConnection(ctx context.Context, pctx aisoc.PluginContext) (bool, error) {
	if err := g.checkConfig(pctx); err != nil {
		return false, err
	}
	req, err := g.newRequest(ctx, pctx, "GET", fmt.Sprintf("/orgs/%s", pctx.Config["org"]))
	if err != nil {
		return false, err
	}
	resp, err := g.httpClient.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return false, errors.New("github auth: " + resp.Status)
	}
	return true, nil
}

func (g *GitHubAuditConnector) FetchEvents(
	ctx context.Context,
	pctx aisoc.PluginContext,
	since string,
) (<-chan map[string]any, error) {
	out := make(chan map[string]any)
	go func() {
		defer close(out)
		if err := g.checkConfig(pctx); err != nil {
			out <- map[string]any{"error": err.Error()}
			return
		}
		path := fmt.Sprintf("/orgs/%s/audit-log?per_page=100", pctx.Config["org"])
		if since != "" {
			path += "&after=" + since
		}
		req, err := g.newRequest(ctx, pctx, "GET", path)
		if err != nil {
			out <- map[string]any{"error": err.Error()}
			return
		}
		resp, err := g.httpClient.Do(req)
		if err != nil {
			out <- map[string]any{"error": err.Error()}
			return
		}
		defer resp.Body.Close()
		var events []map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&events)
		for _, e := range events {
			out <- e
		}
	}()
	return out, nil
}

func (g *GitHubAuditConnector) checkConfig(pctx aisoc.PluginContext) error {
	for _, k := range []string{"org", "token"} {
		if pctx.Config[k] == nil {
			return fmt.Errorf("missing config key: %s", k)
		}
	}
	return nil
}

func (g *GitHubAuditConnector) newRequest(
	ctx context.Context,
	pctx aisoc.PluginContext,
	method, path string,
) (*http.Request, error) {
	base := "https://api.github.com"
	if v, ok := pctx.Config["base_url"].(string); ok && v != "" {
		base = strings.TrimRight(v, "/")
	}
	req, err := http.NewRequestWithContext(ctx, method, base+path, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+pctx.Config["token"].(string))
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	return req, nil
}

func main() {
	registry := aisoc.NewRegistry()
	if err := registry.Register(&GitHubAuditConnector{}); err != nil {
		panic(err)
	}
	fmt.Println("github-audit reference plugin loaded")
}
