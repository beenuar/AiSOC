// Package main is the GitLab audit connector reference implementation in Go.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/beenuar/aisoc/plugin-sdk-go/aisoc"
)

// GitLabConnector implements aisoc.Connector for the GitLab audit events API.
type GitLabConnector struct {
	aisoc.BasePlugin

	httpClient *http.Client
}

func (g *GitLabConnector) Manifest() aisoc.PluginManifest {
	return aisoc.PluginManifest{
		ID:          "gitlab-audit",
		Name:        "GitLab Audit Connector",
		Version:     "1.0.0",
		PluginType:  aisoc.PluginTypeConnector,
		Description: "Pulls audit events from GitLab at instance, group, or project scope.",
		Author:      "AiSOC Core Team",
		Tags:        []string{"identity", "gitlab", "audit", "devsecops", "connector"},
	}
}

func (g *GitLabConnector) OnLoad(ctx context.Context, pctx aisoc.PluginContext) error {
	g.httpClient = &http.Client{Timeout: 30 * time.Second}
	return nil
}

func (g *GitLabConnector) baseURL(pctx aisoc.PluginContext) string {
	base, _ := pctx.Config["base_url"].(string)
	if base == "" {
		base = "https://gitlab.com"
	}
	return strings.TrimRight(base, "/")
}

func (g *GitLabConnector) auditPath(pctx aisoc.PluginContext) (string, error) {
	scope, _ := pctx.Config["scope"].(string)
	scopeID, _ := pctx.Config["scope_id"].(string)
	switch scope {
	case "group":
		if scopeID == "" {
			return "", errors.New("scope_id required for group scope")
		}
		return "/api/v4/groups/" + scopeID + "/audit_events", nil
	case "project":
		if scopeID == "" {
			return "", errors.New("scope_id required for project scope")
		}
		return "/api/v4/projects/" + scopeID + "/audit_events", nil
	default:
		return "/api/v4/audit_events", nil
	}
}

func (g *GitLabConnector) get(
	ctx context.Context,
	pctx aisoc.PluginContext,
	path string,
	params url.Values,
) ([]byte, error) {
	token, _ := pctx.Config["token"].(string)
	if token == "" {
		return nil, errors.New("token is required")
	}
	full := g.baseURL(pctx) + path
	if len(params) > 0 {
		full += "?" + params.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, full, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("PRIVATE-TOKEN", token)
	req.Header.Set("Accept", "application/json")
	resp, err := g.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		return body, errors.New("gitlab: " + resp.Status)
	}
	return body, nil
}

func (g *GitLabConnector) TestConnection(
	ctx context.Context,
	pctx aisoc.PluginContext,
) (bool, error) {
	path, err := g.auditPath(pctx)
	if err != nil {
		return false, err
	}
	if _, err := g.get(ctx, pctx, path, url.Values{"per_page": []string{"1"}}); err != nil {
		return false, err
	}
	return true, nil
}

func (g *GitLabConnector) FetchEvents(
	ctx context.Context,
	pctx aisoc.PluginContext,
	since string,
) (<-chan map[string]any, error) {
	out := make(chan map[string]any)
	path, err := g.auditPath(pctx)
	if err != nil {
		close(out)
		return out, err
	}
	if since == "" {
		since = time.Now().Add(-15 * time.Minute).UTC().Format(time.RFC3339)
	}
	go func() {
		defer close(out)
		params := url.Values{
			"created_after": []string{since},
			"per_page":      []string{"100"},
		}
		body, err := g.get(ctx, pctx, path, params)
		if err != nil {
			out <- map[string]any{"error": err.Error()}
			return
		}
		var events []map[string]any
		if err := json.Unmarshal(body, &events); err != nil {
			out <- map[string]any{"error": err.Error()}
			return
		}
		for _, ev := range events {
			ev["_aisoc_source"] = "gitlab-audit"
			out <- ev
		}
	}()
	return out, nil
}

func main() {
	registry := aisoc.NewRegistry()
	if err := registry.Register(&GitLabConnector{}); err != nil {
		panic(err)
	}
	fmt.Println("gitlab-audit reference plugin loaded")
}
