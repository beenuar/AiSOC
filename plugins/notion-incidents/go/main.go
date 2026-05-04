// Package main is the Notion incidents sync action reference implementation in Go.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/beenuar/aisoc/plugin-sdk-go/aisoc"
)

const apiBase = "https://api.notion.com/v1"

// NotionAction implements aisoc.Action for syncing incidents to a Notion database.
type NotionAction struct {
	aisoc.BasePlugin

	httpClient *http.Client
}

func (n *NotionAction) Manifest() aisoc.PluginManifest {
	return aisoc.PluginManifest{
		ID:          "notion-incidents",
		Name:        "Notion Incidents Sync",
		Version:     "1.0.0",
		PluginType:  aisoc.PluginTypeAction,
		Description: "Syncs AiSOC incidents to a Notion database for runbook archives.",
		Author:      "AiSOC Core Team",
		Tags:        []string{"collaboration", "notion", "incidents", "postmortem", "action"},
	}
}

func (n *NotionAction) OnLoad(_ context.Context, _ aisoc.PluginContext) error {
	n.httpClient = &http.Client{Timeout: 30 * time.Second}
	return nil
}

func (n *NotionAction) SupportedActions() []string {
	return []string{
		"create_incident_page",
		"update_incident_page",
		"append_post_mortem",
	}
}

func (n *NotionAction) Execute(
	ctx context.Context,
	req aisoc.ActionRequest,
	pctx aisoc.PluginContext,
) (aisoc.ActionResult, error) {
	result := aisoc.ActionResult{
		ActionID: req.ActionID,
		DryRun:   req.DryRun,
		Details:  map[string]any{},
	}

	token, _ := pctx.Config["api_token"].(string)
	dbID, _ := pctx.Config["database_id"].(string)
	if token == "" || dbID == "" {
		result.Error = "api_token and database_id are required"
		return result, errors.New(result.Error)
	}
	notionVersion, _ := pctx.Config["notion_version"].(string)
	if notionVersion == "" {
		notionVersion = "2022-06-28"
	}

	if req.DryRun {
		result.Success = true
		result.Summary = "dry-run: no Notion API call made"
		result.Details["action"] = req.ActionID
		return result, nil
	}

	switch req.ActionID {
	case "create_incident_page":
		body := map[string]any{
			"parent":     map[string]any{"database_id": dbID},
			"properties": buildProps(req.Params),
			"children":   buildChildren(req.Params),
		}
		raw, err := n.do(ctx, token, notionVersion, http.MethodPost, "/pages", body)
		if err != nil {
			result.Error = err.Error()
			return result, err
		}
		var parsed map[string]any
		_ = json.Unmarshal(raw, &parsed)
		pageID, _ := parsed["id"].(string)
		result.Success = true
		result.Summary = "created Notion page " + pageID
		result.Details["page"] = parsed
		return result, nil

	case "update_incident_page":
		pageID, _ := req.Params["page_id"].(string)
		if pageID == "" {
			result.Error = "page_id is required"
			return result, errors.New(result.Error)
		}
		body := map[string]any{"properties": buildProps(req.Params)}
		raw, err := n.do(
			ctx, token, notionVersion, http.MethodPatch, "/pages/"+pageID, body,
		)
		if err != nil {
			result.Error = err.Error()
			return result, err
		}
		var parsed map[string]any
		_ = json.Unmarshal(raw, &parsed)
		result.Success = true
		result.Summary = "updated Notion page " + pageID
		result.Details["page"] = parsed
		return result, nil

	case "append_post_mortem":
		pageID, _ := req.Params["page_id"].(string)
		text, _ := req.Params["post_mortem"].(string)
		if pageID == "" || text == "" {
			result.Error = "page_id and post_mortem text required"
			return result, errors.New(result.Error)
		}
		body := map[string]any{
			"children": []map[string]any{
				{
					"object": "block",
					"type":   "heading_2",
					"heading_2": map[string]any{
						"rich_text": []map[string]any{
							{"type": "text", "text": map[string]any{"content": "Post-mortem"}},
						},
					},
				},
				{
					"object": "block",
					"type":   "paragraph",
					"paragraph": map[string]any{
						"rich_text": []map[string]any{
							{"type": "text", "text": map[string]any{"content": truncate(text, 1900)}},
						},
					},
				},
			},
		}
		raw, err := n.do(
			ctx, token, notionVersion, http.MethodPatch,
			"/blocks/"+pageID+"/children", body,
		)
		if err != nil {
			result.Error = err.Error()
			return result, err
		}
		var parsed map[string]any
		_ = json.Unmarshal(raw, &parsed)
		result.Success = true
		result.Summary = "appended post-mortem to page " + pageID
		result.Details["blocks"] = parsed
		return result, nil

	default:
		result.Error = "unknown action: " + req.ActionID
		return result, errors.New(result.Error)
	}
}

func buildProps(params map[string]any) map[string]any {
	title, _ := params["title"].(string)
	if title == "" {
		title = "AiSOC Incident"
	}
	severity, _ := params["severity"].(string)
	if severity == "" {
		severity = "medium"
	}
	status, _ := params["status"].(string)
	if status == "" {
		status = "open"
	}
	props := map[string]any{
		"Name": map[string]any{
			"title": []map[string]any{{"text": map[string]any{"content": title}}},
		},
		"Severity": map[string]any{"select": map[string]any{"name": severity}},
		"Status":   map[string]any{"select": map[string]any{"name": status}},
	}
	if u, ok := params["case_url"].(string); ok && u != "" {
		props["AiSOC Case"] = map[string]any{"url": u}
	}
	return props
}

func buildChildren(params map[string]any) []map[string]any {
	summary, _ := params["summary"].(string)
	if summary == "" {
		return nil
	}
	return []map[string]any{
		{
			"object": "block",
			"type":   "paragraph",
			"paragraph": map[string]any{
				"rich_text": []map[string]any{
					{"type": "text", "text": map[string]any{"content": truncate(summary, 1900)}},
				},
			},
		},
	}
}

func (n *NotionAction) do(
	ctx context.Context,
	token, notionVersion, method, path string,
	body any,
) ([]byte, error) {
	buf, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(
		ctx, method, apiBase+path, bytes.NewReader(buf),
	)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Notion-Version", notionVersion)
	req.Header.Set("Content-Type", "application/json")
	resp, err := n.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		return raw, errors.New("notion: " + resp.Status)
	}
	return raw, nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

func main() {
	registry := aisoc.NewRegistry()
	if err := registry.Register(&NotionAction{}); err != nil {
		panic(err)
	}
	fmt.Println("notion-incidents reference plugin loaded")
}
