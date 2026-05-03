// Package aisoc — async HTTP client for the AiSOC REST API.
//
// Plugins use Client to:
//   - Fetch and update case records
//   - Patch indicator enrichment data
//   - Complete manual playbook steps
package aisoc

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

// ClientError is returned when the AiSOC API responds with a non-2xx status.
type ClientError struct {
	StatusCode int
	Body       string
}

func (e *ClientError) Error() string {
	return fmt.Sprintf("AiSOC API error %d: %s", e.StatusCode, e.Body)
}

// Client is a thin HTTP client scoped to a single plugin invocation.
// Instantiate it with NewClient, passing the PluginContext supplied to your plugin.
//
//	client := aisoc.NewClient(pctx)
//	data, err := client.GetCase(ctx, "case-123")
type Client struct {
	base    string
	token   string
	http    *http.Client
}

// NewClient creates a Client using credentials from the given PluginContext.
// An optional timeout may be passed; 0 uses the default of 30 s.
func NewClient(pctx PluginContext, timeout time.Duration) *Client {
	if timeout == 0 {
		timeout = 30 * time.Second
	}
	return &Client{
		base:  pctx.APIBaseURL,
		token: pctx.APIToken,
		http:  &http.Client{Timeout: timeout},
	}
}

// ── internal helpers ──────────────────────────────────────────────────────

func (c *Client) do(ctx context.Context, method, path string, body any) (map[string]any, error) {
	var bodyReader io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("marshal request body: %w", err)
		}
		bodyReader = bytes.NewReader(b)
	}

	u, err := url.JoinPath(c.base, path)
	if err != nil {
		return nil, fmt.Errorf("build URL: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, method, u, bodyReader)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("http %s %s: %w", method, path, err)
	}
	defer resp.Body.Close() //nolint:errcheck

	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, &ClientError{StatusCode: resp.StatusCode, Body: string(raw)}
	}

	var result map[string]any
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &result); err != nil {
			return nil, fmt.Errorf("decode response: %w", err)
		}
	}
	return result, nil
}

// ── Cases API ─────────────────────────────────────────────────────────────

// GetCase fetches a case by ID.
func (c *Client) GetCase(ctx context.Context, caseID string) (map[string]any, error) {
	return c.do(ctx, http.MethodGet, "/api/v1/cases/"+caseID, nil)
}

// AddCaseNote appends a plain-text note to a case timeline.
func (c *Client) AddCaseNote(ctx context.Context, caseID, note string) (map[string]any, error) {
	return c.do(ctx, http.MethodPost, "/api/v1/cases/"+caseID+"/notes",
		map[string]any{"content": note})
}

// UpdateCaseSeverity sets case severity. severity must be one of: low, medium, high, critical.
func (c *Client) UpdateCaseSeverity(ctx context.Context, caseID, severity string) (map[string]any, error) {
	return c.do(ctx, http.MethodPatch, "/api/v1/cases/"+caseID,
		map[string]any{"severity": severity})
}

// ── Indicators API ────────────────────────────────────────────────────────

// GetIndicator fetches a raw indicator record.
func (c *Client) GetIndicator(ctx context.Context, indicatorID string) (map[string]any, error) {
	return c.do(ctx, http.MethodGet, "/api/v1/indicators/"+indicatorID, nil)
}

// PatchIndicator merges enrichment data into an existing indicator record.
func (c *Client) PatchIndicator(ctx context.Context, indicatorID string, enrichments map[string]any) (map[string]any, error) {
	return c.do(ctx, http.MethodPatch, "/api/v1/indicators/"+indicatorID,
		map[string]any{"enrichments": enrichments})
}

// ── Playbook runs API ─────────────────────────────────────────────────────

// GetPlaybookRun fetches playbook run status.
func (c *Client) GetPlaybookRun(ctx context.Context, runID string) (map[string]any, error) {
	return c.do(ctx, http.MethodGet, "/api/v1/playbook-runs/"+runID, nil)
}

// CompletePlaybookStep signals that a manual or async step is complete.
func (c *Client) CompletePlaybookStep(ctx context.Context, runID, stepID string, result map[string]any) (map[string]any, error) {
	return c.do(ctx, http.MethodPost,
		fmt.Sprintf("/api/v1/playbook-runs/%s/steps/%s/complete", runID, stepID),
		result)
}
