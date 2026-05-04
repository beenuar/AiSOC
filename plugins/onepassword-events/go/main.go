// Package main is the 1Password Events connector reference implementation in Go.
//
// Demonstrates the AiSOC Go Plugin SDK for an identity event-source connector
// against the 1Password Events API.
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

var regionHosts = map[string]string{
	"com": "https://events.1password.com",
	"ca":  "https://events.1password.ca",
	"eu":  "https://events.1password.eu",
}

var feedPaths = map[string]string{
	"signinattempts": "/api/v1/signinattempts",
	"itemusages":     "/api/v1/itemusages",
	"auditevents":    "/api/v1/auditevents",
}

// OnePasswordConnector implements aisoc.Connector for the 1Password Events API.
type OnePasswordConnector struct {
	aisoc.BasePlugin

	httpClient *http.Client
}

func (o *OnePasswordConnector) Manifest() aisoc.PluginManifest {
	return aisoc.PluginManifest{
		ID:          "onepassword-events",
		Name:        "1Password Events Connector",
		Version:     "1.0.0",
		PluginType:  aisoc.PluginTypeConnector,
		Description: "Pulls sign-in, item-usage, and audit events from the 1Password Events API.",
		Author:      "AiSOC Core Team",
		Tags:        []string{"identity", "secrets", "1password", "events", "connector"},
	}
}

func (o *OnePasswordConnector) OnLoad(ctx context.Context, pctx aisoc.PluginContext) error {
	o.httpClient = &http.Client{Timeout: 30 * time.Second}
	return nil
}

func (o *OnePasswordConnector) TestConnection(
	ctx context.Context,
	pctx aisoc.PluginContext,
) (bool, error) {
	body, err := json.Marshal(map[string]any{
		"limit":      1,
		"start_time": time.Now().Add(-5 * time.Minute).UTC().Format(time.RFC3339),
	})
	if err != nil {
		return false, err
	}
	if _, err := o.do(ctx, pctx, "POST", feedPaths["signinattempts"], body); err != nil {
		return false, err
	}
	return true, nil
}

func (o *OnePasswordConnector) FetchEvents(
	ctx context.Context,
	pctx aisoc.PluginContext,
	since string,
) (<-chan map[string]any, error) {
	out := make(chan map[string]any)
	go func() {
		defer close(out)

		feeds := []string{"signinattempts", "itemusages", "auditevents"}
		if cfgFeeds, ok := pctx.Config["feeds"].([]any); ok && len(cfgFeeds) > 0 {
			feeds = feeds[:0]
			for _, f := range cfgFeeds {
				if s, ok := f.(string); ok {
					feeds = append(feeds, s)
				}
			}
		}

		startTime := since
		if startTime == "" {
			startTime = time.Now().Add(-15 * time.Minute).UTC().Format(time.RFC3339)
		}
		body, err := json.Marshal(map[string]any{
			"limit":      200,
			"start_time": startTime,
		})
		if err != nil {
			out <- map[string]any{"error": err.Error()}
			return
		}

		for _, feed := range feeds {
			path, ok := feedPaths[feed]
			if !ok {
				continue
			}
			raw, err := o.do(ctx, pctx, "POST", path, body)
			if err != nil {
				out <- map[string]any{"error": err.Error(), "feed": feed}
				continue
			}
			var parsed struct {
				Items []map[string]any `json:"items"`
			}
			if err := json.Unmarshal(raw, &parsed); err != nil {
				continue
			}
			for _, item := range parsed.Items {
				item["_aisoc_feed"] = feed
				out <- item
			}
		}
	}()
	return out, nil
}

func (o *OnePasswordConnector) do(
	ctx context.Context,
	pctx aisoc.PluginContext,
	method, path string,
	body []byte,
) ([]byte, error) {
	token, _ := pctx.Config["api_token"].(string)
	if token == "" {
		return nil, errors.New("api_token is required")
	}
	region, _ := pctx.Config["region"].(string)
	if region == "" {
		region = "com"
	}
	base, ok := regionHosts[region]
	if !ok {
		base = regionHosts["com"]
	}
	req, err := http.NewRequestWithContext(ctx, method, base+path, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := o.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return nil, errors.New("1password api: " + resp.Status)
	}
	return io.ReadAll(resp.Body)
}

func main() {
	registry := aisoc.NewRegistry()
	if err := registry.Register(&OnePasswordConnector{}); err != nil {
		panic(err)
	}
	fmt.Println("onepassword-events reference plugin loaded")
}
