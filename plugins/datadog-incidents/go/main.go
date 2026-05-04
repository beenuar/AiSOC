// Package main is the Datadog incidents connector reference implementation in Go.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/beenuar/aisoc/plugin-sdk-go/aisoc"
)

// DatadogConnector implements aisoc.Connector for the Datadog Incidents/Signals APIs.
type DatadogConnector struct {
	aisoc.BasePlugin

	httpClient *http.Client
}

func (d *DatadogConnector) Manifest() aisoc.PluginManifest {
	return aisoc.PluginManifest{
		ID:          "datadog-incidents",
		Name:        "Datadog Incidents Connector",
		Version:     "1.0.0",
		PluginType:  aisoc.PluginTypeConnector,
		Description: "Pulls open Datadog incidents and security signals into AiSOC.",
		Author:      "AiSOC Core Team",
		Tags:        []string{"observability", "datadog", "incidents", "signals", "connector"},
	}
}

func (d *DatadogConnector) OnLoad(ctx context.Context, pctx aisoc.PluginContext) error {
	d.httpClient = &http.Client{Timeout: 30 * time.Second}
	return nil
}

func (d *DatadogConnector) baseURL(pctx aisoc.PluginContext) string {
	site, _ := pctx.Config["site"].(string)
	if site == "" {
		site = "datadoghq.com"
	}
	return "https://api." + site
}

func (d *DatadogConnector) headers(pctx aisoc.PluginContext) (http.Header, error) {
	apiKey, _ := pctx.Config["api_key"].(string)
	appKey, _ := pctx.Config["app_key"].(string)
	if apiKey == "" || appKey == "" {
		return nil, errors.New("api_key and app_key are required")
	}
	h := http.Header{}
	h.Set("DD-API-KEY", apiKey)
	h.Set("DD-APPLICATION-KEY", appKey)
	h.Set("Content-Type", "application/json")
	return h, nil
}

func (d *DatadogConnector) get(
	ctx context.Context,
	url string,
	headers http.Header,
) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header = headers
	resp, err := d.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		return body, fmt.Errorf("datadog: %s", resp.Status)
	}
	return body, nil
}

func (d *DatadogConnector) TestConnection(
	ctx context.Context,
	pctx aisoc.PluginContext,
) (bool, error) {
	headers, err := d.headers(pctx)
	if err != nil {
		return false, err
	}
	body, err := d.get(ctx, d.baseURL(pctx)+"/api/v1/validate", headers)
	if err != nil {
		return false, err
	}
	var parsed map[string]any
	_ = json.Unmarshal(body, &parsed)
	if v, ok := parsed["valid"].(bool); ok {
		return v, nil
	}
	return false, nil
}

func (d *DatadogConnector) FetchEvents(
	ctx context.Context,
	pctx aisoc.PluginContext,
	since string,
) (<-chan map[string]any, error) {
	out := make(chan map[string]any)
	headers, err := d.headers(pctx)
	if err != nil {
		close(out)
		return out, err
	}

	feeds := []string{"incidents", "security_signals"}
	if cfgFeeds, ok := pctx.Config["feeds"].([]any); ok && len(cfgFeeds) > 0 {
		feeds = feeds[:0]
		for _, f := range cfgFeeds {
			if s, ok := f.(string); ok {
				feeds = append(feeds, s)
			}
		}
	}

	if since == "" {
		since = time.Now().Add(-1 * time.Hour).UTC().Format(time.RFC3339)
	}

	go func() {
		defer close(out)
		base := d.baseURL(pctx)

		for _, feed := range feeds {
			var url string
			switch feed {
			case "incidents":
				url = base + "/api/v2/incidents"
			case "security_signals":
				url = fmt.Sprintf(
					"%s/api/v2/security_monitoring/signals?filter[from]=%s&page[limit]=100",
					base, since,
				)
			default:
				continue
			}
			body, err := d.get(ctx, url, headers)
			if err != nil {
				out <- map[string]any{"error": err.Error(), "feed": feed}
				continue
			}
			var parsed struct {
				Data []map[string]any `json:"data"`
			}
			if err := json.Unmarshal(body, &parsed); err != nil {
				continue
			}
			for _, item := range parsed.Data {
				item["_aisoc_feed"] = feed
				out <- item
			}
		}
	}()
	return out, nil
}

func main() {
	registry := aisoc.NewRegistry()
	if err := registry.Register(&DatadogConnector{}); err != nil {
		panic(err)
	}
	fmt.Println("datadog-incidents reference plugin loaded")
}
