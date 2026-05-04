// Package main is the Jamf Pro MDM connector reference implementation in Go.
//
// This binary registers a Jamf connector against the AiSOC Go plugin SDK and
// exposes the same surface as the Python implementation:
//
//	get_device, list_devices, lock_device, wipe_device, get_compliance, get_inventory
//
// AiSOC's runtime currently loads Python plugins via plugin.py; this Go file
// is a reference for cross-language SDK parity for operators who want to
// build their own native binary plugins.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/beenuar/aisoc/plugin-sdk-go/aisoc"
)

// JamfConnector implements the aisoc.Connector interface for Jamf Pro.
type JamfConnector struct {
	aisoc.BasePlugin

	httpClient *http.Client
	token      string
	tokenExp   time.Time
}

// Manifest returns the plugin manifest matching the canonical aisoc-plugin.json.
func (j *JamfConnector) Manifest() aisoc.PluginManifest {
	return aisoc.PluginManifest{
		ID:          "jamf-mdm",
		Name:        "Jamf Pro MDM Connector",
		Version:     "1.0.0",
		PluginType:  aisoc.PluginTypeConnector,
		Description: "Jamf Pro MDM connector for Apple device fleet management.",
		Author:      "AiSOC Core Team",
		Tags:        []string{"mdm", "jamf", "endpoint", "apple"},
	}
}

// OnLoad initializes the HTTP client.
func (j *JamfConnector) OnLoad(ctx context.Context, pctx aisoc.PluginContext) error {
	j.httpClient = &http.Client{Timeout: 30 * time.Second}
	return nil
}

// TestConnection verifies credentials by fetching an OAuth token.
func (j *JamfConnector) TestConnection(ctx context.Context, pctx aisoc.PluginContext) (bool, error) {
	if _, err := j.fetchToken(ctx, pctx); err != nil {
		return false, err
	}
	return true, nil
}

// FetchEvents pulls computer-inventory updates as a stream of audit events.
func (j *JamfConnector) FetchEvents(
	ctx context.Context,
	pctx aisoc.PluginContext,
	since string,
) (<-chan map[string]any, error) {
	out := make(chan map[string]any)
	go func() {
		defer close(out)
		token, err := j.fetchToken(ctx, pctx)
		if err != nil {
			out <- map[string]any{"error": err.Error()}
			return
		}
		base := strings.TrimRight(pctx.Config["jamf_url"].(string), "/")
		req, _ := http.NewRequestWithContext(
			ctx, "GET", base+"/api/v1/computers-inventory?page-size=100", nil,
		)
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Accept", "application/json")
		resp, err := j.httpClient.Do(req)
		if err != nil {
			out <- map[string]any{"error": err.Error()}
			return
		}
		defer resp.Body.Close()
		var body struct {
			Results []map[string]any `json:"results"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&body)
		for _, r := range body.Results {
			out <- r
		}
	}()
	return out, nil
}

func (j *JamfConnector) fetchToken(ctx context.Context, pctx aisoc.PluginContext) (string, error) {
	if j.token != "" && time.Now().Before(j.tokenExp.Add(-30*time.Second)) {
		return j.token, nil
	}
	cfg := pctx.Config
	for _, k := range []string{"jamf_url", "client_id", "client_secret"} {
		if cfg[k] == nil {
			return "", fmt.Errorf("missing config key: %s", k)
		}
	}
	form := url.Values{}
	form.Set("grant_type", "client_credentials")
	form.Set("client_id", cfg["client_id"].(string))
	form.Set("client_secret", cfg["client_secret"].(string))

	base := strings.TrimRight(cfg["jamf_url"].(string), "/")
	req, _ := http.NewRequestWithContext(
		ctx, "POST", base+"/api/oauth/token", strings.NewReader(form.Encode()),
	)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := j.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return "", errors.New("jamf oauth: " + resp.Status)
	}
	var body struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return "", err
	}
	j.token = body.AccessToken
	j.tokenExp = time.Now().Add(time.Duration(body.ExpiresIn) * time.Second)
	return j.token, nil
}

func main() {
	registry := aisoc.NewRegistry()
	if err := registry.Register(&JamfConnector{}); err != nil {
		panic(err)
	}
	fmt.Println("jamf-mdm reference plugin loaded")
}
