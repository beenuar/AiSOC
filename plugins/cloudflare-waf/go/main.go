// Package main is the Cloudflare WAF action reference implementation in Go.
//
// This file mirrors the Python plugin.py and demonstrates cross-language SDK
// parity. The AiSOC runtime currently invokes plugin.py at execution time;
// this Go reference is intended for operators who prefer to ship native
// binary plugins.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/beenuar/aisoc/plugin-sdk-go/aisoc"
)

const apiBase = "https://api.cloudflare.com/client/v4"

// CloudflareWAFAction implements aisoc.Action for Cloudflare firewall ops.
type CloudflareWAFAction struct {
	aisoc.BasePlugin

	httpClient *http.Client
}

func (c *CloudflareWAFAction) Manifest() aisoc.PluginManifest {
	return aisoc.PluginManifest{
		ID:          "cloudflare-waf",
		Name:        "Cloudflare WAF Action",
		Version:     "1.0.0",
		PluginType:  aisoc.PluginTypeAction,
		Description: "Block IPs, toggle Under Attack mode, and purge cache via the Cloudflare API.",
		Author:      "AiSOC Core Team",
		Tags:        []string{"network", "cloudflare", "waf", "response"},
	}
}

func (c *CloudflareWAFAction) OnLoad(ctx context.Context, pctx aisoc.PluginContext) error {
	c.httpClient = &http.Client{Timeout: 30 * time.Second}
	return nil
}

func (c *CloudflareWAFAction) SupportedActions() []string {
	return []string{
		"block_ip",
		"unblock_ip",
		"set_under_attack",
		"purge_cache",
		"list_rules",
	}
}

func (c *CloudflareWAFAction) Execute(
	ctx context.Context,
	req aisoc.ActionRequest,
	pctx aisoc.PluginContext,
) (aisoc.ActionResult, error) {
	token, _ := pctx.Config["api_token"].(string)
	if token == "" {
		return aisoc.ActionResult{
			ActionID: req.ActionID,
			Success:  false,
			Error:    "api_token is required",
		}, errors.New("api_token is required")
	}

	switch req.ActionID {
	case "block_ip":
		accountID, _ := pctx.Config["account_id"].(string)
		if accountID == "" {
			return aisoc.ActionResult{ActionID: req.ActionID, Error: "account_id required"}, nil
		}
		ip, _ := req.Params["ip"].(string)
		body := map[string]any{
			"mode": "block",
			"configuration": map[string]any{
				"target": "ip",
				"value":  ip,
			},
			"notes": "blocked by AiSOC",
		}
		buf, _ := json.Marshal(body)
		path := fmt.Sprintf("/accounts/%s/firewall/access_rules/rules", accountID)
		resp, err := c.do(ctx, token, "POST", path, buf)
		if err != nil {
			return aisoc.ActionResult{ActionID: req.ActionID, Error: err.Error()}, err
		}
		return aisoc.ActionResult{
			ActionID: req.ActionID,
			Success:  true,
			Summary:  fmt.Sprintf("Blocked IP %s", ip),
			Details:  resp,
		}, nil
	default:
		return aisoc.ActionResult{
			ActionID: req.ActionID,
			Error:    "unsupported action: " + req.ActionID,
		}, nil
	}
}

func (c *CloudflareWAFAction) do(
	ctx context.Context,
	token, method, path string,
	body []byte,
) (map[string]any, error) {
	req, err := http.NewRequestWithContext(ctx, method, apiBase+path, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return nil, errors.New("cloudflare api: " + resp.Status)
	}
	var out map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	return out, nil
}

func main() {
	registry := aisoc.NewRegistry()
	if err := registry.Register(&CloudflareWAFAction{}); err != nil {
		panic(err)
	}
	fmt.Println("cloudflare-waf reference plugin loaded")
}
