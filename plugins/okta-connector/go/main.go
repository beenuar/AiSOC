// Package main is the Okta connector reference implementation in Go.
//
// Implements both aisoc.Connector (system log streaming) and aisoc.Action
// (lifecycle actions: suspend, unsuspend, MFA reset, session expiry) on the
// same plugin struct. The Registry's interface checks pick up both roles
// independently.
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

// OktaConnector is a connector + action plugin for the Okta Identity Cloud.
type OktaConnector struct {
	aisoc.BasePlugin

	httpClient *http.Client
}

func (o *OktaConnector) Manifest() aisoc.PluginManifest {
	return aisoc.PluginManifest{
		ID:          "okta-connector",
		Name:        "Okta Connector",
		Version:     "1.0.0",
		PluginType:  aisoc.PluginTypeConnector,
		Description: "Okta Identity Cloud connector for log streaming and account response actions.",
		Author:      "AiSOC Core Team",
		Tags:        []string{"identity", "okta", "iam", "sso"},
	}
}

func (o *OktaConnector) OnLoad(ctx context.Context, pctx aisoc.PluginContext) error {
	o.httpClient = &http.Client{Timeout: 30 * time.Second}
	return nil
}

func (o *OktaConnector) baseURL(pctx aisoc.PluginContext) (string, error) {
	domain, _ := pctx.Config["okta_domain"].(string)
	if domain == "" {
		return "", errors.New("okta_domain is required")
	}
	domain = strings.TrimRight(domain, "/")
	if !strings.HasPrefix(domain, "http") {
		domain = "https://" + domain
	}
	return domain, nil
}

func (o *OktaConnector) authHeader(pctx aisoc.PluginContext) (string, error) {
	token, _ := pctx.Config["api_token"].(string)
	if token == "" {
		return "", errors.New("api_token is required")
	}
	return "SSWS " + token, nil
}

// request performs a single Okta API call. The body slice is null on GET/DELETE.
// Returns either the decoded object payload or an array payload, depending on
// what Okta returns for the endpoint.
func (o *OktaConnector) request(
	ctx context.Context,
	pctx aisoc.PluginContext,
	method, path string,
	params url.Values,
) (map[string]any, []map[string]any, error) {
	base, err := o.baseURL(pctx)
	if err != nil {
		return nil, nil, err
	}
	auth, err := o.authHeader(pctx)
	if err != nil {
		return nil, nil, err
	}

	full := base + path
	if len(params) > 0 {
		full += "?" + params.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, method, full, nil)
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("Authorization", auth)
	req.Header.Set("Accept", "application/json")
	resp, err := o.httpClient.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		return nil, nil, fmt.Errorf("okta: %s: %s", resp.Status, string(body))
	}
	if len(body) == 0 || resp.StatusCode == http.StatusNoContent {
		return map[string]any{"status": resp.StatusCode}, nil, nil
	}
	if body[0] == '[' {
		var arr []map[string]any
		if err := json.Unmarshal(body, &arr); err != nil {
			return nil, nil, err
		}
		return nil, arr, nil
	}
	var obj map[string]any
	if err := json.Unmarshal(body, &obj); err != nil {
		return nil, nil, err
	}
	return obj, nil, nil
}

// TestConnection verifies the API token and tenant by hitting /api/v1/users/me
// (works for user tokens) and falling back to /api/v1/org (works for SSWS API
// tokens scoped to an org).
func (o *OktaConnector) TestConnection(
	ctx context.Context,
	pctx aisoc.PluginContext,
) (bool, error) {
	if _, _, err := o.request(ctx, pctx, http.MethodGet, "/api/v1/users/me", nil); err != nil {
		if _, _, err := o.request(ctx, pctx, http.MethodGet, "/api/v1/org", nil); err != nil {
			return false, err
		}
	}
	return true, nil
}

// FetchEvents streams Okta system log events newer than `since` over a channel.
// Tags each event with `_aisoc_source = "okta"` so downstream pipelines can
// route per-source.
func (o *OktaConnector) FetchEvents(
	ctx context.Context,
	pctx aisoc.PluginContext,
	since string,
) (<-chan map[string]any, error) {
	out := make(chan map[string]any)
	go func() {
		defer close(out)
		if since == "" {
			since = time.Now().Add(-15 * time.Minute).UTC().Format(time.RFC3339)
		}
		params := url.Values{
			"since": []string{since},
			"limit": []string{"100"},
		}
		_, events, err := o.request(ctx, pctx, http.MethodGet, "/api/v1/logs", params)
		if err != nil {
			select {
			case <-ctx.Done():
			case out <- map[string]any{"error": err.Error(), "_aisoc_source": "okta"}:
			}
			return
		}
		for _, ev := range events {
			ev["_aisoc_source"] = "okta"
			select {
			case <-ctx.Done():
				return
			case out <- ev:
			}
		}
	}()
	return out, nil
}

// SupportedActions exposes the response actions Okta can perform on a user.
func (o *OktaConnector) SupportedActions() []string {
	return []string{
		"lookup_user",
		"suspend_user",
		"unsuspend_user",
		"clear_factors",
		"expire_sessions",
	}
}

// Execute runs a response action against a user identified by `user_id` or
// `login` in req.Params. Honors req.DryRun by returning a planned summary
// without calling Okta.
func (o *OktaConnector) Execute(
	ctx context.Context,
	req aisoc.ActionRequest,
	pctx aisoc.PluginContext,
) (aisoc.ActionResult, error) {
	userID, _ := req.Params["user_id"].(string)
	if userID == "" {
		userID, _ = req.Params["login"].(string)
	}
	if userID == "" {
		err := errors.New("user_id or login is required")
		return aisoc.ActionResult{
			ActionID: req.ActionID,
			Success:  false,
			DryRun:   req.DryRun,
			Error:    err.Error(),
		}, err
	}

	if req.DryRun {
		return aisoc.ActionResult{
			ActionID: req.ActionID,
			Success:  true,
			DryRun:   true,
			Summary:  fmt.Sprintf("would %s for user %s", req.ActionID, userID),
			Details:  map[string]any{"user_id": userID},
		}, nil
	}

	switch req.ActionID {
	case "lookup_user":
		obj, _, err := o.request(ctx, pctx, http.MethodGet, "/api/v1/users/"+userID, nil)
		if err != nil {
			return aisoc.ActionResult{ActionID: req.ActionID, Error: err.Error()}, err
		}
		return aisoc.ActionResult{
			ActionID: req.ActionID,
			Success:  true,
			Summary:  "looked up user " + userID,
			Details:  obj,
		}, nil

	case "suspend_user":
		obj, _, err := o.request(
			ctx, pctx, http.MethodPost,
			"/api/v1/users/"+userID+"/lifecycle/suspend", nil,
		)
		if err != nil {
			return aisoc.ActionResult{ActionID: req.ActionID, Error: err.Error()}, err
		}
		return aisoc.ActionResult{
			ActionID: req.ActionID,
			Success:  true,
			Summary:  "suspended user " + userID,
			Details:  obj,
		}, nil

	case "unsuspend_user":
		obj, _, err := o.request(
			ctx, pctx, http.MethodPost,
			"/api/v1/users/"+userID+"/lifecycle/unsuspend", nil,
		)
		if err != nil {
			return aisoc.ActionResult{ActionID: req.ActionID, Error: err.Error()}, err
		}
		return aisoc.ActionResult{
			ActionID: req.ActionID,
			Success:  true,
			Summary:  "unsuspended user " + userID,
			Details:  obj,
		}, nil

	case "clear_factors":
		_, factors, err := o.request(
			ctx, pctx, http.MethodGet,
			"/api/v1/users/"+userID+"/factors", nil,
		)
		if err != nil {
			return aisoc.ActionResult{ActionID: req.ActionID, Error: err.Error()}, err
		}
		var deleted []string
		for _, f := range factors {
			fid, _ := f["id"].(string)
			if fid == "" {
				continue
			}
			if _, _, err := o.request(
				ctx, pctx, http.MethodDelete,
				"/api/v1/users/"+userID+"/factors/"+fid, nil,
			); err != nil {
				return aisoc.ActionResult{
					ActionID: req.ActionID,
					Error:    err.Error(),
					Details:  map[string]any{"deleted_so_far": deleted, "failed_at": fid},
				}, err
			}
			deleted = append(deleted, fid)
		}
		return aisoc.ActionResult{
			ActionID: req.ActionID,
			Success:  true,
			Summary:  fmt.Sprintf("cleared %d MFA factors for user %s", len(deleted), userID),
			Details:  map[string]any{"deleted_factors": deleted},
		}, nil

	case "expire_sessions":
		obj, _, err := o.request(
			ctx, pctx, http.MethodDelete,
			"/api/v1/users/"+userID+"/sessions",
			url.Values{"oauthTokens": []string{"true"}},
		)
		if err != nil {
			return aisoc.ActionResult{ActionID: req.ActionID, Error: err.Error()}, err
		}
		return aisoc.ActionResult{
			ActionID: req.ActionID,
			Success:  true,
			Summary:  "expired all sessions for user " + userID,
			Details:  obj,
		}, nil

	default:
		return aisoc.ActionResult{
			ActionID: req.ActionID,
			Error:    "unsupported action: " + req.ActionID,
		}, nil
	}
}

func main() {
	registry := aisoc.NewRegistry()
	if err := registry.Register(&OktaConnector{}); err != nil {
		panic(err)
	}
	fmt.Println("okta-connector reference plugin loaded")
}
