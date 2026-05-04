// Package main is the PagerDuty paging action reference implementation in Go.
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

const eventsURL = "https://events.pagerduty.com/v2/enqueue"

// PagerDutyAction implements aisoc.Action for the PagerDuty Events API v2.
type PagerDutyAction struct {
	aisoc.BasePlugin

	httpClient *http.Client
}

func (p *PagerDutyAction) Manifest() aisoc.PluginManifest {
	return aisoc.PluginManifest{
		ID:          "pagerduty-paging",
		Name:        "PagerDuty Paging",
		Version:     "1.0.0",
		PluginType:  aisoc.PluginTypeAction,
		Description: "Pages on-call responders via PagerDuty Events API v2.",
		Author:      "AiSOC Core Team",
		Tags:        []string{"paging", "pagerduty", "oncall", "incidents", "action"},
	}
}

func (p *PagerDutyAction) OnLoad(_ context.Context, _ aisoc.PluginContext) error {
	p.httpClient = &http.Client{Timeout: 30 * time.Second}
	return nil
}

func (p *PagerDutyAction) SupportedActions() []string {
	return []string{
		"trigger_incident",
		"acknowledge_incident",
		"resolve_incident",
	}
}

func (p *PagerDutyAction) Execute(
	ctx context.Context,
	req aisoc.ActionRequest,
	pctx aisoc.PluginContext,
) (aisoc.ActionResult, error) {
	result := aisoc.ActionResult{
		ActionID: req.ActionID,
		DryRun:   req.DryRun,
		Details:  map[string]any{},
	}

	routingKey, _ := pctx.Config["routing_key"].(string)
	if routingKey == "" {
		result.Error = "routing_key is required"
		return result, errors.New(result.Error)
	}

	if req.DryRun {
		result.Success = true
		result.Summary = "dry-run: no PagerDuty event sent"
		result.Details["action"] = req.ActionID
		return result, nil
	}

	switch req.ActionID {
	case "trigger_incident":
		return p.trigger(ctx, routingKey, req, result)
	case "acknowledge_incident":
		return p.lifecycle(ctx, routingKey, req, "acknowledge", result)
	case "resolve_incident":
		return p.lifecycle(ctx, routingKey, req, "resolve", result)
	default:
		result.Error = "unknown action: " + req.ActionID
		return result, errors.New(result.Error)
	}
}

func (p *PagerDutyAction) trigger(
	ctx context.Context,
	routingKey string,
	req aisoc.ActionRequest,
	result aisoc.ActionResult,
) (aisoc.ActionResult, error) {
	summary, _ := req.Params["summary"].(string)
	if summary == "" {
		summary = "AiSOC alert"
	}
	severity, _ := req.Params["severity"].(string)
	if severity == "" {
		severity = "error"
	}
	dedupKey, _ := req.Params["dedup_key"].(string)
	source, _ := req.Params["source"].(string)
	if source == "" {
		source = "aisoc"
	}
	body, err := json.Marshal(map[string]any{
		"routing_key":  routingKey,
		"event_action": "trigger",
		"dedup_key":    dedupKey,
		"payload": map[string]any{
			"summary":  summary,
			"severity": severity,
			"source":   source,
		},
	})
	if err != nil {
		result.Error = err.Error()
		return result, err
	}
	raw, err := p.do(ctx, body)
	if err != nil {
		result.Error = err.Error()
		return result, err
	}
	var parsed map[string]any
	_ = json.Unmarshal(raw, &parsed)
	result.Success = true
	result.Summary = "triggered PagerDuty incident: " + summary
	result.Details["pagerduty"] = parsed
	return result, nil
}

func (p *PagerDutyAction) lifecycle(
	ctx context.Context,
	routingKey string,
	req aisoc.ActionRequest,
	eventAction string,
	result aisoc.ActionResult,
) (aisoc.ActionResult, error) {
	dedupKey, _ := req.Params["dedup_key"].(string)
	if dedupKey == "" {
		result.Error = "dedup_key required for ack/resolve"
		return result, errors.New(result.Error)
	}
	body, err := json.Marshal(map[string]any{
		"routing_key":  routingKey,
		"event_action": eventAction,
		"dedup_key":    dedupKey,
	})
	if err != nil {
		result.Error = err.Error()
		return result, err
	}
	raw, err := p.do(ctx, body)
	if err != nil {
		result.Error = err.Error()
		return result, err
	}
	var parsed map[string]any
	_ = json.Unmarshal(raw, &parsed)
	result.Success = true
	result.Summary = eventAction + "d PagerDuty incident " + dedupKey
	result.Details["pagerduty"] = parsed
	return result, nil
}

func (p *PagerDutyAction) do(ctx context.Context, body []byte) ([]byte, error) {
	req, err := http.NewRequestWithContext(
		ctx, http.MethodPost, eventsURL, bytes.NewReader(body),
	)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := p.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		return raw, errors.New("pagerduty: " + resp.Status)
	}
	return raw, nil
}

func main() {
	registry := aisoc.NewRegistry()
	if err := registry.Register(&PagerDutyAction{}); err != nil {
		panic(err)
	}
	fmt.Println("pagerduty-paging reference plugin loaded")
}
