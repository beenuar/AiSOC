// Package main is the Slack quarantine notifier reference implementation in Go.
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

// SlackQuarantineNotifier implements aisoc.Action for Slack-based response comms.
type SlackQuarantineNotifier struct {
	aisoc.BasePlugin

	httpClient *http.Client
}

func (s *SlackQuarantineNotifier) Manifest() aisoc.PluginManifest {
	return aisoc.PluginManifest{
		ID:          "slack-quarantine",
		Name:        "Slack Quarantine Notifier",
		Version:     "1.0.0",
		PluginType:  aisoc.PluginTypeAction,
		Description: "Posts incident-response notifications to Slack with Block Kit formatting.",
		Author:      "AiSOC Core Team",
		Tags:        []string{"slack", "notification", "quarantine", "response"},
	}
}

func (s *SlackQuarantineNotifier) OnLoad(_ context.Context, _ aisoc.PluginContext) error {
	s.httpClient = &http.Client{Timeout: 30 * time.Second}
	return nil
}

func (s *SlackQuarantineNotifier) SupportedActions() []string {
	return []string{
		"post_quarantine",
		"page_oncall",
		"thread_update",
	}
}

func (s *SlackQuarantineNotifier) Execute(
	ctx context.Context,
	req aisoc.ActionRequest,
	pctx aisoc.PluginContext,
) (aisoc.ActionResult, error) {
	result := aisoc.ActionResult{
		ActionID: req.ActionID,
		DryRun:   req.DryRun,
		Details:  map[string]any{},
	}

	token, _ := pctx.Config["bot_token"].(string)
	if token == "" {
		result.Error = "bot_token is required"
		return result, errors.New(result.Error)
	}

	channel, _ := pctx.Config["channel"].(string)
	if c, ok := req.Params["channel"].(string); ok && c != "" {
		channel = c
	}

	if req.DryRun {
		result.Success = true
		result.Summary = "dry-run: no Slack call made"
		result.Details["channel"] = channel
		result.Details["action"] = req.ActionID
		return result, nil
	}

	switch req.ActionID {
	case "post_quarantine":
		if channel == "" {
			result.Error = "channel is required"
			return result, errors.New(result.Error)
		}
		body := map[string]any{
			"channel": channel,
			"text":    "Quarantine activated",
			"blocks":  s.buildBlocks(req),
		}
		if ts, ok := req.Params["thread_ts"].(string); ok && ts != "" {
			body["thread_ts"] = ts
		}
		out, err := s.post(ctx, token, "chat.postMessage", body)
		if err != nil {
			result.Error = err.Error()
			return result, err
		}
		result.Success = true
		result.Summary = "posted quarantine notice to " + channel
		result.Details["slack"] = out
		return result, nil

	case "page_oncall":
		oncall, _ := pctx.Config["oncall_user"].(string)
		if u, ok := req.Params["user"].(string); ok && u != "" {
			oncall = u
		}
		if oncall == "" {
			result.Error = "oncall_user is required"
			return result, errors.New(result.Error)
		}
		body := map[string]any{
			"channel": oncall,
			"text":    "P0 alert: please respond",
			"blocks":  s.buildBlocks(req),
		}
		out, err := s.post(ctx, token, "chat.postMessage", body)
		if err != nil {
			result.Error = err.Error()
			return result, err
		}
		result.Success = true
		result.Summary = "paged on-call user " + oncall
		result.Details["slack"] = out
		return result, nil

	case "thread_update":
		if channel == "" {
			result.Error = "channel is required"
			return result, errors.New(result.Error)
		}
		ts, _ := req.Params["thread_ts"].(string)
		if ts == "" {
			result.Error = "thread_ts is required"
			return result, errors.New(result.Error)
		}
		text, _ := req.Params["text"].(string)
		if text == "" {
			text = "Status update"
		}
		body := map[string]any{
			"channel":   channel,
			"thread_ts": ts,
			"text":      text,
		}
		out, err := s.post(ctx, token, "chat.postMessage", body)
		if err != nil {
			result.Error = err.Error()
			return result, err
		}
		result.Success = true
		result.Summary = "appended thread update on " + channel
		result.Details["slack"] = out
		return result, nil

	default:
		result.Error = "unknown action: " + req.ActionID
		return result, errors.New(result.Error)
	}
}

func (s *SlackQuarantineNotifier) buildBlocks(req aisoc.ActionRequest) []map[string]any {
	caseID, _ := req.Params["case_id"].(string)
	if caseID == "" {
		caseID = req.CaseID
	}
	host, _ := req.Params["host"].(string)
	user, _ := req.Params["user"].(string)
	severity, _ := req.Params["severity"].(string)
	reason, _ := req.Params["reason"].(string)

	target := host
	if target == "" {
		target = user
	}
	if target == "" {
		target = "unknown"
	}

	header := fmt.Sprintf(":rotating_light: *Quarantine Activated* — `%s`", target)
	if caseID != "" {
		header += fmt.Sprintf(" (case `%s`)", caseID)
	}

	fields := []map[string]any{}
	if severity != "" {
		fields = append(fields, map[string]any{
			"type": "mrkdwn",
			"text": fmt.Sprintf("*Severity:* `%s`", severity),
		})
	}
	if reason != "" {
		fields = append(fields, map[string]any{
			"type": "mrkdwn",
			"text": "*Reason:* " + reason,
		})
	}

	blocks := []map[string]any{
		{
			"type": "section",
			"text": map[string]any{"type": "mrkdwn", "text": header},
		},
	}
	if len(fields) > 0 {
		blocks = append(blocks, map[string]any{
			"type":   "section",
			"fields": fields,
		})
	}
	return blocks
}

func (s *SlackQuarantineNotifier) post(
	ctx context.Context,
	token, path string,
	body map[string]any,
) (map[string]any, error) {
	buf, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(
		ctx, http.MethodPost,
		"https://slack.com/api/"+path,
		bytes.NewReader(buf),
	)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json; charset=utf-8")

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)

	var result map[string]any
	if err := json.Unmarshal(raw, &result); err != nil {
		return nil, err
	}
	if ok, _ := result["ok"].(bool); !ok {
		errMsg, _ := result["error"].(string)
		if errMsg == "" {
			errMsg = "slack api error"
		}
		return result, errors.New("slack: " + errMsg)
	}
	return result, nil
}

func main() {
	registry := aisoc.NewRegistry()
	if err := registry.Register(&SlackQuarantineNotifier{}); err != nil {
		panic(err)
	}
	fmt.Println("slack-quarantine reference plugin loaded")
}
