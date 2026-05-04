// Package main is the Twilio SMS action reference implementation in Go.
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

// TwilioAction implements aisoc.Action for sending SMS via Twilio.
type TwilioAction struct {
	aisoc.BasePlugin

	httpClient *http.Client
}

func (t *TwilioAction) Manifest() aisoc.PluginManifest {
	return aisoc.PluginManifest{
		ID:          "twilio-sms",
		Name:        "Twilio SMS Notifier",
		Version:     "1.0.0",
		PluginType:  aisoc.PluginTypeAction,
		Description: "Sends SMS messages via Twilio for paging and emergency notifications.",
		Author:      "AiSOC Core Team",
		Tags:        []string{"notification", "sms", "twilio", "paging", "action"},
	}
}

func (t *TwilioAction) OnLoad(_ context.Context, _ aisoc.PluginContext) error {
	t.httpClient = &http.Client{Timeout: 30 * time.Second}
	return nil
}

func (t *TwilioAction) SupportedActions() []string {
	return []string{"send_sms", "bulk_send"}
}

func (t *TwilioAction) Execute(
	ctx context.Context,
	req aisoc.ActionRequest,
	pctx aisoc.PluginContext,
) (aisoc.ActionResult, error) {
	result := aisoc.ActionResult{
		ActionID: req.ActionID,
		DryRun:   req.DryRun,
		Details:  map[string]any{},
	}

	accountSID, _ := pctx.Config["account_sid"].(string)
	authToken, _ := pctx.Config["auth_token"].(string)
	fromNumber, _ := pctx.Config["from_number"].(string)
	if accountSID == "" || authToken == "" || fromNumber == "" {
		result.Error = "account_sid, auth_token, and from_number are required"
		return result, errors.New(result.Error)
	}

	body, _ := req.Params["body"].(string)
	if body == "" {
		body, _ = req.Params["message"].(string)
	}
	if body == "" {
		body = "AiSOC alert"
	}

	if req.DryRun {
		result.Success = true
		result.Summary = "dry-run: no SMS sent"
		result.Details["action"] = req.ActionID
		result.Details["body"] = body
		return result, nil
	}

	switch req.ActionID {
	case "send_sms":
		to, _ := req.Params["to"].(string)
		if to == "" {
			if def, ok := pctx.Config["default_recipients"].([]any); ok && len(def) > 0 {
				if first, ok := def[0].(string); ok {
					to = first
				}
			}
		}
		if to == "" {
			result.Error = "`to` recipient is required"
			return result, errors.New(result.Error)
		}
		raw, err := t.send(ctx, accountSID, authToken, fromNumber, to, body)
		if err != nil {
			result.Error = err.Error()
			return result, err
		}
		var parsed map[string]any
		_ = json.Unmarshal(raw, &parsed)
		sid, _ := parsed["sid"].(string)
		result.Success = true
		result.Summary = "sent SMS " + sid + " to " + to
		result.Details["twilio"] = parsed
		return result, nil

	case "bulk_send":
		var recipients []string
		if list, ok := req.Params["recipients"].([]any); ok {
			for _, r := range list {
				if s, ok := r.(string); ok {
					recipients = append(recipients, s)
				}
			}
		}
		if len(recipients) == 0 {
			if def, ok := pctx.Config["default_recipients"].([]any); ok {
				for _, r := range def {
					if s, ok := r.(string); ok {
						recipients = append(recipients, s)
					}
				}
			}
		}
		if len(recipients) == 0 {
			result.Error = "no recipients configured"
			return result, errors.New(result.Error)
		}
		results := make([]map[string]any, 0, len(recipients))
		errCount := 0
		for _, to := range recipients {
			raw, err := t.send(ctx, accountSID, authToken, fromNumber, to, body)
			entry := map[string]any{"to": to}
			if err != nil {
				entry["error"] = err.Error()
				errCount++
			} else {
				var parsed map[string]any
				_ = json.Unmarshal(raw, &parsed)
				if sid, ok := parsed["sid"]; ok {
					entry["sid"] = sid
				}
			}
			results = append(results, entry)
		}
		result.Success = errCount < len(recipients)
		result.Summary = fmt.Sprintf(
			"bulk SMS: %d/%d delivered", len(recipients)-errCount, len(recipients),
		)
		result.Details["results"] = results
		return result, nil

	default:
		result.Error = "unknown action: " + req.ActionID
		return result, errors.New(result.Error)
	}
}

func (t *TwilioAction) send(
	ctx context.Context,
	accountSID, authToken, from, to, body string,
) ([]byte, error) {
	endpoint := fmt.Sprintf(
		"https://api.twilio.com/2010-04-01/Accounts/%s/Messages.json",
		accountSID,
	)
	form := url.Values{}
	form.Set("From", from)
	form.Set("To", to)
	form.Set("Body", body)
	req, err := http.NewRequestWithContext(
		ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()),
	)
	if err != nil {
		return nil, err
	}
	req.SetBasicAuth(accountSID, authToken)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := t.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		return raw, errors.New("twilio: " + resp.Status)
	}
	return raw, nil
}

func main() {
	registry := aisoc.NewRegistry()
	if err := registry.Register(&TwilioAction{}); err != nil {
		panic(err)
	}
	fmt.Println("twilio-sms reference plugin loaded")
}
