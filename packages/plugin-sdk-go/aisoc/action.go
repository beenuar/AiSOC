package aisoc

import "context"

// ActionRequest is the payload sent to a response-action plugin.
type ActionRequest struct {
	ActionID      string         `json:"action_id"`
	Params        map[string]any `json:"params,omitempty"`
	DryRun        bool           `json:"dry_run"`
	CaseID        string         `json:"case_id,omitempty"`
	PlaybookRunID string         `json:"playbook_run_id,omitempty"`
}

// ActionResult is the result returned by a response-action plugin.
type ActionResult struct {
	ActionID string         `json:"action_id"`
	Success  bool           `json:"success"`
	DryRun   bool           `json:"dry_run"`
	Summary  string         `json:"summary,omitempty"`
	Details  map[string]any `json:"details,omitempty"`
	Error    string         `json:"error,omitempty"`
}

// Action is implemented by plugins that perform automated response actions.
type Action interface {
	Plugin
	// SupportedActions returns the list of action IDs this plugin handles.
	SupportedActions() []string
	// Execute runs the action and returns a structured result.
	Execute(ctx context.Context, req ActionRequest, pctx PluginContext) (ActionResult, error)
}
