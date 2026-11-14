// Widget plugin support for the AiSOC Go SDK.
//
// Widget plugins compute structured data for dashboard panels. They receive
// arbitrary JSON payloads (filters, time ranges, slicing parameters) and
// return arbitrary JSON output that the front-end widget renderer consumes.
//
// Widgets typically read from the AiSOC API or directly from analytical
// stores, transform the raw data, and shape it for the renderer. They are
// distinct from Enrichers (which work on indicators) and Actions (which
// have side effects).

package aisoc

import "context"

// PluginTypeWidget identifies a dashboard widget plugin in PluginManifest.
const PluginTypeWidget PluginType = "widget"

// WidgetRequest carries the parameters for a single widget computation.
type WidgetRequest struct {
	// Payload is the dashboard-supplied filter/parameter object. Shape is
	// widget-specific; e.g. {lookback_days: 30, severity_filter: ["high"]}.
	Payload map[string]any `json:"payload,omitempty"`

	// CaseID is set when the widget is rendered in a per-case context.
	CaseID string `json:"case_id,omitempty"`

	// TenantID is the calling tenant for multi-tenant deployments.
	TenantID string `json:"tenant_id,omitempty"`
}

// WidgetResult carries the structured output of a widget computation. The
// `Data` map shape is widget-specific and rendered by the front end.
type WidgetResult struct {
	// Data is the renderer-ready payload (series, summary, breakdowns, ...).
	Data map[string]any `json:"data,omitempty"`

	// SampleSize is an optional count of records used in the computation.
	SampleSize int `json:"sample_size,omitempty"`

	// Error is set when the computation failed; the front end should render a
	// fallback panel instead of charts.
	Error string `json:"error,omitempty"`
}

// Widget is the interface every dashboard widget plugin implements.
type Widget interface {
	Plugin

	// Compute runs the widget computation against AiSOC data and returns a
	// renderer-ready payload. Implementations should be idempotent; the same
	// (req, pctx) pair must produce the same output (modulo data freshness).
	Compute(ctx context.Context, req WidgetRequest, pctx PluginContext) (WidgetResult, error)
}
