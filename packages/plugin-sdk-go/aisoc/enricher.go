package aisoc

import "context"

// IndicatorType classifies the type of security indicator being enriched.
type IndicatorType string

const (
	IndicatorIP     IndicatorType = "ip"
	IndicatorDomain IndicatorType = "domain"
	IndicatorURL    IndicatorType = "url"
	IndicatorHash   IndicatorType = "hash"
	IndicatorEmail  IndicatorType = "email"
)

// EnrichmentRequest is the payload sent to an enricher plugin.
type EnrichmentRequest struct {
	IndicatorType  IndicatorType  `json:"indicator_type"`
	IndicatorValue string         `json:"indicator_value"`
	CaseID         string         `json:"case_id,omitempty"`
	Metadata       map[string]any `json:"metadata,omitempty"`
}

// EnrichmentResult holds the enriched data returned by an enricher plugin.
type EnrichmentResult struct {
	IndicatorType  IndicatorType  `json:"indicator_type"`
	IndicatorValue string         `json:"indicator_value"`
	Enrichments    map[string]any `json:"enrichments,omitempty"`
	Tags           []string       `json:"tags,omitempty"`
	// Malicious is a tri-state: nil = unknown, true/false = determined.
	Malicious  *bool          `json:"malicious,omitempty"`
	Confidence *float64       `json:"confidence,omitempty"`
	Raw        map[string]any `json:"raw,omitempty"`
}

// Enricher is implemented by plugins that enrich security indicators.
type Enricher interface {
	Plugin
	Enrich(ctx context.Context, req EnrichmentRequest, pctx PluginContext) (EnrichmentResult, error)
}
