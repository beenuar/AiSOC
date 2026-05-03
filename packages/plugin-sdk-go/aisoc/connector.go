package aisoc

import "context"

// ConnectorConfig holds per-instance configuration for a connector plugin.
type ConnectorConfig struct {
	ConnectorID           string         `json:"connector_id"`
	Enabled               bool           `json:"enabled"`
	PollIntervalSeconds   int            `json:"poll_interval_seconds"`
	Extra                 map[string]any `json:"extra,omitempty"`
}

// Connector is implemented by plugins that ingest events from external data sources.
type Connector interface {
	Plugin
	// TestConnection verifies that the upstream data source is reachable.
	TestConnection(ctx context.Context, pctx PluginContext) (bool, error)
	// FetchEvents returns a channel of normalised events from the upstream source.
	// The caller is responsible for draining and closing the channel.
	// since is an ISO-8601 timestamp cursor; only events after this point should be returned.
	FetchEvents(ctx context.Context, pctx PluginContext, since string) (<-chan map[string]any, error)
}
