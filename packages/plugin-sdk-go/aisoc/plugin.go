// Package aisoc provides the core types and interfaces for AiSOC plugins.
package aisoc

import "context"

// PluginType enumerates the supported plugin categories.
type PluginType string

const (
	PluginTypeEnricher  PluginType = "enricher"
	PluginTypeAction    PluginType = "action"
	PluginTypeConnector PluginType = "connector"
)

// PluginManifest describes a plugin's identity and capabilities.
type PluginManifest struct {
	ID          string     `json:"id"`
	Name        string     `json:"name"`
	Version     string     `json:"version"`
	Description string     `json:"description,omitempty"`
	Author      string     `json:"author,omitempty"`
	Tags        []string   `json:"tags,omitempty"`
	PluginType  PluginType `json:"plugin_type"`
}

// PluginContext carries runtime credentials and configuration for each invocation.
type PluginContext struct {
	APIBaseURL string         `json:"api_base_url"`
	APIToken   string         `json:"api_token"`
	Config     map[string]any `json:"config"`
}

// PluginResult is a generic wrapper for plugin output.
type PluginResult struct {
	Success bool           `json:"success"`
	Data    map[string]any `json:"data,omitempty"`
	Error   string         `json:"error,omitempty"`
}

// Plugin is the base interface that every AiSOC plugin must implement.
type Plugin interface {
	// Manifest returns static metadata about the plugin.
	Manifest() PluginManifest

	// OnLoad is called once when the plugin is registered and loaded.
	// Implementations should initialise clients, validate config, etc.
	OnLoad(ctx context.Context, pctx PluginContext) error

	// OnUnload is called when the plugin is removed from the registry.
	// Implementations should close connections and release resources.
	OnUnload(ctx context.Context) error
}

// BasePlugin provides a no-op implementation of OnLoad/OnUnload so concrete
// plugin types only need to implement the logic they care about.
type BasePlugin struct{}

func (BasePlugin) OnLoad(_ context.Context, _ PluginContext) error { return nil }
func (BasePlugin) OnUnload(_ context.Context) error                { return nil }
