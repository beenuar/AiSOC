package aisoc

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
)

// Registry is a thread-safe store of loaded plugin instances.
type Registry struct {
	mu      sync.RWMutex
	plugins map[string]Plugin
}

// NewRegistry creates an empty plugin registry.
func NewRegistry() *Registry {
	return &Registry{plugins: make(map[string]Plugin)}
}

// Register adds a plugin to the registry.
// Returns an error if a plugin with the same ID is already registered.
func (r *Registry) Register(p Plugin) error {
	id := p.Manifest().ID
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.plugins[id]; exists {
		return fmt.Errorf("plugin %q already registered", id)
	}
	r.plugins[id] = p
	slog.Info("plugin registered", "id", id, "type", p.Manifest().PluginType)
	return nil
}

// Unregister removes a plugin from the registry by ID.
func (r *Registry) Unregister(id string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.plugins, id)
}

// Get returns the plugin with the given ID, or nil if not found.
func (r *Registry) Get(id string) Plugin {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.plugins[id]
}

// LoadAll calls OnLoad on every registered plugin.
func (r *Registry) LoadAll(ctx context.Context, pctx PluginContext) error {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for id, p := range r.plugins {
		if err := p.OnLoad(ctx, pctx); err != nil {
			return fmt.Errorf("loading plugin %q: %w", id, err)
		}
		slog.Info("plugin loaded", "id", id)
	}
	return nil
}

// UnloadAll calls OnUnload on every registered plugin.
func (r *Registry) UnloadAll(ctx context.Context) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for id, p := range r.plugins {
		if err := p.OnUnload(ctx); err != nil {
			slog.Error("plugin unload failed", "id", id, "err", err)
		}
	}
}

// Enrichers returns all registered plugins that implement the Enricher interface.
func (r *Registry) Enrichers() []Enricher {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var out []Enricher
	for _, p := range r.plugins {
		if e, ok := p.(Enricher); ok {
			out = append(out, e)
		}
	}
	return out
}

// Actions returns all registered plugins that implement the Action interface.
func (r *Registry) Actions() []Action {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var out []Action
	for _, p := range r.plugins {
		if a, ok := p.(Action); ok {
			out = append(out, a)
		}
	}
	return out
}

// Connectors returns all registered plugins that implement the Connector interface.
func (r *Registry) Connectors() []Connector {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var out []Connector
	for _, p := range r.plugins {
		if c, ok := p.(Connector); ok {
			out = append(out, c)
		}
	}
	return out
}

// Widgets returns all registered plugins that implement the Widget interface.
func (r *Registry) Widgets() []Widget {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var out []Widget
	for _, p := range r.plugins {
		if w, ok := p.(Widget); ok {
			out = append(out, w)
		}
	}
	return out
}

// Len returns the total number of registered plugins.
func (r *Registry) Len() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.plugins)
}
