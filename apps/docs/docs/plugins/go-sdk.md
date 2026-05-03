---
sidebar_position: 3
---

# Go Plugin SDK

## Installation

```bash
go get github.com/beenuar/aisoc/plugin-sdk-go
```

## Quick Start: Enricher

```go
package main

import (
    "context"
    "github.com/beenuar/aisoc/plugin-sdk-go/aisoc"
)

type IPReputationEnricher struct {
    aisoc.BasePlugin
}

func (e *IPReputationEnricher) Manifest() aisoc.PluginManifest {
    return aisoc.PluginManifest{
        ID:          "myorg.ip-reputation",
        Name:        "IP Reputation",
        Version:     "1.0.0",
        PluginType:  aisoc.PluginTypeEnricher,
    }
}

func (e *IPReputationEnricher) Enrich(
    ctx context.Context,
    req aisoc.EnrichmentRequest,
    pluginCtx aisoc.PluginContext,
) (aisoc.EnrichmentResult, error) {
    return aisoc.EnrichmentResult{
        IndicatorType:  req.IndicatorType,
        IndicatorValue: req.IndicatorValue,
        Enrichments:    map[string]any{"score": 42},
        Malicious:      true,
        Confidence:     0.87,
    }, nil
}

func main() {
    registry := aisoc.NewRegistry()
    plugin := &IPReputationEnricher{}
    registry.Register(plugin)
    ctx := aisoc.PluginContext{APIBaseURL: "http://localhost:8000"}
    registry.LoadAll(context.Background(), ctx)
}
```

## Quick Start: Action

```go
type BlockIPAction struct {
    aisoc.BasePlugin
}

func (a *BlockIPAction) Manifest() aisoc.PluginManifest {
    return aisoc.PluginManifest{
        ID:         "myorg.block-ip",
        Name:       "Block IP",
        Version:    "1.0.0",
        PluginType: aisoc.PluginTypeAction,
    }
}

func (a *BlockIPAction) SupportedActions() []string {
    return []string{"block_ip"}
}

func (a *BlockIPAction) Execute(
    ctx context.Context,
    req aisoc.ActionRequest,
    pluginCtx aisoc.PluginContext,
) (aisoc.ActionResult, error) {
    if req.DryRun {
        return aisoc.ActionResult{
            ActionID: req.ActionID, Success: true, DryRun: true,
        }, nil
    }
    return aisoc.ActionResult{ActionID: req.ActionID, Success: true}, nil
}
```

## Development

```bash
cd packages/plugin-sdk-go
go test ./...
go vet ./...
```
