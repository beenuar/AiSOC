# aisoc-plugin-sdk · Go

The official Go SDK for building AiSOC plugins — custom enrichers, response
actions, and data-source connectors.

## Installation

```bash
go get github.com/beenuar/aisoc/plugin-sdk-go
```

## Quick Start

### Enricher

```go
package main

import (
    "context"
    "github.com/beenuar/aisoc/plugin-sdk-go/aisoc"
)

type VTEnricher struct{ aisoc.BasePlugin }

func (e *VTEnricher) Manifest() aisoc.PluginManifest {
    return aisoc.PluginManifest{
        ID:         "myorg.virustotal",
        Name:       "VirusTotal Enricher",
        Version:    "1.0.0",
        PluginType: aisoc.PluginTypeEnricher,
    }
}

func (e *VTEnricher) Enrich(
    ctx context.Context,
    req aisoc.EnrichmentRequest,
    pctx aisoc.PluginContext,
) (aisoc.EnrichmentResult, error) {
    // call VirusTotal API here …
    malicious := false
    confidence := 0.95
    return aisoc.EnrichmentResult{
        IndicatorType:  req.IndicatorType,
        IndicatorValue: req.IndicatorValue,
        Enrichments:    map[string]any{"vt_score": 72},
        Malicious:      &malicious,
        Confidence:     &confidence,
    }, nil
}
```

### Response Action

```go
type BlockIPAction struct{ aisoc.BasePlugin }

func (a *BlockIPAction) Manifest() aisoc.PluginManifest {
    return aisoc.PluginManifest{
        ID: "myorg.block-ip", Name: "Block IP",
        Version: "1.0.0", PluginType: aisoc.PluginTypeAction,
    }
}

func (a *BlockIPAction) SupportedActions() []string { return []string{"block_ip"} }

func (a *BlockIPAction) Execute(
    ctx context.Context,
    req aisoc.ActionRequest,
    pctx aisoc.PluginContext,
) (aisoc.ActionResult, error) {
    if req.DryRun {
        return aisoc.ActionResult{ActionID: req.ActionID, Success: true, DryRun: true,
            Summary: "Would block " + req.Params["ip"].(string)}, nil
    }
    // … firewall API call …
    return aisoc.ActionResult{ActionID: req.ActionID, Success: true, Summary: "Blocked"}, nil
}
```

### Plugin Registry

```go
reg := aisoc.NewRegistry()
reg.Register(&VTEnricher{})
reg.Register(&BlockIPAction{})

pctx := aisoc.PluginContext{APIBaseURL: "http://api:8000", APIToken: "…"}
if err := reg.LoadAll(ctx, pctx); err != nil {
    log.Fatal(err)
}

for _, e := range reg.Enrichers() {
    result, _ := e.Enrich(ctx, req, pctx)
    // …
}
```

## Running the Example

```bash
cd examples/enricher
go run main.go
```

## Development

```bash
go test ./...
go vet ./...
```

## License

MIT — see [LICENSE](../../LICENSE).
