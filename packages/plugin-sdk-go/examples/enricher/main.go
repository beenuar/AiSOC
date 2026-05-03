// Example: a minimal enricher plugin written with the AiSOC Go SDK.
package main

import (
	"context"
	"fmt"
	"log"

	"github.com/beenuar/aisoc/plugin-sdk-go/aisoc"
)

// IPReputationEnricher checks a fictional reputation API.
type IPReputationEnricher struct {
	aisoc.BasePlugin
}

func (e *IPReputationEnricher) Manifest() aisoc.PluginManifest {
	return aisoc.PluginManifest{
		ID:          "example.ip-reputation",
		Name:        "IP Reputation Enricher",
		Version:     "1.0.0",
		Description: "Enriches IP addresses with reputation data",
		Author:      "AiSOC Examples",
		Tags:        []string{"ip", "reputation", "threat-intel"},
		PluginType:  aisoc.PluginTypeEnricher,
	}
}

func (e *IPReputationEnricher) OnLoad(_ context.Context, pctx aisoc.PluginContext) error {
	log.Printf("IPReputationEnricher loaded, api=%s", pctx.APIBaseURL)
	return nil
}

func (e *IPReputationEnricher) Enrich(
	_ context.Context,
	req aisoc.EnrichmentRequest,
	_ aisoc.PluginContext,
) (aisoc.EnrichmentResult, error) {
	// In a real plugin you'd call an external API here.
	malicious := req.IndicatorValue == "192.0.2.1"
	confidence := 0.85
	return aisoc.EnrichmentResult{
		IndicatorType:  req.IndicatorType,
		IndicatorValue: req.IndicatorValue,
		Enrichments: map[string]any{
			"country": "US",
			"asn":     "AS64496",
		},
		Tags:       []string{"reputation-checked"},
		Malicious:  &malicious,
		Confidence: &confidence,
	}, nil
}

func main() {
	ctx := context.Background()
	pctx := aisoc.PluginContext{
		APIBaseURL: "http://localhost:8000",
		APIToken:   "demo-token",
	}

	reg := aisoc.NewRegistry()
	if err := reg.Register(&IPReputationEnricher{}); err != nil {
		log.Fatal(err)
	}
	if err := reg.LoadAll(ctx, pctx); err != nil {
		log.Fatal(err)
	}

	for _, e := range reg.Enrichers() {
		result, err := e.Enrich(ctx, aisoc.EnrichmentRequest{
			IndicatorType:  aisoc.IndicatorIP,
			IndicatorValue: "192.0.2.1",
		}, pctx)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("enricher=%s malicious=%v confidence=%.2f\n",
			e.Manifest().ID, *result.Malicious, *result.Confidence)
	}
}
