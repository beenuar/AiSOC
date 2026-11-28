package config

import (
	"fmt"
	"os"
)

// RetiredProvider records an enrichment provider AiSOC used to ship and has
// removed because the vendor API behind it stopped answering.
//
// The registry exists so the removal is not silent. An operator who configured
// the provider before it was retired is still carrying its credentials; with
// the client gone those variables would simply be ignored, and an IOC that
// returns no provider verdict looks exactly like an IOC nothing had to say
// about. Naming the retirement at startup keeps that distinction visible.
type RetiredProvider struct {
	// Name is the provider as the README and the startup log used to call it.
	Name string
	// EnvVars are the variables that configured it.
	EnvVars []string
	// Reason states what actually happened to the vendor API.
	Reason string
	// Successor names the vendor's own replacement, or is empty if there is
	// none. It is informational: AiSOC does not implement it today.
	Successor string
}

// RetiredProviders is the full set. Entries are kept after removal; deleting
// one would make the next upgrade silent again.
var RetiredProviders = []RetiredProvider{
	{
		Name:    "RiskIQ PassiveTotal",
		EnvVars: []string{"RISKIQ_USERNAME", "RISKIQ_API_KEY"},
		Reason: "the api.passivetotal.org API no longer answers: RiskIQ was acquired by " +
			"Microsoft and the host is now a CNAME to www.riskiq.com behind Azure Front Door, " +
			"which presents a *.azureedge.net certificate, so every request fails the TLS " +
			"handshake before the credentials are sent",
		Successor: "Microsoft Defender Threat Intelligence, via the Microsoft Graph " +
			"threatIntelligence APIs — a different auth model (Entra ID OAuth2 with " +
			"ThreatIntelligence.Read.All) and a different schema, so it is not a drop-in " +
			"replacement and AiSOC does not implement it yet",
	},
}

// RetiredProviderNotices returns one human-readable notice per retired
// provider whose credentials are still set in the environment. It returns
// nothing when nothing is configured, and never echoes a credential value.
func RetiredProviderNotices() []string {
	var notices []string
	for _, p := range RetiredProviders {
		var stillSet []string
		for _, name := range p.EnvVars {
			if os.Getenv(name) != "" {
				stillSet = append(stillSet, name)
			}
		}
		if len(stillSet) == 0 {
			continue
		}
		notice := fmt.Sprintf(
			"%s is configured (%v) but the provider has been removed: %s. Unset these variables.",
			p.Name, stillSet, p.Reason,
		)
		if p.Successor != "" {
			notice += " The vendor's named successor is " + p.Successor + "."
		}
		notices = append(notices, notice)
	}
	return notices
}
