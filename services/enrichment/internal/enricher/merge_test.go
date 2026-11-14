package enricher

import (
	"slices"
	"testing"
)

func TestMergeKeepsWhoisFromSourceWithoutRisk(t *testing.T) {
	scored := &EnrichmentResult{RiskScore: 40, Tags: []string{"vendor:phishing"}}
	facts := &EnrichmentResult{
		Whois:      map[string]string{"registrar": "Example Registrar, Inc."},
		DNSRecords: []string{"A 192.0.2.10", "NS ns1.example.net."},
	}

	merged := mergeResults(IOCTypeDomain, "example.com", []*EnrichmentResult{scored, facts})

	if merged.RiskScore != 40 {
		t.Errorf("RiskScore = %v, want 40", merged.RiskScore)
	}
	if merged.Whois["registrar"] != "Example Registrar, Inc." {
		t.Errorf("Whois = %v, want the registrar from the source that had one", merged.Whois)
	}
	if !slices.Equal(merged.DNSRecords, facts.DNSRecords) {
		t.Errorf("DNSRecords = %q", merged.DNSRecords)
	}
}

func TestMergePrefersWhoisOfHighestRiskSource(t *testing.T) {
	facts := &EnrichmentResult{Whois: map[string]string{"registrar": "from-facts"}}
	scored := &EnrichmentResult{RiskScore: 70, Whois: map[string]string{"registrar": "from-scored"}}

	merged := mergeResults(IOCTypeDomain, "example.com", []*EnrichmentResult{facts, scored})

	if merged.Whois["registrar"] != "from-scored" {
		t.Errorf("Whois = %v, want the highest-risk source's", merged.Whois)
	}
}

func TestMergeDeduplicatesDNSRecords(t *testing.T) {
	a := &EnrichmentResult{DNSRecords: []string{"A 192.0.2.10", "MX 10 mail.example.com."}}
	b := &EnrichmentResult{DNSRecords: []string{"A 192.0.2.10", "A 192.0.2.11"}}

	merged := mergeResults(IOCTypeDomain, "example.com", []*EnrichmentResult{a, b})

	want := []string{"A 192.0.2.10", "MX 10 mail.example.com.", "A 192.0.2.11"}
	if !slices.Equal(merged.DNSRecords, want) {
		t.Errorf("DNSRecords = %q, want %q", merged.DNSRecords, want)
	}
}
