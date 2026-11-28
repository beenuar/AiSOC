package config

import (
	"strings"
	"testing"
)

// An operator who configured RiskIQ before it was retired must be told the
// provider is gone. Dropping the variables silently would turn a loud
// per-request failure into an absence that reads like a clean result.

func TestRetiredProviderNoticesReportsStillSetCredentials(t *testing.T) {
	t.Setenv("RISKIQ_USERNAME", "analyst")
	t.Setenv("RISKIQ_API_KEY", "sekrit-riskiq-key")

	notices := RetiredProviderNotices()
	if len(notices) != 1 {
		t.Fatalf("expected exactly one notice, got %d: %v", len(notices), notices)
	}

	notice := notices[0]
	for _, want := range []string{"RISKIQ_USERNAME", "RISKIQ_API_KEY", "Defender Threat Intelligence"} {
		if !strings.Contains(notice, want) {
			t.Errorf("notice should mention %q, got: %s", want, notice)
		}
	}
	if strings.Contains(notice, "sekrit-riskiq-key") {
		t.Errorf("notice must never echo the credential value: %s", notice)
	}
}

func TestRetiredProviderNoticesSilentWhenUnset(t *testing.T) {
	t.Setenv("RISKIQ_USERNAME", "")
	t.Setenv("RISKIQ_API_KEY", "")

	if notices := RetiredProviderNotices(); len(notices) != 0 {
		t.Errorf("expected no notices when nothing is configured, got: %v", notices)
	}
}

func TestRetiredProviderNoticesFireOnEitherVariable(t *testing.T) {
	t.Setenv("RISKIQ_USERNAME", "")
	t.Setenv("RISKIQ_API_KEY", "sekrit-riskiq-key")

	if notices := RetiredProviderNotices(); len(notices) != 1 {
		t.Errorf("a single leftover variable must still warn, got: %v", notices)
	}
}

// Load must no longer carry the retired provider's credentials into the
// service configuration.
func TestLoadDoesNotCarryRetiredCredentials(t *testing.T) {
	t.Setenv("RISKIQ_USERNAME", "analyst")
	t.Setenv("RISKIQ_API_KEY", "sekrit-riskiq-key")

	cfg := Load()
	if cfg == nil {
		t.Fatal("Load returned nil")
	}
	// A compile-time guarantee would be better, but the field is gone, so the
	// only thing left to assert is that nothing reintroduced it by value.
	if strings.Contains(cfg.AnomaliAPIKey+cfg.DomainToolsAPIKey+cfg.CybleAPIKey, "sekrit-riskiq-key") {
		t.Error("a retired credential leaked into another provider's slot")
	}
}
