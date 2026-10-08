package activity

import (
	"strings"
	"testing"
)

// Real agent strings, as these sources emit them. Several are the reason the
// signature order in useragent.go is load-bearing rather than cosmetic.
func TestParseUserAgentClassifiesRealStrings(t *testing.T) {
	cases := []struct {
		raw          string
		wantFamily   string
		wantCategory ClientCategory
		wantVersion  string
	}{
		// CloudTrail's own userAgent values.
		{"aws-cli/2.15.30 Python/3.11.8 Darwin/23.4.0 source/arm64", "aws-cli", ClientCLI, "2.15.30"},
		{"Boto3/1.34.69 md/Botocore#1.34.69 ua/2.0 os/linux#6.1.0", "Boto3", ClientSDK, "1.34.69"},
		{"aws-sdk-go/1.50.0 (go1.22; linux; amd64)", "aws-sdk-go", ClientSDK, "1.50.0"},
		{"cloudformation.amazonaws.com", "CloudFormation", ClientIaC, ""},
		{"APN/1.0 HashiCorp/1.0 Terraform/1.7.5 (+https://www.terraform.io)", "Terraform", ClientIaC, "1.7.5"},
		{"OpenTofu/1.6.2", "OpenTofu", ClientIaC, "1.6.2"},
		// Kubernetes audit.
		{"kubectl/v1.29.2 (darwin/arm64) kubernetes/4b8e819", "kubectl", ClientCLI, "1.29.2"},
		{"kube-probe/1.29", "kube-probe", ClientInfrastructure, "1.29"},
		// Okta and the console.
		{
			"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
			"Chrome", ClientBrowser, "124.0.0.0",
		},
		{
			"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.2478.51",
			"Edge", ClientBrowser, "124.0.2478.51",
		},
		{"Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0", "Firefox", ClientBrowser, "125.0"},
		// Generic libraries.
		{"python-requests/2.31.0", "python-requests", ClientSDK, "2.31.0"},
		{"Go-http-client/2.0", "Go-http-client", ClientSDK, "2.0"},
		{"curl/8.4.0", "curl", ClientCLI, "8.4.0"},
		// Offensive tooling, which is the whole reason for the category.
		{"Pacu/1.5.1 (https://rhinosecuritylabs.com)", "Pacu", ClientOffensive, ""},
		{"Scout Suite", "ScoutSuite", ClientOffensive, ""},
		{"sqlmap/1.8.3#stable (https://sqlmap.org)", "sqlmap", ClientOffensive, "1.8.3"},
		{"Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)", "Nmap", ClientOffensive, ""},
		// Infrastructure noise, worth labelling so it can be excluded on
		// purpose rather than by a rule nobody wrote down.
		{"ELB-HealthChecker/2.0", "ELB-HealthChecker", ClientInfrastructure, ""},
		{"Prometheus/2.51.1", "Prometheus", ClientInfrastructure, "2.51.1"},
	}

	for _, tc := range cases {
		t.Run(tc.wantFamily, func(t *testing.T) {
			got := ParseUserAgent(tc.raw)
			if got.Family != tc.wantFamily {
				t.Errorf("family = %q, want %q", got.Family, tc.wantFamily)
			}
			if got.Category != tc.wantCategory {
				t.Errorf("category = %q, want %q", got.Category, tc.wantCategory)
			}
			if tc.wantVersion != "" && got.Version != tc.wantVersion {
				t.Errorf("version = %q, want %q", got.Version, tc.wantVersion)
			}
			if got.Raw != tc.raw {
				t.Errorf("the raw string was not kept: %q", got.Raw)
			}
		})
	}
}

// The order of the browser signatures is the whole correctness of that
// block: every one of those strings contains the next. An alphabetical
// reorder would silently reclassify every Edge session as Chrome.
func TestBrowserSignatureOrderIsNotAccidental(t *testing.T) {
	edge := "Mozilla/5.0 AppleWebKit/537.36 Chrome/124.0.0.0 Safari/537.36 Edg/124.0.2478.51"
	if got := ParseUserAgent(edge); got.Family != "Edge" {
		t.Errorf("an Edge string parsed as %q; Edge must precede Chrome, and Chrome Safari", got.Family)
	}
	chrome := "Mozilla/5.0 AppleWebKit/537.36 Chrome/124.0.0.0 Safari/537.36"
	if got := ParseUserAgent(chrome); got.Family != "Chrome" {
		t.Errorf("a Chrome string parsed as %q", got.Family)
	}
	// aws-cli's own string contains Botocore, so the CLI must win.
	cli := "aws-cli/2.15.30 md/Botocore#1.34.69 Python/3.11.8"
	if got := ParseUserAgent(cli); got.Family != "aws-cli" {
		t.Errorf("an aws-cli string parsed as %q; aws-cli must precede Boto3", got.Family)
	}
}

// Offensive tooling that disguises itself as a browser must still be caught,
// which is why every offensive signature precedes every browser one.
func TestOffensiveToolingBeatsABrowserDisguise(t *testing.T) {
	for _, raw := range []string{
		"Mozilla/5.0 (Windows NT 10.0) Chrome/124.0.0.0 Safari/537.36 sqlmap/1.8",
		"Mozilla/5.0 (compatible; Nuclei - Open-source project (github.com/projectdiscovery/nuclei))",
		"Mozilla/5.0 Firefox/125.0 ROADtools",
	} {
		got := ParseUserAgent(raw)
		if got.Category != ClientOffensive {
			t.Errorf("%q classified as %q; a browser prefix must not hide the tool name", raw, got.Category)
		}
	}
}

// An absent user agent and an unrecognised one are different facts. A source
// that sends none should not acquire a client block at all.
func TestAnAbsentAgentIsNotAnUnknownOne(t *testing.T) {
	if got := ParseUserAgent(""); got != (Client{}) {
		t.Errorf("an empty string produced %+v, want the zero Client", got)
	}
	if got := ParseUserAgent("   "); got != (Client{}) {
		t.Errorf("whitespace produced %+v, want the zero Client", got)
	}
	got := ParseUserAgent("SomeInternalTool/4")
	if got.Category != ClientUnknown {
		t.Errorf("an unrecognised agent classified as %q, want unknown", got.Category)
	}
	if got.Raw != "SomeInternalTool/4" {
		t.Errorf("an unrecognised agent lost its raw string: %q", got.Raw)
	}
}

// The header is attacker-chosen and reaches a lake column and a graph
// property.
func TestTheRawStringIsBounded(t *testing.T) {
	got := ParseUserAgent(strings.Repeat("x", 100_000))
	if len(got.Raw) > 512 {
		t.Errorf("a 100,000-character agent was kept at %d characters", len(got.Raw))
	}
}

// A signature that matches nothing is dead weight a reader would still
// trust, and one whose version regex cannot fire is a column that is always
// empty for that family.
func TestEverySignatureIsExercisedByThisSuite(t *testing.T) {
	// Not a coverage proxy: this asserts the table itself is well formed,
	// which is the part a reorder or a bad paste breaks.
	seen := map[string]bool{}
	for _, s := range signatures {
		if s.family == "" {
			t.Error("a signature has no family")
		}
		if seen[s.family] {
			t.Errorf("duplicate signature family %q; the second can never fire", s.family)
		}
		seen[s.family] = true
		if s.pattern == nil {
			t.Errorf("signature %q has no pattern", s.family)
		}
		if s.category == "" || s.category == ClientUnknown {
			t.Errorf("signature %q declares category %q; a matched signature must name a real category", s.family, s.category)
		}
	}
}
