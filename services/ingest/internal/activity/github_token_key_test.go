package activity

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// The GitHub token join key crosses a language boundary, and the two sides
// normalise differently by default.
//
// Go writes `hashed_token` into the session projection with
// `strings.TrimSpace` and no case folding, because the value is a digest and
// case is significant. Python's `services/fusion/app/services/baselines.py`
// resolves nearly every other field through a helper that lowercases, which
// is right for a username and wrong for this. Routing the token through that
// helper would produce a baseline key that never joins to the session this
// package wrote — on every GitHub event, silently, with no error anywhere.
//
// This file and `services/fusion/tests/test_github_token_key_parity.py` read
// the same committed fixture and assert the same output, so neither side can
// change the normalisation alone.
const tokenKeyFixture = "testdata/github_token_key.json"

type tokenKeyCase struct {
	Name        string `json:"name"`
	HashedToken any    `json:"hashed_token"`
	Expected    string `json:"expected_key"`
	Why         string `json:"why"`
}

func loadTokenKeyCases(t *testing.T) []tokenKeyCase {
	t.Helper()
	raw, err := os.ReadFile(filepath.Clean(tokenKeyFixture))
	if err != nil {
		t.Fatalf("reading %s: %v", tokenKeyFixture, err)
	}
	var cases []tokenKeyCase
	if err := json.Unmarshal(raw, &cases); err != nil {
		t.Fatalf("parsing %s: %v", tokenKeyFixture, err)
	}
	if len(cases) == 0 {
		// An empty fixture would make every assertion below vacuous, which
		// is the shape of gate this repository keeps rediscovering.
		t.Fatalf("%s contains no cases", tokenKeyFixture)
	}
	return cases
}

func TestGitHubSessionKeyMatchesTheSharedFixture(t *testing.T) {
	for _, tc := range loadTokenKeyCases(t) {
		t.Run(tc.Name, func(t *testing.T) {
			vendor := map[string]any{"actor": "alice"}
			if tc.HashedToken != nil {
				vendor["hashed_token"] = tc.HashedToken
			}
			got := githubSession(vendor)
			if got.Key != tc.Expected {
				t.Fatalf("key = %q, want %q (%s)", got.Key, tc.Expected, tc.Why)
			}
			if tc.Expected != "" && got.KeySource != "hashed_token" {
				t.Fatalf("key_source = %q, want %q", got.KeySource, "hashed_token")
			}
		})
	}
}

func TestGitHubSessionKeyPreservesCase(t *testing.T) {
	// Stated separately from the fixture so the property survives somebody
	// pruning the fixture: lowercasing a digest produces a different
	// credential, not a tidier spelling of the same one.
	mixed := "AbC123+/xyz="
	if got := githubSession(map[string]any{"hashed_token": mixed}).Key; got != mixed {
		t.Fatalf("key = %q, want %q — case must be preserved", got, mixed)
	}
}
