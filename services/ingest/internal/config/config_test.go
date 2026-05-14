// Package config tests cover the JWT_SECRET dev-mode gate. The
// pre-H-8 implementation accepted only ``ENV=development``; these
// cases pin the new behaviour so ``ENVIRONMENT=development`` (the
// alias every other service honours) and the rest of the
// development-class allow-list keep working.
package config

import (
	"os"
	"testing"
)

// withEnv resets a process env var for the duration of a subtest,
// restoring whatever was there before. Tests run sequentially because
// they manipulate shared process state.
func withEnv(t *testing.T, key, value string) {
	t.Helper()
	prev, had := os.LookupEnv(key)
	if value == "" {
		if err := os.Unsetenv(key); err != nil {
			t.Fatalf("unset %s: %v", key, err)
		}
	} else {
		if err := os.Setenv(key, value); err != nil {
			t.Fatalf("set %s=%q: %v", key, value, err)
		}
	}
	t.Cleanup(func() {
		if had {
			_ = os.Setenv(key, prev)
		} else {
			_ = os.Unsetenv(key)
		}
	})
}

func TestLoad_DevEnvAllowsMissingJWTSecret(t *testing.T) {
	cases := []struct {
		name   string
		envKey string
		envVal string
	}{
		{"ENV=development", "ENV", "development"},
		{"ENV=Dev (mixed case)", "ENV", "Dev"},
		{"ENV=local", "ENV", "local"},
		{"ENV=test", "ENV", "test"},
		{"ENVIRONMENT=development alias (no ENV)", "ENVIRONMENT", "development"},
		{"ENVIRONMENT=demo (no ENV)", "ENVIRONMENT", "demo"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Always clear both names before applying the case so a
			// stale ``ENV=production`` from the parent shell can't
			// swamp the ``ENVIRONMENT`` alias under test.
			withEnv(t, "ENV", "")
			withEnv(t, "ENVIRONMENT", "")
			withEnv(t, "JWT_SECRET", "")
			withEnv(t, tc.envKey, tc.envVal)

			cfg, err := Load()
			if err != nil {
				t.Fatalf("expected Load() to succeed in dev env %s=%s, got %v", tc.envKey, tc.envVal, err)
			}
			if cfg == nil {
				t.Fatalf("expected cfg, got nil")
			}
			if cfg.JWTSecret != "" {
				t.Fatalf("expected empty JWTSecret in dev, got %q", cfg.JWTSecret)
			}
		})
	}
}

func TestLoad_NonDevEnvRequiresJWTSecret(t *testing.T) {
	cases := []struct {
		name   string
		envKey string
		envVal string
	}{
		{"ENV=production", "ENV", "production"},
		{"ENVIRONMENT=production alias", "ENVIRONMENT", "production"},
		{"ENV=staging", "ENV", "staging"},
		{"ENV and ENVIRONMENT both unset (defaults to non-dev)", "", ""},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			withEnv(t, "ENV", "")
			withEnv(t, "ENVIRONMENT", "")
			withEnv(t, "JWT_SECRET", "")
			if tc.envKey != "" {
				withEnv(t, tc.envKey, tc.envVal)
			}

			_, err := Load()
			if err == nil {
				t.Fatalf("expected Load() to fail when JWT_SECRET is empty in env %s=%q", tc.envKey, tc.envVal)
			}
		})
	}
}

func TestLoad_NonDevEnvWithJWTSecretSucceeds(t *testing.T) {
	withEnv(t, "ENV", "production")
	withEnv(t, "ENVIRONMENT", "")
	withEnv(t, "JWT_SECRET", "test-secret-not-real")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() failed in production with JWT_SECRET set: %v", err)
	}
	if cfg.JWTSecret != "test-secret-not-real" {
		t.Fatalf("JWTSecret not threaded through: got %q", cfg.JWTSecret)
	}
}

func TestLoad_ENVTakesPrecedenceOverENVIRONMENT(t *testing.T) {
	// If both are set, ``ENV`` wins, matching envmode.Current(). The
	// pre-H-8 code already had this implicit behaviour because it
	// only looked at ENV; the test pins it now that ENVIRONMENT is
	// also consulted.
	withEnv(t, "ENV", "production")
	withEnv(t, "ENVIRONMENT", "development")
	withEnv(t, "JWT_SECRET", "")

	if _, err := Load(); err == nil {
		t.Fatalf("expected Load() to fail: ENV=production should override ENVIRONMENT=development")
	}
}
