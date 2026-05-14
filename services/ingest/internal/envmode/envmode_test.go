package envmode

import "testing"

func TestNormalize(t *testing.T) {
	cases := map[string]string{
		"":              "",
		"Development":   "development",
		"  PRODUCTION ": "production",
		"\tDev\n":       "dev",
	}
	for in, want := range cases {
		if got := Normalize(in); got != want {
			t.Errorf("Normalize(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestIsDev(t *testing.T) {
	dev := []string{"development", "DEV", "local", "Demo", " test "}
	prod := []string{"production", "prod", "staging", "qa", "", "random"}

	for _, v := range dev {
		if !IsDev(v) {
			t.Errorf("IsDev(%q) = false, want true", v)
		}
	}
	for _, v := range prod {
		if IsDev(v) {
			t.Errorf("IsDev(%q) = true, want false", v)
		}
	}
}

func TestCurrentPrefersENVOverENVIRONMENT(t *testing.T) {
	t.Setenv("ENV", "production")
	t.Setenv("ENVIRONMENT", "development")
	if got := Current(); got != "production" {
		t.Fatalf("Current() = %q, want production (ENV wins)", got)
	}
}

func TestCurrentFallsBackToENVIRONMENT(t *testing.T) {
	t.Setenv("ENV", "")
	t.Setenv("ENVIRONMENT", "Development")
	if got := Current(); got != "development" {
		t.Fatalf("Current() = %q, want development (ENVIRONMENT fallback)", got)
	}
}

func TestCurrentEmptyWhenNeitherSet(t *testing.T) {
	t.Setenv("ENV", "")
	t.Setenv("ENVIRONMENT", "")
	if got := Current(); got != "" {
		t.Fatalf("Current() = %q, want empty string", got)
	}
}

func TestIsDevRuntime(t *testing.T) {
	t.Setenv("ENV", "")
	t.Setenv("ENVIRONMENT", "production")
	if IsDevRuntime() {
		t.Fatalf("IsDevRuntime() = true, want false for production via ENVIRONMENT alias")
	}

	t.Setenv("ENV", "demo")
	if !IsDevRuntime() {
		t.Fatalf("IsDevRuntime() = false, want true for ENV=demo")
	}

	// ENVIRONMENT=development with ENV unset is a previously-buggy case:
	// the old Go check only looked at ENV, so it would treat this as
	// production. The unified helper should treat it as dev to match
	// the Python settings model.
	t.Setenv("ENV", "")
	t.Setenv("ENVIRONMENT", "development")
	if !IsDevRuntime() {
		t.Fatalf("IsDevRuntime() = false, want true when only ENVIRONMENT=development is set")
	}
}
