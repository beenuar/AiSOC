package telemetry

import (
	"context"
	"testing"
)

// Ingest is the pipeline's front door. Tracing that can refuse traffic, or
// that silently emits into nothing, is worse than no tracing — so these
// tests are about the disabled and misconfigured paths rather than the
// happy one.

func TestDisabledWhenNoEndpointConfigured(t *testing.T) {
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "")

	shutdown, err := Setup(context.Background())
	if err != nil {
		t.Fatalf("no endpoint should not be an error: %v", err)
	}
	if shutdown == nil {
		t.Fatal("shutdown must be non-nil so the caller's defer is unconditional")
	}
	if err := shutdown(context.Background()); err != nil {
		t.Fatalf("shutting down a disabled tracer should be a no-op: %v", err)
	}
}

func TestTracerIsUsableBeforeSetup(t *testing.T) {
	// A span started before Setup must not panic. Ordering bugs in
	// startup are otherwise fatal rather than merely untraced.
	_, span := Tracer("test").Start(context.Background(), "pre-setup")
	span.End()
}

func TestStripScheme(t *testing.T) {
	// The Python services take a URL in the same variable and the gRPC
	// exporter wants host:port. Accepting both is the difference between
	// one env var and two.
	cases := map[string]string{
		"http://otel-collector:4317":  "otel-collector:4317",
		"https://otel-collector:4317": "otel-collector:4317",
		"grpc://collector:4317":       "collector:4317",
		"otel-collector:4317":         "otel-collector:4317",
		"http://collector:4317/":      "collector:4317",
	}
	for input, want := range cases {
		if got := stripScheme(input); got != want {
			t.Errorf("stripScheme(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestParseRatioClamps(t *testing.T) {
	// A sampler arg outside [0,1] is a typo, not an instruction. Passing
	// it through would either disable sampling or panic the SDK.
	cases := map[string]float64{
		"0":    0,
		"0.25": 0.25,
		"1":    1,
		"-1":   0,
		"7":    1,
	}
	for input, want := range cases {
		got, err := parseRatio(input)
		if err != nil {
			t.Fatalf("parseRatio(%q): %v", input, err)
		}
		if got != want {
			t.Errorf("parseRatio(%q) = %v, want %v", input, got, want)
		}
	}
	if _, err := parseRatio("not-a-number"); err == nil {
		t.Error("a non-numeric sampler arg should error, not default silently")
	}
}

func TestSamplerFallsBackOnGarbage(t *testing.T) {
	// The fallback matters more than the parse: an unparseable value must
	// leave sampling at the default, not at zero. Zero looks identical to
	// "tracing is broken".
	t.Setenv("OTEL_TRACES_SAMPLER_ARG", "not-a-number")
	if sampler() == nil {
		t.Fatal("sampler must never be nil")
	}
}

func TestServiceNameIsOverridable(t *testing.T) {
	t.Setenv("OTEL_SERVICE_NAME", "")
	if got := serviceName(); got != defaultServiceName {
		t.Errorf("default service name = %q, want %q", got, defaultServiceName)
	}
	t.Setenv("OTEL_SERVICE_NAME", "aisoc-ingest-canary")
	if got := serviceName(); got != "aisoc-ingest-canary" {
		t.Errorf("override ignored: got %q", got)
	}
}
