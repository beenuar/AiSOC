// Package telemetry wires OpenTelemetry tracing for the ingest service.
//
// `api`, `agents`, `ueba` and `honeytokens` were instrumented; `ingest`
// (Go) and `realtime` (TypeScript) were not — and those two are the ends
// of the Kafka spine. A trace therefore began at the API and stopped at
// the pipeline boundary, which is precisely where the interesting latency
// is: an event that takes four seconds to become an alert is invisible if
// nothing spans the part that took four seconds.
//
// Two decisions worth stating.
//
// Tracing is off unless an endpoint is configured. Defaulting it on sent
// every span into a connection error on deployments with no collector,
// which fills the logs and makes a missing trace ambiguous between "no
// span" and "no collector" — the failure the compose collector comment
// already records.
//
// Shutdown flushes with a bounded timeout. An unflushed exporter drops
// the spans from the final seconds before a restart, and those are
// disproportionately the ones someone is looking for.
package telemetry

import (
	"context"
	"os"
	"strconv"
	"strings"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
	"go.opentelemetry.io/otel/trace"
	"go.opentelemetry.io/otel/trace/noop"
)

const defaultServiceName = "aisoc-ingest"

// Shutdown flushes pending spans. Always non-nil, so a caller never has to
// nil-check before deferring it.
type Shutdown func(context.Context) error

// Setup configures the global tracer provider from the environment.
//
// Returns a no-op shutdown when tracing is disabled, so the caller's
// `defer shutdown(ctx)` is unconditional and cannot be forgotten on the
// disabled path.
func Setup(ctx context.Context) (Shutdown, error) {
	endpoint := strings.TrimSpace(os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT"))
	if endpoint == "" {
		// Not an error. A deployment without a collector is a supported
		// configuration, and emitting spans nobody collects is worse than
		// emitting none.
		otel.SetTracerProvider(noop.NewTracerProvider())
		return func(context.Context) error { return nil }, nil
	}

	exporter, err := otlptracegrpc.New(
		ctx,
		otlptracegrpc.WithEndpoint(stripScheme(endpoint)),
		// Plaintext to an in-cluster collector, matching the Python
		// services. A collector reachable over the public internet would
		// need TLS, and that is a deployment decision rather than a
		// default.
		otlptracegrpc.WithInsecure(),
	)
	if err != nil {
		return func(context.Context) error { return nil }, err
	}

	res, err := resource.Merge(
		resource.Default(),
		resource.NewWithAttributes(
			semconv.SchemaURL,
			semconv.ServiceName(serviceName()),
			attribute.String("deployment.environment", environment()),
		),
	)
	if err != nil {
		// A resource merge failure is a schema mismatch, not a reason to
		// run untraced. Fall back to the default resource.
		res = resource.Default()
	}

	provider := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exporter),
		sdktrace.WithResource(res),
		sdktrace.WithSampler(sampler()),
	)
	otel.SetTracerProvider(provider)

	// W3C by default so a trace started by the API continues here. Without
	// this the ingest spans form their own disconnected trace, which looks
	// like instrumentation and is not.
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	))

	return func(shutdownCtx context.Context) error {
		flushCtx, cancel := context.WithTimeout(shutdownCtx, 5*time.Second)
		defer cancel()
		return provider.Shutdown(flushCtx)
	}, nil
}

// Tracer returns a named tracer. Safe before Setup: the global provider
// defaults to a no-op.
func Tracer(name string) trace.Tracer {
	return otel.Tracer(name)
}

func serviceName() string {
	if name := strings.TrimSpace(os.Getenv("OTEL_SERVICE_NAME")); name != "" {
		return name
	}
	return defaultServiceName
}

func environment() string {
	for _, key := range []string{"AISOC_ENV", "ENVIRONMENT"} {
		if value := strings.TrimSpace(os.Getenv(key)); value != "" {
			return value
		}
	}
	return "unknown"
}

// sampler honours OTEL_TRACES_SAMPLER_ARG as a ratio.
//
// Ingest is the highest-volume service in the platform, so head sampling
// is the difference between a usable trace store and one that costs more
// than the pipeline. Parent-based so a sampled API request stays sampled
// all the way through rather than being re-decided here — a trace sampled
// at one hop and dropped at the next is worse than not sampling at all.
func sampler() sdktrace.Sampler {
	ratio := 0.05
	if raw := strings.TrimSpace(os.Getenv("OTEL_TRACES_SAMPLER_ARG")); raw != "" {
		if parsed, err := parseRatio(raw); err == nil {
			ratio = parsed
		}
	}
	return sdktrace.ParentBased(sdktrace.TraceIDRatioBased(ratio))
}

func parseRatio(raw string) (float64, error) {
	value, err := strconv.ParseFloat(raw, 64)
	if err != nil {
		return 0, err
	}
	if value < 0 {
		value = 0
	}
	if value > 1 {
		value = 1
	}
	return value, nil
}

// stripScheme normalises an endpoint for the gRPC exporter, which wants
// host:port rather than a URL. The Python services accept the URL form and
// the same env var is shared, so accepting both is the difference between
// one variable and two.
func stripScheme(endpoint string) string {
	for _, prefix := range []string{"http://", "https://", "grpc://"} {
		endpoint = strings.TrimPrefix(endpoint, prefix)
	}
	return strings.TrimSuffix(endpoint, "/")
}
