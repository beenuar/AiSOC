// Package server sets up the HTTP router and server
package server

import (
	"context"
	"crypto/subtle"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/beenuar/aisoc/services/ingest/internal/config"
	"github.com/beenuar/aisoc/services/ingest/internal/envmode"
	"github.com/beenuar/aisoc/services/ingest/internal/graph_ws"
	"github.com/beenuar/aisoc/services/ingest/internal/handler"
	"github.com/beenuar/aisoc/services/ingest/internal/inbox"
	"github.com/beenuar/aisoc/services/ingest/internal/otlp"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/rs/zerolog/log"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
)

// resolveCORSOrigins mirrors the shared Python helper in services/api/app/core/cors.py:
// it reads “AISOC_CORS_ORIGINS“ (canonical) and falls back to “CORS_ORIGINS“
// (legacy). When both are empty the default list keeps local dev usable. We do not
// allow wildcard “*“ combined with credentials here because /v1/ingest doesn't
// carry browser cookies, but operators can still tighten the allow-list per deploy
// without touching code by setting AISOC_CORS_ORIGINS.
func resolveCORSOrigins() []string {
	for _, env := range []string{"AISOC_CORS_ORIGINS", "CORS_ORIGINS"} {
		if v := strings.TrimSpace(os.Getenv(env)); v != "" {
			parts := strings.Split(v, ",")
			out := make([]string, 0, len(parts))
			for _, p := range parts {
				if s := strings.TrimSpace(p); s != "" {
					out = append(out, s)
				}
			}
			if len(out) > 0 {
				return out
			}
		}
	}
	return []string{
		"http://localhost:3000",
		"http://localhost:3001",
		"http://127.0.0.1:3000",
		"http://127.0.0.1:3001",
	}
}

// metricsHandler guards the Prometheus scrape with the same two rules
// services/api and services/agents apply, because this service was the
// one that applied neither.
//
// docker-compose.prod.yml already declared METRICS_TOKEN required for
// ingest with the message "guards /metrics outside development", and
// scripts/ensure_env.py already generated it — but nothing in this
// service read the variable, so the guard the compose file promised did
// not exist here. The series it exposes are not catastrophic on their
// own; they are a tenant-count, topic-name and throughput picture of a
// deployment, and an open endpoint that an operator believes is shut is
// the part worth fixing.
//
// The rules, matching services/agents/app/api/metrics.py:
//
//   - METRICS_TOKEN set: require `Authorization: Bearer <token>`, with a
//     constant-time comparison so a wrong token does not leak its correct
//     prefix through response timing.
//   - METRICS_TOKEN empty: open only in a development-class environment.
//     An operator who never set it in production has a gap rather than an
//     opt-out, and the refusal is what tells them so.
//
// The variable is read per request rather than captured at construction.
// That matches the Python siblings, keeps one code path for the two
// rules, and means a deployment that injects the token after boot is not
// stuck with the answer this process happened to start with.
func metricsHandler() http.HandlerFunc {
	prom := promhttp.Handler()
	return func(w http.ResponseWriter, r *http.Request) {
		if status, msg := authoriseScrape(r); status != 0 {
			w.Header().Set("WWW-Authenticate", `Bearer realm="metrics"`)
			http.Error(w, msg, status)
			return
		}
		prom.ServeHTTP(w, r)
	}
}

// authoriseScrape returns (0, "") when the scrape may proceed, or the
// status and message to refuse it with.
func authoriseScrape(r *http.Request) (int, string) {
	token := strings.TrimSpace(os.Getenv("METRICS_TOKEN"))
	if token != "" {
		presented := strings.TrimSpace(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
		if subtle.ConstantTimeCompare([]byte(presented), []byte(token)) != 1 {
			return http.StatusUnauthorized, "invalid metrics token"
		}
		return 0, ""
	}
	if !envmode.IsDevRuntime() {
		return http.StatusUnauthorized, "metrics endpoint requires METRICS_TOKEN outside development"
	}
	return 0, ""
}

// Server wraps the HTTP server
type Server struct {
	httpServer *http.Server
}

// New creates a new server with routing configured.
//
// inboxHandler is optional — if Postgres isn't reachable at startup we
// still want /v1/ingest to keep working, so server.New tolerates a nil
// inbox handler and just doesn't mount the universal-capture routes.
// In production both handlers are wired; in dev without DATABASE_DSN
// only the connector path is up.
//
// graphWSServer is the optional T1.4 WebSocket broadcaster (graph
// update fan-out). Nil disables the /v1/graph_ws/stream route, which
// is the expected default until an operator opts in via
// AISOC_GRAPH_WS_ENABLED=true.
// otlpReceiver is the optional depth-4.2 OTLP logs endpoint. Nil leaves
// POST /v1/logs unmounted, which is the default until an operator sets
// AISOC_OTLP_LOGS_ENABLED=true.
func New(cfg *config.Config, h *handler.Handler, inboxHandler *inbox.Handler, graphWSServer *graph_ws.Server, otlpReceiver *otlp.Receiver) *Server {
	r := chi.NewRouter()

	// Middleware
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	// Continues a trace started upstream rather than beginning a new one:
	// the propagator reads W3C traceparent, so an API request that reaches
	// ingest stays one trace instead of becoming two disconnected ones.
	// No-op when tracing is disabled, since the global provider is a
	// no-op provider in that case.
	r.Use(func(next http.Handler) http.Handler {
		return otelhttp.NewHandler(next, "ingest")
	})
	r.Use(middleware.Recoverer)
	r.Use(middleware.Timeout(30 * time.Second))
	// Allow-list is resolved from AISOC_CORS_ORIGINS (canonical) / CORS_ORIGINS
	// (legacy) with a safe default that covers local dev only; deployed
	// origins are expected to set the env var.
	// AllowCredentials stays false here. Every route on this service is
	// authenticated by a credential the caller presents per request — a
	// minted push token or a service token on /v1/ingest, an inbox token
	// on /v1/inbox/*, the shared secret on /v1/ingest/k8s-audit — and
	// never by a session cookie, so the browser has no reason to attach
	// one cross-origin and the spec-mandated rejection of
	// "*"+credentials stays safely impossible.
	//
	// This comment previously asserted that /v1/ingest was
	// token-authenticated per request. It was not: the handler read a
	// caller-supplied X-Tenant-ID header and checked nothing. The claim
	// is true as of the credential check in internal/ingestauth.
	r.Use(cors.Handler(cors.Options{
		AllowedOrigins:   resolveCORSOrigins(),
		AllowedMethods:   []string{"GET", "POST", "OPTIONS"},
		AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type", "X-Tenant-ID", "X-Inbox-Token", "X-Splunk-Token", "X-Signature", "X-Hub-Signature-256", "X-AiSOC-K8s-Token"},
		AllowCredentials: false,
		MaxAge:           300,
	}))

	// Routes
	// Liveness and readiness are separate questions, and this service only
	// answered the first one. /health returned 200 whether or not Kafka was
	// reachable — so "ingest is healthy" and "every event is being dropped"
	// could both be true at once. /readyz probes the broker.
	r.Get("/health", h.Health)
	r.Get("/livez", h.Livez)
	r.Get("/readyz", h.Readyz)
	// Liveness and readiness stay open deliberately: an orchestrator's
	// probe carries no credential, and pulling the pipeline's front door
	// out of a load balancer to protect a scrape endpoint would be a
	// worse trade than the one it buys.
	r.Get("/metrics", metricsHandler())

	r.Route("/v1", func(r chi.Router) {
		r.Post("/ingest", h.IngestEvents)
		r.Post("/ingest/batch", h.IngestEvents)

		// Track D / v7.1.0 — Kubernetes apiserver audit-webhook target.
		// Tenant binding lives in the URL path (the apiserver's
		// audit-webhook kubeconfig is awkward to add custom headers
		// to but trivial to point at a templated URL); the auth
		// boundary is the X-AiSOC-K8s-Token shared secret enforced
		// inside the handler. Disabled (returns 503) until an
		// operator sets K8S_AUDIT_SHARED_SECRET on the ingest pod.
		r.Post("/ingest/k8s-audit/{tenant_id}", h.K8sAuditEvents)

		// Workstream 6 — universal capture push paths.
		// /v1/inbox/{token}        → generic JSON or NDJSON webhook
		// /v1/inbox/email/{token}  → email-relay JSON envelope
		// /v1/inbox/cef            → CEF syslog over HTTP (token in header)
		// /v1/inbox/hec            → Splunk HEC-compatible (token in header)
		if inboxHandler != nil {
			r.Route("/inbox", func(r chi.Router) {
				r.Post("/cef", inboxHandler.ServeCEF)
				r.Post("/hec", inboxHandler.ServeHEC)
				r.Post("/email/{token}", inboxHandler.ServeEmail)
				r.Post("/{token}", inboxHandler.ServeJSON)
			})
		} else {
			log.Warn().Msg("inbox routes disabled (no Postgres pool wired)")
		}

		// T1.4 — graph-update WebSocket fan-out. The Python API proxy
		// at services/api/app/api/v1/endpoints/graph_ws.py remains the
		// public-facing entry point and does authenticate the browser,
		// but this route no longer trusts it to have done so: the
		// handler runs the same internal/ingestauth authenticator
		// /v1/ingest runs and takes the tenant from the resulting
		// credential.
		//
		// This comment used to say the route was "internal and trusts
		// that the proxy has validated the connecting tenant", with
		// ?tenant_id=<id> as a "defence-in-depth filter". A tenant the
		// caller types is not a filter on the caller, and the port is
		// published by the root compose file, so there was nothing
		// behind the trust.
		if graphWSServer != nil {
			r.Handle("/graph_ws/stream", graphWSServer.Handler())
		}

		// Depth plan 4.2 — OTLP logs. The path is fixed by the OTLP/HTTP
		// specification: an exporter configured with an endpoint appends
		// /v1/logs itself, so this cannot be mounted anywhere else and
		// still be reachable by a stock collector.
		if otlpReceiver != nil {
			r.Post("/logs", otlpReceiver.ServeLogs)
		}
	})

	return &Server{
		httpServer: &http.Server{
			Addr:         fmt.Sprintf(":%d", cfg.HTTPPort),
			Handler:      r,
			ReadTimeout:  15 * time.Second,
			WriteTimeout: 30 * time.Second,
			IdleTimeout:  120 * time.Second,
		},
	}
}

// Start runs the HTTP server and gracefully shuts down when ctx is cancelled
func (s *Server) Start(ctx context.Context) error {
	errCh := make(chan error, 1)
	go func() {
		if err := s.httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errCh <- err
		}
	}()

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		log.Info().Msg("Shutting down HTTP server...")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return s.httpServer.Shutdown(shutdownCtx)
	}
}
