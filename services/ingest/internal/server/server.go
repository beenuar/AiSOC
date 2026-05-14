// Package server sets up the HTTP router and server
package server

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/beenuar/aisoc/services/ingest/internal/config"
	"github.com/beenuar/aisoc/services/ingest/internal/handler"
	"github.com/beenuar/aisoc/services/ingest/internal/inbox"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/rs/zerolog/log"
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
		"https://tryaisoc.com",
		"https://www.tryaisoc.com",
	}
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
func New(cfg *config.Config, h *handler.Handler, inboxHandler *inbox.Handler) *Server {
	r := chi.NewRouter()

	// Middleware
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Recoverer)
	r.Use(middleware.Timeout(30 * time.Second))
	// Allow-list is resolved from AISOC_CORS_ORIGINS (canonical) / CORS_ORIGINS
	// (legacy) with a safe default for local dev + the tryaisoc.com console.
	// AllowCredentials stays false here — /v1/ingest is token-authenticated
	// per request, not session-cookie-authenticated, so we don't need the
	// browser to attach cookies cross-origin and we keep the spec-mandated
	// rejection of "*"+credentials safely impossible.
	r.Use(cors.Handler(cors.Options{
		AllowedOrigins:   resolveCORSOrigins(),
		AllowedMethods:   []string{"GET", "POST", "OPTIONS"},
		AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type", "X-Tenant-ID", "X-Inbox-Token", "X-Splunk-Token", "X-Signature", "X-Hub-Signature-256", "X-AiSOC-K8s-Token"},
		AllowCredentials: false,
		MaxAge:           300,
	}))

	// Routes
	r.Get("/health", h.Health)
	r.Get("/metrics", promhttp.Handler().ServeHTTP)

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
