package server

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/beenuar/aisoc/enrichment/internal/handler"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
	"github.com/rs/zerolog/log"
)

// resolveCORSOrigins reads “AISOC_CORS_ORIGINS“ (canonical) / “CORS_ORIGINS“
// (legacy alias) so operators can lock the allow-list down per-deploy without
// shipping a new image. /enrich is back-end-to-back-end (services/api calls us),
// not browser-facing, so the default is conservative but not strict.
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

// Server wraps the HTTP server for the enrichment service.
type Server struct {
	httpServer *http.Server
}

// New creates and configures the HTTP server.
func New(port string, h *handler.Handler) *Server {
	r := chi.NewRouter()

	// Middlewares
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Recoverer)
	r.Use(middleware.Timeout(30 * time.Second))
	// /enrich is back-end-to-back-end; AllowCredentials stays false so wildcard
	// is technically safe, but we still resolve the allow-list from env so
	// production deploys can constrain it without code changes.
	r.Use(cors.Handler(cors.Options{
		AllowedOrigins:   resolveCORSOrigins(),
		AllowedMethods:   []string{"GET", "POST", "OPTIONS"},
		AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type", "X-Request-ID"},
		ExposedHeaders:   []string{"X-Request-ID"},
		AllowCredentials: false,
		MaxAge:           300,
	}))

	// Routes
	r.Get("/health", h.Health)
	r.Post("/enrich", h.EnrichIOC)
	r.Post("/enrich/bulk", h.BulkEnrich)

	return &Server{
		httpServer: &http.Server{
			Addr:         fmt.Sprintf(":%s", port),
			Handler:      r,
			ReadTimeout:  15 * time.Second,
			WriteTimeout: 60 * time.Second,
			IdleTimeout:  120 * time.Second,
		},
	}
}

// Start begins listening on the configured port.
func (s *Server) Start() error {
	log.Info().Str("addr", s.httpServer.Addr).Msg("Enrichment service listening")
	return s.httpServer.ListenAndServe()
}

// Shutdown gracefully shuts down the server.
func (s *Server) Shutdown(ctx context.Context) error {
	return s.httpServer.Shutdown(ctx)
}
