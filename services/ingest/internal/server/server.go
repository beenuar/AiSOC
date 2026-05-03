// Package server sets up the HTTP router and server
package server

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/beenuar/aisoc/services/ingest/internal/config"
	"github.com/beenuar/aisoc/services/ingest/internal/handler"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/rs/zerolog/log"
)

// Server wraps the HTTP server
type Server struct {
	httpServer *http.Server
}

// New creates a new server with routing configured
func New(cfg *config.Config, h *handler.Handler) *Server {
	r := chi.NewRouter()

	// Middleware
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Recoverer)
	r.Use(middleware.Timeout(30 * time.Second))
	r.Use(cors.Handler(cors.Options{
		AllowedOrigins:   []string{"*"},
		AllowedMethods:   []string{"GET", "POST", "OPTIONS"},
		AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type", "X-Tenant-ID"},
		AllowCredentials: false,
		MaxAge:           300,
	}))

	// Routes
	r.Get("/health", h.Health)
	r.Get("/metrics", promhttp.Handler().ServeHTTP)

	r.Route("/v1", func(r chi.Router) {
		r.Post("/ingest", h.IngestEvents)
		r.Post("/ingest/batch", h.IngestEvents)
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
