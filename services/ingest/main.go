// AiSOC Ingest Service
// Handles raw event ingestion, OCSF normalization, ATT&CK mapping, and Kafka publishing
// Part of the Cyble AiSOC platform (MIT License)
package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cyble/aisoc/services/ingest/internal/config"
	"github.com/cyble/aisoc/services/ingest/internal/handler"
	"github.com/cyble/aisoc/services/ingest/internal/normalizer"
	"github.com/cyble/aisoc/services/ingest/internal/publisher"
	"github.com/cyble/aisoc/services/ingest/internal/server"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

func main() {
	// Configure structured JSON logging
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix
	if os.Getenv("ENV") == "development" {
		log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr})
	}

	log.Info().Str("service", "ingest").Msg("Starting AiSOC Ingest Service")

	cfg, err := config.Load()
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to load configuration")
	}

	// Initialize components
	norm, err := normalizer.New(cfg)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to initialize normalizer")
	}

	pub, err := publisher.New(cfg)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to initialize Kafka publisher")
	}
	defer pub.Close()

	h := handler.New(norm, pub, cfg)

	srv := server.New(cfg, h)

	// Graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Drain VulnMatches → Kafka in a background goroutine
	if norm.VulnMatches != nil {
		go func() {
			for match := range norm.VulnMatches {
				pubCtx, pubCancel := context.WithTimeout(ctx, 5*time.Second)
				if err := pub.PublishVulnMatch(pubCtx, match); err != nil {
					log.Warn().Err(err).Str("cve", match.CVE).Msg("Failed to publish VulnMatch")
				}
				pubCancel()
			}
		}()
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		sig := <-sigCh
		log.Info().Str("signal", sig.String()).Msg("Received shutdown signal")
		cancel()
	}()

	log.Info().Int("port", cfg.HTTPPort).Msg("HTTP server listening")

	if err := srv.Start(ctx); err != nil && err != http.ErrServerClosed {
		log.Fatal().Err(err).Msg("Server error")
	}

	log.Info().Msg("Ingest service shut down gracefully")
}

// healthResponse is returned by the /health endpoint
type healthResponse struct {
	Status    string    `json:"status"`
	Version   string    `json:"version"`
	Timestamp time.Time `json:"timestamp"`
}

// Version is set at build time via ldflags
var Version = "dev"

func init() {
	// Set version in health check
	_ = fmt.Sprintf("aisoc-ingest/%s", Version)
}
