// AiSOC Ingest Service
// Handles raw event ingestion, OCSF normalization, ATT&CK mapping, and Kafka publishing
// Part of the AiSOC platform (MIT License)
package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/beenuar/aisoc/services/ingest/internal/config"
	"github.com/beenuar/aisoc/services/ingest/internal/envmode"
	"github.com/beenuar/aisoc/services/ingest/internal/handler"
	"github.com/beenuar/aisoc/services/ingest/internal/inbox"
	"github.com/beenuar/aisoc/services/ingest/internal/normalizer"
	"github.com/beenuar/aisoc/services/ingest/internal/publisher"
	"github.com/beenuar/aisoc/services/ingest/internal/server"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

func main() {
	// Configure structured logging. Use the human-friendly console writer
	// in any dev-class environment (development, dev, local, demo, test) —
	// previously this exact-matched ``ENV == "development"`` only, so
	// ``ENVIRONMENT=development`` (the alias the Python API treats as
	// equivalent) silently flipped this service to JSON logs and made
	// local debugging confusing. envmode.IsDevRuntime keeps both layers
	// in lock-step.
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix
	if envmode.IsDevRuntime() {
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

	// Workstream 6 — universal capture push paths.
	//
	// We need a Postgres pool to resolve inbox tokens and a YAML registry
	// to find the matching template. Both are optional in dev (no
	// DATABASE_DSN means /v1/inbox/* is disabled but /v1/ingest still
	// works, so the connector path keeps running).
	var inboxHandler *inbox.Handler
	if cfg.InboxEnabled && cfg.DatabaseDSN != "" {
		poolCtx, poolCancel := context.WithTimeout(context.Background(), 10*time.Second)
		pool, err := pgxpool.New(poolCtx, cfg.DatabaseDSN)
		poolCancel()
		if err != nil {
			log.Warn().Err(err).Msg("Failed to connect to Postgres for inbox; /v1/inbox/* disabled")
		} else {
			defer pool.Close()
			store := inbox.NewStore(pool)
			registry := inbox.NewRegistry()
			if err := registry.Load(cfg.InboxTemplatesDir); err != nil {
				log.Warn().Err(err).Str("dir", cfg.InboxTemplatesDir).
					Msg("Failed to load inbox templates; /v1/inbox/* will return 503 for unknown templates")
			}
			log.Info().
				Strs("templates", registry.IDs()).
				Int64("max_body_bytes", cfg.InboxMaxBodyBytes).
				Msg("inbox: universal-capture push paths enabled")
			inboxHandler = inbox.NewHandler(store, registry, pub, cfg.InboxMaxBodyBytes)
		}
	} else if !cfg.InboxEnabled {
		log.Info().Msg("inbox: disabled via INBOX_ENABLED=false")
	} else {
		log.Info().Msg("inbox: skipped (no DATABASE_DSN)")
	}

	srv := server.New(cfg, h, inboxHandler)

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
