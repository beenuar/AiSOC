package main

import (
	"context"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cyble/aisoc/enrichment/internal/cache"
	"github.com/cyble/aisoc/enrichment/internal/config"
	"github.com/cyble/aisoc/enrichment/internal/enricher"
	"github.com/cyble/aisoc/enrichment/internal/handler"
	"github.com/cyble/aisoc/enrichment/internal/server"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

func main() {
	// Configure logging
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr, TimeFormat: time.RFC3339})

	// Load configuration
	cfg := config.Load()

	// Set log level
	level, err := zerolog.ParseLevel(cfg.LogLevel)
	if err != nil {
		level = zerolog.InfoLevel
	}
	zerolog.SetGlobalLevel(level)

	log.Info().
		Str("service", "aisoc-enrichment").
		Str("port", cfg.HTTPPort).
		Msg("Starting IOC Enrichment Service")

	// Initialize Redis cache
	redisCache, err := cache.NewClient(cfg.RedisURL, cfg.CacheTTL)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to connect to Redis")
	}
	defer redisCache.Close()

	// Initialize enricher
	e := enricher.New(enricher.Config{
		Cache:            redisCache,
		VirusTotalAPIKey: cfg.VirusTotalAPIKey,
		AbuseIPDBAPIKey:  cfg.AbuseIPDBAPIKey,
		GreyNoiseAPIKey:  cfg.GreyNoiseAPIKey,
	})

	// Initialize handler and server
	h := handler.New(e)
	srv := server.New(cfg.HTTPPort, h)

	// Graceful shutdown
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		if err := srv.Start(); err != nil && err != http.ErrServerClosed {
			log.Fatal().Err(err).Msg("Server error")
		}
	}()

	log.Info().Str("port", cfg.HTTPPort).Msg("Enrichment service started successfully")

	<-quit
	log.Info().Msg("Shutting down enrichment service...")

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		log.Error().Err(err).Msg("Server shutdown error")
	}

	log.Info().Msg("Enrichment service stopped")
}
