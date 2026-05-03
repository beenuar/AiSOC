package main

import (
	"context"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/beenuar/aisoc/enrichment/internal/cache"
	"github.com/beenuar/aisoc/enrichment/internal/config"
	"github.com/beenuar/aisoc/enrichment/internal/enricher"
	"github.com/beenuar/aisoc/enrichment/internal/handler"
	"github.com/beenuar/aisoc/enrichment/internal/server"
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
		Cache:                  redisCache,
		VirusTotalAPIKey:       cfg.VirusTotalAPIKey,
		AbuseIPDBAPIKey:        cfg.AbuseIPDBAPIKey,
		GreyNoiseAPIKey:        cfg.GreyNoiseAPIKey,
		CybleAPIKey:            cfg.CybleAPIKey,
		CybleBaseURL:           cfg.CybleBaseURL,
		RecordedFutureAPIKey:   cfg.RecordedFutureAPIKey,
		MandiantAPIKey:         cfg.MandiantAPIKey,
		MandiantAPISecret:      cfg.MandiantAPISecret,
		AnomaliUsername:        cfg.AnomaliUsername,
		AnomaliAPIKey:          cfg.AnomaliAPIKey,
		AnomaliBaseURL:         cfg.AnomaliBaseURL,
		XForceAPIKey:           cfg.XForceAPIKey,
		XForceAPIPassword:      cfg.XForceAPIPassword,
		FlashpointAPIKey:       cfg.FlashpointAPIKey,
		Intel471Username:       cfg.Intel471Username,
		Intel471APIKey:         cfg.Intel471APIKey,
		DomainToolsUsername:    cfg.DomainToolsUsername,
		DomainToolsAPIKey:      cfg.DomainToolsAPIKey,
		RiskIQUsername:         cfg.RiskIQUsername,
		RiskIQAPIKey:           cfg.RiskIQAPIKey,
		CrowdstrikeIntelID:     cfg.CrowdstrikeIntelID,
		CrowdstrikeIntelSecret: cfg.CrowdstrikeIntelSecret,
	})

	log.Info().
		Bool("virustotal", cfg.VirusTotalAPIKey != "").
		Bool("abuseipdb", cfg.AbuseIPDBAPIKey != "").
		Bool("greynoise", cfg.GreyNoiseAPIKey != "").
		Bool("cyble", cfg.CybleAPIKey != "").
		Bool("recorded_future", cfg.RecordedFutureAPIKey != "").
		Bool("mandiant", cfg.MandiantAPIKey != "" && cfg.MandiantAPISecret != "").
		Bool("anomali", cfg.AnomaliAPIKey != "").
		Bool("xforce", cfg.XForceAPIKey != "").
		Bool("flashpoint", cfg.FlashpointAPIKey != "").
		Bool("intel471", cfg.Intel471APIKey != "").
		Bool("domaintools", cfg.DomainToolsAPIKey != "").
		Bool("riskiq", cfg.RiskIQAPIKey != "").
		Bool("crowdstrike_intel", cfg.CrowdstrikeIntelID != "" && cfg.CrowdstrikeIntelSecret != "").
		Msg("Threat intelligence providers configured")

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
