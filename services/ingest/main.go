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
	configsnap "github.com/beenuar/aisoc/services/ingest/internal/config_snapshot"
	"github.com/beenuar/aisoc/services/ingest/internal/envmode"
	"github.com/beenuar/aisoc/services/ingest/internal/graph"
	"github.com/beenuar/aisoc/services/ingest/internal/graph_ws"
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

	// T1.1 (v8.0) — ingest-side graph writer. Runs in fan-out: failures in
	// the graph writer NEVER block fusion ingest; the writer's queue is
	// bounded and drops on full + emits a metric.
	if cfg.GraphEnabled {
		gctx, gcancel := context.WithTimeout(context.Background(), 10*time.Second)
		gw, err := graph.New(gctx, graph.Config{
			URI:           cfg.Neo4jURI,
			Username:      cfg.Neo4jUser,
			Password:      cfg.Neo4jPassword,
			Database:      cfg.Neo4jDatabase,
			BatchSize:     cfg.GraphBatchSize,
			FlushInterval: time.Duration(cfg.GraphFlushIntervalMs) * time.Millisecond,
			QueueSize:     cfg.GraphQueueSize,
			Publisher:     pub,
		})
		gcancel()
		if err != nil {
			// Soft fail: graph writer is opt-in. Ingest still runs without it.
			log.Warn().Err(err).Msg("graph: writer disabled (Neo4j unreachable)")
		} else {
			defer func() { _ = gw.Close() }()
			h.SetGraphWriter(gw)
			log.Info().
				Str("uri", cfg.Neo4jURI).
				Str("schema_version", graph.SchemaVersion).
				Int("batch_size", cfg.GraphBatchSize).
				Int("flush_ms", cfg.GraphFlushIntervalMs).
				Str("updates_topic", cfg.GraphUpdatesTopic).
				Msg("graph: ingest-side writer enabled")

			// T1.2 (v8.0) — config snapshots. Wired only when both the
			// graph writer is up *and* the operator opts in. Falls back
			// to in-memory cache when Redis is unhealthy; falls back to
			// HTTPProvider against the connectors service when configured,
			// otherwise NoopProvider (every snapshot returns
			// ErrNotImplemented and we log skips). Failures NEVER block
			// fusion ingest — same contract as T1.1.
			if cfg.SnapshotEnabled {
				ttl := time.Duration(cfg.SnapshotCacheTTLSecs) * time.Second
				cacheCtx, cacheCancel := context.WithTimeout(context.Background(), 2*time.Second)
				cache := configsnap.NewRedisCache(cacheCtx, configsnap.RedisConfig{
					Addr: cfg.RedisAddr,
					TTL:  ttl,
				})
				cacheCancel()
				var provider configsnap.Provider
				if cfg.SnapshotProviderURL != "" {
					provider = configsnap.NewHTTPProvider(
						cfg.SnapshotProviderURL,
						time.Duration(cfg.SnapshotProviderTimeoutMs)*time.Millisecond,
					)
				} else {
					provider = configsnap.NoopProvider{}
				}
				snapper, err := configsnap.New(configsnap.Config{
					Provider: provider,
					Cache:    cache,
					TTL:      ttl,
				})
				if err != nil {
					log.Warn().Err(err).Msg("snapshot: disabled (constructor failed)")
				} else {
					defer func() { _ = snapper.Close() }()
					h.SetSnapshotApplier(snapper)
					log.Info().
						Str("provider_url", cfg.SnapshotProviderURL).
						Dur("cache_ttl", ttl).
						Msg("snapshot: T1.2 config snapshots enabled")
				}
			} else {
				log.Info().Msg("snapshot: disabled (AISOC_SNAPSHOT_ENABLED!=true)")
			}
		}
	} else {
		log.Info().Msg("graph: writer disabled (AISOC_GRAPH_ENABLED!=true)")
	}

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

	// T1.4 (v8.0) — graph-update WebSocket fan-out. Opt-in via
	// AISOC_GRAPH_WS_ENABLED=true. The broadcaster owns a single
	// Kafka consumer against GraphUpdatesTopic and fans envelopes
	// out to subscribed WebSocket clients with per-tenant filtering.
	// Failures NEVER block the ingest path — the Kafka publish side
	// (T1.1) is independent and the broadcaster is consumer-only.
	var graphWSServer *graph_ws.Server
	var graphWSBroker *graph_ws.Broadcaster
	if cfg.GraphWSEnabled {
		src, err := graph_ws.NewKafkaSource(graph_ws.KafkaSourceConfig{
			Brokers: cfg.KafkaBrokers,
			Topic:   cfg.GraphUpdatesTopic,
			GroupID: cfg.GraphWSGroupID,
		})
		if err != nil {
			log.Warn().Err(err).Msg("graph_ws: disabled (Kafka source init failed)")
		} else {
			graphWSBroker = graph_ws.New(src, graph_ws.Options{BufferSize: cfg.GraphWSSubscriberBuffer})
			graphWSServer = graph_ws.NewServer(graphWSBroker)
			log.Info().
				Str("topic", cfg.GraphUpdatesTopic).
				Int("buffer", cfg.GraphWSSubscriberBuffer).
				Msg("graph_ws: T1.4 WebSocket broadcaster enabled")
		}
	} else {
		log.Info().Msg("graph_ws: disabled (AISOC_GRAPH_WS_ENABLED!=true)")
	}

	srv := server.New(cfg, h, inboxHandler, graphWSServer)

	// Graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if graphWSBroker != nil {
		graphWSBroker.Start(ctx)
		defer graphWSBroker.Stop()
	}

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
