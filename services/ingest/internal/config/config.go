// Package config handles service configuration loading
package config

import (
	"fmt"
	"os"
	"strconv"

	"github.com/beenuar/aisoc/services/ingest/internal/envmode"
)

// Config holds all ingest service configuration
type Config struct {
	HTTPPort        int
	KafkaBrokers    string
	KafkaTopic      string
	RedisAddr       string
	DatabaseDSN     string
	AttckDataPath   string
	NormalizerMode  string // "strict" | "lenient"
	MaxBatchSize    int
	WorkerCount     int
	TenantHeaderKey string
	JWTSecret       string
	MetricsPort     int

	// Shodan enrichment
	ShodanAPIKey          string
	ShodanEnrichEnabled   bool
	ShodanCacheExpirySecs int

	// CVE / vulnerability correlation
	VulnCorrelEnabled   bool
	VulnKafkaTopic      string // topic for VULNERABILITY_MATCH events
	NvdAPIKey           string // optional NVD API key for higher rate limits

	// Workstream 6 — universal capture push paths.
	// InboxEnabled toggles the /v1/inbox/* routes. Off by default in
	// development if no DATABASE_DSN is set, since the inbox store needs
	// Postgres to resolve tokens.
	InboxEnabled       bool
	InboxTemplatesDir  string // path to vendor template YAMLs
	// InboxMaxBodyBytes caps a single inbox webhook body. Anything
	// bigger gets a 413; vendors that page through alerts should batch
	// at the source rather than push 50MB at once.
	InboxMaxBodyBytes  int64

	// Kubernetes audit webhook (Track D, v7.1.0).
	//
	// K8sAuditSharedSecret is the value the apiserver must present in the
	// X-AiSOC-K8s-Token header on every POST /v1/ingest/k8s-audit/{tenant}
	// request. The route returns 503 when this is empty and 401 when the
	// header is missing or doesn't match. Empty by default so a fresh
	// install doesn't accidentally accept anonymous K8s audit pushes.
	K8sAuditSharedSecret string
	// K8sAuditMaxBodyBytes caps a single apiserver audit batch. Mirrors
	// InboxMaxBodyBytes but tracked separately so K8s tuning doesn't drag
	// the broader inbox limit around. The apiserver's default audit batch
	// max is ~10 MiB, so 16 MiB gives a little headroom without
	// leaving the door open for a runaway producer.
	K8sAuditMaxBodyBytes int64

	// Graph writer (T1.1 — v8.0).
	//
	// GraphEnabled toggles the ingest-side graph writer. The writer runs in
	// a fan-out goroutine — failures NEVER block fusion ingest. When this
	// is off the writer is never constructed and the pipeline behaves as
	// it did pre-T1.1.
	GraphEnabled bool
	// Neo4jURI / Neo4jUser / Neo4jPassword are the bolt creds. Only Password
	// is actually sensitive; URI + user are non-secret and end up in the
	// ingest service's startup log for debuggability. Empty password is
	// rejected at construction time when GraphEnabled is true.
	Neo4jURI      string
	Neo4jUser     string
	Neo4jPassword string
	Neo4jDatabase string
	// GraphBatchSize / GraphFlushIntervalMs / GraphQueueSize control the
	// batched UNWIND flusher. Defaults are tuned for v8.0 sandbox load
	// (~1k events/sec); production deployments override via env.
	GraphBatchSize       int
	GraphFlushIntervalMs int
	GraphQueueSize       int
	// GraphUpdatesTopic is the Kafka topic consumed by the realtime service
	// (T1.4) for live graph-update streaming. Empty means "don't publish".
	GraphUpdatesTopic string

	// Config snapshots (T1.2 — v8.0).
	//
	// SnapshotEnabled toggles the per-event resource config snapshotter.
	// When on, every event referencing a resource triggers a (cached)
	// ``get_resource_config`` call on the relevant connector and the
	// result lands as a versioned :Configuration node connected via
	// ``:CONFIGURED_AS {ts}``. Off by default — the writer still runs,
	// it just skips the snapshot lookup until the operator opts in.
	SnapshotEnabled bool
	// SnapshotCacheTTLSecs is the TTL for the Redis-backed config cache.
	// Hot resources (the same EC2 instance referenced by 200 events in a
	// minute) only do one round-trip to the connector per TTL window.
	SnapshotCacheTTLSecs int
	// SnapshotProviderURL is the HTTP base URL of the connectors service
	// that serves ``GET /v1/connectors/{id}/resource-config``. The
	// snapshotter calls this in lieu of importing the connector code
	// directly (the connectors live in Python; the writer is Go).
	// Empty disables remote lookups — the snapshotter then only emits
	// cache-hit configurations or whatever the in-process provider
	// (used in tests) returns.
	SnapshotProviderURL string
	// SnapshotProviderTimeoutMs caps each connector round-trip. Tight by
	// design: the snapshotter is on the graph-flush path, not the
	// fusion-publish path, so a slow connector must NEVER block ingest.
	SnapshotProviderTimeoutMs int
}

// Load reads configuration from environment variables
func Load() (*Config, error) {
	cfg := &Config{
		HTTPPort: mustGetEnvInt("HTTP_PORT", 8080),
		// Canonical env var is ``KAFKA_BOOTSTRAP_SERVERS`` (matches
		// ``.env.example`` and docker-compose). ``KAFKA_BROKERS`` is honored
		// as a back-compat alias for older deployments.
		KafkaBrokers: getEnvFallback("KAFKA_BOOTSTRAP_SERVERS", "KAFKA_BROKERS", "localhost:9092"),
		KafkaTopic:   getEnv("KAFKA_TOPIC", "aisoc.raw_events"),
		RedisAddr:       getEnv("REDIS_ADDR", "localhost:6379"),
		DatabaseDSN:     getEnv("DATABASE_DSN", ""),
		AttckDataPath:   getEnv("ATTCK_DATA_PATH", "/data/enterprise-attack.json"),
		NormalizerMode:  getEnv("NORMALIZER_MODE", "lenient"),
		MaxBatchSize:    mustGetEnvInt("MAX_BATCH_SIZE", 1000),
		WorkerCount:     mustGetEnvInt("WORKER_COUNT", 8),
		TenantHeaderKey: getEnv("TENANT_HEADER_KEY", "X-Tenant-ID"),
		JWTSecret:       getEnv("JWT_SECRET", ""),
		MetricsPort:     mustGetEnvInt("METRICS_PORT", 9090),

		// Shodan
		ShodanAPIKey:          getEnv("SHODAN_API_KEY", ""),
		ShodanEnrichEnabled:   getEnv("SHODAN_ENRICH_ENABLED", "false") == "true",
		ShodanCacheExpirySecs: mustGetEnvInt("SHODAN_CACHE_EXPIRY_SECS", 3600),

		// CVE correlation
		VulnCorrelEnabled: getEnv("VULN_CORREL_ENABLED", "true") == "true",
		VulnKafkaTopic:    getEnv("VULN_KAFKA_TOPIC", "aisoc.vulnerability_matches"),
		NvdAPIKey:         getEnv("NVD_API_KEY", ""),

		// Universal capture (Workstream 6).
		InboxEnabled:      getEnv("INBOX_ENABLED", "true") == "true",
		InboxTemplatesDir: getEnv("INBOX_TEMPLATES_DIR", "/app/templates"),
		InboxMaxBodyBytes: int64(mustGetEnvInt("INBOX_MAX_BODY_BYTES", 10*1024*1024)),

		// Kubernetes audit webhook (Track D, v7.1.0).
		K8sAuditSharedSecret: getEnv("K8S_AUDIT_SHARED_SECRET", ""),
		K8sAuditMaxBodyBytes: int64(mustGetEnvInt("K8S_AUDIT_MAX_BODY_BYTES", 16*1024*1024)),

		// Graph writer (T1.1, v8.0).
		GraphEnabled:         getEnv("AISOC_GRAPH_ENABLED", "false") == "true",
		Neo4jURI:             getEnv("AISOC_NEO4J_URI", "bolt://localhost:7687"),
		Neo4jUser:            getEnv("AISOC_NEO4J_USER", "neo4j"),
		Neo4jPassword:        getEnv("AISOC_NEO4J_PASSWORD", "neo4j"),
		Neo4jDatabase:        getEnv("AISOC_NEO4J_DATABASE", "neo4j"),
		GraphBatchSize:       mustGetEnvInt("AISOC_GRAPH_BATCH_SIZE", 100),
		GraphFlushIntervalMs: mustGetEnvInt("AISOC_GRAPH_FLUSH_INTERVAL_MS", 100),
		GraphQueueSize:       mustGetEnvInt("AISOC_GRAPH_QUEUE_SIZE", 2048),
		GraphUpdatesTopic:    getEnv("AISOC_GRAPH_UPDATES_TOPIC", "security.graph_updates"),

		// Config snapshots (T1.2, v8.0). Disabled by default — operators
		// flip AISOC_SNAPSHOT_ENABLED=true once the connectors service
		// exposes the resource-config endpoint.
		SnapshotEnabled:           getEnv("AISOC_SNAPSHOT_ENABLED", "false") == "true",
		SnapshotCacheTTLSecs:      mustGetEnvInt("AISOC_SNAPSHOT_CACHE_TTL_SECS", 600),
		SnapshotProviderURL:       getEnv("AISOC_SNAPSHOT_PROVIDER_URL", ""),
		SnapshotProviderTimeoutMs: mustGetEnvInt("AISOC_SNAPSHOT_PROVIDER_TIMEOUT_MS", 1500),
	}

	// JWT_SECRET is required outside development-class environments. The
	// previous check exact-matched ``ENV == "development"`` only, so an
	// operator who set ``ENVIRONMENT=development`` (the alias the Python
	// API treats as equivalent) without also setting ``ENV`` would crash
	// here even though every other service treated their stack as dev.
	// envmode.IsDevRuntime closes that gap.
	if cfg.JWTSecret == "" && !envmode.IsDevRuntime() {
		return nil, fmt.Errorf("JWT_SECRET must be set in non-development environments")
	}

	return cfg, nil
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// getEnvFallback returns the first non-empty env var from primary, then
// alternate, otherwise the fallback. Used for backward-compatible env aliases.
func getEnvFallback(primary, alternate, fallback string) string {
	if v := os.Getenv(primary); v != "" {
		return v
	}
	if v := os.Getenv(alternate); v != "" {
		return v
	}
	return fallback
}

func mustGetEnvInt(key string, fallback int) int {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return fallback
	}
	return n
}
