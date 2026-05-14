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
