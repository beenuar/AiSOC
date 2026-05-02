// Package config handles service configuration loading
package config

import (
	"fmt"
	"os"
	"strconv"
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
}

// Load reads configuration from environment variables
func Load() (*Config, error) {
	cfg := &Config{
		HTTPPort:        mustGetEnvInt("HTTP_PORT", 8080),
		KafkaBrokers:    getEnv("KAFKA_BROKERS", "localhost:9092"),
		KafkaTopic:      getEnv("KAFKA_TOPIC", "aisoc.raw_events"),
		RedisAddr:       getEnv("REDIS_ADDR", "localhost:6379"),
		DatabaseDSN:     getEnv("DATABASE_DSN", ""),
		AttckDataPath:   getEnv("ATTCK_DATA_PATH", "/data/enterprise-attack.json"),
		NormalizerMode:  getEnv("NORMALIZER_MODE", "lenient"),
		MaxBatchSize:    mustGetEnvInt("MAX_BATCH_SIZE", 1000),
		WorkerCount:     mustGetEnvInt("WORKER_COUNT", 8),
		TenantHeaderKey: getEnv("TENANT_HEADER_KEY", "X-Tenant-ID"),
		JWTSecret:       getEnv("JWT_SECRET", ""),
		MetricsPort:     mustGetEnvInt("METRICS_PORT", 9090),
	}

	if cfg.JWTSecret == "" && os.Getenv("ENV") != "development" {
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
