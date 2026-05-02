package config

import (
	"os"
	"strconv"
	"time"
)

// Config holds all configuration for the enrichment service.
type Config struct {
	// Server
	HTTPPort string

	// Redis
	RedisURL       string
	CacheTTL       time.Duration
	CacheMaxMemory string

	// External Threat Intel APIs
	AbuseIPDBAPIKey  string
	VirusTotalAPIKey string
	ShodanAPIKey     string
	GreyNoiseAPIKey  string

	// Rate limiting
	RateLimitRPS int
	RateLimitBurst int

	// Logging
	LogLevel string
}

// Load reads configuration from environment variables with sensible defaults.
func Load() *Config {
	cacheTTLSecs, _ := strconv.Atoi(getEnv("CACHE_TTL_SECONDS", "3600"))
	rateLimitRPS, _ := strconv.Atoi(getEnv("RATE_LIMIT_RPS", "100"))
	rateLimitBurst, _ := strconv.Atoi(getEnv("RATE_LIMIT_BURST", "50"))

	return &Config{
		HTTPPort:         getEnv("HTTP_PORT", "8082"),
		RedisURL:         getEnv("REDIS_URL", "redis://localhost:6379/1"),
		CacheTTL:         time.Duration(cacheTTLSecs) * time.Second,
		CacheMaxMemory:   getEnv("CACHE_MAX_MEMORY", "256mb"),
		AbuseIPDBAPIKey:  getEnv("ABUSEIPDB_API_KEY", ""),
		VirusTotalAPIKey: getEnv("VIRUSTOTAL_API_KEY", ""),
		ShodanAPIKey:     getEnv("SHODAN_API_KEY", ""),
		GreyNoiseAPIKey:  getEnv("GREYNOISE_API_KEY", ""),
		RateLimitRPS:     rateLimitRPS,
		RateLimitBurst:   rateLimitBurst,
		LogLevel:         getEnv("LOG_LEVEL", "info"),
	}
}

func getEnv(key, defaultValue string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return defaultValue
}
