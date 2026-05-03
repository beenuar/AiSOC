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

	// External Threat Intel APIs — open-source / freemium
	AbuseIPDBAPIKey  string
	VirusTotalAPIKey string
	ShodanAPIKey     string
	GreyNoiseAPIKey  string
	URLScanAPIKey    string
	IPInfoAPIKey     string

	// External Threat Intel APIs — commercial
	CybleAPIKey            string
	CybleBaseURL           string
	RecordedFutureAPIKey   string
	MandiantAPIKey         string
	MandiantAPISecret      string
	AnomaliUsername        string
	AnomaliAPIKey          string
	AnomaliBaseURL         string
	XForceAPIKey           string
	XForceAPIPassword      string
	FlashpointAPIKey       string
	Intel471Username       string
	Intel471APIKey         string
	DomainToolsUsername    string
	DomainToolsAPIKey      string
	RiskIQUsername         string
	RiskIQAPIKey           string
	CrowdstrikeIntelID     string
	CrowdstrikeIntelSecret string

	// Rate limiting
	RateLimitRPS   int
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
		HTTPPort:               getEnv("HTTP_PORT", "8082"),
		RedisURL:               getEnv("REDIS_URL", "redis://localhost:6379/1"),
		CacheTTL:               time.Duration(cacheTTLSecs) * time.Second,
		CacheMaxMemory:         getEnv("CACHE_MAX_MEMORY", "256mb"),
		AbuseIPDBAPIKey:        getEnv("ABUSEIPDB_API_KEY", ""),
		VirusTotalAPIKey:       getEnv("VIRUSTOTAL_API_KEY", ""),
		ShodanAPIKey:           getEnv("SHODAN_API_KEY", ""),
		GreyNoiseAPIKey:        getEnv("GREYNOISE_API_KEY", ""),
		URLScanAPIKey:          getEnv("URLSCAN_API_KEY", ""),
		IPInfoAPIKey:           getEnv("IPINFO_API_KEY", ""),
		CybleAPIKey:            getEnv("CYBLE_API_KEY", ""),
		CybleBaseURL:           getEnv("CYBLE_BASE_URL", ""),
		RecordedFutureAPIKey:   getEnv("RECORDED_FUTURE_API_KEY", ""),
		MandiantAPIKey:         getEnv("MANDIANT_API_KEY", ""),
		MandiantAPISecret:      getEnv("MANDIANT_API_SECRET", ""),
		AnomaliUsername:        getEnv("ANOMALI_USERNAME", ""),
		AnomaliAPIKey:          getEnv("ANOMALI_API_KEY", ""),
		AnomaliBaseURL:         getEnv("ANOMALI_BASE_URL", ""),
		XForceAPIKey:           getEnv("XFORCE_API_KEY", ""),
		XForceAPIPassword:      getEnv("XFORCE_API_PASSWORD", ""),
		FlashpointAPIKey:       getEnv("FLASHPOINT_API_KEY", ""),
		Intel471Username:       getEnv("INTEL471_USERNAME", ""),
		Intel471APIKey:         getEnv("INTEL471_API_KEY", ""),
		DomainToolsUsername:    getEnv("DOMAINTOOLS_USERNAME", ""),
		DomainToolsAPIKey:      getEnv("DOMAINTOOLS_API_KEY", ""),
		RiskIQUsername:         getEnv("RISKIQ_USERNAME", ""),
		RiskIQAPIKey:           getEnv("RISKIQ_API_KEY", ""),
		CrowdstrikeIntelID:     getEnv("CROWDSTRIKE_INTEL_CLIENT_ID", ""),
		CrowdstrikeIntelSecret: getEnv("CROWDSTRIKE_INTEL_CLIENT_SECRET", ""),
		RateLimitRPS:           rateLimitRPS,
		RateLimitBurst:         rateLimitBurst,
		LogLevel:               getEnv("LOG_LEVEL", "info"),
	}
}

func getEnv(key, defaultValue string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return defaultValue
}
