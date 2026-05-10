// Package config reads AiSOC extension configuration from environment variables.
package config

import (
	"os"
	"time"
)

// Config holds runtime configuration for the osquery extension.
type Config struct {
	// AISOC_API_URL is the base URL of the AiSOC API service.
	// Example: https://api.example.com
	APIURL string

	// AISOC_API_TOKEN is a host-scoped read-only token issued by the AiSOC API.
	APIToken string

	// HostIdentifier uniquely identifies this host to the AiSOC API.
	// Defaults to the machine hostname when not set.
	HostIdentifier string

	// Timeout for all outbound HTTP requests.
	HTTPTimeout time.Duration
}

// Load returns a Config populated from environment variables with sensible
// defaults.  It never returns nil.
func Load() *Config {
	host, _ := os.Hostname()

	cfg := &Config{
		APIURL:         getenv("AISOC_API_URL", "http://localhost:8000"),
		APIToken:       getenv("AISOC_API_TOKEN", ""),
		HostIdentifier: getenv("AISOC_HOST_ID", host),
		HTTPTimeout:    10 * time.Second,
	}
	return cfg
}

func getenv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
