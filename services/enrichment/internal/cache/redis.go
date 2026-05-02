package cache

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/rs/zerolog/log"
)

// Client wraps Redis for enrichment caching with typed operations.
type Client struct {
	rdb *redis.Client
	ttl time.Duration
}

// NewClient creates a new Redis cache client.
func NewClient(redisURL string, ttl time.Duration) (*Client, error) {
	opts, err := redis.ParseURL(redisURL)
	if err != nil {
		return nil, fmt.Errorf("invalid Redis URL: %w", err)
	}

	rdb := redis.NewClient(opts)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := rdb.Ping(ctx).Err(); err != nil {
		return nil, fmt.Errorf("Redis connection failed: %w", err)
	}

	log.Info().Str("url", redisURL).Msg("Redis cache connected")
	return &Client{rdb: rdb, ttl: ttl}, nil
}

// Get retrieves a cached enrichment result. Returns nil, nil if not found.
func (c *Client) Get(ctx context.Context, key string, dest interface{}) error {
	data, err := c.rdb.Get(ctx, key).Bytes()
	if err == redis.Nil {
		return nil
	}
	if err != nil {
		return fmt.Errorf("cache get error: %w", err)
	}
	return json.Unmarshal(data, dest)
}

// Set stores an enrichment result in the cache with TTL.
func (c *Client) Set(ctx context.Context, key string, value interface{}, ttl ...time.Duration) error {
	data, err := json.Marshal(value)
	if err != nil {
		return fmt.Errorf("marshal error: %w", err)
	}

	cacheTTL := c.ttl
	if len(ttl) > 0 && ttl[0] > 0 {
		cacheTTL = ttl[0]
	}

	return c.rdb.Set(ctx, key, data, cacheTTL).Err()
}

// Delete removes a cache entry.
func (c *Client) Delete(ctx context.Context, key string) error {
	return c.rdb.Del(ctx, key).Err()
}

// Exists checks if a key exists in cache.
func (c *Client) Exists(ctx context.Context, key string) (bool, error) {
	n, err := c.rdb.Exists(ctx, key).Result()
	return n > 0, err
}

// Close closes the Redis connection.
func (c *Client) Close() error {
	return c.rdb.Close()
}

// MakeKey constructs a namespaced cache key.
func MakeKey(iocType, value string) string {
	return fmt.Sprintf("aisoc:enrich:%s:%s", iocType, value)
}
