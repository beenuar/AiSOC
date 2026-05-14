// cache.go — TTL cache for resource-config lookups.
//
// The snapshotter (snapshotter.go) sits on the graph-flush path. Every event
// that references a resource may trigger a ``get_resource_config`` round-trip
// to the connectors service. In a busy SOC the same EC2 instance, GitHub
// repo, or Okta app shows up in dozens of events per minute; without a cache
// the connectors service would get hammered for the same resource over and
// over.
//
// Two backends are exposed behind a single ``Cache`` interface:
//
//   - ``RedisCache`` — production. Backed by ``github.com/redis/go-redis/v9``.
//     A failure to connect at construction time is *non-fatal* — we fall
//     back to the in-memory cache. The graph writer must NEVER fail because
//     Redis is unhealthy.
//
//   - ``MemoryCache`` — tests + the in-process default. Bounded LRU-ish via
//     a simple ``map`` + janitor goroutine. Good enough for single-pod
//     deployments and for the unit tests here.
//
// Keys collapse the three coordinates that uniquely identify a config
// snapshot: ``(connector_id, resource_id, ts_bucket)``. The ts is bucketed
// to the cache TTL so two events 30 seconds apart against the same resource
// hit the same cache slot — that's the whole point of the cache.
//
// AiSOC — open-source AI Security Operations Center (MIT License)
package config_snapshot

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/rs/zerolog/log"
)

// Cache is the small surface the snapshotter needs. Implementations MUST be
// safe for concurrent use and MUST never block longer than ~50ms — the
// snapshotter is on the graph flush path and a slow cache would push back on
// the writer queue.
type Cache interface {
	// Get returns (configuration, true) on a hit. A miss returns (nil, false)
	// with no error. Errors are reserved for backend failures the caller may
	// want to log — the snapshotter treats every Get error as a miss.
	Get(ctx context.Context, key string) (map[string]interface{}, bool, error)
	// Set stores a configuration with the configured TTL. Errors are logged
	// but not surfaced to the snapshotter.
	Set(ctx context.Context, key string, value map[string]interface{}) error
	// Close releases backend resources. Idempotent.
	Close() error
}

// CacheKey computes the canonical lookup key for (connector, resource, ts).
//
// The timestamp is bucketed to the TTL so consecutive events against the
// same resource collapse to the same key. Without bucketing each event
// would carry a unique nanosecond timestamp and the cache would never hit.
func CacheKey(connectorID, resourceID string, ts time.Time, ttl time.Duration) string {
	if ttl <= 0 {
		ttl = 10 * time.Minute
	}
	bucket := ts.UTC().Truncate(ttl).Unix()
	// Hash the resource id so we don't leak full ARNs into Redis keys.
	// Some resource ids contain account-scoped data (S3 bucket names,
	// Slack channel ids) that an operator might not want in plaintext on
	// a multi-tenant Redis cluster.
	h := sha256.Sum256([]byte(resourceID))
	return fmt.Sprintf("aisoc:cfg:%s:%s:%d", connectorID, hex.EncodeToString(h[:8]), bucket)
}

// MemoryCache is a process-local TTL cache. Default backend in tests.
type MemoryCache struct {
	ttl   time.Duration
	mu    sync.Mutex
	store map[string]memEntry
	stop  chan struct{}
}

type memEntry struct {
	value  map[string]interface{}
	expiry time.Time
}

// NewMemoryCache builds a process-local TTL cache. ``ttl <= 0`` defaults to
// 10 minutes. Spawns a janitor goroutine that evicts expired entries every
// ``ttl/2`` so a quiet pod doesn't grow unbounded.
func NewMemoryCache(ttl time.Duration) *MemoryCache {
	if ttl <= 0 {
		ttl = 10 * time.Minute
	}
	c := &MemoryCache{
		ttl:   ttl,
		store: make(map[string]memEntry),
		stop:  make(chan struct{}),
	}
	go c.janitor()
	return c
}

func (c *MemoryCache) Get(_ context.Context, key string) (map[string]interface{}, bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.store[key]
	if !ok {
		return nil, false, nil
	}
	if time.Now().After(e.expiry) {
		delete(c.store, key)
		return nil, false, nil
	}
	// Defensive copy — the caller must not mutate cached configs.
	return cloneMap(e.value), true, nil
}

func (c *MemoryCache) Set(_ context.Context, key string, value map[string]interface{}) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.store[key] = memEntry{
		value:  cloneMap(value),
		expiry: time.Now().Add(c.ttl),
	}
	return nil
}

func (c *MemoryCache) Close() error {
	select {
	case <-c.stop:
		return nil
	default:
		close(c.stop)
	}
	return nil
}

func (c *MemoryCache) janitor() {
	tick := time.NewTicker(c.ttl / 2)
	defer tick.Stop()
	for {
		select {
		case <-c.stop:
			return
		case <-tick.C:
			now := time.Now()
			c.mu.Lock()
			for k, e := range c.store {
				if now.After(e.expiry) {
					delete(c.store, k)
				}
			}
			c.mu.Unlock()
		}
	}
}

// RedisCache wraps a go-redis client. Suitable for multi-pod deployments
// where the same resource may be fetched from any pod. Falls back to the
// in-memory cache on Redis errors so a Redis blip never starves the writer.
type RedisCache struct {
	client   *redis.Client
	ttl      time.Duration
	fallback *MemoryCache
}

// RedisConfig wires the Redis client. Address follows the standard
// ``host:port`` shape; password is optional.
type RedisConfig struct {
	Addr     string
	Password string
	DB       int
	TTL      time.Duration
}

// NewRedisCache dials Redis and pings to verify reachability. A dial failure
// is *non-fatal* — the constructor logs a warning, returns a cache that
// degrades to in-memory, and lets the snapshotter keep running.
func NewRedisCache(ctx context.Context, cfg RedisConfig) *RedisCache {
	if cfg.TTL <= 0 {
		cfg.TTL = 10 * time.Minute
	}
	c := &RedisCache{
		ttl:      cfg.TTL,
		fallback: NewMemoryCache(cfg.TTL),
	}
	if cfg.Addr == "" {
		log.Info().Msg("snapshot cache: REDIS_ADDR empty, using in-memory only")
		return c
	}
	client := redis.NewClient(&redis.Options{
		Addr:     cfg.Addr,
		Password: cfg.Password,
		DB:       cfg.DB,
	})
	pingCtx, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
	defer cancel()
	if err := client.Ping(pingCtx).Err(); err != nil {
		log.Warn().Err(err).Str("addr", cfg.Addr).
			Msg("snapshot cache: Redis unreachable, falling back to in-memory")
		_ = client.Close()
		return c
	}
	c.client = client
	log.Info().Str("addr", cfg.Addr).Dur("ttl", cfg.TTL).
		Msg("snapshot cache: Redis ready")
	return c
}

func (c *RedisCache) Get(ctx context.Context, key string) (map[string]interface{}, bool, error) {
	// Always consult the in-memory cache first — it's faster and acts as
	// a tier-1 read-through for the steady state.
	if v, ok, _ := c.fallback.Get(ctx, key); ok {
		return v, true, nil
	}
	if c.client == nil {
		return nil, false, nil
	}
	raw, err := c.client.Get(ctx, key).Bytes()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return nil, false, nil
		}
		log.Debug().Err(err).Str("key", key).Msg("snapshot cache: redis GET failed")
		return nil, false, err
	}
	var out map[string]interface{}
	if err := json.Unmarshal(raw, &out); err != nil {
		// Corrupt entry — treat as miss and let the snapshotter refetch.
		return nil, false, nil
	}
	// Promote to memory tier so the next request from this pod is local.
	_ = c.fallback.Set(ctx, key, out)
	return out, true, nil
}

func (c *RedisCache) Set(ctx context.Context, key string, value map[string]interface{}) error {
	_ = c.fallback.Set(ctx, key, value)
	if c.client == nil {
		return nil
	}
	b, err := json.Marshal(value)
	if err != nil {
		return err
	}
	if err := c.client.Set(ctx, key, b, c.ttl).Err(); err != nil {
		log.Debug().Err(err).Str("key", key).Msg("snapshot cache: redis SET failed")
		return err
	}
	return nil
}

func (c *RedisCache) Close() error {
	if c.client != nil {
		_ = c.client.Close()
	}
	return c.fallback.Close()
}

// cloneMap returns a shallow copy of m. The snapshotter caches the same
// dict it later attaches to the graph; without a copy a downstream mutation
// would corrupt every subsequent cache hit.
func cloneMap(m map[string]interface{}) map[string]interface{} {
	if m == nil {
		return nil
	}
	out := make(map[string]interface{}, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}
