// Package inbox is the universal-capture push path (Workstream 6 of the
// AI Stack & Data Integration plan).
//
// The Python services/api service mints rows in tenant_inbox_tokens
// (see migration 033) when an operator clicks "Push (any vendor)" in the
// onboarding wizard. This package is the Go side: it resolves an inbox
// token presented on /v1/inbox/{token} (or /v1/inbox/cef, /v1/inbox/hec,
// /v1/inbox/email/{token}) to a tenant_id + template_id, runs the
// vendor-specific YAML template against the request body, and reuses the
// existing OCSF normalizer + Kafka publisher to land an event.
//
// Why direct Postgres access (and not an internal HTTP call to
// services/api)?
//
//   - Hot path. Every webhook from PagerDuty / Opsgenie / Cloudflare
//     hits this code; one extra cross-service HTTP hop would double our
//     ingest latency budget.
//   - The DB is already shared. services/connectors writes connector
//     state, services/api reads it back; this is one more table in the
//     same schema with the same RLS posture.
//   - Postgres RLS is a hard backstop. The ingest service connects with
//     a service-role DSN (BYPASSRLS), but if a future change ever wires
//     it through a tenant-scoped pool the policy in migration 033 keeps
//     cross-tenant lookups from leaking.
package inbox

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog/log"
)

// Errors returned by the resolver. Handlers translate these to specific
// HTTP status codes (404 for unknown, 410 for revoked) so vendor
// dashboards can surface accurate failure reasons rather than blanket 4xx.
var (
	// ErrTokenNotFound — no active row matches the presented token.
	// Returned for both "we never minted this" and "fingerprint collision
	// matched a different tenant" cases; the handler treats both as 404
	// because we don't want to leak which one it was.
	ErrTokenNotFound = errors.New("inbox token not found")
	// ErrTokenRevoked — token exists but has been rotated/revoked.
	// Returned as 410 Gone so the operator can distinguish it from "you
	// pasted the wrong URL" (404) at the vendor side.
	ErrTokenRevoked = errors.New("inbox token revoked")
)

// Token is the resolved inbox token: which tenant owns it, which YAML
// template processes its payloads, and (optionally) the HMAC secret used
// to verify the X-Signature header.
type Token struct {
	Token      string
	TenantID   uuid.UUID
	TemplateID string
	Label      string
	HMACSecret string
	CreatedAt  time.Time
	LastUsedAt *time.Time
}

// Store resolves inbox tokens against Postgres with a tiny in-process
// LRU cache.
//
// The cache is intentionally small (default 4096 entries) and short-TTL
// (default 60s) — webhooks for a given token tend to come in bursts, and
// a stale cache hit just means a revoked token works for one more minute.
// We accept that tradeoff to keep the steady-state DB load close to zero.
type Store struct {
	pool *pgxpool.Pool

	mu       sync.RWMutex
	cache    map[string]cachedEntry
	cacheTTL time.Duration
	cacheMax int
}

type cachedEntry struct {
	token   *Token
	revoked bool // remembered separately so we can fail fast
	expires time.Time
}

// NewStore wraps a pgx pool with the resolver + cache.
//
// The pool is expected to be a service-role connection that bypasses RLS
// (since /v1/inbox/{token} runs unauthenticated from the operator's
// perspective — the URL itself is the credential, and the resolver has
// to look across tenants to find the row).
func NewStore(pool *pgxpool.Pool) *Store {
	return &Store{
		pool:     pool,
		cache:    make(map[string]cachedEntry),
		cacheTTL: 60 * time.Second,
		cacheMax: 4096,
	}
}

// SetCacheTTL overrides the default cache TTL. Useful for tests where we
// want to assert that a cache miss happens after a known interval.
func (s *Store) SetCacheTTL(ttl time.Duration) {
	s.mu.Lock()
	s.cacheTTL = ttl
	s.mu.Unlock()
}

// Resolve looks up an inbox token, returning the owning tenant and the
// template_id to apply. The hot path is a cache hit; on cache miss we
// hit Postgres with a single indexed query.
//
// Side effect: on a successful resolve we update last_used_at in the
// background (best-effort, fire-and-forget). We don't hold the request
// path waiting for that write because it's reporting metadata, not a
// security boundary.
func (s *Store) Resolve(ctx context.Context, token string) (*Token, error) {
	if token == "" {
		return nil, ErrTokenNotFound
	}

	// Cache hit?
	s.mu.RLock()
	entry, ok := s.cache[token]
	s.mu.RUnlock()
	if ok && time.Now().Before(entry.expires) {
		if entry.revoked {
			return nil, ErrTokenRevoked
		}
		// Fire-and-forget last_used_at update — only on cache hit because
		// the DB miss path will do its own UPDATE in the SELECT.
		go s.touchLastUsed(token)
		return entry.token, nil
	}

	// Cache miss / expired. Hit Postgres.
	row := s.pool.QueryRow(ctx, `
		SELECT
			token,
			tenant_id,
			template_id,
			COALESCE(label, ''),
			COALESCE(hmac_secret, ''),
			created_at,
			revoked_at,
			last_used_at
		FROM tenant_inbox_tokens
		WHERE token = $1
		LIMIT 1
	`, token)

	var (
		t         Token
		revokedAt *time.Time
		lastUsed  *time.Time
	)
	err := row.Scan(
		&t.Token,
		&t.TenantID,
		&t.TemplateID,
		&t.Label,
		&t.HMACSecret,
		&t.CreatedAt,
		&revokedAt,
		&lastUsed,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			s.cacheMiss(token, true) // negative cache: prevents lookup storm on bogus URLs
			return nil, ErrTokenNotFound
		}
		return nil, fmt.Errorf("inbox: resolve query failed: %w", err)
	}
	t.LastUsedAt = lastUsed

	if revokedAt != nil {
		s.cacheRevoked(token)
		return nil, ErrTokenRevoked
	}

	s.cacheHit(token, &t)
	go s.touchLastUsed(token)
	return &t, nil
}

func (s *Store) cacheHit(token string, t *Token) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.evictIfFullLocked()
	s.cache[token] = cachedEntry{
		token:   t,
		revoked: false,
		expires: time.Now().Add(s.cacheTTL),
	}
}

func (s *Store) cacheRevoked(token string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.evictIfFullLocked()
	s.cache[token] = cachedEntry{
		token:   nil,
		revoked: true,
		expires: time.Now().Add(s.cacheTTL),
	}
}

// cacheMiss caches a "no such token" result. We TTL it like any other
// entry but with a shorter horizon so that mint-then-immediately-call
// flows don't get stuck on a 404.
func (s *Store) cacheMiss(token string, persist bool) {
	if !persist {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.evictIfFullLocked()
	// Negative cache for 5s: long enough to absorb a vendor's retry
	// burst, short enough that the operator's "I just minted this" flow
	// works.
	s.cache[token] = cachedEntry{
		token:   nil,
		revoked: false,
		expires: time.Now().Add(5 * time.Second),
	}
}

// evictIfFullLocked is the world's simplest cache eviction: when we hit
// the size cap, drop expired entries; if we're still full, drop a
// random non-expired entry. We don't bother with LRU because the steady
// state has a small working set (one entry per active vendor webhook
// per tenant) and bursty traffic.
//
// Caller must hold s.mu (write).
func (s *Store) evictIfFullLocked() {
	if len(s.cache) < s.cacheMax {
		return
	}
	now := time.Now()
	for k, v := range s.cache {
		if now.After(v.expires) {
			delete(s.cache, k)
		}
	}
	if len(s.cache) < s.cacheMax {
		return
	}
	for k := range s.cache {
		delete(s.cache, k)
		break
	}
}

// touchLastUsed updates last_used_at in the background. Errors are
// logged at debug level; this metadata is purely for the UI's "last
// vendor delivery" badge so a missed update never affects ingest.
func (s *Store) touchLastUsed(token string) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, err := s.pool.Exec(ctx, `
		UPDATE tenant_inbox_tokens
		SET last_used_at = NOW()
		WHERE token = $1 AND revoked_at IS NULL
	`, token)
	if err != nil {
		log.Debug().Err(err).Msg("inbox: failed to update last_used_at")
	}
}

// Invalidate drops a token from the cache. Used by the rotate/revoke
// path so revoked tokens stop working immediately rather than waiting
// for the TTL to expire. (services/api can hit /admin/cache-bust if we
// ever wire that up; for now operators can also just wait 60s.)
func (s *Store) Invalidate(token string) {
	s.mu.Lock()
	delete(s.cache, token)
	s.mu.Unlock()
}
