package ingestauth

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// PgTenantDirectory checks a declared tenant against the tenants table,
// with a short-TTL cache in front.
//
// Both outcomes are cached, not just the hit. A forged tenant UUID is
// exactly the traffic a service-token holder would generate if it were
// compromised or misconfigured, and an uncached miss turns each one into a
// database round-trip — so the negative cache is the part that keeps a
// flood of bad UUIDs from becoming a second outage on top of the first.
type PgTenantDirectory struct {
	pool   *pgxpool.Pool
	lookup func(ctx context.Context, id uuid.UUID) (bool, error)

	mu    sync.RWMutex
	cache map[uuid.UUID]cachedTenant
	ttl   time.Duration
	max   int
}

type cachedTenant struct {
	active  bool
	expires time.Time
}

// NewTenantDirectory wraps a pgx pool. The 60s TTL matches the inbox token
// cache: a tenant deactivated in the console stops being writable within a
// minute, which is the same staleness window an operator already accepts
// when they revoke an inbox token.
func NewTenantDirectory(pool *pgxpool.Pool) *PgTenantDirectory {
	d := &PgTenantDirectory{
		pool:  pool,
		cache: make(map[uuid.UUID]cachedTenant),
		ttl:   60 * time.Second,
		max:   4096,
	}
	d.lookup = d.queryActive
	return d
}

func (d *PgTenantDirectory) queryActive(ctx context.Context, id uuid.UUID) (bool, error) {
	var active bool
	err := d.pool.QueryRow(ctx,
		`SELECT COALESCE(is_active, TRUE) FROM tenants WHERE id = $1`, id,
	).Scan(&active)
	if err != nil {
		return false, err
	}
	return active, nil
}

// IsActive reports whether the tenant exists and has not been deactivated.
//
// A definitive miss (no such row) is cached as inactive. A lookup failure
// is not: telling a correctly-credentialled service that its tenant is
// unknown, when the truth is that Postgres blinked, sends an operator to
// the wrong problem, so the caller answers 503 instead of 403.
//
// If we have already observed this tenant, though, a lookup failure
// reuses that answer even after the TTL. Service-token auth re-checks
// the directory on every push, and a cache hit does not refresh the TTL,
// so a later push during a brief outage would otherwise 503 once sixty
// seconds had passed — which is exactly the spine invariant that ingest's
// hot path does not depend on Postgres. A tenant that has never been
// seen still surfaces the lookup error.
func (d *PgTenantDirectory) IsActive(ctx context.Context, id uuid.UUID) (bool, error) {
	d.mu.RLock()
	entry, ok := d.cache[id]
	d.mu.RUnlock()
	if ok && time.Now().Before(entry.expires) {
		return entry.active, nil
	}

	active, err := d.lookup(ctx, id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			d.remember(id, false)
			return false, nil
		}
		if ok {
			return entry.active, nil
		}
		return false, fmt.Errorf("ingestauth: tenant lookup failed: %w", err)
	}

	d.remember(id, active)
	return active, nil
}

func (d *PgTenantDirectory) remember(id uuid.UUID, active bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if len(d.cache) >= d.max {
		now := time.Now()
		for k, v := range d.cache {
			if now.After(v.expires) {
				delete(d.cache, k)
			}
		}
		if len(d.cache) >= d.max {
			for k := range d.cache {
				delete(d.cache, k)
				break
			}
		}
	}
	d.cache[id] = cachedTenant{active: active, expires: time.Now().Add(d.ttl)}
}
