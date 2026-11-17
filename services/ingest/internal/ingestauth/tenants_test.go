// tenants_test.go — what PgTenantDirectory does when Postgres blinks.
//
// Service-token auth calls IsActive on every push. The 60s cache is the
// reason a brief outage usually still accepts writes, but a cache hit
// does not refresh the TTL, so the second minute of a job is not
// covered unless a lookup failure can reuse the last observed answer.
// The spine chaos step is the acceptance test for that invariant; these
// unit tests pin the directory itself so a regression does not wait for
// a 60s integration timeout.
package ingestauth

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func directoryWithLookup(ttl time.Duration, lookup func(context.Context, uuid.UUID) (bool, error)) *PgTenantDirectory {
	return &PgTenantDirectory{
		cache:  make(map[uuid.UUID]cachedTenant),
		ttl:    ttl,
		max:    4096,
		lookup: lookup,
	}
}

func TestIsActive_ServesStaleAnswerWhenLookupFailsAfterTTL(t *testing.T) {
	id := uuid.MustParse("55555555-5555-4555-8555-555555555555")
	var calls int
	d := directoryWithLookup(20*time.Millisecond, func(context.Context, uuid.UUID) (bool, error) {
		calls++
		if calls == 1 {
			return true, nil
		}
		return false, errors.New("connection refused")
	})

	active, err := d.IsActive(context.Background(), id)
	if err != nil || !active {
		t.Fatalf("initial lookup: active=%v err=%v; want active tenant", active, err)
	}

	time.Sleep(30 * time.Millisecond)

	active, err = d.IsActive(context.Background(), id)
	if err != nil {
		t.Fatalf("expired cache + lookup failure returned %v; want the stale active answer", err)
	}
	if !active {
		t.Fatalf("stale answer was inactive; want the last observed active=true")
	}
	if calls != 2 {
		t.Fatalf("lookup calls = %d; want 2 (fresh, then after TTL)", calls)
	}
}

func TestIsActive_LookupFailureWithNoCacheIsAnError(t *testing.T) {
	id := uuid.MustParse("66666666-6666-4666-8666-666666666666")
	d := directoryWithLookup(time.Minute, func(context.Context, uuid.UUID) (bool, error) {
		return false, errors.New("connection refused")
	})

	active, err := d.IsActive(context.Background(), id)
	if err == nil {
		t.Fatalf("lookup failure with no cache returned active=%v, nil error; want an error so the caller answers 503", active)
	}
	if active {
		t.Fatalf("lookup failure with no cache returned active=true")
	}
}

func TestIsActive_ErrNoRowsIsInactiveNotAnError(t *testing.T) {
	id := uuid.MustParse("77777777-7777-4777-8777-777777777777")
	d := directoryWithLookup(time.Minute, func(context.Context, uuid.UUID) (bool, error) {
		return false, pgx.ErrNoRows
	})

	active, err := d.IsActive(context.Background(), id)
	if err != nil {
		t.Fatalf("a definitive miss returned %v; want inactive, nil", err)
	}
	if active {
		t.Fatalf("a definitive miss was reported active")
	}

	// A later outage must not revive a tenant we already know is missing.
	d.lookup = func(context.Context, uuid.UUID) (bool, error) {
		return false, errors.New("connection refused")
	}
	// Still inside the TTL: cache hit, no lookup.
	active, err = d.IsActive(context.Background(), id)
	if err != nil || active {
		t.Fatalf("cached miss: active=%v err=%v; want inactive, nil", active, err)
	}
}

func TestIsActive_CacheHitDoesNotLookup(t *testing.T) {
	id := uuid.MustParse("88888888-8888-4888-8888-888888888888")
	var calls int
	d := directoryWithLookup(time.Minute, func(context.Context, uuid.UUID) (bool, error) {
		calls++
		return true, nil
	})

	if _, err := d.IsActive(context.Background(), id); err != nil {
		t.Fatalf("initial lookup: %v", err)
	}
	if _, err := d.IsActive(context.Background(), id); err != nil {
		t.Fatalf("cached lookup: %v", err)
	}
	if calls != 1 {
		t.Fatalf("lookup calls = %d; want 1 — a cache hit must not refresh via the database", calls)
	}
}

func TestIsActive_HealthyLookupAfterTTLRefreshesTheAnswer(t *testing.T) {
	id := uuid.MustParse("99999999-9999-4999-8999-999999999999")
	var calls int
	d := directoryWithLookup(20*time.Millisecond, func(context.Context, uuid.UUID) (bool, error) {
		calls++
		if calls == 1 {
			return true, nil
		}
		return false, nil
	})

	active, err := d.IsActive(context.Background(), id)
	if err != nil || !active {
		t.Fatalf("initial lookup: active=%v err=%v", active, err)
	}
	time.Sleep(30 * time.Millisecond)
	active, err = d.IsActive(context.Background(), id)
	if err != nil {
		t.Fatalf("refresh lookup: %v", err)
	}
	if active {
		t.Fatalf("after TTL a healthy lookup that returned inactive was ignored")
	}
}
