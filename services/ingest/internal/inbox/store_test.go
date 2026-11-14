package inbox

import (
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
)

// Store tests focus on the cache layer because the DB-resolve path is
// exercised by integration tests against the real schema. The cache
// behaviour is what saves us from a thundering herd on every webhook —
// if the LRU/TTL contract regresses, every PagerDuty incident becomes a
// Postgres query, which would silently double our ingest latency budget.
//
// We construct stores with a nil pool because the methods under test
// never touch the pool. The Resolve() method does, but we don't call it
// here — that would need either pgxmock or a real DB and belongs in
// integration coverage.

func newTestStore() *Store {
	return &Store{
		pool:     nil, // intentional — we never call Resolve in these tests
		cache:    make(map[string]cachedEntry),
		cacheTTL: 60 * time.Second,
		cacheMax: 4096,
	}
}

func TestStore_CacheHit_StoresAndExpires(t *testing.T) {
	s := newTestStore()
	s.SetCacheTTL(50 * time.Millisecond)

	tok := &Token{
		Token:      "abc123",
		TenantID:   uuid.New(),
		TemplateID: "pagerduty",
		Label:      "PagerDuty - prod",
	}
	s.cacheHit("abc123", tok)

	// Within TTL: hit.
	s.mu.RLock()
	entry, ok := s.cache["abc123"]
	s.mu.RUnlock()
	if !ok {
		t.Fatalf("cache entry missing after cacheHit")
	}
	if entry.token != tok {
		t.Errorf("cache stored wrong token: %v", entry.token)
	}
	if entry.revoked {
		t.Errorf("cache entry should not be marked revoked")
	}
	if !time.Now().Before(entry.expires) {
		t.Errorf("cache entry already expired immediately after store")
	}

	// After TTL: expired (we look at the expires field rather than the
	// public Resolve contract because Resolve hits the DB on expiry,
	// which we can't do without a pool).
	time.Sleep(60 * time.Millisecond)
	s.mu.RLock()
	entry = s.cache["abc123"]
	s.mu.RUnlock()
	if time.Now().Before(entry.expires) {
		t.Errorf("cache entry should have expired by now")
	}
}

func TestStore_CacheRevoked_FlagsEntryAsRevoked(t *testing.T) {
	s := newTestStore()
	s.cacheRevoked("revoked-token")

	s.mu.RLock()
	entry, ok := s.cache["revoked-token"]
	s.mu.RUnlock()
	if !ok {
		t.Fatalf("cache entry missing after cacheRevoked")
	}
	if !entry.revoked {
		t.Errorf("entry not flagged revoked: %#v", entry)
	}
	if entry.token != nil {
		t.Errorf("revoked entry should not carry a token, got %v", entry.token)
	}
}

func TestStore_CacheMiss_PersistFalseDoesNotCache(t *testing.T) {
	// The persist=false path is a guard for callers who don't want a
	// negative cache entry. Verify the cache stays empty.
	s := newTestStore()
	s.cacheMiss("ignore-me", false)
	if len(s.cache) != 0 {
		t.Errorf("cacheMiss(persist=false) should not store anything, got %d entries", len(s.cache))
	}
}

func TestStore_CacheMiss_PersistTrueSetsShortTTL(t *testing.T) {
	// The persist=true negative cache uses a 5s TTL — short enough that
	// "I just minted this token" flows recover quickly, long enough to
	// absorb a vendor's retry burst on a typo.
	s := newTestStore()
	s.SetCacheTTL(60 * time.Second)
	s.cacheMiss("bogus", true)

	s.mu.RLock()
	entry := s.cache["bogus"]
	s.mu.RUnlock()
	expectedHorizon := time.Now().Add(5 * time.Second)
	delta := entry.expires.Sub(expectedHorizon)
	if delta < -200*time.Millisecond || delta > 200*time.Millisecond {
		t.Errorf("negative cache TTL = %v from now, want ~5s", entry.expires.Sub(time.Now()))
	}
}

func TestStore_Invalidate_DropsEntry(t *testing.T) {
	// Rotation flow: services/api rotates a token, then calls Invalidate
	// so the new revoked status takes effect immediately rather than
	// waiting out the TTL.
	s := newTestStore()
	s.cacheHit("tok", &Token{Token: "tok"})

	s.Invalidate("tok")

	s.mu.RLock()
	_, ok := s.cache["tok"]
	s.mu.RUnlock()
	if ok {
		t.Errorf("Invalidate should have removed the entry")
	}
}

func TestStore_EvictIfFull_RemovesExpiredEntriesFirst(t *testing.T) {
	s := newTestStore()
	s.cacheMax = 4
	s.SetCacheTTL(60 * time.Second)

	// 4 entries, 2 of them already expired.
	now := time.Now()
	s.mu.Lock()
	s.cache["expired-1"] = cachedEntry{token: &Token{}, expires: now.Add(-10 * time.Second)}
	s.cache["expired-2"] = cachedEntry{token: &Token{}, expires: now.Add(-1 * time.Second)}
	s.cache["fresh-1"] = cachedEntry{token: &Token{}, expires: now.Add(60 * time.Second)}
	s.cache["fresh-2"] = cachedEntry{token: &Token{}, expires: now.Add(60 * time.Second)}
	s.mu.Unlock()

	// Add a 5th — eviction should fire and clear the expired pair first.
	s.cacheHit("fresh-3", &Token{})

	s.mu.RLock()
	defer s.mu.RUnlock()
	if _, ok := s.cache["expired-1"]; ok {
		t.Errorf("expired-1 should have been evicted")
	}
	if _, ok := s.cache["expired-2"]; ok {
		t.Errorf("expired-2 should have been evicted")
	}
	// Fresh entries should still be there.
	if _, ok := s.cache["fresh-1"]; !ok {
		t.Errorf("fresh-1 evicted unexpectedly")
	}
	if _, ok := s.cache["fresh-2"]; !ok {
		t.Errorf("fresh-2 evicted unexpectedly")
	}
	if _, ok := s.cache["fresh-3"]; !ok {
		t.Errorf("newly added fresh-3 missing")
	}
}

func TestStore_EvictIfFull_FallsBackToRandomEvictionWhenAllFresh(t *testing.T) {
	// When every entry is fresh and we're full, the simple evictor drops
	// one arbitrary entry to make room. Verify size invariant rather than
	// which specific entry — the contract is "make room", not "be LRU".
	s := newTestStore()
	s.cacheMax = 3

	now := time.Now()
	s.mu.Lock()
	s.cache["a"] = cachedEntry{token: &Token{}, expires: now.Add(60 * time.Second)}
	s.cache["b"] = cachedEntry{token: &Token{}, expires: now.Add(60 * time.Second)}
	s.cache["c"] = cachedEntry{token: &Token{}, expires: now.Add(60 * time.Second)}
	s.mu.Unlock()

	s.cacheHit("d", &Token{})

	s.mu.RLock()
	defer s.mu.RUnlock()
	if len(s.cache) > 3 {
		t.Errorf("cache exceeded max: size=%d, max=%d", len(s.cache), s.cacheMax)
	}
	if _, ok := s.cache["d"]; !ok {
		t.Errorf("most-recent insert evicted itself, which would defeat the purpose")
	}
}

func TestStore_EvictIfFull_NoOpWhenUnderCap(t *testing.T) {
	s := newTestStore()
	s.cacheMax = 100
	s.cacheHit("a", &Token{})
	s.cacheHit("b", &Token{})

	s.mu.RLock()
	defer s.mu.RUnlock()
	if len(s.cache) != 2 {
		t.Errorf("cache size = %d, want 2 (no eviction below cap)", len(s.cache))
	}
}

func TestStore_SetCacheTTL_TakesEffectImmediately(t *testing.T) {
	s := newTestStore()
	s.SetCacheTTL(10 * time.Millisecond)

	s.cacheHit("short-lived", &Token{})

	s.mu.RLock()
	expires := s.cache["short-lived"].expires
	s.mu.RUnlock()

	if expires.Sub(time.Now()) > 100*time.Millisecond {
		t.Errorf("SetCacheTTL not honoured: %v from now", expires.Sub(time.Now()))
	}
}

// Concurrency smoke: lots of goroutines hammering the cache must not
// race or panic. The race detector catches the rest.
func TestStore_Cache_ConcurrentAccessIsSafe(t *testing.T) {
	s := newTestStore()
	const workers = 32
	const ops = 200

	var wg sync.WaitGroup
	wg.Add(workers)
	for w := 0; w < workers; w++ {
		go func(wid int) {
			defer wg.Done()
			tok := &Token{Token: "shared"}
			for i := 0; i < ops; i++ {
				switch i % 4 {
				case 0:
					s.cacheHit("shared", tok)
				case 1:
					s.cacheRevoked("shared")
				case 2:
					s.cacheMiss("shared", true)
				case 3:
					s.Invalidate("shared")
				}
			}
		}(w)
	}
	wg.Wait()
	// If we got here without a deadlock or panic, we're fine.
}
