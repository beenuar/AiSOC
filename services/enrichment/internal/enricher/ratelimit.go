// Per-tenant enrichment rate limiting.
//
// Depth plan wave 2, item 8.3, first half.
//
// `RATE_LIMIT_RPS` and `RATE_LIMIT_BURST` were parsed into config and read
// by nothing. A limiter nobody applies is the same as no limiter, except
// that the settings make a reader believe otherwise, so the honesty cost is
// higher than the missing capability.
//
// A token bucket per tenant, not one bucket shared. Two reasons, and the
// second is easy to miss: a shared bucket lets one noisy tenant spend
// another's budget, and it is also a cross-tenant signal, because tenant B
// could infer tenant A's enrichment volume from its own refusals.
//
// An unset rate means unlimited rather than blocked. The config default is
// 100, but a malformed environment variable parses to 0, and a limiter that
// read that as "allow nothing" would turn enrichment off across the
// deployment with no message anywhere.
package enricher

import (
	"sync"
	"time"
)

// RateLimiter is a per-tenant token bucket.
type RateLimiter struct {
	rps   float64
	burst float64

	mu      sync.Mutex
	buckets map[string]*bucket

	// now is injectable so the refill behaviour can be tested without a
	// sleep. A test that sleeps to prove a refill is slow and flaky, and a
	// refill nobody tests is how a limiter comes to grant one burst and then
	// refuse forever.
	now func() float64
}

type bucket struct {
	tokens float64
	last   float64
}

// NewRateLimiter returns a limiter at `rps` requests per second with a burst
// of `burst`. A non-positive rate means unlimited; see the package comment
// for why that direction rather than the other.
func NewRateLimiter(rps, burst int) *RateLimiter {
	effectiveBurst := float64(burst)
	if effectiveBurst < 1 {
		effectiveBurst = 1
	}
	return &RateLimiter{
		rps:     float64(rps),
		burst:   effectiveBurst,
		buckets: make(map[string]*bucket),
		now:     func() float64 { return float64(time.Now().UnixNano()) / 1e9 },
	}
}

// Allow reports whether this tenant may make one more request now.
func (l *RateLimiter) Allow(tenantID string) bool {
	if l == nil || l.rps <= 0 {
		return true
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	now := l.now()
	b, ok := l.buckets[tenantID]
	if !ok {
		b = &bucket{tokens: l.burst, last: now}
		l.buckets[tenantID] = b
	}

	elapsed := now - b.last
	if elapsed > 0 {
		b.tokens += elapsed * l.rps
		if b.tokens > l.burst {
			b.tokens = l.burst
		}
		b.last = now
	}

	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}
