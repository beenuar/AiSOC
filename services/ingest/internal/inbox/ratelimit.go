package inbox

import (
	"sync"
	"time"

	"github.com/google/uuid"
)

// Per-tenant rate limiting for the public inbox.
//
// /v1/inbox/* is the one endpoint deliberately exposed to the internet with
// no authentication beyond a bearer token in the path, which any vendor
// webhook config can hold. It had no limit of any kind: a single token could
// post unbounded requests carrying unbounded events, and the only backstop
// was maxBodySize on one request. One noisy (or compromised) integration
// could therefore fill Kafka, the lake and every tenant's alert queue behind
// it, and the blast radius crossed tenants because the spine is shared.
//
// Two dimensions are limited because they fail differently:
//
//   - requests/sec bounds connection and parse cost, which is what a
//     misconfigured vendor retry loop consumes.
//   - events/sec bounds what reaches Kafka, which is what actually costs
//     storage and triage. One accepted request can carry thousands of events,
//     so a request limit alone is not a volume limit.
//
// Scope: this is in-process, so with N ingest replicas the effective ceiling
// is N times the configured rate. That is a deliberate trade — a shared
// limiter needs Redis, which ingest does not otherwise depend on, and a
// per-replica bound already turns "unbounded" into "bounded and
// proportional". Operators who need an exact global cap should set the rate
// to the target divided by replica count, or terminate at the edge.

// bucket is a token bucket that refills continuously.
type bucket struct {
	tokens   float64
	lastFill time.Time
	lastSeen time.Time
}

// Limiter enforces per-tenant request and event ceilings.
//
// The zero value is unusable; construct with NewLimiter. A nil *Limiter is
// valid and allows everything, so callers do not need nil checks and the
// limiter can be switched off by configuration without branching at each
// call site.
type Limiter struct {
	mu      sync.Mutex
	buckets map[uuid.UUID]*limiterEntry

	reqRate    float64
	reqBurst   float64
	eventRate  float64
	eventBurst float64

	// now is injectable so tests can advance time without sleeping; a
	// rate limiter tested with real sleeps is either slow or flaky.
	now func() time.Time

	lastSweep time.Time
	idleTTL   time.Duration
}

type limiterEntry struct {
	requests bucket
	events   bucket
}

// NewLimiter builds a limiter. A non-positive rate disables that dimension.
//
// Burst defaults to one second of rate when not positive, which keeps a
// vendor that batches its retries from being rejected for the shape of its
// traffic rather than its volume.
func NewLimiter(reqRate, reqBurst, eventRate, eventBurst float64) *Limiter {
	if reqRate > 0 && reqBurst <= 0 {
		reqBurst = reqRate
	}
	if eventRate > 0 && eventBurst <= 0 {
		eventBurst = eventRate
	}
	return &Limiter{
		buckets:    make(map[uuid.UUID]*limiterEntry),
		reqRate:    reqRate,
		reqBurst:   reqBurst,
		eventRate:  eventRate,
		eventBurst: eventBurst,
		now:        time.Now,
		idleTTL:    15 * time.Minute,
	}
}

// refill advances a bucket to t and returns it.
func (b *bucket) refill(t time.Time, rate, burst float64) {
	if b.lastFill.IsZero() {
		b.tokens = burst
		b.lastFill = t
		return
	}
	elapsed := t.Sub(b.lastFill).Seconds()
	if elapsed <= 0 {
		return
	}
	b.tokens += elapsed * rate
	if b.tokens > burst {
		b.tokens = burst
	}
	b.lastFill = t
}

// take removes n tokens if available. Returns ok and, when not ok, how long
// until n tokens would be available.
func (b *bucket) take(n, rate, burst float64) (bool, time.Duration) {
	if b.tokens >= n {
		b.tokens -= n
		return true, 0
	}
	if rate <= 0 {
		return false, 0
	}
	deficit := n - b.tokens
	// A single request asking for more than the entire burst can never be
	// satisfied by waiting, so report the full refill of the burst rather
	// than a wait that will not help.
	if n > burst {
		return false, time.Duration(burst/rate*float64(time.Second)) + time.Second
	}
	return false, time.Duration(deficit / rate * float64(time.Second))
}

func (l *Limiter) entry(tenant uuid.UUID, t time.Time) *limiterEntry {
	e, ok := l.buckets[tenant]
	if !ok {
		e = &limiterEntry{}
		l.buckets[tenant] = e
	}
	e.requests.lastSeen = t
	e.events.lastSeen = t
	return e
}

// sweep drops buckets untouched for idleTTL. Without it the map grows once
// per distinct tenant seen, which is an attacker-controlled dimension: the
// path segment is a token and a miss still reaches here on the routes that
// resolve first.
func (l *Limiter) sweep(t time.Time) {
	if t.Sub(l.lastSweep) < l.idleTTL {
		return
	}
	l.lastSweep = t
	for id, e := range l.buckets {
		if t.Sub(e.requests.lastSeen) > l.idleTTL {
			delete(l.buckets, id)
		}
	}
}

// AllowRequest reports whether one more request from tenant is permitted.
func (l *Limiter) AllowRequest(tenant uuid.UUID) (bool, time.Duration) {
	if l == nil || l.reqRate <= 0 {
		return true, 0
	}
	l.mu.Lock()
	defer l.mu.Unlock()

	t := l.now()
	l.sweep(t)
	e := l.entry(tenant, t)
	e.requests.refill(t, l.reqRate, l.reqBurst)
	return e.requests.take(1, l.reqRate, l.reqBurst)
}

// AllowEvents reports whether n more events from tenant are permitted.
//
// Called after parsing, because the count is not knowable before then. A
// rejected batch is rejected whole: partially accepting events would split a
// vendor's payload across a boundary the vendor cannot see, and it would
// make retries duplicate the accepted half.
func (l *Limiter) AllowEvents(tenant uuid.UUID, n int) (bool, time.Duration) {
	if l == nil || l.eventRate <= 0 || n <= 0 {
		return true, 0
	}
	l.mu.Lock()
	defer l.mu.Unlock()

	t := l.now()
	e := l.entry(tenant, t)
	e.events.refill(t, l.eventRate, l.eventBurst)
	return e.events.take(float64(n), l.eventRate, l.eventBurst)
}

// Tracked reports how many tenants currently hold buckets. Test and
// diagnostics only.
func (l *Limiter) Tracked() int {
	if l == nil {
		return 0
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.buckets)
}

// retryAfterSeconds renders a Retry-After header value, rounded up so a
// client that honours it exactly does not come back one tick too early.
func retryAfterSeconds(d time.Duration) int {
	if d <= 0 {
		return 1
	}
	secs := int(d / time.Second)
	if d%time.Second != 0 {
		secs++
	}
	if secs < 1 {
		return 1
	}
	return secs
}
