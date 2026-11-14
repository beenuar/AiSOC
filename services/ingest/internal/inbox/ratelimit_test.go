package inbox

import (
	"testing"
	"time"

	"github.com/google/uuid"
)

// The inbox is the one route deliberately open to the internet, and it had
// no ceiling of any kind. These tests pin the properties that make the
// limiter worth having rather than just present: that one tenant cannot
// consume another's budget, that a large batch is bounded by events rather
// than by request count, and that the bucket map cannot grow without bound
// on a dimension an attacker controls.

func newTestLimiter(reqRate, reqBurst, evRate, evBurst float64) (*Limiter, func(time.Duration)) {
	l := NewLimiter(reqRate, reqBurst, evRate, evBurst)
	now := time.Date(2026, 9, 22, 12, 0, 0, 0, time.UTC)
	l.now = func() time.Time { return now }
	return l, func(d time.Duration) { now = now.Add(d) }
}

func TestNilLimiterAllowsEverything(t *testing.T) {
	// Callers must not need nil checks, and switching limiting off must not
	// mean editing every call site.
	var l *Limiter
	if ok, _ := l.AllowRequest(uuid.New()); !ok {
		t.Fatal("nil limiter rejected a request")
	}
	if ok, _ := l.AllowEvents(uuid.New(), 1_000_000); !ok {
		t.Fatal("nil limiter rejected events")
	}
}

func TestZeroRateDisablesTheDimension(t *testing.T) {
	l, _ := newTestLimiter(0, 0, 10, 10)
	for i := 0; i < 1000; i++ {
		if ok, _ := l.AllowRequest(uuid.New()); !ok {
			t.Fatalf("request %d rejected with rate disabled", i)
		}
	}
}

func TestRequestBurstThenThrottle(t *testing.T) {
	l, advance := newTestLimiter(10, 5, 0, 0)
	tenant := uuid.New()

	for i := 0; i < 5; i++ {
		if ok, _ := l.AllowRequest(tenant); !ok {
			t.Fatalf("burst request %d was rejected; burst is 5", i+1)
		}
	}
	ok, wait := l.AllowRequest(tenant)
	if ok {
		t.Fatal("sixth request passed; the burst should be exhausted")
	}
	if wait <= 0 {
		t.Fatal("a rejection must say how long to wait")
	}

	advance(100 * time.Millisecond) // one token at 10/s
	if ok, _ := l.AllowRequest(tenant); !ok {
		t.Fatal("bucket did not refill after the advertised wait")
	}
}

func TestBucketRefillIsCappedAtBurst(t *testing.T) {
	l, advance := newTestLimiter(10, 5, 0, 0)
	tenant := uuid.New()

	advance(1 * time.Hour) // a long idle period must not bank credit
	allowed := 0
	for i := 0; i < 50; i++ {
		if ok, _ := l.AllowRequest(tenant); ok {
			allowed++
		}
	}
	if allowed != 5 {
		t.Fatalf("after an hour idle, allowed %d requests; burst is 5", allowed)
	}
}

func TestTenantsDoNotShareBudget(t *testing.T) {
	// The whole point: one noisy integration must not starve the others.
	l, _ := newTestLimiter(10, 2, 0, 0)
	noisy, quiet := uuid.New(), uuid.New()

	for i := 0; i < 20; i++ {
		l.AllowRequest(noisy)
	}
	if ok, _ := l.AllowRequest(noisy); ok {
		t.Fatal("noisy tenant was not throttled")
	}
	for i := 0; i < 2; i++ {
		if ok, _ := l.AllowRequest(quiet); !ok {
			t.Fatalf("quiet tenant rejected at request %d after a noisy neighbour", i+1)
		}
	}
}

func TestEventQuotaBoundsVolumeNotJustRequestCount(t *testing.T) {
	// A request limit alone is not a volume limit: one accepted request can
	// carry thousands of events.
	l, _ := newTestLimiter(1000, 1000, 100, 100)
	tenant := uuid.New()

	if ok, _ := l.AllowEvents(tenant, 100); !ok {
		t.Fatal("a batch exactly at burst was rejected")
	}
	if ok, _ := l.AllowEvents(tenant, 1); ok {
		t.Fatal("event quota did not bind after the burst was consumed")
	}
	// The request dimension is untouched, which is the point of splitting them.
	if ok, _ := l.AllowRequest(tenant); !ok {
		t.Fatal("request budget was consumed by the event quota")
	}
}

func TestBatchLargerThanBurstIsRejectedWithAFiniteWait(t *testing.T) {
	// Waiting cannot help a batch bigger than the burst; the caller still
	// needs a usable Retry-After rather than a zero or an absurd one.
	l, _ := newTestLimiter(0, 0, 100, 100)
	ok, wait := l.AllowEvents(uuid.New(), 5000)
	if ok {
		t.Fatal("an over-burst batch was accepted")
	}
	if wait <= 0 || wait > 10*time.Second {
		t.Fatalf("implausible Retry-After for an over-burst batch: %v", wait)
	}
}

func TestRejectedBatchConsumesNothing(t *testing.T) {
	// A partial deduction would leave the tenant's budget drained by a batch
	// that was never accepted, so the retry it was told to make also fails.
	l, _ := newTestLimiter(0, 0, 100, 100)
	tenant := uuid.New()

	if ok, _ := l.AllowEvents(tenant, 150); ok {
		t.Fatal("over-budget batch accepted")
	}
	if ok, _ := l.AllowEvents(tenant, 100); !ok {
		t.Fatal("a rejected batch consumed budget it was not granted")
	}
}

func TestNonPositiveEventCountIsNotCharged(t *testing.T) {
	l, _ := newTestLimiter(0, 0, 10, 10)
	tenant := uuid.New()
	for i := 0; i < 100; i++ {
		if ok, _ := l.AllowEvents(tenant, 0); !ok {
			t.Fatal("an empty batch consumed quota")
		}
	}
	if ok, _ := l.AllowEvents(tenant, 10); !ok {
		t.Fatal("empty batches drained the bucket")
	}
}

func TestIdleTenantsAreSweptSoTheMapCannotGrowUnbounded(t *testing.T) {
	// The tenant dimension is reachable by anyone holding tokens, so an
	// unbounded map is a memory-exhaustion vector rather than untidiness.
	l, advance := newTestLimiter(10, 10, 0, 0)

	for i := 0; i < 100; i++ {
		l.AllowRequest(uuid.New())
	}
	if got := l.Tracked(); got != 100 {
		t.Fatalf("tracked %d tenants, expected 100", got)
	}

	advance(16 * time.Minute)
	l.AllowRequest(uuid.New()) // any call triggers the sweep

	if got := l.Tracked(); got > 1 {
		t.Fatalf("idle buckets were not swept: %d still tracked", got)
	}
}

func TestActiveTenantsSurviveTheSweep(t *testing.T) {
	l, advance := newTestLimiter(10, 3, 0, 0)
	active := uuid.New()

	l.AllowRequest(active)
	advance(16 * time.Minute)
	l.AllowRequest(active) // refreshes lastSeen and sweeps
	advance(1 * time.Minute)

	// Consume the burst; if the bucket had been dropped it would be full
	// again and this would not throttle.
	for i := 0; i < 3; i++ {
		l.AllowRequest(active)
	}
	if ok, _ := l.AllowRequest(active); ok {
		t.Fatal("an active tenant's bucket was reset by the sweep")
	}
}

func TestRetryAfterSecondsAlwaysRoundsUp(t *testing.T) {
	// A client honouring Retry-After exactly must not come back one tick
	// early and be rejected again.
	cases := []struct {
		in   time.Duration
		want int
	}{
		{0, 1},
		{-time.Second, 1},
		{1 * time.Millisecond, 1},
		{999 * time.Millisecond, 1},
		{1 * time.Second, 1},
		{1001 * time.Millisecond, 2},
		{2500 * time.Millisecond, 3},
	}
	for _, c := range cases {
		if got := retryAfterSeconds(c.in); got != c.want {
			t.Errorf("retryAfterSeconds(%v) = %d, want %d", c.in, got, c.want)
		}
	}
}

func TestDefaultBurstFallsBackToRate(t *testing.T) {
	l := NewLimiter(10, 0, 20, 0)
	if l.reqBurst != 10 || l.eventBurst != 20 {
		t.Fatalf("burst defaults wrong: req=%v event=%v", l.reqBurst, l.eventBurst)
	}
}

func TestConcurrentAccessIsSafe(t *testing.T) {
	// Run with -race; the limiter is shared across every inbound request.
	l := NewLimiter(1000, 1000, 10000, 10000)
	tenants := []uuid.UUID{uuid.New(), uuid.New(), uuid.New()}
	done := make(chan struct{})

	for i := 0; i < 8; i++ {
		go func(i int) {
			for j := 0; j < 200; j++ {
				tenant := tenants[j%len(tenants)]
				l.AllowRequest(tenant)
				l.AllowEvents(tenant, 3)
			}
			done <- struct{}{}
		}(i)
	}
	for i := 0; i < 8; i++ {
		<-done
	}
	if l.Tracked() != len(tenants) {
		t.Fatalf("tracked %d tenants, expected %d", l.Tracked(), len(tenants))
	}
}
