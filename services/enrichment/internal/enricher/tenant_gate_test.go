package enricher

import "testing"

// Depth plan wave 2, item 8.3, first half.
//
// `RATE_LIMIT_RPS` and `RATE_LIMIT_BURST` were parsed in config.go and
// assigned to struct fields, and read by nothing else in the service. That
// is worse than a missing setting: an operator reading the environment
// believed the service was bounded.
//
// Every test here that grants permission has a partner that must be denied,
// because a limiter asserted only on the allowed path is indistinguishable
// from no limiter, which is exactly what shipped.
//
// The per-tenant *provider* gate that belongs to the same plan item is on
// `depth2/lane-b-enrichment-tenant` and lands with the caller that resolves
// a tenant's policy. It is default-deny, so threading it into `Enrich` here
// -- where no caller sends a policy yet -- would stop enrichment on every
// deployment.

func TestTheRateLimiterRefuses(t *testing.T) {
	// The partner assertion. A limiter that only ever grants is the same as
	// no limiter, and this service has shipped exactly that since the
	// settings were added.
	limiter := NewRateLimiter(1, 1)

	if !limiter.Allow("tenant-a") {
		t.Fatal("the first call within burst was denied; the limiter is not granting at all")
	}
	if limiter.Allow("tenant-a") {
		t.Fatal("a second immediate call was granted against rps=1 burst=1; the limiter does not refuse")
	}
}

func TestTheRateLimiterIsPerTenant(t *testing.T) {
	// One noisy tenant must not spend another tenant's budget, and a shared
	// bucket is also a cross-tenant signal: tenant B could infer tenant A's
	// enrichment volume from its own refusals.
	limiter := NewRateLimiter(1, 1)

	if !limiter.Allow("tenant-a") {
		t.Fatal("tenant A was denied its first call")
	}
	if !limiter.Allow("tenant-b") {
		t.Fatal("tenant B was denied because tenant A had spent the budget; the limiter is not per tenant")
	}
}

func TestAZeroRateMeansUnlimitedRatherThanBlocked(t *testing.T) {
	// A deployment that sets nothing must not silently stop enriching. The
	// config default is 100, but a 0 read from a malformed env var would
	// otherwise turn the whole feature off with no message anywhere.
	limiter := NewRateLimiter(0, 0)
	for i := 0; i < 50; i++ {
		if !limiter.Allow("tenant-a") {
			t.Fatalf("an unconfigured limiter refused call %d; an unset rate must not disable enrichment", i)
		}
	}
}

func TestTheLimiterRefillsOverTime(t *testing.T) {
	// Without a refill the first burst is the last one the deployment ever
	// gets, which is a limiter that breaks the feature rather than bounding
	// it. Driven by an injected clock rather than a sleep, so the test is
	// deterministic and fast.
	limiter := NewRateLimiter(10, 1)
	now := float64(0)
	limiter.now = func() float64 { return now }

	if !limiter.Allow("tenant-a") {
		t.Fatal("first call denied")
	}
	if limiter.Allow("tenant-a") {
		t.Fatal("second immediate call granted against burst=1")
	}
	now = 0.2 // two tokens' worth at 10 per second
	if !limiter.Allow("tenant-a") {
		t.Fatal("the bucket did not refill; the first burst would be the last")
	}
}
