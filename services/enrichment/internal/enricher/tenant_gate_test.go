package enricher

import (
	"context"
	"testing"
)

// Depth plan wave 2, item 8.3.
//
// Two properties, and the first is the one that matters most.
//
// **Nothing is sent for a provider a tenant has not enabled.** Today there is
// no tenant dimension anywhere in this service: `grep -c tenant` over
// `enricher.go` and `config.go` returns 0 and 0. Keys are per deployment, so
// a deployment with a VirusTotal key sends every tenant's indicators to
// VirusTotal whether that tenant agreed to it or not. An indicator is a
// customer's own address, domain or file hash; sending one to a third party
// is a disclosure, and a disclosure nobody consented to is the defect here
// rather than a configuration preference.
//
// **The rate limiter must refuse.** `RATE_LIMIT_RPS` and `RATE_LIMIT_BURST`
// are parsed in config.go and assigned to struct fields, and nothing in the
// service reads them. A limiter asserted only on the allowed path is
// indistinguishable from no limiter, so every test below that grants
// permission has a partner that must be denied.

// recordingProvider stands in for a vendor client and records whether it was
// called. A mock that returns a result on demand would let the gate pass by
// being bypassed; what has to be observable is the *call*.
type recordingProvider struct {
	name   string
	called int
}

func (p *recordingProvider) task() fanOutTask {
	return fanOutTask{
		name: p.name,
		fn: func() (*EnrichmentResult, error) {
			p.called++
			return &EnrichmentResult{Value: "x"}, nil
		},
	}
}

func TestOnlyEnabledProvidersAreCalled(t *testing.T) {
	enabled := &recordingProvider{name: "virustotal"}
	disabled := &recordingProvider{name: "abuseipdb"}

	policy := NewTenantPolicy(map[string]bool{"virustotal": true})

	runFanOutForTenant(context.Background(), "1.2.3.4", policy, []fanOutTask{
		enabled.task(),
		disabled.task(),
	})

	if enabled.called != 1 {
		t.Errorf("an enabled provider was called %d time(s), want 1", enabled.called)
	}
	if disabled.called != 0 {
		t.Errorf("a provider the tenant did not enable was called %d time(s); an indicator is the customer's own data and sending it is a disclosure", disabled.called)
	}
}

func TestAnEmptyPolicyCallsNothing(t *testing.T) {
	// Default-deny, and this is the direction the defect ran: a tenant that
	// has enabled nothing must have nothing sent, not everything the
	// deployment happens to hold a key for.
	provider := &recordingProvider{name: "virustotal"}
	runFanOutForTenant(context.Background(), "1.2.3.4", NewTenantPolicy(nil), []fanOutTask{provider.task()})
	if provider.called != 0 {
		t.Errorf("a tenant that enabled nothing had %d provider(s) called", provider.called)
	}
}

func TestAProviderExplicitlyDisabledIsNotCalled(t *testing.T) {
	provider := &recordingProvider{name: "virustotal"}
	policy := NewTenantPolicy(map[string]bool{"virustotal": false})
	runFanOutForTenant(context.Background(), "1.2.3.4", policy, []fanOutTask{provider.task()})
	if provider.called != 0 {
		t.Errorf("an explicitly disabled provider was called %d time(s)", provider.called)
	}
}

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
