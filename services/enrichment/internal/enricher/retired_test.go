package enricher

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// retiredVendorHosts are API hosts AiSOC once called that can no longer answer.
// Shipping a client against one of these is worse than shipping nothing: the
// provider list, the README and the startup log all advertise a capability
// every request fails to deliver.
//
// api.passivetotal.org — RiskIQ PassiveTotal. RiskIQ was acquired by Microsoft
// and the product folded into Defender Threat Intelligence; the name is now a
// CNAME to www.riskiq.com behind Azure Front Door, which presents a
// *.azureedge.net certificate. Every request dies in the TLS handshake before
// the credentials are sent.
var retiredVendorHosts = []string{
	"api.passivetotal.org",
}

// TestNoRetiredVendorEndpointsRemain walks the shipped Go source of this
// service and fails if any of it still builds a URL against a host that
// cannot answer.
//
// The match is on the scheme separator — "//" immediately before the host —
// so this catches a base URL or an endpoint format string while leaving prose
// free to name the host. internal/config.RetiredProviders has to say which
// host stopped answering for its notice to be worth reading, and that is a
// record of the retirement rather than a call to it. _test.go files are
// skipped so this file may name the hosts it guards.
func TestNoRetiredVendorEndpointsRemain(t *testing.T) {
	serviceRoot, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatalf("resolving service root: %v", err)
	}

	scanned := 0
	walkErr := filepath.Walk(serviceRoot, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		body, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		scanned++
		for _, host := range retiredVendorHosts {
			if strings.Contains(string(body), "//"+host) {
				rel, relErr := filepath.Rel(serviceRoot, path)
				if relErr != nil {
					rel = path
				}
				t.Errorf("%s still builds a URL against the retired host %q; "+
					"retire the provider rather than shipping a client that always fails", rel, host)
			}
		}
		return nil
	})
	if walkErr != nil {
		t.Fatalf("walking %s: %v", serviceRoot, walkErr)
	}
	if scanned == 0 {
		t.Fatal("scanned no Go files — the walk root is wrong and this gate proves nothing")
	}
}
