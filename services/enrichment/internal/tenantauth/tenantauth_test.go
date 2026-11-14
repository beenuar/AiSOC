// What the middleware admits, what it refuses, and why (GHSA-qf6m-hgwv-65f9).
//
// The service ran with no authentication and a body-keyed rate limiter, so
// the tests here are organised around the three credential states the Python
// tenant_scope module defines — nothing configured, console session, service
// token — plus the dev bypass's three conditions. Every grant has a partner
// refusal, because an auth layer whose refusals are untested is how /enrich
// shipped open in the first place.
package tenantauth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

const (
	testSecret  = "unit-test-signing-secret-at-least-32-chars"
	testTenant  = "11111111-1111-1111-1111-111111111111"
	otherTenant = "22222222-2222-2222-2222-222222222222"
)

func b64url(b []byte) string {
	return strings.TrimRight(base64.URLEncoding.EncodeToString(b), "=")
}

// mintToken builds an HS256 token the way services/api's create_access_token
// does, with per-test claim overrides.
func mintToken(t *testing.T, secret string, mutate func(map[string]any)) string {
	t.Helper()
	header := map[string]any{"alg": "HS256", "typ": "JWT"}
	claims := map[string]any{
		"sub":       "user-1",
		"tenant_id": testTenant,
		"role":      "soc_analyst",
		"type":      "access",
		"exp":       time.Now().Add(10 * time.Minute).Unix(),
	}
	if mutate != nil {
		mutate(claims)
	}
	hj, _ := json.Marshal(header)
	cj, _ := json.Marshal(claims)
	signingInput := b64url(hj) + "." + b64url(cj)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(signingInput))
	return signingInput + "." + b64url(mac.Sum(nil))
}

// call runs one request through the middleware and reports the status plus
// the principal the inner handler saw (nil when it never ran).
func call(t *testing.T, mutate func(*http.Request)) (int, *Principal) {
	t.Helper()
	var seen *Principal
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if p, ok := FromContext(r.Context()); ok {
			seen = &p
		}
		w.WriteHeader(http.StatusOK)
	})
	req := httptest.NewRequest(http.MethodPost, "/enrich", strings.NewReader("{}"))
	if mutate != nil {
		mutate(req)
	}
	rec := httptest.NewRecorder()
	Middleware(inner).ServeHTTP(rec, req)
	return rec.Code, seen
}

func clearEnv(t *testing.T) {
	t.Helper()
	for _, k := range []string{
		"SECRET_KEY", "AISOC_SERVICE_TOKEN", "AISOC_ENRICHMENT_SERVICE_TOKEN",
		"AISOC_DEV_MODE", "AISOC_DEV_AUTH_BYPASS", "AISOC_PUBLISHED_BIND_ADDRS",
	} {
		t.Setenv(k, "")
	}
}

// ─── nothing configured ─────────────────────────────────────────────────────

func TestNoCredentialMaterialFailsClosed(t *testing.T) {
	clearEnv(t)
	code, seen := call(t, nil)
	if code != http.StatusServiceUnavailable {
		t.Fatalf("no secret, no token, no bypass answered %d, want 503", code)
	}
	if seen != nil {
		t.Fatal("the inner handler ran for an unconfigured deployment")
	}
}

func TestDevBypassNeedsAllThreeConditions(t *testing.T) {
	cases := []struct {
		name string
		env  map[string]string
		want int
	}{
		{"dev mode alone is not enough", map[string]string{"AISOC_DEV_MODE": "1"}, http.StatusServiceUnavailable},
		{"bypass flag alone is not enough", map[string]string{"AISOC_DEV_AUTH_BYPASS": "1"}, http.StatusServiceUnavailable},
		{
			"published non-loopback bind refuses the bypass",
			map[string]string{"AISOC_DEV_MODE": "1", "AISOC_DEV_AUTH_BYPASS": "1", "AISOC_PUBLISHED_BIND_ADDRS": "0.0.0.0:8082"},
			http.StatusServiceUnavailable,
		},
		{
			"loopback-only deployment with both flags is admitted",
			map[string]string{"AISOC_DEV_MODE": "1", "AISOC_DEV_AUTH_BYPASS": "1", "AISOC_PUBLISHED_BIND_ADDRS": "127.0.0.1:8082"},
			http.StatusOK,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			clearEnv(t)
			for k, v := range tc.env {
				t.Setenv(k, v)
			}
			code, seen := call(t, nil)
			if code != tc.want {
				t.Fatalf("answered %d, want %d", code, tc.want)
			}
			if tc.want == http.StatusOK {
				if seen == nil || seen.TenantID != DevTenantID || seen.Subject != "dev" {
					t.Fatalf("dev bypass resolved %+v, want the demo tenant", seen)
				}
			}
		})
	}
}

// ─── console sessions ───────────────────────────────────────────────────────

func TestConsoleTokenResolvesItsOwnTenant(t *testing.T) {
	clearEnv(t)
	t.Setenv("SECRET_KEY", testSecret)
	code, seen := call(t, func(r *http.Request) {
		r.Header.Set("Authorization", "Bearer "+mintToken(t, testSecret, nil))
	})
	if code != http.StatusOK {
		t.Fatalf("a valid console token answered %d, want 200", code)
	}
	if seen == nil || seen.TenantID != testTenant || seen.Delegated || seen.Role != "soc_analyst" {
		t.Fatalf("resolved %+v, want the token's tenant and role, not delegated", seen)
	}
}

func TestConsoleTokenRefusals(t *testing.T) {
	cases := []struct {
		name  string
		token func(t *testing.T) string
	}{
		{"expired", func(t *testing.T) string {
			return mintToken(t, testSecret, func(c map[string]any) { c["exp"] = time.Now().Add(-time.Hour).Unix() })
		}},
		{"refresh token must not buy access", func(t *testing.T) string {
			return mintToken(t, testSecret, func(c map[string]any) { c["type"] = "refresh" })
		}},
		{"no tenant claim", func(t *testing.T) string {
			return mintToken(t, testSecret, func(c map[string]any) { c["tenant_id"] = "" })
		}},
		{"wrong signature", func(t *testing.T) string {
			return mintToken(t, "some-other-secret-entirely-32-chars!!", nil)
		}},
		{"alg none downgrade", func(t *testing.T) string {
			hj, _ := json.Marshal(map[string]any{"alg": "none"})
			cj, _ := json.Marshal(map[string]any{"tenant_id": testTenant, "type": "access", "exp": time.Now().Add(time.Hour).Unix()})
			return b64url(hj) + "." + b64url(cj) + "."
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			clearEnv(t)
			t.Setenv("SECRET_KEY", testSecret)
			code, seen := call(t, func(r *http.Request) {
				r.Header.Set("Authorization", "Bearer "+tc.token(t))
			})
			if code != http.StatusUnauthorized {
				t.Fatalf("answered %d, want 401", code)
			}
			if seen != nil {
				t.Fatal("the inner handler ran on a refused token")
			}
		})
	}
}

func TestPlaceholderSecretCountsAsUnset(t *testing.T) {
	clearEnv(t)
	t.Setenv("SECRET_KEY", "changeme")
	code, _ := call(t, func(r *http.Request) {
		r.Header.Set("Authorization", "Bearer "+mintToken(t, "changeme", nil))
	})
	if code != http.StatusServiceUnavailable {
		t.Fatalf("a placeholder secret answered %d, want 503: verifying against a published literal authenticates anyone who read the repository", code)
	}
}

// ─── service tokens ─────────────────────────────────────────────────────────

func TestServiceTokenMustDeclareItsTenant(t *testing.T) {
	clearEnv(t)
	t.Setenv("AISOC_SERVICE_TOKEN", "svc-token-1")

	code, _ := call(t, func(r *http.Request) {
		r.Header.Set("Authorization", "Bearer svc-token-1")
	})
	if code != http.StatusForbidden {
		t.Fatalf("a service token with no %s answered %d, want 403: an absent tenant is an empty scope, never every scope", TenantHeader, code)
	}

	code, _ = call(t, func(r *http.Request) {
		r.Header.Set("Authorization", "Bearer svc-token-1")
		r.Header.Set(TenantHeader, "not-a-uuid")
	})
	if code != http.StatusBadRequest {
		t.Fatalf("a non-UUID tenant header answered %d, want 400", code)
	}

	code, seen := call(t, func(r *http.Request) {
		r.Header.Set("Authorization", "Bearer svc-token-1")
		r.Header.Set(TenantHeader, strings.ToUpper(testTenant))
	})
	if code != http.StatusOK {
		t.Fatalf("a declared tenant answered %d, want 200", code)
	}
	if seen == nil || !seen.Delegated || seen.TenantID != testTenant {
		t.Fatalf("resolved %+v, want a delegated principal on the declared tenant (case-normalised)", seen)
	}
}

func TestWrongBearerIsRefused(t *testing.T) {
	clearEnv(t)
	t.Setenv("AISOC_SERVICE_TOKEN", "svc-token-1")
	code, _ := call(t, func(r *http.Request) {
		r.Header.Set("Authorization", "Bearer svc-token-2")
		r.Header.Set(TenantHeader, testTenant)
	})
	if code != http.StatusUnauthorized {
		t.Fatalf("a wrong token answered %d, want 401", code)
	}
}

func TestPerServiceOverrideWins(t *testing.T) {
	clearEnv(t)
	t.Setenv("AISOC_SERVICE_TOKEN", "platform-token")
	t.Setenv("AISOC_ENRICHMENT_SERVICE_TOKEN", "enrichment-token")
	code, _ := call(t, func(r *http.Request) {
		r.Header.Set("Authorization", "Bearer platform-token")
		r.Header.Set(TenantHeader, testTenant)
	})
	if code != http.StatusUnauthorized {
		t.Fatalf("the platform token was accepted while a per-service override is set; answered %d, want 401", code)
	}
}

// ─── principal coverage ─────────────────────────────────────────────────────

func TestCoversIsIntersectionOnly(t *testing.T) {
	p := Principal{TenantID: testTenant}
	if !p.Covers(testTenant) {
		t.Fatal("a principal does not cover its own tenant")
	}
	if !p.Covers(strings.ToUpper(testTenant)) {
		t.Fatal("coverage must be case-insensitive; UUIDs compare canonically")
	}
	for _, raw := range []string{otherTenant, "probe-a", "", "default", fmt.Sprintf(" %s ", otherTenant)} {
		if p.Covers(raw) {
			t.Fatalf("principal covers %q, which it must not", raw)
		}
	}
}
