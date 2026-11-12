// Package tenantauth resolves which tenant a request acts for, from the
// caller's credential (GHSA-qf6m-hgwv-65f9).
//
// /enrich and /enrich/bulk ran behind no authentication at all: the console
// forwarded two same-origin paths straight here through Next rewrites, so an
// unauthenticated client that could reach the console could spend the
// deployment's threat-intel provider quota — and because the rate limiter was
// keyed on a *body* field, every previously unseen `tenant_id` string minted a
// fresh bucket, so the limiter could not even slow it down.
//
// This is the Go port of the contract the Python services vendor in
// app/security/tenant_scope.py (fusion, agents, …), kept deliberately
// behaviour-identical so one description covers both sides:
//
//   - console — the browser's first-party access token, HS256-signed by
//     services/api with a verified `tenant_id` claim. That claim is
//     authoritative; nothing in the request body can widen it.
//   - service — the shared service bearer token (per-service override
//     AISOC_ENRICHMENT_SERVICE_TOKEN, then AISOC_SERVICE_TOKEN). It
//     identifies a trusted service, not a tenant, so the caller must declare
//     the tenant it acts for on X-AiSOC-Tenant-ID. No header, no scope — and
//     an empty scope refuses rather than widening.
//
// With neither a console secret nor a service token configured the
// middleware fails closed (503), unless the explicit dev bypass permits an
// anonymous caller: AISOC_DEV_MODE set, AISOC_DEV_AUTH_BYPASS set, and every
// address in AISOC_PUBLISHED_BIND_ADDRS loopback — the same three conditions,
// in the same order, as the Python module.
package tenantauth

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
)

// TenantHeader is the header a trusted service uses to declare which tenant
// it is acting for — the platform convention shared with the Python side.
const TenantHeader = "X-AiSOC-Tenant-ID"

// DevTenantID matches DEV_TENANT_ID in the Python tenant_scope module: the
// deterministic demo tenant an uncredentialed dev-mode caller resolves to.
const DevTenantID = "00000000-0000-0000-0000-0000000000de"

// clockSkew matches the Python module and the Node verifier.
const clockSkew = 30 * time.Second

// insecureSecretDefaults mirrors INSECURE_SECRET_KEY_DEFAULTS in
// services/api/app/core/config.py: a placeholder secret is treated as unset,
// because verifying tokens against a well-known literal authenticates anyone
// who has read the repository.
var insecureSecretDefaults = map[string]struct{}{
	"change-me-in-production-at-least-32-chars": {},
	"dev_secret_key_change_in_production":       {},
	"changeme":                                  {},
	"secret":                                    {},
}

var truthy = map[string]struct{}{"1": {}, "true": {}, "yes": {}, "on": {}}

// Principal is the outcome of authenticating one request: the single tenant
// it may act for, and what kind of credential proved it.
type Principal struct {
	// TenantID is the canonical lowercase UUID string of the tenant this
	// request acts for. Never empty on a resolved principal.
	TenantID string
	// Subject identifies the caller for logs: "console:<sub>", "service",
	// or "dev".
	Subject string
	// Delegated is true when a service token asserted the tenant rather
	// than a verified console claim carrying it. A delegated caller is a
	// trusted platform service, so its per-item tenant assertions in bulk
	// requests are honoured; a console caller's are overridden.
	Delegated bool
	// Role is the `role` claim from a verified console token, or "".
	Role string
}

// Covers reports whether a request-supplied tenant value names this
// principal's tenant. Intersection only, like the Python module's
// resolve_scoped_tenant: a value that is not a UUID, or is a different
// tenant's UUID, is never covered.
func (p Principal) Covers(raw string) bool {
	n := normalizeUUID(raw)
	return n != "" && n == p.TenantID
}

type ctxKey struct{}

// FromContext returns the principal the middleware resolved for this request.
func FromContext(ctx context.Context) (Principal, bool) {
	p, ok := ctx.Value(ctxKey{}).(Principal)
	return p, ok
}

// WithPrincipal returns a context carrying the given principal. The
// middleware is the only production writer; this exists so handler tests can
// exercise the authenticated paths without re-implementing token minting.
func WithPrincipal(ctx context.Context, p Principal) context.Context {
	return context.WithValue(ctx, ctxKey{}, p)
}

// ResolveConsoleSecret returns the HS256 secret console tokens are signed
// with, or "" when unset or set to a published placeholder.
func ResolveConsoleSecret() string {
	secret := strings.TrimSpace(os.Getenv("SECRET_KEY"))
	if secret == "" {
		return ""
	}
	if _, insecure := insecureSecretDefaults[secret]; insecure {
		return ""
	}
	return secret
}

// ResolveServiceToken returns the shared service token: the per-service
// override first, then the platform-wide one.
func ResolveServiceToken() string {
	if specific := strings.TrimSpace(os.Getenv("AISOC_ENRICHMENT_SERVICE_TOKEN")); specific != "" {
		return specific
	}
	return strings.TrimSpace(os.Getenv("AISOC_SERVICE_TOKEN"))
}

func isTruthy(env string) bool {
	_, ok := truthy[strings.ToLower(strings.TrimSpace(os.Getenv(env)))]
	return ok
}

// isLoopback mirrors _is_loopback in the Python module: a hostname that is
// not obviously loopback refuses the bypass, because when the question
// cannot be decided the safe answer is the one that refuses.
func isLoopback(address string) bool {
	host := strings.ToLower(strings.TrimSpace(address))
	if host == "" {
		return true
	}
	if strings.HasPrefix(host, "[") {
		host = strings.TrimPrefix(strings.SplitN(host, "]", 2)[0], "[")
	} else if strings.Count(host, ":") == 1 {
		host = strings.SplitN(host, ":", 2)[0]
	}
	switch host {
	case "localhost", "::1", "ip6-localhost":
		return true
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	return ip.IsLoopback()
}

// bypassRefusal returns why an uncredentialed caller must not be admitted,
// or "" when the dev bypass genuinely applies. Same three conditions, same
// order, as auth_bypass_refusal in the Python module.
func bypassRefusal() string {
	if !isTruthy("AISOC_DEV_MODE") {
		return "AISOC_DEV_MODE is not set"
	}
	if !isTruthy("AISOC_DEV_AUTH_BYPASS") {
		return "AISOC_DEV_AUTH_BYPASS is not set; set it deliberately, or use infra/compose/docker-compose.dev.yml, which sets it"
	}
	var reachable []string
	for _, addr := range strings.Split(os.Getenv("AISOC_PUBLISHED_BIND_ADDRS"), ",") {
		if a := strings.TrimSpace(addr); a != "" && !isLoopback(a) {
			reachable = append(reachable, a)
		}
	}
	if len(reachable) > 0 {
		return fmt.Sprintf(
			"AISOC_DEV_AUTH_BYPASS is set, but this deployment publishes %s, which is not loopback; bind to 127.0.0.1, or configure SECRET_KEY and a service token",
			strings.Join(reachable, ", "),
		)
	}
	return ""
}

// bypassLogged dedups the once-per-reason bypass logging, as the Python
// module's _BYPASS_LOGGED set does.
var (
	bypassMu     sync.Mutex
	bypassLogged = map[string]struct{}{}
)

func logBypassOnce(reason string) {
	bypassMu.Lock()
	defer bypassMu.Unlock()
	if _, seen := bypassLogged[reason]; seen {
		return
	}
	bypassLogged[reason] = struct{}{}
	if reason == "__active__" {
		log.Warn().Msgf(
			"ANONYMOUS ACCESS IS ENABLED on ENRICHMENT. Requests with no credential resolve to the demo tenant %s. This is a development convenience and must not be used where anyone else can reach this host.",
			DevTenantID,
		)
		return
	}
	log.Info().Str("reason", reason).Msg("anonymous access refused on ENRICHMENT")
}

func b64urlDecode(segment string) ([]byte, error) {
	if pad := len(segment) % 4; pad != 0 {
		segment += strings.Repeat("=", 4-pad)
	}
	return base64.URLEncoding.DecodeString(segment)
}

// consoleClaims is the subset of the access token this service reads.
type consoleClaims struct {
	Sub      string  `json:"sub"`
	TenantID string  `json:"tenant_id"`
	Role     string  `json:"role"`
	Type     string  `json:"type"`
	Exp      float64 `json:"exp"`
}

// verifyConsoleToken verifies a first-party HS256 access token and returns
// its claims, or nil. Mirrors verify_console_token in the Python module and
// verifyRealtimeTicket in services/realtime/src/auth.ts: pin HS256 (so
// "alg: none" and asymmetric algorithms cannot downgrade the check), require
// type == "access" (a refresh token must not buy access), check expiry with
// 30s skew, and require a tenant_id claim.
func verifyConsoleToken(token, secret string) *consoleClaims {
	if token == "" || secret == "" {
		return nil
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil
	}
	headerRaw, err := b64urlDecode(parts[0])
	if err != nil {
		return nil
	}
	var header struct {
		Alg string `json:"alg"`
	}
	if err := json.Unmarshal(headerRaw, &header); err != nil || header.Alg != "HS256" {
		return nil
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(parts[0] + "." + parts[1]))
	provided, err := b64urlDecode(parts[2])
	if err != nil || !hmac.Equal(mac.Sum(nil), provided) {
		return nil
	}
	payloadRaw, err := b64urlDecode(parts[1])
	if err != nil {
		return nil
	}
	var claims consoleClaims
	if err := json.Unmarshal(payloadRaw, &claims); err != nil {
		return nil
	}
	if claims.Type != "access" {
		return nil
	}
	if claims.Exp == 0 || time.Unix(int64(claims.Exp), 0).Add(clockSkew).Before(time.Now()) {
		return nil
	}
	if normalizeUUID(claims.TenantID) == "" {
		return nil
	}
	return &claims
}

// normalizeUUID returns the canonical lowercase form of a UUID string, or ""
// when the value is not a UUID. Stdlib-only on purpose: this module must not
// grow dependencies for one format check.
func normalizeUUID(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	if len(s) != 36 {
		return ""
	}
	for i, c := range s {
		switch i {
		case 8, 13, 18, 23:
			if c != '-' {
				return ""
			}
		default:
			if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
				return ""
			}
		}
	}
	return s
}

type errorResponse struct {
	Error string `json:"error"`
	Code  int    `json:"code"`
}

func refuse(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	if status == http.StatusUnauthorized {
		w.Header().Set("WWW-Authenticate", "Bearer")
	}
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(errorResponse{Error: msg, Code: status})
}

// Middleware authenticates every request and injects the resolved Principal
// into the context. Handlers behind it may assume FromContext succeeds.
func Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		consoleSecret := ResolveConsoleSecret()
		serviceToken := ResolveServiceToken()

		if consoleSecret == "" && serviceToken == "" {
			if reason := bypassRefusal(); reason == "" {
				logBypassOnce("__active__")
				ctx := context.WithValue(r.Context(), ctxKey{}, Principal{
					TenantID: DevTenantID,
					Subject:  "dev",
				})
				next.ServeHTTP(w, r.WithContext(ctx))
				return
			} else {
				logBypassOnce(reason)
			}
			// No credential material configured at all: refuse to serve
			// rather than serve openly — same fail-closed posture as the
			// Python services.
			refuse(w, http.StatusServiceUnavailable,
				"tenant-scoped auth is not configured; set SECRET_KEY and/or AISOC_SERVICE_TOKEN (or AISOC_ENRICHMENT_SERVICE_TOKEN) before exposing this service")
			return
		}

		auth := r.Header.Get("Authorization")
		if !strings.HasPrefix(auth, "Bearer ") {
			refuse(w, http.StatusUnauthorized, "missing bearer credential")
			return
		}
		token := strings.TrimSpace(strings.TrimPrefix(auth, "Bearer "))

		// --- console session ---
		if consoleSecret != "" {
			if claims := verifyConsoleToken(token, consoleSecret); claims != nil {
				ctx := context.WithValue(r.Context(), ctxKey{}, Principal{
					TenantID: normalizeUUID(claims.TenantID),
					Subject:  "console:" + claims.Sub,
					Role:     strings.TrimSpace(claims.Role),
				})
				next.ServeHTTP(w, r.WithContext(ctx))
				return
			}
		}

		// --- trusted service acting for a declared tenant ---
		if serviceToken != "" && subtle.ConstantTimeCompare([]byte(token), []byte(serviceToken)) == 1 {
			declared := strings.TrimSpace(r.Header.Get(TenantHeader))
			if declared == "" {
				// An absent tenant is an empty scope, never every scope.
				log.Warn().Str("header", TenantHeader).Msg("tenant_scope.service_token_without_tenant service=ENRICHMENT")
				refuse(w, http.StatusForbidden,
					fmt.Sprintf("service token must declare the tenant it acts for on %s", TenantHeader))
				return
			}
			tenant := normalizeUUID(declared)
			if tenant == "" {
				refuse(w, http.StatusBadRequest, fmt.Sprintf("%s must be a UUID", TenantHeader))
				return
			}
			ctx := context.WithValue(r.Context(), ctxKey{}, Principal{
				TenantID:  tenant,
				Subject:   "service",
				Delegated: true,
			})
			next.ServeHTTP(w, r.WithContext(ctx))
			return
		}

		refuse(w, http.StatusUnauthorized, "invalid or missing credential")
	})
}
