package ingestauth

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"

	"github.com/beenuar/aisoc/services/ingest/internal/inbox"
	"github.com/google/uuid"
)

// PushTemplateID is the template a token must be minted with before it can
// push to /v1/ingest.
//
// The route is pinned to one template for the same reason /v1/inbox/cef
// and /v1/inbox/hec are: an inbox token is pasted into a third party's
// webhook configuration, so PagerDuty holds one, Cloudflare holds another.
// Without the pin, any of those vendors could replay their own URL's token
// against /v1/ingest and write arbitrary connector events for the tenant.
// Minting a connector-push token is a separate, deliberate act.
//
// Like itsm-inbound, this id has no YAML in the normalizer's template
// directory — it names a credential purpose, not a payload mapping, and
// /v1/ingest normalizes through connectorProfiles rather than a template.
// scripts/check_inbox_templates.py records that exemption in both
// directions so the two sets cannot drift apart unnoticed.
const PushTemplateID = "connector-push"

// DefaultTenantHeaders are the headers a caller may use to name the tenant
// it is writing for. X-Tenant-ID is this service's own spelling and is what
// services/connectors already sends; X-AiSOC-Tenant-ID is the platform
// convention used by the Python services' tenant_scope. Both are only ever
// intersected with the credential's scope, never trusted on their own.
var DefaultTenantHeaders = []string{"X-Tenant-ID", "X-AiSOC-Tenant-ID"}

// TokenResolver is the subset of *inbox.Store this package needs, declared
// as an interface so the tenant-derivation logic can be tested without a
// Postgres pool.
type TokenResolver interface {
	Resolve(ctx context.Context, token string) (*inbox.Token, error)
}

// TenantDirectory answers whether a tenant exists and is active. Used only
// for the service-token path: a minted token's tenant_id carries a foreign
// key to tenants(id), so resolving the token has already proved the tenant
// exists, whereas a service token's asserted tenant is just a string until
// somebody checks.
type TenantDirectory interface {
	IsActive(ctx context.Context, id uuid.UUID) (bool, error)
}

// Error carries the status and the client-facing message for a refused
// request, so the handler does not have to re-derive either.
type Error struct {
	Status int
	Msg    string
}

func (e *Error) Error() string { return e.Msg }

// Identity is the outcome of authenticating one request.
type Identity struct {
	Principal Principal
	// HMACSecret is non-empty when the presented token was minted with a
	// signature secret, in which case the body must carry a matching
	// X-Signature. Empty means the token itself is the only authenticator.
	HMACSecret string
}

// Authenticator resolves a credential into the set of tenants it may write
// for. A nil Authenticator refuses everything, which is the posture we want
// if wiring ever regresses: a missing authenticator must not read as an
// absent requirement.
type Authenticator struct {
	tokens        TokenResolver
	tenants       TenantDirectory
	serviceToken  string
	tenantHeaders []string
}

// New builds an Authenticator.
//
// tokens and tenants may be nil when the service has no database — in that
// case only the service-token path can work, and if serviceToken is empty
// too the authenticator refuses every request with 503. That is deliberate:
// an ingest service that cannot check a credential must stop accepting
// writes, not accept them unchecked.
//
// tenantHeader is the deployment's configured spelling (TENANT_HEADER_KEY).
// It is tried before the defaults so that customising it moves both the
// credential's tenant declaration and the header we intersect against
// together — changing one without the other is how a header ends up
// silently ignored on one of the two paths.
func New(tokens TokenResolver, tenants TenantDirectory, serviceToken, tenantHeader string) *Authenticator {
	headers := make([]string, 0, len(DefaultTenantHeaders)+1)
	if h := strings.TrimSpace(tenantHeader); h != "" {
		headers = append(headers, h)
	}
	for _, h := range DefaultTenantHeaders {
		if !slices.Contains(headers, h) {
			headers = append(headers, h)
		}
	}
	return &Authenticator{
		tokens:        tokens,
		tenants:       tenants,
		serviceToken:  strings.TrimSpace(serviceToken),
		tenantHeaders: headers,
	}
}

// DeclaredTenant returns the tenant the caller named, from whichever
// accepted header carries one. The value is never authoritative on its own
// — Resolve intersects it with the credential's scope.
func (a *Authenticator) DeclaredTenant(r *http.Request) string {
	headers := DefaultTenantHeaders
	if a != nil && len(a.tenantHeaders) > 0 {
		headers = a.tenantHeaders
	}
	for _, h := range headers {
		if v := strings.TrimSpace(r.Header.Get(h)); v != "" {
			return v
		}
	}
	return ""
}

// Configured reports whether any credential shape can be verified at all.
// main uses it to log the refusal loudly at startup rather than leaving an
// operator to discover it as a 503 per request.
func (a *Authenticator) Configured() bool {
	if a == nil {
		return false
	}
	return a.tokens != nil || a.serviceToken != ""
}

// Authenticate resolves the request's credential into an Identity.
//
// Two credential shapes reach this route, mirroring tenant_scope.py:
//
//	tenant push token — a row in tenant_inbox_tokens minted with the
//	    connector-push template. It carries its own tenant_id, which is a
//	    foreign key into tenants(id), so the tenant is proved by the
//	    lookup rather than asserted by the caller.
//	service token — the shared secret for service-to-service pushes
//	    (services/connectors polls on behalf of many tenants). It
//	    identifies a trusted service, not a tenant, so a caller presenting
//	    it must also declare which tenant it is acting for. The
//	    declaration is explicit and required: no tenant header resolves to
//	    an empty scope, and an empty scope refuses rather than widening.
func (a *Authenticator) Authenticate(ctx context.Context, r *http.Request) (Identity, error) {
	if a == nil || !a.Configured() {
		return Identity{}, &Error{
			Status: http.StatusServiceUnavailable,
			Msg: "ingest authentication is not configured on this deployment: set AISOC_SERVICE_TOKEN " +
				"for service-to-service pushes, or DATABASE_DSN so minted push tokens can be resolved",
		}
	}

	credential := CredentialFromRequest(r)
	if credential == "" {
		return Identity{}, &Error{
			Status: http.StatusUnauthorized,
			Msg: "missing ingest credential: send 'Authorization: Bearer <token>' with a token minted by " +
				"POST /api/v1/inbox/tokens using the connector-push template",
		}
	}

	if a.serviceToken != "" && subtle.ConstantTimeCompare([]byte(credential), []byte(a.serviceToken)) == 1 {
		return a.authenticateService(ctx, r)
	}

	if a.tokens == nil {
		return Identity{}, &Error{
			Status: http.StatusServiceUnavailable,
			Msg:    "minted push tokens cannot be resolved on this deployment (no DATABASE_DSN)",
		}
	}

	tok, err := a.tokens.Resolve(ctx, credential)
	if err != nil {
		switch {
		case errors.Is(err, inbox.ErrTokenNotFound):
			return Identity{}, &Error{Status: http.StatusUnauthorized, Msg: "unrecognised ingest credential"}
		case errors.Is(err, inbox.ErrTokenRevoked):
			return Identity{}, &Error{
				Status: http.StatusUnauthorized,
				Msg:    "this ingest token has been revoked; mint a new one",
			}
		default:
			return Identity{}, &Error{Status: http.StatusServiceUnavailable, Msg: "temporary credential lookup failure"}
		}
	}

	if tok.TemplateID != PushTemplateID {
		return Identity{}, &Error{
			Status: http.StatusForbidden,
			Msg: fmt.Sprintf("this token was minted for the %q template; /v1/ingest requires one minted "+
				"with the %q template", tok.TemplateID, PushTemplateID),
		}
	}

	return Identity{
		Principal:  NewPrincipal("token:"+Fingerprint(tok.Token), false, tok.TenantID),
		HMACSecret: tok.HMACSecret,
	}, nil
}

// authenticateService handles the trusted-service shape. The tenant comes
// from the header here — that is the point of a delegated credential — but
// it is checked against the tenants table before it becomes a scope, so a
// service token cannot write into a tenant that does not exist or has been
// deactivated.
func (a *Authenticator) authenticateService(ctx context.Context, r *http.Request) (Identity, error) {
	declared := a.DeclaredTenant(r)
	if declared == "" {
		return Identity{}, &Error{
			Status: http.StatusForbidden,
			Msg: "a service token must declare the tenant it is acting for on the " +
				a.tenantHeaders[0] + " header",
		}
	}
	id, err := uuid.Parse(declared)
	if err != nil {
		return Identity{}, &Error{Status: http.StatusBadRequest, Msg: "declared tenant is not a UUID"}
	}
	if a.tenants == nil {
		return Identity{}, &Error{
			Status: http.StatusServiceUnavailable,
			Msg:    "cannot validate the declared tenant on this deployment (no DATABASE_DSN)",
		}
	}
	active, err := a.tenants.IsActive(ctx, id)
	if err != nil {
		return Identity{}, &Error{Status: http.StatusServiceUnavailable, Msg: "temporary tenant lookup failure"}
	}
	if !active {
		// One message for "no such tenant" and "deactivated": a service
		// token is trusted, but the response should still not be a probe
		// for which tenant UUIDs exist.
		return Identity{}, &Error{Status: http.StatusForbidden, Msg: "declared tenant is unknown or inactive"}
	}
	return Identity{Principal: NewPrincipal("service", true, id)}, nil
}

// VerifySignature enforces the optional HMAC-SHA256 body signature when the
// presented token was minted with a secret. Same headers and same
// constant-time comparison as the inbox routes, so an operator who has
// signed one push path already knows how to sign this one.
func VerifySignature(r *http.Request, id Identity, body []byte) error {
	if id.HMACSecret == "" {
		return nil
	}
	provided := r.Header.Get("X-Signature")
	if provided == "" {
		provided = r.Header.Get("X-Hub-Signature-256")
	}
	if provided == "" {
		return &Error{
			Status: http.StatusUnauthorized,
			Msg:    "this token requires a body signature (set X-Signature: sha256=<hex>)",
		}
	}
	mac := hmac.New(sha256.New, []byte(id.HMACSecret))
	mac.Write(body)
	expected := hex.EncodeToString(mac.Sum(nil))
	if !hmac.Equal([]byte(strings.TrimPrefix(provided, "sha256=")), []byte(expected)) {
		return &Error{Status: http.StatusUnauthorized, Msg: "HMAC signature mismatch"}
	}
	return nil
}

// CredentialFromRequest pulls the presented credential from Authorization
// (Bearer / Splunk / bare) or X-Inbox-Token, matching tokenFromHeaders in
// the inbox package so both push paths accept the same header shapes.
func CredentialFromRequest(r *http.Request) string {
	if v := r.Header.Get("Authorization"); v != "" {
		parts := strings.Fields(v)
		switch len(parts) {
		case 1:
			return parts[0]
		case 2:
			return parts[1]
		}
	}
	return r.Header.Get("X-Inbox-Token")
}

// Fingerprint reduces a credential to something safe to log — the same
// trailing-8 form services/api uses when it records a mint.
func Fingerprint(token string) string {
	if len(token) > 8 {
		return "..." + token[len(token)-8:]
	}
	return "...<short>"
}
