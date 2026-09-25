// ingest_auth_test.go — the credential check on POST /v1/ingest[/batch].
//
// These tests exist because the endpoint used to have no authentication at
// all: it read a tenant out of a caller-supplied X-Tenant-ID header and
// wrote events for whatever that header said. The load-bearing property is
// therefore not "an authenticated caller can push" but "a credential for
// one tenant cannot write into another", so that is what most of this file
// asserts, driven through the real handler rather than against the
// resolver in isolation.
//
// Every cross-tenant case here first proves the target tenant genuinely
// exists and is genuinely writable by its own credential. Without that,
// a refusal is indistinguishable from the tenant simply not being there,
// and the test would keep passing if the check were deleted and replaced
// by an unrelated 404.
package handler

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/beenuar/aisoc/services/ingest/internal/config"
	"github.com/beenuar/aisoc/services/ingest/internal/inbox"
	"github.com/beenuar/aisoc/services/ingest/internal/ingestauth"
	"github.com/beenuar/aisoc/services/ingest/internal/normalizer"
	"github.com/google/uuid"
)

// ── two tenants, seeded ────────────────────────────────────────────────
//
// "Acme" is the caller. "Umbra" is the outsider — the tenant Acme must not
// be able to reach. Both are real rows as far as the fakes are concerned:
// both resolve, both are active, and the tests below prove Umbra is
// writable by its own token before asserting that Acme cannot write to it.

var (
	acmeTenant  = uuid.MustParse("11111111-1111-4111-8111-111111111111")
	umbraTenant = uuid.MustParse("22222222-2222-4222-8222-222222222222")
	ghostTenant = uuid.MustParse("33333333-3333-4333-8333-333333333333") // never seeded

	acmeToken  = "aitnb_acme_push_token_aaaaaaaaaaaa"
	umbraToken = "aitnb_umbra_push_token_bbbbbbbbbbb"
)

const testServiceToken = "svc-token-for-trusted-internal-callers"

// fakeTokens is an in-memory stand-in for inbox.Store.
type fakeTokens struct {
	rows map[string]*inbox.Token
}

func (f *fakeTokens) Resolve(_ context.Context, token string) (*inbox.Token, error) {
	row, ok := f.rows[token]
	if !ok {
		return nil, inbox.ErrTokenNotFound
	}
	if row.Label == "revoked" {
		return nil, inbox.ErrTokenRevoked
	}
	return row, nil
}

// fakeTenants stands in for the tenants table. Only the service-token path
// consults it; a minted token's tenant is proved by the token row's own
// foreign key.
type fakeTenants struct{ active map[uuid.UUID]bool }

func (f *fakeTenants) IsActive(_ context.Context, id uuid.UUID) (bool, error) {
	return f.active[id], nil
}

// capturingPublisher records the tenant of every event that reaches Kafka,
// which is the only evidence that matters here: a refusal that still
// published would be worse than no refusal, because it would look fixed.
type capturingPublisher struct {
	mu        sync.Mutex
	published []*normalizer.NormalizedEvent
}

func (p *capturingPublisher) PublishBatch(_ context.Context, events []*normalizer.NormalizedEvent) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.published = append(p.published, events...)
	return nil
}

func (p *capturingPublisher) Ready(context.Context) error { return nil }

// tenantsWritten returns how many events landed for one tenant.
func (p *capturingPublisher) tenantsWritten(tenant uuid.UUID) int {
	p.mu.Lock()
	defer p.mu.Unlock()
	n := 0
	for _, e := range p.published {
		if e.TenantID == tenant.String() {
			n++
		}
	}
	return n
}

// testConfig is the minimum an ingest handler needs to normalize and
// publish. NormalizerMode is lenient so a plain vendor event maps without
// a per-vendor profile, which keeps these tests about the credential.
func testConfig() *config.Config {
	return &config.Config{
		TenantHeaderKey:    "X-Tenant-ID",
		NormalizerMode:     "lenient",
		MaxBatchSize:       500,
		IngestMaxBodyBytes: 1 << 20,
	}
}

func newAuthHandler(t *testing.T, serviceToken string) (*Handler, *capturingPublisher) {
	t.Helper()
	tokens := &fakeTokens{rows: map[string]*inbox.Token{
		acmeToken: {
			Token: acmeToken, TenantID: acmeTenant, TemplateID: ingestauth.PushTemplateID,
		},
		umbraToken: {
			Token: umbraToken, TenantID: umbraTenant, TemplateID: ingestauth.PushTemplateID,
		},
		"aitnb_revoked_cccccccccccccccccccc": {
			Token: "aitnb_revoked_cccccccccccccccccccc", TenantID: acmeTenant,
			TemplateID: ingestauth.PushTemplateID, Label: "revoked",
		},
		"aitnb_pagerduty_webhook_dddddddddd": {
			Token: "aitnb_pagerduty_webhook_dddddddddd", TenantID: acmeTenant,
			TemplateID: "pagerduty",
		},
		"aitnb_acme_signed_eeeeeeeeeeeeeeee": {
			Token: "aitnb_acme_signed_eeeeeeeeeeeeeeee", TenantID: acmeTenant,
			TemplateID: ingestauth.PushTemplateID, HMACSecret: "shared-signing-secret",
		},
	}}
	tenants := &fakeTenants{active: map[uuid.UUID]bool{
		acmeTenant:  true,
		umbraTenant: true,
	}}

	cfg := testConfig()
	norm, err := normalizer.New(cfg)
	if err != nil {
		t.Fatalf("normalizer: %v", err)
	}
	pub := &capturingPublisher{}
	h := New(norm, pub, cfg)
	h.SetAuthenticator(ingestauth.New(tokens, tenants, serviceToken, cfg.TenantHeaderKey))
	return h, pub
}

// push builds and runs one ingest request. credential goes on
// Authorization; declaredTenant, when non-empty, goes on X-Tenant-ID.
func push(t *testing.T, h *Handler, credential, declaredTenant string, opts ...func(*http.Request)) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(map[string]any{
		"connector_id":   "edr-1",
		"connector_type": "crowdstrike",
		"source_format":  "json",
		"events": []map[string]any{{
			"severity": "high",
			"title":    "Encoded PowerShell from Office",
			"host":     "WIN-FIN-01",
		}},
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/v1/ingest/batch", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if credential != "" {
		req.Header.Set("Authorization", "Bearer "+credential)
	}
	if declaredTenant != "" {
		req.Header.Set("X-Tenant-ID", declaredTenant)
	}
	for _, opt := range opts {
		opt(req)
	}
	rec := httptest.NewRecorder()
	h.IngestEvents(rec, req)
	return rec
}

// ── the vulnerability, stated as a test ────────────────────────────────

func TestIngest_OneTenantsTokenCannotWriteIntoAnother(t *testing.T) {
	h, pub := newAuthHandler(t, "")

	// Vacuity guard, part one: Umbra is a real, active tenant whose own
	// token writes successfully. If this ever stops being true, the
	// refusal below stops proving anything.
	if rec := push(t, h, umbraToken, umbraTenant.String()); rec.Code != http.StatusOK {
		t.Fatalf("precondition: Umbra's own token must be able to write; got %d %s", rec.Code, rec.Body)
	}
	if got := pub.tenantsWritten(umbraTenant); got != 1 {
		t.Fatalf("precondition: expected 1 event for Umbra, got %d", got)
	}

	// Vacuity guard, part two: Acme's token is genuinely working — so a
	// refusal below is about the tenant it named, not about the token.
	if rec := push(t, h, acmeToken, acmeTenant.String()); rec.Code != http.StatusOK {
		t.Fatalf("precondition: Acme's own token must be able to write; got %d %s", rec.Code, rec.Body)
	}

	before := pub.tenantsWritten(umbraTenant)

	// The attack: a valid credential for Acme, naming Umbra's tenant.
	// This is exactly what an unauthenticated caller used to be able to
	// do with nothing but a UUID.
	rec := push(t, h, acmeToken, umbraTenant.String())
	if rec.Code != http.StatusForbidden {
		t.Fatalf("Acme's token naming Umbra must be refused with 403; got %d %s", rec.Code, rec.Body)
	}
	if after := pub.tenantsWritten(umbraTenant); after != before {
		t.Fatalf("a refused cross-tenant push still published %d event(s) into Umbra", after-before)
	}
	// And it must not have been silently redirected into Acme either:
	// narrowing to nothing means refusing, not falling back to the
	// credential's own tenant.
	if got := pub.tenantsWritten(acmeTenant); got != 1 {
		t.Fatalf("refused push should not publish anywhere; Acme has %d events, expected the 1 from the precondition", got)
	}
}

func TestIngest_ServiceTokenCannotReachAnUnseededTenant(t *testing.T) {
	h, pub := newAuthHandler(t, testServiceToken)

	// The delegated path works for a tenant that exists...
	if rec := push(t, h, testServiceToken, umbraTenant.String()); rec.Code != http.StatusOK {
		t.Fatalf("precondition: the service token must write for a real tenant; got %d %s", rec.Code, rec.Body)
	}
	if got := pub.tenantsWritten(umbraTenant); got != 1 {
		t.Fatalf("precondition: expected 1 event for Umbra, got %d", got)
	}

	// ...and refuses one that does not, rather than creating data under
	// a tenant id nobody owns.
	rec := push(t, h, testServiceToken, ghostTenant.String())
	if rec.Code != http.StatusForbidden {
		t.Fatalf("service token naming an unseeded tenant must be refused; got %d %s", rec.Code, rec.Body)
	}
	if got := pub.tenantsWritten(ghostTenant); got != 0 {
		t.Fatalf("published %d event(s) for a tenant that does not exist", got)
	}
}

func TestIngest_ServiceTokenMustDeclareTheTenantItActsFor(t *testing.T) {
	h, pub := newAuthHandler(t, testServiceToken)

	rec := push(t, h, testServiceToken, "")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("a service token with no declared tenant must refuse, not widen; got %d %s", rec.Code, rec.Body)
	}
	if n := len(pub.published); n != 0 {
		t.Fatalf("an undeclared service push published %d event(s)", n)
	}
}

// A placeholder is not a tenant. The string "default" is the slug migration
// 001 seeds and the demo seed renames, so it identifies nothing — it must
// be read as "the caller did not name one" and resolve to the credential's
// own tenant, not treated as a tenant called "default".
func TestIngest_PlaceholderTenantRefResolvesToTheCredentialsOwnTenant(t *testing.T) {
	h, pub := newAuthHandler(t, "")

	for _, placeholder := range []string{"", "default", "none", "null"} {
		rec := push(t, h, acmeToken, placeholder)
		if rec.Code != http.StatusOK {
			t.Fatalf("placeholder %q should resolve to Acme, got %d %s", placeholder, rec.Code, rec.Body)
		}
	}
	if got := pub.tenantsWritten(acmeTenant); got != 4 {
		t.Fatalf("expected 4 events for Acme, got %d", got)
	}
}

// ── the unauthenticated hole itself ────────────────────────────────────

func TestIngest_RefusesWithNoCredential(t *testing.T) {
	h, pub := newAuthHandler(t, testServiceToken)

	// This is the exact request shape that used to succeed: a tenant UUID
	// in a header, nothing else.
	rec := push(t, h, "", umbraTenant.String())
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("an unauthenticated push must be 401; got %d %s", rec.Code, rec.Body)
	}
	if got := pub.tenantsWritten(umbraTenant); got != 0 {
		t.Fatalf("an unauthenticated push published %d event(s)", got)
	}
}

func TestIngest_RefusesWhenNoCredentialSourceIsConfigured(t *testing.T) {
	// No token store and no service token: the service cannot verify
	// anything, so it must refuse rather than accept unchecked. A
	// deployment that loses its database must not fail open.
	cfg := testConfig()
	norm, err := normalizer.New(cfg)
	if err != nil {
		t.Fatalf("normalizer: %v", err)
	}
	pub := &capturingPublisher{}
	h := New(norm, pub, cfg)
	h.SetAuthenticator(ingestauth.New(nil, nil, "", cfg.TenantHeaderKey))

	rec := push(t, h, acmeToken, acmeTenant.String())
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("unconfigured auth must refuse with 503; got %d %s", rec.Code, rec.Body)
	}
	if n := len(pub.published); n != 0 {
		t.Fatalf("unconfigured auth published %d event(s)", n)
	}
}

// A nil authenticator is a wiring regression, not a feature flag. It must
// refuse rather than read as "authentication not required here".
func TestIngest_NilAuthenticatorFailsClosed(t *testing.T) {
	cfg := testConfig()
	norm, err := normalizer.New(cfg)
	if err != nil {
		t.Fatalf("normalizer: %v", err)
	}
	pub := &capturingPublisher{}
	h := New(norm, pub, cfg)

	rec := push(t, h, acmeToken, acmeTenant.String())
	if rec.Code < 400 {
		t.Fatalf("a handler with no authenticator must refuse; got %d %s", rec.Code, rec.Body)
	}
	if n := len(pub.published); n != 0 {
		t.Fatalf("a handler with no authenticator published %d event(s)", n)
	}
}

// ── credential hygiene ─────────────────────────────────────────────────

func TestIngest_RevokedTokenIsRefused(t *testing.T) {
	h, pub := newAuthHandler(t, "")
	rec := push(t, h, "aitnb_revoked_cccccccccccccccccccc", acmeTenant.String())
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("a revoked token must be refused; got %d %s", rec.Code, rec.Body)
	}
	if n := len(pub.published); n != 0 {
		t.Fatalf("a revoked token published %d event(s)", n)
	}
}

// A token pasted into a vendor's webhook configuration is held by that
// vendor. It must not double as a general connector-push credential for
// the whole tenant, which is why the route is pinned to one template the
// same way /v1/inbox/cef and /v1/inbox/hec are.
func TestIngest_TokenMintedForAnotherTemplateIsRefused(t *testing.T) {
	h, pub := newAuthHandler(t, "")
	rec := push(t, h, "aitnb_pagerduty_webhook_dddddddddd", acmeTenant.String())
	if rec.Code != http.StatusForbidden {
		t.Fatalf("a pagerduty inbox token must not push to /v1/ingest; got %d %s", rec.Code, rec.Body)
	}
	if n := len(pub.published); n != 0 {
		t.Fatalf("a wrong-template token published %d event(s)", n)
	}
}

func TestIngest_SignedTokenRequiresAMatchingSignature(t *testing.T) {
	h, pub := newAuthHandler(t, "")
	const signed = "aitnb_acme_signed_eeeeeeeeeeeeeeee"

	if rec := push(t, h, signed, acmeTenant.String()); rec.Code != http.StatusUnauthorized {
		t.Fatalf("a token minted with an HMAC secret must require a signature; got %d %s", rec.Code, rec.Body)
	}

	wrong := func(r *http.Request) { r.Header.Set("X-Signature", "sha256=deadbeef") }
	if rec := push(t, h, signed, acmeTenant.String(), wrong); rec.Code != http.StatusUnauthorized {
		t.Fatalf("a bad signature must be refused; got %d %s", rec.Code, rec.Body)
	}
	if n := len(pub.published); n != 0 {
		t.Fatalf("unsigned/badly-signed pushes published %d event(s)", n)
	}

	// The happy path has to work, or the check above proves only that the
	// route is broken.
	sign := func(r *http.Request) {
		body := readAll(t, r)
		mac := hmac.New(sha256.New, []byte("shared-signing-secret"))
		mac.Write(body)
		r.Header.Set("X-Signature", "sha256="+hex.EncodeToString(mac.Sum(nil)))
	}
	if rec := push(t, h, signed, acmeTenant.String(), sign); rec.Code != http.StatusOK {
		t.Fatalf("a correctly signed push must succeed; got %d %s", rec.Code, rec.Body)
	}
	if got := pub.tenantsWritten(acmeTenant); got != 1 {
		t.Fatalf("expected the signed push to land 1 event for Acme, got %d", got)
	}
}

// readAll drains and restores a request body so a test option can sign it.
func readAll(t *testing.T, r *http.Request) []byte {
	t.Helper()
	buf := new(bytes.Buffer)
	if _, err := buf.ReadFrom(r.Body); err != nil {
		t.Fatalf("read body: %v", err)
	}
	body := buf.Bytes()
	r.Body = httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body)).Body
	return body
}

// ── the resolver's own contract ────────────────────────────────────────

func TestResolve_IsIntersectionOnly(t *testing.T) {
	acme := ingestauth.NewPrincipal("token:...aaaa", false, acmeTenant)

	if _, err := ingestauth.Resolve(acme, umbraTenant.String()); err == nil {
		t.Fatal("resolving a tenant outside the principal must fail")
	}
	got, err := ingestauth.Resolve(acme, acmeTenant.String())
	if err != nil || got != acmeTenant {
		t.Fatalf("resolving the principal's own tenant must succeed; got %v %v", got, err)
	}
	if _, err := ingestauth.Resolve(ingestauth.NewPrincipal("nobody", false), acmeTenant.String()); err == nil {
		t.Fatal("an empty principal must refuse rather than widen")
	}
	if _, err := ingestauth.Resolve(acme, "not-a-uuid"); err == nil {
		t.Fatal("a non-UUID tenant ref must be refused")
	}
}

// A credential that reaches several tenants must be made to name one,
// rather than having one picked for it.
func TestResolve_MultiTenantPrincipalMustNameATenant(t *testing.T) {
	both := ingestauth.NewPrincipal("service", true, acmeTenant, umbraTenant)
	if _, err := ingestauth.Resolve(both, ""); err == nil {
		t.Fatal("a multi-tenant principal with no named tenant must refuse")
	}
	for _, want := range []uuid.UUID{acmeTenant, umbraTenant} {
		got, err := ingestauth.Resolve(both, want.String())
		if err != nil || got != want {
			t.Fatalf("naming %v should resolve to it; got %v %v", want, got, err)
		}
	}
	if _, err := ingestauth.Resolve(both, ghostTenant.String()); err == nil {
		t.Fatal("a multi-tenant principal must still refuse a tenant outside its scope")
	}
}

func TestFingerprint_NeverReturnsTheCredential(t *testing.T) {
	for _, token := range []string{acmeToken, "short", ""} {
		fp := ingestauth.Fingerprint(token)
		if fp == token {
			t.Fatalf("fingerprint of %q returned the credential itself", token)
		}
		if len(token) > 8 && fmt.Sprintf("...%s", token[len(token)-8:]) != fp {
			t.Fatalf("unexpected fingerprint %q for %q", fp, token)
		}
	}
}
