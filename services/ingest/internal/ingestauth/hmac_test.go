// hmac_test.go — what an unusable signing secret does to a push.
//
// The body signature is genuinely optional on this path: migration 033
// documents a NULL hmac_secret as "no signature verification (still
// secured by the token in the URL)", because a webhook vendor often
// cannot sign. So the rule under test is not "every push must be
// signed". It is narrower and the one the shipped code got wrong: a
// token that *declares* a signature requirement must never be satisfied
// by a secret that cannot carry one.
//
// Both of the obvious readings of a blank secret are unsafe, which is
// why refusing is the only answer left:
//
//   - Skip verification (what the code did) and an unsigned body is
//     accepted from anyone holding the token.
//   - Verify against it and a forged body is accepted from anyone at
//     all, because HMAC keyed on the empty string is a value the
//     attacker can compute as easily as we can. TestABlankKeyIsForgeable
//     below demonstrates that directly rather than asserting it.
package ingestauth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
)

var hmacTenant = uuid.MustParse("44444444-4444-4444-8444-444444444444")

func pushRequest(signature string) *http.Request {
	r := httptest.NewRequest(http.MethodPost, "/v1/ingest", nil)
	if signature != "" {
		r.Header.Set("X-Signature", signature)
	}
	return r
}

func identityWithSecret(secret string, configured bool) Identity {
	return Identity{
		Principal:      NewPrincipal("token:...testtest", false, hmacTenant),
		HMACSecret:     secret,
		HMACConfigured: configured,
	}
}

// TestBlankConfiguredSecretIsRefused is the reporter's proof of concept:
// submit with a token whose hmac_secret is empty, and no signature.
// The shipped code returned nil here and the submission was accepted.
func TestBlankConfiguredSecretIsRefused(t *testing.T) {
	body := []byte(`{"events":[{"forged":true}]}`)

	for _, blank := range []string{"", " ", "\t\n"} {
		err := VerifySignature(pushRequest(""), identityWithSecret(blank, true), body)
		if err == nil {
			t.Fatalf("a token declaring a signature requirement with secret %q accepted an unsigned body", blank)
		}
		var authErr *Error
		if !asError(err, &authErr) {
			t.Fatalf("want *ingestauth.Error, got %T", err)
		}
		if authErr.Status != http.StatusServiceUnavailable {
			t.Fatalf("status %d; want 503 — the row is misconfigured, which is not the caller's fault "+
				"and is not something a different credential would fix", authErr.Status)
		}
	}
}

// TestABlankKeyIsForgeable is why "verify against the empty key" was not
// the alternative fix. It computes the signature an attacker would send,
// with no secret knowledge whatsoever, and shows it matches. If this test
// ever fails, the empty key stopped being guessable and the reasoning in
// VerifySignature needs revisiting.
func TestABlankKeyIsForgeable(t *testing.T) {
	body := []byte(`{"events":[{"forged":true}]}`)

	mac := hmac.New(sha256.New, []byte("")) // what any attacker can compute
	mac.Write(body)
	forged := "sha256=" + hex.EncodeToString(mac.Sum(nil))

	err := VerifySignature(pushRequest(forged), identityWithSecret("", true), body)
	if err == nil {
		t.Fatal("a signature computed from the empty key was accepted; an unusable secret must refuse, " +
			"not be used as a key")
	}
}

// TestUnconfiguredSecretStillPushesUnsigned is the positive control, and
// it is the half that keeps the fix from being an outage. A NULL
// hmac_secret is a documented, supported configuration — every webhook
// vendor that cannot sign depends on it — so refusing it would have
// broken far more than it secured.
func TestUnconfiguredSecretStillPushesUnsigned(t *testing.T) {
	body := []byte(`{"events":[{"ok":true}]}`)

	if err := VerifySignature(pushRequest(""), identityWithSecret("", false), body); err != nil {
		t.Fatalf("a token with no configured secret was refused: %v", err)
	}
}

// TestConfiguredSecretStillVerifies is the other positive control: a real
// secret must still accept a correct signature and reject a wrong one. A
// gate that refused everything would pass the two tests above.
func TestConfiguredSecretStillVerifies(t *testing.T) {
	const secret = "a-real-secret-of-sufficient-length"
	body := []byte(`{"events":[{"ok":true}]}`)

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	good := "sha256=" + hex.EncodeToString(mac.Sum(nil))

	if err := VerifySignature(pushRequest(good), identityWithSecret(secret, true), body); err != nil {
		t.Fatalf("a correctly signed body was refused: %v", err)
	}
	if err := VerifySignature(pushRequest("sha256=deadbeef"), identityWithSecret(secret, true), body); err == nil {
		t.Fatal("a wrong signature was accepted")
	}
	if err := VerifySignature(pushRequest(""), identityWithSecret(secret, true), body); err == nil {
		t.Fatal("a missing signature was accepted against a configured secret")
	}
}

// asError is errors.As, spelled locally so the test file does not import
// errors purely for one call.
func asError(err error, target **Error) bool {
	if e, ok := err.(*Error); ok {
		*target = e
		return true
	}
	return false
}
