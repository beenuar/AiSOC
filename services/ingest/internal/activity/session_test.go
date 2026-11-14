package activity

import (
	"strings"
	"testing"
)

// Same rule as activity_test.go: every fixture is a transcription of the
// documented vendor schema named in session.go, not an invention. A fixture
// that put `externalSessionId` somewhere Okta does not would make this suite
// agree with itself forever while the derivation read nothing in production.

func TestSessionKeyComesFromTheVendorsOwnField(t *testing.T) {
	cases := []struct {
		name       string
		connector  string
		vendor     map[string]any
		wantKey    string
		wantKind   SessionKeyKind
		wantSource string
	}{
		{
			name:      "CloudTrail temporary credentials are the session",
			connector: "aws_cloudtrail",
			vendor: map[string]any{
				"eventName": "GetObject",
				"userIdentity": map[string]any{
					"type":        "AssumedRole",
					"arn":         "arn:aws:sts::123456789012:assumed-role/Deploy/i-0abc",
					"accessKeyId": "ASIAIOSFODNN7EXAMPLE",
				},
			},
			wantKey:    "ASIAIOSFODNN7EXAMPLE",
			wantKind:   SessionVendorCredential,
			wantSource: "userIdentity.accessKeyId",
		},
		{
			name:      "Okta names a session",
			connector: "okta",
			vendor: map[string]any{
				"actor":                 map[string]any{"alternateId": "alice@corp.example", "type": "User"},
				"authenticationContext": map[string]any{"externalSessionId": "00okta0session0EXAMPLE0001"},
			},
			wantKey:    "00okta0session0EXAMPLE0001",
			wantKind:   SessionVendorSession,
			wantSource: "authenticationContext.externalSessionId",
		},
		{
			name:      "M365 carries the Entra session the token was issued for",
			connector: "m365_audit",
			vendor: map[string]any{
				"UserId":           "alice@corp.example",
				"AppAccessContext": map[string]any{"AADSessionId": "c0ffee00-1111-2222-3333-444455556666"},
			},
			wantKey:    "c0ffee00-1111-2222-3333-444455556666",
			wantKind:   SessionVendorSession,
			wantSource: "AppAccessContext.AADSessionId",
		},
		{
			name:      "Entra correlates a sign-in flow, which is not a session",
			connector: "azure_entra",
			vendor: map[string]any{
				"userPrincipalName": "alice@corp.example",
				"correlationId":     "00000000-1111-2222-3333-444444444444",
			},
			wantKey:    "00000000-1111-2222-3333-444444444444",
			wantKind:   SessionVendorFlow,
			wantSource: "correlationId",
		},
		{
			name:      "Workspace groups an OAuth application's activity by its client id",
			connector: "google_workspace",
			vendor: map[string]any{
				"actor": map[string]any{"email": "alice@corp.example"},
				"events": []any{map[string]any{
					"type": "token",
					"name": "authorize",
					"parameters": []any{
						map[string]any{"name": "app_name", "value": "Some App"},
						map[string]any{"name": "client_id", "value": "1234567890.apps.googleusercontent.com"},
					},
				}},
			},
			wantKey:    "1234567890.apps.googleusercontent.com",
			wantKind:   SessionVendorCredential,
			wantSource: "events[].parameters[client_id]",
		},
		{
			name:      "GitHub has no session, so the token is the grouping",
			connector: "github",
			vendor: map[string]any{
				"actor":        "alice",
				"action":       "repo.destroy",
				"hashed_token": "ZWFzdGVyLWVnZw==",
			},
			wantKey:    "ZWFzdGVyLWVnZw==",
			wantKind:   SessionVendorCredential,
			wantSource: "hashed_token",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := Project(tc.connector, canonical(tc.connector, tc.vendor), nil).Session
			if got.Key != tc.wantKey {
				t.Fatalf("key: got %q, want %q", got.Key, tc.wantKey)
			}
			if got.KeyKind != tc.wantKind {
				t.Fatalf("kind: got %q, want %q", got.KeyKind, tc.wantKind)
			}
			if got.KeySource != tc.wantSource {
				t.Fatalf("source: got %q, want %q", got.KeySource, tc.wantSource)
			}
		})
	}
}

// The negative control for the whole file. Each case removes exactly the
// field the matching positive case above reads, and asserts the derivation
// reports no vendor key rather than inventing one.
func TestNoVendorFieldMeansNoVendorKey(t *testing.T) {
	cases := []struct {
		name      string
		connector string
		vendor    map[string]any
	}{
		{
			name:      "CloudTrail without an access key",
			connector: "aws_cloudtrail",
			vendor: map[string]any{
				"eventName":    "GetObject",
				"userIdentity": map[string]any{"type": "AssumedRole", "arn": "arn:aws:sts::1:assumed-role/R/s"},
			},
		},
		{
			// Okta writes the literal "unknown" rather than omitting the
			// field. Reading it would collapse every session-less event in
			// the tenant into one enormous session called "unknown".
			name:      "Okta writes the literal unknown",
			connector: "okta",
			vendor: map[string]any{
				"actor":                 map[string]any{"alternateId": "alice@corp.example"},
				"authenticationContext": map[string]any{"externalSessionId": "unknown"},
			},
		},
		{
			name:      "M365 without an app access context",
			connector: "m365_audit",
			vendor:    map[string]any{"UserId": "alice@corp.example", "Operation": "FileAccessed"},
		},
		{
			name:      "Entra without a correlation id",
			connector: "azure_entra",
			vendor:    map[string]any{"userPrincipalName": "alice@corp.example"},
		},
		{
			name:      "Workspace activity that is not a token application",
			connector: "google_workspace",
			vendor: map[string]any{
				"actor": map[string]any{"email": "alice@corp.example"},
				"events": []any{map[string]any{
					"type":       "login",
					"name":       "login_success",
					"parameters": []any{map[string]any{"name": "login_type", "value": "google_password"}},
				}},
			},
		},
		{
			name:      "GitHub without a hashed token",
			connector: "github",
			vendor:    map[string]any{"actor": "alice", "action": "repo.destroy"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := Project(tc.connector, canonical(tc.connector, tc.vendor), nil).Session
			if got.KeyKind != "" && got.KeyKind != SessionDerived {
				t.Fatalf("invented a %s key %q from a record that carries none", got.KeyKind, got.Key)
			}
		})
	}
}

// The chain is the reason this projection exists. A second-hop session's own
// events name only the role it assumed; the edge back to the person lives on
// the AssumeRole call alone, and is unrecoverable once that record is gone.
func TestAssumeRoleRecordsTheSessionItIssued(t *testing.T) {
	cases := []struct {
		name       string
		vendor     map[string]any
		wantKey    string
		wantWho    string
		wantSource string
	}{
		{
			name: "sourceIdentity is the strongest, and AWS carries it onward itself",
			vendor: map[string]any{
				"eventName":         "AssumeRole",
				"userIdentity":      map[string]any{"arn": "arn:aws:iam::123456789012:user/ci"},
				"requestParameters": map[string]any{"roleSessionName": "build-471", "sourceIdentity": "alice@corp.example"},
				"responseElements": map[string]any{
					"credentials":     map[string]any{"accessKeyId": "ASIACHILD0000000EXMP"},
					"assumedRoleUser": map[string]any{"arn": "arn:aws:sts::123456789012:assumed-role/Deploy/build-471"},
				},
			},
			wantKey:    "ASIACHILD0000000EXMP",
			wantWho:    "alice@corp.example",
			wantSource: "requestParameters.sourceIdentity",
		},
		{
			name: "AssumeRoleWithSAML names the person the IdP authenticated",
			vendor: map[string]any{
				"eventName":         "AssumeRoleWithSAML",
				"requestParameters": map[string]any{"roleSessionName": "alice"},
				"responseElements": map[string]any{
					"credentials":     map[string]any{"accessKeyId": "ASIASAML00000000EXMP"},
					"subject":         "alice@corp.example",
					"assumedRoleUser": map[string]any{"arn": "arn:aws:sts::1:assumed-role/Admin/alice"},
				},
			},
			wantKey:    "ASIASAML00000000EXMP",
			wantWho:    "alice@corp.example",
			wantSource: "responseElements.subject",
		},
		{
			name: "AssumeRoleWithWebIdentity names the token subject",
			vendor: map[string]any{
				"eventName": "AssumeRoleWithWebIdentity",
				"responseElements": map[string]any{
					"credentials":                 map[string]any{"accessKeyId": "ASIAOIDC00000000EXMP"},
					"subjectFromWebIdentityToken": "repo:acme/app:ref:refs/heads/main",
				},
			},
			wantKey:    "ASIAOIDC00000000EXMP",
			wantWho:    "repo:acme/app:ref:refs/heads/main",
			wantSource: "responseElements.subjectFromWebIdentityToken",
		},
		{
			// Caller-chosen free text. Carried because an analyst reading it
			// knows which estate they are in, and kept in its own source
			// string so nothing downstream mistakes it for an authenticated
			// identity.
			name: "roleSessionName is the weakest and says so",
			vendor: map[string]any{
				"eventName":         "AssumeRole",
				"requestParameters": map[string]any{"roleSessionName": "alice@corp.example"},
				"responseElements": map[string]any{
					"credentials": map[string]any{"accessKeyId": "ASIANAME00000000EXMP"},
				},
			},
			wantKey:    "ASIANAME00000000EXMP",
			wantWho:    "alice@corp.example",
			wantSource: "requestParameters.roleSessionName",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := Project("aws_cloudtrail", canonical("aws_cloudtrail", tc.vendor), nil).Session
			if got.Issued == nil {
				t.Fatal("no issued session recorded, so the chain to the person is lost")
			}
			if got.Issued.Key != tc.wantKey {
				t.Fatalf("issued key: got %q, want %q", got.Issued.Key, tc.wantKey)
			}
			if got.Issued.OriginatingHuman != tc.wantWho {
				t.Fatalf("originating human: got %q, want %q", got.Issued.OriginatingHuman, tc.wantWho)
			}
			if got.Issued.OriginatingHumanSource != tc.wantSource {
				t.Fatalf("source: got %q, want %q", got.Issued.OriginatingHumanSource, tc.wantSource)
			}
		})
	}
}

// A call that issues no credential must record no issued session, or every
// consumer walking the chain gains an edge that does not exist.
func TestOnlyCredentialIssuingCallsRecordAnIssuedSession(t *testing.T) {
	for _, eventName := range []string{"GetObject", "ConsoleLogin", "DeleteBucket", "GetCallerIdentity"} {
		t.Run(eventName, func(t *testing.T) {
			got := Project("aws_cloudtrail", canonical("aws_cloudtrail", map[string]any{
				"eventName":        eventName,
				"userIdentity":     map[string]any{"arn": "arn:aws:iam::1:user/alice", "accessKeyId": "AKIA0000000000000EXM"},
				"responseElements": map[string]any{"credentials": map[string]any{"accessKeyId": "ASIANOTREAL00000EXMP"}},
			}), nil).Session
			if got.Issued != nil {
				t.Fatalf("%s is not a credential-issuing call but recorded an issued session", eventName)
			}
		})
	}
}

// An AssumeRole whose caller set nothing identifying must leave the person
// empty. The role name is a role, not a human, and reading it as one would
// attribute a machine's actions to an invented person.
func TestAnAnonymousAssumeRoleNamesNobody(t *testing.T) {
	got := Project("aws_cloudtrail", canonical("aws_cloudtrail", map[string]any{
		"eventName": "AssumeRole",
		"responseElements": map[string]any{
			"credentials":     map[string]any{"accessKeyId": "ASIAANON00000000EXMP"},
			"assumedRoleUser": map[string]any{"arn": "arn:aws:sts::1:assumed-role/Batch/nightly"},
		},
	}), nil).Session
	if got.Issued == nil {
		t.Fatal("the issued session itself should still be recorded")
	}
	if got.Issued.OriginatingHuman != "" {
		t.Fatalf("named %q as the originating human from a record that names nobody", got.Issued.OriginatingHuman)
	}
}

// The plan's fallback: principal plus address plus client. All three are
// required, because two of them is a grouping that merges unrelated work.
func TestTheDerivedKeyNeedsAllThreeParts(t *testing.T) {
	// The address reaches the projection through the OCSF event rather than
	// the vendor record, because the normalizer's identity aliases have
	// already resolved the four spellings these sources use.
	ocsf := map[string]any{"src_endpoint": map[string]any{"ip": "203.0.113.10"}}
	full := map[string]any{
		"actor":          map[string]any{"alternateId": "alice@corp.example", "type": "User"},
		"client":         map[string]any{"userAgent": map[string]any{"rawUserAgent": "Mozilla/5.0"}},
		"outcome":        map[string]any{"result": "SUCCESS"},
		"eventType":      "policy.lifecycle.update",
		"displayMessage": "Update policy",
	}
	got := Project("okta", canonical("okta", full), ocsf).Session
	if got.KeyKind != SessionDerived {
		t.Fatalf("kind: got %q, want %q", got.KeyKind, SessionDerived)
	}
	if n := len(strings.Split(got.Key, "|")); n != 3 {
		t.Fatalf("derived key %q has %d parts, want 3", got.Key, n)
	}
	if got.KeySource != "principal+ip+user_agent" {
		t.Fatalf("source: got %q", got.KeySource)
	}

	// Negative control: drop the user agent and the key must disappear
	// entirely rather than degrade to principal+ip, which would merge a
	// browser session and a CLI run from one office.
	withoutClient := map[string]any{
		"actor":   map[string]any{"alternateId": "alice@corp.example", "type": "User"},
		"outcome": map[string]any{"result": "SUCCESS"},
	}
	if got := Project("okta", canonical("okta", withoutClient), ocsf).Session; got.Key != "" {
		t.Fatalf("derived a key %q from two parts", got.Key)
	}
}

// Every kind a derivation can emit has to be in the closed set, or the lake
// enum and the gate are describing a vocabulary the producer does not use.
func TestEverySessionKindIsInTheClosedSet(t *testing.T) {
	allowed := map[SessionKeyKind]bool{}
	for _, k := range SessionKeyKinds {
		allowed[k] = true
	}
	vendors := map[string]map[string]any{
		"aws_cloudtrail":   {"userIdentity": map[string]any{"accessKeyId": "ASIA0000000000000EXM"}},
		"okta":             {"authenticationContext": map[string]any{"externalSessionId": "s1"}},
		"m365_audit":       {"AppAccessContext": map[string]any{"AADSessionId": "s2"}},
		"azure_entra":      {"correlationId": "s3"},
		"google_workspace": {"events": []any{map[string]any{"parameters": []any{map[string]any{"name": "client_id", "value": "s4"}}}}},
		"github":           {"hashed_token": "s5"},
	}
	for connector, vendor := range vendors {
		got := Project(connector, canonical(connector, vendor), nil).Session
		if got.KeyKind != "" && !allowed[got.KeyKind] {
			t.Fatalf("%s emitted kind %q, which is outside the closed set", connector, got.KeyKind)
		}
	}
}

// The key is kept as the vendor spells it so an analyst can paste it into
// the vendor's own console. A hash here would be a value that exists nowhere
// else and cannot be looked up anywhere.
func TestTheKeyIsTheVendorsOwnValue(t *testing.T) {
	const raw = "00okta0session0EXAMPLE0001"
	got := Project("okta", canonical("okta", map[string]any{
		"actor":                 map[string]any{"alternateId": "alice@corp.example"},
		"authenticationContext": map[string]any{"externalSessionId": raw},
	}), nil).Session
	if got.Key != raw {
		t.Fatalf("key %q is not the vendor's own value %q", got.Key, raw)
	}
}
