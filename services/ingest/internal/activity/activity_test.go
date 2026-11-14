package activity

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// Each case is a real vendor record shape, trimmed to the fields the
// derivation reads plus enough context to show where they sit. They are
// transcriptions of the documented schemas named in actor.go, not inventions:
// a fixture that puts `userIdentity.type` somewhere AWS does not would make
// this suite agree with itself forever.
func canonical(connector string, vendor map[string]any) map[string]any {
	return map[string]any{"source": connector, "raw_event": vendor}
}

func TestActorKindComesFromTheVendorsOwnField(t *testing.T) {
	cases := []struct {
		name       string
		connector  string
		vendor     map[string]any
		wantKind   ActorKind
		wantSource string
	}{
		{
			name:      "CloudTrail AWSService is compute acting as itself",
			connector: "aws_cloudtrail",
			vendor: map[string]any{
				"eventName":    "AssumeRole",
				"userIdentity": map[string]any{"type": "AWSService", "invokedBy": "config.amazonaws.com"},
			},
			wantKind:   ActorWorkload,
			wantSource: "userIdentity.invokedBy",
		},
		{
			name:      "CloudTrail root is a person",
			connector: "aws_cloudtrail",
			vendor: map[string]any{
				"eventName":    "ConsoleLogin",
				"userIdentity": map[string]any{"type": "Root", "arn": "arn:aws:iam::123456789012:root"},
			},
			wantKind:   ActorHuman,
			wantSource: "userIdentity.type",
		},
		{
			name:      "CloudTrail IdentityCenterUser is a person",
			connector: "aws_cloudtrail",
			vendor: map[string]any{
				"userIdentity": map[string]any{"type": "IdentityCenterUser"},
			},
			wantKind:   ActorHuman,
			wantSource: "userIdentity.type",
		},
		{
			name:      "Okta User",
			connector: "okta",
			vendor: map[string]any{
				"eventType": "user.session.start",
				"actor":     map[string]any{"type": "User", "displayName": "Alice"},
			},
			wantKind:   ActorHuman,
			wantSource: "actor.type",
		},
		{
			name:      "Okta SystemPrincipal",
			connector: "okta",
			vendor: map[string]any{
				"actor": map[string]any{"type": "SystemPrincipal"},
			},
			wantKind:   ActorServiceAccount,
			wantSource: "actor.type",
		},
		{
			name:      "Okta PublicClientApp is a delegated app",
			connector: "okta",
			vendor: map[string]any{
				"actor": map[string]any{"type": "PublicClientApp"},
			},
			wantKind:   ActorOAuthApp,
			wantSource: "actor.type",
		},
		{
			name:       "M365 UserType 5 is an application",
			connector:  "m365_audit",
			vendor:     map[string]any{"Operation": "MailItemsAccessed", "UserType": float64(5)},
			wantKind:   ActorOAuthApp,
			wantSource: "UserType",
		},
		{
			name:       "M365 UserType 6 is a service principal",
			connector:  "m365_audit",
			vendor:     map[string]any{"UserType": float64(6)},
			wantKind:   ActorServiceAccount,
			wantSource: "UserType",
		},
		{
			name:       "M365 UserType 2 is an admin, still a person",
			connector:  "m365_audit",
			vendor:     map[string]any{"UserType": float64(2)},
			wantKind:   ActorHuman,
			wantSource: "UserType",
		},
		{
			name:      "Entra initiatedBy.app alone is a service principal",
			connector: "azure_entra",
			vendor: map[string]any{
				"activityDisplayName": "Add member to role",
				"initiatedBy":         map[string]any{"app": map[string]any{"appId": "0000-1111"}},
			},
			wantKind:   ActorServiceAccount,
			wantSource: "initiatedBy.app",
		},
		{
			name:      "Entra initiatedBy.user is a person",
			connector: "azure_entra",
			vendor: map[string]any{
				"initiatedBy": map[string]any{"user": map[string]any{"userPrincipalName": "alice@example.com"}},
			},
			wantKind:   ActorHuman,
			wantSource: "initiatedBy.user",
		},
		{
			name:      "Workspace callerType KEY is a token",
			connector: "google_workspace",
			vendor: map[string]any{
				"actor":  map[string]any{"callerType": "KEY"},
				"events": []any{map[string]any{"name": "download"}},
			},
			wantKind:   ActorAPIToken,
			wantSource: "actor.callerType",
		},
		{
			name:      "Workspace callerType APPLICATION is a delegated app",
			connector: "google_workspace",
			vendor: map[string]any{
				"actor": map[string]any{"callerType": "APPLICATION"},
			},
			wantKind:   ActorOAuthApp,
			wantSource: "actor.callerType",
		},
		{
			name:      "GCP service account by its own namespace",
			connector: "gcp_cloud_audit",
			vendor: map[string]any{
				"protoPayload": map[string]any{
					"methodName":         "storage.objects.list",
					"authenticationInfo": map[string]any{"principalEmail": "etl@proj.iam.gserviceaccount.com"},
				},
			},
			wantKind:   ActorServiceAccount,
			wantSource: "authenticationInfo.principalEmail",
		},
		{
			name:      "GCP impersonation is a service account whatever the caller is",
			connector: "gcp_cloud_audit",
			vendor: map[string]any{
				"protoPayload": map[string]any{
					"authenticationInfo": map[string]any{
						"principalEmail":               "alice@example.com",
						"serviceAccountDelegationInfo": []any{map[string]any{"principalSubject": "svc"}},
					},
				},
			},
			wantKind:   ActorServiceAccount,
			wantSource: "authenticationInfo.serviceAccountDelegationInfo",
		},
		{
			name:       "GitHub personal access token",
			connector:  "github",
			vendor:     map[string]any{"action": "repo.destroy", "programmatic_access_type": "Fine-grained personal access token"},
			wantKind:   ActorAPIToken,
			wantSource: "programmatic_access_type",
		},
		{
			name:       "GitHub bot actor",
			connector:  "github",
			vendor:     map[string]any{"action": "workflow_run", "actor_is_bot": true},
			wantKind:   ActorWorkload,
			wantSource: "actor_is_bot",
		},
		{
			name:       "Kubernetes service account by its reserved username",
			connector:  "kubernetes_audit",
			vendor:     map[string]any{"verb": "list", "user": map[string]any{"username": "system:serviceaccount:kube-system:replicaset-controller"}},
			wantKind:   ActorServiceAccount,
			wantSource: "user.username",
		},
		{
			name:       "Kubernetes node by its reserved username",
			connector:  "kubernetes_audit",
			vendor:     map[string]any{"verb": "get", "user": map[string]any{"username": "system:node:ip-10-0-1-5"}},
			wantKind:   ActorWorkload,
			wantSource: "user.username",
		},
		{
			name:       "an AI agent says so in its own envelope",
			connector:  "ai_gateway",
			vendor:     map[string]any{"agent_id": "agt-7", "tool_name": "search_siem"},
			wantKind:   ActorAIAgent,
			wantSource: "agent_id",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := Project(tc.connector, canonical(tc.connector, tc.vendor), map[string]any{})
			if got.Actor.Kind != tc.wantKind {
				t.Errorf("kind = %q, want %q", got.Actor.Kind, tc.wantKind)
			}
			if got.Actor.KindSource != tc.wantSource {
				t.Errorf("kind_source = %q, want %q", got.Actor.KindSource, tc.wantSource)
			}
		})
	}
}

// The rule with the sharpest edge: what cannot be derived stays unknown.
//
// An inferred `human` is worse than no answer, because a privilege decision,
// a blast radius and an auto-close would each treat the guess as evidence.
// Every case below is a shape a plausible heuristic would get wrong.
func TestWhatCannotBeDerivedStaysUnknown(t *testing.T) {
	cases := []struct {
		name      string
		connector string
		vendor    map[string]any
	}{
		{
			// AWS does not say whether an IAM user is a person, and a great
			// many are long-lived programmatic identities.
			name:      "CloudTrail IAMUser",
			connector: "aws_cloudtrail",
			vendor:    map[string]any{"userIdentity": map[string]any{"type": "IAMUser", "userName": "deploy-bot"}},
		},
		{
			// An assumed role is whatever assumed it.
			name:      "CloudTrail AssumedRole with no invokedBy",
			connector: "aws_cloudtrail",
			vendor:    map[string]any{"userIdentity": map[string]any{"type": "AssumedRole"}},
		},
		{
			// A name that looks like a service account is not a vendor
			// field. "svc-" means nothing.
			name:      "a username that looks automated",
			connector: "okta",
			vendor:    map[string]any{"actor": map[string]any{"displayName": "svc-backup-runner"}},
		},
		{
			// GitHub documents when programmatic_access_type appears, not
			// that it appears on every API event, so silence is not a web
			// session.
			name:      "GitHub with no programmatic access type",
			connector: "github",
			vendor:    map[string]any{"action": "team.add_member", "actor": "alice"},
		},
		{
			// An email address in a corporate domain says nothing about
			// whether a person or a job is behind it.
			name:      "GCP principal in a corporate domain",
			connector: "gcp_cloud_audit",
			vendor: map[string]any{
				"protoPayload": map[string]any{"authenticationInfo": map[string]any{"principalEmail": "alice@example.com"}},
			},
		},
		{
			name:      "M365 UserType 1, which Microsoft documents as Reserved",
			connector: "m365_audit",
			vendor:    map[string]any{"UserType": float64(1)},
		},
		{
			name:      "a source with no identity-type field at all",
			connector: "zscaler",
			vendor:    map[string]any{"action": "Allow", "url": "example.com"},
		},
		{
			name:      "a connector this package has no derivation for",
			connector: "tailscale",
			vendor:    map[string]any{"actor": "device-01", "action": "UPDATE"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := Project(tc.connector, canonical(tc.connector, tc.vendor), map[string]any{})
			if got.Actor.Kind != ActorUnknown {
				t.Errorf("kind = %q, want %q — this source does not say, and a guess here becomes evidence downstream",
					got.Actor.Kind, ActorUnknown)
			}
			if got.Actor.KindSource != "" {
				t.Errorf("kind_source = %q, want empty: an unknown kind was read from no field", got.Actor.KindSource)
			}
		})
	}
}

// A kind is only ever one of the closed set. A typo in a derivation would
// otherwise reach a lake column and a graph property as a value nothing
// queries for.
func TestEveryDerivedKindIsInTheClosedSet(t *testing.T) {
	allowed := map[ActorKind]bool{}
	for _, k := range ActorKinds {
		allowed[k] = true
	}
	// Drive every connector this package derives for, with a shape that
	// resolves, and one that does not.
	for _, connector := range []string{
		"aws_cloudtrail", "okta", "m365_audit", "azure_entra", "google_workspace",
		"gcp_cloud_audit", "github", "kubernetes_audit", "ai_gateway", "zscaler",
	} {
		for _, vendor := range []map[string]any{
			{"userIdentity": map[string]any{"type": "Root"}},
			{"actor": map[string]any{"type": "User", "callerType": "KEY"}},
			{"UserType": float64(6)},
			{"agent_id": "a"},
			{},
		} {
			got := Project(connector, canonical(connector, vendor), map[string]any{})
			if !allowed[got.Actor.Kind] {
				t.Errorf("%s produced kind %q, which is not in ActorKinds", connector, got.Actor.Kind)
			}
		}
	}
}

// The envelope key is `raw_event` and never `raw`. 26 connectors once emitted
// `raw`, missed the normalizer's canonical-envelope check and fell through to
// a borrowed vendor profile; reading only the one key here keeps this package
// from re-introducing that fork under a different name.
func TestOnlyRawEventIsReadAsTheVendorRecord(t *testing.T) {
	vendor := map[string]any{"userIdentity": map[string]any{"type": "Root"}}

	viaRawEvent := Project("aws_cloudtrail", map[string]any{"source": "aws_cloudtrail", "raw_event": vendor}, map[string]any{})
	if viaRawEvent.Actor.Kind != ActorHuman {
		t.Fatalf("raw_event envelope: kind = %q, want human", viaRawEvent.Actor.Kind)
	}

	viaRaw := Project("aws_cloudtrail", map[string]any{"source": "aws_cloudtrail", "raw": vendor}, map[string]any{})
	if viaRaw.Actor.Kind != ActorUnknown {
		t.Errorf("a `raw` key resolved to kind %q; this package must read `raw_event` only, so a connector "+
			"emitting the wrong key is visibly unclassified rather than quietly working", viaRaw.Actor.Kind)
	}
}

func TestOutcomeDistinguishesSilenceFromSuccess(t *testing.T) {
	cases := []struct {
		name   string
		vendor map[string]any
		want   Outcome
	}{
		{"an explicit false", map[string]any{"success": false}, OutcomeFailure},
		{"an explicit true", map[string]any{"success": true}, OutcomeSuccess},
		{"an AWS error code", map[string]any{"errorCode": "AccessDenied"}, OutcomeFailure},
		{"Okta FAILURE", map[string]any{"outcome": map[string]any{"result": "FAILURE"}}, OutcomeFailure},
		{"Okta SUCCESS", map[string]any{"outcome": map[string]any{"result": "SUCCESS"}}, OutcomeSuccess},
		{"M365 Succeeded", map[string]any{"ResultStatus": "Succeeded"}, OutcomeSuccess},
		{"a Kubernetes 403", map[string]any{"responseStatus": map[string]any{"code": float64(403)}}, OutcomeFailure},
		{"a Kubernetes 201", map[string]any{"responseStatus": map[string]any{"code": float64(201)}}, OutcomeSuccess},
		{
			"a source that says nothing",
			map[string]any{"url": "example.com"},
			// The whole point: a detection counting failures would read a
			// silent source as a clean estate if this folded into success.
			OutcomeUnknown,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := Project("generic", canonical("generic", tc.vendor), map[string]any{})
			if got.Outcome != tc.want {
				t.Errorf("outcome = %q, want %q", got.Outcome, tc.want)
			}
		})
	}
}

func TestActionNormalizesAcrossVendors(t *testing.T) {
	cases := []struct {
		connector string
		vendor    map[string]any
		want      string
	}{
		{"aws_cloudtrail", map[string]any{"eventName": "CreateAccessKey"}, "create.access.key"},
		{"okta", map[string]any{"eventType": "system.api_token.create"}, "system.api.token.create"},
		{"m365_audit", map[string]any{"Operation": "Add service principal credentials."}, "add.service.principal.credentials"},
		{"gcp_cloud_audit", map[string]any{"protoPayload": map[string]any{"methodName": "storage.objects.list"}}, "storage.objects.list"},
		{"github", map[string]any{"action": "repo.destroy"}, "repo.destroy"},
		{"kubernetes_audit", map[string]any{"verb": "create", "objectRef": map[string]any{"resource": "pods"}}, "create.pods"},
		{"windows_event", map[string]any{"EventID": "4688"}, "windows.event.4688"},
		{"auditd", map[string]any{"syscall": "execve"}, "auditd.execve"},
		// A source naming no event type gets no action, rather than a verb
		// invented from prose that nothing else in the platform shares.
		{"zscaler", map[string]any{"url": "example.com"}, ""},
	}
	for _, tc := range cases {
		t.Run(tc.connector+"/"+tc.want, func(t *testing.T) {
			got := Project(tc.connector, canonical(tc.connector, tc.vendor), map[string]any{})
			if got.Action != tc.want {
				t.Errorf("action = %q, want %q", got.Action, tc.want)
			}
		})
	}
}

// An attacker chooses the event name on a pushed payload, and it reaches a
// lake column and a graph property.
func TestActionIsBounded(t *testing.T) {
	got := NormalizeAction(strings.Repeat("A", 4000))
	if len(got) > 256 {
		t.Errorf("a 4,000-character event name normalized to %d characters", len(got))
	}
}

func TestResourceComesFromTheSourcesOwnResourceFields(t *testing.T) {
	ct := Project("aws_cloudtrail", canonical("aws_cloudtrail", map[string]any{
		"eventName": "DeleteBucket",
		"resources": []any{map[string]any{
			"ARN":       "arn:aws:s3:::finance-exports",
			"type":      "AWS::S3::Bucket",
			"accountId": "123456789012",
		}},
	}), map[string]any{})
	if ct.Resource.Type != "AWS::S3::Bucket" || ct.Resource.ID != "arn:aws:s3:::finance-exports" || ct.Resource.Owner != "123456789012" {
		t.Errorf("CloudTrail resource = %+v", ct.Resource)
	}

	k8s := Project("kubernetes_audit", canonical("kubernetes_audit", map[string]any{
		"verb":      "delete",
		"objectRef": map[string]any{"resource": "secrets", "name": "db-password", "namespace": "payments"},
	}), map[string]any{})
	if k8s.Resource.Type != "secrets" || k8s.Resource.Name != "db-password" || k8s.Resource.Owner != "payments" {
		t.Errorf("Kubernetes resource = %+v", k8s.Resource)
	}
}

// The assumed-role chain back to the originating human is what makes an
// actor kind actionable rather than merely accurate.
func TestOnBehalfOfResolvesTheOriginatingPrincipal(t *testing.T) {
	got := Project("aws_cloudtrail", canonical("aws_cloudtrail", map[string]any{
		"eventName": "GetObject",
		"userIdentity": map[string]any{
			"type":           "AssumedRole",
			"sourceIdentity": "alice@example.com",
		},
	}), map[string]any{})
	if got.Actor.OnBehalfOf != "alice@example.com" {
		t.Errorf("on_behalf_of = %q, want the sourceIdentity AWS recorded", got.Actor.OnBehalfOf)
	}
}

// ──────────────────────────────────────────────────────────────────────────
// Enrichment
// ──────────────────────────────────────────────────────────────────────────

// No private, loopback, link-local, CGNAT, documentation or benchmarking
// address may leave the process. Sending one costs a round trip to learn
// nothing and publishes the customer's internal topology to a service that
// forwards to third-party vendors.
func TestOnlyPublicAddressesAreEnriched(t *testing.T) {
	var asked []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]string
		_ = json.NewDecoder(r.Body).Decode(&body)
		asked = append(asked, body["value"])
		_ = json.NewEncoder(w).Encode(map[string]any{
			"risk_score":   72.5,
			"geo_location": map[string]any{"country": "Sweden", "country_code": "SE", "asn": 1299, "as_org": "Arelion"},
		})
	}))
	defer server.Close()

	enricher := NewIPEnricher(server.URL, "token", time.Minute, time.Second)
	private := []string{
		"10.0.0.4", "172.16.3.9", "192.168.1.1", "127.0.0.1", "169.254.169.254",
		"100.64.1.1", "192.0.2.5", "198.51.100.7", "203.0.113.9", "198.18.0.1",
		"::1", "fe80::1", "fd00::1", "2001:db8::1", "", "not-an-ip",
	}
	for _, ip := range private {
		loc := Location{IP: ip}
		enricher.Enrich(context.Background(), &loc)
		if loc.Country != "" || loc.ASN != 0 || loc.ReputationKnown {
			t.Errorf("%q was enriched: %+v", ip, loc)
		}
	}
	if len(asked) != 0 {
		t.Errorf("the enrichment service was asked about %v; none of those addresses has a public answer", asked)
	}

	loc := Location{IP: "8.8.8.8"}
	enricher.Enrich(context.Background(), &loc)
	if loc.CountryCode != "SE" || loc.ASN != 1299 || loc.ASOrg != "Arelion" {
		t.Errorf("a public address was not enriched: %+v", loc)
	}
	if !loc.ReputationKnown || loc.Reputation != 72.5 {
		t.Errorf("reputation = %v known=%v, want 72.5 known", loc.Reputation, loc.ReputationKnown)
	}
	if len(asked) != 1 || asked[0] != "8.8.8.8" {
		t.Errorf("asked = %v, want exactly the one public address", asked)
	}
}

// A clean verdict and an unreachable enrichment service both produce a
// reputation of 0. Only the flag separates them, and a surface that renders
// 0 as "clean" when nobody answered is the fabricated-confidence shape this
// repository keeps finding.
func TestAnUnreachableEnricherLeavesReputationUnknown(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	loc := Location{IP: "8.8.8.8"}
	NewIPEnricher(server.URL, "token", time.Minute, time.Second).Enrich(context.Background(), &loc)
	if loc.ReputationKnown {
		t.Error("reputation_known is true after the service returned 500")
	}
}

// An internal call with no credential is answered 401 by our own service and
// reads to an operator as the vendor rejecting us.
func TestTheServiceTokenIsSent(t *testing.T) {
	var auth string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth = r.Header.Get("Authorization")
		_ = json.NewEncoder(w).Encode(map[string]any{"risk_score": 1.0})
	}))
	defer server.Close()

	loc := Location{IP: "8.8.8.8"}
	NewIPEnricher(server.URL, "s3cr3t", time.Minute, time.Second).Enrich(context.Background(), &loc)
	if auth != "Bearer s3cr3t" {
		t.Errorf("Authorization = %q, want the service token", auth)
	}
}

// A second event from the same address must not be a second round trip.
func TestTheEnricherCaches(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls++
		_ = json.NewEncoder(w).Encode(map[string]any{"risk_score": 5.0})
	}))
	defer server.Close()

	enricher := NewIPEnricher(server.URL, "", time.Minute, time.Second)
	for range 5 {
		loc := Location{IP: "8.8.8.8"}
		enricher.Enrich(context.Background(), &loc)
	}
	if calls != 1 {
		t.Errorf("the enrichment service was called %d times for one address", calls)
	}
}

// No URL means no enricher, and a nil enricher is usable. A deployment with
// no enrichment service must get thinner events, not a nil dereference.
func TestNoURLMeansNoEnricherAndThatIsSafe(t *testing.T) {
	enricher := NewIPEnricher("", "token", time.Minute, time.Second)
	if enricher != nil {
		t.Fatal("an empty URL produced an enricher")
	}
	loc := Location{IP: "8.8.8.8"}
	enricher.Enrich(context.Background(), &loc)
	if loc.ReputationKnown {
		t.Error("a nil enricher filled a reputation")
	}
}
