// Package activity builds the canonical activity projection carried on every
// normalized event: who acted, what kind of actor they were, what they did,
// to which resource, from where, and with what outcome.
//
// Why one projection rather than per-source fields
// ------------------------------------------------
// Every consumer downstream of ingest — the detection matcher, the lake, the
// entity graph, triage, the investigation rail — asks the same five questions
// of an event, and before this package each answered them from whatever field
// names the vendor happened to use. The OCSF mapping gets an event's *shape*
// right; it does not say whether `actor.user.name` is a person, the OAuth app
// acting for them, or a long-lived token somebody minted two years ago.
//
// `actor.kind` is the field that separates those, and it is the one with the
// strictest rule in this package: it is derived from the vendor's own
// identity-type, token-type and client fields, and **never guessed**. A
// source that does not say stays `unknown`. An inferred `human` is worse than
// no answer, because every later surface — a privilege decision, a blast
// radius, an auto-close — would treat the guess as evidence.
//
// Each derivation below names the vendor field it reads and the documented
// vocabulary of that field. Where a vendor's enumeration has no member
// meaning "a person", the result is `unknown` rather than a default.
package activity

import "strings"

// ActorKind is the closed set the projection may report.
//
// The names come from depth plan 2.2 and are deliberately about *what is
// acting*, not about what it is allowed to do:
//
//	human            a person, interactively or through a client they drive
//	service_account  a non-human principal the directory manages as an account
//	oauth_app        a third-party application acting with delegated consent
//	api_token        a long-lived programmatic credential acting on its own
//	workload         compute acting as itself (a cloud service, a node, a pod)
//	ai_agent         an autonomous agent acting on a person's behalf
//	unknown          the source did not say, and this package does not guess
type ActorKind string

const (
	ActorHuman          ActorKind = "human"
	ActorServiceAccount ActorKind = "service_account"
	ActorOAuthApp       ActorKind = "oauth_app"
	ActorAPIToken       ActorKind = "api_token"
	ActorWorkload       ActorKind = "workload"
	ActorAIAgent        ActorKind = "ai_agent"
	ActorUnknown        ActorKind = "unknown"
)

// ActorKinds is the closed set, in the order the plan names them. The gate
// and the lake's enum read this rather than a second list.
var ActorKinds = []ActorKind{
	ActorHuman, ActorServiceAccount, ActorOAuthApp,
	ActorAPIToken, ActorWorkload, ActorAIAgent, ActorUnknown,
}

// Outcome is the result the source reported, normalized to three values.
//
// Three and not two: a source that does not report an outcome must be
// distinguishable from one that reported success, or a detection counting
// failures would read every silent source as a clean estate.
type Outcome string

const (
	OutcomeSuccess Outcome = "success"
	OutcomeFailure Outcome = "failure"
	OutcomeUnknown Outcome = "unknown"
)

// Actor is who acted and what kind of thing they are.
type Actor struct {
	// Kind is never guessed. See the package comment.
	Kind ActorKind `json:"kind"`
	// KindSource names the vendor field the kind was read from, so a
	// reviewer can check the derivation against the vendor's documentation
	// without re-reading this package. Empty when Kind is unknown.
	KindSource string `json:"kind_source,omitempty"`
	Name       string `json:"name,omitempty"`
	ID         string `json:"id,omitempty"`
	Email      string `json:"email,omitempty"`
	// OnBehalfOf is the human an agent, app or token is acting for, when
	// the source says. This is what makes `actor.kind` useful rather than
	// merely accurate: an OAuth app reading a mailbox is interesting
	// because of whose mailbox it is.
	OnBehalfOf string `json:"on_behalf_of,omitempty"`
}

// Resource is what was acted on.
type Resource struct {
	Type  string `json:"type,omitempty"`
	ID    string `json:"id,omitempty"`
	Name  string `json:"name,omitempty"`
	Owner string `json:"owner,omitempty"`
}

// Location is where the action came from.
//
// Geography, ASN and reputation are filled by the enrichment pass, which
// runs only for public addresses: a private address has no useful answer and
// sending one to a third party would leak the customer's internal topology.
type Location struct {
	IP          string `json:"ip,omitempty"`
	Country     string `json:"country,omitempty"`
	CountryCode string `json:"country_code,omitempty"`
	City        string `json:"city,omitempty"`
	ASN         int64  `json:"asn,omitempty"`
	ASOrg       string `json:"as_org,omitempty"`
	// Reputation is the enrichment service's 0-100 risk score, and
	// ReputationKnown says whether anything answered — a score of 0 from a
	// source that answered "clean" and a score of 0 from no answer at all
	// are different facts.
	Reputation      float64 `json:"reputation,omitempty"`
	ReputationKnown bool    `json:"reputation_known"`
	Device          string  `json:"device,omitempty"`
	// Client is the parsed user agent. The raw string is kept beside it
	// because every parser is a lossy summary of a string an attacker can
	// choose, and a hunt needs the original.
	Client Client `json:"client,omitempty"`
}

// Activity is the projection itself.
type Activity struct {
	Actor    Actor    `json:"actor"`
	Action   string   `json:"action,omitempty"`
	Resource Resource `json:"resource,omitempty"`
	Location Location `json:"location,omitempty"`
	Outcome  Outcome  `json:"outcome"`
}

// Project builds the projection for one normalized event.
//
// `payload` is the connector's own output — for a canonical envelope that is
// the envelope, with the vendor's record under `raw_event`. `ocsf` is the
// event this normalizer has already built, which is where the identity
// aliases have resolved a name, a host and a source IP that the vendor's
// record may spell four different ways.
//
// Reading both is deliberate. The vendor record is the only place the
// identity-type fields live, and the OCSF event is the only place the
// aliases have already done the cross-vendor work.
func Project(connectorType string, payload, ocsf map[string]any) Activity {
	vendor := vendorRecord(payload)

	act := Activity{
		Actor:    deriveActor(connectorType, payload, vendor, ocsf),
		Action:   deriveAction(connectorType, payload, vendor, ocsf),
		Resource: deriveResource(connectorType, payload, vendor, ocsf),
		Outcome:  deriveOutcome(payload, vendor, ocsf),
	}
	act.Location = deriveLocation(payload, vendor, ocsf)
	return act
}

// vendorRecord returns the vendor's own record from a canonical envelope, or
// the payload itself when there is no envelope.
//
// The key is `raw_event` and never `raw`: 26 connectors once emitted `raw`,
// missed the canonical-envelope check in the normalizer and fell through to a
// borrowed vendor profile. Reading only the one key here keeps this package
// from re-introducing that fork under a different name.
func vendorRecord(payload map[string]any) map[string]any {
	if nested, ok := payload["raw_event"].(map[string]any); ok {
		return nested
	}
	return payload
}

// nested walks a dotted path through maps and returns the leaf, or nil.
func nested(m map[string]any, path ...string) any {
	var cur any = m
	for _, key := range path {
		asMap, ok := cur.(map[string]any)
		if !ok {
			return nil
		}
		cur = asMap[key]
	}
	return cur
}

// str returns a trimmed non-empty string at a dotted path, or "".
func str(m map[string]any, path ...string) string {
	if s, ok := nested(m, path...).(string); ok {
		return strings.TrimSpace(s)
	}
	return ""
}

// firstStr returns the first non-empty value among several dotted paths, in
// declared order. Order is precedence; a map would randomise it.
func firstStr(m map[string]any, paths ...[]string) string {
	for _, path := range paths {
		if v := str(m, path...); v != "" {
			return v
		}
	}
	return ""
}
