package activity

import (
	"strings"
)

// Session identity, derived per event from the strongest key the source offers.
//
// What this file does and does not do
// -----------------------------------
// A session is a *stateful* object: it has a start, an end, a duration and a
// set of events. None of that can be decided while looking at one event, so
// none of it is decided here. This file answers the one question that is
// answerable per event and that no later stage can recover once the vendor
// record is gone: **which session does this event belong to, and how do we
// know**. Grouping, duration, idle expiry and the walk up an assumed-role
// chain are stateful and live in `services/fusion/app/services/sessions.py`.
//
// The key, not a guess
// --------------------
// Same rule as `actor.go`: read a field whose documented meaning is "the
// session (or the credential that is the session)" and report nothing
// otherwise. A session id invented from a user plus a timestamp would group
// events that have nothing to do with each other, and every surface that
// later says "what else did this session do" would be lying with a precise
// number.
//
// `KeyKind` is how strong the answer is, and it is carried to every consumer
// rather than flattened away:
//
//	vendor_session     the vendor names a session and this is its id
//	vendor_credential  the vendor names the credential, which *is* the session
//	                   (an AWS temporary access key, a GitHub token hash)
//	vendor_flow        the vendor groups one sign-in flow but not a durable
//	                   session, so events outside that flow will not join
//	derived            no vendor key: principal + address + client, which
//	                   fusion closes on an idle gap
//
// References, each read before the derivation below was written:
//
//	AWS CloudTrail userIdentity (accessKeyId, sessionContext, sourceIdentity)
//	  https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-user-identity.html
//	AWS STS AssumeRoleWithSAML / AssumeRoleWithWebIdentity response elements
//	  https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRoleWithSAML.html
//	  https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRoleWithWebIdentity.html
//	Okta System Log authenticationContext.externalSessionId
//	  https://developer.okta.com/docs/reference/api/system-log/
//	Office 365 Management Activity API common schema, AppAccessContext
//	  https://learn.microsoft.com/en-us/office/office-365-management-api/office-365-management-activity-api-schema
//	Microsoft Entra signIn resource (correlationId)
//	  https://learn.microsoft.com/en-us/graph/api/resources/signin
//	Google Workspace Reports API activities (token application parameters)
//	  https://developers.google.com/workspace/admin/reports/v1/appendix/activity/token
//	GitHub audit log hashed_token
//	  https://docs.github.com/en/organizations/keeping-your-organization-secure/managing-security-settings-for-your-organization/reviewing-the-audit-log-for-your-organization

// SessionKeyKind is the closed set describing how a session key was obtained.
type SessionKeyKind string

const (
	// SessionVendorSession — the vendor's own session identifier.
	SessionVendorSession SessionKeyKind = "vendor_session"
	// SessionVendorCredential — the credential is the session. An AWS
	// temporary access key exists for exactly one assumed-role session, so
	// it identifies that session as precisely as a session id would.
	SessionVendorCredential SessionKeyKind = "vendor_credential"
	// SessionVendorFlow — the vendor correlates one sign-in flow and
	// nothing wider. Grouping on it is correct for the events of that flow
	// and will not pick up what the resulting session went on to do.
	SessionVendorFlow SessionKeyKind = "vendor_flow"
	// SessionDerived — no vendor key at all. Fusion closes these on an
	// idle gap; they are the weakest and are labelled so a surface can say
	// so rather than presenting them as the vendor's own grouping.
	SessionDerived SessionKeyKind = "derived"
)

// SessionKeyKinds is the closed set in strength order, strongest first. The
// gate and the lake enum read this rather than a second list.
var SessionKeyKinds = []SessionKeyKind{
	SessionVendorSession, SessionVendorCredential, SessionVendorFlow, SessionDerived,
}

// IssuedSession is a session this event *created*, as opposed to the one it
// belongs to.
//
// Only credential-issuing calls populate it, and today that means AWS STS.
// It is what makes an assumed-role chain reconstructable: the AssumeRole call
// is logged against the *calling* session and carries the new session's
// access key in its response, so this is the only place the edge between the
// two exists. Without it a chained session's originating human is
// unrecoverable, because the second hop's own events name only the role.
type IssuedSession struct {
	Key       string `json:"key"`
	KeySource string `json:"key_source"`
	// Principal is the identity the new session acts as (the role ARN).
	Principal string `json:"principal,omitempty"`
	// OriginatingHuman is the person the new session is for, where the
	// issuing call named one. Empty is the honest answer when it did not.
	OriginatingHuman       string `json:"originating_human,omitempty"`
	OriginatingHumanSource string `json:"originating_human_source,omitempty"`
}

// Session is the per-event session projection.
type Session struct {
	// Key is the raw value as the vendor spells it, not a hash. Fusion
	// namespaces it by tenant and source when it mints a session id; keeping
	// the vendor's own value here is what lets an analyst paste it into the
	// vendor's console.
	Key     string         `json:"key,omitempty"`
	KeyKind SessionKeyKind `json:"key_kind,omitempty"`
	// KeySource names the vendor field the key was read from, so a reviewer
	// can check the derivation against the vendor's documentation without
	// re-reading this package.
	KeySource string `json:"key_source,omitempty"`
	// Principal is the identity the session acts as.
	Principal string `json:"principal,omitempty"`
	// OriginatingHuman is the person behind the session when *this event*
	// names one. A chained session names nobody on its own events; fusion
	// resolves those by walking Issued edges.
	OriginatingHuman       string `json:"originating_human,omitempty"`
	OriginatingHumanSource string `json:"originating_human_source,omitempty"`
	// Issued is set only on a credential-issuing call. See IssuedSession.
	Issued *IssuedSession `json:"issued,omitempty"`
}

// deriveSession fills the session block for one event.
func deriveSession(connectorType string, payload, vendor map[string]any, act *Activity) Session {
	var s Session
	switch connectorType {
	case "aws_cloudtrail", "aws_cloudtrail_s3":
		s = cloudTrailSession(vendor)
	case "okta", "okta_system_log":
		s = oktaSession(vendor)
	case "m365_audit":
		s = m365Session(vendor)
	case "azure_entra":
		s = entraSession(vendor)
	case "google_workspace":
		s = workspaceSession(vendor)
	case "github":
		s = githubSession(vendor)
	}

	if s.Principal == "" {
		s.Principal = firstNonEmpty(act.Actor.ID, act.Actor.Email, act.Actor.Name)
	}
	if s.OriginatingHuman == "" && act.Actor.OnBehalfOf != "" {
		s.OriginatingHuman = act.Actor.OnBehalfOf
		s.OriginatingHumanSource = "activity.actor.on_behalf_of"
	}
	// An actor the source called a person is their own originating human.
	// Stated rather than left empty so a human session and an unattributed
	// one are different rows rather than both being blank.
	if s.OriginatingHuman == "" && act.Actor.Kind == ActorHuman && s.Principal != "" {
		s.OriginatingHuman = s.Principal
		s.OriginatingHumanSource = "activity.actor.kind=human"
	}

	if s.Key == "" {
		s.Key, s.KeySource = derivedSessionKey(s.Principal, act)
		if s.Key != "" {
			s.KeyKind = SessionDerived
		}
	}
	return s
}

// cloudTrailSession reads the temporary access key, which identifies exactly
// one assumed-role session, and the STS response elements that name the
// session this call issued.
//
// A long-lived IAM user key (AKIA…) is also returned: it is still the
// credential the request was signed with, and grouping an IAM user's calls by
// the key they used is the question an analyst asks after a key leaks. What
// it is *not* is a login session, which is why the kind is `vendor_credential`
// and not `vendor_session`.
// The issued session is read *before* the caller's own identity and
// independently of it. The federated AssumeRole calls — `AssumeRoleWithSAML`
// and `AssumeRoleWithWebIdentity` — carry no `userIdentity` at all, because
// the caller is not yet an AWS principal when they make the request. An early
// return on a missing identity therefore drops the chain edge on exactly the
// two calls where the person is named and nowhere else, leaving every
// subsequent event of that session attributable only to a role.
func cloudTrailSession(vendor map[string]any) Session {
	var s Session
	if issued := cloudTrailIssued(vendor); issued != nil {
		s.Issued = issued
	}

	identity, _ := nested(vendor, "userIdentity").(map[string]any)
	if identity == nil {
		return s
	}
	s.Principal = firstStr(identity, []string{"arn"}, []string{"principalId"})
	if key := str(identity, "accessKeyId"); key != "" {
		s.Key, s.KeyKind, s.KeySource = key, SessionVendorCredential, "userIdentity.accessKeyId"
	}

	// sourceIdentity is AWS's documented mechanism for carrying the
	// originating principal across a role assumption, and it is the only
	// CloudTrail field that means that. It is set on the identity itself and,
	// on some event versions, inside sessionContext.
	if who := firstStr(identity,
		[]string{"sourceIdentity"},
		[]string{"sessionContext", "sourceIdentity"},
	); who != "" {
		s.OriginatingHuman = who
		s.OriginatingHumanSource = "userIdentity.sourceIdentity"
	}
	return s
}

// cloudTrailIssued reads the session an STS call created.
//
// The `credentials.accessKeyId` under responseElements is the new session's
// key. The originating human comes from whichever of the three documented
// federation shapes the call used, and from `sourceIdentity` when the caller
// set one — never from the role name, which names the role and not a person.
func cloudTrailIssued(vendor map[string]any) *IssuedSession {
	eventName := str(vendor, "eventName")
	if !strings.HasPrefix(eventName, "AssumeRole") && eventName != "GetFederationToken" && eventName != "GetSessionToken" {
		return nil
	}
	resp, _ := nested(vendor, "responseElements").(map[string]any)
	if resp == nil {
		return nil
	}
	key := firstStr(resp,
		[]string{"credentials", "accessKeyId"},
		[]string{"Credentials", "AccessKeyId"},
	)
	if key == "" {
		return nil
	}
	issued := &IssuedSession{
		Key:       key,
		KeySource: "responseElements.credentials.accessKeyId",
		Principal: firstStr(resp,
			[]string{"assumedRoleUser", "arn"},
			[]string{"federatedUser", "arn"},
		),
	}

	req, _ := nested(vendor, "requestParameters").(map[string]any)
	if req == nil {
		req = map[string]any{}
	}
	switch {
	case str(req, "sourceIdentity") != "":
		// Explicitly set by the caller and carried by AWS on every
		// subsequent event of the new session.
		issued.OriginatingHuman = str(req, "sourceIdentity")
		issued.OriginatingHumanSource = "requestParameters.sourceIdentity"
	case str(resp, "subject") != "":
		// AssumeRoleWithSAML: the SAML NameID, which is the person the
		// identity provider authenticated.
		issued.OriginatingHuman = str(resp, "subject")
		issued.OriginatingHumanSource = "responseElements.subject"
	case str(resp, "subjectFromWebIdentityToken") != "":
		issued.OriginatingHuman = str(resp, "subjectFromWebIdentityToken")
		issued.OriginatingHumanSource = "responseElements.subjectFromWebIdentityToken"
	case str(req, "roleSessionName") != "":
		// Weakest of the four and labelled as what it is. The session name
		// is caller-chosen free text; in an IAM Identity Center estate it is
		// reliably the signed-in user's name, and elsewhere it can be
		// anything. Carried because an analyst reading it knows which it is,
		// and dropped into its own source string so nothing downstream can
		// mistake it for an authenticated identity.
		issued.OriginatingHuman = str(req, "roleSessionName")
		issued.OriginatingHumanSource = "requestParameters.roleSessionName"
	}
	return issued
}

// oktaSession reads `authenticationContext.externalSessionId`.
//
// Okta writes the literal string "unknown" on events with no session rather
// than omitting the field, so that value is treated as absent. Reading it as
// a key would collapse every session-less event in the tenant into one
// enormous session called "unknown".
func oktaSession(vendor map[string]any) Session {
	s := Session{Principal: firstStr(vendor,
		[]string{"actor", "alternateId"},
		[]string{"actor", "id"},
	)}
	id := str(vendor, "authenticationContext", "externalSessionId")
	if id != "" && id != "unknown" {
		s.Key, s.KeyKind, s.KeySource = id, SessionVendorSession, "authenticationContext.externalSessionId"
	}
	return s
}

// m365Session reads `AppAccessContext.AADSessionId`, the Entra session the
// token was issued for, and falls back to a record-level `SessionId` on the
// schemas that carry one.
func m365Session(vendor map[string]any) Session {
	s := Session{Principal: str(vendor, "UserId")}
	if id := str(vendor, "AppAccessContext", "AADSessionId"); id != "" {
		s.Key, s.KeyKind, s.KeySource = id, SessionVendorSession, "AppAccessContext.AADSessionId"
		return s
	}
	if id := str(vendor, "SessionId"); id != "" {
		s.Key, s.KeyKind, s.KeySource = id, SessionVendorSession, "SessionId"
	}
	return s
}

// entraSession reads `correlationId`.
//
// This is deliberately `vendor_flow` and not `vendor_session`. Microsoft
// documents correlationId as the identifier sent by the client when a sign-in
// is initiated; it groups the operations of one sign-in flow and says nothing
// about the session that flow produced. The v1.0 signIn resource exposes no
// session identifier at all, so there is no stronger field to read, and
// labelling this as a session would promise a grouping Entra does not give.
// M365 audit records *do* carry the Entra session id (AADSessionId above),
// which is where a durable Entra session is reconstructable from.
func entraSession(vendor map[string]any) Session {
	s := Session{Principal: firstStr(vendor,
		[]string{"userPrincipalName"},
		[]string{"initiatedBy", "user", "userPrincipalName"},
		[]string{"userId"},
	)}
	if id := str(vendor, "correlationId"); id != "" {
		s.Key, s.KeyKind, s.KeySource = id, SessionVendorFlow, "correlationId"
	}
	return s
}

// workspaceSession reads the OAuth client id from a token-application
// activity.
//
// The Reports API publishes no session identifier on any application. What it
// does publish, on the `token` application, is the `client_id` of the
// application acting — which is the "token id" half of the plan's wording and
// the thing worth grouping on, because an OAuth app's reads are one campaign
// whoever authorised them. Everything else on Workspace falls to the derived
// key, which is the honest answer rather than a fabricated one.
func workspaceSession(vendor map[string]any) Session {
	s := Session{Principal: str(vendor, "actor", "email")}
	if id := workspaceParam(vendor, "client_id"); id != "" {
		s.Key, s.KeyKind, s.KeySource = id, SessionVendorCredential, "events[].parameters[client_id]"
	}
	return s
}

// workspaceParam reads a named parameter out of the Reports API's
// `events[].parameters[]` list of `{name, value}` objects.
func workspaceParam(vendor map[string]any, name string) string {
	events, ok := nested(vendor, "events").([]any)
	if !ok {
		return ""
	}
	for _, raw := range events {
		event, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		params, ok := event["parameters"].([]any)
		if !ok {
			continue
		}
		for _, rawParam := range params {
			param, ok := rawParam.(map[string]any)
			if !ok {
				continue
			}
			if str(param, "name") == name {
				if v := str(param, "value"); v != "" {
					return v
				}
			}
		}
	}
	return ""
}

// githubSession reads `hashed_token`, the SHA-256 of the credential the call
// was made with. GitHub audit entries carry no session identifier; the token
// hash is the credential and groups one token's activity, which is the
// question asked after a token leaks.
func githubSession(vendor map[string]any) Session {
	s := Session{Principal: str(vendor, "actor")}
	if id := str(vendor, "hashed_token"); id != "" {
		s.Key, s.KeyKind, s.KeySource = id, SessionVendorCredential, "hashed_token"
	}
	return s
}

// derivedSessionKey is the fallback the plan names: principal plus address
// plus client, which fusion then closes on an idle gap.
//
// All three parts are required. Two events share a derived session only when
// the same principal acted from the same address with the same client, which
// is the weakest grouping that is still a grouping — principal plus address
// alone would merge a browser session and a CLI run from one office, and
// address alone would merge every user behind one NAT gateway into a single
// session.
func derivedSessionKey(principal string, act *Activity) (string, string) {
	ip := act.Location.IP
	client := act.Location.Client.Raw
	if principal == "" || ip == "" || client == "" {
		return "", ""
	}
	return strings.Join([]string{principal, ip, client}, "|"), "principal+ip+user_agent"
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v = strings.TrimSpace(v); v != "" {
			return v
		}
	}
	return ""
}
