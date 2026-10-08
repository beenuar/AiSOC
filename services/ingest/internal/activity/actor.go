package activity

import "strings"

// Actor-kind derivation, one source at a time.
//
// The rule for everything in this file: read a field whose *documented
// meaning* is the thing being asserted, and return `unknown` otherwise. Each
// function names the vendor reference it was written against. None of them
// infers a kind from a name, a domain, a severity or a pattern the vendor
// does not define — "svc-" in a username means nothing, and a repository that
// guesses from it will keep guessing wrong on the accounts that matter.
//
// References, each read before the derivation below was written:
//
//	AWS CloudTrail userIdentity.type
//	  https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-user-identity.html
//	Okta System Log actor.type
//	  https://developer.okta.com/docs/reference/api/system-log/
//	Microsoft 365 Management Activity API UserType
//	  https://learn.microsoft.com/en-us/office/office-365-management-api/office-365-management-activity-api-schema
//	Microsoft Entra audit initiatedBy
//	  https://learn.microsoft.com/en-us/graph/api/resources/audituserinfo
//	Google Workspace Reports API actor.callerType
//	  https://developers.google.com/workspace/admin/reports/reference/rest/v1/activities/list
//	GCP Cloud Audit authenticationInfo
//	  https://cloud.google.com/logging/docs/audit
//	GitHub audit log programmatic_access_type
//	  https://docs.github.com/en/organizations/keeping-your-organization-secure/managing-security-settings-for-your-organization/reviewing-the-audit-log-for-your-organization
//	Kubernetes audit user.username and user.groups
//	  https://kubernetes.io/docs/reference/access-authn-authz/service-accounts-admin/

// deriveActor fills the actor block. The kind comes from a per-source
// function; the name, id and email come from the OCSF event, where the
// normalizer's identity aliases have already reconciled the vendor's spelling.
func deriveActor(connectorType string, payload, vendor, ocsf map[string]any) Actor {
	kind, source := actorKind(connectorType, payload, vendor)
	return Actor{
		Kind:       kind,
		KindSource: source,
		Name:       str(ocsf, "actor", "user", "name"),
		ID:         str(ocsf, "actor", "user", "uid"),
		Email:      str(ocsf, "actor", "user", "email_addr"),
		OnBehalfOf: onBehalfOf(connectorType, payload, vendor),
	}
}

// actorKind returns the kind and the vendor field it was read from. An empty
// source string accompanies ActorUnknown and nothing else.
func actorKind(connectorType string, payload, vendor map[string]any) (ActorKind, string) {
	// The AI sources are first because they are the only ones that can
	// report ai_agent, and they say so in their own envelope rather than
	// in a vendor record.
	if kind, source := aiActorKind(payload, vendor); kind != ActorUnknown {
		return kind, source
	}

	switch connectorType {
	case "aws_cloudtrail":
		return cloudTrailActorKind(vendor)
	case "okta", "okta_system_log":
		return oktaActorKind(vendor)
	case "m365_audit":
		return m365ActorKind(vendor)
	case "azure_entra":
		return entraActorKind(vendor)
	case "google_workspace":
		return workspaceActorKind(vendor)
	case "gcp_cloud_audit":
		return gcpActorKind(vendor)
	case "github":
		return githubActorKind(vendor)
	case "kubernetes_audit":
		return kubernetesActorKind(vendor)
	}
	return ActorUnknown, ""
}

// aiActorKind reads the AI SDK's own envelope. `agent_id` is set by
// packages/aisoc-ai-sdk and by the ai-runtime webhook template, and it means
// exactly one thing: an autonomous agent made this call.
func aiActorKind(payload, vendor map[string]any) (ActorKind, string) {
	for _, m := range []map[string]any{payload, vendor} {
		if str(m, "agent_id") != "" {
			return ActorAIAgent, "agent_id"
		}
	}
	return ActorUnknown, ""
}

// cloudTrailActorKind reads `userIdentity.type`, whose documented members are
// Root, IAMUser, AssumedRole, Role, FederatedUser, Directory, AWSAccount,
// AWSService, IdentityCenterUser, SAMLUser, WebIdentityUser and Unknown.
//
// `IAMUser` and `AssumedRole` deliberately return unknown. AWS does not say
// whether an IAM user is a person, and in practice a great many are
// long-lived programmatic identities; an assumed role is whatever assumed it.
// Returning `human` for either would put a guess in the field whose whole
// purpose is to be ungessed.
//
// `invokedBy` is checked first and overrides the type: AWS sets it when
// another AWS service made the call, which is compute acting as itself
// whatever the principal's type says.
func cloudTrailActorKind(vendor map[string]any) (ActorKind, string) {
	identity, _ := nested(vendor, "userIdentity").(map[string]any)
	if identity == nil {
		return ActorUnknown, ""
	}
	if str(identity, "invokedBy") != "" {
		return ActorWorkload, "userIdentity.invokedBy"
	}
	switch str(identity, "type") {
	case "AWSService":
		return ActorWorkload, "userIdentity.type"
	case "Root", "IdentityCenterUser", "SAMLUser", "WebIdentityUser", "FederatedUser":
		return ActorHuman, "userIdentity.type"
	}
	return ActorUnknown, ""
}

// oktaActorKind reads `actor.type`. Okta's documented members include User,
// SystemPrincipal, PublicClientApp, AppInstance, AppUser and Client.
//
// AppUser is not mapped: Okta uses it for an application's representation of
// a user, which is a person's account inside an app rather than a statement
// about who acted.
func oktaActorKind(vendor map[string]any) (ActorKind, string) {
	switch str(vendor, "actor", "type") {
	case "User":
		return ActorHuman, "actor.type"
	case "SystemPrincipal":
		return ActorServiceAccount, "actor.type"
	case "PublicClientApp", "AppInstance", "Client":
		return ActorOAuthApp, "actor.type"
	}
	return ActorUnknown, ""
}

// m365ActorKind reads `UserType`, an integer enumeration: 0 Regular,
// 1 Reserved, 2 Admin, 3 DcAdmin, 4 System, 5 Application,
// 6 ServicePrincipal, 7 CustomPolicy, 8 SystemPolicy.
//
// 1, 7 and 8 are not mapped: Reserved has no documented meaning, and the two
// policy members describe a policy evaluation rather than a principal.
func m365ActorKind(vendor map[string]any) (ActorKind, string) {
	value, ok := intField(vendor, "UserType")
	if !ok {
		return ActorUnknown, ""
	}
	switch value {
	case 0, 2, 3:
		return ActorHuman, "UserType"
	case 4:
		return ActorWorkload, "UserType"
	case 5:
		return ActorOAuthApp, "UserType"
	case 6:
		return ActorServiceAccount, "UserType"
	}
	return ActorUnknown, ""
}

// entraActorKind reads `initiatedBy`, which Graph documents as carrying
// either a `user` object or an `app` object and never both for one event.
func entraActorKind(vendor map[string]any) (ActorKind, string) {
	initiated, _ := nested(vendor, "initiatedBy").(map[string]any)
	if initiated == nil {
		return ActorUnknown, ""
	}
	if app, ok := initiated["app"].(map[string]any); ok && len(app) > 0 {
		// A service principal acting with its own credentials is a service
		// account; one acting with delegated consent is an OAuth app. Graph
		// distinguishes them by whether a user is also named.
		if _, hasUser := initiated["user"].(map[string]any); hasUser {
			return ActorOAuthApp, "initiatedBy.app+user"
		}
		return ActorServiceAccount, "initiatedBy.app"
	}
	if user, ok := initiated["user"].(map[string]any); ok && len(user) > 0 {
		return ActorHuman, "initiatedBy.user"
	}
	return ActorUnknown, ""
}

// workspaceActorKind reads `actor.callerType`, documented as USER,
// APPLICATION, APPLICATION_OWNER or KEY. `KEY` is Google's own name for a
// request authenticated by a consumer key rather than a signed-in identity.
func workspaceActorKind(vendor map[string]any) (ActorKind, string) {
	switch str(vendor, "actor", "callerType") {
	case "USER":
		return ActorHuman, "actor.callerType"
	case "APPLICATION", "APPLICATION_OWNER":
		return ActorOAuthApp, "actor.callerType"
	case "KEY":
		return ActorAPIToken, "actor.callerType"
	}
	return ActorUnknown, ""
}

// gcpActorKind reads `authenticationInfo`. Two documented signals:
// `serviceAccountDelegationInfo` is present only when a service account was
// impersonated, and a principal in the `gserviceaccount.com` namespace is a
// service account by Google's own naming contract rather than by convention.
func gcpActorKind(vendor map[string]any) (ActorKind, string) {
	auth, _ := nested(vendor, "protoPayload", "authenticationInfo").(map[string]any)
	if auth == nil {
		auth, _ = nested(vendor, "authenticationInfo").(map[string]any)
	}
	if auth == nil {
		return ActorUnknown, ""
	}
	if delegation, ok := auth["serviceAccountDelegationInfo"].([]any); ok && len(delegation) > 0 {
		return ActorServiceAccount, "authenticationInfo.serviceAccountDelegationInfo"
	}
	if principal := str(auth, "principalEmail"); strings.HasSuffix(principal, ".gserviceaccount.com") {
		return ActorServiceAccount, "authenticationInfo.principalEmail"
	}
	return ActorUnknown, ""
}

// githubActorKind reads `programmatic_access_type`, which GitHub sets on
// audit entries produced through the API, and `actor_is_bot`.
//
// The absence of `programmatic_access_type` is not read as "a person": GitHub
// documents when the field appears, not that it appears on every API event,
// so treating silence as a web session would be exactly the guess this file
// refuses.
func githubActorKind(vendor map[string]any) (ActorKind, string) {
	if isBot, ok := vendor["actor_is_bot"].(bool); ok && isBot {
		return ActorWorkload, "actor_is_bot"
	}
	access := strings.ToLower(str(vendor, "programmatic_access_type"))
	switch {
	case access == "":
		return ActorUnknown, ""
	case strings.Contains(access, "personal access token"):
		return ActorAPIToken, "programmatic_access_type"
	case strings.Contains(access, "oauth"):
		return ActorOAuthApp, "programmatic_access_type"
	case strings.Contains(access, "github app"):
		return ActorOAuthApp, "programmatic_access_type"
	case strings.Contains(access, "ssh key") || strings.Contains(access, "deploy key"):
		return ActorAPIToken, "programmatic_access_type"
	}
	return ActorUnknown, ""
}

// kubernetesActorKind reads `user.username` and `user.groups`. Both prefixes
// are reserved by Kubernetes itself: `system:serviceaccount:<ns>:<name>` is
// the only username a service account can have, and `system:node:<name>` the
// only one a kubelet can.
func kubernetesActorKind(vendor map[string]any) (ActorKind, string) {
	username := str(vendor, "user", "username")
	switch {
	case strings.HasPrefix(username, "system:serviceaccount:"):
		return ActorServiceAccount, "user.username"
	case strings.HasPrefix(username, "system:node:"):
		return ActorWorkload, "user.username"
	}
	if groups, ok := nested(vendor, "user", "groups").([]any); ok {
		for _, group := range groups {
			if g, ok := group.(string); ok && g == "system:serviceaccounts" {
				return ActorServiceAccount, "user.groups"
			}
		}
	}
	return ActorUnknown, ""
}

// onBehalfOf is the human an agent, app or token is acting for, where the
// source names one. Only fields whose documented meaning is "the principal
// this call is attributed to" qualify.
func onBehalfOf(connectorType string, payload, vendor map[string]any) string {
	if v := firstStr(payload, []string{"on_behalf_of"}); v != "" {
		return v
	}
	if v := firstStr(vendor, []string{"on_behalf_of"}); v != "" {
		return v
	}
	switch connectorType {
	case "aws_cloudtrail":
		// sourceIdentity is set by AWS when the role was assumed with one,
		// and it is the documented way an assumed-role chain names the
		// originating principal.
		return firstStr(vendor,
			[]string{"userIdentity", "sourceIdentity"},
			[]string{"userIdentity", "sessionContext", "sessionIssuer", "userName"},
		)
	case "google_workspace":
		return str(vendor, "actor", "email")
	case "m365_audit":
		return str(vendor, "UserId")
	}
	return ""
}

// intField reads an integer that may have arrived as a float (JSON numbers
// decode to float64) or as a string.
func intField(m map[string]any, key string) (int, bool) {
	switch v := m[key].(type) {
	case int:
		return v, true
	case int64:
		return int(v), true
	case float64:
		return int(v), true
	}
	return 0, false
}
