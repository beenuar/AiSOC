"""Transcribed vendor event vocabularies, so a rule cannot name a non-event.

Three of the twelve GitHub rules issue #1545 examined clausing on actions
GitHub has never logged — ``deploy_key.create`` (the real entry is
``public_key.create``), ``repo.visibility_change`` (the real one is
``repo.access``) and ``runner_register``. Nothing caught them. A field
reachability gate cannot: the *field* exists and carries a string. Fixture
replay cannot: the fixture is synthesised from the rule, so it carries the
invented value too and the rule matches itself.

What catches it is a list of what the vendor actually publishes. This module
is that list, transcribed per product, and
`scripts/check_scenario_family_alignment.py` fails a rule naming anything
outside it.

Two deliberate properties:

* **Each entry is a prefix-stripped bare name.** Connectors prefix the event
  into `event_type` (``slack.app_installed``, ``workspace.login.2sv_disable``),
  and a rule clauses on the prefixed form. `unknown_names` strips the prefix
  this product's connector adds before comparing, so the vocabulary stays the
  vendor's list rather than a copy of our naming convention.
* **A product with no vocabulary is not silently allowed.** `unknown_names`
  returns nothing for it, and the alignment gate's own coverage listing is
  what makes that visible — an unknown bucket that passes quietly is the
  defect this repository keeps finding, so the gap is printed rather than
  assumed clean.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

#: Google Workspace Reports API activity names, by application. Transcribed
#: from the Admin SDK activity reference. Keys are the `applicationName`
#: values the connector puts between `workspace.` and the event name.
GOOGLE_WORKSPACE: dict[str, frozenset[str]] = {
    "login": frozenset(
        {
            "2sv_disable",
            "2sv_enroll",
            "account_disabled_generic",
            "account_disabled_password_leak",
            "account_disabled_spamming",
            "gov_attack_warning",
            "login_challenge",
            "login_failure",
            "login_success",
            "login_verification",
            "logout",
            "password_edit",
            "recovery_email_edit",
            "recovery_phone_edit",
            "suspicious_login",
            "suspicious_login_less_secure_app",
            "suspicious_programmatic_login",
        }
    ),
    "admin": frozenset(
        {
            "allow_strong_authentication",
            "assign_role",
            "change_email_setting",
            "change_password",
            "create_email_monitor",
            "create_role",
            "create_user",
            "delegate_admin_privileges",
            "delete_role",
            "delete_user",
            "enforce_strong_authentication",
            "grant_admin_privilege",
            "reset_password",
            "revoke_admin_privilege",
            "suspend_user",
            "unenroll_user_from_strong_auth",
            "unsuspend_user",
        }
    ),
    "drive": frozenset(
        {
            "change_acl_editors",
            "change_document_access_scope",
            "change_document_visibility",
            "change_user_access",
            "create",
            "create_link_sharing",
            "delete",
            "download",
            "edit",
            "shared_drive_settings_change",
            "view",
        }
    ),
    "token": frozenset({"activity", "authorize", "request", "revoke"}),
    "mobile": frozenset({"device_compromised_event", "failed_password_attempts_event"}),
}

#: Slack Audit Logs API actions. Transcribed from Slack's audit-log action
#: reference; only the actions AiSOC writes rules against are listed, which
#: is the point — adding a rule means adding its action here deliberately.
SLACK: frozenset[str] = frozenset(
    {
        "app_installed",
        "app_scopes_expanded",
        "app_token_rotated",
        "app_uninstalled",
        "channel_converted_to_private",
        "external_shared_channel_connected",
        "file_downloaded",
        "guest_created",
        "organization_export_started",
        "pref.allow_message_deletion",
        "pref.sso_setting_changed",
        "pref.two_factor_auth_changed",
        "role_change_to_admin",
        "role_change_to_owner",
        "user_channel_join",
        "user_login",
        "user_session_invalidation_disabled",
        "user_session_reset_by_admin",
        "workspace_public_url_updated",
    }
)

#: Salesforce SetupAuditTrail actions.
SALESFORCE: frozenset[str] = frozenset(
    {
        "PermSetAssign",
        "PermSetCreate",
        "PermSetGroupCreate",
        "changedInterfaceUrl",
        "changedPassword",
        "changedProfile",
        "createdPolicy",
        "dataExport",
        "deactivateUser",
        "frozeUser",
        "insertCertificate",
        "insertConnectedApplication",
        "loginAsGrantedToPartnerBT",
        "loginPolicyChanged",
        "newUser",
        "suOrgAdminLogin",
        "updatedConnectedApplication",
        "updatedPolicy",
    }
)

#: Box Enterprise Events `event_type` values.
BOX: frozenset[str] = frozenset(
    {
        "APPLICATION_PUBLIC_KEY_ADDED",
        "APPLICATION_PUBLIC_KEY_DELETED",
        "COLLABORATION_INVITE",
        "COLLABORATION_ROLE_CHANGE",
        "DATA_RETENTION_REMOVE_RETENTION",
        "DELETE",
        "DELETE_USER",
        "DISABLE_TWO_FACTOR_AUTH",
        "FAILED_LOGIN",
        "GROUP_ADMIN_CREATED",
        "ITEM_DOWNLOAD",
        "ITEM_SHARED_LINK",
        "ITEM_SHARED_UPDATE",
        "LEGAL_HOLD_ASSIGNMENT_DELETE",
        "OAUTH2_ACCESS_TOKEN_REVOKE",
        "ROLE_CHANGE_TO_ADMIN",
        "SHARE",
        "SHIELD_ALERT",
        "SHIELD_EXTERNAL_COLLAB_INVITE_ABNORMAL_LOCATION",
        "SHIELD_EXTERNAL_COLLAB_INVITE_BLOCKED",
        "USER_LOGIN",
    }
)

#: Dropbox Business team-log `event_type` tags.
DROPBOX: frozenset[str] = frozenset(
    {
        "account_external_password_unmask",
        "app_link_team",
        "device_link_success",
        "device_unlink",
        "file_download",
        "group_add_member",
        "group_create",
        "member_change_admin_role",
        "member_change_email",
        "member_change_status",
        "paper_external_view_allow",
        "shared_content_change_link_audience_to_public",
        "shared_content_download",
        "shared_content_remove_member",
        "shared_link_create",
        "sign_in_as_session_start",
        "sso_change_policy",
        "team_folder_change_status",
        "team_member_create_team_invite_link",
        "tfa_change_policy",
    }
)

#: 1Password sign-in attempt categories.
ONEPASSWORD: frozenset[str] = frozenset(
    {
        "signin.credentials_failed",
        "signin.firewall_failed",
        "signin.firewall_reported_success",
        "signin.mfa_failed",
        "signin.modern_version_failed",
        "signin.success",
    }
)

#: Snowflake ACCOUNT_USAGE streams the connector emits, plus the QUERY_TYPE
#: values a rule may name. `query.<type lowercased>` is the connector's form.
SNOWFLAKE: frozenset[str] = frozenset(
    {
        "login",
        "query.create_user",
        "query.delete",
        "query.grant",
        "query.insert",
        "query.revoke",
        "query.select",
        "query.unload",
    }
)

#: GCP Cloud Audit method names are matched on `method_name` rather than on
#: `event_type`, so they are checked under their own key below.
GCP_METHODS: frozenset[str] = frozenset(
    {
        "CreateProject",
        "DeleteProject",
        "MoveProject",
        "SetIamPolicy",
        "UndeleteProject",
        "UpdateProject",
        "dns.changes.create",
        "dns.managedZones.create",
        "google.api.serviceusage.v1.ServiceUsage.DisableService",
        "google.api.serviceusage.v1.ServiceUsage.EnableService",
        "google.cloud.bigquery.v2.DatasetService.UpdateDataset",
        "google.cloud.bigquery.v2.JobService.InsertJob",
        "google.cloud.bigquery.v2.TableService.DeleteTable",
        "google.cloud.bigquery.v2.TableService.InsertTable",
        "google.cloud.functions.v1.CloudFunctionsService.CreateFunction",
        "google.cloud.functions.v1.CloudFunctionsService.SetIamPolicy",
        "google.cloud.functions.v1.CloudFunctionsService.UpdateFunction",
        "google.cloud.iap.v1.IdentityAwareProxyAdminService.SetIamPolicy",
        "google.cloud.iap.v1.IdentityAwareProxyAdminService.UpdateIapSettings",
        "google.cloud.kms.v1.KeyManagementService.CreateCryptoKey",
        "google.cloud.kms.v1.KeyManagementService.DestroyCryptoKeyVersion",
        "google.cloud.kms.v1.KeyManagementService.SetIamPolicy",
        "google.cloud.kms.v1.KeyManagementService.UpdateCryptoKeyPrimaryVersion",
        "google.cloud.orgpolicy.v2.OrgPolicy.DeletePolicy",
        "google.cloud.orgpolicy.v2.OrgPolicy.UpdatePolicy",
        "google.cloud.run.v1.Services.ReplaceService",
        "google.cloud.run.v1.Services.SetIamPolicy",
        "google.cloud.secretmanager.v1.SecretManagerService.AccessSecretVersion",
        "google.cloud.secretmanager.v1.SecretManagerService.AddSecretVersion",
        "google.cloud.secretmanager.v1.SecretManagerService.CreateSecret",
        "google.cloud.secretmanager.v1.SecretManagerService.DeleteSecret",
        "google.cloud.secretmanager.v1.SecretManagerService.SetIamPolicy",
        "google.cloud.securitycenter.v1.SecurityCenter.DeleteNotificationConfig",
        "google.cloud.securitycenter.v1.SecurityCenter.UpdateSource",
        "google.container.v1.ClusterManager.CreateCluster",
        "google.container.v1.ClusterManager.DeleteCluster",
        "google.container.v1.ClusterManager.SetMasterAuth",
        "google.container.v1.ClusterManager.SetNodePoolManagement",
        "google.container.v1.ClusterManager.UpdateCluster",
        "google.iam.admin.v1.CreateRole",
        "google.iam.admin.v1.CreateServiceAccount",
        "google.iam.admin.v1.CreateServiceAccountKey",
        "google.iam.admin.v1.DeleteRole",
        "google.iam.admin.v1.DeleteServiceAccount",
        "google.iam.admin.v1.DeleteServiceAccountKey",
        "google.iam.admin.v1.DisableServiceAccount",
        "google.iam.admin.v1.EnableServiceAccount",
        "google.iam.admin.v1.UndeleteRole",
        "google.iam.admin.v1.UpdateRole",
        "google.iam.admin.v1.UpdateServiceAccount",
        "google.iam.v1.WorkloadIdentityPools.CreateWorkloadIdentityPool",
        "google.iam.v1.WorkloadIdentityPools.CreateWorkloadIdentityPoolProvider",
        "google.logging.v2.ConfigServiceV2.CreateExclusion",
        "google.logging.v2.ConfigServiceV2.CreateSink",
        "google.logging.v2.ConfigServiceV2.DeleteSink",
        "google.logging.v2.ConfigServiceV2.UpdateSink",
        "google.logging.v2.LoggingServiceV2.DeleteLog",
        "google.pubsub.v1.Publisher.CreateTopic",
        "google.pubsub.v1.Subscriber.CreateSubscription",
        "storage.buckets.create",
        "storage.buckets.delete",
        "storage.buckets.update",
        "storage.hmacKeys.create",
        "storage.objects.delete",
        "storage.setIamPermissions",
        "v1.compute.disks.createSnapshot",
        "v1.compute.firewalls.delete",
        "v1.compute.firewalls.insert",
        "v1.compute.firewalls.patch",
        "v1.compute.images.insert",
        "v1.compute.instances.addAccessConfig",
        "v1.compute.instances.delete",
        "v1.compute.instances.getSerialPortOutput",
        "v1.compute.instances.insert",
        "v1.compute.instances.setIamPolicy",
        "v1.compute.instances.setMetadata",
        "v1.compute.instances.setServiceAccount",
        "v1.compute.networks.insert",
        "v1.compute.projects.setCommonInstanceMetadata",
        "v1.compute.routes.insert",
        "v1.compute.subnetworks.patch",
        "v1.compute.vpnTunnels.insert",
    }
)


#: Okta System Log event types.
OKTA: frozenset[str] = frozenset(
    {
        "application.user_membership.add",
        "group.privilege.grant",
        "policy.lifecycle.update",
        "policy.rule.deactivate",
        "security.threat.detected",
        "system.api_token.create",
        "system.api_token.revoke",
        "user.lifecycle.suspend",
        "user.lifecycle.unsuspend",
        "user.mfa.factor.deactivate",
        "user.mfa.factor.reset_all",
        "user.session.impersonation.grant",
        "user.session.impersonation.initiate",
        "zone.update",
    }
)

#: GitHub organisation audit-log actions, from GitHub's audit-log event
#: reference. This is the list that refuses `deploy_key.create`: GitHub
#: logs a deploy-key add as `public_key.create`, and a visibility flip as
#: `repo.access` rather than `repo.visibility_change`.
GITHUB: frozenset[str] = frozenset(
    {
        "environment.create",
        "hook.config_changed",
        "hook.create",
        "ip_allow_list_entry.create",
        "oauth_application.create",
        "org.add_member",
        "org.audit_log_export",
        "org.create_actions_secret",
        "org.disable_ip_allow_list",
        "org.disable_oauth_app_restrictions",
        "org.disable_saml",
        "org.disable_two_factor_requirement",
        "org.invite_member",
        "org.register_self_hosted_runner",
        "org.remove_actions_secret",
        "org.remove_member",
        "org.remove_self_hosted_runner",
        "org.update_default_repository_permission",
        "org.update_member",
        "personal_access_token.access_granted",
        "personal_access_token.request_created",
        "protected_branch.destroy",
        "protected_branch.dismiss_stale_reviews",
        "protected_branch.policy_override",
        "public_key.create",
        "repo.access",
        "repo.archived",
        "repo.create",
        "repo.destroy",
        "repo.transfer",
    }
)


#: AWS CloudTrail event names. Only the ones the second authoring pass added
#: are listed: the older AWS rules predate this module and are covered by
#: the fireability replay rather than by a vocabulary arm, which is stated
#: here rather than left for a reader to infer from an absence.
AWS_EVENTS: frozenset[str] = frozenset(
    {
        "AddUserToGroup",
        "AssumeRoleWithSAML",
        "CreateResource",
        "DeleteDetector",
        "DetachPolicy",
        "GetSecretValue",
        "RemoveAccountFromOrganization",
        "SharedSnapshotCopyInitiated",
        "StopConfigurationRecorder",
        "UpdateLoginProfile",
    }
)


def _workspace_known(value: str) -> bool:
    """`workspace.<application>.<event>` against the per-application list."""
    parts = value.split(".", 2)
    if len(parts) != 3 or parts[0] != "workspace":
        return False
    vocabulary = GOOGLE_WORKSPACE.get(parts[1])
    # An application AiSOC does not poll is out of scope rather than wrong;
    # the connector's `_DEFAULT_APPS` decides what arrives at all.
    return vocabulary is None or parts[2] in vocabulary


#: product -> (prefix the connector adds, vocabulary, which clause key holds it)
_SIMPLE: dict[str, tuple[str, frozenset[str]]] = {
    "slack": ("slack.", SLACK),
    "salesforce": ("salesforce.", SALESFORCE),
    "box": ("box.", BOX),
    "dropbox": ("dropbox.", DROPBOX),
    "onepassword": ("onepassword.", ONEPASSWORD),
    "snowflake": ("snowflake.", SNOWFLAKE),
    "okta": ("", OKTA),
    "github": ("github.", GITHUB),
}


def _event_type_literals(match_when: dict[str, Any]) -> list[str]:
    """Every literal a clause compares `event_type` against."""
    out: list[str] = []
    for key, value in match_when.items():
        if key == "event_type" and isinstance(value, str):
            out.append(value)
        elif key == "event_type_in" and isinstance(value, Iterable) and not isinstance(value, str):
            out.extend(str(v) for v in value)
    return out


def unknown_names(product: str, match_when: dict[str, Any]) -> list[str]:
    """Event or method names in `match_when` the vendor does not publish.

    Empty for a product with no transcribed vocabulary. The alignment gate's
    `--list` is what surfaces those, rather than this returning a value that
    would read as "checked and clean".
    """
    bad: list[str] = []

    if product == "google-workspace":
        bad.extend(v for v in _event_type_literals(match_when) if not _workspace_known(v))
    elif product in _SIMPLE:
        prefix, vocabulary = _SIMPLE[product]
        for value in _event_type_literals(match_when):
            if not value.startswith(prefix) or value[len(prefix) :] not in vocabulary:
                bad.append(value)
    elif product == "aws":
        name = match_when.get("event_name")
        # Only the scenario-family specs reach this function, and the AWS
        # ones among them are exactly the second-pass rules listed above.
        # The older AWS corpus predates this module and is covered by the
        # fireability replay instead; an empty-set check here would have
        # been a no-op dressed as a gate.
        if isinstance(name, str) and name not in AWS_EVENTS:
            bad.append(name)
    elif product == "gcp":
        method = match_when.get("method_name")
        if isinstance(method, str) and method not in GCP_METHODS:
            bad.append(method)
        for value in match_when.get("method_name_in", []) or []:
            if str(value) not in GCP_METHODS:
                bad.append(str(value))

    return bad
