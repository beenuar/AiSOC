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
        "changedPassword",
        "changedProfile",
        "dataExport",
        "deactivateUser",
        "frozeUser",
        "insertCertificate",
        "insertConnectedApplication",
        "loginPolicyChanged",
        "newUser",
        "suOrgAdminLogin",
        "updatedConnectedApplication",
    }
)

#: Box Enterprise Events `event_type` values.
BOX: frozenset[str] = frozenset(
    {
        "APPLICATION_PUBLIC_KEY_ADDED",
        "APPLICATION_PUBLIC_KEY_DELETED",
        "COLLABORATION_INVITE",
        "COLLABORATION_ROLE_CHANGE",
        "DELETE_USER",
        "FAILED_LOGIN",
        "GROUP_ADMIN_CREATED",
        "ITEM_DOWNLOAD",
        "ITEM_SHARED_LINK",
        "ITEM_SHARED_UPDATE",
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
        "file_download",
        "member_change_admin_role",
        "member_change_status",
        "shared_content_change_link_audience_to_public",
        "shared_content_download",
        "shared_content_remove_member",
        "shared_link_create",
        "sso_change_policy",
        "team_folder_change_status",
        "team_member_create_team_invite_link",
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
        "SetIamPolicy",
        "google.iam.admin.v1.CreateServiceAccount",
        "google.iam.admin.v1.CreateServiceAccountKey",
        "google.iam.admin.v1.DeleteRole",
        "google.iam.admin.v1.DeleteServiceAccount",
        "google.iam.admin.v1.DeleteServiceAccountKey",
        "google.iam.admin.v1.DisableServiceAccount",
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
    elif product == "gcp":
        method = match_when.get("method_name")
        if isinstance(method, str) and method not in GCP_METHODS:
            bad.append(method)
        for value in match_when.get("method_name_in", []) or []:
            if str(value) not in GCP_METHODS:
                bad.append(str(value))

    return bad
