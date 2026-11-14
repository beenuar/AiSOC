"""Depth 2 wave 2, item 2.1 — named scenario families for SaaS and cloud.

Every spec here clauses on a field that reaches the engine namespace through
a real connector. That is not a style note: the engine flattens ``raw_event``
exactly one level, so a value the vendor nests deeper is invisible, and a rule
naming it reads ``None`` and can never fire while still counting toward the
published executable total. Seven connectors were changed to lift the fields
these rules read (`scripts/check_connector_field_lift.py` holds them), and
`scripts/check_scenario_family_alignment.py` replays a real-shaped vendor
payload through the real connector and the real engine for every rule below
and fails unless the rule fires.

Families are declared, not derived. `F()` stamps the family onto the spec,
`scripts/export_detection_ruleset.py` carries it into the artefact the engine
loads, and `scripts/project_stats.py` counts by it — so the console, the gate
and the documentation read one string rather than three guesses from a slug.

Authoring rules
---------------
*   Clause only on names in the engine namespace for that product. Run
    `scripts/check_connector_field_lift.py`; do not assume a field is
    visible because the vendor sends it.
*   Use the vendor's own vocabulary for event and action names.
    `scripts/vendor_event_vocabulary.py` transcribes each vendor's list and
    the alignment gate refuses a name that is not in it — the defect that
    shipped ``deploy_key.create``, which GitHub has never logged.
*   A rule that needs a *sequence* ("recovery changed, then the password")
    does not belong here. The windowed engine counts and does not order, and
    24 rules were already refused on that ground rather than shipped as
    weaker rules under a stronger name. Ordered pairs go to the weak-signal
    aggregator (item 2.3), which is built for exactly that shape.
"""

from __future__ import annotations

from typing import Any

from detection_specs_part3_helpers import (  # type: ignore[import-not-found]
    FP_AUTOMATION,
    FP_BREAK_GLASS,
    FP_ONBOARD,
    FP_PENTEST,
    FP_TUNING,
    S,
)

#: Anonymizing and hosting network classes stamped at ingest by item 1.6.
#: Re-authenticating from one of these is the shared shape across the
#: Workspace, code-platform and third-party families, so it is named once.
ANONYMIZER_CLASSES = ["vpn", "tor_exit", "public_proxy", "hosting_provider"]

#: Google OAuth scopes that read a mailbox or a drive. A consent grant
#: carrying one of these is the business-email-compromise vector; the same
#: grant without them is an ordinary sign-in-with-Google.
GWS_SENSITIVE_SCOPES = [
    "https://www.googleapis.com/auth/gmail.readonly",
    "https://www.googleapis.com/auth/gmail.modify",
    "https://mail.google.com/",
    "https://www.googleapis.com/auth/drive",
    "https://www.googleapis.com/auth/drive.readonly",
]


def F(*, family: str, category: str, **kwargs: Any) -> dict[str, Any]:
    """`S()` with the scenario family and its target category recorded.

    `category` decides which `detections/<category>/` directory the rule is
    generated into and which bucket `detection_specs_index` puts it in. It is
    declared per rule rather than per family because a family spans them: a
    Workspace takeover is an identity event when it changes a factor and a
    data-movement event when it opens a drive to the public.
    """
    spec = S(**kwargs)
    spec["family"] = family
    spec["_category"] = category
    return spec


def by_category(*groups: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    """Partition specs onto their declared category, dropping the marker."""
    out: dict[str, list[dict[str, Any]]] = {}
    for group in groups:
        for spec in group:
            out.setdefault(spec.pop("_category"), []).append(spec)
    return out


# ===========================================================================
# Family: workspace-takeover
#
# Google Workspace account takeover and the persistence installed once the
# session is held. Names are Reports API activity names; the connector
# lowercases them into `event_type` as `workspace.<application>.<event>` and
# lifts each `events[].parameters` entry as `param_<name>`.
# ===========================================================================
WORKSPACE_TAKEOVER: list[dict] = [
    F(
        family="workspace-takeover",
        category="identity",
        slug="gws-recovery-email-edited",
        name="Workspace Recovery Email Changed By The Account Holder",
        severity="high",
        mitre=["t1098.005", "t1556"],
        product="google-workspace",
        service="login",
        when={"event_type": "workspace.login.recovery_email_edit"},
        fp=["Staff member correcting their own recovery address", FP_ONBOARD],
        playbook="tpl-account-takeover",
        description=(
            "The recovery address moved from the user's own session. Taken before a password reset it makes the reset survive the owner "
            "noticing."
        ),
    ),
    F(
        family="workspace-takeover",
        category="identity",
        slug="gws-recovery-phone-edited",
        name="Workspace Recovery Phone Changed By The Account Holder",
        severity="high",
        mitre=["t1098.005", "t1556"],
        product="google-workspace",
        service="login",
        when={"event_type": "workspace.login.recovery_phone_edit"},
        fp=["Staff member replacing a lost handset"],
        playbook="tpl-account-takeover",
    ),
    F(
        family="workspace-takeover",
        category="identity",
        slug="gws-2sv-disabled-by-user",
        name="Workspace 2-Step Verification Turned Off By The Account Holder",
        severity="critical",
        mitre=["t1556.006"],
        product="google-workspace",
        service="login",
        when={"event_type": "workspace.login.2sv_disable"},
        fp=[FP_BREAK_GLASS, "Staff member who lost their second factor"],
        playbook="tpl-defense-evasion",
    ),
    F(
        family="workspace-takeover",
        category="identity",
        slug="gws-2sv-unenrolled-by-admin",
        name="Workspace 2-Step Verification Removed By An Administrator",
        severity="critical",
        mitre=["t1556.006"],
        product="google-workspace",
        service="admin",
        when={"event_type": "workspace.admin.unenroll_user_from_strong_auth"},
        fp=[FP_BREAK_GLASS, "Help-desk recovery after a verified identity check"],
        playbook="tpl-defense-evasion",
    ),
    F(
        family="workspace-takeover",
        category="identity",
        slug="gws-strong-auth-enforcement-relaxed",
        name="Workspace Strong Authentication Enforcement Relaxed",
        severity="high",
        mitre=["t1556.006"],
        product="google-workspace",
        service="admin",
        when={"event_type": "workspace.admin.allow_strong_authentication"},
        fp=["Documented policy change with a change ticket"],
        playbook="tpl-defense-evasion",
    ),
    F(
        family="workspace-takeover",
        category="identity",
        slug="gws-reauth-from-anonymizer",
        name="Workspace Sign-In From An Anonymizing Or Hosting Network",
        severity="high",
        mitre=["t1078.004", "t1090.003"],
        product="google-workspace",
        service="login",
        when={"event_type": "workspace.login.login_success", "ip_class_in": ANONYMIZER_CLASSES},
        fp=["Corporate VPN egress classified as a hosting provider", FP_PENTEST],
        playbook="tpl-account-takeover",
        neg_field="ip_class",
        description=(
            "A successful sign-in from an address the pinned ingest dataset classes as VPN, Tor, proxy or hosting. The class and its "
            "dataset version travel on the alert."
        ),
    ),
    F(
        family="workspace-takeover",
        category="identity",
        slug="gws-suspicious-login-flagged",
        name="Workspace Suspicious Sign-In Flagged By Google",
        severity="medium",
        mitre=["t1078.004"],
        product="google-workspace",
        service="login",
        when={"event_type": "workspace.login.suspicious_login"},
        fp=["Travelling staff on an unfamiliar network"],
        playbook="tpl-account-takeover",
    ),
    F(
        family="workspace-takeover",
        category="identity",
        slug="gws-suspicious-programmatic-login",
        name="Workspace Suspicious Programmatic Sign-In",
        severity="high",
        mitre=["t1078.004", "t1550.001"],
        product="google-workspace",
        service="login",
        when={"event_type": "workspace.login.suspicious_programmatic_login"},
        fp=["Scripted integration authenticating with a user credential rather than a service account"],
        playbook="tpl-account-takeover",
    ),
    F(
        family="workspace-takeover",
        category="identity",
        slug="gws-less-secure-app-login",
        name="Workspace Sign-In From A Less Secure Application",
        severity="medium",
        mitre=["t1078.004"],
        product="google-workspace",
        service="login",
        when={"event_type": "workspace.login.suspicious_login_less_secure_app"},
        fp=["Legacy IMAP client still in service"],
        playbook="tpl-account-takeover",
    ),
    F(
        family="workspace-takeover",
        category="identity",
        slug="gws-gov-attack-warning",
        name="Workspace Government-Backed Attack Warning",
        severity="critical",
        mitre=["t1566"],
        product="google-workspace",
        service="login",
        when={"event_type": "workspace.login.gov_attack_warning"},
        fp=["Google has issued the warning in error, which is rare enough to treat as true until shown otherwise"],
        playbook="tpl-account-takeover",
    ),
    F(
        family="workspace-takeover",
        category="identity",
        slug="gws-account-disabled-password-leak",
        name="Workspace Account Disabled After A Leaked Password",
        severity="high",
        mitre=["t1078.004"],
        product="google-workspace",
        service="login",
        when={"event_type": "workspace.login.account_disabled_password_leak"},
        fp=["Credential reused from an unrelated breach, with no access achieved"],
        playbook="tpl-account-takeover",
    ),
    F(
        family="workspace-takeover",
        category="identity",
        slug="gws-oauth-grant-mail-or-drive-scope",
        name="Workspace OAuth Grant Of Mail Or Drive Scopes",
        severity="high",
        mitre=["t1550.001", "t1528"],
        product="google-workspace",
        service="token",
        when={"event_type": "workspace.token.authorize", "param_scope_has_any": GWS_SENSITIVE_SCOPES},
        fp=["Approved integration from the organisation's allow-list"],
        playbook="tpl-account-takeover",
        neg_field="param_scope",
        description=(
            "A consent grant carrying a mailbox or drive scope. The scope list is the clause; a grant without one is an ordinary sign-in- "
            "with-Google."
        ),
    ),
    F(
        family="workspace-takeover",
        category="data-exfil",
        slug="gws-email-monitor-created",
        name="Workspace Email Monitor Created On A Mailbox",
        severity="critical",
        mitre=["t1114.002"],
        product="google-workspace",
        service="admin",
        when={"event_type": "workspace.admin.create_email_monitor"},
        fp=["Legal hold or investigation with a recorded authorisation"],
        playbook="tpl-exfiltration",
        description=(
            "An email monitor copies a mailbox to another address. Created outside a recorded legal process it is covert mail collection."
        ),
    ),
    F(
        family="workspace-takeover",
        category="identity",
        slug="gws-super-admin-granted",
        name="Workspace Super-Admin Privilege Granted",
        severity="critical",
        mitre=["t1098.003"],
        product="google-workspace",
        service="admin",
        when={"event_type": "workspace.admin.grant_admin_privilege"},
        fp=["Planned administrator onboarding", FP_BREAK_GLASS],
        playbook="tpl-privilege-escalation",
    ),
    F(
        family="workspace-takeover",
        category="identity",
        slug="gws-delegated-admin-granted",
        name="Workspace Delegated Admin Privileges Assigned",
        severity="high",
        mitre=["t1098.003"],
        product="google-workspace",
        service="admin",
        when={"event_type": "workspace.admin.delegate_admin_privileges"},
        fp=["Delegation to a help-desk role as designed"],
        playbook="tpl-privilege-escalation",
    ),
    F(
        family="workspace-takeover",
        category="identity",
        slug="gws-admin-role-assigned",
        name="Workspace Administrator Role Assigned",
        severity="high",
        mitre=["t1098.003"],
        product="google-workspace",
        service="admin",
        when={"event_type": "workspace.admin.assign_role"},
        fp=[FP_ONBOARD, "Role rotation inside the platform team"],
        playbook="tpl-privilege-escalation",
    ),
    F(
        family="workspace-takeover",
        category="data-exfil",
        slug="gws-drive-visibility-opened-publicly",
        name="Workspace Drive Document Opened To Anyone With The Link",
        severity="high",
        mitre=["t1537"],
        product="google-workspace",
        service="drive",
        when={
            "event_type": "workspace.drive.change_document_visibility",
            "param_visibility_in": ["people_with_link", "public_on_the_web"],
        },
        fp=["Marketing asset published deliberately"],
        playbook="tpl-exfiltration",
        neg_field="param_visibility",
    ),
    F(
        family="workspace-takeover",
        category="data-exfil",
        slug="gws-drive-external-access-granted",
        name="Workspace Drive Access Granted Outside The Domain",
        severity="high",
        mitre=["t1537", "t1567.002"],
        product="google-workspace",
        service="drive",
        when={"event_type": "workspace.drive.change_user_access", "param_visibility": "shared_externally"},
        fp=["Sanctioned collaboration with a named partner domain"],
        playbook="tpl-exfiltration",
        neg_field="param_visibility",
    ),
    F(
        family="workspace-takeover",
        category="data-exfil",
        slug="gws-drive-link-sharing-created",
        name="Workspace Drive Link Sharing Created",
        severity="medium",
        mitre=["t1537"],
        product="google-workspace",
        service="drive",
        when={"event_type": "workspace.drive.create_link_sharing"},
        fp=["Ordinary internal collaboration"],
        playbook="tpl-exfiltration",
    ),
    F(
        family="workspace-takeover",
        category="data-exfil",
        slug="gws-shared-drive-settings-weakened",
        name="Workspace Shared Drive Settings Changed",
        severity="medium",
        mitre=["t1537"],
        product="google-workspace",
        service="drive",
        when={"event_type": "workspace.drive.shared_drive_settings_change"},
        fp=[FP_TUNING, "Drive owner relaxing restrictions for a project"],
        playbook="tpl-exfiltration",
    ),
    F(
        family="workspace-takeover",
        category="identity",
        slug="gws-mobile-device-compromised",
        name="Workspace Managed Mobile Device Reported Compromised",
        severity="high",
        mitre=["t1078.004"],
        product="google-workspace",
        service="mobile",
        when={"event_type": "workspace.mobile.device_compromised_event"},
        fp=["Developer handset deliberately rooted for testing"],
        playbook="tpl-triage",
    ),
]


# ===========================================================================
# Family: apps-script-impersonation
#
# The Apps Script service creates projects under a system folder with `sys-`
# ids, through its own service account. A user principal creating one, or a
# `sys-` project configured in a way the service never configures it, means
# someone is borrowing the folder's trust.
# ===========================================================================
APPS_SCRIPT: list[dict] = [
    F(
        family="apps-script-impersonation",
        category="cloud",
        slug="gcp-apps-script-project-created-by-user",
        name="GCP Apps Script Project Created By A User Principal",
        severity="high",
        mitre=["t1078.004", "t1098.001"],
        product="gcp",
        service="cloudresourcemanager",
        when={
            "method_name": "CreateProject",
            "project_id_startswith": "sys-",
            "actor_is_service_account": False,
        },
        fp=["Platform engineer reproducing an Apps Script project deliberately"],
        playbook="tpl-privilege-escalation",
        neg_field="actor_is_service_account",
        description=(
            "Apps Script creates its own projects through its service account. A user principal doing it under the same `sys-` prefix is "
            "impersonating that path."
        ),
    ),
    F(
        family="apps-script-impersonation",
        category="cloud",
        slug="gcp-sys-project-iam-policy-set",
        name="GCP IAM Policy Set On An Apps Script System Project",
        severity="high",
        mitre=["t1098.001"],
        product="gcp",
        service="cloudresourcemanager",
        when={"method_name": "SetIamPolicy", "project_id_startswith": "sys-"},
        fp=["Platform team granting itself visibility into the folder"],
        playbook="tpl-privilege-escalation",
        neg_field="project_id",
    ),
    F(
        family="apps-script-impersonation",
        category="cloud",
        slug="gcp-sys-project-sa-key-created",
        name="GCP Service Account Key Created Under An Apps Script Project",
        severity="critical",
        mitre=["t1098.001", "t1528"],
        product="gcp",
        service="iam",
        when={
            "method_name": "google.iam.admin.v1.CreateServiceAccountKey",
            "project_id_startswith": "sys-",
        },
        fp=["Documented migration off Apps Script"],
        playbook="tpl-credential-access",
        neg_field="project_id",
        description="A downloadable key minted under the Apps Script folder is a long-lived credential in a project nobody audits.",
    ),
    F(
        family="apps-script-impersonation",
        category="cloud",
        slug="gcp-apps-script-user-agent-outside-service",
        name="GCP Apps Script User Agent On A Non-Script Service",
        severity="medium",
        mitre=["t1078.004"],
        product="gcp",
        service="cloudresourcemanager",
        when={
            "method_name": "CreateProject",
            "caller_user_agent_contains": "apps-script",
            "actor_is_service_account": False,
        },
        fp=["Apps Script editor acting for a signed-in user, which is legitimate inside the script project"],
        playbook="tpl-triage",
        neg_field="actor_is_service_account",
    ),
]


# ===========================================================================
# Family: third-party-access
#
# Vendor-owned identities, OAuth apps and installed integrations acting
# outside the shape they were approved for.
# ===========================================================================
THIRD_PARTY_ACCESS: list[dict] = [
    F(
        family="third-party-access",
        category="application",
        slug="slack-app-installed-broad-read-scopes",
        name="Slack App Installed With Broad Read Scopes",
        severity="high",
        mitre=["t1528", "t1199"],
        product="slack",
        service="audit",
        when={
            "event_type": "slack.app_installed",
            "app_scopes_has_any": ["files:read", "channels:history", "groups:history", "im:history"],
        },
        fp=["Approved integration from the organisation's allow-list"],
        playbook="tpl-triage",
        neg_field="app_scopes",
        description=(
            "A newly installed app that can read message history or files. The scope list is the clause; the install alone is routine."
        ),
    ),
    F(
        family="third-party-access",
        category="application",
        slug="slack-app-scopes-expanded",
        name="Slack App Scopes Expanded After Install",
        severity="high",
        mitre=["t1528"],
        product="slack",
        service="audit",
        when={"event_type": "slack.app_scopes_expanded"},
        fp=["Vendor shipping a feature that needs a new scope, with change approval"],
        playbook="tpl-triage",
    ),
    F(
        family="third-party-access",
        category="application",
        slug="slack-app-uninstalled",
        name="Slack App Uninstalled",
        severity="low",
        mitre=["t1070"],
        product="slack",
        service="audit",
        when={"event_type": "slack.app_uninstalled"},
        fp=["Ordinary integration retirement"],
        playbook="tpl-triage",
    ),
    F(
        family="third-party-access",
        category="application",
        slug="slack-external-shared-channel-connected",
        name="Slack External Shared Channel Connected",
        severity="medium",
        mitre=["t1199"],
        product="slack",
        service="audit",
        when={"event_type": "slack.external_shared_channel_connected"},
        fp=["Partner collaboration opened deliberately"],
        playbook="tpl-triage",
    ),
    F(
        family="third-party-access",
        category="application",
        slug="slack-org-export-started",
        name="Slack Organisation Export Started",
        severity="critical",
        mitre=["t1530", "t1567"],
        product="slack",
        service="audit",
        when={"event_type": "slack.organization_export_started"},
        fp=["Legal hold or discovery export with a recorded authorisation"],
        playbook="tpl-exfiltration",
    ),
    F(
        family="third-party-access",
        category="application",
        slug="slack-role-change-to-owner",
        name="Slack Role Changed To Organisation Owner",
        severity="critical",
        mitre=["t1098.003"],
        product="slack",
        service="audit",
        when={"event_type": "slack.role_change_to_owner"},
        fp=["Planned ownership handover"],
        playbook="tpl-privilege-escalation",
    ),
    F(
        family="third-party-access",
        category="application",
        slug="slack-role-change-to-admin",
        name="Slack Role Changed To Workspace Admin",
        severity="high",
        mitre=["t1098.003"],
        product="slack",
        service="audit",
        when={"event_type": "slack.role_change_to_admin"},
        fp=["Administrator onboarding", FP_ONBOARD],
        playbook="tpl-privilege-escalation",
    ),
    F(
        family="third-party-access",
        category="application",
        slug="slack-sso-setting-changed",
        name="Slack Single Sign-On Setting Changed",
        severity="critical",
        mitre=["t1556"],
        product="slack",
        service="audit",
        when={"event_type": "slack.pref.sso_setting_changed"},
        fp=["Identity-provider migration with a change ticket"],
        playbook="tpl-defense-evasion",
    ),
    F(
        family="third-party-access",
        category="application",
        slug="slack-two-factor-policy-changed",
        name="Slack Two-Factor Policy Changed",
        severity="critical",
        mitre=["t1556.006"],
        product="slack",
        service="audit",
        when={"event_type": "slack.pref.two_factor_auth_changed"},
        fp=["Policy tightened rather than relaxed; the entry records the direction"],
        playbook="tpl-defense-evasion",
    ),
    F(
        family="third-party-access",
        category="application",
        slug="slack-session-invalidation-disabled",
        name="Slack Session Invalidation Disabled",
        severity="high",
        mitre=["t1556"],
        product="slack",
        service="audit",
        when={"event_type": "slack.user_session_invalidation_disabled"},
        fp=["Administrator troubleshooting a sign-out loop"],
        playbook="tpl-defense-evasion",
    ),
    F(
        family="third-party-access",
        category="application",
        slug="slack-message-deletion-allowed",
        name="Slack Message Deletion Permission Widened",
        severity="high",
        mitre=["t1070"],
        product="slack",
        service="audit",
        when={"event_type": "slack.pref.allow_message_deletion"},
        fp=["Retention policy change with approval"],
        playbook="tpl-defense-evasion",
        description="Letting members delete messages removes the record an investigation reads.",
    ),
    F(
        family="third-party-access",
        category="application",
        slug="slack-channel-converted-to-private",
        name="Slack Channel Converted To Private",
        severity="low",
        mitre=["t1564"],
        product="slack",
        service="audit",
        when={"event_type": "slack.channel_converted_to_private"},
        fp=["Team restricting a channel for ordinary confidentiality"],
        playbook="tpl-triage",
    ),
    F(
        family="third-party-access",
        category="application",
        slug="slack-guest-created",
        name="Slack Guest Account Created",
        severity="medium",
        mitre=["t1136.003"],
        product="slack",
        service="audit",
        when={"event_type": "slack.guest_created"},
        fp=["Contractor onboarding", FP_ONBOARD],
        playbook="tpl-persistence",
    ),
    F(
        family="third-party-access",
        category="application",
        slug="slack-public-url-updated",
        name="Slack Workspace Public URL Updated",
        severity="high",
        mitre=["t1491"],
        product="slack",
        service="audit",
        when={"event_type": "slack.workspace_public_url_updated"},
        fp=["Rebrand with a change ticket"],
        playbook="tpl-triage",
    ),
    F(
        family="third-party-access",
        category="application",
        slug="slack-file-downloaded-from-anonymizer",
        name="Slack File Downloaded From An Anonymizing Network",
        severity="high",
        mitre=["t1530"],
        product="slack",
        service="audit",
        when={"event_type": "slack.file_downloaded", "ip_class_in": ANONYMIZER_CLASSES},
        fp=["Staff member on a corporate VPN whose egress is classified as hosting"],
        playbook="tpl-exfiltration",
        neg_field="ip_class",
    ),
    F(
        family="third-party-access",
        category="application",
        slug="sfdc-connected-app-installed",
        name="Salesforce Connected Application Installed",
        severity="high",
        mitre=["t1528", "t1199"],
        product="salesforce",
        service="setup-audit",
        when={"event_type": "salesforce.insertConnectedApplication"},
        fp=["Approved integration from the organisation's allow-list"],
        playbook="tpl-triage",
    ),
    F(
        family="third-party-access",
        category="application",
        slug="sfdc-connected-app-updated",
        name="Salesforce Connected Application Updated",
        severity="medium",
        mitre=["t1528"],
        product="salesforce",
        service="setup-audit",
        when={"event_type": "salesforce.updatedConnectedApplication"},
        fp=["Vendor-published update applied during a maintenance window"],
        playbook="tpl-triage",
    ),
    F(
        family="third-party-access",
        category="application",
        slug="sfdc-login-as-user",
        name="Salesforce Administrator Signed In As Another User",
        severity="high",
        mitre=["t1078.004"],
        product="salesforce",
        service="setup-audit",
        when={"event_type": "salesforce.suOrgAdminLogin"},
        fp=["Support engineer reproducing a reported defect with the user's consent"],
        playbook="tpl-account-takeover",
        description=(
            "`DelegateUser` on the record names the administrator who assumed the identity, which is the field an investigation needs and "
            "the connector now lifts."
        ),
    ),
    F(
        family="third-party-access",
        category="application",
        slug="sfdc-permission-set-assigned",
        name="Salesforce Permission Set Assigned",
        severity="high",
        mitre=["t1098"],
        product="salesforce",
        service="setup-audit",
        when={"event_type": "salesforce.PermSetAssign"},
        fp=[FP_ONBOARD, "Role change processed by the identity-governance pipeline"],
        playbook="tpl-privilege-escalation",
    ),
    F(
        family="third-party-access",
        category="application",
        slug="sfdc-permission-set-created",
        name="Salesforce Permission Set Created",
        severity="medium",
        mitre=["t1098"],
        product="salesforce",
        service="setup-audit",
        when={"event_type": "salesforce.PermSetCreate"},
        fp=["Administrator building a role for a new team"],
        playbook="tpl-privilege-escalation",
    ),
    F(
        family="third-party-access",
        category="application",
        slug="sfdc-profile-changed",
        name="Salesforce User Profile Changed",
        severity="medium",
        mitre=["t1098"],
        product="salesforce",
        service="setup-audit",
        when={"event_type": "salesforce.changedProfile"},
        fp=[FP_ONBOARD, "Planned profile migration"],
        playbook="tpl-privilege-escalation",
    ),
    F(
        family="third-party-access",
        category="application",
        slug="sfdc-data-export-scheduled",
        name="Salesforce Data Export Run",
        severity="high",
        mitre=["t1530", "t1567"],
        product="salesforce",
        service="setup-audit",
        when={"event_type": "salesforce.dataExport"},
        fp=["Scheduled backup export", FP_AUTOMATION],
        playbook="tpl-exfiltration",
    ),
    F(
        family="third-party-access",
        category="application",
        slug="sfdc-login-policy-changed",
        name="Salesforce Login Policy Changed",
        severity="high",
        mitre=["t1556"],
        product="salesforce",
        service="setup-audit",
        when={"event_type": "salesforce.loginPolicyChanged"},
        fp=["IP-range policy updated for a new office"],
        playbook="tpl-defense-evasion",
    ),
    F(
        family="third-party-access",
        category="application",
        slug="sfdc-certificate-inserted",
        name="Salesforce Certificate Inserted",
        severity="high",
        mitre=["t1556"],
        product="salesforce",
        service="setup-audit",
        when={"event_type": "salesforce.insertCertificate"},
        fp=["Identity-provider certificate rotation"],
        playbook="tpl-persistence",
    ),
]


# ===========================================================================
# Family: saas-data-movement
#
# Bulk movement of files and records out of a SaaS tenant, across the
# file-storage and warehouse sources.
# ===========================================================================
SAAS_DATA_MOVEMENT: list[dict] = [
    F(
        family="saas-data-movement",
        category="data-exfil",
        slug="box-shared-link-opened-publicly",
        name="Box Shared Link Set To Open Access",
        severity="high",
        mitre=["t1537"],
        product="box",
        service="events",
        when={"event_type": "box.SHARE", "shared_link_access": "open"},
        fp=["Public asset published deliberately"],
        playbook="tpl-exfiltration",
        neg_field="shared_link_access",
        description=(
            "Box records the resulting access level under `additional_details.shared_link.access`, which is two levels down and was "
            "invisible until the connector lifted it."
        ),
    ),
    F(
        family="saas-data-movement",
        category="data-exfil",
        slug="box-item-shared-link-created",
        name="Box Shared Link Created On An Item",
        severity="medium",
        mitre=["t1537"],
        product="box",
        service="events",
        when={"event_type": "box.ITEM_SHARED_LINK"},
        fp=["Ordinary internal collaboration"],
        playbook="tpl-exfiltration",
    ),
    F(
        family="saas-data-movement",
        category="data-exfil",
        slug="box-external-collab-invite-blocked",
        name="Box External Collaboration Invite Blocked By Shield",
        severity="high",
        mitre=["t1199"],
        product="box",
        service="events",
        when={"event_type": "box.SHIELD_EXTERNAL_COLLAB_INVITE_BLOCKED"},
        fp=["Policy tuned too tightly for a sanctioned partner"],
        playbook="tpl-triage",
    ),
    F(
        family="saas-data-movement",
        category="data-exfil",
        slug="box-external-collab-abnormal-location",
        name="Box External Collaboration Invite From An Abnormal Location",
        severity="high",
        mitre=["t1199", "t1078.004"],
        product="box",
        service="events",
        when={"event_type": "box.SHIELD_EXTERNAL_COLLAB_INVITE_ABNORMAL_LOCATION"},
        fp=["Staff member travelling"],
        playbook="tpl-account-takeover",
    ),
    F(
        family="saas-data-movement",
        category="data-exfil",
        slug="box-shield-alert",
        name="Box Shield Alert Raised",
        severity="high",
        mitre=["t1530"],
        product="box",
        service="events",
        when={"event_type": "box.SHIELD_ALERT"},
        fp=["Shield policy tuned too tightly"],
        playbook="tpl-triage",
    ),
    F(
        family="saas-data-movement",
        category="data-exfil",
        slug="box-admin-role-granted",
        name="Box Role Changed To Administrator",
        severity="critical",
        mitre=["t1098.003"],
        product="box",
        service="events",
        when={"event_type": "box.ROLE_CHANGE_TO_ADMIN"},
        fp=["Planned administrator onboarding", FP_ONBOARD],
        playbook="tpl-privilege-escalation",
    ),
    F(
        family="saas-data-movement",
        category="data-exfil",
        slug="box-app-public-key-added",
        name="Box Application Public Key Added",
        severity="critical",
        mitre=["t1098.001", "t1528"],
        product="box",
        service="events",
        when={"event_type": "box.APPLICATION_PUBLIC_KEY_ADDED"},
        fp=["Scheduled key rotation for a sanctioned integration"],
        playbook="tpl-persistence",
        description=(
            "A public key added to a Box application authorises a new JWT signer, which is server-to-server persistence that no user "
            "sign-in reveals."
        ),
    ),
    F(
        family="saas-data-movement",
        category="data-exfil",
        slug="box-app-public-key-deleted",
        name="Box Application Public Key Deleted",
        severity="high",
        mitre=["t1070"],
        product="box",
        service="events",
        when={"event_type": "box.APPLICATION_PUBLIC_KEY_DELETED"},
        fp=["Scheduled key rotation for a sanctioned integration"],
        playbook="tpl-triage",
    ),
    F(
        family="saas-data-movement",
        category="data-exfil",
        slug="box-login-from-anonymizer",
        name="Box Sign-In From An Anonymizing Or Hosting Network",
        severity="high",
        mitre=["t1078.004", "t1090.003"],
        product="box",
        service="events",
        when={"event_type": "box.USER_LOGIN", "ip_class_in": ANONYMIZER_CLASSES},
        fp=["Corporate VPN egress classified as a hosting provider"],
        playbook="tpl-account-takeover",
        neg_field="ip_class",
    ),
    F(
        family="saas-data-movement",
        category="data-exfil",
        slug="box-user-deleted",
        name="Box User Deleted",
        severity="medium",
        mitre=["t1531"],
        product="box",
        service="events",
        when={"event_type": "box.DELETE_USER"},
        fp=["Leaver process running on schedule", FP_AUTOMATION],
        playbook="tpl-triage",
    ),
    F(
        family="saas-data-movement",
        category="data-exfil",
        slug="dropbox-link-audience-changed-to-public",
        name="Dropbox Shared Link Audience Changed To Public",
        severity="high",
        mitre=["t1537"],
        product="dropbox",
        service="events",
        when={"event_type": "dropbox.shared_content_change_link_audience_to_public"},
        fp=["Marketing asset published deliberately"],
        playbook="tpl-exfiltration",
    ),
    F(
        family="saas-data-movement",
        category="data-exfil",
        slug="dropbox-shared-content-downloaded",
        name="Dropbox Shared Content Downloaded",
        severity="medium",
        mitre=["t1530"],
        product="dropbox",
        service="events",
        when={"event_type": "dropbox.shared_content_download"},
        fp=["Ordinary collaboration inside the team"],
        playbook="tpl-exfiltration",
    ),
    F(
        family="saas-data-movement",
        category="data-exfil",
        slug="dropbox-shared-content-member-removed",
        name="Dropbox Shared Content Member Removed",
        severity="medium",
        mitre=["t1531"],
        product="dropbox",
        service="events",
        when={"event_type": "dropbox.shared_content_remove_member"},
        fp=["Project wind-down removing collaborators"],
        playbook="tpl-triage",
    ),
    F(
        family="saas-data-movement",
        category="data-exfil",
        slug="dropbox-team-invite-link-created",
        name="Dropbox Team Invite Link Created",
        severity="high",
        mitre=["t1136.003"],
        product="dropbox",
        service="events",
        when={"event_type": "dropbox.team_member_create_team_invite_link"},
        fp=["Bulk onboarding with an approved invite link"],
        playbook="tpl-persistence",
        description=(
            "An invite link lets anyone holding it join the team, which is persistence that survives the original account being disabled."
        ),
    ),
    F(
        family="saas-data-movement",
        category="data-exfil",
        slug="dropbox-admin-role-changed",
        name="Dropbox Member Admin Role Changed",
        severity="critical",
        mitre=["t1098.003"],
        product="dropbox",
        service="events",
        when={"event_type": "dropbox.member_change_admin_role"},
        fp=["Planned administrator onboarding", FP_ONBOARD],
        playbook="tpl-privilege-escalation",
    ),
    F(
        family="saas-data-movement",
        category="data-exfil",
        slug="dropbox-sso-policy-changed",
        name="Dropbox Single Sign-On Policy Changed",
        severity="critical",
        mitre=["t1556"],
        product="dropbox",
        service="events",
        when={"event_type": "dropbox.sso_change_policy"},
        fp=["Identity-provider migration with a change ticket"],
        playbook="tpl-defense-evasion",
    ),
    F(
        family="saas-data-movement",
        category="data-exfil",
        slug="dropbox-app-linked-to-team",
        name="Dropbox Application Linked To The Team",
        severity="high",
        mitre=["t1528", "t1199"],
        product="dropbox",
        service="events",
        when={"event_type": "dropbox.app_link_team"},
        fp=["Approved integration from the organisation's allow-list"],
        playbook="tpl-triage",
    ),
    F(
        family="saas-data-movement",
        category="data-exfil",
        slug="dropbox-team-folder-status-changed",
        name="Dropbox Team Folder Status Changed",
        severity="medium",
        mitre=["t1485"],
        product="dropbox",
        service="events",
        when={"event_type": "dropbox.team_folder_change_status"},
        fp=["Team restructure with a change ticket"],
        playbook="tpl-triage",
    ),
    F(
        family="saas-data-movement",
        category="data-exfil",
        slug="dropbox-external-password-unmasked",
        name="Dropbox External Password Unmasked",
        severity="critical",
        mitre=["t1555"],
        product="dropbox",
        service="events",
        when={"event_type": "dropbox.account_external_password_unmask"},
        fp=["Password-manager migration performed by the account owner"],
        playbook="tpl-credential-access",
    ),
    F(
        family="saas-data-movement",
        category="data-exfil",
        slug="dropbox-device-linked-from-anonymizer",
        name="Dropbox Device Linked From An Anonymizing Network",
        severity="high",
        mitre=["t1078.004"],
        product="dropbox",
        service="events",
        when={"event_type": "dropbox.device_link_success", "ip_class_in": ANONYMIZER_CLASSES},
        fp=["Staff member on a corporate VPN whose egress is classified as hosting"],
        playbook="tpl-account-takeover",
        neg_field="ip_class",
    ),
    F(
        family="saas-data-movement",
        category="data-exfil",
        slug="snowflake-bulk-rows-produced",
        name="Snowflake Query Returned A Very Large Row Count",
        severity="medium",
        mitre=["t1530"],
        product="snowflake",
        service="query-history",
        when={"event_type": "snowflake.query.select", "rows_produced_gt": 1000000},
        fp=["Scheduled extract for a reporting warehouse", FP_AUTOMATION],
        playbook="tpl-exfiltration",
        neg_field="rows_produced",
    ),
    F(
        family="saas-data-movement",
        category="data-exfil",
        slug="snowflake-unload-to-stage",
        name="Snowflake Data Unloaded To A Stage",
        severity="high",
        mitre=["t1537", "t1567"],
        product="snowflake",
        service="query-history",
        when={"query_type": "UNLOAD"},
        fp=["Scheduled export into the organisation's own object store", FP_AUTOMATION],
        playbook="tpl-exfiltration",
    ),
    F(
        family="saas-data-movement",
        category="data-exfil",
        slug="snowflake-grant-executed",
        name="Snowflake Privilege Granted",
        severity="high",
        mitre=["t1098"],
        product="snowflake",
        service="query-history",
        when={"query_type": "GRANT"},
        fp=["Role provisioning through the data-platform pipeline", FP_AUTOMATION],
        playbook="tpl-privilege-escalation",
    ),
    F(
        family="saas-data-movement",
        category="data-exfil",
        slug="snowflake-create-user",
        name="Snowflake User Created",
        severity="high",
        mitre=["t1136"],
        product="snowflake",
        service="query-history",
        when={"query_type": "CREATE_USER"},
        fp=[FP_ONBOARD, "Provisioning pipeline creating a service user"],
        playbook="tpl-persistence",
    ),
]


# ===========================================================================
# Family: saas-authentication-abuse
#
# Authentication against SaaS sources where the vendor states the outcome
# and the factor, so a failure class can be told from a success.
# ===========================================================================
SAAS_AUTHENTICATION_ABUSE: list[dict] = [
    F(
        family="saas-authentication-abuse",
        category="identity",
        slug="snowflake-login-single-factor-service-user",
        name="Snowflake Password-Only Sign-In Succeeded",
        severity="medium",
        mitre=["t1078.004"],
        product="snowflake",
        service="login-history",
        when={
            "event_type": "snowflake.login",
            "is_success": True,
            "first_auth_factor": "PASSWORD",
            "mfa_satisfied": False,
        },
        fp=["Service user that cannot hold a second factor and is restricted by network policy instead"],
        playbook="tpl-account-takeover",
        neg_field="mfa_satisfied",
        description=(
            "Snowflake states both factors on every LOGIN_HISTORY row, so a password-only success is a fact rather than an inference."
        ),
    ),
    F(
        family="saas-authentication-abuse",
        category="identity",
        slug="snowflake-login-failed-bad-credentials",
        name="Snowflake Sign-In Failed With Incorrect Credentials",
        severity="low",
        mitre=["t1110"],
        product="snowflake",
        service="login-history",
        when={"event_type": "snowflake.login", "is_success": False, "error_code": "390100"},
        fp=["Staff member mistyping a password"],
        playbook="tpl-triage",
        neg_field="error_code",
    ),
    F(
        family="saas-authentication-abuse",
        category="identity",
        slug="snowflake-login-from-anonymizer",
        name="Snowflake Sign-In From An Anonymizing Or Hosting Network",
        severity="high",
        mitre=["t1078.004", "t1090.003"],
        product="snowflake",
        service="login-history",
        when={"event_type": "snowflake.login", "is_success": True, "ip_class_in": ANONYMIZER_CLASSES},
        fp=["Warehouse reached through a cloud-hosted transformation job"],
        playbook="tpl-account-takeover",
        neg_field="ip_class",
    ),
    F(
        family="saas-authentication-abuse",
        category="identity",
        slug="snowflake-driver-change-for-user",
        name="Snowflake Sign-In From A Programmatic Driver",
        severity="low",
        mitre=["t1078.004"],
        product="snowflake",
        service="login-history",
        when={"event_type": "snowflake.login", "is_success": True, "client_type": "JDBC_DRIVER"},
        fp=["Established extract-transform-load job", FP_AUTOMATION],
        playbook="tpl-triage",
        neg_field="client_type",
    ),
    F(
        family="saas-authentication-abuse",
        category="identity",
        slug="1p-credentials-failed",
        name="1Password Sign-In Failed On Credentials",
        severity="medium",
        mitre=["t1110"],
        product="onepassword",
        service="signin-attempts",
        when={"event_type": "onepassword.signin.credentials_failed"},
        fp=["Staff member mistyping their account password"],
        playbook="tpl-triage",
    ),
    F(
        family="saas-authentication-abuse",
        category="identity",
        slug="1p-mfa-failed",
        name="1Password Sign-In Failed On Second Factor",
        severity="high",
        mitre=["t1621", "t1110"],
        product="onepassword",
        service="signin-attempts",
        when={"event_type": "onepassword.signin.mfa_failed"},
        fp=["Clock drift on a time-based code generator"],
        playbook="tpl-account-takeover",
        description=(
            "The credential was right and the factor was not, which separates a password-guessing attempt from one that already holds the "
            "password."
        ),
    ),
    F(
        family="saas-authentication-abuse",
        category="identity",
        slug="1p-firewall-blocked",
        name="1Password Sign-In Blocked By The Account Firewall",
        severity="medium",
        mitre=["t1078"],
        product="onepassword",
        service="signin-attempts",
        when={"event_type": "onepassword.signin.firewall_failed"},
        fp=["Staff member travelling outside an allowed country"],
        playbook="tpl-triage",
    ),
    F(
        family="saas-authentication-abuse",
        category="identity",
        slug="1p-firewall-reported-success",
        name="1Password Sign-In Succeeded From A Firewall-Reported Address",
        severity="high",
        mitre=["t1078"],
        product="onepassword",
        service="signin-attempts",
        when={"event_type": "onepassword.signin.firewall_reported_success"},
        fp=["Policy in report-only mode during a rollout"],
        playbook="tpl-account-takeover",
    ),
    F(
        family="saas-authentication-abuse",
        category="identity",
        slug="1p-modern-version-failed",
        name="1Password Sign-In Refused For An Outdated Client",
        severity="low",
        mitre=["t1078"],
        product="onepassword",
        service="signin-attempts",
        when={"event_type": "onepassword.signin.modern_version_failed"},
        fp=["Staff member on an unmanaged device that has not updated"],
        playbook="tpl-triage",
    ),
    F(
        family="saas-authentication-abuse",
        category="identity",
        slug="1p-signin-from-anonymizer",
        name="1Password Sign-In From An Anonymizing Or Hosting Network",
        severity="high",
        mitre=["t1078", "t1090.003"],
        product="onepassword",
        service="signin-attempts",
        when={"event_type": "onepassword.signin.success", "ip_class_in": ANONYMIZER_CLASSES},
        fp=["Corporate VPN egress classified as a hosting provider"],
        playbook="tpl-account-takeover",
        neg_field="ip_class",
    ),
]


#: Specs partitioned onto the `detections/<category>/` directories.
#: `detection_specs_index` reads these; nothing else should re-derive them.
BY_CATEGORY = by_category(
    WORKSPACE_TAKEOVER,
    APPS_SCRIPT,
    THIRD_PARTY_ACCESS,
    SAAS_DATA_MOVEMENT,
    SAAS_AUTHENTICATION_ABUSE,
)

FAMILIES_CLOUD: list[dict] = BY_CATEGORY.get("cloud", [])
FAMILIES_IDENTITY: list[dict] = BY_CATEGORY.get("identity", [])
FAMILIES_APPLICATION: list[dict] = BY_CATEGORY.get("application", [])
FAMILIES_DATA_EXFIL: list[dict] = BY_CATEGORY.get("data-exfil", [])


# ===========================================================================
# Family: long-horizon-identity
#
# Item 2.2. Accumulation over days to weeks per account, from the
# long-horizon store (`services/fusion/app/services/long_horizon_identity.py`)
# rather than the windowed engine, whose longest window is one day and which
# counts rather than accumulates sets.
#
# The thresholds are a recorded *rationale*, not a measurement:
# `docs/detections/long-horizon-thresholds.json` carries `measured: false`
# because no corpus here has an authentication event with an account, a
# source network and an outcome together. The descriptions say so, because a
# threshold a reader believes was derived is worse than one they can check.
# ===========================================================================
LONG_HORIZON_IDENTITY: list[dict] = [
    F(
        family="long-horizon-identity",
        category="identity",
        slug="lh-distributed-failures-against-one-account",
        name="Account Failed Authentication From Many Networks Over Weeks",
        severity="high",
        mitre=["t1110.003"],
        product="identity",
        service="authentication",
        when={"lh_distinct_failed_asn_gte": 8},
        fp=["Shared service account authenticated by a fleet of workers across many networks"],
        playbook="tpl-account-takeover",
        description=(
            "Eight or more distinct autonomous systems have failed against this one account "
            "inside the 30-day horizon. Spread this thin the attempt crosses no hourly "
            "threshold, which is why the windowed engine cannot see it. The threshold is a "
            "recorded rationale and not a measurement; see docs/detections/long-horizon-thresholds.json."
        ),
    ),
    F(
        family="long-horizon-identity",
        category="identity",
        slug="lh-failure-breadth-exceeds-success-breadth",
        name="Account Fails From Far More Networks Than It Succeeds From",
        severity="high",
        mitre=["t1110.003", "t1078"],
        product="identity",
        service="authentication",
        when={"lh_failed_to_success_asn_ratio_gte": 4.0},
        fp=["Account whose client retries against a rotating egress pool"],
        playbook="tpl-account-takeover",
        description=(
            "The ratio is the discriminator the plan names: a travelling employee widens both "
            "sides together, an attack widens only the failing one. Undefined when the account "
            "has no observed successes, so a dormant account cannot fire it. The threshold is a "
            "recorded rationale and not a measurement."
        ),
    ),
    F(
        family="long-horizon-identity",
        category="identity",
        slug="lh-failed-country-breadth",
        name="Account Failed Authentication From Many Countries Over Weeks",
        severity="medium",
        mitre=["t1110.003"],
        product="identity",
        service="authentication",
        when={"lh_distinct_failed_country_gte": 5},
        fp=["Globally distributed workforce sharing one break-glass account"],
        playbook="tpl-account-takeover",
        description=(
            "Country breadth is weaker evidence than autonomous-system breadth — a single "
            "provider spans countries — so this is medium where the ASN rule is high. The "
            "threshold is a recorded rationale and not a measurement."
        ),
    ),
    F(
        family="long-horizon-identity",
        category="identity",
        slug="lh-failed-network-set-saturated",
        name="Account Failure Sources Exceeded The Daily Enumeration Cap",
        severity="high",
        mitre=["t1110.003"],
        product="identity",
        service="authentication",
        when={"lh_failed_asn_saturated": True},
        fp=["Load generator or authentication test harness pointed at a real account"],
        playbook="tpl-account-takeover",
        description=(
            "The store stops admitting new sources for an account's day at a cap, so the day is "
            "reported as saturated rather than silently truncated. Saturation is itself the "
            "finding: the account is being reached from more networks than it is worth enumerating."
        ),
    ),
]

BY_CATEGORY_LONG_HORIZON = by_category(LONG_HORIZON_IDENTITY)
FAMILIES_IDENTITY.extend(BY_CATEGORY_LONG_HORIZON.get("identity", []))


# ===========================================================================
# Family: api-behaviour
#
# Item 2.4. Deviations from an endpoint's learned shape, from
# `services/fusion/app/services/api_behaviour.py`. Off by default per tenant,
# and a signal is published only for a template with enough history, so none
# of these can fire on the first request to a new endpoint.
# ===========================================================================
API_BEHAVIOUR: list[dict] = [
    F(
        family="api-behaviour",
        category="application",
        slug="api-unknown-parameter-on-known-endpoint",
        name="Unknown Parameter Sent To A Profiled API Endpoint",
        severity="medium",
        mitre=["t1190"],
        product="api-gateway",
        service="access-log",
        when={"api_unknown_parameter": True},
        fp=["A release that added a parameter; the profile relearns it within the window"],
        playbook="tpl-triage",
        description=(
            "A parameter name this templated endpoint has not received before, on an endpoint "
            "with at least 50 requests of history. A mass-assignment or hidden-parameter probe "
            "looks exactly like this; so does a deploy, which is why the false positive is named."
        ),
    ),
    F(
        family="api-behaviour",
        category="application",
        slug="api-parameter-type-changed",
        name="Known API Parameter Changed Type",
        severity="high",
        mitre=["t1190"],
        product="api-gateway",
        service="access-log",
        when={"api_parameter_type_change": True},
        fp=["A client that began sending an identifier as a string"],
        playbook="tpl-triage",
        description=(
            "A parameter the endpoint has always received as an integer arrived as a string. "
            "Injection and type-confusion probes change the type; ordinary traffic does not."
        ),
    ),
    F(
        family="api-behaviour",
        category="application",
        slug="api-identifier-enumeration",
        name="Client Walked Many Identifiers Through One API Endpoint",
        severity="high",
        mitre=["t1087", "t1190"],
        product="api-gateway",
        service="access-log",
        when={"api_identifier_enumeration": True},
        fp=["A sanctioned export job paging through records by identifier"],
        playbook="tpl-triage",
        description=(
            "One client requested 50 or more distinct identifiers through one templated path "
            "inside five minutes. Templating is what makes this visible at all: without it the "
            "requests are unrelated strings."
        ),
    ),
]

BY_CATEGORY_API = by_category(API_BEHAVIOUR)
FAMILIES_APPLICATION.extend(BY_CATEGORY_API.get("application", []))
