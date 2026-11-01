#!/usr/bin/env python3
"""CI gate: every scenario-family rule fires on what its connector emits.

"Executable" in this repository means *replayed through the real connector
and the real engine and observed to fire on a well-formed event of its log
source*. It is not a claim the rule detects an attack, and nothing below
measures that. Keeping the two apart is the whole point: a rule can pass
fixture replay, be loaded by the engine and count toward the published total
while being unable to fire on any real event, because fixtures are
synthesised from the rule they test and replaying one is a tautology.

`scripts/check_github_rule_alignment.py` closed that hole for one product
after issue #1545 measured ten of twelve GitHub rules dead. This gate is the
same proof generalised across the vendors depth 2 wave 2 item 2.1 adds, and
it checks two independent things:

1. **Vocabulary.** Every vendor event or action name a rule clauses on must
   appear in `scripts/vendor_event_vocabulary.py`, which transcribes the
   vendor's own published list. This is what catches ``deploy_key.create`` —
   a name GitHub has never logged, matched by a rule that looked fine.
2. **Fireability.** A real-shaped payload in the vendor's own envelope,
   carrying that name, goes through the real connector and the real
   `DetectionEngine`, and the rule must fire. This is what catches a field
   the connector drops, a value it rewrites (``github.{action}``) and a
   severity map that swallows the discriminator.

The payload is built from the vendor's envelope, never from the rule. A
sample derived from `match_when` would pass against any connector, including
one that deletes every field.

Out of process, for the reason `connector_normalize_worker.py` documents:
`services/connectors` and `services/fusion` both ship their code under the
package name `app`, so only one is importable at a time.

Usage:
    python3 scripts/check_scenario_family_alignment.py
    python3 scripts/check_scenario_family_alignment.py --list
    python3 scripts/check_scenario_family_alignment.py --self-test
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))

from gate_toolkit import repo_root, self_test_main

ROOT = repo_root()
WORKER = ROOT / "scripts" / "connector_normalize_worker.py"
RULESET = ROOT / "services" / "fusion" / "app" / "data" / "detection_ruleset.json"

#: Which connector emits each product's telemetry. A product with no entry
#: is not covered by this gate; `--list` names them so the gap is visible
#: rather than silent.
PRODUCT_EMITTER: dict[str, str] = {
    "google-workspace": "google_workspace",
    "gcp": "gcp_cloud_audit",
    "slack": "slack_audit",
    "salesforce": "salesforce",
    "snowflake": "snowflake",
    "box": "box",
    "dropbox": "dropbox",
    "onepassword": "onepassword",
    "azure": "azure_entra",
    "kubernetes": "kubernetes_audit",
    "github": "github",
    "gitlab": "gitlab",
    "m365": "m365_audit",
    "okta": "okta",
    "atlassian": "confluence_audit",
}

#: Fields the engine derives at evaluate time rather than reading off the
#: event: the ingest IP classification (item 1.6) and the business-hours
#: booleans. A rule may clause on them, and this gate supplies them around
#: the connector output rather than pretending the connector emits them.
DERIVED_FIELDS = frozenset({"ip_class", "is_business_hours", "is_after_hours", "is_weekend"})


def _gws(application: str, event_name: str, parameters: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    """A Reports API activity, in the shape the Admin SDK returns it."""
    return {
        "_aisoc_application": application,
        "kind": "admin#reports#activity",
        "id": {
            "time": "2026-11-01T10:00:00.000Z",
            "uniqueQualifier": "proof",
            "applicationName": application,
            "customerId": "C00000000",
        },
        "actor": {"email": "user@example.com", "profileId": "100000000000000000000"},
        "ipAddress": "203.0.113.5",
        "events": [{"type": application, "name": event_name, "parameters": parameters or []}],
    }


def _gcp(
    method: str, service: str, project: str = "example-prod", principal: str = "user@example.com", agent: str = "google-cloud-sdk"
) -> dict[str, Any]:
    """A Cloud Audit log entry, in the shape Cloud Logging exports it."""
    return {
        "logName": f"projects/{project}/logs/cloudaudit.googleapis.com%2Factivity",
        "insertId": "proof",
        "timestamp": "2026-11-01T10:00:00Z",
        "severity": "NOTICE",
        "resource": {"type": "project", "labels": {"project_id": project}},
        "protoPayload": {
            "@type": "type.googleapis.com/google.cloud.audit.AuditLog",
            "serviceName": service,
            "methodName": method,
            "authenticationInfo": {"principalEmail": principal},
            "requestMetadata": {"callerIp": "203.0.113.5", "callerSuppliedUserAgent": agent},
            "resourceName": f"projects/{project}",
            "status": {},
        },
    }


def _slack(action: str, entity: dict[str, Any] | None = None) -> dict[str, Any]:
    """An Audit Logs API entry, in the shape audit.slack.com returns it."""
    return {
        "id": "proof",
        "date_create": 1793952000,
        "action": action,
        "actor": {"type": "user", "user": {"id": "W0000001", "name": "alice", "email": "alice@example.com", "team": "T0000001"}},
        "entity": entity or {"type": "user", "user": {"id": "W0000002", "name": "bob"}},
        "context": {
            "location": {"type": "enterprise", "id": "E0001", "name": "Example", "domain": "example"},
            "ua": "Mozilla/5.0",
            "ip_address": "203.0.113.5",
        },
    }


def _sfdc(action: str, section: str = "Manage Users") -> dict[str, Any]:
    """A SetupAuditTrail row, in the shape the REST query returns it."""
    return {
        "attributes": {"type": "SetupAuditTrail", "url": "/services/data/v60.0/sobjects/SetupAuditTrail/0Ym000000000001"},
        "Id": "0Ym000000000001",
        "Action": action,
        "Section": section,
        "Display": f"{action} recorded by the setup audit trail",
        "CreatedDate": "2026-11-01T10:00:00.000+0000",
        "CreatedById": "005000000000001",
        "DelegateUser": "admin@example.com",
    }


def _snowflake_login(**overrides: Any) -> dict[str, Any]:
    """A LOGIN_HISTORY row, in the shape ACCOUNT_USAGE returns it."""
    row = {
        "EVENT_ID": "1",
        "EVENT_TIMESTAMP": "2026-11-01T10:00:00Z",
        "USER_NAME": "ANALYST",
        "CLIENT_IP": "203.0.113.5",
        "REPORTED_CLIENT_TYPE": "SNOWFLAKE_UI",
        "FIRST_AUTHENTICATION_FACTOR": "PASSWORD",
        "SECOND_AUTHENTICATION_FACTOR": None,
        "IS_SUCCESS": "YES",
        "ERROR_CODE": None,
        "ERROR_MESSAGE": None,
    }
    row.update(overrides)
    return row


def _snowflake_query(query_type: str, **overrides: Any) -> dict[str, Any]:
    """A QUERY_HISTORY row, in the shape ACCOUNT_USAGE returns it."""
    row = {
        "QUERY_ID": "1",
        "START_TIME": "2026-11-01T10:00:00Z",
        "USER_NAME": "ANALYST",
        "ROLE_NAME": "ANALYST_ROLE",
        "WAREHOUSE_NAME": "WH_ANALYTICS",
        "DATABASE_NAME": "PROD",
        "SCHEMA_NAME": "PUBLIC",
        "QUERY_TYPE": query_type,
        "EXECUTION_STATUS": "SUCCESS",
        "ROWS_PRODUCED": 10,
        "BYTES_SCANNED": 1024,
    }
    row.update(overrides)
    return row


def _box(event_type: str, additional: dict[str, Any] | None = None) -> dict[str, Any]:
    """An Enterprise Events entry, in the shape the Events API returns it."""
    return {
        "type": "event",
        "event_id": "proof",
        "created_at": "2026-11-01T10:00:00-00:00",
        "event_type": event_type,
        "ip_address": "203.0.113.5",
        "created_by": {"type": "user", "id": "11", "name": "Alice", "login": "alice@example.com"},
        "source": {
            "item_type": "file",
            "item_id": "f1",
            "item_name": "forecast.xlsx",
            "parent": {"id": "0"},
            "owned_by": {"login": "alice@example.com"},
        },
        "additional_details": additional or {},
    }


def _dropbox(tag: str) -> dict[str, Any]:
    """A team event, in the shape team_log/get_events returns it."""
    return {
        "timestamp": "2026-11-01T10:00:00Z",
        "event_category": {".tag": "sharing"},
        "event_type": {".tag": tag, "description": tag.replace("_", " ")},
        "actor": {
            ".tag": "user",
            "user": {
                ".tag": "team_member",
                "account_id": "a1",
                "display_name": "Alice",
                "email": "alice@example.com",
                "team_member_id": "m1",
            },
        },
        "origin": {"geo_location": {"ip_address": "203.0.113.5", "city": "Austin", "country": "US"}, "access_method": {".tag": "end_user"}},
        "assets": [{".tag": "file", "path": {"contextual": "/forecast.xlsx"}}],
    }


def _onepassword(category: str, signin_type: str | None = None) -> dict[str, Any]:
    """A sign-in attempt, in the shape the Events API returns it."""
    return {
        "uuid": "proof",
        "session_uuid": "s1",
        "timestamp": "2026-11-01T10:00:00Z",
        "category": category,
        "type": signin_type or category,
        "country": "US",
        "target_user": {"uuid": "u1", "email": "alice@example.com", "name": "Alice"},
        "client": {
            "app_name": "1Password for Mac",
            "app_version": "8.10.0",
            "platform_name": "macOS",
            "os_name": "macOS",
            "ip_address": "203.0.113.5",
        },
    }


_GWS_DRIVE_VISIBILITY: list[dict[str, Any]] = [
    {"name": "visibility", "value": "public_on_the_web"},
    {"name": "doc_title", "value": "Forecast"},
]
_GWS_DRIVE_EXTERNAL: list[dict[str, Any]] = [
    {"name": "visibility", "value": "shared_externally"},
    {"name": "target_user", "value": "outsider@example.net"},
]
_GWS_OAUTH_SCOPES: list[dict[str, Any]] = [
    {"name": "client_id", "value": "100000000000.apps.googleusercontent.com"},
    {"name": "app_name", "value": "Unvetted Exporter"},
    {"name": "scope", "multiValue": ["https://www.googleapis.com/auth/gmail.readonly", "https://www.googleapis.com/auth/calendar"]},
]

#: One real-shaped payload per rule slug, and the derived fields the engine
#: would have stamped for that event. The payload carries the vendor's own
#: event name in the vendor's own envelope — it is never built from the
#: rule's `match_when`.
PROOF_EVENTS: dict[str, tuple[str, dict[str, Any], dict[str, Any]]] = {
    # ---- workspace-takeover -------------------------------------------
    "gws-recovery-email-edited": ("google_workspace", _gws("login", "recovery_email_edit"), {}),
    "gws-recovery-phone-edited": ("google_workspace", _gws("login", "recovery_phone_edit"), {}),
    "gws-2sv-disabled-by-user": ("google_workspace", _gws("login", "2sv_disable"), {}),
    "gws-2sv-unenrolled-by-admin": ("google_workspace", _gws("admin", "UNENROLL_USER_FROM_STRONG_AUTH"), {}),
    "gws-strong-auth-enforcement-relaxed": ("google_workspace", _gws("admin", "ALLOW_STRONG_AUTHENTICATION"), {}),
    "gws-reauth-from-anonymizer": ("google_workspace", _gws("login", "login_success"), {"ip_class": "tor_exit"}),
    "gws-suspicious-login-flagged": ("google_workspace", _gws("login", "suspicious_login"), {}),
    "gws-suspicious-programmatic-login": ("google_workspace", _gws("login", "suspicious_programmatic_login"), {}),
    "gws-less-secure-app-login": ("google_workspace", _gws("login", "suspicious_login_less_secure_app"), {}),
    "gws-gov-attack-warning": ("google_workspace", _gws("login", "gov_attack_warning"), {}),
    "gws-account-disabled-password-leak": ("google_workspace", _gws("login", "account_disabled_password_leak"), {}),
    "gws-oauth-grant-mail-or-drive-scope": ("google_workspace", _gws("token", "authorize", _GWS_OAUTH_SCOPES), {}),
    "gws-email-monitor-created": ("google_workspace", _gws("admin", "CREATE_EMAIL_MONITOR"), {}),
    "gws-super-admin-granted": ("google_workspace", _gws("admin", "GRANT_ADMIN_PRIVILEGE"), {}),
    "gws-delegated-admin-granted": ("google_workspace", _gws("admin", "DELEGATE_ADMIN_PRIVILEGES"), {}),
    "gws-admin-role-assigned": ("google_workspace", _gws("admin", "ASSIGN_ROLE"), {}),
    "gws-drive-visibility-opened-publicly": ("google_workspace", _gws("drive", "change_document_visibility", _GWS_DRIVE_VISIBILITY), {}),
    "gws-drive-external-access-granted": ("google_workspace", _gws("drive", "change_user_access", _GWS_DRIVE_EXTERNAL), {}),
    "gws-drive-link-sharing-created": ("google_workspace", _gws("drive", "create_link_sharing"), {}),
    "gws-shared-drive-settings-weakened": ("google_workspace", _gws("drive", "shared_drive_settings_change"), {}),
    "gws-mobile-device-compromised": ("google_workspace", _gws("mobile", "DEVICE_COMPROMISED_EVENT"), {}),
    # ---- apps-script-impersonation ------------------------------------
    "gcp-apps-script-project-created-by-user": (
        "gcp_cloud_audit",
        _gcp("CreateProject", "cloudresourcemanager.googleapis.com", "sys-01234567890123456789"),
        {},
    ),
    "gcp-sys-project-iam-policy-set": (
        "gcp_cloud_audit",
        _gcp("SetIamPolicy", "cloudresourcemanager.googleapis.com", "sys-01234567890123456789"),
        {},
    ),
    "gcp-sys-project-sa-key-created": (
        "gcp_cloud_audit",
        _gcp("google.iam.admin.v1.CreateServiceAccountKey", "iam.googleapis.com", "sys-01234567890123456789"),
        {},
    ),
    "gcp-apps-script-user-agent-outside-service": (
        "gcp_cloud_audit",
        _gcp(
            "CreateProject", "cloudresourcemanager.googleapis.com", "sys-01234567890123456789", agent="Mozilla/5.0 (compatible) apps-script"
        ),
        {},
    ),
    # ---- third-party-access -------------------------------------------
    "slack-app-installed-broad-read-scopes": (
        "slack_audit",
        _slack(
            "app_installed",
            {
                "type": "app",
                "app": {"id": "A1", "name": "Unvetted Exporter", "is_distributed": False, "scopes": ["files:read", "chat:write"]},
            },
        ),
        {},
    ),
    "slack-app-scopes-expanded": (
        "slack_audit",
        _slack("app_scopes_expanded", {"type": "app", "app": {"id": "A1", "name": "Exporter", "scopes": ["files:read"]}}),
        {},
    ),
    "slack-app-uninstalled": ("slack_audit", _slack("app_uninstalled", {"type": "app", "app": {"id": "A1", "name": "Exporter"}}), {}),
    "slack-external-shared-channel-connected": (
        "slack_audit",
        _slack(
            "external_shared_channel_connected",
            {
                "type": "channel",
                "channel": {"id": "C1", "name": "partners", "privacy": "public", "is_shared": True, "is_org_shared": False},
            },
        ),
        {},
    ),
    "slack-org-export-started": ("slack_audit", _slack("organization_export_started"), {}),
    "slack-role-change-to-owner": ("slack_audit", _slack("role_change_to_owner"), {}),
    "slack-role-change-to-admin": ("slack_audit", _slack("role_change_to_admin"), {}),
    "slack-sso-setting-changed": ("slack_audit", _slack("pref.sso_setting_changed"), {}),
    "slack-two-factor-policy-changed": ("slack_audit", _slack("pref.two_factor_auth_changed"), {}),
    "slack-session-invalidation-disabled": ("slack_audit", _slack("user_session_invalidation_disabled"), {}),
    "slack-message-deletion-allowed": ("slack_audit", _slack("pref.allow_message_deletion"), {}),
    "slack-channel-converted-to-private": (
        "slack_audit",
        _slack(
            "channel_converted_to_private",
            {
                "type": "channel",
                "channel": {"id": "C1", "name": "secrets", "privacy": "private", "is_shared": False, "is_org_shared": False},
            },
        ),
        {},
    ),
    "slack-guest-created": ("slack_audit", _slack("guest_created"), {}),
    "slack-public-url-updated": ("slack_audit", _slack("workspace_public_url_updated"), {}),
    "slack-file-downloaded-from-anonymizer": (
        "slack_audit",
        _slack("file_downloaded", {"type": "file", "file": {"id": "F1", "name": "forecast.xlsx", "filetype": "xlsx"}}),
        {"ip_class": "vpn"},
    ),
    "sfdc-connected-app-installed": ("salesforce", _sfdc("insertConnectedApplication", "Connected Apps"), {}),
    "sfdc-connected-app-updated": ("salesforce", _sfdc("updatedConnectedApplication", "Connected Apps"), {}),
    "sfdc-login-as-user": ("salesforce", _sfdc("suOrgAdminLogin", "Login As User"), {}),
    "sfdc-permission-set-assigned": ("salesforce", _sfdc("PermSetAssign"), {}),
    "sfdc-permission-set-created": ("salesforce", _sfdc("PermSetCreate"), {}),
    "sfdc-profile-changed": ("salesforce", _sfdc("changedProfile"), {}),
    "sfdc-data-export-scheduled": ("salesforce", _sfdc("dataExport", "Data Export"), {}),
    "sfdc-login-policy-changed": ("salesforce", _sfdc("loginPolicyChanged", "Session Settings"), {}),
    "sfdc-certificate-inserted": ("salesforce", _sfdc("insertCertificate", "Certificate and Key Management"), {}),
    # ---- saas-data-movement -------------------------------------------
    "box-shared-link-opened-publicly": ("box", _box("SHARE", {"shared_link": {"access": "open"}}), {}),
    "box-item-shared-link-created": ("box", _box("ITEM_SHARED_LINK"), {}),
    "box-external-collab-invite-blocked": ("box", _box("SHIELD_EXTERNAL_COLLAB_INVITE_BLOCKED"), {}),
    "box-external-collab-abnormal-location": ("box", _box("SHIELD_EXTERNAL_COLLAB_INVITE_ABNORMAL_LOCATION"), {}),
    "box-shield-alert": ("box", _box("SHIELD_ALERT"), {}),
    "box-admin-role-granted": ("box", _box("ROLE_CHANGE_TO_ADMIN"), {}),
    "box-app-public-key-added": ("box", _box("APPLICATION_PUBLIC_KEY_ADDED"), {}),
    "box-app-public-key-deleted": ("box", _box("APPLICATION_PUBLIC_KEY_DELETED"), {}),
    "box-login-from-anonymizer": ("box", _box("USER_LOGIN"), {"ip_class": "hosting_provider"}),
    "box-user-deleted": ("box", _box("DELETE_USER"), {}),
    "dropbox-link-audience-changed-to-public": ("dropbox", _dropbox("shared_content_change_link_audience_to_public"), {}),
    "dropbox-shared-content-downloaded": ("dropbox", _dropbox("shared_content_download"), {}),
    "dropbox-shared-content-member-removed": ("dropbox", _dropbox("shared_content_remove_member"), {}),
    "dropbox-team-invite-link-created": ("dropbox", _dropbox("team_member_create_team_invite_link"), {}),
    "dropbox-admin-role-changed": ("dropbox", _dropbox("member_change_admin_role"), {}),
    "dropbox-sso-policy-changed": ("dropbox", _dropbox("sso_change_policy"), {}),
    "dropbox-app-linked-to-team": ("dropbox", _dropbox("app_link_team"), {}),
    "dropbox-team-folder-status-changed": ("dropbox", _dropbox("team_folder_change_status"), {}),
    "dropbox-external-password-unmasked": ("dropbox", _dropbox("account_external_password_unmask"), {}),
    "dropbox-device-linked-from-anonymizer": ("dropbox", _dropbox("device_link_success"), {"ip_class": "public_proxy"}),
    "snowflake-bulk-rows-produced": ("snowflake", _snowflake_query("SELECT", ROWS_PRODUCED=4_200_000), {}),
    "snowflake-unload-to-stage": ("snowflake", _snowflake_query("UNLOAD"), {}),
    "snowflake-grant-executed": ("snowflake", _snowflake_query("GRANT"), {}),
    "snowflake-create-user": ("snowflake", _snowflake_query("CREATE_USER"), {}),
    # ---- saas-authentication-abuse ------------------------------------
    "snowflake-login-single-factor-service-user": ("snowflake", _snowflake_login(), {}),
    "snowflake-login-failed-bad-credentials": (
        "snowflake",
        _snowflake_login(IS_SUCCESS="NO", ERROR_CODE="390100", ERROR_MESSAGE="Incorrect username or password was specified."),
        {},
    ),
    "snowflake-login-from-anonymizer": ("snowflake", _snowflake_login(), {"ip_class": "hosting_provider"}),
    "snowflake-driver-change-for-user": ("snowflake", _snowflake_login(REPORTED_CLIENT_TYPE="JDBC_DRIVER"), {}),
    "1p-credentials-failed": ("onepassword", _onepassword("credentials_failed", "password_secret_bad"), {}),
    "1p-mfa-failed": ("onepassword", _onepassword("mfa_failed", "totp_bad"), {}),
    "1p-firewall-blocked": ("onepassword", _onepassword("firewall_failed", "country_blocked"), {}),
    "1p-firewall-reported-success": ("onepassword", _onepassword("firewall_reported_success", "credentials_ok"), {}),
    "1p-modern-version-failed": ("onepassword", _onepassword("modern_version_failed", "modern_version_old"), {}),
    "1p-signin-from-anonymizer": ("onepassword", _onepassword("success", "credentials_ok"), {"ip_class": "tor_exit"}),
}


def _family_specs() -> list[tuple[str, dict[str, Any]]]:
    """Every scenario-family spec, from both authoring passes.

    The second pass carries its proof payload on the spec itself rather than
    in `PROOF_EVENTS`, so a rule edited without its proof fails immediately
    instead of drifting from a distant table. Both are read here and the
    checks below do not care which arrangement a spec uses.
    """
    from detection_specs_part5_families import BY_CATEGORY  # noqa: PLC0415 — scripts/ sibling, path set above
    from detection_specs_part6_coverage import BY_CATEGORY as COVERAGE  # noqa: PLC0415

    out = [(category, spec) for category, specs in BY_CATEGORY.items() for spec in specs]
    out += [(category, spec) for category, specs in COVERAGE.items() for spec in specs]
    return out


def _proofs_for(specs: list[tuple[str, dict[str, Any]]]) -> dict[str, tuple[str, dict[str, Any], dict[str, Any]]]:
    """`PROOF_EVENTS` plus every proof a spec carries on itself."""
    merged = dict(PROOF_EVENTS)
    for _category, spec in specs:
        carried = spec.get("proof")
        if carried:
            emitter, payload = carried
            merged[str(spec["slug"])] = (emitter, payload, spec.get("proof_derived") or {})
    return merged


def _normalize_batch(entries: list[tuple[str, dict[str, Any]]]) -> list[dict[str, Any] | None]:
    lines = "\n".join(json.dumps({"emitter": emitter, "raw": raw}) for emitter, raw in entries)
    done = subprocess.run(  # noqa: S603
        [sys.executable, str(WORKER)],
        input=lines,
        capture_output=True,
        text=True,
        check=True,
    )
    out: list[dict[str, Any] | None] = []
    for line in done.stdout.strip().splitlines():
        if not line.strip():
            continue
        res = json.loads(line)
        out.append(res["normalized"] if res.get("ok") else None)
    if len(out) != len(entries):
        raise SystemExit(f"connector worker returned {len(out)} results for {len(entries)} inputs")
    return out


def check(specs: list[tuple[str, dict[str, Any]]], proofs: dict[str, tuple[str, dict[str, Any], dict[str, Any]]]) -> list[str]:
    """Every problem that stops a scenario-family rule being proven."""
    sys.path.insert(0, str(ROOT / "services" / "fusion"))
    from app.services.detection_matcher import matches  # noqa: PLC0415 — package collision, see module docstring
    from vendor_event_vocabulary import unknown_names  # noqa: PLC0415 — scripts/ sibling

    problems: list[str] = []

    covered = [(category, spec) for category, spec in specs if (spec.get("log_source") or {}).get("product") in PRODUCT_EMITTER]
    for category, spec in covered:
        slug = str(spec["slug"])
        if slug not in proofs:
            problems.append(
                f"{category}/{slug}: no proof entry. Add a real-shaped vendor payload to "
                "PROOF_EVENTS so the rule is proven against the connector, not against a copy of itself."
            )

    # Vocabulary: a name the vendor does not publish can never arrive.
    for category, spec in covered:
        product = (spec["log_source"] or {}).get("product", "")
        for bad in unknown_names(product, spec["match_when"]):
            problems.append(
                f"{category}/{spec['slug']}: {bad!r} is not in {product}'s published vocabulary (scripts/vendor_event_vocabulary.py)"
            )

    provable = [(c, s) for c, s in covered if str(s["slug"]) in proofs]
    if not provable:
        # An empty corpus must fail rather than report success: that is how a
        # route-parity gate once compared zero pairs and printed OK.
        problems.append("no scenario-family rule had a proof entry — the gate would have passed over an empty corpus")
        return problems

    entries = [(proofs[str(s["slug"])][0], proofs[str(s["slug"])][1]) for _, s in provable]
    normalized = _normalize_batch(entries)

    for (category, spec), result in zip(provable, normalized, strict=True):
        slug = str(spec["slug"])
        if result is None:
            problems.append(f"{category}/{slug}: the connector rejected its proof payload")
            continue
        namespace = {k: v for k, v in result.items() if k != "raw_event"}
        nested = result.get("raw_event")
        if isinstance(nested, dict):
            for key, value in nested.items():
                namespace.setdefault(key, value)
        # Derived fields are stamped by fusion before the matcher runs, not
        # by the connector. Supplying them here keeps the proof honest about
        # which half produced which value.
        for key, value in proofs[slug][2].items():
            if key not in DERIVED_FIELDS:
                problems.append(f"{category}/{slug}: {key!r} is listed as derived but is not a field fusion derives")
            namespace[key] = value
        if not matches(spec["match_when"], namespace):
            missing = sorted(k for k in spec.get("fields", ()) if k not in namespace)
            detail = f" (absent from the namespace: {', '.join(missing)})" if missing else ""
            problems.append(f"{category}/{slug}: did not fire on its real-shaped payload through the real connector{detail}")

    return problems


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--list", action="store_true", help="name every rule and whether it is covered")
    parser.add_argument("--self-test", action="store_true", help="run the gate's own tests")
    args = parser.parse_args(argv)
    if args.self_test:
        return self_test_main(Path(__file__).name)

    specs = _family_specs()
    if args.list:
        for category, spec in sorted(specs, key=lambda cs: (cs[0], cs[1]["slug"])):
            product = (spec.get("log_source") or {}).get("product", "")
            state = "covered" if product in PRODUCT_EMITTER else f"NOT COVERED (no emitter for {product!r})"
            print(f"  {category}/{spec['slug']:48} {state}")
        return 0

    problems = check(specs, _proofs_for(specs))
    if problems:
        print("scenario family alignment: FAILED\n", file=sys.stderr)
        for problem in problems:
            print(f"  {problem}", file=sys.stderr)
        print("", file=sys.stderr)
        return 1
    covered = sum(1 for _, s in specs if (s.get("log_source") or {}).get("product") in PRODUCT_EMITTER)
    print(f"scenario family alignment: OK — {covered} rules fired through their real connector and the real engine")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
