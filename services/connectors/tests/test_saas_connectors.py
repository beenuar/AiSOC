"""
Unit tests for the four SaaS connectors landed in the connectors PR:

- ``m365_audit`` — Microsoft 365 Management Activity API
- ``google_workspace`` — Admin SDK Reports API
- ``cloudflare`` — Account audit logs
- ``github`` — Org audit log + Code Scanning alerts

The shape mirrors ``test_azure_connectors.py`` and ``test_gcp_connectors.py``:
schema sanity, normalize() severity rules, then HTTP routing through respx.

For ``google_workspace`` we reuse the GCP-style fake-service-account JSON
fixture (real RS256 signing, mocked token endpoint) so the JWT path is
actually exercised — the ``sub`` claim for domain-wide delegation is the
single most-broken piece of Workspace integrations and needs to round-trip
through real signing to be useful.
"""

from __future__ import annotations

import json

import httpx
import pytest
import respx
from app.connectors.cloudflare import CloudflareConnector
from app.connectors.github import GitHubConnector
from app.connectors.google_workspace import GoogleWorkspaceConnector
from app.connectors.m365_audit import M365AuditConnector
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

_TENANT = "00000000-0000-0000-0000-000000000000"
_CLIENT_ID = "11111111-1111-1111-1111-111111111111"
_CLIENT_SECRET = "super-secret"
_ACCOUNT_ID = "abc123def456"
_TOKEN = "ghp_fakeFakeFakeFakeFakeFakeFakeFake"
_ORG = "aisoc-test-org"
_ADMIN_EMAIL = "audit-bot@example.com"


# ---------------------------------------------------------------------------
# Fake Workspace service-account JSON — module-scope to avoid paying the
# 2048-bit RSA generation cost on every test.
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def fake_workspace_sa_json() -> str:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("ascii")
    return json.dumps(
        {
            "type": "service_account",
            "project_id": "aisoc-workspace",
            "private_key_id": "abc123",
            "private_key": pem,
            "client_email": "audit-bot@aisoc-workspace.iam.gserviceaccount.com",
            "client_id": "111111111111111111111",
            "token_uri": "https://oauth2.googleapis.com/token",
        }
    )


# ===========================================================================
# M365 Audit
# ===========================================================================


def test_m365_audit_schema_has_required_fields():
    schema = M365AuditConnector.schema()
    field_names = {f.name for f in schema.fields}
    assert {"tenant_id", "client_id", "client_secret"} <= field_names
    assert schema.category == "saas"
    secret = next(f for f in schema.fields if f.name == "client_secret")
    assert secret.type == "secret"


def test_m365_audit_schema_advertises_hosted_oauth():
    # M365 has a real Azure AD OAuth flow — distinct from the GCP/Workspace
    # service-account model — so the frontend should be told this is a
    # candidate for hosted OAuth in a follow-up.
    schema = M365AuditConnector.schema()
    assert schema.oauth is not None
    assert schema.oauth.supported_in_hosted is True
    assert "ActivityFeed.Read" in (schema.oauth.scopes or [""])[0]


def test_m365_normalize_high_risk_op_is_high():
    connector = M365AuditConnector(_TENANT, _CLIENT_ID, _CLIENT_SECRET)
    raw = {
        "Id": "evt-1",
        "Operation": "Add member to role",
        "Workload": "AzureActiveDirectory",
        "ResultStatus": "Success",
        "UserId": "alice@example.com",
        "ClientIP": "1.2.3.4",
        "CreationTime": "2026-01-01T00:00:00Z",
    }
    out = connector.normalize(raw)
    assert out["source"] == "m365_audit"
    assert out["severity"] == "high"
    assert out["actor_email"] == "alice@example.com"
    assert out["src_ip"] == "1.2.3.4"


def test_m365_normalize_inboxrule_is_high_bec_indicator():
    # BEC playbook: attacker compromises mailbox, sets a forwarding rule.
    # New-InboxRule must be high regardless of result_status.
    connector = M365AuditConnector(_TENANT, _CLIENT_ID, _CLIENT_SECRET)
    raw = {
        "Id": "evt-2",
        "Operation": "New-InboxRule",
        "Workload": "Exchange",
        "ResultStatus": "Success",
        "UserId": "victim@example.com",
    }
    out = connector.normalize(raw)
    assert out["severity"] == "high"


def test_m365_normalize_failed_login_is_low():
    connector = M365AuditConnector(_TENANT, _CLIENT_ID, _CLIENT_SECRET)
    raw = {
        "Id": "evt-3",
        "Operation": "UserLoggedIn",
        "Workload": "AzureActiveDirectory",
        "ResultStatus": "Failed",
        "UserId": "bob@example.com",
    }
    out = connector.normalize(raw)
    # Failed logins land at low so spray detections can multiply them up.
    assert out["severity"] == "low"


def test_m365_normalize_admin_routine_op_bumps_to_low():
    # Plain "info" admin actions should escalate one notch when UserType is
    # admin (2) or DcAdmin (3). Operator activity is always higher-stakes.
    connector = M365AuditConnector(_TENANT, _CLIENT_ID, _CLIENT_SECRET)
    raw = {
        "Id": "evt-4",
        "Operation": "FilePreviewed",
        "Workload": "SharePoint",
        "ResultStatus": "Success",
        "UserId": "admin@example.com",
        "UserType": 2,
    }
    out = connector.normalize(raw)
    assert out["severity"] == "low"


def test_m365_normalize_routine_user_op_is_info():
    connector = M365AuditConnector(_TENANT, _CLIENT_ID, _CLIENT_SECRET)
    raw = {
        "Id": "evt-5",
        "Operation": "FileAccessed",
        "Workload": "SharePoint",
        "ResultStatus": "Success",
        "UserId": "alice@example.com",
        "UserType": 0,
    }
    out = connector.normalize(raw)
    assert out["severity"] == "info"
    assert out["event_type"].startswith("m365.sharepoint.")


@pytest.mark.asyncio
@respx.mock
async def test_m365_test_connection_success():
    respx.post(
        f"https://login.microsoftonline.com/{_TENANT}/oauth2/v2.0/token"
    ).mock(return_value=httpx.Response(200, json={"access_token": "tok-abc"}))
    respx.get(
        f"https://manage.office.com/api/v1.0/{_TENANT}/activity/feed/subscriptions/list"
    ).mock(
        return_value=httpx.Response(
            200,
            json=[
                {"contentType": "Audit.AzureActiveDirectory", "status": "enabled"},
                {"contentType": "Audit.Exchange", "status": "disabled"},
            ],
        )
    )

    connector = M365AuditConnector(_TENANT, _CLIENT_ID, _CLIENT_SECRET)
    result = await connector.test_connection()
    assert result["success"] is True
    assert result["tenant_id"] == _TENANT
    # Only enabled subscriptions surface; disabled ones are filtered out.
    assert result["active_subscriptions"] == ["Audit.AzureActiveDirectory"]


@pytest.mark.asyncio
@respx.mock
async def test_m365_test_connection_surfaces_403():
    respx.post(
        f"https://login.microsoftonline.com/{_TENANT}/oauth2/v2.0/token"
    ).mock(return_value=httpx.Response(200, json={"access_token": "tok-abc"}))
    respx.get(
        f"https://manage.office.com/api/v1.0/{_TENANT}/activity/feed/subscriptions/list"
    ).mock(
        return_value=httpx.Response(403, text="ActivityFeed.Read not granted")
    )

    connector = M365AuditConnector(_TENANT, _CLIENT_ID, _CLIENT_SECRET)
    result = await connector.test_connection()
    assert result["success"] is False
    assert "403" in result["error"]


@pytest.mark.asyncio
@respx.mock
async def test_m365_fetch_alerts_pulls_blob_content():
    # The Activity API is a two-step flow: list content blobs, then GET each
    # blob URI. We mock both layers and assert the connector materializes
    # the inner events through normalize().
    respx.post(
        f"https://login.microsoftonline.com/{_TENANT}/oauth2/v2.0/token"
    ).mock(return_value=httpx.Response(200, json={"access_token": "tok-abc"}))

    # Idempotent subscribe on every content type — return 200 OK.
    respx.post(
        f"https://manage.office.com/api/v1.0/{_TENANT}/activity/feed/subscriptions/start"
    ).mock(return_value=httpx.Response(200, json={"contentType": "ok"}))

    blob_uri = "https://manage.office.com/api/v1.0/blob/abc"
    # Only the AzureActiveDirectory listing returns a blob; the rest are
    # empty so we can assert filtering plus de-duplication of empty content
    # types in a single test.
    aad_url = (
        f"https://manage.office.com/api/v1.0/{_TENANT}/activity/feed/subscriptions/content"
    )

    def list_handler(request: httpx.Request) -> httpx.Response:
        if request.url.params.get("contentType") == "Audit.AzureActiveDirectory":
            return httpx.Response(200, json=[{"contentUri": blob_uri, "contentId": "b1"}])
        return httpx.Response(200, json=[])

    respx.get(aad_url).mock(side_effect=list_handler)
    respx.get(blob_uri).mock(
        return_value=httpx.Response(
            200,
            json=[
                {
                    "Id": "evt-1",
                    "Operation": "Add member to role",
                    "Workload": "AzureActiveDirectory",
                    "ResultStatus": "Success",
                    "UserId": "alice@example.com",
                }
            ],
        )
    )

    connector = M365AuditConnector(_TENANT, _CLIENT_ID, _CLIENT_SECRET)
    events = await connector.fetch_alerts(since_seconds=300)
    assert len(events) == 1
    assert events[0]["source"] == "m365_audit"
    assert events[0]["severity"] == "high"


# ===========================================================================
# Google Workspace
# ===========================================================================


def test_workspace_schema_has_required_fields():
    schema = GoogleWorkspaceConnector.schema()
    field_names = {f.name for f in schema.fields}
    assert {"admin_email", "service_account_json"} <= field_names
    assert schema.category == "saas"
    sa = next(f for f in schema.fields if f.name == "service_account_json")
    assert sa.type == "secret"


def test_workspace_schema_oauth_hosted_is_false():
    schema = GoogleWorkspaceConnector.schema()
    assert schema.oauth is not None
    assert schema.oauth.supported_in_hosted is False


def test_workspace_rejects_non_json_service_account():
    with pytest.raises(ValueError, match="not valid JSON"):
        GoogleWorkspaceConnector(_ADMIN_EMAIL, "not-json-at-all")


def test_workspace_rejects_sa_missing_required_fields():
    bad = json.dumps({"client_email": "x@y.iam.gserviceaccount.com"})
    with pytest.raises(ValueError, match="missing required field"):
        GoogleWorkspaceConnector(_ADMIN_EMAIL, bad)


def test_workspace_normalize_grant_admin_is_high(fake_workspace_sa_json):
    connector = GoogleWorkspaceConnector(_ADMIN_EMAIL, fake_workspace_sa_json)
    raw = {
        "_aisoc_application": "admin",
        "id": {"uniqueQualifier": "evt-1", "time": "2026-01-01T00:00:00Z"},
        "actor": {"email": "ceo@example.com"},
        "ipAddress": "1.2.3.4",
        "events": [{"name": "GRANT_ADMIN_PRIVILEGE", "type": "DELEGATED_ADMIN_SETTINGS"}],
    }
    out = connector.normalize(raw)
    assert out["source"] == "google_workspace"
    assert out["severity"] == "high"
    assert out["actor_email"] == "ceo@example.com"
    assert out["src_ip"] == "1.2.3.4"
    assert out["event_type"] == "workspace.admin.grant_admin_privilege"


def test_workspace_normalize_suspicious_login_is_medium(fake_workspace_sa_json):
    connector = GoogleWorkspaceConnector(_ADMIN_EMAIL, fake_workspace_sa_json)
    raw = {
        "_aisoc_application": "login",
        "id": {"uniqueQualifier": "evt-2"},
        "actor": {"email": "alice@example.com"},
        "events": [{"name": "suspicious_login", "type": "login"}],
    }
    out = connector.normalize(raw)
    assert out["severity"] == "medium"


def test_workspace_normalize_failed_login_is_low(fake_workspace_sa_json):
    connector = GoogleWorkspaceConnector(_ADMIN_EMAIL, fake_workspace_sa_json)
    raw = {
        "_aisoc_application": "login",
        "id": {"uniqueQualifier": "evt-3"},
        "actor": {"email": "alice@example.com"},
        "events": [{"name": "login_failure", "type": "login"}],
    }
    out = connector.normalize(raw)
    assert out["severity"] == "low"


def test_workspace_normalize_drive_acl_change_is_medium(fake_workspace_sa_json):
    connector = GoogleWorkspaceConnector(_ADMIN_EMAIL, fake_workspace_sa_json)
    raw = {
        "_aisoc_application": "drive",
        "id": {"uniqueQualifier": "evt-4"},
        "actor": {"email": "alice@example.com"},
        "events": [{"name": "change_acl_editors", "type": "acl_change"}],
    }
    out = connector.normalize(raw)
    assert out["severity"] == "medium"


def test_workspace_normalize_routine_event_is_info(fake_workspace_sa_json):
    connector = GoogleWorkspaceConnector(_ADMIN_EMAIL, fake_workspace_sa_json)
    raw = {
        "_aisoc_application": "drive",
        "id": {"uniqueQualifier": "evt-5"},
        "actor": {"email": "alice@example.com"},
        "events": [{"name": "view", "type": "access"}],
    }
    out = connector.normalize(raw)
    assert out["severity"] == "info"


@pytest.mark.asyncio
@respx.mock
async def test_workspace_test_connection_success(fake_workspace_sa_json):
    respx.post("https://oauth2.googleapis.com/token").mock(
        return_value=httpx.Response(
            200, json={"access_token": "tok-abc", "expires_in": 3600}
        )
    )
    respx.get(
        "https://admin.googleapis.com/admin/reports/v1/activity/users/all/applications/login"
    ).mock(return_value=httpx.Response(200, json={"items": []}))

    connector = GoogleWorkspaceConnector(_ADMIN_EMAIL, fake_workspace_sa_json)
    result = await connector.test_connection()
    assert result["success"] is True
    assert result["admin_email"] == _ADMIN_EMAIL
    assert "service_account" in result


@pytest.mark.asyncio
@respx.mock
async def test_workspace_test_connection_surfaces_403(fake_workspace_sa_json):
    respx.post("https://oauth2.googleapis.com/token").mock(
        return_value=httpx.Response(
            200, json={"access_token": "tok-abc", "expires_in": 3600}
        )
    )
    respx.get(
        "https://admin.googleapis.com/admin/reports/v1/activity/users/all/applications/login"
    ).mock(
        return_value=httpx.Response(
            403, text="The user is not authorized to access this resource"
        )
    )

    connector = GoogleWorkspaceConnector(_ADMIN_EMAIL, fake_workspace_sa_json)
    result = await connector.test_connection()
    assert result["success"] is False
    assert "403" in result["error"]


@pytest.mark.asyncio
@respx.mock
async def test_workspace_fetch_alerts_iterates_apps(fake_workspace_sa_json):
    respx.post("https://oauth2.googleapis.com/token").mock(
        return_value=httpx.Response(
            200, json={"access_token": "tok-abc", "expires_in": 3600}
        )
    )

    # Each ApplicationName has its own URL. We return one event for
    # "admin" and empty for the rest, then assert the connector tagged
    # the event with the right application.
    apps_with_data = {
        "admin": [
            {
                "id": {"uniqueQualifier": "evt-1", "time": "2026-01-01T00:00:00Z"},
                "actor": {"email": "owner@example.com"},
                "events": [{"name": "GRANT_ADMIN_PRIVILEGE"}],
            }
        ],
    }

    def app_handler(request: httpx.Request) -> httpx.Response:
        # URL path ends with .../applications/<app>
        app = request.url.path.rsplit("/", 1)[-1]
        return httpx.Response(200, json={"items": apps_with_data.get(app, [])})

    respx.get(
        url__regex=r"^https://admin\.googleapis\.com/admin/reports/v1/activity/users/all/applications/.*"
    ).mock(side_effect=app_handler)

    connector = GoogleWorkspaceConnector(_ADMIN_EMAIL, fake_workspace_sa_json)
    events = await connector.fetch_alerts(since_seconds=300)
    assert len(events) == 1
    assert events[0]["severity"] == "high"
    assert events[0]["application"] == "admin"


# ===========================================================================
# Cloudflare
# ===========================================================================


def test_cloudflare_schema_has_required_fields():
    schema = CloudflareConnector.schema()
    field_names = {f.name for f in schema.fields}
    assert {"account_id", "api_token"} <= field_names
    assert schema.category == "saas"
    token_field = next(f for f in schema.fields if f.name == "api_token")
    assert token_field.type == "secret"


def test_cloudflare_schema_oauth_hosted_is_false():
    # API-token model only — no hosted OAuth flow.
    schema = CloudflareConnector.schema()
    assert schema.oauth is not None
    assert schema.oauth.supported_in_hosted is False


def test_cloudflare_normalize_token_create_is_high():
    connector = CloudflareConnector(_ACCOUNT_ID, "cf-token")
    raw = {
        "id": "evt-1",
        "when": "2026-01-01T00:00:00Z",
        "action": {"type": "tokenCreate", "result": True},
        "actor": {"email": "ops@example.com", "id": "actor-1", "ip": "1.2.3.4"},
        "resource": {"type": "user", "id": "u-1"},
    }
    out = connector.normalize(raw)
    assert out["source"] == "cloudflare"
    assert out["severity"] == "high"
    assert out["actor_email"] == "ops@example.com"
    assert out["src_ip"] == "1.2.3.4"


def test_cloudflare_normalize_waf_delete_is_high():
    # Disabling/deleting WAF rules is the textbook ATT&CK T1562 pattern.
    connector = CloudflareConnector(_ACCOUNT_ID, "cf-token")
    raw = {
        "id": "evt-2",
        "when": "2026-01-01T00:00:00Z",
        "action": {"type": "wafRuleDelete", "result": True},
        "actor": {"email": "ops@example.com"},
        "resource": {"type": "zone", "id": "z-1"},
    }
    out = connector.normalize(raw)
    assert out["severity"] == "high"


def test_cloudflare_normalize_failed_action_is_low():
    connector = CloudflareConnector(_ACCOUNT_ID, "cf-token")
    raw = {
        "id": "evt-3",
        "when": "2026-01-01T00:00:00Z",
        "action": {"type": "zoneUpdate", "result": False},
        "actor": {"email": "ops@example.com"},
        "resource": {"type": "zone", "id": "z-1"},
    }
    out = connector.normalize(raw)
    assert out["severity"] == "low"


def test_cloudflare_normalize_routine_action_is_info():
    connector = CloudflareConnector(_ACCOUNT_ID, "cf-token")
    raw = {
        "id": "evt-4",
        "when": "2026-01-01T00:00:00Z",
        "action": {"type": "pageRuleUpdate", "result": True},
        "actor": {"email": "ops@example.com"},
        "resource": {"type": "zone", "id": "z-1"},
    }
    out = connector.normalize(raw)
    assert out["severity"] == "info"


@pytest.mark.asyncio
@respx.mock
async def test_cloudflare_test_connection_success():
    respx.get("https://api.cloudflare.com/client/v4/user/tokens/verify").mock(
        return_value=httpx.Response(200, json={"result": {"status": "active"}})
    )
    respx.get(
        f"https://api.cloudflare.com/client/v4/accounts/{_ACCOUNT_ID}/audit_logs"
    ).mock(return_value=httpx.Response(200, json={"result": []}))

    connector = CloudflareConnector(_ACCOUNT_ID, "cf-token")
    result = await connector.test_connection()
    assert result["success"] is True
    assert result["account_id"] == _ACCOUNT_ID


@pytest.mark.asyncio
@respx.mock
async def test_cloudflare_test_connection_inactive_token_fails():
    respx.get("https://api.cloudflare.com/client/v4/user/tokens/verify").mock(
        return_value=httpx.Response(200, json={"result": {"status": "expired"}})
    )

    connector = CloudflareConnector(_ACCOUNT_ID, "cf-token")
    result = await connector.test_connection()
    assert result["success"] is False
    assert "expired" in result["error"]


@pytest.mark.asyncio
@respx.mock
async def test_cloudflare_test_connection_missing_audit_perm_fails():
    respx.get("https://api.cloudflare.com/client/v4/user/tokens/verify").mock(
        return_value=httpx.Response(200, json={"result": {"status": "active"}})
    )
    respx.get(
        f"https://api.cloudflare.com/client/v4/accounts/{_ACCOUNT_ID}/audit_logs"
    ).mock(return_value=httpx.Response(403, text="missing scope"))

    connector = CloudflareConnector(_ACCOUNT_ID, "cf-token")
    result = await connector.test_connection()
    assert result["success"] is False
    assert "audit_logs failed" in result["error"]


@pytest.mark.asyncio
@respx.mock
async def test_cloudflare_fetch_alerts_returns_normalized_events():
    respx.get(
        f"https://api.cloudflare.com/client/v4/accounts/{_ACCOUNT_ID}/audit_logs"
    ).mock(
        return_value=httpx.Response(
            200,
            json={
                "result": [
                    {
                        "id": "evt-1",
                        "when": "2026-01-01T00:00:00Z",
                        "action": {"type": "tokenCreate", "result": True},
                        "actor": {
                            "email": "ops@example.com",
                            "id": "actor-1",
                            "ip": "1.2.3.4",
                        },
                        "resource": {"type": "user", "id": "u-1"},
                    }
                ]
            },
        )
    )

    connector = CloudflareConnector(_ACCOUNT_ID, "cf-token")
    events = await connector.fetch_alerts(since_seconds=300)
    assert len(events) == 1
    assert events[0]["source"] == "cloudflare"
    assert events[0]["severity"] == "high"


@pytest.mark.asyncio
@respx.mock
async def test_cloudflare_fetch_alerts_returns_empty_on_500():
    respx.get(
        f"https://api.cloudflare.com/client/v4/accounts/{_ACCOUNT_ID}/audit_logs"
    ).mock(return_value=httpx.Response(500, text="bad gateway"))

    connector = CloudflareConnector(_ACCOUNT_ID, "cf-token")
    events = await connector.fetch_alerts(since_seconds=300)
    assert events == []


# ===========================================================================
# GitHub
# ===========================================================================


def test_github_schema_has_required_fields():
    schema = GitHubConnector.schema()
    field_names = {f.name for f in schema.fields}
    assert {"organization", "token"} <= field_names
    # vcs is the more precise category — GitHub is a version-control SaaS,
    # not a generic SaaS platform — and the schema test allows it.
    assert schema.category == "vcs"
    token_field = next(f for f in schema.fields if f.name == "token")
    assert token_field.type == "secret"


def test_github_schema_oauth_hosted_is_false():
    # We accept tokens directly. The hosted device-flow OAuth is a follow-up.
    schema = GitHubConnector.schema()
    assert schema.oauth is not None
    assert schema.oauth.supported_in_hosted is False
    assert "read:audit_log" in (schema.oauth.scopes or [])


def test_github_normalize_audit_high_risk_action_is_high():
    connector = GitHubConnector(_ORG, _TOKEN)
    raw = {
        "_aisoc_stream": "audit_log",
        "_document_id": "doc-1",
        "@timestamp": 1735689600000,
        "action": "org.update_member",
        "actor": "alice",
        "user_email": "alice@example.com",
        "actor_ip": "1.2.3.4",
        "repo": "aisoc/aisoc",
        "org": _ORG,
    }
    out = connector.normalize(raw)
    assert out["source"] == "github"
    assert out["severity"] == "high"
    assert out["actor_email"] == "alice@example.com"
    assert out["src_ip"] == "1.2.3.4"
    assert out["event_type"] == "github.org.update_member"


def test_github_normalize_secret_scanning_disable_is_high():
    connector = GitHubConnector(_ORG, _TOKEN)
    raw = {
        "_aisoc_stream": "audit_log",
        "@timestamp": 1735689600000,
        "action": "secret_scanning.disable",
        "actor": "attacker",
    }
    out = connector.normalize(raw)
    assert out["severity"] == "high"


def test_github_normalize_unknown_destroy_is_medium():
    # We don't enumerate every ``.destroy`` action in HIGH_RISK_ACTIONS,
    # so the catch-all suffix rule should land them at medium.
    connector = GitHubConnector(_ORG, _TOKEN)
    raw = {
        "_aisoc_stream": "audit_log",
        "@timestamp": 1735689600000,
        "action": "team.destroy",
        "actor": "alice",
    }
    out = connector.normalize(raw)
    assert out["severity"] == "medium"


def test_github_normalize_routine_action_is_info():
    connector = GitHubConnector(_ORG, _TOKEN)
    raw = {
        "_aisoc_stream": "audit_log",
        "@timestamp": 1735689600000,
        "action": "issues.opened",
        "actor": "alice",
    }
    out = connector.normalize(raw)
    assert out["severity"] == "info"


def test_github_normalize_code_scanning_critical_collapses_to_high():
    connector = GitHubConnector(_ORG, _TOKEN)
    raw = {
        "_aisoc_stream": "code_scanning",
        "number": 42,
        "created_at": "2026-01-01T00:00:00Z",
        "rule": {
            "id": "py/sql-injection",
            "description": "SQL injection",
            "security_severity_level": "critical",
            "severity": "error",
        },
        "repository": {"full_name": "aisoc/aisoc"},
        "tool": {"name": "CodeQL"},
        "most_recent_instance": {"location": {"path": "src/db.py"}},
    }
    out = connector.normalize(raw)
    assert out["severity"] == "high"
    assert out["external_id"] == "code-scanning-42"
    assert out["title"].startswith("Code Scanning:")
    assert out["event_type"] == "github.code_scanning.py/sql-injection"


def test_github_normalize_code_scanning_low_is_low():
    connector = GitHubConnector(_ORG, _TOKEN)
    raw = {
        "_aisoc_stream": "code_scanning",
        "number": 7,
        "created_at": "2026-01-01T00:00:00Z",
        "rule": {
            "id": "py/style",
            "security_severity_level": "low",
            "severity": "warning",
        },
        "repository": {"full_name": "aisoc/aisoc"},
        "tool": {"name": "CodeQL"},
        "most_recent_instance": {"location": {"path": "src/x.py"}},
    }
    out = connector.normalize(raw)
    assert out["severity"] == "low"


def test_github_normalize_code_scanning_unknown_severity_falls_back_to_info():
    connector = GitHubConnector(_ORG, _TOKEN)
    raw = {
        "_aisoc_stream": "code_scanning",
        "number": 99,
        "created_at": "2026-01-01T00:00:00Z",
        "rule": {"id": "rule-x"},
        "repository": {"full_name": "aisoc/aisoc"},
    }
    out = connector.normalize(raw)
    assert out["severity"] == "info"


@pytest.mark.asyncio
@respx.mock
async def test_github_test_connection_success_with_audit_log():
    respx.get(f"https://api.github.com/orgs/{_ORG}").mock(
        return_value=httpx.Response(200, json={"login": _ORG})
    )
    respx.get(f"https://api.github.com/orgs/{_ORG}/audit-log").mock(
        return_value=httpx.Response(200, json=[])
    )

    connector = GitHubConnector(_ORG, _TOKEN)
    result = await connector.test_connection()
    assert result["success"] is True
    assert result["organization"] == _ORG
    assert result["audit_log_available"] is True


@pytest.mark.asyncio
@respx.mock
async def test_github_test_connection_succeeds_when_audit_log_404():
    # An org on a Free/Team plan returns 404 for the audit log endpoint.
    # That's a legitimate operational state — we still consider the
    # connector "connected" but flag audit_log_available = False so the
    # frontend can warn the operator.
    respx.get(f"https://api.github.com/orgs/{_ORG}").mock(
        return_value=httpx.Response(200, json={"login": _ORG})
    )
    respx.get(f"https://api.github.com/orgs/{_ORG}/audit-log").mock(
        return_value=httpx.Response(404, text="not found")
    )

    connector = GitHubConnector(_ORG, _TOKEN)
    result = await connector.test_connection()
    assert result["success"] is True
    assert result["audit_log_available"] is False


@pytest.mark.asyncio
@respx.mock
async def test_github_test_connection_403_org_fails():
    respx.get(f"https://api.github.com/orgs/{_ORG}").mock(
        return_value=httpx.Response(403, text="bad token")
    )

    connector = GitHubConnector(_ORG, _TOKEN)
    result = await connector.test_connection()
    assert result["success"] is False
    assert "403" in result["error"]


@pytest.mark.asyncio
@respx.mock
async def test_github_fetch_alerts_merges_audit_and_code_scanning():
    respx.get(f"https://api.github.com/orgs/{_ORG}/audit-log").mock(
        return_value=httpx.Response(
            200,
            json=[
                {
                    "_document_id": "doc-1",
                    "@timestamp": 1735689600000,
                    "action": "org.update_member",
                    "actor": "alice",
                }
            ],
        )
    )
    respx.get(f"https://api.github.com/orgs/{_ORG}/code-scanning/alerts").mock(
        return_value=httpx.Response(
            200,
            json=[
                {
                    "number": 1,
                    "created_at": "2099-01-01T00:00:00Z",
                    "rule": {
                        "id": "py/sql-injection",
                        "security_severity_level": "high",
                    },
                    "repository": {"full_name": "aisoc/aisoc"},
                }
            ],
        )
    )

    connector = GitHubConnector(_ORG, _TOKEN)
    events = await connector.fetch_alerts(since_seconds=300)
    sources = {e["event_type"] for e in events}
    # Confirm both streams flowed through to normalize().
    assert any(s == "github.org.update_member" for s in sources)
    assert any(s.startswith("github.code_scanning.") for s in sources)
    assert all(e["source"] == "github" for e in events)


@pytest.mark.asyncio
@respx.mock
async def test_github_fetch_alerts_handles_audit_log_unavailable():
    # 404 on audit log shouldn't stop us from delivering code scanning.
    respx.get(f"https://api.github.com/orgs/{_ORG}/audit-log").mock(
        return_value=httpx.Response(404, text="not found")
    )
    respx.get(f"https://api.github.com/orgs/{_ORG}/code-scanning/alerts").mock(
        return_value=httpx.Response(
            200,
            json=[
                {
                    "number": 1,
                    "created_at": "2099-01-01T00:00:00Z",
                    "rule": {
                        "id": "py/sql-injection",
                        "security_severity_level": "high",
                    },
                    "repository": {"full_name": "aisoc/aisoc"},
                }
            ],
        )
    )

    connector = GitHubConnector(_ORG, _TOKEN)
    events = await connector.fetch_alerts(since_seconds=300)
    assert len(events) == 1
    assert events[0]["event_type"].startswith("github.code_scanning.")
