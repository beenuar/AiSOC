"""
Unit tests for the Azure family of connectors.

We exercise three concerns per connector:

1. ``schema()`` is shaped correctly and registry-wired (smoke tests above
   in ``test_schemas.py`` cover the contract bits, here we assert the
   *Azure-specific* expectations like field names).
2. ``normalize()`` produces an event dict that downstream code can rely on.
3. ``test_connection()`` and ``fetch_alerts()`` route through ``httpx`` the
   way we expect — driven by ``respx`` so we never hit real Azure APIs.
"""

from __future__ import annotations

import httpx
import pytest
import respx
from app.connectors.azure_activity import AzureActivityConnector
from app.connectors.azure_defender import AzureDefenderConnector
from app.connectors.azure_entra import AzureEntraConnector

_TENANT = "00000000-0000-0000-0000-000000000001"
_CLIENT = "00000000-0000-0000-0000-000000000002"
_SECRET = "super-secret-value"
_SUB = "00000000-0000-0000-0000-000000000003"


# ---------------------------------------------------------------------------
# Schema sanity (Azure-specific; generic contract checks live in test_schemas)
# ---------------------------------------------------------------------------


def test_azure_entra_schema_has_required_fields():
    schema = AzureEntraConnector.schema()
    field_names = {f.name for f in schema.fields}
    assert {"tenant_id", "client_id", "client_secret"} <= field_names
    assert schema.category == "iam"
    assert schema.oauth is not None
    assert schema.oauth.supported_in_hosted is True


def test_azure_activity_schema_includes_subscription_field():
    schema = AzureActivityConnector.schema()
    field_names = {f.name for f in schema.fields}
    assert "subscription_id" in field_names, (
        "azure_activity must collect a subscription_id; without it the polling "
        "loop has no scope to query"
    )
    assert {"tenant_id", "client_id", "client_secret"} <= field_names
    assert schema.category == "cloud"


def test_azure_defender_schema_marks_secret_field():
    schema = AzureDefenderConnector.schema()
    secret_field = next(f for f in schema.fields if f.name == "client_secret")
    assert secret_field.type == "secret"
    assert schema.category == "edr"


# ---------------------------------------------------------------------------
# Normalize: shape + severity rules
# ---------------------------------------------------------------------------


def test_azure_entra_normalize_directory_audit_role_change_is_high():
    connector = AzureEntraConnector(_TENANT, _CLIENT, _SECRET)
    raw = {
        "id": "audit-1",
        "category": "RoleManagement",
        "result": "success",
        "activityDisplayName": "Add member to role",
        "activityDateTime": "2026-01-01T00:00:00Z",
        "initiatedBy": {
            "user": {
                "displayName": "Alice Admin",
                "userPrincipalName": "alice@example.com",
            }
        },
        "_aisoc_event_kind": "directoryAudit",
    }
    out = connector.normalize(raw)
    assert out["source"] == "azure_entra"
    assert out["external_id"] == "audit-1"
    assert out["severity"] == "high", "successful RoleManagement audits must be high"
    assert out["actor"] == "Alice Admin"
    assert out["actor_email"] == "alice@example.com"
    assert out["event_type"].startswith("azure.entra.audit.")


def test_azure_entra_normalize_risky_signin_maps_severity():
    connector = AzureEntraConnector(_TENANT, _CLIENT, _SECRET)
    raw = {
        "id": "signin-1",
        "userPrincipalName": "bob@example.com",
        "userDisplayName": "Bob User",
        "ipAddress": "1.2.3.4",
        "createdDateTime": "2026-01-01T00:00:00Z",
        "riskLevelAggregated": "high",
        "riskState": "atRisk",
        "riskEventTypes_v2": ["unfamiliarFeatures"],
        "_aisoc_event_kind": "riskySignIn",
    }
    out = connector.normalize(raw)
    assert out["severity"] == "high"
    assert out["src_ip"] == "1.2.3.4"
    assert out["actor_email"] == "bob@example.com"
    assert out["event_type"] == "azure.entra.signin.risky"


def test_azure_activity_normalize_role_assignment_write_is_high():
    connector = AzureActivityConnector(_TENANT, _CLIENT, _SECRET, _SUB)
    raw = {
        "eventDataId": "act-1",
        "operationName": {
            "value": "Microsoft.Authorization/roleAssignments/write",
        },
        "status": {"value": "Succeeded"},
        "subStatus": {"value": "OK"},
        "level": "Informational",
        "caller": "service-principal@example.com",
        "resourceId": "/subscriptions/sub/resourceGroups/rg",
        "eventTimestamp": "2026-01-01T00:00:00Z",
    }
    out = connector.normalize(raw)
    assert out["severity"] == "high", (
        "writing role assignments is a high-blast-radius operation"
    )
    assert out["external_id"] == "act-1"
    assert out["actor"] == "service-principal@example.com"
    assert out["actor_email"] == "service-principal@example.com"
    assert out["event_type"].startswith("azure.activity.")


def test_azure_activity_normalize_routine_read_is_info():
    connector = AzureActivityConnector(_TENANT, _CLIENT, _SECRET, _SUB)
    raw = {
        "eventDataId": "act-2",
        "operationName": {
            "value": "Microsoft.Storage/storageAccounts/read",
        },
        "status": {"value": "Succeeded"},
        "level": "Informational",
        "caller": "alice@example.com",
        "resourceId": "/subscriptions/sub",
        "eventTimestamp": "2026-01-01T00:00:00Z",
    }
    out = connector.normalize(raw)
    assert out["severity"] == "info"


def test_azure_defender_normalize_maps_informational_to_info():
    connector = AzureDefenderConnector(_TENANT, _CLIENT, _SECRET)
    raw = {
        "id": "def-1",
        "title": "Suspicious sign-in",
        "description": "Unusual location",
        "severity": "informational",
        "status": "newAlert",
        "createdDateTime": "2026-01-01T00:00:00Z",
        "serviceSource": "microsoftDefenderForEndpoint",
        "category": "InitialAccess",
        "evidence": [
            {
                "@odata.type": "#microsoft.graph.security.userEvidence",
                "userAccount": {
                    "displayName": "Eve User",
                    "userPrincipalName": "eve@example.com",
                    "accountName": "eve",
                },
            },
            {
                "@odata.type": "#microsoft.graph.security.deviceEvidence",
                "deviceDnsName": "host01.example.com",
            },
        ],
    }
    out = connector.normalize(raw)
    assert out["severity"] == "info"
    assert out["actor"] == "Eve User"
    assert out["actor_email"] == "eve@example.com"
    assert out["host"] == "host01.example.com"
    assert out["service_source"] == "microsoftDefenderForEndpoint"
    assert out["event_type"] == "azure.defender.microsoftdefenderforendpoint"


def test_azure_defender_normalize_preserves_high_severity():
    connector = AzureDefenderConnector(_TENANT, _CLIENT, _SECRET)
    raw = {
        "id": "def-2",
        "title": "Ransomware execution",
        "severity": "high",
        "createdDateTime": "2026-01-01T00:00:00Z",
        "serviceSource": "microsoftDefenderForEndpoint",
    }
    out = connector.normalize(raw)
    assert out["severity"] == "high"


# ---------------------------------------------------------------------------
# Live HTTP routing via respx
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
@respx.mock
async def test_azure_entra_test_connection_success():
    respx.post(f"https://login.microsoftonline.com/{_TENANT}/oauth2/v2.0/token").mock(
        return_value=httpx.Response(200, json={"access_token": "abc"})
    )
    respx.get("https://graph.microsoft.com/v1.0/organization").mock(
        return_value=httpx.Response(
            200, json={"value": [{"id": "org-1", "displayName": "Acme Corp"}]}
        )
    )

    connector = AzureEntraConnector(_TENANT, _CLIENT, _SECRET)
    result = await connector.test_connection()
    assert result["success"] is True
    assert result["organization"] == "Acme Corp"


@pytest.mark.asyncio
@respx.mock
async def test_azure_entra_test_connection_bubbles_http_error():
    respx.post(f"https://login.microsoftonline.com/{_TENANT}/oauth2/v2.0/token").mock(
        return_value=httpx.Response(401, text="invalid_client")
    )

    connector = AzureEntraConnector(_TENANT, _CLIENT, _SECRET)
    result = await connector.test_connection()
    assert result["success"] is False
    assert "401" in result["error"]


@pytest.mark.asyncio
@respx.mock
async def test_azure_entra_fetch_alerts_returns_normalized_events():
    respx.post(f"https://login.microsoftonline.com/{_TENANT}/oauth2/v2.0/token").mock(
        return_value=httpx.Response(200, json={"access_token": "abc"})
    )
    respx.get("https://graph.microsoft.com/v1.0/auditLogs/directoryAudits").mock(
        return_value=httpx.Response(
            200,
            json={
                "value": [
                    {
                        "id": "a-1",
                        "category": "UserManagement",
                        "result": "success",
                        "activityDisplayName": "Add user",
                        "activityDateTime": "2026-01-01T00:00:00Z",
                        "initiatedBy": {"user": {"displayName": "Alice"}},
                    }
                ]
            },
        )
    )
    respx.get("https://graph.microsoft.com/v1.0/auditLogs/signIns").mock(
        return_value=httpx.Response(200, json={"value": []})
    )

    connector = AzureEntraConnector(_TENANT, _CLIENT, _SECRET)
    events = await connector.fetch_alerts(since_seconds=300)
    assert len(events) == 1
    assert events[0]["source"] == "azure_entra"
    assert events[0]["external_id"] == "a-1"


@pytest.mark.asyncio
@respx.mock
async def test_azure_activity_test_connection_success():
    respx.post(f"https://login.microsoftonline.com/{_TENANT}/oauth2/v2.0/token").mock(
        return_value=httpx.Response(200, json={"access_token": "abc"})
    )
    respx.get(f"https://management.azure.com/subscriptions/{_SUB}").mock(
        return_value=httpx.Response(
            200, json={"id": f"/subscriptions/{_SUB}", "displayName": "Production"}
        )
    )

    connector = AzureActivityConnector(_TENANT, _CLIENT, _SECRET, _SUB)
    result = await connector.test_connection()
    assert result["success"] is True
    assert result["subscription_name"] == "Production"


@pytest.mark.asyncio
@respx.mock
async def test_azure_activity_fetch_alerts_handles_empty_response():
    respx.post(f"https://login.microsoftonline.com/{_TENANT}/oauth2/v2.0/token").mock(
        return_value=httpx.Response(200, json={"access_token": "abc"})
    )
    activity_url = (
        f"https://management.azure.com/subscriptions/{_SUB}"
        "/providers/Microsoft.Insights/eventtypes/management/values"
    )
    respx.get(activity_url).mock(
        return_value=httpx.Response(200, json={"value": []})
    )

    connector = AzureActivityConnector(_TENANT, _CLIENT, _SECRET, _SUB)
    events = await connector.fetch_alerts(since_seconds=600)
    assert events == []


@pytest.mark.asyncio
@respx.mock
async def test_azure_defender_test_connection_handles_failure():
    respx.post(f"https://login.microsoftonline.com/{_TENANT}/oauth2/v2.0/token").mock(
        return_value=httpx.Response(200, json={"access_token": "abc"})
    )
    respx.get("https://graph.microsoft.com/v1.0/security/alerts_v2").mock(
        return_value=httpx.Response(403, text="insufficient_privileges")
    )

    connector = AzureDefenderConnector(_TENANT, _CLIENT, _SECRET)
    result = await connector.test_connection()
    assert result["success"] is False
    assert "403" in result["error"]


@pytest.mark.asyncio
@respx.mock
async def test_azure_defender_fetch_alerts_returns_normalized_events():
    respx.post(f"https://login.microsoftonline.com/{_TENANT}/oauth2/v2.0/token").mock(
        return_value=httpx.Response(200, json={"access_token": "abc"})
    )
    respx.get("https://graph.microsoft.com/v1.0/security/alerts_v2").mock(
        return_value=httpx.Response(
            200,
            json={
                "value": [
                    {
                        "id": "alert-1",
                        "title": "Malware detected",
                        "description": "Trojan found on host",
                        "severity": "high",
                        "createdDateTime": "2026-01-01T00:00:00Z",
                        "serviceSource": "microsoftDefenderForEndpoint",
                    }
                ]
            },
        )
    )

    connector = AzureDefenderConnector(_TENANT, _CLIENT, _SECRET)
    events = await connector.fetch_alerts(since_seconds=300)
    assert len(events) == 1
    assert events[0]["severity"] == "high"
    assert events[0]["source"] == "azure_defender"
