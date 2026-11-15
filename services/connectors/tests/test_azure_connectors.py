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
        "azure_activity must collect a subscription_id; without it the polling loop has no scope to query"
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
    # Issue #1718: the principal name, not the display name. Graph puts a
    # first-party client in that display-name slot when a person acts through
    # one, so this assertion used to pin "Microsoft Teams Services" as the
    # actor of changes a person made. The display name is still carried,
    # under a name that says what it is.
    assert out["actor"] == "alice@example.com"
    assert out["actor_email"] == "alice@example.com"
    assert out["actor_display_name"] == "Alice Admin"
    assert out["initiator_type"] == "user"
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
    assert out["severity"] == "high", "writing role assignments is a high-blast-radius operation"
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
        return_value=httpx.Response(200, json={"value": [{"id": "org-1", "displayName": "Acme Corp"}]})
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
    respx.get("https://graph.microsoft.com/v1.0/auditLogs/signIns").mock(return_value=httpx.Response(200, json={"value": []}))

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
        return_value=httpx.Response(200, json={"id": f"/subscriptions/{_SUB}", "displayName": "Production"})
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
    activity_url = f"https://management.azure.com/subscriptions/{_SUB}/providers/Microsoft.Insights/eventtypes/management/values"
    respx.get(activity_url).mock(return_value=httpx.Response(200, json={"value": []}))

    connector = AzureActivityConnector(_TENANT, _CLIENT, _SECRET, _SUB)
    events = await connector.fetch_alerts(since_seconds=600)
    assert events == []


@pytest.mark.asyncio
@respx.mock
async def test_azure_defender_test_connection_handles_failure():
    respx.post(f"https://login.microsoftonline.com/{_TENANT}/oauth2/v2.0/token").mock(
        return_value=httpx.Response(200, json={"access_token": "abc"})
    )
    respx.get("https://graph.microsoft.com/v1.0/security/alerts_v2").mock(return_value=httpx.Response(403, text="insufficient_privileges"))

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


@pytest.mark.asyncio
@respx.mock
async def test_azure_defender_get_resource_config_empty_id():
    connector = AzureDefenderConnector(_TENANT, _CLIENT, _SECRET)
    assert await connector.get_resource_config("") == {}
    assert await connector.get_resource_config("   ") == {}


@pytest.mark.asyncio
@respx.mock
async def test_azure_defender_get_resource_config_success():
    respx.post(f"https://login.microsoftonline.com/{_TENANT}/oauth2/v2.0/token").mock(
        return_value=httpx.Response(200, json={"access_token": "abc", "expires_in": 3600})
    )
    detail_url = "https://graph.microsoft.com/v1.0/security/alerts_v2/alert-detail-1"
    respx.get(detail_url).mock(
        return_value=httpx.Response(
            200,
            json={"id": "alert-detail-1", "title": "Detail", "severity": "high"},
        )
    )

    connector = AzureDefenderConnector(_TENANT, _CLIENT, _SECRET)
    cfg = await connector.get_resource_config("alert-detail-1", at_ts="2026-01-15T12:00:00Z")
    assert cfg["snapshot_freshness"] == "live"
    assert cfg["snapshot_requested_at"] == "2026-01-15T12:00:00Z"
    assert cfg["raw"]["id"] == "alert-detail-1"
    assert cfg["raw"]["title"] == "Detail"


@pytest.mark.asyncio
@respx.mock
async def test_azure_defender_get_resource_config_401_then_retry():
    respx.post(f"https://login.microsoftonline.com/{_TENANT}/oauth2/v2.0/token").mock(
        side_effect=[
            httpx.Response(200, json={"access_token": "tok-1", "expires_in": 3600}),
            httpx.Response(200, json={"access_token": "tok-2", "expires_in": 3600}),
        ]
    )
    detail_url = "https://graph.microsoft.com/v1.0/security/alerts_v2/alert-retry"
    respx.get(detail_url).mock(
        side_effect=[
            httpx.Response(401, text="expired"),
            httpx.Response(200, json={"id": "alert-retry", "title": "After refresh"}),
        ]
    )

    connector = AzureDefenderConnector(_TENANT, _CLIENT, _SECRET)
    cfg = await connector.get_resource_config("alert-retry")
    assert cfg["raw"]["title"] == "After refresh"


@pytest.mark.asyncio
@respx.mock
async def test_azure_defender_get_resource_config_non_200_returns_empty():
    respx.post(f"https://login.microsoftonline.com/{_TENANT}/oauth2/v2.0/token").mock(
        return_value=httpx.Response(200, json={"access_token": "abc", "expires_in": 3600})
    )
    respx.get("https://graph.microsoft.com/v1.0/security/alerts_v2/missing").mock(return_value=httpx.Response(404, text="not found"))

    connector = AzureDefenderConnector(_TENANT, _CLIENT, _SECRET)
    assert await connector.get_resource_config("missing") == {}


# ---------------------------------------------------------------------------
# Certificate (client_assertion) auth — Entra and M365 audit share the helper
# ---------------------------------------------------------------------------


def _make_cert_pem(*, with_cert: bool = True) -> tuple[str, str, object]:
    """Throwaway RSA key + self-signed cert -> (pem, sha1 hex thumbprint, cert)."""
    import datetime as dt

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "aisoc-test")])
    now = dt.datetime.now(dt.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + dt.timedelta(days=1))
        .sign(key, hashes.SHA256())
    )
    pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode()
    if with_cert:
        pem += cert.public_bytes(serialization.Encoding.PEM).decode()
    return pem, cert.fingerprint(hashes.SHA1()).hex(), cert  # noqa: S303 - test


def _b64d(part: str) -> bytes:
    import base64

    return base64.urlsafe_b64decode(part + "=" * (-len(part) % 4))


def _connector_cases():
    from app.connectors.m365_audit import M365AuditConnector

    return [AzureEntraConnector, M365AuditConnector]


def _posted_form(route) -> dict[str, str]:
    from urllib.parse import parse_qs

    return {k: v[0] for k, v in parse_qs(route.calls.last.request.content.decode()).items()}


@pytest.mark.asyncio
@pytest.mark.parametrize("cls_index", [0, 1])
@pytest.mark.parametrize("with_cert", [True, False])
async def test_certificate_auth_sends_signed_client_assertion(cls_index, with_cert):
    import json

    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding

    pem, thumb_hex, cert = _make_cert_pem(with_cert=with_cert)
    connector = _connector_cases()[cls_index](
        tenant_id=_TENANT,
        client_id=_CLIENT,
        certificate_pem=pem,
        certificate_thumbprint="" if with_cert else thumb_hex.upper(),
    )
    token_url = f"https://login.microsoftonline.com/{_TENANT}/oauth2/v2.0/token"
    with respx.mock(assert_all_called=False) as mock:
        route = mock.post(token_url).mock(return_value=httpx.Response(200, json={"access_token": "tok"}))
        assert await connector._authenticate() == "tok"

    form = _posted_form(route)
    assert "client_secret" not in form
    assert form["client_assertion_type"] == "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
    h, c, s = form["client_assertion"].split(".")
    header, claims = json.loads(_b64d(h)), json.loads(_b64d(c))
    assert header["alg"] == "RS256"
    assert _b64d(header["x5t"]).hex() == thumb_hex
    assert ("x5t#S256" in header) is with_cert
    if with_cert:
        assert _b64d(header["x5t#S256"]) == cert.fingerprint(hashes.SHA256())
    assert claims["aud"] == token_url
    assert claims["iss"] == claims["sub"] == _CLIENT
    assert claims["exp"] > claims["nbf"]
    assert claims["jti"]
    cert.public_key().verify(_b64d(s), f"{h}.{c}".encode(), padding.PKCS1v15(), hashes.SHA256())


@pytest.mark.asyncio
@pytest.mark.parametrize("cls_index", [0, 1])
async def test_secret_auth_unchanged(cls_index):
    connector = _connector_cases()[cls_index](_TENANT, _CLIENT, _SECRET)
    with respx.mock() as mock:
        route = mock.post(f"https://login.microsoftonline.com/{_TENANT}/oauth2/v2.0/token").mock(
            return_value=httpx.Response(200, json={"access_token": "tok"})
        )
        await connector._authenticate()
    form = _posted_form(route)
    assert form["client_secret"] == _SECRET
    assert "client_assertion" not in form


@pytest.mark.parametrize("cls_index", [0, 1])
def test_certificate_wins_when_both_given_and_bad_config_refused(cls_index):
    cls = _connector_cases()[cls_index]
    pem, _, _ = _make_cert_pem()
    assert cls(_TENANT, _CLIENT, _SECRET, certificate_pem=pem)._cert is not None
    with pytest.raises(ValueError, match="either client_secret or certificate_pem"):
        cls(_TENANT, _CLIENT)
    with pytest.raises(ValueError, match="PRIVATE KEY"):
        cls(_TENANT, _CLIENT, certificate_pem="not a pem")
    key_only, _, _ = _make_cert_pem(with_cert=False)
    with pytest.raises(ValueError, match="certificate_thumbprint is required"):
        cls(_TENANT, _CLIENT, certificate_pem=key_only)
    with pytest.raises(ValueError, match="hex SHA-1"):
        cls(_TENANT, _CLIENT, certificate_pem=key_only, certificate_thumbprint="zz")


@pytest.mark.parametrize("cls_index", [0, 1])
def test_schema_cert_fields_optional(cls_index):
    fields = {f.name: f for f in _connector_cases()[cls_index].schema().fields}
    assert fields["client_secret"].required is False
    for name in ("certificate_pem", "certificate_thumbprint", "private_key_password"):
        assert fields[name].required is False
    assert fields["certificate_pem"].type == "secret"
    assert fields["private_key_password"].type == "secret"
