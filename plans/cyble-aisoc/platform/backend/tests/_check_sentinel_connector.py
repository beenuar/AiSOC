"""Smoke test for the SentinelSiemConnector.

Intercepts HTTP calls with `httpx.MockTransport` so the test never hits
real Azure endpoints. Verifies:

  1. Factory is registered for ConnectorKind.SIEM / vendor=sentinel.
  2. Construction requires workspace_id and azure_tenant_id (both as
     valid Azure GUIDs).
  3. Missing client_id/client_secret raises ConnectorAuthError when
     the OAuth flow first runs.
  4. KQL injection prevention: control chars and empty strings are
     rejected; backslashes/quotes are escaped.
  5. Invalid events_table / alerts_table identifiers are rejected.
  6. `search_events` posts to `/workspaces/{id}/query` with a KQL
     body, normalizes Log Analytics' (columns,rows) response into the
     SIEM event envelope, picks `type` from EventID/Activity/etc., and
     converts `TimeGenerated` to ISO-8601.
  7. `search_events` honours `entity_type` host/user/ip via default
     KQL templates with distinct field predicates.
  8. `get_related_alerts` posts a SecurityAlert KQL and normalizes
     into id/title/severity (lowercased), with VendorOriginalId
     fallback when SystemAlertId is missing.
  9. Unsupported entity_type raises ConnectorError unless an
     events_query_template override is supplied.
 10. Custom KQL templates substitute placeholders correctly.
 11. Log Analytics in-body `error` blocks surface as ConnectorError.
 12. 401 from the OAuth token endpoint raises ConnectorAuthError.
 13. health_check posts a trivial `print Ok = "ok"` query.

Run with:

    cd platform/backend
    python -m tests._check_sentinel_connector
"""
from __future__ import annotations

import asyncio
import json
import os
import sys
import tempfile
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs

import httpx

# Force ephemeral DB before app imports so we don't touch the real one.
TMP_DIR = Path(tempfile.mkdtemp(prefix="aisoc-sentinel-"))
os.environ["AISOC_DB_PATH"] = str(TMP_DIR / "sentinel-test.db")
os.environ.setdefault("AISOC_ENV", "development")

# Repo root on path so `app.*` imports resolve when run as a script.
HERE = Path(__file__).resolve()
sys.path.insert(0, str(HERE.parent.parent))

from app.connectors.sdk.base import (  # noqa: E402
    ConnectorAuthError,
    ConnectorConfig,
    ConnectorError,
    ConnectorKind,
)
from app.connectors.sdk.builtin import register_builtin_factories  # noqa: E402
from app.connectors.sdk.http import OAuthClientCredentials  # noqa: E402
from app.connectors.sdk.registry import _FACTORIES as _CONNECTOR_FACTORIES  # noqa: E402
from app.connectors.sentinel import (  # noqa: E402
    SentinelSiemConnector,
    _escape_kql_value,
    _validate_guid,
    _validate_table,
    make_sentinel_siem,
)


# Canonical (random but valid) GUIDs used throughout the test.
TEST_WORKSPACE_ID = "11111111-2222-3333-4444-555555555555"
TEST_AZURE_TENANT_ID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"


# ─── fake Azure surface ──────────────────────────────────────────────────


class FakeAzure:
    """In-memory Azure AD + Log Analytics stub for httpx MockTransport.

    Handles two endpoints:
      * ``POST https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token``
        — issues a fake access token unless ``oauth_status`` is set.
      * ``POST https://api.loganalytics.io/v1/workspaces/{id}/query``
        — returns ``next_query_response`` (Log Analytics shape).

    Records both kinds of requests in ``token_requests`` / ``query_requests``
    so tests can assert headers, KQL bodies, and form fields.
    """

    def __init__(self) -> None:
        self.token_requests: list[httpx.Request] = []
        self.query_requests: list[httpx.Request] = []
        self.next_query_response: dict[str, Any] = {
            "tables": [{"name": "PrimaryResult", "columns": [], "rows": []}]
        }
        # Override the OAuth token endpoint behaviour for negative tests.
        self.oauth_status: int = 200
        self.oauth_body: dict[str, Any] = {
            "access_token": "fake-access-token",
            "token_type": "Bearer",
            "expires_in": 3600,
        }
        # Force a status on /query (e.g. 401, 500).
        self.query_force_status: int | None = None
        self.query_force_body: bytes = b""

    def handler(self, request: httpx.Request) -> httpx.Response:
        url = str(request.url)

        if "login.microsoftonline.com" in url and url.endswith("/oauth2/v2.0/token"):
            self.token_requests.append(request)
            if self.oauth_status != 200:
                return httpx.Response(
                    self.oauth_status,
                    json={"error": "invalid_client", "error_description": "bad secret"},
                )
            return httpx.Response(200, json=self.oauth_body)

        if "/workspaces/" in url and url.endswith("/query"):
            self.query_requests.append(request)
            if self.query_force_status is not None:
                return httpx.Response(
                    self.query_force_status,
                    content=self.query_force_body,
                    headers={"Content-Type": "application/json"},
                )
            return httpx.Response(
                200,
                json=self.next_query_response,
                headers={"Content-Type": "application/json"},
            )

        return httpx.Response(404, content=b"", headers={"X-Test": "unhandled"})

    def last_kql(self) -> str:
        assert self.query_requests, "no /query requests captured"
        body = json.loads(self.query_requests[-1].content.decode("utf-8"))
        return body["query"]

    def last_token_form(self) -> dict[str, list[str]]:
        assert self.token_requests, "no /token requests captured"
        return parse_qs(self.token_requests[-1].content.decode("utf-8"))


def _make_connector(
    *,
    fake: FakeAzure,
    params: dict[str, Any] | None = None,
    secrets: dict[str, str] | None = None,
) -> SentinelSiemConnector:
    """Build a SentinelSiemConnector wired to the FakeAzure transport.

    The transport intercepts *both* the OAuth token endpoint and the
    Log Analytics query endpoint, so a single MockTransport drives the
    whole flow.
    """
    cfg = ConnectorConfig(
        tenant_id="t-sentinel-test",
        kind=ConnectorKind.SIEM,
        vendor="sentinel",
        params=params
        if params is not None
        else {
            "workspace_id": TEST_WORKSPACE_ID,
            "azure_tenant_id": TEST_AZURE_TENANT_ID,
            "max_results": 50,
        },
        secrets=secrets
        if secrets is not None
        else {"client_id": "fake-client-id", "client_secret": "fake-secret"},
    )
    conn = SentinelSiemConnector(cfg)
    transport = httpx.MockTransport(fake.handler)
    # Hot-swap the inner httpx.AsyncClient with one bound to MockTransport.
    # OAuthClientCredentials.post() uses the absolute token URL, so the
    # MockTransport will receive both relative (/workspaces/.../query) and
    # absolute (login.microsoftonline.com) URLs and dispatch by host.
    conn._http._client = httpx.AsyncClient(
        base_url="https://api.loganalytics.io/v1",
        transport=transport,
        headers={"Accept": "application/json", "Content-Type": "application/json"},
    )
    return conn


# ─── synchronous checks ──────────────────────────────────────────────────


def check_factory_registered() -> None:
    register_builtin_factories()
    factory = _CONNECTOR_FACTORIES.get((ConnectorKind.SIEM, "sentinel"))
    assert factory is make_sentinel_siem, (
        f"expected make_sentinel_siem registered for SIEM/sentinel, got {factory}"
    )
    print("OK  factory registered: ConnectorKind.SIEM, vendor='sentinel'")


def check_required_params_rejected() -> None:
    base_secrets = {"client_id": "x", "client_secret": "y"}

    # Missing workspace_id
    try:
        SentinelSiemConnector(
            ConnectorConfig(
                tenant_id="t",
                kind=ConnectorKind.SIEM,
                vendor="sentinel",
                params={"azure_tenant_id": TEST_AZURE_TENANT_ID},
                secrets=base_secrets,
            )
        )
    except ConnectorError as e:
        assert "workspace_id" in str(e), e
        print("OK  missing workspace_id -> ConnectorError")
    else:
        raise AssertionError("expected ConnectorError on missing workspace_id")

    # Missing azure_tenant_id
    try:
        SentinelSiemConnector(
            ConnectorConfig(
                tenant_id="t",
                kind=ConnectorKind.SIEM,
                vendor="sentinel",
                params={"workspace_id": TEST_WORKSPACE_ID},
                secrets=base_secrets,
            )
        )
    except ConnectorError as e:
        assert "azure_tenant_id" in str(e), e
        print("OK  missing azure_tenant_id -> ConnectorError")
    else:
        raise AssertionError("expected ConnectorError on missing azure_tenant_id")

    # Bad GUID format
    try:
        SentinelSiemConnector(
            ConnectorConfig(
                tenant_id="t",
                kind=ConnectorKind.SIEM,
                vendor="sentinel",
                params={
                    "workspace_id": "not-a-guid",
                    "azure_tenant_id": TEST_AZURE_TENANT_ID,
                },
                secrets=base_secrets,
            )
        )
    except ConnectorError as e:
        assert "workspace_id" in str(e) and "not-a-guid" in str(e), e
        print("OK  non-GUID workspace_id -> ConnectorError")
    else:
        raise AssertionError("expected ConnectorError on non-GUID workspace_id")


def check_missing_secrets_rejected() -> None:
    # client_id missing
    try:
        SentinelSiemConnector(
            ConnectorConfig(
                tenant_id="t",
                kind=ConnectorKind.SIEM,
                vendor="sentinel",
                params={
                    "workspace_id": TEST_WORKSPACE_ID,
                    "azure_tenant_id": TEST_AZURE_TENANT_ID,
                },
                secrets={"client_secret": "y"},
            )
        )
    except ConnectorAuthError as e:
        assert "client_id" in str(e), e
        print("OK  missing client_id -> ConnectorAuthError")
    else:
        raise AssertionError("expected ConnectorAuthError on missing client_id")

    # client_secret missing
    try:
        SentinelSiemConnector(
            ConnectorConfig(
                tenant_id="t",
                kind=ConnectorKind.SIEM,
                vendor="sentinel",
                params={
                    "workspace_id": TEST_WORKSPACE_ID,
                    "azure_tenant_id": TEST_AZURE_TENANT_ID,
                },
                secrets={"client_id": "x"},
            )
        )
    except ConnectorAuthError as e:
        assert "client_secret" in str(e), e
        print("OK  missing client_secret -> ConnectorAuthError")
    else:
        raise AssertionError("expected ConnectorAuthError on missing client_secret")


def check_kql_escaping() -> None:
    # Backslashes and quotes are escaped (caller wraps in "..." outside).
    assert _escape_kql_value(r'a"b\c') == 'a\\"b\\\\c'
    assert _escape_kql_value("plain") == "plain"
    for bad in ("", "host\nbad", "host\x00bad", "host\tbad"):
        try:
            _escape_kql_value(bad)
        except ConnectorError:
            pass
        else:
            raise AssertionError(f"expected rejection for {bad!r}")
    print("OK  KQL escaping: quotes/backslashes escaped, control chars rejected")


def check_guid_and_table_validation() -> None:
    assert (
        _validate_guid(TEST_WORKSPACE_ID, name="workspace_id") == TEST_WORKSPACE_ID
    )
    for bad in ("", "abc", "11111111-2222-3333-4444"):
        try:
            _validate_guid(bad, name="workspace_id")
        except ConnectorError:
            pass
        else:
            raise AssertionError(f"expected rejection for GUID {bad!r}")

    # KQL identifier rules: letters/underscore start, then alnum/underscore.
    for good in ("SecurityEvent", "CommonSecurityLog", "MyEdr_CL", "_AzureSystem"):
        assert _validate_table(good, field="events_table") == good
    for bad in ("", "1Bad", "Has Space", "drop;Table", "Has-Dash"):
        try:
            _validate_table(bad, field="events_table")
        except ConnectorError:
            pass
        else:
            raise AssertionError(f"expected rejection for table {bad!r}")
    print("OK  GUID + KQL identifier validation enforced")


# ─── async checks ────────────────────────────────────────────────────────


async def check_search_events_happy_path() -> None:
    fake = FakeAzure()
    fake.next_query_response = {
        "tables": [
            {
                "name": "PrimaryResult",
                "columns": [
                    {"name": "TimeGenerated", "type": "datetime"},
                    {"name": "Computer", "type": "string"},
                    {"name": "EventID", "type": "int"},
                    {"name": "Account", "type": "string"},
                    {"name": "Activity", "type": "string"},
                    {"name": "Empty", "type": "string"},
                    {"name": "Type", "type": "string"},
                ],
                "rows": [
                    [
                        "2026-06-17T10:00:00.123Z",
                        "host-7",
                        4625,
                        "alice",
                        "4625 - An account failed to log on",
                        None,
                        "SecurityEvent",
                    ],
                    [
                        "2026-06-17T09:55:00Z",
                        "host-7",
                        None,
                        None,
                        "4624 - An account was logged on",
                        None,
                        "SecurityEvent",
                    ],
                ],
            }
        ]
    }
    conn = _make_connector(fake=fake)
    try:
        out = await conn.search_events(
            entity="host-7", entity_type="host", minutes=120
        )

        # Envelope
        assert out["entity"] == "host-7"
        assert out["entity_type"] == "host"
        assert out["window_minutes"] == 120
        assert len(out["events"]) == 2

        # First row: EventID wins as type, ISO timestamp normalised,
        # Empty column (None) stripped.
        ev0 = out["events"][0]
        assert ev0["type"] == "4625", ev0
        assert ev0["ts"].startswith("2026-06-17T10:00:00"), ev0["ts"]
        assert ev0["Computer"] == "host-7"
        assert ev0["Account"] == "alice"
        assert "Empty" not in ev0  # None columns stripped

        # Second row: no EventID -> Activity wins; "Z" normalised.
        ev1 = out["events"][1]
        assert ev1["type"].startswith("4624"), ev1
        assert ev1["ts"].startswith("2026-06-17T09:55:00"), ev1["ts"]

        # KQL body shape
        kql = fake.last_kql()
        assert kql.startswith("SecurityEvent"), kql
        assert 'ago(120m)' in kql, kql
        assert '"host-7"' in kql, kql
        assert "top 50 by TimeGenerated desc" in kql, kql

        # Request URL
        req = fake.query_requests[-1]
        assert req.url.path == f"/v1/workspaces/{TEST_WORKSPACE_ID}/query", req.url
        assert req.headers.get("Authorization") == "Bearer fake-access-token"

        # OAuth ran once and used client_credentials with the LA scope
        assert len(fake.token_requests) == 1, fake.token_requests
        form = fake.last_token_form()
        assert form["grant_type"] == ["client_credentials"], form
        assert form["client_id"] == ["fake-client-id"], form
        assert form["scope"] == ["https://api.loganalytics.io/.default"], form
        # Token URL must contain the directory tenant id (not our tenant_id)
        token_url = str(fake.token_requests[0].url)
        assert TEST_AZURE_TENANT_ID in token_url, token_url

        print("OK  search_events: KQL + auth headers + LA response normalization")
    finally:
        await conn.aclose()


async def check_search_events_user_and_ip() -> None:
    fake = FakeAzure()
    fake.next_query_response = {
        "tables": [{"name": "PrimaryResult", "columns": [], "rows": []}]
    }
    conn = _make_connector(fake=fake)
    try:
        # user
        await conn.search_events(
            entity="alice@corp", entity_type="user", minutes=30
        )
        kql = fake.last_kql()
        assert 'Account == "alice@corp"' in kql, kql
        assert 'UserPrincipalName == "alice@corp"' in kql, kql
        assert 'ago(30m)' in kql, kql

        # ip
        await conn.search_events(
            entity="10.0.0.42", entity_type="ip", minutes=60
        )
        kql = fake.last_kql()
        assert 'SourceIP == "10.0.0.42"' in kql, kql
        assert 'DestinationIP == "10.0.0.42"' in kql, kql

        # OAuth must have only run once (token reused across calls).
        assert len(fake.token_requests) == 1, (
            f"expected token reuse, got {len(fake.token_requests)} requests"
        )
        print("OK  search_events: default templates for user/ip + token reuse")
    finally:
        await conn.aclose()


async def check_unsupported_entity_type_rejected() -> None:
    fake = FakeAzure()
    conn = _make_connector(fake=fake)
    try:
        try:
            await conn.search_events(
                entity="x", entity_type="weirdo", minutes=10
            )
        except ConnectorError as e:
            assert "entity_type" in str(e) and "weirdo" in str(e), str(e)
            print("OK  unsupported entity_type -> ConnectorError")
        else:
            raise AssertionError("expected ConnectorError")
    finally:
        await conn.aclose()


async def check_custom_template_override() -> None:
    fake = FakeAzure()
    fake.next_query_response = {
        "tables": [{"name": "PrimaryResult", "columns": [], "rows": []}]
    }
    conn = _make_connector(
        fake=fake,
        params={
            "workspace_id": TEST_WORKSPACE_ID,
            "azure_tenant_id": TEST_AZURE_TENANT_ID,
            "max_results": 25,
            "events_table": "CommonSecurityLog",
            "events_query_template": (
                '{events_table} | where SourceUserName == "{entity}" '
                "| where TimeGenerated > ago({minutes}m) "
                "| top {max_results} by TimeGenerated desc"
            ),
        },
    )
    try:
        await conn.search_events(
            entity='weird"val', entity_type="customthing", minutes=15
        )
        kql = fake.last_kql()
        assert kql == (
            'CommonSecurityLog | where SourceUserName == "weird\\"val" '
            "| where TimeGenerated > ago(15m) "
            "| top 25 by TimeGenerated desc"
        ), kql
        print("OK  custom events_query_template substitution + quote escaping")
    finally:
        await conn.aclose()


async def check_related_alerts_happy_path() -> None:
    fake = FakeAzure()
    fake.next_query_response = {
        "tables": [
            {
                "name": "PrimaryResult",
                "columns": [
                    {"name": "TimeGenerated", "type": "datetime"},
                    {"name": "SystemAlertId", "type": "string"},
                    {"name": "AlertName", "type": "string"},
                    {"name": "AlertSeverity", "type": "string"},
                    {"name": "VendorOriginalId", "type": "string"},
                ],
                "rows": [
                    [
                        "2026-06-17T09:00:00Z",
                        "abc-system-id",
                        "Brute force suspected",
                        "High",
                        None,
                    ],
                    [
                        # No SystemAlertId -> falls back to VendorOriginalId.
                        "2026-06-17T08:30:00Z",
                        None,
                        "Suspicious activity",
                        "MEDIUM",
                        "vendor-original-99",
                    ],
                ],
            }
        ]
    }
    conn = _make_connector(fake=fake)
    try:
        out = await conn.get_related_alerts(entity="host-7", hours=8)
        assert out["entity"] == "host-7"
        assert out["related_count"] == 2

        a0 = out["related"][0]
        assert a0["id"] == "abc-system-id"
        assert a0["title"] == "Brute force suspected"
        assert a0["severity"] == "high"  # lowercased

        a1 = out["related"][1]
        assert a1["id"] == "vendor-original-99", a1
        assert a1["title"] == "Suspicious activity", a1
        assert a1["severity"] == "medium", a1

        kql = fake.last_kql()
        assert kql.startswith("SecurityAlert"), kql
        assert 'ago(8h)' in kql, kql
        assert 'Entities contains "host-7"' in kql, kql
        print("OK  get_related_alerts: KQL + normalization + id fallback")
    finally:
        await conn.aclose()


async def check_log_analytics_error_surfaced() -> None:
    """LA can return HTTP-200 with an ``error`` block — surface that."""
    fake = FakeAzure()
    fake.next_query_response = {
        "error": {
            "code": "SyntaxError",
            "message": "A recognition error occurred in the query.",
        }
    }
    conn = _make_connector(fake=fake)
    try:
        try:
            await conn.search_events(
                entity="host-7", entity_type="host", minutes=10
            )
        except ConnectorError as e:
            assert "SyntaxError" in str(e) or "recognition error" in str(e).lower(), str(e)
            print("OK  Log Analytics in-body error -> ConnectorError")
        else:
            raise AssertionError("expected ConnectorError")
    finally:
        await conn.aclose()


async def check_health_check_happy_path() -> None:
    fake = FakeAzure()
    fake.next_query_response = {
        "tables": [
            {
                "name": "PrimaryResult",
                "columns": [{"name": "Ok", "type": "string"}],
                "rows": [["ok"]],
            }
        ]
    }
    conn = _make_connector(fake=fake)
    try:
        info = await conn.health_check()
        assert info["ok"] is True
        assert info["vendor"] == "sentinel"
        assert info["kind"] == "siem"
        assert info["workspace_id"] == TEST_WORKSPACE_ID
        assert info["rows_returned"] == 1
        kql = fake.last_kql()
        assert kql == 'print Ok = "ok"', kql
        print("OK  health_check: trivial KQL + parsed envelope")
    finally:
        await conn.aclose()


async def check_oauth_failure_surfaced() -> None:
    fake = FakeAzure()
    fake.oauth_status = 401
    conn = _make_connector(fake=fake)
    conn._http.max_retries = 0
    try:
        try:
            await conn.search_events(
                entity="host-7", entity_type="host", minutes=10
            )
        except ConnectorAuthError as e:
            assert "OAuth" in str(e) or "token" in str(e).lower(), str(e)
            print("OK  401 from token endpoint -> ConnectorAuthError")
        else:
            raise AssertionError("expected ConnectorAuthError on OAuth failure")
    finally:
        await conn.aclose()


# ─── runner ──────────────────────────────────────────────────────────────


async def _main() -> None:
    # Sync checks first (cheap, fail-fast).
    check_factory_registered()
    check_required_params_rejected()
    check_missing_secrets_rejected()
    check_kql_escaping()
    check_guid_and_table_validation()

    # Async checks.
    await check_search_events_happy_path()
    await check_search_events_user_and_ip()
    await check_unsupported_entity_type_rejected()
    await check_custom_template_override()
    await check_related_alerts_happy_path()
    await check_log_analytics_error_surfaced()
    await check_health_check_happy_path()
    await check_oauth_failure_surfaced()

    print("\nALL SENTINEL CHECKS PASSED")


if __name__ == "__main__":
    asyncio.run(_main())
