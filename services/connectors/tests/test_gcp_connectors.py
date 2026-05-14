"""
Unit tests for the GCP family of connectors.

These exercise the same three concerns as the Azure suite: schema sanity,
``normalize()`` severity rules, and HTTP routing through ``respx``. The
extra wrinkle is that GCP service accounts authenticate by signing a JWT
with an RSA private key, so we generate a throwaway 2048-bit key once per
test module and forge a realistic service-account JSON blob from it. That
way ``_build_jwt`` exercises real RSA signing — we just intercept the
token endpoint to return a canned access token.
"""

from __future__ import annotations

import json

import httpx
import pytest
import respx
from app.connectors.gcp_cloud_audit import GCPCloudAuditConnector
from app.connectors.gcp_scc import GCPSCCConnector
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

_PROJECT = "aisoc-test-project"
_ORG = "1234567890"


# ---------------------------------------------------------------------------
# One throwaway RSA key per test module — generating per-test would slow
# the suite (~150ms per 2048-bit key). Module-scope keeps tests honest
# (real signing path) without paying the cost on every test.
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def fake_sa_json() -> str:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("ascii")
    return json.dumps(
        {
            "type": "service_account",
            "project_id": _PROJECT,
            "private_key_id": "abc123",
            "private_key": pem,
            "client_email": "aisoc-bot@aisoc-test-project.iam.gserviceaccount.com",
            "client_id": "111111111111111111111",
            "token_uri": "https://oauth2.googleapis.com/token",
        }
    )


# ---------------------------------------------------------------------------
# Schema sanity
# ---------------------------------------------------------------------------


def test_gcp_cloud_audit_schema_has_required_fields():
    schema = GCPCloudAuditConnector.schema()
    field_names = {f.name for f in schema.fields}
    assert {"project_id", "service_account_json"} <= field_names
    assert schema.category == "cloud"
    sa_field = next(f for f in schema.fields if f.name == "service_account_json")
    assert sa_field.type == "secret", "SA key must be a secret field"


def test_gcp_scc_schema_has_required_fields():
    schema = GCPSCCConnector.schema()
    field_names = {f.name for f in schema.fields}
    assert {"organization_id", "service_account_json"} <= field_names
    assert schema.category == "cloud"
    sa_field = next(f for f in schema.fields if f.name == "service_account_json")
    assert sa_field.type == "secret"


def test_gcp_cloud_audit_schema_oauth_hosted_is_false():
    # Service-account auth doesn't fit the hosted-OAuth flow at all; the
    # frontend should not advertise "hosted OAuth" for these connectors.
    schema = GCPCloudAuditConnector.schema()
    assert schema.oauth is not None
    assert schema.oauth.supported_in_hosted is False


# ---------------------------------------------------------------------------
# Constructor input validation
# ---------------------------------------------------------------------------


def test_gcp_connector_rejects_non_json_service_account(fake_sa_json):
    with pytest.raises(ValueError, match="not valid JSON"):
        GCPCloudAuditConnector(_PROJECT, "this-is-not-json")


def test_gcp_connector_rejects_sa_missing_required_fields():
    bad = json.dumps({"client_email": "x@y.iam.gserviceaccount.com"})
    with pytest.raises(ValueError, match="missing required field"):
        GCPCloudAuditConnector(_PROJECT, bad)


# ---------------------------------------------------------------------------
# Normalize: cloud audit severity rules
# ---------------------------------------------------------------------------


def test_cloud_audit_normalize_setiampolicy_is_high(fake_sa_json):
    connector = GCPCloudAuditConnector(_PROJECT, fake_sa_json)
    raw = {
        "insertId": "audit-1",
        "timestamp": "2026-01-01T00:00:00Z",
        "severity": "NOTICE",
        "protoPayload": {
            "methodName": "SetIamPolicy",
            "serviceName": "cloudresourcemanager.googleapis.com",
            "authenticationInfo": {"principalEmail": "alice@example.com"},
            "requestMetadata": {"callerIp": "1.2.3.4"},
            "status": {},
        },
        "resource": {"type": "project"},
    }
    out = connector.normalize(raw)
    assert out["source"] == "gcp_cloud_audit"
    assert out["severity"] == "high", "SetIamPolicy is high blast radius"
    assert out["actor"] == "alice@example.com"
    assert out["actor_email"] == "alice@example.com"
    assert out["src_ip"] == "1.2.3.4"
    assert out["event_type"].startswith("gcp.audit.")


def test_cloud_audit_normalize_failed_op_bumps_to_medium(fake_sa_json):
    connector = GCPCloudAuditConnector(_PROJECT, fake_sa_json)
    raw = {
        "insertId": "audit-2",
        "timestamp": "2026-01-01T00:00:00Z",
        "severity": "INFO",
        "protoPayload": {
            "methodName": "google.compute.v1.instances.start",
            "serviceName": "compute.googleapis.com",
            "authenticationInfo": {"principalEmail": "bob@example.com"},
            "status": {"code": 7, "message": "PERMISSION_DENIED"},
        },
        "resource": {"type": "gce_instance"},
    }
    out = connector.normalize(raw)
    assert out["severity"] == "medium", "failed control-plane operations should escalate above info"


def test_cloud_audit_normalize_routine_read_is_info(fake_sa_json):
    connector = GCPCloudAuditConnector(_PROJECT, fake_sa_json)
    raw = {
        "insertId": "audit-3",
        "timestamp": "2026-01-01T00:00:00Z",
        "severity": "INFO",
        "protoPayload": {
            "methodName": "google.storage.buckets.list",
            "serviceName": "storage.googleapis.com",
            "authenticationInfo": {"principalEmail": "alice@example.com"},
            "status": {},
        },
        "resource": {"type": "gcs_bucket"},
    }
    out = connector.normalize(raw)
    assert out["severity"] == "info"


def test_cloud_audit_normalize_critical_log_severity_is_high(fake_sa_json):
    connector = GCPCloudAuditConnector(_PROJECT, fake_sa_json)
    raw = {
        "insertId": "audit-4",
        "timestamp": "2026-01-01T00:00:00Z",
        "severity": "CRITICAL",
        "protoPayload": {
            "methodName": "google.compute.v1.instances.detachDisk",
            "serviceName": "compute.googleapis.com",
            "authenticationInfo": {"principalEmail": "alice@example.com"},
            "status": {},
        },
        "resource": {"type": "gce_instance"},
    }
    out = connector.normalize(raw)
    assert out["severity"] == "high"


# ---------------------------------------------------------------------------
# Normalize: SCC severity mapping
# ---------------------------------------------------------------------------


def test_scc_normalize_critical_preserves_critical(fake_sa_json):
    # SCC CRITICAL findings mirror directly into AiSOC's ``critical``
    # tier (P1, 15-minute MTTD SLA) — the highest-impact GCP findings
    # must not be silently downgraded.
    connector = GCPSCCConnector(_ORG, fake_sa_json)
    raw = {
        "finding": {
            "name": "organizations/123/sources/456/findings/abc",
            "category": "MALWARE_BAD_DOMAIN",
            "description": "Connection to known-bad domain",
            "severity": "CRITICAL",
            "eventTime": "2026-01-01T00:00:00Z",
            "access": {"principalEmail": "compromised@example.com"},
        },
        "resource": {
            "name": "//compute.googleapis.com/projects/p/zones/z/instances/i",
            "type": "google.compute.Instance",
        },
    }
    out = connector.normalize(raw)
    assert out["source"] == "gcp_scc"
    assert out["severity"] == "critical"
    assert out["title"] == "MALWARE_BAD_DOMAIN"
    assert out["actor_email"] == "compromised@example.com"
    assert out["resource_type"] == "google.compute.Instance"
    assert out["event_type"] == "gcp.scc.malware_bad_domain"


def test_scc_normalize_low_severity_maps_to_low(fake_sa_json):
    connector = GCPSCCConnector(_ORG, fake_sa_json)
    raw = {
        "finding": {
            "name": "organizations/123/sources/456/findings/xyz",
            "category": "OPEN_FIREWALL",
            "severity": "LOW",
            "eventTime": "2026-01-01T00:00:00Z",
        },
        "resource": {
            "name": "//compute.googleapis.com/projects/p/global/firewalls/f",
            "type": "google.compute.Firewall",
        },
    }
    out = connector.normalize(raw)
    assert out["severity"] == "low"


def test_scc_normalize_unknown_severity_falls_back_to_info(fake_sa_json):
    connector = GCPSCCConnector(_ORG, fake_sa_json)
    raw = {"finding": {"name": "x", "category": "UNKNOWN_THING"}}
    out = connector.normalize(raw)
    assert out["severity"] == "info"


# ---------------------------------------------------------------------------
# HTTP routing via respx
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
@respx.mock
async def test_cloud_audit_test_connection_success(fake_sa_json):
    respx.post("https://oauth2.googleapis.com/token").mock(
        return_value=httpx.Response(200, json={"access_token": "tok-abc", "expires_in": 3600})
    )
    respx.post("https://logging.googleapis.com/v2/entries:list").mock(return_value=httpx.Response(200, json={"entries": []}))

    connector = GCPCloudAuditConnector(_PROJECT, fake_sa_json)
    result = await connector.test_connection()
    assert result["success"] is True
    assert result["project_id"] == _PROJECT
    assert "service_account" in result


@pytest.mark.asyncio
@respx.mock
async def test_cloud_audit_test_connection_surfaces_403(fake_sa_json):
    respx.post("https://oauth2.googleapis.com/token").mock(
        return_value=httpx.Response(200, json={"access_token": "tok-abc", "expires_in": 3600})
    )
    respx.post("https://logging.googleapis.com/v2/entries:list").mock(
        return_value=httpx.Response(403, text="caller does not have permission")
    )

    connector = GCPCloudAuditConnector(_PROJECT, fake_sa_json)
    result = await connector.test_connection()
    assert result["success"] is False
    assert "403" in result["error"]


@pytest.mark.asyncio
@respx.mock
async def test_cloud_audit_fetch_alerts_returns_normalized_events(fake_sa_json):
    respx.post("https://oauth2.googleapis.com/token").mock(
        return_value=httpx.Response(200, json={"access_token": "tok-abc", "expires_in": 3600})
    )
    respx.post("https://logging.googleapis.com/v2/entries:list").mock(
        return_value=httpx.Response(
            200,
            json={
                "entries": [
                    {
                        "insertId": "log-1",
                        "timestamp": "2026-01-01T00:00:00Z",
                        "severity": "NOTICE",
                        "protoPayload": {
                            "methodName": "SetIamPolicy",
                            "serviceName": "cloudresourcemanager.googleapis.com",
                            "authenticationInfo": {"principalEmail": "alice@example.com"},
                            "status": {},
                        },
                        "resource": {"type": "project"},
                    }
                ]
            },
        )
    )

    connector = GCPCloudAuditConnector(_PROJECT, fake_sa_json)
    events = await connector.fetch_alerts(since_seconds=300)
    assert len(events) == 1
    assert events[0]["source"] == "gcp_cloud_audit"
    assert events[0]["severity"] == "high"
    assert events[0]["actor_email"] == "alice@example.com"


@pytest.mark.asyncio
@respx.mock
async def test_cloud_audit_fetch_alerts_returns_empty_on_500(fake_sa_json):
    respx.post("https://oauth2.googleapis.com/token").mock(
        return_value=httpx.Response(200, json={"access_token": "tok-abc", "expires_in": 3600})
    )
    respx.post("https://logging.googleapis.com/v2/entries:list").mock(return_value=httpx.Response(500, text="internal"))

    connector = GCPCloudAuditConnector(_PROJECT, fake_sa_json)
    events = await connector.fetch_alerts(since_seconds=300)
    assert events == []


@pytest.mark.asyncio
@respx.mock
async def test_scc_test_connection_success(fake_sa_json):
    respx.post("https://oauth2.googleapis.com/token").mock(
        return_value=httpx.Response(200, json={"access_token": "tok-abc", "expires_in": 3600})
    )
    respx.get(f"https://securitycenter.googleapis.com/v1/organizations/{_ORG}/sources").mock(
        return_value=httpx.Response(200, json={"sources": []})
    )

    connector = GCPSCCConnector(_ORG, fake_sa_json)
    result = await connector.test_connection()
    assert result["success"] is True
    assert result["organization_id"] == _ORG


@pytest.mark.asyncio
@respx.mock
async def test_scc_fetch_alerts_returns_normalized_findings(fake_sa_json):
    respx.post("https://oauth2.googleapis.com/token").mock(
        return_value=httpx.Response(200, json={"access_token": "tok-abc", "expires_in": 3600})
    )
    respx.get(f"https://securitycenter.googleapis.com/v1/organizations/{_ORG}/sources/-/findings").mock(
        return_value=httpx.Response(
            200,
            json={
                "listFindingsResults": [
                    {
                        "finding": {
                            "name": "organizations/x/sources/y/findings/z",
                            "category": "PUBLIC_BUCKET_ACL",
                            "severity": "HIGH",
                            "eventTime": "2026-01-01T00:00:00Z",
                            "description": "GCS bucket has allUsers in ACL",
                        },
                        "resource": {
                            "name": "//storage.googleapis.com/projects/p/buckets/b",
                            "type": "google.cloud.storage.Bucket",
                        },
                    }
                ]
            },
        )
    )

    connector = GCPSCCConnector(_ORG, fake_sa_json)
    events = await connector.fetch_alerts(since_seconds=300)
    assert len(events) == 1
    assert events[0]["source"] == "gcp_scc"
    assert events[0]["severity"] == "high"
    assert events[0]["title"] == "PUBLIC_BUCKET_ACL"
    assert events[0]["resource_type"] == "google.cloud.storage.Bucket"
