"""
Unit tests for the v8.0 wave-3 connectors:

- ``abnormal_security`` — Abnormal Security threats + cases
- ``box`` — Box admin audit events
- ``datadog`` — Datadog logs + APM events
- ``dropbox`` — Dropbox Business team audit
- ``lacework`` — Lacework cloud security alerts (smoke-tested here,
  full coverage lives next to the older lacework module)
- ``oci`` — Oracle Cloud Infrastructure audit events
- ``sublime_security`` — Sublime Security email detections

The shape mirrors ``test_saas_connectors.py``: schema sanity, then
``normalize()`` severity rules, then HTTP routing through ``respx``.
The job is *coverage of the public contract*: schema must be
wizard-renderable, ``capabilities()`` must be a tuple of the
public-facing verbs, ``normalize()`` must produce the AiSOC alert
shape with a deterministic severity for each known threat / event
type, and ``fetch_alerts()`` must swallow network errors rather than
crash the polling loop.
"""

from __future__ import annotations

import httpx
import pytest
import respx
from app.connectors.abnormal_security import AbnormalSecurityConnector
from app.connectors.base import Capability
from app.connectors.box import BoxConnector
from app.connectors.datadog import DatadogConnector
from app.connectors.dropbox import DropboxConnector
from app.connectors.lacework import LaceworkConnector
from app.connectors.oci import OCIConnector
from app.connectors.sublime_security import SublimeSecurityConnector

# ---------------------------------------------------------------------------
# Abnormal Security
# ---------------------------------------------------------------------------


def test_abnormal_schema_marks_token_as_secret():
    schema = AbnormalSecurityConnector.schema()
    names = {f.name for f in schema.fields}
    assert {"api_token"} <= names
    assert schema.category == "saas"
    token = next(f for f in schema.fields if f.name == "api_token")
    assert token.type == "secret"


def test_abnormal_capabilities_are_read_only():
    caps = set(AbnormalSecurityConnector.capabilities())
    assert Capability.PULL_ALERTS in caps
    assert Capability.PIVOT_USER in caps
    # No kinetic verbs — Abnormal connector is pull-only by design.
    kinetic = {
        Capability.ISOLATE_HOST,
        Capability.QUARANTINE_FILE,
        Capability.DISABLE_USER,
    }
    assert not (caps & kinetic)


def test_abnormal_normalize_high_threat_is_high():
    c = AbnormalSecurityConnector(api_token="t")
    norm = c.normalize(
        {
            "_kind": "threat",
            "threatId": "abn-1",
            "threatType": "businessEmailCompromise",
            "subject": "Wire transfer",
            "fromAddress": "evil@phisher.test",
            "toAddresses": ["finance@acme.test"],
        }
    )
    assert norm["severity"] == "high"
    assert norm["source"] == "abnormal_security"
    assert norm["external_id"] == "abn-1"
    assert "businessemailcompromise" in norm["event_type"]


def test_abnormal_normalize_spam_is_low():
    c = AbnormalSecurityConnector(api_token="t")
    norm = c.normalize({"_kind": "threat", "threatType": "spam"})
    assert norm["severity"] == "low"


def test_abnormal_normalize_unknown_threat_defaults_medium():
    """Abnormal only reports things it considers abnormal — the floor
    is medium, not info."""
    c = AbnormalSecurityConnector(api_token="t")
    norm = c.normalize({"_kind": "threat", "threatType": "weirdNewVector"})
    assert norm["severity"] == "medium"


@respx.mock
@pytest.mark.asyncio
async def test_abnormal_test_connection_ok():
    respx.get("https://api.abnormalplatform.com/v1/threats").mock(return_value=httpx.Response(200, json={"threats": []}))
    c = AbnormalSecurityConnector(api_token="t")
    r = await c.test_connection()
    assert r == {"success": True, "connector": "abnormal_security"}


@respx.mock
@pytest.mark.asyncio
async def test_abnormal_fetch_swallows_network_error():
    respx.get("https://api.abnormalplatform.com/v1/threats").mock(side_effect=httpx.ConnectError("boom"))
    respx.get("https://api.abnormalplatform.com/v1/cases").mock(side_effect=httpx.ConnectError("boom"))
    c = AbnormalSecurityConnector(api_token="t")
    events = await c.fetch_alerts()
    # No exception, and an empty list — exactly what the scheduler relies on.
    assert events == []


# ---------------------------------------------------------------------------
# Box
# ---------------------------------------------------------------------------


def test_box_schema_marks_token_secret():
    schema = BoxConnector.schema()
    names = {f.name for f in schema.fields}
    assert "access_token" in names
    tok = next(f for f in schema.fields if f.name == "access_token")
    assert tok.type == "secret"


def test_box_capabilities_are_audit_centric():
    caps = set(BoxConnector.capabilities())
    assert Capability.PULL_AUDIT in caps
    assert Capability.READ_AUDIT_TRAIL in caps


def test_box_normalize_shield_alert_is_high():
    c = BoxConnector(access_token="t")
    norm = c.normalize(
        {
            "event_id": "ev1",
            "event_type": "SHIELD_ALERT",
            "created_by": {"login": "alice@acme.test"},
            "source": {"item_name": "secrets.txt"},
            "ip_address": "203.0.113.10",
            "created_at": "2025-01-01T00:00:00Z",
        }
    )
    assert norm["severity"] == "high"
    assert norm["source"] == "box"
    assert norm["target"] == "secrets.txt"
    assert norm["src_ip"] == "203.0.113.10"


def test_box_normalize_collab_invite_is_medium():
    c = BoxConnector(access_token="t")
    norm = c.normalize({"event_type": "COLLABORATION_INVITE", "created_by": {}, "source": {}})
    assert norm["severity"] == "medium"


def test_box_normalize_unknown_event_is_info():
    c = BoxConnector(access_token="t")
    norm = c.normalize({"event_type": "FOO_BAR", "created_by": {}, "source": {}})
    assert norm["severity"] == "info"


@respx.mock
@pytest.mark.asyncio
async def test_box_test_connection_ok():
    respx.get("https://api.box.com/2.0/users/me").mock(
        return_value=httpx.Response(
            200,
            json={"login": "admin@acme.test", "enterprise": {"name": "Acme"}},
        )
    )
    c = BoxConnector(access_token="t")
    r = await c.test_connection()
    assert r["success"] is True
    assert r["user"] == "admin@acme.test"
    assert r["enterprise"] == "Acme"


@respx.mock
@pytest.mark.asyncio
async def test_box_fetch_swallows_500():
    respx.get("https://api.box.com/2.0/events").mock(return_value=httpx.Response(500))
    c = BoxConnector(access_token="t")
    events = await c.fetch_alerts()
    assert events == []


# ---------------------------------------------------------------------------
# Datadog (Logs + APM events)
# ---------------------------------------------------------------------------


def test_datadog_schema_has_site_mode_keys():
    schema = DatadogConnector.schema()
    names = {f.name for f in schema.fields}
    assert {"site", "mode", "query", "api_key", "application_key"} <= names
    assert schema.category == "siem"
    # both api_key and application_key must be marked secret
    assert next(f for f in schema.fields if f.name == "api_key").type == "secret"
    assert next(f for f in schema.fields if f.name == "application_key").type == "secret"


def test_datadog_capabilities():
    caps = set(DatadogConnector.capabilities())
    assert Capability.PULL_LOGS in caps
    assert Capability.PULL_ALERTS in caps
    assert Capability.QUERY_LOGS in caps


@respx.mock
@pytest.mark.asyncio
async def test_datadog_test_connection_uses_validate_endpoint():
    """``test_connection`` hits ``/api/v1/validate`` (the canonical
    Datadog key-validity probe), not the per-mode search endpoint."""
    respx.get("https://api.datadoghq.com/api/v1/validate").mock(return_value=httpx.Response(200, json={"valid": True}))
    c = DatadogConnector(site="us1", mode="logs", query="*", api_key="k", application_key="a")
    r = await c.test_connection()
    assert r["success"] is True
    assert r["site"] == "us1"
    assert r["mode"] == "logs"


@respx.mock
@pytest.mark.asyncio
async def test_datadog_fetch_logs_emits_normalized_events():
    respx.post("https://api.datadoghq.com/api/v2/logs/events/search").mock(
        return_value=httpx.Response(
            200,
            json={
                "data": [
                    {
                        "id": "log-1",
                        "attributes": {
                            "service": "nginx",
                            "status": "critical",
                            "message": "upstream timeout",
                            "host": "web-1",
                            "timestamp": "2025-01-01T00:00:00Z",
                        },
                    }
                ],
                "meta": {"page": {"after": None}},
            },
        )
    )
    c = DatadogConnector(site="us1", mode="logs", query="*", api_key="k", application_key="a")
    events = await c.fetch_alerts()
    assert len(events) == 1
    ev = events[0]
    assert ev["source"] == "datadog"
    assert ev["severity"] == "high"  # status:critical → high
    assert ev["raw_event"]["attributes"]["service"] == "nginx"


def test_datadog_normalize_log_error_is_medium():
    """``status:error`` collapses to ``medium`` (not high) — that is
    deliberate so emergencies (``emergency``/``alert``/``critical``)
    stay distinguishable in the alert queue."""
    c = DatadogConnector(site="us1", mode="logs", query="*", api_key="k", application_key="a")
    norm = c.normalize(
        {
            "_kind": "log",
            "id": "log-2",
            "attributes": {"status": "error", "message": "boom"},
        }
    )
    assert norm["severity"] == "medium"


def test_datadog_normalize_event_alert_error_is_high():
    c = DatadogConnector(site="us1", mode="events", query="*", api_key="k", application_key="a")
    norm = c.normalize(
        {
            "_kind": "event",
            "id": 42,
            "alert_type": "error",
            "title": "Monitor [host:web-1] is alerting",
        }
    )
    assert norm["severity"] == "high"
    assert norm["external_id"] == "42"


@respx.mock
@pytest.mark.asyncio
async def test_datadog_fetch_swallows_errors():
    respx.post("https://api.datadoghq.com/api/v2/logs/events/search").mock(side_effect=httpx.ReadTimeout("slow"))
    c = DatadogConnector(site="us1", mode="logs", query="*", api_key="k", application_key="a")
    events = await c.fetch_alerts()
    assert events == []


# ---------------------------------------------------------------------------
# Dropbox
# ---------------------------------------------------------------------------


def test_dropbox_schema_marks_token_secret():
    schema = DropboxConnector.schema()
    names = {f.name for f in schema.fields}
    assert "team_admin_token" in names
    tok = next(f for f in schema.fields if f.name == "team_admin_token")
    assert tok.type == "secret"


def test_dropbox_capabilities_are_audit_centric():
    caps = set(DropboxConnector.capabilities())
    assert Capability.PULL_AUDIT in caps
    assert Capability.PIVOT_USER in caps


def test_dropbox_normalize_admin_change_is_high():
    c = DropboxConnector(team_admin_token="t")
    norm = c.normalize(
        {
            "event_id": "ev-1",
            "event_category": {".tag": "members"},
            "event_type": {".tag": "member_change_admin_role"},
            "actor": {"user": {"email": "admin@acme.test"}},
            "context": {"user": {"email": "bob@acme.test"}},
            "timestamp": "2025-01-01T00:00:00Z",
        }
    )
    assert norm["severity"] == "high"
    assert norm["source"] == "dropbox"


def test_dropbox_normalize_login_fail_is_medium():
    c = DropboxConnector(team_admin_token="t")
    norm = c.normalize(
        {
            "event_id": "ev-2",
            "event_category": {".tag": "logins"},
            "event_type": {".tag": "login_fail"},
            "actor": {"user": {"email": "u@acme.test"}},
            "context": {},
        }
    )
    assert norm["severity"] == "medium"


def test_dropbox_normalize_unknown_event_is_info():
    """Severity is prefix-driven over ``event_type``; types that do
    not match either prefix list stay at the floor."""
    c = DropboxConnector(team_admin_token="t")
    norm = c.normalize(
        {
            "event_id": "ev-3",
            "event_type": {".tag": "file_unrelated_event"},
            "actor": {"user": {}},
        }
    )
    assert norm["severity"] == "info"


@respx.mock
@pytest.mark.asyncio
async def test_dropbox_test_connection_hits_team_get_info():
    """``test_connection`` calls ``/2/team/get_info`` — that returns
    the team name + provisioned-user count, which the wizard surfaces
    so the operator can confirm they connected the right tenant."""
    respx.post("https://api.dropboxapi.com/2/team/get_info").mock(
        return_value=httpx.Response(200, json={"name": "Acme", "num_provisioned_users": 42})
    )
    c = DropboxConnector(team_admin_token="t")
    r = await c.test_connection()
    assert r["success"] is True
    assert r["team"] == "Acme"
    assert r["members"] == 42


@respx.mock
@pytest.mark.asyncio
async def test_dropbox_fetch_swallows_500():
    respx.post("https://api.dropboxapi.com/2/team_log/get_events").mock(return_value=httpx.Response(500))
    c = DropboxConnector(team_admin_token="t")
    events = await c.fetch_alerts()
    assert events == []


# ---------------------------------------------------------------------------
# Lacework (smoke — full coverage lives in the original lacework module)
# ---------------------------------------------------------------------------


def test_lacework_schema_marks_secret_secret():
    schema = LaceworkConnector.schema()
    names = {f.name for f in schema.fields}
    assert {"account", "key_id", "secret"} <= names
    assert next(f for f in schema.fields if f.name == "secret").type == "secret"


def test_lacework_capabilities():
    caps = set(LaceworkConnector.capabilities())
    assert Capability.PULL_ALERTS in caps
    assert Capability.ENRICH_VULN in caps


# ---------------------------------------------------------------------------
# OCI
# ---------------------------------------------------------------------------


def test_oci_schema_required_fields_present():
    schema = OCIConnector.schema()
    names = {f.name for f in schema.fields}
    assert {
        "tenancy_ocid",
        "user_ocid",
        "compartment_ocid",
        "fingerprint",
        "private_key_pem",
        "region",
    } <= names
    pem = next(f for f in schema.fields if f.name == "private_key_pem")
    assert pem.type == "secret"


def test_oci_capabilities_are_audit_centric():
    caps = set(OCIConnector.capabilities())
    assert Capability.PULL_AUDIT in caps
    assert Capability.READ_AUDIT_TRAIL in caps


# ---------------------------------------------------------------------------
# Sublime Security
# ---------------------------------------------------------------------------


def test_sublime_schema_marks_api_key_secret():
    schema = SublimeSecurityConnector.schema()
    names = {f.name for f in schema.fields}
    assert "api_key" in names
    key = next(f for f in schema.fields if f.name == "api_key")
    assert key.type == "secret"
    # base_url must be optional with a default
    base_url = next(f for f in schema.fields if f.name == "base_url")
    assert base_url.required is False
    assert base_url.default == "https://api.platform.sublimesecurity.com"


def test_sublime_capabilities():
    caps = set(SublimeSecurityConnector.capabilities())
    assert Capability.PULL_ALERTS in caps
    assert Capability.PIVOT_USER in caps
    assert Capability.QUARANTINE_FILE in caps


def test_sublime_normalize_malicious_is_high():
    c = SublimeSecurityConnector(api_key="t")
    norm = c.normalize({"id": "m1", "classification": "malicious", "subject": "wire"})
    assert norm["severity"] == "high"
    assert norm["source"] == "sublime_security"
    assert norm["external_id"] == "m1"


def test_sublime_normalize_phishing_rule_promotes_to_high():
    """Even if classification is suspicious, a phishing-rule trigger
    must promote to high (mirrors the production behaviour)."""
    c = SublimeSecurityConnector(api_key="t")
    norm = c.normalize(
        {
            "id": "m2",
            "classification": "suspicious",
            "triggered_rules": [{"name": "Credential Phishing — Microsoft 365"}],
        }
    )
    assert norm["severity"] == "high"


def test_sublime_normalize_benign_is_info():
    c = SublimeSecurityConnector(api_key="t")
    norm = c.normalize({"id": "m3", "classification": "benign"})
    assert norm["severity"] == "info"


@respx.mock
@pytest.mark.asyncio
async def test_sublime_test_connection_ok():
    respx.get("https://api.platform.sublimesecurity.com/v1/me").mock(
        return_value=httpx.Response(200, json={"organization": {"name": "Acme"}})
    )
    c = SublimeSecurityConnector(api_key="t")
    r = await c.test_connection()
    assert r["success"] is True
    assert r["tenant"] == "Acme"


@respx.mock
@pytest.mark.asyncio
async def test_sublime_fetch_swallows_500():
    respx.get("https://api.platform.sublimesecurity.com/v1/messages").mock(return_value=httpx.Response(500))
    c = SublimeSecurityConnector(api_key="t")
    events = await c.fetch_alerts()
    assert events == []
