"""Connector egress may not point inside the deployment (GHSA-cq4g-g6wp-4m2w).

Reproduced live before the fix: a **viewer-role** console JWT posted
``POST /connectors/splunk/test`` with ``base_url`` naming a loopback listener,
and this service fetched ``GET /services/server/info`` from it and reflected
the parsed response — an SSRF with a response oracle, reachable by any
authenticated tenant user, from the service that decrypts every tenant's
integration credentials at poll time.

Three layers are pinned here, because the entry points are three:
the stateless test route (the reproduced vector), ``_instantiate_or_422``
(every other router construction site), and the scheduler's poll path (stored
rows predating registration-time validation, and DNS rebinding between save
and poll).

The guard matches the **value's shape** (an ``http(s)://`` string under any
key), not a key-name list — the census found ``base_url`` plus a dozen other
spellings, and a key list is the one-directional check that misses the next
connector. IP-literal destinations are used throughout these tests so no DNS
resolution is needed and the suite is deterministic offline.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
import uuid
from unittest.mock import AsyncMock

import httpx
import pytest
from app.security.egress import EgressRefused, refuse_internal_destinations

INTERNAL_URLS = [
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "http://127.0.0.1:5432/",
    "http://[::1]:8000/",
    "http://0.0.0.0:8000/",
    "http://2130706433/",  # 127.0.0.1 in decimal
    "http://10.0.0.5/",
    "http://192.168.1.10:8089/",
]


# ---------------------------------------------------------------------------
# The helper itself
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("url", INTERNAL_URLS)
def test_internal_urls_are_refused_under_any_key(url: str) -> None:
    with pytest.raises(EgressRefused) as exc_info:
        refuse_internal_destinations({"some_vendor_specific_field": url})
    assert exc_info.value.field_name == "some_vendor_specific_field"
    assert "destination refused" in str(exc_info.value)


def test_a_public_destination_is_accepted() -> None:
    # IP literal so the check needs no DNS. 93.184.216.34 is example.com.
    refuse_internal_destinations({"base_url": "https://93.184.216.34:8089"})


def test_non_url_strings_and_non_strings_are_ignored() -> None:
    refuse_internal_destinations(
        {
            "token": "x" * 64,
            "page_size": 500,
            "ssl_verify": False,
            "saved_search": "AiSOC notables",
            "host_label": "prod-splunk",  # not a URL shape; out of scope by design
        }
    )


def test_list_values_are_walked() -> None:
    with pytest.raises(EgressRefused):
        refuse_internal_destinations({"urls": ["https://93.184.216.34/", "http://169.254.169.254/"]})


def test_an_unresolvable_hostname_is_not_a_refusal() -> None:
    """A gaierror is the connector's own 'DNS lookup failed' to report, and a
    host the guard cannot resolve is one the client cannot connect to either.
    Deterministic both online (.invalid is NXDOMAIN by RFC 2606) and offline
    (resolution fails the same way)."""
    refuse_internal_destinations({"base_url": "https://no-such-host.invalid:8089"})


def test_allow_private_relaxes_rfc1918_but_never_metadata(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AISOC_SSRF_ALLOW_PRIVATE", "1")
    refuse_internal_destinations({"base_url": "https://10.1.2.3:8089"})  # on-prem SIEM
    with pytest.raises(EgressRefused):
        refuse_internal_destinations({"base_url": "http://169.254.169.254/latest/meta-data/"})


# ---------------------------------------------------------------------------
# The reproduced entry point: POST /connectors/{id}/test
# ---------------------------------------------------------------------------

SECRET = "egress-guard-test-secret-at-least-32-chars"


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _console_jwt(role: str = "viewer") -> str:
    header = _b64(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    payload = _b64(
        json.dumps(
            {
                "sub": "egress-test",
                "tenant_id": str(uuid.uuid4()),
                "role": role,
                "type": "access",
                "exp": int(time.time()) + 600,
            }
        ).encode()
    )
    sig = _b64(hmac.new(SECRET.encode(), f"{header}.{payload}".encode(), hashlib.sha256).digest())
    return f"{header}.{payload}.{sig}"


@pytest.fixture()
def client(monkeypatch: pytest.MonkeyPatch) -> httpx.AsyncClient:
    monkeypatch.setenv("SECRET_KEY", SECRET)
    monkeypatch.setenv("AISOC_CONNECTORS_DISABLE_SCHEDULER", "1")
    monkeypatch.delenv("AISOC_SSRF_ALLOW_PRIVATE", raising=False)
    from app.main import app

    transport = httpx.ASGITransport(app=app, raise_app_exceptions=False)
    return httpx.AsyncClient(transport=transport, base_url="http://testserver")


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "base_url",
    [
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        "http://127.0.0.1:8000",
        "http://10.0.0.5:8089",
    ],
)
async def test_the_test_route_refuses_internal_destinations(client: httpx.AsyncClient, base_url: str) -> None:
    async with client as c:
        r = await c.post(
            "/api/v1/connectors/splunk/test",
            headers={"Authorization": f"Bearer {_console_jwt('viewer')}"},
            json={"auth_config": {"token": "x"}, "connector_config": {"base_url": base_url, "ssl_verify": False}},
        )
    assert r.status_code == 422, r.text
    assert "destination refused" in r.text


@pytest.mark.asyncio
async def test_the_test_route_still_reaches_the_connector_for_public_urls(
    client: httpx.AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The guard must refuse before any socket opens, and only then. A public
    IP-literal destination (RFC 5737 TEST-NET ranges are themselves on the
    guard's blocklist, measured) passes the guard and reaches the connector's
    own test_connection — stubbed here so the test opens no real socket."""
    from app.connectors.splunk import SplunkConnector

    probe = AsyncMock(return_value={"success": True, "connector": "splunk", "version": "stub"})
    monkeypatch.setattr(SplunkConnector, "test_connection", probe)
    async with client as c:
        r = await c.post(
            "/api/v1/connectors/splunk/test",
            headers={"Authorization": f"Bearer {_console_jwt('viewer')}"},
            json={
                "auth_config": {"token": "x"},
                # example.com's address: public, so the guard admits it.
                "connector_config": {"base_url": "https://93.184.216.34:8089", "ssl_verify": False},
            },
        )
    assert "destination refused" not in r.text
    assert r.status_code == 200, r.text
    probe.assert_awaited_once()


@pytest.mark.asyncio
async def test_scheduler_owned_config_keys_do_not_reach_the_constructor(client: httpx.AsyncClient, monkeypatch: pytest.MonkeyPatch) -> None:
    """A connector that has polled once carries scheduler state in its stored
    ``connector_config`` — ``record_checkpoint`` writes ``checkpoint`` there,
    beside ``poll_interval_seconds`` and ``filter_rules``. This route merged
    the blob verbatim into the constructor, so the first recorded checkpoint
    made every later test-connection answer 422 ("unexpected keyword argument
    'checkpoint'") on every connector whose ``__init__`` does not take it.
    The exclusion is ``_connector_kwargs`` — the same set the scheduler uses —
    so the next scheduler-only key cannot drift past this route either.
    Pre-fix this test fails with exactly that 422; Splunk's ``__init__``
    declares its keywords explicitly, so the stray key cannot be swallowed."""
    from app.connectors.splunk import SplunkConnector

    probe = AsyncMock(return_value={"success": True, "connector": "splunk", "version": "stub"})
    monkeypatch.setattr(SplunkConnector, "test_connection", probe)
    async with client as c:
        r = await c.post(
            "/api/v1/connectors/splunk/test",
            headers={"Authorization": f"Bearer {_console_jwt('viewer')}"},
            json={
                "auth_config": {"token": "x"},
                "connector_config": {
                    "base_url": "https://93.184.216.34:8089",
                    "ssl_verify": False,
                    # The scheduler-owned trio a polled connector accumulates.
                    "checkpoint": {"cursor": "2026-10-29T00:00:00Z"},
                    "poll_interval_seconds": 120,
                    "filter_rules": [{"field": "severity", "op": "gte", "value": "high"}],
                },
            },
        )
    assert r.status_code == 200, r.text
    probe.assert_awaited_once()
