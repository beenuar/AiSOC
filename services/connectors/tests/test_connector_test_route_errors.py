"""A connector's own validation message reaches the operator.

Issue #1685. A connector constructor that raises ``ValueError`` is rejecting
a value it was handed, and the message is written for the person who typed
it: "unknown mode ''", "zone_id is required when mode='waf'". That raise fell
into the catch-all in ``test_connector_connection``, which answers **500**
with a fixed string — and the API service turns a 500 from here into a 502
upstream, so the console showed ``API 502`` and the one sentence that said
what to change was discarded.

The reporter hit this through a separate console defect (a required select
submitting an empty value), and said the opaque response was what made it
hard to diagnose. Both halves are worth closing: the console should not send
an empty value, and when any caller does, the answer should say so.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
import uuid

import httpx
import pytest

SECRET = "connector-route-error-test-secret-at-least-32-chars"


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def _console_jwt(role: str = "viewer") -> str:
    header = _b64(json.dumps({"alg": "HS256", "typ": "JWT"}, separators=(",", ":")).encode())
    now = int(time.time())
    payload = _b64(
        json.dumps(
            {
                "sub": str(uuid.uuid4()),
                "tenant_id": str(uuid.uuid4()),
                "role": role,
                "type": "access",
                "iat": now,
                "exp": now + 3600,
            },
            separators=(",", ":"),
        ).encode()
    )
    sig = _b64(hmac.new(SECRET.encode(), f"{header}.{payload}".encode(), hashlib.sha256).digest())
    return f"{header}.{payload}.{sig}"


@pytest.fixture()
def client(monkeypatch: pytest.MonkeyPatch) -> httpx.AsyncClient:
    monkeypatch.setenv("SECRET_KEY", SECRET)
    monkeypatch.setenv("AISOC_CONNECTORS_DISABLE_SCHEDULER", "1")
    from app.main import app

    transport = httpx.ASGITransport(app=app, raise_app_exceptions=False)
    return httpx.AsyncClient(transport=transport, base_url="http://testserver")


@pytest.mark.asyncio
async def test_an_empty_required_select_is_422_naming_the_field(client: httpx.AsyncClient) -> None:
    """The exact payload the console sent before #1688: ``mode`` is ``''``."""
    async with client as c:
        r = await c.post(
            "/api/v1/connectors/cloudflare_zt/test",
            headers={"Authorization": f"Bearer {_console_jwt()}"},
            json={
                "auth_config": {"api_token": "t"},
                "connector_config": {"mode": "", "account_id": "a", "zone_id": "z"},
            },
        )
    assert r.status_code == 422, f"a validation message came back as {r.status_code}: {r.text}"
    assert "mode" in r.text, r.text
    assert "Failed to construct connector" not in r.text, "the connector's own message was replaced by the catch-all"


@pytest.mark.asyncio
async def test_a_missing_dependent_field_is_422_naming_the_field(client: httpx.AsyncClient) -> None:
    async with client as c:
        r = await c.post(
            "/api/v1/connectors/cloudflare_zt/test",
            headers={"Authorization": f"Bearer {_console_jwt()}"},
            json={
                "auth_config": {"api_token": "t"},
                "connector_config": {"mode": "waf", "account_id": "a"},
            },
        )
    assert r.status_code == 422, r.text
    assert "zone_id" in r.text, r.text


@pytest.mark.asyncio
async def test_an_unknown_connector_is_still_404(client: httpx.AsyncClient) -> None:
    """Positive control for the surrounding ladder.

    A route that answered 422 to everything would satisfy both tests above.
    """
    async with client as c:
        r = await c.post(
            "/api/v1/connectors/not_a_connector/test",
            headers={"Authorization": f"Bearer {_console_jwt()}"},
            json={"auth_config": {}, "connector_config": {}},
        )
    assert r.status_code == 404, r.text
