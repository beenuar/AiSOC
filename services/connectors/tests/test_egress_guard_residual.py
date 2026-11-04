"""The residual half of the connector egress guard (GHSA-32q9-5fvr-8wcx).

GHSA-cq4g-g6wp-4m2w closed ``POST /connectors/{id}/test`` and the scheduler's
poll path. Two ways through were left, and both are reachable by the same
authenticated tenant user that reproduced the original report:

**Routes that build a connector without the guard.** ``_instantiate_or_422``
runs the check, but three construction sites called ``cls(**kwargs)``
directly — ``POST /connectors/{id}/query``, ``POST
/connectors/{id}/resource_config`` and the saved-instance
``GET /connectors/instances/{id}/resource-config``. The first two take the
destination straight from the request body, so the fix for ``/test`` moved
the vector one route sideways rather than closing it.

**Bare host fields.** The guard matched values shaped like an
``http(s)://`` URL. Nine connectors assemble their URL from a hostname
instead — ``f"https://{self._host}{path}"`` in Duo, ``self._fqdn`` in Cortex
XDR, ``tenant_fqdn`` in XSIAM, ``domain`` in Auth0 — so ``api_hostname =
169.254.169.254`` reached cloud metadata under a guard that had looked at the
value and declared it not a URL. The four that interpolate into a vendor
suffix (``f"https://{account}.lacework.net"``) are not safe by construction
either: one ``/`` or ``#`` in the value ends the authority and the suffix
lands in the path.

Every assertion here is an IP literal or an RFC 2606 ``.invalid`` name, so the
suite is deterministic offline — no test depends on a DNS answer.
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

SECRET = "egress-residual-test-secret-at-least-32-chars"

#: Destinations inside the deployment, in the spellings the report used.
INTERNAL_HOSTS = [
    "169.254.169.254",
    "127.0.0.1:5432",
    "10.0.0.5",
    "192.168.1.10:8089",
    "localhost:9200",
]


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _console_jwt(role: str = "viewer") -> str:
    header = _b64(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    payload = _b64(
        json.dumps(
            {
                "sub": "egress-residual-test",
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


# ---------------------------------------------------------------------------
# Routes that built a connector without the guard
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
@pytest.mark.parametrize("base_url", ["http://169.254.169.254", "http://127.0.0.1:9200", "http://10.0.0.5:8089"])
async def test_query_route_refuses_internal_destinations(client: httpx.AsyncClient, base_url: str) -> None:
    """``/query`` is the report's proof of concept, verbatim.

    Pre-fix this route answered 502 after the connector had already opened
    the socket — the refusal must land before the constructor, so the only
    acceptable answer is 422 naming the field.
    """
    async with client as c:
        r = await c.post(
            "/api/v1/connectors/splunk/query",
            headers={"Authorization": f"Bearer {_console_jwt('viewer')}"},
            json={
                "auth_config": {"token": "x"},
                "connector_config": {"base_url": base_url, "ssl_verify": False},
                "query": {"free_text": "failed login", "limit": 1},
            },
        )
    assert r.status_code == 422, r.text
    assert "destination refused" in r.text


@pytest.mark.asyncio
async def test_resource_config_route_refuses_internal_destinations(client: httpx.AsyncClient) -> None:
    """The posture-collection route takes its destination from the body too."""
    async with client as c:
        r = await c.post(
            "/api/v1/connectors/okta/resource_config",
            headers={"Authorization": f"Bearer {_console_jwt('viewer')}"},
            json={
                "auth_config": {"api_token": "x"},
                "connector_config": {"domain": "http://169.254.169.254"},
                "resource_id": "whatever",
            },
        )
    assert r.status_code == 422, r.text
    assert "destination refused" in r.text


@pytest.mark.asyncio
async def test_query_route_still_reaches_a_public_destination(client: httpx.AsyncClient, monkeypatch: pytest.MonkeyPatch) -> None:
    """The positive control: refusing everything would pass the test above.

    93.184.216.34 is example.com's address — public, so the guard admits it
    and the connector's own ``query`` is reached. Stubbed, so no socket opens.
    """
    from app.connectors.splunk import SplunkConnector

    probe = AsyncMock(return_value=[])
    monkeypatch.setattr(SplunkConnector, "query", probe)
    async with client as c:
        r = await c.post(
            "/api/v1/connectors/splunk/query",
            headers={"Authorization": f"Bearer {_console_jwt('viewer')}"},
            json={
                "auth_config": {"token": "x"},
                "connector_config": {"base_url": "https://93.184.216.34:8089", "ssl_verify": False},
                "query": {"free_text": "failed login", "limit": 1},
            },
        )
    assert "destination refused" not in r.text
    assert r.status_code == 200, r.text
    probe.assert_awaited_once()


@pytest.mark.asyncio
async def test_query_route_drops_scheduler_owned_config_keys(client: httpx.AsyncClient, monkeypatch: pytest.MonkeyPatch) -> None:
    """Same drift ``/test`` had: a polled instance carries ``checkpoint``.

    ``/query`` merged the stored blob verbatim, so a connector that had polled
    once answered 422 ("unexpected keyword argument 'checkpoint'") on every
    federated search. Routing through ``_connector_kwargs`` is what keeps the
    exclusion in one place.
    """
    from app.connectors.splunk import SplunkConnector

    probe = AsyncMock(return_value=[])
    monkeypatch.setattr(SplunkConnector, "query", probe)
    async with client as c:
        r = await c.post(
            "/api/v1/connectors/splunk/query",
            headers={"Authorization": f"Bearer {_console_jwt('viewer')}"},
            json={
                "auth_config": {"token": "x"},
                "connector_config": {
                    "base_url": "https://93.184.216.34:8089",
                    "ssl_verify": False,
                    "checkpoint": {"cursor": "2026-11-04T00:00:00Z"},
                    "poll_interval_seconds": 120,
                    "filter_rules": [{"field": "severity", "op": "gte", "value": "high"}],
                },
                "query": {"free_text": "failed login", "limit": 1},
            },
        )
    assert r.status_code == 200, r.text
    probe.assert_awaited_once()


# ---------------------------------------------------------------------------
# Bare host fields
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("host", INTERNAL_HOSTS)
def test_bare_host_values_are_refused(host: str) -> None:
    """A hostname is a destination whenever a connector interpolates it.

    The key name is deliberately one no connector declares: the rule is the
    value's shape, not a list of field names, for the same reason the URL rule
    is — a key list silently misses the next connector.
    """
    with pytest.raises(EgressRefused) as exc_info:
        refuse_internal_destinations({"some_vendor_hostname": host})
    assert exc_info.value.field_name == "some_vendor_hostname"


@pytest.mark.parametrize(
    "field,value",
    [
        ("api_hostname", "169.254.169.254"),  # duo_security -> f"https://{host}{path}"
        ("fqdn", "10.0.0.5"),  # cortex_xdr
        ("tenant_fqdn", "127.0.0.1"),  # cortex_xsiam
        ("domain", "192.168.1.10"),  # auth0 -> f"https://{domain}"
    ],
)
def test_the_real_bare_host_fields_are_refused(field: str, value: str) -> None:
    with pytest.raises(EgressRefused):
        refuse_internal_destinations({field: value})


@pytest.mark.parametrize(
    "value",
    [
        "169.254.169.254/",  # f"https://{account}.lacework.net" -> suffix lands in the path
        "169.254.169.254#",  # ...and here in the fragment
        "169.254.169.254?x=",
        "user@169.254.169.254",  # userinfo, so the authority is still the metadata IP
    ],
)
def test_suffix_template_breakouts_are_refused(value: str) -> None:
    """Four connectors build ``f"https://{value}.vendor.com"``.

    A vendor suffix is not a boundary: one delimiter ends the authority and
    everything after it is a path, a query or a fragment. The guard has to
    read the authority the way the URL parser will, not the way the format
    string reads.
    """
    with pytest.raises(EgressRefused):
        refuse_internal_destinations({"account": value})


@pytest.mark.asyncio
async def test_bare_host_refused_through_the_real_route(client: httpx.AsyncClient) -> None:
    """End to end, through the ASGI app and the real auth dependency."""
    async with client as c:
        r = await c.post(
            "/api/v1/connectors/duo_security/test",
            headers={"Authorization": f"Bearer {_console_jwt('viewer')}"},
            json={
                "auth_config": {"integration_key": "DI1", "secret_key": "s"},
                "connector_config": {"api_hostname": "169.254.169.254"},
            },
        )
    assert r.status_code == 422, r.text
    assert "destination refused" in r.text


# ---------------------------------------------------------------------------
# What must keep working — the false-positive floor
# ---------------------------------------------------------------------------


def test_non_destination_strings_are_still_ignored() -> None:
    """The cost of a host rule is false refusals, so this is the real test.

    None of these is a destination. ``prod-splunk`` and the opaque token have
    no dot and are not IP literals; the saved-search name has a space; the
    index pattern has a glob; the version string resolves nowhere. Any of them
    refusing would break a working connector on upgrade, which is worse than
    the bug.
    """
    refuse_internal_destinations(
        {
            "token": "x" * 64,
            "page_size": 500,
            "ssl_verify": False,
            "saved_search": "AiSOC notables",
            "host_label": "prod-splunk",
            "index_pattern": "wazuh-alerts-*",
            "region": "us-east-1",
            "tenant_id": str(uuid.uuid4()),
            "api_version": "2.11.0",
            "email": "soc@example.invalid",
        }
    )


def test_a_legitimate_vendor_hostname_is_accepted() -> None:
    """An unresolvable name is the connector's own error to report, not ours.

    ``.invalid`` is NXDOMAIN by RFC 2606, which is the same ``gaierror`` a
    customer's unreachable on-prem hostname produces — the carve-out the URL
    rule already makes, applied identically to the host rule.
    """
    refuse_internal_destinations({"api_hostname": "mycompany.duosecurity.invalid"})
    refuse_internal_destinations({"domain": "acme.okta.invalid"})


def test_allow_private_relaxes_a_bare_host_but_never_metadata(monkeypatch: pytest.MonkeyPatch) -> None:
    """On-prem deployments keep their escape hatch; metadata is never in it."""
    monkeypatch.setenv("AISOC_SSRF_ALLOW_PRIVATE", "1")
    refuse_internal_destinations({"fqdn": "10.1.2.3"})
    with pytest.raises(EgressRefused):
        refuse_internal_destinations({"fqdn": "169.254.169.254"})
