"""Regression tests for the UEBA → context-bundle baseline path (#1929).

Four independent defects meant ``ContextBundleBuilder._fetch_baselines``
could not return a baseline on any deployment:

1. the default URL named ``:8086``, a port UEBA has never listened on;
2. the request carried no service credential against a router that fails
   closed (and the tenant assertion header was missing too);
3. the bundle's entity vocabulary was passed through unmapped, although
   UEBA stores hosts as ``device`` and has no ``email`` kind;
4. the response was read through field names ``BaselineOut`` does not have
   (``baseline_features``/``window_days``/``deviation_score``), so even a
   matching row produced an empty baseline and a 0.0 deviation.

These tests pin each half separately and then the whole path end to end
against an httpx mock transport that speaks UEBA's real wire shapes.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

import httpx
import pytest

_TESTS_DIR = Path(__file__).parent
_AGENTS_ROOT = _TESTS_DIR.parent
if str(_AGENTS_ROOT) not in sys.path:
    sys.path.insert(0, str(_AGENTS_ROOT))

from app.context import bundle as bundle_mod  # noqa: E402
from app.context.bundle import (  # noqa: E402
    _DEFAULT_UEBA_URL,
    _UEBA_ENTITY_TYPES,
    ContextBundleBuilder,
    EntityRef,
    _baseline_from_wire,
    _ueba_headers,
)

TENANT = "00000000-0000-0000-0000-000000000001"

#: UEBA's actual ``BaselineOut`` wire shape — ``feature_stats`` as
#: ``{feature: {mean, std, count}}`` plus the window pair. See
#: services/ueba/app/api/routes.py.
BASELINE_ROW = {
    "id": "11111111-1111-1111-1111-111111111111",
    "tenant_id": TENANT,
    "entity_type": "device",
    "entity_id": "web-01",
    "feature_stats": {
        "logon_count": {"mean": 4.2, "std": 1.1, "count": 30},
        "bytes_out": {"mean": 1024.0, "std": 300.0, "count": 30},
        "malformed": "not-a-dict",
    },
    "peer_group_id": "pg-webservers",
    "window_start": "2026-11-01T00:00:00+00:00",
    "window_end": "2026-11-15T00:00:00+00:00",
}

ANOMALY_ROW = {
    "id": "22222222-2222-2222-2222-222222222222",
    "tenant_id": TENANT,
    "entity_type": "device",
    "entity_id": "web-01",
    "event_type": "process",
    "anomaly_score": 3.4,
    "risk_level": "high",
    "features": {},
    "peer_group_id": "pg-webservers",
    "peer_deviation_score": 2.1,
    "detected_at": "2026-11-15T12:00:00+00:00",
    "acknowledged": False,
}


# ────────────────────────────────────────────────────────────────────────────
# Headers — the caller must present UEBA's token, with the tenant assertion
# ────────────────────────────────────────────────────────────────────────────


def test_headers_prefer_ueba_specific_token(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AISOC_UEBA_SERVICE_TOKEN", "ueba-token")
    monkeypatch.setenv("AISOC_SERVICE_TOKEN", "platform-token")
    headers = _ueba_headers(TENANT)
    assert headers["Authorization"] == "Bearer ueba-token"
    assert headers["X-AiSOC-Tenant-ID"] == TENANT


def test_headers_fall_back_to_platform_token(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("AISOC_UEBA_SERVICE_TOKEN", raising=False)
    monkeypatch.setenv("AISOC_SERVICE_TOKEN", "platform-token")
    assert _ueba_headers(TENANT)["Authorization"] == "Bearer platform-token"


def test_headers_carry_no_credential_when_none_configured(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("AISOC_UEBA_SERVICE_TOKEN", raising=False)
    monkeypatch.delenv("AISOC_SERVICE_TOKEN", raising=False)
    headers = _ueba_headers(TENANT)
    assert "Authorization" not in headers
    assert headers["X-AiSOC-Tenant-ID"] == TENANT


# ────────────────────────────────────────────────────────────────────────────
# Vocabulary — host maps to device, email is not queried at all
# ────────────────────────────────────────────────────────────────────────────


def test_entity_type_map_translates_host_and_excludes_email() -> None:
    assert _UEBA_ENTITY_TYPES["host"] == "device"
    assert _UEBA_ENTITY_TYPES["user"] == "user"
    assert _UEBA_ENTITY_TYPES["ip"] == "ip"
    # UEBA has no email kind; a query that can never match reads as "no
    # baseline" rather than "not a baselined kind", so email must be absent.
    assert "email" not in _UEBA_ENTITY_TYPES


def test_default_url_names_uebas_real_port() -> None:
    assert _DEFAULT_UEBA_URL == "http://ueba:8004"


def test_compose_parity_agents_point_at_ueba_8004() -> None:
    """The compose default and the code default must agree (#1929 shipped
    because nothing tied them together)."""
    compose = Path(__file__).parents[3] / "docker-compose.yml"
    if not compose.exists():  # pragma: no cover — sdist/test-only checkouts
        pytest.skip("docker-compose.yml not present in this checkout")
    text = compose.read_text(encoding="utf-8")
    m = re.search(r"AISOC_UEBA_URL:\s*\$\{AISOC_UEBA_URL:-([^}]+)\}", text)
    assert m, "agents compose block no longer sets AISOC_UEBA_URL"
    assert m.group(1) == _DEFAULT_UEBA_URL


# ────────────────────────────────────────────────────────────────────────────
# Wire mapping — BaselineOut's real field names
# ────────────────────────────────────────────────────────────────────────────


def test_baseline_from_wire_maps_feature_stats_and_window() -> None:
    entity = EntityRef(type="host", value="web-01")
    baseline = _baseline_from_wire(entity, BASELINE_ROW, deviation_score=3.4, notes="n")
    assert baseline.baseline == {"logon_count": 4.2, "bytes_out": 1024.0}
    assert baseline.activity_window_days == 14
    assert baseline.peer_group_id == "pg-webservers"
    assert baseline.deviation_score == 3.4
    assert baseline.entity.key == "host:web-01"


def test_baseline_from_wire_tolerates_sparse_rows() -> None:
    entity = EntityRef(type="user", value="svc-deploy")
    baseline = _baseline_from_wire(
        entity,
        {"entity_id": "svc-deploy", "entity_type": "user", "feature_stats": {}},
        deviation_score=0.0,
        notes="",
    )
    assert baseline.baseline == {}
    assert baseline.activity_window_days == 30  # model default, window unparseable
    assert baseline.peer_group_id is None


# ────────────────────────────────────────────────────────────────────────────
# End to end against UEBA's wire protocol
# ────────────────────────────────────────────────────────────────────────────


def _install_transport(monkeypatch: pytest.MonkeyPatch, handler) -> list[httpx.Request]:
    captured: list[httpx.Request] = []

    def _handler(request: httpx.Request) -> httpx.Response:
        captured.append(request)
        return handler(request)

    transport = httpx.MockTransport(_handler)
    real_client = httpx.AsyncClient

    def _patched(**kwargs):
        kwargs.pop("transport", None)
        return real_client(transport=transport, **kwargs)

    monkeypatch.setattr(bundle_mod.httpx, "AsyncClient", _patched)
    return captured


def _ueba_like_server(request: httpx.Request) -> httpx.Response:
    """Behaves like the real router: fails closed without a credential,
    requires the tenant assertion, filters on entity_id server-side."""
    if request.headers.get("Authorization") != "Bearer platform-token":
        return httpx.Response(401, json={"detail": "service token required"})
    if not request.headers.get("X-AiSOC-Tenant-ID"):
        return httpx.Response(403, json={"detail": "tenant scope required"})
    params = request.url.params
    if request.url.path == "/api/v1/ueba/baselines":
        if params.get("entity_type") == "device" and params.get("entity_id") == "web-01":
            return httpx.Response(200, json=[BASELINE_ROW], headers={"content-type": "application/json"})
        return httpx.Response(200, json=[], headers={"content-type": "application/json"})
    if request.url.path == "/api/v1/ueba/anomalies":
        if params.get("entity_id") == "web-01":
            return httpx.Response(200, json=[ANOMALY_ROW], headers={"content-type": "application/json"})
        return httpx.Response(200, json=[], headers={"content-type": "application/json"})
    return httpx.Response(404)


@pytest.mark.asyncio
async def test_fetch_baselines_end_to_end(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("AISOC_UEBA_SERVICE_TOKEN", raising=False)
    monkeypatch.setenv("AISOC_SERVICE_TOKEN", "platform-token")
    monkeypatch.delenv("AISOC_UEBA_URL", raising=False)
    captured = _install_transport(monkeypatch, _ueba_like_server)

    builder = ContextBundleBuilder(per_source_timeout=2.0)
    entities = [
        EntityRef(type="host", value="web-01"),
        EntityRef(type="email", value="eve@example.com"),
        EntityRef(type="ip", value="10.0.0.9"),
        EntityRef(type="domain", value="example.net"),
    ]
    out = await builder._fetch_baselines(TENANT, entities)

    # The host baseline came back fully mapped, deviation from /anomalies.
    assert set(out) == {"host:web-01"}
    got = out["host:web-01"]
    assert got.baseline["logon_count"] == 4.2
    assert got.deviation_score == 3.4
    assert got.peer_group_id == "pg-webservers"
    assert "anomaly score" in got.notes

    # email/domain were never queried; host went out as device with a
    # server-side entity_id filter; every request carried the credential pair.
    baseline_calls = [r for r in captured if r.url.path.endswith("/baselines")]
    queried_types = {r.url.params.get("entity_type") for r in baseline_calls}
    assert queried_types == {"device", "ip"}
    device_call = next(r for r in baseline_calls if r.url.params.get("entity_type") == "device")
    assert device_call.url.params.get("entity_id") == "web-01"
    assert device_call.url.params.get("limit") == "1"
    assert device_call.url.port == 8004
    for r in captured:
        assert r.headers.get("Authorization") == "Bearer platform-token"
        assert r.headers.get("X-AiSOC-Tenant-ID") == TENANT


@pytest.mark.asyncio
async def test_fetch_baselines_fails_closed_without_credential(monkeypatch: pytest.MonkeyPatch) -> None:
    """No token configured → UEBA refuses → empty result, no raise, no row."""
    monkeypatch.delenv("AISOC_UEBA_SERVICE_TOKEN", raising=False)
    monkeypatch.delenv("AISOC_SERVICE_TOKEN", raising=False)
    monkeypatch.delenv("AISOC_UEBA_URL", raising=False)
    _install_transport(monkeypatch, _ueba_like_server)

    builder = ContextBundleBuilder(per_source_timeout=2.0)
    out = await builder._fetch_baselines(TENANT, [EntityRef(type="host", value="web-01")])
    assert out == {}


@pytest.mark.asyncio
async def test_fetch_baselines_survives_anomaly_endpoint_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    """A broken /anomalies must not cost the baseline; deviation reads 0 with
    an honest 'not computed' note instead of an invented score."""
    monkeypatch.delenv("AISOC_UEBA_SERVICE_TOKEN", raising=False)
    monkeypatch.setenv("AISOC_SERVICE_TOKEN", "platform-token")
    monkeypatch.delenv("AISOC_UEBA_URL", raising=False)

    def server(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/v1/ueba/baselines":
            return httpx.Response(200, json=[BASELINE_ROW], headers={"content-type": "application/json"})
        return httpx.Response(500, json={"detail": "boom"})

    _install_transport(monkeypatch, server)
    builder = ContextBundleBuilder(per_source_timeout=2.0)
    out = await builder._fetch_baselines(TENANT, [EntityRef(type="host", value="web-01")])
    assert set(out) == {"host:web-01"}
    assert out["host:web-01"].deviation_score == 0.0
    assert "not computed" in out["host:web-01"].notes
