"""
Tests for the synchronous fusion entrypoint ``POST /process`` (Issue #190).

The endpoint exists so other services (notably ``DetectAgent`` in the
agents service) can drive the fusion pipeline over HTTP without standing
up a Kafka producer. Behaviour MUST match the Kafka path exactly — same
``FusionEngine`` instance, same dedup / correlation / scoring semantics.

These tests cover the contract the agents service depends on:

1. The endpoint returns the same ``FusedAlert`` shape the engine emits.
2. When the worker / engine is not yet ready, callers get a 503.
3. Malformed payloads fail validation at the FastAPI boundary (422).
4. The duplicate fast-path is preserved — duplicates return a
   ``DUPLICATE`` envelope and never run the rest of the pipeline.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock, MagicMock
from uuid import UUID, uuid4

import pytest
from app.api import router as router_mod
from app.api.router import router, set_worker
from app.models.alert import (
    AlertSeverity,
    FusedAlert,
    FusionDecision,
    RawAlert,
)
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient


def _raw_alert_payload(**overrides: Any) -> dict[str, Any]:
    """Build a ``RawAlert``-shaped JSON payload for ``POST /process``.

    We deliberately produce a dict (not a ``RawAlert`` instance) because
    that's what real HTTP callers send. FastAPI validates the payload
    against the Pydantic model on the boundary, so a passing test here
    is also a passing test of the wire-level contract.
    """
    base: dict[str, Any] = {
        "tenant_id": str(UUID("11111111-1111-1111-1111-111111111111")),
        "source": "edr",
        "title": "Suspicious PowerShell execution",
        "severity": "high",
        "src_ip": "10.0.0.42",
        "hostname": "host-42",
        "mitre_tactics": ["execution"],
        "mitre_techniques": ["T1059.001"],
    }
    base.update(overrides)
    return base


def _new_incident_fused(alert: RawAlert) -> FusedAlert:
    """Stand-in ``FusedAlert`` matching the engine's ``NEW_INCIDENT`` output."""
    return FusedAlert(
        id=alert.id,
        tenant_id=alert.tenant_id,
        incident_id=uuid4(),
        fusion_decision=FusionDecision.NEW_INCIDENT,
        duplicate_of=None,
        alert=alert,
    )


def _duplicate_fused(alert: RawAlert, original_id: UUID) -> FusedAlert:
    """Stand-in ``FusedAlert`` matching the engine's ``DUPLICATE`` output."""
    return FusedAlert(
        id=alert.id,
        tenant_id=alert.tenant_id,
        incident_id=None,
        fusion_decision=FusionDecision.DUPLICATE,
        duplicate_of=original_id,
        alert=alert,
    )


def _make_app(worker: Any | None) -> FastAPI:
    """Build a fresh FastAPI app with the fusion router mounted.

    We rebuild the app per test so the module-level ``_worker_ref`` is
    explicitly controlled — leaking worker state across tests would
    couple unrelated cases (e.g. the 503 test would pass spuriously if a
    previous test left a ready worker behind).
    """
    set_worker(worker) if worker is not None else _clear_worker()
    app = FastAPI()
    app.include_router(router)
    return app


def _clear_worker() -> None:
    """Reset the router's module-level worker reference to ``None``.

    ``set_worker`` only accepts a real ``FusionWorker``; for the 503
    case we need ``_worker_ref`` itself to be ``None``. Touching the
    module attribute directly is intentional — it's the same mutation
    the lifespan handler would do in reverse on shutdown.
    """
    router_mod._worker_ref = None  # noqa: SLF001 — test seam


def _stub_worker(engine_process: AsyncMock | None) -> MagicMock:
    """Build a ``FusionWorker``-shaped stub with a controllable engine.

    Passing ``engine_process=None`` simulates "worker exists but engine
    not yet initialised", which the router treats the same as no worker
    (both return 503). That branch is tested via :func:`_clear_worker`.
    """
    worker = MagicMock()
    if engine_process is None:
        worker.engine = None
    else:
        worker.engine = MagicMock()
        worker.engine.process = engine_process
    return worker


@pytest.fixture
def client_factory():
    """Return an async client factory bound to a fresh app per call.

    Using ``ASGITransport`` keeps the test in-process: no real socket,
    no port allocation, no flake budget. The factory takes the worker
    stub so each test can express its own readiness scenario.
    """

    def _factory(worker: Any | None) -> AsyncClient:
        app = _make_app(worker)
        transport = ASGITransport(app=app)
        return AsyncClient(transport=transport, base_url="http://fusion")

    return _factory


# ─────────────────────────────────────────────────────────────────────────────
# Happy path: new incident
# ─────────────────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_process_returns_fused_alert_for_new_alert(client_factory):
    """A novel alert produces a ``NEW_INCIDENT`` envelope from the engine."""
    payload = _raw_alert_payload()
    expected = _new_incident_fused(RawAlert(**payload))

    engine_process = AsyncMock(return_value=expected)
    worker = _stub_worker(engine_process)

    async with client_factory(worker) as client:
        resp = await client.post("/process", json=payload)

    assert resp.status_code == 200
    body = resp.json()
    assert body["fusion_decision"] == FusionDecision.NEW_INCIDENT.value
    assert body["incident_id"] == str(expected.incident_id)
    assert body["duplicate_of"] is None
    assert body["tenant_id"] == payload["tenant_id"]
    # The engine MUST be called exactly once with a parsed RawAlert.
    engine_process.assert_awaited_once()
    called_with = engine_process.await_args.args[0]
    assert isinstance(called_with, RawAlert)
    assert called_with.title == payload["title"]


# ─────────────────────────────────────────────────────────────────────────────
# Duplicate fast-path
# ─────────────────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_process_returns_duplicate_envelope(client_factory):
    """A duplicate alert produces a ``DUPLICATE`` envelope without an incident.

    This is the contract the agents service depends on: callers must be
    able to distinguish a fresh incident from a suppressed duplicate
    purely from the response body, never from a side channel.
    """
    payload = _raw_alert_payload()
    original_id = uuid4()
    expected = _duplicate_fused(RawAlert(**payload), original_id=original_id)

    worker = _stub_worker(AsyncMock(return_value=expected))

    async with client_factory(worker) as client:
        resp = await client.post("/process", json=payload)

    assert resp.status_code == 200
    body = resp.json()
    assert body["fusion_decision"] == FusionDecision.DUPLICATE.value
    assert body["incident_id"] is None
    assert body["duplicate_of"] == str(original_id)


# ─────────────────────────────────────────────────────────────────────────────
# Readiness gate (503)
# ─────────────────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_process_returns_503_when_worker_not_ready(client_factory):
    """Before the lifespan handler wires the worker, ``/process`` is 503."""
    async with client_factory(None) as client:
        resp = await client.post("/process", json=_raw_alert_payload())

    assert resp.status_code == 503
    assert "not ready" in resp.json()["detail"].lower()


@pytest.mark.asyncio
async def test_process_returns_503_when_engine_not_ready(client_factory):
    """A worker that exists but hasn't built its engine yet is also 503.

    This matches the router's combined check (``worker is None or
    worker.engine is None``) — both branches must surface the same 503
    so callers don't need to special-case partial readiness states.
    """
    worker = _stub_worker(engine_process=None)
    async with client_factory(worker) as client:
        resp = await client.post("/process", json=_raw_alert_payload())

    assert resp.status_code == 503


# ─────────────────────────────────────────────────────────────────────────────
# Validation
# ─────────────────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_process_rejects_malformed_payload(client_factory):
    """Missing required fields fail at the FastAPI boundary with 422.

    The agents-side client treats 4xx as a hard failure (raises) — we
    rely on this for the "don't lose alerts silently" contract, so
    pinning the status code here is load-bearing, not cosmetic.
    """
    # Missing ``tenant_id``, ``source``, ``title`` — all required.
    bad_payload = {"severity": "high"}

    worker = _stub_worker(AsyncMock())
    async with client_factory(worker) as client:
        resp = await client.post("/process", json=bad_payload)

    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_process_rejects_invalid_severity(client_factory):
    """Unknown enum values fail validation rather than silently downgrading."""
    payload = _raw_alert_payload(severity="catastrophic")  # not in the enum

    worker = _stub_worker(AsyncMock())
    async with client_factory(worker) as client:
        resp = await client.post("/process", json=payload)

    assert resp.status_code == 422


# ─────────────────────────────────────────────────────────────────────────────
# Same engine as Kafka path
# ─────────────────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_process_uses_same_engine_instance_as_worker(client_factory):
    """The HTTP path delegates to ``_worker_ref.engine.process`` — not a fresh engine.

    Issue #190 explicitly requires that the synchronous HTTP entrypoint
    and the Kafka consumer share the same engine instance (so dedup
    state, RBA rollups, and incident grouping are consistent regardless
    of how an alert arrives). We verify this by making the worker's
    engine.process the only mock that should be hit.
    """
    payload = _raw_alert_payload(severity=AlertSeverity.CRITICAL.value)
    engine_process = AsyncMock(return_value=_new_incident_fused(RawAlert(**payload)))
    worker = _stub_worker(engine_process)

    async with client_factory(worker) as client:
        await client.post("/process", json=payload)
        await client.post("/process", json=payload)

    assert engine_process.await_count == 2
