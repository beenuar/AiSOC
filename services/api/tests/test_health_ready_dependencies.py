"""``/api/v1/health`` and ``/api/v1/health/ready`` (#1446).

The chaos store-outage grader reads these two surfaces: readiness must name
every dependency it checked (a store that is gone while the body omits it is
indistinguishable from a healthy idle one), and the status code must track the
service's own job — 503 only for the block dependency (Postgres), 200 with the
key flipped for the degrade one (Redis). The grader reads the 503 *body*, so
the keys must be present on the failure path too.

Probes are monkeypatched here: what this file locks down is the route
semantics, not connectivity — the live halves are exercised by the chaos
workflow against real containers (redis and postgres legs, #1446).
"""

from __future__ import annotations

import pytest
from app.api.v1.endpoints import health
from fastapi import FastAPI
from fastapi.testclient import TestClient


def _client() -> TestClient:
    app = FastAPI()
    app.include_router(health.router, prefix="/api/v1")
    return TestClient(app)


async def _up() -> bool:
    return True


async def _down() -> bool:
    return False


def test_liveness_answers_without_touching_any_store(monkeypatch: pytest.MonkeyPatch) -> None:
    """A liveness probe that fails when a dependency is down invites the
    orchestrator to restart a healthy process. Poisoning both probes proves
    the route cannot reach them."""

    def _boom() -> bool:
        raise AssertionError("liveness touched a store probe")

    monkeypatch.setattr(health, "_database_reachable", _boom)
    monkeypatch.setattr(health, "_cache_reachable", _boom)

    response = _client().get("/api/v1/health")

    assert response.status_code == 200
    assert response.json() == {"status": "alive", "service": "aisoc-api"}


def test_ready_names_every_dependency_when_healthy(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(health, "_database_reachable", _up)
    monkeypatch.setattr(health, "_cache_reachable", _up)

    response = _client().get("/api/v1/health/ready")

    assert response.status_code == 200
    assert response.json() == {
        "status": "ready",
        "service": "aisoc-api",
        "database": True,
        "cache": True,
    }


def test_cache_loss_degrades_without_failing_readiness(monkeypatch: pytest.MonkeyPatch) -> None:
    """Redis is a cache: its loss is reported while the service keeps serving.
    Failing readiness here would pull the API out of the load balancer to fix
    a cache."""
    monkeypatch.setattr(health, "_database_reachable", _up)
    monkeypatch.setattr(health, "_cache_reachable", _down)

    response = _client().get("/api/v1/health/ready")

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ready"
    assert body["cache"] is False
    assert body["database"] is True


def test_database_loss_fails_readiness_with_the_reason_in_the_body(monkeypatch: pytest.MonkeyPatch) -> None:
    """Postgres is block: 503 so the load balancer stops sending traffic —
    and the body still names every key, because the chaos grader (and any
    operator) reads the reason out of the failure response."""
    monkeypatch.setattr(health, "_database_reachable", _down)
    monkeypatch.setattr(health, "_cache_reachable", _up)

    response = _client().get("/api/v1/health/ready")

    assert response.status_code == 503
    body = response.json()
    assert body["status"] == "not_ready"
    assert body["database"] is False
    assert body["cache"] is True
