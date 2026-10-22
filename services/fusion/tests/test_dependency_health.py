from __future__ import annotations

import asyncio
import time

from app._health import install_health_routes, register_dependency
from fastapi import FastAPI
from fastapi.testclient import TestClient


def test_dependency_is_reported_before_startup_finishes() -> None:
    app = FastAPI()
    install_health_routes(app, service_name="test")
    register_dependency(app, "database", lambda: False)

    response = TestClient(app).get("/readyz")

    assert response.status_code == 503
    assert response.json()["status"] == "starting"
    assert response.json()["database"] is False


def test_required_dependency_failure_returns_503_and_named_key() -> None:
    app = FastAPI()
    mark_ready, _ = install_health_routes(app, service_name="test")
    register_dependency(app, "database", lambda: False)
    mark_ready()

    response = TestClient(app).get("/readyz")

    assert response.status_code == 503
    assert response.json()["database"] is False
    assert "database" in response.json()["detached"]


def test_optional_dependency_failure_reports_degraded_but_stays_ready() -> None:
    app = FastAPI()
    mark_ready, _ = install_health_routes(app, service_name="test")
    register_dependency(app, "lake_writer", lambda: False, required=False)
    mark_ready()

    response = TestClient(app).get("/readyz")

    assert response.status_code == 200
    assert response.json()["status"] == "ready_degraded"
    assert response.json()["lake_writer"] is False


def test_slow_dependency_is_bounded_and_reported_down() -> None:
    app = FastAPI()
    mark_ready, _ = install_health_routes(app, service_name="test")

    async def slow_probe() -> bool:
        await asyncio.sleep(10)
        return True

    register_dependency(app, "database", slow_probe)
    mark_ready()

    started = time.monotonic()
    response = TestClient(app).get("/readyz")

    assert time.monotonic() - started < 2.5
    assert response.status_code == 503
    assert response.json()["database"] is False
    assert response.json()["dependency_errors"]["database"] == "TimeoutError"
