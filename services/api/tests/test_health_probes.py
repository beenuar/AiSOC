"""
Phase 2.6 — unit tests for the shared liveness / readiness probe
helper in ``app._health``.

We don't exercise the full ``app.main:app`` lifespan here because
that pulls in Postgres, Redis, OpenSearch, and a fistful of
background workers — they're tested separately. The helper itself
is what we want to lock down: ``/livez`` must answer 200
unconditionally and ``/readyz`` must report 503 until
``mark_ready()`` is called and 503 again after ``mark_not_ready()``.

This file lives under ``services/api/tests/`` (not in a shared
location) because the ``_health`` module is copied — by intent —
into every service's ``app/`` directory so each service can ship
independently. Phase 2.6's invariant is that every copy behaves
identically; the test verifies that invariant against the
canonical copy.
"""

from __future__ import annotations

from app._health import install_health_routes
from fastapi import FastAPI
from fastapi.testclient import TestClient


def _build_app() -> tuple[FastAPI, callable, callable]:
    app = FastAPI()
    mark_ready, mark_not_ready = install_health_routes(app, service_name="aisoc-test")
    return app, mark_ready, mark_not_ready


def test_livez_always_200() -> None:
    app, _, _ = _build_app()
    client = TestClient(app)
    response = client.get("/livez")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "alive"
    assert body["service"] == "aisoc-test"


def test_readyz_returns_503_until_marked_ready() -> None:
    app, mark_ready, _ = _build_app()
    client = TestClient(app)

    response = client.get("/readyz")
    assert response.status_code == 503
    body = response.json()
    assert body["status"] == "starting"
    assert body["service"] == "aisoc-test"

    mark_ready()
    response = client.get("/readyz")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ready"
    assert body["service"] == "aisoc-test"


def test_readyz_drains_back_to_503_on_shutdown() -> None:
    app, mark_ready, mark_not_ready = _build_app()
    client = TestClient(app)

    mark_ready()
    assert client.get("/readyz").status_code == 200

    mark_not_ready()
    response = client.get("/readyz")
    assert response.status_code == 503
    body = response.json()
    assert body["status"] == "starting"


def test_readyz_can_recover_after_not_ready() -> None:
    """Tolerate a transient draining → ready bounce.

    Some orchestrators flip readiness off during a config reload
    and back on once the reload finishes; we don't want the helper
    to be one-shot. The state machine is intentionally just a
    boolean.
    """
    app, mark_ready, mark_not_ready = _build_app()
    client = TestClient(app)

    mark_ready()
    mark_not_ready()
    mark_ready()
    assert client.get("/readyz").status_code == 200


def test_probes_excluded_from_openapi() -> None:
    """``/livez`` and ``/readyz`` are operator-facing; we don't want
    them spamming the SDK / OpenAPI surface that the rest of the
    routes get exposed through.
    """
    app, _, _ = _build_app()
    paths = app.openapi()["paths"]
    assert "/livez" not in paths
    assert "/readyz" not in paths
