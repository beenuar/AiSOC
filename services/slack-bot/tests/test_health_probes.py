"""The shared probe helper, exercised in this tree too.

``app/_health.py`` is vendored byte-identical into thirteen services, and its
whole point is that every copy answers the same contract — which is only
worth something if more than one copy is ever run. ``services/api`` owns the
exhaustive suite; this asserts the parts an operator reads off a dashboard,
against *this* service's copy.

Worth keeping rather than deduplicating: when the helper grew
``register_subscription``, the api tree's tests covered the new branches and
none of the other twelve did. Here that showed up as this service's coverage
falling below its floor, which is a coarse signal and, that time, the only
one.
"""

from __future__ import annotations

from collections.abc import Callable

import pytest
from app._health import install_health_routes, register_subscription
from fastapi import FastAPI
from fastapi.testclient import TestClient


def _build_app() -> tuple[FastAPI, Callable[[], None], Callable[[], None]]:
    app = FastAPI()
    mark_ready, mark_not_ready = install_health_routes(app, service_name="aisoc-slack-bot")
    return app, mark_ready, mark_not_ready


def test_livez_is_200_before_startup_finishes() -> None:
    app, _, _ = _build_app()

    response = TestClient(app).get("/livez")

    assert response.status_code == 200
    assert response.json()["service"] == "aisoc-slack-bot"


def test_readyz_is_503_until_marked_ready() -> None:
    app, mark_ready, _ = _build_app()
    client = TestClient(app)

    assert client.get("/readyz").status_code == 503
    mark_ready()
    assert client.get("/readyz").status_code == 200


def test_readyz_is_503_again_after_draining() -> None:
    app, mark_ready, mark_not_ready = _build_app()
    client = TestClient(app)

    mark_ready()
    mark_not_ready()

    assert client.get("/readyz").status_code == 503


def test_a_detached_subscription_is_named_in_the_503() -> None:
    app, mark_ready, _ = _build_app()
    attached = {"value": True}
    register_subscription(app, "aisoc.alerts.fused", lambda: attached["value"])
    mark_ready()
    client = TestClient(app)
    assert client.get("/readyz").json()["subscriptions"] == ["aisoc.alerts.fused"]

    attached["value"] = False

    response = client.get("/readyz")
    assert response.status_code == 503
    assert response.json()["detached"] == ["aisoc.alerts.fused"]


def test_a_probe_that_raises_is_not_a_healthy_answer() -> None:
    def explode() -> bool:
        raise RuntimeError("gone")

    app, mark_ready, _ = _build_app()
    register_subscription(app, "aisoc.alerts.fused", explode)
    mark_ready()

    assert TestClient(app).get("/readyz").status_code == 503


def test_livez_ignores_a_detached_subscription() -> None:
    """Liveness failing means "restart me", and a restart does not fix a
    missing column or a revoked grant."""
    app, mark_ready, _ = _build_app()
    register_subscription(app, "aisoc.alerts.fused", lambda: False)
    mark_ready()

    assert TestClient(app).get("/livez").status_code == 200


def test_registration_requires_the_routes_first() -> None:
    with pytest.raises(RuntimeError):
        register_subscription(FastAPI(), "aisoc.alerts.fused", lambda: True)
