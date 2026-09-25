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

from collections.abc import Callable

import pytest
from app._health import install_health_routes, register_subscription
from fastapi import FastAPI
from fastapi.testclient import TestClient


def _build_app() -> tuple[FastAPI, Callable[[], None], Callable[[], None]]:
    # `callable` (the builtin) was used here as a type, which is not one:
    # mypy read every `mark_ready()` in this file as calling a value of type
    # `callable?` and recorded six `misc` findings plus a `valid-type` for
    # the annotation. Adding tests below made the count grow rather than the
    # cause get fixed.
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


class TestSubscriptionProbes:
    """Readiness has to answer "is it running", not "was it started".

    UEBA is what made this necessary. Its consumer was created as a
    fire-and-forget ``asyncio.create_task`` and ``mark_ready()`` was called
    on the next line, so readiness recorded that the task had been created.
    The first scoreable event raised ``UndefinedColumnError``, the loop
    exited, and ``/readyz`` answered 200 for as long as the container was
    left up. Two other services had the same pairing.
    """

    def test_ready_stays_200_while_the_subscription_is_attached(self) -> None:
        app, mark_ready, _ = _build_app()
        register_subscription(app, "aisoc.raw_events", lambda: True)
        mark_ready()

        response = TestClient(app).get("/readyz")

        assert response.status_code == 200
        # Named on the way past, so a 200 says what it checked rather than
        # only that nothing was wrong.
        assert response.json()["subscriptions"] == ["aisoc.raw_events"]

    def test_detached_subscription_makes_readiness_503(self) -> None:
        app, mark_ready, _ = _build_app()
        attached = {"value": True}
        register_subscription(app, "aisoc.raw_events", lambda: attached["value"])
        mark_ready()
        client = TestClient(app)
        assert client.get("/readyz").status_code == 200

        attached["value"] = False

        response = client.get("/readyz")
        assert response.status_code == 503
        assert response.json()["status"] == "degraded"
        assert response.json()["detached"] == ["aisoc.raw_events"]

    def test_a_probe_that_raises_counts_as_detached(self) -> None:
        """Fail closed. The probe asks a live object whether it still
        works; if that question itself raises, the answer is not "yes"."""

        def explode() -> bool:
            raise RuntimeError("consumer object is gone")

        app, mark_ready, _ = _build_app()
        register_subscription(app, "aisoc.alerts.fused", explode)
        mark_ready()

        response = TestClient(app).get("/readyz")

        assert response.status_code == 503
        assert response.json()["detached"] == ["aisoc.alerts.fused"]

    def test_livez_ignores_a_detached_subscription(self) -> None:
        """Deliberate. Liveness failing tells an orchestrator to restart the
        pod, and a restart does not fix a missing column or a revoked grant
        — it just hides it behind a crash loop."""
        app, mark_ready, _ = _build_app()
        register_subscription(app, "aisoc.raw_events", lambda: False)
        mark_ready()

        assert TestClient(app).get("/livez").status_code == 200

    def test_probes_are_not_consulted_before_startup_finishes(self) -> None:
        """An attached consumer does not make a half-started service ready."""
        app, _, _ = _build_app()
        register_subscription(app, "aisoc.raw_events", lambda: True)

        response = TestClient(app).get("/readyz")

        assert response.status_code == 503
        assert response.json()["status"] == "starting"

    def test_registration_requires_the_routes_to_be_installed(self) -> None:
        with pytest.raises(RuntimeError):
            register_subscription(FastAPI(), "aisoc.raw_events", lambda: True)

    def test_two_apps_do_not_share_a_registry(self) -> None:
        """The registry hangs off ``app.state``, not a module global: two
        test clients in one process must not see each other's probes."""
        first, first_ready, _ = _build_app()
        second, second_ready, _ = _build_app()
        register_subscription(first, "first.topic", lambda: False)
        first_ready()
        second_ready()

        assert TestClient(first).get("/readyz").status_code == 503
        assert TestClient(second).get("/readyz").status_code == 200


def test_probes_excluded_from_openapi() -> None:
    """``/livez`` and ``/readyz`` are operator-facing; we don't want
    them spamming the SDK / OpenAPI surface that the rest of the
    routes get exposed through.
    """
    app, _, _ = _build_app()
    paths = app.openapi()["paths"]
    assert "/livez" not in paths
    assert "/readyz" not in paths
