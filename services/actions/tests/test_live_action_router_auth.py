"""The route that executes real vendor containment must require a token.

`/api/v1/live-actions/dispatch` reaches `dispatch()`, which runs the registered
executor against a live vendor: isolating a host, disabling an account,
blocking an IP. It carried no authentication of any kind, while the legacy
`app.api.router` mounted beside it had required a service token on every
mutating route since it was written.

The dependency is applied to the router rather than to each route, so these
tests check the whole surface rather than one handler — a route added later
should be protected without anyone remembering to decorate it.
"""

from __future__ import annotations

from uuid import uuid4

import pytest
from app.api.live_actions_router import router
from app.core.config import get_settings
from fastapi import FastAPI
from fastapi.testclient import TestClient

_BODY = {
    "request_id": str(uuid4()),
    "capability": "isolate_host",
    "vendor_id": "crowdstrike",
    "target": "WIN-DC01",
    "dry_run": True,
}


def _client(monkeypatch: pytest.MonkeyPatch, **env: str) -> TestClient:
    for key in ("AISOC_ACTIONS_SERVICE_TOKEN", "AISOC_DEV_MODE"):
        monkeypatch.delenv(key, raising=False)
    for key, value in env.items():
        monkeypatch.setenv(key, value)
    get_settings.cache_clear()
    app = FastAPI()
    app.include_router(router)
    return TestClient(app)


def test_dispatch_rejects_a_caller_with_no_token(monkeypatch: pytest.MonkeyPatch):
    client = _client(monkeypatch, AISOC_ACTIONS_SERVICE_TOKEN="s3cr3t", AISOC_DEV_MODE="false")
    assert client.post("/live-actions/dispatch", json=_BODY).status_code == 401


def test_dispatch_rejects_a_wrong_token(monkeypatch: pytest.MonkeyPatch):
    client = _client(monkeypatch, AISOC_ACTIONS_SERVICE_TOKEN="s3cr3t", AISOC_DEV_MODE="false")
    resp = client.post(
        "/live-actions/dispatch",
        json=_BODY,
        headers={"Authorization": "Bearer wrong"},
    )
    assert resp.status_code == 401


def test_dispatch_accepts_the_configured_token(monkeypatch: pytest.MonkeyPatch):
    """Auth passes, so the request reaches the dispatcher.

    The capability/vendor pair is unregistered in this bare app, and the
    router's documented contract is to report executor problems inside the
    result body rather than as an HTTP error — so a 200 here means the request
    got past auth and into `dispatch()`, which is what we are asserting.
    """
    client = _client(monkeypatch, AISOC_ACTIONS_SERVICE_TOKEN="s3cr3t", AISOC_DEV_MODE="false")
    resp = client.post(
        "/live-actions/dispatch",
        json=_BODY,
        headers={"Authorization": "Bearer s3cr3t"},
    )
    assert resp.status_code == 200


def test_unconfigured_token_fails_closed_in_production(monkeypatch: pytest.MonkeyPatch):
    """No token and no dev mode must refuse service, not serve openly."""
    client = _client(monkeypatch, AISOC_DEV_MODE="false")
    assert client.post("/live-actions/dispatch", json=_BODY).status_code == 503


def test_dev_mode_keeps_the_local_stack_usable(monkeypatch: pytest.MonkeyPatch):
    client = _client(monkeypatch, AISOC_DEV_MODE="true")
    assert client.post("/live-actions/dispatch", json=_BODY).status_code == 200


def test_the_dry_run_route_is_protected_too(monkeypatch: pytest.MonkeyPatch):
    """A dry run leaks the vendor/capability inventory, so it is not public."""
    client = _client(monkeypatch, AISOC_ACTIONS_SERVICE_TOKEN="s3cr3t", AISOC_DEV_MODE="false")
    assert client.post("/live-actions/dry-run", json=_BODY).status_code == 401


def test_every_route_on_the_router_is_protected(monkeypatch: pytest.MonkeyPatch):
    """Router-level, not per-route: a new endpoint inherits the dependency.

    Asserted by walking the router's real routes rather than a hand-kept list,
    so adding an unprotected one fails here.
    """
    client = _client(monkeypatch, AISOC_ACTIONS_SERVICE_TOKEN="s3cr3t", AISOC_DEV_MODE="false")
    checked = 0
    for route in router.routes:
        path = getattr(route, "path", "")
        if "{" in path:  # skip templated paths; no safe placeholder to inject
            continue
        for method in sorted(getattr(route, "methods", set()) - {"HEAD", "OPTIONS"}):
            resp = client.request(method, path, json=_BODY if method == "POST" else None)
            assert resp.status_code == 401, f"{method} {path} is not protected"
            checked += 1
    assert checked >= 3
