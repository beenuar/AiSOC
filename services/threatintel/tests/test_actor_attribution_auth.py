"""HTTP-level tests for the optional shared-secret gate on /api/v1/actors/*.

The gate (``app.api.auth.require_actor_auth``) is a no-op when
``AISOC_THREATINTEL_SERVICE_TOKEN`` is unset (internal-only default) and a
constant-time bearer-token check when it is set. We mount the real router on
a throwaway app with a real (lightweight, os_store-less) attribution engine
and drive it with FastAPI's ``TestClient``.
"""

from __future__ import annotations

import pytest
from app.actors.attribution import ThreatActorAttributionEngine
from app.api.actor_attribution import router
from app.config import settings
from fastapi import FastAPI
from fastapi.testclient import TestClient


def _client() -> TestClient:
    app = FastAPI()
    app.state.attribution_engine = ThreatActorAttributionEngine()
    app.include_router(router)
    return TestClient(app)


@pytest.fixture
def token(monkeypatch: pytest.MonkeyPatch):
    """Configure a shared secret for the duration of a test."""
    monkeypatch.setattr(settings, "AISOC_THREATINTEL_SERVICE_TOKEN", "s3cret-token")
    return "s3cret-token"


def test_unconfigured_allows_unauthenticated(monkeypatch: pytest.MonkeyPatch):
    """With no token set, the endpoints keep their internal-only open behaviour."""
    monkeypatch.setattr(settings, "AISOC_THREATINTEL_SERVICE_TOKEN", "")
    resp = _client().get("/api/v1/actors/profiles")
    assert resp.status_code == 200
    assert isinstance(resp.json(), list)


def test_configured_rejects_missing_token(token):
    resp = _client().get("/api/v1/actors/profiles")
    assert resp.status_code == 401


def test_configured_rejects_wrong_token(token):
    resp = _client().get("/api/v1/actors/profiles", headers={"Authorization": "Bearer nope"})
    assert resp.status_code == 401


def test_configured_accepts_correct_token(token):
    resp = _client().get("/api/v1/actors/profiles", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 200


def test_attribute_endpoint_is_also_gated(token):
    """The POST /attribute route is gated by the same router dependency."""
    client = _client()
    body = {"iocs": [], "mitre_techniques": ["T1566"], "case_metadata": {}}

    assert client.post("/api/v1/actors/attribute", json=body).status_code == 401

    ok = client.post(
        "/api/v1/actors/attribute",
        json=body,
        headers={"Authorization": f"Bearer {token}"},
    )
    assert ok.status_code == 200
    assert "actor_id" in ok.json()


def test_profile_by_id_is_also_gated(token):
    client = _client()
    assert client.get("/api/v1/actors/profiles/APT28").status_code == 401
    ok = client.get("/api/v1/actors/profiles/APT28", headers={"Authorization": f"Bearer {token}"})
    assert ok.status_code == 200
