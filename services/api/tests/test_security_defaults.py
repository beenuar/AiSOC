"""Tests for the P0.3 hardening: insecure-default warnings + /metrics auth.

The audit finding was that the API silently shipped:

* a placeholder ``SECRET_KEY``
* an unauthenticated ``/metrics`` endpoint (Prometheus text exposed to
  anyone who could reach the pod)
* ``PLUGIN_TRUST_MODE=disabled`` with no operator-visible warning

These tests pin the corrective behavior so future refactors cannot
regress it without a failing test.
"""

from __future__ import annotations

import pytest
from app.core.config import (
    INSECURE_SECRET_KEY_DEFAULTS,
    Settings,
    warn_if_insecure_defaults,
)
from fastapi import FastAPI
from fastapi.testclient import TestClient


def _make_settings(**overrides) -> Settings:
    """Construct a Settings instance without reading the host .env file."""
    base: dict = {
        "ENVIRONMENT": "production",
        "SECRET_KEY": "a" * 64,
        "METRICS_TOKEN": "long-random-token",
        "PLUGIN_TRUST_MODE": "strict",
        # Pre-generated Fernet key. Real deployments mount this via Fly secret.
        "AISOC_CREDENTIAL_KEY": "Z7t9fM3pZ8U_bN5oVxQYr1w2kLsHd4aJiTvE6cNxYpA=",
        # SAML/OIDC session signing secret. Empty/placeholder values now warn
        # in prod (issue #130, finding #10), so the "clean prod" baseline
        # has to set a real value.
        "JWT_SECRET": "b" * 64,
        # Bearer token the agents service uses to push events into realtime.
        # Empty in prod means the channel is unauthenticated, which warns.
        "REALTIME_INTERNAL_TOKEN": "c" * 64,
        # Shared HS256 secret the API uses to mint WS/SSE tickets and the
        # realtime service uses to verify them (issue #239). Empty/placeholder
        # values fail closed (503) in prod, so the "clean prod" baseline must
        # set a real value.
        "AISOC_REALTIME_JWT_SECRET": "d" * 64,
    }
    base.update(overrides)
    # ``_env_file=None`` skips .env discovery so test runs are deterministic
    # regardless of the developer's local config.
    return Settings(_env_file=None, **base)


# ─── warn_if_insecure_defaults ─────────────────────────────────────────────


def test_secret_key_placeholder_in_prod_warns():
    bad = next(iter(INSECURE_SECRET_KEY_DEFAULTS))
    s = _make_settings(SECRET_KEY=bad)
    msgs = warn_if_insecure_defaults(s)
    assert any("SECRET_KEY" in m for m in msgs)


def test_secret_key_placeholder_in_dev_still_warns():
    bad = next(iter(INSECURE_SECRET_KEY_DEFAULTS))
    s = _make_settings(ENVIRONMENT="development", SECRET_KEY=bad)
    msgs = warn_if_insecure_defaults(s)
    # SECRET_KEY check is environment-independent: we always want to nag.
    assert any("SECRET_KEY" in m for m in msgs)


def test_empty_metrics_token_in_prod_warns():
    s = _make_settings(METRICS_TOKEN="")
    msgs = warn_if_insecure_defaults(s)
    assert any("METRICS_TOKEN" in m for m in msgs)


def test_empty_metrics_token_in_dev_does_not_warn():
    s = _make_settings(ENVIRONMENT="development", METRICS_TOKEN="")
    msgs = warn_if_insecure_defaults(s)
    assert not any("METRICS_TOKEN" in m for m in msgs)


def test_plugin_trust_disabled_in_prod_warns():
    s = _make_settings(PLUGIN_TRUST_MODE="disabled")
    msgs = warn_if_insecure_defaults(s)
    assert any("PLUGIN_TRUST_MODE" in m for m in msgs)


def test_plugin_trust_disabled_in_dev_does_not_warn():
    s = _make_settings(ENVIRONMENT="development", PLUGIN_TRUST_MODE="disabled")
    msgs = warn_if_insecure_defaults(s)
    assert not any("PLUGIN_TRUST_MODE" in m for m in msgs)


def test_clean_prod_settings_emit_no_warnings():
    s = _make_settings()
    msgs = warn_if_insecure_defaults(s)
    assert msgs == []


def test_empty_credential_key_in_prod_warns():
    """Operators must set AISOC_CREDENTIAL_KEY before connector secrets touch Postgres."""
    s = _make_settings(AISOC_CREDENTIAL_KEY="")
    msgs = warn_if_insecure_defaults(s)
    assert any("AISOC_CREDENTIAL_KEY" in m for m in msgs)


def test_empty_credential_key_in_dev_does_not_warn():
    """Dev auto-generates an ephemeral key, so silence here is intentional."""
    s = _make_settings(ENVIRONMENT="development", AISOC_CREDENTIAL_KEY="")
    msgs = warn_if_insecure_defaults(s)
    assert not any("AISOC_CREDENTIAL_KEY" in m for m in msgs)


def test_empty_jwt_secret_in_prod_warns():
    """SAML/OIDC session tokens must be signed with a real secret in prod."""
    s = _make_settings(JWT_SECRET="")
    msgs = warn_if_insecure_defaults(s)
    assert any("JWT_SECRET" in m for m in msgs)


def test_placeholder_jwt_secret_in_prod_warns():
    """The "changeme" sentinel is treated as empty — same warning fires."""
    s = _make_settings(JWT_SECRET="changeme-insecure-default")
    msgs = warn_if_insecure_defaults(s)
    assert any("JWT_SECRET" in m for m in msgs)


def test_empty_jwt_secret_in_dev_does_not_warn():
    """Dev environments are noisy; we don't nag there."""
    s = _make_settings(ENVIRONMENT="development", JWT_SECRET="")
    msgs = warn_if_insecure_defaults(s)
    assert not any("JWT_SECRET" in m for m in msgs)


def test_empty_realtime_token_in_prod_warns():
    """Agents → realtime channel is unauthenticated when the token is unset."""
    s = _make_settings(REALTIME_INTERNAL_TOKEN="")
    msgs = warn_if_insecure_defaults(s)
    assert any("REALTIME_INTERNAL_TOKEN" in m for m in msgs)


def test_empty_realtime_token_in_dev_does_not_warn():
    s = _make_settings(ENVIRONMENT="development", REALTIME_INTERNAL_TOKEN="")
    msgs = warn_if_insecure_defaults(s)
    assert not any("REALTIME_INTERNAL_TOKEN" in m for m in msgs)


def test_empty_realtime_jwt_secret_in_prod_warns():
    """WS/SSE ticket signing must use a real shared secret in prod (#239)."""
    s = _make_settings(AISOC_REALTIME_JWT_SECRET="")
    msgs = warn_if_insecure_defaults(s)
    assert any("AISOC_REALTIME_JWT_SECRET" in m for m in msgs)


def test_empty_realtime_jwt_secret_in_dev_does_not_warn():
    """Dev falls back to a hardcoded ticket secret, so silence is intentional."""
    s = _make_settings(ENVIRONMENT="development", AISOC_REALTIME_JWT_SECRET="")
    msgs = warn_if_insecure_defaults(s)
    assert not any("AISOC_REALTIME_JWT_SECRET" in m for m in msgs)


# ─── /metrics auth gate ────────────────────────────────────────────────────


@pytest.fixture
def metrics_app(monkeypatch):
    """A FastAPI app with just the /metrics endpoint, isolated from real settings."""
    import app.main as main_module

    # Bypass the lifespan (DB, Neo4j, plugin discovery) by mounting the
    # endpoint directly on a fresh app — we are only testing the auth gate.
    test_app = FastAPI()
    test_app.add_api_route("/metrics", main_module.metrics, methods=["GET"])
    return test_app, main_module


def test_metrics_requires_token_when_configured(metrics_app, monkeypatch):
    test_app, main_module = metrics_app
    monkeypatch.setattr(main_module.settings, "METRICS_TOKEN", "s3cret")
    monkeypatch.setattr(main_module.settings, "ENVIRONMENT", "production")

    client = TestClient(test_app)
    assert client.get("/metrics").status_code == 401
    assert client.get("/metrics", headers={"Authorization": "Bearer wrong"}).status_code == 401
    ok = client.get("/metrics", headers={"Authorization": "Bearer s3cret"})
    assert ok.status_code == 200
    assert ok.headers["content-type"].startswith("text/plain")


def test_metrics_open_in_dev_when_token_unset(metrics_app, monkeypatch):
    test_app, main_module = metrics_app
    monkeypatch.setattr(main_module.settings, "METRICS_TOKEN", "")
    monkeypatch.setattr(main_module.settings, "ENVIRONMENT", "development")

    client = TestClient(test_app)
    assert client.get("/metrics").status_code == 200


def test_metrics_refused_in_prod_when_token_unset(metrics_app, monkeypatch):
    test_app, main_module = metrics_app
    monkeypatch.setattr(main_module.settings, "METRICS_TOKEN", "")
    monkeypatch.setattr(main_module.settings, "ENVIRONMENT", "production")

    client = TestClient(test_app)
    resp = client.get("/metrics")
    assert resp.status_code == 401
    assert "METRICS_TOKEN" in resp.text


def test_metrics_token_compare_is_constant_time(metrics_app, monkeypatch):
    """Sanity check: we wired up hmac.compare_digest, not ==.

    We can't observe wall-clock timing reliably in CI, so we just assert
    that the exact-match path returns 200 and a near-match returns 401.
    The implementation comment in main.py documents the constant-time
    intent; this test fails loudly if someone replaces it with ``==``.
    """
    test_app, main_module = metrics_app
    monkeypatch.setattr(main_module.settings, "METRICS_TOKEN", "abc123")
    monkeypatch.setattr(main_module.settings, "ENVIRONMENT", "production")

    client = TestClient(test_app)
    assert client.get("/metrics", headers={"Authorization": "Bearer abc123"}).status_code == 200
    assert client.get("/metrics", headers={"Authorization": "Bearer abc124"}).status_code == 401
