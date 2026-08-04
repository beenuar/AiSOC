"""Wave 4 — invoking-identity authorization (W4.2 least-privilege, W4.3 route
auth, W4.4 bound approval / separation of duties)."""

from __future__ import annotations

from uuid import uuid4

import pytest
from app.core.config import get_settings
from app.models.action import ActionPrincipal, ActionRequest, ActionType
from app.security.authz import (
    ActionAuthzError,
    authorize_action,
    authorize_approver,
    has_action_permission,
)
from fastapi import FastAPI
from fastapi.testclient import TestClient

_TENANT = uuid4()


def _principal(perms, *, tenant=None, uid="u1"):
    return ActionPrincipal(user_id=uid, tenant_id=tenant, permissions=perms)


def _request(action_type, principal=None, tenant=None):
    return ActionRequest(
        incident_id=uuid4(),
        tenant_id=tenant or _TENANT,
        action_type=action_type,
        target="host-1",
        principal=principal,
    )


# ── W4.2 permission model ──────────────────────────────────────────────────


def test_permission_tiers_and_wildcards():
    assert has_action_permission(["actions:execute:high"], "actions:execute:low")
    assert has_action_permission(["actions:execute:medium"], "actions:execute:medium")
    assert not has_action_permission(["actions:execute:low"], "actions:execute:high")
    assert has_action_permission(["actions:*"], "actions:execute:high")
    assert has_action_permission(["*"], "actions:execute:medium")
    assert not has_action_permission([], "actions:execute:low")


def test_authorize_action_allows_with_sufficient_permission():
    req = _request(ActionType.ISOLATE_HOST, _principal(["actions:execute:high"], tenant=_TENANT))
    authorize_action(req, require_principal=True)  # no raise


def test_authorize_action_denies_insufficient_permission():
    req = _request(ActionType.ISOLATE_HOST, _principal(["actions:execute:low"]))
    with pytest.raises(ActionAuthzError):
        authorize_action(req, require_principal=True)


def test_authorize_action_denies_tenant_mismatch():
    req = _request(ActionType.NOTIFY_SLACK, _principal(["actions:*"], tenant=uuid4()))
    with pytest.raises(ActionAuthzError):
        authorize_action(req, require_principal=True)


def test_authorize_action_principal_optional_unless_required():
    req = _request(ActionType.ISOLATE_HOST, principal=None)
    authorize_action(req, require_principal=False)  # legacy/system path: allowed
    with pytest.raises(ActionAuthzError):
        authorize_action(req, require_principal=True)


# ── W4.4 bound approval / separation of duties ─────────────────────────────


def test_approver_must_hold_permission():
    record = {"action_type": ActionType.ISOLATE_HOST.value, "requested_by_user_id": "requester"}
    with pytest.raises(ActionAuthzError):
        authorize_approver(record, _principal(["actions:execute:low"], uid="approver"))
    authorize_approver(record, _principal(["actions:execute:high"], uid="approver"))  # ok


def test_approver_cannot_be_requester():
    record = {"action_type": ActionType.ISOLATE_HOST.value, "requested_by_user_id": "same-user"}
    with pytest.raises(ActionAuthzError):
        authorize_approver(record, _principal(["actions:execute:high"], uid="same-user"))


# ── W4.3 route auth ────────────────────────────────────────────────────────


def _client(monkeypatch, **env):
    for key in ("AISOC_ACTIONS_SERVICE_TOKEN", "AISOC_DEV_MODE", "AISOC_ACTIONS_REQUIRE_PRINCIPAL"):
        monkeypatch.delenv(key, raising=False)
    for key, value in env.items():
        monkeypatch.setenv(key, value)
    get_settings.cache_clear()
    from app.api.router import router

    app = FastAPI()
    app.include_router(router)
    return TestClient(app)


_BODY = {
    "incident_id": str(uuid4()),
    "tenant_id": str(_TENANT),
    "action_type": "isolate_host",  # approval-required → no auto-execution
    "target": "host-1",
}


def test_route_requires_token_when_configured(monkeypatch):
    client = _client(monkeypatch, AISOC_ACTIONS_SERVICE_TOKEN="s3cr3t", AISOC_DEV_MODE="false")
    assert client.post("/actions", json=_BODY).status_code == 401
    ok = client.post("/actions", json=_BODY, headers={"Authorization": "Bearer s3cr3t"})
    assert ok.status_code != 401


def test_route_open_in_dev_without_token(monkeypatch):
    client = _client(monkeypatch, AISOC_DEV_MODE="true")
    assert client.post("/actions", json=_BODY).status_code == 200


def test_route_fails_closed_in_prod_without_token(monkeypatch):
    client = _client(monkeypatch, AISOC_DEV_MODE="false")
    assert client.post("/actions", json=_BODY).status_code == 503


def teardown_module(_module):
    get_settings.cache_clear()
