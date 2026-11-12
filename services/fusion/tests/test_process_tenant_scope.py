"""Tenant scoping and role gating on the fusion write routes (GHSA-qfvv-rf5p-6h69).

``POST /process`` accepted any authenticated caller's ``RawAlert`` verbatim:
the body's ``tenant_id`` was never intersected with the credential's scope and
no role was required. A viewer in tenant A could inject alerts into tenant B's
live dedup / correlation / RBA state — and register dedup fingerprints under
tenant B, so a later *real* alert with the same fingerprint came back
``DUPLICATE``. The advisory's PoC is the first test, kept in its exact shape.

The class is wider than one route, so its siblings are pinned here too:

- ``/ml/feedback`` carries a body ``tenant_id`` and retrains the ranker;
- ``/confidence/score`` carries a body ``tenant_id`` (pure today, but an
  unchecked id is the same defect waiting for the scorer to grow state);
- ``/ml/retrain`` is a deployment-wide ML-ops trigger;
- ``/dlq/replay`` is deployment-scoped and its audited door is the API, so a
  console session — any role, any tenant — must not reach it directly.

The role sets mirror ``ROLE_PERMISSIONS`` in services/api; the mirror is
pinned by parsing that file, exactly as the agents service pins its playbook
role tables (``test_playbook_authorization.py``), and for the same reason — a
second permission model that can silently disagree with the first.
"""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock
from uuid import UUID

import pytest
from app.api import router as router_mod
from app.api.router import _MAY_WRITE_ALERTS, router, set_worker
from app.models.alert import FusedAlert, FusionDecision, RawAlert
from app.security.tenant_scope import TenantPrincipal, require_console_or_service_auth
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

TENANT_A = UUID("aaaaaaaa-0000-0000-0000-00000000000a")
TENANT_B = UUID("bbbbbbbb-0000-0000-0000-00000000000b")

API_SECURITY = Path(__file__).resolve().parents[2] / "api" / "app" / "core" / "security.py"


def _payload(tenant: UUID, **overrides: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "tenant_id": str(tenant),
        "source": "edr",
        "title": "Suspicious PowerShell execution",
        "severity": "high",
        "src_ip": "10.0.0.42",
        "hostname": "host-42",
    }
    base.update(overrides)
    return base


def _fused(alert: RawAlert) -> FusedAlert:
    return FusedAlert(
        id=alert.id,
        tenant_id=alert.tenant_id,
        fusion_decision=FusionDecision.NEW_INCIDENT,
        alert=alert,
    )


def _worker() -> MagicMock:
    worker = MagicMock()
    worker.engine = MagicMock()

    async def _process(alert: RawAlert) -> FusedAlert:
        return _fused(alert)

    worker.engine.process = AsyncMock(side_effect=_process)
    worker.engine.ml_scorer.record_feedback = AsyncMock(return_value=None)
    worker.engine.ml_scorer.retrain = AsyncMock(return_value={"status": "retrained"})
    return worker


def _client(principal: TenantPrincipal) -> AsyncClient:
    set_worker(_worker())
    app = FastAPI()
    app.include_router(router)
    app.dependency_overrides[require_console_or_service_auth] = lambda: principal
    return AsyncClient(transport=ASGITransport(app=app), base_url="http://fusion")


def _console(tenant: UUID, role: str) -> TenantPrincipal:
    return TenantPrincipal(tenant_ids=frozenset({tenant}), subject=f"console:{role}", role=role)


def _service(tenant: UUID) -> TenantPrincipal:
    return TenantPrincipal(tenant_ids=frozenset({tenant}), subject="service", delegated=True)


@pytest.fixture(autouse=True)
def _reset_worker():
    yield
    router_mod._worker_ref = None  # noqa: SLF001 — test seam


# ─────────────────────────────────────────────────────────────────────────────
# POST /process — the advisory's PoC, and the contract that replaces it
# ─────────────────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_console_caller_cannot_inject_into_another_tenant():
    """The PoC: a tenant-A session naming tenant B in the body gets 403.

    Before the fix this returned 200 with ``FusedAlert.tenant_id == B`` and a
    second submission returned ``DUPLICATE`` — proof the fingerprint had been
    registered under the victim tenant.
    """
    async with _client(_console(TENANT_A, "soc_analyst")) as client:
        resp = await client.post("/process", json=_payload(TENANT_B))
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_viewer_cannot_submit_even_to_its_own_tenant():
    """Submitting an alert is a write; ``viewer`` holds ``alerts:read`` only."""
    async with _client(_console(TENANT_A, "viewer")) as client:
        resp = await client.post("/process", json=_payload(TENANT_A))
    assert resp.status_code == 403
    assert "alerts:write" in resp.json()["detail"]


@pytest.mark.asyncio
async def test_analyst_submitting_to_own_tenant_still_works():
    async with _client(_console(TENANT_A, "soc_analyst")) as client:
        resp = await client.post("/process", json=_payload(TENANT_A))
    assert resp.status_code == 200
    assert resp.json()["tenant_id"] == str(TENANT_A)


@pytest.mark.asyncio
async def test_service_caller_is_held_to_its_declared_tenant():
    """A service token declares its tenant on X-AiSOC-Tenant-ID; the body
    must agree. The agents service's DetectAgent is this caller."""
    async with _client(_service(TENANT_A)) as client:
        ok = await client.post("/process", json=_payload(TENANT_A))
        cross = await client.post("/process", json=_payload(TENANT_B))
    assert ok.status_code == 200
    assert cross.status_code == 403


# ─────────────────────────────────────────────────────────────────────────────
# Sibling write routes carry the same contract
# ─────────────────────────────────────────────────────────────────────────────


def _feedback(tenant: UUID) -> dict[str, Any]:
    return {
        "alert_id": "99999999-9999-9999-9999-999999999999",
        "tenant_id": str(tenant),
        "analyst_id": "analyst-1",
        "is_true_positive": True,
        "assigned_priority": 2,
    }


@pytest.mark.asyncio
async def test_feedback_cannot_name_another_tenant():
    async with _client(_console(TENANT_A, "soc_analyst")) as client:
        resp = await client.post("/ml/feedback", json=_feedback(TENANT_B))
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_feedback_is_refused_to_viewer_and_allowed_to_analyst():
    async with _client(_console(TENANT_A, "viewer")) as client:
        refused = await client.post("/ml/feedback", json=_feedback(TENANT_A))
    async with _client(_console(TENANT_A, "soc_analyst")) as client:
        accepted = await client.post("/ml/feedback", json=_feedback(TENANT_A))
    assert refused.status_code == 403
    assert accepted.status_code == 200


@pytest.mark.asyncio
async def test_confidence_score_scopes_the_body_tenant():
    async with _client(_console(TENANT_A, "viewer")) as client:
        cross = await client.post("/confidence/score", json=_payload(TENANT_B))
        own = await client.post("/confidence/score", json=_payload(TENANT_A))
    assert cross.status_code == 403
    # The scorer is a read, so viewer passes for its own tenant. The stubbed
    # engine's MagicMock scorer returns MagicMock fields, so anything but a
    # 403/422 proves the gate ordering: scope check first, scorer after.
    assert own.status_code != 403


@pytest.mark.asyncio
async def test_retrain_is_refused_to_viewer():
    async with _client(_console(TENANT_A, "viewer")) as client:
        resp = await client.post("/ml/retrain")
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_dlq_replay_refuses_console_sessions_and_admits_the_service_door(monkeypatch):
    """A console admin is still refused — the audited door is the API.

    The API's gateway (services/api/app/services/dlq_replay_gateway.py)
    authenticates with the service token and the tenant header, which
    resolves to a delegated principal here.
    """
    replay = AsyncMock()
    replay.return_value = MagicMock(as_dict=lambda: {"status": "dry_run"})
    monkeypatch.setattr(router_mod, "replay_from_offset", replay)

    body = {"topic": "aisoc.raw", "partition": 0, "start_offset": 0}
    async with _client(_console(TENANT_A, "tenant_admin")) as client:
        console_resp = await client.post("/dlq/replay", json=body)
    async with _client(_service(TENANT_A)) as client:
        service_resp = await client.post("/dlq/replay", json=body)

    assert console_resp.status_code == 403
    assert "dead-letters/replay" in console_resp.json()["detail"]
    assert service_resp.status_code == 200
    replay.assert_awaited_once()


# ─────────────────────────────────────────────────────────────────────────────
# The role mirror cannot drift from the API's table
# ─────────────────────────────────────────────────────────────────────────────


def _api_role_permissions() -> dict[str, set[str]]:
    """Parse ``ROLE_PERMISSIONS`` out of the API's source.

    Parsed rather than imported: both services name their top-level package
    ``app``, so importing one inside the other's test process shadows it.
    Same approach, same reason, as the agents service's
    ``test_playbook_authorization.py``.
    """
    tree = ast.parse(API_SECURITY.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign | ast.AnnAssign):
            continue
        targets = node.targets if isinstance(node, ast.Assign) else [node.target]
        for target in targets:
            if isinstance(target, ast.Name) and target.id == "ROLE_PERMISSIONS" and node.value is not None:
                return {role: set(perms) for role, perms in ast.literal_eval(node.value).items()}
    raise AssertionError("ROLE_PERMISSIONS is no longer a module-level literal in services/api")


def test_the_role_mirror_matches_the_api() -> None:
    permissions = _api_role_permissions()
    assert permissions, "ROLE_PERMISSIONS could not be parsed; the pin is not measuring anything"
    holders = {role for role, perms in permissions.items() if "alerts:write" in perms or "*" in perms}
    assert holders == set(_MAY_WRITE_ALERTS), (
        "the roles holding alerts:write in services/api no longer match _MAY_WRITE_ALERTS "
        "in services/fusion/app/api/router.py — update the mirror deliberately"
    )


def test_viewer_does_not_hold_alerts_write_in_the_api() -> None:
    """The premise of the role gate, taken from the API rather than assumed."""
    permissions = _api_role_permissions()
    assert "viewer" in permissions, "the API no longer defines a viewer role"
    assert "alerts:write" not in permissions["viewer"]
