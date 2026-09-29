"""Posture, compliance, reporting and platform-config writes authorize now.

Sixteen routes across six modules resolved a session and then checked no
entitlement. The two worth naming:

`POST /posture/findings/{id}/suppress` stands a cloud misconfiguration down
with a reason of the caller's choosing. It is the CSPM equivalent of the
pre-approval GHSA-wj5c-88hg-5926 let a `viewer` install: a read-only account
could suppress every finding in the tenant one id at a time and the dashboard
would go green.

`POST /compliance/evidence/{id}/review` sets the `status` an auditor relies
on, on a hash-chained evidence item. Ungated, a read-only account could append
to the chain and accept its own entries.

Compliance takes two different permissions on purpose: `reports:write` to
collect, `settings:write` to review, so a `soc_lead` can produce evidence and
cannot accept it. That is a role-level separation rather than the person-level
separation `services/actions` enforces on response approvals, and the reason
is a schema fact — migration 013's `aisoc_compliance_evidence` records
`reviewed_by` and no collector, so there is nobody to compare an approver
against. `test_the_role_level_separation_is_real` asserts the split; the
person-level check is not claimed anywhere.

`POST /kb/query` is deliberately left ungated and
`test_kb_query_is_deliberately_not_gated` records that as an assertion rather
than a comment, so flipping it needs a decision and an edit here.
"""

from __future__ import annotations

import uuid
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest
from app.api.v1.deps import CurrentUser, get_current_user
from app.api.v1.endpoints import compliance, deployment, easm, knowledge_base, posture, reports
from app.db.database import get_db
from fastapi import FastAPI
from fastapi.testclient import TestClient

TENANT = uuid.UUID("11111111-1111-1111-1111-111111111111")
ROW = uuid.UUID("22222222-2222-2222-2222-222222222222")

GATED: list[tuple[Any, str, str, str, str, dict[str, Any] | None]] = [
    (
        posture,
        "ingest_finding",
        "settings:write",
        "POST",
        "/api/v1/posture/findings",
        {"provider": "aws", "resource_id": "s3://b", "rule_id": "S3-1", "severity": "high", "title": "public bucket"},
    ),
    (posture, "suppress_finding", "settings:write", "POST", f"/api/v1/posture/findings/{ROW}/suppress", {"reason": "accepted"}),
    (posture, "resolve_finding", "settings:write", "POST", f"/api/v1/posture/findings/{ROW}/resolve", None),
    (posture, "cspm_scan", "settings:read", "POST", "/api/v1/posture/scan", {"resources": []}),
    (
        posture,
        "destination_preview",
        "settings:read",
        "POST",
        "/api/v1/posture/destinations/preview",
        {"kind": "webhook", "alert": {"title": "t"}},
    ),
    (
        compliance,
        "trigger_evidence_collection",
        "reports:write",
        "POST",
        "/api/v1/compliance/evidence/collect",
        {"framework": "SOC2", "scope": "all"},
    ),
    (
        compliance,
        "collect_evidence",
        "reports:write",
        "POST",
        "/api/v1/compliance/evidence",
        {"framework": "SOC2", "control_id": "CC6.1", "summary": "s", "evidence_kind": "attestation"},
    ),
    (
        compliance,
        "review_evidence",
        "settings:write",
        "POST",
        f"/api/v1/compliance/evidence/{ROW}/review",
        {"decision": "accepted"},
    ),
    (easm, "trigger_easm_scan", "settings:write", "POST", "/api/v1/easm/scan", {"tenant_id": str(TENANT)}),
    (deployment, "update_deployment_config", "settings:write", "PUT", "/api/v1/deployment/config", {"airgapped": True}),
    (deployment, "create_airgap_bundle", "settings:write", "POST", "/api/v1/deployment/airgap/bundle", None),
    (reports, "create_template", "reports:write", "POST", "/api/v1/reports/templates", {"name": "board", "report_type": "executive"}),
    (reports, "delete_template", "reports:write", "DELETE", f"/api/v1/reports/templates/{ROW}", None),
    (
        reports,
        "generate_report",
        "reports:write",
        "POST",
        "/api/v1/reports/generate",
        {"report_type": "executive", "title": "Q3", "period_start": "2026-07-01T00:00:00Z", "period_end": "2026-09-30T00:00:00Z"},
    ),
    (
        knowledge_base,
        "ingest",
        "settings:write",
        "POST",
        "/api/v1/kb/ingest",
        {"title": "runbook", "content": "steps", "doc_kind": "runbook"},
    ),
    (knowledge_base, "delete_document", "settings:write", "DELETE", f"/api/v1/kb/documents/{ROW}", None),
]

HOLDER = {"settings:write": "tenant_admin", "settings:read": "tenant_admin", "reports:write": "soc_lead"}

REFUSED = {
    "settings:write": ["viewer", "soc_analyst", "soc_lead", "threat_hunter"],
    "settings:read": ["viewer", "soc_analyst", "soc_lead", "threat_hunter"],
    "reports:write": ["viewer", "soc_analyst", "threat_hunter"],
}

IDS = [f"{m.__name__.rsplit('.', 1)[-1]}.{h}" for m, h, *_ in GATED]


def _user(role: str) -> CurrentUser:
    return CurrentUser(user_id=uuid.uuid4(), tenant_id=TENANT, role=role, email=f"{role}@tenant.example")


def _db() -> AsyncMock:
    result = MagicMock()
    result.fetchone = MagicMock(return_value=None)
    result.fetchall = MagicMock(return_value=[])
    result.scalar_one_or_none = MagicMock(return_value=None)
    result.scalars = MagicMock(return_value=MagicMock(all=MagicMock(return_value=[])))
    result.rowcount = 0
    db = AsyncMock()
    db.execute = AsyncMock(return_value=result)
    db.get = AsyncMock(return_value=None)
    db.commit = AsyncMock()
    db.rollback = AsyncMock()
    db.refresh = AsyncMock()
    db.flush = AsyncMock()
    db.delete = AsyncMock()
    db.add = MagicMock()
    return db


def _request(module: Any, role: str, method: str, path: str, payload: dict[str, Any] | None) -> tuple[int, bool]:
    app = FastAPI()
    app.include_router(module.router, prefix="/api/v1")
    db = _db()
    app.dependency_overrides[get_current_user] = lambda: _user(role)
    app.dependency_overrides[get_db] = lambda: db
    client = TestClient(app, raise_server_exceptions=False)
    response = client.request(method, path, json=payload)
    return response.status_code, db.commit.await_count > 0


def _permissions_on(route: Any) -> list[str]:
    found: list[str] = []

    def walk(dependant: Any) -> None:
        call = getattr(dependant, "call", None)
        if getattr(call, "__name__", "") == "_check":
            for cell in getattr(call, "__closure__", None) or ():
                if isinstance(cell.cell_contents, str):
                    found.append(cell.cell_contents)
        for sub in getattr(dependant, "dependencies", []):
            walk(sub)

    walk(route.dependant)
    return found


def _route_for(module: Any, handler_name: str) -> Any:
    for route in module.router.routes:
        if getattr(route, "endpoint", None) is getattr(module, handler_name):
            return route
    raise AssertionError(f"no route registered for {module.__name__}.{handler_name}")


class TestUnentitledCallersAreRefused:
    @pytest.mark.parametrize(("module", "handler", "permission", "method", "path", "payload"), GATED, ids=IDS)
    def test_every_role_without_the_permission_is_refused(
        self, module: Any, handler: str, permission: str, method: str, path: str, payload: dict[str, Any] | None
    ) -> None:
        for role in REFUSED[permission]:
            status, committed = _request(module, role, method, path, payload)
            assert not committed, f"{role} committed a write through {handler}"
            assert status == 403, f"{role} got HTTP {status} from {handler}, not 403"

    def test_a_viewer_cannot_suppress_a_cloud_misconfiguration(self) -> None:
        """Suppressing every finding one id at a time turns the dashboard green."""
        status, committed = _request(posture, "viewer", "POST", f"/api/v1/posture/findings/{ROW}/suppress", {"reason": "accepted"})
        assert not committed
        assert status == 403

    def test_a_viewer_cannot_accept_compliance_evidence(self) -> None:
        status, committed = _request(compliance, "viewer", "POST", f"/api/v1/compliance/evidence/{ROW}/review", {"decision": "accepted"})
        assert not committed
        assert status == 403

    def test_a_viewer_cannot_launch_an_external_scan(self) -> None:
        """`POST /easm/scan` runs an active TCP connect probe when enabled."""
        status, _ = _request(easm, "viewer", "POST", "/api/v1/easm/scan", {"tenant_id": str(TENANT)})
        assert status == 403

    def test_a_viewer_cannot_erase_a_runbook_for_the_whole_tenant(self) -> None:
        """The delete removes every chunk sharing the document's title."""
        status, committed = _request(knowledge_base, "viewer", "DELETE", f"/api/v1/kb/documents/{ROW}", None)
        assert not committed
        assert status == 403

    def test_a_viewer_cannot_change_the_deployment_config(self) -> None:
        """`_config` is module-level, so one request changed it for everybody."""
        status, _ = _request(deployment, "viewer", "PUT", "/api/v1/deployment/config", {"airgapped": True})
        assert status == 403


class TestTheRoleLevelSeparationIsReal:
    """Collecting evidence and accepting it are two different permissions.

    Asserted rather than described, because one permission for both would let
    whoever produced an evidence item sign it off, and that is the whole point
    of the artefact.
    """

    def test_a_lead_may_collect_evidence(self) -> None:
        status, _ = _request(
            compliance,
            "soc_lead",
            "POST",
            "/api/v1/compliance/evidence",
            {"framework": "SOC2", "control_id": "CC6.1", "summary": "s", "evidence_kind": "attestation"},
        )
        assert status != 403

    def test_the_same_lead_may_not_accept_it(self) -> None:
        status, committed = _request(compliance, "soc_lead", "POST", f"/api/v1/compliance/evidence/{ROW}/review", {"decision": "accepted"})
        assert not committed
        assert status == 403

    def test_collection_and_review_do_not_share_a_permission(self) -> None:
        collect = _permissions_on(_route_for(compliance, "collect_evidence"))
        review = _permissions_on(_route_for(compliance, "review_evidence"))
        assert collect and review
        assert set(collect).isdisjoint(review), f"collect {collect} and review {review} share a permission"


class TestEntitledCallersStillWork:
    @pytest.mark.parametrize(("module", "handler", "permission", "method", "path", "payload"), GATED, ids=IDS)
    def test_a_holder_of_the_permission_is_admitted(
        self, module: Any, handler: str, permission: str, method: str, path: str, payload: dict[str, Any] | None
    ) -> None:
        status, _ = _request(module, HOLDER[permission], method, path, payload)
        assert status != 403, f"{HOLDER[permission]} holds {permission} but {handler} answered 403"

    def test_a_lead_may_still_generate_a_board_report(self) -> None:
        """`reports:write` is held by `soc_lead`, not admins only."""
        status, _ = _request(
            reports,
            "soc_lead",
            "POST",
            "/api/v1/reports/generate",
            {"report_type": "executive", "title": "Q3", "period_start": "2026-07-01T00:00:00Z", "period_end": "2026-09-30T00:00:00Z"},
        )
        assert status != 403

    def test_a_viewer_may_still_read_posture_findings(self) -> None:
        status, _ = _request(posture, "viewer", "GET", "/api/v1/posture/findings", None)
        assert status != 403


class TestWiring:
    @pytest.mark.parametrize(("module", "handler", "permission", "method", "path", "payload"), GATED, ids=IDS)
    def test_route_enforces_exactly_its_permission(
        self, module: Any, handler: str, permission: str, method: str, path: str, payload: dict[str, Any] | None
    ) -> None:
        assert _permissions_on(_route_for(module, handler)) == [permission]

    @pytest.mark.parametrize("module", [posture, compliance, easm, deployment, reports], ids=lambda m: m.__name__.rsplit(".", 1)[-1])
    def test_no_state_changing_route_in_these_modules_is_unguarded(self, module: Any) -> None:
        unguarded = [
            getattr(r.endpoint, "__name__", "?")
            for r in module.router.routes
            if r.methods & {"POST", "PUT", "PATCH", "DELETE"} and not _permissions_on(r)
        ]
        assert not unguarded, f"{module.__name__} has state-changing routes with no permission: {unguarded}"

    def test_kb_query_is_deliberately_not_gated(self) -> None:
        """The one route in this change left alone, pinned so it stays a decision.

        The vocabulary has no knowledge-base permission: every candidate is
        either held by every role including machine keys (`cases:read`,
        `reports:read`) or restricted to tenant administrators
        (`settings:read`), which would take the runbooks away from the
        analysts who need them mid-incident. Picking one on the strength of
        its role list rather than what the route does would be
        reverse-engineering a permission from the answer.

        If somebody gates it, this fails and they write down which entitlement
        governs reading the library — and whether LLM synthesis needs a
        stronger one than retrieval. The rest of `knowledge_base.py` is gated,
        so a *new* ungated route there still fails the check below.
        """
        assert _permissions_on(_route_for(knowledge_base, "query_kb")) == []

    def test_the_rest_of_the_knowledge_base_is_gated(self) -> None:
        unguarded = {
            getattr(r.endpoint, "__name__", "?")
            for r in knowledge_base.router.routes
            if r.methods & {"POST", "PUT", "PATCH", "DELETE"} and not _permissions_on(r)
        }
        assert unguarded == {"query_kb"}, f"unexpected ungated knowledge-base routes: {unguarded - {'query_kb'}}"
