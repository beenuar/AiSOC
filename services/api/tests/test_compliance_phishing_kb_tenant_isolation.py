"""Tenant-isolation tests for /compliance, /phishing, and /kb endpoints.

These tests verify that every SQL statement in the compliance, phishing,
and knowledge-base endpoints filters on ``tenant_id`` — preventing
cross-tenant data leakage.

Follows the same mock-session pattern used by
``test_alerts_tenant_isolation.py`` and
``test_threat_intel_tenant_isolation.py``.
"""

from __future__ import annotations

import json
import re
import uuid
from datetime import UTC, datetime
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest
from app.api.v1.deps import CurrentUser

# ────────────────────────────────────────────────────────────────────────────
# Helpers
# ────────────────────────────────────────────────────────────────────────────


def _bound(executed: list[tuple[str, dict[str, Any]]], fragment: str) -> dict[str, Any]:
    """Return the bound parameters of the one executed statement matching ``fragment``."""
    normalized = [(re.sub(r"\s+", " ", sql).lower(), params) for sql, params in executed]
    matches = [params for sql, params in normalized if fragment.lower() in sql]
    assert matches, f"no executed statement contained {fragment!r}; saw {[s for s, _ in normalized]}"
    return matches[0]


def _user(tenant_id: uuid.UUID | None = None) -> CurrentUser:
    """Construct the real authenticated principal without touching DB or JWT.

    This used to be a ``MagicMock`` that assigned ``__str__``. That one line
    made ``str(user)`` return an email under test while the real
    :class:`CurrentUser` returned ``<...CurrentUser object at 0x...>``, so
    three handlers stamping an actor column that way passed their tests and
    wrote an object address to the column an auditor reads. Use the real
    class: a principal fake that is friendlier than the principal proves
    nothing about the principal.
    """
    return CurrentUser(
        user_id=uuid.uuid4(),
        tenant_id=tenant_id or uuid.uuid4(),
        role="analyst",
        email="analyst@example.com",
    )


def _mk_db(rows: list[Any]) -> MagicMock:
    """Mock AsyncSession that captures executed SQL and returns queued rows."""
    db = MagicMock()
    db.executed: list[tuple[str, dict[str, Any]]] = []
    iterator = iter(rows)

    async def _execute(clause: Any, *args: Any, **kwargs: Any) -> MagicMock:
        sql = str(clause)
        try:
            params = dict(clause.compile().params) if hasattr(clause, "compile") else {}
        except Exception:
            params = {}
        db.executed.append((sql, params))
        try:
            payload = next(iterator)
        except StopIteration:
            payload = None
        result = MagicMock()
        if isinstance(payload, list):
            result.fetchall = MagicMock(return_value=payload)
            result.fetchone = MagicMock(return_value=payload[0] if payload else None)
        else:
            result.fetchall = MagicMock(return_value=[payload] if payload else [])
            result.fetchone = MagicMock(return_value=payload)
        return result

    db.execute = AsyncMock(side_effect=_execute)
    db.commit = AsyncMock()
    db.rollback = AsyncMock()
    return db


def _assert_tenant_scoped(
    executed: list[tuple[str, dict[str, Any]]],
    tenant_id: uuid.UUID,
    table_name: str,
) -> None:
    """Every executed statement against ``table_name`` must filter on tenant_id."""
    assert executed, "expected at least one DB call"
    saw_tenant_scoped = False
    for sql, params in executed:
        normalized = re.sub(r"\s+", " ", sql).lower()
        if table_name not in normalized:
            continue
        assert "tenant_id" in normalized, f"SQL against {table_name} missing tenant_id filter: {sql}"
        matching = [
            (name, value) for name, value in params.items() if (name == "tenant_id" or name.startswith("tenant_id_")) and value == tenant_id
        ]
        assert matching, f"no bound tenant_id matches caller's tenant in SQL: {sql}; params={params}; expected_tenant={tenant_id}"
        saw_tenant_scoped = True
    assert saw_tenant_scoped, f"no {table_name} statement was tenant-scoped; every read/write must filter on tenant_id"


def _evidence_row(tenant_id: uuid.UUID, **overrides: Any) -> MagicMock:
    """Build a fake compliance evidence row."""
    now = datetime.now(UTC)
    defaults = {
        "id": uuid.uuid4(),
        "tenant_id": tenant_id,
        "case_id": None,
        "framework": "SOC2",
        "control_id": "CC7.2",
        "control_title": "System Monitoring",
        "evidence_kind": "alert",
        "summary": "Test evidence item",
        "raw_payload": {},
        "payload_hash": "abc123",
        "prev_hash": None,
        "collected_at": now,
        "reviewed_by": None,
        "reviewed_at": None,
        "status": "pending",
        "created_at": now,
    }
    defaults.update(overrides)
    row = MagicMock()
    for k, v in defaults.items():
        setattr(row, k, v)
    return row


def _phishing_row(tenant_id: uuid.UUID, **overrides: Any) -> MagicMock:
    """Build a fake phishing submission row."""
    now = datetime.now(UTC)
    defaults = {
        "id": uuid.uuid4(),
        "tenant_id": tenant_id,
        "artifact_kind": "email",
        "sender": "attacker@evil.com",
        "subject": "Urgent: Verify your account",
        "urls": ["https://evil.com/phish"],
        "verdict": "phishing",
        "confidence": 0.9,
        "indicators": [{"kind": "url", "value": "https://evil.com/phish"}],
        "mitre_technique": "T1566.001",
        "case_id": None,
        "submitted_at": now,
        "triaged_at": now,
        "raw_content": "Click here to verify",
    }
    defaults.update(overrides)
    row = MagicMock()
    for k, v in defaults.items():
        setattr(row, k, v)
    return row


def _kb_row(tenant_id: uuid.UUID, **overrides: Any) -> MagicMock:
    """Build a fake KB document row."""
    now = datetime.now(UTC)
    defaults = {
        "id": uuid.uuid4(),
        "tenant_id": tenant_id,
        "title": "Incident Response Runbook",
        "doc_kind": "runbook",
        "source_url": None,
        "content": "Step 1: Contain the threat. " * 20,
        "tags": ["ir", "runbook"],
        "chunk_index": 0,
        "chunk_total": 1,
        "created_at": now,
        "updated_at": now,
        "created_by": "analyst@example.com",
    }
    defaults.update(overrides)
    row = MagicMock()
    for k, v in defaults.items():
        setattr(row, k, v)
    return row


# ────────────────────────────────────────────────────────────────────────────
# Compliance endpoint tests
# ────────────────────────────────────────────────────────────────────────────


class TestComplianceTenantIsolation:
    """All compliance endpoints must scope queries by tenant_id."""

    @pytest.mark.asyncio
    async def test_list_evidence_scopes_by_tenant(self) -> None:
        from app.api.v1.endpoints.compliance import list_evidence

        user = _user()
        row = _evidence_row(user.tenant_id)
        db = _mk_db([[row]])
        result = await list_evidence(db=db, user=user)
        assert len(result) == 1
        _assert_tenant_scoped(db.executed, user.tenant_id, "aisoc_compliance_evidence")

    @pytest.mark.asyncio
    async def test_get_evidence_cross_tenant_returns_404(self) -> None:
        from app.api.v1.endpoints.compliance import get_evidence
        from fastapi import HTTPException

        user = _user()
        db = _mk_db([None])  # No row found for this tenant
        with pytest.raises(HTTPException) as exc:
            await get_evidence(evidence_id=uuid.uuid4(), db=db, user=user)
        assert exc.value.status_code == 404
        _assert_tenant_scoped(db.executed, user.tenant_id, "aisoc_compliance_evidence")

    @pytest.mark.asyncio
    async def test_collect_evidence_binds_the_callers_tenant(self) -> None:
        """The INSERT must run, and must bind the caller's tenant_id.

        This asserted on ``inspect.getsource`` under a docstring claiming
        ``text().bindparams()`` needed a live connection to resolve a
        ``::jsonb`` cast. ``bindparams()`` never opens a connection, and the
        cast was not being resolved at all: SQLAlchemy's scanner refuses a
        parameter name followed by a colon, so ``:payload::jsonb`` declared
        ``payload`` minus its last character and ``.bindparams(payload=...)``
        raised before the route reached the ``try``. Calling the handler is
        what makes that visible.
        """
        from app.api.v1.endpoints.compliance import CollectEvidenceRequest, collect_evidence

        user = _user()
        row = _evidence_row(user.tenant_id)
        db = _mk_db([None, row])  # _latest_hash finds nothing, then the INSERT returns
        body = CollectEvidenceRequest(
            framework="SOC2", control_id="CC7.2", evidence_kind="alert", summary="Evidence summary", raw_payload={"a": 1}
        )

        result = await collect_evidence(body=body, db=db, user=user)

        assert result.id == row.id
        _assert_tenant_scoped(db.executed, user.tenant_id, "aisoc_compliance_evidence")
        params = _bound(db.executed, "insert into aisoc_compliance_evidence")
        assert params["tenant_id"] == user.tenant_id
        assert params["payload"] == '{"a": 1}', "the jsonb cast must not swallow the bound payload"

    @pytest.mark.asyncio
    async def test_review_evidence_cross_tenant_returns_404(self) -> None:
        from app.api.v1.endpoints.compliance import ReviewEvidenceRequest, review_evidence
        from fastapi import HTTPException

        user = _user()
        db = _mk_db([None])  # UPDATE returns no row
        body = ReviewEvidenceRequest(decision="accepted")
        with pytest.raises(HTTPException) as exc:
            await review_evidence(evidence_id=uuid.uuid4(), body=body, db=db, user=user)
        assert exc.value.status_code == 404
        _assert_tenant_scoped(db.executed, user.tenant_id, "aisoc_compliance_evidence")

    @pytest.mark.asyncio
    async def test_review_evidence_stamps_a_readable_reviewer(self) -> None:
        """``reviewed_by`` is the sign-off field on a compliance record.

        The handler falls back to the caller when the body names no reviewer,
        and that fallback was ``str(user)`` — so the requests that did not
        name a reviewer are exactly the ones whose sign-off became an object
        address.
        """
        from app.api.v1.endpoints.compliance import ReviewEvidenceRequest, review_evidence

        user = _user()
        db = _mk_db([_evidence_row(user.tenant_id)])
        await review_evidence(evidence_id=uuid.uuid4(), body=ReviewEvidenceRequest(decision="accepted"), db=db, user=user)

        params = _bound(db.executed, "update aisoc_compliance_evidence")
        assert params["reviewer"] == "analyst@example.com", f"reviewed_by must name the reviewer, got {params['reviewer']!r}"
        assert "object at 0x" not in params["reviewer"]

    @pytest.mark.asyncio
    async def test_compliance_report_scopes_by_tenant(self) -> None:
        from app.api.v1.endpoints.compliance import compliance_report

        user = _user()
        db = _mk_db([[]])  # Empty result set
        result = await compliance_report(db=db, user=user, framework=None)
        # Should still return framework entries from FRAMEWORKS dict
        assert isinstance(result, list)
        _assert_tenant_scoped(db.executed, user.tenant_id, "aisoc_compliance_evidence")


# ────────────────────────────────────────────────────────────────────────────
# Phishing endpoint tests
# ────────────────────────────────────────────────────────────────────────────


class TestPhishingTenantIsolation:
    """All phishing endpoints must scope queries by tenant_id."""

    @pytest.mark.asyncio
    async def test_list_submissions_scopes_by_tenant(self) -> None:
        from app.api.v1.endpoints.phishing import list_submissions

        user = _user()
        row = _phishing_row(user.tenant_id)
        db = _mk_db([[row]])
        result = await list_submissions(db=db, user=user)
        assert len(result) == 1
        _assert_tenant_scoped(db.executed, user.tenant_id, "aisoc_phishing_submissions")

    @pytest.mark.asyncio
    async def test_get_submission_cross_tenant_returns_404(self) -> None:
        from app.api.v1.endpoints.phishing import get_submission
        from fastapi import HTTPException

        user = _user()
        db = _mk_db([None])
        with pytest.raises(HTTPException) as exc:
            await get_submission(submission_id=uuid.uuid4(), db=db, user=user)
        assert exc.value.status_code == 404
        _assert_tenant_scoped(db.executed, user.tenant_id, "aisoc_phishing_submissions")

    @pytest.mark.asyncio
    async def test_submit_binds_the_callers_tenant_and_a_readable_actor(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """The INSERT must run, bind the caller's tenant, and name a real actor.

        Was an ``inspect.getsource`` substring check. Two defects hid behind
        it: ``:urls::text[]`` and ``:iocs::jsonb`` each declared a truncated
        parameter, so ``.bindparams()`` raised on every call; and
        ``submitted_by`` was stamped with ``str(user)``, which on the real
        principal is an object address.
        """
        from app.api.v1.endpoints import phishing as phishing_mod
        from app.api.v1.endpoints.phishing import SubmitRequest, submit

        monkeypatch.setattr(phishing_mod, "_triage", AsyncMock(return_value=None))
        user = _user()
        row = _phishing_row(user.tenant_id)
        db = _mk_db([row])
        body = SubmitRequest(artifact_kind="email", raw_content="Click here to verify", urls=["https://evil.com/phish"])

        result = await submit(body=body, db=db, user=user)

        assert result.id == row.id
        _assert_tenant_scoped(db.executed, user.tenant_id, "aisoc_phishing_submissions")
        params = _bound(db.executed, "insert into aisoc_phishing_submissions")
        assert params["tenant_id"] == user.tenant_id
        assert params["urls"] == ["https://evil.com/phish"], "the text[] cast must not swallow the bound urls"
        assert json.loads(params["iocs"]), "the jsonb cast must not swallow the bound indicators"
        assert params["by"] == "analyst@example.com", f"submitted_by must name the analyst, got {params['by']!r}"
        assert "object at 0x" not in params["by"]

    @pytest.mark.asyncio
    async def test_retriage_cross_tenant_returns_404(self) -> None:
        from app.api.v1.endpoints.phishing import retriage
        from fastapi import HTTPException

        user = _user()
        db = _mk_db([None])
        with pytest.raises(HTTPException) as exc:
            await retriage(submission_id=uuid.uuid4(), db=db, user=user)
        assert exc.value.status_code == 404
        _assert_tenant_scoped(db.executed, user.tenant_id, "aisoc_phishing_submissions")

    @pytest.mark.asyncio
    async def test_retriage_reaches_the_update(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """The UPDATE must run. Only the 404 branch was covered.

        ``test_retriage_cross_tenant_returns_404`` hands the handler an empty
        SELECT, so it returns before the UPDATE. That left the UPDATE's
        ``indicators = :iocs::jsonb`` unexercised, and it raised on every
        request that got past the SELECT.
        """
        from app.api.v1.endpoints import phishing as phishing_mod
        from app.api.v1.endpoints.phishing import retriage

        monkeypatch.setattr(phishing_mod, "_triage", AsyncMock(return_value=None))
        user = _user()
        existing = _phishing_row(user.tenant_id)
        db = _mk_db([existing, _phishing_row(user.tenant_id)])

        result = await retriage(submission_id=existing.id, db=db, user=user)

        assert result.verdict
        params = _bound(db.executed, "update aisoc_phishing_submissions")
        assert params["tenant_id"] == user.tenant_id
        assert json.loads(params["iocs"]) is not None, "the jsonb cast must not swallow the bound indicators"


# ────────────────────────────────────────────────────────────────────────────
# Knowledge Base endpoint tests
# ────────────────────────────────────────────────────────────────────────────


class TestKnowledgeBaseTenantIsolation:
    """All KB endpoints must scope queries by tenant_id."""

    @pytest.mark.asyncio
    async def test_list_documents_scopes_by_tenant(self) -> None:
        from app.api.v1.endpoints.knowledge_base import list_documents

        user = _user()
        row = _kb_row(user.tenant_id)
        db = _mk_db([[row]])
        result = await list_documents(db=db, user=user)
        assert len(result) == 1
        _assert_tenant_scoped(db.executed, user.tenant_id, "aisoc_kb_documents")

    @pytest.mark.asyncio
    async def test_get_document_cross_tenant_returns_404(self) -> None:
        from app.api.v1.endpoints.knowledge_base import get_document
        from fastapi import HTTPException

        user = _user()
        db = _mk_db([None])
        with pytest.raises(HTTPException) as exc:
            await get_document(doc_id=uuid.uuid4(), db=db, user=user)
        assert exc.value.status_code == 404
        _assert_tenant_scoped(db.executed, user.tenant_id, "aisoc_kb_documents")

    @pytest.mark.asyncio
    async def test_delete_document_cross_tenant_returns_404(self) -> None:
        from app.api.v1.endpoints.knowledge_base import delete_document
        from fastapi import HTTPException

        user = _user()
        db = _mk_db([None])
        with pytest.raises(HTTPException) as exc:
            await delete_document(doc_id=uuid.uuid4(), db=db, user=user)
        assert exc.value.status_code == 404
        _assert_tenant_scoped(db.executed, user.tenant_id, "aisoc_kb_documents")

    @pytest.mark.asyncio
    async def test_delete_document_scopes_delete_by_tenant(self) -> None:
        """DELETE must use WHERE title = :title AND tenant_id = :tenant_id
        to avoid destroying other tenants' documents with the same title."""
        from app.api.v1.endpoints.knowledge_base import delete_document

        user = _user()
        existing = MagicMock()
        existing.title = "Shared Runbook Title"
        db = _mk_db([existing, None])  # SELECT returns row, DELETE returns nothing
        await delete_document(doc_id=uuid.uuid4(), db=db, user=user)

        # The DELETE statement must be tenant-scoped
        delete_stmts = [(sql, params) for sql, params in db.executed if "delete" in re.sub(r"\s+", " ", sql).lower()]
        assert delete_stmts, "expected a DELETE statement"
        for sql, _params in delete_stmts:
            normalized = re.sub(r"\s+", " ", sql).lower()
            assert "tenant_id" in normalized, f"DELETE against aisoc_kb_documents missing tenant_id: {sql}"

    @pytest.mark.asyncio
    async def test_ingest_binds_the_callers_tenant_and_a_readable_actor(self) -> None:
        """The INSERT must run, bind the caller's tenant, and name a real actor.

        Was an ``inspect.getsource`` substring check, which hid the same two
        defects as ``phishing.submit``: ``:tags::text[]`` declared ``tag`` and
        ``.bindparams(tags=...)`` raised, and ``created_by`` was stamped with
        ``str(user)``. ``created_by`` is returned by the API, so the object
        address was rendered back to the operator.
        """
        from app.api.v1.endpoints.knowledge_base import IngestRequest, ingest

        user = _user()
        row = _kb_row(user.tenant_id)
        db = _mk_db([row])
        body = IngestRequest(title="Incident Response Runbook", doc_kind="runbook", content="Step 1: contain.", tags=["ir", "runbook"])

        result = await ingest(body=body, db=db, user=user)

        assert result and result[0].id == row.id
        _assert_tenant_scoped(db.executed, user.tenant_id, "aisoc_kb_documents")
        params = _bound(db.executed, "insert into aisoc_kb_documents")
        assert params["tenant_id"] == user.tenant_id
        assert params["tags"] == ["ir", "runbook"], "the text[] cast must not swallow the bound tags"
        assert params["user"] == "analyst@example.com", f"created_by must name the analyst, got {params['user']!r}"
        assert "object at 0x" not in params["user"]
