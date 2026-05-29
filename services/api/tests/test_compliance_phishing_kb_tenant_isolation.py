"""Tenant-isolation tests for /compliance, /phishing, and /kb endpoints.

These tests verify that every SQL statement in the compliance, phishing,
and knowledge-base endpoints filters on ``tenant_id`` — preventing
cross-tenant data leakage.

Follows the same mock-session pattern used by
``test_alerts_tenant_isolation.py`` and
``test_threat_intel_tenant_isolation.py``.
"""

from __future__ import annotations

import re
import uuid
from datetime import UTC, datetime
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

# ────────────────────────────────────────────────────────────────────────────
# Helpers
# ────────────────────────────────────────────────────────────────────────────


def _user(tenant_id: uuid.UUID | None = None) -> MagicMock:
    """Construct an AuthUser-like object without touching DB or JWT."""
    u = MagicMock()
    u.tenant_id = tenant_id or uuid.uuid4()
    u.user_id = uuid.uuid4()
    u.email = "analyst@example.com"
    u.__str__ = lambda self: self.email
    return u


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

    def test_collect_evidence_sql_includes_tenant_id(self) -> None:
        """The INSERT statement in collect_evidence must include tenant_id.

        We inspect the source rather than calling the function because
        SQLAlchemy's ``text().bindparams()`` cannot resolve PostgreSQL
        cast syntax (``::jsonb``) without a live DB connection.
        """
        import inspect

        from app.api.v1.endpoints.compliance import collect_evidence

        src = inspect.getsource(collect_evidence)
        # The INSERT column list and VALUES list must both mention tenant_id.
        assert "tenant_id" in src, "collect_evidence INSERT must include tenant_id"
        assert "user.tenant_id" in src, "collect_evidence must bind user.tenant_id"

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

    def test_submit_sql_includes_tenant_id(self) -> None:
        """The INSERT statement in submit must include tenant_id.

        SQLAlchemy's ``text().bindparams()`` cannot resolve PostgreSQL
        array cast syntax (``::text[]``) without a live DB connection,
        so we inspect the source instead.
        """
        import inspect

        from app.api.v1.endpoints.phishing import submit

        src = inspect.getsource(submit)
        assert "tenant_id" in src, "submit INSERT must include tenant_id"
        assert "user.tenant_id" in src, "submit must bind user.tenant_id"

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

    def test_ingest_sql_includes_tenant_id(self) -> None:
        """The INSERT statement in ingest must include tenant_id.

        SQLAlchemy's ``text().bindparams()`` cannot resolve PostgreSQL
        array cast syntax (``::text[]``) without a live DB connection,
        so we inspect the source instead.
        """
        import inspect

        from app.api.v1.endpoints.knowledge_base import ingest

        src = inspect.getsource(ingest)
        assert "tenant_id" in src, "ingest INSERT must include tenant_id"
        assert "user.tenant_id" in src, "ingest must bind user.tenant_id"
