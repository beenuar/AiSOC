"""Contract regressions for case comments and the resolution field (#1932).

Two console-breaking contract gaps, both invisible from the server's own
suite because every existing test spoke the server's dialect:

* ``casesApi.addComment`` sent ``{"comment": ...}`` while
  :class:`AddCommentRequest` read only ``body`` — every post 422'd, and the
  workspace's optimistic insert plus a demo-copy toast made the failure look
  like a save. The model now accepts both names; these tests pin the alias
  (and that the alias does not relax the non-empty validation).

* The console has always rendered a Resolution panel and typed
  ``Case.resolution``, and the column has existed since migration 046, but
  ``UpdateCaseRequest`` had no field and ``CaseResponse`` never returned one
  — there was no persistence path at all. These tests pin the PATCH write
  and the response read.

Harness style mirrors ``test_cases_tenant_isolation.py``: endpoint functions
called directly with a mocked ``DBSession``.
"""

from __future__ import annotations

import re
import uuid
from datetime import UTC, datetime
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest
from app.api.v1.deps import CurrentUser
from app.api.v1.endpoints.cases import (
    AddCommentRequest,
    UpdateCaseRequest,
    _row_to_case,
    update_case,
)
from pydantic import ValidationError

# ────────────────────────────────────────────────────────────────────────────
# Fixtures / helpers (local copies — see test_cases_tenant_isolation.py for
# why the row double is spec'd to an explicit column list)
# ────────────────────────────────────────────────────────────────────────────


def _user() -> CurrentUser:
    return CurrentUser(
        user_id=uuid.uuid4(),
        tenant_id=uuid.uuid4(),
        role="analyst",
        email="analyst@example.com",
    )


def _case_row(**overrides: Any) -> MagicMock:
    now = datetime.now(UTC)
    defaults = {
        "id": uuid.uuid4(),
        "case_number": "INC-001",
        "title": "Phish wave",
        "description": "Phishing detected",
        "severity": "high",
        "status": "new",
        "assignee": "analyst@example.com",
        "mitre_techniques": [],
        "alert_ids": [],
        "observable_graph": {},
        "evidence_chain": [],
        "compliance_frameworks": [],
        "opened_at": now,
        "triaged_at": None,
        "resolved_at": None,
        "closed_at": None,
        "reopened_at": None,
        "reopen_count": 0,
        "reopen_reason": None,
        "created_at": now,
        "updated_at": now,
        "created_by": "analyst@example.com",
        "tags": {},
        "sla_due_at": None,
        "resolution": None,
    }
    defaults.update(overrides)
    row = MagicMock(spec=list(defaults))
    for k, v in defaults.items():
        setattr(row, k, v)
    return row


def _mk_db(rows: list[Any]) -> MagicMock:
    db = MagicMock()
    # Annotate the list, then attach it: annotating `db.executed` directly is
    # a mypy `misc` error (declaration on a non-self attribute).
    executed: list[tuple[str, dict[str, Any]]] = []
    db.executed = executed
    iterator = iter(rows)

    async def _execute(clause: Any, *args: Any, **kwargs: Any) -> MagicMock:
        sql = str(clause)
        try:
            params = dict(clause.compile().params) if hasattr(clause, "compile") else {}
        except Exception:  # pragma: no cover — defensive: never crash the mock.
            params = {}
        db.executed.append((sql, params))
        try:
            payload = next(iterator)
        except StopIteration:
            payload = None
        result = MagicMock()
        result.fetchone = MagicMock(return_value=payload)
        result.fetchall = MagicMock(return_value=[payload] if payload else [])
        return result

    db.execute = AsyncMock(side_effect=_execute)
    db.commit = AsyncMock()
    db.rollback = AsyncMock()
    return db


# ────────────────────────────────────────────────────────────────────────────
# AddCommentRequest — both wire names must parse; validation must not relax
# ────────────────────────────────────────────────────────────────────────────


def test_add_comment_request_accepts_comment_alias() -> None:
    """The console's historical payload key must parse (the #1932 422)."""
    parsed = AddCommentRequest.model_validate({"comment": "lateral movement confirmed"})
    assert parsed.body == "lateral movement confirmed"


def test_add_comment_request_accepts_canonical_body() -> None:
    parsed = AddCommentRequest.model_validate({"body": "contained at 14:02"})
    assert parsed.body == "contained at 14:02"


def test_add_comment_request_alias_keeps_min_length() -> None:
    """The alias must not become a bypass of the non-empty rule."""
    with pytest.raises(ValidationError):
        AddCommentRequest.model_validate({"comment": ""})
    with pytest.raises(ValidationError):
        AddCommentRequest.model_validate({"body": ""})


def test_add_comment_request_still_requires_text() -> None:
    with pytest.raises(ValidationError):
        AddCommentRequest.model_validate({})


# ────────────────────────────────────────────────────────────────────────────
# Resolution — PATCH persists it, responses carry it
# ────────────────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_update_case_persists_resolution() -> None:
    user = _user()
    cid = uuid.uuid4()
    existing = MagicMock()
    existing.status = "new"
    text = "Root cause: leaked PAT. Remediation: token rotated, scope reduced."
    db = _mk_db([existing, _case_row(id=cid, resolution=text)])

    response = await update_case(
        case_id=str(cid),
        body=UpdateCaseRequest(resolution=text),
        db=db,
        user=user,
    )

    assert len(db.executed) >= 2
    upd_sql, upd_params = db.executed[1]
    normalized = re.sub(r"\s+", " ", upd_sql).lower()
    assert "update aisoc_cases" in normalized
    assert "resolution = :resolution" in normalized
    assert upd_params["resolution"] == text
    assert upd_params["tenant_id"] == user.tenant_id
    assert response.resolution == text


@pytest.mark.asyncio
async def test_update_case_empty_resolution_clears_field() -> None:
    """An empty string is a deliberate clear, not an omitted field."""
    user = _user()
    cid = uuid.uuid4()
    existing = MagicMock()
    existing.status = "new"
    db = _mk_db([existing, _case_row(id=cid, resolution="")])

    await update_case(
        case_id=str(cid),
        body=UpdateCaseRequest(resolution=""),
        db=db,
        user=user,
    )

    upd_sql, upd_params = db.executed[1]
    assert "resolution = :resolution" in re.sub(r"\s+", " ", upd_sql).lower()
    assert upd_params["resolution"] == ""


@pytest.mark.asyncio
async def test_update_case_omitted_resolution_leaves_column_alone() -> None:
    """A PATCH that does not name the field must not touch the column."""
    user = _user()
    cid = uuid.uuid4()
    existing = MagicMock()
    existing.status = "new"
    db = _mk_db([existing, _case_row(id=cid, title="renamed")])

    await update_case(
        case_id=str(cid),
        body=UpdateCaseRequest(title="renamed"),
        db=db,
        user=user,
    )

    upd_sql, _ = db.executed[1]
    assert "resolution" not in re.sub(r"\s+", " ", upd_sql).lower()


def test_row_to_case_carries_resolution() -> None:
    row = _case_row(resolution="rotated the credential")
    assert _row_to_case(row).resolution == "rotated the credential"


def test_row_to_case_tolerates_rows_without_resolution_column() -> None:
    """Mappers are also handed rows from explicit column lists that predate
    the column; those must read as None, not raise."""
    row = _case_row()
    del row.resolution
    assert _row_to_case(row).resolution is None
