"""`GET /cases?status=open` must honour the alias the write path honours.

What happened (found live, v23.5.0)
-----------------------------------
`"open"` is not a stored case status — the `aisoc_cases` CHECK vocabulary is
new/triaged/investigating/contained/resolved/closed — but `UpdateCaseRequest`
has always *accepted* `"open"` as a legacy alias, and the console's
"Add to existing case" picker queries `GET /cases?status=open`. The list
endpoint string-matched the filter, so the alias matched zero rows on every
deployment: the picker always said "No open cases yet", the add-to-case flow
was unreachable, and with it the shared-alert path into related-cases.

What is asserted
----------------
* `status=open` expands to exactly `case_status.OPEN_STATUSES` (the one
  product-wide definition of openness), each value bound as a parameter.
* A concrete status (e.g. `closed`) still matches as an exact string.
* The tenant anchor survives the expansion.
"""

from __future__ import annotations

import uuid
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest
from app.api.v1.endpoints.cases import list_cases
from app.services import case_status


def _user() -> MagicMock:
    user = MagicMock()
    user.tenant_id = uuid.uuid4()
    user.user_id = uuid.uuid4()
    return user


def _db(captured: list[tuple[str, dict[str, Any]]]) -> AsyncMock:
    db = AsyncMock()

    async def execute(stmt: Any, *args: Any, **kwargs: Any) -> MagicMock:
        params: dict[str, Any] = {}
        compiled = getattr(stmt, "compile", None)
        if compiled is not None:
            params = dict(stmt.compile().params)
        captured.append((str(stmt), params))
        result = MagicMock()
        result.fetchall.return_value = []
        return result

    db.execute = execute
    return db


@pytest.mark.asyncio
async def test_open_alias_expands_to_open_statuses() -> None:
    captured: list[tuple[str, dict[str, Any]]] = []
    await list_cases(
        db=_db(captured),
        user=_user(),
        status_filter="open",
        severity=None,
        assignee=None,
        limit=50,
        offset=0,
    )
    assert captured, "no SQL executed"
    sql, params = captured[0]
    assert "status IN (" in sql, f"alias not expanded: {sql}"
    bound = {v for k, v in params.items() if k.startswith("status_")}
    assert bound == set(case_status.OPEN_STATUSES), (
        f"the alias must expand to case_status.OPEN_STATUSES — one definition of open, everywhere; got {bound!r}"
    )
    assert "tenant_id = :tenant_id" in sql


@pytest.mark.asyncio
async def test_concrete_status_still_exact_matches() -> None:
    captured: list[tuple[str, dict[str, Any]]] = []
    await list_cases(
        db=_db(captured),
        user=_user(),
        status_filter="closed",
        severity=None,
        assignee=None,
        limit=50,
        offset=0,
    )
    sql, params = captured[0]
    assert "status = :status" in sql
    assert params.get("status") == "closed"
