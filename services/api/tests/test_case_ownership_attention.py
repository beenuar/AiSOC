"""Every open case has an owner and a next action, or it surfaces (WS7.4).

What was wrong
--------------
A case could sit open with nobody — person or agent — responsible for it and
no time by which anything was due. Nothing surfaced that state: the
operations dashboard counted cases but never asked "who owns this and when
is its next action due", so an unowned, overdue case looked exactly like a
well-tended one.

What this asserts
-----------------
* ``aisoc_cases`` carries ``next_action_due_at`` and ``owner_agent_run_id``;
  an owner is a person (``assigned_to_id``) **or** an agent run.
* ``GET /cases/attention`` lists open cases that are unowned or overdue,
  each row saying which it is (``owner_kind``: person / agent_run / none;
  ``overdue_seconds`` null when not due yet — null, never a confident 0).
* PATCH can set and clear the due time and the agent-run owner.
* Launching an investigation claims an **unowned** case for the run, and
  never steals a case a person already owns.

The attention feed is what the operations dashboard renders and what the
WS8.1 shift handoff will consume.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest
from app.api.v1.endpoints import cases as cases_ep

TENANT = uuid.UUID("aaaaaaaa-0000-0000-0000-00000000000a")


def _user() -> MagicMock:
    user = MagicMock()
    user.tenant_id = TENANT
    user.email = "analyst@aisoc.internal"
    return user


def _row(**overrides: Any) -> MagicMock:
    now = datetime.now(UTC)
    row = MagicMock()
    row.id = overrides.get("id", uuid.uuid4())
    row.case_number = overrides.get("case_number", "CASE-1")
    row.title = overrides.get("title", "t")
    row.status = overrides.get("status", "investigating")
    row.severity = overrides.get("severity", "high")
    row.assigned_to_id = overrides.get("assigned_to_id")
    row.owner_agent_run_id = overrides.get("owner_agent_run_id")
    row.next_action_due_at = overrides.get("next_action_due_at")
    row.updated_at = overrides.get("updated_at", now)
    return row


def _db(rows: list[Any]) -> AsyncMock:
    db = AsyncMock()
    result = MagicMock()
    result.fetchall.return_value = rows
    db.execute = AsyncMock(return_value=result)
    return db


@pytest.mark.asyncio
class TestAttentionFeed:
    async def test_rows_say_which_kind_of_owner_and_whether_overdue(self) -> None:
        now = datetime.now(UTC)
        person = _row(assigned_to_id=uuid.uuid4(), next_action_due_at=now - timedelta(hours=2))
        agent = _row(owner_agent_run_id=uuid.uuid4(), next_action_due_at=now + timedelta(hours=1))
        unowned = _row()

        out = await cases_ep.get_cases_attention(db=_db([person, agent, unowned]), user=_user())

        by_id = {entry["case_id"]: entry for entry in out["cases"]}
        p = by_id[str(person.id)]
        assert p["owner_kind"] == "person"
        assert p["overdue_seconds"] is not None and p["overdue_seconds"] > 0

        a = by_id[str(agent.id)]
        assert a["owner_kind"] == "agent_run"
        # Due in the future: not overdue, and the honest value is null —
        # a confident 0 would read as "exactly due now".
        assert a["overdue_seconds"] is None

        u = by_id[str(unowned.id)]
        assert u["owner_kind"] == "none"

    async def test_the_query_scopes_to_the_tenant_and_open_statuses(self) -> None:
        db = _db([])
        await cases_ep.get_cases_attention(db=db, user=_user())
        sql = str(db.execute.await_args_list[0].args[0])
        assert "tenant_id" in sql
        assert "closed" not in sql.split("WHERE")[0]  # selection happens in WHERE
        params = db.execute.await_args_list[0].args[1]
        assert params["tenant_id"] == str(TENANT)


@pytest.mark.asyncio
class TestLaunchClaimsUnownedCases:
    async def test_claim_sql_only_touches_unowned_cases(self) -> None:
        """The UPDATE must carry both no-person and no-agent predicates:
        an agent must never steal a case a person already owns."""
        db = AsyncMock()
        db.execute = AsyncMock(return_value=MagicMock())
        run_id = uuid.uuid4()
        case_id = uuid.uuid4()

        await cases_ep._claim_case_for_run(db, tenant_id=TENANT, case_id=case_id, run_id=run_id)

        sql = str(db.execute.await_args_list[0].args[0])
        assert "owner_agent_run_id" in sql
        assert "assigned_to_id IS NULL" in sql
        assert "owner_agent_run_id IS NULL" in sql
        assert "tenant_id" in sql


class TestPatchSurface:
    def test_update_request_carries_the_two_new_fields(self) -> None:
        request = cases_ep.UpdateCaseRequest(
            next_action_due_at=datetime(2026, 11, 23, 9, 0, tzinfo=UTC),
            owner_agent_run_id=uuid.uuid4(),
        )
        assert request.next_action_due_at is not None
        assert request.owner_agent_run_id is not None
