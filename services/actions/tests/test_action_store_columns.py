"""What `aisoc_action_records` columns actually receive.

The record is stored whole as JSONB, and three columns are lifted out of it
so the table can be queried: `tenant_id`, `status` and now `approval_tier`.
Both of the first two were wrong in a way the JSONB copy hid.

`status` held `'ActionStatus.COMPLETED'`. `ActionStatus` is a
`class ActionStatus(str, Enum)`, and `Enum` keeps its own `__str__` for a
mixin like that, so `str(member)` is the qualified name rather than the
value. `json.dumps` does not go through `__str__` for a `str` subclass, so
the JSONB said `"completed"` while the column beside it said something no
query would ever ask for. The index on `(tenant_id, status)` indexed that
string, and `services/api`'s usage meter counting executed actions could
only ever return zero.

`approval_tier` did not exist. The grading ran on every submission and the
answer was logged and dropped, so a completed row could not say afterwards
whether a human had approved it.

These tests drive the real `save()` against a connection double that
records its arguments. They do not prove Postgres accepts the statement —
`tests/isolation/test_live_actions_live.py` is where that happens — they
prove the values handed to it are the ones a query can find.
"""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import pytest
from app.models.action import ActionStatus, BlastRadius
from app.services import action_store

# The positional parameters `save()` binds, in order.
_ID, _TENANT, _STATUS, _TIER, _RECORD = range(5)


class _RecordingConnection:
    """Captures the arguments `save()` binds, and nothing else."""

    def __init__(self) -> None:
        self.args: tuple[Any, ...] = ()
        self.sql = ""

    async def execute(self, sql: str, *args: Any) -> None:
        self.sql = sql
        self.args = args

    async def close(self) -> None:
        return None


@pytest.fixture
def captured(monkeypatch: pytest.MonkeyPatch) -> _RecordingConnection:
    connection = _RecordingConnection()
    monkeypatch.setenv("DATABASE_DSN", "postgresql://aisoc@localhost:5432/aisoc")
    monkeypatch.setattr(action_store, "_connect", lambda _dsn: _async(connection))
    action_store.clear()
    return connection


async def _async(value: Any) -> Any:
    return value


def _record(**overrides: Any) -> dict[str, Any]:
    base = {
        "id": str(uuid4()),
        "tenant_id": str(uuid4()),
        "status": ActionStatus.COMPLETED,
        "blast_radius": BlastRadius.LOW,
        "approval_tier": "automatic",
    }
    base.update(overrides)
    return base


class TestTheStatusColumnHoldsAValueAQueryCanMatch:
    @pytest.mark.asyncio
    async def test_an_enum_member_is_written_as_its_value(self, captured):
        await action_store.save(_record(status=ActionStatus.COMPLETED))
        assert captured.args[_STATUS] == "completed"

    @pytest.mark.asyncio
    async def test_the_qualified_enum_name_never_reaches_the_column(self, captured):
        """The negative control for the defect itself.

        `str(ActionStatus.COMPLETED)` still returns the qualified name — the
        language behaviour has not changed, only what this module does with
        it — so this assertion fails the moment the conversion is dropped.
        """
        assert str(ActionStatus.COMPLETED) == "ActionStatus.COMPLETED", (
            "Enum.__str__ no longer qualifies a str-mixin member; re-read whether _column_text is still needed"
        )
        await action_store.save(_record(status=ActionStatus.COMPLETED))
        assert "ActionStatus." not in captured.args[_STATUS]

    @pytest.mark.asyncio
    async def test_a_plain_string_status_is_unchanged(self, captured):
        """The approve path rewrites `status` from an executor result, and
        not every executor returns the enum."""
        await action_store.save(_record(status="awaiting_approval"))
        assert captured.args[_STATUS] == "awaiting_approval"


class TestTheApprovalTierIsPersisted:
    @pytest.mark.asyncio
    async def test_the_graded_tier_reaches_its_own_column(self, captured):
        await action_store.save(_record(approval_tier="analyst"))
        assert captured.args[_TIER] == "analyst"

    @pytest.mark.asyncio
    async def test_an_ungraded_record_writes_null_rather_than_an_empty_string(self, captured):
        """NULL is the value the meter counts as "nobody graded this".

        An empty string would be a fourth state meaning the same thing, and
        the meter's `IS NULL OR = ''` would then be load-bearing instead of
        defensive.
        """
        record = _record()
        record.pop("approval_tier")
        await action_store.save(record)
        assert captured.args[_TIER] is None

    @pytest.mark.asyncio
    async def test_the_statement_names_the_column_on_both_insert_and_update(self, captured):
        """An upsert that sets it only on insert leaves the first grading
        frozen on a row that is saved again after execution."""
        await action_store.save(_record())
        assert captured.sql.count("approval_tier") >= 2, captured.sql
