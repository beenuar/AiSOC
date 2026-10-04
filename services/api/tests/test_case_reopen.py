"""Reopening a closed case works, and `PATCH` still cannot do it.

Why there is a route at all
---------------------------
`case_status.TRANSITIONS[CLOSED]` is an empty set, so the state machine has no
backward move and `PATCH /cases/{id}` refuses every transition out of
`closed`. That is the right default -- a forward-only machine is what makes
"this case was closed" mean something.

But "closed in error" and "it came back" are real, and the only way to record
either was to open a second case, which discards the history that made the
first one worth keeping. So reopening is its own deliberate act with its own
column, rather than a hole punched in the transition table.

Why this runs against live Postgres
-----------------------------------
A previous attempt wrote `reopened_at` from the route without ever creating
the column, so **every call raised `UndefinedColumnError`** -- the route was
merged, read as complete, and had never once succeeded. A mocked session
answers any UPDATE, so only a real database can tell the difference between
"this works" and "this names a column that does not exist".

Skips when no database answers so a local run stays green, but cannot skip
where it is meant to run: `integration.yml` sets `MSSP_ISOLATION_REQUIRED=1`
and an unreachable database is then a failure.
"""

from __future__ import annotations

import os
import uuid

import pytest
import pytest_asyncio
from sqlalchemy import text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

DSN = os.environ.get("DATABASE_URL", "")
REQUIRED = os.environ.get("MSSP_ISOLATION_REQUIRED", "").strip() not in ("", "0", "false")

TENANT = uuid.UUID("0e100000-0000-0000-0000-00000000000a")


@pytest_asyncio.fixture
async def db():
    if "postgres" not in DSN and not REQUIRED:
        pytest.skip("needs a live Postgres with the migration chain applied (integration.yml)")
    engine = create_async_engine(DSN)
    try:
        async with engine.connect() as probe:
            await probe.execute(text("SELECT 1"))
    except Exception as exc:
        await engine.dispose()
        if REQUIRED:
            pytest.fail(
                "MSSP_ISOLATION_REQUIRED is set but no database answered at DATABASE_URL — "
                f"the reopen proof did not run: {type(exc).__name__}: {exc}"
            )
        pytest.skip(f"no database at DATABASE_URL ({type(exc).__name__}) — runs in integration.yml")

    factory = async_sessionmaker(engine, expire_on_commit=False)
    async with factory() as session:
        await _reset(session)
        try:
            yield session
        finally:
            await _reset(session)
    await engine.dispose()


async def _reset(session) -> None:
    """Clear the cases and leave the tenant, user and audit rows in place.

    `audit_log` is append-only -- a trigger raises `audit_log rows are
    immutable (attempted DELETE)` -- which is the control working, and the
    `actor_id` foreign key then pins the user, which pins the tenant. So the
    test tenant is a fixture of the database rather than of a single run, and
    both seeds are `ON CONFLICT DO NOTHING`.
    """
    await session.rollback()
    await session.execute(text("DELETE FROM aisoc_cases WHERE tenant_id = CAST(:t AS uuid)"), {"t": str(TENANT)})
    await session.commit()


#: A real `users` row, because `audit_log.actor_id` has a foreign key to it.
#: Seeding one rather than passing a random UUID keeps the audit write on its
#: production path -- and the first draft of this file did pass a random UUID,
#: which surfaced a genuine defect: a failed audit left the session in a
#: broken transaction, so the route's own read raised and a successful reopen
#: was reported to the caller as a failure.
USER = uuid.UUID("0e100000-0000-0000-0000-0000000000aa")


async def _seed_case(session, status: str = "closed") -> uuid.UUID:
    await session.execute(
        text("INSERT INTO tenants (id, name, slug) VALUES (CAST(:t AS uuid), 'Reopen Test', 'reopen-test') ON CONFLICT (id) DO NOTHING"),
        {"t": str(TENANT)},
    )
    await session.execute(
        text(
            "INSERT INTO users (id, tenant_id, username, email, hashed_password, role) "
            "VALUES (CAST(:u AS uuid), CAST(:t AS uuid), 'reopen-analyst', 'analyst@example.test', 'x', 'soc_lead') "
            "ON CONFLICT (id) DO NOTHING"
        ),
        {"u": str(USER), "t": str(TENANT)},
    )
    cid = uuid.uuid4()
    await session.execute(
        text(
            """
            INSERT INTO aisoc_cases (id, tenant_id, case_number, title, status, priority, severity,
                                     closed_at, resolved_at)
            VALUES (CAST(:i AS uuid), CAST(:t AS uuid), :num, 'A case that came back', :st,
                    'medium', 'medium', NOW(), NOW())
            """
        ),
        {"i": str(cid), "t": str(TENANT), "num": f"CASE-{cid.hex[:8]}", "st": status},
    )
    await session.commit()
    return cid


@pytest.mark.asyncio
class TestTheColumnsExist:
    """The reproduction. The handed-over version wrote these without creating
    them, so every call raised `UndefinedColumnError`."""

    async def test_the_migration_added_all_three(self, db) -> None:
        rows = (
            await db.execute(
                text("SELECT column_name FROM information_schema.columns WHERE table_name = 'aisoc_cases' AND column_name LIKE 'reopen%'")
            )
        ).fetchall()

        assert {r[0] for r in rows} == {"reopened_at", "reopen_count", "reopen_reason"}

    async def test_reopen_count_defaults_to_zero_not_null(self, db) -> None:
        """Unlike the timestamp, "no reopen recorded" genuinely is zero. A
        NULL here would render as blank and read as missing data."""
        cid = await _seed_case(db)

        row = (
            await db.execute(text("SELECT reopen_count, reopened_at FROM aisoc_cases WHERE id = CAST(:i AS uuid)"), {"i": str(cid)})
        ).fetchone()

        assert row.reopen_count == 0
        assert row.reopened_at is None


@pytest.mark.asyncio
class TestReopeningWorksEndToEnd:
    async def test_a_closed_case_comes_back(self, db) -> None:
        from app.api.v1.endpoints.cases import ReopenCaseRequest, reopen_case

        cid = await _seed_case(db, status="closed")
        user = _principal()

        result = await reopen_case(
            str(cid),
            ReopenCaseRequest(reason="The indicator reappeared on two more hosts overnight."),
            db,
            user,
        )

        assert result.status == "investigating"
        assert result.reopened_at is not None
        assert result.reopen_count == 1
        assert "reappeared" in (result.reopen_reason or "")

    async def test_closure_timestamps_are_cleared(self, db) -> None:
        """A case cannot be terminal and active at once, and every closure
        metric reads these columns -- leaving them set would keep the case in
        the MTTR average while it sits in the open queue."""
        from app.api.v1.endpoints.cases import ReopenCaseRequest, reopen_case

        cid = await _seed_case(db, status="closed")

        await reopen_case(str(cid), ReopenCaseRequest(reason="Closed in error by the overnight shift."), db, _principal())

        row = (
            await db.execute(text("SELECT closed_at, resolved_at FROM aisoc_cases WHERE id = CAST(:i AS uuid)"), {"i": str(cid)})
        ).fetchone()

        assert row.closed_at is None
        assert row.resolved_at is None

    async def test_reopening_twice_counts_twice(self, db) -> None:
        """`reopened_at` is overwritten each time, so without the counter a
        case reopened four times is indistinguishable from one reopened once."""
        from app.api.v1.endpoints.cases import ReopenCaseRequest, reopen_case

        cid = await _seed_case(db, status="closed")

        await reopen_case(str(cid), ReopenCaseRequest(reason="First reopen, indicator returned."), db, _principal())
        await db.execute(text("UPDATE aisoc_cases SET status = 'closed' WHERE id = CAST(:i AS uuid)"), {"i": str(cid)})
        await db.commit()
        result = await reopen_case(str(cid), ReopenCaseRequest(reason="Second reopen, lateral movement found."), db, _principal())

        assert result.reopen_count == 2

    async def test_resolved_is_not_reopenable_because_it_is_not_terminal(self, db) -> None:
        """`resolved` looks terminal and deliberately is not.

        `case_status` puts it in `OPEN_STATUSES` with the reasoning attached:
        a resolved case has an outcome but has not been closed out, and
        treating it as finished is what made "cases closed this week" count
        the wrong rows. It still has a forward edge to `closed`, so there is
        nothing to reopen -- and a route that accepted it here would let a
        case skip the closure step entirely.

        This test was written the other way round first and the code was
        right.
        """
        from app.api.v1.endpoints.cases import ReopenCaseRequest, reopen_case
        from app.services import case_status
        from fastapi import HTTPException

        assert case_status.RESOLVED in case_status.OPEN_STATUSES
        assert case_status.TRANSITIONS[case_status.RESOLVED] == {case_status.CLOSED}

        cid = await _seed_case(db, status="resolved")

        with pytest.raises(HTTPException) as exc:
            await reopen_case(str(cid), ReopenCaseRequest(reason="The fix did not hold past the weekend."), db, _principal())

        assert exc.value.status_code == 409


@pytest.mark.asyncio
class TestItRefusesWhatItShould:
    async def test_an_open_case_cannot_be_reopened(self, db) -> None:
        """409, not a silent no-op. Reopening something already open is a
        caller confusion worth naming."""
        from app.api.v1.endpoints.cases import ReopenCaseRequest, reopen_case
        from fastapi import HTTPException

        cid = await _seed_case(db, status="investigating")

        with pytest.raises(HTTPException) as exc:
            await reopen_case(str(cid), ReopenCaseRequest(reason="This should not be allowed."), db, _principal())

        assert exc.value.status_code == 409
        assert "not a terminal state" in str(exc.value.detail)

    async def test_another_tenants_case_is_not_found(self, db) -> None:
        from app.api.v1.endpoints.cases import ReopenCaseRequest, reopen_case
        from fastapi import HTTPException

        cid = await _seed_case(db, status="closed")
        other = _principal(tenant_id=uuid.uuid4())

        with pytest.raises(HTTPException) as exc:
            await reopen_case(str(cid), ReopenCaseRequest(reason="Cross-tenant attempt, must 404."), db, other)

        assert exc.value.status_code == 404

    def test_a_reason_is_required(self) -> None:
        """An unexplained reopen is what an auditor asks about six months
        later. No database needed, so this holds wherever the suite runs."""
        import pydantic
        from app.api.v1.endpoints.cases import ReopenCaseRequest

        with pytest.raises(pydantic.ValidationError):
            ReopenCaseRequest()  # type: ignore[call-arg]
        with pytest.raises(pydantic.ValidationError):
            ReopenCaseRequest(reason="oops")  # too short to be a reason


class TestPatchStaysForwardOnly:
    """The property the route exists to preserve. If `PATCH` could do this,
    a title edit carrying a status would walk a case backwards silently."""

    def test_the_transition_table_has_no_backward_edge(self) -> None:
        from app.services import case_status

        assert case_status.TRANSITIONS[case_status.CLOSED] == set()

    def test_reopen_is_not_implemented_by_widening_the_table(self) -> None:
        from app.services import case_status

        for terminal in case_status.TERMINAL_STATUSES:
            assert not case_status.TRANSITIONS.get(terminal), (
                f"{terminal!r} gained an outbound transition. Reopening must stay its own route, "
                "or an ordinary PATCH can undo a closure without a reason or an audit entry."
            )


def _principal(tenant_id: uuid.UUID | None = None):
    from app.api.v1.deps import CurrentUser

    return CurrentUser(
        user_id=USER,
        tenant_id=tenant_id or TENANT,
        role="soc_lead",
        email="analyst@example.test",
        resolved_permissions=frozenset({"cases:write"}),
    )
