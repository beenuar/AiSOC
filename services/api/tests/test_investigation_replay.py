"""The investigation ledger's read side: /replay, /events and /explain.

"Investigation Ledger stores every step" is a front-page claim, and the gate
the claim matrix named for it — ``api tests (audit_hash, audit immutability)``
— covers a different table. ``test_audit_hash.py`` tests the hash chain over
``audit_log``, which the API's audit middleware writes. The ledger is
``investigation_events``, written by ``services/agents/app/investigator/
ledger.py`` over raw asyncpg, and its only test covered tenant resolution
against a stub connection. No test in this directory touched ``/replay``,
``/events`` or ``/explain`` at all, and the "hermetic e2e" the row cited is a
single Playwright spec in the ``screenshots`` project, run from a monthly cron
whose job is to capture PNGs rather than from any pull request.

Why the stub declines to sort
-----------------------------

``_Session`` returns rows in the order the *emitted SQL asks for* and, when
the statement carries no ``ORDER BY``, in the order the fixture stored them —
which is deliberately not sequence order. That is not a trick to make a test
fail; it is the guarantee Postgres actually gives. A query with no ``ORDER BY``
may return rows in any order at all, and in practice the order changes with
the plan, the page layout and whether a sequential scan went parallel. So a
replay handler that loses its ``ORDER BY seq`` keeps passing every test that
asserts on a *set* of steps and starts serving an investigation whose steps
are in the wrong order — which is precisely what "stores every step" must not
be allowed to mean.

Removing ``.order_by(InvestigationEvent.seq.asc())`` from ``replay_run`` turns
this file red. The parity gate ``scripts/check_ledger_replay_contract.py``
catches the same edit structurally; both are here because the gate reads the
source and this reads what the route serves.
"""

from __future__ import annotations

import re
import uuid
from datetime import UTC, datetime
from types import SimpleNamespace
from typing import Any

import pytest
from app.api.v1.deps import CurrentUser, get_current_user
from app.api.v1.endpoints.investigations import EventOut
from app.api.v1.endpoints.investigations import router as investigations_router
from app.db.rls import get_tenant_db
from fastapi import FastAPI
from fastapi.testclient import TestClient

TENANT = uuid.UUID("aaaaaaaa-0000-0000-0000-00000000ledg".replace("ledg", "1ed9"))
RUN_ID = uuid.UUID("bbbbbbbb-0000-0000-0000-000000000001")

#: The sequence numbers the fixture holds, and the order it holds them in.
#: Scrambled on purpose — see the module docstring. If this were already
#: sorted, a handler that dropped its ORDER BY would still look correct.
STORED_ORDER = (3, 1, 5, 2, 4)


# ---------------------------------------------------------------------------
# Rows
# ---------------------------------------------------------------------------


def _event(seq: int) -> SimpleNamespace:
    """One ``investigation_events`` row, as the ORM would hand it over."""
    return SimpleNamespace(
        id=uuid.UUID(int=seq),
        run_id=RUN_ID,
        seq=seq,
        ts=datetime(2026, 5, 1, 12, 0, seq, tzinfo=UTC),
        kind="llm_response",
        agent="aisoc-investigation",
        summary=f"step {seq}",
        payload={"step": seq},
        input_hash=f"in-{seq}",
        output_hash=f"out-{seq}",
        duration_ms=seq * 100,
    )


def _run() -> SimpleNamespace:
    return SimpleNamespace(
        id=RUN_ID,
        tenant_id=TENANT,
        case_id="INC-LEDGER-001",
        status="completed",
        model_used="llama3.2:3b",
        iterations=5,
        total_tokens=4096,
        total_cost_usd=0.0,
        measured_call_count=0,
        estimated_cost_usd=0.0,
        estimated_call_count=0,
        unpriced_call_count=5,
        started_at=datetime(2026, 5, 1, 12, 0, tzinfo=UTC),
        completed_at=datetime(2026, 5, 1, 12, 5, tzinfo=UTC),
        error=None,
        alert_summary="Impossible travel on a privileged account",
    )


def _artifact(event_seq: int) -> SimpleNamespace:
    return SimpleNamespace(
        id=uuid.UUID(int=1000 + event_seq),
        run_id=RUN_ID,
        event_id=uuid.UUID(int=event_seq),
        kind="llm_response",
        content="the literal model transcript",
        blob_ref=None,
        sha256="f" * 64,
        size_bytes=28,
        created_at=datetime(2026, 5, 1, 12, 0, event_seq, tzinfo=UTC),
    )


# ---------------------------------------------------------------------------
# The stubbed database
# ---------------------------------------------------------------------------

#: ``investigation_events.seq <op> :bound`` as SQLAlchemy renders it.
_SEQ_PREDICATE = re.compile(r"investigation_events\.seq\s*(<=|>=|<|>|=)\s*:(\w+)")
_LIMIT = re.compile(r"LIMIT\s*:(\w+)")

_OPERATORS: dict[str, Any] = {
    "<": lambda value, bound: value < bound,
    "<=": lambda value, bound: value <= bound,
    ">": lambda value, bound: value > bound,
    ">=": lambda value, bound: value >= bound,
    "=": lambda value, bound: value == bound,
}


class _Result:
    """Enough of SQLAlchemy's ``Result`` for the four shapes these routes use."""

    def __init__(self, rows: list[Any]) -> None:
        self._rows = rows

    def scalars(self) -> _Result:
        return self

    def all(self) -> list[Any]:
        return list(self._rows)

    def scalar_one_or_none(self) -> Any:
        return self._rows[0] if self._rows else None

    def scalar_one(self) -> Any:
        if not self._rows:
            raise AssertionError("scalar_one() on an empty result")
        return self._rows[0]


class _Session:
    """Answers the ledger read queries the way Postgres would.

    Specifically: it applies the predicates, the ordering and the limit the
    *emitted statement* carries, and applies no ordering the statement does
    not ask for. A handler gets back what its own SQL described, which is the
    only way a test can tell a replay from a bag of steps.
    """

    def __init__(
        self,
        *,
        run: SimpleNamespace | None,
        events: list[SimpleNamespace] | None = None,
        artifacts: list[SimpleNamespace] | None = None,
    ) -> None:
        self.run = run
        self.events = events if events is not None else [_event(seq) for seq in STORED_ORDER]
        self.artifacts = artifacts or []
        self.statements: list[tuple[str, dict[str, Any]]] = []

    async def execute(self, statement: Any) -> _Result:
        sql = " ".join(str(statement).split())
        params = dict(statement.compile().params)
        self.statements.append((sql, params))

        # Order matters: the count statement wraps the event select in a
        # subquery, so it names `investigation_events` too.
        if "count(" in sql:
            return _Result([len(self._events(sql, params))])
        if "FROM investigation_runs" in sql:
            return _Result([self.run] if self.run is not None else [])
        if "FROM investigation_artifacts" in sql:
            return _Result(list(self.artifacts))
        if "FROM investigation_events" in sql:
            return _Result(self._events(sql, params))
        if "aisoc_run_costs" in sql:
            return _Result([])
        raise AssertionError(f"the stub was asked something it does not model: {sql}")

    def _events(self, sql: str, params: dict[str, Any]) -> list[SimpleNamespace]:
        rows = list(self.events)

        for operator, bound_name in _SEQ_PREDICATE.findall(sql):
            bound = params.get(bound_name)
            if bound is None:
                continue
            rows = [row for row in rows if _OPERATORS[operator](row.seq, bound)]

        # No ORDER BY, no ordering. This is the whole point of the fixture.
        if "ORDER BY investigation_events.seq" in sql:
            rows.sort(key=lambda row: row.seq, reverse="ORDER BY investigation_events.seq DESC" in sql)

        limit = _LIMIT.search(sql)
        if limit:
            rows = rows[: params[limit.group(1)]]
        return rows

    def statement_for(self, table: str) -> str:
        """The last statement issued against ``table``, for diagnostics."""
        for sql, _params in reversed(self.statements):
            if f"FROM {table}" in sql and "count(" not in sql:
                return sql
        raise AssertionError(f"no statement was issued against {table}")


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _user(*, scopes: list[str] | None = None) -> CurrentUser:
    return CurrentUser(
        user_id=uuid.uuid4(),
        tenant_id=TENANT,
        role="tenant_admin",
        email="analyst@example.invalid",
        scopes=["*"] if scopes is None else scopes,
    )


def _client(session: _Session, *, user: CurrentUser | None = None) -> TestClient:
    app = FastAPI()
    app.include_router(investigations_router, prefix="/api/v1")

    async def _db() -> Any:
        yield session

    app.dependency_overrides[get_tenant_db] = _db
    app.dependency_overrides[get_current_user] = lambda: user or _user()
    return TestClient(app)


@pytest.fixture
def session() -> _Session:
    return _Session(run=_run())


@pytest.fixture
def client(session: _Session) -> TestClient:
    return _client(session)


_REPLAY = f"/api/v1/investigations/{RUN_ID}/replay"
_EVENTS = f"/api/v1/investigations/{RUN_ID}/events"
_EXPLAIN = f"/api/v1/investigations/{RUN_ID}/explain"


# ---------------------------------------------------------------------------
# Ordering — the property the claim rests on
# ---------------------------------------------------------------------------


class TestReplayIsOrderedBySequence:
    def test_steps_come_back_in_sequence_order_not_storage_order(self, client: TestClient) -> None:
        """The assertion that goes red when ``ORDER BY seq`` leaves the handler.

        The fixture holds the steps as 3, 1, 5, 2, 4. A replay that does not
        order them serves them that way, and an analyst reading the run sees
        the agent reach a conclusion before it gathered the evidence.
        """
        body = client.get(_REPLAY).json()

        assert [step["seq"] for step in body] == [1, 2, 3, 4, 5]
        assert [step["seq"] for step in body] != list(STORED_ORDER)

    def test_the_emitted_statement_orders_by_seq_ascending(self, session: _Session, client: TestClient) -> None:
        """Names the cause when the test above fails, rather than the symptom."""
        client.get(_REPLAY)

        assert "ORDER BY investigation_events.seq ASC" in session.statement_for("investigation_events")

    def test_the_paginated_stream_is_ordered_too(self, client: TestClient) -> None:
        """``/events`` is what a tailing client reads; out of order it cannot tail."""
        body = client.get(_EVENTS).json()

        assert [step["seq"] for step in body["items"]] == [1, 2, 3, 4, 5]

    def test_a_replay_of_one_step_is_still_a_replay(self, client: TestClient) -> None:
        """Guards the degenerate case a sort would pass trivially."""
        body = client.get(_REPLAY, params={"max_events": 1}).json()

        assert [step["seq"] for step in body] == [1]


# ---------------------------------------------------------------------------
# Bounds
# ---------------------------------------------------------------------------


class TestReplayHonoursItsBound:
    def test_max_events_truncates_and_keeps_the_earliest_steps(self, client: TestClient) -> None:
        """Truncation has to take the *first* steps, which needs the ordering.

        An unordered query truncated to two would hand back steps 3 and 1 and
        call them the start of the investigation.
        """
        body = client.get(_REPLAY, params={"max_events": 2}).json()

        assert [step["seq"] for step in body] == [1, 2]

    def test_the_bound_reaches_the_query_rather_than_the_serialiser(self, session: _Session, client: TestClient) -> None:
        client.get(_REPLAY, params={"max_events": 3})

        sql, params = session.statements[-1]
        limit = _LIMIT.search(sql)
        assert limit is not None, f"the replay query carries no LIMIT: {sql}"
        assert params[limit.group(1)] == 3

    def test_the_default_bound_is_applied_when_none_is_asked_for(self, session: _Session, client: TestClient) -> None:
        """A replay with no bound at all would stream an unbounded response."""
        client.get(_REPLAY)

        sql, params = session.statements[-1]
        limit = _LIMIT.search(sql)
        assert limit is not None
        assert params[limit.group(1)] == 10000

    @pytest.mark.parametrize("max_events", [0, -1, 50001])
    def test_a_bound_outside_the_declared_range_is_refused(self, client: TestClient, max_events: int) -> None:
        assert client.get(_REPLAY, params={"max_events": max_events}).status_code == 422

    @pytest.mark.parametrize("limit", [0, 1001])
    def test_the_event_page_size_is_bounded_the_same_way(self, client: TestClient, limit: int) -> None:
        assert client.get(_EVENTS, params={"limit": limit}).status_code == 422


class TestEventCursor:
    def test_since_returns_only_later_steps_and_reports_the_next_cursor(self, client: TestClient) -> None:
        body = client.get(_EVENTS, params={"since": 2}).json()

        assert [step["seq"] for step in body["items"]] == [3, 4, 5]
        assert body["since"] == 2
        assert body["next_seq"] == 5

    def test_total_counts_the_matching_rows_not_the_returned_page(self, client: TestClient) -> None:
        """A total equal to the page size tells a tailing client nothing."""
        body = client.get(_EVENTS, params={"limit": 2}).json()

        assert [step["seq"] for step in body["items"]] == [1, 2]
        assert body["total"] == 5

    def test_an_exhausted_cursor_reports_no_next_seq(self, client: TestClient) -> None:
        body = client.get(_EVENTS, params={"since": 5}).json()

        assert body["items"] == []
        assert body["next_seq"] is None


# ---------------------------------------------------------------------------
# The response contract
# ---------------------------------------------------------------------------


class TestServedFieldsAreExactlyTheModel:
    def test_replay_serves_every_event_field_and_no_others(self, client: TestClient) -> None:
        """Pins the response against ``EventOut`` rather than a hand-typed list.

        ``scripts/check_ledger_replay_contract.py`` holds ``EventOut`` against
        the console's ``LedgerEvent``; this holds the served document against
        ``EventOut``. Between them a field cannot be added to the model and
        dropped on the way out, or renamed in one place only.
        """
        step = client.get(_REPLAY).json()[0]

        assert set(step) == set(EventOut.model_fields)

    def test_the_hashes_that_make_a_step_auditable_are_served(self, client: TestClient) -> None:
        """``input_hash``/``output_hash`` are what tie a step to its evidence."""
        step = client.get(_REPLAY).json()[0]

        assert step["input_hash"] == "in-1"
        assert step["output_hash"] == "out-1"
        assert step["payload"] == {"step": 1}

    def test_the_event_page_serves_the_same_shape(self, client: TestClient) -> None:
        body = client.get(_EVENTS).json()

        assert set(body) == {"items", "total", "since", "next_seq"}
        assert set(body["items"][0]) == set(EventOut.model_fields)


# ---------------------------------------------------------------------------
# Explain
# ---------------------------------------------------------------------------


class TestExplainStep:
    def test_it_renders_the_step_with_the_decisions_either_side(self, session: _Session) -> None:
        session.artifacts = [_artifact(3)]
        body = _client(session).get(_EXPLAIN, params={"step": 3}).json()

        assert body["focus"]["seq"] == 3
        assert body["previous"]["seq"] == 2
        assert body["next"]["seq"] == 4

    def test_the_neighbours_are_the_adjacent_steps_not_arbitrary_ones(self, session: _Session) -> None:
        """The prev/next lookups order by ``seq`` in opposite directions.

        With the fixture stored as 3, 1, 5, 2, 4 an unordered ``LIMIT 1`` would
        answer with whichever row came first, so this is the same ordering
        property as replay, asserted where it is easiest to get wrong.
        """
        body = _client(session).get(_EXPLAIN, params={"step": 4}).json()

        assert body["previous"]["seq"] == 3
        assert body["next"]["seq"] == 5

    def test_the_first_step_has_no_previous_and_the_last_has_no_next(self, session: _Session) -> None:
        first = _client(session).get(_EXPLAIN, params={"step": 1}).json()
        last = _client(session).get(_EXPLAIN, params={"step": 5}).json()

        assert first["previous"] is None
        assert first["next"]["seq"] == 2
        assert last["previous"]["seq"] == 4
        assert last["next"] is None

    def test_the_transcript_attached_to_the_step_is_inlined(self, session: _Session) -> None:
        session.artifacts = [_artifact(2)]
        body = _client(session).get(_EXPLAIN, params={"step": 2}).json()

        assert [artifact["content"] for artifact in body["artifacts"]] == ["the literal model transcript"]

    def test_a_step_the_run_never_took_is_a_404(self, session: _Session) -> None:
        response = _client(session).get(_EXPLAIN, params={"step": 99})

        assert response.status_code == 404
        assert "seq=99" in response.json()["detail"]

    def test_the_step_is_required(self, client: TestClient) -> None:
        assert client.get(_EXPLAIN).status_code == 422


# ---------------------------------------------------------------------------
# Authorization and the missing run
# ---------------------------------------------------------------------------


class TestAccessControl:
    """Every read here is a step an agent took inside somebody's estate."""

    @pytest.mark.parametrize("url", [_REPLAY, _EVENTS, _EXPLAIN])
    def test_a_run_that_is_not_this_tenants_is_a_404_not_an_empty_list(self, url: str) -> None:
        """An empty replay reads as "the agent did nothing", which is a lie.

        ``_fetch_run`` filters on the authenticated tenant, so a run belonging
        to somebody else is indistinguishable from one that does not exist —
        and both must refuse rather than answer with zero steps.
        """
        response = _client(_Session(run=None)).get(url, params={"step": 1})

        assert response.status_code == 404
        assert response.json()["detail"] == "Investigation run not found"

    @pytest.mark.parametrize("url", [_REPLAY, _EVENTS, _EXPLAIN])
    def test_a_caller_without_cases_read_is_refused(self, session: _Session, url: str) -> None:
        response = _client(session, user=_user(scopes=[])).get(url, params={"step": 1})

        assert response.status_code == 403
        assert "cases:read" in response.json()["detail"]

    @pytest.mark.parametrize("url", [_REPLAY, _EVENTS, _EXPLAIN])
    def test_authorization_is_checked_before_the_database_is_touched(self, session: _Session, url: str) -> None:
        """A refused caller must not be able to make the route run a query."""
        _client(session, user=_user(scopes=[])).get(url, params={"step": 1})

        assert session.statements == []

    @pytest.mark.parametrize("url", [_REPLAY, _EVENTS, _EXPLAIN])
    def test_a_read_only_scope_is_enough(self, session: _Session, url: str) -> None:
        response = _client(session, user=_user(scopes=["cases:read"])).get(url, params={"step": 1})

        assert response.status_code == 200

    def test_the_run_is_resolved_against_the_callers_tenant(self, session: _Session, client: TestClient) -> None:
        """Without the tenant predicate any authenticated caller reads any run."""
        client.get(_REPLAY)

        sql, params = session.statements[0]
        assert "FROM investigation_runs" in sql
        assert "investigation_runs.tenant_id" in sql
        assert TENANT in params.values()
