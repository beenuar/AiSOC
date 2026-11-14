"""Depth plan 2.4 — the stateful half of the session projection.

The fake connection here records the SQL and arguments it was given rather
than answering whatever it is asked. A double that returns a plausible row for
any query is how a store that writes to the wrong column passes its tests: the
assertions below are on what would reach Postgres, and the schema those
arguments have to satisfy is asserted against the migration itself.
"""

from __future__ import annotations

import asyncio
import json
import re
import uuid
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from pathlib import Path

import pytest
from app.services.sessions import (
    DERIVED_IDLE_SECONDS,
    KEY_KINDS,
    SessionStore,
    session_id,
)

MIGRATION = Path(__file__).resolve().parents[3] / "services" / "api" / "migrations" / "102_sessions.sql"

TENANT = "11111111-1111-1111-1111-111111111111"


class RecordingConn:
    def __init__(self, fail: Exception | None = None, tenants: list[str] | None = None) -> None:
        self.calls: list[tuple[str, tuple]] = []
        self._fail = fail
        # What `SELECT DISTINCT tenant_id` returns. asyncpg hands back
        # mapping-like Records, so a dict is the honest stand-in.
        self._tenants = tenants if tenants is not None else []

    async def execute(self, sql: str, *args):
        if self._fail is not None:
            raise self._fail
        self.calls.append((sql, args))
        return "INSERT 0 1"

    async def fetch(self, sql: str, *args):
        if self._fail is not None:
            raise self._fail
        self.calls.append((sql, args))
        return [{"tenant_id": t} for t in self._tenants]

    def all_sql_containing(self, needle: str) -> list[tuple[str, tuple]]:
        return [(sql, args) for sql, args in self.calls if needle in sql]

    def sql_containing(self, needle: str) -> tuple[str, tuple]:
        for sql, args in self.calls:
            if needle in sql:
                return sql, args
        raise AssertionError(f"no statement containing {needle!r}; saw {[s[:40] for s, _ in self.calls]}")


class RecordingPool:
    def __init__(self, conn: RecordingConn) -> None:
        self.conn = conn

    @asynccontextmanager
    async def acquire(self):
        yield self.conn


def event(session: dict | None, *, tenant_source: str = "aws_cloudtrail", actor_kind: str = "human") -> dict:
    activity: dict = {"actor": {"kind": actor_kind, "id": "arn:aws:iam::1:user/alice"}, "location": {"ip": "203.0.113.10"}}
    if session is not None:
        activity["session"] = session
    return {
        "metadata": {"product": {"name": tenant_source}},
        "time": 1_760_000_000_000,
        "activity": activity,
    }


@pytest.mark.asyncio
async def test_a_vendor_session_is_upserted_with_its_kind():
    conn = RecordingConn()
    store = SessionStore(RecordingPool(conn))

    ref = await store.record_event(
        TENANT,
        event({"key": "ASIAIOSFODNN7EXAMPLE", "key_kind": "vendor_credential", "key_source": "userIdentity.accessKeyId"}),
    )

    assert ref is not None
    assert ref.key == "ASIAIOSFODNN7EXAMPLE"
    assert ref.key_kind == "vendor_credential"
    assert ref.is_vendor_grouping is True

    _, args = conn.sql_containing("INSERT INTO sessions")
    assert args[0] == session_id(TENANT, "aws_cloudtrail", "ASIAIOSFODNN7EXAMPLE")
    assert args[2] == "ASIAIOSFODNN7EXAMPLE"
    assert args[3] == "vendor_credential"
    assert json.loads(args[10]) == ["human"]
    assert json.loads(args[11]) == ["203.0.113.10"]


@pytest.mark.asyncio
async def test_an_event_with_no_session_writes_nothing():
    """None is an answer, and it has to stay None all the way to the console.

    A session of one invented for every unattributable event would make "what
    else did this session do" answerable with a number that means nothing.
    """
    conn = RecordingConn()
    store = SessionStore(RecordingPool(conn))

    assert await store.record_event(TENANT, event(None)) is None
    assert conn.calls == []


@pytest.mark.asyncio
async def test_a_kind_outside_the_closed_set_is_refused():
    """Producer and consumer drift is a deploy-skew bug, not a data quirk.

    Writing the row anyway would fail the CHECK constraint in Postgres and
    surface as an unexplained insert error on the hot path.
    """
    conn = RecordingConn()
    store = SessionStore(RecordingPool(conn))

    assert await store.record_event(TENANT, event({"key": "s1", "key_kind": "guessed"})) is None
    assert conn.calls == []


@pytest.mark.asyncio
async def test_the_derived_kind_is_marked_as_not_the_vendors_grouping():
    conn = RecordingConn()
    store = SessionStore(RecordingPool(conn))

    ref = await store.record_event(
        TENANT, event({"key": "alice|203.0.113.10|curl/8", "key_kind": "derived", "key_source": "principal+ip+user_agent"})
    )

    assert ref is not None
    assert ref.is_vendor_grouping is False


@pytest.mark.asyncio
async def test_the_issued_session_is_written_with_the_edge_back_to_its_parent():
    """The chain is why 2.4 reaches into the AssumeRole response at all.

    The child session's own events name only the role it assumed, so without
    this row the person behind it is unrecoverable once the issuing call ages
    out of the lake.
    """
    conn = RecordingConn()
    store = SessionStore(RecordingPool(conn))

    parent = await store.record_event(
        TENANT,
        event(
            {
                "key": "AKIAPARENT0000000EXM",
                "key_kind": "vendor_credential",
                "key_source": "userIdentity.accessKeyId",
                "issued": {
                    "key": "ASIACHILD0000000EXMP",
                    "key_source": "responseElements.credentials.accessKeyId",
                    "principal": "arn:aws:sts::1:assumed-role/Deploy/build-471",
                    "originating_human": "alice@corp.example",
                    "originating_human_source": "requestParameters.sourceIdentity",
                },
            }
        ),
    )

    assert parent is not None
    _, args = conn.sql_containing("parent_session_id")
    assert args[0] == session_id(TENANT, "aws_cloudtrail", "ASIACHILD0000000EXMP")
    assert args[2] == "ASIACHILD0000000EXMP"
    assert args[6] == "alice@corp.example"
    assert args[7] == "requestParameters.sourceIdentity"
    assert args[9] == parent.id, "the edge must point at the session that issued the credential"


@pytest.mark.asyncio
async def test_a_call_that_issued_its_own_credential_is_not_its_own_parent():
    conn = RecordingConn()
    store = SessionStore(RecordingPool(conn))

    await store.record_event(
        TENANT,
        event(
            {
                "key": "ASIASAME00000000EXMP",
                "key_kind": "vendor_credential",
                "issued": {"key": "ASIASAME00000000EXMP", "key_source": "responseElements.credentials.accessKeyId"},
            }
        ),
    )

    assert all("parent_session_id" not in sql for sql, _ in conn.calls)


@pytest.mark.asyncio
async def test_the_id_is_deterministic_across_stores_and_replays():
    """Three stores have to agree on one id without coordinating, and a Kafka
    replay must upsert the same row rather than minting a second session."""
    first = session_id(TENANT, "okta", "00okta0session0EXAMPLE0001")
    second = session_id(TENANT, "okta", "00okta0session0EXAMPLE0001")
    assert first == second
    assert isinstance(first, uuid.UUID)

    # Namespaced by tenant and by source: two tenants may legitimately observe
    # the same vendor identifier, and an Okta session id and a GitHub token
    # hash share no namespace.
    assert session_id("22222222-2222-2222-2222-222222222222", "okta", "00okta0session0EXAMPLE0001") != first
    assert session_id(TENANT, "github", "00okta0session0EXAMPLE0001") != first


@pytest.mark.asyncio
async def test_an_unreachable_store_degrades_the_alert_and_does_not_block_it():
    """An alert without session context is degraded; an alert that never
    arrives because the session store was down is an outage."""
    conn = RecordingConn(fail=RuntimeError("connection refused"))
    store = SessionStore(RecordingPool(conn))

    assert await store.record_event(TENANT, event({"key": "s1", "key_kind": "vendor_session"})) is None


@pytest.mark.asyncio
async def test_only_derived_sessions_are_closed_on_an_idle_gap():
    """A vendor session ends when the vendor says so. Guessing on its behalf
    would report a session as over while it is still being used."""
    conn = RecordingConn()
    store = SessionStore(RecordingPool(conn))

    await store.close_idle(900, tenant_id=TENANT)

    sql, args = conn.sql_containing("UPDATE sessions")
    assert "key_kind = 'derived'" in sql
    assert args == (TENANT, 900.0)


@pytest.mark.asyncio
async def test_the_idle_sweep_never_issues_an_update_without_a_tenant():
    """The first version of this swept the whole table and leaned on the RLS
    policy's `current_tenant_id() IS NULL` arm, which a worker satisfies by
    setting nothing -- so one statement reached every tenant's rows and
    `check_tenant_query_predicates.py` failed the build for it.

    RLS is defence in depth here, not the control. Every UPDATE the sweep
    issues names exactly one tenant."""
    other = "33333333-3333-3333-3333-333333333333"
    conn = RecordingConn(tenants=[TENANT, other])
    store = SessionStore(RecordingPool(conn))

    closed = await store.close_idle(900)

    updates = conn.all_sql_containing("UPDATE sessions")
    assert len(updates) == 2
    assert {args[0] for _, args in updates} == {TENANT, other}
    for sql, _ in updates:
        assert "tenant_id = $1" in sql
    assert closed == 2


@pytest.mark.asyncio
async def test_a_sweep_with_no_idle_tenants_issues_no_update_at_all():
    """The control. A quiet deployment must not write, or the test above
    would pass on a sweep that updates unconditionally."""
    conn = RecordingConn(tenants=[])
    store = SessionStore(RecordingPool(conn))

    assert await store.close_idle(900) == 0
    assert conn.all_sql_containing("UPDATE sessions") == []


def test_the_closed_set_matches_the_migrations_check_constraint():
    """Three declarations of the same vocabulary — Go, this module, and the
    CHECK constraint — and nothing but a test keeps them equal."""
    sql = MIGRATION.read_text()
    match = re.search(r"key_kind IN \(([^)]*)\)", sql)
    assert match, "migration 102 no longer declares a CHECK on key_kind"
    in_sql = {value.strip().strip("'") for value in match.group(1).split(",") if value.strip()}
    assert in_sql == set(KEY_KINDS)


def test_the_upsert_widens_the_window_and_never_rewinds_it():
    """Kafka delivers out of order after a rebalance. A late event must widen
    the session's window, not move `last_seen_at` back before an event that
    has already been counted."""
    from app.services.sessions import _UPSERT_SQL

    assert "least(sessions.first_seen_at" in _UPSERT_SQL
    assert "greatest(sessions.last_seen_at" in _UPSERT_SQL
    assert "event_count   = sessions.event_count + 1" in _UPSERT_SQL


@pytest.mark.parametrize(
    ("raw", "expect_year"),
    [
        (1_760_000_000_000, 2025),  # OCSF milliseconds
        (1_760_000_000, 2025),  # seconds, which must not land in 1970
        ("2026-03-04T05:06:07Z", 2026),
        (None, datetime.now(UTC).year),
    ],
)
def test_event_time_handles_every_shape_the_spine_delivers(raw, expect_year):
    from app.services.sessions import _event_time

    payload = {"time": raw} if raw is not None else {}
    assert _event_time(payload).year == expect_year


@pytest.mark.asyncio
async def test_the_idle_sweep_runs_from_the_worker_rather_than_nowhere():
    """`close_idle` had no production caller at all.

    A derived session ends when the activity stops, so nothing on the event
    path can ever close one -- the closing condition is the *absence* of an
    event. Without a ticker every derived session stays open forever and
    "what else did this sitting do" accumulates months of unrelated activity
    under one id, which is worse than having no session grouping at all.

    Drives the worker's real ticker with the real interval arithmetic rather
    than asserting the call exists in the source.
    """
    from app.workers import consumer as consumer_mod

    swept: list[int] = []

    class SweepOnlyStore:
        async def close_idle(self, *_a, **_kw) -> int:
            swept.append(1)
            return 0

    worker = consumer_mod.FusionWorker.__new__(consumer_mod.FusionWorker)
    worker._running = True
    worker._lake = None
    # Depth 6.1 gave the ticker a second optional store; the double carries
    # it the same way the constructor does, as None, so this test keeps
    # exercising the real loop rather than an AttributeError in it.
    worker._ai_assets = None
    worker._sessions = SweepOnlyStore()

    # The real period is a quarter of the idle window (~7 minutes). Shortened
    # here so the test exercises the real loop and its real clock arithmetic
    # rather than a reimplementation of it.
    monkeypatch = pytest.MonkeyPatch()
    monkeypatch.setattr(consumer_mod, "SESSION_SWEEP_SECONDS", 0.0)
    monkeypatch.setattr(consumer_mod.settings, "lake_batch_max_age_seconds", 0.01)
    try:
        task = asyncio.create_task(worker._periodic_flush())
        for _ in range(200):
            await asyncio.sleep(0.01)
            if swept:
                break
        worker._running = False
        task.cancel()
        # Bound rather than discarded. `return_exceptions=True` hands back
        # *how* the ticker ended instead of raising it, which is the thing
        # worth asserting: clearing `_running` can retire the loop before
        # `cancel()` reaches it, so either ending is correct -- but a sweeper
        # that died of its own exception is not, and a bare `await task`
        # cannot tell the three apart.
        (ended,) = await asyncio.gather(task, return_exceptions=True)
        assert ended is None or isinstance(ended, asyncio.CancelledError), f"the sweep ticker raised {ended!r} rather than stopping cleanly"
    finally:
        monkeypatch.undo()

    assert swept, "the worker ticker never called close_idle"


def test_the_sweep_period_is_shorter_than_the_window_it_sweeps_for():
    """Two independently-written numbers describing one budget.

    If the sweep ran less often than the idle window, a session would stay
    open for up to the sum of the two rather than the window -- the shape
    this repository has already been bitten by, where a caller's deadline
    was a sixth of the retry budget it wrapped and the shorter number won
    silently. Asserted as a relation, not as either value.
    """
    from app.workers.consumer import SESSION_SWEEP_SECONDS

    assert 0 < SESSION_SWEEP_SECONDS <= DERIVED_IDLE_SECONDS / 2
