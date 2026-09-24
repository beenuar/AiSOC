"""``PostgresTimerStore`` does not create its own table, and scopes every row.

``approval_timers`` was in no migration anywhere: the store created it at
startup with ``CREATE TABLE IF NOT EXISTS``. Two consequences, and the tests
below pin both.

* It had no row-level-security policy, because ``060_rls_coverage.sql`` gave
  one to every tenant-scoped table *in the chain* and this table was outside
  it — on a table that decides whether a pending containment auto-rejects. It
  also had no ``tenant_id`` for a policy to filter on.
* Under the DML-only runtime role the DDL itself fails: Postgres checks the
  schema ACL before the existence test, so ``CREATE TABLE IF NOT EXISTS``
  raises ``permission denied for schema public`` even when the table is there.
  ``main.py`` caught that into a log line and fell back to the in-memory
  store, so "durable approval timers" would have quietly stopped being
  durable.

These drive a recording double rather than a live database: what is being
asserted is the statements the store issues, which is exactly what a policy
and a missing migration turn on. The live half is
``tests/isolation/test_postgres_rls.py``.
"""

from __future__ import annotations

import pytest
from app.services.timer_store import MissingApprovalTimersTable, PostgresTimerStore, TimerRecord

TENANT = "11111111-1111-1111-1111-111111111111"
OTHER = "22222222-2222-2222-2222-222222222222"


class _Conn:
    def __init__(self, rows: list[dict] | None = None) -> None:
        self.statements: list[tuple[str, tuple]] = []
        self._rows = rows or []

    async def execute(self, sql, *args):
        self.statements.append((sql, args))

    async def fetch(self, sql, *args):
        self.statements.append((sql, args))
        return self._rows

    async def fetchval(self, sql, *args):
        self.statements.append((sql, args))
        return "approval_timers"


class _Acquire:
    def __init__(self, conn: _Conn) -> None:
        self._conn = conn

    async def __aenter__(self) -> _Conn:
        return self._conn

    async def __aexit__(self, *exc) -> None:
        return None


class _Pool:
    def __init__(self, conn: _Conn) -> None:
        self._conn = conn

    def acquire(self) -> _Acquire:
        return _Acquire(self._conn)


def _sql(conn: _Conn) -> str:
    return " ".join(sql for sql, _ in conn.statements)


@pytest.mark.asyncio
async def test_put_carries_the_tenant():
    conn = _Conn()
    store = PostgresTimerStore(_Pool(conn), TENANT)
    await store.put(TimerRecord(action_id="a1", fire_at_epoch=1.0, safe_default="rejected"))
    sql, args = conn.statements[0]
    assert "tenant_id" in sql
    assert TENANT in args


@pytest.mark.asyncio
async def test_delete_is_scoped_to_the_tenant():
    conn = _Conn()
    store = PostgresTimerStore(_Pool(conn), TENANT)
    await store.delete("a1")
    sql, args = conn.statements[0]
    assert "tenant_id=$2" in sql.replace(" ", "")
    assert args == ("a1", TENANT)


@pytest.mark.asyncio
async def test_list_pending_is_scoped_to_the_tenant():
    conn = _Conn(
        rows=[
            {
                "action_id": "a1",
                "tenant_id": TENANT,
                "fire_at": 1.0,
                "safe_default": "rejected",
                "case_id": "c1",
                "channel": None,
                "approver_id": "scheduler",
            }
        ]
    )
    store = PostgresTimerStore(_Pool(conn), TENANT)
    records = await store.list_pending()
    sql, args = conn.statements[0]
    assert "WHERE tenant_id = $1" in sql
    assert args == (TENANT,)
    assert records[0].tenant_id == TENANT


@pytest.mark.asyncio
async def test_a_record_naming_another_tenant_does_not_override_the_store():
    """The store's tenant wins. A record is data; the connection is the scope."""
    conn = _Conn()
    store = PostgresTimerStore(_Pool(conn), TENANT)
    await store.put(TimerRecord(action_id="a1", fire_at_epoch=1.0, safe_default="rejected", tenant_id=""))
    _sql_text, args = conn.statements[0]
    assert TENANT in args
    assert OTHER not in args


def test_the_store_issues_no_ddl():
    """A grep over the module, because the failure was DDL on a startup path.

    Asserted against the source rather than against a call log: the point is
    that no code path can create the table, not that one particular path did
    not this time.
    """
    import inspect  # noqa: PLC0415

    from app.services import timer_store  # noqa: PLC0415

    source = inspect.getsource(timer_store)
    body = source.split('"""', 2)[-1]  # drop the module docstring, which names the SQL
    for statement in ("CREATE TABLE", "CREATE INDEX", "ALTER TABLE"):
        assert statement not in body, f"{statement} is back in timer_store.py; it belongs in a migration"


@pytest.mark.asyncio
async def test_create_refuses_when_the_table_is_absent(monkeypatch):
    """An absent table is an error naming the migration, not a silent fallback."""

    class _AbsentConn(_Conn):
        async def fetchval(self, sql, *args):
            return None

    closed: list[bool] = []

    class _ClosablePool(_Pool):
        async def close(self) -> None:
            closed.append(True)

    class _FakeAsyncpg:
        @staticmethod
        async def create_pool(*_args, **_kwargs):
            return _ClosablePool(_AbsentConn())

    monkeypatch.setitem(__import__("sys").modules, "asyncpg", _FakeAsyncpg)

    with pytest.raises(MissingApprovalTimersTable) as caught:
        await PostgresTimerStore.create("postgresql+asyncpg://u:p@h/db", TENANT)
    assert "062_approval_timers.sql" in str(caught.value)
    assert closed, "the pool was left open after refusing"


@pytest.mark.asyncio
async def test_create_binds_the_rls_context_on_every_connection(monkeypatch):
    """The policy only engages on a connection that bound a tenant."""
    captured: dict[str, object] = {}

    class _FakeAsyncpg:
        @staticmethod
        async def create_pool(*_args, **kwargs):
            captured["init"] = kwargs.get("init")
            return _Pool(_Conn())

    monkeypatch.setitem(__import__("sys").modules, "asyncpg", _FakeAsyncpg)
    await PostgresTimerStore.create("postgresql+asyncpg://u:p@h/db", TENANT)

    init = captured["init"]
    assert init is not None, "connections are pooled without binding a tenant, so the policy never engages"
    conn = _Conn()
    await init(conn)  # type: ignore[operator]
    sql, args = conn.statements[0]
    assert "app.current_tenant_id" in sql
    assert TENANT in args
