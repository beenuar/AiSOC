"""Unit tests for the in-process connector scheduler.

We test the scheduler in isolation from APScheduler internals by directly
calling ``reload_jobs`` / ``_poll_one`` with fakes for the engine, vault,
ingest client, and connector class. The point of these tests is to
exercise the *control flow*:

* reload picks up new instances, reschedules changed ones, drops removed ones
* a successful poll decrypts creds, instantiates the connector, calls
  fetch_alerts, pushes to ingest, and records success
* every failure path flips the connector to unhealthy without raising

We do *not* test APScheduler itself — that has its own tests.
"""

from __future__ import annotations

import uuid
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest
from app.db.connector_repo import ConnectorInstance
from app.scheduler import ConnectorScheduler, _coerce_poll_interval


def _make_instance(
    *,
    connector_type: str = "crowdstrike",
    is_enabled: bool = True,
    auth_config: dict[str, Any] | None = None,
    connector_config: dict[str, Any] | None = None,
) -> ConnectorInstance:
    return ConnectorInstance(
        id=uuid.uuid4(),
        tenant_id=uuid.uuid4(),
        name="test",
        connector_type=connector_type,
        is_enabled=is_enabled,
        auth_config=auth_config or {"client_id": "id", "client_secret": "secret"},
        connector_config=connector_config or {},
        health_status="healthy",
        last_sync=None,
        events_ingested=0,
        error_count=0,
    )


# ---------------------------------------------------------------------------
# poll_interval coercion
# ---------------------------------------------------------------------------


def test_poll_interval_default():
    assert _coerce_poll_interval({}) == 300


def test_poll_interval_clamps_low():
    assert _coerce_poll_interval({"poll_interval_seconds": 5}) == 30


def test_poll_interval_clamps_high():
    assert _coerce_poll_interval({"poll_interval_seconds": 999_999}) == 86400


def test_poll_interval_invalid_falls_back():
    assert _coerce_poll_interval({"poll_interval_seconds": "not-a-number"}) == 300


def test_poll_interval_passes_through_valid():
    assert _coerce_poll_interval({"poll_interval_seconds": 600}) == 600


# ---------------------------------------------------------------------------
# _poll_one happy path
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_poll_one_happy_path(monkeypatch):
    inst = _make_instance(
        connector_type="fake_connector",
        connector_config={"poll_interval_seconds": 60},
    )

    fake_connector = MagicMock()
    fake_connector.fetch_alerts = AsyncMock(return_value=[{"raw": "event"}])
    fake_connector.normalize = MagicMock(side_effect=lambda e: {"normalized": True, **e})

    fake_connector_class = MagicMock(return_value=fake_connector)

    monkeypatch.setattr(
        "app.scheduler.CONNECTOR_REGISTRY",
        {"fake_connector": fake_connector_class},
    )

    fake_engine = _FakeEngine([inst])
    fake_vault = _FakeVault()
    fake_ingest = _FakeIngestClient(accepted=1)

    scheduler = ConnectorScheduler(
        engine=fake_engine, ingest_client=fake_ingest, vault=fake_vault
    )
    # We don't call start() because we don't want APScheduler running for
    # this test — _poll_one operates on the injected fakes directly.

    await scheduler._poll_one(connector_id=inst.id)

    fake_connector_class.assert_called_once_with(
        client_id="id", client_secret="secret"
    )
    fake_connector.fetch_alerts.assert_awaited_once_with(since_seconds=60)
    assert fake_ingest.calls == 1
    pushed = fake_ingest.last_payload
    assert pushed["events"] == [{"normalized": True, "raw": "event"}]
    assert fake_engine.success_calls == [inst.id]
    assert fake_engine.failure_calls == []


# ---------------------------------------------------------------------------
# Failure paths each flip the row to unhealthy without raising
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_poll_one_unknown_connector_type(monkeypatch):
    inst = _make_instance(connector_type="not_in_registry")
    monkeypatch.setattr("app.scheduler.CONNECTOR_REGISTRY", {})

    scheduler = ConnectorScheduler(
        engine=_FakeEngine([inst]), ingest_client=_FakeIngestClient(), vault=_FakeVault()
    )
    await scheduler._poll_one(connector_id=inst.id)

    engine: _FakeEngine = scheduler._engine  # type: ignore[assignment]
    assert engine.failure_calls == [inst.id]


@pytest.mark.asyncio
async def test_poll_one_decrypt_failure(monkeypatch):
    inst = _make_instance(connector_type="fake_connector")
    monkeypatch.setattr(
        "app.scheduler.CONNECTOR_REGISTRY", {"fake_connector": MagicMock()}
    )

    bad_vault = _FakeVault()
    bad_vault.fail = True

    scheduler = ConnectorScheduler(
        engine=_FakeEngine([inst]), ingest_client=_FakeIngestClient(), vault=bad_vault
    )
    await scheduler._poll_one(connector_id=inst.id)

    engine: _FakeEngine = scheduler._engine  # type: ignore[assignment]
    assert engine.failure_calls == [inst.id]


@pytest.mark.asyncio
async def test_poll_one_constructor_typeerror(monkeypatch):
    inst = _make_instance(
        connector_type="fake_connector",
        auth_config={"unexpected_kwarg": "x"},
    )

    def bad_ctor(**_kwargs: Any) -> Any:
        raise TypeError("got unexpected keyword argument")

    monkeypatch.setattr(
        "app.scheduler.CONNECTOR_REGISTRY", {"fake_connector": bad_ctor}
    )

    scheduler = ConnectorScheduler(
        engine=_FakeEngine([inst]), ingest_client=_FakeIngestClient(), vault=_FakeVault()
    )
    await scheduler._poll_one(connector_id=inst.id)

    engine: _FakeEngine = scheduler._engine  # type: ignore[assignment]
    assert engine.failure_calls == [inst.id]


@pytest.mark.asyncio
async def test_poll_one_fetch_raises(monkeypatch):
    inst = _make_instance(connector_type="fake_connector")
    fake_connector = MagicMock()
    fake_connector.fetch_alerts = AsyncMock(side_effect=RuntimeError("api boom"))
    monkeypatch.setattr(
        "app.scheduler.CONNECTOR_REGISTRY",
        {"fake_connector": MagicMock(return_value=fake_connector)},
    )

    scheduler = ConnectorScheduler(
        engine=_FakeEngine([inst]), ingest_client=_FakeIngestClient(), vault=_FakeVault()
    )
    await scheduler._poll_one(connector_id=inst.id)

    engine: _FakeEngine = scheduler._engine  # type: ignore[assignment]
    assert engine.failure_calls == [inst.id]


@pytest.mark.asyncio
async def test_poll_one_ingest_raises(monkeypatch):
    from app.ingest_client import IngestClientError

    inst = _make_instance(connector_type="fake_connector")
    fake_connector = MagicMock()
    fake_connector.fetch_alerts = AsyncMock(return_value=[{"x": 1}])
    fake_connector.normalize = MagicMock(side_effect=lambda e: e)
    monkeypatch.setattr(
        "app.scheduler.CONNECTOR_REGISTRY",
        {"fake_connector": MagicMock(return_value=fake_connector)},
    )

    bad_ingest = _FakeIngestClient()
    bad_ingest.exc = IngestClientError("ingest down")

    scheduler = ConnectorScheduler(
        engine=_FakeEngine([inst]), ingest_client=bad_ingest, vault=_FakeVault()
    )
    await scheduler._poll_one(connector_id=inst.id)

    engine: _FakeEngine = scheduler._engine  # type: ignore[assignment]
    assert engine.failure_calls == [inst.id]


@pytest.mark.asyncio
async def test_poll_one_instance_disappeared(monkeypatch):
    """If the connector row was deleted between reload and poll, we no-op."""
    monkeypatch.setattr("app.scheduler.CONNECTOR_REGISTRY", {})
    scheduler = ConnectorScheduler(
        engine=_FakeEngine([]), ingest_client=_FakeIngestClient(), vault=_FakeVault()
    )
    await scheduler._poll_one(connector_id=uuid.uuid4())

    engine: _FakeEngine = scheduler._engine  # type: ignore[assignment]
    assert engine.success_calls == []
    assert engine.failure_calls == []


# ---------------------------------------------------------------------------
# reload_jobs sync logic
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_reload_adds_and_drops_jobs(monkeypatch):
    monkeypatch.setattr("app.scheduler.CONNECTOR_REGISTRY", {})
    a = _make_instance()
    b = _make_instance()
    engine = _FakeEngine([a, b])
    scheduler = ConnectorScheduler(
        engine=engine, ingest_client=_FakeIngestClient(), vault=_FakeVault()
    )
    fake_aps = _FakeAPScheduler()
    scheduler._scheduler = fake_aps

    await scheduler.reload_jobs()
    added_first = {kw["id"] for kw in fake_aps.added}
    assert f"connector:{a.id}" in added_first
    assert f"connector:{b.id}" in added_first

    # Drop b.
    engine.instances = [a]
    await scheduler.reload_jobs()
    assert f"connector:{b.id}" in fake_aps.removed


@pytest.mark.asyncio
async def test_reload_skips_unchanged_jobs(monkeypatch):
    monkeypatch.setattr("app.scheduler.CONNECTOR_REGISTRY", {})
    inst = _make_instance(connector_config={"poll_interval_seconds": 120})
    engine = _FakeEngine([inst])
    scheduler = ConnectorScheduler(
        engine=engine, ingest_client=_FakeIngestClient(), vault=_FakeVault()
    )
    fake_aps = _FakeAPScheduler()
    scheduler._scheduler = fake_aps

    await scheduler.reload_jobs()
    assert len(fake_aps.added) == 1

    # Second reload with no changes — no add_job should fire again.
    await scheduler.reload_jobs()
    assert len(fake_aps.added) == 1


@pytest.mark.asyncio
async def test_reload_reschedules_when_interval_changes(monkeypatch):
    monkeypatch.setattr("app.scheduler.CONNECTOR_REGISTRY", {})
    inst = _make_instance(connector_config={"poll_interval_seconds": 120})
    engine = _FakeEngine([inst])
    scheduler = ConnectorScheduler(
        engine=engine, ingest_client=_FakeIngestClient(), vault=_FakeVault()
    )
    fake_aps = _FakeAPScheduler()
    scheduler._scheduler = fake_aps

    await scheduler.reload_jobs()
    assert len(fake_aps.added) == 1
    first_seconds = fake_aps.added[0]["seconds"]
    assert first_seconds == 120

    # Mutate the instance to bump the interval; reload should add_job again
    # (with replace_existing=True, which APScheduler treats as reschedule).
    inst.connector_config = {"poll_interval_seconds": 600}
    await scheduler.reload_jobs()
    assert len(fake_aps.added) == 2
    assert fake_aps.added[-1]["seconds"] == 600


# ---------------------------------------------------------------------------
# Test fakes
# ---------------------------------------------------------------------------


class _FakeAPScheduler:
    def __init__(self) -> None:
        self.added: list[dict[str, Any]] = []
        self.removed: list[str] = []

    def add_job(
        self,
        func: Any,
        trigger: str,
        *,
        seconds: int,
        id: str,
        replace_existing: bool,
        max_instances: int,
        coalesce: bool,
        next_run_time: Any = None,
        kwargs: dict[str, Any] | None = None,
    ) -> None:
        self.added.append(
            {
                "func": func,
                "trigger": trigger,
                "seconds": seconds,
                "id": id,
                "kwargs": kwargs or {},
            }
        )

    def remove_job(self, job_id: str) -> None:
        self.removed.append(job_id)


class _FakeAsyncContextManager:
    """Minimal stand-in for ``async with engine.begin() as conn``."""

    def __init__(self, conn: Any) -> None:
        self._conn = conn

    async def __aenter__(self) -> Any:
        return self._conn

    async def __aexit__(self, *_args: Any) -> None:
        return None


class _FakeEngine:
    """Async engine fake that records record_poll_success/failure calls."""

    def __init__(self, instances: list[ConnectorInstance]) -> None:
        self.instances = list(instances)
        self.success_calls: list[uuid.UUID] = []
        self.failure_calls: list[uuid.UUID] = []

    def begin(self) -> _FakeAsyncContextManager:
        return _FakeAsyncContextManager(_FakeConnection(self))


class _FakeConnection:
    def __init__(self, engine: _FakeEngine) -> None:
        self.engine = engine


class _FakeVault:
    def __init__(self) -> None:
        self.fail = False

    def decrypt_dict(self, payload: dict[str, Any]) -> dict[str, Any]:
        if self.fail:
            from app.security.credential_vault import CredentialVaultError

            raise CredentialVaultError("decrypt failed")
        return dict(payload)


class _FakeIngestClient:
    def __init__(self, accepted: int = 0) -> None:
        self.calls = 0
        self.accepted = accepted
        self.last_payload: dict[str, Any] | None = None
        self.exc: BaseException | None = None

    async def push_events(self, **kwargs: Any) -> dict[str, Any]:
        self.calls += 1
        self.last_payload = kwargs
        if self.exc is not None:
            raise self.exc
        return {"accepted": self.accepted, "rejected": 0}

    async def aclose(self) -> None:
        return None


# Patch the connector_repo db functions to operate on the fake engine
# attached to each connection. We do this once at module import via a
# pytest fixture autouse=True so individual tests don't need to
# remember.


@pytest.fixture(autouse=True)
def _patch_repo_calls(monkeypatch):
    async def fake_fetch_enabled_connectors(conn: Any) -> list[ConnectorInstance]:
        return list(conn.engine.instances)

    async def fake_record_poll_success(conn: Any, connector_id: uuid.UUID, *, events_added: int) -> None:
        conn.engine.success_calls.append(connector_id)

    async def fake_record_poll_failure(conn: Any, connector_id: uuid.UUID) -> None:
        conn.engine.failure_calls.append(connector_id)

    monkeypatch.setattr("app.scheduler.fetch_enabled_connectors", fake_fetch_enabled_connectors)
    monkeypatch.setattr("app.scheduler.record_poll_success", fake_record_poll_success)
    monkeypatch.setattr("app.scheduler.record_poll_failure", fake_record_poll_failure)
