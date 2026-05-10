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
from datetime import UTC, datetime, timedelta
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
        events_dropped=0,
        schema_fingerprint=None,
        last_schema_drift_at=None,
        last_drift_details=None,
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

    scheduler = ConnectorScheduler(engine=fake_engine, ingest_client=fake_ingest, vault=fake_vault)
    # We don't call start() because we don't want APScheduler running for
    # this test — _poll_one operates on the injected fakes directly.

    await scheduler._poll_one(connector_id=inst.id)

    fake_connector_class.assert_called_once_with(client_id="id", client_secret="secret")
    fake_connector.fetch_alerts.assert_awaited_once_with(since_seconds=60)
    assert fake_ingest.calls == 1
    pushed = fake_ingest.last_payload
    assert pushed["events"] == [{"normalized": True, "raw": "event"}]
    assert fake_engine.success_calls == [inst.id]
    assert fake_engine.failure_calls == []


# ---------------------------------------------------------------------------
# Schema-Drift Sentinel + filter-rules pipeline integration
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_poll_one_filter_rules_drop_events(monkeypatch):
    """Pre-ingest filter rules should drop matching events and bump the
    drop counter passed to record_poll_success without ever shipping the
    dropped events to ingest."""
    inst = _make_instance(
        connector_type="fake_connector",
        connector_config={
            "poll_interval_seconds": 60,
            "filter_rules": [
                {"field": "severity", "op": "eq", "value": "info", "action": "drop"},
            ],
        },
    )

    fake_connector = MagicMock()
    fake_connector.fetch_alerts = AsyncMock(
        return_value=[
            {"severity": "info", "id": "drop-me"},
            {"severity": "high", "id": "keep-me"},
        ]
    )
    fake_connector.normalize = MagicMock(side_effect=lambda e: e)

    monkeypatch.setattr(
        "app.scheduler.CONNECTOR_REGISTRY",
        {"fake_connector": MagicMock(return_value=fake_connector)},
    )

    fake_engine = _FakeEngine([inst])
    fake_ingest = _FakeIngestClient(accepted=1)

    captured_success: dict[str, Any] = {}

    async def capture_record_poll_success(
        conn: Any,
        connector_id: uuid.UUID,
        *,
        events_added: int,
        events_dropped: int = 0,
        schema_fingerprint: str | None = None,
        last_event_at: Any = None,
        last_event_kind: str | None = None,
    ) -> None:
        conn.engine.success_calls.append(connector_id)
        captured_success["events_added"] = events_added
        captured_success["events_dropped"] = events_dropped
        captured_success["schema_fingerprint"] = schema_fingerprint

    monkeypatch.setattr("app.scheduler.record_poll_success", capture_record_poll_success)

    scheduler = ConnectorScheduler(engine=fake_engine, ingest_client=fake_ingest, vault=_FakeVault())
    await scheduler._poll_one(connector_id=inst.id)

    # Only the high-severity event should reach ingest.
    pushed = fake_ingest.last_payload
    assert pushed is not None
    assert pushed["events"] == [{"severity": "high", "id": "keep-me"}]
    assert captured_success["events_dropped"] == 1
    assert captured_success["events_added"] == 1
    assert captured_success["schema_fingerprint"] is not None


@pytest.mark.asyncio
async def test_poll_one_first_poll_records_fingerprint_no_drift(monkeypatch):
    """First poll on a connector with no baseline should record the new
    fingerprint via record_poll_success but NOT trigger record_schema_drift."""
    inst = _make_instance(
        connector_type="fake_connector",
        connector_config={"poll_interval_seconds": 60},
    )
    # Baseline is None on the ConnectorInstance.

    fake_connector = MagicMock()
    fake_connector.fetch_alerts = AsyncMock(return_value=[{"severity": "high", "host": "h1"}])
    fake_connector.normalize = MagicMock(side_effect=lambda e: e)

    monkeypatch.setattr(
        "app.scheduler.CONNECTOR_REGISTRY",
        {"fake_connector": MagicMock(return_value=fake_connector)},
    )

    fake_engine = _FakeEngine([inst])
    scheduler = ConnectorScheduler(
        engine=fake_engine,
        ingest_client=_FakeIngestClient(accepted=1),
        vault=_FakeVault(),
    )
    await scheduler._poll_one(connector_id=inst.id)

    assert fake_engine.success_calls == [inst.id]
    # No drift expected on first poll.
    assert fake_engine.drift_calls == []


@pytest.mark.asyncio
async def test_poll_one_detects_schema_drift(monkeypatch):
    """When the new fingerprint differs from the stored baseline,
    record_schema_drift should be called with details describing the
    change before record_poll_success is invoked."""
    # Synthesize a baseline fingerprint that differs from what the
    # current poll will produce.
    from app.pipeline.fingerprint import compute_fingerprint as cf

    stale_fp = cf([{"severity": "high"}])  # baseline: only one field
    inst = _make_instance(
        connector_type="fake_connector",
        connector_config={"poll_interval_seconds": 60},
    )
    inst.schema_fingerprint = stale_fp

    fake_connector = MagicMock()
    fake_connector.fetch_alerts = AsyncMock(return_value=[{"severity": "high", "host": "h1", "new_field": "x"}])
    fake_connector.normalize = MagicMock(side_effect=lambda e: e)

    monkeypatch.setattr(
        "app.scheduler.CONNECTOR_REGISTRY",
        {"fake_connector": MagicMock(return_value=fake_connector)},
    )

    fake_engine = _FakeEngine([inst])
    scheduler = ConnectorScheduler(
        engine=fake_engine,
        ingest_client=_FakeIngestClient(accepted=1),
        vault=_FakeVault(),
    )
    await scheduler._poll_one(connector_id=inst.id)

    assert fake_engine.success_calls == [inst.id]
    assert len(fake_engine.drift_calls) == 1
    drift = fake_engine.drift_calls[0]
    assert drift["connector_id"] == inst.id
    assert drift["fingerprint"] != stale_fp
    assert "added" in drift["details"]
    assert "previous_fingerprint" in drift["details"]
    assert drift["details"]["previous_fingerprint"] == stale_fp


@pytest.mark.asyncio
async def test_poll_one_stable_schema_no_drift(monkeypatch):
    """If the new fingerprint matches the stored baseline, the row's
    fingerprint is rewritten via success but no drift event fires."""
    from app.pipeline.fingerprint import compute_fingerprint as cf

    events = [{"severity": "high", "host": "h1"}]
    baseline_fp = cf(events)
    inst = _make_instance(
        connector_type="fake_connector",
        connector_config={"poll_interval_seconds": 60},
    )
    inst.schema_fingerprint = baseline_fp

    fake_connector = MagicMock()
    fake_connector.fetch_alerts = AsyncMock(return_value=events)
    fake_connector.normalize = MagicMock(side_effect=lambda e: e)

    monkeypatch.setattr(
        "app.scheduler.CONNECTOR_REGISTRY",
        {"fake_connector": MagicMock(return_value=fake_connector)},
    )

    fake_engine = _FakeEngine([inst])
    scheduler = ConnectorScheduler(
        engine=fake_engine,
        ingest_client=_FakeIngestClient(accepted=1),
        vault=_FakeVault(),
    )
    await scheduler._poll_one(connector_id=inst.id)

    assert fake_engine.success_calls == [inst.id]
    assert fake_engine.drift_calls == []


@pytest.mark.asyncio
async def test_poll_one_quiet_hour_does_not_clobber_fingerprint(monkeypatch):
    """If a poll returns zero events the fingerprint is None and we should
    NOT overwrite the baseline in the row (ConnectorInstance fingerprint
    stays as-is)."""
    from app.pipeline.fingerprint import compute_fingerprint as cf

    baseline_fp = cf([{"severity": "high", "host": "h1"}])
    inst = _make_instance(
        connector_type="fake_connector",
        connector_config={"poll_interval_seconds": 60},
    )
    inst.schema_fingerprint = baseline_fp

    fake_connector = MagicMock()
    fake_connector.fetch_alerts = AsyncMock(return_value=[])
    fake_connector.normalize = MagicMock(side_effect=lambda e: e)

    monkeypatch.setattr(
        "app.scheduler.CONNECTOR_REGISTRY",
        {"fake_connector": MagicMock(return_value=fake_connector)},
    )

    captured_success: dict[str, Any] = {}

    async def capture_record_poll_success(
        conn: Any,
        connector_id: uuid.UUID,
        *,
        events_added: int,
        events_dropped: int = 0,
        schema_fingerprint: str | None = None,
        last_event_at: Any = None,
        last_event_kind: str | None = None,
    ) -> None:
        conn.engine.success_calls.append(connector_id)
        captured_success["schema_fingerprint"] = schema_fingerprint

    monkeypatch.setattr("app.scheduler.record_poll_success", capture_record_poll_success)

    fake_engine = _FakeEngine([inst])
    scheduler = ConnectorScheduler(
        engine=fake_engine,
        ingest_client=_FakeIngestClient(accepted=0),
        vault=_FakeVault(),
    )
    await scheduler._poll_one(connector_id=inst.id)

    # Empty batch → fingerprint should be None so the DB layer leaves the
    # baseline alone.
    assert captured_success["schema_fingerprint"] is None
    assert fake_engine.drift_calls == []


# ---------------------------------------------------------------------------
# Failure paths each flip the row to unhealthy without raising
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_poll_one_unknown_connector_type(monkeypatch):
    inst = _make_instance(connector_type="not_in_registry")
    monkeypatch.setattr("app.scheduler.CONNECTOR_REGISTRY", {})

    scheduler = ConnectorScheduler(engine=_FakeEngine([inst]), ingest_client=_FakeIngestClient(), vault=_FakeVault())
    await scheduler._poll_one(connector_id=inst.id)

    engine: _FakeEngine = scheduler._engine  # type: ignore[assignment]
    assert engine.failure_calls == [inst.id]


@pytest.mark.asyncio
async def test_poll_one_decrypt_failure(monkeypatch):
    inst = _make_instance(connector_type="fake_connector")
    monkeypatch.setattr("app.scheduler.CONNECTOR_REGISTRY", {"fake_connector": MagicMock()})

    bad_vault = _FakeVault()
    bad_vault.fail = True

    scheduler = ConnectorScheduler(engine=_FakeEngine([inst]), ingest_client=_FakeIngestClient(), vault=bad_vault)
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

    monkeypatch.setattr("app.scheduler.CONNECTOR_REGISTRY", {"fake_connector": bad_ctor})

    scheduler = ConnectorScheduler(engine=_FakeEngine([inst]), ingest_client=_FakeIngestClient(), vault=_FakeVault())
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

    scheduler = ConnectorScheduler(engine=_FakeEngine([inst]), ingest_client=_FakeIngestClient(), vault=_FakeVault())
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

    scheduler = ConnectorScheduler(engine=_FakeEngine([inst]), ingest_client=bad_ingest, vault=_FakeVault())
    await scheduler._poll_one(connector_id=inst.id)

    engine: _FakeEngine = scheduler._engine  # type: ignore[assignment]
    assert engine.failure_calls == [inst.id]


@pytest.mark.asyncio
async def test_poll_one_instance_disappeared(monkeypatch):
    """If the connector row was deleted between reload and poll, we no-op."""
    monkeypatch.setattr("app.scheduler.CONNECTOR_REGISTRY", {})
    scheduler = ConnectorScheduler(engine=_FakeEngine([]), ingest_client=_FakeIngestClient(), vault=_FakeVault())
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
    scheduler = ConnectorScheduler(engine=engine, ingest_client=_FakeIngestClient(), vault=_FakeVault())
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
    scheduler = ConnectorScheduler(engine=engine, ingest_client=_FakeIngestClient(), vault=_FakeVault())
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
    scheduler = ConnectorScheduler(engine=engine, ingest_client=_FakeIngestClient(), vault=_FakeVault())
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
# Workstream 5: backfill-on-outage worker
# ---------------------------------------------------------------------------
#
# These tests pin down the behavior described in the v2 plan:
#
# * After an outage of >= ``_BACKFILL_OUTAGE_THRESHOLD_S`` (30 min) the
#   recovery poll schedules a one-shot backfill poll using a lookback that
#   covers the outage duration plus a small buffer, capped at
#   ``_MAX_BACKFILL_LOOKBACK_S`` (24h).
# * Outages shorter than the threshold do NOT trigger a backfill.
# * If a backfill ran inside ``_BACKFILL_FLAP_WINDOW_S`` (10 min) we
#   suppress re-firing — flap protection.
# * Backfill polls themselves never recurse into another backfill (we
#   pass ``backfill_seconds`` so the scheduler treats this as a one-shot).
# * The flap-suppress timestamp is written *before* the backfill poll
#   runs so a parallel scheduler job can't double-fire.


@pytest.mark.asyncio
async def test_poll_one_recovery_after_long_outage_schedules_backfill(monkeypatch):
    """Recovery from a 45-minute outage should fire one backfill poll
    using a lookback window that covers the outage + small buffer."""
    from app import scheduler as scheduler_mod

    inst = _make_instance(connector_type="fake_connector")
    inst.last_outage_at = datetime.now(UTC) - timedelta(minutes=45)
    inst.last_backfill_at = None

    fake_connector = MagicMock()
    fake_connector.fetch_alerts = AsyncMock(return_value=[{"x": 1}])
    fake_connector.normalize = MagicMock(side_effect=lambda e: e)

    monkeypatch.setattr(
        "app.scheduler.CONNECTOR_REGISTRY",
        {"fake_connector": MagicMock(return_value=fake_connector)},
    )

    fake_engine = _FakeEngine([inst])
    scheduler = ConnectorScheduler(
        engine=fake_engine,
        ingest_client=_FakeIngestClient(accepted=1),
        vault=_FakeVault(),
    )

    await scheduler._poll_one(connector_id=inst.id)

    # First call: normal recovery poll using poll_interval (300 default).
    # Second call: one-shot backfill with the outage-derived lookback.
    assert fake_connector.fetch_alerts.await_count == 2
    first_call = fake_connector.fetch_alerts.await_args_list[0]
    second_call = fake_connector.fetch_alerts.await_args_list[1]

    assert first_call.kwargs["since_seconds"] == 300  # default poll cadence
    backfill_seconds = second_call.kwargs["since_seconds"]

    # Window should be ~45 min + 5 min buffer = ~3000s, but the backfill
    # caller passes ``int(outage_duration) + buffer``. Allow ±10s for
    # clock drift between the test setup and the now() inside the
    # scheduler.
    expected = int(45 * 60) + scheduler_mod._BACKFILL_LOOKBACK_BUFFER_S
    assert abs(backfill_seconds - expected) <= 10
    # Cap should never be exceeded.
    assert backfill_seconds <= scheduler_mod._MAX_BACKFILL_LOOKBACK_S

    # Backfill timestamp was stamped before the second poll fired.
    assert getattr(fake_engine, "backfill_calls", []) == [inst.id]


@pytest.mark.asyncio
async def test_poll_one_short_outage_skips_backfill(monkeypatch):
    """Outages shorter than the 30-minute threshold should never schedule
    a backfill — the recovery poll covers them."""
    inst = _make_instance(connector_type="fake_connector")
    # 5 minutes of outage — well below the 30-min threshold.
    inst.last_outage_at = datetime.now(UTC) - timedelta(minutes=5)

    fake_connector = MagicMock()
    fake_connector.fetch_alerts = AsyncMock(return_value=[{"x": 1}])
    fake_connector.normalize = MagicMock(side_effect=lambda e: e)

    monkeypatch.setattr(
        "app.scheduler.CONNECTOR_REGISTRY",
        {"fake_connector": MagicMock(return_value=fake_connector)},
    )

    fake_engine = _FakeEngine([inst])
    scheduler = ConnectorScheduler(
        engine=fake_engine,
        ingest_client=_FakeIngestClient(accepted=1),
        vault=_FakeVault(),
    )

    await scheduler._poll_one(connector_id=inst.id)

    # Exactly one fetch (the recovery poll). No backfill fan-out.
    assert fake_connector.fetch_alerts.await_count == 1
    assert getattr(fake_engine, "backfill_calls", []) == []


@pytest.mark.asyncio
async def test_poll_one_recent_backfill_suppresses_flap(monkeypatch):
    """If we already ran a backfill inside the flap window, do NOT
    re-fire even if last_outage_at looks long enough."""
    inst = _make_instance(connector_type="fake_connector")
    inst.last_outage_at = datetime.now(UTC) - timedelta(minutes=60)
    # Recent backfill — inside the 10-minute flap window.
    inst.last_backfill_at = datetime.now(UTC) - timedelta(minutes=2)

    fake_connector = MagicMock()
    fake_connector.fetch_alerts = AsyncMock(return_value=[{"x": 1}])
    fake_connector.normalize = MagicMock(side_effect=lambda e: e)

    monkeypatch.setattr(
        "app.scheduler.CONNECTOR_REGISTRY",
        {"fake_connector": MagicMock(return_value=fake_connector)},
    )

    fake_engine = _FakeEngine([inst])
    scheduler = ConnectorScheduler(
        engine=fake_engine,
        ingest_client=_FakeIngestClient(accepted=1),
        vault=_FakeVault(),
    )

    await scheduler._poll_one(connector_id=inst.id)

    # No second fetch and no new backfill stamp.
    assert fake_connector.fetch_alerts.await_count == 1
    assert getattr(fake_engine, "backfill_calls", []) == []


@pytest.mark.asyncio
async def test_poll_one_old_backfill_outside_flap_window_allows_refire(monkeypatch):
    """If the previous backfill ran outside the flap window, a fresh
    long-outage recovery should still schedule a new backfill."""
    inst = _make_instance(connector_type="fake_connector")
    inst.last_outage_at = datetime.now(UTC) - timedelta(minutes=60)
    # Last backfill 30 minutes ago — outside the 10-minute flap window.
    inst.last_backfill_at = datetime.now(UTC) - timedelta(minutes=30)

    fake_connector = MagicMock()
    fake_connector.fetch_alerts = AsyncMock(return_value=[{"x": 1}])
    fake_connector.normalize = MagicMock(side_effect=lambda e: e)

    monkeypatch.setattr(
        "app.scheduler.CONNECTOR_REGISTRY",
        {"fake_connector": MagicMock(return_value=fake_connector)},
    )

    fake_engine = _FakeEngine([inst])
    scheduler = ConnectorScheduler(
        engine=fake_engine,
        ingest_client=_FakeIngestClient(accepted=1),
        vault=_FakeVault(),
    )

    await scheduler._poll_one(connector_id=inst.id)

    # Recovery poll + one-shot backfill = 2 fetches.
    assert fake_connector.fetch_alerts.await_count == 2
    assert getattr(fake_engine, "backfill_calls", []) == [inst.id]


@pytest.mark.asyncio
async def test_poll_one_backfill_does_not_recurse(monkeypatch):
    """A backfill poll itself must not schedule yet another backfill —
    we pass ``backfill_seconds`` so recovery detection is skipped."""
    inst = _make_instance(connector_type="fake_connector")
    # Even if last_outage_at is set, an explicit backfill_seconds should
    # cause the recovery branch to be skipped.
    inst.last_outage_at = datetime.now(UTC) - timedelta(hours=2)

    fake_connector = MagicMock()
    fake_connector.fetch_alerts = AsyncMock(return_value=[{"x": 1}])
    fake_connector.normalize = MagicMock(side_effect=lambda e: e)

    monkeypatch.setattr(
        "app.scheduler.CONNECTOR_REGISTRY",
        {"fake_connector": MagicMock(return_value=fake_connector)},
    )

    fake_engine = _FakeEngine([inst])
    scheduler = ConnectorScheduler(
        engine=fake_engine,
        ingest_client=_FakeIngestClient(accepted=1),
        vault=_FakeVault(),
    )

    await scheduler._poll_one(connector_id=inst.id, backfill_seconds=3600)

    # Exactly one fetch (the backfill itself). No second one for cascade.
    assert fake_connector.fetch_alerts.await_count == 1
    assert fake_connector.fetch_alerts.await_args.kwargs["since_seconds"] == 3600
    assert getattr(fake_engine, "backfill_calls", []) == []


@pytest.mark.asyncio
async def test_poll_one_backfill_window_capped_at_max(monkeypatch):
    """A 36-hour outage should still produce a backfill window capped at
    24 hours (``_MAX_BACKFILL_LOOKBACK_S``)."""
    from app import scheduler as scheduler_mod

    inst = _make_instance(connector_type="fake_connector")
    inst.last_outage_at = datetime.now(UTC) - timedelta(hours=36)

    fake_connector = MagicMock()
    fake_connector.fetch_alerts = AsyncMock(return_value=[{"x": 1}])
    fake_connector.normalize = MagicMock(side_effect=lambda e: e)

    monkeypatch.setattr(
        "app.scheduler.CONNECTOR_REGISTRY",
        {"fake_connector": MagicMock(return_value=fake_connector)},
    )

    fake_engine = _FakeEngine([inst])
    scheduler = ConnectorScheduler(
        engine=fake_engine,
        ingest_client=_FakeIngestClient(accepted=1),
        vault=_FakeVault(),
    )

    await scheduler._poll_one(connector_id=inst.id)

    # Two fetches: recovery + one-shot backfill.
    assert fake_connector.fetch_alerts.await_count == 2
    backfill_seconds = fake_connector.fetch_alerts.await_args_list[1].kwargs["since_seconds"]
    # The cap kicks in BEFORE the buffer is added inside _poll_one
    # (see ``backfill_window_seconds = min(...)``), so the value passed
    # to the recursive call equals the cap exactly.
    assert backfill_seconds == scheduler_mod._MAX_BACKFILL_LOOKBACK_S


@pytest.mark.asyncio
async def test_poll_one_no_outage_no_backfill(monkeypatch):
    """When the connector was never in outage (last_outage_at is None),
    no backfill should ever fire even if a poll succeeds."""
    inst = _make_instance(connector_type="fake_connector")
    assert inst.last_outage_at is None

    fake_connector = MagicMock()
    fake_connector.fetch_alerts = AsyncMock(return_value=[{"x": 1}])
    fake_connector.normalize = MagicMock(side_effect=lambda e: e)

    monkeypatch.setattr(
        "app.scheduler.CONNECTOR_REGISTRY",
        {"fake_connector": MagicMock(return_value=fake_connector)},
    )

    fake_engine = _FakeEngine([inst])
    scheduler = ConnectorScheduler(
        engine=fake_engine,
        ingest_client=_FakeIngestClient(accepted=1),
        vault=_FakeVault(),
    )

    await scheduler._poll_one(connector_id=inst.id)

    assert fake_connector.fetch_alerts.await_count == 1
    assert getattr(fake_engine, "backfill_calls", []) == []


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
        self.drift_calls: list[dict[str, Any]] = []
        # Workstream 5: track every record_backfill_run() call so backfill
        # tests can assert when the flap-suppress timestamp was stamped.
        self.backfill_calls: list[uuid.UUID] = []

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

    async def fake_record_poll_success(
        conn: Any,
        connector_id: uuid.UUID,
        *,
        events_added: int,
        events_dropped: int = 0,
        schema_fingerprint: str | None = None,
        last_event_at: Any = None,
        last_event_kind: str | None = None,
    ) -> None:
        conn.engine.success_calls.append(connector_id)

    async def fake_record_poll_failure(conn: Any, connector_id: uuid.UUID) -> None:
        conn.engine.failure_calls.append(connector_id)

    async def fake_record_schema_drift(
        conn: Any,
        connector_id: uuid.UUID,
        *,
        fingerprint: str,
        details: dict[str, Any],
    ) -> None:
        getattr(conn.engine, "drift_calls", []).append({"connector_id": connector_id, "fingerprint": fingerprint, "details": details})

    async def fake_record_backfill_run(
        conn: Any,
        connector_id: uuid.UUID,
    ) -> None:
        getattr(conn.engine, "backfill_calls", []).append(connector_id)

    monkeypatch.setattr("app.scheduler.fetch_enabled_connectors", fake_fetch_enabled_connectors)
    monkeypatch.setattr("app.scheduler.record_poll_success", fake_record_poll_success)
    monkeypatch.setattr("app.scheduler.record_poll_failure", fake_record_poll_failure)
    monkeypatch.setattr("app.scheduler.record_schema_drift", fake_record_schema_drift)
    monkeypatch.setattr("app.scheduler.record_backfill_run", fake_record_backfill_run)
